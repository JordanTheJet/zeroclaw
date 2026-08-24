//! Behavior-boundary coverage for the read-only stdio control MCP transport.
//!
//! Every interesting property of this surface is a refusal, so these tests are
//! written to fail if a refusal ever becomes an answer. They drive the real
//! server the way an MCP client does — `initialize`, `tools/list`,
//! `tools/call` — against a throwaway install root, and assert on the JSON-RPC
//! frames rather than on internal state.
//!
//! Grant-gated tools are reachable here only because the control crate's
//! test-only `fixture-grants` feature is enabled through this package's
//! `[dev-dependencies]`. `cargo build` does not build dev-dependencies, so the
//! shipped binary contains no constructor for a grant and therefore no session
//! that can reach these tools. `the_default_installation_grants_nothing`
//! asserts the production path takes the unregistered branch regardless.
//!
//! `Config::load_or_init` resolves the install root from the environment, so
//! every test here serializes on `ENV_LOCK` and restores the previous value
//! before releasing it.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use serde_json::{Value, json};
use tokio::sync::Mutex;
use zeroclaw::control_mcp::{ControlHost, ControlLaunch, ControlMcpServer};
use zeroclaw_config::schema::Config;
use zeroclaw_config::secrets::KeySource as _;
use zeroclaw_control::client_registry::{
    ClientGrant, ClientLabel, ClientRegistration, ClientRegistry, RegistrationStatus,
};
use zeroclaw_control::genesis::{
    FirstOperatorIdentity, GenesisRecord, KeyCommitment, PresenceClass, generate_instance_id,
    now_unix_secs,
};
use zeroclaw_control::keys::ApprovalAuditKey;
use zeroclaw_control::protocol::{
    AgentCreateContainedOperation, CapabilitySet, ControlErrorCode, PreviewResult,
    STARTUP_REFUSAL_META_KEY, StartupRefusal, StartupRefusalCode, canonical_json,
    capability_digest, operation_digest, operation_digest_for, source_revision_id,
};
use zeroclaw_control::registry::{
    GenesisDigest, InstanceId, TargetRecord, TargetRegistry, TrustEpoch,
};
use zeroclaw_control::{
    CapabilityRestrictedProviderFactory, ControlPaths, ControlService, ControlSession,
    CredentialDelivery, IsolatedProvider, MemoryChoice, PROPOSAL_DOMAIN_AGENT,
    PersonalityFileProposal, ProviderError, ProviderErrorCode, ProviderTarget, RegistrationId,
    RequesterGrant, RiskChoice, RuntimeChoice, client_registry, registry_store,
};
use zeroclaw_runtime::quickstart::Surface;

static ENV_LOCK: Mutex<()> = Mutex::const_new(());

/// The version string the server advertises in these tests.
const TEST_VERSION: &str = "0.0.0-test";

/// The three tools an unregistered session may see, in registry order.
const ALWAYS_AVAILABLE: [&str; 3] = [
    "control.ping",
    "control.server_info",
    "control.registration_help",
];

/// The five read tools a registered grant adds, in registry order.
const GRANT_GATED: [&str; 5] = [
    "control.catalog",
    "control.describe",
    "control.inspect",
    "control.validate",
    "control.preview",
];

/// The two owner-scoped read tools a registered grant adds, in registry order.
/// They are visible to any session holding the preview read domain, on a managed
/// or unmanaged instance and whether or not mutations are enabled — they change
/// nothing and each answer is scoped to the caller's own operations.
const OWNER_SCOPED_READS: [&str; 2] = ["control.status", "control.verify"];

/// Verbs that name a change to host state.
///
/// Matched against the `.`/`_` separated words of a tool name rather than as
/// substrings, so `control.registration_help` is not mistaken for a register
/// operation.
const MUTATION_VERBS: [&str; 19] = [
    "apply", "write", "create", "set", "delete", "remove", "register", "approve", "rotate",
    "enable", "disable", "update", "install", "commit", "mutate", "add", "put", "patch", "revoke",
];

/// Restores `ZEROCLAW_CONFIG_DIR` when the test that pinned it finishes.
struct ConfigDirGuard {
    previous: Option<String>,
}

impl ConfigDirGuard {
    /// # Safety
    ///
    /// The caller must hold `ENV_LOCK` for the whole lifetime of the guard.
    fn pin(dir: &Path) -> Self {
        let previous = std::env::var("ZEROCLAW_CONFIG_DIR").ok();
        // SAFETY: serialized by ENV_LOCK; restored on drop.
        unsafe { std::env::set_var("ZEROCLAW_CONFIG_DIR", dir) };
        Self { previous }
    }
}

impl Drop for ConfigDirGuard {
    fn drop(&mut self) {
        // SAFETY: serialized by ENV_LOCK.
        match self.previous.take() {
            Some(value) => unsafe { std::env::set_var("ZEROCLAW_CONFIG_DIR", value) },
            None => unsafe { std::env::remove_var("ZEROCLAW_CONFIG_DIR") },
        }
    }
}

/// The same provider fixture the `ControlService` tests use. The URI is never
/// contacted, and these tests prove it is never even resolved.
const PROVIDER_CONFIG: &str = r#"schema_version = 3

[memory]
backend = "none"

[reliability]
provider_retries = 0
provider_backoff_ms = 0

[providers.models.custom.fixture]
api_key = "fixture-placeholder"
uri = "http://127.0.0.1:1"
model = "fixture-model"
wire_api = "chat_completions"
"#;

/// A provider factory that records every call and refuses to build a provider.
///
/// Validation is answered from the borrowed configuration, exactly as the
/// production factory's config-only half does, so the read-only surface behaves
/// normally. Construction is the interesting half: it counts the attempt and
/// then fails, so a transport that ever reached for a model provider would both
/// be counted and break loudly rather than quietly opening a socket.
struct RecordingFactory {
    validations: AtomicUsize,
    creations: AtomicUsize,
}

impl RecordingFactory {
    fn new() -> Self {
        Self {
            validations: AtomicUsize::new(0),
            creations: AtomicUsize::new(0),
        }
    }
}

impl CapabilityRestrictedProviderFactory for RecordingFactory {
    fn validate_capability_restricted_model_provider_alias(
        &self,
        config: &Config,
        reference: &str,
    ) -> Result<ProviderTarget, ProviderError> {
        self.validations.fetch_add(1, Ordering::SeqCst);
        let Some((family, alias, entry)) = config.providers.models.find_by_name(reference) else {
            return Err(ProviderError::new(
                ProviderErrorCode::NotConfigured,
                reference,
            ));
        };
        let Some(model) = entry.model.clone() else {
            return Err(ProviderError::new(
                ProviderErrorCode::MissingModel,
                reference,
            ));
        };
        Ok(ProviderTarget {
            reference: format!("{family}.{alias}"),
            model,
        })
    }

    fn create_isolated_model_provider_for_alias(
        &self,
        _config: &Config,
        reference: &str,
    ) -> Result<IsolatedProvider, ProviderError> {
        self.creations.fetch_add(1, Ordering::SeqCst);
        Err(ProviderError::new(
            ProviderErrorCode::ConstructionFailed,
            reference,
        ))
    }
}

fn seed_install(dir: &Path) -> std::path::PathBuf {
    let config_path = dir.join("config.toml");
    std::fs::write(&config_path, PROVIDER_CONFIG).expect("write provider config");
    config_path
}

/// Restores an arbitrary environment variable when the test that pinned it
/// finishes.
///
/// The credential descriptor is named by an environment variable, so a test
/// that sets one and leaves it set would silently arm every later test in this
/// binary with a stale descriptor number.
struct EnvVarGuard {
    key: &'static str,
    previous: Option<std::ffi::OsString>,
}

impl EnvVarGuard {
    /// # Safety
    ///
    /// The caller must hold `ENV_LOCK` for the whole lifetime of the guard.
    fn pin(key: &'static str, value: &str) -> Self {
        let previous = std::env::var_os(key);
        // SAFETY: serialized by ENV_LOCK; restored on drop.
        unsafe { std::env::set_var(key, value) };
        Self { key, previous }
    }
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        // SAFETY: serialized by ENV_LOCK.
        match self.previous.take() {
            Some(value) => unsafe { std::env::set_var(self.key, value) },
            None => unsafe { std::env::remove_var(self.key) },
        }
    }
}

/// The environment variable the inherited-descriptor mechanism reads.
const CREDENTIAL_FD_ENV: &str = "ZEROCLAW_CONTROL_CREDENTIAL_FD";

/// One initialized instance on disk, with a real config, a sealed genesis
/// record, and a signed target registry naming it.
///
/// Built from the control crate's public durable-state API rather than by
/// running `ceremony::run_genesis`: the ceremony needs a `UserPresence`
/// adapter and `PresenceAttestation` has no constructor outside the `ceremony`
/// module, so no test outside that crate can drive it. What is written here is
/// what the ceremony writes — the same records, through the same publishers,
/// sealed under the same deployment key — so the server under test reads state
/// it cannot distinguish from ceremony output.
struct ManagedInstall {
    temp: tempfile::TempDir,
    config_path: PathBuf,
    paths: ControlPaths,
    instance_id: InstanceId,
    genesis_digest: GenesisDigest,
}

impl ManagedInstall {
    fn new() -> Self {
        let temp = tempfile::tempdir().expect("temporary install root");
        let config_path = seed_install(temp.path());
        std::fs::create_dir_all(temp.path().join("data")).expect("create the data root");
        let paths = ControlPaths::resolve(temp.path()).expect("resolve control paths");

        let key_source = paths.key_source();
        key_source
            .initialize()
            .expect("initialize the deployment key source");
        let key =
            ApprovalAuditKey::derive(&key_source, TrustEpoch::GENESIS).expect("derive the key");

        let instance_id = generate_instance_id().expect("instance id");
        let record = GenesisRecord {
            instance_id: instance_id.clone(),
            trust_epoch: TrustEpoch::GENESIS,
            canonical_roots: paths.canonical_roots().expect("canonical roots"),
            created_at_unix_secs: now_unix_secs().expect("clock"),
            user_presence_class: PresenceClass::Terminal,
            first_operator: FirstOperatorIdentity::new("operator").expect("operator identity"),
            host_key_commitment: KeyCommitment::compute(&key),
        };
        let genesis_digest = zeroclaw_control::genesis::write_record(&paths, &record, &key)
            .expect("write the genesis record");

        let target = TargetRecord::register(
            instance_id.clone(),
            paths.canonical_roots().expect("canonical roots"),
            None,
            TrustEpoch::GENESIS,
            genesis_digest,
        )
        .expect("build the target record");
        let mut targets = TargetRegistry::new();
        targets.insert(target).expect("insert the target record");
        registry_store::save_new(&paths, &targets, &key).expect("save the target registry");

        Self {
            temp,
            config_path,
            paths,
            instance_id,
            genesis_digest,
        }
    }

    fn root(&self) -> &Path {
        self.temp.path()
    }

    fn key(&self) -> ApprovalAuditKey {
        ApprovalAuditKey::derive(&self.paths.key_source(), TrustEpoch::GENESIS)
            .expect("derive the key")
    }

    fn full_grant(&self, delivery: CredentialDelivery) -> ClientGrant {
        ClientGrant::full_v1(
            ClientLabel::new("component-client").expect("label"),
            delivery,
            self.instance_id.clone(),
        )
    }

    /// Register one client and write its one-time credential to a file, exactly
    /// as the ceremony's `--credential-out` does.
    ///
    /// Returns the registration id and the path of the credential file. The
    /// secret is never returned as a value a later assertion could accidentally
    /// print; tests that need to compare against it read the file.
    fn register(&self, grant: &ClientGrant, filename: &str) -> (RegistrationId, PathBuf) {
        let key = self.key();
        let issued = ClientRegistration::issue(
            grant,
            TrustEpoch::GENESIS,
            now_unix_secs().expect("clock"),
            self.genesis_digest,
            PresenceClass::Terminal,
            &key,
        )
        .expect("issue a registration");
        let id = issued.registration.registration_id.clone();

        let credential_path = self.temp.path().join(filename);
        client_registry::write_credential_file(&credential_path, &issued.credential)
            .expect("deliver the credential");

        let mut registry = if client_registry::is_present(&self.paths) {
            client_registry::load(&self.paths, &key).expect("load the client registry")
        } else {
            ClientRegistry::new()
        };
        registry
            .insert(issued.registration)
            .expect("insert the registration");
        client_registry::save(&self.paths, &registry, &key).expect("save the client registry");
        (id, credential_path)
    }

    fn revoke(&self, id: &RegistrationId) {
        let key = self.key();
        let existing = client_registry::load(&self.paths, &key).expect("load the client registry");
        let mut replacement = ClientRegistry::new();
        for registration in existing.iter() {
            let mut copy = registration.clone();
            if &copy.registration_id == id {
                copy.status = RegistrationStatus::Revoked;
            }
            replacement.insert(copy).expect("insert");
        }
        client_registry::save(&self.paths, &replacement, &key).expect("save the client registry");
    }

    /// The credential as it sits in its delivery file.
    fn secret(&self, credential_path: &Path) -> String {
        std::fs::read_to_string(credential_path)
            .expect("read the credential file")
            .trim()
            .to_string()
    }
}

/// Hand an open descriptor on `path` to the process and name it in the
/// environment.
///
/// `into_raw_fd` deliberately leaks ownership: the server takes the descriptor
/// and closes it, which is the behavior under test. The guard restores the
/// environment either way.
fn present_descriptor(path: &Path) -> (EnvVarGuard, i32) {
    use std::os::fd::IntoRawFd as _;
    let fd = std::fs::File::open(path)
        .expect("open the credential file")
        .into_raw_fd();
    (EnvVarGuard::pin(CREDENTIAL_FD_ENV, &fd.to_string()), fd)
}

/// Write an executable credential helper that prints `body` to stdout.
#[cfg(unix)]
fn write_helper(dir: &Path, name: &str, body: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt as _;
    let path = dir.join(name);
    std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).expect("write the helper");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
        .expect("make the helper executable");
    path
}

/// Start a host with the inherited-descriptor mechanism.
async fn start_with_descriptor(
    install: &ManagedInstall,
    id: &RegistrationId,
    credential_path: &Path,
) -> Result<ControlHost, StartupRefusal> {
    let (_env, _fd) = present_descriptor(credential_path);
    let launch = ControlLaunch::resolve(Some(id.as_str().to_string()), None)?;
    assert!(launch.presents_credential());
    zeroclaw::control_mcp::start(install.config_path.clone(), TEST_VERSION, launch).await
}

fn refusal_code(result: &Result<ControlHost, StartupRefusal>, what: &str) -> StartupRefusalCode {
    match result {
        Ok(_) => panic!("{what} must not start a registered session"),
        Err(refusal) => refusal.code,
    }
}

fn service_with(factory: &Arc<RecordingFactory>, config_path: &Path) -> ControlService {
    ControlService::with_factory(
        config_path.to_path_buf(),
        Surface::Cli,
        factory.clone() as Arc<dyn CapabilityRestrictedProviderFactory>,
    )
}

/// The typed operation these tests propose: the same contained `writer` agent
/// the `ControlService` and terminal-flow tests use.
fn writer_operation() -> AgentCreateContainedOperation {
    AgentCreateContainedOperation {
        provider_alias: "custom.fixture".to_string(),
        agent_alias: "writer".to_string(),
        risk: RiskChoice::LockedDown,
        runtime: RuntimeChoice::Tight,
        memory: MemoryChoice::Markdown,
        personality_files: vec![PersonalityFileProposal {
            filename: "SOUL.md".to_string(),
            content: "# Soul\nWrite carefully.".to_string(),
        }],
    }
}

/// A scripted user-presence adapter for the phase-5 ceremony paths.
///
/// This test binary enables the control crate's `fixture-grants` feature, which
/// exposes `PresenceAttestation::fixture` — the seam that lets a test attest a
/// fixed operator identity without a real controlling terminal. It is absent
/// from every shipped build and covered by the fixture-absence CI gate.
struct FixturePresence {
    operator: FirstOperatorIdentity,
}

impl FixturePresence {
    fn new(operator: &str) -> Self {
        Self {
            operator: FirstOperatorIdentity::new(operator).expect("operator identity"),
        }
    }
}

impl zeroclaw_control::UserPresence for FixturePresence {
    fn confirm(
        &self,
        _request: &zeroclaw_control::ceremony::PresenceRequest,
    ) -> Result<zeroclaw_control::ceremony::PresenceAttestation, zeroclaw_control::PresenceError>
    {
        Ok(zeroclaw_control::ceremony::PresenceAttestation::fixture(
            PresenceClass::Terminal,
            Some(self.operator.clone()),
        ))
    }
}

/// Enable mutations on `install` through the fixture presence ceremony, naming
/// the genesis first operator. This is the host-side enablement `zeroclaw
/// control enable-mutations` performs; nothing an MCP session can reach.
fn enable_mutations(install: &ManagedInstall) {
    zeroclaw_control::management::enable_mutations(
        install.root(),
        &FixturePresence::new("operator"),
        "confirm".to_string(),
        "operator".to_string(),
    )
    .expect("the ceremony enables mutations");
}

/// The durable journal file for this install, whose absence proves no proposal
/// was parked.
fn journal_path(install: &ManagedInstall) -> PathBuf {
    install
        .paths
        .control_dir()
        .join(zeroclaw_control::journal::JOURNAL_FILE)
}

/// The `control.request_apply` arguments for the standard writer proposal.
fn request_apply_args() -> Value {
    json!({
        "operation_id": "agent.create_contained",
        "operation": serde_json::to_value(writer_operation()).expect("operation serializes"),
    })
}

fn request(id: u64, method: &str, params: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params })
}

fn call(id: u64, name: &str, arguments: Value) -> Value {
    request(
        id,
        "tools/call",
        json!({ "name": name, "arguments": arguments }),
    )
}

/// Submit one frame and return the response, failing if the server stayed
/// silent on a request that carried an id.
async fn exchange(server: &ControlMcpServer, frame: &Value) -> Value {
    let bytes = serde_json::to_vec(frame).expect("request serializes");
    server
        .handle_frame(&bytes)
        .await
        .expect("a request with an id must be answered")
}

/// The `structuredContent` of a successful `tools/call`, with the envelope's
/// `result` unwrapped.
fn tool_ok(response: &Value) -> Value {
    let result = &response["result"];
    assert_eq!(
        result["isError"],
        json!(false),
        "expected success, got: {result}"
    );
    result["structuredContent"]["result"].clone()
}

/// The typed error payload of a refused `tools/call`.
fn tool_err(response: &Value) -> Value {
    let result = &response["result"];
    assert_eq!(
        result["isError"],
        json!(true),
        "expected a refusal, got: {result}"
    );
    result["structuredContent"]["error"].clone()
}

fn error_code(response: &Value) -> String {
    tool_err(response)["code"]
        .as_str()
        .expect("a typed error carries a code")
        .to_string()
}

fn listed_tool_names(response: &Value) -> Vec<String> {
    response["result"]["tools"]
        .as_array()
        .expect("tools/list returns an array")
        .iter()
        .map(|tool| {
            tool["name"]
                .as_str()
                .expect("every tool has a name")
                .to_string()
        })
        .collect()
}

async fn initialize(server: &ControlMcpServer) -> Value {
    exchange(
        server,
        &request(
            1,
            "initialize",
            json!({
                "protocolVersion": "2024-11-05",
                "clientInfo": { "name": "component-test", "version": "1.0.0" },
                "_meta": {
                    "zeroclaw_control": {
                        "supported_control_protocol_versions": ["1.0"],
                    },
                },
            }),
        ),
    )
    .await
}

// ---------------------------------------------------------------------------
// Fixture-credential contract, points 5 and 6
// ---------------------------------------------------------------------------

#[tokio::test]
async fn an_unregistered_session_exposes_only_initialize_and_the_three_always_available_tools() {
    let _lock = ENV_LOCK.lock().await;
    let temp = tempfile::tempdir().expect("temporary install root");
    let config_path = seed_install(temp.path());
    let _guard = ConfigDirGuard::pin(temp.path());
    let factory = Arc::new(RecordingFactory::new());
    let server = ControlMcpServer::with_service_and_session(
        service_with(&factory, &config_path),
        ControlSession::unregistered(),
        TEST_VERSION,
    );

    let initialized = initialize(&server).await;
    assert!(
        initialized["result"]["_meta"]["zeroclaw_control"].is_object(),
        "initialize must succeed for an unregistered session"
    );

    let listed = exchange(&server, &request(2, "tools/list", json!({}))).await;
    assert_eq!(
        listed_tool_names(&listed),
        ALWAYS_AVAILABLE,
        "an unregistered session sees exactly the always-available tools"
    );

    // Each always-available tool answers.
    for (index, name) in ALWAYS_AVAILABLE.iter().enumerate() {
        let response = exchange(&server, &call(10 + index as u64, name, json!({}))).await;
        assert_eq!(
            response["result"]["isError"],
            json!(false),
            "{name} must answer an unregistered session"
        );
    }

    // Every grant-gated tool refuses by name, even though it was never listed.
    for (index, name) in GRANT_GATED.iter().enumerate() {
        let response = exchange(&server, &call(20 + index as u64, name, json!({}))).await;
        assert_eq!(
            error_code(&response),
            "unregistered_client",
            "{name} must refuse an unregistered caller"
        );
    }
}

#[tokio::test]
async fn the_default_installation_grants_nothing() {
    let _lock = ENV_LOCK.lock().await;
    let temp = tempfile::tempdir().expect("temporary install root");
    let config_path = seed_install(temp.path());
    let _guard = ConfigDirGuard::pin(temp.path());

    // The production constructor, exactly as `zeroclaw control --mcp` calls it.
    // No environment variable, config value, or file on disk participates.
    let server = ControlMcpServer::new(config_path, TEST_VERSION);
    let listed = exchange(&server, &request(1, "tools/list", json!({}))).await;
    assert_eq!(listed_tool_names(&listed), ALWAYS_AVAILABLE);

    let info = tool_ok(&exchange(&server, &call(2, "control.server_info", json!({}))).await);
    assert_eq!(info["session"]["registration_state"], json!("unregistered"));
    assert_eq!(
        info["session"]["requester_class"],
        json!("external_requester")
    );
    assert_eq!(info["session"]["assurance_class"], Value::Null);
    assert_eq!(info["read_only"], json!(true));
    assert_eq!(info["mutation_tools"], json!([]));
}

#[tokio::test]
async fn no_session_can_see_a_tool_that_changes_host_state() {
    let _lock = ENV_LOCK.lock().await;
    let temp = tempfile::tempdir().expect("temporary install root");
    let config_path = seed_install(temp.path());
    let _guard = ConfigDirGuard::pin(temp.path());
    let factory = Arc::new(RecordingFactory::new());

    for (label, session, expected) in [
        (
            "unregistered",
            ControlSession::unregistered(),
            ALWAYS_AVAILABLE.to_vec(),
        ),
        (
            "fixture-granted",
            ControlSession::fixture_granted(RequesterGrant::fixture_full()),
            // Mutations are disabled on this bare install, so `control.request_apply`
            // — the one tool whose name carries a mutation verb — is absent from
            // the surface entirely. The two owner-scoped reads are present and
            // name no mutation verb.
            ALWAYS_AVAILABLE
                .iter()
                .chain(GRANT_GATED.iter())
                .chain(OWNER_SCOPED_READS.iter())
                .copied()
                .collect(),
        ),
    ] {
        let server = ControlMcpServer::with_service_and_session(
            service_with(&factory, &config_path),
            session,
            TEST_VERSION,
        );
        let listed = exchange(&server, &request(1, "tools/list", json!({}))).await;
        let names = listed_tool_names(&listed);
        assert_eq!(names, expected, "{label} session exposes an unexpected set");

        for name in &names {
            for word in name.split(['.', '_']) {
                assert!(
                    !MUTATION_VERBS.contains(&word),
                    "{label} session exposes `{name}`, whose `{word}` names a change to host state"
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Envelope, advertisement, and canonical-text parity
// ---------------------------------------------------------------------------

#[tokio::test]
async fn every_response_carries_the_envelope_and_a_byte_identical_canonical_text() {
    let _lock = ENV_LOCK.lock().await;
    let temp = tempfile::tempdir().expect("temporary install root");
    let config_path = seed_install(temp.path());
    let _guard = ConfigDirGuard::pin(temp.path());
    let factory = Arc::new(RecordingFactory::new());
    let server = ControlMcpServer::with_service_and_session(
        service_with(&factory, &config_path),
        ControlSession::fixture_granted(RequesterGrant::fixture_full()),
        TEST_VERSION,
    );
    let expected_digest = capability_digest(&CapabilitySet::current());
    let operation = serde_json::to_value(writer_operation()).expect("operation serializes");

    let calls = [
        ("control.ping", json!({})),
        ("control.server_info", json!({})),
        ("control.registration_help", json!({})),
        ("control.catalog", json!({})),
        (
            "control.describe",
            json!({ "operation_id": "agent.create_contained" }),
        ),
        ("control.inspect", json!({ "view": "agent.summary" })),
        (
            "control.validate",
            json!({
                "operation_id": "agent.create_contained",
                "operation": operation,
            }),
        ),
        (
            "control.preview",
            json!({
                "operation_id": "agent.create_contained",
                "operation": operation,
            }),
        ),
        // A refusal must carry the same canonical-text guarantee as a success.
        (
            "control.describe",
            json!({ "operation_id": "agent.no_such_operation" }),
        ),
    ];

    for (index, (name, arguments)) in calls.iter().enumerate() {
        let response = exchange(&server, &call(index as u64, name, arguments.clone())).await;
        let result = &response["result"];
        let structured = &result["structuredContent"];
        let text = result["content"][0]["text"]
            .as_str()
            .expect("every result carries one text content item");
        assert_eq!(
            canonical_json(structured),
            text,
            "{name}: structuredContent and content text must agree after canonical serialization"
        );
        assert_eq!(result["content"][0]["type"], json!("text"));

        if result["isError"] == json!(false) {
            assert_eq!(
                structured["control_protocol_version"],
                json!("1.0"),
                "{name} must carry the protocol version"
            );
            assert_eq!(
                structured["capability_digest"],
                json!(expected_digest),
                "{name} must repeat the capability digest"
            );
        }
    }
}

#[tokio::test]
async fn the_initialize_and_server_info_advertisements_are_byte_identical() {
    let _lock = ENV_LOCK.lock().await;
    let temp = tempfile::tempdir().expect("temporary install root");
    let config_path = seed_install(temp.path());
    let _guard = ConfigDirGuard::pin(temp.path());
    let factory = Arc::new(RecordingFactory::new());
    let server = ControlMcpServer::with_service_and_session(
        service_with(&factory, &config_path),
        ControlSession::unregistered(),
        TEST_VERSION,
    );

    let initialized = initialize(&server).await;
    let from_initialize = &initialized["result"]["_meta"]["zeroclaw_control"];
    let info = tool_ok(&exchange(&server, &call(2, "control.server_info", json!({}))).await);
    assert_eq!(
        canonical_json(from_initialize),
        canonical_json(&info["advertisement"])
    );
    assert_eq!(from_initialize["zeroclaw_version"], json!(TEST_VERSION));
    assert_eq!(from_initialize["control_protocol_version"], json!("1.0"));
    assert_eq!(
        from_initialize["config_schema_version"],
        json!(zeroclaw_config::migration::CURRENT_SCHEMA_VERSION)
    );
    assert_eq!(
        from_initialize["capabilities"],
        json!(["agents"]),
        "a phase-2 server implements contained agent creation only"
    );
}

// ---------------------------------------------------------------------------
// The granted walk, and transport parity with ControlService
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_fixture_granted_session_can_walk_the_whole_read_only_surface() {
    let _lock = ENV_LOCK.lock().await;
    let temp = tempfile::tempdir().expect("temporary install root");
    let config_path = seed_install(temp.path());
    let _guard = ConfigDirGuard::pin(temp.path());
    let factory = Arc::new(RecordingFactory::new());
    let server = ControlMcpServer::with_service_and_session(
        service_with(&factory, &config_path),
        ControlSession::fixture_granted(RequesterGrant::fixture_full()),
        TEST_VERSION,
    );
    let operation = serde_json::to_value(writer_operation()).expect("operation serializes");

    let catalog = tool_ok(&exchange(&server, &call(1, "control.catalog", json!({}))).await);
    let operations = catalog["operations"].as_array().expect("operations array");
    assert_eq!(operations.len(), 1);
    assert_eq!(
        operations[0]["operation_id"],
        json!("agent.create_contained")
    );
    assert_eq!(operations[0]["requires_approval"], json!(true));
    assert_eq!(operations[0]["meta_authority"], json!(false));

    let described = tool_ok(
        &exchange(
            &server,
            &call(
                2,
                "control.describe",
                json!({ "operation_id": "agent.create_contained" }),
            ),
        )
        .await,
    );
    assert!(
        described["request_schema"]["properties"]["provider_alias"].is_object(),
        "the request schema must be generated from the compiled operation type"
    );
    assert!(described["response_schema"]["properties"].is_object());
    assert!(
        described["requirements_digest"]
            .as_str()
            .is_some_and(|digest| digest.starts_with("sha256:"))
    );

    let agents = tool_ok(
        &exchange(
            &server,
            &call(3, "control.inspect", json!({ "view": "agent.summary" })),
        )
        .await,
    );
    assert_eq!(agents["view"], json!("agent.summary"));
    assert_eq!(agents["target"]["target_id"], json!("local"));
    assert_eq!(
        agents["items"],
        json!([]),
        "the fixture install has no agents"
    );
    assert_eq!(agents["observations"][0]["frozen"], json!(false));

    let providers = tool_ok(
        &exchange(
            &server,
            &call(
                4,
                "control.inspect",
                json!({ "view": "provider.alias_list" }),
            ),
        )
        .await,
    );
    assert_eq!(providers["items"][0]["alias"], json!("custom.fixture"));
    assert_eq!(providers["items"][0]["kind"], json!("provider_alias"));

    let validated = tool_ok(
        &exchange(
            &server,
            &call(
                5,
                "control.validate",
                json!({
                    "operation_id": "agent.create_contained",
                    "operation": operation,
                }),
            ),
        )
        .await,
    );
    assert_eq!(validated["valid"], json!(true));
    assert_eq!(validated["diagnostics"], json!([]));

    let previewed = tool_ok(
        &exchange(
            &server,
            &call(
                6,
                "control.preview",
                json!({
                    "operation_id": "agent.create_contained",
                    "operation": operation,
                }),
            ),
        )
        .await,
    );
    assert_eq!(previewed["durable"], json!(false));
    assert_eq!(previewed["irreversible_effects"], json!([]));
    assert_eq!(previewed["apply_order"], json!(["e1", "e2"]));
    assert_eq!(previewed["effects"][0]["artifact_kind"], json!("config"));
    assert_eq!(
        previewed["effects"][1]["artifact_kind"],
        json!("personality_file")
    );
    assert_eq!(
        previewed["operation_digest"], validated["operation_digest"],
        "validate and preview must name the same operation"
    );
    assert_eq!(previewed["source_revision"], validated["source_revision"]);

    // Nothing about a read-only walk touches the config on disk.
    assert_eq!(
        std::fs::read_to_string(&config_path).expect("read config"),
        PROVIDER_CONFIG,
        "no read-only tool may write the config"
    );
    assert!(
        !temp.path().join("agents").exists(),
        "no read-only tool may create an agent workspace"
    );
}

#[tokio::test]
async fn an_mcp_preview_equals_the_same_preview_taken_directly_from_control_service() {
    let _lock = ENV_LOCK.lock().await;
    let temp = tempfile::tempdir().expect("temporary install root");
    let config_path = seed_install(temp.path());
    let _guard = ConfigDirGuard::pin(temp.path());
    let factory = Arc::new(RecordingFactory::new());
    let operation = writer_operation();

    let server = ControlMcpServer::with_service_and_session(
        service_with(&factory, &config_path),
        ControlSession::fixture_granted(RequesterGrant::fixture_full()),
        TEST_VERSION,
    );
    let over_mcp: PreviewResult = serde_json::from_value(tool_ok(
        &exchange(
            &server,
            &call(
                1,
                "control.preview",
                json!({
                    "operation_id": "agent.create_contained",
                    "operation": serde_json::to_value(&operation).expect("serializes"),
                }),
            ),
        )
        .await,
    ))
    .expect("the preview result deserializes into the shared wire type");

    // The same operation, submitted to `ControlService` with no transport in
    // the way, projected through the same shared projection.
    let native = service_with(&factory, &config_path);
    let inspection = native.inspect().await.expect("inspect the seeded install");
    let revision = source_revision_id(inspection.source_revision());
    let bound = native
        .preview(
            inspection,
            &operation.provider_alias,
            &operation.to_proposal(),
        )
        .expect("preview the writer proposal");
    let directly = server.project_preview(bound.preview(), &revision);

    assert_eq!(over_mcp.operation_digest, directly.operation_digest);
    assert_eq!(over_mcp.dependency_digest, directly.dependency_digest);
    assert_eq!(over_mcp.source_revision, directly.source_revision);
    assert_eq!(over_mcp.target, directly.target);
    assert_eq!(over_mcp.effects, directly.effects);
    assert_eq!(over_mcp.apply_order, directly.apply_order);
    assert_eq!(over_mcp.irreversible_effects, directly.irreversible_effects);
    assert_eq!(over_mcp.risks, directly.risks);
    assert_eq!(over_mcp.verification_plan, directly.verification_plan);
    assert_eq!(over_mcp.durable, directly.durable);
    assert_eq!(
        over_mcp.config_schema_version,
        directly.config_schema_version
    );
    // The digest computed from the submitted operation and the digest computed
    // from the host's own preview must agree, or a rejected `control.validate`
    // would name a different operation than `control.preview` accepted.
    assert_eq!(
        operation_digest_for(&operation),
        operation_digest(bound.preview())
    );
    // `preview_id` and `expires_at` are the only fields allowed to differ; both
    // are process-local and carry no authority.
    assert_ne!(over_mcp.preview_id, String::new());
    assert!(over_mcp.preview_id.starts_with("prv_"));
}

#[tokio::test]
async fn the_operation_digest_ignores_the_order_personality_files_were_submitted_in() {
    let mut reordered = writer_operation();
    reordered.personality_files.push(PersonalityFileProposal {
        filename: "IDENTITY.md".to_string(),
        content: "# Identity".to_string(),
    });
    let mut swapped = reordered.clone();
    swapped.personality_files.reverse();
    assert_eq!(
        operation_digest_for(&reordered),
        operation_digest_for(&swapped),
        "the framework, not the caller, chooses the canonical field order"
    );
}

// ---------------------------------------------------------------------------
// The typed error table
// ---------------------------------------------------------------------------

#[tokio::test]
async fn every_error_code_in_the_v1_table_is_producible_and_carries_no_host_detail() {
    let _lock = ENV_LOCK.lock().await;
    let temp = tempfile::tempdir().expect("temporary install root");
    let config_path = seed_install(temp.path());
    let _guard = ConfigDirGuard::pin(temp.path());
    let factory = Arc::new(RecordingFactory::new());
    let root = temp.path().display().to_string();
    let operation = serde_json::to_value(writer_operation()).expect("operation serializes");
    let mut seen: Vec<String> = Vec::new();

    let unregistered = ControlMcpServer::with_service_and_session(
        service_with(&factory, &config_path),
        ControlSession::unregistered(),
        TEST_VERSION,
    );
    let granted = ControlMcpServer::with_service_and_session(
        service_with(&factory, &config_path),
        ControlSession::fixture_granted(RequesterGrant::fixture_full()),
        TEST_VERSION,
    );
    // A grant that covers only the agent summary, so an ungranted-but-defined
    // view is distinguishable from an unregistered session.
    let narrow = ControlMcpServer::with_service_and_session(
        service_with(&factory, &config_path),
        ControlSession::fixture_granted(RequesterGrant::fixture(
            &["agent.summary"],
            &[PROPOSAL_DOMAIN_AGENT],
        )),
        TEST_VERSION,
    );
    // A service pinned at a path that does not exist, so the canonical read
    // fails as a host error rather than as a validation verdict.
    let broken = ControlMcpServer::with_service_and_session(
        service_with(&factory, &temp.path().join("absent").join("config.toml")),
        ControlSession::fixture_granted(RequesterGrant::fixture_full()),
        TEST_VERSION,
    );

    let cases: Vec<(&ControlMcpServer, &str, Value, &str)> = vec![
        (
            &unregistered,
            "control.inspect",
            json!({ "view": "agent.summary" }),
            "unregistered_client",
        ),
        (
            &narrow,
            "control.inspect",
            json!({ "view": "provider.alias_list" }),
            "grant_required",
        ),
        (
            &granted,
            "control.describe",
            json!({ "operation_id": "agent.delete" }),
            "unknown_operation",
        ),
        (
            &granted,
            "control.inspect",
            json!({ "view": "agent.summary", "target": { "target_id": "inst_elsewhere" } }),
            "target_not_registered",
        ),
        (
            &granted,
            "control.preview",
            json!({
                "operation_id": "agent.create_contained",
                "operation": { "provider_alias": "custom.absent", "agent_alias": "writer",
                               "risk": "locked_down", "runtime": "tight", "memory": "markdown",
                               "personality_files": [] },
            }),
            "validation_failed",
        ),
        (
            &granted,
            "control.preview",
            json!({
                "operation_id": "agent.create_contained",
                "operation": operation,
                "capability_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            }),
            "capability_digest_mismatch",
        ),
        (
            &granted,
            "control.preview",
            json!({
                "operation_id": "agent.create_contained",
                "operation": operation,
                "source_revision": "rev_0000000000000000000000000000000000000000000000000000000000000000",
            }),
            "stale_source_revision",
        ),
        (
            &broken,
            "control.inspect",
            json!({ "view": "agent.summary" }),
            "internal_error",
        ),
    ];

    for (index, (server, name, arguments, expected)) in cases.iter().enumerate() {
        let response = exchange(server, &call(100 + index as u64, name, arguments.clone())).await;
        assert_eq!(
            error_code(&response),
            *expected,
            "{name} with {arguments} should have produced {expected}"
        );
        let payload = tool_err(&response);
        assert_eq!(payload["operation"], json!(*name));
        assert!(payload["message"].is_string());
        let serialized = serde_json::to_string(&response).expect("response serializes");
        assert!(
            !serialized.contains(&root),
            "{expected} disclosed the install root: {serialized}"
        );
        seen.push((*expected).to_string());
    }

    // `mutations_disabled` is a phase-5 refusal: a registered session on a
    // mutations-disabled instance (this bare install) parks nothing.
    {
        let response = exchange(
            &granted,
            &call(
                200,
                "control.request_apply",
                json!({ "operation_id": "agent.create_contained", "operation": operation }),
            ),
        )
        .await;
        assert_eq!(error_code(&response), "mutations_disabled");
        let serialized = serde_json::to_string(&response).expect("response serializes");
        assert!(
            !serialized.contains(&root),
            "mutations_disabled disclosed the install root"
        );
        seen.push("mutations_disabled".to_string());
    }

    // `quota_exceeded` needs a managed, mutations-enabled instance parked to its
    // per-requester quota. `Quotas::default().max_awaiting_approval` is 8, so the
    // ninth concurrent park is refused without evicting any prior entry.
    {
        let install = ManagedInstall::new();
        let inner_guard = ConfigDirGuard::pin(install.root());
        enable_mutations(&install);
        let (id, credential_path) = install.register(
            &install.full_grant(CredentialDelivery::IsolatedDescriptor),
            "quota.cred",
        );
        let host = start_with_descriptor(&install, &id, &credential_path)
            .await
            .expect("the credential authenticates");
        let server = host.server();
        let mut last = json!(null);
        for n in 0..9u64 {
            last = exchange(
                server,
                &call(300 + n, "control.request_apply", request_apply_args()),
            )
            .await;
        }
        assert_eq!(
            error_code(&last),
            "quota_exceeded",
            "the ninth concurrent park exceeds the quota"
        );
        let serialized = serde_json::to_string(&last).expect("response serializes");
        assert!(
            !serialized.contains(&install.root().display().to_string()),
            "quota_exceeded disclosed the install root"
        );
        seen.push("quota_exceeded".to_string());
        drop(inner_guard);
    }

    // `unsupported_protocol_version` is a lifecycle refusal, so it arrives as a
    // JSON-RPC error carrying the same typed payload rather than as a tool
    // result.
    let refused = exchange(
        &unregistered,
        &request(
            1,
            "initialize",
            json!({
                "protocolVersion": "2024-11-05",
                "_meta": {
                    "zeroclaw_control": {
                        "supported_control_protocol_versions": ["2.0", "3.1"],
                    },
                },
            }),
        ),
    )
    .await;
    assert_eq!(
        refused["error"]["data"]["error"]["code"],
        json!("unsupported_protocol_version"),
        "an unknown control-protocol major version must fail closed"
    );
    assert!(refused["result"].is_null());
    seen.push("unsupported_protocol_version".to_string());

    seen.sort();
    seen.dedup();
    let mut expected: Vec<String> = ControlErrorCode::ALL
        .iter()
        .map(|code| code.as_str().to_string())
        .collect();
    expected.sort();
    assert_eq!(
        seen, expected,
        "every code in the v1 table must be reachable from this transport"
    );
}

#[tokio::test]
async fn an_unknown_tool_name_is_an_unknown_operation_rather_than_a_partial_behavior() {
    let _lock = ENV_LOCK.lock().await;
    let temp = tempfile::tempdir().expect("temporary install root");
    let config_path = seed_install(temp.path());
    let _guard = ConfigDirGuard::pin(temp.path());
    let factory = Arc::new(RecordingFactory::new());
    let server = ControlMcpServer::with_service_and_session(
        service_with(&factory, &config_path),
        ControlSession::fixture_granted(RequesterGrant::fixture_full()),
        TEST_VERSION,
    );

    // `control.request_apply`, `control.status`, and `control.verify` now exist,
    // so they are covered by the phase-5 tests. The names that must still NOT
    // exist are the config-mutating and approval verbs: there is no
    // model-callable apply, approve, reject, finalize, or registration.
    for name in [
        "control.apply",
        "control.approve",
        "control.reject",
        "control.finalize",
        "control.commit",
        "control.enable_mutations",
        "control.register",
    ] {
        let response = exchange(&server, &call(1, name, json!({}))).await;
        assert_eq!(
            error_code(&response),
            "unknown_operation",
            "{name} must not exist even for a fully granted session"
        );
    }
}

// ---------------------------------------------------------------------------
// Redaction fixtures
// ---------------------------------------------------------------------------

#[tokio::test]
async fn no_successful_response_discloses_an_install_path_or_a_credential() {
    let _lock = ENV_LOCK.lock().await;
    let temp = tempfile::tempdir().expect("temporary install root");
    let config_path = seed_install(temp.path());
    let _guard = ConfigDirGuard::pin(temp.path());
    let factory = Arc::new(RecordingFactory::new());
    let server = ControlMcpServer::with_service_and_session(
        service_with(&factory, &config_path),
        ControlSession::fixture_granted(RequesterGrant::fixture_full()),
        TEST_VERSION,
    );
    let root = temp.path().display().to_string();
    let operation = serde_json::to_value(writer_operation()).expect("operation serializes");

    let responses = [
        exchange(
            &server,
            &call(1, "control.inspect", json!({ "view": "agent.summary" })),
        )
        .await,
        exchange(
            &server,
            &call(
                2,
                "control.inspect",
                json!({ "view": "provider.alias_list" }),
            ),
        )
        .await,
        exchange(
            &server,
            &call(
                3,
                "control.preview",
                json!({ "operation_id": "agent.create_contained", "operation": operation }),
            ),
        )
        .await,
    ];

    for response in &responses {
        let serialized = serde_json::to_string(response).expect("response serializes");
        assert!(
            !serialized.contains(&root),
            "a result disclosed the install root: {serialized}"
        );
        assert!(
            !serialized.contains("fixture-placeholder"),
            "a result disclosed a credential: {serialized}"
        );
        assert!(
            !serialized.contains("http://127.0.0.1:1"),
            "a result disclosed a provider endpoint: {serialized}"
        );
        assert!(
            !serialized.contains("config.toml"),
            "a result disclosed a config filename: {serialized}"
        );
    }
}

#[tokio::test]
async fn a_validation_failure_names_the_field_without_echoing_the_rejected_value() {
    let _lock = ENV_LOCK.lock().await;
    let temp = tempfile::tempdir().expect("temporary install root");
    let config_path = seed_install(temp.path());
    let _guard = ConfigDirGuard::pin(temp.path());
    let factory = Arc::new(RecordingFactory::new());
    let server = ControlMcpServer::with_service_and_session(
        service_with(&factory, &config_path),
        ControlSession::fixture_granted(RequesterGrant::fixture_full()),
        TEST_VERSION,
    );

    let secretish_alias = "sk-live-do-not-echo-this-anywhere";
    let response = exchange(
        &server,
        &call(
            1,
            "control.validate",
            json!({
                "operation_id": "agent.create_contained",
                "operation": {
                    "provider_alias": secretish_alias,
                    "agent_alias": "writer",
                    "risk": "locked_down",
                    "runtime": "tight",
                    "memory": "markdown",
                    "personality_files": [],
                },
            }),
        ),
    )
    .await;

    let result = tool_ok(&response);
    assert_eq!(result["valid"], json!(false));
    assert_eq!(
        result["diagnostics"][0]["code"],
        json!("provider_alias_unknown")
    );
    assert_eq!(result["diagnostics"][0]["path"], json!("provider"));
    assert_eq!(result["diagnostics"][0]["severity"], json!("error"));

    let serialized = serde_json::to_string(&response).expect("response serializes");
    assert!(
        !serialized.contains(secretish_alias),
        "a diagnostic echoed the rejected value: {serialized}"
    );
    assert!(!serialized.contains(&temp.path().display().to_string()));
}

// ---------------------------------------------------------------------------
// No model request, and stdout framing
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_full_read_only_session_constructs_no_model_provider() {
    let _lock = ENV_LOCK.lock().await;
    let temp = tempfile::tempdir().expect("temporary install root");
    let config_path = seed_install(temp.path());
    let _guard = ConfigDirGuard::pin(temp.path());
    let factory = Arc::new(RecordingFactory::new());
    let server = ControlMcpServer::with_service_and_session(
        service_with(&factory, &config_path),
        ControlSession::fixture_granted(RequesterGrant::fixture_full()),
        TEST_VERSION,
    );
    let operation = serde_json::to_value(writer_operation()).expect("operation serializes");

    initialize(&server).await;
    exchange(&server, &request(2, "tools/list", json!({}))).await;
    for (index, (name, arguments)) in [
        ("control.ping", json!({})),
        ("control.server_info", json!({})),
        ("control.registration_help", json!({})),
        ("control.catalog", json!({})),
        (
            "control.describe",
            json!({ "operation_id": "agent.create_contained" }),
        ),
        ("control.inspect", json!({ "view": "agent.summary" })),
        ("control.inspect", json!({ "view": "provider.alias_list" })),
        (
            "control.validate",
            json!({ "operation_id": "agent.create_contained", "operation": operation }),
        ),
        (
            "control.preview",
            json!({ "operation_id": "agent.create_contained", "operation": operation }),
        ),
    ]
    .iter()
    .enumerate()
    {
        exchange(&server, &call(10 + index as u64, name, arguments.clone())).await;
    }

    assert_eq!(
        factory.creations.load(Ordering::SeqCst),
        0,
        "no tool may construct a model provider"
    );
    assert!(
        factory.validations.load(Ordering::SeqCst) > 0,
        "the walk must actually have consulted the provider inventory, or this \
         test would pass for the wrong reason"
    );
}

#[tokio::test]
async fn stdout_carries_only_a_clean_sequence_of_json_rpc_frames() {
    let _lock = ENV_LOCK.lock().await;
    let temp = tempfile::tempdir().expect("temporary install root");
    let config_path = seed_install(temp.path());
    let _guard = ConfigDirGuard::pin(temp.path());
    let factory = Arc::new(RecordingFactory::new());
    let mut server = ControlMcpServer::with_service_and_session(
        service_with(&factory, &config_path),
        ControlSession::unregistered(),
        TEST_VERSION,
    );

    // A realistic client script, plus the two frames a server must survive
    // without corrupting the channel: a notification, which gets no answer at
    // all, and a garbage line, which gets a parse error and does not stop the
    // session.
    let script = [
        serde_json::to_string(&request(1, "initialize", json!({}))).expect("serializes"),
        serde_json::to_string(&json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": {},
        }))
        .expect("serializes"),
        "not json at all".to_string(),
        String::new(),
        serde_json::to_string(&request(2, "tools/list", json!({}))).expect("serializes"),
        serde_json::to_string(&call(3, "control.ping", json!({}))).expect("serializes"),
        serde_json::to_string(&request(4, "no/such/method", json!({}))).expect("serializes"),
    ]
    .join("\n");

    let mut stdout: Vec<u8> = Vec::new();
    server
        .serve(script.as_bytes(), &mut stdout)
        .await
        .expect("the session ends cleanly at end of input");

    let text = String::from_utf8(stdout).expect("stdout is valid UTF-8");
    assert!(
        text.ends_with('\n'),
        "every frame must be newline-terminated"
    );
    let frames: Vec<Value> = text
        .lines()
        .map(|line| {
            serde_json::from_str::<Value>(line).unwrap_or_else(|error| {
                panic!("stdout line is not a JSON-RPC frame: {line} ({error})")
            })
        })
        .collect();

    assert_eq!(
        frames.len(),
        5,
        "one frame per request with an id, and none for the notification or the blank line"
    );
    for frame in &frames {
        assert_eq!(frame["jsonrpc"], json!("2.0"));
    }
    assert_eq!(frames[0]["id"], json!(1));
    assert!(frames[0]["result"]["_meta"]["zeroclaw_control"].is_object());
    // The garbage line answers with a parse error and a null id, then the
    // session carries on.
    assert_eq!(frames[1]["id"], Value::Null);
    assert_eq!(frames[1]["error"]["code"], json!(-32700));
    assert_eq!(frames[2]["id"], json!(2));
    assert_eq!(listed_tool_names(&frames[2]), ALWAYS_AVAILABLE);
    assert_eq!(frames[3]["id"], json!(3));
    assert_eq!(
        frames[3]["result"]["structuredContent"]["result"]["ok"],
        json!(true)
    );
    assert_eq!(frames[4]["id"], json!(4));
    assert_eq!(frames[4]["error"]["code"], json!(-32601));
}

#[tokio::test]
async fn what_a_client_declares_at_initialize_cannot_widen_the_surface_it_gets() {
    let _lock = ENV_LOCK.lock().await;
    let temp = tempfile::tempdir().expect("temporary install root");
    let config_path = seed_install(temp.path());
    let _guard = ConfigDirGuard::pin(temp.path());
    let factory = Arc::new(RecordingFactory::new());

    // Three clients that differ only in what they declare: one that declares
    // the current version, one that declares nothing, and one that claims to
    // be an older minor. None of them may negotiate its way past the
    // registration gate, and none may negotiate a different tool list.
    for declared in [
        json!({ "supported_control_protocol_versions": ["1.0"] }),
        json!({}),
        json!({ "supported_control_protocol_versions": ["1.0", "1.4"] }),
    ] {
        let server = ControlMcpServer::with_service_and_session(
            service_with(&factory, &config_path),
            ControlSession::unregistered(),
            TEST_VERSION,
        );
        let initialized = exchange(
            &server,
            &request(
                1,
                "initialize",
                json!({ "protocolVersion": "2024-11-05", "_meta": { "zeroclaw_control": declared } }),
            ),
        )
        .await;
        assert_eq!(
            initialized["result"]["_meta"]["zeroclaw_control"]["control_protocol_version"],
            json!("1.0"),
            "the server advertises its own version regardless of what was declared"
        );

        let listed = exchange(&server, &request(2, "tools/list", json!({}))).await;
        assert_eq!(
            listed_tool_names(&listed),
            ALWAYS_AVAILABLE,
            "negotiation must not change which tools an unregistered session sees"
        );
        assert_eq!(
            error_code(
                &exchange(
                    &server,
                    &call(3, "control.inspect", json!({ "view": "agent.summary" }))
                )
                .await
            ),
            "unregistered_client",
            "negotiation must not remove the registration check"
        );
    }
}

// ---------------------------------------------------------------------------
// Production client authentication
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_registered_client_walks_the_whole_read_only_surface_and_leaks_no_secret() {
    let _lock = ENV_LOCK.lock().await;
    let install = ManagedInstall::new();
    let _guard = ConfigDirGuard::pin(install.root());
    let (id, credential_path) = install.register(
        &install.full_grant(CredentialDelivery::IsolatedDescriptor),
        "client.cred",
    );
    let secret = install.secret(&credential_path);

    let host = start_with_descriptor(&install, &id, &credential_path)
        .await
        .expect("the issued credential authenticates over the real transport");
    let server = host.server();
    let operation = serde_json::to_value(writer_operation()).expect("operation serializes");

    // Every frame of the session is kept, so the secret check at the end covers
    // the whole conversation rather than one hand-picked response.
    let initialized = initialize(server).await;
    let listed = exchange(server, &request(2, "tools/list", json!({}))).await;
    assert_eq!(
        listed_tool_names(&listed),
        ALWAYS_AVAILABLE
            .iter()
            .chain(GRANT_GATED.iter())
            .chain(OWNER_SCOPED_READS.iter())
            .copied()
            .collect::<Vec<_>>(),
        "a full registration on a mutations-disabled instance lists the read tools \
         and the two owner-scoped reads, but not control.request_apply"
    );

    let info_frame = exchange(server, &call(3, "control.server_info", json!({}))).await;
    let info = tool_ok(&info_frame);
    assert_eq!(info["session"]["registration_state"], json!("registered"));
    assert_eq!(
        info["session"]["requester_class"],
        json!("external_requester"),
        "a verified credential creates a requester, never anything stronger"
    );
    assert_eq!(
        info["session"]["assurance_class"],
        json!("isolated_descriptor"),
        "the reported class is the mechanism that was actually used"
    );
    assert_eq!(info["read_only"], json!(true));
    assert_eq!(info["mutation_tools"], json!([]));

    let help_frame = exchange(server, &call(4, "control.registration_help", json!({}))).await;
    assert_eq!(
        tool_ok(&help_frame)["registration_state"],
        json!("registered")
    );

    let catalog_frame = exchange(server, &call(5, "control.catalog", json!({}))).await;
    assert_eq!(
        tool_ok(&catalog_frame)["operations"][0]["operation_id"],
        json!("agent.create_contained")
    );

    let describe_frame = exchange(
        server,
        &call(
            6,
            "control.describe",
            json!({ "operation_id": "agent.create_contained" }),
        ),
    )
    .await;
    assert!(tool_ok(&describe_frame)["request_schema"]["properties"]["provider_alias"].is_object());

    let agents_frame = exchange(
        server,
        &call(7, "control.inspect", json!({ "view": "agent.summary" })),
    )
    .await;
    assert_eq!(
        tool_ok(&agents_frame)["target"]["target_id"],
        json!("local")
    );

    let providers_frame = exchange(
        server,
        &call(
            8,
            "control.inspect",
            json!({ "view": "provider.alias_list" }),
        ),
    )
    .await;
    assert_eq!(
        tool_ok(&providers_frame)["items"][0]["alias"],
        json!("custom.fixture")
    );

    let validate_frame = exchange(
        server,
        &call(
            9,
            "control.validate",
            json!({ "operation_id": "agent.create_contained", "operation": operation }),
        ),
    )
    .await;
    assert_eq!(tool_ok(&validate_frame)["valid"], json!(true));

    let preview_frame = exchange(
        server,
        &call(
            10,
            "control.preview",
            json!({ "operation_id": "agent.create_contained", "operation": operation }),
        ),
    )
    .await;
    let previewed: PreviewResult =
        serde_json::from_value(tool_ok(&preview_frame)).expect("the preview deserializes");
    assert!(!previewed.durable);

    let ping_frame = exchange(server, &call(11, "control.ping", json!({}))).await;
    let session: Vec<Value> = vec![
        initialized,
        listed,
        info_frame,
        help_frame,
        catalog_frame,
        describe_frame,
        agents_frame,
        providers_frame,
        validate_frame,
        preview_frame,
        ping_frame,
    ];

    // Transport parity: the same operation submitted straight to
    // `ControlService`, projected through the same shared projection.
    let native = ControlService::new(install.config_path.clone(), Surface::Cli);
    let inspection = native.inspect().await.expect("inspect the managed install");
    let revision = source_revision_id(inspection.source_revision());
    let operation_typed = writer_operation();
    let bound = native
        .preview(
            inspection,
            &operation_typed.provider_alias,
            &operation_typed.to_proposal(),
        )
        .expect("preview the writer proposal");
    let directly = server.project_preview(bound.preview(), &revision);
    assert_eq!(previewed.operation_digest, directly.operation_digest);
    assert_eq!(previewed.dependency_digest, directly.dependency_digest);
    assert_eq!(previewed.source_revision, directly.source_revision);
    assert_eq!(previewed.target, directly.target);
    assert_eq!(previewed.effects, directly.effects);
    assert_eq!(previewed.apply_order, directly.apply_order);
    assert_eq!(previewed.risks, directly.risks);
    assert_eq!(previewed.verification_plan, directly.verification_plan);
    assert_eq!(
        operation_digest_for(&operation_typed),
        operation_digest(bound.preview())
    );

    // The whole conversation, checked for the secret in every encoding a frame
    // could carry it in.
    let transcript = serde_json::to_string(&session).expect("the session serializes");
    assert_eq!(secret.len(), 64, "the credential file holds 64 hex bytes");
    assert!(
        !transcript.contains(&secret),
        "a frame carried the credential"
    );
    assert!(
        !transcript.contains(&secret.to_uppercase()),
        "a frame carried the credential in another case"
    );
    assert!(
        !transcript.contains(id.as_str()),
        "a frame carried the registration id, which server_info has no field for"
    );
    assert!(
        !transcript.contains(&install.root().display().to_string()),
        "a frame carried the install root"
    );
    assert!(
        !transcript.contains("component-client"),
        "a frame carried the client label"
    );
}

#[tokio::test]
async fn a_partial_registration_lists_partial_tools_and_refuses_the_rest() {
    let _lock = ENV_LOCK.lock().await;
    let install = ManagedInstall::new();
    let _guard = ConfigDirGuard::pin(install.root());

    let partial = ClientGrant {
        client_label: ClientLabel::new("partial").expect("label"),
        delivery_assurance: CredentialDelivery::IsolatedDescriptor,
        granted_instances: [install.instance_id.clone()].into_iter().collect(),
        granted_read_domains: ["agent.summary".to_string(), "control.catalog".to_string()]
            .into_iter()
            .collect(),
        proposal_domains: [PROPOSAL_DOMAIN_AGENT.to_string()].into_iter().collect(),
    };
    let (id, credential_path) = install.register(&partial, "partial.cred");

    let host = start_with_descriptor(&install, &id, &credential_path)
        .await
        .expect("the issued credential authenticates");
    let server = host.server();

    let listed = exchange(server, &request(1, "tools/list", json!({}))).await;
    assert_eq!(
        listed_tool_names(&listed),
        vec![
            "control.ping",
            "control.server_info",
            "control.registration_help",
            "control.catalog",
            "control.inspect",
        ],
        "a registration granting two read domains lists two gated tools"
    );

    // The granted ones answer.
    assert_eq!(
        exchange(server, &call(2, "control.catalog", json!({}))).await["result"]["isError"],
        json!(false)
    );
    assert_eq!(
        exchange(
            server,
            &call(3, "control.inspect", json!({ "view": "agent.summary" }))
        )
        .await["result"]["isError"],
        json!(false)
    );

    // The ungranted ones refuse by name, even though they were never listed.
    for name in ["control.describe", "control.validate", "control.preview"] {
        let response = exchange(server, &call(4, name, json!({ "operation_id": "x" }))).await;
        assert_eq!(
            error_code(&response),
            "grant_required",
            "{name} must refuse a registered client that was not granted it"
        );
    }
    // And so does the view inside a tool it does hold.
    assert_eq!(
        error_code(
            &exchange(
                server,
                &call(
                    5,
                    "control.inspect",
                    json!({ "view": "provider.alias_list" })
                )
            )
            .await
        ),
        "grant_required"
    );
}

#[tokio::test]
async fn a_credential_that_does_not_verify_refuses_loudly_instead_of_downgrading() {
    let _lock = ENV_LOCK.lock().await;
    let install = ManagedInstall::new();
    let _guard = ConfigDirGuard::pin(install.root());
    let (id, credential_path) = install.register(
        &install.full_grant(CredentialDelivery::IsolatedDescriptor),
        "client.cred",
    );

    // A syntactically perfect credential that is not this client's.
    let wrong = install.root().join("wrong.cred");
    std::fs::write(&wrong, format!("{}\n", "ab".repeat(32))).expect("write a wrong credential");
    let refused = start_with_descriptor(&install, &id, &wrong).await;
    assert_eq!(
        refusal_code(&refused, "a wrong secret"),
        StartupRefusalCode::CredentialRejected,
    );

    // The refusal is a refusal, not a quieter session: nothing about it yields
    // a server at all, so there is no unregistered surface to fall back to.
    assert!(refused.is_err());

    // A client identifier that names no registration.
    let unknown = ControlLaunch::resolve(Some("reg-00000000000000000000".to_string()), None);
    let unknown = match unknown {
        Ok(_) => panic!("no descriptor is set, so this must not resolve"),
        Err(refusal) => refusal,
    };
    assert_eq!(
        unknown.code,
        StartupRefusalCode::CredentialMechanismInvalid,
        "an identifier with no mechanism is a launch error, not a rejected credential"
    );

    // And the correct presentation still works, so nothing above passed for the
    // wrong reason.
    assert!(
        start_with_descriptor(&install, &id, &credential_path)
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn a_revoked_registration_refuses() {
    let _lock = ENV_LOCK.lock().await;
    let install = ManagedInstall::new();
    let _guard = ConfigDirGuard::pin(install.root());
    let (id, credential_path) = install.register(
        &install.full_grant(CredentialDelivery::IsolatedDescriptor),
        "client.cred",
    );
    assert!(
        start_with_descriptor(&install, &id, &credential_path)
            .await
            .is_ok(),
        "the registration authenticates before revocation"
    );

    install.revoke(&id);

    let refused = start_with_descriptor(&install, &id, &credential_path).await;
    assert_eq!(
        refusal_code(&refused, "a revoked registration"),
        StartupRefusalCode::CredentialRejected,
        "revocation fails closed and is indistinguishable from a wrong secret"
    );
}

#[tokio::test]
async fn a_delivery_class_mismatch_refuses() {
    let _lock = ENV_LOCK.lock().await;
    let install = ManagedInstall::new();
    let _guard = ConfigDirGuard::pin(install.root());
    // Registered for the inherited descriptor...
    let (id, credential_path) = install.register(
        &install.full_grant(CredentialDelivery::IsolatedDescriptor),
        "client.cred",
    );

    // ...but presented through a helper, which is the other class.
    #[cfg(unix)]
    {
        let helper = write_helper(
            install.root(),
            "read-credential",
            &format!("cat {}", credential_path.display()),
        );
        let launch = ControlLaunch::resolve(Some(id.as_str().to_string()), Some(helper))
            .expect("the helper launch resolves");
        let refused =
            zeroclaw::control_mcp::start(install.config_path.clone(), TEST_VERSION, launch).await;
        assert_eq!(
            refusal_code(
                &refused,
                "a credential presented through the wrong mechanism"
            ),
            StartupRefusalCode::DeliveryClassMismatch,
            "the mechanism used is the class presented; it is not a claim the client makes"
        );
    }

    // The descriptor mechanism still works for the same registration.
    assert!(
        start_with_descriptor(&install, &id, &credential_path)
            .await
            .is_ok()
    );
}

#[cfg(unix)]
#[tokio::test]
async fn a_credential_helper_delivers_the_sandbox_isolated_store_class() {
    let _lock = ENV_LOCK.lock().await;
    let install = ManagedInstall::new();
    let _guard = ConfigDirGuard::pin(install.root());
    let (id, credential_path) = install.register(
        &install.full_grant(CredentialDelivery::SandboxIsolatedStore),
        "client.cred",
    );
    let secret = install.secret(&credential_path);

    let helper = write_helper(
        install.root(),
        "read-credential",
        &format!("cat {}", credential_path.display()),
    );
    let launch = ControlLaunch::resolve(Some(id.as_str().to_string()), Some(helper))
        .expect("the helper launch resolves");
    let host = zeroclaw::control_mcp::start(install.config_path.clone(), TEST_VERSION, launch)
        .await
        .expect("the helper's credential authenticates");

    let info = tool_ok(&exchange(host.server(), &call(1, "control.server_info", json!({}))).await);
    assert_eq!(info["session"]["registration_state"], json!("registered"));
    assert_eq!(
        info["session"]["assurance_class"],
        json!("sandbox_isolated_store")
    );
    let serialized = serde_json::to_string(&info).expect("serializes");
    assert!(
        !serialized.contains(&secret),
        "server_info carried the secret"
    );

    // A helper that fails is a refusal, not a downgrade.
    let broken = write_helper(install.root(), "broken-helper", "exit 3");
    let launch = ControlLaunch::resolve(Some(id.as_str().to_string()), Some(broken))
        .expect("the helper launch resolves");
    let refused =
        zeroclaw::control_mcp::start(install.config_path.clone(), TEST_VERSION, launch).await;
    assert_eq!(
        refusal_code(&refused, "a helper that exits nonzero"),
        StartupRefusalCode::CredentialUnavailable
    );

    // So is one that prints something that is not a credential.
    let noisy = write_helper(install.root(), "noisy-helper", "echo not-a-credential");
    let launch = ControlLaunch::resolve(Some(id.as_str().to_string()), Some(noisy))
        .expect("the helper launch resolves");
    let refused =
        zeroclaw::control_mcp::start(install.config_path.clone(), TEST_VERSION, launch).await;
    assert_eq!(
        refusal_code(&refused, "a helper that prints garbage"),
        StartupRefusalCode::CredentialUnavailable
    );
}

/// Costs one real timeout. The bound is a wall-clock property of the startup
/// path, and a test that mocked the clock would not prove the child is actually
/// abandoned.
#[cfg(unix)]
#[tokio::test]
async fn a_credential_helper_that_hangs_is_refused_rather_than_waited_on() {
    let _lock = ENV_LOCK.lock().await;
    let install = ManagedInstall::new();
    let _guard = ConfigDirGuard::pin(install.root());
    let (id, _credential_path) = install.register(
        &install.full_grant(CredentialDelivery::SandboxIsolatedStore),
        "client.cred",
    );

    let slow = write_helper(install.root(), "slow-helper", "sleep 120");
    let launch = ControlLaunch::resolve(Some(id.as_str().to_string()), Some(slow))
        .expect("the helper launch resolves");
    let started = std::time::Instant::now();
    let refused =
        zeroclaw::control_mcp::start(install.config_path.clone(), TEST_VERSION, launch).await;
    let elapsed = started.elapsed();

    assert_eq!(
        refusal_code(&refused, "a helper that never returns"),
        StartupRefusalCode::CredentialUnavailable
    );
    assert!(
        elapsed < std::time::Duration::from_secs(60),
        "the helper timeout must bound startup, took {elapsed:?}"
    );
}

#[tokio::test]
async fn a_second_control_process_is_refused_while_one_holds_the_host_lock() {
    let _lock = ENV_LOCK.lock().await;
    let install = ManagedInstall::new();
    let _guard = ConfigDirGuard::pin(install.root());
    let (id, credential_path) = install.register(
        &install.full_grant(CredentialDelivery::IsolatedDescriptor),
        "client.cred",
    );

    let first = start_with_descriptor(&install, &id, &credential_path)
        .await
        .expect("the first registered host starts");

    let second = start_with_descriptor(&install, &id, &credential_path).await;
    assert_eq!(
        refusal_code(&second, "a second host on one instance"),
        StartupRefusalCode::HostAlreadyServing,
    );

    // The lock is a property of the live open file description, not of a file
    // on disk: drop the holder and the next host starts, with no cleanup step
    // in between.
    //
    // Retried because the lock is scoped to an open file description and
    // `fork()` duplicates a whole descriptor table. Any other test in this
    // binary that spawns a subprocess at the instant our descriptor is open
    // hands that child an inherited reference that outlives our `drop`. The
    // children involved are short-lived, so a bounded retry distinguishes "the
    // lock was never released" from "someone else briefly held a copy".
    drop(first);
    let mut third = start_with_descriptor(&install, &id, &credential_path).await;
    for _ in 0..20 {
        if third.is_ok() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        third = start_with_descriptor(&install, &id, &credential_path).await;
    }
    assert!(
        third.is_ok(),
        "releasing the lock must not need a stale-lock policy"
    );
    assert!(
        install.paths.control_dir().join("host.lock").exists(),
        "the placeholder file survives, and carries no state"
    );
}

#[tokio::test]
async fn a_launch_with_no_credential_options_is_the_unchanged_unregistered_session() {
    let _lock = ENV_LOCK.lock().await;
    let install = ManagedInstall::new();
    let _guard = ConfigDirGuard::pin(install.root());
    // A registered client exists on this instance and is not being presented.
    install.register(
        &install.full_grant(CredentialDelivery::IsolatedDescriptor),
        "client.cred",
    );

    let launch = ControlLaunch::resolve(None, None).expect("an empty launch resolves");
    assert!(!launch.presents_credential());
    let host = zeroclaw::control_mcp::start(install.config_path.clone(), TEST_VERSION, launch)
        .await
        .expect("an unregistered host always starts");
    let server = host.server();

    let listed = exchange(server, &request(1, "tools/list", json!({}))).await;
    assert_eq!(
        listed_tool_names(&listed),
        ALWAYS_AVAILABLE,
        "an initialized instance with a registered client still serves an \
         unregistered launch exactly the always-available surface"
    );
    let info = tool_ok(&exchange(server, &call(2, "control.server_info", json!({}))).await);
    assert_eq!(info["session"]["registration_state"], json!("unregistered"));
    assert_eq!(info["session"]["assurance_class"], Value::Null);
    assert_eq!(
        error_code(
            &exchange(
                server,
                &call(3, "control.inspect", json!({ "view": "agent.summary" }))
            )
            .await
        ),
        "unregistered_client"
    );
    assert!(
        !install.paths.control_dir().join("host.lock").exists(),
        "an unregistered session takes no host lock and writes no lock file"
    );
}

#[tokio::test]
async fn an_incoherent_credential_launch_refuses_before_anything_is_read() {
    let _lock = ENV_LOCK.lock().await;
    let temp = tempfile::tempdir().expect("temporary dir");
    let credential = temp.path().join("client.cred");
    std::fs::write(&credential, format!("{}\n", "cd".repeat(32))).expect("write");

    // An identifier with no mechanism.
    assert!(matches!(
        ControlLaunch::resolve(Some("reg-abc".to_string()), None),
        Err(refusal) if refusal.code == StartupRefusalCode::CredentialMechanismInvalid
    ));

    // Both mechanisms at once.
    {
        let (_env, _fd) = present_descriptor(&credential);
        assert!(matches!(
            ControlLaunch::resolve(Some("reg-abc".to_string()), Some(temp.path().join("helper"))),
            Err(refusal) if refusal.code == StartupRefusalCode::CredentialMechanismInvalid
        ));
        // A mechanism with no identifier.
        assert!(matches!(
            ControlLaunch::resolve(None, None),
            Err(refusal) if refusal.code == StartupRefusalCode::CredentialMechanismInvalid
        ));
    }

    // The reserved descriptors, and a value that is not a number at all.
    for value in ["0", "1", "2", "-1", "", "  ", "three"] {
        let _env = EnvVarGuard::pin(CREDENTIAL_FD_ENV, value);
        assert!(
            matches!(
                ControlLaunch::resolve(Some("reg-abc".to_string()), None),
                Err(refusal) if refusal.code == StartupRefusalCode::CredentialMechanismInvalid
            ),
            "descriptor {value:?} must be refused"
        );
    }

    // An empty helper path.
    assert!(matches!(
        ControlLaunch::resolve(Some("reg-abc".to_string()), Some(PathBuf::new())),
        Err(refusal) if refusal.code == StartupRefusalCode::CredentialMechanismInvalid
    ));
    // A blank client id.
    {
        let (_env, _fd) = present_descriptor(&credential);
        assert!(matches!(
            ControlLaunch::resolve(Some("   ".to_string()), None),
            Err(refusal) if refusal.code == StartupRefusalCode::CredentialMechanismInvalid
        ));
    }
}

#[tokio::test]
async fn a_refused_start_answers_one_typed_frame_and_ends_the_session() {
    let _lock = ENV_LOCK.lock().await;
    let install = ManagedInstall::new();
    let _guard = ConfigDirGuard::pin(install.root());
    let (id, _path) = install.register(
        &install.full_grant(CredentialDelivery::IsolatedDescriptor),
        "client.cred",
    );
    let wrong = install.root().join("wrong.cred");
    std::fs::write(&wrong, format!("{}\n", "ef".repeat(32))).expect("write");
    let refusal = match start_with_descriptor(&install, &id, &wrong).await {
        Ok(_) => panic!("a wrong secret must refuse"),
        Err(refusal) => refusal,
    };

    let script = [
        serde_json::to_string(&request(1, "initialize", json!({}))).expect("serializes"),
        serde_json::to_string(&request(2, "tools/list", json!({}))).expect("serializes"),
        serde_json::to_string(&call(3, "control.ping", json!({}))).expect("serializes"),
    ]
    .join("\n");

    let mut stdout: Vec<u8> = Vec::new();
    zeroclaw::control_mcp::serve_refusal(script.as_bytes(), &mut stdout, &refusal)
        .await
        .expect("the refusal frame is written");

    let text = String::from_utf8(stdout).expect("stdout is valid UTF-8");
    let frames: Vec<Value> = text
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("a JSON-RPC frame"))
        .collect();
    assert_eq!(
        frames.len(),
        1,
        "a refusing process answers once and stops, whatever the client sends next"
    );
    let frame = &frames[0];
    assert_eq!(frame["jsonrpc"], json!("2.0"));
    assert_eq!(frame["id"], json!(1));
    assert!(
        frame["result"].is_null(),
        "a refusal is never a successful result"
    );
    assert_eq!(frame["error"]["code"], json!(-32600));
    let carried = &frame["error"]["data"][STARTUP_REFUSAL_META_KEY];
    assert_eq!(carried["code"], json!("credential_rejected"));
    assert_eq!(carried["retryable"], json!(false));
    assert!(
        frame["error"]["data"]["error"].is_null(),
        "a startup refusal must not impersonate a v1 tool error payload"
    );

    // Redaction: fixed text only.
    assert!(!text.contains(&install.root().display().to_string()));
    assert!(!text.contains(id.as_str()));
    assert!(!text.contains("component-client"));
    assert!(!text.contains(&install.secret(&wrong)));
}

#[test]
fn the_transport_module_never_writes_to_stdout_outside_the_frame_writer() {
    // The stdio channel is the protocol. A stray `println!` anywhere in the
    // transport would corrupt a client's frame stream in a way that is very
    // hard to diagnose from the client side, so the absence of one is asserted
    // rather than left to review. `write_frame` is the single writer.
    let source =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/control_mcp.rs"))
            .expect("read the transport module");
    // Comment lines are prose and are allowed to *discuss* the names below;
    // what matters is that no line of code contains them.
    let code: String = source
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");

    for forbidden in ["println!", "print!", "eprintln!", "eprint!", "dbg!"] {
        assert!(
            !code.contains(forbidden),
            "src/control_mcp.rs uses `{forbidden}`; the stdio channel must carry only JSON-RPC frames"
        );
    }
    assert_eq!(
        code.matches("writer.write_all").count(),
        1,
        "exactly one writer may touch the stdio channel"
    );

    // The same file must not name a provider factory, a model provider, or the
    // apply path, so "MCP mode makes no model request and mutates nothing" is a
    // property of what the transport can reach and not only of what the tests
    // happened to exercise.
    for forbidden in [
        "zeroclaw_providers",
        "ModelProvider",
        "create_isolated_model_provider",
        "CurrentProviderFactory",
        "ControlApplyOutcome",
        ".apply(",
    ] {
        assert!(
            !code.contains(forbidden),
            "src/control_mcp.rs names `{forbidden}`; the transport must not be able to reach it"
        );
    }
}

// ---------------------------------------------------------------------------
// Phase 5: request apply (durable journal only), status, verify, and the
// operator approve/reject backchannel
// ---------------------------------------------------------------------------

/// Whether the effective config on disk names an agent alias.
fn config_names_agent(install: &ManagedInstall, alias: &str) -> bool {
    std::fs::read_to_string(&install.config_path)
        .expect("read the config")
        .contains(alias)
}

#[tokio::test]
async fn request_apply_parks_a_proposal_and_changes_no_config() {
    let _lock = ENV_LOCK.lock().await;
    let install = ManagedInstall::new();
    let _guard = ConfigDirGuard::pin(install.root());
    enable_mutations(&install);
    let (id, credential_path) = install.register(
        &install.full_grant(CredentialDelivery::IsolatedDescriptor),
        "client.cred",
    );
    let host = start_with_descriptor(&install, &id, &credential_path)
        .await
        .expect("the credential authenticates");
    let server = host.server();
    let _ = initialize(server).await;

    // With mutations enabled and the proposal grant held, the durable-effect tool
    // is now on the surface.
    let listed = listed_tool_names(&exchange(server, &request(1, "tools/list", json!({}))).await);
    assert!(
        listed.contains(&"control.request_apply".to_string()),
        "request_apply is listed once mutations are enabled for a proposal-granted client"
    );

    let config_before = std::fs::read(&install.config_path).expect("read config before");

    let parked = tool_ok(
        &exchange(
            server,
            &call(2, "control.request_apply", request_apply_args()),
        )
        .await,
    );
    let operation_id = parked["operation_id"].as_str().expect("op id").to_string();
    let resume_secret = parked["resume_secret"]
        .as_str()
        .expect("resume secret")
        .to_string();
    assert!(operation_id.starts_with("op-"));
    assert!(resume_secret.starts_with("resume-"));
    assert_eq!(parked["state"], json!("awaiting_approval"));
    assert_eq!(parked["durable"], json!(true));

    // The invariant: parking is durable-journal-only and changes no config.
    let config_after = std::fs::read(&install.config_path).expect("read config after");
    assert_eq!(
        config_before, config_after,
        "request_apply must change no config"
    );

    // A durable journal row exists, and the owner can read it back by name.
    assert!(
        journal_path(&install).exists(),
        "request_apply must have written one journal row"
    );
    let status = tool_ok(
        &exchange(
            server,
            &call(3, "control.status", json!({ "operation_id": operation_id })),
        )
        .await,
    );
    assert_eq!(status["state"], json!("awaiting_approval"));
    assert_eq!(status["operation"], json!("agent.create_contained"));
    assert_eq!(status["effects_reached_post_image"], json!(0));
}

#[tokio::test]
async fn no_mcp_call_can_approve_or_apply_a_proposal() {
    let _lock = ENV_LOCK.lock().await;
    let install = ManagedInstall::new();
    let _guard = ConfigDirGuard::pin(install.root());
    enable_mutations(&install);
    let (id, credential_path) = install.register(
        &install.full_grant(CredentialDelivery::IsolatedDescriptor),
        "client.cred",
    );
    let host = start_with_descriptor(&install, &id, &credential_path)
        .await
        .expect("the credential authenticates");
    let server = host.server();
    let _ = initialize(server).await;

    // The full phase-5 surface is listed, but no tool approves, applies, or
    // finalizes: there is no model-callable approve.
    let listed = listed_tool_names(&exchange(server, &request(1, "tools/list", json!({}))).await);
    for present in ["control.request_apply", "control.status", "control.verify"] {
        assert!(
            listed.contains(&present.to_string()),
            "{present} must be listed"
        );
    }
    for forbidden in [
        "control.approve",
        "control.reject",
        "control.apply",
        "control.finalize",
        "control.commit",
        "control.enable_mutations",
    ] {
        assert!(
            !listed.contains(&forbidden.to_string()),
            "{forbidden} must never appear in tools/list"
        );
        let response = exchange(
            server,
            &call(2, forbidden, json!({ "operation_id": "op-x" })),
        )
        .await;
        assert_eq!(
            error_code(&response),
            "unknown_operation",
            "{forbidden} must not exist as a callable tool"
        );
    }

    // The one durable-effect tool the same client can call only parks — it
    // cannot approve its own proposal.
    let parked = exchange(
        server,
        &call(3, "control.request_apply", request_apply_args()),
    )
    .await;
    assert_eq!(
        parked["result"]["isError"],
        json!(false),
        "request_apply only parks"
    );
    assert!(
        !config_names_agent(&install, "writer"),
        "no MCP call applied the parked proposal"
    );
}

#[tokio::test]
async fn an_operator_approves_via_the_cli_path_and_config_changes_through_the_cas() {
    let _lock = ENV_LOCK.lock().await;
    let install = ManagedInstall::new();
    let _guard = ConfigDirGuard::pin(install.root());
    enable_mutations(&install);
    let (id, credential_path) = install.register(
        &install.full_grant(CredentialDelivery::IsolatedDescriptor),
        "client.cred",
    );
    let host = start_with_descriptor(&install, &id, &credential_path)
        .await
        .expect("the credential authenticates");
    let server = host.server();
    let _ = initialize(server).await;

    // 1. The client PARKS a proposal. No config changes yet.
    let parked = tool_ok(
        &exchange(
            server,
            &call(1, "control.request_apply", request_apply_args()),
        )
        .await,
    );
    let operation_id = parked["operation_id"].as_str().expect("op id").to_string();
    assert!(
        !config_names_agent(&install, "writer"),
        "no agent exists before approval"
    );

    // 2. A registered operator approves via the CLI composition — the ONLY path
    //    that changes config. It authenticates through the terminal backchannel
    //    (scripted here), the broker mints a single-use receipt, and the
    //    ApplyWorker drives the six-step claim + CAS. The operator ("operator",
    //    the genesis first operator) is distinct from the requester (the
    //    registration id), so it is eligible.
    let outcome = zeroclaw::control_operator::approve_operation_blocking(
        install.config_path.clone(),
        &operation_id,
        "operator",
        &FixturePresence::new("operator"),
        // Isolation-proving fixture evidence. Production passes Evidence::unknown(),
        // which is conservatively ineligible, so the shipped path fails closed
        // until a reachability prober exists.
        zeroclaw_control::Evidence::fixture_isolated(),
        "confirm".to_string(),
        "operator".to_string(),
    )
    .expect("the operator approval applies through the CAS");
    assert_eq!(outcome.agent_alias, "writer");
    assert_eq!(outcome.state, "verified");

    // 3. Config changed through the CAS, and Status reports verified by name.
    assert!(
        config_names_agent(&install, "writer"),
        "the agent exists in effective config after approval"
    );
    let status = tool_ok(
        &exchange(
            server,
            &call(2, "control.status", json!({ "operation_id": operation_id })),
        )
        .await,
    );
    assert_eq!(status["state"], json!("verified"));

    // Verify confirms effective state, not merely a successful write.
    let verified = tool_ok(
        &exchange(
            server,
            &call(3, "control.verify", json!({ "operation_id": operation_id })),
        )
        .await,
    );
    assert_eq!(verified["state"], json!("verified"));
    assert_eq!(verified["agent_present"], json!(true));
    assert_eq!(verified["effective"], json!(true));
}

#[tokio::test]
async fn request_apply_refuses_and_writes_nothing_while_mutations_are_disabled() {
    let _lock = ENV_LOCK.lock().await;
    let install = ManagedInstall::new();
    let _guard = ConfigDirGuard::pin(install.root());
    // Deliberately NOT enabling mutations: a registered read grant, read-only mode.
    let (id, credential_path) = install.register(
        &install.full_grant(CredentialDelivery::IsolatedDescriptor),
        "client.cred",
    );
    let host = start_with_descriptor(&install, &id, &credential_path)
        .await
        .expect("the credential authenticates");
    let server = host.server();
    let _ = initialize(server).await;

    // The read-only surface is fully usable, and request_apply does not appear.
    let listed = listed_tool_names(&exchange(server, &request(1, "tools/list", json!({}))).await);
    assert!(
        !listed.contains(&"control.request_apply".to_string()),
        "request_apply must not appear usable while mutations are disabled"
    );
    assert!(listed.contains(&"control.preview".to_string()));
    let preview = exchange(server, &call(2, "control.preview", request_apply_args())).await;
    assert_eq!(
        preview["result"]["isError"],
        json!(false),
        "preview still works"
    );

    // Calling request_apply by name is a hard read-only boundary: it refuses and
    // writes nothing durable.
    let response = exchange(
        server,
        &call(3, "control.request_apply", request_apply_args()),
    )
    .await;
    assert_eq!(error_code(&response), "mutations_disabled");
    assert!(
        !journal_path(&install).exists(),
        "read-only mode must create no parked proposal"
    );
}

#[tokio::test]
async fn request_apply_refuses_a_read_grant_without_the_proposal_domain() {
    let _lock = ENV_LOCK.lock().await;
    let install = ManagedInstall::new();
    let _guard = ConfigDirGuard::pin(install.root());
    enable_mutations(&install);
    // Every read domain, but no proposal domain: a read grant is not enough.
    let read_only = ClientGrant {
        client_label: ClientLabel::new("read-only").expect("label"),
        delivery_assurance: CredentialDelivery::IsolatedDescriptor,
        granted_instances: [install.instance_id.clone()].into_iter().collect(),
        granted_read_domains: client_registry::READ_DOMAINS_V1
            .iter()
            .map(|d| (*d).to_string())
            .collect(),
        proposal_domains: std::collections::BTreeSet::new(),
    };
    let (id, credential_path) = install.register(&read_only, "read-only.cred");
    let host = start_with_descriptor(&install, &id, &credential_path)
        .await
        .expect("the credential authenticates");
    let server = host.server();
    let _ = initialize(server).await;

    // Not usable: hidden from tools/list even with mutations enabled.
    let listed = listed_tool_names(&exchange(server, &request(1, "tools/list", json!({}))).await);
    assert!(
        !listed.contains(&"control.request_apply".to_string()),
        "a read-only grant must not see request_apply"
    );
    // And calling by name refuses on the proposal-domain gate, writing nothing.
    let response = exchange(
        server,
        &call(2, "control.request_apply", request_apply_args()),
    )
    .await;
    assert_eq!(error_code(&response), "grant_required");
    assert!(
        !journal_path(&install).exists(),
        "a read grant must park nothing"
    );
}

#[tokio::test]
async fn grant_proposal_unlocks_request_apply_for_a_read_only_client() {
    // The #52 end-to-end unlock: a client registered read-only (the shape
    // `register-client` issues today) is refused by request_apply until the
    // host-side grant-proposal ceremony widens its grant, after which the SAME
    // client can park a proposal. This is the seam the mutation check for the
    // request_apply authorization targets: reverting the grant to ignore the
    // newly-granted domain leaves the widened client refused and fails here.
    let _lock = ENV_LOCK.lock().await;
    let install = ManagedInstall::new();
    let _guard = ConfigDirGuard::pin(install.root());
    enable_mutations(&install);

    // A read-only client: every read domain, no proposal domain.
    let read_only = ClientGrant {
        client_label: ClientLabel::new("read-only").expect("label"),
        delivery_assurance: CredentialDelivery::IsolatedDescriptor,
        granted_instances: [install.instance_id.clone()].into_iter().collect(),
        granted_read_domains: client_registry::READ_DOMAINS_V1
            .iter()
            .map(|d| (*d).to_string())
            .collect(),
        proposal_domains: std::collections::BTreeSet::new(),
    };
    let (id, credential_path) = install.register(&read_only, "read-only.cred");

    // Before the grant: request_apply is hidden and refuses on the proposal gate.
    {
        let host = start_with_descriptor(&install, &id, &credential_path)
            .await
            .expect("the credential authenticates");
        let server = host.server();
        let _ = initialize(server).await;
        let listed =
            listed_tool_names(&exchange(server, &request(1, "tools/list", json!({}))).await);
        assert!(
            !listed.contains(&"control.request_apply".to_string()),
            "a read-only grant must not see request_apply before the grant"
        );
        let refused = exchange(
            server,
            &call(2, "control.request_apply", request_apply_args()),
        )
        .await;
        assert_eq!(error_code(&refused), "grant_required");
        assert!(
            !journal_path(&install).exists(),
            "a read-only client parks nothing before the grant"
        );
    }

    // The host-side grant-proposal ceremony widens the registration, naming the
    // genesis first operator ("operator") through the fixture presence adapter.
    // This is exactly what `zeroclaw control grant-proposal` performs; nothing an
    // MCP session can reach.
    let granted = zeroclaw_control::grant::grant_proposal_domains(
        install.root(),
        &FixturePresence::new("operator"),
        &id,
        "confirm".to_string(),
        "operator".to_string(),
    )
    .expect("the grant-proposal ceremony widens the client's grant");
    assert!(
        granted.newly_granted,
        "the first grant newly adds the domain"
    );
    assert!(granted.proposal_domains.contains(PROPOSAL_DOMAIN_AGENT));

    // After the grant: a fresh session (capabilities are not retroactive) now
    // sees request_apply and parks a durable proposal, changing no config.
    let host = start_with_descriptor(&install, &id, &credential_path)
        .await
        .expect("the credential still authenticates");
    let server = host.server();
    let _ = initialize(server).await;
    let listed = listed_tool_names(&exchange(server, &request(1, "tools/list", json!({}))).await);
    assert!(
        listed.contains(&"control.request_apply".to_string()),
        "the widened client sees request_apply"
    );
    let config_before = std::fs::read(&install.config_path).expect("config before");
    let parked = tool_ok(
        &exchange(
            server,
            &call(2, "control.request_apply", request_apply_args()),
        )
        .await,
    );
    assert_eq!(parked["state"], json!("awaiting_approval"));
    assert_eq!(parked["durable"], json!(true));
    assert!(
        journal_path(&install).exists(),
        "the widened client parked a durable proposal"
    );
    let config_after = std::fs::read(&install.config_path).expect("config after");
    assert_eq!(
        config_before, config_after,
        "parking changes no config — operator approval is still a separate step"
    );
}

#[tokio::test]
async fn status_and_verify_are_scoped_to_the_owning_requester() {
    let _lock = ENV_LOCK.lock().await;
    let install = ManagedInstall::new();
    let _guard = ConfigDirGuard::pin(install.root());
    enable_mutations(&install);
    let (id_a, cred_a) = install.register(
        &install.full_grant(CredentialDelivery::IsolatedDescriptor),
        "a.cred",
    );
    let host_a = start_with_descriptor(&install, &id_a, &cred_a)
        .await
        .expect("client A authenticates");
    let server_a = host_a.server();
    let _ = initialize(server_a).await;
    let parked = tool_ok(
        &exchange(
            server_a,
            &call(1, "control.request_apply", request_apply_args()),
        )
        .await,
    );
    let operation_id = parked["operation_id"].as_str().expect("op id").to_string();

    // Client A reads its own operation.
    let own = exchange(
        server_a,
        &call(2, "control.status", json!({ "operation_id": operation_id })),
    )
    .await;
    assert_eq!(
        own["result"]["isError"],
        json!(false),
        "the owner can read its own operation"
    );

    // Client B — a different requester subject on the same instance — cannot see
    // it. Owner-scoping is by requester fingerprint, which the subject
    // determines; a fixture session with a distinct subject models a second
    // client without taking a second host lock.
    let server_b = ControlMcpServer::with_service_and_session(
        service_with(&Arc::new(RecordingFactory::new()), &install.config_path),
        ControlSession::fixture_granted(RequesterGrant::fixture_full()),
        TEST_VERSION,
    )
    .with_requester_subject("reg-a-different-client");
    assert_eq!(
        error_code(
            &exchange(
                &server_b,
                &call(3, "control.status", json!({ "operation_id": operation_id }))
            )
            .await
        ),
        "unknown_operation",
        "status must not disclose another owner's operation"
    );
    assert_eq!(
        error_code(
            &exchange(
                &server_b,
                &call(4, "control.verify", json!({ "operation_id": operation_id }))
            )
            .await
        ),
        "unknown_operation",
        "verify must not disclose another owner's operation"
    );
}

#[tokio::test]
async fn the_resume_secret_is_returned_once_and_stored_only_as_a_verifier() {
    let _lock = ENV_LOCK.lock().await;
    let install = ManagedInstall::new();
    let _guard = ConfigDirGuard::pin(install.root());
    enable_mutations(&install);
    let (id, credential_path) = install.register(
        &install.full_grant(CredentialDelivery::IsolatedDescriptor),
        "client.cred",
    );
    let host = start_with_descriptor(&install, &id, &credential_path)
        .await
        .expect("the credential authenticates");
    let server = host.server();
    let _ = initialize(server).await;

    let parked = tool_ok(
        &exchange(
            server,
            &call(1, "control.request_apply", request_apply_args()),
        )
        .await,
    );
    let resume_secret = parked["resume_secret"]
        .as_str()
        .expect("resume secret")
        .to_string();
    assert!(resume_secret.starts_with("resume-"));

    // The durable journal stores only a verifier, never the secret — exactly as
    // a client credential is stored.
    let sealed = std::fs::read_to_string(journal_path(&install)).expect("read the sealed journal");
    assert!(
        !sealed.contains(&resume_secret),
        "the plaintext resume secret must never be persisted"
    );

    // It is single-proposal: a second park mints a different secret.
    let parked2 = tool_ok(
        &exchange(
            server,
            &call(2, "control.request_apply", request_apply_args()),
        )
        .await,
    );
    let resume_secret2 = parked2["resume_secret"]
        .as_str()
        .expect("second resume secret")
        .to_string();
    assert_ne!(
        resume_secret, resume_secret2,
        "each parked proposal gets its own resume secret"
    );
}
