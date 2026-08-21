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

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use serde_json::{Value, json};
use tokio::sync::Mutex;
use zeroclaw::control_mcp::ControlMcpServer;
use zeroclaw_config::schema::Config;
use zeroclaw_control::protocol::{
    AgentCreateContainedOperation, CapabilitySet, ControlErrorCode, PreviewResult, canonical_json,
    capability_digest, operation_digest, operation_digest_for, source_revision_id,
};
use zeroclaw_control::{
    CapabilityRestrictedProviderFactory, ControlService, ControlSession, IsolatedProvider,
    MemoryChoice, PROPOSAL_DOMAIN_AGENT, PersonalityFileProposal, ProviderError, ProviderErrorCode,
    ProviderTarget, RequesterGrant, RiskChoice, RuntimeChoice,
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

/// The five tools a registered grant adds, in registry order.
const GRANT_GATED: [&str; 5] = [
    "control.catalog",
    "control.describe",
    "control.inspect",
    "control.validate",
    "control.preview",
];

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
            ALWAYS_AVAILABLE
                .iter()
                .chain(GRANT_GATED.iter())
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

    for name in [
        "control.apply",
        "control.request_apply",
        "control.status",
        "control.verify",
        "control.register",
        "control.approve",
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
