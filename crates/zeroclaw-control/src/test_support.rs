//! Shared scaffolding for this crate's unit tests.
//!
//! `#[cfg(test)]` at the module declaration in `lib.rs`, so none of this exists
//! in a shipped build. It lives in one module rather than being copied into
//! each test module so that "what a test instance looks like" has a single
//! definition — a scripted presence adapter that drifted between two test
//! modules would let one of them pass for the wrong reason.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::ceremony::{
    GenesisRequest, PresenceAttestation, PresenceError, PresenceRequest, UserPresence, run_genesis,
};
use crate::genesis::{FirstOperatorIdentity, GenesisRecord, PresenceClass, classify};
use crate::keys::ApprovalAuditKey;
use crate::operator::{OperatorIdentity, RequesterContext, RequesterSubject};
use crate::reachability::Evidence;
use crate::store::ControlPaths;

/// A scripted presence adapter.
///
/// It reports [`PresenceClass::Terminal`] because that is the strongest class
/// this phase defines, and no adapter may name a class it cannot achieve.
pub(crate) struct ScriptedPresence {
    outcome: Result<Option<String>, PresenceError>,
    seen: Mutex<Vec<PresenceRequest>>,
}

impl ScriptedPresence {
    /// Confirms, and attests `identity` when the request asks for one.
    pub(crate) fn affirming(identity: &str) -> Self {
        Self {
            outcome: Ok(Some(identity.to_string())),
            seen: Mutex::new(Vec::new()),
        }
    }

    /// Confirms, but attests no identity even when asked.
    pub(crate) fn affirming_without_identity() -> Self {
        Self {
            outcome: Ok(None),
            seen: Mutex::new(Vec::new()),
        }
    }

    /// Produces no attestation.
    pub(crate) fn failing(error: PresenceError) -> Self {
        Self {
            outcome: Err(error),
            seen: Mutex::new(Vec::new()),
        }
    }

    /// How many times a prompt was put to the human.
    pub(crate) fn prompts(&self) -> usize {
        self.seen.lock().expect("presence log").len()
    }
}

impl UserPresence for ScriptedPresence {
    fn confirm(&self, request: &PresenceRequest) -> Result<PresenceAttestation, PresenceError> {
        self.seen
            .lock()
            .expect("presence log")
            .push(request.clone());
        match &self.outcome {
            Ok(identity) => Ok(PresenceAttestation::for_test(
                PresenceClass::Terminal,
                match (identity, &request.operator_prompt) {
                    (Some(value), Some(_)) => Some(
                        FirstOperatorIdentity::new(value.clone()).expect("test identity is valid"),
                    ),
                    _ => None,
                },
            )),
            Err(e) => Err(e.clone()),
        }
    }
}

/// A bare install root: a config file and a data directory, no control state.
pub(crate) fn install_root(tmp: &tempfile::TempDir) -> PathBuf {
    let root = tmp.path().join("install");
    std::fs::create_dir_all(root.join("data")).expect("create install root");
    std::fs::write(root.join("config.toml"), b"# config").expect("write config");
    root
}

/// A genesis'd instance whose first operator is `jordan`.
pub(crate) fn genesis_instance(
    tmp: &tempfile::TempDir,
) -> (PathBuf, ControlPaths, Box<GenesisRecord>) {
    let root = install_root(tmp);
    run_genesis(
        &root,
        &ScriptedPresence::affirming("jordan"),
        &GenesisRequest {
            prompt: "Authorize genesis? ".to_string(),
            operator_prompt: "First operator identity: ".to_string(),
            register_client: None,
        },
    )
    .expect("genesis must succeed");
    let paths = ControlPaths::resolve(&root).expect("resolve");
    let record = Box::new(
        classify(&paths, &paths.key_source())
            .record()
            .expect("managed")
            .clone(),
    );
    (root, paths, record)
}

/// The approval and audit key for a managed instance.
pub(crate) fn key_for(paths: &ControlPaths, record: &GenesisRecord) -> ApprovalAuditKey {
    ApprovalAuditKey::derive(&paths.key_source(), record.trust_epoch).expect("derive")
}

/// A valid operator identity.
pub(crate) fn operator(name: &str) -> OperatorIdentity {
    OperatorIdentity::new(name).expect("valid operator identity")
}

/// The one proposal domain v1 defines.
pub(crate) fn agent_domain() -> std::collections::BTreeSet<String> {
    crate::client_registry::PROPOSAL_DOMAINS_V1
        .iter()
        .map(|d| (*d).to_string())
        .collect()
}

/// A requester the host has proved cannot reach the operator backchannel.
///
/// Nothing in this phase can actually discharge those proofs; this is the only
/// way a test can exercise the eligible branch at all, which is itself the
/// honest statement of where the phase stands.
pub(crate) fn isolated_requester(subject: &str) -> RequesterContext {
    RequesterContext::external(
        RequesterSubject::new(subject).expect("subject"),
        agent_domain(),
        Evidence::fully_isolated(),
    )
}

/// A same-process agent requester: the host has proved nothing about it.
pub(crate) fn unprovable_requester(subject: &str) -> RequesterContext {
    RequesterContext::agent(
        RequesterSubject::new(subject).expect("subject"),
        agent_domain(),
        Evidence::unknown(),
    )
}

/// The one process-wide lock every test that pins `ZEROCLAW_CONFIG_DIR` must
/// hold. `Config::load_or_init` resolves the install root from that environment
/// variable, so two tests pinning it concurrently in the shared lib-test process
/// would each see the other's directory. A single lock — defined once here
/// rather than copied per module — is what keeps them serialized.
pub(crate) fn config_env_lock() -> &'static tokio::sync::Mutex<()> {
    static LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    &LOCK
}

/// Pins `ZEROCLAW_CONFIG_DIR` for the lifetime of the guard and restores the
/// previous value on drop.
pub(crate) struct ConfigDirGuard {
    previous: Option<String>,
}

impl ConfigDirGuard {
    /// # Safety
    ///
    /// The caller must hold [`config_env_lock`] for the whole lifetime of the
    /// guard, so no other test reads or writes the variable concurrently.
    pub(crate) fn pin(dir: &Path) -> Self {
        let previous = std::env::var("ZEROCLAW_CONFIG_DIR").ok();
        // SAFETY: serialized by `config_env_lock`; restored on drop.
        unsafe { std::env::set_var("ZEROCLAW_CONFIG_DIR", dir) };
        Self { previous }
    }
}

impl Drop for ConfigDirGuard {
    fn drop(&mut self) {
        // SAFETY: serialized by `config_env_lock`.
        match self.previous.take() {
            Some(value) => unsafe { std::env::set_var("ZEROCLAW_CONFIG_DIR", value) },
            None => unsafe { std::env::remove_var("ZEROCLAW_CONFIG_DIR") },
        }
    }
}

// ---------------------------------------------------------------------------
// Applyable-instance harness
// ---------------------------------------------------------------------------

/// Run one async test body on a thread with a large stack.
///
/// `Config::load_or_init` builds a very large value, and the control apply path
/// drives it several times inside one async state machine, whose locals all
/// share a single frame. The default 2 MiB test-thread stack overflows; a
/// dedicated wide-stack thread with its own current-thread runtime is the
/// standard fix and keeps every apply test on plain `#[test]`.
pub(crate) fn run_async<F, Fut>(body: F)
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()>,
{
    std::thread::Builder::new()
        .stack_size(64 * 1024 * 1024)
        .spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("build runtime");
            runtime.block_on(body());
        })
        .expect("spawn wide-stack thread")
        .join()
        .expect("test thread panicked");
}

/// A minimal, valid v3 provider config an apply can actually run against — the
/// same shape the service tests seed.
pub(crate) const PROVIDER_CONFIG: &str = r#"schema_version = 3

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

/// A genesis'd instance whose config is a real, applyable revision, plus the
/// trust material an approval needs. Shared by the apply-worker and recovery
/// tests so both drive one definition of "an instance a proposal can apply to".
pub(crate) struct ApplyHarness {
    pub(crate) _tmp: tempfile::TempDir,
    pub(crate) root: PathBuf,
    pub(crate) config_path: PathBuf,
    pub(crate) paths: ControlPaths,
    pub(crate) record: Box<GenesisRecord>,
    pub(crate) key: ApprovalAuditKey,
    pub(crate) operators: crate::operator::OperatorRegistry,
    pub(crate) trust: crate::genesis::InstanceTrustState,
}

impl ApplyHarness {
    pub(crate) fn new() -> Self {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = std::fs::canonicalize(tmp.path()).expect("canonical root");
        std::fs::create_dir_all(root.join("data")).expect("data dir");
        std::fs::write(root.join("config.toml"), PROVIDER_CONFIG).expect("seed config");
        run_genesis(
            &root,
            &ScriptedPresence::affirming("jordan"),
            &GenesisRequest {
                prompt: "Authorize genesis? ".to_string(),
                operator_prompt: "First operator identity: ".to_string(),
                register_client: None,
            },
        )
        .expect("genesis");
        let paths = ControlPaths::resolve(&root).expect("resolve");
        let record = Box::new(
            classify(&paths, &paths.key_source())
                .record()
                .expect("managed")
                .clone(),
        );
        let key = key_for(&paths, &record);
        let operators = crate::operator::OperatorRegistry::new().with_genesis_operator(&record);
        let trust = crate::genesis::InstanceTrustState::Managed(record.clone());
        Self {
            config_path: root.join("config.toml"),
            _tmp: tmp,
            root,
            paths,
            record,
            key,
            operators,
            trust,
        }
    }

    pub(crate) fn service(&self) -> crate::service::ControlService {
        crate::service::ControlService::new(
            self.config_path.clone(),
            zeroclaw_runtime::quickstart::Surface::Cli,
        )
    }

    pub(crate) fn worker<'a>(
        &'a self,
        service: &'a crate::service::ControlService,
    ) -> crate::apply_worker::ApplyWorker<'a> {
        crate::apply_worker::ApplyWorker::new(
            &self.paths,
            &self.key,
            &self.operators,
            service,
            self.record.as_ref(),
        )
    }

    pub(crate) fn fingerprint(&self) -> crate::registry::InstanceFingerprint {
        let roots = self.paths.canonical_roots().expect("roots");
        let config =
            crate::registry::RootIdentity::probe(&roots.config_root).expect("probe config");
        let data = crate::registry::RootIdentity::probe(&roots.data_root).expect("probe data");
        crate::registry::InstanceFingerprint::compute(
            &self.record.instance_id,
            &self.record.digest(),
            self.record.trust_epoch,
            &roots,
            &config,
            &data,
        )
    }

    pub(crate) fn proposal(&self) -> crate::proposal::AgentProposal {
        crate::proposal::AgentProposal {
            agent_alias: "writer".to_string(),
            risk: crate::inventory::RiskChoice::LockedDown,
            runtime: crate::inventory::RuntimeChoice::Tight,
            memory: crate::inventory::MemoryChoice::Markdown,
            personality_files: vec![crate::proposal::PersonalityFileProposal {
                filename: "SOUL.md".to_string(),
                content: "# Soul\nWrite carefully.".to_string(),
            }],
        }
    }

    /// Park a proposal, mint a real operator receipt, record it, and leave the
    /// entry `approved`. Returns the operation id and the receipt.
    pub(crate) async fn arrange_approved(
        &self,
        service: &crate::service::ControlService,
        now: u64,
    ) -> (
        crate::journal::OperationId,
        crate::approval::AuthenticatedReceipt,
    ) {
        use crate::approval::{
            ApprovalBroker, ApprovalRequest, InMemoryReceiptLedger, ProposalDigest,
            SourceRevisionDigest,
        };
        use crate::journal::{ParkRequest, ProposalJournal, Quotas};
        use crate::meta_authority::ControlOperation;
        use crate::operator::authenticate_operator;

        let proposal = self.proposal();
        let inspection = service.inspect().await.expect("inspect");
        let bound = service
            .preview(inspection, "custom.fixture", &proposal)
            .expect("preview");
        let digest = ProposalDigest::of_bound_proposal(&bound).expect("digest");
        let request = ApprovalRequest {
            operation: ControlOperation::ProposeAgentProfile,
            proposal_digest: digest,
            target_instance: self.record.instance_id.clone(),
            instance_fingerprint: self.fingerprint(),
            source_revision: SourceRevisionDigest::of(bound.source_revision()),
        };
        let requester = isolated_requester("reg-abc123");
        let auth = authenticate_operator(
            &ScriptedPresence::affirming("jordan"),
            "Approve? ".to_string(),
            "Operator identity: ".to_string(),
            &operator("jordan"),
            &self.operators,
            self.record.trust_epoch,
            &requester,
            &request.proposal_digest,
            &request.target_instance,
            now,
        )
        .expect("operator authenticates");
        let mint_ledger = InMemoryReceiptLedger::new();
        let broker = ApprovalBroker::new(&self.key, &self.trust, &self.operators, &mint_ledger);
        let issued = broker
            .request_approval(&request, &requester, auth, now)
            .expect("issue receipt");

        let mut journal = ProposalJournal::load(&self.paths, &self.key).expect("load");
        let (op_id, _secret) = journal
            .park(
                &ParkRequest {
                    operation: ControlOperation::ProposeAgentProfile,
                    bound: &bound,
                    agent_proposal: &proposal,
                    selected_provider_ref: "custom.fixture",
                    target_instance: self.record.instance_id.clone(),
                    instance_fingerprint: self.fingerprint(),
                    requester: &requester,
                    owner_token: "reg-abc123".to_string(),
                    client_session: "sess-1".to_string(),
                    proposal_ttl_secs: 900,
                },
                now,
                &Quotas::default(),
                &self.paths,
                &self.key,
            )
            .expect("park");
        journal
            .record_approval(&op_id, &issued, now, &self.paths, &self.key)
            .expect("record approval");
        (op_id, issued)
    }

    pub(crate) fn config_text(&self) -> String {
        std::fs::read_to_string(&self.config_path).expect("read config")
    }

    pub(crate) fn load_journal(&self) -> crate::journal::ProposalJournal {
        crate::journal::ProposalJournal::load(&self.paths, &self.key).expect("load journal")
    }
}
