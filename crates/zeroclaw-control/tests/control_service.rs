//! Behavior-boundary coverage for the `ControlService` seam.
//!
//! These tests drive the service the way a transport does — inspect, preview,
//! apply — against a throwaway install root, and assert the same observable
//! outcome the terminal flow's component tests assert for the same proposal
//! (`tests/component/zerona_cli.rs`,
//! `real_terminal_apply_previews_then_persists_only_the_approved_agent`). The
//! fixture configuration, proposal, and post-conditions are deliberately kept
//! identical to that test so "the current CLI and service produce identical
//! contained-agent outcomes" is checked rather than asserted.
//!
//! One property is not tested here because the type system already carries it:
//! `ControlService::apply` accepts only a `BoundProposal`, and only
//! `ControlService::preview` can mint one. There is no way to reach the
//! revision-bound Quickstart commit without first producing the preview whose
//! source revision the commit is checked against.
//!
//! `Config::load_or_init` resolves the install root from the environment, so
//! every test here serializes on `ENV_LOCK` and restores the previous value
//! before releasing it.

use std::path::Path;

use tokio::sync::Mutex;
use zeroclaw_config::multi_agent::MemoryBackendKind;
use zeroclaw_config::schema::Config;
use zeroclaw_control::{
    AgentProposal, ApplyIntegration, ControlApplyOutcome, ControlError, ControlService,
    MemoryChoice, PersonalityFileProposal, ProposalErrorCode, RevisionBinding, RiskChoice,
    RuntimeChoice,
};
use zeroclaw_runtime::quickstart::Surface;

static ENV_LOCK: Mutex<()> = Mutex::const_new(());

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

/// The component test's provider fixture. The URI is never contacted: the
/// service's transaction makes no provider call.
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

/// The exact proposal the component test's scripted model emits.
fn writer_proposal() -> AgentProposal {
    AgentProposal {
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

fn seed_install(dir: &Path) -> std::path::PathBuf {
    let config_path = dir.join("config.toml");
    std::fs::write(&config_path, PROVIDER_CONFIG).expect("write provider config");
    config_path
}

/// Re-read the persisted configuration exactly as the component test does, so
/// both paths are judged against the same on-disk bytes.
fn reload_persisted(dir: &Path, config_path: &Path) -> Config {
    let mut reloaded: Config =
        toml::from_str(&std::fs::read_to_string(config_path).expect("read applied config"))
            .expect("parse applied config");
    reloaded.config_path = config_path.to_path_buf();
    reloaded.data_dir = dir.join("data");
    reloaded
}

/// The component test's post-conditions for the approved `writer` agent.
fn assert_component_test_outcome(dir: &Path, config_path: &Path) {
    let reloaded = reload_persisted(dir, config_path);
    let agent = reloaded.agents.get("writer").expect("writer agent saved");
    assert_eq!(agent.model_provider.as_str(), "custom.fixture");
    assert_eq!(agent.risk_profile.as_str(), "locked_down");
    assert_eq!(agent.runtime_profile.as_str(), "tight");
    assert_eq!(agent.memory.backend, MemoryBackendKind::Markdown);
    assert_eq!(
        reloaded.memory.backend, "none",
        "agent-scoped memory must not rewrite install-wide memory"
    );
    assert!(agent.channels.is_empty());

    let soul = reloaded.agent_workspace_dir("writer").join("SOUL.md");
    assert_eq!(
        std::fs::read_to_string(&soul).expect("read applied personality"),
        "# Soul\nWrite carefully."
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            std::fs::metadata(&soul)
                .expect("personality metadata")
                .permissions()
                .mode()
                & 0o077,
            0,
            "staged personality files must not become group/world-readable"
        );
    }
}

#[tokio::test]
async fn service_transaction_produces_the_terminal_flow_s_contained_agent() {
    let _lock = ENV_LOCK.lock().await;
    let temp = tempfile::tempdir().expect("temporary install root");
    let config_path = seed_install(temp.path());
    let _guard = ConfigDirGuard::pin(temp.path());

    let service = ControlService::new(config_path.clone(), Surface::Cli);
    let inspection = service.inspect().await.expect("inspect the seeded install");
    assert_eq!(
        service.provider_inventory(&inspection).provider_refs,
        vec!["custom.fixture".to_string()],
        "the fixture alias is the only capability-restricted provider on offer"
    );
    assert_eq!(
        inspection.source_revision(),
        PROVIDER_CONFIG,
        "the inspected revision is the exact source on disk"
    );

    let bound = service
        .preview(inspection, "custom.fixture", &writer_proposal())
        .expect("the contained proposal previews");
    let outcome = service
        .apply(bound)
        .await
        .expect("the bound proposal applies");
    assert_eq!(
        outcome,
        ControlApplyOutcome::Verified {
            agent_alias: "writer".to_string()
        }
    );

    assert_component_test_outcome(temp.path(), &config_path);
}

#[tokio::test]
async fn preview_binds_the_inspected_revision_to_the_quickstart_commit() {
    let _lock = ENV_LOCK.lock().await;
    let temp = tempfile::tempdir().expect("temporary install root");
    let config_path = seed_install(temp.path());
    let _guard = ConfigDirGuard::pin(temp.path());

    let service = ControlService::new(config_path, Surface::Cli);
    let inspection = service.inspect().await.expect("inspect the seeded install");
    let bound = service
        .preview(inspection, "custom.fixture", &writer_proposal())
        .expect("the contained proposal previews");

    assert_eq!(bound.source_revision(), PROVIDER_CONFIG);
    assert_eq!(bound.agent_alias(), "writer");
    assert_eq!(
        bound.preview().revision_binding,
        RevisionBinding::ExpectedSource,
        "a preview the service hands out is always bound to its source revision"
    );
    assert_eq!(
        bound.preview().persistence.apply_integration,
        ApplyIntegration::RevisionBoundQuickstart,
        "the service never offers a preview a caller could apply unbound"
    );
    assert!(
        !temp.path().join("agents").exists(),
        "preview writes nothing"
    );
}

#[tokio::test]
async fn apply_refuses_a_preview_bound_to_a_superseded_revision() {
    let _lock = ENV_LOCK.lock().await;
    let temp = tempfile::tempdir().expect("temporary install root");
    let config_path = seed_install(temp.path());
    let _guard = ConfigDirGuard::pin(temp.path());

    let service = ControlService::new(config_path.clone(), Surface::Cli);
    let inspection = service.inspect().await.expect("inspect the seeded install");
    let bound = service
        .preview(inspection, "custom.fixture", &writer_proposal())
        .expect("the contained proposal previews");

    // Someone else edits the configuration after the operator saw the preview.
    let superseded = format!("{PROVIDER_CONFIG}\n# external policy edit\n");
    std::fs::write(&config_path, &superseded).expect("simulate an external config edit");

    let error = service
        .apply(bound)
        .await
        .expect_err("a proposal bound to a superseded revision must not commit");
    let ControlError::Apply { errors } = &error else {
        panic!("expected a revision-bound apply refusal, got {error:?}");
    };
    assert!(!errors.is_empty(), "the refusal must explain itself");

    assert_eq!(
        std::fs::read_to_string(&config_path).expect("read config after refusal"),
        superseded,
        "a refused commit must leave the newer revision exactly as it was"
    );
    assert!(
        !temp.path().join("agents").join("writer").exists(),
        "a refused commit must not leave a staged agent workspace behind"
    );
}

#[tokio::test]
async fn preview_rejects_a_proposal_the_inventory_does_not_allow() {
    let _lock = ENV_LOCK.lock().await;
    let temp = tempfile::tempdir().expect("temporary install root");
    let config_path = seed_install(temp.path());
    let _guard = ConfigDirGuard::pin(temp.path());

    let service = ControlService::new(config_path.clone(), Surface::Cli);
    let mut proposal = writer_proposal();
    proposal.personality_files[0].filename = "MEMORY.md".to_string();

    let inspection = service.inspect().await.expect("inspect the seeded install");
    let error = service
        .preview(inspection, "custom.fixture", &proposal)
        .expect_err("a non-canonical personality filename must not preview");
    let ControlError::Proposal(rejection) = &error else {
        panic!("expected a typed proposal rejection, got {error:?}");
    };
    assert_eq!(
        rejection.code,
        ProposalErrorCode::NoncanonicalPersonalityFile
    );

    assert_eq!(
        std::fs::read_to_string(&config_path).expect("read config after rejection"),
        PROVIDER_CONFIG
    );
    assert!(!temp.path().join("agents").exists());
}

#[tokio::test]
async fn preview_rejects_a_provider_the_instance_does_not_offer() {
    let _lock = ENV_LOCK.lock().await;
    let temp = tempfile::tempdir().expect("temporary install root");
    let config_path = seed_install(temp.path());
    let _guard = ConfigDirGuard::pin(temp.path());

    let service = ControlService::new(config_path, Surface::Cli);
    let inspection = service.inspect().await.expect("inspect the seeded install");
    let error = service
        .preview(inspection, "custom.absent", &writer_proposal())
        .expect_err("an unlisted provider alias must not preview");
    let ControlError::Proposal(rejection) = &error else {
        panic!("expected a typed proposal rejection, got {error:?}");
    };
    assert_eq!(rejection.code, ProposalErrorCode::ProviderUnavailable);
}

#[tokio::test]
async fn inspect_refuses_a_stale_source_schema_before_loading_it() {
    let _lock = ENV_LOCK.lock().await;
    let temp = tempfile::tempdir().expect("temporary install root");
    let config_path = temp.path().join("config.toml");
    let legacy = "schema_version = 2\n";
    std::fs::write(&config_path, legacy).expect("write legacy config");
    let legacy_workspace = temp.path().join("workspace");
    std::fs::create_dir_all(&legacy_workspace).expect("create legacy workspace");
    std::fs::write(legacy_workspace.join("SOUL.md"), "legacy soul")
        .expect("write legacy personality");
    let _guard = ConfigDirGuard::pin(temp.path());

    let service = ControlService::new(config_path.clone(), Surface::Cli);
    let error = service
        .inspect()
        .await
        .expect_err("a stale schema must be refused, not migrated");
    assert!(
        matches!(error, ControlError::SourceSchemaOutdated),
        "expected a stale-schema refusal, got {error:?}"
    );

    assert_eq!(
        std::fs::read_to_string(&config_path).expect("read legacy config"),
        legacy,
        "refusing must not run the loader's filesystem migration"
    );
    assert_eq!(
        std::fs::read_to_string(legacy_workspace.join("SOUL.md"))
            .expect("legacy workspace remains"),
        "legacy soul"
    );
    assert!(!temp.path().join("agents/default/workspace").exists());
}

#[tokio::test]
async fn a_second_agent_cannot_reuse_an_alias_the_instance_already_has() {
    let _lock = ENV_LOCK.lock().await;
    let temp = tempfile::tempdir().expect("temporary install root");
    let config_path = seed_install(temp.path());
    let _guard = ConfigDirGuard::pin(temp.path());

    let service = ControlService::new(config_path.clone(), Surface::Cli);
    let first = service.inspect().await.expect("inspect the seeded install");
    let bound = service
        .preview(first, "custom.fixture", &writer_proposal())
        .expect("the contained proposal previews");
    service.apply(bound).await.expect("first apply succeeds");

    let second = service
        .inspect()
        .await
        .expect("inspect the install after the first apply");
    let error = service
        .preview(second, "custom.fixture", &writer_proposal())
        .expect_err("the alias is taken now");
    let ControlError::Proposal(rejection) = &error else {
        panic!("expected a typed proposal rejection, got {error:?}");
    };
    assert_eq!(rejection.code, ProposalErrorCode::AgentAliasExists);

    assert_component_test_outcome(temp.path(), &config_path);
}
