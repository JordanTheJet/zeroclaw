//! The approval receipt's binding to a *real* preview-bound proposal.
//!
//! The unit tests in `src/approval.rs` drive the broker with a synthetic
//! [`ProposalDigest`], which is the right level for the refusal matrix. This
//! file covers the one thing that cannot be checked with a synthetic digest:
//! that [`ProposalDigest::of_bound_proposal`] actually distinguishes the
//! proposals a `ControlService` produces, so a receipt for one cannot authorize
//! another.
//!
//! **No apply runs here.** `ControlService::apply` is never called: these tests
//! stop at `preview`, which the service documents as writing nothing. Phase 4
//! adds no path from a receipt to a configuration change, and this file must
//! not be the exception.
//!
//! `Config::load_or_init` resolves the install root from the environment, so
//! every test here serializes on `ENV_LOCK` and restores the previous value
//! before releasing it — the same discipline `control_service.rs` uses.

use std::path::Path;

use tokio::sync::Mutex;
use zeroclaw_control::{
    AgentProposal, ControlService, MemoryChoice, PersonalityFileProposal, ProposalDigest,
    RiskChoice, RuntimeChoice, SourceRevisionDigest,
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

/// The provider fixture. The URI is never contacted: preview makes no provider
/// call.
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

/// Digest the proposal a fresh service produces for `proposal`.
async fn digest_of(dir: &Path, proposal: &AgentProposal) -> ProposalDigest {
    let config_path = dir.join("config.toml");
    let service = ControlService::new(config_path, Surface::Cli);
    let inspection = service.inspect().await.expect("inspect the seeded install");
    let bound = service
        .preview(inspection, "custom.fixture", proposal)
        .expect("the contained proposal previews");
    ProposalDigest::of_bound_proposal(&bound).expect("digest the bound proposal")
}

#[tokio::test]
async fn the_same_bound_proposal_digests_identically() {
    let _lock = ENV_LOCK.lock().await;
    let temp = tempfile::tempdir().expect("temporary install root");
    seed_install(temp.path());
    let _guard = ConfigDirGuard::pin(temp.path());

    let first = digest_of(temp.path(), &writer_proposal()).await;
    let second = digest_of(temp.path(), &writer_proposal()).await;
    assert_eq!(
        first, second,
        "one proposal against one revision must have one digest, or a receipt \
         could never be matched back to the proposal it approved"
    );
    assert!(
        !temp.path().join("agents").exists(),
        "digesting a preview writes nothing"
    );
}

#[tokio::test]
async fn a_different_proposal_has_a_different_digest() {
    let _lock = ENV_LOCK.lock().await;
    let temp = tempfile::tempdir().expect("temporary install root");
    seed_install(temp.path());
    let _guard = ConfigDirGuard::pin(temp.path());

    let baseline = digest_of(temp.path(), &writer_proposal()).await;

    // Every field an operator would read off the preview must move the digest.
    // A receipt for one of these must not authorize another.
    let mut alias = writer_proposal();
    alias.agent_alias = "reader".to_string();

    let mut risk = writer_proposal();
    risk.risk = RiskChoice::Balanced;

    let mut runtime = writer_proposal();
    runtime.runtime = RuntimeChoice::Balanced;

    let mut memory = writer_proposal();
    memory.memory = MemoryChoice::None;

    let mut personality = writer_proposal();
    personality.personality_files = vec![PersonalityFileProposal {
        filename: "SOUL.md".to_string(),
        // One character different, and a materially different instruction.
        content: "# Soul\nWrite carelessly.".to_string(),
    }];

    let mut filename = writer_proposal();
    filename.personality_files = vec![PersonalityFileProposal {
        filename: "AGENTS.md".to_string(),
        content: "# Soul\nWrite carefully.".to_string(),
    }];

    for (what, proposal) in [
        ("agent alias", alias),
        ("risk profile", risk),
        ("runtime profile", runtime),
        ("memory backend", memory),
        ("personality content", personality),
        ("personality filename", filename),
    ] {
        let digest = digest_of(temp.path(), &proposal).await;
        assert_ne!(
            baseline, digest,
            "changing the {what} must change the proposal digest"
        );
    }
}

#[tokio::test]
async fn the_same_proposal_against_a_changed_revision_has_a_different_digest() {
    let _lock = ENV_LOCK.lock().await;
    let temp = tempfile::tempdir().expect("temporary install root");
    seed_install(temp.path());
    let _guard = ConfigDirGuard::pin(temp.path());

    let baseline = digest_of(temp.path(), &writer_proposal()).await;

    // The same proposal, previewed against a configuration that moved. A
    // receipt issued for the first must not apply to the second.
    std::fs::write(
        temp.path().join("config.toml"),
        format!("{PROVIDER_CONFIG}\n# an unrelated edit\n"),
    )
    .expect("rewrite config");

    let after = digest_of(temp.path(), &writer_proposal()).await;
    assert_ne!(
        baseline, after,
        "a preview computed against a different source revision is a different \
         proposal, so a stale receipt cannot follow the config"
    );
}

#[tokio::test]
async fn the_digest_discloses_neither_the_configuration_nor_the_personality_text() {
    let _lock = ENV_LOCK.lock().await;
    let temp = tempfile::tempdir().expect("temporary install root");
    seed_install(temp.path());
    let _guard = ConfigDirGuard::pin(temp.path());

    let digest = digest_of(temp.path(), &writer_proposal()).await;
    let rendered = digest.to_hex();
    for secret in [
        "fixture-placeholder",
        "Write carefully",
        "schema_version",
        "SOUL.md",
    ] {
        assert!(
            !rendered.contains(secret),
            "a digest must disclose nothing about its inputs: {secret}"
        );
    }
    assert_eq!(rendered.len(), 64, "a digest is 32 hex-encoded bytes");

    // The source-revision digest is likewise a digest, not the revision.
    let revision = SourceRevisionDigest::of(PROVIDER_CONFIG);
    assert!(!revision.to_hex().contains("fixture-placeholder"));
}
