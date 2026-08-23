//! The transport-independent management authority.
//!
//! [`ControlService`] owns one typed transaction over one ZeroClaw instance:
//!
//! ```text
//! inspect -> preview (validate + bind source revision) -> apply -> verify
//! ```
//!
//! It conducts no conversation, selects no model, reads no terminal, and prints
//! nothing. Approval is the caller's concern, but authority is not: [`apply`]
//! consumes a [`BoundProposal`] that only [`preview`] can mint, so no transport
//! can reach the revision-bound Quickstart commit without first producing the
//! preview an operator approved.
//!
//! The service holds no configuration of its own. Every step resolves the
//! canonical on-disk config at use time and proves its source bytes stayed
//! identical across the whole read; that revision is what the commit is bound
//! to. Post-apply verification is judged against the revision the commit
//! produced: the pinned config path is re-read, the read is proven stable
//! across the verification load, and the committed bytes are proven to be the
//! bound revision plus exactly the approved effect — so a concurrent writer's
//! state is refused rather than verified in the commit's name.
//!
//! [`apply`]: ControlService::apply
//! [`preview`]: ControlService::preview

use std::path::{Path, PathBuf};
use std::sync::Arc;

use zeroclaw_config::multi_agent::MemoryBackendKind;
use zeroclaw_config::schema::Config;
use zeroclaw_runtime::quickstart::{
    Surface, apply_new_agent_strict_if_source_unchanged_per_agent_memory,
};

use crate::FluentMessage;
use crate::inventory::{
    CapabilityRestrictedProviderFactory, CurrentProviderFactory, MemoryChoice,
    ProviderPickerInventory,
};
use crate::preview::{ProposalPreview, build_preview};
use crate::proposal::{
    AgentProposal, ProposalError, ValidatedProposal, revalidate_proposal, validate_proposal,
};

/// How many times a canonical read may be retried when the source bytes move
/// underneath it before the instance is reported busy.
const CONFIG_LOAD_ATTEMPTS: usize = 3;

/// The Quickstart error field that marks a config commit whose outcome could
/// not be determined. Such an operation is never retried.
const AMBIGUOUS_COMMIT_FIELD: &str = "config_commit_ambiguous";

/// The section holding the Quickstart bookkeeping flag every apply flips, and
/// the flag itself. Its movement is the commit's own footprint, never evidence
/// that something else edited the file.
const ONBOARD_STATE_SECTION: &str = "onboard_state";
/// See [`ONBOARD_STATE_SECTION`].
const QUICKSTART_COMPLETED_KEY: &str = "quickstart_completed";

/// Reject a source whose on-disk schema is not the current revision.
///
/// This runs before any generic loader so a V1/V2 filesystem migration cannot
/// happen underneath an operator who only asked to add an agent.
#[must_use]
pub fn source_schema_is_current(source: &str) -> bool {
    toml::from_str::<toml::Value>(source)
        .ok()
        .and_then(|value| zeroclaw_config::migration::detect_version(&value).ok())
        == Some(zeroclaw_config::migration::CURRENT_SCHEMA_VERSION)
}

/// Every way one management transaction can refuse.
///
/// Variants that correspond to operator-visible conditions carry a
/// [`FluentMessage`]; the client owns the catalogue and renders it. Variants
/// without one carry host detail that a transport must decide how to disclose.
#[derive(Debug)]
pub enum ControlError {
    /// The on-disk schema is not the current revision; the host must migrate
    /// explicitly before any management operation runs.
    SourceSchemaOutdated,
    /// The loaded configuration reported degraded security or degraded
    /// sections, so it is not a safe base for a new agent.
    ConfigDegraded,
    /// The source bytes changed under every stable-read attempt.
    ConfigBusy,
    /// Typed rejection from validation, preview, or pre-apply revalidation.
    Proposal(ProposalError),
    /// Quickstart refused the revision-bound commit and no agent was created.
    /// The caller may request a fresh preview against the new revision.
    Apply {
        /// Raw Quickstart error text, in Quickstart's own order. A transport is
        /// responsible for sanitizing this before display.
        errors: Vec<String>,
    },
    /// The config commit outcome could not be determined. The operation must
    /// not be retried; it needs operator resolution.
    AmbiguousCommit {
        /// Raw Quickstart error text, in Quickstart's own order. A transport is
        /// responsible for sanitizing this before display.
        errors: Vec<String>,
    },
    /// Post-apply verification could not confirm the approved bindings.
    VerificationFailed,
    /// Host I/O or configuration-load failure.
    Host(anyhow::Error),
}

impl ControlError {
    fn host(error: impl std::error::Error + Send + Sync + 'static, context: &'static str) -> Self {
        Self::Host(anyhow::Error::new(error).context(context))
    }

    /// The localization request for an operator-visible refusal, if this
    /// variant has one.
    #[must_use]
    pub fn fluent(&self) -> Option<FluentMessage> {
        let key = match self {
            Self::SourceSchemaOutdated => "cli-zerona-error-current-schema-required",
            Self::ConfigDegraded => "cli-zerona-error-healthy-config-required",
            Self::ConfigBusy => "cli-zerona-error-config-busy",
            Self::Proposal(error) => return Some(error.fluent()),
            Self::AmbiguousCommit { .. } => "cli-zerona-error-partial-apply",
            Self::VerificationFailed => "cli-zerona-error-verification",
            Self::Apply { .. } | Self::Host(_) => return None,
        };
        Some(FluentMessage::new(key))
    }
}

impl std::fmt::Display for ControlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SourceSchemaOutdated => {
                write!(f, "config source schema is not the current revision")
            }
            Self::ConfigDegraded => write!(f, "config loaded with degraded security or sections"),
            Self::ConfigBusy => write!(f, "config source changed during every stable read"),
            Self::Proposal(error) => write!(f, "{error}"),
            Self::Apply { errors } => {
                write!(f, "revision-bound apply refused: {}", errors.join("; "))
            }
            Self::AmbiguousCommit { errors } => {
                write!(
                    f,
                    "config commit outcome is ambiguous: {}",
                    errors.join("; ")
                )
            }
            Self::VerificationFailed => write!(f, "post-apply verification failed"),
            Self::Host(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for ControlError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Proposal(error) => Some(error),
            Self::Host(error) => Some(error.as_ref()),
            _ => None,
        }
    }
}

/// One canonical read of the target instance: the live configuration together
/// with the exact source bytes it was loaded from.
///
/// The two halves only mean something together. The configuration answers what
/// is true now; the revision is what a later commit is bound to. Nothing here
/// is cached — a new inspection is one new read.
pub struct ControlInspection {
    config: Config,
    source_revision: String,
}

impl ControlInspection {
    /// The live configuration this inspection resolved.
    #[must_use]
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// The exact source bytes the configuration was loaded from.
    #[must_use]
    pub fn source_revision(&self) -> &str {
        &self.source_revision
    }
}

/// Deliberately redacted: an inspection holds the whole live configuration and
/// its raw source bytes, so formatting it must never be a way to spill provider
/// settings, credentials, or install paths into a log or a panic message.
impl std::fmt::Debug for ControlInspection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ControlInspection")
            .field("source_revision_bytes", &self.source_revision.len())
            .finish_non_exhaustive()
    }
}

/// A validated proposal bound to the configuration revision its preview was
/// built from.
///
/// Only [`ControlService::preview`] mints one and only [`ControlService::apply`]
/// consumes one, which is what keeps "previewed and approved" and "applied"
/// the same operation rather than two.
pub struct BoundProposal {
    validated: ValidatedProposal,
    config: Config,
    expected_source: String,
    preview: ProposalPreview,
}

impl BoundProposal {
    /// The redacted effect and posture preview an operator approves.
    #[must_use]
    pub fn preview(&self) -> &ProposalPreview {
        &self.preview
    }

    /// The alias this transaction will create.
    #[must_use]
    pub fn agent_alias(&self) -> &str {
        &self.validated.proposal().agent_alias
    }

    /// The source revision the commit is bound to.
    #[must_use]
    pub fn source_revision(&self) -> &str {
        &self.expected_source
    }
}

/// Redacted for the same reason as [`ControlInspection`]: a bound proposal
/// carries the pre-image configuration and the operator's personality text.
impl std::fmt::Debug for BoundProposal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BoundProposal")
            .field("agent_alias", &self.agent_alias())
            .field("source_revision_bytes", &self.expected_source.len())
            .finish_non_exhaustive()
    }
}

/// The terminal state of a successful management transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlApplyOutcome {
    /// Quickstart committed the bound revision and verification confirmed the
    /// approved bindings.
    Verified {
        /// The alias that now exists.
        agent_alias: String,
    },
    /// Quickstart reported errors, but the reloaded configuration contains the
    /// approved agent and verification confirmed it. The change is durable, so
    /// the caller must report success and must not retry.
    VerifiedAfterReportedFailure {
        /// The alias that now exists.
        agent_alias: String,
    },
}

impl ControlApplyOutcome {
    /// The alias the transaction created.
    #[must_use]
    pub fn agent_alias(&self) -> &str {
        match self {
            Self::Verified { agent_alias } | Self::VerifiedAfterReportedFailure { agent_alias } => {
                agent_alias
            }
        }
    }
}

/// The single management authority for one ZeroClaw instance.
///
/// Construct one per target. It pins the target's config path and the surface
/// its commits are attributed to, and it resolves everything else from disk at
/// use time.
pub struct ControlService {
    config_path: PathBuf,
    surface: Surface,
    factory: Arc<dyn CapabilityRestrictedProviderFactory>,
    /// Interposition between the Quickstart commit and the post-apply read, so
    /// a test can land a foreign write in exactly the window this service is
    /// supposed to be immune to. Compiled out of every non-test build: the
    /// production transaction has no such seam.
    #[cfg(test)]
    post_commit_hook: Option<Arc<dyn Fn() + Send + Sync>>,
}

impl ControlService {
    /// A service for the instance whose configuration lives at `config_path`,
    /// attributing its commits to `surface`.
    #[must_use]
    pub fn new(config_path: impl Into<PathBuf>, surface: Surface) -> Self {
        Self::with_factory(config_path, surface, Arc::new(CurrentProviderFactory))
    }

    /// The same service with an explicit capability-restricted provider
    /// factory, so a test can drive the transaction without the production
    /// provider registry.
    #[must_use]
    pub fn with_factory(
        config_path: impl Into<PathBuf>,
        surface: Surface,
        factory: Arc<dyn CapabilityRestrictedProviderFactory>,
    ) -> Self {
        Self {
            config_path: config_path.into(),
            surface,
            factory,
            #[cfg(test)]
            post_commit_hook: None,
        }
    }

    /// The same service with a hook that runs after the Quickstart commit and
    /// before the post-apply revision is read. See [`Self::post_commit_hook`].
    #[cfg(test)]
    fn with_post_commit_hook(mut self, hook: Arc<dyn Fn() + Send + Sync>) -> Self {
        self.post_commit_hook = Some(hook);
        self
    }

    /// The configuration path this service is pinned to.
    #[must_use]
    pub fn config_path(&self) -> &Path {
        &self.config_path
    }

    /// Resolve the canonical configuration and prove its source bytes stayed
    /// identical for the whole read.
    ///
    /// A stale on-disk schema and a degraded load are refused here rather than
    /// migrated or tolerated, so no later step in the transaction can be built
    /// on one.
    pub async fn inspect(&self) -> Result<ControlInspection, ControlError> {
        for _ in 0..CONFIG_LOAD_ATTEMPTS {
            let before = tokio::fs::read_to_string(&self.config_path)
                .await
                .map_err(|error| {
                    ControlError::host(error, "read config revision before Zerona preview")
                })?;
            if !source_schema_is_current(&before) {
                return Err(ControlError::SourceSchemaOutdated);
            }
            let loaded = Box::pin(Config::load_or_init())
                .await
                .map_err(ControlError::Host)?;
            if !loaded.degraded_security.is_empty() || !loaded.degraded_sections.is_empty() {
                return Err(ControlError::ConfigDegraded);
            }
            let after = tokio::fs::read_to_string(&self.config_path)
                .await
                .map_err(|error| {
                    ControlError::host(error, "read config revision after Zerona preview")
                })?;
            if before == after && loaded.config_path == self.config_path {
                return Ok(ControlInspection {
                    config: loaded,
                    source_revision: before,
                });
            }
        }
        Err(ControlError::ConfigBusy)
    }

    /// The secret-free inventory of model-provider aliases eligible for a
    /// capability-restricted session on this instance.
    #[must_use]
    pub fn provider_inventory(&self, inspection: &ControlInspection) -> ProviderPickerInventory {
        ProviderPickerInventory::from_config(&inspection.config, self.factory.as_ref())
    }

    /// Validate one proposal against the inspected revision and bind the
    /// resulting preview to it.
    ///
    /// The inspection is consumed: its configuration and revision become the
    /// pre-image the commit is checked against, so the bytes an operator
    /// approves and the bytes the commit replaces are the same bytes.
    pub fn preview(
        &self,
        inspection: ControlInspection,
        selected_provider_ref: &str,
        proposal: &AgentProposal,
    ) -> Result<BoundProposal, ControlError> {
        let ControlInspection {
            config,
            source_revision,
        } = inspection;
        // Validation and preview are both pure and both start from the same
        // `validate_proposal`, so running validation first only fixes which
        // typed error a caller sees first: the validation error, exactly as
        // `build_preview` would have reported it.
        let validated = validate_proposal(
            &config,
            self.factory.as_ref(),
            selected_provider_ref,
            proposal,
        )
        .map_err(ControlError::Proposal)?;
        let preview = build_preview(
            &config,
            self.factory.as_ref(),
            selected_provider_ref,
            proposal,
        )
        .map_err(ControlError::Proposal)?
        .bind_expected_source();
        Ok(BoundProposal {
            validated,
            config,
            expected_source: source_revision,
            preview,
        })
    }

    /// Revalidate, commit against the bound revision, and verify the result.
    ///
    /// Quickstart performs the compare-and-set: if the on-disk source no longer
    /// equals [`BoundProposal::source_revision`], the commit is refused and the
    /// caller must request a fresh preview. Verification then re-reads the
    /// pinned config path, proves those bytes are the revision this commit
    /// produced (see [`Self::verify_committed_revision`]), and proves the
    /// installed agent matches the approved proposal and that nothing else
    /// moved.
    pub async fn apply(&self, bound: BoundProposal) -> Result<ControlApplyOutcome, ControlError> {
        let BoundProposal {
            validated,
            mut config,
            expected_source,
            preview: _,
        } = bound;
        let approved = revalidate_proposal(&config, self.factory.as_ref(), &validated)
            .map_err(ControlError::Proposal)?;
        let alias = approved.proposal().agent_alias.clone();
        let submission = approved.to_builder_submission();
        let preserved =
            PreservedApplyState::capture(&config).map_err(|_| ControlError::VerificationFailed)?;
        let apply_result = Box::pin(apply_new_agent_strict_if_source_unchanged_per_agent_memory(
            submission,
            &mut config,
            self.surface,
            &expected_source,
        ))
        .await;
        #[cfg(test)]
        if let Some(hook) = self.post_commit_hook.as_ref() {
            hook();
        }
        // Read the committed revision before the load that verification reads,
        // so the two can be proven to describe the same bytes. A failed read is
        // not an error here: the paths that do not verify must keep reporting
        // exactly what they reported before, and the paths that do verify treat
        // an unreadable revision as unverifiable.
        let committed = tokio::fs::read_to_string(&self.config_path).await.ok();
        let reloaded = Box::pin(Config::load_or_init())
            .await
            .map_err(ControlError::Host)?;
        match apply_result {
            Ok(_) => {
                self.verify_committed_revision(
                    &expected_source,
                    committed.as_deref(),
                    &reloaded,
                    &approved,
                )
                .await?;
                verify_install(&reloaded, &approved, &alias, &preserved)?;
                Ok(ControlApplyOutcome::Verified { agent_alias: alias })
            }
            Err(errors) => {
                if reloaded.agents.contains_key(&alias) {
                    self.verify_committed_revision(
                        &expected_source,
                        committed.as_deref(),
                        &reloaded,
                        &approved,
                    )
                    .await?;
                    verify_install(&reloaded, &approved, &alias, &preserved)?;
                    return Ok(ControlApplyOutcome::VerifiedAfterReportedFailure {
                        agent_alias: alias,
                    });
                }
                let ambiguous = errors
                    .iter()
                    .any(|error| error.field == AMBIGUOUS_COMMIT_FIELD);
                let errors: Vec<String> = errors.iter().map(ToString::to_string).collect();
                if ambiguous {
                    return Err(ControlError::AmbiguousCommit { errors });
                }
                Err(ControlError::Apply { errors })
            }
        }
    }

    /// Prove the state verification is about to judge is the state this
    /// transaction committed, not whatever happens to be on disk.
    ///
    /// `Config::load_or_init` resolves the install from the ambient
    /// environment and takes no lock, so on its own it can hand verification a
    /// concurrent writer's revision and let the transaction claim that
    /// revision as its own result. Four properties close that gap, each of
    /// which fails the transaction rather than widening what it will accept:
    ///
    /// 1. The load resolved *this* service's pinned config path, so the bytes
    ///    verified and the bytes committed are the same file.
    /// 2. The pinned path still holds `committed` after the load, so no write
    ///    slipped between reading the revision and loading it.
    /// 3. The committed revision is not the revision the commit was bound to:
    ///    a commit that reported success must have moved the file.
    /// 4. The committed revision is the bound revision plus exactly this
    ///    proposal's approved effect and nothing else — the precise form of
    ///    (3), and the property a foreign edit to any other section breaks.
    async fn verify_committed_revision(
        &self,
        bound_source: &str,
        committed: Option<&str>,
        reloaded: &Config,
        approved: &ValidatedProposal,
    ) -> Result<(), ControlError> {
        let Some(committed) = committed else {
            return Err(ControlError::VerificationFailed);
        };
        if reloaded.config_path != self.config_path {
            return Err(ControlError::VerificationFailed);
        }
        let after_load = tokio::fs::read_to_string(&self.config_path).await.ok();
        if after_load.as_deref() != Some(committed) {
            return Err(ControlError::VerificationFailed);
        }
        if committed == bound_source {
            return Err(ControlError::VerificationFailed);
        }
        if !committed_revision_is_the_approved_post_image(bound_source, committed, approved) {
            return Err(ControlError::VerificationFailed);
        }
        Ok(())
    }
}

/// Is `committed` exactly `bound_source` plus the effect this proposal was
/// approved for?
///
/// A strict add-agent commit writes four regions and no others: the new
/// agent's own table, the Quickstart completion flag, and the two named
/// profile presets — and a preset only when the bound revision did not already
/// carry one under that name, because an existing block always wins. Removing
/// exactly those regions must leave the two documents identical.
///
/// The comparison is deliberately made on the on-disk documents rather than on
/// loaded [`Config`] values: both sides are then the same kind of bytes, so
/// secret ciphertext, environment-masked values, and formatting cannot make a
/// faithful commit look like drift. It is also deliberately an allowlist —
/// anything Quickstart might write in future that this list does not name
/// fails the transaction loudly instead of passing unnoticed.
fn committed_revision_is_the_approved_post_image(
    bound_source: &str,
    committed: &str,
    approved: &ValidatedProposal,
) -> bool {
    let (Ok(mut bound_doc), Ok(mut committed_doc)) = (
        toml::from_str::<toml::Value>(bound_source),
        toml::from_str::<toml::Value>(committed),
    ) else {
        return false;
    };
    let raw = approved.proposal();
    // The approved agent is the whole point of the commit: present in what was
    // written, absent from what it was written against.
    if !remove_table_entry(&mut committed_doc, "agents", &raw.agent_alias)
        || table_entry_exists(&bound_doc, "agents", &raw.agent_alias)
    {
        return false;
    }
    for (section, preset) in [
        ("risk_profiles", raw.risk.preset_name()),
        ("runtime_profiles", raw.runtime.preset_name()),
    ] {
        if !table_entry_exists(&bound_doc, section, preset) {
            remove_table_entry(&mut committed_doc, section, preset);
        }
    }
    remove_table_entry(
        &mut bound_doc,
        ONBOARD_STATE_SECTION,
        QUICKSTART_COMPLETED_KEY,
    );
    remove_table_entry(
        &mut committed_doc,
        ONBOARD_STATE_SECTION,
        QUICKSTART_COMPLETED_KEY,
    );
    bound_doc == committed_doc
}

/// Remove `<section>.<key>`, and the now-empty `<section>` with it, so a table
/// one document only has because of the approved effect cannot itself read as
/// a difference. Reports whether the entry was there to remove.
fn remove_table_entry(document: &mut toml::Value, section: &str, key: &str) -> bool {
    let Some(root) = document.as_table_mut() else {
        return false;
    };
    let Some(entries) = root.get_mut(section).and_then(toml::Value::as_table_mut) else {
        return false;
    };
    let removed = entries.remove(key).is_some();
    if entries.is_empty() {
        root.remove(section);
    }
    removed
}

/// See [`remove_table_entry`].
fn table_entry_exists(document: &toml::Value, section: &str, key: &str) -> bool {
    document
        .get(section)
        .and_then(|entries| entries.get(key))
        .is_some()
}

/// The configuration sections an add-agent transaction must leave alone.
///
/// Captured before the commit and compared after it, so "added exactly one
/// agent" is proven rather than assumed.
struct PreservedApplyState {
    memory: serde_json::Value,
    storage: serde_json::Value,
    agents: serde_json::Value,
    channels: serde_json::Value,
    peer_groups: serde_json::Value,
    providers: serde_json::Value,
}

impl PreservedApplyState {
    fn capture(config: &Config) -> Result<Self, serde_json::Error> {
        Ok(Self {
            memory: serde_json::to_value(&config.memory)?,
            storage: serde_json::to_value(&config.storage)?,
            agents: serde_json::to_value(&config.agents)?,
            channels: serde_json::to_value(&config.channels)?,
            peer_groups: serde_json::to_value(&config.peer_groups)?,
            providers: serde_json::to_value(&config.providers)?,
        })
    }

    fn matches_after_add(
        &self,
        config: &Config,
        added_alias: &str,
    ) -> Result<bool, serde_json::Error> {
        let mut existing_agents = config.agents.clone();
        existing_agents.remove(added_alias);
        Ok(self.memory == serde_json::to_value(&config.memory)?
            && self.storage == serde_json::to_value(&config.storage)?
            && self.agents == serde_json::to_value(existing_agents)?
            && self.channels == serde_json::to_value(&config.channels)?
            && self.peer_groups == serde_json::to_value(&config.peer_groups)?
            && self.providers == serde_json::to_value(&config.providers)?)
    }
}

/// Prove the reloaded configuration contains exactly the approved agent, bound
/// to the approved provider, profiles, and memory, with the approved
/// personality bytes on disk and no other section changed.
fn verify_install(
    config: &Config,
    proposal: &ValidatedProposal,
    expected_alias: &str,
    preserved: &PreservedApplyState,
) -> Result<(), ControlError> {
    let Some(agent) = config.agents.get(expected_alias) else {
        return Err(ControlError::VerificationFailed);
    };
    let raw = proposal.proposal();
    let expected_memory = match raw.memory {
        MemoryChoice::Sqlite => MemoryBackendKind::Sqlite,
        MemoryChoice::Markdown => MemoryBackendKind::Markdown,
        MemoryChoice::None => MemoryBackendKind::None,
    };
    if !preserved
        .matches_after_add(config, expected_alias)
        .map_err(|_| ControlError::VerificationFailed)?
        || agent.model_provider.as_str() != proposal.selected_provider_ref()
        || agent.risk_profile.as_str() != raw.risk.preset_name()
        || agent.runtime_profile.as_str() != raw.runtime.preset_name()
        || !agent.channels.is_empty()
        || agent.memory.backend != expected_memory
    {
        return Err(ControlError::VerificationFailed);
    }
    let workspace = config.agent_workspace_dir(expected_alias);
    for file in &raw.personality_files {
        let installed = std::fs::read_to_string(workspace.join(&file.filename))
            .map_err(|_| ControlError::VerificationFailed)?;
        if installed != file.content {
            return Err(ControlError::VerificationFailed);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inventory::{RiskChoice, RuntimeChoice};
    use crate::proposal::PersonalityFileProposal;
    use zeroclaw_config::schema::AliasedAgentConfig;

    use crate::test_support::{ConfigDirGuard, config_env_lock};

    /// The fixture `tests/control_service.rs` seeds, so the concurrent-writer
    /// test and the behavior-boundary tests judge the same install.
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

    /// The proposal above, validated against the fixture, so the post-image
    /// comparison can be driven with the same approved effect an apply carries.
    fn approved_writer_proposal() -> ValidatedProposal {
        let mut config: Config = toml::from_str(PROVIDER_CONFIG).expect("parse fixture config");
        config.config_path = PathBuf::from("/nonexistent/config.toml");
        validate_proposal(
            &config,
            &CurrentProviderFactory,
            "custom.fixture",
            &writer_proposal(),
        )
        .expect("the fixture proposal validates")
    }

    /// The revision a faithful commit of [`approved_writer_proposal`] leaves on
    /// disk: the fixture plus the agent, both named presets, and the Quickstart
    /// completion flag.
    fn faithful_post_image() -> String {
        format!(
            "{PROVIDER_CONFIG}
[agents.writer]
model_provider = \"custom.fixture\"
risk_profile = \"locked_down\"
runtime_profile = \"tight\"

[agents.writer.memory]
backend = \"markdown\"

[risk_profiles.locked_down]
allow_shell = false

[runtime_profiles.tight]
max_tokens = 1024

[onboard_state]
quickstart_completed = true
"
        )
    }

    #[test]
    fn post_apply_snapshot_allows_only_the_new_agent_in_preserved_sections() {
        let mut before = Config::default();
        before
            .agents
            .insert("resident".into(), AliasedAgentConfig::default());
        let preserved = PreservedApplyState::capture(&before).expect("capture preserved sections");

        let mut after = before.clone();
        after
            .agents
            .insert("new_agent".into(), AliasedAgentConfig::default());
        assert!(
            preserved
                .matches_after_add(&after, "new_agent")
                .expect("compare preserved sections")
        );

        after.memory.backend = "none".into();
        assert!(
            !preserved
                .matches_after_add(&after, "new_agent")
                .expect("compare preserved sections")
        );
    }

    #[test]
    fn stale_source_schemas_are_refused_before_any_loader_runs() {
        assert!(source_schema_is_current("schema_version = 3\n"));
        assert!(!source_schema_is_current("schema_version = 2\n"));
        assert!(!source_schema_is_current("[autonomy]\nlevel = 'full'\n"));
        assert!(!source_schema_is_current("not valid toml = [\n"));
    }

    #[test]
    fn the_approved_effect_is_the_only_difference_a_committed_revision_may_carry() {
        let approved = approved_writer_proposal();
        assert!(
            committed_revision_is_the_approved_post_image(
                PROVIDER_CONFIG,
                &faithful_post_image(),
                &approved
            ),
            "the agent, both seeded presets, and the completion flag are the approved effect"
        );

        let foreign = faithful_post_image().replace("provider_retries = 0", "provider_retries = 7");
        assert!(
            !committed_revision_is_the_approved_post_image(PROVIDER_CONFIG, &foreign, &approved),
            "an edit to a section this transaction never touched is not the approved effect"
        );

        assert!(
            !committed_revision_is_the_approved_post_image(
                PROVIDER_CONFIG,
                PROVIDER_CONFIG,
                &approved
            ),
            "a revision without the approved agent cannot be the revision that added it"
        );
    }

    #[test]
    fn a_preset_the_bound_revision_already_carried_may_not_move() {
        let bound = format!("{PROVIDER_CONFIG}\n[risk_profiles.locked_down]\nallow_shell = true\n");
        assert!(
            !committed_revision_is_the_approved_post_image(
                &bound,
                &faithful_post_image(),
                &approved_writer_proposal()
            ),
            "Quickstart never rewrites an existing preset block, so a moved one is drift"
        );
    }

    /// The window this service is supposed to be immune to: the commit has
    /// landed, and someone else rewrites the config before verification reads
    /// it. The edit is deliberately one every other post-apply check tolerates
    /// — `reliability` is not the new agent, not one of the preserved sections,
    /// and not a field `verify_install` reads — so what refuses it can only be
    /// the committed-revision proof.
    #[tokio::test]
    async fn a_writer_that_lands_before_verification_reads_is_refused_not_verified() {
        let _lock = config_env_lock().lock().await;
        let temp = tempfile::tempdir().expect("temporary install root");
        let config_path = temp.path().join("config.toml");
        std::fs::write(&config_path, PROVIDER_CONFIG).expect("seed the install");
        let _guard = ConfigDirGuard::pin(temp.path());

        let foreign_writer = {
            let config_path = config_path.clone();
            Arc::new(move || {
                let committed =
                    std::fs::read_to_string(&config_path).expect("read the committed revision");
                assert!(
                    committed.contains("writer"),
                    "the hook must run after the commit landed"
                );
                let edited = committed.replace("provider_retries = 0", "provider_retries = 7");
                assert_ne!(edited, committed, "the foreign edit must change the file");
                std::fs::write(&config_path, edited).expect("land the foreign edit");
            }) as Arc<dyn Fn() + Send + Sync>
        };

        let service = ControlService::new(config_path.clone(), Surface::Cli)
            .with_post_commit_hook(foreign_writer);
        let inspection = service.inspect().await.expect("inspect the seeded install");
        let bound = service
            .preview(inspection, "custom.fixture", &writer_proposal())
            .expect("the contained proposal previews");

        let error = service
            .apply(bound)
            .await
            .expect_err("verification must not judge a concurrent writer's revision");
        assert!(
            matches!(error, ControlError::VerificationFailed),
            "expected the committed-revision proof to refuse, got {error:?}"
        );

        assert!(
            std::fs::read_to_string(&config_path)
                .expect("read config after the refusal")
                .contains("provider_retries = 7"),
            "refusing reports the transaction unverified; it does not undo the writer"
        );
    }
}
