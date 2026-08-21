//! Quickstart apply path.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use zeroclaw_config::helpers::kebab_to_snake;
use zeroclaw_config::presets::{
    AgentIdentity, BuilderSubmission, ChannelQuickStart, MemoryChoice, ModelProviderChoice,
    SelectorChoice, recommended_runtime_preset, risk_preset, runtime_preset,
};
use zeroclaw_config::schema::{Config, WireApi};
use zeroclaw_config::traits::AliasSource;

/// Which surface invoked the Quickstart. Stamped on every event in
/// the apply path so SSE/dashboard consumers can filter by origin
/// without parsing message strings.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Surface {
    Web,
    Tui,
    Cli,
    Test,
}

impl Surface {
    pub fn as_str(self) -> &'static str {
        match self {
            Surface::Web => "web",
            Surface::Tui => "tui",
            Surface::Cli => "cli",
            Surface::Test => "test",
        }
    }
}

/// Per-run attribution carried through the apply path so every emitted
/// event lands with the same correlation id. Constructed by `apply`
/// and `validate_only`; threaded down into `apply_into` and the
/// per-selector helpers via `&RunCtx`.
struct RunCtx {
    run_id: String,
    surface: Surface,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MemoryApplyMode {
    InstallWide,
    CreatedAgent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PersonalityCommitOrder {
    AfterConfig,
    BeforeConfigForNewAgent,
}

fn strict_workspace_rollback_allowed(
    disposition: zeroclaw_config::schema::ConfigWriteDisposition,
) -> bool {
    disposition == zeroclaw_config::schema::ConfigWriteDisposition::NotCommitted
}

struct AgentWorkspaceLock(std::fs::File);

impl Drop for AgentWorkspaceLock {
    fn drop(&mut self) {
        let _ = fs2::FileExt::unlock(&self.0);
    }
}

async fn acquire_agent_workspace_lock(
    config: &Config,
    agent_alias: &str,
    ctx: Option<&RunCtx>,
) -> Result<AgentWorkspaceLock, QuickstartError> {
    let lock_dir = config.install_root_dir().join(".zeroclaw-locks");
    tokio::fs::create_dir_all(&lock_dir)
        .await
        .map_err(|error| {
            QuickstartError::for_surface(
                ctx,
                QuickstartStep::Agent,
                "agent_workspace_lock",
                format!("could not create agent workspace lock directory: {error}"),
                "cli-quickstart-error-personality-workspace",
                &[("err", &error.to_string())],
            )
        })?;
    let alias_digest = format!("{:x}", Sha256::digest(agent_alias.as_bytes()));
    let lock_path = lock_dir.join(format!("agent-{alias_digest}.lock"));
    let file = tokio::task::spawn_blocking(move || -> std::io::Result<std::fs::File> {
        use fs2::FileExt as _;
        let mut options = std::fs::OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let file = options.open(lock_path)?;
        file.lock_exclusive()?;
        Ok(file)
    })
    .await
    .map_err(|error| {
        QuickstartError::for_surface(
            ctx,
            QuickstartStep::Agent,
            "agent_workspace_lock",
            format!("agent workspace lock task failed: {error}"),
            "cli-quickstart-error-personality-workspace",
            &[("err", &error.to_string())],
        )
    })?
    .map_err(|error| {
        QuickstartError::for_surface(
            ctx,
            QuickstartStep::Agent,
            "agent_workspace_lock",
            format!("could not acquire agent workspace lock: {error}"),
            "cli-quickstart-error-personality-workspace",
            &[("err", &error.to_string())],
        )
    })?;
    Ok(AgentWorkspaceLock(file))
}

impl RunCtx {
    fn new(surface: Surface) -> Self {
        // Fall back to nanosecond timestamp if a system without a clock
        // is somehow in play. Either way the id is unique per process.
        let run_id = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| format!("{:x}{:x}", d.as_secs(), d.subsec_nanos()))
            .unwrap_or_else(|_| format!("{:x}", std::process::id()));
        Self { run_id, surface }
    }

    fn base_attrs(&self) -> serde_json::Value {
        serde_json::json!({
            "quickstart.run_id": self.run_id,
            "quickstart.surface": self.surface.as_str(),
        })
    }
}

/// Layer per-event attrs on top of the run-scoped base. Both must be
/// JSON objects; non-object inputs return `base` unchanged.
fn merge_attrs(base: serde_json::Value, extra: serde_json::Value) -> serde_json::Value {
    let (mut base_map, extra_map) = match (base, extra) {
        (serde_json::Value::Object(b), serde_json::Value::Object(e)) => (b, e),
        (b, _) => return b,
    };
    for (k, v) in extra_map {
        base_map.insert(k, v);
    }
    serde_json::Value::Object(base_map)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppliedAgent {
    pub alias: String,
    pub model_provider: String,
    pub risk_profile: String,
    pub runtime_profile: String,
    pub channels: Vec<String>,
    pub memory_backend: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum QuickstartStep {
    ModelProvider,
    RiskProfile,
    RuntimeProfile,
    Memory,
    Channels,
    PeerGroups,
    Agent,
}

impl QuickstartStep {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::ModelProvider => "Model provider",
            Self::RiskProfile => "Risk profile",
            Self::RuntimeProfile => "Runtime profile",
            Self::Memory => "Memory",
            Self::Channels => "Channels",
            Self::PeerGroups => "Peer groups",
            Self::Agent => "Agent",
        }
    }

    #[must_use]
    pub fn label_key(self) -> &'static str {
        match self {
            Self::ModelProvider => "cli-quickstart-step-model-provider",
            Self::RiskProfile => "cli-quickstart-step-risk-profile",
            Self::RuntimeProfile => "cli-quickstart-step-runtime-profile",
            Self::Memory => "cli-quickstart-step-memory",
            Self::Channels => "cli-quickstart-step-channels",
            Self::PeerGroups => "cli-quickstart-step-peer-groups",
            Self::Agent => "cli-quickstart-step-agent",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct QuickstartError {
    pub step: QuickstartStep,
    pub field: String,
    pub message: String,
}

impl QuickstartError {
    fn new(step: QuickstartStep, field: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            step,
            field: field.into(),
            message: message.into(),
        }
    }

    fn for_surface(
        ctx: Option<&RunCtx>,
        step: QuickstartStep,
        field: impl Into<String>,
        fallback: impl Into<String>,
        key: &str,
        args: &[(&str, &str)],
    ) -> Self {
        let fallback = fallback.into();
        if !matches!(ctx.map(|ctx| ctx.surface), Some(Surface::Cli)) {
            return Self::new(step, field, fallback);
        }

        Self::new(
            step,
            field,
            crate::i18n::get_required_cli_string_with_args(key, args),
        )
    }

    fn config_source_changed(ctx: &RunCtx) -> Self {
        const REASON: &str =
            "configuration changed since the Quickstart preview; reload and review before applying";
        Self::for_surface(
            Some(ctx),
            QuickstartStep::Agent,
            "config_source",
            REASON,
            "cli-quickstart-error-persist-config",
            &[("err", REASON)],
        )
    }
}

impl std::fmt::Display for QuickstartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.field.is_empty() {
            write!(f, "{:?}: {}", self.step, self.message)
        } else {
            write!(f, "{:?}.{}: {}", self.step, self.field, self.message)
        }
    }
}

pub fn validate_only(
    submission: &BuilderSubmission,
    config: &Config,
) -> Result<(), Vec<QuickstartError>> {
    validate_only_with_surface(submission, config, Surface::Web)
}

pub fn validate_only_with_surface(
    submission: &BuilderSubmission,
    config: &Config,
    surface: Surface,
) -> Result<(), Vec<QuickstartError>> {
    let ctx = RunCtx::new(surface);
    let mut staged = config.clone();
    let mut errors = Vec::new();
    // validate-only never commits; staged tempfiles drop at scope exit.
    let mut staged_files = Vec::new();
    apply_into(
        &mut staged,
        submission,
        &mut staged_files,
        &mut errors,
        Some(&ctx),
    );
    let ok = errors.is_empty();
    let attrs = merge_attrs(
        ctx.base_attrs(),
        serde_json::json!({"error_count": errors.len()}),
    );
    let outcome = if ok {
        ::zeroclaw_log::EventOutcome::Success
    } else {
        ::zeroclaw_log::EventOutcome::Failure
    };
    if ok {
        ::zeroclaw_log::record!(
            INFO,
            ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Validate)
                .with_outcome(outcome)
                .with_attrs(attrs),
            "quickstart: validate_only"
        );
    } else {
        ::zeroclaw_log::record!(
            WARN,
            ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Validate)
                .with_outcome(outcome)
                .with_attrs(attrs),
            "quickstart: validate_only"
        );
    }
    if ok { Ok(()) } else { Err(errors) }
}

pub async fn apply(
    submission: BuilderSubmission,
    config: &mut Config,
) -> Result<AppliedAgent, Vec<QuickstartError>> {
    apply_with_surface(submission, config, Surface::Web).await
}

pub async fn apply_with_surface(
    submission: BuilderSubmission,
    config: &mut Config,
    surface: Surface,
) -> Result<AppliedAgent, Vec<QuickstartError>> {
    apply_with_surface_impl(
        submission,
        config,
        surface,
        None,
        MemoryApplyMode::InstallWide,
        PersonalityCommitOrder::AfterConfig,
    )
    .await
}

/// Apply a Quickstart submission only while `config.toml` still matches the
/// exact source revision against which the caller previewed and approved it.
///
/// The source is checked before any submission mutation or personality-file
/// staging, then checked again by [`Config::save_dirty_if_source_unchanged`]
/// at the persistence boundary. A persistence-boundary drift refusal leaves
/// staged tempfiles to drop and keeps the in-memory edits and dirty paths for
/// caller diagnostics; callers should reload rather than reuse that state.
pub async fn apply_with_surface_if_source_unchanged(
    submission: BuilderSubmission,
    config: &mut Config,
    surface: Surface,
    expected_source: &str,
) -> Result<AppliedAgent, Vec<QuickstartError>> {
    apply_with_surface_impl(
        submission,
        config,
        surface,
        Some(expected_source),
        MemoryApplyMode::InstallWide,
        PersonalityCommitOrder::AfterConfig,
    )
    .await
}

/// Revision-bound Quickstart apply for adding one agent without changing the
/// install-wide memory backend or storage registry.
///
/// `submission.memory` must be a fresh `sqlite`, `markdown`, or `none` choice.
/// That choice is written only to `agents.<new_alias>.memory.backend`; existing
/// agents, [`Config::memory`], and [`Config::storage`] are left untouched. All
/// other Quickstart mutation, persistence, and personality-file ordering is
/// shared with [`apply_with_surface_if_source_unchanged`].
pub async fn apply_with_surface_if_source_unchanged_per_agent_memory(
    submission: BuilderSubmission,
    config: &mut Config,
    surface: Surface,
    expected_source: &str,
) -> Result<AppliedAgent, Vec<QuickstartError>> {
    apply_with_surface_impl(
        submission,
        config,
        surface,
        Some(expected_source),
        MemoryApplyMode::CreatedAgent,
        PersonalityCommitOrder::AfterConfig,
    )
    .await
}

/// Strict revision-bound add-agent apply used by Zerona. Personality files are
/// committed into a previously-absent agent workspace before the config CAS;
/// the config is never allowed to reference an incomplete personality bundle.
/// If the CAS refuses, the newly-created workspace is removed.
pub async fn apply_new_agent_strict_if_source_unchanged_per_agent_memory(
    submission: BuilderSubmission,
    config: &mut Config,
    surface: Surface,
    expected_source: &str,
) -> Result<AppliedAgent, Vec<QuickstartError>> {
    apply_with_surface_impl(
        submission,
        config,
        surface,
        Some(expected_source),
        MemoryApplyMode::CreatedAgent,
        PersonalityCommitOrder::BeforeConfigForNewAgent,
    )
    .await
}

async fn apply_with_surface_impl(
    submission: BuilderSubmission,
    config: &mut Config,
    surface: Surface,
    expected_source: Option<&str>,
    memory_mode: MemoryApplyMode,
    personality_order: PersonalityCommitOrder,
) -> Result<AppliedAgent, Vec<QuickstartError>> {
    let ctx = RunCtx::new(surface);
    let started = std::time::Instant::now();
    let _agent_workspace_lock =
        if personality_order == PersonalityCommitOrder::BeforeConfigForNewAgent {
            Some(
                acquire_agent_workspace_lock(config, &submission.agent.name, Some(&ctx))
                    .await
                    .map_err(|error| vec![error])?,
            )
        } else {
            None
        };

    ::zeroclaw_log::record!(
        INFO,
        ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Start)
            .with_attrs(ctx.base_attrs()),
        "quickstart: apply"
    );

    if let Some(expected_source) = expected_source {
        let source_matches = match tokio::fs::read_to_string(&config.config_path).await {
            Ok(current) => current == expected_source,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => false,
            Err(err) => {
                return Err(vec![QuickstartError::for_surface(
                    Some(&ctx),
                    QuickstartStep::Agent,
                    "config_source",
                    format!("failed to read config before apply: {err}"),
                    "cli-quickstart-error-persist-config",
                    &[("err", &err.to_string())],
                )]);
            }
        };
        if !source_matches {
            ::zeroclaw_log::record!(
                WARN,
                ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Reject)
                    .with_outcome(::zeroclaw_log::EventOutcome::Failure)
                    .with_attrs(merge_attrs(
                        ctx.base_attrs(),
                        serde_json::json!({
                            "phase": "pre_apply",
                            "reason": "config_source_changed",
                        }),
                    )),
                "quickstart: expected config source changed"
            );
            return Err(vec![QuickstartError::config_source_changed(&ctx)]);
        }
    }

    if personality_order == PersonalityCommitOrder::BeforeConfigForNewAgent
        && let Err(error) =
            ensure_new_agent_workspace_absent(config, &submission.agent.name, Some(&ctx))
    {
        return Err(vec![error]);
    }

    let mut errors = Vec::new();
    let mut staged_files = Vec::new();
    let applied = apply_into_with_memory_mode(
        config,
        &submission,
        &mut staged_files,
        &mut errors,
        Some(&ctx),
        memory_mode,
    );
    if !errors.is_empty() {
        ::zeroclaw_log::record!(
            WARN,
            ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Fail)
                .with_outcome(::zeroclaw_log::EventOutcome::Failure)
                .with_attrs(merge_attrs(
                    ctx.base_attrs(),
                    serde_json::json!({
                        "error_count": errors.len(),
                        "elapsed_ms": started.elapsed().as_millis() as u64,
                    }),
                )),
            "quickstart: apply rejected"
        );
        return Err(errors);
    }
    let applied = match applied {
        Some(applied) => applied,
        None => {
            return Err(vec![QuickstartError::for_surface(
                Some(&ctx),
                QuickstartStep::Agent,
                "apply",
                "internal error: apply_into returned no result despite no validation errors",
                "cli-quickstart-error-internal-no-result",
                &[],
            )]);
        }
    };

    config
        .set_prop_persistent("onboard_state.quickstart_completed", "true")
        .map_err(|err| {
            vec![QuickstartError::for_surface(
                Some(&ctx),
                QuickstartStep::Agent,
                "",
                format!("failed to flip quickstart-completed: {err}"),
                "cli-quickstart-error-completion-flag",
                &[("err", &err.to_string())],
            )]
        })?;
    ::zeroclaw_log::record!(
        INFO,
        ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Note).with_attrs(
            merge_attrs(
                ctx.base_attrs(),
                serde_json::json!({"flag": "quickstart_completed"}),
            )
        ),
        "quickstart: completion flag flipped"
    );

    let strict_workspace = if personality_order == PersonalityCommitOrder::BeforeConfigForNewAgent {
        if let Err(error) =
            ensure_new_agent_workspace_absent(config, &submission.agent.name, Some(&ctx))
        {
            return Err(vec![error]);
        }
        let workspace = commit_new_agent_personality_before_config(
            std::mem::take(&mut staged_files),
            &mut errors,
            Some(&ctx),
        );
        if !errors.is_empty() {
            return Err(errors);
        }
        workspace
    } else {
        None
    };

    let dirty_count = config.dirty_paths.len();
    let write_started = std::time::Instant::now();
    ::zeroclaw_log::record!(
        DEBUG,
        ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Write).with_attrs(
            merge_attrs(
                ctx.base_attrs(),
                serde_json::json!({"dirty_path_count": dirty_count}),
            )
        ),
        "quickstart: persist start"
    );
    let write_result = match expected_source {
        Some(expected_source) => config.save_dirty_if_source_unchanged(expected_source).await,
        None => config.save_dirty().await.map(|()| true),
    };
    let write_ms = write_started.elapsed().as_millis() as u64;
    match &write_result {
        Ok(true) => ::zeroclaw_log::record!(
            INFO,
            ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Write)
                .with_outcome(::zeroclaw_log::EventOutcome::Success)
                .with_attrs(merge_attrs(
                    ctx.base_attrs(),
                    serde_json::json!({
                        "dirty_path_count": dirty_count,
                        "elapsed_ms": write_ms,
                    }),
                )),
            "quickstart: persist complete"
        ),
        Ok(false) => ::zeroclaw_log::record!(
            WARN,
            ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Reject)
                .with_outcome(::zeroclaw_log::EventOutcome::Failure)
                .with_attrs(merge_attrs(
                    ctx.base_attrs(),
                    serde_json::json!({
                        "dirty_path_count": dirty_count,
                        "elapsed_ms": write_ms,
                        "phase": "persist",
                        "reason": "config_source_changed",
                    }),
                )),
            "quickstart: expected config source changed"
        ),
        Err(err) => ::zeroclaw_log::record!(
            WARN,
            ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Write)
                .with_outcome(::zeroclaw_log::EventOutcome::Failure)
                .with_attrs(merge_attrs(
                    ctx.base_attrs(),
                    serde_json::json!({
                        "dirty_path_count": dirty_count,
                        "elapsed_ms": write_ms,
                        "error": err.to_string(),
                    }),
                )),
            "quickstart: persist failed"
        ),
    }
    let persisted = match write_result {
        Ok(persisted) => persisted,
        Err(err) => {
            let disposition = zeroclaw_config::schema::config_write_disposition(&err);
            let error_field =
                if disposition == zeroclaw_config::schema::ConfigWriteDisposition::Ambiguous {
                    "config_commit_ambiguous"
                } else {
                    ""
                };
            let mut errors = vec![QuickstartError::for_surface(
                Some(&ctx),
                QuickstartStep::Agent,
                error_field,
                format!("failed to persist config: {err}"),
                "cli-quickstart-error-persist-config",
                &[("err", &err.to_string())],
            )];
            if strict_workspace_rollback_allowed(disposition)
                && let Some(workspace) = strict_workspace
                && let Err(cleanup_error) = workspace.rollback()
            {
                errors.push(QuickstartError::for_surface(
                    Some(&ctx),
                    QuickstartStep::Agent,
                    "personality_files",
                    format!("failed to roll back uncommitted workspace: {cleanup_error}"),
                    "cli-quickstart-error-personality-write-failed",
                    &[("path", "workspace"), ("err", &cleanup_error.to_string())],
                ));
            }
            return Err(errors);
        }
    };
    if !persisted {
        let mut errors = vec![QuickstartError::config_source_changed(&ctx)];
        if let Some(workspace) = strict_workspace
            && let Err(cleanup_error) = workspace.rollback()
        {
            errors.push(QuickstartError::for_surface(
                Some(&ctx),
                QuickstartStep::Agent,
                "personality_files",
                format!("failed to roll back stale workspace: {cleanup_error}"),
                "cli-quickstart-error-personality-write-failed",
                &[("path", "workspace"), ("err", &cleanup_error.to_string())],
            ));
        }
        return Err(errors);
    }

    if personality_order == PersonalityCommitOrder::AfterConfig {
        // Legacy Quickstart ordering: config first, optional personality files
        // second. Zerona uses the strict branch above instead.
        let mut commit_errors = Vec::new();
        commit_personality_files(staged_files, &mut commit_errors, Some(&ctx));
        if !commit_errors.is_empty() {
            return Err(commit_errors);
        }
    }

    ::zeroclaw_log::record!(
        INFO,
        ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Complete)
            .with_outcome(::zeroclaw_log::EventOutcome::Success)
            .with_attrs(merge_attrs(
                ctx.base_attrs(),
                serde_json::json!({
                    "agent": applied.alias,
                    "channels": applied.channels.len(),
                    "elapsed_ms": started.elapsed().as_millis() as u64,
                }),
            )),
        "quickstart: apply complete"
    );
    Ok(applied)
}

pub fn record_dismissed(run_id: &str, surface: Surface, last_step: Option<QuickstartStep>) {
    let last_step_str = last_step
        .map(|s| match s {
            QuickstartStep::ModelProvider => "model_provider",
            QuickstartStep::RiskProfile => "risk_profile",
            QuickstartStep::RuntimeProfile => "runtime_profile",
            QuickstartStep::Memory => "memory",
            QuickstartStep::Channels => "channels",
            QuickstartStep::PeerGroups => "peer_groups",
            QuickstartStep::Agent => "agent",
        })
        .unwrap_or("none");
    ::zeroclaw_log::record!(
        INFO,
        ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Note)
            .with_outcome(::zeroclaw_log::EventOutcome::Unknown)
            .with_attrs(::serde_json::json!({
                "quickstart.run_id": run_id,
                "quickstart.surface": surface.as_str(),
                "last_step": last_step_str,
                "dismissed": true,
            })),
        "quickstart: dismissed"
    );
}

/// `onboard_state.quickstart_completed` is false **and** no
/// `agents.*` entries exist. Returning users with existing agents
/// never see the auto-trigger even if the flag was never flipped.
pub fn should_auto_launch(config: &Config) -> bool {
    !config.onboard_state.quickstart_completed && config.agents.is_empty()
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub struct QuickstartState {
    pub quickstart_completed: bool,
    pub agents: Vec<String>,
    pub risk_profiles: Vec<String>,
    pub runtime_profiles: Vec<String>,
    /// Canonical runtime fallback used when a provider has no recommendation.
    pub default_runtime_profile: String,
    /// `<provider_type>.<alias>` refs for every configured model provider.
    pub model_providers: Vec<String>,
    /// `<channel_type>.<alias>` refs.
    pub channels: Vec<String>,
    #[serde(default)]
    pub unassigned_channels: Vec<String>,
    /// `<storage_type>.<alias>` refs.
    pub storage: Vec<String>,
    pub model_provider_types: Vec<QuickstartTypeOption>,
    pub channel_types: Vec<QuickstartTypeOption>,
    /// Risk presets from `zeroclaw_config::presets::RISK_PRESETS`.
    pub risk_presets: &'static [zeroclaw_config::presets::RiskPreset],
    /// Runtime presets from `zeroclaw_config::presets::RUNTIME_PRESETS`.
    pub runtime_presets: &'static [zeroclaw_config::presets::RuntimePreset],
    /// Memory backend snake-case kinds from `MemoryBackendKind`.
    pub memory_kinds: Vec<String>,
    /// Canonical personality filenames the Quickstart will accept.
    /// Surfaces iterate this; never hardcode the filename list.
    pub personality_files: &'static [&'static str],
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct QuickstartTypeOption {
    /// Canonical identifier (e.g. `"anthropic"`, `"telegram"`).
    pub kind: String,
    /// Human-readable picker label (e.g. `"Anthropic"`, `"Telegram"`).
    pub display_name: String,
    /// `true` when the entry runs locally and needs no remote
    /// credential. Channels always report `false`; providers reflect
    /// their `local` flag from `ModelProviderInfo`.
    pub local: bool,
    /// Runtime preset the daemon recommends when this provider is selected.
    /// Resolved from provider registry metadata and the canonical preset table
    /// for each state snapshot; never persisted as config.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_runtime_profile: Option<String>,
}

/// Resolve a Quickstart provider-type input to the canonical config family.
///
/// The provider registry remains the source of truth for real config families.
/// Auth-provider aliases (`openai-codex`, `claude`, `google`, `grok`, ...)
/// are accepted as Quickstart conveniences and normalize to existing config
/// families. Only `openai-codex` preselects a different Quickstart auth mode.
#[must_use]
pub fn resolve_model_provider_type(type_key: &str) -> Option<(&'static str, bool)> {
    let trimmed = type_key.trim();
    if let Some(info) = zeroclaw_providers::list_model_providers()
        .into_iter()
        .find(|info| info.name.eq_ignore_ascii_case(trimmed))
    {
        return Some((info.name, false));
    }

    let provider = trimmed
        .parse::<zeroclaw_providers::auth::AuthProvider>()
        .ok()?;
    Some(match provider {
        zeroclaw_providers::auth::AuthProvider::OpenaiCodex => ("openai", true),
        zeroclaw_providers::auth::AuthProvider::Anthropic => ("anthropic", false),
        zeroclaw_providers::auth::AuthProvider::Gemini => ("gemini", false),
        zeroclaw_providers::auth::AuthProvider::Xai => ("xai", false),
    })
}

/// Build a [`QuickstartState`] snapshot from the live config.
///
/// The two `*_types` lists are populated from the canonical sources
/// (`zeroclaw_providers::list_model_providers()` for providers,
/// `cfg.channels.channels()` for channel kinds). Adding a new entry in
/// either source automatically lights up here — no Quickstart code
/// change required. This is the DRY contract the plan calls out under
/// "Reads the per-provider field map at render time so adding a
/// provider in the schema doesn't require Quickstart code changes."
pub fn snapshot_state(cfg: &Config) -> QuickstartState {
    let model_provider_types = zeroclaw_providers::list_model_providers()
        .into_iter()
        .map(|info| QuickstartTypeOption {
            kind: info.name.to_string(),
            display_name: info.display_name.to_string(),
            local: info.local,
            default_runtime_profile: zeroclaw_providers::recommended_runtime_profile(info.name)
                .and_then(runtime_preset)
                .map(|preset| preset.preset_name.to_string()),
        })
        .collect();
    let channel_types = build_channel_type_options(&cfg.channels);
    QuickstartState {
        quickstart_completed: cfg.onboard_state.quickstart_completed,
        agents: cfg.agents.keys().cloned().collect(),
        risk_profiles: cfg.risk_profiles.keys().cloned().collect(),
        runtime_profiles: cfg.runtime_profiles.keys().cloned().collect(),
        default_runtime_profile: recommended_runtime_preset(None)
            .map(|preset| preset.preset_name.to_string())
            .unwrap_or_default(),
        model_providers: cfg.resolve_alias_source(AliasSource::ModelProviders),
        channels: collect_aliased_refs(&cfg.channels),
        unassigned_channels: collect_aliased_refs(&cfg.channels)
            .into_iter()
            .filter(|ch| cfg.agent_for_channel(ch).is_none())
            .collect(),
        storage: collect_aliased_refs(&cfg.storage),
        model_provider_types,
        channel_types,
        risk_presets: zeroclaw_config::presets::RISK_PRESETS,
        runtime_presets: zeroclaw_config::presets::RUNTIME_PRESETS,
        memory_kinds: memory_kind_keys(),
        personality_files: crate::agent::personality::EDITABLE_PERSONALITY_FILES,
    }
}

/// Snake-case wire keys for every `MemoryBackendKind` variant. Exhaustive
/// match probe catches missing variants at compile time; serde produces
/// the wire key so there's no parallel mapping.
fn memory_kind_keys() -> Vec<String> {
    use zeroclaw_config::multi_agent::MemoryBackendKind as M;
    [
        M::Sqlite,
        M::Markdown,
        M::Postgres,
        M::Qdrant,
        M::Lucid,
        M::None,
    ]
    .into_iter()
    .map(|k| {
        // Exhaustiveness guard: adding a new variant forces this match to fail
        // to compile until the contributor decides whether the new backend
        // belongs in the quickstart picker.
        match k {
            M::Sqlite | M::Markdown | M::Postgres | M::Qdrant | M::Lucid | M::None => (),
        }
        serde_json::to_value(k)
            .ok()
            .and_then(|v| v.as_str().map(str::to_string))
            .unwrap_or_default()
    })
    .collect()
}

fn build_channel_type_options(
    channels_cfg: &zeroclaw_config::schema::ChannelsConfig,
) -> Vec<QuickstartTypeOption> {
    channels_cfg
        .channels()
        .into_iter()
        .map(|info| QuickstartTypeOption {
            kind: info.kind.to_string(),
            display_name: info.name.to_string(),
            local: false,
            default_runtime_profile: None,
        })
        .collect()
}

fn resolve_channel_quickstart_type(channel_type: &str) -> (&str, bool) {
    match channel_type {
        "whatsapp-web" | "whatsapp_web" => ("whatsapp", true),
        other => (other, false),
    }
}

fn canonical_quickstart_channel_ref(reference: &str) -> Option<String> {
    let (channel_type, alias) = split_ref(reference.trim())?;
    let (config_channel_type, _) = resolve_channel_quickstart_type(channel_type);
    Some(format!("{config_channel_type}.{alias}"))
}

fn default_whatsapp_web_session_path(config: &Config, alias: &str) -> String {
    config
        .config_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."))
        .join("state")
        .join("whatsapp-web")
        .join(format!("{alias}.db"))
        .to_string_lossy()
        .into_owned()
}

/// Walk the serialised form of `value` and yield `<type>.<alias>` refs
/// for every `HashMap<String, _>`-shaped subsection. Schema-driven —
/// adding a new channel or storage slot in the schema lights up here
/// for free, no code change required.
fn collect_aliased_refs<T: serde::Serialize>(value: &T) -> Vec<String> {
    let mut out = Vec::new();
    let Ok(serde_json::Value::Object(map)) = serde_json::to_value(value) else {
        return out;
    };
    for (family, subvalue) in map {
        if let serde_json::Value::Object(entries) = subvalue {
            for alias in entries.keys() {
                out.push(format!("{family}.{alias}"));
            }
        }
    }
    out.sort();
    out
}

/// Selector kinds that the Quickstart "field shape" descriptor
/// covers. The TUI / web ask the runtime for the shape, then render
/// inputs dumbly off the response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldSection {
    ModelProvider,
    Channel,
    PeerGroup,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct FieldDescriptor {
    /// Schema-side field key (kebab-case terminal segment). The
    /// caller submits this back through [`BuilderSubmission`].
    pub key: String,
    /// Human label shown next to the input.
    pub label: String,
    /// One-line help blurb. Empty when the schema field has no doc.
    pub help: String,
    /// Wire-tag for the input control to render. Mirrors
    /// `PropKind::wire_name`.
    pub kind: zeroclaw_config::traits::PropKind,
    /// `true` for `#[secret]` fields — the modal masks input.
    pub is_secret: bool,
    /// Closed-set choices for `Enum` kind. `None` for everything else.
    pub enum_variants: Option<Vec<String>>,
    /// `true` when Quickstart treats this field as required. Currently
    /// every field returned by [`field_shape`] is required, but the
    /// flag is exposed so future additions can include optional rows.
    pub required: bool,
    /// Pre-filled default the modal should show as ghost text /
    /// initial input value. `None` when the schema has no meaningful
    /// default for this field (e.g. API keys, bot tokens).
    pub default: Option<String>,
}

/// Return the renderable field shape for a single section + type
/// combination. Walks `prop_fields()` against a synthetic config with
/// one default-instantiated entry under the requested type, then
/// filters to the per-section "essential" allowlist.
pub fn field_shape(section: FieldSection, type_key: &str) -> Vec<FieldDescriptor> {
    const SYNTHETIC_ALIAS: &str = "qs0probe";
    let (section_path, essentials, codex_auth_preselected) = match section {
        FieldSection::ModelProvider => {
            let Some((provider_type, codex_auth_preselected)) =
                resolve_model_provider_type(type_key)
            else {
                return Vec::new();
            };
            (
                format!("providers.models.{provider_type}"),
                MODEL_PROVIDER_ESSENTIALS,
                codex_auth_preselected,
            )
        }
        FieldSection::Channel => {
            let essentials = if type_key == "webhook" {
                WEBHOOK_CHANNEL_ESSENTIALS
            } else {
                CHANNEL_ESSENTIALS
            };
            (format!("channels.{type_key}"), essentials, false)
        }
        FieldSection::PeerGroup => ("peer_groups".to_string(), PEER_GROUP_ESSENTIALS, false),
    };

    // A throwaway Config we can mutate freely. Inject one default
    // entry under the requested type so `prop_fields()` enumerates
    // its leaves.
    let mut probe = Config::default();
    if probe
        .create_map_key(&section_path, SYNTHETIC_ALIAS)
        .is_err()
    {
        return Vec::new();
    }
    let leaf_prefix = format!("{section_path}.{SYNTHETIC_ALIAS}.");

    let mut out = Vec::new();
    for info in probe.prop_fields() {
        let Some(field_path) = info.name.strip_prefix(&leaf_prefix) else {
            continue;
        };
        if !essentials.contains(&field_path) {
            continue;
        }
        let default = if section_path == "channels.webhook" && field_path == "port" {
            Some(zeroclaw_config::schema::DEFAULT_WEBHOOK_CHANNEL_PORT.to_string())
        } else if info.is_secret {
            None
        } else {
            let raw = info.display_value.trim();
            if raw.is_empty() || raw == zeroclaw_config::traits::UNSET_DISPLAY {
                None
            } else {
                Some(raw.to_string())
            }
        };
        let help = if section_path == "providers.models.anthropic" && field_path == "api_key" {
            crate::i18n::get_required_cli_string("cli-quickstart-anthropic-api-key-help")
        } else {
            info.description.trim().to_string()
        };
        out.push(FieldDescriptor {
            key: field_path.to_string(),
            label: kebab_to_snake(field_path),
            help,
            kind: info.kind,
            is_secret: info.is_secret,
            enum_variants: info.enum_variants.map(|f| f()),
            // `uri` is an override-only field — operators set it only
            // when pointing at a self-hosted gateway. `api_key` is left
            // non-required because local providers (Ollama) and Codex
            // subscription auth don't need one — the runtime surfaces a clear
            // error at request time if a remote provider is missing its key.
            // Everything else in the essentials list is required to actually
            // issue a request.
            required: !matches!(field_path, "uri" | "api_key"),
            default,
        });
    }
    if matches!(section, FieldSection::ModelProvider)
        && let Some(provider_type) = section_path.strip_prefix("providers.models.")
        && let Some(descriptor) = auth_mode_descriptor(provider_type, codex_auth_preselected)
    {
        out.push(descriptor);
    }
    out.sort_by_key(|d| {
        essentials
            .iter()
            .position(|k| *k == d.key.as_str())
            .unwrap_or(usize::MAX)
    });
    out
}

/// Essentials per section kind. Kept in one place so adding a
/// provider type or channel kind lights up Quickstart for free,
/// while keeping the modal focused on what an agent cannot start
/// without.
const MODEL_PROVIDER_ESSENTIALS: &[&str] = &["model", QUICKSTART_AUTH_MODE_FIELD, "api_key", "uri"];
const CHANNEL_ESSENTIALS: &[&str] = &["bot_token", "token", "webhook_url", "allowed_users"];
const WEBHOOK_CHANNEL_ESSENTIALS: &[&str] = &[
    "bot_token",
    "token",
    "webhook_url",
    "allowed_users",
    "port",
    "secret",
];
const PEER_GROUP_ESSENTIALS: &[&str] = &["channel", "external_peers", "agents", "ignore"];

const QUICKSTART_AUTH_MODE_FIELD: &str = "auth_mode";
const QUICKSTART_AUTH_MODE_API_KEY: &str = "api_key";
const QUICKSTART_AUTH_MODE_CODEX: &str = "codex";
const QUICKSTART_AUTH_MODE_SETUP_TOKEN: &str = "setup_token";
const QUICKSTART_OPENAI_AUTH_MODES: &[&str] =
    &[QUICKSTART_AUTH_MODE_API_KEY, QUICKSTART_AUTH_MODE_CODEX];
const QUICKSTART_ANTHROPIC_AUTH_MODES: &[&str] = &[
    QUICKSTART_AUTH_MODE_API_KEY,
    QUICKSTART_AUTH_MODE_SETUP_TOKEN,
];

fn auth_modes_for(provider_type: &str) -> Option<&'static [&'static str]> {
    match provider_type {
        "openai" => Some(QUICKSTART_OPENAI_AUTH_MODES),
        "anthropic" => Some(QUICKSTART_ANTHROPIC_AUTH_MODES),
        _ => None,
    }
}

fn auth_mode_descriptor(
    provider_type: &str,
    codex_auth_preselected: bool,
) -> Option<FieldDescriptor> {
    let modes = auth_modes_for(provider_type)?;
    let (label_key, help_key) = match provider_type {
        "openai" => (
            "cli-quickstart-openai-auth-mode-label",
            "cli-quickstart-openai-auth-mode-help",
        ),
        "anthropic" => (
            "cli-quickstart-anthropic-auth-mode-label",
            "cli-quickstart-anthropic-auth-mode-help",
        ),
        _ => return None,
    };
    let default = if provider_type == "openai" && codex_auth_preselected {
        QUICKSTART_AUTH_MODE_CODEX
    } else {
        QUICKSTART_AUTH_MODE_API_KEY
    };
    Some(FieldDescriptor {
        key: QUICKSTART_AUTH_MODE_FIELD.to_string(),
        label: crate::i18n::get_required_cli_string(label_key),
        help: crate::i18n::get_required_cli_string(help_key),
        kind: zeroclaw_config::traits::PropKind::Enum,
        is_secret: false,
        enum_variants: Some(modes.iter().map(|mode| (*mode).to_string()).collect()),
        required: true,
        default: Some(default.to_string()),
    })
}

fn apply_into(
    config: &mut Config,
    submission: &BuilderSubmission,
    staged_files: &mut Vec<StagedPersonalityWrite>,
    errors: &mut Vec<QuickstartError>,
    ctx: Option<&RunCtx>,
) -> Option<AppliedAgent> {
    apply_into_with_memory_mode(
        config,
        submission,
        staged_files,
        errors,
        ctx,
        MemoryApplyMode::InstallWide,
    )
}

fn apply_into_with_memory_mode(
    config: &mut Config,
    submission: &BuilderSubmission,
    staged_files: &mut Vec<StagedPersonalityWrite>,
    errors: &mut Vec<QuickstartError>,
    ctx: Option<&RunCtx>,
    memory_mode: MemoryApplyMode,
) -> Option<AppliedAgent> {
    if !validate_runtime_profile_choice(config, &submission.runtime_profile, errors, ctx) {
        return None;
    }
    let provider_ref = apply_model_provider(config, &submission.model_provider, errors, ctx)?;
    emit_selector_pick(
        ctx,
        "model_provider",
        selector_mode(&submission.model_provider),
        &provider_ref,
    );

    let risk_alias = apply_named_preset(
        config,
        &submission.risk_profile,
        QuickstartStep::RiskProfile,
        risk_preset_keys,
        write_risk_preset,
        errors,
        ctx,
    )?;
    emit_selector_pick(
        ctx,
        "risk_profile",
        selector_mode(&submission.risk_profile),
        &risk_alias,
    );

    let runtime_alias = apply_named_preset(
        config,
        &submission.runtime_profile,
        QuickstartStep::RuntimeProfile,
        runtime_preset_keys,
        write_runtime_preset,
        errors,
        ctx,
    )?;
    emit_selector_pick(
        ctx,
        "runtime_profile",
        selector_mode(&submission.runtime_profile),
        &runtime_alias,
    );

    let (memory_backend, agent_memory_backend) = match memory_mode {
        MemoryApplyMode::InstallWide => {
            (apply_memory(config, &submission.memory, errors, ctx)?, None)
        }
        MemoryApplyMode::CreatedAgent => {
            let backend = select_per_agent_memory(&submission.memory, errors)?;
            (memory_choice_name(&backend), Some(backend))
        }
    };
    emit_selector_pick(
        ctx,
        "memory",
        selector_mode(&submission.memory),
        &memory_backend,
    );

    let channel_refs = apply_channels(config, &submission.channels, errors, ctx);
    if let Some(ctx) = ctx {
        ::zeroclaw_log::record!(
            DEBUG,
            ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Note).with_attrs(
                merge_attrs(
                    ctx.base_attrs(),
                    serde_json::json!({
                        "selector": "channels",
                        "count": channel_refs.len(),
                    }),
                )
            ),
            "quickstart: selector channels"
        );
    }

    if !errors.is_empty() {
        return None;
    }
    let alias = apply_agent(
        config,
        &submission.agent,
        &provider_ref,
        &risk_alias,
        &runtime_alias,
        agent_memory_backend,
        &channel_refs,
        errors,
        ctx,
    )?;
    emit_selector_pick(ctx, "agent", "create_new", &alias);

    let peer_group_refs =
        apply_peer_groups(config, &submission.peer_groups, &channel_refs, errors, ctx);
    if let Some(ctx) = ctx {
        ::zeroclaw_log::record!(
            DEBUG,
            ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Note).with_attrs(
                merge_attrs(
                    ctx.base_attrs(),
                    serde_json::json!({
                        "selector": "peer_groups",
                        "count": peer_group_refs.len(),
                    }),
                )
            ),
            "quickstart: selector peer_groups"
        );
    }

    apply_personality_files(
        config,
        &alias,
        &submission.agent.personality_files,
        staged_files,
        errors,
        ctx,
    );

    materialize_default_skills_bundle(config);

    if !errors.is_empty() {
        return None;
    }

    Some(AppliedAgent {
        alias,
        model_provider: provider_ref,
        risk_profile: risk_alias,
        runtime_profile: runtime_alias,
        channels: channel_refs,
        memory_backend,
    })
}

fn validate_runtime_profile_choice(
    config: &Config,
    choice: &SelectorChoice<String>,
    errors: &mut Vec<QuickstartError>,
    ctx: Option<&RunCtx>,
) -> bool {
    let message = match choice {
        SelectorChoice::Existing(alias) if !config.runtime_profiles.contains_key(alias) => {
            Some(QuickstartError::for_surface(
                ctx,
                QuickstartStep::RuntimeProfile,
                "",
                format!("no `{alias}` profile configured"),
                "cli-quickstart-error-no-profile",
                &[("alias", alias)],
            ))
        }
        SelectorChoice::Fresh(preset_name) if runtime_preset(preset_name).is_none() => {
            Some(QuickstartError::new(
                QuickstartStep::RuntimeProfile,
                "",
                format!("unknown runtime preset `{preset_name}`"),
            ))
        }
        _ => None,
    };
    if let Some(error) = message {
        errors.push(error);
        false
    } else {
        true
    }
}

/// Surface representation of a selector's submission mode for
/// observability. We never inspect the wrapped value here — only
/// whether the user picked an existing alias or created fresh.
fn selector_mode<T>(choice: &SelectorChoice<T>) -> &'static str {
    match choice {
        SelectorChoice::Existing(_) => "use_existing",
        SelectorChoice::Fresh(_) => "create_new",
    }
}

fn emit_selector_pick(ctx: Option<&RunCtx>, selector: &str, mode: &str, value: &str) {
    let Some(ctx) = ctx else { return };
    ::zeroclaw_log::record!(
        DEBUG,
        ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Note).with_attrs(
            merge_attrs(
                ctx.base_attrs(),
                serde_json::json!({
                    "selector": selector,
                    "mode": mode,
                    "value": value,
                }),
            )
        ),
        "quickstart: selector pick"
    );
}

// ── Model provider ─────────────────────────────────────────────────

fn apply_model_provider(
    config: &mut Config,
    choice: &SelectorChoice<ModelProviderChoice>,
    errors: &mut Vec<QuickstartError>,
    ctx: Option<&RunCtx>,
) -> Option<String> {
    match choice {
        SelectorChoice::Existing(reference) => {
            let (family, alias) = match split_ref(reference) {
                Some(parts) => parts,
                None => {
                    errors.push(QuickstartError::for_surface(
                        ctx,
                        QuickstartStep::ModelProvider,
                        "",
                        format!("`{reference}` is not a `<type>.<alias>` reference"),
                        "cli-quickstart-error-not-type-alias-ref",
                        &[("reference", reference)],
                    ));
                    return None;
                }
            };
            if !section_has_alias(config, "providers.models", family, alias) {
                let path = format!("providers.models.{family}.{alias}");
                errors.push(QuickstartError::for_surface(
                    ctx,
                    QuickstartStep::ModelProvider,
                    "",
                    format!("no `{path}` configured"),
                    "cli-quickstart-error-no-configured-path",
                    &[("path", &path)],
                ));
                return None;
            }
            Some(reference.clone())
        }
        SelectorChoice::Fresh(choice) => {
            if choice.provider_type.trim().is_empty()
                || choice.alias.trim().is_empty()
                || choice.model.trim().is_empty()
            {
                errors.push(QuickstartError::for_surface(
                    ctx,
                    QuickstartStep::ModelProvider,
                    "",
                    "provider type, alias, and model are required",
                    "cli-quickstart-error-provider-required",
                    &[],
                ));
                return None;
            }
            // Canonicalize the provider type against the registry. The picker
            // offers canonical `info.name` keys, but a hand-typed or
            // whitespace-padded value (e.g. "llamacpp ", "llama.cpp") would
            // otherwise reach `create_map_key` verbatim and fail with a cryptic
            // "no map-keyed/list section" because the family key doesn't match.
            // `openai-codex` is accepted as a convenience input alias and
            // normalizes to the existing `openai` config family.
            let Some((provider_type, codex_alias_requested)) =
                resolve_model_provider_type(&choice.provider_type)
            else {
                errors.push(QuickstartError::for_surface(
                    ctx,
                    QuickstartStep::ModelProvider,
                    "provider_type",
                    format!(
                        "unknown model provider type `{}` — pick one from the provider list",
                        choice.provider_type.trim()
                    ),
                    "cli-quickstart-error-unknown-provider-type",
                    &[("provider", choice.provider_type.trim())],
                ));
                return None;
            };
            let default_auth_mode = if codex_alias_requested {
                QUICKSTART_AUTH_MODE_CODEX
            } else {
                QUICKSTART_AUTH_MODE_API_KEY
            };
            let auth_mode = choice
                .fields
                .get(QUICKSTART_AUTH_MODE_FIELD)
                .map(|value| value.trim().to_ascii_lowercase())
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| default_auth_mode.to_string());
            if let Some(allowed_modes) = auth_modes_for(provider_type)
                && !allowed_modes.contains(&auth_mode.as_str())
            {
                let (provider_name, error_key) = if provider_type == "openai" {
                    ("OpenAI", "cli-quickstart-error-unknown-openai-auth-mode")
                } else {
                    (
                        "Anthropic",
                        "cli-quickstart-error-unknown-anthropic-auth-mode",
                    )
                };
                let expected = allowed_modes
                    .iter()
                    .map(|mode| format!("`{mode}`"))
                    .collect::<Vec<_>>()
                    .join(" or ");
                errors.push(QuickstartError::for_surface(
                    ctx,
                    QuickstartStep::ModelProvider,
                    QUICKSTART_AUTH_MODE_FIELD,
                    format!("unknown {provider_name} auth mode `{auth_mode}` — pick {expected}"),
                    error_key,
                    &[("mode", &auth_mode)],
                ));
                return None;
            }
            if section_has_alias(config, "providers.models", provider_type, &choice.alias) {
                let alias_ref = format!("{}.{}", provider_type, choice.alias);
                errors.push(QuickstartError::for_surface(
                    ctx,
                    QuickstartStep::ModelProvider,
                    "alias",
                    format!("alias `{alias_ref}` already exists"),
                    "cli-quickstart-error-alias-exists",
                    &[("alias", &alias_ref)],
                ));
                return None;
            }
            let codex_auth = provider_type == "openai" && auth_mode == QUICKSTART_AUTH_MODE_CODEX;
            let prefix = format!("providers.models.{}.{}", provider_type, choice.alias);
            if let Err(err) = config.create_map_key(
                &format!("providers.models.{}", provider_type),
                &choice.alias,
            ) {
                errors.push(QuickstartError::new(
                    QuickstartStep::ModelProvider,
                    "provider_type",
                    err.to_string(),
                ));
                return None;
            }
            if let Err(err) = config.set_prop_persistent(&format!("{prefix}.model"), &choice.model)
            {
                errors.push(QuickstartError::new(
                    QuickstartStep::ModelProvider,
                    "model",
                    err.to_string(),
                ));
                return None;
            }
            if codex_auth {
                if let Err(err) = config
                    .set_prop_persistent(&format!("{prefix}.wire_api"), WireApi::Responses.as_str())
                {
                    errors.push(QuickstartError::new(
                        QuickstartStep::ModelProvider,
                        "wire_api",
                        err.to_string(),
                    ));
                    return None;
                }
                if let Err(err) =
                    config.set_prop_persistent(&format!("{prefix}.requires_openai_auth"), "true")
                {
                    errors.push(QuickstartError::new(
                        QuickstartStep::ModelProvider,
                        "requires_openai_auth",
                        err.to_string(),
                    ));
                    return None;
                }
            }
            // Round-trip every field the surface echoed back. Keys are
            // whatever `field_shape()` emitted — the daemon authored
            // them, so it knows where they go.
            let mut entries: Vec<(&String, &String)> = choice.fields.iter().collect();
            entries.sort_by(|a, b| a.0.cmp(b.0));
            for (key, value) in entries {
                if key == QUICKSTART_AUTH_MODE_FIELD {
                    continue;
                }
                if codex_auth
                    && matches!(
                        key.as_str(),
                        "api_key" | "wire_api" | "requires_openai_auth"
                    )
                {
                    continue;
                }
                if value.is_empty() {
                    continue;
                }
                if let Err(err) = config.set_prop_persistent(&format!("{prefix}.{key}"), value) {
                    errors.push(QuickstartError::new(
                        QuickstartStep::ModelProvider,
                        zeroclaw_config::helpers::kebab_to_snake(key),
                        err.to_string(),
                    ));
                    return None;
                }
            }
            // Auto-populate context_window from provider's /models endpoint if supported.
            // Silently ignores failures (falls back to config default).
            // Only runs on multi-threaded Tokio runtime (actual CLI), not single-threaded test runtime.
            let provider_config = zeroclaw_config::schema::ModelProviderConfig {
                model: Some(choice.model.clone()),
                uri: config.get_prop(&format!("{prefix}.uri")).ok(),
                api_key: choice
                    .fields
                    .get("api_key")
                    .and_then(|v| if v.is_empty() { None } else { Some(v.clone()) }),
                ..Default::default()
            };
            if tokio::runtime::Handle::try_current()
                .map(|h| {
                    matches!(
                        h.runtime_flavor(),
                        tokio::runtime::RuntimeFlavor::MultiThread
                    )
                })
                .unwrap_or(false)
                && let Some(ctx) = tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current().block_on(
                        zeroclaw_providers::fetch_context_window(provider_type, &provider_config),
                    )
                })
            {
                let _ = config
                    .set_prop_persistent(&format!("{prefix}.context_window"), &ctx.to_string());
            }
            Some(format!("{}.{}", provider_type, choice.alias))
        }
    }
}

// ── Risk / Runtime presets ─────────────────────────────────────────

fn apply_named_preset<K, W>(
    config: &mut Config,
    choice: &SelectorChoice<String>,
    step: QuickstartStep,
    list_existing: K,
    write_preset: W,
    errors: &mut Vec<QuickstartError>,
    ctx: Option<&RunCtx>,
) -> Option<String>
where
    K: Fn(&Config) -> Vec<String>,
    W: Fn(&mut Config, &str) -> Result<String, String>,
{
    match choice {
        SelectorChoice::Existing(alias) => {
            if list_existing(config).iter().any(|a| a == alias) {
                Some(alias.clone())
            } else {
                errors.push(QuickstartError::for_surface(
                    ctx,
                    step,
                    "",
                    format!("no `{alias}` profile configured"),
                    "cli-quickstart-error-no-profile",
                    &[("alias", alias)],
                ));
                None
            }
        }
        SelectorChoice::Fresh(preset_name) => match write_preset(config, preset_name) {
            Ok(alias) => Some(alias),
            Err(msg) => {
                errors.push(QuickstartError::new(step, "", msg));
                None
            }
        },
    }
}

fn risk_preset_keys(config: &Config) -> Vec<String> {
    config.risk_profiles.keys().cloned().collect()
}

fn runtime_preset_keys(config: &Config) -> Vec<String> {
    config.runtime_profiles.keys().cloned().collect()
}

fn write_risk_preset(config: &mut Config, preset_name: &str) -> Result<String, String> {
    let preset =
        risk_preset(preset_name).ok_or_else(|| format!("unknown risk preset `{preset_name}`"))?;
    // Existing block wins — never clobber a user-customised `[risk-profiles.<name>]`
    // that happens to share a preset name.
    if config.risk_profiles.contains_key(preset.preset_name) {
        return Ok(preset.preset_name.to_string());
    }
    config
        .create_map_key("risk_profiles", preset.preset_name)
        .map_err(|e| e.to_string())?;
    config
        .risk_profiles
        .insert(preset.preset_name.to_string(), (preset.values)());
    config.mark_dirty(&format!("risk_profiles.{}", preset.preset_name));
    Ok(preset.preset_name.to_string())
}

fn write_runtime_preset(config: &mut Config, preset_name: &str) -> Result<String, String> {
    let preset = runtime_preset(preset_name)
        .ok_or_else(|| format!("unknown runtime preset `{preset_name}`"))?;
    // Existing block wins — same rule as `write_risk_preset`.
    if config.runtime_profiles.contains_key(preset.preset_name) {
        return Ok(preset.preset_name.to_string());
    }
    config
        .create_map_key("runtime_profiles", preset.preset_name)
        .map_err(|e| e.to_string())?;
    config
        .runtime_profiles
        .insert(preset.preset_name.to_string(), (preset.values)());
    config.mark_dirty(&format!("runtime_profiles.{}", preset.preset_name));
    Ok(preset.preset_name.to_string())
}

// ── Memory ─────────────────────────────────────────────────────────

fn memory_choice_name(kind: &MemoryChoice) -> String {
    serde_json::to_value(kind)
        .ok()
        .and_then(|value| value.as_str().map(str::to_string))
        .unwrap_or_else(|| format!("{kind:?}").to_lowercase())
}

fn select_per_agent_memory(
    choice: &SelectorChoice<MemoryChoice>,
    errors: &mut Vec<QuickstartError>,
) -> Option<MemoryChoice> {
    match choice {
        SelectorChoice::Fresh(
            kind @ (MemoryChoice::Sqlite | MemoryChoice::Markdown | MemoryChoice::None),
        ) => Some(*kind),
        SelectorChoice::Fresh(kind) => {
            errors.push(QuickstartError::new(
                QuickstartStep::Memory,
                "backend",
                format!(
                    "per-agent memory does not support `{}`; choose `sqlite`, `markdown`, or `none`",
                    memory_choice_name(kind)
                ),
            ));
            None
        }
        SelectorChoice::Existing(reference) => {
            errors.push(QuickstartError::new(
                QuickstartStep::Memory,
                "backend",
                format!(
                    "per-agent memory does not accept storage reference `{reference}`; choose a fresh `sqlite`, `markdown`, or `none` backend"
                ),
            ));
            None
        }
    }
}

fn apply_memory(
    config: &mut Config,
    choice: &SelectorChoice<MemoryChoice>,
    errors: &mut Vec<QuickstartError>,
    ctx: Option<&RunCtx>,
) -> Option<String> {
    match choice {
        SelectorChoice::Existing(reference) => {
            let (family, alias) = match split_ref(reference) {
                Some(parts) => parts,
                None => {
                    errors.push(QuickstartError::for_surface(
                        ctx,
                        QuickstartStep::Memory,
                        "",
                        format!("`{reference}` is not a `<type>.<alias>` reference"),
                        "cli-quickstart-error-not-type-alias-ref",
                        &[("reference", reference)],
                    ));
                    return None;
                }
            };
            if !storage_has_ref(config, reference) {
                let path = format!("storage.{family}.{alias}");
                errors.push(QuickstartError::for_surface(
                    ctx,
                    QuickstartStep::Memory,
                    "",
                    format!("no `{path}` configured"),
                    "cli-quickstart-error-no-configured-path",
                    &[("path", &path)],
                ));
                return None;
            }
            if let Err(err) = config.set_prop_persistent("memory.backend", reference) {
                errors.push(QuickstartError::new(
                    QuickstartStep::Memory,
                    "backend",
                    err.to_string(),
                ));
                return None;
            }
            Some(reference.clone())
        }
        SelectorChoice::Fresh(kind) => {
            let kind_name = memory_choice_name(kind);
            if matches!(kind, MemoryChoice::None) {
                if let Err(err) = config.set_prop_persistent("memory.backend", "none") {
                    errors.push(QuickstartError::new(
                        QuickstartStep::Memory,
                        "backend",
                        err.to_string(),
                    ));
                    return None;
                }
                return Some("none".to_string());
            }
            let backend_ref = format!("{kind_name}.{kind_name}");
            let parent_path = format!("storage.{kind_name}");
            if let Err(err) = config.create_map_key(&parent_path, &kind_name) {
                errors.push(QuickstartError::new(
                    QuickstartStep::Memory,
                    "",
                    err.to_string(),
                ));
                return None;
            }
            if let Err(err) = config.set_prop_persistent("memory.backend", &backend_ref) {
                errors.push(QuickstartError::new(
                    QuickstartStep::Memory,
                    "backend",
                    err.to_string(),
                ));
                return None;
            }
            Some(backend_ref)
        }
    }
}

// ── Channels ───────────────────────────────────────────────────────

fn usable_quickstart_value(value: &str) -> Option<&str> {
    let value = value.trim();
    (!zeroclaw_config::traits::is_unset_display_value(value)).then_some(value)
}

fn apply_channels(
    config: &mut Config,
    channels: &[SelectorChoice<ChannelQuickStart>],
    errors: &mut Vec<QuickstartError>,
    ctx: Option<&RunCtx>,
) -> Vec<String> {
    let mut refs = Vec::with_capacity(channels.len());
    for (idx, ch) in channels.iter().enumerate() {
        match ch {
            SelectorChoice::Existing(reference) => {
                if let Some((family, alias)) = split_ref(reference) {
                    if !channel_exists(config, family, alias) {
                        let path = format!("channels.{family}.{alias}");
                        errors.push(QuickstartError::for_surface(
                            ctx,
                            QuickstartStep::Channels,
                            format!("channels[{idx}]"),
                            format!("no `{path}` configured"),
                            "cli-quickstart-error-no-configured-path",
                            &[("path", &path)],
                        ));
                        continue;
                    }
                    // Existing channel already bound to a different agent
                    // cannot be re-used — one channel, one agent invariant.
                    if let Some(owner) = config.agent_for_channel(reference) {
                        errors.push(QuickstartError::for_surface(
                            ctx,
                            QuickstartStep::Channels,
                            format!("channels[{idx}]"),
                            format!("channel `{reference}` is already bound to agent `{owner}`"),
                            "cli-quickstart-error-channel-bound",
                            &[("reference", reference), ("owner", owner)],
                        ));
                        continue;
                    }
                    refs.push(reference.clone());
                } else {
                    errors.push(QuickstartError::for_surface(
                        ctx,
                        QuickstartStep::Channels,
                        format!("channels[{idx}]"),
                        format!("`{reference}` is not a `<type>.<alias>` reference"),
                        "cli-quickstart-error-not-type-alias-ref",
                        &[("reference", reference)],
                    ));
                }
            }
            SelectorChoice::Fresh(entry) => {
                let submitted_channel_type = entry.channel_type.trim();
                let alias = entry.alias.trim();
                if submitted_channel_type.is_empty() || alias.is_empty() {
                    errors.push(QuickstartError::for_surface(
                        ctx,
                        QuickstartStep::Channels,
                        format!("channels[{idx}]"),
                        "channel type and alias are required",
                        "cli-quickstart-error-channel-required",
                        &[],
                    ));
                    continue;
                }
                let (config_channel_type, is_whatsapp_web) =
                    resolve_channel_quickstart_type(submitted_channel_type);
                if channel_exists(config, config_channel_type, alias) {
                    let alias_ref = format!("{config_channel_type}.{alias}");
                    errors.push(QuickstartError::for_surface(
                        ctx,
                        QuickstartStep::Channels,
                        format!("channels[{idx}].alias"),
                        format!("alias `{alias_ref}` already exists"),
                        "cli-quickstart-error-alias-exists",
                        &[("alias", &alias_ref)],
                    ));
                    continue;
                }
                let advertised: std::collections::HashSet<String> =
                    field_shape(FieldSection::Channel, &entry.channel_type)
                        .into_iter()
                        .map(|field| field.key)
                        .collect();
                if let Some(key) = entry
                    .fields
                    .keys()
                    .filter(|key| !advertised.contains(*key))
                    .min()
                {
                    errors.push(QuickstartError::for_surface(
                        ctx,
                        QuickstartStep::Channels,
                        format!("channels[{idx}].fields.{key}"),
                        format!("channel field `{key}` is not available in Quickstart"),
                        "cli-quickstart-error-channel-field-not-advertised",
                        &[("field", key.as_str())],
                    ));
                    continue;
                }
                if config_channel_type == "webhook"
                    && entry
                        .fields
                        .get("secret")
                        .and_then(|value| usable_quickstart_value(value))
                        .is_none()
                {
                    errors.push(QuickstartError::for_surface(
                        ctx,
                        QuickstartStep::Channels,
                        format!("channels[{idx}].fields.secret"),
                        "webhook secret is required",
                        "cli-quickstart-error-webhook-secret-required",
                        &[],
                    ));
                    continue;
                }
                let mut staged = config.clone();
                if let Err(err) =
                    staged.create_map_key(&format!("channels.{config_channel_type}"), alias)
                {
                    errors.push(QuickstartError::new(
                        QuickstartStep::Channels,
                        format!("channels[{idx}].channel_type"),
                        err.to_string(),
                    ));
                    continue;
                }
                let prefix = format!("channels.{config_channel_type}.{alias}");
                if config_channel_type == "webhook"
                    && entry
                        .fields
                        .get("port")
                        .and_then(|value| usable_quickstart_value(value))
                        .is_none()
                    && let Err(err) = staged.set_prop_persistent(
                        &format!("{prefix}.port"),
                        &zeroclaw_config::schema::DEFAULT_WEBHOOK_CHANNEL_PORT.to_string(),
                    )
                {
                    errors.push(QuickstartError::new(
                        QuickstartStep::Channels,
                        format!("channels[{idx}].fields.port"),
                        err.to_string(),
                    ));
                    continue;
                }
                let mut fields: Vec<_> = entry
                    .fields
                    .iter()
                    .filter_map(|(key, value)| {
                        usable_quickstart_value(value).map(|value| (key, value))
                    })
                    .collect();
                fields.sort_by_key(|(left, _)| *left);

                let mut failed = false;
                for (key, value) in fields {
                    if let Err(err) = staged.set_prop_persistent(&format!("{prefix}.{key}"), value)
                    {
                        errors.push(QuickstartError::new(
                            QuickstartStep::Channels,
                            format!("channels[{idx}].fields.{key}"),
                            err.to_string(),
                        ));
                        failed = true;
                        break;
                    }
                }
                if !failed && is_whatsapp_web {
                    let default_path = default_whatsapp_web_session_path(config, alias);
                    if let Err(err) =
                        staged.set_prop_persistent(&format!("{prefix}.session_path"), &default_path)
                    {
                        errors.push(QuickstartError::new(
                            QuickstartStep::Channels,
                            format!("channels[{idx}].channel_type"),
                            err.to_string(),
                        ));
                        failed = true;
                    }
                }
                if !failed
                    && let Err(err) =
                        staged.set_prop_persistent(&format!("{prefix}.enabled"), "true")
                {
                    errors.push(QuickstartError::new(
                        QuickstartStep::Channels,
                        format!("channels[{idx}].fields.enabled"),
                        err.to_string(),
                    ));
                    failed = true;
                }
                if !failed
                    && config_channel_type == "telegram"
                    && let Some(telegram) = staged.channels.telegram.get(alias)
                    && let Err(err) = telegram.validate_bot_token(alias)
                {
                    let structured =
                        zeroclaw_config::api_error::ConfigApiError::from_validation(err);
                    let terminal = structured
                        .path
                        .as_deref()
                        .and_then(|path| path.rsplit('.').next())
                        .unwrap_or("credential");
                    errors.push(QuickstartError::for_surface(
                        ctx,
                        QuickstartStep::Channels,
                        format!("channels[{idx}].fields.{terminal}"),
                        structured.message,
                        "cli-quickstart-error-channel-token-required",
                        &[],
                    ));
                    failed = true;
                }
                if !failed
                    && config_channel_type == "discord"
                    && let Some(discord) = staged.channels.discord.get(alias)
                    && let Err(err) = discord.validate_bot_token(alias)
                {
                    let structured =
                        zeroclaw_config::api_error::ConfigApiError::from_validation(err);
                    let terminal = structured
                        .path
                        .as_deref()
                        .and_then(|path| path.rsplit('.').next())
                        .unwrap_or("credential");
                    errors.push(QuickstartError::for_surface(
                        ctx,
                        QuickstartStep::Channels,
                        format!("channels[{idx}].fields.{terminal}"),
                        structured.message,
                        "cli-quickstart-error-channel-token-required",
                        &[],
                    ));
                    failed = true;
                }
                if failed {
                    continue;
                }
                *config = staged;
                refs.push(format!("{config_channel_type}.{alias}"));
            }
        }
    }
    refs
}

fn channel_exists(config: &Config, channel_type: &str, alias: &str) -> bool {
    let probe = format!("channels.{channel_type}.{alias}.enabled");
    config.get_prop(&probe).is_ok()
}

// ── Peer groups ────────────────────────────────────────────────────

fn apply_peer_groups(
    config: &mut Config,
    peer_groups: &[zeroclaw_config::presets::QuickstartPeerGroup],
    staged_channel_refs: &[String],
    errors: &mut Vec<QuickstartError>,
    ctx: Option<&RunCtx>,
) -> Vec<String> {
    let mut refs = Vec::with_capacity(peer_groups.len());
    for (idx, pg) in peer_groups.iter().enumerate() {
        if pg.name.trim().is_empty() {
            errors.push(QuickstartError::for_surface(
                ctx,
                QuickstartStep::Channels,
                format!("peer_groups[{idx}].name"),
                "peer-group name is required",
                "cli-quickstart-error-peer-group-name-required",
                &[],
            ));
            continue;
        }
        if pg.channel.trim().is_empty() {
            errors.push(QuickstartError::for_surface(
                ctx,
                QuickstartStep::Channels,
                format!("peer_groups[{idx}].channel"),
                "peer-group channel ref is required",
                "cli-quickstart-error-peer-group-channel-required",
                &[],
            ));
            continue;
        }
        let Some(channel_ref) = canonical_quickstart_channel_ref(&pg.channel) else {
            errors.push(QuickstartError::for_surface(
                ctx,
                QuickstartStep::Channels,
                format!("peer_groups[{idx}].channel"),
                format!("`{}` is not a `<type>.<alias>` reference", pg.channel),
                "cli-quickstart-error-not-type-alias-ref",
                &[("reference", &pg.channel)],
            ));
            continue;
        };
        // Channel ref must resolve to either a channel already in config
        // OR a channel staged in this same submission.
        let staged_match = staged_channel_refs.iter().any(|r| r == &channel_ref);
        let configured_match = match split_ref(&channel_ref) {
            Some((family, alias)) => channel_exists(config, family, alias),
            None => false,
        };
        if !staged_match && !configured_match {
            errors.push(QuickstartError::for_surface(
                ctx,
                QuickstartStep::Channels,
                format!("peer_groups[{idx}].channel"),
                format!(
                    "peer-group `{}` references unknown channel `{}`",
                    pg.name, pg.channel
                ),
                "cli-quickstart-error-peer-group-unknown-channel",
                &[("name", &pg.name), ("channel", &pg.channel)],
            ));
            continue;
        }
        // Collision: existing peer-group block wins. Surface the conflict
        // so the operator sees what they need to rename.
        if config.peer_groups.contains_key(&pg.name) {
            errors.push(QuickstartError::for_surface(
                ctx,
                QuickstartStep::Channels,
                format!("peer_groups[{idx}].name"),
                format!("peer-group `{}` already exists", pg.name),
                "cli-quickstart-error-peer-group-exists",
                &[("name", &pg.name)],
            ));
            continue;
        }
        if let Err(err) = config.create_map_key("peer_groups", &pg.name) {
            errors.push(QuickstartError::new(
                QuickstartStep::Channels,
                format!("peer_groups[{idx}]"),
                err.to_string(),
            ));
            continue;
        }
        let prefix = format!("peer_groups.{}", pg.name);
        if let Err(err) = config.set_prop_persistent(&format!("{prefix}.channel"), &channel_ref) {
            errors.push(QuickstartError::new(
                QuickstartStep::Channels,
                format!("peer_groups[{idx}].channel"),
                err.to_string(),
            ));
            continue;
        }
        if !pg.external_peers.is_empty() {
            let joined = pg
                .external_peers
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join("\n");
            if let Err(err) =
                config.set_prop_persistent(&format!("{prefix}.external_peers"), &joined)
            {
                errors.push(QuickstartError::new(
                    QuickstartStep::Channels,
                    format!("peer_groups[{idx}].external_peers"),
                    err.to_string(),
                ));
                continue;
            }
        }
        if !pg.ignore.is_empty() {
            let joined = pg
                .ignore
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join("\n");
            if let Err(err) = config.set_prop_persistent(&format!("{prefix}.ignore"), &joined) {
                errors.push(QuickstartError::new(
                    QuickstartStep::Channels,
                    format!("peer_groups[{idx}].ignore"),
                    err.to_string(),
                ));
                continue;
            }
        }
        refs.push(pg.name.clone());
    }
    refs
}

// ── Personality files ──────────────────────────────────────────────

/// A personality file staged under an already-open install-root handle during
/// `apply_into`, moved into a capability-bounded workspace handle only after
/// the atomic config write succeeds. On config failure the tempfile drops and
/// cleans itself up without creating the workspace.
struct StagedPersonalityWrite {
    root: cap_std::fs::Dir,
    temp_name: std::path::PathBuf,
    workspace_rel: std::path::PathBuf,
    dest_name: String,
    display_dest: std::path::PathBuf,
    committed: bool,
}

impl StagedPersonalityWrite {
    fn commit(&mut self) -> std::io::Result<()> {
        let workspace = create_bounded_dir_chain_nofollow(&self.root, &self.workspace_rel)?;
        self.root
            .rename(&self.temp_name, &workspace, &self.dest_name)?;
        sync_bounded_directory(&workspace)?;
        self.committed = true;
        Ok(())
    }
}

fn open_existing_dir_chain_nofollow(
    root: &cap_std::fs::Dir,
    relative: &std::path::Path,
) -> std::io::Result<Option<cap_std::fs::Dir>> {
    let mut current = root.try_clone()?;
    for component in relative.components() {
        let std::path::Component::Normal(name) = component else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "workspace path must contain only normal relative components",
            ));
        };
        let current_file = current.try_clone()?.into_std_file();
        match cap_primitives::fs::open_dir_nofollow(&current_file, std::path::Path::new(name)) {
            Ok(next) => current = cap_std::fs::Dir::from_std_file(next),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        }
    }
    Ok(Some(current))
}

fn create_bounded_dir_chain_nofollow(
    root: &cap_std::fs::Dir,
    relative: &std::path::Path,
) -> std::io::Result<cap_std::fs::Dir> {
    let mut current = root.try_clone()?;
    for component in relative.components() {
        let std::path::Component::Normal(name) = component else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "workspace path must contain only normal relative components",
            ));
        };
        let current_file = current.try_clone()?.into_std_file();
        current = match cap_primitives::fs::open_dir_nofollow(
            &current_file,
            std::path::Path::new(name),
        ) {
            Ok(next) => cap_std::fs::Dir::from_std_file(next),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                current.create_dir(std::path::Path::new(name))?;
                sync_bounded_directory(&current)?;
                let current_file = current.try_clone()?.into_std_file();
                cap_std::fs::Dir::from_std_file(cap_primitives::fs::open_dir_nofollow(
                    &current_file,
                    std::path::Path::new(name),
                )?)
            }
            Err(error) => return Err(error),
        };
    }
    Ok(current)
}

fn sync_bounded_directory(directory: &cap_std::fs::Dir) -> std::io::Result<()> {
    let result = directory.try_clone()?.into_std_file().sync_all();
    #[cfg(windows)]
    if result
        .as_ref()
        .is_err_and(|error| error.kind() == std::io::ErrorKind::PermissionDenied)
    {
        return Ok(());
    }
    result
}

fn ensure_new_agent_workspace_absent(
    config: &Config,
    agent_alias: &str,
    ctx: Option<&RunCtx>,
) -> Result<(), QuickstartError> {
    use cap_std::ambient_authority;
    use cap_std::fs::Dir;

    let install_root = config.install_root_dir();
    let workspace = config.agent_workspace_dir(agent_alias);
    let workspace_rel = workspace.strip_prefix(&install_root).map_err(|error| {
        QuickstartError::for_surface(
            ctx,
            QuickstartStep::Agent,
            "personality_files",
            format!("agent workspace is outside the install root: {error}"),
            "cli-quickstart-error-personality-workspace",
            &[("err", &error.to_string())],
        )
    })?;
    let root = Dir::open_ambient_dir(&install_root, ambient_authority()).map_err(|error| {
        QuickstartError::for_surface(
            ctx,
            QuickstartStep::Agent,
            "personality_files",
            format!("could not open install root: {error}"),
            "cli-quickstart-error-personality-workspace",
            &[("err", &error.to_string())],
        )
    })?;
    match open_existing_dir_chain_nofollow(&root, workspace_rel) {
        Ok(None) => Ok(()),
        Ok(Some(_)) => Err(QuickstartError::for_surface(
            ctx,
            QuickstartStep::Agent,
            "personality_files",
            "strict new-agent apply refuses an existing workspace".to_string(),
            "cli-quickstart-error-personality-workspace",
            &[("err", "workspace already exists")],
        )),
        Err(error) => Err(QuickstartError::for_surface(
            ctx,
            QuickstartStep::Agent,
            "personality_files",
            format!("could not inspect bounded agent workspace: {error}"),
            "cli-quickstart-error-personality-workspace",
            &[("err", &error.to_string())],
        )),
    }
}

impl Drop for StagedPersonalityWrite {
    fn drop(&mut self) {
        if !self.committed {
            let _ = self.root.remove_file(&self.temp_name);
        }
    }
}

fn apply_personality_files(
    config: &Config,
    agent_alias: &str,
    files: &[zeroclaw_config::presets::QuickstartPersonalityFile],
    staged: &mut Vec<StagedPersonalityWrite>,
    errors: &mut Vec<QuickstartError>,
    ctx: Option<&RunCtx>,
) {
    if files.is_empty() {
        return;
    }
    use cap_std::ambient_authority;
    use cap_std::fs::{Dir, OpenOptions};
    use std::io::Write as _;

    let install_root = config.install_root_dir();
    let workspace = config.agent_workspace_dir(agent_alias);
    let workspace_rel = match workspace.strip_prefix(&install_root) {
        Ok(relative) => relative.to_path_buf(),
        Err(err) => {
            errors.push(QuickstartError::for_surface(
                ctx,
                QuickstartStep::Agent,
                "personality_files",
                format!("agent workspace is outside the install root: {err}"),
                "cli-quickstart-error-personality-workspace",
                &[("err", &err.to_string())],
            ));
            return;
        }
    };
    let root = match Dir::open_ambient_dir(&install_root, ambient_authority()) {
        Ok(root) => root,
        Err(err) => {
            errors.push(QuickstartError::for_surface(
                ctx,
                QuickstartStep::Agent,
                "personality_files",
                format!("could not open install root: {err}"),
                "cli-quickstart-error-personality-workspace",
                &[("err", &err.to_string())],
            ));
            return;
        }
    };
    if let Err(err) = open_existing_dir_chain_nofollow(&root, &workspace_rel) {
        errors.push(QuickstartError::for_surface(
            ctx,
            QuickstartStep::Agent,
            "personality_files",
            format!("could not open bounded agent workspace: {err}"),
            "cli-quickstart-error-personality-workspace",
            &[("err", &err.to_string())],
        ));
        return;
    }
    for (idx, file) in files.iter().enumerate() {
        let trimmed = file.filename.trim();
        if trimmed.is_empty() {
            errors.push(QuickstartError::for_surface(
                ctx,
                QuickstartStep::Agent,
                format!("personality_files[{idx}].filename"),
                "filename is required",
                "cli-quickstart-error-personality-filename-required",
                &[],
            ));
            continue;
        }
        if !crate::agent::personality::EDITABLE_PERSONALITY_FILES.contains(&trimmed) {
            errors.push(QuickstartError::for_surface(
                ctx,
                QuickstartStep::Agent,
                format!("personality_files[{idx}].filename"),
                format!("`{trimmed}` is not an editable personality file"),
                "cli-quickstart-error-personality-not-editable",
                &[("filename", trimmed)],
            ));
            continue;
        }
        if file.content.chars().count() > crate::agent::personality::MAX_FILE_CHARS {
            let limit = crate::agent::personality::MAX_FILE_CHARS.to_string();
            errors.push(QuickstartError::for_surface(
                ctx,
                QuickstartStep::Agent,
                format!("personality_files[{idx}].content"),
                format!("content exceeds {} char limit", limit),
                "cli-quickstart-error-personality-too-large",
                &[("limit", &limit)],
            ));
            continue;
        }
        // Stage under the existing install-root handle. The workspace is not
        // created until after config persistence, and the later rename uses a
        // directory handle so a symlink swap cannot redirect the write.
        let temp_name = std::path::PathBuf::from(format!(
            ".zeroclaw-personality-{}.tmp",
            uuid::Uuid::new_v4()
        ));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use cap_std::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let mut tempfile = match root.open_with(&temp_name, &options) {
            Ok(file) => file,
            Err(err) => {
                errors.push(QuickstartError::for_surface(
                    ctx,
                    QuickstartStep::Agent,
                    format!("personality_files[{idx}]"),
                    format!("could not stage `{trimmed}`: {err}"),
                    "cli-quickstart-error-personality-stage-failed",
                    &[("filename", trimmed), ("err", &err.to_string())],
                ));
                continue;
            }
        };
        if let Err(err) = tempfile
            .write_all(file.content.as_bytes())
            .and_then(|()| tempfile.flush())
            .and_then(|()| tempfile.sync_all())
        {
            let _ = root.remove_file(&temp_name);
            errors.push(QuickstartError::for_surface(
                ctx,
                QuickstartStep::Agent,
                format!("personality_files[{idx}]"),
                format!("could not stage `{trimmed}`: {err}"),
                "cli-quickstart-error-personality-stage-failed",
                &[("filename", trimmed), ("err", &err.to_string())],
            ));
            continue;
        }
        let staged_root = match root.try_clone() {
            Ok(root) => root,
            Err(err) => {
                let _ = root.remove_file(&temp_name);
                errors.push(QuickstartError::for_surface(
                    ctx,
                    QuickstartStep::Agent,
                    format!("personality_files[{idx}]"),
                    format!("could not retain bounded workspace handle: {err}"),
                    "cli-quickstart-error-personality-stage-failed",
                    &[("filename", trimmed), ("err", &err.to_string())],
                ));
                continue;
            }
        };
        staged.push(StagedPersonalityWrite {
            root: staged_root,
            temp_name,
            workspace_rel: workspace_rel.clone(),
            dest_name: trimmed.to_string(),
            display_dest: workspace.join(trimmed),
            committed: false,
        });
    }
}

/// Move every staged tempfile into place. Called only after the atomic
/// config write succeeds; a failure here is reported but the agent is
/// already persisted and valid.
fn commit_personality_files(
    staged: Vec<StagedPersonalityWrite>,
    errors: &mut Vec<QuickstartError>,
    ctx: Option<&RunCtx>,
) {
    for mut write in staged {
        if let Err(err) = write.commit() {
            let path = write.display_dest.display().to_string();
            errors.push(QuickstartError::for_surface(
                ctx,
                QuickstartStep::Agent,
                "personality_files",
                format!("could not write `{path}`: {err}"),
                "cli-quickstart-error-personality-write-failed",
                &[("path", &path), ("err", &err.to_string())],
            ));
        }
    }
}

struct CommittedPersonalityWorkspace {
    root: cap_std::fs::Dir,
    workspace_rel: std::path::PathBuf,
}

impl CommittedPersonalityWorkspace {
    fn rollback(self) -> std::io::Result<()> {
        match self.root.remove_dir_all(&self.workspace_rel) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }
}

/// Commit a complete personality bundle before config persistence. The target
/// workspace must not already exist, which makes rollback ownership unambiguous:
/// every path removed on failure was created by this transaction.
fn commit_new_agent_personality_before_config(
    mut staged: Vec<StagedPersonalityWrite>,
    errors: &mut Vec<QuickstartError>,
    ctx: Option<&RunCtx>,
) -> Option<CommittedPersonalityWorkspace> {
    let first = staged.first()?;
    let root = match first.root.try_clone() {
        Ok(root) => root,
        Err(error) => {
            errors.push(QuickstartError::for_surface(
                ctx,
                QuickstartStep::Agent,
                "personality_files",
                format!("could not retain workspace rollback handle: {error}"),
                "cli-quickstart-error-personality-stage-failed",
                &[("filename", "workspace"), ("err", &error.to_string())],
            ));
            return None;
        }
    };
    let workspace_rel = first.workspace_rel.clone();
    match open_existing_dir_chain_nofollow(&root, &workspace_rel) {
        Ok(None) => {}
        Ok(Some(_)) => {
            errors.push(QuickstartError::for_surface(
                ctx,
                QuickstartStep::Agent,
                "personality_files",
                "strict new-agent apply refuses an existing workspace".to_string(),
                "cli-quickstart-error-personality-workspace",
                &[("err", "workspace already exists")],
            ));
            return None;
        }
        Err(error) => {
            errors.push(QuickstartError::for_surface(
                ctx,
                QuickstartStep::Agent,
                "personality_files",
                format!("could not inspect bounded agent workspace: {error}"),
                "cli-quickstart-error-personality-workspace",
                &[("err", &error.to_string())],
            ));
            return None;
        }
    }

    for write in &mut staged {
        if let Err(error) = write.commit() {
            let path = write.display_dest.display().to_string();
            errors.push(QuickstartError::for_surface(
                ctx,
                QuickstartStep::Agent,
                "personality_files",
                format!("could not write `{path}`: {error}"),
                "cli-quickstart-error-personality-write-failed",
                &[("path", &path), ("err", &error.to_string())],
            ));
            let cleanup = CommittedPersonalityWorkspace {
                root,
                workspace_rel,
            };
            if let Err(cleanup_error) = cleanup.rollback() {
                errors.push(QuickstartError::for_surface(
                    ctx,
                    QuickstartStep::Agent,
                    "personality_files",
                    format!("could not roll back incomplete workspace: {cleanup_error}"),
                    "cli-quickstart-error-personality-write-failed",
                    &[("path", &path), ("err", &cleanup_error.to_string())],
                ));
            }
            return None;
        }
    }

    Some(CommittedPersonalityWorkspace {
        root,
        workspace_rel,
    })
}

// ── Default skills bundle FTUE ─────────────────────────────────────

fn materialize_default_skills_bundle(config: &mut Config) {
    if !config.skill_bundles.is_empty() {
        return;
    }
    // create_map_key returns Ok(false) on existing key (idempotent),
    // Ok(true) on insertion. We don't propagate the error: the FTUE
    // bundle is best-effort and the operator can configure one later.
    let _ = config.create_map_key("skill-bundles", "default");
}

// ── Agent ──────────────────────────────────────────────────────────

fn apply_agent(
    config: &mut Config,
    identity: &AgentIdentity,
    provider_ref: &str,
    risk_alias: &str,
    runtime_alias: &str,
    agent_memory_backend: Option<MemoryChoice>,
    channel_refs: &[String],
    errors: &mut Vec<QuickstartError>,
    ctx: Option<&RunCtx>,
) -> Option<String> {
    if identity.name.trim().is_empty() {
        errors.push(QuickstartError::for_surface(
            ctx,
            QuickstartStep::Agent,
            "name",
            "agent name is required",
            "cli-quickstart-error-agent-name-required",
            &[],
        ));
        return None;
    }
    if config.agents.contains_key(&identity.name) {
        errors.push(QuickstartError::for_surface(
            ctx,
            QuickstartStep::Agent,
            "name",
            format!("agent `{}` already exists", identity.name),
            "cli-quickstart-error-agent-exists",
            &[("name", &identity.name)],
        ));
        return None;
    }

    let prefix = format!("agents.{}", identity.name);
    // Operator-facing surface: route through the shared guard so onboarding an
    // agent literally named `default` is refused (the reserved runtime fallback),
    // symmetric with the create/RPC/CLI surfaces. Non-`default` names create as
    // before.
    if let Err(err) =
        zeroclaw_config::alias_refs::create_map_key_checked(config, "agents", &identity.name)
    {
        errors.push(QuickstartError::new(
            QuickstartStep::Agent,
            "name",
            err.to_string(),
        ));
        return None;
    }
    let writes: [(&str, &str); 3] = [
        ("model_provider", provider_ref),
        ("risk_profile", risk_alias),
        ("runtime_profile", runtime_alias),
    ];
    for (field, value) in writes {
        let path = format!("{prefix}.{field}");
        if let Err(err) = config.set_prop_persistent(&path, value) {
            errors.push(QuickstartError::new(
                QuickstartStep::Agent,
                field,
                err.to_string(),
            ));
            return None;
        }
    }
    if let Some(memory_backend) = agent_memory_backend {
        let path = format!("{prefix}.memory.backend");
        if let Err(err) = config.set_prop_persistent(&path, &memory_choice_name(&memory_backend)) {
            errors.push(QuickstartError::new(
                QuickstartStep::Memory,
                "backend",
                err.to_string(),
            ));
            return None;
        }
    }
    if !channel_refs.is_empty() {
        let path = format!("{prefix}.channels");
        let json = serde_json::to_string(channel_refs).unwrap_or_else(|_| "[]".to_string());
        if let Err(err) = config.set_prop_persistent(&path, &json) {
            errors.push(QuickstartError::new(
                QuickstartStep::Agent,
                "channels",
                err.to_string(),
            ));
            return None;
        }
    }
    Some(identity.name.clone())
}

// ── Shared helpers ─────────────────────────────────────────────────

fn split_ref(reference: &str) -> Option<(&str, &str)> {
    let (ty, alias) = reference.split_once('.')?;
    if ty.is_empty() || alias.is_empty() {
        None
    } else {
        Some((ty, alias))
    }
}

fn section_has_alias(config: &Config, prefix: &str, family: &str, alias: &str) -> bool {
    for probe_field in ["enabled", "model", "uri"] {
        let probe = format!("{prefix}.{family}.{alias}.{probe_field}");
        if config.get_prop(&probe).is_ok() {
            return true;
        }
    }
    false
}

fn storage_has_ref(config: &Config, reference: &str) -> bool {
    collect_aliased_refs(&config.storage)
        .iter()
        .any(|configured| configured == reference)
}

pub async fn model_catalog(
    model_provider: &str,
) -> (
    Vec<String>,
    Option<std::collections::HashMap<String, zeroclaw_api::model_provider::ModelPricing>>,
    bool,
) {
    model_catalog_with_config(None, model_provider).await
}

pub async fn model_catalog_with_config(
    config: Option<&Config>,
    model_provider: &str,
) -> (
    Vec<String>,
    Option<std::collections::HashMap<String, zeroclaw_api::model_provider::ModelPricing>>,
    bool,
) {
    let resolved = config.and_then(|cfg| cfg.providers.models.find_by_name(model_provider));
    let api_key = resolved
        .as_ref()
        .and_then(|(_family, _alias, base)| base.api_key.clone());
    // Honor a configured custom endpoint so proxied / self-hosted OpenAI-compatible
    // deployments list from their own `/models` rather than the family default.
    let api_url = resolved.as_ref().and_then(|(_family, _alias, base)| {
        base.uri
            .as_deref()
            .map(str::trim)
            .filter(|u| !u.is_empty())
            .map(ToString::to_string)
    });
    // `create_model_provider` and the chat-catalog ranker expect a bare family
    // name, not a dotted ref. Prefer the family `find_by_name` resolved; when it
    // could not (no config / unknown alias) strip any `<family>.<alias>` suffix
    // ourselves so a dotted selector still constructs.
    let family: &str = resolved
        .as_ref()
        .map(|(family, _alias, _base)| *family)
        .unwrap_or_else(|| {
            model_provider
                .split_once('.')
                .map_or(model_provider, |(f, _)| f)
        });

    let handle = zeroclaw_providers::create_model_provider_with_url(
        family,
        api_key.as_deref(),
        api_url.as_deref(),
    );
    if let Ok(handle) = handle
        && let Ok(models) = zeroclaw_providers::ProviderDispatch::from_ref(&*handle)
            .list_models_with_pricing()
            .await
        && !models.is_empty()
    {
        let raw_pricing: std::collections::HashMap<
            String,
            zeroclaw_api::model_provider::ModelPricing,
        > = models
            .iter()
            .filter_map(|m| m.pricing.as_ref().map(|p| (m.id.clone(), p.clone())))
            .collect();
        let ids = models.into_iter().map(|m| m.id).collect();
        let Some(ids) = zeroclaw_providers::catalog::sort_model_catalog_for_chat(family, ids)
        else {
            return (Vec::new(), None, false);
        };
        let pricing: std::collections::HashMap<String, zeroclaw_api::model_provider::ModelPricing> =
            ids.iter()
                .filter_map(|id| raw_pricing.get(id).map(|p| (id.clone(), p.clone())))
                .collect();
        let pricing = if pricing.is_empty() {
            None
        } else {
            Some(pricing)
        };
        return (ids, pricing, true);
    }
    match zeroclaw_providers::catalog::list_models_for_family(family).await {
        Ok(models) if !models.is_empty() => (
            zeroclaw_providers::catalog::sort_model_catalog_for_chat(family, models)
                .unwrap_or_default(),
            None,
            true,
        ),
        _ => (Vec::new(), None, false),
    }
}

/// `true` for model_provider families that need no remote credential.
#[must_use]
pub fn model_provider_is_local(model_provider: &str) -> bool {
    zeroclaw_providers::list_model_providers()
        .iter()
        .find(|p| p.name == model_provider)
        .is_some_and(|p| p.local)
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroclaw_config::presets::{
        AgentIdentity, BuilderSubmission, ChannelQuickStart, MemoryChoice, ModelProviderChoice,
        QuickstartPersonalityFile, SelectorChoice,
    };
    use zeroclaw_config::schema::{AliasedAgentConfig, Config, SqliteStorageConfig};

    #[test]
    fn channel_type_options_cover_every_schema_channel() {
        let cfg = Config::default();
        let picker = build_channel_type_options(&cfg.channels);
        let schema = cfg.channels.channels();
        assert_eq!(
            picker.len(),
            schema.len(),
            "Quickstart channel-type picker count diverged from \
             ChannelsConfig::channels(); picker has {} rows, schema has {}",
            picker.len(),
            schema.len(),
        );
        for (picked, expected) in picker.iter().zip(schema.iter()) {
            assert_eq!(
                picked.kind, expected.kind,
                "kind mismatch at {} — picker `{}`, schema `{}`",
                picked.display_name, picked.kind, expected.kind,
            );
            assert_eq!(
                picked.display_name, expected.name,
                "display_name mismatch at `{}` — picker `{}`, schema `{}`",
                picked.kind, picked.display_name, expected.name,
            );
        }
    }

    #[test]
    fn provider_runtime_defaults_follow_canonical_provider_recommendations() {
        let snapshot = snapshot_state(&Config::default());

        let local = snapshot
            .model_provider_types
            .iter()
            .find(|provider| provider.kind == "lmstudio")
            .expect("LM Studio should be present in the canonical provider registry");
        assert!(local.local);
        assert_eq!(
            local.default_runtime_profile.as_deref(),
            Some("local_small")
        );

        let ollama = snapshot
            .model_provider_types
            .iter()
            .find(|provider| provider.kind == "ollama")
            .expect("Ollama should be present in the canonical provider registry");
        assert!(ollama.local);
        assert_eq!(
            ollama.default_runtime_profile.as_deref(),
            None,
            "providers without native tools must use the canonical fallback",
        );

        let remote = snapshot
            .model_provider_types
            .iter()
            .find(|provider| provider.kind == "anthropic")
            .expect("Anthropic should be present in the canonical provider registry");
        assert!(!remote.local);
        assert_eq!(remote.default_runtime_profile, None);
        assert_eq!(snapshot.default_runtime_profile, "unbounded");

        let cli_shim = snapshot
            .model_provider_types
            .iter()
            .find(|provider| provider.kind == "gemini_cli")
            .expect("Gemini CLI should be present in the canonical provider registry");
        assert!(cli_shim.local);
        assert_eq!(
            cli_shim.default_runtime_profile.as_deref(),
            None,
            "credential-free cloud CLI providers must not inherit local-small policy",
        );

        for provider in &snapshot.model_provider_types {
            if let Some(default) = provider.default_runtime_profile.as_deref() {
                assert!(
                    snapshot
                        .runtime_presets
                        .iter()
                        .any(|preset| preset.preset_name == default),
                    "provider {} advertised unavailable runtime preset {default}",
                    provider.kind,
                );
            }
        }
    }

    #[test]
    fn snapshot_state_sorts_configured_model_provider_refs() {
        let mut cfg = Config::default();
        cfg.create_map_key("providers.models.openai", "zeta")
            .unwrap();
        cfg.create_map_key("providers.models.anthropic", "omega")
            .unwrap();
        cfg.create_map_key("providers.models.anthropic", "alpha")
            .unwrap();

        let snapshot = snapshot_state(&cfg);

        assert_eq!(
            snapshot.model_providers,
            vec![
                "anthropic.alpha".to_string(),
                "anthropic.omega".to_string(),
                "openai.zeta".to_string(),
            ]
        );
    }

    fn fresh_submission(agent_name: &str) -> BuilderSubmission {
        BuilderSubmission {
            model_provider: SelectorChoice::Fresh(ModelProviderChoice {
                provider_type: "anthropic".into(),
                alias: "anthropic".into(),
                model: "claude-sonnet-4-5".into(),
                fields: std::collections::HashMap::from([(
                    "api_key".to_string(),
                    "sk-test".to_string(),
                )]),
            }),
            risk_profile: SelectorChoice::Fresh("balanced".into()),
            runtime_profile: SelectorChoice::Fresh("balanced".into()),
            memory: SelectorChoice::Fresh(MemoryChoice::Sqlite),
            channels: vec![],
            peer_groups: vec![],
            agent: AgentIdentity {
                name: agent_name.into(),
                system_prompt: "You are helpful.".into(),
                personality_file: None,
                personality_files: vec![],
            },
        }
    }

    fn fresh_channel(
        channel_type: &str,
        alias: &str,
        fields: &[(&str, &str)],
    ) -> ChannelQuickStart {
        ChannelQuickStart {
            channel_type: channel_type.into(),
            alias: alias.into(),
            fields: fields
                .iter()
                .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
                .collect(),
        }
    }

    fn apply_fresh_provider(
        choice: ModelProviderChoice,
    ) -> (Config, Option<AppliedAgent>, Vec<QuickstartError>) {
        let mut cfg = Config::default();
        let mut submission = fresh_submission("bot");
        submission.model_provider = SelectorChoice::Fresh(choice);
        let mut staged = Vec::new();
        let mut errors = Vec::new();
        let applied = apply_into(&mut cfg, &submission, &mut staged, &mut errors, None);
        (cfg, applied, errors)
    }

    #[test]
    fn existing_postgres_memory_storage_ref_is_accepted() {
        let mut cfg = Config::default();
        cfg.storage.postgres.insert(
            "default".into(),
            zeroclaw_config::schema::PostgresStorageConfig::default(),
        );
        let choice = SelectorChoice::Existing("postgres.default".to_string());
        let mut errors = Vec::new();

        let applied = apply_memory(&mut cfg, &choice, &mut errors, None);

        assert!(errors.is_empty(), "apply_memory errors: {errors:?}");
        assert_eq!(applied.as_deref(), Some("postgres.default"));
        assert_eq!(cfg.memory.backend, "postgres.default");
    }

    #[test]
    fn memory_storage_refs_from_snapshot_are_accepted() {
        let mut cfg = Config::default();
        cfg.storage.postgres.insert(
            "default".into(),
            zeroclaw_config::schema::PostgresStorageConfig::default(),
        );
        let snapshot = snapshot_state(&cfg);

        assert!(
            snapshot
                .storage
                .iter()
                .any(|ref_| ref_ == "postgres.default"),
            "snapshot should expose configured postgres storage: {:?}",
            snapshot.storage
        );
        for reference in snapshot.storage {
            let mut candidate = cfg.clone();
            let choice = SelectorChoice::Existing(reference.clone());
            let mut errors = Vec::new();

            let applied = apply_memory(&mut candidate, &choice, &mut errors, None);

            assert!(
                errors.is_empty(),
                "snapshot storage ref {reference:?} should apply without errors: {errors:?}"
            );
            assert_eq!(applied.as_deref(), Some(reference.as_str()));
            assert_eq!(candidate.memory.backend, reference);
        }
    }

    #[test]
    fn apply_serializes_provider_fields_as_snake_case() {
        let mut cfg = Config::default();
        let submission = fresh_submission("bot");
        let mut staged = Vec::new();
        let mut errors = Vec::new();
        let applied = apply_into(&mut cfg, &submission, &mut staged, &mut errors, None);
        assert!(errors.is_empty(), "apply_into errors: {errors:?}");
        assert!(applied.is_some(), "apply_into should yield an agent");
        // The submission carries the snake field key `api_key` and it must
        // land on disk as the snake serde field `api_key`, never kebab.
        let toml = toml::to_string(&cfg).expect("serialize config");
        assert!(
            toml.contains("api_key"),
            "expected snake `api_key` in serialized config:\n{toml}"
        );
        assert!(
            !toml.contains("api-key"),
            "kebab `api-key` leaked into serialized config:\n{toml}"
        );
    }

    #[test]
    fn apply_provider_type_trims_and_canonicalizes_whitespace() {
        // A provider type with stray whitespace must canonicalize to the
        // registry's family key, not reach create_map_key verbatim (which would
        // fail with "no map-keyed/list section at providers.models.llamacpp ").
        let (cfg, applied, errors) = apply_fresh_provider(ModelProviderChoice {
            provider_type: "  llamacpp  ".into(),
            alias: "local".into(),
            model: "qwen2.5-coder".into(),
            fields: std::collections::HashMap::new(),
        });
        assert!(errors.is_empty(), "apply_into errors: {errors:?}");
        assert!(applied.is_some());
        assert!(
            cfg.providers.models.find("llamacpp", "local").is_some(),
            "expected providers.models.llamacpp.local to exist"
        );
        let agent = cfg.agents.get("bot").expect("agent created");
        assert_eq!(agent.model_provider.as_str(), "llamacpp.local");
    }

    #[test]
    fn apply_provider_type_case_insensitive() {
        let (cfg, applied, errors) = apply_fresh_provider(ModelProviderChoice {
            provider_type: "Anthropic".into(),
            alias: "main".into(),
            model: "claude-sonnet-4-5".into(),
            fields: std::collections::HashMap::new(),
        });
        assert!(errors.is_empty(), "apply_into errors: {errors:?}");
        assert!(applied.is_some());
        assert!(cfg.providers.models.find("anthropic", "main").is_some());
    }

    #[test]
    fn apply_claude_alias_writes_canonical_anthropic_config() {
        let (cfg, applied, errors) = apply_fresh_provider(ModelProviderChoice {
            provider_type: "claude".into(),
            alias: "max".into(),
            model: "claude-sonnet-4-5".into(),
            fields: std::collections::HashMap::from([
                ("auth_mode".to_string(), "setup_token".to_string()),
                ("api_key".to_string(), "sk-ant-oat01-test-token".to_string()),
            ]),
        });
        assert!(errors.is_empty(), "apply_into errors: {errors:?}");
        assert!(applied.is_some());
        let entry = cfg
            .providers
            .models
            .find("anthropic", "max")
            .expect("anthropic.max entry");
        assert_eq!(entry.model.as_deref(), Some("claude-sonnet-4-5"));
        assert_eq!(entry.api_key.as_deref(), Some("sk-ant-oat01-test-token"));
        assert!(
            cfg.get_prop("providers.models.anthropic.max.auth_mode")
                .is_err()
        );
        let agent = cfg.agents.get("bot").expect("agent created");
        assert_eq!(agent.model_provider.as_str(), "anthropic.max");
    }

    #[test]
    fn apply_openai_codex_alias_writes_canonical_openai_auth_config() {
        let (cfg, applied, errors) = apply_fresh_provider(ModelProviderChoice {
            provider_type: "openai-codex".into(),
            alias: "coding".into(),
            model: "gpt-5.4".into(),
            fields: std::collections::HashMap::new(),
        });
        assert!(errors.is_empty(), "apply_into errors: {errors:?}");
        assert!(applied.is_some());
        let entry = cfg
            .providers
            .models
            .find("openai", "coding")
            .expect("openai.coding entry");
        assert_eq!(entry.model.as_deref(), Some("gpt-5.4"));
        assert_eq!(entry.wire_api, Some(WireApi::Responses));
        assert!(entry.requires_openai_auth);
        let agent = cfg.agents.get("bot").expect("agent created");
        assert_eq!(agent.model_provider.as_str(), "openai.coding");
    }

    #[test]
    fn apply_openai_auth_mode_codex_ignores_api_key_field() {
        let (cfg, applied, errors) = apply_fresh_provider(ModelProviderChoice {
            provider_type: "openai".into(),
            alias: "coding".into(),
            model: "gpt-5.4".into(),
            fields: std::collections::HashMap::from([
                ("auth_mode".to_string(), "codex".to_string()),
                ("api_key".to_string(), "sk-should-not-persist".to_string()),
            ]),
        });
        assert!(errors.is_empty(), "apply_into errors: {errors:?}");
        assert!(applied.is_some());
        let entry = cfg
            .providers
            .models
            .find("openai", "coding")
            .expect("openai.coding entry");
        assert_eq!(entry.wire_api, Some(WireApi::Responses));
        assert!(entry.requires_openai_auth);
        assert!(
            entry.api_key.is_none(),
            "Codex auth must not persist an API key from the Quickstart form"
        );
    }

    #[test]
    fn apply_unknown_anthropic_auth_mode_errors_clearly() {
        let (_, applied, errors) = apply_fresh_provider(ModelProviderChoice {
            provider_type: "anthropic".into(),
            alias: "main".into(),
            model: "claude-sonnet-4-5".into(),
            fields: std::collections::HashMap::from([(
                "auth_mode".to_string(),
                "not_real".to_string(),
            )]),
        });
        assert!(applied.is_none());
        assert!(
            errors
                .iter()
                .any(|e| e.step == QuickstartStep::ModelProvider
                    && e.field == "auth_mode"
                    && e.message.contains("unknown Anthropic auth mode")),
            "expected a clear unknown-Anthropic-auth-mode error, got: {errors:?}"
        );
    }

    #[test]
    fn apply_unknown_provider_type_errors_clearly() {
        let (_, applied, errors) = apply_fresh_provider(ModelProviderChoice {
            provider_type: "not_a_real_provider".into(),
            alias: "x".into(),
            model: "m".into(),
            fields: std::collections::HashMap::new(),
        });
        assert!(applied.is_none());
        assert!(
            errors
                .iter()
                .any(|e| e.step == QuickstartStep::ModelProvider
                    && e.message.contains("unknown model provider type")),
            "expected a clear unknown-provider error, got: {errors:?}"
        );
    }

    #[test]
    fn validate_only_passes_on_fresh_submission() {
        let cfg = Config::default();
        let submission = fresh_submission("bot");
        validate_only(&submission, &cfg).expect("fresh submission validates");
    }

    #[test]
    fn validate_only_rejects_blank_agent_name() {
        let cfg = Config::default();
        let submission = fresh_submission("");
        let errors = validate_only(&submission, &cfg).unwrap_err();
        assert!(
            errors
                .iter()
                .any(|e| e.step == QuickstartStep::Agent && e.field == "name")
        );
    }

    #[test]
    fn validate_only_rejects_existing_agent_name() {
        let mut cfg = Config::default();
        cfg.agents.insert(
            "bot".into(),
            zeroclaw_config::schema::AliasedAgentConfig::default(),
        );
        let submission = fresh_submission("bot");
        let errors = validate_only(&submission, &cfg).unwrap_err();
        assert!(errors.iter().any(|e| e.step == QuickstartStep::Agent));
    }

    #[test]
    fn validate_only_rejects_unknown_risk_preset() {
        let cfg = Config::default();
        let mut submission = fresh_submission("bot");
        submission.risk_profile = SelectorChoice::Fresh("does-not-exist".into());
        let errors = validate_only(&submission, &cfg).unwrap_err();
        assert!(errors.iter().any(|e| e.step == QuickstartStep::RiskProfile));
    }

    #[tokio::test]
    async fn rejected_runtime_selection_leaves_live_config_unchanged() {
        let mut cfg = Config::default();
        let before = serde_json::to_value(&cfg).expect("serialize initial config");
        let before_dirty_paths = cfg.dirty_paths.clone();
        let mut submission = fresh_submission("bot");
        submission.runtime_profile = SelectorChoice::Fresh("does-not-exist".into());

        let errors = apply(submission, &mut cfg).await.unwrap_err();

        assert!(
            errors
                .iter()
                .any(|error| error.step == QuickstartStep::RuntimeProfile),
            "expected a runtime-profile error, got {errors:?}",
        );
        assert_eq!(
            serde_json::to_value(&cfg).expect("serialize rejected config"),
            before,
        );
        assert_eq!(cfg.dirty_paths, before_dirty_paths);
    }

    #[tokio::test]
    async fn missing_existing_runtime_leaves_live_config_unchanged() {
        let mut cfg = Config::default();
        let before = serde_json::to_value(&cfg).expect("serialize initial config");
        let before_dirty_paths = cfg.dirty_paths.clone();
        let mut submission = fresh_submission("bot");
        submission.runtime_profile = SelectorChoice::Existing("missing".into());

        let errors = apply(submission, &mut cfg).await.unwrap_err();

        assert!(
            errors
                .iter()
                .any(|error| error.step == QuickstartStep::RuntimeProfile),
            "expected a runtime-profile error, got {errors:?}",
        );
        assert_eq!(
            serde_json::to_value(&cfg).expect("serialize rejected config"),
            before,
        );
        assert_eq!(cfg.dirty_paths, before_dirty_paths);
    }

    #[test]
    fn validate_only_accepts_every_builtin_risk_preset() {
        let cfg = Config::default();
        for p in zeroclaw_config::presets::RISK_PRESETS {
            let mut submission = fresh_submission("bot");
            submission.risk_profile = SelectorChoice::Fresh(p.preset_name.into());
            validate_only(&submission, &cfg).unwrap_or_else(|e| {
                panic!("risk preset `{}` failed validate: {e:?}", p.preset_name)
            });
        }
    }

    #[test]
    fn field_shape_returns_model_provider_rows_for_canonical_types() {
        for kind in ["anthropic", "openai", "ollama", "openrouter", "groq"] {
            let rows = super::field_shape(super::FieldSection::ModelProvider, kind);
            let keys: Vec<&str> = rows.iter().map(|r| r.key.as_str()).collect();
            assert!(
                keys.contains(&"model"),
                "field_shape for `{kind}` is missing `model` row; got {keys:?}",
            );
            assert!(
                keys.contains(&"api_key"),
                "field_shape for `{kind}` is missing `api_key` row; got {keys:?}",
            );
        }
    }

    /// Codex subscription auth: `field_shape(ModelProvider, "openai")` exposes
    /// one Quickstart-only auth selector instead of raw config toggles. Apply
    /// translates `auth_mode = "codex"` into the canonical persisted
    /// `wire_api = "responses"` + `requires_openai_auth = true` fields.
    #[test]
    fn field_shape_openai_includes_codex_auth_mode() {
        let rows = super::field_shape(super::FieldSection::ModelProvider, "openai");
        let keys: Vec<&str> = rows.iter().map(|r| r.key.as_str()).collect();
        assert!(
            keys.contains(&"auth_mode"),
            "field_shape for openai must include `auth_mode` for Codex subscription; got {keys:?}",
        );
        assert!(
            !keys.contains(&"requires_openai_auth") && !keys.contains(&"wire_api"),
            "field_shape for openai should hide raw Codex config toggles; got {keys:?}",
        );
        let auth = rows
            .iter()
            .find(|row| row.key == "auth_mode")
            .expect("auth_mode row");
        assert!(auth.required);
        assert_eq!(
            auth.enum_variants.as_deref(),
            Some(["api_key".to_string(), "codex".to_string()].as_slice())
        );
        assert_eq!(auth.default.as_deref(), Some("api_key"));
        // No row may carry the `<unset>` placeholder as its default.
        // It's a display sentinel for an unset Option; echoing it back
        // through any surface (CLI/TUI/web) makes the daemon validate
        // `<unset>` against the field's real type and reject it.
        for row in &rows {
            assert_ne!(
                row.default.as_deref(),
                Some(zeroclaw_config::traits::UNSET_DISPLAY),
                "`{}` must not default to the <unset> placeholder",
                row.key
            );
        }
    }

    #[test]
    fn field_shape_openai_codex_alias_preselects_codex_auth() {
        let rows = super::field_shape(super::FieldSection::ModelProvider, "openai-codex");
        let auth = rows
            .iter()
            .find(|row| row.key == "auth_mode")
            .expect("auth_mode row");
        assert_eq!(auth.default.as_deref(), Some("codex"));
    }

    #[test]
    fn field_shape_anthropic_includes_claude_auth_mode() {
        let rows = super::field_shape(super::FieldSection::ModelProvider, "claude");
        let keys: Vec<&str> = rows.iter().map(|r| r.key.as_str()).collect();
        assert!(
            keys.contains(&"auth_mode"),
            "field_shape for claude/anthropic must include `auth_mode`; got {keys:?}",
        );
        let auth = rows
            .iter()
            .find(|row| row.key == "auth_mode")
            .expect("auth_mode row");
        assert!(auth.required);
        assert_eq!(
            auth.enum_variants.as_deref(),
            Some(["api_key".to_string(), "setup_token".to_string()].as_slice())
        );
        assert_eq!(auth.default.as_deref(), Some("api_key"));
        let api_key = rows
            .iter()
            .find(|row| row.key == "api_key")
            .expect("api_key row");
        assert!(
            api_key.help.contains("claude setup-token"),
            "Anthropic API key help should mention setup-token flow; got {:?}",
            api_key.help
        );
    }

    /// `api_key` must be non-required in the Quickstart form so Codex
    /// subscription (no API key) and local providers (Ollama) can proceed
    /// without one.
    #[test]
    fn field_shape_api_key_is_not_required() {
        for kind in ["openai", "ollama"] {
            let rows = super::field_shape(super::FieldSection::ModelProvider, kind);
            let api_key_row = rows.iter().find(|r| r.key == "api_key");
            assert!(
                api_key_row.is_some(),
                "field_shape for `{kind}` must include `api_key`",
            );
            assert!(
                !api_key_row.unwrap().required,
                "`api_key` must be non-required for `{kind}` (Codex subscription / local providers don't need one)",
            );
        }
    }

    #[test]
    fn webhook_channel_quickstart_fields_include_port_and_secret() {
        let rows = super::field_shape(super::FieldSection::Channel, "webhook");
        let port = rows
            .iter()
            .find(|row| row.key == "port")
            .expect("webhook port row");
        assert_eq!(port.default.as_deref(), Some("8090"));
        assert!(port.required);
        assert!(!port.is_secret);

        let secret = rows
            .iter()
            .find(|row| row.key == "secret")
            .expect("webhook secret row");
        assert!(secret.required);
        assert!(secret.is_secret);
        assert_eq!(secret.default, None);
    }

    #[test]
    fn non_webhook_channel_quickstart_fields_exclude_webhook_requirements() {
        for channel_type in ["irc", "lark"] {
            let rows = super::field_shape(super::FieldSection::Channel, channel_type);
            assert!(
                rows.iter()
                    .all(|row| row.key != "port" && row.key != "secret"),
                "{channel_type} must not inherit webhook-only fields; got {rows:?}"
            );
        }
    }

    async fn apply_to_temp(submission: BuilderSubmission) -> (tempfile::TempDir, Config) {
        let dir = tempfile::tempdir().unwrap();
        let config = Config {
            config_path: dir.path().join("config.toml"),
            data_dir: dir.path().join("data"),
            ..Default::default()
        };
        config.save().await.unwrap();
        let mut config = config;
        super::apply(submission, &mut config)
            .await
            .expect("apply should succeed");
        (dir, config)
    }

    fn reload(dir: &tempfile::TempDir) -> Config {
        let raw = std::fs::read_to_string(dir.path().join("config.toml")).unwrap();
        toml::from_str(&raw).expect("on-disk config must round-trip")
    }

    async fn seeded_multi_agent_config(dir: &tempfile::TempDir) -> Config {
        let mut config = Config {
            config_path: dir.path().join("config.toml"),
            data_dir: dir.path().join("data"),
            ..Default::default()
        };
        config.memory.backend = "sqlite.shared".into();
        config.storage.sqlite.insert(
            "shared".into(),
            SqliteStorageConfig {
                path: Some("resident-memory.db".into()),
                open_timeout_secs: Some(17),
            },
        );
        let mut resident = AliasedAgentConfig {
            enabled: false,
            skill_bundles: vec!["resident_bundle".into()],
            ..Default::default()
        };
        resident.memory.backend = MemoryChoice::Markdown;
        config.agents.insert("resident".into(), resident);
        config.save().await.unwrap();
        config
    }

    #[tokio::test]
    async fn ordinary_apply_with_surface_still_persists() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = Config {
            config_path: dir.path().join("config.toml"),
            data_dir: dir.path().join("data"),
            ..Default::default()
        };
        config.save().await.unwrap();

        super::apply_with_surface(fresh_submission("ordinary"), &mut config, Surface::Test)
            .await
            .expect("ordinary apply_with_surface should succeed");

        let reloaded = reload(&dir);
        assert_eq!(reloaded.memory.backend, "sqlite.sqlite");
        let agent = reloaded
            .agents
            .get("ordinary")
            .expect("ordinary apply_with_surface must persist the agent");
        assert_eq!(agent.model_provider, "anthropic.anthropic");
        assert_eq!(agent.risk_profile, "balanced");
        assert_eq!(agent.runtime_profile, "balanced");
    }

    #[tokio::test]
    async fn revision_bound_apply_refuses_stale_source_before_workspace_staging() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = Config {
            config_path: dir.path().join("config.toml"),
            data_dir: dir.path().join("data"),
            ..Default::default()
        };
        config.save().await.unwrap();
        let expected_source = std::fs::read_to_string(&config.config_path).unwrap();
        let drifted_source = format!("{expected_source}\n# external config edit\n");
        std::fs::write(&config.config_path, &drifted_source).unwrap();

        let mut submission = fresh_submission("stale");
        submission.agent.personality_files = vec![QuickstartPersonalityFile {
            filename: "IDENTITY.md".into(),
            content: "This file must never be staged.".into(),
        }];
        let workspace = config.agent_workspace_dir("stale");

        let errors = super::apply_with_surface_if_source_unchanged(
            submission,
            &mut config,
            Surface::Test,
            &expected_source,
        )
        .await
        .expect_err("stale expected source must refuse Quickstart apply");

        assert!(errors.iter().any(|error| {
            error.step == QuickstartStep::Agent
                && error.field == "config_source"
                && error.message.contains("configuration changed")
        }));
        assert_eq!(
            std::fs::read_to_string(&config.config_path).unwrap(),
            drifted_source,
            "stale apply must not rewrite the externally changed config"
        );
        assert!(
            !workspace.exists(),
            "the pre-apply guard must run before workspace creation and tempfile staging"
        );
        assert!(!config.agents.contains_key("stale"));
        assert!(config.dirty_paths.is_empty());
    }

    #[tokio::test]
    async fn revision_bound_apply_with_matching_source_persists_bindings_and_personality() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = Config {
            config_path: dir.path().join("config.toml"),
            data_dir: dir.path().join("data"),
            ..Default::default()
        };
        config.save().await.unwrap();
        let expected_source = std::fs::read_to_string(&config.config_path).unwrap();

        let mut submission = fresh_submission("revision_bound");
        submission.agent.personality_files = vec![QuickstartPersonalityFile {
            filename: "IDENTITY.md".into(),
            content: "Revision-bound personality".into(),
        }];

        let applied = super::apply_with_surface_if_source_unchanged(
            submission,
            &mut config,
            Surface::Test,
            &expected_source,
        )
        .await
        .expect("matching expected source should apply");

        assert_eq!(applied.alias, "revision_bound");
        assert_eq!(applied.model_provider, "anthropic.anthropic");
        assert_eq!(applied.risk_profile, "balanced");
        assert_eq!(applied.runtime_profile, "balanced");

        let reloaded = reload(&dir);
        assert_eq!(reloaded.memory.backend, "sqlite.sqlite");
        let agent = reloaded
            .agents
            .get("revision_bound")
            .expect("revision-bound agent persisted");
        assert_eq!(agent.model_provider, "anthropic.anthropic");
        assert_eq!(agent.risk_profile, "balanced");
        assert_eq!(agent.runtime_profile, "balanced");
        assert!(reloaded.risk_profiles.contains_key("balanced"));
        assert!(reloaded.runtime_profiles.contains_key("balanced"));
        assert_eq!(
            reloaded
                .providers
                .models
                .find("anthropic", "anthropic")
                .and_then(|provider| provider.model.as_deref()),
            Some("claude-sonnet-4-5")
        );

        let personality_path = config
            .agent_workspace_dir("revision_bound")
            .join("IDENTITY.md");
        assert_eq!(
            std::fs::read_to_string(personality_path).unwrap(),
            "Revision-bound personality"
        );
    }

    #[tokio::test]
    async fn strict_new_agent_apply_persists_only_after_complete_personality_bundle() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = Config {
            config_path: dir.path().join("config.toml"),
            data_dir: dir.path().join("data"),
            ..Default::default()
        };
        config.save().await.unwrap();
        let expected_source = std::fs::read_to_string(&config.config_path).unwrap();
        let mut submission = fresh_submission("strict_agent");
        submission.agent.personality_files = vec![
            QuickstartPersonalityFile {
                filename: "SOUL.md".into(),
                content: "Strict soul".into(),
            },
            QuickstartPersonalityFile {
                filename: "IDENTITY.md".into(),
                content: "Strict identity".into(),
            },
        ];

        super::apply_new_agent_strict_if_source_unchanged_per_agent_memory(
            submission,
            &mut config,
            Surface::Test,
            &expected_source,
        )
        .await
        .expect("strict add-agent apply should succeed");

        let reloaded = reload(&dir);
        assert!(reloaded.agents.contains_key("strict_agent"));
        let workspace = config.agent_workspace_dir("strict_agent");
        assert_eq!(
            std::fs::read_to_string(workspace.join("SOUL.md")).unwrap(),
            "Strict soul"
        );
        assert_eq!(
            std::fs::read_to_string(workspace.join("IDENTITY.md")).unwrap(),
            "Strict identity"
        );
    }

    #[test]
    fn strict_workspace_rollback_requires_proven_uncommitted_config() {
        assert!(strict_workspace_rollback_allowed(
            zeroclaw_config::schema::ConfigWriteDisposition::NotCommitted
        ));
        assert!(!strict_workspace_rollback_allowed(
            zeroclaw_config::schema::ConfigWriteDisposition::Committed
        ));
        assert!(!strict_workspace_rollback_allowed(
            zeroclaw_config::schema::ConfigWriteDisposition::Ambiguous
        ));
    }

    #[tokio::test]
    async fn strict_new_agent_apply_refuses_preexisting_workspace_without_config_write() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = Config {
            config_path: dir.path().join("config.toml"),
            data_dir: dir.path().join("data"),
            ..Default::default()
        };
        config.save().await.unwrap();
        let expected_source = std::fs::read_to_string(&config.config_path).unwrap();
        let mut submission = fresh_submission("occupied");
        submission.agent.personality_files = vec![QuickstartPersonalityFile {
            filename: "SOUL.md".into(),
            content: "New soul".into(),
        }];
        let workspace = config.agent_workspace_dir("occupied");
        std::fs::create_dir_all(&workspace).unwrap();
        std::fs::write(workspace.join("sentinel"), "owned elsewhere").unwrap();

        super::apply_new_agent_strict_if_source_unchanged_per_agent_memory(
            submission,
            &mut config,
            Surface::Test,
            &expected_source,
        )
        .await
        .expect_err("strict add-agent must not claim an existing workspace");

        assert!(!reload(&dir).agents.contains_key("occupied"));
        assert_eq!(
            std::fs::read_to_string(workspace.join("sentinel")).unwrap(),
            "owned elsewhere"
        );
        assert!(!workspace.join("SOUL.md").exists());
    }

    #[tokio::test]
    async fn strict_new_agent_without_personality_still_refuses_preexisting_workspace() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = Config {
            config_path: dir.path().join("config.toml"),
            data_dir: dir.path().join("data"),
            ..Default::default()
        };
        config.save().await.unwrap();
        let expected_source = std::fs::read_to_string(&config.config_path).unwrap();
        let submission = fresh_submission("occupied_without_files");
        let workspace = config.agent_workspace_dir("occupied_without_files");
        std::fs::create_dir_all(&workspace).unwrap();
        std::fs::write(workspace.join("sentinel"), "owned elsewhere").unwrap();

        super::apply_new_agent_strict_if_source_unchanged_per_agent_memory(
            submission,
            &mut config,
            Surface::Test,
            &expected_source,
        )
        .await
        .expect_err("strict add-agent must reject an existing workspace even without new files");

        assert!(!reload(&dir).agents.contains_key("occupied_without_files"));
        assert_eq!(
            std::fs::read_to_string(workspace.join("sentinel")).unwrap(),
            "owned elsewhere"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_strict_same_alias_apply_keeps_the_winner_workspace() {
        let dir = tempfile::tempdir().unwrap();
        let config = Config {
            config_path: dir.path().join("config.toml"),
            data_dir: dir.path().join("data"),
            ..Default::default()
        };
        config.save().await.unwrap();
        let expected_source = std::fs::read_to_string(&config.config_path).unwrap();
        let mut submission = fresh_submission("one_winner");
        submission.agent.personality_files = vec![QuickstartPersonalityFile {
            filename: "SOUL.md".into(),
            content: "Winner workspace".into(),
        }];
        let mut first_config = config.clone();
        let mut second_config = config.clone();
        let first_submission = submission.clone();
        let second_submission = submission;
        let first_source = expected_source.clone();
        let second_source = expected_source;

        let (first, second) = tokio::join!(
            super::apply_new_agent_strict_if_source_unchanged_per_agent_memory(
                first_submission,
                &mut first_config,
                Surface::Test,
                &first_source,
            ),
            super::apply_new_agent_strict_if_source_unchanged_per_agent_memory(
                second_submission,
                &mut second_config,
                Surface::Test,
                &second_source,
            ),
        );
        assert_ne!(
            first.is_ok(),
            second.is_ok(),
            "exactly one same-alias transaction must publish"
        );

        let reloaded = reload(&dir);
        assert!(reloaded.agents.contains_key("one_winner"));
        assert_eq!(
            std::fs::read_to_string(config.agent_workspace_dir("one_winner").join("SOUL.md"))
                .unwrap(),
            "Winner workspace"
        );
    }

    #[tokio::test]
    async fn strict_workspace_rolls_back_when_config_revision_changes_after_file_commit() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = Config {
            config_path: dir.path().join("config.toml"),
            data_dir: dir.path().join("data"),
            ..Default::default()
        };
        config.save().await.unwrap();
        let expected_source = std::fs::read_to_string(&config.config_path).unwrap();
        let mut submission = fresh_submission("drift_after_files");
        submission.agent.personality_files = vec![QuickstartPersonalityFile {
            filename: "SOUL.md".into(),
            content: "Never expose partially".into(),
        }];
        let ctx = RunCtx::new(Surface::Test);
        let mut staged_files = Vec::new();
        let mut errors = Vec::new();
        let applied = apply_into_with_memory_mode(
            &mut config,
            &submission,
            &mut staged_files,
            &mut errors,
            Some(&ctx),
            MemoryApplyMode::CreatedAgent,
        );
        assert!(errors.is_empty());
        assert!(applied.is_some());
        config
            .set_prop_persistent("onboard_state.quickstart_completed", "true")
            .unwrap();
        let committed =
            commit_new_agent_personality_before_config(staged_files, &mut errors, Some(&ctx))
                .expect("personality bundle should commit before config");
        assert!(errors.is_empty());
        let workspace = config.agent_workspace_dir("drift_after_files");
        assert!(workspace.join("SOUL.md").exists());

        let drifted = format!("{expected_source}\n# external edit\n");
        std::fs::write(&config.config_path, &drifted).unwrap();
        assert!(
            !config
                .save_dirty_if_source_unchanged(&expected_source)
                .await
                .unwrap()
        );
        committed.rollback().unwrap();

        assert!(!workspace.exists());
        assert_eq!(
            std::fs::read_to_string(&config.config_path).unwrap(),
            drifted
        );
        assert!(!reload(&dir).agents.contains_key("drift_after_files"));
    }

    #[tokio::test]
    async fn per_agent_memory_apply_preserves_global_memory_existing_agents_and_storage() {
        for (suffix, memory_backend) in [
            ("sqlite", MemoryChoice::Sqlite),
            ("markdown", MemoryChoice::Markdown),
            ("none", MemoryChoice::None),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let mut config = seeded_multi_agent_config(&dir).await;
            let persisted_before = reload(&dir);
            let global_memory_before = persisted_before.memory.backend.clone();
            let resident_before =
                serde_json::to_value(&persisted_before.agents["resident"]).unwrap();
            let storage_before = serde_json::to_value(&persisted_before.storage).unwrap();
            let expected_source = std::fs::read_to_string(&config.config_path).unwrap();

            let alias = format!("agent_{suffix}");
            let mut submission = fresh_submission(&alias);
            submission.memory = SelectorChoice::Fresh(memory_backend);
            submission.agent.personality_files = vec![QuickstartPersonalityFile {
                filename: "IDENTITY.md".into(),
                content: format!("Per-agent {suffix} memory"),
            }];

            let applied = super::apply_with_surface_if_source_unchanged_per_agent_memory(
                submission,
                &mut config,
                Surface::Test,
                &expected_source,
            )
            .await
            .expect("matching source should apply per-agent memory");

            assert_eq!(applied.alias, alias);
            assert_eq!(applied.memory_backend, suffix);
            let reloaded = reload(&dir);
            assert_eq!(reloaded.memory.backend, global_memory_before);
            assert_eq!(
                serde_json::to_value(&reloaded.agents["resident"]).unwrap(),
                resident_before,
                "adding {alias} must not mutate the resident agent"
            );
            assert_eq!(
                serde_json::to_value(&reloaded.storage).unwrap(),
                storage_before,
                "adding {alias} must not create or mutate install-wide storage"
            );

            let agent = reloaded.agents.get(&alias).expect("new agent persisted");
            assert_eq!(agent.memory.backend, memory_backend);
            assert_eq!(agent.risk_profile, "balanced");
            assert_eq!(agent.runtime_profile, "balanced");
            assert_eq!(agent.model_provider, "anthropic.anthropic");
            assert_eq!(
                std::fs::read_to_string(config.agent_workspace_dir(&alias).join("IDENTITY.md"))
                    .unwrap(),
                format!("Per-agent {suffix} memory")
            );
        }
    }

    #[tokio::test]
    async fn per_agent_memory_apply_refuses_stale_source_without_writes() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = seeded_multi_agent_config(&dir).await;
        let expected_source = std::fs::read_to_string(&config.config_path).unwrap();
        let drifted_source = format!("{expected_source}\n# concurrent edit\n");
        std::fs::write(&config.config_path, &drifted_source).unwrap();

        let global_memory_before = config.memory.backend.clone();
        let resident_before = serde_json::to_value(&config.agents["resident"]).unwrap();
        let storage_before = serde_json::to_value(&config.storage).unwrap();
        let mut submission = fresh_submission("stale_agent_memory");
        submission.memory = SelectorChoice::Fresh(MemoryChoice::None);
        submission.agent.personality_files = vec![QuickstartPersonalityFile {
            filename: "IDENTITY.md".into(),
            content: "Must not be staged".into(),
        }];
        let workspace = config.agent_workspace_dir("stale_agent_memory");

        let errors = super::apply_with_surface_if_source_unchanged_per_agent_memory(
            submission,
            &mut config,
            Surface::Test,
            &expected_source,
        )
        .await
        .expect_err("stale expected source must refuse per-agent-memory apply");

        assert!(errors.iter().any(|error| {
            error.field == "config_source" && error.message.contains("configuration changed")
        }));
        assert_eq!(
            std::fs::read_to_string(&config.config_path).unwrap(),
            drifted_source
        );
        assert!(!workspace.exists());
        assert!(!config.agents.contains_key("stale_agent_memory"));
        assert_eq!(config.memory.backend, global_memory_before);
        assert_eq!(
            serde_json::to_value(&config.agents["resident"]).unwrap(),
            resident_before
        );
        assert_eq!(
            serde_json::to_value(&config.storage).unwrap(),
            storage_before
        );
        assert!(config.dirty_paths.is_empty());
    }

    #[test]
    fn personality_staging_does_not_create_workspace_before_config_persists() {
        let dir = tempfile::tempdir().unwrap();
        let config = Config {
            config_path: dir.path().join("config.toml"),
            data_dir: dir.path().join("data"),
            ..Default::default()
        };
        let workspace = config.agent_workspace_dir("staged_only");
        let files = vec![QuickstartPersonalityFile {
            filename: "IDENTITY.md".into(),
            content: "staged but not committed".into(),
        }];
        let mut staged = Vec::new();
        let mut errors = Vec::new();

        apply_personality_files(
            &config,
            "staged_only",
            &files,
            &mut staged,
            &mut errors,
            None,
        );

        assert!(errors.is_empty(), "staging failed: {errors:?}");
        assert_eq!(staged.len(), 1);
        assert!(
            !workspace.exists(),
            "a late config-drift refusal must not leave an empty workspace"
        );
        drop(staged);
        assert!(
            std::fs::read_dir(dir.path()).unwrap().all(|entry| !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".zeroclaw-personality-")),
            "dropping staged writes must remove install-root tempfiles"
        );
    }

    #[cfg(unix)]
    #[test]
    fn personality_staging_refuses_workspace_symlink_escape() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let config = Config {
            config_path: dir.path().join("config.toml"),
            data_dir: dir.path().join("data"),
            ..Default::default()
        };
        let workspace = config.agent_workspace_dir("escape");
        std::fs::create_dir_all(workspace.parent().unwrap()).unwrap();
        symlink(outside.path(), &workspace).unwrap();
        let files = vec![QuickstartPersonalityFile {
            filename: "SOUL.md".into(),
            content: "must stay contained".into(),
        }];
        let mut staged = Vec::new();
        let mut errors = Vec::new();

        apply_personality_files(&config, "escape", &files, &mut staged, &mut errors, None);

        assert!(staged.is_empty());
        assert!(
            !errors.is_empty(),
            "a workspace symlink must be refused before config persistence"
        );
        assert!(!outside.path().join("SOUL.md").exists());
    }

    #[cfg(unix)]
    #[test]
    fn personality_staging_refuses_workspace_symlink_to_another_agent() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let config = Config {
            config_path: dir.path().join("config.toml"),
            data_dir: dir.path().join("data"),
            ..Default::default()
        };
        let resident_workspace = config.agent_workspace_dir("resident");
        std::fs::create_dir_all(&resident_workspace).unwrap();
        let workspace = config.agent_workspace_dir("escape");
        std::fs::create_dir_all(workspace.parent().unwrap()).unwrap();
        symlink(&resident_workspace, &workspace).unwrap();
        let files = vec![QuickstartPersonalityFile {
            filename: "SOUL.md".into(),
            content: "must not overwrite a resident".into(),
        }];
        let mut staged = Vec::new();
        let mut errors = Vec::new();

        apply_personality_files(&config, "escape", &files, &mut staged, &mut errors, None);

        assert!(staged.is_empty());
        assert!(
            !errors.is_empty(),
            "an in-install workspace symlink must be refused"
        );
        assert!(!resident_workspace.join("SOUL.md").exists());
    }

    #[cfg(unix)]
    #[test]
    fn personality_staging_refuses_intermediate_agent_symlink() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let config = Config {
            config_path: dir.path().join("config.toml"),
            data_dir: dir.path().join("data"),
            ..Default::default()
        };
        let resident_workspace = config.agent_workspace_dir("resident");
        std::fs::create_dir_all(&resident_workspace).unwrap();
        let escape_agent_dir = config.install_root_dir().join("agents/escape");
        symlink(
            config.install_root_dir().join("agents/resident"),
            &escape_agent_dir,
        )
        .unwrap();
        let files = vec![QuickstartPersonalityFile {
            filename: "SOUL.md".into(),
            content: "must not cross the alias boundary".into(),
        }];
        let mut staged = Vec::new();
        let mut errors = Vec::new();

        apply_personality_files(&config, "escape", &files, &mut staged, &mut errors, None);

        assert!(staged.is_empty());
        assert!(
            !errors.is_empty(),
            "an intermediate agent-directory symlink must be refused"
        );
        assert!(!resident_workspace.join("SOUL.md").exists());
    }

    #[tokio::test]
    async fn fresh_preset_profiles_persist_to_disk() {
        let (dir, applied) = apply_to_temp(fresh_submission("bot")).await;
        assert!(applied.risk_profiles.contains_key("balanced"));
        assert!(applied.runtime_profiles.contains_key("balanced"));
        let reloaded = reload(&dir);
        assert!(
            reloaded.risk_profiles.contains_key("balanced"),
            "risk_profiles.balanced must survive save_dirty + reload, not dangle"
        );
        assert!(
            reloaded.runtime_profiles.contains_key("balanced"),
            "runtime_profiles.balanced must survive save_dirty + reload, not dangle"
        );
        let agent = reloaded.agents.get("bot").expect("agent persisted");
        assert_eq!(agent.risk_profile, "balanced");
        assert_eq!(agent.runtime_profile, "balanced");
    }

    #[tokio::test]
    async fn existing_runtime_profile_is_reused_without_writing_preset() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = Config {
            config_path: dir.path().join("config.toml"),
            data_dir: dir.path().join("data"),
            ..Default::default()
        };
        config.runtime_profiles.insert(
            "small-laptop".into(),
            zeroclaw_config::schema::RuntimeProfileConfig {
                max_tool_iterations: 2,
                ..Default::default()
            },
        );
        config.save().await.unwrap();

        let mut submission = fresh_submission("bot");
        submission.runtime_profile = SelectorChoice::Existing("small-laptop".into());
        super::apply(submission, &mut config)
            .await
            .expect("apply should reuse existing runtime profile");

        let reloaded = reload(&dir);
        assert!(
            reloaded.runtime_profiles.contains_key("small-laptop"),
            "existing runtime profile must stay configured"
        );
        assert!(
            !reloaded.runtime_profiles.contains_key("balanced"),
            "existing runtime profile choice must not write the fresh preset"
        );
        let agent = reloaded.agents.get("bot").expect("agent persisted");
        assert_eq!(agent.runtime_profile, "small-laptop");
        assert_eq!(
            reloaded
                .runtime_profiles
                .get("small-laptop")
                .expect("existing profile persisted")
                .max_tool_iterations,
            2,
            "existing profile values must not be clobbered"
        );
    }

    #[tokio::test]
    async fn multiple_channels_all_bind_to_agent() {
        let mut submission = fresh_submission("bot");
        submission.channels = vec![
            SelectorChoice::Fresh(fresh_channel("telegram", "tg", &[("bot_token", "tok-a")])),
            SelectorChoice::Fresh(fresh_channel("discord", "dc", &[("bot_token", "tok-b")])),
        ];
        let (dir, _applied) = apply_to_temp(submission).await;
        let reloaded = reload(&dir);
        let agent = reloaded.agents.get("bot").expect("agent persisted");
        let bound: Vec<String> = agent.channels.iter().map(|c| c.to_string()).collect();
        assert!(
            bound.iter().any(|c| c.contains("tg")),
            "first channel must stay bound; got {bound:?}"
        );
        assert!(
            bound.iter().any(|c| c.contains("dc")),
            "second channel must also be bound; got {bound:?}"
        );
        assert_eq!(bound.len(), 2, "both channels bound, not just the last");
        let store = zeroclaw_config::secrets::SecretStore::new(dir.path(), true);
        assert_eq!(
            store
                .decrypt(&reloaded.channels.telegram["tg"].bot_token)
                .unwrap(),
            "tok-a"
        );
        assert!(reloaded.channels.telegram["tg"].enabled);
        assert_eq!(
            store
                .decrypt(&reloaded.channels.discord["dc"].bot_token)
                .unwrap(),
            "tok-b"
        );
        assert!(reloaded.channels.discord["dc"].enabled);
    }

    #[tokio::test]
    async fn telegram_channel_fields_persist_canonical_bot_token() {
        let mut submission = fresh_submission("bot");
        submission.channels = vec![SelectorChoice::Fresh(fresh_channel(
            "telegram",
            "ops",
            &[("bot_token", " 123:ABC ")],
        ))];

        let (dir, _) = apply_to_temp(submission).await;
        let reloaded = reload(&dir);
        let store = zeroclaw_config::secrets::SecretStore::new(dir.path(), true);
        assert_eq!(
            store
                .decrypt(&reloaded.channels.telegram["ops"].bot_token)
                .unwrap(),
            "123:ABC"
        );
        assert!(reloaded.channels.telegram["ops"].enabled);
    }

    #[tokio::test]
    async fn webhook_channel_quickstart_fields_persist() {
        let mut submission = fresh_submission("bot");
        submission.channels = vec![SelectorChoice::Fresh(fresh_channel(
            "webhook",
            "inbound",
            &[("port", "9191"), ("secret", "shared-secret")],
        ))];

        let (dir, _) = apply_to_temp(submission).await;
        let reloaded = reload(&dir);
        let webhook = &reloaded.channels.webhook["inbound"];
        assert_eq!(webhook.port, 9191);
        assert!(webhook.enabled);

        let stored_secret = webhook.secret.as_deref().expect("persisted webhook secret");
        assert!(zeroclaw_config::secrets::SecretStore::is_encrypted(
            stored_secret
        ));
        let store = zeroclaw_config::secrets::SecretStore::new(dir.path(), true);
        assert_eq!(store.decrypt(stored_secret).unwrap(), "shared-secret");
    }

    #[test]
    fn webhook_channel_defaults_port_and_rejects_unusable_secret() {
        for value in [
            None,
            Some(""),
            Some("   "),
            Some(zeroclaw_config::traits::UNSET_DISPLAY),
        ] {
            let mut cfg = Config::default();
            let fields = value.map_or_else(Vec::new, |value| vec![("secret", value)]);
            let channels = vec![SelectorChoice::Fresh(fresh_channel(
                "webhook", "inbound", &fields,
            ))];
            let mut errors = Vec::new();

            let refs = apply_channels(&mut cfg, &channels, &mut errors, None);

            assert!(refs.is_empty());
            assert!(errors.iter().any(|error| {
                error.field == "channels[0].fields.secret" && error.message.contains("required")
            }));
            assert!(!cfg.channels.webhook.contains_key("inbound"));
        }

        let mut cfg = Config::default();
        let channels = vec![SelectorChoice::Fresh(fresh_channel(
            "webhook",
            "inbound",
            &[("secret", "shared-secret")],
        ))];
        let mut errors = Vec::new();

        let refs = apply_channels(&mut cfg, &channels, &mut errors, None);

        assert!(errors.is_empty(), "apply errors: {errors:?}");
        assert_eq!(refs, ["webhook.inbound"]);
        assert_eq!(
            cfg.channels.webhook["inbound"].port,
            zeroclaw_config::schema::DEFAULT_WEBHOOK_CHANNEL_PORT
        );
    }

    #[test]
    fn webhook_channel_cli_reports_webhook_secret_error() {
        let cfg = Config::default();
        let mut submission = fresh_submission("bot");
        submission.channels = vec![SelectorChoice::Fresh(fresh_channel(
            "webhook",
            "inbound",
            &[("secret", "")],
        ))];

        let errors = validate_only_with_surface(&submission, &cfg, Surface::Cli)
            .expect_err("empty webhook secret must be rejected");

        assert!(errors.iter().any(|error| {
            error.field == "channels[0].fields.secret"
                && error.message == "Webhook shared secret is required"
        }));
    }

    #[test]
    fn telegram_channel_fields_reject_unusable_bot_token_values() {
        for value in [
            None,
            Some(""),
            Some("   "),
            Some(zeroclaw_config::traits::UNSET_DISPLAY),
        ] {
            let cfg = Config::default();
            let mut submission = fresh_submission("bot");
            let fields = value.map_or_else(Vec::new, |value| vec![("bot_token", value)]);
            submission.channels = vec![SelectorChoice::Fresh(fresh_channel(
                "telegram", "ops", &fields,
            ))];

            let errors = validate_only(&submission, &cfg).expect_err("token must be rejected");
            assert!(errors.iter().any(|error| {
                error.step == QuickstartStep::Channels
                    && error.field == "channels[0].fields.bot_token"
                    && error.message.contains("required")
            }));
        }
    }

    #[test]
    fn discord_channel_fields_reject_unusable_bot_token_values() {
        // Discord twin of telegram_channel_fields_reject_unusable_bot_token_values:
        // the quickstart arm calls DiscordConfig::validate_bot_token.
        for value in [
            None,
            Some(""),
            Some("   "),
            Some(zeroclaw_config::traits::UNSET_DISPLAY),
        ] {
            let cfg = Config::default();
            let mut submission = fresh_submission("bot");
            let fields = value.map_or_else(Vec::new, |value| vec![("bot_token", value)]);
            submission.channels = vec![SelectorChoice::Fresh(fresh_channel(
                "discord", "ops", &fields,
            ))];

            let errors = validate_only(&submission, &cfg).expect_err("token must be rejected");
            assert!(errors.iter().any(|error| {
                error.step == QuickstartStep::Channels
                    && error.field == "channels[0].fields.bot_token"
                    && error.message.contains("required")
            }));
        }
    }

    #[test]
    fn channel_fields_reject_unknown_keys_without_exposing_values() {
        let mut cfg = Config::default();
        let before = serde_json::to_value(&cfg).expect("serialize config");
        let before_dirty_paths = cfg.dirty_paths.clone();
        let mut submission = fresh_submission("bot");
        submission.channels = vec![SelectorChoice::Fresh(fresh_channel(
            "discord",
            "ops",
            &[("unknown_secret", "super-secret-value")],
        ))];
        let mut errors = Vec::new();

        let refs = apply_channels(&mut cfg, &submission.channels, &mut errors, None);

        assert!(refs.is_empty());
        let error = errors
            .iter()
            .find(|error| error.field == "channels[0].fields.unknown_secret")
            .expect("structured unknown-field error");
        assert!(!error.message.contains("super-secret-value"));
        assert_eq!(
            serde_json::to_value(&cfg).expect("serialize config"),
            before
        );
        assert_eq!(cfg.dirty_paths, before_dirty_paths);
    }

    #[test]
    fn channel_fields_reject_valid_but_unadvertised_schema_keys() {
        let mut cfg = Config::default();
        let before = serde_json::to_value(&cfg).expect("serialize config");
        let mut submission = fresh_submission("bot");
        submission.channels = vec![SelectorChoice::Fresh(fresh_channel(
            "telegram",
            "ops",
            &[
                ("bot_token", "123:ABC"),
                ("api_base_url", "https://example.invalid"),
            ],
        ))];
        let mut errors = Vec::new();

        let refs = apply_channels(&mut cfg, &submission.channels, &mut errors, None);

        assert!(refs.is_empty());
        assert!(errors.iter().any(|error| {
            error.field == "channels[0].fields.api_base_url"
                && error.message.contains("not available in Quickstart")
        }));
        assert_eq!(
            serde_json::to_value(&cfg).expect("serialize config"),
            before
        );
    }

    #[test]
    fn channel_fields_materialize_credential_free_channel() {
        let mut cfg = Config::default();
        let mut submission = fresh_submission("bot");
        submission.channels = vec![SelectorChoice::Fresh(fresh_channel(
            "imessage",
            "local",
            &[],
        ))];
        let mut staged = Vec::new();
        let mut errors = Vec::new();

        let applied = apply_into(&mut cfg, &submission, &mut staged, &mut errors, None);

        assert!(errors.is_empty(), "apply_into errors: {errors:?}");
        assert!(applied.is_some());
        assert!(channel_exists(&cfg, "imessage", "local"));
    }

    #[tokio::test]
    async fn fresh_whatsapp_web_channel_persists_under_whatsapp_config_family() {
        for submitted_type in ["whatsapp-web", "whatsapp_web"] {
            let mut submission = fresh_submission("bot");
            submission.channels = vec![SelectorChoice::Fresh(fresh_channel(
                submitted_type,
                "personal",
                &[],
            ))];
            submission.peer_groups = vec![zeroclaw_config::presets::QuickstartPeerGroup {
                name: "self_chat".into(),
                channel: format!("{submitted_type}.personal"),
                external_peers: vec!["*".into()],
                ignore: vec![],
            }];

            let (dir, _applied) = apply_to_temp(submission).await;
            let raw = std::fs::read_to_string(dir.path().join("config.toml")).unwrap();
            assert!(
                raw.contains("[channels.whatsapp.personal]"),
                "WhatsApp Web quickstart must persist under the canonical WhatsApp config family:\n{raw}"
            );
            assert!(
                !raw.contains("[channels.whatsapp-web.personal]")
                    && !raw.contains("[channels.whatsapp_web.personal]"),
                "Quickstart must not write a non-schema WhatsApp Web table:\n{raw}"
            );

            let reloaded = reload(&dir);
            let whatsapp = reloaded
                .channels
                .whatsapp
                .get("personal")
                .expect("canonical WhatsApp alias persisted");
            let expected_session = dir
                .path()
                .join("state")
                .join("whatsapp-web")
                .join("personal.db")
                .to_string_lossy()
                .into_owned();
            assert_eq!(
                whatsapp.session_path.as_deref(),
                Some(expected_session.as_str())
            );
            assert!(
                whatsapp.is_web_config(),
                "fresh WhatsApp Web entry must seed a Web selector"
            );
            let agent = reloaded.agents.get("bot").expect("agent persisted");
            let bound: Vec<String> = agent.channels.iter().map(|c| c.to_string()).collect();
            assert_eq!(
                bound,
                vec!["whatsapp.personal".to_string()],
                "agent must bind the canonical channel ref"
            );
            let group = reloaded
                .peer_groups
                .get("self_chat")
                .expect("peer group persisted");
            assert_eq!(group.channel, "whatsapp.personal");
        }
    }

    #[tokio::test]
    async fn peer_groups_persist_to_canonical_section() {
        let mut submission = fresh_submission("bot");
        submission.channels = vec![SelectorChoice::Fresh(fresh_channel(
            "telegram",
            "tg",
            &[("bot_token", "tok-a")],
        ))];
        submission.peer_groups = vec![zeroclaw_config::presets::QuickstartPeerGroup {
            name: "team".into(),
            channel: "telegram.tg".into(),
            external_peers: vec!["*".into()],
            ignore: vec![],
        }];

        let (dir, _applied) = apply_to_temp(submission).await;
        let raw = std::fs::read_to_string(dir.path().join("config.toml")).unwrap();
        assert!(
            raw.contains("[peer_groups.team]"),
            "Quickstart must serialize peer groups through canonical snake_case paths:\n{raw}"
        );
        assert!(
            !raw.contains("[peer-groups.team]"),
            "Quickstart must not write the stale kebab-case peer-groups path:\n{raw}"
        );

        let reloaded = reload(&dir);
        let group = reloaded
            .peer_groups
            .get("team")
            .expect("peer group persisted");
        assert_eq!(group.channel, "telegram.tg");
        assert_eq!(group.external_peers, vec!["*".to_string()]);
    }

    #[tokio::test]
    async fn model_catalog_with_config_uses_native_endpoint_when_credentialed() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        // Native /models endpoint advertising a model that is NOT in the
        // static models.dev snapshot (a freshly released Grok).
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/models"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": [
                    {"id": "grok-4.5-native-only"},
                    {"id": "grok-4.3"}
                ]
            })))
            .mount(&server)
            .await;

        let mut config = Config::default();
        config.providers.models.xai.insert(
            "default".to_string(),
            zeroclaw_config::schema::XaiModelProviderConfig {
                base: zeroclaw_config::schema::ModelProviderConfig {
                    api_key: Some("xai-test-key".to_string()),
                    uri: Some(server.uri()),
                    ..Default::default()
                },
            },
        );

        let (models, _pricing, live) =
            model_catalog_with_config(Some(&config), "xai.default").await;

        assert!(live, "credentialed native listing must report live=true");
        assert!(
            models.iter().any(|m| m == "grok-4.5-native-only"),
            "native /models result must surface the freshly-released model \
             that models.dev does not carry; got {models:?}"
        );
    }

    #[tokio::test]
    async fn model_catalog_with_config_resolves_named_alias_endpoint() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/models"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": [{"id": "grok-named-alias-native"}]
            })))
            .mount(&server)
            .await;

        let mut config = Config::default();
        // Non-default alias name to prove the dotted ref targets it precisely.
        config.providers.models.xai.insert(
            "prod".to_string(),
            zeroclaw_config::schema::XaiModelProviderConfig {
                base: zeroclaw_config::schema::ModelProviderConfig {
                    api_key: Some("xai-test-key".to_string()),
                    uri: Some(server.uri()),
                    ..Default::default()
                },
            },
        );

        let (models, _pricing, live) = model_catalog_with_config(Some(&config), "xai.prod").await;

        assert!(live);
        assert!(
            models.iter().any(|m| m == "grok-named-alias-native"),
            "dotted `<family>.<alias>` selector must resolve that alias's \
             configured endpoint; got {models:?}"
        );
    }
}
