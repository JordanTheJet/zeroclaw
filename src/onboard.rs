//! Interactive CLI host for the capability-free Zerona agent creator.

use std::io::{BufRead, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use zeroclaw_api::principal::Principal;
use zeroclaw_config::multi_agent::MemoryBackendKind;
use zeroclaw_config::schema::{Config, SopConfig};
use zeroclaw_control::{
    CurrentProviderFactory, FluentMessage, PROPOSAL_MARKER, PersonalityFilePreview,
    ProposalPreview, ValidatedProposal, ZeronaSession, build_preview, eligible_provider_refs,
    revalidate_proposal, validate_operator_input,
};
use zeroclaw_runtime::quickstart::{
    Surface, apply_new_agent_strict_if_source_unchanged_per_agent_memory,
};
use zeroclaw_runtime::sop::approval::{ApprovalPrincipal, BrokerOutcome, ResolveOutcome};
use zeroclaw_runtime::sop::types::SopAdmissionPolicy;
use zeroclaw_runtime::sop::{
    ApprovalDecision, Sop, SopEngine, SopEvent, SopExecutionMode, SopPriority, SopRunAction,
    SopRunStatus, SopStep, SopStepKind, SopStepResult, SopStepStatus, SopTrigger, SopTriggerSource,
    StepFailure, StepRouting, StepSchema, SwitchRule, SystemSopId,
};

const INPUT_CAP_BYTES: usize = 64 * 1024;
const CONFIG_LOAD_ATTEMPTS: usize = 3;
const ZERONA_SOP_NAME: &str = "system.zerona.create_agent";

fn tr(key: &str) -> String {
    zeroclaw_runtime::i18n::get_required_cli_string(key)
}

fn render_message(message: &FluentMessage) -> String {
    let args: Vec<(&str, &str)> = message
        .args
        .iter()
        .map(|(key, value)| (key.as_str(), value.as_str()))
        .collect();
    zeroclaw_runtime::i18n::get_required_cli_string_with_args(message.key, &args)
}

fn tra(key: &str, args: &[(&str, &str)]) -> String {
    zeroclaw_runtime::i18n::get_required_cli_string_with_args(key, args)
}

fn interactive_terminal_available() -> bool {
    std::io::stdin().is_terminal() && std::io::stdout().is_terminal()
}

fn is_exit_alias(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "exit" | "quit" | "/exit" | "/quit"
    )
}

fn cap_line_utf8_safe(value: &mut String, max_bytes: usize) {
    if value.len() <= max_bytes {
        return;
    }
    let mut end = max_bytes;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    value.truncate(end);
}

fn read_line(prompt: &str) -> Result<Option<String>> {
    print!("{prompt} ");
    std::io::stdout().flush()?;
    let mut line = String::new();
    let read = std::io::stdin()
        .lock()
        .take((INPUT_CAP_BYTES + 1) as u64)
        .read_line(&mut line)?;
    if read == 0 {
        return Ok(None);
    }
    if line.len() > INPUT_CAP_BYTES {
        cap_line_utf8_safe(&mut line, INPUT_CAP_BYTES);
        anyhow::bail!(tr("cli-zerona-error-input-too-large"));
    }
    Ok(Some(line.trim_end_matches(['\r', '\n']).to_string()))
}

fn choose_provider(config: &Config) -> Result<Option<String>> {
    let providers = eligible_provider_refs(config, &CurrentProviderFactory);
    if providers.is_empty() {
        println!("{}", tr("cli-zerona-no-provider"));
        return Ok(None);
    }
    if providers.len() == 1 {
        return Ok(providers.into_iter().next());
    }
    let selection = dialoguer::Select::new()
        .with_prompt(tr("cli-zerona-provider-prompt"))
        .items(&providers)
        .default(0)
        .interact_opt()?;
    Ok(selection.map(|index| providers[index].clone()))
}

/// Load a config while proving its source bytes stayed unchanged for the whole
/// load. The returned source is the revision the operator will preview.
async fn load_stable_config(config_path: &Path) -> Result<(Config, String)> {
    for _ in 0..CONFIG_LOAD_ATTEMPTS {
        let before = tokio::fs::read_to_string(config_path)
            .await
            .context("read config revision before Zerona preview")?;
        if !source_schema_is_current(&before) {
            anyhow::bail!(tr("cli-zerona-error-current-schema-required"));
        }
        let loaded = Box::pin(Config::load_or_init()).await?;
        if !loaded.degraded_security.is_empty() || !loaded.degraded_sections.is_empty() {
            anyhow::bail!(tr("cli-zerona-error-healthy-config-required"));
        }
        let after = tokio::fs::read_to_string(config_path)
            .await
            .context("read config revision after Zerona preview")?;
        if before == after && loaded.config_path == config_path {
            return Ok((loaded, before));
        }
    }
    anyhow::bail!(tr("cli-zerona-error-config-busy"))
}

fn source_schema_is_current(source: &str) -> bool {
    toml::from_str::<toml::Value>(source)
        .ok()
        .and_then(|value| zeroclaw_config::migration::detect_version(&value).ok())
        == Some(zeroclaw_config::migration::CURRENT_SCHEMA_VERSION)
}

/// Refuse stale on-disk schemas before the generic config loader can run its
/// V1/V2 filesystem migration. A missing file is allowed so the normal fresh
/// install path can initialize it and then report that no provider is ready.
pub async fn preflight_source_schema() -> Result<()> {
    let (config_dir, _) = zeroclaw_config::schema::resolve_runtime_dirs().await?;
    let config_path = config_dir.join("config.toml");
    match tokio::fs::read_to_string(&config_path).await {
        Ok(source) if source_schema_is_current(&source) => Ok(()),
        Ok(_) => anyhow::bail!(tr("cli-zerona-error-current-schema-required")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).context("read config schema before Zerona startup"),
    }
}

fn visible_assistant_text(reply: &str) -> &str {
    reply
        .split_once(PROPOSAL_MARKER)
        .map_or(reply, |(visible, _)| visible)
        .trim()
}

fn safe_terminal(value: &str) -> String {
    value
        .chars()
        .filter(|character| {
            (!character.is_control() || matches!(character, '\n' | '\t'))
                && !matches!(
                    character,
                    '\u{061c}'
                        | '\u{200e}'
                        | '\u{200f}'
                        | '\u{2028}'
                        | '\u{2029}'
                        | '\u{202a}'..='\u{202e}'
                        | '\u{2066}'..='\u{206f}'
                )
        })
        .collect()
}

fn render_personality_file(file: &PersonalityFilePreview) {
    println!(
        "{}",
        tra(
            "cli-zerona-preview-file-heading",
            &[("filename", &file.filename)]
        )
    );
    for line in file.content.split_inclusive('\n') {
        let line = line.strip_suffix('\n').unwrap_or(line);
        println!("│ {}", safe_terminal(line));
    }
    println!(
        "{}",
        tra(
            "cli-zerona-preview-file-destination",
            &[(
                "path",
                &safe_terminal(&file.destination.display().to_string())
            )]
        )
    );
    println!("{}", tr("cli-zerona-preview-file-overwrite-warning"));
    println!(
        "{}",
        tra(
            "cli-zerona-preview-file-end",
            &[("filename", &file.filename)]
        )
    );
}

fn print_preview(preview: &ProposalPreview) {
    println!();
    println!("{}", tr("cli-zerona-preview-title"));
    for (key, value) in [
        ("cli-zerona-preview-agent", preview.agent_alias.as_str()),
        (
            "cli-zerona-preview-provider",
            preview.selected_model_provider.as_str(),
        ),
        ("cli-zerona-preview-model", preview.selected_model.as_str()),
        ("cli-zerona-preview-risk", preview.risk.preset_name()),
        ("cli-zerona-preview-runtime", preview.runtime.preset_name()),
        ("cli-zerona-preview-memory", preview.memory.wire_name()),
    ] {
        println!("{}", tra(key, &[("value", value)]));
    }
    if preview.persistence.creates_workspace_during_apply {
        println!(
            "{}",
            tra(
                "cli-zerona-preview-workspace",
                &[(
                    "path",
                    &safe_terminal(&preview.persistence.workspace_dir.display().to_string())
                )]
            )
        );
    } else {
        println!("{}", tr("cli-zerona-preview-workspace-not-created"));
    }
    println!(
        "{}",
        tra(
            "cli-zerona-preview-config",
            &[(
                "path",
                &safe_terminal(&preview.persistence.config_path.display().to_string())
            )]
        )
    );
    for path in &preview.persistence.config_paths {
        println!(
            "{}",
            tra("cli-zerona-preview-config-write", &[("path", path)])
        );
    }

    println!();
    println!("{}", tr("cli-zerona-preview-personality"));
    if preview.personality_files.is_empty() {
        println!("{}", tr("cli-zerona-preview-personality-empty"));
    } else {
        for file in &preview.personality_files {
            render_personality_file(file);
        }
    }

    println!();
    println!("{}", tr("cli-zerona-preview-posture"));
    println!(
        "{}",
        tra(
            "cli-zerona-preview-autonomy",
            &[(
                "value",
                &format!("{:?}", preview.effective_posture.autonomy)
            )]
        )
    );
    println!(
        "{}",
        tra(
            "cli-zerona-preview-workspace-only",
            &[(
                "value",
                if preview.effective_posture.workspace_only {
                    "true"
                } else {
                    "false"
                }
            )]
        )
    );
    println!(
        "{}",
        tra(
            "cli-zerona-preview-high-risk-blocked",
            &[(
                "value",
                if preview.effective_posture.block_high_risk_commands {
                    "true"
                } else {
                    "false"
                }
            )]
        )
    );
    println!(
        "{}",
        tra(
            "cli-zerona-preview-filesystem-unconfined",
            &[(
                "value",
                if preview.effective_posture.filesystem_unconfined {
                    "true"
                } else {
                    "false"
                }
            )]
        )
    );
    for path in &preview.effective_posture.allowed_roots {
        println!(
            "{}",
            tra(
                "cli-zerona-preview-allowed-root",
                &[("path", &safe_terminal(&path.display().to_string()))]
            )
        );
    }
    for path in &preview.effective_posture.allowed_roots_read_only {
        println!(
            "{}",
            tra(
                "cli-zerona-preview-allowed-root-read-only",
                &[("path", &safe_terminal(&path.display().to_string()))]
            )
        );
    }
    for path in &preview.effective_posture.allowed_roots_write_only {
        println!(
            "{}",
            tra(
                "cli-zerona-preview-allowed-root-write-only",
                &[("path", &safe_terminal(&path.display().to_string()))]
            )
        );
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReviewVerdict {
    Apply,
    Revise,
    Cancel,
}

fn parse_review_verdict(value: &str) -> Option<ReviewVerdict> {
    match value {
        "apply" => Some(ReviewVerdict::Apply),
        "revise" => Some(ReviewVerdict::Revise),
        "cancel" => Some(ReviewVerdict::Cancel),
        _ => None,
    }
}

fn read_review_verdict() -> Result<ReviewVerdict> {
    loop {
        let Some(value) = read_line(&tr("cli-zerona-review-prompt"))? else {
            return Ok(ReviewVerdict::Cancel);
        };
        if let Some(verdict) = parse_review_verdict(&value) {
            return Ok(verdict);
        }
        eprintln!("{}", tr("cli-zerona-review-invalid"));
    }
}

fn host_revision_message(feedback: &str) -> String {
    format!(
        "[ZERONA_HOST_FEEDBACK] The operator requested a revision: {feedback}. \
         Keep the useful context, ask only what is missing, then produce a complete new proposal."
    )
}

fn host_drift_message() -> String {
    "[ZERONA_HOST_FEEDBACK] The canonical configuration changed after the preview. \
     Re-read the host-provided inventory and produce a new complete proposal."
        .to_string()
}

fn zerona_turn_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "required": ["proposal_ready", "turn_digest", "artifact_digest"],
        "properties": {
            "proposal_ready": {"type": "boolean"},
            "turn_digest": {"type": "string"},
            "artifact_digest": {"type": "string"}
        }
    })
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn builtin_zerona_sop() -> Sop {
    let turn_schema = zerona_turn_schema();
    Sop {
        name: ZERONA_SOP_NAME.to_string(),
        description: "Built-in capability-free agent creation".to_string(),
        version: "1.0.0".to_string(),
        priority: SopPriority::Normal,
        execution_mode: SopExecutionMode::Deterministic,
        triggers: vec![SopTrigger::Manual],
        steps: vec![
            SopStep {
                number: 1,
                title: tr("cli-zerona-turn-prompt"),
                body: tr("cli-zerona-turn-prompt"),
                kind: SopStepKind::Input,
                schema: Some(StepSchema {
                    input: None,
                    output: Some(serde_json::json!({"type": "string"})),
                }),
                routing: StepRouting {
                    next: Some(2),
                    ..StepRouting::default()
                },
                ..SopStep::default()
            },
            SopStep {
                number: 2,
                title: "Zerona capability-free model turn".to_string(),
                body: "The host executes one isolated ZeronaSession turn.".to_string(),
                kind: SopStepKind::Execute,
                schema: Some(StepSchema {
                    input: Some(serde_json::json!({"type": "string"})),
                    output: Some(turn_schema.clone()),
                }),
                routing: StepRouting {
                    switch: vec![
                        SwitchRule {
                            name: "proposal".to_string(),
                            when: Some("$.steps.2.proposal_ready == true".to_string()),
                            goto: Some(3),
                        },
                        SwitchRule {
                            name: "continue".to_string(),
                            when: None,
                            goto: Some(1),
                        },
                    ],
                    ..StepRouting::default()
                },
                on_failure: StepFailure::Goto { step: 1 },
                ..SopStep::default()
            },
            SopStep {
                number: 3,
                title: tr("cli-zerona-preview-title"),
                body: tr("cli-zerona-review-prompt"),
                kind: SopStepKind::Checkpoint,
                schema: Some(StepSchema {
                    input: Some(turn_schema.clone()),
                    output: Some(turn_schema.clone()),
                }),
                routing: StepRouting {
                    next: Some(4),
                    ..StepRouting::default()
                },
                on_failure: StepFailure::Goto { step: 1 },
                gate_prompt: Some(tr("cli-zerona-review-prompt")),
                ..SopStep::default()
            },
            SopStep {
                number: 4,
                title: "Apply approved Zerona proposal".to_string(),
                body: "The host revalidates and atomically applies the approved proposal."
                    .to_string(),
                kind: SopStepKind::Execute,
                schema: Some(StepSchema {
                    input: Some(turn_schema),
                    output: Some(serde_json::json!({
                        "type": "object",
                        "required": ["agent_alias"],
                        "properties": {"agent_alias": {"type": "string"}}
                    })),
                }),
                routing: StepRouting {
                    terminal: true,
                    ..StepRouting::default()
                },
                on_failure: StepFailure::Goto { step: 1 },
                ..SopStep::default()
            },
        ],
        cooldown_secs: 0,
        max_concurrent: 1,
        location: None,
        deterministic: true,
        admission_policy: SopAdmissionPolicy::Hold,
        max_pending_approvals: 1,
        agent: None,
    }
}

fn zerona_manual_event() -> SopEvent {
    SopEvent {
        source: SopTriggerSource::Manual,
        topic: None,
        payload: None,
        timestamp: zeroclaw_runtime::sop::engine::now_iso8601(),
    }
}

fn failed_sop_step(step: &SopStep, reason: String) -> SopStepResult {
    let now = zeroclaw_runtime::sop::engine::now_iso8601();
    SopStepResult {
        step_number: step.number,
        status: SopStepStatus::Failed,
        output: reason,
        started_at: now.clone(),
        completed_at: Some(now),
        effective_agent: None,
        tool_calls: Vec::new(),
    }
}

fn resumed_broker_action(outcome: BrokerOutcome) -> Result<SopRunAction> {
    match outcome {
        BrokerOutcome::Resolved(ResolveOutcome::Resumed(action)) => Ok(*action),
        other => anyhow::bail!("Zerona checkpoint did not resume: {other:?}"),
    }
}

struct PendingApply {
    validated: ValidatedProposal,
    config: Config,
    expected_source: String,
}

fn session_source_is_current(session_source: &str, current_source: &str) -> bool {
    session_source == current_source
}

struct PreservedApplyState {
    memory: serde_json::Value,
    storage: serde_json::Value,
    agents: serde_json::Value,
    channels: serde_json::Value,
    peer_groups: serde_json::Value,
    providers: serde_json::Value,
}

impl PreservedApplyState {
    fn capture(config: &Config) -> Result<Self> {
        Ok(Self {
            memory: serde_json::to_value(&config.memory)?,
            storage: serde_json::to_value(&config.storage)?,
            agents: serde_json::to_value(&config.agents)?,
            channels: serde_json::to_value(&config.channels)?,
            peer_groups: serde_json::to_value(&config.peer_groups)?,
            providers: serde_json::to_value(&config.providers)?,
        })
    }

    fn matches_after_add(&self, config: &Config, added_alias: &str) -> Result<bool> {
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

fn verify_install(
    config: &Config,
    proposal: &ValidatedProposal,
    expected_alias: &str,
    preserved: &PreservedApplyState,
) -> Result<()> {
    let Some(agent) = config.agents.get(expected_alias) else {
        anyhow::bail!("applied agent is absent after config reload");
    };
    let raw = proposal.proposal();
    let expected_memory = match raw.memory {
        zeroclaw_control::MemoryChoice::Sqlite => MemoryBackendKind::Sqlite,
        zeroclaw_control::MemoryChoice::Markdown => MemoryBackendKind::Markdown,
        zeroclaw_control::MemoryChoice::None => MemoryBackendKind::None,
    };
    if !preserved.matches_after_add(config, expected_alias)?
        || agent.model_provider.as_str() != proposal.selected_provider_ref()
        || agent.risk_profile.as_str() != raw.risk.preset_name()
        || agent.runtime_profile.as_str() != raw.runtime.preset_name()
        || !agent.channels.is_empty()
        || agent.memory.backend != expected_memory
    {
        anyhow::bail!("installed agent bindings differ from the approved proposal");
    }
    let workspace = config.agent_workspace_dir(expected_alias);
    for file in &raw.personality_files {
        let installed = std::fs::read_to_string(workspace.join(&file.filename))?;
        if installed != file.content {
            anyhow::bail!("installed personality differs from the approved proposal");
        }
    }
    Ok(())
}

pub async fn run(initial_config: Config) -> Result<()> {
    if !interactive_terminal_available() {
        anyhow::bail!(tr("cli-zerona-tty-required"));
    }
    let config_path: PathBuf = initial_config.config_path.clone();
    let (session_config, session_source) = Box::pin(load_stable_config(&config_path)).await?;
    let Some(selected_provider) = choose_provider(&session_config)? else {
        return Ok(());
    };
    let mut session = ZeronaSession::new(&session_config, selected_provider.clone())
        .map_err(|error| anyhow::Error::msg(render_message(&error.fluent())))?;

    println!(
        "{}",
        tra(
            "cli-zerona-intro",
            &[("provider", selected_provider.as_str())]
        )
    );
    let mut sop_engine = SopEngine::new(SopConfig::default());
    sop_engine.register_builtin_sop(SystemSopId::ZERONA_CREATE_AGENT, builtin_zerona_sop())?;
    let mut action =
        sop_engine.start_system_run(SystemSopId::ZERONA_CREATE_AGENT, zerona_manual_event())?;
    let mut host_message: Option<String> = None;
    let mut pending_apply: Option<PendingApply> = None;

    loop {
        match action {
            SopRunAction::InteractiveInputWait {
                run_id,
                step,
                prior_input: _,
                reference_revision,
                request_fingerprint,
            } => {
                let message = loop {
                    let candidate = if let Some(message) = host_message.take() {
                        message
                    } else {
                        let Some(message) = read_line(&step.body)? else {
                            sop_engine.cancel_run(&run_id)?;
                            println!("{}", tr("cli-zerona-cancelled"));
                            return Ok(());
                        };
                        if is_exit_alias(&message) {
                            sop_engine.cancel_run(&run_id)?;
                            println!("{}", tr("cli-zerona-cancelled"));
                            return Ok(());
                        }
                        message
                    };
                    match validate_operator_input(&candidate) {
                        Ok(()) => break candidate,
                        Err(error) => eprintln!("{}", render_message(&error.fluent())),
                    }
                };
                action = sop_engine.submit_interactive_input(
                    &run_id,
                    reference_revision,
                    &request_fingerprint,
                    serde_json::Value::String(message),
                    Principal::shared_operator(),
                )?;
            }
            SopRunAction::DeterministicStep {
                run_id,
                step,
                input,
            } if step.number == 2 => {
                let message = input.as_str().ok_or_else(|| {
                    anyhow::Error::msg("Zerona SOP model step received non-string input")
                })?;
                let (turn_config, turn_source) = Box::pin(load_stable_config(&config_path)).await?;
                if !session_source_is_current(&session_source, &turn_source) {
                    sop_engine.cancel_run(&run_id)?;
                    eprintln!("{}", tr("cli-zerona-error-session-config-changed"));
                    return Ok(());
                }
                let turn = match session.turn(&turn_config, message).await {
                    Ok(turn) => turn,
                    Err(error) => {
                        let rendered = render_message(&error.fluent());
                        eprintln!("{rendered}");
                        action =
                            sop_engine.advance_step(&run_id, failed_sop_step(&step, rendered))?;
                        continue;
                    }
                };
                let visible = visible_assistant_text(&turn.assistant_text);
                if !visible.is_empty() {
                    println!("\n{}", safe_terminal(visible));
                }
                pending_apply = None;
                let turn_digest = sha256_hex(turn.assistant_text.as_bytes());
                let mut artifact_digest = String::new();
                let proposal_ready = if let Some(validated) = turn.proposal {
                    let (preview_config, expected_source) =
                        Box::pin(load_stable_config(&config_path)).await?;
                    if !session_source_is_current(&session_source, &expected_source) {
                        sop_engine.cancel_run(&run_id)?;
                        eprintln!("{}", tr("cli-zerona-error-session-config-changed"));
                        return Ok(());
                    }
                    let preview = match build_preview(
                        &preview_config,
                        &CurrentProviderFactory,
                        &selected_provider,
                        validated.proposal(),
                    ) {
                        Ok(preview) => preview.bind_expected_source(),
                        Err(error) => {
                            let rendered = render_message(&error.fluent());
                            eprintln!("{rendered}");
                            host_message = Some(host_drift_message());
                            action = sop_engine
                                .advance_step(&run_id, failed_sop_step(&step, rendered))?;
                            continue;
                        }
                    };
                    print_preview(&preview);
                    artifact_digest = sha256_hex(&serde_json::to_vec(validated.proposal())?);
                    pending_apply = Some(PendingApply {
                        validated,
                        config: preview_config,
                        expected_source,
                    });
                    true
                } else {
                    false
                };
                action = sop_engine.advance_deterministic_step(
                    &run_id,
                    serde_json::json!({
                        "proposal_ready": proposal_ready,
                        "turn_digest": turn_digest,
                        "artifact_digest": artifact_digest,
                    }),
                    None,
                )?;
            }
            SopRunAction::CheckpointWait { run_id, .. } => match read_review_verdict()? {
                ReviewVerdict::Cancel => {
                    sop_engine.cancel_run(&run_id)?;
                    println!("{}", tr("cli-zerona-cancelled"));
                    return Ok(());
                }
                ReviewVerdict::Revise => {
                    let feedback = loop {
                        let Some(feedback) = read_line(&tr("cli-zerona-revision-prompt"))? else {
                            let _ = sop_engine.resolve_via_broker(
                                &run_id,
                                ApprovalDecision::Deny {
                                    reason: Some("operator closed revision input".to_string()),
                                },
                                ApprovalPrincipal::cli(None),
                            )?;
                            println!("{}", tr("cli-zerona-cancelled"));
                            return Ok(());
                        };
                        if is_exit_alias(&feedback) {
                            let _ = sop_engine.resolve_via_broker(
                                &run_id,
                                ApprovalDecision::Deny {
                                    reason: Some("operator cancelled revision".to_string()),
                                },
                                ApprovalPrincipal::cli(None),
                            )?;
                            println!("{}", tr("cli-zerona-cancelled"));
                            return Ok(());
                        }
                        match validate_operator_input(&feedback) {
                            Ok(()) => break feedback,
                            Err(error) => eprintln!("{}", render_message(&error.fluent())),
                        }
                    };
                    pending_apply = None;
                    host_message = Some(host_revision_message(&feedback));
                    action = resumed_broker_action(sop_engine.resolve_via_broker(
                        &run_id,
                        ApprovalDecision::Deny {
                            reason: Some("revision_requested".to_string()),
                        },
                        ApprovalPrincipal::cli(None),
                    )?)?;
                }
                ReviewVerdict::Apply => {
                    action = resumed_broker_action(sop_engine.resolve_via_broker(
                        &run_id,
                        ApprovalDecision::Approve,
                        ApprovalPrincipal::cli(None),
                    )?)?;
                }
            },
            SopRunAction::DeterministicStep { run_id, step, .. } if step.number == 4 => {
                let Some(PendingApply {
                    validated,
                    mut config,
                    expected_source,
                }) = pending_apply.take()
                else {
                    anyhow::bail!("Zerona SOP reached apply without an approved proposal");
                };
                let approved =
                    match revalidate_proposal(&config, &CurrentProviderFactory, &validated) {
                        Ok(approved) => approved,
                        Err(error) => {
                            let rendered = render_message(&error.fluent());
                            eprintln!("{rendered}");
                            host_message = Some(host_drift_message());
                            action = sop_engine
                                .advance_step(&run_id, failed_sop_step(&step, rendered))?;
                            continue;
                        }
                    };
                let alias = approved.proposal().agent_alias.clone();
                let submission = approved.to_builder_submission();
                let preserved = PreservedApplyState::capture(&config)
                    .map_err(|_| anyhow::Error::msg(tr("cli-zerona-error-verification")))?;
                let apply_result =
                    Box::pin(apply_new_agent_strict_if_source_unchanged_per_agent_memory(
                        submission,
                        &mut config,
                        Surface::Cli,
                        &expected_source,
                    ))
                    .await;
                let reloaded = Box::pin(Config::load_or_init()).await?;
                match apply_result {
                    Ok(_) => {
                        verify_install(&reloaded, &approved, &alias, &preserved)
                            .map_err(|_| anyhow::Error::msg(tr("cli-zerona-error-verification")))?;
                        action = sop_engine.advance_deterministic_step(
                            &run_id,
                            serde_json::json!({"agent_alias": alias}),
                            None,
                        )?;
                        if !matches!(action, SopRunAction::Completed { .. }) {
                            anyhow::bail!("Zerona SOP did not complete after a verified apply");
                        }
                        println!(
                            "{}",
                            tra("cli-zerona-complete", &[("alias", alias.as_str())])
                        );
                        return Ok(());
                    }
                    Err(errors) => {
                        if reloaded.agents.contains_key(&alias) {
                            verify_install(&reloaded, &approved, &alias, &preserved).map_err(
                                |_| anyhow::Error::msg(tr("cli-zerona-error-verification")),
                            )?;
                            println!(
                                "{}",
                                tra("cli-zerona-complete", &[("alias", alias.as_str())])
                            );
                            return Ok(());
                        }
                        let ambiguous = errors
                            .iter()
                            .any(|error| error.field == "config_commit_ambiguous");
                        let mut rendered = Vec::new();
                        for error in errors {
                            let error = safe_terminal(&error.to_string());
                            eprintln!("{error}");
                            rendered.push(error);
                        }
                        if ambiguous {
                            anyhow::bail!(tr("cli-zerona-error-partial-apply"));
                        }
                        host_message = Some(host_drift_message());
                        action = sop_engine
                            .advance_step(&run_id, failed_sop_step(&step, rendered.join("; ")))?;
                    }
                }
            }
            SopRunAction::Completed { .. } => return Ok(()),
            SopRunAction::Failed { reason, .. } | SopRunAction::Pending { reason, .. } => {
                anyhow::bail!(reason)
            }
            SopRunAction::ExecuteStep { .. }
            | SopRunAction::WaitApproval { .. }
            | SopRunAction::DeterministicStep { .. } => {
                anyhow::bail!("Zerona SOP produced an unexpected action")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_aliases_are_local_and_case_insensitive() {
        for value in ["exit", "quit", "/exit", "/quit", " QUIT "] {
            assert!(is_exit_alias(value), "missed {value:?}");
        }
        assert!(!is_exit_alias("please quit after creating it"));
    }

    #[test]
    fn proposal_json_is_not_echoed_to_the_operator() {
        let reply = "I have a draft.\nPROPOSAL: {\"agent_alias\":\"writer\"}";
        assert_eq!(visible_assistant_text(reply), "I have a draft.");
    }

    #[test]
    fn review_verdicts_are_exact() {
        assert_eq!(parse_review_verdict("apply"), Some(ReviewVerdict::Apply));
        assert_eq!(parse_review_verdict("revise"), Some(ReviewVerdict::Revise));
        assert_eq!(parse_review_verdict("cancel"), Some(ReviewVerdict::Cancel));
        for rejected in ["yes", "approve", "APPLY", "apply now", " revise "] {
            assert_eq!(
                parse_review_verdict(rejected),
                None,
                "accepted {rejected:?}"
            );
        }
    }

    #[test]
    fn terminal_sanitizer_drops_controls_and_bidi() {
        assert_eq!(safe_terminal("safe\u{1b}[31m\u{202e}text"), "safe[31mtext");
    }

    #[test]
    fn session_source_binding_detects_any_config_change() {
        assert!(session_source_is_current(
            "schema_version = 3\n",
            "schema_version = 3\n"
        ));
        assert!(!session_source_is_current(
            "schema_version = 3\n",
            "schema_version = 3\n# external edit\n"
        ));
    }

    #[test]
    fn zerona_refuses_to_auto_migrate_an_older_source() {
        assert!(source_schema_is_current("schema_version = 3\n"));
        assert!(!source_schema_is_current("schema_version = 2\n"));
        assert!(!source_schema_is_current("[autonomy]\nlevel = 'full'\n"));
        assert!(!source_schema_is_current("not valid toml = [\n"));
    }

    #[test]
    fn post_apply_snapshot_allows_only_the_new_agent_in_preserved_sections() {
        let mut before = Config::default();
        before.agents.insert(
            "resident".into(),
            zeroclaw_config::schema::AliasedAgentConfig::default(),
        );
        let preserved = PreservedApplyState::capture(&before).unwrap();

        let mut after = before.clone();
        after.agents.insert(
            "new_agent".into(),
            zeroclaw_config::schema::AliasedAgentConfig::default(),
        );
        assert!(preserved.matches_after_add(&after, "new_agent").unwrap());

        after.memory.backend = "none".into();
        assert!(!preserved.matches_after_add(&after, "new_agent").unwrap());
    }

    #[test]
    fn builtin_sop_revision_returns_to_authenticated_input() {
        let mut engine = SopEngine::new(SopConfig::default());
        engine
            .register_builtin_sop(SystemSopId::ZERONA_CREATE_AGENT, builtin_zerona_sop())
            .unwrap();
        let first = engine
            .start_system_run(SystemSopId::ZERONA_CREATE_AGENT, zerona_manual_event())
            .unwrap();
        let (run_id, revision, fingerprint) = match first {
            SopRunAction::InteractiveInputWait {
                run_id,
                reference_revision,
                request_fingerprint,
                ..
            } => (run_id, reference_revision, request_fingerprint),
            other => panic!("expected initial input wait, got {other:?}"),
        };
        let model = engine
            .submit_interactive_input(
                &run_id,
                revision,
                &fingerprint,
                serde_json::json!("create a reviewer"),
                Principal::shared_operator(),
            )
            .unwrap();
        assert!(matches!(
            model,
            SopRunAction::DeterministicStep { ref step, .. } if step.number == 2
        ));
        let checkpoint = engine
            .advance_deterministic_step(
                &run_id,
                serde_json::json!({
                    "proposal_ready": true,
                    "turn_digest": "turn",
                    "artifact_digest": "proposal",
                }),
                None,
            )
            .unwrap();
        assert!(matches!(checkpoint, SopRunAction::CheckpointWait { .. }));
        let revised = resumed_broker_action(
            engine
                .resolve_via_broker(
                    &run_id,
                    ApprovalDecision::Deny {
                        reason: Some("revision_requested".to_string()),
                    },
                    ApprovalPrincipal::cli(None),
                )
                .unwrap(),
        )
        .unwrap();
        let (revision, fingerprint) = match revised {
            SopRunAction::InteractiveInputWait {
                reference_revision,
                request_fingerprint,
                ..
            } => (reference_revision, request_fingerprint),
            other => panic!("expected revised input wait, got {other:?}"),
        };
        let model = engine
            .submit_interactive_input(
                &run_id,
                revision,
                &fingerprint,
                serde_json::json!("make it terse"),
                Principal::shared_operator(),
            )
            .unwrap();
        assert!(matches!(
            model,
            SopRunAction::DeterministicStep { ref step, .. } if step.number == 2
        ));
    }
}
