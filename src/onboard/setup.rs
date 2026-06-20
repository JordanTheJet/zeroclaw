//! Conversational `setup` — the intuitive path to a working agent.
//!
//! Ported in spirit from OpenClaw's `onboard --modern` setup. It asks the
//! questions that have no sensible default, gathers a little identity so the
//! new agent feels personal, then shows an **editable review** before writing:
//!
//! * Fresh install → pick provider (key prompt skipped for local/keyless) →
//!   API key → model (catalog default = newest, or free-text).
//! * Either way → name the agent, your name, a communication style, and an
//!   autonomy (risk) level → review (change any field) → apply.
//!
//! The identity answers seed the agent's personality markdown (SOUL/IDENTITY/
//! USER/…) via the default template. Every prompt is Esc-to-back-out, and
//! nothing is written until you choose *Apply*. Choices land through the
//! canonical [`apply_with_surface`] path.

use std::collections::HashMap;
use std::io::IsTerminal;
use std::time::Duration;

use anyhow::Result;
use console::style;
use dialoguer::{FuzzySelect, Input, Password, Select};

use zeroclaw_config::presets::{
    AgentIdentity, BuilderSubmission, MemoryChoice, ModelProviderChoice, QuickstartPersonalityFile,
    SelectorChoice,
};
use zeroclaw_config::schema::Config;
use zeroclaw_runtime::agent::personality_templates::{TemplateContext, render_preset_default};
use zeroclaw_runtime::quickstart::{Surface, apply_with_surface, model_catalog};

use super::execute::Outcome;

/// Bound on the model-catalog lookup so a slow/offline fetch never stalls setup.
const CATALOG_TIMEOUT: Duration = Duration::from_secs(6);

/// Communication styles offered in setup: `(label key, label fallback, the
/// style text written into the agent's personality files)`.
const COMM_STYLES: &[(&str, &str, &str)] = &[
    (
        "cli-onboard-style-warm",
        "Warm & friendly",
        "Be warm, natural, and clear. Use occasional relevant emojis (1-2 max) and avoid robotic phrasing.",
    ),
    (
        "cli-onboard-style-concise",
        "Concise & direct",
        "Be concise and direct. Lead with the answer; skip pleasantries and filler.",
    ),
    (
        "cli-onboard-style-formal",
        "Formal & precise",
        "Be formal, precise, and professional. Avoid slang and emojis.",
    ),
    (
        "cli-onboard-style-playful",
        "Playful & witty",
        "Be playful and a little witty, while staying genuinely helpful and clear.",
    ),
];

/// Autonomy levels offered in setup: `(label key, label fallback, risk preset)`.
const RISK_CHOICES: &[(&str, &str, &str)] = &[
    (
        "cli-onboard-risk-balanced",
        "Balanced — supervised, stays in its workspace (recommended)",
        "balanced",
    ),
    (
        "cli-onboard-risk-locked",
        "Locked down — most restrictive",
        "locked_down",
    ),
    (
        "cli-onboard-risk-open",
        "Open — full autonomy, can leave the workspace (advanced)",
        "yolo",
    ),
];

/// Where the agent's model comes from.
enum ProviderSource {
    /// A freshly-chosen provider: type, local/keyless, key, model.
    Fresh {
        provider_type: String,
        local: bool,
        key: Option<String>,
        model: String,
    },
    /// An already-configured provider, referenced by `<family>.<alias>`.
    Existing { reference: String, model: String },
}

/// Everything setup collects, all editable on the review screen.
struct Draft {
    provider: ProviderSource,
    agent_name: String,
    user_name: String,
    comm_style: usize,
    risk: usize,
}

/// Run the conversational setup flow. Self-gates on a TTY and asks for its own
/// approval (via the review screen) before writing.
pub async fn run(config: &mut Config) -> Result<Outcome> {
    if !std::io::stdin().is_terminal() || !std::io::stderr().is_terminal() {
        println!(
            "{}",
            crate::t(
                "cli-onboard-setup-needs-tty",
                "Setup is interactive — run `zeroclaw onboard` in a terminal (or `zeroclaw quickstart`).",
            )
        );
        return Ok(plain());
    }

    let Some(draft) = collect(config).await? else {
        return Ok(skipped());
    };
    let submission = build_submission(&draft);

    match Box::pin(apply_with_surface(submission, config, Surface::Cli)).await {
        Ok(applied) => {
            let glyph = style("✓").green().to_string();
            println!(
                "{}",
                crate::ta(
                    "cli-onboard-setup-done",
                    &[("glyph", &glyph), ("name", &applied.alias)],
                    "{$glyph} Created agent {$name}. Run `talk to agent` to start it.",
                )
            );
            Ok(applied_outcome())
        }
        Err(errors) => {
            let glyph = style("✗").red().to_string();
            println!(
                "{}",
                crate::ta(
                    "cli-onboard-setup-failed",
                    &[("glyph", &glyph)],
                    "{$glyph} Setup could not finish:",
                )
            );
            for err in &errors {
                println!("  - {err}");
            }
            Ok(plain())
        }
    }
}

/// Collect all fields (initial pass), then loop on an editable review until the
/// user applies or cancels.
async fn collect(config: &Config) -> Result<Option<Draft>> {
    // Provider: reuse an already-usable one, else pick fresh.
    let provider = if let Some((reference, model)) = first_usable_provider(config) {
        println!(
            "{}",
            crate::ta(
                "cli-onboard-setup-existing",
                &[("provider", &reference), ("model", &model)],
                "Using your configured provider {$provider} (model {$model}).",
            )
        );
        ProviderSource::Existing { reference, model }
    } else {
        let Some(p) = pick_fresh_provider().await? else {
            return Ok(None);
        };
        p
    };

    // Identity: agent name, your name, style. Defaults let you Enter through.
    let Some(agent_name) = prompt_agent_name(config, None)? else {
        return Ok(None);
    };
    let Some(user_name) = prompt_user_name()? else {
        return Ok(None);
    };
    let Some(comm_style) = pick_choice(
        "cli-onboard-setup-style-prompt",
        "How should it talk to you?",
        COMM_STYLES,
        0,
    )?
    else {
        return Ok(None);
    };

    let mut draft = Draft {
        provider,
        agent_name,
        user_name,
        comm_style,
        risk: 0,
    };

    loop {
        print_review(&draft);
        match review_action(&draft)? {
            ReviewAction::Apply => return Ok(Some(draft)),
            ReviewAction::Cancel => return Ok(None),
            ReviewAction::Provider => {
                if let Some(p) = pick_fresh_provider().await? {
                    draft.provider = p;
                }
            }
            ReviewAction::Key => {
                if let ProviderSource::Fresh {
                    provider_type, key, ..
                } = &mut draft.provider
                {
                    if let Some(k) = prompt_key(provider_type)? {
                        *key = Some(k);
                    }
                }
            }
            ReviewAction::Model => {
                if let ProviderSource::Fresh {
                    provider_type,
                    model,
                    ..
                } = &mut draft.provider
                {
                    if let Some(m) = pick_model(provider_type).await? {
                        *model = m;
                    }
                }
            }
            ReviewAction::Rename => {
                if let Some(n) = prompt_agent_name(config, Some(&draft.agent_name))? {
                    draft.agent_name = n;
                }
            }
            ReviewAction::UserName => {
                if let Some(n) = prompt_user_name()? {
                    draft.user_name = n;
                }
            }
            ReviewAction::Style => {
                if let Some(i) = pick_choice(
                    "cli-onboard-setup-style-prompt",
                    "How should it talk to you?",
                    COMM_STYLES,
                    draft.comm_style,
                )? {
                    draft.comm_style = i;
                }
            }
            ReviewAction::Risk => {
                if let Some(i) = pick_choice(
                    "cli-onboard-setup-risk-prompt",
                    "How much autonomy should it have?",
                    RISK_CHOICES,
                    draft.risk,
                )? {
                    draft.risk = i;
                }
            }
        }
    }
}

/// Pick a fresh provider and collect its key (if remote) and model.
async fn pick_fresh_provider() -> Result<Option<ProviderSource>> {
    let Some((provider_type, local)) = pick_provider()? else {
        return Ok(None);
    };
    let key = if local {
        None
    } else {
        match prompt_key(&provider_type)? {
            Some(k) => Some(k),
            None => return Ok(None),
        }
    };
    let Some(model) = pick_model(&provider_type).await? else {
        return Ok(None);
    };
    Ok(Some(ProviderSource::Fresh {
        provider_type,
        local,
        key,
        model,
    }))
}

/// One review action chosen from the menu.
enum ReviewAction {
    Apply,
    Provider,
    Key,
    Model,
    Rename,
    UserName,
    Style,
    Risk,
    Cancel,
}

/// Render the editable summary.
fn print_review(draft: &Draft) {
    println!("{}", crate::t("cli-onboard-setup-review-header", "Review:"));
    match &draft.provider {
        ProviderSource::Fresh {
            provider_type,
            local,
            key,
            model,
        } => {
            review_line(
                "cli-onboard-setup-review-provider",
                "provider  {$v}",
                provider_type,
            );
            if !local {
                let status = if key.as_deref().is_some_and(|k| !k.trim().is_empty()) {
                    crate::t("cli-onboard-setup-key-set", "(set)")
                } else {
                    crate::t("cli-onboard-setup-key-unset", "(not set)")
                };
                review_line("cli-onboard-setup-review-key", "key       {$v}", &status);
            }
            review_line("cli-onboard-setup-review-model", "model     {$v}", model);
        }
        ProviderSource::Existing { reference, model } => {
            review_line(
                "cli-onboard-setup-review-provider",
                "provider  {$v}",
                reference,
            );
            review_line("cli-onboard-setup-review-model", "model     {$v}", model);
        }
    }
    review_line(
        "cli-onboard-setup-review-agent",
        "agent     {$v}",
        &draft.agent_name,
    );
    review_line(
        "cli-onboard-setup-review-you",
        "you       {$v}",
        &draft.user_name,
    );
    review_line(
        "cli-onboard-setup-review-style",
        "style     {$v}",
        &crate::t(
            COMM_STYLES[draft.comm_style].0,
            COMM_STYLES[draft.comm_style].1,
        ),
    );
    review_line(
        "cli-onboard-setup-review-risk",
        "autonomy  {$v}",
        &crate::t(RISK_CHOICES[draft.risk].0, RISK_CHOICES[draft.risk].1),
    );
}

/// Print one indented `label  value` review row.
fn review_line(key: &str, fallback: &str, value: &str) {
    println!("  {}", crate::ta(key, &[("v", value)], fallback));
}

/// The review menu. Esc → [`ReviewAction::Cancel`].
fn review_action(draft: &Draft) -> Result<ReviewAction> {
    let mut actions = vec![ReviewAction::Apply];
    let mut labels = vec![crate::t(
        "cli-onboard-setup-action-apply",
        "Apply — create the agent",
    )];
    if let ProviderSource::Fresh { local, .. } = &draft.provider {
        actions.push(ReviewAction::Provider);
        labels.push(crate::t(
            "cli-onboard-setup-action-provider",
            "Change provider",
        ));
        if !local {
            actions.push(ReviewAction::Key);
            labels.push(crate::t("cli-onboard-setup-action-key", "Change API key"));
        }
        actions.push(ReviewAction::Model);
        labels.push(crate::t("cli-onboard-setup-action-model", "Change model"));
    }
    actions.push(ReviewAction::Rename);
    labels.push(crate::t("cli-onboard-setup-action-rename", "Rename agent"));
    actions.push(ReviewAction::UserName);
    labels.push(crate::t(
        "cli-onboard-setup-action-username",
        "Change your name",
    ));
    actions.push(ReviewAction::Style);
    labels.push(crate::t("cli-onboard-setup-action-style", "Change style"));
    actions.push(ReviewAction::Risk);
    labels.push(crate::t("cli-onboard-setup-action-risk", "Change autonomy"));
    actions.push(ReviewAction::Cancel);
    labels.push(crate::t("cli-onboard-setup-action-cancel", "Cancel"));

    let pick = Select::new()
        .with_prompt(crate::t("cli-onboard-setup-action-prompt", "What next?"))
        .items(&labels)
        .default(0)
        .interact_opt()?;
    Ok(match pick {
        Some(i) => actions.into_iter().nth(i).unwrap_or(ReviewAction::Cancel),
        None => ReviewAction::Cancel,
    })
}

/// First configured provider that could actually run (has a model and either a
/// key or is a local/keyless family), as `("<family>.<alias>", model)`.
fn first_usable_provider(config: &Config) -> Option<(String, String)> {
    config
        .providers
        .models
        .iter_entries()
        .find_map(|(family, alias, entry)| {
            let model = entry
                .model
                .as_deref()
                .map(str::trim)
                .filter(|m| !m.is_empty())?;
            let has_key = entry
                .api_key
                .as_deref()
                .map(|k| !k.trim().is_empty())
                .unwrap_or(false);
            if has_key || is_local_family(family) {
                Some((format!("{family}.{alias}"), model.to_string()))
            } else {
                None
            }
        })
}

/// Whether a provider family runs locally (no API key needed).
fn is_local_family(family: &str) -> bool {
    zeroclaw_providers::list_model_providers()
        .iter()
        .find(|p| p.name == family)
        .is_some_and(|p| p.local)
}

/// Provider picker. Returns `(canonical_name, is_local)`, or `None` if aborted.
fn pick_provider() -> Result<Option<(String, bool)>> {
    let providers = zeroclaw_providers::list_model_providers();
    let labels: Vec<String> = providers
        .iter()
        .map(|p| {
            if p.local {
                crate::ta(
                    "cli-onboard-setup-provider-local",
                    &[("name", p.display_name)],
                    "{$name} (local — no key)",
                )
            } else {
                p.display_name.to_string()
            }
        })
        .collect();
    let Some(i) = FuzzySelect::new()
        .with_prompt(crate::t(
            "cli-onboard-setup-provider-prompt",
            "Choose a model provider",
        ))
        .items(&labels)
        .default(0)
        .max_length(12)
        .interact_opt()?
    else {
        return Ok(None);
    };
    Ok(Some((providers[i].name.to_string(), providers[i].local)))
}

/// Masked API-key prompt. `None` only on abort; empty entry is `Some("")`.
fn prompt_key(provider: &str) -> Result<Option<String>> {
    match Password::new()
        .with_prompt(crate::ta(
            "cli-onboard-setup-key-prompt",
            &[("provider", provider)],
            "API key for {$provider}",
        ))
        .allow_empty_password(true)
        .interact()
    {
        Ok(key) => Ok(Some(key)),
        Err(_) => Ok(None),
    }
}

/// Model picker. Offers the provider's catalog (default = newest via the
/// chat-rank sort); falls back to free-text when no catalog is available.
async fn pick_model(provider: &str) -> Result<Option<String>> {
    let ids = match tokio::time::timeout(CATALOG_TIMEOUT, model_catalog(provider)).await {
        Ok((ids, _, _)) => {
            zeroclaw_providers::catalog::sort_model_catalog_for_chat(provider, ids.clone())
                .unwrap_or(ids)
        }
        Err(_) => Vec::new(),
    };

    if ids.is_empty() {
        let model: String = Input::new()
            .with_prompt(crate::t("cli-onboard-setup-model-input", "Model id"))
            .allow_empty(false)
            .interact_text()?;
        return Ok(Some(model));
    }

    let Some(i) = FuzzySelect::new()
        .with_prompt(crate::t("cli-onboard-setup-model-prompt", "Choose a model"))
        .items(&ids)
        .default(0)
        .max_length(12)
        .interact_opt()?
    else {
        return Ok(None);
    };
    Ok(Some(ids[i].clone()))
}

/// Agent-name prompt, validated as an alias. Defaults to `current` when editing,
/// else `assistant` (unless taken). Returns `None` if aborted.
fn prompt_agent_name(config: &Config, current: Option<&str>) -> Result<Option<String>> {
    let default = match current {
        Some(name) => name.to_string(),
        None => crate::t("cli-onboard-setup-name-default", "assistant"),
    };
    let mut input = Input::<String>::new()
        .with_prompt(crate::t("cli-onboard-setup-name-prompt", "Name your agent"))
        .allow_empty(false)
        .validate_with(|s: &String| zeroclaw_config::helpers::validate_alias_key(s));
    if !default.is_empty() && (current.is_some() || !config.agents.contains_key(&default)) {
        input = input.default(default);
    }
    match input.interact_text() {
        Ok(name) => Ok(Some(name)),
        Err(_) => Ok(None),
    }
}

/// "What's your name?" — defaults to `$USER`. Returns `None` if aborted.
fn prompt_user_name() -> Result<Option<String>> {
    let default = std::env::var("USER")
        .ok()
        .filter(|u| !u.trim().is_empty())
        .unwrap_or_else(|| "friend".to_string());
    match Input::<String>::new()
        .with_prompt(crate::t(
            "cli-onboard-setup-username-prompt",
            "What's your name?",
        ))
        .default(default)
        .allow_empty(false)
        .interact_text()
    {
        Ok(name) => Ok(Some(name)),
        Err(_) => Ok(None),
    }
}

/// Pick one labelled choice from `(label_key, label_fallback, _)` rows; returns
/// the chosen index, or `None` if aborted.
fn pick_choice(
    prompt_key: &str,
    prompt_fallback: &str,
    choices: &[(&str, &str, &str)],
    default: usize,
) -> Result<Option<usize>> {
    let labels: Vec<String> = choices
        .iter()
        .map(|(key, fallback, _)| crate::t(key, fallback))
        .collect();
    Ok(Select::new()
        .with_prompt(crate::t(prompt_key, prompt_fallback))
        .items(&labels)
        .default(default.min(labels.len().saturating_sub(1)))
        .interact_opt()?)
}

/// Build the submission from the collected draft, seeding personality files
/// from the identity answers via the default template.
fn build_submission(draft: &Draft) -> BuilderSubmission {
    let model_provider = match &draft.provider {
        ProviderSource::Fresh {
            provider_type,
            key,
            model,
            ..
        } => {
            let mut fields = HashMap::new();
            if let Some(k) = key.as_ref().filter(|k| !k.trim().is_empty()) {
                fields.insert("api_key".to_string(), k.clone());
            }
            SelectorChoice::Fresh(ModelProviderChoice {
                provider_type: provider_type.clone(),
                alias: "default".to_string(),
                model: model.clone(),
                fields,
            })
        }
        ProviderSource::Existing { reference, .. } => SelectorChoice::Existing(reference.clone()),
    };

    let ctx = TemplateContext {
        agent: draft.agent_name.clone(),
        user: draft.user_name.clone(),
        timezone: std::env::var("TZ").unwrap_or_else(|_| "UTC".to_string()),
        communication_style: COMM_STYLES[draft.comm_style].2.to_string(),
        include_memory: true,
    };
    let personality_files = render_preset_default(&ctx)
        .into_iter()
        .map(|(filename, content)| QuickstartPersonalityFile {
            filename: filename.to_string(),
            content,
        })
        .collect();

    BuilderSubmission {
        model_provider,
        risk_profile: SelectorChoice::Fresh(RISK_CHOICES[draft.risk].2.to_string()),
        runtime_profile: SelectorChoice::Fresh("unbounded".to_string()),
        memory: SelectorChoice::Fresh(MemoryChoice::Sqlite),
        channels: vec![],
        peer_groups: vec![],
        agent: AgentIdentity {
            name: draft.agent_name.clone(),
            system_prompt: String::new(),
            personality_file: None,
            personality_files,
        },
    }
}

fn plain() -> Outcome {
    Outcome {
        applied: false,
        exit_loop: false,
    }
}

fn applied_outcome() -> Outcome {
    Outcome {
        applied: true,
        exit_loop: false,
    }
}

fn skipped() -> Outcome {
    println!("{}", crate::t("cli-onboard-skipped", "Skipped."));
    plain()
}
