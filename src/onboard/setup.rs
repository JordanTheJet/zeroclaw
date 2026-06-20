//! Conversational `setup` — the intuitive path to a working agent.
//!
//! Ported in spirit from OpenClaw's `onboard --modern` setup. Instead of the
//! full quickstart checklist, it asks only the questions that have no sensible
//! default, then shows an **editable review** so nothing is a one-way march:
//!
//! * Already-usable install (a provider with a model exists) → ask the agent
//!   name, review, apply.
//! * Fresh install → pick provider (key prompt skipped for local/keyless) →
//!   API key → model (catalog default = newest, or free-text) → agent name →
//!   review (change any field) → apply.
//!
//! Every prompt is Esc-to-back-out, and nothing is written until you choose
//! *Apply* on the review screen. The collected choices are landed through the
//! canonical [`apply_with_surface`] path — the same sanctioned write path the
//! quickstart wizard uses.

use std::collections::HashMap;
use std::io::IsTerminal;
use std::time::Duration;

use anyhow::Result;
use console::style;
use dialoguer::{FuzzySelect, Input, Password, Select};

use zeroclaw_config::presets::{
    AgentIdentity, BuilderSubmission, MemoryChoice, ModelProviderChoice, SelectorChoice,
};
use zeroclaw_config::schema::Config;
use zeroclaw_runtime::quickstart::{Surface, apply_with_surface, model_catalog};

use super::execute::Outcome;

/// Bound on the model-catalog lookup so a slow/offline fetch never stalls setup.
const CATALOG_TIMEOUT: Duration = Duration::from_secs(6);

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

    // Branch on whether the install already has a provider that can run.
    let collected = if let Some((provider_ref, model)) = first_usable_provider(config) {
        println!(
            "{}",
            crate::ta(
                "cli-onboard-setup-existing",
                &[("provider", &provider_ref), ("model", &model)],
                "Using your configured provider {$provider} (model {$model}).",
            )
        );
        collect_existing(config, &provider_ref, &model)?
    } else {
        collect_fresh(config).await?
    };

    let Some((model_provider, name)) = collected else {
        return Ok(skipped());
    };
    let submission = build_submission(model_provider, name);

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

/// Fresh-install collection: pick everything, then loop on an editable review
/// until the user applies or cancels. Returns the provider choice + agent name.
async fn collect_fresh(
    config: &Config,
) -> Result<Option<(SelectorChoice<ModelProviderChoice>, String)>> {
    let Some((mut provider_type, mut local)) = pick_provider()? else {
        return Ok(None);
    };
    let mut key = if local {
        None
    } else {
        match prompt_key(&provider_type)? {
            Some(k) => Some(k),
            None => return Ok(None),
        }
    };
    let Some(mut model) = pick_model(&provider_type).await? else {
        return Ok(None);
    };
    let Some(mut name) = prompt_agent_name(config, None)? else {
        return Ok(None);
    };

    loop {
        print_review(&provider_type, local, key.as_deref(), &model, &name);
        match review_action(local)? {
            ReviewAction::Apply => {
                let mut fields = HashMap::new();
                if let Some(k) = key.as_ref().filter(|k| !k.trim().is_empty()) {
                    // snake_case key — the apply path round-trips it verbatim into
                    // set_prop_persistent, which rejects the kebab spelling.
                    fields.insert("api_key".to_string(), k.clone());
                }
                return Ok(Some((
                    SelectorChoice::Fresh(ModelProviderChoice {
                        provider_type: provider_type.clone(),
                        alias: "default".to_string(),
                        model: model.clone(),
                        fields,
                    }),
                    name.clone(),
                )));
            }
            ReviewAction::Cancel => return Ok(None),
            ReviewAction::Provider => {
                // Provider drives the key requirement and the model list, so
                // re-collect those when it changes.
                if let Some((pt, lo)) = pick_provider()? {
                    provider_type = pt;
                    local = lo;
                    key = if local {
                        None
                    } else {
                        prompt_key(&provider_type)?.or(key)
                    };
                    if let Some(m) = pick_model(&provider_type).await? {
                        model = m;
                    }
                }
            }
            ReviewAction::Key => {
                if let Some(k) = prompt_key(&provider_type)? {
                    key = Some(k);
                }
            }
            ReviewAction::Model => {
                if let Some(m) = pick_model(&provider_type).await? {
                    model = m;
                }
            }
            ReviewAction::Rename => {
                if let Some(n) = prompt_agent_name(config, Some(&name))? {
                    name = n;
                }
            }
        }
    }
}

/// Already-usable collection: bind a new agent to the existing provider. Only
/// the agent name is editable here.
fn collect_existing(
    config: &Config,
    provider_ref: &str,
    model: &str,
) -> Result<Option<(SelectorChoice<ModelProviderChoice>, String)>> {
    let Some(mut name) = prompt_agent_name(config, None)? else {
        return Ok(None);
    };
    loop {
        println!("{}", crate::t("cli-onboard-setup-review-header", "Review:"));
        review_line(
            "cli-onboard-setup-review-provider",
            "provider  {$v}",
            provider_ref,
        );
        review_line("cli-onboard-setup-review-model", "model     {$v}", model);
        review_line("cli-onboard-setup-review-agent", "agent     {$v}", &name);
        let labels = [
            crate::t("cli-onboard-setup-action-apply", "Apply — create the agent"),
            crate::t("cli-onboard-setup-action-rename", "Rename agent"),
            crate::t("cli-onboard-setup-action-cancel", "Cancel"),
        ];
        match Select::new()
            .with_prompt(crate::t("cli-onboard-setup-action-prompt", "What next?"))
            .items(&labels)
            .default(0)
            .interact_opt()?
        {
            Some(0) => {
                return Ok(Some((
                    SelectorChoice::Existing(provider_ref.to_string()),
                    name,
                )));
            }
            Some(1) => {
                if let Some(n) = prompt_agent_name(config, Some(&name))? {
                    name = n;
                }
            }
            _ => return Ok(None),
        }
    }
}

/// One review action chosen from the menu.
enum ReviewAction {
    Apply,
    Provider,
    Key,
    Model,
    Rename,
    Cancel,
}

/// Render the editable summary for the fresh flow.
fn print_review(provider: &str, local: bool, key: Option<&str>, model: &str, name: &str) {
    println!("{}", crate::t("cli-onboard-setup-review-header", "Review:"));
    review_line(
        "cli-onboard-setup-review-provider",
        "provider  {$v}",
        provider,
    );
    if !local {
        let status = if key.is_some_and(|k| !k.trim().is_empty()) {
            crate::t("cli-onboard-setup-key-set", "(set)")
        } else {
            crate::t("cli-onboard-setup-key-unset", "(not set)")
        };
        review_line("cli-onboard-setup-review-key", "key       {$v}", &status);
    }
    review_line("cli-onboard-setup-review-model", "model     {$v}", model);
    review_line("cli-onboard-setup-review-agent", "agent     {$v}", name);
}

/// Print one indented `label  value` review row.
fn review_line(key: &str, fallback: &str, value: &str) {
    println!("  {}", crate::ta(key, &[("v", value)], fallback));
}

/// The review menu for the fresh flow. Esc → [`ReviewAction::Cancel`].
fn review_action(local: bool) -> Result<ReviewAction> {
    let mut actions = vec![ReviewAction::Apply];
    let mut labels = vec![crate::t(
        "cli-onboard-setup-action-apply",
        "Apply — create the agent",
    )];
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
    actions.push(ReviewAction::Rename);
    labels.push(crate::t("cli-onboard-setup-action-rename", "Rename agent"));
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

/// Whether a provider family runs locally (no API key needed), per the
/// canonical provider registry.
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

/// Masked API-key prompt. Returns `None` only when the user aborts (Ctrl+C);
/// an empty entry is `Some("")` so a remote provider can still be created and
/// the key supplied later.
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
        // dialoguer maps Ctrl+C to an IO/Interrupted error — treat as "backed out".
        Err(_) => Ok(None),
    }
}

/// Model picker. Offers the provider's catalog (default = newest/strongest via
/// the chat-rank sort); falls back to free-text when no catalog is available.
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

/// Build a minimal one-agent submission. Risk `balanced`, sqlite memory, no
/// channels; `runtime_profile` is force-defaulted to `unbounded` by apply.
fn build_submission(
    model_provider: SelectorChoice<ModelProviderChoice>,
    name: String,
) -> BuilderSubmission {
    BuilderSubmission {
        model_provider,
        risk_profile: SelectorChoice::Fresh("balanced".to_string()),
        runtime_profile: SelectorChoice::Fresh("unbounded".to_string()),
        memory: SelectorChoice::Fresh(MemoryChoice::Sqlite),
        channels: vec![],
        peer_groups: vec![],
        agent: AgentIdentity {
            name,
            system_prompt: String::new(),
            personality_file: None,
            personality_files: vec![],
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
