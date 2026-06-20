//! Conversational `setup` — the intuitive path to a working agent.
//!
//! Ported in spirit from OpenClaw's `onboard --modern` setup, which detects
//! what's usable and asks for as little as possible. Instead of the full
//! quickstart checklist, this asks only the questions that have no sensible
//! default:
//!
//! * Already-usable install (a provider with a model exists) → ask only the
//!   **agent name**, bind a new agent to that provider.
//! * Fresh install → **pick provider → enter key** (skipped for local/keyless
//!   providers) → **pick model** (catalog default = newest/strongest, or
//!   free-text) → **agent name**.
//!
//! Everything else is defaulted: `balanced` risk, `sqlite` memory, no
//! channels, empty system prompt. The collected choices are landed through the
//! canonical [`apply_with_surface`] path — the same sanctioned write path the
//! quickstart wizard uses — after an explicit approval.

use std::collections::HashMap;
use std::io::IsTerminal;
use std::time::Duration;

use anyhow::Result;
use console::style;
use dialoguer::{Confirm, FuzzySelect, Input, Password};

use zeroclaw_config::presets::{
    AgentIdentity, BuilderSubmission, MemoryChoice, ModelProviderChoice, SelectorChoice,
};
use zeroclaw_config::schema::Config;
use zeroclaw_runtime::quickstart::{Surface, apply_with_surface, model_catalog};

use super::execute::Outcome;

/// Bound on the model-catalog lookup so a slow/offline fetch never stalls setup.
const CATALOG_TIMEOUT: Duration = Duration::from_secs(6);

/// Run the conversational setup flow. Self-gates on a TTY and asks for its own
/// approval before writing, so the caller invokes it directly (it is not a
/// generic approval-gated operation).
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
    let submission = if let Some((provider_ref, model)) = first_usable_provider(config) {
        println!(
            "{}",
            crate::ta(
                "cli-onboard-setup-existing",
                &[("provider", &provider_ref), ("model", &model)],
                "Using your configured provider {$provider} (model {$model}).",
            )
        );
        let Some(name) = prompt_agent_name(config)? else {
            return Ok(skipped());
        };
        if !confirm_plan(&name, &provider_ref, &model)? {
            return Ok(skipped());
        }
        build_submission(SelectorChoice::Existing(provider_ref), name)
    } else {
        let Some((provider_type, local)) = pick_provider()? else {
            return Ok(skipped());
        };
        let key = if local {
            None
        } else {
            prompt_key(&provider_type)?
        };
        // Aborting the key prompt (Ctrl+C) bails out of setup entirely.
        if !local && key.is_none() {
            return Ok(skipped());
        }
        let Some(model) = pick_model(&provider_type).await? else {
            return Ok(skipped());
        };
        let Some(name) = prompt_agent_name(config)? else {
            return Ok(skipped());
        };
        if !confirm_plan(&name, &provider_type, &model)? {
            return Ok(skipped());
        }
        let mut fields = HashMap::new();
        if let Some(k) = key.filter(|k| !k.trim().is_empty()) {
            // snake_case key — the apply path round-trips it verbatim into
            // set_prop_persistent, which rejects the kebab spelling.
            fields.insert("api_key".to_string(), k);
        }
        build_submission(
            SelectorChoice::Fresh(ModelProviderChoice {
                provider_type,
                alias: "default".to_string(),
                model,
                fields,
            }),
            name,
        )
    };

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

/// Agent-name prompt, validated as an alias. Defaults to `assistant` unless
/// that alias is taken. Returns `None` if aborted.
fn prompt_agent_name(config: &Config) -> Result<Option<String>> {
    let suggested = crate::t("cli-onboard-setup-name-default", "assistant");
    let mut input = Input::<String>::new()
        .with_prompt(crate::t("cli-onboard-setup-name-prompt", "Name your agent"))
        .allow_empty(false)
        .validate_with(|s: &String| zeroclaw_config::helpers::validate_alias_key(s));
    if !config.agents.contains_key(&suggested) {
        input = input.default(suggested);
    }
    match input.interact_text() {
        Ok(name) => Ok(Some(name)),
        Err(_) => Ok(None),
    }
}

/// Print the plan and ask for approval before any write.
fn confirm_plan(name: &str, provider: &str, model: &str) -> Result<bool> {
    let glyph = style("?").yellow().to_string();
    println!(
        "{}",
        crate::ta(
            "cli-onboard-setup-plan",
            &[
                ("glyph", &glyph),
                ("name", name),
                ("provider", provider),
                ("model", model)
            ],
            "{$glyph} Plan: create agent {$name} using {$provider}/{$model}.",
        )
    );
    Ok(Confirm::new()
        .with_prompt(crate::t("cli-onboard-apply-prompt", "Apply this change?"))
        .default(false)
        .interact()?)
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
