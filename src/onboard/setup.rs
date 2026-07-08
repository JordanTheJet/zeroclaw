//! Minimal `setup` — get a working model, then hand off to the setup assistant.
//!
//! Setup asks only what has no sensible default: pick a provider, enter the key
//! (skipped for local/keyless), pick a model. Everything else — the agent's
//! name, personality, autonomy — is handled conversationally by the
//! [`super::setup_assistant`], which setup launches once a model is configured.
//!
//! Fresh-install choices land on an editable review screen; nothing is written
//! until you choose *Apply*, and every prompt is Esc-to-back-out.

use std::io::IsTerminal;
use std::time::Duration;

use anyhow::Result;
use dialoguer::{FuzzySelect, Input, Password, Select};

use zeroclaw_config::presets::{ModelProviderChoice, SelectorChoice};
use zeroclaw_config::schema::Config;
use zeroclaw_runtime::quickstart::model_catalog;

use super::execute::Outcome;
use std::collections::HashMap;

/// Bound on the model-catalog lookup so a slow/offline fetch never stalls setup.
const CATALOG_TIMEOUT: Duration = Duration::from_secs(6);

/// Run minimal setup, then launch the setup assistant.
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

    // Reuse an already-usable provider if there is one; otherwise collect one.
    let model_provider = if let Some((reference, model)) = first_usable_provider(config) {
        println!(
            "{}",
            crate::ta(
                "cli-onboard-setup-existing",
                &[("provider", &reference), ("model", &model)],
                "Using your configured provider {$provider} (model {$model}).",
            )
        );
        SelectorChoice::Existing(reference)
    } else {
        match collect_fresh().await? {
            Some(mp) => mp,
            None => return Ok(skipped()),
        }
    };

    super::setup_assistant::run(config, model_provider).await
}

/// Fresh-install collection: pick provider → key → model, then loop on an
/// editable review until apply or cancel.
async fn collect_fresh() -> Result<Option<SelectorChoice<ModelProviderChoice>>> {
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

    loop {
        print_review(&provider_type, local, key.as_deref(), &model);
        match review_action(local)? {
            ReviewAction::Apply => {
                let mut fields = HashMap::new();
                if let Some(k) = key.as_ref().filter(|k| !k.trim().is_empty()) {
                    fields.insert("api_key".to_string(), k.clone());
                }
                return Ok(Some(SelectorChoice::Fresh(ModelProviderChoice {
                    provider_type,
                    alias: "default".to_string(),
                    model,
                    fields,
                })));
            }
            ReviewAction::Cancel => return Ok(None),
            ReviewAction::Provider => {
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
        }
    }
}

/// One review action chosen from the menu.
enum ReviewAction {
    Apply,
    Provider,
    Key,
    Model,
    Cancel,
}

/// Render the editable summary.
fn print_review(provider: &str, local: bool, key: Option<&str>, model: &str) {
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
}

/// Print one indented `label  value` review row.
fn review_line(key: &str, fallback: &str, value: &str) {
    println!("  {}", crate::ta(key, &[("v", value)], fallback));
}

/// The review menu. Esc → [`ReviewAction::Cancel`].
fn review_action(local: bool) -> Result<ReviewAction> {
    let mut actions = vec![ReviewAction::Apply];
    let mut labels = vec![crate::t(
        "cli-onboard-setup-action-apply",
        "Apply — start the agent builder",
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

/// First configured provider that could run (has a model and either a key or is
/// a local/keyless family), as `("<family>.<alias>", model)`.
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

fn plain() -> Outcome {
    Outcome {
        applied: false,
        exit_loop: false,
    }
}

fn skipped() -> Outcome {
    println!("{}", crate::t("cli-onboard-skipped", "Skipped."));
    plain()
}
