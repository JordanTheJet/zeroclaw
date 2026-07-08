//! LLM planner: map a free-form request to one allowed command.
//!
//! Reached only when the deterministic parser fails. The model is given the
//! overview as grounding and constrained — by prompt and by narrow JSON
//! parsing — to emit exactly one command from the onboarding vocabulary.
//! The returned command is *not* trusted: the caller re-parses it through
//! [`super::operation::parse`], so a hallucinated or unsafe string simply
//! resolves to nothing and the user sees the deterministic fallback hint.

use std::time::Duration;

use zeroclaw_config::schema::Config;
use zeroclaw_providers::ProviderDispatch;

use super::overview::Overview;

/// A planner result: a command string (re-validated by the caller) plus an
/// optional human reply and the model label used.
pub struct Plan {
    pub command: String,
    pub reply: Option<String>,
    pub model_label: String,
}

/// One planner call is bounded so a slow/hung model never stalls the loop.
const PLANNER_TIMEOUT: Duration = Duration::from_secs(12);

const SYSTEM_PROMPT: &str = "\
You are ZeroClaw's setup assistant.
Turn the user's request into exactly one safe ZeroClaw command.
Return ONLY compact JSON with keys \"reply\" and \"command\".
Do not invent commands. Do not claim a change was applied.
Plan only from the supplied overview; do not use tools, shell, file edits, or network lookups.
Allowed commands:
- overview
- status
- doctor
- models
- agents
- gateway status
- start gateway
- stop gateway
- restart gateway
- validate config
- setup
- set default model <family>/<model-id>
- config set <path> <value>
- talk to agent
- help
If unsure, choose overview.";

/// Plan a command for `input`, or `None` if no model is available, the call
/// fails/times out, or the response can't be parsed.
pub async fn plan(config: &Config, input: &str, overview: &Overview) -> Option<Plan> {
    let input = input.trim();
    if input.is_empty() {
        return None;
    }
    let (provider, model, label) = pick_model(config)?;
    let user_prompt = build_user_prompt(input, overview);

    let dispatch = ProviderDispatch::from_ref(&*provider);
    let call = dispatch.chat_with_system(Some(SYSTEM_PROMPT), &user_prompt, &model, Some(0.0));
    let text = tokio::time::timeout(PLANNER_TIMEOUT, call)
        .await
        .ok()?
        .ok()?;

    let (command, reply) = parse_plan_json(&text)?;
    Some(Plan {
        command,
        reply,
        model_label: label,
    })
}

/// Pick the first configured provider that has both a model and a configured
/// key, and build a (non-resilient) provider instance for one planning call.
///
/// We gate on a non-empty `entry.api_key` — the same canonical signal the
/// overview reports — so we never make a doomed API call on an unconfigured
/// entry. Keyless-only installs simply leave the planner unavailable and fall
/// back to deterministic parsing, which is fine for a best-effort helper.
fn pick_model(
    config: &Config,
) -> Option<(
    Box<dyn zeroclaw_api::model_provider::ModelProvider>,
    String,
    String,
)> {
    let options = zeroclaw_providers::ModelProviderRuntimeOptions::default();
    for (family, alias, entry) in config.providers.models.iter_entries() {
        let Some(model) = entry
            .model
            .as_deref()
            .map(str::trim)
            .filter(|m| !m.is_empty())
        else {
            continue;
        };
        let Some(key) = entry
            .api_key
            .as_deref()
            .map(str::trim)
            .filter(|k| !k.is_empty())
        else {
            continue;
        };
        // Alias-aware factory: honors the configured alias and endpoint rather
        // than the legacy alias="default" path.
        if let Ok(provider) = zeroclaw_providers::create_model_provider_for_alias(
            config,
            family,
            alias,
            Some(key),
            &options,
        ) {
            let label = format!("{family}.{alias}/{model}");
            return Some((provider, model.to_string(), label));
        }
    }
    None
}

fn build_user_prompt(input: &str, overview: &Overview) -> String {
    let agents = if overview.agents.is_empty() {
        "  - none".to_string()
    } else {
        overview
            .agents
            .iter()
            .map(|a| {
                format!(
                    "  - {} (provider={}{})",
                    a.alias,
                    a.model_provider,
                    a.model
                        .as_deref()
                        .map(|m| format!(", model={m}"))
                        .unwrap_or_default()
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    };
    format!(
        "User request: {input}\n\n\
         Config present: {}\n\
         Default model: {}\n\
         Gateway reachable: {}\n\
         Service running: {}\n\
         Configured: {}\n\
         Agents:\n{agents}",
        overview.config_exists,
        overview
            .default_model
            .as_deref()
            .unwrap_or("not configured"),
        overview.gateway_reachable,
        overview.service_running,
        overview.configured(),
    )
}

/// Extract `{ "command": ..., "reply": ... }` from possibly-noisy model text.
/// Requires a non-empty `command` string; `reply` is optional.
fn parse_plan_json(text: &str) -> Option<(String, Option<String>)> {
    let start = text.find('{')?;
    let end = text.rfind('}')?;
    if end <= start {
        return None;
    }
    let value: serde_json::Value = serde_json::from_str(&text[start..=end]).ok()?;
    let command = value.get("command")?.as_str()?.trim().to_string();
    if command.is_empty() {
        return None;
    }
    let reply = value
        .get("reply")
        .and_then(|r| r.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string);
    Some((command, reply))
}
