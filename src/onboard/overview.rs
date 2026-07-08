//! System-state snapshot that grounds the onboarding assistant.
//!
//! The overview is the assistant's only source of truth about the live
//! install: it is rendered for the user, fed to the LLM planner as
//! grounding, and consulted by the executor for "next step" hints. Every
//! field is resolved from [`Config`] (and a single best-effort gateway
//! health probe) on demand — nothing here is cached state, so it can never
//! drift from the canonical config.

use std::time::Duration;

use serde::Serialize;

use zeroclaw_config::schema::Config;

/// One configured agent, summarized for display + planner grounding.
#[derive(Debug, Clone, Serialize)]
pub struct AgentSummary {
    pub alias: String,
    pub model_provider: String,
    pub model: Option<String>,
    pub enabled: bool,
}

/// One configured model-provider entry and whether it has a usable key.
#[derive(Debug, Clone, Serialize)]
pub struct ProviderSummary {
    pub family: String,
    pub alias: String,
    pub model: Option<String>,
    /// A key is present either in config (`api_key`) or via the family's
    /// conventional environment variable.
    pub has_key: bool,
}

/// Resolved-on-demand snapshot of the current ZeroClaw install.
#[derive(Debug, Clone, Serialize)]
pub struct Overview {
    pub config_path: String,
    pub config_exists: bool,
    /// First non-empty model across all providers (ZeroClaw's notion of a
    /// "default" model — there is no global default-agent concept).
    pub default_model: Option<String>,
    pub agents: Vec<AgentSummary>,
    pub providers: Vec<ProviderSummary>,
    pub gateway_url: String,
    pub gateway_reachable: bool,
    pub service_running: bool,
    /// Config-category diagnostics with `error` severity, if any.
    pub config_issues: Vec<String>,
}

impl Overview {
    /// Resolve the full snapshot. Performs one bounded gateway health
    /// probe; everything else is in-memory config resolution.
    pub async fn build(config: &Config) -> Self {
        let mut providers: Vec<ProviderSummary> = config
            .providers
            .models
            .iter_entries()
            .map(|(family, alias, entry)| {
                let model = entry
                    .model
                    .as_deref()
                    .map(str::trim)
                    .filter(|m| !m.is_empty())
                    .map(ToString::to_string);
                // Canonical "has a key" signal: the config field itself, the
                // same one doctor's `configured_model_provider_api_key` reads.
                // The runtime resolves credentials from `entry.api_key` (env
                // keys are folded in at config load via the ZEROCLAW_<path>
                // grammar), so probing legacy provider env vars here would
                // disagree with what the agent can actually use.
                let has_key = entry
                    .api_key
                    .as_deref()
                    .map(|k| !k.trim().is_empty())
                    .unwrap_or(false);
                ProviderSummary {
                    family: family.to_string(),
                    alias: alias.to_string(),
                    model,
                    has_key,
                }
            })
            .collect();
        providers.sort_by(|a, b| {
            (a.family.as_str(), a.alias.as_str()).cmp(&(b.family.as_str(), b.alias.as_str()))
        });

        let mut agents: Vec<AgentSummary> = config
            .agents
            .iter()
            .map(|(alias, agent)| AgentSummary {
                alias: alias.clone(),
                model_provider: agent.model_provider.to_string(),
                model: config
                    .resolved_model_provider_for_agent(alias)
                    .and_then(|(_, _, entry)| {
                        entry
                            .model
                            .as_deref()
                            .map(str::trim)
                            .filter(|m| !m.is_empty())
                            .map(ToString::to_string)
                    }),
                enabled: agent.enabled,
            })
            .collect();
        agents.sort_by(|a, b| a.alias.cmp(&b.alias));

        let (gateway_url, gateway_reachable) = probe_gateway(config).await;

        Self {
            config_path: config.config_path.display().to_string(),
            config_exists: config.config_path.exists(),
            default_model: config.resolve_default_model(),
            agents,
            providers,
            gateway_url,
            gateway_reachable,
            service_running: crate::service::is_running(config),
            config_issues: config_issues(config),
        }
    }

    /// True once there is at least one provider with a model and one agent —
    /// i.e. the install can actually run an agent.
    pub fn configured(&self) -> bool {
        self.default_model.is_some() && self.agents.iter().any(|a| a.enabled)
    }

    /// The single recommended next command, mirroring the install's state.
    /// Returns a localized string (display-only; the planner reads the struct
    /// fields, not this text).
    pub fn next_step(&self) -> String {
        if !self.config_exists || self.default_model.is_none() {
            crate::t(
                "cli-onboard-next-setup-first",
                "run `setup` to create your first working agent",
            )
        } else if !self.config_issues.is_empty() {
            crate::t(
                "cli-onboard-next-validate",
                "run `validate config` or `doctor` to inspect the issues above",
            )
        } else if self.agents.iter().all(|a| !a.enabled) {
            crate::t("cli-onboard-next-add-agent", "run `setup` to add an agent")
        } else if !self.gateway_reachable && !self.service_running {
            crate::t(
                "cli-onboard-next-gateway",
                "run `gateway status` to check the gateway/daemon",
            )
        } else {
            crate::t(
                "cli-onboard-next-talk",
                "run `talk to agent` to start your configured agent",
            )
        }
    }

    /// Human-readable banner shown on entry and on `overview`/`status`.
    /// Every surface string routes through the locale bundle; only data
    /// (paths, aliases, model ids, urls) and the structured field keys are
    /// substituted verbatim. Display-only — `--json` serializes the struct,
    /// and the planner reads the struct fields, not this text.
    pub fn format(&self) -> String {
        let mut lines = Vec::new();

        let config_state = if self.config_exists {
            crate::t("cli-onboard-ov-present", "present")
        } else {
            crate::t("cli-onboard-ov-missing", "missing (first run)")
        };
        lines.push(crate::ta(
            "cli-onboard-ov-config",
            &[("state", &config_state)],
            "Config: {$state}",
        ));
        lines.push(crate::ta(
            "cli-onboard-ov-path",
            &[("path", &self.config_path)],
            "Path: {$path}",
        ));
        let default_model = self
            .default_model
            .clone()
            .unwrap_or_else(|| crate::t("cli-onboard-ov-not-configured", "not configured"));
        lines.push(crate::ta(
            "cli-onboard-ov-default-model",
            &[("model", &default_model)],
            "Default model: {$model}",
        ));

        lines.push(crate::t("cli-onboard-ov-agents", "Agents:"));
        if self.agents.is_empty() {
            lines.push(format!("  - {}", crate::t("cli-onboard-ov-none", "none")));
        } else {
            for a in &self.agents {
                let model = a
                    .model
                    .clone()
                    .unwrap_or_else(|| crate::t("cli-onboard-agent-inherited", "(inherited)"));
                let state = if a.enabled {
                    String::new()
                } else {
                    format!(" {}", crate::t("cli-onboard-agent-disabled", "[disabled]"))
                };
                lines.push(format!(
                    "  - {}",
                    crate::ta(
                        "cli-onboard-agent-row",
                        &[
                            ("alias", &a.alias),
                            ("provider", &a.model_provider),
                            ("model", &model),
                            ("state", &state),
                        ],
                        "{$alias} | provider={$provider} | model={$model}{$state}",
                    )
                ));
            }
        }

        lines.push(crate::t("cli-onboard-ov-providers", "Providers:"));
        if self.providers.is_empty() {
            lines.push(format!("  - {}", crate::t("cli-onboard-ov-none", "none")));
        } else {
            for p in &self.providers {
                let model = p
                    .model
                    .clone()
                    .unwrap_or_else(|| crate::t("cli-onboard-ov-model-none", "(none)"));
                let key = if p.has_key {
                    crate::t("cli-onboard-ov-key-yes", "yes")
                } else {
                    crate::t("cli-onboard-ov-key-no", "no")
                };
                lines.push(format!(
                    "  - {}",
                    crate::ta(
                        "cli-onboard-ov-provider-row",
                        &[
                            ("family", &p.family),
                            ("alias", &p.alias),
                            ("model", &model),
                            ("key", &key),
                        ],
                        "{$family}.{$alias} | model={$model} | key={$key}",
                    )
                ));
            }
        }

        let gw_state = if self.gateway_reachable {
            crate::t("cli-onboard-reachable", "reachable")
        } else {
            crate::t("cli-onboard-not-reachable", "not reachable")
        };
        lines.push(crate::ta(
            "cli-onboard-ov-gateway",
            &[("state", &gw_state), ("url", &self.gateway_url)],
            "Gateway: {$state} ({$url})",
        ));
        let svc_state = if self.service_running {
            crate::t("cli-onboard-running", "running")
        } else {
            crate::t("cli-onboard-not-running", "not running")
        };
        lines.push(crate::ta(
            "cli-onboard-ov-service",
            &[("state", &svc_state)],
            "Service: {$state}",
        ));
        let planner_state = if self.default_model.is_some() {
            crate::t(
                "cli-onboard-ov-planner-on",
                "model-assisted for free-form requests",
            )
        } else {
            crate::t(
                "cli-onboard-ov-planner-off",
                "deterministic only until a model is configured",
            )
        };
        lines.push(crate::ta(
            "cli-onboard-ov-planner",
            &[("state", &planner_state)],
            "Planner: {$state}",
        ));

        if !self.config_issues.is_empty() {
            lines.push(crate::t("cli-onboard-ov-config-issues", "Config issues:"));
            for issue in &self.config_issues {
                lines.push(format!("  - {issue}"));
            }
        }

        let step = self.next_step();
        lines.push(crate::ta(
            "cli-onboard-ov-next",
            &[("step", &step)],
            "Next: {$step}",
        ));
        lines.join("\n")
    }
}

/// Config validation warnings, capped so the snapshot stays terse. Uses the
/// schema's own cheap `collect_warnings` rather than `doctor::diagnose`, which
/// spawns ~40 child processes (git/curl/which/df probes) per call — far too
/// heavy to run on every overview render.
fn config_issues(config: &Config) -> Vec<String> {
    config
        .collect_warnings()
        .into_iter()
        .map(|w| w.message)
        .take(8)
        .collect()
}

/// Probe the local gateway `/health` endpoint with a short timeout.
/// Returns `(url, reachable)`; never blocks longer than ~2s.
async fn probe_gateway(config: &Config) -> (String, bool) {
    let host = if config.gateway.host == "[::]" || config.gateway.host == "0.0.0.0" {
        "127.0.0.1"
    } else {
        config.gateway.host.as_str()
    };
    let url = format!("http://{host}:{}/health", config.gateway.port);
    let reachable = reqwest::Client::new()
        .get(&url)
        .timeout(Duration::from_secs(2))
        .send()
        .await
        .map(|r| r.status().is_success())
        .unwrap_or(false);
    (url, reachable)
}
