//! Agent-loop tool that launches a *configured* ZeroClaw agent's interactive
//! session in the current terminal, so the calling agent can hand the user
//! straight to another agent. It spawns `zeroclaw agent --agent <name>` as a
//! foreground child sharing this process's stdio; control returns to the caller
//! when that session ends.
//!
//! This is the "switch to my new agent" affordance an onboarding agent (Zerona)
//! uses right after [`create_agent`](super::create_agent): build the agent, then
//! offer to start it. Beyond the usual risk-profile allowlist gate and shared
//! action budget, it adds two guards:
//!
//! * **interactive-only** — refuses unless stdin/stdout are a terminal, so it
//!   can never spawn an interactive session in a daemon/channel context.
//! * **no self-launch** — refuses if the target name equals the calling agent's
//!   alias, so an agent can't relaunch itself into an endless nest.

use std::io::IsTerminal;
use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use serde_json::json;

use zeroclaw_api::tool::{Tool, ToolResult};
use zeroclaw_config::schema::Config;

use crate::security::SecurityPolicy;
use crate::security::policy::ToolOperation;

/// Launch a configured agent's interactive session in this terminal.
pub struct StartAgentTool {
    /// Snapshot config, used only to resolve the caller's risk-profile gate.
    /// Existence of the *target* agent is checked against a fresh on-disk load,
    /// since it may have been created earlier in this same session.
    config: Arc<Config>,
    /// The caller's live policy — gates autonomy and consumes one action slot.
    security: Arc<SecurityPolicy>,
    /// The alias of the agent invoking this tool (for the self-launch guard).
    caller_alias: String,
}

impl StartAgentTool {
    pub const NAME: &'static str = "start_agent";

    pub fn new(
        config: Arc<Config>,
        security: Arc<SecurityPolicy>,
        caller_alias: impl Into<String>,
    ) -> Self {
        Self {
            config,
            security,
            caller_alias: caller_alias.into(),
        }
    }

    fn refuse(msg: impl Into<String>) -> ToolResult {
        ToolResult {
            success: false,
            output: String::new(),
            error: Some(msg.into()),
        }
    }

    fn arg_str<'a>(args: &'a serde_json::Value, key: &str) -> Option<&'a str> {
        args.get(key)
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|v| !v.is_empty())
    }
}

#[async_trait]
impl Tool for StartAgentTool {
    fn name(&self) -> &str {
        Self::NAME
    }

    fn description(&self) -> &str {
        "Launch a configured ZeroClaw agent's interactive session in this \
         terminal so the user can start talking to it. Use this right after \
         create_agent to hand the user straight to their new agent. Control \
         returns to you when that session ends, so the user is back with you \
         afterward. Only works in an interactive terminal; pass the agent's name."
    }

    fn parameters_schema(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "name": {
                    "type": "string",
                    "description": "Alias of an already-configured agent to start (e.g. one you just created)."
                }
            },
            "required": ["name"],
            "additionalProperties": false
        })
    }

    async fn execute(&self, args: serde_json::Value) -> Result<ToolResult> {
        // Risk-profile tool gate (mirrors create_agent): a non-empty
        // allowed_tools that omits start_agent, or an excluded_tools that names
        // it, refuses up front.
        if let Some(rp) = self.config.risk_profile_for_agent(&self.caller_alias) {
            let excluded = rp.excluded_tools.iter().any(|t| t == Self::NAME);
            let allowed =
                rp.allowed_tools.is_empty() || rp.allowed_tools.iter().any(|t| t == Self::NAME);
            if excluded || !allowed {
                return Ok(Self::refuse(format!(
                    "start_agent: refused — agent '{}' risk_profile does not allow start_agent",
                    self.caller_alias
                )));
            }
        }

        // Action gate: autonomy + rate limit (one slot per launch attempt).
        if let Err(error) = self
            .security
            .enforce_tool_operation(ToolOperation::Act, Self::NAME)
        {
            return Ok(Self::refuse(error));
        }

        let Some(name) = Self::arg_str(&args, "name") else {
            return Ok(Self::refuse("start_agent: 'name' is required"));
        };
        if name == self.caller_alias {
            return Ok(Self::refuse(
                "start_agent: refused — cannot launch the calling agent into itself",
            ));
        }

        // Interactive-only: a launched session inherits this terminal's stdio,
        // so it is meaningless (and would hang) without an operator present.
        if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
            return Ok(Self::refuse(
                "start_agent: refused — only works in an interactive terminal",
            ));
        }

        // Check the target against a fresh on-disk config: an agent created
        // earlier this session won't be in the snapshot the tool was built with.
        let cfg = match Config::load_or_init().await {
            Ok(cfg) => cfg,
            Err(e) => {
                return Ok(Self::refuse(format!(
                    "start_agent: could not load config — {e}"
                )));
            }
        };
        if !cfg.agents.contains_key(name) {
            return Ok(Self::refuse(format!(
                "start_agent: no agent named '{name}' is configured"
            )));
        }

        // Hand the terminal to the agent's interactive session and wait. When it
        // exits (the user quits), control returns here and the caller resumes.
        let exe = match std::env::current_exe() {
            Ok(exe) => exe,
            Err(e) => {
                return Ok(Self::refuse(format!(
                    "start_agent: could not locate the zeroclaw executable — {e}"
                )));
            }
        };
        let status = tokio::process::Command::new(exe)
            .arg("agent")
            .arg("--agent")
            .arg(name)
            .status()
            .await;

        match status {
            Ok(_) => Ok(ToolResult {
                success: true,
                output: serde_json::to_string_pretty(&json!({
                    "message": format!("Launched agent '{name}'; its session has ended and the user is back with you."),
                    "agent": name,
                }))?,
                error: None,
            }),
            Err(e) => Ok(Self::refuse(format!(
                "start_agent: failed to launch agent '{name}' — {e}"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroclaw_config::schema::{AliasedAgentConfig, RiskProfileConfig};

    fn tool_for(caller: &str, config: Config) -> StartAgentTool {
        StartAgentTool::new(
            Arc::new(config),
            Arc::new(SecurityPolicy::default()),
            caller,
        )
    }

    fn config_with_allowed(alias: &str, allowed_tools: Vec<String>) -> Config {
        let mut config = Config::default();
        config.risk_profiles.insert(
            "default".to_string(),
            RiskProfileConfig {
                allowed_tools,
                ..RiskProfileConfig::default()
            },
        );
        config.agents.insert(
            alias.to_string(),
            AliasedAgentConfig {
                risk_profile: "default".into(),
                ..AliasedAgentConfig::default()
            },
        );
        config
    }

    #[tokio::test]
    async fn requires_name() {
        let tool = tool_for("zerona", Config::default());
        let result = tool.execute(json!({})).await.unwrap();
        assert!(!result.success);
        assert!(result.error.unwrap().contains("'name' is required"));
    }

    #[tokio::test]
    async fn refuses_to_launch_the_calling_agent() {
        let tool = tool_for("zerona", Config::default());
        let result = tool.execute(json!({ "name": "zerona" })).await.unwrap();
        assert!(!result.success);
        assert!(result.error.unwrap().contains("calling agent"));
    }

    #[tokio::test]
    async fn refuses_when_risk_profile_excludes_start_agent() {
        let tool = tool_for(
            "zerona",
            config_with_allowed("zerona", vec!["shell".into()]),
        );
        let result = tool.execute(json!({ "name": "scout" })).await.unwrap();
        assert!(!result.success);
        assert!(result.error.unwrap().contains("does not allow start_agent"));
    }
}
