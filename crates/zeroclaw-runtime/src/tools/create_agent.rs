//! Agent-loop tool that creates a NEW ZeroClaw agent — name, model provider,
//! model, autonomy (risk) level, and a personalized identity — by landing a
//! [`BuilderSubmission`] through the canonical quickstart apply path. It writes
//! config only; it does not run the new agent.
//!
//! This is the capability an onboarding agent (e.g. "Zerona") uses to set up
//! the user's agents from a conversation. Beyond the usual risk-profile
//! allowlist gate and shared action budget, it adds two guards:
//!
//! * **create-only** — refuses if an agent with that name already exists, so it
//!   can never overwrite/escalate an existing agent's profile.
//! * **no self-modification** — refuses if the target name equals the calling
//!   agent's alias.

use anyhow::Result;
use async_trait::async_trait;
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;

use zeroclaw_api::tool::{Tool, ToolResult};
use zeroclaw_config::presets::{
    AgentIdentity, BuilderSubmission, MemoryChoice, ModelProviderChoice, QuickstartPersonalityFile,
    SelectorChoice,
};
use zeroclaw_config::schema::Config;

use crate::agent::personality_templates::{TemplateContext, render_preset_default};
use crate::quickstart::{Surface, apply_with_surface};
use crate::security::SecurityPolicy;
use crate::security::policy::ToolOperation;

/// Create a new agent (config only) from a structured description.
pub struct CreateAgentTool {
    /// Snapshot config, used to resolve the caller's risk-profile gate and to
    /// recognise existing provider references.
    config: Arc<Config>,
    /// The caller's live policy — gates autonomy and consumes one action slot.
    security: Arc<SecurityPolicy>,
    /// The alias of the agent invoking this tool (for the self-mod guard).
    caller_alias: String,
}

impl CreateAgentTool {
    pub const NAME: &'static str = "create_agent";

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
impl Tool for CreateAgentTool {
    fn name(&self) -> &str {
        Self::NAME
    }

    fn description(&self) -> &str {
        "Create a new ZeroClaw agent (writes config only; does not run it). \
         Use this to set up an agent for the user from a conversation: choose a \
         name, a model provider + model, an autonomy level, and weave the \
         person's name and preferred communication style into the agent's \
         personality. Refuses to overwrite an existing agent or to modify the \
         calling agent."
    }

    fn parameters_schema(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "name": {
                    "type": "string",
                    "description": "Alias for the new agent: lowercase letters, digits, and single underscores; no leading/trailing underscore."
                },
                "provider": {
                    "type": "string",
                    "description": "Model provider family (e.g. \"anthropic\", \"openai\", \"ollama\"), or an existing \"family.alias\" reference to reuse a configured provider."
                },
                "model": {
                    "type": "string",
                    "description": "Model id (e.g. \"claude-sonnet-4-6\"). Required for a new provider; omit when reusing an existing provider reference."
                },
                "api_key": {
                    "type": "string",
                    "description": "API key for a new remote provider. Omit for local/keyless providers or when reusing an existing provider."
                },
                "risk": {
                    "type": "string",
                    "enum": ["balanced", "locked_down", "yolo"],
                    "default": "balanced",
                    "description": "Autonomy level: locked_down (most restricted), balanced (supervised, workspace-only), yolo (full autonomy)."
                },
                "user_name": {
                    "type": "string",
                    "description": "The person's name, woven into the new agent's personality files."
                },
                "communication_style": {
                    "type": "string",
                    "description": "How the new agent should talk (free text), woven into its personality."
                }
            },
            "required": ["name", "provider"],
            "additionalProperties": false
        })
    }

    async fn execute(&self, args: serde_json::Value) -> Result<ToolResult> {
        // Risk-profile tool gate (mirrors spawn_subagent): a non-empty
        // allowed_tools that omits create_agent, or an excluded_tools that
        // names it, refuses up front.
        if let Some(rp) = self.config.risk_profile_for_agent(&self.caller_alias) {
            let excluded = rp.excluded_tools.iter().any(|t| t == Self::NAME);
            let allowed =
                rp.allowed_tools.is_empty() || rp.allowed_tools.iter().any(|t| t == Self::NAME);
            if excluded || !allowed {
                return Ok(Self::refuse(format!(
                    "create_agent: refused — agent '{}' risk_profile does not allow create_agent",
                    self.caller_alias
                )));
            }
        }

        // Action gate: autonomy + rate limit (one slot per create attempt).
        if let Err(error) = self
            .security
            .enforce_tool_operation(ToolOperation::Act, Self::NAME)
        {
            return Ok(Self::refuse(error));
        }

        let Some(name) = Self::arg_str(&args, "name") else {
            return Ok(Self::refuse("create_agent: 'name' is required"));
        };
        if let Err(e) = zeroclaw_config::helpers::validate_alias_key(name) {
            return Ok(Self::refuse(format!("create_agent: invalid name — {e}")));
        }
        if name == self.caller_alias {
            return Ok(Self::refuse(
                "create_agent: refused — cannot modify the calling agent",
            ));
        }
        let Some(provider) = Self::arg_str(&args, "provider") else {
            return Ok(Self::refuse("create_agent: 'provider' is required"));
        };

        // Load a fresh, fully-resolved config to write into (the snapshot in
        // `self.config` is read-only and may be stale).
        let mut cfg = match Config::load_or_init().await {
            Ok(cfg) => cfg,
            Err(e) => {
                return Ok(Self::refuse(format!(
                    "create_agent: could not load config — {e}"
                )));
            }
        };
        if cfg.agents.contains_key(name) {
            return Ok(Self::refuse(format!(
                "create_agent: refused — an agent named '{name}' already exists"
            )));
        }

        // Provider: reuse an existing "family.alias" reference, or create fresh.
        let model_provider = if let Some((family, alias)) = provider.split_once('.') {
            if cfg.providers.models.find(family, alias).is_some() {
                SelectorChoice::Existing(provider.to_string())
            } else {
                return Ok(Self::refuse(format!(
                    "create_agent: no configured provider '{provider}' — pass a family + model to create one"
                )));
            }
        } else {
            let Some(model) = Self::arg_str(&args, "model") else {
                return Ok(Self::refuse(
                    "create_agent: 'model' is required when creating a new provider",
                ));
            };
            let mut fields = HashMap::new();
            if let Some(key) = Self::arg_str(&args, "api_key") {
                fields.insert("api_key".to_string(), key.to_string());
            }
            SelectorChoice::Fresh(ModelProviderChoice {
                provider_type: provider.to_string(),
                alias: "default".to_string(),
                model: model.to_string(),
                fields,
            })
        };

        let risk = Self::arg_str(&args, "risk").unwrap_or("balanced");
        let user = Self::arg_str(&args, "user_name").unwrap_or("the user");
        let ctx = TemplateContext {
            agent: name.to_string(),
            user: user.to_string(),
            timezone: std::env::var("TZ").unwrap_or_else(|_| "UTC".to_string()),
            communication_style: Self::arg_str(&args, "communication_style").map_or_else(
                || TemplateContext::default().communication_style,
                str::to_string,
            ),
            include_memory: true,
        };
        let personality_files = render_preset_default(&ctx)
            .into_iter()
            .map(|(filename, content)| QuickstartPersonalityFile {
                filename: filename.to_string(),
                content,
            })
            .collect();

        let submission = BuilderSubmission {
            model_provider,
            risk_profile: SelectorChoice::Fresh(risk.to_string()),
            runtime_profile: SelectorChoice::Fresh("unbounded".to_string()),
            memory: SelectorChoice::Fresh(MemoryChoice::Sqlite),
            channels: vec![],
            peer_groups: vec![],
            agent: AgentIdentity {
                name: name.to_string(),
                system_prompt: String::new(),
                personality_file: None,
                personality_files,
            },
        };

        match apply_with_surface(submission, &mut cfg, Surface::Cli).await {
            Ok(applied) => Ok(ToolResult {
                success: true,
                output: serde_json::to_string_pretty(&json!({
                    "message": format!("Created agent '{}'", applied.alias),
                    "agent": applied.alias,
                    "model_provider": applied.model_provider,
                    "risk_profile": applied.risk_profile,
                }))?,
                error: None,
            }),
            Err(errors) => Ok(Self::refuse(format!(
                "create_agent: {}",
                errors
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join("; ")
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroclaw_config::schema::{AliasedAgentConfig, RiskProfileConfig};

    fn tool_for(caller: &str, config: Config) -> CreateAgentTool {
        CreateAgentTool::new(
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
    async fn refuses_to_modify_the_calling_agent() {
        let tool = tool_for("zerona", Config::default());
        let result = tool
            .execute(json!({ "name": "zerona", "provider": "anthropic", "model": "x" }))
            .await
            .unwrap();
        assert!(!result.success);
        assert!(result.error.unwrap().contains("calling agent"));
    }

    #[tokio::test]
    async fn requires_name_and_provider() {
        let tool = tool_for("zerona", Config::default());
        assert!(
            !tool
                .execute(json!({ "provider": "anthropic" }))
                .await
                .unwrap()
                .success
        );
        assert!(
            !tool
                .execute(json!({ "name": "bot" }))
                .await
                .unwrap()
                .success
        );
    }

    #[tokio::test]
    async fn rejects_invalid_alias() {
        let tool = tool_for("zerona", Config::default());
        let result = tool
            .execute(json!({ "name": "Bad Name!", "provider": "anthropic", "model": "x" }))
            .await
            .unwrap();
        assert!(!result.success);
        assert!(result.error.unwrap().contains("invalid name"));
    }

    #[tokio::test]
    async fn refuses_when_risk_profile_excludes_create_agent() {
        let tool = tool_for(
            "zerona",
            config_with_allowed("zerona", vec!["shell".into()]),
        );
        let result = tool
            .execute(json!({ "name": "bot", "provider": "anthropic", "model": "x" }))
            .await
            .unwrap();
        assert!(!result.success);
        assert!(
            result
                .error
                .unwrap()
                .contains("does not allow create_agent")
        );
    }
}
