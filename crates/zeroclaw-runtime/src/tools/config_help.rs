//! Read-only tool that hands an agent the **authoritative** ZeroClaw config
//! schema for a section, so it can edit `config.toml` with the right keys
//! instead of guessing.
//!
//! It renders the field table (name, type, description, default) straight from
//! `schemars::schema_for!(Config)` via the same [`schema_markdown`] machinery
//! that builds the published docs — so it is generated from the live
//! `Configurable` definitions and can never go stale (unlike a fetched doc page
//! or a hand-written cookbook). No filesystem, no network: it only describes the
//! schema.
//!
//! [`schema_markdown`]: zeroclaw_config::schema_markdown

use anyhow::Result;
use async_trait::async_trait;
use serde_json::json;

use zeroclaw_api::tool::{Tool, ToolResult};

/// Look up the config schema for a section (read-only).
pub struct ConfigHelpTool;

impl ConfigHelpTool {
    pub const NAME: &'static str = "config_help";

    pub fn new() -> Self {
        Self
    }

    fn ok(text: String) -> ToolResult {
        ToolResult {
            success: true,
            output: text,
            error: None,
        }
    }

    fn refuse(msg: impl Into<String>) -> ToolResult {
        ToolResult {
            success: false,
            output: String::new(),
            error: Some(msg.into()),
        }
    }
}

impl Default for ConfigHelpTool {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Tool for ConfigHelpTool {
    fn name(&self) -> &str {
        Self::NAME
    }

    fn description(&self) -> &str {
        "Look up the authoritative ZeroClaw config schema before editing config.toml. \
         Pass a section path (e.g. \"channels\", \"cron_jobs\", \"providers.models\", \"agents\", \
         \"risk_profiles\") to get that section's fields — name, type, description, and default. \
         Omit `section` to list all top-level config sections. Read-only; generated from the live \
         schema so it never goes stale. Consult it for any section whose exact keys you are unsure of."
    }

    fn parameters_schema(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "section": {
                    "type": "string",
                    "description": "Config section path, e.g. \"channels\", \"cron_jobs\", \"providers.models\", \"agents\", \"risk_profiles\". Omit to list all top-level sections."
                }
            },
            "additionalProperties": false
        })
    }

    async fn execute(&self, args: serde_json::Value) -> Result<ToolResult> {
        // The schema is built in zeroclaw-config (which carries the schemars
        // derives); `None` only when that crate was built without schema-export.
        let Some(root) = zeroclaw_config::schema_markdown::config_schema_root() else {
            return Ok(Self::refuse(
                "config_help: unavailable — this build lacks the schema-export feature",
            ));
        };
        let section = args
            .get("section")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty());
        Ok(match section {
            None => Self::ok(format!(
                "Top-level config sections — pass one as `section` to see its fields:\n{}",
                list_sections(&root)
            )),
            Some(path) => {
                match zeroclaw_config::schema_markdown::field_table_for_path(
                    &root, path, false, None,
                ) {
                    Ok(table) => Self::ok(table),
                    Err(e) => Self::refuse(format!(
                        "{e}\n\nTop-level sections:\n{}",
                        list_sections(&root)
                    )),
                }
            }
        })
    }
}

/// The top-level config section names, from the schema root (following the
/// `$ref` into `$defs` that schemars emits for the root type).
fn list_sections(root: &serde_json::Value) -> String {
    use serde_json::Value;
    let node = root
        .get("$ref")
        .and_then(Value::as_str)
        .and_then(|r| r.rsplit('/').next())
        .and_then(|name| root.get("$defs").and_then(|d| d.get(name)))
        .unwrap_or(root);
    let mut keys: Vec<&str> = node
        .get("properties")
        .and_then(Value::as_object)
        .map(|m| m.keys().map(String::as_str).collect())
        .unwrap_or_default();
    keys.sort_unstable();
    keys.iter()
        .map(|k| format!("- {k}"))
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(all(test, feature = "schema-export"))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn lists_top_level_sections_when_no_arg() {
        let result = ConfigHelpTool::new().execute(json!({})).await.unwrap();
        assert!(result.success);
        // `agents` and `risk_profiles` are stable top-level config sections.
        assert!(result.output.contains("agents"), "list: {}", result.output);
        assert!(result.output.contains("risk_profiles"));
    }

    #[tokio::test]
    async fn renders_fields_for_a_known_section() {
        let result = ConfigHelpTool::new()
            .execute(json!({ "section": "risk_profiles" }))
            .await
            .unwrap();
        assert!(result.success, "error: {:?}", result.error);
        // RiskProfileConfig exposes these fields, so they must appear in the table.
        assert!(
            result.output.contains("workspace_only") && result.output.contains("allowed_tools"),
            "table: {}",
            result.output
        );
    }

    #[tokio::test]
    async fn unknown_section_errors_with_a_section_hint() {
        let result = ConfigHelpTool::new()
            .execute(json!({ "section": "definitely_not_a_section" }))
            .await
            .unwrap();
        assert!(!result.success);
        let err = result.error.unwrap();
        assert!(err.contains("definitely_not_a_section") || err.contains("not found"));
        // The error lists the real sections so the agent can recover.
        assert!(err.contains("agents"), "hint missing sections: {err}");
    }
}
