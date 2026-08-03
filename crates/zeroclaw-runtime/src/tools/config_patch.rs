//! Agent-facing JSON Patch over the config file.
//!
//! The third consumer of `zeroclaw_config::patch`, after the gateway's
//! `PATCH /api/config` and the CLI's `zeroclaw config patch`. An agent drafts
//! ops; the approval gate puts them in front of the operator; this tool
//! applies what was approved through the same validated implementation the
//! operator surfaces use.
//!
//! Two deliberate containment properties:
//!
//! - **Disk only, never the live process.** The tool reads `config.toml`
//!   fresh, patches, validates, and saves. The running daemon's in-memory
//!   config — including this agent's own `SecurityPolicy` and tool registry —
//!   is untouched until the operator reloads or restarts. An agent therefore
//!   cannot act under a policy it changed in the turn that changed it; making
//!   a change live is always a second, human act.
//! - **No self-narration.** The arguments carry ops and nothing else — no
//!   free-text "reason" field for the model to argue its case inside the
//!   approval prompt. What the operator sees is computed by the host from
//!   the ops themselves.

use std::path::PathBuf;

use async_trait::async_trait;

use zeroclaw_api::tool::{Tool, ToolOutput, ToolResult};
use zeroclaw_config::api_error::ConfigApiError;
use zeroclaw_config::patch::{apply_patch_ops, parse_patch_ops};
use zeroclaw_config::schema::Config;

pub struct ConfigPatchTool {
    config_path: PathBuf,
}

impl ConfigPatchTool {
    pub fn new(config_path: PathBuf) -> Self {
        Self { config_path }
    }

    /// One human-readable line for a structured patch error. Same rendering
    /// the CLI's human mode uses: path and op index become prose prefixes.
    fn error_text(err: &ConfigApiError) -> String {
        match (err.op_index, err.path.as_deref()) {
            (Some(idx), Some(path)) => format!("op[{idx}] on `{path}`: {}", err.message),
            (Some(idx), None) => format!("op[{idx}]: {}", err.message),
            (None, Some(path)) => format!("`{path}`: {}", err.message),
            (None, None) => err.message.clone(),
        }
    }

    fn refuse(err: &ConfigApiError) -> ToolResult {
        ToolResult {
            success: false,
            output: ToolOutput::default(),
            error: Some(format!(
                "config patch rejected — nothing was saved. {}",
                Self::error_text(err)
            )),
        }
    }
}

#[async_trait]
impl Tool for ConfigPatchTool {
    fn name(&self) -> &str {
        "config_patch"
    }

    fn description(&self) -> &str {
        "Apply a JSON Patch to the ZeroClaw configuration file. Every call \
         requires operator approval. Changes are written to disk only: the \
         running daemon keeps its current configuration until the operator \
         reloads or restarts it, and this agent's own permissions do not \
         change mid-session. Supported ops: add/replace (require `value`), \
         remove, test (refused on secret paths), comment (requires `comment`). \
         Paths may be JSON Pointer (`/gateway/host`) or dotted (`gateway.host`)."
    }

    fn parameters_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "ops": {
                    "type": "array",
                    "description": "JSON Patch operations over config properties",
                    "items": {
                        "type": "object",
                        "properties": {
                            "op": {
                                "type": "string",
                                "enum": ["add", "replace", "remove", "test", "comment"]
                            },
                            "path": {
                                "type": "string",
                                "description": "Config property path, JSON Pointer or dotted form"
                            },
                            "value": {
                                "description": "New value for add/replace; expected value for test"
                            },
                            "comment": {
                                "type": "string",
                                "description": "TOML comment preserved alongside the value"
                            }
                        },
                        "required": ["op", "path"]
                    }
                }
            },
            "required": ["ops"]
        })
    }

    async fn execute(&self, args: serde_json::Value) -> anyhow::Result<ToolResult> {
        let Some(ops_value) = args.get("ops").cloned() else {
            return Ok(ToolResult {
                success: false,
                output: ToolOutput::default(),
                error: Some("missing required `ops` parameter (a JSON Patch array)".into()),
            });
        };

        let ops = match parse_patch_ops(ops_value) {
            Ok(ops) => ops,
            Err(err) => return Ok(Self::refuse(&err)),
        };

        // Fresh read of the on-disk state, not the boot-time snapshot: the
        // operator may have edited config since this process started, and a
        // stale base would resurrect overwritten values. By the time an agent
        // is running, boot has already migrated the file to the current
        // schema, so a parse failure here means the file is genuinely broken.
        let raw = match tokio::fs::read_to_string(&self.config_path).await {
            Ok(raw) => raw,
            Err(err) => {
                return Ok(ToolResult {
                    success: false,
                    output: ToolOutput::default(),
                    error: Some(format!(
                        "failed to read {}: {err}",
                        self.config_path.display()
                    )),
                });
            }
        };
        let mut working: Config = match toml::from_str(&raw) {
            Ok(config) => config,
            Err(err) => {
                return Ok(ToolResult {
                    success: false,
                    output: ToolOutput::default(),
                    error: Some(format!(
                        "config.toml did not parse ({err}); refusing to patch a broken file"
                    )),
                });
            }
        };
        working.config_path = self.config_path.clone();

        let results = match apply_patch_ops(&mut working, &ops) {
            Ok(results) => results,
            Err(err) => return Ok(Self::refuse(&err)),
        };

        if let Err(err) = working.validate() {
            let api_err = ConfigApiError::from_validation(err);
            return Ok(ToolResult {
                success: false,
                output: ToolOutput::default(),
                error: Some(format!(
                    "validation failed after applying patch — nothing was saved. {}",
                    Self::error_text(&api_err)
                )),
            });
        }

        working.save_dirty().await?;

        // Comments go on after save so the comment-preserving sync_table
        // pass doesn't strip them — same order as the gateway and CLI.
        let annotations: Vec<(String, String)> = ops
            .iter()
            .zip(results.iter())
            .filter_map(|(op, res)| op.comment.as_ref().map(|c| (res.path.clone(), c.clone())))
            .collect();
        if !annotations.is_empty()
            && let Err(err) =
                zeroclaw_config::comment_writer::apply_comments(&self.config_path, &annotations)
                    .await
        {
            ::zeroclaw_log::record!(
                WARN,
                ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Note)
                    .with_outcome(::zeroclaw_log::EventOutcome::Unknown)
                    .with_attrs(::serde_json::json!({"error": format!("{}", err)})),
                "config_patch: failed to apply op comments to config.toml"
            );
        }

        Ok(ToolResult::ok(ToolOutput::json(serde_json::json!({
            "saved": true,
            "results": results,
            "note": "written to config.toml; the running daemon keeps its current \
                     configuration until the operator reloads or restarts it"
        }))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn saved_config(dir: &std::path::Path) -> PathBuf {
        let path = dir.join("config.toml");
        let config = Config {
            config_path: path.clone(),
            ..Config::default()
        };
        config.save().await.expect("save initial config");
        path
    }

    fn read_config(path: &PathBuf) -> Config {
        let raw = std::fs::read_to_string(path).expect("read config back");
        toml::from_str(&raw).expect("saved config parses")
    }

    #[tokio::test]
    async fn applies_a_replace_and_persists_it_to_disk() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = saved_config(dir.path()).await;
        let tool = ConfigPatchTool::new(path.clone());

        let result = tool
            .execute(serde_json::json!({
                "ops": [{"op": "replace", "path": "/gateway/host", "value": "127.0.0.2"}]
            }))
            .await
            .expect("execute");

        assert!(result.success, "patch should succeed: {:?}", result.error);
        assert_eq!(read_config(&path).gateway.host, "127.0.0.2");
        let data = result.output.data().expect("structured output");
        assert_eq!(data["saved"], true);
        assert_eq!(data["results"][0]["path"], "gateway.host");
        assert!(
            data["note"].as_str().expect("note").contains("reloads"),
            "success output must state that nothing is live until reload"
        );
    }

    #[tokio::test]
    async fn an_invalid_op_is_refused_and_the_file_does_not_move() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = saved_config(dir.path()).await;
        let before = std::fs::read_to_string(&path).expect("read before");
        let tool = ConfigPatchTool::new(path.clone());

        let result = tool
            .execute(serde_json::json!({
                "ops": [{"op": "frobnicate", "path": "/gateway/host", "value": "x"}]
            }))
            .await
            .expect("execute");

        assert!(!result.success);
        let error = result.error.expect("error text");
        assert!(
            error.contains("nothing was saved") && error.contains("op[0]"),
            "refusal should carry the op context: {error}"
        );
        assert_eq!(
            std::fs::read_to_string(&path).expect("read after"),
            before,
            "a refused patch must not touch the file"
        );
    }

    #[tokio::test]
    async fn post_apply_validation_failure_saves_nothing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = saved_config(dir.path()).await;
        let before = std::fs::read_to_string(&path).expect("read before");
        let tool = ConfigPatchTool::new(path.clone());

        let result = tool
            .execute(serde_json::json!({
                "ops": [{"op": "replace", "path": "/gateway/host", "value": ""}]
            }))
            .await
            .expect("execute");

        assert!(!result.success);
        assert!(
            result.error.expect("error").contains("validation failed"),
            "the refusal should name validation as the reason"
        );
        assert_eq!(
            std::fs::read_to_string(&path).expect("read after"),
            before,
            "a patch that fails validation must not be saved"
        );
    }

    #[tokio::test]
    async fn missing_ops_parameter_is_a_clean_refusal() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = saved_config(dir.path()).await;
        let tool = ConfigPatchTool::new(path);

        let result = tool.execute(serde_json::json!({})).await.expect("execute");

        assert!(!result.success);
        assert!(result.error.expect("error").contains("`ops`"));
    }

    #[tokio::test]
    async fn a_missing_config_file_is_reported_not_created() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("config.toml");
        let tool = ConfigPatchTool::new(path.clone());

        let result = tool
            .execute(serde_json::json!({
                "ops": [{"op": "replace", "path": "/gateway/host", "value": "127.0.0.2"}]
            }))
            .await
            .expect("execute");

        assert!(!result.success);
        assert!(
            !path.exists(),
            "the tool must never bring a config file into existence"
        );
    }

    #[test]
    fn schema_offers_no_free_text_narration_field() {
        let dir = std::env::temp_dir();
        let tool = ConfigPatchTool::new(dir.join("config.toml"));
        let schema = tool.parameters_schema();
        let props = schema["properties"].as_object().expect("properties");
        assert_eq!(
            props.keys().collect::<Vec<_>>(),
            vec!["ops"],
            "the model gets ops and nothing else — no reason/description field \
             to argue its case inside the approval prompt"
        );
    }
}
