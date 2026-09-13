//! Runtime-side implementation of the cron execution seam.
//!
//! `zeroclaw-cron` decides *when* a job runs and *whether* policy admits it.
//! Running the agent and reporting process health belong to the runtime. This
//! module supplies those capabilities explicitly at each cron entry point.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use tokio_util::sync::CancellationToken;
use zeroclaw_api::runtime_traits::RuntimeAdapter;
use zeroclaw_config::schema::Config;
use zeroclaw_cron::{
    CronAgentExecutor, CronAgentRequest, CronAgentRun, CronHealthReporter, CronJob,
};
use zeroclaw_log::Instrument;

/// Bridges cron's health calls onto the runtime's component registry.
pub struct RuntimeCronHealth;

impl CronHealthReporter for RuntimeCronHealth {
    fn mark_ok(&self, component: &str) {
        crate::health::mark_component_ok(component);
    }

    fn mark_error(&self, component: &str, reason: &str) {
        crate::health::mark_component_error(component, reason.to_string());
    }
}

/// Runs cron's agent jobs through the agent loop.
pub struct RuntimeCronAgentExecutor;

impl CronAgentExecutor for RuntimeCronAgentExecutor {
    fn run_agent_job<'a>(
        &'a self,
        request: CronAgentRequest,
    ) -> Pin<Box<dyn Future<Output = CronAgentRun> + Send + 'a>> {
        Box::pin(async move {
            let CronAgentRequest {
                mut config,
                security,
                job_id,
                agent_alias,
                prompt,
                model,
                session_path,
                allowed_tools,
                uses_memory,
            } = request;

            // Cron jobs never auto-save conversation memory: a scheduled run is
            // not a conversation, and letting it write would accumulate turns
            // nobody asked for.
            config.memory.auto_save = false;
            let cleanup_config = config.clone();

            let span = zeroclaw_log::info_span!(
                "subagent",
                category = "cron",
                agent_alias = %agent_alias,
                cron_job_id = %job_id,
                spawn_site = "cron",
            );

            let overrides = crate::agent::loop_::AgentRunOverrides {
                security: Some(security),
                memory: None,
                is_subagent: false,
                // `uses_memory = false` opts the job out of memory-context
                // injection and makes the run memory-free end to end: the loop
                // binds a `NoneMemory` backend and drops the persistent memory
                // tools, so such a job can neither recall/store through a real
                // backend nor reach one via advertised tools.
                suppress_memory_inject: !uses_memory,
                memory_free: !uses_memory,
                // Cron runs are short-lived and one-shot, so the per-call
                // `connect_all` path inside `agent::run` is correct here. The
                // daemon heartbeat worker is the only `mcp_registry` supplier.
                mcp_registry: None,
            };

            let temperature = config
                .model_provider_for_agent(&agent_alias)
                .and_then(|e| e.temperature);

            let result = Box::pin(
                crate::agent::run(
                    config,
                    &agent_alias,
                    Some(prompt),
                    None,
                    model,
                    temperature,
                    vec![],
                    false,
                    Some(session_path.clone()),
                    allowed_tools,
                    zeroclaw_api::ingress::TurnOrigin::Cron,
                    overrides,
                )
                .instrument(span),
            )
            .await;

            match result {
                Ok(response) => CronAgentRun {
                    success: true,
                    output: if response.trim().is_empty() {
                        "agent job executed".to_string()
                    } else {
                        response
                    },
                },
                Err(e) => {
                    // A failed isolated run leaves session memory behind that
                    // nothing will ever read. Purge it rather than accumulate
                    // one dead session per failure.
                    if session_path != std::path::Path::new("main") {
                        let key = zeroclaw_api::session_keys::sanitize_session_key(&format!(
                            "cli:{}",
                            session_path.display()
                        ));
                        if let Ok(mem) = zeroclaw_memory::create_memory_for_agent(
                            &cleanup_config,
                            &agent_alias,
                            cleanup_config
                                .model_provider_for_agent(&agent_alias)
                                .and_then(|e| e.api_key.as_deref()),
                        )
                        .await
                        {
                            let _ = mem.purge_session(&key).await;
                        }
                    }
                    CronAgentRun {
                        success: false,
                        output: format!("agent job failed: {e}"),
                    }
                }
            }
        })
    }
}

/// Run the scheduler with this runtime's explicit host capabilities.
pub async fn run_scheduler(
    config: Config,
    event_tx: zeroclaw_cron::scheduler::EventBroadcast,
    cancel: CancellationToken,
) -> anyhow::Result<()> {
    zeroclaw_cron::scheduler::run(
        config,
        event_tx,
        cancel,
        Arc::new(RuntimeCronAgentExecutor),
        Arc::new(RuntimeCronHealth),
    )
    .await
}

/// Manually run a cron job through this runtime's agent executor.
pub async fn run_manual_job(
    config: &Config,
    job: &CronJob,
    context: zeroclaw_cron::scheduler::CronDeliveryContext,
    event_tx: &zeroclaw_cron::scheduler::EventBroadcast,
) -> zeroclaw_cron::scheduler::ManualCronRunResult {
    zeroclaw_cron::scheduler::run_manual_job(
        config,
        job,
        context,
        event_tx,
        &RuntimeCronAgentExecutor,
    )
    .await
}

/// Manually run a cron job with a caller-supplied shell runtime.
pub async fn run_manual_job_with_runtime(
    config: &Config,
    job: &CronJob,
    context: zeroclaw_cron::scheduler::CronDeliveryContext,
    event_tx: &zeroclaw_cron::scheduler::EventBroadcast,
    runtime: &dyn RuntimeAdapter,
    approved: bool,
) -> zeroclaw_cron::scheduler::ManualCronRunResult {
    zeroclaw_cron::scheduler::run_manual_job_with_runtime(
        config,
        job,
        context,
        event_tx,
        runtime,
        approved,
        &RuntimeCronAgentExecutor,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Json, Router, routing::post};
    use tempfile::TempDir;
    use tokio::net::TcpListener;
    use zeroclaw_config::policy::{AutonomyLevel, SecurityPolicy};
    use zeroclaw_config::schema::{
        AliasedAgentConfig, ModelProviderConfig, OllamaModelProviderConfig, RiskProfileConfig,
        RuntimeProfileConfig,
    };

    const TEST_AGENT: &str = "cron-host-test";

    async fn test_config(tmp: &TempDir, provider_address: std::net::SocketAddr) -> Config {
        let mut config = Config {
            data_dir: tmp.path().join("data"),
            config_path: tmp.path().join("config.toml"),
            ..Config::default()
        };
        config.memory.backend = "none".to_string();
        config.memory.auto_save = false;
        config.risk_profiles.insert(
            TEST_AGENT.to_string(),
            RiskProfileConfig {
                level: AutonomyLevel::Full,
                ..RiskProfileConfig::default()
            },
        );
        config
            .runtime_profiles
            .insert(TEST_AGENT.to_string(), RuntimeProfileConfig::default());
        config.providers.models.ollama.insert(
            TEST_AGENT.to_string(),
            OllamaModelProviderConfig {
                base: ModelProviderConfig {
                    model: Some("cron-workspace-test-model".to_string()),
                    timeout_secs: Some(5),
                    uri: Some(format!("http://{provider_address}")),
                    ..ModelProviderConfig::default()
                },
                ..OllamaModelProviderConfig::default()
            },
        );
        config.agents.insert(
            TEST_AGENT.to_string(),
            AliasedAgentConfig {
                model_provider: format!("ollama.{TEST_AGENT}").into(),
                risk_profile: TEST_AGENT.into(),
                runtime_profile: TEST_AGENT.into(),
                ..AliasedAgentConfig::default()
            },
        );
        tokio::fs::create_dir_all(&config.data_dir).await.unwrap();
        config
    }

    #[tokio::test]
    async fn executor_uses_the_policy_resolved_by_cron() {
        let requests = Arc::new(std::sync::Mutex::new(Vec::<serde_json::Value>::new()));
        let requests_for_handler = Arc::clone(&requests);
        let app = Router::new().route(
            "/v1/chat/completions",
            post(move |Json(body): Json<serde_json::Value>| {
                requests_for_handler.lock().unwrap().push(body.clone());
                let has_tool_result = body["messages"].as_array().is_some_and(|messages| {
                    messages.iter().any(|message| {
                        message.get("role").and_then(serde_json::Value::as_str) == Some("tool")
                    })
                });
                async move {
                    if has_tool_result {
                        Json(serde_json::json!({
                            "choices": [{"message": {"content": "done"}}]
                        }))
                    } else {
                        Json(serde_json::json!({
                            "choices": [{
                                "message": {
                                    "content": null,
                                    "tool_calls": [{
                                        "id": "call-shell",
                                        "type": "function",
                                        "function": {
                                            "name": "shell",
                                            "arguments": "{\"command\":\"pwd\"}"
                                        }
                                    }]
                                }
                            }]
                        }))
                    }
                }
            }),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = zeroclaw_spawn::spawn!(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let tmp = TempDir::new().unwrap();
        let config = test_config(&tmp, address).await;
        let mut security = SecurityPolicy::for_agent(&config, TEST_AGENT).unwrap();
        let scheduler_workspace = tmp.path().join("scheduler-owned-workspace");
        std::fs::create_dir_all(&scheduler_workspace).unwrap();
        security.workspace_dir = scheduler_workspace.clone();
        assert_ne!(scheduler_workspace, config.agent_workspace_dir(TEST_AGENT));

        let result = RuntimeCronAgentExecutor
            .run_agent_job(CronAgentRequest {
                config,
                security: Arc::new(security),
                job_id: "workspace-boundary".to_string(),
                agent_alias: TEST_AGENT.to_string(),
                prompt: "Print the current workspace directory".to_string(),
                model: None,
                session_path: std::path::PathBuf::from("cron-workspace-boundary"),
                allowed_tools: Some(vec!["shell".to_string()]),
                uses_memory: false,
            })
            .await;

        assert!(result.success, "cron agent run failed: {}", result.output);
        assert_eq!(result.output, "done");

        let requests = requests.lock().unwrap();
        let tool_result = requests
            .iter()
            .filter_map(|request| request["messages"].as_array())
            .flatten()
            .find_map(|message| {
                (message.get("role").and_then(serde_json::Value::as_str) == Some("tool"))
                    .then(|| message.get("content")?.as_str())
                    .flatten()
            })
            .expect("the model-request transcript should contain the shell result");
        assert!(
            tool_result.contains(scheduler_workspace.to_string_lossy().as_ref()),
            "shell output must come from cron's resolved workspace {scheduler_workspace:?}, got {tool_result:?}"
        );

        server.abort();
    }
}
