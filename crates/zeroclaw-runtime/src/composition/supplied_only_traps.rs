//! A supplied-only build constructs no native integration at any eager entry
//! point, even with MCP, peripherals and workspace skills configured.
//!
//! Each native integration is configured with a trap that leaves evidence when
//! it is constructed: a real stdio MCP server that writes a launch marker, a
//! peripheral board the registered peripheral factory counts, and a workspace
//! skill whose name appears in any prompt that loaded it. The native-recipe
//! controls show each trap fires, so the supplied-only tests cannot pass
//! vacuously.

use super::test_support::{
    RecordingMemory, RecordingProviders, recording_capabilities,
};
use super::{
    ProviderRequest, ProviderSource, RuntimeCapabilities, ToolRequest, ToolSource,
};
use crate::tools::Tool;
use async_trait::async_trait;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Once};
use zeroclaw_api::ingress::TurnOrigin;
use zeroclaw_api::model_provider::{ChatRequest, ChatResponse, ModelProvider};
use zeroclaw_api::tool::{ToolOutput, ToolResult};
use zeroclaw_config::schema::{
    AliasedAgentConfig, Config, McpBundleConfig, McpServerConfig, McpTransport,
    ModelProviderConfig, OpenAIModelProviderConfig, PeripheralBoardConfig, RiskProfileConfig,
};

const AGENT: &str = "trap-agent";
const SOURCE_TOOL: &str = "trap_source_tool";
const REPLY: &str = "trap turn answered";

static PERIPHERAL_LOADS: LazyLock<Mutex<HashMap<String, usize>>> =
    LazyLock::new(Default::default);

/// The process-wide peripheral factory counts loads of trap boards and builds
/// nothing, so registering it cannot change any other test's registry.
fn register_peripheral_trap() {
    static REGISTER: Once = Once::new();
    REGISTER.call_once(|| {
        crate::agent::loop_::register_peripheral_tools_fn(Box::new(|config| {
            for board in &config.boards {
                if board.board.starts_with("native-trap-") {
                    *PERIPHERAL_LOADS.lock().entry(board.board.clone()).or_default() += 1;
                }
            }
            Box::pin(async { Ok(Vec::new()) })
        }));
    });
}

struct NativeTraps {
    mcp_marker: PathBuf,
    board: String,
    skill: String,
}

impl NativeTraps {
    fn arm(config: &mut Config, root: &Path) -> Self {
        let label = uuid::Uuid::new_v4().simple().to_string();
        // A symlink to the checked-in executable fixture: writing a fresh
        // script in a multithreaded test process can race a concurrent fork.
        let server = root.join("native-trap-mcp-server.sh");
        std::os::unix::fs::symlink(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/mcp-server.sh"),
            &server,
        )
        .expect("link the stdio MCP fixture");
        let mcp_marker = root.join("native-trap-mcp-launched");
        config.mcp.enabled = true;
        config.mcp.deferred_loading = false;
        config.mcp.servers.push(McpServerConfig {
            name: "native_trap".into(),
            command: server.display().to_string(),
            args: vec![mcp_marker.display().to_string()],
            transport: McpTransport::Stdio,
            ..Default::default()
        });
        config.mcp_bundles.insert(
            "native-trap".into(),
            McpBundleConfig {
                servers: vec!["native_trap".into()],
                exclude: Vec::new(),
            },
        );
        config
            .agents
            .get_mut(AGENT)
            .expect("trap agent")
            .mcp_bundles
            .push("native-trap".into());

        register_peripheral_trap();
        let board = format!("native-trap-{label}");
        config.peripherals.enabled = true;
        config.peripherals.boards.push(PeripheralBoardConfig {
            board: board.clone(),
            ..Default::default()
        });

        let skill = format!("native-trap-skill-{label}");
        let skill_dir = config
            .agent_workspace_dir(AGENT)
            .join("skills")
            .join(&skill);
        std::fs::create_dir_all(&skill_dir).unwrap();
        std::fs::write(
            skill_dir.join("SKILL.md"),
            format!("---\nname: {skill}\ndescription: Native skill loading trap.\n---\nUse {skill}.\n"),
        )
        .unwrap();

        Self {
            mcp_marker,
            board,
            skill,
        }
    }

    fn mcp_launched(&self) -> bool {
        self.mcp_marker.exists()
    }

    fn peripheral_loads(&self) -> usize {
        PERIPHERAL_LOADS.lock().get(&self.board).copied().unwrap_or(0)
    }

    fn skill_in(&self, prompt: &str) -> bool {
        prompt.contains(&self.skill)
    }
}

fn trap_config(root: &Path) -> Config {
    let mut config = Config {
        data_dir: root.join("data"),
        config_path: root.join("config.toml"),
        ..Default::default()
    };
    config.memory.backend = "none".into();
    config.memory.auto_save = false;
    config.plugins.enabled = false;
    config.plugins.auto_discover = false;
    config.risk_profiles.insert(
        "trap".into(),
        RiskProfileConfig {
            auto_approve: vec![SOURCE_TOOL.into()],
            ..Default::default()
        },
    );
    config.providers.models.openai.insert(
        "trap".into(),
        OpenAIModelProviderConfig {
            base: ModelProviderConfig {
                model: Some("trap-model".into()),
                // Unroutable: only the supplied provider can answer.
                uri: Some("http://127.0.0.1:9".into()),
                api_key: Some("trap-key".into()),
                ..Default::default()
            },
        },
    );
    config.agents.insert(
        AGENT.into(),
        AliasedAgentConfig {
            model_provider: "openai.trap".into(),
            risk_profile: "trap".into(),
            ..Default::default()
        },
    );
    config
}

struct SourceTool;

zeroclaw_api::mock_tool_attribution!(SourceTool);

#[async_trait]
impl Tool for SourceTool {
    fn name(&self) -> &str {
        SOURCE_TOOL
    }
    fn description(&self) -> &str {
        "the one supplied tool"
    }
    fn parameters_schema(&self) -> serde_json::Value {
        serde_json::json!({"type": "object"})
    }
    async fn execute(&self, _args: serde_json::Value) -> anyhow::Result<ToolResult> {
        Ok(ToolResult {
            success: true,
            output: ToolOutput::default(),
            error: None,
        })
    }
}

/// Supplies one tool; `native` also selects the native compatibility recipe.
struct TrapTools {
    native: bool,
}

impl ToolSource for TrapTools {
    fn native_recipe<'s>(
        &'s self,
        _request: &ToolRequest<'_>,
    ) -> anyhow::Result<Option<&'s super::NativeRegistryRecipe>> {
        Ok(self
            .native
            .then_some(&super::defaults::native_compat_registry))
    }

    fn tools(&self, _request: &ToolRequest<'_>) -> anyhow::Result<Vec<Box<dyn Tool>>> {
        Ok(vec![Box::new(SourceTool)])
    }
}

/// Answers every chat and records each system prompt it was sent.
struct PromptProvider(Arc<Mutex<Vec<String>>>);

impl zeroclaw_api::attribution::Attributable for PromptProvider {
    fn role(&self) -> zeroclaw_api::attribution::Role {
        zeroclaw_api::attribution::Role::Provider(zeroclaw_api::attribution::ProviderKind::Model(
            zeroclaw_api::attribution::ModelProviderKind::Custom,
        ))
    }
    fn alias(&self) -> &str {
        "trap"
    }
}

#[async_trait]
impl ModelProvider for PromptProvider {
    async fn chat_with_system(
        &self,
        system_prompt: Option<&str>,
        _message: &str,
        _model: &str,
        _temperature: Option<f64>,
    ) -> anyhow::Result<String> {
        self.0.lock().push(system_prompt.unwrap_or_default().to_string());
        Ok(REPLY.into())
    }

    async fn chat(
        &self,
        request: ChatRequest<'_>,
        _model: &str,
        _temperature: Option<f64>,
    ) -> anyhow::Result<ChatResponse> {
        let system = request
            .messages
            .iter()
            .filter(|message| message.role == "system")
            .map(|message| message.content.clone())
            .collect::<Vec<_>>()
            .join("\n");
        self.0.lock().push(system);
        Ok(ChatResponse {
            text: Some(REPLY.into()),
            tool_calls: Vec::new(),
            usage: None,
            reasoning_content: None,
        })
    }
}

struct PromptProviders(Arc<Mutex<Vec<String>>>);

impl ProviderSource for PromptProviders {
    fn model_provider(
        &self,
        _request: &ProviderRequest<'_>,
    ) -> anyhow::Result<Arc<dyn ModelProvider>> {
        Ok(Arc::new(PromptProvider(Arc::clone(&self.0))))
    }
}

fn trap_capabilities(native: bool, prompts: &Arc<Mutex<Vec<String>>>) -> RuntimeCapabilities {
    let mut capabilities = recording_capabilities(
        Arc::new(RecordingProviders::default()),
        Arc::new(RecordingMemory::default()),
        Arc::new(TrapTools { native }),
    );
    capabilities.providers = Arc::new(PromptProviders(Arc::clone(prompts)));
    capabilities
}

/// What one entry point left behind.
struct Evidence {
    mcp_launched: bool,
    peripheral_loads: usize,
    /// The prompts the turn sent, or the agent's prompt, when the entry point
    /// produces one; `None` for entry points that only assemble a registry.
    prompts: Option<Vec<String>>,
    /// The assembled registry's names, for entry points that return one.
    tools: Option<Vec<String>>,
}

impl Evidence {
    fn skill_loaded(&self, traps: &NativeTraps) -> bool {
        self.prompts
            .as_ref()
            .is_some_and(|prompts| prompts.iter().any(|prompt| traps.skill_in(prompt)))
    }

    fn assert_supplied_only(&self, traps: &NativeTraps, entry: &str) {
        assert!(!self.mcp_launched, "{entry}: a supplied-only build launched the MCP server");
        assert_eq!(
            self.peripheral_loads, 0,
            "{entry}: a supplied-only build loaded peripherals"
        );
        assert!(
            !self.skill_loaded(traps),
            "{entry}: a supplied-only build loaded workspace skills"
        );
        if let Some(tools) = &self.tools {
            assert_eq!(
                tools,
                &[SOURCE_TOOL.to_string()],
                "{entry}: the supplied vector is the whole registry"
            );
        }
    }
}

/// Run `entry` against a trapped config with the given recipe choice.
async fn exercise(entry: &str, native: bool) -> (Evidence, NativeTraps, tempfile::TempDir) {
    let root = tempfile::TempDir::new().unwrap();
    let mut config = trap_config(root.path());
    let traps = NativeTraps::arm(&mut config, root.path());
    let prompts = Arc::new(Mutex::new(Vec::new()));
    let capabilities = trap_capabilities(native, &prompts);
    let (prompt_entry, tools) = match entry {
        "agent" => {
            let agent = crate::agent::agent::Agent::from_config_with_capabilities(
                &config,
                AGENT,
                &capabilities,
                None,
            )
            .await
            .expect("the agent builds");
            prompts
                .lock()
                .push(agent.system_prompt_for_test().expect("the agent prompt renders"));
            let tools = agent.tool_names().into_iter().map(str::to_string).collect();
            (true, Some(tools))
        }
        "run" => {
            let reply = crate::agent::loop_::run_with_capabilities(
                config,
                capabilities,
                None,
                AGENT,
                Some("hello".into()),
                None,
                None,
                None,
                Vec::new(),
                false,
                None,
                None,
                TurnOrigin::Interactive,
                crate::agent::loop_::AgentRunOverrides::default(),
            )
            .await
            .expect("the CLI turn runs");
            assert_eq!(reply, REPLY);
            (true, None)
        }
        "process_message" => {
            let reply = crate::agent::loop_::process_message_with_capabilities(
                Arc::new(config),
                capabilities,
                None,
                AGENT,
                "hello",
                None,
                TurnOrigin::SubTurn,
                None,
            )
            .await
            .expect("the message turn runs");
            assert_eq!(reply, REPLY);
            (true, None)
        }
        "owned_sop" => {
            let engine = Arc::new(std::sync::Mutex::new(crate::sop::SopEngine::new(
                zeroclaw_config::schema::SopConfig::default(),
            )));
            let owned = crate::agent::turn::assemble_owned_execution_with_capabilities(
                &config,
                None,
                &capabilities,
                None,
                AGENT,
                engine,
                None,
                None,
                None,
            )
            .await
            .expect("the owned SOP step assembles");
            let tools = owned
                .tools_registry
                .iter()
                .map(|tool| tool.name().to_string())
                .collect();
            (false, Some(tools))
        }
        "independent_delegate" => {
            let config = Arc::new(config);
            let policy = Arc::new(
                zeroclaw_config::policy::SecurityPolicy::for_agent(&config, AGENT)
                    .expect("trap policy resolves"),
            );
            let delegate = crate::tools::delegate::DelegateTool::new(
                config.agents.clone(),
                None,
                Arc::clone(&policy),
            )
            .with_root_config(Arc::clone(&config))
            .with_caller_alias(AGENT)
            .with_runtime(Arc::new(crate::platform::NativeRuntime::new()))
            .with_capabilities(capabilities, None);
            let target = delegate
                .independent_agentic_tools_for_target(AGENT, policy)
                .await
                .expect("the independent target registry builds");
            let tools = target
                .tools
                .iter()
                .map(|tool| tool.name().to_string())
                .collect();
            (false, Some(tools))
        }
        _ => unreachable!("unknown entry point"),
    };
    let evidence = Evidence {
        mcp_launched: traps.mcp_launched(),
        peripheral_loads: traps.peripheral_loads(),
        prompts: prompt_entry.then(|| prompts.lock().clone()),
        tools,
    };
    (evidence, traps, root)
}

async fn supplied_only(entry: &str) {
    let (evidence, traps, _root) = exercise(entry, false).await;
    evidence.assert_supplied_only(&traps, entry);
}

#[tokio::test]
async fn supplied_only_agent_constructs_no_native_integration() {
    supplied_only("agent").await;
}

#[tokio::test]
async fn supplied_only_cli_turn_constructs_no_native_integration() {
    supplied_only("run").await;
}

#[tokio::test]
async fn supplied_only_process_message_constructs_no_native_integration() {
    supplied_only("process_message").await;
}

#[tokio::test]
async fn supplied_only_owned_sop_step_constructs_no_native_integration() {
    supplied_only("owned_sop").await;
}

#[tokio::test]
async fn supplied_only_independent_delegate_constructs_no_native_integration() {
    supplied_only("independent_delegate").await;
}

/// The same builds with the native recipe trip every trap that entry point
/// can reach, so the supplied-only tests above are not passing vacuously.
#[tokio::test]
async fn native_recipe_trips_the_construction_traps() {
    for (entry, peripherals, skills) in [
        ("agent", false, true),
        ("run", true, true),
        ("process_message", true, true),
        ("owned_sop", false, false),
        ("independent_delegate", false, false),
    ] {
        let (evidence, traps, _root) = exercise(entry, true).await;
        assert!(evidence.mcp_launched, "{entry}: the MCP trap did not fire");
        if peripherals {
            assert!(
                evidence.peripheral_loads > 0,
                "{entry}: the peripheral trap did not fire"
            );
        }
        if skills {
            assert!(
                evidence.skill_loaded(&traps),
                "{entry}: the skills trap did not fire"
            );
        }
    }
}
