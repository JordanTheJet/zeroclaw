use std::collections::BTreeSet;
use std::sync::Arc;

use tempfile::TempDir;
use zeroclaw_api::runtime_traits::RuntimeAdapter;
use zeroclaw_config::builtin_tools::CORE_TOOL_NAMES;
use zeroclaw_config::platform::NativeRuntime;
use zeroclaw_config::policy::SecurityPolicy;
use zeroclaw_config::schema::{AliasedAgentConfig, Config, RiskProfileConfig};
use zeroclaw_memory::{Memory, NoneMemory};
use zeroclaw_runtime::tools::scoped::{ScopedAssembled, ScopedAssembly, ScopedToolRegistry};

fn fixture(tmp: &TempDir) -> Config {
    let workspace = tmp.path().join("workspace");
    std::fs::create_dir_all(&workspace).unwrap();
    let mut config = Config {
        data_dir: tmp.path().join("data"),
        config_path: tmp.path().join("config.toml"),
        ..Config::default()
    };
    config.memory.backend = "none".into();
    config.plugins.enabled = false;
    config
        .agents
        .insert("boundary".into(), AliasedAgentConfig::default());
    config
        .providers
        .models
        .openai
        .insert("boundary".into(), Default::default());
    config.agents.get_mut("boundary").unwrap().model_provider = "openai.boundary".into();
    config.knowledge.db_path = tmp
        .path()
        .join("optional-knowledge.db")
        .display()
        .to_string();
    config
}

async fn assemble(
    tmp: &TempDir,
    config: &Config,
    allowed: Option<Vec<String>>,
    excluded: Option<Vec<String>>,
    caller_allowed: Option<&[String]>,
) -> ScopedAssembled {
    let workspace = tmp.path().join("workspace");
    let security = Arc::new(SecurityPolicy {
        workspace_dir: workspace.clone(),
        allowed_tools: allowed,
        excluded_tools: excluded,
        ..SecurityPolicy::default()
    });
    let runtime: Arc<dyn RuntimeAdapter> = Arc::new(NativeRuntime::new());
    let memory: Arc<dyn Memory> = Arc::new(NoneMemory::new("boundary"));
    let built = zeroclaw_runtime::tools::all_tools_with_runtime(
        Arc::new(config.clone()),
        &security,
        &RiskProfileConfig::default(),
        "boundary",
        Arc::clone(&runtime),
        memory,
        None,
        None,
        &config.browser,
        &config.http_request,
        &config.web_fetch,
        &workspace,
        &config.agents,
        None,
        config,
        None,
        false,
        None,
        None,
        None,
        None,
    )
    .unwrap();
    ScopedToolRegistry::assemble(ScopedAssembly {
        config,
        agent_alias: "boundary",
        security: &security,
        built,
        skills: &[],
        runtime,
        caller_allowed,
        connect_mcp: false,
        connect_peripherals: false,
        exclude_memory: false,
        acp_delivery: false,
        list_deferred_mcp_specs: false,
        emit_assembly_logs: false,
        mcp_registry: None,
    })
    .await
}

fn names(assembled: &ScopedAssembled) -> BTreeSet<String> {
    assembled
        .registry
        .iter()
        .map(|tool| tool.spec().name)
        .collect()
}

#[tokio::test]
async fn default_model_catalog_is_eleven_before_optional_store_preparation() {
    let tmp = TempDir::new().unwrap();
    let mut config = fixture(&tmp);
    config.knowledge.enabled = true;
    let assembled = assemble(&tmp, &config, None, None, None).await;

    assert!(
        !tmp.path().join("optional-knowledge.db").exists(),
        "unselected knowledge preparation must not open a store"
    );
    assert!(
        !config.data_dir.exists(),
        "unselected session tools must not open their shared store"
    );
    assert_eq!(
        names(&assembled),
        CORE_TOOL_NAMES
            .iter()
            .map(|name| (*name).to_string())
            .collect()
    );
    assert!(assembled.delegate_handle.is_none());
    assert!(assembled.ask_user_handle.is_none());
    assert!(assembled.poll_handle.is_none());
}

#[tokio::test]
async fn selected_calculator_executes_through_the_scoped_registry() {
    let tmp = TempDir::new().unwrap();
    let mut config = fixture(&tmp);
    config.tools.optional = vec!["calculator".into()];
    let assembled = assemble(&tmp, &config, None, None, None).await;
    let mut expected: BTreeSet<String> = CORE_TOOL_NAMES
        .iter()
        .map(|name| (*name).to_string())
        .collect();
    expected.insert("calculator".into());
    assert_eq!(names(&assembled), expected);
    let calculator = assembled
        .registry
        .iter()
        .find(|tool| tool.name() == "calculator")
        .unwrap();
    let result = calculator
        .execute(serde_json::json!({"function": "multiply", "values": [6, 7]}))
        .await
        .unwrap();
    assert!(result.success, "{result:?}");
    assert!(result.output.contains("42"), "{result:?}");
}

#[tokio::test]
async fn selection_never_expands_agent_or_caller_permission() {
    let tmp = TempDir::new().unwrap();
    let mut config = fixture(&tmp);
    config.tools.optional = vec!["calculator".into()];
    let shell_only = vec!["shell".to_string()];

    let agent_denied = assemble(&tmp, &config, Some(shell_only.clone()), None, None).await;
    assert_eq!(names(&agent_denied), BTreeSet::from(["shell".to_string()]));

    let caller_denied = assemble(&tmp, &config, None, None, Some(&shell_only)).await;
    assert_eq!(names(&caller_denied), BTreeSet::from(["shell".to_string()]));

    let excluded = assemble(&tmp, &config, None, Some(vec!["calculator".into()]), None).await;
    assert!(!names(&excluded).contains("calculator"));
    assert!(names(&excluded).contains("git_operations"));
}

#[tokio::test]
async fn selected_knowledge_still_requires_its_canonical_enabled_setting() {
    let tmp = TempDir::new().unwrap();
    let mut config = fixture(&tmp);
    config.tools.optional = vec!["knowledge".into()];
    config.knowledge.enabled = false;
    let inactive = assemble(&tmp, &config, None, None, None).await;
    assert!(!names(&inactive).contains("knowledge"));
    assert!(!tmp.path().join("optional-knowledge.db").exists());

    config.knowledge.enabled = true;
    let active = assemble(&tmp, &config, None, None, None).await;
    assert!(tmp.path().join("optional-knowledge.db").is_file());
    let knowledge = active
        .registry
        .iter()
        .find(|tool| tool.name() == "knowledge")
        .unwrap();
    let result = knowledge
        .execute(serde_json::json!({"action": "graph_stats"}))
        .await
        .unwrap();
    assert!(result.success, "{result:?}");
}
