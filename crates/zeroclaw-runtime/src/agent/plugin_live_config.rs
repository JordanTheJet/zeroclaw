//! Regression: plugin tools built by a **live-config** Agent must resolve their
//! `[plugins.entries.config]` section from the daemon's shared handle on every
//! invocation, not from the startup snapshot.
//!
//! The focused resolver test in `crate::tools` proves the resolver honours a
//! live handle *when one is supplied*. It cannot prove the production Agent
//! supplies it: `from_config_with_session_cwd_and_mcp_approval_mode` accepts a
//! `live_config` handle for the daemon-backed constructors and then builds the
//! tool registry. If that call drops the handle, the resolver silently captures
//! the fallback `Arc<Config>` snapshot and a reload or credential rotation never
//! reaches an already-constructed plugin tool.
//!
//! So this test drives the real constructor
//! ([`Agent::from_live_config_with_tui_env`]) against a real component, mutates
//! the canonical instance entry through the live handle *after* the tools are
//! built, and asserts the next execution observes the new value.
//!
//! The component is the in-tree `zeroclaw-plugins` tool fixture, built on demand
//! into a separate target directory so the nested Cargo invocation cannot
//! contend with the host test process's build lock. There is no skip path: a
//! fixture that cannot be built is a test failure, matching the plugin crate's
//! own component tests.

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, OnceLock};

use parking_lot::RwLock;
use tempfile::TempDir;
use zeroclaw_config::schema::{AliasedAgentConfig, Config, PluginEntryConfig, RiskProfileConfig};
use zeroclaw_plugins::instance::PluginInstanceScope;
use zeroclaw_plugins::{PluginCapability, PluginManifest};

use super::Agent;

/// The fixture package's manifest: the single source of truth for both the
/// seeded `manifest.toml` and the instance key its config entry is stored
/// under. Kept byte-identical to the plugin crate's own fixture manifest so the
/// two suites describe the same installed plugin.
const FIXTURE_MANIFEST: &str = r#"name = "tool-fixture"
version = "0.0.0"
wasm_path = "tool-fixture.wasm"
capabilities = ["tool"]
permissions = ["config_read"]

[config_schema]
"$schema" = "https://json-schema.org/draft/2020-12/schema"
type = "object"
additionalProperties = false

[config_schema.properties.label]
type = "string"

[config_schema.properties.max_len]
type = "integer"

[config_schema.properties.uppercase]
type = "boolean"
"#;

/// Where the nested fixture build writes its artifacts.
///
/// `CARGO_TARGET_TMPDIR` only exists for integration-test and bench targets;
/// this regression has to live beside the Agent so it can read the constructed
/// tool registry, so fall back to the workspace `target/` directory rather than
/// rebuilding into a fresh temp dir on every run.
fn fixture_target_dir() -> PathBuf {
    let root = match option_env!("CARGO_TARGET_TMPDIR") {
        Some(dir) => PathBuf::from(dir),
        None => match std::env::var_os("CARGO_TARGET_DIR") {
            Some(dir) => PathBuf::from(dir),
            None => PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target"),
        },
    };
    root.join("tool-plugin-fixture-live-config")
}

/// Build the in-tree tool fixture once per test binary and return its component.
fn fixture() -> PathBuf {
    static FIXTURE: OnceLock<PathBuf> = OnceLock::new();
    FIXTURE
        .get_or_init(|| {
            let fixture_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../zeroclaw-plugins/tests/fixtures/tool-fixture");
            let target_dir = fixture_target_dir();
            let status = Command::new(env!("CARGO"))
                .current_dir(&fixture_dir)
                .args([
                    "build",
                    "--locked",
                    "--quiet",
                    "--package",
                    "zeroclaw-tool-plugin-fixture",
                    "--target",
                    "wasm32-wasip2",
                    "--target-dir",
                ])
                .arg(&target_dir)
                .status()
                .expect("run Cargo for the tool component fixture");
            assert!(
                status.success(),
                "tool fixture must build; install the wasm32-wasip2 target"
            );

            let wasm = target_dir.join("wasm32-wasip2/debug/zeroclaw_tool_plugin_fixture.wasm");
            assert!(wasm.is_file(), "tool fixture WASM was not produced");
            wasm
        })
        .clone()
}

/// Lay out a plugins dir the way `zeroclaw plugin install` does, and return the
/// canonical instance key the operator's config section must be stored under.
fn install_fixture_plugin(plugins_root: &std::path::Path) -> String {
    let plugin_dir = plugins_root.join("tool-fixture");
    std::fs::create_dir_all(&plugin_dir).expect("create plugin package dir");
    std::fs::copy(fixture(), plugin_dir.join("tool-fixture.wasm")).expect("install fixture wasm");
    std::fs::write(plugin_dir.join("manifest.toml"), FIXTURE_MANIFEST).expect("write manifest");

    let manifest: PluginManifest =
        toml::from_str(FIXTURE_MANIFEST).expect("fixture manifest parses");
    // The same admission the production registry performs, so the key below is
    // the one `plugin_config_resolver` will look up.
    let scope = PluginInstanceScope::for_package_binding(
        &manifest,
        PluginCapability::Tool,
        manifest.permissions.iter().copied(),
    )
    .expect("fixture manifest admits its declared permissions");
    scope
        .id()
        .config_entry_key()
        .expect("fixture instance key is derivable")
}

/// A config that boots one agent with the fixture plugin installed and its
/// canonical section set to `label`.
fn live_agent_config(tmp: &TempDir, plugins_root: &std::path::Path, instance_key: &str) -> Config {
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&data_dir).expect("create data dir");

    let mut config = Config {
        data_dir,
        config_path: tmp.path().join("config.toml"),
        ..Config::default()
    };
    {
        let entry = config
            .providers
            .models
            .ensure("custom", "default")
            .expect("custom model_provider type slot");
        // Never called: this regression exercises tool construction and
        // execution, not a turn.
        entry.api_key = Some("test-key".to_string());
        entry.model = Some("test-model".to_string());
        entry.uri = Some("http://127.0.0.1:9".to_string());
    }
    config.memory.backend = "none".to_string();
    config.memory.auto_save = false;
    config
        .risk_profiles
        .insert("test-profile".to_string(), RiskProfileConfig::default());
    config.agents.insert(
        "plugin-agent".to_string(),
        AliasedAgentConfig {
            model_provider: "custom.default".into(),
            risk_profile: "test-profile".into(),
            ..AliasedAgentConfig::default()
        },
    );

    config.plugins.enabled = true;
    config.plugins.plugins_dir = plugins_root.display().to_string();
    config.plugins.entries = vec![PluginEntryConfig {
        name: instance_key.to_string(),
        config: HashMap::from([
            ("label".to_string(), "before-reload".to_string()),
            ("uppercase".to_string(), "false".to_string()),
            ("max_len".to_string(), "0".to_string()),
        ]),
        egress_hosts: Vec::new(),
        egress_allow_private: Vec::new(),
    }];
    config
}

#[tokio::test]
async fn live_agent_plugin_tool_observes_config_reload_after_construction() {
    let tmp = TempDir::new().expect("temp dir");
    let plugins_root = tmp.path().join("plugins");
    let instance_key = install_fixture_plugin(&plugins_root);
    let config = live_agent_config(&tmp, &plugins_root, &instance_key);

    // The daemon's canonical handle. Everything after this point goes through
    // the production live-Agent constructor.
    let live = Arc::new(RwLock::new(config));
    let agent = Agent::from_live_config_with_tui_env(
        Arc::clone(&live),
        "plugin-agent",
        None,
        // No MCP: this test is about plugin config, and connecting MCP servers
        // would be unrelated I/O.
        false,
        false,
        None,
        None,
        None,
    )
    .await
    .expect("build a live-config Agent with the fixture plugin installed");

    let tool = agent
        .tools
        .iter()
        .find(|tool| tool.name() == "config-echo")
        .expect(
            "the fixture tool plugin must be registered on the Agent; without it this \
             regression cannot observe plugin config resolution at all",
        );

    let before = tool
        .execute(serde_json::json!({"text": "hello world"}))
        .await
        .expect("first plugin execution");
    assert!(before.success, "first plugin execution failed: {before:?}");
    assert_eq!(
        before.output.as_str(),
        "label=before-reload|uppercase=false|max_len=0|keys=3|text=hello world",
        "the plugin must observe the operator's section as configured at startup"
    );

    // A reload / credential rotation: the canonical instance entry changes in
    // the shared handle, with no Agent rebuild and no new tool registry.
    live.write()
        .plugins
        .entries
        .iter_mut()
        .find(|entry| entry.name == instance_key)
        .expect("the canonical instance entry is present in the live config")
        .config
        .insert("label".to_string(), "after-reload".to_string());

    let after = tool
        .execute(serde_json::json!({"text": "hello world"}))
        .await
        .expect("second plugin execution");
    assert!(after.success, "second plugin execution failed: {after:?}");
    assert_eq!(
        after.output.as_str(),
        "label=after-reload|uppercase=false|max_len=0|keys=3|text=hello world",
        "an already-constructed plugin tool must resolve config from the live handle \
         on every call; observing the startup value means the live-Agent constructor \
         dropped the handle when it built the tool registry"
    );
}
