//! Supported recovery relocates bytes without changing admission or authority.

use zeroclaw_config::schema::v2::{
    migrate_v2_to_v3_install_filesystem, workspace_toplevel_v3_path,
};
use zeroclaw_config::schema::{Config, PluginsConfig, legacy_plugin_dirs_with_entries};
use zeroclaw_plugins::error::PluginError;
use zeroclaw_plugins::host::{PluginHost, migrate_plugins_dir};
use zeroclaw_plugins::signature::SignatureMode;

fn package(root: &std::path::Path, name: &str, payload: &str) {
    std::fs::create_dir_all(root.join(name)).unwrap();
    std::fs::write(
        root.join(name).join("manifest.toml"),
        format!("name = \"{name}\"\n"),
    )
    .unwrap();
    std::fs::write(root.join(name).join("payload"), payload).unwrap();
}

#[test]
fn migrated_workspace_packages_reach_recovery_without_clobber_or_admission() {
    let tmp = tempfile::tempdir().unwrap();
    let install = tmp.path().join("install");
    let target = tmp.path().join("current-plugins");
    let config = Config {
        config_path: install.join("config.toml"),
        data_dir: install.join("data"),
        plugins: PluginsConfig {
            plugins_dir: target.to_string_lossy().into_owned(),
            ..Default::default()
        },
        ..Default::default()
    };
    let authority = serde_json::to_value(&config.plugins).unwrap();
    let source = install.join("data/plugins");
    let legacy = install.join("workspace/plugins");
    package(&legacy, "alpha", "recoverable-bytes");
    package(&legacy, "beta", "legacy-beta");
    let report = migrate_v2_to_v3_install_filesystem(&install).unwrap();
    assert!(report.entries_relocated > 0);
    let backup = report.backup_dir.unwrap().join("legacy-workspace/plugins");
    assert_eq!(
        std::fs::read(backup.join("alpha/payload")).unwrap(),
        b"recoverable-bytes"
    );
    assert_eq!(
        std::fs::read(source.join("alpha/payload")).unwrap(),
        b"recoverable-bytes"
    );
    assert_eq!(workspace_toplevel_v3_path(&install, "plugins"), source);
    assert!(!install.join("agents/default/workspace/plugins").exists());
    package(&target, "beta", "operator-beta");
    let recovery = legacy_plugin_dirs_with_entries(&config);
    assert_eq!(recovery, vec![source.clone()]);
    let moved: usize = recovery
        .iter()
        .map(|dir| migrate_plugins_dir(dir, &target).unwrap())
        .sum();
    assert_eq!(moved, 1);
    assert_eq!(
        std::fs::read(target.join("alpha/payload")).unwrap(),
        b"recoverable-bytes"
    );
    assert_eq!(
        std::fs::read(target.join("beta/payload")).unwrap(),
        b"operator-beta"
    );
    assert_eq!(
        std::fs::read(source.join("beta/payload")).unwrap(),
        b"legacy-beta"
    );
    assert!(!source.join("alpha").exists());
    assert_eq!(serde_json::to_value(&config.plugins).unwrap(), authority);
    // Recovery finds and relocates directories. These deliberately incomplete
    // manifests still fail the existing host parser, even with signing disabled.
    assert!(
        PluginHost::from_plugins_dir(&target)
            .unwrap()
            .list_plugins()
            .is_empty()
    );
    assert_eq!(migrate_plugins_dir(&source, &target).unwrap(), 0);
}

fn historical_config(install: &std::path::Path, target: &std::path::Path) -> Config {
    Config {
        config_path: install.join("config.toml"),
        data_dir: install.join("data"),
        plugins: PluginsConfig {
            plugins_dir: target.to_string_lossy().into_owned(),
            ..Default::default()
        },
        ..Default::default()
    }
}

fn skill_package(root: &std::path::Path, name: &str) -> std::path::PathBuf {
    let dir = root.join(name);
    std::fs::create_dir_all(dir.join("skills/fixture")).unwrap();
    std::fs::write(
        dir.join("manifest.toml"),
        format!("name = \"{name}\"\nversion = \"0.1.0\"\ncapabilities = [\"skill\"]\n"),
    )
    .unwrap();
    std::fs::write(
        dir.join("skills/fixture/SKILL.md"),
        "---\nname: fixture\ndescription: Selected fixture skill\n---\n# Selected skill\n",
    )
    .unwrap();
    dir
}

/// Constructed prior-layout contents are not automatically selected, even
/// when a compatible package appears after the resolver ran.
#[test]
fn historical_agent_workspace_is_not_a_directory_wide_migration_source() {
    let tmp = tempfile::tempdir().unwrap();
    let install = tmp.path().join("install");
    let target = tmp.path().join("managed");
    let config = historical_config(&install, &target);
    let live = config.agent_workspace_dir("default").join("plugins");
    let selected = skill_package(&live, "historical");
    let before = std::fs::read(selected.join("manifest.toml")).unwrap();
    let authority = serde_json::to_value(&config.plugins).unwrap();
    let recovery = legacy_plugin_dirs_with_entries(&config);
    let inserted = skill_package(&live, "inserted");
    let moved: usize = recovery
        .iter()
        .map(|source| migrate_plugins_dir(source, &target).unwrap())
        .sum();
    assert!(recovery.is_empty());
    assert_eq!(moved, 0);
    assert!(!target.join("historical").exists());
    assert!(!target.join("inserted").exists());
    assert_eq!(
        std::fs::read(selected.join("manifest.toml")).unwrap(),
        before
    );
    assert!(inserted.join("skills/fixture/SKILL.md").is_file());
    assert_eq!(serde_json::to_value(&config.plugins).unwrap(), authority);
}

/// This reaches the host admission/install boundary used by the existing CLI.
/// It does not exercise the CLI's WASM load gate or config/grant seeding.
#[test]
fn explicit_historical_install_adopts_only_the_selected_compatible_package() {
    let tmp = tempfile::tempdir().unwrap();
    let install = tmp.path().join("install");
    let target = tmp.path().join("managed");
    let config = historical_config(&install, &target);
    let live = config.agent_workspace_dir("default").join("plugins");
    let selected = skill_package(&live, "selected");
    let sibling = skill_package(&live, "unselected");
    let source_manifest = std::fs::read(selected.join("manifest.toml")).unwrap();
    let source_skill = std::fs::read(selected.join("skills/fixture/SKILL.md")).unwrap();
    assert!(legacy_plugin_dirs_with_entries(&config).is_empty());

    let mut host = PluginHost::from_plugins_dir_with_security(
        &config.plugins.resolved_plugins_dir(),
        PluginHost::resolve_signature_mode(&config.plugins.security.signature_mode),
        config.plugins.security.trusted_publisher_keys.clone(),
    )
    .unwrap();
    let admitted = host.admit_source(selected.to_str().unwrap()).unwrap();
    assert!(admitted.component().is_none());
    assert_eq!(host.install_admitted(admitted).unwrap(), "selected");
    assert_eq!(
        std::fs::read(target.join("selected/manifest.toml")).unwrap(),
        source_manifest
    );
    assert_eq!(
        std::fs::read(target.join("selected/skills/fixture/SKILL.md")).unwrap(),
        source_skill
    );
    assert_eq!(
        std::fs::read(selected.join("manifest.toml")).unwrap(),
        source_manifest
    );
    assert_eq!(
        std::fs::read(selected.join("skills/fixture/SKILL.md")).unwrap(),
        source_skill
    );
    assert!(sibling.join("manifest.toml").is_file());
    assert!(!target.join("unselected").exists());
    assert!(matches!(
        host.admit_source(selected.to_str().unwrap()),
        Err(PluginError::AlreadyLoaded(_))
    ));
    assert_eq!(
        std::fs::read(target.join("selected/manifest.toml")).unwrap(),
        source_manifest
    );

    package(&live, "incomplete", "unsupported-legacy-payload");
    assert!(
        host.admit_source(live.join("incomplete").to_str().unwrap())
            .is_err()
    );
    assert!(!target.join("incomplete").exists());
    assert_eq!(
        std::fs::read(live.join("incomplete/payload")).unwrap(),
        b"unsupported-legacy-payload"
    );
}

#[test]
fn explicit_historical_install_preserves_strict_signature_refusal() {
    let tmp = tempfile::tempdir().unwrap();
    let install = tmp.path().join("install");
    let target = tmp.path().join("managed");
    let mut config = historical_config(&install, &target);
    config.plugins.security.signature_mode = "strict".into();
    let source = skill_package(
        &config.agent_workspace_dir("default").join("plugins"),
        "unsigned",
    );
    let before = std::fs::read(source.join("manifest.toml")).unwrap();
    let mode = PluginHost::resolve_signature_mode(&config.plugins.security.signature_mode);
    assert!(matches!(mode, SignatureMode::Strict));
    let host = PluginHost::from_plugins_dir_with_security(
        &config.plugins.resolved_plugins_dir(),
        mode,
        config.plugins.security.trusted_publisher_keys.clone(),
    )
    .unwrap();
    assert!(matches!(
        host.admit_source(source.to_str().unwrap()),
        Err(PluginError::UnsignedPlugin(_))
    ));
    assert!(host.list_plugins().is_empty());
    assert!(!target.join("unsigned").exists());
    assert_eq!(std::fs::read(source.join("manifest.toml")).unwrap(), before);
}
