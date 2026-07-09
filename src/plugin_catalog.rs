//! CLI-side gathering + rendering of the unified capability catalog.
//!
//! This is the thin "seed gathering" layer for the terminal: it reads the three
//! sources available to the binary — compiled-in channels
//! ([`zeroclaw_channels::listing`]), installed plugins ([`PluginHost`]), and the
//! cached registry — maps them to the neutral seeds in
//! [`zeroclaw_plugins::catalog`], and calls the shared
//! [`merge_capabilities`](zeroclaw_plugins::catalog::merge_capabilities). The
//! merge/dedup/precedence logic itself lives once in `zeroclaw-plugins`, so the
//! gateway and zerocode surfaces resolve capabilities identically.

use serde_json::Value;
use zeroclaw_config::schema::{ActiveChannelAliases, Config};
use zeroclaw_plugins::catalog::{
    BuiltinSeed, CapabilityCatalogEntry, CapabilityKind, CapabilityOrigin, available_seeds,
    installed_seeds, merge_capabilities,
};
use zeroclaw_plugins::host::PluginHost;
use zeroclaw_runtime::i18n::{get_required_cli_string, get_required_cli_string_with_args};

/// Build the unified catalog from the binary's three capability sources. `all`
/// includes every compiled-in channel; otherwise only configured
/// built-ins are seeded so the default view stays focused on operator intent or
/// installable.
pub fn gather(config: &Config, host: &PluginHost, all: bool) -> Vec<CapabilityCatalogEntry> {
    // Per-channel-type: is any configured alias enabled? Read the serialized
    // channels tree (the same view the mirror runtime uses) so we don't hand-map
    // every channel struct's `enabled` field.
    // ── Built-in channels ──────────────────────────────────────────────────
    let compiled = zeroclaw_channels::listing::compiled_channels(&config.channels)
        .into_iter()
        .filter(|ci| all || ci.configured)
        .map(|ci| (ci, true));
    // Configured but not compiled into this binary — candidates a plugin can
    // mirror. Always shown (the operator configured them).
    let uncompiled = zeroclaw_channels::listing::configured_uncompiled_channels(&config.channels)
        .into_iter()
        .map(|ci| (ci, false));
    let mut builtins_by_id = std::collections::BTreeMap::<String, BuiltinSeed>::new();
    for (ci, compiled) in compiled.chain(uncompiled) {
        let id = zeroclaw_channels::listing::canonical_channel_type(&config.channels, ci.kind)
            .unwrap_or(ci.kind)
            .to_string();
        let configured = channel_type_configured(config, &id);
        builtins_by_id
            .entry(id.clone())
            .and_modify(|seed| {
                seed.compiled |= compiled;
                seed.configured |= configured;
                seed.toggleable |= ci.configured;
            })
            .or_insert_with(|| BuiltinSeed {
                id,
                kind: CapabilityKind::Channel,
                display: Some(ci.name.to_string()),
                description: Some(ci.desc.to_string()),
                compiled,
                configured,
                toggleable: ci.configured,
            });
    }
    let builtins = builtins_by_id.into_values().collect();

    // ── Installed plugins ──────────────────────────────────────────────────
    let plugins_configured = config.plugins.enabled;
    let active_channels = ActiveChannelAliases::compute(config);
    let installed = installed_seeds(
        host,
        plugins_configured,
        |id, mirrors_builtin| {
            if mirrors_builtin {
                channel_type_configured(config, id)
            } else {
                active_channels.contains(id)
            }
        },
        |id, mirrors_builtin| {
            mirrors_builtin && !channel_aliases(config, id).is_empty()
        },
    );

    // ── Registry-available ─────────────────────────────────────────────────
    // ── Installed plugins + registry (shared folding) ──────────────────────
    let cached_index =
        match zeroclaw_plugins::registry::read_cached_registry_index(&config.data_dir) {
            Ok(index) => index,
            Err(error) => {
                let error = error.to_string();
                eprintln!(
                    "{}",
                    get_required_cli_string_with_args(
                        "cli-plugin-catalog-cache-failed",
                        &[("error", error.as_str())],
                    )
                );
                None
            }
        };
    let available = cached_index
        .map(|index| available_seeds(&index))
        .unwrap_or_default();

    merge_capabilities(builtins, installed, available)
}

// ── enable / disable ──────────────────────────────────────────────────────────

/// Configured aliases for a channel type, read from the serialized channels tree
/// (the keys of `[channels.<type>]`).
pub fn channel_aliases(config: &Config, channel_type: &str) -> Vec<String> {
    let channel_type =
        zeroclaw_channels::listing::canonical_channel_type(&config.channels, channel_type)
            .unwrap_or(channel_type);
    serde_json::to_value(&config.channels)
        .ok()
        .and_then(|v| {
            v.get(channel_type)
                .and_then(|m| m.as_object())
                .map(|o| o.keys().cloned().collect())
        })
        .unwrap_or_default()
}

/// Whether any configured alias in this canonical channel family is enabled.
/// This is an on-demand view over `Config.channels`, not stored catalog state.
fn channel_type_configured(config: &Config, channel_type: &str) -> bool {
    let channel_type =
        zeroclaw_channels::listing::canonical_channel_type(&config.channels, channel_type)
            .unwrap_or(channel_type);
    serde_json::to_value(&config.channels)
        .ok()
        .is_some_and(|value| {
            value
                .get(channel_type)
                .and_then(Value::as_object)
                .is_some_and(|aliases| {
                    aliases
                        .values()
                        .any(|alias| alias.get("enabled").and_then(Value::as_bool) == Some(true))
                })
        })
}

/// Whether `id` names a channel family in the canonical config schema.
pub fn is_channel_id(config: &Config, id: &str) -> bool {
    zeroclaw_channels::listing::canonical_channel_type(&config.channels, id).is_some()
}

/// Whether an installed plugin serves this channel id (mirror via `provides`, or
/// a novel channel plugin named `id`), so enabling it must also turn the plugin
/// subsystem on.
fn channel_is_plugin_backed(host: &PluginHost, id: &str) -> bool {
    host.channel_plugins().iter().any(|manifest| {
        manifest.provides.as_deref().map_or_else(
            || zeroclaw_api::channel::plugin_channel_ref(&manifest.name) == id,
            |provides| provides == id,
        )
    })
}

fn resolve_channel_targets(
    id: &str,
    aliases: &[String],
    requested_alias: Option<String>,
    enabled: bool,
) -> anyhow::Result<Option<Vec<String>>> {
    if let Some(alias) = requested_alias {
        if aliases.iter().any(|configured| configured == &alias) {
            return Ok(Some(vec![alias]));
        }
        let available = if aliases.is_empty() {
            get_required_cli_string("cli-plugin-aliases-none")
        } else {
            aliases.join(", ")
        };
        anyhow::bail!(get_required_cli_string_with_args(
            "cli-plugin-toggle-unknown-alias",
            &[
                ("id", id),
                ("alias", alias.as_str()),
                ("aliases", available.as_str()),
            ],
        ));
    }

    match aliases {
        [] if enabled => anyhow::bail!(get_required_cli_string_with_args(
            "cli-plugin-enable-none-configured",
            &[("id", id)],
        )),
        [] => Ok(None),
        [one] => Ok(Some(vec![one.clone()])),
        many => {
            let available = many.join(", ");
            anyhow::bail!(get_required_cli_string_with_args(
                "cli-plugin-toggle-multiple-aliases",
                &[("id", id), ("aliases", available.as_str())],
            ));
        }
    }
}

fn channel_toggle_paths(id: &str, aliases: &[String]) -> Vec<String> {
    aliases
        .iter()
        .map(|alias| format!("channels.{id}.{alias}.enabled"))
        .collect()
}

/// Flip a channel capability's config `enabled` (the SSOT — never a new
/// `[features]` table) and persist. v1 handles channels only; a novel tool/skill
/// plugin has no per-entry config toggle yet.
/// Resolves only existing aliases (0 → error/skip, 1 → auto, many → require
/// `--alias`) and turns the plugin subsystem on when enabling a plugin-backed
/// channel.
pub async fn set_capability_enabled(
    config: &mut Config,
    host: &PluginHost,
    id: &str,
    alias: Option<String>,
    enabled: bool,
) -> anyhow::Result<()> {
    let id = zeroclaw_channels::listing::canonical_channel_type(&config.channels, id).unwrap_or(id);
    let known_channel = is_channel_id(config, id);
    let plugin_backed = channel_is_plugin_backed(host, id);
    if !known_channel && !plugin_backed {
        anyhow::bail!(get_required_cli_string_with_args(
            "cli-plugin-toggle-not-channel",
            &[("id", id)],
        ));
    }
    if !known_channel {
        anyhow::bail!(get_required_cli_string_with_args(
            "cli-plugin-toggle-novel-channel",
            &[("id", id)],
        ));
    }

    let aliases = channel_aliases(config, id);
    let Some(targets) = resolve_channel_targets(id, &aliases, alias, enabled)? else {
        println!(
            "{}",
            get_required_cli_string_with_args("cli-plugin-disable-none-configured", &[("id", id)],)
        );
        return Ok(());
    };

    let val = if enabled { "true" } else { "false" };
    let mut changes: Vec<(String, String)> = Vec::new();
    for path in channel_toggle_paths(id, &targets) {
        config.set_prop_persistent(&path, val)?;
        changes.push((path, val.to_string()));
    }
    // A plugin-backed channel needs the plugin subsystem on to load at all.
    if enabled && plugin_backed && !config.plugins.enabled {
        config.set_prop_persistent("plugins.enabled", "true")?;
        changes.push(("plugins.enabled".to_string(), "true".to_string()));
    }

    // `save_dirty` pulls the whole Config into its future; box it to keep this
    // fn's future small (clippy::large_futures), matching the CLI `config set`.
    Box::pin(config.save_dirty()).await?;
    for (p, v) in &changes {
        println!(
            "  {}",
            get_required_cli_string_with_args(
                "cli-plugin-set-applied",
                &[("path", p.as_str()), ("value", v.as_str())],
            )
        );
    }
    println!("{}", get_required_cli_string("cli-plugin-reload-hint"));
    Ok(())
}

fn kind_label(k: &CapabilityKind) -> String {
    get_required_cli_string(match k {
        CapabilityKind::Channel => "cli-plugin-kind-channels",
        CapabilityKind::Tool => "cli-plugin-kind-tools",
        CapabilityKind::Memory => "cli-plugin-kind-memory",
        CapabilityKind::Observer => "cli-plugin-kind-observers",
        CapabilityKind::Skill => "cli-plugin-kind-skills",
        CapabilityKind::Other(_) => "cli-plugin-kind-other",
    })
}

/// The `origin`/flags rendered as a compact source label, e.g. `built-in`,
/// `built-in + plugin`, `plugin`, or `available`.
fn source_label(e: &CapabilityCatalogEntry) -> String {
    if e.conflicted {
        return get_required_cli_string("cli-plugin-source-conflict");
    }
    get_required_cli_string(match e.origin {
        CapabilityOrigin::BuiltIn if e.installed => "cli-plugin-source-builtin-plugin",
        CapabilityOrigin::BuiltIn => "cli-plugin-source-builtin",
        CapabilityOrigin::Plugin if e.mirrors_builtin => "cli-plugin-source-plugin-mirror",
        CapabilityOrigin::Plugin => "cli-plugin-source-plugin",
        CapabilityOrigin::Registry => "cli-plugin-source-available",
    })
}

/// Print the catalog as a grouped table to stdout.
pub fn render(entries: &[CapabilityCatalogEntry]) {
    if entries.is_empty() {
        println!("{}", get_required_cli_string("cli-plugin-catalog-empty"));
        return;
    }
    let mut current: Option<&CapabilityKind> = None;
    for e in entries {
        if current != Some(&e.kind) {
            println!("\n{}:", kind_label(&e.kind));
            current = Some(&e.kind);
        }
        // Status glyph: ● selected by config, ○ present but not selected,
        // · registry-only.
        let glyph = if e.configured {
            '●'
        } else if e.origin == CapabilityOrigin::Registry {
            '·'
        } else {
            '○'
        };
        let ver = e
            .version
            .as_deref()
            .map(|v| format!(" v{v}"))
            .unwrap_or_default();
        let plugin = e
            .plugin_name
            .as_deref()
            .filter(|n| Some(*n) != Some(e.id.as_str()))
            .map(|n| format!(" [{n}]"))
            .unwrap_or_default();
        println!(
            "  {glyph} {:<20} {:<18}{ver}{plugin}",
            e.id,
            source_label(e),
        );
    }
    println!("\n{}", get_required_cli_string("cli-plugin-catalog-legend"));
}

#[cfg(test)]
mod tests {
    use super::{
        channel_aliases, channel_toggle_paths, channel_type_configured, gather, is_channel_id,
        resolve_channel_targets, set_capability_enabled,
    };
    use zeroclaw_config::providers::ChannelRef;
    use zeroclaw_config::scattered_types::{GmailPushConfig, VoiceCallConfig};
    use zeroclaw_config::schema::{
        AliasedAgentConfig, Config, NextcloudTalkConfig, TelegramConfig, VoiceWakeConfig,
        WeComWsConfig, WhatsAppConfig,
    };
    use zeroclaw_plugins::host::PluginHost;
    use zeroclaw_plugins::registry::{
        PluginRegistryEntry, PluginRegistryIndex, write_cached_registry_index,
    };
    use zeroclaw_runtime::i18n::get_required_cli_string_with_args;

    fn aliases(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_string()).collect()
    }

    #[test]
    fn explicit_alias_must_already_exist() {
        let result = resolve_channel_targets(
            "telegram",
            &aliases(&["main"]),
            Some("typo".to_string()),
            true,
        );
        assert!(result.is_err(), "a typo must not create a new alias");
    }

    #[test]
    fn one_alias_is_selected_implicitly() {
        let targets = resolve_channel_targets("telegram", &aliases(&["main"]), None, true)
            .expect("one configured alias resolves")
            .expect("enable has a target");
        assert_eq!(targets, ["main"]);
    }

    #[test]
    fn multiple_aliases_require_an_explicit_choice() {
        let result =
            resolve_channel_targets("telegram", &aliases(&["main", "alerts"]), None, false);
        assert!(result.is_err());
    }

    #[test]
    fn disabling_an_unconfigured_channel_is_a_noop() {
        let targets = resolve_channel_targets("telegram", &[], None, false)
            .expect("disable without aliases is not an error");
        assert!(targets.is_none());
    }

    #[test]
    fn channel_identity_uses_canonical_schema_families() {
        let config = Config::default();
        assert!(is_channel_id(&config, "git"));
        assert!(is_channel_id(&config, "nextcloud"));
        assert!(is_channel_id(&config, "nextcloud_talk"));
        assert!(is_channel_id(&config, "whatsapp-web"));
        assert!(!is_channel_id(&config, "novel-plugin-channel"));
    }

    #[test]
    fn mismatched_inventory_ids_share_catalog_state_and_persistence_paths() {
        let temp = tempfile::tempdir().expect("temp plugin catalog directory");
        let mut config = Config {
            data_dir: temp.path().join("data"),
            ..Config::default()
        };
        let alias = "probe".to_string();

        config
            .channels
            .gmail_push
            .insert(alias.clone(), GmailPushConfig::default());
        config
            .channels
            .wecom_ws
            .insert(alias.clone(), WeComWsConfig::default());
        config
            .channels
            .voice_call
            .insert(alias.clone(), VoiceCallConfig::default());
        config
            .channels
            .voice_wake
            .insert(alias.clone(), VoiceWakeConfig::default());
        config
            .channels
            .nextcloud_talk
            .insert(alias.clone(), NextcloudTalkConfig::default());
        config
            .channels
            .whatsapp
            .insert(alias.clone(), WhatsAppConfig::default());
        config.channels.gmail_push.get_mut(&alias).unwrap().enabled = true;
        config.channels.wecom_ws.get_mut(&alias).unwrap().enabled = true;
        config.channels.voice_call.get_mut(&alias).unwrap().enabled = true;
        config.channels.voice_wake.get_mut(&alias).unwrap().enabled = true;
        config
            .channels
            .nextcloud_talk
            .get_mut(&alias)
            .unwrap()
            .enabled = true;
        config.channels.whatsapp.get_mut(&alias).unwrap().enabled = true;
        // Make the shared WhatsApp entry a Web implementation as well as a
        // canonical `[channels.whatsapp]` alias.
        config
            .channels
            .whatsapp
            .get_mut(&alias)
            .unwrap()
            .session_path = Some("session.db".to_string());

        let cases = [
            ("gmail-push", "gmail_push"),
            ("wecom-ws", "wecom_ws"),
            ("voice-call", "voice_call"),
            ("voice-wake", "voice_wake"),
            ("nextcloud", "nextcloud_talk"),
            ("whatsapp-web", "whatsapp"),
        ];
        for (inventory_id, canonical) in cases {
            assert!(channel_type_configured(&config, inventory_id));
            assert_eq!(
                channel_aliases(&config, inventory_id),
                std::slice::from_ref(&alias)
            );
            assert_eq!(
                channel_toggle_paths(canonical, std::slice::from_ref(&alias)),
                [format!("channels.{canonical}.{alias}.enabled")]
            );
        }

        let host = PluginHost::new(&temp.path().join("plugins")).expect("empty plugin host");
        let catalog = gather(&config, &host, true);
        for (_, canonical) in cases {
            assert_eq!(
                catalog.iter().filter(|entry| entry.id == canonical).count(),
                1,
                "{canonical} must merge into one catalog row"
            );
        }
        for (inventory_id, canonical) in cases {
            if inventory_id != canonical {
                assert!(
                    catalog.iter().all(|entry| entry.id != inventory_id),
                    "legacy/display id {inventory_id} must not become a second row"
                );
            }
        }
    }

    #[tokio::test]
    async fn novel_channel_configured_state_follows_global_flag_and_active_owner() {
        let temp = tempfile::tempdir().expect("temp plugin catalog directory");
        let plugin_dir = temp.path().join("plugins/novel-channel");
        std::fs::create_dir_all(&plugin_dir).unwrap();
        std::fs::write(
            plugin_dir.join("manifest.toml"),
            concat!(
                "name = \"novel-channel\"\n",
                "version = \"0.1.0\"\n",
                "capabilities = [\"channel\"]\n",
                "wasm_path = \"plugin.wasm\"\n",
            ),
        )
        .unwrap();
        std::fs::write(plugin_dir.join("plugin.wasm"), b"\0asm").unwrap();

        let host = PluginHost::new(temp.path()).expect("discover novel channel manifest");
        let mut config = Config {
            data_dir: temp.path().join("data"),
            ..Config::default()
        };
        let catalog = gather(&config, &host, true);
        let novel_id = zeroclaw_api::channel::plugin_channel_ref("novel-channel");
        let novel = catalog
            .iter()
            .find(|entry| entry.id == novel_id)
            .expect("novel channel is listed");
        assert!(!novel.toggleable);
        assert!(!novel.configured);

        config.plugins.enabled = true;
        let catalog = gather(&config, &host, true);
        let novel = catalog
            .iter()
            .find(|entry| entry.id == novel_id)
            .expect("novel channel remains listed");
        assert!(
            novel.configured,
            "legacy mode selects novel channels when plugins are enabled"
        );

        config.agents.insert(
            "alpha".to_string(),
            AliasedAgentConfig {
                channels: vec![ChannelRef::new("telegram.main")],
                ..AliasedAgentConfig::default()
            },
        );
        let catalog = gather(&config, &host, true);
        let novel = catalog
            .iter()
            .find(|entry| entry.id == novel_id)
            .expect("novel channel remains listed");
        assert!(
            !novel.configured,
            "an explicit unrelated binding ends legacy admission"
        );

        config
            .agents
            .get_mut("alpha")
            .expect("test agent")
            .channels
            .push(ChannelRef::new(novel_id.clone()));
        let catalog = gather(&config, &host, true);
        let novel = catalog
            .iter()
            .find(|entry| entry.id == novel_id)
            .expect("novel channel remains listed");
        assert!(
            novel.configured,
            "an enabled owner selects the novel channel"
        );

        config.agents.get_mut("alpha").expect("test agent").enabled = false;
        let catalog = gather(&config, &host, true);
        let novel = catalog
            .iter()
            .find(|entry| entry.id == novel_id)
            .expect("novel channel remains listed");
        assert!(
            !novel.configured,
            "a disabled owner does not select the novel channel"
        );
        config.agents.get_mut("alpha").expect("test agent").enabled = true;

        let error = set_capability_enabled(&mut config, &host, &novel_id, None, false)
            .await
            .expect_err("novel channel must not claim a typed per-channel toggle");
        assert_eq!(
            error.to_string(),
            get_required_cli_string_with_args(
                "cli-plugin-toggle-novel-channel",
                &[("id", novel_id.as_str())],
            )
        );
        assert!(config.plugins.enabled, "the failed toggle changes no state");
    }

    #[tokio::test]
    async fn novel_telegram_package_does_not_merge_with_or_toggle_typed_telegram() {
        let temp = tempfile::tempdir().expect("temp plugin catalog directory");
        let plugin_dir = temp.path().join("plugins/telegram");
        std::fs::create_dir_all(&plugin_dir).unwrap();
        std::fs::write(
            plugin_dir.join("manifest.toml"),
            concat!(
                "name = \"telegram\"\n",
                "version = \"0.1.0\"\n",
                "capabilities = [\"channel\"]\n",
                "wasm_path = \"plugin.wasm\"\n",
            ),
        )
        .unwrap();
        std::fs::write(plugin_dir.join("plugin.wasm"), b"\0asm").unwrap();

        let host = PluginHost::new(temp.path()).expect("discover novel telegram plugin");
        let mut config = Config {
            data_dir: temp.path().join("data"),
            ..Config::default()
        };
        config
            .channels
            .telegram
            .insert("main".to_string(), TelegramConfig::default());
        write_cached_registry_index(
            &config.data_dir,
            "https://example.invalid/registry.json",
            &PluginRegistryIndex {
                plugins: vec![PluginRegistryEntry {
                    name: "telegram".to_string(),
                    version: "0.1.0".to_string(),
                    description: Some("novel package".to_string()),
                    author: None,
                    capabilities: vec!["channel".to_string()],
                    provides: None,
                    sender_match: None,
                    url: "https://example.invalid/telegram.zip".to_string(),
                    sha256: None,
                }],
                registry_url: None,
            },
        )
        .expect("cache registry fixture");

        let catalog = gather(&config, &host, true);
        let novel_id = zeroclaw_api::channel::plugin_channel_ref("telegram");
        assert_eq!(
            catalog
                .iter()
                .filter(|entry| entry.id == "telegram")
                .count(),
            1,
            "typed Telegram keeps one canonical row"
        );
        let novel = catalog
            .iter()
            .find(|entry| entry.id == novel_id)
            .expect("installed and registry novel package share plugin.telegram");
        assert!(novel.installed && novel.available);
        assert!(!novel.toggleable);

        let error = set_capability_enabled(&mut config, &host, &novel_id, None, true)
            .await
            .expect_err("novel identity cannot toggle typed Telegram");
        assert_eq!(
            error.to_string(),
            get_required_cli_string_with_args(
                "cli-plugin-toggle-novel-channel",
                &[("id", novel_id.as_str())],
            )
        );
        assert!(!config.plugins.enabled);
        assert!(
            !config
                .channels
                .telegram
                .get("main")
                .expect("typed Telegram alias")
                .enabled
        );
    }
}
