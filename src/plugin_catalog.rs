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
use zeroclaw_config::schema::Config;
use zeroclaw_plugins::PluginPermission;
use zeroclaw_plugins::catalog::{
    AvailableSeed, BuiltinSeed, CapabilityCatalogEntry, CapabilityKind, CapabilityOrigin,
    InstalledSeed, merge_capabilities,
};
use zeroclaw_plugins::host::PluginHost;
use zeroclaw_runtime::i18n::{get_required_cli_string, get_required_cli_string_with_args};

fn perm_wire(p: &PluginPermission) -> String {
    serde_json::to_value(p)
        .ok()
        .and_then(|v| v.as_str().map(String::from))
        .unwrap_or_default()
}

/// Build the unified catalog from the binary's three capability sources. `all`
/// includes every compiled-in channel; otherwise only configured/active
/// built-ins are seeded so the default view stays focused on what's in use or
/// installable.
pub fn gather(config: &Config, host: &PluginHost, all: bool) -> Vec<CapabilityCatalogEntry> {
    // Per-channel-type: is any configured alias enabled? Read the serialized
    // channels tree (the same view the mirror runtime uses) so we don't hand-map
    // every channel struct's `enabled` field.
    let channels_json = serde_json::to_value(&config.channels).unwrap_or(Value::Null);
    let type_enabled = |kind: &str| -> bool {
        channels_json
            .get(kind)
            .and_then(Value::as_object)
            .map(|aliases| {
                aliases
                    .values()
                    .any(|a| a.get("enabled").and_then(Value::as_bool) == Some(true))
            })
            .unwrap_or(false)
    };

    // ── Built-in channels ──────────────────────────────────────────────────
    let mut builtins: Vec<BuiltinSeed> = Vec::new();
    for ci in zeroclaw_channels::listing::compiled_channels(&config.channels) {
        if all || ci.configured {
            builtins.push(BuiltinSeed {
                id: ci.kind.to_string(),
                kind: CapabilityKind::Channel,
                display: Some(ci.name.to_string()),
                description: Some(ci.desc.to_string()),
                compiled: true,
                enabled: type_enabled(ci.kind),
            });
        }
    }
    // Configured but not compiled into this binary — candidates a plugin can
    // mirror. Always shown (the operator configured them).
    for ci in zeroclaw_channels::listing::configured_uncompiled_channels(&config.channels) {
        builtins.push(BuiltinSeed {
            id: ci.kind.to_string(),
            kind: CapabilityKind::Channel,
            display: Some(ci.name.to_string()),
            description: Some(ci.desc.to_string()),
            compiled: false,
            enabled: false,
        });
    }

    // ── Installed plugins ──────────────────────────────────────────────────
    let plugins_enabled = config.plugins.enabled;
    let infos = host.list_plugins();
    let version_of = |name: &str| {
        infos
            .iter()
            .find(|i| i.name == name)
            .map(|i| i.version.clone())
    };
    let loaded_of = |name: &str| {
        infos
            .iter()
            .find(|i| i.name == name)
            .map(|i| i.loaded)
            .unwrap_or(false)
    };

    let mut installed: Vec<InstalledSeed> = Vec::new();
    for m in host.channel_plugins() {
        let mirrors = m.provides.is_some();
        let id = m.provides.clone().unwrap_or_else(|| m.name.clone());
        let loaded = loaded_of(&m.name);
        // A mirror is live only when its mirrored channel is enabled; a novel
        // plugin is live when the subsystem is on and it loaded (there is no
        // per-entry `enabled` yet).
        let enabled = plugins_enabled && loaded && if mirrors { type_enabled(&id) } else { true };
        installed.push(InstalledSeed {
            plugin_name: m.name.clone(),
            id,
            kind: CapabilityKind::Channel,
            mirrors_builtin: mirrors,
            version: version_of(&m.name),
            description: m.description.clone(),
            permissions: m.permissions.iter().map(perm_wire).collect(),
            enabled,
        });
    }
    for m in host.tool_plugins() {
        let loaded = loaded_of(&m.name);
        installed.push(InstalledSeed {
            plugin_name: m.name.clone(),
            id: m.name.clone(),
            kind: CapabilityKind::Tool,
            mirrors_builtin: false,
            version: version_of(&m.name),
            description: m.description.clone(),
            permissions: m.permissions.iter().map(perm_wire).collect(),
            enabled: plugins_enabled && loaded,
        });
    }
    for m in host.skill_plugins() {
        let loaded = loaded_of(&m.name);
        installed.push(InstalledSeed {
            plugin_name: m.name.clone(),
            id: m.name.clone(),
            kind: CapabilityKind::Skill,
            mirrors_builtin: false,
            version: version_of(&m.name),
            description: m.description.clone(),
            permissions: m.permissions.iter().map(perm_wire).collect(),
            enabled: plugins_enabled && loaded,
        });
    }

    // ── Registry-available ─────────────────────────────────────────────────
    let available: Vec<AvailableSeed> =
        zeroclaw_plugins::registry::read_cached_registry_index(&config.data_dir)
            .ok()
            .flatten()
            .map(|idx| {
                idx.plugins
                    .iter()
                    .flat_map(|e| {
                        // One row per declared capability kind (a plugin may be both a
                        // channel and a tool); unknown strings bucket into Other.
                        e.capabilities.iter().map(move |c| AvailableSeed {
                            id: e.name.clone(),
                            kind: CapabilityKind::from_wire(c),
                            version: Some(e.version.clone()),
                            description: e.description.clone(),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();

    merge_capabilities(builtins, installed, available)
}

// ── enable / disable ──────────────────────────────────────────────────────────

/// Configured aliases for a channel type, read from the serialized channels tree
/// (the keys of `[channels.<type>]`).
pub fn channel_aliases(config: &Config, channel_type: &str) -> Vec<String> {
    serde_json::to_value(&config.channels)
        .ok()
        .and_then(|v| {
            v.get(channel_type)
                .and_then(|m| m.as_object())
                .map(|o| o.keys().cloned().collect())
        })
        .unwrap_or_default()
}

/// Whether `id` names a known channel type — compiled into this binary or
/// configured (a configured-uncompiled channel has alias entries).
pub fn is_channel_id(config: &Config, id: &str) -> bool {
    zeroclaw_channels::listing::is_channel_type_compiled(id)
        || !channel_aliases(config, id).is_empty()
}

/// Whether an installed plugin serves this channel id (mirror via `provides`, or
/// a novel channel plugin named `id`), so enabling it must also turn the plugin
/// subsystem on.
fn channel_is_plugin_backed(host: &PluginHost, id: &str) -> bool {
    host.channel_plugins()
        .iter()
        .any(|m| m.provides.as_deref() == Some(id) || m.name == id)
}

/// Flip a channel capability's config `enabled` (the SSOT — never a new
/// `[features]` table) and persist. v1 handles channels only; a novel tool/skill
/// plugin runs whenever `plugins.enabled` is on and has no per-entry toggle yet.
/// Resolves the alias (0 → error/skip, 1 → auto, many → require `--alias`), and
/// turns the plugin subsystem on when enabling a plugin-backed channel.
pub async fn set_capability_enabled(
    config: &mut Config,
    host: &PluginHost,
    id: &str,
    alias: Option<String>,
    enabled: bool,
) -> anyhow::Result<()> {
    if !is_channel_id(config, id) {
        anyhow::bail!(
            "'{id}' is not a channel. Only channels can be enabled/disabled today; \
             novel tool/skill plugins run whenever `plugins.enabled` is on. \
             See `zeroclaw plugin list`."
        );
    }

    let aliases = channel_aliases(config, id);
    let targets: Vec<String> = match alias {
        Some(a) => vec![a],
        None => match aliases.as_slice() {
            [] if enabled => anyhow::bail!(
                "no configured '{id}' channel to enable — add one first \
                 (set `channels.{id}.<alias>.<field> ...`) or pass --alias <name>."
            ),
            [] => {
                println!(
                    "{}",
                    get_required_cli_string_with_args(
                        "cli-plugin-disable-none-configured",
                        &[("id", id)],
                    )
                );
                return Ok(());
            }
            [one] => vec![one.clone()],
            many => anyhow::bail!(
                "'{id}' has multiple aliases ({}); pass --alias <name>.",
                many.join(", ")
            ),
        },
    };

    let val = if enabled { "true" } else { "false" };
    let mut changes: Vec<(String, String)> = Vec::new();
    for a in &targets {
        let base = format!("channels.{id}.{a}");
        config.ensure_map_key_for_path(&base);
        let path = format!("{base}.enabled");
        config.set_prop_persistent(&path, val)?;
        changes.push((path, val.to_string()));
    }
    // A plugin-backed channel needs the plugin subsystem on to load at all.
    if enabled && channel_is_plugin_backed(host, id) && !config.plugins.enabled {
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

fn kind_label(k: &CapabilityKind) -> &str {
    match k {
        CapabilityKind::Channel => "Channels",
        CapabilityKind::Tool => "Tools",
        CapabilityKind::Memory => "Memory backends",
        CapabilityKind::Observer => "Observers",
        CapabilityKind::Skill => "Skills",
        CapabilityKind::Other(_) => "Other",
    }
}

/// The `origin`/flags rendered as a compact source label, e.g. `built-in`,
/// `built-in + plugin`, `plugin`, or `available`.
fn source_label(e: &CapabilityCatalogEntry) -> String {
    match e.origin {
        CapabilityOrigin::BuiltIn if e.installed => "built-in + plugin".to_string(),
        CapabilityOrigin::BuiltIn => "built-in".to_string(),
        CapabilityOrigin::Plugin if e.mirrors_builtin => "plugin (mirror)".to_string(),
        CapabilityOrigin::Plugin => "plugin".to_string(),
        CapabilityOrigin::Registry => "available".to_string(),
    }
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
        // status glyph: ● enabled/live, ○ installed-but-off, · installable-only.
        let glyph = if e.enabled {
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
    println!(
        "\n  ● enabled   ○ installed/built-in (off)   · installable\n  \
         `zeroclaw plugin install <name>` to add · items."
    );
}
