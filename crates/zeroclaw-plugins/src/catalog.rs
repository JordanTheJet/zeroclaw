//! Unified capability catalog — one row per (kind, id) merged across the three
//! places a ZeroClaw capability can come from: **compiled-in** (a built-in
//! behind a Cargo feature), **installed** (a WASM plugin on disk, possibly
//! mirroring a built-in via `provides`), and **available** (listed in the plugin
//! registry but not installed).
//!
//! This module owns only the merge/dedup/precedence logic over *neutral seeds*;
//! it deliberately has no dependency on the channel/config crates. Each surface
//! (the CLI, the gateway `/api/plugins`, the zerocode TUI) gathers seeds from its
//! own available types and calls [`merge_capabilities`], so the resolution logic
//! lives exactly once. Precedence mirrors the runtime's native-wins rule:
//! **built-in > installed plugin > registry**; a plugin that `provides` a
//! compiled-in channel *mirrors* it (does not override), and only becomes the
//! resolved provider when the built-in is not compiled into this binary.

use serde::Serialize;
use std::collections::HashSet;

use crate::host::PluginHost;
use crate::registry::PluginRegistryIndex;
use crate::{PluginCapability, PluginPermission};

/// The kind of capability a catalog row describes. Mirrors `PluginCapability`
/// plus an `Other` bucket for registry entries that carry an unrecognized
/// capability string (so nothing is silently dropped).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityKind {
    Channel,
    Tool,
    Memory,
    Observer,
    Skill,
    Other(String),
}

impl CapabilityKind {
    /// Parse a registry/manifest capability wire string (snake_case) into a
    /// kind, bucketing anything unknown into `Other` rather than dropping it.
    pub fn from_wire(s: &str) -> Self {
        match s {
            "channel" => Self::Channel,
            "tool" => Self::Tool,
            "memory" => Self::Memory,
            "observer" => Self::Observer,
            "skill" => Self::Skill,
            other => Self::Other(other.to_string()),
        }
    }
}

/// Which source actually provides a capability after precedence is applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityOrigin {
    /// Compiled into this binary behind a Cargo feature.
    BuiltIn,
    /// Served by an installed WASM plugin.
    Plugin,
    /// Only listed in the registry (installable, not configured locally).
    Registry,
}

/// Whether an installable package came from the canonical default registry or
/// from a caller-selected registry. The registry URL itself is deliberately
/// not carried into catalog/UI projections because it may contain credentials.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CatalogRegistryOrigin {
    Default,
    Custom,
}

// ── Neutral input seeds ───────────────────────────────────────────────────────

/// A compiled-in / configured built-in capability (e.g. a channel from
/// `CHANNEL_COMPILE_SPECS`). `compiled` is whether the feature is in this
/// binary; `configured` is the caller-computed config intent. It deliberately
/// does not claim that a runtime component started or passed its health check.
#[derive(Debug, Clone)]
pub struct BuiltinSeed {
    pub id: String,
    pub kind: CapabilityKind,
    pub display: Option<String>,
    pub description: Option<String>,
    pub compiled: bool,
    pub configured: bool,
    pub toggleable: bool,
}

/// An installed plugin capability. `id` is the `provides` id when it mirrors a
/// built-in, else the canonical `plugin.<name>` binding for a novel channel.
/// `configured` is the caller-computed config intent, not runtime liveness.
#[derive(Debug, Clone)]
pub struct InstalledSeed {
    pub plugin_name: String,
    pub id: String,
    pub kind: CapabilityKind,
    pub mirrors_builtin: bool,
    pub version: Option<String>,
    pub description: Option<String>,
    pub permissions: Vec<String>,
    pub configured: bool,
    pub toggleable: bool,
}

/// A registry-listed (installable, not installed) capability.
#[derive(Debug, Clone)]
pub struct AvailableSeed {
    /// Registry package name used by install/update commands. This can differ
    /// from `id` when a package mirrors a canonical capability.
    pub plugin_name: String,
    pub id: String,
    pub kind: CapabilityKind,
    pub version: Option<String>,
    pub description: Option<String>,
    /// Exact registry package identity (`name@version`) for install guidance.
    pub install_source: String,
    pub registry_origin: CatalogRegistryOrigin,
}

// ── Output ────────────────────────────────────────────────────────────────────

/// One catalog row: a capability id, every place it comes from (the `*_in`
/// flags), and the resolved provider's details.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CapabilityCatalogEntry {
    pub kind: CapabilityKind,
    pub id: String,
    pub display_name: Option<String>,
    pub description: Option<String>,

    /// Compiled into this binary.
    pub compiled_in: bool,
    /// An installed plugin serves or mirrors this id.
    pub installed: bool,
    /// Listed in the registry (installable).
    pub available: bool,
    /// The installed plugin `provides` a compiled-in built-in (mirror, not an
    /// override).
    pub mirrors_builtin: bool,
    /// More than one provider at the highest available precedence claims this
    /// `(kind, id)`. Ambiguity among losing lower-precedence sources only
    /// withholds their metadata; it does not invalidate the selected provider.
    pub conflicted: bool,
    /// The current config has a concrete lifecycle control for this
    /// capability. Novel plugins remain false until per-plugin activation has
    /// a canonical config source.
    pub toggleable: bool,

    /// Which source wins after precedence (built-in > plugin > registry).
    pub origin: CapabilityOrigin,
    /// The resolved source is selected by canonical configuration. This is
    /// configuration intent, not proof that a component loaded or is healthy.
    pub configured: bool,
    /// Version of the resolved provider (plugin version; `None` for built-ins).
    pub version: Option<String>,
    /// The installed plugin's name, when a plugin is involved.
    pub plugin_name: Option<String>,
    /// Exact registry package identity for an unambiguous available provider.
    /// This is display metadata, not an executable shell command.
    pub install_source: Option<String>,
    /// Registry classification without exposing the cached registry URL.
    pub registry_origin: Option<CatalogRegistryOrigin>,
    /// Permissions the installed plugin requests (empty for pure built-ins).
    pub permissions: Vec<String>,
}

/// Per-call accumulator carrying source-specific configured state and provider
/// identities so the resolved view can be chosen without an order winner.
struct Acc {
    entry: CapabilityCatalogEntry,
    builtin_configured: Option<bool>,
    plugin_configured: Option<bool>,
    installed_plugin_names: HashSet<String>,
    available_plugin_names: HashSet<String>,
}

/// Merge the three seed sets into one deduped, precedence-resolved catalog,
/// sorted by (kind, id) for stable output. Fold order is built-ins → installed →
/// registry so a plugin can attach to (or shadow) a built-in, and a registry
/// entry can mark an existing capability installable.
pub fn merge_capabilities(
    builtins: Vec<BuiltinSeed>,
    installed: Vec<InstalledSeed>,
    available: Vec<AvailableSeed>,
) -> Vec<CapabilityCatalogEntry> {
    let mut accs: Vec<Acc> = Vec::new();

    // helper: index of the entry with this (kind, id), if any.
    fn find(accs: &[Acc], kind: &CapabilityKind, id: &str) -> Option<usize> {
        accs.iter()
            .position(|a| &a.entry.kind == kind && a.entry.id == id)
    }

    for b in builtins {
        accs.push(Acc {
            entry: CapabilityCatalogEntry {
                kind: b.kind,
                id: b.id,
                display_name: b.display,
                description: b.description,
                compiled_in: b.compiled,
                installed: false,
                available: false,
                mirrors_builtin: false,
                conflicted: false,
                toggleable: b.toggleable,
                // finalized below
                origin: CapabilityOrigin::BuiltIn,
                configured: false,
                version: None,
                plugin_name: None,
                install_source: None,
                registry_origin: None,
                permissions: Vec::new(),
            },
            builtin_configured: Some(b.configured),
            plugin_configured: None,
            installed_plugin_names: HashSet::new(),
            available_plugin_names: HashSet::new(),
        });
    }

    for p in installed {
        match find(&accs, &p.kind, &p.id) {
            Some(i) => {
                let a = &mut accs[i];
                if !a.installed_plugin_names.insert(p.plugin_name.clone()) {
                    continue;
                }
                if a.installed_plugin_names.len() > 1 {
                    a.entry.mirrors_builtin |= p.mirrors_builtin;
                    a.entry.plugin_name = None;
                    a.entry.install_source = None;
                    a.entry.registry_origin = None;
                    a.entry.version = None;
                    a.entry.permissions.clear();
                    if a.builtin_configured.is_none() {
                        a.entry.description = None;
                    }
                    a.plugin_configured = Some(false);
                    continue;
                }
                a.entry.installed = true;
                a.entry.mirrors_builtin = p.mirrors_builtin;
                a.entry.toggleable |= p.toggleable;
                a.entry.plugin_name = Some(p.plugin_name);
                a.entry.version = p.version;
                a.entry.permissions = p.permissions;
                a.plugin_configured = Some(p.configured);
                // Provider metadata never replaces a canonical built-in view.
                if a.builtin_configured.is_none() {
                    a.entry.description = p.description;
                }
            }
            None => accs.push(Acc {
                entry: CapabilityCatalogEntry {
                    kind: p.kind,
                    id: p.id,
                    display_name: None,
                    description: p.description,
                    compiled_in: false,
                    installed: true,
                    available: false,
                    mirrors_builtin: p.mirrors_builtin,
                    conflicted: false,
                    toggleable: p.toggleable,
                    origin: CapabilityOrigin::Plugin,
                    configured: false,
                    version: p.version,
                    plugin_name: Some(p.plugin_name.clone()),
                    install_source: None,
                    registry_origin: None,
                    permissions: p.permissions,
                },
                builtin_configured: None,
                plugin_configured: Some(p.configured),
                installed_plugin_names: HashSet::from([p.plugin_name]),
                available_plugin_names: HashSet::new(),
            }),
        }
    }

    for r in available {
        match find(&accs, &r.kind, &r.id) {
            Some(i) => {
                let a = &mut accs[i];
                if !a.available_plugin_names.insert(r.plugin_name.clone()) {
                    continue;
                }
                let entry = &mut a.entry;
                entry.available = true;
                if a.available_plugin_names.len() > 1 {
                    entry.install_source = None;
                    entry.registry_origin = None;
                    if !entry.installed {
                        entry.plugin_name = None;
                        entry.version = None;
                        if a.builtin_configured.is_none() {
                            entry.description = None;
                        }
                    }
                    continue;
                }
                let installed_provider_is_ambiguous = a.installed_plugin_names.len() > 1;
                if !installed_provider_is_ambiguous && entry.plugin_name.is_none() {
                    entry.plugin_name = Some(r.plugin_name);
                }
                if !installed_provider_is_ambiguous {
                    entry.install_source = Some(r.install_source);
                    entry.registry_origin = Some(r.registry_origin);
                }
                if !entry.compiled_in && !entry.installed {
                    entry.version = r.version;
                    if a.builtin_configured.is_none() {
                        entry.description = r.description;
                    }
                }
            }
            None => accs.push(Acc {
                entry: CapabilityCatalogEntry {
                    kind: r.kind,
                    id: r.id,
                    display_name: None,
                    description: r.description,
                    compiled_in: false,
                    installed: false,
                    available: true,
                    mirrors_builtin: false,
                    conflicted: false,
                    toggleable: false,
                    origin: CapabilityOrigin::Registry,
                    configured: false,
                    version: r.version,
                    plugin_name: Some(r.plugin_name.clone()),
                    install_source: Some(r.install_source),
                    registry_origin: Some(r.registry_origin),
                    permissions: Vec::new(),
                },
                builtin_configured: None,
                plugin_configured: None,
                installed_plugin_names: HashSet::new(),
                available_plugin_names: HashSet::from([r.plugin_name]),
            }),
        }
    }

    // Finalize: resolve origin (built-in > plugin > registry) and the resolved
    // provider's configured state.
    let mut out: Vec<CapabilityCatalogEntry> = accs
        .into_iter()
        .map(|a| {
            let installed_conflicted = a.installed_plugin_names.len() > 1;
            let registry_conflicted = a.available_plugin_names.len() > 1;
            let mut e = a.entry;
            e.origin = if e.compiled_in {
                CapabilityOrigin::BuiltIn
            } else if e.installed {
                CapabilityOrigin::Plugin
            } else if e.available {
                CapabilityOrigin::Registry
            } else {
                // A known-but-uncompiled built-in with no plugin/registry source.
                CapabilityOrigin::BuiltIn
            };
            e.configured = match e.origin {
                CapabilityOrigin::BuiltIn => a.builtin_configured.unwrap_or(false),
                CapabilityOrigin::Plugin => a.plugin_configured.unwrap_or(false),
                CapabilityOrigin::Registry => false,
            };
            e.conflicted = match e.origin {
                CapabilityOrigin::BuiltIn => false,
                CapabilityOrigin::Plugin => installed_conflicted,
                CapabilityOrigin::Registry => registry_conflicted,
            };
            if e.conflicted {
                e.toggleable = false;
            }
            e
        })
        .collect();

    out.sort_by(|a, b| {
        kind_rank(&a.kind)
            .cmp(&kind_rank(&b.kind))
            .then_with(|| a.id.cmp(&b.id))
    });
    out
}

fn kind_rank(k: &CapabilityKind) -> u8 {
    match k {
        CapabilityKind::Channel => 0,
        CapabilityKind::Tool => 1,
        CapabilityKind::Memory => 2,
        CapabilityKind::Observer => 3,
        CapabilityKind::Skill => 4,
        CapabilityKind::Other(_) => 5,
    }
}

// ── Shared seed gathering from installed plugins + the registry ────────────────
//
// These fold the plugin/registry sources (both `zeroclaw-plugins`-owned types)
// into neutral seeds, so every surface reuses them. Building the *built-in*
// channel seeds stays per-surface because it needs `zeroclaw-channels`, which
// this crate deliberately does not depend on.

/// A plugin permission's snake_case wire string (`"config_read"`, …).
fn perm_wire(p: &PluginPermission) -> String {
    serde_json::to_value(p)
        .ok()
        .and_then(|v| v.as_str().map(String::from))
        .unwrap_or_default()
}

/// Fold every installed plugin capability into seeds.
///
/// `plugins_configured` is the subsystem switch. The two callbacks derive a
/// channel's configuration and lifecycle control from the caller's live
/// config view. `mirrors_builtin` distinguishes canonical built-in ids from
/// novel `plugin.<name>` bindings without moving config ownership into this
/// crate.
pub fn installed_seeds(
    host: &PluginHost,
    plugins_configured: bool,
    channel_configured: impl Fn(&str, bool) -> bool,
    channel_toggleable: impl Fn(&str, bool) -> bool,
) -> Vec<InstalledSeed> {
    let infos = host.list_plugins();
    let version_of = |name: &str| {
        infos
            .iter()
            .find(|i| i.name == name)
            .map(|i| i.version.clone())
    };
    let mut out = Vec::new();
    for m in host.channel_plugins() {
        let mirrors = m.provides.is_some();
        let id = m
            .provides
            .clone()
            .unwrap_or_else(|| zeroclaw_api::channel::plugin_channel_ref(&m.name));
        out.push(InstalledSeed {
            plugin_name: m.name.clone(),
            configured: plugins_configured && channel_configured(&id, mirrors),
            toggleable: channel_toggleable(&id, mirrors),
            id,
            kind: CapabilityKind::Channel,
            mirrors_builtin: mirrors,
            version: version_of(&m.name),
            description: m.description.clone(),
            permissions: m.permissions.iter().map(perm_wire).collect(),
        });
    }
    for info in &infos {
        for capability in &info.capabilities {
            let kind = match capability {
                PluginCapability::Channel => continue,
                PluginCapability::Tool => CapabilityKind::Tool,
                PluginCapability::Memory => CapabilityKind::Memory,
                PluginCapability::Observer => CapabilityKind::Observer,
                PluginCapability::Skill => CapabilityKind::Skill,
            };
            out.push(InstalledSeed {
                plugin_name: info.name.clone(),
                id: info.name.clone(),
                kind,
                mirrors_builtin: false,
                version: Some(info.version.clone()),
                description: info.description.clone(),
                permissions: info.permissions.iter().map(perm_wire).collect(),
                configured: plugins_configured,
                toggleable: false,
            });
        }
    }
    out
}

/// Fold a cached registry index into available seeds — one row per declared
/// capability kind (a plugin may be both a channel and a tool).
pub fn available_seeds(index: &PluginRegistryIndex) -> Vec<AvailableSeed> {
    let registry_origin = match index
        .registry_url
        .as_deref()
        .map(str::trim)
        .filter(|url| !url.is_empty())
    {
        Some(crate::registry::DEFAULT_REGISTRY_URL) | None => CatalogRegistryOrigin::Default,
        Some(_) => CatalogRegistryOrigin::Custom,
    };
    crate::registry::resolved_entries(index)
        .into_iter()
        .flat_map(|e| {
            e.capabilities.iter().map(move |capability| {
                let kind = CapabilityKind::from_wire(capability);
                let id = if kind == CapabilityKind::Channel {
                    e.provides
                        .clone()
                        .unwrap_or_else(|| zeroclaw_api::channel::plugin_channel_ref(&e.name))
                } else {
                    e.name.clone()
                };
                AvailableSeed {
                    plugin_name: e.name.clone(),
                    id,
                    kind,
                    version: Some(e.version.clone()),
                    description: e.description.clone(),
                    install_source: crate::registry::install_source(e),
                    registry_origin,
                }
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn builtin(id: &str, compiled: bool, configured: bool) -> BuiltinSeed {
        BuiltinSeed {
            id: id.to_string(),
            kind: CapabilityKind::Channel,
            display: Some(id.to_string()),
            description: None,
            compiled,
            configured,
            toggleable: true,
        }
    }

    fn plugin(id: &str, name: &str, mirrors: bool, configured: bool) -> InstalledSeed {
        InstalledSeed {
            plugin_name: name.to_string(),
            id: id.to_string(),
            kind: CapabilityKind::Channel,
            mirrors_builtin: mirrors,
            version: Some("1.0".to_string()),
            description: None,
            permissions: vec!["config_read".to_string()],
            configured,
            toggleable: mirrors,
        }
    }

    fn available(id: &str, kind: CapabilityKind) -> AvailableSeed {
        AvailableSeed {
            plugin_name: id.to_string(),
            id: id.to_string(),
            kind,
            version: Some("2.0".to_string()),
            description: Some("from registry".to_string()),
            install_source: format!("{id}@2.0"),
            registry_origin: CatalogRegistryOrigin::Default,
        }
    }

    fn get<'a>(v: &'a [CapabilityCatalogEntry], id: &str) -> &'a CapabilityCatalogEntry {
        v.iter().find(|e| e.id == id).expect("entry present")
    }

    #[test]
    fn builtin_alone_resolves_builtin() {
        let out = merge_capabilities(vec![builtin("telegram", true, true)], vec![], vec![]);
        let e = get(&out, "telegram");
        assert_eq!(e.origin, CapabilityOrigin::BuiltIn);
        assert!(e.compiled_in && e.configured);
        assert!(!e.installed && !e.available);
    }

    #[test]
    fn plugin_mirroring_compiled_builtin_native_wins() {
        // discord compiled-in AND a plugin provides it → built-in wins, but the
        // row records the plugin source + version.
        let out = merge_capabilities(
            vec![builtin("discord", true, true)],
            vec![plugin("discord", "discord-plugin", true, true)],
            vec![],
        );
        assert_eq!(out.len(), 1, "same id → one row");
        let e = get(&out, "discord");
        assert_eq!(e.origin, CapabilityOrigin::BuiltIn, "native wins");
        assert!(e.compiled_in && e.installed && e.mirrors_builtin);
        assert_eq!(e.plugin_name.as_deref(), Some("discord-plugin"));
        assert_eq!(e.version.as_deref(), Some("1.0"));
        // Configured state reflects the resolved built-in source.
        assert!(e.configured);
    }

    #[test]
    fn plugin_mirroring_uncompiled_builtin_becomes_resolved() {
        // whatsapp-cloud NOT compiled + a plugin provides it → the plugin is the
        // selected provider; configured state comes from the plugin config.
        let out = merge_capabilities(
            vec![builtin("whatsapp_cloud", false, false)],
            vec![plugin("whatsapp_cloud", "wa-plugin", true, true)],
            vec![],
        );
        let e = get(&out, "whatsapp_cloud");
        assert_eq!(e.origin, CapabilityOrigin::Plugin);
        assert!(!e.compiled_in && e.installed && e.mirrors_builtin);
        assert!(e.configured, "plugin config wins when native is absent");
    }

    #[test]
    fn novel_plugin_is_its_own_row() {
        let out = merge_capabilities(
            vec![],
            vec![plugin("weather", "weather", false, true)],
            vec![],
        );
        let e = get(&out, "weather");
        assert_eq!(e.origin, CapabilityOrigin::Plugin);
        assert!(!e.compiled_in && e.installed && !e.mirrors_builtin);
    }

    #[test]
    fn registry_only_entry_is_available_not_configured() {
        let out = merge_capabilities(
            vec![],
            vec![],
            vec![available("bluesky", CapabilityKind::Channel)],
        );
        let e = get(&out, "bluesky");
        assert_eq!(e.origin, CapabilityOrigin::Registry);
        assert!(e.available && !e.installed && !e.compiled_in);
        assert!(!e.configured, "registry-only has no local configuration");
        assert_eq!(e.install_source.as_deref(), Some("bluesky@2.0"));
        assert_eq!(e.registry_origin, Some(CatalogRegistryOrigin::Default));
    }

    #[test]
    fn registry_metadata_keeps_exact_release_when_compiled_builtin_wins() {
        let out = merge_capabilities(
            vec![builtin("git", true, true)],
            vec![],
            vec![AvailableSeed {
                plugin_name: "gitea".to_string(),
                id: "git".to_string(),
                kind: CapabilityKind::Channel,
                version: Some("0.2.0".to_string()),
                description: None,
                install_source: "gitea@0.2.0".to_string(),
                registry_origin: CatalogRegistryOrigin::Custom,
            }],
        );
        let entry = get(&out, "git");
        assert_eq!(entry.origin, CapabilityOrigin::BuiltIn);
        assert_eq!(entry.version, None, "resolved built-in has no version");
        assert_eq!(entry.install_source.as_deref(), Some("gitea@0.2.0"));
        assert_eq!(entry.registry_origin, Some(CatalogRegistryOrigin::Custom));
    }

    #[test]
    fn registry_marks_installed_capability_upgradable() {
        // installed novel plugin AND same id in registry → one row, available=true.
        let out = merge_capabilities(
            vec![],
            vec![plugin("weather", "weather", false, true)],
            vec![available("weather", CapabilityKind::Channel)],
        );
        assert_eq!(out.len(), 1);
        let e = get(&out, "weather");
        assert_eq!(e.origin, CapabilityOrigin::Plugin);
        assert!(e.installed && e.available);
    }

    #[test]
    fn duplicate_installed_providers_are_order_independent_and_restore_builtin_metadata() {
        let mut builtin = builtin("git", false, true);
        builtin.description = Some("canonical git channel".to_string());
        let mut first = plugin("git", "gitea-a", true, true);
        first.version = Some("1.0.0".to_string());
        first.description = Some("provider a".to_string());
        first.permissions = vec!["config_read".to_string()];
        let mut second = plugin("git", "gitea-b", true, false);
        second.version = Some("2.0.0".to_string());
        second.description = Some("provider b".to_string());
        second.permissions = vec!["http_client".to_string()];

        let forward = merge_capabilities(
            vec![builtin.clone()],
            vec![first.clone(), second.clone()],
            vec![],
        );
        let reverse = merge_capabilities(vec![builtin], vec![second, first], vec![]);

        assert_eq!(forward, reverse);
        let entry = get(&forward, "git");
        assert!(entry.conflicted);
        assert!(!entry.toggleable);
        assert!(!entry.configured, "ambiguous plugin provider fails closed");
        assert_eq!(entry.description.as_deref(), Some("canonical git channel"));
        assert_eq!(entry.plugin_name, None);
        assert_eq!(entry.install_source, None);
        assert_eq!(entry.registry_origin, None);
        assert_eq!(entry.version, None);
        assert!(entry.permissions.is_empty());
    }

    #[test]
    fn registry_metadata_does_not_hide_an_installed_provider_conflict() {
        let out = merge_capabilities(
            vec![],
            vec![
                plugin("git", "gitea-a", true, true),
                plugin("git", "gitea-b", true, true),
            ],
            vec![AvailableSeed {
                plugin_name: "gitea-a".to_string(),
                id: "git".to_string(),
                kind: CapabilityKind::Channel,
                version: Some("1.0".to_string()),
                description: None,
                install_source: "gitea-a@1.0".to_string(),
                registry_origin: CatalogRegistryOrigin::Default,
            }],
        );
        let entry = get(&out, "git");
        assert!(entry.conflicted && entry.available);
        assert!(!entry.toggleable);
        assert_eq!(entry.plugin_name, None);
    }

    #[test]
    fn duplicate_registry_packages_are_order_independent_without_a_winner() {
        let first = AvailableSeed {
            plugin_name: "gitea".to_string(),
            id: "git".to_string(),
            kind: CapabilityKind::Channel,
            version: Some("1.0.0".to_string()),
            description: Some("provider a".to_string()),
            install_source: "gitea@1.0.0".to_string(),
            registry_origin: CatalogRegistryOrigin::Default,
        };
        let second = AvailableSeed {
            plugin_name: "forgejo".to_string(),
            id: "git".to_string(),
            kind: CapabilityKind::Channel,
            version: Some("2.0.0".to_string()),
            description: Some("provider b".to_string()),
            install_source: "forgejo@2.0.0".to_string(),
            registry_origin: CatalogRegistryOrigin::Default,
        };

        let forward = merge_capabilities(vec![], vec![], vec![first.clone(), second.clone()]);
        let reverse = merge_capabilities(vec![], vec![], vec![second, first]);

        assert_eq!(forward, reverse);
        let entry = get(&forward, "git");
        assert!(entry.conflicted && entry.available);
        assert!(!entry.toggleable);
        assert!(!entry.configured);
        assert_eq!(entry.plugin_name, None);
        assert_eq!(entry.version, None);
        assert_eq!(entry.description, None);
        assert_eq!(entry.install_source, None);
        assert_eq!(entry.registry_origin, None);
    }

    #[test]
    fn duplicate_registry_packages_restore_builtin_metadata() {
        let mut canonical = builtin("git", false, true);
        canonical.description = Some("canonical git channel".to_string());
        let first = AvailableSeed {
            plugin_name: "gitea".to_string(),
            id: "git".to_string(),
            kind: CapabilityKind::Channel,
            version: Some("1.0.0".to_string()),
            description: Some("provider a".to_string()),
            install_source: "gitea@1.0.0".to_string(),
            registry_origin: CatalogRegistryOrigin::Default,
        };
        let second = AvailableSeed {
            plugin_name: "forgejo".to_string(),
            id: "git".to_string(),
            kind: CapabilityKind::Channel,
            version: Some("2.0.0".to_string()),
            description: Some("provider b".to_string()),
            install_source: "forgejo@2.0.0".to_string(),
            registry_origin: CatalogRegistryOrigin::Default,
        };

        let forward = merge_capabilities(
            vec![canonical.clone()],
            vec![],
            vec![first.clone(), second.clone()],
        );
        let reverse = merge_capabilities(vec![canonical], vec![], vec![second, first]);

        assert_eq!(forward, reverse);
        let entry = get(&forward, "git");
        assert!(entry.conflicted && entry.available);
        assert!(!entry.toggleable);
        assert_eq!(entry.description.as_deref(), Some("canonical git channel"));
        assert_eq!(entry.plugin_name, None);
        assert_eq!(entry.version, None);
    }

    #[test]
    fn lower_registry_conflict_preserves_compiled_builtin_controls() {
        let first = AvailableSeed {
            plugin_name: "gitea".to_string(),
            id: "git".to_string(),
            kind: CapabilityKind::Channel,
            version: Some("1.0.0".to_string()),
            description: None,
            install_source: "gitea@1.0.0".to_string(),
            registry_origin: CatalogRegistryOrigin::Default,
        };
        let second = AvailableSeed {
            plugin_name: "forgejo".to_string(),
            id: "git".to_string(),
            kind: CapabilityKind::Channel,
            version: Some("2.0.0".to_string()),
            description: None,
            install_source: "forgejo@2.0.0".to_string(),
            registry_origin: CatalogRegistryOrigin::Default,
        };

        let entry = merge_capabilities(
            vec![builtin("git", true, true)],
            vec![],
            vec![first, second],
        )
        .remove(0);
        assert_eq!(entry.origin, CapabilityOrigin::BuiltIn);
        assert!(!entry.conflicted, "selected native provider is unambiguous");
        assert!(entry.configured && entry.toggleable);
        assert_eq!(entry.install_source, None, "registry install is ambiguous");
        assert_eq!(entry.registry_origin, None);
    }

    #[test]
    fn lower_registry_conflict_preserves_installed_provider_controls() {
        let first = AvailableSeed {
            plugin_name: "gitea-release".to_string(),
            id: "git".to_string(),
            kind: CapabilityKind::Channel,
            version: Some("1.0.0".to_string()),
            description: None,
            install_source: "gitea-release@1.0.0".to_string(),
            registry_origin: CatalogRegistryOrigin::Default,
        };
        let second = AvailableSeed {
            plugin_name: "forgejo-release".to_string(),
            id: "git".to_string(),
            kind: CapabilityKind::Channel,
            version: Some("2.0.0".to_string()),
            description: None,
            install_source: "forgejo-release@2.0.0".to_string(),
            registry_origin: CatalogRegistryOrigin::Default,
        };

        let entry = merge_capabilities(
            vec![],
            vec![plugin("git", "installed-git", true, true)],
            vec![first, second],
        )
        .remove(0);
        assert_eq!(entry.origin, CapabilityOrigin::Plugin);
        assert!(
            !entry.conflicted,
            "selected installed provider is unambiguous"
        );
        assert!(entry.configured && entry.toggleable);
        assert_eq!(entry.plugin_name.as_deref(), Some("installed-git"));
        assert_eq!(entry.install_source, None, "registry update is ambiguous");
        assert_eq!(entry.registry_origin, None);
    }

    #[test]
    fn registry_package_name_can_differ_from_canonical_capability_id() {
        let out = merge_capabilities(
            vec![builtin("git", false, false)],
            vec![],
            vec![AvailableSeed {
                plugin_name: "gitea".to_string(),
                id: "git".to_string(),
                kind: CapabilityKind::Channel,
                version: Some("0.1.0".to_string()),
                description: None,
                install_source: "gitea@0.1.0".to_string(),
                registry_origin: CatalogRegistryOrigin::Default,
            }],
        );
        assert_eq!(out.len(), 1);
        let entry = get(&out, "git");
        assert!(entry.available);
        assert_eq!(entry.origin, CapabilityOrigin::Registry);
        assert_eq!(entry.plugin_name.as_deref(), Some("gitea"));
        assert_eq!(entry.version.as_deref(), Some("0.1.0"));
    }

    #[test]
    fn kind_distinguishes_same_id() {
        // A channel and a tool named "notion" are distinct rows.
        let out = merge_capabilities(
            vec![],
            vec![
                plugin("notion", "notion-channel", false, true),
                InstalledSeed {
                    kind: CapabilityKind::Tool,
                    ..plugin("notion", "notion-tool", false, true)
                },
            ],
            vec![],
        );
        assert_eq!(out.len(), 2, "same id, different kind → two rows");
    }

    #[test]
    fn output_sorted_by_kind_then_id() {
        let out = merge_capabilities(
            vec![builtin("zzz", true, true), builtin("aaa", true, true)],
            vec![InstalledSeed {
                kind: CapabilityKind::Tool,
                ..plugin("redact", "redact", false, true)
            }],
            vec![],
        );
        let ids: Vec<&str> = out.iter().map(|e| e.id.as_str()).collect();
        // channels (aaa, zzz) before tools (redact)
        assert_eq!(ids, vec!["aaa", "zzz", "redact"]);
    }

    #[test]
    fn installed_seeds_include_every_declared_non_channel_kind() {
        let dir = tempfile::tempdir().expect("temporary plugin root");
        let plugin_dir = dir.path().join("plugins").join("multi-capability");
        std::fs::create_dir_all(&plugin_dir).expect("plugin directory");
        std::fs::write(plugin_dir.join("plugin.wasm"), b"").expect("placeholder component");
        std::fs::write(
            plugin_dir.join("manifest.toml"),
            r#"
name = "multi-capability"
version = "1.0.0"
wasm_path = "plugin.wasm"
capabilities = ["tool", "memory", "observer"]
"#,
        )
        .expect("plugin manifest");

        let host = PluginHost::new(dir.path()).expect("discover plugin");
        let seeds = installed_seeds(&host, true, |_, _| false, |_, _| false);

        for kind in [
            CapabilityKind::Tool,
            CapabilityKind::Memory,
            CapabilityKind::Observer,
        ] {
            assert!(
                seeds
                    .iter()
                    .any(|seed| seed.kind == kind && seed.configured),
                "missing configured {kind:?} seed"
            );
        }
        assert_eq!(seeds.len(), 3, "one seed per declared capability");
    }

    #[test]
    fn installed_novel_channel_uses_canonical_binding_and_config_view() {
        let dir = tempfile::tempdir().expect("temporary plugin root");
        let plugin_dir = dir.path().join("plugins").join("novel-channel");
        std::fs::create_dir_all(&plugin_dir).expect("plugin directory");
        std::fs::write(plugin_dir.join("plugin.wasm"), b"").expect("placeholder component");
        std::fs::write(
            plugin_dir.join("manifest.toml"),
            r#"
name = "novel-channel"
version = "1.0.0"
wasm_path = "plugin.wasm"
capabilities = ["channel"]
"#,
        )
        .expect("plugin manifest");

        let host = PluginHost::new(dir.path()).expect("discover plugin");
        let seeds = installed_seeds(
            &host,
            true,
            |id, mirrors_builtin| id == "plugin.novel-channel" && !mirrors_builtin,
            |_, _| false,
        );

        assert_eq!(seeds.len(), 1);
        assert_eq!(seeds[0].id, "plugin.novel-channel");
        assert!(seeds[0].configured);
        assert!(!seeds[0].toggleable);
    }

    #[test]
    fn available_seeds_use_resolved_release_and_canonical_channel_identity() {
        fn entry(
            name: &str,
            version: &str,
            provides: Option<&str>,
        ) -> crate::registry::PluginRegistryEntry {
            crate::registry::PluginRegistryEntry {
                name: name.to_string(),
                version: version.to_string(),
                description: None,
                author: None,
                capabilities: vec!["channel".to_string()],
                provides: provides.map(str::to_string),
                sender_match: None,
                url: format!("https://example.invalid/{name}-{version}.zip"),
                sha256: None,
            }
        }

        let index = PluginRegistryIndex {
            plugins: vec![
                entry("novel", "0.1.0", None),
                entry("mirror", "0.2.0", Some("git")),
                entry("novel", "0.2.0", None),
            ],
            registry_url: None,
        };

        let seeds = available_seeds(&index);
        assert_eq!(seeds.len(), 2, "one resolved release per package");
        let novel = seeds
            .iter()
            .find(|seed| seed.plugin_name == "novel")
            .expect("novel package seed");
        assert_eq!(novel.id, "plugin.novel");
        assert_eq!(novel.version.as_deref(), Some("0.2.0"));
        assert_eq!(novel.install_source, "novel@0.2.0");
        assert_eq!(novel.registry_origin, CatalogRegistryOrigin::Default);
        let mirror = seeds
            .iter()
            .find(|seed| seed.plugin_name == "mirror")
            .expect("mirror package seed");
        assert_eq!(mirror.id, "git");
    }
}
