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
    /// Only listed in the registry (installable, not live).
    Registry,
}

// ── Neutral input seeds ───────────────────────────────────────────────────────

/// A compiled-in / configured built-in capability (e.g. a channel from
/// `CHANNEL_COMPILE_SPECS`). `compiled` is whether the feature is in this
/// binary; `enabled` is the caller-computed live state (compiled && configured
/// && at least one alias enabled).
#[derive(Debug, Clone)]
pub struct BuiltinSeed {
    pub id: String,
    pub kind: CapabilityKind,
    pub display: Option<String>,
    pub description: Option<String>,
    pub compiled: bool,
    pub enabled: bool,
    pub toggleable: bool,
}

/// An installed plugin capability. `id` is the `provides` id when it mirrors a
/// built-in, else the plugin's own name. `enabled` is the caller-computed live
/// state (plugins.enabled && loaded && its config `enabled`).
#[derive(Debug, Clone)]
pub struct InstalledSeed {
    pub plugin_name: String,
    pub id: String,
    pub kind: CapabilityKind,
    pub mirrors_builtin: bool,
    pub version: Option<String>,
    pub description: Option<String>,
    pub permissions: Vec<String>,
    pub enabled: bool,
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
}

// ── Output ────────────────────────────────────────────────────────────────────

/// One catalog row: a capability id, every place it comes from (the `*_in`
/// flags), and the resolved provider's details.
#[derive(Debug, Clone, Serialize)]
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
    /// More than one installed plugin claims this `(kind, id)`. Runtime
    /// resolution fails closed for the ambiguous providers; the catalog must
    /// not choose one based on discovery order.
    pub conflicted: bool,
    /// The current config has a concrete lifecycle control for this
    /// capability. Novel plugins remain false until per-plugin activation has
    /// a canonical config source.
    pub toggleable: bool,

    /// Which source wins after precedence (built-in > plugin > registry).
    pub origin: CapabilityOrigin,
    /// The resolved provider is enabled/live.
    pub enabled: bool,
    /// Version of the resolved provider (plugin version; `None` for built-ins).
    pub version: Option<String>,
    /// The installed plugin's name, when a plugin is involved.
    pub plugin_name: Option<String>,
    /// Permissions the installed plugin requests (empty for pure built-ins).
    pub permissions: Vec<String>,
}

/// Internal accumulator carrying both providers' enabled/version so the resolved
/// value can be chosen in a final pass.
struct Acc {
    entry: CapabilityCatalogEntry,
    builtin_enabled: Option<bool>,
    plugin_enabled: Option<bool>,
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
                enabled: false,
                version: None,
                plugin_name: None,
                permissions: Vec::new(),
            },
            builtin_enabled: Some(b.enabled),
            plugin_enabled: None,
        });
    }

    for p in installed {
        match find(&accs, &p.kind, &p.id) {
            Some(i) => {
                let a = &mut accs[i];
                if a.entry.installed {
                    a.entry.conflicted = true;
                    a.entry.mirrors_builtin |= p.mirrors_builtin;
                    a.entry.plugin_name = None;
                    a.entry.version = None;
                    a.entry.permissions.clear();
                    a.plugin_enabled = Some(false);
                    continue;
                }
                a.entry.installed = true;
                a.entry.mirrors_builtin = p.mirrors_builtin;
                a.entry.toggleable |= p.toggleable;
                a.entry.plugin_name = Some(p.plugin_name);
                a.entry.version = p.version;
                a.entry.permissions = p.permissions;
                a.plugin_enabled = Some(p.enabled);
                // Take the plugin's description when the built-in had none.
                if a.entry.description.is_none() {
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
                    enabled: false,
                    version: p.version,
                    plugin_name: Some(p.plugin_name),
                    permissions: p.permissions,
                },
                builtin_enabled: None,
                plugin_enabled: Some(p.enabled),
            }),
        }
    }

    for r in available {
        match find(&accs, &r.kind, &r.id) {
            Some(i) => {
                let entry = &mut accs[i].entry;
                entry.available = true;
                if !entry.conflicted && entry.plugin_name.is_none() {
                    entry.plugin_name = Some(r.plugin_name);
                }
                if !entry.compiled_in && !entry.installed {
                    entry.version = r.version;
                    if entry.description.is_none() {
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
                    enabled: false,
                    version: r.version,
                    plugin_name: Some(r.plugin_name),
                    permissions: Vec::new(),
                },
                builtin_enabled: None,
                plugin_enabled: None,
            }),
        }
    }

    // Finalize: resolve origin (built-in > plugin > registry) and the resolved
    // provider's `enabled`.
    let mut out: Vec<CapabilityCatalogEntry> = accs
        .into_iter()
        .map(|a| {
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
            e.enabled = match e.origin {
                CapabilityOrigin::BuiltIn => a.builtin_enabled.unwrap_or(false),
                CapabilityOrigin::Plugin => a.plugin_enabled.unwrap_or(false),
                CapabilityOrigin::Registry => false,
            };
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

#[cfg(test)]
mod tests {
    use super::*;

    fn builtin(id: &str, compiled: bool, enabled: bool) -> BuiltinSeed {
        BuiltinSeed {
            id: id.to_string(),
            kind: CapabilityKind::Channel,
            display: Some(id.to_string()),
            description: None,
            compiled,
            enabled,
            toggleable: true,
        }
    }

    fn plugin(id: &str, name: &str, mirrors: bool, enabled: bool) -> InstalledSeed {
        InstalledSeed {
            plugin_name: name.to_string(),
            id: id.to_string(),
            kind: CapabilityKind::Channel,
            mirrors_builtin: mirrors,
            version: Some("1.0".to_string()),
            description: None,
            permissions: vec!["config_read".to_string()],
            enabled,
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
        assert!(e.compiled_in && e.enabled);
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
        // Enabled reflects the resolved (built-in) provider.
        assert!(e.enabled);
    }

    #[test]
    fn plugin_mirroring_uncompiled_builtin_becomes_resolved() {
        // whatsapp-cloud NOT compiled + a plugin provides it → the plugin is the
        // live provider; enabled comes from the plugin.
        let out = merge_capabilities(
            vec![builtin("whatsapp_cloud", false, false)],
            vec![plugin("whatsapp_cloud", "wa-plugin", true, true)],
            vec![],
        );
        let e = get(&out, "whatsapp_cloud");
        assert_eq!(e.origin, CapabilityOrigin::Plugin);
        assert!(!e.compiled_in && e.installed && e.mirrors_builtin);
        assert!(
            e.enabled,
            "plugin provider's enabled wins when native absent"
        );
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
    fn registry_only_entry_is_available_not_enabled() {
        let out = merge_capabilities(
            vec![],
            vec![],
            vec![available("bluesky", CapabilityKind::Channel)],
        );
        let e = get(&out, "bluesky");
        assert_eq!(e.origin, CapabilityOrigin::Registry);
        assert!(e.available && !e.installed && !e.compiled_in);
        assert!(!e.enabled, "registry-only is never live");
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
    fn duplicate_installed_providers_fail_closed_without_order_winner() {
        let out = merge_capabilities(
            vec![],
            vec![
                plugin("git", "gitea-a", true, true),
                plugin("git", "gitea-b", true, true),
            ],
            vec![],
        );
        assert_eq!(out.len(), 1);
        let entry = get(&out, "git");
        assert!(entry.conflicted);
        assert!(!entry.enabled);
        assert_eq!(entry.plugin_name, None);
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
            }],
        );
        let entry = get(&out, "git");
        assert!(entry.conflicted && entry.available);
        assert_eq!(entry.plugin_name, None);
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
}
