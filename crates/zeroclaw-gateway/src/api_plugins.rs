//! Read-only plugin and capability catalog API.
//!
//! The route is available whenever the gateway is built, including builds
//! without the WASM plugin feature. WASM-specific discovery degrades to an
//! empty source while compiled/configured built-ins remain visible.

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Json, Response},
};
use serde::Serialize;

use super::AppState;
use zeroclaw_config::schema::Config;

/// Stable wire identity for the source selected by catalog precedence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "schema-export", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum PluginCatalogOrigin {
    BuiltIn,
    Plugin,
    Registry,
}

/// Stable classification of the registry that supplied install metadata.
/// The gateway deliberately never returns the registry URL because a custom
/// URL may contain credentials.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "schema-export", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum PluginCatalogRegistryOrigin {
    Default,
    Custom,
}

/// One stable, gateway-owned capability row.
///
/// This DTO deliberately does not expose the plugin crate's experimental
/// catalog struct. It is a request-time projection over canonical config,
/// host discovery, and the cached registry index.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "schema-export", derive(schemars::JsonSchema))]
pub struct PluginCatalogEntry {
    pub kind: String,
    pub id: String,
    pub display_name: Option<String>,
    pub description: Option<String>,
    /// Compiled into this binary.
    pub compiled_in: bool,
    /// An installed plugin serves or mirrors this capability.
    pub installed: bool,
    /// Listed in the cached registry and therefore installable.
    pub available: bool,
    /// The installed plugin declares that it mirrors a built-in capability.
    pub mirrors_builtin: bool,
    /// More than one provider at the selected precedence claims this
    /// capability, so no winner was selected from discovery order.
    pub conflicted: bool,
    /// Canonical config exposes a lifecycle control for this capability.
    pub toggleable: bool,
    pub origin: PluginCatalogOrigin,
    /// Configuration intent derived from canonical config and discovery.
    /// This is not a runtime supervisor or health signal.
    pub configured: bool,
    pub version: Option<String>,
    pub plugin_name: Option<String>,
    /// Exact registry package identity (`name@version`) for display as a data
    /// token. This is not an executable command.
    pub install_source: Option<String>,
    /// Default/custom classification without exposing a registry URL.
    pub registry_origin: Option<PluginCatalogRegistryOrigin>,
    pub permissions: Vec<String>,
}

/// Back-compatible installed-plugin summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "schema-export", derive(schemars::JsonSchema))]
pub struct InstalledPlugin {
    pub name: String,
    pub version: String,
    pub description: Option<String>,
    pub capabilities: Vec<String>,
    /// Whether the declared component/skill artifacts are present on disk.
    /// This does not claim that a runtime instance is healthy or listening.
    pub loaded: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "schema-export", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum PluginCatalogIssueSource {
    Installed,
    Registry,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "schema-export", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum PluginCatalogIssueCode {
    DiscoveryFailed,
    CacheReadFailed,
}

/// A stable, non-diagnostic source failure. Detailed errors remain in logs;
/// the dashboard localizes these codes instead of displaying internals.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "schema-export", derive(schemars::JsonSchema))]
pub struct PluginCatalogIssue {
    pub source: PluginCatalogIssueSource,
    pub code: PluginCatalogIssueCode,
}

/// Response from `GET /api/plugins`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "schema-export", derive(schemars::JsonSchema))]
pub struct PluginsResponse {
    /// Canonical `[plugins].enabled` config value.
    pub plugins_enabled: bool,
    /// Whether this binary was compiled with WASM plugin catalog support.
    pub wasm_plugins_available: bool,
    /// Canonical configured plugin directory, before path expansion.
    pub plugins_dir: String,
    /// Legacy installed-plugin list retained for existing API consumers.
    pub plugins: Vec<InstalledPlugin>,
    pub capabilities: Vec<PluginCatalogEntry>,
    /// Source failures, distinct from a valid empty catalog.
    pub issues: Vec<PluginCatalogIssue>,
}

/// Request-local materialized view of one built-in capability. Every value is
/// derived on demand from `Config.channels` and the compile-time inventory; it
/// is never stored as runtime state.
struct BuiltinView {
    id: String,
    display_name: String,
    description: String,
    compiled_in: bool,
    configured: bool,
    toggleable: bool,
}

/// Request-local inputs copied while the config read lock is held. This value
/// exists only for one response so filesystem discovery never blocks config
/// readers; `Config` remains the canonical source.
struct CatalogRequestView {
    plugins_enabled: bool,
    plugins_dir: String,
    builtins: Vec<BuiltinView>,
    #[cfg(feature = "plugins-wasm")]
    plugin_path: std::path::PathBuf,
    #[cfg(feature = "plugins-wasm")]
    signature_mode: String,
    #[cfg(feature = "plugins-wasm")]
    trusted_publisher_keys: Vec<String>,
    #[cfg(feature = "plugins-wasm")]
    data_dir: std::path::PathBuf,
    #[cfg(feature = "plugins-wasm")]
    active_channels: zeroclaw_config::schema::ActiveChannelAliases,
}

impl CatalogRequestView {
    fn from_config(config: &Config) -> Self {
        let channels_json = serde_json::to_value(&config.channels).unwrap_or_default();
        let configured = |kind: &str| {
            let kind = zeroclaw_channels::listing::canonical_channel_type(&config.channels, kind)
                .unwrap_or(kind);
            channels_json
                .get(kind)
                .and_then(serde_json::Value::as_object)
                .is_some_and(|aliases| {
                    aliases.values().any(|alias| {
                        alias.get("enabled").and_then(serde_json::Value::as_bool) == Some(true)
                    })
                })
        };

        let compiled = zeroclaw_channels::listing::compiled_channels(&config.channels)
            .into_iter()
            .filter(|channel| channel.configured)
            .map(|channel| (channel, true));
        let uncompiled =
            zeroclaw_channels::listing::configured_uncompiled_channels(&config.channels)
                .into_iter()
                .map(|channel| (channel, false));
        let mut builtins = std::collections::BTreeMap::<String, BuiltinView>::new();
        for (channel, compiled_in) in compiled.chain(uncompiled) {
            let id =
                zeroclaw_channels::listing::canonical_channel_type(&config.channels, channel.kind)
                    .unwrap_or(channel.kind)
                    .to_string();
            let channel_configured = configured(&id);
            builtins
                .entry(id.clone())
                .and_modify(|view| {
                    view.compiled_in |= compiled_in;
                    view.configured |= channel_configured;
                    view.toggleable |= channel.configured;
                })
                .or_insert_with(|| BuiltinView {
                    id,
                    display_name: channel.name.to_string(),
                    description: channel.desc.to_string(),
                    compiled_in,
                    configured: channel_configured,
                    toggleable: channel.configured,
                });
        }

        Self {
            plugins_enabled: config.plugins.enabled,
            plugins_dir: config.plugins.plugins_dir.clone(),
            builtins: builtins.into_values().collect(),
            #[cfg(feature = "plugins-wasm")]
            plugin_path: config.plugins.resolved_plugins_dir(),
            #[cfg(feature = "plugins-wasm")]
            signature_mode: config.plugins.security.signature_mode.clone(),
            #[cfg(feature = "plugins-wasm")]
            trusted_publisher_keys: config.plugins.security.trusted_publisher_keys.clone(),
            #[cfg(feature = "plugins-wasm")]
            data_dir: config.data_dir.clone(),
            #[cfg(feature = "plugins-wasm")]
            active_channels: zeroclaw_config::schema::ActiveChannelAliases::compute(config),
        }
    }
}

/// `GET /api/plugins` — return the unified capability catalog plus the legacy
/// installed-plugin fields. Enable/disable remains owned by config APIs.
pub async fn list_plugins(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if state.pairing.require_pairing() {
        let token = headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|auth| auth.strip_prefix("Bearer "))
            .unwrap_or("");
        if !state.pairing.is_authenticated(token) {
            return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
        }
    }

    let request = CatalogRequestView::from_config(&state.config.read());
    Json(build_response(request)).into_response()
}

#[cfg(not(feature = "plugins-wasm"))]
fn build_response(request: CatalogRequestView) -> PluginsResponse {
    PluginsResponse {
        plugins_enabled: request.plugins_enabled,
        wasm_plugins_available: false,
        plugins_dir: request.plugins_dir,
        plugins: Vec::new(),
        capabilities: request
            .builtins
            .into_iter()
            .map(|builtin| PluginCatalogEntry {
                kind: "channel".to_string(),
                id: builtin.id,
                display_name: Some(builtin.display_name),
                description: Some(builtin.description),
                compiled_in: builtin.compiled_in,
                installed: false,
                available: false,
                mirrors_builtin: false,
                conflicted: false,
                toggleable: builtin.toggleable,
                origin: PluginCatalogOrigin::BuiltIn,
                configured: builtin.configured,
                version: None,
                plugin_name: None,
                install_source: None,
                registry_origin: None,
                permissions: Vec::new(),
            })
            .collect(),
        issues: Vec::new(),
    }
}

#[cfg(feature = "plugins-wasm")]
fn build_response(request: CatalogRequestView) -> PluginsResponse {
    use zeroclaw_plugins::catalog::{
        BuiltinSeed, available_seeds, installed_seeds, merge_capabilities,
    };

    let CatalogRequestView {
        plugins_enabled,
        plugins_dir,
        builtins,
        plugin_path,
        signature_mode,
        trusted_publisher_keys,
        data_dir,
        active_channels,
    } = request;

    let configured_channels: std::collections::HashSet<String> = builtins
        .iter()
        .filter(|builtin| builtin.configured)
        .map(|builtin| builtin.id.clone())
        .collect();
    let toggleable_channels: std::collections::HashSet<String> = builtins
        .iter()
        .filter(|builtin| builtin.toggleable)
        .map(|builtin| builtin.id.clone())
        .collect();
    let builtin_seeds = builtins.into_iter().map(|builtin| BuiltinSeed {
        id: builtin.id,
        kind: zeroclaw_plugins::catalog::CapabilityKind::Channel,
        display: Some(builtin.display_name),
        description: Some(builtin.description),
        compiled: builtin.compiled_in,
        configured: builtin.configured,
        toggleable: builtin.toggleable,
    });

    let mut issues = Vec::new();
    let host = match plugin_path.try_exists() {
        Ok(true) => {
            let mode = zeroclaw_plugins::host::PluginHost::resolve_signature_mode(&signature_mode);
            match zeroclaw_plugins::host::PluginHost::from_plugins_dir_with_security_report(
                &plugin_path,
                mode,
                trusted_publisher_keys,
            ) {
                Ok((host, report)) => {
                    if report.has_failures() {
                        ::zeroclaw_log::record!(
                            WARN,
                            ::zeroclaw_log::Event::new(
                                module_path!(),
                                ::zeroclaw_log::Action::Note,
                            )
                            .with_outcome(::zeroclaw_log::EventOutcome::Failure)
                            .with_attrs(::serde_json::json!({
                                "failure_count": report.failure_count(),
                                "error_key": "plugin_catalog_discovery_partial",
                            })),
                            "plugin catalog discovery was partial"
                        );
                        issues.push(PluginCatalogIssue {
                            source: PluginCatalogIssueSource::Installed,
                            code: PluginCatalogIssueCode::DiscoveryFailed,
                        });
                    }
                    Some(host)
                }
                Err(error) => {
                    ::zeroclaw_log::record!(
                        ERROR,
                        ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Fail)
                            .with_outcome(::zeroclaw_log::EventOutcome::Failure)
                            .with_attrs(::serde_json::json!({
                                "error": error.to_string(),
                                "error_key": "plugin_catalog_discovery_failed",
                            })),
                        "plugin catalog discovery failed"
                    );
                    issues.push(PluginCatalogIssue {
                        source: PluginCatalogIssueSource::Installed,
                        code: PluginCatalogIssueCode::DiscoveryFailed,
                    });
                    None
                }
            }
        }
        Ok(false) => None,
        Err(error) => {
            ::zeroclaw_log::record!(
                ERROR,
                ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Fail)
                    .with_outcome(::zeroclaw_log::EventOutcome::Failure)
                    .with_attrs(::serde_json::json!({
                        "error": error.to_string(),
                        "error_key": "plugin_catalog_discovery_metadata_failed",
                    })),
                "plugin catalog directory metadata could not be read"
            );
            issues.push(PluginCatalogIssue {
                source: PluginCatalogIssueSource::Installed,
                code: PluginCatalogIssueCode::DiscoveryFailed,
            });
            None
        }
    };

    let installed = host
        .as_ref()
        .map(|host| {
            installed_seeds(
                host,
                plugins_enabled,
                |id, mirrors_builtin| {
                    if mirrors_builtin {
                        configured_channels.contains(id)
                    } else {
                        active_channels.contains(id)
                    }
                },
                |id, mirrors_builtin| mirrors_builtin && toggleable_channels.contains(id),
            )
        })
        .unwrap_or_default();
    let available = match zeroclaw_plugins::registry::read_cached_registry_index(&data_dir) {
        Ok(Some(index)) => available_seeds(&index),
        Ok(None) => Vec::new(),
        Err(error) => {
            ::zeroclaw_log::record!(
                ERROR,
                ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Fail)
                    .with_outcome(::zeroclaw_log::EventOutcome::Failure)
                    .with_attrs(::serde_json::json!({
                        "error": error.to_string(),
                        "error_key": "plugin_catalog_registry_cache_read_failed",
                    })),
                "plugin catalog registry cache could not be read"
            );
            issues.push(PluginCatalogIssue {
                source: PluginCatalogIssueSource::Registry,
                code: PluginCatalogIssueCode::CacheReadFailed,
            });
            Vec::new()
        }
    };

    let capabilities = merge_capabilities(builtin_seeds.collect(), installed, available)
        .into_iter()
        .map(PluginCatalogEntry::from)
        .collect();
    let mut plugins: Vec<InstalledPlugin> = host
        .as_ref()
        .map(|host| {
            host.list_plugins()
                .into_iter()
                .map(InstalledPlugin::from)
                .collect()
        })
        .unwrap_or_default();
    plugins.sort_by(|left, right| left.name.cmp(&right.name));

    PluginsResponse {
        plugins_enabled,
        wasm_plugins_available: true,
        plugins_dir,
        plugins,
        capabilities,
        issues,
    }
}

#[cfg(feature = "plugins-wasm")]
impl From<zeroclaw_plugins::catalog::CapabilityCatalogEntry> for PluginCatalogEntry {
    fn from(entry: zeroclaw_plugins::catalog::CapabilityCatalogEntry) -> Self {
        use zeroclaw_plugins::catalog::{CapabilityKind, CapabilityOrigin, CatalogRegistryOrigin};

        let kind = match entry.kind {
            CapabilityKind::Channel => "channel".to_string(),
            CapabilityKind::Tool => "tool".to_string(),
            CapabilityKind::Memory => "memory".to_string(),
            CapabilityKind::Observer => "observer".to_string(),
            CapabilityKind::Skill => "skill".to_string(),
            CapabilityKind::Other(other) => other,
        };
        let origin = match entry.origin {
            CapabilityOrigin::BuiltIn => PluginCatalogOrigin::BuiltIn,
            CapabilityOrigin::Plugin => PluginCatalogOrigin::Plugin,
            CapabilityOrigin::Registry => PluginCatalogOrigin::Registry,
        };
        let registry_origin = entry.registry_origin.map(|origin| match origin {
            CatalogRegistryOrigin::Default => PluginCatalogRegistryOrigin::Default,
            CatalogRegistryOrigin::Custom => PluginCatalogRegistryOrigin::Custom,
        });

        Self {
            kind,
            id: entry.id,
            display_name: entry.display_name,
            description: entry.description,
            compiled_in: entry.compiled_in,
            installed: entry.installed,
            available: entry.available,
            mirrors_builtin: entry.mirrors_builtin,
            conflicted: entry.conflicted,
            toggleable: entry.toggleable,
            origin,
            configured: entry.configured,
            version: entry.version,
            plugin_name: entry.plugin_name,
            install_source: entry.install_source,
            registry_origin,
            permissions: entry.permissions,
        }
    }
}

#[cfg(feature = "plugins-wasm")]
impl From<zeroclaw_plugins::PluginInfo> for InstalledPlugin {
    fn from(plugin: zeroclaw_plugins::PluginInfo) -> Self {
        let capabilities = plugin
            .capabilities
            .into_iter()
            .map(|capability| match capability {
                zeroclaw_plugins::PluginCapability::Channel => "channel".to_string(),
                zeroclaw_plugins::PluginCapability::Tool => "tool".to_string(),
                zeroclaw_plugins::PluginCapability::Memory => "memory".to_string(),
                zeroclaw_plugins::PluginCapability::Observer => "observer".to_string(),
                zeroclaw_plugins::PluginCapability::Skill => "skill".to_string(),
            })
            .collect();
        Self {
            name: plugin.name,
            version: plugin.version,
            description: plugin.description,
            capabilities,
            loaded: plugin.loaded,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_reports_compile_time_wasm_availability() {
        let response = build_response(CatalogRequestView::from_config(&Config::default()));
        assert_eq!(
            response.wasm_plugins_available,
            cfg!(feature = "plugins-wasm")
        );
    }

    #[test]
    fn request_view_uses_canonical_channel_ids_and_explicit_toggleability() {
        let mut config = Config::default();
        config
            .channels
            .nextcloud_talk
            .insert("primary".to_string(), Default::default());
        config
            .channels
            .nextcloud_talk
            .get_mut("primary")
            .expect("nextcloud alias")
            .enabled = true;

        let request = CatalogRequestView::from_config(&config);
        let canonical = request
            .builtins
            .iter()
            .find(|builtin| builtin.id == "nextcloud_talk")
            .expect("canonical nextcloud family");
        assert!(canonical.configured);
        assert!(canonical.toggleable);
        assert!(
            request
                .builtins
                .iter()
                .all(|builtin| builtin.id != "nextcloud")
        );
    }

    #[cfg(feature = "plugins-wasm")]
    #[test]
    fn installed_plugins_remain_visible_while_subsystem_is_disabled() {
        let temp = tempfile::tempdir().expect("temporary plugin catalog");
        let plugin_dir = temp.path().join("plugins/example");
        std::fs::create_dir_all(&plugin_dir).expect("plugin directory");
        std::fs::write(plugin_dir.join("plugin.wasm"), b"\0asm").expect("component fixture");
        std::fs::write(
            plugin_dir.join("manifest.toml"),
            concat!(
                "name = \"example\"\n",
                "version = \"1.0.0\"\n",
                "wasm_path = \"plugin.wasm\"\n",
                "capabilities = [\"tool\"]\n",
            ),
        )
        .expect("manifest fixture");
        let mut config = Config::default();
        config.plugins.enabled = false;
        config.plugins.plugins_dir = temp.path().join("plugins").display().to_string();

        let response = build_response(CatalogRequestView::from_config(&config));
        let capability = response
            .capabilities
            .iter()
            .find(|entry| entry.id == "example")
            .expect("installed capability remains discoverable");
        assert!(capability.installed);
        assert!(!capability.configured);
        assert_eq!(response.plugins.len(), 1);
        assert!(!response.plugins_enabled);
    }

    #[cfg(feature = "plugins-wasm")]
    #[test]
    fn malformed_installed_candidate_reports_partial_discovery_and_preserves_valid_entries() {
        let temp = tempfile::tempdir().expect("temporary plugin catalog");
        let valid_dir = temp.path().join("plugins/valid-tool");
        std::fs::create_dir_all(&valid_dir).expect("valid plugin directory");
        std::fs::write(valid_dir.join("plugin.wasm"), b"\0asm").expect("component fixture");
        std::fs::write(
            valid_dir.join("manifest.toml"),
            concat!(
                "name = \"valid-tool\"\n",
                "version = \"1.0.0\"\n",
                "wasm_path = \"plugin.wasm\"\n",
                "capabilities = [\"tool\"]\n",
            ),
        )
        .expect("valid manifest fixture");
        let malformed_dir = temp.path().join("plugins/malformed-tool");
        std::fs::create_dir_all(&malformed_dir).expect("malformed plugin directory");
        std::fs::write(malformed_dir.join("manifest.toml"), "this is not toml")
            .expect("malformed manifest fixture");
        let mut config = Config::default();
        config.plugins.plugins_dir = temp.path().join("plugins").display().to_string();

        let response = build_response(CatalogRequestView::from_config(&config));
        assert!(response.issues.contains(&PluginCatalogIssue {
            source: PluginCatalogIssueSource::Installed,
            code: PluginCatalogIssueCode::DiscoveryFailed,
        }));
        assert!(
            response
                .capabilities
                .iter()
                .any(|entry| entry.id == "valid-tool" && entry.installed)
        );
        assert_eq!(response.plugins.len(), 1);
    }

    #[cfg(feature = "plugins-wasm")]
    #[test]
    fn strict_signature_rejection_reports_discovery_failure_instead_of_empty_success() {
        let temp = tempfile::tempdir().expect("temporary strict plugin catalog");
        let plugin_dir = temp.path().join("plugins/unsigned-tool");
        std::fs::create_dir_all(&plugin_dir).expect("plugin directory");
        std::fs::write(plugin_dir.join("plugin.wasm"), b"\0asm").expect("component fixture");
        std::fs::write(
            plugin_dir.join("manifest.toml"),
            concat!(
                "name = \"unsigned-tool\"\n",
                "version = \"1.0.0\"\n",
                "wasm_path = \"plugin.wasm\"\n",
                "capabilities = [\"tool\"]\n",
            ),
        )
        .expect("manifest fixture");
        let mut config = Config::default();
        config.plugins.plugins_dir = temp.path().join("plugins").display().to_string();
        config.plugins.security.signature_mode = "strict".to_string();

        let response = build_response(CatalogRequestView::from_config(&config));
        assert!(response.issues.contains(&PluginCatalogIssue {
            source: PluginCatalogIssueSource::Installed,
            code: PluginCatalogIssueCode::DiscoveryFailed,
        }));
        assert!(response.plugins.is_empty());
        assert!(
            response
                .capabilities
                .iter()
                .all(|entry| entry.plugin_name.as_deref() != Some("unsigned-tool"))
        );
    }

    #[cfg(feature = "plugins-wasm")]
    #[test]
    fn plugin_directory_metadata_failure_is_not_reported_as_empty_success() {
        let temp = tempfile::tempdir().expect("temporary plugin catalog");
        let non_directory = temp.path().join("not-a-directory");
        std::fs::write(&non_directory, b"file").expect("blocking file fixture");
        let mut config = Config::default();
        config.plugins.plugins_dir = non_directory.join("plugins").display().to_string();

        let response = build_response(CatalogRequestView::from_config(&config));
        assert!(response.issues.contains(&PluginCatalogIssue {
            source: PluginCatalogIssueSource::Installed,
            code: PluginCatalogIssueCode::DiscoveryFailed,
        }));
        assert!(response.plugins.is_empty());
    }

    #[cfg(feature = "plugins-wasm")]
    #[test]
    fn installed_mirror_uses_canonical_alias_enablement_when_builtin_is_uncompiled() {
        let temp = tempfile::tempdir().expect("temporary mirror catalog");
        let plugin_dir = temp.path().join("plugins/telegram-mirror");
        std::fs::create_dir_all(&plugin_dir).expect("plugin directory");
        std::fs::write(plugin_dir.join("plugin.wasm"), b"\0asm").expect("component fixture");
        std::fs::write(
            plugin_dir.join("manifest.toml"),
            concat!(
                "name = \"telegram-mirror\"\n",
                "version = \"1.0.0\"\n",
                "wasm_path = \"plugin.wasm\"\n",
                "capabilities = [\"channel\"]\n",
                "provides = \"telegram\"\n",
            ),
        )
        .expect("manifest fixture");
        let mut config = Config::default();
        config.plugins.enabled = true;
        config.plugins.plugins_dir = temp.path().join("plugins").display().to_string();
        config
            .channels
            .telegram
            .insert("mirror".to_string(), Default::default());
        config
            .channels
            .telegram
            .get_mut("mirror")
            .expect("telegram alias")
            .enabled = true;

        let response = build_response(CatalogRequestView::from_config(&config));
        let capability = response
            .capabilities
            .iter()
            .find(|entry| entry.id == "telegram")
            .expect("mirrored channel capability");
        assert!(!capability.compiled_in);
        assert!(capability.installed);
        assert!(capability.configured);
        assert!(capability.toggleable);
        assert!(!capability.conflicted);
    }

    #[cfg(feature = "plugins-wasm")]
    #[test]
    fn novel_channel_configuration_follows_canonical_agent_bindings() {
        use zeroclaw_config::providers::ChannelRef;
        use zeroclaw_config::schema::AliasedAgentConfig;

        let temp = tempfile::tempdir().expect("temporary novel channel catalog");
        let plugin_dir = temp.path().join("plugins/novel-channel");
        std::fs::create_dir_all(&plugin_dir).expect("plugin directory");
        std::fs::write(plugin_dir.join("plugin.wasm"), b"\0asm").expect("component fixture");
        std::fs::write(
            plugin_dir.join("manifest.toml"),
            concat!(
                "name = \"novel-channel\"\n",
                "version = \"1.0.0\"\n",
                "wasm_path = \"plugin.wasm\"\n",
                "capabilities = [\"channel\"]\n",
            ),
        )
        .expect("manifest fixture");
        let mut config = Config::default();
        config.plugins.enabled = true;
        config.plugins.plugins_dir = temp.path().join("plugins").display().to_string();
        config.agents.insert(
            "alpha".to_string(),
            AliasedAgentConfig {
                channels: vec![ChannelRef::new("telegram.primary")],
                ..AliasedAgentConfig::default()
            },
        );

        let response = build_response(CatalogRequestView::from_config(&config));
        let novel = response
            .capabilities
            .iter()
            .find(|entry| entry.id == "plugin.novel-channel")
            .expect("novel channel capability");
        assert!(
            !novel.configured,
            "an unrelated explicit binding fails closed"
        );
        assert!(
            !novel.toggleable,
            "novel channels have no typed config toggle"
        );

        config
            .agents
            .get_mut("alpha")
            .expect("test agent")
            .channels
            .push(ChannelRef::new("plugin.novel-channel"));
        let response = build_response(CatalogRequestView::from_config(&config));
        let novel = response
            .capabilities
            .iter()
            .find(|entry| entry.id == "plugin.novel-channel")
            .expect("novel channel capability");
        assert!(novel.configured);
    }

    #[cfg(feature = "plugins-wasm")]
    #[test]
    fn registry_cache_failure_is_not_reported_as_empty_success() {
        let temp = tempfile::tempdir().expect("temporary registry cache");
        let cache_dir = temp.path().join("plugin-registry");
        std::fs::create_dir_all(&cache_dir).expect("registry cache directory");
        std::fs::write(cache_dir.join("registry.json"), "not json").expect("invalid cache");
        let config = Config {
            data_dir: temp.path().to_path_buf(),
            ..Config::default()
        };

        let response = build_response(CatalogRequestView::from_config(&config));
        assert!(response.issues.contains(&PluginCatalogIssue {
            source: PluginCatalogIssueSource::Registry,
            code: PluginCatalogIssueCode::CacheReadFailed,
        }));
    }

    #[cfg(feature = "plugins-wasm")]
    #[test]
    fn registry_cache_io_failure_is_not_reported_as_empty_success() {
        let temp = tempfile::tempdir().expect("temporary registry cache");
        let cache_dir = temp.path().join("plugin-registry");
        std::fs::create_dir_all(&cache_dir).expect("registry cache directory");
        std::fs::write(cache_dir.join("registry.json"), [0xff]).expect("non-UTF-8 registry cache");
        let config = Config {
            data_dir: temp.path().to_path_buf(),
            ..Config::default()
        };

        let response = build_response(CatalogRequestView::from_config(&config));
        assert!(response.issues.contains(&PluginCatalogIssue {
            source: PluginCatalogIssueSource::Registry,
            code: PluginCatalogIssueCode::CacheReadFailed,
        }));
    }

    #[cfg(feature = "plugins-wasm")]
    #[test]
    fn registry_install_metadata_is_exact_without_exposing_registry_urls() {
        use zeroclaw_plugins::registry::{
            DEFAULT_REGISTRY_URL, PluginRegistryEntry, PluginRegistryIndex,
            write_cached_registry_index,
        };

        let registry_entry = |version: &str| PluginRegistryEntry {
            name: "gitea".to_string(),
            version: version.to_string(),
            description: None,
            author: None,
            capabilities: vec!["channel".to_string()],
            provides: Some("git".to_string()),
            sender_match: None,
            url: format!("https://example.invalid/gitea-{version}.zip"),
            sha256: None,
        };
        let index = PluginRegistryIndex {
            plugins: vec![registry_entry("0.1.0"), registry_entry("0.2.0")],
            registry_url: None,
        };

        for (registry_url, expected_origin) in [
            (DEFAULT_REGISTRY_URL, PluginCatalogRegistryOrigin::Default),
            (
                "https://user:secret@example.invalid/registry.json?token=private",
                PluginCatalogRegistryOrigin::Custom,
            ),
        ] {
            let temp = tempfile::tempdir().expect("temporary registry cache");
            write_cached_registry_index(temp.path(), registry_url, &index)
                .expect("cached registry index");
            let config = Config {
                data_dir: temp.path().to_path_buf(),
                ..Config::default()
            };

            let response = build_response(CatalogRequestView::from_config(&config));
            let git = response
                .capabilities
                .iter()
                .find(|entry| entry.id == "git")
                .expect("registry mirror capability");
            assert_eq!(git.install_source.as_deref(), Some("gitea@0.2.0"));
            assert_eq!(git.registry_origin, Some(expected_origin));
            let response_json = serde_json::to_string(&response).expect("catalog JSON");
            assert!(!response_json.contains(registry_url));
            assert!(!response_json.contains("registry_url"));
            assert!(!response_json.contains("token=private"));
        }
    }
}
