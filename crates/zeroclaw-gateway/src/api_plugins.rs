//! Plugin management API routes (requires `plugins-wasm` feature).

#[cfg(feature = "plugins-wasm")]
pub mod plugin_routes {
    use axum::{
        extract::State,
        http::{HeaderMap, StatusCode, header},
        response::{IntoResponse, Json},
    };
    use serde_json::Value;

    use super::super::AppState;
    use zeroclaw_plugins::catalog::{
        BuiltinSeed, CapabilityKind, available_seeds, installed_seeds, merge_capabilities,
    };

    /// `GET /api/plugins` — the unified capability catalog (built-in channels,
    /// installed plugins, and registry-available plugins), plus back-compat
    /// fields. Enable/disable is not a dedicated route: the dashboard toggles a
    /// channel via the existing `PATCH /api/config/prop`
    /// (`channels.<type>.<alias>.enabled`), the same SSOT the CLI writes.
    pub async fn list_plugins(
        State(state): State<AppState>,
        headers: HeaderMap,
    ) -> impl IntoResponse {
        // Auth check (paired Bearer token; open gateway passes).
        if state.pairing.require_pairing() {
            let token = headers
                .get(header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .and_then(|auth| auth.strip_prefix("Bearer "))
                .unwrap_or("");
            if !state.pairing.is_authenticated(token) {
                return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
            }
        }

        let config = state.config.read();
        let plugins_enabled = config.plugins.enabled;
        let plugins_dir = config.plugins.plugins_dir.clone();
        let plugin_path = config.plugins.resolved_plugins_dir();
        let signature_mode_raw = config.plugins.security.signature_mode.clone();
        let trusted_publisher_keys = config.plugins.security.trusted_publisher_keys.clone();
        let data_dir = config.data_dir.clone();

        // Built-in channel seeds + a per-type "any alias enabled" lookup, read
        // from the serialized channels tree (owned, so the config lock can drop).
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
        let mut builtins: Vec<BuiltinSeed> = Vec::new();
        for ci in zeroclaw_channels::listing::compiled_channels(&config.channels) {
            if ci.configured {
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
        drop(config);

        // Installed plugins — resolve the configured signature policy so the
        // listing matches the runtime tool path exactly (a plugin the agent
        // refuses in strict mode must not show `loaded: true`); unrecognized
        // values fail safe to strict.
        let host = if plugins_enabled && plugin_path.exists() {
            let mode =
                zeroclaw_plugins::host::PluginHost::resolve_signature_mode(&signature_mode_raw);
            zeroclaw_plugins::host::PluginHost::from_plugins_dir_with_security(
                &plugin_path,
                mode,
                trusted_publisher_keys,
            )
            .ok()
        } else {
            None
        };

        let installed = host
            .as_ref()
            .map(|h| installed_seeds(h, plugins_enabled, type_enabled))
            .unwrap_or_default();
        let available = zeroclaw_plugins::registry::read_cached_registry_index(&data_dir)
            .ok()
            .flatten()
            .map(|idx| available_seeds(&idx))
            .unwrap_or_default();
        let catalog = merge_capabilities(builtins, installed, available);
        let capabilities = serde_json::to_value(&catalog).unwrap_or(Value::Null);

        // Back-compat: the flat installed-plugin list earlier clients read.
        let plugins: Vec<Value> = host
            .as_ref()
            .map(|h| {
                h.list_plugins()
                    .into_iter()
                    .map(|p| {
                        serde_json::json!({
                            "name": p.name,
                            "version": p.version,
                            "description": p.description,
                            "capabilities": p.capabilities,
                            "loaded": p.loaded,
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();

        Json(serde_json::json!({
            "plugins_enabled": plugins_enabled,
            "plugins_dir": plugins_dir,
            "plugins": plugins,
            "capabilities": capabilities,
        }))
        .into_response()
    }
}
