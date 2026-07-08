//! Build installed WASM channel plugins into runnable [`Channel`] trait objects.
//!
//! The tool-plugin equivalent lives inline in [`crate::tools`]; this is the
//! channel side. The channel orchestrator (`zeroclaw-channels`) deliberately
//! does **not** depend on `zeroclaw-plugins` (that would pull wasmtime into the
//! channels crate), so it cannot name `WasmChannel`/`PluginHost` directly.
//! `zeroclaw-runtime` already depends on both `zeroclaw-plugins` and
//! `zeroclaw-api`, and the dependency direction is `channels → runtime`, so this
//! helper is the cycle-safe home for the wiring: the orchestrator calls it and
//! applies native-wins dedup itself (it owns the set of compiled-in channel ids).

use std::sync::Arc;

use zeroclaw_api::channel::Channel;
use zeroclaw_api::webhook::PluginWebhookRegistry;
use zeroclaw_config::schema::Config;

/// A channel plugin built into a runnable trait object, plus the identity the
/// orchestrator needs to dedup it against native channels.
pub struct BuiltChannelPlugin {
    /// Native-wins dedup key. A **mirror** (a plugin that `provides` a built-in
    /// channel id) uses the composite `"<id>.<alias>"` so it matches a
    /// compiled-in channel's per-alias registry key; a **novel** plugin uses its
    /// bare manifest name.
    pub dedup_key: String,
    /// ZeroClaw channel alias for the runtime registry: `Some(<config-alias>)`
    /// for a mirror, `None` for a novel singleton plugin channel.
    pub alias: Option<String>,
    /// The runnable channel, registered and supervised exactly like a native one.
    pub channel: Arc<dyn Channel>,
}

/// Instantiate every installed channel plugin.
///
/// A plugin that declares `provides = "<channel-id>"` **mirrors** the compiled
/// channel of that id: one instance per configured & enabled
/// `[channels.<id>.<alias>]`, each fed that alias's plaintext canonical config
/// (the same source of truth the native channel reads — no second config home).
/// A plugin without `provides` is **novel**: a single instance keyed by its
/// manifest name, configured from its `[[plugins.entries.<name>]]` map.
///
/// Returns empty when the plugin system is disabled, the plugins directory is
/// absent, or the host fails to load. Per-plugin failures are logged and skipped
/// so one broken component cannot sink channel startup. The
/// `#[cfg(not(feature = "plugins-wasm"))]` stub returns empty for builds with no
/// WASM engine, so the call site compiles unconditionally.
#[cfg(feature = "plugins-wasm")]
pub async fn build_channel_plugins(
    config: &Config,
    webhooks: Option<&PluginWebhookRegistry>,
) -> Vec<BuiltChannelPlugin> {
    let plugin_path = config.plugins.resolved_plugins_dir();
    if !config.plugins.enabled || !plugin_path.exists() {
        return Vec::new();
    }

    let signature_mode = zeroclaw_plugins::host::PluginHost::resolve_signature_mode(
        &config.plugins.security.signature_mode,
    );
    let trusted_publisher_keys = config.plugins.security.trusted_publisher_keys.clone();
    let host = match zeroclaw_plugins::host::PluginHost::from_plugins_dir_with_security(
        &plugin_path,
        signature_mode,
        trusted_publisher_keys,
    ) {
        Ok(host) => host,
        Err(e) => {
            ::zeroclaw_log::record!(
                WARN,
                ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Note)
                    .with_outcome(::zeroclaw_log::EventOutcome::Unknown)
                    .with_attrs(::serde_json::json!({ "error": format!("{}", e) })),
                "Failed to load WASM channel plugins"
            );
            return Vec::new();
        }
    };

    let limits = zeroclaw_plugins::component::PluginLimits {
        call_fuel: config.plugins.limits.call_fuel,
        max_memory_bytes: config
            .plugins
            .limits
            .max_memory_mb
            .saturating_mul(1024 * 1024),
        max_table_elements: config.plugins.limits.max_table_elements,
        max_instances: config.plugins.limits.max_instances,
    };

    // Serialize the live (post-decrypt) channel config once. Secrets are
    // plaintext here — the `#[secret]` `mask()` is applied only to throwaway
    // display/gateway clones, never to the runtime `Config` the daemon holds.
    // Indexing `[id][alias]` gives a mirror the exact typed section its native
    // counterpart reads, so there is no second config home (AGENTS.md SSOT).
    let channels_json =
        ::serde_json::to_value(&config.channels).unwrap_or(::serde_json::Value::Null);

    let mut built: Vec<BuiltChannelPlugin> = Vec::new();
    for (manifest, wasm_path) in host.channel_plugin_details() {
        match manifest.provides.as_deref() {
            Some(id) => {
                let Some(aliases) = channels_json.get(id).and_then(|v| v.as_object()) else {
                    ::zeroclaw_log::record!(
                        WARN,
                        ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Note)
                            .with_outcome(::zeroclaw_log::EventOutcome::Unknown)
                            .with_attrs(::serde_json::json!({
                                "plugin": manifest.name.clone(),
                                "provides": id,
                            })),
                        "Channel plugin `provides` an unknown or unconfigured channel id; skipping"
                    );
                    continue;
                };
                // A mirror is configured from the canonical section, which is
                // withheld without ConfigRead — a credential-less channel is
                // worse than none, so skip rather than start it dead.
                if !manifest
                    .permissions
                    .contains(&zeroclaw_plugins::PluginPermission::ConfigRead)
                {
                    ::zeroclaw_log::record!(
                        WARN,
                        ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Note)
                            .with_outcome(::zeroclaw_log::EventOutcome::Unknown)
                            .with_attrs(::serde_json::json!({
                                "plugin": manifest.name.clone(),
                                "provides": id,
                            })),
                        "Mirror channel plugin lacks config_read; skipping (would start unconfigured)"
                    );
                    continue;
                }
                for (alias, cfg_obj) in aliases {
                    let enabled = cfg_obj
                        .get("enabled")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    if !enabled {
                        continue;
                    }
                    let resolved = apply_env_fallbacks(cfg_obj, id);
                    let config_json =
                        ::serde_json::to_string(&resolved).unwrap_or_else(|_| "{}".to_string());
                    match zeroclaw_plugins::wasm_channel::WasmChannel::from_wasm_mirror(
                        id,
                        alias.as_str(),
                        wasm_path,
                        &manifest.permissions,
                        &config_json,
                        limits,
                    )
                    .await
                    {
                        Ok(channel) => {
                            register_plugin_webhook(
                                &channel,
                                &manifest.name,
                                &manifest.permissions,
                                webhooks,
                            )
                            .await;
                            built.push(BuiltChannelPlugin {
                                dedup_key: format!("{id}.{alias}"),
                                alias: Some(alias.clone()),
                                channel: Arc::new(channel),
                            });
                        }
                        Err(e) => log_instantiate_failure(&manifest.name, &e),
                    }
                }
            }
            None => {
                // Novel plugin: sole config home is [[plugins.entries.<name>]].
                let plugin_config = config
                    .plugins
                    .entry_config(&manifest.name)
                    .cloned()
                    .unwrap_or_default();
                match zeroclaw_plugins::wasm_channel::WasmChannel::from_wasm(
                    manifest.name.clone(),
                    wasm_path,
                    &manifest.permissions,
                    &plugin_config,
                    limits,
                )
                .await
                {
                    Ok(channel) => {
                        register_plugin_webhook(
                            &channel,
                            &manifest.name,
                            &manifest.permissions,
                            webhooks,
                        )
                        .await;
                        built.push(BuiltChannelPlugin {
                            dedup_key: manifest.name.clone(),
                            alias: None,
                            channel: Arc::new(channel),
                        });
                    }
                    Err(e) => log_instantiate_failure(&manifest.name, &e),
                }
            }
        }
    }
    built
}

/// Overlay env-var credentials onto a mirror's canonical config, reproducing
/// the native channels' `resolved_*` fallback (e.g. Slack's `SLACK_BOT_TOKEN`,
/// Telegram's `TELEGRAM_BOT_TOKEN`): for each **present-but-empty string** field,
/// fill it from `ZEROCLAW_<ID>_<FIELD>` (preferred, so ZeroClaw-scoped secrets
/// win) or the conventional `<ID>_<FIELD>`. Config always wins over env; only
/// blank fields are filled, and non-string / non-empty fields are untouched.
///
/// Limitation vs. native: a field entirely **absent** from the config object
/// (e.g. dropped by `skip_serializing_if`) is not added — the generic view can't
/// know a channel's field names. Set the field to `""` in config to opt it into
/// env resolution.
#[cfg(feature = "plugins-wasm")]
fn apply_env_fallbacks(cfg_obj: &::serde_json::Value, id: &str) -> ::serde_json::Value {
    let mut obj = cfg_obj.clone();
    let Some(map) = obj.as_object_mut() else {
        return obj;
    };
    let id_up = id.to_ascii_uppercase();
    for (field, value) in map.iter_mut() {
        if value.as_str() != Some("") {
            continue;
        }
        let field_up = field.to_ascii_uppercase();
        for key in [
            format!("ZEROCLAW_{id_up}_{field_up}"),
            format!("{id_up}_{field_up}"),
        ] {
            if let Ok(v) = std::env::var(&key) {
                let v = v.trim();
                if !v.is_empty() {
                    *value = ::serde_json::Value::String(v.to_string());
                    break;
                }
            }
        }
    }
    obj
}

#[cfg(feature = "plugins-wasm")]
fn log_instantiate_failure(plugin: &str, err: &anyhow::Error) {
    ::zeroclaw_log::record!(
        WARN,
        ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Note)
            .with_outcome(::zeroclaw_log::EventOutcome::Unknown)
            .with_attrs(::serde_json::json!({
                "plugin": plugin,
                "error": format!("{}", err),
            })),
        "Failed to instantiate WASM channel plugin"
    );
}

/// If a built channel advertises `webhook-ingress`, claim its declared path in
/// the shared registry and hand it the sink drain end so the gateway can feed
/// inbound. Requires `ConfigRead` (the channel's secret home — it verifies the
/// webhook signature). Path collisions, a missing registry, or a missing
/// permission are logged and skipped (the channel simply gets no inbound), never
/// fatal to startup.
#[cfg(feature = "plugins-wasm")]
async fn register_plugin_webhook(
    channel: &zeroclaw_plugins::wasm_channel::WasmChannel,
    plugin: &str,
    permissions: &[zeroclaw_plugins::PluginPermission],
    webhooks: Option<&PluginWebhookRegistry>,
) {
    let Some(registry) = webhooks else { return };
    if !channel.has_webhook_ingress() {
        return;
    }
    if !permissions.contains(&zeroclaw_plugins::PluginPermission::ConfigRead) {
        ::zeroclaw_log::record!(
            WARN,
            ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Note)
                .with_outcome(::zeroclaw_log::EventOutcome::Unknown)
                .with_attrs(::serde_json::json!({ "plugin": plugin })),
            "Webhook channel plugin lacks config_read; inbound disabled"
        );
        return;
    }
    let Some(path) = channel.webhook_path().await else {
        return;
    };
    if path.is_empty() || path.contains('/') || path.contains('.') {
        ::zeroclaw_log::record!(
            WARN,
            ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Note)
                .with_outcome(::zeroclaw_log::EventOutcome::Unknown)
                .with_attrs(::serde_json::json!({ "plugin": plugin, "path": path })),
            "Webhook plugin declared an invalid path (must be a single segment); skipping"
        );
        return;
    }
    let (tx, rx) = ::tokio::sync::mpsc::channel::<zeroclaw_api::webhook::RawWebhook>(64);
    if registry.insert(path.clone(), tx) {
        channel.set_webhook_rx(rx);
        ::zeroclaw_log::record!(
            INFO,
            ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Note)
                .with_attrs(::serde_json::json!({ "plugin": plugin, "path": path })),
            "Registered plugin webhook route at /plugin/<path>"
        );
    } else {
        ::zeroclaw_log::record!(
            WARN,
            ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Note)
                .with_outcome(::zeroclaw_log::EventOutcome::Unknown)
                .with_attrs(::serde_json::json!({ "plugin": plugin, "path": path })),
            "Webhook path already claimed by another plugin; skipping"
        );
    }
}

/// Stub for builds without a WASM engine: channel plugins are unavailable, so no
/// channels are contributed. Keeps the orchestrator call site feature-agnostic.
#[cfg(not(feature = "plugins-wasm"))]
pub async fn build_channel_plugins(
    _config: &Config,
    _webhooks: Option<&PluginWebhookRegistry>,
) -> Vec<BuiltChannelPlugin> {
    Vec::new()
}

#[cfg(all(test, feature = "plugins-wasm"))]
mod tests {
    use super::apply_env_fallbacks;
    use serde_json::json;

    #[test]
    fn env_fills_only_blank_string_fields() {
        // SAFETY: unique keys owned by this test, restored before it returns.
        unsafe {
            std::env::set_var("ZEROCLAW_MIRRORTEST_BOT_TOKEN", "from-zeroclaw-env");
        }
        let cfg = json!({ "bot_token": "", "enabled": true, "kept": "config-val" });
        let out = apply_env_fallbacks(&cfg, "mirrortest");
        assert_eq!(
            out["bot_token"],
            json!("from-zeroclaw-env"),
            "blank string is filled from env"
        );
        assert_eq!(
            out["kept"],
            json!("config-val"),
            "non-blank field untouched"
        );
        assert_eq!(out["enabled"], json!(true), "non-string field untouched");
        unsafe {
            std::env::remove_var("ZEROCLAW_MIRRORTEST_BOT_TOKEN");
        }
    }

    #[test]
    fn plain_env_name_used_and_config_wins() {
        unsafe {
            std::env::set_var("MIRRORTWO_BOT_TOKEN", "from-plain-env");
        }
        // Blank → filled from the conventional `<ID>_<FIELD>` name.
        let blank = apply_env_fallbacks(&json!({ "bot_token": "" }), "mirrortwo");
        assert_eq!(blank["bot_token"], json!("from-plain-env"));
        // A non-blank config value always wins over env.
        let set = apply_env_fallbacks(&json!({ "bot_token": "config-token" }), "mirrortwo");
        assert_eq!(set["bot_token"], json!("config-token"));
        unsafe {
            std::env::remove_var("MIRRORTWO_BOT_TOKEN");
        }
    }
}
