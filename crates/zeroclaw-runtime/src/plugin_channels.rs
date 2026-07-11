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

use parking_lot::RwLock;
use zeroclaw_api::channel::Channel;
use zeroclaw_api::webhook::PluginWebhookRegistry;
use zeroclaw_config::schema::Config;
#[cfg(feature = "plugins-wasm")]
use zeroclaw_plugins::wasm_channel::SenderAuthorizer;

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
    config_arc: &Arc<RwLock<Config>>,
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
                    // Same default-deny sender allowlist the native channel of
                    // this id enforces, resolved live from `peer_groups`.
                    let authorizer = channel_authorizer(config_arc, id, alias.as_str());
                    note_if_no_allowlist(config, id, alias.as_str(), &manifest.name);
                    match zeroclaw_plugins::wasm_channel::WasmChannel::from_wasm_mirror(
                        id,
                        alias.as_str(),
                        wasm_path,
                        &manifest.permissions,
                        &config_json,
                        limits,
                        authorizer,
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
                // A novel channel has no native counterpart; it still gets a
                // default-deny gate keyed on `peer_groups.<name>`, so an
                // operator opens it by allowlisting senders (or `["*"]`), never
                // fail-open. Exact-id match (no domain-class channel is novel).
                let authorizer = channel_authorizer(config_arc, &manifest.name, "");
                note_if_no_allowlist(config, &manifest.name, "", &manifest.name);
                match zeroclaw_plugins::wasm_channel::WasmChannel::from_wasm(
                    manifest.name.clone(),
                    wasm_path,
                    &manifest.permissions,
                    &plugin_config,
                    limits,
                    authorizer,
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

/// Which allowlist matcher a channel type authorizes senders with — a faithful
/// mirror of the per-channel choice each native channel hard-codes. Keep this in
/// sync with the native `is_user_allowed*` call sites in `zeroclaw-channels`.
#[cfg(feature = "plugins-wasm")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum SenderMatch {
    /// Case-sensitive exact id — the common case (platform user ids, and the
    /// E.164 phone a phone channel plugin normalizes the same way native does).
    Exact,
    /// Case-insensitive exact — `git` usernames, `irc` nicks, `imessage`,
    /// `matrix` MXIDs (all case-insensitive in their native channel).
    CaseInsensitive,
    /// `telegram`: mirror `normalize_identity` — trim + strip a leading `@` on
    /// both the sender and each peer, then case-sensitive exact. NOTE: native
    /// telegram also accepts EITHER a user's @username OR numeric id; a single
    /// `sender` field can carry only one, so the telegram plugin must emit a
    /// consistent identity and operators must allowlist that same identity.
    Handle,
    /// Domain-class email (`@host` admits a whole domain) — `gmail_push`, `email`.
    Email,
}

/// The matcher a channel type authorizes with, mirroring native. Pure (no
/// config) so the taxonomy — the logic that must stay in lockstep with the
/// native channels — is unit-testable on its own.
#[cfg(feature = "plugins-wasm")]
fn matcher_for(channel_type: &str) -> SenderMatch {
    match channel_type {
        "gmail_push" | "email" => SenderMatch::Email,
        "telegram" => SenderMatch::Handle,
        "git" | "irc" | "imessage" | "matrix" => SenderMatch::CaseInsensitive,
        _ => SenderMatch::Exact,
    }
}

/// Apply a matcher to an already-resolved peer list — the pure decision the
/// live authorizer wraps. Default-deny (empty ⇒ none, `["*"]` ⇒ anyone) via the
/// shared `zeroclaw_config::allowlist` primitives every native channel uses.
#[cfg(feature = "plugins-wasm")]
fn sender_allowed(matcher: SenderMatch, peers: &[String], sender: &str) -> bool {
    use zeroclaw_config::allowlist::{self, Match};
    match matcher {
        SenderMatch::Email => allowlist::is_user_allowed_by(peers, sender, allowlist::email_match),
        SenderMatch::CaseInsensitive => {
            allowlist::is_user_allowed(peers, sender, Match::CaseInsensitive)
        }
        SenderMatch::Exact => allowlist::is_user_allowed(peers, sender, Match::Sensitive),
        SenderMatch::Handle => {
            // Mirror native telegram `normalize_identity` (telegram.rs): trim +
            // strip a leading `@` on both sides, drop entries that normalize to
            // empty, then a case-sensitive exact compare.
            let norm = |s: &str| s.trim().trim_start_matches('@').to_string();
            let normalized_peers: Vec<String> = peers
                .iter()
                .map(|p| norm(p))
                .filter(|p| !p.is_empty())
                .collect();
            allowlist::is_user_allowed(&normalized_peers, &norm(sender), Match::Sensitive)
        }
    }
}

/// Build the sender-authorization gate for a plugin channel: the **same**
/// default-deny allowlist a native channel of this `channel_type` applies,
/// resolved live from `peer_groups` (via `channel_external_peers`) on every
/// inbound message, so a channel plugin authenticates senders identically to
/// its built-in counterpart. An empty allowlist admits no one (`["*"]` admits
/// everyone) — the exact stance the native channel takes.
#[cfg(feature = "plugins-wasm")]
fn channel_authorizer(
    config_arc: &Arc<RwLock<Config>>,
    channel_type: &str,
    alias: &str,
) -> SenderAuthorizer {
    let cfg = Arc::clone(config_arc);
    let channel_type = channel_type.to_string();
    let alias = alias.to_string();
    let matcher = matcher_for(&channel_type);
    Arc::new(move |sender: &str| {
        let peers = cfg.read().channel_external_peers(&channel_type, &alias);
        sender_allowed(matcher, &peers, sender)
    })
}

/// A channel plugin with an empty sender allowlist accepts no inbound (default
/// deny — the same stance the native channel takes). That is silent per-message,
/// so surface it once at startup: it is the usual reason a freshly-installed
/// plugin channel "does nothing", and the fix is a `[peer_groups]` entry (or
/// `"*"`). Purely informational — the authorization decision is unchanged.
#[cfg(feature = "plugins-wasm")]
fn note_if_no_allowlist(config: &Config, channel_type: &str, alias: &str, plugin: &str) {
    if config
        .channel_external_peers(channel_type, alias)
        .is_empty()
    {
        ::zeroclaw_log::record!(
            INFO,
            ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Note).with_attrs(
                ::serde_json::json!({ "plugin": plugin, "channel": channel_type, "alias": alias })
            ),
            "Channel plugin has an empty sender allowlist; it will accept no inbound until \
             a peer group authorizes senders for it (or \"*\" for anyone)"
        );
    }
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
    _config_arc: &Arc<RwLock<Config>>,
    _webhooks: Option<&PluginWebhookRegistry>,
) -> Vec<BuiltChannelPlugin> {
    Vec::new()
}

#[cfg(all(test, feature = "plugins-wasm"))]
mod tests {
    use super::{SenderMatch, apply_env_fallbacks, matcher_for, sender_allowed};
    use serde_json::json;

    fn v(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn matcher_for_mirrors_native_per_channel_choice() {
        // Keep in lockstep with the native is_user_allowed* call sites.
        assert_eq!(matcher_for("gmail_push"), SenderMatch::Email);
        assert_eq!(matcher_for("email"), SenderMatch::Email);
        assert_eq!(matcher_for("telegram"), SenderMatch::Handle);
        for ci in ["git", "irc", "imessage", "matrix"] {
            assert_eq!(matcher_for(ci), SenderMatch::CaseInsensitive, "{ci}");
        }
        for exact in [
            "slack",
            "discord",
            "wati",
            "linq",
            "whatsapp",
            "a-novel-plugin",
        ] {
            assert_eq!(matcher_for(exact), SenderMatch::Exact, "{exact}");
        }
    }

    #[test]
    fn every_matcher_is_default_deny_and_wildcard_open() {
        for m in [
            SenderMatch::Exact,
            SenderMatch::CaseInsensitive,
            SenderMatch::Handle,
            SenderMatch::Email,
        ] {
            assert!(!sender_allowed(m, &[], "anyone"), "empty ⇒ deny ({m:?})");
            assert!(
                sender_allowed(m, &v(&["*"]), "anyone"),
                "wildcard ⇒ allow ({m:?})"
            );
        }
    }

    #[test]
    fn exact_is_case_sensitive() {
        assert!(sender_allowed(SenderMatch::Exact, &v(&["alice"]), "alice"));
        assert!(!sender_allowed(SenderMatch::Exact, &v(&["alice"]), "Alice"));
    }

    #[test]
    fn case_insensitive_matches_matrix_mxid_casing() {
        // Native matrix authorizes case-insensitively; @Bot:Example.org must
        // match @bot:example.org.
        assert!(sender_allowed(
            SenderMatch::CaseInsensitive,
            &v(&["@Bot:Example.org"]),
            "@bot:example.org"
        ));
    }

    #[test]
    fn handle_strips_at_and_trims_both_sides() {
        // Mirror native telegram normalize_identity: "@alice" and "alice" are the
        // same identity, from either the peer or the sender side.
        assert!(sender_allowed(
            SenderMatch::Handle,
            &v(&["@alice"]),
            "alice"
        ));
        assert!(sender_allowed(
            SenderMatch::Handle,
            &v(&["alice"]),
            "@alice"
        ));
        assert!(sender_allowed(
            SenderMatch::Handle,
            &v(&[" @alice "]),
            "alice"
        ));
        assert!(!sender_allowed(SenderMatch::Handle, &v(&["@alice"]), "bob"));
        // A peer entry that normalizes to empty (bare "@") never admits anyone.
        assert!(!sender_allowed(SenderMatch::Handle, &v(&["@"]), ""));
    }

    #[test]
    fn email_matches_domain_class() {
        assert!(sender_allowed(
            SenderMatch::Email,
            &v(&["@example.com"]),
            "anyone@example.com"
        ));
        assert!(!sender_allowed(
            SenderMatch::Email,
            &v(&["@example.com"]),
            "stranger@evil.com"
        ));
    }

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
