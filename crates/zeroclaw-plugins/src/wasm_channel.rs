//! Channel adapter: `WasmChannel` implements `zeroclaw_api::channel::Channel`
//! backed by the `channel-plugin` component world.
//!
//! Warm lifecycle: the store and bindings are created once and held in an async
//! mutex. `listen` runs a poll-to-push bridge with exponential backoff.

use crate::PluginPermission;
use crate::component::InboundQueue;
use crate::component::bindings::channel::ChannelPlugin;
use crate::component::bindings::channel::exports::zeroclaw::plugin::channel::{
    ApprovalRequest as WitApprovalRequest, ApprovalResponse as WitApprovalResponse,
    ChannelCapabilities, InboundMessage as WitInboundMessage,
    MediaAttachment as WitMediaAttachment, SendMessage as WitSendMessage,
};
use crate::component::{PluginState, call_plugin, engine, load_component, wt};
use anyhow::Result;
use async_trait::async_trait;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::sync::mpsc;
use wasmtime::Store;
use wasmtime::component::Linker;
use zeroclaw_api::attribution::{Attributable, ChannelKind, Role};
use zeroclaw_api::channel::{
    Channel, ChannelApprovalRequest, ChannelApprovalResponse, ChannelMessage, SendMessage,
};
use zeroclaw_api::media::MediaAttachment;
use zeroclaw_api::webhook::{RawWebhook, WebhookReject};

/// A channel backed by a WIT component-model plugin.
pub struct WasmChannel {
    /// Platform id for routing, session keys, and native-wins dedup — the
    /// plugin's manifest name for a novel plugin, or the built-in channel id it
    /// `provides` for a mirror.
    name: String,
    /// Host-owned config alias stamped onto inbound messages so routing and
    /// session keys never trust the plugin. `None` for novel plugins.
    stamped_alias: Option<String>,
    capabilities: ChannelCapabilities,
    state: Arc<Mutex<(Store<PluginState>, ChannelPlugin)>>,
    inbound: InboundQueue,
    cached_self_handle: Option<String>,
    cached_self_addressed_mention: Option<String>,
    cached_multi_message_delay_ms: u64,
    poll_healthy: Arc<AtomicBool>,
    /// Sink-drain end for host-fed webhooks (set by the orchestrator when this
    /// channel declares a `webhook-path`). Taken once by `listen`.
    webhook_rx: std::sync::Mutex<Option<mpsc::Receiver<RawWebhook>>>,
}

/// Whether the listen loop's last `poll-message` did not trap. A channel whose
/// poll bridge is trapping is reported unhealthy even when the plugin exposes no
/// `health-check` export, so a broken plugin cannot masquerade as idle forever.
fn poll_health_ok(flag: &AtomicBool) -> bool {
    flag.load(Ordering::Relaxed)
}

fn mark_poll_healthy(flag: &AtomicBool, healthy: bool) {
    flag.store(healthy, Ordering::Relaxed);
}

impl Attributable for WasmChannel {
    fn role(&self) -> Role {
        Role::Channel(ChannelKind::Plugin)
    }
    fn alias(&self) -> &str {
        self.stamped_alias.as_deref().unwrap_or(&self.name)
    }
}

/// Resolve the JSON config section handed to a channel plugin's `configure`.
/// Withheld (an empty object) unless the manifest grants `ConfigRead`, so a
/// plugin without the permission can never be configured with another channel's
/// secrets. Mirrors the tool-plugin `__config` rule.
fn resolve_configure_json(
    config: &HashMap<String, String>,
    permissions: &[PluginPermission],
) -> String {
    if permissions.contains(&PluginPermission::ConfigRead) {
        serde_json::to_string(config).unwrap_or_else(|_| "{}".to_string())
    } else {
        "{}".to_string()
    }
}

fn build_linker(http: bool, websocket: bool) -> Result<Linker<PluginState>> {
    let mut linker = Linker::new(engine());
    crate::component::add_wasi(&mut linker)?;
    if http {
        crate::component::add_wasi_http(&mut linker)?;
    }
    let mut options = crate::component::bindings::channel::LinkOptions::default();
    options.plugins_wit_v0(true);
    // Per-permission gate: the `ws-client` import is installed only for plugins
    // granted `WebSocketClient`, mirroring the `wasi:http` gate above.
    options.plugins_wit_v0_websocket(websocket);
    wt(
        ChannelPlugin::add_to_linker::<_, wasmtime::component::HasSelf<_>>(
            &mut linker,
            &options,
            |s| s,
        ),
        "failed to add channel plugin imports to linker",
    )?;
    Ok(linker)
}

impl WasmChannel {
    /// Compile + instantiate a channel plugin and cache its capabilities and the
    /// static-identity exports the sync trait methods return. `name` is the
    /// platform id used for routing, session keys, and native-wins dedup;
    /// `stamped_alias` is the host-owned config alias stamped onto inbound
    /// messages (`None` for novel plugins). `config_json` is the already
    /// `ConfigRead`-resolved JSON object handed to the plugin's `configure` once,
    /// before any other call. The permission set decides whether the store and
    /// linker expose outbound `wasi:http`; without `HttpClient` the channel
    /// cannot reach the network. The returned channel owns an [`InboundQueue`];
    /// a host-run listener obtains its handle via [`WasmChannel::inbound`].
    /// `limits` bounds the per-call fuel and the memory/table/instance ceilings.
    async fn instantiate(
        name: String,
        stamped_alias: Option<String>,
        wasm_path: &Path,
        permissions: &[PluginPermission],
        config_json: String,
        limits: crate::component::PluginLimits,
    ) -> Result<Self> {
        let component = load_component(wasm_path)?;
        let inbound = InboundQueue::default();
        let mut store =
            crate::component::new_store_with_inbound(permissions, inbound.clone(), limits);
        let http = store.data().http_enabled();
        let websocket = store.data().websocket_enabled();
        let linker = build_linker(http, websocket)?;
        crate::component::ensure_http_coherent(&store, http)?;
        crate::component::ensure_ws_coherent(&store, websocket)?;
        let bindings = wt(
            ChannelPlugin::instantiate_async(&mut store, &component, &linker).await,
            "failed to instantiate channel plugin",
        )?;

        let channel = bindings.zeroclaw_plugin_channel();

        wt(
            channel.call_configure(&mut store, &config_json).await,
            "channel.configure trapped",
        )?
        .map_err(anyhow::Error::msg)?;

        let capabilities = wt(
            channel.call_get_channel_capabilities(&mut store).await,
            "channel.get-channel-capabilities failed",
        )?;

        let cached_self_handle = if capabilities.contains(ChannelCapabilities::SELF_HANDLE) {
            wt(
                channel.call_self_handle(&mut store).await,
                "channel.self-handle failed",
            )?
        } else {
            None
        };
        let cached_self_addressed_mention =
            if capabilities.contains(ChannelCapabilities::SELF_ADDRESSED_MENTION) {
                wt(
                    channel.call_self_addressed_mention(&mut store).await,
                    "channel.self-addressed-mention failed",
                )?
            } else {
                None
            };
        let cached_multi_message_delay_ms =
            if capabilities.contains(ChannelCapabilities::MULTI_MESSAGE_DELAY_MS) {
                wt(
                    channel.call_multi_message_delay_ms(&mut store).await,
                    "channel.multi-message-delay-ms failed",
                )?
            } else {
                800
            };

        Ok(Self {
            name,
            stamped_alias,
            capabilities,
            state: Arc::new(Mutex::new((store, bindings))),
            inbound,
            cached_self_handle,
            cached_self_addressed_mention,
            cached_multi_message_delay_ms,
            poll_healthy: Arc::new(AtomicBool::new(true)),
            webhook_rx: std::sync::Mutex::new(None),
        })
    }

    /// Whether this plugin advertises `webhook-ingress` (serves inbound via a
    /// host webhook route rather than self-polling).
    pub fn has_webhook_ingress(&self) -> bool {
        self.capabilities
            .contains(ChannelCapabilities::WEBHOOK_INGRESS)
    }

    /// The URL path segment this channel serves webhooks on, or `None` for a
    /// poll-only channel. Calls the plugin's `webhook-path` export (only when it
    /// advertised the capability).
    pub async fn webhook_path(&self) -> Option<String> {
        if !self.has_webhook_ingress() {
            return None;
        }
        let result: Result<Option<String>> = call_plugin!(
            self,
            async move |store: &mut Store<PluginState>, bindings: &mut ChannelPlugin| {
                wt(
                    bindings
                        .zeroclaw_plugin_channel()
                        .call_webhook_path(store)
                        .await,
                    "channel.webhook-path failed",
                )
            }
        );
        result.ok().flatten()
    }

    /// Hand this channel the drain end of its webhook sink, before it is boxed
    /// into an `Arc<dyn Channel>`; `listen` takes it once.
    pub fn set_webhook_rx(&self, rx: mpsc::Receiver<RawWebhook>) {
        *self.webhook_rx.lock().expect("webhook_rx poisoned") = Some(rx);
    }

    /// Instantiate a **novel** channel plugin: identity is the plugin's own
    /// `name`, config comes from its `[[plugins.entries]]` map (withheld unless
    /// `ConfigRead` is granted — matching the tool-plugin `__config` rule), and
    /// inbound messages carry no host-stamped alias.
    pub async fn from_wasm(
        name: impl Into<String>,
        wasm_path: &Path,
        permissions: &[PluginPermission],
        config: &HashMap<String, String>,
        limits: crate::component::PluginLimits,
    ) -> Result<Self> {
        let config_json = resolve_configure_json(config, permissions);
        Self::instantiate(
            name.into(),
            None,
            wasm_path,
            permissions,
            config_json,
            limits,
        )
        .await
    }

    /// Instantiate a **mirror** channel plugin — one that `provides` a compiled
    /// channel id. Identity is the built-in `name` (routing/dedup key), `alias`
    /// is the host-owned config alias stamped onto inbound messages, and
    /// `config_json` is the plaintext canonical `[channels.<name>.<alias>]`
    /// section serialized as a JSON object (preserving typed fields the flat
    /// string-map path would lose). Config is withheld (`"{}"`) unless
    /// `ConfigRead` is granted, exactly as `from_wasm`.
    pub async fn from_wasm_mirror(
        name: impl Into<String>,
        alias: impl Into<String>,
        wasm_path: &Path,
        permissions: &[PluginPermission],
        config_json: &str,
        limits: crate::component::PluginLimits,
    ) -> Result<Self> {
        let config_json = if permissions.contains(&PluginPermission::ConfigRead) {
            config_json.to_string()
        } else {
            "{}".to_string()
        };
        Self::instantiate(
            name.into(),
            Some(alias.into()),
            wasm_path,
            permissions,
            config_json,
            limits,
        )
        .await
    }

    /// Handle to this channel's inbound queue. A host-run listener clones it and
    /// calls [`InboundQueue::enqueue`] for each received message; the plugin
    /// drains them through its imported `inbound` interface.
    pub fn inbound(&self) -> InboundQueue {
        self.inbound.clone()
    }
}

fn to_wit_media(a: &MediaAttachment) -> WitMediaAttachment {
    WitMediaAttachment {
        file_name: a.file_name.clone(),
        data: a.data.clone(),
        mime_type: a.mime_type.clone(),
    }
}

fn from_wit_media(a: WitMediaAttachment) -> MediaAttachment {
    MediaAttachment {
        file_name: a.file_name,
        data: a.data,
        mime_type: a.mime_type,
    }
}

fn to_wit_send(msg: &SendMessage) -> WitSendMessage {
    WitSendMessage {
        content: msg.content.clone(),
        recipient: msg.recipient.clone(),
        subject: msg.subject.clone(),
        thread_ts: msg.thread_ts.clone(),
        attachments: msg.attachments.iter().map(to_wit_media).collect(),
        in_reply_to: msg.in_reply_to.clone(),
    }
}

fn from_wit_inbound(
    msg: WitInboundMessage,
    channel_name: &str,
    stamped_alias: Option<&str>,
) -> ChannelMessage {
    ChannelMessage {
        id: msg.id,
        sender: msg.sender,
        reply_target: msg.reply_target,
        content: msg.content,
        channel: channel_name.to_string(),
        // Host-stamped alias wins over any value the plugin supplied, so routing
        // and session keys never depend on plugin cooperation.
        channel_alias: stamped_alias.map(str::to_string).or(msg.channel_alias),
        timestamp: msg.timestamp,
        thread_ts: msg.thread_ts,
        interruption_scope_id: msg.interruption_scope_id,
        attachments: msg.attachments.into_iter().map(from_wit_media).collect(),
        subject: msg.subject,
        ..Default::default()
    }
}

fn to_wit_approval_request(req: &ChannelApprovalRequest) -> WitApprovalRequest {
    WitApprovalRequest {
        tool_name: req.tool_name.clone(),
        arguments_summary: req.arguments_summary.clone(),
        raw_arguments: req.raw_arguments.as_ref().map(|v| v.to_string()),
    }
}

fn from_wit_approval_response(r: WitApprovalResponse) -> ChannelApprovalResponse {
    match r {
        WitApprovalResponse::Approve => ChannelApprovalResponse::Approve,
        WitApprovalResponse::Deny => ChannelApprovalResponse::Deny,
        WitApprovalResponse::AlwaysApprove => ChannelApprovalResponse::AlwaysApprove,
        WitApprovalResponse::DenyWithEdit(s) => {
            ChannelApprovalResponse::DenyWithEdit { replacement: s }
        }
    }
}

#[async_trait]
impl Channel for WasmChannel {
    fn name(&self) -> &str {
        &self.name
    }

    async fn send(&self, message: &SendMessage) -> Result<()> {
        let wit_msg = to_wit_send(message);
        call_plugin!(
            self,
            async move |store: &mut Store<PluginState>, bindings: &mut ChannelPlugin| {
                wt(
                    bindings
                        .zeroclaw_plugin_channel()
                        .call_send(store, &wit_msg)
                        .await,
                    "channel.send trapped",
                )?
                .map_err(anyhow::Error::msg)
            }
        )
    }

    async fn listen(&self, tx: tokio::sync::mpsc::Sender<ChannelMessage>) -> Result<()> {
        let channel_name = self.name.clone();
        let stamped_alias = self.stamped_alias.clone();
        let state = Arc::clone(&self.state);
        let poll_healthy = Arc::clone(&self.poll_healthy);

        // Webhook ingress: if the gateway feeds this channel raw webhooks via a
        // registered sink, drain them on a second task. Each is decoded by the
        // plugin's `parse-webhook` export (which also verifies authenticity) and
        // forwarded on `tx` — the exact path native inbound takes. The two tasks
        // share the store mutex, so there is no store aliasing.
        if let Some(mut webhook_rx) = self.webhook_rx.lock().expect("webhook_rx poisoned").take() {
            let wh_state = Arc::clone(&self.state);
            let wh_name = self.name.clone();
            let wh_alias = self.stamped_alias.clone();
            let wh_tx = tx.clone();
            zeroclaw_spawn::spawn!(async move {
                while let Some(RawWebhook {
                    headers,
                    body,
                    reply,
                }) = webhook_rx.recv().await
                {
                    let decoded = {
                        let mut guard = wh_state.lock().await;
                        let (ref mut store, ref mut bindings) = *guard;
                        crate::component::refuel(store);
                        bindings
                            .zeroclaw_plugin_channel()
                            .call_parse_webhook(store, &headers, &body)
                            .await
                    };
                    match decoded {
                        Ok(Ok(msgs)) => {
                            for m in msgs {
                                let _ = wh_tx
                                    .send(from_wit_inbound(m, &wh_name, wh_alias.as_deref()))
                                    .await;
                            }
                            let _ = reply.send(Ok(()));
                        }
                        // Plugin rejected the webhook (bad signature / payload).
                        Ok(Err(reason)) => {
                            let _ = reply.send(Err(WebhookReject::Unauthorized(reason)));
                        }
                        // The plugin trapped decoding the webhook.
                        Err(e) => {
                            let _ = reply.send(Err(WebhookReject::BadRequest(format!("{e:#}"))));
                        }
                    }
                }
            });
        }

        zeroclaw_spawn::spawn!(async move {
            const INITIAL_BACKOFF: Duration = Duration::from_millis(50);
            const MAX_BACKOFF: Duration = Duration::from_millis(500);
            let mut backoff = INITIAL_BACKOFF;
            loop {
                let polled = {
                    let mut guard = state.lock().await;
                    let (ref mut store, ref mut bindings) = *guard;
                    crate::component::refuel(store);
                    bindings
                        .zeroclaw_plugin_channel()
                        .call_poll_message(store)
                        .await
                };
                match polled {
                    Ok(Some(wit_msg)) => {
                        mark_poll_healthy(&poll_healthy, true);
                        backoff = INITIAL_BACKOFF;
                        if tx
                            .send(from_wit_inbound(
                                wit_msg,
                                &channel_name,
                                stamped_alias.as_deref(),
                            ))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    Ok(None) => {
                        mark_poll_healthy(&poll_healthy, true);
                        tokio::time::sleep(backoff).await;
                        backoff = (backoff * 2).min(MAX_BACKOFF);
                    }
                    Err(e) => {
                        mark_poll_healthy(&poll_healthy, false);
                        ::zeroclaw_log::record!(
                            WARN,
                            ::zeroclaw_log::Event::new(
                                module_path!(),
                                ::zeroclaw_log::Action::Inbound
                            )
                            .with_outcome(::zeroclaw_log::EventOutcome::Failure)
                            .with_attrs(::serde_json::json!({
                                "channel_alias": channel_name,
                                "error": format!("{e:#}"),
                            })),
                            "channel plugin poll-message trapped; backing off"
                        );
                        tokio::time::sleep(backoff).await;
                        backoff = (backoff * 2).min(MAX_BACKOFF);
                    }
                }
            }
        });
        Ok(())
    }

    async fn health_check(&self) -> bool {
        if !poll_health_ok(&self.poll_healthy) {
            return false;
        }
        if !self
            .capabilities
            .contains(ChannelCapabilities::HEALTH_CHECK)
        {
            return true;
        }
        let result: Result<bool> = call_plugin!(
            self,
            async move |store: &mut Store<PluginState>, bindings: &mut ChannelPlugin| {
                wt(
                    bindings
                        .zeroclaw_plugin_channel()
                        .call_health_check(store)
                        .await,
                    "channel.health-check failed",
                )
            }
        );
        result.unwrap_or(false)
    }

    fn self_handle(&self) -> Option<String> {
        self.cached_self_handle.clone()
    }

    fn self_addressed_mention(&self) -> Option<String> {
        self.cached_self_addressed_mention.clone()
    }

    fn drop_self_messages(&self, msg: &ChannelMessage) -> bool {
        let Some(handle) = self.self_handle() else {
            return false;
        };
        let handle_norm = handle.trim_start_matches('@').to_ascii_lowercase();
        let sender_norm = msg.sender.trim_start_matches('@').to_ascii_lowercase();
        !handle_norm.is_empty() && handle_norm == sender_norm
    }

    async fn start_typing(&self, recipient: &str) -> Result<()> {
        if !self
            .capabilities
            .contains(ChannelCapabilities::START_TYPING)
        {
            return Ok(());
        }
        let recipient = recipient.to_string();
        call_plugin!(
            self,
            async move |store: &mut Store<PluginState>, bindings: &mut ChannelPlugin| {
                wt(
                    bindings
                        .zeroclaw_plugin_channel()
                        .call_start_typing(store, &recipient)
                        .await,
                    "channel.start-typing trapped",
                )?
                .map_err(anyhow::Error::msg)
            }
        )
    }

    async fn stop_typing(&self, recipient: &str) -> Result<()> {
        if !self.capabilities.contains(ChannelCapabilities::STOP_TYPING) {
            return Ok(());
        }
        let recipient = recipient.to_string();
        call_plugin!(
            self,
            async move |store: &mut Store<PluginState>, bindings: &mut ChannelPlugin| {
                wt(
                    bindings
                        .zeroclaw_plugin_channel()
                        .call_stop_typing(store, &recipient)
                        .await,
                    "channel.stop-typing trapped",
                )?
                .map_err(anyhow::Error::msg)
            }
        )
    }

    fn supports_draft_updates(&self) -> bool {
        self.capabilities
            .contains(ChannelCapabilities::SUPPORTS_DRAFT_UPDATES)
    }

    async fn send_draft(&self, message: &SendMessage) -> Result<Option<String>> {
        if !self.capabilities.contains(ChannelCapabilities::SEND_DRAFT) {
            return Ok(None);
        }
        let wit_msg = to_wit_send(message);
        call_plugin!(
            self,
            async move |store: &mut Store<PluginState>, bindings: &mut ChannelPlugin| {
                wt(
                    bindings
                        .zeroclaw_plugin_channel()
                        .call_send_draft(store, &wit_msg)
                        .await,
                    "channel.send-draft trapped",
                )?
                .map_err(anyhow::Error::msg)
            }
        )
    }

    async fn update_draft(&self, recipient: &str, message_id: &str, text: &str) -> Result<()> {
        if !self
            .capabilities
            .contains(ChannelCapabilities::UPDATE_DRAFT)
        {
            return Ok(());
        }
        let (recipient, message_id, text) = (
            recipient.to_string(),
            message_id.to_string(),
            text.to_string(),
        );
        call_plugin!(
            self,
            async move |store: &mut Store<PluginState>, bindings: &mut ChannelPlugin| {
                wt(
                    bindings
                        .zeroclaw_plugin_channel()
                        .call_update_draft(store, &recipient, &message_id, &text)
                        .await,
                    "channel.update-draft trapped",
                )?
                .map_err(anyhow::Error::msg)
            }
        )
    }

    async fn update_draft_progress(
        &self,
        recipient: &str,
        message_id: &str,
        text: &str,
    ) -> Result<()> {
        if !self
            .capabilities
            .contains(ChannelCapabilities::UPDATE_DRAFT_PROGRESS)
        {
            return Ok(());
        }
        let (recipient, message_id, text) = (
            recipient.to_string(),
            message_id.to_string(),
            text.to_string(),
        );
        call_plugin!(
            self,
            async move |store: &mut Store<PluginState>, bindings: &mut ChannelPlugin| {
                wt(
                    bindings
                        .zeroclaw_plugin_channel()
                        .call_update_draft_progress(store, &recipient, &message_id, &text)
                        .await,
                    "channel.update-draft-progress trapped",
                )?
                .map_err(anyhow::Error::msg)
            }
        )
    }

    async fn finalize_draft(
        &self,
        recipient: &str,
        message_id: &str,
        text: &str,
        _suppress_voice: bool,
    ) -> Result<()> {
        if !self
            .capabilities
            .contains(ChannelCapabilities::FINALIZE_DRAFT)
        {
            return Ok(());
        }
        let (recipient, message_id, text) = (
            recipient.to_string(),
            message_id.to_string(),
            text.to_string(),
        );
        call_plugin!(
            self,
            async move |store: &mut Store<PluginState>, bindings: &mut ChannelPlugin| {
                wt(
                    bindings
                        .zeroclaw_plugin_channel()
                        .call_finalize_draft(store, &recipient, &message_id, &text)
                        .await,
                    "channel.finalize-draft trapped",
                )?
                .map_err(anyhow::Error::msg)
            }
        )
    }

    async fn cancel_draft(&self, recipient: &str, message_id: &str) -> Result<()> {
        if !self
            .capabilities
            .contains(ChannelCapabilities::CANCEL_DRAFT)
        {
            return Ok(());
        }
        let (recipient, message_id) = (recipient.to_string(), message_id.to_string());
        call_plugin!(
            self,
            async move |store: &mut Store<PluginState>, bindings: &mut ChannelPlugin| {
                wt(
                    bindings
                        .zeroclaw_plugin_channel()
                        .call_cancel_draft(store, &recipient, &message_id)
                        .await,
                    "channel.cancel-draft trapped",
                )?
                .map_err(anyhow::Error::msg)
            }
        )
    }

    fn supports_multi_message_streaming(&self) -> bool {
        self.capabilities
            .contains(ChannelCapabilities::SUPPORTS_MULTI_MESSAGE_STREAMING)
    }

    fn multi_message_delay_ms(&self) -> u64 {
        self.cached_multi_message_delay_ms
    }

    async fn add_reaction(&self, channel_id: &str, message_id: &str, emoji: &str) -> Result<()> {
        if !self
            .capabilities
            .contains(ChannelCapabilities::ADD_REACTION)
        {
            return Ok(());
        }
        let (channel_id, message_id, emoji) = (
            channel_id.to_string(),
            message_id.to_string(),
            emoji.to_string(),
        );
        call_plugin!(
            self,
            async move |store: &mut Store<PluginState>, bindings: &mut ChannelPlugin| {
                wt(
                    bindings
                        .zeroclaw_plugin_channel()
                        .call_add_reaction(store, &channel_id, &message_id, &emoji)
                        .await,
                    "channel.add-reaction trapped",
                )?
                .map_err(anyhow::Error::msg)
            }
        )
    }

    async fn remove_reaction(&self, channel_id: &str, message_id: &str, emoji: &str) -> Result<()> {
        if !self
            .capabilities
            .contains(ChannelCapabilities::REMOVE_REACTION)
        {
            return Ok(());
        }
        let (channel_id, message_id, emoji) = (
            channel_id.to_string(),
            message_id.to_string(),
            emoji.to_string(),
        );
        call_plugin!(
            self,
            async move |store: &mut Store<PluginState>, bindings: &mut ChannelPlugin| {
                wt(
                    bindings
                        .zeroclaw_plugin_channel()
                        .call_remove_reaction(store, &channel_id, &message_id, &emoji)
                        .await,
                    "channel.remove-reaction trapped",
                )?
                .map_err(anyhow::Error::msg)
            }
        )
    }

    async fn pin_message(&self, channel_id: &str, message_id: &str) -> Result<()> {
        if !self.capabilities.contains(ChannelCapabilities::PIN_MESSAGE) {
            return Ok(());
        }
        let (channel_id, message_id) = (channel_id.to_string(), message_id.to_string());
        call_plugin!(
            self,
            async move |store: &mut Store<PluginState>, bindings: &mut ChannelPlugin| {
                wt(
                    bindings
                        .zeroclaw_plugin_channel()
                        .call_pin_message(store, &channel_id, &message_id)
                        .await,
                    "channel.pin-message trapped",
                )?
                .map_err(anyhow::Error::msg)
            }
        )
    }

    async fn unpin_message(&self, channel_id: &str, message_id: &str) -> Result<()> {
        if !self
            .capabilities
            .contains(ChannelCapabilities::UNPIN_MESSAGE)
        {
            return Ok(());
        }
        let (channel_id, message_id) = (channel_id.to_string(), message_id.to_string());
        call_plugin!(
            self,
            async move |store: &mut Store<PluginState>, bindings: &mut ChannelPlugin| {
                wt(
                    bindings
                        .zeroclaw_plugin_channel()
                        .call_unpin_message(store, &channel_id, &message_id)
                        .await,
                    "channel.unpin-message trapped",
                )?
                .map_err(anyhow::Error::msg)
            }
        )
    }

    async fn redact_message(
        &self,
        channel_id: &str,
        message_id: &str,
        reason: Option<String>,
    ) -> Result<()> {
        if !self
            .capabilities
            .contains(ChannelCapabilities::REDACT_MESSAGE)
        {
            return Ok(());
        }
        let (channel_id, message_id) = (channel_id.to_string(), message_id.to_string());
        call_plugin!(
            self,
            async move |store: &mut Store<PluginState>, bindings: &mut ChannelPlugin| {
                wt(
                    bindings
                        .zeroclaw_plugin_channel()
                        .call_redact_message(store, &channel_id, &message_id, reason.as_deref())
                        .await,
                    "channel.redact-message trapped",
                )?
                .map_err(anyhow::Error::msg)
            }
        )
    }

    async fn request_approval(
        &self,
        recipient: &str,
        request: &ChannelApprovalRequest,
    ) -> Result<Option<ChannelApprovalResponse>> {
        if !self
            .capabilities
            .contains(ChannelCapabilities::REQUEST_APPROVAL)
        {
            return Ok(None);
        }
        let recipient = recipient.to_string();
        let wit_req = to_wit_approval_request(request);
        call_plugin!(
            self,
            async move |store: &mut Store<PluginState>, bindings: &mut ChannelPlugin| {
                let out = wt(
                    bindings
                        .zeroclaw_plugin_channel()
                        .call_request_approval(store, &recipient, &wit_req)
                        .await,
                    "channel.request-approval trapped",
                )?
                .map_err(anyhow::Error::msg)?;
                Ok(out.map(from_wit_approval_response))
            }
        )
    }

    async fn request_choice(
        &self,
        question: &str,
        choices: &[String],
        timeout: Duration,
    ) -> Result<Option<String>> {
        if !self
            .capabilities
            .contains(ChannelCapabilities::REQUEST_CHOICE)
        {
            return Ok(None);
        }
        let question = question.to_string();
        let choices = choices.to_vec();
        let timeout_secs = timeout.as_secs();
        call_plugin!(
            self,
            async move |store: &mut Store<PluginState>, bindings: &mut ChannelPlugin| {
                wt(
                    bindings
                        .zeroclaw_plugin_channel()
                        .call_request_choice(store, &question, &choices, timeout_secs)
                        .await,
                    "channel.request-choice trapped",
                )?
                .map_err(anyhow::Error::msg)
            }
        )
    }

    fn supports_free_form_ask(&self) -> bool {
        self.capabilities
            .contains(ChannelCapabilities::SUPPORTS_FREE_FORM_ASK)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn media_round_trip() {
        let ma = MediaAttachment {
            file_name: "photo.jpg".into(),
            data: vec![0xFF, 0xD8, 0xFF],
            mime_type: Some("image/jpeg".into()),
        };
        let back = from_wit_media(to_wit_media(&ma));
        assert_eq!(back.file_name, "photo.jpg");
        assert_eq!(back.data, vec![0xFF_u8, 0xD8, 0xFF]);
        assert_eq!(back.mime_type.as_deref(), Some("image/jpeg"));
    }

    #[test]
    fn capabilities_bitfield() {
        let caps = ChannelCapabilities::HEALTH_CHECK | ChannelCapabilities::SEND_DRAFT;
        assert!(caps.contains(ChannelCapabilities::HEALTH_CHECK));
        assert!(!caps.contains(ChannelCapabilities::PIN_MESSAGE));
    }

    #[test]
    fn poll_trap_marks_channel_unhealthy() {
        let flag = AtomicBool::new(true);
        assert!(poll_health_ok(&flag), "starts healthy");

        // A trapping poll clears the flag; a broken plugin can no longer look
        // like a quiet, idle one.
        mark_poll_healthy(&flag, false);
        assert!(!poll_health_ok(&flag), "trap surfaces as unhealthy");

        // A subsequent successful poll clears the condition.
        mark_poll_healthy(&flag, true);
        assert!(poll_health_ok(&flag), "recovers after a clean poll");
    }

    #[test]
    fn configure_withholds_section_without_config_read() {
        let mut config = HashMap::new();
        config.insert("api_key".to_string(), "secret".to_string());
        let json = resolve_configure_json(&config, &[PluginPermission::HttpClient]);
        assert_eq!(json, "{}", "no ConfigRead means an empty config object");
    }

    #[test]
    fn configure_passes_section_with_config_read() {
        let mut config = HashMap::new();
        config.insert("identity".to_string(), "on-call".to_string());
        let json = resolve_configure_json(&config, &[PluginPermission::ConfigRead]);
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["identity"], "on-call", "granted section round-trips");
    }

    #[test]
    fn host_enqueued_inbound_reaches_the_drain_handle() {
        // The inbound contract is host-fed: a listener the orchestrator owns
        // (vendor tunnel, webhook) enqueues through the handle from
        // `WasmChannel::inbound()`, and the plugin drains the same queue. Prove
        // the producer side here so the transport is not just asserted at the
        // queue type but at the handle a host listener actually holds.
        let queue = crate::component::InboundQueue::default();
        let listener_handle = queue.clone();
        assert_eq!(queue.pending(), 0, "starts empty");

        listener_handle.enqueue(crate::component::HostInboundMessage {
            id: "evt-1".into(),
            sender: "+15550100".into(),
            reply_target: "+15550100".into(),
            content: "inbound sms".into(),
            channel: "inkbox".into(),
            channel_alias: Some("on-call".into()),
            timestamp: 0,
            thread_ts: None,
            interruption_scope_id: None,
            subject: None,
        });

        assert_eq!(
            queue.pending(),
            1,
            "host enqueue is visible on the drain side"
        );
        let drained = queue
            .poll()
            .expect("the plugin-side drain sees the message");
        assert_eq!(drained.id, "evt-1");
        assert_eq!(drained.content, "inbound sms");
        assert_eq!(queue.pending(), 0, "draining empties the shared queue");
    }

    #[test]
    fn from_wit_inbound_host_stamps_alias_over_plugin() {
        let make = || WitInboundMessage {
            id: "1".into(),
            sender: "u".into(),
            reply_target: "u".into(),
            content: "hi".into(),
            channel: "plugin-ignored".into(),
            channel_alias: Some("plugin-supplied".into()),
            timestamp: 0,
            thread_ts: None,
            interruption_scope_id: None,
            attachments: Vec::new(),
            subject: None,
        };

        // A mirror stamps the host-owned alias, overriding whatever the plugin
        // put in `channel_alias`, so routing/session keys never trust the plugin.
        let stamped = from_wit_inbound(make(), "telegram", Some("main"));
        assert_eq!(stamped.channel, "telegram");
        assert_eq!(stamped.channel_alias.as_deref(), Some("main"));

        // A novel plugin carries no host stamp, so the plugin's own value passes
        // through unchanged.
        let novel = from_wit_inbound(make(), "echo-channel", None);
        assert_eq!(novel.channel, "echo-channel");
        assert_eq!(novel.channel_alias.as_deref(), Some("plugin-supplied"));
    }
}
