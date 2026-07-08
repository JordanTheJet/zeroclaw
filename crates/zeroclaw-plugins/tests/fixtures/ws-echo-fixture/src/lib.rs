//! ZeroClaw WIT channel plugin fixture exercising the host `ws-client` import.
//!
//! On `configure` it reads a `ws://` URL from its config and dials it through the
//! host (`ws-connect`). On the first `poll-message` it sends a `"ping"` text
//! frame (`ws-send-text`); on each subsequent poll it drains `ws-receive`,
//! returning the echoed frame as its one inbound message once it arrives. Any
//! connect/send/receive error, or an unexpected close, is surfaced as the inbound
//! content instead so a failing round-trip is visible to the host test rather
//! than hanging. Proves the whole host WebSocket path — dial, duplex framing,
//! buffered receive — end-to-end against a local echo server. No filesystem, no
//! direct network (the host owns the socket).
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../../../../wit/v0",
        world: "channel-plugin",
        features: ["plugins-wit-v0", "plugins-wit-v0-websocket"],
    });

    use std::cell::{Cell, RefCell};

    use exports::zeroclaw::plugin::channel::{
        ApprovalRequest, ApprovalResponse, ChannelCapabilities, Guest as Channel, InboundMessage,
        SendMessage,
    };
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use zeroclaw::plugin::ws_client::{self, WsEvent};

    const PLUGIN_NAME: &str = "ws-echo-channel";
    const PLUGIN_VERSION: &str = "0.1.0";

    struct WsEcho;

    thread_local! {
        // 0 = not connected. Set once `configure` dials successfully.
        static HANDLE: Cell<u64> = const { Cell::new(0) };
        // Whether the outbound "ping" has been sent.
        static SENT: Cell<bool> = const { Cell::new(false) };
        // Whether a terminal inbound message has already been delivered.
        static DONE: Cell<bool> = const { Cell::new(false) };
        // Non-empty once a dial/config error must be surfaced.
        static CONNECT_ERR: RefCell<String> = const { RefCell::new(String::new()) };
    }

    /// Pull the `"url"` value out of the config JSON object without linking a
    /// JSON parser into the wasm fixture. The host passes a flat object such as
    /// `{"url":"ws://127.0.0.1:PORT"}`; URLs never contain a `"`, so scanning to
    /// the next quote is sufficient here.
    fn extract_url(config: &str) -> Option<String> {
        let after_key = &config[config.find("\"url\"")? + 5..];
        let after_colon = &after_key[after_key.find(':')? + 1..];
        let start = after_colon.find('"')? + 1;
        let end = after_colon[start..].find('"')? + start;
        Some(after_colon[start..end].to_string())
    }

    fn inbound(content: String) -> InboundMessage {
        InboundMessage {
            id: "ws-echo-1".to_string(),
            sender: "ws".to_string(),
            reply_target: "ws".to_string(),
            content,
            channel: PLUGIN_NAME.to_string(),
            channel_alias: None,
            timestamp: 0,
            thread_ts: None,
            interruption_scope_id: None,
            attachments: Vec::new(),
            subject: None,
        }
    }

    impl PluginInfo for WsEcho {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }
        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Channel for WsEcho {
        fn name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn configure(config: String) -> Result<(), String> {
            match extract_url(&config) {
                Some(url) => match ws_client::ws_connect(&url, &[]) {
                    Ok(handle) => HANDLE.with(|h| h.set(handle)),
                    Err(e) => CONNECT_ERR.with(|c| *c.borrow_mut() = format!("connect: {e}")),
                },
                None => CONNECT_ERR.with(|c| *c.borrow_mut() = "no url in config".to_string()),
            }
            Ok(())
        }

        fn send(_message: SendMessage) -> Result<(), String> {
            Ok(())
        }

        fn poll_message() -> Option<InboundMessage> {
            if DONE.with(Cell::get) {
                return None;
            }
            let err = CONNECT_ERR.with(|c| c.borrow().clone());
            if !err.is_empty() {
                DONE.with(|d| d.set(true));
                return Some(inbound(err));
            }
            let handle = HANDLE.with(Cell::get);
            if handle == 0 {
                return None;
            }
            if !SENT.with(Cell::get) {
                SENT.with(|s| s.set(true));
                if let Err(e) = ws_client::ws_send_text(handle, "ping") {
                    DONE.with(|d| d.set(true));
                    return Some(inbound(format!("send-error: {e}")));
                }
            }
            match ws_client::ws_receive(handle) {
                Ok(WsEvent::Text(t)) => {
                    DONE.with(|d| d.set(true));
                    Some(inbound(t))
                }
                // Nothing yet — let the host back off and poll again.
                Ok(WsEvent::Idle) => None,
                Ok(WsEvent::Closed(r)) => {
                    DONE.with(|d| d.set(true));
                    Some(inbound(format!("closed: {r}")))
                }
                Err(e) => {
                    DONE.with(|d| d.set(true));
                    Some(inbound(format!("recv-error: {e}")))
                }
            }
        }

        fn get_channel_capabilities() -> ChannelCapabilities {
            ChannelCapabilities::HEALTH_CHECK
        }

        fn health_check() -> bool {
            true
        }

        fn self_handle() -> Option<String> {
            None
        }

        fn self_addressed_mention() -> Option<String> {
            None
        }

        fn drop_self_message(_msg: InboundMessage) -> bool {
            false
        }

        fn start_typing(_recipient: String) -> Result<(), String> {
            Ok(())
        }

        fn stop_typing(_recipient: String) -> Result<(), String> {
            Ok(())
        }

        fn supports_draft_updates() -> bool {
            false
        }

        fn send_draft(_message: SendMessage) -> Result<Option<String>, String> {
            Ok(None)
        }

        fn update_draft(_r: String, _m: String, _t: String) -> Result<(), String> {
            Ok(())
        }

        fn update_draft_progress(_r: String, _m: String, _t: String) -> Result<(), String> {
            Ok(())
        }

        fn finalize_draft(_r: String, _m: String, _t: String) -> Result<(), String> {
            Ok(())
        }

        fn cancel_draft(_r: String, _m: String) -> Result<(), String> {
            Ok(())
        }

        fn supports_multi_message_streaming() -> bool {
            false
        }

        fn multi_message_delay_ms() -> u64 {
            800
        }

        fn add_reaction(_c: String, _m: String, _e: String) -> Result<(), String> {
            Ok(())
        }

        fn remove_reaction(_c: String, _m: String, _e: String) -> Result<(), String> {
            Ok(())
        }

        fn pin_message(_c: String, _m: String) -> Result<(), String> {
            Ok(())
        }

        fn unpin_message(_c: String, _m: String) -> Result<(), String> {
            Ok(())
        }

        fn redact_message(_c: String, _m: String, _reason: Option<String>) -> Result<(), String> {
            Ok(())
        }

        fn request_approval(
            _recipient: String,
            _request: ApprovalRequest,
        ) -> Result<Option<ApprovalResponse>, String> {
            Ok(None)
        }

        fn request_choice(
            _question: String,
            _choices: Vec<String>,
            _timeout_secs: u64,
        ) -> Result<Option<String>, String> {
            Ok(None)
        }

        fn supports_free_form_ask() -> bool {
            true
        }

        fn webhook_path() -> Option<String> {
            None
        }

        fn parse_webhook(
            _headers: Vec<(String, String)>,
            _body: Vec<u8>,
        ) -> Result<Vec<InboundMessage>, String> {
            Err("unsupported".to_string())
        }
    }

    export!(WsEcho);
}
