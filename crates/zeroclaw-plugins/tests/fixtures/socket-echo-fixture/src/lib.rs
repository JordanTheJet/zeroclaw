//! ZeroClaw WIT channel plugin fixture exercising the host `socket` import.
//!
//! On `configure` it reads a `host:port` string from its config and dials it
//! through the host (`tcp-connect`, plaintext). On the first `poll-message` it
//! sends a `"ping"` byte chunk (`tcp-send`); on each subsequent poll it drains
//! `tcp-receive`, returning the echoed bytes as its one inbound message once
//! they arrive. Any connect/send/receive error, or an unexpected close, is
//! surfaced as the inbound content instead so a failing round-trip is visible to
//! the host test rather than hanging. Proves the whole host raw-TCP path —
//! dial, duplex byte pumping, buffered receive — end-to-end against a local echo
//! server. No filesystem, no direct network (the host owns the socket).
//!
//! The host E2E tests build this source on demand with the checked-in lockfile.
//! Manual build: `cargo build --locked --target wasm32-wasip2`.

// Parse the same world with only the core feature. This catches feature
// annotations inside optional transport interfaces that would otherwise make
// unrelated channel components fail before code generation.
#[cfg(all(target_family = "wasm", feature = "core-wit-parse"))]
mod core_only_wit_parse {
    wit_bindgen::generate!({
        path: "../../../../../wit/v0",
        world: "channel-plugin",
        features: ["plugins-wit-v0"],
    });
}

#[cfg(all(target_family = "wasm", not(feature = "core-wit-parse")))]
mod component {
    wit_bindgen::generate!({
        path: "../../../../../wit/v0",
        world: "channel-plugin",
        features: ["plugins-wit-v0", "plugins-wit-v0-sockets"],
    });

    use std::cell::{Cell, RefCell};

    use exports::zeroclaw::plugin::channel::{
        ApprovalRequest, ApprovalResponse, ChannelCapabilities, Guest as Channel, InboundMessage,
        SendMessage,
    };
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use zeroclaw::plugin::socket::{self, SocketEvent};

    const PLUGIN_NAME: &str = "socket-echo-channel";
    const PLUGIN_VERSION: &str = "0.1.0";

    struct SocketEcho;

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
    /// `{"url":"127.0.0.1:PORT"}`; the value never contains a `"`, so scanning
    /// to the next quote is sufficient here.
    fn extract_url(config: &str) -> Option<String> {
        let after_key = &config[config.find("\"url\"")? + 5..];
        let after_colon = &after_key[after_key.find(':')? + 1..];
        let start = after_colon.find('"')? + 1;
        let end = after_colon[start..].find('"')? + start;
        Some(after_colon[start..end].to_string())
    }

    /// Split a `host:port` string on its LAST `:` (so a future IPv6-ish host
    /// with embedded colons keeps its port) and parse the port.
    fn split_host_port(url: &str) -> Option<(String, u16)> {
        let idx = url.rfind(':')?;
        let port = url[idx + 1..].parse::<u16>().ok()?;
        Some((url[..idx].to_string(), port))
    }

    fn inbound(content: String) -> InboundMessage {
        InboundMessage {
            id: "socket-echo-1".to_string(),
            sender: "socket".to_string(),
            reply_target: "socket".to_string(),
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

    impl PluginInfo for SocketEcho {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }
        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Channel for SocketEcho {
        fn name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn configure(config: String) -> Result<(), String> {
            match extract_url(&config).and_then(|url| split_host_port(&url)) {
                Some((host, port)) => match socket::tcp_connect(&host, port, false) {
                    Ok(handle) => HANDLE.with(|h| h.set(handle)),
                    Err(e) => CONNECT_ERR.with(|c| *c.borrow_mut() = format!("connect: {e}")),
                },
                None => {
                    CONNECT_ERR.with(|c| *c.borrow_mut() = "no host:port in config".to_string())
                }
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
                if let Err(e) = socket::tcp_send(handle, b"ping") {
                    DONE.with(|d| d.set(true));
                    return Some(inbound(format!("send-error: {e}")));
                }
            }
            match socket::tcp_receive(handle) {
                Ok(SocketEvent::Data(bytes)) => {
                    DONE.with(|d| d.set(true));
                    Some(inbound(String::from_utf8_lossy(&bytes).into_owned()))
                }
                // Nothing yet — let the host back off and poll again.
                Ok(SocketEvent::Idle) => None,
                Ok(SocketEvent::Closed(r)) => {
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
    }

    export!(SocketEcho);
}
