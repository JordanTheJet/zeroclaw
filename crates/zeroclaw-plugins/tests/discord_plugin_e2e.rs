//! End-to-end: drive the real Discord channel plugin through the host's
//! `WasmChannel` + `ws-client` against an in-process fake Discord Gateway.
//!
//! The plugin (`discord-plugin.wasm`, source in the sibling `zeroclaw-plugins`
//! repo `plugins/discord/`) runs the actual Gateway protocol over the host
//! WebSocket capability: it connects, waits for Hello, sends IDENTIFY, and on
//! READY + MESSAGE_CREATE emits the message as inbound. The fake gateway speaks
//! just enough of the protocol to prove the round-trip; the `gateway_url` config
//! override points the plugin at it, so no discord.com traffic occurs.
//!
//! The component is provisioned out of band as a build artifact (never
//! committed), same as `reference_plugin_e2e`:
//!
//! ```text
//! cd ../zeroclaw-plugins/plugins/discord   # the plugins repo
//! cargo build --target wasm32-wasip2 --release
//! cp target/wasm32-wasip2/release/discord.wasm \
//!    <this repo>/crates/zeroclaw-plugins/tests/fixtures/discord-plugin.wasm
//! ```
//!
//! When the fixture is absent this test skips, so it never fails a checkout that
//! did not build it.

#![cfg(feature = "plugins-wasm-cranelift")]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use serde_json::Value;
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;
use zeroclaw_api::channel::Channel;
use zeroclaw_plugins::PluginPermission;
use zeroclaw_plugins::component::PluginLimits;
use zeroclaw_plugins::wasm_channel::{SenderAuthorizer, WasmChannel};
use zeroclaw_plugins::ws::{WsEgressException, WsEgressPolicy};

fn allow_all() -> SenderAuthorizer {
    Arc::new(|_| true)
}

fn fixture() -> Option<PathBuf> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/discord-plugin.wasm");
    path.exists().then_some(path)
}

fn test_limits() -> PluginLimits {
    PluginLimits {
        call_fuel: 1_000_000_000,
        max_memory_bytes: 64 * 1024 * 1024,
        max_table_elements: 100_000,
        max_instances: 64,
    }
}

fn loopback_test_policy() -> WsEgressPolicy {
    Arc::new(|host, exception| {
        host == "127.0.0.1"
            && matches!(
                exception,
                WsEgressException::Plaintext | WsEgressException::PrivateNetwork
            )
    })
}

/// A minimal in-process Discord Gateway: on each connection it sends Hello,
/// waits for the plugin's IDENTIFY (op 2), then pushes READY followed by one
/// MESSAGE_CREATE. A long heartbeat interval keeps the short test from needing
/// to service heartbeats. Returns the bound loopback address.
async fn fake_gateway() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake gateway");
    let addr = listener.local_addr().expect("gateway local addr");
    zeroclaw_spawn::spawn!(async move {
        while let Ok((stream, _)) = listener.accept().await {
            zeroclaw_spawn::spawn!(async move {
                let Ok(ws) = tokio_tungstenite::accept_async(stream).await else {
                    return;
                };
                let (mut write, mut read) = ws.split();

                // Hello with a long heartbeat interval.
                if write
                    .send(Message::Text(
                        r#"{"op":10,"d":{"heartbeat_interval":60000}}"#.into(),
                    ))
                    .await
                    .is_err()
                {
                    return;
                }

                // Wait for the plugin's IDENTIFY (op 2) before dispatching, so
                // the test proves the handshake actually happened.
                let mut identified = false;
                while let Some(Ok(msg)) = read.next().await {
                    if let Message::Text(t) = msg
                        && serde_json::from_str::<Value>(&t)
                            .ok()
                            .and_then(|v| v["op"].as_u64())
                            == Some(2)
                    {
                        identified = true;
                        break;
                    }
                }
                if !identified {
                    return;
                }

                // READY establishes the session + the bot's own id; then one
                // user message the plugin must surface as inbound.
                let ready = r#"{"op":0,"t":"READY","s":1,"d":{
                    "session_id":"sess-1","resume_gateway_url":"ws://unused",
                    "user":{"id":"bot-id","username":"zc-bot"}}}"#;
                let message = r#"{"op":0,"t":"MESSAGE_CREATE","s":2,"d":{
                    "id":"999","type":0,"channel_id":"chan-1","guild_id":"g-1",
                    "author":{"id":"user-1","username":"alice"},"content":"hello from user"}}"#;
                let _ = write.send(Message::Text(ready.into())).await;
                let _ = write.send(Message::Text(message.into())).await;

                // Keep the socket open (absorb any later frames, e.g. heartbeats).
                while let Some(Ok(_)) = read.next().await {}
            });
        }
    });
    addr
}

#[tokio::test]
async fn discord_plugin_delivers_a_gateway_message() {
    let Some(wasm) = fixture() else {
        eprintln!("discord-plugin.wasm absent; skipping (build it per the module docs).");
        return;
    };

    let addr = fake_gateway().await;
    // `gateway_url` sends the plugin straight to the fake gateway (no
    // GET /gateway/bot, no discord.com). The token's first segment decodes to a
    // valid id so the pre-READY self-filter is well-formed.
    let config = format!(r#"{{"bot_token":"MTIzNDU2.abc.def","gateway_url":"ws://{addr}"}}"#);

    // Mirror the built-in `discord` id; the plugin needs HttpClient (it imports
    // wasi:http via waki) + WebSocketClient (the Gateway) + ConfigRead.
    let channel = WasmChannel::from_wasm_mirror_with_ws_egress_policy(
        "discord",
        "main",
        &wasm,
        &[
            PluginPermission::ConfigRead,
            PluginPermission::HttpClient,
            PluginPermission::WebSocketClient,
        ],
        &config,
        test_limits(),
        allow_all(),
        loopback_test_policy(),
    )
    .await
    .expect("discord plugin instantiates with ws-client + wasi:http granted");
    assert_eq!(channel.name(), "discord");

    let (tx, mut rx) = tokio::sync::mpsc::channel(4);
    let listener = zeroclaw_spawn::spawn!(async move { channel.listen(tx).await });

    let content = tokio::time::timeout(Duration::from_secs(15), rx.recv())
        .await
        .expect("the gateway message reaches the host within timeout")
        .expect("channel sender not dropped")
        .content;

    assert_eq!(
        content, "hello from user",
        "the plugin ran the full Hello→Identify→Ready→Message flow over host ws-client"
    );

    drop(rx);
    tokio::time::timeout(Duration::from_secs(2), listener)
        .await
        .expect("listener stops after its receiver closes")
        .expect("listener task joins")
        .expect("listener exits cleanly");
}
