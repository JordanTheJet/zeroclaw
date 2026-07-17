//! End-to-end: drive a real WASM channel plugin that opens a host-mediated
//! WebSocket through the `ws-client` import, exactly as the daemon would. Loads
//! `ws-echo-fixture.wasm` — a channel built for `wasm32-wasip2` (source in
//! `tests/fixtures/ws-echo-fixture/`) that dials a `ws://` URL from its config,
//! sends a `"ping"` frame, and returns the echoed frame as its one inbound
//! message — against a local in-process echo server. Proves the host owns the
//! socket (dial + duplex framing + buffered receive) while the plugin drives the
//! protocol, and that the capability is permission-gated: without
//! `WebSocketClient` the import is not linked and the component fails closed.
//!
//! The test builds the checked-in fixture source for `wasm32-wasip2` before it
//! runs. Missing target support or a fixture compile failure is a test failure,
//! so this guest boundary can no longer disappear from a green run.

#![cfg(feature = "plugins-wasm-cranelift")]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
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

fn fixture() -> PathBuf {
    static FIXTURE: OnceLock<PathBuf> = OnceLock::new();
    FIXTURE
        .get_or_init(|| {
            let fixture_dir =
                PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/ws-echo-fixture");
            let status = Command::new(env!("CARGO"))
                .args([
                    "build",
                    "--locked",
                    "--target",
                    "wasm32-wasip2",
                    "--release",
                ])
                .current_dir(&fixture_dir)
                .status()
                .expect("start mandatory ws-echo fixture build");
            assert!(status.success(), "mandatory ws-echo fixture must build");

            let path = fixture_dir.join("target/wasm32-wasip2/release/ws_echo_fixture.wasm");
            assert!(
                path.is_file(),
                "fixture build did not produce {}",
                path.display()
            );
            path
        })
        .clone()
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

fn test_limits() -> PluginLimits {
    PluginLimits {
        call_fuel: 1_000_000_000,
        max_memory_bytes: 64 * 1024 * 1024,
        max_table_elements: 100_000,
        max_instances: 64,
    }
}

/// Start an in-process WebSocket server that echoes every text/binary frame.
/// Binds an ephemeral loopback port and returns its address; the accept loop and
/// each connection handler live for the test process. Plaintext `ws://` — no
/// certs — so the round-trip is fully offline and deterministic.
async fn start_echo_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind echo server");
    let addr = listener.local_addr().expect("echo server local addr");
    zeroclaw_spawn::spawn!(async move {
        while let Ok((stream, _)) = listener.accept().await {
            zeroclaw_spawn::spawn!(async move {
                let Ok(ws) = tokio_tungstenite::accept_async(stream).await else {
                    return;
                };
                let (mut write, mut read) = ws.split();
                while let Some(Ok(msg)) = read.next().await {
                    match msg {
                        Message::Text(_) | Message::Binary(_) => {
                            if write.send(msg).await.is_err() {
                                break;
                            }
                        }
                        Message::Close(_) => break,
                        _ => {}
                    }
                }
            });
        }
    });
    addr
}

#[tokio::test]
async fn ws_client_round_trips_a_text_frame() {
    let wasm = fixture();

    let addr = start_echo_server().await;
    let mut config = HashMap::new();
    config.insert("url".to_string(), format!("ws://{addr}"));

    // ConfigRead delivers the URL; WebSocketClient links the `ws-client` import.
    let channel = WasmChannel::from_wasm_with_ws_egress_policy(
        "ws-echo-channel",
        &wasm,
        &[
            PluginPermission::ConfigRead,
            PluginPermission::WebSocketClient,
        ],
        &config,
        test_limits(),
        allow_all(),
        loopback_test_policy(),
    )
    .await
    .expect("ws channel plugin instantiates with WebSocketClient granted");

    let (tx, mut rx) = tokio::sync::mpsc::channel(4);
    let listener = zeroclaw_spawn::spawn!(async move { channel.listen(tx).await });
    let content = tokio::time::timeout(Duration::from_secs(10), rx.recv())
        .await
        .expect("echoed frame arrives within timeout")
        .expect("channel sender not dropped")
        .content;

    assert_eq!(
        content, "ping",
        "the host dials, the plugin sends a frame, and the host pumps the echo back"
    );

    drop(rx);
    tokio::time::timeout(Duration::from_secs(2), listener)
        .await
        .expect("listener stops after its receiver closes")
        .expect("listener task joins")
        .expect("listener exits cleanly");
}

#[tokio::test]
async fn ws_plugin_without_permission_fails_closed() {
    let wasm = fixture();

    // No WebSocketClient → the `ws-client` import is not linked. A component that
    // imports it must fail to instantiate rather than silently run without a
    // socket (or, worse, reach the network another way).
    let mut config = HashMap::new();
    config.insert("url".to_string(), "ws://127.0.0.1:1".to_string());
    let result = WasmChannel::from_wasm(
        "ws-echo-channel",
        &wasm,
        &[PluginPermission::ConfigRead],
        &config,
        test_limits(),
        allow_all(),
    )
    .await;

    assert!(
        result.is_err(),
        "a plugin importing ws-client without WebSocketClient must fail to instantiate"
    );
}
