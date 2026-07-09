//! End-to-end: drive a real WASM channel plugin that opens a host-mediated raw
//! TCP connection through the `socket` import, exactly as the daemon would.
//! Loads `socket-echo-fixture.wasm` — a channel built for `wasm32-wasip2`
//! (source in `tests/fixtures/socket-echo-fixture/`) that dials a `host:port`
//! from its config, sends a `"ping"` chunk, and returns the echoed bytes as its
//! one inbound message — against a local in-process TCP echo server. Proves the
//! host owns the socket (dial + duplex byte pumping + buffered receive) while
//! the plugin drives the protocol, and that the capability is permission-gated:
//! without `SocketClient` the import is not linked and the component fails
//! closed.
//!
//! The component is provisioned out of band as a build artifact (never
//! committed), same as the other channel/tool fixtures:
//!
//! ```text
//! cd crates/zeroclaw-plugins/tests/fixtures/socket-echo-fixture
//! cargo build --target wasm32-wasip2 --release
//! cp target/wasm32-wasip2/release/socket_echo_fixture.wasm ../socket-echo-fixture.wasm
//! ```
//!
//! When the fixture is absent these tests skip, so they never fail a checkout
//! that did not build it.

#![cfg(feature = "plugins-wasm-cranelift")]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use zeroclaw_api::channel::Channel;
use zeroclaw_plugins::PluginPermission;
use zeroclaw_plugins::component::PluginLimits;
use zeroclaw_plugins::wasm_channel::WasmChannel;

fn fixture() -> Option<PathBuf> {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/socket-echo-fixture.wasm");
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

/// Start an in-process TCP server that echoes every received byte. Binds an
/// ephemeral loopback port and returns its address; the accept loop and each
/// connection handler live for the test process. Plaintext — no certs — so the
/// round-trip is fully offline and deterministic.
async fn start_echo_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind echo server");
    let addr = listener.local_addr().expect("echo server local addr");
    zeroclaw_spawn::spawn!(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            zeroclaw_spawn::spawn!(async move {
                let mut buf = [0u8; 4096];
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if stream.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    addr
}

#[tokio::test]
async fn socket_client_round_trips_bytes() {
    let Some(wasm) = fixture() else {
        eprintln!("socket-echo-fixture.wasm absent; skipping (build it per the module docs).");
        return;
    };

    let addr = start_echo_server().await;
    let mut config = HashMap::new();
    config.insert("url".to_string(), addr.to_string());

    // ConfigRead delivers the host:port; SocketClient links the `socket` import.
    let channel = WasmChannel::from_wasm(
        "socket-echo-channel",
        &wasm,
        &[PluginPermission::ConfigRead, PluginPermission::SocketClient],
        &config,
        test_limits(),
    )
    .await
    .expect("socket channel plugin instantiates with SocketClient granted");

    let (tx, mut rx) = tokio::sync::mpsc::channel(4);
    channel.listen(tx).await.expect("listen starts");
    let content = tokio::time::timeout(Duration::from_secs(10), rx.recv())
        .await
        .expect("echoed bytes arrive within timeout")
        .expect("channel sender not dropped")
        .content;

    assert_eq!(
        content, "ping",
        "the host dials, the plugin sends bytes, and the host pumps the echo back"
    );
}

#[tokio::test]
async fn socket_plugin_without_permission_fails_closed() {
    let Some(wasm) = fixture() else {
        return;
    };

    // No SocketClient → the `socket` import is not linked. A component that
    // imports it must fail to instantiate rather than silently run without a
    // socket (or, worse, reach the network another way).
    let mut config = HashMap::new();
    config.insert("url".to_string(), "127.0.0.1:1".to_string());
    let result = WasmChannel::from_wasm(
        "socket-echo-channel",
        &wasm,
        &[PluginPermission::ConfigRead],
        &config,
        test_limits(),
    )
    .await;

    assert!(
        result.is_err(),
        "a plugin importing socket without SocketClient must fail to instantiate"
    );
}
