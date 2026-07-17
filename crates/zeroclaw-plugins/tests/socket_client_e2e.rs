//! End-to-end: drive a real WASM channel plugin through the production
//! permission and destination-policy boundary for the `socket` import.
//! Loads `socket-echo-fixture.wasm` — a channel built for `wasm32-wasip2`
//! (source in `tests/fixtures/socket-echo-fixture/`) that dials a `host:port`
//! from its config. The production-path tests prove that plaintext fails closed
//! without live operator authorization, that authorization never bypasses the
//! public-only destination guard, and that the capability is permission-gated:
//! without `SocketClient` the import is not linked and the component fails
//! closed. The offline byte round-trip lives beside the socket host unit tests,
//! where an exact test-only endpoint exception is unavailable to production
//! builds.
//!
//! The test builds the component from its checked-in source on demand. The
//! fixture is mandatory: a missing `wasm32-wasip2` target or a failed component
//! build fails the test rather than silently skipping the boundary proof.
//!
//! ```text
//! cd crates/zeroclaw-plugins/tests/fixtures/socket-echo-fixture
//! cargo build --target wasm32-wasip2
//! ```

#![cfg(feature = "plugins-wasm-cranelift")]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use zeroclaw_api::channel::Channel;
use zeroclaw_plugins::PluginPermission;
use zeroclaw_plugins::component::PluginLimits;
use zeroclaw_plugins::wasm_channel::WasmChannel;

fn fixture() -> PathBuf {
    static FIXTURE: OnceLock<PathBuf> = OnceLock::new();
    FIXTURE
        .get_or_init(|| {
            let fixture_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/socket-echo-fixture");
            let target_dir = fixture_dir.join("target");
            let core_only_status = Command::new(env!("CARGO"))
                .current_dir(&fixture_dir)
                .args([
                    "check",
                    "--locked",
                    "--quiet",
                    "--target",
                    "wasm32-wasip2",
                    "--features",
                    "core-wit-parse",
                    "--target-dir",
                ])
                .arg(&target_dir)
                .status()
                .expect("run cargo to parse the core-only channel world");
            assert!(
                core_only_status.success(),
                "optional socket annotations must not break core-only channel bindings"
            );
            let status = Command::new(env!("CARGO"))
                .current_dir(&fixture_dir)
                .args([
                    "build",
                    "--locked",
                    "--quiet",
                    "--target",
                    "wasm32-wasip2",
                    "--target-dir",
                ])
                .arg(&target_dir)
                .status()
                .expect("run cargo to build socket component fixture");
            assert!(
                status.success(),
                "socket component fixture must build; install the wasm32-wasip2 target"
            );
            let wasm = target_dir.join("wasm32-wasip2/debug/socket_echo_fixture.wasm");
            assert!(wasm.is_file(), "socket component fixture was not produced");
            wasm
        })
        .clone()
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
async fn socket_client_rejects_plaintext_without_operator_policy() {
    let wasm = fixture();
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
        Arc::new(|_| true),
    )
    .await
    .expect("socket channel plugin instantiates with SocketClient granted");

    let (tx, mut rx) = tokio::sync::mpsc::channel(4);
    let listener = zeroclaw_spawn::spawn!(async move { channel.listen(tx).await });
    let content = tokio::time::timeout(Duration::from_secs(10), rx.recv())
        .await
        .expect("echoed bytes arrive within timeout")
        .expect("channel sender not dropped")
        .content;
    listener.abort();

    assert!(
        content.starts_with("connect: socket_plaintext_not_allowed:"),
        "production socket policy must fail closed for plaintext, got: {content}"
    );
}

#[tokio::test]
async fn plaintext_authorization_does_not_bypass_destination_policy() {
    let wasm = fixture();
    let addr = start_echo_server().await;
    let mut config = HashMap::new();
    config.insert("url".to_string(), addr.to_string());

    let channel = WasmChannel::from_wasm_with_socket_policy(
        "socket-echo-channel",
        &wasm,
        &[PluginPermission::ConfigRead, PluginPermission::SocketClient],
        &config,
        test_limits(),
        Arc::new(|_| true),
        Arc::new(|host| host == "127.0.0.1"),
    )
    .await
    .expect("socket channel plugin instantiates with SocketClient granted");

    let (tx, mut rx) = tokio::sync::mpsc::channel(4);
    let listener = zeroclaw_spawn::spawn!(async move { channel.listen(tx).await });
    let content = tokio::time::timeout(Duration::from_secs(10), rx.recv())
        .await
        .expect("policy error arrives within timeout")
        .expect("channel sender not dropped")
        .content;
    listener.abort();

    assert!(
        content.starts_with("connect: socket_destination_not_allowed:"),
        "plaintext authorization must not permit loopback, got: {content}"
    );
}

#[tokio::test]
async fn socket_plugin_without_permission_fails_closed() {
    let wasm = fixture();

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
        Arc::new(|_| true),
    )
    .await;

    assert!(
        result.is_err(),
        "a plugin importing socket without SocketClient must fail to instantiate"
    );
}
