//! End-to-end: drive a real WASM channel plugin through the host's `WasmChannel`
//! exactly as the daemon does. Loads `channel-fixture.wasm` — a minimal echo
//! channel built for `wasm32-wasip2` (source in `tests/fixtures/channel-fixture/`)
//! that echoes the JSON it received from `configure` back as its one inbound
//! message — and exercises both delivery paths:
//!   * `from_wasm`        — a novel plugin (flat `[[plugins.entries]]` config)
//!   * `from_wasm_mirror` — a plugin that `provides` a built-in channel id and
//!     receives the plaintext, typed canonical `[channels.<id>.<alias>]` section
//!
//! The component is provisioned out of band as a build artifact (never committed,
//! same as `reference_plugin_e2e`):
//!
//! ```text
//! cd crates/zeroclaw-plugins/tests/fixtures/channel-fixture
//! cargo build --target wasm32-wasip2 --release
//! cp target/wasm32-wasip2/release/channel_fixture.wasm ../channel-fixture.wasm
//! ```
//!
//! When the fixture is absent these tests skip, so they never fail a checkout
//! that did not build it.

#![cfg(feature = "plugins-wasm-cranelift")]

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

use serde_json::Value;
use zeroclaw_api::channel::{Channel, SendMessage};
use zeroclaw_api::webhook::{RawWebhook, WebhookReject};
use zeroclaw_plugins::PluginPermission;
use zeroclaw_plugins::component::PluginLimits;
use zeroclaw_plugins::wasm_channel::WasmChannel;

fn fixture() -> Option<PathBuf> {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/channel-fixture.wasm");
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

fn outbound(content: &str) -> SendMessage {
    SendMessage {
        content: content.to_string(),
        recipient: "tester".to_string(),
        subject: None,
        thread_ts: None,
        cancellation_token: None,
        attachments: Vec::new(),
        in_reply_to: None,
        suppress_voice: false,
        force_voice: false,
    }
}

/// Run the host listen loop and return the content of the first inbound message
/// the plugin delivers (the fixture echoes its received config there).
async fn first_inbound_content(channel: &WasmChannel) -> String {
    let (tx, mut rx) = tokio::sync::mpsc::channel(4);
    channel.listen(tx).await.expect("listen starts");
    tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("inbound message arrives within timeout")
        .expect("channel sender not dropped")
        .content
}

#[tokio::test]
async fn novel_channel_plugin_runs_end_to_end() {
    let Some(wasm) = fixture() else {
        eprintln!("channel-fixture.wasm absent; skipping (build it per the module docs).");
        return;
    };

    // Novel path: identity is the plugin's own name; config is a flat map.
    let mut config = HashMap::new();
    config.insert("greeting".to_string(), "hi".to_string());
    let channel = WasmChannel::from_wasm(
        "echo-channel",
        &wasm,
        &[PluginPermission::ConfigRead],
        &config,
        test_limits(),
    )
    .await
    .expect("channel plugin instantiates (configure + get-channel-capabilities)");

    assert_eq!(channel.name(), "echo-channel");
    assert_eq!(channel.self_handle().as_deref(), Some("@echo"));
    assert!(channel.health_check().await, "fixture reports healthy");
    channel
        .send(&outbound("pong"))
        .await
        .expect("send succeeds");

    let echoed: Value = serde_json::from_str(&first_inbound_content(&channel).await)
        .expect("echoed config is JSON");
    assert_eq!(
        echoed.get("greeting").and_then(Value::as_str),
        Some("hi"),
        "novel plugin receives its flat-map config"
    );
}

#[tokio::test]
async fn mirror_channel_plugin_receives_plaintext_typed_config() {
    let Some(wasm) = fixture() else {
        return;
    };

    // Mirror path: the host feeds the canonical section as a JSON object, so a
    // plaintext secret AND typed fields (bool, array) survive — the flat
    // string-map path would lose the latter.
    let config_json =
        r#"{"bot_token":"secret-123","mention_only":true,"guild_ids":[1,2],"enabled":true}"#;
    let channel = WasmChannel::from_wasm_mirror(
        "telegram",
        "main",
        &wasm,
        &[PluginPermission::ConfigRead],
        config_json,
        test_limits(),
    )
    .await
    .expect("mirror channel plugin instantiates");

    // Identity is the mirrored built-in id, not the plugin's own WIT name.
    assert_eq!(channel.name(), "telegram");

    let echoed: Value = serde_json::from_str(&first_inbound_content(&channel).await)
        .expect("echoed config is JSON");
    assert_eq!(
        echoed.get("bot_token").and_then(Value::as_str),
        Some("secret-123"),
        "plaintext secret reaches the mirror"
    );
    assert_eq!(
        echoed.get("mention_only").and_then(Value::as_bool),
        Some(true),
        "bool type is preserved"
    );
    assert_eq!(
        echoed.get("guild_ids"),
        Some(&serde_json::json!([1, 2])),
        "array type is preserved"
    );
}

#[tokio::test]
async fn mirror_without_config_read_is_withheld() {
    let Some(wasm) = fixture() else {
        return;
    };

    // No ConfigRead → the canonical section (with its secret) is withheld; the
    // plugin is configured with `{}`, never another channel's credentials.
    let config_json = r#"{"bot_token":"secret-123","enabled":true}"#;
    let channel =
        WasmChannel::from_wasm_mirror("telegram", "main", &wasm, &[], config_json, test_limits())
            .await
            .expect("instantiates with empty config");

    assert_eq!(
        first_inbound_content(&channel).await,
        "{}",
        "config withheld without config_read"
    );
}

#[tokio::test]
async fn webhook_ingress_delivers_inbound() {
    let Some(wasm) = fixture() else {
        return;
    };

    // The fixture serves webhook path "fixture" and authenticates the
    // `x-fixture-secret` header against its configured value.
    let channel = WasmChannel::from_wasm_mirror(
        "fixture",
        "default",
        &wasm,
        &[PluginPermission::ConfigRead],
        "test-secret",
        test_limits(),
    )
    .await
    .expect("fixture instantiates");
    assert_eq!(channel.webhook_path().await.as_deref(), Some("fixture"));

    // Register the sink drain end + start the listener (which drains webhooks
    // on a second task), then feed raw webhooks as the gateway would.
    let (sink_tx, sink_rx) = tokio::sync::mpsc::channel::<RawWebhook>(4);
    channel.set_webhook_rx(sink_rx);
    let (tx, mut rx) = tokio::sync::mpsc::channel(4);
    channel.listen(tx).await.expect("listen starts");

    // Valid signature → the body is decoded into an inbound message and the
    // reply resolves Ok.
    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    sink_tx
        .send(RawWebhook {
            headers: vec![("x-fixture-secret".to_string(), "test-secret".to_string())],
            body: b"hello from webhook".to_vec(),
            reply: reply_tx,
        })
        .await
        .expect("sink accepts");
    assert!(
        matches!(reply_rx.await, Ok(Ok(()))),
        "valid webhook → reply Ok"
    );

    // Both the fixture's one-shot config echo (poll) and the webhook message
    // arrive on `tx`; order is not guaranteed, so assert the webhook body is
    // among the delivered messages.
    let mut delivered = Vec::new();
    for _ in 0..2 {
        if let Ok(Some(m)) = tokio::time::timeout(Duration::from_secs(5), rx.recv()).await {
            delivered.push(m.content);
        }
    }
    assert!(
        delivered.iter().any(|c| c == "hello from webhook"),
        "webhook body delivered as inbound: {delivered:?}"
    );

    // Wrong signature → the plugin rejects it: reply Err(Unauthorized).
    let (reply_tx2, reply_rx2) = tokio::sync::oneshot::channel();
    sink_tx
        .send(RawWebhook {
            headers: vec![("x-fixture-secret".to_string(), "wrong".to_string())],
            body: b"nope".to_vec(),
            reply: reply_tx2,
        })
        .await
        .expect("sink accepts");
    assert!(
        matches!(reply_rx2.await, Ok(Err(WebhookReject::Unauthorized(_)))),
        "bad signature → Unauthorized"
    );
}
