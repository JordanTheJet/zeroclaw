//! Host-owned outbound WebSocket client for channel plugins (`ws-client`).
//!
//! `zeroclaw-plugins` is otherwise a no-network sandbox crate (see the invariant
//! on [`crate::component::PluginState`]): the WASI context has no preopens and no
//! sockets. This module is the one deliberate, permission-gated exception.
//! Channel plugins whose platform needs a persistent duplex socket — Discord
//! Gateway, Slack Socket Mode — cannot open one inside the sandbox, so, exactly
//! as the host runs their inbound listener and performs their `wasi:http` TLS,
//! the host owns the socket here and hands the plugin an opaque `u64` handle over
//! the `ws-client` WIT import. The plugin drives the application protocol
//! (identify, heartbeats, acks, resume); the host stays protocol-agnostic and
//! only pumps frames.
//!
//! Each live connection owns two spawned tasks — a read pump draining frames into
//! a bounded buffer and a writer forwarding queued outbound frames — that are
//! aborted when the [`WsConn`] is dropped (on `ws-close` or when the whole
//! [`WsRegistry`] drops with its `PluginState`), so a plugin restart never
//! orphans a socket or a task.
//!
//! TODO(follow-up): extract the concrete dialer behind a `WsTransport` trait
//! injected from `zeroclaw-runtime`, so this crate's no-network invariant stays
//! literal (see the strategy plan's Phase-C notes).

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use tokio::sync::{Notify, mpsc};
use tokio::task::AbortHandle;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::{HeaderName, HeaderValue};
use tokio_tungstenite::tungstenite::protocol::CloseFrame;

use crate::component::PluginState;
use crate::component::bindings;

/// Max text frames buffered per connection before the read pump parks. Bounds
/// host memory if the plugin stops draining; parking the pump lets TCP flow
/// control slow the server rather than growing the buffer without bound.
const INBOUND_CAP: usize = 1024;

/// Depth of the per-connection outbound queue. A `ws-send-text` that would
/// exceed it fails fast rather than blocking the guest call, signalling the
/// plugin is producing faster than the socket drains.
const OUTBOUND_CAP: usize = 256;

/// Max live WebSocket connections per plugin store. Each entry owns a host
/// socket and two pump tasks outside the guest's memory/table/fuel limits, so
/// the existing `WsRegistry::conns` table is checked before every dial.
/// `ws-close` removes the entry and immediately frees capacity.
const MAX_CONNS: usize = 16;

/// Bound on DNS resolution, TCP/TLS setup, and the WebSocket handshake. A
/// plugin call holds the warm store lock while connecting, so an unbounded
/// handshake would stall every other export for that channel.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// A single event surfaced to the plugin by [`WsRegistry::receive`], decoupled
/// from the generated `ws-event` bindings type (mapped to it in the `Host` impl).
pub enum WsPoll {
    /// A received text frame.
    Text(String),
    /// Nothing queued and the connection is still live.
    Idle,
    /// The connection has ended and its buffered frames are drained.
    Closed(String),
}

/// One live host-owned connection: the outbound queue the writer drains, the
/// inbound buffer the reader fills, and the abort handles for both pump tasks.
struct WsConn {
    outbound: mpsc::Sender<Message>,
    inbound: Arc<Mutex<VecDeque<String>>>,
    /// Set by the read pump once the socket closes or errors; further receives
    /// drain the buffer, then report [`WsPoll::Closed`].
    dead: Arc<AtomicBool>,
    close_reason: Arc<Mutex<String>>,
    /// Woken after a drain so a pump parked on a full buffer resumes reading.
    notify: Arc<Notify>,
    reader: AbortHandle,
    writer: AbortHandle,
}

impl Drop for WsConn {
    fn drop(&mut self) {
        // Abort both pumps so a closed/dropped connection leaves nothing running.
        self.reader.abort();
        self.writer.abort();
    }
}

/// Per-plugin table of live host-owned WebSocket connections, keyed by the
/// opaque handle the plugin holds. One [`WsRegistry`] lives in each channel
/// plugin's [`PluginState`]; dropping it (with the store, on plugin shutdown or
/// restart) drops every [`WsConn`], aborting all pump tasks.
pub struct WsRegistry {
    conns: HashMap<u64, WsConn>,
    next: u64,
}

impl Default for WsRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl WsRegistry {
    pub fn new() -> Self {
        Self {
            conns: HashMap::new(),
            // Start at 1 so 0 is never a valid handle.
            next: 1,
        }
    }

    /// Dial `url` with the given extra upgrade headers, spawn the read/write
    /// pumps, and register the connection. Returns its handle.
    pub async fn connect(
        &mut self,
        url: String,
        headers: Vec<(String, String)>,
    ) -> Result<u64, String> {
        self.connect_with_timeout(url, headers, CONNECT_TIMEOUT)
            .await
    }

    async fn connect_with_timeout(
        &mut self,
        url: String,
        headers: Vec<(String, String)>,
        connect_timeout: Duration,
    ) -> Result<u64, String> {
        if self.conns.len() >= MAX_CONNS {
            return Err(format!(
                "websocket connection limit reached ({MAX_CONNS} live connections); \
                 ws-close one before connecting again"
            ));
        }

        let mut request = url
            .as_str()
            .into_client_request()
            .map_err(|e| format!("invalid websocket url {url:?}: {e}"))?;
        {
            let req_headers = request.headers_mut();
            for (k, v) in &headers {
                let name = HeaderName::from_bytes(k.as_bytes())
                    .map_err(|e| format!("invalid header name {k:?}: {e}"))?;
                let value = HeaderValue::from_str(v)
                    .map_err(|e| format!("invalid header value for {k:?}: {e}"))?;
                req_headers.append(name, value);
            }
        }

        let (stream, _response) =
            tokio::time::timeout(connect_timeout, tokio_tungstenite::connect_async(request))
                .await
                .map_err(|_| {
                    format!("websocket connect to {url:?} timed out after {connect_timeout:?}")
                })?
                .map_err(|e| format!("websocket connect to {url:?} failed: {e}"))?;
        let (mut write, mut read) = stream.split();

        let inbound: Arc<Mutex<VecDeque<String>>> = Arc::new(Mutex::new(VecDeque::new()));
        let dead = Arc::new(AtomicBool::new(false));
        let close_reason = Arc::new(Mutex::new(String::new()));
        let notify = Arc::new(Notify::new());
        let (out_tx, mut out_rx) = mpsc::channel::<Message>(OUTBOUND_CAP);

        // Writer: forward queued outbound frames until the queue closes (the
        // connection was dropped) or the socket errors, then flush a close frame.
        let writer = zeroclaw_spawn::spawn!(async move {
            while let Some(msg) = out_rx.recv().await {
                if write.send(msg).await.is_err() {
                    break;
                }
            }
            let _ = write.close().await;
        });

        // Reader: drain text frames into the bounded buffer; record close/error.
        let inbound_r = inbound.clone();
        let dead_r = dead.clone();
        let reason_r = close_reason.clone();
        let notify_r = notify.clone();
        let reader = zeroclaw_spawn::spawn!(async move {
            loop {
                // Backpressure: park while the buffer is full so we stop reading
                // and TCP flow control kicks in; `receive` wakes us after a drain.
                while lock(&inbound_r).len() >= INBOUND_CAP {
                    notify_r.notified().await;
                }
                match read.next().await {
                    Some(Ok(Message::Text(text))) => {
                        lock(&inbound_r).push_back(text.to_string());
                    }
                    // Binary/Ping/Pong/raw Frame are ignored; tungstenite answers
                    // transport-level Pings on its own.
                    Some(Ok(
                        Message::Binary(_)
                        | Message::Ping(_)
                        | Message::Pong(_)
                        | Message::Frame(_),
                    )) => {}
                    Some(Ok(Message::Close(frame))) => {
                        *lock(&reason_r) = format_close_reason(frame);
                        dead_r.store(true, Ordering::SeqCst);
                        break;
                    }
                    Some(Err(e)) => {
                        *lock(&reason_r) = format!("websocket error: {e}");
                        dead_r.store(true, Ordering::SeqCst);
                        break;
                    }
                    None => {
                        *lock(&reason_r) = "websocket stream ended".to_string();
                        dead_r.store(true, Ordering::SeqCst);
                        break;
                    }
                }
            }
        });

        let handle = self.next;
        self.next += 1;
        self.conns.insert(
            handle,
            WsConn {
                outbound: out_tx,
                inbound,
                dead,
                close_reason,
                notify,
                reader: reader.abort_handle(),
                writer: writer.abort_handle(),
            },
        );
        Ok(handle)
    }

    /// Queue a text frame for the connection. Non-blocking: a full outbound
    /// buffer or a closed connection is a fast error, never a stall of the guest
    /// call (which holds the plugin store lock).
    pub fn send_text(&self, handle: u64, text: String) -> Result<(), String> {
        let conn = self.conn(handle)?;
        if conn.dead.load(Ordering::SeqCst) {
            return Err("websocket connection is closed".to_string());
        }
        conn.outbound
            .try_send(Message::Text(text.into()))
            .map_err(|e| match e {
                mpsc::error::TrySendError::Full(_) => "websocket outbound buffer full".to_string(),
                mpsc::error::TrySendError::Closed(_) => {
                    "websocket connection is closed".to_string()
                }
            })
    }

    /// Pop the next buffered frame, `Idle` when none is queued and the socket is
    /// live, or `Closed` once it has ended and its buffer is drained.
    pub fn receive(&self, handle: u64) -> Result<WsPoll, String> {
        let conn = self.conn(handle)?;
        let frame = lock(&conn.inbound).pop_front();
        // Wake the read pump in case it parked on a full buffer.
        conn.notify.notify_one();
        match frame {
            Some(text) => Ok(WsPoll::Text(text)),
            None if conn.dead.load(Ordering::SeqCst) => {
                Ok(WsPoll::Closed(lock(&conn.close_reason).clone()))
            }
            None => Ok(WsPoll::Idle),
        }
    }

    /// Number of frames currently buffered for the connection.
    pub fn pending(&self, handle: u64) -> Result<u32, String> {
        Ok(lock(&self.conn(handle)?.inbound).len() as u32)
    }

    /// Drop the connection, aborting its pumps (via [`WsConn`]'s `Drop`).
    /// Idempotent: an unknown handle is a no-op.
    pub fn close(&mut self, handle: u64) {
        self.conns.remove(&handle);
    }

    fn conn(&self, handle: u64) -> Result<&WsConn, String> {
        self.conns
            .get(&handle)
            .ok_or_else(|| format!("unknown websocket handle {handle}"))
    }
}

/// Lock a mutex, recovering a poisoned guard so a panic in one pump task cannot
/// strand a connection's buffer — matching `InboundQueue`'s recovery policy.
fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// The `Closed` reason string for a server close frame: the numeric close code
/// as a leading `"<code>"`, optionally followed by `": <reason>"`. A plugin can
/// parse the leading code to distinguish fatal protocol closes (e.g. a Discord
/// 4004/4014, which must stop reconnecting) from transient ones. A close with no
/// frame gets a plain reason with no code.
fn format_close_reason(frame: Option<CloseFrame>) -> String {
    match frame {
        Some(f) => {
            let code = u16::from(f.code);
            let text = f.reason.as_str();
            if text.is_empty() {
                code.to_string()
            } else {
                format!("{code}: {text}")
            }
        }
        None => "server closed the connection".to_string(),
    }
}

impl bindings::channel::zeroclaw::plugin::ws_client::Host for PluginState {
    async fn ws_connect(
        &mut self,
        url: String,
        headers: Vec<(String, String)>,
    ) -> Result<u64, String> {
        self.websocket_mut().connect(url, headers).await
    }

    async fn ws_send_text(&mut self, handle: u64, text: String) -> Result<(), String> {
        self.websocket_mut().send_text(handle, text)
    }

    async fn ws_receive(
        &mut self,
        handle: u64,
    ) -> Result<bindings::channel::zeroclaw::plugin::ws_client::WsEvent, String> {
        use bindings::channel::zeroclaw::plugin::ws_client::WsEvent;
        self.websocket_mut().receive(handle).map(|poll| match poll {
            WsPoll::Text(t) => WsEvent::Text(t),
            WsPoll::Idle => WsEvent::Idle,
            WsPoll::Closed(r) => WsEvent::Closed(r),
        })
    }

    async fn ws_pending(&mut self, handle: u64) -> Result<u32, String> {
        self.websocket_mut().pending(handle)
    }

    async fn ws_close(&mut self, handle: u64) {
        self.websocket_mut().close(handle);
    }
}

#[cfg(test)]
mod tests {
    use super::{MAX_CONNS, WsRegistry, format_close_reason};
    use std::time::Duration;
    use tokio::net::TcpListener;
    use tokio_tungstenite::tungstenite::protocol::CloseFrame;
    use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;

    #[test]
    fn close_reason_surfaces_the_numeric_code() {
        assert_eq!(
            format_close_reason(Some(CloseFrame {
                code: CloseCode::from(4014),
                reason: "Disallowed intent(s).".into(),
            })),
            "4014: Disallowed intent(s)."
        );
        // Empty reason → bare code.
        assert_eq!(
            format_close_reason(Some(CloseFrame {
                code: CloseCode::from(1000),
                reason: "".into(),
            })),
            "1000"
        );
        // No frame → plain reason, no leading code for the plugin to misparse.
        assert_eq!(format_close_reason(None), "server closed the connection");
    }

    #[tokio::test]
    async fn connect_fails_at_cap_and_close_frees_capacity() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind local websocket server");
        let addr = listener.local_addr().expect("read listener address");
        zeroclaw_spawn::spawn!(async move {
            let mut held = Vec::new();
            while let Ok((tcp, _)) = listener.accept().await {
                if let Ok(websocket) = tokio_tungstenite::accept_async(tcp).await {
                    held.push(websocket);
                }
            }
        });

        let mut registry = WsRegistry::new();
        for _ in 0..MAX_CONNS {
            registry
                .connect(format!("ws://{addr}"), Vec::new())
                .await
                .expect("connection below the cap succeeds");
        }

        let err = registry
            .connect(format!("ws://{addr}"), Vec::new())
            .await
            .expect_err("connection above the cap fails");
        assert!(
            err.contains("websocket connection limit reached"),
            "cap error must be named, got: {err}"
        );

        registry.close(1);
        registry
            .connect(format!("ws://{addr}"), Vec::new())
            .await
            .expect("ws-close returns capacity to the registry");
    }

    #[tokio::test]
    async fn connect_times_out_when_peer_never_finishes_handshake() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind stalled handshake server");
        let addr = listener.local_addr().expect("read listener address");
        zeroclaw_spawn::spawn!(async move {
            if let Ok((tcp, _)) = listener.accept().await {
                let _held_open = tcp;
                std::future::pending::<()>().await;
            }
        });

        let mut registry = WsRegistry::new();
        let err = registry
            .connect_with_timeout(
                format!("ws://{addr}"),
                Vec::new(),
                Duration::from_millis(25),
            )
            .await
            .expect_err("a stalled handshake must hit the host deadline");
        assert!(
            err.contains("timed out"),
            "timeout error must be named, got: {err}"
        );
    }
}
