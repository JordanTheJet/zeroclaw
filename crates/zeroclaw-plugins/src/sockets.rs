//! Host-owned outbound raw TCP (+TLS) client for channel plugins (`socket`).
//!
//! `zeroclaw-plugins` is otherwise a no-network sandbox crate (see the invariant
//! on [`crate::component::PluginState`]): the WASI context has no preopens and no
//! sockets. This module is a deliberate, permission-gated exception. Channel
//! plugins whose platform speaks a raw byte protocol over a socket — IRC,
//! email IMAP/SMTP, MQTT, AMQP — cannot open one inside the sandbox, so, exactly
//! as the host runs their inbound listener and performs their `wasi:http` TLS,
//! the host owns the socket here and hands the plugin an opaque `u64` handle over
//! the `socket` WIT import. It resolves and dials `host:port`, optionally
//! performs the TLS client handshake (`tls = true`), and pumps bytes; the plugin
//! drives the application protocol (registration, login, keepalives, framing)
//! while the host stays protocol-agnostic.
//!
//! Each live connection owns two spawned tasks — a read pump draining byte
//! chunks into a bounded buffer and a writer forwarding queued outbound chunks —
//! that are aborted when the [`SocketConn`] is dropped (on `tcp-close` or when
//! the whole [`SocketRegistry`] drops with its `PluginState`), so a plugin
//! restart never orphans a socket or a task.
//!
//! TODO(follow-up): extract the concrete dialer behind a `SocketTransport` trait
//! injected from `zeroclaw-runtime`, so this crate's no-network invariant stays
//! literal (see the strategy plan's Phase-C notes) — and add a manifest host/port
//! allowlist: raw TCP to any `host:port` is a wider SSRF surface than the
//! WebSocket capability's URL dial, so a granted plugin should be confinable to
//! the endpoints its manifest declares.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{Notify, mpsc};
use tokio::task::AbortHandle;
use tokio_rustls::rustls::pki_types::ServerName;

use crate::component::PluginState;
use crate::component::bindings;

/// Max byte chunks buffered per connection before the read pump parks. Bounds
/// host memory if the plugin stops draining; parking the pump lets TCP flow
/// control slow the peer rather than growing the buffer without bound.
const INBOUND_CAP: usize = 1024;

/// Depth of the per-connection outbound queue. A `tcp-send` that would exceed
/// it fails fast rather than blocking the guest call, signalling the plugin is
/// producing faster than the socket drains.
const OUTBOUND_CAP: usize = 256;

/// Size of the read pump's scratch buffer, and therefore the largest single
/// chunk surfaced to the plugin. Raw TCP has no framing, so the boundary is
/// arbitrary anyway; the plugin reassembles its own protocol units.
const READ_CHUNK: usize = 16 * 1024;

/// Max live connections per plugin store. Each connection is a host socket
/// plus two spawned pump tasks — resources that live outside the guest's
/// memory/table/fuel limits — so without a cap a plugin holding
/// `socket_client` could loop `tcp-connect` and exhaust host file
/// descriptors and tasks. The protocols this import exists for need a
/// handful (IRC one; email one IMAP + one SMTP; MQTT one), so a small
/// constant bounds abuse without constraining real use; `tcp-close` frees
/// capacity.
const MAX_CONNS: usize = 16;

/// Bound on the DNS resolve + TCP dial, and separately on the TLS handshake,
/// in [`SocketRegistry::connect`]. The guest's `tcp-connect` call holds the
/// plugin store lock, so an unbounded dial against a firewall that silently
/// drops SYNs — or a peer that accepts TCP but never completes the TLS
/// handshake — would freeze every other call on the plugin (the listen poll
/// loop included) for as long as the OS lets the attempt hang. Deliberately
/// tighter than the WebSocket capability's unbounded `ws-connect` (a known gap
/// there, not a template behavior to preserve).
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// A single event surfaced to the plugin by [`SocketRegistry::receive`],
/// decoupled from the generated `socket-event` bindings type (mapped to it in
/// the `Host` impl).
pub enum SocketPoll {
    /// A chunk of received bytes.
    Data(Vec<u8>),
    /// Nothing queued and the connection is still live.
    Idle,
    /// The connection has ended and its buffered chunks are drained.
    Closed(String),
}

/// One live host-owned connection: the outbound queue the writer drains, the
/// inbound buffer the reader fills, and the abort handles for both pump tasks.
struct SocketConn {
    outbound: mpsc::Sender<Vec<u8>>,
    inbound: Arc<Mutex<VecDeque<Vec<u8>>>>,
    /// Set by the read pump once the socket closes or errors; further receives
    /// drain the buffer, then report [`SocketPoll::Closed`].
    dead: Arc<AtomicBool>,
    close_reason: Arc<Mutex<String>>,
    /// Woken after a drain so a pump parked on a full buffer resumes reading.
    notify: Arc<Notify>,
    reader: AbortHandle,
    writer: AbortHandle,
}

impl Drop for SocketConn {
    fn drop(&mut self) {
        // Abort both pumps so a closed/dropped connection leaves nothing running.
        self.reader.abort();
        self.writer.abort();
    }
}

/// Per-plugin table of live host-owned TCP connections, keyed by the opaque
/// handle the plugin holds. One [`SocketRegistry`] lives in each channel
/// plugin's [`PluginState`]; dropping it (with the store, on plugin shutdown or
/// restart) drops every [`SocketConn`], aborting all pump tasks.
pub struct SocketRegistry {
    conns: HashMap<u64, SocketConn>,
    next: u64,
}

impl Default for SocketRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl SocketRegistry {
    pub fn new() -> Self {
        Self {
            conns: HashMap::new(),
            // Start at 1 so 0 is never a valid handle.
            next: 1,
        }
    }

    /// Dial `host:port` (TLS client handshake on top when `tls` is set), spawn
    /// the read/write pumps, and register the connection. Returns its handle.
    pub async fn connect(&mut self, host: String, port: u16, tls: bool) -> Result<u64, String> {
        // Refuse before dialing: the cap bounds host sockets and pump tasks,
        // so a connection that would exceed it must never be created at all.
        if self.conns.len() >= MAX_CONNS {
            return Err(format!(
                "socket connection limit reached ({MAX_CONNS} live connections); \
                 tcp-close one before connecting again"
            ));
        }
        let tcp = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect((host.as_str(), port)))
            .await
            .map_err(|_| {
                format!(
                    "tcp connect to {host}:{port} timed out after {}s",
                    CONNECT_TIMEOUT.as_secs()
                )
            })?
            .map_err(|e| format!("tcp connect to {host}:{port} failed: {e}"))?;
        // Byte protocols multiplexed over this import (IRC lines, IMAP commands)
        // are latency-sensitive and small; trade batching for prompt delivery.
        let _ = tcp.set_nodelay(true);

        // Box the halves so plain-TCP and TLS connections share one `SocketConn`
        // shape; the pumps only need `AsyncRead`/`AsyncWrite`.
        type ReadHalf = Box<dyn AsyncRead + Unpin + Send>;
        type WriteHalf = Box<dyn AsyncWrite + Unpin + Send>;
        let (mut read_half, mut write_half): (ReadHalf, WriteHalf) = if tls {
            let connector = tls_connector()?;
            let server_name = ServerName::try_from(host.clone())
                .map_err(|e| format!("invalid tls server name {host:?}: {e}"))?;
            let stream = tokio::time::timeout(CONNECT_TIMEOUT, connector.connect(server_name, tcp))
                .await
                .map_err(|_| {
                    format!(
                        "tls handshake to {host:?} timed out after {}s",
                        CONNECT_TIMEOUT.as_secs()
                    )
                })?
                .map_err(|e| format!("tls handshake to {host:?} failed: {e}"))?;
            let (r, w) = tokio::io::split(stream);
            (Box::new(r), Box::new(w))
        } else {
            let (r, w) = tokio::io::split(tcp);
            (Box::new(r), Box::new(w))
        };

        let inbound: Arc<Mutex<VecDeque<Vec<u8>>>> = Arc::new(Mutex::new(VecDeque::new()));
        let dead = Arc::new(AtomicBool::new(false));
        let close_reason = Arc::new(Mutex::new(String::new()));
        let notify = Arc::new(Notify::new());
        let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(OUTBOUND_CAP);

        // Writer: forward queued outbound chunks until the queue closes (the
        // connection was dropped) or the socket errors, then flush a shutdown.
        let writer = zeroclaw_spawn::spawn!(async move {
            while let Some(bytes) = out_rx.recv().await {
                if write_half.write_all(&bytes).await.is_err() {
                    break;
                }
            }
            let _ = write_half.shutdown().await;
        });

        // Reader: drain byte chunks into the bounded buffer; record close/error.
        let inbound_r = inbound.clone();
        let dead_r = dead.clone();
        let reason_r = close_reason.clone();
        let notify_r = notify.clone();
        let reader = zeroclaw_spawn::spawn!(async move {
            let mut buf = vec![0u8; READ_CHUNK];
            loop {
                // Backpressure: park while the buffer is full so we stop reading
                // and TCP flow control kicks in; `receive` wakes us after a drain.
                while lock(&inbound_r).len() >= INBOUND_CAP {
                    notify_r.notified().await;
                }
                match read_half.read(&mut buf).await {
                    Ok(0) => {
                        *lock(&reason_r) = format_read_close_reason(None);
                        dead_r.store(true, Ordering::SeqCst);
                        break;
                    }
                    Ok(n) => {
                        lock(&inbound_r).push_back(buf[..n].to_vec());
                    }
                    Err(e) => {
                        *lock(&reason_r) = format_read_close_reason(Some(&e));
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
            SocketConn {
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

    /// Queue a chunk of bytes for the connection. Non-blocking: a full outbound
    /// buffer or a closed connection is a fast error, never a stall of the guest
    /// call (which holds the plugin store lock).
    pub fn send(&self, handle: u64, bytes: Vec<u8>) -> Result<(), String> {
        let conn = self.conn(handle)?;
        if conn.dead.load(Ordering::SeqCst) {
            return Err("socket connection is closed".to_string());
        }
        conn.outbound.try_send(bytes).map_err(|e| match e {
            mpsc::error::TrySendError::Full(_) => "socket outbound buffer full".to_string(),
            mpsc::error::TrySendError::Closed(_) => "socket connection is closed".to_string(),
        })
    }

    /// Pop the next buffered chunk, `Idle` when none is queued and the socket is
    /// live, or `Closed` once it has ended and its buffer is drained.
    pub fn receive(&self, handle: u64) -> Result<SocketPoll, String> {
        let conn = self.conn(handle)?;
        let chunk = lock(&conn.inbound).pop_front();
        // Wake the read pump in case it parked on a full buffer.
        conn.notify.notify_one();
        match chunk {
            Some(bytes) => Ok(SocketPoll::Data(bytes)),
            None if conn.dead.load(Ordering::SeqCst) => {
                Ok(SocketPoll::Closed(lock(&conn.close_reason).clone()))
            }
            None => Ok(SocketPoll::Idle),
        }
    }

    /// Number of byte chunks currently buffered for the connection.
    pub fn pending(&self, handle: u64) -> Result<u32, String> {
        Ok(lock(&self.conn(handle)?.inbound).len() as u32)
    }

    /// Drop the connection, aborting its pumps (via [`SocketConn`]'s `Drop`).
    /// Idempotent: an unknown handle is a no-op.
    pub fn close(&mut self, handle: u64) {
        self.conns.remove(&handle);
    }

    fn conn(&self, handle: u64) -> Result<&SocketConn, String> {
        self.conns
            .get(&handle)
            .ok_or_else(|| format!("unknown socket handle {handle}"))
    }
}

/// Lock a mutex, recovering a poisoned guard so a panic in one pump task cannot
/// strand a connection's buffer — matching `InboundQueue`'s recovery policy.
fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// The `Closed` reason recorded by the read pump: a clean EOF (`read` returned
/// `Ok(0)`) is the peer closing the connection; an I/O error carries its text so
/// the plugin can log it or decide whether to reconnect.
fn format_read_close_reason(error: Option<&std::io::Error>) -> String {
    match error {
        Some(e) => format!("socket read error: {e}"),
        None => "peer closed the connection".to_string(),
    }
}

/// A TLS connector over the WebPKI root set with the `ring` provider, built
/// per-connection. Deliberately self-contained (`builder_with_provider`, no
/// global `install_default`) so linking this crate never mutates process-wide
/// rustls state another component may have configured differently.
fn tls_connector() -> Result<tokio_rustls::TlsConnector, String> {
    use tokio_rustls::rustls::{ClientConfig, RootCertStore};
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = ClientConfig::builder_with_provider(std::sync::Arc::new(
        tokio_rustls::rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| format!("tls client config rejected safe default protocol versions: {e}"))?
    .with_root_certificates(roots)
    .with_no_client_auth();
    Ok(tokio_rustls::TlsConnector::from(std::sync::Arc::new(
        config,
    )))
}

impl bindings::channel::zeroclaw::plugin::socket::Host for PluginState {
    async fn tcp_connect(&mut self, host: String, port: u16, tls: bool) -> Result<u64, String> {
        self.socket_mut().connect(host, port, tls).await
    }

    async fn tcp_send(&mut self, handle: u64, bytes: Vec<u8>) -> Result<(), String> {
        self.socket_mut().send(handle, bytes)
    }

    async fn tcp_receive(
        &mut self,
        handle: u64,
    ) -> Result<bindings::channel::zeroclaw::plugin::socket::SocketEvent, String> {
        use bindings::channel::zeroclaw::plugin::socket::SocketEvent;
        self.socket_mut().receive(handle).map(|poll| match poll {
            SocketPoll::Data(bytes) => SocketEvent::Data(bytes),
            SocketPoll::Idle => SocketEvent::Idle,
            SocketPoll::Closed(r) => SocketEvent::Closed(r),
        })
    }

    async fn tcp_pending(&mut self, handle: u64) -> Result<u32, String> {
        self.socket_mut().pending(handle)
    }

    async fn tcp_close(&mut self, handle: u64) {
        self.socket_mut().close(handle);
    }
}

#[cfg(test)]
mod tests {
    use super::{MAX_CONNS, SocketRegistry, format_read_close_reason};

    #[test]
    fn read_close_reason_distinguishes_eof_from_error() {
        // A clean EOF is the peer closing — no error text for the plugin to
        // misparse as a fault worth alerting on.
        assert_eq!(format_read_close_reason(None), "peer closed the connection");
        // An I/O error carries its text so the plugin can log it or decide
        // whether the failure is worth a reconnect.
        let err = std::io::Error::new(std::io::ErrorKind::ConnectionReset, "reset by peer");
        assert_eq!(
            format_read_close_reason(Some(&err)),
            "socket read error: reset by peer"
        );
    }

    #[test]
    fn unknown_handle_is_a_named_error() {
        // Handles start at 1 and no connection was opened, so every operation
        // on an arbitrary handle must fail with the handle named — never panic.
        let registry = SocketRegistry::new();
        assert_eq!(
            registry.send(7, b"x".to_vec()).unwrap_err(),
            "unknown socket handle 7"
        );
        assert_eq!(
            registry.receive(7).map(|_| ()).unwrap_err(),
            "unknown socket handle 7"
        );
        assert_eq!(registry.pending(7).unwrap_err(), "unknown socket handle 7");
    }

    #[test]
    fn close_is_idempotent_for_unknown_handles() {
        // `tcp-close` is documented as a no-op on unknown/already-closed
        // handles, so a plugin's shutdown path can close defensively.
        let mut registry = SocketRegistry::new();
        registry.close(42);
        registry.close(42);
    }

    #[tokio::test]
    async fn connect_fails_at_cap_and_close_frees_capacity() {
        // Sockets and pump tasks are host resources outside the guest's wasm
        // limits, so the registry itself must refuse work past MAX_CONNS —
        // with a named error, not a panic — and must hand the slot back on
        // close so a well-behaved plugin can rotate connections.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        zeroclaw_spawn::spawn!(async move {
            // Hold every accepted socket so the registry's ends stay live.
            let mut held = Vec::new();
            while let Ok((conn, _)) = listener.accept().await {
                held.push(conn);
            }
        });

        let mut registry = SocketRegistry::new();
        for _ in 0..MAX_CONNS {
            registry
                .connect("127.0.0.1".to_string(), port, false)
                .await
                .unwrap();
        }
        let err = registry
            .connect("127.0.0.1".to_string(), port, false)
            .await
            .unwrap_err();
        assert!(
            err.contains("socket connection limit reached"),
            "cap error must be named, got: {err}"
        );

        // Handles start at 1, so the first connection is handle 1.
        registry.close(1);
        registry
            .connect("127.0.0.1".to_string(), port, false)
            .await
            .unwrap();
    }
}
