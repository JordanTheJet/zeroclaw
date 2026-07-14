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
//! `socket_client` grants public-network egress, not arbitrary host access.
//! Before dialing, the host rejects local/private names and resolves the target
//! once; every resolved address must pass [`zeroclaw_infra::net_guard`], and the
//! checked address set is passed directly to `TcpStream` so DNS cannot redirect
//! the subsequent dial to loopback, link-local, private, metadata, or reserved
//! space. There is no private-network exception in this capability.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
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
use zeroclaw_infra::net_guard::{is_non_global_v4, is_non_global_v6, is_private_or_local_host};

/// Max byte chunks buffered per connection before the read pump parks. Bounds
/// host memory if the plugin stops draining; parking the pump lets TCP flow
/// control slow the peer rather than growing the buffer without bound.
const INBOUND_CAP: usize = 1024;

/// Depth of the per-connection outbound queue. A `tcp-send` that would exceed
/// it fails fast rather than blocking the guest call, signalling the plugin is
/// producing faster than the socket drains.
const OUTBOUND_CAP: usize = 256;

/// Largest byte chunk retained by either pump. The read side never produces a
/// larger chunk, and `tcp-send` rejects a larger guest-owned vector before it
/// can enter the host queue. Combined with the fixed queue depths and
/// connection cap, this bounds retained host memory independently of Wasm
/// linear-memory limits.
const MAX_CHUNK_BYTES: usize = 16 * 1024;

/// Stable error key returned when a guest exceeds [`MAX_CHUNK_BYTES`]. The WIT
/// contract documents this key so plugins can classify the failure without
/// parsing the human-readable byte counts that follow it.
const OUTBOUND_CHUNK_TOO_LARGE: &str = "socket_outbound_chunk_too_large";

/// Stable error key for a destination rejected by the public-network policy.
const DESTINATION_NOT_ALLOWED: &str = "socket_destination_not_allowed";

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

#[cfg(test)]
tokio::task_local! {
    /// Exact loopback endpoint admitted only while an offline component test is
    /// scoped inside it. This symbol and its bypass do not exist in production
    /// builds.
    static TEST_SOCKET_DESTINATION: SocketAddr;
}

#[cfg(test)]
tokio::task_local! {
    /// One generated certificate trusted only inside the local TLS regression.
    /// Production builds contain neither this root nor this override.
    static TEST_TLS_ROOT: tokio_rustls::rustls::pki_types::CertificateDer<'static>;
}

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
        let normalized_host = normalized_host(&host)?.to_string();
        let tcp = tokio::time::timeout(CONNECT_TIMEOUT, connect_public(&normalized_host, port))
            .await
            .map_err(|_| {
                format!(
                    "tcp resolve/connect to {host}:{port} timed out after {}s",
                    CONNECT_TIMEOUT.as_secs()
                )
            })??;
        // Byte protocols multiplexed over this import (IRC lines, IMAP commands)
        // are latency-sensitive and small; trade batching for prompt delivery.
        let _ = tcp.set_nodelay(true);

        // Box the halves so plain-TCP and TLS connections share one `SocketConn`
        // shape; the pumps only need `AsyncRead`/`AsyncWrite`.
        type ReadHalf = Box<dyn AsyncRead + Unpin + Send>;
        type WriteHalf = Box<dyn AsyncWrite + Unpin + Send>;
        let (mut read_half, mut write_half): (ReadHalf, WriteHalf) = if tls {
            let connector = tls_connector()?;
            let server_name = ServerName::try_from(normalized_host.clone())
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
            let mut buf = vec![0u8; MAX_CHUNK_BYTES];
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
        validate_outbound_chunk(bytes.len())?;
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

/// Resolve once, reject the entire answer set if any address is non-global,
/// then dial those exact addresses. Passing the resolved set to `TcpStream`
/// avoids a second DNS lookup between authorization and connection.
async fn connect_public(host: &str, port: u16) -> Result<TcpStream, String> {
    let host = normalized_host(host)?;
    if is_private_or_local_host(host) && !test_literal_destination_allowed(host, port) {
        return Err(format!(
            "{DESTINATION_NOT_ALLOWED}: {host}:{port} is local or non-global"
        ));
    }

    let resolved = tokio::net::lookup_host((host, port))
        .await
        .map_err(|e| format!("tcp resolve for {host}:{port} failed: {e}"))?
        .collect::<Vec<_>>();
    validate_resolved_destinations(host, port, &resolved)?;

    TcpStream::connect(resolved.as_slice())
        .await
        .map_err(|e| format!("tcp connect to {host}:{port} failed: {e}"))
}

fn validate_resolved_destinations(
    host: &str,
    port: u16,
    resolved: &[SocketAddr],
) -> Result<(), String> {
    if resolved.is_empty() {
        return Err(format!(
            "tcp resolve for {host}:{port} returned no addresses"
        ));
    }

    if let Some(blocked) = resolved
        .iter()
        .copied()
        .find(|addr| !destination_allowed(*addr))
    {
        return Err(format!(
            "{DESTINATION_NOT_ALLOWED}: {host}:{port} resolved to non-global address {blocked}"
        ));
    }
    Ok(())
}

fn normalized_host(host: &str) -> Result<&str, String> {
    if host.is_empty() || host.trim() != host {
        return Err("socket host must be non-empty and contain no surrounding whitespace".into());
    }
    if let Some(without_open) = host.strip_prefix('[') {
        return without_open
            .strip_suffix(']')
            .ok_or_else(|| "socket host has invalid IPv6 brackets".to_string());
    }
    if host.ends_with(']') {
        return Err("socket host has invalid IPv6 brackets".to_string());
    }
    Ok(host)
}

fn destination_allowed(addr: SocketAddr) -> bool {
    let public = match addr.ip() {
        IpAddr::V4(v4) => !is_non_global_v4(v4),
        IpAddr::V6(v6) => !is_non_global_v6(v6),
    };
    if public {
        return true;
    }

    #[cfg(test)]
    {
        TEST_SOCKET_DESTINATION
            .try_with(|allowed| *allowed == addr)
            .unwrap_or(false)
    }

    #[cfg(not(test))]
    {
        false
    }
}

fn test_literal_destination_allowed(host: &str, port: u16) -> bool {
    #[cfg(test)]
    {
        host.parse::<IpAddr>()
            .ok()
            .map(|ip| SocketAddr::new(ip, port))
            .is_some_and(|addr| {
                TEST_SOCKET_DESTINATION
                    .try_with(|allowed| *allowed == addr)
                    .unwrap_or(false)
            })
    }

    #[cfg(not(test))]
    {
        let _ = (host, port);
        false
    }
}

fn validate_outbound_chunk(len: usize) -> Result<(), String> {
    if len > MAX_CHUNK_BYTES {
        return Err(format!(
            "{OUTBOUND_CHUNK_TOO_LARGE}: {len} bytes exceeds the {MAX_CHUNK_BYTES}-byte limit"
        ));
    }
    Ok(())
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
    #[cfg(test)]
    if let Ok(cert) = TEST_TLS_ROOT.try_with(Clone::clone) {
        roots
            .add(cert)
            .map_err(|e| format!("test tls root rejected: {e}"))?;
    }
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
    #[cfg(feature = "plugins-wasm-cranelift")]
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    #[cfg(feature = "plugins-wasm-cranelift")]
    use std::path::PathBuf;
    #[cfg(feature = "plugins-wasm-cranelift")]
    use std::process::Command;
    use std::sync::Arc;
    #[cfg(feature = "plugins-wasm-cranelift")]
    use std::sync::OnceLock;
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::oneshot;
    #[cfg(feature = "plugins-wasm-cranelift")]
    use zeroclaw_api::channel::Channel;

    use super::{
        DESTINATION_NOT_ALLOWED, MAX_CHUNK_BYTES, MAX_CONNS, OUTBOUND_CHUNK_TOO_LARGE,
        SocketRegistry, TEST_SOCKET_DESTINATION, TEST_TLS_ROOT, destination_allowed,
        format_read_close_reason, normalized_host, validate_outbound_chunk,
        validate_resolved_destinations,
    };
    use crate::PluginPermission;
    use crate::component::PluginLimits;

    fn test_limits() -> PluginLimits {
        PluginLimits {
            call_fuel: 1_000_000_000,
            max_memory_bytes: 64 * 1024 * 1024,
            max_table_elements: 100_000,
            max_instances: 64,
        }
    }

    async fn connect_local(registry: &mut SocketRegistry, addr: SocketAddr) -> Result<u64, String> {
        TEST_SOCKET_DESTINATION
            .scope(
                addr,
                registry.connect(addr.ip().to_string(), addr.port(), false),
            )
            .await
    }

    /// Accept one connection and report both acceptance and peer EOF. EOF is
    /// the externally observable proof that dropping the registry-owned pump
    /// tasks released their socket halves.
    async fn start_observed_peer() -> (SocketAddr, oneshot::Receiver<()>, oneshot::Receiver<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (accepted_tx, accepted_rx) = oneshot::channel();
        let (closed_tx, closed_rx) = oneshot::channel();
        zeroclaw_spawn::spawn!(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let _ = accepted_tx.send(());
            let mut buf = [0_u8; 64];
            loop {
                match stream.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
            }
            let _ = closed_tx.send(());
        });
        (addr, accepted_rx, closed_rx)
    }

    async fn start_tls_echo_server() -> (
        SocketAddr,
        tokio_rustls::rustls::pki_types::CertificateDer<'static>,
    ) {
        use tokio_rustls::rustls::ServerConfig;
        use tokio_rustls::rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

        let rcgen::CertifiedKey { cert, key_pair } =
            rcgen::generate_simple_self_signed(["127.0.0.1".to_string()]).unwrap();
        let cert_der = cert.der().clone();
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));
        let config = ServerConfig::builder_with_provider(Arc::new(
            tokio_rustls::rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key)
        .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        zeroclaw_spawn::spawn!(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let Ok(mut stream) = acceptor.accept(stream).await else {
                return;
            };
            let mut buf = [0_u8; 4096];
            loop {
                match stream.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => stream.write_all(&buf[..n]).await.unwrap(),
                }
            }
        });
        (addr, cert_der)
    }

    #[cfg(feature = "plugins-wasm-cranelift")]
    fn socket_fixture() -> PathBuf {
        static FIXTURE: OnceLock<PathBuf> = OnceLock::new();
        FIXTURE
            .get_or_init(|| {
                let fixture_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/fixtures/socket-echo-fixture");
                let target_dir = fixture_dir.join("target");
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

    #[test]
    fn outbound_chunk_accepts_exact_limit_and_rejects_one_byte_over() {
        assert_eq!(validate_outbound_chunk(MAX_CHUNK_BYTES), Ok(()));
        let err = validate_outbound_chunk(MAX_CHUNK_BYTES + 1).unwrap_err();
        assert!(err.starts_with(OUTBOUND_CHUNK_TOO_LARGE));
        assert!(err.contains(&(MAX_CHUNK_BYTES + 1).to_string()));
        assert!(err.contains(&MAX_CHUNK_BYTES.to_string()));
    }

    #[test]
    fn destination_policy_allows_only_global_addresses() {
        for addr in [
            SocketAddr::from(([127, 0, 0, 1], 443)),
            SocketAddr::from(([10, 0, 0, 1], 443)),
            SocketAddr::from(([169, 254, 169, 254], 80)),
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 443),
            SocketAddr::new("fe80::1".parse().unwrap(), 443),
        ] {
            assert!(!destination_allowed(addr), "{addr} must be blocked");
        }
        for addr in [
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 443),
            SocketAddr::new("2606:4700:4700::1111".parse().unwrap(), 443),
        ] {
            assert!(destination_allowed(addr), "{addr} must be allowed");
        }
    }

    #[test]
    fn destination_policy_rejects_empty_and_mixed_dns_answers() {
        let public = SocketAddr::from(([1, 1, 1, 1], 443));
        let private = SocketAddr::from(([10, 0, 0, 1], 443));

        let empty = validate_resolved_destinations("example.com", 443, &[]).unwrap_err();
        assert!(empty.contains("returned no addresses"), "{empty}");
        assert!(validate_resolved_destinations("example.com", 443, &[public]).is_ok());

        let mixed =
            validate_resolved_destinations("example.com", 443, &[public, private]).unwrap_err();
        assert!(mixed.starts_with(DESTINATION_NOT_ALLOWED), "{mixed}");
        assert!(mixed.contains(&private.to_string()), "{mixed}");
    }

    #[test]
    fn host_normalization_accepts_bracketed_ipv6_only_when_balanced() {
        assert_eq!(normalized_host("[::1]").unwrap(), "::1");
        assert_eq!(normalized_host("example.com").unwrap(), "example.com");
        assert!(normalized_host("[::1").is_err());
        assert!(normalized_host("::1]").is_err());
        assert!(normalized_host(" example.com").is_err());
    }

    #[tokio::test]
    async fn private_destination_is_rejected_before_dial() {
        let mut registry = SocketRegistry::new();
        let err = registry
            .connect("169.254.169.254".to_string(), 80, false)
            .await
            .unwrap_err();
        assert!(err.starts_with(DESTINATION_NOT_ALLOWED), "{err}");
        assert!(registry.conns.is_empty());
    }

    #[tokio::test]
    async fn oversized_send_is_not_retained_and_connection_remains_usable() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        zeroclaw_spawn::spawn!(async move {
            let (_stream, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(5)).await;
        });

        let mut registry = SocketRegistry::new();
        let handle = connect_local(&mut registry, addr).await.unwrap();
        let err = registry
            .send(handle, vec![0; MAX_CHUNK_BYTES + 1])
            .unwrap_err();
        assert!(err.starts_with(OUTBOUND_CHUNK_TOO_LARGE), "{err}");

        registry
            .send(handle, vec![0; MAX_CHUNK_BYTES])
            .expect("the rejected vector did not consume queue capacity");
        registry.close(handle);
    }

    #[tokio::test]
    async fn tls_connect_verifies_certificate_and_round_trips_bytes() {
        let (addr, root) = start_tls_echo_server().await;
        let mut registry = SocketRegistry::new();
        let handle = TEST_TLS_ROOT
            .scope(
                root,
                TEST_SOCKET_DESTINATION.scope(
                    addr,
                    registry.connect(addr.ip().to_string(), addr.port(), true),
                ),
            )
            .await
            .expect("TLS connection trusts the scoped test certificate");

        registry.send(handle, b"ping".to_vec()).unwrap();
        let bytes = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                match registry.receive(handle).unwrap() {
                    super::SocketPoll::Data(bytes) => break bytes,
                    super::SocketPoll::Idle => tokio::time::sleep(Duration::from_millis(10)).await,
                    super::SocketPoll::Closed(reason) => {
                        panic!("TLS echo connection closed before data: {reason}")
                    }
                }
            }
        })
        .await
        .expect("TLS echo arrives");
        assert_eq!(bytes, b"ping");
        registry.close(handle);
    }

    #[tokio::test]
    async fn tls_connect_rejects_untrusted_certificate() {
        let (addr, _untrusted_root) = start_tls_echo_server().await;
        let mut registry = SocketRegistry::new();
        let err = TEST_SOCKET_DESTINATION
            .scope(
                addr,
                registry.connect(addr.ip().to_string(), addr.port(), true),
            )
            .await
            .unwrap_err();
        assert!(err.starts_with("tls handshake"), "unexpected error: {err}");
        assert!(registry.conns.is_empty());
    }

    #[tokio::test]
    async fn close_terminates_pumps_and_releases_socket() {
        let (addr, accepted, closed) = start_observed_peer().await;
        let mut registry = SocketRegistry::new();
        let handle = connect_local(&mut registry, addr).await.unwrap();
        accepted.await.unwrap();

        registry.close(handle);
        assert!(
            registry.conns.is_empty(),
            "tcp-close releases registry capacity"
        );
        tokio::time::timeout(Duration::from_secs(2), closed)
            .await
            .expect("peer observes EOF after tcp-close")
            .unwrap();
    }

    #[tokio::test]
    async fn plugin_store_drop_terminates_pumps_and_releases_socket() {
        let (addr, accepted, closed) = start_observed_peer().await;
        let mut store =
            crate::component::new_store(&[PluginPermission::SocketClient], test_limits());
        connect_local(store.data_mut().socket_mut(), addr)
            .await
            .unwrap();
        accepted.await.unwrap();

        drop(store);
        tokio::time::timeout(Duration::from_secs(2), closed)
            .await
            .expect("peer observes EOF after plugin store state drops")
            .unwrap();
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
            connect_local(&mut registry, SocketAddr::from(([127, 0, 0, 1], port)))
                .await
                .unwrap();
        }
        let err = connect_local(&mut registry, SocketAddr::from(([127, 0, 0, 1], port)))
            .await
            .unwrap_err();
        assert!(
            err.contains("socket connection limit reached"),
            "cap error must be named, got: {err}"
        );

        // Handles start at 1, so the first connection is handle 1.
        registry.close(1);
        connect_local(&mut registry, SocketAddr::from(([127, 0, 0, 1], port)))
            .await
            .unwrap();
    }

    #[cfg(feature = "plugins-wasm-cranelift")]
    #[tokio::test]
    async fn real_component_round_trips_through_socket_import() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        zeroclaw_spawn::spawn!(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = [0_u8; 4096];
            loop {
                match stream.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => stream.write_all(&buf[..n]).await.unwrap(),
                }
            }
        });

        let mut config = HashMap::new();
        config.insert("url".to_string(), addr.to_string());
        let channel = TEST_SOCKET_DESTINATION
            .scope(
                addr,
                crate::wasm_channel::WasmChannel::from_wasm(
                    "socket-echo-channel",
                    &socket_fixture(),
                    &[PluginPermission::ConfigRead, PluginPermission::SocketClient],
                    &config,
                    test_limits(),
                ),
            )
            .await
            .expect("real socket component instantiates");

        let (tx, mut rx) = tokio::sync::mpsc::channel(4);
        channel.listen(tx).await.unwrap();
        let content = tokio::time::timeout(Duration::from_secs(10), rx.recv())
            .await
            .expect("component receives echoed bytes")
            .expect("channel sender remains open")
            .content;
        assert_eq!(content, "ping");
    }
}
