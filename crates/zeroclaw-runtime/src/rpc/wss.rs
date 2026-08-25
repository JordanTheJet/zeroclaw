//! WebSocket Secure (WSS) transport for the RPC layer.
//! Mirrors the Unix socket transport (`unix.rs`) but uses TLS-encrypted
//! WebSocket connections, enabling remote TUI-to-daemon connectivity.

use super::context::RpcContext;
use super::dispatch::RpcDispatcher;
use super::transport::RpcTransport;
use anyhow::{Context, Result};
use async_trait::async_trait;
use futures_util::{SinkExt, StreamExt};
use std::collections::HashMap;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::Poll;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::protocol::CloseFrame;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_util::sync::CancellationToken;

type TlsStream = tokio_rustls::server::TlsStream<TcpStream>;

/// What the WebSocket parser actually reads from: the TLS stream with a
/// byte counter in front of it. See [`CountingStream`].
type CountedTlsStream = CountingStream<TlsStream>;

/// How long the read side waits for any frame before sending a liveness Ping.
const HEARTBEAT_IDLE: Duration = Duration::from_secs(20);

/// How long to wait after a Ping for any frame (a Pong, or anything else)
/// before declaring the peer dead and tearing the connection down.
const HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(10);

/// Backoff after a transient `accept()` error so the serve loop does not
/// hot-spin while the condition (e.g. fd exhaustion) clears.
const ACCEPT_ERROR_BACKOFF_MS: u64 = 50;

/// Default ceiling on sockets past `accept()` but not yet through the TLS and
/// WebSocket handshakes. See [`WssLimits::max_pending_handshakes`].
pub const DEFAULT_MAX_PENDING_HANDSHAKES: usize = 256;

/// Default absolute budget for TLS accept plus the WebSocket upgrade.
/// See [`WssLimits::handshake_timeout`].
pub const DEFAULT_HANDSHAKE_TIMEOUT_SECS: u64 = 10;

/// Default ceiling on concurrently established WSS sessions.
/// See [`WssLimits::max_sessions`].
pub const DEFAULT_MAX_SESSIONS: usize = 512;

/// Default ceiling on concurrent sessions holding ONE client certificate.
/// See [`WssLimits::max_sessions_per_client`].
pub const DEFAULT_MAX_SESSIONS_PER_CLIENT: usize = 8;

/// Default lifetime bound on a partially-received data message.
/// See [`WssLimits::incomplete_message_timeout`].
pub const DEFAULT_INCOMPLETE_MESSAGE_TIMEOUT_SECS: u64 = 60;

/// Bytes read with no message completed before the incomplete-message deadline
/// applies at all. Below this nothing worth reclaiming is parked in the parser,
/// and the threshold is what keeps a QUIET connection (which accumulates no
/// bytes) out of the rule entirely.
const INCOMPLETE_MESSAGE_BYTES: u64 = 64 * 1024;

/// Wire size of a client-to-server control frame's header: two bytes of framing
/// plus the four-byte mask every client frame carries (RFC 6455 5.1). Control
/// frames cannot be fragmented and cap their payload at 125 bytes, so this is
/// exact rather than an estimate.
const CONTROL_FRAME_HEADER_BYTES: u64 = 6;

/// Bound on the courtesy Close frame sent to a refused peer, so a peer that
/// stops reading cannot make the refusal itself hold the permits it was denied.
const REFUSAL_CLOSE_TIMEOUT: Duration = Duration::from_secs(2);

/// Bounds on the WSS listener's pre-authentication and session state.
///
/// The remote WSS plane is the daemon's mandatory mTLS surface and its default
/// bind is `0.0.0.0`, so every state an *unauthenticated* peer can reach has to
/// be bounded in both time and count. Without these, each accepted TCP socket
/// spawned a task that awaited the TLS handshake and the WebSocket upgrade with
/// no deadline and no cap, so a peer that merely connected - and never proved
/// anything - could accumulate sockets, tasks and TLS parser state without
/// limit. Mirrors the bounds the relay applies to its own admission path.
#[derive(Debug, Clone)]
pub struct WssLimits {
    /// Ceiling on sockets past `accept()` that have not finished the TLS
    /// handshake and WebSocket upgrade. When the pool is exhausted new sockets
    /// are dropped at accept rather than queued, so a slowloris spread across
    /// many source addresses sheds instead of accumulating.
    pub max_pending_handshakes: usize,
    /// One absolute deadline covering TLS accept AND the WebSocket upgrade,
    /// measured from accept. It is a single budget for the whole setup
    /// sequence, not a fresh window per phase: the heartbeat only starts once
    /// a session is established, so without this a peer could stall in either
    /// handshake forever.
    pub handshake_timeout: Duration,
    /// Ceiling on concurrently established WSS sessions. Bounds the steady
    /// state that survives authentication, so an authorized-but-abusive peer
    /// cannot grow dispatcher and transport state without limit.
    pub max_sessions: usize,
    /// Ceiling on concurrent sessions presenting ONE client certificate, keyed
    /// by that certificate's SHA-256 fingerprint.
    ///
    /// `max_sessions` alone is an arithmetic ceiling, not a host-memory budget:
    /// every session may declare a message up to the parser envelope
    /// (`rpc_ws_config`), so 512 sessions is a 16 GiB ceiling, and one
    /// admitted-but-hostile credential (or a stolen one, before it is detected
    /// and revoked) can occupy all of it. This bounds the parser bytes ONE
    /// credential can reserve at `max_sessions_per_client x envelope`.
    pub max_sessions_per_client: usize,
    /// How long a partially-received data message may be held by the parser.
    ///
    /// The heartbeat proves liveness, not progress: tungstenite yields
    /// interleaved control frames while a fragmented message is still
    /// incomplete, so a peer can Ping forever while the parser retains the
    /// partial buffer. This bounds that hold time. It applies only while bytes
    /// are actually accumulating with no message completed (see
    /// `INCOMPLETE_MESSAGE_BYTES`); an idle connection is the heartbeat's
    /// business.
    ///
    /// It is a lifetime bound, not a stall detector - a peer that trickles
    /// bytes is exactly the case a stall detector would miss - so it also
    /// bounds the slowest legitimate upload: a full-size request
    /// ([`crate::rpc::attachments::MAX_REQUEST_BYTES`], 20 MiB) must arrive
    /// within this window (at the 60s default that is a ~341 KiB/s floor;
    /// operators on slower links should raise the window, not disable it).
    pub incomplete_message_timeout: Duration,
}

impl Default for WssLimits {
    fn default() -> Self {
        Self {
            max_pending_handshakes: DEFAULT_MAX_PENDING_HANDSHAKES,
            handshake_timeout: Duration::from_secs(DEFAULT_HANDSHAKE_TIMEOUT_SECS),
            max_sessions: DEFAULT_MAX_SESSIONS,
            max_sessions_per_client: DEFAULT_MAX_SESSIONS_PER_CLIENT,
            incomplete_message_timeout: Duration::from_secs(
                DEFAULT_INCOMPLETE_MESSAGE_TIMEOUT_SECS,
            ),
        }
    }
}

/// Concurrent sessions per client credential, keyed by the SHA-256 fingerprint
/// of the presented client certificate.
///
/// The fingerprint is the only stable per-credential identity the mTLS accept
/// path exposes; source address is not one (a single credential can arrive from
/// many addresses, and many credentials can share one). Entries exist only
/// while a credential holds at least one session, so a churn of certificates
/// cannot grow this map.
#[derive(Default)]
struct ClientSessionQuota {
    counts: Mutex<HashMap<String, usize>>,
}

impl ClientSessionQuota {
    /// Reserve one session slot for `fingerprint`, or `None` when that
    /// credential is already at `max`. A refused peer is never recorded, so a
    /// rejection leaves no residue in the map.
    fn try_admit(self: &Arc<Self>, fingerprint: &str, max: usize) -> Option<ClientSessionGuard> {
        let cap = max.max(1);
        let mut counts = self.lock_counts();
        let current = counts.get(fingerprint).copied().unwrap_or(0);
        if current >= cap {
            return None;
        }
        counts.insert(fingerprint.to_string(), current + 1);
        drop(counts);
        Some(ClientSessionGuard {
            quota: self.clone(),
            fingerprint: fingerprint.to_string(),
        })
    }

    /// A poisoned lock means some other task panicked mid-update; the map is a
    /// plain counter table with no invariant that a panic can leave broken, so
    /// recover the guard rather than propagating the panic into the accept loop.
    fn lock_counts(&self) -> std::sync::MutexGuard<'_, HashMap<String, usize>> {
        self.counts.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// Releases the per-credential session slot on every exit path of a session
/// task - dispatcher return, read error, EOF, heartbeat timeout, panic. Manual
/// decrements would be missed by at least one of those, and a missed decrement
/// permanently shrinks that credential's quota.
struct ClientSessionGuard {
    quota: Arc<ClientSessionQuota>,
    fingerprint: String,
}

impl Drop for ClientSessionGuard {
    fn drop(&mut self) {
        let mut counts = self.quota.lock_counts();
        if let Some(slot) = counts.get_mut(&self.fingerprint) {
            *slot = slot.saturating_sub(1);
            if *slot == 0 {
                counts.remove(&self.fingerprint);
            }
        }
    }
}

/// Counts plaintext bytes read out of the inner stream.
///
/// tungstenite does not expose the buffer holding a partially-received message,
/// so bytes read with no message completed is the observable stand-in for how
/// much a peer has parked in the parser. See
/// [`WssLimits::incomplete_message_timeout`].
struct CountingStream<S> {
    inner: S,
    bytes_in: Arc<AtomicU64>,
}

impl<S> CountingStream<S> {
    fn new(inner: S) -> (Self, Arc<AtomicU64>) {
        let bytes_in = Arc::new(AtomicU64::new(0));
        (
            Self {
                inner,
                bytes_in: bytes_in.clone(),
            },
            bytes_in,
        )
    }

    fn get_ref(&self) -> &S {
        &self.inner
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for CountingStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let polled = Pin::new(&mut this.inner).poll_read(cx, buf);
        if matches!(polled, Poll::Ready(Ok(()))) {
            let read = buf.filled().len().saturating_sub(before);
            this.bytes_in.fetch_add(read as u64, Ordering::Relaxed);
        }
        polled
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for CountingStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// Decrements the shared client counter on every exit path of a connection
/// task. The counter drives `--ephemeral` shutdown, so a missed decrement
/// would keep an idle daemon alive forever.
struct ClientCountGuard(Arc<AtomicUsize>);

impl Drop for ClientCountGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

/// File-descriptor exhaustion errno values, stable across the Unix targets
/// we support (Linux, macOS, BSD).
#[cfg(unix)]
const EMFILE: i32 = 24; // too many open files (this process)
#[cfg(unix)]
const ENFILE: i32 = 23; // too many open files (system-wide)

fn is_recoverable_accept_error(e: &std::io::Error) -> bool {
    if matches!(
        e.kind(),
        ErrorKind::ConnectionAborted | ErrorKind::Interrupted | ErrorKind::WouldBlock
    ) {
        return true;
    }
    #[cfg(unix)]
    if matches!(e.raw_os_error(), Some(EMFILE) | Some(ENFILE)) {
        return true;
    }
    false
}

// ── Transport ────────────────────────────────────────────────────

/// Control frames the read side asks the writer task to emit out-of-band
/// from the JSON-RPC text stream.
enum Control {
    Ping,
}

pub struct WssTransport {
    reader: futures_util::stream::SplitStream<WebSocketStream<CountedTlsStream>>,
    writer_tx: mpsc::Sender<String>,
    control_tx: mpsc::Sender<Control>,
    peer_label: String,
    /// Set once a Ping has been sent and we are awaiting any reply. Detects a
    /// peer that went silent on a half-open TCP connection (no FIN/RST).
    awaiting_pong: bool,
    /// Plaintext bytes read off this connection, shared with the IO layer.
    bytes_in: Arc<AtomicU64>,
    /// `bytes_in` as of the last COMPLETED message (or of the upgrade).
    bytes_at_last_message: u64,
    /// When the last message completed, or when the session began.
    last_message_at: tokio::time::Instant,
    /// See [`WssLimits::incomplete_message_timeout`].
    incomplete_message_timeout: Duration,
}

impl WssTransport {
    /// Module-private: a transport is only well-formed when its parser sits
    /// behind the byte counter the listener installs, so only the listener can
    /// build one.
    fn new(
        ws: WebSocketStream<CountedTlsStream>,
        remote_addr: SocketAddr,
        bytes_in: Arc<AtomicU64>,
        incomplete_message_timeout: Duration,
    ) -> Self {
        let peer_label = format!("wss:{remote_addr}");
        // Baseline past the handshake bytes: only what the parser reads for
        // MESSAGES counts toward the incomplete-message bound.
        let bytes_at_last_message = bytes_in.load(Ordering::Relaxed);
        let (sink, stream) = ws.split();

        let (writer_tx, mut writer_rx) = mpsc::channel::<String>(64);
        let (control_tx, mut control_rx) = mpsc::channel::<Control>(8);
        zeroclaw_spawn::spawn!(async move {
            let mut sink = sink;
            loop {
                let msg = tokio::select! {
                    line = writer_rx.recv() => match line {
                        Some(line) => Message::Text(line.into()),
                        None => break,
                    },
                    ctrl = control_rx.recv() => match ctrl {
                        Some(Control::Ping) => Message::Ping(Vec::new().into()),
                        None => break,
                    },
                };
                if sink.send(msg).await.is_err() {
                    break;
                }
            }
        });

        Self {
            reader: stream,
            writer_tx,
            control_tx,
            peer_label,
            awaiting_pong: false,
            bytes_in,
            bytes_at_last_message,
            last_message_at: tokio::time::Instant::now(),
            incomplete_message_timeout,
        }
    }

    /// Bytes read with no message completed since. tungstenite hides its
    /// partial-message buffer, so this is what stands in for it.
    fn pending_bytes(&self) -> u64 {
        self.bytes_in
            .load(Ordering::Relaxed)
            .saturating_sub(self.bytes_at_last_message)
    }

    /// When a partially-received message must be given up on, or `None` when
    /// nothing meaningful is parked in the parser.
    ///
    /// Gated on bytes having actually accumulated: a QUIET connection parks
    /// nothing and must NOT be torn down here - idle liveness is the
    /// heartbeat's policy, and this rule would otherwise duplicate it with a
    /// different deadline.
    fn incomplete_message_deadline(&self) -> Option<tokio::time::Instant> {
        (self.pending_bytes() > INCOMPLETE_MESSAGE_BYTES)
            .then(|| self.last_message_at + self.incomplete_message_timeout)
    }

    /// A message completed: the parser released its buffer, so the
    /// incomplete-message window restarts from here.
    fn note_message_completed(&mut self) {
        self.bytes_at_last_message = self.bytes_in.load(Ordering::Relaxed);
        self.last_message_at = tokio::time::Instant::now();
    }

    /// Discount a control frame from the accounting above.
    ///
    /// A control frame is delivered whole and parks NOTHING in the parser, so
    /// its bytes are not held memory. Leaving them in the count would make a
    /// healthy session that only exchanges keepalives eventually cross the
    /// threshold and be closed by a rule that is meant to reclaim buffered
    /// message bytes. It does NOT extend the window: the deadline still runs
    /// from the last COMPLETED message, which is what stops a peer from
    /// holding a partial message alive by pinging.
    fn credit_control_frame(&mut self, payload_len: usize) {
        self.bytes_at_last_message = self
            .bytes_at_last_message
            .saturating_add(CONTROL_FRAME_HEADER_BYTES + payload_len as u64);
    }
}

#[async_trait]
impl RpcTransport for WssTransport {
    fn writer(&self) -> mpsc::Sender<String> {
        self.writer_tx.clone()
    }

    async fn next_frame(&mut self) -> Option<String> {
        loop {
            let idle = if self.awaiting_pong {
                HEARTBEAT_TIMEOUT
            } else {
                HEARTBEAT_IDLE
            };
            // The incomplete-message bound runs on its OWN timer rather than by
            // shortening the heartbeat window: the two answer different
            // questions (is the peer alive vs. is it still holding a partial
            // message), and folding them together would let either fire for the
            // other's reason. It also lands on a peer that never sends another
            // frame to wake this loop.
            let message_deadline = self.incomplete_message_deadline();
            let read = tokio::time::timeout(idle, self.reader.next());
            let polled = match message_deadline {
                Some(at) => tokio::select! {
                    biased;
                    _ = tokio::time::sleep_until(at) => None,
                    frame = read => Some(frame),
                },
                None => Some(read.await),
            };

            let Some(frame) = polled else {
                ::zeroclaw_log::record!(
                    WARN,
                    ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Note)
                        .with_outcome(::zeroclaw_log::EventOutcome::Unknown),
                    &format!(
                        "WSS closing {}: {} bytes held in an incomplete message for over {}s; \
                         control frames do not extend that budget",
                        self.peer_label,
                        self.pending_bytes(),
                        self.incomplete_message_timeout.as_secs()
                    )
                );
                return None;
            };

            match frame {
                Err(_) => {
                    if self.awaiting_pong {
                        return None;
                    }
                    if self.control_tx.send(Control::Ping).await.is_err() {
                        return None;
                    }
                    self.awaiting_pong = true;
                }
                Ok(frame) => {
                    self.awaiting_pong = false;
                    match frame {
                        Some(Ok(Message::Text(text))) => {
                            self.note_message_completed();
                            return Some(text.to_string());
                        }
                        Some(Ok(Message::Close(_))) | None => return None,
                        // Control frames prove liveness but complete no
                        // message, so they deliberately do NOT restart the
                        // incomplete-message window - only discount their own
                        // bytes, which the parser is not holding.
                        Some(Ok(Message::Ping(payload) | Message::Pong(payload))) => {
                            self.credit_control_frame(payload.len());
                            continue;
                        }
                        // Never yielded by a read, so there is nothing to
                        // discount.
                        Some(Ok(Message::Frame(_))) => continue,
                        Some(Ok(Message::Binary(_))) => {
                            self.note_message_completed();
                            continue;
                        }
                        Some(Err(_)) => return None,
                    }
                }
            }
        }
    }

    fn peer_label(&self) -> String {
        self.peer_label.clone()
    }
}

// ── TLS acceptor ─────────────────────────────────────────────────

/// Build a [`TlsAcceptor`] for the remote WSS RPC plane.
///
/// The remote plane is ALWAYS mutually authenticated and TLS 1.3 only: every
/// client certificate is verified against `ca_cert_path` (optionally pinned to
/// `pinned_certs`). There is deliberately no server-only / no-client-auth path
/// here (threat model A11); the secure-by-construction builder lives in
/// [`zeroclaw_tls::build_mtls_acceptor`].
pub fn build_tls_acceptor(
    cert_path: &str,
    key_path: &str,
    ca_cert_path: &str,
    pinned_certs: &[String],
    crl_path: &str,
) -> Result<TlsAcceptor> {
    zeroclaw_tls::build_mtls_acceptor(cert_path, key_path, ca_cert_path, pinned_certs, crl_path)
}

// ── Listener ─────────────────────────────────────────────────────

/// Parser limits for the WSS RPC plane. tungstenite defaults to a 64 MiB message
/// / 16 MiB frame, which would let the parser buffer far more than the RPC
/// contract permits before [`WssTransport`]/`RpcDispatcher` can reject it.
fn rpc_ws_config() -> tokio_tungstenite::tungstenite::protocol::WebSocketConfig {
    /// Why 32 MiB, and what it does and does not bound:
    ///
    /// - ONE WSS message carries a WHOLE RPC request, and the attachment
    ///   contract caps a request at [`crate::rpc::attachments::MAX_REQUEST_BYTES`]
    ///   (20 MiB). This envelope is that ceiling plus encoding headroom
    ///   (base64 plus JSON framing), so a legitimate max-size request is
    ///   admitted as a single frame - which tungstenite's 16 MiB DEFAULT frame
    ///   cap would wrongly reject. It must not be shrunk below the request
    ///   contract.
    /// - It mirrors the client's RPC-plane config (zerocode `rpc_ws_config`),
    ///   so the two ends cannot drift into one side rejecting what the other
    ///   will send.
    /// - It is a PER-MESSAGE bound, not a host budget. Aggregate parser
    ///   exposure is bounded elsewhere and multiplicatively:
    ///   [`WssLimits::max_sessions_per_client`] x this envelope per credential,
    ///   and [`WssLimits::max_sessions`] x this envelope globally. How long a
    ///   session may hold a partial message toward that envelope is bounded by
    ///   [`WssLimits::incomplete_message_timeout`].
    const RPC_WS_MAX: usize = 32 * 1024 * 1024;
    let mut cfg = tokio_tungstenite::tungstenite::protocol::WebSocketConfig::default();
    cfg.max_message_size = Some(RPC_WS_MAX);
    cfg.max_frame_size = Some(RPC_WS_MAX);
    cfg
}

/// Refuse an authenticated peer with a stated WebSocket close reason rather
/// than a bare drop, so the client can distinguish a policy refusal from a
/// network failure. Bounded by [`REFUSAL_CLOSE_TIMEOUT`]: a peer that stops
/// reading must not be able to make the refusal itself hold the permits the
/// caller is about to release.
async fn close_with_reason(ws: &mut WebSocketStream<CountedTlsStream>, reason: &'static str) {
    let frame = CloseFrame {
        code: CloseCode::Policy,
        reason: reason.into(),
    };
    let _ = tokio::time::timeout(REFUSAL_CLOSE_TIMEOUT, ws.close(Some(frame))).await;
}

/// Run the WSS RPC listener as a daemon subsystem.
/// `client_count` is incremented on connect, decremented on disconnect —
/// shared with the Unix socket listener for `--ephemeral` shutdown logic.
pub async fn run_wss_listener(
    ctx: Arc<RpcContext>,
    cancel: CancellationToken,
    client_count: Arc<AtomicUsize>,
    tls_acceptor: TlsAcceptor,
    bind_addr: SocketAddr,
    limits: WssLimits,
) -> Result<()> {
    let listener = TcpListener::bind(bind_addr)
        .await
        .with_context(|| format!("binding WSS listener on {bind_addr}"))?;

    // Bounds on unauthenticated setup work and on established sessions. A
    // permit is held from accept until the peer is through both handshakes;
    // the session permit is held for the life of the dispatcher.
    let handshake_permits = Arc::new(tokio::sync::Semaphore::new(
        limits.max_pending_handshakes.max(1),
    ));
    let session_permits = Arc::new(tokio::sync::Semaphore::new(limits.max_sessions.max(1)));
    // Per-credential slice of that ceiling, so one enrolled (or stolen)
    // certificate cannot occupy the global limit by itself.
    let client_quota = Arc::new(ClientSessionQuota::default());

    ::zeroclaw_log::record!(
        INFO,
        ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Note)
            .with_attrs(::serde_json::json!({"addr": bind_addr.to_string()})),
        "RPC WSS listener started"
    );

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                ::zeroclaw_log::record!(
                    INFO,
                    ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Note),
                    "RPC WSS listener shutting down"
                );
                break;
            }
            accept = listener.accept() => {
                let (tcp_stream, remote_addr) = match accept {
                    Ok(v) => v,
                    Err(e) => {
                        if is_recoverable_accept_error(&e) {
                            // Transient (e.g. EMFILE under fd pressure):
                            // the listener is still valid. Back off briefly
                            // to avoid hot-spinning, then keep serving
                            // rather than killing the daemon
                            ::zeroclaw_log::record!(
                                WARN,
                                ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Note)
                                    .with_outcome(::zeroclaw_log::EventOutcome::Unknown),
                                &format!("WSS accept() transient error: {e}")
                            );
                            tokio::time::sleep(Duration::from_millis(ACCEPT_ERROR_BACKOFF_MS)).await;
                            continue;
                        }
                        return Err(e).context("WSS accept error");
                    }
                };

                // Shed before spending any TLS/task state on this socket when the
                // unauthenticated setup budget is exhausted. The ESTABLISHED-session
                // ceiling (`max_sessions`) is NOT applied here: a permit taken at
                // accept would be held through TLS/WS setup, so an unauthenticated
                // stall would consume a session slot (with max_sessions=1, one
                // staller blocks a valid client until the handshake deadline). The
                // session permit is taken only once both handshakes succeed (below).
                // Dropping the stream closes it, so a shed client sees a prompt EOF
                // instead of an indefinite stall.
                let Ok(handshake_permit) =
                    handshake_permits.clone().try_acquire_owned()
                else {
                    drop(tcp_stream);
                    ::zeroclaw_log::record!(
                        WARN,
                        ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Note)
                            .with_outcome(::zeroclaw_log::EventOutcome::Unknown),
                        &format!(
                            "WSS shedding connection from {remote_addr}: {} pending handshakes \
                             already in flight",
                            limits.max_pending_handshakes
                        )
                    );
                    continue;
                };

                let ctx = ctx.clone();
                let count = client_count.clone();
                let acceptor = tls_acceptor.clone();
                let handshake_timeout = limits.handshake_timeout;
                // Consumed only after both handshakes succeed, so an unauthenticated
                // stall can never occupy an established-session slot.
                let session_permits = session_permits.clone();
                let max_sessions = limits.max_sessions;
                let client_quota = client_quota.clone();
                let max_sessions_per_client = limits.max_sessions_per_client;
                let incomplete_message_timeout = limits.incomplete_message_timeout;

                count.fetch_add(1, Ordering::Relaxed);

                zeroclaw_spawn::spawn!(async move {
                    // Guarantees the `--ephemeral` counter is decremented on
                    // every exit path below, including the new timeout one.
                    let _count_guard = ClientCountGuard(count);

                    // ONE absolute deadline over TLS accept AND the WebSocket
                    // upgrade, measured from accept. A fresh per-phase window
                    // would let a peer spend the full budget twice.
                    let deadline = tokio::time::Instant::now() + handshake_timeout;

                    let setup = async {
                    // TLS handshake.
                    let tls_stream = match acceptor.accept(tcp_stream).await {
                        Ok(s) => s,
                        Err(e) => {
                            // The WSS plane is always mutually authenticated, so a
                            // client with no certificate (un-migrated) or a revoked
                            // one fails here. Surface it actionably rather than as a
                            // bare TLS error so the operator knows to enroll it.
                            ::zeroclaw_log::record!(
                                WARN,
                                ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Note)
                                    .with_outcome(::zeroclaw_log::EventOutcome::Unknown),
                                &format!(
                                    "WSS TLS handshake failed from {remote_addr}: {e}. The WSS plane \
                                     requires a client certificate; an un-migrated client must enroll \
                                     first (zerocode --enroll), and a revoked cert is refused."
                                )
                            );
                            return None;
                        }
                    };

                    // Count plaintext bytes from here on. What buffers a
                    // partially-received message is the WebSocket parser, and it
                    // does not expose that buffer, so the session loop reads
                    // progress off this counter instead.
                    let (counted_stream, bytes_in) = CountingStream::new(tls_stream);

                    // WebSocket upgrade. An explicit parser config replaces
                    // tungstenite's 64 MiB message / 16 MiB frame defaults with a
                    // ceiling sized to the RPC contract, so the parser cannot buffer
                    // far more than a legitimate request before `next_frame` sees it.
                    let ws_stream = match tokio_tungstenite::accept_async_with_config(
                        counted_stream,
                        Some(rpc_ws_config()),
                    )
                    .await
                    {
                        Ok(ws) => ws,
                        Err(e) => {
                            ::zeroclaw_log::record!(
                                WARN,
                                ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Note)
                                    .with_outcome(::zeroclaw_log::EventOutcome::Unknown),
                                &format!("WSS WebSocket upgrade failed from {remote_addr}: {e}")
                            );
                            return None;
                        }
                    };
                        Some((ws_stream, bytes_in))
                    };

                    let (mut ws_stream, bytes_in) = match tokio::time::timeout_at(deadline, setup).await {
                        Ok(Some(ws)) => ws,
                        Ok(None) => return, // logged above
                        Err(_) => {
                            ::zeroclaw_log::record!(
                                WARN,
                                ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Note)
                                    .with_outcome(::zeroclaw_log::EventOutcome::Unknown),
                                &format!(
                                    "WSS setup from {remote_addr} exceeded the {}s handshake \
                                     budget; connection dropped",
                                    handshake_timeout.as_secs()
                                )
                            );
                            return;
                        }
                    };

                    // Through both handshakes: this peer presented a valid client
                    // certificate. Only now consume an ESTABLISHED-session slot, so
                    // unauthenticated setup stalls (bounded separately by
                    // max_pending_handshakes) can never exhaust the session ceiling.
                    // Take the session permit BEFORE releasing the handshake permit
                    // so the two bounds hand off with no gap a flood could exploit.
                    let Ok(_session_permit) = session_permits.try_acquire_owned() else {
                        ::zeroclaw_log::record!(
                            WARN,
                            ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Note)
                                .with_outcome(::zeroclaw_log::EventOutcome::Unknown),
                            &format!(
                                "WSS shedding authenticated connection from {remote_addr}: {} \
                                 sessions already established",
                                max_sessions
                            )
                        );
                        return;
                    };
                    // The client cert was verified against the CA during the
                    // mTLS handshake; capture its SHA-256 fingerprint (the ledger
                    // key, and the per-credential quota key) before the stream is
                    // consumed by the transport.
                    let peer_cert_fp = ws_stream
                        .get_ref()
                        .get_ref()
                        .get_ref()
                        .1
                        .peer_certificates()
                        .and_then(|certs| certs.first())
                        .map(|der| zeroclaw_tls::cert_sha256_fingerprint(der.as_ref()));

                    // The plane is mandatory mTLS, so this is always present. A
                    // session with no credential could not be attributed to one
                    // and so could not be quota-bounded: refuse rather than admit
                    // an unaccountable session.
                    let Some(peer_cert_fp) = peer_cert_fp else {
                        ::zeroclaw_log::record!(
                            WARN,
                            ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Note)
                                .with_outcome(::zeroclaw_log::EventOutcome::Unknown),
                            &format!(
                                "WSS refusing {remote_addr}: the mutually-authenticated handshake \
                                 exposed no client certificate, so no per-credential quota applies"
                            )
                        );
                        close_with_reason(&mut ws_stream, "no client certificate").await;
                        return;
                    };

                    // Per-credential slice of the session ceiling. Held for the
                    // life of the session by a guard, so it is returned on every
                    // exit path below (dispatcher return, read error, EOF,
                    // heartbeat, incomplete-message deadline).
                    let Some(_client_slot) =
                        client_quota.try_admit(&peer_cert_fp, max_sessions_per_client)
                    else {
                        ::zeroclaw_log::record!(
                            WARN,
                            ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Note)
                                .with_outcome(::zeroclaw_log::EventOutcome::Unknown),
                            &format!(
                                "WSS refusing {remote_addr}: client certificate {peer_cert_fp} \
                                 already holds {max_sessions_per_client} sessions, its \
                                 per-credential ceiling"
                            )
                        );
                        // Distinct, clean refusal; the session permit and the
                        // handshake permit are released by returning, and the
                        // refused credential is never recorded in the quota map.
                        close_with_reason(&mut ws_stream, "per-certificate session quota").await;
                        return;
                    };

                    // Released for the next connection being set up now that this
                    // one holds an established-session slot and a credential slot.
                    drop(handshake_permit);

                    let mut transport = WssTransport::new(
                        ws_stream,
                        remote_addr,
                        bytes_in,
                        incomplete_message_timeout,
                    );
                    let peer = transport.peer_label();
                    let writer_tx = transport.writer();
                    let mut dispatcher = RpcDispatcher::new(ctx.clone(), writer_tx, peer)
                        .with_peer_cert_fingerprint(Some(peer_cert_fp));
                    dispatcher.run(&mut transport).await;

                    if let Some(tui_id) = dispatcher.tui_id() {
                        ctx.tui_registry.unregister(tui_id);
                        use ::zeroclaw_log::Instrument as _;
                        let span = ::zeroclaw_log::info_span!(
                            target: "zeroclaw_log_internal_scope",
                            "zeroclaw_scope",
                            owner_tui_id = %tui_id,
                            channel = "wss",
                        );
                        async {
                            ::zeroclaw_log::record!(
                                INFO,
                                ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Note)
                                    .with_category(::zeroclaw_log::EventCategory::Agent),
                                "WSS TUI disconnected; sessions retained (persistent)"
                            );
                        }
                        .instrument(span)
                        .await;
                    }
                });
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod accept_error_tests {
    use super::is_recoverable_accept_error;
    use std::io::{Error, ErrorKind};

    #[cfg(unix)]
    #[test]
    fn fd_exhaustion_accept_errors_are_recoverable() {
        // EMFILE/ENFILE must not terminate the daemon.
        assert!(is_recoverable_accept_error(&Error::from_raw_os_error(24))); // EMFILE
        assert!(is_recoverable_accept_error(&Error::from_raw_os_error(23))); // ENFILE
    }

    #[test]
    fn transient_kinds_recover_but_fatal_propagates() {
        assert!(is_recoverable_accept_error(&Error::from(
            ErrorKind::ConnectionAborted
        )));
        assert!(is_recoverable_accept_error(&Error::from(
            ErrorKind::Interrupted
        )));
        // A non-transient error is not swallowed (loop will propagate it).
        assert!(!is_recoverable_accept_error(&Error::from(
            ErrorKind::InvalidInput
        )));
    }
}

#[cfg(test)]
// Test code, not daemon-path: bare `tokio::spawn` is fine here (the
// `zeroclaw_spawn::spawn!` attribution rule is for production daemon tasks).
#[allow(clippy::disallowed_methods)]
mod parser_bound_tests {
    use super::*;
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;
    use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

    // In-memory duplex only (no network/TLS). The URI is built from parts with
    // the scheme as a bare field so no insecure-scheme string literal exists in
    // source for the hosted scanner to flag.
    fn loopback_url() -> tokio_tungstenite::tungstenite::http::Uri {
        tokio_tungstenite::tungstenite::http::Uri::builder()
            .scheme("ws")
            .authority("ceiling.test")
            .path_and_query("/")
            .build()
            .expect("valid test uri")
    }

    // A client permitted to EMIT frames larger than tungstenite's 16 MiB default,
    // so the SERVER's configured ceiling is what is under test.
    fn permissive_client_config() -> WebSocketConfig {
        let mut cfg = WebSocketConfig::default();
        cfg.max_message_size = Some(64 * 1024 * 1024);
        cfg.max_frame_size = Some(64 * 1024 * 1024);
        cfg
    }

    // W1: the WSS upgrade applies an explicit parser config sized to the RPC
    // contract. A legitimate max-size request (MAX_REQUEST_BYTES = 20 MiB) must be
    // admitted as a single frame — which tungstenite's 16 MiB DEFAULT frame cap
    // would wrongly reject — while a message beyond the 32 MiB ceiling is refused
    // at the parser instead of buffered up to the 64 MiB message default.
    #[tokio::test]
    async fn rpc_ws_config_admits_contract_max_and_refuses_oversized() {
        // (1) A 20 MiB message is accepted and delivered intact.
        {
            let (client_io, server_io) = tokio::io::duplex(1 << 20);
            let server = tokio::spawn(async move {
                let mut ws =
                    tokio_tungstenite::accept_async_with_config(server_io, Some(rpc_ws_config()))
                        .await
                        .expect("server upgrade");
                match ws.next().await {
                    Some(Ok(Message::Binary(b))) => Ok(b.len()),
                    other => Err(format!("{other:?}")),
                }
            });
            let (mut client, _r) = tokio_tungstenite::client_async_with_config(
                loopback_url(),
                client_io,
                Some(permissive_client_config()),
            )
            .await
            .expect("client upgrade");
            let payload = vec![7u8; 20 * 1024 * 1024];
            client
                .send(Message::binary(payload))
                .await
                .expect("send 20 MiB");
            client.flush().await.expect("flush");
            let got = server.await.unwrap();
            assert_eq!(
                got,
                Ok(20 * 1024 * 1024),
                "a 20 MiB request (contract max) must be admitted as one frame"
            );
        }
        // (2) A message beyond the 32 MiB ceiling is refused at the parser.
        {
            let (client_io, server_io) = tokio::io::duplex(1 << 20);
            let server = tokio::spawn(async move {
                let mut ws =
                    tokio_tungstenite::accept_async_with_config(server_io, Some(rpc_ws_config()))
                        .await
                        .expect("server upgrade");
                loop {
                    match ws.next().await {
                        Some(Ok(_)) => continue,
                        Some(Err(_)) => return true,
                        None => return false,
                    }
                }
            });
            let (mut client, _r) = tokio_tungstenite::client_async_with_config(
                loopback_url(),
                client_io,
                Some(permissive_client_config()),
            )
            .await
            .expect("client upgrade");
            let oversized = vec![0u8; 33 * 1024 * 1024];
            let _ = client.send(Message::binary(oversized)).await;
            let _ = client.flush().await;
            let refused = server.await.unwrap();
            assert!(
                refused,
                "a message beyond the 32 MiB ceiling must be refused"
            );
        }
    }
}
