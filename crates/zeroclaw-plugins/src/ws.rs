//! Host-owned outbound WebSocket client for channel plugins (`ws-client`).
//!
//! `zeroclaw-plugins` is otherwise a no-network sandbox crate (see the invariant
//! on [`crate::component::PluginState`]): the WASI context has no preopens and no
//! sockets. This module is the one deliberate, permission-gated exception.
//! Channel plugins whose platform needs a persistent duplex socket cannot open
//! one inside the sandbox, so the host owns the socket and hands the plugin an
//! opaque handle. The plugin drives the application protocol while the host
//! enforces destination, handshake, framing, queue, and lifecycle boundaries.

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio::sync::Notify;
use tokio::task::AbortHandle;
use tokio_tungstenite::client_async_tls_with_config;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::handshake::client::Request;
use tokio_tungstenite::tungstenite::http::{HeaderName, HeaderValue};
use tokio_tungstenite::tungstenite::protocol::{CloseFrame, WebSocketConfig};

use crate::component::PluginState;
use crate::component::bindings;

/// Maximum number of text frames retained in either per-connection queue.
const INBOUND_FRAME_CAP: usize = 1024;
const OUTBOUND_FRAME_CAP: usize = 256;

/// Per-message and per-frame transport ceilings. A message may be fragmented,
/// but neither an assembled message nor an individual frame can exceed these.
const MAX_MESSAGE_BYTES: usize = 1024 * 1024;
const MAX_FRAME_BYTES: usize = 256 * 1024;

/// Aggregate payload ceilings for host-owned queues. Queue byte use is derived
/// from the payloads in the queue; there is no counter that can drift.
const INBOUND_QUEUE_BYTES: usize = 4 * MAX_MESSAGE_BYTES;
const OUTBOUND_QUEUE_BYTES: usize = 2 * MAX_MESSAGE_BYTES;

/// Bounds on guest-controlled upgrade headers, checked before DNS or dialing.
const MAX_HEADER_COUNT: usize = 32;
const MAX_HEADER_BYTES: usize = 16 * 1024;

/// Max live WebSocket connections per plugin store. The connection map is the
/// canonical live-resource source, so no second counter is maintained.
const MAX_CONNS: usize = 16;

/// Bound on resolution, TCP/TLS setup, and the WebSocket handshake.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// A host policy decision that can widen the secure WebSocket default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WsEgressException {
    /// Permit an unencrypted `ws://` destination.
    Plaintext,
    /// Permit a loopback, private, or otherwise non-global destination.
    PrivateNetwork,
}

/// Live host-side resolver for operator egress policy. The callback receives
/// the normalized destination host and the exception being requested. Keeping
/// the resolver, rather than copied config values, lets the embedding runtime
/// consult its canonical configuration at each dial.
pub type WsEgressPolicy = Arc<dyn Fn(&str, WsEgressException) -> bool + Send + Sync>;

/// Secure default: public destinations over `wss://` only.
#[must_use]
pub fn deny_ws_egress_exceptions() -> WsEgressPolicy {
    Arc::new(|_, _| false)
}

/// A single event surfaced to the plugin by [`WsRegistry::receive`].
pub enum WsPoll {
    /// A received text frame.
    Text(String),
    /// Nothing queued and the connection is still live.
    Idle,
    /// The connection ended and all earlier buffered frames were drained. This
    /// event consumes the handle.
    Closed(String),
}

#[derive(Default)]
struct TextQueue {
    frames: VecDeque<String>,
}

impl TextQueue {
    fn len(&self) -> usize {
        self.frames.len()
    }

    fn bytes(&self) -> usize {
        self.frames.iter().map(String::len).sum()
    }

    fn can_push(&self, len: usize, frame_cap: usize, byte_cap: usize) -> bool {
        self.frames.len() < frame_cap
            && self
                .bytes()
                .checked_add(len)
                .is_some_and(|total| total <= byte_cap)
    }

    fn try_push(
        &mut self,
        text: String,
        frame_cap: usize,
        byte_cap: usize,
        label: &str,
    ) -> Result<(), String> {
        if self.frames.len() >= frame_cap {
            return Err(format!("websocket {label} frame buffer full"));
        }
        if !self.can_push(text.len(), frame_cap, byte_cap) {
            return Err(format!(
                "websocket {label} byte budget exceeded ({byte_cap} bytes)"
            ));
        }
        self.frames.push_back(text);
        Ok(())
    }

    fn pop(&mut self) -> Option<String> {
        self.frames.pop_front()
    }
}

/// One live host-owned connection and the handles needed to stop its pumps.
struct WsConn {
    outbound: Arc<Mutex<TextQueue>>,
    outbound_ready: Arc<Notify>,
    inbound: Arc<Mutex<TextQueue>>,
    inbound_space: Arc<Notify>,
    terminal: Arc<Mutex<Option<String>>>,
    reader: AbortHandle,
    writer: AbortHandle,
}

impl Drop for WsConn {
    fn drop(&mut self) {
        self.reader.abort();
        self.writer.abort();
    }
}

/// Per-plugin table of live host-owned WebSocket connections.
pub struct WsRegistry {
    conns: HashMap<u64, WsConn>,
    next: u64,
    egress_policy: WsEgressPolicy,
}

impl Default for WsRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl WsRegistry {
    /// Build a registry with the secure public-`wss` policy.
    pub fn new() -> Self {
        Self::with_egress_policy(deny_ws_egress_exceptions())
    }

    /// Build a registry whose exception decisions are resolved by host policy.
    pub fn with_egress_policy(egress_policy: WsEgressPolicy) -> Self {
        Self {
            conns: HashMap::new(),
            next: 1,
            egress_policy,
        }
    }

    /// Dial `url`, spawn bounded read/write pumps, and register the connection.
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

        let policy = Arc::clone(&self.egress_policy);
        let url_for_timeout = url.clone();
        let (stream, _response) = tokio::time::timeout(connect_timeout, async move {
            let target = resolve_target_with(url, headers, &policy, resolve_host).await?;
            let config = websocket_config();
            let mut last_error = None;
            for addr in target.addrs {
                let tcp = match TcpStream::connect(addr).await {
                    Ok(tcp) => tcp,
                    Err(error) => {
                        last_error = Some(format!("tcp connect to {addr} failed: {error}"));
                        continue;
                    }
                };
                let _ = tcp.set_nodelay(true);
                match client_async_tls_with_config(target.request.clone(), tcp, Some(config), None)
                    .await
                {
                    Ok(connected) => return Ok(connected),
                    Err(error) => {
                        last_error =
                            Some(format!("websocket handshake via {addr} failed: {error}"));
                    }
                }
            }
            Err(last_error.unwrap_or_else(|| "websocket destination resolved no addresses".into()))
        })
        .await
        .map_err(|_| {
            format!("websocket connect to {url_for_timeout:?} timed out after {connect_timeout:?}")
        })??;
        let (mut write, mut read) = stream.split();

        let outbound = Arc::new(Mutex::new(TextQueue::default()));
        let outbound_ready = Arc::new(Notify::new());
        let inbound = Arc::new(Mutex::new(TextQueue::default()));
        let inbound_space = Arc::new(Notify::new());
        let terminal = Arc::new(Mutex::new(None));

        let outbound_w = Arc::clone(&outbound);
        let outbound_ready_w = Arc::clone(&outbound_ready);
        let terminal_w = Arc::clone(&terminal);
        let writer = zeroclaw_spawn::spawn!(async move {
            loop {
                let notified = outbound_ready_w.notified();
                let next = lock(&outbound_w).pop();
                if let Some(text) = next {
                    if let Err(error) = write.send(Message::Text(text.into())).await {
                        mark_dead(&terminal_w, format!("websocket write error: {error}"));
                        break;
                    }
                    continue;
                }
                if lock(&terminal_w).is_some() {
                    break;
                }
                notified.await;
            }
            let _ = write.close().await;
        });

        let inbound_r = Arc::clone(&inbound);
        let inbound_space_r = Arc::clone(&inbound_space);
        let terminal_r = Arc::clone(&terminal);
        let outbound_ready_r = Arc::clone(&outbound_ready);
        let reader = zeroclaw_spawn::spawn!(async move {
            loop {
                match read.next().await {
                    Some(Ok(Message::Text(text))) => {
                        let text = text.to_string();
                        loop {
                            let notified = inbound_space_r.notified();
                            let pushed = {
                                let mut queue = lock(&inbound_r);
                                if queue.can_push(
                                    text.len(),
                                    INBOUND_FRAME_CAP,
                                    INBOUND_QUEUE_BYTES,
                                ) {
                                    queue
                                        .try_push(
                                            text.clone(),
                                            INBOUND_FRAME_CAP,
                                            INBOUND_QUEUE_BYTES,
                                            "inbound",
                                        )
                                        .is_ok()
                                } else {
                                    false
                                }
                            };
                            if pushed {
                                break;
                            }
                            notified.await;
                        }
                    }
                    Some(Ok(
                        Message::Binary(_)
                        | Message::Ping(_)
                        | Message::Pong(_)
                        | Message::Frame(_),
                    )) => {}
                    Some(Ok(Message::Close(frame))) => {
                        mark_dead(&terminal_r, format_close_reason(frame));
                        outbound_ready_r.notify_waiters();
                        break;
                    }
                    Some(Err(error)) => {
                        mark_dead(&terminal_r, format!("websocket error: {error}"));
                        outbound_ready_r.notify_waiters();
                        break;
                    }
                    None => {
                        mark_dead(&terminal_r, "websocket stream ended".to_string());
                        outbound_ready_r.notify_waiters();
                        break;
                    }
                }
            }
        });

        let handle = self.next;
        self.next = self.next.wrapping_add(1).max(1);
        self.conns.insert(
            handle,
            WsConn {
                outbound,
                outbound_ready,
                inbound,
                inbound_space,
                terminal,
                reader: reader.abort_handle(),
                writer: writer.abort_handle(),
            },
        );
        Ok(handle)
    }

    /// Queue a text frame without blocking the guest call.
    pub fn send_text(&self, handle: u64, text: String) -> Result<(), String> {
        validate_message_size(text.len(), "outbound")?;
        let conn = self.conn(handle)?;
        if lock(&conn.terminal).is_some() {
            return Err("websocket connection is closed".to_string());
        }
        lock(&conn.outbound).try_push(
            text,
            OUTBOUND_FRAME_CAP,
            OUTBOUND_QUEUE_BYTES,
            "outbound",
        )?;
        conn.outbound_ready.notify_one();
        Ok(())
    }

    /// Pop a buffered frame. The terminal event removes the connection before
    /// it is returned, aborting both pumps and releasing registry capacity.
    pub fn receive(&mut self, handle: u64) -> Result<WsPoll, String> {
        let terminal_reason = {
            let conn = self.conn(handle)?;
            if let Some(text) = lock(&conn.inbound).pop() {
                conn.inbound_space.notify_one();
                return Ok(WsPoll::Text(text));
            }
            lock(&conn.terminal).clone()
        };

        match terminal_reason {
            Some(reason) => {
                self.conns.remove(&handle);
                Ok(WsPoll::Closed(reason))
            }
            None => Ok(WsPoll::Idle),
        }
    }

    /// Number of text frames currently buffered for the connection.
    pub fn pending(&self, handle: u64) -> Result<u32, String> {
        Ok(lock(&self.conn(handle)?.inbound).len() as u32)
    }

    /// Drop the connection. Idempotent for unknown or already-retired handles.
    pub fn close(&mut self, handle: u64) {
        self.conns.remove(&handle);
    }

    fn conn(&self, handle: u64) -> Result<&WsConn, String> {
        self.conns
            .get(&handle)
            .ok_or_else(|| format!("unknown websocket handle {handle}"))
    }
}

struct ResolvedTarget {
    request: Request,
    addrs: Vec<SocketAddr>,
}

async fn resolve_target_with<R, F>(
    url: String,
    headers: Vec<(String, String)>,
    policy: &WsEgressPolicy,
    resolver: R,
) -> Result<ResolvedTarget, String>
where
    R: FnOnce(String, u16) -> F,
    F: Future<Output = Result<Vec<SocketAddr>, String>>,
{
    validate_headers(&headers)?;
    let mut request = url
        .as_str()
        .into_client_request()
        .map_err(|error| format!("invalid websocket url: {error}"))?;
    let scheme = request
        .uri()
        .scheme_str()
        .ok_or_else(|| "websocket url has no scheme".to_string())?;
    if scheme != "ws" && scheme != "wss" {
        return Err(format!("unsupported websocket scheme {scheme:?}"));
    }
    let authority = request
        .uri()
        .authority()
        .ok_or_else(|| "websocket url has no authority".to_string())?;
    if authority.as_str().contains('@') {
        return Err("websocket url userinfo is not allowed".to_string());
    }
    let host = request
        .uri()
        .host()
        .ok_or_else(|| "websocket url has no host".to_string())?
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase();
    let port = request
        .uri()
        .port_u16()
        .or_else(|| (scheme == "wss").then_some(443))
        .or_else(|| (scheme == "ws").then_some(80))
        .ok_or_else(|| "websocket url has no valid port".to_string())?;

    if scheme == "ws" && !(policy)(&host, WsEgressException::Plaintext) {
        return Err("plaintext websocket destinations are blocked; use wss://".to_string());
    }
    if zeroclaw_infra::net_guard::is_private_or_local_host(&host)
        && !(policy)(&host, WsEgressException::PrivateNetwork)
    {
        return Err(format!(
            "websocket destination {host:?} is private or non-global"
        ));
    }

    let mut addrs = resolver(host.clone(), port).await?;
    addrs.sort_unstable();
    addrs.dedup();
    if addrs.is_empty() {
        return Err(format!(
            "websocket destination {host:?} resolved no addresses"
        ));
    }
    for addr in &addrs {
        let ip = addr.ip();
        if ip_is_non_global(ip) && !(policy)(&host, WsEgressException::PrivateNetwork) {
            return Err(format!(
                "websocket destination {host:?} resolved to non-global address {ip}"
            ));
        }
    }

    let req_headers = request.headers_mut();
    for (name, value) in headers {
        let name = HeaderName::from_bytes(name.as_bytes())
            .map_err(|error| format!("invalid websocket header name: {error}"))?;
        let value = HeaderValue::from_str(&value)
            .map_err(|error| format!("invalid websocket header value: {error}"))?;
        req_headers.append(name, value);
    }
    Ok(ResolvedTarget { request, addrs })
}

async fn resolve_host(host: String, port: u16) -> Result<Vec<SocketAddr>, String> {
    tokio::net::lookup_host((host.as_str(), port))
        .await
        .map(|resolved| resolved.collect())
        .map_err(|error| format!("failed to resolve websocket host {host:?}: {error}"))
}

fn validate_headers(headers: &[(String, String)]) -> Result<(), String> {
    if headers.len() > MAX_HEADER_COUNT {
        return Err(format!(
            "websocket upgrade header count exceeds {MAX_HEADER_COUNT}"
        ));
    }
    let total = headers.iter().try_fold(0usize, |sum, (name, value)| {
        sum.checked_add(name.len())?.checked_add(value.len())
    });
    if total.is_none_or(|bytes| bytes > MAX_HEADER_BYTES) {
        return Err(format!(
            "websocket upgrade headers exceed {MAX_HEADER_BYTES} bytes"
        ));
    }
    Ok(())
}

fn validate_message_size(len: usize, direction: &str) -> Result<(), String> {
    if len > MAX_MESSAGE_BYTES {
        return Err(format!(
            "websocket {direction} message exceeds {MAX_MESSAGE_BYTES} bytes"
        ));
    }
    Ok(())
}

fn websocket_config() -> WebSocketConfig {
    WebSocketConfig::default()
        .read_buffer_size(16 * 1024)
        .write_buffer_size(16 * 1024)
        .max_write_buffer_size(OUTBOUND_QUEUE_BYTES)
        .max_message_size(Some(MAX_MESSAGE_BYTES))
        .max_frame_size(Some(MAX_FRAME_BYTES))
}

fn ip_is_non_global(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => zeroclaw_infra::net_guard::is_non_global_v4(ip),
        IpAddr::V6(ip) => zeroclaw_infra::net_guard::is_non_global_v6(ip),
    }
}

fn mark_dead(terminal: &Mutex<Option<String>>, message: String) {
    let mut terminal = lock(terminal);
    if terminal.is_none() {
        *terminal = Some(message);
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|error| error.into_inner())
}

fn format_close_reason(frame: Option<CloseFrame>) -> String {
    match frame {
        Some(frame) => {
            let code = u16::from(frame.code);
            if frame.reason.is_empty() {
                code.to_string()
            } else {
                format!("{code}: {}", frame.reason)
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
            WsPoll::Text(text) => WsEvent::Text(text),
            WsPoll::Idle => WsEvent::Idle,
            WsPoll::Closed(reason) => WsEvent::Closed(reason),
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
    use super::*;
    use std::net::Ipv4Addr;
    use std::sync::Arc;
    use tokio::net::TcpListener;
    use tokio_tungstenite::tungstenite::protocol::frame::Frame;
    use tokio_tungstenite::tungstenite::protocol::frame::coding::{CloseCode, Data, OpCode};

    fn loopback_policy() -> WsEgressPolicy {
        Arc::new(|host, _| host == "127.0.0.1" || host == "localhost")
    }

    async fn held_server() -> SocketAddr {
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
        addr
    }

    async fn terminal_reason(registry: &mut WsRegistry, handle: u64) -> String {
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                match registry.receive(handle).expect("known live handle") {
                    WsPoll::Closed(reason) => break reason,
                    WsPoll::Idle => tokio::time::sleep(Duration::from_millis(5)).await,
                    WsPoll::Text(_) => {}
                }
            }
        })
        .await
        .expect("terminal event reaches registry")
    }

    #[test]
    fn close_reason_surfaces_the_numeric_code() {
        assert_eq!(
            format_close_reason(Some(CloseFrame {
                code: CloseCode::from(4014),
                reason: "Disallowed intent(s).".into(),
            })),
            "4014: Disallowed intent(s)."
        );
        assert_eq!(
            format_close_reason(Some(CloseFrame {
                code: CloseCode::from(1000),
                reason: "".into(),
            })),
            "1000"
        );
        assert_eq!(format_close_reason(None), "server closed the connection");
    }

    #[tokio::test]
    async fn secure_default_rejects_plaintext_and_non_global_destinations() {
        let policy = deny_ws_egress_exceptions();
        for url in [
            "ws://example.com/socket",
            "wss://127.0.0.1/socket",
            "wss://10.0.0.1/socket",
            "wss://169.254.169.254/latest/meta-data",
            "wss://[::1]/socket",
            "wss://[fe80::1]/socket",
            "wss://[fd00:ec2::254]/socket",
        ] {
            let result =
                resolve_target_with(url.into(), Vec::new(), &policy, |_, port| async move {
                    Ok(vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)])
                })
                .await;
            assert!(result.is_err(), "{url} must be denied");
        }
    }

    #[tokio::test]
    async fn secure_default_accepts_public_wss_destination() {
        let policy = deny_ws_egress_exceptions();
        let expected = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 443);
        let target = resolve_target_with(
            "wss://public.example/socket".into(),
            Vec::new(),
            &policy,
            |host, port| async move {
                assert_eq!(host, "public.example");
                assert_eq!(port, 443);
                Ok(vec![expected])
            },
        )
        .await
        .expect("public wss destination passes policy");

        assert_eq!(target.addrs, vec![expected]);
        assert_eq!(target.request.uri().host(), Some("public.example"));
    }

    #[tokio::test]
    async fn rejects_unsupported_schemes_and_url_userinfo() {
        let policy = deny_ws_egress_exceptions();
        for url in [
            "http://example.com/socket",
            "file:///tmp/socket",
            "wss://user:secret@example.com/socket",
        ] {
            assert!(
                resolve_target_with(url.into(), Vec::new(), &policy, |_, port| async move {
                    Ok(vec![SocketAddr::new(
                        IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
                        port,
                    )])
                })
                .await
                .is_err(),
                "{url} must be denied"
            );
        }
    }

    #[tokio::test]
    async fn rejects_dns_rebinding_to_private_or_metadata_addresses() {
        let policy = deny_ws_egress_exceptions();
        for ip in [
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)),
            IpAddr::V6("fe80::1".parse().expect("link-local v6")),
            IpAddr::V6("fd00:ec2::254".parse().expect("metadata v6")),
        ] {
            let result = resolve_target_with(
                "wss://public.example/socket".into(),
                Vec::new(),
                &policy,
                |_, port| async move { Ok(vec![SocketAddr::new(ip, port)]) },
            )
            .await;
            assert!(result.is_err(), "resolved {ip} must be denied");
        }
    }

    #[tokio::test]
    async fn rejects_a_mixed_public_private_resolution_set() {
        let policy = deny_ws_egress_exceptions();
        let result = resolve_target_with(
            "wss://rebinding.example/socket".into(),
            Vec::new(),
            &policy,
            |_, port| async move {
                Ok(vec![
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), port),
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
                ])
            },
        )
        .await;
        assert!(result.is_err(), "every resolved address must pass policy");
    }

    #[test]
    fn header_count_and_total_bytes_are_bounded() {
        let too_many = (0..=MAX_HEADER_COUNT)
            .map(|index| (format!("x-{index}"), "v".to_string()))
            .collect::<Vec<_>>();
        assert!(validate_headers(&too_many).unwrap_err().contains("count"));

        let too_large = vec![("x".into(), "a".repeat(MAX_HEADER_BYTES))];
        assert!(validate_headers(&too_large).unwrap_err().contains("bytes"));

        let exact = vec![("x".into(), "a".repeat(MAX_HEADER_BYTES - 1))];
        validate_headers(&exact).expect("exact header-byte boundary is accepted");
    }

    #[test]
    fn message_and_queue_byte_boundaries_reject_one_byte_over() {
        validate_message_size(MAX_MESSAGE_BYTES, "outbound").expect("exact message limit");
        assert!(validate_message_size(MAX_MESSAGE_BYTES + 1, "outbound").is_err());

        let mut outbound = TextQueue::default();
        outbound
            .try_push(
                "a".repeat(MAX_MESSAGE_BYTES),
                OUTBOUND_FRAME_CAP,
                OUTBOUND_QUEUE_BYTES,
                "outbound",
            )
            .unwrap();
        outbound
            .try_push(
                "b".repeat(MAX_MESSAGE_BYTES),
                OUTBOUND_FRAME_CAP,
                OUTBOUND_QUEUE_BYTES,
                "outbound",
            )
            .unwrap();
        assert!(
            outbound
                .try_push(
                    "x".to_string(),
                    OUTBOUND_FRAME_CAP,
                    OUTBOUND_QUEUE_BYTES,
                    "outbound",
                )
                .is_err()
        );

        let mut inbound = TextQueue::default();
        for _ in 0..(INBOUND_QUEUE_BYTES / MAX_MESSAGE_BYTES) {
            inbound
                .try_push(
                    "a".repeat(MAX_MESSAGE_BYTES),
                    INBOUND_FRAME_CAP,
                    INBOUND_QUEUE_BYTES,
                    "inbound",
                )
                .unwrap();
        }
        assert!(
            inbound
                .try_push(
                    "x".to_string(),
                    INBOUND_FRAME_CAP,
                    INBOUND_QUEUE_BYTES,
                    "inbound",
                )
                .is_err()
        );
    }

    #[tokio::test]
    async fn outbound_message_one_byte_over_limit_is_rejected_by_send() {
        let addr = held_server().await;
        let mut registry = WsRegistry::with_egress_policy(loopback_policy());
        let handle = registry
            .connect(format!("ws://{addr}"), Vec::new())
            .await
            .expect("connect outbound-limit client");

        registry
            .send_text(handle, "a".repeat(MAX_MESSAGE_BYTES))
            .expect("exact outbound message boundary is accepted");
        let error = registry
            .send_text(handle, "a".repeat(MAX_MESSAGE_BYTES + 1))
            .expect_err("one byte over the outbound message boundary is rejected");
        assert!(
            error.contains("message exceeds"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn transport_config_has_explicit_message_and_frame_limits() {
        let config = websocket_config();
        assert_eq!(config.max_message_size, Some(MAX_MESSAGE_BYTES));
        assert_eq!(config.max_frame_size, Some(MAX_FRAME_BYTES));
        assert_eq!(config.max_write_buffer_size, OUTBOUND_QUEUE_BYTES);
    }

    #[tokio::test]
    async fn inbound_frame_one_byte_over_limit_is_rejected() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind oversized-frame server");
        let addr = listener.local_addr().expect("oversized-frame address");
        zeroclaw_spawn::spawn!(async move {
            let (tcp, _) = listener.accept().await.expect("accept frame client");
            let mut websocket = tokio_tungstenite::accept_async(tcp)
                .await
                .expect("upgrade frame client");
            let frame = Frame::message(
                vec![b'a'; MAX_FRAME_BYTES + 1],
                OpCode::Data(Data::Text),
                true,
            );
            let _ = websocket.send(Message::Frame(frame)).await;
        });

        let mut registry = WsRegistry::with_egress_policy(loopback_policy());
        let handle = registry
            .connect(format!("ws://{addr}"), Vec::new())
            .await
            .expect("connect oversized-frame client");
        let reason = terminal_reason(&mut registry, handle).await;
        assert!(
            reason.contains(&format!("{} > {MAX_FRAME_BYTES}", MAX_FRAME_BYTES + 1)),
            "unexpected reason: {reason}"
        );
    }

    #[tokio::test]
    async fn fragmented_message_one_byte_over_limit_is_rejected() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind oversized-message server");
        let addr = listener.local_addr().expect("oversized-message address");
        zeroclaw_spawn::spawn!(async move {
            let (tcp, _) = listener.accept().await.expect("accept message client");
            let mut websocket = tokio_tungstenite::accept_async(tcp)
                .await
                .expect("upgrade message client");
            let first =
                Frame::message(vec![b'a'; MAX_FRAME_BYTES], OpCode::Data(Data::Text), false);
            let _ = websocket.send(Message::Frame(first)).await;
            for _ in 0..3 {
                let continuation = Frame::message(
                    vec![b'a'; MAX_FRAME_BYTES],
                    OpCode::Data(Data::Continue),
                    false,
                );
                let _ = websocket.send(Message::Frame(continuation)).await;
            }
            let last = Frame::message(vec![b'a'], OpCode::Data(Data::Continue), true);
            let _ = websocket.send(Message::Frame(last)).await;
        });

        let mut registry = WsRegistry::with_egress_policy(loopback_policy());
        let handle = registry
            .connect(format!("ws://{addr}"), Vec::new())
            .await
            .expect("connect oversized-message client");
        let reason = terminal_reason(&mut registry, handle).await;
        assert!(
            reason.contains(&format!("{} > {MAX_MESSAGE_BYTES}", MAX_MESSAGE_BYTES + 1)),
            "unexpected reason: {reason}"
        );
    }

    #[tokio::test]
    async fn connect_fails_at_cap_and_close_frees_capacity() {
        let addr = held_server().await;
        let mut registry = WsRegistry::with_egress_policy(loopback_policy());
        for _ in 0..MAX_CONNS {
            registry
                .connect(format!("ws://{addr}"), Vec::new())
                .await
                .expect("connection below the cap succeeds");
        }
        let error = registry
            .connect(format!("ws://{addr}"), Vec::new())
            .await
            .expect_err("connection above the cap fails");
        assert!(error.contains("connection limit"));
        registry.close(1);
        registry
            .connect(format!("ws://{addr}"), Vec::new())
            .await
            .expect("ws-close returns capacity");
    }

    #[tokio::test]
    async fn terminal_event_retires_handles_across_reconnect_cycles() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind closing websocket server");
        let addr = listener.local_addr().expect("closing server address");
        zeroclaw_spawn::spawn!(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                if let Ok(mut websocket) = tokio_tungstenite::accept_async(tcp).await {
                    let _ = websocket.send(Message::Text("buffered".into())).await;
                    let _ = websocket.close(None).await;
                }
            }
        });

        let mut registry = WsRegistry::with_egress_policy(loopback_policy());
        for _ in 0..(MAX_CONNS + 8) {
            let handle = registry
                .connect(format!("ws://{addr}"), Vec::new())
                .await
                .expect("reconnect succeeds after prior terminal event");
            let (buffered, terminal) = tokio::time::timeout(Duration::from_secs(2), async {
                let mut buffered = None;
                loop {
                    match registry.receive(handle).expect("known live handle") {
                        WsPoll::Text(text) => {
                            assert!(
                                buffered.replace(text).is_none(),
                                "one buffered frame expected"
                            );
                        }
                        WsPoll::Closed(reason) => break (buffered, reason),
                        WsPoll::Idle => tokio::time::sleep(Duration::from_millis(5)).await,
                    }
                }
            })
            .await
            .expect("buffered frame and terminal event reach registry");
            assert_eq!(buffered.as_deref(), Some("buffered"));
            assert!(!terminal.is_empty());
            assert_eq!(
                registry.receive(handle).map(|_| ()).unwrap_err(),
                format!("unknown websocket handle {handle}")
            );
            registry.close(handle);
        }
        assert!(registry.conns.is_empty());
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

        let mut registry = WsRegistry::with_egress_policy(loopback_policy());
        let error = registry
            .connect_with_timeout(
                format!("ws://{addr}"),
                Vec::new(),
                Duration::from_millis(25),
            )
            .await
            .expect_err("a stalled handshake must hit the host deadline");
        assert!(error.contains("timed out"), "unexpected error: {error}");
    }
}
