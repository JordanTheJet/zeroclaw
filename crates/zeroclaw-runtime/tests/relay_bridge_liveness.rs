//! Liveness regressions for the daemon-side relay bridge's OUTBOUND link, run
//! against a real listener that speaks just enough of the relay protocol to be
//! hostile.
//!
//! [`relay_full_path`](../relay_full_path.rs) covers the successful path. These
//! cover the two ways a relay can hold the bridge without ever refusing it:
//! accepting a socket and then never answering (setup), and accepting the
//! registration and then never reading again (established). Both must end in a
//! bounded time, and daemon cancellation must return promptly from any phase of
//! the setup rather than waiting on a peer that has stopped speaking.
#![allow(clippy::disallowed_methods)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use futures_util::{SinkExt, StreamExt};
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_util::sync::CancellationToken;
use zeroclaw_relay_proto::{Control, PEER_HINT_ENROLL, SUBPROTOCOL, encode_data};

/// Mirrors the bridge's own `SETUP_DEADLINE`. The constant is module-private, so
/// these tests assert the behaviour it produces with margins wide enough that
/// retuning it does not turn into a false failure.
const SETUP_DEADLINE: Duration = Duration::from_secs(30);
/// Mirrors the bridge's `DEAD_AFTER`, which is also its outbound write bound.
const DEAD_AFTER: Duration = Duration::from_secs(60);
/// Ping frames the wedging relay pushes at the bridge. It stalls long before
/// this; the count only has to outlast the socket buffers on both sides.
const FLOOD_FRAMES: usize = 50_000;
/// Bytes the wedging relay must have delivered before a stalled flood counts as
/// the wedge rather than a slow start. One ping yields one queued pong, so this
/// is many times the bridge's 256-slot outbound queue.
const WEDGE_FLOOR: u64 = 64 * 1024;

/// What the stub relay does before it goes silent.
#[derive(Debug, Clone, Copy)]
enum RelayBehavior {
    /// Read the TLS ClientHello and never speak TLS.
    SilentAtTls,
    /// Complete outer TLS, read the WebSocket upgrade request, never answer it.
    SilentAtWsUpgrade,
    /// Complete the upgrade, read `Hello`, never send `Challenge`.
    SilentAtChallenge,
    /// Send `Challenge`, read `Register`, never send `Registered`.
    SilentAtRegistered,
    /// Complete the whole registration, then stop reading and flood the bridge
    /// with pings so its outbound queue and socket fill behind a writer this
    /// relay will never drain again.
    WedgeAfterRegistration,
    /// Complete registration, stop reading, saturate BOTH the shared outbound
    /// queue and one conn's inbound queue, then open a sibling route. The
    /// sibling dial is the proof that the shared reader never parked.
    SaturateThenOpenSibling,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RelayEvent {
    /// A TCP connection from the bridge was accepted.
    Accepted,
    /// The relay consumed the bridge's last message for its configured phase and
    /// went silent, so the bridge is now parked awaiting a reply.
    Parked,
    /// The signed registration completed; the link is established.
    Registered,
}

struct StubRelay {
    addr: SocketAddr,
    events: mpsc::UnboundedReceiver<RelayEvent>,
    /// Bytes the wedging behaviour has actually pushed onto the wire.
    written: Arc<AtomicU64>,
}

/// Build a self-signed outer TLS acceptor for the stub relay (its own identity).
/// The bridge is configured `relay_insecure`, so nothing here asserts PKI.
fn relay_outer_acceptor() -> TlsAcceptor {
    let ck =
        rcgen::generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()]).unwrap();
    let cert = rustls::pki_types::CertificateDer::from(ck.cert.der().to_vec());
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
        ck.key_pair.serialize_der(),
    ));
    let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![cert], key)
    .unwrap();
    TlsAcceptor::from(Arc::new(cfg))
}

async fn spawn_stub_relay(behavior: RelayBehavior) -> StubRelay {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let acceptor = relay_outer_acceptor();
    let (events, rx) = mpsc::unbounded_channel();
    let written = Arc::new(AtomicU64::new(0));
    let conn_written = written.clone();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            if events.send(RelayEvent::Accepted).is_err() {
                return;
            }
            let acceptor = acceptor.clone();
            let events = events.clone();
            let written = conn_written.clone();
            tokio::spawn(serve_stub_conn(tcp, acceptor, behavior, events, written));
        }
    });
    StubRelay {
        addr,
        events: rx,
        written,
    }
}

async fn serve_stub_conn(
    mut tcp: TcpStream,
    acceptor: TlsAcceptor,
    behavior: RelayBehavior,
    events: mpsc::UnboundedSender<RelayEvent>,
    written: Arc<AtomicU64>,
) {
    let mut scratch = [0u8; 4096];
    if matches!(behavior, RelayBehavior::SilentAtTls) {
        // Consume the ClientHello, so the bridge is parked awaiting the server's
        // half of the handshake rather than still writing its own.
        if tcp.read(&mut scratch).await.is_err() {
            return;
        }
        let _ = events.send(RelayEvent::Parked);
        park(tcp).await;
        return;
    }

    let Ok(mut tls) = acceptor.accept(tcp).await else {
        return;
    };
    if matches!(behavior, RelayBehavior::SilentAtWsUpgrade) {
        if tls.read(&mut scratch).await.is_err() {
            return;
        }
        let _ = events.send(RelayEvent::Parked);
        park(tls).await;
        return;
    }

    let Ok(mut ws) = tokio_tungstenite::accept_hdr_async(tls, echo_subprotocol).await else {
        return;
    };
    let Some(Control::Hello { .. }) = next_control(&mut ws).await else {
        return;
    };
    if matches!(behavior, RelayBehavior::SilentAtChallenge) {
        let _ = events.send(RelayEvent::Parked);
        park(ws).await;
        return;
    }

    let challenge = Control::Challenge {
        nonce: B64.encode(b"relay-bridge-liveness-nonce"),
    };
    if ws.send(Message::text(challenge.to_json())).await.is_err() {
        return;
    }
    let Some(Control::Register { node_id, .. }) = next_control(&mut ws).await else {
        return;
    };
    if matches!(behavior, RelayBehavior::SilentAtRegistered) {
        let _ = events.send(RelayEvent::Parked);
        park(ws).await;
        return;
    }

    let registered = Control::Registered {
        node_id,
        lease_ttl_secs: 300,
    };
    if ws.send(Message::text(registered.to_json())).await.is_err() {
        return;
    }
    let _ = events.send(RelayEvent::Registered);

    if matches!(behavior, RelayBehavior::SaturateThenOpenSibling) {
        saturate_then_open_sibling(ws).await;
        return;
    }

    // From here the relay never reads again. Each ping the bridge receives costs
    // it one pong through its bounded outbound queue, so the queue fills behind
    // a writer whose socket nobody is draining.
    let payload = vec![0u8; 125];
    for _ in 0..FLOOD_FRAMES {
        if ws
            .send(Message::Ping(payload.clone().into()))
            .await
            .is_err()
        {
            break;
        }
        written.fetch_add(payload.len() as u64 + 2, Ordering::Relaxed);
    }
    park(ws).await;
}

/// Hold a connection open and answer nothing further.
async fn park<T>(held: T) {
    let _held = held;
    std::future::pending::<()>().await
}

/// Conn id the saturating stub wedges, and the sibling it probes with afterwards.
const WEDGED_CONN: u64 = 1;
const SIBLING_CONN: u64 = 2;
/// Pings pushed to fill the bridge's 256-slot outbound queue behind a writer
/// whose socket this relay has stopped draining. Each one costs the bridge a
/// pong through that queue, so this is many times over what saturation needs.
const SATURATING_PINGS: usize = 3_000;
/// DATA frames pushed at `WEDGED_CONN` to fill its own 256-slot inbound queue.
const SATURATING_DATA: usize = 400;
/// How many `Open` frames are pushed purely to be refused while the outbound
/// queue is full. `max_conns` is 1 and `WEDGED_CONN` holds the only slot, so the
/// first few are refused `busy`; sent back to back they then outrun the
/// `open_burst` of 3 and the rest are refused `rate_limited`. Both refusals are
/// emitted by the shared reader, which is the point.
const REFUSED_OPENS: u64 = 12;
/// Real-clock pause before the sibling probe, so the `Open` rate bucket refills
/// after the refusals above deliberately drained it.
const BUCKET_REFILL: Duration = Duration::from_millis(300);

/// Drive the reviewed cascade: register, stop reading, then saturate BOTH the
/// shared outbound queue and one conn's inbound queue before asking the bridge
/// to open a sibling route. If any notification on the shared reader path awaits
/// the outbound queue, the reader parks here and the sibling `Open` is never
/// processed.
async fn saturate_then_open_sibling<S>(mut ws: WebSocketStream<S>)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let open_wedged = Control::Open {
        conn_id: WEDGED_CONN,
        peer_hint: None,
    };
    if ws.send(Message::text(open_wedged.to_json())).await.is_err() {
        return;
    }

    // Fill the bridge's outbound queue first: from here every notification the
    // shared reader wants to emit has nowhere to go.
    let ping_payload = vec![0u8; 125];
    for _ in 0..SATURATING_PINGS {
        if ws
            .send(Message::Ping(ping_payload.clone().into()))
            .await
            .is_err()
        {
            return;
        }
    }

    // Capacity and rate refusals, both emitted by the shared reader with the
    // outbound queue already full. `WEDGED_CONN` still holds the only slot, so
    // the first few are refused `busy`; back to back they then outrun the open
    // bucket and the rest are refused `rate_limited`.
    for offset in 0..REFUSED_OPENS {
        let open = Control::Open {
            conn_id: 100 + offset,
            peer_hint: None,
        };
        if ws.send(Message::text(open.to_json())).await.is_err() {
            return;
        }
    }

    // Now fill the wedged conn's inbound queue, so delivery hits the
    // backpressure path that tears the route down and notifies the relay.
    let data_payload = vec![0u8; 4096];
    for _ in 0..SATURATING_DATA {
        let frame = Message::binary(encode_data(WEDGED_CONN, &data_payload));
        if ws.send(frame).await.is_err() {
            return;
        }
    }

    // Let the `Open` bucket refill before the probe: the refusals above drained
    // it deliberately, and a rate-limited probe would prove nothing.
    tokio::time::sleep(BUCKET_REFILL).await;

    // The probe: a sibling route the shared reader can only open if it is still
    // running. It targets the enrollment listener, which reports the dial.
    let open_sibling = Control::Open {
        conn_id: SIBLING_CONN,
        peer_hint: Some(PEER_HINT_ENROLL.to_string()),
    };
    let _ = ws.send(Message::text(open_sibling.to_json())).await;
    park(ws).await;
}

/// A loopback listener that accepts and never reads, so whatever the bridge
/// writes to it backs up. Stands in for a wedged local WSS peer.
async fn stalled_local_target() -> (String, tokio::task::JoinHandle<()>) {
    let socket = tokio::net::TcpSocket::new_v4().expect("socket");
    let _ = socket.set_recv_buffer_size(4 * 1024);
    socket
        .bind("127.0.0.1:0".parse().expect("addr"))
        .expect("bind");
    let listener = socket.listen(16).expect("listen");
    let addr = listener.local_addr().expect("addr").to_string();
    let task = tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept().await {
            held.push(stream);
        }
    });
    (addr, task)
}

/// A loopback listener that reports every connection it accepts. This is the
/// sibling probe: a dial arriving here proves the shared reader processed a
/// frame that came in AFTER both queues were saturated.
async fn reporting_local_target() -> (String, mpsc::UnboundedReceiver<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr").to_string();
    let (tx, rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept().await {
            held.push(stream);
            if tx.send(()).is_err() {
                return;
            }
        }
    });
    (addr, rx)
}

/// The bridge asks for the relay subprotocol, so the stub must grant it. The
/// error type is the tungstenite callback's, not ours.
#[allow(clippy::result_large_err)]
fn echo_subprotocol(
    _req: &tokio_tungstenite::tungstenite::handshake::server::Request,
    mut resp: tokio_tungstenite::tungstenite::handshake::server::Response,
) -> std::result::Result<
    tokio_tungstenite::tungstenite::handshake::server::Response,
    tokio_tungstenite::tungstenite::handshake::server::ErrorResponse,
> {
    resp.headers_mut().insert(
        "Sec-WebSocket-Protocol",
        tokio_tungstenite::tungstenite::http::HeaderValue::from_static(SUBPROTOCOL),
    );
    Ok(resp)
}

async fn next_control<S>(ws: &mut WebSocketStream<S>) -> Option<Control>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    while let Some(msg) = ws.next().await {
        match msg {
            Ok(Message::Text(t)) => return Control::from_json(t.as_str()).ok(),
            Ok(Message::Ping(p)) => {
                let _ = ws.send(Message::Pong(p)).await;
            }
            Ok(_) => {}
            Err(_) => return None,
        }
    }
    None
}

/// [`bridge_config`] with both loopback targets pointed at real listeners, so
/// `Open` frames actually dial something.
fn bridge_config_with_targets(
    relay_addr: SocketAddr,
    data_dir: &std::path::Path,
    signing_key: Vec<u8>,
    local_wss_addr: String,
    local_enroll_addr: String,
) -> zeroclaw_runtime::relay::RelayBridgeConfig {
    zeroclaw_runtime::relay::RelayBridgeConfig {
        local_wss_addr,
        local_enroll_addr: Some(local_enroll_addr),
        // Tight enough that the reader's capacity and rate refusals are both
        // reachable while its outbound queue is saturated.
        max_conns: 1,
        open_burst: 3,
        ..bridge_config(relay_addr, data_dir, signing_key)
    }
}

fn bridge_config(
    relay_addr: SocketAddr,
    data_dir: &std::path::Path,
    signing_key: Vec<u8>,
) -> zeroclaw_runtime::relay::RelayBridgeConfig {
    zeroclaw_runtime::relay::RelayBridgeConfig {
        relay_addr: relay_addr.to_string(),
        relay_host: "localhost".into(),
        node_id: "relay-device".into(),
        relay_token: None,
        // Never dialed: no client ever reaches an `Open` in these tests.
        local_wss_addr: "127.0.0.1:9".into(),
        local_enroll_addr: None,
        enroll_bridge_ports: None,
        signing_key_pkcs8: signing_key,
        relay_ca_path: None,
        relay_insecure: true, // self-signed stub outer cert
        relay_tofu: false,
        outer_client_cert: None,
        outer_client_key: None,
        max_conns: 16,
        open_burst: 60,
        open_rate_per_sec: 20.0,
        data_dir: data_dir.to_path_buf(),
        node_id_rotation_days: 0,
        rotation_allowed: false,
    }
}

/// Await `wanted`, discarding the events that precede it.
async fn wait_for(
    events: &mut mpsc::UnboundedReceiver<RelayEvent>,
    wanted: RelayEvent,
    within: Duration,
) {
    let seen = tokio::time::timeout(within, async {
        loop {
            match events.recv().await {
                Some(event) if event == wanted => return,
                Some(_) => {}
                None => panic!("the stub relay stopped before {wanted:?}"),
            }
        }
    })
    .await;
    assert!(seen.is_ok(), "the stub relay never reached {wanted:?}");
}

/// Wait, on the real clock, until the relay's flood stops making progress. That
/// stall IS the wedge under test: the bridge has stopped reading because its
/// bounded outbound queue filled behind a writer parked in `sink.send`.
async fn wait_for_wedge(written: &AtomicU64) {
    let mut previous = 0;
    let mut stalled = 0;
    for _ in 0..200 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        let now = written.load(Ordering::Relaxed);
        if now == previous && now >= WEDGE_FLOOR {
            stalled += 1;
            if stalled >= 4 {
                return;
            }
        } else {
            stalled = 0;
        }
        previous = now;
    }
    panic!("the relay's writes never stalled, so the bridge outbound path never wedged");
}

/// A relay that accepts and then stops answering must cost the bridge one
/// bounded setup budget, after which it retries. A second connection is the
/// observable proof: without a deadline over the setup the first attempt never
/// ends and no second connection is ever made.
///
/// Only the budget runs on the virtual clock, and it is driven by hand. A
/// running virtual clock cannot tell a task waiting on real socket readiness
/// from an idle runtime, so leaving auto-advance on across the handshake would
/// race the budget against the very I/O it is supposed to be timing.
async fn assert_setup_is_bounded_and_retries(behavior: RelayBehavior) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut relay = spawn_stub_relay(behavior).await;
    let dir = tempfile::tempdir().unwrap();
    let signing_key = zeroclaw_runtime::relay::ensure_signing_key(dir.path()).unwrap();
    let cancel = CancellationToken::new();

    let bridge = tokio::spawn(zeroclaw_runtime::relay::run_relay_bridge(
        bridge_config(relay.addr, dir.path(), signing_key),
        cancel.clone(),
    ));
    wait_for(
        &mut relay.events,
        RelayEvent::Accepted,
        Duration::from_secs(10),
    )
    .await;
    wait_for(
        &mut relay.events,
        RelayEvent::Parked,
        Duration::from_secs(10),
    )
    .await;

    // The parked setup holds nothing but its own deadline now, so the budget is
    // spent by advancing the clock rather than by waiting on it. The clock is
    // handed back before the retry so the retry's real I/O is not racing it.
    tokio::time::pause();
    tokio::time::advance(SETUP_DEADLINE / 2).await;
    assert!(
        relay.events.try_recv().is_err(),
        "a parked setup must be given its full budget, not abandoned early"
    );

    tokio::time::advance(SETUP_DEADLINE).await;
    tokio::time::resume();
    wait_for(
        &mut relay.events,
        RelayEvent::Accepted,
        Duration::from_secs(10),
    )
    .await;

    cancel.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), bridge).await;
}

#[tokio::test]
async fn setup_is_bounded_when_the_relay_never_speaks_tls() {
    assert_setup_is_bounded_and_retries(RelayBehavior::SilentAtTls).await;
}

#[tokio::test]
async fn setup_is_bounded_when_the_relay_never_answers_the_upgrade() {
    assert_setup_is_bounded_and_retries(RelayBehavior::SilentAtWsUpgrade).await;
}

#[tokio::test]
async fn setup_is_bounded_when_the_relay_never_challenges() {
    assert_setup_is_bounded_and_retries(RelayBehavior::SilentAtChallenge).await;
}

#[tokio::test]
async fn setup_is_bounded_when_the_relay_never_confirms_registration() {
    assert_setup_is_bounded_and_retries(RelayBehavior::SilentAtRegistered).await;
}

/// Daemon shutdown must not wait on a relay that has stopped speaking. `Parked`
/// is emitted only once the relay has consumed the bridge's last message for the
/// phase under test, so cancellation lands while the bridge is awaiting a reply
/// that never comes. The real clock runs here: the setup budget cannot expire
/// inside the window this asserts, so a prompt return can only come from
/// cancellation.
async fn assert_cancellation_during_setup_returns_promptly(behavior: RelayBehavior) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut relay = spawn_stub_relay(behavior).await;
    let dir = tempfile::tempdir().unwrap();
    let signing_key = zeroclaw_runtime::relay::ensure_signing_key(dir.path()).unwrap();
    let cancel = CancellationToken::new();

    let bridge = tokio::spawn(zeroclaw_runtime::relay::run_relay_bridge(
        bridge_config(relay.addr, dir.path(), signing_key),
        cancel.clone(),
    ));
    wait_for(
        &mut relay.events,
        RelayEvent::Parked,
        Duration::from_secs(10),
    )
    .await;

    cancel.cancel();
    tokio::time::timeout(Duration::from_secs(2), bridge)
        .await
        .expect("cancellation must return from a parked setup without waiting for the peer")
        .expect("bridge task")
        .expect("clean shutdown");
}

#[tokio::test]
async fn cancellation_returns_while_parked_in_the_tls_handshake() {
    assert_cancellation_during_setup_returns_promptly(RelayBehavior::SilentAtTls).await;
}

#[tokio::test]
async fn cancellation_returns_while_parked_in_the_websocket_upgrade() {
    assert_cancellation_during_setup_returns_promptly(RelayBehavior::SilentAtWsUpgrade).await;
}

#[tokio::test]
async fn cancellation_returns_while_parked_awaiting_the_challenge() {
    assert_cancellation_during_setup_returns_promptly(RelayBehavior::SilentAtChallenge).await;
}

#[tokio::test]
async fn cancellation_returns_while_parked_awaiting_registration() {
    assert_cancellation_during_setup_returns_promptly(RelayBehavior::SilentAtRegistered).await;
}

/// One backpressured connection must not freeze the node.
///
/// The shared reader demuxes every conn on the link and owns the `link_dead` and
/// cancellation arms. If any notification it emits AWAITS the bounded outbound
/// queue, then a relay that has stopped reading parks the reader there: sibling
/// routes stop being served and teardown stops being observed for the writer's
/// whole stall budget, rather than the backpressure staying isolated to the one
/// conn that caused it.
///
/// The stub saturates both queues and then asks for a sibling route. The dial
/// landing on the enrollment listener is the proof that the reader kept running.
#[tokio::test]
async fn a_saturated_link_still_serves_sibling_routes_and_stays_tearable() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (wedged_addr, _wedged_target) = stalled_local_target().await;
    let (sibling_addr, mut sibling_dials) = reporting_local_target().await;

    let mut relay = spawn_stub_relay(RelayBehavior::SaturateThenOpenSibling).await;
    let dir = tempfile::tempdir().unwrap();
    let signing_key = zeroclaw_runtime::relay::ensure_signing_key(dir.path()).unwrap();
    let cancel = CancellationToken::new();

    let bridge = tokio::spawn(zeroclaw_runtime::relay::run_relay_bridge(
        bridge_config_with_targets(
            relay.addr,
            dir.path(),
            signing_key,
            wedged_addr,
            sibling_addr,
        ),
        cancel.clone(),
    ));
    wait_for(
        &mut relay.events,
        RelayEvent::Registered,
        Duration::from_secs(10),
    )
    .await;

    // The sibling `Open` is the last frame the stub sends, after both queues are
    // full. Real clock: the bridge's stall budgets are minutes away, so nothing
    // but a live reader can produce this dial inside the window.
    tokio::time::timeout(Duration::from_secs(20), sibling_dials.recv())
        .await
        .expect("a saturated link must still serve sibling routes")
        .expect("sibling listener");

    // ... and the node must still be tearable, not held until a write budget
    // expires.
    cancel.cancel();
    tokio::time::timeout(Duration::from_secs(5), bridge)
        .await
        .expect("teardown must not wait on the saturated outbound queue")
        .expect("bridge task")
        .expect("clean shutdown");
}

/// An established relay that stops reading wedges every outbound producer: the
/// writer parks in `sink.send`, the bounded queue fills behind it, and the
/// reader loop and keepalive watchdog both block on that queue. Nothing is left
/// to notice, so without the liveness bound the link stays half-alive forever
/// and the bridge never reconnects.
#[tokio::test]
async fn an_established_relay_that_stops_reading_is_declared_dead_and_reconnected() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut relay = spawn_stub_relay(RelayBehavior::WedgeAfterRegistration).await;
    let dir = tempfile::tempdir().unwrap();
    let signing_key = zeroclaw_runtime::relay::ensure_signing_key(dir.path()).unwrap();
    let cancel = CancellationToken::new();

    let bridge = tokio::spawn(zeroclaw_runtime::relay::run_relay_bridge(
        bridge_config(relay.addr, dir.path(), signing_key),
        cancel.clone(),
    ));
    wait_for(
        &mut relay.events,
        RelayEvent::Registered,
        Duration::from_secs(10),
    )
    .await;
    wait_for_wedge(&relay.written).await;

    // The wedge holds nothing but timers now, so the minute-scale budget is
    // spent by advancing the clock rather than by waiting. The clock is driven
    // explicitly and handed back before the reconnect, so that the reconnect's
    // real I/O is never racing an auto-advancing clock.
    tokio::time::pause();
    tokio::time::advance(DEAD_AFTER / 2).await;
    assert!(
        relay.events.try_recv().is_err(),
        "a wedged link must be given its full budget, not torn down on sight"
    );

    tokio::time::advance(DEAD_AFTER * 3).await;
    tokio::time::resume();
    wait_for(
        &mut relay.events,
        RelayEvent::Accepted,
        Duration::from_secs(10),
    )
    .await;

    cancel.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), bridge).await;
}
