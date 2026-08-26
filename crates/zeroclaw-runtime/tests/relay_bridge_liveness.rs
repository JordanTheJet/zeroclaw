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
use zeroclaw_relay_proto::{Control, SUBPROTOCOL};

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
