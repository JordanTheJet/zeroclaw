//! Startup checks after the app launches a daemon: the core over RPC, then the
//! dashboard's HTTP gateway, each with a deadline and a failure the splash can
//! name.
//!
//! The process ID and version the core reports are diagnostics. They decide
//! which failure to show, never whether a process is owned or trusted: the
//! endpoint's operating-system account is checked before the handshake, and
//! ownership comes only from the handle the launch returned.

use crate::gateway_client::GatewayClient;
use serde_json::Value;
use std::path::Path;
use std::time::Duration;
use zeroclaw_rpc_client::{
    ClientError, ConnectOptions, Method, RPC_PROTOCOL_VERSION, RpcClient, error_codes,
};

/// How long the dashboard's HTTP gateway gets to answer `/health` after the
/// launched daemon is ready.
pub const GATEWAY_READY_DEADLINE: Duration = Duration::from_secs(60);
/// How long the RPC handshake with the launched core may take.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// How often the gateway wait retries.
const GATEWAY_POLL: Duration = Duration::from_secs(1);

/// Why the daemon the app launched cannot be used, as the splash shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartupFailure {
    /// The daemon did not become ready before the deadline.
    Timeout(String),
    /// The core and this app do not speak compatible versions.
    Incompatible(String),
    /// Another process serves the daemon's RPC endpoint.
    EndpointHeld(String),
    /// Another process holds the dashboard's port.
    PortHeld(String),
    /// The launched core stopped answering before its gateway was ready.
    CoreUnavailable(String),
}

impl StartupFailure {
    /// The `zeroclaw://splash-status` kind for this failure.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Timeout(_) => "timeout",
            Self::Incompatible(_) => "incompatible",
            Self::EndpointHeld(_) => "endpoint_held",
            Self::PortHeld(_) => "port_held",
            Self::CoreUnavailable(_) => "core_unavailable",
        }
    }

    /// The message the splash shows.
    pub fn message(&self) -> &str {
        match self {
            Self::Timeout(message)
            | Self::Incompatible(message)
            | Self::EndpointHeld(message)
            | Self::PortHeld(message)
            | Self::CoreUnavailable(message) => message,
        }
    }

    /// Whether the launched daemon can never become usable, so the app stops
    /// it. A timeout is not final: the daemon may still finish starting.
    pub fn is_final(&self) -> bool {
        !matches!(self, Self::Timeout(_))
    }
}

/// What the core reported in its `initialize` answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreHandshake {
    pub protocol_version: u64,
    pub server_version: String,
    pub server_pid: u32,
}

/// Check the core's handshake against this app. A bundled kernel ships with
/// this app from one build, so its version must equal the app's; a kernel
/// installed separately only has to speak this protocol. A process ID other
/// than the daemon the supervisor started means another core answered on
/// that endpoint.
pub fn check_handshake(
    handshake: &CoreHandshake,
    launched_pid: Option<u32>,
    bundled: bool,
    app_version: &str,
) -> Result<(), StartupFailure> {
    if handshake.protocol_version != RPC_PROTOCOL_VERSION {
        return Err(StartupFailure::Incompatible(format!(
            "The ZeroClaw core speaks protocol {}, but this app speaks protocol {RPC_PROTOCOL_VERSION}. Install a matching ZeroClaw and desktop app.",
            handshake.protocol_version
        )));
    }
    if bundled && handshake.server_version != app_version {
        return Err(StartupFailure::Incompatible(format!(
            "The ZeroClaw core bundled with this app is version {}, but the app is version {app_version}. Reinstall ZeroClaw Desktop.",
            handshake.server_version
        )));
    }
    if let Some(launched) = launched_pid
        && launched != handshake.server_pid
    {
        return Err(StartupFailure::EndpointHeld(format!(
            "Another ZeroClaw core (process {}) answers on the endpoint of the daemon this app started (process {launched}). Stop the other ZeroClaw and reopen the app.",
            handshake.server_pid
        )));
    }
    Ok(())
}

/// Dial the launched core's endpoint and check its handshake. On Unix the
/// endpoint must first prove, through the kernel, that it is served by this
/// app's own account. Windows cannot prove a pipe server's account yet, and
/// this dial carries no credential, so it is not gated there.
pub async fn verify_core(
    endpoint: &Path,
    launched_pid: Option<u32>,
    bundled: bool,
) -> Result<RpcClient, StartupFailure> {
    let options = ConnectOptions {
        handshake_timeout: Some(HANDSHAKE_TIMEOUT),
        verify_endpoint_owner: cfg!(unix),
        ..ConnectOptions::default()
    };
    // The handshake timeout starts only after the endpoint check; bound the
    // whole dial so a stalled connect or check cannot hold startup either.
    let client = tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        RpcClient::connect_local(endpoint, options),
    )
    .await
    .map_err(|_| {
        StartupFailure::Timeout(format!(
            "The ZeroClaw core at {} did not complete its handshake within {} seconds.",
            endpoint.display(),
            HANDSHAKE_TIMEOUT.as_secs()
        ))
    })?
    .map_err(|error| classify_dial_error(endpoint, error))?;
    let handshake = client.handshake();
    check_handshake(
        &CoreHandshake {
            protocol_version: handshake.protocol_version,
            server_version: handshake.server_version.clone(),
            server_pid: handshake.server_pid,
        },
        launched_pid,
        bundled,
        env!("CARGO_PKG_VERSION"),
    )?;
    Ok(client)
}

fn classify_dial_error(endpoint: &Path, error: ClientError) -> StartupFailure {
    match error {
        ClientError::UntrustedEndpoint { rejection, .. } => StartupFailure::EndpointHeld(format!(
            "The ZeroClaw endpoint {} is not this user's ({rejection}). Stop the other process and reopen the app.",
            endpoint.display()
        )),
        ClientError::Rpc(rpc) if rpc.code == error_codes::VERSION_MISMATCH => {
            StartupFailure::Incompatible(format!(
                "The ZeroClaw core refused this app's protocol: {}. Install a matching ZeroClaw and desktop app.",
                rpc.message
            ))
        }
        other => StartupFailure::Timeout(format!(
            "The ZeroClaw core at {} did not complete its handshake: {other}",
            endpoint.display()
        )),
    }
}

/// The error a core reports for its HTTP gateway when the gateway could not
/// bind its port because another process holds it.
pub fn gateway_port_held(health: &Value) -> Option<String> {
    let error = health["components"]["gateway"]["last_error"].as_str()?;
    let lower = error.to_ascii_lowercase();
    let in_use = lower.contains("address already in use")
        || lower.contains("only one usage of each socket address")
        || lower.contains("(os error 48)")
        || lower.contains("(os error 98)")
        || lower.contains("(os error 10048)");
    in_use.then(|| error.to_string())
}

/// Wait, within `budget` overall, until the dashboard's gateway is ready.
///
/// For the daemon this app launched, `core` is its verified RPC connection.
/// The core must then report that its own gateway bound its port, and the
/// dashboard address must answer as that same process. An HTTP answer alone
/// proves nothing about who serves it: any program can hold the port, and a
/// gateway that lost the port to one is reported as such. Without a core (an
/// older kernel), a successful `/health` is all there is to go on.
pub async fn await_gateway(
    gateway_url: &str,
    core: Option<&RpcClient>,
    budget: Duration,
) -> Result<(), StartupFailure> {
    let client = GatewayClient::new(gateway_url, None);
    let mut last_gateway_error = None;
    let wait = async {
        loop {
            let ready = match core {
                Some(core) => {
                    launched_gateway_ready(&client, core, gateway_url, &mut last_gateway_error)
                        .await?
                }
                None => client.get_health().await.unwrap_or(false),
            };
            if ready {
                return Ok(());
            }
            tokio::time::sleep(GATEWAY_POLL).await;
        }
    };
    let outcome = tokio::time::timeout(budget, wait).await;
    outcome.unwrap_or_else(|_| {
        let reported = last_gateway_error
            .map(|error| format!(" Its gateway last reported: {error}."))
            .unwrap_or_default();
        Err(StartupFailure::Timeout(format!(
            "ZeroClaw did not finish starting within {} seconds.{reported} Its log is in the ZeroClaw config directory under logs/zeroclaw-desktop-daemon.log.",
            budget.as_secs()
        )))
    })
}

/// One check of the launched daemon's gateway: `Ok(true)` once the core
/// reports it bound and the dashboard address answers as the core's process.
async fn launched_gateway_ready(
    client: &GatewayClient,
    core: &RpcClient,
    gateway_url: &str,
    last_gateway_error: &mut Option<String>,
) -> Result<bool, StartupFailure> {
    // The daemon rejects `"params": null`; an empty object is the no-argument
    // form it accepts.
    let health = core
        .request(Method::Health, Value::Object(serde_json::Map::new()))
        .await
        .map_err(|error| {
            StartupFailure::CoreUnavailable(format!(
                "The ZeroClaw core stopped answering while it started: {error}. Its log is in the ZeroClaw config directory under logs/zeroclaw-desktop-daemon.log."
            ))
        })?;
    if let Some(error) = gateway_port_held(&health) {
        return Err(StartupFailure::PortHeld(format!(
            "Another program is using the dashboard's address {gateway_url}: {error}. Close it and reopen ZeroClaw."
        )));
    }
    let gateway = &health["components"]["gateway"];
    if gateway["status"].as_str() != Some("ok") {
        *last_gateway_error = gateway["last_error"].as_str().map(str::to_string);
        return Ok(false);
    }
    // The core's gateway is bound and serving. A program bound to a more
    // specific address on the same port would still take loopback
    // connections, so the address must answer as the core's own process.
    let Some(report) = client.health_report().await else {
        return Ok(false);
    };
    let core_pid = core.handshake().server_pid;
    match report["runtime"]["pid"].as_u64() {
        Some(pid) if pid == u64::from(core_pid) => Ok(true),
        answered => Err(StartupFailure::PortHeld(format!(
            "Another program answers on the dashboard's address {gateway_url} ({}), not the ZeroClaw core this app started (process {core_pid}). Close it and reopen ZeroClaw.",
            answered.map_or_else(
                || "it does not report a ZeroClaw process".to_string(),
                |pid| format!("it reports process {pid}")
            )
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[cfg(unix)]
    use std::time::Instant;

    fn handshake(protocol: u64, version: &str, pid: u32) -> CoreHandshake {
        CoreHandshake {
            protocol_version: protocol,
            server_version: version.to_string(),
            server_pid: pid,
        }
    }

    #[test]
    fn a_matching_bundled_core_passes() {
        assert_eq!(
            check_handshake(
                &handshake(RPC_PROTOCOL_VERSION, "0.9.0", 7),
                Some(7),
                true,
                "0.9.0"
            ),
            Ok(())
        );
    }

    #[test]
    fn another_protocol_is_incompatible() {
        let failure = check_handshake(&handshake(2, "0.9.0", 7), Some(7), true, "0.9.0")
            .expect_err("protocol 2 is not spoken");
        assert_eq!(failure.kind(), "incompatible");
        assert!(failure.is_final());
    }

    #[test]
    fn a_bundled_core_of_another_version_is_incompatible() {
        let failure = check_handshake(
            &handshake(RPC_PROTOCOL_VERSION, "0.8.5", 7),
            Some(7),
            true,
            "0.9.0",
        )
        .expect_err("a bundled pair must match exactly");
        assert_eq!(failure.kind(), "incompatible");
        assert!(failure.message().contains("0.8.5") && failure.message().contains("0.9.0"));
    }

    #[test]
    fn a_separately_installed_core_only_needs_the_protocol() {
        assert_eq!(
            check_handshake(
                &handshake(RPC_PROTOCOL_VERSION, "0.8.5", 7),
                Some(7),
                false,
                "0.9.0"
            ),
            Ok(())
        );
    }

    #[test]
    fn another_core_on_the_endpoint_is_reported() {
        let failure = check_handshake(
            &handshake(RPC_PROTOCOL_VERSION, "0.9.0", 99),
            Some(7),
            true,
            "0.9.0",
        )
        .expect_err("a different process answered");
        assert_eq!(failure.kind(), "endpoint_held");
        assert!(failure.message().contains("99"));
    }

    #[test]
    fn a_gateway_that_lost_its_port_is_recognised_on_every_platform() {
        for error in [
            "Failed to bind 127.0.0.1:42617: Address already in use (os error 48)",
            "Failed to bind 127.0.0.1:42617: Address already in use (os error 98)",
            "Failed to bind 127.0.0.1:42617: Only one usage of each socket address (protocol/network address/port) is normally permitted. (os error 10048)",
        ] {
            let health = json!({ "components": { "gateway": { "last_error": error } } });
            assert_eq!(gateway_port_held(&health).as_deref(), Some(error));
        }
        let unrelated = json!({ "components": { "gateway": { "last_error": "TLS key missing" } } });
        assert_eq!(gateway_port_held(&unrelated), None);
        assert_eq!(gateway_port_held(&json!({ "components": {} })), None);
    }

    #[test]
    fn only_a_timeout_leaves_the_launched_daemon_running() {
        assert!(!StartupFailure::Timeout(String::new()).is_final());
        assert!(StartupFailure::PortHeld(String::new()).is_final());
        assert!(StartupFailure::EndpointHeld(String::new()).is_final());
        assert!(StartupFailure::CoreUnavailable(String::new()).is_final());
    }

    /// A core listening on a private socket answers `initialize`; the app
    /// verifies the endpoint's account, completes the handshake and checks
    /// the version pair.
    #[cfg(unix)]
    #[tokio::test]
    async fn verify_core_completes_against_a_same_account_endpoint() {
        let dir = PrivateDir::new("same");
        let endpoint = dir.0.join("d.sock");
        let pid = serve_initialize(&endpoint, env!("CARGO_PKG_VERSION"));
        verify_core(&endpoint, Some(pid), true)
            .await
            .expect("a matching core on a private endpoint verifies");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn verify_core_refuses_a_bundled_core_of_another_version() {
        let dir = PrivateDir::new("skew");
        let endpoint = dir.0.join("d.sock");
        let pid = serve_initialize(&endpoint, "0.0.1");
        let failure = verify_core(&endpoint, Some(pid), true)
            .await
            .expect_err("the bundled pair differs");
        assert_eq!(failure.kind(), "incompatible");
    }

    /// The core reports that its gateway lost the dashboard port. An HTTP
    /// 200 from some other listener on the address must not override that.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_foreign_http_answer_does_not_override_the_core_s_port_failure() {
        let core = FakeCore::start("held", gateway_health("error", Some(PORT_HELD)), false).await;
        let control = await_gateway(&fake_http(503, None), Some(&core.client), SHORT).await;
        assert!(
            matches!(control, Err(StartupFailure::PortHeld(_))),
            "{control:?}"
        );

        let foreign = fake_http(200, Some(json!({ "status": "ok" })));
        let outcome = await_gateway(&foreign, Some(&core.client), SHORT).await;
        assert!(
            matches!(outcome, Err(StartupFailure::PortHeld(_))),
            "{outcome:?}"
        );
        assert_eq!(
            core.health_calls(),
            2,
            "the core is asked before HTTP is trusted"
        );
    }

    /// The core's gateway reports itself bound, but the dashboard address
    /// answers as another process (or as no ZeroClaw at all).
    #[cfg(unix)]
    #[tokio::test]
    async fn an_address_answering_as_another_process_is_not_the_launched_gateway() {
        let core = FakeCore::start("other", gateway_health("ok", None), false).await;
        let other_pid = std::process::id() + 1;
        for body in [Some(json!({ "runtime": { "pid": other_pid } })), None] {
            let outcome =
                await_gateway(&fake_http(200, body.clone()), Some(&core.client), SHORT).await;
            match outcome {
                Err(StartupFailure::PortHeld(message)) => {
                    assert!(
                        message.contains(&std::process::id().to_string()),
                        "{message}"
                    );
                }
                other => panic!("{body:?}: expected PortHeld, got {other:?}"),
            }
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn the_launched_gateway_is_ready_once_the_core_and_its_address_agree() {
        let core = FakeCore::start("agree", gateway_health("ok", None), false).await;
        let gateway = fake_http(
            200,
            Some(json!({ "runtime": { "pid": std::process::id() } })),
        );
        await_gateway(&gateway, Some(&core.client), SHORT)
            .await
            .expect("the core's own gateway answers");
    }

    /// An HTTP answer, even from the right process, is not readiness while
    /// the core still reports its gateway starting or failing; the timeout
    /// names the gateway's last error.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_gateway_the_core_does_not_report_bound_is_not_ready() {
        let core = FakeCore::start(
            "start",
            gateway_health("error", Some("TLS key missing")),
            false,
        )
        .await;
        let gateway = fake_http(
            200,
            Some(json!({ "runtime": { "pid": std::process::id() } })),
        );
        match await_gateway(&gateway, Some(&core.client), Duration::from_millis(300)).await {
            Err(StartupFailure::Timeout(message)) => {
                assert!(message.contains("TLS key missing"), "{message}");
            }
            other => panic!("expected a timeout, got {other:?}"),
        }
    }

    /// The deadline bounds the whole wait, including a core request in
    /// flight that the core never answers.
    #[cfg(unix)]
    #[tokio::test]
    async fn the_gateway_deadline_bounds_an_in_flight_core_request() {
        let core = FakeCore::start("stall", gateway_health("ok", None), true).await;
        let gateway = fake_http(503, None);
        let started = Instant::now();
        let outcome = tokio::time::timeout(
            Duration::from_secs(5),
            await_gateway(&gateway, Some(&core.client), Duration::from_millis(30)),
        )
        .await
        .expect("the gateway deadline must end the wait, not the core request timeout");
        assert!(
            matches!(outcome, Err(StartupFailure::Timeout(_))),
            "{outcome:?}"
        );
        assert_eq!(
            core.health_calls(),
            1,
            "the core received the request it never answers"
        );
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "{:?}",
            started.elapsed()
        );
    }

    #[cfg(unix)]
    const SHORT: Duration = Duration::from_secs(3);
    #[cfg(unix)]
    const PORT_HELD: &str = "Failed to bind 127.0.0.1:42617: Address already in use (os error 48)";

    #[cfg(unix)]
    fn gateway_health(status: &str, last_error: Option<&str>) -> Value {
        json!({ "components": { "gateway": { "status": status, "last_error": last_error } } })
    }

    /// A launched core on a private socket, already verified: it answers
    /// `initialize` as this process, then every `health` with a fixed report,
    /// or never answers `health` when `stall` is set.
    #[cfg(unix)]
    struct FakeCore {
        _dir: PrivateDir,
        client: RpcClient,
        health_calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    #[cfg(unix)]
    impl FakeCore {
        async fn start(label: &str, health: Value, stall: bool) -> Self {
            use std::io::{BufRead, BufReader, Write};
            let dir = PrivateDir::new(label);
            let endpoint = dir.0.join("d.sock");
            let listener =
                std::os::unix::net::UnixListener::bind(&endpoint).expect("bind endpoint");
            let pid = std::process::id();
            let health_calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let counted = std::sync::Arc::clone(&health_calls);
            std::thread::spawn(move || {
                let (stream, _) = listener.accept().expect("accept");
                let mut write = stream.try_clone().expect("clone stream");
                for line in BufReader::new(stream).lines() {
                    let Ok(line) = line else { break };
                    let request: Value = serde_json::from_str(&line).expect("json request");
                    // Like the daemon's dispatcher, refuse null params.
                    if request["params"].is_null() {
                        let refusal = json!({
                            "jsonrpc": "2.0",
                            "id": request["id"],
                            "error": {
                                "code": -32600,
                                "message": "Invalid request: params must be an object or array when present"
                            }
                        });
                        if write.write_all(format!("{refusal}\n").as_bytes()).is_err() {
                            break;
                        }
                        continue;
                    }
                    let result = if request["method"] == "initialize" {
                        json!({
                            "protocol_version": RPC_PROTOCOL_VERSION,
                            "server_version": env!("CARGO_PKG_VERSION"),
                            "server_pid": pid,
                        })
                    } else {
                        counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        if stall {
                            continue;
                        }
                        health.clone()
                    };
                    let answer = json!({ "jsonrpc": "2.0", "id": request["id"], "result": result });
                    if write.write_all(format!("{answer}\n").as_bytes()).is_err() {
                        break;
                    }
                }
            });
            let client = verify_core(&endpoint, Some(pid), true)
                .await
                .expect("a matching core on a private endpoint verifies");
            Self {
                _dir: dir,
                client,
                health_calls,
            }
        }

        fn health_calls(&self) -> usize {
            self.health_calls.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    /// Answer HTTP on loopback for a few seconds, every request with `status`
    /// and `body`; returns the base URL.
    #[cfg(unix)]
    fn fake_http(status: u16, body: Option<Value>) -> String {
        use std::io::{BufRead, BufReader, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let url = format!("http://{}", listener.local_addr().expect("local address"));
        listener
            .set_nonblocking(true)
            .expect("non-blocking listener");
        let body = body.map(|body| body.to_string()).unwrap_or_default();
        std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(10);
            while Instant::now() < deadline {
                let Ok((stream, _)) = listener.accept() else {
                    std::thread::sleep(Duration::from_millis(10));
                    continue;
                };
                let _ = stream.set_nonblocking(false);
                let mut reader = BufReader::new(stream);
                let mut line = String::new();
                while reader.read_line(&mut line).unwrap_or(0) > 0 && line != "\r\n" {
                    line.clear();
                }
                let response = format!(
                    "HTTP/1.1 {status} test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = reader.get_mut().write_all(response.as_bytes());
            }
        });
        url
    }

    /// A directory only this account can write, as the endpoint check requires.
    #[cfg(unix)]
    struct PrivateDir(std::path::PathBuf);

    #[cfg(unix)]
    impl PrivateDir {
        fn new(label: &str) -> Self {
            use std::os::unix::fs::DirBuilderExt;
            let unique = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock should be after the Unix epoch")
                .as_nanos();
            let dir = std::env::temp_dir()
                .join(format!("zc-ready-{label}-{}-{unique}", std::process::id()));
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&dir)
                .expect("create private directory");
            Self(dir)
        }
    }

    #[cfg(unix)]
    impl Drop for PrivateDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// Answer one `initialize` on a socket bound at `endpoint`, reporting
    /// `version` and this process's ID; returns that ID.
    #[cfg(unix)]
    fn serve_initialize(endpoint: &Path, version: &str) -> u32 {
        use std::io::{BufRead, BufReader, Write};
        let listener = std::os::unix::net::UnixListener::bind(endpoint).expect("bind endpoint");
        let pid = std::process::id();
        let version = version.to_string();
        std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            let mut write = stream.try_clone().expect("clone stream");
            let mut lines = BufReader::new(stream).lines();
            let request = lines.next().expect("a request").expect("read request");
            let request: Value = serde_json::from_str(&request).expect("json request");
            let answer = json!({
                "jsonrpc": "2.0",
                "id": request["id"],
                "result": {
                    "protocol_version": RPC_PROTOCOL_VERSION,
                    "server_version": version,
                    "server_pid": pid,
                }
            });
            write
                .write_all(format!("{answer}\n").as_bytes())
                .expect("answer");
            // Keep the connection open while the client finishes.
            let _ = lines.next();
        });
        pid
    }
}
