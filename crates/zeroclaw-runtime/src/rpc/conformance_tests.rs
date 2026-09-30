//! Local transport conformance.
//!
//! One scenario list, run against the daemon's real local listener: a Unix
//! domain socket on Unix and a named pipe on Windows. Every scenario speaks
//! NDJSON JSON-RPC to [`run_local_listener`] the way an external client
//! does, so the same assertions hold on both transports. Only
//! [`open_stream`] is platform-specific; each scenario compiles on every
//! target and runs over whichever transport the target has.
//!
//! Covered here: the handshake (initialize, refusal before it, protocol
//! version), identity and denial, endpoint discovery, and turn streaming
//! (completed, failed and cancelled turns, a closed connection, a subscriber
//! that falls behind). Frame bounds, the connection ceiling and the
//! initialize deadline have per-transport tests beside the listener in
//! `local.rs`. Scenarios that need a transport-intrinsic peer identity are
//! Unix-only: a named pipe carries no peer uid.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio_util::sync::CancellationToken;
use zeroclaw_api::jsonrpc::error_codes::{AUTH_REQUIRED, SESSION_NOT_FOUND, VERSION_MISMATCH};
use zeroclaw_api::principal::PrincipalId;
use zeroclaw_config::schema::Config;
use zeroclaw_infra::session_queue::SessionActorQueue;

use super::context::RpcContext;
use super::dispatch::{Method, RPC_PROTOCOL_VERSION};
use super::local::{run_local_listener, socket_path};
use super::session::SessionStore;

/// Upper bound on any single wait for the daemon.
const WAIT: Duration = Duration::from_secs(10);

/// The transport under test, for assertion messages.
const TRANSPORT: &str = if cfg!(windows) {
    "named pipe"
} else {
    "unix socket"
};

type ReadHalf = Box<dyn AsyncRead + Send + Unpin>;
type WriteHalf = Box<dyn AsyncWrite + Send + Unpin>;

/// Connect to the daemon's endpoint, retrying while the listener comes up.
#[cfg(unix)]
async fn open_stream(endpoint: &Path) -> (ReadHalf, WriteHalf) {
    for _ in 0..250 {
        if let Ok(stream) = tokio::net::UnixStream::connect(endpoint).await {
            let (read, write) = stream.into_split();
            return (Box::new(read), Box::new(write));
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("no daemon accepted on {}", endpoint.display());
}

/// Connect to the daemon's endpoint, retrying while the listener creates its
/// pending pipe instance.
#[cfg(windows)]
async fn open_stream(endpoint: &Path) -> (ReadHalf, WriteHalf) {
    use tokio::net::windows::named_pipe::ClientOptions;
    let name = endpoint.to_string_lossy().into_owned();
    for _ in 0..250 {
        if let Ok(client) = ClientOptions::new().open(&name) {
            let (read, write) = tokio::io::split(client);
            return (Box::new(read), Box::new(write));
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("no daemon accepted on {name}");
}

/// A daemon listening on its real local endpoint.
struct Daemon {
    ctx: Arc<RpcContext>,
    endpoint: PathBuf,
    clients: Arc<AtomicUsize>,
    cancel: CancellationToken,
    listener: tokio::task::JoinHandle<anyhow::Result<()>>,
}

impl Daemon {
    /// Serve `ctx` on the endpoint its configuration resolves to.
    fn start(ctx: Arc<RpcContext>) -> Self {
        let endpoint = socket_path(&ctx.config.read());
        let clients = Arc::new(AtomicUsize::new(0));
        let cancel = CancellationToken::new();
        let listener = {
            let ctx = Arc::clone(&ctx);
            let clients = Arc::clone(&clients);
            let cancel = cancel.clone();
            zeroclaw_spawn::spawn!(
                async move { run_local_listener(ctx, cancel, clients, None).await }
            )
        };
        Self {
            ctx,
            endpoint,
            clients,
            cancel,
            listener,
        }
    }

    async fn connect(&self) -> Client {
        let (read, write) = open_stream(&self.endpoint).await;
        Client {
            reader: BufReader::new(read),
            writer: write,
            next_id: 0,
        }
    }

    /// Wait until the listener counts exactly `expected` live connections.
    async fn wait_for_clients(&self, expected: usize) {
        let reached = tokio::time::timeout(WAIT, async {
            while self.clients.load(Ordering::Relaxed) != expected {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await;
        assert!(
            reached.is_ok(),
            "{TRANSPORT}: client count never reached {expected}; last observed {}",
            self.clients.load(Ordering::Relaxed)
        );
    }

    async fn stop(self) {
        self.cancel.cancel();
        let stopped = tokio::time::timeout(WAIT, self.listener).await;
        assert!(stopped.is_ok(), "{TRANSPORT}: the listener did not stop");
    }
}

/// An NDJSON JSON-RPC client over one connection.
struct Client {
    reader: BufReader<ReadHalf>,
    writer: WriteHalf,
    next_id: u64,
}

/// One request's response and the notifications read while waiting for it.
struct Exchange {
    response: Value,
    notifications: Vec<Value>,
}

impl Exchange {
    fn result(&self) -> &Value {
        assert!(
            self.response["error"].is_null(),
            "{TRANSPORT}: unexpected RPC error: {}",
            self.response
        );
        &self.response["result"]
    }

    fn error_code(&self) -> i64 {
        self.response["error"]["code"]
            .as_i64()
            .unwrap_or_else(|| panic!("{TRANSPORT}: expected an RPC error: {}", self.response))
    }
}

impl Client {
    /// Send `method` with `params`; returns the request id.
    async fn send(&mut self, method: &str, params: Value) -> u64 {
        self.next_id += 1;
        let id = self.next_id;
        let mut line = json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": id,
        })
        .to_string();
        line.push('\n');
        self.writer
            .write_all(line.as_bytes())
            .await
            .unwrap_or_else(|e| panic!("{TRANSPORT}: write {method}: {e}"));
        id
    }

    /// The next frame from the daemon. Fails on end of stream or silence.
    async fn frame(&mut self) -> Value {
        let mut line = String::new();
        let read = tokio::time::timeout(WAIT, self.reader.read_line(&mut line))
            .await
            .unwrap_or_else(|_| panic!("{TRANSPORT}: no frame within {WAIT:?}"))
            .unwrap_or_else(|e| panic!("{TRANSPORT}: read failed: {e}"));
        assert_ne!(read, 0, "{TRANSPORT}: the daemon closed the connection");
        serde_json::from_str(line.trim())
            .unwrap_or_else(|e| panic!("{TRANSPORT}: frame is not JSON ({e}): {line}"))
    }

    /// Read until the response to `id`, keeping the notifications before it.
    async fn response(&mut self, id: u64) -> Exchange {
        let mut notifications = Vec::new();
        loop {
            let frame = self.frame().await;
            if frame.get("method").is_some() && frame.get("id").is_none() {
                notifications.push(frame);
            } else if frame["id"] == json!(id) {
                return Exchange {
                    response: frame,
                    notifications,
                };
            } else {
                panic!("{TRANSPORT}: unexpected frame while waiting for {id}: {frame}");
            }
        }
    }

    async fn call(&mut self, method: Method, params: Value) -> Exchange {
        let id = self.send(method.wire_name(), params).await;
        self.response(id).await
    }

    /// `initialize` with protocol version 1 and no explicit credential.
    async fn initialize(&mut self) -> Exchange {
        self.call(
            Method::Initialize,
            json!({ "protocol_version": RPC_PROTOCOL_VERSION }),
        )
        .await
    }
}

fn config_in(dir: &Path) -> Config {
    Config {
        data_dir: dir.to_path_buf(),
        config_path: dir.join("config.toml"),
        ..Config::default()
    }
}

fn sessions() -> Arc<SessionStore> {
    let queue = Arc::new(SessionActorQueue::new(4, 30, 60));
    Arc::new(SessionStore::new(64, queue))
}

fn daemon_with(config: Config) -> Daemon {
    Daemon::start(RpcContext::minimal(config, sessions()))
}

/// A roster of one user whose profile grants only `system:read`, bound to
/// `uid`. The daemon's own uid is not trusted, so a local peer maps through
/// the roster or not at all.
fn roster_config(dir: &Path, uid: u32) -> Config {
    use zeroclaw_api::grants::{Resource, Verb};
    use zeroclaw_config::schema::{PermissionProfileConfig, UserConfig};
    let mut config = config_in(dir);
    config.security.trust_daemon_uid = false;
    config.permission_profiles.insert(
        "status-reader".into(),
        PermissionProfileConfig {
            grants: std::collections::HashMap::from([(Resource::System, vec![Verb::Read])]),
            ..PermissionProfileConfig::default()
        },
    );
    config.users.insert(
        "alice".into(),
        UserConfig {
            principal_id: None,
            uid: Some(uid),
            permission_profiles: vec!["status-reader".into()],
        },
    );
    config
}

/// The `session/update` notifications for `session_id` of event `kind`.
fn updates<'a>(frames: &'a [Value], session_id: &str, kind: &str) -> Vec<&'a Value> {
    frames
        .iter()
        .filter(|frame| frame["method"] == "session/update")
        .filter(|frame| frame["params"]["session_id"] == session_id)
        .filter(|frame| frame["params"]["type"] == kind)
        .map(|frame| &frame["params"])
        .collect()
}

/// Keep reading notifications until one `turn_complete` for `session_id`
/// has arrived, starting from those already read.
async fn read_until_turn_complete(
    client: &mut Client,
    mut frames: Vec<Value>,
    session_id: &str,
) -> Vec<Value> {
    while updates(&frames, session_id, "turn_complete").is_empty() {
        frames.push(client.frame().await);
    }
    frames
}

// ── Handshake ────────────────────────────────────────────────────

#[tokio::test]
async fn initialize_binds_the_connection_and_advertises_every_method() {
    let tmp = tempfile::tempdir().unwrap();
    let daemon = daemon_with(config_in(tmp.path()));
    let mut client = daemon.connect().await;

    let init = client.initialize().await;
    let result = init.result();
    assert_eq!(result["protocol_version"], RPC_PROTOCOL_VERSION);
    assert_eq!(result["server_version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(result["server_pid"], std::process::id());
    assert!(result["tui_id"].is_string(), "{result}");
    // No roster: the endpoint's access control is the credential, and the
    // connection is the shared operator.
    assert_eq!(result["principal_id"], PrincipalId::SHARED_OPERATOR);

    let mut advertised: Vec<&str> = result["capabilities"]
        .as_array()
        .expect("capabilities")
        .iter()
        .map(|name| name.as_str().expect("method name"))
        .collect();
    advertised.sort_unstable();
    let mut methods: Vec<&str> = Method::ALL.iter().map(|(_, name)| *name).collect();
    methods.sort_unstable();
    assert_eq!(
        advertised, methods,
        "{TRANSPORT}: initialize advertises exactly the method table"
    );

    let status = client.call(Method::Status, json!({})).await;
    assert_eq!(status.result()["protocol_version"], RPC_PROTOCOL_VERSION);

    drop(client);
    daemon.stop().await;
}

#[tokio::test]
async fn a_request_before_initialize_is_refused_and_initialize_still_succeeds() {
    let tmp = tempfile::tempdir().unwrap();
    let daemon = daemon_with(config_in(tmp.path()));
    let mut client = daemon.connect().await;

    let early = client.call(Method::Status, json!({})).await;
    assert_eq!(early.error_code(), i64::from(AUTH_REQUIRED));

    client.initialize().await.result();
    client.call(Method::Status, json!({})).await.result();

    drop(client);
    daemon.stop().await;
}

#[tokio::test]
async fn an_omitted_protocol_version_is_read_as_version_one() {
    let tmp = tempfile::tempdir().unwrap();
    let daemon = daemon_with(config_in(tmp.path()));
    let mut client = daemon.connect().await;

    let init = client.call(Method::Initialize, json!({})).await;
    assert_eq!(init.result()["protocol_version"], 1);

    drop(client);
    daemon.stop().await;
}

/// The handshake field is `protocol_version`. The camelCase `protocolVersion`
/// spelling is not a recognised field today: it is ignored, whatever value it
/// carries, and the handshake is read as version 1. This pins that behaviour
/// so that changing it is a deliberate protocol decision.
#[tokio::test]
async fn a_camel_case_protocol_version_is_ignored_and_read_as_version_one() {
    let tmp = tempfile::tempdir().unwrap();
    let daemon = daemon_with(config_in(tmp.path()));

    for spelled in [1, RPC_PROTOCOL_VERSION + 1] {
        let mut client = daemon.connect().await;
        let init = client
            .call(Method::Initialize, json!({ "protocolVersion": spelled }))
            .await;
        assert_eq!(
            init.result()["protocol_version"],
            1,
            "{TRANSPORT}: protocolVersion={spelled} is read as version 1"
        );
        drop(client);
    }

    daemon.stop().await;
}

#[tokio::test]
async fn an_unsupported_protocol_version_is_refused_and_binds_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let daemon = daemon_with(config_in(tmp.path()));
    let mut client = daemon.connect().await;

    for unsupported in [0, RPC_PROTOCOL_VERSION + 1] {
        let refused = client
            .call(
                Method::Initialize,
                json!({ "protocol_version": unsupported }),
            )
            .await;
        assert_eq!(refused.error_code(), i64::from(VERSION_MISMATCH));
        let message = refused.response["error"]["message"]
            .as_str()
            .expect("message");
        assert!(
            message.contains(&format!("server={RPC_PROTOCOL_VERSION}"))
                && message.contains(&format!("client={unsupported}")),
            "{TRANSPORT}: the refusal names both versions: {message}"
        );

        let unbound = client.call(Method::Status, json!({})).await;
        assert_eq!(
            unbound.error_code(),
            i64::from(AUTH_REQUIRED),
            "{TRANSPORT}: a refused handshake binds no principal"
        );
    }

    // The same connection can still complete a supported handshake.
    client.initialize().await.result();
    client.call(Method::Status, json!({})).await.result();

    drop(client);
    daemon.stop().await;
}

// ── Identity and denial ──────────────────────────────────────────

#[tokio::test]
async fn a_paired_token_binds_its_principal() {
    let tmp = tempfile::tempdir().unwrap();
    let mut config = config_in(tmp.path());
    config.gateway.paired_tokens = vec!["zc_conformance_paired".into()];
    let daemon = daemon_with(config);
    let mut client = daemon.connect().await;

    let init = client
        .call(
            Method::Initialize,
            json!({
                "protocol_version": RPC_PROTOCOL_VERSION,
                "auth_token": "zc_conformance_paired",
            }),
        )
        .await;
    assert_eq!(init.result()["principal_id"], PrincipalId::SHARED_OPERATOR);
    client.call(Method::Status, json!({})).await.result();

    drop(client);
    daemon.stop().await;
}

#[tokio::test]
async fn an_unpaired_token_is_refused_without_falling_back_to_the_endpoint() {
    let tmp = tempfile::tempdir().unwrap();
    let mut config = config_in(tmp.path());
    config.gateway.paired_tokens = vec!["zc_conformance_paired".into()];
    let daemon = daemon_with(config);
    let mut client = daemon.connect().await;

    // Without a roster a tokenless local connection would be the shared
    // operator; a presented credential that fails must not reach that path.
    let refused = client
        .call(
            Method::Initialize,
            json!({
                "protocol_version": RPC_PROTOCOL_VERSION,
                "auth_token": "zc_conformance_never_paired",
            }),
        )
        .await;
    assert_eq!(refused.error_code(), i64::from(AUTH_REQUIRED));
    let unbound = client.call(Method::Status, json!({})).await;
    assert_eq!(unbound.error_code(), i64::from(AUTH_REQUIRED));

    drop(client);
    daemon.stop().await;
}

#[tokio::test]
async fn with_a_roster_a_local_caller_it_does_not_name_is_refused() {
    use crate::security::auth_provider::PeercredAuthProvider;
    let tmp = tempfile::tempdir().unwrap();
    // A uid that is not this process: on Unix the kernel reports this
    // process's uid, which the roster does not name; a named pipe presents
    // no uid at all.
    let other_uid = PeercredAuthProvider::current_process_uid().wrapping_add(1);
    let daemon = daemon_with(roster_config(tmp.path(), other_uid));
    let mut client = daemon.connect().await;

    let refused = client.initialize().await;
    assert_eq!(refused.error_code(), i64::from(AUTH_REQUIRED));
    let unbound = client.call(Method::Status, json!({})).await;
    assert_eq!(unbound.error_code(), i64::from(AUTH_REQUIRED));

    drop(client);
    daemon.stop().await;
}

/// The socket's kernel-reported peer uid is a credential: it binds the
/// roster principal that names it, and that principal's grants decide each
/// call.
#[cfg(unix)]
#[tokio::test]
async fn the_peer_uid_binds_its_roster_principal_and_its_grants_gate_each_call() {
    use crate::security::auth_provider::PeercredAuthProvider;
    use zeroclaw_api::jsonrpc::error_codes::FORBIDDEN;
    let tmp = tempfile::tempdir().unwrap();
    let uid = PeercredAuthProvider::current_process_uid();
    let daemon = daemon_with(roster_config(tmp.path(), uid));
    let mut client = daemon.connect().await;

    let init = client.initialize().await;
    assert_eq!(init.result()["principal_id"], "user:alice");

    client.call(Method::Status, json!({})).await.result();
    let denied = client.call(Method::ConfigGet, json!({})).await;
    assert_eq!(
        denied.error_code(),
        i64::from(FORBIDDEN),
        "a method outside the principal's grants is refused"
    );

    drop(client);
    daemon.stop().await;
}

/// With `trust_daemon_uid` (the default), the daemon's own uid keeps the
/// shared-operator path on the socket even when a roster exists.
#[cfg(unix)]
#[tokio::test]
async fn the_daemons_own_uid_keeps_the_operator_path_when_trusted() {
    use crate::security::auth_provider::PeercredAuthProvider;
    let tmp = tempfile::tempdir().unwrap();
    let other_uid = PeercredAuthProvider::current_process_uid().wrapping_add(1);
    let mut config = roster_config(tmp.path(), other_uid);
    config.security.trust_daemon_uid = true;
    let daemon = daemon_with(config);
    let mut client = daemon.connect().await;

    let init = client.initialize().await;
    assert_eq!(init.result()["principal_id"], PrincipalId::SHARED_OPERATOR);

    drop(client);
    daemon.stop().await;
}

// ── Endpoint discovery ───────────────────────────────────────────

#[tokio::test]
async fn each_data_dir_gets_its_own_endpoint_and_the_daemon_reports_it() {
    let first_dir = tempfile::tempdir().unwrap();
    let second_dir = tempfile::tempdir().unwrap();
    let first = daemon_with(config_in(first_dir.path()));
    let second = daemon_with(config_in(second_dir.path()));
    assert_ne!(first.endpoint, second.endpoint);

    for (daemon, dir) in [(&first, first_dir.path()), (&second, second_dir.path())] {
        // A client that knows only the data directory resolves the same
        // endpoint the daemon bound.
        let resolved = socket_path(&Config {
            data_dir: dir.to_path_buf(),
            ..Config::default()
        });
        assert_eq!(resolved, daemon.endpoint);
        #[cfg(unix)]
        assert_eq!(resolved, dir.join("daemon.sock"));
        #[cfg(windows)]
        assert!(
            resolved
                .to_string_lossy()
                .starts_with(r"\\.\pipe\zeroclaw-"),
            "{}",
            resolved.display()
        );

        let mut client = daemon.connect().await;
        client.initialize().await.result();
        let status = client.call(Method::Status, json!({})).await;
        assert_eq!(
            status.result()["local_ipc_endpoint"],
            resolved.display().to_string(),
            "{TRANSPORT}: the daemon reports the endpoint the client resolved"
        );
    }

    first.stop().await;
    second.stop().await;
}

// ── Turn streaming ───────────────────────────────────────────────

#[tokio::test]
async fn a_prompt_streams_updates_and_ends_in_a_completed_turn() {
    use super::dispatch::connection_test_support::{
        IMMEDIATE_SID, fixture, insert_immediate_session,
    };
    let tmp = tempfile::tempdir().unwrap();
    let fixture = fixture(tmp.path()).await;
    insert_immediate_session(&fixture.ctx, tmp.path()).await;
    let daemon = Daemon::start(Arc::clone(&fixture.ctx));
    let mut client = daemon.connect().await;
    client.initialize().await.result();

    let prompt = client
        .call(
            Method::SessionPrompt,
            json!({
                "session_id": IMMEDIATE_SID,
                "prompt": "run",
                "client_turn_generation": 7,
            }),
        )
        .await;
    // The turn's outcome travels in `turn_complete`; the response is an
    // empty object, kept so request-form callers are answered.
    assert_eq!(*prompt.result(), json!({}));
    let frames = read_until_turn_complete(&mut client, prompt.notifications, IMMEDIATE_SID).await;
    let terminal = updates(&frames, IMMEDIATE_SID, "turn_complete");
    assert_eq!(terminal.len(), 1, "{TRANSPORT}: one terminal event");
    assert_eq!(terminal[0]["outcome"], "completed");
    assert_eq!(terminal[0]["content"], "done");
    assert_eq!(terminal[0]["client_turn_generation"], 7);

    // The connection keeps serving after the turn.
    client.call(Method::Health, json!({})).await.result();

    drop(client);
    daemon.stop().await;
}

#[tokio::test]
async fn a_prompt_on_an_unknown_session_ends_in_a_failed_turn() {
    let tmp = tempfile::tempdir().unwrap();
    let daemon = daemon_with(config_in(tmp.path()));
    let mut client = daemon.connect().await;
    client.initialize().await.result();

    let prompt = client
        .call(
            Method::SessionPrompt,
            json!({
                "session_id": "conformance-no-such-session",
                "prompt": "run",
                "client_turn_generation": 41,
            }),
        )
        .await;
    assert_eq!(prompt.error_code(), i64::from(SESSION_NOT_FOUND));
    let frames = read_until_turn_complete(
        &mut client,
        prompt.notifications,
        "conformance-no-such-session",
    )
    .await;
    let terminal = updates(&frames, "conformance-no-such-session", "turn_complete");
    assert_eq!(terminal[0]["outcome"], "failed");
    assert_eq!(terminal[0]["client_turn_generation"], 41);

    drop(client);
    daemon.stop().await;
}

#[tokio::test]
async fn cancelling_a_running_turn_ends_it_as_cancelled() {
    use super::dispatch::connection_test_support::{RUNNING_SID, fixture};
    let tmp = tempfile::tempdir().unwrap();
    let fixture = fixture(tmp.path()).await;
    let daemon = Daemon::start(Arc::clone(&fixture.ctx));
    let mut client = daemon.connect().await;
    client.initialize().await.result();
    // Rebinding the live session makes this connection its owner, which
    // `session/cancel` requires.
    client
        .call(
            Method::SessionNew,
            json!({ "agent_alias": "test-agent", "session_id": RUNNING_SID }),
        )
        .await
        .result();

    let prompt_id = client
        .send(
            Method::SessionPrompt.wire_name(),
            json!({ "session_id": RUNNING_SID, "prompt": "run" }),
        )
        .await;
    tokio::time::timeout(WAIT, fixture.provider_started.notified())
        .await
        .expect("the turn reaches its provider");

    let cancel = client
        .call(Method::SessionCancel, json!({ "session_id": RUNNING_SID }))
        .await;
    cancel.result();
    let prompt = client.response(prompt_id).await;
    let mut frames = cancel.notifications;
    frames.extend(prompt.notifications);
    let frames = read_until_turn_complete(&mut client, frames, RUNNING_SID).await;
    let terminal = updates(&frames, RUNNING_SID, "turn_complete");
    assert_eq!(terminal.len(), 1, "{TRANSPORT}: one terminal event");
    assert_eq!(terminal[0]["outcome"], "cancelled");
    assert!(
        fixture.provider_dropped.load(Ordering::Acquire),
        "{TRANSPORT}: cancelling the turn drops its provider call"
    );

    drop(client);
    daemon.stop().await;
}

/// Protocol 1 turns belong to the connection that started them: closing it
/// ends the turn. The session itself outlives the connection.
#[tokio::test]
async fn closing_the_prompting_connection_ends_its_turn_but_not_its_session() {
    use super::dispatch::connection_test_support::{RUNNING_SID, fixture};
    let tmp = tempfile::tempdir().unwrap();
    let fixture = fixture(tmp.path()).await;
    let daemon = Daemon::start(Arc::clone(&fixture.ctx));
    let mut client = daemon.connect().await;
    client.initialize().await.result();

    client
        .send(
            Method::SessionPrompt.wire_name(),
            json!({ "session_id": RUNNING_SID, "prompt": "run" }),
        )
        .await;
    tokio::time::timeout(WAIT, fixture.provider_started.notified())
        .await
        .expect("the turn reaches its provider");
    assert!(daemon.ctx.sessions.has_inflight_turn(RUNNING_SID));

    drop(client);
    let ended = tokio::time::timeout(WAIT, async {
        while !fixture.provider_dropped.load(Ordering::Acquire)
            || daemon.ctx.sessions.has_inflight_turn(RUNNING_SID)
        {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    assert!(
        ended.is_ok(),
        "{TRANSPORT}: closing the connection ends the turn it started"
    );
    daemon.wait_for_clients(0).await;

    let mut next = daemon.connect().await;
    next.initialize().await.result();
    let state = next
        .call(Method::SessionState, json!({ "session_id": RUNNING_SID }))
        .await;
    assert_eq!(
        state.result()["state"],
        "idle",
        "{TRANSPORT}: the session outlives the connection and is idle"
    );

    drop(next);
    daemon.stop().await;
}

#[tokio::test]
async fn a_subscriber_that_falls_behind_is_told_where_to_resume_then_streams_live() {
    use super::subscription::{RingLimits, Source, SubscriptionHub};
    let tmp = tempfile::tempdir().unwrap();
    let hub = Arc::new(SubscriptionHub::with_limits(
        RingLimits {
            max_frames: 4,
            max_bytes: usize::MAX,
        },
        usize::MAX,
    ));
    let (event_tx, _event_rx) = tokio::sync::broadcast::channel(16);
    let daemon = Daemon::start(RpcContext::minimal_with_subscription_hub(
        config_in(tmp.path()),
        sessions(),
        event_tx,
        Arc::clone(&hub),
    ));
    for n in 1..=10 {
        hub.publish(Source::Logs, json!({ "n": n }));
    }

    let mut client = daemon.connect().await;
    client.initialize().await.result();
    let subscribed = client
        .call(
            Method::LogsSubscribe,
            json!({ "since_seq": 0, "epoch": hub.epoch() }),
        )
        .await;
    let subscription_id = subscribed.result()["subscription_id"]
        .as_str()
        .expect("subscription id")
        .to_owned();

    let mut frames = subscribed.notifications;
    while frames.len() < 5 {
        frames.push(client.frame().await);
    }
    assert_eq!(frames[0]["method"], "subscription/lagged", "{frames:?}");
    assert_eq!(
        frames[0]["params"],
        json!({
            "subscription_id": subscription_id,
            "from_seq": 1,
            "resume_seq": 7,
            "epoch_changed": false,
        }),
        "{TRANSPORT}: the lag notice names the lost range and the resume point"
    );
    let replayed: Vec<u64> = frames[1..]
        .iter()
        .map(|frame| {
            assert_eq!(frame["method"], "logs/event", "{frame}");
            frame["params"]["seq"].as_u64().expect("seq")
        })
        .collect();
    assert_eq!(replayed, [7, 8, 9, 10]);

    hub.publish(Source::Logs, json!({ "n": 11 }));
    let live = client.frame().await;
    assert_eq!(live["method"], "logs/event");
    assert_eq!(live["params"]["seq"], 11);
    assert_eq!(live["params"]["subscription_id"], subscription_id.as_str());

    drop(client);
    daemon.stop().await;
}
