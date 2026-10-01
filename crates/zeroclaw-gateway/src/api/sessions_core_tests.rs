//! The sessions routes with a core attached.
//!
//! `GET /api/sessions` answers the same HTTP whether the core or the
//! gateway's in-process body serves it. Parity runs against the daemon's real
//! in-process connector over one session store, opened twice as in
//! production: once by the core, once by the gateway.
//!
//! The routes that address one session stay in-process. The rest of this
//! module pins why, one test per hazard a core-backed version had: a revoked
//! bearer cancelling a turn, the core acting on a competing row, a delete
//! returning while the gateway's own turn still runs, and a transcript too
//! large for one RPC frame.

use super::tests::{response_json, test_state, test_state_with_session_backend};
use super::*;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use axum::http::HeaderValue;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, DuplexStream};
use tokio_util::sync::CancellationToken;
use zeroclaw_config::schema::Config;
use zeroclaw_infra::session_backend::{SessionBackend, SessionContext};
use zeroclaw_providers::ChatMessage;
use zeroclaw_runtime::rpc::context::RpcContext;
use zeroclaw_runtime::rpc::inproc::InprocConnector;

use crate::core_rpc::{CoreRpc, Dial, DialFuture};

const OPERATOR_TOKEN: &str = "zc_gw_operator";

/// A core and a gateway over one store, with the gateway's own handle.
struct Stores {
    _tmp: tempfile::TempDir,
    ctx: Arc<RpcContext>,
    core: CoreRpc,
    stop: CancellationToken,
    state: AppState,
    backend: Arc<dyn SessionBackend>,
}

impl Drop for Stores {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}

impl Stores {
    /// Share the core's live pairing authority with the gateway, as a
    /// supervised gateway does: pairing required, revocation seen by both.
    fn with_shared_pairing(mut self) -> Self {
        self.state.pairing = Arc::clone(self.ctx.auth.pairing());
        self
    }
}

fn open_store(config: &Config) -> Arc<dyn SessionBackend> {
    zeroclaw_infra::make_session_backend(&config.data_dir, &config.channels.session_backend)
        .expect("open the session store")
}

fn stores() -> Stores {
    let tmp = tempfile::tempdir().expect("tempdir");
    let mut config = Config {
        data_dir: tmp.path().to_path_buf(),
        config_path: tmp.path().join("config.toml"),
        ..Config::default()
    };
    config.gateway.require_pairing = true;
    config.gateway.paired_tokens = vec![OPERATOR_TOKEN.into()];
    let sessions = Arc::new(zeroclaw_runtime::rpc::session::SessionStore::new(
        16,
        Arc::new(zeroclaw_infra::session_queue::SessionActorQueue::new(
            4, 10, 60,
        )),
    ));
    let mut ctx = RpcContext::for_live_test(config.clone(), sessions);
    Arc::get_mut(&mut ctx)
        .expect("a fresh context has one owner")
        .session_backend = Some(open_store(&config));
    let stop = CancellationToken::new();
    let connector = InprocConnector::new(stop.clone());
    connector.bind(Arc::clone(&ctx));
    let backend = open_store(&config);
    let state = test_state_with_session_backend(config, Arc::clone(&backend));
    Stores {
        _tmp: tmp,
        ctx,
        core: CoreRpc::inproc(connector, || true),
        stop,
        state,
        backend,
    }
}

fn seed(backend: &dyn SessionBackend) {
    // A named dashboard chat with a turn in flight.
    backend
        .append("gw_alpha", &ChatMessage::user("hi"))
        .unwrap();
    backend
        .append("gw_alpha", &ChatMessage::assistant("hello"))
        .unwrap();
    backend.set_session_agent_alias("gw_alpha", "main").unwrap();
    backend.set_session_name("gw_alpha", "Alpha").unwrap();
    backend
        .set_session_state("gw_alpha", "running", Some("turn-7"))
        .unwrap();
    // A channel session, attributable by its channel alone.
    backend
        .append("discord.room_1", &ChatMessage::user("from discord"))
        .unwrap();
    backend
        .set_session_context(
            "discord.room_1",
            SessionContext {
                channel_id: Some("discord.ops"),
                ..SessionContext::default()
            },
        )
        .unwrap();
    // A session another client opened over RPC keeps its prefix here.
    backend
        .append("rpc_zc1", &ChatMessage::user("from zerocode"))
        .unwrap();
    backend.set_session_agent_alias("rpc_zc1", "main").unwrap();
    // No alias and no channel: an orphan neither path lists.
    backend
        .append("gw_orphan", &ChatMessage::user("orphan"))
        .unwrap();
}

fn bearer(token: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
    );
    headers
}

async fn through(core: &CoreRpc, token: &str) -> CoreAccess {
    let access = core
        .access(&bearer(token))
        .await
        .expect("the bearer opens a core connection");
    assert!(matches!(access, CoreAccess::Core(_)));
    access
}

async fn answer(response: impl IntoResponse) -> (StatusCode, Value) {
    let response = response.into_response();
    let status = response.status();
    (status, response_json(response).await)
}

fn register_turn(state: &AppState, cancel_key: &str) -> CancellationToken {
    let token = CancellationToken::new();
    state
        .cancel_tokens
        .lock()
        .expect("cancel_tokens lock")
        .insert(cancel_key.to_string(), Arc::new(token.clone()));
    token
}

// ── The listing, through the core ─────────────────────────────────

#[tokio::test]
async fn the_listing_is_the_same_through_the_core() {
    let stores = stores();
    seed(&*stores.backend);
    let access = through(&stores.core, OPERATOR_TOKEN).await;

    let core = answer(
        handle_api_sessions_list(State(stores.state.clone()), access, HeaderMap::new()).await,
    )
    .await;
    let local = answer(
        handle_api_sessions_list(
            State(stores.state.clone()),
            CoreAccess::InProcess,
            HeaderMap::new(),
        )
        .await,
    )
    .await;
    assert_eq!(core, local, "GET /api/sessions");

    let rows = core.1["sessions"].as_array().expect("a sessions array");
    let row = |key: &str| {
        rows.iter()
            .find(|row| row["session_key"] == key)
            .unwrap_or_else(|| panic!("{key} is listed"))
    };
    assert_eq!(rows.len(), 3, "every attributable session, and no orphan");
    assert_eq!(row("gw_alpha")["session_id"], "alpha");
    assert_eq!(row("gw_alpha")["name"], "Alpha");
    assert_eq!(
        row("rpc_zc1")["session_id"],
        "rpc_zc1",
        "only the gateway prefix is stripped for display"
    );
    assert_eq!(row("discord.room_1")["channel_id"], "discord.ops");
    assert_eq!(row("discord.room_1")["agent_alias"], Value::Null);
}

// ── Why the per-session routes stay in-process ───────────────────

/// A revoked pairing token that still has a pooled core connection cannot
/// cancel a turn through DELETE: the route checks the live pairing authority
/// before it touches the gateway's turn.
#[tokio::test]
async fn a_revoked_bearer_with_a_pooled_connection_cancels_nothing() {
    let stores = stores().with_shared_pairing();
    seed(&*stores.backend);
    let turn = register_turn(&stores.state, "gw_alpha");

    // Warm the pool: a core-backed read with the operator's bearer.
    let (status, _) = answer(
        handle_api_sessions_list(
            State(stores.state.clone()),
            through(&stores.core, OPERATOR_TOKEN).await,
            bearer(OPERATOR_TOKEN),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    assert!(stores.ctx.auth.pairing().revoke_token(OPERATOR_TOKEN));
    let (status, body) = answer(
        handle_api_session_delete(
            State(stores.state.clone()),
            bearer(OPERATOR_TOKEN),
            Path("alpha".to_string()),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert!(!turn.is_cancelled(), "a refused caller cancels nothing");
    assert!(stores.backend.session_exists("gw_alpha"));
}

/// With `gw_alpha` and a same-owner `rpc_gw_alpha`, the core resolves the
/// id `gw_alpha` to the RPC row. The routes act on the row this gateway
/// selected, because they do not ask the core to resolve it.
#[tokio::test]
async fn a_competing_rpc_row_never_answers_for_the_gateway_row() {
    let stores = stores();
    seed(&*stores.backend);
    stores
        .backend
        .append(
            "rpc_gw_alpha",
            &ChatMessage::user("different RPC conversation"),
        )
        .unwrap();

    // The hazard is real: asked for `gw_alpha`, the core reads the RPC row.
    let CoreAccess::Core(call) = through(&stores.core, OPERATOR_TOKEN).await else {
        unreachable!()
    };
    let core_read = call
        .request(Method::SessionMessages, json!({ "session_id": "gw_alpha" }))
        .await
        .expect("the core answers");
    assert_eq!(
        core_read["messages"][0]["content"], "different RPC conversation",
        "the core's resolver prefers the rpc_ row"
    );

    let (status, body) = answer(
        handle_api_session_messages(
            State(stores.state.clone()),
            bearer(OPERATOR_TOKEN),
            Path("alpha".to_string()),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let contents: Vec<&str> = body["messages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["content"].as_str().unwrap())
        .collect();
    assert_eq!(contents, ["hi", "hello"]);

    let (status, body) = answer(
        handle_api_session_state(
            State(stores.state.clone()),
            bearer(OPERATOR_TOKEN),
            Path("alpha".to_string()),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["state"], "running");
    assert_eq!(body["turn_id"], "turn-7");

    let (status, body) = answer(
        handle_api_session_delete(
            State(stores.state.clone()),
            bearer(OPERATOR_TOKEN),
            Path("alpha".to_string()),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        !stores.backend.session_exists("gw_alpha"),
        "the selected row goes"
    );
    assert!(
        stores.backend.session_exists("rpc_gw_alpha"),
        "the competing row stays"
    );
}

/// A delete waits for the gateway's own turn on the session to finish
/// before it answers, and a bearer the pairing authority does not know (an
/// administrator's OIDC token, say) neither deletes nor touches that turn.
#[tokio::test]
async fn a_delete_answers_only_after_the_gateways_turn_has_settled() {
    let stores = stores().with_shared_pairing();
    seed(&*stores.backend);
    let turn = register_turn(&stores.state, "gw_alpha");
    let settled = Arc::new(AtomicBool::new(false));
    let permit = stores
        .state
        .session_queue
        .acquire("gw_alpha")
        .await
        .expect("the turn holds the session");
    let worker = {
        let turn = turn.clone();
        let settled = Arc::clone(&settled);
        zeroclaw_spawn::spawn!(async move {
            turn.cancelled().await;
            // Unwinding takes a moment; the permit is held throughout.
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            settled.store(true, Ordering::SeqCst);
            drop(permit);
        })
    };

    let (status, _) = answer(
        handle_api_session_delete(
            State(stores.state.clone()),
            bearer("zc_gw_admin_from_elsewhere"),
            Path("alpha".to_string()),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(!turn.is_cancelled());
    assert!(stores.backend.session_exists("gw_alpha"));

    let (status, body) = answer(
        handle_api_session_delete(
            State(stores.state.clone()),
            bearer(OPERATOR_TOKEN),
            Path("alpha".to_string()),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        settled.load(Ordering::SeqCst),
        "the delete answered while the turn was still running"
    );
    assert!(!stores.backend.session_exists("gw_alpha"));
    worker.await.expect("worker");
}

/// A transcript larger than one RPC frame (8 MiB) is still served whole.
#[tokio::test]
async fn a_transcript_larger_than_an_rpc_frame_is_served_whole() {
    let stores = stores();
    let chunk = "x".repeat(60 * 1024);
    for _ in 0..150 {
        stores
            .backend
            .append("gw_big", &ChatMessage::user(&chunk))
            .unwrap();
    }
    let (status, body) = answer(
        handle_api_session_messages(
            State(stores.state.clone()),
            bearer(OPERATOR_TOKEN),
            Path("big".to_string()),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["messages"].as_array().unwrap().len(), 150);
}

// ── A scripted core: was it asked at all ─────────────────────────

#[derive(Default)]
struct ScriptedCore {
    methods: Mutex<Vec<String>>,
}

struct Scripted(Arc<ScriptedCore>);

impl Dial for Scripted {
    fn dial(&self) -> DialFuture<'_> {
        let core = Arc::clone(&self.0);
        Box::pin(async move {
            let (client, server) = tokio::io::duplex(64 * 1024);
            zeroclaw_spawn::spawn!(serve_scripted(core, server));
            Some(client)
        })
    }
}

async fn serve_scripted(core: Arc<ScriptedCore>, stream: DuplexStream) {
    let (read, mut write) = tokio::io::split(stream);
    let mut lines = BufReader::new(read).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        let frame: Value = serde_json::from_str(&line).expect("client frames are JSON");
        let id = frame["id"].clone();
        let method = frame["method"].as_str().unwrap_or_default().to_owned();
        let answer = if method == "initialize" {
            json!({"jsonrpc": "2.0", "id": id, "result": {
                "protocol_version": 1, "server_version": "scripted", "server_pid": 1,
                "principal_id": "shared-operator",
            }})
        } else {
            core.methods.lock().expect("methods lock").push(method);
            json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32601, "message": "unscripted"}})
        };
        if write
            .write_all(format!("{answer}\n").as_bytes())
            .await
            .is_err()
        {
            break;
        }
    }
}

#[tokio::test]
async fn with_gateway_persistence_off_the_core_is_not_asked() {
    let scripted = Arc::new(ScriptedCore::default());
    let core = CoreRpc::over_dialer(Scripted(Arc::clone(&scripted)));
    let state = test_state(Config::default());
    assert!(state.session_backend.is_none());

    let list = answer(
        handle_api_sessions_list(
            State(state.clone()),
            through(&core, OPERATOR_TOKEN).await,
            HeaderMap::new(),
        )
        .await,
    )
    .await;
    assert_eq!(
        list,
        (
            StatusCode::OK,
            json!({"sessions": [], "message": "Session persistence is disabled"})
        )
    );
    assert!(
        scripted.methods.lock().unwrap().is_empty(),
        "no session method reached the core"
    );
}
