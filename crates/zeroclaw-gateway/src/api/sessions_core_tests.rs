//! The ported sessions routes answer the same HTTP whether the core or the
//! gateway's in-process body serves them.
//!
//! Parity runs against the daemon's real in-process connector over one
//! session store, opened twice as in production: once by the core, once by
//! the gateway. The delete gating and the persistence-off shortcut use a
//! scripted core, because they are about which principal the core bound and
//! whether the core is asked at all.

use super::tests::{response_json, test_state, test_state_with_session_backend};
use super::*;

use std::sync::{Arc, Mutex};

use axum::http::HeaderValue;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, DuplexStream};
use tokio_util::sync::CancellationToken;
use zeroclaw_api::jsonrpc::error_codes::FORBIDDEN;
use zeroclaw_config::schema::Config;
use zeroclaw_infra::session_backend::{SessionBackend, SessionContext};
use zeroclaw_providers::ChatMessage;
use zeroclaw_runtime::rpc::inproc::InprocConnector;

use crate::core_rpc::{CoreRpc, Dial, DialFuture};

const OPERATOR_TOKEN: &str = "zc_gw_operator";

/// A core and a gateway over one store, with the gateway's own handle.
struct Stores {
    _tmp: tempfile::TempDir,
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
    let mut ctx =
        zeroclaw_runtime::rpc::context::RpcContext::for_live_test(config.clone(), sessions);
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
        core: CoreRpc::inproc(connector, || true),
        stop,
        state,
        backend,
    }
}

/// The persisted key a WebSocket client's `ops.beta` lands under when the
/// store sanitizes it.
fn sanitized_ops_beta() -> String {
    crate::gateway_session_key("ops.beta")
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
    // A dotted id persisted raw, and one persisted under its sanitized key.
    backend
        .append("gw_team.alpha", &ChatMessage::user("raw dotted"))
        .unwrap();
    backend
        .set_session_agent_alias("gw_team.alpha", "main")
        .unwrap();
    backend
        .append(&sanitized_ops_beta(), &ChatMessage::user("sanitized"))
        .unwrap();
    backend
        .set_session_agent_alias(&sanitized_ops_beta(), "main")
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

/// Same status; same body on success. A refusal carries the same message,
/// and the core path adds its machine-readable `code`.
fn assert_same_answer(what: &str, core: &(StatusCode, Value), local: &(StatusCode, Value)) {
    assert_eq!(core.0, local.0, "{what}: status");
    if core.0.is_success() {
        assert_eq!(core.1, local.1, "{what}: body");
    } else {
        assert_eq!(core.1["error"], local.1["error"], "{what}: error message");
        assert!(
            core.1["code"].is_string(),
            "{what}: the core path names a code"
        );
    }
}

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
    assert_same_answer("GET /api/sessions", &core, &local);

    let rows = core.1["sessions"].as_array().expect("a sessions array");
    let row = |key: &str| {
        rows.iter()
            .find(|row| row["session_key"] == key)
            .unwrap_or_else(|| panic!("{key} is listed"))
    };
    assert_eq!(rows.len(), 5, "every attributable session, and no orphan");
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

#[tokio::test]
async fn transcripts_are_the_same_through_the_core_timestamps_included() {
    let stores = stores();
    seed(&*stores.backend);
    for id in [
        "alpha",
        "gw_alpha",
        "team.alpha",
        "gw_team.alpha",
        "ops.beta",
        "never-existed",
    ] {
        let access = through(&stores.core, OPERATOR_TOKEN).await;
        let core = answer(
            handle_api_session_messages(
                State(stores.state.clone()),
                access,
                HeaderMap::new(),
                Path(id.to_string()),
            )
            .await,
        )
        .await;
        let local = answer(
            handle_api_session_messages(
                State(stores.state.clone()),
                CoreAccess::InProcess,
                HeaderMap::new(),
                Path(id.to_string()),
            )
            .await,
        )
        .await;
        assert_same_answer(&format!("GET messages for {id}"), &core, &local);
    }

    let access = through(&stores.core, OPERATOR_TOKEN).await;
    let (_, body) = answer(
        handle_api_session_messages(
            State(stores.state.clone()),
            access,
            HeaderMap::new(),
            Path("alpha".to_string()),
        )
        .await,
    )
    .await;
    let messages = body["messages"].as_array().expect("a messages array");
    assert_eq!(messages.len(), 2);
    assert!(
        messages.iter().all(|m| m["created_at"].is_string()),
        "the core returns each row's persisted time: {body}"
    );
}

#[tokio::test]
async fn session_state_is_the_same_through_the_core() {
    let stores = stores();
    seed(&*stores.backend);
    for id in [
        "alpha",
        "gw_alpha",
        "team.alpha",
        "ops.beta",
        "never-existed",
    ] {
        let access = through(&stores.core, OPERATOR_TOKEN).await;
        let core = answer(
            handle_api_session_state(
                State(stores.state.clone()),
                access,
                HeaderMap::new(),
                Path(id.to_string()),
            )
            .await,
        )
        .await;
        let local = answer(
            handle_api_session_state(
                State(stores.state.clone()),
                CoreAccess::InProcess,
                HeaderMap::new(),
                Path(id.to_string()),
            )
            .await,
        )
        .await;
        assert_same_answer(&format!("GET state for {id}"), &core, &local);
    }
}

#[tokio::test]
async fn deleting_is_the_same_through_the_core_and_the_core_is_the_writer() {
    for id in ["alpha", "gw_team.alpha", "ops.beta", "never-existed"] {
        let via_core = stores();
        let in_process = stores();
        seed(&*via_core.backend);
        seed(&*in_process.backend);
        let key = resolve_gateway_session_key(id, |k| via_core.backend.session_exists(k));

        let access = through(&via_core.core, OPERATOR_TOKEN).await;
        let core = answer(
            handle_api_session_delete(
                State(via_core.state.clone()),
                access,
                HeaderMap::new(),
                Path(id.to_string()),
            )
            .await,
        )
        .await;
        let local = answer(
            handle_api_session_delete(
                State(in_process.state.clone()),
                CoreAccess::InProcess,
                HeaderMap::new(),
                Path(id.to_string()),
            )
            .await,
        )
        .await;
        assert_same_answer(&format!("DELETE {id}"), &core, &local);
        assert_eq!(
            via_core.backend.session_exists(&key),
            in_process.backend.session_exists(&key),
            "{id}: the same row survives or goes"
        );
    }
}

#[tokio::test]
async fn the_operators_delete_through_the_core_settles_the_gateways_own_turn_first() {
    let stores = stores();
    seed(&*stores.backend);
    // A WebSocket turn registered under the raw dotted id, while the store
    // holds the sanitized key: the two are resolved independently.
    let token = CancellationToken::new();
    stores
        .state
        .cancel_tokens
        .lock()
        .expect("cancel_tokens lock")
        .insert("gw_ops.beta".to_string(), Arc::new(token.clone()));
    let before = stores.state.session_queue.generation(&sanitized_ops_beta());

    let access = through(&stores.core, OPERATOR_TOKEN).await;
    let (status, body) = answer(
        handle_api_session_delete(
            State(stores.state.clone()),
            access,
            HeaderMap::new(),
            Path("ops.beta".to_string()),
        )
        .await,
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body, json!({"deleted": true, "session_id": "ops.beta"}));
    assert!(token.is_cancelled(), "the gateway's own turn is cancelled");
    assert!(!stores.backend.session_exists(&sanitized_ops_beta()));
    assert!(stores.state.session_queue.generation(&sanitized_ops_beta()) > before);
}

// ── A scripted core: which principal it binds, what it answers ─────

struct ScriptedCore {
    principal: &'static str,
    delete: Result<Value, (i32, &'static str)>,
    methods: Mutex<Vec<String>>,
}

impl ScriptedCore {
    fn new(principal: &'static str, delete: Result<Value, (i32, &'static str)>) -> Arc<Self> {
        Arc::new(Self {
            principal,
            delete,
            methods: Mutex::new(Vec::new()),
        })
    }

    fn methods(&self) -> Vec<String> {
        self.methods.lock().expect("methods lock").clone()
    }
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
                "principal_id": core.principal,
            }})
        } else {
            core.methods
                .lock()
                .expect("methods lock")
                .push(method.clone());
            match (&core.delete, method.as_str()) {
                (Ok(result), "session/delete") => {
                    json!({"jsonrpc": "2.0", "id": id, "result": result})
                }
                (Err((code, message)), "session/delete") => {
                    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
                }
                _ => {
                    json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32601, "message": "unscripted"}})
                }
            }
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

/// A gateway with its own store seeded with `gw_alpha` and a running local
/// turn on it.
fn gateway_with_local_turn() -> (
    tempfile::TempDir,
    AppState,
    Arc<dyn SessionBackend>,
    CancellationToken,
) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let config = Config {
        data_dir: tmp.path().to_path_buf(),
        config_path: tmp.path().join("config.toml"),
        ..Config::default()
    };
    let backend = open_store(&config);
    seed(&*backend);
    let state = test_state_with_session_backend(config, Arc::clone(&backend));
    let token = CancellationToken::new();
    state
        .cancel_tokens
        .lock()
        .expect("cancel_tokens lock")
        .insert("gw_alpha".to_string(), Arc::new(token.clone()));
    (tmp, state, backend, token)
}

#[tokio::test]
async fn a_delete_the_core_refuses_touches_no_local_turn() {
    let (_tmp, state, backend, token) = gateway_with_local_turn();
    let scripted = ScriptedCore::new(
        "alice",
        Err((
            FORBIDDEN,
            "Session not found or not owned by this principal",
        )),
    );
    let core = CoreRpc::over_dialer(Scripted(Arc::clone(&scripted)));
    let before = state.session_queue.generation("gw_alpha");

    let (status, body) = answer(
        handle_api_session_delete(
            State(state.clone()),
            through(&core, "zc_gw_alice").await,
            HeaderMap::new(),
            Path("alpha".to_string()),
        )
        .await,
    )
    .await;

    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(!token.is_cancelled(), "a refused caller cancels nothing");
    assert!(backend.session_exists("gw_alpha"), "and deletes nothing");
    assert_eq!(state.session_queue.generation("gw_alpha"), before);
    assert_eq!(scripted.methods(), vec!["session/delete"]);
}

#[tokio::test]
async fn another_principals_delete_leaves_the_gateways_own_turn_alone() {
    let (_tmp, state, backend, token) = gateway_with_local_turn();
    let scripted = ScriptedCore::new(
        "alice",
        Ok(json!({"session_id": "gw_alpha", "deleted": true})),
    );
    let core = CoreRpc::over_dialer(Scripted(Arc::clone(&scripted)));
    let before = state.session_queue.generation("gw_alpha");

    let (status, body) = answer(
        handle_api_session_delete(
            State(state.clone()),
            through(&core, "zc_gw_alice").await,
            HeaderMap::new(),
            Path("alpha".to_string()),
        )
        .await,
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        !token.is_cancelled(),
        "only the shared operator's delete cancels the gateway's own turn"
    );
    assert!(
        backend.session_exists("gw_alpha"),
        "the scripted core deleted nothing, and the gateway wrote nothing itself"
    );
    assert!(state.session_queue.generation("gw_alpha") > before);
}

#[tokio::test]
async fn with_gateway_persistence_off_the_core_is_not_asked() {
    let scripted = ScriptedCore::new("shared-operator", Ok(json!({})));
    let core = CoreRpc::over_dialer(Scripted(Arc::clone(&scripted)));
    let state = test_state(Config::default());
    assert!(state.session_backend.is_none());
    let id = || Path("alpha".to_string());

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
    let messages = answer(
        handle_api_session_messages(
            State(state.clone()),
            through(&core, OPERATOR_TOKEN).await,
            HeaderMap::new(),
            id(),
        )
        .await,
    )
    .await;
    assert_eq!(
        messages,
        (
            StatusCode::OK,
            json!({"session_id": "alpha", "messages": [], "session_persistence": false})
        )
    );
    for response in [
        answer(
            handle_api_session_state(
                State(state.clone()),
                through(&core, OPERATOR_TOKEN).await,
                HeaderMap::new(),
                id(),
            )
            .await,
        )
        .await,
        answer(
            handle_api_session_delete(
                State(state.clone()),
                through(&core, OPERATOR_TOKEN).await,
                HeaderMap::new(),
                id(),
            )
            .await,
        )
        .await,
    ] {
        assert_eq!(
            response,
            (
                StatusCode::NOT_FOUND,
                json!({"error": "Session persistence is disabled"})
            )
        );
    }
    assert!(
        scripted.methods().is_empty(),
        "no session method reached the core: {:?}",
        scripted.methods()
    );
}
