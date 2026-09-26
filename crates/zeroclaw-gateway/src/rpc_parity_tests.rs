//! Golden parity between the dashboard's HTTP routes and the core RPC
//! methods that replace them. Each test drives the real HTTP handler and the
//! RPC handler against identical state and requires the same body, so a route
//! can move to RPC without its clients seeing a change.
//!
//! The RPC side calls the method's handler after authorization. Routing and
//! the `Method::authz()` and selector checks are covered by the dispatcher's
//! own tests in the runtime crate.

use axum::{
    Json,
    body::to_bytes,
    extract::{Path, Query, State},
    http::HeaderMap,
    response::Response,
};
use serde_json::Value;
use zeroclaw_api::jsonrpc::{
    FsDeleteRequest, FsMkdirRequest, FsMoveRequest, FsReadRequest, FsRmdirRequest,
    WorkspaceListRequest,
};
use zeroclaw_config::schema::Config;
use zeroclaw_runtime::rpc::workspace as rpc_ws;

use crate::api::tests::test_state;
use crate::api_browse::{
    BrowsePathBody, BrowseQuery, MoveBody, handle_agent_workspace_delete,
    handle_agent_workspace_list, handle_agent_workspace_mkdir, handle_agent_workspace_move,
    handle_agent_workspace_read, handle_browse, handle_browse_mkdir, handle_browse_rmdir,
};

const AGENT: &str = "alpha";

async fn body_json(response: Response) -> (u16, Value) {
    let status = response.status().as_u16();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}

/// An install tree with a shared area and one agent workspace holding a text
/// file, a binary file and a subdirectory.
fn install() -> (tempfile::TempDir, Config) {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("shared/skills/one")).unwrap();
    std::fs::write(dir.path().join("shared/readme.txt"), b"hi").unwrap();
    let workspace = dir.path().join("agents").join(AGENT).join("workspace");
    std::fs::create_dir_all(workspace.join("notes")).unwrap();
    std::fs::write(workspace.join("notes/todo.md"), b"# todo\n").unwrap();
    std::fs::write(workspace.join("blob.bin"), [0u8, 159, 146, 150, 255]).unwrap();
    let config = Config {
        config_path: dir.path().join("config.toml"),
        ..Config::default()
    };
    (dir, config)
}

fn path_query(path: &str) -> Query<BrowseQuery> {
    Query(BrowseQuery {
        path: Some(path.to_string()),
    })
}

/// The RPC error, shaped like the HTTP adapter's error body so the two
/// messages compare directly.
fn rpc_error_body(err: &zeroclaw_api::jsonrpc::JsonRpcError) -> Value {
    serde_json::json!({ "error": err.message })
}

#[tokio::test]
async fn workspace_list_matches_the_agent_workspace_and_browse_routes() {
    let (_dir, config) = install();
    let state = test_state(config.clone());

    for path in ["", "notes"] {
        let (status, http) = body_json(
            handle_agent_workspace_list(
                State(state.clone()),
                HeaderMap::new(),
                Path(AGENT.to_string()),
                path_query(path),
            )
            .await,
        )
        .await;
        assert_eq!(status, 200, "{http}");
        let rpc = rpc_ws::handle_workspace_list(
            &config,
            &WorkspaceListRequest {
                agent: Some(AGENT.into()),
                path: Some(path.into()),
            },
        )
        .unwrap();
        assert_eq!(rpc, http, "agent workspace listing at {path:?}");
    }

    let (status, http) =
        body_json(handle_browse(State(state.clone()), HeaderMap::new(), path_query("")).await)
            .await;
    assert_eq!(status, 200, "{http}");
    let rpc = rpc_ws::handle_workspace_list(
        &config,
        &WorkspaceListRequest {
            agent: None,
            path: None,
        },
    )
    .unwrap();
    assert_eq!(rpc, http, "shared-area listing");
}

#[tokio::test]
async fn fs_read_matches_the_workspace_read_route_for_text_and_binary() {
    let (_dir, config) = install();
    let state = test_state(config.clone());
    for path in ["notes/todo.md", "blob.bin"] {
        let (status, http) = body_json(
            handle_agent_workspace_read(
                State(state.clone()),
                HeaderMap::new(),
                Path(AGENT.to_string()),
                path_query(path),
            )
            .await,
        )
        .await;
        assert_eq!(status, 200, "{http}");
        let rpc = rpc_ws::handle_fs_read(
            &config,
            &FsReadRequest {
                agent: AGENT.into(),
                path: path.into(),
            },
        )
        .unwrap();
        assert_eq!(rpc, http, "read of {path}");
    }
}

#[tokio::test]
async fn fs_errors_carry_the_same_message_as_the_routes() {
    let (_dir, config) = install();
    let state = test_state(config.clone());
    for path in ["missing.md", "../../etc/passwd", "notes"] {
        let (status, http) = body_json(
            handle_agent_workspace_read(
                State(state.clone()),
                HeaderMap::new(),
                Path(AGENT.to_string()),
                path_query(path),
            )
            .await,
        )
        .await;
        assert_ne!(status, 200, "{path} must fail over HTTP: {http}");
        let err = rpc_ws::handle_fs_read(
            &config,
            &FsReadRequest {
                agent: AGENT.into(),
                path: path.into(),
            },
        )
        .unwrap_err();
        assert_eq!(rpc_error_body(&err), http, "error for {path}");
    }
}

#[tokio::test]
async fn fs_mutations_match_their_routes_and_leave_the_same_tree() {
    // Each side mutates its own identical install, then the trees are listed
    // and compared, so a body can't match while the effect differs.
    let (_http_dir, http_config) = install();
    let (_rpc_dir, rpc_config) = install();
    let state = test_state(http_config.clone());
    let list = |config: &Config, agent: Option<&str>| {
        rpc_ws::handle_workspace_list(
            config,
            &WorkspaceListRequest {
                agent: agent.map(str::to_string),
                path: None,
            },
        )
        .unwrap()
    };

    // mkdir in the agent workspace and in the shared area.
    let (_, http) = body_json(
        handle_agent_workspace_mkdir(
            State(state.clone()),
            HeaderMap::new(),
            Path(AGENT.to_string()),
            Json(BrowsePathBody {
                path: "drafts".into(),
            }),
        )
        .await,
    )
    .await;
    let rpc = rpc_ws::handle_fs_mkdir(
        &rpc_config,
        &FsMkdirRequest {
            agent: Some(AGENT.into()),
            path: "drafts".into(),
        },
    )
    .unwrap();
    assert_eq!(rpc, http, "agent mkdir");

    let (_, http) = body_json(
        handle_browse_mkdir(
            State(state.clone()),
            HeaderMap::new(),
            Json(BrowsePathBody {
                path: "scratch".into(),
            }),
        )
        .await,
    )
    .await;
    let rpc = rpc_ws::handle_fs_mkdir(
        &rpc_config,
        &FsMkdirRequest {
            agent: None,
            path: "scratch".into(),
        },
    )
    .unwrap();
    assert_eq!(rpc, http, "shared mkdir");

    // move, then delete, in the agent workspace.
    let (_, http) = body_json(
        handle_agent_workspace_move(
            State(state.clone()),
            HeaderMap::new(),
            Path(AGENT.to_string()),
            Json(MoveBody {
                from: "notes/todo.md".into(),
                to: "drafts/todo.md".into(),
            }),
        )
        .await,
    )
    .await;
    let rpc = rpc_ws::handle_fs_move(
        &rpc_config,
        &FsMoveRequest {
            agent: AGENT.into(),
            from: "notes/todo.md".into(),
            to: "drafts/todo.md".into(),
        },
    )
    .unwrap();
    assert_eq!(rpc, http, "move");

    let (_, http) = body_json(
        handle_agent_workspace_delete(
            State(state.clone()),
            HeaderMap::new(),
            Path(AGENT.to_string()),
            Json(BrowsePathBody {
                path: "blob.bin".into(),
            }),
        )
        .await,
    )
    .await;
    let rpc = rpc_ws::handle_fs_delete(
        &rpc_config,
        &FsDeleteRequest {
            agent: AGENT.into(),
            path: "blob.bin".into(),
        },
    )
    .unwrap();
    assert_eq!(rpc, http, "delete");

    // rmdir in the shared area.
    let (_, http) = body_json(
        handle_browse_rmdir(
            State(state.clone()),
            HeaderMap::new(),
            Json(BrowsePathBody {
                path: "scratch".into(),
            }),
        )
        .await,
    )
    .await;
    let rpc = rpc_ws::handle_fs_rmdir(
        &rpc_config,
        &FsRmdirRequest {
            path: "scratch".into(),
        },
    )
    .unwrap();
    assert_eq!(rpc, http, "shared rmdir");

    assert_eq!(
        list(&rpc_config, Some(AGENT)),
        list(&http_config, Some(AGENT)),
        "the agent workspace ends up the same"
    );
    assert_eq!(
        list(&rpc_config, None),
        list(&http_config, None),
        "the shared area ends up the same"
    );
}

#[tokio::test]
async fn an_escaping_agent_alias_is_refused_alike_on_both_surfaces() {
    let (_dir, config) = install();
    let state = test_state(config.clone());
    let (status, http) = body_json(
        handle_agent_workspace_list(
            State(state),
            HeaderMap::new(),
            Path("..".to_string()),
            path_query(""),
        )
        .await,
    )
    .await;
    assert_eq!(status, 400, "{http}");
    let err = rpc_ws::handle_workspace_list(
        &config,
        &WorkspaceListRequest {
            agent: Some("..".into()),
            path: None,
        },
    )
    .unwrap_err();
    assert_eq!(err.code, zeroclaw_api::jsonrpc::error_codes::INVALID_PARAMS);
    assert_eq!(rpc_error_body(&err), http);
}
