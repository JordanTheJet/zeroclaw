//! Dispatcher-level tests for the core-parity methods: routing, the coarse
//! `Method::authz()` gate, and each method's selector. Body parity with the
//! HTTP routes is covered by the gateway's `p6_parity_tests`.

use super::*;

/// Principals bound by peer uid: `scoped` may use agent `alpha` with every
/// `files` verb, `ungranted` may use `alpha` but holds no `files` grant, and
/// `wildcard` may use every agent with every `files` verb but is not admin.
const SCOPED: u32 = 5101;
const UNGRANTED: u32 = 5102;
const WILDCARD_UID: u32 = 5103;

fn files_config(tmp: &tempfile::TempDir) -> zeroclaw_config::schema::Config {
    use std::collections::HashMap;
    use zeroclaw_api::grants::{Resource, Verb};
    use zeroclaw_config::schema::{PermissionProfileConfig, UserConfig};

    let mut config = zeroclaw_config::schema::Config {
        config_path: tmp.path().join("config.toml"),
        ..zeroclaw_config::schema::Config::default()
    };
    let all_files = HashMap::from([(
        Resource::Files,
        vec![Verb::Create, Verb::Read, Verb::Update, Verb::Delete],
    )]);
    for (name, agents, grants) in [
        ("files-alpha", vec!["alpha"], all_files.clone()),
        ("alpha-only", vec!["alpha"], HashMap::new()),
        (
            "files-everyone",
            vec![zeroclaw_api::grants::WILDCARD],
            all_files,
        ),
    ] {
        config.permission_profiles.insert(
            name.into(),
            PermissionProfileConfig {
                allowed_agents: agents.into_iter().map(str::to_string).collect(),
                grants,
                ..PermissionProfileConfig::default()
            },
        );
    }
    for (user, uid, profile) in [
        ("scoped", SCOPED, "files-alpha"),
        ("ungranted", UNGRANTED, "alpha-only"),
        ("wildcard", WILDCARD_UID, "files-everyone"),
    ] {
        config.users.insert(
            user.into(),
            UserConfig {
                uid: Some(uid),
                permission_profiles: vec![profile.into()],
                ..UserConfig::default()
            },
        );
    }
    let alpha = tmp.path().join("agents/alpha/workspace");
    std::fs::create_dir_all(alpha.join("notes")).unwrap();
    std::fs::write(alpha.join("notes/todo.md"), b"todo").unwrap();
    let beta = tmp.path().join("agents/beta/workspace");
    std::fs::create_dir_all(&beta).unwrap();
    std::fs::write(beta.join("secret.md"), b"beta only").unwrap();
    std::fs::create_dir_all(tmp.path().join("shared")).unwrap();
    config
}

fn assert_forbidden(response: &Value, what: &str) {
    assert_eq!(
        response["error"]["code"],
        json!(FORBIDDEN),
        "{what}: {response}"
    );
}

#[tokio::test]
async fn a_scoped_principal_works_in_its_own_agent_workspace() {
    let tmp = tempfile::TempDir::new().unwrap();
    let ctx = enforcement_ctx(files_config(&tmp));
    let (mut peer, mut rx) = roster_peer(&ctx, SCOPED).await;

    let listed = rpc(
        &mut peer,
        &mut rx,
        1,
        "workspace/list",
        json!({"agent": "alpha"}),
    )
    .await;
    assert_eq!(
        listed["result"]["entries"][0]["name"],
        json!("notes"),
        "{listed}"
    );
    let read = rpc(
        &mut peer,
        &mut rx,
        2,
        "fs/read",
        json!({"agent": "alpha", "path": "notes/todo.md"}),
    )
    .await;
    assert_eq!(read["result"]["content"], json!("todo"), "{read}");
    let made = rpc(
        &mut peer,
        &mut rx,
        3,
        "fs/mkdir",
        json!({"agent": "alpha", "path": "d"}),
    )
    .await;
    assert_eq!(made["result"], json!({"created": "d"}), "{made}");
    let moved = rpc(
        &mut peer,
        &mut rx,
        4,
        "fs/move",
        json!({"agent": "alpha", "from": "notes/todo.md", "to": "d/todo.md"}),
    )
    .await;
    assert_eq!(
        moved["result"],
        json!({"from": "notes/todo.md", "to": "d/todo.md"}),
        "{moved}"
    );
    let deleted = rpc(
        &mut peer,
        &mut rx,
        5,
        "fs/delete",
        json!({"agent": "alpha", "path": "d/todo.md"}),
    )
    .await;
    assert_eq!(
        deleted["result"],
        json!({"removed": "d/todo.md"}),
        "{deleted}"
    );
    assert!(!tmp.path().join("agents/alpha/workspace/d/todo.md").exists());
}

#[tokio::test]
async fn a_scoped_principal_cannot_reach_another_agents_workspace() {
    let tmp = tempfile::TempDir::new().unwrap();
    let ctx = enforcement_ctx(files_config(&tmp));
    let (mut peer, mut rx) = roster_peer(&ctx, SCOPED).await;

    let mut messages = Vec::new();
    for (id, method, params) in [
        (1, "workspace/list", json!({"agent": "beta"})),
        (2, "fs/read", json!({"agent": "beta", "path": "secret.md"})),
        (3, "fs/read", json!({"agent": "beta", "path": "absent.md"})),
        (
            4,
            "fs/delete",
            json!({"agent": "beta", "path": "secret.md"}),
        ),
        (
            5,
            "fs/move",
            json!({"agent": "beta", "from": "secret.md", "to": "x.md"}),
        ),
        (6, "fs/mkdir", json!({"agent": "beta", "path": "d"})),
    ] {
        let response = rpc(&mut peer, &mut rx, id, method, params).await;
        assert_forbidden(&response, method);
        messages.push((method, response["error"]["message"].clone()));
    }
    assert_eq!(
        messages[1].1, messages[2].1,
        "an existing and an absent file refuse alike, so the refusal reveals nothing"
    );
    assert!(tmp.path().join("agents/beta/workspace/secret.md").exists());
    assert!(!tmp.path().join("agents/beta/workspace/d").exists());
}

#[tokio::test]
async fn the_shared_area_needs_access_to_every_agent() {
    let tmp = tempfile::TempDir::new().unwrap();
    let ctx = enforcement_ctx(files_config(&tmp));
    let (mut scoped, mut scoped_rx) = roster_peer(&ctx, SCOPED).await;
    for (id, method, params) in [
        (1, "workspace/list", json!({})),
        (2, "fs/mkdir", json!({"path": "made"})),
        (3, "fs/rmdir", json!({"path": "made"})),
    ] {
        let response = rpc(&mut scoped, &mut scoped_rx, id, method, params).await;
        assert_forbidden(&response, method);
    }
    assert!(!tmp.path().join("shared/made").exists());

    let (mut wildcard, mut wildcard_rx) = roster_peer(&ctx, WILDCARD_UID).await;
    let made = rpc(
        &mut wildcard,
        &mut wildcard_rx,
        4,
        "fs/mkdir",
        json!({"path": "made"}),
    )
    .await;
    assert_eq!(made["result"], json!({"created": "made"}), "{made}");
    let removed = rpc(
        &mut wildcard,
        &mut wildcard_rx,
        5,
        "fs/rmdir",
        json!({"path": "made"}),
    )
    .await;
    assert_eq!(removed["result"], json!({"removed": "made"}), "{removed}");
}

#[tokio::test]
async fn workspace_methods_require_the_files_grant() {
    let tmp = tempfile::TempDir::new().unwrap();
    let ctx = enforcement_ctx(files_config(&tmp));
    let (mut peer, mut rx) = roster_peer(&ctx, UNGRANTED).await;
    for (id, method, params) in [
        (1, "workspace/list", json!({"agent": "alpha"})),
        (
            2,
            "fs/read",
            json!({"agent": "alpha", "path": "notes/todo.md"}),
        ),
        (3, "fs/mkdir", json!({"agent": "alpha", "path": "d"})),
        (
            4,
            "fs/move",
            json!({"agent": "alpha", "from": "notes", "to": "n"}),
        ),
        (5, "fs/delete", json!({"agent": "alpha", "path": "notes"})),
    ] {
        let response = rpc(&mut peer, &mut rx, id, method, params).await;
        assert_forbidden(&response, method);
    }
    assert!(tmp.path().join("agents/alpha/workspace/notes").exists());
}

/// The wildcard selector passes any alias string, so it is the principal an
/// alias that escapes `<install>/agents/` would have empowered.
#[tokio::test]
async fn a_wildcard_principal_cannot_escape_the_agents_tree_through_the_alias() {
    let tmp = tempfile::TempDir::new().unwrap();
    let ctx = enforcement_ctx(files_config(&tmp));
    let outside = tmp.path().join("elsewhere");
    std::fs::create_dir_all(outside.join("workspace")).unwrap();
    std::fs::write(outside.join("workspace/secret.md"), b"outside").unwrap();
    let (mut peer, mut rx) = roster_peer(&ctx, WILDCARD_UID).await;

    let absolute = outside.to_string_lossy().to_string();
    for (id, agent) in [(1, "../elsewhere"), (2, absolute.as_str()), (3, "..")] {
        let response = rpc(
            &mut peer,
            &mut rx,
            id,
            "fs/read",
            json!({"agent": agent, "path": "secret.md"}),
        )
        .await;
        assert_eq!(
            response["error"]["code"],
            json!(INVALID_PARAMS),
            "alias {agent:?}: {response}"
        );
    }
    assert!(outside.join("workspace/secret.md").exists());
}

#[test]
fn workspace_methods_are_classified_and_named() {
    use zeroclaw_api::grants::{Resource, Verb};
    for (method, wire, verb) in [
        (Method::WorkspaceList, "workspace/list", Verb::Read),
        (Method::FsRead, "fs/read", Verb::Read),
        (Method::FsMkdir, "fs/mkdir", Verb::Create),
        (Method::FsMove, "fs/move", Verb::Update),
        (Method::FsRmdir, "fs/rmdir", Verb::Delete),
        (Method::FsDelete, "fs/delete", Verb::Delete),
    ] {
        assert_eq!(method.wire_name(), wire);
        assert_eq!(Method::from_wire(wire), Some(method));
        assert_eq!(
            method.authz(),
            MethodAuthz::Requires(Resource::Files, verb),
            "{wire}"
        );
    }
}

#[test]
fn catalog_methods_are_classified_and_named() {
    use zeroclaw_api::grants::{Resource, Verb};
    for (method, wire, resource) in [
        (
            Method::IntegrationsList,
            "integrations/list",
            Resource::Tools,
        ),
        (
            Method::ToolsCliDiscover,
            "tools/cli-discover",
            Resource::Tools,
        ),
        (Method::PluginsList, "plugins/list", Resource::Plugins),
        (Method::A2aIdentity, "a2a/identity", Resource::System),
    ] {
        assert_eq!(method.wire_name(), wire);
        assert_eq!(Method::from_wire(wire), Some(method));
        assert_eq!(
            method.authz(),
            MethodAuthz::Requires(resource, Verb::Read),
            "{wire}"
        );
    }
}

/// `scoped` holds `system:read` and `tools:read` for agent `alpha` only.
fn catalog_config(tmp: &tempfile::TempDir) -> zeroclaw_config::schema::Config {
    use std::collections::HashMap;
    use zeroclaw_api::grants::{Resource, Verb};
    use zeroclaw_config::schema::{AliasedAgentConfig, PermissionProfileConfig, UserConfig};

    let mut config = zeroclaw_config::schema::Config {
        config_path: tmp.path().join("config.toml"),
        ..zeroclaw_config::schema::Config::default()
    };
    config.a2a.server.enabled = true;
    for alias in ["alpha", "beta"] {
        let mut agent = AliasedAgentConfig {
            enabled: true,
            ..Default::default()
        };
        agent.a2a.published = true;
        config.agents.insert(alias.into(), agent);
    }
    config.permission_profiles.insert(
        "catalog-alpha".into(),
        PermissionProfileConfig {
            allowed_agents: vec!["alpha".into()],
            grants: HashMap::from([
                (Resource::System, vec![Verb::Read]),
                (Resource::Tools, vec![Verb::Read]),
            ]),
            ..PermissionProfileConfig::default()
        },
    );
    config.users.insert(
        "scoped".into(),
        UserConfig {
            uid: Some(SCOPED),
            permission_profiles: vec!["catalog-alpha".into()],
            ..UserConfig::default()
        },
    );
    config
}

#[tokio::test]
async fn a2a_identity_holds_a_named_agent_to_the_selector() {
    let tmp = tempfile::TempDir::new().unwrap();
    let ctx = enforcement_ctx(catalog_config(&tmp));
    let (mut peer, mut rx) = roster_peer(&ctx, SCOPED).await;

    let own = rpc(
        &mut peer,
        &mut rx,
        1,
        "a2a/identity",
        json!({"agent": "alpha"}),
    )
    .await;
    assert_eq!(own["result"]["name"], json!("alpha"), "{own}");
    let other = rpc(
        &mut peer,
        &mut rx,
        2,
        "a2a/identity",
        json!({"agent": "beta"}),
    )
    .await;
    assert_forbidden(&other, "another agent's card");
    // The catalog lists published agents only, like the unauthenticated
    // well-known route, so it is not held to the selector.
    let catalog = rpc(&mut peer, &mut rx, 3, "a2a/identity", json!({})).await;
    assert_eq!(
        catalog["result"]["name"],
        json!("ZeroClaw agents"),
        "{catalog}"
    );
}

#[tokio::test]
async fn catalog_methods_route_through_the_gate() {
    let tmp = tempfile::TempDir::new().unwrap();
    let ctx = enforcement_ctx(catalog_config(&tmp));
    let (mut peer, mut rx) = roster_peer(&ctx, SCOPED).await;

    let integrations = rpc(&mut peer, &mut rx, 1, "integrations/list", json!({})).await;
    assert!(
        integrations["result"]["integrations"].is_array(),
        "{integrations}"
    );
    // `plugins:read` is not granted, so the gate refuses before the handler.
    let plugins = rpc(&mut peer, &mut rx, 2, "plugins/list", json!({})).await;
    assert_forbidden(&plugins, "plugins/list without plugins:read");
}

// ── Canvas ────────────────────────────────────────────────────────────────

/// Before the daemon's canvas store reached the RPC context, an RPC-built
/// agent's canvas tool wrote to a private store no reader could see.
#[tokio::test]
async fn a_canvas_drawn_by_an_rpc_built_agent_is_the_one_canvas_rpc_serves() {
    let tmp = tempfile::TempDir::new().unwrap();
    let ctx = enforcement_ctx(make_acp_test_config(&tmp));
    let (mut operator, mut rx) = local_operator(&ctx).await;
    let created = rpc(
        &mut operator,
        &mut rx,
        1,
        "session/new",
        json!({"agent_alias": "test-agent", "session_id": "s-canvas"}),
    )
    .await;
    assert_eq!(
        created["result"]["session_id"],
        json!("s-canvas"),
        "{created}"
    );

    let agent = ctx
        .sessions
        .get_agent("s-canvas")
        .await
        .expect("session exists");
    let drawn = agent
        .lock()
        .await
        .execute_tool_for_test(
            "canvas",
            json!({
                "action": "render",
                "canvas_id": "board",
                "content_type": "text",
                "content": "drawn by the agent",
            }),
        )
        .await
        .expect("the agent has the canvas tool")
        .expect("the canvas tool runs");
    assert!(drawn.success, "{drawn:?}");

    let got = rpc(
        &mut operator,
        &mut rx,
        2,
        "canvas/get",
        json!({"canvas_id": "board"}),
    )
    .await;
    assert_eq!(
        got["result"]["frame"]["content"],
        json!("drawn by the agent"),
        "{got}"
    );
    let listed = rpc(&mut operator, &mut rx, 3, "canvas/list", json!({})).await;
    assert_eq!(listed["result"]["canvases"], json!(["board"]), "{listed}");
}

#[tokio::test]
async fn canvas_render_refuses_what_the_route_refuses() {
    let tmp = tempfile::TempDir::new().unwrap();
    let ctx = enforcement_ctx(make_acp_test_config(&tmp));
    let (mut operator, mut rx) = local_operator(&ctx).await;

    let eval = rpc(
        &mut operator,
        &mut rx,
        1,
        "canvas/render",
        json!({"canvas_id": "c", "content_type": "eval", "content": "alert(1)"}),
    )
    .await;
    assert_eq!(eval["error"]["code"], json!(INVALID_PARAMS), "{eval}");
    let huge = "x".repeat(crate::tools::MAX_CONTENT_SIZE + 1);
    let too_large = rpc(
        &mut operator,
        &mut rx,
        2,
        "canvas/render",
        json!({"canvas_id": "c", "content": huge}),
    )
    .await;
    assert_eq!(
        too_large["error"]["code"],
        json!(INVALID_PARAMS),
        "{too_large}"
    );
    let missing = rpc(
        &mut operator,
        &mut rx,
        3,
        "canvas/get",
        json!({"canvas_id": "nope"}),
    )
    .await;
    assert_eq!(
        missing["error"]["message"],
        json!("Canvas 'nope' not found"),
        "{missing}"
    );
    assert!(ctx.canvas_store.list().is_empty(), "nothing was rendered");

    let rendered = rpc(
        &mut operator,
        &mut rx,
        4,
        "canvas/render",
        json!({"canvas_id": "c", "content": "<p>ok</p>"}),
    )
    .await;
    assert_eq!(
        rendered["result"]["frame"]["content_type"],
        json!("html"),
        "{rendered}"
    );
    let cleared = rpc(
        &mut operator,
        &mut rx,
        5,
        "canvas/clear",
        json!({"canvas_id": "c"}),
    )
    .await;
    assert_eq!(
        cleared["result"],
        json!({"canvas_id": "c", "status": "cleared"}),
        "{cleared}"
    );
}

#[tokio::test]
async fn canvas_methods_need_a_canvas_grant() {
    // `files-alpha` grants files only, so every canvas method is refused.
    let tmp = tempfile::TempDir::new().unwrap();
    let ctx = enforcement_ctx(files_config(&tmp));
    let (mut peer, mut rx) = roster_peer(&ctx, SCOPED).await;
    for (id, method, params) in [
        (1, "canvas/list", json!({})),
        (2, "canvas/get", json!({"canvas_id": "c"})),
        (3, "canvas/history", json!({"canvas_id": "c"})),
        (
            4,
            "canvas/render",
            json!({"canvas_id": "c", "content": "x"}),
        ),
        (5, "canvas/clear", json!({"canvas_id": "c"})),
    ] {
        let response = rpc(&mut peer, &mut rx, id, method, params).await;
        assert_forbidden(&response, method);
    }
    assert!(ctx.canvas_store.list().is_empty());
}

#[test]
fn canvas_methods_are_classified_and_named() {
    use zeroclaw_api::grants::{Resource, Verb};
    for (method, wire, verb) in [
        (Method::CanvasList, "canvas/list", Verb::Read),
        (Method::CanvasGet, "canvas/get", Verb::Read),
        (Method::CanvasHistory, "canvas/history", Verb::Read),
        (Method::CanvasRender, "canvas/render", Verb::Update),
        (Method::CanvasClear, "canvas/clear", Verb::Delete),
    ] {
        assert_eq!(method.wire_name(), wire);
        assert_eq!(Method::from_wire(wire), Some(method));
        assert_eq!(
            method.authz(),
            MethodAuthz::Requires(Resource::Canvas, verb),
            "{wire}"
        );
    }
}
