use super::*;

use std::collections::BTreeSet;

fn args(list: &[&str]) -> Vec<String> {
    list.iter().map(|arg| (*arg).to_owned()).collect()
}

fn bootstrap(list: &[&str], socket_env: Option<&str>) -> Result<Bootstrap, String> {
    match parse_args(args(list), socket_env.map(str::to_owned))? {
        Invocation::Serve(bootstrap) => Ok(bootstrap),
        other => panic!("expected a serve invocation, got {other:?}"),
    }
}

// ── Bootstrap ────────────────────────────────────────────────────

#[test]
fn the_endpoint_comes_from_the_socket_flag_then_the_environment_then_the_data_dir() {
    let flag = bootstrap(
        &["--socket", "/run/flag.sock", "--data-dir", "/var/zc"],
        Some("/run/env.sock"),
    )
    .unwrap();
    assert_eq!(flag.endpoint, PathBuf::from("/run/flag.sock"));

    let env = bootstrap(&["--data-dir", "/var/zc"], Some("/run/env.sock")).unwrap();
    assert_eq!(env.endpoint, PathBuf::from("/run/env.sock"));

    let data_dir = bootstrap(&["--data-dir", "/var/zc"], Some("  ")).unwrap();
    assert_eq!(
        data_dir.endpoint,
        zeroclaw_rpc_client::endpoint::default_endpoint(Path::new("/var/zc"))
    );
}

#[test]
fn without_an_endpoint_it_refuses_and_never_falls_back_to_config() {
    let refused = bootstrap(&[], None).unwrap_err();
    assert!(
        refused.contains("--socket") && refused.contains("config.toml"),
        "{refused}"
    );
    for flag in ["--config", "--config-dir"] {
        let refused = bootstrap(&[flag, "/etc/zeroclaw"], None).unwrap_err();
        assert!(refused.contains("never reads config.toml"), "{refused}");
    }
}

#[test]
fn defaults_serve_on_loopback_without_tls_or_dashboard() {
    let plain = bootstrap(&["--socket", "/run/zc.sock"], None).unwrap();
    assert_eq!(plain.listen, DEFAULT_LISTEN.parse::<SocketAddr>().unwrap());
    assert_eq!(plain.web_dist, None);
    assert_eq!(plain.tls, None);
}

#[test]
fn a_public_listen_address_needs_an_explicit_opt_in() {
    let refused = bootstrap(&["--socket", "/s", "--listen", "0.0.0.0:8080"], None).unwrap_err();
    assert!(refused.contains("--allow-public-bind"), "{refused}");
    let allowed = bootstrap(
        &[
            "--socket",
            "/s",
            "--listen",
            "0.0.0.0:8080",
            "--allow-public-bind",
        ],
        None,
    )
    .unwrap();
    assert_eq!(allowed.listen.port(), 8080);
}

#[test]
fn tls_needs_both_files_and_malformed_arguments_are_refused() {
    let tls = bootstrap(
        &[
            "--socket",
            "/s",
            "--tls-cert",
            "c.pem",
            "--tls-key",
            "k.pem",
        ],
        None,
    )
    .unwrap();
    assert_eq!(
        tls.tls,
        Some(TlsFiles {
            cert: "c.pem".into(),
            key: "k.pem".into()
        })
    );
    for list in [
        &["--socket", "/s", "--tls-cert", "c.pem"][..],
        &["--socket", "/s", "--tls-key", "k.pem"][..],
        &["--socket"][..],
        &["--socket", "/s", "--listen", "not-an-address"][..],
        &["--socket", "/s", "--frobnicate"][..],
    ] {
        assert!(bootstrap(list, None).is_err(), "{list:?} must be refused");
    }
    assert_eq!(parse_args(args(&["--help"]), None), Ok(Invocation::Help));
    assert_eq!(parse_args(args(&["-V"]), None), Ok(Invocation::Version));
}

// ── The fail-closed route map ────────────────────────────────────

/// Routes of the in-process gateway the preview serves itself.
const SERVED: &[&str] = &["/health", "/api/openapi.json", "/api/docs"];

/// Route paths the in-process gateway registers with a string literal, from
/// its production source (test modules excluded).
fn in_process_routes() -> BTreeSet<String> {
    let sources = [
        include_str!("../lib.rs"),
        include_str!("../api_oidc.rs"),
        include_str!("../a2a.rs"),
        include_str!("../plugin_webhook.rs"),
    ];
    let mut paths = BTreeSet::new();
    for source in sources {
        let production = source
            .split("#[cfg(test)]\nmod tests")
            .next()
            .expect("split yields the head");
        let mut rest = production;
        while let Some(at) = rest.find(".route(") {
            rest = &rest[at + ".route(".len()..];
            let literal = rest.trim_start();
            if let Some(body) = literal.strip_prefix('"')
                && let Some(end) = body.find('"')
            {
                paths.insert(body[..end].to_owned());
            }
        }
    }
    paths
}

#[test]
fn every_in_process_route_is_served_or_refused() {
    let classified: BTreeSet<&str> = REFUSED
        .iter()
        .map(|(path, _, _)| *path)
        .chain(SERVED.iter().copied())
        .collect();
    let routes = in_process_routes();
    assert!(routes.len() > 100, "the scan found the router: {routes:?}");
    let unclassified: Vec<&String> = routes
        .iter()
        .filter(|path| !path.starts_with("/_app/") && !classified.contains(path.as_str()))
        .collect();
    assert!(
        unclassified.is_empty(),
        "routes the preview neither serves nor refuses: {unclassified:?}"
    );

    // The table names no route the in-process gateway lacks, except the A2A
    // card paths, which the router builds from constants.
    let from_constants = [
        "/.well-known/agents-card.json",
        "/a2a/.well-known/agents-card.json",
        "/a2a/{alias}/.well-known/agent-card.json",
    ];
    let stale: Vec<&&str> = classified
        .iter()
        .filter(|path| !routes.contains(**path) && !from_constants.contains(path))
        .collect();
    assert!(
        stale.is_empty(),
        "the table names unknown routes: {stale:?}"
    );
}

#[test]
fn every_refused_route_names_known_methods() {
    for (path, methods, _) in REFUSED {
        assert!(!methods.is_empty(), "{path}");
        // Panics on a method the router cannot express.
        let _ = method_filter(methods);
    }
}

// ── Refusals the operator can act on ─────────────────────────────

async fn explained(error: CoreError) -> (StatusCode, serde_json::Value) {
    use http_body_util::BodyExt as _;
    let response = explain(error);
    let status = response.status();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&body).unwrap())
}

#[tokio::test]
async fn a_protocol_mismatch_says_to_install_matching_versions() {
    let (status, body) = explained(CoreError::Rpc(zeroclaw_api::jsonrpc::JsonRpcError {
        code: zeroclaw_api::jsonrpc::error_codes::VERSION_MISMATCH,
        message: "Protocol version mismatch: server=1, client=2".into(),
        data: None,
    }))
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["code"], "core_incompatible");
    assert_eq!(
        body["error"], "Protocol version mismatch: server=1, client=2",
        "the core's own words are kept"
    );
    assert!(
        body["hint"]
            .as_str()
            .is_some_and(|hint| hint.contains("matching versions")),
        "{body}"
    );
}

#[tokio::test]
async fn a_refused_credential_and_an_unreachable_core_explain_themselves_distinctly() {
    let (status, body) = explained(CoreError::AuthRequired("credential rejected".into())).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["code"], "auth_required");
    assert!(
        body["hint"].as_str().is_some_and(|h| h.contains("Bearer")),
        "{body}"
    );

    let (status, body) = explained(CoreError::Unavailable("socket missing".into())).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["code"], "core_unavailable");
    assert!(
        body["hint"]
            .as_str()
            .is_some_and(|h| h.contains("zeroclaw daemon")),
        "{body}"
    );
}

// ── The router, against a real core on a real socket ─────────────

#[cfg(unix)]
mod against_a_core {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt as _;
    use std::sync::atomic::AtomicUsize;
    use std::time::Duration;
    use tokio_util::sync::CancellationToken;
    use tower::ServiceExt as _;

    const TOKEN: &str = "zc_preview_token";

    /// A core serving its real local listener on a socket under `dir`.
    struct Core {
        ctx: Arc<zeroclaw_runtime::rpc::context::RpcContext>,
        endpoint: PathBuf,
        cancel: CancellationToken,
        listener: tokio::task::JoinHandle<anyhow::Result<()>>,
    }

    impl Core {
        async fn start(dir: &Path) -> Self {
            assert!(
                std::env::var_os("ZEROCLAW_SOCKET").is_none(),
                "ZEROCLAW_SOCKET must be unset for these tests"
            );
            let mut config = zeroclaw_config::schema::Config {
                data_dir: dir.to_path_buf(),
                config_path: dir.join("config.toml"),
                ..Default::default()
            };
            config.gateway.paired_tokens = vec![TOKEN.into()];
            let sessions = Arc::new(zeroclaw_runtime::rpc::session::SessionStore::new(
                16,
                Arc::new(zeroclaw_infra::session_queue::SessionActorQueue::new(
                    4, 10, 60,
                )),
            ));
            let ctx = zeroclaw_runtime::rpc::context::RpcContext::for_live_test(config, sessions);
            Self::serve(ctx).await
        }

        async fn serve(ctx: Arc<zeroclaw_runtime::rpc::context::RpcContext>) -> Self {
            let endpoint = zeroclaw_runtime::rpc::local::socket_path(&ctx.config.read());
            let cancel = CancellationToken::new();
            let listener = {
                let ctx = Arc::clone(&ctx);
                let cancel = cancel.clone();
                zeroclaw_spawn::spawn!(async move {
                    zeroclaw_runtime::rpc::local::run_local_listener(
                        ctx,
                        cancel,
                        Arc::new(AtomicUsize::new(0)),
                        None,
                    )
                    .await
                })
            };
            for _ in 0..250 {
                if tokio::net::UnixStream::connect(&endpoint).await.is_ok() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            Self {
                ctx,
                endpoint,
                cancel,
                listener,
            }
        }

        /// Stop the listener and hand back the context for a restart.
        async fn stop(self) -> Arc<zeroclaw_runtime::rpc::context::RpcContext> {
            self.cancel.cancel();
            let _ = tokio::time::timeout(Duration::from_secs(10), self.listener).await;
            self.ctx
        }
    }

    fn web_dist(dir: &Path) -> PathBuf {
        let dist = dir.join("dist");
        std::fs::create_dir_all(dist.join("_app")).unwrap();
        std::fs::write(dist.join("index.html"), "<html>preview dashboard</html>").unwrap();
        std::fs::write(dist.join("_app").join("app.js"), "console.log(1)").unwrap();
        dist
    }

    async fn get(router: &Router, path: &str, token: Option<&str>) -> (StatusCode, String) {
        send(router, "GET", path, token).await
    }

    async fn send(
        router: &Router,
        method: &str,
        path: &str,
        token: Option<&str>,
    ) -> (StatusCode, String) {
        let mut request = Request::builder().method(method).uri(path);
        if let Some(token) = token {
            request = request.header("authorization", format!("Bearer {token}"));
        }
        let response = router
            .clone()
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        (status, String::from_utf8_lossy(&body).into_owned())
    }

    fn json_of(body: &str) -> serde_json::Value {
        serde_json::from_str(body).unwrap_or_else(|e| panic!("not JSON ({e}): {body}"))
    }

    #[tokio::test]
    async fn the_preview_serves_through_the_core_and_refuses_everything_else() {
        let tmp = tempfile::tempdir().unwrap();
        let core = Core::start(tmp.path()).await;
        let router = router(
            CoreRpc::local(core.endpoint.clone(), EndpointOwner::SameAccount),
            core.endpoint.clone(),
            Some(web_dist(tmp.path())),
        );

        let (status, body) = get(&router, "/health", None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(json_of(&body)["core"]["link"], "reachable");

        // The core-link diagnostic needs the caller's own credential.
        let (status, body) = get(&router, CORE_LINK_PATH, None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
        assert_eq!(json_of(&body)["code"], "auth_required");
        assert!(json_of(&body)["hint"].is_string(), "{body}");
        let (status, body) = get(&router, CORE_LINK_PATH, Some("zc_not_paired")).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
        let (status, body) = get(&router, CORE_LINK_PATH, Some(TOKEN)).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let link = json_of(&body);
        assert_eq!(link["principal_id"], "shared-operator");
        assert_eq!(link["core"]["server_version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(link["gateway"]["protocol_version"], RPC_PROTOCOL_VERSION);

        // A dashboard route not served yet: the credential first, then a
        // refusal that names the route.
        let (status, body) = get(&router, "/api/cron", None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
        let (status, body) = get(&router, "/api/cron", Some(TOKEN)).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
        let refused = json_of(&body);
        assert_eq!(refused["code"], "capability_missing");
        assert_eq!(refused["route"], "GET /api/cron");
        assert_eq!(refused["deferred"], false);
        let (_, body) = get(&router, "/api/sessions/abc/state", Some(TOKEN)).await;
        assert_eq!(json_of(&body)["route"], "GET /api/sessions/{id}/state");

        // A deferred route carries no bearer by nature and is refused as is.
        for (method, path, route) in [
            ("POST", "/webhook", "POST /webhook"),
            ("POST", "/pair", "POST /pair"),
            ("GET", "/acp", "GET /acp"),
            ("GET", "/oidc/callback", "GET /oidc/callback"),
            ("POST", "/plugin/inbox", "POST /plugin/{path}"),
        ] {
            let (status, body) = send(&router, method, path, None).await;
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{path}: {body}");
            let refused = json_of(&body);
            assert_eq!(refused["code"], "capability_missing", "{path}");
            assert_eq!(refused["route"], route);
            assert_eq!(refused["deferred"], true);
        }

        // Nothing under an API prefix falls through to the dashboard page.
        for path in ["/api/no-such-route", "/ws/other", "/admin/other"] {
            let (status, body) = get(&router, path, Some(TOKEN)).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{path}: {body}");
            assert_eq!(json_of(&body)["code"], "not_found", "{path}");
        }
        // Dashboard pages and assets are served from the build.
        let (status, body) = get(&router, "/sessions", None).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("preview dashboard"), "{body}");
        let (status, body) = get(&router, "/_app/app.js", None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "console.log(1)");
        let (status, _) = get(&router, "/api/openapi.json", None).await;
        assert_eq!(status, StatusCode::OK);

        // Core down: the health check and core-backed routes say so, with a
        // hint the dashboard can show; a bad credential is still a 401.
        let ctx = core.stop().await;
        let (status, body) = get(&router, "/health", None).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
        let health = json_of(&body);
        assert_eq!(health["code"], "core_unavailable");
        assert_eq!(health["core"]["link"], "unreachable");
        let (status, body) = get(&router, CORE_LINK_PATH, Some(TOKEN)).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
        assert_eq!(json_of(&body)["code"], "core_unavailable");
        assert!(
            json_of(&body)["hint"]
                .as_str()
                .is_some_and(|hint| hint.contains("zeroclaw daemon")),
            "{body}"
        );
        let (status, _) = get(&router, CORE_LINK_PATH, None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        // The core comes back on the same endpoint: the next request
        // reconnects with the caller's credential.
        let core = Core::serve(ctx).await;
        let (status, body) = get(&router, "/health", None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let (status, body) = get(&router, CORE_LINK_PATH, Some(TOKEN)).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        core.stop().await;
    }

    #[tokio::test]
    async fn no_dashboard_build_means_no_page_fallback() {
        let tmp = tempfile::tempdir().unwrap();
        let core = Core::start(tmp.path()).await;
        let router = router(
            CoreRpc::local(core.endpoint.clone(), EndpointOwner::SameAccount),
            core.endpoint.clone(),
            None,
        );
        let (status, body) = get(&router, "/sessions", None).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
        assert_eq!(json_of(&body)["code"], "dashboard_unavailable");
        core.stop().await;
    }
}
