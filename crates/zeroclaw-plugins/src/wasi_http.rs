//! ZeroClaw's `wasi:http` outbound handler for plugin stores (ADR-013).
//!
//! A plugin granted `http_client` gets the `wasi:http` linker, but the linker is
//! not the authority. This module replaces wasmtime's default [`WasiHttpHooks`]
//! with hooks that submit every guest-issued request to the host-owned egress
//! boundary in [`crate::egress`], and then perform the send itself.
//!
//! Three properties carry the security weight, and all three are decided by the
//! shared boundary rather than here:
//!
//! 1. **Deny by default.** A store built without an [`EgressHostService`] denies
//!    every request. The linker still carries `wasi:http` — store construction
//!    is unchanged — but nothing gets out. "Granted `http_client`" and "may
//!    reach the network" are deliberately different states, which is what shuts
//!    the self-grant path: a component that writes `http_client` into its own
//!    unsigned manifest still reaches nothing.
//!
//! 2. **Policy is read per request, never snapshotted.** The service holds a
//!    resolver closure, so an operator's edit to the canonical config takes
//!    effect on the next request without re-instantiating the guest, which is
//!    ADR-012's use-time resolution mode.
//!
//! 3. **The connect is pinned.** [`EgressHostService::authorize`] performs the
//!    one resolution and hands back the exact addresses that passed validation.
//!    This adapter dials those and never resolves the name again, so a DNS
//!    answer cannot change address classes between the check and the connect.
//!    TLS still takes SNI and certificate verification from the *hostname*, so
//!    pinning the connect does not weaken TLS identity.
//!
//! What is deliberately *not* here: the allowlist match, the address-class
//! verdict, NAT64 classification, and the connection budget. Re-deciding any of
//! them in a transport adapter is how a plugin and a built-in tool come to
//! disagree about what is reachable.
//!
//! Redirects are not followed. A guest that wants to chase one issues a second
//! request, and that request is authorized on its own from scratch.

use std::time::Duration;

use hyper::header::HOST;
use wasmtime_wasi_http::p2::{
    WasiHttpHooks,
    bindings::http::types::ErrorCode,
    body::HyperOutgoingBody,
    types::{HostFutureIncomingResponse, IncomingResponse, OutgoingRequestConfig},
};
use zeroclaw_infra::net_guard::NetworkGuardError;

use crate::egress::{
    AuthorizedEgress, EgressError, EgressHostService, EgressRequest, EgressTransport,
};
use crate::instance::{PluginInstanceId, PluginInstanceScope};

/// The masked text a denied guest sees.
///
/// It names the policy and nothing else: no host, no address, no matched or
/// unmatched pattern. A guest must not be able to use denial messages to map the
/// host's internal network.
pub const DENIED_MESSAGE: &str = "zeroclaw plugin egress policy: destination not permitted";

fn denied() -> ErrorCode {
    ErrorCode::InternalError(Some(DENIED_MESSAGE.to_string()))
}

/// A destination that could not be resolved. Distinct from [`denied`] on
/// purpose: a name that does not resolve is not a policy decision, and reporting
/// it as one would tell a guest that every unreachable host is blocked. Mirrors
/// what the default send path reports for the same condition.
fn dns_failure() -> ErrorCode {
    ErrorCode::DnsError(
        wasmtime_wasi_http::p2::bindings::http::types::DnsErrorPayload {
            rcode: Some("address not available".to_string()),
            info_code: Some(0),
        },
    )
}

/// Emit the structured denial event that attributes the attempt to the exact
/// instance. The destination host and the boundary's reason are recorded
/// host-side — the operator needs both to seed a grant — while only the guest's
/// error is masked.
fn record_denial(id: &PluginInstanceId, host: &str, reason: &str) {
    ::zeroclaw_log::record!(
        WARN,
        ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Note)
            .with_outcome(::zeroclaw_log::EventOutcome::Failure)
            .with_attrs(::serde_json::json!({
                "plugin": id.package(),
                "capability": format!("{:?}", id.capability()),
                "binding": id.binding(),
                "host": host,
                "reason": reason,
                "error_key": "plugin_egress_denied",
            })),
        "Denied plugin outbound request by egress policy"
    );
}

/// ZeroClaw's replacement for wasmtime's default `wasi:http` hooks.
///
/// One per plugin store. `egress: None` is the deny-by-default state.
pub(crate) struct PluginEgressHooks {
    scope: PluginInstanceScope,
    egress: Option<EgressHostService>,
}

impl PluginEgressHooks {
    pub(crate) fn new(scope: PluginInstanceScope, egress: Option<EgressHostService>) -> Self {
        Self { scope, egress }
    }
}

impl WasiHttpHooks for PluginEgressHooks {
    fn send_request(
        &mut self,
        request: hyper::Request<HyperOutgoingBody>,
        config: OutgoingRequestConfig,
    ) -> wasmtime_wasi_http::p2::HttpResult<HostFutureIncomingResponse> {
        let Some(authority) = request.uri().authority().cloned() else {
            return Ok(HostFutureIncomingResponse::ready(Ok(Err(
                ErrorCode::HttpRequestUriInvalid,
            ))));
        };
        let host = authority.host().to_string();
        let port = authority
            .port_u16()
            .unwrap_or(if config.use_tls { 443 } else { 80 });

        // Deny by default, before anything is spawned and before any name is
        // looked up: a store that links `wasi:http` without a host-owned egress
        // service reaches nothing.
        let Some(service) = self.egress.clone() else {
            record_denial(
                self.scope.id(),
                &host,
                "no egress policy granted for this instance",
            );
            return Ok(HostFutureIncomingResponse::ready(Ok(Err(denied()))));
        };

        // `encrypted` is the confidentiality mode, not a second permission axis:
        // the operator's grant covers a host, and plain HTTP to a granted host
        // is permitted. The transport is what selects the effective grant the
        // boundary re-checks.
        let egress_request = match EgressRequest::new(
            self.scope.clone(),
            EgressTransport::Http {
                encrypted: config.use_tls,
            },
            &host,
            port,
        ) {
            Ok(request) => request,
            // A malformed destination never becomes a request, so it never
            // reaches DNS. The guest still sees only the masked denial.
            Err(error) => {
                record_denial(self.scope.id(), &host, &error.to_string());
                return Ok(HostFutureIncomingResponse::ready(Ok(Err(denied()))));
            }
        };

        let id = self.scope.id().clone();
        let handle = wasmtime_wasi::runtime::spawn(async move {
            Ok(send(request, config, egress_request, service, id).await)
        });
        Ok(HostFutureIncomingResponse::pending(handle))
    }
}

/// The host-owned pinned send path.
///
/// This mirrors the mechanics of `wasmtime_wasi_http::p2::default_send_request_handler`
/// — same `Host` header fill-in, same connect/first-byte timeouts, same
/// origin-form URI rewrite before `send_request`, same hyper http1 handshake and
/// worker task — but replaces its single `TcpStream::connect(authority)` (which
/// resolves and connects in one unobservable step) with **authorize, then
/// connect to an address the boundary already validated**.
async fn send(
    mut request: hyper::Request<HyperOutgoingBody>,
    config: OutgoingRequestConfig,
    egress_request: EgressRequest,
    service: EgressHostService,
    id: PluginInstanceId,
) -> Result<IncomingResponse, ErrorCode> {
    use http_body_util::BodyExt;
    use tokio::net::TcpStream;
    use tokio::time::timeout;

    if !request.headers().contains_key(HOST)
        && let Some(authority) = request.uri().authority()
        && let Ok(value) = hyper::header::HeaderValue::from_str(authority.as_str())
    {
        request.headers_mut().insert(HOST, value);
    }

    // ── authorize ────────────────────────────────────────────────
    // The shared boundary checks the effective grant and the operator's
    // allowlist *before* it resolves anything, then performs the one resolution
    // and pins what it validated. Bounding the whole call with the same
    // `connect_timeout` the default path applies to its combined
    // resolve-and-connect keeps a stalled resolver from hanging the guest.
    //
    // The requested host is scoped to this block on purpose: past it the only
    // host in hand is the pin's, so there is nothing left to resolve a second
    // time.
    let authorized = {
        let host = egress_request.host().to_string();
        match timeout(config.connect_timeout, service.authorize(egress_request)).await {
            Ok(Ok(authorized)) => authorized,
            Ok(Err(error)) => {
                record_denial(&id, &host, &error.to_string());
                return Err(match error {
                    EgressError::DnsFailed { .. }
                    | EgressError::Network(NetworkGuardError::NoAddresses { .. }) => dns_failure(),
                    _ => denied(),
                });
            }
            Err(_) => return Err(ErrorCode::ConnectionTimeout),
        }
    };

    // ── connect (pinned) ─────────────────────────────────────────
    // Connect by `SocketAddr`, never by name: these are the addresses the
    // boundary validated, so no second resolution can substitute a different
    // class. `ResolvedDestination` is never empty, so the fallback here is
    // unreachable rather than a policy decision.
    let address = *authorized
        .destination()
        .addresses()
        .first()
        .ok_or_else(dns_failure)?;
    // Canonical host from the pin, used for SNI and certificate verification —
    // never for a second resolution.
    let server_name = authorized.destination().host().to_string();

    let tcp_stream = timeout(config.connect_timeout, TcpStream::connect(address))
        .await
        .map_err(|_| ErrorCode::ConnectionTimeout)?
        .map_err(|_| ErrorCode::ConnectionRefused)?;

    let (mut sender, worker) = if config.use_tls {
        use rustls::pki_types::ServerName;
        use wasmtime_wasi_http::io::TokioIo;

        let root_cert_store = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.into(),
        };
        let tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_cert_store)
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(tls_config));
        let domain = ServerName::try_from(server_name).map_err(|_| ErrorCode::TlsProtocolError)?;
        let stream = connector
            .connect(domain, tcp_stream)
            .await
            .map_err(|_| ErrorCode::TlsProtocolError)?;
        handshake(TokioIo::new(stream), config.connect_timeout, authorized).await?
    } else {
        use wasmtime_wasi_http::io::TokioIo;
        handshake(TokioIo::new(tcp_stream), config.connect_timeout, authorized).await?
    };

    // hyper's `SendRequest` does not strip scheme/authority, and an origin
    // server must receive origin-form; same rewrite the default path does.
    *request.uri_mut() = hyper::Uri::builder()
        .path_and_query(
            request
                .uri()
                .path_and_query()
                .map_or("/", |p| p.as_str())
                .to_string(),
        )
        .build()
        .map_err(|_| ErrorCode::HttpRequestUriInvalid)?;

    let resp = timeout(config.first_byte_timeout, sender.send_request(request))
        .await
        .map_err(|_| ErrorCode::ConnectionReadTimeout)?
        .map_err(|_| ErrorCode::HttpProtocolError)?
        .map(|body| {
            body.map_err(|_| ErrorCode::HttpProtocolError)
                .boxed_unsync()
        });

    Ok(IncomingResponse {
        resp,
        worker: Some(worker),
        between_bytes_timeout: config.between_bytes_timeout,
    })
}

/// Drive one hyper http1 handshake and spawn its connection worker.
///
/// `authorized` travels into the worker rather than being dropped here: the
/// token holds this instance's connection slot, and the slot has to last as long
/// as the connection it paid for, not as long as [`send`].
async fn handshake<S>(
    stream: S,
    connect_timeout: Duration,
    authorized: AuthorizedEgress,
) -> Result<
    (
        hyper::client::conn::http1::SendRequest<HyperOutgoingBody>,
        wasmtime_wasi::runtime::AbortOnDropJoinHandle<()>,
    ),
    ErrorCode,
>
where
    S: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let (sender, conn) = tokio::time::timeout(
        connect_timeout,
        hyper::client::conn::http1::handshake(stream),
    )
    .await
    .map_err(|_| ErrorCode::ConnectionTimeout)?
    .map_err(|_| ErrorCode::HttpProtocolError)?;

    let worker = wasmtime_wasi::runtime::spawn(async move {
        let outcome = conn.await;
        drop(authorized);
        if let Err(error) = outcome {
            ::zeroclaw_log::record!(
                DEBUG,
                ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Note)
                    .with_outcome(::zeroclaw_log::EventOutcome::Failure)
                    .with_attrs(::serde_json::json!({ "error": format!("{error}") })),
                "plugin egress connection ended with an error"
            );
        }
    });

    Ok((sender, worker))
}

#[cfg(test)]
mod tests {
    use http_body_util::BodyExt;

    use super::*;
    use crate::egress::{EgressPolicy, EgressPolicyResolver};
    use crate::{PluginCapability, PluginPermission};

    fn hooks(egress: Option<EgressHostService>) -> PluginEgressHooks {
        let scope = crate::instance::test_scope(
            PluginCapability::Tool,
            "main",
            [PluginPermission::HttpClient],
        );
        PluginEgressHooks::new(scope, egress)
    }

    fn request(uri: &str) -> hyper::Request<HyperOutgoingBody> {
        let body = http_body_util::Empty::<hyper::body::Bytes>::new()
            .map_err(|_| unreachable!("an empty body cannot fail"))
            .boxed_unsync();
        hyper::Request::builder()
            .uri(uri)
            .body(body)
            .expect("valid fixture request")
    }

    fn config() -> OutgoingRequestConfig {
        OutgoingRequestConfig {
            use_tls: false,
            connect_timeout: Duration::from_secs(1),
            first_byte_timeout: Duration::from_secs(1),
            between_bytes_timeout: Duration::from_secs(1),
        }
    }

    fn denial(response: HostFutureIncomingResponse) -> ErrorCode {
        match response {
            HostFutureIncomingResponse::Ready(Ok(Err(code))) => code,
            other => panic!("expected a synchronous denial, got: {other:?}"),
        }
    }

    /// Deny-by-default is answered synchronously, before a task is spawned and
    /// before the host looks anything up. The e2e proves no packet leaves; this
    /// proves the refusal does not even reach the async send path.
    #[test]
    fn a_store_without_an_egress_service_denies_without_spawning() {
        let mut hooks = hooks(None);
        for uri in [
            "http://example.com/",
            "http://127.0.0.1:9/",
            "http://api.internal/",
        ] {
            let response = hooks
                .send_request(request(uri), config())
                .expect("a denial is a guest-visible error, never a trap");
            assert!(
                matches!(denial(response), ErrorCode::InternalError(Some(message)) if message == DENIED_MESSAGE),
                "{uri} must be denied without a granted policy"
            );
        }
    }

    /// A destination the shared boundary cannot even accept as a request host is
    /// refused on the same masked path, not reported as a distinct condition.
    #[test]
    fn a_malformed_request_host_is_denied_without_resolving() {
        let service = EgressHostService::new(EgressPolicyResolver::new(|_| {
            EgressPolicy::new(&["example.com".to_string()], &[], &[], 4)
        }));
        let mut hooks = hooks(Some(service));
        let response = hooks
            .send_request(request("http://exa_mple.com/"), config())
            .expect("a denial is a guest-visible error, never a trap");
        assert!(matches!(
            denial(response),
            ErrorCode::InternalError(Some(message)) if message == DENIED_MESSAGE
        ));
    }

    #[test]
    fn denial_message_names_the_policy_and_leaks_no_host() {
        let ErrorCode::InternalError(Some(message)) = denied() else {
            panic!("denial must carry a message");
        };
        assert!(message.contains("egress policy"), "{message}");
        assert!(!message.contains("127.0.0.1"), "{message}");
    }
}
