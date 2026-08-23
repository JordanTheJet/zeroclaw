//! The read-only stdio MCP transport for the control plane.
//!
//! This module is a protocol adapter and nothing else. It frames JSON-RPC over
//! stdio, resolves a tool name, calls `ControlService`, and projects the result
//! into the wire types that `zeroclaw_control::protocol` defines. It owns no
//! policy: which tools exist, who may call them, what an error says, and what a
//! result looks like are all decided in the control crate so a future native
//! in-process transport reaches identical answers.
//!
//! # What this transport cannot do
//!
//! - **It cannot mutate host state.** `ControlService::apply` is never named
//!   here, and no tool in `zeroclaw_control::protocol::TOOLS` maps to it. The
//!   only way to reach a revision-bound commit is to consume a `BoundProposal`,
//!   and this module drops every one it creates.
//! - **It cannot make a model request.** Nothing in this file imports or names
//!   a provider factory, a `ModelProvider`, or anything from
//!   `zeroclaw_providers`. The three `ControlService` methods it calls —
//!   `inspect`, `provider_inventory`, and `preview` — read configuration and
//!   run pure validators. Provider *construction* lives behind
//!   `CapabilityRestrictedProviderFactory::create_isolated_model_provider_for_alias`,
//!   which only `ZeronaSession` calls and which this transport never reaches.
//! - **It cannot register itself.** Launching the command creates a requester
//!   principal. A session becomes registered only by *presenting* a credential
//!   an operator ceremony already minted, and only the control crate decides
//!   whether that credential authenticates. This module carries the secret from
//!   the operator's chosen delivery mechanism to `authenticate_client` and
//!   holds no opinion about the answer.
//!
//! # Credential delivery
//!
//! The principals design allows exactly two delivery assurance classes, and
//! this transport implements exactly one mechanism for each. Which mechanism
//! was used *is* the presented class: it is not a value the caller states, so a
//! client cannot claim an assurance it did not achieve.
//!
//! | Mechanism | Presented class |
//! |---|---|
//! | An inherited descriptor named by `ZEROCLAW_CONTROL_CREDENTIAL_FD` | `isolated_descriptor` |
//! | A helper command named by `--credential-helper` | `sandbox_isolated_store` |
//!
//! Neither mechanism puts secret material on `argv` or in an environment
//! *value*:
//!
//! - `ZEROCLAW_CONTROL_CREDENTIAL_FD` carries a **descriptor number**, not a
//!   credential. The number is meaningless outside this process's descriptor
//!   table: anyone reading the environment of this process learns "fd 3", which
//!   is not a secret and cannot be redeemed anywhere. The secret itself travels
//!   through the descriptor, which the supervising client opened and which an
//!   agent subprocess does not inherit. This is the mechanism the design calls
//!   an inherited descriptor, and reading a number out of the environment to
//!   find it is not the thing the design forbids — passing the credential
//!   *itself* through "an ordinary environment variable" is.
//! - `--credential-helper` carries a **command name**. The command is executed
//!   directly, with no shell, no arguments, and no interpretation, so no part
//!   of a secret can be spliced into it.
//!
//! # stdout discipline
//!
//! The stdio channel carries newline-delimited JSON-RPC frames and nothing
//! else. Requests are awaited in sequence rather than handed to spawned tasks,
//! so two responses can never interleave bytes, and every diagnostic goes
//! through `zeroclaw_log`, which writes to stderr.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Result;
use serde_json::{Value, json};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroclaw_api::jsonrpc::error_codes;
use zeroclaw_control::protocol::{
    Advertisement, CONTROL_PROTOCOL_MAJOR, CatalogRequest, ControlErrorCode, DescribeRequest,
    Diagnostic, Envelope, ErrorPayload, InspectRequest, InspectResult, LOCAL_TARGET_ID,
    OPERATION_AGENT_CREATE_CONTAINED, PingResult, PreviewRequest, PreviewResult, ProtocolError,
    STARTUP_REFUSAL_META_KEY, ServerInfoResult, SessionInfo, StartupRefusal, StartupRefusalCode,
    TOOL_CATALOG, TOOL_DESCRIBE, TOOL_INSPECT, TOOL_PING, TOOL_PREVIEW, TOOL_REGISTRATION_HELP,
    TOOL_SERVER_INFO, TOOL_VALIDATE, TOOLS, TargetRef, TargetSelector, ValidateRequest,
    ValidateResult, canonical_json, catalog, dependency_digest, describe, diagnostic_for,
    inspect_view, instance_fingerprint, operation_digest, operation_digest_for, preview_effects,
    preview_risks, protocol_error_for, sha256_hex, source_revision_id, verification_plan,
};
use zeroclaw_control::{
    ClientCredential, ControlError, ControlInspection, ControlPaths, ControlService,
    ControlSession, CredentialDelivery, PROPOSAL_DOMAIN_AGENT, ProposalPreview,
    authenticate_client, registration_help,
};
use zeroclaw_runtime::quickstart::Surface;

/// The MCP lifecycle protocol version this server speaks.
///
/// Distinct from the control protocol version: this one governs `initialize`,
/// `tools/list`, and `tools/call` framing. It is the same constant the
/// workspace's MCP *client* uses, so both halves of the repository agree.
const MCP_PROTOCOL_VERSION: &str = zeroclaw_tools::mcp_protocol::MCP_PROTOCOL_VERSION;

/// The `serverInfo.name` an MCP client sees.
const SERVER_NAME: &str = "zeroclaw-control";

/// How long a preview stays fresh. Process-local and advisory: v1 parks no
/// proposal, so nothing durable expires.
const PREVIEW_TTL_SECONDS: i64 = 900;

/// Frames larger than this end the session rather than being buffered further.
const MAX_FRAME_BYTES: usize = 4 * 1024 * 1024;

/// Names the descriptor the credential arrives on. Carries a **number**, never
/// secret material — see the module documentation.
const CREDENTIAL_FD_ENV: &str = "ZEROCLAW_CONTROL_CREDENTIAL_FD";

/// Upper bound on what a delivery mechanism may hand back.
///
/// A credential is 64 hex characters plus a newline. The cap is generous enough
/// to tolerate a helper that adds trailing whitespace and small enough that a
/// runaway or hostile helper cannot make this process buffer without bound. The
/// read stops at the cap rather than after it, so oversize input is refused
/// rather than truncated into something that might parse.
const MAX_CREDENTIAL_BYTES: u64 = 4096;

/// How long a credential helper may take.
///
/// Short on purpose: a helper is expected to read a local file or query an
/// already-unlocked store. A helper that blocks on a prompt has not achieved
/// the sandbox-isolated-store class this mechanism claims, and hanging the
/// server on it would turn a misconfiguration into an unexplained stall.
const CREDENTIAL_HELPER_TIMEOUT: Duration = Duration::from_secs(5);

/// The exclusive host lock, under the control state directory.
const HOST_LOCK_FILE: &str = "host.lock";

/// The lowest descriptor number the inherited-descriptor mechanism accepts.
///
/// 0, 1, and 2 are refused. Standard input and standard output *are* the
/// protocol channel, so reading a credential from one would consume the client's
/// frames; and a credential delivered on a descriptor the client is also using
/// for diagnostics is not isolated in any sense the design would recognize.
const LOWEST_ACCEPTED_CREDENTIAL_FD: i32 = 3;

/// One read-only control session over a stdio JSON-RPC channel.
pub struct ControlMcpServer {
    service: ControlService,
    session: ControlSession,
    advertisement: Advertisement,
    process_nonce: String,
}

impl ControlMcpServer {
    /// The server a launched `zeroclaw control --mcp` process runs when it
    /// presents no credential.
    ///
    /// The config root is pinned here, at startup, and no tool accepts a target
    /// path afterwards. The session is unregistered because nothing was
    /// presented: registration is an operator ceremony on the host, and nothing
    /// this process can observe about itself — a TTY, a loopback address, its
    /// parent, its OS account, an environment value — upgrades that
    /// classification. A session that *did* present a credential is built by
    /// [`start`] instead, from a grant the control crate verified.
    ///
    /// `Surface::Cli` attributes commits this transport cannot perform. It is
    /// required to build a `ControlService` and is never consulted, because
    /// `apply` is unreachable from here.
    #[must_use]
    pub fn new(config_path: impl Into<PathBuf>, zeroclaw_version: &str) -> Self {
        Self::with_service_and_session(
            ControlService::new(config_path, Surface::Cli),
            ControlSession::unregistered(),
            zeroclaw_version,
        )
    }

    /// The same server over an explicitly constructed service and session.
    ///
    /// A caller can supply a registered session only if it holds a
    /// `ControlSession::Registered`, and the only two things that produce one
    /// are `zeroclaw_control::authenticate_client` — which demands a verified
    /// registration on this instance — and the control crate's test-only
    /// `fixture-grants` constructors. Passing a session in does not create
    /// authority; it carries authority that was already established.
    #[must_use]
    pub fn with_service_and_session(
        service: ControlService,
        session: ControlSession,
        zeroclaw_version: &str,
    ) -> Self {
        Self {
            service,
            session,
            advertisement: Advertisement::current(zeroclaw_version),
            process_nonce: process_nonce(),
        }
    }

    /// Read newline-delimited JSON-RPC frames from `reader` until end of input,
    /// answering each one on `writer`.
    ///
    /// A frame that does not parse gets a JSON-RPC parse error with a null id
    /// and the loop continues, matching how the workspace's MCP client tolerates
    /// a malformed peer. A notification — a request with no `id` — is handled
    /// and produces no output, as JSON-RPC requires.
    ///
    /// # Errors
    ///
    /// Propagates a write failure on `writer`. A read failure ends the session
    /// cleanly, because a closed stdin is how an MCP client says goodbye.
    pub async fn serve<R, W>(&mut self, mut reader: R, writer: &mut W) -> Result<()>
    where
        R: AsyncBufRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        let mut frame = Vec::new();
        loop {
            frame.clear();
            let read = match reader.read_until(b'\n', &mut frame).await {
                Ok(0) | Err(_) => return Ok(()),
                Ok(read) => read,
            };
            if read > MAX_FRAME_BYTES {
                write_frame(
                    writer,
                    &json!({
                        "jsonrpc": "2.0",
                        "id": Value::Null,
                        "error": {
                            "code": error_codes::INVALID_REQUEST,
                            "message": "Request frame exceeds the maximum size.",
                        },
                    }),
                )
                .await?;
                return Ok(());
            }
            let trimmed = trim_frame(&frame);
            if trimmed.is_empty() {
                continue;
            }
            if let Some(response) = Box::pin(self.handle_frame(trimmed)).await {
                write_frame(writer, &response).await?;
            }
        }
    }

    /// The response one frame produces, or `None` for a notification.
    pub async fn handle_frame(&self, frame: &[u8]) -> Option<Value> {
        let Ok(request) = serde_json::from_slice::<Value>(frame) else {
            return Some(json!({
                "jsonrpc": "2.0",
                "id": Value::Null,
                "error": {
                    "code": error_codes::PARSE_ERROR,
                    "message": "Request is not valid JSON.",
                },
            }));
        };
        let id = request.get("id").cloned();
        let method = request.get("method").and_then(Value::as_str).unwrap_or("");
        let params = request.get("params").cloned().unwrap_or(Value::Null);

        let outcome = Box::pin(self.dispatch(method, &params)).await;
        // A notification carries no id and must never be answered, even when
        // the method was unknown or the handler refused.
        let id = id?;
        Some(match outcome {
            Ok(result) => json!({ "jsonrpc": "2.0", "id": id, "result": result }),
            Err(error) => json!({ "jsonrpc": "2.0", "id": id, "error": error }),
        })
    }

    async fn dispatch(&self, method: &str, params: &Value) -> Result<Value, Value> {
        match method {
            "initialize" => self.initialize(params),
            // MCP `ping` answers with an empty result; the two lifecycle
            // notifications answer with nothing at all, because
            // `handle_frame` discards a response to a frame with no id.
            "notifications/initialized" | "notifications/cancelled" | "ping" => Ok(json!({})),
            "tools/list" => Ok(self.tools_list()),
            "tools/call" => Ok(Box::pin(self.tools_call(params)).await),
            _ => Err(json!({
                "code": error_codes::METHOD_NOT_FOUND,
                "message": format!("Method not found: {method}"),
            })),
        }
    }

    /// The MCP lifecycle handshake.
    ///
    /// A client that declares a control-protocol range with no major version in
    /// common with this server is refused here rather than allowed to discover
    /// the mismatch one tool call later. A client that declares nothing is
    /// accepted and reads the advertised version out of the result.
    fn initialize(&self, params: &Value) -> Result<Value, Value> {
        let declared = params
            .get("_meta")
            .and_then(|meta| meta.get("zeroclaw_control"))
            .and_then(|block| block.get("supported_control_protocol_versions"))
            .and_then(Value::as_array);
        if let Some(versions) = declared
            && !versions.iter().filter_map(Value::as_str).any(major_matches)
        {
            let refusal =
                ProtocolError::new(ControlErrorCode::UnsupportedProtocolVersion, "initialize");
            let message = refusal.message.clone();
            return Err(json!({
                "code": error_codes::INVALID_PARAMS,
                "message": message,
                "data": ErrorPayload::from(refusal),
            }));
        }
        Ok(json!({
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "capabilities": { "tools": {} },
            "serverInfo": {
                "name": SERVER_NAME,
                "version": &self.advertisement.zeroclaw_version,
            },
            // The advertisement block is carried here and repeated verbatim by
            // `control.server_info`; a test proves the two are byte-identical.
            "_meta": { "zeroclaw_control": &self.advertisement },
        }))
    }

    /// The tools this session can see.
    ///
    /// Grant-gated tools are absent for an unregistered session. Absence is the
    /// primary control; the refusal in [`ControlMcpServer::tools_call`] is the
    /// backstop for a client that calls a name it was never shown.
    fn tools_list(&self) -> Value {
        let tools: Vec<Value> = TOOLS
            .iter()
            .filter(|tool| self.session.can_see(tool))
            .map(|tool| {
                json!({
                    "name": tool.name,
                    "title": tool.title,
                    "description": tool.description,
                    "inputSchema": (tool.input_schema)(),
                })
            })
            .collect();
        json!({ "tools": tools })
    }

    async fn tools_call(&self, params: &Value) -> Value {
        let name = params.get("name").and_then(Value::as_str).unwrap_or("");
        let arguments = params
            .get("arguments")
            .cloned()
            .unwrap_or_else(|| json!({}));

        let Some(tool) = zeroclaw_control::protocol::tool(name) else {
            return tool_error(ProtocolError::new(ControlErrorCode::UnknownOperation, name));
        };
        if let Err(code) = self.session.authorize_tool(tool) {
            return tool_error(ProtocolError::new(code, name));
        }

        let outcome = match name {
            TOOL_PING => self.ping(),
            TOOL_SERVER_INFO => self.server_info(),
            TOOL_REGISTRATION_HELP => self.registration_help(),
            TOOL_CATALOG => self.catalog(&arguments),
            TOOL_DESCRIBE => self.describe(&arguments),
            TOOL_INSPECT => Box::pin(self.inspect(&arguments)).await,
            TOOL_VALIDATE => Box::pin(self.validate(&arguments)).await,
            TOOL_PREVIEW => Box::pin(self.preview(&arguments)).await,
            // Unreachable: the registry lookup above already rejected every
            // name this version does not define. Refusing rather than
            // panicking keeps a future registry entry without a handler
            // fail-closed.
            _ => Err(ProtocolError::new(ControlErrorCode::UnknownOperation, name)),
        };
        match outcome {
            Ok(result) => tool_result(&result),
            Err(refusal) => tool_error(refusal),
        }
    }

    fn ping(&self) -> Result<Value, ProtocolError> {
        envelope(&PingResult {
            ok: true,
            server_time: now_rfc3339(),
        })
    }

    fn server_info(&self) -> Result<Value, ProtocolError> {
        envelope(&ServerInfoResult {
            advertisement: self.advertisement.clone(),
            session: SessionInfo {
                registration_state: self.session.registration_state().to_string(),
                // Never upgraded by a TTY, a loopback address, the process
                // parent, the OS account, or an environment variable.
                requester_class: "external_requester".to_string(),
                assurance_class: self
                    .session
                    .grant()
                    .map(|grant| grant.assurance_class().to_string()),
            },
            // A statement about the protocol version, not about this instance.
            mutation_tools: Vec::new(),
            read_only: true,
        })
    }

    fn registration_help(&self) -> Result<Value, ProtocolError> {
        envelope(&registration_help(&self.session))
    }

    fn catalog(&self, arguments: &Value) -> Result<Value, ProtocolError> {
        let request = parse_arguments::<CatalogRequest>(arguments, TOOL_CATALOG)?;
        let mut result = catalog(request.domains.as_deref());
        // The specification's open question 7 asks whether Catalog is filtered
        // by the grant's proposal domains or is the full product catalogue.
        // Filtering is the conservative reading, so a narrowly granted client
        // learns only about what it could actually propose.
        result.operations.retain(|operation| {
            self.session
                .authorize_proposal_domain(&operation.domain)
                .is_ok()
        });
        envelope(&result)
    }

    fn describe(&self, arguments: &Value) -> Result<Value, ProtocolError> {
        let request = parse_arguments::<DescribeRequest>(arguments, TOOL_DESCRIBE)?;
        self.authorize_target(request.target.as_ref(), TOOL_DESCRIBE)?;
        // Same ordering rationale as `authorize_proposal`: operation existence
        // is a product fact, the grant gates everything instance-shaped.
        let Some(result) = describe(&request.operation_id) else {
            return Err(ProtocolError::new(
                ControlErrorCode::UnknownOperation,
                TOOL_DESCRIBE,
            ));
        };
        self.session
            .authorize_proposal_domain(PROPOSAL_DOMAIN_AGENT)
            .map_err(|code| ProtocolError::new(code, TOOL_DESCRIBE))?;
        envelope(&result)
    }

    async fn inspect(&self, arguments: &Value) -> Result<Value, ProtocolError> {
        let request = parse_arguments::<InspectRequest>(arguments, TOOL_INSPECT)?;
        self.authorize_target(request.target.as_ref(), TOOL_INSPECT)?;
        // A view the grant does not cover and a view this version does not
        // define are the same refusal, so probing discloses nothing.
        self.session
            .authorize_read_domain(&request.view)
            .map_err(|code| ProtocolError::new(code, TOOL_INSPECT))?;
        if let Some(operation_id) = &request.operation_id
            && operation_id != OPERATION_AGENT_CREATE_CONTAINED
        {
            return Err(ProtocolError::new(
                ControlErrorCode::UnknownOperation,
                TOOL_INSPECT,
            ));
        }

        let inspection = self.inspect_now(TOOL_INSPECT).await?;
        // `provider_inventory` validates configured aliases against the
        // capability-restricted rules. It resolves no endpoint and constructs
        // no provider client.
        let provider_refs = self.service.provider_inventory(&inspection).provider_refs;
        let Some((items, observations)) = inspect_view(&inspection, &provider_refs, &request.view)
        else {
            return Err(ProtocolError::new(
                ControlErrorCode::GrantRequired,
                TOOL_INSPECT,
            ));
        };
        envelope(&InspectResult {
            target: self.target_ref(),
            view: request.view.clone(),
            source_revision: source_revision_id(inspection.source_revision()),
            items,
            observations,
        })
    }

    async fn validate(&self, arguments: &Value) -> Result<Value, ProtocolError> {
        let request = parse_arguments::<ValidateRequest>(arguments, TOOL_VALIDATE)?;
        self.authorize_proposal(
            request.target.as_ref(),
            &request.operation_id,
            request.capability_digest.as_deref(),
            TOOL_VALIDATE,
        )?;
        let inspection = self.inspect_now(TOOL_VALIDATE).await?;
        let source_revision = source_revision_id(inspection.source_revision());
        self.check_revision_pin(
            request.source_revision.as_deref(),
            &source_revision,
            TOOL_VALIDATE,
        )?;

        let digest = operation_digest_for(&request.operation);
        let diagnostics = match self.service.preview(
            inspection,
            &request.operation.provider_alias,
            &request.operation.to_proposal(),
        ) {
            // The bound proposal is dropped here. Only `ControlService::apply`
            // consumes one, and nothing in this transport calls it.
            Ok(_) => Vec::new(),
            Err(ControlError::Proposal(rejection)) => vec![diagnostic_for(&rejection)],
            // A host failure is not a validation verdict, so it stays an error
            // rather than becoming `valid: false`.
            Err(other) => return Err(protocol_error_for(&other, TOOL_VALIDATE)),
        };
        envelope(&ValidateResult {
            valid: diagnostics.is_empty(),
            operation_digest: digest,
            source_revision,
            config_schema_version: self.advertisement.config_schema_version,
            diagnostics,
        })
    }

    async fn preview(&self, arguments: &Value) -> Result<Value, ProtocolError> {
        let request = parse_arguments::<PreviewRequest>(arguments, TOOL_PREVIEW)?;
        self.authorize_proposal(
            request.target.as_ref(),
            &request.operation_id,
            request.capability_digest.as_deref(),
            TOOL_PREVIEW,
        )?;
        let inspection = self.inspect_now(TOOL_PREVIEW).await?;
        let source_revision = source_revision_id(inspection.source_revision());
        self.check_revision_pin(
            request.source_revision.as_deref(),
            &source_revision,
            TOOL_PREVIEW,
        )?;

        let bound = self
            .service
            .preview(
                inspection,
                &request.operation.provider_alias,
                &request.operation.to_proposal(),
            )
            .map_err(|error| protocol_error_for(&error, TOOL_PREVIEW))?;
        let result = self.project_preview(bound.preview(), &source_revision);
        // `bound` is dropped without ever reaching `ControlService::apply`.
        envelope(&result)
    }

    /// Project a `ControlService` preview onto the wire type.
    ///
    /// Kept public so a transport-parity test can compare a preview obtained
    /// over MCP with one obtained by calling `ControlService` directly and
    /// projecting it the same way.
    #[must_use]
    pub fn project_preview(
        &self,
        preview: &ProposalPreview,
        source_revision: &str,
    ) -> PreviewResult {
        let digest = operation_digest(preview);
        let (effects, apply_order) = preview_effects(preview);
        PreviewResult {
            preview_id: self.preview_id(&digest),
            durable: false,
            dependency_digest: dependency_digest(preview),
            operation_digest: digest,
            target: self.target_ref(),
            source_revision: source_revision.to_string(),
            config_schema_version: self.advertisement.config_schema_version,
            expires_at: rfc3339_in(PREVIEW_TTL_SECONDS),
            effects,
            apply_order,
            // Adding one agent entry and writing canonical personality files
            // are both snapshot-reversible, so nothing lands here.
            irreversible_effects: Vec::new(),
            risks: preview_risks(),
            verification_plan: verification_plan(),
        }
    }

    /// The instance every result in this process is about.
    #[must_use]
    pub fn target_ref(&self) -> TargetRef {
        TargetRef {
            target_id: LOCAL_TARGET_ID.to_string(),
            instance_fingerprint: instance_fingerprint(self.service.config_path()),
        }
    }

    fn authorize_target(
        &self,
        target: Option<&TargetSelector>,
        operation: &str,
    ) -> Result<(), ProtocolError> {
        let target_id = target.map_or(LOCAL_TARGET_ID, |selector| selector.target_id.as_str());
        self.session
            .authorize_target(target_id)
            .map_err(|code| ProtocolError::new(code, operation))
    }

    fn authorize_proposal(
        &self,
        target: Option<&TargetSelector>,
        operation_id: &str,
        capability_digest: Option<&str>,
        operation: &str,
    ) -> Result<(), ProtocolError> {
        self.authorize_target(target, operation)?;
        // Operation existence is checked before the proposal-domain grant, and
        // that ordering is deliberate: the catalogue of operation *kinds* is a
        // product fact the specification states contains no configured instance
        // state, so `unknown_operation` discloses nothing about this host.
        // Everything after this point is instance-shaped and is gated first.
        if operation_id != OPERATION_AGENT_CREATE_CONTAINED {
            return Err(ProtocolError::new(
                ControlErrorCode::UnknownOperation,
                operation,
            ));
        }
        self.session
            .authorize_proposal_domain(PROPOSAL_DOMAIN_AGENT)
            .map_err(|code| ProtocolError::new(code, operation))?;
        if let Some(pinned) = capability_digest
            && pinned != self.advertisement.capability_digest
        {
            return Err(ProtocolError::new(
                ControlErrorCode::CapabilityDigestMismatch,
                operation,
            ));
        }
        Ok(())
    }

    fn check_revision_pin(
        &self,
        pinned: Option<&str>,
        current: &str,
        operation: &str,
    ) -> Result<(), ProtocolError> {
        if pinned.is_some_and(|revision| revision != current) {
            return Err(ProtocolError::new(
                ControlErrorCode::StaleSourceRevision,
                operation,
            ));
        }
        Ok(())
    }

    /// One canonical read of the pinned instance.
    ///
    /// Every tool call performs its own read rather than caching: the service's
    /// contract is that a revision is proven stable across one read, and a
    /// cached inspection would silently weaken that.
    async fn inspect_now(&self, operation: &str) -> Result<ControlInspection, ProtocolError> {
        // Boxed: `ControlInspection` carries a whole `Config`, and this future
        // is awaited several async frames deep inside the dispatch chain.
        Box::pin(self.service.inspect())
            .await
            .map_err(|error| protocol_error_for(&error, operation))
    }

    /// A process-local preview identifier.
    ///
    /// Derived from a per-process nonce and the operation digest, so it does
    /// not survive a restart, is not a resume secret, and conveys no authority.
    fn preview_id(&self, operation_digest: &str) -> String {
        let mut material = self.process_nonce.clone();
        material.push(':');
        material.push_str(operation_digest);
        format!("prv_{}", &sha256_hex(material.as_bytes())[..32])
    }
}

/// Wrap a result in the protocol envelope and serialize it.
fn envelope<T: serde::Serialize>(result: &T) -> Result<Value, ProtocolError> {
    serde_json::to_value(Envelope::new(result))
        .map_err(|_| ProtocolError::new(ControlErrorCode::InternalError, "control"))
}

/// The MCP `CallToolResult` for a successful control result.
///
/// `content[0].text` is the canonical serialization of the same value that goes
/// into `structuredContent`, for clients that cannot read structured output.
fn tool_result(value: &Value) -> Value {
    json!({
        "content": [{ "type": "text", "text": canonical_json(value) }],
        "structuredContent": value,
        "isError": false,
    })
}

/// The MCP `CallToolResult` for a typed refusal.
///
/// A refusal is a tool-level error, not a JSON-RPC error: the call itself was
/// well formed and the server answered it.
fn tool_error(refusal: ProtocolError) -> Value {
    let payload = serde_json::to_value(ErrorPayload::from(refusal)).unwrap_or(Value::Null);
    json!({
        "content": [{ "type": "text", "text": canonical_json(&payload) }],
        "structuredContent": payload,
        "isError": true,
    })
}

/// Deserialize a tool's arguments into its typed request.
///
/// A shape mismatch is `validation_failed` with a diagnostic naming the
/// argument object, never the serde message, which can quote submitted values.
fn parse_arguments<T: serde::de::DeserializeOwned>(
    arguments: &Value,
    operation: &str,
) -> Result<T, ProtocolError> {
    serde_json::from_value::<T>(arguments.clone()).map_err(|_| {
        ProtocolError::new(ControlErrorCode::ValidationFailed, operation).with_diagnostics(vec![
            Diagnostic {
                severity: "error".to_string(),
                code: "arguments_schema_mismatch".to_string(),
                path: "arguments".to_string(),
                message: "The arguments do not match this tool's generated input schema."
                    .to_string(),
            },
        ])
    })
}

fn major_matches(declared: &str) -> bool {
    declared
        .split('.')
        .next()
        .and_then(|major| major.parse::<u32>().ok())
        == Some(CONTROL_PROTOCOL_MAJOR)
}

fn trim_frame(frame: &[u8]) -> &[u8] {
    let mut end = frame.len();
    while end > 0 && (frame[end - 1] == b'\n' || frame[end - 1] == b'\r') {
        end -= 1;
    }
    &frame[..end]
}

async fn write_frame<W>(writer: &mut W, value: &Value) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut line = serde_json::to_string(value)?;
    line.push('\n');
    writer.write_all(line.as_bytes()).await?;
    writer.flush().await?;
    Ok(())
}

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

fn rfc3339_in(seconds: i64) -> String {
    (chrono::Utc::now() + chrono::Duration::seconds(seconds))
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// A value that differs between processes but discloses nothing about the host.
fn process_nonce() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_nanos());
    sha256_hex(format!("{}:{now}", std::process::id()).as_bytes())
}

// ---------------------------------------------------------------------------
// Credential delivery
// ---------------------------------------------------------------------------

/// How a launched process was told to obtain its client credential.
///
/// One variant per delivery assurance class the principals design accepts.
/// There is no third variant, so there is no mechanism this transport can use
/// that resolves to `uid_ambient` or to anything the fixture path spells.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialMechanism {
    /// A descriptor the supervising client opened and this process inherited.
    #[cfg(unix)]
    InheritedDescriptor(i32),
    /// A command that prints the credential on its standard output.
    Helper(PathBuf),
}

impl CredentialMechanism {
    /// The delivery assurance class using this mechanism *is*.
    ///
    /// Derived from the mechanism rather than declared by the caller: a client
    /// cannot present a credential one way and claim the other class, because
    /// no input names the class.
    #[must_use]
    pub const fn delivery_class(&self) -> CredentialDelivery {
        match self {
            #[cfg(unix)]
            Self::InheritedDescriptor(_) => CredentialDelivery::IsolatedDescriptor,
            Self::Helper(_) => CredentialDelivery::SandboxIsolatedStore,
        }
    }
}

/// What the command line and environment said about credential delivery.
///
/// Either both a client identifier and a mechanism, or neither. There is no
/// third shape, which is what makes "no credential was offered" and "a
/// credential was offered and failed" impossible to confuse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlLaunch {
    client_id: Option<String>,
    mechanism: Option<CredentialMechanism>,
}

impl ControlLaunch {
    /// The launch a process with no credential options has.
    ///
    /// Serves an unregistered session: exactly the surface, framing, and
    /// responses of a build with no registration support at all.
    #[must_use]
    pub const fn unregistered() -> Self {
        Self {
            client_id: None,
            mechanism: None,
        }
    }

    /// Resolve the launch from the two CLI options and the descriptor
    /// environment variable.
    ///
    /// Every incoherent combination is a refusal rather than a fallback,
    /// because the failure mode a fallback creates is the dangerous one: an
    /// operator who mistypes an option and silently gets an unregistered
    /// session sees "my client lost its tools" and has no way to tell that from
    /// a revoked registration.
    ///
    /// Refused combinations:
    ///
    /// - **Both mechanisms.** Which class was presented would be a coin toss.
    /// - **A mechanism with no `--client-id`.** The registration identifier is
    ///   attribution, not authentication, but without it the host would have to
    ///   guess which registration a secret belongs to, and "try them all" turns
    ///   one client's credential into a lookup across every registration.
    /// - **`--client-id` with no mechanism.** The operator asked for a
    ///   registered session and offered nothing to authenticate it with.
    /// - **A descriptor that is not a number, or is 0, 1, or 2.**
    /// - **A descriptor on a platform with no descriptor inheritance.**
    ///
    /// An absent environment variable is absent. An empty or blank one is
    /// present and malformed, and refuses.
    ///
    /// # Errors
    ///
    /// Returns [`StartupRefusalCode::CredentialMechanismInvalid`] for every
    /// combination above.
    pub fn resolve(
        client_id: Option<String>,
        credential_helper: Option<PathBuf>,
    ) -> Result<Self, StartupRefusal> {
        let invalid = || StartupRefusal::new(StartupRefusalCode::CredentialMechanismInvalid);
        let descriptor = std::env::var_os(CREDENTIAL_FD_ENV);

        let mechanism = match (descriptor, credential_helper) {
            (None, None) => None,
            (Some(_), Some(_)) => return Err(invalid()),
            (Some(raw), None) => Some(parse_descriptor_mechanism(&raw)?),
            (None, Some(command)) => {
                if command.as_os_str().is_empty() {
                    return Err(invalid());
                }
                Some(CredentialMechanism::Helper(command))
            }
        };

        let client_id = match client_id {
            Some(id) if id.trim().is_empty() => return Err(invalid()),
            other => other,
        };

        match (client_id, mechanism) {
            (None, None) => Ok(Self::unregistered()),
            (Some(client_id), Some(mechanism)) => Ok(Self {
                client_id: Some(client_id),
                mechanism: Some(mechanism),
            }),
            _ => Err(invalid()),
        }
    }

    /// Whether this launch presents a credential at all.
    #[must_use]
    pub const fn presents_credential(&self) -> bool {
        self.mechanism.is_some()
    }
}

/// Parse the descriptor environment value into a mechanism.
#[cfg(unix)]
fn parse_descriptor_mechanism(
    raw: &std::ffi::OsStr,
) -> Result<CredentialMechanism, StartupRefusal> {
    let invalid = || StartupRefusal::new(StartupRefusalCode::CredentialMechanismInvalid);
    let number: i32 = raw
        .to_str()
        .ok_or_else(invalid)?
        .trim()
        .parse()
        .map_err(|_| invalid())?;
    if number < LOWEST_ACCEPTED_CREDENTIAL_FD {
        return Err(invalid());
    }
    Ok(CredentialMechanism::InheritedDescriptor(number))
}

/// Descriptor inheritance is a POSIX contract. A platform without it has no
/// isolated-descriptor mechanism to offer, and pretending otherwise would let a
/// registration claim an assurance class the host cannot deliver.
#[cfg(not(unix))]
fn parse_descriptor_mechanism(
    _raw: &std::ffi::OsStr,
) -> Result<CredentialMechanism, StartupRefusal> {
    Err(StartupRefusal::new(
        StartupRefusalCode::CredentialMechanismInvalid,
    ))
}

/// Obtain the credential the mechanism names.
///
/// Bounded in size and, for the helper, in time. The bytes are parsed into a
/// [`ClientCredential`] — which has no `Serialize`, no `Display`, and a
/// redacted `Debug` — and the intermediate buffer is zeroed before this
/// function returns, so the only copy that outlives it is the one the control
/// crate will consume and drop.
async fn obtain_credential(
    mechanism: &CredentialMechanism,
) -> Result<ClientCredential, StartupRefusal> {
    let unavailable = || StartupRefusal::new(StartupRefusalCode::CredentialUnavailable);
    let mut raw = match mechanism {
        #[cfg(unix)]
        CredentialMechanism::InheritedDescriptor(fd) => read_inherited_descriptor(*fd)?,
        CredentialMechanism::Helper(command) => run_credential_helper(command).await?,
    };
    if raw.len() as u64 > MAX_CREDENTIAL_BYTES {
        raw.fill(0);
        return Err(unavailable());
    }
    let parsed = std::str::from_utf8(&raw)
        .ok()
        .and_then(|text| ClientCredential::from_delivery_hex(text).ok());
    raw.fill(0);
    parsed.ok_or_else(unavailable)
}

/// Read the credential from an inherited descriptor and close it.
///
/// Closing matters: a descriptor left open is a live handle on the credential
/// source for the whole life of the process, and this transport spawns nothing
/// that should ever be able to reach it.
#[cfg(unix)]
fn read_inherited_descriptor(fd: i32) -> Result<Vec<u8>, StartupRefusal> {
    use std::io::Read as _;
    use std::os::fd::FromRawFd as _;

    // SAFETY: the launching client's contract is that this descriptor number
    // names an open description it transferred to this process. Taking
    // ownership is what lets the read close it. A number that names nothing
    // fails the read below and refuses; 0, 1, and 2 were refused before this
    // point, so the protocol channel cannot be consumed here.
    let file = unsafe { std::fs::File::from_raw_fd(fd) };
    let mut out = Vec::new();
    file.take(MAX_CREDENTIAL_BYTES + 1)
        .read_to_end(&mut out)
        .map_err(|_| StartupRefusal::new(StartupRefusalCode::CredentialUnavailable))?;
    Ok(out)
}

/// Run the credential helper and read its standard output.
///
/// The command is the program, and only the program: it is passed to
/// `Command::new` with no arguments and no shell, so nothing in it is word
/// split, glob expanded, or substituted. An operator who needs arguments wraps
/// the invocation in a script and names the script here — which also gives the
/// approved-helper identity the design wants to record a single stable name.
///
/// The child gets a null standard input and a null standard error. Null stderr
/// is not tidiness: an inherited stderr on a helper that echoes what it read
/// would print a credential to the operator's terminal, and an inherited stdout
/// would interleave it with this server's JSON-RPC frames.
async fn run_credential_helper(command: &Path) -> Result<Vec<u8>, StartupRefusal> {
    let unavailable = || StartupRefusal::new(StartupRefusalCode::CredentialUnavailable);

    let collect = async {
        let mut child = tokio::process::Command::new(command)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            // Dropping this future on timeout must not leave the helper
            // running against a credential store.
            .kill_on_drop(true)
            .spawn()
            .map_err(|_| unavailable())?;

        let mut out = Vec::new();
        {
            let stdout = child.stdout.take().ok_or_else(unavailable)?;
            // Capped before buffering, not after: a helper that emits without
            // bound must not be able to exhaust this process's memory.
            stdout
                .take(MAX_CREDENTIAL_BYTES + 1)
                .read_to_end(&mut out)
                .await
                .map_err(|_| unavailable())?;
        }
        let status = child.wait().await.map_err(|_| unavailable())?;
        if !status.success() {
            out.fill(0);
            return Err(unavailable());
        }
        Ok(out)
    };

    match tokio::time::timeout(CREDENTIAL_HELPER_TIMEOUT, collect).await {
        Ok(result) => result,
        Err(_elapsed) => Err(unavailable()),
    }
}

// ---------------------------------------------------------------------------
// The exclusive host lock
// ---------------------------------------------------------------------------

/// Exclusive ownership of one instance's control host.
///
/// # Why there is no stale-lock policy
///
/// The lock is an advisory whole-file lock on an open file description, taken
/// with [`std::fs::File::try_lock`]. The kernel releases it when the holding
/// description is closed, which includes every way a process can die — clean
/// exit, panic, signal, power loss followed by a reboot. There is therefore no
/// such thing as a stale control host lock: a lock that is held is held by a
/// living process, and the file left on disk between runs is an empty
/// placeholder that carries no state and needs no cleanup. That is the whole
/// reason to use a file lock here rather than a lock *file* whose existence
/// means ownership, which would need a policy for deciding when to break it —
/// and a wrong policy there is how two hosts end up sharing an instance.
///
/// # Which sessions take it
///
/// Registered sessions only, and this is a deliberate narrowing of the design's
/// "daemonless hosting requires exclusive host and instance locks":
///
/// 1. An unregistered session reads no control-plane durable state, holds no
///    grant, and can reach nothing a second unregistered session could race it
///    for. There is nothing to serialize.
/// 2. Taking the lock requires the control state directory, which exists only
///    on an instance that has run genesis. Creating it for an unregistered
///    session would mean a read-only surface writing durable state onto an
///    uninitialized instance.
/// 3. It would newly refuse a second unregistered `zeroclaw control --mcp`,
///    which is a behavior change to the exact surface the phase-2 tests pin.
///
/// When the exclusive *instance* lock arrives with the mutation surface, it
/// will cover more than this. This lock covers what this phase has.
struct HostLock {
    /// Held for the lifetime of the process. The lock is a property of this
    /// open file description, so dropping the handle releases it.
    _file: std::fs::File,
}

impl HostLock {
    /// Take the exclusive host lock for the instance at `paths`.
    ///
    /// # Errors
    ///
    /// Returns [`StartupRefusalCode::HostAlreadyServing`] when another process
    /// holds it, and when the lock file cannot be opened or locked at all — a
    /// host whose lock cannot be evaluated must not be served, because the
    /// alternative is serving it twice.
    fn acquire(paths: &ControlPaths) -> Result<Self, StartupRefusal> {
        let refused = || StartupRefusal::new(StartupRefusalCode::HostAlreadyServing);
        let path = paths.control_dir().join(HOST_LOCK_FILE);

        let mut options = std::fs::OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let file = options.open(&path).map_err(|_| refused())?;

        match file.try_lock() {
            Ok(()) => Ok(Self { _file: file }),
            Err(_) => Err(refused()),
        }
    }
}

// ---------------------------------------------------------------------------
// Startup
// ---------------------------------------------------------------------------

/// A control server that has finished starting, plus whatever it holds.
pub struct ControlHost {
    server: ControlMcpServer,
    /// Present exactly when the session is registered. Dropped with the host,
    /// which is what releases the lock.
    _lock: Option<HostLock>,
}

impl ControlHost {
    /// The server this host runs.
    #[must_use]
    pub fn server(&self) -> &ControlMcpServer {
        &self.server
    }

    /// The server this host runs, mutably, for driving the serve loop.
    pub fn server_mut(&mut self) -> &mut ControlMcpServer {
        &mut self.server
    }
}

/// Start a control host: obtain and verify a credential if one was offered,
/// take the host lock if the session is registered, and build the server.
///
/// # No downgrade
///
/// A launch that presents no credential yields an unregistered host and touches
/// nothing else — no path resolution, no registry read, no lock. A launch that
/// presents one either yields a registered host or fails. There is no branch
/// that offers a credential, fails to make it work, and continues unregistered.
///
/// # Errors
///
/// Returns a [`StartupRefusal`] whose text is fixed and discloses no path,
/// client identifier, or presented value.
pub async fn start(
    config_path: impl Into<PathBuf>,
    zeroclaw_version: &str,
    launch: ControlLaunch,
) -> Result<ControlHost, StartupRefusal> {
    let config_path = config_path.into();
    let Some(mechanism) = launch.mechanism else {
        return Ok(ControlHost {
            server: ControlMcpServer::new(config_path, zeroclaw_version),
            _lock: None,
        });
    };
    // `ControlLaunch::resolve` is the only constructor that can produce a
    // mechanism, and it refuses a mechanism without an identifier, so this is
    // unreachable rather than a real branch. It refuses instead of unwrapping.
    let Some(client_id) = launch.client_id else {
        return Err(StartupRefusal::new(
            StartupRefusalCode::CredentialMechanismInvalid,
        ));
    };

    let credential = obtain_credential(&mechanism).await?;
    let install_root = config_path
        .parent()
        .ok_or_else(|| StartupRefusal::new(StartupRefusalCode::InstanceNotManaged))?;
    let authenticated = authenticate_client(
        install_root,
        &client_id,
        &credential,
        mechanism.delivery_class(),
    )?;
    // Zeroed here rather than at end of scope, so the secret is gone before
    // anything else runs.
    drop(credential);

    let lock = HostLock::acquire(&authenticated.paths)?;
    Ok(ControlHost {
        server: ControlMcpServer::with_service_and_session(
            ControlService::new(config_path, Surface::Cli),
            authenticated.session,
            zeroclaw_version,
        ),
        _lock: Some(lock),
    })
}

/// The one JSON-RPC frame a refusing process emits.
///
/// Carried under `error.data.control_startup_refusal` rather than
/// `error.data.error`, which is where a *tool* refusal from the frozen v1 table
/// lives. A client that reads one key or the other always knows which kind of
/// refusal it is holding.
#[must_use]
pub fn startup_refusal_frame(id: &Value, refusal: &StartupRefusal) -> Value {
    let mut data = serde_json::Map::new();
    data.insert(
        STARTUP_REFUSAL_META_KEY.to_string(),
        serde_json::to_value(refusal).unwrap_or(Value::Null),
    );
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": error_codes::INVALID_REQUEST,
            "message": refusal.message,
            "data": Value::Object(data),
        },
    })
}

/// Answer the first request with a startup refusal, then stop.
///
/// The alternative — exiting before writing anything — is worse for exactly the
/// reason the refusal exists: an MCP client whose server closes the pipe during
/// `initialize` reports a crashed server, and an operator who has just mistyped
/// a credential option learns nothing. One typed frame turns that into a
/// readable message, and the nonzero exit still tells a supervisor the process
/// did not serve. This mirrors how a control-protocol major-version mismatch is
/// already delivered at `initialize`.
///
/// Exactly one frame is written. The session is over either way.
///
/// # Errors
///
/// Propagates a failure to write the refusal frame.
pub async fn serve_refusal<R, W>(
    mut reader: R,
    writer: &mut W,
    refusal: &StartupRefusal,
) -> Result<()>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut frame = Vec::new();
    loop {
        frame.clear();
        let read = match reader.read_until(b'\n', &mut frame).await {
            Ok(0) | Err(_) => return Ok(()),
            Ok(read) => read,
        };
        if read > MAX_FRAME_BYTES {
            return Ok(());
        }
        let trimmed = trim_frame(&frame);
        if trimmed.is_empty() {
            continue;
        }
        // An unparseable first frame still gets the refusal, with a null id.
        // The reason this process is going away matters more than whose
        // request it was.
        let id = serde_json::from_slice::<Value>(trimmed)
            .ok()
            .and_then(|request| request.get("id").cloned())
            .unwrap_or(Value::Null);
        write_frame(writer, &startup_refusal_frame(&id, refusal)).await?;
        return Ok(());
    }
}

/// Run the read-only control MCP server on this process's stdin and stdout.
///
/// A refused start answers one request and returns the refusal, which the
/// binary reports on stderr and turns into a nonzero exit. It never serves an
/// unregistered session in place of a registered one it could not establish.
///
/// # Errors
///
/// Propagates a failure to write a response frame, and returns the
/// [`StartupRefusal`] when the process refused to serve.
pub async fn run(
    config_path: impl Into<PathBuf>,
    client_id: Option<String>,
    credential_helper: Option<PathBuf>,
) -> Result<()> {
    let config_path = config_path.into();
    let stdin = tokio::io::BufReader::new(tokio::io::stdin());
    let mut stdout = tokio::io::stdout();

    let started = match ControlLaunch::resolve(client_id, credential_helper) {
        Ok(launch) => start(config_path, env!("CARGO_PKG_VERSION"), launch).await,
        Err(refusal) => Err(refusal),
    };
    match started {
        Ok(mut host) => host.server_mut().serve(stdin, &mut stdout).await,
        Err(refusal) => {
            serve_refusal(stdin, &mut stdout, &refusal).await?;
            Err(anyhow::Error::new(refusal))
        }
    }
}
