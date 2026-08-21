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
//!   principal. `ControlSession::unregistered()` is the only session
//!   constructor production code can reach, so a released build has no
//!   inhabited grant at all.
//!
//! # stdout discipline
//!
//! The stdio channel carries newline-delimited JSON-RPC frames and nothing
//! else. Requests are awaited in sequence rather than handed to spawned tasks,
//! so two responses can never interleave bytes, and every diagnostic goes
//! through `zeroclaw_log`, which writes to stderr.

use std::path::PathBuf;

use anyhow::Result;
use serde_json::{Value, json};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt};
use zeroclaw_api::jsonrpc::error_codes;
use zeroclaw_control::protocol::{
    Advertisement, CONTROL_PROTOCOL_MAJOR, CatalogRequest, ControlErrorCode, DescribeRequest,
    Diagnostic, Envelope, ErrorPayload, InspectRequest, InspectResult, LOCAL_TARGET_ID,
    OPERATION_AGENT_CREATE_CONTAINED, PingResult, PreviewRequest, PreviewResult, ProtocolError,
    ServerInfoResult, SessionInfo, TOOL_CATALOG, TOOL_DESCRIBE, TOOL_INSPECT, TOOL_PING,
    TOOL_PREVIEW, TOOL_REGISTRATION_HELP, TOOL_SERVER_INFO, TOOL_VALIDATE, TOOLS, TargetRef,
    TargetSelector, ValidateRequest, ValidateResult, canonical_json, catalog, dependency_digest,
    describe, diagnostic_for, inspect_view, instance_fingerprint, operation_digest,
    operation_digest_for, preview_effects, preview_risks, protocol_error_for, sha256_hex,
    source_revision_id, verification_plan,
};
use zeroclaw_control::{
    ControlError, ControlInspection, ControlService, ControlSession, PROPOSAL_DOMAIN_AGENT,
    ProposalPreview, registration_help,
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

/// One read-only control session over a stdio JSON-RPC channel.
pub struct ControlMcpServer {
    service: ControlService,
    session: ControlSession,
    advertisement: Advertisement,
    process_nonce: String,
}

impl ControlMcpServer {
    /// The server a launched `zeroclaw control --mcp` process runs.
    ///
    /// The config root is pinned here, at startup, and no tool accepts a target
    /// path afterwards. The session is unregistered because registration is an
    /// operator ceremony on the host that phase 3 introduces; nothing this
    /// process can observe about itself upgrades that classification.
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
    /// A caller can only supply a registered session if it can construct a
    /// `RequesterGrant`, which is possible only under the control crate's
    /// test-only `fixture-grants` feature. In a released build this constructor
    /// is therefore equivalent to [`ControlMcpServer::new`].
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

/// Run the read-only control MCP server on this process's stdin and stdout.
///
/// # Errors
///
/// Propagates a failure to write a response frame.
pub async fn run(config_path: impl Into<PathBuf>) -> Result<()> {
    let mut server = ControlMcpServer::new(config_path, env!("CARGO_PKG_VERSION"));
    let stdin = tokio::io::BufReader::new(tokio::io::stdin());
    let mut stdout = tokio::io::stdout();
    server.serve(stdin, &mut stdout).await
}
