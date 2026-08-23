//! The normative wire types for read-only control protocol v1.
//!
//! The protocol specification's first drift-prevention rule makes these Rust
//! types — not a document and not a hand-maintained schema artifact — the
//! source of truth for the wire shape. Every transport (the stdio MCP server
//! today, native in-process tools later) serializes exactly these types, so a
//! field cannot exist on one transport and not the other.
//!
//! Nothing in this module touches the filesystem, the clock, the network, or a
//! model provider. Values that need a clock (`server_time`, `expires_at`) or a
//! process identity (`preview_id`) are supplied by the transport, which keeps
//! every function here deterministic and therefore digestible.
//!
//! # Redaction
//!
//! The specification forbids secret values, absolute config, data, workspace,
//! credential, or plugin paths, account identifiers, raw provider error bodies,
//! environment values, and headers from appearing in any response — success or
//! error. That is enforced structurally rather than by review:
//!
//! - [`ProtocolError`] has no constructor that accepts caller-supplied prose.
//!   Its `message` comes from [`ControlErrorCode::message`], a fixed table of
//!   static strings, so a host error's `Display` can never reach the wire.
//! - The projections below take the crate's rich internal types
//!   (`ControlInspection`, `ProposalPreview`) and copy out only named,
//!   path-free fields. `PersistencePreview::config_path`,
//!   `workspace_dir`, and `PersonalityFilePreview::destination` are absolute
//!   paths and are deliberately dropped.
//! - [`Diagnostic::path`] is a *typed-operation field path* such as
//!   `personality_files[0].content`. It is never a filesystem path.

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::inventory::{MemoryChoice, RiskChoice, RuntimeChoice};
use crate::preview::ProposalPreview;
use crate::proposal::{AgentProposal, PersonalityFileProposal, ProposalError, ProposalErrorCode};
use crate::service::{ControlError, ControlInspection};

/// `major.minor` of this protocol. A major mismatch fails closed.
pub const CONTROL_PROTOCOL_VERSION: &str = "1.0";

/// The major component of [`CONTROL_PROTOCOL_VERSION`], used for negotiation.
pub const CONTROL_PROTOCOL_MAJOR: u32 = 1;

/// The capability identifiers this server implements.
///
/// The parent architecture document illustrates `["agents", "providers",
/// "plugins"]`, but that is a product-level list. A phase-2 server implements
/// contained agent creation only, and the specification's open question 4
/// resolves `capabilities` to "what the running server implements" because only
/// that reading is safe for negotiation.
pub const CAPABILITIES: &[&str] = &["agents"];

/// The one operation kind this protocol version can express.
pub const OPERATION_AGENT_CREATE_CONTAINED: &str = "agent.create_contained";

/// Read views this protocol version can resolve.
pub const VIEW_AGENT_SUMMARY: &str = "agent.summary";
/// The provider-alias inventory view.
pub const VIEW_PROVIDER_ALIAS_LIST: &str = "provider.alias_list";

/// Every view name in a stable order.
pub const VIEWS: &[&str] = &[VIEW_AGENT_SUMMARY, VIEW_PROVIDER_ALIAS_LIST];

/// The identifier of the single instance a control process is pinned to.
///
/// The specification assumes a signed target registry that phase 3 introduces.
/// A phase-2 process pins one config root at startup and can address no other
/// instance, so the registry degenerates to this one constant. Any other
/// `target_id` is [`ControlErrorCode::TargetNotRegistered`].
pub const LOCAL_TARGET_ID: &str = "local";

/// Liveness tool. Discloses no configured state.
pub const TOOL_PING: &str = "control.ping";
/// Advertisement plus bounded session facts.
pub const TOOL_SERVER_INFO: &str = "control.server_info";
/// Static operator guidance for registering this client.
pub const TOOL_REGISTRATION_HELP: &str = "control.registration_help";
/// Product-supported operation kinds.
pub const TOOL_CATALOG: &str = "control.catalog";
/// Typed requirements for one operation.
pub const TOOL_DESCRIBE: &str = "control.describe";
/// Redacted view of current relevant state.
pub const TOOL_INSPECT: &str = "control.inspect";
/// Validate a proposed typed operation.
pub const TOOL_VALIDATE: &str = "control.validate";
/// Canonical effects, risks, and verification plan.
pub const TOOL_PREVIEW: &str = "control.preview";
/// Park a preview-bound proposal for operator review. Durable journal only.
pub const TOOL_REQUEST_APPLY: &str = "control.request_apply";
/// Read the durable journal state of one of the requester's own operations.
pub const TOOL_STATUS: &str = "control.status";
/// Verify effective state for one of the requester's own completed operations.
pub const TOOL_VERIFY: &str = "control.verify";

/// Whether a tool is reachable without a registered requester grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolGate {
    /// Reachable by every session, including an unregistered one.
    Always,
    /// Requires a registered requester grant. Absent from `tools/list` for an
    /// unregistered session; absence is the primary control and
    /// [`ControlErrorCode::UnregisteredClient`] is the backstop.
    RegisteredGrant,
}

/// One entry in the frozen tool registry.
pub struct ToolDescriptor {
    /// The wire name a client calls.
    pub name: &'static str,
    /// Short human label.
    pub title: &'static str,
    /// What the tool does, for a client's tool list.
    pub description: &'static str,
    /// Whether a registered grant is required.
    pub gate: ToolGate,
    /// The read domains that make this tool reachable for a registered
    /// session, in **any** semantics: the grant must cover at least one.
    ///
    /// Empty for a [`ToolGate::Always`] tool, which no grant gates.
    ///
    /// The vocabulary is `client_registry::READ_DOMAINS_V1`, whose six members
    /// are the two Inspect views plus the four read-only tool names. Each gated
    /// tool other than `control.inspect` names exactly one domain — its own
    /// name — so for those "any" and "all" coincide. `control.inspect` names
    /// both views, because a registration granting either view has a view to
    /// resolve and Inspect is how it resolves it; the per-view check in
    /// [`crate::ControlSession::authorize_read_domain`] still refuses the view
    /// the grant does not cover.
    pub required_read_domains: &'static [&'static str],
    /// Generated JSON Schema for this tool's arguments.
    pub input_schema: fn() -> Value,
}

/// The complete tool surface of control protocol v1.
///
/// # Deviations from `control-plane-mcp-protocol-v1.md`
///
/// Recorded here rather than in a separate document so a reviewer reading the
/// tool list sees them. The specification's escape clause is that where it
/// demands something `ControlService` cannot express, the honest subset ships
/// and the delta is stated.
///
/// 1. **`control.catalog` lists exactly one operation.** `ControlService`
///    implements contained agent creation only, so the catalogue is
///    `agent.create_contained`. The specification's example already shows this
///    as the sole entry; the deviation is that there is no path by which a
///    second operation could appear.
/// 2. **`control.inspect` resolves two views, not an open set.**
///    `ControlService` exposes `inspect` (configuration) and
///    `provider_inventory`, which map to [`VIEW_AGENT_SUMMARY`] and
///    [`VIEW_PROVIDER_ALIAS_LIST`]. Any other view name is
///    [`ControlErrorCode::GrantRequired`].
/// 3. **`source_revision` is a content digest, not an opaque registry id.**
///    `ControlInspection::source_revision` is the raw config source *bytes*,
///    which must never reach a client. [`source_revision_id`] hashes them, so
///    the value is stable, comparable across calls, and preimage-resistant.
/// 4. **`target_id` is the constant [`LOCAL_TARGET_ID`]** — see that constant.
/// 5. **`Observation` reports schema currency, not reachability.** The
///    specification illustrates a `provider.default` / `reachable`
///    observation. A read-only phase-2 server makes no provider contact, so
///    reporting reachability would be a fabrication; the honest observation is
///    the one the schema gate actually computes.
/// 6. **`control.validate` and `control.preview` accept an optional
///    `capability_digest` and `source_revision` pin.** The specification's
///    request examples omit both, but it also requires
///    [`ControlErrorCode::CapabilityDigestMismatch`] and
///    [`ControlErrorCode::StaleSourceRevision`] to be producible, and the
///    parent document binds the capability digest into every proposal. Pins are
///    optional; omitting them cannot widen authority.
/// 7. **No mutation tool exists at any gate.** `ControlService::apply` is not
///    wired into this registry and cannot be reached from a transport that only
///    knows these names.
/// 8. **A registered session's tool list is the intersection of this registry
///    and the registration's read domains.** The specification fixes the
///    unregistered surface at exactly the three always-available tools and says
///    the rest "require a registered requester grant"; it does not say a grant
///    is all-or-nothing. The principals design does: a grant carries *explicit*
///    read domains and authorization is an intersection, never a union. So a
///    registration granting fewer domains lists fewer tools, and absence stays
///    the primary control.
pub const TOOLS: &[ToolDescriptor] = &[
    ToolDescriptor {
        name: TOOL_PING,
        title: "Ping",
        description: "Liveness check. Discloses no configured state, target identity, or registration status.",
        gate: ToolGate::Always,
        required_read_domains: &[],
        input_schema: empty_request_schema,
    },
    ToolDescriptor {
        name: TOOL_SERVER_INFO,
        title: "Server info",
        description: "The protocol advertisement block plus the bounded session facts an unregistered client needs to decide what to do next.",
        gate: ToolGate::Always,
        required_read_domains: &[],
        input_schema: empty_request_schema,
    },
    ToolDescriptor {
        name: TOOL_REGISTRATION_HELP,
        title: "Registration help",
        description: "Static operator guidance describing how a human registers this client. Initiates nothing and returns no credential material.",
        gate: ToolGate::Always,
        required_read_domains: &[],
        input_schema: empty_request_schema,
    },
    ToolDescriptor {
        name: TOOL_CATALOG,
        title: "Catalog",
        description: "Product-supported operation kinds. Contains no configured instance state.",
        gate: ToolGate::RegisteredGrant,
        required_read_domains: &[TOOL_CATALOG],
        input_schema: catalog_request_schema,
    },
    ToolDescriptor {
        name: TOOL_DESCRIBE,
        title: "Describe",
        description: "Current typed requirements and generated JSON Schemas for one operation.",
        gate: ToolGate::RegisteredGrant,
        required_read_domains: &[TOOL_DESCRIBE],
        input_schema: describe_request_schema,
    },
    ToolDescriptor {
        name: TOOL_INSPECT,
        title: "Inspect",
        description: "A redacted view of current relevant state, filtered by the requester's target and domain grant.",
        gate: ToolGate::RegisteredGrant,
        required_read_domains: VIEWS,
        input_schema: inspect_request_schema,
    },
    ToolDescriptor {
        name: TOOL_VALIDATE,
        title: "Validate",
        description: "Validate a proposed typed operation. No host effect and no durable state.",
        gate: ToolGate::RegisteredGrant,
        required_read_domains: &[TOOL_VALIDATE],
        input_schema: validate_request_schema,
    },
    ToolDescriptor {
        name: TOOL_PREVIEW,
        title: "Preview",
        description: "Canonical effects, risks, and verification plan for a proposed typed operation. No host effect.",
        gate: ToolGate::RegisteredGrant,
        required_read_domains: &[TOOL_PREVIEW],
        input_schema: preview_request_schema,
    },
    // The three phase-5 tools below share the `control.preview` read domain for
    // visibility, because the whole request/status/verify lifecycle belongs to a
    // client that first previewed the operation. Their *authorization* is
    // stronger than that read domain and is enforced in the transport handlers:
    // `control.request_apply` additionally requires the PROPOSAL domain (a read
    // grant is not enough) plus a mutations-enabled, managed instance, and it is
    // absent from `tools/list` entirely while mutations are disabled; the two
    // read tools scope every answer to the caller's own operations. None of the
    // three applies anything — `control.request_apply` writes the durable
    // journal only, and there is no model-callable approve, apply, or finalize.
    ToolDescriptor {
        name: TOOL_REQUEST_APPLY,
        title: "Request apply",
        description: "Park a preview-bound proposal for operator review. Durable journal only: it changes no config and conveys no approval authority. Refused while mutations are disabled.",
        gate: ToolGate::RegisteredGrant,
        required_read_domains: &[TOOL_PREVIEW],
        input_schema: request_apply_request_schema,
    },
    ToolDescriptor {
        name: TOOL_STATUS,
        title: "Status",
        description: "The exact durable journal state and bounded progress of one of the requester's own operations, reported by name. No host effect.",
        gate: ToolGate::RegisteredGrant,
        required_read_domains: &[TOOL_PREVIEW],
        input_schema: status_request_schema,
    },
    ToolDescriptor {
        name: TOOL_VERIFY,
        title: "Verify",
        description: "Bounded, redacted verification reads for one of the requester's own completed operations. No host effect.",
        gate: ToolGate::RegisteredGrant,
        required_read_domains: &[TOOL_PREVIEW],
        input_schema: verify_request_schema,
    },
];

/// The registry entry for `name`, if this protocol version defines one.
#[must_use]
pub fn tool(name: &str) -> Option<&'static ToolDescriptor> {
    TOOLS.iter().find(|entry| entry.name == name)
}

/// Every tool name this protocol version defines, in registry order.
#[must_use]
pub fn tool_names() -> Vec<&'static str> {
    TOOLS.iter().map(|entry| entry.name).collect()
}

fn empty_request_schema() -> Value {
    schema_value::<EmptyRequest>()
}

fn catalog_request_schema() -> Value {
    schema_value::<CatalogRequest>()
}

fn describe_request_schema() -> Value {
    schema_value::<DescribeRequest>()
}

fn inspect_request_schema() -> Value {
    schema_value::<InspectRequest>()
}

fn validate_request_schema() -> Value {
    schema_value::<ValidateRequest>()
}

fn preview_request_schema() -> Value {
    schema_value::<PreviewRequest>()
}

fn request_apply_request_schema() -> Value {
    schema_value::<RequestApplyRequest>()
}

fn status_request_schema() -> Value {
    schema_value::<StatusRequest>()
}

fn verify_request_schema() -> Value {
    schema_value::<VerifyRequest>()
}

/// The generated JSON Schema for `T` as a JSON value.
///
/// Generated from the compiled type by `schemars`, never hand written, so the
/// schema a client validates against cannot drift from the type this crate
/// deserializes.
#[must_use]
pub fn schema_value<T: JsonSchema>() -> Value {
    serde_json::to_value(schemars::schema_for!(T))
        .unwrap_or_else(|_| Value::Object(serde_json::Map::new()))
}

// ---------------------------------------------------------------------------
// Canonical serialization and digests
// ---------------------------------------------------------------------------

/// Serialize `value` with object keys in sorted order and no insignificant
/// whitespace.
///
/// `serde_json`'s own output depends on struct field declaration order and, if
/// the `preserve_order` feature is ever enabled anywhere in the workspace, on
/// map insertion order. Digests and the `structuredContent`/`content`
/// byte-identity rule both need a serialization that does not move for either
/// reason, so canonical form is produced here rather than borrowed.
#[must_use]
pub fn canonical_json(value: &Value) -> String {
    let mut out = String::new();
    write_canonical(value, &mut out);
    out
}

fn write_canonical(value: &Value, out: &mut String) {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_unstable();
            out.push('{');
            for (index, key) in keys.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                out.push_str(&Value::String((*key).clone()).to_string());
                out.push(':');
                if let Some(child) = map.get(*key) {
                    write_canonical(child, out);
                }
            }
            out.push('}');
        }
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_canonical(item, out);
            }
            out.push(']');
        }
        scalar => out.push_str(&scalar.to_string()),
    }
}

/// Lowercase hex SHA-256 of `bytes`.
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        // Two lowercase hex digits per byte. `from_digit` is infallible for a
        // radix-16 nibble, so the fallback is unreachable rather than lossy.
        out.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
        out.push(char::from_digit(u32::from(byte & 0x0f), 16).unwrap_or('0'));
    }
    out
}

/// `sha256:`-prefixed digest over the canonical serialization of `value`.
#[must_use]
pub fn digest_of<T: Serialize>(value: &T) -> String {
    let json = serde_json::to_value(value).unwrap_or(Value::Null);
    format!("sha256:{}", sha256_hex(canonical_json(&json).as_bytes()))
}

/// The opaque, path-free identifier for one configuration revision.
///
/// `ControlInspection::source_revision` is the raw config source, so it is
/// hashed rather than disclosed. Equality of two ids means the source bytes are
/// identical, which is exactly what a client needs to detect drift.
#[must_use]
pub fn source_revision_id(source: &str) -> String {
    format!("rev_{}", sha256_hex(source.as_bytes()))
}

/// The stable opaque fingerprint for the pinned instance.
///
/// Derived from the config path so it is stable across restarts and distinct
/// between installs, but preimage-resistant so it discloses no path.
#[must_use]
pub fn instance_fingerprint(config_path: &std::path::Path) -> String {
    format!(
        "sha256:{}",
        sha256_hex(config_path.display().to_string().as_bytes())
    )
}

/// The advertised capability set that [`capability_digest`] hashes.
///
/// Every field is something a client negotiates against. The tool list is
/// included so that adding, removing, or renaming a tool necessarily changes
/// the digest and invalidates an outstanding preview.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilitySet {
    /// The protocol version these capabilities belong to.
    pub control_protocol_version: String,
    /// The canonical config schema version the host interprets.
    pub config_schema_version: u32,
    /// Capability identifiers the running server implements.
    pub capabilities: Vec<String>,
    /// Every tool name this protocol version defines, sorted.
    pub tools: Vec<String>,
    /// Every operation id this protocol version defines, sorted.
    pub operations: Vec<String>,
}

impl CapabilitySet {
    /// The capability set this build advertises.
    #[must_use]
    pub fn current() -> Self {
        let mut tools: Vec<String> = tool_names().into_iter().map(String::from).collect();
        tools.sort();
        Self {
            control_protocol_version: CONTROL_PROTOCOL_VERSION.to_string(),
            config_schema_version: zeroclaw_config::migration::CURRENT_SCHEMA_VERSION,
            capabilities: CAPABILITIES
                .iter()
                .map(|name| (*name).to_string())
                .collect(),
            tools,
            operations: vec![OPERATION_AGENT_CREATE_CONTAINED.to_string()],
        }
    }
}

/// `sha256:`-prefixed digest over the canonical serialization of `set`.
#[must_use]
pub fn capability_digest(set: &CapabilitySet) -> String {
    digest_of(set)
}

/// The digest this build advertises on every response.
#[must_use]
pub fn current_capability_digest() -> String {
    capability_digest(&CapabilitySet::current())
}

// ---------------------------------------------------------------------------
// Envelope, advertisement, errors
// ---------------------------------------------------------------------------

/// The header every successful result carries.
///
/// `capability_digest` is repeated on every response so a client can detect a
/// server capability change mid-session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope<T> {
    /// `major.minor` of this protocol.
    pub control_protocol_version: String,
    /// The digest over the advertised capability set.
    pub capability_digest: String,
    /// The tool-specific payload.
    pub result: T,
}

impl<T> Envelope<T> {
    /// Wrap `result` in the current protocol header.
    pub fn new(result: T) -> Self {
        Self {
            control_protocol_version: CONTROL_PROTOCOL_VERSION.to_string(),
            capability_digest: current_capability_digest(),
            result,
        }
    }
}

/// The block returned verbatim in both the `initialize` result and
/// `control.server_info`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Advertisement {
    /// Product version of the running binary.
    pub zeroclaw_version: String,
    /// `major.minor` of this protocol.
    pub control_protocol_version: String,
    /// Canonical config schema version. Interpretation is server-owned.
    pub config_schema_version: u32,
    /// Capability identifiers the running server implements.
    pub capabilities: Vec<String>,
    /// `sha256:` digest over the canonical capability set.
    pub capability_digest: String,
}

impl Advertisement {
    /// The advertisement for a server built from this crate and running inside
    /// a binary reporting `zeroclaw_version`.
    ///
    /// The version is a parameter rather than `env!("CARGO_PKG_VERSION")`
    /// because `env!` would resolve to *this crate's* version, not the shipped
    /// binary's.
    #[must_use]
    pub fn current(zeroclaw_version: &str) -> Self {
        let set = CapabilitySet::current();
        Self {
            zeroclaw_version: zeroclaw_version.to_string(),
            control_protocol_version: CONTROL_PROTOCOL_VERSION.to_string(),
            config_schema_version: set.config_schema_version,
            capabilities: set.capabilities.clone(),
            capability_digest: capability_digest(&set),
        }
    }
}

/// The stable typed error codes defined by v1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlErrorCode {
    /// The session has no registered client credential.
    UnregisteredClient,
    /// Registered, but the grant does not cover this target, domain, or view.
    GrantRequired,
    /// No such operation in this protocol version.
    UnknownOperation,
    /// Client and server major versions do not intersect.
    UnsupportedProtocolVersion,
    /// The client supplied a digest the server no longer advertises.
    CapabilityDigestMismatch,
    /// The requested target ID is not in the target registry.
    TargetNotRegistered,
    /// The typed operation did not validate; see `diagnostics`.
    ValidationFailed,
    /// The pinned source revision no longer matches.
    StaleSourceRevision,
    /// Management mutations are not enabled on this instance, so a proposal
    /// cannot be parked. A read-only refusal that writes nothing durable.
    MutationsDisabled,
    /// A per-requester parking quota would be exceeded. No entry is evicted and
    /// nothing durable is written.
    QuotaExceeded,
    /// Unclassified host failure.
    InternalError,
}

impl ControlErrorCode {
    /// The wire spelling of this code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnregisteredClient => "unregistered_client",
            Self::GrantRequired => "grant_required",
            Self::UnknownOperation => "unknown_operation",
            Self::UnsupportedProtocolVersion => "unsupported_protocol_version",
            Self::CapabilityDigestMismatch => "capability_digest_mismatch",
            Self::TargetNotRegistered => "target_not_registered",
            Self::ValidationFailed => "validation_failed",
            Self::StaleSourceRevision => "stale_source_revision",
            Self::MutationsDisabled => "mutations_disabled",
            Self::QuotaExceeded => "quota_exceeded",
            Self::InternalError => "internal_error",
        }
    }

    /// The only text this code ever puts on the wire.
    ///
    /// Fixed and static by construction: there is no code path that formats a
    /// host error, a path, or a caller value into an error message, so the
    /// specification's redaction rule for `message` holds without review.
    #[must_use]
    pub const fn message(self) -> &'static str {
        match self {
            Self::UnregisteredClient => {
                "This session has no registered client credential. Call control.registration_help."
            }
            Self::GrantRequired => "This client is not granted the requested read domain.",
            Self::UnknownOperation => "No such operation in this protocol version.",
            Self::UnsupportedProtocolVersion => {
                "The client and server control protocol major versions do not intersect."
            }
            Self::CapabilityDigestMismatch => {
                "The supplied capability digest is not the digest this server advertises."
            }
            Self::TargetNotRegistered => "The requested target is not registered on this host.",
            Self::ValidationFailed => "The typed operation did not validate.",
            Self::StaleSourceRevision => "The pinned source revision no longer matches.",
            Self::MutationsDisabled => "Management mutations are not enabled on this instance.",
            Self::QuotaExceeded => "A per-requester parking quota would be exceeded.",
            Self::InternalError => "The host could not complete this operation.",
        }
    }

    /// Whether a client may retry the same request unchanged.
    #[must_use]
    pub const fn retryable(self) -> bool {
        matches!(self, Self::StaleSourceRevision)
    }

    /// Every code in the v1 table, for exhaustive tests.
    pub const ALL: [Self; 11] = [
        Self::UnregisteredClient,
        Self::GrantRequired,
        Self::UnknownOperation,
        Self::UnsupportedProtocolVersion,
        Self::CapabilityDigestMismatch,
        Self::TargetNotRegistered,
        Self::ValidationFailed,
        Self::StaleSourceRevision,
        Self::MutationsDisabled,
        Self::QuotaExceeded,
        Self::InternalError,
    ];
}

/// One diagnostic attached to a failed validation.
///
/// `path` is a path *within the typed operation* — `provider_alias`,
/// `personality_files[0].content` — and is never a filesystem path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Diagnostic {
    /// Always `error` in v1; warnings are not produced.
    pub severity: String,
    /// Stable machine-readable reason.
    pub code: String,
    /// The typed-operation field this diagnostic is about.
    pub path: String,
    /// Fixed explanatory text carrying no caller value.
    pub message: String,
}

/// The typed error payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolError {
    /// The stable code from the v1 table.
    pub code: ControlErrorCode,
    /// Fixed text from [`ControlErrorCode::message`].
    pub message: String,
    /// The tool or lifecycle method that refused.
    pub operation: String,
    /// Whether an unchanged retry could succeed.
    pub retryable: bool,
    /// Structured, whitelisted extra context. Empty unless a code defines one.
    pub details: BTreeMap<String, Value>,
}

impl ProtocolError {
    /// A refusal of `operation` with `code`.
    ///
    /// This is the only constructor. It takes no message, so no caller can put
    /// host detail on the wire.
    #[must_use]
    pub fn new(code: ControlErrorCode, operation: &str) -> Self {
        Self {
            code,
            message: code.message().to_string(),
            operation: operation.to_string(),
            retryable: code.retryable(),
            details: BTreeMap::new(),
        }
    }

    /// Attach validation diagnostics under `details.diagnostics`.
    #[must_use]
    pub fn with_diagnostics(mut self, diagnostics: Vec<Diagnostic>) -> Self {
        if let Ok(value) = serde_json::to_value(diagnostics) {
            self.details.insert("diagnostics".to_string(), value);
        }
        self
    }
}

/// The wire envelope for a refusal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorPayload {
    /// The typed error.
    pub error: ProtocolError,
}

impl From<ProtocolError> for ErrorPayload {
    fn from(error: ProtocolError) -> Self {
        Self { error }
    }
}

// ---------------------------------------------------------------------------
// Startup refusals
// ---------------------------------------------------------------------------

/// Where a startup refusal rides inside a JSON-RPC `error.data` object.
///
/// Deliberately **not** `data.error`, which carries [`ErrorPayload`] and
/// therefore a code from the frozen v1 table. A client that reads
/// `data.error.code` and finds an unknown string would be right to call the
/// server non-conformant; a client that finds this key instead learns
/// unambiguously that the process refused to serve at all.
pub const STARTUP_REFUSAL_META_KEY: &str = "control_startup_refusal";

/// Why a control process refused to serve.
///
/// A **lifecycle** vocabulary, disjoint from [`ControlErrorCode`] by
/// construction. Nothing here is a tool result: a process that emits one of
/// these answers exactly one request and exits nonzero. The v1 error table is
/// frozen and describes what a *running* session can refuse; adding a startup
/// condition to it would change the meaning of a table the specification
/// enumerates.
///
/// # What each code may disclose
///
/// A caller reaches these by launching the binary with credential-delivery
/// options, so every one of them is read by whoever controls that launch. They
/// are still written to the redaction rule: fixed text, no path, no client
/// identifier, no enumeration of who else is registered.
///
/// Two fusions are deliberate rather than incidental:
///
/// - [`Self::CredentialRejected`] covers an unknown client identifier, a wrong
///   secret, a revoked registration, a registration issued under a superseded
///   trust epoch, **and a host with no client registry at all**. Splitting the
///   last one out would let anyone who can launch the binary learn whether the
///   host has ever registered a client, by presenting a fabricated credential.
/// - [`Self::InstanceNotManaged`] covers both "genesis never ran" and
///   "recovery-only". `zeroclaw control genesis` reports the precise state to
///   an operator on the host, which is where that detail belongs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StartupRefusalCode {
    /// The credential-delivery options are contradictory, incomplete, or
    /// malformed. Nothing was read and no credential was presented.
    CredentialMechanismInvalid,
    /// A delivery mechanism was named but produced no usable credential.
    CredentialUnavailable,
    /// The presented credential does not authenticate.
    CredentialRejected,
    /// The mechanism used is not the delivery assurance class the registration
    /// was created under.
    DeliveryClassMismatch,
    /// The instance has no verified genesis record.
    InstanceNotManaged,
    /// The client registry is present but could not be authenticated or
    /// re-validated under this deployment's key.
    RegistryUnverifiable,
    /// Another control process already holds this instance's host lock.
    HostAlreadyServing,
}

impl StartupRefusalCode {
    /// The wire spelling of this code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CredentialMechanismInvalid => "credential_mechanism_invalid",
            Self::CredentialUnavailable => "credential_unavailable",
            Self::CredentialRejected => "credential_rejected",
            Self::DeliveryClassMismatch => "delivery_class_mismatch",
            Self::InstanceNotManaged => "instance_not_managed",
            Self::RegistryUnverifiable => "registry_unverifiable",
            Self::HostAlreadyServing => "host_already_serving",
        }
    }

    /// The only text this code ever puts on the wire, or in a process exit
    /// message.
    ///
    /// Fixed and static exactly as [`ControlErrorCode::message`] is, so no host
    /// error, path, client label, or presented value can reach a reader.
    #[must_use]
    pub const fn message(self) -> &'static str {
        match self {
            Self::CredentialMechanismInvalid => {
                "The control credential delivery options are contradictory, incomplete, or malformed."
            }
            Self::CredentialUnavailable => {
                "The named credential delivery mechanism produced no usable credential."
            }
            Self::CredentialRejected => "The presented control client credential was rejected.",
            Self::DeliveryClassMismatch => {
                "The credential was presented through a delivery mechanism this registration was not created under."
            }
            Self::InstanceNotManaged => {
                "This instance has no verified control-plane trust root, so no client can be authenticated."
            }
            Self::RegistryUnverifiable => {
                "This instance's client registry could not be authenticated under its own key."
            }
            Self::HostAlreadyServing => {
                "Another control process already holds this instance's host lock."
            }
        }
    }

    /// Whether relaunching unchanged could succeed.
    ///
    /// Only the host lock: every other code describes a durable condition that
    /// an operator has to change.
    #[must_use]
    pub const fn retryable(self) -> bool {
        matches!(self, Self::HostAlreadyServing)
    }

    /// Every startup refusal code, for exhaustive tests.
    pub const ALL: [Self; 7] = [
        Self::CredentialMechanismInvalid,
        Self::CredentialUnavailable,
        Self::CredentialRejected,
        Self::DeliveryClassMismatch,
        Self::InstanceNotManaged,
        Self::RegistryUnverifiable,
        Self::HostAlreadyServing,
    ];
}

impl std::fmt::Display for StartupRefusalCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A refusal to serve at all.
///
/// [`StartupRefusal::new`] is the only constructor and takes no message, so —
/// exactly as with [`ProtocolError`] — there is no code path that can format a
/// host error, a path, or a presented value into the text a client reads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StartupRefusal {
    /// The stable code.
    pub code: StartupRefusalCode,
    /// Fixed text from [`StartupRefusalCode::message`].
    pub message: String,
    /// Whether relaunching unchanged could succeed.
    pub retryable: bool,
}

impl StartupRefusal {
    /// A refusal carrying `code`.
    #[must_use]
    pub fn new(code: StartupRefusalCode) -> Self {
        Self {
            code,
            message: code.message().to_string(),
            retryable: code.retryable(),
        }
    }
}

impl std::fmt::Display for StartupRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code.as_str(), self.message)
    }
}

impl std::error::Error for StartupRefusal {}

// ---------------------------------------------------------------------------
// Requests
// ---------------------------------------------------------------------------

/// The argument object of a tool that takes none.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EmptyRequest {}

/// Addresses one instance. Phase 2 pins exactly [`LOCAL_TARGET_ID`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TargetSelector {
    /// The instance identifier.
    pub target_id: String,
}

/// `control.catalog` arguments.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CatalogRequest {
    /// Optional domain filter. Omitting it returns every operation the grant
    /// covers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domains: Option<Vec<String>>,
}

/// `control.describe` arguments.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DescribeRequest {
    /// The operation to describe.
    pub operation_id: String,
    /// The instance the requirements are resolved against.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<TargetSelector>,
}

/// `control.inspect` arguments.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InspectRequest {
    /// The instance to inspect.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<TargetSelector>,
    /// The view to resolve.
    pub view: String,
    /// Optional narrowing to one operation's minimum disclosure.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<String>,
}

/// The typed operation for [`OPERATION_AGENT_CREATE_CONTAINED`].
///
/// This is the wire form of [`AgentProposal`] plus the provider alias the host
/// binds the new agent to. The two are kept as one type here so the generated
/// `request_schema` describes exactly what a client submits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentCreateContainedOperation {
    /// An already-configured model provider alias on this instance.
    pub provider_alias: String,
    /// The alias the new agent will be created under.
    pub agent_alias: String,
    /// Built-in risk preset.
    pub risk: RiskChoice,
    /// Built-in runtime preset.
    pub runtime: RuntimeChoice,
    /// Agent-scoped memory backend.
    pub memory: MemoryChoice,
    /// Canonical personality files to write into the agent workspace.
    #[serde(default)]
    pub personality_files: Vec<PersonalityFileProposal>,
}

impl AgentCreateContainedOperation {
    /// The `ControlService` proposal this operation denotes.
    #[must_use]
    pub fn to_proposal(&self) -> AgentProposal {
        AgentProposal {
            agent_alias: self.agent_alias.clone(),
            risk: self.risk,
            runtime: self.runtime,
            memory: self.memory,
            personality_files: self.personality_files.clone(),
        }
    }
}

/// `control.validate` arguments.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ValidateRequest {
    /// The instance to validate against.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<TargetSelector>,
    /// The operation kind being proposed.
    pub operation_id: String,
    /// The typed operation, conforming to Describe's `request_schema`.
    pub operation: AgentCreateContainedOperation,
    /// Optional pin: refuse if the server no longer advertises this digest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_digest: Option<String>,
    /// Optional pin: refuse if the instance is no longer at this revision.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_revision: Option<String>,
}

/// `control.preview` arguments. Identical in shape to [`ValidateRequest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PreviewRequest {
    /// The instance to preview against.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<TargetSelector>,
    /// The operation kind being proposed.
    pub operation_id: String,
    /// The typed operation, conforming to Describe's `request_schema`.
    pub operation: AgentCreateContainedOperation,
    /// Optional pin: refuse if the server no longer advertises this digest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_digest: Option<String>,
    /// Optional pin: refuse if the instance is no longer at this revision.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_revision: Option<String>,
}

/// `control.request_apply` arguments. Identical in shape to [`PreviewRequest`]:
/// the client re-submits the operation it previewed, and the host reconstructs
/// and re-verifies the bound proposal against the current revision before
/// parking it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RequestApplyRequest {
    /// The instance to park against.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<TargetSelector>,
    /// The operation kind being proposed.
    pub operation_id: String,
    /// The typed operation, conforming to Describe's `request_schema`.
    pub operation: AgentCreateContainedOperation,
    /// Optional pin: refuse if the server no longer advertises this digest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_digest: Option<String>,
    /// Optional pin: refuse if the instance is no longer at this revision.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_revision: Option<String>,
}

/// `control.status` arguments. Addresses one operation the caller owns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StatusRequest {
    /// The instance the operation lives on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<TargetSelector>,
    /// The operation id returned by `control.request_apply`.
    pub operation_id: String,
}

/// `control.verify` arguments. Addresses one operation the caller owns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VerifyRequest {
    /// The instance the operation lives on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<TargetSelector>,
    /// The operation id returned by `control.request_apply`.
    pub operation_id: String,
}

// ---------------------------------------------------------------------------
// Results
// ---------------------------------------------------------------------------

/// `control.ping` result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PingResult {
    /// Always `true`.
    pub ok: bool,
    /// Host wall clock in RFC 3339 UTC, so a client can detect gross skew. Not
    /// an authority for expiration.
    pub server_time: String,
}

/// The calling session's own registration facts. Says nothing about any other
/// session, client, or instance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionInfo {
    /// `unregistered` or `registered`, for this session only.
    pub registration_state: String,
    /// Always `external_requester`: launching the command creates a requester
    /// principal and nothing upgrades it.
    pub requester_class: String,
    /// The credential delivery assurance class, when registered.
    pub assurance_class: Option<String>,
}

/// `control.server_info` result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerInfoResult {
    /// The advertisement block, byte-identical to the `initialize` copy.
    pub advertisement: Advertisement,
    /// Facts about the calling session only.
    pub session: SessionInfo,
    /// The durable-effect tools reachable by *this* session — at most
    /// `control.request_apply`, and only when this registered session can park a
    /// proposal. Empty for an unregistered session, a session without the
    /// proposal grant, and any session while mutations are disabled.
    pub mutation_tools: Vec<String>,
    /// Whether this session can reach no durable-effect tool. `true` unless the
    /// session can park a proposal.
    pub read_only: bool,
    /// Whether management mutations are enabled on this instance. A
    /// configured-instance fact that stays behind a grant: it is always `false`
    /// for an unregistered session and never discloses the instance's real value
    /// to one, matching the read-only server_info disclosure rule.
    pub mutations_enabled: bool,
}

/// `control.registration_help` result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistrationHelpResult {
    /// This session's registration state.
    pub registration_state: String,
    /// Registration is a meta-authority operation performed by an operator.
    pub registration_is_meta_authority: bool,
    /// Credential-delivery assurance classes an operator may choose.
    pub accepted_assurance_classes: Vec<String>,
    /// Assurance classes that are refused.
    pub rejected_assurance_classes: Vec<String>,
    /// What a human does, on the host, to register this client.
    pub operator_steps: Vec<String>,
    /// Repository-relative documentation reference. Not a host path.
    pub documentation: String,
}

/// One product-supported operation kind.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationDescriptor {
    /// Stable operation identifier.
    pub operation_id: String,
    /// The domain the operation belongs to.
    pub domain: String,
    /// Short human label.
    pub title: String,
    /// What the operation does.
    pub summary: String,
    /// `ordinary` or a stricter class.
    pub operation_class: String,
    /// `true` for every mutating operation. Descriptive only in v1: no apply
    /// path exists to exercise it.
    pub requires_approval: bool,
    /// Whether the operation changes who may authorize.
    pub meta_authority: bool,
    /// Stability of the operation's contract.
    pub stability: String,
    /// The protocol version the operation appeared in.
    pub since_control_protocol_version: String,
    /// The artifact kinds the operation would affect.
    pub effect_kinds: Vec<String>,
}

/// `control.catalog` result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogResult {
    /// Canonical config schema version.
    pub config_schema_version: u32,
    /// Operation kinds the grant covers.
    pub operations: Vec<OperationDescriptor>,
}

/// The minimum disclosure one operation declares.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Disclosure {
    /// Read views the operation needs.
    pub read_domains: Vec<String>,
}

/// `control.describe` result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DescribeResult {
    /// The operation described.
    pub operation_id: String,
    /// Canonical config schema version.
    pub config_schema_version: u32,
    /// Digest over everything in this response that a client validates against.
    pub requirements_digest: String,
    /// Generated JSON Schema for the typed operation.
    pub request_schema: Value,
    /// Generated JSON Schema for the preview the operation produces.
    pub response_schema: Value,
    /// Server capabilities the operation needs.
    pub required_server_capabilities: Vec<String>,
    /// Operator-backchannel capabilities the operation would need to be
    /// approved. Declared for shape parity; no backchannel is contacted in a
    /// read-only release.
    pub required_backchannel_capabilities: Vec<String>,
    /// The kinds of existing configuration the operation depends on.
    pub dependency_kinds: Vec<String>,
    /// The minimum disclosure the operation declares.
    pub disclosure: Disclosure,
}

/// The instance a result is about.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TargetRef {
    /// The instance identifier.
    pub target_id: String,
    /// Stable opaque fingerprint. Discloses no path.
    pub instance_fingerprint: String,
}

/// One row of a resolved inspect view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InspectItem {
    /// The configured alias.
    pub alias: String,
    /// What kind of thing the alias names.
    pub kind: String,
    /// Whether the alias is configured on this instance.
    pub availability: String,
    /// Coarse health, computed without contacting anything.
    pub health: String,
    /// Redacted one-line policy description.
    pub policy_summary: String,
}

/// A health fact that cannot be frozen into an apply-time guarantee.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Observation {
    /// What the observation is about.
    pub subject: String,
    /// The observed category.
    pub category: String,
    /// Always `false`: observations are repeated during verification rather
    /// than presented as guarantees.
    pub frozen: bool,
}

/// `control.inspect` result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InspectResult {
    /// The instance inspected.
    pub target: TargetRef,
    /// The view resolved.
    pub view: String,
    /// Opaque id of the configuration revision this view was read from.
    pub source_revision: String,
    /// The rows of the view.
    pub items: Vec<InspectItem>,
    /// Unfrozen health facts.
    pub observations: Vec<Observation>,
}

/// `control.validate` result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidateResult {
    /// Whether the typed operation validated.
    pub valid: bool,
    /// Host-computed digest over the canonical typed operation.
    pub operation_digest: String,
    /// Opaque id of the configuration revision validation ran against.
    pub source_revision: String,
    /// Canonical config schema version.
    pub config_schema_version: u32,
    /// Empty when `valid`.
    pub diagnostics: Vec<Diagnostic>,
}

/// One effect a proposed operation would have.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Effect {
    /// Identifier referenced by `apply_order` and `irreversible_effects`.
    pub effect_id: String,
    /// The kind of artifact affected.
    pub artifact_kind: String,
    /// What would happen to it.
    pub action: String,
    /// Path-free description of the change.
    pub redacted_summary: String,
    /// Whether the effect can be rolled back.
    pub reversible: bool,
    /// The rollback artifact that makes it reversible.
    pub rollback_artifact: String,
}

/// One risk a proposed operation carries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Risk {
    /// Stable machine-readable risk identifier.
    pub code: String,
    /// Coarse severity.
    pub severity: String,
    /// Path-free description.
    pub summary: String,
}

/// One post-apply check the host would run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct VerificationStep {
    /// Stable machine-readable check identifier.
    pub check: String,
    /// What a passing check proves.
    pub expectation: String,
}

/// `control.preview` result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PreviewResult {
    /// Process-local identifier. Not a resume secret and conveys no authority.
    pub preview_id: String,
    /// Always `false` in v1: preview parks no proposal and writes no journal.
    pub durable: bool,
    /// Host-computed digest over the canonical typed operation.
    pub operation_digest: String,
    /// Digest over the existing configuration the operation depends on.
    pub dependency_digest: String,
    /// The instance previewed against.
    pub target: TargetRef,
    /// Opaque id of the configuration revision the preview is bound to.
    pub source_revision: String,
    /// Canonical config schema version.
    pub config_schema_version: u32,
    /// RFC 3339 UTC instant after which this preview is stale.
    pub expires_at: String,
    /// The effects, in no particular order; `apply_order` sequences them.
    pub effects: Vec<Effect>,
    /// The order effects would be applied in.
    pub apply_order: Vec<String>,
    /// Effects that could not be rolled back. Empty for this operation.
    pub irreversible_effects: Vec<String>,
    /// Risks the operation carries.
    pub risks: Vec<Risk>,
    /// Checks the host would run after an apply.
    pub verification_plan: Vec<VerificationStep>,
}

/// `control.request_apply` result.
///
/// A successful call has written exactly one immutable `awaiting_approval`
/// journal entry and changed **no** config. It conveys no approval authority:
/// the config mutation happens only when a separate eligible operator approves
/// at the terminal backchannel and the host worker consumes the receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestApplyResult {
    /// The durable operation identifier. Addresses `control.status` and
    /// `control.verify` for this operation.
    pub operation_id: String,
    /// The opaque single-proposal resume secret, returned exactly once. The host
    /// stores only its verifier, never the secret. It conveys no approval
    /// authority and expires with the proposal.
    pub resume_secret: String,
    /// The durable state the proposal was parked in, reported by name.
    pub state: String,
    /// RFC 3339 UTC instant after which the parked proposal expires.
    pub expires_at: String,
    /// Always `true`: a parked proposal is durable. Distinguishes this from a
    /// `control.preview`, which is process-local.
    pub durable: bool,
}

/// `control.status` result: the exact durable state and bounded progress of one
/// operation the caller owns, reported by name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusResult {
    /// The operation addressed.
    pub operation_id: String,
    /// The durable journal state, by its verbatim name. Never collapsed into a
    /// generic pending result.
    pub state: String,
    /// The operation kind being decided and applied.
    pub operation: String,
    /// Expiry, RFC 3339 UTC.
    pub expires_at: String,
    /// How many effects the proposal declares.
    pub effects_total: usize,
    /// How many declared effects have reached their expected post-image, as
    /// bounded progress — never a substitute for the state name.
    pub effects_reached_post_image: usize,
    /// A short, non-secret note on why a terminal or parked state was entered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disposition: Option<String>,
}

/// `control.verify` result: bounded, redacted verification reads for one
/// completed operation the caller owns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyResult {
    /// The operation addressed.
    pub operation_id: String,
    /// The durable journal state, by name.
    pub state: String,
    /// Whether the created agent is present in effective configuration.
    pub agent_present: bool,
    /// Whether the declared personality files are present and correct.
    pub personality_files_ok: bool,
    /// Whether the operation's effect is confirmed effective, not merely written.
    pub effective: bool,
}

// ---------------------------------------------------------------------------
// Projections from the ControlService types onto the wire types
// ---------------------------------------------------------------------------

/// The one operation kind this protocol version defines.
#[must_use]
pub fn operation_descriptor() -> OperationDescriptor {
    OperationDescriptor {
        operation_id: OPERATION_AGENT_CREATE_CONTAINED.to_string(),
        domain: "agent".to_string(),
        title: "Create a contained agent".to_string(),
        summary: "Create one agent restricted to an existing provider, built-in risk and runtime \
                  presets, memory, and personality files."
            .to_string(),
        operation_class: "ordinary".to_string(),
        requires_approval: true,
        meta_authority: false,
        stability: "experimental".to_string(),
        since_control_protocol_version: CONTROL_PROTOCOL_VERSION.to_string(),
        effect_kinds: vec!["config".to_string(), "personality_file".to_string()],
    }
}

/// The catalogue, optionally filtered to `domains`.
///
/// Output depends only on the compiled protocol, never on configured instance
/// state, so two registered clients with the same grant see the same catalogue
/// on differently configured hosts.
#[must_use]
pub fn catalog(domains: Option<&[String]>) -> CatalogResult {
    let descriptor = operation_descriptor();
    let keep = domains.is_none_or(|filter| filter.contains(&descriptor.domain));
    CatalogResult {
        config_schema_version: zeroclaw_config::migration::CURRENT_SCHEMA_VERSION,
        operations: if keep { vec![descriptor] } else { Vec::new() },
    }
}

/// The typed requirements for `operation_id`, or `None` if this protocol
/// version does not define it.
#[must_use]
pub fn describe(operation_id: &str) -> Option<DescribeResult> {
    if operation_id != OPERATION_AGENT_CREATE_CONTAINED {
        return None;
    }
    let mut result = DescribeResult {
        operation_id: operation_id.to_string(),
        config_schema_version: zeroclaw_config::migration::CURRENT_SCHEMA_VERSION,
        requirements_digest: String::new(),
        request_schema: schema_value::<AgentCreateContainedOperation>(),
        response_schema: schema_value::<PreviewResult>(),
        required_server_capabilities: vec!["agents".to_string()],
        required_backchannel_capabilities: vec!["render_agent_effects".to_string()],
        dependency_kinds: vec![
            "provider_alias".to_string(),
            "risk_profile".to_string(),
            "runtime_preset".to_string(),
        ],
        disclosure: Disclosure {
            read_domains: vec![
                VIEW_AGENT_SUMMARY.to_string(),
                VIEW_PROVIDER_ALIAS_LIST.to_string(),
            ],
        },
    };
    result.requirements_digest = digest_of(&result);
    Some(result)
}

/// The rows and observations of one inspect view.
///
/// Only the two views `ControlService` can actually resolve are handled;
/// `None` means the view does not exist and the caller reports
/// [`ControlErrorCode::GrantRequired`] rather than confirming or denying that
/// some other view might exist for a wider grant.
#[must_use]
pub fn inspect_view(
    inspection: &ControlInspection,
    provider_refs: &[String],
    view: &str,
) -> Option<(Vec<InspectItem>, Vec<Observation>)> {
    let observations = vec![Observation {
        // The schema gate is the only health fact a read-only server computes
        // without contacting anything, so it is the only one reported.
        subject: "config.schema".to_string(),
        category: "current".to_string(),
        frozen: false,
    }];
    match view {
        VIEW_AGENT_SUMMARY => {
            let mut items: Vec<InspectItem> = inspection
                .config()
                .agents
                .iter()
                .filter(|(alias, _)| zeroclaw_config::helpers::validate_alias_key(alias).is_ok())
                .map(|(alias, agent)| InspectItem {
                    alias: alias.clone(),
                    kind: "agent".to_string(),
                    availability: "configured".to_string(),
                    health: "ok".to_string(),
                    // Preset names only. Never the resolved policy body, a
                    // provider setting, a workspace path, or a credential.
                    policy_summary: format!(
                        "risk {}; runtime {}; agent-scoped memory",
                        agent.risk_profile.as_str(),
                        agent.runtime_profile.as_str()
                    ),
                })
                .collect();
            items.sort_by(|left, right| left.alias.cmp(&right.alias));
            Some((items, observations))
        }
        VIEW_PROVIDER_ALIAS_LIST => {
            let items = provider_refs
                .iter()
                .map(|reference| InspectItem {
                    alias: reference.clone(),
                    kind: "provider_alias".to_string(),
                    availability: "configured".to_string(),
                    health: "ok".to_string(),
                    policy_summary: "eligible for a capability-restricted session".to_string(),
                })
                .collect();
            Some((items, observations))
        }
        _ => None,
    }
}

/// The canonical typed operation a digest is computed over.
///
/// Derived from the preview the host built, not from the caller's request, so
/// the fields that participate are chosen by this framework rather than by
/// free-form input. `selected_model` is deliberately excluded: it is provider
/// metadata resolved from configuration, not part of the operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct CanonicalOperation<'a> {
    operation_id: &'a str,
    provider_alias: &'a str,
    agent_alias: &'a str,
    risk: RiskChoice,
    runtime: RuntimeChoice,
    memory: MemoryChoice,
    personality_files: Vec<(&'a str, &'a str)>,
}

/// Put personality files in the one canonical order, so the digest does not
/// depend on the order a client happened to submit them in.
///
/// The order is the position in [`crate::inventory::PERSONALITY_FILENAMES`],
/// which is also the order `validate_proposal` canonicalizes to. That constant
/// is the single source of the rule; this function and the validator both read
/// it rather than each carrying a list.
fn canonical_file_order<'a>(mut files: Vec<(&'a str, &'a str)>) -> Vec<(&'a str, &'a str)> {
    files.sort_by_key(|(filename, _)| {
        crate::inventory::PERSONALITY_FILENAMES
            .iter()
            .position(|candidate| candidate == filename)
            .unwrap_or(crate::inventory::PERSONALITY_FILENAMES.len())
    });
    files
}

/// The host-computed digest over the canonical typed operation `preview`
/// describes.
#[must_use]
pub fn operation_digest(preview: &ProposalPreview) -> String {
    digest_of(&CanonicalOperation {
        operation_id: OPERATION_AGENT_CREATE_CONTAINED,
        provider_alias: &preview.selected_model_provider,
        agent_alias: &preview.agent_alias,
        risk: preview.risk,
        runtime: preview.runtime,
        memory: preview.memory,
        personality_files: canonical_file_order(
            preview
                .personality_files
                .iter()
                .map(|file| (file.filename.as_str(), file.content.as_str()))
                .collect(),
        ),
    })
}

/// The host-computed digest over a submitted typed operation.
///
/// Available whether or not the operation validates, so a rejected
/// `control.validate` can still name the operation it rejected. It agrees with
/// [`operation_digest`] for every operation that does validate, which is
/// asserted rather than assumed.
#[must_use]
pub fn operation_digest_for(operation: &AgentCreateContainedOperation) -> String {
    digest_of(&CanonicalOperation {
        operation_id: OPERATION_AGENT_CREATE_CONTAINED,
        provider_alias: &operation.provider_alias,
        agent_alias: &operation.agent_alias,
        risk: operation.risk,
        runtime: operation.runtime,
        memory: operation.memory,
        personality_files: canonical_file_order(
            operation
                .personality_files
                .iter()
                .map(|file| (file.filename.as_str(), file.content.as_str()))
                .collect(),
        ),
    })
}

/// The digest over the existing configuration the operation depends on.
#[must_use]
pub fn dependency_digest(preview: &ProposalPreview) -> String {
    let mut map = BTreeMap::new();
    map.insert(
        "provider_alias".to_string(),
        Value::String(preview.selected_model_provider.clone()),
    );
    map.insert(
        "risk_profile".to_string(),
        Value::String(preview.risk.preset_name().to_string()),
    );
    map.insert(
        "runtime_preset".to_string(),
        Value::String(preview.runtime.preset_name().to_string()),
    );
    map.insert(
        "config_schema_version".to_string(),
        Value::from(zeroclaw_config::migration::CURRENT_SCHEMA_VERSION),
    );
    digest_of(&map)
}

/// The effects, apply order, risks, and verification plan a preview describes.
///
/// Every path-bearing field of `ProposalPreview` is dropped here:
/// `persistence.config_path`, `persistence.workspace_dir`, and each
/// `PersonalityFilePreview::destination` are absolute paths that the
/// specification forbids on the wire. Filenames survive because they are drawn
/// from a fixed canonical set, not from the filesystem.
#[must_use]
pub fn preview_effects(preview: &ProposalPreview) -> (Vec<Effect>, Vec<String>) {
    let mut effects = vec![Effect {
        effect_id: "e1".to_string(),
        artifact_kind: "config".to_string(),
        action: "create".to_string(),
        redacted_summary: "Add one contained agent entry.".to_string(),
        reversible: true,
        rollback_artifact: "config_snapshot".to_string(),
    }];
    for index in 0..preview.personality_files.len() {
        effects.push(Effect {
            effect_id: format!("e{}", index + 2),
            artifact_kind: "personality_file".to_string(),
            action: "create".to_string(),
            redacted_summary: "Write one personality file for the new agent.".to_string(),
            reversible: true,
            rollback_artifact: "file_snapshot".to_string(),
        });
    }
    let order = effects
        .iter()
        .map(|effect| effect.effect_id.clone())
        .collect();
    (effects, order)
}

/// The risks a contained-agent creation carries.
///
/// `validate_proposal` refuses an uncontained posture outright, so the only
/// risk this operation can reach the preview with is the new capability
/// surface the agent gains.
#[must_use]
pub fn preview_risks() -> Vec<Risk> {
    vec![Risk {
        code: "new_agent_capability_surface".to_string(),
        severity: "medium".to_string(),
        summary: "A new agent gains the configured provider and preset.".to_string(),
    }]
}

/// The checks the host would run after an apply.
#[must_use]
pub fn verification_plan() -> Vec<VerificationStep> {
    vec![
        VerificationStep {
            check: "agent_present_in_effective_config".to_string(),
            expectation: "The alias resolves after reload.".to_string(),
        },
        VerificationStep {
            check: "preserved_sections_unchanged".to_string(),
            expectation:
                "Memory, storage, channels, peer groups, and providers are byte-identical."
                    .to_string(),
        },
    ]
}

/// The fixed explanation for one proposal rejection.
///
/// Static per code and carrying no caller value, so a diagnostic cannot become
/// an echo channel for rejected content.
#[must_use]
pub const fn diagnostic_message(code: ProposalErrorCode) -> &'static str {
    match code {
        ProposalErrorCode::CredentialLikeContent => "The submitted text looks like a credential.",
        ProposalErrorCode::ConfigurationContent => "The submitted text looks like configuration.",
        ProposalErrorCode::TerminalControl => "The submitted text contains terminal control codes.",
        ProposalErrorCode::BidiControl => {
            "The submitted text contains bidirectional control characters."
        }
        ProposalErrorCode::InvalidJson => "The typed operation could not be parsed.",
        ProposalErrorCode::InvalidAgentAlias => "The agent alias is not a valid alias key.",
        ProposalErrorCode::ReservedAgentAlias => "The agent alias is reserved.",
        ProposalErrorCode::AgentAliasExists => "An agent with that alias already exists.",
        ProposalErrorCode::ProviderUnavailable => {
            "No granted provider alias with that name is eligible."
        }
        ProposalErrorCode::RiskChoiceUnavailable => "That risk preset is not available.",
        ProposalErrorCode::RuntimeChoiceUnavailable => "That runtime preset is not available.",
        ProposalErrorCode::NoncanonicalPersonalityFile => {
            "That personality filename is not one of the canonical names."
        }
        ProposalErrorCode::DuplicatePersonalityFile => {
            "The same personality file was supplied twice."
        }
        ProposalErrorCode::PersonalityFileTooLarge => "That personality file exceeds the limit.",
        ProposalErrorCode::TooManyPersonalityFiles => "Too many personality files were supplied.",
        ProposalErrorCode::UncontainedPosture => {
            "The resulting posture would be uncontained and is refused."
        }
        ProposalErrorCode::ProfileDrift => "The resolved preset changed under the proposal.",
        ProposalErrorCode::ProviderTargetDrift => "The provider target changed under the proposal.",
    }
}

/// The stable wire spelling of a proposal rejection code.
#[must_use]
pub const fn diagnostic_code(code: ProposalErrorCode) -> &'static str {
    match code {
        ProposalErrorCode::CredentialLikeContent => "credential_like_content",
        ProposalErrorCode::ConfigurationContent => "configuration_content",
        ProposalErrorCode::TerminalControl => "terminal_control",
        ProposalErrorCode::BidiControl => "bidi_control",
        ProposalErrorCode::InvalidJson => "invalid_json",
        ProposalErrorCode::InvalidAgentAlias => "invalid_agent_alias",
        ProposalErrorCode::ReservedAgentAlias => "reserved_agent_alias",
        ProposalErrorCode::AgentAliasExists => "agent_alias_exists",
        ProposalErrorCode::ProviderUnavailable => "provider_alias_unknown",
        ProposalErrorCode::RiskChoiceUnavailable => "risk_choice_unavailable",
        ProposalErrorCode::RuntimeChoiceUnavailable => "runtime_choice_unavailable",
        ProposalErrorCode::NoncanonicalPersonalityFile => "noncanonical_personality_file",
        ProposalErrorCode::DuplicatePersonalityFile => "duplicate_personality_file",
        ProposalErrorCode::PersonalityFileTooLarge => "personality_file_too_large",
        ProposalErrorCode::TooManyPersonalityFiles => "too_many_personality_files",
        ProposalErrorCode::UncontainedPosture => "uncontained_posture",
        ProposalErrorCode::ProfileDrift => "profile_drift",
        ProposalErrorCode::ProviderTargetDrift => "provider_target_drift",
    }
}

/// The diagnostic one proposal rejection produces.
#[must_use]
pub fn diagnostic_for(error: &ProposalError) -> Diagnostic {
    Diagnostic {
        severity: "error".to_string(),
        code: diagnostic_code(error.code).to_string(),
        // `ProposalError::field` is a typed-operation field path such as
        // `agent_alias` or `personality_files[0].content`, produced by this
        // crate's validators. It never carries a caller value or a host path.
        path: error.field.clone(),
        message: diagnostic_message(error.code).to_string(),
    }
}

/// The wire error code one `ControlService` refusal maps to.
///
/// Host-state failures collapse to [`ControlErrorCode::InternalError`] on
/// purpose: `SourceSchemaOutdated` and `ConfigDegraded` describe the host's
/// configuration, and the specification forbids disclosing configured-instance
/// facts to a client. `ConfigBusy` is the one host condition that is also a
/// statement about the caller's request — the revision moved under the read —
/// so it maps to [`ControlErrorCode::StaleSourceRevision`] and is retryable.
///
/// The apply-path variants are unreachable from this protocol version because
/// `ControlService::apply` is not wired to any tool; they are mapped
/// defensively rather than left to a catch-all that could later leak.
#[must_use]
pub fn error_code_for(error: &ControlError) -> ControlErrorCode {
    match error {
        ControlError::Proposal(_) => ControlErrorCode::ValidationFailed,
        ControlError::ConfigBusy => ControlErrorCode::StaleSourceRevision,
        ControlError::SourceSchemaOutdated
        | ControlError::ConfigDegraded
        | ControlError::Apply { .. }
        | ControlError::AmbiguousCommit { .. }
        | ControlError::VerificationFailed
        | ControlError::Host(_) => ControlErrorCode::InternalError,
    }
}

/// The typed refusal one `ControlService` error becomes on the wire.
#[must_use]
pub fn protocol_error_for(error: &ControlError, operation: &str) -> ProtocolError {
    let code = error_code_for(error);
    let refusal = ProtocolError::new(code, operation);
    match error {
        ControlError::Proposal(proposal) => {
            refusal.with_diagnostics(vec![diagnostic_for(proposal)])
        }
        _ => refusal,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_serialization_sorts_object_keys_at_every_depth() {
        let value = serde_json::json!({
            "b": 1,
            "a": { "z": [3, { "y": 1, "x": 2 }], "c": null },
        });
        assert_eq!(
            canonical_json(&value),
            r#"{"a":{"c":null,"z":[3,{"x":2,"y":1}]},"b":1}"#
        );
    }

    #[test]
    fn the_capability_digest_is_stable_and_moves_with_the_tool_set() {
        let baseline = CapabilitySet::current();
        assert_eq!(
            capability_digest(&baseline),
            capability_digest(&CapabilitySet::current()),
            "the digest must not move between calls in one build"
        );
        assert_eq!(
            capability_digest(&baseline),
            "sha256:835c3c0815a6f29d6ad52917eb04023823e0dce775f9bbeec243f87abeb42065",
            "a change here is a protocol change and must be deliberate"
        );

        let mut with_new_tool = baseline.clone();
        with_new_tool.tools.push("control.apply".to_string());
        assert_ne!(
            capability_digest(&baseline),
            capability_digest(&with_new_tool),
            "adding a tool must invalidate every outstanding preview"
        );

        let mut without_a_tool = baseline.clone();
        without_a_tool.tools.retain(|name| name != TOOL_PREVIEW);
        assert_ne!(
            capability_digest(&baseline),
            capability_digest(&without_a_tool),
            "removing a tool must invalidate every outstanding preview"
        );

        let mut wider_capabilities = baseline.clone();
        wider_capabilities.capabilities.push("plugins".to_string());
        assert_ne!(
            capability_digest(&baseline),
            capability_digest(&wider_capabilities)
        );
    }

    #[test]
    fn the_registry_defines_exactly_the_phase5_surface_and_no_model_callable_approve() {
        assert_eq!(
            tool_names(),
            vec![
                "control.ping",
                "control.server_info",
                "control.registration_help",
                "control.catalog",
                "control.describe",
                "control.inspect",
                "control.validate",
                "control.preview",
                "control.request_apply",
                "control.status",
                "control.verify",
            ]
        );
        let always: Vec<&str> = TOOLS
            .iter()
            .filter(|entry| entry.gate == ToolGate::Always)
            .map(|entry| entry.name)
            .collect();
        assert_eq!(
            always,
            vec![
                "control.ping",
                "control.server_info",
                "control.registration_help"
            ]
        );
        // The invariant the whole architecture exists to protect: no tool
        // approves, applies config, or otherwise finalizes a mutation. The one
        // durable-effect tool, `control.request_apply`, parks a proposal and
        // nothing more. Adding any of these names is the confused-deputy tool
        // this test forbids.
        for forbidden in [
            "control.approve",
            "control.reject",
            "control.apply",
            "control.finalize",
            "control.commit",
            "control.enable_mutations",
        ] {
            assert!(
                tool(forbidden).is_none(),
                "{forbidden} must never be a model-callable tool"
            );
        }
    }

    #[test]
    fn the_read_domains_that_gate_tools_are_exactly_the_grantable_ones() {
        use std::collections::BTreeSet;

        let grantable: BTreeSet<&str> = crate::client_registry::READ_DOMAINS_V1
            .iter()
            .copied()
            .collect();
        let mut gating: BTreeSet<&str> = BTreeSet::new();
        for entry in TOOLS {
            match entry.gate {
                ToolGate::Always => assert!(
                    entry.required_read_domains.is_empty(),
                    "{} is always available and must name no read domain",
                    entry.name
                ),
                ToolGate::RegisteredGrant => {
                    assert!(
                        !entry.required_read_domains.is_empty(),
                        "{} is grant-gated and must name the domains that reach it",
                        entry.name
                    );
                    for domain in entry.required_read_domains {
                        assert!(
                            grantable.contains(domain),
                            "{} names {domain}, which no registration can grant",
                            entry.name
                        );
                        gating.insert(domain);
                    }
                }
            }
        }
        assert_eq!(
            gating, grantable,
            "every grantable read domain must gate something, or a registration \
             could name a domain that changes nothing"
        );
    }

    #[test]
    fn the_startup_refusal_vocabulary_is_disjoint_from_the_v1_error_table() {
        let tool_codes: Vec<&str> = ControlErrorCode::ALL.iter().map(|c| c.as_str()).collect();
        for code in StartupRefusalCode::ALL {
            assert!(
                !tool_codes.contains(&code.as_str()),
                "{} collides with a v1 tool error code",
                code.as_str()
            );
            assert_eq!(StartupRefusal::new(code).code, code);
        }
        assert_eq!(StartupRefusalCode::ALL.len(), 7);
        assert_eq!(STARTUP_REFUSAL_META_KEY, "control_startup_refusal");
    }

    #[test]
    fn every_error_code_carries_fixed_path_free_text() {
        for code in ControlErrorCode::ALL {
            let error = ProtocolError::new(code, "control.inspect");
            assert_eq!(error.message, code.message());
            assert!(
                !error.message.contains('/') && !error.message.contains('\\'),
                "{} carries a path separator",
                code.as_str()
            );
            assert!(error.details.is_empty());
        }
    }

    #[test]
    fn the_generated_schemas_describe_the_compiled_types() {
        let schema = schema_value::<AgentCreateContainedOperation>();
        let properties = schema
            .get("properties")
            .and_then(Value::as_object)
            .expect("the operation schema declares properties");
        for field in [
            "provider_alias",
            "agent_alias",
            "risk",
            "runtime",
            "memory",
            "personality_files",
        ] {
            assert!(properties.contains_key(field), "{field} is missing");
        }
        assert!(
            !schema_value::<PreviewResult>()
                .get("properties")
                .and_then(Value::as_object)
                .expect("the preview schema declares properties")
                .is_empty()
        );
    }

    #[test]
    fn describe_covers_only_the_one_operation_this_version_implements() {
        assert!(describe(OPERATION_AGENT_CREATE_CONTAINED).is_some());
        assert!(describe("agent.delete").is_none());
        assert!(describe("provider.add").is_none());

        let filtered = catalog(Some(&["provider".to_string()]));
        assert!(filtered.operations.is_empty());
        let unfiltered = catalog(None);
        assert_eq!(unfiltered.operations.len(), 1);
        assert_eq!(
            unfiltered.operations[0].operation_id,
            OPERATION_AGENT_CREATE_CONTAINED
        );
    }
}
