//! The durable proposal journal: phase 5's single source of truth for every
//! in-flight and terminal management transaction.
//!
//! This module owns the state machine defined by
//! `docs/book/src/architecture/control-plane-proposal-journal.md`, the durable
//! consumed-receipt set that makes an approval single-use *across restarts*, and
//! the per-requester quotas that bound journal growth. It writes **no
//! configuration**: parking a proposal and recording an approval are
//! journal-only facts. The one place host state is mutated as a result of the
//! control plane is [`crate::apply_worker`], which drives the existing
//! Quickstart compare-and-swap under the atomic `approved` to `applying` claim.
//!
//! ## Durability model
//!
//! The whole journal is one sealed artefact under `<data_root>/control/`
//! ([`crate::store::CONTROL_STATE_DIR`]). Every transition rewrites it
//! atomically through [`crate::store::publish_replace`] — write to a temporary
//! sibling, `fsync`, rename, `fsync` the directory — so the journal is **always
//! ahead of the filesystem**: it is committed and synced before any config
//! change. Receipt consumption and the `approved` to `applying` record are
//! therefore one durable fact, because they are two fields written by one
//! atomic file replacement. A journal that trailed the config could not classify
//! what happened after a crash; this ordering is what makes recovery sound.
//!
//! ## Authentication
//!
//! The artefact is sealed under the instance's ADR-015 approval/audit key, the
//! same key the genesis record and registries use, with its own domain label so
//! a file of another kind renamed over it fails authentication rather than being
//! parsed. The tag covers a canonical encoding of the payload; a payload that
//! cannot be canonicalized is a fail-closed error, never a silently-defaulted
//! read.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::approval::{
    ApprovalError, ApprovalErrorCode, AuthenticatedReceipt, ConsumptionMarker, ProposalDigest,
    ReceiptId, ReceiptLedger, SourceRevisionDigest,
};
use crate::keys::{ApprovalAuditKey, Tag};
use crate::meta_authority::ControlOperation;
use crate::operator::{PrincipalClass, RequesterContext, RequesterFingerprint};
use crate::proposal::AgentProposal;
use crate::registry::{InstanceFingerprint, InstanceId};
use crate::service::BoundProposal;
use crate::store::{
    ControlPaths, StoreError, absorb_field, absorb_str, absorb_u64, ensure_state_dir, os_random_32,
    publish_replace, read_optional,
};

/// File name of the sealed proposal journal, under the control state directory.
pub const JOURNAL_FILE: &str = "journal.json";

/// Domain-separation label bound into the journal's authentication tag. The
/// `/v1` suffix means a change to what is authenticated is a new label, never a
/// silent reinterpretation of an old file.
const JOURNAL_DOMAIN: &str = "zeroclaw/control-plane/proposal-journal/v1";

/// On-disk format version bound into the tag.
const JOURNAL_FORMAT_VERSION: u32 = 1;

/// Domain label for the resume-secret verifier digest. The verifier is a digest
/// of the secret under this label, never the secret itself.
const RESUME_SECRET_LABEL: &str = "zeroclaw/control-plane/resume-secret/v1";

/// Default proposal lifetime if a caller does not pin one.
pub const DEFAULT_PROPOSAL_TTL_SECS: u64 = 15 * 60;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Stable classification for a journal failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JournalErrorCode {
    /// The sealed journal could not be read, parsed, or authenticated.
    Store,
    /// A payload could not be canonicalized or serialized.
    Encode,
    /// The requested operation identifier is not in the journal.
    UnknownOperation,
    /// A state transition the machine does not permit was attempted.
    IllegalTransition,
    /// A per-requester quota would be exceeded by this request.
    QuotaExceeded,
    /// The proposal digest could not be derived from the bound proposal.
    DigestUnavailable,
    /// The wall clock stepped back below the last recorded journal time, or the
    /// time source is otherwise not trustworthy. The affected credential
    /// expires rather than extends.
    ClockUntrustworthy,
    /// The proposal, receipt, or resume secret is past its expiry.
    Expired,
    /// A recorded approval does not bind to this entry.
    ApprovalBindingMismatch,
    /// A caller is not the requester bound to this entry.
    RequesterMismatch,
    /// The random source needed for an identifier or secret was unavailable.
    RandomSource,
}

/// A journal failure.
///
/// `detail` carries a diagnostic. It never carries a secret, a receipt body, or
/// a config value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalError {
    pub code: JournalErrorCode,
    pub detail: String,
}

impl JournalError {
    pub(crate) fn new(code: JournalErrorCode, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }

    fn store(error: StoreError) -> Self {
        Self::new(JournalErrorCode::Store, error.to_string())
    }
}

impl std::fmt::Display for JournalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let what = match self.code {
            JournalErrorCode::Store => "journal durable state error",
            JournalErrorCode::Encode => "journal payload could not be encoded",
            JournalErrorCode::UnknownOperation => "no such operation in the journal",
            JournalErrorCode::IllegalTransition => "illegal journal state transition",
            JournalErrorCode::QuotaExceeded => "per-requester quota exceeded",
            JournalErrorCode::DigestUnavailable => "proposal digest unavailable",
            JournalErrorCode::ClockUntrustworthy => "time source is not trustworthy",
            JournalErrorCode::Expired => "credential is past its expiry",
            JournalErrorCode::ApprovalBindingMismatch => "approval does not bind to this entry",
            JournalErrorCode::RequesterMismatch => "requester is not bound to this entry",
            JournalErrorCode::RandomSource => "operating system random source unavailable",
        };
        write!(f, "{what}: {}", self.detail)
    }
}

impl std::error::Error for JournalError {}

// ---------------------------------------------------------------------------
// Identifiers
// ---------------------------------------------------------------------------

/// A journal operation identifier.
///
/// Path-safe and opaque: minted from the OS random source, prefixed, and
/// constrained to `[A-Za-z0-9._-]` so it can never be spliced into a path.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct OperationId(String);

impl OperationId {
    /// Mint a fresh identifier from the operating system random source.
    ///
    /// # Errors
    ///
    /// Returns [`JournalErrorCode::RandomSource`] when the OS random source is
    /// unavailable.
    pub fn generate() -> Result<Self, JournalError> {
        let bytes = os_random_32()
            .map_err(|e| JournalError::new(JournalErrorCode::RandomSource, e.detail))?;
        Ok(Self(format!("op-{}", hex::encode(&bytes[..16]))))
    }

    /// Validate and wrap an identifier.
    ///
    /// # Errors
    ///
    /// Returns [`JournalErrorCode::Store`] for anything outside `[A-Za-z0-9._-]`
    /// or longer than 128 bytes.
    pub fn new(value: impl Into<String>) -> Result<Self, JournalError> {
        let value = value.into();
        if value.is_empty() || value.len() > 128 {
            return Err(JournalError::new(
                JournalErrorCode::Store,
                "operation id length is out of range",
            ));
        }
        if !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-')
        {
            return Err(JournalError::new(
                JournalErrorCode::Store,
                "operation id contains an unacceptable character",
            ));
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for OperationId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for OperationId {
    type Error = JournalError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<OperationId> for String {
    fn from(value: OperationId) -> Self {
        value.0
    }
}

/// A stable identifier for one declared effect, referenced by the recorded
/// apply order.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct EffectId(String);

impl EffectId {
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// An opaque, single-proposal resume secret.
///
/// Returned to the caller exactly once at park time. The journal stores only a
/// verifier ([`ResumeSecretVerifier`]), never the secret, exactly as client
/// credentials are stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResumeSecret(String);

impl ResumeSecret {
    /// Mint a fresh opaque resume secret from the OS random source.
    ///
    /// # Errors
    ///
    /// Returns [`JournalErrorCode::RandomSource`] when the OS random source is
    /// unavailable.
    pub(crate) fn generate() -> Result<Self, JournalError> {
        let bytes = os_random_32()
            .map_err(|e| JournalError::new(JournalErrorCode::RandomSource, e.detail))?;
        Ok(Self(format!("resume-{}", hex::encode(bytes))))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn verifier(&self) -> ResumeSecretVerifier {
        let mut message = Vec::new();
        absorb_str(&mut message, RESUME_SECRET_LABEL);
        absorb_str(&mut message, &self.0);
        let mut hasher = Sha256::new();
        hasher.update(&message);
        ResumeSecretVerifier(hasher.finalize().into())
    }
}

/// The stored verifier for a [`ResumeSecret`]. A digest of the secret under a
/// domain label; the secret cannot be recovered from it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct ResumeSecretVerifier(#[serde(with = "hex_array")] [u8; 32]);

// ---------------------------------------------------------------------------
// The state machine
// ---------------------------------------------------------------------------

/// A journal entry's durable state.
///
/// The names are exactly those in the design's state machine, and [`Self::wire`]
/// is what Status reports. The transition table
/// ([`JournalState::may_transition_to`]) is the single encoding of which moves
/// are legal; an attempt at any other move is a fail-closed runtime refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JournalState {
    /// An immutable proposal exists, bound to its target, revision, requester,
    /// digest, dependencies, effects, and expiration.
    Prepared,
    /// The proposal has been presented to an eligible operator backchannel.
    AwaitingApproval,
    /// An operator decided against it.
    Rejected,
    /// A binding fact changed or the deadline passed before a decision.
    Expired,
    /// A valid receipt exists and has been recorded, but not consumed.
    Approved,
    /// The receipt has been consumed and effects are being written.
    Applying,
    /// Every declared effect reached its expected post-image.
    Applied,
    /// The verification plan confirmed effective runtime state.
    Verified,
    /// Apply stopped with every effect classified.
    Failed,
    /// At least one effect could not be classified, or an ambiguity survived
    /// recovery. A parked state awaiting operator resolution; it has no
    /// auto-exit.
    RecoveryRequired,
}

impl JournalState {
    /// The verbatim design name for this state.
    #[must_use]
    pub const fn wire(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::AwaitingApproval => "awaiting_approval",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
            Self::Approved => "approved",
            Self::Applying => "applying",
            Self::Applied => "applied",
            Self::Verified => "verified",
            Self::Failed => "failed",
            Self::RecoveryRequired => "recovery_required",
        }
    }

    /// A terminal state has no successor a requester or worker can reach in this
    /// lane. `recovery_required` is terminal here because operator resolution is
    /// out of this lane's scope.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Rejected | Self::Expired | Self::Verified | Self::Failed | Self::RecoveryRequired
        )
    }

    /// Whether the durable bytes of an entry in this state are attributable to
    /// its requester's parked-byte budget. Terminal-but-freed states release
    /// their bytes; an in-flight or parked-for-recovery entry still holds them.
    #[must_use]
    const fn counts_against_parked_bytes(self) -> bool {
        !matches!(
            self,
            Self::Rejected | Self::Expired | Self::Verified | Self::Failed
        )
    }

    /// The single encoding of the legal state machine. Every move not listed
    /// here is refused.
    #[must_use]
    pub const fn may_transition_to(self, to: Self) -> bool {
        matches!(
            (self, to),
            (Self::Prepared, Self::AwaitingApproval)
                | (Self::Prepared, Self::Expired)
                | (Self::AwaitingApproval, Self::Approved)
                | (Self::AwaitingApproval, Self::Rejected)
                | (Self::AwaitingApproval, Self::Expired)
                | (Self::AwaitingApproval, Self::RecoveryRequired)
                | (Self::Approved, Self::Applying)
                | (Self::Approved, Self::Expired)
                | (Self::Approved, Self::RecoveryRequired)
                | (Self::Applying, Self::Applied)
                | (Self::Applying, Self::Failed)
                | (Self::Applying, Self::RecoveryRequired)
                | (Self::Applied, Self::Verified)
                | (Self::Applied, Self::RecoveryRequired)
        )
    }
}

// ---------------------------------------------------------------------------
// Effects
// ---------------------------------------------------------------------------

/// The kind of durable artefact one declared effect writes.
///
/// Each variant carries the identity of the artefact's *expected post-image*, so
/// a classifier can decide whether an observed artefact matches it without a
/// separate stored digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ArtifactKind {
    /// The instance `config.toml`. Its expected post-image is "the bound
    /// revision plus exactly this agent" — a structural identity, because the
    /// exact bytes Quickstart writes are not deterministic. Recovery never
    /// infers success from the config digest alone.
    Config {
        /// The agent alias the approved effect adds.
        agent_alias: String,
    },
    /// One personality file in the new agent's workspace. Its expected
    /// post-image is the exact content digest.
    PersonalityFile {
        /// Path relative to the agent workspace directory.
        relative_path: String,
        /// Digest of the exact file content the proposal declares.
        #[serde(with = "hex_array")]
        content_sha256: [u8; 32],
    },
}

/// Whether an effect can be undone without a new approval, and how.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "rollback", rename_all = "snake_case")]
pub enum RollbackDeclaration {
    /// The config commit is all-or-nothing through the Quickstart revision-bound
    /// CAS: a refused commit leaves the bound revision untouched, so the CAS
    /// itself is the rollback artefact.
    QuickstartAtomicCas,
    /// The artefact is a new file in a previously-absent workspace; removing it
    /// restores the pre-image.
    NewFileRemoval,
}

/// The image identity an artefact had, or must have.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "image", rename_all = "snake_case")]
pub enum EffectImage {
    /// The artefact was absent.
    Absent,
    /// The artefact's exact bytes digested to this value.
    Digest {
        #[serde(with = "hex_array")]
        sha256: [u8; 32],
    },
}

/// One effect's recovery classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectClassification {
    /// The artefact matches its recorded pre-image. It did not happen and may be
    /// attempted under the existing consumed receipt.
    NotApplied,
    /// The artefact matches its expected post-image. It happened and must not be
    /// repeated.
    AppliedNotVerified,
    /// The artefact matches neither image. Nothing may be inferred; the whole
    /// operation parks in `recovery_required`.
    Ambiguous,
}

impl EffectClassification {
    #[must_use]
    pub const fn wire(self) -> &'static str {
        match self {
            Self::NotApplied => "not_applied",
            Self::AppliedNotVerified => "applied_not_verified",
            Self::Ambiguous => "ambiguous",
        }
    }
}

/// One declared effect of a proposal, with the slots recovery fills in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeclaredEffect {
    /// Stable identifier, referenced by the recorded apply order.
    pub effect_id: EffectId,
    /// What artefact this effect writes and its expected post-image identity.
    pub artifact_kind: ArtifactKind,
    /// The rollback artefact, or the declared reason none is needed.
    pub rollback: RollbackDeclaration,
    /// Whether the effect can be undone without a new approval.
    pub reversible: bool,
    /// Whether the effect has an irreversible external side effect. Always
    /// `false` for the v1 add-agent operation.
    pub irreversible_external: bool,
    /// The pre-image captured under lock at claim time, before any write. Absent
    /// until the atomic claim records it.
    pub pre_image: Option<EffectImage>,
    /// The classification recovery observed, if recovery has run.
    pub observed: Option<EffectClassification>,
}

/// The verification plan a successful apply is judged against.
///
/// For the v1 add-agent operation the plan is fixed: re-read effective config
/// and confirm the approved agent is present, bound, and complete — exactly the
/// checks [`crate::service::ControlService::apply`] performs internally. The
/// plan is recorded so Verify can report what it confirmed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationPlan {
    /// The agent alias whose effective presence must be confirmed.
    pub expected_agent_alias: String,
}

/// The read-only Status surface: the exact durable state and bounded progress
/// of one proposal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusReport {
    /// The durable state, reported by name.
    pub state: JournalState,
    /// The operation being decided and applied.
    pub operation: ControlOperation,
    /// Expiry, seconds since the Unix epoch.
    pub expires_at_unix_secs: u64,
    /// How many effects the proposal declares.
    pub effects_total: usize,
    /// How many declared effects have reached their expected post-image, as
    /// bounded progress — never a substitute for the state name.
    pub effects_reached_post_image: usize,
    /// A short, non-secret note on why a terminal or parked state was entered.
    pub disposition: Option<String>,
}

// ---------------------------------------------------------------------------
// Journal entry
// ---------------------------------------------------------------------------

/// One immutable proposal and everything durable about its transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalEntry {
    /// The operation identifier.
    pub operation_id: OperationId,
    /// The operation being decided and applied.
    pub operation: ControlOperation,
    /// Canonical digest of the immutable proposal.
    pub proposal_digest: ProposalDigest,
    /// The agent proposal payload, a durable reference the worker re-mints the
    /// bound proposal from against the current config. Combined with the digest,
    /// any drift in the resulting preview is caught at claim.
    pub agent_proposal: AgentProposal,
    /// The provider alias the proposal selected.
    pub selected_provider_ref: String,
    /// The registered instance this transaction targets.
    pub target_instance: InstanceId,
    /// Digest of the source revision the preview was built against.
    pub source_revision: SourceRevisionDigest,
    /// The instance fingerprint recomputed under lock at park time.
    pub instance_fingerprint: InstanceFingerprint,
    /// The requester principal class.
    pub requester_class: PrincipalClass,
    /// The host-derived requester subject.
    pub requester_subject: String,
    /// The requester's binding fingerprint, which the receipt is bound to.
    pub requester_fingerprint: RequesterFingerprint,
    /// Attribution only: the client's `registration_id` (the owner token). It
    /// conveys no approval authority and is not the resume secret.
    pub owner_token: String,
    /// Attribution only: the client session that parked this proposal.
    pub client_session: String,
    /// The verifier for this proposal's single opaque resume secret.
    resume_secret_verifier: ResumeSecretVerifier,
    /// The declared effects and the slots recovery fills in.
    pub effects: Vec<DeclaredEffect>,
    /// The verification plan a successful apply is judged against.
    pub verification_plan: VerificationPlan,
    /// Park time, seconds since the Unix epoch.
    pub created_at_unix_secs: u64,
    /// Expiry, seconds since the Unix epoch. Exclusive.
    pub expires_at_unix_secs: u64,
    /// The current durable state.
    pub state: JournalState,
    /// The sealed approval receipt recorded at `approved`, hex-encoded. Present
    /// from `approved` onward.
    recorded_receipt: Option<String>,
    /// The receipt consumed at the atomic claim. Present from `applying` onward.
    pub consumed_receipt_id: Option<ReceiptId>,
    /// The recorded apply order, by effect id, written before the first effect.
    pub apply_order: Vec<EffectId>,
    /// A short, non-secret note on why a terminal or parked state was entered.
    pub disposition: Option<String>,
}

impl JournalEntry {
    /// The exact `config.toml` effect this entry declares, if any.
    #[must_use]
    pub fn config_effect(&self) -> Option<&DeclaredEffect> {
        self.effects
            .iter()
            .find(|e| matches!(e.artifact_kind, ArtifactKind::Config { .. }))
    }

    /// The sealed, authenticated recorded receipt, if one has been recorded.
    ///
    /// # Errors
    ///
    /// Returns an approval error when the recorded bytes do not authenticate
    /// under `key`.
    pub fn recorded_receipt(
        &self,
        key: &ApprovalAuditKey,
    ) -> Result<Option<AuthenticatedReceipt>, ApprovalError> {
        let Some(hex_bytes) = self.recorded_receipt.as_ref() else {
            return Ok(None);
        };
        let bytes = hex::decode(hex_bytes)
            .map_err(|e| ApprovalError::new(ApprovalErrorCode::Unparseable, e.to_string()))?;
        Ok(Some(AuthenticatedReceipt::open(&bytes, key)?))
    }
}

// ---------------------------------------------------------------------------
// Quotas
// ---------------------------------------------------------------------------

/// The bounded per-requester quotas the design requires. Exceeding any of them
/// refuses a new proposal; a refusal never evicts, invalidates, reorders, or
/// discloses another requester's state, and never notifies an operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Quotas {
    /// Maximum concurrent entries in `prepared`.
    pub max_prepared: usize,
    /// Maximum concurrent entries in `awaiting_approval`.
    pub max_awaiting_approval: usize,
    /// Maximum total durable bytes attributable to one requester.
    pub max_parked_bytes: usize,
    /// Maximum park requests per requester within [`Self::rate_interval_secs`].
    pub max_requests_per_interval: usize,
    /// The rate window, in seconds.
    pub rate_interval_secs: u64,
}

impl Default for Quotas {
    fn default() -> Self {
        Self {
            max_prepared: 8,
            max_awaiting_approval: 8,
            max_parked_bytes: 256 * 1024,
            max_requests_per_interval: 16,
            rate_interval_secs: 60,
        }
    }
}

// ---------------------------------------------------------------------------
// Park request
// ---------------------------------------------------------------------------

/// Everything [`ProposalJournal::park`] needs to write an immutable
/// `prepared` to `awaiting_approval` entry.
pub struct ParkRequest<'a> {
    /// The operation being parked.
    pub operation: ControlOperation,
    /// The bound proposal, used only to derive the canonical digest and source
    /// revision. It is not stored; a durable reference is stored instead.
    pub bound: &'a BoundProposal,
    /// The agent proposal payload the worker re-mints from.
    pub agent_proposal: &'a AgentProposal,
    /// The provider alias the proposal selected.
    pub selected_provider_ref: &'a str,
    /// The registered instance being targeted.
    pub target_instance: InstanceId,
    /// The instance fingerprint recomputed under lock.
    pub instance_fingerprint: InstanceFingerprint,
    /// The requester parking the proposal.
    pub requester: &'a RequesterContext,
    /// The client's `registration_id` (owner token, attribution only).
    pub owner_token: String,
    /// The client session (attribution only).
    pub client_session: String,
    /// The proposal lifetime in seconds.
    pub proposal_ttl_secs: u64,
}

// ---------------------------------------------------------------------------
// The durable journal
// ---------------------------------------------------------------------------

/// The whole sealed proposal journal.
///
/// One instance per managed target. Loaded from disk, mutated in memory, and
/// re-sealed atomically on every transition. The consumed-receipt set is part of
/// the durable payload, so [`DurableReceiptLedger`] enforces single-use across
/// restarts.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProposalJournal {
    /// The highest wall-clock time the journal has ever recorded. A monotonic
    /// high-water mark: a `now` below it means the clock stepped back and the
    /// time source is untrustworthy, so affected credentials expire.
    high_water_unix_secs: u64,
    /// Every entry, keyed by operation id.
    entries: BTreeMap<OperationId, JournalEntry>,
    /// The durable consumed-receipt set. One consumption, ever, across restarts.
    consumed_receipts: BTreeSet<ReceiptId>,
    /// Proposal digests a rejection is terminal for.
    rejected_proposals: BTreeSet<ProposalDigest>,
    /// A rolling record of recent park request times per requester fingerprint,
    /// for rate limiting. Bounded: entries older than the widest rate window are
    /// pruned on each park.
    #[serde(default)]
    recent_park_times: BTreeMap<String, Vec<u64>>,
}

impl ProposalJournal {
    /// Load the sealed journal at `paths`, or an empty journal if none exists.
    ///
    /// # Errors
    ///
    /// Returns [`JournalErrorCode::Store`] when a present journal cannot be read
    /// or does not authenticate under `key`. Absence is not an error; a
    /// first-run instance has no journal.
    pub fn load(paths: &ControlPaths, key: &ApprovalAuditKey) -> Result<Self, JournalError> {
        let path = paths.control_dir().join(JOURNAL_FILE);
        match read_optional(&path).map_err(JournalError::store)? {
            None => Ok(Self::default()),
            Some(bytes) => open_journal(&bytes, key),
        }
    }

    /// Atomically re-seal and persist the journal. This is the commit point: it
    /// returns only after the bytes are on disk and the directory is synced, so
    /// the journal is ahead of any config change that follows.
    ///
    /// # Errors
    ///
    /// Returns [`JournalErrorCode::Encode`] when the payload cannot be sealed and
    /// [`JournalErrorCode::Store`] when the atomic write fails.
    pub fn persist(
        &self,
        paths: &ControlPaths,
        key: &ApprovalAuditKey,
    ) -> Result<(), JournalError> {
        let dir = paths.control_dir();
        ensure_state_dir(&dir).map_err(JournalError::store)?;
        let bytes = seal_journal(self, key)?;
        publish_replace(&dir.join(JOURNAL_FILE), &bytes).map_err(JournalError::store)
    }

    /// The durable high-water time.
    #[must_use]
    pub fn high_water_unix_secs(&self) -> u64 {
        self.high_water_unix_secs
    }

    /// An immutable view of one entry, scoped to the requester that owns it.
    ///
    /// Returns [`JournalErrorCode::UnknownOperation`] rather than disclosing that
    /// the entry belongs to another requester: persisted proposals are not
    /// enumerable across owners.
    ///
    /// # Errors
    ///
    /// See above.
    pub fn entry_for(
        &self,
        operation_id: &OperationId,
        requester: &RequesterContext,
    ) -> Result<&JournalEntry, JournalError> {
        match self.entries.get(operation_id) {
            Some(entry) if entry.requester_fingerprint == requester.fingerprint() => Ok(entry),
            _ => Err(JournalError::new(
                JournalErrorCode::UnknownOperation,
                operation_id.as_str().to_owned(),
            )),
        }
    }

    /// The entry for `operation_id`, unscoped. For the host worker and recovery,
    /// which are not requester-facing.
    #[must_use]
    pub fn entry(&self, operation_id: &OperationId) -> Option<&JournalEntry> {
        self.entries.get(operation_id)
    }

    /// Every entry, for recovery and host-side status. Not a requester surface.
    pub fn iter(&self) -> impl Iterator<Item = &JournalEntry> {
        self.entries.values()
    }

    /// Resolve the one proposal an opaque resume secret grants access to.
    ///
    /// The secret must match a stored verifier **and** the caller must be the
    /// registered requester bound to that entry. Neither conveys approval
    /// authority.
    ///
    /// # Errors
    ///
    /// Returns [`JournalErrorCode::UnknownOperation`] when no entry matches both
    /// the secret and the requester binding.
    pub fn resolve_resume_secret(
        &self,
        secret: &ResumeSecret,
        requester: &RequesterContext,
    ) -> Result<&JournalEntry, JournalError> {
        let verifier = secret.verifier();
        let fingerprint = requester.fingerprint();
        self.entries
            .values()
            .find(|entry| {
                entry.resume_secret_verifier == verifier
                    && entry.requester_fingerprint == fingerprint
            })
            .ok_or_else(|| {
                JournalError::new(
                    JournalErrorCode::UnknownOperation,
                    "no matching parked proposal",
                )
            })
    }

    /// Advance the high-water mark, refusing a clock that stepped backwards.
    ///
    /// This is the durable half of the clock rule: a `now` below the last
    /// recorded time means the wall clock rolled back, which expires rather than
    /// extends. The caller must have already resolved `now` from a trusted
    /// source; passing a value below the high-water mark is treated as a rollback
    /// regardless.
    fn advance_clock(&mut self, now_unix_secs: u64) -> Result<(), JournalError> {
        if now_unix_secs < self.high_water_unix_secs {
            return Err(JournalError::new(
                JournalErrorCode::ClockUntrustworthy,
                format!(
                    "now {now_unix_secs} is below the last recorded time {}",
                    self.high_water_unix_secs
                ),
            ));
        }
        self.high_water_unix_secs = now_unix_secs;
        Ok(())
    }

    /// Park a proposal: write an immutable `prepared` then `awaiting_approval`
    /// entry. Changes no config.
    ///
    /// Returns the operation id and the one opaque resume secret, which is
    /// returned exactly once and never stored.
    ///
    /// # Errors
    ///
    /// Returns [`JournalErrorCode::QuotaExceeded`] when a per-requester quota
    /// would be exceeded (without evicting any entry),
    /// [`JournalErrorCode::ClockUntrustworthy`] on a backward clock step,
    /// [`JournalErrorCode::DigestUnavailable`] when the digest cannot be derived,
    /// and store/encode errors on a failed durable write.
    pub fn park(
        &mut self,
        request: &ParkRequest<'_>,
        now_unix_secs: u64,
        quotas: &Quotas,
        paths: &ControlPaths,
        key: &ApprovalAuditKey,
    ) -> Result<(OperationId, ResumeSecret), JournalError> {
        self.advance_clock(now_unix_secs)?;
        let fingerprint = request.requester.fingerprint();
        let fp_key = hex::encode(fingerprint.as_bytes());

        self.enforce_quotas(&fingerprint, &fp_key, request, now_unix_secs, quotas)?;

        let proposal_digest = ProposalDigest::of_bound_proposal(request.bound)
            .map_err(|e| JournalError::new(JournalErrorCode::DigestUnavailable, e.detail))?;
        let source_revision = SourceRevisionDigest::of(request.bound.source_revision());
        let operation_id = OperationId::generate()?;
        let resume_secret = ResumeSecret::generate()?;
        let effects = declared_effects(request.agent_proposal);
        let entry = JournalEntry {
            operation_id: operation_id.clone(),
            operation: request.operation,
            proposal_digest,
            agent_proposal: request.agent_proposal.clone(),
            selected_provider_ref: request.selected_provider_ref.to_owned(),
            target_instance: request.target_instance.clone(),
            source_revision,
            instance_fingerprint: request.instance_fingerprint,
            requester_class: request.requester.class(),
            requester_subject: request.requester.subject().as_str().to_owned(),
            requester_fingerprint: fingerprint,
            owner_token: request.owner_token.clone(),
            client_session: request.client_session.clone(),
            resume_secret_verifier: resume_secret.verifier(),
            effects,
            verification_plan: VerificationPlan {
                expected_agent_alias: request.agent_proposal.agent_alias.clone(),
            },
            created_at_unix_secs: now_unix_secs,
            expires_at_unix_secs: now_unix_secs.saturating_add(request.proposal_ttl_secs),
            // `prepared` and `awaiting_approval` are one indivisible park step;
            // the entry is written directly into `awaiting_approval` after the
            // `prepared` invariants are all satisfied. The transition is recorded
            // as legal by construction.
            state: JournalState::AwaitingApproval,
            recorded_receipt: None,
            consumed_receipt_id: None,
            apply_order: Vec::new(),
            disposition: None,
        };
        debug_assert!(JournalState::Prepared.may_transition_to(JournalState::AwaitingApproval));
        self.entries.insert(operation_id.clone(), entry);
        // Record this park time and prune anything older than the rate window,
        // so the rolling record stays bounded rather than growing without limit.
        let window_start = now_unix_secs.saturating_sub(quotas.rate_interval_secs);
        let times = self.recent_park_times.entry(fp_key).or_default();
        times.retain(|t| *t >= window_start);
        times.push(now_unix_secs);
        self.persist(paths, key)?;
        Ok((operation_id, resume_secret))
    }

    /// Enforce the per-requester quotas without evicting anything.
    fn enforce_quotas(
        &self,
        fingerprint: &RequesterFingerprint,
        fp_key: &str,
        _request: &ParkRequest<'_>,
        now_unix_secs: u64,
        quotas: &Quotas,
    ) -> Result<(), JournalError> {
        let mut prepared = 0usize;
        let mut awaiting = 0usize;
        let mut parked_bytes = 0usize;
        for entry in self.entries.values() {
            if &entry.requester_fingerprint != fingerprint {
                continue;
            }
            match entry.state {
                JournalState::Prepared => prepared += 1,
                JournalState::AwaitingApproval => awaiting += 1,
                _ => {}
            }
            if entry.state.counts_against_parked_bytes() {
                parked_bytes = parked_bytes.saturating_add(entry_byte_cost(entry));
            }
        }
        // A new park lands in `awaiting_approval`, so it consumes one unit of the
        // awaiting quota. The prepared quota is checked too so the bound holds
        // for any future path that leaves an entry in `prepared`.
        if awaiting >= quotas.max_awaiting_approval || prepared >= quotas.max_prepared {
            return Err(JournalError::new(
                JournalErrorCode::QuotaExceeded,
                "concurrent entry quota reached",
            ));
        }
        let projected = parked_bytes.saturating_add(QUOTA_ENTRY_BYTE_ESTIMATE);
        if projected > quotas.max_parked_bytes {
            return Err(JournalError::new(
                JournalErrorCode::QuotaExceeded,
                "parked-byte quota reached",
            ));
        }
        let window_start = now_unix_secs.saturating_sub(quotas.rate_interval_secs);
        let recent = self
            .recent_park_times
            .get(fp_key)
            .map(|times| times.iter().filter(|t| **t >= window_start).count())
            .unwrap_or(0);
        if recent >= quotas.max_requests_per_interval {
            return Err(JournalError::new(
                JournalErrorCode::QuotaExceeded,
                "request rate quota reached",
            ));
        }
        Ok(())
    }

    /// Record a broker-issued approval receipt against an `awaiting_approval`
    /// entry, moving it to `approved`. Consumes nothing.
    ///
    /// The full, independent re-verification of the receipt happens at the
    /// atomic claim ([`crate::apply_worker`]); recording performs the binding
    /// sanity checks that make `approved` mean "a valid receipt for *this*
    /// proposal exists".
    ///
    /// # Errors
    ///
    /// Returns [`JournalErrorCode::ApprovalBindingMismatch`] when the receipt
    /// does not bind to this entry, [`JournalErrorCode::IllegalTransition`] when
    /// the entry is not `awaiting_approval`, and store/encode errors on a failed
    /// write.
    pub fn record_approval(
        &mut self,
        operation_id: &OperationId,
        receipt: &AuthenticatedReceipt,
        now_unix_secs: u64,
        paths: &ControlPaths,
        key: &ApprovalAuditKey,
    ) -> Result<(), JournalError> {
        self.advance_clock(now_unix_secs)?;
        let entry = self.entries.get(operation_id).ok_or_else(|| {
            JournalError::new(
                JournalErrorCode::UnknownOperation,
                operation_id.as_str().to_owned(),
            )
        })?;
        let recorded = receipt.receipt();
        if recorded.proposal_digest != entry.proposal_digest
            || recorded.target_instance != entry.target_instance
            || recorded.operation != entry.operation
            || recorded.requester_fingerprint != entry.requester_fingerprint
        {
            return Err(JournalError::new(
                JournalErrorCode::ApprovalBindingMismatch,
                "receipt does not bind to this proposal",
            ));
        }
        if !recorded.decision.authorizes() {
            // A rejection is recorded through the rejection path, not here.
            return Err(JournalError::new(
                JournalErrorCode::ApprovalBindingMismatch,
                "receipt does not record an approval",
            ));
        }
        self.transition(
            operation_id,
            JournalState::Approved,
            |entry| {
                entry.recorded_receipt = Some(hex::encode(receipt.as_sealed_bytes()));
            },
            paths,
            key,
        )
    }

    /// Record a rejection as terminal for the entry's proposal digest and move
    /// it to `rejected`.
    ///
    /// # Errors
    ///
    /// See [`Self::transition`].
    pub fn record_rejection(
        &mut self,
        operation_id: &OperationId,
        now_unix_secs: u64,
        paths: &ControlPaths,
        key: &ApprovalAuditKey,
    ) -> Result<(), JournalError> {
        self.advance_clock(now_unix_secs)?;
        let digest = self
            .entries
            .get(operation_id)
            .map(|e| e.proposal_digest)
            .ok_or_else(|| {
                JournalError::new(
                    JournalErrorCode::UnknownOperation,
                    operation_id.as_str().to_owned(),
                )
            })?;
        self.rejected_proposals.insert(digest);
        self.transition(
            operation_id,
            JournalState::Rejected,
            |entry| entry.disposition = Some("operator rejected".to_owned()),
            paths,
            key,
        )
    }

    /// Move an entry to `expired`, recording the reason.
    ///
    /// # Errors
    ///
    /// See [`Self::transition`].
    pub fn expire(
        &mut self,
        operation_id: &OperationId,
        reason: impl Into<String>,
        paths: &ControlPaths,
        key: &ApprovalAuditKey,
    ) -> Result<(), JournalError> {
        let reason = reason.into();
        self.transition(
            operation_id,
            JournalState::Expired,
            |entry| entry.disposition = Some(reason),
            paths,
            key,
        )
    }

    /// Apply a validated, legal state transition to one entry and persist.
    ///
    /// The transition table is consulted first: an illegal move is a fail-closed
    /// refusal, never a silent write. `mutate` runs only after the move is
    /// approved, so it cannot leave the entry in an inconsistent partial state on
    /// a rejected transition.
    ///
    /// # Errors
    ///
    /// Returns [`JournalErrorCode::UnknownOperation`],
    /// [`JournalErrorCode::IllegalTransition`], or a store/encode error.
    pub(crate) fn transition(
        &mut self,
        operation_id: &OperationId,
        to: JournalState,
        mutate: impl FnOnce(&mut JournalEntry),
        paths: &ControlPaths,
        key: &ApprovalAuditKey,
    ) -> Result<(), JournalError> {
        let entry = self.entries.get_mut(operation_id).ok_or_else(|| {
            JournalError::new(
                JournalErrorCode::UnknownOperation,
                operation_id.as_str().to_owned(),
            )
        })?;
        if !entry.state.may_transition_to(to) {
            return Err(JournalError::new(
                JournalErrorCode::IllegalTransition,
                format!("{} -> {}", entry.state.wire(), to.wire()),
            ));
        }
        entry.state = to;
        mutate(entry);
        self.persist(paths, key)
    }

    /// The exact durable status of one proposal, scoped to the requester that
    /// owns it.
    ///
    /// Reports the journal state **by name** and never collapses `approved`,
    /// `applying`, or `recovery_required` into a generic pending result. It
    /// performs no host effect, reads no secret, and discloses nothing about
    /// another requester's proposal — [`Self::entry_for`] refuses a mismatched
    /// requester as "unknown".
    ///
    /// # Errors
    ///
    /// Returns [`JournalErrorCode::UnknownOperation`] when the caller does not
    /// own an entry with this identifier.
    pub fn status(
        &self,
        operation_id: &OperationId,
        requester: &RequesterContext,
    ) -> Result<StatusReport, JournalError> {
        let entry = self.entry_for(operation_id, requester)?;
        let effects_total = entry.effects.len();
        let effects_reached_post_image = entry
            .effects
            .iter()
            .filter(|e| e.observed == Some(EffectClassification::AppliedNotVerified))
            .count();
        Ok(StatusReport {
            state: entry.state,
            operation: entry.operation,
            expires_at_unix_secs: entry.expires_at_unix_secs,
            effects_total,
            effects_reached_post_image,
            disposition: entry.disposition.clone(),
        })
    }

    /// A [`DurableReceiptLedger`] view of this journal, for
    /// [`crate::approval::verify_for_consumption`].
    #[must_use]
    pub fn ledger(&self) -> DurableReceiptLedger<'_> {
        DurableReceiptLedger { journal: self }
    }

    /// Whether a receipt id is already in the durable consumed set.
    #[must_use]
    pub fn is_receipt_consumed(&self, receipt_id: &ReceiptId) -> bool {
        self.consumed_receipts.contains(receipt_id)
    }

    /// Record a consumption in the durable set. Used only by the atomic claim,
    /// inside the same in-memory mutation that records `applying`, before a
    /// single [`Self::persist`] makes both one durable fact.
    ///
    /// # Errors
    ///
    /// Returns [`JournalErrorCode::ApprovalBindingMismatch`] when the receipt is
    /// already consumed — one consumption, ever, across restarts.
    pub(crate) fn mark_receipt_consumed(
        &mut self,
        marker: &ConsumptionMarker,
    ) -> Result<(), JournalError> {
        if self.consumed_receipts.contains(marker.receipt_id()) {
            return Err(JournalError::new(
                JournalErrorCode::ApprovalBindingMismatch,
                "receipt already consumed",
            ));
        }
        self.consumed_receipts.insert(marker.receipt_id().clone());
        Ok(())
    }

    /// Direct mutable access to one entry, for the worker's claim which must
    /// mutate the entry and the consumed set together before one persist. Not a
    /// requester surface.
    pub(crate) fn entry_mut(&mut self, operation_id: &OperationId) -> Option<&mut JournalEntry> {
        self.entries.get_mut(operation_id)
    }
}

/// A rough per-entry byte cost for parked-byte accounting. Serializing each
/// entry precisely on every quota check would be wasteful; a fixed estimate that
/// dominates the fixed fields plus the bounded personality payload keeps the
/// bound conservative.
const QUOTA_ENTRY_BYTE_ESTIMATE: usize = 4 * 1024;

fn entry_byte_cost(entry: &JournalEntry) -> usize {
    let personality: usize = entry
        .agent_proposal
        .personality_files
        .iter()
        .map(|f| f.content.len() + f.filename.len())
        .sum();
    QUOTA_ENTRY_BYTE_ESTIMATE.saturating_add(personality)
}

/// Derive the declared effects of an add-agent proposal: one config effect and
/// one personality-file effect per declared file.
fn declared_effects(proposal: &AgentProposal) -> Vec<DeclaredEffect> {
    let mut effects = Vec::with_capacity(1 + proposal.personality_files.len());
    effects.push(DeclaredEffect {
        effect_id: EffectId::new("config.toml"),
        artifact_kind: ArtifactKind::Config {
            agent_alias: proposal.agent_alias.clone(),
        },
        rollback: RollbackDeclaration::QuickstartAtomicCas,
        reversible: false,
        irreversible_external: false,
        pre_image: None,
        observed: None,
    });
    for file in &proposal.personality_files {
        let mut hasher = Sha256::new();
        hasher.update(file.content.as_bytes());
        effects.push(DeclaredEffect {
            effect_id: EffectId::new(format!("personality:{}", file.filename)),
            artifact_kind: ArtifactKind::PersonalityFile {
                relative_path: file.filename.clone(),
                content_sha256: hasher.finalize().into(),
            },
            rollback: RollbackDeclaration::NewFileRemoval,
            reversible: true,
            irreversible_external: false,
            pre_image: None,
            observed: None,
        });
    }
    effects
}

// ---------------------------------------------------------------------------
// Durable receipt ledger
// ---------------------------------------------------------------------------

/// A [`ReceiptLedger`] backed by the durable journal.
///
/// This is the phase-5 replacement for [`crate::approval::InMemoryReceiptLedger`]:
/// the consumed set is on disk, so a receipt consumed before a restart is still
/// consumed after one, and its single-use guarantee survives a crash.
#[derive(Debug, Clone, Copy)]
pub struct DurableReceiptLedger<'a> {
    journal: &'a ProposalJournal,
}

impl ReceiptLedger for DurableReceiptLedger<'_> {
    fn is_consumed(&self, receipt_id: &ReceiptId) -> Result<bool, ApprovalError> {
        Ok(self.journal.consumed_receipts.contains(receipt_id))
    }

    fn is_rejected(&self, proposal_digest: &ProposalDigest) -> Result<bool, ApprovalError> {
        Ok(self.journal.rejected_proposals.contains(proposal_digest))
    }
}

// ---------------------------------------------------------------------------
// Sealing
// ---------------------------------------------------------------------------

/// The on-disk envelope for the sealed journal.
#[derive(Serialize, Deserialize)]
struct JournalEnvelope {
    domain: String,
    format_version: u32,
    payload: ProposalJournal,
    authentication_tag: String,
}

/// The exact byte string the journal's authentication tag is computed over.
///
/// Domain and version are absorbed first, then the canonical JSON of the
/// payload as a single length-prefixed field. The payload contains only
/// strings, integers, booleans, unit enums, sequences, and `BTreeMap`s with
/// string keys, so `serde_json` encodes it deterministically for a given build
/// — the same property [`crate::approval::ProposalDigest::of_bound_proposal`]
/// relies on. Cross-version reinterpretation is guarded by the version field.
fn journal_message(payload_json: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    absorb_str(&mut out, JOURNAL_DOMAIN);
    absorb_u64(&mut out, u64::from(JOURNAL_FORMAT_VERSION));
    absorb_field(&mut out, payload_json);
    out
}

fn seal_journal(
    payload: &ProposalJournal,
    key: &ApprovalAuditKey,
) -> Result<Vec<u8>, JournalError> {
    let payload_json = serde_json::to_vec(payload)
        .map_err(|e| JournalError::new(JournalErrorCode::Encode, e.to_string()))?;
    let tag = key.sign(&journal_message(&payload_json));
    let envelope = JournalEnvelope {
        domain: JOURNAL_DOMAIN.to_owned(),
        format_version: JOURNAL_FORMAT_VERSION,
        payload: payload.clone(),
        authentication_tag: tag.to_hex(),
    };
    let mut bytes = serde_json::to_vec_pretty(&envelope)
        .map_err(|e| JournalError::new(JournalErrorCode::Encode, e.to_string()))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn open_journal(bytes: &[u8], key: &ApprovalAuditKey) -> Result<ProposalJournal, JournalError> {
    let envelope: JournalEnvelope = serde_json::from_slice(bytes)
        .map_err(|e| JournalError::new(JournalErrorCode::Store, format!("journal parse: {e}")))?;
    if envelope.domain != JOURNAL_DOMAIN {
        return Err(JournalError::new(
            JournalErrorCode::Store,
            format!("expected domain {JOURNAL_DOMAIN}"),
        ));
    }
    if envelope.format_version != JOURNAL_FORMAT_VERSION {
        return Err(JournalError::new(
            JournalErrorCode::Store,
            format!(
                "unsupported journal format version {}",
                envelope.format_version
            ),
        ));
    }
    let mut tag_bytes = [0u8; 32];
    hex::decode_to_slice(&envelope.authentication_tag, &mut tag_bytes)
        .map_err(|e| JournalError::new(JournalErrorCode::Store, format!("journal tag: {e}")))?;
    let payload_json = serde_json::to_vec(&envelope.payload)
        .map_err(|e| JournalError::new(JournalErrorCode::Encode, e.to_string()))?;
    if key.verify(&journal_message(&payload_json), &Tag::from_bytes(tag_bytes)) {
        Ok(envelope.payload)
    } else {
        Err(JournalError::new(
            JournalErrorCode::Store,
            "journal authentication tag did not verify",
        ))
    }
}

// ---------------------------------------------------------------------------
// Hex serialization for fixed-size byte arrays
// ---------------------------------------------------------------------------

mod hex_array {
    use serde::{Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(bytes))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let raw = String::deserialize(d)?;
        let mut out = [0u8; 32];
        hex::decode_to_slice(&raw, &mut out).map_err(serde::de::Error::custom)?;
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inventory::{MemoryChoice, RiskChoice, RuntimeChoice};
    use crate::proposal::{AgentProposal, PersonalityFileProposal};
    use crate::test_support::{genesis_instance, isolated_requester, key_for};

    const NOW: u64 = 1_700_000_000;

    fn sample_proposal(alias: &str) -> AgentProposal {
        AgentProposal {
            agent_alias: alias.to_owned(),
            risk: RiskChoice::LockedDown,
            runtime: RuntimeChoice::Tight,
            memory: MemoryChoice::Markdown,
            personality_files: vec![PersonalityFileProposal {
                filename: "SOUL.md".to_owned(),
                content: "# Soul".to_owned(),
            }],
        }
    }

    /// Build a journal entry directly, without a live service, so the durable
    /// mechanics can be tested in isolation from the config CAS.
    fn sample_entry(operation_id: &OperationId, state: JournalState) -> JournalEntry {
        let requester = isolated_requester("reg-sample");
        let proposal = sample_proposal("writer");
        JournalEntry {
            operation_id: operation_id.clone(),
            operation: ControlOperation::ProposeAgentProfile,
            proposal_digest: ProposalDigest::from_bytes([0x11; 32]),
            agent_proposal: proposal.clone(),
            selected_provider_ref: "custom.fixture".to_owned(),
            target_instance: InstanceId::new("inst-sample").expect("id"),
            source_revision: SourceRevisionDigest::of("schema_version = 3\n"),
            instance_fingerprint: InstanceFingerprint::from_bytes([0x22; 32]),
            requester_class: requester.class(),
            requester_subject: requester.subject().as_str().to_owned(),
            requester_fingerprint: requester.fingerprint(),
            owner_token: "reg-owner".to_owned(),
            client_session: "sess-1".to_owned(),
            resume_secret_verifier: ResumeSecret::generate().expect("secret").verifier(),
            effects: declared_effects(&proposal),
            verification_plan: VerificationPlan {
                expected_agent_alias: "writer".to_owned(),
            },
            created_at_unix_secs: NOW,
            expires_at_unix_secs: NOW + 900,
            state,
            recorded_receipt: None,
            consumed_receipt_id: None,
            apply_order: Vec::new(),
            disposition: None,
        }
    }

    #[test]
    fn the_transition_table_admits_only_the_designed_moves() {
        use JournalState::{
            Applied, Applying, Approved, AwaitingApproval, Expired, Failed, Prepared,
            RecoveryRequired, Rejected, Verified,
        };
        // A representative set of every legal edge in the design diagram.
        for (from, to) in [
            (Prepared, AwaitingApproval),
            (AwaitingApproval, Approved),
            (AwaitingApproval, Rejected),
            (AwaitingApproval, Expired),
            (Approved, Applying),
            (Approved, Expired),
            (Applying, Applied),
            (Applying, Failed),
            (Applying, RecoveryRequired),
            (Applied, Verified),
            (Applied, RecoveryRequired),
        ] {
            assert!(
                from.may_transition_to(to),
                "{} -> {} must be legal",
                from.wire(),
                to.wire()
            );
        }
        // Moves the machine must refuse: no skipping approval, no reviving a
        // terminal state, no un-applying.
        for (from, to) in [
            (AwaitingApproval, Applying),
            (Prepared, Approved),
            (Prepared, Applying),
            (Approved, Applied),
            (Applying, Verified),
            (Verified, Applying),
            (Rejected, Approved),
            (Expired, Approved),
            (RecoveryRequired, Applying),
            (Failed, Applying),
            (Applied, Applying),
        ] {
            assert!(
                !from.may_transition_to(to),
                "{} -> {} must be refused",
                from.wire(),
                to.wire()
            );
        }
    }

    #[test]
    fn recovery_required_is_terminal_and_has_no_exit() {
        for to in [
            JournalState::Prepared,
            JournalState::AwaitingApproval,
            JournalState::Approved,
            JournalState::Applying,
            JournalState::Applied,
            JournalState::Verified,
            JournalState::Failed,
            JournalState::Expired,
            JournalState::Rejected,
            JournalState::RecoveryRequired,
        ] {
            assert!(
                !JournalState::RecoveryRequired.may_transition_to(to),
                "recovery_required must not exit to {}",
                to.wire()
            );
        }
        assert!(JournalState::RecoveryRequired.is_terminal());
    }

    #[test]
    fn a_sealed_journal_round_trips_and_rejects_tampering() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (_root, paths, record) = genesis_instance(&tmp);
        let key = key_for(&paths, &record);

        let mut journal = ProposalJournal::default();
        let op = OperationId::generate().expect("op id");
        journal.entries.insert(
            op.clone(),
            sample_entry(&op, JournalState::AwaitingApproval),
        );
        journal.high_water_unix_secs = NOW;
        journal.persist(&paths, &key).expect("persist");

        let reloaded = ProposalJournal::load(&paths, &key).expect("reload");
        assert_eq!(reloaded.entries.get(&op), journal.entries.get(&op));
        assert_eq!(reloaded.high_water_unix_secs, NOW);

        // Tamper with the sealed payload: a flipped byte in a durable field must
        // fail authentication rather than load.
        let path = paths.control_dir().join(JOURNAL_FILE);
        let bytes = std::fs::read_to_string(&path).expect("read journal");
        let tampered = bytes.replace("inst-sample", "inst-EVILXX");
        assert_ne!(tampered, bytes, "the tamper must change the file");
        std::fs::write(&path, tampered).expect("write tampered");
        let err = ProposalJournal::load(&paths, &key).expect_err("tampered journal must not load");
        assert_eq!(err.code, JournalErrorCode::Store);
    }

    #[test]
    fn the_durable_consumed_set_survives_a_reload() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (_root, paths, record) = genesis_instance(&tmp);
        let key = key_for(&paths, &record);

        let receipt_id = ReceiptId::generate().expect("receipt id");
        let mut journal = ProposalJournal::default();
        // The consumed set is what enforces single use; here it is populated
        // directly and its durability across a restart is what is under test.
        // The atomic-claim path that populates it through a verified marker is
        // exercised end to end in the apply-worker tests.
        journal.consumed_receipts.insert(receipt_id.clone());
        journal.persist(&paths, &key).expect("persist");

        let reloaded = ProposalJournal::load(&paths, &key).expect("reload");
        assert!(reloaded.is_receipt_consumed(&receipt_id));
        assert!(
            reloaded.ledger().is_consumed(&receipt_id).expect("ledger"),
            "the durable ledger reports the receipt consumed after a reload"
        );
        // A rejected digest is likewise durable and answered by the ledger.
        assert!(
            !reloaded
                .ledger()
                .is_rejected(&ProposalDigest::from_bytes([0x99; 32]))
                .expect("ledger")
        );
    }

    #[test]
    fn status_reports_each_non_generic_state_by_name() {
        let requester = isolated_requester("reg-sample");
        let mut journal = ProposalJournal::default();
        for (label, state) in [
            ("approved", JournalState::Approved),
            ("applying", JournalState::Applying),
            ("recovery_required", JournalState::RecoveryRequired),
        ] {
            let op = OperationId::generate().expect("op id");
            journal.entries.insert(op.clone(), sample_entry(&op, state));
            let status = journal.status(&op, &requester).expect("status");
            assert_eq!(status.state, state);
            assert_eq!(
                status.state.wire(),
                label,
                "status must not collapse the state name"
            );
        }
        // The three are distinct names, never one generic "pending".
        assert_ne!(JournalState::Approved.wire(), JournalState::Applying.wire());
        assert_ne!(
            JournalState::Applying.wire(),
            JournalState::RecoveryRequired.wire()
        );
    }

    #[test]
    fn status_refuses_another_requesters_proposal_as_unknown() {
        let owner = isolated_requester("reg-sample");
        let stranger = isolated_requester("reg-stranger");
        let mut journal = ProposalJournal::default();
        let op = OperationId::generate().expect("op id");
        journal.entries.insert(
            op.clone(),
            sample_entry(&op, JournalState::AwaitingApproval),
        );
        assert!(journal.status(&op, &owner).is_ok());
        let err = journal
            .status(&op, &stranger)
            .expect_err("a stranger must not read another requester's proposal");
        assert_eq!(err.code, JournalErrorCode::UnknownOperation);
    }
}
