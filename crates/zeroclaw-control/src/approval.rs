//! Signed, single-use approval receipts and the broker that issues them.
//!
//! # The one property this module exists to guarantee
//!
//! **A requester cannot obtain a receipt.** Not by asking twice, not by passing
//! `approved: true`, not by replaying a nonce, not by calling a second tool,
//! and not by switching transport. The guarantee rests on three facts that hold
//! together, each checkable by reading the types:
//!
//! 1. [`ApprovalBroker::request_approval`] takes an
//!    [`OperatorAuthentication`] by reference, and that type has no public
//!    constructor. The only thing that produces one is
//!    [`crate::operator::authenticate_operator`], which requires a
//!    [`crate::ceremony::UserPresence`] attestation from a controlling
//!    terminal. There is no `Default`, no `Deserialize`, no builder, and no
//!    field a caller can set.
//! 2. The receipt is authenticated with the ADR-015 approval and audit key,
//!    which is derived inside the `KeySource` boundary and exposed only through
//!    sign and verify. **The real boundary is key-source confidentiality**: the
//!    key is an HKDF subkey of the single ADR-013 authority, whose backend is a
//!    0600 host secret no requester-facing tool, adapter, plugin, or agent can
//!    resolve, read, or proxy. A party that *did* hold the derived key could
//!    authenticate the exact wire bytes of any receipt regardless of any Rust
//!    visibility modifier — [`AuthenticatedReceipt::seal_new`] and
//!    [`crate::keys::ApprovalAuditKey::sign`] being `pub(crate)` gates the
//!    minting *type* against an in-crate mistake and stops another crate reaching
//!    the signer, but it is defense-in-depth layered on the key-source secret,
//!    not the guarantee itself. Because the threat model excludes a process that
//!    can read that host key, a requester cannot mint a tag even though it can
//!    construct the plain [`ApprovalReceipt`] struct.
//! 3. **No tool accepts a receipt, because no tool exists that consumes one.**
//!    Phase 4 adds no mutating tool and no apply path. A receipt in this phase
//!    authorizes nothing yet; it is a verifiable fact awaiting the phase-5
//!    journal. Possession therefore grants a requester nothing even in the
//!    hypothetical where it obtained one.
//!
//! The requester never supplies a decision field of any kind. There is no
//! `approved` parameter on any function here, and [`Decision`] appears in the
//! receipt only where the broker put it after an operator authenticated.
//!
//! # What this phase deliberately does not build
//!
//! - **No apply path.** Nothing here writes `config.toml`, a personality file,
//!   a credential, or any host state. [`ConsumptionMarker`] and
//!   [`ReceiptLedger`] define the *interface* the phase-5 durable journal will
//!   implement, and [`InMemoryReceiptLedger`] is a non-durable stand-in for
//!   tests. Verifying a receipt does not consume it: consumption must be atomic
//!   with the state transition it authorizes, inside one journal transaction,
//!   and that transaction does not exist yet.
//! - **No quorum enforcement beyond one.** [`required_quorum`] already returns
//!   2 for a meta-authority operation on a two-operator installation, and the
//!   verifier already refuses a receipt whose decisions do not meet its stated
//!   quorum. The broker collects exactly one authentication, so it *refuses* a
//!   request whose quorum exceeds one rather than approving it with a single
//!   decision. Fail-closed, and 2-of-N turns on without changing the receipt.
//! - **No second backchannel.** Terminal user presence is the only one.
//!
//! # Why the receipt binds what it binds
//!
//! The parent document fixes the binding set — proposal digest, target
//! instance, source revision, operator principal, decision, expiration — and
//! this implementation adds the receipt id, trust epoch, instance fingerprint,
//! operation, and quorum fields without weakening any of them. Each binding
//! answers a specific substitution attack: a receipt for one proposal cannot
//! authorize another, a receipt cannot follow a target root that moved, a stale
//! receipt cannot apply to a config that changed underneath it, and a receipt
//! cannot survive an epoch transition.
//!
//! The source revision is stored as a **digest**, never as the revision text.
//! The text is the whole configuration source and may contain secret values; a
//! receipt is an audit artefact that outlives the decision, so it must not
//! carry one.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::genesis::{InstanceTrustState, PresenceClass};
use crate::keys::ApprovalAuditKey;
use crate::meta_authority::{AuthorityTier, ControlOperation, RequiredQuorum, required_quorum};
use crate::operator::{
    OperatorAuthentication, OperatorIdentity, OperatorRegistry, RequesterContext,
};
use crate::registry::{InstanceFingerprint, InstanceId, TrustEpoch};
use crate::service::BoundProposal;
use crate::store::{
    CanonicalBytes, StoreErrorCode, absorb_field, absorb_str, absorb_u64, open_sealed,
    os_random_32, seal,
};

/// Domain-separation label for a sealed approval receipt.
pub const APPROVAL_RECEIPT_DOMAIN: &str = "zeroclaw/control-plane/approval-receipt/v1";

/// On-disk and on-wire format version of a sealed approval receipt.
pub const APPROVAL_RECEIPT_FORMAT_VERSION: u32 = 1;

/// Label bound into a proposal digest.
pub const PROPOSAL_DIGEST_LABEL: &str = "zeroclaw/control-plane/proposal-digest/v1";

/// Label bound into a source-revision digest.
pub const SOURCE_REVISION_DIGEST_LABEL: &str = "zeroclaw/control-plane/source-revision/v1";

/// How long an issued receipt stays valid, in seconds, by default.
///
/// Short on purpose. A receipt is consumed by the transaction worker moments
/// after it is issued; a long window only widens the replay surface a crash or
/// a stolen journal would expose.
pub const DEFAULT_RECEIPT_TTL_SECS: u64 = 300;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Why an approval request or a receipt verification refused.
///
/// Every variant is a refusal. None of them downgrades, retries at a weaker
/// tier, or falls back to a different backchannel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalErrorCode {
    /// A requester principal claimed approval authority.
    RequesterCannotApprove,
    /// The instance has no verified trust root.
    InstanceNotManaged,
    /// The trust epoch of the request, key, record, or authentication disagree.
    TrustEpochMismatch,
    /// The request names an instance this host does not manage.
    TargetMismatch,
    /// No requester grant can reach a meta-authority operation.
    MetaAuthorityNotProposable,
    /// The requester's grant does not cover the operation's proposal domain.
    GrantRequired,
    /// The operator authentication was produced for a different requester.
    AuthenticationNotForThisRequester,
    /// The authenticated party is not an operator.
    NotAnOperator,
    /// The operator is not registered and active in the trust root.
    OperatorNotRegistered,
    /// The operator identity is the requester's own subject.
    OperatorIsTheRequester,
    /// The requester can reach or impersonate this operator identity.
    OperatorIneligible,
    /// A rejection is terminal for this proposal digest.
    ProposalRejected,
    /// The receipt could not be encoded.
    NotIssued,
    /// The receipt could not be parsed.
    Unparseable,
    /// The receipt's authentication tag did not verify.
    AuthenticationFailed,
    /// The receipt does not carry an approval decision.
    NotAnApproval,
    /// The receipt is bound to a different proposal.
    ProposalDigestMismatch,
    /// The receipt is bound to a different target instance.
    TargetInstanceMismatch,
    /// The registered root moved or changed identity under the receipt.
    InstanceFingerprintMismatch,
    /// The configuration changed under the receipt.
    SourceRevisionMismatch,
    /// The receipt has expired.
    Expired,
    /// The host clock moved backwards past the receipt's issue time.
    ClockRollback,
    /// The recorded decisions do not meet the receipt's stated quorum.
    QuorumNotSatisfied,
    /// The receipt has already been consumed.
    AlreadyConsumed,
    /// The consumption ledger could not answer.
    LedgerUnavailable,
}

impl ApprovalErrorCode {
    /// A stable, non-secret wire spelling.
    #[must_use]
    pub const fn wire(self) -> &'static str {
        match self {
            Self::RequesterCannotApprove => "requester_cannot_approve",
            Self::InstanceNotManaged => "instance_not_managed",
            Self::TrustEpochMismatch => "trust_epoch_mismatch",
            Self::TargetMismatch => "target_mismatch",
            Self::MetaAuthorityNotProposable => "meta_authority_not_proposable",
            Self::GrantRequired => "grant_required",
            Self::AuthenticationNotForThisRequester => "authentication_not_for_this_requester",
            Self::NotAnOperator => "not_an_operator",
            Self::OperatorNotRegistered => "operator_not_registered",
            Self::OperatorIsTheRequester => "operator_is_the_requester",
            Self::OperatorIneligible => "operator_ineligible",
            Self::ProposalRejected => "proposal_rejected",
            Self::NotIssued => "not_issued",
            Self::Unparseable => "unparseable",
            Self::AuthenticationFailed => "authentication_failed",
            Self::NotAnApproval => "not_an_approval",
            Self::ProposalDigestMismatch => "proposal_digest_mismatch",
            Self::TargetInstanceMismatch => "target_instance_mismatch",
            Self::InstanceFingerprintMismatch => "instance_fingerprint_mismatch",
            Self::SourceRevisionMismatch => "source_revision_mismatch",
            Self::Expired => "expired",
            Self::ClockRollback => "clock_rollback",
            Self::QuorumNotSatisfied => "quorum_not_satisfied",
            Self::AlreadyConsumed => "already_consumed",
            Self::LedgerUnavailable => "ledger_unavailable",
        }
    }
}

/// An approval-path refusal. `detail` never carries key material, a credential,
/// or configuration source text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalError {
    pub code: ApprovalErrorCode,
    pub detail: String,
}

impl ApprovalError {
    #[must_use]
    pub fn new(code: ApprovalErrorCode, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }
}

impl std::fmt::Display for ApprovalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code.wire(), self.detail)
    }
}

impl std::error::Error for ApprovalError {}

// ---------------------------------------------------------------------------
// Identifiers and digests
// ---------------------------------------------------------------------------

/// A receipt's unique identifier, used for consumption bookkeeping.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ReceiptId(String);

impl ReceiptId {
    /// Mint a fresh identifier from the operating system random source.
    ///
    /// # Errors
    ///
    /// Propagates a random-source failure rather than falling back to a weaker
    /// generator: a predictable receipt id would let an attacker pre-compute
    /// consumption bookkeeping.
    pub fn generate() -> Result<Self, ApprovalError> {
        let bytes = os_random_32()
            .map_err(|e| ApprovalError::new(ApprovalErrorCode::NotIssued, e.detail))?;
        Ok(Self(format!("rcpt-{}", hex::encode(&bytes[..16]))))
    }

    /// Validate and wrap an identifier.
    ///
    /// # Errors
    ///
    /// Returns [`ApprovalErrorCode::Unparseable`] for anything outside
    /// `[A-Za-z0-9._-]` or longer than 128 bytes. The charset excludes path
    /// separators, so an identifier can never be spliced into a path.
    pub fn new(value: impl Into<String>) -> Result<Self, ApprovalError> {
        let value = value.into();
        if value.is_empty() || value.len() > 128 {
            return Err(ApprovalError::new(
                ApprovalErrorCode::Unparseable,
                "receipt id length is out of range",
            ));
        }
        if !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-')
        {
            return Err(ApprovalError::new(
                ApprovalErrorCode::Unparseable,
                "receipt id contains an unacceptable character",
            ));
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ReceiptId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for ReceiptId {
    type Error = ApprovalError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<ReceiptId> for String {
    fn from(value: ReceiptId) -> Self {
        value.0
    }
}

macro_rules! approval_digest_newtype {
    ($name:ident, $what:literal) => {
        impl $name {
            #[must_use]
            pub const fn from_bytes(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }

            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }

            #[must_use]
            pub fn to_hex(&self) -> String {
                hex::encode(self.0)
            }

            /// Parse a 64-character hex digest.
            ///
            /// # Errors
            ///
            /// Returns [`ApprovalErrorCode::Unparseable`] when the input is not
            /// exactly 32 hex-encoded bytes.
            pub fn from_hex(value: &str) -> Result<Self, ApprovalError> {
                let mut bytes = [0u8; 32];
                hex::decode_to_slice(value, &mut bytes).map_err(|e| {
                    ApprovalError::new(
                        ApprovalErrorCode::Unparseable,
                        format!(concat!($what, ": {}"), e),
                    )
                })?;
                Ok(Self(bytes))
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(&self.to_hex())
            }
        }

        impl Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.serialize_str(&self.to_hex())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let raw = String::deserialize(d)?;
                Self::from_hex(&raw).map_err(serde::de::Error::custom)
            }
        }
    };
}

/// Canonical digest of the immutable proposal an operator approved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProposalDigest([u8; 32]);

approval_digest_newtype!(ProposalDigest, "proposal digest");

/// Digest of the exact configuration source revision a preview was computed
/// against.
///
/// A digest rather than the revision, because the revision is the whole
/// configuration source and may contain secret values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SourceRevisionDigest([u8; 32]);

approval_digest_newtype!(SourceRevisionDigest, "source revision digest");

impl SourceRevisionDigest {
    /// Digest a configuration source revision.
    #[must_use]
    pub fn of(source_revision: &str) -> Self {
        let mut message = Vec::new();
        absorb_str(&mut message, SOURCE_REVISION_DIGEST_LABEL);
        absorb_str(&mut message, source_revision);
        let mut hasher = Sha256::new();
        hasher.update(&message);
        Self(hasher.finalize().into())
    }
}

impl ProposalDigest {
    /// The canonical digest of a preview-bound proposal.
    ///
    /// Computed over the agent alias, the redacted preview an operator would
    /// actually see, and the digest of the source revision the preview was
    /// built against. Two proposals that would produce different previews, or
    /// the same preview against a different revision, therefore have different
    /// digests — which is what makes "a receipt for one proposal cannot
    /// authorize a different one" true rather than hoped for.
    ///
    /// The preview is canonicalized through `serde_json`. Every type it
    /// contains is a struct, `Vec`, `String`, `PathBuf`, `bool`, or a unit
    /// enum — there is no map whose iteration order could vary — so the
    /// encoding is deterministic for a given build.
    ///
    /// # Errors
    ///
    /// Returns [`ApprovalErrorCode::NotIssued`] when the preview cannot be
    /// encoded.
    pub fn of_bound_proposal(bound: &BoundProposal) -> Result<Self, ApprovalError> {
        let preview = serde_json::to_vec(bound.preview()).map_err(|e| {
            ApprovalError::new(
                ApprovalErrorCode::NotIssued,
                format!("proposal preview could not be canonicalized: {e}"),
            )
        })?;
        let mut message = Vec::new();
        absorb_str(&mut message, PROPOSAL_DIGEST_LABEL);
        absorb_str(&mut message, bound.agent_alias());
        absorb_field(&mut message, &preview);
        absorb_field(
            &mut message,
            SourceRevisionDigest::of(bound.source_revision()).as_bytes(),
        );
        let mut hasher = Sha256::new();
        hasher.update(&message);
        Ok(Self(hasher.finalize().into()))
    }
}

// ---------------------------------------------------------------------------
// Decisions
// ---------------------------------------------------------------------------

/// An operator's decision on a proposal.
///
/// Both variants produce a signed receipt. A rejection is a durable fact, not
/// an absence — which is what lets it be terminal for the proposal digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    /// The operation may proceed.
    Approve,
    /// The operation must not proceed, now or later, for this digest.
    Reject,
}

impl Decision {
    /// Every decision.
    pub const ALL: &'static [Self] = &[Self::Approve, Self::Reject];

    /// The authenticated spelling.
    #[must_use]
    pub const fn wire(self) -> &'static str {
        match self {
            Self::Approve => "approve",
            Self::Reject => "reject",
        }
    }

    /// Whether this decision authorizes the operation.
    #[must_use]
    pub const fn authorizes(self) -> bool {
        match self {
            Self::Approve => true,
            Self::Reject => false,
        }
    }
}

impl std::fmt::Display for Decision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.wire())
    }
}

/// One operator's recorded decision.
///
/// The receipt carries a list of these so a 2-of-N quorum is expressible in the
/// existing format. This phase records exactly one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorDecision {
    /// The authenticated operator who decided.
    pub operator: OperatorIdentity,
    /// What they decided.
    pub decision: Decision,
    /// The assurance class of the ceremony that authenticated them.
    ///
    /// Recorded per operator rather than once per receipt, because a 2-of-N
    /// quorum may authenticate its operators through different backchannels,
    /// and a later mutation-enablement rule needs to see the weakest one.
    pub presence_class: PresenceClass,
    /// When they decided, seconds since the Unix epoch.
    pub decided_at_unix_secs: u64,
}

// ---------------------------------------------------------------------------
// The receipt
// ---------------------------------------------------------------------------

/// A single-use, authenticated approval or rejection receipt.
///
/// The fields are public so a host can inspect and audit one, and so tests can
/// construct adversarial shapes. That is safe precisely because the struct is
/// not the authority: [`AuthenticatedReceipt`] is, and reaching one requires
/// the ADR-015 key. A hand-built `ApprovalReceipt` is inert.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalReceipt {
    /// Unique identifier, used for consumption bookkeeping.
    pub receipt_id: ReceiptId,
    /// Canonical digest of the immutable proposal.
    pub proposal_digest: ProposalDigest,
    /// The registered instance this decision is for.
    pub target_instance: InstanceId,
    /// The instance fingerprint recomputed under lock at decision time.
    pub instance_fingerprint: InstanceFingerprint,
    /// Digest of the source revision the preview was computed against.
    pub source_revision: SourceRevisionDigest,
    /// The operation being decided.
    pub operation: ControlOperation,
    /// The operation's authority tier at decision time.
    pub authority_tier: AuthorityTier,
    /// The aggregate decision.
    pub decision: Decision,
    /// How many distinct operator decisions this receipt requires.
    pub required_quorum: RequiredQuorum,
    /// The recorded per-operator decisions.
    pub operator_decisions: Vec<OperatorDecision>,
    /// The epoch this receipt was issued under.
    pub trust_epoch: TrustEpoch,
    /// Issue time, seconds since the Unix epoch.
    pub issued_at_unix_secs: u64,
    /// Expiry, seconds since the Unix epoch. Exclusive: a receipt is invalid
    /// at its expiry instant, not after it.
    pub expires_at_unix_secs: u64,
}

impl CanonicalBytes for ApprovalReceipt {
    const DOMAIN: &'static str = APPROVAL_RECEIPT_DOMAIN;
    const FORMAT_VERSION: u32 = APPROVAL_RECEIPT_FORMAT_VERSION;

    fn absorb_canonical(&self, out: &mut Vec<u8>) {
        // Exhaustive destructure, no `..`: a field this does not absorb is a
        // field the tag does not cover, and an attacker who can write the
        // receipt could then change it freely.
        let Self {
            receipt_id,
            proposal_digest,
            target_instance,
            instance_fingerprint,
            source_revision,
            operation,
            authority_tier,
            decision,
            required_quorum,
            operator_decisions,
            trust_epoch,
            issued_at_unix_secs,
            expires_at_unix_secs,
        } = self;
        absorb_str(out, receipt_id.as_str());
        absorb_field(out, proposal_digest.as_bytes());
        absorb_str(out, target_instance.as_str());
        absorb_field(out, instance_fingerprint.as_bytes());
        absorb_field(out, source_revision.as_bytes());
        absorb_str(out, operation.wire());
        absorb_str(out, authority_tier.wire());
        absorb_str(out, decision.wire());
        absorb_u64(out, u64::from(required_quorum.get()));
        absorb_u64(out, operator_decisions.len() as u64);
        for entry in operator_decisions {
            let OperatorDecision {
                operator,
                decision,
                presence_class,
                decided_at_unix_secs,
            } = entry;
            absorb_str(out, operator.as_str());
            absorb_str(out, decision.wire());
            absorb_str(out, presence_class.wire());
            absorb_u64(out, *decided_at_unix_secs);
        }
        absorb_u64(out, trust_epoch.get());
        absorb_u64(out, *issued_at_unix_secs);
        absorb_u64(out, *expires_at_unix_secs);
    }
}

impl ApprovalReceipt {
    /// The distinct operators who recorded an approval.
    ///
    /// Distinct, because counting a repeated operator twice would let one
    /// operator satisfy a 2-of-N quorum alone.
    #[must_use]
    pub fn distinct_approving_operators(&self) -> BTreeSet<&OperatorIdentity> {
        self.operator_decisions
            .iter()
            .filter(|d| d.decision.authorizes())
            .map(|d| &d.operator)
            .collect()
    }

    /// Whether the recorded decisions meet the stated quorum.
    #[must_use]
    pub fn quorum_is_satisfied(&self) -> bool {
        let approvals =
            u32::try_from(self.distinct_approving_operators().len()).unwrap_or(u32::MAX);
        self.required_quorum.is_satisfied_by(approvals)
    }
}

/// A receipt together with proof that a holder of the ADR-015 key produced it.
///
/// The only way to build one is [`Self::seal_new`], which is `pub(crate)` and
/// reached only through [`ApprovalBroker`], or [`Self::open`], which verifies a
/// tag. Neither is reachable from a requester surface.
#[derive(Debug, Clone)]
pub struct AuthenticatedReceipt {
    receipt: ApprovalReceipt,
    sealed: Vec<u8>,
}

impl AuthenticatedReceipt {
    /// Authenticate `receipt` under `key`.
    ///
    /// `pub(crate)` deliberately: minting is the broker's job, and no other
    /// crate — not the binary, not the MCP transport — may reach it.
    pub(crate) fn seal_new(
        receipt: ApprovalReceipt,
        key: &ApprovalAuditKey,
    ) -> Result<Self, ApprovalError> {
        let sealed = seal(&receipt, key)
            .map_err(|e| ApprovalError::new(ApprovalErrorCode::NotIssued, e.detail))?;
        Ok(Self { receipt, sealed })
    }

    /// Parse and authenticate a sealed receipt.
    ///
    /// # Errors
    ///
    /// Returns [`ApprovalErrorCode::AuthenticationFailed`] when the tag does not
    /// verify under `key`, and [`ApprovalErrorCode::Unparseable`] for a
    /// malformed envelope, an unknown domain, or an unsupported version.
    pub fn open(bytes: &[u8], key: &ApprovalAuditKey) -> Result<Self, ApprovalError> {
        let receipt: ApprovalReceipt = open_sealed(bytes, key).map_err(|e| {
            let code = match e.code {
                StoreErrorCode::AuthenticationFailed => ApprovalErrorCode::AuthenticationFailed,
                _ => ApprovalErrorCode::Unparseable,
            };
            ApprovalError::new(code, e.detail)
        })?;
        Ok(Self {
            receipt,
            sealed: bytes.to_vec(),
        })
    }

    /// The authenticated receipt.
    #[must_use]
    pub const fn receipt(&self) -> &ApprovalReceipt {
        &self.receipt
    }

    /// The sealed bytes, as they would be journalled.
    #[must_use]
    pub fn as_sealed_bytes(&self) -> &[u8] {
        &self.sealed
    }
}

// ---------------------------------------------------------------------------
// Consumption bookkeeping
// ---------------------------------------------------------------------------

/// Permission to consume one receipt exactly once.
///
/// Produced only by a successful [`verify_for_consumption`], so a caller cannot
/// mark a receipt consumed without having verified it first. Phase 5 records
/// this inside the same journal transaction as the `approved` to `applying`
/// transition; **this phase records it nowhere durable, because there is no
/// apply.**
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsumptionMarker {
    receipt_id: ReceiptId,
    proposal_digest: ProposalDigest,
}

impl ConsumptionMarker {
    /// The receipt this marker consumes.
    #[must_use]
    pub const fn receipt_id(&self) -> &ReceiptId {
        &self.receipt_id
    }

    /// The proposal the consumed receipt authorized.
    #[must_use]
    pub const fn proposal_digest(&self) -> &ProposalDigest {
        &self.proposal_digest
    }
}

/// What the host already knows about consumed receipts and rejected proposals.
///
/// The interface the phase-5 durable journal will implement. Both questions
/// return `Result` because a durable implementation can fail to answer, and an
/// unanswerable question must fail closed rather than default to "no".
pub trait ReceiptLedger {
    /// Whether this receipt has already been consumed.
    ///
    /// # Errors
    ///
    /// Returns [`ApprovalErrorCode::LedgerUnavailable`] when the ledger cannot
    /// answer.
    fn is_consumed(&self, receipt_id: &ReceiptId) -> Result<bool, ApprovalError>;

    /// Whether a rejection is already terminal for this proposal digest.
    ///
    /// # Errors
    ///
    /// Returns [`ApprovalErrorCode::LedgerUnavailable`] when the ledger cannot
    /// answer.
    fn is_rejected(&self, proposal_digest: &ProposalDigest) -> Result<bool, ApprovalError>;
}

/// A non-durable ledger.
///
/// For tests and for the broker's own refusal checks before a journal exists.
/// It is explicitly **not** the phase-5 implementation: it forgets everything
/// on restart, which is exactly what a single-use guarantee cannot tolerate.
#[derive(Debug, Clone, Default)]
pub struct InMemoryReceiptLedger {
    consumed: BTreeMap<ReceiptId, ProposalDigest>,
    rejected: BTreeSet<ProposalDigest>,
}

impl InMemoryReceiptLedger {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a consumption.
    ///
    /// Takes a [`ConsumptionMarker`], so nothing can be marked consumed that
    /// was not verified.
    ///
    /// # Errors
    ///
    /// Returns [`ApprovalErrorCode::AlreadyConsumed`] when the receipt is
    /// already recorded. One consumption, ever.
    pub fn mark_consumed(&mut self, marker: &ConsumptionMarker) -> Result<(), ApprovalError> {
        if self.consumed.contains_key(marker.receipt_id()) {
            return Err(ApprovalError::new(
                ApprovalErrorCode::AlreadyConsumed,
                marker.receipt_id().as_str().to_owned(),
            ));
        }
        self.consumed
            .insert(marker.receipt_id().clone(), *marker.proposal_digest());
        Ok(())
    }

    /// Record a rejection as terminal for its proposal digest.
    ///
    /// Takes an [`AuthenticatedReceipt`], so a rejection can only be recorded
    /// from a receipt an operator actually signed.
    ///
    /// # Errors
    ///
    /// Returns [`ApprovalErrorCode::NotAnApproval`] when the receipt does not
    /// carry a rejection.
    pub fn record_rejection(
        &mut self,
        receipt: &AuthenticatedReceipt,
    ) -> Result<(), ApprovalError> {
        if receipt.receipt().decision != Decision::Reject {
            return Err(ApprovalError::new(
                ApprovalErrorCode::NotAnApproval,
                "only a rejection receipt records a rejection",
            ));
        }
        self.rejected.insert(receipt.receipt().proposal_digest);
        Ok(())
    }
}

impl ReceiptLedger for InMemoryReceiptLedger {
    fn is_consumed(&self, receipt_id: &ReceiptId) -> Result<bool, ApprovalError> {
        Ok(self.consumed.contains_key(receipt_id))
    }

    fn is_rejected(&self, proposal_digest: &ProposalDigest) -> Result<bool, ApprovalError> {
        Ok(self.rejected.contains(proposal_digest))
    }
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

/// What a receipt must match to authorize the operation in hand.
///
/// Every field is required. There is no "skip this check" option and no
/// `Default`, so a caller cannot verify against a partially specified
/// expectation and believe it checked more than it did.
#[derive(Debug, Clone, Copy)]
pub struct Expectations<'a> {
    /// The proposal being applied, digested.
    pub proposal_digest: &'a ProposalDigest,
    /// The instance being applied to.
    pub target_instance: &'a InstanceId,
    /// The instance fingerprint recomputed under lock, now.
    pub instance_fingerprint: &'a InstanceFingerprint,
    /// The source revision being applied against, digested, now.
    pub source_revision: &'a SourceRevisionDigest,
    /// The current trust epoch.
    pub trust_epoch: TrustEpoch,
    /// The current wall-clock time, seconds since the Unix epoch.
    pub now_unix_secs: u64,
}

/// Verify a sealed receipt against the operation in hand.
///
/// Returns a [`ConsumptionMarker`] on success. **It does not consume the
/// receipt**: consumption must be atomic with the state transition it
/// authorizes, inside the phase-5 journal transaction, and doing it here would
/// split one durable fact into two.
///
/// Every check is a refusal. In order: the tag must verify under the
/// current-epoch key; the epoch, proposal digest, target, fingerprint, and
/// source revision must all match; the decision must be an approval; the
/// proposal must not carry a terminal rejection; the receipt must be within its
/// validity window; the recorded decisions must meet the stated quorum; and the
/// receipt must not already be consumed.
///
/// # Errors
///
/// See [`ApprovalErrorCode`]. Forged, modified, expired, replayed,
/// wrong-epoch, wrong-digest, and rejection receipts all fail closed.
pub fn verify_for_consumption(
    sealed: &[u8],
    key: &ApprovalAuditKey,
    expectations: &Expectations<'_>,
    ledger: &dyn ReceiptLedger,
) -> Result<ConsumptionMarker, ApprovalError> {
    // Authenticity first. Nothing about an unauthenticated receipt's contents
    // is worth comparing, and comparing them would leak which field an attacker
    // guessed wrong.
    let authenticated = AuthenticatedReceipt::open(sealed, key)?;
    let receipt = authenticated.receipt();

    // The key is already epoch-derived, so a receipt from another epoch would
    // usually fail the tag check. This is checked anyway: the two facts have
    // different sources, and relying on the tag alone would make the binding
    // implicit.
    if receipt.trust_epoch != expectations.trust_epoch {
        return Err(ApprovalError::new(
            ApprovalErrorCode::TrustEpochMismatch,
            format!(
                "receipt epoch {}, current epoch {}",
                receipt.trust_epoch, expectations.trust_epoch
            ),
        ));
    }

    if &receipt.proposal_digest != expectations.proposal_digest {
        return Err(ApprovalError::new(
            ApprovalErrorCode::ProposalDigestMismatch,
            "the receipt authorizes a different proposal",
        ));
    }
    if &receipt.target_instance != expectations.target_instance {
        return Err(ApprovalError::new(
            ApprovalErrorCode::TargetInstanceMismatch,
            "the receipt authorizes a different instance",
        ));
    }
    if &receipt.instance_fingerprint != expectations.instance_fingerprint {
        return Err(ApprovalError::new(
            ApprovalErrorCode::InstanceFingerprintMismatch,
            "the registered root changed identity under this receipt",
        ));
    }
    if &receipt.source_revision != expectations.source_revision {
        return Err(ApprovalError::new(
            ApprovalErrorCode::SourceRevisionMismatch,
            "the configuration changed under this receipt",
        ));
    }

    if receipt.decision != Decision::Approve {
        return Err(ApprovalError::new(
            ApprovalErrorCode::NotAnApproval,
            format!("the receipt records {}", receipt.decision),
        ));
    }
    if ledger.is_rejected(&receipt.proposal_digest)? {
        return Err(ApprovalError::new(
            ApprovalErrorCode::ProposalRejected,
            "a rejection is terminal for this proposal",
        ));
    }

    // Clock rules: expiry fails closed, and a clock that moved backwards past
    // the issue time shortens validity rather than extending it.
    if expectations.now_unix_secs < receipt.issued_at_unix_secs {
        return Err(ApprovalError::new(
            ApprovalErrorCode::ClockRollback,
            "the host clock is before this receipt's issue time",
        ));
    }
    if expectations.now_unix_secs >= receipt.expires_at_unix_secs {
        return Err(ApprovalError::new(
            ApprovalErrorCode::Expired,
            "the receipt is past its expiry",
        ));
    }

    if !receipt.quorum_is_satisfied() {
        return Err(ApprovalError::new(
            ApprovalErrorCode::QuorumNotSatisfied,
            format!(
                "{} distinct approving operators, {} required",
                receipt.distinct_approving_operators().len(),
                receipt.required_quorum
            ),
        ));
    }

    if ledger.is_consumed(&receipt.receipt_id)? {
        return Err(ApprovalError::new(
            ApprovalErrorCode::AlreadyConsumed,
            "this receipt has already been consumed",
        ));
    }

    Ok(ConsumptionMarker {
        receipt_id: receipt.receipt_id.clone(),
        proposal_digest: receipt.proposal_digest,
    })
}

// ---------------------------------------------------------------------------
// The broker
// ---------------------------------------------------------------------------

/// What an approval is being requested for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalRequest {
    /// The operation being decided.
    pub operation: ControlOperation,
    /// The preview-bound proposal digest.
    pub proposal_digest: ProposalDigest,
    /// The registered instance being targeted.
    pub target_instance: InstanceId,
    /// The instance fingerprint recomputed under lock.
    pub instance_fingerprint: InstanceFingerprint,
    /// The digest of the source revision the preview was built against.
    pub source_revision: SourceRevisionDigest,
}

/// Issues approval and rejection receipts for a managed instance.
///
/// The broker holds the ADR-015 key by reference. It is constructed host-side,
/// never from a transport, and there is no accessor that hands the key out.
pub struct ApprovalBroker<'a> {
    key: &'a ApprovalAuditKey,
    trust: &'a InstanceTrustState,
    operators: &'a OperatorRegistry,
    ledger: &'a dyn ReceiptLedger,
    receipt_ttl_secs: u64,
}

/// Redacted: the broker holds a signing key, and its `Debug` must never invite
/// a caller to print it.
impl std::fmt::Debug for ApprovalBroker<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApprovalBroker")
            .field("trust_state", &self.trust.wire())
            .field("active_operators", &self.operators.active_count())
            .field("receipt_ttl_secs", &self.receipt_ttl_secs)
            .finish_non_exhaustive()
    }
}

impl<'a> ApprovalBroker<'a> {
    /// Build a broker over a managed instance's trust root.
    #[must_use]
    pub fn new(
        key: &'a ApprovalAuditKey,
        trust: &'a InstanceTrustState,
        operators: &'a OperatorRegistry,
        ledger: &'a dyn ReceiptLedger,
    ) -> Self {
        Self {
            key,
            trust,
            operators,
            ledger,
            receipt_ttl_secs: DEFAULT_RECEIPT_TTL_SECS,
        }
    }

    /// Use a non-default receipt lifetime.
    #[must_use]
    pub const fn with_receipt_ttl_secs(mut self, ttl: u64) -> Self {
        self.receipt_ttl_secs = ttl;
        self
    }

    /// Issue an approval receipt for `request`.
    ///
    /// The requester supplies no decision, no nonce, and no token. The only
    /// input that can produce a receipt is `operator_auth`, which exists only
    /// because a human answered at a controlling terminal as a registered
    /// operator distinct from, and unreachable by, this requester.
    ///
    /// # Errors
    ///
    /// See [`ApprovalErrorCode`].
    pub fn request_approval(
        &self,
        request: &ApprovalRequest,
        requester: &RequesterContext,
        operator_auth: &OperatorAuthentication,
        now_unix_secs: u64,
    ) -> Result<AuthenticatedReceipt, ApprovalError> {
        self.decide(
            request,
            requester,
            operator_auth,
            Decision::Approve,
            now_unix_secs,
        )
    }

    /// Issue a rejection receipt for `request`.
    ///
    /// A rejection is a durable fact rather than an absence, so it is signed
    /// exactly like an approval. Recording it in the ledger makes it terminal
    /// for the proposal digest.
    ///
    /// # Errors
    ///
    /// See [`ApprovalErrorCode`].
    pub fn reject(
        &self,
        request: &ApprovalRequest,
        requester: &RequesterContext,
        operator_auth: &OperatorAuthentication,
        now_unix_secs: u64,
    ) -> Result<AuthenticatedReceipt, ApprovalError> {
        self.decide(
            request,
            requester,
            operator_auth,
            Decision::Reject,
            now_unix_secs,
        )
    }

    fn decide(
        &self,
        request: &ApprovalRequest,
        requester: &RequesterContext,
        operator_auth: &OperatorAuthentication,
        decision: Decision,
        now_unix_secs: u64,
    ) -> Result<AuthenticatedReceipt, ApprovalError> {
        // 1. Non-escalation rule 5, checked before anything else. The context
        //    type already makes this unreachable; checking it means a future
        //    widening of the class rule refuses here instead of proceeding.
        if requester.can_approve() {
            return Err(ApprovalError::new(
                ApprovalErrorCode::RequesterCannotApprove,
                format!("{} claimed approval authority", requester.class()),
            ));
        }

        // 2. An instance without a verified trust root brokers nothing.
        let Some(record) = self.trust.record() else {
            return Err(ApprovalError::new(
                ApprovalErrorCode::InstanceNotManaged,
                self.trust.wire(),
            ));
        };

        // 3. One epoch, agreed by the record, the key, and the authentication.
        if record.trust_epoch != self.key.trust_epoch()
            || record.trust_epoch != operator_auth.trust_epoch()
        {
            return Err(ApprovalError::new(
                ApprovalErrorCode::TrustEpochMismatch,
                format!(
                    "record {}, key {}, authentication {}",
                    record.trust_epoch,
                    self.key.trust_epoch(),
                    operator_auth.trust_epoch()
                ),
            ));
        }

        // 4. The request must name this instance.
        if request.target_instance != record.instance_id {
            return Err(ApprovalError::new(
                ApprovalErrorCode::TargetMismatch,
                "the request names another instance",
            ));
        }

        // 5. Authorization is an intersection with the operation class. Every
        //    meta-authority operation is unproposable by any requester, so this
        //    is where rule 11 bites.
        let Some(domain) = request.operation.proposal_domain() else {
            return Err(ApprovalError::new(
                ApprovalErrorCode::MetaAuthorityNotProposable,
                format!(
                    "{} is meta-authority and no requester grant reaches it",
                    request.operation
                ),
            ));
        };
        if !requester.covers_proposal_domain(domain) {
            return Err(ApprovalError::new(
                ApprovalErrorCode::GrantRequired,
                format!("the grant does not cover {domain}"),
            ));
        }

        // 6. A rejection is terminal.
        if self.ledger.is_rejected(&request.proposal_digest)? {
            return Err(ApprovalError::new(
                ApprovalErrorCode::ProposalRejected,
                "a rejection is terminal for this proposal",
            ));
        }

        // 7. The authentication must be the one made for this requester.
        if operator_auth.issued_for() != &requester.fingerprint() {
            return Err(ApprovalError::new(
                ApprovalErrorCode::AuthenticationNotForThisRequester,
                "the operator authenticated for a different requester",
            ));
        }

        // 8. Only an operator approves.
        if !operator_auth.principal_class().can_approve() {
            return Err(ApprovalError::new(
                ApprovalErrorCode::NotAnOperator,
                operator_auth.principal_class().wire(),
            ));
        }

        // 9. Re-check the trust root, distinctness, and reachability here as
        //    well as at authentication time. The registry or the requester's
        //    evidence can change between the two, and the decision that gets
        //    signed must reflect the state at signing.
        let operator = operator_auth.identity();
        if self.operators.get_active(operator).is_none() {
            return Err(ApprovalError::new(
                ApprovalErrorCode::OperatorNotRegistered,
                operator.as_str().to_owned(),
            ));
        }
        if requester.subject().is(operator) {
            return Err(ApprovalError::new(
                ApprovalErrorCode::OperatorIsTheRequester,
                operator.as_str().to_owned(),
            ));
        }
        let analysis = requester.reachability(operator);
        if !analysis.permits_approval() {
            return Err(ApprovalError::new(
                ApprovalErrorCode::OperatorIneligible,
                match analysis.unproven() {
                    Some(question) => format!("{operator}: unproven {question}"),
                    None => operator.as_str().to_owned(),
                },
            ));
        }

        // 10. Quorum, read from the *configured* active operator count and
        //     never from an eligibility-filtered one.
        let tier = request.operation.authority_tier();
        let quorum = required_quorum(tier, self.operators.active_count());

        let expires_at_unix_secs = now_unix_secs.saturating_add(self.receipt_ttl_secs);
        let receipt = ApprovalReceipt {
            receipt_id: ReceiptId::generate()?,
            proposal_digest: request.proposal_digest,
            target_instance: request.target_instance.clone(),
            instance_fingerprint: request.instance_fingerprint,
            source_revision: request.source_revision,
            operation: request.operation,
            authority_tier: tier,
            decision,
            required_quorum: quorum,
            operator_decisions: vec![OperatorDecision {
                operator: operator.clone(),
                decision,
                presence_class: operator_auth.presence_class(),
                decided_at_unix_secs: operator_auth.authenticated_at_unix_secs(),
            }],
            trust_epoch: record.trust_epoch,
            issued_at_unix_secs: now_unix_secs,
            expires_at_unix_secs,
        };

        // 11. Do not sign an approval this broker could not itself verify.
        //
        //     This release collects exactly one operator authentication per
        //     request, so a quorum above one cannot be met and the receipt must
        //     be refused rather than signed with a claim it did not collect.
        //     Refusing is the fail-closed direction, and it is what lets 2-of-N
        //     be switched on by teaching the broker to collect a second
        //     authentication — without changing the receipt format.
        //
        //     Today every operation whose quorum can exceed one is also
        //     meta-authority, and meta-authority is already refused at step 5,
        //     so this guard always passes. It runs on every request anyway: it
        //     is the invariant that keeps a future change to `required_quorum`
        //     or to `proposal_domain` from silently minting an unverifiable
        //     receipt.
        if decision == Decision::Approve && !receipt.quorum_is_satisfied() {
            return Err(ApprovalError::new(
                ApprovalErrorCode::QuorumNotSatisfied,
                format!("{quorum} operator decisions are required and this release collects one"),
            ));
        }

        AuthenticatedReceipt::seal_new(receipt, self.key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ceremony::PresenceError;
    use crate::genesis::GenesisRecord;
    use crate::operator::{
        OperatorOrigin, OperatorRecord, OperatorStatus, RequesterSubject, authenticate_operator,
    };
    use crate::reachability::Evidence;
    use crate::store::ControlPaths;
    use crate::test_support::{
        ScriptedPresence, agent_domain, genesis_instance, isolated_requester, key_for, operator,
        unprovable_requester,
    };

    const NOW: u64 = 1_700_000_000;

    /// Everything a broker test needs, built over one throwaway instance.
    struct Fixture {
        _tmp: tempfile::TempDir,
        paths: ControlPaths,
        record: Box<GenesisRecord>,
        trust: InstanceTrustState,
        operators: OperatorRegistry,
    }

    impl Fixture {
        fn new() -> Self {
            let tmp = tempfile::tempdir().expect("tempdir");
            let (_root, paths, record) = genesis_instance(&tmp);
            let operators = OperatorRegistry::new().with_genesis_operator(&record);
            Self {
                _tmp: tmp,
                paths,
                trust: InstanceTrustState::Managed(record.clone()),
                record,
                operators,
            }
        }

        /// Add a second active operator, so the configured count is two.
        fn with_second_operator(mut self) -> Self {
            let mut registry = OperatorRegistry::new();
            registry
                .insert(OperatorRecord {
                    identity: operator("morgan"),
                    origin: OperatorOrigin::Registered,
                    trust_epoch: self.record.trust_epoch,
                    created_at_unix_secs: 1,
                    created_by_genesis_digest: self.record.digest(),
                    ceremony_presence_class: PresenceClass::Terminal,
                    status: OperatorStatus::Active,
                })
                .expect("insert");
            self.operators = registry.with_genesis_operator(&self.record);
            self
        }

        fn key(&self) -> ApprovalAuditKey {
            key_for(&self.paths, &self.record)
        }

        fn fingerprint(&self) -> InstanceFingerprint {
            let roots = self.paths.canonical_roots().expect("roots");
            let config = crate::registry::RootIdentity::probe(&roots.config_root).expect("probe");
            let data = crate::registry::RootIdentity::probe(&roots.data_root).expect("probe");
            InstanceFingerprint::compute(
                &self.record.instance_id,
                &self.record.digest(),
                self.record.trust_epoch,
                &roots,
                &config,
                &data,
            )
        }

        fn request(&self) -> ApprovalRequest {
            ApprovalRequest {
                operation: ControlOperation::ProposeAgentProfile,
                proposal_digest: ProposalDigest::from_bytes([0xA1; 32]),
                target_instance: self.record.instance_id.clone(),
                instance_fingerprint: self.fingerprint(),
                source_revision: SourceRevisionDigest::of("schema_version = 3\n"),
            }
        }

        fn expectations<'a>(&self, request: &'a ApprovalRequest, now: u64) -> Expectations<'a> {
            Expectations {
                proposal_digest: &request.proposal_digest,
                target_instance: &request.target_instance,
                instance_fingerprint: &request.instance_fingerprint,
                source_revision: &request.source_revision,
                trust_epoch: self.record.trust_epoch,
                now_unix_secs: now,
            }
        }

        /// An operator authentication for `requester`, through a real presence
        /// ceremony against the real trust root.
        fn authenticate(&self, requester: &RequesterContext) -> OperatorAuthentication {
            authenticate_operator(
                &ScriptedPresence::affirming("jordan"),
                "Approve? ".to_string(),
                "Operator identity: ".to_string(),
                &operator("jordan"),
                &self.operators,
                self.record.trust_epoch,
                requester,
            )
            .expect("the genesis operator must authenticate for an isolated requester")
        }
    }

    /// Seal a hand-built receipt under `key`. Tests only: production receipts
    /// come from the broker.
    fn seal_receipt(receipt: ApprovalReceipt, key: &ApprovalAuditKey) -> Vec<u8> {
        AuthenticatedReceipt::seal_new(receipt, key)
            .expect("seal")
            .as_sealed_bytes()
            .to_vec()
    }

    // -- the happy path -----------------------------------------------------

    #[test]
    fn a_valid_operator_authentication_yields_a_verifying_receipt() {
        let fixture = Fixture::new();
        let key = fixture.key();
        let ledger = InMemoryReceiptLedger::new();
        let broker = ApprovalBroker::new(&key, &fixture.trust, &fixture.operators, &ledger);

        let requester = isolated_requester("reg-abc123");
        let request = fixture.request();
        let auth = fixture.authenticate(&requester);

        let issued = broker
            .request_approval(&request, &requester, &auth, NOW)
            .expect("an authenticated operator must be able to approve");

        let receipt = issued.receipt();
        assert_eq!(receipt.decision, Decision::Approve);
        assert_eq!(receipt.proposal_digest, request.proposal_digest);
        assert_eq!(receipt.target_instance, request.target_instance);
        assert_eq!(receipt.source_revision, request.source_revision);
        assert_eq!(receipt.trust_epoch, fixture.record.trust_epoch);
        assert_eq!(receipt.required_quorum.get(), 1);
        assert_eq!(receipt.operator_decisions.len(), 1);
        assert_eq!(receipt.operator_decisions[0].operator, operator("jordan"));
        assert_eq!(
            receipt.operator_decisions[0].presence_class,
            PresenceClass::Terminal,
            "the receipt records the assurance class actually achieved"
        );
        assert_eq!(receipt.authority_tier, AuthorityTier::Ordinary);
        assert!(receipt.expires_at_unix_secs > receipt.issued_at_unix_secs);

        let marker = verify_for_consumption(
            issued.as_sealed_bytes(),
            &key,
            &fixture.expectations(&request, NOW),
            &ledger,
        )
        .expect("a freshly issued receipt must verify");
        assert_eq!(marker.receipt_id(), &receipt.receipt_id);
        assert_eq!(marker.proposal_digest(), &request.proposal_digest);
    }

    #[test]
    fn a_receipt_carries_no_configuration_source_text() {
        // The source revision is bound as a digest. A receipt is an audit
        // artefact that outlives the decision, and the revision is the whole
        // configuration source.
        let fixture = Fixture::new();
        let key = fixture.key();
        let ledger = InMemoryReceiptLedger::new();
        let broker = ApprovalBroker::new(&key, &fixture.trust, &fixture.operators, &ledger);
        let requester = isolated_requester("reg-abc123");
        let mut request = fixture.request();
        let secret = "api_key = \"super-secret-value\"";
        request.source_revision = SourceRevisionDigest::of(secret);
        let auth = fixture.authenticate(&requester);

        let issued = broker
            .request_approval(&request, &requester, &auth, NOW)
            .expect("approve");
        let rendered = String::from_utf8(issued.as_sealed_bytes().to_vec()).expect("utf8");
        assert!(
            !rendered.contains("super-secret-value"),
            "a receipt must not carry configuration source text"
        );
    }

    // -- a requester cannot get a receipt -----------------------------------

    #[test]
    fn a_forged_receipt_sealed_under_another_key_fails_closed() {
        // The forgery a requester could actually attempt: build the struct it
        // wants and authenticate it with any key it can reach. It cannot reach
        // the ADR-015 key, so the tag is wrong.
        //
        // Guarded by a mutation check: dropping the tag verification from
        // `AuthenticatedReceipt::open` must make this test fail.
        let fixture = Fixture::new();
        let key = fixture.key();
        let ledger = InMemoryReceiptLedger::new();
        let broker = ApprovalBroker::new(&key, &fixture.trust, &fixture.operators, &ledger);
        let requester = isolated_requester("reg-abc123");
        let request = fixture.request();
        let auth = fixture.authenticate(&requester);
        let genuine = broker
            .request_approval(&request, &requester, &auth, NOW)
            .expect("approve");

        // An attacker key: a different epoch derives a different subkey.
        let attacker = ApprovalAuditKey::derive(&fixture.paths.key_source(), TrustEpoch::new(9999))
            .expect("derive");
        let forged = seal_receipt(genuine.receipt().clone(), &attacker);

        let err =
            verify_for_consumption(&forged, &key, &fixture.expectations(&request, NOW), &ledger)
                .expect_err("a receipt this host did not authenticate must fail closed");
        assert_eq!(err.code, ApprovalErrorCode::AuthenticationFailed);

        assert!(
            AuthenticatedReceipt::open(&forged, &key).is_err(),
            "opening it must fail for the same reason"
        );
    }

    #[test]
    fn a_tampered_receipt_fails_closed() {
        let fixture = Fixture::new();
        let key = fixture.key();
        let ledger = InMemoryReceiptLedger::new();
        let broker = ApprovalBroker::new(&key, &fixture.trust, &fixture.operators, &ledger);
        let requester = isolated_requester("reg-abc123");
        let request = fixture.request();
        let auth = fixture.authenticate(&requester);
        let issued = broker
            .request_approval(&request, &requester, &auth, NOW)
            .expect("approve");

        let raw = String::from_utf8(issued.as_sealed_bytes().to_vec()).expect("utf8");
        // Flip the decision in the JSON body without being able to re-tag it.
        let tampered = raw.replace("\"approve\"", "\"reject\"");
        assert_ne!(raw, tampered, "the test must actually change something");

        let err = verify_for_consumption(
            tampered.as_bytes(),
            &key,
            &fixture.expectations(&request, NOW),
            &ledger,
        )
        .expect_err("a modified receipt must fail closed");
        assert_eq!(err.code, ApprovalErrorCode::AuthenticationFailed);
    }

    #[test]
    fn a_replayed_receipt_fails_closed() {
        // Single use, ever. Guarded by a mutation check: dropping the consumed
        // check from `verify_for_consumption` must make this test fail.
        let fixture = Fixture::new();
        let key = fixture.key();
        let mut ledger = InMemoryReceiptLedger::new();
        let requester = isolated_requester("reg-abc123");
        let request = fixture.request();

        let issued = {
            let broker = ApprovalBroker::new(&key, &fixture.trust, &fixture.operators, &ledger);
            let auth = fixture.authenticate(&requester);
            broker
                .request_approval(&request, &requester, &auth, NOW)
                .expect("approve")
        };

        let marker = verify_for_consumption(
            issued.as_sealed_bytes(),
            &key,
            &fixture.expectations(&request, NOW),
            &ledger,
        )
        .expect("the first verification succeeds");
        ledger.mark_consumed(&marker).expect("consume once");

        let err = verify_for_consumption(
            issued.as_sealed_bytes(),
            &key,
            &fixture.expectations(&request, NOW),
            &ledger,
        )
        .expect_err("a consumed receipt must never verify again");
        assert_eq!(err.code, ApprovalErrorCode::AlreadyConsumed);

        // And the ledger itself refuses a second consumption of the same id.
        assert_eq!(
            ledger.mark_consumed(&marker).expect_err("second").code,
            ApprovalErrorCode::AlreadyConsumed
        );
    }

    #[test]
    fn an_expired_receipt_fails_closed() {
        // Guarded by a mutation check: dropping the expiry check must make this
        // test fail.
        let fixture = Fixture::new();
        let key = fixture.key();
        let ledger = InMemoryReceiptLedger::new();
        let broker = ApprovalBroker::new(&key, &fixture.trust, &fixture.operators, &ledger)
            .with_receipt_ttl_secs(60);
        let requester = isolated_requester("reg-abc123");
        let request = fixture.request();
        let auth = fixture.authenticate(&requester);
        let issued = broker
            .request_approval(&request, &requester, &auth, NOW)
            .expect("approve");

        // Valid one second before expiry.
        assert!(
            verify_for_consumption(
                issued.as_sealed_bytes(),
                &key,
                &fixture.expectations(&request, NOW + 59),
                &ledger,
            )
            .is_ok()
        );
        // Invalid at the expiry instant, not merely after it.
        for now in [NOW + 60, NOW + 61, NOW + 10_000] {
            let err = verify_for_consumption(
                issued.as_sealed_bytes(),
                &key,
                &fixture.expectations(&request, now),
                &ledger,
            )
            .expect_err("an expired receipt must fail closed");
            assert_eq!(err.code, ApprovalErrorCode::Expired);
        }
    }

    #[test]
    fn a_clock_rollback_shortens_rather_than_extends_validity() {
        let fixture = Fixture::new();
        let key = fixture.key();
        let ledger = InMemoryReceiptLedger::new();
        let broker = ApprovalBroker::new(&key, &fixture.trust, &fixture.operators, &ledger);
        let requester = isolated_requester("reg-abc123");
        let request = fixture.request();
        let auth = fixture.authenticate(&requester);
        let issued = broker
            .request_approval(&request, &requester, &auth, NOW)
            .expect("approve");

        let err = verify_for_consumption(
            issued.as_sealed_bytes(),
            &key,
            &fixture.expectations(&request, NOW - 1),
            &ledger,
        )
        .expect_err("a clock before the issue time must not extend validity");
        assert_eq!(err.code, ApprovalErrorCode::ClockRollback);
    }

    #[test]
    fn a_receipt_bound_to_other_facts_fails_closed() {
        let fixture = Fixture::new();
        let key = fixture.key();
        let ledger = InMemoryReceiptLedger::new();
        let broker = ApprovalBroker::new(&key, &fixture.trust, &fixture.operators, &ledger);
        let requester = isolated_requester("reg-abc123");
        let request = fixture.request();
        let auth = fixture.authenticate(&requester);
        let issued = broker
            .request_approval(&request, &requester, &auth, NOW)
            .expect("approve");
        let sealed = issued.as_sealed_bytes();

        // A different proposal.
        let other_digest = ProposalDigest::from_bytes([0xB2; 32]);
        let mut expectations = fixture.expectations(&request, NOW);
        expectations.proposal_digest = &other_digest;
        assert_eq!(
            verify_for_consumption(sealed, &key, &expectations, &ledger)
                .expect_err("wrong proposal")
                .code,
            ApprovalErrorCode::ProposalDigestMismatch
        );

        // A different target instance.
        let other_instance = InstanceId::new("inst-0000").expect("instance id");
        let mut expectations = fixture.expectations(&request, NOW);
        expectations.target_instance = &other_instance;
        assert_eq!(
            verify_for_consumption(sealed, &key, &expectations, &ledger)
                .expect_err("wrong target")
                .code,
            ApprovalErrorCode::TargetInstanceMismatch
        );

        // A root that moved or changed identity under the receipt.
        let moved = InstanceFingerprint::from_bytes([0xC3; 32]);
        let mut expectations = fixture.expectations(&request, NOW);
        expectations.instance_fingerprint = &moved;
        assert_eq!(
            verify_for_consumption(sealed, &key, &expectations, &ledger)
                .expect_err("moved root")
                .code,
            ApprovalErrorCode::InstanceFingerprintMismatch
        );

        // A configuration that changed underneath it.
        let changed = SourceRevisionDigest::of("schema_version = 3\n# and one more line\n");
        let mut expectations = fixture.expectations(&request, NOW);
        expectations.source_revision = &changed;
        assert_eq!(
            verify_for_consumption(sealed, &key, &expectations, &ledger)
                .expect_err("stale revision")
                .code,
            ApprovalErrorCode::SourceRevisionMismatch
        );
    }

    #[test]
    fn a_receipt_from_another_epoch_fails_closed() {
        let fixture = Fixture::new();
        let key = fixture.key();
        let ledger = InMemoryReceiptLedger::new();
        let broker = ApprovalBroker::new(&key, &fixture.trust, &fixture.operators, &ledger);
        let requester = isolated_requester("reg-abc123");
        let request = fixture.request();
        let auth = fixture.authenticate(&requester);
        let issued = broker
            .request_approval(&request, &requester, &auth, NOW)
            .expect("approve");

        // Verifying under the next epoch's key: the tag was minted under the
        // previous epoch's subkey, so authenticity fails first.
        let next_key =
            ApprovalAuditKey::derive(&fixture.paths.key_source(), TrustEpoch::new(2)).expect("key");
        let mut expectations = fixture.expectations(&request, NOW);
        expectations.trust_epoch = TrustEpoch::new(2);
        assert_eq!(
            verify_for_consumption(issued.as_sealed_bytes(), &next_key, &expectations, &ledger)
                .expect_err("a receipt must not survive an epoch transition")
                .code,
            ApprovalErrorCode::AuthenticationFailed
        );

        // And with the right key but the wrong declared epoch, the explicit
        // binding catches it rather than relying on the tag alone.
        let mut expectations = fixture.expectations(&request, NOW);
        expectations.trust_epoch = TrustEpoch::new(2);
        assert_eq!(
            verify_for_consumption(issued.as_sealed_bytes(), &key, &expectations, &ledger)
                .expect_err("epoch binding")
                .code,
            ApprovalErrorCode::TrustEpochMismatch
        );
    }

    // -- self-approval and eligibility --------------------------------------

    #[test]
    fn a_requester_that_is_the_operator_cannot_obtain_a_receipt() {
        // Non-escalation rule 4 at the broker boundary. The authentication is
        // obtained legitimately for one requester, then presented alongside a
        // requester whose subject is the operator itself.
        let fixture = Fixture::new();
        let key = fixture.key();
        let ledger = InMemoryReceiptLedger::new();
        let broker = ApprovalBroker::new(&key, &fixture.trust, &fixture.operators, &ledger);
        let request = fixture.request();

        let honest = isolated_requester("reg-abc123");
        let auth = fixture.authenticate(&honest);

        let self_requester = RequesterContext::external(
            RequesterSubject::new("jordan").expect("subject"),
            agent_domain(),
            Evidence::fully_isolated(),
        );
        let err = broker
            .request_approval(&request, &self_requester, &auth, NOW)
            .expect_err("a requester must not approve itself");
        // The authentication was made for a different requester, which is the
        // first thing that fails; the distinctness check backstops it below.
        assert_eq!(
            err.code,
            ApprovalErrorCode::AuthenticationNotForThisRequester
        );

        // Even an authentication legitimately bound to this requester cannot
        // help: `authenticate_operator` refuses to produce one.
        let refused = authenticate_operator(
            &ScriptedPresence::affirming("jordan"),
            "Approve? ".to_string(),
            "Operator identity: ".to_string(),
            &operator("jordan"),
            &fixture.operators,
            fixture.record.trust_epoch,
            &self_requester,
        )
        .expect_err("no authentication exists for a self-approving requester");
        assert_eq!(
            refused.code,
            crate::operator::OperatorErrorCode::OperatorIsTheRequester
        );
    }

    #[test]
    fn an_authentication_cannot_be_carried_to_a_different_requester() {
        let fixture = Fixture::new();
        let key = fixture.key();
        let ledger = InMemoryReceiptLedger::new();
        let broker = ApprovalBroker::new(&key, &fixture.trust, &fixture.operators, &ledger);
        let request = fixture.request();

        let first = isolated_requester("reg-abc123");
        let auth = fixture.authenticate(&first);

        let second = isolated_requester("reg-def456");
        let err = broker
            .request_approval(&request, &second, &auth, NOW)
            .expect_err("an authentication is bound to one requester");
        assert_eq!(
            err.code,
            ApprovalErrorCode::AuthenticationNotForThisRequester
        );
    }

    #[test]
    fn a_requester_that_can_reach_the_operator_cannot_obtain_a_receipt() {
        // Guarded by a mutation check: making reachability optimistic must make
        // this test fail.
        let fixture = Fixture::new();
        let key = fixture.key();
        let ledger = InMemoryReceiptLedger::new();
        let broker = ApprovalBroker::new(&key, &fixture.trust, &fixture.operators, &ledger);
        let request = fixture.request();

        // The authentication is obtained for an isolated requester, then the
        // *same subject* is presented with unprovable evidence. The fingerprint
        // covers class and subject, not evidence, so this reaches the broker's
        // own reachability re-check rather than stopping at the binding.
        let isolated = RequesterContext::external(
            RequesterSubject::new("reg-abc123").expect("subject"),
            agent_domain(),
            Evidence::fully_isolated(),
        );
        let auth = fixture.authenticate(&isolated);

        let now_unprovable = RequesterContext::external(
            RequesterSubject::new("reg-abc123").expect("subject"),
            agent_domain(),
            Evidence::unknown(),
        );
        assert_eq!(
            auth.issued_for(),
            &now_unprovable.fingerprint(),
            "the two contexts must be the same principal for this test to bite"
        );

        let err = broker
            .request_approval(&request, &now_unprovable, &auth, NOW)
            .expect_err("an operator the requester may reach must be ineligible");
        assert_eq!(err.code, ApprovalErrorCode::OperatorIneligible);

        // And the same requester cannot get an authentication in the first
        // place.
        assert_eq!(
            authenticate_operator(
                &ScriptedPresence::affirming("jordan"),
                "Approve? ".to_string(),
                "Operator identity: ".to_string(),
                &operator("jordan"),
                &fixture.operators,
                fixture.record.trust_epoch,
                &unprovable_requester("agent-alpha"),
            )
            .expect_err("no authentication for an unprovable requester")
            .code,
            crate::operator::OperatorErrorCode::OperatorIneligible
        );
    }

    #[test]
    fn an_operator_revoked_after_authenticating_cannot_still_approve() {
        // The broker re-checks the trust root at signing time, not only at
        // authentication time.
        let fixture = Fixture::new();
        let key = fixture.key();
        let ledger = InMemoryReceiptLedger::new();
        let requester = isolated_requester("reg-abc123");
        let request = fixture.request();
        let auth = fixture.authenticate(&requester);

        // The operator set the broker reads no longer contains the operator.
        let empty = OperatorRegistry::new();
        let broker = ApprovalBroker::new(&key, &fixture.trust, &empty, &ledger);
        let err = broker
            .request_approval(&request, &requester, &auth, NOW)
            .expect_err("an operator absent from the trust root cannot approve");
        assert_eq!(err.code, ApprovalErrorCode::OperatorNotRegistered);
    }

    // -- authority tier -----------------------------------------------------

    #[test]
    fn a_requester_cannot_obtain_a_receipt_for_any_meta_authority_operation() {
        // Non-escalation rule 11 and rule 13 together: no requester reaches the
        // trust root, and meta-authority cannot be downgraded into a class one
        // could reach.
        let fixture = Fixture::new();
        let key = fixture.key();
        let ledger = InMemoryReceiptLedger::new();
        let broker = ApprovalBroker::new(&key, &fixture.trust, &fixture.operators, &ledger);
        let requester = isolated_requester("reg-abc123");
        let auth = fixture.authenticate(&requester);

        for operation in ControlOperation::PERMANENTLY_META_AUTHORITY {
            let request = ApprovalRequest {
                operation: *operation,
                ..fixture.request()
            };
            match broker.request_approval(&request, &requester, &auth, NOW) {
                Ok(_) => panic!("{operation} is meta-authority and must never yield a receipt"),
                Err(err) => assert_eq!(
                    err.code,
                    ApprovalErrorCode::MetaAuthorityNotProposable,
                    "{operation} must be refused as unproposable"
                ),
            }
        }
    }

    #[test]
    fn a_requester_whose_grant_omits_the_domain_cannot_obtain_a_receipt() {
        let fixture = Fixture::new();
        let key = fixture.key();
        let ledger = InMemoryReceiptLedger::new();
        let broker = ApprovalBroker::new(&key, &fixture.trust, &fixture.operators, &ledger);
        let request = fixture.request();

        let ungranted = RequesterContext::external(
            RequesterSubject::new("reg-abc123").expect("subject"),
            std::collections::BTreeSet::new(),
            Evidence::fully_isolated(),
        );
        let auth = fixture.authenticate(&ungranted);
        let err = broker
            .request_approval(&request, &ungranted, &auth, NOW)
            .expect_err("a grant that does not cover the domain reaches nothing");
        assert_eq!(err.code, ApprovalErrorCode::GrantRequired);
    }

    // -- quorum -------------------------------------------------------------

    #[test]
    fn a_required_quorum_of_two_with_one_decision_does_not_verify() {
        // Quorum-ready enforcement, proven against a receipt this host actually
        // signed: authenticity is not the thing that stops it, the quorum rule
        // is.
        let fixture = Fixture::new();
        let key = fixture.key();
        let ledger = InMemoryReceiptLedger::new();
        let request = fixture.request();

        let receipt = ApprovalReceipt {
            receipt_id: ReceiptId::generate().expect("id"),
            proposal_digest: request.proposal_digest,
            target_instance: request.target_instance.clone(),
            instance_fingerprint: request.instance_fingerprint,
            source_revision: request.source_revision,
            operation: ControlOperation::ProposeAgentProfile,
            authority_tier: AuthorityTier::Ordinary,
            decision: Decision::Approve,
            required_quorum: required_quorum(AuthorityTier::MetaAuthority, 2),
            operator_decisions: vec![OperatorDecision {
                operator: operator("jordan"),
                decision: Decision::Approve,
                presence_class: PresenceClass::Terminal,
                decided_at_unix_secs: NOW,
            }],
            trust_epoch: fixture.record.trust_epoch,
            issued_at_unix_secs: NOW,
            expires_at_unix_secs: NOW + 300,
        };
        assert_eq!(receipt.required_quorum.get(), 2);
        let sealed = seal_receipt(receipt, &key);

        let err =
            verify_for_consumption(&sealed, &key, &fixture.expectations(&request, NOW), &ledger)
                .expect_err("one decision must not satisfy a quorum of two");
        assert_eq!(err.code, ApprovalErrorCode::QuorumNotSatisfied);
    }

    #[test]
    fn one_operator_cannot_satisfy_a_quorum_of_two_by_deciding_twice() {
        let fixture = Fixture::new();
        let key = fixture.key();
        let ledger = InMemoryReceiptLedger::new();
        let request = fixture.request();

        let decision = OperatorDecision {
            operator: operator("jordan"),
            decision: Decision::Approve,
            presence_class: PresenceClass::Terminal,
            decided_at_unix_secs: NOW,
        };
        let receipt = ApprovalReceipt {
            receipt_id: ReceiptId::generate().expect("id"),
            proposal_digest: request.proposal_digest,
            target_instance: request.target_instance.clone(),
            instance_fingerprint: request.instance_fingerprint,
            source_revision: request.source_revision,
            operation: ControlOperation::ProposeAgentProfile,
            authority_tier: AuthorityTier::Ordinary,
            decision: Decision::Approve,
            required_quorum: required_quorum(AuthorityTier::MetaAuthority, 2),
            operator_decisions: vec![decision.clone(), decision],
            trust_epoch: fixture.record.trust_epoch,
            issued_at_unix_secs: NOW,
            expires_at_unix_secs: NOW + 300,
        };
        let sealed = seal_receipt(receipt, &key);

        let err =
            verify_for_consumption(&sealed, &key, &fixture.expectations(&request, NOW), &ledger)
                .expect_err("a repeated operator is one operator");
        assert_eq!(err.code, ApprovalErrorCode::QuorumNotSatisfied);
    }

    #[test]
    fn the_configured_operator_count_is_what_the_quorum_reads() {
        // A second configured operator raises the meta-authority quorum even
        // though this requester might only be able to use one of them. An
        // eligibility-filtered count here would let a requester lower the bar
        // by becoming able to reach an operator.
        let fixture = Fixture::new().with_second_operator();
        assert_eq!(fixture.operators.active_count(), 2);
        assert_eq!(
            required_quorum(
                AuthorityTier::MetaAuthority,
                fixture.operators.active_count()
            )
            .get(),
            2
        );
        assert_eq!(
            required_quorum(AuthorityTier::Ordinary, fixture.operators.active_count()).get(),
            1,
            "an ordinary operation still needs one operator distinct from the requester"
        );
    }

    // -- rejection ----------------------------------------------------------

    #[test]
    fn a_rejection_is_signed_and_terminal_for_its_proposal_digest() {
        let fixture = Fixture::new();
        let key = fixture.key();
        let mut ledger = InMemoryReceiptLedger::new();
        let requester = isolated_requester("reg-abc123");
        let request = fixture.request();

        let rejection = {
            let broker = ApprovalBroker::new(&key, &fixture.trust, &fixture.operators, &ledger);
            let auth = fixture.authenticate(&requester);
            broker
                .reject(&request, &requester, &auth, NOW)
                .expect("an operator may reject")
        };
        assert_eq!(rejection.receipt().decision, Decision::Reject);
        // A rejection is a durable, authenticated fact, not an absence.
        assert!(AuthenticatedReceipt::open(rejection.as_sealed_bytes(), &key).is_ok());

        // It does not verify as an authorization.
        assert_eq!(
            verify_for_consumption(
                rejection.as_sealed_bytes(),
                &key,
                &fixture.expectations(&request, NOW),
                &ledger,
            )
            .expect_err("a rejection authorizes nothing")
            .code,
            ApprovalErrorCode::NotAnApproval
        );

        ledger.record_rejection(&rejection).expect("record");

        // Terminal: no later approval for the same digest can be obtained.
        let broker = ApprovalBroker::new(&key, &fixture.trust, &fixture.operators, &ledger);
        let auth = fixture.authenticate(&requester);
        assert_eq!(
            broker
                .request_approval(&request, &requester, &auth, NOW)
                .expect_err("a rejected proposal cannot later be approved")
                .code,
            ApprovalErrorCode::ProposalRejected
        );
    }

    #[test]
    fn an_approval_receipt_issued_before_a_rejection_stops_verifying_after_it() {
        let fixture = Fixture::new();
        let key = fixture.key();
        let mut ledger = InMemoryReceiptLedger::new();
        let requester = isolated_requester("reg-abc123");
        let request = fixture.request();

        let (approval, rejection) = {
            let broker = ApprovalBroker::new(&key, &fixture.trust, &fixture.operators, &ledger);
            let approval = broker
                .request_approval(&request, &requester, &fixture.authenticate(&requester), NOW)
                .expect("approve");
            let rejection = broker
                .reject(&request, &requester, &fixture.authenticate(&requester), NOW)
                .expect("reject");
            (approval, rejection)
        };

        assert!(
            verify_for_consumption(
                approval.as_sealed_bytes(),
                &key,
                &fixture.expectations(&request, NOW),
                &ledger,
            )
            .is_ok(),
            "before the rejection is recorded the approval still verifies"
        );

        ledger.record_rejection(&rejection).expect("record");

        assert_eq!(
            verify_for_consumption(
                approval.as_sealed_bytes(),
                &key,
                &fixture.expectations(&request, NOW),
                &ledger,
            )
            .expect_err("a terminal rejection outranks an outstanding approval")
            .code,
            ApprovalErrorCode::ProposalRejected
        );
    }

    #[test]
    fn only_a_rejection_receipt_can_record_a_rejection() {
        let fixture = Fixture::new();
        let key = fixture.key();
        let mut ledger = InMemoryReceiptLedger::new();
        let requester = isolated_requester("reg-abc123");
        let request = fixture.request();
        let approval = {
            let broker = ApprovalBroker::new(&key, &fixture.trust, &fixture.operators, &ledger);
            broker
                .request_approval(&request, &requester, &fixture.authenticate(&requester), NOW)
                .expect("approve")
        };

        assert_eq!(
            ledger
                .record_rejection(&approval)
                .expect_err("an approval is not a rejection")
                .code,
            ApprovalErrorCode::NotAnApproval
        );
    }

    // -- instance state -----------------------------------------------------

    #[test]
    fn an_unmanaged_instance_brokers_nothing() {
        let fixture = Fixture::new();
        let key = fixture.key();
        let ledger = InMemoryReceiptLedger::new();
        let requester = isolated_requester("reg-abc123");
        let request = fixture.request();
        let auth = fixture.authenticate(&requester);

        for trust in [
            InstanceTrustState::EligibleForFirstGenesis,
            InstanceTrustState::RecoveryOnly {
                reason: crate::genesis::RecoveryReason::RecordAuthenticationFailed,
                detail: "test".to_string(),
            },
        ] {
            let broker = ApprovalBroker::new(&key, &trust, &fixture.operators, &ledger);
            let err = broker
                .request_approval(&request, &requester, &auth, NOW)
                .expect_err("only a managed instance brokers approvals");
            assert_eq!(err.code, ApprovalErrorCode::InstanceNotManaged);
        }
    }

    #[test]
    fn a_request_naming_another_instance_is_refused() {
        let fixture = Fixture::new();
        let key = fixture.key();
        let ledger = InMemoryReceiptLedger::new();
        let broker = ApprovalBroker::new(&key, &fixture.trust, &fixture.operators, &ledger);
        let requester = isolated_requester("reg-abc123");
        let auth = fixture.authenticate(&requester);

        let request = ApprovalRequest {
            target_instance: InstanceId::new("inst-somewhere-else").expect("id"),
            ..fixture.request()
        };
        assert_eq!(
            broker
                .request_approval(&request, &requester, &auth, NOW)
                .expect_err("another instance is not this one")
                .code,
            ApprovalErrorCode::TargetMismatch
        );
    }

    #[test]
    fn a_broker_whose_key_epoch_disagrees_with_the_record_refuses() {
        let fixture = Fixture::new();
        let ledger = InMemoryReceiptLedger::new();
        let requester = isolated_requester("reg-abc123");
        let request = fixture.request();
        let auth = fixture.authenticate(&requester);

        let wrong_epoch_key =
            ApprovalAuditKey::derive(&fixture.paths.key_source(), TrustEpoch::new(2)).expect("key");
        let broker = ApprovalBroker::new(
            &wrong_epoch_key,
            &fixture.trust,
            &fixture.operators,
            &ledger,
        );
        assert_eq!(
            broker
                .request_approval(&request, &requester, &auth, NOW)
                .expect_err("the record, key, and authentication must agree on the epoch")
                .code,
            ApprovalErrorCode::TrustEpochMismatch
        );
    }

    // -- digests ------------------------------------------------------------

    #[test]
    fn source_revision_digests_separate_revisions_and_hide_their_text() {
        let a = SourceRevisionDigest::of("schema_version = 3\n");
        let b = SourceRevisionDigest::of("schema_version = 3\n\n");
        assert_ne!(a, b, "a one-byte change is a different revision");
        assert_eq!(a, SourceRevisionDigest::of("schema_version = 3\n"));
        assert!(!a.to_hex().contains("schema_version"));
        assert_eq!(
            SourceRevisionDigest::from_hex(&a.to_hex()).expect("round trip"),
            a
        );
    }

    #[test]
    fn a_receipt_id_is_random_and_bounded() {
        let a = ReceiptId::generate().expect("id");
        let b = ReceiptId::generate().expect("id");
        assert_ne!(a, b);
        assert!(a.as_str().starts_with("rcpt-"));
        assert!(ReceiptId::new("rcpt-abc_123.def").is_ok());
        for bad in ["", "has space", "has/slash", "has\\back", &"x".repeat(129)] {
            assert!(ReceiptId::new(bad).is_err(), "{bad:?} must be refused");
        }
    }

    #[test]
    fn the_canonical_encoding_covers_every_receipt_field() {
        // Length-prefixed absorption of an exhaustively destructured struct: a
        // change to any field must change the message the tag is computed over.
        let fixture = Fixture::new();
        let request = fixture.request();
        let base = ApprovalReceipt {
            receipt_id: ReceiptId::new("rcpt-fixed").expect("id"),
            proposal_digest: request.proposal_digest,
            target_instance: request.target_instance.clone(),
            instance_fingerprint: request.instance_fingerprint,
            source_revision: request.source_revision,
            operation: ControlOperation::ProposeAgentProfile,
            authority_tier: AuthorityTier::Ordinary,
            decision: Decision::Approve,
            required_quorum: RequiredQuorum::MINIMUM,
            operator_decisions: vec![OperatorDecision {
                operator: operator("jordan"),
                decision: Decision::Approve,
                presence_class: PresenceClass::Terminal,
                decided_at_unix_secs: NOW,
            }],
            trust_epoch: fixture.record.trust_epoch,
            issued_at_unix_secs: NOW,
            expires_at_unix_secs: NOW + 300,
        };
        let encode = |r: &ApprovalReceipt| {
            let mut out = Vec::new();
            r.absorb_canonical(&mut out);
            out
        };
        let baseline = encode(&base);

        let mut changed = base.clone();
        changed.decision = Decision::Reject;
        assert_ne!(baseline, encode(&changed), "decision must be covered");

        let mut changed = base.clone();
        changed.expires_at_unix_secs = NOW + 301;
        assert_ne!(baseline, encode(&changed), "expiry must be covered");

        let mut changed = base.clone();
        changed.required_quorum = required_quorum(AuthorityTier::MetaAuthority, 2);
        assert_ne!(baseline, encode(&changed), "quorum must be covered");

        let mut changed = base.clone();
        changed.operator_decisions[0].operator = operator("morgan");
        assert_ne!(baseline, encode(&changed), "the operator must be covered");

        let mut changed = base.clone();
        changed.operation = ControlOperation::WidenPolicy;
        assert_ne!(baseline, encode(&changed), "the operation must be covered");

        let mut changed = base;
        changed.operator_decisions.clear();
        assert_ne!(
            baseline,
            encode(&changed),
            "the decision count must be covered"
        );
    }

    #[test]
    fn a_declined_operator_ceremony_produces_no_receipt() {
        let fixture = Fixture::new();
        let requester = isolated_requester("reg-abc123");
        assert_eq!(
            authenticate_operator(
                &ScriptedPresence::failing(PresenceError::Declined),
                "Approve? ".to_string(),
                "Operator identity: ".to_string(),
                &operator("jordan"),
                &fixture.operators,
                fixture.record.trust_epoch,
                &requester,
            )
            .expect_err("a decline authenticates nobody")
            .code,
            crate::operator::OperatorErrorCode::PresenceDeclined
        );
    }
}
