//! Control-plane principals: the four classes, operator identities, and the
//! requester context the approval broker judges.
//!
//! # The four classes, and why there is no fifth
//!
//! The principals design defines exactly four principal classes and no others:
//!
//! | Class | Source | Authority |
//! |---|---|---|
//! | Agent requester | Runtime-derived agent identity | Inspect, propose, request review within a grant; **never approve** |
//! | External requester | Registered MCP client identity | Inspect, propose, request review within a grant; **never approve** |
//! | Operator | User-presence-authenticated human identity | Approve within configured policy |
//! | Recovery service | Host startup recovery worker | Resume or classify an already-authorized journal entry; **never approve** |
//!
//! There is no "local", "trusted", "admin", "root", or "same-user" class, and no
//! class a process acquires by how it was started. [`PrincipalClass`] is a
//! closed enum with those four variants, and the authority rules are methods on
//! it — [`PrincipalClass::can_approve`],
//! [`PrincipalClass::is_requester`], and
//! [`PrincipalClass::may_resume_authorized_entry`] — rather than prose a reader
//! has to remember. A test asserts the rule over every variant, so adding a
//! variant without deciding its authority does not compile past review.
//!
//! # Why an operator holds no bearer secret
//!
//! A registered client authenticates with a credential
//! ([`crate::client_registry::ClientCredential`]). An operator deliberately does
//! not, and this is a security property rather than an omission:
//!
//! - A bearer token is a thing an operator *has*, so it can be captured. Any
//!   process that can read the operator's files, memory, or terminal buffer can
//!   take it, and a requester that captured it would then be able to approve its
//!   own proposal — the one outcome the whole model exists to prevent.
//! - Presence cannot be captured and replayed. It is re-performed per decision,
//!   at a controlling terminal, and produces no artefact a requester could
//!   steal and re-present later.
//!
//! So [`OperatorRecord`] stores an identity label, a status, and provenance —
//! and no verifier, no secret, and no field whose value could stand in for
//! being present. The registry is sealed under the ADR-015 key exactly like the
//! client registry, so the *set* of operators is authenticated even though no
//! individual operator holds a secret.
//!
//! # Honest scope of terminal presence
//!
//! The one backchannel this phase implements is
//! [`crate::ceremony::TerminalConfirmation`], whose assurance class is
//! [`PresenceClass::Terminal`]. What it attests is precisely *a human answered
//! at the controlling terminal*, and the identity they type is matched against
//! the registered operator set. The label is not a secret, so terminal presence
//! does not distinguish *which* human is present — it distinguishes a human
//! from an agent.
//!
//! That is why [`PresenceClass::permits_mutation_enablement`] is `false` for
//! `Terminal` and stays false here. This phase records the attested class in
//! every receipt so a later mutation-enablement ceremony can refuse to inherit
//! it. Nothing in this phase treats `Terminal` as sufficient for enabling
//! mutations, because nothing in this phase enables mutations.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::approval::ProposalDigest;
use crate::ceremony::{PresenceError, PresenceRequest, UserPresence};
use crate::client_registry::ClientRegistry;
use crate::genesis::{
    FirstOperatorIdentity, GenesisRecord, InstanceTrustState, PresenceClass, RecoveryReason,
    classify, now_unix_secs,
};
use crate::keys::ApprovalAuditKey;
use crate::principal::RequesterGrant;
use crate::reachability::{self, Analysis, Evidence};
use crate::registry::{GenesisDigest, InstanceId, TrustEpoch};
use crate::store::{
    CanonicalBytes, ControlPaths, StoreError, absorb_field, absorb_str, absorb_u64, open_sealed,
    os_random_32, publish_new, publish_replace, read_optional, seal,
};

/// How long an operator authentication stays usable to mint a receipt, in
/// seconds.
///
/// Short on purpose, and bounded independently of the receipt lifetime: the
/// authentication is consumed by the broker moments after the ceremony
/// completes, and binding an expiry to it is what stops one presence ceremony
/// from authorising a decision an unbounded time later.
pub const OPERATOR_AUTHENTICATION_TTL_SECS: u64 = 300;

/// Domain-separation label for the sealed operator registry.
pub const OPERATOR_REGISTRY_DOMAIN: &str = "zeroclaw/control-plane/operator-registry/v1";

/// On-disk format version of the sealed operator registry.
pub const OPERATOR_REGISTRY_FORMAT_VERSION: u32 = 1;

/// File name of the sealed operator registry, inside the control state
/// directory.
///
/// Defined here rather than on [`ControlPaths`] because this module owns the
/// artefact; [`operator_registry_path`] is the single place that composes it.
pub const OPERATOR_REGISTRY_FILE: &str = "operators.json";

/// Label bound into a requester fingerprint.
pub const REQUESTER_FINGERPRINT_LABEL: &str = "zeroclaw/control-plane/requester-fingerprint/v1";

/// The sealed operator registry's path inside an instance's control directory.
#[must_use]
pub fn operator_registry_path(paths: &ControlPaths) -> PathBuf {
    paths.control_dir().join(OPERATOR_REGISTRY_FILE)
}

// ---------------------------------------------------------------------------
// Principal classes
// ---------------------------------------------------------------------------

/// One of the four control-plane principal classes.
///
/// See the module documentation for the table this reproduces. The variants are
/// closed and the authority methods are exhaustive `match`es, so a fifth class
/// cannot be added without answering every authority question for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalClass {
    /// Runtime-derived agent identity inside the daemon process.
    AgentRequester,
    /// Registered MCP client identity, verified through its credential.
    ExternalRequester,
    /// User-presence-authenticated human identity.
    Operator,
    /// The host startup recovery worker. It has no external entry point.
    RecoveryService,
}

impl PrincipalClass {
    /// Every class, in a stable order.
    pub const ALL: &'static [Self] = &[
        Self::AgentRequester,
        Self::ExternalRequester,
        Self::Operator,
        Self::RecoveryService,
    ];

    /// A stable, non-secret wire spelling.
    #[must_use]
    pub const fn wire(self) -> &'static str {
        match self {
            Self::AgentRequester => "agent_requester",
            Self::ExternalRequester => "external_requester",
            Self::Operator => "operator",
            Self::RecoveryService => "recovery_service",
        }
    }

    /// Parse a wire spelling, refusing anything outside the vocabulary.
    #[must_use]
    pub fn from_wire(value: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|c| c.wire() == value)
    }

    /// Whether this class may submit an approval decision.
    ///
    /// **Only [`Self::Operator`].** This is non-escalation rule 5 — "requester
    /// classes never approve" — and rule 10 — "the recovery service never
    /// approves" — expressed as code rather than as a comment. There is no
    /// configuration, grant, quorum setting, or deployment mode that changes
    /// this answer, because there is no input to change: the answer is a
    /// function of the class alone.
    #[must_use]
    pub const fn can_approve(self) -> bool {
        match self {
            Self::AgentRequester | Self::ExternalRequester | Self::RecoveryService => false,
            Self::Operator => true,
        }
    }

    /// Whether this class is one of the two requester classes.
    #[must_use]
    pub const fn is_requester(self) -> bool {
        match self {
            Self::AgentRequester | Self::ExternalRequester => true,
            Self::Operator | Self::RecoveryService => false,
        }
    }

    /// Whether this class may resume or classify an **already authorized**
    /// journal entry.
    ///
    /// Only the recovery service, and only for an entry that an operator
    /// already approved. This is not an approval capability: it cannot
    /// authorize a new proposal, mint a receipt, or re-consume a consumed one,
    /// which is why it is a separate question from [`Self::can_approve`].
    #[must_use]
    pub const fn may_resume_authorized_entry(self) -> bool {
        match self {
            Self::RecoveryService => true,
            Self::AgentRequester | Self::ExternalRequester | Self::Operator => false,
        }
    }
}

impl std::fmt::Display for PrincipalClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.wire())
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Why an operator-facing operation refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperatorErrorCode {
    /// The identity label is not acceptable.
    InvalidIdentity,
    /// The instance root could not be resolved or is unusable.
    RootUnusable,
    /// The instance has no genesis record.
    NotManaged,
    /// The instance is in recovery-only mode.
    RecoveryOnly,
    /// The deployment key source could not be read.
    KeySourceUnusable,
    /// The operator registry could not be loaded, verified, or written.
    RegistryUnusable,
    /// An operator with this identity is already registered.
    DuplicateOperator,
    /// The identity collides with a requester subject the host knows about.
    IdentityCollidesWithRequester,
    /// No presence attestation was produced.
    PresenceUnavailable,
    /// A human declined.
    PresenceDeclined,
    /// The attested identity is not the one being authenticated.
    IdentityMismatch,
    /// The identity is not a registered, active operator.
    NotARegisteredOperator,
    /// The requester can reach or impersonate this operator identity.
    OperatorIneligible,
    /// The operator identity is the requester's own subject.
    OperatorIsTheRequester,
    /// A principal class was used where it has no authority.
    ClassNotPermitted,
}

impl OperatorErrorCode {
    /// A stable, non-secret wire spelling.
    #[must_use]
    pub const fn wire(self) -> &'static str {
        match self {
            Self::InvalidIdentity => "invalid_identity",
            Self::RootUnusable => "root_unusable",
            Self::NotManaged => "not_managed",
            Self::RecoveryOnly => "recovery_only",
            Self::KeySourceUnusable => "key_source_unusable",
            Self::RegistryUnusable => "registry_unusable",
            Self::DuplicateOperator => "duplicate_operator",
            Self::IdentityCollidesWithRequester => "identity_collides_with_requester",
            Self::PresenceUnavailable => "presence_unavailable",
            Self::PresenceDeclined => "presence_declined",
            Self::IdentityMismatch => "identity_mismatch",
            Self::NotARegisteredOperator => "not_a_registered_operator",
            Self::OperatorIneligible => "operator_ineligible",
            Self::OperatorIsTheRequester => "operator_is_the_requester",
            Self::ClassNotPermitted => "class_not_permitted",
        }
    }
}

/// An operator-path refusal. `detail` never carries key material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperatorError {
    pub code: OperatorErrorCode,
    pub detail: String,
}

impl OperatorError {
    pub(crate) fn new(code: OperatorErrorCode, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }

    fn from_presence(error: &PresenceError) -> Self {
        match error {
            PresenceError::Declined => {
                Self::new(OperatorErrorCode::PresenceDeclined, error.to_string())
            }
            PresenceError::NoControllingTerminal
            | PresenceError::InvalidOperatorIdentity(_)
            | PresenceError::Io(_) => {
                Self::new(OperatorErrorCode::PresenceUnavailable, error.to_string())
            }
        }
    }

    fn recovery_only(reason: RecoveryReason, detail: &str) -> Self {
        Self::new(
            OperatorErrorCode::RecoveryOnly,
            format!("{}: {detail}", reason.wire()),
        )
    }
}

impl std::fmt::Display for OperatorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let what = match self.code {
            OperatorErrorCode::InvalidIdentity => "operator identity is not acceptable",
            OperatorErrorCode::RootUnusable => "instance root is unusable",
            OperatorErrorCode::NotManaged => {
                "this instance has no genesis record; run the genesis ceremony first"
            }
            OperatorErrorCode::RecoveryOnly => {
                "this instance is in recovery-only mode; only the recovery ceremony can leave it"
            }
            OperatorErrorCode::KeySourceUnusable => "the deployment key source could not be read",
            OperatorErrorCode::RegistryUnusable => "the operator registry could not be used",
            OperatorErrorCode::DuplicateOperator => "an operator with this identity is registered",
            OperatorErrorCode::IdentityCollidesWithRequester => {
                "this identity is already a requester subject on this instance"
            }
            OperatorErrorCode::PresenceUnavailable => "no user-presence attestation was produced",
            OperatorErrorCode::PresenceDeclined => "the ceremony was declined",
            OperatorErrorCode::IdentityMismatch => {
                "the attested identity is not the operator being authenticated"
            }
            OperatorErrorCode::NotARegisteredOperator => {
                "this identity is not a registered, active operator"
            }
            OperatorErrorCode::OperatorIneligible => {
                "the requester can reach or impersonate this operator identity"
            }
            OperatorErrorCode::OperatorIsTheRequester => {
                "the operator identity is the requester's own subject"
            }
            OperatorErrorCode::ClassNotPermitted => {
                "this principal class has no authority for this operation"
            }
        };
        write!(f, "{what}: {}", self.detail)
    }
}

impl std::error::Error for OperatorError {}

// ---------------------------------------------------------------------------
// Operator identity
// ---------------------------------------------------------------------------

/// A registered operator's identity label.
///
/// Validation is delegated to [`FirstOperatorIdentity::new`] rather than
/// re-implemented, so there is exactly one definition of what an operator label
/// may contain: non-empty after trimming, at most 128 bytes, no control
/// characters. The genesis first operator and a later-registered operator are
/// therefore the same kind of name, which is what lets the first operator be
/// looked up in the same registry view as the rest.
///
/// It is not a secret and confers no authority by itself. Authority comes from
/// being *present*, verified against this label at a controlling terminal.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct OperatorIdentity(String);

impl OperatorIdentity {
    /// Validate and wrap an operator identity label.
    ///
    /// # Errors
    ///
    /// Returns [`OperatorErrorCode::InvalidIdentity`] for an empty, oversized,
    /// or control-character-bearing label.
    pub fn new(value: impl Into<String>) -> Result<Self, OperatorError> {
        FirstOperatorIdentity::new(value)
            .map(Self::from)
            .map_err(|e| OperatorError::new(OperatorErrorCode::InvalidIdentity, e.detail))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<FirstOperatorIdentity> for OperatorIdentity {
    fn from(value: FirstOperatorIdentity) -> Self {
        Self(value.as_str().to_string())
    }
}

impl std::fmt::Display for OperatorIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for OperatorIdentity {
    type Error = OperatorError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<OperatorIdentity> for String {
    fn from(value: OperatorIdentity) -> Self {
        value.0
    }
}

// ---------------------------------------------------------------------------
// Requester subject and context
// ---------------------------------------------------------------------------

/// The host-derived identity of a requester.
///
/// For an agent requester this is the runtime-derived agent identity; for an
/// external requester it is the registration identifier. Both are *derived by
/// the host from facts the caller cannot choose* — the principals design's
/// classification-inputs rule — so this type is deliberately constructed by the
/// host, never parsed from a request body.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RequesterSubject(String);

impl RequesterSubject {
    /// Wrap a host-derived subject.
    ///
    /// # Errors
    ///
    /// Returns [`OperatorErrorCode::InvalidIdentity`] when the subject is empty
    /// after trimming, longer than 128 bytes, or contains a control character.
    /// The same bounds as an operator identity, so the two namespaces are
    /// directly comparable — which is what makes the "operator is the
    /// requester" check meaningful rather than a comparison of differently
    /// normalized strings.
    pub fn new(value: impl Into<String>) -> Result<Self, OperatorError> {
        FirstOperatorIdentity::new(value)
            .map(|v| Self(v.as_str().to_string()))
            .map_err(|e| OperatorError::new(OperatorErrorCode::InvalidIdentity, e.detail))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether this subject and `identity` name the same principal.
    ///
    /// Compared under a case fold ([`fold_identity`]), so `Jordan` and `jordan`
    /// are the same principal and the capitalised form cannot slip the
    /// "approver is the requester" check. Folding is the safe direction here:
    /// it can only make *more* pairings count as the same principal, which means
    /// *more* self-approvals are refused, never fewer. The stored identity is
    /// untouched — this normalizes for the comparison only.
    #[must_use]
    pub fn is(&self, identity: &OperatorIdentity) -> bool {
        fold_identity(&self.0) == fold_identity(identity.as_str())
    }
}

/// Fold an identity for a distinctness comparison only.
///
/// Applies Unicode simple case folding through [`char::to_lowercase`], which is
/// enough to unify `Jordan`/`jordan` and other case variants. Comparison only:
/// no stored identity is ever mutated by this.
///
/// Limitation: this is case folding, not NFC normalization. Canonically
/// equivalent but differently composed strings — a precomposed `é` versus `e`
/// plus a combining accent — still compare distinct. Closing that gap needs
/// `unicode-normalization`, which is not a direct dependency of this crate;
/// adding it is out of scope here, so the residual is documented rather than
/// fixed.
fn fold_identity(value: &str) -> String {
    value.chars().flat_map(char::to_lowercase).collect()
}

impl std::fmt::Display for RequesterSubject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A digest binding an operator authentication to one specific requester.
///
/// Without it, an authentication obtained while requester A was asking could be
/// replayed by the host against requester B, whose reachability analysis was
/// never run. See [`OperatorAuthentication::issued_for`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RequesterFingerprint([u8; 32]);

impl RequesterFingerprint {
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parse a 64-character hex fingerprint.
    ///
    /// # Errors
    ///
    /// Returns [`OperatorErrorCode::InvalidIdentity`] when the input is not
    /// exactly 32 hex-encoded bytes. Needed because a receipt binds this value
    /// and is deserialized when it is opened.
    pub fn from_hex(value: &str) -> Result<Self, OperatorError> {
        let mut bytes = [0u8; 32];
        hex::decode_to_slice(value, &mut bytes).map_err(|e| {
            OperatorError::new(
                OperatorErrorCode::InvalidIdentity,
                format!("requester fingerprint: {e}"),
            )
        })?;
        Ok(Self(bytes))
    }
}

impl std::fmt::Display for RequesterFingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl Serialize for RequesterFingerprint {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for RequesterFingerprint {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(d)?;
        Self::from_hex(&raw).map_err(serde::de::Error::custom)
    }
}

/// Everything the approval broker needs to know about the principal asking.
///
/// Constructed only through [`Self::agent`] and [`Self::external`], both of
/// which pin a requester class. There is no constructor that produces a
/// `RequesterContext` in the [`PrincipalClass::Operator`] or
/// [`PrincipalClass::RecoveryService`] class, so "the requester" and "the
/// approver" are different types at every call site rather than the same type
/// with a different flag.
///
/// It carries the requester's *proposal domains* rather than a whole
/// [`RequesterGrant`]. The grant remains the source of truth — the host derives
/// the set from it with [`Self::proposal_domains_from_grant`] — but the broker
/// needs only this projection, and taking less keeps the read domains, target
/// ids, and assurance class of a grant out of a type that circulates near the
/// approval path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequesterContext {
    class: PrincipalClass,
    subject: RequesterSubject,
    proposal_domains: std::collections::BTreeSet<String>,
    evidence: Evidence,
}

impl RequesterContext {
    /// A runtime-derived agent requester.
    #[must_use]
    pub fn agent(
        subject: RequesterSubject,
        proposal_domains: std::collections::BTreeSet<String>,
        evidence: Evidence,
    ) -> Self {
        Self {
            class: PrincipalClass::AgentRequester,
            subject,
            proposal_domains,
            evidence,
        }
    }

    /// A registered external MCP client requester.
    #[must_use]
    pub fn external(
        subject: RequesterSubject,
        proposal_domains: std::collections::BTreeSet<String>,
        evidence: Evidence,
    ) -> Self {
        Self {
            class: PrincipalClass::ExternalRequester,
            subject,
            proposal_domains,
            evidence,
        }
    }

    /// Project a [`RequesterGrant`]'s proposal authority into the set this type
    /// carries.
    ///
    /// Filters the closed [`crate::client_registry::PROPOSAL_DOMAINS_V1`]
    /// vocabulary through the grant rather than reading the grant's private
    /// field, so a domain the grant does not cover cannot appear here, and a
    /// domain this build does not define cannot appear either.
    #[must_use]
    pub fn proposal_domains_from_grant(
        grant: &RequesterGrant,
    ) -> std::collections::BTreeSet<String> {
        crate::client_registry::PROPOSAL_DOMAINS_V1
            .iter()
            .filter(|domain| grant.covers_proposal_domain(domain))
            .map(|domain| (*domain).to_string())
            .collect()
    }

    #[must_use]
    pub const fn class(&self) -> PrincipalClass {
        self.class
    }

    #[must_use]
    pub const fn subject(&self) -> &RequesterSubject {
        &self.subject
    }

    /// The proposal domains this requester may propose within.
    #[must_use]
    pub const fn proposal_domains(&self) -> &std::collections::BTreeSet<String> {
        &self.proposal_domains
    }

    /// Whether this requester may propose in `domain`.
    #[must_use]
    pub fn covers_proposal_domain(&self, domain: &str) -> bool {
        self.proposal_domains.contains(domain)
    }

    #[must_use]
    pub const fn evidence(&self) -> &Evidence {
        &self.evidence
    }

    /// Whether this requester may approve. Always `false`.
    ///
    /// Delegates to [`PrincipalClass::can_approve`] rather than returning a
    /// literal, so the one encoded rule governs both. The broker calls this as
    /// a fail-closed guard before anything else, so if the class rule were ever
    /// widened to admit a requester, the broker would refuse rather than
    /// silently accept a self-approval.
    #[must_use]
    pub const fn can_approve(&self) -> bool {
        self.class.can_approve()
    }

    /// This requester's binding fingerprint.
    #[must_use]
    pub fn fingerprint(&self) -> RequesterFingerprint {
        let mut message = Vec::new();
        absorb_str(&mut message, REQUESTER_FINGERPRINT_LABEL);
        absorb_str(&mut message, self.class.wire());
        absorb_str(&mut message, self.subject.as_str());
        let mut hasher = Sha256::new();
        hasher.update(&message);
        RequesterFingerprint(hasher.finalize().into())
    }

    /// Classify this requester against `identity` under the conservative rule.
    #[must_use]
    pub fn reachability(&self, identity: &OperatorIdentity) -> Analysis {
        reachability::classify(identity, &self.evidence)
    }
}

// ---------------------------------------------------------------------------
// Operator records and registry
// ---------------------------------------------------------------------------

/// Whether an operator may currently authenticate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatorStatus {
    /// Normal operation.
    Active,
    /// Permanently withdrawn. Revocation is immediate and fails closed.
    Revoked,
}

impl OperatorStatus {
    /// The authenticated spelling.
    #[must_use]
    pub const fn wire(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Revoked => "revoked",
        }
    }
}

/// How an operator identity entered the trust root.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatorOrigin {
    /// Established by the genesis ceremony as the first operator.
    Genesis,
    /// Added later by the operator-registration ceremony.
    Registered,
}

impl OperatorOrigin {
    /// The authenticated spelling.
    #[must_use]
    pub const fn wire(self) -> &'static str {
        match self {
            Self::Genesis => "genesis",
            Self::Registered => "registered",
        }
    }
}

/// One registered operator.
///
/// There is **no credential, verifier, or token field**, and no field whose
/// value could stand in for being present. See the module documentation for why
/// that is a property rather than an omission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorRecord {
    /// The identity label an operator authenticates as.
    pub identity: OperatorIdentity,
    /// How this identity entered the trust root.
    pub origin: OperatorOrigin,
    /// Epoch at registration. A recovery epoch transition invalidates records
    /// written under a prior epoch, exactly like a client registration.
    pub trust_epoch: TrustEpoch,
    /// Wall-clock creation time, seconds since the Unix epoch.
    pub created_at_unix_secs: u64,
    /// The genesis record this registration is anchored to.
    pub created_by_genesis_digest: GenesisDigest,
    /// The user-presence assurance class of the ceremony that registered it.
    pub ceremony_presence_class: PresenceClass,
    /// Current status.
    pub status: OperatorStatus,
}

impl OperatorRecord {
    /// Whether this record may currently authenticate.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.status == OperatorStatus::Active
    }
}

/// Every operator on one instance.
///
/// The genesis first operator is materialized into this registry by
/// [`Self::with_genesis_operator`] rather than stored twice: the genesis record
/// remains the source of truth for who the first operator is, and this view is
/// rebuilt from it on every load.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorRegistry {
    operators: BTreeMap<OperatorIdentity, OperatorRecord>,
}

impl OperatorRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a record, refusing to overwrite one.
    ///
    /// # Errors
    ///
    /// Returns [`OperatorErrorCode::DuplicateOperator`] when the identity is
    /// present. Silently replacing would let one registration retarget another
    /// operator's provenance.
    pub fn insert(&mut self, record: OperatorRecord) -> Result<(), OperatorError> {
        if self.operators.contains_key(&record.identity) {
            return Err(OperatorError::new(
                OperatorErrorCode::DuplicateOperator,
                record.identity.as_str().to_owned(),
            ));
        }
        self.operators.insert(record.identity.clone(), record);
        Ok(())
    }

    #[must_use]
    pub fn get(&self, identity: &OperatorIdentity) -> Option<&OperatorRecord> {
        self.operators.get(identity)
    }

    /// The record for `identity`, only when it may currently authenticate.
    #[must_use]
    pub fn get_active(&self, identity: &OperatorIdentity) -> Option<&OperatorRecord> {
        self.operators.get(identity).filter(|r| r.is_active())
    }

    pub fn iter(&self) -> impl Iterator<Item = &OperatorRecord> {
        self.operators.values()
    }

    /// Every operator that may currently authenticate.
    pub fn active(&self) -> impl Iterator<Item = &OperatorRecord> {
        self.operators.values().filter(|r| r.is_active())
    }

    /// How many operators may currently authenticate.
    ///
    /// This is the **configured** count, and it is what the quorum rule reads.
    /// It deliberately does not subtract operators that a particular requester
    /// can reach: the design's rule 4 resolution states that an ineligible
    /// operator does not lower the required quorum, because otherwise a
    /// requester could reduce the quorum by becoming able to reach an operator.
    #[must_use]
    pub fn active_count(&self) -> usize {
        self.active().count()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.operators.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.operators.is_empty()
    }

    /// This registry plus the genesis first operator.
    ///
    /// Genesis establishes an operator before any operator registry exists, so
    /// the first operator lives in the genesis record and is projected here on
    /// load. If a later registration somehow recorded the same identity, the
    /// genesis entry wins and the duplicate is dropped — the trust root outranks
    /// a file written after it.
    ///
    /// One exception, so the first operator is revocable like any other: if the
    /// loaded registry — authenticated under the ADR-015 key, so this is a
    /// host-written fact, not an attacker's — already records this identity as
    /// [`OperatorStatus::Revoked`], that sealed revocation is honored over the
    /// genesis default. Only the status is taken from the sealed record; origin,
    /// epoch, and provenance still come from genesis, so a later file cannot
    /// retarget the first operator's provenance, only revoke it.
    #[must_use]
    pub fn with_genesis_operator(mut self, record: &GenesisRecord) -> Self {
        let identity = OperatorIdentity::from(record.first_operator.clone());
        let status = match self.operators.get(&identity) {
            Some(existing) if existing.status == OperatorStatus::Revoked => OperatorStatus::Revoked,
            _ => OperatorStatus::Active,
        };
        self.operators.insert(
            identity.clone(),
            OperatorRecord {
                identity,
                origin: OperatorOrigin::Genesis,
                trust_epoch: record.trust_epoch,
                created_at_unix_secs: record.created_at_unix_secs,
                created_by_genesis_digest: record.digest(),
                ceremony_presence_class: record.user_presence_class,
                status,
            },
        );
        self
    }
}

/// Absorb one operator record.
///
/// Destructured exhaustively, without `..`: an unabsorbed field is a field the
/// authentication tag does not cover.
fn absorb_operator(out: &mut Vec<u8>, record: &OperatorRecord) {
    let OperatorRecord {
        identity,
        origin,
        trust_epoch,
        created_at_unix_secs,
        created_by_genesis_digest,
        ceremony_presence_class,
        status,
    } = record;
    absorb_str(out, identity.as_str());
    absorb_str(out, origin.wire());
    absorb_u64(out, trust_epoch.get());
    absorb_u64(out, *created_at_unix_secs);
    absorb_field(out, created_by_genesis_digest.as_bytes());
    absorb_str(out, ceremony_presence_class.wire());
    absorb_str(out, status.wire());
}

impl CanonicalBytes for OperatorRegistry {
    const DOMAIN: &'static str = OPERATOR_REGISTRY_DOMAIN;
    const FORMAT_VERSION: u32 = OPERATOR_REGISTRY_FORMAT_VERSION;

    fn absorb_canonical(&self, out: &mut Vec<u8>) {
        absorb_u64(out, self.len() as u64);
        for record in self.iter() {
            absorb_operator(out, record);
        }
    }
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

/// Whether an operator registry file exists at the fixed path.
#[must_use]
pub fn is_present(paths: &ControlPaths) -> bool {
    operator_registry_path(paths).exists()
}

/// Seal and publish the operator registry.
///
/// # Errors
///
/// Returns [`OperatorErrorCode::RegistryUnusable`] on an encoding or
/// publication failure.
pub fn save(
    paths: &ControlPaths,
    registry: &OperatorRegistry,
    key: &ApprovalAuditKey,
) -> Result<(), OperatorError> {
    let bytes = seal(registry, key).map_err(registry_unusable)?;
    publish_replace(&operator_registry_path(paths), &bytes).map_err(registry_unusable)
}

/// Publish the operator registry for the first time, refusing to replace one.
///
/// # Errors
///
/// Returns [`OperatorErrorCode::RegistryUnusable`] when one is already present.
pub fn save_new(
    paths: &ControlPaths,
    registry: &OperatorRegistry,
    key: &ApprovalAuditKey,
) -> Result<(), OperatorError> {
    let bytes = seal(registry, key).map_err(registry_unusable)?;
    publish_new(&operator_registry_path(paths), &bytes).map_err(registry_unusable)
}

/// Load and authenticate the operator registry, or an empty one when there is
/// none.
///
/// An absent registry is not an error: an instance whose only operator is the
/// genesis first operator has never written one. An *unverifiable* registry is
/// an error, and fails closed rather than degrading to the genesis-only view —
/// silently ignoring a tampered file would let an attacker delete operators by
/// corrupting it.
///
/// # Errors
///
/// Returns [`OperatorErrorCode::RegistryUnusable`] when a registry is present
/// but cannot be read or authenticated.
pub fn load(
    paths: &ControlPaths,
    key: &ApprovalAuditKey,
) -> Result<OperatorRegistry, OperatorError> {
    let path = operator_registry_path(paths);
    let Some(raw) = read_optional(&path).map_err(registry_unusable)? else {
        return Ok(OperatorRegistry::new());
    };
    open_sealed(&raw, key).map_err(registry_unusable)
}

fn registry_unusable(error: StoreError) -> OperatorError {
    OperatorError::new(OperatorErrorCode::RegistryUnusable, error.detail)
}

/// Load the operator registry and project the genesis first operator into it.
///
/// This is the view every authorization decision reads.
///
/// # Errors
///
/// See [`load`].
pub fn load_view(
    paths: &ControlPaths,
    record: &GenesisRecord,
    key: &ApprovalAuditKey,
) -> Result<OperatorRegistry, OperatorError> {
    Ok(load(paths, key)?.with_genesis_operator(record))
}

// ---------------------------------------------------------------------------
// Operator authentication
// ---------------------------------------------------------------------------

/// Proof that a registered operator authenticated, for one specific requester.
///
/// # Why this type has no public constructor
///
/// The only way to obtain one is [`authenticate_operator`], which requires a
/// [`UserPresence`] attestation. There is no `new`, no `Deserialize`, no
/// builder, and no field a caller can set. A requester therefore cannot
/// fabricate an `OperatorAuthentication`, and since
/// [`crate::approval::ApprovalBroker::request_approval`] takes one by reference
/// and there is no other way to reach a receipt, a requester cannot reach a
/// receipt either.
///
/// It is also bound to the requester it was produced for
/// ([`Self::issued_for`]), the exact proposal digest and target instance the
/// decision is about ([`Self::proposal_digest`], [`Self::instance`]), a wall-
/// clock expiry ([`Self::expires_at_unix_secs`]), and a fresh random nonce
/// ([`Self::nonce`]). Those bindings are what stop one presence ceremony from
/// authorising a *different* proposal, a decision on a *different* instance, or a
/// decision an unbounded time later.
///
/// It is deliberately **not** `Clone`, and
/// [`crate::approval::ApprovalBroker::request_approval`] consumes it **by
/// value**: a single ceremony can therefore mint at most one receipt, closing
/// the "one presence ceremony minted five receipts for five proposals" finding
/// structurally rather than by a runtime check that could be forgotten.
#[derive(Debug, PartialEq, Eq)]
pub struct OperatorAuthentication {
    identity: OperatorIdentity,
    presence_class: PresenceClass,
    trust_epoch: TrustEpoch,
    issued_for: RequesterFingerprint,
    proposal_digest: ProposalDigest,
    instance: InstanceId,
    authenticated_at_unix_secs: u64,
    expires_at_unix_secs: u64,
    nonce: [u8; 32],
}

impl OperatorAuthentication {
    /// The authenticated operator.
    #[must_use]
    pub const fn identity(&self) -> &OperatorIdentity {
        &self.identity
    }

    /// The proposal digest this authentication is bound to.
    #[must_use]
    pub const fn proposal_digest(&self) -> &ProposalDigest {
        &self.proposal_digest
    }

    /// The target instance this authentication is bound to.
    #[must_use]
    pub const fn instance(&self) -> &InstanceId {
        &self.instance
    }

    /// When this authentication expires, seconds since the Unix epoch. A broker
    /// that mints a receipt after this instant refuses.
    #[must_use]
    pub const fn expires_at_unix_secs(&self) -> u64 {
        self.expires_at_unix_secs
    }

    /// The fresh random nonce bound at authentication time.
    #[must_use]
    pub const fn nonce(&self) -> &[u8; 32] {
        &self.nonce
    }

    /// The assurance class actually achieved by the ceremony.
    #[must_use]
    pub const fn presence_class(&self) -> PresenceClass {
        self.presence_class
    }

    /// The epoch this authentication was made under.
    #[must_use]
    pub const fn trust_epoch(&self) -> TrustEpoch {
        self.trust_epoch
    }

    /// The requester this authentication was produced for.
    #[must_use]
    pub const fn issued_for(&self) -> &RequesterFingerprint {
        &self.issued_for
    }

    /// When the ceremony completed, seconds since the Unix epoch.
    #[must_use]
    pub const fn authenticated_at_unix_secs(&self) -> u64 {
        self.authenticated_at_unix_secs
    }

    /// The principal class of the authenticated party. Always
    /// [`PrincipalClass::Operator`].
    #[must_use]
    pub const fn principal_class(&self) -> PrincipalClass {
        PrincipalClass::Operator
    }
}

/// Authenticate `claimed` as an operator, for `requester`'s pending decision.
///
/// # Order, and why it is this order
///
/// 1. **The identity must be a registered, active operator.** An anonymous
///    terminal invocation is a requester, not an operator; the only way to be an
///    operator is to be in the trust root.
/// 2. **The operator must not be the requester.** Non-escalation rule 4: the
///    approver is always distinct from the requester.
/// 3. **The reachability analysis must clear the operator for this requester.**
///    Conservatively: unprovable means reachable means ineligible. This runs
///    *before* the prompt so an ineligible pairing never causes an operator to
///    be interrupted — and so a requester cannot use refusals to make the
///    terminal prompt fire at will.
/// 4. **Only then, the presence ceremony.** The human present types the identity
///    they are acting as, and it must equal the claimed identity.
///
/// The resulting authentication is bound to `proposal_digest`, `instance`, a
/// wall-clock expiry (`now_unix_secs` plus
/// [`OPERATOR_AUTHENTICATION_TTL_SECS`]), and a fresh random nonce, in addition
/// to the requester it was produced for. The broker re-checks the proposal,
/// instance, and expiry before it will mint a receipt, so an authentication
/// obtained for one request cannot authorise another.
///
/// # Errors
///
/// See [`OperatorErrorCode`]. Every failure is a refusal; none downgrades to a
/// weaker authentication.
pub fn authenticate_operator(
    presence: &dyn UserPresence,
    prompt: String,
    identity_prompt: String,
    claimed: &OperatorIdentity,
    operators: &OperatorRegistry,
    trust_epoch: TrustEpoch,
    requester: &RequesterContext,
    proposal_digest: &ProposalDigest,
    instance: &InstanceId,
    now_unix_secs: u64,
) -> Result<OperatorAuthentication, OperatorError> {
    // A requester class can never be on the approving side of this call. The
    // context type already makes this unreachable; checking it anyway means a
    // future widening of the class rule refuses here instead of proceeding.
    if requester.can_approve() {
        return Err(OperatorError::new(
            OperatorErrorCode::ClassNotPermitted,
            format!("{} claimed approval authority", requester.class().wire()),
        ));
    }

    let Some(record) = operators.get_active(claimed) else {
        return Err(OperatorError::new(
            OperatorErrorCode::NotARegisteredOperator,
            claimed.as_str().to_owned(),
        ));
    };

    if requester.subject().is(claimed) {
        return Err(OperatorError::new(
            OperatorErrorCode::OperatorIsTheRequester,
            claimed.as_str().to_owned(),
        ));
    }

    let analysis = requester.reachability(claimed);
    if !analysis.permits_approval() {
        return Err(OperatorError::new(
            OperatorErrorCode::OperatorIneligible,
            match analysis.unproven() {
                Some(question) => format!("{claimed}: unproven {question}"),
                None => claimed.as_str().to_owned(),
            },
        ));
    }

    // A record written under a superseded epoch is not a current operator.
    if record.trust_epoch != trust_epoch {
        return Err(OperatorError::new(
            OperatorErrorCode::NotARegisteredOperator,
            format!(
                "{claimed} was registered under epoch {}, current epoch is {trust_epoch}",
                record.trust_epoch
            ),
        ));
    }

    let attestation = presence
        .confirm(&PresenceRequest {
            prompt,
            operator_prompt: Some(identity_prompt),
        })
        .map_err(|e| OperatorError::from_presence(&e))?;

    let Some(attested) = attestation.operator_identity() else {
        return Err(OperatorError::new(
            OperatorErrorCode::PresenceUnavailable,
            "the ceremony attested no operator identity",
        ));
    };
    let attested = OperatorIdentity::from(attested.clone());
    if &attested != claimed {
        // Do not echo the attested label: it is text just typed at a prompt
        // that failed a trust check.
        return Err(OperatorError::new(
            OperatorErrorCode::IdentityMismatch,
            claimed.as_str().to_owned(),
        ));
    }

    let nonce = os_random_32()
        .map_err(|e| OperatorError::new(OperatorErrorCode::RegistryUnusable, e.detail))?;

    Ok(OperatorAuthentication {
        identity: claimed.clone(),
        presence_class: attestation.class(),
        trust_epoch,
        issued_for: requester.fingerprint(),
        proposal_digest: *proposal_digest,
        instance: instance.clone(),
        authenticated_at_unix_secs: now_unix_secs,
        expires_at_unix_secs: now_unix_secs.saturating_add(OPERATOR_AUTHENTICATION_TTL_SECS),
        nonce,
    })
}

// ---------------------------------------------------------------------------
// Operator registration ceremony
// ---------------------------------------------------------------------------

/// What an operator-registration ceremony needs from its caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterOperatorRequest {
    /// The identity the new operator will authenticate as.
    pub identity: OperatorIdentity,
    /// The rendered confirmation prompt.
    pub prompt: String,
}

/// What an operator-registration ceremony established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisteredOperator {
    pub identity: OperatorIdentity,
    pub trust_epoch: TrustEpoch,
    pub presence_class: PresenceClass,
    /// How many operators may authenticate after this registration.
    pub active_operator_count: usize,
}

/// Register an additional operator on an already-managed instance.
///
/// Registering an operator is a **meta-authority operation**
/// ([`crate::meta_authority::ControlOperation::RegisterOperator`]). Like the
/// ADR-016 bootstrap client registration, it runs host-side inside a user
/// presence ceremony rather than consuming a receipt, because it is reachable
/// only from the terminal and never from a requester surface: there is no tool,
/// no MCP method, and no daemon entry point that calls it.
///
/// # What it refuses, and why those are the checkable rules
///
/// - **Recovery-only and unmanaged instances.** No trust root, no operators.
/// - **A duplicate identity.** Including the genesis first operator.
/// - **An identity that collides with a requester subject the host knows
///   about** — any registered client's label or registration id. Creating an
///   operator named after a requester is exactly the "grant that can expose or
///   impersonate an operator backchannel identity" the design makes
///   meta-authority, and it is the one impersonation check the host can fully
///   discharge at registration time, because the client registry enumerates
///   every external requester subject.
///
/// The *per-requester* eligibility question — can this particular live requester
/// reach this operator — cannot be answered here, because registration happens
/// at a terminal with no requester in flight. It is answered conservatively at
/// approval time by [`authenticate_operator`], which is the point where the
/// requester is known. Splitting it this way is deliberate: this ceremony
/// discharges what it can prove, and defers what it cannot to the moment the
/// missing fact exists.
///
/// # Errors
///
/// See [`OperatorErrorCode`].
pub fn run_register_operator(
    install_root: &Path,
    presence: &dyn UserPresence,
    request: &RegisterOperatorRequest,
) -> Result<RegisteredOperator, OperatorError> {
    let paths = ControlPaths::resolve(install_root)
        .map_err(|e| OperatorError::new(OperatorErrorCode::RootUnusable, e.detail))?;
    let key_source = paths.key_source();

    let record = match classify(&paths, &key_source) {
        InstanceTrustState::Managed(record) => record,
        InstanceTrustState::EligibleForFirstGenesis => {
            return Err(OperatorError::new(
                OperatorErrorCode::NotManaged,
                paths.genesis_record().display().to_string(),
            ));
        }
        InstanceTrustState::RecoveryOnly { reason, detail } => {
            return Err(OperatorError::recovery_only(reason, &detail));
        }
    };

    let key = ApprovalAuditKey::derive(&key_source, record.trust_epoch)
        .map_err(|e| OperatorError::new(OperatorErrorCode::KeySourceUnusable, format!("{e:#}")))?;

    // Verify both registries before prompting, so an unverifiable one refuses
    // without troubling the operator.
    let clients = load_clients_for_collision_check(&paths, &key)?;
    refuse_requester_collision(&request.identity, &clients)?;
    let existing = load(&paths, &key)?;
    let view = existing.clone().with_genesis_operator(&record);
    if view.get(&request.identity).is_some() {
        return Err(OperatorError::new(
            OperatorErrorCode::DuplicateOperator,
            request.identity.as_str().to_owned(),
        ));
    }

    let attestation = presence
        .confirm(&PresenceRequest {
            prompt: request.prompt.clone(),
            operator_prompt: None,
        })
        .map_err(|e| OperatorError::from_presence(&e))?;

    // Re-read after the prompt rather than reusing the pre-prompt copy: a human
    // typing is an unbounded window, and this crate has no registry lock yet.
    let first_write = !is_present(&paths);
    let mut registry = load(&paths, &key)?;
    if registry
        .clone()
        .with_genesis_operator(&record)
        .get(&request.identity)
        .is_some()
    {
        return Err(OperatorError::new(
            OperatorErrorCode::DuplicateOperator,
            request.identity.as_str().to_owned(),
        ));
    }

    registry.insert(OperatorRecord {
        identity: request.identity.clone(),
        origin: OperatorOrigin::Registered,
        trust_epoch: record.trust_epoch,
        created_at_unix_secs: now_unix_secs()
            .map_err(|e| OperatorError::new(OperatorErrorCode::RegistryUnusable, e.detail))?,
        created_by_genesis_digest: record.digest(),
        ceremony_presence_class: attestation.class(),
        status: OperatorStatus::Active,
    })?;

    if first_write {
        save_new(&paths, &registry, &key)?;
    } else {
        save(&paths, &registry, &key)?;
    }

    Ok(RegisteredOperator {
        identity: request.identity.clone(),
        trust_epoch: record.trust_epoch,
        presence_class: attestation.class(),
        active_operator_count: registry.with_genesis_operator(&record).active_count(),
    })
}

/// Load the client registry for the collision check, tolerating its absence.
fn load_clients_for_collision_check(
    paths: &ControlPaths,
    key: &ApprovalAuditKey,
) -> Result<ClientRegistry, OperatorError> {
    if crate::client_registry::is_present(paths) {
        crate::client_registry::load(paths, key)
            .map_err(|e| OperatorError::new(OperatorErrorCode::RegistryUnusable, e.to_string()))
    } else {
        Ok(ClientRegistry::new())
    }
}

/// Refuse an operator identity that names a known requester subject.
///
/// The comparison is case-folded ([`fold_identity`]), so registering an operator
/// `Jordan` is refused when a client `jordan` already exists — the confusable
/// pair the byte-exact check would have let through. Comparison only; the stored
/// identities and registrations are untouched.
fn refuse_requester_collision(
    identity: &OperatorIdentity,
    clients: &ClientRegistry,
) -> Result<(), OperatorError> {
    let folded = fold_identity(identity.as_str());
    for registration in clients.iter() {
        if fold_identity(registration.registration_id.as_str()) == folded
            || fold_identity(registration.client_label.as_str()) == folded
        {
            return Err(OperatorError::new(
                OperatorErrorCode::IdentityCollidesWithRequester,
                identity.as_str().to_owned(),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client_registry::{ClientGrant, ClientLabel, CredentialDelivery};
    use crate::test_support::{
        ScriptedPresence, agent_domain, genesis_instance, install_root, isolated_requester,
        key_for, operator, unprovable_requester,
    };

    /// A fixed proposal digest for tests that only exercise authentication.
    fn test_proposal_digest() -> ProposalDigest {
        ProposalDigest::from_bytes([0x11; 32])
    }

    /// A fixed target instance for tests that only exercise authentication.
    fn test_instance() -> InstanceId {
        InstanceId::new("inst-operator-test").expect("instance id")
    }

    fn authenticate(
        presence: &dyn UserPresence,
        claimed: &OperatorIdentity,
        operators: &OperatorRegistry,
        epoch: TrustEpoch,
        requester: &RequesterContext,
    ) -> Result<OperatorAuthentication, OperatorError> {
        authenticate_operator(
            presence,
            "Approve this operation? ".to_string(),
            "Operator identity: ".to_string(),
            claimed,
            operators,
            epoch,
            requester,
            &test_proposal_digest(),
            &test_instance(),
            1_700_000_000,
        )
    }

    // -- principal classes --------------------------------------------------

    #[test]
    fn no_requester_class_and_no_recovery_service_can_ever_approve() {
        // Non-escalation rules 5 and 10, encoded as code rather than prose.
        //
        // Guarded by a mutation check: making any requester class return `true`
        // from `can_approve` must make this test fail.
        for class in [
            PrincipalClass::AgentRequester,
            PrincipalClass::ExternalRequester,
            PrincipalClass::RecoveryService,
        ] {
            assert!(
                !class.can_approve(),
                "{class} must never be able to approve"
            );
        }
        assert!(
            PrincipalClass::Operator.can_approve(),
            "the operator class is the only one that approves"
        );
        assert_eq!(
            PrincipalClass::ALL
                .iter()
                .filter(|c| c.can_approve())
                .count(),
            1,
            "exactly one of the four classes may approve"
        );
    }

    #[test]
    fn only_the_recovery_service_may_resume_an_authorized_entry_and_it_still_cannot_approve() {
        for class in PrincipalClass::ALL {
            assert_eq!(
                class.may_resume_authorized_entry(),
                *class == PrincipalClass::RecoveryService,
                "{class} resume authority is wrong"
            );
        }
        // The two capabilities are disjoint: resuming is not approving.
        assert!(PrincipalClass::RecoveryService.may_resume_authorized_entry());
        assert!(!PrincipalClass::RecoveryService.can_approve());
    }

    #[test]
    fn exactly_the_two_requester_classes_are_requesters() {
        for class in PrincipalClass::ALL {
            assert_eq!(
                class.is_requester(),
                matches!(
                    class,
                    PrincipalClass::AgentRequester | PrincipalClass::ExternalRequester
                ),
                "{class} requester classification is wrong"
            );
        }
        // There is no fifth class, and in particular no "local"/"admin"/"root".
        assert_eq!(PrincipalClass::ALL.len(), 4);
    }

    #[test]
    fn the_class_vocabulary_round_trips_and_refuses_unknown_spellings() {
        for class in PrincipalClass::ALL {
            assert_eq!(PrincipalClass::from_wire(class.wire()), Some(*class));
        }
        for unknown in ["local", "trusted", "admin", "root", "same_user", ""] {
            assert_eq!(
                PrincipalClass::from_wire(unknown),
                None,
                "{unknown} must not name a principal class"
            );
        }
    }

    // -- requester context --------------------------------------------------

    #[test]
    fn a_requester_context_can_never_report_approval_authority() {
        for requester in [
            unprovable_requester("agent-alpha"),
            isolated_requester("reg-abc123"),
        ] {
            assert!(!requester.can_approve());
            assert!(requester.class().is_requester());
        }
    }

    #[test]
    fn requester_fingerprints_separate_subjects_and_classes() {
        let a = unprovable_requester("agent-alpha");
        let b = unprovable_requester("agent-beta");
        assert_ne!(
            a.fingerprint(),
            b.fingerprint(),
            "two subjects must not share a fingerprint"
        );

        // Same subject string, different class, must not collide: otherwise an
        // authentication issued for an external client could be replayed for a
        // same-named agent.
        let agent = RequesterContext::agent(
            RequesterSubject::new("shared").expect("subject"),
            agent_domain(),
            Evidence::unknown(),
        );
        let external = RequesterContext::external(
            RequesterSubject::new("shared").expect("subject"),
            agent_domain(),
            Evidence::unknown(),
        );
        assert_ne!(agent.fingerprint(), external.fingerprint());

        // Stable across rebuilds of the same context.
        assert_eq!(
            a.fingerprint(),
            unprovable_requester("agent-alpha").fingerprint()
        );
    }

    // -- identities ---------------------------------------------------------

    #[test]
    fn an_operator_identity_shares_the_genesis_first_operator_validation() {
        assert_eq!(operator("  jordan  ").as_str(), "jordan");
        for bad in ["", "   ", "jordan\nadmin", "jordan\u{0}"] {
            assert!(
                OperatorIdentity::new(bad).is_err(),
                "{bad:?} must not be an operator identity"
            );
        }
        assert!(OperatorIdentity::new("a".repeat(128)).is_ok());
        assert!(OperatorIdentity::new("a".repeat(129)).is_err());

        // A requester subject normalizes identically, so the "operator is the
        // requester" comparison cannot be dodged with padding.
        let subject = RequesterSubject::new("  jordan  ").expect("subject");
        assert!(subject.is(&operator("jordan")));
    }

    // -- registry -----------------------------------------------------------

    #[test]
    fn the_genesis_first_operator_is_projected_into_the_registry() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (_root, _paths, record) = genesis_instance(&tmp);

        let view = OperatorRegistry::new().with_genesis_operator(&record);
        let first = view
            .get_active(&operator("jordan"))
            .expect("first operator");
        assert_eq!(first.origin, OperatorOrigin::Genesis);
        assert_eq!(first.trust_epoch, TrustEpoch::GENESIS);
        assert_eq!(first.ceremony_presence_class, PresenceClass::Terminal);
        assert_eq!(view.active_count(), 1, "genesis establishes one operator");
    }

    #[test]
    fn inserting_a_duplicate_operator_is_refused() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (_root, _paths, record) = genesis_instance(&tmp);
        let mut registry = OperatorRegistry::new();
        let make = |name: &str| OperatorRecord {
            identity: operator(name),
            origin: OperatorOrigin::Registered,
            trust_epoch: TrustEpoch::GENESIS,
            created_at_unix_secs: 1,
            created_by_genesis_digest: record.digest(),
            ceremony_presence_class: PresenceClass::Terminal,
            status: OperatorStatus::Active,
        };
        registry.insert(make("morgan")).expect("first insert");
        let err = registry
            .insert(make("morgan"))
            .expect_err("a duplicate must be refused");
        assert_eq!(err.code, OperatorErrorCode::DuplicateOperator);
    }

    #[test]
    fn a_revoked_operator_is_not_active_and_does_not_count_toward_quorum() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (_root, _paths, record) = genesis_instance(&tmp);
        let mut registry = OperatorRegistry::new();
        registry
            .insert(OperatorRecord {
                identity: operator("morgan"),
                origin: OperatorOrigin::Registered,
                trust_epoch: TrustEpoch::GENESIS,
                created_at_unix_secs: 1,
                created_by_genesis_digest: record.digest(),
                ceremony_presence_class: PresenceClass::Terminal,
                status: OperatorStatus::Revoked,
            })
            .expect("insert");
        assert!(registry.get(&operator("morgan")).is_some());
        assert!(
            registry.get_active(&operator("morgan")).is_none(),
            "revocation is immediate and fails closed"
        );
        let view = registry.with_genesis_operator(&record);
        assert_eq!(
            view.active_count(),
            1,
            "only the genesis operator is active"
        );
    }

    #[test]
    fn an_operator_record_carries_no_credential_or_verifier_field() {
        // The design's rule expressed as a shape assertion: there is nowhere in
        // this record to put a bearer secret an attacker could capture.
        let tmp = tempfile::tempdir().expect("tempdir");
        let (_root, _paths, record) = genesis_instance(&tmp);
        let view = OperatorRegistry::new().with_genesis_operator(&record);
        let rendered =
            serde_json::to_string(view.get(&operator("jordan")).expect("record")).expect("encode");
        for forbidden in [
            "credential",
            "verifier",
            "secret",
            "token",
            "password",
            "key",
        ] {
            assert!(
                !rendered.contains(forbidden),
                "an operator record must contain no {forbidden} field: {rendered}"
            );
        }
    }

    // -- persistence --------------------------------------------------------

    #[test]
    fn the_operator_registry_round_trips_through_the_seal() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (_root, paths, record) = genesis_instance(&tmp);
        let key = key_for(&paths, &record);

        assert!(!is_present(&paths));
        assert!(
            load(&paths, &key).expect("absent loads empty").is_empty(),
            "an instance with only the genesis operator has written no registry"
        );

        let mut registry = OperatorRegistry::new();
        registry
            .insert(OperatorRecord {
                identity: operator("morgan"),
                origin: OperatorOrigin::Registered,
                trust_epoch: TrustEpoch::GENESIS,
                created_at_unix_secs: 42,
                created_by_genesis_digest: record.digest(),
                ceremony_presence_class: PresenceClass::Terminal,
                status: OperatorStatus::Active,
            })
            .expect("insert");
        save_new(&paths, &registry, &key).expect("save");
        assert!(is_present(&paths));
        assert_eq!(load(&paths, &key).expect("load"), registry);
    }

    #[test]
    fn a_tampered_operator_registry_fails_closed() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (_root, paths, record) = genesis_instance(&tmp);
        let key = key_for(&paths, &record);

        let mut registry = OperatorRegistry::new();
        registry
            .insert(OperatorRecord {
                identity: operator("morgan"),
                origin: OperatorOrigin::Registered,
                trust_epoch: TrustEpoch::GENESIS,
                created_at_unix_secs: 42,
                created_by_genesis_digest: record.digest(),
                ceremony_presence_class: PresenceClass::Terminal,
                status: OperatorStatus::Active,
            })
            .expect("insert");
        save_new(&paths, &registry, &key).expect("save");

        // Rewrite the payload without being able to re-tag it: exactly what an
        // attacker who can write the file but not derive the key can do.
        let path = operator_registry_path(&paths);
        let raw = std::fs::read_to_string(&path).expect("read");
        std::fs::write(&path, raw.replace("morgan", "attack")).expect("tamper");

        let err = load(&paths, &key).expect_err("a tampered registry must not load");
        assert_eq!(err.code, OperatorErrorCode::RegistryUnusable);
    }

    // -- authentication -----------------------------------------------------

    #[test]
    fn a_registered_operator_authenticates_for_a_distinct_isolated_requester() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (_root, _paths, record) = genesis_instance(&tmp);
        let operators = OperatorRegistry::new().with_genesis_operator(&record);
        let presence = ScriptedPresence::affirming("jordan");

        let auth = authenticate(
            &presence,
            &operator("jordan"),
            &operators,
            TrustEpoch::GENESIS,
            &isolated_requester("reg-abc123"),
        )
        .expect("a registered, eligible operator must authenticate");

        assert_eq!(auth.identity(), &operator("jordan"));
        assert_eq!(auth.presence_class(), PresenceClass::Terminal);
        assert_eq!(auth.trust_epoch(), TrustEpoch::GENESIS);
        assert_eq!(auth.principal_class(), PrincipalClass::Operator);
        assert_eq!(
            auth.issued_for(),
            &isolated_requester("reg-abc123").fingerprint(),
            "the authentication must be bound to the requester it was made for"
        );
        assert_eq!(presence.prompts(), 1);
    }

    #[test]
    fn an_unregistered_identity_cannot_authenticate_as_an_operator() {
        // "An anonymous TTY invocation is a requester, not an operator." Being
        // at the terminal is necessary and not sufficient: the identity must be
        // in the trust root.
        let tmp = tempfile::tempdir().expect("tempdir");
        let (_root, _paths, record) = genesis_instance(&tmp);
        let operators = OperatorRegistry::new().with_genesis_operator(&record);
        let presence = ScriptedPresence::affirming("nobody");

        let err = authenticate(
            &presence,
            &operator("nobody"),
            &operators,
            TrustEpoch::GENESIS,
            &isolated_requester("reg-abc123"),
        )
        .expect_err("an unregistered identity must not authenticate");
        assert_eq!(err.code, OperatorErrorCode::NotARegisteredOperator);
        assert_eq!(
            presence.prompts(),
            0,
            "an unregistered identity must be refused before any prompt"
        );
    }

    #[test]
    fn an_operator_identity_equal_to_the_requester_subject_is_refused() {
        // Non-escalation rule 4: the approver is always distinct from the
        // requester. There is no configuration in which this succeeds.
        let tmp = tempfile::tempdir().expect("tempdir");
        let (_root, _paths, record) = genesis_instance(&tmp);
        let operators = OperatorRegistry::new().with_genesis_operator(&record);
        let presence = ScriptedPresence::affirming("jordan");

        // A requester that has somehow taken the operator's own subject name.
        let self_requester = RequesterContext::external(
            RequesterSubject::new("jordan").expect("subject"),
            agent_domain(),
            Evidence::fully_isolated(),
        );

        let err = authenticate(
            &presence,
            &operator("jordan"),
            &operators,
            TrustEpoch::GENESIS,
            &self_requester,
        )
        .expect_err("a requester must not authenticate as itself");
        assert_eq!(err.code, OperatorErrorCode::OperatorIsTheRequester);
        assert_eq!(presence.prompts(), 0);
    }

    #[test]
    fn an_operator_the_requester_can_reach_is_ineligible() {
        // The conservative reachability rule at the authentication boundary.
        //
        // Guarded by a mutation check: making `reachability::classify` treat an
        // unprovable requester as isolated must make this test fail.
        let tmp = tempfile::tempdir().expect("tempdir");
        let (_root, _paths, record) = genesis_instance(&tmp);
        let operators = OperatorRegistry::new().with_genesis_operator(&record);
        let presence = ScriptedPresence::affirming("jordan");

        let err = authenticate(
            &presence,
            &operator("jordan"),
            &operators,
            TrustEpoch::GENESIS,
            &unprovable_requester("agent-alpha"),
        )
        .expect_err("an operator the requester may reach must be ineligible");
        assert_eq!(err.code, OperatorErrorCode::OperatorIneligible);
        assert!(
            err.detail.contains("distinct_os_account"),
            "the refusal must name the missing proof: {}",
            err.detail
        );
        assert_eq!(
            presence.prompts(),
            0,
            "an ineligible pairing must never reach the operator's terminal"
        );
    }

    #[test]
    fn a_declined_presence_produces_no_authentication() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (_root, _paths, record) = genesis_instance(&tmp);
        let operators = OperatorRegistry::new().with_genesis_operator(&record);

        for (error, expected) in [
            (PresenceError::Declined, OperatorErrorCode::PresenceDeclined),
            (
                PresenceError::NoControllingTerminal,
                OperatorErrorCode::PresenceUnavailable,
            ),
        ] {
            let presence = ScriptedPresence::failing(error);
            let err = authenticate(
                &presence,
                &operator("jordan"),
                &operators,
                TrustEpoch::GENESIS,
                &isolated_requester("reg-abc123"),
            )
            .expect_err("no attestation means no authentication");
            assert_eq!(err.code, expected);
        }
    }

    #[test]
    fn an_attested_identity_that_differs_from_the_claim_is_refused() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (_root, _paths, record) = genesis_instance(&tmp);
        let mut registry = OperatorRegistry::new();
        registry
            .insert(OperatorRecord {
                identity: operator("morgan"),
                origin: OperatorOrigin::Registered,
                trust_epoch: TrustEpoch::GENESIS,
                created_at_unix_secs: 7,
                created_by_genesis_digest: record.digest(),
                ceremony_presence_class: PresenceClass::Terminal,
                status: OperatorStatus::Active,
            })
            .expect("insert");
        let operators = registry.with_genesis_operator(&record);

        // The human present types a different registered operator's name.
        let presence = ScriptedPresence::affirming("morgan");
        let err = authenticate(
            &presence,
            &operator("jordan"),
            &operators,
            TrustEpoch::GENESIS,
            &isolated_requester("reg-abc123"),
        )
        .expect_err("the attested identity must be the claimed one");
        assert_eq!(err.code, OperatorErrorCode::IdentityMismatch);
    }

    #[test]
    fn an_attestation_carrying_no_identity_is_refused() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (_root, _paths, record) = genesis_instance(&tmp);
        let operators = OperatorRegistry::new().with_genesis_operator(&record);
        let presence = ScriptedPresence::affirming_without_identity();

        let err = authenticate(
            &presence,
            &operator("jordan"),
            &operators,
            TrustEpoch::GENESIS,
            &isolated_requester("reg-abc123"),
        )
        .expect_err("an attestation with no identity authenticates nobody");
        assert_eq!(err.code, OperatorErrorCode::PresenceUnavailable);
    }

    #[test]
    fn a_revoked_operator_cannot_authenticate() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (_root, _paths, record) = genesis_instance(&tmp);
        let mut registry = OperatorRegistry::new();
        registry
            .insert(OperatorRecord {
                identity: operator("morgan"),
                origin: OperatorOrigin::Registered,
                trust_epoch: TrustEpoch::GENESIS,
                created_at_unix_secs: 7,
                created_by_genesis_digest: record.digest(),
                ceremony_presence_class: PresenceClass::Terminal,
                status: OperatorStatus::Revoked,
            })
            .expect("insert");
        let operators = registry.with_genesis_operator(&record);

        let presence = ScriptedPresence::affirming("morgan");
        let err = authenticate(
            &presence,
            &operator("morgan"),
            &operators,
            TrustEpoch::GENESIS,
            &isolated_requester("reg-abc123"),
        )
        .expect_err("a revoked operator must not authenticate");
        assert_eq!(err.code, OperatorErrorCode::NotARegisteredOperator);
        assert_eq!(presence.prompts(), 0);
    }

    #[test]
    fn an_operator_from_a_superseded_epoch_cannot_authenticate() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (_root, _paths, record) = genesis_instance(&tmp);
        let operators = OperatorRegistry::new().with_genesis_operator(&record);
        let presence = ScriptedPresence::affirming("jordan");

        let err = authenticate(
            &presence,
            &operator("jordan"),
            &operators,
            TrustEpoch::new(2),
            &isolated_requester("reg-abc123"),
        )
        .expect_err("an epoch transition must invalidate an operator record");
        assert_eq!(err.code, OperatorErrorCode::NotARegisteredOperator);
        assert_eq!(presence.prompts(), 0);
    }

    // -- registration ceremony ----------------------------------------------

    #[test]
    fn registering_an_operator_appends_it_to_the_sealed_registry() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (root, paths, record) = genesis_instance(&tmp);
        let presence = ScriptedPresence::affirming("ignored");

        let registered = run_register_operator(
            &root,
            &presence,
            &RegisterOperatorRequest {
                identity: operator("morgan"),
                prompt: "Register this operator? ".to_string(),
            },
        )
        .expect("registration must succeed");

        assert_eq!(registered.identity, operator("morgan"));
        assert_eq!(registered.trust_epoch, TrustEpoch::GENESIS);
        assert_eq!(registered.presence_class, PresenceClass::Terminal);
        assert_eq!(
            registered.active_operator_count, 2,
            "the genesis operator plus the new one"
        );

        let key = key_for(&paths, &record);
        let view = load_view(&paths, &record, &key).expect("load");
        assert_eq!(view.active_count(), 2);
        let added = view.get_active(&operator("morgan")).expect("registered");
        assert_eq!(added.origin, OperatorOrigin::Registered);
        assert_eq!(added.created_by_genesis_digest, record.digest());
    }

    #[test]
    fn operator_registration_refuses_in_recovery_only_mode() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (root, paths, _record) = genesis_instance(&tmp);
        std::fs::write(paths.genesis_record(), b"{ corrupted").expect("corrupt");

        let presence = ScriptedPresence::affirming("ignored");
        let err = run_register_operator(
            &root,
            &presence,
            &RegisterOperatorRequest {
                identity: operator("morgan"),
                prompt: "Register this operator? ".to_string(),
            },
        )
        .expect_err("recovery-only must refuse operator registration");
        assert_eq!(err.code, OperatorErrorCode::RecoveryOnly);
        assert!(
            err.detail
                .contains(RecoveryReason::RecordUnparseable.wire()),
            "the refusal must be reportable: {}",
            err.detail
        );
        assert_eq!(presence.prompts(), 0);
    }

    #[test]
    fn operator_registration_refuses_an_uninitialized_instance() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = install_root(&tmp);
        let presence = ScriptedPresence::affirming("ignored");

        let err = run_register_operator(
            &root,
            &presence,
            &RegisterOperatorRequest {
                identity: operator("morgan"),
                prompt: "Register this operator? ".to_string(),
            },
        )
        .expect_err("an instance with no trust root has no operators");
        assert_eq!(err.code, OperatorErrorCode::NotManaged);
        assert_eq!(presence.prompts(), 0);
    }

    #[test]
    fn operator_registration_refuses_a_duplicate_including_the_genesis_operator() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (root, _paths, _record) = genesis_instance(&tmp);

        let presence = ScriptedPresence::affirming("ignored");
        let err = run_register_operator(
            &root,
            &presence,
            &RegisterOperatorRequest {
                identity: operator("jordan"),
                prompt: "Register this operator? ".to_string(),
            },
        )
        .expect_err("the genesis operator is already an operator");
        assert_eq!(err.code, OperatorErrorCode::DuplicateOperator);
        assert_eq!(presence.prompts(), 0);

        // And a second registration of a newly added operator.
        run_register_operator(
            &root,
            &ScriptedPresence::affirming("ignored"),
            &RegisterOperatorRequest {
                identity: operator("morgan"),
                prompt: "Register this operator? ".to_string(),
            },
        )
        .expect("first registration");
        let err = run_register_operator(
            &root,
            &ScriptedPresence::affirming("ignored"),
            &RegisterOperatorRequest {
                identity: operator("morgan"),
                prompt: "Register this operator? ".to_string(),
            },
        )
        .expect_err("a duplicate must be refused");
        assert_eq!(err.code, OperatorErrorCode::DuplicateOperator);
    }

    #[test]
    fn operator_registration_refuses_an_identity_naming_a_registered_client() {
        // Creating an operator named after a requester subject is the
        // "grant that can expose or impersonate an operator backchannel
        // identity" case, and the host can fully discharge it here because the
        // client registry enumerates every external requester subject.
        let tmp = tempfile::tempdir().expect("tempdir");
        let (root, paths, record) = genesis_instance(&tmp);
        let key = key_for(&paths, &record);

        let issued = crate::client_registry::ClientRegistration::issue(
            &ClientGrant::full_v1(
                ClientLabel::new("claude-code").expect("label"),
                CredentialDelivery::IsolatedDescriptor,
                record.instance_id.clone(),
            ),
            TrustEpoch::GENESIS,
            1,
            record.digest(),
            PresenceClass::Terminal,
            &key,
        )
        .expect("issue");
        let registration_id = issued.registration.registration_id.clone();
        let mut clients = ClientRegistry::new();
        clients.insert(issued.registration).expect("insert");
        crate::client_registry::save_new(&paths, &clients, &key).expect("save clients");

        for colliding in [registration_id.as_str(), "claude-code"] {
            let presence = ScriptedPresence::affirming("ignored");
            let err = run_register_operator(
                &root,
                &presence,
                &RegisterOperatorRequest {
                    identity: operator(colliding),
                    prompt: "Register this operator? ".to_string(),
                },
            )
            .expect_err("an operator must not be named after a requester");
            assert_eq!(err.code, OperatorErrorCode::IdentityCollidesWithRequester);
            assert_eq!(presence.prompts(), 0);
        }
    }

    #[test]
    fn requester_subject_distinctness_is_case_insensitive() {
        // 'Jordan' and 'jordan' are the same principal for the
        // approver-is-the-requester check. A byte-exact comparison let the
        // capitalised form slip it.
        let subject = RequesterSubject::new("Jordan").expect("subject");
        assert!(
            subject.is(&operator("jordan")),
            "case must not distinguish a requester from an operator"
        );
        assert!(
            subject.is(&operator("JORDAN")),
            "an all-caps operator is still the same principal"
        );
        assert!(
            !subject.is(&operator("morgan")),
            "distinct names remain distinct"
        );
    }

    #[test]
    fn a_case_variant_of_the_requester_cannot_authenticate_as_operator() {
        // The distinctness check is re-applied at authentication under the fold,
        // so a requester 'Jordan' cannot use operator 'jordan'.
        let tmp = tempfile::tempdir().expect("tempdir");
        let (_root, _paths, record) = genesis_instance(&tmp);
        let operators = OperatorRegistry::new().with_genesis_operator(&record);
        let requester = RequesterContext::external(
            RequesterSubject::new("Jordan").expect("subject"),
            agent_domain(),
            Evidence::fully_isolated(),
        );
        let err = authenticate(
            &ScriptedPresence::affirming("jordan"),
            &operator("jordan"),
            &operators,
            record.trust_epoch,
            &requester,
        )
        .expect_err("a case variant of the requester is still the requester");
        assert_eq!(err.code, OperatorErrorCode::OperatorIsTheRequester);
    }

    #[test]
    fn an_operator_identity_that_case_collides_with_a_client_is_refused() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (_root, paths, record) = genesis_instance(&tmp);
        let key = key_for(&paths, &record);

        let issued = crate::client_registry::ClientRegistration::issue(
            &ClientGrant::full_v1(
                ClientLabel::new("claude-code").expect("label"),
                CredentialDelivery::IsolatedDescriptor,
                record.instance_id.clone(),
            ),
            TrustEpoch::GENESIS,
            1,
            record.digest(),
            PresenceClass::Terminal,
            &key,
        )
        .expect("issue");
        let mut clients = ClientRegistry::new();
        clients.insert(issued.registration).expect("insert");

        // The exact label and its case variants all collide.
        for candidate in ["claude-code", "Claude-Code", "CLAUDE-CODE"] {
            let err = refuse_requester_collision(&operator(candidate), &clients)
                .expect_err("an operator must not case-collide with a client label");
            assert_eq!(err.code, OperatorErrorCode::IdentityCollidesWithRequester);
        }
    }

    #[test]
    fn a_sealed_revocation_of_the_genesis_operator_is_honored() {
        // The genesis first operator must be revocable. A sealed Revoked record
        // for its identity outranks the Active genesis default, so
        // `with_genesis_operator` does not resurrect it.
        let tmp = tempfile::tempdir().expect("tempdir");
        let (_root, _paths, record) = genesis_instance(&tmp);
        let mut registry = OperatorRegistry::new();
        registry
            .insert(OperatorRecord {
                identity: operator("jordan"),
                origin: OperatorOrigin::Registered,
                trust_epoch: record.trust_epoch,
                created_at_unix_secs: 1,
                created_by_genesis_digest: record.digest(),
                ceremony_presence_class: PresenceClass::Terminal,
                status: OperatorStatus::Revoked,
            })
            .expect("insert");

        let view = registry.with_genesis_operator(&record);
        assert!(
            view.get(&operator("jordan")).is_some(),
            "the record is still present"
        );
        assert!(
            view.get_active(&operator("jordan")).is_none(),
            "a sealed revocation of the genesis operator is honored"
        );
        assert_eq!(view.active_count(), 0, "no operator remains active");
    }

    #[test]
    fn a_declined_registration_writes_no_operator() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (root, paths, record) = genesis_instance(&tmp);

        let err = run_register_operator(
            &root,
            &ScriptedPresence::failing(PresenceError::Declined),
            &RegisterOperatorRequest {
                identity: operator("morgan"),
                prompt: "Register this operator? ".to_string(),
            },
        )
        .expect_err("a declined ceremony registers nobody");
        assert_eq!(err.code, OperatorErrorCode::PresenceDeclined);

        assert!(!is_present(&paths), "nothing durable may have been written");
        let key = key_for(&paths, &record);
        assert_eq!(
            load_view(&paths, &record, &key)
                .expect("load")
                .active_count(),
            1
        );
    }
}
