//! The trust-genesis record and the three startup states it defines.
//!
//! The genesis record is the root of trust for every later operator, client,
//! target, and key change. It lives at a **fixed path under the data root**,
//! `<data_root>/control/genesis.record`, and it is the *managed-instance
//! marker*: the maintainer decided on
//! [issue #26](https://github.com/JordanTheJet/zeroclaw/issues/26) (item 20,
//! 2026-08-22) that the durable genesis record itself is the marker,
//! authenticated by the host key chain, and that a present-but-invalid record
//! enters recovery-only mode. There is no second marker file to keep in sync.
//!
//! ## The three states, and nothing else
//!
//! [`classify`] returns exactly one of:
//!
//! | State | Condition | Effect in this phase |
//! |---|---|---|
//! | [`InstanceTrustState::EligibleForFirstGenesis`] | No record at the fixed path | First genesis may run |
//! | [`InstanceTrustState::Managed`] | A record that parses and authenticates against these roots | First genesis refuses; the instance is initialized |
//! | [`InstanceTrustState::RecoveryOnly`] | A record is present but unreadable, unparseable, wrongly domained, unauthenticated, root-mismatched, symlinked, or its key source is unavailable | Genesis refuses **and** registration refuses |
//!
//! Recovery-only is a reportable, terminal state in phase 3. The recovery
//! ceremony that leaves it is explicitly out of scope: it requires a
//! deployment trust root or an OS user-presence authority, and binding the
//! prior genesis digest and audit-chain head, none of which exists yet.
//!
//! ## Why deleting files does not re-enable first genesis
//!
//! Deleting the configuration, the target registry, or the deployment key file
//! leaves the genesis record in place, so [`classify`] still refuses first
//! genesis. That is the whole anti-reset property: if unlinking a file
//! downgraded the instance to uninitialized, any process that can unlink in the
//! data root could then run genesis itself, register its own operator identity
//! and its own host key, and every later approval would be authentic under a
//! trust root the attacker created.
//!
//! ### The limitation, stated rather than papered over
//!
//! **Deleting the genesis record — in practice, wiping the whole data root —
//! does make the instance eligible for first genesis again.** That is a direct
//! consequence of the maintainer's choice to make the record its own marker,
//! and it was chosen knowingly. The design's own reasoning applies: a process
//! that can unlink inside the data root already has direct write access to the
//! ZeroClaw config and data roots, and such a process already holds authority
//! outside this protocol. The rule's job is to ensure that nothing *short* of
//! that resets the trust root. It is not, and does not claim to be, a defence
//! against an attacker who can already delete arbitrary files there. A marker
//! outside the data root, or an OS-attested one, would be needed for that, and
//! no such marker is decided.
//!
//! ## What the record is authenticated by
//!
//! An ADR-015 tag over the record's canonical encoding, under the key derived
//! from the deployment's single ADR-013 key-source authority at the record's
//! own trust epoch. Verification re-derives the key from the [`KeySource`] and
//! recomputes the tag; nothing about the record is trusted before that
//! succeeds. A missing or unreadable key source with a record present is
//! recovery-only, never first-genesis-eligible — the key's absence says
//! nothing about whether this root has ever been managed.
//!
//! ## The assurance class is recorded because it is not yet sufficient
//!
//! [`GenesisRecord::user_presence_class`] stores the assurance class of the
//! ceremony that authorized genesis. In v1 the only shipped adapter is a
//! terminal confirmation, whose class is [`PresenceClass::Terminal`], and the
//! trust-genesis design is explicit that **an ordinary terminal prompt does not
//! satisfy interactive genesis** in the final system. See
//! [`crate::ceremony`] for why it ships anyway and what that costs. The rule
//! that follows from recording it is written into
//! [`PresenceClass::permits_mutation_enablement`]: a future
//! mutation-enablement ceremony must re-attest under a high-assurance adapter
//! and must not inherit a terminal-class genesis.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroclaw_config::secrets::{KeySource, ProvisioningState};

use crate::keys::ApprovalAuditKey;
use crate::registry::{CanonicalRoots, GenesisDigest, InstanceId, TrustEpoch};
use crate::store::{
    CanonicalBytes, ControlPaths, StoreError, StoreErrorCode, absorb_path, absorb_str, absorb_u64,
    open_sealed, os_random_32, publish_new, read_state_file, seal, sealed_message,
};

/// Domain-separation label for the genesis record.
pub const GENESIS_RECORD_DOMAIN: &str = "zeroclaw/control-plane/genesis-record/v1";

/// The only genesis-record encoding this build understands.
pub const GENESIS_RECORD_FORMAT_VERSION: u32 = 1;

/// The fixed, public string the host-key commitment is a tag over.
///
/// ## Why committing to a constant is safe
///
/// The commitment is `HMAC(derived_key, KEY_COMMITMENT_STRING)`. The message is
/// public and fixed, so publishing the tag reveals nothing an attacker could
/// use: recovering the key from an HMAC output is exactly the forgery problem
/// HMAC-SHA256 is designed to resist, and a single known (message, tag) pair
/// gives no advantage over guessing the 256-bit key. Verification re-derives
/// the key and recomputes the tag, so no key bytes are stored or compared.
///
/// ## What it binds, and what it does not
///
/// The commitment binds the record to *the key derived from this deployment's
/// key-source content at this epoch*. ADR-015 accepts that rotating the master
/// key re-derives, and therefore rotates, the approval key — so a master
/// rotation changes the commitment and the record no longer matches. That is
/// epoch-transition territory: a planned rotation appends an epoch-transition
/// row authenticated under the old key, and this phase implements no epoch
/// transition at all. Until it does, a rotated master leaves the instance in
/// recovery-only mode, which is the correct fail-closed outcome rather than a
/// silent re-commitment.
pub const KEY_COMMITMENT_STRING: &str = "zeroclaw/control-plane/key-commitment/v1";

/// Upper bound on an operator identity label.
const MAX_OPERATOR_IDENTITY_LEN: usize = 128;

// ---------------------------------------------------------------------------
// Presence class
// ---------------------------------------------------------------------------

/// The assurance class of the user-presence ceremony that authorized genesis.
///
/// A production vocabulary with exactly one member in v1. There is deliberately
/// no test-only variant: a record written by any build states the class that
/// was actually attested, and a test adapter that wanted to claim a class it
/// did not achieve would have nowhere to put it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PresenceClass {
    /// Interactive confirmation on a real controlling terminal.
    ///
    /// The weakest class the design contemplates, and explicitly **not**
    /// sufficient for interactive genesis in the final system. See
    /// [`crate::ceremony`].
    Terminal,
}

impl PresenceClass {
    /// Every class this build defines, in a stable order.
    pub const ALL: &'static [Self] = &[Self::Terminal];

    /// The wire spelling.
    #[must_use]
    pub const fn wire(self) -> &'static str {
        match self {
            Self::Terminal => "terminal",
        }
    }

    /// Parse a wire spelling, refusing anything not in the vocabulary.
    #[must_use]
    pub fn from_wire(value: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|c| c.wire() == value)
    }

    /// Whether a ceremony of this class may enable mutations.
    ///
    /// Always `false` in v1, and that is the point. The genesis record stores
    /// the class precisely so a later mutation-enablement ceremony can refuse
    /// to inherit it: enablement requires genesis-equivalent, OS-mediated user
    /// presence, and a terminal prompt is not that. Whoever adds the first
    /// high-assurance adapter adds a variant here and returns `true` for it —
    /// they do not relax this function for [`Self::Terminal`].
    #[must_use]
    pub const fn permits_mutation_enablement(self) -> bool {
        match self {
            Self::Terminal => false,
        }
    }
}

impl std::fmt::Display for PresenceClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.wire())
    }
}

// ---------------------------------------------------------------------------
// First operator
// ---------------------------------------------------------------------------

/// The first operator identity a genesis ceremony establishes.
///
/// ## Honest scope
///
/// The design calls for a *first operator public identity*. There is no
/// operator key infrastructure in this phase — the operator backchannel and
/// the approval-receipt broker are phase 4 — so what a terminal ceremony can
/// attest is a label the present human supplied, not a public key. This type
/// is that label: an opaque, non-secret, bounded string, recorded for
/// attribution and for a later ceremony to match against.
///
/// It confers no authority. Nothing in this phase consumes it as an
/// authorization input, because nothing in this phase authorizes a mutation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct FirstOperatorIdentity(String);

impl FirstOperatorIdentity {
    /// Validate and wrap an operator identity label.
    ///
    /// # Errors
    ///
    /// Returns [`StoreErrorCode::Decode`] when the value is empty after
    /// trimming, longer than 128 bytes, or contains a control character. A
    /// control character in an identity that later reaches a terminal or a log
    /// line is an injection surface, so it is refused at the boundary.
    pub fn new(value: impl Into<String>) -> Result<Self, StoreError> {
        let value = value.into().trim().to_string();
        if value.is_empty() {
            return Err(StoreError::new(
                StoreErrorCode::Decode,
                "first operator identity is empty",
            ));
        }
        if value.len() > MAX_OPERATOR_IDENTITY_LEN {
            return Err(StoreError::new(
                StoreErrorCode::Decode,
                format!(
                    "first operator identity is {} bytes; the limit is {MAX_OPERATOR_IDENTITY_LEN}",
                    value.len()
                ),
            ));
        }
        if value.chars().any(char::is_control) {
            return Err(StoreError::new(
                StoreErrorCode::Decode,
                "first operator identity contains a control character",
            ));
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for FirstOperatorIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for FirstOperatorIdentity {
    type Error = StoreError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<FirstOperatorIdentity> for String {
    fn from(value: FirstOperatorIdentity) -> Self {
        value.0
    }
}

// ---------------------------------------------------------------------------
// Host key commitment
// ---------------------------------------------------------------------------

/// A commitment to the derived approval and audit key.
///
/// Holds a tag, not key material. See [`KEY_COMMITMENT_STRING`] for why
/// publishing it is safe and what it binds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeyCommitment([u8; 32]);

impl KeyCommitment {
    /// Compute the commitment for `key`.
    #[must_use]
    pub fn compute(key: &ApprovalAuditKey) -> Self {
        Self(*key.sign(KEY_COMMITMENT_STRING.as_bytes()).as_bytes())
    }

    /// Whether `key` is the key this commitment was made to.
    ///
    /// Re-derives nothing itself: the caller supplies the key derived from the
    /// [`KeySource`], and this recomputes the tag over the public constant and
    /// compares in constant time through [`ApprovalAuditKey::verify`].
    #[must_use]
    pub fn matches(&self, key: &ApprovalAuditKey) -> bool {
        key.verify(
            KEY_COMMITMENT_STRING.as_bytes(),
            &crate::keys::Tag::from_bytes(self.0),
        )
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parse a 64-character hex commitment.
    ///
    /// # Errors
    ///
    /// Returns [`StoreErrorCode::Decode`] when the input is not exactly 32
    /// hex-encoded bytes.
    pub fn from_hex(value: &str) -> Result<Self, StoreError> {
        let mut bytes = [0u8; 32];
        hex::decode_to_slice(value, &mut bytes).map_err(|e| {
            StoreError::new(StoreErrorCode::Decode, format!("host key commitment: {e}"))
        })?;
        Ok(Self(bytes))
    }
}

impl std::fmt::Display for KeyCommitment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl Serialize for KeyCommitment {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for KeyCommitment {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(d)?;
        Self::from_hex(&raw).map_err(serde::de::Error::custom)
    }
}

// ---------------------------------------------------------------------------
// The record
// ---------------------------------------------------------------------------

/// The immutable root of trust for one instance.
///
/// Written once, by the genesis ceremony, and never rewritten by any code path
/// in this crate: the only writer is [`write_record`], which publishes through
/// an exclusive create and refuses a path that already exists.
///
/// The record's **format version** is carried by the sealed envelope
/// ([`CanonicalBytes::FORMAT_VERSION`]) rather than duplicated in this struct.
/// It is authenticated exactly like every other field, because the envelope
/// binds it into the tag; storing it twice would be two sources of truth for
/// one fact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenesisRecord {
    /// Stable, random instance identifier. Everything else in the control
    /// plane is keyed by it.
    pub instance_id: InstanceId,
    /// The initial epoch. Genesis establishes [`TrustEpoch::GENESIS`].
    pub trust_epoch: TrustEpoch,
    /// The canonical config and data roots, as canonicalized at genesis.
    pub canonical_roots: CanonicalRoots,
    /// Wall-clock creation time, seconds since the Unix epoch.
    pub created_at_unix_secs: u64,
    /// The assurance class of the ceremony that authorized this genesis.
    pub user_presence_class: PresenceClass,
    /// The first operator identity established by that ceremony.
    pub first_operator: FirstOperatorIdentity,
    /// Commitment to the derived approval and audit key.
    pub host_key_commitment: KeyCommitment,
}

impl CanonicalBytes for GenesisRecord {
    const DOMAIN: &'static str = GENESIS_RECORD_DOMAIN;
    const FORMAT_VERSION: u32 = GENESIS_RECORD_FORMAT_VERSION;

    fn absorb_canonical(&self, out: &mut Vec<u8>) {
        // Exhaustive destructure, no `..`: adding a field must not compile
        // until it is absorbed here, because an unabsorbed field is an
        // unauthenticated field.
        let Self {
            instance_id,
            trust_epoch,
            canonical_roots,
            created_at_unix_secs,
            user_presence_class,
            first_operator,
            host_key_commitment,
        } = self;
        absorb_str(out, instance_id.as_str());
        absorb_u64(out, trust_epoch.get());
        absorb_path(out, &canonical_roots.config_root);
        absorb_path(out, &canonical_roots.data_root);
        absorb_u64(out, *created_at_unix_secs);
        absorb_str(out, user_presence_class.wire());
        absorb_str(out, first_operator.as_str());
        crate::store::absorb_field(out, host_key_commitment.as_bytes());
    }
}

impl GenesisRecord {
    /// The digest of this record, as the instance fingerprint and any later
    /// recovery manifest reference it.
    ///
    /// Computed over the same canonical encoding the authentication tag covers,
    /// so a record whose digest matches is a record whose tag was computed over
    /// identical bytes.
    #[must_use]
    pub fn digest(&self) -> GenesisDigest {
        let mut hasher = Sha256::new();
        hasher.update(sealed_message(self));
        GenesisDigest::from_bytes(hasher.finalize().into())
    }
}

/// Generate a fresh, random instance identifier.
///
/// Random rather than derived from the roots: two installs that happen to share
/// a path (a restored backup, a container image) must not share an instance
/// identity, because every audit chain and credential is keyed by it.
///
/// # Errors
///
/// Propagates a failure of the operating system random source rather than
/// falling back to a weaker generator.
pub fn generate_instance_id() -> Result<InstanceId, StoreError> {
    let bytes = os_random_32()?;
    InstanceId::new(format!("inst-{}", hex::encode(&bytes[..16])))
        .map_err(|e| StoreError::new(StoreErrorCode::Encode, e.detail))
}

/// Seconds since the Unix epoch.
///
/// # Errors
///
/// Returns [`StoreErrorCode::Io`] when the host clock is before the Unix epoch.
/// The journal design treats an implausible clock as a real condition; a
/// genesis record with a fabricated timestamp is worse than a refusal.
pub fn now_unix_secs() -> Result<u64, StoreError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| {
            StoreError::new(
                StoreErrorCode::Io,
                format!("host clock is before the Unix epoch: {e}"),
            )
        })
}

/// Write the genesis record at its fixed path.
///
/// Publishes through an exclusive create, so a record that already exists is
/// [`StoreErrorCode::AlreadyPresent`] rather than an overwrite, and two
/// concurrent ceremonies resolve to exactly one winner.
///
/// # Errors
///
/// Propagates encoding and publication failures.
pub fn write_record(
    paths: &ControlPaths,
    record: &GenesisRecord,
    key: &ApprovalAuditKey,
) -> Result<GenesisDigest, StoreError> {
    let bytes = seal(record, key)?;
    publish_new(&paths.genesis_record(), &bytes)?;
    Ok(record.digest())
}

// ---------------------------------------------------------------------------
// Classification
// ---------------------------------------------------------------------------

/// Why an instance is in recovery-only mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryReason {
    /// The record is present but could not be read.
    RecordUnreadable,
    /// The record's path is a symlink.
    RecordPathIsSymlink,
    /// The record could not be parsed.
    RecordUnparseable,
    /// The record carries another artefact's domain label.
    RecordWrongDomain,
    /// The record's format version is not one this build understands.
    RecordFormatVersionUnsupported,
    /// The record's authentication tag did not verify.
    RecordAuthenticationFailed,
    /// The record's committed key does not match the derived key.
    HostKeyCommitmentMismatch,
    /// The record's canonical roots are not the roots being classified.
    CanonicalRootMismatch,
    /// The deployment key source is missing, uninitialized, or unusable, so
    /// the record cannot be authenticated at all.
    KeySourceUnavailable,
}

impl RecoveryReason {
    /// A stable, non-secret wire spelling for reporting.
    #[must_use]
    pub const fn wire(self) -> &'static str {
        match self {
            Self::RecordUnreadable => "record_unreadable",
            Self::RecordPathIsSymlink => "record_path_is_symlink",
            Self::RecordUnparseable => "record_unparseable",
            Self::RecordWrongDomain => "record_wrong_domain",
            Self::RecordFormatVersionUnsupported => "record_format_version_unsupported",
            Self::RecordAuthenticationFailed => "record_authentication_failed",
            Self::HostKeyCommitmentMismatch => "host_key_commitment_mismatch",
            Self::CanonicalRootMismatch => "canonical_root_mismatch",
            Self::KeySourceUnavailable => "key_source_unavailable",
        }
    }
}

impl std::fmt::Display for RecoveryReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.wire())
    }
}

/// What startup concluded about this instance root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstanceTrustState {
    /// No genesis record exists at the fixed path. First genesis may run.
    EligibleForFirstGenesis,
    /// A genesis record exists, parses, authenticates, and names these roots.
    Managed(Box<GenesisRecord>),
    /// A genesis record is present but did not verify. Genesis refuses,
    /// registration refuses, and only the recovery ceremony — which this phase
    /// does not implement — could leave this state.
    RecoveryOnly {
        reason: RecoveryReason,
        detail: String,
    },
}

impl InstanceTrustState {
    /// Whether first genesis may run against this root.
    ///
    /// The single predicate the ceremony consults. Fail-closed by
    /// construction: only the one state that means "never managed" is
    /// eligible, so a state added later is ineligible until it is listed here.
    #[must_use]
    pub const fn is_eligible_for_first_genesis(&self) -> bool {
        matches!(self, Self::EligibleForFirstGenesis)
    }

    /// Whether this root is a managed instance with a verified trust root.
    #[must_use]
    pub const fn is_managed(&self) -> bool {
        matches!(self, Self::Managed(_))
    }

    /// Whether registration-dependent and registry-dependent operations must
    /// refuse.
    #[must_use]
    pub const fn is_recovery_only(&self) -> bool {
        matches!(self, Self::RecoveryOnly { .. })
    }

    /// The verified record, if this root is managed.
    #[must_use]
    pub fn record(&self) -> Option<&GenesisRecord> {
        match self {
            Self::Managed(record) => Some(record),
            Self::EligibleForFirstGenesis | Self::RecoveryOnly { .. } => None,
        }
    }

    /// A stable, non-secret summary for an operator-facing report.
    #[must_use]
    pub fn wire(&self) -> &'static str {
        match self {
            Self::EligibleForFirstGenesis => "eligible_for_first_genesis",
            Self::Managed(_) => "managed",
            Self::RecoveryOnly { .. } => "recovery_only",
        }
    }
}

/// Classify one instance root.
///
/// Never mutates anything: the key source is **probed** with
/// [`KeySource::provisioning_state`] before any attempt to read it, because a
/// file-backed source creates its key material on first read and a
/// classification must not manufacture a master key as a side effect of
/// answering a question. ADR-013 states the rule directly — a provisioning
/// probe must not unexpectedly execute a helper, contact a network service,
/// prompt a user, or unlock a keychain, and genesis probes before it prompts.
#[must_use]
pub fn classify(paths: &ControlPaths, key_source: &dyn KeySource) -> InstanceTrustState {
    let record_path = paths.genesis_record();

    // Presence first. Absence is the *only* road to first genesis.
    match std::fs::symlink_metadata(&record_path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return InstanceTrustState::EligibleForFirstGenesis;
        }
        Err(e) => {
            // Present-but-unreadable, or a parent we cannot stat through. Fail
            // closed: an instance we cannot inspect is not an instance we may
            // re-initialize.
            return recovery(RecoveryReason::RecordUnreadable, format!("{e}"));
        }
        Ok(_) => {}
    }

    let raw = match read_state_file(&record_path) {
        Ok(bytes) => bytes,
        Err(e) if e.code == StoreErrorCode::PathIsSymlink => {
            return recovery(RecoveryReason::RecordPathIsSymlink, e.detail);
        }
        Err(e) => return recovery(RecoveryReason::RecordUnreadable, e.detail),
    };

    // A record is present, so from here every failure is recovery-only.
    match key_source.provisioning_state() {
        ProvisioningState::Initialized | ProvisioningState::ExternallyProvisioned => {}
        ProvisioningState::NeedsInitialization => {
            return recovery(
                RecoveryReason::KeySourceUnavailable,
                format!(
                    "the '{}' key source has no material; a managed instance cannot \
                     re-initialize one",
                    key_source.backend_name()
                ),
            );
        }
    }

    // The declared epoch is inside the authenticated encoding, so deriving at
    // the declared value is safe: a forged epoch produces a key that cannot
    // reproduce the tag.
    let declared_epoch = match declared_trust_epoch(&raw) {
        Ok(epoch) => epoch,
        Err(detail) => return recovery(RecoveryReason::RecordUnparseable, detail),
    };

    let key = match ApprovalAuditKey::derive(key_source, declared_epoch) {
        Ok(key) => key,
        Err(e) => return recovery(RecoveryReason::KeySourceUnavailable, format!("{e:#}")),
    };

    let record: GenesisRecord = match open_sealed(&raw, &key) {
        Ok(record) => record,
        Err(e) => {
            let reason = match e.code {
                StoreErrorCode::DomainMismatch => RecoveryReason::RecordWrongDomain,
                StoreErrorCode::FormatVersionUnsupported => {
                    RecoveryReason::RecordFormatVersionUnsupported
                }
                StoreErrorCode::AuthenticationFailed => RecoveryReason::RecordAuthenticationFailed,
                _ => RecoveryReason::RecordUnparseable,
            };
            return recovery(reason, e.detail);
        }
    };

    // The tag proves the record was written by a holder of this deployment's
    // key. The commitment proves the *same* key is the one the record names,
    // which is what a later epoch transition needs in order to prove
    // continuity.
    if !record.host_key_commitment.matches(&key) {
        return recovery(
            RecoveryReason::HostKeyCommitmentMismatch,
            "the record commits to a different approval and audit key".to_string(),
        );
    }

    // A record authenticated for one pair of roots must not authorize another.
    let roots = match paths.canonical_roots() {
        Ok(roots) => roots,
        Err(e) => return recovery(RecoveryReason::CanonicalRootMismatch, e.detail),
    };
    if record.canonical_roots != roots {
        return recovery(
            RecoveryReason::CanonicalRootMismatch,
            format!(
                "the record names {} and {}",
                record.canonical_roots.config_root.display(),
                record.canonical_roots.data_root.display()
            ),
        );
    }

    InstanceTrustState::Managed(Box::new(record))
}

fn recovery(reason: RecoveryReason, detail: String) -> InstanceTrustState {
    InstanceTrustState::RecoveryOnly { reason, detail }
}

/// Read the epoch a sealed record declares, before anything about it is
/// trusted.
///
/// Used only to choose the derivation epoch; the value is re-read from the
/// authenticated payload afterwards.
fn declared_trust_epoch(raw: &[u8]) -> Result<TrustEpoch, String> {
    let value: serde_json::Value =
        serde_json::from_slice(raw).map_err(|e| format!("genesis record: {e}"))?;
    value
        .get("payload")
        .and_then(|p| p.get("trust_epoch"))
        .and_then(serde_json::Value::as_u64)
        .map(TrustEpoch::new)
        .ok_or_else(|| "genesis record declares no trust epoch".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::ControlPaths;
    use std::path::{Path, PathBuf};
    use zeroclaw_config::secrets::FileKeySource;

    /// A key source that is present and usable.
    #[derive(Debug)]
    struct FixedKeySource([u8; 32]);

    impl KeySource for FixedKeySource {
        fn with_key(
            &self,
            f: &mut dyn FnMut(&[u8; 32]) -> anyhow::Result<()>,
        ) -> anyhow::Result<()> {
            f(&self.0)
        }
        fn backend_name(&self) -> &'static str {
            "test-fixed"
        }
        fn provisioning_state(&self) -> ProvisioningState {
            ProvisioningState::Initialized
        }
    }

    /// A key source whose material is gone.
    #[derive(Debug)]
    struct MissingKeySource;

    impl KeySource for MissingKeySource {
        fn with_key(
            &self,
            _f: &mut dyn FnMut(&[u8; 32]) -> anyhow::Result<()>,
        ) -> anyhow::Result<()> {
            anyhow::bail!("no key material")
        }
        fn backend_name(&self) -> &'static str {
            "test-missing"
        }
        fn provisioning_state(&self) -> ProvisioningState {
            ProvisioningState::NeedsInitialization
        }
    }

    fn key(byte: u8) -> ApprovalAuditKey {
        ApprovalAuditKey::derive(&FixedKeySource([byte; 32]), TrustEpoch::GENESIS)
            .expect("derive test key")
    }

    fn install_root(tmp: &tempfile::TempDir) -> PathBuf {
        let root = tmp.path().join("install");
        std::fs::create_dir_all(root.join("data")).expect("create install root");
        root
    }

    fn record_for(paths: &ControlPaths) -> GenesisRecord {
        GenesisRecord {
            instance_id: InstanceId::new("inst-test").expect("instance id"),
            trust_epoch: TrustEpoch::GENESIS,
            canonical_roots: paths.canonical_roots().expect("roots"),
            created_at_unix_secs: 1_755_000_000,
            user_presence_class: PresenceClass::Terminal,
            first_operator: FirstOperatorIdentity::new("operator@example").expect("identity"),
            host_key_commitment: KeyCommitment::compute(&key(0x11)),
        }
    }

    fn established(tmp: &tempfile::TempDir) -> (ControlPaths, GenesisRecord) {
        let paths = ControlPaths::resolve(&install_root(tmp)).expect("resolve");
        let record = record_for(&paths);
        write_record(&paths, &record, &key(0x11)).expect("write record");
        (paths, record)
    }

    /// Rewrite the sealed record with `mutate` applied to its JSON.
    fn rewrite_record(paths: &ControlPaths, mutate: impl FnOnce(&mut serde_json::Value)) {
        let raw = std::fs::read(paths.genesis_record()).expect("read record");
        let mut value: serde_json::Value = serde_json::from_slice(&raw).expect("parse");
        mutate(&mut value);
        std::fs::write(
            paths.genesis_record(),
            serde_json::to_vec(&value).expect("encode"),
        )
        .expect("rewrite record");
    }

    // -- presence class -----------------------------------------------------

    #[test]
    fn the_presence_vocabulary_has_no_test_variant() {
        // Exhaustive match: a variant added later must be classified here
        // rather than defaulting into the accepted set.
        for class in PresenceClass::ALL {
            match class {
                PresenceClass::Terminal => {}
            }
        }
        assert_eq!(PresenceClass::ALL.len(), 1);
        assert_eq!(
            PresenceClass::from_wire("terminal"),
            Some(PresenceClass::Terminal)
        );
        for absent in ["test_only", "fixture", "os_user_presence", ""] {
            assert!(
                PresenceClass::from_wire(absent).is_none(),
                "{absent:?} must not name a presence class"
            );
        }
    }

    #[test]
    fn a_terminal_ceremony_does_not_permit_mutation_enablement() {
        // The rule this phase writes down so a later phase cannot inherit it
        // by accident.
        assert!(!PresenceClass::Terminal.permits_mutation_enablement());
        assert!(
            PresenceClass::ALL
                .iter()
                .all(|c| !c.permits_mutation_enablement()),
            "no adapter shipped in this phase may enable mutations"
        );
    }

    // -- operator identity --------------------------------------------------

    #[test]
    fn an_operator_identity_is_bounded_and_free_of_control_characters() {
        assert!(FirstOperatorIdentity::new("  jordan  ").is_ok());
        assert_eq!(
            FirstOperatorIdentity::new("  jordan  ")
                .expect("identity")
                .as_str(),
            "jordan"
        );
        for bad in ["", "   ", "a\nb", "a\u{7}b"] {
            assert!(
                FirstOperatorIdentity::new(bad).is_err(),
                "{bad:?} must be refused"
            );
        }
        assert!(FirstOperatorIdentity::new("a".repeat(MAX_OPERATOR_IDENTITY_LEN)).is_ok());
        assert!(FirstOperatorIdentity::new("a".repeat(MAX_OPERATOR_IDENTITY_LEN + 1)).is_err());
    }

    // -- key commitment -----------------------------------------------------

    #[test]
    fn the_commitment_matches_only_the_key_it_was_made_to() {
        let mine = key(0x11);
        let theirs = key(0x22);
        let commitment = KeyCommitment::compute(&mine);
        assert!(commitment.matches(&mine));
        assert!(
            !commitment.matches(&theirs),
            "a commitment must not match another deployment's key"
        );
    }

    #[test]
    fn the_commitment_changes_when_the_master_key_rotates() {
        // ADR-015 accepts that rotating the master re-derives the approval
        // key. Pin the observable consequence rather than assuming it.
        assert_ne!(
            KeyCommitment::compute(&key(0x01)),
            KeyCommitment::compute(&key(0x02))
        );
    }

    #[test]
    fn the_commitment_reveals_no_key_bytes() {
        let k = key(0x11);
        let commitment = KeyCommitment::compute(&k);
        let hex = commitment.to_hex();
        assert_eq!(hex.len(), 64);
        // The commitment is a tag over a public constant; the constant itself
        // must be what is committed to, not any key-derived string.
        assert!(!hex.contains(KEY_COMMITMENT_STRING));
        assert_ne!(
            commitment.as_bytes(),
            &[0u8; 32],
            "an all-zero commitment would mean the key never reached the MAC"
        );
    }

    #[test]
    fn the_commitment_round_trips_through_hex() {
        let commitment = KeyCommitment::compute(&key(0x11));
        assert_eq!(
            KeyCommitment::from_hex(&commitment.to_hex()).expect("parse"),
            commitment
        );
        for bad in ["", "zz", &"aa".repeat(31), &"aa".repeat(33)] {
            assert!(
                KeyCommitment::from_hex(bad).is_err(),
                "{bad:?} must not parse"
            );
        }
    }

    // -- the record ---------------------------------------------------------

    #[test]
    fn the_canonical_encoding_binds_every_field() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let paths = ControlPaths::resolve(&install_root(&tmp)).expect("resolve");
        let base = record_for(&paths);
        let baseline = sealed_message(&base);

        let mut other_instance = base.clone();
        other_instance.instance_id = InstanceId::new("inst-other").expect("id");
        let mut other_epoch = base.clone();
        other_epoch.trust_epoch = TrustEpoch::new(2);
        let mut other_roots = base.clone();
        other_roots.canonical_roots = CanonicalRoots::new(
            PathBuf::from("/srv/other"),
            PathBuf::from("/srv/other/data"),
        )
        .expect("roots");
        let mut other_time = base.clone();
        other_time.created_at_unix_secs += 1;
        let mut other_operator = base.clone();
        other_operator.first_operator = FirstOperatorIdentity::new("someone-else").expect("id");
        let mut other_commitment = base.clone();
        other_commitment.host_key_commitment = KeyCommitment::compute(&key(0x22));

        for (name, variant) in [
            ("instance id", other_instance),
            ("trust epoch", other_epoch),
            ("canonical roots", other_roots),
            ("created at", other_time),
            ("first operator", other_operator),
            ("host key commitment", other_commitment),
        ] {
            assert_ne!(
                baseline,
                sealed_message(&variant),
                "the tag must bind the {name}"
            );
        }
        // `user_presence_class` has one variant in v1, so it cannot be varied
        // here; the encoder absorbs it and the exhaustive destructure in
        // `absorb_canonical` is what keeps it that way.
        assert!(
            sealed_message(&base)
                .windows(PresenceClass::Terminal.wire().len())
                .any(|w| w == PresenceClass::Terminal.wire().as_bytes()),
            "the presence class must appear in the authenticated encoding"
        );
    }

    #[test]
    fn the_digest_is_stable_and_field_sensitive() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let paths = ControlPaths::resolve(&install_root(&tmp)).expect("resolve");
        let record = record_for(&paths);
        assert_eq!(record.digest(), record.digest());

        let mut other = record.clone();
        other.created_at_unix_secs += 1;
        assert_ne!(record.digest(), other.digest());
    }

    #[test]
    fn a_generated_instance_id_is_random_and_path_safe() {
        let a = generate_instance_id().expect("id");
        let b = generate_instance_id().expect("id");
        assert_ne!(a, b);
        assert!(a.as_str().starts_with("inst-"));
        assert!(
            !a.as_str().contains('/') && !a.as_str().contains(".."),
            "an instance id is spliced into paths by other components"
        );
    }

    // -- classification: the three states -----------------------------------

    #[test]
    fn a_root_with_no_record_is_eligible_for_first_genesis() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let paths = ControlPaths::resolve(&install_root(&tmp)).expect("resolve");
        let state = classify(&paths, &FixedKeySource([0x11; 32]));
        assert!(state.is_eligible_for_first_genesis());
        assert_eq!(state.wire(), "eligible_for_first_genesis");
        assert!(state.record().is_none());
    }

    #[test]
    fn a_valid_record_makes_the_instance_managed() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (paths, record) = established(&tmp);
        let state = classify(&paths, &FixedKeySource([0x11; 32]));
        assert!(state.is_managed(), "got {state:?}");
        assert!(!state.is_eligible_for_first_genesis());
        assert_eq!(state.record(), Some(&record));
    }

    #[test]
    fn a_tampered_record_enters_recovery_only() {
        // Guarded by mutation check: skipping the authentication-tag
        // verification in `open_sealed` must make this test fail.
        let tmp = tempfile::tempdir().expect("tempdir");
        let (paths, _) = established(&tmp);
        rewrite_record(&paths, |value| {
            value["payload"]["first_operator"] = serde_json::Value::String("attacker".to_string());
        });

        let state = classify(&paths, &FixedKeySource([0x11; 32]));
        assert!(state.is_recovery_only(), "got {state:?}");
        assert!(!state.is_eligible_for_first_genesis());
        match state {
            InstanceTrustState::RecoveryOnly { reason, .. } => {
                assert_eq!(reason, RecoveryReason::RecordAuthenticationFailed);
            }
            other => panic!("expected recovery-only, got {other:?}"),
        }
    }

    #[test]
    fn an_unparseable_record_enters_recovery_only() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (paths, _) = established(&tmp);
        std::fs::write(paths.genesis_record(), b"{ not json").expect("corrupt");
        let state = classify(&paths, &FixedKeySource([0x11; 32]));
        match state {
            InstanceTrustState::RecoveryOnly { reason, .. } => {
                assert_eq!(reason, RecoveryReason::RecordUnparseable);
            }
            other => panic!("expected recovery-only, got {other:?}"),
        }
    }

    #[test]
    fn an_empty_record_enters_recovery_only() {
        // The state a crash between reservation and publication leaves.
        let tmp = tempfile::tempdir().expect("tempdir");
        let (paths, _) = established(&tmp);
        std::fs::write(paths.genesis_record(), b"").expect("truncate");
        assert!(classify(&paths, &FixedKeySource([0x11; 32])).is_recovery_only());
    }

    #[test]
    fn a_record_sealed_under_another_key_enters_recovery_only() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (paths, _) = established(&tmp);
        let state = classify(&paths, &FixedKeySource([0x99; 32]));
        match state {
            InstanceTrustState::RecoveryOnly { reason, .. } => {
                assert_eq!(reason, RecoveryReason::RecordAuthenticationFailed);
            }
            other => panic!("expected recovery-only, got {other:?}"),
        }
    }

    #[test]
    fn a_record_with_an_unsupported_format_version_enters_recovery_only() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (paths, _) = established(&tmp);
        rewrite_record(&paths, |value| {
            value["format_version"] = serde_json::Value::from(99u32);
        });
        match classify(&paths, &FixedKeySource([0x11; 32])) {
            InstanceTrustState::RecoveryOnly { reason, .. } => {
                assert_eq!(reason, RecoveryReason::RecordFormatVersionUnsupported);
            }
            other => panic!("expected recovery-only, got {other:?}"),
        }
    }

    #[test]
    fn a_record_naming_other_roots_enters_recovery_only() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let paths = ControlPaths::resolve(&install_root(&tmp)).expect("resolve");
        let mut record = record_for(&paths);
        record.canonical_roots = CanonicalRoots::new(
            PathBuf::from("/srv/elsewhere"),
            PathBuf::from("/srv/elsewhere/data"),
        )
        .expect("roots");
        write_record(&paths, &record, &key(0x11)).expect("write");

        match classify(&paths, &FixedKeySource([0x11; 32])) {
            InstanceTrustState::RecoveryOnly { reason, .. } => {
                assert_eq!(reason, RecoveryReason::CanonicalRootMismatch);
            }
            other => panic!("expected recovery-only, got {other:?}"),
        }
    }

    #[test]
    fn a_record_committing_to_another_key_enters_recovery_only() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let paths = ControlPaths::resolve(&install_root(&tmp)).expect("resolve");
        let mut record = record_for(&paths);
        record.host_key_commitment = KeyCommitment::compute(&key(0x22));
        // Sealed under the real key, so the tag verifies; only the commitment
        // is wrong.
        write_record(&paths, &record, &key(0x11)).expect("write");

        match classify(&paths, &FixedKeySource([0x11; 32])) {
            InstanceTrustState::RecoveryOnly { reason, .. } => {
                assert_eq!(reason, RecoveryReason::HostKeyCommitmentMismatch);
            }
            other => panic!("expected recovery-only, got {other:?}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_record_path_enters_recovery_only() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let paths = ControlPaths::resolve(&install_root(&tmp)).expect("resolve");
        let record = record_for(&paths);
        let elsewhere = tmp.path().join("elsewhere.record");
        std::fs::write(&elsewhere, seal(&record, &key(0x11)).expect("seal")).expect("write");
        std::fs::create_dir_all(paths.control_dir()).expect("mkdir");
        std::os::unix::fs::symlink(&elsewhere, paths.genesis_record()).expect("symlink");

        match classify(&paths, &FixedKeySource([0x11; 32])) {
            InstanceTrustState::RecoveryOnly { reason, .. } => {
                assert_eq!(reason, RecoveryReason::RecordPathIsSymlink);
            }
            other => panic!("expected recovery-only, got {other:?}"),
        }
    }

    #[test]
    fn a_missing_key_source_with_a_record_present_is_recovery_only_not_eligible() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (paths, _) = established(&tmp);
        let state = classify(&paths, &MissingKeySource);
        assert!(!state.is_eligible_for_first_genesis());
        match state {
            InstanceTrustState::RecoveryOnly { reason, .. } => {
                assert_eq!(reason, RecoveryReason::KeySourceUnavailable);
            }
            other => panic!("expected recovery-only, got {other:?}"),
        }
    }

    #[test]
    fn classification_never_creates_key_material() {
        // A file-backed key source creates its key on first read. Classifying
        // a root with a record present must not be the thing that creates it.
        let tmp = tempfile::tempdir().expect("tempdir");
        let (paths, _) = established(&tmp);
        let key_file = paths.deployment_key_file();
        assert!(!key_file.exists(), "precondition: no key file yet");

        let state = classify(&paths, &FileKeySource::new(key_file.clone()));
        assert!(state.is_recovery_only(), "got {state:?}");
        assert!(
            !key_file.exists(),
            "classification must not manufacture a master key"
        );
    }

    // -- the anti-reset matrix ---------------------------------------------

    #[test]
    fn deleting_the_config_the_registry_or_the_key_file_never_re_enables_first_genesis() {
        // Guarded by mutation check: making first genesis eligible despite an
        // existing record must make this test fail.
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = install_root(&tmp);
        std::fs::write(root.join("config.toml"), b"# config").expect("write config");
        let paths = ControlPaths::resolve(&root).expect("resolve");
        let record = record_for(&paths);
        write_record(&paths, &record, &key(0x11)).expect("write record");
        std::fs::write(paths.target_registry(), b"{}").expect("write registry");
        std::fs::write(paths.deployment_key_file(), b"unused-by-the-fixed-source")
            .expect("write key file");

        let source = FixedKeySource([0x11; 32]);
        assert!(classify(&paths, &source).is_managed());

        // Delete the configuration.
        std::fs::remove_file(root.join("config.toml")).expect("remove config");
        assert!(
            classify(&paths, &source).is_managed(),
            "deleting config.toml must not un-manage the instance"
        );

        // Delete the target registry.
        std::fs::remove_file(paths.target_registry()).expect("remove registry");
        assert!(
            classify(&paths, &source).is_managed(),
            "deleting the registry must not un-manage the instance"
        );

        // Delete the deployment key file. The record can no longer be
        // authenticated, so this is recovery-only — which is still not
        // eligible for first genesis.
        std::fs::remove_file(paths.deployment_key_file()).expect("remove key file");
        let without_key = classify(&paths, &MissingKeySource);
        assert!(
            !without_key.is_eligible_for_first_genesis(),
            "deleting the key file must not re-enable first genesis"
        );
        assert!(without_key.is_recovery_only());
    }

    #[test]
    fn deleting_the_genesis_record_does_re_enable_first_genesis_by_design() {
        // The documented limitation of genesis-record-as-marker. Pinned as a
        // test so the tradeoff stays visible rather than becoming folklore: a
        // process that can unlink inside the data root already holds authority
        // outside this protocol.
        let tmp = tempfile::tempdir().expect("tempdir");
        let (paths, _) = established(&tmp);
        let source = FixedKeySource([0x11; 32]);
        assert!(classify(&paths, &source).is_managed());

        std::fs::remove_file(paths.genesis_record()).expect("remove record");
        assert!(
            classify(&paths, &source).is_eligible_for_first_genesis(),
            "the maintainer chose the record as its own marker knowing a data-root \
             wipe resets it"
        );
    }

    // -- the record is written once ----------------------------------------

    #[test]
    fn the_record_is_never_rewritten() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (paths, record) = established(&tmp);
        let before = std::fs::read(paths.genesis_record()).expect("read");

        let mut replacement = record.clone();
        replacement.first_operator = FirstOperatorIdentity::new("attacker").expect("id");
        let err = write_record(&paths, &replacement, &key(0x11))
            .expect_err("a second genesis record must be refused");
        assert_eq!(err.code, StoreErrorCode::AlreadyPresent);

        assert_eq!(
            std::fs::read(paths.genesis_record()).expect("read"),
            before,
            "the original record must be byte-identical after a refused rewrite"
        );
    }

    #[test]
    fn a_written_record_reads_back_identically() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (paths, record) = established(&tmp);
        let digest = record.digest();
        match classify(&paths, &FixedKeySource([0x11; 32])) {
            InstanceTrustState::Managed(read_back) => {
                assert_eq!(*read_back, record);
                assert_eq!(read_back.digest(), digest);
            }
            other => panic!("expected managed, got {other:?}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn the_record_is_owner_only_on_disk() {
        use std::os::unix::fs::PermissionsExt as _;
        let tmp = tempfile::tempdir().expect("tempdir");
        let (paths, _) = established(&tmp);
        let mode = std::fs::metadata(paths.genesis_record())
            .expect("stat")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn a_record_path_under_a_different_data_root_is_not_consulted() {
        // Two installs, one record. Classifying the second must not find the
        // first's record.
        let tmp = tempfile::tempdir().expect("tempdir");
        let (_first, _) = established(&tmp);
        let second_root = tmp.path().join("second");
        std::fs::create_dir_all(second_root.join("data")).expect("mkdir");
        let second = ControlPaths::resolve(&second_root).expect("resolve");
        assert!(classify(&second, &FixedKeySource([0x11; 32])).is_eligible_for_first_genesis());
    }

    #[test]
    fn the_record_path_is_fixed_under_the_data_root() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let paths = ControlPaths::resolve(&install_root(&tmp)).expect("resolve");
        assert_eq!(
            paths.genesis_record(),
            paths.data_root().join("control").join("genesis.record"),
            "the marker's location is part of the trust model, not a preference"
        );
        assert!(paths.genesis_record().starts_with(paths.data_root()));
        assert!(Path::new(&paths.genesis_record()).is_absolute());
    }
}
