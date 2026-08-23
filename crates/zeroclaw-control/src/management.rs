//! The durable mutation-enablement fact and its host-side ceremony.
//!
//! The default-enabled release is **read-only**: Request apply, durable
//! parking, approval, and apply are all refused until an operator enables
//! mutations through a host-side ceremony. This module owns the one durable
//! fact that gates them and the ceremony that writes it.
//!
//! ## The fact
//!
//! A sealed record at `<data_root>/control/management.record`, authenticated by
//! the same ADR-015 key chain as the genesis record and the two registries, and
//! carrying exactly one security-relevant bit: whether this instance's operator
//! has enabled management mutations. Its **absence is `false`** — a first-run
//! instance, and any instance whose record cannot be read or authenticated,
//! reads as read-only. Nothing here ever falls back to an unauthenticated read
//! or a default of `true`.
//!
//! ## The ceremony
//!
//! [`enable_mutations`] is host-side only, exactly like genesis and operator
//! registration: no agent, tool, or MCP session can reach it. It requires a
//! managed instance, a usable approval-and-audit key source, and an
//! OS-mediated user-presence attestation naming a registered operator. It
//! records the enabling operator and the assurance class, and it grants no tool
//! to any agent — enablement lifts a refusal, it does not widen a grant.
//!
//! ## Why the terminal adapter is the v1 backchannel
//!
//! The trust-genesis design envisions a stricter high-assurance adapter for
//! enablement, and [`crate::genesis::PresenceClass::permits_mutation_enablement`]
//! returns `false` for the terminal class in anticipation of it. This release
//! ships exactly one presence adapter — [`crate::TerminalConfirmation`] — and it
//! is already the operator backchannel every phase-4 approval authenticates
//! through ([`crate::authenticate_operator`]). Enablement therefore uses the
//! same backchannel the approvals it unlocks already use, rather than gating on
//! a stricter adapter that does not exist yet. When a higher-assurance adapter
//! lands, this ceremony inherits it without a contract change.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::ceremony::{PresenceError, PresenceRequest, UserPresence};
use crate::genesis::{GenesisRecord, InstanceTrustState, classify, now_unix_secs};
use crate::keys::ApprovalAuditKey;
use crate::operator::{self, OperatorIdentity};
use crate::registry::{InstanceId, TrustEpoch};
use crate::store::{
    CanonicalBytes, ControlPaths, absorb_str, absorb_u64, ensure_state_dir, open_sealed,
    publish_replace, read_optional, seal,
};

/// Domain-separation label for the management record.
pub const MANAGEMENT_RECORD_DOMAIN: &str = "zeroclaw/control-plane/management-record/v1";

/// The only management-record encoding this build understands.
pub const MANAGEMENT_RECORD_FORMAT_VERSION: u32 = 1;

/// File name of the sealed management record.
pub const MANAGEMENT_RECORD_FILE: &str = "management.record";

// ---------------------------------------------------------------------------
// The record
// ---------------------------------------------------------------------------

/// The durable `[management] mutations_enabled` fact.
///
/// Sealed under the ADR-015 key exactly like the genesis record. Absence reads
/// as disabled; a present-but-unauthenticatable record reads as disabled too,
/// because a fact the host cannot trust must not unlock a mutation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagementRecord {
    /// The instance this fact is about. Bound so a record cannot be transplanted
    /// within a deployment that ever held two instance identities.
    pub instance_id: InstanceId,
    /// The epoch the enabling ceremony ran under.
    pub trust_epoch: TrustEpoch,
    /// Whether management mutations are enabled on this instance.
    pub mutations_enabled: bool,
    /// The operator identity that enabled mutations. Attribution only.
    pub enabling_operator: String,
    /// The presence assurance class the enabling ceremony achieved.
    pub assurance_class: String,
    /// Wall-clock enablement time, seconds since the Unix epoch.
    pub enabled_at_unix_secs: u64,
}

impl CanonicalBytes for ManagementRecord {
    const DOMAIN: &'static str = MANAGEMENT_RECORD_DOMAIN;
    const FORMAT_VERSION: u32 = MANAGEMENT_RECORD_FORMAT_VERSION;

    fn absorb_canonical(&self, out: &mut Vec<u8>) {
        // Exhaustive destructure, no `..`: an unabsorbed field is an
        // unauthenticated field, so adding one must not compile until it is
        // bound into the tag here.
        let Self {
            instance_id,
            trust_epoch,
            mutations_enabled,
            enabling_operator,
            assurance_class,
            enabled_at_unix_secs,
        } = self;
        absorb_str(out, instance_id.as_str());
        absorb_u64(out, trust_epoch.get());
        absorb_u64(out, u64::from(*mutations_enabled));
        absorb_str(out, enabling_operator);
        absorb_str(out, assurance_class);
        absorb_u64(out, *enabled_at_unix_secs);
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Why the enablement ceremony refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagementErrorCode {
    /// The install root could not be resolved, or a root is symlinked.
    RootUnusable,
    /// This instance has no verified genesis record.
    NotManaged,
    /// This instance is in recovery-only mode.
    RecoveryOnly,
    /// The deployment key source could not be read.
    KeySourceUnusable,
    /// No presence attestation was produced.
    PresenceUnavailable,
    /// A human declined.
    PresenceDeclined,
    /// The presence ceremony attested no operator identity.
    NoOperatorAttested,
    /// The attested identity is not a registered, active operator.
    OperatorNotRegistered,
    /// The record could not be written.
    NotWritten,
    /// The operator registry could not be loaded or verified.
    RegistryUnusable,
}

/// An enablement refusal. `detail` never carries key material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagementError {
    pub code: ManagementErrorCode,
    pub detail: String,
}

impl ManagementError {
    fn new(code: ManagementErrorCode, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }
}

impl std::fmt::Display for ManagementError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let what = match self.code {
            ManagementErrorCode::RootUnusable => "instance root is unusable",
            ManagementErrorCode::NotManaged => {
                "this instance has no verified control-plane trust root"
            }
            ManagementErrorCode::RecoveryOnly => "this instance is in recovery-only mode",
            ManagementErrorCode::KeySourceUnusable => "the deployment key source is unusable",
            ManagementErrorCode::PresenceUnavailable => "no user-presence attestation was produced",
            ManagementErrorCode::PresenceDeclined => "the enablement ceremony was declined",
            ManagementErrorCode::NoOperatorAttested => "the ceremony attested no operator identity",
            ManagementErrorCode::OperatorNotRegistered => {
                "the attested identity is not a registered operator"
            }
            ManagementErrorCode::NotWritten => "the management record could not be written",
            ManagementErrorCode::RegistryUnusable => "the operator registry is unusable",
        };
        write!(f, "{what}: {}", self.detail)
    }
}

impl std::error::Error for ManagementError {}

// ---------------------------------------------------------------------------
// Reading the fact
// ---------------------------------------------------------------------------

/// Whether management mutations are enabled for the instance at `install_root`.
///
/// **Fail-closed in every branch.** An unresolvable root, an unmanaged or
/// recovery-only instance, an unusable key source, an absent record, and a
/// record that does not authenticate all read as `false`. Only a present,
/// authenticated record whose `mutations_enabled` bit is set — and whose
/// `instance_id` matches this instance — returns `true`.
#[must_use]
pub fn mutations_enabled(install_root: &Path) -> bool {
    let Ok(paths) = ControlPaths::resolve(install_root) else {
        return false;
    };
    let key_source = paths.key_source();
    let record = match classify(&paths, &key_source) {
        InstanceTrustState::Managed(record) => record,
        InstanceTrustState::EligibleForFirstGenesis | InstanceTrustState::RecoveryOnly { .. } => {
            return false;
        }
    };
    let Ok(key) = ApprovalAuditKey::derive(&key_source, record.trust_epoch) else {
        return false;
    };
    mutations_enabled_with(&paths, &record, &key)
}

/// Whether mutations are enabled, given already-resolved trust material.
///
/// The [`mutations_enabled`] entry point resolves the material itself; callers
/// that already hold it (the operator apply path) use this to avoid a second
/// classify.
#[must_use]
pub fn mutations_enabled_with(
    paths: &ControlPaths,
    record: &GenesisRecord,
    key: &ApprovalAuditKey,
) -> bool {
    let path = paths.control_dir().join(MANAGEMENT_RECORD_FILE);
    let Ok(Some(bytes)) = read_optional(&path) else {
        return false;
    };
    let Ok(parsed) = open_sealed::<ManagementRecord>(&bytes, key) else {
        return false;
    };
    parsed.instance_id == record.instance_id && parsed.mutations_enabled
}

// ---------------------------------------------------------------------------
// The enablement ceremony
// ---------------------------------------------------------------------------

/// What an enablement ceremony established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MutationEnablement {
    pub instance_id: InstanceId,
    pub trust_epoch: TrustEpoch,
    pub enabling_operator: String,
    pub assurance_class: String,
    pub enabled_at_unix_secs: u64,
}

/// Enable management mutations on the instance at `install_root`.
///
/// Host-side only. Requires a managed instance, a usable key source, and an
/// OS-mediated user-presence attestation naming a **registered, active**
/// operator. It grants no tool to any agent.
///
/// # Errors
///
/// See [`ManagementErrorCode`]. Every failure is a refusal; nothing partial is
/// written and nothing is downgraded.
pub fn enable_mutations(
    install_root: &Path,
    presence: &dyn UserPresence,
    prompt: String,
    operator_prompt: String,
) -> Result<MutationEnablement, ManagementError> {
    let paths = ControlPaths::resolve(install_root)
        .map_err(|e| ManagementError::new(ManagementErrorCode::RootUnusable, e.detail))?;
    let key_source = paths.key_source();

    let record = match classify(&paths, &key_source) {
        InstanceTrustState::Managed(record) => *record,
        InstanceTrustState::EligibleForFirstGenesis => {
            return Err(ManagementError::new(
                ManagementErrorCode::NotManaged,
                "run genesis first",
            ));
        }
        InstanceTrustState::RecoveryOnly { reason, .. } => {
            return Err(ManagementError::new(
                ManagementErrorCode::RecoveryOnly,
                reason.wire(),
            ));
        }
    };

    let key = ApprovalAuditKey::derive(&key_source, record.trust_epoch).map_err(|e| {
        ManagementError::new(ManagementErrorCode::KeySourceUnusable, format!("{e:#}"))
    })?;

    // The operator registry, including the genesis first operator, is loaded
    // before the prompt so an unregistered claim never causes a terminal
    // interruption for a ceremony that would refuse anyway.
    let operators = operator::load_view(&paths, &record, &key)
        .map_err(|e| ManagementError::new(ManagementErrorCode::RegistryUnusable, e.to_string()))?;

    let attestation = presence
        .confirm(&PresenceRequest {
            prompt,
            operator_prompt: Some(operator_prompt),
        })
        .map_err(from_presence)?;

    let Some(attested) = attestation.operator_identity() else {
        return Err(ManagementError::new(
            ManagementErrorCode::NoOperatorAttested,
            "the ceremony attested no operator identity",
        ));
    };
    let operator_label = attested.as_str().to_owned();
    let claimed = OperatorIdentity::from(attested.clone());
    if operators.get_active(&claimed).is_none() {
        // Do not echo the attested label: it is text just typed at a prompt.
        return Err(ManagementError::new(
            ManagementErrorCode::OperatorNotRegistered,
            "the attested operator is not registered",
        ));
    }

    let now = now_unix_secs()
        .map_err(|e| ManagementError::new(ManagementErrorCode::NotWritten, e.detail))?;
    let enablement = ManagementRecord {
        instance_id: record.instance_id.clone(),
        trust_epoch: record.trust_epoch,
        mutations_enabled: true,
        enabling_operator: operator_label.clone(),
        assurance_class: attestation.class().wire().to_owned(),
        enabled_at_unix_secs: now,
    };

    let dir = paths.control_dir();
    ensure_state_dir(&dir)
        .map_err(|e| ManagementError::new(ManagementErrorCode::NotWritten, e.detail))?;
    let bytes = seal(&enablement, &key)
        .map_err(|e| ManagementError::new(ManagementErrorCode::NotWritten, e.detail))?;
    publish_replace(&dir.join(MANAGEMENT_RECORD_FILE), &bytes)
        .map_err(|e| ManagementError::new(ManagementErrorCode::NotWritten, e.detail))?;

    Ok(MutationEnablement {
        instance_id: record.instance_id,
        trust_epoch: record.trust_epoch,
        enabling_operator: operator_label,
        assurance_class: enablement.assurance_class,
        enabled_at_unix_secs: now,
    })
}

fn from_presence(error: PresenceError) -> ManagementError {
    match error {
        PresenceError::Declined => {
            ManagementError::new(ManagementErrorCode::PresenceDeclined, error.to_string())
        }
        PresenceError::NoControllingTerminal
        | PresenceError::InvalidOperatorIdentity(_)
        | PresenceError::Io(_) => {
            ManagementError::new(ManagementErrorCode::PresenceUnavailable, error.to_string())
        }
    }
}
