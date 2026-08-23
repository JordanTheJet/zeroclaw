//! The trust-genesis ceremony and the user-presence adapter it runs under.
//!
//! Genesis is a ceremony rather than an operation because it is one of only two
//! management transitions that do not consume a prior approval receipt — and a
//! receipt needs a trust root that only genesis can create. That circularity is
//! why this module exists and why it is not reachable from `ControlService`,
//! from a native tool, or from MCP. The only entry points are
//! [`run_genesis`] and [`run_register_client`], both of which take a
//! [`UserPresence`] adapter by reference and refuse without an attestation from
//! it.
//!
//! # The v1 adapter is not sufficient, and ships anyway
//!
//! **Read this before extending anything here.**
//!
//! The trust-genesis design lists what does *not* satisfy interactive genesis,
//! and the first item is "an ordinary terminal prompt". [`TerminalConfirmation`]
//! is an ordinary terminal prompt. Shipping it as the v1 adapter is a
//! deliberate, recorded deviation, taken for three reasons:
//!
//! 1. **No OS user-presence adapter is decided.** The design requires an
//!    OS-mediated ceremony; which OS mechanism, on which platforms, with what
//!    fallback, is an open question, and inventing one here would be a
//!    unilateral answer to a decision that belongs to the maintainer.
//! 2. **Mutations are structurally impossible in this phase.** What genesis
//!    establishes here is a trust root and a registry, not authority to change
//!    anything. There is no receipt broker, no proposal journal, and no
//!    mutating tool; the strongest thing an attacker who forged this ceremony
//!    could obtain is the ability to read configured state through a
//!    registered client, on a host where they already had terminal access.
//! 3. **The record says what it got.** [`GenesisRecord::user_presence_class`]
//!    stores the class of the ceremony that authorized genesis, so nothing
//!    downstream has to guess whether a real presence check happened.
//!
//! Point 3 is what turns this from a shortcut into a bounded one, and it comes
//! with a rule that is written into the code rather than into a comment:
//! [`PresenceClass::permits_mutation_enablement`] returns `false` for every
//! class this phase can produce. A future mutation-enablement ceremony
//! **must re-attest under a high-assurance adapter**; it may not inherit a
//! terminal-class genesis, and there is no configuration that lets it. Building
//! that adapter is future work and is explicitly not done here.
//!
//! # What a ceremony refuses
//!
//! Both ceremonies fail closed at every step:
//!
//! - genesis runs only from [`InstanceTrustState::EligibleForFirstGenesis`], so
//!   a managed instance and a recovery-only instance both refuse;
//! - genesis additionally refuses a root that already carries a target or
//!   client registry, because state without a record is not a state genesis may
//!   overwrite;
//! - registration runs only on a **managed** instance whose target registry
//!   verifies, so recovery-only refuses there too;
//! - a presence adapter that cannot attest — no controlling terminal, a
//!   declined prompt, an unreadable stream — refuses, and the refusal is
//!   distinguishable from a decline; and
//! - a credential path inside an agent workspace root, or one that already
//!   exists, refuses before any durable state is written.
//!
//! # Receipt exemption
//!
//! Per [ADR-016] the ceremony may register the first client or clients
//! receipt-exempt. [`run_register_client`] is the bounded post-genesis form of
//! the same exception: it runs the *same* presence ceremony, verifies the
//! genesis record first, and anchors the registration to that record's digest
//! rather than to a receipt. The exception closes at mutation enablement, which
//! this phase neither implements nor can reach.
//!
//! [ADR-016]: ../../../docs/book/src/architecture/decisions/ADR-016-control-plane-registration-bootstrap.md
//!
//! # No user-facing text lives here
//!
//! This crate never calls the Fluent catalogue; it returns typed values and the
//! CLI renders them. A [`PresenceRequest`] therefore carries **already
//! rendered** prompt strings, supplied by the caller. That keeps the localized
//! text in the binary that owns the catalogue and keeps this module free of
//! bare literals.

use std::io::{BufRead as _, IsTerminal as _, Write as _};
use std::path::{Path, PathBuf};

use zeroclaw_config::secrets::{KeySource, ProvisioningState};

use crate::client_registry::{
    ClientCredential, ClientGrant, ClientLabel, ClientRegistration, ClientRegistry,
    ClientRegistryError, CredentialDelivery, RegistrationId, refuse_credential_path_inside,
    write_credential_file,
};
use crate::genesis::{
    FirstOperatorIdentity, GenesisRecord, InstanceTrustState, KeyCommitment, PresenceClass,
    RecoveryReason, classify, generate_instance_id, now_unix_secs, write_record,
};
use crate::keys::ApprovalAuditKey;
use crate::registry::{GenesisDigest, InstanceId, TargetRecord, TargetRegistry, TrustEpoch};
use crate::registry_store;
use crate::store::{ControlPaths, StoreError};

// ---------------------------------------------------------------------------
// User presence
// ---------------------------------------------------------------------------

/// What a ceremony asks the human present to authorize.
///
/// Both fields are text the caller has already localized. This crate does not
/// own a catalogue and must not embed one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresenceRequest {
    /// The question. An adapter must require an affirmative answer.
    pub prompt: String,
    /// When `Some`, the ceremony also collects a first-operator identity, and
    /// this is the label to ask for it under. Genesis sets it; registration
    /// does not, because genesis already established the operator.
    pub operator_prompt: Option<String>,
}

/// The result of a successful presence ceremony.
///
/// Constructible only by an adapter in this module, so no caller can fabricate
/// an attestation for a ceremony that did not happen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresenceAttestation {
    class: PresenceClass,
    operator_identity: Option<FirstOperatorIdentity>,
}

impl PresenceAttestation {
    /// Build an attestation directly, for a scripted adapter in a sibling
    /// module's tests.
    ///
    /// # Test-only
    ///
    /// `#[cfg(test)]` and `pub(crate)`: it exists in no shipped build and is
    /// reachable from no other crate. The fields are otherwise private to this
    /// module, which is what stops a caller anywhere from fabricating an
    /// attestation for a ceremony that did not happen — sibling modules such as
    /// [`crate::operator`] need a way to script presence in *their* tests
    /// without that guarantee being weakened for production.
    #[cfg(test)]
    pub(crate) const fn for_test(
        class: PresenceClass,
        operator_identity: Option<FirstOperatorIdentity>,
    ) -> Self {
        Self {
            class,
            operator_identity,
        }
    }

    /// Build an attestation for the `fixture-grants` test seam.
    ///
    /// # Test-only
    ///
    /// Compiled only under the `fixture-grants` feature, which no released
    /// profile enables, so it is absent from every shipped build and covered by
    /// `control_fixture_absence_gate.sh`. It is the cross-crate analogue of
    /// [`Self::for_test`]: an out-of-crate test that drives the operator-approve
    /// or mutation-enablement ceremony needs a `UserPresence` that succeeds, and
    /// this type's fields are otherwise unreachable outside this module. A
    /// production adapter still attests only the class it actually achieved.
    #[cfg(feature = "fixture-grants")]
    #[must_use]
    pub const fn fixture(
        class: PresenceClass,
        operator_identity: Option<FirstOperatorIdentity>,
    ) -> Self {
        Self {
            class,
            operator_identity,
        }
    }

    /// The assurance class actually achieved.
    #[must_use]
    pub const fn class(&self) -> PresenceClass {
        self.class
    }

    /// The first-operator identity, when the request asked for one.
    #[must_use]
    pub const fn operator_identity(&self) -> Option<&FirstOperatorIdentity> {
        self.operator_identity.as_ref()
    }
}

/// Why a presence ceremony produced no attestation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PresenceError {
    /// The host offers no controlling terminal, so no human can be present at
    /// this adapter. Distinct from [`Self::Declined`]: nobody said no, there
    /// was nobody to ask.
    NoControllingTerminal,
    /// A human was asked and did not affirm.
    Declined,
    /// The operator identity supplied was not acceptable.
    InvalidOperatorIdentity(String),
    /// The prompt could not be written or the answer could not be read.
    Io(String),
}

impl std::fmt::Display for PresenceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoControllingTerminal => f.write_str("no controlling terminal"),
            Self::Declined => f.write_str("the ceremony was declined"),
            Self::InvalidOperatorIdentity(detail) => {
                write!(f, "invalid first operator identity: {detail}")
            }
            Self::Io(detail) => write!(f, "presence prompt failed: {detail}"),
        }
    }
}

impl std::error::Error for PresenceError {}

/// An adapter that can attest a human is present and authorizing.
///
/// The trait is deliberately narrow. An implementation may not weaken what it
/// attests: it returns the class it actually achieved, and a class it cannot
/// achieve is a class it must not name.
pub trait UserPresence {
    /// Ask the human present to authorize a ceremony.
    ///
    /// # Errors
    ///
    /// Returns [`PresenceError`] when no attestation can be produced. An
    /// implementation must never return `Ok` for an unanswered prompt.
    fn confirm(&self, request: &PresenceRequest) -> Result<PresenceAttestation, PresenceError>;
}

/// The affirmative answer a terminal ceremony requires.
///
/// Exact and case-sensitive on purpose: an accidental keystroke, a stray `y`
/// left in a buffer, or a pasted fragment must not authorize a trust root.
pub const TERMINAL_CONFIRMATION_ANSWER: &str = "yes";

/// Interactive confirmation on a real controlling terminal.
///
/// Requires both stdin and stderr to be terminals. The prompt goes to stderr so
/// stdout stays available for the caller's machine-readable summary, and the
/// answer is read from stdin.
///
/// **This adapter's assurance class is [`PresenceClass::Terminal`], which the
/// design says does not satisfy interactive genesis.** See the module docs for
/// why it ships and what constrains it.
#[derive(Debug, Clone, Copy, Default)]
pub struct TerminalConfirmation;

impl TerminalConfirmation {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl UserPresence for TerminalConfirmation {
    fn confirm(&self, request: &PresenceRequest) -> Result<PresenceAttestation, PresenceError> {
        // A real controlling terminal is the whole of what this adapter
        // attests. Without one there is no human to ask, and proceeding would
        // mean writing a record claiming a presence check that never happened.
        if !std::io::stdin().is_terminal() || !std::io::stderr().is_terminal() {
            return Err(PresenceError::NoControllingTerminal);
        }

        let answer = prompt_line(&request.prompt)?;
        if answer.trim() != TERMINAL_CONFIRMATION_ANSWER {
            return Err(PresenceError::Declined);
        }

        let operator_identity = match &request.operator_prompt {
            Some(label) => {
                let raw = prompt_line(label)?;
                Some(
                    FirstOperatorIdentity::new(raw)
                        .map_err(|e| PresenceError::InvalidOperatorIdentity(e.detail))?,
                )
            }
            None => None,
        };

        Ok(PresenceAttestation {
            class: PresenceClass::Terminal,
            operator_identity,
        })
    }
}

/// Write `prompt` to stderr and read one line from stdin.
fn prompt_line(prompt: &str) -> Result<String, PresenceError> {
    let mut err = std::io::stderr();
    err.write_all(prompt.as_bytes())
        .and_then(|()| err.flush())
        .map_err(|e| PresenceError::Io(e.to_string()))?;

    let mut answer = String::new();
    let read = std::io::stdin()
        .lock()
        .read_line(&mut answer)
        .map_err(|e| PresenceError::Io(e.to_string()))?;
    if read == 0 {
        // End of input is not an affirmative answer.
        return Err(PresenceError::Declined);
    }
    Ok(answer)
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Why a ceremony refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CeremonyErrorCode {
    /// The install root could not be resolved, or a root is symlinked.
    RootUnusable,
    /// This root already has a valid genesis record.
    AlreadyManaged,
    /// This root is in recovery-only mode.
    RecoveryOnly,
    /// This root has no genesis record, so there is nothing to register into.
    NotManaged,
    /// Control-plane state exists that genesis did not write.
    StateAlreadyPresent,
    /// No presence attestation was produced.
    PresenceUnavailable,
    /// A human declined.
    PresenceDeclined,
    /// The deployment key source could not be initialized or read.
    KeySourceUnusable,
    /// Durable state could not be written.
    NotWritten,
    /// The target registry could not be loaded or verified.
    RegistryUnusable,
    /// The client registry could not be loaded, verified, or written.
    ClientRegistryUnusable,
    /// The instance being registered against is not an operable target.
    InstanceNotRegistered,
    /// The credential could not be minted or delivered.
    CredentialNotDelivered,
}

/// A ceremony refusal.
///
/// `detail` never carries credential bytes or key material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CeremonyError {
    pub code: CeremonyErrorCode,
    pub detail: String,
}

impl CeremonyError {
    fn new(code: CeremonyErrorCode, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }

    fn from_presence(error: &PresenceError) -> Self {
        match error {
            PresenceError::Declined => {
                Self::new(CeremonyErrorCode::PresenceDeclined, error.to_string())
            }
            PresenceError::NoControllingTerminal
            | PresenceError::InvalidOperatorIdentity(_)
            | PresenceError::Io(_) => {
                Self::new(CeremonyErrorCode::PresenceUnavailable, error.to_string())
            }
        }
    }

    fn from_store(error: &StoreError) -> Self {
        Self::new(CeremonyErrorCode::NotWritten, error.detail.clone())
    }

    fn from_client_registry(error: &ClientRegistryError) -> Self {
        Self::new(CeremonyErrorCode::ClientRegistryUnusable, error.to_string())
    }
}

impl std::fmt::Display for CeremonyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let what = match self.code {
            CeremonyErrorCode::RootUnusable => "instance root is unusable",
            CeremonyErrorCode::AlreadyManaged => {
                "this instance already has a genesis record; first genesis cannot run again"
            }
            CeremonyErrorCode::RecoveryOnly => {
                "this instance is in recovery-only mode; only the recovery ceremony can leave it"
            }
            CeremonyErrorCode::NotManaged => "this instance has no genesis record",
            CeremonyErrorCode::StateAlreadyPresent => {
                "control-plane state exists that no genesis record accounts for"
            }
            CeremonyErrorCode::PresenceUnavailable => "user presence could not be attested",
            CeremonyErrorCode::PresenceDeclined => "the ceremony was declined",
            CeremonyErrorCode::KeySourceUnusable => "the deployment key source is unusable",
            CeremonyErrorCode::NotWritten => "durable state could not be written",
            CeremonyErrorCode::RegistryUnusable => "the target registry could not be verified",
            CeremonyErrorCode::ClientRegistryUnusable => {
                "the client registry could not be verified or written"
            }
            CeremonyErrorCode::InstanceNotRegistered => "the instance is not an operable target",
            CeremonyErrorCode::CredentialNotDelivered => "the credential could not be delivered",
        };
        write!(f, "{what}: {}", self.detail)
    }
}

impl std::error::Error for CeremonyError {}

// ---------------------------------------------------------------------------
// Requests and outcomes
// ---------------------------------------------------------------------------

/// The optional bootstrap client registration a ceremony performs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientRegistrationRequest {
    /// Display name for the client.
    pub client_label: ClientLabel,
    /// Where the one copy of the credential is written. Must not exist, and
    /// must not resolve inside an agent workspace root.
    pub credential_path: PathBuf,
    /// How the credential reaches the client.
    pub delivery_assurance: CredentialDelivery,
    /// Roots the credential path may not land in. The CLI supplies these from
    /// the loaded configuration; see [`refuse_credential_path_inside`] for what
    /// the check can and cannot see.
    pub forbidden_credential_roots: Vec<PathBuf>,
}

/// Everything a genesis ceremony needs from its caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenesisRequest {
    /// The rendered confirmation prompt.
    pub prompt: String,
    /// The rendered prompt for the first-operator identity.
    pub operator_prompt: String,
    /// An optional bootstrap client registration, performed inside the same
    /// presence session per ADR-016.
    pub register_client: Option<ClientRegistrationRequest>,
}

/// What a bootstrap registration produced.
///
/// Deliberately carries no credential: the secret is written to its file inside
/// the ceremony and dropped, so no caller can print it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisteredClient {
    pub registration_id: RegistrationId,
    pub client_label: ClientLabel,
    pub credential_path: PathBuf,
    pub delivery_assurance: CredentialDelivery,
}

/// What a genesis ceremony established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenesisOutcome {
    pub instance_id: InstanceId,
    pub trust_epoch: TrustEpoch,
    pub genesis_digest: GenesisDigest,
    pub config_root: PathBuf,
    pub data_root: PathBuf,
    pub presence_class: PresenceClass,
    pub first_operator: FirstOperatorIdentity,
    pub mutations_enabled: bool,
    pub registered_client: Option<RegisteredClient>,
}

// ---------------------------------------------------------------------------
// The genesis ceremony
// ---------------------------------------------------------------------------

/// Run first genesis against `install_root`.
///
/// The order is chosen so that every refusal happens before any durable state
/// is written: classify, check for orphaned state, validate the credential
/// path, attest presence, then initialize the key source, then write.
///
/// # Errors
///
/// See [`CeremonyErrorCode`].
pub fn run_genesis(
    install_root: &Path,
    presence: &dyn UserPresence,
    request: &GenesisRequest,
) -> Result<GenesisOutcome, CeremonyError> {
    let paths = ControlPaths::resolve(install_root)
        .map_err(|e| CeremonyError::new(CeremonyErrorCode::RootUnusable, e.detail))?;
    let key_source = paths.key_source();

    match classify(&paths, &key_source) {
        InstanceTrustState::EligibleForFirstGenesis => {}
        InstanceTrustState::Managed(record) => {
            return Err(CeremonyError::new(
                CeremonyErrorCode::AlreadyManaged,
                record.instance_id.to_string(),
            ));
        }
        InstanceTrustState::RecoveryOnly { reason, detail } => {
            return Err(recovery_only_error(reason, &detail));
        }
    }

    // A registry with no genesis record is not a state first genesis may
    // silently absorb; something wrote control-plane state outside a ceremony.
    if registry_store::is_present(&paths) || crate::client_registry::is_present(&paths) {
        return Err(CeremonyError::new(
            CeremonyErrorCode::StateAlreadyPresent,
            paths.control_dir().display().to_string(),
        ));
    }

    if let Some(registration) = &request.register_client {
        precheck_credential_path(registration)?;
    }

    let attestation = presence
        .confirm(&PresenceRequest {
            prompt: request.prompt.clone(),
            operator_prompt: Some(request.operator_prompt.clone()),
        })
        .map_err(|e| CeremonyError::from_presence(&e))?;
    let Some(first_operator) = attestation.operator_identity().cloned() else {
        return Err(CeremonyError::new(
            CeremonyErrorCode::PresenceUnavailable,
            "the ceremony attested no first operator identity",
        ));
    };

    let key = provision_and_derive(&key_source, TrustEpoch::GENESIS)?;

    let instance_id = generate_instance_id().map_err(|e| CeremonyError::from_store(&e))?;
    let record = GenesisRecord {
        instance_id: instance_id.clone(),
        trust_epoch: TrustEpoch::GENESIS,
        canonical_roots: paths
            .canonical_roots()
            .map_err(|e| CeremonyError::new(CeremonyErrorCode::RootUnusable, e.detail))?,
        created_at_unix_secs: now_unix_secs().map_err(|e| CeremonyError::from_store(&e))?,
        user_presence_class: attestation.class(),
        first_operator: first_operator.clone(),
        host_key_commitment: KeyCommitment::compute(&key),
    };

    let genesis_digest =
        write_record(&paths, &record, &key).map_err(|e| CeremonyError::from_store(&e))?;

    register_default_instance(&paths, &instance_id, genesis_digest, &key)?;

    let registered_client = match &request.register_client {
        Some(registration) => Some(issue_and_deliver(
            &paths,
            registration,
            &ClientRegistry::new(),
            &instance_id,
            TrustEpoch::GENESIS,
            genesis_digest,
            attestation.class(),
            &key,
            true,
        )?),
        None => None,
    };

    Ok(GenesisOutcome {
        instance_id,
        trust_epoch: TrustEpoch::GENESIS,
        genesis_digest,
        config_root: paths.config_root().to_path_buf(),
        data_root: paths.data_root().to_path_buf(),
        presence_class: attestation.class(),
        first_operator,
        // Genesis establishes who may approve; it does not enable approving.
        // Mutation enablement is a separate ceremony that this phase does not
        // implement, so this is a constant `false` rather than a stored flag.
        mutations_enabled: false,
        registered_client,
    })
}

/// Register a client on an already-managed instance.
///
/// The bounded post-genesis form of the ADR-016 exemption: it runs the same
/// presence ceremony, re-verifies the genesis record first, and refuses in
/// recovery-only mode.
///
/// # Errors
///
/// See [`CeremonyErrorCode`].
pub fn run_register_client(
    install_root: &Path,
    presence: &dyn UserPresence,
    prompt: String,
    request: &ClientRegistrationRequest,
) -> Result<RegisteredClient, CeremonyError> {
    let paths = ControlPaths::resolve(install_root)
        .map_err(|e| CeremonyError::new(CeremonyErrorCode::RootUnusable, e.detail))?;
    let key_source = paths.key_source();

    let record = match classify(&paths, &key_source) {
        InstanceTrustState::Managed(record) => record,
        InstanceTrustState::EligibleForFirstGenesis => {
            return Err(CeremonyError::new(
                CeremonyErrorCode::NotManaged,
                paths.genesis_record().display().to_string(),
            ));
        }
        InstanceTrustState::RecoveryOnly { reason, detail } => {
            return Err(recovery_only_error(reason, &detail));
        }
    };

    precheck_credential_path(request)?;

    let key = ApprovalAuditKey::derive(&key_source, record.trust_epoch)
        .map_err(|e| CeremonyError::new(CeremonyErrorCode::KeySourceUnusable, format!("{e:#}")))?;

    // The registry must verify before a credential is minted against it: a
    // grant naming an instance whose roots moved is a grant over nothing.
    let targets = registry_store::load(&paths, &key)
        .map_err(|e| CeremonyError::new(CeremonyErrorCode::RegistryUnusable, e.to_string()))?;
    if targets.get_operable(&record.instance_id).is_none() {
        return Err(CeremonyError::new(
            CeremonyErrorCode::InstanceNotRegistered,
            record.instance_id.to_string(),
        ));
    }

    // Verify the existing client registry before prompting, so an unverifiable
    // one refuses without troubling the operator.
    drop(load_client_registry(&paths, &key)?);

    let attestation = presence
        .confirm(&PresenceRequest {
            prompt,
            operator_prompt: None,
        })
        .map_err(|e| CeremonyError::from_presence(&e))?;

    // Re-read after the prompt rather than reusing the pre-prompt copy. A human
    // typing is an unbounded window, and this crate has no registry lock yet
    // (see the concurrency note on `issue_and_deliver`), so the read-modify-write
    // is kept as short as it can be made without one.
    let (existing, first_write) = load_client_registry(&paths, &key)?;

    issue_and_deliver(
        &paths,
        request,
        &existing,
        &record.instance_id,
        record.trust_epoch,
        record.digest(),
        attestation.class(),
        &key,
        first_write,
    )
}

/// Load the client registry, or an empty one when there is none.
///
/// Returns the registry and whether this would be the first write, so the two
/// answers come from one presence check rather than two.
fn load_client_registry(
    paths: &ControlPaths,
    key: &ApprovalAuditKey,
) -> Result<(ClientRegistry, bool), CeremonyError> {
    if crate::client_registry::is_present(paths) {
        let registry = crate::client_registry::load(paths, key)
            .map_err(|e| CeremonyError::from_client_registry(&e))?;
        Ok((registry, false))
    } else {
        Ok((ClientRegistry::new(), true))
    }
}

// ---------------------------------------------------------------------------
// Steps
// ---------------------------------------------------------------------------

fn recovery_only_error(reason: RecoveryReason, detail: &str) -> CeremonyError {
    CeremonyError::new(
        CeremonyErrorCode::RecoveryOnly,
        format!("{}: {detail}", reason.wire()),
    )
}

/// Refuse a credential path before anything durable happens.
///
/// `publish_new` re-checks existence atomically at delivery time; this is the
/// early, friendly refusal so an operator typo does not half-initialize an
/// instance.
fn precheck_credential_path(request: &ClientRegistrationRequest) -> Result<(), CeremonyError> {
    refuse_credential_path_inside(
        &request.credential_path,
        &request.forbidden_credential_roots,
    )
    .map_err(|e| CeremonyError::new(CeremonyErrorCode::CredentialNotDelivered, e.to_string()))?;
    if request.credential_path.exists() {
        return Err(CeremonyError::new(
            CeremonyErrorCode::CredentialNotDelivered,
            format!("{} already exists", request.credential_path.display()),
        ));
    }
    Ok(())
}

/// Initialize the deployment key source if it has no material, then derive.
///
/// ADR-013's two rules apply here and are the reason this is a probe followed
/// by an initialize rather than a bare read: a probe must not prompt or unlock,
/// and initialization must publish complete restrictive material without
/// replacing what is there. `FileKeySource::initialize` does exactly that, so
/// this never rotates an existing key.
fn provision_and_derive(
    key_source: &dyn KeySource,
    epoch: TrustEpoch,
) -> Result<ApprovalAuditKey, CeremonyError> {
    if key_source.provisioning_state() == ProvisioningState::NeedsInitialization {
        key_source.initialize().map_err(|e| {
            CeremonyError::new(CeremonyErrorCode::KeySourceUnusable, format!("{e:#}"))
        })?;
    }
    ApprovalAuditKey::derive(key_source, epoch)
        .map_err(|e| CeremonyError::new(CeremonyErrorCode::KeySourceUnusable, format!("{e:#}")))
}

/// Write the signed target registry holding this instance's own record.
fn register_default_instance(
    paths: &ControlPaths,
    instance_id: &InstanceId,
    genesis_digest: GenesisDigest,
    key: &ApprovalAuditKey,
) -> Result<(), CeremonyError> {
    let record = TargetRecord::register(
        instance_id.clone(),
        paths
            .canonical_roots()
            .map_err(|e| CeremonyError::new(CeremonyErrorCode::RootUnusable, e.detail))?,
        // A root instance created by its own genesis ceremony has no creation
        // parent. Approved creation parents are a meta-authority operation and
        // are out of scope here.
        None,
        TrustEpoch::GENESIS,
        genesis_digest,
    )
    .map_err(|e| CeremonyError::new(CeremonyErrorCode::RegistryUnusable, e.to_string()))?;

    let mut registry = TargetRegistry::new();
    registry
        .insert(record)
        .map_err(|e| CeremonyError::new(CeremonyErrorCode::RegistryUnusable, e.to_string()))?;
    registry_store::save_new(paths, &registry, key)
        .map_err(|e| CeremonyError::new(CeremonyErrorCode::NotWritten, e.to_string()))
}

/// Mint a registration, deliver its one credential, and persist the registry.
///
/// The credential file is written **before** the registry is saved. If the file
/// cannot be written, nothing has been recorded and the operator can retry. If
/// the registry save then fails, the delivered file is removed, because a
/// credential that authenticates nothing is a live-looking secret sitting on
/// disk.
///
/// # Not serialized against a concurrent ceremony
///
/// Saving a registration is a read-modify-write and **this crate has no
/// registry lock**. Two `register-client` runs racing on one instance can both
/// read the same registry and the later save wins, dropping the earlier
/// registration while its delivered credential file survives on disk,
/// authenticating nothing.
///
/// Genesis itself is safe from this: the genesis record is published with an
/// exclusive create, so concurrent first-genesis attempts resolve to exactly one
/// winner and the loser refuses. Only the append path is exposed.
///
/// The design calls for a registry lock and an exclusive bootstrap lock. Neither
/// is implemented here, and implementing one is a separate piece of work — it
/// needs a stale-lock policy, which is a decision rather than a mechanism. The
/// window is narrowed to the span between the post-prompt re-read and the save,
/// but it is not closed.
#[allow(clippy::too_many_arguments)]
fn issue_and_deliver(
    paths: &ControlPaths,
    request: &ClientRegistrationRequest,
    existing: &ClientRegistry,
    instance_id: &InstanceId,
    trust_epoch: TrustEpoch,
    genesis_digest: GenesisDigest,
    presence_class: PresenceClass,
    key: &ApprovalAuditKey,
    first_write: bool,
) -> Result<RegisteredClient, CeremonyError> {
    let grant = ClientGrant::full_v1(
        request.client_label.clone(),
        request.delivery_assurance,
        instance_id.clone(),
    );
    let issued = ClientRegistration::issue(
        &grant,
        trust_epoch,
        now_unix_secs().map_err(|e| CeremonyError::from_store(&e))?,
        genesis_digest,
        presence_class,
        key,
    )
    .map_err(|e| CeremonyError::from_client_registry(&e))?;

    let summary = RegisteredClient {
        registration_id: issued.registration.registration_id.clone(),
        client_label: issued.registration.client_label.clone(),
        credential_path: request.credential_path.clone(),
        delivery_assurance: issued.registration.delivery_assurance,
    };

    deliver(&request.credential_path, &issued.credential)?;
    // The credential is dropped here, zeroised. Nothing below can print it.
    drop(issued.credential);

    let mut registry = existing.clone();
    registry
        .insert(issued.registration)
        .map_err(|e| CeremonyError::from_client_registry(&e))?;

    let saved = if first_write {
        crate::client_registry::save_new(paths, &registry, key)
    } else {
        crate::client_registry::save(paths, &registry, key)
    };
    if let Err(e) = saved {
        let _ = std::fs::remove_file(&request.credential_path);
        return Err(CeremonyError::from_client_registry(&e));
    }
    Ok(summary)
}

fn deliver(path: &Path, credential: &ClientCredential) -> Result<(), CeremonyError> {
    write_credential_file(path, credential)
        .map_err(|e| CeremonyError::new(CeremonyErrorCode::CredentialNotDelivered, e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client_registry;
    use crate::genesis::RecoveryReason;
    use std::sync::Mutex;

    // -- the test presence adapter -----------------------------------------

    /// A scripted presence adapter.
    ///
    /// Compiled only under `cfg(test)`, so no shipped build contains a way to
    /// attest presence without a terminal. It reports
    /// [`PresenceClass::Terminal`] because that is the strongest class this
    /// phase defines, and a record must never claim a class no adapter can
    /// achieve.
    struct ScriptedPresence {
        outcome: Result<Option<&'static str>, PresenceError>,
        seen: Mutex<Vec<PresenceRequest>>,
    }

    impl ScriptedPresence {
        fn affirming(identity: &'static str) -> Self {
            Self {
                outcome: Ok(Some(identity)),
                seen: Mutex::new(Vec::new()),
            }
        }

        fn failing(error: PresenceError) -> Self {
            Self {
                outcome: Err(error),
                seen: Mutex::new(Vec::new()),
            }
        }

        fn requests(&self) -> Vec<PresenceRequest> {
            self.seen.lock().expect("presence log").clone()
        }
    }

    impl UserPresence for ScriptedPresence {
        fn confirm(&self, request: &PresenceRequest) -> Result<PresenceAttestation, PresenceError> {
            self.seen
                .lock()
                .expect("presence log")
                .push(request.clone());
            match &self.outcome {
                Ok(identity) => Ok(PresenceAttestation {
                    class: PresenceClass::Terminal,
                    operator_identity: match (identity, &request.operator_prompt) {
                        (Some(value), Some(_)) => Some(
                            FirstOperatorIdentity::new(*value).expect("test identity is valid"),
                        ),
                        _ => None,
                    },
                }),
                Err(e) => Err(e.clone()),
            }
        }
    }

    fn install_root(tmp: &tempfile::TempDir) -> PathBuf {
        let root = tmp.path().join("install");
        std::fs::create_dir_all(root.join("data")).expect("create install root");
        std::fs::write(root.join("config.toml"), b"# config").expect("write config");
        root
    }

    fn genesis_request() -> GenesisRequest {
        GenesisRequest {
            prompt: "Authorize control-plane genesis? ".to_string(),
            operator_prompt: "First operator identity: ".to_string(),
            register_client: None,
        }
    }

    fn client_request(path: PathBuf) -> ClientRegistrationRequest {
        ClientRegistrationRequest {
            client_label: ClientLabel::new("claude-code").expect("label"),
            credential_path: path,
            delivery_assurance: CredentialDelivery::IsolatedDescriptor,
            forbidden_credential_roots: Vec::new(),
        }
    }

    // -- happy path ---------------------------------------------------------

    #[test]
    fn first_genesis_writes_the_record_and_the_registry() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = install_root(&tmp);
        let presence = ScriptedPresence::affirming("jordan");

        let outcome =
            run_genesis(&root, &presence, &genesis_request()).expect("first genesis must succeed");

        assert_eq!(outcome.trust_epoch, TrustEpoch::GENESIS);
        assert_eq!(outcome.presence_class, PresenceClass::Terminal);
        assert_eq!(outcome.first_operator.as_str(), "jordan");
        assert!(
            !outcome.mutations_enabled,
            "genesis establishes who may approve; it does not enable approving"
        );
        assert!(outcome.registered_client.is_none());

        let paths = ControlPaths::resolve(&root).expect("resolve");
        assert!(paths.genesis_record().is_file());
        assert!(paths.target_registry().is_file());
        assert!(
            !paths.client_registry().exists(),
            "no client was requested, so no client registry may appear"
        );

        // The record classifies as managed, and the registry verifies.
        let state = classify(&paths, &paths.key_source());
        let record = state.record().expect("managed");
        assert_eq!(record.instance_id, outcome.instance_id);
        assert_eq!(record.digest(), outcome.genesis_digest);

        let key =
            ApprovalAuditKey::derive(&paths.key_source(), TrustEpoch::GENESIS).expect("derive");
        let targets = registry_store::load(&paths, &key).expect("registry must verify");
        assert_eq!(targets.len(), 1);
        assert!(targets.get_operable(&outcome.instance_id).is_some());

        // The ceremony asked exactly once, and asked for an operator identity.
        let asked = presence.requests();
        assert_eq!(asked.len(), 1);
        assert!(asked[0].operator_prompt.is_some());
    }

    #[test]
    fn genesis_creates_the_deployment_key_file_it_derives_from() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = install_root(&tmp);
        let key_file = root.join(".secret_key");
        assert!(!key_file.exists());

        run_genesis(
            &root,
            &ScriptedPresence::affirming("jordan"),
            &genesis_request(),
        )
        .expect("genesis");
        assert!(
            key_file.is_file(),
            "genesis must initialize the single deployment key source"
        );
    }

    #[test]
    fn genesis_reuses_an_existing_deployment_key_rather_than_rotating_it() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = install_root(&tmp);
        let paths_probe = ControlPaths::resolve(&root).expect("resolve");
        // Materialize the key through the same source production uses.
        paths_probe.key_source().initialize().expect("initialize");
        let before = std::fs::read(root.join(".secret_key")).expect("read key");

        run_genesis(
            &root,
            &ScriptedPresence::affirming("jordan"),
            &genesis_request(),
        )
        .expect("genesis");

        assert_eq!(
            std::fs::read(root.join(".secret_key")).expect("read key"),
            before,
            "ADR-013: initialization is not rotation"
        );
    }

    // -- re-running refuses -------------------------------------------------

    #[test]
    fn re_running_first_genesis_refuses() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = install_root(&tmp);
        let first = run_genesis(
            &root,
            &ScriptedPresence::affirming("jordan"),
            &genesis_request(),
        )
        .expect("first genesis");

        let second_presence = ScriptedPresence::affirming("attacker");
        let err = run_genesis(&root, &second_presence, &genesis_request())
            .expect_err("a second genesis must refuse");
        assert_eq!(err.code, CeremonyErrorCode::AlreadyManaged);
        assert!(
            second_presence.requests().is_empty(),
            "an ineligible root must refuse before prompting anyone"
        );

        // The original record is untouched.
        let paths = ControlPaths::resolve(&root).expect("resolve");
        let state = classify(&paths, &paths.key_source());
        assert_eq!(
            state.record().expect("managed").instance_id,
            first.instance_id
        );
    }

    #[test]
    fn genesis_refuses_on_a_recovery_only_root() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = install_root(&tmp);
        run_genesis(
            &root,
            &ScriptedPresence::affirming("jordan"),
            &genesis_request(),
        )
        .expect("genesis");

        let paths = ControlPaths::resolve(&root).expect("resolve");
        std::fs::write(paths.genesis_record(), b"{ corrupted").expect("corrupt");

        let presence = ScriptedPresence::affirming("attacker");
        let err = run_genesis(&root, &presence, &genesis_request())
            .expect_err("recovery-only must refuse genesis");
        assert_eq!(err.code, CeremonyErrorCode::RecoveryOnly);
        assert!(
            err.detail
                .contains(RecoveryReason::RecordUnparseable.wire()),
            "the refusal must be reportable: {}",
            err.detail
        );
        assert!(presence.requests().is_empty());
    }

    #[test]
    fn genesis_refuses_a_root_carrying_state_it_did_not_write() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = install_root(&tmp);
        let paths = ControlPaths::resolve(&root).expect("resolve");
        std::fs::create_dir_all(paths.control_dir()).expect("mkdir");
        std::fs::write(paths.target_registry(), b"{}").expect("plant a registry");

        let err = run_genesis(
            &root,
            &ScriptedPresence::affirming("jordan"),
            &genesis_request(),
        )
        .expect_err("orphaned state must refuse");
        assert_eq!(err.code, CeremonyErrorCode::StateAlreadyPresent);
    }

    // -- presence -----------------------------------------------------------

    #[test]
    fn genesis_refuses_without_a_controlling_terminal() {
        // Guarded by mutation check: accepting a non-TTY in
        // `TerminalConfirmation` must make this test fail.
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = install_root(&tmp);

        // The real adapter, under a test harness, which has no terminal.
        let err = run_genesis(&root, &TerminalConfirmation::new(), &genesis_request())
            .expect_err("a headless host must refuse the terminal ceremony");
        assert_eq!(err.code, CeremonyErrorCode::PresenceUnavailable);
        assert_eq!(
            TerminalConfirmation::new()
                .confirm(&PresenceRequest {
                    prompt: "x".to_string(),
                    operator_prompt: None,
                })
                .expect_err("no terminal"),
            PresenceError::NoControllingTerminal,
            "the refusal must be 'nobody to ask', not 'somebody said no'"
        );

        let paths = ControlPaths::resolve(&root).expect("resolve");
        assert!(
            !paths.genesis_record().exists(),
            "a refused ceremony must leave no record behind"
        );
    }

    #[test]
    fn a_declined_ceremony_writes_nothing() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = install_root(&tmp);
        let err = run_genesis(
            &root,
            &ScriptedPresence::failing(PresenceError::Declined),
            &genesis_request(),
        )
        .expect_err("a decline must refuse");
        assert_eq!(err.code, CeremonyErrorCode::PresenceDeclined);

        let paths = ControlPaths::resolve(&root).expect("resolve");
        assert!(!paths.genesis_record().exists());
        assert!(!paths.target_registry().exists());
        assert!(
            classify(&paths, &paths.key_source()).is_eligible_for_first_genesis(),
            "a declined ceremony must leave the root exactly as it was"
        );
    }

    #[test]
    fn a_ceremony_that_attests_no_operator_identity_refuses() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = install_root(&tmp);
        // An adapter that affirms but yields no identity.
        struct Silent;
        impl UserPresence for Silent {
            fn confirm(
                &self,
                _request: &PresenceRequest,
            ) -> Result<PresenceAttestation, PresenceError> {
                Ok(PresenceAttestation {
                    class: PresenceClass::Terminal,
                    operator_identity: None,
                })
            }
        }
        let err = run_genesis(&root, &Silent, &genesis_request())
            .expect_err("genesis needs a first operator");
        assert_eq!(err.code, CeremonyErrorCode::PresenceUnavailable);
    }

    #[test]
    fn the_confirmation_answer_is_exact() {
        assert_eq!(TERMINAL_CONFIRMATION_ANSWER, "yes");
        for near_miss in ["y", "Y", "YES", "yes please", "", "no"] {
            assert_ne!(
                near_miss, TERMINAL_CONFIRMATION_ANSWER,
                "{near_miss:?} must not authorize a trust root"
            );
        }
    }

    // -- symlinked roots ----------------------------------------------------

    #[cfg(unix)]
    #[test]
    fn genesis_refuses_a_symlinked_data_root() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = tmp.path().join("install");
        std::fs::create_dir_all(&root).expect("mkdir");
        let elsewhere = tmp.path().join("elsewhere");
        std::fs::create_dir_all(&elsewhere).expect("mkdir");
        std::os::unix::fs::symlink(&elsewhere, root.join("data")).expect("symlink");

        let presence = ScriptedPresence::affirming("jordan");
        let err = run_genesis(&root, &presence, &genesis_request())
            .expect_err("a symlinked data root must refuse");
        assert_eq!(err.code, CeremonyErrorCode::RootUnusable);
        assert!(presence.requests().is_empty());
    }

    // -- bootstrap client registration -------------------------------------

    #[test]
    fn genesis_can_register_the_first_client_in_the_same_session() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = install_root(&tmp);
        let credential_path = tmp.path().join("claude-code.cred");
        let mut request = genesis_request();
        request.register_client = Some(client_request(credential_path.clone()));

        let presence = ScriptedPresence::affirming("jordan");
        let outcome = run_genesis(&root, &presence, &request).expect("genesis with registration");

        let registered = outcome
            .registered_client
            .as_ref()
            .expect("a client was requested");
        assert_eq!(registered.client_label.as_str(), "claude-code");
        assert_eq!(registered.credential_path, credential_path);
        assert!(credential_path.is_file());

        // One presence session covered both, which is the ADR-016 bound.
        assert_eq!(presence.requests().len(), 1);

        // The registration authenticates with the delivered credential.
        let paths = ControlPaths::resolve(&root).expect("resolve");
        let key =
            ApprovalAuditKey::derive(&paths.key_source(), TrustEpoch::GENESIS).expect("derive");
        let clients = client_registry::load(&paths, &key).expect("client registry must verify");
        let registration = clients
            .get(&registered.registration_id)
            .expect("the registration is stored");
        let delivered = ClientCredential::from_delivery_hex(
            &std::fs::read_to_string(&credential_path).expect("read credential"),
        )
        .expect("parse credential");
        assert!(registration.authenticate(&delivered, &key));

        // And it is anchored to the ceremony rather than to a receipt.
        assert_eq!(
            registration.created_by_genesis_digest,
            outcome.genesis_digest
        );
        assert_eq!(
            registration.ceremony_presence_class,
            PresenceClass::Terminal
        );
        assert!(registration.covers_instance(&outcome.instance_id));
    }

    #[test]
    fn a_credential_path_inside_a_workspace_refuses_before_genesis_runs() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = install_root(&tmp);
        let workspace = root.join("data");
        let mut registration = client_request(workspace.join("leaked.cred"));
        registration.forbidden_credential_roots = vec![workspace];
        let mut request = genesis_request();
        request.register_client = Some(registration);

        let presence = ScriptedPresence::affirming("jordan");
        let err = run_genesis(&root, &presence, &request)
            .expect_err("a credential inside a workspace must refuse");
        assert_eq!(err.code, CeremonyErrorCode::CredentialNotDelivered);
        assert!(
            presence.requests().is_empty(),
            "the path check must run before the prompt"
        );

        let paths = ControlPaths::resolve(&root).expect("resolve");
        assert!(!paths.genesis_record().exists());
    }

    #[test]
    fn a_credential_path_that_already_exists_refuses() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = install_root(&tmp);
        let credential_path = tmp.path().join("taken.cred");
        std::fs::write(&credential_path, b"someone else's").expect("write");
        let mut request = genesis_request();
        request.register_client = Some(client_request(credential_path.clone()));

        let err = run_genesis(&root, &ScriptedPresence::affirming("jordan"), &request)
            .expect_err("an occupied credential path must refuse");
        assert_eq!(err.code, CeremonyErrorCode::CredentialNotDelivered);
        assert_eq!(
            std::fs::read(&credential_path).expect("read"),
            b"someone else's"
        );
    }

    // -- standalone registration -------------------------------------------

    #[test]
    fn register_client_runs_the_same_ceremony_on_a_managed_instance() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = install_root(&tmp);
        let outcome = run_genesis(
            &root,
            &ScriptedPresence::affirming("jordan"),
            &genesis_request(),
        )
        .expect("genesis");

        let credential_path = tmp.path().join("later.cred");
        let presence = ScriptedPresence::affirming("jordan");
        let registered = run_register_client(
            &root,
            &presence,
            "Authorize client registration? ".to_string(),
            &client_request(credential_path.clone()),
        )
        .expect("registration");

        assert_eq!(presence.requests().len(), 1);
        assert!(
            presence.requests()[0].operator_prompt.is_none(),
            "genesis already established the operator"
        );
        assert!(credential_path.is_file());

        let paths = ControlPaths::resolve(&root).expect("resolve");
        let key =
            ApprovalAuditKey::derive(&paths.key_source(), TrustEpoch::GENESIS).expect("derive");
        let clients = client_registry::load(&paths, &key).expect("load");
        assert_eq!(clients.len(), 1);
        let registration = clients.get(&registered.registration_id).expect("stored");
        assert!(registration.covers_instance(&outcome.instance_id));
    }

    #[test]
    fn register_client_appends_rather_than_replacing() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = install_root(&tmp);
        let mut request = genesis_request();
        request.register_client = Some(client_request(tmp.path().join("first.cred")));
        run_genesis(&root, &ScriptedPresence::affirming("jordan"), &request).expect("genesis");

        run_register_client(
            &root,
            &ScriptedPresence::affirming("jordan"),
            "Authorize? ".to_string(),
            &client_request(tmp.path().join("second.cred")),
        )
        .expect("second registration");

        let paths = ControlPaths::resolve(&root).expect("resolve");
        let key =
            ApprovalAuditKey::derive(&paths.key_source(), TrustEpoch::GENESIS).expect("derive");
        assert_eq!(client_registry::load(&paths, &key).expect("load").len(), 2);
    }

    #[test]
    fn register_client_refuses_before_genesis() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = install_root(&tmp);
        let presence = ScriptedPresence::affirming("jordan");
        let err = run_register_client(
            &root,
            &presence,
            "Authorize? ".to_string(),
            &client_request(tmp.path().join("c.cred")),
        )
        .expect_err("registration needs a trust root");
        assert_eq!(err.code, CeremonyErrorCode::NotManaged);
        assert!(presence.requests().is_empty());
    }

    #[test]
    fn register_client_refuses_in_recovery_only_mode() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = install_root(&tmp);
        run_genesis(
            &root,
            &ScriptedPresence::affirming("jordan"),
            &genesis_request(),
        )
        .expect("genesis");

        let paths = ControlPaths::resolve(&root).expect("resolve");
        // Tamper with the record: present but no longer authentic.
        let raw = std::fs::read(paths.genesis_record()).expect("read");
        let mut value: serde_json::Value = serde_json::from_slice(&raw).expect("parse");
        value["payload"]["first_operator"] = serde_json::Value::String("attacker".to_string());
        std::fs::write(
            paths.genesis_record(),
            serde_json::to_vec(&value).expect("encode"),
        )
        .expect("write");

        let credential_path = tmp.path().join("c.cred");
        let presence = ScriptedPresence::affirming("attacker");
        let err = run_register_client(
            &root,
            &presence,
            "Authorize? ".to_string(),
            &client_request(credential_path.clone()),
        )
        .expect_err("recovery-only must refuse registration");
        assert_eq!(err.code, CeremonyErrorCode::RecoveryOnly);
        assert!(presence.requests().is_empty());
        assert!(!credential_path.exists());
    }

    #[test]
    fn register_client_refuses_when_the_target_registry_does_not_verify() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = install_root(&tmp);
        run_genesis(
            &root,
            &ScriptedPresence::affirming("jordan"),
            &genesis_request(),
        )
        .expect("genesis");

        let paths = ControlPaths::resolve(&root).expect("resolve");
        std::fs::write(paths.target_registry(), b"{ tampered").expect("tamper");

        let err = run_register_client(
            &root,
            &ScriptedPresence::affirming("jordan"),
            "Authorize? ".to_string(),
            &client_request(tmp.path().join("c.cred")),
        )
        .expect_err("an unverifiable registry must refuse registration");
        assert_eq!(err.code, CeremonyErrorCode::RegistryUnusable);
    }

    #[test]
    fn register_client_refuses_when_the_client_registry_does_not_verify() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = install_root(&tmp);
        let mut request = genesis_request();
        request.register_client = Some(client_request(tmp.path().join("first.cred")));
        run_genesis(&root, &ScriptedPresence::affirming("jordan"), &request).expect("genesis");

        let paths = ControlPaths::resolve(&root).expect("resolve");
        std::fs::write(paths.client_registry(), b"{ tampered").expect("tamper");

        let credential_path = tmp.path().join("second.cred");
        let presence = ScriptedPresence::affirming("jordan");
        let err = run_register_client(
            &root,
            &presence,
            "Authorize? ".to_string(),
            &client_request(credential_path.clone()),
        )
        .expect_err("an unverifiable client registry must refuse");
        assert_eq!(err.code, CeremonyErrorCode::ClientRegistryUnusable);
        assert!(
            presence.requests().is_empty(),
            "an unverifiable registry must refuse before prompting anyone"
        );
        assert!(
            !credential_path.exists(),
            "no credential may be delivered against a registry that will not load"
        );
    }

    #[test]
    fn register_client_refuses_without_a_controlling_terminal() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = install_root(&tmp);
        run_genesis(
            &root,
            &ScriptedPresence::affirming("jordan"),
            &genesis_request(),
        )
        .expect("genesis");

        let credential_path = tmp.path().join("c.cred");
        let err = run_register_client(
            &root,
            &TerminalConfirmation::new(),
            "Authorize? ".to_string(),
            &client_request(credential_path.clone()),
        )
        .expect_err("a headless host must refuse");
        assert_eq!(err.code, CeremonyErrorCode::PresenceUnavailable);
        assert!(!credential_path.exists());
    }
}
