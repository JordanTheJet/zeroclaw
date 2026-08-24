//! The proposal-grant issuance ceremony.
//!
//! A registered external client is issued with read domains only. Until an
//! operator widens its grant to include a proposal domain,
//! [`crate::protocol::TOOL_REQUEST_APPLY`] refuses it — a read-only client
//! cannot park a proposal, so the mutation path is structurally unreachable in a
//! shipped build. This module owns the ceremony that widens the grant.
//!
//! ## Why this is a high-assurance operator ceremony
//!
//! The principals design lists "registering or widening an external client
//! grant" among the operations that are **permanently meta-authority**: no
//! adapter, policy value, protocol minor version, or deployment mode may move
//! one of these into a weaker class. Widening a grant is exactly the escalation
//! a requester must never be able to perform on itself, so this ceremony is
//! host-side only and authenticates a **registered, active operator** through
//! user presence, exactly like [`crate::management::enable_mutations`] and
//! [`crate::operator::run_register_operator`]. There is no tool, no MCP method,
//! and no daemon entry point that calls it: an MCP argument, an environment
//! variable, a TTY, a loopback address, the process parent, or the OS account
//! cannot reach it, and cannot supply the operator identity, which is attested
//! by the presence adapter and checked against the trust root.
//!
//! ## Operator presence, not a receipt
//!
//! Meta-authority operations normally consume a phase-4 approval receipt. The
//! receipt broker authenticates a *requester's* pending decision and is bound to
//! a proposal digest; there is no requester and no proposal in flight here, so —
//! as with genesis, operator registration, and mutation enablement — this
//! ceremony authenticates operator presence directly rather than minting and
//! consuming a receipt. When a stricter high-assurance adapter or a host-side
//! receipt path lands, this ceremony inherits it without a contract change.
//!
//! ## What it does not do
//!
//! It widens no read domain, mints no credential, and grants no approval
//! authority or tool to any agent. It adds exactly the v1 proposal domain(s) to
//! one named registration and records the widening's provenance. It never
//! touches a client's credential, so a widened client authenticates with the
//! same secret it already held.

use std::collections::BTreeSet;
use std::path::Path;

use crate::ceremony::{PresenceError, PresenceRequest, UserPresence};
use crate::client_registry::{
    self, ClientLabel, ClientRegistry, ClientRegistryError, ClientRegistryErrorCode,
    PROPOSAL_DOMAINS_V1, RegistrationId, RegistrationStatus,
};
use crate::genesis::{InstanceTrustState, classify, now_unix_secs};
use crate::keys::ApprovalAuditKey;
use crate::operator::{self, OperatorIdentity};
use crate::store::ControlPaths;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Why the grant-proposal ceremony refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantErrorCode {
    /// The install root could not be resolved, or a root is symlinked.
    RootUnusable,
    /// This instance has no verified genesis record.
    NotManaged,
    /// This instance is in recovery-only mode.
    RecoveryOnly,
    /// The deployment key source could not be read.
    KeySourceUnusable,
    /// The operator or client registry could not be loaded or verified.
    RegistryUnusable,
    /// No client registry exists, so there is no registered client to widen.
    NoRegisteredClients,
    /// No registration with the requested id is present.
    UnknownRegistration,
    /// The named registration is revoked.
    RegistrationRevoked,
    /// No presence attestation was produced.
    PresenceUnavailable,
    /// A human declined.
    PresenceDeclined,
    /// The presence ceremony attested no operator identity.
    NoOperatorAttested,
    /// The attested identity is not a registered, active operator.
    OperatorNotRegistered,
    /// The widened registry could not be written.
    NotWritten,
}

/// A grant-proposal refusal. `detail` never carries credential bytes or key
/// material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantError {
    pub code: GrantErrorCode,
    pub detail: String,
}

impl GrantError {
    fn new(code: GrantErrorCode, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }
}

impl std::fmt::Display for GrantError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let what = match self.code {
            GrantErrorCode::RootUnusable => "instance root is unusable",
            GrantErrorCode::NotManaged => "this instance has no verified control-plane trust root",
            GrantErrorCode::RecoveryOnly => "this instance is in recovery-only mode",
            GrantErrorCode::KeySourceUnusable => "the deployment key source is unusable",
            GrantErrorCode::RegistryUnusable => "a control registry could not be verified",
            GrantErrorCode::NoRegisteredClients => "no client is registered on this instance",
            GrantErrorCode::UnknownRegistration => "no such client registration",
            GrantErrorCode::RegistrationRevoked => "the client registration is revoked",
            GrantErrorCode::PresenceUnavailable => "no user-presence attestation was produced",
            GrantErrorCode::PresenceDeclined => "the ceremony was declined",
            GrantErrorCode::NoOperatorAttested => "the ceremony attested no operator identity",
            GrantErrorCode::OperatorNotRegistered => {
                "the attested identity is not a registered operator"
            }
            GrantErrorCode::NotWritten => "the client registry could not be written",
        };
        write!(f, "{what}: {}", self.detail)
    }
}

impl std::error::Error for GrantError {}

fn from_presence(error: PresenceError) -> GrantError {
    match error {
        PresenceError::Declined => {
            GrantError::new(GrantErrorCode::PresenceDeclined, error.to_string())
        }
        PresenceError::NoControllingTerminal
        | PresenceError::InvalidOperatorIdentity(_)
        | PresenceError::Io(_) => {
            GrantError::new(GrantErrorCode::PresenceUnavailable, error.to_string())
        }
    }
}

/// Map a client-registry failure onto the ceremony's own vocabulary.
fn from_client_registry(error: ClientRegistryError) -> GrantError {
    match error.code {
        ClientRegistryErrorCode::NotPresent => {
            GrantError::new(GrantErrorCode::NoRegisteredClients, error.detail)
        }
        ClientRegistryErrorCode::UnknownRegistration => {
            GrantError::new(GrantErrorCode::UnknownRegistration, error.detail)
        }
        ClientRegistryErrorCode::RegistrationRevoked => {
            GrantError::new(GrantErrorCode::RegistrationRevoked, error.detail)
        }
        ClientRegistryErrorCode::NotWritten => {
            GrantError::new(GrantErrorCode::NotWritten, error.detail)
        }
        _ => GrantError::new(GrantErrorCode::RegistryUnusable, error.to_string()),
    }
}

// ---------------------------------------------------------------------------
// Outcome
// ---------------------------------------------------------------------------

/// What a grant-proposal ceremony established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProposalGrantIssued {
    /// The registration that was widened.
    pub registration_id: RegistrationId,
    /// Its display label, for the operator-facing summary.
    pub client_label: ClientLabel,
    /// The operator that authorized the widening. Attribution only.
    pub granting_operator: String,
    /// The presence assurance class the granting operator authenticated under.
    pub assurance_class: String,
    /// Every proposal domain the registration now holds.
    pub proposal_domains: BTreeSet<String>,
    /// Whether this run added anything. `false` is the idempotent no-op, where
    /// the client already held the domain.
    pub newly_granted: bool,
    /// Wall-clock time of the widening, seconds since the Unix epoch.
    pub granted_at_unix_secs: u64,
}

// ---------------------------------------------------------------------------
// The ceremony
// ---------------------------------------------------------------------------

/// Widen the named client's grant to include the v1 proposal domain(s).
///
/// Host-side only. Requires a managed instance, a usable key source, a known
/// active registration, and an OS-mediated user-presence attestation naming a
/// **registered, active** operator. It is idempotent: granting a domain a client
/// already holds succeeds and adds nothing.
///
/// # Errors
///
/// See [`GrantErrorCode`]. Every failure is a refusal; nothing partial is
/// written and no refusal downgrades to a weaker authentication.
pub fn grant_proposal_domains(
    install_root: &Path,
    presence: &dyn UserPresence,
    registration_id: &RegistrationId,
    prompt: String,
    operator_prompt: String,
) -> Result<ProposalGrantIssued, GrantError> {
    let paths = ControlPaths::resolve(install_root)
        .map_err(|e| GrantError::new(GrantErrorCode::RootUnusable, e.detail))?;
    let key_source = paths.key_source();

    let record = match classify(&paths, &key_source) {
        InstanceTrustState::Managed(record) => *record,
        InstanceTrustState::EligibleForFirstGenesis => {
            return Err(GrantError::new(
                GrantErrorCode::NotManaged,
                "run genesis first",
            ));
        }
        InstanceTrustState::RecoveryOnly { reason, .. } => {
            return Err(GrantError::new(GrantErrorCode::RecoveryOnly, reason.wire()));
        }
    };

    let key = ApprovalAuditKey::derive(&key_source, record.trust_epoch)
        .map_err(|e| GrantError::new(GrantErrorCode::KeySourceUnusable, format!("{e:#}")))?;

    // The operator registry (including the genesis first operator) is loaded
    // before the prompt so an unregistered claim never causes a terminal
    // interruption for a ceremony that would refuse anyway.
    let operators = operator::load_view(&paths, &record, &key)
        .map_err(|e| GrantError::new(GrantErrorCode::RegistryUnusable, e.to_string()))?;

    // Verify the client registry and the target registration before prompting,
    // so an unknown or revoked client refuses without troubling the operator.
    let existing = load_clients(&paths, &key)?;
    match existing.get(registration_id) {
        None => {
            return Err(GrantError::new(
                GrantErrorCode::UnknownRegistration,
                registration_id.as_str().to_owned(),
            ));
        }
        Some(registration) if registration.status != RegistrationStatus::Active => {
            return Err(GrantError::new(
                GrantErrorCode::RegistrationRevoked,
                registration_id.as_str().to_owned(),
            ));
        }
        Some(_) => {}
    }

    let attestation = presence
        .confirm(&PresenceRequest {
            prompt,
            operator_prompt: Some(operator_prompt),
        })
        .map_err(from_presence)?;

    let Some(attested) = attestation.operator_identity() else {
        return Err(GrantError::new(
            GrantErrorCode::NoOperatorAttested,
            "the ceremony attested no operator identity",
        ));
    };
    let operator_label = attested.as_str().to_owned();
    let claimed = OperatorIdentity::from(attested.clone());
    if operators.get_active(&claimed).is_none() {
        // Do not echo the attested label: it is text just typed at a prompt
        // that failed a trust check.
        return Err(GrantError::new(
            GrantErrorCode::OperatorNotRegistered,
            "the attested operator is not registered",
        ));
    }

    let now = now_unix_secs().map_err(|e| GrantError::new(GrantErrorCode::NotWritten, e.detail))?;
    let assurance_class = attestation.class().wire().to_owned();

    // Re-read after the prompt rather than reusing the pre-prompt copy: a human
    // typing is an unbounded window, and this crate has no registry lock yet.
    // The widen re-checks unknown and revoked, so a registration revoked during
    // the prompt is still refused here.
    let mut registry = load_clients(&paths, &key)?;
    let outcome = registry
        .widen_proposal_domains(
            registration_id,
            PROPOSAL_DOMAINS_V1,
            &operator_label,
            &assurance_class,
            now,
        )
        .map_err(from_client_registry)?;

    client_registry::save(&paths, &registry, &key).map_err(from_client_registry)?;

    Ok(ProposalGrantIssued {
        registration_id: outcome.registration_id,
        client_label: outcome.client_label,
        granting_operator: operator_label,
        assurance_class,
        newly_granted: !outcome.newly_granted.is_empty(),
        proposal_domains: outcome.proposal_domains,
        granted_at_unix_secs: now,
    })
}

/// Load the client registry, mapping an absent one to
/// [`GrantErrorCode::NoRegisteredClients`].
fn load_clients(
    paths: &ControlPaths,
    key: &ApprovalAuditKey,
) -> Result<ClientRegistry, GrantError> {
    client_registry::load(paths, key).map_err(from_client_registry)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client_registry::{
        ClientGrant, ClientLabel, ClientRegistration, CredentialDelivery, PROPOSAL_DOMAINS_V1,
    };
    use crate::genesis::PresenceClass;
    use crate::principal::PROPOSAL_DOMAIN_AGENT;
    use crate::registry::InstanceId;
    use crate::test_support::{ScriptedPresence, genesis_instance, key_for};

    /// Issue and save a read-only client (every read domain, no proposal domain)
    /// on the managed instance, returning its registration id.
    fn register_read_only_client(paths: &ControlPaths, key: &ApprovalAuditKey) -> RegistrationId {
        let record = crate::genesis::classify(paths, &paths.key_source())
            .record()
            .expect("managed")
            .clone();
        let instance = record.instance_id.clone();
        let grant = ClientGrant {
            client_label: ClientLabel::new("read-only-client").expect("label"),
            delivery_assurance: CredentialDelivery::IsolatedDescriptor,
            granted_instances: [instance].into_iter().collect(),
            granted_read_domains: client_registry::READ_DOMAINS_V1
                .iter()
                .map(|d| (*d).to_string())
                .collect(),
            proposal_domains: BTreeSet::new(),
        };
        let issued = ClientRegistration::issue(
            &grant,
            record.trust_epoch,
            now_unix_secs().expect("clock"),
            record.digest(),
            PresenceClass::Terminal,
            key,
        )
        .expect("issue");
        let id = issued.registration.registration_id.clone();
        let mut registry = ClientRegistry::new();
        registry.insert(issued.registration).expect("insert");
        client_registry::save_new(paths, &registry, key).expect("save");
        id
    }

    #[test]
    fn an_operator_widens_a_read_only_client_and_the_grant_reloads() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (root, paths, record) = genesis_instance(&tmp);
        let key = key_for(&paths, &record);
        let id = register_read_only_client(&paths, &key);

        let outcome = grant_proposal_domains(
            &root,
            &ScriptedPresence::affirming("jordan"),
            &id,
            "Grant? ".to_string(),
            "Operator: ".to_string(),
        )
        .expect("the ceremony widens the grant");
        assert!(outcome.newly_granted);
        assert_eq!(outcome.granting_operator, "jordan");
        assert!(outcome.proposal_domains.contains(PROPOSAL_DOMAIN_AGENT));

        // Sealed and reloadable: a fresh load sees the widened grant and its
        // recorded provenance.
        let reloaded = client_registry::load(&paths, &key).expect("reload");
        let registration = reloaded.get(&id).expect("present");
        assert!(registration.covers_proposal_domain(PROPOSAL_DOMAIN_AGENT));
        assert_eq!(registration.proposal_grant_audit.len(), 1);
        assert_eq!(
            registration.proposal_grant_audit[0].granting_operator,
            "jordan"
        );
    }

    #[test]
    fn widening_is_idempotent_across_two_ceremonies() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (root, paths, record) = genesis_instance(&tmp);
        let key = key_for(&paths, &record);
        let id = register_read_only_client(&paths, &key);

        let first = grant_proposal_domains(
            &root,
            &ScriptedPresence::affirming("jordan"),
            &id,
            "Grant? ".to_string(),
            "Operator: ".to_string(),
        )
        .expect("first");
        assert!(first.newly_granted);

        let second = grant_proposal_domains(
            &root,
            &ScriptedPresence::affirming("jordan"),
            &id,
            "Grant? ".to_string(),
            "Operator: ".to_string(),
        )
        .expect("second");
        assert!(!second.newly_granted, "a second grant adds nothing");

        let reloaded = client_registry::load(&paths, &key).expect("reload");
        assert_eq!(
            reloaded
                .get(&id)
                .expect("present")
                .proposal_grant_audit
                .len(),
            1,
            "an already-granted domain records no second audit entry"
        );
    }

    #[test]
    fn an_unregistered_operator_is_refused_and_the_grant_is_untouched() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (root, paths, record) = genesis_instance(&tmp);
        let key = key_for(&paths, &record);
        let id = register_read_only_client(&paths, &key);

        // "mallory" is not the genesis operator "jordan" and was never
        // registered. This is the guard mutation check (1) targets: accepting a
        // non-operator here must make this test fail.
        let refusal = grant_proposal_domains(
            &root,
            &ScriptedPresence::affirming("mallory"),
            &id,
            "Grant? ".to_string(),
            "Operator: ".to_string(),
        )
        .expect_err("an unregistered operator must be refused");
        assert_eq!(refusal.code, GrantErrorCode::OperatorNotRegistered);

        let reloaded = client_registry::load(&paths, &key).expect("reload");
        assert!(
            !reloaded
                .get(&id)
                .expect("present")
                .covers_proposal_domain(PROPOSAL_DOMAIN_AGENT),
            "a refused ceremony grants nothing"
        );
    }

    #[test]
    fn a_ceremony_that_attests_no_operator_is_refused() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (root, paths, record) = genesis_instance(&tmp);
        let key = key_for(&paths, &record);
        let id = register_read_only_client(&paths, &key);

        let refusal = grant_proposal_domains(
            &root,
            &ScriptedPresence::affirming_without_identity(),
            &id,
            "Grant? ".to_string(),
            "Operator: ".to_string(),
        )
        .expect_err("no attested operator must be refused");
        assert_eq!(refusal.code, GrantErrorCode::NoOperatorAttested);
    }

    #[test]
    fn no_controlling_terminal_is_refused() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (root, paths, record) = genesis_instance(&tmp);
        let key = key_for(&paths, &record);
        let id = register_read_only_client(&paths, &key);

        let refusal = grant_proposal_domains(
            &root,
            &ScriptedPresence::failing(PresenceError::NoControllingTerminal),
            &id,
            "Grant? ".to_string(),
            "Operator: ".to_string(),
        )
        .expect_err("no presence must be refused");
        assert_eq!(refusal.code, GrantErrorCode::PresenceUnavailable);
    }

    #[test]
    fn an_unknown_registration_is_refused_before_prompting() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (root, paths, record) = genesis_instance(&tmp);
        let key = key_for(&paths, &record);
        let _present = register_read_only_client(&paths, &key);

        let presence = ScriptedPresence::affirming("jordan");
        let missing = RegistrationId::new("reg-missing").expect("id");
        let refusal = grant_proposal_domains(
            &root,
            &presence,
            &missing,
            "Grant? ".to_string(),
            "Operator: ".to_string(),
        )
        .expect_err("unknown registration must be refused");
        assert_eq!(refusal.code, GrantErrorCode::UnknownRegistration);
        assert_eq!(presence.prompts(), 0, "an unknown client never prompts");
    }

    #[test]
    fn a_revoked_registration_is_refused() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (root, paths, record) = genesis_instance(&tmp);
        let key = key_for(&paths, &record);
        let id = register_read_only_client(&paths, &key);

        // Revoke it directly in the sealed registry.
        let mut registry = client_registry::load(&paths, &key).expect("load");
        let mut replacement = ClientRegistry::new();
        for registration in registry.iter() {
            let mut copy = registration.clone();
            if copy.registration_id == id {
                copy.status = RegistrationStatus::Revoked;
            }
            replacement.insert(copy).expect("insert");
        }
        registry = replacement;
        client_registry::save(&paths, &registry, &key).expect("save");

        let refusal = grant_proposal_domains(
            &root,
            &ScriptedPresence::affirming("jordan"),
            &id,
            "Grant? ".to_string(),
            "Operator: ".to_string(),
        )
        .expect_err("a revoked registration must be refused");
        assert_eq!(refusal.code, GrantErrorCode::RegistrationRevoked);
    }

    #[test]
    fn an_instance_with_no_registered_clients_is_refused() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (root, _paths, _record) = genesis_instance(&tmp);
        let id = RegistrationId::new("reg-anything").expect("id");

        let refusal = grant_proposal_domains(
            &root,
            &ScriptedPresence::affirming("jordan"),
            &id,
            "Grant? ".to_string(),
            "Operator: ".to_string(),
        )
        .expect_err("no client registry must be refused");
        assert_eq!(refusal.code, GrantErrorCode::NoRegisteredClients);
    }

    #[test]
    fn an_unmanaged_instance_is_refused() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = crate::test_support::install_root(&tmp);
        let id = RegistrationId::new("reg-anything").expect("id");

        let refusal = grant_proposal_domains(
            &root,
            &ScriptedPresence::affirming("jordan"),
            &id,
            "Grant? ".to_string(),
            "Operator: ".to_string(),
        )
        .expect_err("an unmanaged instance must be refused");
        assert_eq!(refusal.code, GrantErrorCode::NotManaged);
    }

    #[test]
    fn the_v1_proposal_vocabulary_is_the_one_agent_domain() {
        // Pins what the ceremony grants: exactly the agent proposal domain.
        assert_eq!(PROPOSAL_DOMAINS_V1, &[PROPOSAL_DOMAIN_AGENT]);
        let _ = InstanceId::new("inst-ignored");
    }
}
