//! ZeroClaw's transport-independent management core.
//!
//! [`ControlService`] is the management authority: it resolves the canonical
//! configuration, validates one typed operation against it, builds a preview
//! bound to that exact source revision, applies through Quickstart's
//! revision-bound transaction, and verifies the result. Every transport — the
//! terminal onboarding flow today, native tools and stdio MCP later — goes
//! through it rather than reimplementing its validators or persistence rules.
//!
//! [`ZeronaSession`] is the other half and deliberately not part of that
//! authority: it is a client-side adapter that holds an in-memory
//! capability-restricted provider conversation, exposes no tools, and produces
//! a narrowly typed agent proposal for the service to judge. Conversation,
//! model selection, approval prompting, and rendering all stay outside the
//! service.
//!
//! This crate deliberately sits above `zeroclaw-runtime`.

pub mod ceremony;
pub mod client_registry;
pub mod genesis;
mod guard;
mod inventory;
pub mod keys;
pub mod operator;
mod preview;
mod principal;
mod proposal;
pub mod protocol;
pub mod reachability;
pub mod registry;
pub mod registry_store;
mod service;
mod session;
pub mod store;

pub use ceremony::{
    CeremonyError, CeremonyErrorCode, GenesisOutcome, GenesisRequest, PresenceError,
    TerminalConfirmation, UserPresence, run_genesis, run_register_client,
};
pub use client_registry::{
    ClientCredential, ClientGrant, ClientLabel, ClientRegistration, ClientRegistry,
    ClientRegistryError, ClientRegistryErrorCode, CredentialDelivery, CredentialVerifier,
    RegistrationId, RegistrationStatus,
};
pub use genesis::{
    GenesisRecord, InstanceTrustState, KeyCommitment, PresenceClass, RecoveryReason,
};
pub use guard::{
    EffectivePosture, GuardCode, GuardError, assess_effective_posture, validate_operator_input,
};
pub use inventory::{
    CapabilityRestrictedProviderFactory, CurrentProviderFactory, IsolatedProvider, MemoryChoice,
    ProviderError, ProviderErrorCode, ProviderPickerInventory, ProviderTarget, RiskChoice,
    RuntimeChoice, SafeInventory, eligible_provider_refs,
};
pub use operator::{
    OperatorAuthentication, OperatorError, OperatorErrorCode, OperatorIdentity, OperatorOrigin,
    OperatorRecord, OperatorRegistry, OperatorStatus, PrincipalClass, RegisterOperatorRequest,
    RegisteredOperator, RequesterContext, RequesterFingerprint, RequesterSubject,
    authenticate_operator, run_register_operator,
};
pub use preview::{
    ApplyIntegration, PersistencePreview, PersonalityFilePreview, ProfileDisposition,
    ProposalPreview, RevisionBinding, build_preview,
};
pub use principal::{
    ACCEPTED_ASSURANCE_CLASSES, AuthenticatedClient, ControlSession, PROPOSAL_DOMAIN_AGENT,
    REJECTED_ASSURANCE_CLASSES, RequesterGrant, authenticate_client, registration_help,
};
#[cfg(feature = "fixture-grants")]
pub use principal::{FIXTURE_ASSURANCE_CLASS, FIXTURE_CREDENTIAL_MARKER};
pub use proposal::{
    AgentProposal, PROPOSAL_MARKER, PersonalityFileProposal, ProposalError, ProposalErrorCode,
    ValidatedProposal, parse_proposal, revalidate_proposal, validate_proposal,
};
pub use reachability::{Evidence, IsolationQuestion, Reachability};
pub use registry_store::{RegistryStoreError, RegistryStoreErrorCode};
pub use service::{
    BoundProposal, ControlApplyOutcome, ControlError, ControlInspection, ControlService,
    source_schema_is_current,
};
pub use session::{MAX_OPERATOR_TURNS, SessionError, SessionErrorCode, SessionTurn, ZeronaSession};
pub use store::{ControlPaths, StoreError, StoreErrorCode};

/// A user-facing localization request. The CLI owns the Fluent catalogue and
/// renders this key with these non-secret arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FluentMessage {
    pub key: &'static str,
    pub args: std::collections::BTreeMap<String, String>,
}

impl FluentMessage {
    #[must_use]
    pub fn new(key: &'static str) -> Self {
        Self {
            key,
            args: std::collections::BTreeMap::new(),
        }
    }

    #[must_use]
    pub fn with_arg(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.args.insert(key.into(), value.into());
        self
    }
}
