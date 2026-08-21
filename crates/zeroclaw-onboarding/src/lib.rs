//! Zerona's capability-free, guided agent-creation conversation.
//!
//! This crate deliberately sits above `zeroclaw-runtime`. It keeps an
//! in-memory provider conversation, exposes no tools, reads a borrowed live
//! [`zeroclaw_config::schema::Config`] on every turn, and produces a narrowly
//! typed agent proposal. Preview and validation are pure. Persistence remains
//! a host concern: the root CLI passes the approved source bytes to
//! Quickstart's revision-bound add-agent path, which atomically replaces config
//! before committing its staged personality files.

mod guard;
mod inventory;
mod preview;
mod proposal;
mod session;

pub use guard::{
    EffectivePosture, GuardCode, GuardError, assess_effective_posture, validate_operator_input,
};
pub use inventory::{
    CapabilityRestrictedProviderFactory, CurrentProviderFactory, IsolatedProvider, MemoryChoice,
    ProviderError, ProviderErrorCode, ProviderPickerInventory, ProviderTarget, RiskChoice,
    RuntimeChoice, SafeInventory, eligible_provider_refs,
};
pub use preview::{
    ApplyIntegration, PersistencePreview, PersonalityFilePreview, ProfileDisposition,
    ProposalPreview, RevisionBinding, build_preview,
};
pub use proposal::{
    AgentProposal, PROPOSAL_MARKER, PersonalityFileProposal, ProposalError, ProposalErrorCode,
    ValidatedProposal, parse_proposal, revalidate_proposal, validate_proposal,
};
pub use session::{MAX_OPERATOR_TURNS, SessionError, SessionErrorCode, SessionTurn, ZeronaSession};

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
