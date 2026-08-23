//! Which control-plane operations are permanently meta-authority.
//!
//! The parent architecture document lists the operations that are
//! *permanently* meta-authority, and "permanently" is the load-bearing word: no
//! adapter, policy value, protocol minor version, or deployment mode may move
//! one of them into a weaker class. Non-escalation rule 13 states it
//! normatively:
//!
//! > **Meta-authority cannot be declassified.** Meta-authority changes always
//! > use the strongest confirmation tier and can never be placed in a
//! > no-approval class, including by a later adapter, policy value, or protocol
//! > minor version.
//!
//! # How that rule is made unbreakable here
//!
//! Three structural choices, rather than three comments:
//!
//! 1. **There is no no-approval tier to be placed into.** [`AuthorityTier`] has
//!    exactly two variants and [`AuthorityTier::requires_approval`] returns
//!    `true` for both. A declassification would have to *add a variant*, which
//!    is a visible type change, not a configuration value. The first stable
//!    protocol has no unapproved mutation class at all, and this type is that
//!    statement.
//! 2. **The classification is a total function of the operation alone.**
//!    [`ControlOperation::authority_tier`] is an exhaustive `match` over a
//!    closed enum with no policy, config, adapter, or protocol-version
//!    parameter. There is nothing to pass that could change an answer.
//! 3. **The set is pinned by a test, not just by the match.**
//!    [`ControlOperation::PERMANENTLY_META_AUTHORITY`] enumerates the design's
//!    list, and a test asserts every member classifies as meta-authority, takes
//!    the strongest confirmation, and is unproposable. Moving one out of the
//!    list fails that test.
//!
//! # Why no requester can propose a meta-authority operation
//!
//! [`ControlOperation::proposal_domain`] returns `None` for every
//! meta-authority operation. A requester's authority is the intersection of its
//! grant with the operation class, and a grant can only name domains from the
//! closed [`crate::client_registry::PROPOSAL_DOMAINS_V1`] vocabulary — which
//! contains no meta-authority domain. So there is no grant, however wide, that
//! reaches one. This is non-escalation rule 11 ("a requester cannot reach the
//! trust root") expressed as an absence rather than as a check that could be
//! forgotten.
//!
//! Meta-authority operations are consequently reachable only host-side, from a
//! ceremony at a terminal — which is exactly how
//! [`crate::operator::run_register_operator`] and the ADR-016 bootstrap client
//! registration work.
//!
//! # Quorum
//!
//! [`required_quorum`] implements the design's confirmation-tier rules and the
//! maintainer's 2026-08-22 single-operator-now, quorum-ready decision. The
//! count it reads is the number of **configured** active operators, never the
//! number eligible for the requester at hand. That distinction is the whole of
//! the design's resolved open question 4: an operator made ineligible by
//! reachability does not lower the required quorum, because otherwise a
//! requester could reduce the quorum by becoming able to reach an operator.

use crate::principal::PROPOSAL_DOMAIN_AGENT;

/// How strong a confirmation an operation demands.
///
/// Deliberately has **no** `None` variant. There is no operation in this
/// protocol version that proceeds without an operator decision, so a tier
/// meaning "no confirmation" would be unreachable at best and a declassification
/// route at worst.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ConfirmationTier {
    /// The ordinary operator confirmation.
    Standard,
    /// The strongest tier this build defines. Every meta-authority operation
    /// takes it, unconditionally.
    Strongest,
}

impl ConfirmationTier {
    /// Every tier, in increasing strength.
    pub const ALL: &'static [Self] = &[Self::Standard, Self::Strongest];

    /// A stable, non-secret wire spelling.
    #[must_use]
    pub const fn wire(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::Strongest => "strongest",
        }
    }
}

impl std::fmt::Display for ConfirmationTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.wire())
    }
}

/// The authority class of one control-plane operation.
///
/// Two variants, both of which require an approval receipt. See the module
/// documentation for why there is no third.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AuthorityTier {
    /// A normal managed change, within a requester's granted proposal domains.
    Ordinary,
    /// A change to the trust root, the authority model, or anything that can
    /// widen either. Permanently the strongest tier.
    MetaAuthority,
}

impl AuthorityTier {
    /// Every tier.
    pub const ALL: &'static [Self] = &[Self::Ordinary, Self::MetaAuthority];

    /// A stable, non-secret wire spelling.
    #[must_use]
    pub const fn wire(self) -> &'static str {
        match self {
            Self::Ordinary => "ordinary",
            Self::MetaAuthority => "meta_authority",
        }
    }

    /// Whether an operation in this tier needs an approval receipt.
    ///
    /// `true` for every tier. The first stable protocol has no unapproved
    /// mutation class, and introducing one later requires a new architecture
    /// decision — not a new return value here.
    #[must_use]
    pub const fn requires_approval(self) -> bool {
        match self {
            Self::Ordinary | Self::MetaAuthority => true,
        }
    }

    /// The confirmation strength this tier demands.
    #[must_use]
    pub const fn confirmation(self) -> ConfirmationTier {
        match self {
            Self::Ordinary => ConfirmationTier::Standard,
            Self::MetaAuthority => ConfirmationTier::Strongest,
        }
    }
}

impl std::fmt::Display for AuthorityTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.wire())
    }
}

/// One typed control-plane operation.
///
/// Closed on purpose: an operation that is not named here has no authority tier
/// and therefore cannot be brokered at all, which is the fail-closed direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ControlOperation {
    // -- ordinary ----------------------------------------------------------
    /// Create a managed agent profile: the phase-2 proposal this crate already
    /// validates and previews.
    ProposeAgentProfile,

    // -- permanently meta-authority ----------------------------------------
    /// Enable management mutations on this instance.
    EnableManagementMutations,
    /// Change approval modes, groups, quorum, or principal links.
    ChangeApprovalPolicy,
    /// Change the configured operator backchannels.
    ChangeOperatorBackchannel,
    /// Change the management or audit key source.
    ChangeKeySource,
    /// Register a target root.
    RegisterTargetRoot,
    /// Register an approved creation parent.
    RegisterCreationParent,
    /// Register an external client grant.
    RegisterClientGrant,
    /// Widen an existing external client grant.
    WidenClientGrant,
    /// Change a registration's credential delivery assurance class.
    ChangeCredentialDeliveryAssurance,
    /// Create a child instance.
    CreateChildInstance,
    /// Change a child instance's inherited operator or trust set.
    ChangeInheritedTrustSet,
    /// Register an additional operator identity.
    RegisterOperator,
    /// Change a grant or binding that can expose or impersonate an operator
    /// backchannel identity.
    ExposeOperatorIdentity,
    /// Widen policy.
    WidenPolicy,
    /// Grant management authority to the requester.
    GrantManagementToRequester,
    /// Trust a plugin publisher.
    TrustPluginPublisher,
    /// Enable the external WASM plugin system.
    EnableExternalWasmPlugins,
    /// Change the rule that classifies an operation as requiring approval.
    ChangeApprovalClassifyingRule,
}

impl ControlOperation {
    /// Every operation this build defines.
    pub const ALL: &'static [Self] = &[
        Self::ProposeAgentProfile,
        Self::EnableManagementMutations,
        Self::ChangeApprovalPolicy,
        Self::ChangeOperatorBackchannel,
        Self::ChangeKeySource,
        Self::RegisterTargetRoot,
        Self::RegisterCreationParent,
        Self::RegisterClientGrant,
        Self::WidenClientGrant,
        Self::ChangeCredentialDeliveryAssurance,
        Self::CreateChildInstance,
        Self::ChangeInheritedTrustSet,
        Self::RegisterOperator,
        Self::ExposeOperatorIdentity,
        Self::WidenPolicy,
        Self::GrantManagementToRequester,
        Self::TrustPluginPublisher,
        Self::EnableExternalWasmPlugins,
        Self::ChangeApprovalClassifyingRule,
    ];

    /// The parent document's permanently meta-authority set, reproduced in
    /// full.
    ///
    /// Kept as an explicit list *in addition to* the `match` in
    /// [`Self::authority_tier`] so the two must agree. A test asserts exactly
    /// that, which turns "someone quietly reclassified an operation" from a
    /// review question into a build failure.
    pub const PERMANENTLY_META_AUTHORITY: &'static [Self] = &[
        Self::EnableManagementMutations,
        Self::ChangeApprovalPolicy,
        Self::ChangeOperatorBackchannel,
        Self::ChangeKeySource,
        Self::RegisterTargetRoot,
        Self::RegisterCreationParent,
        Self::RegisterClientGrant,
        Self::WidenClientGrant,
        Self::ChangeCredentialDeliveryAssurance,
        Self::CreateChildInstance,
        Self::ChangeInheritedTrustSet,
        Self::RegisterOperator,
        Self::ExposeOperatorIdentity,
        Self::WidenPolicy,
        Self::GrantManagementToRequester,
        Self::TrustPluginPublisher,
        Self::EnableExternalWasmPlugins,
        Self::ChangeApprovalClassifyingRule,
    ];

    /// A stable, non-secret wire spelling.
    #[must_use]
    pub const fn wire(self) -> &'static str {
        match self {
            Self::ProposeAgentProfile => "propose_agent_profile",
            Self::EnableManagementMutations => "enable_management_mutations",
            Self::ChangeApprovalPolicy => "change_approval_policy",
            Self::ChangeOperatorBackchannel => "change_operator_backchannel",
            Self::ChangeKeySource => "change_key_source",
            Self::RegisterTargetRoot => "register_target_root",
            Self::RegisterCreationParent => "register_creation_parent",
            Self::RegisterClientGrant => "register_client_grant",
            Self::WidenClientGrant => "widen_client_grant",
            Self::ChangeCredentialDeliveryAssurance => "change_credential_delivery_assurance",
            Self::CreateChildInstance => "create_child_instance",
            Self::ChangeInheritedTrustSet => "change_inherited_trust_set",
            Self::RegisterOperator => "register_operator",
            Self::ExposeOperatorIdentity => "expose_operator_identity",
            Self::WidenPolicy => "widen_policy",
            Self::GrantManagementToRequester => "grant_management_to_requester",
            Self::TrustPluginPublisher => "trust_plugin_publisher",
            Self::EnableExternalWasmPlugins => "enable_external_wasm_plugins",
            Self::ChangeApprovalClassifyingRule => "change_approval_classifying_rule",
        }
    }

    /// This operation's authority tier.
    ///
    /// A total function of the operation alone. There is no policy, adapter,
    /// deployment mode, or protocol version parameter, because there is no
    /// input that may change one of these answers.
    #[must_use]
    pub const fn authority_tier(self) -> AuthorityTier {
        match self {
            Self::ProposeAgentProfile => AuthorityTier::Ordinary,
            Self::EnableManagementMutations
            | Self::ChangeApprovalPolicy
            | Self::ChangeOperatorBackchannel
            | Self::ChangeKeySource
            | Self::RegisterTargetRoot
            | Self::RegisterCreationParent
            | Self::RegisterClientGrant
            | Self::WidenClientGrant
            | Self::ChangeCredentialDeliveryAssurance
            | Self::CreateChildInstance
            | Self::ChangeInheritedTrustSet
            | Self::RegisterOperator
            | Self::ExposeOperatorIdentity
            | Self::WidenPolicy
            | Self::GrantManagementToRequester
            | Self::TrustPluginPublisher
            | Self::EnableExternalWasmPlugins
            | Self::ChangeApprovalClassifyingRule => AuthorityTier::MetaAuthority,
        }
    }

    /// Whether this operation is meta-authority.
    #[must_use]
    pub const fn is_meta_authority(self) -> bool {
        matches!(self.authority_tier(), AuthorityTier::MetaAuthority)
    }

    /// The proposal domain a requester's grant would have to cover to propose
    /// this operation, or `None` when no requester can propose it at all.
    ///
    /// Every meta-authority operation returns `None`. See the module
    /// documentation: this is how "a requester cannot reach the trust root"
    /// becomes an absence rather than a check.
    #[must_use]
    pub const fn proposal_domain(self) -> Option<&'static str> {
        match self {
            Self::ProposeAgentProfile => Some(PROPOSAL_DOMAIN_AGENT),
            Self::EnableManagementMutations
            | Self::ChangeApprovalPolicy
            | Self::ChangeOperatorBackchannel
            | Self::ChangeKeySource
            | Self::RegisterTargetRoot
            | Self::RegisterCreationParent
            | Self::RegisterClientGrant
            | Self::WidenClientGrant
            | Self::ChangeCredentialDeliveryAssurance
            | Self::CreateChildInstance
            | Self::ChangeInheritedTrustSet
            | Self::RegisterOperator
            | Self::ExposeOperatorIdentity
            | Self::WidenPolicy
            | Self::GrantManagementToRequester
            | Self::TrustPluginPublisher
            | Self::EnableExternalWasmPlugins
            | Self::ChangeApprovalClassifyingRule => None,
        }
    }

    /// The confirmation strength this operation demands.
    #[must_use]
    pub const fn confirmation(self) -> ConfirmationTier {
        self.authority_tier().confirmation()
    }
}

impl std::fmt::Display for ControlOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.wire())
    }
}

/// How many distinct operator decisions an operation needs.
///
/// A newtype rather than a bare `u32` so a count of operators cannot be passed
/// where a quorum is expected, and so the invariant "never zero" lives in one
/// place.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RequiredQuorum(u32);

impl RequiredQuorum {
    /// The smallest quorum this protocol permits.
    ///
    /// One, never zero. A zero quorum would be an unapproved operation, which
    /// this protocol version does not have.
    pub const MINIMUM: Self = Self(1);

    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }

    /// Whether `decisions` distinct approving operators satisfy this quorum.
    #[must_use]
    pub const fn is_satisfied_by(self, decisions: u32) -> bool {
        decisions >= self.0
    }
}

impl std::fmt::Display for RequiredQuorum {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// The quorum an operation requires, given how many operators are configured.
///
/// The design's confirmation-tier rules:
///
/// - meta-authority changes always use the strongest confirmation tier;
/// - when at least two eligible operators exist, they require at least two
///   distinct operator principals; and
/// - a single-operator installation requires one user-presence-authenticated
///   operator distinct from the requester.
///
/// `configured_active_operators` must be the count of operators the instance
/// has **configured and active**, not the count eligible for the requester in
/// hand. Passing an eligibility-filtered count here would recreate exactly the
/// escalation the design's resolved open question 4 forbids: a requester could
/// drop a two-operator installation to the single-operator path by becoming
/// able to reach one operator.
///
/// # Phase-4 enforcement bound
///
/// This function is quorum-*ready*: it returns 2 for a meta-authority operation
/// on a two-operator installation. Phase 4 collects exactly one operator
/// authentication, so the broker refuses such a request rather than approving
/// it with one decision. That is the fail-closed direction, and it is what lets
/// 2-of-N be turned on later without redesigning the receipt.
#[must_use]
pub const fn required_quorum(
    tier: AuthorityTier,
    configured_active_operators: usize,
) -> RequiredQuorum {
    match tier {
        AuthorityTier::Ordinary => RequiredQuorum::MINIMUM,
        AuthorityTier::MetaAuthority => {
            if configured_active_operators >= 2 {
                RequiredQuorum(2)
            } else {
                RequiredQuorum::MINIMUM
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client_registry::PROPOSAL_DOMAINS_V1;

    #[test]
    fn every_operation_in_the_designs_list_is_meta_authority() {
        // The permanently meta-authority set, pinned. Reclassifying any of
        // these fails here.
        for operation in ControlOperation::PERMANENTLY_META_AUTHORITY {
            assert_eq!(
                operation.authority_tier(),
                AuthorityTier::MetaAuthority,
                "{operation} must be meta-authority"
            );
            assert!(operation.is_meta_authority());
        }
    }

    #[test]
    fn the_explicit_list_and_the_classification_agree_in_both_directions() {
        // Neither can drift from the other: an operation classified as
        // meta-authority but missing from the list, or listed but classified
        // ordinary, both fail.
        for operation in ControlOperation::ALL {
            assert_eq!(
                operation.is_meta_authority(),
                ControlOperation::PERMANENTLY_META_AUTHORITY.contains(operation),
                "{operation} is classified one way and listed the other"
            );
        }
        assert_eq!(
            ControlOperation::ALL.len(),
            ControlOperation::PERMANENTLY_META_AUTHORITY.len() + 1,
            "exactly one operation in this build is ordinary"
        );
    }

    #[test]
    fn meta_authority_always_takes_the_strongest_confirmation() {
        for operation in ControlOperation::PERMANENTLY_META_AUTHORITY {
            assert_eq!(
                operation.confirmation(),
                ConfirmationTier::Strongest,
                "{operation} must take the strongest confirmation tier"
            );
        }
        assert_eq!(
            ControlOperation::ProposeAgentProfile.confirmation(),
            ConfirmationTier::Standard
        );
        // And the strongest tier really is the strongest defined.
        assert_eq!(
            ConfirmationTier::ALL.last(),
            Some(&ConfirmationTier::Strongest)
        );
    }

    #[test]
    fn there_is_no_no_approval_class_to_be_declassified_into() {
        // Non-escalation rule 13. Every tier this build defines requires an
        // approval receipt, so there is nowhere weaker to move an operation.
        for tier in AuthorityTier::ALL {
            assert!(
                tier.requires_approval(),
                "{tier} must require approval; this protocol has no unapproved class"
            );
        }
        assert_eq!(AuthorityTier::ALL.len(), 2);
        // Likewise there is no "no confirmation" tier.
        assert_eq!(ConfirmationTier::ALL.len(), 2);
    }

    #[test]
    fn no_requester_grant_can_reach_a_meta_authority_operation() {
        // The domain vocabulary a grant may name is closed, and no
        // meta-authority operation maps into it. So the intersection of any
        // grant with any meta-authority operation is empty by construction.
        for operation in ControlOperation::PERMANENTLY_META_AUTHORITY {
            assert_eq!(
                operation.proposal_domain(),
                None,
                "{operation} must be unproposable by any requester"
            );
        }
        let ordinary = ControlOperation::ProposeAgentProfile
            .proposal_domain()
            .expect("the ordinary operation is proposable");
        assert!(
            PROPOSAL_DOMAINS_V1.contains(&ordinary),
            "a proposable operation must name a domain a grant can carry"
        );
        // Every domain a grant can name maps back to a non-meta operation.
        for domain in PROPOSAL_DOMAINS_V1 {
            assert!(
                ControlOperation::ALL.iter().any(|operation| {
                    operation.proposal_domain() == Some(domain) && !operation.is_meta_authority()
                }),
                "{domain} must not be a route to a meta-authority operation"
            );
        }
    }

    #[test]
    fn a_single_operator_installation_requires_one_operator() {
        assert_eq!(
            required_quorum(AuthorityTier::MetaAuthority, 1),
            RequiredQuorum::MINIMUM
        );
        assert_eq!(
            required_quorum(AuthorityTier::Ordinary, 1),
            RequiredQuorum::MINIMUM
        );
    }

    #[test]
    fn a_second_configured_operator_raises_the_meta_authority_quorum() {
        // Quorum-ready: the rule already returns 2, even though this phase
        // collects one authentication and therefore refuses.
        for configured in [2usize, 3, 7] {
            assert_eq!(
                required_quorum(AuthorityTier::MetaAuthority, configured).get(),
                2,
                "{configured} configured operators must require two decisions"
            );
        }
    }

    #[test]
    fn the_quorum_is_never_zero_even_with_no_configured_operators() {
        // A zero quorum would be an unapproved operation. There is none.
        for tier in AuthorityTier::ALL {
            assert!(
                required_quorum(*tier, 0).get() >= 1,
                "{tier} must never resolve to a zero quorum"
            );
        }
        assert!(!RequiredQuorum::MINIMUM.is_satisfied_by(0));
        assert!(RequiredQuorum::MINIMUM.is_satisfied_by(1));
    }

    #[test]
    fn a_two_of_n_quorum_is_not_satisfied_by_one_decision() {
        let quorum = required_quorum(AuthorityTier::MetaAuthority, 2);
        assert!(!quorum.is_satisfied_by(0));
        assert!(!quorum.is_satisfied_by(1));
        assert!(quorum.is_satisfied_by(2));
        assert!(quorum.is_satisfied_by(3));
    }

    #[test]
    fn the_operation_vocabulary_is_unique_and_stable() {
        let mut spellings: Vec<&str> = ControlOperation::ALL.iter().map(|o| o.wire()).collect();
        spellings.sort_unstable();
        let count = spellings.len();
        spellings.dedup();
        assert_eq!(count, spellings.len(), "two operations share a spelling");
    }
}
