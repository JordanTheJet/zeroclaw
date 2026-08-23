//! Conservative requester-to-operator reachability analysis.
//!
//! Before the broker will accept an operator's decision on a requester's
//! proposal, the host must answer one question: *can this requester act as, or
//! reach the backchannel of, that operator identity?* The principals design
//! fixes which way the answer defaults when the host does not know, and the
//! safety of the entire approval model rests on that default:
//!
//! > Reachability analysis is conservative. If the host cannot prove that a
//! > broad egress grant, plugin, delegated credential, or integration cannot
//! > reach or impersonate the operator identity, it treats that identity as
//! > reachable and ineligible for that requester.
//!
//! Two consequences are encoded here as types rather than left to callers:
//!
//! 1. **The burden of proof is on eligibility.** An operator identity is
//!    eligible only when the host can positively demonstrate the requester
//!    cannot reach it. Absence of evidence of reach is not evidence of
//!    isolation, so every question this module asks is a
//!    `Option<bool>` whose `None` — "the host does not know" — is a refusal,
//!    not a pass.
//! 2. **Fail closed when nothing remains.** If no eligible operator remains,
//!    mutations fail closed. There is no fallback to a lower-assurance
//!    backchannel and no path that approves with the requester's own identity.
//!
//! ## What phase 4 can actually prove
//!
//! This phase has exactly one backchannel: terminal user presence
//! ([`crate::ceremony::TerminalConfirmation`]). So the question
//! "can the requester reach the operator" concretely means: *can the requester
//! cause code to run at, observe, or answer the operator's controlling
//! terminal?*
//!
//! For the deployment shape this phase actually ships — an agent running inside
//! the daemon process, under the same OS account as the human at the terminal —
//! the honest answer is **yes**, and no evidence available to this build says
//! otherwise. A same-account process can generally write to the terminal, read
//! it, or attach to the process that owns it. [`Evidence::unknown`] is therefore
//! the accurate default for a same-process agent requester, and it classifies
//! as [`Reachability::Reachable`].
//!
//! That is not a placeholder to be relaxed later. The way an operator becomes
//! eligible is for the host to gain real separation — a distinct OS account, an
//! enforced sandbox that excludes the terminal and the control socket — and to
//! record that separation as proof. Widening this module's notion of proof
//! without widening the actual separation would be the exact escalation the
//! design forbids.
//!
//! ## Not modelled here
//!
//! The design lists egress, plugins, delegated credentials, integrations, and
//! shell and filesystem grants as inputs the analysis must consider. This phase
//! has one backchannel and no wiring to `EgressPolicyResolver` or the plugin
//! registry, so those inputs are not read. That is a *narrowing*, not a gap in
//! the default: an unread input is an unanswered question, and an unanswered
//! question already means reachable. Wiring an input later can only ever move
//! an identity from reachable to eligible by supplying a proof, never the
//! reverse.

use crate::operator::OperatorIdentity;

/// Whether a requester can reach or impersonate an operator identity.
///
/// Deliberately two-valued with no "unknown" variant. Uncertainty is resolved
/// *into* [`Self::Reachable`] by [`classify`] rather than carried forward,
/// so no caller can encounter an unknown and decide for itself what to do
/// with it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Reachability {
    /// The requester can reach or impersonate the identity, or the host cannot
    /// prove it cannot. The identity is ineligible for this requester.
    Reachable,
    /// The host positively demonstrated the requester cannot reach or
    /// impersonate the identity.
    ProvablyIsolated,
}

impl Reachability {
    /// Whether an operator identity with this classification may decide for
    /// this requester.
    #[must_use]
    pub const fn permits_approval(self) -> bool {
        match self {
            Self::Reachable => false,
            Self::ProvablyIsolated => true,
        }
    }

    /// A stable, non-secret wire spelling for audit and refusal reporting.
    #[must_use]
    pub const fn wire(self) -> &'static str {
        match self {
            Self::Reachable => "reachable",
            Self::ProvablyIsolated => "provably_isolated",
        }
    }
}

impl std::fmt::Display for Reachability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.wire())
    }
}

/// One isolation question the host must answer to make an operator eligible.
///
/// Named so a refusal can say *which* proof was missing without inventing a
/// string at the call site.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum IsolationQuestion {
    /// Does the requester provably run under an OS account distinct from the
    /// one owning the operator's controlling terminal?
    DistinctOsAccount,
    /// Does an enforced sandbox provably exclude the operator backchannel — the
    /// controlling terminal and the control socket — from the requester?
    SandboxExcludesBackchannel,
    /// Does the requester provably run outside the host process, so it cannot
    /// execute code in the process that performs the presence ceremony?
    OutsideHostProcess,
    /// Does the requester provably hold no shell or filesystem grant that would
    /// let it read the backchannel or the control socket?
    NoShellOrFilesystemGrant,
}

impl IsolationQuestion {
    /// Every question that must be answered affirmatively for eligibility.
    ///
    /// [`classify`] iterates this, so adding a variant makes every previously
    /// eligible evidence set ineligible until the new question is answered.
    /// That direction is deliberate: a new way to reach an operator must
    /// default to "reachable", never be silently ignored.
    pub const ALL: &'static [Self] = &[
        Self::DistinctOsAccount,
        Self::SandboxExcludesBackchannel,
        Self::OutsideHostProcess,
        Self::NoShellOrFilesystemGrant,
    ];

    /// A stable, non-secret wire spelling.
    #[must_use]
    pub const fn wire(self) -> &'static str {
        match self {
            Self::DistinctOsAccount => "distinct_os_account",
            Self::SandboxExcludesBackchannel => "sandbox_excludes_backchannel",
            Self::OutsideHostProcess => "outside_host_process",
            Self::NoShellOrFilesystemGrant => "no_shell_or_filesystem_grant",
        }
    }
}

impl std::fmt::Display for IsolationQuestion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.wire())
    }
}

/// What the host can prove about one requester's separation from the operator
/// backchannel.
///
/// Every field is a tri-state on purpose. `Some(true)` is a proof of isolation,
/// `Some(false)` is a proof of reach, and `None` is *the host does not know* —
/// which the conservative rule treats exactly like `Some(false)`. There is no
/// constructor that fills unknowns with optimistic defaults.
///
/// The fields are **private**. Production code builds an `Evidence` only through
/// [`Self::unknown`] (equivalently `Default`), and the single value that answers
/// every question affirmatively — [`Self::fully_isolated`] — is `#[cfg(test)]`,
/// so it exists in no shipped build and no workspace crate can flip an operator
/// from ineligible to eligible by hand. When a real host-presence prober arrives
/// it will construct this type from discharged proofs through a new constructor
/// in this module, never from a free-standing "isolated" literal. This mirrors
/// [`crate::ceremony::PresenceAttestation`], whose fields are likewise private
/// and whose only direct constructor is test-only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Evidence {
    /// See [`IsolationQuestion::DistinctOsAccount`].
    distinct_os_account: Option<bool>,
    /// See [`IsolationQuestion::SandboxExcludesBackchannel`].
    sandbox_excludes_backchannel: Option<bool>,
    /// See [`IsolationQuestion::OutsideHostProcess`].
    outside_host_process: Option<bool>,
    /// See [`IsolationQuestion::NoShellOrFilesystemGrant`].
    no_shell_or_filesystem_grant: Option<bool>,
}

impl Evidence {
    /// The honest default: the host has proved nothing.
    ///
    /// This is what a same-process agent requester gets on the deployment shape
    /// this phase ships, and it classifies as [`Reachability::Reachable`].
    #[must_use]
    pub const fn unknown() -> Self {
        Self {
            distinct_os_account: None,
            sandbox_excludes_backchannel: None,
            outside_host_process: None,
            no_shell_or_filesystem_grant: None,
        }
    }

    /// Evidence answering every question affirmatively.
    ///
    /// # Test-only
    ///
    /// `#[cfg(test)]` and `pub(crate)`, like
    /// [`crate::ceremony::PresenceAttestation::for_test`]: it exists in no
    /// shipped build and is reachable from no other crate. Nothing in this phase
    /// can actually discharge all four proofs, so the only callers are tests that
    /// need to exercise the eligible branch. A production path that has really
    /// proven isolation must construct `Evidence` from those proofs, never from
    /// this constructor.
    #[cfg(test)]
    #[must_use]
    pub(crate) const fn fully_isolated() -> Self {
        Self {
            distinct_os_account: Some(true),
            sandbox_excludes_backchannel: Some(true),
            outside_host_process: Some(true),
            no_shell_or_filesystem_grant: Some(true),
        }
    }

    /// Isolation-proving evidence for the `fixture-grants` test seam.
    ///
    /// # Test-only
    ///
    /// Compiled only under the `fixture-grants` feature, which no released
    /// profile enables, so it exists in no shipped build and is covered by the
    /// same `control_fixture_absence_gate.sh` that pins every other fixture
    /// symbol out of the binary. It is the cross-crate analogue of
    /// [`Self::fully_isolated`]: the phase-5 operator-approve path cannot mint a
    /// receipt without an operator the reachability analysis clears, and no such
    /// analysis exists yet, so an out-of-crate test needs a way to construct the
    /// eligible branch. A production apply path that has really proven isolation
    /// must construct `Evidence` from discharged proofs, never from this.
    #[cfg(feature = "fixture-grants")]
    #[must_use]
    pub const fn fixture_isolated() -> Self {
        Self {
            distinct_os_account: Some(true),
            sandbox_excludes_backchannel: Some(true),
            outside_host_process: Some(true),
            no_shell_or_filesystem_grant: Some(true),
        }
    }

    /// This host's answer to one question.
    #[must_use]
    pub const fn answer(&self, question: IsolationQuestion) -> Option<bool> {
        match question {
            IsolationQuestion::DistinctOsAccount => self.distinct_os_account,
            IsolationQuestion::SandboxExcludesBackchannel => self.sandbox_excludes_backchannel,
            IsolationQuestion::OutsideHostProcess => self.outside_host_process,
            IsolationQuestion::NoShellOrFilesystemGrant => self.no_shell_or_filesystem_grant,
        }
    }
}

/// The classification and, when reachable, the first proof that was missing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Analysis {
    reachability: Reachability,
    unproven: Option<IsolationQuestion>,
}

impl Analysis {
    /// The classification.
    #[must_use]
    pub const fn reachability(&self) -> Reachability {
        self.reachability
    }

    /// Whether an operator with this analysis may decide for the requester.
    #[must_use]
    pub const fn permits_approval(&self) -> bool {
        self.reachability.permits_approval()
    }

    /// The first question that was not answered affirmatively, when the
    /// identity is reachable. Non-secret, and suitable for a refusal message.
    #[must_use]
    pub const fn unproven(&self) -> Option<IsolationQuestion> {
        self.unproven
    }
}

/// Classify one requester against one operator identity.
///
/// The identity is taken by reference because the analysis is *per requester
/// and per operator identity*, and a caller that passed the wrong identity
/// would otherwise silently reuse another's verdict. Phase 4's single
/// backchannel is not identity-specific — every registered operator
/// authenticates at the same kind of controlling terminal — so the verdict
/// currently depends only on the evidence. That is a property of having one
/// backchannel, not a licence to drop the parameter: a second backchannel makes
/// the verdict identity-specific immediately.
///
/// The rule, in one place: **every question in [`IsolationQuestion::ALL`] must
/// be answered `Some(true)`.** Anything else — a proof of reach, or no answer
/// at all — is [`Reachability::Reachable`].
#[must_use]
pub fn classify(_operator: &OperatorIdentity, evidence: &Evidence) -> Analysis {
    for question in IsolationQuestion::ALL {
        match evidence.answer(*question) {
            Some(true) => {}
            // `Some(false)` is a proof of reach and `None` is the absence of a
            // proof of isolation. The conservative rule treats them
            // identically, and collapsing them here is what makes "unknown
            // means ineligible" impossible to bypass by leaving a field unset.
            Some(false) | None => {
                return Analysis {
                    reachability: Reachability::Reachable,
                    unproven: Some(*question),
                };
            }
        }
    }
    Analysis {
        reachability: Reachability::ProvablyIsolated,
        unproven: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> OperatorIdentity {
        OperatorIdentity::new("jordan").expect("valid operator identity")
    }

    #[test]
    fn unknown_evidence_is_reachable_and_therefore_ineligible() {
        // The load-bearing default. Guarded by a mutation check: making
        // `classify` treat `None` as isolated must make this test fail.
        let analysis = classify(&identity(), &Evidence::unknown());
        assert_eq!(
            analysis.reachability(),
            Reachability::Reachable,
            "an unprovable requester must be treated as able to reach the operator"
        );
        assert!(
            !analysis.permits_approval(),
            "an unprovable requester must not be able to use this operator"
        );
        assert_eq!(
            analysis.unproven(),
            Some(IsolationQuestion::DistinctOsAccount),
            "the refusal must name the first missing proof"
        );
    }

    #[test]
    fn the_default_evidence_is_the_unknown_evidence() {
        // `Default` must not be a quiet optimistic path around `unknown()`.
        assert_eq!(Evidence::default(), Evidence::unknown());
        assert!(!classify(&identity(), &Evidence::default()).permits_approval());
    }

    #[test]
    fn every_single_unanswered_question_alone_makes_the_identity_reachable() {
        // Proves the rule is a conjunction over *all* questions, not a check of
        // whichever one happens to be first.
        for question in IsolationQuestion::ALL {
            let mut evidence = Evidence::fully_isolated();
            match question {
                IsolationQuestion::DistinctOsAccount => evidence.distinct_os_account = None,
                IsolationQuestion::SandboxExcludesBackchannel => {
                    evidence.sandbox_excludes_backchannel = None;
                }
                IsolationQuestion::OutsideHostProcess => evidence.outside_host_process = None,
                IsolationQuestion::NoShellOrFilesystemGrant => {
                    evidence.no_shell_or_filesystem_grant = None;
                }
            }
            let analysis = classify(&identity(), &evidence);
            assert_eq!(
                analysis.reachability(),
                Reachability::Reachable,
                "leaving {question} unanswered must make the operator ineligible"
            );
            assert_eq!(analysis.unproven(), Some(*question));
        }
    }

    #[test]
    fn every_single_disproven_question_alone_makes_the_identity_reachable() {
        for question in IsolationQuestion::ALL {
            let mut evidence = Evidence::fully_isolated();
            match question {
                IsolationQuestion::DistinctOsAccount => {
                    evidence.distinct_os_account = Some(false);
                }
                IsolationQuestion::SandboxExcludesBackchannel => {
                    evidence.sandbox_excludes_backchannel = Some(false);
                }
                IsolationQuestion::OutsideHostProcess => {
                    evidence.outside_host_process = Some(false);
                }
                IsolationQuestion::NoShellOrFilesystemGrant => {
                    evidence.no_shell_or_filesystem_grant = Some(false);
                }
            }
            assert!(
                !classify(&identity(), &evidence).permits_approval(),
                "a proof of reach on {question} must make the operator ineligible"
            );
        }
    }

    #[test]
    fn only_fully_discharged_evidence_is_eligible() {
        let analysis = classify(&identity(), &Evidence::fully_isolated());
        assert_eq!(analysis.reachability(), Reachability::ProvablyIsolated);
        assert!(analysis.permits_approval());
        assert_eq!(analysis.unproven(), None);
    }

    #[test]
    fn reachable_never_permits_approval() {
        assert!(!Reachability::Reachable.permits_approval());
        assert!(Reachability::ProvablyIsolated.permits_approval());
    }
}
