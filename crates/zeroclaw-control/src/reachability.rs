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

use std::collections::BTreeSet;

use crate::client_registry::{PROPOSAL_DOMAINS_V1, READ_DOMAINS_V1};
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

    /// Build evidence from the proofs a local-daemon reachability prover has
    /// discharged.
    ///
    /// This is the **production** constructor the [`Evidence`] documentation
    /// promises: the way a real host-presence prober turns discharged proofs
    /// into evidence, in place of the test-only all-affirmative seams below. It
    /// is the single most safety-critical function in this module, because a
    /// question answered `Some(true)` without a genuine proof is the
    /// self-approval hole the whole approval model exists to prevent.
    ///
    /// Each of the four questions is answered **only** from a genuine proof in
    /// `proofs`, and `None` — fail-closed — otherwise. See
    /// [`LocalDaemonProofs`] for the per-question logic and, in particular, the
    /// soundness argument for the [`IsolationQuestion::SandboxExcludesBackchannel`]
    /// crux.
    ///
    /// This lane builds the pure logic only. It does not obtain peer
    /// credentials, open a socket, or classify anything in a shipped build:
    /// production still passes [`Self::unknown`] at the approve site, and no
    /// production caller constructs `LocalDaemonProofs` yet. Wiring real proofs
    /// in is a later lane.
    #[must_use]
    pub fn from_local_daemon_proofs(proofs: &LocalDaemonProofs) -> Self {
        Self {
            distinct_os_account: proofs.distinct_os_account(),
            sandbox_excludes_backchannel: proofs.sandbox_excludes_backchannel(),
            outside_host_process: proofs.outside_host_process(),
            no_shell_or_filesystem_grant: proofs.no_shell_or_filesystem_grant(),
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

// ---------------------------------------------------------------------------
// Discharged proofs for the local-daemon prover
// ---------------------------------------------------------------------------

/// The uid the OS reserves for the superuser.
///
/// Named rather than written as a bare `0` because it is load-bearing in the
/// [`IsolationQuestion::SandboxExcludesBackchannel`] crux: a *distinct* uid is
/// not enough on its own, because uid `0` is distinct from every ordinary uid
/// yet bypasses the DAC and ptrace checks the crux relies on. A requester
/// running as root is treated as able to reach any backchannel.
const ROOT_UID: u32 = 0;

/// How the requester reached the daemon.
///
/// An explicit input rather than an inference: the design forbids upgrading a
/// principal by *how* it was started, so this records only the one distinction
/// the reachability analysis needs — whether the requester's code runs in its
/// own process or inside the daemon's — and defaults to [`Self::Unknown`] when
/// the host cannot tell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequesterOrigin {
    /// A separate process that connected over the local control socket. Its
    /// code runs in its own address space, not the daemon's, so it cannot
    /// execute code in the process that performs the presence ceremony merely
    /// by virtue of the connection.
    LocalSocketPeer,
    /// Code running inside the daemon process itself — the same process that
    /// performs the presence ceremony. It can reach the backchannel directly.
    NativeInProcess,
    /// The host could not determine the origin. Fails closed.
    Unknown,
}

/// The requester's registered grant, reduced to the domain sets a reachability
/// analysis inspects.
///
/// Holds only what [`IsolationQuestion::NoShellOrFilesystemGrant`] reads: the
/// read and proposal domains a host-issued grant confers. It carries no
/// credential, no target, and no approval field, because a grant has none to
/// carry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InspectedGrant {
    read_domains: BTreeSet<String>,
    proposal_domains: BTreeSet<String>,
}

impl InspectedGrant {
    /// Build the inspectable view from the domains a host-issued grant confers.
    ///
    /// The caller passes the grant's own read and proposal domain sets — for a
    /// registered client, [`crate::client_registry::ClientRegistration::granted_read_domains`]
    /// and its proposal domains. This type does not obtain them; it inspects
    /// what it is given.
    #[must_use]
    pub fn new(read_domains: BTreeSet<String>, proposal_domains: BTreeSet<String>) -> Self {
        Self {
            read_domains,
            proposal_domains,
        }
    }

    /// Whether every domain this grant confers is a member of the v1 read or
    /// proposal vocabulary — the closed, non-execution surface a control client
    /// holds — so none is a shell, filesystem, or tool-execution domain.
    ///
    /// An **allowlist**, in the conservative direction: a read domain outside
    /// [`READ_DOMAINS_V1`] or a proposal domain outside [`PROPOSAL_DOMAINS_V1`]
    /// is treated as *potentially* shell, filesystem, or execution capable and
    /// makes the answer `false`. An unrecognised domain is a reason to refuse,
    /// never to pass. The v1 read domains are the two Inspect views plus the
    /// four read-only tool domains (catalog, describe, validate, preview) — none
    /// executes anything — and the one v1 proposal domain (`agent`) proposes a
    /// profile rather than running a tool, which is why a control client's
    /// read+proposal grant qualifies. An empty grant trivially qualifies: it
    /// confers no domain at all, so it confers no dangerous one.
    #[must_use]
    fn confers_no_shell_or_filesystem_domain(&self) -> bool {
        self.read_domains
            .iter()
            .all(|domain| READ_DOMAINS_V1.contains(&domain.as_str()))
            && self
                .proposal_domains
                .iter()
                .all(|domain| PROPOSAL_DOMAINS_V1.contains(&domain.as_str()))
    }
}

/// A host attestation about who owns and can reach the operator's backchannel —
/// its controlling terminal and the control socket.
///
/// This is the input the [`IsolationQuestion::SandboxExcludesBackchannel`] crux
/// requires. It is an attestation the host makes from real facts (the terminal
/// device's owner and mode, the socket's owner and mode), never a label a
/// requester can assert.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackchannelOwnership {
    owner_uid: u32,
    uid_restricted: bool,
}

impl BackchannelOwnership {
    /// Attest that the operator's controlling terminal and control socket are
    /// owned by `owner_uid`, and whether the host verified they are restricted
    /// to that uid: the terminal is not writable or readable by another uid, and
    /// the socket is mode `0600` owned by `owner_uid`.
    ///
    /// `uid_restricted` is `true` only when the host has checked *both* the
    /// terminal and the socket. A partial check — owner known but mode
    /// unverified — must pass `false`, so the crux stays unproven.
    #[must_use]
    pub const fn new(owner_uid: u32, uid_restricted: bool) -> Self {
        Self {
            owner_uid,
            uid_restricted,
        }
    }
}

/// The discharged proofs a local-daemon reachability prover hands to
/// [`Evidence::from_local_daemon_proofs`].
///
/// Every field is a host-derived fact. There is deliberately **no** `Default`
/// and no constructor that yields an all-affirmative value: a caller must supply
/// each fact, exactly as the later lane that plumbs real peer credentials and
/// socket metadata will. Absent or unknown facts stay `None` / [`RequesterOrigin::Unknown`],
/// and the constructor answers the corresponding question `None`, which
/// classifies as [`Reachability::Reachable`]. This mirrors
/// [`crate::ceremony::PresenceAttestation`]: it cannot be forged into an
/// all-true state trivially, because there is no all-true state to reach without
/// asserting the underlying facts — and asserting them falsely is the plumbing
/// lane's contract to keep, not something this type can paper over.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalDaemonProofs {
    requester_uid: Option<u32>,
    operator_uid: Option<u32>,
    origin: RequesterOrigin,
    grant: Option<InspectedGrant>,
    backchannel: Option<BackchannelOwnership>,
}

impl LocalDaemonProofs {
    /// Assemble the proofs from host-derived facts.
    ///
    /// - `requester_uid`: the peer-credential uid of the requester's local
    ///   socket connection, if the host obtained it; `None` if it did not. This
    ///   lane takes it as an input and does not obtain it.
    /// - `operator_uid`: the OS uid running the approve ceremony, if known.
    /// - `origin`: how the requester reached the daemon.
    /// - `grant`: the requester's registered grant reduced to its domain sets,
    ///   if the host has it to inspect; `None` if it does not.
    /// - `backchannel`: an attestation about the operator backchannel's uid
    ///   ownership, if the host made one; `None` if it did not.
    #[must_use]
    pub fn new(
        requester_uid: Option<u32>,
        operator_uid: Option<u32>,
        origin: RequesterOrigin,
        grant: Option<InspectedGrant>,
        backchannel: Option<BackchannelOwnership>,
    ) -> Self {
        Self {
            requester_uid,
            operator_uid,
            origin,
            grant,
            backchannel,
        }
    }

    // -- the four questions, each answered only from a genuine proof ---------

    /// [`IsolationQuestion::DistinctOsAccount`]: `Some(true)` iff both uids are
    /// known and different, `Some(false)` iff both are known and equal, `None`
    /// iff either is unknown.
    fn distinct_os_account(&self) -> Option<bool> {
        match (self.requester_uid, self.operator_uid) {
            (Some(requester), Some(operator)) => Some(requester != operator),
            _ => None,
        }
    }

    /// [`IsolationQuestion::OutsideHostProcess`]: `Some(true)` for a separate
    /// local-socket peer, `Some(false)` for native in-process code, `None` when
    /// the origin is unknown.
    fn outside_host_process(&self) -> Option<bool> {
        match self.origin {
            RequesterOrigin::LocalSocketPeer => Some(true),
            RequesterOrigin::NativeInProcess => Some(false),
            RequesterOrigin::Unknown => None,
        }
    }

    /// [`IsolationQuestion::NoShellOrFilesystemGrant`]: `Some(true)` iff the
    /// grant is available to inspect and provably confers no shell, filesystem,
    /// or tool-execution domain; `Some(false)` iff it is available and confers
    /// one; `None` iff no grant is available to inspect.
    fn no_shell_or_filesystem_grant(&self) -> Option<bool> {
        self.grant
            .as_ref()
            .map(InspectedGrant::confers_no_shell_or_filesystem_domain)
    }

    /// [`IsolationQuestion::SandboxExcludesBackchannel`] — the crux, answered as
    /// conservatively as the module allows.
    ///
    /// # What this returns `Some(true)` for, and why it is sound
    ///
    /// This is the one question whose affirmative answer rests on an argument
    /// about the operating system rather than on a single recorded fact, so the
    /// argument is written out in full. It answers `Some(true)` **only** when the
    /// conjunction of these holds, and `None` otherwise (never `Some(false)`: a
    /// failure here is "cannot prove isolation", which the conservative rule
    /// already treats as reachable):
    ///
    /// 1. a backchannel attestation is present;
    /// 2. that attestation reports the operator's controlling terminal *and*
    ///    control socket are restricted to a single owner uid
    ///    (`uid_restricted`);
    /// 3. that owner uid **is** the operator's uid — the backchannel is owned by
    ///    the operator, not by some third account; and
    /// 4. the requester runs under a uid that is both **distinct** from the
    ///    operator's (proof #1 true) and **not root** ([`ROOT_UID`]).
    ///
    /// Under those conditions the OS account boundary genuinely excludes the
    /// requester from the operator's terminal and socket:
    ///
    /// - **Terminal injection (`TIOCSTI`) is blocked.** Injecting input into a
    ///   terminal needs an open descriptor to that terminal device. Opening the
    ///   operator's controlling tty requires read/write permission on it, which
    ///   discretionary access control denies to a different, unprivileged uid;
    ///   modern kernels additionally gate `TIOCSTI` behind a capability or
    ///   sysctl. A distinct unprivileged uid therefore cannot push characters
    ///   into the operator's terminal.
    /// - **Process attach (`ptrace`) is blocked.** Attaching to the process that
    ///   runs the ceremony would let the requester drive it. The kernel's
    ///   `ptrace` access check requires the tracer's uid to match the tracee's,
    ///   or `CAP_SYS_PTRACE`. A distinct unprivileged uid matches neither, so it
    ///   cannot attach to the operator's session process.
    /// - **Socket access is blocked.** Connecting to or reading a `0600` unix
    ///   socket owned by the operator requires permission the socket's mode
    ///   denies to another uid.
    ///
    /// # The assumptions this rests on
    ///
    /// The argument is sound only under assumptions the host, not this function,
    /// must uphold. They are stated so a reviewer can check them against the
    /// deployment, and they are exactly why a *distinct uid alone* is
    /// insufficient:
    ///
    /// - **No privileged requester.** The requester holds no uid `0` and no
    ///   privilege-escalating capability (`CAP_DAC_OVERRIDE`, `CAP_SYS_PTRACE`,
    ///   `CAP_SYS_ADMIN`). The `!= ROOT_UID` check rules out the uid-`0` case;
    ///   the capability case is not visible from a uid and is an assumption the
    ///   host makes about the local-socket peer being an ordinary process. A
    ///   privileged requester defeats every mechanism above.
    /// - **No shared or inherited backchannel descriptor.** The requester did
    ///   not inherit an open descriptor to the operator's terminal or socket
    ///   (e.g. by having been forked from the operator's session). A separately
    ///   connected socket peer under a distinct uid did not, but this function
    ///   cannot see a descriptor table, so it is an assumption.
    /// - **No shared interactive input session bridging the uids.** The operator
    ///   is not approving inside a GUI session the requester can drive by another
    ///   channel (for example an X11 display whose cookie the requester holds).
    ///   Holding the operator's display cookie would itself require reading the
    ///   operator's `0600` files, which the uid boundary denies, so this is
    ///   defence in depth rather than a fresh hole — but it is why a headless
    ///   daemon, or an attestation that also covers the input session, is the
    ///   safer deployment. See the finding reported alongside this lane.
    ///
    /// I concluded the proof **is** sound from OS-account separation for the
    /// local-daemon distinct-account case, under the assumptions above, and so
    /// answer `Some(true)` rather than forcing `None` unconditionally. The
    /// assumptions are precisely "no privileged requester, no shared TTY, socket
    /// mode `0600` owned by the operator", which the design's evidence list
    /// already names. Where the host cannot uphold them, it must not construct a
    /// [`BackchannelOwnership`] with `uid_restricted: true`, and this stays
    /// `None`.
    fn sandbox_excludes_backchannel(&self) -> Option<bool> {
        let Some(backchannel) = self.backchannel else {
            // No attestation about the backchannel's ownership: unproven.
            return None;
        };
        let (Some(requester_uid), Some(operator_uid)) = (self.requester_uid, self.operator_uid)
        else {
            // Without both uids there is no distinct-account proof to rest on.
            return None;
        };

        let requester_is_distinct_and_unprivileged =
            requester_uid != operator_uid && requester_uid != ROOT_UID;
        let backchannel_is_operator_owned_and_restricted =
            backchannel.uid_restricted && backchannel.owner_uid == operator_uid;

        if requester_is_distinct_and_unprivileged && backchannel_is_operator_owned_and_restricted {
            Some(true)
        } else {
            None
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

    // -----------------------------------------------------------------------
    // The production constructor: `Evidence::from_local_daemon_proofs`.
    //
    // Every affirmative answer must trace to a genuine proof. These tests pin
    // that each question fails closed on its own, that the crux fails closed
    // even when the other three are proven, and that the only path to
    // `ProvablyIsolated` is a fully discharged proof set.
    // -----------------------------------------------------------------------

    /// A distinct, unprivileged requester uid.
    const REQUESTER_UID: u32 = 1001;
    /// The uid the approve ceremony runs under.
    const OPERATOR_UID: u32 = 1000;

    /// A grant confined to the v1 read + proposal vocabulary — what a control
    /// client holds, and what question three must accept.
    fn safe_grant() -> InspectedGrant {
        InspectedGrant::new(
            READ_DOMAINS_V1.iter().map(|d| (*d).to_string()).collect(),
            PROPOSAL_DOMAINS_V1
                .iter()
                .map(|d| (*d).to_string())
                .collect(),
        )
    }

    /// Proofs in which the host has genuinely discharged all four: a distinct,
    /// unprivileged requester uid, a local-socket peer origin, a
    /// read+proposal-only grant, and an operator-owned uid-restricted
    /// backchannel. Each test starts here and spoils exactly one fact.
    fn all_discharged() -> LocalDaemonProofs {
        LocalDaemonProofs::new(
            Some(REQUESTER_UID),
            Some(OPERATOR_UID),
            RequesterOrigin::LocalSocketPeer,
            Some(safe_grant()),
            Some(BackchannelOwnership::new(OPERATOR_UID, true)),
        )
    }

    #[test]
    fn all_four_proofs_discharged_classifies_provably_isolated() {
        let evidence = Evidence::from_local_daemon_proofs(&all_discharged());
        assert_eq!(
            evidence.answer(IsolationQuestion::DistinctOsAccount),
            Some(true)
        );
        assert_eq!(
            evidence.answer(IsolationQuestion::SandboxExcludesBackchannel),
            Some(true)
        );
        assert_eq!(
            evidence.answer(IsolationQuestion::OutsideHostProcess),
            Some(true)
        );
        assert_eq!(
            evidence.answer(IsolationQuestion::NoShellOrFilesystemGrant),
            Some(true)
        );

        let analysis = classify(&identity(), &evidence);
        assert_eq!(analysis.reachability(), Reachability::ProvablyIsolated);
        assert_eq!(analysis.unproven(), None);
        assert!(analysis.permits_approval());
    }

    #[test]
    fn all_unknown_proofs_prove_nothing_and_fail_closed() {
        // The constructor has no optimistic default: empty inputs yield the
        // same all-`None` evidence as `Evidence::unknown`, which is reachable.
        let proofs = LocalDaemonProofs::new(None, None, RequesterOrigin::Unknown, None, None);
        let evidence = Evidence::from_local_daemon_proofs(&proofs);
        for question in IsolationQuestion::ALL {
            assert_eq!(
                evidence.answer(*question),
                None,
                "{question} must be unproven from empty inputs"
            );
        }
        let analysis = classify(&identity(), &evidence);
        assert_eq!(analysis.reachability(), Reachability::Reachable);
        assert!(!analysis.permits_approval());
        assert_eq!(
            analysis.unproven(),
            Some(IsolationQuestion::DistinctOsAccount)
        );
    }

    #[test]
    fn same_requester_and_operator_uid_disproves_distinct_os_account() {
        // Mutation-check target 1: an implementation that answered `Some(true)`
        // when the uids are equal must fail this test.
        let proofs = LocalDaemonProofs::new(
            Some(OPERATOR_UID),
            Some(OPERATOR_UID),
            RequesterOrigin::LocalSocketPeer,
            Some(safe_grant()),
            Some(BackchannelOwnership::new(OPERATOR_UID, true)),
        );
        let evidence = Evidence::from_local_daemon_proofs(&proofs);
        assert_eq!(
            evidence.answer(IsolationQuestion::DistinctOsAccount),
            Some(false),
            "equal uids are a proof the requester shares the operator's account"
        );
        let analysis = classify(&identity(), &evidence);
        assert_eq!(analysis.reachability(), Reachability::Reachable);
        assert_eq!(
            analysis.unproven(),
            Some(IsolationQuestion::DistinctOsAccount)
        );
    }

    #[test]
    fn unknown_requester_uid_leaves_distinct_os_account_unproven() {
        let mut proofs = all_discharged();
        proofs.requester_uid = None;
        let evidence = Evidence::from_local_daemon_proofs(&proofs);
        assert_eq!(evidence.answer(IsolationQuestion::DistinctOsAccount), None);
        let analysis = classify(&identity(), &evidence);
        assert_eq!(analysis.reachability(), Reachability::Reachable);
        assert_eq!(
            analysis.unproven(),
            Some(IsolationQuestion::DistinctOsAccount)
        );
    }

    #[test]
    fn unknown_operator_uid_leaves_distinct_os_account_unproven() {
        let mut proofs = all_discharged();
        proofs.operator_uid = None;
        let evidence = Evidence::from_local_daemon_proofs(&proofs);
        assert_eq!(evidence.answer(IsolationQuestion::DistinctOsAccount), None);
        // The crux also collapses without the operator uid, but distinct-account
        // is the first question, so it is what the refusal names.
        let analysis = classify(&identity(), &evidence);
        assert_eq!(analysis.reachability(), Reachability::Reachable);
        assert_eq!(
            analysis.unproven(),
            Some(IsolationQuestion::DistinctOsAccount)
        );
    }

    #[test]
    fn native_in_process_origin_disproves_outside_host_process() {
        let mut proofs = all_discharged();
        proofs.origin = RequesterOrigin::NativeInProcess;
        let evidence = Evidence::from_local_daemon_proofs(&proofs);
        assert_eq!(
            evidence.answer(IsolationQuestion::OutsideHostProcess),
            Some(false)
        );
        // The distinct-account and sandbox questions are still proven here (this
        // test holds them provable to isolate the origin question), so the first
        // failure the classifier reaches is `OutsideHostProcess`.
        let analysis = classify(&identity(), &evidence);
        assert_eq!(analysis.reachability(), Reachability::Reachable);
        assert_eq!(
            analysis.unproven(),
            Some(IsolationQuestion::OutsideHostProcess)
        );
    }

    #[test]
    fn unknown_origin_leaves_outside_host_process_unproven() {
        let mut proofs = all_discharged();
        proofs.origin = RequesterOrigin::Unknown;
        let evidence = Evidence::from_local_daemon_proofs(&proofs);
        assert_eq!(evidence.answer(IsolationQuestion::OutsideHostProcess), None);
        let analysis = classify(&identity(), &evidence);
        assert_eq!(analysis.reachability(), Reachability::Reachable);
        assert_eq!(
            analysis.unproven(),
            Some(IsolationQuestion::OutsideHostProcess)
        );
    }

    #[test]
    fn a_grant_with_a_shell_domain_disproves_no_shell_or_filesystem_grant() {
        // Mutation-check target 3: an implementation that ignored a shell grant
        // and answered `Some(true)` must fail this test.
        let mut read_domains: BTreeSet<String> =
            READ_DOMAINS_V1.iter().map(|d| (*d).to_string()).collect();
        read_domains.insert("host.shell".to_string());
        let mut proofs = all_discharged();
        proofs.grant = Some(InspectedGrant::new(
            read_domains,
            PROPOSAL_DOMAINS_V1
                .iter()
                .map(|d| (*d).to_string())
                .collect(),
        ));
        let evidence = Evidence::from_local_daemon_proofs(&proofs);
        assert_eq!(
            evidence.answer(IsolationQuestion::NoShellOrFilesystemGrant),
            Some(false),
            "a grant naming a domain outside the read/proposal allowlist is a proof of reach"
        );
        let analysis = classify(&identity(), &evidence);
        assert_eq!(analysis.reachability(), Reachability::Reachable);
        assert_eq!(
            analysis.unproven(),
            Some(IsolationQuestion::NoShellOrFilesystemGrant)
        );
    }

    #[test]
    fn an_unavailable_grant_leaves_no_shell_or_filesystem_grant_unproven() {
        let mut proofs = all_discharged();
        proofs.grant = None;
        let evidence = Evidence::from_local_daemon_proofs(&proofs);
        assert_eq!(
            evidence.answer(IsolationQuestion::NoShellOrFilesystemGrant),
            None
        );
        let analysis = classify(&identity(), &evidence);
        assert_eq!(analysis.reachability(), Reachability::Reachable);
        assert_eq!(
            analysis.unproven(),
            Some(IsolationQuestion::NoShellOrFilesystemGrant)
        );
    }

    #[test]
    fn an_empty_grant_confers_no_shell_or_filesystem_domain() {
        // An empty grant confers no domain at all, so it confers no dangerous
        // one: question three is `Some(true)`, and with the other three proven
        // the requester is provably isolated.
        let mut proofs = all_discharged();
        proofs.grant = Some(InspectedGrant::new(BTreeSet::new(), BTreeSet::new()));
        let evidence = Evidence::from_local_daemon_proofs(&proofs);
        assert_eq!(
            evidence.answer(IsolationQuestion::NoShellOrFilesystemGrant),
            Some(true)
        );
        assert_eq!(
            classify(&identity(), &evidence).reachability(),
            Reachability::ProvablyIsolated
        );
    }

    #[test]
    fn backchannel_attestation_absent_fails_the_crux_closed_even_with_the_other_three_true() {
        // The crux, proven to fail closed. Mutation-check target 2: an
        // implementation that answered `Some(true)` without the backchannel
        // attestation must fail this test.
        let mut proofs = all_discharged();
        proofs.backchannel = None;
        let evidence = Evidence::from_local_daemon_proofs(&proofs);

        // The other three are genuinely proven...
        assert_eq!(
            evidence.answer(IsolationQuestion::DistinctOsAccount),
            Some(true)
        );
        assert_eq!(
            evidence.answer(IsolationQuestion::OutsideHostProcess),
            Some(true)
        );
        assert_eq!(
            evidence.answer(IsolationQuestion::NoShellOrFilesystemGrant),
            Some(true)
        );
        // ...yet the crux is unproven, and that alone makes the operator
        // ineligible.
        assert_eq!(
            evidence.answer(IsolationQuestion::SandboxExcludesBackchannel),
            None
        );
        let analysis = classify(&identity(), &evidence);
        assert_eq!(analysis.reachability(), Reachability::Reachable);
        assert!(!analysis.permits_approval());
        assert_eq!(
            analysis.unproven(),
            Some(IsolationQuestion::SandboxExcludesBackchannel)
        );
    }

    #[test]
    fn distinct_uid_but_backchannel_not_uid_restricted_fails_the_crux() {
        let mut proofs = all_discharged();
        proofs.backchannel = Some(BackchannelOwnership::new(OPERATOR_UID, false));
        let evidence = Evidence::from_local_daemon_proofs(&proofs);
        assert_eq!(
            evidence.answer(IsolationQuestion::DistinctOsAccount),
            Some(true)
        );
        assert_eq!(
            evidence.answer(IsolationQuestion::SandboxExcludesBackchannel),
            None,
            "an unrestricted backchannel is not a proof the requester is excluded from it"
        );
        let analysis = classify(&identity(), &evidence);
        assert_eq!(analysis.reachability(), Reachability::Reachable);
        assert_eq!(
            analysis.unproven(),
            Some(IsolationQuestion::SandboxExcludesBackchannel)
        );
    }

    #[test]
    fn a_root_requester_is_distinct_but_still_fails_the_crux() {
        // uid 0 is distinct from every ordinary uid, so `DistinctOsAccount` is
        // `Some(true)` — but root bypasses the DAC and ptrace checks the crux
        // rests on, so the crux must stay unproven. This is why a distinct uid
        // alone is insufficient.
        let mut proofs = all_discharged();
        proofs.requester_uid = Some(ROOT_UID);
        let evidence = Evidence::from_local_daemon_proofs(&proofs);
        assert_eq!(
            evidence.answer(IsolationQuestion::DistinctOsAccount),
            Some(true),
            "root's uid is genuinely distinct from the operator's"
        );
        assert_eq!(
            evidence.answer(IsolationQuestion::SandboxExcludesBackchannel),
            None,
            "a root requester can reach any backchannel, so the crux stays unproven"
        );
        let analysis = classify(&identity(), &evidence);
        assert_eq!(analysis.reachability(), Reachability::Reachable);
        assert_eq!(
            analysis.unproven(),
            Some(IsolationQuestion::SandboxExcludesBackchannel)
        );
    }

    #[test]
    fn a_backchannel_owned_by_a_third_uid_fails_the_crux() {
        // The backchannel is uid-restricted, and the requester is a distinct
        // unprivileged uid — but the backchannel is owned by neither the
        // operator nor a proven-excluded party, so the operator's backchannel is
        // not proven protected. Unproven.
        let mut proofs = all_discharged();
        proofs.backchannel = Some(BackchannelOwnership::new(2000, true));
        let evidence = Evidence::from_local_daemon_proofs(&proofs);
        assert_eq!(
            evidence.answer(IsolationQuestion::SandboxExcludesBackchannel),
            None,
            "a backchannel owned by a third uid is not a proof the operator's is protected"
        );
        let analysis = classify(&identity(), &evidence);
        assert_eq!(analysis.reachability(), Reachability::Reachable);
        assert_eq!(
            analysis.unproven(),
            Some(IsolationQuestion::SandboxExcludesBackchannel)
        );
    }
}
