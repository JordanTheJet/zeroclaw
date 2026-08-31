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
//! ## Questions are reach-path foreclosures, not mechanisms
//!
//! The two separations named above are different mechanisms that close the
//! same reach paths, so each [`IsolationQuestion`] is worded as the
//! foreclosure it demands, and each deployment shape discharges it with the
//! mechanism that shape actually has:
//!
//! - **Shape A — local daemon, distinct OS account**
//!   ([`Evidence::from_local_daemon_proofs`]): kernel identity and DAC facts
//!   (peer credentials, capability sets, TTY/socket ownership and modes).
//! - **Shape B — host-spawned, sandbox-constructed requester**
//!   ([`Evidence::from_ceremony_spawn`]): construction records of the spawn
//!   the host itself performed (fd table at exec, session detachment,
//!   pre-exec sandbox policy).
//!
//! A mechanism a shape does not have answers `None`, never a vacuous
//! `Some(true)`: shape B cannot claim a distinct account, so it must instead
//! prove the same authority was stripped by construction, and where its
//! platform cannot prove enforcement (Darwin today) the answer stays `None`
//! and the operator stays ineligible.
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
///
/// Each question names a **reach-path foreclosure**, not a mechanism: it asks
/// whether a family of ways to reach the operator backchannel is provably
/// closed, and different deployment shapes may close the same family with
/// different mechanisms. Shape A (a local daemon serving a requester under a
/// distinct OS account — [`Evidence::from_local_daemon_proofs`]) discharges
/// them from kernel identity and DAC facts. Shape B (a requester the host
/// itself spawned into a constructed, sandboxed environment) discharges them
/// from construction records of that spawn. What never changes across shapes:
/// the facts are raw, the verdict is computed in this module, and an
/// undischarged question is a refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum IsolationQuestion {
    /// Is the requester provably unable to wield the operator account's
    /// ambient OS authority? Same-account processes normally inherit the
    /// full authority of the account that owns the operator's terminal —
    /// discharge requires either a genuinely distinct, unprivileged identity
    /// (distinct uid + no overriding capabilities: shape A) or a
    /// host-constructed environment that provably strips that authority
    /// before the requester ever runs (no-new-privs, emptied capability
    /// sets: shape B).
    OperatorAmbientAuthority,
    /// Are the backchannel objects — the operator's controlling terminal and
    /// the control socket — provably out of the requester's reach? Discharge
    /// requires either DAC facts excluding the requester's identity from
    /// every object and its enclosing path (shape A's backchannel crux) or a
    /// pre-exec sandbox policy whose recorded rules deny the requester those
    /// objects, pty allocation included (shape B).
    BackchannelObjectReach,
    /// Does the requester provably run outside the host process, so it cannot
    /// execute code in the process that performs the presence ceremony?
    /// Being a separate process is necessary but not sufficient: the
    /// process-inspection family (ptrace and its relatives) must also be
    /// foreclosed, by identity boundary (shape A) or by recorded syscall
    /// policy (shape B).
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
        Self::OperatorAmbientAuthority,
        Self::BackchannelObjectReach,
        Self::OutsideHostProcess,
        Self::NoShellOrFilesystemGrant,
    ];

    /// A stable, non-secret wire spelling.
    #[must_use]
    pub const fn wire(self) -> &'static str {
        match self {
            Self::OperatorAmbientAuthority => "operator_ambient_authority",
            Self::BackchannelObjectReach => "backchannel_object_reach",
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
    /// See [`IsolationQuestion::OperatorAmbientAuthority`].
    operator_ambient_authority: Option<bool>,
    /// See [`IsolationQuestion::BackchannelObjectReach`].
    backchannel_object_reach: Option<bool>,
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
            operator_ambient_authority: None,
            backchannel_object_reach: None,
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
    /// soundness argument for the [`IsolationQuestion::BackchannelObjectReach`]
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
            operator_ambient_authority: proofs.operator_ambient_authority(),
            backchannel_object_reach: proofs.backchannel_object_reach(),
            outside_host_process: proofs.outside_host_process(),
            no_shell_or_filesystem_grant: proofs.no_shell_or_filesystem_grant(),
        }
    }

    /// Build evidence from the construction records of a spawn the host
    /// itself performed — shape B, the same-account counterpart of
    /// [`Self::from_local_daemon_proofs`].
    ///
    /// Everything the shape-A constructor's documentation says about safety
    /// applies here with one aggravation: the spawned requester runs under
    /// the operator's own uid, so there is no kernel identity boundary
    /// behind these records — the discharge rests entirely on the recorded
    /// sandbox policy. See [`crate::spawn::SpawnIsolation`] for the
    /// per-question conjunctions, the platform gate (`Some(true)` only on
    /// Linux; Darwin answers `None` until a Seatbelt-soundness proof
    /// exists), and the ledger of what is deliberately not yet proven.
    ///
    /// This lane builds the pure logic only: no production spawner exists,
    /// nothing constructs [`crate::spawn::SpawnIsolation`] in a shipped
    /// build, and production still passes [`Self::unknown`] at the approve
    /// site. The onboarding-ceremony spawner is a later lane and will be the
    /// only production constructor of these records.
    #[must_use]
    pub fn from_ceremony_spawn(records: &crate::spawn::SpawnIsolation) -> Self {
        Self {
            operator_ambient_authority: records.operator_ambient_authority(),
            backchannel_object_reach: records.backchannel_object_reach(),
            outside_host_process: records.outside_host_process(),
            no_shell_or_filesystem_grant: records.no_shell_or_filesystem_grant(),
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
            operator_ambient_authority: Some(true),
            backchannel_object_reach: Some(true),
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
            operator_ambient_authority: Some(true),
            backchannel_object_reach: Some(true),
            outside_host_process: Some(true),
            no_shell_or_filesystem_grant: Some(true),
        }
    }

    /// This host's answer to one question.
    #[must_use]
    pub const fn answer(&self, question: IsolationQuestion) -> Option<bool> {
        match question {
            IsolationQuestion::OperatorAmbientAuthority => self.operator_ambient_authority,
            IsolationQuestion::BackchannelObjectReach => self.backchannel_object_reach,
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
/// [`IsolationQuestion::BackchannelObjectReach`] crux: a *distinct* uid is
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
    pub(crate) fn confers_no_shell_or_filesystem_domain(&self) -> bool {
        self.read_domains
            .iter()
            .all(|domain| READ_DOMAINS_V1.contains(&domain.as_str()))
            && self
                .proposal_domains
                .iter()
                .all(|domain| PROPOSAL_DOMAINS_V1.contains(&domain.as_str()))
    }
}

/// The OS family a set of backchannel facts was gathered on.
///
/// The sandbox-exclusion argument in
/// [`LocalDaemonProofs::backchannel_object_reach`] is Linux-specific: it
/// relies on Linux enforcing socket permission bits on `connect(2)`
/// (`MAY_WRITE`), on Linux `ptrace` uid semantics, and on Linux discretionary
/// access control on the terminal device. Socket-mode-on-connect is POSIX
/// implementation-defined — historic BSD and Darwin did not enforce it — and
/// `ptrace` semantics differ across kernels. The proof therefore answers
/// `Some(true)` only when it was gathered on Linux; every other platform fails
/// closed until a platform-specific argument and prober exist. This type is a
/// gathered fact, not a fabricated one: a host records the platform it actually
/// read the facts on, and does not claim Linux on a system that is not Linux.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatheredPlatform {
    /// Linux, where the DAC + `ptrace` argument holds.
    Linux,
    /// Apple's Darwin/macOS, where socket-mode-on-connect was historically not
    /// enforced. No isolation proof exists here yet.
    MacOs,
    /// Any other platform. No isolation proof exists here yet.
    Other,
}

/// Which operator backchannel a [`BackchannelOwnership`] attestation covers.
///
/// The phase-4 argument is specific to a TTY controlling terminal plus the
/// control socket (see [`crate::ceremony::TerminalConfirmation`]). Excluding a
/// GUI, D-Bus, or Wayland channel is an *unchecked* assumption, so an
/// attestation for any other backchannel shape fails closed rather than claim an
/// isolation it never established.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackchannelKind {
    /// The operator's controlling terminal (a TTY) together with the control
    /// socket — the only shape the terminal and socket facts can prove isolation
    /// for.
    ControllingTerminalAndSocket,
    /// Any other backchannel (a GUI/D-Bus/Wayland session, a remote channel, …).
    /// Not covered by the terminal and socket facts; unproven.
    Other,
}

/// The kind of an `AF_UNIX` control socket, as it bears on filesystem isolation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnixSocketKind {
    /// A pathname socket: a filesystem node whose owner, mode, and
    /// parent-directory chain govern who may connect to it or unlink and rebind
    /// it.
    Pathname,
    /// An abstract-namespace socket: it has no filesystem node and therefore no
    /// permission bits at all. It cannot be isolated by mode, so it always fails
    /// closed.
    Abstract,
}

/// A Linux capability that, if held by the requester, defeats one of the
/// foreclosures the [`IsolationQuestion::BackchannelObjectReach`] crux rests
/// on.
///
/// A non-root uid is *not* automatically unprivileged: file and ambient
/// capabilities grant these powers to ordinary uids. Any one of them held in any
/// of the requester's effective, permitted, or ambient sets is enough to reach
/// the operator's backchannel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BackchannelCapability {
    /// `CAP_DAC_OVERRIDE`: bypasses file read/write/execute permission checks,
    /// defeating the socket-mode and terminal-mode foreclosures.
    DacOverride,
    /// `CAP_SYS_PTRACE`: attach to any process, defeating the `ptrace`
    /// foreclosure on the ceremony process.
    SysPtrace,
    /// `CAP_KILL`: send signals to any process, letting the requester disrupt or
    /// drive the ceremony process.
    Kill,
    /// `CAP_SYS_ADMIN`: an effectively-root capability that subsumes the others.
    SysAdmin,
}

/// The backchannel-relevant capability state the host observed for the
/// requester.
///
/// Carries the [`BackchannelCapability`] members observed in each of the
/// requester's effective, permitted, and ambient capability sets, as a prober
/// would read them from the kernel. The verdict — whether the requester is
/// unprivileged for the crux's purposes — is computed in this module from those
/// raw sets, never supplied as a pre-collapsed boolean. There is deliberately no
/// `Default`: a caller must supply the observed state, and an absent observation
/// stays `None` on [`LocalDaemonProofs`], which fails the crux closed. This lane
/// defines only the contract; a later prober reads `/proc/<pid>/status`
/// (`CapEff`/`CapPrm`/`CapAmb`) to populate it, and this lane adds no
/// capability-reading dependency.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequesterPrivilege {
    effective: BTreeSet<BackchannelCapability>,
    permitted: BTreeSet<BackchannelCapability>,
    ambient: BTreeSet<BackchannelCapability>,
}

impl RequesterPrivilege {
    /// Record the backchannel-relevant capabilities observed in each set.
    ///
    /// Each set holds only the [`BackchannelCapability`] members the host
    /// actually saw present; three empty sets mean the host read the capability
    /// state and found none of them.
    #[must_use]
    pub fn observed(
        effective: BTreeSet<BackchannelCapability>,
        permitted: BTreeSet<BackchannelCapability>,
        ambient: BTreeSet<BackchannelCapability>,
    ) -> Self {
        Self {
            effective,
            permitted,
            ambient,
        }
    }

    /// Whether the requester provably holds none of the backchannel-relevant
    /// capabilities in any of its effective, permitted, or ambient sets.
    ///
    /// Permitted and ambient count, not just effective: a process can raise a
    /// permitted capability into its effective set itself, and an ambient
    /// capability is inherited across `execve`.
    fn is_unprivileged(&self) -> bool {
        self.effective.is_empty() && self.permitted.is_empty() && self.ambient.is_empty()
    }
}

/// Stat facts about the operator's controlling terminal device.
///
/// Raw facts, not a verdict: [`Self::excludes_requester`] derives whether the
/// requester can inject into or observe the terminal from the owner, group, and
/// mode, accounting for the requester's supplementary-group membership. A pts
/// slave is mode `0620` `chown user:tty`, so the file's *group* carries write —
/// the group axis, not just the `other` bits, decides isolation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TtyFacts {
    owner_uid: u32,
    group_gid: u32,
    mode: u32,
}

impl TtyFacts {
    /// Record the controlling terminal's owner uid, group gid, and permission
    /// mode (the low bits of `st_mode`).
    #[must_use]
    pub const fn new(owner_uid: u32, group_gid: u32, mode: u32) -> Self {
        Self {
            owner_uid,
            group_gid,
            mode,
        }
    }

    /// Whether the operator's controlling terminal provably excludes the
    /// requester: it is the operator's own terminal, and the requester — by uid
    /// and by supplementary-group membership — can neither write to it (inject
    /// `TIOCSTI`) nor read from it.
    fn excludes_requester(
        &self,
        operator_uid: u32,
        requester_uid: u32,
        requester_groups: &BTreeSet<u32>,
    ) -> bool {
        // It must be the operator's own terminal, and the requester a distinct
        // uid (the owner permission bits then do not apply to the requester).
        if self.owner_uid != operator_uid || requester_uid == operator_uid {
            return false;
        }
        // `other` read or write lets any uid, the requester included, reach it.
        if (self.mode & 0o006) != 0 {
            return false;
        }
        // Group read or write reaches it when the requester belongs to the
        // file's group — the pts-slave `tty`-group case.
        if (self.mode & 0o060) != 0 && requester_groups.contains(&self.group_gid) {
            return false;
        }
        true
    }
}

/// Stat facts about one ancestor directory on the control socket's path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirectoryFacts {
    owner_uid: u32,
    mode: u32,
}

impl DirectoryFacts {
    /// Record an ancestor directory's owner uid and permission mode.
    #[must_use]
    pub const fn new(owner_uid: u32, mode: u32) -> Self {
        Self { owner_uid, mode }
    }

    /// Whether this directory is non-writable by any uid other than the
    /// operator: owned by the operator with no group-write and no other-write
    /// bit.
    ///
    /// A world-writable sticky directory such as `/tmp` does *not* qualify — the
    /// sticky bit only prevents unlinking *others'* files, a subtlety the
    /// contract deliberately does not depend on. This is intentionally
    /// conservative: a system ancestor owned by root (rather than the operator)
    /// also fails here, so a deployment whose socket lives under a root-owned
    /// path stays `None` until a later lane teaches the walk to accept ancestors
    /// owned by a uid the requester is provably not.
    fn restricted_to(&self, operator_uid: u32) -> bool {
        self.owner_uid == operator_uid && (self.mode & 0o022) == 0
    }
}

/// Stat facts about the control socket and its parent-directory chain.
///
/// Raw facts, not a verdict. [`Self::excludes_requester`] derives isolation from
/// the socket kind, owner, mode, and — the finding that motivated this — the
/// writability of every ancestor directory, because a parent directory writable
/// by another uid lets that uid unlink and rebind the socket for a
/// man-in-the-middle even when the socket's own mode is `0600`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketFacts {
    kind: UnixSocketKind,
    owner_uid: u32,
    mode: u32,
    parent_chain: Vec<DirectoryFacts>,
}

impl SocketFacts {
    /// Record the socket's kind, owner uid, permission mode, and the stat facts
    /// of every ancestor directory from its immediate parent up to the
    /// filesystem root.
    ///
    /// The chain is the host's actual walk of the path; an empty chain records
    /// no ancestors and therefore cannot prove the path is non-writable.
    #[must_use]
    pub fn new(
        kind: UnixSocketKind,
        owner_uid: u32,
        mode: u32,
        parent_chain: Vec<DirectoryFacts>,
    ) -> Self {
        Self {
            kind,
            owner_uid,
            mode,
            parent_chain,
        }
    }

    /// Whether the control socket provably excludes every uid but the operator.
    fn excludes_requester(&self, operator_uid: u32) -> bool {
        // An abstract-namespace socket has no filesystem node and no mode, so it
        // cannot be isolated by permission at all.
        if self.kind != UnixSocketKind::Pathname {
            return false;
        }
        // Owned by the operator, owner-only (no group or other access): a
        // distinct uid cannot connect to it.
        if self.owner_uid != operator_uid || (self.mode & 0o077) != 0 {
            return false;
        }
        // An empty recorded chain proves nothing about the path's writability.
        if self.parent_chain.is_empty() {
            return false;
        }
        // The whole parent chain must be non-writable by another uid; otherwise a
        // distinct uid could unlink and rebind the socket.
        if !self
            .parent_chain
            .iter()
            .all(|dir| dir.restricted_to(operator_uid))
        {
            return false;
        }
        true
    }
}

/// A host attestation about who owns and can reach the operator's backchannel —
/// its controlling terminal and the control socket.
///
/// This is the input the [`IsolationQuestion::BackchannelObjectReach`] crux
/// requires. It carries only *facts* the host gathered — the platform it read
/// them on, which backchannel shape they describe, and the raw stat facts of the
/// terminal device and the socket — never a pre-collapsed "isolated" flag. The
/// crux derives the verdict from these facts in
/// [`LocalDaemonProofs::backchannel_object_reach`], so no caller can assert
/// an isolation the OS does not actually establish.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackchannelOwnership {
    platform: GatheredPlatform,
    kind: BackchannelKind,
    tty: TtyFacts,
    socket: SocketFacts,
}

impl BackchannelOwnership {
    /// Attest the platform the facts were gathered on, which backchannel they
    /// describe, and the raw stat facts of the operator's controlling terminal
    /// and control socket.
    ///
    /// This constructor records facts and computes no verdict: whether they add
    /// up to isolation is decided by the reviewed crux, not here. A partial or
    /// uncertain observation must not be dressed up as a complete one — the host
    /// either supplies the real terminal and socket facts or supplies no
    /// attestation at all (`None` on [`LocalDaemonProofs`]), which fails closed.
    #[must_use]
    pub fn new(
        platform: GatheredPlatform,
        kind: BackchannelKind,
        tty: TtyFacts,
        socket: SocketFacts,
    ) -> Self {
        Self {
            platform,
            kind,
            tty,
            socket,
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
    requester_groups: Option<BTreeSet<u32>>,
    requester_privilege: Option<RequesterPrivilege>,
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
    /// - `requester_groups`: the requester's group memberships (primary plus
    ///   supplementary gids), if the host obtained them; `None` if it did not.
    ///   The crux needs them because a controlling terminal is often
    ///   group-writable (`0620` `chown user:tty`), so uid alone cannot decide
    ///   whether the requester can write it.
    /// - `requester_privilege`: the backchannel-relevant capability state the
    ///   host observed for the requester, if it read it; `None` if it did not. A
    ///   non-root uid holding `CAP_DAC_OVERRIDE`/`CAP_SYS_PTRACE`/`CAP_KILL`
    ///   defeats the crux's foreclosures, so an unread capability state fails
    ///   closed.
    /// - `operator_uid`: the OS uid running the approve ceremony, if known.
    /// - `origin`: how the requester reached the daemon.
    /// - `grant`: the requester's registered grant reduced to its domain sets,
    ///   if the host has it to inspect; `None` if it does not.
    /// - `backchannel`: an attestation about the operator backchannel's platform,
    ///   kind, and terminal/socket stat facts, if the host made one; `None` if it
    ///   did not.
    #[must_use]
    pub fn new(
        requester_uid: Option<u32>,
        requester_groups: Option<BTreeSet<u32>>,
        requester_privilege: Option<RequesterPrivilege>,
        operator_uid: Option<u32>,
        origin: RequesterOrigin,
        grant: Option<InspectedGrant>,
        backchannel: Option<BackchannelOwnership>,
    ) -> Self {
        Self {
            requester_uid,
            requester_groups,
            requester_privilege,
            operator_uid,
            origin,
            grant,
            backchannel,
        }
    }

    // -- the four questions, each answered only from a genuine proof ---------

    /// [`IsolationQuestion::OperatorAmbientAuthority`]: `Some(true)` iff both uids are
    /// known and different, `Some(false)` iff both are known and equal, `None`
    /// iff either is unknown.
    fn operator_ambient_authority(&self) -> Option<bool> {
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

    /// [`IsolationQuestion::BackchannelObjectReach`] — the crux, answered as
    /// conservatively as the module allows.
    ///
    /// # What this returns `Some(true)` for, and why it is sound
    ///
    /// This is the one question whose affirmative answer rests on an argument
    /// about the operating system rather than a single recorded fact, so the
    /// argument is written out in full. It answers `Some(true)` **only** when the
    /// conjunction of all of these holds, and `None` otherwise (never
    /// `Some(false)`: a failure here is "cannot prove isolation", which the
    /// conservative rule already treats as reachable). Every clause is derived in
    /// *this* reviewed module from raw host facts; no caller supplies a
    /// pre-collapsed "isolated" boolean.
    ///
    /// 1. **A backchannel attestation, the requester's groups, and the
    ///    requester's capability state are all present.** Any missing fact is an
    ///    unanswered question, so the crux stays `None`.
    /// 2. **The facts were gathered on Linux** ([`GatheredPlatform::Linux`]).
    ///    The argument below is Linux-DAC/`ptrace`-specific; on any other
    ///    platform no proof exists yet.
    /// 3. **The attestation is for a TTY controlling terminal plus the control
    ///    socket** ([`BackchannelKind::ControllingTerminalAndSocket`]). A GUI,
    ///    D-Bus, or Wayland backchannel is not covered and stays `None`.
    /// 4. **The requester uid is distinct from the operator's and is not root**
    ///    ([`ROOT_UID`]). Root is distinct from every ordinary uid yet bypasses
    ///    DAC and `ptrace`, which is why distinctness alone is insufficient.
    /// 5. **The requester holds no backchannel-relevant capability** in any of
    ///    its effective, permitted, or ambient sets. A non-root uid with
    ///    `CAP_DAC_OVERRIDE`/`CAP_SYS_PTRACE`/`CAP_KILL`/`CAP_SYS_ADMIN` defeats
    ///    the foreclosures below, so a non-root uid is not enough on its own.
    /// 6. **The operator's controlling terminal provably excludes the
    ///    requester** — by uid *and* by the requester's supplementary-group
    ///    membership, because a pts slave is `0620` `chown user:tty` and a
    ///    requester in the `tty` group could otherwise write it.
    /// 7. **The control socket provably excludes the requester** — a pathname
    ///    (not abstract-namespace) socket, mode owner-only, owned by the
    ///    operator, whose *entire parent-directory chain* is non-writable by any
    ///    other uid, so no distinct uid can unlink and rebind it.
    ///
    /// Under those conditions the OS account boundary genuinely excludes the
    /// requester from the operator's terminal and socket:
    ///
    /// - **Terminal injection (`TIOCSTI`) is blocked.** Injecting input needs an
    ///   open descriptor to the terminal device, which requires read/write
    ///   permission DAC denies to a distinct unprivileged uid — checked here
    ///   against the terminal's owner, group, and mode *and* the requester's
    ///   group memberships (clause 6), not merely its `other` bits.
    /// - **Process attach (`ptrace`) is blocked.** The kernel's `ptrace` check
    ///   requires the tracer's uid to match the tracee's or `CAP_SYS_PTRACE`;
    ///   clauses 4 and 5 rule out both.
    /// - **Socket access is blocked, including rebind MITM.** A distinct uid
    ///   cannot connect to an owner-only socket owned by the operator, and
    ///   cannot unlink-and-rebind it because clause 7 requires every ancestor
    ///   directory to be non-writable by another uid. An abstract-namespace
    ///   socket has no permission bits and is rejected outright.
    ///
    /// # What this deliberately does not yet prove
    ///
    /// Two residual vectors are handled by failing closed rather than by a
    /// positive proof, and a host that cannot rule them out must not construct a
    /// [`BackchannelOwnership`] that would satisfy the clauses above:
    ///
    /// - **Inherited backchannel descriptor.** A requester forked from the
    ///   operator's session could inherit an open terminal/socket descriptor.
    ///   This function cannot see a descriptor table; the
    ///   [`RequesterOrigin::LocalSocketPeer`] origin (a separately connected
    ///   peer) is what the host uses to exclude that case, and it is enforced by
    ///   the separate [`IsolationQuestion::OutsideHostProcess`] question.
    /// - **Root-owned system ancestors.** Clause 7 currently requires every
    ///   ancestor to be *operator*-owned, so a socket under a root-owned path
    ///   (`/run`, `/`) fails closed. That is conservative and safe; a later lane
    ///   may accept ancestors owned by a uid the requester is provably not.
    fn backchannel_object_reach(&self) -> Option<bool> {
        // Clause 1: every fact the argument rests on must be present. A missing
        // one is "cannot prove isolation", which stays `None` (never
        // `Some(false)`).
        let backchannel = self.backchannel.as_ref()?;
        let (Some(requester_uid), Some(operator_uid)) = (self.requester_uid, self.operator_uid)
        else {
            return None;
        };
        let requester_groups = self.requester_groups.as_ref()?;
        let privilege = self.requester_privilege.as_ref()?;

        // Clause 2: the Linux-specific argument only holds on Linux.
        if backchannel.platform != GatheredPlatform::Linux {
            return None;
        }

        // Clause 3: the attestation must be for a TTY controlling terminal plus
        // the control socket; any other backchannel shape is unproven.
        if backchannel.kind != BackchannelKind::ControllingTerminalAndSocket {
            return None;
        }

        // Clause 4: distinct from the operator, and not root (root bypasses DAC
        // and `ptrace`).
        if requester_uid == operator_uid || requester_uid == ROOT_UID {
            return None;
        }

        // Clause 5: non-root is not enough — a backchannel-relevant capability
        // defeats the foreclosures, so the observed capability state must be
        // provably empty of them.
        if !privilege.is_unprivileged() {
            return None;
        }

        // Clauses 6 and 7: derive the terminal and socket verdicts from the raw
        // stat facts, here in this reviewed module.
        let tty_excludes_requester =
            backchannel
                .tty
                .excludes_requester(operator_uid, requester_uid, requester_groups);
        let socket_excludes_requester = backchannel.socket.excludes_requester(operator_uid);

        if tty_excludes_requester && socket_excludes_requester {
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
            Some(IsolationQuestion::OperatorAmbientAuthority),
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
                IsolationQuestion::OperatorAmbientAuthority => {
                    evidence.operator_ambient_authority = None
                }
                IsolationQuestion::BackchannelObjectReach => {
                    evidence.backchannel_object_reach = None;
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
                IsolationQuestion::OperatorAmbientAuthority => {
                    evidence.operator_ambient_authority = Some(false);
                }
                IsolationQuestion::BackchannelObjectReach => {
                    evidence.backchannel_object_reach = Some(false);
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
    /// The gid of the `tty` group that owns a pts slave. The requester is
    /// deliberately *not* a member of it in the discharged fixture.
    const TTY_GROUP_GID: u32 = 5;

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

    /// The requester's group memberships: its own primary group only, and
    /// pointedly not the `tty` group that owns the operator's terminal.
    fn requester_groups() -> BTreeSet<u32> {
        BTreeSet::from([REQUESTER_UID])
    }

    /// A capability state the host read and found empty of every
    /// backchannel-relevant capability — the requester is provably unprivileged.
    fn unprivileged() -> RequesterPrivilege {
        RequesterPrivilege::observed(BTreeSet::new(), BTreeSet::new(), BTreeSet::new())
    }

    /// The operator's controlling terminal in its real pts-slave shape: owned by
    /// the operator, group `tty`, mode `0620` (owner rw, group w). It excludes
    /// the requester because the requester is not in the `tty` group.
    fn isolating_tty() -> TtyFacts {
        TtyFacts::new(OPERATOR_UID, TTY_GROUP_GID, 0o620)
    }

    /// A pathname control socket, mode `0600`, owned by the operator, under a
    /// parent-directory chain every ancestor of which is operator-owned and
    /// non-writable by another uid.
    fn isolating_socket() -> SocketFacts {
        SocketFacts::new(
            UnixSocketKind::Pathname,
            OPERATOR_UID,
            0o600,
            vec![
                DirectoryFacts::new(OPERATOR_UID, 0o700),
                DirectoryFacts::new(OPERATOR_UID, 0o755),
            ],
        )
    }

    /// A backchannel attestation gathered on Linux, for a TTY controlling
    /// terminal plus the control socket, carrying the isolating terminal and
    /// socket facts.
    fn isolating_backchannel() -> BackchannelOwnership {
        BackchannelOwnership::new(
            GatheredPlatform::Linux,
            BackchannelKind::ControllingTerminalAndSocket,
            isolating_tty(),
            isolating_socket(),
        )
    }

    /// Proofs in which the host has genuinely discharged all four questions: a
    /// distinct, unprivileged requester uid with known groups and an empty
    /// backchannel-relevant capset, a local-socket peer origin, a
    /// read+proposal-only grant, and a Linux TTY+socket backchannel whose
    /// terminal and socket facts exclude the requester. Each test starts here
    /// and spoils exactly one fact.
    fn all_discharged() -> LocalDaemonProofs {
        LocalDaemonProofs::new(
            Some(REQUESTER_UID),
            Some(requester_groups()),
            Some(unprivileged()),
            Some(OPERATOR_UID),
            RequesterOrigin::LocalSocketPeer,
            Some(safe_grant()),
            Some(isolating_backchannel()),
        )
    }

    #[test]
    fn all_four_proofs_discharged_classifies_provably_isolated() {
        let evidence = Evidence::from_local_daemon_proofs(&all_discharged());
        assert_eq!(
            evidence.answer(IsolationQuestion::OperatorAmbientAuthority),
            Some(true)
        );
        assert_eq!(
            evidence.answer(IsolationQuestion::BackchannelObjectReach),
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
        let proofs =
            LocalDaemonProofs::new(None, None, None, None, RequesterOrigin::Unknown, None, None);
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
            Some(IsolationQuestion::OperatorAmbientAuthority)
        );
    }

    #[test]
    fn same_requester_and_operator_uid_disproves_operator_ambient_authority() {
        // Mutation-check target 1: an implementation that answered `Some(true)`
        // when the uids are equal must fail this test.
        let proofs = LocalDaemonProofs::new(
            Some(OPERATOR_UID),
            Some(requester_groups()),
            Some(unprivileged()),
            Some(OPERATOR_UID),
            RequesterOrigin::LocalSocketPeer,
            Some(safe_grant()),
            Some(isolating_backchannel()),
        );
        let evidence = Evidence::from_local_daemon_proofs(&proofs);
        assert_eq!(
            evidence.answer(IsolationQuestion::OperatorAmbientAuthority),
            Some(false),
            "equal uids are a proof the requester shares the operator's account"
        );
        let analysis = classify(&identity(), &evidence);
        assert_eq!(analysis.reachability(), Reachability::Reachable);
        assert_eq!(
            analysis.unproven(),
            Some(IsolationQuestion::OperatorAmbientAuthority)
        );
    }

    #[test]
    fn unknown_requester_uid_leaves_operator_ambient_authority_unproven() {
        let mut proofs = all_discharged();
        proofs.requester_uid = None;
        let evidence = Evidence::from_local_daemon_proofs(&proofs);
        assert_eq!(
            evidence.answer(IsolationQuestion::OperatorAmbientAuthority),
            None
        );
        let analysis = classify(&identity(), &evidence);
        assert_eq!(analysis.reachability(), Reachability::Reachable);
        assert_eq!(
            analysis.unproven(),
            Some(IsolationQuestion::OperatorAmbientAuthority)
        );
    }

    #[test]
    fn unknown_operator_uid_leaves_operator_ambient_authority_unproven() {
        let mut proofs = all_discharged();
        proofs.operator_uid = None;
        let evidence = Evidence::from_local_daemon_proofs(&proofs);
        assert_eq!(
            evidence.answer(IsolationQuestion::OperatorAmbientAuthority),
            None
        );
        // The crux also collapses without the operator uid, but distinct-account
        // is the first question, so it is what the refusal names.
        let analysis = classify(&identity(), &evidence);
        assert_eq!(analysis.reachability(), Reachability::Reachable);
        assert_eq!(
            analysis.unproven(),
            Some(IsolationQuestion::OperatorAmbientAuthority)
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
            evidence.answer(IsolationQuestion::OperatorAmbientAuthority),
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
            evidence.answer(IsolationQuestion::BackchannelObjectReach),
            None
        );
        let analysis = classify(&identity(), &evidence);
        assert_eq!(analysis.reachability(), Reachability::Reachable);
        assert!(!analysis.permits_approval());
        assert_eq!(
            analysis.unproven(),
            Some(IsolationQuestion::BackchannelObjectReach)
        );
    }

    #[test]
    fn distinct_uid_but_group_accessible_socket_fails_the_crux() {
        // The socket is a pathname socket owned by the operator under a
        // non-writable chain, but its mode grants group access (`0660`), so a
        // uid in the socket's group could connect. Not owner-only is not a proof
        // the requester is excluded.
        let mut proofs = all_discharged();
        proofs.backchannel = Some(BackchannelOwnership::new(
            GatheredPlatform::Linux,
            BackchannelKind::ControllingTerminalAndSocket,
            isolating_tty(),
            SocketFacts::new(
                UnixSocketKind::Pathname,
                OPERATOR_UID,
                0o660,
                vec![DirectoryFacts::new(OPERATOR_UID, 0o700)],
            ),
        ));
        let evidence = Evidence::from_local_daemon_proofs(&proofs);
        assert_eq!(
            evidence.answer(IsolationQuestion::OperatorAmbientAuthority),
            Some(true)
        );
        assert_eq!(
            evidence.answer(IsolationQuestion::BackchannelObjectReach),
            None,
            "a group-accessible socket is not a proof the requester is excluded from it"
        );
        let analysis = classify(&identity(), &evidence);
        assert_eq!(analysis.reachability(), Reachability::Reachable);
        assert_eq!(
            analysis.unproven(),
            Some(IsolationQuestion::BackchannelObjectReach)
        );
    }

    #[test]
    fn a_root_requester_is_distinct_but_still_fails_the_crux() {
        // uid 0 is distinct from every ordinary uid, so `OperatorAmbientAuthority` is
        // `Some(true)` — but root bypasses the DAC and ptrace checks the crux
        // rests on, so the crux must stay unproven. This is why a distinct uid
        // alone is insufficient.
        let mut proofs = all_discharged();
        proofs.requester_uid = Some(ROOT_UID);
        let evidence = Evidence::from_local_daemon_proofs(&proofs);
        assert_eq!(
            evidence.answer(IsolationQuestion::OperatorAmbientAuthority),
            Some(true),
            "root's uid is genuinely distinct from the operator's"
        );
        assert_eq!(
            evidence.answer(IsolationQuestion::BackchannelObjectReach),
            None,
            "a root requester can reach any backchannel, so the crux stays unproven"
        );
        let analysis = classify(&identity(), &evidence);
        assert_eq!(analysis.reachability(), Reachability::Reachable);
        assert_eq!(
            analysis.unproven(),
            Some(IsolationQuestion::BackchannelObjectReach)
        );
    }

    #[test]
    fn a_backchannel_owned_by_a_third_uid_fails_the_crux() {
        // The terminal and socket are owner-restricted, and the requester is a
        // distinct unprivileged uid — but they are owned by a third uid, neither
        // the operator nor a proven-excluded party, so the operator's backchannel
        // is not proven protected. Unproven.
        const THIRD_UID: u32 = 2000;
        let mut proofs = all_discharged();
        proofs.backchannel = Some(BackchannelOwnership::new(
            GatheredPlatform::Linux,
            BackchannelKind::ControllingTerminalAndSocket,
            TtyFacts::new(THIRD_UID, TTY_GROUP_GID, 0o600),
            SocketFacts::new(
                UnixSocketKind::Pathname,
                THIRD_UID,
                0o600,
                vec![DirectoryFacts::new(THIRD_UID, 0o700)],
            ),
        ));
        let evidence = Evidence::from_local_daemon_proofs(&proofs);
        assert_eq!(
            evidence.answer(IsolationQuestion::BackchannelObjectReach),
            None,
            "a backchannel owned by a third uid is not a proof the operator's is protected"
        );
        let analysis = classify(&identity(), &evidence);
        assert_eq!(analysis.reachability(), Reachability::Reachable);
        assert_eq!(
            analysis.unproven(),
            Some(IsolationQuestion::BackchannelObjectReach)
        );
    }

    // -----------------------------------------------------------------------
    // The five hardened findings: each vector that previously answered
    // `Some(true)` unsoundly now fails closed. Every test below spoils exactly
    // one fact from `all_discharged` and asserts the crux answers `None`.
    // -----------------------------------------------------------------------

    #[test]
    fn a_writable_socket_parent_directory_fails_the_crux() {
        // Finding 1. The socket is a pathname `0600` socket owned by the
        // operator, but an ancestor directory is other-writable, so a distinct
        // uid could unlink and rebind the socket for a man-in-the-middle. Mutation
        // check 1: dropping the parent-chain check makes this pass `Some(true)`.
        let mut proofs = all_discharged();
        proofs.backchannel = Some(BackchannelOwnership::new(
            GatheredPlatform::Linux,
            BackchannelKind::ControllingTerminalAndSocket,
            isolating_tty(),
            SocketFacts::new(
                UnixSocketKind::Pathname,
                OPERATOR_UID,
                0o600,
                vec![
                    DirectoryFacts::new(OPERATOR_UID, 0o700),
                    // Other-writable: another uid can rewrite this directory's
                    // entries and swap the socket beneath it.
                    DirectoryFacts::new(OPERATOR_UID, 0o707),
                ],
            ),
        ));
        let evidence = Evidence::from_local_daemon_proofs(&proofs);
        assert_eq!(
            evidence.answer(IsolationQuestion::BackchannelObjectReach),
            None,
            "a socket whose parent chain is writable by another uid is not isolated"
        );
        assert!(!classify(&identity(), &evidence).permits_approval());
    }

    #[test]
    fn an_abstract_namespace_socket_fails_the_crux() {
        // Finding 1. An abstract-namespace socket has no filesystem node and no
        // permission bits, so it cannot be isolated by mode at all.
        let mut proofs = all_discharged();
        proofs.backchannel = Some(BackchannelOwnership::new(
            GatheredPlatform::Linux,
            BackchannelKind::ControllingTerminalAndSocket,
            isolating_tty(),
            SocketFacts::new(
                UnixSocketKind::Abstract,
                OPERATOR_UID,
                0o600,
                vec![DirectoryFacts::new(OPERATOR_UID, 0o700)],
            ),
        ));
        let evidence = Evidence::from_local_daemon_proofs(&proofs);
        assert_eq!(
            evidence.answer(IsolationQuestion::BackchannelObjectReach),
            None,
            "an abstract-namespace socket has no mode and cannot be isolated"
        );
        assert!(!classify(&identity(), &evidence).permits_approval());
    }

    #[test]
    fn an_empty_socket_parent_chain_fails_the_crux() {
        // Finding 1, boundary. A recorded chain with no ancestors proves nothing
        // about whether the path is writable, so it fails closed.
        let mut proofs = all_discharged();
        proofs.backchannel = Some(BackchannelOwnership::new(
            GatheredPlatform::Linux,
            BackchannelKind::ControllingTerminalAndSocket,
            isolating_tty(),
            SocketFacts::new(UnixSocketKind::Pathname, OPERATOR_UID, 0o600, Vec::new()),
        ));
        let evidence = Evidence::from_local_daemon_proofs(&proofs);
        assert_eq!(
            evidence.answer(IsolationQuestion::BackchannelObjectReach),
            None,
            "an empty parent chain is not a proof the path is non-writable"
        );
    }

    #[test]
    fn a_requester_with_a_backchannel_capability_fails_the_crux() {
        // Finding 2. A distinct, non-root uid that nonetheless holds
        // `CAP_DAC_OVERRIDE` defeats the DAC foreclosures. Mutation check 2:
        // dropping the capability check makes this pass `Some(true)`.
        let mut proofs = all_discharged();
        proofs.requester_privilege = Some(RequesterPrivilege::observed(
            BTreeSet::from([BackchannelCapability::DacOverride]),
            BTreeSet::new(),
            BTreeSet::new(),
        ));
        let evidence = Evidence::from_local_daemon_proofs(&proofs);
        assert_eq!(
            evidence.answer(IsolationQuestion::OperatorAmbientAuthority),
            Some(true),
            "the uid is genuinely distinct; privilege is a separate axis"
        );
        assert_eq!(
            evidence.answer(IsolationQuestion::BackchannelObjectReach),
            None,
            "a non-root uid holding CAP_DAC_OVERRIDE is not unprivileged"
        );
        assert!(!classify(&identity(), &evidence).permits_approval());
    }

    #[test]
    fn a_backchannel_capability_in_the_ambient_set_alone_fails_the_crux() {
        // Finding 2. Ambient (and permitted) capabilities count, not just
        // effective: an ambient `CAP_SYS_PTRACE` survives `execve` and can be
        // raised to effective, so it must fail closed even with an empty
        // effective set.
        let mut proofs = all_discharged();
        proofs.requester_privilege = Some(RequesterPrivilege::observed(
            BTreeSet::new(),
            BTreeSet::new(),
            BTreeSet::from([BackchannelCapability::SysPtrace]),
        ));
        let evidence = Evidence::from_local_daemon_proofs(&proofs);
        assert_eq!(
            evidence.answer(IsolationQuestion::BackchannelObjectReach),
            None,
            "an ambient backchannel capability is not proof of an unprivileged requester"
        );
    }

    #[test]
    fn an_unknown_requester_privilege_fails_the_crux() {
        // Finding 2. If the host never read the capability state, privilege is
        // not established, so the crux fails closed.
        let mut proofs = all_discharged();
        proofs.requester_privilege = None;
        let evidence = Evidence::from_local_daemon_proofs(&proofs);
        assert_eq!(
            evidence.answer(IsolationQuestion::BackchannelObjectReach),
            None,
            "an unread capability state cannot prove the requester is unprivileged"
        );
    }

    #[test]
    fn a_group_writable_tty_with_the_requester_in_that_group_fails_the_crux() {
        // Finding 3. The terminal is `0620` `chown user:tty`; if the requester is
        // a member of the `tty` group it can write (inject into) the terminal.
        // The `other` bits alone would say "isolated" — the group axis is what
        // catches this.
        let mut proofs = all_discharged();
        proofs.requester_groups = Some(BTreeSet::from([REQUESTER_UID, TTY_GROUP_GID]));
        let evidence = Evidence::from_local_daemon_proofs(&proofs);
        assert_eq!(
            evidence.answer(IsolationQuestion::BackchannelObjectReach),
            None,
            "a requester in the tty group can write a 0620 terminal"
        );
        assert!(!classify(&identity(), &evidence).permits_approval());
    }

    #[test]
    fn a_world_writable_tty_fails_the_crux() {
        // Finding 3. A terminal writable by `other` is reachable by any uid,
        // regardless of group membership.
        let mut proofs = all_discharged();
        proofs.backchannel = Some(BackchannelOwnership::new(
            GatheredPlatform::Linux,
            BackchannelKind::ControllingTerminalAndSocket,
            TtyFacts::new(OPERATOR_UID, TTY_GROUP_GID, 0o622),
            isolating_socket(),
        ));
        let evidence = Evidence::from_local_daemon_proofs(&proofs);
        assert_eq!(
            evidence.answer(IsolationQuestion::BackchannelObjectReach),
            None,
            "an other-writable terminal is reachable by any uid"
        );
    }

    #[test]
    fn an_unknown_requester_group_set_fails_the_crux() {
        // Finding 3. Without the requester's group memberships, the host cannot
        // prove it is outside the terminal's group, so the crux fails closed.
        let mut proofs = all_discharged();
        proofs.requester_groups = None;
        let evidence = Evidence::from_local_daemon_proofs(&proofs);
        assert_eq!(
            evidence.answer(IsolationQuestion::BackchannelObjectReach),
            None,
            "unknown group memberships cannot prove the requester is out of the tty group"
        );
    }

    #[test]
    fn a_non_linux_platform_tag_fails_the_crux() {
        // Finding 4. The DAC/`ptrace` argument is Linux-specific; on macOS (or
        // any non-Linux platform) no proof exists yet. Mutation check 3: dropping
        // the platform gate makes this pass `Some(true)`.
        let mut proofs = all_discharged();
        proofs.backchannel = Some(BackchannelOwnership::new(
            GatheredPlatform::MacOs,
            BackchannelKind::ControllingTerminalAndSocket,
            isolating_tty(),
            isolating_socket(),
        ));
        let evidence = Evidence::from_local_daemon_proofs(&proofs);
        assert_eq!(
            evidence.answer(IsolationQuestion::BackchannelObjectReach),
            None,
            "the Linux-specific argument does not hold on a non-Linux platform"
        );
        assert!(!classify(&identity(), &evidence).permits_approval());
    }

    #[test]
    fn a_non_tty_backchannel_kind_fails_the_crux() {
        // Finding 5. The GUI/D-Bus/Wayland exclusion is unchecked; an attestation
        // for any backchannel other than a TTY controlling terminal plus the
        // control socket fails closed.
        let mut proofs = all_discharged();
        proofs.backchannel = Some(BackchannelOwnership::new(
            GatheredPlatform::Linux,
            BackchannelKind::Other,
            isolating_tty(),
            isolating_socket(),
        ));
        let evidence = Evidence::from_local_daemon_proofs(&proofs);
        assert_eq!(
            evidence.answer(IsolationQuestion::BackchannelObjectReach),
            None,
            "a non-TTY backchannel is not covered by the terminal and socket facts"
        );
        assert!(!classify(&identity(), &evidence).permits_approval());
    }

    #[test]
    fn the_positive_case_with_all_hardened_facts_is_provably_isolated() {
        // The one path to `Some(true)`: Linux, a TTY+socket backchannel, a
        // pathname `0600` socket under an operator-owned non-writable chain, a
        // `0620` terminal whose `tty` group the requester is not in, and a
        // distinct non-root uid with an empty backchannel-relevant capset.
        let evidence = Evidence::from_local_daemon_proofs(&all_discharged());
        assert_eq!(
            evidence.answer(IsolationQuestion::BackchannelObjectReach),
            Some(true),
            "genuinely isolating facts must discharge the crux"
        );
        let analysis = classify(&identity(), &evidence);
        assert_eq!(analysis.reachability(), Reachability::ProvablyIsolated);
        assert_eq!(analysis.unproven(), None);
        assert!(analysis.permits_approval());
    }
}
