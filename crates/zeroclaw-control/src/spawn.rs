//! Shape B: isolation constructed by the host at spawn time.
//!
//! Shape A ([`crate::reachability::LocalDaemonProofs`]) proves a requester
//! isolated by *inspecting* kernel identity facts about a process the host
//! did not create. This module covers the opposite deployment: the host —
//! an onboarding ceremony running at the operator's terminal — **spawns the
//! requester itself**, and therefore holds construction records of the
//! environment it built: which fds existed at exec, whether the child was
//! detached from the controlling terminal, and exactly which sandbox rules
//! were installed before the requester's first instruction ran.
//!
//! The same-account caveat, stated up front: the spawned requester runs
//! **under the operator's own uid**, so there is no kernel identity boundary
//! to fall back on. Every discharge below rests entirely on the recorded
//! sandbox policy being enforced and complete. That is why the discharge
//! conditions here are conjunctions with no partial credit, why every
//! insufficient record answers `None` (never a vacuous `Some(true)`), and
//! why non-Linux platforms answer `None` across the board until an enforced
//! per-platform proof exists ([`GatheredPlatform::MacOs`] included — Seatbelt
//! soundness is a separate verification lane, not an assumption).
//!
//! ## The same-uid reach paths this must close
//!
//! With no uid boundary, every same-uid primitive that can reach the
//! operator's process, memory, fds, or terminal is a live threat and must be
//! individually foreclosed. The dangerous ones, and how each is closed:
//!
//! - **fd theft.** `pidfd_open(operator) + pidfd_getfd()` steals the
//!   operator's already-open control-socket or TTY fd directly out of the
//!   operator's process — same-uid passes `ptrace_may_access`, so it is *not*
//!   covered by denying `ptrace(2)`. Closed by denying `pidfd_getfd` (and
//!   `pidfd_open`) in seccomp explicitly.
//! - **memory read.** `process_vm_readv`/`writev` and `ptrace(PTRACE_PEEK…)`
//!   read the operator's address space same-uid. Closed by denying both.
//! - **fd passing.** `SCM_RIGHTS` can carry an fd only over an `AF_UNIX`
//!   socket the child controls; closed by denying `socket(AF_UNIX)` *and*
//!   `socketpair(AF_UNIX)` at creation, given no `AF_UNIX` fd was inherited.
//! - **`/proc` memory and fd duplication.** `open("/proc/<operator>/mem")`
//!   reads the operator's memory, and `open("/proc/<operator>/fd/<n>")`
//!   *dup's* the operator's already-open socket/TTY fd through the magic
//!   symlink — a distinct fd-acquisition path from `pidfd_getfd`. Both pass
//!   `ptrace_may_access` same-uid and neither is a ptrace or pidfd syscall,
//!   so they rest entirely on the Landlock exclusion of the whole `/proc`
//!   subtree denying the `open`, plus no inherited `/proc` directory fd.
//! - **terminal injection.** `TIOCSTI`/`TIOCLINUX` on any tty fd; closed by
//!   the no-tty-fd process facts, the tty-device Landlock exclusion, and a
//!   seccomp denial of those ioctls as belt.
//! - **`io_uring` off-filter replay.** `io_uring` performs `openat`,
//!   `connect`, `read`, and `recvmsg` through submission-queue entries that
//!   a seccomp *syscall* filter never inspects — so it can replay every
//!   `open`/socket/`/proc` reach above while bypassing the syscall denials
//!   that close them. Denying the individual primitives is necessary but not
//!   sufficient while `io_uring` can perform them off-filter; closed by
//!   denying `io_uring_setup` (which prevents any ring from being created)
//!   and `io_uring_enter`, given no ring fd is inherited.
//! - **namespace mount relocation.** `unshare(CLONE_NEWUSER)` needs no
//!   capability yet grants `CAP_SYS_ADMIN` in-namespace; with a further
//!   `unshare(CLONE_NEWNS)` the child can mount a fresh procfs at an
//!   *allowlisted* working path, and because no PID namespace was entered it
//!   still shows the operator's PID — so `open("/allowed/…/proc/<op>/fd/<n>")`
//!   dup's the operator's socket/TTY fd from inside a Landlock-allowed path,
//!   past the real-`/proc` exclusion. Closed by denying the namespace family
//!   ([`NamespaceDenials`]: `unshare`, `setns`, `clone(CLONE_NEW*)`, `clone3`)
//!   and the mount family ([`MountDenials`]: `mount`, `move_mount`, `fsopen`,
//!   `fsconfig`, `fsmount`, `open_tree`, `pivot_root`, `mount_setattr`), each
//!   syscall enumerated so an incomplete denial cannot read as complete.
//! - **handle-based open.** `open_by_handle_at` resolves a file by handle
//!   rather than by path, bypassing Landlock's path-walk hook entirely; a
//!   path-based allowlist cannot contain it. Closed by denying it and
//!   `name_to_handle_at`. (It also needs `CAP_DAC_READ_SEARCH`, which
//!   caps-cleared denies — but only via the ambient-authority question, so
//!   the explicit denial keeps each reach verdict self-contained.)
//!
//! This is why the seccomp facts are **one field per syscall family**, never
//! a single "process inspection denied" boolean: a bundled flag would let a
//! spawner assert the family closed having denied only `ptrace(2)` while
//! leaving `pidfd_getfd` — the actual same-uid theft primitive — wide open.
//! Yama `ptrace_scope` is deliberately *not* relied upon: it is an ambient
//! system-wide sysctl, not a per-spawn construction record the ceremony
//! controls, so it has no field here.
//!
//! ## The enforcement floor is itself a fact
//!
//! Landlock coverage is kernel-version dependent, so "the allowlist excludes
//! `/proc`" can be *recorded* true yet be *false in effect* on a kernel whose
//! Landlock ABI silently dropped the rights the ruleset asked for. The
//! filesystem-path rules this module relies on are Landlock ABI v1 (Linux
//! 5.13), but a sound spawner must not assume the running kernel provides
//! them: [`LandlockAllowlist`] carries an explicit
//! `abi_floor_supports_required_rights` record — the kernel's supported
//! Landlock ABI was queried and covers every right the allowlist depends on,
//! with no best-effort downgrade — and the verdict is `None` without it.
//!
//! ## Trust boundary
//!
//! Fact types here are **construction records**: the spawner records what it
//! did (called `setsid`, installed this Landlock ruleset, denied these
//! syscalls), atomically, one primitive per field. They are host-constructed
//! only — nothing reachable from MCP input builds them — and the per-question
//! verdicts are computed in this module from the raw records, mirroring the
//! shape-A rule that a caller never hands over a pre-collapsed conclusion.
//!
//! No production spawner exists yet: the onboarding ceremony that performs
//! the spawn is a later lane, and it will be the only production constructor
//! of these records. Landing the types and verdict logic first means that
//! spawner is written *to* this contract instead of the contract being
//! shaped around whatever the spawner happens to do.
//!
//! ## What this deliberately does not yet prove
//!
//! - **Signals — argued out of scope, does NOT block the verdict.** A
//!   same-uid child can send signals to the ceremony process. This is
//!   assessed as *availability* (it can `SIGKILL`/`SIGSTOP` the ceremony,
//!   denying service), never *authority*: a signal cannot answer a presence
//!   prompt, and the `SIGSTOP`-then-inspect escalation requires the
//!   inspection family (`ptrace`/`process_vm`/`pidfd_getfd`/`/proc`) which
//!   the verdict already requires closed. The reachability question is
//!   reach/impersonate/read-credential, and a pure availability primitive is
//!   outside it, so this is a documented out-of-scope note rather than a
//!   `None`. If the inspection family were *not* required closed, this
//!   argument would collapse and signals would have to block — the two are
//!   linked deliberately.
//! - **Darwin — blocks the verdict (`None`).** Seatbelt-based records would
//!   mirror this contract, but no enforcement-soundness proof exists, so
//!   [`GatheredPlatform::MacOs`] answers `None` on every question via the
//!   platform gate.
//! - **A harness that needs `exec` — blocks the verdict (`None`).** The v1
//!   discharge set requires `execve`/`execveat` denied, which confines it to
//!   purpose-built chat clients that talk to a model API over the network and
//!   do nothing else. A full agent harness with subprocess tools cannot
//!   satisfy this contract, by design — the required `exec`-denial field is
//!   unset for it, so its verdict is `None`.

use crate::reachability::{GatheredPlatform, InspectedGrant};

/// Process-state records from the spawn itself.
///
/// One primitive action per field. Each is what the spawner *did*, not a
/// conclusion about what the child can therefore reach — the conclusions are
/// drawn by [`SpawnIsolation`]'s verdict methods.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpawnProcessFacts {
    /// The child was placed in a new session (`setsid`) and no terminal was
    /// opened between that and `exec`, so it has no controlling terminal.
    new_session_without_controlling_tty: bool,
    /// Fds 0/1/2 at exec were pipes created by the spawner for this child.
    stdio_is_spawner_pipes: bool,
    /// Every fd beyond stdio was closed (or `CLOEXEC`) at exec, so no
    /// terminal, socket, or file handle was inherited past the records here.
    no_fd_inherited_beyond_stdio: bool,
}

impl SpawnProcessFacts {
    /// Record the process facts of one performed spawn.
    #[must_use]
    pub const fn new(
        new_session_without_controlling_tty: bool,
        stdio_is_spawner_pipes: bool,
        no_fd_inherited_beyond_stdio: bool,
    ) -> Self {
        Self {
            new_session_without_controlling_tty,
            stdio_is_spawner_pipes,
            no_fd_inherited_beyond_stdio,
        }
    }

    const fn complete(&self) -> bool {
        self.new_session_without_controlling_tty
            && self.stdio_is_spawner_pipes
            && self.no_fd_inherited_beyond_stdio
    }
}

/// Privilege-state records imposed before exec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpawnPrivilegeFacts {
    /// `prctl(PR_SET_NO_NEW_PRIVS, 1)` was set, so no setuid/file-capability
    /// binary can re-acquire authority the records below strip.
    no_new_privs: bool,
    /// Effective, permitted, inheritable, and ambient capability sets were
    /// all emptied before exec.
    capability_sets_cleared: bool,
}

impl SpawnPrivilegeFacts {
    /// Record the privilege state imposed on one performed spawn.
    #[must_use]
    pub const fn new(no_new_privs: bool, capability_sets_cleared: bool) -> Self {
        Self {
            no_new_privs,
            capability_sets_cleared,
        }
    }

    const fn complete(&self) -> bool {
        self.no_new_privs && self.capability_sets_cleared
    }
}

/// Landlock filesystem-allowlist records: default-deny with the child's own
/// working files allowed, plus explicit confirmation that each named
/// backchannel path is outside the allowlist. Defense in depth for every
/// `open`-based reach path (terminal devices, the control socket, the config
/// root, and `/proc`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LandlockAllowlist {
    /// An enforced Landlock ruleset is in place whose allowlist is the
    /// child's own working files only — anything not allowed is denied.
    default_deny_enforced: bool,
    /// Nothing under the terminal device families (`/dev/tty*`, `/dev/pts/*`,
    /// `/dev/console`) is in the allowlist.
    excludes_tty_devices: bool,
    /// Nothing under the control socket path or its parent directory is in
    /// the allowlist.
    excludes_control_socket: bool,
    /// Nothing under the instance config root (sealed stores, registries,
    /// journal) is in the allowlist.
    excludes_config_root: bool,
    /// Nothing under the whole `/proc` subtree is in the allowlist, closing
    /// same-uid `open("/proc/<pid>/mem")` (memory read) *and*
    /// `open("/proc/<pid>/fd/<n>")` (magic-symlink fd duplication).
    excludes_proc: bool,
    /// The running kernel's Landlock ABI was queried and supports every
    /// filesystem-path access right this allowlist depends on (ABI v1, Linux
    /// 5.13), with no best-effort downgrade — so the exclusions above are
    /// enforced in effect, not merely requested. Without this, an older
    /// kernel could leave the `/proc`/tty/socket exclusions inert while the
    /// record reads as complete.
    abi_floor_supports_required_rights: bool,
}

impl LandlockAllowlist {
    /// Record the Landlock allowlist facts of one performed spawn.
    #[must_use]
    pub const fn new(
        default_deny_enforced: bool,
        excludes_tty_devices: bool,
        excludes_control_socket: bool,
        excludes_config_root: bool,
        excludes_proc: bool,
        abi_floor_supports_required_rights: bool,
    ) -> Self {
        Self {
            default_deny_enforced,
            excludes_tty_devices,
            excludes_control_socket,
            excludes_config_root,
            excludes_proc,
            abi_floor_supports_required_rights,
        }
    }

    /// Every filesystem backchannel path is excluded under an enforced
    /// default-deny ruleset whose rights the running kernel actually provides.
    const fn complete(&self) -> bool {
        self.default_deny_enforced
            && self.excludes_tty_devices
            && self.excludes_control_socket
            && self.excludes_config_root
            && self.excludes_proc
            && self.abi_floor_supports_required_rights
    }
}

/// Mount-family syscall denials — every entry point that can create, move,
/// pivot, or re-attribute a mount, each recorded separately.
///
/// One field per syscall on purpose: a single folded "mounting denied"
/// boolean would let an honest-but-incomplete spawner deny `mount(2)`, forget
/// `move_mount`/`fsmount`, and still record the folded flag `true` — silently
/// reopening the procfs-relocation escape with the fact set reading complete.
/// Enumerating each entry point makes the honest-spawner contract per-syscall
/// verifiable by a reviewer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MountDenials {
    /// `mount(2)` denied.
    mount: bool,
    /// `move_mount` denied (attaches a detached mount to the tree).
    move_mount: bool,
    /// `fsopen` denied (opens a filesystem context for the new mount API).
    fsopen: bool,
    /// `fsconfig` denied (configures that context).
    fsconfig: bool,
    /// `fsmount` denied (materializes a mount from the context).
    fsmount: bool,
    /// `open_tree` denied, `OPEN_TREE_CLONE` included (clones a mount subtree
    /// into a detached mount without `mount(2)`).
    open_tree: bool,
    /// `pivot_root` denied — the root filesystem cannot be swapped.
    pivot_root: bool,
    /// `mount_setattr` denied — cannot change mount attributes (propagation,
    /// idmap). Transitively foreclosed already (it can neither create nor
    /// relocate a mount, and its idmap attr needs a userns fd the namespace
    /// denials foreclose), but enumerated here so the mount family names every
    /// member rather than resting on a sibling denial.
    mount_setattr: bool,
}

impl MountDenials {
    /// Record the mount-family denials installed for one performed spawn.
    #[must_use]
    #[allow(clippy::fn_params_excessive_bools, clippy::too_many_arguments)]
    pub const fn new(
        mount: bool,
        move_mount: bool,
        fsopen: bool,
        fsconfig: bool,
        fsmount: bool,
        open_tree: bool,
        pivot_root: bool,
        mount_setattr: bool,
    ) -> Self {
        Self {
            mount,
            move_mount,
            fsopen,
            fsconfig,
            fsmount,
            open_tree,
            pivot_root,
            mount_setattr,
        }
    }

    /// Every mount entry point is denied, so nothing can be mounted, moved,
    /// pivoted, or re-attributed.
    const fn all_denied(&self) -> bool {
        self.mount
            && self.move_mount
            && self.fsopen
            && self.fsconfig
            && self.fsmount
            && self.open_tree
            && self.pivot_root
            && self.mount_setattr
    }
}

/// Namespace create/enter syscall denials, each recorded separately.
///
/// Same rationale as [`MountDenials`]: filtering `clone(CLONE_NEW*)` while
/// forgetting `clone3` (whose flags seccomp cannot inspect, so it must be
/// blocked wholesale) would leave a namespace-creation path open under a
/// folded flag reading `true`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NamespaceDenials {
    /// `unshare` denied — no new namespace can be created. Load-bearing
    /// against the mount-relocation escape: `unshare(CLONE_NEWUSER)` needs no
    /// capability yet grants `CAP_SYS_ADMIN` in-namespace.
    unshare: bool,
    /// `setns` denied — no re-entering an existing namespace.
    setns: bool,
    /// `clone(CLONE_NEW*)` namespace-creation flags filtered.
    clone_newns: bool,
    /// `clone3` blocked wholesale — its flags live in a struct seccomp cannot
    /// inspect, so it cannot be flag-filtered like `clone`.
    clone3: bool,
}

impl NamespaceDenials {
    /// Record the namespace-family denials installed for one performed spawn.
    #[must_use]
    pub const fn new(unshare: bool, setns: bool, clone_newns: bool, clone3: bool) -> Self {
        Self {
            unshare,
            setns,
            clone_newns,
            clone3,
        }
    }

    /// No namespace can be created or entered by any path.
    const fn all_denied(&self) -> bool {
        self.unshare && self.setns && self.clone_newns && self.clone3
    }
}

/// seccomp syscall-denial records, one field per syscall family that opens a
/// same-uid reach path.
///
/// Granular on purpose (see the module header): a single "process inspection
/// denied" boolean would let a spawner claim the family closed while leaving
/// `pidfd_getfd` — the same-uid fd-theft primitive — open, because it passes
/// `ptrace_may_access` same-uid and is not covered by denying `ptrace(2)`. The
/// mount and namespace families carry the same risk across several syscalls
/// each, so they are their own enumerated [`MountDenials`]/[`NamespaceDenials`]
/// records rather than folded booleans.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SeccompDenials {
    /// `socket(AF_UNIX, ..)` creation denied (value-typed domain arg) —
    /// forecloses pathname *and* abstract-namespace unix connects at the root.
    af_unix_socket: bool,
    /// `socketpair(AF_UNIX, ..)` denied, closing the second `AF_UNIX`
    /// creation path (so `SCM_RIGHTS` fd passing has no socket to ride).
    af_unix_socketpair: bool,
    /// `ptrace` denied.
    ptrace: bool,
    /// `process_vm_readv`/`process_vm_writev` denied (same-uid memory access).
    process_vm: bool,
    /// `pidfd_open` denied (prerequisite for `pidfd_getfd` fd theft).
    pidfd_open: bool,
    /// `pidfd_getfd` denied — the same-uid fd-theft primitive that steals the
    /// operator's already-open socket/TTY fd.
    pidfd_getfd: bool,
    /// `kcmp` denied.
    kcmp: bool,
    /// Terminal-injection ioctls (`TIOCSTI`, `TIOCLINUX`) denied.
    tty_ioctls: bool,
    /// `execve`/`execveat` denied — no shell or other binary can run.
    exec: bool,
    /// `io_uring_setup` denied — no io_uring ring can be created, so the
    /// interface cannot replay `openat`/`connect`/`recvmsg` off the syscall
    /// filter.
    io_uring_setup: bool,
    /// `io_uring_enter` denied — belt over `io_uring_setup`, in case a ring
    /// fd ever appeared (none is inherited).
    io_uring_enter: bool,
    /// Every mount entry point denied — the enumerated [`MountDenials`], so no
    /// procfs or bind mount can relocate a backchannel path into the allowlist.
    mount: MountDenials,
    /// Every namespace create/enter path denied — the enumerated
    /// [`NamespaceDenials`], closing the `unshare`/`clone` route to a new
    /// namespace in which a mount could be performed.
    namespace: NamespaceDenials,
    /// `open_by_handle_at` denied — it resolves a file by handle rather than
    /// by path, bypassing Landlock's path-walk hook entirely, so a
    /// path-based allowlist cannot contain it.
    open_by_handle_at: bool,
    /// `name_to_handle_at` denied — belt: without a handle source,
    /// `open_by_handle_at` has nothing to resolve.
    name_to_handle_at: bool,
}

impl SeccompDenials {
    /// Record the seccomp denials installed for one performed spawn.
    #[must_use]
    // One primitive record per syscall family, by design — each denial is its
    // own field so a spawner cannot over-claim a bundled family.
    #[allow(clippy::fn_params_excessive_bools, clippy::too_many_arguments)]
    pub const fn new(
        af_unix_socket: bool,
        af_unix_socketpair: bool,
        ptrace: bool,
        process_vm: bool,
        pidfd_open: bool,
        pidfd_getfd: bool,
        kcmp: bool,
        tty_ioctls: bool,
        exec: bool,
        io_uring_setup: bool,
        io_uring_enter: bool,
        mount: MountDenials,
        namespace: NamespaceDenials,
        open_by_handle_at: bool,
        name_to_handle_at: bool,
    ) -> Self {
        Self {
            af_unix_socket,
            af_unix_socketpair,
            ptrace,
            process_vm,
            pidfd_open,
            pidfd_getfd,
            kcmp,
            tty_ioctls,
            exec,
            io_uring_setup,
            io_uring_enter,
            mount,
            namespace,
            open_by_handle_at,
            name_to_handle_at,
        }
    }

    /// Both `AF_UNIX` creation paths denied, so no unix socket exists to
    /// connect the backchannel or receive a passed fd.
    const fn denies_unix_socket_creation(&self) -> bool {
        self.af_unix_socket && self.af_unix_socketpair
    }

    /// Every same-uid process-inspection and fd/memory-theft primitive
    /// denied: `ptrace`, `process_vm_*`, `pidfd_open`, `pidfd_getfd`, `kcmp`.
    const fn denies_process_inspection(&self) -> bool {
        self.ptrace && self.process_vm && self.pidfd_open && self.pidfd_getfd && self.kcmp
    }

    /// The io_uring interface is denied at creation, so no syscall denial in
    /// this record can be replayed off-filter through a submission queue.
    /// Load-bearing for *every* other seccomp and Landlock claim: without it,
    /// they reason about a syscall surface the requester can sidestep.
    const fn denies_syscall_filter_bypass(&self) -> bool {
        self.io_uring_setup && self.io_uring_enter
    }

    /// No namespace can be created or entered and nothing can be mounted, so
    /// the requester cannot relocate a backchannel path (a fresh procfs, a
    /// bind mount) into an allowlisted location and thereby reach it past the
    /// path-based Landlock exclusions.
    const fn denies_namespace_escape(&self) -> bool {
        self.namespace.all_denied() && self.mount.all_denied()
    }

    /// File opening by handle is denied, so the requester cannot bypass
    /// Landlock's path-walk hook by resolving a file through a handle instead
    /// of a path.
    const fn denies_handle_open_bypass(&self) -> bool {
        self.open_by_handle_at && self.name_to_handle_at
    }
}

/// Records of the sandbox policy installed before exec (Linux): the Landlock
/// filesystem allowlist and the seccomp syscall denials.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpawnSandboxPolicy {
    landlock: LandlockAllowlist,
    seccomp: SeccompDenials,
}

impl SpawnSandboxPolicy {
    /// Assemble the Landlock and seccomp records of one performed spawn.
    #[must_use]
    pub const fn new(landlock: LandlockAllowlist, seccomp: SeccompDenials) -> Self {
        Self { landlock, seccomp }
    }
}

/// Everything the host recorded about one spawn it performed.
///
/// The only path from here to an eligible operator is
/// [`Evidence::from_ceremony_spawn`], which copies this type's per-question
/// verdicts. There is no `Default` and no partial constructor.
///
/// [`Evidence::from_ceremony_spawn`]: crate::reachability::Evidence::from_ceremony_spawn
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpawnIsolation {
    platform: GatheredPlatform,
    process: SpawnProcessFacts,
    privilege: SpawnPrivilegeFacts,
    policy: SpawnSandboxPolicy,
    grant: Option<InspectedGrant>,
}

impl SpawnIsolation {
    /// Assemble the records of one performed spawn.
    ///
    /// `grant` is the spawned client's own host-issued grant (its registered
    /// read/proposal domains), or `None` when the spawner did not inspect
    /// one — which leaves `NoShellOrFilesystemGrant` undischarged rather than
    /// assumed.
    #[must_use]
    pub const fn new(
        platform: GatheredPlatform,
        process: SpawnProcessFacts,
        privilege: SpawnPrivilegeFacts,
        policy: SpawnSandboxPolicy,
        grant: Option<InspectedGrant>,
    ) -> Self {
        Self {
            platform,
            process,
            privilege,
            policy,
            grant,
        }
    }

    /// Whether the recorded platform's enforcement claims are proven.
    ///
    /// Only Linux today. Darwin's Seatbelt would mirror this contract, but
    /// its enforcement soundness is an unstarted verification lane, so it
    /// answers `None` — the same platform gate shape A applies.
    const fn platform_proven(&self) -> bool {
        matches!(self.platform, GatheredPlatform::Linux)
    }

    /// See [`crate::reachability::IsolationQuestion::OperatorAmbientAuthority`]:
    /// the child runs under the operator's own uid, so authority must be
    /// provably *stripped by construction* — no-new-privs plus emptied
    /// capability sets, with exec denied so nothing can hand authority back.
    pub(crate) fn operator_ambient_authority(&self) -> Option<bool> {
        (self.platform_proven() && self.privilege.complete() && self.policy.seccomp.exec)
            .then_some(true)
    }

    /// See [`crate::reachability::IsolationQuestion::BackchannelObjectReach`]:
    /// the backchannel objects (controlling terminal, control socket) must be
    /// unreachable by *creation* (no tty fd, no new unix socket, tty devices
    /// and socket path off the allowlist), by *injection* (tty ioctls
    /// denied), and by *theft* — `pidfd_getfd` stealing the operator's open
    /// socket/TTY fd is a same-uid path that none of the above closes.
    pub(crate) fn backchannel_object_reach(&self) -> Option<bool> {
        (self.platform_proven()
            && self.process.complete()
            && self.policy.landlock.complete()
            && self.policy.seccomp.denies_unix_socket_creation()
            && self.policy.seccomp.tty_ioctls
            && self.policy.seccomp.pidfd_open
            && self.policy.seccomp.pidfd_getfd
            && self.policy.seccomp.denies_syscall_filter_bypass()
            && self.policy.seccomp.denies_namespace_escape()
            && self.policy.seccomp.denies_handle_open_bypass())
        .then_some(true)
    }

    /// See [`crate::reachability::IsolationQuestion::OutsideHostProcess`]:
    /// the child is a separate process by construction; what must still be
    /// foreclosed is the same-uid process-inspection family (`ptrace`,
    /// `process_vm_*`, `pidfd_*`, `kcmp`) and `open("/proc/<pid>/mem")`,
    /// which is not a ptrace syscall and rests on the `/proc` exclusion.
    pub(crate) fn outside_host_process(&self) -> Option<bool> {
        (self.platform_proven()
            && self.policy.seccomp.denies_process_inspection()
            && self.policy.landlock.excludes_proc
            && self.policy.landlock.abi_floor_supports_required_rights
            && self.policy.seccomp.denies_syscall_filter_bypass()
            && self.policy.seccomp.denies_namespace_escape()
            && self.policy.seccomp.denies_handle_open_bypass())
        .then_some(true)
    }

    /// See [`crate::reachability::IsolationQuestion::NoShellOrFilesystemGrant`]:
    /// exec is denied (no shell exists to grant), the filesystem allowlist
    /// excludes every backchannel object, and the client's own host-issued
    /// grant confers no shell or filesystem domain.
    pub(crate) fn no_shell_or_filesystem_grant(&self) -> Option<bool> {
        let grant_clean = self
            .grant
            .as_ref()
            .is_some_and(InspectedGrant::confers_no_shell_or_filesystem_domain);
        (self.platform_proven()
            && self.policy.seccomp.exec
            && self.policy.landlock.complete()
            && self.policy.seccomp.denies_syscall_filter_bypass()
            && self.policy.seccomp.denies_namespace_escape()
            && self.policy.seccomp.denies_handle_open_bypass()
            && grant_clean)
            .then_some(true)
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use std::collections::BTreeSet;

    /// A complete, Linux, fully-recorded spawn — the only fact set that
    /// discharges all four questions. Tests derive every negative case by
    /// breaking exactly one record.
    pub(crate) fn complete_linux_spawn() -> SpawnIsolation {
        SpawnIsolation::new(
            GatheredPlatform::Linux,
            SpawnProcessFacts::new(true, true, true),
            SpawnPrivilegeFacts::new(true, true),
            SpawnSandboxPolicy::new(
                LandlockAllowlist::new(true, true, true, true, true, true),
                SeccompDenials::new(
                    true,
                    true,
                    true,
                    true,
                    true,
                    true,
                    true,
                    true,
                    true,
                    true,
                    true,
                    MountDenials::new(true, true, true, true, true, true, true, true),
                    NamespaceDenials::new(true, true, true, true),
                    true,
                    true,
                ),
            ),
            // An empty grant trivially confers no shell or filesystem
            // domain; the conferring case is covered by its own test.
            Some(InspectedGrant::new(BTreeSet::new(), BTreeSet::new())),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::complete_linux_spawn;
    use super::*;
    use crate::operator::OperatorIdentity;
    use crate::reachability::{Evidence, Reachability, classify};

    fn identity() -> OperatorIdentity {
        OperatorIdentity::new("jordan").expect("valid operator identity")
    }

    fn eligible(spawn: &SpawnIsolation) -> bool {
        classify(&identity(), &Evidence::from_ceremony_spawn(spawn)).permits_approval()
    }

    #[test]
    fn a_complete_linux_spawn_discharges_all_four_questions() {
        let spawn = complete_linux_spawn();
        let analysis = classify(&identity(), &Evidence::from_ceremony_spawn(&spawn));
        assert_eq!(analysis.reachability(), Reachability::ProvablyIsolated);
        assert!(analysis.permits_approval());
    }

    #[test]
    fn darwin_answers_none_on_every_question_regardless_of_records() {
        // The platform gate: identical records, Darwin platform — Seatbelt
        // enforcement soundness is unproven, so nothing discharges. Guarded
        // by a mutation check: making `platform_proven` accept MacOs must
        // fail this test.
        let mut spawn = complete_linux_spawn();
        spawn.platform = GatheredPlatform::MacOs;
        assert_eq!(spawn.operator_ambient_authority(), None);
        assert_eq!(spawn.backchannel_object_reach(), None);
        assert_eq!(spawn.outside_host_process(), None);
        assert_eq!(spawn.no_shell_or_filesystem_grant(), None);
        assert!(!eligible(&spawn));
    }

    #[test]
    fn other_platforms_answer_none_on_every_question() {
        let mut spawn = complete_linux_spawn();
        spawn.platform = GatheredPlatform::Other;
        assert!(!eligible(&spawn));
    }

    #[test]
    fn breaking_any_single_process_record_refuses_backchannel_reach() {
        for breaker in [
            (|f: &mut SpawnIsolation| f.process.new_session_without_controlling_tty = false)
                as fn(&mut SpawnIsolation),
            |f: &mut SpawnIsolation| f.process.stdio_is_spawner_pipes = false,
            |f: &mut SpawnIsolation| f.process.no_fd_inherited_beyond_stdio = false,
        ] {
            let mut spawn = complete_linux_spawn();
            breaker(&mut spawn);
            assert_eq!(
                spawn.backchannel_object_reach(),
                None,
                "an incomplete process record must leave the backchannel undischarged"
            );
            assert!(!eligible(&spawn));
        }
    }

    #[test]
    fn breaking_any_single_landlock_record_refuses_eligibility() {
        for breaker in [
            (|p: &mut LandlockAllowlist| p.default_deny_enforced = false)
                as fn(&mut LandlockAllowlist),
            |p: &mut LandlockAllowlist| p.excludes_tty_devices = false,
            |p: &mut LandlockAllowlist| p.excludes_control_socket = false,
            |p: &mut LandlockAllowlist| p.excludes_config_root = false,
            |p: &mut LandlockAllowlist| p.excludes_proc = false,
            |p: &mut LandlockAllowlist| p.abi_floor_supports_required_rights = false,
        ] {
            let mut spawn = complete_linux_spawn();
            breaker(&mut spawn.policy.landlock);
            assert!(
                !eligible(&spawn),
                "a single missing Landlock exclusion must refuse eligibility"
            );
        }
    }

    #[test]
    fn breaking_any_single_seccomp_denial_refuses_eligibility() {
        // Every seccomp denial is load-bearing for at least one question —
        // in particular pidfd_getfd/pidfd_open (fd theft) and socketpair
        // (the second AF_UNIX creation path), the same-uid holes a bundled
        // "inspection denied" flag would have hidden.
        for breaker in [
            (|s: &mut SeccompDenials| s.af_unix_socket = false) as fn(&mut SeccompDenials),
            |s: &mut SeccompDenials| s.af_unix_socketpair = false,
            |s: &mut SeccompDenials| s.ptrace = false,
            |s: &mut SeccompDenials| s.process_vm = false,
            |s: &mut SeccompDenials| s.pidfd_open = false,
            |s: &mut SeccompDenials| s.pidfd_getfd = false,
            |s: &mut SeccompDenials| s.kcmp = false,
            |s: &mut SeccompDenials| s.tty_ioctls = false,
            |s: &mut SeccompDenials| s.exec = false,
            |s: &mut SeccompDenials| s.io_uring_setup = false,
            |s: &mut SeccompDenials| s.io_uring_enter = false,
            |s: &mut SeccompDenials| s.open_by_handle_at = false,
            |s: &mut SeccompDenials| s.name_to_handle_at = false,
        ] {
            let mut spawn = complete_linux_spawn();
            breaker(&mut spawn.policy.seccomp);
            assert!(
                !eligible(&spawn),
                "a single missing seccomp denial must refuse eligibility"
            );
        }
    }

    #[test]
    fn breaking_any_single_mount_denial_refuses_eligibility() {
        // Every mount entry point is load-bearing: a spawner that denies
        // mount(2) but forgets, say, move_mount or fsmount must NOT read as
        // complete — the enumerated split is what makes that honest.
        for breaker in [
            (|m: &mut MountDenials| m.mount = false) as fn(&mut MountDenials),
            |m: &mut MountDenials| m.move_mount = false,
            |m: &mut MountDenials| m.fsopen = false,
            |m: &mut MountDenials| m.fsconfig = false,
            |m: &mut MountDenials| m.fsmount = false,
            |m: &mut MountDenials| m.open_tree = false,
            |m: &mut MountDenials| m.pivot_root = false,
            |m: &mut MountDenials| m.mount_setattr = false,
        ] {
            let mut spawn = complete_linux_spawn();
            breaker(&mut spawn.policy.seccomp.mount);
            assert!(
                !eligible(&spawn),
                "a single missing mount-family denial must refuse eligibility"
            );
        }
    }

    #[test]
    fn breaking_any_single_namespace_denial_refuses_eligibility() {
        // clone vs clone3 is the load-bearing pair: filtering clone flags but
        // forgetting clone3 (unfilterable, must be blocked wholesale) must not
        // read as complete.
        for breaker in [
            (|n: &mut NamespaceDenials| n.unshare = false) as fn(&mut NamespaceDenials),
            |n: &mut NamespaceDenials| n.setns = false,
            |n: &mut NamespaceDenials| n.clone_newns = false,
            |n: &mut NamespaceDenials| n.clone3 = false,
        ] {
            let mut spawn = complete_linux_spawn();
            breaker(&mut spawn.policy.seccomp.namespace);
            assert!(
                !eligible(&spawn),
                "a single missing namespace-family denial must refuse eligibility"
            );
        }
    }

    #[test]
    fn namespace_escape_alone_defeats_the_reach_verdicts() {
        // The gate's highest-priority vector: unshare(NEWUSER)+unshare(NEWNS)
        // then mount a fresh procfs at an allowlisted path relocates
        // /proc/<operator>/fd/<n> inside a Landlock-allowed path, dup'ing the
        // operator's socket/TTY fd past excludes_proc. Leaving only `unshare`
        // open must refuse every reach verdict while ambient (privilege state
        // unshare cannot alter in the init namespace) stays provable.
        let mut spawn = complete_linux_spawn();
        spawn.policy.seccomp.namespace.unshare = false;
        assert_eq!(spawn.backchannel_object_reach(), None);
        assert_eq!(spawn.outside_host_process(), None);
        assert_eq!(spawn.no_shell_or_filesystem_grant(), None);
        assert_eq!(spawn.operator_ambient_authority(), Some(true));
        assert!(!eligible(&spawn));
    }

    #[test]
    fn open_by_handle_at_alone_defeats_the_reach_verdicts() {
        // Handle-based open bypasses Landlock path-walk; leaving it open must
        // refuse the path-dependent verdicts self-containedly, not only via
        // the caps-cleared gate that lives in operator_ambient_authority.
        let mut spawn = complete_linux_spawn();
        spawn.policy.seccomp.open_by_handle_at = false;
        assert_eq!(spawn.backchannel_object_reach(), None);
        assert_eq!(spawn.outside_host_process(), None);
        assert_eq!(spawn.no_shell_or_filesystem_grant(), None);
        assert!(!eligible(&spawn));
    }

    #[test]
    fn pidfd_getfd_theft_alone_defeats_backchannel_reach() {
        // The gate's headline vector, pinned explicitly: everything else
        // recorded, only pidfd_getfd left open — the operator's socket/TTY fd
        // is stealable, so the backchannel is not out of reach.
        let mut spawn = complete_linux_spawn();
        spawn.policy.seccomp.pidfd_getfd = false;
        assert_eq!(spawn.backchannel_object_reach(), None);
        assert!(!eligible(&spawn));
    }

    #[test]
    fn io_uring_setup_alone_defeats_every_syscall_dependent_verdict() {
        // io_uring off-filter replay: with the ring left open, every
        // open/socket/proc denial is bypassable, so each syscall- or
        // path-dependent question must refuse — while operator_ambient_authority
        // (process privilege state io_uring cannot alter) is unaffected.
        let mut spawn = complete_linux_spawn();
        spawn.policy.seccomp.io_uring_setup = false;
        assert_eq!(spawn.backchannel_object_reach(), None);
        assert_eq!(spawn.outside_host_process(), None);
        assert_eq!(spawn.no_shell_or_filesystem_grant(), None);
        assert_eq!(
            spawn.operator_ambient_authority(),
            Some(true),
            "ambient authority rests on privilege state io_uring cannot change"
        );
        assert!(!eligible(&spawn));
    }

    #[test]
    fn an_unrecorded_landlock_abi_floor_refuses_eligibility() {
        // The version-floor fact: exclusions recorded but the kernel's
        // Landlock ABI not confirmed to provide them → inert in effect → None.
        let mut spawn = complete_linux_spawn();
        spawn.policy.landlock.abi_floor_supports_required_rights = false;
        assert_eq!(spawn.backchannel_object_reach(), None);
        assert_eq!(spawn.outside_host_process(), None);
        assert!(!eligible(&spawn));
    }

    #[test]
    fn missing_privilege_records_refuse_ambient_authority() {
        let mut spawn = complete_linux_spawn();
        spawn.privilege.no_new_privs = false;
        assert_eq!(spawn.operator_ambient_authority(), None);

        let mut spawn = complete_linux_spawn();
        spawn.privilege.capability_sets_cleared = false;
        assert_eq!(spawn.operator_ambient_authority(), None);
    }

    #[test]
    fn an_uninspected_or_conferring_grant_refuses_the_grant_question() {
        let mut spawn = complete_linux_spawn();
        spawn.grant = None;
        assert_eq!(
            spawn.no_shell_or_filesystem_grant(),
            None,
            "no inspected grant must mean undischarged, never assumed clean"
        );

        let mut spawn = complete_linux_spawn();
        spawn.grant = Some(InspectedGrant::new(
            std::collections::BTreeSet::from(["shell.exec".to_string()]),
            std::collections::BTreeSet::new(),
        ));
        assert_eq!(
            spawn.no_shell_or_filesystem_grant(),
            None,
            "a grant conferring a shell domain must leave the question undischarged"
        );
    }
}
