//! The durable apply worker: the atomic `approved` to `applying` claim, and the
//! host-driven apply that follows it.
//!
//! This is the single place in the control plane where host state is mutated as
//! a result of a proposal. It exists to make one invariant true: **config is
//! written only after a valid single-use approval receipt from an eligible
//! operator is verified and consumed in the same durable transaction, and that
//! write goes exclusively through the existing revision-bound Quickstart
//! compare-and-swap.**
//!
//! The worker is **host-driven**, never requester-driven. It takes an operation
//! identifier and a clock; it reconstructs the requester binding from the
//! durable journal entry and consumes the receipt an operator already issued and
//! the journal already recorded. There is no requester field it accepts that
//! could trigger an apply, and it never mints a receipt or accepts an `approved`
//! flag.
//!
//! ## The six-step claim
//!
//! Reproduced verbatim from
//! `docs/book/src/architecture/control-plane-proposal-journal.md`, because the
//! ordering is the property. Before entering `applying`, the host:
//!
//! 1. acquires the exclusive instance config and transaction lock;
//! 2. re-reads the source revision and framework-derived dependencies, and
//!    recomputes the instance fingerprint under lock (a replaced or symlinked
//!    root expires the proposal);
//! 3. verifies every pinned external fact represented in the preview (a changed
//!    fact expires, not applies);
//! 4. starts one journal-database transaction;
//! 5. verifies and consumes the approval receipt while changing `approved` to
//!    `applying` — receipt consumption and the `applying` record are one atomic
//!    durable fact; and
//! 6. commits and syncs that transaction before changing config.
//!
//! Steps 2 and 3 are realized by re-inspecting the config under the transaction
//! lock, recomputing the instance fingerprint from the probed roots, and
//! re-deriving the canonical proposal digest from a freshly built preview. Any
//! drift — a moved source revision, a replaced or symlinked root, a changed
//! provider target or other previewed fact — makes one of those recomputed
//! values differ from what the receipt was issued against, and
//! [`verify_for_consumption`] refuses it. The refusal expires the proposal; it
//! never consumes the receipt and never writes config.
//!
//! ## The transaction lock
//!
//! Step 1's "exclusive instance config and transaction lock" is realized as a
//! layered pair. This worker holds a control-plane transaction lock
//! (`control/journal.lock`) across the whole claim and the apply, which
//! serializes every control-plane apply and root-selection against each other so
//! two workers cannot rewrite the journal concurrently. The Quickstart CAS that
//! performs the actual config byte-write independently holds the revision-bound
//! config write lock (finding #41, `.config.toml.lock`). They are two distinct
//! lock files on purpose: reusing one would deadlock the inner CAS against the
//! outer claim.

use std::fs::OpenOptions;
use std::path::PathBuf;

use fs2::FileExt as _;

use crate::approval::{Expectations, ProposalDigest, SourceRevisionDigest, verify_for_consumption};
use crate::genesis::GenesisRecord;
use crate::journal::{
    ArtifactKind, EffectImage, JournalError, JournalState, OperationId, ProposalJournal,
};
use crate::keys::ApprovalAuditKey;
use crate::operator::{OperatorRegistry, PrincipalClass, RequesterContext, RequesterSubject};
use crate::reachability::Evidence;
use crate::registry::{InstanceFingerprint, RootIdentity};
use crate::service::{ControlError, ControlService};
use crate::store::ControlPaths;
use sha2::{Digest, Sha256};

/// File name of the control-plane transaction lock, under the control state
/// directory.
pub const TRANSACTION_LOCK_FILE: &str = "journal.lock";

/// The terminal outcome of a successful claim and apply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkerOutcome {
    /// The receipt was consumed, config committed through the Quickstart CAS,
    /// and the verification plan confirmed effective state. The entry is
    /// `verified`.
    Verified {
        /// The agent alias that now exists.
        agent_alias: String,
    },
}

/// Why a claim did not reach `verified`.
///
/// Each variant names the durable state the entry was left in, so a caller can
/// read Status without re-deriving it. No variant leaves a half-written config:
/// `Expired` and `Failed` guarantee no effect reached disk under this receipt,
/// and `RecoveryRequired` parks for the recovery service.
#[derive(Debug)]
pub enum WorkerError {
    /// A binding fact changed, the clock was untrustworthy, or the receipt did
    /// not verify. The entry is `expired`; no receipt was consumed and no config
    /// was written.
    Expired { detail: String },
    /// The apply was refused with every effect classified as not-applied. The
    /// entry is `failed`; the receipt stays consumed and a new approval is
    /// required to try again.
    Failed { detail: String },
    /// The apply outcome could not be determined, or verification could not
    /// confirm effective state. The entry is `recovery_required` and awaits the
    /// recovery service or an operator.
    RecoveryRequired { detail: String },
    /// The named entry is not in `approved`; there is nothing to claim.
    NotApproved { state: JournalState },
    /// The named entry does not exist.
    UnknownOperation,
    /// The durable journal could not be read or written.
    Journal(JournalError),
    /// The transaction lock could not be acquired.
    Lock(String),
    /// A test-injected crash at a claim seam. Never constructed in a shipped
    /// build.
    #[cfg(test)]
    InjectedCrash,
}

impl std::fmt::Display for WorkerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Expired { detail } => write!(f, "proposal expired: {detail}"),
            Self::Failed { detail } => write!(f, "apply failed: {detail}"),
            Self::RecoveryRequired { detail } => write!(f, "recovery required: {detail}"),
            Self::NotApproved { state } => {
                write!(f, "entry is {}, not approved", state.wire())
            }
            Self::UnknownOperation => write!(f, "no such operation"),
            Self::Journal(error) => write!(f, "{error}"),
            Self::Lock(detail) => write!(f, "transaction lock: {detail}"),
            #[cfg(test)]
            Self::InjectedCrash => write!(f, "injected crash"),
        }
    }
}

impl std::error::Error for WorkerError {}

impl From<JournalError> for WorkerError {
    fn from(error: JournalError) -> Self {
        Self::Journal(error)
    }
}

/// A test-only seam that simulates a crash at one of the two documented claim
/// windows (and the pre-commit window). Compiled out of every shipped build.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FaultPoint {
    /// Crash after the in-memory claim mutation but before the step-6 commit.
    /// The durable journal stays `approved`, the receipt unconsumed.
    PreApplyingCommit,
    /// Crash after the step-6 commit but before the config write. The durable
    /// journal is `applying`, the receipt consumed, config unchanged.
    PostCommitPreConfig,
    /// Crash after the config write but before recording `applied`. The durable
    /// journal is `applying`, the receipt consumed, config carries the effect.
    PostConfigPreApplied,
}

/// Drives one approved proposal through the atomic claim and the host apply.
///
/// Holds only borrows: the durable paths, the ADR-015 key, the operator
/// registry, the management service, and the genesis record whose identity the
/// instance fingerprint is recomputed against.
pub struct ApplyWorker<'a> {
    paths: &'a ControlPaths,
    key: &'a ApprovalAuditKey,
    operators: &'a OperatorRegistry,
    service: &'a ControlService,
    record: &'a GenesisRecord,
    #[cfg(test)]
    fault_at: Option<FaultPoint>,
}

impl<'a> ApplyWorker<'a> {
    /// Build a worker over one managed instance.
    #[must_use]
    pub fn new(
        paths: &'a ControlPaths,
        key: &'a ApprovalAuditKey,
        operators: &'a OperatorRegistry,
        service: &'a ControlService,
        record: &'a GenesisRecord,
    ) -> Self {
        Self {
            paths,
            key,
            operators,
            service,
            record,
            #[cfg(test)]
            fault_at: None,
        }
    }

    /// The same worker with a crash injected at `point`. Test-only.
    #[cfg(test)]
    pub(crate) fn with_fault(mut self, point: FaultPoint) -> Self {
        self.fault_at = Some(point);
        self
    }

    /// The control-plane transaction lock path.
    fn transaction_lock_path(&self) -> PathBuf {
        self.paths.control_dir().join(TRANSACTION_LOCK_FILE)
    }

    /// The durable paths this worker operates over.
    pub(crate) fn paths(&self) -> &ControlPaths {
        self.paths
    }

    /// The ADR-015 approval and audit key.
    pub(crate) fn key(&self) -> &ApprovalAuditKey {
        self.key
    }

    /// The management service the apply is driven through.
    pub(crate) fn service(&self) -> &ControlService {
        self.service
    }

    /// Acquire the exclusive control-plane transaction lock. The returned file
    /// releases the advisory lock on drop.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::Lock`] when the lock file cannot be opened or the
    /// lock cannot be acquired.
    pub(crate) fn acquire_transaction_lock(&self) -> Result<std::fs::File, WorkerError> {
        let lock_path = self.transaction_lock_path();
        crate::store::ensure_state_dir(&self.paths.control_dir())
            .map_err(|e| WorkerError::Lock(e.to_string()))?;
        let lock_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)
            .map_err(|e| WorkerError::Lock(format!("open {}: {e}", lock_path.display())))?;
        lock_file
            .lock_exclusive()
            .map_err(|e| WorkerError::Lock(format!("acquire: {e}")))?;
        Ok(lock_file)
    }

    /// Recompute the instance fingerprint from the currently-probed roots.
    ///
    /// A replaced root has a different object identity, and a root redirected
    /// through a symlink probes as [`crate::registry::RootFileType::Symlink`];
    /// either changes the fingerprint, so the receipt — issued against the
    /// fingerprint at decision time — no longer matches and is refused.
    fn recompute_fingerprint(&self) -> Result<InstanceFingerprint, WorkerError> {
        let roots = self
            .paths
            .canonical_roots()
            .map_err(|e| WorkerError::Expired {
                detail: e.to_string(),
            })?;
        let config = RootIdentity::probe(&roots.config_root).map_err(|e| WorkerError::Expired {
            detail: format!("probe config root: {e}"),
        })?;
        let data = RootIdentity::probe(&roots.data_root).map_err(|e| WorkerError::Expired {
            detail: format!("probe data root: {e}"),
        })?;
        Ok(InstanceFingerprint::compute(
            &self.record.instance_id,
            &self.record.digest(),
            self.record.trust_epoch,
            &roots,
            &config,
            &data,
        ))
    }

    /// Claim an approved proposal and apply it.
    ///
    /// Host-driven: it takes only the operation identifier and the current
    /// trusted wall-clock time. The requester binding is reconstructed from the
    /// durable entry, and the receipt is read from the durable entry — no live
    /// requester input reaches this path.
    ///
    /// # Errors
    ///
    /// See [`WorkerError`]. Every non-`Verified` outcome leaves the entry in a
    /// durable state that guarantees no partial config write under this receipt.
    pub async fn apply_approved(
        &self,
        operation_id: &OperationId,
        now_unix_secs: u64,
    ) -> Result<WorkerOutcome, WorkerError> {
        self.claim_and_apply(operation_id, now_unix_secs).await
    }

    /// Continue an already-authorized `applying` entry, assuming the transaction
    /// lock is already held by the caller (the recovery service).
    ///
    /// This is the "continue that exact operation" scope from the design: the
    /// receipt is already consumed and is not re-verified or re-consumed. The
    /// worker re-inspects and re-previews, drives the same revision-bound CAS,
    /// and records the terminal state. It never re-derives a new operation and
    /// never mints or re-consumes a receipt. An inspection or preview failure
    /// here cannot expire an `applying` entry, so it parks in
    /// `recovery_required`.
    ///
    /// # Errors
    ///
    /// See [`WorkerError`].
    pub(crate) async fn resume_applying_locked(
        &self,
        operation_id: &OperationId,
        now_unix_secs: u64,
    ) -> Result<WorkerOutcome, WorkerError> {
        let _ = now_unix_secs;
        let mut journal = ProposalJournal::load(self.paths, self.key)?;
        let entry = journal
            .entry(operation_id)
            .ok_or(WorkerError::UnknownOperation)?;
        if entry.state != JournalState::Applying {
            return Err(WorkerError::NotApproved { state: entry.state });
        }
        let expected_agent_alias = entry.verification_plan.expected_agent_alias.clone();
        let agent_proposal = entry.agent_proposal.clone();
        let selected_provider_ref = entry.selected_provider_ref.clone();

        let inspection = match self.service.inspect().await {
            Ok(inspection) => inspection,
            Err(error) => {
                return self.park_recovery(&mut journal, operation_id, inspect_reason(&error));
            }
        };
        let bound = match self
            .service
            .preview(inspection, &selected_provider_ref, &agent_proposal)
        {
            Ok(bound) => bound,
            Err(error) => {
                return self.park_recovery(&mut journal, operation_id, preview_reason(&error));
            }
        };
        let apply_result = self.service.apply(bound).await;
        self.record_apply_result(
            &mut journal,
            operation_id,
            apply_result,
            expected_agent_alias,
        )
        .await
    }

    /// Move an entry to `recovery_required` and return the matching error.
    pub(crate) fn park_recovery(
        &self,
        journal: &mut ProposalJournal,
        operation_id: &OperationId,
        detail: impl Into<String>,
    ) -> Result<WorkerOutcome, WorkerError> {
        let detail = detail.into();
        journal.transition(
            operation_id,
            JournalState::RecoveryRequired,
            |entry| entry.disposition = Some(detail.clone()),
            self.paths,
            self.key,
        )?;
        Err(WorkerError::RecoveryRequired { detail })
    }

    async fn claim_and_apply(
        &self,
        operation_id: &OperationId,
        now_unix_secs: u64,
    ) -> Result<WorkerOutcome, WorkerError> {
        // Step 1: the exclusive control-plane transaction lock. Held for the
        // whole claim and apply so no other control-plane worker can move the
        // journal or config out from under this one. It releases on drop at the
        // end of this function, after the apply and every journal write.
        let lock_file = self.acquire_transaction_lock()?;
        let result = self
            .claim_and_apply_locked(operation_id, now_unix_secs)
            .await;
        drop(lock_file);
        result
    }

    async fn claim_and_apply_locked(
        &self,
        operation_id: &OperationId,
        now_unix_secs: u64,
    ) -> Result<WorkerOutcome, WorkerError> {
        // Reload the journal under the lock: the state every later step observes
        // is one no other writer can move.
        let mut journal = ProposalJournal::load(self.paths, self.key)?;
        let entry = journal
            .entry(operation_id)
            .ok_or(WorkerError::UnknownOperation)?;
        if entry.state != JournalState::Approved {
            return Err(WorkerError::NotApproved { state: entry.state });
        }

        // Reconstruct the requester binding from the durable entry. No live
        // requester input reaches the claim; this is what makes "no requester
        // field triggers an apply" structurally true.
        let requester = reconstruct_requester(entry)?;

        // The receipt an operator already issued and the journal already
        // recorded. The worker consumes one; it never mints one.
        let recorded = entry
            .recorded_receipt(self.key)
            .map_err(|e| WorkerError::Expired {
                detail: e.to_string(),
            })?
            .ok_or(WorkerError::Expired {
                detail: "no recorded receipt on an approved entry".to_owned(),
            })?;
        let sealed_receipt = recorded.as_sealed_bytes().to_vec();

        let expected_agent_alias = entry.verification_plan.expected_agent_alias.clone();
        let agent_proposal = entry.agent_proposal.clone();
        let selected_provider_ref = entry.selected_provider_ref.clone();
        let operation = entry.operation;
        let target_instance = entry.target_instance.clone();
        let high_water = journal.high_water_unix_secs().max(now_unix_secs);

        // Step 2: re-read the source revision and recompute the fingerprint
        // under lock. An inspection failure (stale schema, degraded, or busy)
        // is a fact change and expires the proposal before any transaction.
        let inspection = match self.service.inspect().await {
            Ok(inspection) => inspection,
            Err(error) => {
                return self.expire(&mut journal, operation_id, inspect_reason(&error));
            }
        };
        let fresh_source = inspection.source_revision().to_owned();
        let source_revision = SourceRevisionDigest::of(&fresh_source);
        let workspace_dir = inspection
            .config()
            .agent_workspace_dir(&expected_agent_alias);
        let instance_fingerprint = match self.recompute_fingerprint() {
            Ok(fingerprint) => fingerprint,
            Err(WorkerError::Expired { detail }) => {
                return self.expire(&mut journal, operation_id, detail);
            }
            Err(other) => return Err(other),
        };

        // Step 3: re-derive the canonical proposal digest from a preview built
        // against the current config. Any changed previewed fact — provider
        // target, profile, memory, alias availability — changes the preview and
        // therefore the digest, and the receipt no longer matches.
        let bound = match self
            .service
            .preview(inspection, &selected_provider_ref, &agent_proposal)
        {
            Ok(bound) => bound,
            Err(error) => {
                return self.expire(&mut journal, operation_id, preview_reason(&error));
            }
        };
        let recomputed_digest = match ProposalDigest::of_bound_proposal(&bound) {
            Ok(digest) => digest,
            Err(error) => {
                return self.expire(&mut journal, operation_id, error.detail);
            }
        };

        // Capture pre-images under lock, before any effect is written, so
        // recovery can compare current state against them.
        let config_pre_image = EffectImage::Digest {
            sha256: sha256(fresh_source.as_bytes()),
        };
        let personality_pre_images =
            capture_personality_pre_images(&agent_proposal, &workspace_dir);

        // Steps 4 and 5: one journal transaction that verifies and consumes the
        // receipt while changing `approved` to `applying`. Verification is the
        // hardened re-check; nothing here restates the receipt's own fields.
        let expectations = Expectations {
            operation,
            proposal_digest: &recomputed_digest,
            target_instance: &target_instance,
            instance_fingerprint: &instance_fingerprint,
            source_revision: &source_revision,
            trust_epoch: self.record.trust_epoch,
            now_unix_secs,
            high_water_unix_secs: high_water,
        };
        let marker = match verify_for_consumption(
            &sealed_receipt,
            self.key,
            &expectations,
            &journal.ledger(),
            self.operators,
            &requester,
        ) {
            Ok(marker) => marker,
            Err(error) => {
                // A failed verification is never an apply. The proposal expires;
                // the receipt is untouched and stays consumable only if nothing
                // else expired it.
                return self.expire(&mut journal, operation_id, error.detail);
            }
        };

        // The in-memory claim mutation: consume the receipt and record
        // `applying`, its apply order, and every pre-image. These are two
        // fields of one journal that a single `persist` writes as one durable
        // fact.
        journal.mark_receipt_consumed(&marker)?;
        {
            let entry = journal
                .entry_mut(operation_id)
                .ok_or(WorkerError::UnknownOperation)?;
            if !entry.state.may_transition_to(JournalState::Applying) {
                return Err(WorkerError::Journal(JournalError::new(
                    crate::journal::JournalErrorCode::IllegalTransition,
                    format!("{} -> applying", entry.state.wire()),
                )));
            }
            entry.state = JournalState::Applying;
            entry.consumed_receipt_id = Some(marker.receipt_id().clone());
            record_pre_images(entry, &config_pre_image, &personality_pre_images);
            entry.apply_order = apply_order(entry);
        }

        #[cfg(test)]
        if self.fault_at == Some(FaultPoint::PreApplyingCommit) {
            // Simulate a crash before the step-6 commit: return without
            // persisting. On disk the journal is still `approved`, the receipt
            // unconsumed.
            return Err(WorkerError::InjectedCrash);
        }

        // Step 6: commit and sync the transaction BEFORE any config change. The
        // journal is now ahead of the filesystem.
        journal.persist(self.paths, self.key)?;

        #[cfg(test)]
        if self.fault_at == Some(FaultPoint::PostCommitPreConfig) {
            // Simulate a crash after the step-6 commit, before the config write.
            // On disk the journal is `applying`, the receipt consumed, config
            // unchanged.
            return Err(WorkerError::InjectedCrash);
        }

        // Drive the existing revision-bound Quickstart CAS. This is the only
        // path that writes config, and it is reached only here, only after the
        // committed claim above.
        let apply_result = self.service.apply(bound).await;

        #[cfg(test)]
        if self.fault_at == Some(FaultPoint::PostConfigPreApplied) {
            // Simulate a crash after the config write, before recording
            // `applied`. On disk the journal is `applying`; the config write may
            // have landed. Recovery classifies from the observed artefacts.
            let _ = apply_result;
            return Err(WorkerError::InjectedCrash);
        }

        self.record_apply_result(
            &mut journal,
            operation_id,
            apply_result,
            expected_agent_alias,
        )
        .await
    }

    /// Fold the Quickstart apply result into a durable terminal or parked state.
    async fn record_apply_result(
        &self,
        journal: &mut ProposalJournal,
        operation_id: &OperationId,
        apply_result: Result<crate::service::ControlApplyOutcome, ControlError>,
        expected_agent_alias: String,
    ) -> Result<WorkerOutcome, WorkerError> {
        match apply_result {
            Ok(outcome) => {
                // The service's own apply already verified the committed
                // revision and the effective install. Record every effect as
                // applied, move to `applied`, then to `verified`.
                journal.transition(
                    operation_id,
                    JournalState::Applied,
                    record_all_applied,
                    self.paths,
                    self.key,
                )?;
                journal.transition(
                    operation_id,
                    JournalState::Verified,
                    |entry| {
                        entry.disposition = Some(format!("verified: {}", outcome.agent_alias()));
                    },
                    self.paths,
                    self.key,
                )?;
                Ok(WorkerOutcome::Verified {
                    agent_alias: expected_agent_alias,
                })
            }
            Err(error) => self.record_apply_failure(journal, operation_id, error),
        }
    }

    /// Map a failed apply into `failed` (definitely no write) or
    /// `recovery_required` (uncertain), conservatively.
    fn record_apply_failure(
        &self,
        journal: &mut ProposalJournal,
        operation_id: &OperationId,
        error: ControlError,
    ) -> Result<WorkerOutcome, WorkerError> {
        // Conservative disposition: only outcomes that could not have written
        // config are `failed`; anything uncertain parks in `recovery_required`
        // so a human resolves it rather than the worker guessing.
        let definitely_no_write = matches!(
            error,
            ControlError::Apply { .. }
                | ControlError::SourceSchemaOutdated
                | ControlError::ConfigDegraded
                | ControlError::Proposal(_)
        );
        let detail = error.to_string();
        if definitely_no_write {
            journal.transition(
                operation_id,
                JournalState::Failed,
                |entry| {
                    record_all_not_applied(entry);
                    entry.disposition = Some(format!("apply refused: {detail}"));
                },
                self.paths,
                self.key,
            )?;
            Err(WorkerError::Failed { detail })
        } else {
            journal.transition(
                operation_id,
                JournalState::RecoveryRequired,
                |entry| entry.disposition = Some(format!("apply outcome uncertain: {detail}")),
                self.paths,
                self.key,
            )?;
            Err(WorkerError::RecoveryRequired { detail })
        }
    }

    /// Move an entry to `expired` and return the matching error.
    fn expire(
        &self,
        journal: &mut ProposalJournal,
        operation_id: &OperationId,
        detail: impl Into<String>,
    ) -> Result<WorkerOutcome, WorkerError> {
        let detail = detail.into();
        journal.expire(operation_id, detail.clone(), self.paths, self.key)?;
        Err(WorkerError::Expired { detail })
    }
}

/// Reconstruct the requester binding from a durable entry.
///
/// Only the stored class and subject participate; both are what the requester
/// fingerprint is derived from, so the reconstruction's fingerprint equals the
/// stored one. Evidence and proposal domains are not part of the fingerprint or
/// of [`verify_for_consumption`]'s checks, so a minimal, unprivileged context is
/// sufficient and correct.
fn reconstruct_requester(
    entry: &crate::journal::JournalEntry,
) -> Result<RequesterContext, WorkerError> {
    let subject = RequesterSubject::new(entry.requester_subject.clone()).map_err(|e| {
        WorkerError::Expired {
            detail: e.to_string(),
        }
    })?;
    let domains = std::collections::BTreeSet::new();
    let context = match entry.requester_class {
        PrincipalClass::AgentRequester => {
            RequesterContext::agent(subject, domains, Evidence::unknown())
        }
        PrincipalClass::ExternalRequester => {
            RequesterContext::external(subject, domains, Evidence::unknown())
        }
        // A parked entry can only belong to a requester class. Anything else is
        // a corrupt entry; fail closed rather than reconstruct an approver.
        PrincipalClass::Operator | PrincipalClass::RecoveryService => {
            return Err(WorkerError::Expired {
                detail: "entry requester class is not a requester".to_owned(),
            });
        }
    };
    if context.fingerprint() != entry.requester_fingerprint {
        return Err(WorkerError::Expired {
            detail: "reconstructed requester does not match the bound fingerprint".to_owned(),
        });
    }
    Ok(context)
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

/// Probe the declared personality files' pre-images. A new agent's workspace is
/// absent, so these are normally [`EffectImage::Absent`]; a pre-existing file is
/// captured by digest so recovery can classify it honestly.
fn capture_personality_pre_images(
    proposal: &crate::proposal::AgentProposal,
    workspace_dir: &std::path::Path,
) -> Vec<(String, EffectImage)> {
    proposal
        .personality_files
        .iter()
        .map(|file| {
            let path = workspace_dir.join(&file.filename);
            let image = match std::fs::read(&path) {
                Ok(bytes) => EffectImage::Digest {
                    sha256: sha256(&bytes),
                },
                Err(_) => EffectImage::Absent,
            };
            (file.filename.clone(), image)
        })
        .collect()
}

/// Record the captured pre-images onto each declared effect.
fn record_pre_images(
    entry: &mut crate::journal::JournalEntry,
    config_pre_image: &EffectImage,
    personality_pre_images: &[(String, EffectImage)],
) {
    for effect in &mut entry.effects {
        match &effect.artifact_kind {
            ArtifactKind::Config { .. } => {
                effect.pre_image = Some(config_pre_image.clone());
            }
            ArtifactKind::PersonalityFile { relative_path, .. } => {
                if let Some((_, image)) = personality_pre_images
                    .iter()
                    .find(|(name, _)| name == relative_path)
                {
                    effect.pre_image = Some(image.clone());
                }
            }
        }
    }
}

/// The order effects are attempted, matching Quickstart's actual order:
/// personality files are committed into the new workspace before the config CAS.
fn apply_order(entry: &crate::journal::JournalEntry) -> Vec<crate::journal::EffectId> {
    let mut order = Vec::with_capacity(entry.effects.len());
    for effect in &entry.effects {
        if matches!(effect.artifact_kind, ArtifactKind::PersonalityFile { .. }) {
            order.push(effect.effect_id.clone());
        }
    }
    for effect in &entry.effects {
        if matches!(effect.artifact_kind, ArtifactKind::Config { .. }) {
            order.push(effect.effect_id.clone());
        }
    }
    order
}

fn record_all_applied(entry: &mut crate::journal::JournalEntry) {
    for effect in &mut entry.effects {
        effect.observed = Some(crate::journal::EffectClassification::AppliedNotVerified);
    }
}

fn record_all_not_applied(entry: &mut crate::journal::JournalEntry) {
    for effect in &mut entry.effects {
        effect.observed = Some(crate::journal::EffectClassification::NotApplied);
    }
}

/// A stable, non-secret reason string for an inspection failure.
fn inspect_reason(error: &ControlError) -> String {
    match error {
        ControlError::SourceSchemaOutdated => "source schema is no longer current".to_owned(),
        ControlError::ConfigDegraded => "config loaded degraded".to_owned(),
        ControlError::ConfigBusy => "config source is changing under the lock".to_owned(),
        other => format!("inspection failed: {other}"),
    }
}

/// A stable, non-secret reason string for a preview failure at claim time.
fn preview_reason(error: &ControlError) -> String {
    format!("a previewed fact changed: {error}")
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::approval::{ApprovalErrorCode, ProposalDigest, SourceRevisionDigest};
    use crate::journal::{ParkRequest, Quotas};
    use crate::meta_authority::ControlOperation;
    use crate::test_support::{
        ApplyHarness, ConfigDirGuard, config_env_lock, isolated_requester, run_async,
    };

    const NOW: u64 = 1_700_000_000;

    // -- the happy path -----------------------------------------------------

    #[test]
    fn park_approve_claim_apply_verify_mutates_config_through_the_cas() {
        run_async(|| async {
            let _lock = config_env_lock().lock().await;
            let harness = ApplyHarness::new();
            let _guard = ConfigDirGuard::pin(&harness.root);
            let service = harness.service();

            let (op_id, _issued) = harness.arrange_approved(&service, NOW).await;
            assert!(
                !harness.config_text().contains("[agents.writer]"),
                "not applied yet"
            );

            let outcome = harness
                .worker(&service)
                .apply_approved(&op_id, NOW)
                .await
                .expect("claim and apply must reach verified");
            assert_eq!(
                outcome,
                WorkerOutcome::Verified {
                    agent_alias: "writer".to_string()
                }
            );

            let config = harness.config_text();
            assert!(config.contains("[agents.writer]"), "the agent was added");
            assert!(
                config.contains("quickstart_completed = true"),
                "the write went through the Quickstart CAS"
            );

            let journal = harness.load_journal();
            let entry = journal.entry(&op_id).expect("entry");
            assert_eq!(entry.state, JournalState::Verified);
            let receipt_id = entry.consumed_receipt_id.clone().expect("consumed id");
            assert!(journal.is_receipt_consumed(&receipt_id));
        });
    }

    // -- no apply without a verified receipt --------------------------------

    #[test]
    fn an_entry_without_a_recorded_receipt_cannot_be_claimed() {
        run_async(|| async {
            let _lock = config_env_lock().lock().await;
            let harness = ApplyHarness::new();
            let _guard = ConfigDirGuard::pin(&harness.root);
            let service = harness.service();

            let proposal = harness.proposal();
            let inspection = service.inspect().await.expect("inspect");
            let bound = service
                .preview(inspection, "custom.fixture", &proposal)
                .expect("preview");
            let requester = isolated_requester("reg-abc123");
            let mut journal = harness.load_journal();
            let (op_id, _secret) = journal
                .park(
                    &ParkRequest {
                        operation: ControlOperation::ProposeAgentProfile,
                        bound: &bound,
                        agent_proposal: &proposal,
                        selected_provider_ref: "custom.fixture",
                        target_instance: harness.record.instance_id.clone(),
                        instance_fingerprint: harness.fingerprint(),
                        requester: &requester,
                        owner_token: "reg-abc123".to_string(),
                        client_session: "sess-1".to_string(),
                        proposal_ttl_secs: 900,
                    },
                    NOW,
                    &Quotas::default(),
                    &harness.paths,
                    &harness.key,
                )
                .expect("park");

            let error = harness
                .worker(&service)
                .apply_approved(&op_id, NOW)
                .await
                .expect_err("a parked-but-unapproved proposal cannot apply");
            assert!(
                matches!(error, WorkerError::NotApproved { .. }),
                "got {error}"
            );
            assert!(
                !harness.config_text().contains("[agents.writer]"),
                "no config write"
            );
        });
    }

    // -- single use across a simulated restart ------------------------------

    #[test]
    fn a_consumed_receipt_cannot_be_consumed_again_after_a_restart() {
        run_async(|| async {
            let _lock = config_env_lock().lock().await;
            let harness = ApplyHarness::new();
            let _guard = ConfigDirGuard::pin(&harness.root);
            let service = harness.service();

            let (op_id, issued) = harness.arrange_approved(&service, NOW).await;

            let crash = harness
                .worker(&service)
                .with_fault(FaultPoint::PostCommitPreConfig)
                .apply_approved(&op_id, NOW)
                .await
                .expect_err("injected crash");
            assert!(matches!(crash, WorkerError::InjectedCrash));
            assert!(
                !harness.config_text().contains("[agents.writer]"),
                "config untouched"
            );

            let reloaded = harness.load_journal();
            let entry = reloaded.entry(&op_id).expect("entry");
            assert_eq!(entry.state, JournalState::Applying);
            let receipt_id = entry.consumed_receipt_id.clone().expect("consumed id");
            assert!(
                reloaded.is_receipt_consumed(&receipt_id),
                "durably consumed"
            );

            let inspection = service.inspect().await.expect("inspect");
            let source_revision = SourceRevisionDigest::of(inspection.source_revision());
            let bound = service
                .preview(inspection, "custom.fixture", &harness.proposal())
                .expect("preview");
            let digest = ProposalDigest::of_bound_proposal(&bound).expect("digest");
            let requester = isolated_requester("reg-abc123");
            let fingerprint = harness.fingerprint();
            let expectations = Expectations {
                operation: ControlOperation::ProposeAgentProfile,
                proposal_digest: &digest,
                target_instance: &harness.record.instance_id,
                instance_fingerprint: &fingerprint,
                source_revision: &source_revision,
                trust_epoch: harness.record.trust_epoch,
                now_unix_secs: NOW,
                high_water_unix_secs: reloaded.high_water_unix_secs().max(NOW),
            };
            let replay = verify_for_consumption(
                issued.as_sealed_bytes(),
                &harness.key,
                &expectations,
                &reloaded.ledger(),
                &harness.operators,
                &requester,
            )
            .expect_err("a consumed receipt must not verify again");
            assert_eq!(replay.code, ApprovalErrorCode::AlreadyConsumed);
        });
    }

    // -- drift refuses before mutation --------------------------------------

    #[test]
    fn an_expired_proposal_refuses_and_never_writes_config() {
        run_async(|| async {
            let _lock = config_env_lock().lock().await;
            let harness = ApplyHarness::new();
            let _guard = ConfigDirGuard::pin(&harness.root);
            let service = harness.service();

            let (op_id, _issued) = harness.arrange_approved(&service, NOW).await;
            let error = harness
                .worker(&service)
                .apply_approved(&op_id, NOW + 100_000)
                .await
                .expect_err("an expired proposal must not apply");
            assert!(matches!(error, WorkerError::Expired { .. }), "got {error}");
            assert!(!harness.config_text().contains("[agents.writer]"));
            assert_eq!(
                harness.load_journal().entry(&op_id).expect("entry").state,
                JournalState::Expired
            );
        });
    }

    #[test]
    fn a_changed_source_revision_refuses_and_never_writes_config() {
        run_async(|| async {
            let _lock = config_env_lock().lock().await;
            let harness = ApplyHarness::new();
            let _guard = ConfigDirGuard::pin(&harness.root);
            let service = harness.service();

            let (op_id, _issued) = harness.arrange_approved(&service, NOW).await;

            let edited = harness
                .config_text()
                .replace("provider_retries = 0", "provider_retries = 5");
            std::fs::write(&harness.config_path, edited).expect("foreign edit");

            let error = harness
                .worker(&service)
                .apply_approved(&op_id, NOW)
                .await
                .expect_err("a moved source revision must not apply");
            assert!(matches!(error, WorkerError::Expired { .. }), "got {error}");
            assert!(
                !harness.config_text().contains("[agents.writer]"),
                "no agent added"
            );
            assert_eq!(
                harness.load_journal().entry(&op_id).expect("entry").state,
                JournalState::Expired
            );
        });
    }

    #[cfg(unix)]
    #[test]
    fn a_changed_instance_fingerprint_refuses_and_never_writes_config() {
        run_async(|| async {
            use std::os::unix::fs::PermissionsExt as _;
            let _lock = config_env_lock().lock().await;
            let harness = ApplyHarness::new();
            let _guard = ConfigDirGuard::pin(&harness.root);
            let service = harness.service();

            let (op_id, _issued) = harness.arrange_approved(&service, NOW).await;

            // Toggle the group-read bit of the config root: a guaranteed change
            // to the root's security-relevant permissions, which the instance
            // fingerprint commits to. Owner access is untouched.
            let current = std::fs::metadata(&harness.root)
                .expect("meta")
                .permissions()
                .mode();
            let mut perms = std::fs::metadata(&harness.root)
                .expect("meta")
                .permissions();
            perms.set_mode((current & 0o7777) ^ 0o040);
            std::fs::set_permissions(&harness.root, perms).expect("chmod root");

            let error = harness
                .worker(&service)
                .apply_approved(&op_id, NOW)
                .await
                .expect_err("a changed fingerprint must not apply");
            assert!(matches!(error, WorkerError::Expired { .. }), "got {error}");
            assert!(!harness.config_text().contains("[agents.writer]"));
        });
    }

    // -- the pre-commit crash window ----------------------------------------

    #[test]
    fn a_crash_before_the_step_six_commit_leaves_approved_and_unconsumed() {
        run_async(|| async {
            let _lock = config_env_lock().lock().await;
            let harness = ApplyHarness::new();
            let _guard = ConfigDirGuard::pin(&harness.root);
            let service = harness.service();

            let (op_id, _issued) = harness.arrange_approved(&service, NOW).await;
            let crash = harness
                .worker(&service)
                .with_fault(FaultPoint::PreApplyingCommit)
                .apply_approved(&op_id, NOW)
                .await
                .expect_err("injected crash before commit");
            assert!(matches!(crash, WorkerError::InjectedCrash));

            let journal = harness.load_journal();
            let entry = journal.entry(&op_id).expect("entry");
            assert_eq!(entry.state, JournalState::Approved);
            assert!(entry.consumed_receipt_id.is_none(), "receipt not consumed");
            assert!(!harness.config_text().contains("[agents.writer]"));

            let outcome = harness
                .worker(&service)
                .apply_approved(&op_id, NOW)
                .await
                .expect("a re-claim proceeds under the same receipt");
            assert_eq!(
                outcome,
                WorkerOutcome::Verified {
                    agent_alias: "writer".to_string()
                }
            );
            assert_eq!(
                harness.config_text().matches("[agents.writer]").count(),
                1,
                "applied exactly once"
            );
        });
    }

    // -- quotas and parking -------------------------------------------------

    #[test]
    fn quota_exhaustion_refuses_a_new_park_without_evicting() {
        run_async(|| async {
            let _lock = config_env_lock().lock().await;
            let harness = ApplyHarness::new();
            let _guard = ConfigDirGuard::pin(&harness.root);
            let service = harness.service();

            let proposal = harness.proposal();
            let inspection = service.inspect().await.expect("inspect");
            let bound = service
                .preview(inspection, "custom.fixture", &proposal)
                .expect("preview");
            let requester = isolated_requester("reg-abc123");
            let quotas = Quotas {
                max_awaiting_approval: 2,
                max_prepared: 2,
                ..Quotas::default()
            };
            let mut journal = harness.load_journal();
            let mut park = || {
                journal.park(
                    &ParkRequest {
                        operation: ControlOperation::ProposeAgentProfile,
                        bound: &bound,
                        agent_proposal: &proposal,
                        selected_provider_ref: "custom.fixture",
                        target_instance: harness.record.instance_id.clone(),
                        instance_fingerprint: harness.fingerprint(),
                        requester: &requester,
                        owner_token: "reg-abc123".to_string(),
                        client_session: "sess-1".to_string(),
                        proposal_ttl_secs: 900,
                    },
                    NOW,
                    &quotas,
                    &harness.paths,
                    &harness.key,
                )
            };
            let (first, _) = park().expect("first park");
            let (second, _) = park().expect("second park");
            let refused = park().expect_err("the third park is over quota");
            assert_eq!(
                refused.code,
                crate::journal::JournalErrorCode::QuotaExceeded
            );

            let reloaded = harness.load_journal();
            assert_eq!(reloaded.iter().count(), 2, "no eviction");
            for op in [&first, &second] {
                assert_eq!(
                    reloaded.entry(op).expect("entry").state,
                    JournalState::AwaitingApproval
                );
            }
            assert!(!harness.config_text().contains("[agents.writer]"));
        });
    }

    #[test]
    fn a_resume_secret_resolves_exactly_one_proposal_for_its_requester() {
        run_async(|| async {
            let _lock = config_env_lock().lock().await;
            let harness = ApplyHarness::new();
            let _guard = ConfigDirGuard::pin(&harness.root);
            let service = harness.service();

            let proposal = harness.proposal();
            let inspection = service.inspect().await.expect("inspect");
            let bound = service
                .preview(inspection, "custom.fixture", &proposal)
                .expect("preview");
            let owner = isolated_requester("reg-owner");
            let stranger = isolated_requester("reg-stranger");
            let mut journal = harness.load_journal();
            let (op_id, secret) = journal
                .park(
                    &ParkRequest {
                        operation: ControlOperation::ProposeAgentProfile,
                        bound: &bound,
                        agent_proposal: &proposal,
                        selected_provider_ref: "custom.fixture",
                        target_instance: harness.record.instance_id.clone(),
                        instance_fingerprint: harness.fingerprint(),
                        requester: &owner,
                        owner_token: "reg-owner".to_string(),
                        client_session: "sess-1".to_string(),
                        proposal_ttl_secs: 900,
                    },
                    NOW,
                    &Quotas::default(),
                    &harness.paths,
                    &harness.key,
                )
                .expect("park");

            let resolved = journal
                .resolve_resume_secret(&secret, &owner)
                .expect("owner resolves its proposal");
            assert_eq!(resolved.operation_id, op_id);

            assert!(journal.resolve_resume_secret(&secret, &stranger).is_err());
            let forged = crate::journal::ResumeSecret::generate().expect("forged secret");
            assert!(journal.resolve_resume_secret(&forged, &owner).is_err());
        });
    }

    // -- the transaction lock is exclusive ----------------------------------

    #[test]
    fn the_transaction_lock_admits_exactly_one_owner() {
        run_async(|| async {
            let harness = ApplyHarness::new();
            let service = harness.service();
            let worker = harness.worker(&service);

            let held = worker.acquire_transaction_lock().expect("first owner");
            let second = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(harness.paths.control_dir().join(TRANSACTION_LOCK_FILE))
                .expect("open second handle");
            assert!(
                second.try_lock_exclusive().is_err(),
                "the lock must reject a second concurrent owner"
            );
            drop(held);
            assert!(
                second.try_lock_exclusive().is_ok(),
                "released lock is re-acquirable"
            );
        });
    }
}
