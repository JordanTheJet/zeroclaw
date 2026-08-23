//! Startup crash recovery for interrupted `applying` operations, and the
//! read-only Verify surface.
//!
//! Recovery implements **exactly the two crash-window readings** the design
//! defines, and no third:
//!
//! | Durable state | Receipt | Action |
//! |---|---|---|
//! | `approved` | unconsumed | The operation has not begun. It may proceed later under the same receipt via a normal claim. Recovery does not touch it. |
//! | `applying` | consumed | The recovery service is authorized to continue or classify **only that exact operation**. |
//!
//! For each `applying` entry, recovery observes every declared effect and
//! classifies it as `not_applied`, `applied_not_verified`, or `ambiguous` by
//! comparing the current artefact against the recorded pre-image and the
//! expected post-image identity. It never blindly repeats a mutation: an effect
//! is re-attempted only when the artefact positively matches its pre-image.
//!
//! The continuation policy is deliberately conservative and per operation, not
//! per effect:
//!
//! - **any effect ambiguous** ⇒ the whole operation parks in
//!   `recovery_required` (a parked state with no auto-exit);
//! - **every effect not applied** ⇒ continue the exact operation: re-drive the
//!   same revision-bound CAS under the already-consumed receipt, which writes
//!   each effect exactly once;
//! - **every effect applied but not verified** ⇒ do not repeat; move to
//!   `applied` and run verification, reaching `verified` or parking
//!   `recovery_required`;
//! - **any other mixture** ⇒ park in `recovery_required`, because completing it
//!   would risk repeating an already-applied effect.
//!
//! Recovery can resume or classify an already-authorized entry and can never
//! approve a new proposal, generalize a consumed receipt to a similar or retried
//! operation, or re-derive one. Parking never restores approval authority and
//! never makes the consumed receipt reusable.

use sha2::{Digest, Sha256};

use crate::apply_worker::{ApplyWorker, WorkerError, WorkerOutcome};
use crate::journal::{
    ArtifactKind, EffectClassification, EffectImage, JournalEntry, JournalState, OperationId,
    ProposalJournal,
};
use crate::operator::RequesterContext;
use crate::service::{ControlError, ControlInspection};

/// What recovery did with one interrupted operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryAction {
    /// Every effect was not applied; the operation was continued to `verified`.
    Continued,
    /// Every effect was applied; verification confirmed effective state and the
    /// operation reached `verified`.
    Verified,
    /// The operation parked in `recovery_required`, with a non-secret reason.
    Parked(String),
}

/// The outcome of one recovery pass.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RecoveryReport {
    /// Each interrupted operation recovery handled, and what it did.
    pub actions: Vec<(OperationId, RecoveryAction)>,
}

/// The read-only Verify surface: bounded diagnostics about effective state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyReport {
    /// The durable state, reported by name.
    pub state: JournalState,
    /// Whether the approved agent is present in effective configuration.
    pub agent_present: bool,
    /// Whether every declared personality file is present with matching content.
    pub personality_files_ok: bool,
    /// The overall effective-state judgement: partial or ineffective
    /// configuration is reported as `false` rather than trusted from a
    /// successful write.
    pub effective: bool,
}

/// Recover every interrupted `applying` operation in the journal.
///
/// Acquires the control-plane transaction lock once and holds it for the whole
/// pass, so no concurrent worker can move the journal underneath recovery.
///
/// # Errors
///
/// Returns [`WorkerError`] when the lock cannot be acquired or the journal
/// cannot be read or written.
pub async fn recover(
    worker: &ApplyWorker<'_>,
    now_unix_secs: u64,
) -> Result<RecoveryReport, WorkerError> {
    let lock = worker.acquire_transaction_lock()?;
    let result = recover_locked(worker, now_unix_secs).await;
    drop(lock);
    result
}

async fn recover_locked(
    worker: &ApplyWorker<'_>,
    now_unix_secs: u64,
) -> Result<RecoveryReport, WorkerError> {
    let journal = ProposalJournal::load(worker.paths(), worker.key())?;
    let applying: Vec<OperationId> = journal
        .iter()
        .filter(|entry| entry.state == JournalState::Applying)
        .map(|entry| entry.operation_id.clone())
        .collect();

    let mut report = RecoveryReport::default();
    for operation_id in applying {
        let action = recover_one(worker, &operation_id, now_unix_secs).await?;
        report.actions.push((operation_id, action));
    }
    Ok(report)
}

async fn recover_one(
    worker: &ApplyWorker<'_>,
    operation_id: &OperationId,
    now_unix_secs: u64,
) -> Result<RecoveryAction, WorkerError> {
    // Re-read the journal and re-inspect per entry: a continued operation writes
    // config, so a later entry must be classified against the fresh state.
    let mut journal = ProposalJournal::load(worker.paths(), worker.key())?;
    let entry = match journal.entry(operation_id) {
        Some(entry) if entry.state == JournalState::Applying => entry.clone(),
        // Already resolved by an earlier iteration or a concurrent path.
        _ => return Ok(RecoveryAction::Parked("no longer applying".to_owned())),
    };

    // F2 (defense-in-depth): an `applying` entry is authorized to be continued
    // or confirmed only because a receipt was consumed to reach `applying`. If a
    // future trusted-writer bug ever produced `applying` with no consumed
    // receipt, refuse across every branch — do not continue, verify, or bless
    // it. Park in `recovery_required` for operator resolution.
    if entry.consumed_receipt_id.is_none() {
        let detail = "an applying entry has no consumed receipt; refusing recovery".to_owned();
        return match worker.park_recovery(&mut journal, operation_id, detail.clone()) {
            Ok(_) | Err(WorkerError::RecoveryRequired { .. }) => Ok(RecoveryAction::Parked(detail)),
            Err(other) => Err(other),
        };
    }

    let inspection = match worker.service().inspect().await {
        Ok(inspection) => inspection,
        Err(error) => {
            // The config cannot be read or is not classifiable; nothing may be
            // inferred, so the operation parks.
            let detail = format!("config unclassifiable: {}", inspect_reason(&error));
            worker.park_recovery(&mut journal, operation_id, detail.clone())?;
            return Ok(RecoveryAction::Parked(detail));
        }
    };

    let classifications = classify_entry(&entry, &inspection);
    let summary = summarize(&classifications);

    match summary {
        ClassificationSummary::AnyAmbiguous => {
            let detail = "an effect matched neither its pre-image nor its expected \
                          post-image"
                .to_owned();
            park_with_observations(
                worker,
                &mut journal,
                operation_id,
                &classifications,
                &detail,
            )?;
            Ok(RecoveryAction::Parked(detail))
        }
        ClassificationSummary::AllNotApplied => {
            // Continue the exact operation. The receipt is already consumed and
            // is not re-verified; the CAS writes each effect exactly once.
            match worker
                .resume_applying_locked(operation_id, now_unix_secs)
                .await
            {
                Ok(WorkerOutcome::Verified { .. }) => Ok(RecoveryAction::Continued),
                Err(WorkerError::RecoveryRequired { detail }) => Ok(RecoveryAction::Parked(detail)),
                Err(WorkerError::Failed { detail }) => Ok(RecoveryAction::Parked(detail)),
                Err(other) => Err(other),
            }
        }
        ClassificationSummary::AllApplied => {
            // Do not repeat any effect. Confirm effective state, then move to
            // `applied` and `verified`; a failed verification parks.
            let verify = verify_effective(&entry, &inspection);
            if verify.effective {
                confirm_applied_then_verified(
                    worker,
                    &mut journal,
                    operation_id,
                    &classifications,
                )?;
                Ok(RecoveryAction::Verified)
            } else {
                let detail =
                    "apply landed but verification could not confirm effective state".to_owned();
                park_with_observations(
                    worker,
                    &mut journal,
                    operation_id,
                    &classifications,
                    &detail,
                )?;
                Ok(RecoveryAction::Parked(detail))
            }
        }
        ClassificationSummary::Mixed => {
            let detail =
                "a partial apply: some effects applied and some did not, so completing it \
                 would risk repeating an applied effect"
                    .to_owned();
            park_with_observations(
                worker,
                &mut journal,
                operation_id,
                &classifications,
                &detail,
            )?;
            Ok(RecoveryAction::Parked(detail))
        }
    }
}

/// The read-only Verify surface for one requester-owned proposal.
///
/// Re-reads effective configuration and reports whether the approved agent is
/// actually present and complete. It performs no host effect and no transition,
/// and it is scoped to the caller's own proposal.
///
/// # Errors
///
/// Returns [`WorkerError`] when the entry is not owned by the requester or the
/// config cannot be inspected.
pub async fn verify(
    worker: &ApplyWorker<'_>,
    journal: &ProposalJournal,
    operation_id: &OperationId,
    requester: &RequesterContext,
) -> Result<VerifyReport, WorkerError> {
    let entry = journal
        .entry_for(operation_id, requester)
        .map_err(WorkerError::Journal)?
        .clone();
    let inspection =
        worker
            .service()
            .inspect()
            .await
            .map_err(|error| WorkerError::RecoveryRequired {
                detail: format!("verify could not inspect: {}", inspect_reason(&error)),
            })?;
    Ok(verify_effective(&entry, &inspection))
}

// ---------------------------------------------------------------------------
// Classification
// ---------------------------------------------------------------------------

enum ClassificationSummary {
    AnyAmbiguous,
    AllNotApplied,
    AllApplied,
    Mixed,
}

fn summarize(classifications: &[(usize, EffectClassification)]) -> ClassificationSummary {
    if classifications
        .iter()
        .any(|(_, c)| *c == EffectClassification::Ambiguous)
    {
        return ClassificationSummary::AnyAmbiguous;
    }
    let all_not_applied = classifications
        .iter()
        .all(|(_, c)| *c == EffectClassification::NotApplied);
    let all_applied = classifications
        .iter()
        .all(|(_, c)| *c == EffectClassification::AppliedNotVerified);
    if all_not_applied {
        ClassificationSummary::AllNotApplied
    } else if all_applied {
        ClassificationSummary::AllApplied
    } else {
        ClassificationSummary::Mixed
    }
}

/// Classify every effect of one entry against the current inspection. The
/// returned pairs carry the effect index so observations can be written back.
fn classify_entry(
    entry: &JournalEntry,
    inspection: &ControlInspection,
) -> Vec<(usize, EffectClassification)> {
    let current_config = inspection.source_revision().as_bytes();
    let alias_present = match entry.config_effect().map(|e| &e.artifact_kind) {
        Some(ArtifactKind::Config { agent_alias }) => {
            inspection.config().agents.contains_key(agent_alias)
        }
        _ => false,
    };
    let mut out = Vec::with_capacity(entry.effects.len());
    for (index, effect) in entry.effects.iter().enumerate() {
        let classification = match &effect.artifact_kind {
            ArtifactKind::Config { .. } => {
                classify_config(current_config, effect.pre_image.as_ref(), alias_present)
            }
            ArtifactKind::PersonalityFile {
                relative_path,
                content_sha256,
            } => {
                let workspace = inspection
                    .config()
                    .agent_workspace_dir(config_alias(entry).unwrap_or_default());
                let path = workspace.join(relative_path);
                classify_personality(&path, effect.pre_image.as_ref(), content_sha256)
            }
        };
        out.push((index, classification));
    }
    out
}

fn config_alias(entry: &JournalEntry) -> Option<&str> {
    match entry.config_effect().map(|e| &e.artifact_kind) {
        Some(ArtifactKind::Config { agent_alias }) => Some(agent_alias.as_str()),
        _ => None,
    }
}

/// Classify the config effect. Recovery never infers success from the config
/// digest alone: a digest match means not-applied, but the applied case is
/// judged by the approved agent's structural presence, not by an exact
/// post-image digest that Quickstart's formatting does not make deterministic.
fn classify_config(
    current_config: &[u8],
    pre_image: Option<&EffectImage>,
    alias_present: bool,
) -> EffectClassification {
    if matches!(pre_image, Some(EffectImage::Digest { sha256 }) if *sha256 == digest(current_config))
    {
        return EffectClassification::NotApplied;
    }
    if alias_present {
        EffectClassification::AppliedNotVerified
    } else {
        EffectClassification::Ambiguous
    }
}

/// Classify a personality-file effect against its recorded pre-image and
/// expected content digest.
fn classify_personality(
    path: &std::path::Path,
    pre_image: Option<&EffectImage>,
    expected_content_sha256: &[u8; 32],
) -> EffectClassification {
    match std::fs::read(path) {
        Err(_) => match pre_image {
            Some(EffectImage::Absent) | None => EffectClassification::NotApplied,
            Some(EffectImage::Digest { .. }) => EffectClassification::Ambiguous,
        },
        Ok(bytes) => {
            let observed = digest(&bytes);
            if observed == *expected_content_sha256 {
                EffectClassification::AppliedNotVerified
            } else if matches!(pre_image, Some(EffectImage::Digest { sha256 }) if *sha256 == observed)
            {
                EffectClassification::NotApplied
            } else {
                EffectClassification::Ambiguous
            }
        }
    }
}

/// Re-read effective configuration and judge whether the approved agent is
/// present and complete.
fn verify_effective(entry: &JournalEntry, inspection: &ControlInspection) -> VerifyReport {
    let alias = &entry.verification_plan.expected_agent_alias;
    let agent_present = inspection.config().agents.contains_key(alias);
    let workspace = inspection.config().agent_workspace_dir(alias);
    let personality_files_ok = entry
        .effects
        .iter()
        .all(|effect| match &effect.artifact_kind {
            ArtifactKind::PersonalityFile {
                relative_path,
                content_sha256,
            } => matches!(
                std::fs::read(workspace.join(relative_path)),
                Ok(bytes) if digest(&bytes) == *content_sha256
            ),
            ArtifactKind::Config { .. } => true,
        });
    VerifyReport {
        state: entry.state,
        agent_present,
        personality_files_ok,
        effective: agent_present && personality_files_ok,
    }
}

// ---------------------------------------------------------------------------
// State transitions with observations
// ---------------------------------------------------------------------------

fn park_with_observations(
    worker: &ApplyWorker<'_>,
    journal: &mut ProposalJournal,
    operation_id: &OperationId,
    classifications: &[(usize, EffectClassification)],
    detail: &str,
) -> Result<(), WorkerError> {
    let classifications = classifications.to_vec();
    let detail = detail.to_owned();
    journal
        .transition(
            operation_id,
            JournalState::RecoveryRequired,
            |entry| {
                apply_observations(entry, &classifications);
                entry.disposition = Some(detail);
            },
            worker.paths(),
            worker.key(),
        )
        .map_err(WorkerError::Journal)
}

fn confirm_applied_then_verified(
    worker: &ApplyWorker<'_>,
    journal: &mut ProposalJournal,
    operation_id: &OperationId,
    classifications: &[(usize, EffectClassification)],
) -> Result<(), WorkerError> {
    let classifications = classifications.to_vec();
    journal
        .transition(
            operation_id,
            JournalState::Applied,
            |entry| apply_observations(entry, &classifications),
            worker.paths(),
            worker.key(),
        )
        .map_err(WorkerError::Journal)?;
    journal
        .transition(
            operation_id,
            JournalState::Verified,
            |entry| entry.disposition = Some("recovery verified an applied operation".to_owned()),
            worker.paths(),
            worker.key(),
        )
        .map_err(WorkerError::Journal)
}

fn apply_observations(entry: &mut JournalEntry, classifications: &[(usize, EffectClassification)]) {
    for (index, classification) in classifications {
        if let Some(effect) = entry.effects.get_mut(*index) {
            effect.observed = Some(*classification);
        }
    }
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

/// A stable, non-secret reason string for an inspection failure.
fn inspect_reason(error: &ControlError) -> String {
    match error {
        ControlError::SourceSchemaOutdated => "source schema is not current".to_owned(),
        ControlError::ConfigDegraded => "config loaded degraded".to_owned(),
        ControlError::ConfigBusy => "config source is changing under the lock".to_owned(),
        other => format!("inspection failed: {other}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::apply_worker::FaultPoint;
    use crate::test_support::{
        ApplyHarness, ConfigDirGuard, PROVIDER_CONFIG, config_env_lock, run_async,
    };

    const NOW: u64 = 1_700_000_000;

    fn sha(bytes: &[u8]) -> [u8; 32] {
        digest(bytes)
    }

    // -- crash-recovery of an interrupted `applying` operation --------------

    #[test]
    fn a_crash_after_the_step_six_commit_recovers_without_double_applying() {
        run_async(|| async {
            let _lock = config_env_lock().lock().await;
            let harness = ApplyHarness::new();
            let _guard = ConfigDirGuard::pin(&harness.root);
            let service = harness.service();

            let (op_id, _issued) = harness.arrange_approved(&service, NOW).await;
            let crash = harness
                .worker(&service)
                .with_fault(FaultPoint::PostCommitPreConfig)
                .apply_approved(&op_id, NOW)
                .await
                .expect_err("injected crash after commit");
            assert!(matches!(crash, WorkerError::InjectedCrash));

            // The second documented reading: durable state `applying`, receipt
            // consumed, config not yet written.
            let entry = harness.load_journal().entry(&op_id).expect("entry").clone();
            assert_eq!(entry.state, JournalState::Applying);
            assert!(entry.consumed_receipt_id.is_some(), "receipt consumed");
            assert!(!harness.config_text().contains("[agents.writer]"));

            // Recovery continues that exact operation; config is written once.
            let report = recover(&harness.worker(&service), NOW)
                .await
                .expect("recovery");
            assert_eq!(report.actions.len(), 1);
            assert_eq!(report.actions[0].1, RecoveryAction::Continued);
            assert_eq!(
                harness.config_text().matches("[agents.writer]").count(),
                1,
                "the agent is present exactly once"
            );
            assert_eq!(
                harness.load_journal().entry(&op_id).expect("entry").state,
                JournalState::Verified
            );
        });
    }

    #[test]
    fn a_crash_after_the_config_write_recovers_without_repeating_the_effect() {
        run_async(|| async {
            let _lock = config_env_lock().lock().await;
            let harness = ApplyHarness::new();
            let _guard = ConfigDirGuard::pin(&harness.root);
            let service = harness.service();

            let (op_id, _issued) = harness.arrange_approved(&service, NOW).await;
            let crash = harness
                .worker(&service)
                .with_fault(FaultPoint::PostConfigPreApplied)
                .apply_approved(&op_id, NOW)
                .await
                .expect_err("injected crash after config write");
            assert!(matches!(crash, WorkerError::InjectedCrash));

            assert_eq!(
                harness.load_journal().entry(&op_id).expect("entry").state,
                JournalState::Applying
            );
            assert!(
                harness.config_text().contains("[agents.writer]"),
                "config write landed"
            );

            // Every effect classifies as applied-not-verified; recovery must not
            // repeat it. It verifies and reaches `verified`.
            let report = recover(&harness.worker(&service), NOW)
                .await
                .expect("recovery");
            assert_eq!(report.actions[0].1, RecoveryAction::Verified);
            assert_eq!(
                harness.config_text().matches("[agents.writer]").count(),
                1,
                "the effect is not repeated"
            );
            assert_eq!(
                harness.load_journal().entry(&op_id).expect("entry").state,
                JournalState::Verified
            );
        });
    }

    #[test]
    fn an_unclassifiable_effect_parks_recovery_required() {
        run_async(|| async {
            let _lock = config_env_lock().lock().await;
            let harness = ApplyHarness::new();
            let _guard = ConfigDirGuard::pin(&harness.root);
            let service = harness.service();

            let (op_id, _issued) = harness.arrange_approved(&service, NOW).await;
            harness
                .worker(&service)
                .with_fault(FaultPoint::PostCommitPreConfig)
                .apply_approved(&op_id, NOW)
                .await
                .expect_err("injected crash");

            // Replace the config with a valid revision that is neither the
            // recorded pre-image nor a post-image that contains the agent: the
            // config effect matches neither image and is ambiguous.
            let ambiguous = PROVIDER_CONFIG.replace("provider_retries = 0", "provider_retries = 9");
            std::fs::write(&harness.config_path, ambiguous).expect("ambiguous config");

            let report = recover(&harness.worker(&service), NOW)
                .await
                .expect("recovery");
            assert!(matches!(report.actions[0].1, RecoveryAction::Parked(_)));
            let entry = harness.load_journal().entry(&op_id).expect("entry").clone();
            assert_eq!(entry.state, JournalState::RecoveryRequired);
            // The consumed receipt stays consumed; parking does not restore it.
            assert!(entry.consumed_receipt_id.is_some());
            assert!(
                !harness.config_text().contains("[agents.writer]"),
                "recovery never wrote the agent for an ambiguous config"
            );
        });
    }

    // -- F2: recovery refuses a receipt-less `applying` entry ---------------

    #[test]
    fn recovery_refuses_a_receipt_less_applying_entry_and_never_verifies_it() {
        run_async(|| async {
            let _lock = config_env_lock().lock().await;
            let harness = ApplyHarness::new();
            let _guard = ConfigDirGuard::pin(&harness.root);
            let service = harness.service();

            // A faithful apply reaches `verified`: config carries the agent bound
            // to the approved profile, with the personality files on disk.
            let (op_id, _issued) = harness.arrange_approved(&service, NOW).await;
            let outcome = harness
                .worker(&service)
                .apply_approved(&op_id, NOW)
                .await
                .expect("apply reaches verified");
            assert!(matches!(outcome, WorkerOutcome::Verified { .. }));

            // Simulate a trusted-writer bug: the entry is back in `applying` with
            // no consumed receipt, even though config already carries the agent.
            let mut journal = harness.load_journal();
            {
                let entry = journal.entry_mut(&op_id).expect("entry");
                entry.state = JournalState::Applying;
                entry.consumed_receipt_id = None;
            }
            journal
                .persist(&harness.paths, &harness.key)
                .expect("persist");

            // Recovery must refuse to bless it. Even the all-applied branch that
            // would otherwise confirm+verify parks in recovery_required.
            let report = recover(&harness.worker(&service), NOW)
                .await
                .expect("recovery");
            assert_eq!(report.actions.len(), 1);
            assert!(
                matches!(report.actions[0].1, RecoveryAction::Parked(_)),
                "got {:?}",
                report.actions[0].1
            );
            assert_eq!(
                harness.load_journal().entry(&op_id).expect("entry").state,
                JournalState::RecoveryRequired
            );
        });
    }

    #[test]
    fn resume_refuses_a_receipt_less_applying_entry_and_never_applies() {
        run_async(|| async {
            let _lock = config_env_lock().lock().await;
            let harness = ApplyHarness::new();
            let _guard = ConfigDirGuard::pin(&harness.root);
            let service = harness.service();

            // Approved but never applied: config is clean (no agent).
            let (op_id, _issued) = harness.arrange_approved(&service, NOW).await;
            // Trusted-writer bug: force `applying` with no consumed receipt.
            let mut journal = harness.load_journal();
            {
                let entry = journal.entry_mut(&op_id).expect("entry");
                entry.state = JournalState::Applying;
                entry.consumed_receipt_id = None;
            }
            journal
                .persist(&harness.paths, &harness.key)
                .expect("persist");

            let error = harness
                .worker(&service)
                .resume_applying_locked(&op_id, NOW)
                .await
                .expect_err("a receipt-less applying entry cannot be continued");
            assert!(
                matches!(error, WorkerError::RecoveryRequired { .. }),
                "got {error}"
            );
            assert!(
                !harness.config_text().contains("[agents.writer]"),
                "no config write under a receipt-less continuation"
            );
            assert_eq!(
                harness.load_journal().entry(&op_id).expect("entry").state,
                JournalState::RecoveryRequired
            );
        });
    }

    // -- effect classification ---------------------------------------------

    #[test]
    fn classify_config_reads_the_three_classifications() {
        let pre = b"schema_version = 3\n";
        let pre_image = EffectImage::Digest { sha256: sha(pre) };

        // Unchanged config that matches the recorded pre-image: not applied.
        assert_eq!(
            classify_config(pre, Some(&pre_image), false),
            EffectClassification::NotApplied
        );
        // Changed config that carries the approved agent: applied but not
        // verified.
        assert_eq!(
            classify_config(b"different\n", Some(&pre_image), true),
            EffectClassification::AppliedNotVerified
        );
        // Changed config that does NOT carry the agent: ambiguous. Nothing may
        // be inferred and the operation must park.
        assert_eq!(
            classify_config(b"different\n", Some(&pre_image), false),
            EffectClassification::Ambiguous
        );
    }

    #[test]
    fn classify_personality_reads_the_three_classifications() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("SOUL.md");
        let content = b"# Soul";
        let expected = sha(content);

        // Absent file whose pre-image was absent: not applied.
        assert_eq!(
            classify_personality(&path, Some(&EffectImage::Absent), &expected),
            EffectClassification::NotApplied
        );

        // Present file whose content matches the expected post-image: applied.
        std::fs::write(&path, content).expect("write file");
        assert_eq!(
            classify_personality(&path, Some(&EffectImage::Absent), &expected),
            EffectClassification::AppliedNotVerified
        );

        // Present file whose content matches neither the pre-image nor the
        // expected post-image: ambiguous.
        std::fs::write(&path, b"tampered").expect("write file");
        assert_eq!(
            classify_personality(&path, Some(&EffectImage::Absent), &expected),
            EffectClassification::Ambiguous
        );

        // Present file that matches the recorded pre-image digest is not
        // applied, even though it is present.
        let pre = b"prior contents";
        std::fs::write(&path, pre).expect("write file");
        assert_eq!(
            classify_personality(
                &path,
                Some(&EffectImage::Digest { sha256: sha(pre) }),
                &expected
            ),
            EffectClassification::NotApplied
        );
    }
}
