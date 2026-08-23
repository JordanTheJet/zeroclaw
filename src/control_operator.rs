//! The operator-side approve/reject composition — the terminal backchannel.
//!
//! This is the **only** path in the whole control plane that causes config to
//! change, and it is not an MCP tool. A registered client can PARK a proposal
//! (a durable-journal-only write) through `control.request_apply`; the config
//! mutation happens here, when a separate eligible operator confirms presence at
//! a controlling terminal and the host worker consumes the receipt through the
//! phase-5 apply path.
//!
//! The composition is shared by the `zeroclaw control approve|reject`
//! subcommands and by the component tests, so both drive exactly the same
//! sequence: reconstruct the parked proposal against the current revision,
//! authenticate the operator via [`authenticate_operator`], have the broker
//! issue a single-use receipt, record it on the journal, and drive the
//! [`ApplyWorker`] through its six-step claim + apply.
//!
//! ## Why apply goes through `ApplyWorker` and nothing else
//!
//! There is exactly one config-writing path: [`ApplyWorker::apply_approved`],
//! which re-verifies and consumes the recorded receipt inside the atomic claim
//! and commits through the Quickstart revision-bound CAS. This module never
//! calls [`ControlService::apply`] directly — a second apply route would bypass
//! the claim and the CAS, which is the confused-deputy shape the architecture
//! exists to prevent.
//!
//! ## Operator eligibility, honestly
//!
//! [`authenticate_operator`] refuses unless the reachability analysis clears the
//! operator for the parked requester. No host-presence prober exists this phase,
//! so the caller must supply the [`Evidence`] the analysis reads: production
//! passes [`Evidence::unknown`], which is conservatively *ineligible*, so the
//! approve path **fails closed in a shipped build** — exactly as the design
//! requires until a reachability analysis lands. Tests that exercise the
//! eligible branch pass the `fixture-grants` isolation seam.

use std::collections::BTreeSet;
use std::path::PathBuf;

use zeroclaw_control::approval::{
    ApprovalBroker, ApprovalRequest, ProposalDigest, SourceRevisionDigest,
};
use zeroclaw_control::genesis::{GenesisRecord, InstanceTrustState, classify, now_unix_secs};
use zeroclaw_control::keys::ApprovalAuditKey;
use zeroclaw_control::registry::{InstanceFingerprint, RootIdentity};
use zeroclaw_control::{
    ApplyWorker, ControlPaths, ControlService, Evidence, InMemoryReceiptLedger, OperationId,
    OperatorIdentity, ProposalJournal, RequesterContext, RequesterSubject, WorkerOutcome,
    authenticate_operator, management, operator,
};
use zeroclaw_runtime::quickstart::Surface;

/// Why an operator action refused. Every variant is a fail-closed refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperatorActionErrorCode {
    /// The install root could not be resolved.
    RootUnusable,
    /// The instance is unmanaged or in recovery-only mode.
    NotManaged,
    /// Management mutations are not enabled on this instance.
    MutationsDisabled,
    /// The deployment key source could not be read.
    KeySourceUnusable,
    /// No operation with that identifier is parked on this instance.
    UnknownOperation,
    /// The parked proposal no longer previews cleanly against the current
    /// configuration.
    PreviewStale,
    /// The operator could not be authenticated, or is ineligible for this
    /// requester.
    OperatorRefused,
    /// The broker refused to mint a receipt.
    ApprovalRefused,
    /// The apply worker did not reach `verified`.
    ApplyFailed,
    /// The durable journal could not be read or written.
    Journal,
    /// The operator registry could not be loaded or verified.
    RegistryUnusable,
    /// The host clock is untrustworthy.
    Clock,
    /// The parked requester subject could not be reconstructed.
    RequesterInvalid,
}

/// An operator-action refusal. `detail` never carries key material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperatorActionError {
    pub code: OperatorActionErrorCode,
    pub detail: String,
}

impl OperatorActionError {
    fn new(code: OperatorActionErrorCode, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }
}

impl std::fmt::Display for OperatorActionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let what = match self.code {
            OperatorActionErrorCode::RootUnusable => "instance root is unusable",
            OperatorActionErrorCode::NotManaged => "instance is not managed",
            OperatorActionErrorCode::MutationsDisabled => {
                "management mutations are not enabled on this instance"
            }
            OperatorActionErrorCode::KeySourceUnusable => "the deployment key source is unusable",
            OperatorActionErrorCode::UnknownOperation => "no such parked operation",
            OperatorActionErrorCode::PreviewStale => {
                "the parked proposal no longer previews cleanly"
            }
            OperatorActionErrorCode::OperatorRefused => "the operator was not authenticated",
            OperatorActionErrorCode::ApprovalRefused => "the broker refused to mint a receipt",
            OperatorActionErrorCode::ApplyFailed => "the apply did not reach verified",
            OperatorActionErrorCode::Journal => "the durable journal is unusable",
            OperatorActionErrorCode::RegistryUnusable => "the operator registry is unusable",
            OperatorActionErrorCode::Clock => "the host clock is untrustworthy",
            OperatorActionErrorCode::RequesterInvalid => "the parked requester is unusable",
        };
        write!(f, "{what}: {}", self.detail)
    }
}

impl std::error::Error for OperatorActionError {}

/// A successful approval: the config changed through the CAS and verification
/// confirmed effective state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApproveOutcome {
    pub operation_id: String,
    pub agent_alias: String,
    /// The durable journal state, by name. Always `verified` on success.
    pub state: String,
}

/// A successful rejection: a durable fact recorded for the proposal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RejectOutcome {
    pub operation_id: String,
    /// The durable journal state, by name. Always `rejected` on success.
    pub state: String,
}

/// Everything the approve and reject paths reconstruct in common.
struct Prepared {
    paths: ControlPaths,
    record: GenesisRecord,
    key: ApprovalAuditKey,
    operators: zeroclaw_control::OperatorRegistry,
    trust: InstanceTrustState,
    service: ControlService,
    journal: ProposalJournal,
    operation_id: OperationId,
    request: ApprovalRequest,
    requester: RequesterContext,
    now: u64,
}

/// Reconstruct the parked proposal against the current instance state.
async fn prepare(
    config_path: PathBuf,
    operation_id: &str,
    evidence: Evidence,
) -> Result<Prepared, OperatorActionError> {
    use OperatorActionErrorCode as Code;

    let install_root = config_path
        .parent()
        .ok_or_else(|| OperatorActionError::new(Code::RootUnusable, "config path has no parent"))?
        .to_path_buf();
    let paths = ControlPaths::resolve(&install_root)
        .map_err(|e| OperatorActionError::new(Code::RootUnusable, e.detail))?;
    let key_source = paths.key_source();
    let record = match classify(&paths, &key_source) {
        InstanceTrustState::Managed(record) => *record,
        InstanceTrustState::EligibleForFirstGenesis => {
            return Err(OperatorActionError::new(
                Code::NotManaged,
                "run genesis first",
            ));
        }
        InstanceTrustState::RecoveryOnly { reason, .. } => {
            return Err(OperatorActionError::new(Code::NotManaged, reason.wire()));
        }
    };
    let key = ApprovalAuditKey::derive(&key_source, record.trust_epoch)
        .map_err(|e| OperatorActionError::new(Code::KeySourceUnusable, format!("{e:#}")))?;

    // Approve and reject both refuse on a mutations-disabled instance.
    if !management::mutations_enabled_with(&paths, &record, &key) {
        return Err(OperatorActionError::new(
            Code::MutationsDisabled,
            "enable mutations first",
        ));
    }

    let operators = operator::load_view(&paths, &record, &key)
        .map_err(|e| OperatorActionError::new(Code::RegistryUnusable, e.to_string()))?;
    let trust = InstanceTrustState::Managed(Box::new(record.clone()));
    let service = ControlService::new(config_path.clone(), Surface::Cli);
    let journal = ProposalJournal::load(&paths, &key)
        .map_err(|e| OperatorActionError::new(Code::Journal, e.to_string()))?;

    let operation_id_typed = OperationId::new(operation_id)
        .map_err(|_| OperatorActionError::new(Code::UnknownOperation, operation_id.to_owned()))?;
    let entry = journal
        .entry(&operation_id_typed)
        .ok_or_else(|| OperatorActionError::new(Code::UnknownOperation, operation_id.to_owned()))?
        .clone();

    // Rebuild the bound proposal from the durable payload against the CURRENT
    // config: any drift expires the proposal at the atomic claim, but the digest
    // the operator authenticates against must be the current one.
    //
    // Boxed: `ControlInspection` carries a whole `Config`, so an un-boxed future
    // here overflows the test thread stack.
    let inspection = Box::pin(service.inspect())
        .await
        .map_err(|_| OperatorActionError::new(Code::PreviewStale, "inspect failed"))?;
    let bound = service
        .preview(
            inspection,
            &entry.selected_provider_ref,
            &entry.agent_proposal,
        )
        .map_err(|_| OperatorActionError::new(Code::PreviewStale, "preview failed"))?;
    let proposal_digest = ProposalDigest::of_bound_proposal(&bound)
        .map_err(|e| OperatorActionError::new(Code::PreviewStale, e.detail))?;
    let fingerprint = instance_fingerprint_for(&record, &paths)
        .ok_or_else(|| OperatorActionError::new(Code::RootUnusable, "fingerprint"))?;

    let request = ApprovalRequest {
        operation: entry.operation,
        proposal_digest,
        target_instance: record.instance_id.clone(),
        instance_fingerprint: fingerprint,
        source_revision: SourceRevisionDigest::of(bound.source_revision()),
    };
    // Reconstruct the parked requester's proposal domains: the broker requires
    // the requester to cover the operation's domain, exactly as it did when the
    // proposal was parked. The requester fingerprint the receipt binds to depends
    // only on class and subject, so this does not perturb it.
    let mut proposal_domains = BTreeSet::new();
    if let Some(domain) = entry.operation.proposal_domain() {
        proposal_domains.insert(domain.to_owned());
    }
    let requester = RequesterContext::external(
        RequesterSubject::new(&entry.requester_subject)
            .map_err(|e| OperatorActionError::new(Code::RequesterInvalid, e.detail))?,
        proposal_domains,
        evidence,
    );
    let now = now_unix_secs().map_err(|e| OperatorActionError::new(Code::Clock, e.detail))?;

    Ok(Prepared {
        paths,
        record,
        key,
        operators,
        trust,
        service,
        journal,
        operation_id: operation_id_typed,
        request,
        requester,
        now,
    })
}

/// Approve a parked proposal, driving the config mutation through the CAS.
///
/// `evidence` is what the reachability analysis reads: production passes
/// [`Evidence::unknown`] and fails closed until a prober exists.
///
/// # Errors
///
/// See [`OperatorActionErrorCode`].
pub async fn approve_operation(
    config_path: PathBuf,
    operation_id: &str,
    operator_identity: &str,
    presence: &dyn zeroclaw_control::UserPresence,
    evidence: Evidence,
    prompt: String,
    identity_prompt: String,
) -> Result<ApproveOutcome, OperatorActionError> {
    use OperatorActionErrorCode as Code;

    // Boxed: `prepare` holds a `ControlInspection` (a whole `Config`) across its
    // awaits, so inlining its future here would overflow the caller's stack.
    let mut prepared = Box::pin(prepare(config_path, operation_id, evidence)).await?;
    let claimed = OperatorIdentity::new(operator_identity)
        .map_err(|e| OperatorActionError::new(Code::OperatorRefused, e.detail))?;

    let auth = authenticate_operator(
        presence,
        prompt,
        identity_prompt,
        &claimed,
        &prepared.operators,
        prepared.record.trust_epoch,
        &prepared.requester,
        &prepared.request.proposal_digest,
        &prepared.record.instance_id,
        prepared.now,
    )
    .map_err(|e| OperatorActionError::new(Code::OperatorRefused, e.to_string()))?;

    let issued = {
        let ledger = InMemoryReceiptLedger::new();
        let broker =
            ApprovalBroker::new(&prepared.key, &prepared.trust, &prepared.operators, &ledger);
        broker
            .request_approval(&prepared.request, &prepared.requester, auth, prepared.now)
            .map_err(|e| OperatorActionError::new(Code::ApprovalRefused, e.to_string()))?
    };
    prepared
        .journal
        .record_approval(
            &prepared.operation_id,
            &issued,
            prepared.now,
            &prepared.paths,
            &prepared.key,
        )
        .map_err(|e| OperatorActionError::new(Code::Journal, e.to_string()))?;

    let worker = ApplyWorker::new(
        &prepared.paths,
        &prepared.key,
        &prepared.operators,
        &prepared.service,
        &prepared.record,
    );
    // Boxed for the same reason as `inspect`: the apply future re-inspects and
    // re-previews, so it carries a `Config` too.
    let WorkerOutcome::Verified { agent_alias } =
        Box::pin(worker.apply_approved(&prepared.operation_id, prepared.now))
            .await
            .map_err(|e| OperatorActionError::new(Code::ApplyFailed, e.to_string()))?;

    Ok(ApproveOutcome {
        operation_id: prepared.operation_id.as_str().to_owned(),
        agent_alias,
        state: "verified".to_owned(),
    })
}

/// Reject a parked proposal. Records a durable rejection; changes no config.
///
/// The operator still authenticates through the terminal backchannel, so a
/// requester cannot reject on an operator's behalf.
///
/// # Errors
///
/// See [`OperatorActionErrorCode`].
pub async fn reject_operation(
    config_path: PathBuf,
    operation_id: &str,
    operator_identity: &str,
    presence: &dyn zeroclaw_control::UserPresence,
    evidence: Evidence,
    prompt: String,
    identity_prompt: String,
) -> Result<RejectOutcome, OperatorActionError> {
    use OperatorActionErrorCode as Code;

    // Boxed: `prepare` holds a `ControlInspection` (a whole `Config`) across its
    // awaits, so inlining its future here would overflow the caller's stack.
    let mut prepared = Box::pin(prepare(config_path, operation_id, evidence)).await?;
    let claimed = OperatorIdentity::new(operator_identity)
        .map_err(|e| OperatorActionError::new(Code::OperatorRefused, e.detail))?;

    // The presence ceremony gates the rejection the same way it gates an
    // approval: only an authenticated, eligible operator reaches the record.
    let _auth = authenticate_operator(
        presence,
        prompt,
        identity_prompt,
        &claimed,
        &prepared.operators,
        prepared.record.trust_epoch,
        &prepared.requester,
        &prepared.request.proposal_digest,
        &prepared.record.instance_id,
        prepared.now,
    )
    .map_err(|e| OperatorActionError::new(Code::OperatorRefused, e.to_string()))?;

    prepared
        .journal
        .record_rejection(
            &prepared.operation_id,
            prepared.now,
            &prepared.paths,
            &prepared.key,
        )
        .map_err(|e| OperatorActionError::new(Code::Journal, e.to_string()))?;

    Ok(RejectOutcome {
        operation_id: prepared.operation_id.as_str().to_owned(),
        state: "rejected".to_owned(),
    })
}

/// Approve a parked proposal on a dedicated large-stack thread.
///
/// The apply chain (inspect, re-preview, the six-step claim, and the
/// revision-bound CAS) is deep and carries a whole `Config` at several frames,
/// so in a debug build it exceeds a default 2 MiB thread stack — the control
/// crate's own apply tests run on a 64 MiB thread for exactly this reason. The
/// `#[tokio::main]` runtime this CLI runs under gives its workers the default
/// stack, so the composition is driven here on a scoped thread with a generous
/// stack and its own current-thread runtime, rather than on the caller's.
///
/// `presence` is required to be `Sync` so the scoped thread may borrow it; the
/// terminal adapter and the test fixture both are.
///
/// # Errors
///
/// See [`OperatorActionErrorCode`].
pub fn approve_operation_blocking(
    config_path: PathBuf,
    operation_id: &str,
    operator_identity: &str,
    presence: &(dyn zeroclaw_control::UserPresence + Sync),
    evidence: Evidence,
    prompt: String,
    identity_prompt: String,
) -> Result<ApproveOutcome, OperatorActionError> {
    run_on_large_stack(move || {
        block_on_new_runtime(approve_operation(
            config_path,
            operation_id,
            operator_identity,
            presence,
            evidence,
            prompt,
            identity_prompt,
        ))
    })
}

/// Reject a parked proposal on a dedicated large-stack thread. See
/// [`approve_operation_blocking`].
///
/// # Errors
///
/// See [`OperatorActionErrorCode`].
pub fn reject_operation_blocking(
    config_path: PathBuf,
    operation_id: &str,
    operator_identity: &str,
    presence: &(dyn zeroclaw_control::UserPresence + Sync),
    evidence: Evidence,
    prompt: String,
    identity_prompt: String,
) -> Result<RejectOutcome, OperatorActionError> {
    run_on_large_stack(move || {
        block_on_new_runtime(reject_operation(
            config_path,
            operation_id,
            operator_identity,
            presence,
            evidence,
            prompt,
            identity_prompt,
        ))
    })
}

/// Drive one future to completion on a fresh current-thread runtime.
fn block_on_new_runtime<F, T>(future: F) -> Result<T, OperatorActionError>
where
    F: std::future::Future<Output = Result<T, OperatorActionError>>,
{
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| {
            OperatorActionError::new(OperatorActionErrorCode::ApplyFailed, e.to_string())
        })?;
    runtime.block_on(future)
}

/// Run `f` on a scoped thread with a 64 MiB stack, returning its result. The
/// scope borrows are what let the closure hold `&(dyn UserPresence + Sync)`.
fn run_on_large_stack<F, T>(f: F) -> Result<T, OperatorActionError>
where
    F: FnOnce() -> Result<T, OperatorActionError> + Send,
    T: Send,
{
    std::thread::scope(|scope| {
        match std::thread::Builder::new()
            .stack_size(64 * 1024 * 1024)
            .spawn_scoped(scope, f)
        {
            Ok(handle) => match handle.join() {
                Ok(result) => result,
                Err(_) => Err(OperatorActionError::new(
                    OperatorActionErrorCode::ApplyFailed,
                    "the apply thread panicked",
                )),
            },
            Err(e) => Err(OperatorActionError::new(
                OperatorActionErrorCode::ApplyFailed,
                e.to_string(),
            )),
        }
    })
}

/// Recompute the instance fingerprint over the roots the record names.
fn instance_fingerprint_for(
    record: &GenesisRecord,
    paths: &ControlPaths,
) -> Option<InstanceFingerprint> {
    let roots = paths.canonical_roots().ok()?;
    let config_identity = RootIdentity::probe(&roots.config_root).ok()?;
    let data_identity = RootIdentity::probe(&roots.data_root).ok()?;
    Some(InstanceFingerprint::compute(
        &record.instance_id,
        &record.digest(),
        record.trust_epoch,
        &roots,
        &config_identity,
        &data_identity,
    ))
}
