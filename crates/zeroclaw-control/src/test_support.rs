//! Shared scaffolding for this crate's unit tests.
//!
//! `#[cfg(test)]` at the module declaration in `lib.rs`, so none of this exists
//! in a shipped build. It lives in one module rather than being copied into
//! each test module so that "what a test instance looks like" has a single
//! definition — a scripted presence adapter that drifted between two test
//! modules would let one of them pass for the wrong reason.

use std::path::PathBuf;
use std::sync::Mutex;

use crate::ceremony::{
    GenesisRequest, PresenceAttestation, PresenceError, PresenceRequest, UserPresence, run_genesis,
};
use crate::genesis::{FirstOperatorIdentity, GenesisRecord, PresenceClass, classify};
use crate::keys::ApprovalAuditKey;
use crate::operator::{OperatorIdentity, RequesterContext, RequesterSubject};
use crate::reachability::Evidence;
use crate::store::ControlPaths;

/// A scripted presence adapter.
///
/// It reports [`PresenceClass::Terminal`] because that is the strongest class
/// this phase defines, and no adapter may name a class it cannot achieve.
pub(crate) struct ScriptedPresence {
    outcome: Result<Option<String>, PresenceError>,
    seen: Mutex<Vec<PresenceRequest>>,
}

impl ScriptedPresence {
    /// Confirms, and attests `identity` when the request asks for one.
    pub(crate) fn affirming(identity: &str) -> Self {
        Self {
            outcome: Ok(Some(identity.to_string())),
            seen: Mutex::new(Vec::new()),
        }
    }

    /// Confirms, but attests no identity even when asked.
    pub(crate) fn affirming_without_identity() -> Self {
        Self {
            outcome: Ok(None),
            seen: Mutex::new(Vec::new()),
        }
    }

    /// Produces no attestation.
    pub(crate) fn failing(error: PresenceError) -> Self {
        Self {
            outcome: Err(error),
            seen: Mutex::new(Vec::new()),
        }
    }

    /// How many times a prompt was put to the human.
    pub(crate) fn prompts(&self) -> usize {
        self.seen.lock().expect("presence log").len()
    }
}

impl UserPresence for ScriptedPresence {
    fn confirm(&self, request: &PresenceRequest) -> Result<PresenceAttestation, PresenceError> {
        self.seen
            .lock()
            .expect("presence log")
            .push(request.clone());
        match &self.outcome {
            Ok(identity) => Ok(PresenceAttestation::for_test(
                PresenceClass::Terminal,
                match (identity, &request.operator_prompt) {
                    (Some(value), Some(_)) => Some(
                        FirstOperatorIdentity::new(value.clone()).expect("test identity is valid"),
                    ),
                    _ => None,
                },
            )),
            Err(e) => Err(e.clone()),
        }
    }
}

/// A bare install root: a config file and a data directory, no control state.
pub(crate) fn install_root(tmp: &tempfile::TempDir) -> PathBuf {
    let root = tmp.path().join("install");
    std::fs::create_dir_all(root.join("data")).expect("create install root");
    std::fs::write(root.join("config.toml"), b"# config").expect("write config");
    root
}

/// A genesis'd instance whose first operator is `jordan`.
pub(crate) fn genesis_instance(
    tmp: &tempfile::TempDir,
) -> (PathBuf, ControlPaths, Box<GenesisRecord>) {
    let root = install_root(tmp);
    run_genesis(
        &root,
        &ScriptedPresence::affirming("jordan"),
        &GenesisRequest {
            prompt: "Authorize genesis? ".to_string(),
            operator_prompt: "First operator identity: ".to_string(),
            register_client: None,
        },
    )
    .expect("genesis must succeed");
    let paths = ControlPaths::resolve(&root).expect("resolve");
    let record = Box::new(
        classify(&paths, &paths.key_source())
            .record()
            .expect("managed")
            .clone(),
    );
    (root, paths, record)
}

/// The approval and audit key for a managed instance.
pub(crate) fn key_for(paths: &ControlPaths, record: &GenesisRecord) -> ApprovalAuditKey {
    ApprovalAuditKey::derive(&paths.key_source(), record.trust_epoch).expect("derive")
}

/// A valid operator identity.
pub(crate) fn operator(name: &str) -> OperatorIdentity {
    OperatorIdentity::new(name).expect("valid operator identity")
}

/// The one proposal domain v1 defines.
pub(crate) fn agent_domain() -> std::collections::BTreeSet<String> {
    crate::client_registry::PROPOSAL_DOMAINS_V1
        .iter()
        .map(|d| (*d).to_string())
        .collect()
}

/// A requester the host has proved cannot reach the operator backchannel.
///
/// Nothing in this phase can actually discharge those proofs; this is the only
/// way a test can exercise the eligible branch at all, which is itself the
/// honest statement of where the phase stands.
pub(crate) fn isolated_requester(subject: &str) -> RequesterContext {
    RequesterContext::external(
        RequesterSubject::new(subject).expect("subject"),
        agent_domain(),
        Evidence::fully_isolated(),
    )
}

/// A same-process agent requester: the host has proved nothing about it.
pub(crate) fn unprovable_requester(subject: &str) -> RequesterContext {
    RequesterContext::agent(
        RequesterSubject::new(subject).expect("subject"),
        agent_domain(),
        Evidence::unknown(),
    )
}
