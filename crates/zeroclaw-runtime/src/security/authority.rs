//! Authority that is rechecked at the effect, not only at admission.
//!
//! Authorization computed once, against a snapshot of grants and resource
//! state, goes stale when the effect runs later: after a session queue
//! permit, a config write lock, a decision-model wait, a scheduler tick, a
//! delegation hop, or on every delivered stream frame. The check was correct
//! when it ran and wrong when it mattered.
//!
//! This module turns the second check into a type obligation. An operation is
//! written in four steps, in this order:
//!
//! ```text
//! admit   : gate + selectors on the stamped grants        -> Admitted<Op>
//! wait    : queue permit / write lock / decision / claim  -> a SerializationProof
//! recheck : Admitted::recheck(fresh grants, fresh resource, &proof) -> Effect<Op>
//! effect  : fn do_the_thing(effect: Effect<Op>, ..)
//! ```
//!
//! [`Effect`] has no public constructor, so an effect function that takes one
//! by value cannot be reached without a recheck, and [`Admitted::recheck`]
//! demands a [`SerializationProof`], a sealed trait implemented only by the
//! guard types a wait returns. The compiler, not the reviewer, orders the
//! steps.
//!
//! Rules a site implements (numbered as in the design record):
//!
//! 1. One predicate, called twice. [`AuthorizedOp::predicate`] is the whole
//!    fine-grained check; admission and recheck both call it.
//! 2. Fresh grants, never the stamped copy: the recheck re-resolves through
//!    the accepted policy, so a widened grant is honoured and a narrowed one
//!    applies.
//! 3. Fresh resource: the caller reads owner, incarnation, channel owner and
//!    the like again after the wait and passes them as `Live`.
//! 4. Inside the serialization the effect runs under: the proof is a
//!    parameter, and a publication that lands between the resolution and
//!    the generation read fails closed.
//! 5. Fail closed and audit: a failed recheck is refused with the gate's
//!    denial; nothing falls back to the admitted grants.
//!
//! Effects that run outside a connection (cron ticks, SOP drivers, delegation
//! targets) carry a [`crate::security::principal_envelope::PrincipalEnvelope`]
//! instead of a connection binding; see that module.

use std::marker::PhantomData;

use zeroclaw_api::grants::ResolvedGrants;
use zeroclaw_api::principal::PrincipalId;

use crate::rpc::auth::{AuthDenied, ConnectionAuth, RpcInboundAuth};
use crate::rpc::dispatch::{Method, MethodAuthz, current_authority};

/// One authority-sensitive operation, implemented per site.
pub trait AuthorizedOp: Sized + Send {
    /// Stable name for audit records and the test pause registry.
    const NAME: &'static str;

    /// The resource facts the predicate needs, read fresh at every call.
    type Live: ?Sized;

    /// The RPC method whose coarse grant this operation requires. The
    /// recheck applies it through [`current_authority`].
    fn method(&self) -> Method;

    /// The complete fine-grained predicate: selectors, ownership, ceilings.
    /// Called at admission with the stamped grants and a snapshot, and at
    /// recheck with freshly resolved grants and a fresh read. Never split
    /// into an admission half and a recheck half.
    fn predicate(&self, grants: &ResolvedGrants, live: &Self::Live) -> Result<(), AuthDenied>;
}

mod sealed {
    pub trait Sealed {}
    /// Private token so [`super::Effect`] cannot be built outside this module.
    pub struct Token(pub(super) ());
}

/// Proof that the caller holds the serialization the effect runs under. Only
/// the guard types listed in this module implement it, so a site cannot pass
/// a bare `()` and skip the wait.
pub trait SerializationProof: sealed::Sealed {
    /// Short label for audit records.
    fn kind(&self) -> &'static str;
}

/// The config write lock (`RpcContext::config_write_lock`), held by the
/// config mutation handlers through commit.
impl sealed::Sealed for crate::rpc::context::ConfigWriteGuard {}
impl SerializationProof for crate::rpc::context::ConfigWriteGuard {
    fn kind(&self) -> &'static str {
        "config_write_lock"
    }
}

/// The session actor permit (`SessionActorQueue::acquire`), held by prompt,
/// append, and the other session mutations while they run.
impl sealed::Sealed for zeroclaw_infra::session_queue::SessionGuard {}
impl SerializationProof for zeroclaw_infra::session_queue::SessionGuard {
    fn kind(&self) -> &'static str {
        "session_admission"
    }
}

/// A SOP decision model has finished evaluating and the run is about to be
/// admitted. Constructed only by the dispatch path that awaited the model.
#[must_use]
pub struct DecisionSettled(());

impl DecisionSettled {
    /// Call only at the point where the decision wait has returned.
    pub fn after_decision_wait() -> Self {
        Self(())
    }
}
impl sealed::Sealed for DecisionSettled {}
impl SerializationProof for DecisionSettled {
    fn kind(&self) -> &'static str {
        "decision_settled"
    }
}

/// The scheduler holds this tick's claim on a job. Constructed only by the
/// scheduler after `claim` succeeded.
#[must_use]
pub struct SchedulerClaim(());

impl SchedulerClaim {
    /// Call only once the job row is claimed for this tick.
    pub fn after_claim() -> Self {
        Self(())
    }
}
impl sealed::Sealed for SchedulerClaim {}
impl SerializationProof for SchedulerClaim {
    fn kind(&self) -> &'static str {
        "scheduler_claim"
    }
}

/// One stream frame is about to be written to one viewer. Constructed by
/// the delivery loop per frame, so per-frame rechecks are the only kind.
#[must_use]
pub struct DeliverySlot(());

impl DeliverySlot {
    /// Call once per frame, immediately before the write.
    pub fn for_frame() -> Self {
        Self(())
    }
}
impl sealed::Sealed for DeliverySlot {}
impl SerializationProof for DeliverySlot {
    fn kind(&self) -> &'static str {
        "delivery_slot"
    }
}

/// An operation that passed admission and has not yet been rechecked. It
/// has no effect: nothing accepts it but [`Admitted::recheck`].
#[must_use = "an admitted operation has no effect until it is rechecked"]
pub struct Admitted<Op: AuthorizedOp> {
    op: Op,
    principal: PrincipalId,
    admitted_generation: u64,
    _no_effect: PhantomData<()>,
}

/// The only value an effect function accepts. No public constructor; the
/// single way to obtain one is [`Admitted::recheck`].
pub struct Effect<Op: AuthorizedOp> {
    op: Op,
    principal: PrincipalId,
    grants: ResolvedGrants,
    checked_generation: u64,
    proof_kind: &'static str,
    _sealed: sealed::Token,
}

impl<Op: AuthorizedOp> std::fmt::Debug for Admitted<Op> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Admitted")
            .field("op", &Op::NAME)
            .field("principal", &self.principal)
            .field("admitted_generation", &self.admitted_generation)
            .finish_non_exhaustive()
    }
}

impl<Op: AuthorizedOp> std::fmt::Debug for Effect<Op> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Effect")
            .field("op", &Op::NAME)
            .field("principal", &self.principal)
            .field("checked_generation", &self.checked_generation)
            .field("proof_kind", &self.proof_kind)
            .finish_non_exhaustive()
    }
}

impl<Op: AuthorizedOp> Admitted<Op> {
    /// Step 1. Runs the coarse grant for `op.method()` and the full
    /// predicate on the grants stamped on `conn`, against `live` as it is
    /// now. `live` is a snapshot; the recheck reads it again.
    pub fn admit(op: Op, conn: &ConnectionAuth, live: &Op::Live) -> Result<Self, AuthDenied> {
        let method = op.method();
        if let MethodAuthz::Requires(resource, verb) = method.authz()
            && !conn.grants.permits(resource, verb)
        {
            return Err(AuthDenied::forbidden(format!(
                "Principal is not granted {resource}:{verb} (required by {})",
                method.wire_name()
            )));
        }
        op.predicate(&conn.grants, live)?;
        Ok(Self {
            op,
            principal: conn.principal.id.clone(),
            admitted_generation: conn.generation,
            _no_effect: PhantomData,
        })
    }

    /// The operation, for logging between admission and recheck.
    pub fn op(&self) -> &Op {
        &self.op
    }

    /// The authorization generation the admission was judged under.
    pub fn admitted_generation(&self) -> u64 {
        self.admitted_generation
    }

    /// Step 3. Consumes the admission; runs the same predicate on freshly
    /// resolved grants and a freshly read `live`, under `proof`.
    ///
    /// Liveness, re-resolution, and the moved-generation check are
    /// [`current_authority`]'s; this adds the predicate and hands back an
    /// [`Effect`]. In test builds the registered pause for `Op::NAME` fires
    /// here, after the proof is held and before re-resolution, so a test can
    /// change the policy at exactly the point the effect is about to run.
    pub async fn recheck<P: SerializationProof>(
        self,
        inbound: &RpcInboundAuth,
        conn: &ConnectionAuth,
        live: &Op::Live,
        proof: &P,
    ) -> Result<Effect<Op>, AuthDenied> {
        #[cfg(any(test, feature = "test-util"))]
        test_pause::registry().wait_if_armed(Op::NAME, true).await;

        let grants = current_authority(inbound, conn, self.op.method())?;
        self.op.predicate(&grants, live)?;
        Ok(Effect {
            op: self.op,
            principal: self.principal,
            grants,
            checked_generation: inbound.generation(),
            proof_kind: proof.kind(),
            _sealed: sealed::Token(()),
        })
    }
}

impl<Op: AuthorizedOp> Effect<Op> {
    /// The operation the effect may now perform.
    pub fn op(&self) -> &Op {
        &self.op
    }

    /// The freshly resolved grants, for the effect's own fine-grained
    /// selectors (a config path, an agent, a tool).
    pub fn grants(&self) -> &ResolvedGrants {
        &self.grants
    }

    /// The principal the effect runs for.
    pub fn principal(&self) -> &PrincipalId {
        &self.principal
    }

    /// The authorization generation the recheck was judged under.
    pub fn checked_generation(&self) -> u64 {
        self.checked_generation
    }

    /// Which serialization the recheck ran under, for audit records.
    pub fn proof_kind(&self) -> &'static str {
        self.proof_kind
    }

    /// Consume the effect and take the operation.
    pub fn into_op(self) -> Op {
        self.op
    }
}

/// Test-only pause points, shared by every site.
///
/// A pause point is armed by a test, fires once inside the code under test
/// at the moment the test wants to change the world, and records whether
/// the serialization proof was held when it fired. That record is the guard
/// against a vacuous test: a park before admission would pass trivially.
///
/// Two flavours exist because the code under test is sometimes async (the
/// dispatcher) and sometimes a synchronous trait method (a session backend).
/// Both share one [`TestPause`].
#[cfg(any(test, feature = "test-util"))]
pub mod test_pause {
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Condvar, Mutex, OnceLock};

    use tokio::sync::Notify;

    /// One armable pause point. Embed one per instance (as `SessionStore`
    /// does) or register one per operation name through [`registry`].
    #[derive(Default)]
    pub struct TestPause {
        armed: Mutex<Option<Arc<Armed>>>,
    }

    struct Armed {
        entered: Notify,
        released: (Mutex<bool>, Condvar),
        fired: AtomicBool,
        proof_held: AtomicBool,
    }

    /// What a test holds while a pause is armed. Dropping it disarms the
    /// pause and releases anything still parked on it.
    pub struct PauseHandle {
        armed: Arc<Armed>,
        owner: Arc<TestPause>,
    }

    impl TestPause {
        /// Arm the pause. The returned handle is how the test waits for the
        /// code under test to arrive and then lets it continue.
        pub fn arm(self: &Arc<Self>) -> PauseHandle {
            let armed = Arc::new(Armed {
                entered: Notify::new(),
                released: (Mutex::new(false), Condvar::new()),
                fired: AtomicBool::new(false),
                proof_held: AtomicBool::new(false),
            });
            *self.armed.lock().unwrap_or_else(|e| e.into_inner()) = Some(Arc::clone(&armed));
            PauseHandle {
                armed,
                owner: Arc::clone(self),
            }
        }

        fn take_armed(&self) -> Option<Arc<Armed>> {
            self.armed
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .as_ref()
                .map(Arc::clone)
        }

        /// Async flavour: if armed, record `proof_held`, signal the test,
        /// and park until it releases. A no-op when not armed.
        pub async fn wait_if_armed(&self, proof_held: bool) {
            let Some(armed) = self.take_armed() else {
                return;
            };
            armed.fire(proof_held);
            let parked = Arc::clone(&armed);
            tokio::task::spawn_blocking(move || parked.block_until_released())
                .await
                .expect("the pause waiter is never cancelled");
        }

        /// Blocking flavour for synchronous code under test.
        pub fn wait_if_armed_blocking(&self, proof_held: bool) {
            let Some(armed) = self.take_armed() else {
                return;
            };
            armed.fire(proof_held);
            armed.block_until_released();
        }
    }

    impl Armed {
        fn fire(&self, proof_held: bool) {
            self.proof_held.store(proof_held, Ordering::SeqCst);
            self.fired.store(true, Ordering::SeqCst);
            self.entered.notify_one();
        }

        fn block_until_released(&self) {
            let (lock, cvar) = &self.released;
            let mut released = lock.lock().unwrap_or_else(|e| e.into_inner());
            while !*released {
                released = cvar.wait(released).unwrap_or_else(|e| e.into_inner());
            }
        }

        fn release(&self) {
            let (lock, cvar) = &self.released;
            *lock.lock().unwrap_or_else(|e| e.into_inner()) = true;
            cvar.notify_all();
        }
    }

    impl PauseHandle {
        /// Resolves when the code under test has reached the pause point.
        pub async fn admitted(&self) {
            if self.armed.fired.load(Ordering::SeqCst) {
                return;
            }
            self.armed.entered.notified().await;
        }

        /// Let the parked code continue.
        pub fn release(&self) {
            self.armed.release();
        }

        /// Whether the pause has fired at least once.
        pub fn fired(&self) -> bool {
            self.armed.fired.load(Ordering::SeqCst)
        }

        /// The guard assertion: whether the serialization proof was held
        /// when the pause fired. A revoke-mid-flight test asserts this is
        /// `true`, or it parked before admission and proves nothing.
        pub fn proof_was_held_at_pause(&self) -> bool {
            self.armed.proof_held.load(Ordering::SeqCst)
        }

        /// The legacy `(entered, release)` shape used by
        /// `SessionStore::set_test_prompt_registration_pause` callers.
        pub fn legacy_pair(&self) -> (Arc<Notify>, Arc<Notify>) {
            let entered = Arc::new(Notify::new());
            let release = Arc::new(Notify::new());
            let armed = Arc::clone(&self.armed);
            let entered_out = Arc::clone(&entered);
            let release_in = Arc::clone(&release);
            // Bridge: forward the pause's `entered` to the tuple's, and the
            // tuple's `release` to the pause's condvar.
            zeroclaw_spawn::spawn!(async move {
                armed.entered.notified().await;
                entered_out.notify_one();
                release_in.notified().await;
                armed.release();
            });
            (entered, release)
        }
    }

    impl Drop for PauseHandle {
        fn drop(&mut self) {
            // Disarm only if the owner still points at this arming; a later
            // `arm` replaced it and must not be disturbed.
            let mut slot = self.owner.armed.lock().unwrap_or_else(|e| e.into_inner());
            if slot
                .as_ref()
                .is_some_and(|current| Arc::ptr_eq(current, &self.armed))
            {
                *slot = None;
            }
            drop(slot);
            self.armed.release();
        }
    }

    /// Process-wide registry of pause points keyed by [`super::AuthorizedOp::NAME`].
    /// [`super::Admitted::recheck`] consults it. Tests that arm the same
    /// name must not run concurrently; use distinct names per site.
    pub struct PauseRegistry {
        points: Mutex<HashMap<&'static str, Arc<TestPause>>>,
    }

    impl PauseRegistry {
        fn point(&self, name: &'static str) -> Arc<TestPause> {
            Arc::clone(
                self.points
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .entry(name)
                    .or_default(),
            )
        }

        /// Arm the pause for `name`.
        pub fn arm(&self, name: &'static str) -> PauseHandle {
            self.point(name).arm()
        }

        /// Async wait used by [`super::Admitted::recheck`].
        pub async fn wait_if_armed(&self, name: &'static str, proof_held: bool) {
            let point = {
                let points = self.points.lock().unwrap_or_else(|e| e.into_inner());
                points.get(name).map(Arc::clone)
            };
            if let Some(point) = point {
                point.wait_if_armed(proof_held).await;
            }
        }

        /// Blocking wait for synchronous code under test.
        pub fn wait_if_armed_blocking(&self, name: &'static str, proof_held: bool) {
            let point = {
                let points = self.points.lock().unwrap_or_else(|e| e.into_inner());
                points.get(name).map(Arc::clone)
            };
            if let Some(point) = point {
                point.wait_if_armed_blocking(proof_held);
            }
        }
    }

    /// The process-wide registry.
    pub fn registry() -> &'static PauseRegistry {
        static REGISTRY: OnceLock<PauseRegistry> = OnceLock::new();
        REGISTRY.get_or_init(|| PauseRegistry {
            points: Mutex::new(HashMap::new()),
        })
    }

    /// Arm the pause that [`super::Admitted::recheck`] fires for `Op::NAME`.
    pub fn authority_test_pause(name: &'static str) -> PauseHandle {
        registry().arm(name)
    }

    /// A session backend that parks immediately before every access while
    /// its pause is armed, so a test can change ownership or policy between
    /// an operation's admission and its storage effect.
    ///
    /// The forwarded methods are synchronous and block the calling thread
    /// while parked, so drive the operation under test from a task on a
    /// multi-thread runtime (or `spawn_blocking`) and release from the test
    /// body, as `PauseBeforeAccessBackend` did in the session-tools tests.
    pub struct PausingSessionBackend {
        inner: Arc<dyn SessionBackend>,
        pause: Arc<TestPause>,
    }

    use zeroclaw_api::model_provider::ChatMessage;
    use zeroclaw_infra::session_backend::{
        SessionBackend, SessionContext, SessionMetadata, SessionQuery, SessionState,
        TimestampedMessage,
    };

    impl PausingSessionBackend {
        pub fn new(inner: Arc<dyn SessionBackend>) -> Self {
            Self {
                inner,
                pause: Arc::new(TestPause::default()),
            }
        }

        /// The pause point; arm it with [`TestPause::arm`].
        pub fn pause(&self) -> &Arc<TestPause> {
            &self.pause
        }

        /// The wrapped backend, for the test to mutate state behind the
        /// parked operation.
        pub fn inner(&self) -> &Arc<dyn SessionBackend> {
            &self.inner
        }

        fn park(&self) {
            // A backend access holds no serialization proof of its own; the
            // caller that obtained the permit records that separately.
            self.pause.wait_if_armed_blocking(false);
        }
    }

    impl SessionBackend for PausingSessionBackend {
        fn load(&self, session_key: &str) -> Vec<ChatMessage> {
            self.park();
            self.inner.load(session_key)
        }
        fn try_load(&self, session_key: &str) -> std::io::Result<Vec<ChatMessage>> {
            self.park();
            self.inner.try_load(session_key)
        }
        fn load_with_timestamps(&self, session_key: &str) -> Vec<TimestampedMessage> {
            self.park();
            self.inner.load_with_timestamps(session_key)
        }
        fn append(&self, session_key: &str, message: &ChatMessage) -> std::io::Result<()> {
            self.park();
            self.inner.append(session_key, message)
        }
        fn remove_last(&self, session_key: &str) -> std::io::Result<bool> {
            self.park();
            self.inner.remove_last(session_key)
        }
        fn rewrite_messages(
            &self,
            session_key: &str,
            messages: &[ChatMessage],
        ) -> std::io::Result<()> {
            self.park();
            self.inner.rewrite_messages(session_key, messages)
        }
        fn update_last(&self, session_key: &str, message: &ChatMessage) -> std::io::Result<bool> {
            self.park();
            self.inner.update_last(session_key, message)
        }
        fn list_sessions(&self) -> Vec<String> {
            self.park();
            self.inner.list_sessions()
        }
        fn list_sessions_with_metadata(&self) -> Vec<SessionMetadata> {
            self.park();
            self.inner.list_sessions_with_metadata()
        }
        fn compact(&self, session_key: &str) -> std::io::Result<()> {
            self.park();
            self.inner.compact(session_key)
        }
        fn cleanup_stale(&self, ttl_hours: u32) -> std::io::Result<usize> {
            self.park();
            self.inner.cleanup_stale(ttl_hours)
        }
        fn search(&self, query: &SessionQuery) -> Vec<SessionMetadata> {
            self.park();
            self.inner.search(query)
        }
        fn clear_messages(&self, session_key: &str) -> std::io::Result<usize> {
            self.park();
            self.inner.clear_messages(session_key)
        }
        fn delete_session(&self, session_key: &str) -> std::io::Result<bool> {
            self.park();
            self.inner.delete_session(session_key)
        }
        fn clear_agent_attribution(&self, agent_alias: &str) -> std::io::Result<usize> {
            self.park();
            self.inner.clear_agent_attribution(agent_alias)
        }
        fn rename_agent_attribution(&self, from: &str, to: &str) -> std::io::Result<usize> {
            self.park();
            self.inner.rename_agent_attribution(from, to)
        }
        fn count_agent_attribution(&self, agent_alias: &str) -> std::io::Result<usize> {
            self.park();
            self.inner.count_agent_attribution(agent_alias)
        }
        fn session_exists(&self, session_key: &str) -> bool {
            self.park();
            self.inner.session_exists(session_key)
        }
        fn set_session_name(&self, session_key: &str, name: &str) -> std::io::Result<()> {
            self.park();
            self.inner.set_session_name(session_key, name)
        }
        fn get_session_name(&self, session_key: &str) -> std::io::Result<Option<String>> {
            self.park();
            self.inner.get_session_name(session_key)
        }
        fn set_session_agent_alias(
            &self,
            session_key: &str,
            agent_alias: &str,
        ) -> std::io::Result<()> {
            self.park();
            self.inner.set_session_agent_alias(session_key, agent_alias)
        }
        fn get_session_agent_alias(&self, session_key: &str) -> std::io::Result<Option<String>> {
            self.park();
            self.inner.get_session_agent_alias(session_key)
        }
        fn set_session_trim_breadcrumb(
            &self,
            session_key: &str,
            present: bool,
        ) -> std::io::Result<()> {
            self.park();
            self.inner.set_session_trim_breadcrumb(session_key, present)
        }
        fn get_session_trim_breadcrumb(&self, session_key: &str) -> std::io::Result<Option<bool>> {
            self.park();
            self.inner.get_session_trim_breadcrumb(session_key)
        }
        fn replace_conversation_state(
            &self,
            session_key: &str,
            messages: &[ChatMessage],
            breadcrumb_present: bool,
        ) -> std::io::Result<()> {
            self.park();
            self.inner
                .replace_conversation_state(session_key, messages, breadcrumb_present)
        }
        fn replace_conversation_state_if_exists(
            &self,
            session_key: &str,
            messages: &[ChatMessage],
            breadcrumb_present: bool,
        ) -> std::io::Result<bool> {
            self.park();
            self.inner.replace_conversation_state_if_exists(
                session_key,
                messages,
                breadcrumb_present,
            )
        }
        fn set_session_context(
            &self,
            session_key: &str,
            context: SessionContext<'_>,
        ) -> std::io::Result<()> {
            self.park();
            self.inner.set_session_context(session_key, context)
        }
        fn get_session_metadata(&self, session_key: &str) -> Option<SessionMetadata> {
            self.park();
            self.inner.get_session_metadata(session_key)
        }
        fn set_session_principal(
            &self,
            session_key: &str,
            principal_id: &str,
        ) -> std::io::Result<()> {
            self.park();
            self.inner.set_session_principal(session_key, principal_id)
        }
        fn delete_session_owned(
            &self,
            session_key: &str,
            owner_principal_id: &str,
        ) -> std::io::Result<bool> {
            self.park();
            self.inner
                .delete_session_owned(session_key, owner_principal_id)
        }
        fn set_session_state(
            &self,
            session_key: &str,
            state: &str,
            turn_id: Option<&str>,
        ) -> std::io::Result<()> {
            self.park();
            self.inner.set_session_state(session_key, state, turn_id)
        }
        fn get_session_state(&self, session_key: &str) -> std::io::Result<Option<SessionState>> {
            self.park();
            self.inner.get_session_state(session_key)
        }
        fn list_running_sessions(&self) -> Vec<SessionMetadata> {
            self.park();
            self.inner.list_running_sessions()
        }
        fn list_stuck_sessions(&self, threshold_secs: u64) -> Vec<SessionMetadata> {
            self.park();
            self.inner.list_stuck_sessions(threshold_secs)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use zeroclaw_api::grants::{Resource, Verb};
    use zeroclaw_config::pairing::{PairingCodePolicy, PairingGuard};
    use zeroclaw_config::schema::{Config, PermissionProfileConfig, UserConfig};

    use crate::rpc::transport::TransportKind;
    use crate::security::auth_provider::Credential;

    const ALICE_UID: u32 = 4242;

    /// A roster with alice holding `sessions:read` and access to `alpha`.
    fn config_with_alice(agents: &[&str]) -> Config {
        let mut config = Config::default();
        // The selector validation refuses a profile that names an agent the
        // config does not define, and an invalid policy compiles to deny-all.
        for alias in ["alpha", "beta"] {
            config.agents.insert(
                alias.to_string(),
                zeroclaw_config::schema::AliasedAgentConfig::default(),
            );
        }
        config.permission_profiles.insert(
            "reader".into(),
            PermissionProfileConfig {
                grants: std::collections::HashMap::from([(Resource::Sessions, vec![Verb::Read])]),
                allowed_agents: agents.iter().map(|a| (*a).to_string()).collect(),
                ..PermissionProfileConfig::default()
            },
        );
        config.users.insert(
            "alice".into(),
            UserConfig {
                principal_id: None,
                uid: Some(ALICE_UID),
                permission_profiles: vec!["reader".into()],
            },
        );
        config
    }

    fn inbound_for(config: &Config) -> RpcInboundAuth {
        RpcInboundAuth::from_config(
            config,
            Arc::new(PairingGuard::new(true, &[], PairingCodePolicy::default())),
        )
        .expect("valid policy")
    }

    async fn alice_on(inbound: &RpcInboundAuth) -> ConnectionAuth {
        inbound
            .authenticate(
                TransportKind::Local,
                Credential::Peercred { uid: ALICE_UID },
                None,
                None,
            )
            .await
            .expect("alice is on the roster")
    }

    /// A read of one agent's sessions: coarse `sessions:read` plus the agent
    /// selector, with the live fact being which agent the session belongs to.
    struct ReadAgentSessions;

    impl AuthorizedOp for ReadAgentSessions {
        const NAME: &'static str = "test_read_agent_sessions";
        type Live = str;

        fn method(&self) -> Method {
            Method::SessionList
        }

        fn predicate(&self, grants: &ResolvedGrants, live: &str) -> Result<(), AuthDenied> {
            if grants.may_use_agent(live) {
                Ok(())
            } else {
                Err(AuthDenied::forbidden(format!(
                    "not entitled to agent {live:?}"
                )))
            }
        }
    }

    fn write_lock() -> crate::rpc::context::ConfigWriteGuard {
        Arc::new(tokio::sync::Mutex::new(()))
            .try_lock_owned()
            .expect("fresh lock")
    }

    #[tokio::test]
    async fn admit_then_recheck_yields_an_effect_when_nothing_changed() {
        let inbound = inbound_for(&config_with_alice(&["alpha"]));
        let conn = alice_on(&inbound).await;
        let admitted = Admitted::admit(ReadAgentSessions, &conn, "alpha").expect("admitted");
        let effect = admitted
            .recheck(&inbound, &conn, "alpha", &write_lock())
            .await
            .expect("still authorized");
        assert_eq!(effect.proof_kind(), "config_write_lock");
        assert_eq!(effect.checked_generation(), inbound.generation());
        assert!(effect.grants().permits(Resource::Sessions, Verb::Read));
    }

    #[tokio::test]
    async fn admit_refuses_the_coarse_grant_and_the_selector() {
        let inbound = inbound_for(&config_with_alice(&["alpha"]));
        let conn = alice_on(&inbound).await;
        let denied = Admitted::admit(ReadAgentSessions, &conn, "beta").unwrap_err();
        assert!(denied.message.contains("beta"), "{denied:?}");
    }

    #[tokio::test]
    async fn recheck_refuses_a_grant_narrowed_after_admission() {
        let inbound = inbound_for(&config_with_alice(&["alpha"]));
        let conn = alice_on(&inbound).await;
        let admitted = Admitted::admit(ReadAgentSessions, &conn, "alpha").expect("admitted");

        // The world changes while the operation is parked: alice loses alpha.
        inbound
            .refresh_from_config(&config_with_alice(&[]))
            .expect("narrowed policy compiles");

        let denied = admitted
            .recheck(&inbound, &conn, "alpha", &write_lock())
            .await
            .unwrap_err();
        assert!(denied.message.contains("alpha"), "{denied:?}");
    }

    #[tokio::test]
    async fn recheck_honours_a_grant_widened_after_admission() {
        // Admission needs alpha; the recheck reads the live agent as beta,
        // which only the widened policy allows. Proves re-resolution, not a
        // comparison against the stamped grants.
        let inbound = inbound_for(&config_with_alice(&["alpha"]));
        let conn = alice_on(&inbound).await;
        let admitted = Admitted::admit(ReadAgentSessions, &conn, "alpha").expect("admitted");

        inbound
            .refresh_from_config(&config_with_alice(&["alpha", "beta"]))
            .expect("widened policy compiles");

        let effect = admitted
            .recheck(&inbound, &conn, "beta", &write_lock())
            .await
            .expect("the widened grant is honoured");
        assert!(effect.grants().may_use_agent("beta"));
    }

    #[tokio::test]
    async fn recheck_refuses_a_resource_reowned_after_admission() {
        let inbound = inbound_for(&config_with_alice(&["alpha"]));
        let conn = alice_on(&inbound).await;
        let admitted = Admitted::admit(ReadAgentSessions, &conn, "alpha").expect("admitted");
        // Same policy, but the live resource now belongs to another agent.
        let denied = admitted
            .recheck(&inbound, &conn, "beta", &write_lock())
            .await
            .unwrap_err();
        assert!(denied.message.contains("beta"), "{denied:?}");
    }

    #[tokio::test]
    async fn the_pause_fires_after_the_proof_is_held_and_before_re_resolution() {
        let inbound = Arc::new(inbound_for(&config_with_alice(&["alpha"])));
        let conn = alice_on(&inbound).await;
        let admitted = Admitted::admit(ReadAgentSessions, &conn, "alpha").expect("admitted");
        let pause = test_pause::authority_test_pause(ReadAgentSessions::NAME);

        let inbound_task = Arc::clone(&inbound);
        let task = zeroclaw_spawn::spawn!(async move {
            admitted
                .recheck(&inbound_task, &conn, "alpha", &write_lock())
                .await
        });

        pause.admitted().await;
        assert!(
            pause.proof_was_held_at_pause(),
            "the recheck must pause with the serialization proof already held"
        );
        // Narrow while parked: the recheck has not re-resolved yet, so the
        // narrowing must be what it sees.
        inbound
            .refresh_from_config(&config_with_alice(&[]))
            .expect("narrowed policy compiles");
        pause.release();

        let outcome = task.await.expect("recheck task completes");
        assert!(
            outcome.is_err(),
            "a narrowing applied during the pause must refuse"
        );
    }

    #[tokio::test]
    async fn an_unarmed_pause_is_a_no_op() {
        let point = Arc::new(test_pause::TestPause::default());
        point.wait_if_armed(true).await;
        point.wait_if_armed_blocking(true);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_pausing_backend_parks_before_the_access_and_sees_the_change() {
        use zeroclaw_api::model_provider::ChatMessage;
        use zeroclaw_infra::session_backend::SessionBackend;

        let tmp = tempfile::TempDir::new().expect("tempdir");
        let inner = zeroclaw_infra::make_session_backend(tmp.path(), "sqlite").expect("backend");
        inner
            .append("shared", &ChatMessage::user("before"))
            .expect("seed");
        let backend = Arc::new(test_pause::PausingSessionBackend::new(Arc::clone(&inner)));
        let handle = backend.pause().arm();

        let reader = Arc::clone(&backend);
        let task = tokio::task::spawn_blocking(move || reader.load("shared"));

        handle.admitted().await;
        assert!(
            !handle.proof_was_held_at_pause(),
            "a backend access holds no proof"
        );
        inner
            .append("shared", &ChatMessage::user("during"))
            .expect("append while parked");
        handle.release();

        let seen = task.await.expect("reader completes");
        assert_eq!(
            seen.len(),
            2,
            "the parked read sees the change made while it waited"
        );
    }

    #[tokio::test]
    async fn dropping_the_handle_disarms_and_releases() {
        let point = Arc::new(test_pause::TestPause::default());
        let handle = point.arm();
        let waiter = {
            let point = Arc::clone(&point);
            zeroclaw_spawn::spawn!(async move { point.wait_if_armed(false).await })
        };
        handle.admitted().await;
        assert!(!handle.proof_was_held_at_pause());
        drop(handle);
        tokio::time::timeout(std::time::Duration::from_secs(2), waiter)
            .await
            .expect("dropping the handle releases the parked waiter")
            .expect("waiter task completes");
        // Disarmed: a second wait does not park.
        point.wait_if_armed(true).await;
    }
}
