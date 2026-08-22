//! Who is calling, and what that entitles them to.
//!
//! Launching a control transport creates a **requester** principal and nothing
//! upgrades it: not a TTY, not a loopback address, not the process parent, not
//! the OS account, not an environment variable. A requester becomes
//! *registered* only by presenting a credential minted by an operator
//! registration ceremony.
//!
//! That ceremony is phase 3 work and does not exist yet, which is why
//! [`RequesterGrant`] has **no constructor outside the `fixture-grants`
//! feature**. In any build that a user could install, the only inhabited
//! session is [`ControlSession::Unregistered`], so every grant-gated tool is
//! absent from the tool list and refuses when called by name. That is a
//! property of the type, not of a runtime check that could be misconfigured:
//! there is no config value, environment variable, CLI flag, MCP argument, or
//! file on disk that can produce a grant, because nothing in a default build
//! can produce the value a grant is made of.
//!
//! The `fixture-grants` feature is enabled only by this workspace's
//! `[dev-dependencies]`. It is not in any crate's default feature set and no
//! released profile turns it on, so `cargo build --release` compiles none of
//! the code below that is marked with it.
//!
//! That argument is about the build graph, so it is checked against the
//! artifact rather than trusted. `scripts/ci/control_fixture_absence_gate.sh`
//! builds the `zeroclaw` binary, asserts the fixture identifiers below are
//! absent from it, and asserts real control-plane strings are present so the
//! absence cannot pass vacuously on a wrong or empty file. CI runs it as the
//! required `Control Fixture Absence` job whenever this crate, the workspace
//! manifest, or the gate itself changes.

use std::collections::BTreeSet;

use crate::protocol::{ControlErrorCode, RegistrationHelpResult, ToolDescriptor, ToolGate};

/// Credential-delivery assurance classes an operator registration ceremony may
/// use.
///
/// Deliberately an allowlist. `test_only` is not a member and must never
/// become one: the fixture path in this module is replaced by phase 3
/// registration, not extended by it.
pub const ACCEPTED_ASSURANCE_CLASSES: &[&str] = &["isolated_descriptor", "sandbox_isolated_store"];

/// Assurance classes an operator registration ceremony refuses.
pub const REJECTED_ASSURANCE_CLASSES: &[&str] = &["uid_ambient"];

/// The proposal domain the one v1 operation belongs to.
pub const PROPOSAL_DOMAIN_AGENT: &str = "agent";

/// The assurance class a fixture credential carries.
///
/// Compiled only under `fixture-grants`, so this string is absent from a
/// release artifact. `scripts/ci/control_fixture_absence_gate.sh` searches a
/// built binary for it and fails when it is present.
#[cfg(feature = "fixture-grants")]
pub const FIXTURE_ASSURANCE_CLASS: &str = "test_only";

/// A unique, greppable marker proving fixture code is or is not linked.
///
/// It is stored in every fixture grant rather than merely declared, so a build
/// that compiles the fixture path necessarily contains this string and a build
/// that does not, necessarily does not.
#[cfg(feature = "fixture-grants")]
pub const FIXTURE_CREDENTIAL_MARKER: &str = "zeroclaw-control-fixture-grant-test-only-do-not-ship";

/// What a registered requester is entitled to.
///
/// A grant names explicit instances, read domains, and proposal domains. It
/// never grants approval authority, and there is no operation in this protocol
/// version that could consume approval authority if it did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequesterGrant {
    assurance_class: String,
    /// Only a fixture grant carries a credential marker, and only a build that
    /// compiles the fixture path has anywhere to put one.
    #[cfg(feature = "fixture-grants")]
    credential_marker: String,
    target_id: String,
    read_domains: BTreeSet<String>,
    proposal_domains: BTreeSet<String>,
}

impl RequesterGrant {
    /// The credential-delivery assurance class this grant was issued under.
    #[must_use]
    pub fn assurance_class(&self) -> &str {
        &self.assurance_class
    }

    /// Whether this grant covers `target_id`.
    #[must_use]
    pub fn covers_target(&self, target_id: &str) -> bool {
        self.target_id == target_id
    }

    /// Whether this grant covers the read domain `view`.
    #[must_use]
    pub fn covers_read_domain(&self, view: &str) -> bool {
        self.read_domains.contains(view)
    }

    /// Whether this grant covers the proposal domain `domain`.
    #[must_use]
    pub fn covers_proposal_domain(&self, domain: &str) -> bool {
        self.proposal_domains.contains(domain)
    }

    /// A test-only grant over the pinned local instance.
    ///
    /// # Test-only
    ///
    /// This is the sole constructor of a [`RequesterGrant`] anywhere in the
    /// workspace, and it exists only when the `fixture-grants` feature is on.
    /// No released profile enables that feature, so a shipped binary contains
    /// no way to construct this type and therefore no way to reach a
    /// grant-gated tool.
    #[cfg(feature = "fixture-grants")]
    #[must_use]
    pub fn fixture(read_domains: &[&str], proposal_domains: &[&str]) -> Self {
        Self {
            assurance_class: FIXTURE_ASSURANCE_CLASS.to_string(),
            credential_marker: FIXTURE_CREDENTIAL_MARKER.to_string(),
            target_id: crate::protocol::LOCAL_TARGET_ID.to_string(),
            read_domains: read_domains
                .iter()
                .map(|domain| (*domain).to_string())
                .collect(),
            proposal_domains: proposal_domains
                .iter()
                .map(|domain| (*domain).to_string())
                .collect(),
        }
    }

    /// A test-only grant covering every read view and proposal domain v1
    /// defines.
    ///
    /// # Test-only
    ///
    /// See [`RequesterGrant::fixture`].
    #[cfg(feature = "fixture-grants")]
    #[must_use]
    pub fn fixture_full() -> Self {
        Self::fixture(crate::protocol::VIEWS, &[PROPOSAL_DOMAIN_AGENT])
    }

    /// The marker proving this grant came from the fixture path.
    ///
    /// # Test-only
    #[cfg(feature = "fixture-grants")]
    #[must_use]
    pub fn credential_marker(&self) -> &str {
        &self.credential_marker
    }
}

/// One control session's principal state.
///
/// [`ControlSession::Registered`] is uninhabited in a released build because
/// [`RequesterGrant`] has no constructor there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlSession {
    /// No registered client credential was presented.
    Unregistered,
    /// A registered requester with an explicit grant.
    Registered(RequesterGrant),
}

impl ControlSession {
    /// The session every launched control process starts in.
    ///
    /// This is the only session constructor reachable from production code, and
    /// the transport calls nothing else. Registration is an operator ceremony
    /// on the host; it is not something an MCP session can perform on itself.
    #[must_use]
    pub fn unregistered() -> Self {
        Self::Unregistered
    }

    /// A session holding a test-only fixture grant.
    ///
    /// # Test-only
    ///
    /// Compiled only under `fixture-grants`. See [`RequesterGrant::fixture`].
    #[cfg(feature = "fixture-grants")]
    #[must_use]
    pub fn fixture_granted(grant: RequesterGrant) -> Self {
        Self::Registered(grant)
    }

    /// Whether this session presented a registered client credential.
    #[must_use]
    pub fn is_registered(&self) -> bool {
        matches!(self, Self::Registered(_))
    }

    /// The grant this session holds, if it is registered.
    #[must_use]
    pub fn grant(&self) -> Option<&RequesterGrant> {
        match self {
            Self::Unregistered => None,
            Self::Registered(grant) => Some(grant),
        }
    }

    /// The wire spelling of this session's registration state.
    #[must_use]
    pub fn registration_state(&self) -> &'static str {
        if self.is_registered() {
            "registered"
        } else {
            "unregistered"
        }
    }

    /// Whether `tool` appears in this session's `tools/list`.
    ///
    /// Absence is the primary control. A grant-gated tool is not listed for an
    /// unregistered session at all, and calling it by name is refused
    /// separately by [`ControlSession::authorize_tool`].
    #[must_use]
    pub fn can_see(&self, tool: &ToolDescriptor) -> bool {
        match tool.gate {
            ToolGate::Always => true,
            ToolGate::RegisteredGrant => self.is_registered(),
        }
    }

    /// The refusal a session gets for calling `tool` by name, if any.
    ///
    /// Registration is checked before anything else, so an unregistered caller
    /// learns only that it is unregistered — never whether the target exists,
    /// whether a view is defined, or whether some other client is registered.
    ///
    /// # Errors
    ///
    /// Returns [`ControlErrorCode::UnregisteredClient`] when the session holds
    /// no grant.
    pub fn authorize_tool(&self, tool: &ToolDescriptor) -> Result<(), ControlErrorCode> {
        match tool.gate {
            ToolGate::Always => Ok(()),
            ToolGate::RegisteredGrant if self.is_registered() => Ok(()),
            ToolGate::RegisteredGrant => Err(ControlErrorCode::UnregisteredClient),
        }
    }

    /// The refusal for addressing `target_id`, if any.
    ///
    /// # Errors
    ///
    /// Returns [`ControlErrorCode::UnregisteredClient`] when the session holds
    /// no grant and [`ControlErrorCode::TargetNotRegistered`] when the grant
    /// does not cover the requested instance.
    pub fn authorize_target(&self, target_id: &str) -> Result<(), ControlErrorCode> {
        let grant = self.grant().ok_or(ControlErrorCode::UnregisteredClient)?;
        if grant.covers_target(target_id) {
            Ok(())
        } else {
            Err(ControlErrorCode::TargetNotRegistered)
        }
    }

    /// The refusal for resolving the read domain `view`, if any.
    ///
    /// A view this protocol version does not define and a view the grant does
    /// not cover produce the same code on purpose: a narrow client must not be
    /// able to enumerate the wider surface by probing.
    ///
    /// # Errors
    ///
    /// Returns [`ControlErrorCode::UnregisteredClient`] when the session holds
    /// no grant and [`ControlErrorCode::GrantRequired`] when the grant does not
    /// cover the view.
    pub fn authorize_read_domain(&self, view: &str) -> Result<(), ControlErrorCode> {
        let grant = self.grant().ok_or(ControlErrorCode::UnregisteredClient)?;
        if grant.covers_read_domain(view) {
            Ok(())
        } else {
            Err(ControlErrorCode::GrantRequired)
        }
    }

    /// The refusal for proposing into `domain`, if any.
    ///
    /// # Errors
    ///
    /// Returns [`ControlErrorCode::UnregisteredClient`] when the session holds
    /// no grant and [`ControlErrorCode::GrantRequired`] when the grant does not
    /// cover the proposal domain.
    pub fn authorize_proposal_domain(&self, domain: &str) -> Result<(), ControlErrorCode> {
        let grant = self.grant().ok_or(ControlErrorCode::UnregisteredClient)?;
        if grant.covers_proposal_domain(domain) {
            Ok(())
        } else {
            Err(ControlErrorCode::GrantRequired)
        }
    }
}

/// The static operator guidance `control.registration_help` returns.
///
/// Generated from the constants above rather than maintained in a skill or a
/// prompt, and containing no token, nonce, challenge, path, or callback a model
/// could complete.
#[must_use]
pub fn registration_help(session: &ControlSession) -> RegistrationHelpResult {
    RegistrationHelpResult {
        registration_state: session.registration_state().to_string(),
        registration_is_meta_authority: true,
        accepted_assurance_classes: ACCEPTED_ASSURANCE_CLASSES
            .iter()
            .map(|class| (*class).to_string())
            .collect(),
        rejected_assurance_classes: REJECTED_ASSURANCE_CLASSES
            .iter()
            .map(|class| (*class).to_string())
            .collect(),
        operator_steps: vec![
            "Registration is performed by an operator on the host, not through this MCP session."
                .to_string(),
            "The operator selects a credential delivery mechanism in an accepted assurance class."
                .to_string(),
            "The operator grants explicit instances, read domains, and proposal domains."
                .to_string(),
            "Registration never grants approval authority.".to_string(),
        ],
        documentation: "docs/book/src/architecture/control-plane-principals-and-approvals.md"
            .to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{LOCAL_TARGET_ID, TOOLS, VIEW_AGENT_SUMMARY, tool};

    #[test]
    fn an_unregistered_session_sees_only_the_always_available_tools() {
        let session = ControlSession::unregistered();
        assert!(!session.is_registered());
        assert!(session.grant().is_none());
        assert_eq!(session.registration_state(), "unregistered");

        let visible: Vec<&str> = TOOLS
            .iter()
            .filter(|entry| session.can_see(entry))
            .map(|entry| entry.name)
            .collect();
        assert_eq!(
            visible,
            vec![
                "control.ping",
                "control.server_info",
                "control.registration_help"
            ]
        );

        for name in [
            "control.catalog",
            "control.describe",
            "control.inspect",
            "control.validate",
            "control.preview",
        ] {
            let entry = tool(name).expect("registry entry");
            assert!(!session.can_see(entry), "{name} must not be listed");
            assert_eq!(
                session.authorize_tool(entry),
                Err(ControlErrorCode::UnregisteredClient),
                "{name} must refuse an unregistered caller"
            );
        }
    }

    #[test]
    fn an_unregistered_session_learns_nothing_from_target_or_view_probing() {
        let session = ControlSession::unregistered();
        assert_eq!(
            session.authorize_target(LOCAL_TARGET_ID),
            Err(ControlErrorCode::UnregisteredClient)
        );
        assert_eq!(
            session.authorize_target("some-other-instance"),
            Err(ControlErrorCode::UnregisteredClient),
            "a real and an invented target must be indistinguishable"
        );
        assert_eq!(
            session.authorize_read_domain(VIEW_AGENT_SUMMARY),
            Err(ControlErrorCode::UnregisteredClient)
        );
        assert_eq!(
            session.authorize_proposal_domain(PROPOSAL_DOMAIN_AGENT),
            Err(ControlErrorCode::UnregisteredClient)
        );
    }

    #[test]
    fn the_fixture_assurance_class_is_not_acceptable_to_a_production_ceremony() {
        assert!(
            !ACCEPTED_ASSURANCE_CLASSES.contains(&"test_only"),
            "phase 3 registration replaces the fixture path; it must not extend it"
        );
        assert_eq!(
            ACCEPTED_ASSURANCE_CLASSES,
            &["isolated_descriptor", "sandbox_isolated_store"]
        );
        assert_eq!(REJECTED_ASSURANCE_CLASSES, &["uid_ambient"]);
    }

    #[cfg(feature = "fixture-grants")]
    #[test]
    fn a_narrow_fixture_grant_refuses_the_domains_it_does_not_cover() {
        use crate::protocol::{VIEW_PROVIDER_ALIAS_LIST, VIEWS};

        let session = ControlSession::fixture_granted(RequesterGrant::fixture(
            &[VIEW_AGENT_SUMMARY],
            &[PROPOSAL_DOMAIN_AGENT],
        ));
        assert!(session.is_registered());
        assert_eq!(session.registration_state(), "registered");
        assert_eq!(session.authorize_read_domain(VIEW_AGENT_SUMMARY), Ok(()));
        assert_eq!(
            session.authorize_read_domain(VIEW_PROVIDER_ALIAS_LIST),
            Err(ControlErrorCode::GrantRequired),
            "a grant is an allowlist, not a switch"
        );
        assert_eq!(
            session.authorize_read_domain("agent.secrets"),
            Err(ControlErrorCode::GrantRequired),
            "an undefined view and an ungranted view must be indistinguishable"
        );
        assert_eq!(session.authorize_target(LOCAL_TARGET_ID), Ok(()));
        assert_eq!(
            session.authorize_target("inst_other"),
            Err(ControlErrorCode::TargetNotRegistered)
        );

        let narrow = ControlSession::fixture_granted(RequesterGrant::fixture(VIEWS, &[]));
        assert_eq!(
            narrow.authorize_proposal_domain(PROPOSAL_DOMAIN_AGENT),
            Err(ControlErrorCode::GrantRequired)
        );
    }

    #[cfg(feature = "fixture-grants")]
    #[test]
    fn a_fixture_grant_is_labelled_test_only_and_carries_the_ship_marker() {
        let grant = RequesterGrant::fixture_full();
        assert_eq!(grant.assurance_class(), "test_only");
        assert_eq!(
            grant.credential_marker(),
            "zeroclaw-control-fixture-grant-test-only-do-not-ship"
        );
    }
}
