//! Who is calling, and what that entitles them to.
//!
//! Launching a control transport creates a **requester** principal and nothing
//! upgrades it: not a TTY, not a loopback address, not the process parent, not
//! the OS account, not an environment variable. A requester becomes
//! *registered* only by presenting a credential minted by an operator
//! registration ceremony.
//!
//! # The two ways a [`RequesterGrant`] can exist, and why they cannot meet
//!
//! [`authenticate_client`] is the **production** path and the only one a
//! released build compiles. It reaches a grant only by reading this instance's
//! sealed, key-authenticated client registry and finding a record whose ADR-015
//! verifier reproduces over a presented secret. Nothing a caller supplies —
//! a config value, an environment value, a CLI flag, an MCP argument, a TTY, a
//! loopback address, the process parent, the OS account — participates in that
//! answer. Presenting a credential that does not verify is a
//! [`crate::protocol::StartupRefusal`], never an unregistered session:
//! downgrading would turn a revoked registration and a mistyped option into the
//! same silent symptom.
//!
//! [`RequesterGrant::fixture`] is the **test** path, kept for the phase-2 tests
//! that predate registration. It is compiled only under the `fixture-grants`
//! feature, which is enabled only by this workspace's `[dev-dependencies]`; it
//! is in no crate's default feature set and no released profile turns it on, so
//! `cargo build --release` compiles none of the code marked with it.
//!
//! The two share no constructor, no verifier, and no assurance vocabulary. A
//! production grant's class comes from
//! [`crate::client_registry::CredentialDelivery`], which has exactly two
//! variants and no way to spell the fixture's own class; the fixture's class is
//! a string literal that the delivery enum refuses to parse. That is a property
//! of the types rather than of a runtime check that could be misconfigured, and
//! it is the specification's fixture-contract point 7 — the production and
//! fixture verifier paths stay disjoint — expressed in the type system.
//!
//! The compile-out argument is about the build graph, so it is checked against
//! the artifact rather than trusted. `scripts/ci/control_fixture_absence_gate.sh`
//! builds the `zeroclaw` binary, asserts the fixture identifiers below are
//! absent from it, and asserts real control-plane strings are present so the
//! absence cannot pass vacuously on a wrong or empty file. CI runs it as the
//! required `Control Fixture Absence` job whenever this crate, the workspace
//! manifest, or the gate itself changes.

use std::collections::BTreeSet;
use std::path::Path;

use crate::client_registry::{
    self, ClientCredential, ClientRegistration, CredentialDelivery, RegistrationId,
};
use crate::genesis::{InstanceTrustState, classify};
use crate::keys::ApprovalAuditKey;
use crate::protocol::{
    ControlErrorCode, LOCAL_TARGET_ID, RegistrationHelpResult, StartupRefusal, StartupRefusalCode,
    ToolDescriptor, ToolGate,
};
use crate::registry_store;
use crate::store::ControlPaths;

/// Credential-delivery assurance classes an operator registration ceremony may
/// use.
///
/// Deliberately an allowlist, and no longer independently spelled: each entry
/// is a [`CredentialDelivery`] variant's own wire spelling, so the classes this
/// protocol advertises and the classes a registration can actually be created
/// under cannot drift apart by a typo. `CredentialDelivery` has no third
/// variant, which is what keeps `uid_ambient` and the fixture path's own class
/// out of this list structurally rather than by review.
pub const ACCEPTED_ASSURANCE_CLASSES: &[&str] = &[
    CredentialDelivery::IsolatedDescriptor.wire(),
    CredentialDelivery::SandboxIsolatedStore.wire(),
];

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
    /// The grant a verified [`ClientRegistration`] resolves to.
    ///
    /// The only production constructor, and the only one anywhere that a
    /// released build compiles. It takes the registration by reference rather
    /// than loose fields so the grant cannot be assembled with a wider domain
    /// set than the record carries, and it derives the assurance class from the
    /// record's typed [`CredentialDelivery`] rather than from a string, so the
    /// class a session reports is a class a registration could be created
    /// under.
    ///
    /// `target_id` becomes [`LOCAL_TARGET_ID`]. A phase-2 process pins one
    /// config root and can address no other instance, so the target registry
    /// degenerates to that constant on the wire; the caller has already
    /// established that the registration covers *this* instance's real
    /// identifier, which is the check that means anything.
    #[must_use]
    fn registered(registration: &ClientRegistration) -> Self {
        Self {
            assurance_class: registration.delivery_assurance.wire().to_string(),
            // Empty, never the fixture marker. In a fixture-enabled test build
            // the field still exists, and a production grant carrying the
            // marker would make the two paths indistinguishable; a disjointness
            // test below pins that it stays empty.
            #[cfg(feature = "fixture-grants")]
            credential_marker: String::new(),
            target_id: LOCAL_TARGET_ID.to_string(),
            read_domains: registration.granted_read_domains.clone(),
            proposal_domains: registration.proposal_domains.clone(),
        }
    }

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
    /// This exists only when the `fixture-grants` feature is on, and no
    /// released profile enables that feature. The other constructor,
    /// [`RequesterGrant::registered`], is private to this module and reachable
    /// only through [`authenticate_client`], which demands a verified
    /// registration. A shipped binary therefore has exactly one way to reach a
    /// grant-gated tool, and it runs through the client registry.
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

    /// A test-only grant covering every read domain and proposal domain v1
    /// defines.
    ///
    /// Reads `READ_DOMAINS_V1` rather than re-spelling a list, so "everything"
    /// keeps meaning everything when a domain is added. That constant is the
    /// six-member vocabulary — both Inspect views plus the four read-only tool
    /// names — and a grant holding all six is what makes every gated tool
    /// visible.
    ///
    /// # Test-only
    ///
    /// See [`RequesterGrant::fixture`].
    #[cfg(feature = "fixture-grants")]
    #[must_use]
    pub fn fixture_full() -> Self {
        Self::fixture(client_registry::READ_DOMAINS_V1, &[PROPOSAL_DOMAIN_AGENT])
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
/// [`ControlSession::Registered`] is inhabited only by [`authenticate_client`],
/// which reaches it only from a verified client registration, and by the
/// test-only fixture path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlSession {
    /// No registered client credential was presented.
    Unregistered,
    /// A registered requester with an explicit grant.
    Registered(RequesterGrant),
}

impl ControlSession {
    /// The session a launched control process gets when it presents no
    /// credential.
    ///
    /// Registration is an operator ceremony on the host; it is not something an
    /// MCP session can perform on itself. This constructor never *becomes*
    /// registered, and no failure elsewhere falls back to it — a launch that
    /// presented a credential either produces a registered session or refuses
    /// to serve.
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
    /// Absence is the primary control, and it is defined as *exactly* the
    /// negation of the refusal: a tool is listed when
    /// [`ControlSession::authorize_tool`] would let this session call it, and
    /// not otherwise. Deriving one from the other is deliberate — two
    /// independent predicates could drift, and a tool that is listed but
    /// refuses (or refuses but is listed) is precisely the confusion the
    /// specification's "absence is the primary control and the error is the
    /// backstop" rule exists to prevent.
    #[must_use]
    pub fn can_see(&self, tool: &ToolDescriptor) -> bool {
        self.authorize_tool(tool).is_ok()
    }

    /// The refusal a session gets for calling `tool` by name, if any.
    ///
    /// Registration is checked before the grant's contents, so an unregistered
    /// caller learns only that it is unregistered — never whether the target
    /// exists, whether a view is defined, or whether some other client is
    /// registered.
    ///
    /// A registered session that does not hold any of the tool's read domains
    /// gets [`ControlErrorCode::GrantRequired`]: authorization is an
    /// intersection, so a narrow registration reaches a narrow surface. That is
    /// the same code an ungranted *view* produces, which keeps an ungranted
    /// tool and an ungranted view indistinguishable from the outside.
    ///
    /// # Errors
    ///
    /// Returns [`ControlErrorCode::UnregisteredClient`] when the session holds
    /// no grant, and [`ControlErrorCode::GrantRequired`] when it holds one that
    /// covers none of `tool.required_read_domains`.
    pub fn authorize_tool(&self, tool: &ToolDescriptor) -> Result<(), ControlErrorCode> {
        match tool.gate {
            ToolGate::Always => Ok(()),
            ToolGate::RegisteredGrant => {
                let grant = self.grant().ok_or(ControlErrorCode::UnregisteredClient)?;
                if tool
                    .required_read_domains
                    .iter()
                    .any(|domain| grant.covers_read_domain(domain))
                {
                    Ok(())
                } else {
                    Err(ControlErrorCode::GrantRequired)
                }
            }
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

// ---------------------------------------------------------------------------
// Production client authentication
// ---------------------------------------------------------------------------

/// A verified registered client and the instance it was verified against.
///
/// The resolved [`ControlPaths`] travel with the session so a caller that needs
/// the same instance again — to take the host lock, say — uses the roots this
/// authentication actually ran against rather than resolving them a second time
/// and possibly getting a different answer.
#[derive(Debug, Clone)]
pub struct AuthenticatedClient {
    /// The registered session.
    pub session: ControlSession,
    /// The instance roots the registry was read from.
    pub paths: ControlPaths,
}

/// Verify a presented client credential and resolve the session it entitles.
///
/// This is the production counterpart of the fixture path, and it shares
/// nothing with it: no constructor, no type, no verifier. A fixture grant is
/// minted from string literals inside a test process; a registered session
/// exists only when a sealed, key-authenticated registry on this instance holds
/// a record whose ADR-015 verifier reproduces over the presented secret.
///
/// # The order of the checks, and why
///
/// 1. **Resolve the instance roots.** A root that is missing, not a directory,
///    or a symlink is [`StartupRefusalCode::InstanceNotManaged`]: a redirected
///    root is exactly the substitution the genesis record's root binding exists
///    to catch.
/// 2. **Classify the trust root.** Only [`InstanceTrustState::Managed`]
///    continues. Recovery-only and never-initialized both refuse, fused into
///    one code — see [`StartupRefusalCode`].
/// 3. **Derive the ADR-015 key at the record's epoch**, from the deployment's
///    single key-source authority. A failure here is not a rejected credential,
///    it is a host that cannot authenticate anything.
/// 4. **Intersect with target registration.** The signed target registry must
///    list this instance as operable. This runs before any credential is looked
///    at, because an instance that is not servable is not servable for anyone.
/// 5. **Load and re-validate the client registry.** A registry that is absent
///    reports as a rejected credential; a registry that is present but fails
///    its tag or its grant re-validation reports as
///    [`StartupRefusalCode::RegistryUnverifiable`], because a host whose sealed
///    state has been tampered with must say so loudly.
/// 6. **Look up the named registration**, then **authenticate the secret**.
///    Unknown identifier, wrong secret, revoked status, and a registration
///    issued under a superseded epoch are one code.
/// 7. **Only then, compare the delivery class.** Deliberately last of the
///    credential checks: a caller who cannot produce the secret must not be
///    able to learn which assurance class a real registration was created
///    under by probing.
/// 8. **Require the registration to cover this instance.** A record that grants
///    some other instance grants nothing here, because this process can address
///    no other instance.
///
/// # What this never does
///
/// It never consults a TTY, a loopback address, the process parent, the OS
/// account, or an environment *value*. It never widens a grant, never falls
/// back to an unregistered session, and never returns a partial result: every
/// branch is a session or a refusal.
///
/// # Errors
///
/// Returns a [`StartupRefusal`] whose text is fixed and carries no path, client
/// identifier, or presented value.
pub fn authenticate_client(
    install_root: &Path,
    client_id: &str,
    credential: &ClientCredential,
    presented_delivery: CredentialDelivery,
) -> Result<AuthenticatedClient, StartupRefusal> {
    let refuse = |code: StartupRefusalCode| StartupRefusal::new(code);

    let paths = ControlPaths::resolve(install_root)
        .map_err(|_| refuse(StartupRefusalCode::InstanceNotManaged))?;
    let key_source = paths.key_source();

    let record = match classify(&paths, &key_source) {
        InstanceTrustState::Managed(record) => record,
        InstanceTrustState::EligibleForFirstGenesis | InstanceTrustState::RecoveryOnly { .. } => {
            return Err(refuse(StartupRefusalCode::InstanceNotManaged));
        }
    };

    let key = ApprovalAuditKey::derive(&key_source, record.trust_epoch)
        .map_err(|_| refuse(StartupRefusalCode::RegistryUnverifiable))?;

    // Intersect with target registration before looking at any credential. An
    // instance whose signed target record is absent, revoked, or suspended is
    // not one this process may serve, whatever a client presents.
    let targets = registry_store::load(&paths, &key)
        .map_err(|_| refuse(StartupRefusalCode::RegistryUnverifiable))?;
    if targets.get_operable(&record.instance_id).is_none() {
        return Err(refuse(StartupRefusalCode::InstanceNotManaged));
    }

    let registry = client_registry::load(&paths, &key).map_err(|error| {
        use crate::client_registry::ClientRegistryErrorCode as Code;
        match error.code {
            // A host with no registry is indistinguishable from a host that has
            // one without this client. Anything else means the sealed state is
            // present and wrong, which an operator has to be told.
            Code::NotPresent => refuse(StartupRefusalCode::CredentialRejected),
            _ => refuse(StartupRefusalCode::RegistryUnverifiable),
        }
    })?;

    let registration_id = RegistrationId::new(client_id)
        .map_err(|_| refuse(StartupRefusalCode::CredentialRejected))?;
    let Some(registration) = registry.get(&registration_id) else {
        return Err(refuse(StartupRefusalCode::CredentialRejected));
    };

    // `authenticate` answers "is this the secret" and "may this record still
    // authenticate" together, so a revoked registration refuses even for the
    // correct credential. The epoch check is separate because a record carried
    // forward across a recovery would otherwise be judged only by a tag that a
    // re-derived key would already have failed; checking it explicitly means
    // the refusal does not depend on that coincidence.
    if registration.trust_epoch != record.trust_epoch
        || !registration.authenticate(credential, &key)
    {
        return Err(refuse(StartupRefusalCode::CredentialRejected));
    }

    if registration.delivery_assurance != presented_delivery {
        return Err(refuse(StartupRefusalCode::DeliveryClassMismatch));
    }

    if !registration.covers_instance(&record.instance_id) {
        return Err(refuse(StartupRefusalCode::CredentialRejected));
    }

    Ok(AuthenticatedClient {
        session: ControlSession::Registered(RequesterGrant::registered(registration)),
        paths,
    })
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
    use crate::client_registry::{
        ClientGrant, ClientLabel, ClientRegistry, IssuedRegistration, READ_DOMAINS_V1,
        RegistrationStatus,
    };
    use crate::genesis::{
        FirstOperatorIdentity, GenesisRecord, KeyCommitment, PresenceClass, generate_instance_id,
        now_unix_secs,
    };
    use crate::protocol::{
        LOCAL_TARGET_ID, TOOL_CATALOG, TOOL_DESCRIBE, TOOL_INSPECT, TOOL_PREVIEW, TOOL_VALIDATE,
        TOOLS, VIEW_AGENT_SUMMARY, VIEW_PROVIDER_ALIAS_LIST, tool,
    };
    use crate::registry::{GenesisDigest, InstanceId, TargetRecord, TargetRegistry, TrustEpoch};
    use std::collections::BTreeSet;
    use std::path::PathBuf;
    use zeroclaw_config::secrets::KeySource as _;

    // -- a real managed instance, built from the public durable-state API ----

    /// One initialized instance on disk: a sealed genesis record, a signed
    /// target registry naming it, and a deployment key source.
    ///
    /// Built from `genesis::write_record`, `registry_store`, and
    /// `client_registry` rather than by running `ceremony::run_genesis`,
    /// because the ceremony needs a `UserPresence` adapter and
    /// `PresenceAttestation` has no constructor outside `ceremony`. The durable
    /// state written here is the state that ceremony writes — the same records,
    /// through the same publishers, sealed under the same key.
    struct ManagedInstance {
        _temp: tempfile::TempDir,
        install_root: PathBuf,
        paths: ControlPaths,
        instance_id: InstanceId,
        genesis_digest: GenesisDigest,
    }

    impl ManagedInstance {
        fn new() -> Self {
            let temp = tempfile::tempdir().expect("temporary install root");
            let install_root = temp.path().join("install");
            std::fs::create_dir_all(install_root.join("data")).expect("create install root");
            let paths = ControlPaths::resolve(&install_root).expect("resolve control paths");

            let key_source = paths.key_source();
            key_source
                .initialize()
                .expect("initialize the deployment key");
            let key =
                ApprovalAuditKey::derive(&key_source, TrustEpoch::GENESIS).expect("derive the key");

            let instance_id = generate_instance_id().expect("instance id");
            let record = GenesisRecord {
                instance_id: instance_id.clone(),
                trust_epoch: TrustEpoch::GENESIS,
                canonical_roots: paths.canonical_roots().expect("canonical roots"),
                created_at_unix_secs: now_unix_secs().expect("clock"),
                user_presence_class: PresenceClass::Terminal,
                first_operator: FirstOperatorIdentity::new("operator").expect("operator"),
                host_key_commitment: KeyCommitment::compute(&key),
            };
            let genesis_digest =
                crate::genesis::write_record(&paths, &record, &key).expect("write genesis record");

            let target = TargetRecord::register(
                instance_id.clone(),
                paths.canonical_roots().expect("canonical roots"),
                None,
                TrustEpoch::GENESIS,
                genesis_digest,
            )
            .expect("target record");
            let mut targets = TargetRegistry::new();
            targets.insert(target).expect("insert target");
            registry_store::save_new(&paths, &targets, &key).expect("save target registry");

            Self {
                _temp: temp,
                install_root,
                paths,
                instance_id,
                genesis_digest,
            }
        }

        fn key(&self) -> ApprovalAuditKey {
            ApprovalAuditKey::derive(&self.paths.key_source(), TrustEpoch::GENESIS)
                .expect("derive the key")
        }

        /// Register one client and return its identifier and the one copy of
        /// its credential, in the delivery encoding the credential file uses.
        fn register(&self, grant: &ClientGrant) -> (RegistrationId, String) {
            let key = self.key();
            let issued: IssuedRegistration = ClientRegistration::issue(
                grant,
                TrustEpoch::GENESIS,
                now_unix_secs().expect("clock"),
                self.genesis_digest,
                PresenceClass::Terminal,
                &key,
            )
            .expect("issue a registration");
            let id = issued.registration.registration_id.clone();
            let secret = issued.credential.to_delivery_hex();
            self.save(|registry| {
                registry
                    .insert(issued.registration.clone())
                    .expect("insert the registration");
            });
            (id, secret)
        }

        /// Read the client registry, let `edit` change it, and write it back.
        fn save(&self, edit: impl FnOnce(&mut ClientRegistry)) {
            let key = self.key();
            let mut registry = if client_registry::is_present(&self.paths) {
                client_registry::load(&self.paths, &key).expect("load the client registry")
            } else {
                ClientRegistry::new()
            };
            edit(&mut registry);
            client_registry::save(&self.paths, &registry, &key).expect("save the client registry");
        }

        fn full_grant(&self, delivery: CredentialDelivery) -> ClientGrant {
            ClientGrant::full_v1(
                ClientLabel::new("component-client").expect("label"),
                delivery,
                self.instance_id.clone(),
            )
        }

        fn authenticate(
            &self,
            client_id: &str,
            secret: &str,
            delivery: CredentialDelivery,
        ) -> Result<AuthenticatedClient, StartupRefusal> {
            let credential = ClientCredential::from_delivery_hex(secret).expect("parse credential");
            authenticate_client(&self.install_root, client_id, &credential, delivery)
        }
    }

    fn refusal_code(
        result: Result<AuthenticatedClient, StartupRefusal>,
        what: &str,
    ) -> StartupRefusalCode {
        match result {
            Ok(_) => panic!("{what} must not authenticate"),
            Err(refusal) => refusal.code,
        }
    }

    // -- the production path ------------------------------------------------

    #[test]
    fn a_registered_client_resolves_to_a_grant_over_its_recorded_domains() {
        let instance = ManagedInstance::new();
        let (id, secret) =
            instance.register(&instance.full_grant(CredentialDelivery::IsolatedDescriptor));

        let authenticated = instance
            .authenticate(id.as_str(), &secret, CredentialDelivery::IsolatedDescriptor)
            .expect("the issued credential authenticates");
        let session = authenticated.session;
        assert!(session.is_registered());
        assert_eq!(session.registration_state(), "registered");

        let grant = session.grant().expect("a registered session holds a grant");
        assert_eq!(grant.assurance_class(), "isolated_descriptor");
        assert!(grant.covers_target(LOCAL_TARGET_ID));
        assert!(!grant.covers_target("inst-elsewhere"));
        for domain in READ_DOMAINS_V1 {
            assert!(
                grant.covers_read_domain(domain),
                "a full grant must cover {domain}"
            );
        }
        assert!(grant.covers_proposal_domain(PROPOSAL_DOMAIN_AGENT));

        let visible: Vec<&str> = TOOLS
            .iter()
            .filter(|entry| session.can_see(entry))
            .map(|entry| entry.name)
            .collect();
        // A full grant covers the `control.preview` read domain, which also
        // gates the three phase-5 tools' visibility. Their stronger
        // authorization (the proposal domain for request_apply, owner-scoping for
        // status and verify) and the mutations-enabled visibility gate live in
        // the transport, above `can_see`; at the grant level a full grant can see
        // all eleven.
        assert_eq!(
            visible,
            vec![
                "control.ping",
                "control.server_info",
                "control.registration_help",
                "control.catalog",
                "control.describe",
                "control.inspect",
                "control.validate",
                "control.preview",
                "control.request_apply",
                "control.status",
                "control.verify",
            ]
        );
    }

    #[test]
    fn a_narrow_registration_reaches_a_narrow_tool_surface() {
        let instance = ManagedInstance::new();
        let narrow = ClientGrant {
            client_label: ClientLabel::new("narrow").expect("label"),
            delivery_assurance: CredentialDelivery::SandboxIsolatedStore,
            granted_instances: [instance.instance_id.clone()].into_iter().collect(),
            granted_read_domains: [VIEW_AGENT_SUMMARY.to_string(), TOOL_CATALOG.to_string()]
                .into_iter()
                .collect(),
            proposal_domains: [PROPOSAL_DOMAIN_AGENT.to_string()].into_iter().collect(),
        };
        let (id, secret) = instance.register(&narrow);

        let session = instance
            .authenticate(
                id.as_str(),
                &secret,
                CredentialDelivery::SandboxIsolatedStore,
            )
            .expect("the issued credential authenticates")
            .session;

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
                "control.registration_help",
                "control.catalog",
                "control.inspect",
            ],
            "a registration granting two domains lists two gated tools"
        );

        for absent in [TOOL_DESCRIBE, TOOL_VALIDATE, TOOL_PREVIEW] {
            let entry = tool(absent).expect("registry entry");
            assert!(!session.can_see(entry), "{absent} must not be listed");
            assert_eq!(
                session.authorize_tool(entry),
                Err(ControlErrorCode::GrantRequired),
                "{absent} must refuse a registered caller that does not hold it"
            );
        }
        // The tool it does hold still filters views inside itself.
        let inspect = tool(TOOL_INSPECT).expect("registry entry");
        assert_eq!(session.authorize_tool(inspect), Ok(()));
        assert_eq!(session.authorize_read_domain(VIEW_AGENT_SUMMARY), Ok(()));
        assert_eq!(
            session.authorize_read_domain(VIEW_PROVIDER_ALIAS_LIST),
            Err(ControlErrorCode::GrantRequired)
        );
    }

    #[test]
    fn every_way_a_credential_can_fail_is_a_refusal_and_never_a_downgrade() {
        let instance = ManagedInstance::new();
        let (id, secret) =
            instance.register(&instance.full_grant(CredentialDelivery::IsolatedDescriptor));

        // A different 32-byte secret.
        let other = ClientCredential::issue().expect("issue").to_delivery_hex();
        assert_eq!(
            refusal_code(
                instance.authenticate(id.as_str(), &other, CredentialDelivery::IsolatedDescriptor),
                "a wrong secret",
            ),
            StartupRefusalCode::CredentialRejected
        );

        // One flipped bit.
        let mut near_miss = secret.clone().into_bytes();
        near_miss[0] = if near_miss[0] == b'0' { b'1' } else { b'0' };
        let near_miss = String::from_utf8(near_miss).expect("hex stays ASCII");
        assert_eq!(
            refusal_code(
                instance.authenticate(
                    id.as_str(),
                    &near_miss,
                    CredentialDelivery::IsolatedDescriptor
                ),
                "a near-miss secret",
            ),
            StartupRefusalCode::CredentialRejected
        );

        // A client identifier no registration carries, and one that is not even
        // a well-formed identifier. Both are the same refusal, so probing
        // cannot enumerate registrations.
        for unknown in ["reg-0000000000000000", "not/an/id"] {
            assert_eq!(
                refusal_code(
                    instance.authenticate(unknown, &secret, CredentialDelivery::IsolatedDescriptor),
                    "an unknown client identifier",
                ),
                StartupRefusalCode::CredentialRejected
            );
        }

        // The right secret through the wrong mechanism.
        assert_eq!(
            refusal_code(
                instance.authenticate(
                    id.as_str(),
                    &secret,
                    CredentialDelivery::SandboxIsolatedStore
                ),
                "a delivery-class mismatch",
            ),
            StartupRefusalCode::DeliveryClassMismatch
        );

        // And the correct presentation still works, so none of the above passed
        // for the wrong reason.
        assert!(
            instance
                .authenticate(id.as_str(), &secret, CredentialDelivery::IsolatedDescriptor)
                .is_ok()
        );
    }

    #[test]
    fn a_revoked_registration_refuses_its_own_credential() {
        let instance = ManagedInstance::new();
        let (id, secret) =
            instance.register(&instance.full_grant(CredentialDelivery::IsolatedDescriptor));
        assert!(
            instance
                .authenticate(id.as_str(), &secret, CredentialDelivery::IsolatedDescriptor)
                .is_ok()
        );

        instance.save(|registry| {
            let mut revoked = registry.get(&id).expect("the registration").clone();
            revoked.status = RegistrationStatus::Revoked;
            *registry = {
                let mut replacement = ClientRegistry::new();
                replacement.insert(revoked).expect("insert");
                replacement
            };
        });

        assert_eq!(
            refusal_code(
                instance.authenticate(id.as_str(), &secret, CredentialDelivery::IsolatedDescriptor),
                "a revoked registration",
            ),
            StartupRefusalCode::CredentialRejected,
            "revocation fails closed, and looks exactly like a wrong secret"
        );
    }

    #[test]
    fn a_registration_that_covers_another_instance_grants_nothing_here() {
        let instance = ManagedInstance::new();
        let elsewhere = ClientGrant {
            client_label: ClientLabel::new("elsewhere").expect("label"),
            delivery_assurance: CredentialDelivery::IsolatedDescriptor,
            granted_instances: [InstanceId::new("inst-elsewhere").expect("id")]
                .into_iter()
                .collect(),
            granted_read_domains: READ_DOMAINS_V1.iter().map(|d| (*d).to_string()).collect(),
            proposal_domains: BTreeSet::new(),
        };
        let (id, secret) = instance.register(&elsewhere);

        assert_eq!(
            refusal_code(
                instance.authenticate(id.as_str(), &secret, CredentialDelivery::IsolatedDescriptor),
                "a registration over another instance",
            ),
            StartupRefusalCode::CredentialRejected
        );
    }

    #[test]
    fn an_uninitialized_or_unverifiable_instance_authenticates_nobody() {
        // No genesis record at all.
        let bare = tempfile::tempdir().expect("temporary install root");
        let root = bare.path().join("install");
        std::fs::create_dir_all(root.join("data")).expect("create install root");
        let credential = ClientCredential::issue().expect("issue");
        assert_eq!(
            refusal_code(
                authenticate_client(
                    &root,
                    "reg-0000000000000000",
                    &credential,
                    CredentialDelivery::IsolatedDescriptor,
                ),
                "an instance that never ran genesis",
            ),
            StartupRefusalCode::InstanceNotManaged
        );

        // A root that does not exist is the same refusal, and discloses no more.
        assert_eq!(
            refusal_code(
                authenticate_client(
                    &bare.path().join("absent"),
                    "reg-0000000000000000",
                    &credential,
                    CredentialDelivery::IsolatedDescriptor,
                ),
                "a root that does not exist",
            ),
            StartupRefusalCode::InstanceNotManaged
        );

        // A managed instance with no client registry looks exactly like one
        // whose registry does not hold this client.
        let instance = ManagedInstance::new();
        assert_eq!(
            refusal_code(
                instance.authenticate(
                    "reg-0000000000000000",
                    &credential.to_delivery_hex(),
                    CredentialDelivery::IsolatedDescriptor,
                ),
                "a managed instance with no client registry",
            ),
            StartupRefusalCode::CredentialRejected
        );

        // A registry that is present but does not authenticate is loud.
        let (id, secret) =
            instance.register(&instance.full_grant(CredentialDelivery::IsolatedDescriptor));
        let path = instance.paths.client_registry();
        let mut sealed = std::fs::read(&path).expect("read the client registry");
        let last = sealed.len() - 1;
        sealed[last] ^= 0x01;
        std::fs::write(&path, &sealed).expect("write the tampered registry");
        assert_eq!(
            refusal_code(
                instance.authenticate(id.as_str(), &secret, CredentialDelivery::IsolatedDescriptor),
                "a tampered client registry",
            ),
            StartupRefusalCode::RegistryUnverifiable
        );
    }

    #[test]
    fn a_startup_refusal_carries_fixed_text_and_no_host_detail() {
        for code in StartupRefusalCode::ALL {
            let refusal = StartupRefusal::new(code);
            assert_eq!(refusal.message, code.message());
            assert!(
                !refusal.message.contains('/') && !refusal.message.contains('\\'),
                "{} carries a path separator",
                code.as_str()
            );
            let rendered = serde_json::to_string(&refusal).expect("serializes");
            assert!(rendered.contains(code.as_str()));
        }
        assert!(!StartupRefusalCode::CredentialRejected.retryable());
        assert!(StartupRefusalCode::HostAlreadyServing.retryable());
    }

    /// Spec point 7, extended to the production path this phase adds: the
    /// production registration path and the fixture path share no verifier, no
    /// constructor, and no assurance vocabulary.
    #[test]
    fn the_production_registration_path_and_the_fixture_path_stay_disjoint() {
        // 1. The classes a production session can report are exactly the two
        //    the delivery enum defines, and the enum has no third variant.
        assert_eq!(
            ACCEPTED_ASSURANCE_CLASSES,
            CredentialDelivery::ALL
                .iter()
                .map(|class| class.wire())
                .collect::<Vec<_>>()
                .as_slice(),
        );
        for rejected in REJECTED_ASSURANCE_CLASSES {
            assert!(CredentialDelivery::from_wire(rejected).is_none());
        }

        // 2. `authenticate_client` takes a `CredentialDelivery` by value, so no
        //    caller can name a class outside that enum. The only classes a
        //    real session can carry are therefore these two.
        let instance = ManagedInstance::new();
        for delivery in CredentialDelivery::ALL.iter().copied() {
            let grant = instance.full_grant(delivery);
            let (id, secret) = instance.register(&grant);
            let session = instance
                .authenticate(id.as_str(), &secret, delivery)
                .expect("the issued credential authenticates")
                .session;
            let class = session
                .grant()
                .expect("a registered session holds a grant")
                .assurance_class()
                .to_string();
            assert_eq!(class, delivery.wire());
            assert!(
                ACCEPTED_ASSURANCE_CLASSES.contains(&class.as_str()),
                "a production session reported an unacceptable class"
            );
            assert!(
                CredentialDelivery::from_wire(&class).is_some(),
                "a production session's class must round-trip through the enum"
            );
        }
    }

    /// The half of spec point 7 that only a fixture build can check.
    #[cfg(feature = "fixture-grants")]
    #[test]
    fn a_production_grant_never_carries_the_fixture_marker() {
        let instance = ManagedInstance::new();
        let (id, secret) =
            instance.register(&instance.full_grant(CredentialDelivery::IsolatedDescriptor));
        let session = instance
            .authenticate(id.as_str(), &secret, CredentialDelivery::IsolatedDescriptor)
            .expect("authenticates")
            .session;
        let grant = session.grant().expect("grant");
        assert_eq!(
            grant.credential_marker(),
            "",
            "a production grant must not carry the fixture marker"
        );
        assert_ne!(grant.assurance_class(), FIXTURE_ASSURANCE_CLASS);
        assert_ne!(
            RequesterGrant::fixture_full().assurance_class(),
            grant.assurance_class(),
            "the two paths must not converge on one class"
        );
    }

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
