//! Client registration records and one-time credential issuance.
//!
//! A registered external client presents a credential minted by an operator
//! registration ceremony. The credential identifies a client and grants
//! explicit instances, read domains, and proposal domains. **It never grants
//! approval**, and there is no field on [`ClientRegistration`] whose value
//! could: `approval_authority` is structurally absent, exactly as the
//! principals design requires.
//!
//! ## Only a verifier is stored
//!
//! The credential is 32 bytes from the operating system random source, handed
//! to the operator exactly once at registration. What persists is
//! [`CredentialVerifier`] — an ADR-015 tag over the label, the registration id,
//! and the secret.
//!
//! A plain digest would also resist a dictionary attack against 32 random
//! bytes, so that is not the reason for a keyed verifier. Two other properties
//! are:
//!
//! - **No offline verification.** An attacker who reads `clients.json` cannot
//!   test a guessed credential at all without also holding the deployment key.
//!   With a plain hash they could test guesses freely; the entropy makes that
//!   futile *today*, but it stops being an argument the moment a future
//!   ceremony accepts an operator-chosen credential.
//! - **The verifier is deployment-bound.** A stolen `clients.json` cannot be
//!   replanted on another host, because the verifier only reproduces under the
//!   key derived from *this* deployment's key-source authority.
//!
//! The registration id is inside the tag, so a verifier lifted from one record
//! and pasted into another does not authenticate.
//!
//! ## The secret never reaches argv, an environment variable, or a log
//!
//! [`ClientCredential`] has no `Serialize`, no `Display`, and a redacted
//! `Debug`. It is generated in-process, written once through
//! [`write_credential_file`] to an owner-only file that must not already
//! exist, and dropped. Nothing in this module reads or sets an environment
//! variable, and no code path passes the secret to a subprocess. The *path* of
//! the credential file comes from the operator's command line; its contents
//! never do.
//!
//! ## Receipt exemption, precisely bounded
//!
//! Registration is a meta-authority operation and normally consumes an approval
//! receipt issued under the existing trust epoch. The receipt broker is phase
//! 4. [ADR-016] decides that the genesis and mutation-enablement ceremony may
//! register the first client or clients receipt-exempt, and that the exception
//! closes the moment mutation enablement completes.
//!
//! Every registration this crate can create carries the presence class of the
//! ceremony that made it ([`ClientRegistration::ceremony_presence_class`]) and
//! anchors to the genesis record digest rather than to a receipt
//! ([`ClientRegistration::created_by_genesis_digest`]), which is what ADR-016
//! requires of a bootstrap registration. Mutation enablement does not exist in
//! this phase and cannot be reached from it, so the bootstrap window has not
//! closed; whoever implements enablement must close it, and there is no
//! non-ceremony registration path here for them to have to remove.
//!
//! [ADR-016]: ../../../docs/book/src/architecture/decisions/ADR-016-control-plane-registration-bootstrap.md
//!
//! ## What this module deliberately does not model
//!
//! The principals design lists more registration-record fields than exist here.
//! Each omission is because the machinery that would give the field meaning is
//! not in this phase, and a field nothing maintains is worse than no field:
//!
//! - `delivery_mechanism` — there is no approved credential-helper registry to
//!   name, and no inherited-descriptor contract to reference.
//! - `rotation_generation` — credential rotation is a meta-authority operation
//!   that needs the phase-4 receipt broker.
//! - `not_after` — expiry needs the journal design's clock rules.
//! - `reachability_evaluation` — the assurance-collapse re-evaluation needs
//!   sandbox policy digests and an enumeration of reachable principals.
//! - `audit_anchor` — there is no audit chain yet.
//! - a `suspended` status — [`RegistrationStatus`] has `Active` and `Revoked`
//!   only, and revocation beyond the flag is out of scope.

use std::collections::BTreeSet;
use std::collections::btree_map::{BTreeMap, Entry};
use std::path::Path;

use serde::{Deserialize, Serialize};
use zeroclaw_config::secrets::KeySource;

use crate::genesis::PresenceClass;
use crate::keys::{ApprovalAuditKey, Tag};
use crate::protocol::{
    TOOL_CATALOG, TOOL_DESCRIBE, TOOL_PREVIEW, TOOL_VALIDATE, VIEW_AGENT_SUMMARY,
    VIEW_PROVIDER_ALIAS_LIST,
};
use crate::registry::{GenesisDigest, InstanceId, TrustEpoch};
use crate::store::{
    CanonicalBytes, ControlPaths, StoreError, StoreErrorCode, absorb_field, absorb_str, absorb_u64,
    open_sealed, os_random_32, publish_new, publish_replace, read_optional, seal,
};

/// Domain-separation label for the client registry file.
pub const CLIENT_REGISTRY_DOMAIN: &str = "zeroclaw/control-plane/client-registry/v1";

/// The only client-registry encoding this build understands.
pub const CLIENT_REGISTRY_FORMAT_VERSION: u32 = 1;

/// Domain-separation label for a credential verifier.
///
/// Separate from the registry's own label so a verifier tag and a file tag can
/// never be confused for one another.
pub const CLIENT_CREDENTIAL_LABEL: &str = "zeroclaw/control-plane/client-credential/v1";

/// The read domains v1 defines.
///
/// The two Inspect views plus the four read-only tool domains. Built from the
/// protocol's own constants rather than re-spelled, so a protocol rename cannot
/// leave a grant naming a domain that no longer exists.
pub const READ_DOMAINS_V1: &[&str] = &[
    VIEW_AGENT_SUMMARY,
    VIEW_PROVIDER_ALIAS_LIST,
    TOOL_CATALOG,
    TOOL_DESCRIBE,
    TOOL_VALIDATE,
    TOOL_PREVIEW,
];

/// The proposal domains v1 defines.
///
/// Recorded on a registration and **inert**: no operation in this phase
/// consumes a proposal domain, because there is no mutation surface for a
/// proposal to target. They are recorded now so the grant a client is issued
/// does not have to change when the surface arrives.
pub const PROPOSAL_DOMAINS_V1: &[&str] = &[crate::principal::PROPOSAL_DOMAIN_AGENT];

/// Upper bound on a client display label.
const MAX_CLIENT_LABEL_LEN: usize = 96;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Why a client registration was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientRegistryErrorCode {
    /// A client label was empty, over-long, or held a control character.
    InvalidClientLabel,
    /// A registration id was malformed.
    InvalidRegistrationId,
    /// A granted read domain is not one v1 defines.
    UnknownReadDomain,
    /// A granted proposal domain is not one v1 defines.
    UnknownProposalDomain,
    /// A registration granted no instance, so it could reach nothing.
    NoGrantedInstance,
    /// The registration id is already present.
    DuplicateRegistration,
    /// No client registry file exists at the fixed path.
    NotPresent,
    /// The file could not be read, parsed, or authenticated.
    Unverifiable,
    /// The registry could not be written.
    NotWritten,
    /// The credential could not be minted or delivered.
    CredentialNotIssued,
    /// The requested credential path is inside an agent workspace root.
    CredentialPathInsideWorkspace,
}

/// A client registration failure.
///
/// `detail` never carries credential bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientRegistryError {
    pub code: ClientRegistryErrorCode,
    pub detail: String,
}

impl ClientRegistryError {
    fn new(code: ClientRegistryErrorCode, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }
}

impl std::fmt::Display for ClientRegistryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let what = match self.code {
            ClientRegistryErrorCode::InvalidClientLabel => "invalid client label",
            ClientRegistryErrorCode::InvalidRegistrationId => "invalid registration id",
            ClientRegistryErrorCode::UnknownReadDomain => "unknown read domain",
            ClientRegistryErrorCode::UnknownProposalDomain => "unknown proposal domain",
            ClientRegistryErrorCode::NoGrantedInstance => "registration grants no instance",
            ClientRegistryErrorCode::DuplicateRegistration => "registration id already present",
            ClientRegistryErrorCode::NotPresent => "no client registry",
            ClientRegistryErrorCode::Unverifiable => "client registry could not be verified",
            ClientRegistryErrorCode::NotWritten => "client registry could not be written",
            ClientRegistryErrorCode::CredentialNotIssued => "client credential could not be issued",
            ClientRegistryErrorCode::CredentialPathInsideWorkspace => {
                "credential path is inside an agent workspace root"
            }
        };
        write!(f, "{what}: {}", self.detail)
    }
}

impl std::error::Error for ClientRegistryError {}

// ---------------------------------------------------------------------------
// Credential delivery assurance
// ---------------------------------------------------------------------------

/// The credential-delivery assurance classes a **production** registration may
/// be created under.
///
/// The parent design defines three classes: isolated descriptor,
/// sandbox-isolated store, and UID-ambient. Only the first two may register a
/// client at all — a UID-ambient credential is refused for Inspect, Propose,
/// Request-apply, and every configured-state tool, so a registration under it
/// would grant nothing. It is therefore not a variant here: a class this type
/// cannot spell is a class no registration can carry.
///
/// ## `test_only` is structurally unrepresentable
///
/// `crate::principal`'s fixture path labels itself `test_only` and exists only
/// under the `fixture-grants` feature. This enum has no such variant and no
/// escape hatch that could produce one:
/// [`ClientRegistration::issue`] takes a `CredentialDelivery` by value, so the
/// only way to construct a registration is to name one of these two classes.
/// The fixture path and this path share no type, no constructor, and no
/// verifier; the disjointness tests in this module pin that.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialDelivery {
    /// A supervising client passes the credential through an inherited
    /// descriptor unavailable to agent subprocesses.
    IsolatedDescriptor,
    /// An approved helper reads the credential from a client store outside
    /// every enforced agent sandbox root.
    SandboxIsolatedStore,
}

impl CredentialDelivery {
    /// Every class this build defines, in a stable order.
    pub const ALL: &'static [Self] = &[Self::IsolatedDescriptor, Self::SandboxIsolatedStore];

    /// The wire spelling.
    #[must_use]
    pub const fn wire(self) -> &'static str {
        match self {
            Self::IsolatedDescriptor => "isolated_descriptor",
            Self::SandboxIsolatedStore => "sandbox_isolated_store",
        }
    }

    /// Parse a wire spelling.
    ///
    /// An allowlist over [`Self::ALL`]: `uid_ambient`, `test_only`, and every
    /// other string return `None`.
    #[must_use]
    pub fn from_wire(value: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|c| c.wire() == value)
    }
}

impl std::fmt::Display for CredentialDelivery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.wire())
    }
}

// ---------------------------------------------------------------------------
// Identifiers
// ---------------------------------------------------------------------------

/// A stable opaque registration identifier.
///
/// Attribution only. It is not a credential and confers nothing.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct RegistrationId(String);

impl RegistrationId {
    /// Mint a fresh identifier from the operating system random source.
    ///
    /// # Errors
    ///
    /// Propagates a random-source failure.
    pub fn generate() -> Result<Self, ClientRegistryError> {
        let bytes = os_random_32().map_err(|e| {
            ClientRegistryError::new(ClientRegistryErrorCode::CredentialNotIssued, e.detail)
        })?;
        Ok(Self(format!("reg-{}", hex::encode(&bytes[..16]))))
    }

    /// Validate and wrap an identifier.
    ///
    /// # Errors
    ///
    /// Returns [`ClientRegistryErrorCode::InvalidRegistrationId`] for anything
    /// outside `[A-Za-z0-9._-]`, or longer than 128 bytes. The charset excludes
    /// path separators, so an identifier can never be spliced into a path and
    /// escape.
    pub fn new(value: impl Into<String>) -> Result<Self, ClientRegistryError> {
        let value = value.into();
        if value.is_empty() || value.len() > 128 {
            return Err(ClientRegistryError::new(
                ClientRegistryErrorCode::InvalidRegistrationId,
                format!("{} bytes", value.len()),
            ));
        }
        if let Some(bad) = value
            .chars()
            .find(|c| !(c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')))
        {
            return Err(ClientRegistryError::new(
                ClientRegistryErrorCode::InvalidRegistrationId,
                format!("character {bad:?} is not allowed"),
            ));
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for RegistrationId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for RegistrationId {
    type Error = ClientRegistryError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<RegistrationId> for String {
    fn from(value: RegistrationId) -> Self {
        value.0
    }
}

/// A human-readable client name.
///
/// Display and attribution only, never authoritative for authorization.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ClientLabel(String);

impl ClientLabel {
    /// Validate and wrap a client label.
    ///
    /// # Errors
    ///
    /// Returns [`ClientRegistryErrorCode::InvalidClientLabel`] when the value
    /// is empty after trimming, longer than 96 bytes, or contains a control
    /// character. Control characters are refused because the label is echoed
    /// to a terminal and written to a log line.
    pub fn new(value: impl Into<String>) -> Result<Self, ClientRegistryError> {
        let value = value.into().trim().to_string();
        if value.is_empty() {
            return Err(ClientRegistryError::new(
                ClientRegistryErrorCode::InvalidClientLabel,
                "empty",
            ));
        }
        if value.len() > MAX_CLIENT_LABEL_LEN {
            return Err(ClientRegistryError::new(
                ClientRegistryErrorCode::InvalidClientLabel,
                format!(
                    "{} bytes exceeds the {MAX_CLIENT_LABEL_LEN}-byte limit",
                    value.len()
                ),
            ));
        }
        if value.chars().any(char::is_control) {
            return Err(ClientRegistryError::new(
                ClientRegistryErrorCode::InvalidClientLabel,
                "contains a control character",
            ));
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ClientLabel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for ClientLabel {
    type Error = ClientRegistryError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<ClientLabel> for String {
    fn from(value: ClientLabel) -> Self {
        value.0
    }
}

// ---------------------------------------------------------------------------
// Credential and verifier
// ---------------------------------------------------------------------------

/// A client credential: 32 bytes, delivered once, never persisted.
///
/// Deliberately has no `Serialize`, no `Display`, no `PartialEq`, and a
/// redacted `Debug`. The only ways out are [`Self::to_delivery_hex`], which the
/// credential file writer uses, and [`ClientRegistration::authenticate`], which
/// consumes it for a constant-time check.
pub struct ClientCredential([u8; 32]);

impl ClientCredential {
    /// Mint a credential from the operating system random source.
    ///
    /// # Errors
    ///
    /// Propagates a random-source failure rather than falling back to a
    /// userspace generator.
    pub fn issue() -> Result<Self, ClientRegistryError> {
        os_random_32().map(Self).map_err(|e| {
            ClientRegistryError::new(ClientRegistryErrorCode::CredentialNotIssued, e.detail)
        })
    }

    /// The delivery encoding written to the credential file.
    ///
    /// Named for what it is so a call site cannot mistake it for a display
    /// helper. Every caller of this function is handling the secret.
    #[must_use]
    pub fn to_delivery_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parse a credential a client presents.
    ///
    /// # Errors
    ///
    /// Returns [`ClientRegistryErrorCode::CredentialNotIssued`] when the value
    /// is not exactly 32 hex-encoded bytes.
    pub fn from_delivery_hex(value: &str) -> Result<Self, ClientRegistryError> {
        let mut bytes = [0u8; 32];
        hex::decode_to_slice(value.trim(), &mut bytes).map_err(|_| {
            // No detail from the parser: it would echo the malformed input,
            // which is a near-miss of a real credential.
            ClientRegistryError::new(
                ClientRegistryErrorCode::CredentialNotIssued,
                "credential is not 32 hex-encoded bytes",
            )
        })?;
        Ok(Self(bytes))
    }
}

/// Redacted: never prints credential bytes.
impl std::fmt::Debug for ClientCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientCredential")
            .field("bytes", &"<redacted>")
            .finish()
    }
}

/// Best-effort zeroisation, matching the treatment of the master key.
impl Drop for ClientCredential {
    fn drop(&mut self) {
        self.0.fill(0);
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

/// What the host stores in place of a credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CredentialVerifier([u8; 32]);

impl CredentialVerifier {
    /// Compute the verifier for `credential` under `registration_id`.
    #[must_use]
    pub fn compute(
        registration_id: &RegistrationId,
        credential: &ClientCredential,
        key: &ApprovalAuditKey,
    ) -> Self {
        Self(
            *key.sign(&credential_message(registration_id, credential))
                .as_bytes(),
        )
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parse a 64-character hex verifier.
    ///
    /// # Errors
    ///
    /// Returns [`StoreErrorCode::Decode`] when the input is not exactly 32
    /// hex-encoded bytes.
    pub fn from_hex(value: &str) -> Result<Self, StoreError> {
        let mut bytes = [0u8; 32];
        hex::decode_to_slice(value, &mut bytes).map_err(|e| {
            StoreError::new(StoreErrorCode::Decode, format!("credential verifier: {e}"))
        })?;
        Ok(Self(bytes))
    }
}

impl std::fmt::Display for CredentialVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl Serialize for CredentialVerifier {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for CredentialVerifier {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(d)?;
        Self::from_hex(&raw).map_err(serde::de::Error::custom)
    }
}

/// The message a credential verifier is a tag over.
///
/// The registration id is bound in, so a verifier is valid for exactly one
/// registration and cannot be moved between records.
fn credential_message(registration_id: &RegistrationId, credential: &ClientCredential) -> Vec<u8> {
    let mut out = Vec::new();
    absorb_str(&mut out, CLIENT_CREDENTIAL_LABEL);
    absorb_str(&mut out, registration_id.as_str());
    absorb_field(&mut out, &credential.0);
    out
}

// ---------------------------------------------------------------------------
// Registration record
// ---------------------------------------------------------------------------

/// Whether a registration may currently authenticate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationStatus {
    /// Normal operation.
    Active,
    /// Permanently withdrawn. Revocation is immediate and fails closed.
    Revoked,
}

impl RegistrationStatus {
    /// The authenticated spelling.
    #[must_use]
    pub const fn wire(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Revoked => "revoked",
        }
    }
}

/// One registered client.
///
/// There is no `approval_authority` field, and no field whose value could grant
/// approval. That is the principals design's rule expressed as a type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientRegistration {
    /// Stable opaque identifier. Attribution only, not a credential.
    pub registration_id: RegistrationId,
    /// Display name. Never authoritative for authorization.
    pub client_label: ClientLabel,
    /// Verifier material only; the credential itself is never stored.
    pub credential_verifier: CredentialVerifier,
    /// The delivery assurance class this registration was created under.
    pub delivery_assurance: CredentialDelivery,
    /// Explicit registered instance ids. No wildcard, no path.
    pub granted_instances: BTreeSet<InstanceId>,
    /// Explicit read domains from [`READ_DOMAINS_V1`].
    pub granted_read_domains: BTreeSet<String>,
    /// Explicit proposal domains from [`PROPOSAL_DOMAINS_V1`]. Inert in v1.
    pub proposal_domains: BTreeSet<String>,
    /// Epoch at issuance. Recovery invalidates credentials from a prior epoch.
    pub trust_epoch: TrustEpoch,
    /// Wall-clock creation time, seconds since the Unix epoch.
    pub created_at_unix_secs: u64,
    /// The ceremony operation this registration is anchored to, per ADR-016:
    /// the genesis record digest rather than a receipt.
    pub created_by_genesis_digest: GenesisDigest,
    /// The user-presence assurance class of that ceremony.
    pub ceremony_presence_class: PresenceClass,
    /// Current status.
    pub status: RegistrationStatus,
}

/// The grant a registration is being issued with.
///
/// A separate input type so [`ClientRegistration::issue`] validates the whole
/// grant in one place, rather than letting a caller assemble a record field by
/// field and skip a check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientGrant {
    pub client_label: ClientLabel,
    pub delivery_assurance: CredentialDelivery,
    pub granted_instances: BTreeSet<InstanceId>,
    pub granted_read_domains: BTreeSet<String>,
    pub proposal_domains: BTreeSet<String>,
}

impl ClientGrant {
    /// The grant a genesis-time bootstrap registration receives: every read
    /// domain and proposal domain v1 defines, over exactly one instance.
    #[must_use]
    pub fn full_v1(
        client_label: ClientLabel,
        delivery_assurance: CredentialDelivery,
        instance: InstanceId,
    ) -> Self {
        Self {
            client_label,
            delivery_assurance,
            granted_instances: [instance].into_iter().collect(),
            granted_read_domains: READ_DOMAINS_V1.iter().map(|d| (*d).to_string()).collect(),
            proposal_domains: PROPOSAL_DOMAINS_V1
                .iter()
                .map(|d| (*d).to_string())
                .collect(),
        }
    }

    /// Refuse a grant naming anything v1 does not define.
    ///
    /// An allowlist in both directions: an unknown read domain and an unknown
    /// proposal domain are both refusals, never silently dropped members.
    ///
    /// # Errors
    ///
    /// See [`ClientRegistryErrorCode::UnknownReadDomain`],
    /// [`ClientRegistryErrorCode::UnknownProposalDomain`], and
    /// [`ClientRegistryErrorCode::NoGrantedInstance`].
    pub fn validate(&self) -> Result<(), ClientRegistryError> {
        if self.granted_instances.is_empty() {
            return Err(ClientRegistryError::new(
                ClientRegistryErrorCode::NoGrantedInstance,
                self.client_label.as_str(),
            ));
        }
        for domain in &self.granted_read_domains {
            if !READ_DOMAINS_V1.contains(&domain.as_str()) {
                return Err(ClientRegistryError::new(
                    ClientRegistryErrorCode::UnknownReadDomain,
                    domain.clone(),
                ));
            }
        }
        for domain in &self.proposal_domains {
            if !PROPOSAL_DOMAINS_V1.contains(&domain.as_str()) {
                return Err(ClientRegistryError::new(
                    ClientRegistryErrorCode::UnknownProposalDomain,
                    domain.clone(),
                ));
            }
        }
        Ok(())
    }
}

/// A freshly issued registration and the one copy of its credential.
///
/// The credential is not `Clone`, so there is exactly one of it and delivering
/// it consumes it.
pub struct IssuedRegistration {
    pub registration: ClientRegistration,
    pub credential: ClientCredential,
}

impl std::fmt::Debug for IssuedRegistration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IssuedRegistration")
            .field("registration", &self.registration)
            .field("credential", &"<redacted>")
            .finish()
    }
}

impl ClientRegistration {
    /// Mint a registration and its one-time credential.
    ///
    /// # Errors
    ///
    /// Returns a validation failure for a grant naming an undefined domain or
    /// no instance, and propagates a random-source failure.
    pub fn issue(
        grant: &ClientGrant,
        trust_epoch: TrustEpoch,
        created_at_unix_secs: u64,
        created_by_genesis_digest: GenesisDigest,
        ceremony_presence_class: PresenceClass,
        key: &ApprovalAuditKey,
    ) -> Result<IssuedRegistration, ClientRegistryError> {
        grant.validate()?;
        let registration_id = RegistrationId::generate()?;
        let credential = ClientCredential::issue()?;
        let credential_verifier = CredentialVerifier::compute(&registration_id, &credential, key);
        Ok(IssuedRegistration {
            registration: Self {
                registration_id,
                client_label: grant.client_label.clone(),
                credential_verifier,
                delivery_assurance: grant.delivery_assurance,
                granted_instances: grant.granted_instances.clone(),
                granted_read_domains: grant.granted_read_domains.clone(),
                proposal_domains: grant.proposal_domains.clone(),
                trust_epoch,
                created_at_unix_secs,
                created_by_genesis_digest,
                ceremony_presence_class,
                status: RegistrationStatus::Active,
            },
            credential,
        })
    }

    /// Whether `presented` is this registration's credential **and** this
    /// registration may still authenticate.
    ///
    /// Both questions are answered here rather than split, so no caller can
    /// check the secret and forget the status. A revoked registration returns
    /// `false` even for the correct credential.
    #[must_use]
    pub fn authenticate(&self, presented: &ClientCredential, key: &ApprovalAuditKey) -> bool {
        if self.status != RegistrationStatus::Active {
            return false;
        }
        key.verify(
            &credential_message(&self.registration_id, presented),
            &Tag::from_bytes(self.credential_verifier.0),
        )
    }

    /// Whether this registration covers `instance`.
    #[must_use]
    pub fn covers_instance(&self, instance: &InstanceId) -> bool {
        self.granted_instances.contains(instance)
    }

    /// Whether this registration covers the read domain `domain`.
    #[must_use]
    pub fn covers_read_domain(&self, domain: &str) -> bool {
        self.granted_read_domains.contains(domain)
    }

    /// Whether this registration covers the proposal domain `domain`.
    #[must_use]
    pub fn covers_proposal_domain(&self, domain: &str) -> bool {
        self.proposal_domains.contains(domain)
    }
}

// ---------------------------------------------------------------------------
// The registry
// ---------------------------------------------------------------------------

/// Every registered client on one instance.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientRegistry {
    registrations: BTreeMap<RegistrationId, ClientRegistration>,
}

impl ClientRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a registration, refusing to overwrite one.
    ///
    /// # Errors
    ///
    /// Returns [`ClientRegistryErrorCode::DuplicateRegistration`] when the id
    /// is already present. Silently replacing would let one registration
    /// retarget another client's grant.
    pub fn insert(&mut self, registration: ClientRegistration) -> Result<(), ClientRegistryError> {
        match self
            .registrations
            .entry(registration.registration_id.clone())
        {
            Entry::Occupied(occupied) => Err(ClientRegistryError::new(
                ClientRegistryErrorCode::DuplicateRegistration,
                occupied.key().as_str().to_owned(),
            )),
            Entry::Vacant(vacant) => {
                vacant.insert(registration);
                Ok(())
            }
        }
    }

    #[must_use]
    pub fn get(&self, registration_id: &RegistrationId) -> Option<&ClientRegistration> {
        self.registrations.get(registration_id)
    }

    pub fn iter(&self) -> impl Iterator<Item = &ClientRegistration> {
        self.registrations.values()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.registrations.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.registrations.is_empty()
    }
}

/// Absorb one registration.
///
/// Destructured exhaustively, without `..`: an unabsorbed field is an
/// unauthenticated field.
fn absorb_registration(out: &mut Vec<u8>, registration: &ClientRegistration) {
    let ClientRegistration {
        registration_id,
        client_label,
        credential_verifier,
        delivery_assurance,
        granted_instances,
        granted_read_domains,
        proposal_domains,
        trust_epoch,
        created_at_unix_secs,
        created_by_genesis_digest,
        ceremony_presence_class,
        status,
    } = registration;
    absorb_str(out, registration_id.as_str());
    absorb_str(out, client_label.as_str());
    absorb_field(out, credential_verifier.as_bytes());
    absorb_str(out, delivery_assurance.wire());
    absorb_u64(out, granted_instances.len() as u64);
    for instance in granted_instances {
        absorb_str(out, instance.as_str());
    }
    absorb_u64(out, granted_read_domains.len() as u64);
    for domain in granted_read_domains {
        absorb_str(out, domain);
    }
    absorb_u64(out, proposal_domains.len() as u64);
    for domain in proposal_domains {
        absorb_str(out, domain);
    }
    absorb_u64(out, trust_epoch.get());
    absorb_u64(out, *created_at_unix_secs);
    absorb_field(out, created_by_genesis_digest.as_bytes());
    absorb_str(out, ceremony_presence_class.wire());
    absorb_str(out, status.wire());
}

impl CanonicalBytes for ClientRegistry {
    const DOMAIN: &'static str = CLIENT_REGISTRY_DOMAIN;
    const FORMAT_VERSION: u32 = CLIENT_REGISTRY_FORMAT_VERSION;

    fn absorb_canonical(&self, out: &mut Vec<u8>) {
        absorb_u64(out, self.len() as u64);
        for registration in self.iter() {
            absorb_registration(out, registration);
        }
    }
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

/// Whether a client registry file exists at the fixed path.
#[must_use]
pub fn is_present(paths: &ControlPaths) -> bool {
    paths.client_registry().exists()
}

/// Seal and publish the client registry.
///
/// # Errors
///
/// Returns [`ClientRegistryErrorCode::NotWritten`] on an encoding or
/// publication failure.
pub fn save(
    paths: &ControlPaths,
    registry: &ClientRegistry,
    key: &ApprovalAuditKey,
) -> Result<(), ClientRegistryError> {
    let bytes = seal(registry, key)
        .map_err(|e| ClientRegistryError::new(ClientRegistryErrorCode::NotWritten, e.detail))?;
    publish_replace(&paths.client_registry(), &bytes)
        .map_err(|e| ClientRegistryError::new(ClientRegistryErrorCode::NotWritten, e.detail))
}

/// Publish the client registry for the first time, refusing to replace one.
///
/// # Errors
///
/// Returns [`ClientRegistryErrorCode::NotWritten`] when a registry is already
/// present.
pub fn save_new(
    paths: &ControlPaths,
    registry: &ClientRegistry,
    key: &ApprovalAuditKey,
) -> Result<(), ClientRegistryError> {
    let bytes = seal(registry, key)
        .map_err(|e| ClientRegistryError::new(ClientRegistryErrorCode::NotWritten, e.detail))?;
    publish_new(&paths.client_registry(), &bytes)
        .map_err(|e| ClientRegistryError::new(ClientRegistryErrorCode::NotWritten, e.detail))
}

/// Load, authenticate, and re-validate the client registry.
///
/// Re-validation is not a formality: the grant allowlists are the authorization
/// surface, so a registry that authenticates but names a domain this build does
/// not define is refused rather than loaded with an uninterpretable grant.
///
/// # Errors
///
/// See [`ClientRegistryErrorCode`]. Nothing partial is returned.
pub fn load(
    paths: &ControlPaths,
    key: &ApprovalAuditKey,
) -> Result<ClientRegistry, ClientRegistryError> {
    let path = paths.client_registry();
    let Some(raw) = read_optional(&path)
        .map_err(|e| ClientRegistryError::new(ClientRegistryErrorCode::Unverifiable, e.detail))?
    else {
        return Err(ClientRegistryError::new(
            ClientRegistryErrorCode::NotPresent,
            path.display().to_string(),
        ));
    };

    let registry: ClientRegistry = open_sealed(&raw, key)
        .map_err(|e| ClientRegistryError::new(ClientRegistryErrorCode::Unverifiable, e.detail))?;

    for registration in registry.iter() {
        ClientGrant {
            client_label: registration.client_label.clone(),
            delivery_assurance: registration.delivery_assurance,
            granted_instances: registration.granted_instances.clone(),
            granted_read_domains: registration.granted_read_domains.clone(),
            proposal_domains: registration.proposal_domains.clone(),
        }
        .validate()?;
    }
    Ok(registry)
}

/// Load the client registry using the deployment's own key source.
///
/// # Errors
///
/// Returns [`ClientRegistryErrorCode::Unverifiable`] when the key cannot be
/// derived, plus everything [`load`] returns.
pub fn load_with_key_source(
    paths: &ControlPaths,
    key_source: &dyn KeySource,
    epoch: TrustEpoch,
) -> Result<ClientRegistry, ClientRegistryError> {
    let key = ApprovalAuditKey::derive(key_source, epoch).map_err(|e| {
        ClientRegistryError::new(ClientRegistryErrorCode::Unverifiable, format!("{e:#}"))
    })?;
    load(paths, &key)
}

// ---------------------------------------------------------------------------
// Credential delivery
// ---------------------------------------------------------------------------

/// Refuse a credential path that lands inside any agent workspace root.
///
/// ## Best effort, and why that is stated rather than hidden
///
/// The check compares canonicalized ancestors, which catches the common
/// mistakes: writing into a workspace directly, or through a symlinked or
/// `..`-laden path that resolves into one. It cannot catch everything. The
/// forbidden roots come from the configuration as loaded *now*, so a workspace
/// added later, a bind mount, a hard link created afterwards, or a sandbox root
/// this crate is not told about will not be seen. Credential delivery is a
/// proof obligation on the host, and this function is one input to it, not the
/// proof.
///
/// The parent directory is canonicalized rather than the target, because the
/// target must not exist yet.
///
/// # Errors
///
/// Returns [`ClientRegistryErrorCode::CredentialPathInsideWorkspace`] when the
/// resolved parent is, or is inside, one of `forbidden_roots`.
pub fn refuse_credential_path_inside(
    target: &Path,
    forbidden_roots: &[std::path::PathBuf],
) -> Result<(), ClientRegistryError> {
    let parent = target.parent().unwrap_or_else(|| Path::new("."));
    let resolved = std::fs::canonicalize(parent).unwrap_or_else(|_| parent.to_path_buf());
    for root in forbidden_roots {
        let resolved_root = std::fs::canonicalize(root).unwrap_or_else(|_| root.clone());
        if resolved.starts_with(&resolved_root) {
            return Err(ClientRegistryError::new(
                ClientRegistryErrorCode::CredentialPathInsideWorkspace,
                format!(
                    "{} resolves inside {}",
                    target.display(),
                    resolved_root.display()
                ),
            ));
        }
    }
    Ok(())
}

/// Write the one copy of a credential to an owner-only file.
///
/// Refuses a path that already exists, so a delivery cannot silently clobber
/// another client's credential, and refuses a symlink, so it cannot be aimed at
/// a file the operator did not intend.
///
/// # Errors
///
/// Returns [`ClientRegistryErrorCode::CredentialNotIssued`] when the file
/// cannot be published.
pub fn write_credential_file(
    path: &Path,
    credential: &ClientCredential,
) -> Result<(), ClientRegistryError> {
    let mut bytes = credential.to_delivery_hex().into_bytes();
    bytes.push(b'\n');
    let result = publish_new(path, &bytes).map_err(|e| {
        ClientRegistryError::new(ClientRegistryErrorCode::CredentialNotIssued, e.detail)
    });
    bytes.fill(0);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::genesis::PresenceClass;
    use std::path::PathBuf;
    use zeroclaw_config::secrets::ProvisioningState;

    #[derive(Debug)]
    struct FixedKeySource([u8; 32]);

    impl KeySource for FixedKeySource {
        fn with_key(
            &self,
            f: &mut dyn FnMut(&[u8; 32]) -> anyhow::Result<()>,
        ) -> anyhow::Result<()> {
            f(&self.0)
        }
        fn backend_name(&self) -> &'static str {
            "test-fixed"
        }
        fn provisioning_state(&self) -> ProvisioningState {
            ProvisioningState::Initialized
        }
    }

    fn key(byte: u8) -> ApprovalAuditKey {
        ApprovalAuditKey::derive(&FixedKeySource([byte; 32]), TrustEpoch::GENESIS)
            .expect("derive test key")
    }

    fn install_root(tmp: &tempfile::TempDir) -> PathBuf {
        let root = tmp.path().join("install");
        std::fs::create_dir_all(root.join("data")).expect("create install root");
        root
    }

    fn grant() -> ClientGrant {
        ClientGrant::full_v1(
            ClientLabel::new("claude-code").expect("label"),
            CredentialDelivery::IsolatedDescriptor,
            InstanceId::new("inst-default").expect("instance"),
        )
    }

    fn issue(key: &ApprovalAuditKey) -> IssuedRegistration {
        ClientRegistration::issue(
            &grant(),
            TrustEpoch::GENESIS,
            1_755_000_000,
            GenesisDigest::from_bytes([0xAA; 32]),
            PresenceClass::Terminal,
            key,
        )
        .expect("issue")
    }

    // -- the production vocabulary -----------------------------------------

    #[test]
    fn the_production_delivery_vocabulary_has_exactly_two_members() {
        // Exhaustive match: a variant added later must be spelled here, so a
        // `test_only` variant cannot be introduced without this failing to
        // compile and this assertion failing.
        for class in CredentialDelivery::ALL {
            match class {
                CredentialDelivery::IsolatedDescriptor
                | CredentialDelivery::SandboxIsolatedStore => {}
            }
        }
        assert_eq!(CredentialDelivery::ALL.len(), 2);
        assert_eq!(
            CredentialDelivery::ALL
                .iter()
                .map(|c| c.wire())
                .collect::<Vec<_>>(),
            vec!["isolated_descriptor", "sandbox_isolated_store"]
        );
    }

    #[test]
    fn no_string_names_a_delivery_class_outside_the_allowlist() {
        for absent in [
            "test_only",
            "uid_ambient",
            "fixture",
            "",
            "ISOLATED_DESCRIPTOR",
            "isolated_descriptor ",
        ] {
            assert!(
                CredentialDelivery::from_wire(absent).is_none(),
                "{absent:?} must not name a production delivery class"
            );
        }
        assert_eq!(
            CredentialDelivery::from_wire("isolated_descriptor"),
            Some(CredentialDelivery::IsolatedDescriptor)
        );
    }

    #[test]
    fn a_registration_cannot_deserialize_an_unacceptable_delivery_class() {
        let k = key(0x11);
        let issued = issue(&k);
        let json = serde_json::to_string(&issued.registration).expect("serialize");
        for forbidden in ["test_only", "uid_ambient"] {
            let tampered = json.replace("\"isolated_descriptor\"", &format!("\"{forbidden}\""));
            assert!(
                serde_json::from_str::<ClientRegistration>(&tampered).is_err(),
                "{forbidden} must not deserialize into a production registration"
            );
        }
    }

    #[test]
    fn the_production_vocabulary_matches_the_classes_the_protocol_advertises() {
        // Single source of truth check across module boundaries: the strings
        // `control.registration_help` advertises must be exactly the classes a
        // registration can be created under.
        assert_eq!(
            CredentialDelivery::ALL
                .iter()
                .map(|c| c.wire())
                .collect::<Vec<_>>(),
            crate::principal::ACCEPTED_ASSURANCE_CLASSES.to_vec()
        );
        for rejected in crate::principal::REJECTED_ASSURANCE_CLASSES {
            assert!(
                CredentialDelivery::from_wire(rejected).is_none(),
                "{rejected} is advertised as rejected and must not be constructible"
            );
        }
    }

    /// Spec point 7: the production verifier path and the fixture-grant path
    /// share no code and no type.
    #[cfg(feature = "fixture-grants")]
    #[test]
    fn the_production_verifier_and_the_fixture_grant_path_are_disjoint() {
        use crate::principal::{
            FIXTURE_ASSURANCE_CLASS, FIXTURE_CREDENTIAL_MARKER, RequesterGrant,
        };

        // 1. The fixture's class is not a production delivery class, so no
        //    registration can be created under it.
        assert_eq!(FIXTURE_ASSURANCE_CLASS, "test_only");
        assert!(CredentialDelivery::from_wire(FIXTURE_ASSURANCE_CLASS).is_none());

        // 2. A fixture grant carries a marker string where a real client
        //    carries a credential. That marker is not a credential: it does not
        //    even parse as one.
        assert!(ClientCredential::from_delivery_hex(FIXTURE_CREDENTIAL_MARKER).is_err());

        // 3. And a real registration does not authenticate it. Padding the
        //    marker to the right length does not help either.
        let k = key(0x11);
        let issued = issue(&k);
        let mut padded = [0u8; 32];
        let marker = FIXTURE_CREDENTIAL_MARKER.as_bytes();
        padded.copy_from_slice(&marker[..32]);
        let forged = ClientCredential::from_delivery_hex(&hex::encode(padded)).expect("parse");
        assert!(
            !issued.registration.authenticate(&forged, &k),
            "the fixture marker must not authenticate against a production verifier"
        );

        // 4. The fixture grant type has no verifier at all, so there is nothing
        //    to convert: `RequesterGrant` exposes an assurance class and
        //    coverage predicates and no credential material.
        let fixture = RequesterGrant::fixture_full();
        assert_eq!(fixture.assurance_class(), FIXTURE_ASSURANCE_CLASS);
        assert_eq!(fixture.credential_marker(), FIXTURE_CREDENTIAL_MARKER);
        assert!(
            CredentialDelivery::from_wire(fixture.assurance_class()).is_none(),
            "a fixture grant cannot be reinterpreted as a production registration"
        );
    }

    // -- domains ------------------------------------------------------------

    #[test]
    fn the_v1_read_domains_cover_every_protocol_view() {
        for view in crate::protocol::VIEWS {
            assert!(
                READ_DOMAINS_V1.contains(view),
                "{view} is a protocol view and must be a grantable read domain"
            );
        }
        assert_eq!(READ_DOMAINS_V1.len(), 6);
    }

    #[test]
    fn a_grant_naming_an_undefined_domain_is_refused() {
        let mut wide = grant();
        wide.granted_read_domains
            .insert("agent.secrets".to_string());
        assert_eq!(
            wide.validate().expect_err("undefined read domain").code,
            ClientRegistryErrorCode::UnknownReadDomain
        );

        let mut proposing = grant();
        proposing.proposal_domains.insert("host.shell".to_string());
        assert_eq!(
            proposing
                .validate()
                .expect_err("undefined proposal domain")
                .code,
            ClientRegistryErrorCode::UnknownProposalDomain
        );

        let mut nowhere = grant();
        nowhere.granted_instances.clear();
        assert_eq!(
            nowhere.validate().expect_err("no instance").code,
            ClientRegistryErrorCode::NoGrantedInstance
        );
    }

    #[test]
    fn a_grant_is_an_allowlist_not_a_switch() {
        let k = key(0x11);
        let narrow = ClientGrant {
            client_label: ClientLabel::new("narrow").expect("label"),
            delivery_assurance: CredentialDelivery::SandboxIsolatedStore,
            granted_instances: [InstanceId::new("inst-default").expect("id")]
                .into_iter()
                .collect(),
            granted_read_domains: [VIEW_AGENT_SUMMARY.to_string()].into_iter().collect(),
            proposal_domains: BTreeSet::new(),
        };
        let issued = ClientRegistration::issue(
            &narrow,
            TrustEpoch::GENESIS,
            1,
            GenesisDigest::from_bytes([0xAA; 32]),
            PresenceClass::Terminal,
            &k,
        )
        .expect("issue");

        let registration = &issued.registration;
        assert!(registration.covers_read_domain(VIEW_AGENT_SUMMARY));
        assert!(!registration.covers_read_domain(VIEW_PROVIDER_ALIAS_LIST));
        assert!(!registration.covers_read_domain(TOOL_PREVIEW));
        assert!(!registration.covers_proposal_domain(crate::principal::PROPOSAL_DOMAIN_AGENT));
        assert!(registration.covers_instance(&InstanceId::new("inst-default").expect("id")));
        assert!(!registration.covers_instance(&InstanceId::new("inst-other").expect("id")));
    }

    #[test]
    fn a_registration_has_no_field_that_could_grant_approval() {
        let k = key(0x11);
        let json = serde_json::to_value(&issue(&k).registration).expect("serialize");
        let fields: Vec<&String> = json.as_object().expect("object").keys().collect();
        for forbidden in ["approval_authority", "may_approve", "operator", "quorum"] {
            assert!(
                !fields.iter().any(|f| f.as_str() == forbidden),
                "a registration must carry no approval field; found {forbidden}"
            );
        }
    }

    // -- credentials --------------------------------------------------------

    #[test]
    fn the_correct_credential_verifies_and_a_wrong_one_does_not() {
        let k = key(0x11);
        let issued = issue(&k);
        assert!(issued.registration.authenticate(&issued.credential, &k));

        let other = ClientCredential::issue().expect("issue");
        assert!(
            !issued.registration.authenticate(&other, &k),
            "a different credential must not authenticate"
        );

        // One flipped bit is enough.
        let mut bytes = [0u8; 32];
        hex::decode_to_slice(issued.credential.to_delivery_hex(), &mut bytes).expect("hex");
        bytes[0] ^= 0x01;
        let near_miss = ClientCredential::from_delivery_hex(&hex::encode(bytes)).expect("parse");
        assert!(!issued.registration.authenticate(&near_miss, &k));
    }

    #[test]
    fn a_credential_does_not_authenticate_against_another_registration() {
        let k = key(0x11);
        let first = issue(&k);
        let second = issue(&k);
        assert!(
            !second.registration.authenticate(&first.credential, &k),
            "the registration id is bound into the verifier"
        );
    }

    #[test]
    fn a_verifier_moved_between_records_does_not_authenticate() {
        let k = key(0x11);
        let first = issue(&k);
        let mut second = issue(&k);
        second.registration.credential_verifier = first.registration.credential_verifier;
        assert!(
            !second.registration.authenticate(&first.credential, &k),
            "a lifted verifier must not carry its credential with it"
        );
    }

    #[test]
    fn a_credential_does_not_authenticate_under_another_deployments_key() {
        let mine = key(0x11);
        let issued = issue(&mine);
        assert!(
            !issued
                .registration
                .authenticate(&issued.credential, &key(0x22)),
            "the verifier is deployment-bound"
        );
    }

    #[test]
    fn a_revoked_registration_refuses_its_own_credential() {
        let k = key(0x11);
        let mut issued = issue(&k);
        assert!(issued.registration.authenticate(&issued.credential, &k));
        issued.registration.status = RegistrationStatus::Revoked;
        assert!(
            !issued.registration.authenticate(&issued.credential, &k),
            "revocation must fail closed even for the right secret"
        );
    }

    #[test]
    fn two_issued_credentials_differ() {
        let a = ClientCredential::issue().expect("issue");
        let b = ClientCredential::issue().expect("issue");
        assert_ne!(a.to_delivery_hex(), b.to_delivery_hex());
        assert_eq!(a.to_delivery_hex().len(), 64);
    }

    #[test]
    fn a_credential_never_prints_itself() {
        let credential = ClientCredential::issue().expect("issue");
        let secret = credential.to_delivery_hex();
        let rendered = format!("{credential:?}");
        assert!(rendered.contains("<redacted>"), "got {rendered}");
        assert!(!rendered.contains(&secret), "Debug leaked the credential");

        let issued = IssuedRegistration {
            registration: issue(&key(0x11)).registration,
            credential,
        };
        let rendered = format!("{issued:?}");
        assert!(!rendered.contains(&secret), "Debug leaked the credential");
    }

    #[test]
    fn a_malformed_credential_is_refused_without_echoing_it() {
        let err = ClientCredential::from_delivery_hex("nearly-a-credential")
            .expect_err("malformed credential");
        assert_eq!(err.code, ClientRegistryErrorCode::CredentialNotIssued);
        assert!(
            !err.detail.contains("nearly-a-credential"),
            "a near-miss credential must not be echoed back: {}",
            err.detail
        );
    }

    // -- the secret is not at rest -----------------------------------------

    #[test]
    fn the_stored_registry_contains_no_credential_bytes() {
        // Guarded by mutation check: storing the raw credential in place of
        // the verifier must make this test fail.
        let tmp = tempfile::tempdir().expect("tempdir");
        let paths = ControlPaths::resolve(&install_root(&tmp)).expect("resolve");
        let k = key(0x11);
        let issued = issue(&k);
        let secret_hex = issued.credential.to_delivery_hex();
        let mut secret_bytes = [0u8; 32];
        hex::decode_to_slice(&secret_hex, &mut secret_bytes).expect("hex");

        let mut registry = ClientRegistry::new();
        registry.insert(issued.registration).expect("insert");
        save(&paths, &registry, &k).expect("save");

        let raw = std::fs::read(paths.client_registry()).expect("read");
        let text = String::from_utf8_lossy(&raw);
        assert!(
            !text.contains(&secret_hex),
            "the stored registry contains the credential in hex"
        );
        assert!(
            !text.contains(&secret_hex.to_uppercase()),
            "the stored registry contains the credential in upper-case hex"
        );
        assert!(
            !raw.windows(32).any(|w| w == secret_bytes),
            "the stored registry contains the raw credential bytes"
        );
        // The verifier is there, so the absence above is not vacuous.
        let verifier = registry
            .iter()
            .next()
            .expect("one registration")
            .credential_verifier
            .to_hex();
        assert!(text.contains(&verifier), "the verifier must be stored");
        assert_ne!(verifier, secret_hex);
    }

    // -- persistence --------------------------------------------------------

    fn established(tmp: &tempfile::TempDir) -> (ControlPaths, ClientRegistry, ApprovalAuditKey) {
        let paths = ControlPaths::resolve(&install_root(tmp)).expect("resolve");
        let k = key(0x11);
        let mut registry = ClientRegistry::new();
        registry.insert(issue(&k).registration).expect("insert");
        save(&paths, &registry, &k).expect("save");
        (paths, registry, k)
    }

    #[test]
    fn a_saved_client_registry_loads_back_identically() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (paths, registry, k) = established(&tmp);
        assert_eq!(load(&paths, &k).expect("load"), registry);
        assert_eq!(
            load_with_key_source(&paths, &FixedKeySource([0x11; 32]), TrustEpoch::GENESIS)
                .expect("load"),
            registry
        );
    }

    #[test]
    fn an_absent_client_registry_is_reported_as_absent_not_empty() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let paths = ControlPaths::resolve(&install_root(&tmp)).expect("resolve");
        assert!(!is_present(&paths));
        assert_eq!(
            load(&paths, &key(0x11)).expect_err("absent").code,
            ClientRegistryErrorCode::NotPresent
        );
    }

    #[test]
    fn a_tampered_client_registry_is_refused() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (paths, registry, k) = established(&tmp);
        let id = registry
            .iter()
            .next()
            .expect("one registration")
            .registration_id
            .clone();

        let raw = std::fs::read(paths.client_registry()).expect("read");
        let mut value: serde_json::Value = serde_json::from_slice(&raw).expect("parse");
        value["payload"]["registrations"][id.as_str()]["granted_read_domains"] =
            serde_json::json!([VIEW_AGENT_SUMMARY, VIEW_PROVIDER_ALIAS_LIST]);
        std::fs::write(
            paths.client_registry(),
            serde_json::to_vec(&value).expect("encode"),
        )
        .expect("write");

        assert_eq!(
            load(&paths, &k).expect_err("tampered").code,
            ClientRegistryErrorCode::Unverifiable
        );
    }

    #[test]
    fn a_client_registry_sealed_under_another_key_is_refused() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (paths, _, _) = established(&tmp);
        assert_eq!(
            load(&paths, &key(0x22)).expect_err("wrong key").code,
            ClientRegistryErrorCode::Unverifiable
        );
    }

    #[test]
    fn the_registry_refuses_a_duplicate_registration() {
        let k = key(0x11);
        let issued = issue(&k);
        let mut registry = ClientRegistry::new();
        let clone = issued.registration.clone();
        registry.insert(issued.registration).expect("first");
        assert_eq!(
            registry.insert(clone).expect_err("duplicate").code,
            ClientRegistryErrorCode::DuplicateRegistration
        );
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn save_new_refuses_to_replace_an_existing_client_registry() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (paths, registry, k) = established(&tmp);
        assert_eq!(
            save_new(&paths, &registry, &k).expect_err("replace").code,
            ClientRegistryErrorCode::NotWritten
        );
    }

    #[test]
    fn the_encoding_binds_every_registration_field() {
        let k = key(0x11);
        let base = issue(&k).registration;
        let mut baseline = Vec::new();
        absorb_registration(&mut baseline, &base);

        let mut other_label = base.clone();
        other_label.client_label = ClientLabel::new("other").expect("label");
        let mut other_verifier = base.clone();
        other_verifier.credential_verifier = issue(&k).registration.credential_verifier;
        let mut other_delivery = base.clone();
        other_delivery.delivery_assurance = CredentialDelivery::SandboxIsolatedStore;
        let mut other_instances = base.clone();
        other_instances
            .granted_instances
            .insert(InstanceId::new("inst-extra").expect("id"));
        let mut other_reads = base.clone();
        other_reads.granted_read_domains.clear();
        let mut other_proposals = base.clone();
        other_proposals.proposal_domains.clear();
        let mut other_epoch = base.clone();
        other_epoch.trust_epoch = TrustEpoch::new(2);
        let mut other_time = base.clone();
        other_time.created_at_unix_secs += 1;
        let mut other_anchor = base.clone();
        other_anchor.created_by_genesis_digest = GenesisDigest::from_bytes([0xBB; 32]);
        let mut other_status = base.clone();
        other_status.status = RegistrationStatus::Revoked;
        let mut other_id = base.clone();
        other_id.registration_id = RegistrationId::new("reg-other").expect("id");

        for (name, variant) in [
            ("registration id", other_id),
            ("client label", other_label),
            ("credential verifier", other_verifier),
            ("delivery assurance", other_delivery),
            ("granted instances", other_instances),
            ("granted read domains", other_reads),
            ("proposal domains", other_proposals),
            ("trust epoch", other_epoch),
            ("created at", other_time),
            ("ceremony anchor", other_anchor),
            ("status", other_status),
        ] {
            let mut encoded = Vec::new();
            absorb_registration(&mut encoded, &variant);
            assert_ne!(baseline, encoded, "the tag must bind the {name}");
        }
    }

    // -- credential delivery ------------------------------------------------

    #[cfg(unix)]
    #[test]
    fn a_credential_file_is_owner_only_and_written_once() {
        use std::os::unix::fs::PermissionsExt as _;
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("client.cred");
        let credential = ClientCredential::issue().expect("issue");
        let secret = credential.to_delivery_hex();
        write_credential_file(&path, &credential).expect("write");

        let mode = std::fs::metadata(&path).expect("stat").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "a credential file must be owner-only");
        assert_eq!(std::fs::read_to_string(&path).expect("read").trim(), secret);

        let second = ClientCredential::issue().expect("issue");
        assert_eq!(
            write_credential_file(&path, &second)
                .expect_err("a second delivery must be refused")
                .code,
            ClientRegistryErrorCode::CredentialNotIssued
        );
        assert_eq!(
            std::fs::read_to_string(&path).expect("read").trim(),
            secret,
            "the first credential must survive a refused overwrite"
        );
    }

    #[test]
    fn a_credential_path_inside_a_workspace_root_is_refused() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let workspace = tmp.path().join("workspace");
        std::fs::create_dir_all(workspace.join("nested")).expect("mkdir");
        let elsewhere = tmp.path().join("elsewhere");
        std::fs::create_dir_all(&elsewhere).expect("mkdir");
        let roots = vec![workspace.clone()];

        assert_eq!(
            refuse_credential_path_inside(&workspace.join("c.cred"), &roots)
                .expect_err("direct")
                .code,
            ClientRegistryErrorCode::CredentialPathInsideWorkspace
        );
        assert_eq!(
            refuse_credential_path_inside(&workspace.join("nested").join("c.cred"), &roots)
                .expect_err("nested")
                .code,
            ClientRegistryErrorCode::CredentialPathInsideWorkspace
        );
        assert_eq!(
            refuse_credential_path_inside(
                &elsewhere.join("..").join("workspace").join("c.cred"),
                &roots
            )
            .expect_err("traversal")
            .code,
            ClientRegistryErrorCode::CredentialPathInsideWorkspace
        );
        assert!(refuse_credential_path_inside(&elsewhere.join("c.cred"), &roots).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn a_credential_path_that_symlinks_into_a_workspace_is_refused() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let workspace = tmp.path().join("workspace");
        std::fs::create_dir_all(&workspace).expect("mkdir");
        let link = tmp.path().join("shortcut");
        std::os::unix::fs::symlink(&workspace, &link).expect("symlink");

        assert_eq!(
            refuse_credential_path_inside(&link.join("c.cred"), &[workspace])
                .expect_err("symlinked parent")
                .code,
            ClientRegistryErrorCode::CredentialPathInsideWorkspace
        );
    }

    #[test]
    fn labels_and_identifiers_are_bounded_and_free_of_control_characters() {
        assert_eq!(
            ClientLabel::new("  claude-code  ").expect("label").as_str(),
            "claude-code"
        );
        for bad in ["", "  ", "a\nb"] {
            assert!(ClientLabel::new(bad).is_err(), "{bad:?} must be refused");
        }
        assert!(ClientLabel::new("a".repeat(MAX_CLIENT_LABEL_LEN)).is_ok());
        assert!(ClientLabel::new("a".repeat(MAX_CLIENT_LABEL_LEN + 1)).is_err());

        for bad in ["", "a/b", "../escape", "a b"] {
            assert!(
                RegistrationId::new(bad).is_err(),
                "{bad:?} must not be a registration id"
            );
        }
        let generated = RegistrationId::generate().expect("generate");
        assert!(generated.as_str().starts_with("reg-"));
        assert_ne!(
            generated,
            RegistrationId::generate().expect("generate"),
            "registration ids must not repeat"
        );
    }
}
