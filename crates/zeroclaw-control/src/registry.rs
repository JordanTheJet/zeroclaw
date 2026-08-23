//! Target registry records and the instance fingerprint.
//!
//! This module is the data model half of the trust-genesis design
//! (`docs/book/src/architecture/control-plane-trust-genesis.md`). It owns:
//!
//! - [`TargetRecord`] — one registered instance: a stable [`InstanceId`], the
//!   canonical config and data roots, the allowed creation parent, the
//!   [`TrustEpoch`] the record was written under, and its [`TargetStatus`];
//! - [`TargetRegistry`] — the set of those records, keyed by instance ID; and
//! - [`InstanceFingerprint`] — the digest the host recomputes under lock before
//!   preview and apply, so that replacing a registered root or redirecting it
//!   through a symlink expires the proposal.
//!
//! ## What this module deliberately does not do
//!
//! - **No persistence.** Nothing here reads or writes a registry file. The
//!   design requires the registry to be resolved under the registry and
//!   instance locks; that locking and its on-disk representation are a later
//!   piece of phase 3.
//! - **No signing.** The design calls for a *signed* target registry. Signing
//!   composes this module with [`crate::keys::ApprovalAuditKey`] once the
//!   genesis ceremony exists to establish the epoch and commit the host key.
//!   Until then a [`TargetRegistry`] carries integrity only as far as the
//!   process that built it.
//! - **No genesis.** [`GenesisDigest`] is accepted as an opaque input. Writing
//!   the genesis record is the ceremony's job, not this module's.
//!
//! ## The registry does not survive an epoch break
//!
//! The maintainer decided on issue #26 (question 18) that **recovery discards
//! registered target roots and approved creation parents**: a registration made
//! under a compromised epoch must not survive the recovery meant to contain it,
//! so operators re-register afterwards. Containment over convenience.
//!
//! Nothing here implements recovery, but the choice shapes this data model.
//! Every [`TargetRecord`] carries the [`TrustEpoch`] it was written under, so a
//! record from a superseded epoch is recognizable rather than silently
//! inherited, and a registry is per-epoch state rather than durable inventory.
//! Whoever implements recovery must drop these records, not migrate them.
//!
//! ## Why the fingerprint probes without following symlinks
//!
//! [`RootIdentity::probe`] uses `symlink_metadata`, so a root that has been
//! replaced by a symlink has the symlink's own file type and inode rather than
//! the target directory's. That is the point: the design treats "redirected
//! through a symlink" as a change of identity that must expire an in-flight
//! proposal, so resolving through the link would defeat the check.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Domain-separation label for the instance fingerprint digest.
///
/// Versioned: a change to what the fingerprint commits to, or to how it is
/// encoded, is a new label rather than a silent reinterpretation of the old
/// one.
pub const INSTANCE_FINGERPRINT_LABEL: &str = "zeroclaw/control-plane/instance-fingerprint/v1";

/// Upper bound on an instance identifier, so a record cannot carry an
/// unbounded string into a digest or a diagnostic.
const MAX_INSTANCE_ID_LEN: usize = 128;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Stable classification for a registry data-model rejection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistryErrorCode {
    /// An instance identifier was empty, over-long, or used characters
    /// outside the accepted set.
    InvalidInstanceId,
    /// A hex-encoded digest was the wrong length or contained a non-hex
    /// character.
    InvalidDigest,
    /// A canonical root was not absolute.
    RootNotAbsolute,
    /// An instance identifier was already present in the registry.
    DuplicateInstance,
    /// A record named an allowed creation parent equal to itself.
    SelfParent,
}

/// A registry data-model rejection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryError {
    pub code: RegistryErrorCode,
    pub detail: String,
}

impl RegistryError {
    fn new(code: RegistryErrorCode, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }
}

impl std::fmt::Display for RegistryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let what = match self.code {
            RegistryErrorCode::InvalidInstanceId => "invalid instance id",
            RegistryErrorCode::InvalidDigest => "invalid digest",
            RegistryErrorCode::RootNotAbsolute => "canonical root is not absolute",
            RegistryErrorCode::DuplicateInstance => "instance is already registered",
            RegistryErrorCode::SelfParent => "instance cannot be its own creation parent",
        };
        write!(f, "{what}: {}", self.detail)
    }
}

impl std::error::Error for RegistryError {}

// ---------------------------------------------------------------------------
// Scalar newtypes
// ---------------------------------------------------------------------------

/// A stable instance identifier.
///
/// Everything else in the control plane is keyed by this value, so it is
/// restricted to ASCII alphanumerics, `-`, `_`, and `.`. That excludes path
/// separators and `..`, so an identifier can never be spliced into a path and
/// escape the root it names.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct InstanceId(String);

impl InstanceId {
    /// Validate and wrap an instance identifier.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryErrorCode::InvalidInstanceId`] when the value is
    /// empty, longer than 128 bytes, `.`, `..`, or contains a character
    /// outside `[A-Za-z0-9._-]`.
    pub fn new(value: impl Into<String>) -> Result<Self, RegistryError> {
        let value = value.into();
        if value.is_empty() {
            return Err(RegistryError::new(
                RegistryErrorCode::InvalidInstanceId,
                "empty",
            ));
        }
        if value.len() > MAX_INSTANCE_ID_LEN {
            return Err(RegistryError::new(
                RegistryErrorCode::InvalidInstanceId,
                format!(
                    "{} bytes exceeds the {MAX_INSTANCE_ID_LEN}-byte limit",
                    value.len()
                ),
            ));
        }
        if value == "." || value == ".." {
            return Err(RegistryError::new(
                RegistryErrorCode::InvalidInstanceId,
                "relative path component",
            ));
        }
        if let Some(bad) = value
            .chars()
            .find(|c| !(c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')))
        {
            return Err(RegistryError::new(
                RegistryErrorCode::InvalidInstanceId,
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

impl std::fmt::Display for InstanceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for InstanceId {
    type Error = RegistryError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<InstanceId> for String {
    fn from(value: InstanceId) -> Self {
        value.0
    }
}

/// The scope under which credentials, grants, and receipts are valid.
///
/// Per the design, an epoch is a monotonic counter scoped to **one** instance.
/// Two epoch values are comparable only within one instance's audit chain, so
/// this type deliberately offers no cross-instance ordering helper beyond the
/// derived `Ord`, which callers must only use after confirming both values
/// belong to the same instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TrustEpoch(u64);

impl TrustEpoch {
    /// The epoch a genesis record establishes.
    pub const GENESIS: Self = Self(1);

    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// The next epoch, or `None` at `u64::MAX` rather than wrapping back onto
    /// an epoch that has already issued credentials.
    #[must_use]
    pub const fn next(self) -> Option<Self> {
        match self.0.checked_add(1) {
            Some(v) => Some(Self(v)),
            None => None,
        }
    }
}

impl std::fmt::Display for TrustEpoch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Digest of the immutable genesis record.
///
/// Opaque to this module: the ceremony that writes the genesis record computes
/// this value, and the fingerprint commits to it so that a registry record can
/// never be reattached to a different root of trust.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GenesisDigest([u8; 32]);

/// The digest the host recomputes under lock before preview and apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InstanceFingerprint([u8; 32]);

macro_rules! hex_digest_newtype {
    ($name:ident) => {
        impl $name {
            #[must_use]
            pub const fn from_bytes(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }

            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }

            #[must_use]
            pub fn to_hex(&self) -> String {
                hex::encode(self.0)
            }

            /// Parse a 64-character lowercase or uppercase hex digest.
            ///
            /// # Errors
            ///
            /// Returns [`RegistryErrorCode::InvalidDigest`] when the input is
            /// not exactly 32 hex-encoded bytes.
            pub fn from_hex(value: &str) -> Result<Self, RegistryError> {
                let mut bytes = [0u8; 32];
                hex::decode_to_slice(value, &mut bytes).map_err(|e| {
                    RegistryError::new(
                        RegistryErrorCode::InvalidDigest,
                        format!("{}: {e}", stringify!($name)),
                    )
                })?;
                Ok(Self(bytes))
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(&self.to_hex())
            }
        }

        impl Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.serialize_str(&self.to_hex())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let raw = String::deserialize(d)?;
                Self::from_hex(&raw).map_err(serde::de::Error::custom)
            }
        }
    };
}

hex_digest_newtype!(GenesisDigest);
hex_digest_newtype!(InstanceFingerprint);

// ---------------------------------------------------------------------------
// Filesystem identity
// ---------------------------------------------------------------------------

/// What kind of object a canonical root actually is.
///
/// Recorded separately from the object ID because it is available on every
/// platform: even where dev+inode is not, a root that was a directory and is
/// now a symlink changes identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RootFileType {
    Directory,
    Symlink,
    File,
    Other,
}

impl RootFileType {
    const fn tag(self) -> u8 {
        match self {
            Self::Directory => 1,
            Self::Symlink => 2,
            Self::File => 3,
            Self::Other => 4,
        }
    }
}

/// Filesystem object identity, where the platform provides one.
///
/// On Unix this is the device and inode number, which together identify the
/// object independently of its path — so replacing a directory with a fresh
/// one at the same path changes this value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct FsObjectId {
    pub device: u64,
    pub inode: u64,
}

/// Owning user and group, where the platform provides them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct OwnerId {
    pub uid: u32,
    pub gid: u32,
}

/// The security-relevant identity of one canonical root.
///
/// Every field here is committed to by [`InstanceFingerprint`]. Adding a field
/// therefore changes the fingerprint for every instance and requires a new
/// [`INSTANCE_FINGERPRINT_LABEL`] version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct RootIdentity {
    /// Object kind as observed **without** following a final symlink.
    pub file_type: RootFileType,
    /// Device and inode on Unix; `None` where the platform does not expose a
    /// stable object identity.
    pub object_id: Option<FsObjectId>,
    /// Owning uid and gid on Unix; `None` elsewhere.
    pub owner: Option<OwnerId>,
    /// Unix permission bits (`mode & 0o7777`, so setuid, setgid, and the
    /// sticky bit are included); `None` elsewhere.
    pub unix_mode: Option<u32>,
    /// Read-only flag, which every supported platform reports.
    pub read_only: bool,
}

impl RootIdentity {
    /// Probe one canonical root **without following a final symlink**.
    ///
    /// # Errors
    ///
    /// Propagates the underlying `symlink_metadata` failure. A registered root
    /// that cannot be stat'd is a real condition the caller must see, not a
    /// value to be defaulted away.
    pub fn probe(path: &Path) -> std::io::Result<Self> {
        let meta = std::fs::symlink_metadata(path)?;
        let ft = meta.file_type();
        let file_type = if ft.is_symlink() {
            RootFileType::Symlink
        } else if ft.is_dir() {
            RootFileType::Directory
        } else if ft.is_file() {
            RootFileType::File
        } else {
            RootFileType::Other
        };

        #[cfg(unix)]
        let (object_id, owner, unix_mode) = {
            use std::os::unix::fs::MetadataExt;
            (
                Some(FsObjectId {
                    device: meta.dev(),
                    inode: meta.ino(),
                }),
                Some(OwnerId {
                    uid: meta.uid(),
                    gid: meta.gid(),
                }),
                Some(meta.mode() & 0o7777),
            )
        };
        #[cfg(not(unix))]
        let (object_id, owner, unix_mode) = (None, None, None);

        Ok(Self {
            file_type,
            object_id,
            owner,
            unix_mode,
            read_only: meta.permissions().readonly(),
        })
    }
}

/// The canonical config and data roots of one instance.
///
/// Apply resolves the target from the registry, never from a caller-supplied
/// path, so these are the only roots an operation may touch.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct CanonicalRoots {
    pub config_root: PathBuf,
    pub data_root: PathBuf,
}

impl CanonicalRoots {
    /// Build a root pair, requiring both paths to be absolute.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryErrorCode::RootNotAbsolute`] when either path is
    /// relative, because a relative root would resolve against whatever
    /// working directory the process happened to have.
    pub fn new(config_root: PathBuf, data_root: PathBuf) -> Result<Self, RegistryError> {
        for (name, path) in [("config_root", &config_root), ("data_root", &data_root)] {
            if !path.is_absolute() {
                return Err(RegistryError::new(
                    RegistryErrorCode::RootNotAbsolute,
                    format!("{name} {}", path.display()),
                ));
            }
        }
        Ok(Self {
            config_root,
            data_root,
        })
    }
}

// ---------------------------------------------------------------------------
// Fingerprint
// ---------------------------------------------------------------------------

/// Absorb one field with an explicit length prefix.
///
/// Length prefixing is what makes the encoding unambiguous: without it,
/// adjacent variable-length fields could be re-split to produce the same digest
/// from different inputs.
fn absorb(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

fn absorb_option_u64(hasher: &mut Sha256, value: Option<u64>) {
    match value {
        Some(v) => {
            hasher.update([1u8]);
            hasher.update(v.to_be_bytes());
        }
        None => hasher.update([0u8]),
    }
}

fn absorb_identity(hasher: &mut Sha256, identity: &RootIdentity) {
    hasher.update([identity.file_type.tag()]);
    absorb_option_u64(hasher, identity.object_id.map(|o| o.device));
    absorb_option_u64(hasher, identity.object_id.map(|o| o.inode));
    absorb_option_u64(hasher, identity.owner.map(|o| u64::from(o.uid)));
    absorb_option_u64(hasher, identity.owner.map(|o| u64::from(o.gid)));
    absorb_option_u64(hasher, identity.unix_mode.map(u64::from));
    hasher.update([u8::from(identity.read_only)]);
}

/// Encode an `OsStr` deterministically on every platform.
#[cfg(unix)]
fn os_str_bytes(value: &OsStr) -> Cow<'_, [u8]> {
    use std::os::unix::ffi::OsStrExt;
    Cow::Borrowed(value.as_bytes())
}

#[cfg(windows)]
fn os_str_bytes(value: &OsStr) -> Cow<'_, [u8]> {
    use std::os::windows::ffi::OsStrExt;
    Cow::Owned(value.encode_wide().flat_map(u16::to_be_bytes).collect())
}

#[cfg(not(any(unix, windows)))]
fn os_str_bytes(value: &OsStr) -> Cow<'_, [u8]> {
    Cow::Owned(value.to_string_lossy().into_owned().into_bytes())
}

impl InstanceFingerprint {
    /// Compute the fingerprint over exactly the inputs the design names:
    /// instance ID, genesis-record digest, trust epoch, canonical roots, and
    /// the filesystem object identity, owner, and security-relevant
    /// permissions of each root.
    #[must_use]
    pub fn compute(
        instance_id: &InstanceId,
        genesis_digest: &GenesisDigest,
        trust_epoch: TrustEpoch,
        roots: &CanonicalRoots,
        config_root_identity: &RootIdentity,
        data_root_identity: &RootIdentity,
    ) -> Self {
        let mut hasher = Sha256::new();
        absorb(&mut hasher, INSTANCE_FINGERPRINT_LABEL.as_bytes());
        absorb(&mut hasher, instance_id.as_str().as_bytes());
        absorb(&mut hasher, genesis_digest.as_bytes());
        absorb(&mut hasher, &trust_epoch.get().to_be_bytes());
        absorb(&mut hasher, &os_str_bytes(roots.config_root.as_os_str()));
        absorb(&mut hasher, &os_str_bytes(roots.data_root.as_os_str()));
        absorb_identity(&mut hasher, config_root_identity);
        absorb_identity(&mut hasher, data_root_identity);
        Self(hasher.finalize().into())
    }
}

// ---------------------------------------------------------------------------
// Records and registry
// ---------------------------------------------------------------------------

/// Whether a registered target may currently be operated on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetStatus {
    /// Normal operation.
    Active,
    /// Registered but temporarily refusing operations; may return to
    /// `Active`.
    Suspended,
    /// Permanently withdrawn. A retired ID is never reused, so the audit
    /// chain keyed by it stays unambiguous.
    Retired,
}

impl TargetStatus {
    /// Whether an operation may be applied to a target in this state.
    ///
    /// Fail-closed by construction: only `Active` is operable, so a status
    /// added later is non-operable until it is explicitly listed here.
    #[must_use]
    pub const fn is_operable(self) -> bool {
        matches!(self, Self::Active)
    }
}

/// One registered instance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetRecord {
    /// Stable instance identifier; the registry key.
    pub instance_id: InstanceId,
    /// Canonical config and data roots.
    pub canonical_roots: CanonicalRoots,
    /// The instance that was permitted to create this one, if any. `None` is
    /// a root instance created by its own genesis ceremony.
    pub allowed_creation_parent: Option<InstanceId>,
    /// Epoch this record was written under.
    pub trust_epoch: TrustEpoch,
    /// Current status.
    pub status: TargetStatus,
    /// Digest of the genesis record this instance is anchored to.
    pub genesis_digest: GenesisDigest,
    /// Fingerprint as recorded at registration time.
    pub fingerprint: InstanceFingerprint,
}

impl TargetRecord {
    /// Build a record, probing both canonical roots to compute the fingerprint
    /// they currently present.
    ///
    /// # Errors
    ///
    /// Returns [`RecordError::Roots`] when a canonical root cannot be probed,
    /// or [`RecordError::Registry`] when the record names itself as its own
    /// creation parent.
    pub fn register(
        instance_id: InstanceId,
        canonical_roots: CanonicalRoots,
        allowed_creation_parent: Option<InstanceId>,
        trust_epoch: TrustEpoch,
        genesis_digest: GenesisDigest,
    ) -> Result<Self, RecordError> {
        if allowed_creation_parent.as_ref() == Some(&instance_id) {
            return Err(RecordError::Registry(RegistryError::new(
                RegistryErrorCode::SelfParent,
                instance_id.as_str().to_owned(),
            )));
        }
        let fingerprint =
            fingerprint_on_disk(&instance_id, &genesis_digest, trust_epoch, &canonical_roots)
                .map_err(RecordError::Roots)?;
        Ok(Self {
            instance_id,
            canonical_roots,
            allowed_creation_parent,
            trust_epoch,
            status: TargetStatus::Active,
            genesis_digest,
            fingerprint,
        })
    }

    /// Recompute the fingerprint from what the canonical roots present *now*.
    ///
    /// The design requires this under the registry and instance locks before
    /// preview and apply; taking the lock is the caller's responsibility, since
    /// this module owns no locking.
    ///
    /// # Errors
    ///
    /// Propagates the failure to probe either canonical root.
    pub fn recompute_fingerprint(&self) -> std::io::Result<InstanceFingerprint> {
        fingerprint_on_disk(
            &self.instance_id,
            &self.genesis_digest,
            self.trust_epoch,
            &self.canonical_roots,
        )
    }

    /// Whether the roots still present the identity recorded at registration.
    ///
    /// # Errors
    ///
    /// Propagates the failure to probe either canonical root. A probe failure
    /// is **not** reported as "unchanged".
    pub fn fingerprint_is_current(&self) -> std::io::Result<bool> {
        Ok(self.recompute_fingerprint()? == self.fingerprint)
    }
}

fn fingerprint_on_disk(
    instance_id: &InstanceId,
    genesis_digest: &GenesisDigest,
    trust_epoch: TrustEpoch,
    roots: &CanonicalRoots,
) -> std::io::Result<InstanceFingerprint> {
    let config_identity = RootIdentity::probe(&roots.config_root)?;
    let data_identity = RootIdentity::probe(&roots.data_root)?;
    Ok(InstanceFingerprint::compute(
        instance_id,
        genesis_digest,
        trust_epoch,
        roots,
        &config_identity,
        &data_identity,
    ))
}

/// Failure building or refreshing a [`TargetRecord`].
#[derive(Debug)]
pub enum RecordError {
    /// A canonical root could not be probed.
    Roots(std::io::Error),
    /// The record itself was rejected.
    Registry(RegistryError),
}

impl std::fmt::Display for RecordError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Roots(e) => write!(f, "canonical root could not be probed: {e}"),
            Self::Registry(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for RecordError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Roots(e) => Some(e),
            Self::Registry(e) => Some(e),
        }
    }
}

/// The set of registered targets.
///
/// In-memory only. The design's *signed* registry composes this with the
/// approval and audit key once genesis exists; see the module docs.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetRegistry {
    records: BTreeMap<InstanceId, TargetRecord>,
}

impl TargetRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a record, refusing to overwrite an existing instance ID.
    ///
    /// Registration is a meta-authority operation in the design; silently
    /// replacing a record would let one re-registration retarget every future
    /// apply, so a duplicate is an error rather than an update.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryErrorCode::DuplicateInstance`] when the ID is
    /// already registered.
    pub fn insert(&mut self, record: TargetRecord) -> Result<(), RegistryError> {
        match self.records.entry(record.instance_id.clone()) {
            Entry::Occupied(occupied) => Err(RegistryError::new(
                RegistryErrorCode::DuplicateInstance,
                occupied.key().as_str().to_owned(),
            )),
            Entry::Vacant(vacant) => {
                vacant.insert(record);
                Ok(())
            }
        }
    }

    #[must_use]
    pub fn get(&self, instance_id: &InstanceId) -> Option<&TargetRecord> {
        self.records.get(instance_id)
    }

    /// Look up a target that may currently be operated on.
    ///
    /// Returns `None` for an unregistered *or* non-[`TargetStatus::Active`]
    /// instance, so a caller cannot apply to a suspended or retired target by
    /// forgetting to check the status separately.
    #[must_use]
    pub fn get_operable(&self, instance_id: &InstanceId) -> Option<&TargetRecord> {
        self.records
            .get(instance_id)
            .filter(|r| r.status.is_operable())
    }

    pub fn iter(&self) -> impl Iterator<Item = &TargetRecord> {
        self.records.values()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(byte: u8) -> GenesisDigest {
        GenesisDigest::from_bytes([byte; 32])
    }

    fn instance(name: &str) -> InstanceId {
        InstanceId::new(name).expect("test instance id is valid")
    }

    fn identity(mode: u32) -> RootIdentity {
        RootIdentity {
            file_type: RootFileType::Directory,
            object_id: Some(FsObjectId {
                device: 1,
                inode: 2,
            }),
            owner: Some(OwnerId { uid: 501, gid: 20 }),
            unix_mode: Some(mode),
            read_only: false,
        }
    }

    fn roots() -> CanonicalRoots {
        CanonicalRoots::new(
            PathBuf::from("/srv/zeroclaw/config"),
            PathBuf::from("/srv/zeroclaw/data"),
        )
        .expect("absolute test roots")
    }

    fn fingerprint_of(config: &RootIdentity, data: &RootIdentity) -> InstanceFingerprint {
        InstanceFingerprint::compute(
            &instance("alpha"),
            &digest(0xAA),
            TrustEpoch::GENESIS,
            &roots(),
            config,
            data,
        )
    }

    // -- instance id --------------------------------------------------------

    #[test]
    fn instance_id_rejects_path_traversal_and_separators() {
        for bad in ["", ".", "..", "a/b", "a\\b", "a b", "a\0b", "über"] {
            assert!(
                InstanceId::new(bad).is_err(),
                "instance id {bad:?} must be rejected"
            );
        }
        for good in ["a", "default", "prod-01", "a.b_c-1"] {
            assert!(
                InstanceId::new(good).is_ok(),
                "instance id {good:?} must be accepted"
            );
        }
    }

    #[test]
    fn instance_id_length_is_bounded() {
        let ok = "a".repeat(MAX_INSTANCE_ID_LEN);
        assert!(InstanceId::new(ok).is_ok());
        let too_long = "a".repeat(MAX_INSTANCE_ID_LEN + 1);
        let err = InstanceId::new(too_long).expect_err("over-long id must be rejected");
        assert_eq!(err.code, RegistryErrorCode::InvalidInstanceId);
    }

    // -- fingerprint: pure computation --------------------------------------

    #[test]
    fn fingerprint_is_deterministic_for_identical_inputs() {
        assert_eq!(
            fingerprint_of(&identity(0o700), &identity(0o700)),
            fingerprint_of(&identity(0o700), &identity(0o700)),
        );
    }

    #[test]
    fn fingerprint_changes_when_permissions_change() {
        // Guarded by mutation check: dropping the permission fields from
        // `absorb_identity` must make this test fail.
        let before = fingerprint_of(&identity(0o700), &identity(0o700));
        let after = fingerprint_of(&identity(0o777), &identity(0o700));
        assert_ne!(
            before, after,
            "a re-permissioned config root must change the fingerprint"
        );
    }

    #[test]
    fn fingerprint_changes_when_setuid_bit_is_added() {
        // `mode & 0o7777` keeps setuid/setgid/sticky in the digest; masking to
        // 0o777 would silently drop this transition.
        let before = fingerprint_of(&identity(0o755), &identity(0o700));
        let after = fingerprint_of(&identity(0o4755), &identity(0o700));
        assert_ne!(before, after, "adding setuid must change the fingerprint");
    }

    #[test]
    fn fingerprint_changes_when_owner_changes() {
        let mut chowned = identity(0o700);
        chowned.owner = Some(OwnerId { uid: 0, gid: 0 });
        assert_ne!(
            fingerprint_of(&identity(0o700), &identity(0o700)),
            fingerprint_of(&chowned, &identity(0o700)),
            "a chowned config root must change the fingerprint"
        );
    }

    #[test]
    fn fingerprint_changes_when_object_identity_changes() {
        let mut replaced = identity(0o700);
        replaced.object_id = Some(FsObjectId {
            device: 1,
            inode: 999,
        });
        assert_ne!(
            fingerprint_of(&identity(0o700), &identity(0o700)),
            fingerprint_of(&replaced, &identity(0o700)),
            "a replaced root must change the fingerprint"
        );
    }

    #[test]
    fn fingerprint_changes_when_read_only_flag_changes() {
        let mut locked = identity(0o700);
        locked.read_only = true;
        assert_ne!(
            fingerprint_of(&identity(0o700), &identity(0o700)),
            fingerprint_of(&locked, &identity(0o700)),
        );
    }

    #[test]
    fn fingerprint_binds_instance_epoch_genesis_and_roots() {
        let base = fingerprint_of(&identity(0o700), &identity(0o700));
        let id = identity(0o700);

        let other_instance = InstanceFingerprint::compute(
            &instance("beta"),
            &digest(0xAA),
            TrustEpoch::GENESIS,
            &roots(),
            &id,
            &id,
        );
        let other_genesis = InstanceFingerprint::compute(
            &instance("alpha"),
            &digest(0xBB),
            TrustEpoch::GENESIS,
            &roots(),
            &id,
            &id,
        );
        let other_epoch = InstanceFingerprint::compute(
            &instance("alpha"),
            &digest(0xAA),
            TrustEpoch::new(2),
            &roots(),
            &id,
            &id,
        );
        let other_roots = InstanceFingerprint::compute(
            &instance("alpha"),
            &digest(0xAA),
            TrustEpoch::GENESIS,
            &CanonicalRoots::new(
                PathBuf::from("/srv/zeroclaw/config"),
                PathBuf::from("/srv/zeroclaw/other-data"),
            )
            .expect("absolute roots"),
            &id,
            &id,
        );

        for (name, other) in [
            ("instance id", other_instance),
            ("genesis digest", other_genesis),
            ("trust epoch", other_epoch),
            ("canonical roots", other_roots),
        ] {
            assert_ne!(base, other, "fingerprint must commit to the {name}");
        }
    }

    #[test]
    fn fingerprint_encoding_is_unambiguous_across_field_boundaries() {
        // Without length prefixing, moving a character from the end of one
        // path to the start of the next would produce the same digest.
        let id = identity(0o700);
        let a = InstanceFingerprint::compute(
            &instance("alpha"),
            &digest(0xAA),
            TrustEpoch::GENESIS,
            &CanonicalRoots::new(PathBuf::from("/ab"), PathBuf::from("/c")).expect("absolute"),
            &id,
            &id,
        );
        let b = InstanceFingerprint::compute(
            &instance("alpha"),
            &digest(0xAA),
            TrustEpoch::GENESIS,
            &CanonicalRoots::new(PathBuf::from("/a"), PathBuf::from("/bc")).expect("absolute"),
            &id,
            &id,
        );
        assert_ne!(a, b);
    }

    // -- fingerprint: against real directories ------------------------------

    #[test]
    fn probe_reports_a_symlinked_root_as_a_different_identity_than_the_real_dir() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let real = tmp.path().join("real");
        std::fs::create_dir(&real).expect("create real dir");
        let link = tmp.path().join("link");

        #[cfg(unix)]
        std::os::unix::fs::symlink(&real, &link).expect("symlink");
        #[cfg(windows)]
        std::os::windows::fs::symlink_dir(&real, &link).expect("symlink");

        let real_identity = RootIdentity::probe(&real).expect("probe real");
        let link_identity = RootIdentity::probe(&link).expect("probe link");

        assert_eq!(real_identity.file_type, RootFileType::Directory);
        assert_eq!(
            link_identity.file_type,
            RootFileType::Symlink,
            "probe must not follow the final symlink"
        );
        assert_ne!(
            real_identity, link_identity,
            "a symlinked root must not present the real directory's identity"
        );
    }

    #[test]
    fn fingerprint_changes_when_a_registered_root_is_replaced_on_disk() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let config_root = tmp.path().join("config");
        let data_root = tmp.path().join("data");
        std::fs::create_dir(&config_root).expect("create config root");
        std::fs::create_dir(&data_root).expect("create data root");

        let record = TargetRecord::register(
            instance("alpha"),
            CanonicalRoots::new(config_root.clone(), data_root).expect("absolute roots"),
            None,
            TrustEpoch::GENESIS,
            digest(0xAA),
        )
        .expect("register");
        assert!(
            record.fingerprint_is_current().expect("probe"),
            "an untouched root must still match"
        );

        // Replace the config root with a fresh directory at the same path.
        std::fs::remove_dir_all(&config_root).expect("remove config root");
        std::fs::create_dir(&config_root).expect("recreate config root");

        assert!(
            !record
                .fingerprint_is_current()
                .expect("probe after replace"),
            "replacing a registered root must expire the fingerprint"
        );
    }

    #[cfg(unix)]
    #[test]
    fn fingerprint_changes_when_a_registered_root_is_re_permissioned_on_disk() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().expect("tempdir");
        let config_root = tmp.path().join("config");
        let data_root = tmp.path().join("data");
        std::fs::create_dir(&config_root).expect("create config root");
        std::fs::create_dir(&data_root).expect("create data root");
        std::fs::set_permissions(&config_root, std::fs::Permissions::from_mode(0o700))
            .expect("chmod 0700");

        let record = TargetRecord::register(
            instance("alpha"),
            CanonicalRoots::new(config_root.clone(), data_root).expect("absolute roots"),
            None,
            TrustEpoch::GENESIS,
            digest(0xAA),
        )
        .expect("register");
        assert!(record.fingerprint_is_current().expect("probe"));

        // Guarded by mutation check: dropping the permission fields from
        // `absorb_identity` must make this test fail.
        std::fs::set_permissions(&config_root, std::fs::Permissions::from_mode(0o755))
            .expect("chmod 0755");

        assert!(
            !record.fingerprint_is_current().expect("probe after chmod"),
            "re-permissioning a registered root must expire the fingerprint"
        );
    }

    #[test]
    fn fingerprint_is_current_propagates_a_missing_root_instead_of_reporting_unchanged() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let config_root = tmp.path().join("config");
        let data_root = tmp.path().join("data");
        std::fs::create_dir(&config_root).expect("create config root");
        std::fs::create_dir(&data_root).expect("create data root");

        let record = TargetRecord::register(
            instance("alpha"),
            CanonicalRoots::new(config_root.clone(), data_root).expect("absolute roots"),
            None,
            TrustEpoch::GENESIS,
            digest(0xAA),
        )
        .expect("register");

        std::fs::remove_dir_all(&config_root).expect("remove config root");
        assert!(
            record.fingerprint_is_current().is_err(),
            "a vanished root must surface as an error, not as `unchanged`"
        );
    }

    // -- records and registry ----------------------------------------------

    #[test]
    fn canonical_roots_reject_relative_paths() {
        let err = CanonicalRoots::new(PathBuf::from("relative"), PathBuf::from("/abs"))
            .expect_err("relative config root must be rejected");
        assert_eq!(err.code, RegistryErrorCode::RootNotAbsolute);
        let err = CanonicalRoots::new(PathBuf::from("/abs"), PathBuf::from("relative"))
            .expect_err("relative data root must be rejected");
        assert_eq!(err.code, RegistryErrorCode::RootNotAbsolute);
    }

    #[test]
    fn a_record_cannot_be_its_own_creation_parent() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let err = TargetRecord::register(
            instance("alpha"),
            CanonicalRoots::new(tmp.path().to_path_buf(), tmp.path().to_path_buf())
                .expect("absolute roots"),
            Some(instance("alpha")),
            TrustEpoch::GENESIS,
            digest(0xAA),
        )
        .expect_err("self-parent must be rejected");
        match err {
            RecordError::Registry(e) => assert_eq!(e.code, RegistryErrorCode::SelfParent),
            other => panic!("expected a registry error, got {other:?}"),
        }
    }

    #[test]
    fn registry_refuses_to_overwrite_a_registered_instance() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let make = |name: &str| {
            TargetRecord::register(
                instance(name),
                CanonicalRoots::new(tmp.path().to_path_buf(), tmp.path().to_path_buf())
                    .expect("absolute roots"),
                None,
                TrustEpoch::GENESIS,
                digest(0xAA),
            )
            .expect("register")
        };

        let mut registry = TargetRegistry::new();
        assert!(registry.is_empty());
        registry.insert(make("alpha")).expect("first insert");
        registry.insert(make("beta")).expect("second insert");

        let err = registry
            .insert(make("alpha"))
            .expect_err("duplicate must be rejected");
        assert_eq!(err.code, RegistryErrorCode::DuplicateInstance);
        assert_eq!(registry.len(), 2);
    }

    #[test]
    fn only_active_targets_are_operable() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let mut record = TargetRecord::register(
            instance("alpha"),
            CanonicalRoots::new(tmp.path().to_path_buf(), tmp.path().to_path_buf())
                .expect("absolute roots"),
            None,
            TrustEpoch::GENESIS,
            digest(0xAA),
        )
        .expect("register");
        assert_eq!(record.status, TargetStatus::Active);

        let id = instance("alpha");
        let mut registry = TargetRegistry::new();
        registry.insert(record.clone()).expect("insert");
        assert!(registry.get_operable(&id).is_some());

        for status in [TargetStatus::Suspended, TargetStatus::Retired] {
            record.status = status;
            let mut registry = TargetRegistry::new();
            registry.insert(record.clone()).expect("insert");
            assert!(
                registry.get(&id).is_some(),
                "{status:?} must still be visible to `get`"
            );
            assert!(
                registry.get_operable(&id).is_none(),
                "{status:?} must not be operable"
            );
        }
    }

    #[test]
    fn trust_epoch_does_not_wrap_at_the_ceiling() {
        assert_eq!(TrustEpoch::GENESIS.next(), Some(TrustEpoch::new(2)));
        assert_eq!(TrustEpoch::new(u64::MAX).next(), None);
    }

    // -- serde --------------------------------------------------------------

    #[test]
    fn record_round_trips_through_json_with_hex_digests() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let record = TargetRecord::register(
            instance("alpha"),
            CanonicalRoots::new(tmp.path().to_path_buf(), tmp.path().to_path_buf())
                .expect("absolute roots"),
            Some(instance("root")),
            TrustEpoch::new(7),
            digest(0xAA),
        )
        .expect("register");

        let json = serde_json::to_string(&record).expect("serialize");
        assert!(
            json.contains(&"aa".repeat(32)),
            "digests must serialize as hex, got {json}"
        );
        let back: TargetRecord = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(record, back);
    }

    #[test]
    fn registry_round_trips_through_json() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let mut registry = TargetRegistry::new();
        for name in ["alpha", "beta"] {
            registry
                .insert(
                    TargetRecord::register(
                        instance(name),
                        CanonicalRoots::new(tmp.path().to_path_buf(), tmp.path().to_path_buf())
                            .expect("absolute roots"),
                        None,
                        TrustEpoch::GENESIS,
                        digest(0x11),
                    )
                    .expect("register"),
                )
                .expect("insert");
        }
        let json = serde_json::to_string(&registry).expect("serialize");
        let back: TargetRegistry = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(registry, back);
    }

    #[test]
    fn deserializing_rejects_an_invalid_instance_id_and_a_malformed_digest() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let record = TargetRecord::register(
            instance("alpha"),
            CanonicalRoots::new(tmp.path().to_path_buf(), tmp.path().to_path_buf())
                .expect("absolute roots"),
            None,
            TrustEpoch::GENESIS,
            digest(0xAA),
        )
        .expect("register");
        let json = serde_json::to_string(&record).expect("serialize");

        let traversal = json.replace("\"alpha\"", "\"../escape\"");
        assert!(
            serde_json::from_str::<TargetRecord>(&traversal).is_err(),
            "an instance id with a path separator must not deserialize"
        );

        let short_digest = json.replace(&"aa".repeat(32), "aabb");
        assert!(
            serde_json::from_str::<TargetRecord>(&short_digest).is_err(),
            "a truncated digest must not deserialize"
        );
    }

    #[test]
    fn digest_hex_round_trips_and_rejects_bad_input() {
        let d = digest(0x5A);
        assert_eq!(d.to_hex(), "5a".repeat(32));
        assert_eq!(GenesisDigest::from_hex(&d.to_hex()).expect("parse"), d);
        for bad in [
            "",
            "zz",
            &"aa".repeat(31),
            &"aa".repeat(33),
            &"gg".repeat(32),
        ] {
            assert!(
                GenesisDigest::from_hex(bad).is_err(),
                "{bad:?} must not parse as a digest"
            );
        }
    }
}
