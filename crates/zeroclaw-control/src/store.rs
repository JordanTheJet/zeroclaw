//! Authenticated, durable on-disk state for the control plane.
//!
//! Three artefacts live under `<data_root>/control/`: the immutable genesis
//! record, the signed target registry, and the signed client registry. This
//! module owns what they have in common:
//!
//! - [`ControlPaths`] — the fixed locations, resolved once from a canonical
//!   install root, with symlinked roots refused before anything is read;
//! - the **sealed envelope** — a JSON wrapper carrying a domain label, a format
//!   version, the payload, and an ADR-015 authentication tag over a canonical
//!   encoding of all three; and
//! - the **publication primitive** — [`publish_new`], which atomically creates
//!   a file that must not already exist.
//!
//! ## Why the tag covers a canonical encoding rather than the JSON bytes
//!
//! JSON is not canonical: key order, whitespace, and number spelling all vary,
//! so a tag over the serialized bytes would break on a serializer change and
//! would tempt a verifier into comparing re-serialized bytes. Instead every
//! sealed type implements [`CanonicalBytes`], which walks its fields into a
//! length-prefixed byte string. The tag is computed over that, so verification
//! parses the JSON and re-derives the encoding from the **parsed values**.
//!
//! The consequence is the property that makes this safe: a field that
//! [`CanonicalBytes::absorb_canonical`] does not absorb is **not
//! authenticated**. Every implementation in this crate therefore destructures
//! `Self` exhaustively, without `..`, so adding a field is a compile error
//! until the encoder is updated.
//!
//! ## Why the domain label is inside the tag
//!
//! Each artefact has its own [`CanonicalBytes::DOMAIN`], and the label is the
//! first thing absorbed. A registry file copied over `genesis.record` therefore
//! fails authentication rather than being parsed as a genesis record that
//! happens to deserialize. The label carries a `/v1` suffix for the same reason
//! [`crate::keys::APPROVAL_AUDIT_LABEL`] does: a change to what is bound is a
//! new label, never a silent reinterpretation.
//!
//! ## Fail-closed, always
//!
//! Every failure in this module is an error. Nothing here falls back to an
//! unauthenticated read, an unverified payload, or a default value. A caller
//! that cannot open a sealed file has learned that the control plane's durable
//! state is unusable, which is a real condition, not a value to be defaulted
//! away.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use rand::TryRng as _;
use rand::rngs::SysRng;
use serde::Serialize;
use serde::de::DeserializeOwned;
use zeroclaw_config::secrets::FileKeySource;

use crate::keys::{ApprovalAuditKey, Tag};
use crate::registry::{CanonicalRoots, os_str_bytes};

/// Directory under the data root that holds every control-plane artefact.
pub const CONTROL_STATE_DIR: &str = "control";

/// File name of the immutable genesis record.
pub const GENESIS_RECORD_FILE: &str = "genesis.record";

/// File name of the signed target registry.
pub const TARGET_REGISTRY_FILE: &str = "registry.json";

/// File name of the signed client registry.
pub const CLIENT_REGISTRY_FILE: &str = "clients.json";

/// The deployment key file, as named by `SecretStore::new`.
///
/// Repeated here rather than invented: ADR-013 allows one key-source authority
/// per deployment, and `zeroclaw_config::secrets::SecretStore::new` already
/// fixes that authority to `<install_root>/.secret_key`. The control plane
/// derives its ADR-015 subkey from the same file and never creates a second
/// key file format.
const DEPLOYMENT_KEY_FILE: &str = ".secret_key";

/// Owner-only permissions for a control-plane file.
#[cfg(unix)]
const OWNER_ONLY_FILE_MODE: u32 = 0o600;

/// Owner-only permissions for the control-plane state directory.
#[cfg(unix)]
const OWNER_ONLY_DIR_MODE: u32 = 0o700;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Stable classification for a durable-state failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreErrorCode {
    /// A canonical root does not exist.
    RootMissing,
    /// A canonical root exists but is not a directory.
    RootNotADirectory,
    /// A canonical root's final path component is a symlink. Following it
    /// would let a link swap redirect every later read and write.
    RootIsSymlink,
    /// A resolved root was not absolute.
    RootNotAbsolute,
    /// The final component of a state file path is a symlink.
    PathIsSymlink,
    /// A file that must not already exist was already there.
    AlreadyPresent,
    /// A filesystem operation failed.
    Io,
    /// A payload could not be encoded.
    Encode,
    /// A sealed file could not be parsed.
    Decode,
    /// The sealed file's domain label is not the one the caller expected.
    DomainMismatch,
    /// The sealed file's format version is not one this build understands.
    FormatVersionUnsupported,
    /// The authentication tag did not verify under the derived key.
    AuthenticationFailed,
}

/// A durable-state failure.
///
/// `detail` carries a path or a diagnostic. It never carries key material,
/// credential bytes, or a payload field value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreError {
    pub code: StoreErrorCode,
    pub detail: String,
}

impl StoreError {
    pub(crate) fn new(code: StoreErrorCode, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }

    fn io(context: &str, error: &std::io::Error) -> Self {
        Self::new(StoreErrorCode::Io, format!("{context}: {error}"))
    }
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let what = match self.code {
            StoreErrorCode::RootMissing => "canonical root is missing",
            StoreErrorCode::RootNotADirectory => "canonical root is not a directory",
            StoreErrorCode::RootIsSymlink => "canonical root is a symlink",
            StoreErrorCode::RootNotAbsolute => "canonical root is not absolute",
            StoreErrorCode::PathIsSymlink => "control-plane state path is a symlink",
            StoreErrorCode::AlreadyPresent => "control-plane state file already exists",
            StoreErrorCode::Io => "control-plane state could not be read or written",
            StoreErrorCode::Encode => "control-plane state could not be encoded",
            StoreErrorCode::Decode => "control-plane state could not be parsed",
            StoreErrorCode::DomainMismatch => "control-plane state has the wrong domain label",
            StoreErrorCode::FormatVersionUnsupported => {
                "control-plane state has an unsupported format version"
            }
            StoreErrorCode::AuthenticationFailed => {
                "control-plane state failed its authentication tag"
            }
        };
        write!(f, "{what}: {}", self.detail)
    }
}

impl std::error::Error for StoreError {}

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

/// The canonical locations of one instance's control-plane state.
///
/// Built from an install root — the directory holding `config.toml`, `data/`,
/// and `shared/`, which the maintainer's issue #26 decision names as the
/// *deployment*. The config root is the install root; the data root is
/// `<install>/data`, matching what `Config::load_or_init` resolves.
///
/// [`ControlPaths::resolve`] canonicalizes both roots and refuses a root whose
/// **final component** is a symlink. Canonicalization resolves symlinked parent
/// components, which is desirable — `/var` pointing at `/private/var` is an
/// ordinary platform fact — but a symlinked root itself is a redirection that
/// would let whoever controls the link point the whole control plane somewhere
/// else after genesis bound the record to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlPaths {
    config_root: PathBuf,
    data_root: PathBuf,
}

impl ControlPaths {
    /// Resolve the control-plane paths for the install root at `install_root`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreErrorCode::RootMissing`] when the install root or its
    /// `data/` directory does not exist, [`StoreErrorCode::RootIsSymlink`] when
    /// either is a symlink, [`StoreErrorCode::RootNotADirectory`] when either
    /// is not a directory, and [`StoreErrorCode::RootNotAbsolute`] when
    /// canonicalization yields a relative path.
    pub fn resolve(install_root: &Path) -> Result<Self, StoreError> {
        let config_root = canonical_directory(install_root, "config root")?;
        let data_root = canonical_directory(&config_root.join("data"), "data root")?;
        Ok(Self {
            config_root,
            data_root,
        })
    }

    /// The canonical config root: the directory holding `config.toml`.
    #[must_use]
    pub fn config_root(&self) -> &Path {
        &self.config_root
    }

    /// The canonical data root: `<config_root>/data`.
    #[must_use]
    pub fn data_root(&self) -> &Path {
        &self.data_root
    }

    /// The roots as the registry data model spells them.
    ///
    /// # Errors
    ///
    /// Returns [`StoreErrorCode::RootNotAbsolute`] when either root is
    /// relative, which canonicalization should already have prevented.
    pub fn canonical_roots(&self) -> Result<CanonicalRoots, StoreError> {
        CanonicalRoots::new(self.config_root.clone(), self.data_root.clone())
            .map_err(|e| StoreError::new(StoreErrorCode::RootNotAbsolute, e.detail))
    }

    /// `<data_root>/control/`.
    #[must_use]
    pub fn control_dir(&self) -> PathBuf {
        self.data_root.join(CONTROL_STATE_DIR)
    }

    /// The fixed path of the genesis record, which is also the
    /// managed-instance marker.
    #[must_use]
    pub fn genesis_record(&self) -> PathBuf {
        self.control_dir().join(GENESIS_RECORD_FILE)
    }

    /// The fixed path of the signed target registry.
    #[must_use]
    pub fn target_registry(&self) -> PathBuf {
        self.control_dir().join(TARGET_REGISTRY_FILE)
    }

    /// The fixed path of the signed client registry.
    #[must_use]
    pub fn client_registry(&self) -> PathBuf {
        self.control_dir().join(CLIENT_REGISTRY_FILE)
    }

    /// The deployment key file this instance's ADR-015 subkey derives from.
    #[must_use]
    pub fn deployment_key_file(&self) -> PathBuf {
        self.config_root.join(DEPLOYMENT_KEY_FILE)
    }

    /// The single ADR-013 key-source authority for this deployment.
    ///
    /// Constructed rather than injected so there is exactly one place in the
    /// control plane that decides which file holds the master key, and it names
    /// the same file `SecretStore::new` does.
    #[must_use]
    pub fn key_source(&self) -> FileKeySource {
        FileKeySource::new(self.deployment_key_file())
    }
}

/// Canonicalize one root, refusing a symlinked final component.
fn canonical_directory(path: &Path, what: &str) -> Result<PathBuf, StoreError> {
    let meta = std::fs::symlink_metadata(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            StoreError::new(
                StoreErrorCode::RootMissing,
                format!("{what} {}", path.display()),
            )
        } else {
            StoreError::io(&format!("{what} {}", path.display()), &e)
        }
    })?;
    if meta.file_type().is_symlink() {
        return Err(StoreError::new(
            StoreErrorCode::RootIsSymlink,
            format!("{what} {}", path.display()),
        ));
    }
    if !meta.is_dir() {
        return Err(StoreError::new(
            StoreErrorCode::RootNotADirectory,
            format!("{what} {}", path.display()),
        ));
    }
    let canonical = std::fs::canonicalize(path)
        .map_err(|e| StoreError::io(&format!("{what} {}", path.display()), &e))?;
    if !canonical.is_absolute() {
        return Err(StoreError::new(
            StoreErrorCode::RootNotAbsolute,
            format!("{what} {}", canonical.display()),
        ));
    }
    Ok(canonical)
}

// ---------------------------------------------------------------------------
// Canonical encoding
// ---------------------------------------------------------------------------

/// Absorb one field with an explicit length prefix.
///
/// Length prefixing is what makes the encoding unambiguous: without it,
/// adjacent variable-length fields could be re-split to produce the same bytes
/// from different values.
pub(crate) fn absorb_field(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// Absorb a string field.
pub(crate) fn absorb_str(out: &mut Vec<u8>, value: &str) {
    absorb_field(out, value.as_bytes());
}

/// Absorb a `u64` field.
pub(crate) fn absorb_u64(out: &mut Vec<u8>, value: u64) {
    absorb_field(out, &value.to_be_bytes());
}

/// Absorb a path field, using the platform-deterministic `OsStr` encoding the
/// instance fingerprint already uses.
pub(crate) fn absorb_path(out: &mut Vec<u8>, value: &Path) {
    absorb_field(out, &os_str_bytes(value.as_os_str()));
}

/// A type that can be sealed under the ADR-015 key.
///
/// # Implementation contract
///
/// [`Self::absorb_canonical`] **must** destructure `Self` exhaustively, without
/// a `..` rest pattern. A field it does not absorb is a field the
/// authentication tag does not cover, and an attacker who can write the file
/// could then change that field freely.
pub(crate) trait CanonicalBytes {
    /// Domain-separation label bound into the tag.
    const DOMAIN: &'static str;
    /// Format version bound into the tag.
    const FORMAT_VERSION: u32;

    /// Append this value's canonical encoding to `out`.
    fn absorb_canonical(&self, out: &mut Vec<u8>);
}

/// The exact byte string the authentication tag is computed over.
pub(crate) fn sealed_message<T: CanonicalBytes>(payload: &T) -> Vec<u8> {
    let mut out = Vec::new();
    absorb_str(&mut out, T::DOMAIN);
    absorb_u64(&mut out, u64::from(T::FORMAT_VERSION));
    payload.absorb_canonical(&mut out);
    out
}

// ---------------------------------------------------------------------------
// Sealed envelope
// ---------------------------------------------------------------------------

/// The on-disk shape of every sealed control-plane artefact.
#[derive(Debug, Serialize, serde::Deserialize)]
struct Envelope<T> {
    /// Which artefact this is. Checked against `T::DOMAIN` and bound into the
    /// tag, so a file cannot be repurposed by renaming it.
    domain: String,
    /// Which encoding of that artefact this is.
    format_version: u32,
    /// The artefact itself.
    payload: T,
    /// Hex-encoded ADR-015 tag over [`sealed_message`].
    authentication_tag: String,
}

/// Serialize `payload` into a sealed envelope, authenticated under `key`.
///
/// # Errors
///
/// Returns [`StoreErrorCode::Encode`] when the payload cannot be serialized.
pub(crate) fn seal<T: CanonicalBytes + Serialize>(
    payload: &T,
    key: &ApprovalAuditKey,
) -> Result<Vec<u8>, StoreError> {
    let tag = key.sign(&sealed_message(payload));
    let envelope = Envelope {
        domain: T::DOMAIN.to_string(),
        format_version: T::FORMAT_VERSION,
        payload,
        authentication_tag: tag.to_hex(),
    };
    let mut bytes = serde_json::to_vec_pretty(&envelope)
        .map_err(|e| StoreError::new(StoreErrorCode::Encode, format!("{}: {e}", T::DOMAIN)))?;
    bytes.push(b'\n');
    Ok(bytes)
}

/// Parse and authenticate a sealed envelope.
///
/// The order is deliberate: parse, check the domain and version, then verify
/// the tag over the encoding rebuilt from the parsed payload. A caller receives
/// a `T` only when all four succeed.
///
/// # Errors
///
/// Returns [`StoreErrorCode::Decode`] for malformed JSON or a malformed tag,
/// [`StoreErrorCode::DomainMismatch`] when the envelope names another artefact,
/// [`StoreErrorCode::FormatVersionUnsupported`] for an unknown version, and
/// [`StoreErrorCode::AuthenticationFailed`] when the tag does not verify.
pub(crate) fn open_sealed<T: CanonicalBytes + DeserializeOwned>(
    bytes: &[u8],
    key: &ApprovalAuditKey,
) -> Result<T, StoreError> {
    let envelope: Envelope<T> = serde_json::from_slice(bytes)
        .map_err(|e| StoreError::new(StoreErrorCode::Decode, format!("{}: {e}", T::DOMAIN)))?;

    if envelope.domain != T::DOMAIN {
        // Do not echo the claimed domain verbatim; it is attacker-controlled
        // text from a file that just failed a trust check.
        return Err(StoreError::new(
            StoreErrorCode::DomainMismatch,
            format!("expected {}", T::DOMAIN),
        ));
    }
    if envelope.format_version != T::FORMAT_VERSION {
        return Err(StoreError::new(
            StoreErrorCode::FormatVersionUnsupported,
            format!(
                "{} declares version {}, this build understands {}",
                T::DOMAIN,
                envelope.format_version,
                T::FORMAT_VERSION
            ),
        ));
    }

    let mut tag_bytes = [0u8; 32];
    hex::decode_to_slice(&envelope.authentication_tag, &mut tag_bytes).map_err(|e| {
        StoreError::new(
            StoreErrorCode::Decode,
            format!("{} authentication tag: {e}", T::DOMAIN),
        )
    })?;

    if key.verify(
        &sealed_message(&envelope.payload),
        &Tag::from_bytes(tag_bytes),
    ) {
        Ok(envelope.payload)
    } else {
        Err(StoreError::new(
            StoreErrorCode::AuthenticationFailed,
            T::DOMAIN.to_string(),
        ))
    }
}

// ---------------------------------------------------------------------------
// Publication
// ---------------------------------------------------------------------------

/// Create the control-plane state directory, owner-only.
///
/// # Errors
///
/// Propagates the directory creation failure.
pub(crate) fn ensure_state_dir(dir: &Path) -> Result<(), StoreError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true).mode(OWNER_ONLY_DIR_MODE);
        builder
            .create(dir)
            .map_err(|e| StoreError::io(&format!("create {}", dir.display()), &e))
    }
    #[cfg(not(unix))]
    {
        // No portable owner-only directory mode outside Unix. The directory
        // inherits the parent ACL; hardening it is follow-up work, recorded as
        // a limitation rather than silently assumed away.
        std::fs::create_dir_all(dir)
            .map_err(|e| StoreError::io(&format!("create {}", dir.display()), &e))
    }
}

/// Write `bytes` to `path`, which **must not already exist**.
///
/// Used for the genesis record and for state a ceremony establishes once. The
/// exclusive creation is what makes two concurrent ceremonies resolve to one
/// winner rather than to a last-writer-wins overwrite.
///
/// The sequence is: reserve the final name with an exclusive create, write the
/// content to a temporary file, fsync it, rename the temporary over our own
/// reservation, and fsync the directory. A crash between the reservation and
/// the rename leaves an empty file, which every reader in this crate treats as
/// present-but-invalid — the designed fail-closed state, not a silent success.
///
/// # Errors
///
/// Returns [`StoreErrorCode::AlreadyPresent`] when the path exists,
/// [`StoreErrorCode::PathIsSymlink`] when it is a symlink, and
/// [`StoreErrorCode::Io`] for any filesystem failure.
pub(crate) fn publish_new(path: &Path, bytes: &[u8]) -> Result<(), StoreError> {
    prepare_publication(path)?;

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(OWNER_ONLY_FILE_MODE);
    }
    match options.open(path) {
        Ok(file) => drop(file),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(StoreError::new(
                StoreErrorCode::AlreadyPresent,
                path.display().to_string(),
            ));
        }
        Err(e) => return Err(StoreError::io(&format!("reserve {}", path.display()), &e)),
    }

    // The reservation is ours exclusively, so removing it on failure cannot
    // destroy another writer's file.
    match write_then_rename(path, bytes) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = std::fs::remove_file(path);
            Err(e)
        }
    }
}

/// Create the parent directory and refuse a symlinked destination.
fn prepare_publication(path: &Path) -> Result<(), StoreError> {
    if let Some(parent) = path.parent() {
        ensure_state_dir(parent)?;
    }
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => Err(StoreError::new(
            StoreErrorCode::PathIsSymlink,
            path.display().to_string(),
        )),
        Ok(_) | Err(_) => Ok(()),
    }
}

/// Write to a temporary sibling, fsync it, rename it into place, fsync the
/// directory.
fn write_then_rename(path: &Path, bytes: &[u8]) -> Result<(), StoreError> {
    let temp = temp_sibling(path)?;
    let result = (|| -> Result<(), StoreError> {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(OWNER_ONLY_FILE_MODE);
        }
        let mut file = options
            .open(&temp)
            .map_err(|e| StoreError::io(&format!("create {}", temp.display()), &e))?;
        file.write_all(bytes)
            .map_err(|e| StoreError::io(&format!("write {}", temp.display()), &e))?;
        file.flush()
            .map_err(|e| StoreError::io(&format!("flush {}", temp.display()), &e))?;
        file.sync_all()
            .map_err(|e| StoreError::io(&format!("fsync {}", temp.display()), &e))?;
        drop(file);
        std::fs::rename(&temp, path)
            .map_err(|e| StoreError::io(&format!("publish {}", path.display()), &e))?;
        sync_parent_dir(path)
    })();

    if result.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    result
}

/// A unique temporary sibling name.
///
/// The suffix comes from the OS random source rather than a counter so a
/// crashed run's leftover temporary can never collide with a live one.
fn temp_sibling(path: &Path) -> Result<PathBuf, StoreError> {
    let mut nonce = [0u8; 8];
    SysRng.try_fill_bytes(&mut nonce).map_err(|e| {
        StoreError::new(
            StoreErrorCode::Io,
            format!("operating system random source unavailable: {e}"),
        )
    })?;
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "control-state".to_string());
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    Ok(parent.join(format!(".{name}.tmp-{}", hex::encode(nonce))))
}

/// Make the new directory entry crash-durable.
///
/// # Platform
///
/// Unix only. Windows has no portable directory fsync through `std`; the
/// rename itself is atomic there, so a crash cannot expose a partial file, but
/// the *name* may not survive a power loss. Recorded as a limitation.
#[cfg(unix)]
fn sync_parent_dir(path: &Path) -> Result<(), StoreError> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    let dir = std::fs::File::open(parent)
        .map_err(|e| StoreError::io(&format!("open {}", parent.display()), &e))?;
    dir.sync_all()
        .map_err(|e| StoreError::io(&format!("fsync {}", parent.display()), &e))
}

#[cfg(not(unix))]
fn sync_parent_dir(_path: &Path) -> Result<(), StoreError> {
    Ok(())
}

/// Read a control-plane state file.
///
/// # Errors
///
/// Returns [`StoreErrorCode::PathIsSymlink`] when the final component is a
/// symlink and [`StoreErrorCode::Io`] for any other read failure, including
/// `NotFound`, which callers distinguish by checking the presence separately.
pub(crate) fn read_state_file(path: &Path) -> Result<Vec<u8>, StoreError> {
    let meta = std::fs::symlink_metadata(path)
        .map_err(|e| StoreError::io(&format!("stat {}", path.display()), &e))?;
    if meta.file_type().is_symlink() {
        return Err(StoreError::new(
            StoreErrorCode::PathIsSymlink,
            path.display().to_string(),
        ));
    }
    if !meta.is_file() {
        return Err(StoreError::new(
            StoreErrorCode::Io,
            format!("{} is not a regular file", path.display()),
        ));
    }
    std::fs::read(path).map_err(|e| StoreError::io(&format!("read {}", path.display()), &e))
}

/// 32 bytes from the operating system random source.
///
/// # Errors
///
/// Propagates the failure rather than falling back to a userspace generator: a
/// host whose OS random source is unavailable must not mint a credential.
pub(crate) fn os_random_32() -> Result<[u8; 32], StoreError> {
    let mut bytes = [0u8; 32];
    SysRng.try_fill_bytes(&mut bytes).map_err(|e| {
        StoreError::new(
            StoreErrorCode::Io,
            format!("operating system random source unavailable: {e}"),
        )
    })?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::TrustEpoch;
    use zeroclaw_config::secrets::{KeySource, ProvisioningState};

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

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
    struct Alpha {
        left: String,
        right: u64,
    }

    impl CanonicalBytes for Alpha {
        const DOMAIN: &'static str = "zeroclaw/control-plane/test-alpha/v1";
        const FORMAT_VERSION: u32 = 1;

        fn absorb_canonical(&self, out: &mut Vec<u8>) {
            let Self { left, right } = self;
            absorb_str(out, left);
            absorb_u64(out, *right);
        }
    }

    /// Same wire shape as `Alpha`, different domain label.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
    struct Beta {
        left: String,
        right: u64,
    }

    impl CanonicalBytes for Beta {
        const DOMAIN: &'static str = "zeroclaw/control-plane/test-beta/v1";
        const FORMAT_VERSION: u32 = 1;

        fn absorb_canonical(&self, out: &mut Vec<u8>) {
            let Self { left, right } = self;
            absorb_str(out, left);
            absorb_u64(out, *right);
        }
    }

    fn alpha() -> Alpha {
        Alpha {
            left: "one".to_string(),
            right: 2,
        }
    }

    // -- canonical encoding -------------------------------------------------

    #[test]
    fn length_prefixing_makes_adjacent_fields_unambiguous() {
        let mut ab = Vec::new();
        absorb_str(&mut ab, "ab");
        absorb_str(&mut ab, "c");
        let mut a_bc = Vec::new();
        absorb_str(&mut a_bc, "a");
        absorb_str(&mut a_bc, "bc");
        assert_ne!(ab, a_bc);
    }

    #[test]
    fn the_sealed_message_starts_with_the_domain_label() {
        let message = sealed_message(&alpha());
        assert!(
            message
                .windows(Alpha::DOMAIN.len())
                .any(|w| w == Alpha::DOMAIN.as_bytes()),
            "the domain label must be bound into the tag"
        );
    }

    #[test]
    fn two_domains_with_the_same_payload_shape_seal_differently() {
        let a = sealed_message(&alpha());
        let b = sealed_message(&Beta {
            left: "one".to_string(),
            right: 2,
        });
        assert_ne!(a, b, "the domain label must separate two artefacts");
    }

    // -- sealing ------------------------------------------------------------

    #[test]
    fn seal_and_open_round_trip() {
        let k = key(0x11);
        let sealed = seal(&alpha(), &k).expect("seal");
        let opened: Alpha = open_sealed(&sealed, &k).expect("open");
        assert_eq!(opened, alpha());
    }

    #[test]
    fn a_tampered_payload_fails_authentication() {
        let k = key(0x11);
        let sealed = seal(&alpha(), &k).expect("seal");
        let tampered = String::from_utf8(sealed)
            .expect("utf-8")
            .replace("\"one\"", "\"two\"");
        let err = open_sealed::<Alpha>(tampered.as_bytes(), &k)
            .expect_err("a tampered payload must not open");
        assert_eq!(err.code, StoreErrorCode::AuthenticationFailed);
    }

    #[test]
    fn a_tampered_tag_fails_authentication() {
        let k = key(0x11);
        let sealed = seal(&alpha(), &k).expect("seal");
        let mut value: serde_json::Value = serde_json::from_slice(&sealed).expect("parse");
        let tag = value["authentication_tag"]
            .as_str()
            .expect("tag is a string")
            .to_string();
        // Flip the low bit of the first tag byte, keeping the length valid.
        let mut bytes = [0u8; 32];
        hex::decode_to_slice(&tag, &mut bytes).expect("tag is hex");
        bytes[0] ^= 0x01;
        value["authentication_tag"] = serde_json::Value::String(hex::encode(bytes));
        let tampered = serde_json::to_vec(&value).expect("re-encode");
        let err = open_sealed::<Alpha>(&tampered, &k).expect_err("a tampered tag must not open");
        assert_eq!(err.code, StoreErrorCode::AuthenticationFailed);
    }

    #[test]
    fn a_file_sealed_under_another_key_does_not_open() {
        let sealed = seal(&alpha(), &key(0x11)).expect("seal");
        let err = open_sealed::<Alpha>(&sealed, &key(0x22))
            .expect_err("another host's key must not open this file");
        assert_eq!(err.code, StoreErrorCode::AuthenticationFailed);
    }

    #[test]
    fn a_file_from_another_domain_does_not_open_even_with_a_matching_shape() {
        let k = key(0x11);
        let sealed = seal(
            &Beta {
                left: "one".to_string(),
                right: 2,
            },
            &k,
        )
        .expect("seal");
        let err = open_sealed::<Alpha>(&sealed, &k)
            .expect_err("a renamed artefact must not be parsed as another");
        assert_eq!(err.code, StoreErrorCode::DomainMismatch);
    }

    #[test]
    fn a_domain_label_forged_in_the_envelope_still_fails_authentication() {
        // Swapping only the label past the domain check must not help: the
        // tag was computed over the *other* domain's message.
        let k = key(0x11);
        let sealed = seal(
            &Beta {
                left: "one".to_string(),
                right: 2,
            },
            &k,
        )
        .expect("seal");
        let forged = String::from_utf8(sealed)
            .expect("utf-8")
            .replace(Beta::DOMAIN, Alpha::DOMAIN);
        let err = open_sealed::<Alpha>(forged.as_bytes(), &k).expect_err("forged label must fail");
        assert_eq!(err.code, StoreErrorCode::AuthenticationFailed);
    }

    #[test]
    fn an_unknown_format_version_is_refused() {
        let k = key(0x11);
        let sealed = seal(&alpha(), &k).expect("seal");
        let bumped = String::from_utf8(sealed)
            .expect("utf-8")
            .replace("\"format_version\": 1", "\"format_version\": 2");
        let err =
            open_sealed::<Alpha>(bumped.as_bytes(), &k).expect_err("unknown version must fail");
        assert_eq!(err.code, StoreErrorCode::FormatVersionUnsupported);
    }

    #[test]
    fn garbage_is_refused_as_unparseable() {
        let err = open_sealed::<Alpha>(b"not json at all", &key(0x11)).expect_err("garbage");
        assert_eq!(err.code, StoreErrorCode::Decode);
        let err = open_sealed::<Alpha>(b"", &key(0x11)).expect_err("empty");
        assert_eq!(err.code, StoreErrorCode::Decode);
    }

    // -- publication --------------------------------------------------------

    #[test]
    fn publish_new_refuses_a_second_write() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("control").join("once");
        publish_new(&path, b"first").expect("first publish");
        let err = publish_new(&path, b"second").expect_err("second publish must be refused");
        assert_eq!(err.code, StoreErrorCode::AlreadyPresent);
        assert_eq!(std::fs::read(&path).expect("read"), b"first");
    }

    #[test]
    fn publication_leaves_no_temporary_behind() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let dir = tmp.path().join("control");
        publish_new(&dir.join("file"), b"content").expect("publish");
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .expect("read dir")
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|name| name != "file")
            .collect();
        assert!(
            leftovers.is_empty(),
            "temporaries left behind: {leftovers:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn published_files_and_directories_are_owner_only() {
        use std::os::unix::fs::PermissionsExt as _;
        let tmp = tempfile::tempdir().expect("tempdir");
        let dir = tmp.path().join("control");
        let path = dir.join("file");
        publish_new(&path, b"content").expect("publish");
        let file_mode = std::fs::metadata(&path).expect("stat").permissions().mode() & 0o777;
        assert_eq!(file_mode, 0o600, "state file must be owner-only");
        let dir_mode = std::fs::metadata(&dir).expect("stat").permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700, "state directory must be owner-only");
    }

    #[cfg(unix)]
    #[test]
    fn publishing_through_a_symlink_is_refused() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let dir = tmp.path().join("control");
        std::fs::create_dir_all(&dir).expect("mkdir");
        let elsewhere = tmp.path().join("elsewhere");
        std::fs::write(&elsewhere, b"victim").expect("write victim");
        let link = dir.join("file");
        std::os::unix::fs::symlink(&elsewhere, &link).expect("symlink");

        let err = publish_new(&link, b"attacker").expect_err("symlink must be refused");
        assert_eq!(err.code, StoreErrorCode::PathIsSymlink);
        assert_eq!(
            std::fs::read(&elsewhere).expect("read"),
            b"victim",
            "the symlink target must be untouched"
        );
    }

    #[cfg(unix)]
    #[test]
    fn reading_through_a_symlink_is_refused() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let real = tmp.path().join("real");
        std::fs::write(&real, b"content").expect("write");
        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(&real, &link).expect("symlink");
        let err = read_state_file(&link).expect_err("symlink must be refused");
        assert_eq!(err.code, StoreErrorCode::PathIsSymlink);
    }

    // -- paths --------------------------------------------------------------

    fn install_root(tmp: &tempfile::TempDir) -> PathBuf {
        let root = tmp.path().join("install");
        std::fs::create_dir_all(root.join("data")).expect("create install root");
        root
    }

    #[test]
    fn resolve_pins_every_control_plane_path_under_the_data_root() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = install_root(&tmp);
        let paths = ControlPaths::resolve(&root).expect("resolve");

        assert_eq!(paths.data_root(), paths.config_root().join("data"));
        assert_eq!(paths.control_dir(), paths.data_root().join("control"));
        assert_eq!(
            paths.genesis_record(),
            paths.control_dir().join("genesis.record")
        );
        assert_eq!(
            paths.target_registry(),
            paths.control_dir().join("registry.json")
        );
        assert_eq!(
            paths.client_registry(),
            paths.control_dir().join("clients.json")
        );
        assert_eq!(
            paths.deployment_key_file(),
            paths.config_root().join(".secret_key"),
            "the control plane must derive from the deployment key file, not a second one"
        );
    }

    #[test]
    fn resolve_refuses_a_missing_root() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let err = ControlPaths::resolve(&tmp.path().join("absent")).expect_err("missing root");
        assert_eq!(err.code, StoreErrorCode::RootMissing);

        let no_data = tmp.path().join("no-data");
        std::fs::create_dir_all(&no_data).expect("mkdir");
        let err = ControlPaths::resolve(&no_data).expect_err("missing data root");
        assert_eq!(err.code, StoreErrorCode::RootMissing);
    }

    #[cfg(unix)]
    #[test]
    fn resolve_refuses_a_symlinked_data_root() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = tmp.path().join("install");
        std::fs::create_dir_all(&root).expect("mkdir");
        let elsewhere = tmp.path().join("elsewhere");
        std::fs::create_dir_all(&elsewhere).expect("mkdir");
        std::os::unix::fs::symlink(&elsewhere, root.join("data")).expect("symlink");

        let err = ControlPaths::resolve(&root).expect_err("symlinked data root must be refused");
        assert_eq!(err.code, StoreErrorCode::RootIsSymlink);
    }

    #[cfg(unix)]
    #[test]
    fn resolve_refuses_a_symlinked_config_root() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let real = tmp.path().join("real");
        std::fs::create_dir_all(real.join("data")).expect("mkdir");
        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(&real, &link).expect("symlink");

        let err = ControlPaths::resolve(&link).expect_err("symlinked config root must be refused");
        assert_eq!(err.code, StoreErrorCode::RootIsSymlink);
    }

    #[test]
    fn resolve_refuses_a_root_that_is_not_a_directory() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let file = tmp.path().join("a-file");
        std::fs::write(&file, b"not a directory").expect("write");
        let err = ControlPaths::resolve(&file).expect_err("file root must be refused");
        assert_eq!(err.code, StoreErrorCode::RootNotADirectory);
    }

    // -- randomness ---------------------------------------------------------

    #[test]
    fn os_random_32_is_not_constant() {
        let a = os_random_32().expect("os random");
        let b = os_random_32().expect("os random");
        assert_ne!(a, b);
        assert!(a.iter().any(|&byte| byte != 0), "all-zero draw");
    }
}
