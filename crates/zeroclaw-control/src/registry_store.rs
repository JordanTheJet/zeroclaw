//! Signed persistence for the target registry.
//!
//! [`crate::registry`] is the data model; this is the half that puts it on
//! disk. The registry lives at `<data_root>/control/registry.json`, sealed
//! under the ADR-015 key exactly like the genesis record, and it is loaded only
//! through [`load`], which does three things in order and refuses at the first
//! failure:
//!
//! 1. **Authenticates the file.** The tag must verify under the key derived
//!    from this deployment's single key-source authority. A tampered or
//!    unsigned registry is not "a registry with a problem"; it is not a
//!    registry, and every registry-dependent operation refuses.
//! 2. **Re-checks each record against the filesystem.** The instance
//!    fingerprint is recomputed from what the canonical roots present *now* and
//!    must equal what was recorded at registration. Replacing a root,
//!    re-permissioning it, chowning it, or redirecting it through a symlink all
//!    change that value, which is the property [`crate::registry`] was built
//!    to give.
//! 3. **Re-checks the security-relevant shape of each root.** Both roots must
//!    still be directories rather than symlinks, and on Unix neither may be
//!    group- or world-writable. The fingerprint proves *unchanged*; these
//!    checks prove *acceptable*, which is a different question — a root that
//!    was already world-writable at registration would have an entirely
//!    self-consistent fingerprint.
//!
//! ## Whole-file refusal, and why
//!
//! A record that fails step 2 or 3 fails the whole load. In this phase the
//! registry holds exactly one record — the default instance, written by the
//! genesis ceremony — so "one record failed" and "this instance's roots are not
//! what genesis bound" are the same statement, and continuing with a partial
//! registry would mean operating an instance whose identity moved underneath
//! it. When child instances arrive, a multi-record registry will need per-record
//! disposition instead of whole-file refusal; that is a deliberate scope
//! boundary, not an oversight.
//!
//! ## The registry does not survive an epoch break
//!
//! The maintainer decided on issue #26 (item 18) that recovery **discards**
//! registered targets. Nothing here implements recovery, but nothing here
//! implements migration either: a registry sealed under a superseded epoch's
//! key simply fails to authenticate, which is the same outcome by construction.

use zeroclaw_config::secrets::KeySource;

use crate::keys::ApprovalAuditKey;
use crate::registry::{RootFileType, RootIdentity, TargetRecord, TargetRegistry, TrustEpoch};
use crate::store::{
    CanonicalBytes, ControlPaths, absorb_field, absorb_path, absorb_str, absorb_u64, open_sealed,
    publish_replace, read_optional, seal,
};

/// Domain-separation label for the target registry.
pub const TARGET_REGISTRY_DOMAIN: &str = "zeroclaw/control-plane/target-registry/v1";

/// The only target-registry encoding this build understands.
pub const TARGET_REGISTRY_FORMAT_VERSION: u32 = 1;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Why a signed registry could not be produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistryStoreErrorCode {
    /// No registry file exists at the fixed path.
    NotPresent,
    /// The file could not be read, parsed, or authenticated.
    Unverifiable,
    /// A registered root no longer presents the identity it was registered
    /// with.
    FingerprintExpired,
    /// A registered root could not be probed at all.
    RootUnreadable,
    /// A registered root is no longer a directory, or is now a symlink.
    RootShapeUnacceptable,
    /// A registered root is group- or world-writable.
    RootPermissionsUnacceptable,
    /// The registry could not be written.
    NotWritten,
}

/// A registry persistence failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryStoreError {
    pub code: RegistryStoreErrorCode,
    pub detail: String,
}

impl RegistryStoreError {
    fn new(code: RegistryStoreErrorCode, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }
}

impl std::fmt::Display for RegistryStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let what = match self.code {
            RegistryStoreErrorCode::NotPresent => "no target registry",
            RegistryStoreErrorCode::Unverifiable => "target registry could not be verified",
            RegistryStoreErrorCode::FingerprintExpired => "registered root has changed identity",
            RegistryStoreErrorCode::RootUnreadable => "registered root could not be probed",
            RegistryStoreErrorCode::RootShapeUnacceptable => "registered root is not a directory",
            RegistryStoreErrorCode::RootPermissionsUnacceptable => {
                "registered root is writable beyond its owner"
            }
            RegistryStoreErrorCode::NotWritten => "target registry could not be written",
        };
        write!(f, "{what}: {}", self.detail)
    }
}

impl std::error::Error for RegistryStoreError {}

// ---------------------------------------------------------------------------
// Canonical encoding
// ---------------------------------------------------------------------------

/// Absorb one target record.
///
/// Destructured exhaustively, without `..`: an unabsorbed field is an
/// unauthenticated field.
fn absorb_record(out: &mut Vec<u8>, record: &TargetRecord) {
    let TargetRecord {
        instance_id,
        canonical_roots,
        allowed_creation_parent,
        trust_epoch,
        status,
        genesis_digest,
        fingerprint,
    } = record;
    absorb_str(out, instance_id.as_str());
    absorb_path(out, &canonical_roots.config_root);
    absorb_path(out, &canonical_roots.data_root);
    match allowed_creation_parent {
        Some(parent) => {
            absorb_u64(out, 1);
            absorb_str(out, parent.as_str());
        }
        None => absorb_u64(out, 0),
    }
    absorb_u64(out, trust_epoch.get());
    absorb_str(out, status_wire(*status));
    absorb_field(out, genesis_digest.as_bytes());
    absorb_field(out, fingerprint.as_bytes());
}

/// The authenticated spelling of a target status.
///
/// Written out rather than derived from `Debug`, so a rename of a variant is a
/// visible change to what the tag covers rather than a silent one.
fn status_wire(status: crate::registry::TargetStatus) -> &'static str {
    match status {
        crate::registry::TargetStatus::Active => "active",
        crate::registry::TargetStatus::Suspended => "suspended",
        crate::registry::TargetStatus::Retired => "retired",
    }
}

impl CanonicalBytes for TargetRegistry {
    const DOMAIN: &'static str = TARGET_REGISTRY_DOMAIN;
    const FORMAT_VERSION: u32 = TARGET_REGISTRY_FORMAT_VERSION;

    fn absorb_canonical(&self, out: &mut Vec<u8>) {
        // The record count is absorbed first so a truncated registry cannot be
        // presented as a shorter but otherwise valid one.
        absorb_u64(out, self.len() as u64);
        // `TargetRegistry` iterates its `BTreeMap` in instance-id order, so the
        // encoding is deterministic without an explicit sort.
        for record in self.iter() {
            absorb_record(out, record);
        }
    }
}

// ---------------------------------------------------------------------------
// Save and load
// ---------------------------------------------------------------------------

/// Seal and publish the target registry.
///
/// # Errors
///
/// Returns [`RegistryStoreErrorCode::NotWritten`] when the file cannot be
/// encoded or published.
pub fn save(
    paths: &ControlPaths,
    registry: &TargetRegistry,
    key: &ApprovalAuditKey,
) -> Result<(), RegistryStoreError> {
    let bytes = seal(registry, key)
        .map_err(|e| RegistryStoreError::new(RegistryStoreErrorCode::NotWritten, e.detail))?;
    publish_replace(&paths.target_registry(), &bytes)
        .map_err(|e| RegistryStoreError::new(RegistryStoreErrorCode::NotWritten, e.detail))
}

/// Publish the target registry for the first time, refusing to replace one.
///
/// The genesis ceremony uses this so a pre-existing registry on a root that has
/// no genesis record is a refusal rather than something genesis silently
/// overwrites.
///
/// # Errors
///
/// Returns [`RegistryStoreErrorCode::NotWritten`] when a registry is already
/// present or the file cannot be published.
pub fn save_new(
    paths: &ControlPaths,
    registry: &TargetRegistry,
    key: &ApprovalAuditKey,
) -> Result<(), RegistryStoreError> {
    let bytes = seal(registry, key)
        .map_err(|e| RegistryStoreError::new(RegistryStoreErrorCode::NotWritten, e.detail))?;
    crate::store::publish_new(&paths.target_registry(), &bytes)
        .map_err(|e| RegistryStoreError::new(RegistryStoreErrorCode::NotWritten, e.detail))
}

/// Whether a registry file exists at the fixed path.
///
/// Presence only; says nothing about whether it verifies.
#[must_use]
pub fn is_present(paths: &ControlPaths) -> bool {
    paths.target_registry().exists()
}

/// Load, authenticate, and re-verify the target registry.
///
/// # Errors
///
/// See [`RegistryStoreErrorCode`]. Every failure mode refuses; none returns a
/// partially verified registry.
pub fn load(
    paths: &ControlPaths,
    key: &ApprovalAuditKey,
) -> Result<TargetRegistry, RegistryStoreError> {
    let path = paths.target_registry();
    let Some(raw) = read_optional(&path)
        .map_err(|e| RegistryStoreError::new(RegistryStoreErrorCode::Unverifiable, e.detail))?
    else {
        return Err(RegistryStoreError::new(
            RegistryStoreErrorCode::NotPresent,
            path.display().to_string(),
        ));
    };

    let registry: TargetRegistry = open_sealed(&raw, key)
        .map_err(|e| RegistryStoreError::new(RegistryStoreErrorCode::Unverifiable, e.detail))?;

    for record in registry.iter() {
        verify_record(record)?;
    }
    Ok(registry)
}

/// Load the registry using the deployment's own key source.
///
/// A convenience for a caller that has [`ControlPaths`] and an epoch but no
/// derived key; it derives through the same single authority every other path
/// uses rather than accepting one from elsewhere.
///
/// # Errors
///
/// Returns [`RegistryStoreErrorCode::Unverifiable`] when the key cannot be
/// derived, plus everything [`load`] returns.
pub fn load_with_key_source(
    paths: &ControlPaths,
    key_source: &dyn KeySource,
    epoch: TrustEpoch,
) -> Result<TargetRegistry, RegistryStoreError> {
    let key = ApprovalAuditKey::derive(key_source, epoch).map_err(|e| {
        RegistryStoreError::new(RegistryStoreErrorCode::Unverifiable, format!("{e:#}"))
    })?;
    load(paths, &key)
}

/// Re-check one record against the filesystem it names.
fn verify_record(record: &TargetRecord) -> Result<(), RegistryStoreError> {
    for (what, root) in [
        ("config root", &record.canonical_roots.config_root),
        ("data root", &record.canonical_roots.data_root),
    ] {
        let identity = RootIdentity::probe(root).map_err(|e| {
            RegistryStoreError::new(
                RegistryStoreErrorCode::RootUnreadable,
                format!("{} {what} {}: {e}", record.instance_id, root.display()),
            )
        })?;
        if identity.file_type != RootFileType::Directory {
            return Err(RegistryStoreError::new(
                RegistryStoreErrorCode::RootShapeUnacceptable,
                format!(
                    "{} {what} {} is {:?}",
                    record.instance_id,
                    root.display(),
                    identity.file_type
                ),
            ));
        }
        if let Some(mode) = identity.unix_mode
            && mode & 0o022 != 0
        {
            return Err(RegistryStoreError::new(
                RegistryStoreErrorCode::RootPermissionsUnacceptable,
                format!(
                    "{} {what} {} has mode {mode:o}",
                    record.instance_id,
                    root.display()
                ),
            ));
        }
    }

    let current = record.recompute_fingerprint().map_err(|e| {
        RegistryStoreError::new(
            RegistryStoreErrorCode::RootUnreadable,
            format!("{}: {e}", record.instance_id),
        )
    })?;
    if current == record.fingerprint {
        Ok(())
    } else {
        Err(RegistryStoreError::new(
            RegistryStoreErrorCode::FingerprintExpired,
            record.instance_id.to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::{CanonicalRoots, GenesisDigest, InstanceId, TargetStatus, TrustEpoch};
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

    fn record_for(paths: &ControlPaths, name: &str) -> TargetRecord {
        TargetRecord::register(
            InstanceId::new(name).expect("instance id"),
            paths.canonical_roots().expect("roots"),
            None,
            TrustEpoch::GENESIS,
            GenesisDigest::from_bytes([0xAA; 32]),
        )
        .expect("register")
    }

    fn one_record_registry(paths: &ControlPaths) -> TargetRegistry {
        let mut registry = TargetRegistry::new();
        registry
            .insert(record_for(paths, "inst-default"))
            .expect("insert");
        registry
    }

    fn established(tmp: &tempfile::TempDir) -> (ControlPaths, TargetRegistry) {
        let paths = ControlPaths::resolve(&install_root(tmp)).expect("resolve");
        let registry = one_record_registry(&paths);
        save(&paths, &registry, &key(0x11)).expect("save");
        (paths, registry)
    }

    // -- canonical encoding -------------------------------------------------

    #[test]
    fn the_encoding_binds_every_record_field() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let paths = ControlPaths::resolve(&install_root(&tmp)).expect("resolve");
        let base = record_for(&paths, "inst-default");

        let mut baseline = Vec::new();
        absorb_record(&mut baseline, &base);

        let mut other_id = base.clone();
        other_id.instance_id = InstanceId::new("inst-other").expect("id");
        let mut other_roots = base.clone();
        other_roots.canonical_roots =
            CanonicalRoots::new(PathBuf::from("/srv/a"), PathBuf::from("/srv/b")).expect("roots");
        let mut other_parent = base.clone();
        other_parent.allowed_creation_parent = Some(InstanceId::new("inst-parent").expect("id"));
        let mut other_epoch = base.clone();
        other_epoch.trust_epoch = TrustEpoch::new(2);
        let mut other_status = base.clone();
        other_status.status = TargetStatus::Retired;
        let mut other_genesis = base.clone();
        other_genesis.genesis_digest = GenesisDigest::from_bytes([0xBB; 32]);
        let mut other_fingerprint = base.clone();
        other_fingerprint.fingerprint =
            crate::registry::InstanceFingerprint::from_bytes([0xCC; 32]);

        for (name, variant) in [
            ("instance id", other_id),
            ("canonical roots", other_roots),
            ("creation parent", other_parent),
            ("trust epoch", other_epoch),
            ("status", other_status),
            ("genesis digest", other_genesis),
            ("fingerprint", other_fingerprint),
        ] {
            let mut encoded = Vec::new();
            absorb_record(&mut encoded, &variant);
            assert_ne!(baseline, encoded, "the tag must bind the {name}");
        }
    }

    #[test]
    fn the_encoding_binds_the_record_count() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let paths = ControlPaths::resolve(&install_root(&tmp)).expect("resolve");
        let one = one_record_registry(&paths);
        let mut two = one.clone();
        two.insert(record_for(&paths, "inst-second"))
            .expect("insert");

        assert_ne!(
            crate::store::sealed_message(&one),
            crate::store::sealed_message(&two)
        );
    }

    #[test]
    fn the_registrys_serialized_shape_is_records_only() {
        // `TargetRegistry` keeps its records private, so `absorb_canonical`
        // reaches them through `iter()` rather than an exhaustive destructure.
        // This is the substitute guard: a second field would be a field the
        // authentication tag does not cover, and it would show up here.
        let json = serde_json::to_value(TargetRegistry::new()).expect("serialize");
        let object = json.as_object().expect("registry serializes as an object");
        assert_eq!(
            object.keys().collect::<Vec<_>>(),
            vec!["records"],
            "a new TargetRegistry field must be absorbed by absorb_canonical"
        );
    }

    #[test]
    fn the_status_spelling_is_pinned() {
        assert_eq!(status_wire(TargetStatus::Active), "active");
        assert_eq!(status_wire(TargetStatus::Suspended), "suspended");
        assert_eq!(status_wire(TargetStatus::Retired), "retired");
    }

    // -- round trip ---------------------------------------------------------

    #[test]
    fn a_saved_registry_loads_back_identically() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (paths, registry) = established(&tmp);
        let loaded = load(&paths, &key(0x11)).expect("load");
        assert_eq!(loaded, registry);
        assert_eq!(loaded.len(), 1);
    }

    #[test]
    fn loading_derives_through_the_deployment_key_source() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (paths, registry) = established(&tmp);
        let loaded = load_with_key_source(&paths, &FixedKeySource([0x11; 32]), TrustEpoch::GENESIS)
            .expect("load");
        assert_eq!(loaded, registry);
    }

    #[test]
    fn an_absent_registry_is_reported_as_absent_not_empty() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let paths = ControlPaths::resolve(&install_root(&tmp)).expect("resolve");
        assert!(!is_present(&paths));
        let err = load(&paths, &key(0x11)).expect_err("absent registry must not load as empty");
        assert_eq!(err.code, RegistryStoreErrorCode::NotPresent);
    }

    // -- fail closed --------------------------------------------------------

    #[test]
    fn a_tampered_registry_is_refused() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (paths, _) = established(&tmp);
        let raw = std::fs::read(paths.target_registry()).expect("read");
        let mut value: serde_json::Value = serde_json::from_slice(&raw).expect("parse");
        value["payload"]["records"]["inst-default"]["status"] =
            serde_json::Value::String("active".to_string());
        // Add a second, attacker-chosen record under a valid shape.
        let stolen = value["payload"]["records"]["inst-default"].clone();
        value["payload"]["records"]["inst-attacker"] = stolen;
        std::fs::write(
            paths.target_registry(),
            serde_json::to_vec(&value).expect("encode"),
        )
        .expect("write");

        let err = load(&paths, &key(0x11)).expect_err("a tampered registry must be refused");
        assert_eq!(err.code, RegistryStoreErrorCode::Unverifiable);
    }

    #[test]
    fn a_registry_sealed_under_another_key_is_refused() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (paths, _) = established(&tmp);
        let err = load(&paths, &key(0x22)).expect_err("another key must not open the registry");
        assert_eq!(err.code, RegistryStoreErrorCode::Unverifiable);
    }

    #[test]
    fn an_unsigned_registry_is_refused() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let paths = ControlPaths::resolve(&install_root(&tmp)).expect("resolve");
        let registry = one_record_registry(&paths);
        crate::store::publish_new(
            &paths.target_registry(),
            &serde_json::to_vec(&registry).expect("encode"),
        )
        .expect("write bare registry");

        let err = load(&paths, &key(0x11)).expect_err("a bare registry must be refused");
        assert_eq!(err.code, RegistryStoreErrorCode::Unverifiable);
    }

    #[test]
    fn a_genesis_record_copied_over_the_registry_is_refused() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let paths = ControlPaths::resolve(&install_root(&tmp)).expect("resolve");
        let record = crate::genesis::GenesisRecord {
            instance_id: InstanceId::new("inst-default").expect("id"),
            trust_epoch: TrustEpoch::GENESIS,
            canonical_roots: paths.canonical_roots().expect("roots"),
            created_at_unix_secs: 1,
            user_presence_class: crate::genesis::PresenceClass::Terminal,
            first_operator: crate::genesis::FirstOperatorIdentity::new("op").expect("id"),
            host_key_commitment: crate::genesis::KeyCommitment::compute(&key(0x11)),
        };
        let sealed = seal(&record, &key(0x11)).expect("seal");
        crate::store::publish_new(&paths.target_registry(), &sealed).expect("write");

        let err = load(&paths, &key(0x11)).expect_err("a substituted artefact must be refused");
        assert_eq!(err.code, RegistryStoreErrorCode::Unverifiable);
    }

    #[test]
    fn a_replaced_root_expires_the_registry() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (paths, _) = established(&tmp);
        assert!(load(&paths, &key(0x11)).is_ok());

        // Replace the data root with a fresh directory at the same path. Move
        // the sealed registry aside first so it survives the replacement.
        let sealed = std::fs::read(paths.target_registry()).expect("read");
        std::fs::remove_dir_all(paths.data_root()).expect("remove data root");
        std::fs::create_dir_all(paths.control_dir()).expect("recreate");
        std::fs::write(paths.target_registry(), &sealed).expect("restore registry");

        let err = load(&paths, &key(0x11)).expect_err("a replaced root must expire the registry");
        assert_eq!(err.code, RegistryStoreErrorCode::FingerprintExpired);
    }

    #[cfg(unix)]
    #[test]
    fn a_world_writable_root_is_refused() {
        use std::os::unix::fs::PermissionsExt as _;
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = install_root(&tmp);
        std::fs::set_permissions(root.join("data"), std::fs::Permissions::from_mode(0o700))
            .expect("chmod");
        let paths = ControlPaths::resolve(&root).expect("resolve");
        let registry = one_record_registry(&paths);
        save(&paths, &registry, &key(0x11)).expect("save");
        assert!(load(&paths, &key(0x11)).is_ok());

        std::fs::set_permissions(paths.data_root(), std::fs::Permissions::from_mode(0o777))
            .expect("chmod 0777");
        let err = load(&paths, &key(0x11)).expect_err("a world-writable root must be refused");
        // Both checks are correct answers here: the fingerprint commits to the
        // mode, and the shape check rejects the mode outright. Either refusal
        // is fail-closed; assert it is one of them rather than pretending the
        // ordering is part of the contract.
        assert!(
            matches!(
                err.code,
                RegistryStoreErrorCode::RootPermissionsUnacceptable
                    | RegistryStoreErrorCode::FingerprintExpired
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn a_vanished_root_is_refused_rather_than_treated_as_unchanged() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let paths = ControlPaths::resolve(&install_root(&tmp)).expect("resolve");

        // A second instance root, registered and then removed. The registry
        // file itself stays where it is, so the failure is unambiguously the
        // vanished root rather than a missing registry.
        let other = tmp.path().join("other");
        std::fs::create_dir_all(other.join("data")).expect("create other root");
        let mut registry = TargetRegistry::new();
        registry
            .insert(
                TargetRecord::register(
                    InstanceId::new("inst-other").expect("id"),
                    CanonicalRoots::new(
                        std::fs::canonicalize(&other).expect("canonical"),
                        std::fs::canonicalize(other.join("data")).expect("canonical"),
                    )
                    .expect("roots"),
                    None,
                    TrustEpoch::GENESIS,
                    GenesisDigest::from_bytes([0xAA; 32]),
                )
                .expect("register"),
            )
            .expect("insert");
        save(&paths, &registry, &key(0x11)).expect("save");
        assert!(load(&paths, &key(0x11)).is_ok());

        std::fs::remove_dir_all(&other).expect("remove the registered root");
        let err = load(&paths, &key(0x11)).expect_err("a vanished root must refuse");
        assert_eq!(err.code, RegistryStoreErrorCode::RootUnreadable);
    }

    // -- publication --------------------------------------------------------

    #[test]
    fn save_new_refuses_to_replace_an_existing_registry() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (paths, registry) = established(&tmp);
        let err = save_new(&paths, &registry, &key(0x11))
            .expect_err("genesis must not overwrite a registry it did not write");
        assert_eq!(err.code, RegistryStoreErrorCode::NotWritten);
    }

    #[test]
    fn save_replaces_an_existing_registry() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (paths, mut registry) = established(&tmp);
        registry
            .insert(record_for(&paths, "inst-second"))
            .expect("insert");
        save(&paths, &registry, &key(0x11)).expect("save");
        assert_eq!(load(&paths, &key(0x11)).expect("load").len(), 2);
    }

    #[cfg(unix)]
    #[test]
    fn the_registry_is_owner_only_on_disk() {
        use std::os::unix::fs::PermissionsExt as _;
        let tmp = tempfile::tempdir().expect("tempdir");
        let (paths, _) = established(&tmp);
        let mode = std::fs::metadata(paths.target_registry())
            .expect("stat")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }
}
