//! The control-plane approval and audit key (ADR-015).
//!
//! [ADR-015] decides that the approval and audit key is an **HKDF-SHA256
//! subkey derived from the single ADR-013 key-source authority**, under the
//! fixed domain-separation label [`APPROVAL_AUDIT_LABEL`]. It is never
//! exportable and is exposed only through sign and verify operations, so raw
//! approval-key bytes never reach a requester-facing surface and a later move
//! to a separate key source would not change this interface.
//!
//! [ADR-015]: ../../../docs/book/src/architecture/decisions/ADR-015-control-plane-approval-audit-key.md
//!
//! ## Why HMAC-SHA256 tags in v1
//!
//! The parent design says the receipt broker "signs or authenticates" a
//! receipt, and ADR-015 requires the *interface* to be sign/verify without
//! fixing the primitive. v1 authenticates with HMAC-SHA256 over the message,
//! because the derived key is symmetric: the same host both issues and checks
//! receipts, so a symmetric authenticator is sufficient and adds no key
//! material beyond the subkey.
//!
//! The consequence is explicit: **a [`Tag`] proves only that a holder of the
//! derived key produced it.** It is not a public-key signature and cannot be
//! verified by a third party who is not trusted to mint tags. Should receipts
//! ever need third-party verifiability, that is a new label
//! (`.../approval-audit/v2`) carrying an asymmetric key, and this module's
//! `sign`/`verify` shape is what lets that swap happen without changing
//! callers.
//!
//! ## Why the derivation is written out here
//!
//! There is no `hkdf` crate in the workspace dependency graph, but `hmac` and
//! `sha2` both are. RFC 5869 extract-and-expand is ~30 lines over an existing
//! HMAC, so it is implemented here against the published test vectors rather
//! than pulling in a new dependency for it.
//!
//! ## Scope
//!
//! This module derives the key and authenticates byte strings. It does not
//! define the receipt format, compute `host_key_commitment`, or persist
//! anything — those belong to the genesis ceremony and the phase-4 receipt
//! broker.

use anyhow::{Context, Result, bail};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroclaw_config::secrets::KeySource;

use crate::registry::TrustEpoch;

type HmacSha256 = Hmac<Sha256>;

/// Output length of SHA-256, in bytes.
const HASH_LEN: usize = 32;

/// The fixed domain-separation label from ADR-015.
///
/// Binding the subkey to this label is what keeps it from colliding with the
/// `enc2:` encryption use of the same master key. The trailing `/v1` means a
/// later contract change is a new label rather than a silent reinterpretation.
pub const APPROVAL_AUDIT_LABEL: &str = "zeroclaw/control-plane/approval-audit/v1";

// ---------------------------------------------------------------------------
// RFC 5869 HKDF-SHA256
// ---------------------------------------------------------------------------

/// RFC 5869 §2.2 extract: `PRK = HMAC-Hash(salt, IKM)`.
///
/// An empty `salt` is equivalent to the RFC's "HashLen zeros" default, because
/// HMAC zero-pads any key shorter than its block size.
fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; HASH_LEN] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(salt)
        .unwrap_or_else(|_| unreachable!("HMAC-SHA256 accepts a key of any length"));
    mac.update(ikm);
    mac.finalize().into_bytes().into()
}

/// RFC 5869 §2.3 expand.
///
/// # Errors
///
/// Returns an error when `okm` is longer than `255 * HashLen`, the RFC's
/// maximum output length.
fn hkdf_expand(prk: &[u8; HASH_LEN], info: &[u8], okm: &mut [u8]) -> Result<()> {
    if okm.len() > 255 * HASH_LEN {
        bail!(
            "HKDF-SHA256 cannot expand to {} bytes; the RFC 5869 maximum is {}",
            okm.len(),
            255 * HASH_LEN
        );
    }
    let mut previous: Vec<u8> = Vec::new();
    for (block, chunk) in okm.chunks_mut(HASH_LEN).enumerate() {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(prk)
            .unwrap_or_else(|_| unreachable!("HMAC-SHA256 accepts a key of any length"));
        mac.update(&previous);
        mac.update(info);
        // Counter is 1-based and `block` is bounded by the 255-block check
        // above, so this cast cannot truncate.
        mac.update(&[(block + 1) as u8]);
        let t = mac.finalize().into_bytes();
        chunk.copy_from_slice(&t[..chunk.len()]);
        previous.clear();
        previous.extend_from_slice(&t);
    }
    Ok(())
}

/// Build the HKDF `info` string: the domain-separation label, an unambiguous
/// separator, then the trust epoch.
///
/// The epoch is included so that an epoch transition re-derives the key: a tag
/// minted under a superseded epoch cannot verify under the current one. See
/// the note on this in the crate-level docs for `derive`.
fn subkey_info(label: &str, epoch: TrustEpoch) -> Vec<u8> {
    let mut info = Vec::with_capacity(label.len() + 1 + 8);
    info.extend_from_slice(label.as_bytes());
    // `\0` cannot appear in a label, so no (label, epoch) pair can be
    // re-split into a different pair with the same encoding.
    info.push(0);
    info.extend_from_slice(&epoch.get().to_be_bytes());
    info
}

/// Derive a 32-byte subkey from master key material.
///
/// Empty salt plus the label in `info` is the construction ADR-015 cites from
/// TLS 1.3 and AWS request signing.
fn derive_subkey(master: &[u8; 32], label: &str, epoch: TrustEpoch) -> Result<[u8; 32]> {
    let prk = hkdf_extract(&[], master);
    let mut okm = [0u8; 32];
    hkdf_expand(&prk, &subkey_info(label, epoch), &mut okm)?;
    Ok(okm)
}

// ---------------------------------------------------------------------------
// Tags
// ---------------------------------------------------------------------------

/// An authentication tag over a message.
///
/// A tag is an output, not a secret, so it prints in full. Deliberately no
/// `PartialEq`: comparing two tags with `==` would be a variable-time
/// comparison, and [`ApprovalAuditKey::verify`] is the constant-time path that
/// callers should use instead.
#[derive(Debug, Clone)]
pub struct Tag([u8; HASH_LEN]);

impl Tag {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; HASH_LEN]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; HASH_LEN] {
        &self.0
    }

    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl std::fmt::Display for Tag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_hex())
    }
}

// ---------------------------------------------------------------------------
// The key
// ---------------------------------------------------------------------------

/// The control-plane approval and audit key.
///
/// Holds the derived key privately. There is no getter, no `Serialize`, and no
/// `Clone`-to-bytes escape hatch; [`Tag`]s are the only thing that leaves.
pub struct ApprovalAuditKey {
    key: [u8; 32],
    epoch: TrustEpoch,
}

impl ApprovalAuditKey {
    /// Derive the approval and audit key for `epoch` from the deployment's
    /// single ADR-013 key-source authority.
    ///
    /// The master key is visible only for the duration of `source.with_key`,
    /// per ADR-013's synchronous-operation boundary.
    ///
    /// # Errors
    ///
    /// Returns an error when the configured key source cannot provide the
    /// master key, or when it returns success without ever invoking its
    /// callback — which would otherwise leave an all-zero "derived" key in
    /// place. ADR-013 requires a successful `with_key` to invoke its callback
    /// exactly once; this checks it rather than trusting it.
    pub fn derive(source: &dyn KeySource, epoch: TrustEpoch) -> Result<Self> {
        let mut derived = [0u8; 32];
        let mut invocations = 0usize;
        let mut inner: Option<anyhow::Error> = None;

        source
            .with_key(&mut |master: &[u8; 32]| {
                invocations += 1;
                match derive_subkey(master, APPROVAL_AUDIT_LABEL, epoch) {
                    Ok(k) => {
                        derived = k;
                        Ok(())
                    }
                    Err(e) => {
                        // Keep the cause; the outer error must not leak key
                        // material, and this one carries none.
                        inner = Some(e);
                        bail!("approval and audit key derivation failed")
                    }
                }
            })
            .with_context(|| {
                format!(
                    "could not derive the control-plane approval and audit key from the '{}' key source",
                    source.backend_name()
                )
            })?;

        if let Some(e) = inner {
            derived.fill(0);
            return Err(e);
        }
        if invocations != 1 {
            derived.fill(0);
            bail!(
                "the '{}' key source reported success but invoked its callback {invocations} times; \
                 ADR-013 requires exactly one invocation",
                source.backend_name()
            );
        }

        Ok(Self {
            key: derived,
            epoch,
        })
    }

    /// The trust epoch this key was derived for.
    #[must_use]
    pub const fn trust_epoch(&self) -> TrustEpoch {
        self.epoch
    }

    /// Authenticate `message`.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> Tag {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&self.key)
            .unwrap_or_else(|_| unreachable!("HMAC-SHA256 accepts a key of any length"));
        mac.update(message);
        Tag(mac.finalize().into_bytes().into())
    }

    /// Check `tag` against `message` in constant time.
    #[must_use]
    pub fn verify(&self, message: &[u8], tag: &Tag) -> bool {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&self.key)
            .unwrap_or_else(|_| unreachable!("HMAC-SHA256 accepts a key of any length"));
        mac.update(message);
        mac.verify_slice(&tag.0).is_ok()
    }
}

/// Redacted: never prints the derived key.
impl std::fmt::Debug for ApprovalAuditKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApprovalAuditKey")
            .field("label", &APPROVAL_AUDIT_LABEL)
            .field("trust_epoch", &self.epoch.get())
            .field("key", &"<redacted>")
            .finish()
    }
}

/// Best-effort zeroisation, matching the treatment of the master key in
/// `zeroclaw_config::secrets`. This is a lifetime hygiene measure, not a
/// guarantee: the compiler may have copied the bytes elsewhere.
impl Drop for ApprovalAuditKey {
    fn drop(&mut self) {
        self.key.fill(0);
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use zeroclaw_config::secrets::ProvisioningState;

    /// A `KeySource` that hands out a fixed master key.
    #[derive(Debug)]
    struct FixedKeySource {
        key: [u8; 32],
        calls: AtomicUsize,
    }

    impl FixedKeySource {
        fn new(byte: u8) -> Self {
            Self {
                key: [byte; 32],
                calls: AtomicUsize::new(0),
            }
        }
    }

    impl KeySource for FixedKeySource {
        fn with_key(&self, f: &mut dyn FnMut(&[u8; 32]) -> Result<()>) -> Result<()> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            f(&self.key)
        }
        fn backend_name(&self) -> &'static str {
            "test-fixed"
        }
        fn provisioning_state(&self) -> ProvisioningState {
            ProvisioningState::Initialized
        }
    }

    /// A `KeySource` that reports success without ever yielding a key.
    #[derive(Debug)]
    struct SilentKeySource;

    impl KeySource for SilentKeySource {
        fn with_key(&self, _f: &mut dyn FnMut(&[u8; 32]) -> Result<()>) -> Result<()> {
            Ok(())
        }
        fn backend_name(&self) -> &'static str {
            "test-silent"
        }
        fn provisioning_state(&self) -> ProvisioningState {
            ProvisioningState::Initialized
        }
    }

    /// A `KeySource` that cannot provide a key.
    #[derive(Debug)]
    struct UnavailableKeySource;

    impl KeySource for UnavailableKeySource {
        fn with_key(&self, _f: &mut dyn FnMut(&[u8; 32]) -> Result<()>) -> Result<()> {
            bail!("keychain is locked")
        }
        fn backend_name(&self) -> &'static str {
            "test-unavailable"
        }
        fn provisioning_state(&self) -> ProvisioningState {
            ProvisioningState::ExternallyProvisioned
        }
    }

    // -- RFC 5869 test vectors ---------------------------------------------
    //
    // Appendix A cases A.1, A.2, and A.3 (the SHA-256 vectors). These pin the
    // extract/expand implementation to the published construction, so a later
    // "simplification" that still round-trips internally cannot pass.

    fn unhex(s: &str) -> Vec<u8> {
        hex::decode(s).expect("test vector is valid hex")
    }

    #[test]
    fn rfc5869_a1_basic_sha256() {
        let ikm = unhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let salt = unhex("000102030405060708090a0b0c");
        let info = unhex("f0f1f2f3f4f5f6f7f8f9");

        let prk = hkdf_extract(&salt, &ikm);
        assert_eq!(
            hex::encode(prk),
            "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
        );

        let mut okm = [0u8; 42];
        hkdf_expand(&prk, &info, &mut okm).expect("expand");
        assert_eq!(
            hex::encode(okm),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );
    }

    #[test]
    fn rfc5869_a2_longer_inputs_sha256() {
        let ikm = unhex(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\
             202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f\
             404142434445464748494a4b4c4d4e4f",
        );
        let salt = unhex(
            "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f\
             808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f\
             a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
        );
        let info = unhex(
            "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf\
             d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef\
             f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        );

        let prk = hkdf_extract(&salt, &ikm);
        assert_eq!(
            hex::encode(prk),
            "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244"
        );

        // 82 bytes spans three HMAC blocks, so this exercises the counter and
        // the T(i-1) chaining, not just a single-block shortcut.
        let mut okm = [0u8; 82];
        hkdf_expand(&prk, &info, &mut okm).expect("expand");
        assert_eq!(
            hex::encode(okm),
            "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c\
             59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71\
             cc30c58179ec3e87c14c01d5c1f3434f1d87"
        );
    }

    #[test]
    fn rfc5869_a3_zero_length_salt_and_info_sha256() {
        let ikm = unhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");

        let prk = hkdf_extract(&[], &ikm);
        assert_eq!(
            hex::encode(prk),
            "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04"
        );

        let mut okm = [0u8; 42];
        hkdf_expand(&prk, &[], &mut okm).expect("expand");
        assert_eq!(
            hex::encode(okm),
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
        );
    }

    #[test]
    fn empty_salt_matches_the_rfc_default_of_hashlen_zeros() {
        let ikm = unhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        assert_eq!(
            hkdf_extract(&[], &ikm),
            hkdf_extract(&[0u8; HASH_LEN], &ikm)
        );
    }

    #[test]
    fn expand_refuses_more_than_the_rfc_maximum() {
        let prk = [7u8; HASH_LEN];
        let mut ok = vec![0u8; 255 * HASH_LEN];
        assert!(hkdf_expand(&prk, b"info", &mut ok).is_ok());
        let mut too_long = vec![0u8; 255 * HASH_LEN + 1];
        assert!(hkdf_expand(&prk, b"info", &mut too_long).is_err());
    }

    // -- domain separation --------------------------------------------------

    #[test]
    fn the_derived_key_is_not_the_master_key() {
        let master = [0x42u8; 32];
        let derived =
            derive_subkey(&master, APPROVAL_AUDIT_LABEL, TrustEpoch::GENESIS).expect("derive");
        assert_ne!(
            derived, master,
            "the approval key must not be the raw encryption master key"
        );
    }

    #[test]
    fn different_labels_derive_different_keys() {
        // Guarded by mutation check: dropping the label from `subkey_info`
        // must make this test fail.
        let master = [0x42u8; 32];
        let approval =
            derive_subkey(&master, APPROVAL_AUDIT_LABEL, TrustEpoch::GENESIS).expect("derive");
        for other in [
            "zeroclaw/control-plane/approval-audit/v2",
            "zeroclaw/control-plane/approval-audi/v1",
            "zeroclaw/secrets/enc2/v1",
            "",
        ] {
            let derived = derive_subkey(&master, other, TrustEpoch::GENESIS).expect("derive");
            assert_ne!(
                approval, derived,
                "label {other:?} must not derive the approval key"
            );
        }
    }

    #[test]
    fn different_epochs_derive_different_keys() {
        let master = [0x42u8; 32];
        let a = derive_subkey(&master, APPROVAL_AUDIT_LABEL, TrustEpoch::GENESIS).expect("derive");
        let b = derive_subkey(&master, APPROVAL_AUDIT_LABEL, TrustEpoch::new(2)).expect("derive");
        assert_ne!(a, b, "an epoch transition must re-derive the key");
    }

    #[test]
    fn the_label_and_epoch_cannot_be_re_split_into_a_different_pair() {
        // The `\0` separator is what prevents ("ab", e) and ("a", e') from
        // encoding identically.
        assert_ne!(
            subkey_info("ab", TrustEpoch::new(1)),
            subkey_info("a", TrustEpoch::new(1)),
        );
        assert!(
            subkey_info(APPROVAL_AUDIT_LABEL, TrustEpoch::GENESIS)
                .starts_with(APPROVAL_AUDIT_LABEL.as_bytes()),
            "the ADR-015 label must be present verbatim in the HKDF info"
        );
    }

    #[test]
    fn rotating_the_master_key_rotates_the_approval_key() {
        // ADR-015 accepts this tradeoff explicitly; pin it so a future change
        // to the derivation cannot silently break the property.
        let a =
            derive_subkey(&[0x01; 32], APPROVAL_AUDIT_LABEL, TrustEpoch::GENESIS).expect("derive");
        let b =
            derive_subkey(&[0x02; 32], APPROVAL_AUDIT_LABEL, TrustEpoch::GENESIS).expect("derive");
        assert_ne!(a, b);
    }

    #[test]
    fn derivation_is_deterministic_for_the_same_master_and_epoch() {
        let source = FixedKeySource::new(0x9e);
        let a = ApprovalAuditKey::derive(&source, TrustEpoch::GENESIS).expect("derive");
        let b = ApprovalAuditKey::derive(&source, TrustEpoch::GENESIS).expect("derive");
        let tag = a.sign(b"receipt");
        assert!(
            b.verify(b"receipt", &tag),
            "two derivations from one master and epoch must agree"
        );
    }

    // -- sign and verify ----------------------------------------------------

    #[test]
    fn sign_and_verify_round_trip() {
        let source = FixedKeySource::new(0x11);
        let key = ApprovalAuditKey::derive(&source, TrustEpoch::GENESIS).expect("derive");
        for message in [
            b"".as_slice(),
            b"a".as_slice(),
            b"proposal:sha256:abc target:alpha epoch:1 decision:approve".as_slice(),
            &[0u8; 1024],
        ] {
            let tag = key.sign(message);
            assert!(key.verify(message, &tag), "a fresh tag must verify");
        }
    }

    #[test]
    fn verify_rejects_a_tampered_message() {
        let source = FixedKeySource::new(0x11);
        let key = ApprovalAuditKey::derive(&source, TrustEpoch::GENESIS).expect("derive");
        let tag = key.sign(b"decision:approve");
        assert!(!key.verify(b"decision:reject", &tag));
        assert!(!key.verify(b"decision:approve ", &tag));
        assert!(!key.verify(b"decision:approv", &tag));
        assert!(!key.verify(b"", &tag));
    }

    #[test]
    fn verify_rejects_a_tampered_tag() {
        let source = FixedKeySource::new(0x11);
        let key = ApprovalAuditKey::derive(&source, TrustEpoch::GENESIS).expect("derive");
        let tag = key.sign(b"decision:approve");
        for bit in [0usize, 7, 128, 255] {
            let mut bytes = *tag.as_bytes();
            bytes[bit / 8] ^= 1 << (bit % 8);
            assert!(
                !key.verify(b"decision:approve", &Tag::from_bytes(bytes)),
                "flipping bit {bit} must invalidate the tag"
            );
        }
    }

    #[test]
    fn a_tag_from_another_master_key_does_not_verify() {
        let mine = ApprovalAuditKey::derive(&FixedKeySource::new(0x11), TrustEpoch::GENESIS)
            .expect("derive");
        let theirs = ApprovalAuditKey::derive(&FixedKeySource::new(0x22), TrustEpoch::GENESIS)
            .expect("derive");
        let tag = theirs.sign(b"decision:approve");
        assert!(!mine.verify(b"decision:approve", &tag));
    }

    #[test]
    fn a_tag_from_a_superseded_epoch_does_not_verify() {
        let source = FixedKeySource::new(0x11);
        let old = ApprovalAuditKey::derive(&source, TrustEpoch::GENESIS).expect("derive");
        let new = ApprovalAuditKey::derive(&source, TrustEpoch::new(2)).expect("derive");
        let tag = old.sign(b"decision:approve");
        assert!(
            !new.verify(b"decision:approve", &tag),
            "an epoch transition must invalidate tags from the prior epoch"
        );
        assert_eq!(new.trust_epoch(), TrustEpoch::new(2));
    }

    // -- the key never leaks ------------------------------------------------

    #[test]
    fn debug_output_contains_no_key_bytes() {
        let master = [0x42u8; 32];
        let expected =
            derive_subkey(&master, APPROVAL_AUDIT_LABEL, TrustEpoch::GENESIS).expect("derive");
        let key = ApprovalAuditKey::derive(&FixedKeySource::new(0x42), TrustEpoch::GENESIS)
            .expect("derive");

        let rendered = format!("{key:?}");
        assert!(rendered.contains("<redacted>"), "got {rendered}");
        assert!(
            !rendered.contains(&hex::encode(expected)),
            "Debug leaked the hex-encoded derived key: {rendered}"
        );
        assert!(
            !rendered.contains(&hex::encode(master)),
            "Debug leaked the hex-encoded master key: {rendered}"
        );
        // Also reject any run of key bytes rendered as decimal, which is what
        // a derived `Debug` on `[u8; 32]` would produce.
        let decimal = expected
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        assert!(
            !rendered.contains(&decimal),
            "Debug leaked the derived key as a byte array: {rendered}"
        );
        // The non-secret context is still useful for diagnostics.
        assert!(rendered.contains(APPROVAL_AUDIT_LABEL));
    }

    // -- key-source failure modes -------------------------------------------

    #[test]
    fn an_unavailable_key_source_fails_closed() {
        let err = ApprovalAuditKey::derive(&UnavailableKeySource, TrustEpoch::GENESIS)
            .expect_err("an unavailable source must not yield a key");
        let rendered = format!("{err:#}");
        assert!(
            rendered.contains("test-unavailable"),
            "the diagnostic must name the source: {rendered}"
        );
    }

    #[test]
    fn a_source_that_never_yields_a_key_is_rejected_rather_than_deriving_from_zeros() {
        let err = ApprovalAuditKey::derive(&SilentKeySource, TrustEpoch::GENESIS)
            .expect_err("a silent source must not produce an all-zero-derived key");
        let rendered = format!("{err:#}");
        assert!(
            rendered.contains("exactly one invocation"),
            "got {rendered}"
        );
    }

    #[test]
    fn derivation_reads_the_master_key_exactly_once() {
        let source = FixedKeySource::new(0x33);
        let _key = ApprovalAuditKey::derive(&source, TrustEpoch::GENESIS).expect("derive");
        assert_eq!(
            source.calls.load(Ordering::SeqCst),
            1,
            "the master key must be exposed for exactly one synchronous operation"
        );
    }
}
