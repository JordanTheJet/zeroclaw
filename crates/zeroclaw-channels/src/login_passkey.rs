//! Channel-owned passkey hooks for QR-pairing channels.
//!
//! WhatsApp Web's SHORTCAKE gate interrupts device linking to demand a
//! WebAuthn assertion signed by a passkey already registered to the account.
//! No process on the host can produce one — the private key lives
//! non-extractable in a platform authenticator — so the channel publishes the
//! server's challenge and waits for an operator to answer it from where a real
//! authenticator exists (in practice a logged-in `web.whatsapp.com` tab, since
//! a browser only signs for an rpId matching the page origin).
//!
//! This module is the dispatch layer between that wait and its callers, and
//! mirrors [`crate::login_relink`] deliberately: each arm delegates to the
//! channel module that owns the state, so knowledge of the on-disk protocol
//! never leaks out of the channel and the gateway endpoint performs no file
//! operations of its own. Paths are resolved from the canonical `Config` per
//! call; nothing is cached.
//!
//! The match over [`QrPairingChannel`] is exhaustive, so adding a QR-pairing
//! channel forces an explicit answer to "does this one have a passkey gate?"
//! rather than silently inheriting WhatsApp's. Today only WhatsApp Web does;
//! WeChat resolves to [`PasskeyState::NotApplicable`], an explicit no-op the
//! caller can surface verbatim.
//!
//! Only the assertion crosses this boundary. It is a one-time signature over
//! the server's challenge and carries no private key, so a captured payload
//! cannot be replayed against a different challenge.

use crate::listing::QrPairingChannel;
use zeroclaw_config::schema::Config;

/// Whether a channel alias is currently waiting for a passkey assertion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PasskeyState {
    /// The channel published a challenge and is blocked until it is
    /// answered. `options` is the server's WebAuthn request JSON, carried
    /// verbatim — it is what the browser ceremony consumes, and
    /// re-serializing it risks perturbing a field the server signs over.
    Pending { options: String },
    /// The assertion was accepted and the fresh link is waiting for the
    /// operator to compare and acknowledge WhatsApp's display code.
    ConfirmationPending { attempt_id: String, code: String },
    /// The channel participates in the ceremony but nothing is waiting.
    /// The ordinary state: a linked channel demands an assertion only while
    /// linking, and only when the server's phased rollout selects it.
    Idle,
    /// This channel type has no passkey gate. Nothing was inspected.
    NotApplicable,
}

/// Why a submitted assertion was not accepted.
///
/// The variants are the distinctions a caller must act on, not every way the
/// underlying write can fail.
#[derive(Debug)]
pub enum SubmitError {
    /// Nothing is waiting for an assertion on this alias, so there is no
    /// challenge for the payload to answer.
    NoPendingRequest,
    /// The payload cannot satisfy the server; carries the specific reason.
    Invalid(String),
    /// This channel type has no passkey gate. Nothing was written.
    NotApplicable,
    /// The assertion could not be handed over.
    Io(String),
}

impl std::fmt::Display for SubmitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoPendingRequest => write!(
                f,
                "this channel is not waiting for a passkey assertion; \
                 nothing was written"
            ),
            Self::Invalid(reason) => write!(f, "{reason}"),
            Self::NotApplicable => {
                write!(f, "this channel type has no passkey gate")
            }
            Self::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for SubmitError {}

/// Why a fresh-link code acknowledgement was not accepted.
#[derive(Debug)]
pub enum ConfirmError {
    /// Nothing is currently waiting for a verification-code acknowledgement.
    NoPendingConfirmation,
    /// The supplied attempt id belongs to another ceremony.
    AttemptMismatch,
    /// This channel type has no passkey gate.
    NotApplicable,
    /// The acknowledgement could not be handed over.
    Io(String),
}

impl std::fmt::Display for ConfirmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoPendingConfirmation => {
                write!(f, "this channel is not waiting for passkey confirmation")
            }
            Self::AttemptMismatch => write!(f, "confirmation attempt_id does not match"),
            Self::NotApplicable => write!(f, "this channel type has no passkey gate"),
            Self::Io(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for ConfirmError {}

/// Report whether `alias` is currently blocked on a passkey assertion, and
/// republish the challenge if so.
///
/// Callers resolve their channel type key to [`QrPairingChannel`] once via
/// [`crate::listing::qr_pairing_channel`], the same typed key
/// [`crate::login_relink::relink`] dispatches on, so no string key reaches
/// this function.
///
/// Errors are I/O failures from reading an existing challenge (permissions,
/// etc.); an absent challenge is [`PasskeyState::Idle`], never an error.
pub fn pending(
    channel: QrPairingChannel,
    config: &Config,
    alias: &str,
) -> anyhow::Result<PasskeyState> {
    // Read at use-time in the feature-gated arms below; the binding keeps
    // the signature stable when no QR-pairing channel feature is compiled.
    let (_config, _alias) = (config, alias);
    match channel {
        #[cfg(feature = "channel-wechat")]
        QrPairingChannel::WeChat => Ok(PasskeyState::NotApplicable),
        #[cfg(feature = "whatsapp-web")]
        QrPairingChannel::WhatsAppWeb => {
            let Some(session_path) = configured_session_path(_config, _alias) else {
                // The alias carries no session path, so the run loop never
                // had a location to publish a challenge to.
                return Ok(PasskeyState::Idle);
            };
            if let Some(confirmation) =
                crate::whatsapp_web::WhatsAppWebChannel::pending_passkey_confirmation(
                    &session_path,
                )?
            {
                return Ok(PasskeyState::ConfirmationPending {
                    attempt_id: confirmation.attempt_id,
                    code: confirmation.code,
                });
            }
            match crate::whatsapp_web::WhatsAppWebChannel::pending_passkey_request(&session_path)? {
                Some(options) => Ok(PasskeyState::Pending { options }),
                None => Ok(PasskeyState::Idle),
            }
        }
    }
}

/// Hand a signed credential to the channel waiting for it.
///
/// `body` is the JSON `navigator.credentials.get()` returned, passed through
/// byte-for-byte — the server verifies a signature over exactly those bytes,
/// so anything that reshapes them invalidates the assertion.
pub fn submit(
    channel: QrPairingChannel,
    config: &Config,
    alias: &str,
    body: Vec<u8>,
) -> Result<(), SubmitError> {
    let (_config, _alias, _body) = (config, alias, body);
    match channel {
        #[cfg(feature = "channel-wechat")]
        QrPairingChannel::WeChat => Err(SubmitError::NotApplicable),
        #[cfg(feature = "whatsapp-web")]
        QrPairingChannel::WhatsAppWeb => {
            let Some(session_path) = configured_session_path(_config, _alias) else {
                return Err(SubmitError::NoPendingRequest);
            };
            crate::whatsapp_web::WhatsAppWebChannel::submit_passkey_assertion(&session_path, _body)
                .map_err(|e| match e {
                    crate::whatsapp_passkey::StageError::NoPendingRequest => {
                        SubmitError::NoPendingRequest
                    }
                    crate::whatsapp_passkey::StageError::Invalid(reason) => {
                        SubmitError::Invalid(reason)
                    }
                    crate::whatsapp_passkey::StageError::Io(io) => SubmitError::Io(io.to_string()),
                })
        }
    }
}

/// Acknowledge the verification code for a fresh passkey link.
pub fn confirm(
    channel: QrPairingChannel,
    config: &Config,
    alias: &str,
    attempt_id: &str,
) -> Result<(), ConfirmError> {
    let (_config, _alias, _attempt_id) = (config, alias, attempt_id);
    match channel {
        #[cfg(feature = "channel-wechat")]
        QrPairingChannel::WeChat => Err(ConfirmError::NotApplicable),
        #[cfg(feature = "whatsapp-web")]
        QrPairingChannel::WhatsAppWeb => {
            let Some(session_path) = configured_session_path(_config, _alias) else {
                return Err(ConfirmError::NoPendingConfirmation);
            };
            crate::whatsapp_web::WhatsAppWebChannel::submit_passkey_confirmation(
                &session_path,
                _attempt_id,
            )
            .map_err(|error| match error {
                crate::whatsapp_passkey::ConfirmationStageError::NoPendingConfirmation => {
                    ConfirmError::NoPendingConfirmation
                }
                crate::whatsapp_passkey::ConfirmationStageError::AttemptMismatch => {
                    ConfirmError::AttemptMismatch
                }
                crate::whatsapp_passkey::ConfirmationStageError::Io(io) => {
                    ConfirmError::Io(io.to_string())
                }
            })
        }
    }
}

/// The `session_path` configured for a WhatsApp Web alias, if it has one.
///
/// Both entry points resolve it the same way and neither defaults it: the
/// run loop only publishes challenges beside a configured session, so
/// inventing a path here would point the endpoint at a file nothing writes.
#[cfg(feature = "whatsapp-web")]
fn configured_session_path(config: &Config, alias: &str) -> Option<String> {
    config
        .channels
        .whatsapp
        .get(alias)
        .and_then(|whatsapp| whatsapp.session_path.clone())
}

#[cfg(test)]
mod tests {
    #[cfg(any(feature = "channel-wechat", feature = "whatsapp-web"))]
    use super::{PasskeyState, pending};
    #[cfg(any(feature = "channel-wechat", feature = "whatsapp-web"))]
    use crate::listing::QrPairingChannel;
    #[cfg(any(feature = "channel-wechat", feature = "whatsapp-web"))]
    use zeroclaw_config::schema::Config;

    #[test]
    fn channels_without_qr_pairing_never_reach_the_passkey_hook() {
        // "Unsupported" is decided at key-resolution time, exactly as it is
        // for relink, so no channel type can be probed by accident.
        assert_eq!(crate::listing::qr_pairing_channel("discord"), None);
        assert_eq!(
            crate::listing::qr_pairing_channel("whatsapp"),
            None,
            "the Cloud API backend links by token and never sees a passkey gate"
        );
    }

    #[cfg(feature = "channel-wechat")]
    #[test]
    fn wechat_has_no_passkey_gate() {
        let config = Config::default();
        assert_eq!(
            pending(QrPairingChannel::WeChat, &config, "admin").unwrap(),
            PasskeyState::NotApplicable
        );
        assert!(matches!(
            super::submit(QrPairingChannel::WeChat, &config, "admin", b"{}".to_vec()),
            Err(super::SubmitError::NotApplicable)
        ));
        assert!(matches!(
            super::confirm(QrPairingChannel::WeChat, &config, "admin", "attempt"),
            Err(super::ConfirmError::NotApplicable)
        ));
    }

    #[cfg(feature = "whatsapp-web")]
    fn whatsapp_config(session_path: &std::path::Path) -> Config {
        let mut config = Config::default();
        config.channels.whatsapp.insert(
            "spare".to_string(),
            zeroclaw_config::schema::WhatsAppConfig {
                enabled: true,
                session_path: Some(session_path.to_string_lossy().into_owned()),
                ..Default::default()
            },
        );
        config
    }

    #[cfg(feature = "whatsapp-web")]
    fn credential_json() -> Vec<u8> {
        use base64::prelude::*;
        serde_json::json!({
            "id": BASE64_URL_SAFE_NO_PAD.encode(b"cred"),
            "rawId": BASE64_URL_SAFE_NO_PAD.encode(b"cred"),
            "type": "public-key",
            "response": {
                "clientDataJSON": "eyJ0IjoxfQ",
                "authenticatorData": "YXV0aA",
                "signature": "c2ln",
                "userHandle": null,
            }
        })
        .to_string()
        .into_bytes()
    }

    #[cfg(feature = "whatsapp-web")]
    #[test]
    fn an_idle_channel_reports_no_challenge_without_creating_files() {
        let temp = tempfile::tempdir().unwrap();
        let session_path = temp.path().join("spare.db");
        let config = whatsapp_config(&session_path);

        assert_eq!(
            pending(QrPairingChannel::WhatsAppWeb, &config, "spare").unwrap(),
            PasskeyState::Idle
        );
        assert!(
            !std::path::Path::new(&crate::whatsapp_passkey::request_path(
                &session_path.to_string_lossy()
            ))
            .exists(),
            "probing must not create the request file"
        );
    }

    #[cfg(feature = "whatsapp-web")]
    #[test]
    fn a_published_challenge_is_served_verbatim_and_answered() {
        let temp = tempfile::tempdir().unwrap();
        let session_path = temp.path().join("spare.db");
        let session = session_path.to_string_lossy().into_owned();
        let config = whatsapp_config(&session_path);

        // Submitting before the channel asks is refused: the authenticator
        // discards any assertion predating its challenge, so accepting one
        // would tell the operator they had answered when they had not.
        assert!(matches!(
            super::submit(
                QrPairingChannel::WhatsAppWeb,
                &config,
                "spare",
                credential_json()
            ),
            Err(super::SubmitError::NoPendingRequest)
        ));

        let options = r#"{"challenge":"AQID","rpId":"web.whatsapp.com"}"#;
        std::fs::write(crate::whatsapp_passkey::request_path(&session), options).unwrap();

        match pending(QrPairingChannel::WhatsAppWeb, &config, "spare").unwrap() {
            PasskeyState::Pending { options: served } => assert_eq!(
                served, options,
                "the challenge must reach the browser byte-for-byte"
            ),
            other => panic!("expected Pending, got {other:?}"),
        }

        super::submit(
            QrPairingChannel::WhatsAppWeb,
            &config,
            "spare",
            credential_json(),
        )
        .unwrap();

        assert_eq!(
            std::fs::read(crate::whatsapp_passkey::assertion_path(&session)).unwrap(),
            credential_json(),
            "the credential must land unmodified where the authenticator polls"
        );
    }

    #[cfg(feature = "whatsapp-web")]
    #[test]
    fn a_payload_that_cannot_satisfy_the_server_is_refused_at_the_boundary() {
        let temp = tempfile::tempdir().unwrap();
        let session_path = temp.path().join("spare.db");
        let session = session_path.to_string_lossy().into_owned();
        let config = whatsapp_config(&session_path);
        std::fs::write(
            crate::whatsapp_passkey::request_path(&session),
            r#"{"challenge":"AQID"}"#,
        )
        .unwrap();

        let err = super::submit(
            QrPairingChannel::WhatsAppWeb,
            &config,
            "spare",
            b"not a credential".to_vec(),
        )
        .unwrap_err();
        assert!(matches!(err, super::SubmitError::Invalid(_)));

        assert!(
            !std::path::Path::new(&crate::whatsapp_passkey::assertion_path(&session)).exists(),
            "a rejected payload must not be left for the run loop to choke on"
        );
        assert!(
            std::path::Path::new(&crate::whatsapp_passkey::request_path(&session)).exists(),
            "a rejected submission must leave the challenge open to retry"
        );
    }

    #[cfg(feature = "whatsapp-web")]
    #[test]
    fn a_pending_confirmation_is_served_and_acknowledged_once() {
        let temp = tempfile::tempdir().unwrap();
        let session_path = temp.path().join("spare.db");
        let session = session_path.to_string_lossy().into_owned();
        let config = whatsapp_config(&session_path);
        let prompt = crate::whatsapp_passkey::PendingPasskeyConfirmation {
            attempt_id: "current-attempt".to_string(),
            code: "ABCD-EFGH".to_string(),
        };
        std::fs::write(
            crate::whatsapp_passkey::confirmation_path(&session),
            serde_json::to_vec(&prompt).unwrap(),
        )
        .unwrap();

        assert_eq!(
            pending(QrPairingChannel::WhatsAppWeb, &config, "spare").unwrap(),
            PasskeyState::ConfirmationPending {
                attempt_id: "current-attempt".to_string(),
                code: "ABCD-EFGH".to_string(),
            }
        );
        assert!(matches!(
            super::confirm(
                QrPairingChannel::WhatsAppWeb,
                &config,
                "spare",
                "older-attempt"
            ),
            Err(super::ConfirmError::AttemptMismatch)
        ));
        assert!(
            !std::path::Path::new(&crate::whatsapp_passkey::confirmation_ack_path(&session))
                .exists()
        );

        super::confirm(
            QrPairingChannel::WhatsAppWeb,
            &config,
            "spare",
            "current-attempt",
        )
        .unwrap();
        assert!(
            std::path::Path::new(&crate::whatsapp_passkey::confirmation_ack_path(&session))
                .is_file()
        );
    }

    #[cfg(feature = "whatsapp-web")]
    #[test]
    fn an_alias_without_a_session_path_is_idle_rather_than_guessed_at() {
        let config = Config::default();
        assert_eq!(
            pending(QrPairingChannel::WhatsAppWeb, &config, "missing").unwrap(),
            PasskeyState::Idle
        );
        assert!(matches!(
            super::submit(
                QrPairingChannel::WhatsAppWeb,
                &config,
                "missing",
                credential_json()
            ),
            Err(super::SubmitError::NoPendingRequest)
        ));
    }
}
