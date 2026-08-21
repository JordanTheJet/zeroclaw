use std::path::{Path, PathBuf};

use serde::Serialize;
use zeroclaw_config::autonomy::AutonomyLevel;
use zeroclaw_config::policy::SecurityPolicy;
use zeroclaw_runtime::security::{LeakDetector, LeakResult};

use crate::FluentMessage;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardCode {
    CredentialLikeContent,
    ConfigurationContent,
    TerminalControl,
    BidiControl,
    UncontainedPosture,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardError {
    pub code: GuardCode,
    pub char_index: Option<usize>,
}

impl GuardError {
    #[must_use]
    pub fn fluent(&self) -> FluentMessage {
        let key = match self.code {
            GuardCode::CredentialLikeContent => "cli-zerona-error-credential-content",
            GuardCode::ConfigurationContent => "cli-zerona-error-config-content",
            GuardCode::TerminalControl => "cli-zerona-error-terminal-control",
            GuardCode::BidiControl => "cli-zerona-error-bidi-control",
            GuardCode::UncontainedPosture => "cli-zerona-error-uncontained-posture",
        };
        let mut message = FluentMessage::new(key);
        if let Some(index) = self.char_index {
            message = message.with_arg("index", index.to_string());
        }
        message
    }
}

impl std::fmt::Display for GuardError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.code {
            GuardCode::CredentialLikeContent => {
                f.write_str("credential-shaped content is not allowed")
            }
            GuardCode::ConfigurationContent => {
                f.write_str("URI or raw configuration content is not allowed")
            }
            GuardCode::TerminalControl => f.write_str("terminal control character is not allowed"),
            GuardCode::BidiControl => f.write_str("bidirectional control character is not allowed"),
            GuardCode::UncontainedPosture => f.write_str("effective posture is not contained"),
        }
    }
}

impl std::error::Error for GuardError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TextMode {
    Structural,
    Multiline,
}

pub(crate) fn ensure_no_credentials(value: &str) -> Result<(), GuardError> {
    match LeakDetector::new().scan(value) {
        LeakResult::Clean => Ok(()),
        LeakResult::Detected { .. } => Err(GuardError {
            code: GuardCode::CredentialLikeContent,
            char_index: None,
        }),
    }
}

pub(crate) fn ensure_safe_text(value: &str, mode: TextMode) -> Result<(), GuardError> {
    ensure_no_credentials(value)?;
    ensure_display_text(value, mode)
}

pub(crate) fn ensure_conversation_text(value: &str, mode: TextMode) -> Result<(), GuardError> {
    ensure_safe_text(value, mode)?;
    if contains_uri_or_raw_config(value) {
        return Err(GuardError {
            code: GuardCode::ConfigurationContent,
            char_index: None,
        });
    }
    Ok(())
}

/// Validate one operator message before any SOP run state records it or any
/// provider sees it. CLI, web, and SOP front ends share this boundary.
pub fn validate_operator_input(value: &str) -> Result<(), GuardError> {
    ensure_conversation_text(value, TextMode::Multiline)
}

fn contains_uri_or_raw_config(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    if lower.contains("config.toml")
        || lower.contains("zeroclaw config ")
        || lower.contains("://")
        || lower.contains("file:/")
        || lower.contains("mailto:")
        || lower.contains("urn:")
        || (lower.contains("data:") && lower.contains(','))
        || [
            "[agents.",
            "[channels.",
            "[gateway]",
            "[memory]",
            "[providers.",
            "[risk_profiles.",
            "[runtime_profiles.",
            "[storage.",
        ]
        .iter()
        .any(|marker| lower.contains(marker))
    {
        return true;
    }

    value.lines().any(|line| {
        let trimmed = line.trim();
        if let Some(section) = trimmed
            .strip_prefix('[')
            .and_then(|line| line.strip_suffix(']'))
            && (section.contains('.')
                || matches!(
                    section,
                    "agents"
                        | "channels"
                        | "gateway"
                        | "memory"
                        | "providers"
                        | "risk_profiles"
                        | "runtime_profiles"
                        | "storage"
                ))
        {
            return true;
        }

        if let Some((left, _right)) = trimmed.split_once('=') {
            let key = left
                .split_whitespace()
                .next_back()
                .unwrap_or_default()
                .trim_matches(|character: char| {
                    !character.is_ascii_alphanumeric() && !"_.-".contains(character)
                });
            if !key.is_empty()
                && key.len() <= 128
                && key
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric() || "_.-".contains(character))
            {
                return true;
            }
        }

        trimmed.contains('{')
            && [
                "\"agents\"",
                "\"channels\"",
                "\"gateway\"",
                "\"memory\"",
                "\"providers\"",
                "\"risk_profiles\"",
                "\"runtime_profiles\"",
                "\"storage\"",
            ]
            .iter()
            .any(|key| trimmed.contains(key))
    })
}

pub(crate) fn ensure_display_text(value: &str, mode: TextMode) -> Result<(), GuardError> {
    for (char_index, ch) in value.chars().enumerate() {
        if is_bidi_control(ch) {
            return Err(GuardError {
                code: GuardCode::BidiControl,
                char_index: Some(char_index),
            });
        }

        let allowed_multiline_control =
            matches!(mode, TextMode::Multiline) && matches!(ch, '\n' | '\t');
        let structural_whitespace = matches!(mode, TextMode::Structural) && ch.is_whitespace();
        if (ch.is_control() && !allowed_multiline_control)
            || structural_whitespace
            || matches!(ch, '\u{2028}' | '\u{2029}')
        {
            return Err(GuardError {
                code: GuardCode::TerminalControl,
                char_index: Some(char_index),
            });
        }
    }
    Ok(())
}

fn is_bidi_control(ch: char) -> bool {
    matches!(
        ch,
        '\u{061c}'
            | '\u{200e}'
            | '\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2066}'..='\u{2069}'
            | '\u{206a}'..='\u{206f}'
    )
}

/// Host-rendered summary of the effective risk/runtime policy. A successful
/// summary always carries `uncontained == false`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EffectivePosture {
    pub autonomy: AutonomyLevel,
    pub workspace_only: bool,
    pub block_high_risk_commands: bool,
    pub filesystem_unconfined: bool,
    pub allowed_roots: Vec<PathBuf>,
    pub allowed_roots_read_only: Vec<PathBuf>,
    pub allowed_roots_write_only: Vec<PathBuf>,
    pub uncontained: bool,
}

/// Reject exactly the dangerous conjunction: unconfined filesystem reach and
/// high-risk commands that are not blocked. Either control on its own is
/// sufficient for this focused onboarding boundary.
pub fn assess_effective_posture(policy: &SecurityPolicy) -> Result<EffectivePosture, GuardError> {
    let filesystem_unconfined = !policy.workspace_only
        || policy
            .allowed_roots
            .iter()
            .chain(policy.allowed_roots_read_only.iter())
            .chain(policy.allowed_roots_write_only.iter())
            .any(|root| is_filesystem_root(root));
    let uncontained = filesystem_unconfined && !policy.block_high_risk_commands;
    if uncontained {
        return Err(GuardError {
            code: GuardCode::UncontainedPosture,
            char_index: None,
        });
    }

    Ok(EffectivePosture {
        autonomy: policy.autonomy,
        workspace_only: policy.workspace_only,
        block_high_risk_commands: policy.block_high_risk_commands,
        filesystem_unconfined,
        allowed_roots: policy.allowed_roots.clone(),
        allowed_roots_read_only: policy.allowed_roots_read_only.clone(),
        allowed_roots_write_only: policy.allowed_roots_write_only.clone(),
        uncontained: false,
    })
}

fn is_filesystem_root(path: &Path) -> bool {
    path.has_root() && path.parent().is_none()
}
