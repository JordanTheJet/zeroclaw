use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use zeroclaw_config::policy::SecurityPolicy;
use zeroclaw_config::presets::{
    AgentIdentity, BuilderSubmission, QuickstartPersonalityFile, SelectorChoice,
};
use zeroclaw_config::schema::Config;

use crate::FluentMessage;
use crate::guard::{
    EffectivePosture, GuardCode, GuardError, TextMode, assess_effective_posture,
    ensure_conversation_text, ensure_safe_text,
};
use crate::inventory::{
    CapabilityRestrictedProviderFactory, MAX_PERSONALITY_FILE_CHARS, MemoryChoice,
    PERSONALITY_FILENAMES, RiskChoice, RuntimeChoice, SafeInventory, resolved_risk_profile,
    resolved_runtime_profile,
};

pub const PROPOSAL_MARKER: &str = "PROPOSAL:";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersonalityFileProposal {
    pub filename: String,
    pub content: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentProposal {
    pub agent_alias: String,
    pub risk: RiskChoice,
    pub runtime: RuntimeChoice,
    pub memory: MemoryChoice,
    pub personality_files: Vec<PersonalityFileProposal>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProposalErrorCode {
    CredentialLikeContent,
    ConfigurationContent,
    TerminalControl,
    BidiControl,
    InvalidJson,
    InvalidAgentAlias,
    ReservedAgentAlias,
    AgentAliasExists,
    ProviderUnavailable,
    RiskChoiceUnavailable,
    RuntimeChoiceUnavailable,
    NoncanonicalPersonalityFile,
    DuplicatePersonalityFile,
    PersonalityFileTooLarge,
    TooManyPersonalityFiles,
    UncontainedPosture,
    ProfileDrift,
    ProviderTargetDrift,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProposalError {
    pub code: ProposalErrorCode,
    pub field: String,
    pub limit: Option<usize>,
}

impl ProposalError {
    pub(crate) fn new(code: ProposalErrorCode, field: impl Into<String>) -> Self {
        Self {
            code,
            field: field.into(),
            limit: None,
        }
    }

    fn with_limit(mut self, limit: usize) -> Self {
        self.limit = Some(limit);
        self
    }

    pub(crate) fn from_guard(field: impl Into<String>, error: GuardError) -> Self {
        let code = match error.code {
            GuardCode::CredentialLikeContent => ProposalErrorCode::CredentialLikeContent,
            GuardCode::ConfigurationContent => ProposalErrorCode::ConfigurationContent,
            GuardCode::TerminalControl => ProposalErrorCode::TerminalControl,
            GuardCode::BidiControl => ProposalErrorCode::BidiControl,
            GuardCode::UncontainedPosture => ProposalErrorCode::UncontainedPosture,
        };
        Self::new(code, field)
    }

    #[must_use]
    pub fn fluent(&self) -> FluentMessage {
        let key = match self.code {
            ProposalErrorCode::CredentialLikeContent => "cli-zerona-error-credential-content",
            ProposalErrorCode::ConfigurationContent => "cli-zerona-error-config-content",
            ProposalErrorCode::TerminalControl => "cli-zerona-error-terminal-control",
            ProposalErrorCode::BidiControl => "cli-zerona-error-bidi-control",
            ProposalErrorCode::InvalidJson => "cli-zerona-error-proposal-json",
            ProposalErrorCode::InvalidAgentAlias => "cli-zerona-error-agent-alias",
            ProposalErrorCode::ReservedAgentAlias => "cli-zerona-error-agent-alias-reserved",
            ProposalErrorCode::AgentAliasExists => "cli-zerona-error-agent-alias-exists",
            ProposalErrorCode::ProviderUnavailable => "cli-zerona-error-provider-unavailable",
            ProposalErrorCode::RiskChoiceUnavailable => "cli-zerona-error-risk-unavailable",
            ProposalErrorCode::RuntimeChoiceUnavailable => "cli-zerona-error-runtime-unavailable",
            ProposalErrorCode::NoncanonicalPersonalityFile => {
                "cli-zerona-error-personality-filename"
            }
            ProposalErrorCode::DuplicatePersonalityFile => "cli-zerona-error-personality-duplicate",
            ProposalErrorCode::PersonalityFileTooLarge => "cli-zerona-error-personality-too-large",
            ProposalErrorCode::TooManyPersonalityFiles => "cli-zerona-error-personality-too-many",
            ProposalErrorCode::UncontainedPosture => "cli-zerona-error-uncontained-posture",
            ProposalErrorCode::ProfileDrift => "cli-zerona-error-profile-drift",
            ProposalErrorCode::ProviderTargetDrift => "cli-zerona-error-provider-target-drift",
        };
        let mut message = FluentMessage::new(key).with_arg("field", self.field.clone());
        if let Some(limit) = self.limit {
            message = message.with_arg("limit", limit.to_string());
        }
        message
    }
}

impl std::fmt::Display for ProposalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "proposal rejected at {} ({:?})", self.field, self.code)
    }
}

impl std::error::Error for ProposalError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedProposal {
    proposal: AgentProposal,
    selected_provider_ref: String,
    selected_model: String,
    posture: EffectivePosture,
    risk_profile_preexisting: bool,
    runtime_profile_preexisting: bool,
}

impl ValidatedProposal {
    #[must_use]
    pub fn proposal(&self) -> &AgentProposal {
        &self.proposal
    }

    #[must_use]
    pub fn selected_provider_ref(&self) -> &str {
        &self.selected_provider_ref
    }

    #[must_use]
    pub fn selected_model(&self) -> &str {
        &self.selected_model
    }

    #[must_use]
    pub fn posture(&self) -> &EffectivePosture {
        &self.posture
    }

    /// Convert only the settled proposal fields. The model provider is always
    /// the host-selected existing ref; every generic Quickstart surface that
    /// Zerona does not own is forced empty or absent.
    #[must_use]
    pub fn to_builder_submission(&self) -> BuilderSubmission {
        BuilderSubmission {
            model_provider: SelectorChoice::Existing(self.selected_provider_ref.clone()),
            risk_profile: SelectorChoice::Fresh(self.proposal.risk.preset_name().to_string()),
            runtime_profile: SelectorChoice::Fresh(self.proposal.runtime.preset_name().to_string()),
            memory: SelectorChoice::Fresh(self.proposal.memory.quickstart_choice()),
            channels: Vec::new(),
            peer_groups: Vec::new(),
            agent: AgentIdentity {
                name: self.proposal.agent_alias.clone(),
                system_prompt: String::new(),
                personality_file: None,
                personality_files: self
                    .proposal
                    .personality_files
                    .iter()
                    .map(|file| QuickstartPersonalityFile {
                        filename: file.filename.clone(),
                        content: file.content.clone(),
                    })
                    .collect(),
            },
        }
    }
}

/// Parse exactly one JSON object after `PROPOSAL:`. Text without the marker is
/// an ordinary conversational response and returns `Ok(None)`.
pub fn parse_proposal(model_text: &str) -> Result<Option<AgentProposal>, ProposalError> {
    ensure_safe_text(model_text, TextMode::Multiline)
        .map_err(|error| ProposalError::from_guard("model_output", error))?;
    let Some(marker_index) = model_text.find(PROPOSAL_MARKER) else {
        ensure_conversation_text(model_text, TextMode::Multiline)
            .map_err(|error| ProposalError::from_guard("model_output", error))?;
        return Ok(None);
    };
    ensure_conversation_text(&model_text[..marker_index], TextMode::Multiline)
        .map_err(|error| ProposalError::from_guard("model_output", error))?;
    let json = &model_text[marker_index + PROPOSAL_MARKER.len()..];
    let proposal = serde_json::from_str::<AgentProposal>(json.trim())
        .map_err(|_| ProposalError::new(ProposalErrorCode::InvalidJson, "proposal"))?;
    Ok(Some(proposal))
}

pub fn validate_proposal(
    config: &Config,
    factory: &(impl CapabilityRestrictedProviderFactory + ?Sized),
    selected_provider_ref: &str,
    proposal: &AgentProposal,
) -> Result<ValidatedProposal, ProposalError> {
    let selected_target =
        crate::inventory::validated_target(config, factory, selected_provider_ref)
            .map_err(|_| ProposalError::new(ProposalErrorCode::ProviderUnavailable, "provider"))?;
    let inventory = SafeInventory::from_config(config, factory, selected_provider_ref)
        .map_err(|_| ProposalError::new(ProposalErrorCode::ProviderUnavailable, "provider"))?;

    ensure_safe_text(&proposal.agent_alias, TextMode::Structural)
        .map_err(|error| ProposalError::from_guard("agent_alias", error))?;
    zeroclaw_config::helpers::validate_alias_key(&proposal.agent_alias)
        .map_err(|_| ProposalError::new(ProposalErrorCode::InvalidAgentAlias, "agent_alias"))?;
    if zeroclaw_config::alias_refs::is_reserved_agent_alias(&proposal.agent_alias) {
        return Err(ProposalError::new(
            ProposalErrorCode::ReservedAgentAlias,
            "agent_alias",
        ));
    }
    if config.agents.contains_key(&proposal.agent_alias) {
        return Err(ProposalError::new(
            ProposalErrorCode::AgentAliasExists,
            "agent_alias",
        ));
    }
    if !inventory.risk_choices.contains(&proposal.risk) {
        return Err(ProposalError::new(
            ProposalErrorCode::RiskChoiceUnavailable,
            "risk",
        ));
    }
    if !inventory.runtime_choices.contains(&proposal.runtime) {
        return Err(ProposalError::new(
            ProposalErrorCode::RuntimeChoiceUnavailable,
            "runtime",
        ));
    }
    if proposal.personality_files.len() > PERSONALITY_FILENAMES.len() {
        return Err(ProposalError::new(
            ProposalErrorCode::TooManyPersonalityFiles,
            "personality_files",
        )
        .with_limit(PERSONALITY_FILENAMES.len()));
    }

    let mut canonical_files = proposal.personality_files.clone();
    let mut seen = BTreeSet::new();
    for (index, file) in canonical_files.iter().enumerate() {
        let filename_field = format!("personality_files[{index}].filename");
        ensure_safe_text(&file.filename, TextMode::Structural)
            .map_err(|error| ProposalError::from_guard(&filename_field, error))?;
        let Some(canonical_index) = PERSONALITY_FILENAMES
            .iter()
            .position(|candidate| *candidate == file.filename)
        else {
            return Err(ProposalError::new(
                ProposalErrorCode::NoncanonicalPersonalityFile,
                filename_field,
            ));
        };
        if !seen.insert(canonical_index) {
            return Err(ProposalError::new(
                ProposalErrorCode::DuplicatePersonalityFile,
                filename_field,
            ));
        }
        let content_field = format!("personality_files[{index}].content");
        ensure_conversation_text(&file.content, TextMode::Multiline)
            .map_err(|error| ProposalError::from_guard(&content_field, error))?;
        if file.content.chars().count() > MAX_PERSONALITY_FILE_CHARS {
            return Err(ProposalError::new(
                ProposalErrorCode::PersonalityFileTooLarge,
                content_field,
            )
            .with_limit(MAX_PERSONALITY_FILE_CHARS));
        }
    }
    canonical_files.sort_by_key(|file| {
        PERSONALITY_FILENAMES
            .iter()
            .position(|candidate| *candidate == file.filename)
            .unwrap_or(PERSONALITY_FILENAMES.len())
    });

    let risk_profile = resolved_risk_profile(config, proposal.risk)
        .ok_or_else(|| ProposalError::new(ProposalErrorCode::RiskChoiceUnavailable, "risk"))?;
    let runtime_profile = resolved_runtime_profile(config, proposal.runtime).ok_or_else(|| {
        ProposalError::new(ProposalErrorCode::RuntimeChoiceUnavailable, "runtime")
    })?;
    let policy = SecurityPolicy::from_profiles(
        &risk_profile,
        Some(&runtime_profile),
        &config.agent_workspace_dir(&proposal.agent_alias),
    );
    let posture = assess_effective_posture(&policy)
        .map_err(|error| ProposalError::from_guard("risk", error))?;

    Ok(ValidatedProposal {
        proposal: AgentProposal {
            agent_alias: proposal.agent_alias.clone(),
            risk: proposal.risk,
            runtime: proposal.runtime,
            memory: proposal.memory,
            personality_files: canonical_files,
        },
        selected_provider_ref: selected_provider_ref.to_string(),
        selected_model: selected_target.model,
        posture,
        risk_profile_preexisting: config
            .risk_profiles
            .contains_key(proposal.risk.preset_name()),
        runtime_profile_preexisting: config
            .runtime_profiles
            .contains_key(proposal.runtime.preset_name()),
    })
}

/// Re-run every config-dependent check against a freshly loaded canonical
/// config. This is optimistic revalidation, not a source-revision/CAS bind.
pub fn revalidate_proposal(
    config: &Config,
    factory: &(impl CapabilityRestrictedProviderFactory + ?Sized),
    validated: &ValidatedProposal,
) -> Result<ValidatedProposal, ProposalError> {
    let fresh = validate_proposal(
        config,
        factory,
        validated.selected_provider_ref(),
        validated.proposal(),
    )?;
    if fresh.risk_profile_preexisting != validated.risk_profile_preexisting {
        return Err(ProposalError::new(ProposalErrorCode::ProfileDrift, "risk"));
    }
    if fresh.runtime_profile_preexisting != validated.runtime_profile_preexisting {
        return Err(ProposalError::new(
            ProposalErrorCode::ProfileDrift,
            "runtime",
        ));
    }
    if fresh.selected_model != validated.selected_model {
        return Err(ProposalError::new(
            ProposalErrorCode::ProviderTargetDrift,
            "provider",
        ));
    }
    Ok(fresh)
}
