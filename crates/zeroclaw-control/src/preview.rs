use std::path::PathBuf;

use serde::Serialize;
use zeroclaw_config::schema::Config;

use crate::guard::EffectivePosture;
use crate::guard::{TextMode, ensure_display_text};
use crate::inventory::{
    CapabilityRestrictedProviderFactory, MemoryChoice, RiskChoice, RuntimeChoice,
};
use crate::proposal::{AgentProposal, ProposalError, validate_proposal};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RevisionBinding {
    /// Pure preview not yet associated with the source bytes captured by its
    /// host.
    Unavailable,
    /// The host captured one stable config source and will use the
    /// revision-bound Quickstart apply entry point for this preview.
    ExpectedSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplyIntegration {
    /// A separate host integration must revalidate against a fresh Config and
    /// provide a revision-bound commit outcome. This crate intentionally does
    /// not call current `quickstart::apply_with_surface`.
    RevisionBoundHostRequired,
    /// The host has wired this preview to Quickstart's expected-source apply.
    RevisionBoundQuickstart,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileDisposition {
    CreateBuiltInPreset,
    ReuseExactBuiltInPreset,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PersonalityFilePreview {
    pub filename: String,
    pub content: String,
    pub destination: PathBuf,
    pub may_overwrite_existing: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PersistencePreview {
    pub config_path: PathBuf,
    pub workspace_dir: PathBuf,
    pub creates_workspace_during_apply: bool,
    pub config_paths: Vec<String>,
    pub risk_profile: ProfileDisposition,
    pub runtime_profile: ProfileDisposition,
    pub memory_storage: Option<ProfileDisposition>,
    pub personality_files: Vec<PersonalityFilePreview>,
    pub apply_integration: ApplyIntegration,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProposalPreview {
    pub agent_alias: String,
    pub selected_model_provider: String,
    pub selected_model: String,
    pub risk: RiskChoice,
    pub runtime: RuntimeChoice,
    pub memory: MemoryChoice,
    pub personality_files: Vec<PersonalityFilePreview>,
    pub effective_posture: EffectivePosture,
    pub persistence: PersistencePreview,
    pub uncontained: bool,
    pub revision_binding: RevisionBinding,
}

impl ProposalPreview {
    /// Mark a pure preview as bound by a host that captured the source revision
    /// and will call the revision-bound Quickstart apply entry point.
    #[must_use]
    pub fn bind_expected_source(mut self) -> Self {
        self.revision_binding = RevisionBinding::ExpectedSource;
        self.persistence.apply_integration = ApplyIntegration::RevisionBoundQuickstart;
        self
    }
}

/// Purely revalidate and build a host-renderable preview. This function does
/// not invoke Quickstart, create a workspace, stage files, or mutate Config.
pub fn build_preview(
    config: &Config,
    factory: &(impl CapabilityRestrictedProviderFactory + ?Sized),
    selected_provider_ref: &str,
    proposal: &AgentProposal,
) -> Result<ProposalPreview, ProposalError> {
    let validated = validate_proposal(config, factory, selected_provider_ref, proposal)?;
    let proposal = validated.proposal();
    let workspace_dir = config.agent_workspace_dir(&proposal.agent_alias);
    ensure_display_text(
        &config.config_path.display().to_string(),
        TextMode::Structural,
    )
    .map_err(|error| ProposalError::from_guard("config_path", error))?;
    ensure_display_text(&workspace_dir.display().to_string(), TextMode::Structural)
        .map_err(|error| ProposalError::from_guard("workspace_path", error))?;
    let personality_files: Vec<PersonalityFilePreview> = proposal
        .personality_files
        .iter()
        .map(|file| {
            let destination = workspace_dir.join(&file.filename);
            ensure_display_text(&destination.display().to_string(), TextMode::Structural)
                .map_err(|error| ProposalError::from_guard("personality_path", error))?;
            Ok(PersonalityFilePreview {
                filename: file.filename.clone(),
                content: file.content.clone(),
                destination,
                may_overwrite_existing: true,
            })
        })
        .collect::<Result<_, ProposalError>>()?;

    let risk_profile = if config
        .risk_profiles
        .contains_key(proposal.risk.preset_name())
    {
        ProfileDisposition::ReuseExactBuiltInPreset
    } else {
        ProfileDisposition::CreateBuiltInPreset
    };
    let runtime_profile = if config
        .runtime_profiles
        .contains_key(proposal.runtime.preset_name())
    {
        ProfileDisposition::ReuseExactBuiltInPreset
    } else {
        ProfileDisposition::CreateBuiltInPreset
    };
    let memory_storage = None;

    let mut config_paths = vec![
        format!("agents.{}", proposal.agent_alias),
        format!("agents.{}.memory.backend", proposal.agent_alias),
        "onboard_state.quickstart_completed".to_string(),
    ];
    if matches!(risk_profile, ProfileDisposition::CreateBuiltInPreset) {
        config_paths.push(format!("risk_profiles.{}", proposal.risk.preset_name()));
    }
    if matches!(runtime_profile, ProfileDisposition::CreateBuiltInPreset) {
        config_paths.push(format!(
            "runtime_profiles.{}",
            proposal.runtime.preset_name()
        ));
    }
    if config.skill_bundles.is_empty() {
        config_paths.push("skill_bundles.default".to_string());
    }
    config_paths.sort();

    let persistence = PersistencePreview {
        config_path: config.config_path.clone(),
        workspace_dir: workspace_dir.clone(),
        creates_workspace_during_apply: !personality_files.is_empty(),
        config_paths,
        risk_profile,
        runtime_profile,
        memory_storage,
        personality_files: personality_files.clone(),
        apply_integration: ApplyIntegration::RevisionBoundHostRequired,
    };

    Ok(ProposalPreview {
        agent_alias: proposal.agent_alias.clone(),
        selected_model_provider: validated.selected_provider_ref().to_string(),
        selected_model: validated.selected_model().to_string(),
        risk: proposal.risk,
        runtime: proposal.runtime,
        memory: proposal.memory,
        personality_files,
        effective_posture: validated.posture().clone(),
        persistence,
        uncontained: false,
        revision_binding: RevisionBinding::Unavailable,
    })
}
