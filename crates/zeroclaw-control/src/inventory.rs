use std::sync::Arc;

use serde::{Deserialize, Serialize};
use zeroclaw_api::model_provider::ModelProvider;
use zeroclaw_config::presets::{risk_preset, runtime_preset};
use zeroclaw_config::schema::{Config, RiskProfileConfig, RuntimeProfileConfig};
use zeroclaw_config::traits::AliasSource;

use crate::FluentMessage;
use crate::guard::{TextMode, assess_effective_posture, ensure_display_text, ensure_safe_text};

pub const PERSONALITY_FILENAMES: &[&str] = &["SOUL.md", "IDENTITY.md", "USER.md", "AGENTS.md"];
pub const MAX_PERSONALITY_FILE_CHARS: usize = zeroclaw_runtime::agent::personality::MAX_FILE_CHARS;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskChoice {
    LockedDown,
    Balanced,
}

impl RiskChoice {
    pub const ALL: [Self; 2] = [Self::LockedDown, Self::Balanced];

    #[must_use]
    pub const fn preset_name(self) -> &'static str {
        match self {
            Self::LockedDown => "locked_down",
            Self::Balanced => "balanced",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeChoice {
    Tight,
    LocalSmall,
    Balanced,
}

impl RuntimeChoice {
    pub const ALL: [Self; 3] = [Self::Tight, Self::LocalSmall, Self::Balanced];

    #[must_use]
    pub const fn preset_name(self) -> &'static str {
        match self {
            Self::Tight => "tight",
            Self::LocalSmall => "local_small",
            Self::Balanced => "balanced",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryChoice {
    Sqlite,
    Markdown,
    None,
}

impl MemoryChoice {
    pub const ALL: [Self; 3] = [Self::Sqlite, Self::Markdown, Self::None];

    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Sqlite => "sqlite",
            Self::Markdown => "markdown",
            Self::None => "none",
        }
    }

    #[must_use]
    pub const fn quickstart_choice(self) -> zeroclaw_config::presets::MemoryChoice {
        match self {
            Self::Sqlite => zeroclaw_config::presets::MemoryChoice::Sqlite,
            Self::Markdown => zeroclaw_config::presets::MemoryChoice::Markdown,
            Self::None => zeroclaw_config::presets::MemoryChoice::None,
        }
    }
}

/// Safe, non-secret metadata returned by the provider worker's restricted
/// alias validator. `model` is used only as the provider call's target; it is
/// intentionally omitted from [`SafeInventory`] and the model-facing prompt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderTarget {
    pub reference: String,
    pub model: String,
}

pub struct IsolatedProvider {
    pub target: ProviderTarget,
    pub provider: Arc<dyn ModelProvider>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderErrorCode {
    NotConfigured,
    CapabilityDenied,
    HostProcessDenied,
    MissingModel,
    InvalidReference,
    ConstructionFailed,
    TargetChanged,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderError {
    pub code: ProviderErrorCode,
    pub reference: String,
}

impl ProviderError {
    #[must_use]
    pub fn new(code: ProviderErrorCode, reference: impl Into<String>) -> Self {
        let reference = reference.into();
        let reference = if ensure_safe_text(&reference, TextMode::Structural).is_ok() {
            reference
        } else {
            String::new()
        };
        Self { code, reference }
    }

    #[must_use]
    pub fn fluent(&self) -> FluentMessage {
        let key = match self.code {
            ProviderErrorCode::NotConfigured => "cli-zerona-error-provider-not-configured",
            ProviderErrorCode::CapabilityDenied => "cli-zerona-error-provider-capability-denied",
            ProviderErrorCode::HostProcessDenied => "cli-zerona-error-provider-host-process",
            ProviderErrorCode::MissingModel => "cli-zerona-error-provider-missing-model",
            ProviderErrorCode::InvalidReference => "cli-zerona-error-provider-invalid-reference",
            ProviderErrorCode::ConstructionFailed => {
                "cli-zerona-error-provider-construction-failed"
            }
            ProviderErrorCode::TargetChanged => "cli-zerona-error-provider-target-changed",
        };
        FluentMessage::new(key).with_arg("provider", self.reference.clone())
    }
}

impl std::fmt::Display for ProviderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "restricted provider selection failed ({:?})", self.code)
    }
}

impl std::error::Error for ProviderError {}

/// Narrow adapter over the provider crate's capability-restricted APIs.
///
/// Implementations must delegate validation to
/// `validate_configured_alias_for_capability_restricted_session` and
/// construction to
/// `create_isolated_model_provider_for_capability_restricted_session`.
/// Construction must re-read the borrowed `Config`, materialize exactly the
/// selected alias and its single configured model, and must not inherit model
/// routes, fallback aliases, fallback models, or host-process providers.
pub trait CapabilityRestrictedProviderFactory: Send + Sync {
    fn validate_capability_restricted_model_provider_alias(
        &self,
        config: &Config,
        reference: &str,
    ) -> Result<ProviderTarget, ProviderError>;

    fn create_isolated_model_provider_for_alias(
        &self,
        config: &Config,
        reference: &str,
    ) -> Result<IsolatedProvider, ProviderError>;
}

/// Production adapter over the capability-restricted provider factory APIs.
#[derive(Debug, Clone, Copy, Default)]
pub struct CurrentProviderFactory;

impl CapabilityRestrictedProviderFactory for CurrentProviderFactory {
    fn validate_capability_restricted_model_provider_alias(
        &self,
        config: &Config,
        reference: &str,
    ) -> Result<ProviderTarget, ProviderError> {
        if !zeroclaw_providers::configured_alias_supports_capability_restricted_session(
            config, reference,
        ) {
            return Err(ProviderError::new(
                ProviderErrorCode::CapabilityDenied,
                reference,
            ));
        }
        zeroclaw_providers::validate_configured_alias_for_capability_restricted_session(
            config, reference,
        )
        .map_err(|_| ProviderError::new(ProviderErrorCode::CapabilityDenied, reference))?;

        let Some((family, alias, entry)) = config.providers.models.find_by_name(reference) else {
            return Err(ProviderError::new(
                ProviderErrorCode::NotConfigured,
                reference,
            ));
        };
        let Some(model) = entry
            .model
            .as_deref()
            .map(str::trim)
            .filter(|model| !model.is_empty())
        else {
            return Err(ProviderError::new(
                ProviderErrorCode::MissingModel,
                reference,
            ));
        };
        Ok(ProviderTarget {
            reference: format!("{family}.{alias}"),
            model: model.to_string(),
        })
    }

    fn create_isolated_model_provider_for_alias(
        &self,
        config: &Config,
        reference: &str,
    ) -> Result<IsolatedProvider, ProviderError> {
        let target = self.validate_capability_restricted_model_provider_alias(config, reference)?;
        let provider =
            zeroclaw_providers::create_isolated_model_provider_for_capability_restricted_session(
                config,
                reference,
                &target.model,
                &config.reliability,
            )
            .map_err(|_| ProviderError::new(ProviderErrorCode::ConstructionFailed, reference))?;
        Ok(IsolatedProvider {
            target,
            provider: Arc::from(provider),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProviderPickerInventory {
    pub provider_refs: Vec<String>,
}

#[must_use]
pub fn eligible_provider_refs(
    config: &Config,
    factory: &(impl CapabilityRestrictedProviderFactory + ?Sized),
) -> Vec<String> {
    let mut refs = config.resolve_alias_source(AliasSource::ModelProviders);
    refs.retain(|reference| validated_target(config, factory, reference).is_ok());
    refs.sort();
    refs.dedup();
    refs
}

impl ProviderPickerInventory {
    #[must_use]
    pub fn from_config(
        config: &Config,
        factory: &(impl CapabilityRestrictedProviderFactory + ?Sized),
    ) -> Self {
        Self {
            provider_refs: eligible_provider_refs(config, factory),
        }
    }
}

/// The only config-derived data sent to Zerona. It contains identifiers and
/// limits, never provider settings, credentials, URIs, profile bodies, or raw
/// config. The provider list contains only the already host-selected target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SafeInventory {
    pub selected_model_provider: String,
    pub risk_choices: Vec<RiskChoice>,
    pub runtime_choices: Vec<RuntimeChoice>,
    pub memory_choices: Vec<MemoryChoice>,
    pub personality_files: Vec<&'static str>,
    pub max_personality_file_chars: usize,
    pub uncontained_allowed: bool,
}

impl SafeInventory {
    pub fn from_config(
        config: &Config,
        factory: &(impl CapabilityRestrictedProviderFactory + ?Sized),
        selected_provider_ref: &str,
    ) -> Result<Self, ProviderError> {
        validated_target(config, factory, selected_provider_ref)?;

        let risk_choices = RiskChoice::ALL
            .into_iter()
            .filter(|choice| risk_choice_is_canonical_and_contained(config, *choice))
            .collect();
        let runtime_choices = RuntimeChoice::ALL
            .into_iter()
            .filter(|choice| runtime_choice_is_canonical(config, *choice))
            .collect();

        Ok(Self {
            selected_model_provider: selected_provider_ref.to_string(),
            risk_choices,
            runtime_choices,
            memory_choices: MemoryChoice::ALL.to_vec(),
            personality_files: PERSONALITY_FILENAMES.to_vec(),
            max_personality_file_chars: MAX_PERSONALITY_FILE_CHARS,
            uncontained_allowed: false,
        })
    }
}

pub(crate) fn validated_target(
    config: &Config,
    factory: &(impl CapabilityRestrictedProviderFactory + ?Sized),
    reference: &str,
) -> Result<ProviderTarget, ProviderError> {
    ensure_safe_text(reference, TextMode::Structural)
        .map_err(|_| ProviderError::new(ProviderErrorCode::InvalidReference, reference))?;
    if !config
        .resolve_alias_source(AliasSource::ModelProviders)
        .iter()
        .any(|configured| configured == reference)
    {
        return Err(ProviderError::new(
            ProviderErrorCode::NotConfigured,
            reference,
        ));
    }

    let target = factory.validate_capability_restricted_model_provider_alias(config, reference)?;
    if target.reference != reference {
        return Err(ProviderError::new(
            ProviderErrorCode::TargetChanged,
            reference,
        ));
    }
    if target.model.is_empty() {
        return Err(ProviderError::new(
            ProviderErrorCode::MissingModel,
            reference,
        ));
    }
    ensure_display_text(&target.model, TextMode::Structural)
        .map_err(|_| ProviderError::new(ProviderErrorCode::MissingModel, reference))?;
    Ok(target)
}

pub(crate) fn resolved_risk_profile(
    config: &Config,
    choice: RiskChoice,
) -> Option<RiskProfileConfig> {
    config
        .risk_profiles
        .get(choice.preset_name())
        .cloned()
        .or_else(|| risk_preset(choice.preset_name()).map(|preset| (preset.values)()))
}

pub(crate) fn resolved_runtime_profile(
    config: &Config,
    choice: RuntimeChoice,
) -> Option<RuntimeProfileConfig> {
    config
        .runtime_profiles
        .get(choice.preset_name())
        .cloned()
        .or_else(|| runtime_preset(choice.preset_name()).map(|preset| (preset.values)()))
}

fn risk_choice_is_canonical_and_contained(config: &Config, choice: RiskChoice) -> bool {
    let Some(preset) = risk_preset(choice.preset_name()) else {
        return false;
    };
    let canonical = (preset.values)();
    let Some(resolved) = resolved_risk_profile(config, choice) else {
        return false;
    };
    if config.risk_profiles.contains_key(choice.preset_name())
        && !same_serialized_profile(&resolved, &canonical)
    {
        return false;
    }
    let policy = zeroclaw_config::policy::SecurityPolicy::from_risk_profile(
        &resolved,
        &config.agent_workspace_dir("zerona_preview"),
    );
    assess_effective_posture(&policy).is_ok()
}

fn runtime_choice_is_canonical(config: &Config, choice: RuntimeChoice) -> bool {
    let Some(preset) = runtime_preset(choice.preset_name()) else {
        return false;
    };
    let canonical = (preset.values)();
    let Some(resolved) = resolved_runtime_profile(config, choice) else {
        return false;
    };
    !config.runtime_profiles.contains_key(choice.preset_name())
        || same_serialized_profile(&resolved, &canonical)
}

fn same_serialized_profile<T: Serialize>(left: &T, right: &T) -> bool {
    match (serde_json::to_value(left), serde_json::to_value(right)) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
    }
}
