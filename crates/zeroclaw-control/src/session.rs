use zeroclaw_api::model_provider::{ChatMessage, ChatRequest};
use zeroclaw_config::schema::Config;

use crate::FluentMessage;
use crate::guard::{TextMode, ensure_conversation_text, ensure_safe_text};
use crate::inventory::{
    CapabilityRestrictedProviderFactory, CurrentProviderFactory, ProviderTarget, SafeInventory,
    validated_target,
};
use crate::proposal::{ProposalError, ValidatedProposal, parse_proposal, validate_proposal};

pub const MAX_OPERATOR_TURNS: usize = 48;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionErrorCode {
    TurnLimit,
    OperatorInputRejected,
    ProviderUnavailable,
    ProviderCallFailed,
    ProviderReturnedToolCall,
    ModelOutputRejected,
    ProposalRejected,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionError {
    pub code: SessionErrorCode,
    pub field: String,
    proposal_error: Option<ProposalError>,
}

impl SessionError {
    fn new(code: SessionErrorCode, field: impl Into<String>) -> Self {
        Self {
            code,
            field: field.into(),
            proposal_error: None,
        }
    }

    fn proposal(error: ProposalError) -> Self {
        Self {
            code: SessionErrorCode::ProposalRejected,
            field: error.field.clone(),
            proposal_error: Some(error),
        }
    }

    #[must_use]
    pub fn proposal_error(&self) -> Option<&ProposalError> {
        self.proposal_error.as_ref()
    }

    #[must_use]
    pub fn fluent(&self) -> FluentMessage {
        if let Some(error) = &self.proposal_error {
            return error.fluent();
        }
        let key = match self.code {
            SessionErrorCode::TurnLimit => "cli-zerona-error-turn-limit",
            SessionErrorCode::OperatorInputRejected => "cli-zerona-error-operator-input",
            SessionErrorCode::ProviderUnavailable => "cli-zerona-error-provider-unavailable",
            SessionErrorCode::ProviderCallFailed => "cli-zerona-error-provider-call",
            SessionErrorCode::ProviderReturnedToolCall => {
                "cli-zerona-error-provider-returned-tool-call"
            }
            SessionErrorCode::ModelOutputRejected => "cli-zerona-error-model-output",
            SessionErrorCode::ProposalRejected => "cli-zerona-error-proposal",
        };
        FluentMessage::new(key).with_arg("field", self.field.clone())
    }
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Zerona session rejected {} ({:?})",
            self.field, self.code
        )
    }
}

impl std::error::Error for SessionError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionTurn {
    pub assistant_text: String,
    pub proposal: Option<ValidatedProposal>,
}

/// In-memory only conversation state. It stores the immutable host-selected
/// provider ref and chat history, but never stores Config or a provider handle.
pub struct ZeronaSession {
    selected_provider: ProviderTarget,
    history: Vec<ChatMessage>,
    operator_turns: usize,
}

impl ZeronaSession {
    pub fn new(
        config: &Config,
        selected_provider_ref: impl Into<String>,
    ) -> Result<Self, SessionError> {
        Self::new_with_factory(config, &CurrentProviderFactory, selected_provider_ref)
    }

    pub fn new_with_factory(
        config: &Config,
        factory: &(impl CapabilityRestrictedProviderFactory + ?Sized),
        selected_provider_ref: impl Into<String>,
    ) -> Result<Self, SessionError> {
        let selected_provider_ref = selected_provider_ref.into();
        SafeInventory::from_config(config, factory, &selected_provider_ref)
            .map_err(|_| SessionError::new(SessionErrorCode::ProviderUnavailable, "provider"))?;
        let selected_provider = validated_target(config, factory, &selected_provider_ref)
            .map_err(|_| SessionError::new(SessionErrorCode::ProviderUnavailable, "provider"))?;
        Ok(Self {
            selected_provider,
            history: Vec::new(),
            operator_turns: 0,
        })
    }

    #[must_use]
    pub fn selected_provider_ref(&self) -> &str {
        &self.selected_provider.reference
    }

    #[must_use]
    pub fn selected_model(&self) -> &str {
        &self.selected_provider.model
    }

    #[must_use]
    pub fn operator_turns(&self) -> usize {
        self.operator_turns
    }

    pub async fn turn(
        &mut self,
        config: &Config,
        operator_input: &str,
    ) -> Result<SessionTurn, SessionError> {
        self.turn_with_factory(config, &CurrentProviderFactory, operator_input)
            .await
    }

    pub async fn turn_with_factory(
        &mut self,
        config: &Config,
        factory: &(impl CapabilityRestrictedProviderFactory + ?Sized),
        operator_input: &str,
    ) -> Result<SessionTurn, SessionError> {
        if self.operator_turns >= MAX_OPERATOR_TURNS {
            return Err(SessionError::new(
                SessionErrorCode::TurnLimit,
                "operator_turns",
            ));
        }
        ensure_conversation_text(operator_input, TextMode::Multiline).map_err(|_| {
            SessionError::new(SessionErrorCode::OperatorInputRejected, "operator_input")
        })?;

        let inventory =
            SafeInventory::from_config(config, factory, &self.selected_provider.reference)
                .map_err(|_| {
                    SessionError::new(SessionErrorCode::ProviderUnavailable, "provider")
                })?;
        let expected_target = validated_target(config, factory, &self.selected_provider.reference)
            .map_err(|_| SessionError::new(SessionErrorCode::ProviderUnavailable, "provider"))?;
        if expected_target != self.selected_provider {
            return Err(SessionError::new(
                SessionErrorCode::ProviderUnavailable,
                "provider",
            ));
        }
        let isolated = factory
            .create_isolated_model_provider_for_alias(config, &self.selected_provider.reference)
            .map_err(|_| SessionError::new(SessionErrorCode::ProviderUnavailable, "provider"))?;
        if isolated.target != self.selected_provider {
            return Err(SessionError::new(
                SessionErrorCode::ProviderUnavailable,
                "provider",
            ));
        }

        let mut messages = Vec::with_capacity(self.history.len() + 2);
        messages.push(ChatMessage::system(render_system_prompt(&inventory)));
        messages.extend(self.history.iter().cloned());
        messages.push(ChatMessage::user(operator_input));

        self.operator_turns += 1;
        let response = isolated
            .provider
            .chat(
                ChatRequest {
                    messages: &messages,
                    tools: None,
                    thinking: None,
                },
                &isolated.target.model,
                None,
            )
            .await
            .map_err(|_| SessionError::new(SessionErrorCode::ProviderCallFailed, "provider"))?;

        if !response.tool_calls.is_empty() {
            return Err(SessionError::new(
                SessionErrorCode::ProviderReturnedToolCall,
                "model_output",
            ));
        }
        if let Some(reasoning) = response.reasoning_content.as_deref() {
            ensure_conversation_text(reasoning, TextMode::Multiline).map_err(|_| {
                SessionError::new(SessionErrorCode::ModelOutputRejected, "reasoning_output")
            })?;
        }
        let assistant_text = response.text.ok_or_else(|| {
            SessionError::new(SessionErrorCode::ModelOutputRejected, "model_output")
        })?;
        // The proposal envelope is JSON by design. Apply the credential and
        // terminal guard to the whole response here; `parse_proposal` applies
        // the URI/raw-config guard to conversational prose and then validates
        // each decoded proposal field separately.
        ensure_safe_text(&assistant_text, TextMode::Multiline).map_err(|_| {
            SessionError::new(SessionErrorCode::ModelOutputRejected, "model_output")
        })?;

        let proposal = parse_proposal(&assistant_text)
            .map_err(|error| {
                if error.field == "model_output" {
                    SessionError::new(SessionErrorCode::ModelOutputRejected, "model_output")
                } else {
                    SessionError::proposal(error)
                }
            })?
            .map(|proposal| {
                validate_proposal(
                    config,
                    factory,
                    &self.selected_provider.reference,
                    &proposal,
                )
            })
            .transpose()
            .map_err(SessionError::proposal)?;

        self.history.push(ChatMessage::user(operator_input));
        self.history
            .push(ChatMessage::assistant(assistant_text.clone()));
        Ok(SessionTurn {
            assistant_text,
            proposal,
        })
    }
}

fn render_system_prompt(inventory: &SafeInventory) -> String {
    let inventory_json = serde_json::to_string(inventory).unwrap_or_else(|_| "{}".to_string());
    format!(
        "You are Zerona, a dedicated guide for creating one ZeroClaw agent.\n\
         You have zero tools and no ability to read files, run commands, browse, save, or apply changes.\n\
         Never ask for credentials, tokens, secrets, URIs, raw config, channels, peer groups, workspace overrides, shell settings, file permissions, tools, or uncontained access.\n\
         The host already selected the model provider. Do not offer another provider and do not include a model_provider field.\n\
         Use only this safe inventory of identifiers (it contains no config values): {inventory_json}\n\
         Ask concise questions until the agent alias, risk, runtime, memory, and optional personality files are clear.\n\
         When ready, emit PROPOSAL: followed by exactly one JSON object and no code fence. The exact shape is:\n\
         {{\"agent_alias\":\"safe_alias\",\"risk\":\"locked_down|balanced\",\"runtime\":\"tight|local_small|balanced\",\"memory\":\"sqlite|markdown|none\",\"personality_files\":[{{\"filename\":\"SOUL.md\",\"content\":\"full file text\"}}]}}\n\
         Omit no required field. Add no other field. Personality filenames must come from the inventory and each full content must stay within its character limit."
    )
}
