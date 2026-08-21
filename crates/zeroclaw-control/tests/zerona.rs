use std::collections::{BTreeSet, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use zeroclaw_api::attribution::{Attributable, ModelProviderKind, ProviderKind, Role};
use zeroclaw_api::model_provider::{ChatMessage, ChatRequest, ChatResponse, ModelProvider};
use zeroclaw_config::autonomy::AutonomyLevel;
use zeroclaw_config::policy::SecurityPolicy;
use zeroclaw_config::presets::{SelectorChoice, risk_preset};
use zeroclaw_config::schema::{AliasedAgentConfig, Config, RiskProfileConfig};
use zeroclaw_control::{
    AgentProposal, ApplyIntegration, CapabilityRestrictedProviderFactory, CurrentProviderFactory,
    GuardCode, IsolatedProvider, MAX_OPERATOR_TURNS, MemoryChoice, PersonalityFileProposal,
    ProfileDisposition, ProposalErrorCode, ProviderError, ProviderErrorCode,
    ProviderPickerInventory, ProviderTarget, RevisionBinding, RiskChoice, RuntimeChoice,
    SafeInventory, SessionErrorCode, ZeronaSession, assess_effective_posture, build_preview,
    parse_proposal, revalidate_proposal, validate_proposal,
};

fn isolated_config(temp: &tempfile::TempDir) -> Config {
    let mut config = Config {
        config_path: temp.path().join("config.toml"),
        data_dir: temp.path().join("data"),
        ..Config::default()
    };
    let safe = config
        .providers
        .models
        .ensure("ollama", "safe")
        .expect("ollama slot exists");
    safe.model = Some("llama3.2".to_string());
    config
}

fn add_host_process_alias(config: &mut Config) {
    let host = config
        .providers
        .models
        .ensure("kilocli", "host")
        .expect("kilocli slot exists");
    host.model = Some("host-model".to_string());
}

fn proposal_with_files(files: Vec<PersonalityFileProposal>) -> AgentProposal {
    AgentProposal {
        agent_alias: "researcher".to_string(),
        risk: RiskChoice::Balanced,
        runtime: RuntimeChoice::Balanced,
        memory: MemoryChoice::Sqlite,
        personality_files: files,
    }
}

fn proposal() -> AgentProposal {
    proposal_with_files(Vec::new())
}

#[derive(Debug, Clone)]
struct CapturedRequest {
    messages: Vec<ChatMessage>,
    tools_were_none: bool,
    model: String,
}

struct FakeProvider {
    responses: Mutex<VecDeque<ChatResponse>>,
    requests: Mutex<Vec<CapturedRequest>>,
}

impl FakeProvider {
    fn new(responses: Vec<ChatResponse>) -> Self {
        Self {
            responses: Mutex::new(responses.into()),
            requests: Mutex::new(Vec::new()),
        }
    }

    fn requests(&self) -> Vec<CapturedRequest> {
        self.requests.lock().expect("capture lock").clone()
    }
}

impl Attributable for FakeProvider {
    fn role(&self) -> Role {
        Role::Provider(ProviderKind::Model(ModelProviderKind::Ollama))
    }

    fn alias(&self) -> &str {
        "fake"
    }
}

#[async_trait]
impl ModelProvider for FakeProvider {
    async fn chat_with_system(
        &self,
        _system_prompt: Option<&str>,
        _message: &str,
        _model: &str,
        _temperature: Option<f64>,
    ) -> anyhow::Result<String> {
        Ok("unused".to_string())
    }

    async fn chat(
        &self,
        request: ChatRequest<'_>,
        model: &str,
        _temperature: Option<f64>,
    ) -> anyhow::Result<ChatResponse> {
        self.requests
            .lock()
            .expect("capture lock")
            .push(CapturedRequest {
                messages: request.messages.to_vec(),
                tools_were_none: request.tools.is_none(),
                model: model.to_string(),
            });
        Ok(self
            .responses
            .lock()
            .expect("response lock")
            .pop_front()
            .unwrap_or_else(|| text_response("Still refining.")))
    }
}

struct FakeFactory {
    provider: Arc<FakeProvider>,
    denied: BTreeSet<String>,
    creations: AtomicUsize,
}

impl FakeFactory {
    fn new(responses: Vec<ChatResponse>) -> Self {
        Self {
            provider: Arc::new(FakeProvider::new(responses)),
            denied: BTreeSet::new(),
            creations: AtomicUsize::new(0),
        }
    }
}

impl CapabilityRestrictedProviderFactory for FakeFactory {
    fn validate_capability_restricted_model_provider_alias(
        &self,
        config: &Config,
        reference: &str,
    ) -> Result<ProviderTarget, ProviderError> {
        if self.denied.contains(reference) {
            return Err(ProviderError::new(
                ProviderErrorCode::HostProcessDenied,
                reference,
            ));
        }
        let Some((family, alias, entry)) = config.providers.models.find_by_name(reference) else {
            return Err(ProviderError::new(
                ProviderErrorCode::NotConfigured,
                reference,
            ));
        };
        let Some(model) = entry.model.clone() else {
            return Err(ProviderError::new(
                ProviderErrorCode::MissingModel,
                reference,
            ));
        };
        Ok(ProviderTarget {
            reference: format!("{family}.{alias}"),
            model,
        })
    }

    fn create_isolated_model_provider_for_alias(
        &self,
        config: &Config,
        reference: &str,
    ) -> Result<IsolatedProvider, ProviderError> {
        let target = self.validate_capability_restricted_model_provider_alias(config, reference)?;
        self.creations.fetch_add(1, Ordering::SeqCst);
        let provider: Arc<dyn ModelProvider> = self.provider.clone();
        Ok(IsolatedProvider { target, provider })
    }
}

fn text_response(text: &str) -> ChatResponse {
    ChatResponse {
        text: Some(text.to_string()),
        tool_calls: Vec::new(),
        usage: None,
        reasoning_content: None,
    }
}

fn marked_proposal(proposal: &AgentProposal) -> String {
    format!(
        "PROPOSAL: {}",
        serde_json::to_string(proposal).expect("proposal serializes")
    )
}

fn credential_shaped_text() -> String {
    format!("token={}", "Q".repeat(32))
}

#[test]
fn inventory_is_narrow_secret_free_and_filters_host_process_providers() {
    let temp = tempfile::tempdir().expect("tempdir");
    let mut config = isolated_config(&temp);
    add_host_process_alias(&mut config);
    let credential = credential_shaped_text();
    config
        .providers
        .models
        .ensure("ollama", "safe")
        .expect("safe provider")
        .api_key = Some(credential.clone());

    let picker = ProviderPickerInventory::from_config(&config, &CurrentProviderFactory);
    assert_eq!(picker.provider_refs, vec!["ollama.safe"]);

    let inventory = SafeInventory::from_config(&config, &CurrentProviderFactory, "ollama.safe")
        .expect("selected provider is safe");
    assert_eq!(
        inventory.risk_choices,
        vec![RiskChoice::LockedDown, RiskChoice::Balanced]
    );
    assert_eq!(
        inventory.runtime_choices,
        vec![
            RuntimeChoice::Tight,
            RuntimeChoice::LocalSmall,
            RuntimeChoice::Balanced
        ]
    );
    assert_eq!(inventory.memory_choices, MemoryChoice::ALL);
    assert!(!inventory.uncontained_allowed);
    let rendered = serde_json::to_string(&inventory).expect("inventory serializes");
    assert!(!rendered.contains("yolo"));
    assert!(!rendered.contains("unbounded"));
    assert!(!rendered.contains("kilocli.host"));
    if rendered.contains(&credential) {
        panic!("safe inventory exposed a configured credential value");
    }
}

#[test]
fn effective_posture_rejects_only_unconfined_plus_unblocked_high_risk() {
    let renamed_full = RiskProfileConfig {
        level: AutonomyLevel::Full,
        block_high_risk_commands: false,
        ..RiskProfileConfig::default()
    };
    let full_policy =
        SecurityPolicy::from_risk_profile(&renamed_full, std::path::Path::new("/workspace"));
    assert_eq!(
        assess_effective_posture(&full_policy)
            .expect_err("renamed full profile must fail")
            .code,
        GuardCode::UncontainedPosture
    );

    let root_slash = RiskProfileConfig {
        workspace_only: true,
        allowed_roots: vec!["/".to_string()],
        block_high_risk_commands: false,
        ..RiskProfileConfig::default()
    };
    let root_policy =
        SecurityPolicy::from_risk_profile(&root_slash, std::path::Path::new("/workspace"));
    assert_eq!(
        assess_effective_posture(&root_policy)
            .expect_err("filesystem root must fail when high risk is unblocked")
            .code,
        GuardCode::UncontainedPosture
    );

    let scoped = RiskProfileConfig {
        workspace_only: true,
        allowed_roots: vec!["/tmp/zerona-scoped".to_string()],
        block_high_risk_commands: false,
        ..RiskProfileConfig::default()
    };
    let scoped_policy =
        SecurityPolicy::from_risk_profile(&scoped, std::path::Path::new("/workspace"));
    let summary = assess_effective_posture(&scoped_policy)
        .expect("a scoped extra root is still contained by this guard");
    assert!(!summary.filesystem_unconfined);
    assert!(!summary.uncontained);

    let blocked_root = RiskProfileConfig {
        workspace_only: false,
        block_high_risk_commands: true,
        ..RiskProfileConfig::default()
    };
    let blocked_policy =
        SecurityPolicy::from_risk_profile(&blocked_root, std::path::Path::new("/workspace"));
    assert!(assess_effective_posture(&blocked_policy).is_ok());
}

#[tokio::test]
async fn operator_and_model_credential_shapes_are_rejected() {
    let temp = tempfile::tempdir().expect("tempdir");
    let config = isolated_config(&temp);
    let factory = FakeFactory::new(vec![text_response(&credential_shaped_text())]);
    let mut session =
        ZeronaSession::new_with_factory(&config, &factory, "ollama.safe").expect("session starts");

    let operator_result = session
        .turn_with_factory(&config, &factory, &credential_shaped_text())
        .await;
    let Err(operator_error) = operator_result else {
        panic!("operator credential shape was accepted");
    };
    assert_eq!(operator_error.code, SessionErrorCode::OperatorInputRejected);
    assert_eq!(factory.creations.load(Ordering::SeqCst), 0);

    let model_result = session
        .turn_with_factory(&config, &factory, "Create a research assistant")
        .await;
    let Err(model_error) = model_result else {
        panic!("model credential shape was accepted");
    };
    assert_eq!(model_error.code, SessionErrorCode::ModelOutputRejected);

    let encoded = serde_json::json!({
        "agent_alias": "researcher",
        "risk": "balanced",
        "runtime": "balanced",
        "memory": "sqlite",
        "personality_files": [{
            "filename": "SOUL.md",
            "content": credential_shaped_text()
        }]
    });
    let parsed = parse_proposal(&format!("PROPOSAL: {encoded}"));
    let Err(error) = parsed else {
        panic!("proposal credential shape was accepted");
    };
    assert_eq!(error.code, ProposalErrorCode::CredentialLikeContent);
}

#[tokio::test]
async fn operator_model_and_personality_config_content_are_rejected() {
    let temp = tempfile::tempdir().expect("tempdir");
    let config = isolated_config(&temp);

    for rejected in [
        "Inspect https://internal.example/v1",
        "Inspect `https://internal.example/v1`",
        "[providers.models.custom.prod]\nmodel = \"private-model\"",
        "`model = \"private-model\"`",
        r#"{"providers":{"models":{"custom":{"prod":{}}}}}"#,
        r#"Here is config: {"providers":{"models":{"custom":{"prod":{}}}}}"#,
        "Run zeroclaw config get providers.models.custom.prod.uri",
    ] {
        let factory = FakeFactory::new(Vec::new());
        let mut session = ZeronaSession::new_with_factory(&config, &factory, "ollama.safe")
            .expect("session starts");
        let error = session
            .turn_with_factory(&config, &factory, rejected)
            .await
            .expect_err("operator config content must be refused before a provider call");
        assert_eq!(error.code, SessionErrorCode::OperatorInputRejected);
        assert_eq!(factory.creations.load(Ordering::SeqCst), 0);
    }

    for rejected in [
        "Please paste https://internal.example/v1",
        "Paste this next: [providers.models.custom.prod]",
    ] {
        let factory = FakeFactory::new(vec![text_response(rejected)]);
        let mut session = ZeronaSession::new_with_factory(&config, &factory, "ollama.safe")
            .expect("session starts");
        let error = session
            .turn_with_factory(&config, &factory, "Create a careful helper")
            .await
            .expect_err("model config solicitation must be refused");
        assert_eq!(error.code, SessionErrorCode::ModelOutputRejected);
    }

    for content in ["Use https://internal.example/v1", "[gateway]\nport = 42617"] {
        let candidate = proposal_with_files(vec![PersonalityFileProposal {
            filename: "SOUL.md".to_string(),
            content: content.to_string(),
        }]);
        assert_eq!(
            validate_proposal(
                &config,
                &FakeFactory::new(Vec::new()),
                "ollama.safe",
                &candidate
            )
            .expect_err("personality config content must be refused")
            .code,
            ProposalErrorCode::ConfigurationContent
        );
    }
}

#[test]
fn parser_rejects_unknown_generic_surface_keys_and_extra_objects() {
    for extra in [
        r#""channels":[]"#,
        r#""peer_groups":[]"#,
        r#""workspace":{"path":"/tmp"}"#,
        r#""model_provider":"ollama.other""#,
        r#""uri":"https://example.invalid""#,
        r#""allow_uncontained":true"#,
    ] {
        let text = format!(
            r#"PROPOSAL: {{"agent_alias":"researcher","risk":"balanced","runtime":"balanced","memory":"sqlite","personality_files":[],{extra}}}"#
        );
        let error = parse_proposal(&text).expect_err("unknown proposal key must fail closed");
        assert_eq!(error.code, ProposalErrorCode::InvalidJson);
    }

    let nested = r#"PROPOSAL: {"agent_alias":"researcher","risk":"balanced","runtime":"balanced","memory":"sqlite","personality_files":[{"filename":"SOUL.md","content":"kind","path":"elsewhere"}]}"#;
    assert_eq!(
        parse_proposal(nested)
            .expect_err("unknown personality key must fail")
            .code,
        ProposalErrorCode::InvalidJson
    );
    let two_objects = r#"PROPOSAL: {"agent_alias":"researcher","risk":"balanced","runtime":"balanced","memory":"sqlite","personality_files":[]} {}"#;
    assert_eq!(
        parse_proposal(two_objects)
            .expect_err("only one JSON object is accepted")
            .code,
        ProposalErrorCode::InvalidJson
    );
    assert!(
        parse_proposal("Tell me more about the agent.")
            .unwrap()
            .is_none()
    );
}

#[test]
fn alias_control_bidi_size_and_personality_filename_guards_fail_closed() {
    let temp = tempfile::tempdir().expect("tempdir");
    let mut config = isolated_config(&temp);
    let factory = FakeFactory::new(Vec::new());

    for alias in ["BadAlias", "bad-alias", "default", "bad\nname"] {
        let mut candidate = proposal();
        candidate.agent_alias = alias.to_string();
        assert!(validate_proposal(&config, &factory, "ollama.safe", &candidate).is_err());
    }
    config
        .agents
        .insert("researcher".to_string(), AliasedAgentConfig::default());
    assert_eq!(
        validate_proposal(&config, &factory, "ollama.safe", &proposal())
            .expect_err("agent alias collision must fail")
            .code,
        ProposalErrorCode::AgentAliasExists
    );
    config.agents.remove("researcher");

    for content in ["visible\u{1b}[31m", "left\u{202e}right"] {
        let candidate = proposal_with_files(vec![PersonalityFileProposal {
            filename: "SOUL.md".to_string(),
            content: content.to_string(),
        }]);
        assert!(validate_proposal(&config, &factory, "ollama.safe", &candidate).is_err());
    }

    let oversized = proposal_with_files(vec![PersonalityFileProposal {
        filename: "SOUL.md".to_string(),
        content: "x".repeat(zeroclaw_runtime::agent::personality::MAX_FILE_CHARS + 1),
    }]);
    assert_eq!(
        validate_proposal(&config, &factory, "ollama.safe", &oversized)
            .expect_err("oversized personality content must fail")
            .code,
        ProposalErrorCode::PersonalityFileTooLarge
    );

    let noncanonical = proposal_with_files(vec![PersonalityFileProposal {
        filename: "TOOLS.md".to_string(),
        content: "No tools.".to_string(),
    }]);
    assert_eq!(
        validate_proposal(&config, &factory, "ollama.safe", &noncanonical)
            .expect_err("noncanonical personality file must fail")
            .code,
        ProposalErrorCode::NoncanonicalPersonalityFile
    );
}

#[test]
fn valid_personality_files_allow_newline_tab_and_are_canonicalized() {
    let temp = tempfile::tempdir().expect("tempdir");
    let config = isolated_config(&temp);
    let factory = FakeFactory::new(Vec::new());
    let candidate = proposal_with_files(vec![
        PersonalityFileProposal {
            filename: "AGENTS.md".to_string(),
            content: "# Rules\n\tBe careful.".to_string(),
        },
        PersonalityFileProposal {
            filename: "SOUL.md".to_string(),
            content: "# Soul\nBe kind.".to_string(),
        },
    ]);
    let validated = validate_proposal(&config, &factory, "ollama.safe", &candidate)
        .expect("valid personality proposal");
    assert_eq!(
        validated
            .proposal()
            .personality_files
            .iter()
            .map(|file| file.filename.as_str())
            .collect::<Vec<_>>(),
        vec!["SOUL.md", "AGENTS.md"]
    );

    let duplicate = proposal_with_files(vec![
        PersonalityFileProposal {
            filename: "SOUL.md".to_string(),
            content: "one".to_string(),
        },
        PersonalityFileProposal {
            filename: "SOUL.md".to_string(),
            content: "two".to_string(),
        },
    ]);
    assert_eq!(
        validate_proposal(&config, &factory, "ollama.safe", &duplicate)
            .expect_err("duplicates must fail")
            .code,
        ProposalErrorCode::DuplicatePersonalityFile
    );
}

#[test]
fn valid_proposal_conversion_is_narrow_and_survives_quickstart_validate_only_without_files() {
    let temp = tempfile::tempdir().expect("tempdir");
    let config = isolated_config(&temp);
    let factory = FakeFactory::new(Vec::new());
    let workspace = config.agent_workspace_dir("researcher");
    let validated =
        validate_proposal(&config, &factory, "ollama.safe", &proposal()).expect("valid proposal");
    let submission = validated.to_builder_submission();

    assert_eq!(
        submission.model_provider,
        SelectorChoice::Existing("ollama.safe".to_string())
    );
    assert!(submission.channels.is_empty());
    assert!(submission.peer_groups.is_empty());
    assert!(submission.agent.system_prompt.is_empty());
    assert!(submission.agent.personality_file.is_none());
    assert!(submission.agent.personality_files.is_empty());
    assert!(!workspace.exists());
    zeroclaw_runtime::quickstart::validate_only_with_surface(
        &submission,
        &config,
        zeroclaw_runtime::quickstart::Surface::Test,
    )
    .expect("empty-file conversion survives current Quickstart validation");
    assert!(
        !workspace.exists(),
        "the empty-file compatibility check must not create a workspace"
    );
}

#[test]
fn config_drift_fails_semantic_revalidation() {
    let temp = tempfile::tempdir().expect("tempdir");
    let mut config = isolated_config(&temp);
    let factory = FakeFactory::new(Vec::new());
    let validated = validate_proposal(&config, &factory, "ollama.safe", &proposal())
        .expect("initial proposal validates");

    config
        .agents
        .insert("researcher".to_string(), AliasedAgentConfig::default());
    assert_eq!(
        revalidate_proposal(&config, &factory, &validated)
            .expect_err("alias collision introduced after preview must fail")
            .code,
        ProposalErrorCode::AgentAliasExists
    );
    config.agents.remove("researcher");

    config.risk_profiles.insert(
        "balanced".to_string(),
        RiskProfileConfig {
            level: AutonomyLevel::Full,
            workspace_only: false,
            block_high_risk_commands: false,
            allowed_roots: vec!["/".to_string()],
            ..RiskProfileConfig::default()
        },
    );
    assert_eq!(
        revalidate_proposal(&config, &factory, &validated)
            .expect_err("widened preset collision must fail")
            .code,
        ProposalErrorCode::RiskChoiceUnavailable
    );
    config.risk_profiles.remove("balanced");

    config.providers.models.ollama.remove("safe");
    assert_eq!(
        revalidate_proposal(&config, &factory, &validated)
            .expect_err("removed provider must fail")
            .code,
        ProposalErrorCode::ProviderUnavailable
    );
}

#[test]
fn removed_preexisting_profile_requires_a_new_preview() {
    let temp = tempfile::tempdir().expect("tempdir");
    let mut config = isolated_config(&temp);
    let balanced = risk_preset("balanced").expect("built-in balanced preset");
    config
        .risk_profiles
        .insert("balanced".to_string(), (balanced.values)());
    let factory = FakeFactory::new(Vec::new());
    let validated = validate_proposal(&config, &factory, "ollama.safe", &proposal())
        .expect("proposal with exact preexisting preset validates");
    config.risk_profiles.remove("balanced");
    assert_eq!(
        revalidate_proposal(&config, &factory, &validated)
            .expect_err("profile removal changes preview materialization")
            .code,
        ProposalErrorCode::ProfileDrift
    );
}

#[tokio::test]
async fn direct_conversation_sends_no_tools_and_yields_a_validated_proposal() {
    let temp = tempfile::tempdir().expect("tempdir");
    let mut config = isolated_config(&temp);
    let credential = credential_shaped_text();
    config
        .providers
        .models
        .ensure("ollama", "safe")
        .expect("safe provider")
        .api_key = Some(credential.clone());
    let response = marked_proposal(&proposal_with_files(vec![PersonalityFileProposal {
        filename: "SOUL.md".to_string(),
        content: "# Soul\nCurious and careful.".to_string(),
    }]));
    let factory = FakeFactory::new(vec![text_response(&response)]);
    let mut session =
        ZeronaSession::new_with_factory(&config, &factory, "ollama.safe").expect("session starts");

    let turn = session
        .turn_with_factory(&config, &factory, "Make a careful research agent")
        .await
        .expect("provider proposal validates");
    assert!(turn.proposal.is_some());
    assert_eq!(factory.creations.load(Ordering::SeqCst), 1);
    let requests = factory.provider.requests();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].tools_were_none);
    assert_eq!(requests[0].model, "llama3.2");
    let system = &requests[0].messages[0].content;
    assert!(system.contains("zero tools"));
    assert!(system.contains("ollama.safe"));
    assert!(!system.contains("yolo"));
    assert!(!system.contains("unbounded"));
    if system.contains(&credential) {
        panic!("system prompt exposed a configured credential value");
    }
}

#[tokio::test]
async fn cancel_revise_and_preview_paths_do_not_create_workspace_or_mutate_config() {
    let temp = tempfile::tempdir().expect("tempdir");
    let config = isolated_config(&temp);
    let workspace = config.agent_workspace_dir("researcher");
    let before = serde_json::to_vec(&config).expect("config serializes");
    let factory = FakeFactory::new(vec![text_response("Let's refine the identity first.")]);
    let mut session =
        ZeronaSession::new_with_factory(&config, &factory, "ollama.safe").expect("session starts");

    let turn = session
        .turn_with_factory(&config, &factory, "Not ready yet")
        .await
        .expect("ordinary conversation succeeds");
    assert!(turn.proposal.is_none());
    drop(session);
    assert_eq!(before, serde_json::to_vec(&config).unwrap());
    assert!(!workspace.exists());

    let with_files = proposal_with_files(vec![PersonalityFileProposal {
        filename: "SOUL.md".to_string(),
        content: "# Soul\nDraft only.".to_string(),
    }]);
    let preview = build_preview(&config, &factory, "ollama.safe", &with_files)
        .expect("pure preview succeeds");
    assert_eq!(preview.revision_binding, RevisionBinding::Unavailable);
    assert_eq!(
        preview.persistence.apply_integration,
        ApplyIntegration::RevisionBoundHostRequired
    );
    assert!(
        preview
            .persistence
            .config_paths
            .contains(&"agents.researcher.memory.backend".to_string())
    );
    assert!(
        !preview
            .persistence
            .config_paths
            .contains(&"memory.backend".to_string()),
        "an add-agent preview must not claim an install-wide memory write"
    );
    assert!(
        preview
            .persistence
            .config_paths
            .iter()
            .all(|path| !path.starts_with("storage.")),
        "agent-scoped memory must not create install-wide storage"
    );
    assert_eq!(
        preview.persistence.risk_profile,
        ProfileDisposition::CreateBuiltInPreset
    );
    assert_eq!(preview.personality_files[0].content, "# Soul\nDraft only.");
    assert!(!preview.uncontained);
    assert!(!preview.effective_posture.uncontained);
    assert!(!workspace.exists());
    assert_eq!(before, serde_json::to_vec(&config).unwrap());

    let mut revision = with_files;
    revision.personality_files[0].filename = "MEMORY.md".to_string();
    assert!(validate_proposal(&config, &factory, "ollama.safe", &revision).is_err());
    assert!(!workspace.exists());
    assert_eq!(before, serde_json::to_vec(&config).unwrap());
}

#[tokio::test]
async fn session_enforces_the_48_operator_turn_bound() {
    let temp = tempfile::tempdir().expect("tempdir");
    let config = isolated_config(&temp);
    let factory = FakeFactory::new(Vec::new());
    let mut session =
        ZeronaSession::new_with_factory(&config, &factory, "ollama.safe").expect("session starts");
    for index in 0..MAX_OPERATOR_TURNS {
        session
            .turn_with_factory(&config, &factory, &format!("turn {index}"))
            .await
            .expect("bounded turn succeeds");
    }
    let error = session
        .turn_with_factory(&config, &factory, "one too many")
        .await
        .expect_err("49th operator turn must fail");
    assert_eq!(error.code, SessionErrorCode::TurnLimit);
}
