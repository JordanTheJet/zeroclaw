//! Closed set of safe onboarding operations + a deterministic parser.
//!
//! User input is mapped to one [`Operation`] here *before* any LLM is
//! consulted. The planner (see [`super::planner`]) is only reached when
//! this parser yields [`Operation::None`]; the planner's output is then
//! re-validated by re-parsing through this same function, so free-form
//! model text can never execute anything outside this vocabulary.

use zeroclaw_config::schema::Config;

/// Which gateway lifecycle action the user asked about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewayAction {
    Start,
    Stop,
    Restart,
}

impl GatewayAction {
    pub fn as_str(self) -> &'static str {
        match self {
            GatewayAction::Start => "start",
            GatewayAction::Stop => "stop",
            GatewayAction::Restart => "restart",
        }
    }
}

/// The complete, closed vocabulary the assistant can act on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Operation {
    /// Print the system overview snapshot.
    Overview,
    /// Friendly reply to a greeting / small talk.
    Greeting,
    /// List the allowed commands.
    Help,
    /// Run full diagnostics (`zeroclaw doctor`).
    Doctor,
    /// List configured models.
    Models,
    /// List configured agents.
    Agents,
    /// Show gateway reachability + service status.
    GatewayStatus,
    /// Print config validity / config issues.
    ValidateConfig,
    /// Launch the guided quickstart wizard (persistent).
    Setup,
    /// Set a configured provider's model: `<family>[.<alias>]/<model-id>`.
    SetDefaultModel { reference: String },
    /// Set an arbitrary config property (persistent).
    ConfigSet { path: String, value: String },
    /// Print the command to start/stop/restart the gateway service.
    Gateway { action: GatewayAction },
    /// Print the command to start the named (or only) agent.
    TalkToAgent { agent: Option<String> },
    /// Nothing matched; carry a user-facing hint. `exit` marks quit/exit.
    None { message: String, exit: bool },
}

impl Operation {
    /// Whether applying this operation changes persisted state and therefore
    /// requires explicit approval *before* it runs. `Setup` is excluded: it is
    /// interactive and asks for its own approval after collecting choices.
    pub fn is_persistent(&self) -> bool {
        matches!(
            self,
            Operation::SetDefaultModel { .. } | Operation::ConfigSet { .. }
        )
    }

    /// One-line description of a persistent operation, for the approval plan.
    /// Secret-ish config values are redacted.
    pub fn describe(&self) -> String {
        match self {
            Operation::Setup => "launch the guided setup wizard".to_string(),
            Operation::SetDefaultModel { reference } => {
                format!("set the model for `{reference}`")
            }
            Operation::ConfigSet { path, value } => {
                format!("set config `{path}` to {}", redact(path, value))
            }
            _ => "apply this action".to_string(),
        }
    }
}

/// Redact values whose config path is a secret field. Uses the schema's
/// canonical, derive-generated check (the same one `zeroclaw config set`
/// relies on) so it stays correct for every `#[secret]` field — including
/// ones whose names don't contain an obvious keyword (db_url, extra_headers).
fn redact(path: &str, value: &str) -> String {
    if Config::prop_is_secret(path) {
        "<redacted>".to_string()
    } else {
        format!("`{value}`")
    }
}

/// Parse one line of user (or planner) input into an [`Operation`].
///
/// Returns [`Operation::None`] for anything unrecognized so the caller can
/// fall back to the LLM planner.
pub fn parse(input: &str) -> Operation {
    let trimmed = input.trim();
    let lower = trimmed.to_ascii_lowercase();

    if trimmed.is_empty() {
        return none(crate::t(
            "cli-onboard-empty-input",
            "Tell me what to set up — try `setup`, `status`, `doctor`, `models`, or `agents`.",
        ));
    }
    if matches!(lower.as_str(), "quit" | "exit" | "bye" | "goodbye" | "q") {
        return Operation::None {
            message: crate::t("cli-onboard-bye", "Bye."),
            exit: true,
        };
    }
    if is_greeting(&lower) {
        return Operation::Greeting;
    }
    if is_help_request(&lower) {
        return Operation::Help;
    }
    if matches!(lower.as_str(), "overview" | "status" | "system") {
        return Operation::Overview;
    }

    // `config set <path> <value>` / `set config <path> <value>`
    if let Some(args) =
        strip_prefix_ci(trimmed, "config set ").or_else(|| strip_prefix_ci(trimmed, "set config "))
    {
        if let Some((path, value)) = split_first_token(args) {
            if !path.is_empty() && !value.trim().is_empty() {
                return Operation::ConfigSet {
                    path: path.to_string(),
                    value: value.trim().to_string(),
                };
            }
        }
    }

    if lower.contains("validate config") || lower.contains("config validate") {
        return Operation::ValidateConfig;
    }

    if lower.contains("doctor") || lower.contains("health") || lower.contains("diagnos") {
        return Operation::Doctor;
    }

    if lower.contains("gateway") {
        if lower.contains("restart") {
            return Operation::Gateway {
                action: GatewayAction::Restart,
            };
        }
        if lower.contains("stop") {
            return Operation::Gateway {
                action: GatewayAction::Stop,
            };
        }
        if lower.contains("start") {
            return Operation::Gateway {
                action: GatewayAction::Start,
            };
        }
        return Operation::GatewayStatus;
    }

    // Setup / onboarding / create-agent — all route to the guided wizard.
    // Checked after the more specific doctor/gateway intents so phrases like
    // "set up the gateway" reach the gateway branch, but before `agent`/`model`
    // so "create agent …" still launches the wizard.
    if is_setup_request(&lower) {
        return Operation::Setup;
    }

    if lower.contains("agent") {
        if is_talk_request(&lower) {
            return Operation::TalkToAgent {
                agent: extract_agent_id(trimmed),
            };
        }
        return Operation::Agents;
    }

    if lower.contains("model") {
        if let Some(reference) = set_model_reference(trimmed) {
            return Operation::SetDefaultModel { reference };
        }
        return Operation::Models;
    }

    none(crate::t(
        "cli-onboard-unknown-input",
        "I didn't quite catch that. I can `setup` an agent, check things with `status`/`doctor`, list `agents`/`models`, or `talk to agent`. Say `help` to see everything.",
    ))
}

/// Whether the input is a greeting or light small talk (handled warmly, no LLM).
fn is_greeting(lower: &str) -> bool {
    const EXACT: &[&str] = &[
        "hi",
        "hii",
        "hiya",
        "hey",
        "heya",
        "hello",
        "helo",
        "yo",
        "sup",
        "howdy",
        "hola",
        "thanks",
        "thank you",
        "thx",
        "ty",
        "cheers",
        "ok",
        "okay",
        "cool",
        "nice",
        "good morning",
        "good afternoon",
        "good evening",
    ];
    let t = lower.trim_end_matches(['!', '.', ' ']);
    EXACT.contains(&t) || t.starts_with("hi ") || t.starts_with("hey ") || t.starts_with("hello ")
}

/// Whether the input is asking for help / what the assistant can do.
fn is_help_request(lower: &str) -> bool {
    matches!(lower, "help" | "?" | "commands" | "menu")
        || lower.contains("help me")
        || lower.contains("can you help")
        || lower.contains("what can you do")
        || lower.contains("what can i do")
        || lower.contains("what do you do")
        || lower.contains("how do i use")
        || lower.contains("how does this work")
}

/// Build a non-exit [`Operation::None`] carrying an already-localized hint.
/// Callers pass the resolved Fluent string (via [`crate::t`]) so the message
/// stored in the enum — and later printed verbatim — never bypasses the
/// locale bundle, even though the `cli_fluent_coverage` source scan can't see
/// strings held in enum fields.
fn none(message: String) -> Operation {
    Operation::None {
        message,
        exit: false,
    }
}

/// Case-insensitive prefix strip that returns the remainder of the *original*
/// (case-preserving) string. Uses `str::get` so a prefix length that lands
/// inside a multibyte UTF-8 char yields `None` instead of panicking.
fn strip_prefix_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    match s.get(..prefix.len()) {
        Some(head) if head.eq_ignore_ascii_case(prefix) => Some(&s[prefix.len()..]),
        _ => None,
    }
}

/// Split off the first whitespace-delimited token, returning `(token, rest)`.
fn split_first_token(s: &str) -> Option<(&str, &str)> {
    let s = s.trim_start();
    let end = s.find(char::is_whitespace)?;
    Some((&s[..end], &s[end..]))
}

fn is_setup_request(lower: &str) -> bool {
    const TRIGGERS: &[&str] = &[
        "setup",
        "set me up",
        "set up",
        "onboard",
        "bootstrap",
        "first run",
        "first-run",
        "get started",
        "create agent",
        "create an agent",
        "create a agent",
        "create a new agent",
        "add agent",
        "add an agent",
        "new agent",
        "make an agent",
    ];
    TRIGGERS.iter().any(|t| lower.contains(t))
}

/// True when the input is a "talk to / switch to / open … agent" request
/// (as opposed to a bare `agents` listing).
fn is_talk_request(lower: &str) -> bool {
    const VERBS: &[&str] = &["talk to", "switch to", "open", "enter", "chat with"];
    VERBS.iter().any(|v| lower.contains(v))
}

/// Extract the agent id from "<verb> <id> agent" (original casing). Returns
/// `None` when no explicit id precedes the word "agent".
fn extract_agent_id(input: &str) -> Option<String> {
    let orig: Vec<&str> = input.split_whitespace().collect();
    let lower_tokens: Vec<String> = orig.iter().map(|t| t.to_ascii_lowercase()).collect();
    let agent_idx = lower_tokens
        .iter()
        .position(|t| t == "agent" || t == "agent.")?;
    agent_idx
        .checked_sub(1)
        .filter(|&i| {
            !matches!(
                lower_tokens[i].as_str(),
                "the" | "my" | "an" | "a" | "to" | "into" | "with"
            )
        })
        .and_then(|i| orig.get(i))
        .map(|t| {
            t.trim_matches(|c: char| !c.is_alphanumeric() && c != '-' && c != '_')
                .to_string()
        })
        .filter(|s| !s.is_empty())
}

/// Extract a `set/use/configure [default] model <ref>` reference where the
/// reference looks like a provider/model spec (contains `/`). Returns `None`
/// for a bare `models` listing request. Preserves the reference's casing.
fn set_model_reference(input: &str) -> Option<String> {
    let lower = input.to_ascii_lowercase();
    const VERBS: &[&str] = &["set ", "use ", "configure ", "switch ", "change "];
    if !VERBS.iter().any(|v| lower.contains(v)) {
        return None;
    }
    let orig: Vec<&str> = input.split_whitespace().collect();
    let lower_tokens: Vec<String> = orig.iter().map(|t| t.to_ascii_lowercase()).collect();
    let model_idx = lower_tokens.iter().position(|t| t.starts_with("model"))?;
    // Take the first provider/model spec after "model", skipping filler words
    // like "to"/"as" (e.g. "set default model to anthropic/claude-opus-4-8").
    orig.get(model_idx + 1..)?
        .iter()
        .find(|t| t.contains('/'))
        .map(|t| (*t).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multibyte_input_does_not_panic() {
        // Prefix length (11 bytes) lands inside the 2-byte 'é' — must not panic.
        for input in ["0123456789é hello", "héllo", "café au lait", "—"] {
            let _ = parse(input);
        }
    }

    #[test]
    fn config_set_parses_path_and_value() {
        match parse("config set gateway.port 8080") {
            Operation::ConfigSet { path, value } => {
                assert_eq!(path, "gateway.port");
                assert_eq!(value, "8080");
            }
            other => panic!("expected ConfigSet, got {other:?}"),
        }
    }

    #[test]
    fn set_default_model_tolerates_filler_words() {
        for input in [
            "set default model anthropic/claude-opus-4-8",
            "set default model to anthropic/claude-opus-4-8",
            "use the model as openai/gpt-5.5",
        ] {
            match parse(input) {
                Operation::SetDefaultModel { reference } => assert!(reference.contains('/')),
                other => panic!("{input:?} expected SetDefaultModel, got {other:?}"),
            }
        }
    }

    #[test]
    fn bare_models_request_lists_not_sets() {
        assert!(matches!(parse("models"), Operation::Models));
        assert!(matches!(parse("list models"), Operation::Models));
    }

    #[test]
    fn setup_does_not_shadow_gateway() {
        // "set up the gateway" should reach the gateway intent, not the wizard.
        assert!(matches!(
            parse("set up the gateway"),
            Operation::GatewayStatus
        ));
        assert!(matches!(
            parse("restart gateway"),
            Operation::Gateway {
                action: GatewayAction::Restart
            }
        ));
    }

    #[test]
    fn create_agent_routes_to_setup() {
        assert!(matches!(parse("create agent foo"), Operation::Setup));
        assert!(matches!(parse("set me up"), Operation::Setup));
        assert!(matches!(parse("setup"), Operation::Setup));
    }

    #[test]
    fn talk_to_named_agent_extracts_id() {
        match parse("talk to jj agent") {
            Operation::TalkToAgent { agent } => assert_eq!(agent.as_deref(), Some("jj")),
            other => panic!("expected TalkToAgent, got {other:?}"),
        }
        // Bare listing.
        assert!(matches!(parse("agents"), Operation::Agents));
    }

    #[test]
    fn quit_marks_exit() {
        assert!(matches!(parse("quit"), Operation::None { exit: true, .. }));
        assert!(matches!(parse("exit"), Operation::None { exit: true, .. }));
        assert!(matches!(
            parse("goodbye"),
            Operation::None { exit: true, .. }
        ));
    }

    #[test]
    fn greetings_get_a_friendly_reply() {
        for g in ["hi", "hello", "hey", "thanks", "hi there", "Good morning!"] {
            assert!(
                matches!(parse(g), Operation::Greeting),
                "{g:?} should greet"
            );
        }
    }

    #[test]
    fn help_phrasings_route_to_help() {
        for h in [
            "help",
            "?",
            "can you help",
            "what can you do",
            "help me",
            "what do you do",
        ] {
            assert!(matches!(parse(h), Operation::Help), "{h:?} should be Help");
        }
    }

    #[test]
    fn commands_are_not_mistaken_for_greetings() {
        assert!(matches!(parse("setup"), Operation::Setup));
        assert!(matches!(parse("status"), Operation::Overview));
        assert!(matches!(parse("agents"), Operation::Agents));
    }

    /// The hints carried in `Operation::None::message` are stored in an enum
    /// field, so the `cli_fluent_coverage` source scan can't see them. This
    /// closes that blind spot: every `None` message must resolve through the
    /// locale bundle, i.e. equal `crate::t(<key>, _)` for its key. (`crate::t`
    /// looks the key up in the embedded catalogue and ignores the fallback, so
    /// a non-empty result also proves the key exists.)
    #[test]
    fn none_messages_route_through_fluent() {
        // (input, expected key, expected exit)
        let cases = [
            ("", "cli-onboard-empty-input", false),
            (
                "\u{fffd}\u{fffd} not a command \u{fffd}",
                "cli-onboard-unknown-input",
                false,
            ),
            ("quit", "cli-onboard-bye", true),
        ];
        for (input, key, exit) in cases {
            match parse(input) {
                Operation::None {
                    message,
                    exit: got_exit,
                } => {
                    assert_eq!(got_exit, exit, "{input:?} exit flag");
                    let resolved = crate::t(key, "");
                    assert!(
                        !resolved.is_empty(),
                        "`{key}` missing from the locale bundle"
                    );
                    assert_eq!(message, resolved, "{input:?} must resolve via `{key}`");
                }
                other => panic!("{input:?} expected None, got {other:?}"),
            }
        }
    }
}
