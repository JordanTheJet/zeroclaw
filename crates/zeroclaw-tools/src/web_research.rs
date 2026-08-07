//! Web research delegate tool.
//!
//! The main agent asks a question; a bounded sub-agent loop does
//! search → fetch → distill against the configured `[web_search]` backend and
//! returns a written summary with a mandatory `Sources:` list. Raw
//! search-engine result text never reaches the primary context window — only
//! the distilled answer does.
//!
//! # Why this is a self-contained loop
//!
//! `zeroclaw-runtime` owns the full turn engine (`run_tool_call_loop`), but
//! this crate cannot depend on runtime — runtime depends on tool
//! implementations (see `crate::i18n` module docs). The two tools being scoped
//! (`web_search_tool`, `web_fetch`) live here, so the delegate lives here too
//! and drives the provider directly. `run_tool_call_loop` also returns only a
//! `String`, with no tool-call trace, so the deterministic source-harvesting
//! guarantee below would not be expressible through it.
//!
//! # Bounds
//!
//! Every run is capped on two independent axes — [`ResearchBounds`] — and both
//! degrade to a best-effort partial answer rather than an error: whatever was
//! gathered is still distilled and returned with its sources.

use async_trait::async_trait;
use regex::Regex;
use serde_json::json;
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};
use zeroclaw_api::model_provider::{ChatMessage, ChatRequest, ModelProvider};
use zeroclaw_api::tool::{Tool, ToolResult, ToolSpec};
use zeroclaw_config::policy::{SecurityPolicy, ToolOperation};
use zeroclaw_providers::{ModelProviderRuntimeOptions, ProviderDispatch};

/// Tool name, used for registration, policy lookup, and auto-approve matching.
pub const NAME: &str = "web_research";

/// Maximum tool calls one research run may execute. Counted per executed call
/// (not per model round) because each call is what costs a network round-trip.
const MAX_TOOL_CALLS: usize = 8;

/// Hard wall-clock ceiling for one research run.
const WALL_CLOCK_SECS: u64 = 180;

/// Budget for the final "wrap up now" call after the loop stops. Separate from
/// the main budget so a run that stopped *because* it timed out can still
/// produce a partial summary.
const WRAPUP_SECS: u64 = 45;

/// Cap on fallback source URLs scraped from search-result text when the
/// sub-agent searched but never fetched a page.
const MAX_FALLBACK_SOURCES: usize = 5;

/// Cap on how much of a single tool result is fed back into the sub-agent's
/// history, so one huge page cannot blow the sub-context.
const MAX_TOOL_RESULT_CHARS: usize = 12_000;

static URL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"https?://[^\s\)\]\},"'`<>]+"#).expect("static URL regex is valid")
});

/// The two independent limits on a research run.
#[derive(Debug, Clone, Copy)]
pub struct ResearchBounds {
    pub max_tool_calls: usize,
    pub wall_clock: Duration,
}

impl Default for ResearchBounds {
    fn default() -> Self {
        Self {
            max_tool_calls: MAX_TOOL_CALLS,
            wall_clock: Duration::from_secs(WALL_CLOCK_SECS),
        }
    }
}

/// Why the research loop stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StopReason {
    /// The sub-agent answered without requesting more tools.
    Completed,
    /// The tool-call budget was exhausted.
    MaxToolCalls,
    /// The wall-clock budget was exhausted.
    Timeout,
    /// The provider failed; whatever was gathered is still returned.
    ProviderError(String),
    /// The provider cannot do native tool calls, so a single deterministic
    /// search/fetch + distill pass ran instead of an agentic loop.
    SinglePass,
}

impl StopReason {
    /// True when the run ended early and the summary is best-effort partial.
    #[must_use]
    pub fn is_partial(&self) -> bool {
        matches!(
            self,
            Self::MaxToolCalls | Self::Timeout | Self::ProviderError(_)
        )
    }
}

/// Result of one research run.
#[derive(Debug, Clone)]
pub struct ResearchOutcome {
    pub summary: String,
    pub sources: Vec<String>,
    pub tool_calls_used: usize,
    pub stop_reason: StopReason,
}

/// Tracks the URLs a run may legitimately cite.
///
/// `fetched` is ground truth — a page we actually retrieved. `candidates` are
/// URLs merely *mentioned* in search-result text; they are only cited when
/// nothing was fetched, so a search-only run still attributes its claims.
#[derive(Debug, Default)]
struct SourceLedger {
    fetched: Vec<String>,
    candidates: Vec<String>,
}

impl SourceLedger {
    fn record_fetched(&mut self, url: &str) {
        push_unique(&mut self.fetched, url.trim());
    }

    fn record_candidates_from(&mut self, text: &str) {
        for m in URL_RE.find_iter(text) {
            if self.candidates.len() >= MAX_FALLBACK_SOURCES {
                return;
            }
            push_unique(&mut self.candidates, m.as_str());
        }
    }

    /// Sources to cite: retrieved pages, else the search-result candidates.
    fn resolve(self) -> Vec<String> {
        if self.fetched.is_empty() {
            self.candidates
        } else {
            self.fetched
        }
    }
}

fn push_unique(list: &mut Vec<String>, value: &str) {
    let value = value.trim_end_matches(['.', ',', ';']).trim();
    if !value.is_empty() && !list.iter().any(|existing| existing == value) {
        list.push(value.to_string());
    }
}

/// Build the sub-agent's system prompt.
///
/// Pure and public to the crate so the prompt contract (decomposition guidance
/// plus the non-negotiable `Sources:` mandate) is directly testable.
fn build_system_prompt(bounds: ResearchBounds, has_start_url: bool) -> String {
    let mut prompt = String::from(
        "You are a focused web-research sub-agent. Your only job is to answer the \
         user's research question from live web sources and return a written \
         briefing. You are not conversing with the user; you produce one final \
         answer.\n\n\
         ## How to search\n\n\
         - Decompose the question into several small, specific queries. Multiple \
         narrow searches beat one long stuffed query — search engines match \
         keywords, not sentences.\n\
         - Start broad to find the authoritative sources, then search again with \
         the precise terms, names, versions, or error strings you discovered.\n\
         - When a search result looks authoritative, fetch the page to read it. \
         Do not summarize from search snippets alone when the full page is \
         available.\n\
         - Prefer primary sources (official docs, specs, release notes, the \
         project's own repository) over aggregators and SEO content.\n\
         - If results contradict each other, say so explicitly and cite both.\n\n",
    );

    if has_start_url {
        prompt.push_str(
            "## Starting point\n\n\
             The user supplied a starting URL. Fetch and read it first, then \
             search only if it does not fully answer the question.\n\n",
        );
    }

    prompt.push_str(&format!(
        "## Budget\n\n\
         You may make at most {} tool calls, and the whole run is capped at {} \
         seconds. Spend them deliberately. When the budget runs out you will be \
         asked to summarize immediately with whatever you have, so do not save \
         your conclusions for a final step that may never come.\n\n\
         ## Required output format\n\n\
         Write a direct, self-contained briefing that answers the question. Do \
         not describe your search process. Then end your reply with a section \
         that begins with the exact line `Sources:` followed by one `- <url>` \
         line per page you actually used.\n\n\
         Including the `Sources:` section is mandatory. Never cite a URL you did \
         not actually retrieve. If you could not find an answer, say so plainly \
         and still list whatever you consulted.",
        bounds.max_tool_calls,
        bounds.wall_clock.as_secs()
    ));

    prompt
}

/// True when `summary` already ends with a `Sources:` section.
fn has_sources_section(summary: &str) -> bool {
    summary
        .lines()
        .any(|line| line.trim_start().to_lowercase().starts_with("sources:"))
}

/// Guarantee the returned briefing carries a `Sources:` section.
///
/// The prompt *asks* for one; this *ensures* one, so the tool's contract holds
/// even when the model ignores the instruction or the run was cut short.
fn ensure_sources_section(summary: &str, sources: &[String]) -> String {
    let summary = summary.trim();
    if has_sources_section(summary) {
        return summary.to_string();
    }

    let mut out = String::from(summary);
    if !out.is_empty() {
        out.push_str("\n\n");
    }
    out.push_str("Sources:\n");
    if sources.is_empty() {
        out.push_str("- (none retrieved)");
    } else {
        for (index, url) in sources.iter().enumerate() {
            if index > 0 {
                out.push('\n');
            }
            out.push_str("- ");
            out.push_str(url);
        }
    }
    out
}

/// Prefix a partial answer so the caller can see the run was truncated.
fn partial_notice(stop_reason: &StopReason) -> Option<&'static str> {
    match stop_reason {
        StopReason::MaxToolCalls => Some(
            "[partial: the research sub-agent hit its tool-call budget; \
             the briefing below is based on what it gathered so far]",
        ),
        StopReason::Timeout => Some(
            "[partial: the research sub-agent hit its time budget; \
             the briefing below is based on what it gathered so far]",
        ),
        StopReason::ProviderError(_) => Some(
            "[partial: the research sub-agent's model call failed; \
             the briefing below is based on what it gathered so far]",
        ),
        StopReason::Completed | StopReason::SinglePass => None,
    }
}

/// Render an outcome into the text the main agent receives.
fn render_outcome(outcome: &ResearchOutcome) -> String {
    let body = ensure_sources_section(&outcome.summary, &outcome.sources);
    match partial_notice(&outcome.stop_reason) {
        Some(notice) => format!("{notice}\n\n{body}"),
        None => body,
    }
}

fn truncate_tool_result(text: &str) -> String {
    if text.chars().count() <= MAX_TOOL_RESULT_CHARS {
        return text.to_string();
    }
    let mut out: String = text.chars().take(MAX_TOOL_RESULT_CHARS).collect();
    out.push_str("\n... [truncated]");
    out
}

fn find_tool<'a>(tools: &'a [Arc<dyn Tool>], name: &str) -> Option<&'a Arc<dyn Tool>> {
    tools.iter().find(|t| t.name() == name)
}

/// Execute one sub-agent tool call and fold its result into the ledger.
async fn execute_scoped_call(
    tools: &[Arc<dyn Tool>],
    name: &str,
    args: &serde_json::Value,
    ledger: &mut SourceLedger,
) -> String {
    let Some(tool) = find_tool(tools, name) else {
        return format!(
            "Error: tool '{name}' is not available to the research sub-agent. \
             Available: {}",
            tools
                .iter()
                .map(|t| t.name())
                .collect::<Vec<_>>()
                .join(", ")
        );
    };

    // A fetch is ground truth: record the target before running, so a page that
    // errors mid-download is still attributable.
    if name == "web_fetch"
        && let Some(url) = args.get("url").and_then(|v| v.as_str())
    {
        ledger.record_fetched(url);
    }

    match tool.execute(args.clone()).await {
        Ok(result) => {
            let text = result.output.to_string();
            if name == "web_search_tool" {
                ledger.record_candidates_from(&text);
            }
            if result.success {
                truncate_tool_result(&text)
            } else {
                format!(
                    "Error from {name}: {}",
                    result.error.unwrap_or_else(|| "unknown error".to_string())
                )
            }
        }
        Err(e) => format!("Error from {name}: {e}"),
    }
}

/// Ask the model for a final briefing using only the history gathered so far.
async fn request_wrapup(
    provider: &dyn ModelProvider,
    model: &str,
    temperature: Option<f64>,
    history: &[ChatMessage],
) -> Option<String> {
    let mut messages = history.to_vec();
    messages.push(ChatMessage::user(
        "Your research budget is now exhausted. Stop searching and write the \
         final briefing immediately, using only what you have already gathered. \
         Remember to end with the mandatory `Sources:` section listing the pages \
         you actually retrieved.",
    ));

    let response = tokio::time::timeout(
        Duration::from_secs(WRAPUP_SECS),
        ProviderDispatch::from_ref(provider).chat(
            ChatRequest {
                messages: &messages,
                tools: None,
                thinking: None,
            },
            model,
            temperature,
        ),
    )
    .await;

    match response {
        Ok(Ok(chat)) => {
            let text = chat.text_or_empty().trim().to_string();
            (!text.is_empty()).then_some(text)
        }
        _ => None,
    }
}

/// Drive the bounded search → fetch → distill loop.
///
/// Takes the provider and tool set by reference so tests can inject stubs and
/// exercise the bounding logic without a network or a real model.
async fn run_research_loop(
    provider: &dyn ModelProvider,
    model: &str,
    temperature: Option<f64>,
    tools: &[Arc<dyn Tool>],
    question: &str,
    start_url: Option<&str>,
    bounds: ResearchBounds,
) -> ResearchOutcome {
    let specs: Vec<ToolSpec> = tools.iter().map(|t| t.spec()).collect();
    let mut ledger = SourceLedger::default();

    let mut history = vec![
        ChatMessage::system(build_system_prompt(bounds, start_url.is_some())),
        ChatMessage::user(match start_url {
            Some(url) => format!("Research question: {question}\n\nStart from this page: {url}"),
            None => format!("Research question: {question}"),
        }),
    ];

    let deadline = Instant::now() + bounds.wall_clock;
    let mut tool_calls_used = 0usize;
    let mut summary: Option<String> = None;
    let stop_reason;

    loop {
        let Some(remaining) = deadline.checked_duration_since(Instant::now()).filter(|d| {
            // `checked_duration_since` returns the elapsed-past-deadline amount
            // only when now < deadline; a zero budget means we are out of time.
            !d.is_zero()
        }) else {
            stop_reason = StopReason::Timeout;
            break;
        };

        let response = tokio::time::timeout(
            remaining,
            ProviderDispatch::from_ref(provider).chat(
                ChatRequest {
                    messages: &history,
                    tools: Some(&specs),
                    thinking: None,
                },
                model,
                temperature,
            ),
        )
        .await;

        let chat = match response {
            Err(_elapsed) => {
                stop_reason = StopReason::Timeout;
                break;
            }
            Ok(Err(e)) => {
                stop_reason = StopReason::ProviderError(e.to_string());
                break;
            }
            Ok(Ok(chat)) => chat,
        };

        if !chat.has_tool_calls() {
            summary = Some(chat.text_or_empty().trim().to_string());
            stop_reason = StopReason::Completed;
            break;
        }

        // Keep the assistant's narration in history for continuity. Tool
        // results come back as user-role observations rather than native
        // `tool` messages: `ChatRequest` carries only `[ChatMessage]`, which
        // structurally cannot round-trip a `tool_call_id`, and an unpaired
        // `tool` message is rejected by several provider APIs.
        let narration = chat.text_or_empty().trim().to_string();
        if !narration.is_empty() {
            history.push(ChatMessage::assistant(narration));
        }

        let mut budget_exhausted = false;
        for call in &chat.tool_calls {
            if tool_calls_used >= bounds.max_tool_calls {
                budget_exhausted = true;
                break;
            }
            tool_calls_used += 1;

            let args: serde_json::Value =
                serde_json::from_str(&call.arguments).unwrap_or_else(|_| json!({}));
            let observation = execute_scoped_call(tools, &call.name, &args, &mut ledger).await;
            history.push(ChatMessage::user(format!(
                "Result of {}({}):\n{observation}",
                call.name, args
            )));
        }

        if budget_exhausted {
            stop_reason = StopReason::MaxToolCalls;
            break;
        }
    }

    // Any early stop still owes the caller a best-effort briefing.
    if summary.is_none() && stop_reason.is_partial() {
        summary = request_wrapup(provider, model, temperature, &history).await;
    }

    ResearchOutcome {
        summary: summary.unwrap_or_default(),
        sources: ledger.resolve(),
        tool_calls_used,
        stop_reason,
    }
}

/// Single deterministic search/fetch + distill pass.
///
/// Used when the provider cannot make native tool calls. Without this,
/// `chat`'s prompt-guided fallback returns prose with **no** parsed tool calls
/// (see `ModelProvider::chat`), so the agentic loop would return a confident,
/// sourceless answer — strictly worse than the raw search tool it replaces.
async fn run_single_pass_research(
    provider: &dyn ModelProvider,
    model: &str,
    temperature: Option<f64>,
    tools: &[Arc<dyn Tool>],
    question: &str,
    start_url: Option<&str>,
) -> ResearchOutcome {
    let mut ledger = SourceLedger::default();
    let mut tool_calls_used = 0usize;

    let gathered = match start_url {
        Some(url) => {
            tool_calls_used += 1;
            execute_scoped_call(tools, "web_fetch", &json!({ "url": url }), &mut ledger).await
        }
        None => {
            tool_calls_used += 1;
            execute_scoped_call(
                tools,
                "web_search_tool",
                &json!({ "query": question }),
                &mut ledger,
            )
            .await
        }
    };

    let messages = vec![
        ChatMessage::system(
            "You are a web-research sub-agent. Answer the question using only the \
             retrieved material below. Do not invent facts or URLs. End your reply \
             with a section beginning with the exact line `Sources:` listing the \
             URLs you used.",
        ),
        ChatMessage::user(format!(
            "Research question: {question}\n\nRetrieved material:\n{gathered}"
        )),
    ];

    let summary = match tokio::time::timeout(
        Duration::from_secs(WRAPUP_SECS),
        ProviderDispatch::from_ref(provider).chat(
            ChatRequest {
                messages: &messages,
                tools: None,
                thinking: None,
            },
            model,
            temperature,
        ),
    )
    .await
    {
        Ok(Ok(chat)) => chat.text_or_empty().trim().to_string(),
        Ok(Err(e)) => {
            return ResearchOutcome {
                summary: String::new(),
                sources: ledger.resolve(),
                tool_calls_used,
                stop_reason: StopReason::ProviderError(e.to_string()),
            };
        }
        Err(_elapsed) => {
            return ResearchOutcome {
                summary: String::new(),
                sources: ledger.resolve(),
                tool_calls_used,
                stop_reason: StopReason::Timeout,
            };
        }
    };

    ResearchOutcome {
        summary,
        sources: ledger.resolve(),
        tool_calls_used,
        stop_reason: StopReason::SinglePass,
    }
}

/// Delegate tool that answers a research question from the live web.
pub struct WebResearchTool {
    security: Arc<SecurityPolicy>,
    /// Tools the research sub-agent may call. Deliberately search + fetch
    /// only: no shell, no writes, and no local-filesystem readers (a hostile
    /// page could otherwise steer the sub-agent into reading local files and
    /// exfiltrating them through a fetch URL).
    scoped_tools: Vec<Arc<dyn Tool>>,
    provider_family: String,
    model: String,
    temperature: Option<f64>,
    api_key: Option<String>,
    provider_runtime_options: ModelProviderRuntimeOptions,
    bounds: ResearchBounds,
}

impl WebResearchTool {
    pub fn new(
        security: Arc<SecurityPolicy>,
        scoped_tools: Vec<Arc<dyn Tool>>,
        provider_family: String,
        model: String,
        temperature: Option<f64>,
        api_key: Option<String>,
        provider_runtime_options: ModelProviderRuntimeOptions,
    ) -> Self {
        Self {
            security,
            scoped_tools,
            provider_family,
            model,
            temperature,
            api_key,
            provider_runtime_options,
            bounds: ResearchBounds::default(),
        }
    }

    /// Names of the tools the sub-agent may call, for diagnostics and tests.
    #[must_use]
    pub fn scoped_tool_names(&self) -> Vec<&str> {
        self.scoped_tools.iter().map(|t| t.name()).collect()
    }
}

#[async_trait]
impl Tool for WebResearchTool {
    fn name(&self) -> &str {
        NAME
    }

    fn description(&self) -> &str {
        "Research a question on the live web and return a written briefing with a \
         Sources list. Runs a bounded search-and-read sub-agent, so raw search \
         results never enter this conversation. Use this instead of searching \
         directly; ask a full question, not keywords."
    }

    fn parameters_schema(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "question": {
                    "type": "string",
                    "description": "The research question, phrased as a full question \
                                    rather than search keywords. Include any context \
                                    that constrains a good answer (versions, dates, \
                                    platform)."
                },
                "url": {
                    "type": "string",
                    "description": "Optional starting page. When given, the sub-agent \
                                    reads this page first and only searches if it does \
                                    not fully answer the question."
                }
            },
            "required": ["question"]
        })
    }

    async fn execute(&self, args: serde_json::Value) -> anyhow::Result<ToolResult> {
        if let Err(error) = self
            .security
            .enforce_tool_operation(ToolOperation::Act, NAME)
        {
            return Ok(ToolResult::err(error));
        }

        let question = match args.get("question").and_then(|v| v.as_str()) {
            Some(q) if !q.trim().is_empty() => q.trim(),
            _ => {
                return Ok(ToolResult::err(
                    "Missing or empty required parameter: question",
                ));
            }
        };

        let start_url = args
            .get("url")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|u| !u.is_empty());

        if self.scoped_tools.is_empty() {
            return Ok(ToolResult::err(
                "web_research has no research tools available; enable [web_search] \
                 and/or [web_fetch]",
            ));
        }

        let provider: Box<dyn ModelProvider> =
            match zeroclaw_providers::create_model_provider_with_options(
                &self.provider_family,
                self.api_key.as_deref(),
                &self.provider_runtime_options,
            ) {
                Ok(p) => p,
                Err(e) => {
                    return Ok(ToolResult::err(format!(
                        "Failed to create model_provider: {e}"
                    )));
                }
            };

        let outcome = if provider.supports_native_tools() {
            run_research_loop(
                &*provider,
                &self.model,
                self.temperature,
                &self.scoped_tools,
                question,
                start_url,
                self.bounds,
            )
            .await
        } else {
            run_single_pass_research(
                &*provider,
                &self.model,
                self.temperature,
                &self.scoped_tools,
                question,
                start_url,
            )
            .await
        };

        // A run that gathered nothing AND produced nothing is a failure, not an
        // empty briefing — surface it so the agent can react.
        if outcome.summary.trim().is_empty() && outcome.sources.is_empty() {
            let detail = match &outcome.stop_reason {
                StopReason::ProviderError(e) => format!("model call failed: {e}"),
                StopReason::Timeout => "the research run timed out".to_string(),
                other => format!("the research run ended without a result ({other:?})"),
            };
            return Ok(ToolResult::err(format!(
                "web_research produced no answer: {detail}"
            )));
        }

        let rendered = render_outcome(&outcome);
        if outcome.stop_reason.is_partial() {
            Ok(ToolResult::partial(
                rendered,
                format!("partial result ({:?})", outcome.stop_reason),
            ))
        } else {
            Ok(ToolResult::ok(rendered))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use zeroclaw_api::model_provider::{ChatResponse, ToolCall};

    // ── Prompt contract ──────────────────────────────────────────────

    #[test]
    fn system_prompt_mandates_a_sources_section() {
        let prompt = build_system_prompt(ResearchBounds::default(), false);
        assert!(
            prompt.contains("`Sources:`"),
            "prompt must name the Sources section verbatim: {prompt}"
        );
        assert!(
            prompt.contains("mandatory"),
            "prompt must state the Sources section is mandatory: {prompt}"
        );
        assert!(
            prompt.contains("Never cite a URL you did not actually retrieve"),
            "prompt must forbid fabricated citations: {prompt}"
        );
    }

    #[test]
    fn system_prompt_teaches_query_decomposition() {
        let prompt = build_system_prompt(ResearchBounds::default(), false);
        assert!(
            prompt.contains("Decompose the question into several small, specific queries"),
            "prompt must teach decomposition: {prompt}"
        );
        assert!(
            prompt.contains(
                "Multiple \
         narrow searches beat one long stuffed query"
            ) || prompt.contains("narrow searches beat one long stuffed query"),
            "prompt must state that several narrow searches beat one stuffed query: {prompt}"
        );
    }

    #[test]
    fn system_prompt_states_the_actual_bounds() {
        let bounds = ResearchBounds {
            max_tool_calls: 3,
            wall_clock: Duration::from_secs(42),
        };
        let prompt = build_system_prompt(bounds, false);
        assert!(prompt.contains("at most 3 tool calls"), "{prompt}");
        assert!(prompt.contains("capped at 42"), "{prompt}");
    }

    #[test]
    fn system_prompt_mentions_the_start_url_only_when_one_is_given() {
        assert!(!build_system_prompt(ResearchBounds::default(), false).contains("Starting point"));
        assert!(build_system_prompt(ResearchBounds::default(), true).contains("Starting point"));
    }

    // ── Sources guarantee ────────────────────────────────────────────

    #[test]
    fn ensure_sources_section_appends_when_the_model_omitted_it() {
        let out = ensure_sources_section("The answer is 42.", &["https://a.example".to_string()]);
        assert!(out.contains("Sources:"), "{out}");
        assert!(out.contains("- https://a.example"), "{out}");
    }

    #[test]
    fn ensure_sources_section_preserves_a_model_written_section() {
        let summary = "The answer is 42.\n\nSources:\n- https://model.example";
        let out = ensure_sources_section(summary, &["https://harvested.example".to_string()]);
        assert_eq!(
            out, summary,
            "an existing Sources section must be preserved"
        );
        assert!(!out.contains("harvested.example"));
    }

    #[test]
    fn ensure_sources_section_is_present_even_with_no_sources() {
        let out = ensure_sources_section("Nothing found.", &[]);
        assert!(out.contains("Sources:"), "{out}");
        assert!(out.contains("(none retrieved)"), "{out}");
    }

    // ── Source ledger ────────────────────────────────────────────────

    #[test]
    fn ledger_prefers_fetched_pages_over_search_candidates() {
        let mut ledger = SourceLedger::default();
        ledger.record_candidates_from("see https://candidate.example/a for more");
        ledger.record_fetched("https://fetched.example/page");
        assert_eq!(ledger.resolve(), vec!["https://fetched.example/page"]);
    }

    #[test]
    fn ledger_falls_back_to_candidates_when_nothing_was_fetched() {
        let mut ledger = SourceLedger::default();
        ledger.record_candidates_from("https://one.example and https://two.example");
        assert_eq!(
            ledger.resolve(),
            vec!["https://one.example", "https://two.example"]
        );
    }

    #[test]
    fn ledger_deduplicates_and_caps_candidates() {
        let mut ledger = SourceLedger::default();
        ledger.record_fetched("https://a.example");
        ledger.record_fetched("https://a.example");
        assert_eq!(ledger.fetched.len(), 1);

        let many: String = (0..20)
            .map(|i| format!("https://s{i}.example "))
            .collect::<String>();
        let mut ledger = SourceLedger::default();
        ledger.record_candidates_from(&many);
        assert_eq!(ledger.candidates.len(), MAX_FALLBACK_SOURCES);
    }

    // ── Stub tools + provider ────────────────────────────────────────

    struct StubTool {
        name: &'static str,
        schema: serde_json::Value,
        output: String,
        calls: Arc<Mutex<Vec<serde_json::Value>>>,
    }

    impl StubTool {
        fn new(name: &'static str, schema: serde_json::Value, output: &str) -> Self {
            Self {
                name,
                schema,
                output: output.to_string(),
                calls: Arc::new(Mutex::new(Vec::new())),
            }
        }
    }

    #[async_trait]
    impl Tool for StubTool {
        fn name(&self) -> &str {
            self.name
        }
        fn description(&self) -> &str {
            "stub"
        }
        fn parameters_schema(&self) -> serde_json::Value {
            self.schema.clone()
        }
        async fn execute(&self, args: serde_json::Value) -> anyhow::Result<ToolResult> {
            self.calls.lock().expect("stub lock").push(args);
            Ok(ToolResult::ok(self.output.clone()))
        }
    }

    zeroclaw_api::mock_tool_attribution!(StubTool);

    /// `ModelProvider` requires `Attributable`; the tool macro cannot supply it
    /// for a non-`Tool` type, so the provider stubs get a shared hand impl.
    macro_rules! stub_provider_attribution {
        ($($ty:ty),+ $(,)?) => {
            $(
                impl zeroclaw_api::attribution::Attributable for $ty {
                    fn role(&self) -> zeroclaw_api::attribution::Role {
                        zeroclaw_api::attribution::Role::Provider(
                            zeroclaw_api::attribution::ProviderKind::Model(
                                zeroclaw_api::attribution::ModelProviderKind::OpenRouter,
                            ),
                        )
                    }
                    fn alias(&self) -> &str {
                        "stub"
                    }
                }
            )+
        };
    }
    stub_provider_attribution!(AlwaysToolCallsProvider, ScriptedProvider);

    fn search_stub(output: &str) -> Arc<StubTool> {
        Arc::new(StubTool::new(
            "web_search_tool",
            json!({"type": "object", "properties": {"query": {"type": "string"}}}),
            output,
        ))
    }

    fn fetch_stub(output: &str) -> Arc<StubTool> {
        Arc::new(StubTool::new(
            "web_fetch",
            json!({"type": "object", "properties": {"url": {"type": "string"}}}),
            output,
        ))
    }

    fn tool_call(id: &str, name: &str, args: serde_json::Value) -> ToolCall {
        ToolCall {
            id: id.to_string(),
            name: name.to_string(),
            arguments: args.to_string(),
            extra_content: None,
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

    /// Never stops asking for tools — exercises the bounding logic.
    struct AlwaysToolCallsProvider {
        rounds: AtomicUsize,
    }

    #[async_trait]
    impl ModelProvider for AlwaysToolCallsProvider {
        fn supports_native_tools(&self) -> bool {
            true
        }
        async fn chat_with_system(
            &self,
            _system_prompt: Option<&str>,
            _message: &str,
            _model: &str,
            _temperature: Option<f64>,
        ) -> anyhow::Result<String> {
            Ok(String::new())
        }
        async fn chat(
            &self,
            request: ChatRequest<'_>,
            _model: &str,
            _temperature: Option<f64>,
        ) -> anyhow::Result<ChatResponse> {
            // No tools offered => this is the wrap-up call.
            if request.tools.is_none() {
                return Ok(text_response("Best effort briefing."));
            }
            let round = self.rounds.fetch_add(1, Ordering::SeqCst);
            Ok(ChatResponse {
                text: Some(format!("round {round}")),
                tool_calls: vec![tool_call(
                    &format!("c{round}"),
                    "web_search_tool",
                    json!({"query": format!("q{round}")}),
                )],
                usage: None,
                reasoning_content: None,
            })
        }
    }

    /// Replays a fixed script of responses, one per `chat` call.
    struct ScriptedProvider {
        script: Mutex<std::collections::VecDeque<ChatResponse>>,
        native: bool,
        seen_tool_specs: Mutex<Vec<Vec<String>>>,
    }

    impl ScriptedProvider {
        fn new(script: Vec<ChatResponse>, native: bool) -> Self {
            Self {
                script: Mutex::new(script.into()),
                native,
                seen_tool_specs: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait]
    impl ModelProvider for ScriptedProvider {
        fn supports_native_tools(&self) -> bool {
            self.native
        }
        async fn chat_with_system(
            &self,
            _system_prompt: Option<&str>,
            _message: &str,
            _model: &str,
            _temperature: Option<f64>,
        ) -> anyhow::Result<String> {
            Ok(String::new())
        }
        async fn chat(
            &self,
            request: ChatRequest<'_>,
            _model: &str,
            _temperature: Option<f64>,
        ) -> anyhow::Result<ChatResponse> {
            self.seen_tool_specs.lock().expect("spec lock").push(
                request
                    .tools
                    .unwrap_or(&[])
                    .iter()
                    .map(|s| s.name.clone())
                    .collect(),
            );
            self.script
                .lock()
                .expect("script lock")
                .pop_front()
                .ok_or_else(|| anyhow::Error::msg("script exhausted"))
        }
    }

    // ── Loop bounds ──────────────────────────────────────────────────

    #[tokio::test]
    async fn loop_stops_at_the_tool_call_budget_and_returns_a_partial() {
        let search = search_stub("result https://found.example/doc");
        let tools: Vec<Arc<dyn Tool>> = vec![search.clone()];
        let provider = AlwaysToolCallsProvider {
            rounds: AtomicUsize::new(0),
        };
        let bounds = ResearchBounds {
            max_tool_calls: 3,
            wall_clock: Duration::from_secs(30),
        };

        let outcome = run_research_loop(
            &provider,
            "m",
            None,
            &tools,
            "why is the sky blue?",
            None,
            bounds,
        )
        .await;

        assert_eq!(outcome.stop_reason, StopReason::MaxToolCalls);
        assert_eq!(
            outcome.tool_calls_used, 3,
            "must execute exactly the budgeted number of tool calls"
        );
        assert_eq!(
            search.calls.lock().expect("stub lock").len(),
            3,
            "the underlying tool must not be invoked past the budget"
        );
        assert!(
            outcome.stop_reason.is_partial(),
            "budget exhaustion is a partial result"
        );
        assert_eq!(outcome.summary, "Best effort briefing.");
    }

    #[tokio::test]
    async fn budget_exhaustion_still_renders_a_sources_section() {
        let tools: Vec<Arc<dyn Tool>> = vec![search_stub("see https://found.example/doc")];
        let provider = AlwaysToolCallsProvider {
            rounds: AtomicUsize::new(0),
        };
        let outcome = run_research_loop(
            &provider,
            "m",
            None,
            &tools,
            "q",
            None,
            ResearchBounds {
                max_tool_calls: 2,
                wall_clock: Duration::from_secs(30),
            },
        )
        .await;

        let rendered = render_outcome(&outcome);
        assert!(rendered.contains("[partial:"), "{rendered}");
        assert!(rendered.contains("Sources:"), "{rendered}");
        assert!(rendered.contains("https://found.example/doc"), "{rendered}");
    }

    #[tokio::test]
    async fn zero_wall_clock_budget_stops_before_any_provider_call() {
        let search = search_stub("unused");
        let tools: Vec<Arc<dyn Tool>> = vec![search.clone()];
        let provider = AlwaysToolCallsProvider {
            rounds: AtomicUsize::new(0),
        };

        let outcome = run_research_loop(
            &provider,
            "m",
            None,
            &tools,
            "q",
            None,
            ResearchBounds {
                max_tool_calls: 8,
                wall_clock: Duration::ZERO,
            },
        )
        .await;

        assert_eq!(outcome.stop_reason, StopReason::Timeout);
        assert_eq!(outcome.tool_calls_used, 0);
        assert!(search.calls.lock().expect("stub lock").is_empty());
    }

    #[tokio::test]
    async fn loop_completes_when_the_model_answers_without_tools() {
        let provider = ScriptedProvider::new(
            vec![
                ChatResponse {
                    text: Some("looking".into()),
                    tool_calls: vec![tool_call(
                        "c1",
                        "web_fetch",
                        json!({"url": "https://a.example/p"}),
                    )],
                    usage: None,
                    reasoning_content: None,
                },
                text_response("Done.\n\nSources:\n- https://a.example/p"),
            ],
            true,
        );
        let tools: Vec<Arc<dyn Tool>> = vec![fetch_stub("page body")];

        let outcome = run_research_loop(
            &provider,
            "m",
            None,
            &tools,
            "q",
            None,
            ResearchBounds::default(),
        )
        .await;

        assert_eq!(outcome.stop_reason, StopReason::Completed);
        assert_eq!(outcome.tool_calls_used, 1);
        assert_eq!(outcome.sources, vec!["https://a.example/p"]);
        assert!(!outcome.stop_reason.is_partial());
    }

    #[tokio::test]
    async fn loop_offers_only_the_scoped_tools_to_the_model() {
        let provider = ScriptedProvider::new(vec![text_response("done")], true);
        let tools: Vec<Arc<dyn Tool>> = vec![search_stub("r"), fetch_stub("p")];

        let _ = run_research_loop(
            &provider,
            "m",
            None,
            &tools,
            "q",
            None,
            ResearchBounds::default(),
        )
        .await;

        let seen = provider.seen_tool_specs.lock().expect("spec lock").clone();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0], vec!["web_search_tool", "web_fetch"]);
    }

    #[tokio::test]
    async fn unknown_tool_calls_are_reported_without_aborting_the_run() {
        let provider = ScriptedProvider::new(
            vec![
                ChatResponse {
                    text: None,
                    tool_calls: vec![tool_call("c1", "shell", json!({"command": "rm -rf /"}))],
                    usage: None,
                    reasoning_content: None,
                },
                text_response("Could not use shell."),
            ],
            true,
        );
        let tools: Vec<Arc<dyn Tool>> = vec![search_stub("r")];

        let outcome = run_research_loop(
            &provider,
            "m",
            None,
            &tools,
            "q",
            None,
            ResearchBounds::default(),
        )
        .await;

        assert_eq!(outcome.stop_reason, StopReason::Completed);
        assert_eq!(
            outcome.tool_calls_used, 1,
            "a rejected call still consumes budget, so a loop of bad names cannot spin"
        );
    }

    #[tokio::test]
    async fn provider_error_returns_a_partial_rather_than_failing_the_run() {
        let provider = ScriptedProvider::new(
            vec![ChatResponse {
                text: None,
                tool_calls: vec![tool_call(
                    "c1",
                    "web_fetch",
                    json!({"url": "https://a.example/p"}),
                )],
                usage: None,
                reasoning_content: None,
            }],
            true,
        );
        let tools: Vec<Arc<dyn Tool>> = vec![fetch_stub("body")];

        let outcome = run_research_loop(
            &provider,
            "m",
            None,
            &tools,
            "q",
            None,
            ResearchBounds::default(),
        )
        .await;

        assert!(matches!(outcome.stop_reason, StopReason::ProviderError(_)));
        assert_eq!(
            outcome.sources,
            vec!["https://a.example/p"],
            "sources gathered before the failure must survive"
        );
        assert!(render_outcome(&outcome).contains("Sources:"));
    }

    // ── Non-native providers ─────────────────────────────────────────

    #[tokio::test]
    async fn single_pass_runs_a_real_search_for_non_native_providers() {
        let search = search_stub("https://found.example/doc — a page");
        let tools: Vec<Arc<dyn Tool>> = vec![search.clone()];
        let provider = ScriptedProvider::new(vec![text_response("Distilled answer.")], false);

        let outcome = run_single_pass_research(&provider, "m", None, &tools, "why?", None).await;

        assert_eq!(outcome.stop_reason, StopReason::SinglePass);
        assert_eq!(
            search.calls.lock().expect("stub lock")[0]["query"],
            "why?",
            "the question must be searched verbatim"
        );
        assert_eq!(outcome.sources, vec!["https://found.example/doc"]);
        assert!(render_outcome(&outcome).contains("Sources:"));
    }

    #[tokio::test]
    async fn single_pass_starts_from_the_supplied_url() {
        let fetch = fetch_stub("page body");
        let tools: Vec<Arc<dyn Tool>> = vec![search_stub("unused"), fetch.clone()];
        let provider = ScriptedProvider::new(vec![text_response("Answer.")], false);

        let outcome = run_single_pass_research(
            &provider,
            "m",
            None,
            &tools,
            "what?",
            Some("https://start.example/page"),
        )
        .await;

        assert_eq!(
            fetch.calls.lock().expect("stub lock")[0]["url"],
            "https://start.example/page"
        );
        assert_eq!(outcome.sources, vec!["https://start.example/page"]);
    }

    // ── Tool surface ─────────────────────────────────────────────────

    fn test_tool(scoped: Vec<Arc<dyn Tool>>) -> WebResearchTool {
        WebResearchTool::new(
            Arc::new(SecurityPolicy::default()),
            scoped,
            "openrouter".to_string(),
            "test-model".to_string(),
            None,
            None,
            ModelProviderRuntimeOptions::default(),
        )
    }

    #[test]
    fn tool_metadata_declares_question_and_optional_url() {
        let tool = test_tool(vec![search_stub("r")]);
        assert_eq!(tool.name(), "web_research");

        let schema = tool.parameters_schema();
        assert!(schema["properties"]["question"].is_object());
        assert!(schema["properties"]["url"].is_object());
        let required = schema["required"].as_array().expect("required array");
        assert_eq!(
            required,
            &vec![json!("question")],
            "only question is required"
        );
    }

    #[tokio::test]
    async fn execute_rejects_a_missing_question() {
        let tool = test_tool(vec![search_stub("r")]);
        let result = tool.execute(json!({})).await.expect("execute");
        assert!(!result.success);
        assert!(result.error.expect("error").contains("question"));
    }

    #[tokio::test]
    async fn execute_rejects_a_blank_question() {
        let tool = test_tool(vec![search_stub("r")]);
        let result = tool
            .execute(json!({"question": "   "}))
            .await
            .expect("execute");
        assert!(!result.success);
    }

    #[tokio::test]
    async fn execute_reports_when_no_research_tools_are_available() {
        let tool = test_tool(vec![]);
        let result = tool
            .execute(json!({"question": "anything"}))
            .await
            .expect("execute");
        assert!(!result.success);
        assert!(result.error.expect("error").contains("no research tools"));
    }

    #[test]
    fn scoped_tool_names_excludes_shell_and_write_tools() {
        let tool = test_tool(vec![search_stub("r"), fetch_stub("p")]);
        let names = tool.scoped_tool_names();
        assert_eq!(names, vec!["web_search_tool", "web_fetch"]);
        assert!(!names.contains(&"shell"));
        assert!(!names.contains(&"file_write"));
    }
}
