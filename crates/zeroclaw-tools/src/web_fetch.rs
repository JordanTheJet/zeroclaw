use crate::helpers::domain_guard;
use async_trait::async_trait;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;
use zeroclaw_api::tool::{Tool, ToolOutput, ToolResult};
use zeroclaw_config::policy::SecurityPolicy;
use zeroclaw_config::schema::{FirecrawlConfig, ProxyConfig, ProxyScope};

/// Minimum body length to consider a standard fetch successful.
/// Bodies shorter than this are treated as JS-only pages that need Firecrawl.
const FIRECRAWL_MIN_BODY_LEN: usize = 100;

/// Appended once when a response was cut short, whether by the display cap or by
/// a decode budget that stopped the decompressor.
const TRUNCATION_MARKER: &str = "\n\n... [Response truncated due to size limit] ...";

const WEB_FETCH_PROXY_PINNING_ERROR: &str = "web_fetch requires direct transport so validated DNS answers remain pinned; set \
     proxy.scope = \"services\" and omit tool.* from proxy.services, or disable the proxy; \
     proxy.scope = \"environment\" is incompatible with the pinned standard fetch";

/// Size of *converted* text (bytes) above which a response is written to a
/// file in the agent workspace instead of being returned inline.
///
/// At or below this, behaviour is unchanged: the body comes back in the tool
/// result. Above it, half a megabyte of markdown in one tool result would
/// flood the model's context and the old hard-truncation dropped the tail
/// outright, so the full text is spilled to disk and the model is handed a
/// path it can read or search with the workspace file tools.
const SPILL_THRESHOLD_BYTES: usize = 50_000;

/// Directory, relative to the workspace root, that oversized responses are
/// spilled into. Kept as components rather than a `"tmp/web_fetch"` literal
/// so the join is separator-correct on every platform.
const SPILL_DIR_COMPONENTS: [&str; 2] = ["tmp", "web_fetch"];

/// Web fetch tool: fetches a web page and converts HTML to plain text for LLM consumption.
///
/// Unlike `http_request` (an API client returning raw responses), this tool:
/// - Only supports GET
/// - Follows redirects (up to 10)
/// - Converts HTML to clean plain text via `nanohtml2text`
/// - Passes through text/plain, text/markdown, and application/json as-is
/// - Sets a descriptive User-Agent
/// - Falls back to Firecrawl API when standard fetch fails (if enabled)
pub struct WebFetchTool {
    security: Arc<SecurityPolicy>,
    allowed_domains: Vec<String>,
    blocked_domains: Vec<String>,
    allowed_private_hosts: Vec<String>,
    /// Network-specific NAT64 prefixes this deployment's translator serves.
    /// Snapshotted at construction like `allowed_domains`; an IPv6 answer
    /// inside one of them is classified by the IPv4 address it embeds.
    nat64_prefixes: Vec<domain_guard::Nat64Prefix>,
    max_response_size: usize,
    timeout_secs: u64,
    firecrawl: FirecrawlConfig,
}

impl WebFetchTool {
    pub fn new(
        security: Arc<SecurityPolicy>,
        allowed_domains: Vec<String>,
        blocked_domains: Vec<String>,
        max_response_size: usize,
        timeout_secs: u64,
        firecrawl: FirecrawlConfig,
        allowed_private_hosts: Vec<String>,
        nat64_prefixes: Vec<String>,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            security,
            allowed_domains: domain_guard::normalize_allowed_domains(
                allowed_domains,
                "web_fetch.allowed_domains",
            )?,
            blocked_domains: domain_guard::normalize_allowed_domains(
                blocked_domains,
                "web_fetch.blocked_domains",
            )?,
            allowed_private_hosts: domain_guard::normalize_allowed_domains(
                allowed_private_hosts,
                "web_fetch.allowed_private_hosts",
            )?,
            nat64_prefixes: domain_guard::parse_nat64_prefixes(
                &nat64_prefixes,
                "security.nat64_prefixes",
            )?,
            max_response_size,
            timeout_secs,
            firecrawl,
        })
    }

    #[cfg(test)]
    fn validate_url(&self, raw_url: &str) -> anyhow::Result<String> {
        validate_target_url(
            raw_url,
            &self.allowed_domains,
            &self.blocked_domains,
            &self.allowed_private_hosts,
            "web_fetch",
        )
    }

    async fn resolve_target(&self, raw_url: &str) -> anyhow::Result<ResolvedWebFetchTarget> {
        let raw_url = raw_url.to_string();
        let allowed_domains = self.allowed_domains.clone();
        let blocked_domains = self.blocked_domains.clone();
        let allowed_private_hosts = self.allowed_private_hosts.clone();
        let nat64_prefixes = self.nat64_prefixes.clone();

        tokio::task::spawn_blocking(move || {
            resolve_target_url(
                &raw_url,
                &allowed_domains,
                &blocked_domains,
                &allowed_private_hosts,
                &nat64_prefixes,
                "web_fetch",
            )
        })
        .await
        .map_err(|e| anyhow::Error::msg(format!("web_fetch DNS validation task failed: {e}")))?
    }

    fn truncate_response(&self, text: &str) -> String {
        if self.max_response_size == 0 {
            return text.to_string();
        }
        if text.len() > self.max_response_size {
            let mut truncated = text
                .chars()
                .take(self.max_response_size)
                .collect::<String>();
            truncated.push_str(TRUNCATION_MARKER);
            truncated
        } else {
            text.to_string()
        }
    }

    /// Read the body, decoding a compressed `Content-Encoding`, and report
    /// whether a budget cut it short. The caller marks truncation after any
    /// HTML-to-text conversion, so the marker never runs through the converter
    /// and a body the decoder stopped early is still marked even when the
    /// converted text ends up under the cap. This tool only ever sends `GET`,
    /// so no request-method bypass applies; the shared status-based bodyless
    /// handling (e.g. `204 No Content`) still does.
    async fn read_response_text_limited(
        &self,
        response: reqwest::Response,
    ) -> anyhow::Result<CappedBody> {
        let limit = (self.max_response_size != 0).then_some(self.max_response_size);
        let (text, cap_hit) = crate::http_decode::read_decoded_text(response, limit, None).await?;
        Ok(CappedBody { text, cap_hit })
    }

    /// Write an oversized converted body to a file inside the agent workspace
    /// and return the short message that replaces it in the tool result.
    ///
    /// `None` means "no spill happened" — an unresolvable workspace, a
    /// containment failure, or an I/O error. Callers fall back to the
    /// pre-existing inline truncation, which is degraded but never wrong.
    async fn spill_to_workspace(
        &self,
        url: &str,
        text: &str,
        extension: &str,
        title: Option<&str>,
        cap_hit: bool,
    ) -> Option<String> {
        match self.try_spill_to_workspace(url, text, extension).await {
            Ok((relative_path, byte_count)) => Some(spill_message(
                url,
                title,
                byte_count,
                &relative_path,
                cap_hit,
            )),
            Err(e) => {
                ::zeroclaw_log::record!(
                    WARN,
                    ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Note)
                        .with_outcome(::zeroclaw_log::EventOutcome::Unknown)
                        .with_attrs(::serde_json::json!({
                            "phase": "spill_to_workspace",
                            "error": format!("{}", e),
                        })),
                    "web_fetch: could not spill oversized response to the workspace, \
                     falling back to inline truncation"
                );
                None
            }
        }
    }

    /// Resolve the spill path, prove it is inside the workspace, and write.
    ///
    /// Returns the workspace-*relative* path (what `file_read` and
    /// `content_search` expect) plus the byte count written.
    async fn try_spill_to_workspace(
        &self,
        url: &str,
        text: &str,
        extension: &str,
    ) -> anyhow::Result<(PathBuf, usize)> {
        // The workspace root has exactly one source of truth in this
        // codebase: `SecurityPolicy::workspace_dir`
        // (crates/zeroclaw-config/src/policy.rs). It is the same field
        // `SecurityPolicy::resolve_tool_path` and
        // `SecurityPolicy::is_resolved_path_allowed` use to root `file_read`
        // and `file_write`, and `WebFetchTool` already holds the policy. Do
        // not introduce a second resolution path here (no env var, no
        // `std::env::temp_dir()`, no constructor-threaded copy) — a divergent
        // second answer is exactly the drift bug AGENTS.md bans.
        let configured_root = self.security.workspace_dir.as_path();
        if configured_root.as_os_str().is_empty() {
            anyhow::bail!("workspace_dir is empty");
        }
        let root = tokio::fs::canonicalize(configured_root)
            .await
            .map_err(|e| anyhow::Error::msg(format!("workspace root is not resolvable: {e}")))?;

        let mut spill_dir = root.clone();
        for component in SPILL_DIR_COMPONENTS {
            spill_dir.push(component);
        }
        tokio::fs::create_dir_all(&spill_dir)
            .await
            .map_err(|e| anyhow::Error::msg(format!("failed to create spill directory: {e}")))?;

        // Re-resolve AFTER creation. `create_dir_all` follows symlinks, so a
        // symlinked `tmp/` planted inside the workspace could otherwise land
        // the write outside the sandbox. This is the containment guard: a
        // spill that does not resolve under the workspace root is abandoned,
        // never written.
        let spill_dir = tokio::fs::canonicalize(&spill_dir)
            .await
            .map_err(|e| anyhow::Error::msg(format!("spill directory is not resolvable: {e}")))?;
        if !spill_dir.starts_with(&root) {
            anyhow::bail!(
                "spill directory {} escapes the workspace root {}",
                spill_dir.display(),
                root.display()
            );
        }

        let path = spill_dir.join(spill_file_name(url, text, extension));
        // `spill_file_name` sanitizes to a single component, but prove it
        // rather than trust it: a name that smuggled in a separator or `..`
        // would re-parent the file out of the checked directory.
        if path.parent() != Some(spill_dir.as_path()) {
            anyhow::bail!("spill file name escaped the spill directory");
        }

        tokio::fs::write(&path, text)
            .await
            .map_err(|e| anyhow::Error::msg(format!("failed to write spill file: {e}")))?;

        let relative = path
            .strip_prefix(&root)
            .map_err(|e| anyhow::Error::msg(format!("spill path is not workspace-relative: {e}")))?
            .to_path_buf();

        Ok((relative, text.len()))
    }

    /// Build the standard-fetch client, wiring the redirect policy that keeps
    /// the DNS pin honest.
    ///
    /// The custom policy is the SSRF boundary for redirects: it caps the chain,
    /// refuses any hop that leaves the pinned host, and re-runs the target
    /// validation on each hop. When it denies a hop it sets the returned flag,
    /// which `should_fallback_to_firecrawl` reads to guarantee that a redirect
    /// blocked here is never retried through Firecrawl — that would hand the
    /// blocked URL to a third party and defeat the denial.
    ///
    /// `execute()` and the redirect regression tests both build their client
    /// here so the policy under test is the policy that ships.
    fn build_redirect_guarded_client(
        &self,
        target: &ResolvedWebFetchTarget,
        timeout_secs: u64,
    ) -> reqwest::Result<RedirectGuardedClient> {
        let allowed_domains = self.allowed_domains.clone();
        let blocked_domains = self.blocked_domains.clone();
        let allowed_private_hosts = self.allowed_private_hosts.clone();
        let pinned_host = target.host.clone();
        let redirect_policy_rejected = Arc::new(AtomicBool::new(false));
        let rejected_by_policy = Arc::clone(&redirect_policy_rejected);
        let redirect_policy = reqwest::redirect::Policy::custom(move |attempt| {
            if attempt.previous().len() >= 10 {
                rejected_by_policy.store(true, Ordering::Relaxed);
                return attempt.error(std::io::Error::other("Too many redirects (max 10)"));
            }

            if let Err(err) = validate_redirect_target(
                attempt.url().as_str(),
                &pinned_host,
                &allowed_domains,
                &blocked_domains,
                &allowed_private_hosts,
            ) {
                rejected_by_policy.store(true, Ordering::Relaxed);
                return attempt.error(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!("Blocked redirect target: {err}"),
                ));
            }

            attempt.follow()
        });

        // Negotiate the encodings `http_decode` can decode. reqwest's own
        // compression features are intentionally disabled (they'd unify across
        // the whole workspace), so this header is set explicitly here.
        let mut default_headers = reqwest::header::HeaderMap::new();
        default_headers.insert(
            reqwest::header::ACCEPT_ENCODING,
            reqwest::header::HeaderValue::from_static("gzip, deflate, br"),
        );
        let builder = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(timeout_secs))
            .connect_timeout(Duration::from_secs(10))
            .redirect(redirect_policy)
            .user_agent("ZeroClaw/0.1 (web_fetch)")
            .default_headers(default_headers);
        let client = pin_resolved_host(builder, target).build()?;

        Ok(RedirectGuardedClient {
            client,
            redirect_policy_rejected,
        })
    }

    /// Whether the standard fetch result should trigger a Firecrawl fallback.
    fn should_fallback_to_firecrawl(
        &self,
        result: &ToolResult,
        redirect_policy_rejected: bool,
    ) -> bool {
        if !self.firecrawl.enabled || redirect_policy_rejected {
            return false;
        }
        // Fallback on failure (HTTP error, network error, etc.)
        if !result.success {
            return true;
        }
        // Fallback on empty or very short body (JS-only pages)
        if result.output.trim().len() < FIRECRAWL_MIN_BODY_LEN {
            return true;
        }
        false
    }

    /// Fetch content via the Firecrawl API.
    async fn fetch_via_firecrawl(&self, url: &str) -> anyhow::Result<ToolResult> {
        let api_key = std::env::var(&self.firecrawl.api_key_env).map_err(|_| {
            ::zeroclaw_log::record!(
                ERROR,
                ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Reject)
                    .with_outcome(::zeroclaw_log::EventOutcome::Failure)
                    .with_attrs(::serde_json::json!({
                        "env_var": &self.firecrawl.api_key_env,
                    })),
                "web_fetch: Firecrawl API key missing from env"
            );
            anyhow::Error::msg(format!(
                "Firecrawl API key not found in environment variable '{}'",
                self.firecrawl.api_key_env
            ))
        })?;

        let endpoint = format!("{}/scrape", self.firecrawl.api_url.trim_end_matches('/'));

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(60))
            .build()
            .map_err(|e| {
                ::zeroclaw_log::record!(
                    ERROR,
                    ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Fail)
                        .with_outcome(::zeroclaw_log::EventOutcome::Failure)
                        .with_attrs(::serde_json::json!({"error": format!("{}", e)})),
                    "web_fetch: failed to build Firecrawl HTTP client"
                );
                anyhow::Error::msg(format!("Failed to build Firecrawl HTTP client: {e}"))
            })?;

        let body = json!({
            "url": url,
            "formats": ["markdown"]
        });

        let response = client
            .post(&endpoint)
            .header("Authorization", format!("Bearer {api_key}"))
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|e| {
                ::zeroclaw_log::record!(
                    ERROR,
                    ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Fail)
                        .with_outcome(::zeroclaw_log::EventOutcome::Failure)
                        .with_attrs(::serde_json::json!({
                            "phase": "firecrawl_request",
                            "error": format!("{}", e),
                        })),
                    "web_fetch: Firecrawl request failed"
                );
                anyhow::Error::msg(format!("Firecrawl request failed: {e}"))
            })?;

        let status = response.status();
        if !status.is_success() {
            let error_body = response.text().await.unwrap_or_default();
            return Ok(ToolResult {
                success: false,
                output: ToolOutput::default(),
                error: Some(format!(
                    "Firecrawl API error: HTTP {} - {}",
                    status.as_u16(),
                    error_body
                )),
            });
        }

        let resp_json: serde_json::Value = response.json().await.map_err(|e| {
            ::zeroclaw_log::record!(
                ERROR,
                ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Fail)
                    .with_outcome(::zeroclaw_log::EventOutcome::Failure)
                    .with_attrs(::serde_json::json!({
                        "phase": "firecrawl_response_parse",
                        "error": format!("{}", e),
                    })),
                "web_fetch: failed to parse Firecrawl response"
            );
            anyhow::Error::msg(format!("Failed to parse Firecrawl response: {e}"))
        })?;

        let markdown = resp_json
            .get("data")
            .and_then(|d| d.get("markdown"))
            .and_then(|m| m.as_str())
            .unwrap_or("");

        if markdown.is_empty() {
            return Ok(ToolResult {
                success: false,
                output: ToolOutput::default(),
                error: Some("Firecrawl returned empty markdown content".into()),
            });
        }

        let output = self.truncate_response(markdown);

        Ok(ToolResult {
            success: true,
            output: output.into(),
            error: None,
        })
    }

    /// Perform the standard HTTP GET fetch and convert to text.
    async fn standard_fetch(&self, client: &reqwest::Client, url: &str) -> ToolResult {
        let response = match client.get(url).send().await {
            Ok(r) => r,
            Err(e) => {
                return ToolResult {
                    success: false,
                    output: ToolOutput::default(),
                    error: Some(format!("HTTP request failed: {e}")),
                };
            }
        };

        let status = response.status();
        if !status.is_success() {
            return ToolResult {
                success: false,
                output: ToolOutput::default(),
                error: Some(format!(
                    "HTTP {} {}",
                    status.as_u16(),
                    status.canonical_reason().unwrap_or("Unknown")
                )),
            };
        }

        // Determine content type for processing strategy
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_lowercase();

        let body_mode = if content_type.contains("text/html") || content_type.is_empty() {
            "html"
        } else if content_type.contains("text/plain")
            || content_type.contains("text/markdown")
            || content_type.contains("application/json")
        {
            "plain"
        } else {
            return ToolResult {
                success: false,
                output: ToolOutput::default(),
                error: Some(format!(
                    "Unsupported content type: {content_type}. \
                     web_fetch supports text/html, text/plain, text/markdown, and application/json."
                )),
            };
        };

        let CappedBody {
            text: body,
            cap_hit,
        } = match self.read_response_text_limited(response).await {
            Ok(t) => t,
            Err(e) => {
                return ToolResult {
                    success: false,
                    output: ToolOutput::default(),
                    error: Some(format!("Failed to read response body: {e}")),
                };
            }
        };

        // Keep the raw HTML alive alongside the converted text so a `<title>`
        // can be lifted from it *only* on the spill path — sub-threshold
        // fetches pay nothing for it.
        let (text, raw_html) = if body_mode == "html" {
            (nanohtml2text::html2text(&body), Some(body))
        } else {
            (body, None)
        };

        // Above the threshold, hand back a file path instead of half a
        // megabyte of text. The stream cap above remains the absolute guard
        // on how much was read; this only changes how it is delivered.
        if text.len() > SPILL_THRESHOLD_BYTES {
            let title = raw_html.as_deref().and_then(extract_html_title);
            if let Some(message) = self
                .spill_to_workspace(
                    url,
                    &text,
                    spill_extension(&content_type, body_mode),
                    title.as_deref(),
                    cap_hit,
                )
                .await
            {
                return ToolResult {
                    success: true,
                    output: message.into(),
                    error: None,
                };
            }
            // No usable workspace, or the write failed: fall through to the
            // pre-existing inline truncation rather than losing the response.
        }

        let mut output = self.truncate_response(&text);
        if cap_hit && !output.ends_with(TRUNCATION_MARKER) {
            output.push_str(TRUNCATION_MARKER);
        }

        ToolResult {
            success: true,
            output: output.into(),
            error: None,
        }
    }
}

#[async_trait]
impl Tool for WebFetchTool {
    fn name(&self) -> &str {
        "web_fetch"
    }

    fn description(&self) -> &str {
        "Fetch a web page and return its content as clean plain text. \
         HTML pages are automatically converted to readable text. \
         JSON and plain text responses are returned as-is. \
         Only GET requests; follows same-host redirects and rejects cross-host redirects. \
         Falls back to Firecrawl for JS-heavy/bot-blocked sites (if enabled). \
         Security: allowlist-only domains, no local/private hosts."
    }

    fn parameters_schema(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "The HTTP or HTTPS URL to fetch"
                }
            },
            "required": ["url"]
        })
    }

    async fn execute(&self, args: serde_json::Value) -> anyhow::Result<ToolResult> {
        let url = args.get("url").and_then(|v| v.as_str()).ok_or_else(|| {
            ::zeroclaw_log::record!(
                WARN,
                ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Reject)
                    .with_outcome(::zeroclaw_log::EventOutcome::Failure)
                    .with_attrs(::serde_json::json!({"param": "url"})),
                "web_fetch: missing url parameter"
            );
            anyhow::Error::msg("Missing 'url' parameter")
        })?;

        if !self.security.can_act() {
            return Ok(ToolResult {
                success: false,
                output: ToolOutput::default(),
                error: Some("Action blocked: autonomy is read-only".into()),
            });
        }

        // Rate limiting is applied by the RateLimitedTool wrapper at
        // registration time (see zeroclaw-runtime::tools::mod).

        let proxy_config = zeroclaw_config::schema::runtime_proxy_config();
        if proxy_conflicts_with_dns_pinning(&proxy_config) {
            ::zeroclaw_log::record!(
                WARN,
                ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Reject)
                    .with_outcome(::zeroclaw_log::EventOutcome::Failure)
                    .with_attrs(::serde_json::json!({"service": "tool.web_fetch"})),
                "web_fetch: configured runtime proxy rejected to preserve validated DNS pin"
            );
            return Ok(ToolResult {
                success: false,
                output: ToolOutput::default(),
                error: Some(WEB_FETCH_PROXY_PINNING_ERROR.into()),
            });
        }

        let ignored_environment_proxy = zeroclaw_config::schema::environment_proxy_for_url(url);
        if let Some(variable) = ignored_environment_proxy {
            ::zeroclaw_log::record!(
                WARN,
                ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Note)
                    .with_outcome(::zeroclaw_log::EventOutcome::Unknown)
                    .with_attrs(::serde_json::json!({"proxy_variable": variable})),
                "web_fetch: standard fetch ignores environment proxy to preserve validated DNS pin"
            );
        }

        let target = match self.resolve_target(url).await {
            Ok(v) => v,
            Err(e) => {
                return Ok(ToolResult {
                    success: false,
                    output: ToolOutput::default(),
                    error: Some(e.to_string()),
                });
            }
        };
        let url = target.url.clone();

        // Build client: follow redirects, set timeout, set User-Agent
        let timeout_secs = if self.timeout_secs == 0 {
            ::zeroclaw_log::record!(
                WARN,
                ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Note)
                    .with_outcome(::zeroclaw_log::EventOutcome::Unknown),
                "web_fetch: timeout_secs is 0, using safe default of 30s"
            );
            30
        } else {
            self.timeout_secs
        };

        let RedirectGuardedClient {
            client,
            redirect_policy_rejected,
        } = match self.build_redirect_guarded_client(&target, timeout_secs) {
            Ok(c) => c,
            Err(e) => {
                return Ok(ToolResult {
                    success: false,
                    output: ToolOutput::default(),
                    error: Some(format!("Failed to build HTTP client: {e}")),
                });
            }
        };

        let mut standard_result = self.standard_fetch(&client, &url).await;
        if let Some(variable) = ignored_environment_proxy
            && !standard_result.success
        {
            let note =
                format!("{variable} was intentionally ignored by the DNS-pinned standard fetch");
            standard_result.error = Some(match standard_result.error.take() {
                Some(error) => format!("{error}; {note}"),
                None => note,
            });
        }

        // If standard fetch succeeded well enough, return it directly.
        // Otherwise, try Firecrawl fallback if enabled.
        if self.should_fallback_to_firecrawl(
            &standard_result,
            redirect_policy_rejected.load(Ordering::Relaxed),
        ) {
            ::zeroclaw_log::record!(
                INFO,
                ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Note)
                    .with_attrs(::serde_json::json!({"url": url})),
                "web_fetch: standard fetch insufficient for , attempting Firecrawl fallback"
            );
            match Box::pin(self.fetch_via_firecrawl(&url)).await {
                Ok(firecrawl_result) if firecrawl_result.success => {
                    return Ok(firecrawl_result);
                }
                Ok(firecrawl_result) => {
                    ::zeroclaw_log::record!(
                        WARN,
                        ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Note)
                            .with_outcome(::zeroclaw_log::EventOutcome::Unknown),
                        &format!(
                            "web_fetch: Firecrawl fallback also failed: {:?}",
                            firecrawl_result.error
                        )
                    );
                    // Return original standard result if Firecrawl also failed
                }
                Err(e) => {
                    ::zeroclaw_log::record!(
                        WARN,
                        ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Note)
                            .with_outcome(::zeroclaw_log::EventOutcome::Unknown)
                            .with_attrs(::serde_json::json!({"error": format!("{}", e)})),
                        "web_fetch: Firecrawl fallback error"
                    );
                }
            }
        }

        Ok(standard_result)
    }
}

// ── Helper functions (independent from http_request.rs per DRY rule-of-three) ──

/// Result of the size-capped streamed body read.
///
/// Per-call value, not stored state: `cap_hit` is knowable only here, at the
/// moment the read stops, and nothing else in the codebase records it.
struct CappedBody {
    /// The bytes that were read, lossily decoded as UTF-8.
    text: String,
    /// True when the read stopped because `max_response_size` was reached,
    /// i.e. the source body was larger than the cap and its tail was dropped.
    cap_hit: bool,
}

/// File extension for a spilled body.
///
/// Derived from the content type the caller already classified — this is a
/// pure mapping for naming only and does not affect which content types
/// `web_fetch` accepts or how their bodies are processed.
fn spill_extension(content_type: &str, body_mode: &str) -> &'static str {
    if body_mode == "html" {
        // HTML arrives converted to readable text, which reads as markdown.
        return "md";
    }
    if content_type.contains("application/json") {
        return "json";
    }
    if content_type.contains("text/markdown") {
        return "md";
    }
    "txt"
}

/// Filename for a spilled response: sanitized URL host + a short hash of the
/// converted text.
///
/// Deterministic — refetching a page whose content has not changed overwrites
/// the same file rather than accumulating copies — and content-addressed, so
/// a stale path can never serve content the model did not fetch.
fn spill_file_name(url: &str, text: &str, extension: &str) -> String {
    let host = extract_host(url)
        .map(|h| sanitize_path_component(&h))
        .unwrap_or_else(|_| "unknown-host".to_string());
    let digest = Sha256::digest(text.as_bytes());
    let short_hash = hex::encode(&digest[..4]);
    format!("{host}-{short_hash}.{extension}")
}

/// Reduce a host to a single safe filename component.
///
/// ASCII alphanumerics, `-` and `.` survive; everything else (including any
/// path separator) becomes `-`. Leading and trailing dots are stripped so the
/// result can never be `.`, `..`, or a hidden file, and the length is capped
/// so host + hash + extension stays well inside filesystem name limits.
fn sanitize_path_component(host: &str) -> String {
    let mut sanitized: String = host
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '.' {
                c
            } else {
                '-'
            }
        })
        .collect();
    // Every char above is ASCII, so this byte index is always a char boundary.
    sanitized.truncate(60);
    let trimmed = sanitized.trim_matches('.');
    if trimmed.is_empty() {
        "unknown-host".to_string()
    } else {
        trimmed.to_string()
    }
}

/// Cheap `<title>` extraction from raw HTML — a bounded substring scan, no
/// regex compile and no parse. Only used on the spill path.
fn extract_html_title(html: &str) -> Option<String> {
    /// A page whose `<title>` is not in the first 64 KiB does not have one
    /// worth paying for.
    const SCAN_LIMIT: usize = 64 * 1024;

    let mut end = html.len().min(SCAN_LIMIT);
    while end > 0 && !html.is_char_boundary(end) {
        end -= 1;
    }
    let head = &html[..end];

    // `to_ascii_lowercase` only maps A-Z, so it preserves byte length and
    // byte indices line up with `head` exactly.
    let lower = head.to_ascii_lowercase();
    let open = lower.find("<title")?;
    let tag_end = open + lower[open..].find('>')?;
    let close = tag_end + lower[tag_end..].find("</title>")?;
    if close < tag_end + 1 {
        return None;
    }

    let title = head[tag_end + 1..close]
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    if title.is_empty() {
        return None;
    }
    Some(title.chars().take(120).collect())
}

/// The short message that replaces an oversized body in the tool result.
///
/// Names the source, the size, and the saved path, and points at the tools
/// that can actually consume it (`file_read` for paging, `content_search` for
/// searching), whose paths resolve relative to the workspace root.
fn spill_message(
    url: &str,
    title: Option<&str>,
    byte_count: usize,
    relative_path: &Path,
    cap_hit: bool,
) -> String {
    let path = relative_path.display();
    let mut message = format!("Fetched {url}\n");
    if let Some(title) = title {
        message.push_str(&format!("Title: {title}\n"));
    }
    message.push_str(&format!(
        "Size: {byte_count} bytes of converted text — too large to return inline, so the \
         full text was written to a file in the agent workspace.\n\n\
         Saved to: {path}\n\n\
         Read it with the file_read tool (path=\"{path}\", using its offset and limit \
         parameters to page through), or search it with the content_search tool \
         (path=\"{path}\" plus a pattern). That path is relative to the workspace root.\n"
    ));
    if cap_hit {
        message.push_str(
            "\nNote: the response hit web_fetch's max_response_size stream cap, so the saved \
             content is the truncated head of the page, not the whole page.\n",
        );
    }
    message
}

#[cfg(test)]
fn validate_target_url(
    raw_url: &str,
    allowed_domains: &[String],
    blocked_domains: &[String],
    allowed_private_hosts: &[String],
    tool_name: &str,
) -> anyhow::Result<String> {
    validate_target_url_with_dns_check(
        raw_url,
        allowed_domains,
        blocked_domains,
        allowed_private_hosts,
        tool_name,
        validate_resolved_host,
    )
}

#[derive(Debug, Clone)]
struct ResolvedWebFetchTarget {
    url: String,
    host: String,
    resolved_addrs: Vec<std::net::SocketAddr>,
}

/// A standard-fetch client together with the flag its redirect policy sets
/// when it denies a hop. The two are returned as a pair because reading the
/// flag only means anything for the client that owns it.
struct RedirectGuardedClient {
    client: reqwest::Client,
    redirect_policy_rejected: Arc<AtomicBool>,
}

fn pin_resolved_host(
    builder: reqwest::ClientBuilder,
    target: &ResolvedWebFetchTarget,
) -> reqwest::ClientBuilder {
    if target.host.parse::<std::net::IpAddr>().is_ok() {
        builder
    } else {
        builder.resolve_to_addrs(&target.host, &target.resolved_addrs)
    }
}

fn proxy_conflicts_with_dns_pinning(config: &ProxyConfig) -> bool {
    (config.enabled && config.scope == ProxyScope::Environment)
        || (config.has_any_proxy_url() && config.should_apply_to_service("tool.web_fetch"))
}

fn validate_redirect_target(
    raw_url: &str,
    pinned_host: &str,
    allowed_domains: &[String],
    blocked_domains: &[String],
    allowed_private_hosts: &[String],
) -> anyhow::Result<()> {
    let redirect_url = reqwest::Url::parse(raw_url)
        .map_err(|e| anyhow::Error::msg(format!("Invalid URL format: {e}")))?;
    if redirect_url.host_str() != Some(pinned_host) {
        anyhow::bail!("Cross-host redirects are blocked so DNS validation remains pinned");
    }

    validate_target_url_with_dns_check(
        raw_url,
        allowed_domains,
        blocked_domains,
        allowed_private_hosts,
        "web_fetch",
        |_, _| Ok(()),
    )?;
    Ok(())
}

fn resolve_target_url(
    raw_url: &str,
    allowed_domains: &[String],
    blocked_domains: &[String],
    allowed_private_hosts: &[String],
    nat64_prefixes: &[domain_guard::Nat64Prefix],
    tool_name: &str,
) -> anyhow::Result<ResolvedWebFetchTarget> {
    let mut resolved_host = None;
    let mut resolved_addrs = None;
    let url = validate_target_url_with_dns_check(
        raw_url,
        allowed_domains,
        blocked_domains,
        allowed_private_hosts,
        tool_name,
        |host, allow_private| {
            resolved_host = Some(host.to_string());
            resolved_addrs = Some(resolve_validated_host(host, allow_private, nat64_prefixes)?);
            Ok(())
        },
    )?;
    let host = resolved_host.ok_or_else(|| anyhow::Error::msg("URL must include a valid host"))?;
    let mut canonical_url = reqwest::Url::parse(&url)
        .map_err(|e| anyhow::Error::msg(format!("Invalid URL format: {e}")))?;
    canonical_url
        .set_host(Some(&host))
        .map_err(|_| anyhow::Error::msg("URL must include a valid host"))?;

    Ok(ResolvedWebFetchTarget {
        url: canonical_url.to_string(),
        host,
        resolved_addrs: resolved_addrs.unwrap_or_default(),
    })
}

fn validate_target_url_with_dns_check(
    raw_url: &str,
    allowed_domains: &[String],
    blocked_domains: &[String],
    allowed_private_hosts: &[String],
    tool_name: &str,
    validate_dns: impl FnOnce(&str, bool) -> anyhow::Result<()>,
) -> anyhow::Result<String> {
    let url = raw_url.trim();

    if url.is_empty() {
        anyhow::bail!("URL cannot be empty");
    }

    if url.chars().any(char::is_whitespace) {
        anyhow::bail!("URL cannot contain whitespace");
    }

    if !url.starts_with("http://") && !url.starts_with("https://") {
        anyhow::bail!("Only http:// and https:// URLs are allowed");
    }

    if allowed_domains.is_empty() {
        anyhow::bail!(
            "{tool_name} tool is enabled but no allowed_domains are configured. \
             Add [{tool_name}].allowed_domains in config.toml"
        );
    }

    let host = extract_host(url)?;

    // blocked_domains always takes precedence
    if domain_guard::host_matches_allowlist(&host, blocked_domains) {
        anyhow::bail!("Host '{host}' is in {tool_name}.blocked_domains");
    }

    let host_is_private_or_local = domain_guard::is_private_or_local_host(&host);
    let private_match = private_allowlist_match(&host, allowed_private_hosts);
    // An explicit entry (a specific host/IP or suffix) is a deliberate per-host
    // carve-out; the "*" wildcard blanket-tolerates a private/internal
    // resolution for any host. The distinction only affects the WARN below.
    let private_explicit = matches!(private_match, PrivateAllow::Explicit);
    // Either an explicit entry or "*" tolerates a private/internal host: it lifts
    // the literal private-host block and skips the resolved-IP public check.
    let private_tolerated = !matches!(private_match, PrivateAllow::None);

    if host_is_private_or_local && !private_tolerated {
        anyhow::bail!(
            "Blocked local/private host: {host}. \
             To allow this host, add it (or \"*\") to \
             {tool_name}.allowed_private_hosts in config.toml"
        );
    }

    if private_explicit || (private_tolerated && host_is_private_or_local) {
        ::zeroclaw_log::record!(
            WARN,
            ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Note)
                .with_outcome(::zeroclaw_log::EventOutcome::Unknown)
                .with_attrs(::serde_json::json!({"tool_name": tool_name, "host": host})),
            "web_fetch: allowing host via allowed_private_hosts"
        );
    }

    let skip_allowed_domains = host_is_private_or_local && private_tolerated;

    if !skip_allowed_domains && !domain_guard::host_matches_allowlist(&host, allowed_domains) {
        anyhow::bail!("Host '{host}' is not in {tool_name}.allowed_domains");
    }

    // Private opt-in relaxes only the public-address requirement. DNS still
    // resolves and the metadata exclusion remains unconditional.
    validate_dns(&host, private_tolerated)?;

    Ok(url.to_string())
}

fn extract_host(url: &str) -> anyhow::Result<String> {
    let parsed = reqwest::Url::parse(url).map_err(|e| {
        ::zeroclaw_log::record!(
            WARN,
            ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Reject)
                .with_outcome(::zeroclaw_log::EventOutcome::Failure)
                .with_attrs(::serde_json::json!({"url": url, "error": format!("{e}")})),
            "web_fetch: invalid URL"
        );
        anyhow::Error::msg(format!("Invalid URL format: {e}"))
    })?;

    if !matches!(parsed.scheme(), "http" | "https") {
        ::zeroclaw_log::record!(
            WARN,
            ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Reject)
                .with_outcome(::zeroclaw_log::EventOutcome::Failure)
                .with_attrs(::serde_json::json!({"url": url})),
            "web_fetch: non-http(s) URL rejected"
        );
        anyhow::bail!("Only http:// and https:// URLs are allowed");
    }

    if !parsed.username().is_empty() || parsed.password().is_some() {
        anyhow::bail!("URL userinfo is not allowed");
    }

    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow::Error::msg("URL must include a host"))?;
    // `Url::host_str()` serializes IPv6 literals with brackets, so parsing the
    // returned string directly would never recognize them.
    if host.starts_with('[') {
        anyhow::bail!("IPv6 hosts are not supported in web_fetch");
    }

    let host = host.trim_end_matches('.').to_ascii_lowercase();

    if host.is_empty() {
        anyhow::bail!("URL must include a valid host");
    }

    Ok(host)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PrivateAllow {
    /// Not covered by the private allowlist.
    None,
    /// Covered only by a `*` wildcard entry.
    Wildcard,
    /// Covered by a specific host/IP or suffix entry.
    Explicit,
}

fn private_allowlist_match(host: &str, allowed_private_hosts: &[String]) -> PrivateAllow {
    let mut wildcard = false;
    for entry in allowed_private_hosts {
        if entry == "*" {
            // Record the wildcard but keep scanning: a later explicit entry
            // should still win, since it is a deliberate per-host carve-out.
            wildcard = true;
        } else if domain_guard::host_matches_allowlist(host, std::slice::from_ref(entry)) {
            return PrivateAllow::Explicit;
        }
    }
    if wildcard {
        PrivateAllow::Wildcard
    } else {
        PrivateAllow::None
    }
}

#[cfg(not(test))]
fn resolve_validated_host(
    host: &str,
    allow_private: bool,
    nat64_prefixes: &[domain_guard::Nat64Prefix],
) -> anyhow::Result<Vec<std::net::SocketAddr>> {
    use std::net::ToSocketAddrs;

    let addrs = (host, 0)
        .to_socket_addrs()
        .map_err(|e| {
            ::zeroclaw_log::record!(
                ERROR,
                ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Fail)
                    .with_outcome(::zeroclaw_log::EventOutcome::Failure)
                    .with_attrs(::serde_json::json!({
                        "host": host,
                        "error": format!("{}", e),
                    })),
                "web_fetch: failed to resolve host"
            );
            anyhow::Error::msg(format!("Failed to resolve host '{host}': {e}"))
        })?
        .collect::<Vec<_>>();
    let ips = addrs
        .iter()
        .map(std::net::SocketAddr::ip)
        .collect::<Vec<_>>();

    validate_resolved_ips_for_ssrf(host, allow_private, &ips, nat64_prefixes)?;
    Ok(addrs)
}

#[cfg(test)]
fn resolve_validated_host(
    _host: &str,
    _allow_private: bool,
    _nat64_prefixes: &[domain_guard::Nat64Prefix],
) -> anyhow::Result<Vec<std::net::SocketAddr>> {
    // Resolver behavior is injected by unit tests that exercise the policy.
    Ok(Vec::new())
}

#[cfg(test)]
fn validate_resolved_host(host: &str, allow_private: bool) -> anyhow::Result<()> {
    resolve_validated_host(host, allow_private, &[]).map(|_| ())
}

fn validate_resolved_ips_for_ssrf(
    host: &str,
    allow_private: bool,
    ips: &[std::net::IpAddr],
    nat64_prefixes: &[domain_guard::Nat64Prefix],
) -> anyhow::Result<()> {
    if allow_private {
        domain_guard::validate_resolved_ips_exclude_metadata(host, ips, nat64_prefixes)
    } else {
        domain_guard::validate_resolved_ips_are_public(host, ips, nat64_prefixes).map_err(|err| {
            if ips.is_empty() || ips.iter().any(|ip| domain_guard::is_cloud_metadata_ip(*ip)) {
                err
            } else {
                anyhow::Error::msg(format!(
                    "{err}. To allow hosts that resolve to private/internal IPs, add '{host}' \
                     (or \"*\") to web_fetch.allowed_private_hosts in config.toml"
                ))
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroclaw_config::autonomy::AutonomyLevel;
    use zeroclaw_config::policy::SecurityPolicy;
    use zeroclaw_config::schema::FirecrawlConfig;

    fn test_tool(allowed_domains: Vec<&str>) -> WebFetchTool {
        test_tool_with_blocklist(allowed_domains, vec![])
    }

    fn test_tool_with_blocklist(
        allowed_domains: Vec<&str>,
        blocked_domains: Vec<&str>,
    ) -> WebFetchTool {
        let security = Arc::new(SecurityPolicy {
            autonomy: AutonomyLevel::Supervised,
            ..SecurityPolicy::default()
        });
        WebFetchTool::new(
            security,
            allowed_domains.into_iter().map(String::from).collect(),
            blocked_domains.into_iter().map(String::from).collect(),
            500_000,
            30,
            FirecrawlConfig::default(),
            vec![],
            vec![],
        )
        .unwrap()
    }

    fn test_tool_with_private_hosts(
        allowed_domains: Vec<&str>,
        blocked_domains: Vec<&str>,
        allowed_private_hosts: Vec<&str>,
    ) -> WebFetchTool {
        let security = Arc::new(SecurityPolicy {
            autonomy: AutonomyLevel::Supervised,
            ..SecurityPolicy::default()
        });
        WebFetchTool::new(
            security,
            allowed_domains.into_iter().map(String::from).collect(),
            blocked_domains.into_iter().map(String::from).collect(),
            500_000,
            30,
            FirecrawlConfig::default(),
            allowed_private_hosts
                .into_iter()
                .map(String::from)
                .collect(),
            vec![],
        )
        .unwrap()
    }

    fn test_tool_with_firecrawl(firecrawl: FirecrawlConfig) -> WebFetchTool {
        let security = Arc::new(SecurityPolicy {
            autonomy: AutonomyLevel::Supervised,
            ..SecurityPolicy::default()
        });
        WebFetchTool::new(
            security,
            vec!["*".into()],
            vec![],
            500_000,
            30,
            firecrawl,
            vec![],
            vec![],
        )
        .unwrap()
    }

    // ── Name and schema ──────────────────────────────────────────

    #[test]
    fn name_is_web_fetch() {
        let tool = test_tool(vec!["example.com"]);
        assert_eq!(tool.name(), "web_fetch");
    }

    #[test]
    fn parameters_schema_requires_url() {
        let tool = test_tool(vec!["example.com"]);
        let schema = tool.parameters_schema();
        assert!(schema["properties"]["url"].is_object());
        let required = schema["required"].as_array().unwrap();
        assert!(required.iter().any(|v| v.as_str() == Some("url")));
    }

    // ── HTML to text conversion ──────────────────────────────────

    #[test]
    fn html_to_text_conversion() {
        let html = "<html><body><h1>Title</h1><p>Hello <b>world</b></p></body></html>";
        let text = nanohtml2text::html2text(html);
        assert!(text.contains("Title"));
        assert!(text.contains("Hello"));
        assert!(text.contains("world"));
        assert!(!text.contains("<h1>"));
        assert!(!text.contains("<p>"));
    }

    // ── URL validation ───────────────────────────────────────────

    #[test]
    fn validate_accepts_exact_domain() {
        let tool = test_tool(vec!["example.com"]);
        let got = tool.validate_url("https://example.com/page").unwrap();
        assert_eq!(got, "https://example.com/page");
    }

    #[test]
    fn validate_accepts_subdomain() {
        let tool = test_tool(vec!["example.com"]);
        assert!(tool.validate_url("https://docs.example.com/guide").is_ok());
    }

    #[test]
    fn validate_accepts_wildcard() {
        let tool = test_tool(vec!["*"]);
        assert!(tool.validate_url("https://news.ycombinator.com").is_ok());
    }

    #[test]
    fn validate_rejects_empty_url() {
        let tool = test_tool(vec!["example.com"]);
        let err = tool.validate_url("").unwrap_err().to_string();
        assert!(err.contains("empty"));
    }

    #[test]
    fn validate_rejects_missing_url() {
        let tool = test_tool(vec!["example.com"]);
        let err = tool.validate_url("  ").unwrap_err().to_string();
        assert!(err.contains("empty"));
    }

    #[test]
    fn validate_rejects_ftp_scheme() {
        let tool = test_tool(vec!["example.com"]);
        let err = tool
            .validate_url("ftp://example.com")
            .unwrap_err()
            .to_string();
        assert!(err.contains("http://") || err.contains("https://"));
    }

    #[test]
    fn validate_rejects_allowlist_miss() {
        let tool = test_tool(vec!["example.com"]);
        let err = tool
            .validate_url("https://google.com")
            .unwrap_err()
            .to_string();
        assert!(err.contains("allowed_domains"));
    }

    #[test]
    fn validate_requires_allowlist() {
        let security = Arc::new(SecurityPolicy::default());
        let tool = WebFetchTool::new(
            security,
            vec![],
            vec![],
            500_000,
            30,
            FirecrawlConfig::default(),
            vec![],
            vec![],
        )
        .unwrap();
        let err = tool
            .validate_url("https://example.com")
            .unwrap_err()
            .to_string();
        assert!(err.contains("allowed_domains"));
    }

    // ── SSRF protection ──────────────────────────────────────────

    #[test]
    fn ssrf_blocks_localhost() {
        let tool = test_tool(vec!["localhost"]);
        let err = tool
            .validate_url("https://localhost:8080")
            .unwrap_err()
            .to_string();
        assert!(err.contains("local/private"));
    }

    #[test]
    fn ssrf_blocks_private_ipv4() {
        let tool = test_tool(vec!["192.168.1.5"]);
        let err = tool
            .validate_url("https://192.168.1.5")
            .unwrap_err()
            .to_string();
        assert!(err.contains("local/private"));
    }

    #[test]
    fn ssrf_wildcard_still_blocks_private() {
        let tool = test_tool(vec!["*"]);
        let err = tool
            .validate_url("https://localhost:8080")
            .unwrap_err()
            .to_string();
        assert!(err.contains("local/private"));
    }

    #[test]
    fn redirect_target_validation_allows_permitted_host() {
        let allowed = vec!["example.com".to_string()];
        let blocked = vec![];
        assert!(
            validate_target_url(
                "https://docs.example.com/page",
                &allowed,
                &blocked,
                &[],
                "web_fetch"
            )
            .is_ok()
        );
    }

    #[test]
    fn redirect_target_validation_blocks_private_host() {
        let allowed = vec!["example.com".to_string()];
        let blocked = vec![];
        let err = validate_target_url(
            "https://127.0.0.1/admin",
            &allowed,
            &blocked,
            &[],
            "web_fetch",
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("local/private"));
    }

    #[test]
    fn redirect_target_validation_blocks_blocklisted_host() {
        let allowed = vec!["*".to_string()];
        let blocked = vec!["evil.com".to_string()];
        let err = validate_target_url(
            "https://evil.com/phish",
            &allowed,
            &blocked,
            &[],
            "web_fetch",
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("blocked_domains"));
    }

    #[test]
    fn redirect_target_cannot_escape_the_pinned_host() {
        let allowed = vec!["*".to_string()];
        let err = validate_redirect_target(
            "https://other.example/page",
            "initial.example",
            &allowed,
            &[],
            &[],
        )
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("Cross-host redirects"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn redirect_target_rejects_trailing_dot_variant_of_pinned_host() {
        let allowed = vec!["*".to_string()];
        let err = validate_redirect_target(
            "https://initial.example./page",
            "initial.example",
            &allowed,
            &[],
            &[],
        )
        .unwrap_err()
        .to_string();

        assert!(
            err.contains("Cross-host redirects"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn resolved_target_canonicalizes_trailing_dot_before_dns_pinning() {
        let target = resolve_target_url(
            "http://dns-rebinding.invalid.:8080/path?x=1",
            &["*".to_string()],
            &[],
            &[],
            &[],
            "web_fetch",
        )
        .unwrap();
        let parsed = reqwest::Url::parse(&target.url).unwrap();

        assert_eq!(target.host, "dns-rebinding.invalid");
        assert_eq!(parsed.host_str(), Some(target.host.as_str()));
        assert_eq!(parsed.port(), Some(8080));
        assert_eq!(parsed.path(), "/path");
        assert_eq!(parsed.query(), Some("x=1"));
    }

    #[test]
    fn resolved_target_uses_canonical_idn_host_for_validation_and_pinning() {
        let target = resolve_target_url(
            "https://exämple.com/path",
            &["*".to_string()],
            &[],
            &[],
            &[],
            "web_fetch",
        )
        .unwrap();
        let parsed = reqwest::Url::parse(&target.url).unwrap();

        assert_eq!(target.host, "xn--exmple-cua.com");
        assert_eq!(parsed.host_str(), Some(target.host.as_str()));
    }

    #[test]
    fn extract_host_rejects_bracketed_ipv6_with_policy_error() {
        let err = extract_host("http://[::1]/").unwrap_err().to_string();
        assert_eq!(err, "IPv6 hosts are not supported in web_fetch");
    }

    #[test]
    fn runtime_proxy_conflicts_with_dns_pinning_only_when_it_applies() {
        let global_proxy = ProxyConfig {
            enabled: true,
            http_proxy: Some("http://proxy.example:8080".into()),
            scope: zeroclaw_config::schema::ProxyScope::Zeroclaw,
            ..ProxyConfig::default()
        };
        assert!(proxy_conflicts_with_dns_pinning(&global_proxy));
        assert!(WEB_FETCH_PROXY_PINNING_ERROR.contains("proxy.scope = \"services\""));
        assert!(WEB_FETCH_PROXY_PINNING_ERROR.contains("omit tool.*"));

        let environment_proxy = ProxyConfig {
            enabled: true,
            http_proxy: Some("http://proxy.example:8080".into()),
            scope: zeroclaw_config::schema::ProxyScope::Environment,
            ..ProxyConfig::default()
        };
        assert!(proxy_conflicts_with_dns_pinning(&environment_proxy));
        assert!(WEB_FETCH_PROXY_PINNING_ERROR.contains("environment"));

        let other_service_proxy = ProxyConfig {
            enabled: true,
            http_proxy: Some("http://proxy.example:8080".into()),
            scope: zeroclaw_config::schema::ProxyScope::Services,
            services: vec!["provider.openai".into()],
            ..ProxyConfig::default()
        };
        assert!(!proxy_conflicts_with_dns_pinning(&other_service_proxy));
        assert!(!proxy_conflicts_with_dns_pinning(&ProxyConfig::default()));
    }

    // ── Security policy ──────────────────────────────────────────

    #[tokio::test]
    async fn blocks_readonly_mode() {
        let security = Arc::new(SecurityPolicy {
            autonomy: AutonomyLevel::ReadOnly,
            ..SecurityPolicy::default()
        });
        let tool = WebFetchTool::new(
            security,
            vec!["example.com".into()],
            vec![],
            500_000,
            30,
            FirecrawlConfig::default(),
            vec![],
            vec![],
        )
        .unwrap();
        let result = tool
            .execute(json!({"url": "https://example.com"}))
            .await
            .unwrap();
        assert!(!result.success);
        assert!(result.error.unwrap().contains("read-only"));
    }

    // ── Response truncation ──────────────────────────────────────

    #[test]
    fn truncate_within_limit() {
        let tool = test_tool(vec!["example.com"]);
        let text = "hello world";
        assert_eq!(tool.truncate_response(text), "hello world");
    }

    #[test]
    fn truncate_response_zero_means_unlimited() {
        // max_response_size == 0 must be treated as unlimited — no truncation
        // marker, full text returned regardless of length.
        let tool = WebFetchTool::new(
            Arc::new(SecurityPolicy::default()),
            vec!["example.com".into()],
            vec![],
            0, // unlimited
            30,
            FirecrawlConfig::default(),
            vec![],
            vec![],
        )
        .unwrap();
        let long_text = "x".repeat(10_000);
        let result = tool.truncate_response(&long_text);
        assert_eq!(result.len(), 10_000, "zero limit must not truncate");
        assert!(
            !result.contains("[Response truncated"),
            "must not append truncation marker"
        );
    }

    #[tokio::test]
    async fn standard_fetch_with_zero_limit_returns_full_body_and_skips_firecrawl_fallback() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let addr = server.address();

        // Body must exceed FIRECRAWL_MIN_BODY_LEN (100 bytes) so any
        // truncation to <100 bytes would (incorrectly) trigger fallback.
        let body = "a".repeat(500);
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string(body.clone()))
            .mount(&server)
            .await;

        let tool = WebFetchTool::new(
            Arc::new(SecurityPolicy {
                autonomy: AutonomyLevel::Supervised,
                ..SecurityPolicy::default()
            }),
            vec!["*".into()],
            vec![],
            0, // max_response_size = unlimited
            30,
            FirecrawlConfig {
                enabled: true,
                ..FirecrawlConfig::default()
            },
            vec![],
            vec![],
        )
        .unwrap();

        // Bypass SSRF-guarded execute() — call standard_fetch directly so
        // wiremock on 127.0.0.1 is reachable.
        let url = format!("http://{}:{}/", addr.ip(), addr.port());
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .expect("reqwest client");
        let standard_result = tool.standard_fetch(&client, &url).await;

        // (a) standard result IS the full body — proves streamed read did
        // not stop after 1 byte under the zero-limit path.
        assert!(
            standard_result.success,
            "standard_fetch must succeed, got error={:?}",
            standard_result.error
        );
        assert_eq!(
            standard_result.output.len(),
            body.len(),
            "streamed body length under zero-limit must equal full body"
        );
        assert_eq!(
            standard_result.output, body,
            "streamed body content must equal full body"
        );
        assert!(
            !standard_result.output.contains("[Response truncated"),
            "must not append truncation marker under zero limit"
        );

        // (b) result does NOT trip should_fallback_to_firecrawl — proves
        // the regression (1-byte short body) is locked out.
        assert!(
            !tool.should_fallback_to_firecrawl(&standard_result, false),
            "500-byte body under zero limit must not trigger Firecrawl fallback"
        );
    }

    // ── Transparent decompression regression matrix ─────────────
    //
    // Covers the three advertised Content-Encodings, the decoded-size cap, and
    // malformed input. Fixtures are compressed at test time so the assertions
    // read as round-trips rather than opaque byte blobs.

    fn gzip_bytes(payload: &[u8]) -> Vec<u8> {
        use flate2::{Compression, write::GzEncoder};
        use std::io::Write;
        let mut enc = GzEncoder::new(Vec::new(), Compression::default());
        enc.write_all(payload).unwrap();
        enc.finish().unwrap()
    }

    fn deflate_bytes(payload: &[u8]) -> Vec<u8> {
        // HTTP `deflate` is zlib-wrapped per RFC 7230; reqwest decodes zlib.
        use flate2::{Compression, write::ZlibEncoder};
        use std::io::Write;
        let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
        enc.write_all(payload).unwrap();
        enc.finish().unwrap()
    }

    fn brotli_bytes(payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut r = payload;
        brotli::BrotliCompress(&mut r, &mut out, &Default::default()).unwrap();
        out
    }

    fn test_tool_with_limit(max_response_size: usize) -> WebFetchTool {
        WebFetchTool::new(
            Arc::new(SecurityPolicy {
                autonomy: AutonomyLevel::Supervised,
                ..SecurityPolicy::default()
            }),
            vec!["*".into()],
            vec![],
            max_response_size,
            30,
            FirecrawlConfig::default(),
            vec![],
            vec![],
        )
        .unwrap()
    }

    async fn fetch_encoded(encoding: &str, body: Vec<u8>, max_response_size: usize) -> ToolResult {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let addr = server.address();
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-encoding", encoding)
                    // text/plain keeps the body verbatim (no html2text pass) so
                    // decoded bytes can be asserted exactly.
                    .insert_header("content-type", "text/plain")
                    .set_body_raw(body, "text/plain"),
            )
            .mount(&server)
            .await;

        let tool = test_tool_with_limit(max_response_size);
        // Call standard_fetch directly so wiremock on 127.0.0.1 is reachable
        // past the SSRF guard. The client does no decoding; `web_fetch` decodes
        // the body in `http_decode` from the Content-Encoding header.
        let url = format!("http://{}:{}/", addr.ip(), addr.port());
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .expect("reqwest client");
        tool.standard_fetch(&client, &url).await
    }

    #[tokio::test]
    async fn standard_fetch_decodes_gzip_brotli_and_deflate() {
        let payload = "ZEROCLAW_DECOMPRESSED_OK ".repeat(8);
        let bytes = payload.as_bytes();
        for (encoding, body) in [
            ("gzip", gzip_bytes(bytes)),
            ("br", brotli_bytes(bytes)),
            ("deflate", deflate_bytes(bytes)),
        ] {
            let result = fetch_encoded(encoding, body, 0).await;
            assert!(
                result.success,
                "{encoding} fetch must succeed, got error={:?}",
                result.error
            );
            assert_eq!(
                result.output, payload,
                "Content-Encoding: {encoding} body must be decompressed"
            );
        }
    }

    #[tokio::test]
    async fn execute_negotiates_and_decodes_through_the_production_client() {
        // `Tool::execute` reads the process-global runtime proxy state, so hold
        // the shared guard against the `proxy_config` writer tests.
        let _proxy_state = crate::test_support::RuntimeProxyStateGuard::acquire().await;
        use wiremock::matchers::{header_exists, method};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        // The rest of the decompression matrix calls `standard_fetch` with a
        // client the test built, so it would stay green if the production
        // client stopped advertising the encodings. This one goes through
        // `Tool::execute`, which builds its client in
        // `build_redirect_guarded_client`: the mock answers only a request that
        // carries the exact Accept-Encoding value, so a decoded body here proves
        // the production wiring end to end.
        let payload = "ZEROCLAW_PRODUCTION_PATH_OK";
        let server = MockServer::start().await;
        let addr = server.address();
        Mock::given(method("GET"))
            .and(header_exists("accept-encoding"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-encoding", "gzip")
                    .insert_header("content-type", "text/plain")
                    .set_body_raw(gzip_bytes(payload.as_bytes()), "text/plain"),
            )
            .mount(&server)
            .await;

        let tool = WebFetchTool::new(
            Arc::new(SecurityPolicy {
                autonomy: AutonomyLevel::Supervised,
                ..SecurityPolicy::default()
            }),
            vec!["*".into()],
            vec![],
            0,
            30,
            FirecrawlConfig::default(),
            vec!["127.0.0.1".into()],
            vec![],
        )
        .unwrap();

        let url = format!("http://{}:{}/", addr.ip(), addr.port());
        let result = tool
            .execute(serde_json::json!({ "url": url }))
            .await
            .expect("execute resolves");

        assert!(result.success, "error={:?}", result.error);

        let seen = server.received_requests().await.unwrap();
        let negotiated: Vec<String> = seen
            .iter()
            .flat_map(|request| request.headers.get_all("accept-encoding"))
            .map(|value| value.to_str().unwrap().to_string())
            .collect();
        assert_eq!(
            negotiated,
            vec!["gzip, deflate, br".to_string()],
            "the production client must advertise exactly the codings http_decode can decode"
        );
        assert!(
            result.output.as_str().contains(payload),
            "the production client must negotiate and decode gzip: {}",
            result.output.as_str()
        );
    }

    #[tokio::test]
    async fn no_content_with_compression_metadata_returns_empty_body() {
        // 204 No Content reaches the reader as a successful response with no
        // body; compression metadata on it describes nothing. The shared
        // status-based bodyless handling must yield an empty body instead of
        // finalizing a decompressor over zero bytes.
        let _proxy_state = crate::test_support::RuntimeProxyStateGuard::acquire().await;
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let addr = server.address();
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(204).insert_header("content-encoding", "gzip"))
            .mount(&server)
            .await;

        let tool = WebFetchTool::new(
            Arc::new(SecurityPolicy {
                autonomy: AutonomyLevel::Supervised,
                ..SecurityPolicy::default()
            }),
            vec!["*".into()],
            vec![],
            0,
            30,
            FirecrawlConfig::default(),
            vec!["127.0.0.1".into()],
            vec![],
        )
        .unwrap();

        let url = format!("http://{}:{}/", addr.ip(), addr.port());
        let result = tool
            .execute(serde_json::json!({ "url": url }))
            .await
            .expect("execute resolves");

        assert!(result.success, "error={:?}", result.error);
        assert!(result.error.is_none());
        assert!(
            result.output.as_str().is_empty(),
            "the body must be empty, got {:?}",
            result.output.as_str()
        );
    }

    #[tokio::test]
    async fn empty_deflate_response_fails_the_body_read() {
        // A GET 200 advertising deflate with zero body bytes has no zlib
        // stream at all; the second affected tool boundary must also report
        // the body-read failure instead of a successful empty response.
        let _proxy_state = crate::test_support::RuntimeProxyStateGuard::acquire().await;
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let addr = server.address();
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).insert_header("content-encoding", "deflate"))
            .mount(&server)
            .await;

        let tool = WebFetchTool::new(
            Arc::new(SecurityPolicy {
                autonomy: AutonomyLevel::Supervised,
                ..SecurityPolicy::default()
            }),
            vec!["*".into()],
            vec![],
            0,
            30,
            FirecrawlConfig::default(),
            vec!["127.0.0.1".into()],
            vec![],
        )
        .unwrap();

        let url = format!("http://{}:{}/", addr.ip(), addr.port());
        let result = tool
            .execute(serde_json::json!({ "url": url }))
            .await
            .expect("execute resolves");

        assert!(
            !result.success,
            "a GET 200 with an empty deflate body must fail: {:?}",
            result.error
        );
        let error = result.error.expect("the body read must report a failure");
        assert!(
            error.contains("Failed to read response body"),
            "got {error:?}"
        );
    }

    #[tokio::test]
    async fn complete_empty_deflate_response_succeeds_with_empty_body() {
        // Positive control through the second boundary: a complete zlib
        // stream encoding zero bytes stays a successful empty fetch.
        let _proxy_state = crate::test_support::RuntimeProxyStateGuard::acquire().await;
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let addr = server.address();
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-encoding", "deflate")
                    .set_body_raw(deflate_bytes(b""), "text/plain"),
            )
            .mount(&server)
            .await;

        let tool = WebFetchTool::new(
            Arc::new(SecurityPolicy {
                autonomy: AutonomyLevel::Supervised,
                ..SecurityPolicy::default()
            }),
            vec!["*".into()],
            vec![],
            0,
            30,
            FirecrawlConfig::default(),
            vec!["127.0.0.1".into()],
            vec![],
        )
        .unwrap();

        let url = format!("http://{}:{}/", addr.ip(), addr.port());
        let result = tool
            .execute(serde_json::json!({ "url": url }))
            .await
            .expect("execute resolves");

        assert!(result.success, "error={:?}", result.error);
        assert!(result.error.is_none());
        assert!(
            result.output.as_str().is_empty(),
            "the body must be empty, got {:?}",
            result.output.as_str()
        );
    }

    #[tokio::test]
    async fn large_complete_deflate_response_decodes_exactly() {
        // The second affected boundary: a valid under-cap deflate body larger
        // than any internal verifier buffer decodes to exactly its content.
        let _proxy_state = crate::test_support::RuntimeProxyStateGuard::acquire().await;
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let payload: String = (0..16_384)
            .map(|i| (b'a' + (i % 26) as u8) as char)
            .collect();
        let server = MockServer::start().await;
        let addr = server.address();
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-encoding", "deflate")
                    .set_body_raw(deflate_bytes(payload.as_bytes()), "text/plain"),
            )
            .mount(&server)
            .await;

        let tool = WebFetchTool::new(
            Arc::new(SecurityPolicy {
                autonomy: AutonomyLevel::Supervised,
                ..SecurityPolicy::default()
            }),
            vec!["*".into()],
            vec![],
            65_536,
            30,
            FirecrawlConfig::default(),
            vec!["127.0.0.1".into()],
            vec![],
        )
        .unwrap();

        let url = format!("http://{}:{}/", addr.ip(), addr.port());
        let result = tool
            .execute(serde_json::json!({ "url": url }))
            .await
            .expect("execute resolves");

        assert!(result.success, "error={:?}", result.error);
        assert!(result.error.is_none());
        assert_eq!(
            result.output.as_str(),
            payload,
            "the body must decode exactly, with no truncation marker"
        );
    }

    #[tokio::test]
    async fn exact_input_allowance_response_is_not_reported_as_truncated() {
        let (body, limit) = crate::http_decode::empty_gzip_members_past_input_slack();
        let result = fetch_encoded("gzip", body, limit).await;

        assert!(result.success, "error={:?}", result.error);
        assert!(result.error.is_none());
        assert!(result.output.as_str().is_empty(), "got {:?}", result.output);
        assert!(
            !result.output.as_str().contains("[Response truncated"),
            "a complete exact-allowance response is not truncated"
        );
    }

    #[tokio::test]
    async fn standard_fetch_decodes_every_gzip_member() {
        // RFC 1952 allows a gzip body to be a series of members. A single-member
        // decoder returns the first one and silently drops the rest, which reads
        // as a complete successful body while it is not.
        let mut body = gzip_bytes(b"first half, ");
        body.extend_from_slice(&gzip_bytes(b"second half"));

        let result = fetch_encoded("gzip", body, 0).await;

        assert!(result.success, "error={:?}", result.error);
        assert_eq!(result.output, "first half, second half");
    }

    #[tokio::test]
    async fn standard_fetch_rejects_repeated_content_encoding_lines() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        // Separate field lines are equivalent to the comma-joined `gzip, br`
        // chain, which this tool refuses rather than half-decoding.
        let server = MockServer::start().await;
        let addr = server.address();
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(200)
                    .append_header("content-encoding", "gzip")
                    .append_header("content-encoding", "br")
                    .insert_header("content-type", "text/plain")
                    .set_body_raw(gzip_bytes(b"payload"), "text/plain"),
            )
            .mount(&server)
            .await;

        let tool = test_tool_with_limit(0);
        let url = format!("http://{}:{}/", addr.ip(), addr.port());
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .expect("reqwest client");
        let result = tool.standard_fetch(&client, &url).await;

        assert!(!result.success, "a coding chain must not be decoded");
        assert!(
            result
                .error
                .as_deref()
                .is_some_and(|e| e.contains("Content-Encoding")),
            "error should name the encoding contract, got {:?}",
            result.error
        );
    }

    #[tokio::test]
    async fn standard_fetch_caps_decoded_expansion() {
        // A tiny gzip body decodes to 10 KiB; the read must stop at the cap so a
        // compressed response cannot expand without bound in memory.
        let payload = "a".repeat(10_000);
        let body = gzip_bytes(payload.as_bytes());
        assert!(body.len() < 200, "compressed fixture should be small");

        let result = fetch_encoded("gzip", body, 128).await;
        assert!(result.success, "capped fetch still succeeds");
        assert!(
            result.output.starts_with(&"a".repeat(128)),
            "decoded prefix must be preserved up to the cap"
        );
        assert!(
            result.output.contains("[Response truncated"),
            "over-cap decoded body must be marked truncated"
        );
        // 128 chars + the truncation marker, nowhere near the 10 KiB decoded size.
        assert!(
            result.output.len() < 256,
            "output must stay bounded to the cap, got {} bytes",
            result.output.len()
        );
    }

    #[tokio::test]
    async fn standard_fetch_reports_malformed_compressed_body() {
        // Advertise gzip but send bytes that are not a valid gzip stream; the
        // decoder error must surface as a clean failure, not a panic.
        let result = fetch_encoded("gzip", b"not a valid gzip stream".to_vec(), 0).await;
        assert!(
            !result.success,
            "malformed compressed body must fail, got output={:?}",
            result.output
        );
        assert!(
            result
                .error
                .as_deref()
                .unwrap_or_default()
                .contains("Failed to read response body"),
            "error should describe the failed body read, got {:?}",
            result.error
        );
    }

    #[test]
    fn truncate_over_limit() {
        let tool = WebFetchTool::new(
            Arc::new(SecurityPolicy::default()),
            vec!["example.com".into()],
            vec![],
            10,
            30,
            FirecrawlConfig::default(),
            vec![],
            vec![],
        )
        .unwrap();
        let text = "hello world this is long";
        let truncated = tool.truncate_response(text);
        assert!(truncated.contains("[Response truncated"));
    }

    // ── Domain normalization ─────────────────────────────────────
    // ── Blocked domains ──────────────────────────────────────────

    #[test]
    fn blocklist_rejects_exact_match() {
        let tool = test_tool_with_blocklist(vec!["*"], vec!["evil.com"]);
        let err = tool
            .validate_url("https://evil.com/page")
            .unwrap_err()
            .to_string();
        assert!(err.contains("blocked_domains"));
    }

    #[test]
    fn blocklist_rejects_subdomain() {
        let tool = test_tool_with_blocklist(vec!["*"], vec!["evil.com"]);
        let err = tool
            .validate_url("https://api.evil.com/v1")
            .unwrap_err()
            .to_string();
        assert!(err.contains("blocked_domains"));
    }

    #[test]
    fn blocklist_wins_over_allowlist() {
        let tool = test_tool_with_blocklist(vec!["evil.com"], vec!["evil.com"]);
        let err = tool
            .validate_url("https://evil.com")
            .unwrap_err()
            .to_string();
        assert!(err.contains("blocked_domains"));
    }

    #[test]
    fn blocklist_allows_non_blocked() {
        let tool = test_tool_with_blocklist(vec!["*"], vec!["evil.com"]);
        assert!(tool.validate_url("https://example.com").is_ok());
    }

    #[test]
    fn resolved_private_ip_is_rejected() {
        let ips = vec!["127.0.0.1".parse().unwrap()];
        let err = validate_resolved_ips_for_ssrf("example.com", false, &ips, &[])
            .unwrap_err()
            .to_string();
        assert!(err.contains("non-global address"));
    }

    #[test]
    fn resolved_mixed_ips_are_rejected() {
        let ips = vec![
            "93.184.216.34".parse().unwrap(),
            "10.0.0.1".parse().unwrap(),
        ];
        let err = validate_resolved_ips_for_ssrf("example.com", false, &ips, &[])
            .unwrap_err()
            .to_string();
        assert!(err.contains("non-global address"));
    }

    #[test]
    fn resolved_public_ips_are_allowed() {
        let ips = vec!["93.184.216.34".parse().unwrap(), "1.1.1.1".parse().unwrap()];
        assert!(validate_resolved_ips_for_ssrf("example.com", false, &ips, &[]).is_ok());
    }

    #[test]
    fn private_opt_in_still_rejects_metadata_resolution() {
        let ips = vec!["169.254.170.23".parse().unwrap()];
        let err = validate_resolved_ips_for_ssrf("internal.example", true, &ips, &[])
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("cloud metadata address"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn metadata_denial_does_not_suggest_ineffective_private_opt_in() {
        let ips = vec!["169.254.169.254".parse().unwrap()];
        let err = validate_resolved_ips_for_ssrf("metadata.example", false, &ips, &[])
            .unwrap_err()
            .to_string();

        assert!(
            err.contains("cloud metadata address"),
            "unexpected error: {err}"
        );
        assert!(
            !err.contains("allowed_private_hosts"),
            "unexpected hint: {err}"
        );
    }

    #[tokio::test]
    async fn pinned_client_uses_the_validated_address_without_second_dns_lookup() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = zeroclaw_spawn::spawn!(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request).await.unwrap();
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .await
                .unwrap();
        });

        let target = ResolvedWebFetchTarget {
            url: format!("http://dns-rebinding.invalid:{}/", address.port()),
            host: "dns-rebinding.invalid".to_string(),
            resolved_addrs: vec![std::net::SocketAddr::new(address.ip(), 0)],
        };
        let client = pin_resolved_host(
            reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none()),
            &target,
        )
        .build()
        .unwrap();

        let response = client.get(&target.url).send().await.unwrap();
        assert_eq!(response.text().await.unwrap(), "ok");
        server.await.unwrap();
    }

    // ── Redirect boundary, end to end over real sockets ─────────────
    //
    // These drive a real 3xx through the real client built by
    // `build_redirect_guarded_client` — the same constructor `execute()`
    // uses. Everything else in this file tests `validate_redirect_target` in
    // isolation, which cannot catch the policy being unwired from the client
    // or the rejection flag going missing.

    /// A raw loopback HTTP server that counts accepted connections and replies
    /// with a canned response chosen by request path.
    struct CountingServer {
        addr: std::net::SocketAddr,
        hits: Arc<std::sync::atomic::AtomicUsize>,
        handle: tokio::task::JoinHandle<()>,
    }

    impl CountingServer {
        fn hits(&self) -> usize {
            self.hits.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    impl Drop for CountingServer {
        fn drop(&mut self) {
            self.handle.abort();
        }
    }

    async fn spawn_counting_server<F>(responder: F) -> CountingServer
    where
        F: Fn(&str) -> String + Send + Sync + 'static,
    {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let hits_for_task = Arc::clone(&hits);

        let handle = zeroclaw_spawn::spawn!(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                // Count on accept: merely reaching this server is the leak we
                // are asserting against, whether or not a request follows.
                hits_for_task.fetch_add(1, std::sync::atomic::Ordering::SeqCst);

                let mut buf = [0u8; 1024];
                let read = stream.read(&mut buf).await.unwrap_or(0);
                let request = String::from_utf8_lossy(&buf[..read]).into_owned();
                let path = request.split_whitespace().nth(1).unwrap_or("/").to_string();

                let _ = stream.write_all(responder(&path).as_bytes()).await;
                let _ = stream.flush().await;
            }
        });

        CountingServer { addr, hits, handle }
    }

    /// A 302 whose `Location` leaves the pinned host must not be followed, and
    /// the resulting failure must never be retried through Firecrawl — that
    /// would hand the blocked URL to a third party and undo the denial.
    #[tokio::test]
    async fn cross_host_redirect_is_denied_and_never_falls_back_to_firecrawl() {
        // Server B: the off-host redirect target. Must never be contacted.
        let server_b = spawn_counting_server(|_| {
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\
             Content-Length: 7\r\n\r\nLEAKED!"
                .to_string()
        })
        .await;

        // Server A: pinned host, redirects off-host to server B. The literal
        // 127.0.0.1 is resolvable without the pin, so a policy that follows
        // this hop really does reach B.
        let location = format!("http://127.0.0.1:{}/leak", server_b.addr.port());
        let server_a = spawn_counting_server(move |_| {
            format!(
                "HTTP/1.1 302 Found\r\nLocation: {location}\r\nConnection: close\r\n\
                 Content-Length: 0\r\n\r\n"
            )
        })
        .await;

        // Firecrawl ENABLED on purpose: with it enabled and the fetch failing,
        // the redirect-policy flag is the only thing that can suppress the
        // fallback, so assertion (c) below tests exactly that flag.
        let tool = test_tool_with_firecrawl(FirecrawlConfig {
            enabled: true,
            ..FirecrawlConfig::default()
        });
        let target = ResolvedWebFetchTarget {
            url: format!("http://pinned.invalid:{}/", server_a.addr.port()),
            host: "pinned.invalid".to_string(),
            resolved_addrs: vec![std::net::SocketAddr::new(server_a.addr.ip(), 0)],
        };

        let guarded = tool
            .build_redirect_guarded_client(&target, 5)
            .expect("client builds");
        let result = tool.standard_fetch(&guarded.client, &target.url).await;
        let rejected = guarded.redirect_policy_rejected.load(Ordering::Relaxed);

        assert_eq!(server_a.hits(), 1, "the pinned host should be fetched once");

        // (a) the cross-host hop was not followed.
        assert_eq!(
            server_b.hits(),
            0,
            "cross-host redirect was followed to the off-host target; error={:?}",
            result.error
        );
        assert!(
            !result.success,
            "a denied redirect must surface as a failed fetch"
        );

        // (c) before (b) deliberately: the security-relevant consequence of
        // losing the flag is the Firecrawl retry, so assert the real decision
        // fn on the real flag first and let that be the failure that shows.
        assert!(
            !tool.should_fallback_to_firecrawl(&result, rejected),
            "an SSRF-blocked redirect must never be retried through Firecrawl"
        );

        // (b) the outcome is marked as a redirect-policy rejection.
        assert!(
            rejected,
            "a policy-denied redirect must set the redirect-policy flag"
        );
    }

    /// The counterpart: the policy must not be a blanket deny. A redirect that
    /// stays on the pinned host is still followed, and does not trip the
    /// rejection flag.
    #[tokio::test]
    async fn same_host_redirect_is_followed_without_tripping_the_policy_flag() {
        let body = "b".repeat(200);
        let body_for_server = body.clone();
        let server = spawn_counting_server(move |path| {
            if path == "/second" {
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\
                     Content-Length: {}\r\n\r\n{}",
                    body_for_server.len(),
                    body_for_server
                )
            } else {
                "HTTP/1.1 302 Found\r\nLocation: /second\r\nConnection: close\r\n\
                 Content-Length: 0\r\n\r\n"
                    .to_string()
            }
        })
        .await;

        let tool = test_tool_with_firecrawl(FirecrawlConfig {
            enabled: true,
            ..FirecrawlConfig::default()
        });
        let target = ResolvedWebFetchTarget {
            url: format!("http://pinned.invalid:{}/", server.addr.port()),
            host: "pinned.invalid".to_string(),
            resolved_addrs: vec![std::net::SocketAddr::new(server.addr.ip(), 0)],
        };

        let guarded = tool
            .build_redirect_guarded_client(&target, 5)
            .expect("client builds");
        let result = tool.standard_fetch(&guarded.client, &target.url).await;
        let rejected = guarded.redirect_policy_rejected.load(Ordering::Relaxed);

        assert!(
            result.success,
            "same-host redirect must still be followed; error={:?}",
            result.error
        );
        assert_eq!(result.output, body, "must return the redirected body");
        assert!(
            !rejected,
            "an allowed redirect must not set the redirect-policy flag"
        );
        assert_eq!(
            server.hits(),
            2,
            "both the 302 and the followed request should reach the pinned host"
        );
    }

    // ── Firecrawl config parsing ────────────────────────────────────

    #[test]
    fn firecrawl_config_defaults() {
        let cfg = FirecrawlConfig::default();
        assert!(!cfg.enabled);
        assert_eq!(cfg.api_key_env, "FIRECRAWL_API_KEY");
        assert_eq!(cfg.api_url, "https://api.firecrawl.dev/v1");
        assert_eq!(cfg.mode, zeroclaw_config::schema::FirecrawlMode::Scrape);
    }

    #[test]
    fn firecrawl_config_deserializes_from_toml() {
        let toml_str = r#"
            enabled = true
            api_key_env = "MY_FC_KEY"
            api_url = "https://custom.firecrawl.io/v2"
            mode = "crawl"
        "#;
        let cfg: FirecrawlConfig = toml::from_str(toml_str).unwrap();
        assert!(cfg.enabled);
        assert_eq!(cfg.api_key_env, "MY_FC_KEY");
        assert_eq!(cfg.api_url, "https://custom.firecrawl.io/v2");
        assert_eq!(cfg.mode, zeroclaw_config::schema::FirecrawlMode::Crawl);
    }

    #[test]
    fn firecrawl_config_deserializes_defaults_from_empty_toml() {
        let cfg: FirecrawlConfig = toml::from_str("").unwrap();
        assert!(!cfg.enabled);
        assert_eq!(cfg.api_key_env, "FIRECRAWL_API_KEY");
    }

    #[test]
    fn web_fetch_config_with_firecrawl_section() {
        use zeroclaw_config::schema::WebFetchConfig;
        let toml_str = r#"
            enabled = true
            [firecrawl]
            enabled = true
            api_key_env = "FC_KEY"
        "#;
        let cfg: WebFetchConfig = toml::from_str(toml_str).unwrap();
        assert!(cfg.enabled);
        assert!(cfg.firecrawl.enabled);
        assert_eq!(cfg.firecrawl.api_key_env, "FC_KEY");
    }

    // ── Firecrawl fallback trigger conditions ───────────────────────

    #[test]
    fn fallback_disabled_when_firecrawl_not_enabled() {
        let tool = test_tool_with_firecrawl(FirecrawlConfig::default());
        let result = ToolResult {
            success: false,
            output: ToolOutput::default(),
            error: Some("HTTP 403 Forbidden".into()),
        };
        assert!(!tool.should_fallback_to_firecrawl(&result, false));
    }

    #[test]
    fn redirect_policy_rejection_never_falls_back_to_firecrawl() {
        let tool = test_tool_with_firecrawl(FirecrawlConfig {
            enabled: true,
            ..FirecrawlConfig::default()
        });
        let result = ToolResult {
            success: false,
            output: ToolOutput::default(),
            error: Some("Blocked redirect target".into()),
        };

        assert!(!tool.should_fallback_to_firecrawl(&result, true));
    }

    #[test]
    fn fallback_triggers_on_http_error() {
        let tool = test_tool_with_firecrawl(FirecrawlConfig {
            enabled: true,
            ..FirecrawlConfig::default()
        });
        let result = ToolResult {
            success: false,
            output: ToolOutput::default(),
            error: Some("HTTP 403 Forbidden".into()),
        };
        assert!(tool.should_fallback_to_firecrawl(&result, false));
    }

    #[test]
    fn fallback_triggers_on_empty_body() {
        let tool = test_tool_with_firecrawl(FirecrawlConfig {
            enabled: true,
            ..FirecrawlConfig::default()
        });
        let result = ToolResult {
            success: true,
            output: ToolOutput::default(),
            error: None,
        };
        assert!(tool.should_fallback_to_firecrawl(&result, false));
    }

    #[test]
    fn fallback_triggers_on_short_body() {
        let tool = test_tool_with_firecrawl(FirecrawlConfig {
            enabled: true,
            ..FirecrawlConfig::default()
        });
        let result = ToolResult {
            success: true,
            output: "Loading...".into(), // < 100 chars, JS-only page
            error: None,
        };
        assert!(tool.should_fallback_to_firecrawl(&result, false));
    }

    #[test]
    fn fallback_skipped_on_good_response() {
        let tool = test_tool_with_firecrawl(FirecrawlConfig {
            enabled: true,
            ..FirecrawlConfig::default()
        });
        let result = ToolResult {
            success: true,
            output: "A".repeat(200).into(), // well above 100 chars
            error: None,
        };
        assert!(!tool.should_fallback_to_firecrawl(&result, false));
    }

    // ── Firecrawl response parsing ──────────────────────────────────

    #[test]
    fn firecrawl_response_parses_markdown() {
        let response_json = json!({
            "success": true,
            "data": {
                "markdown": "# Hello World\n\nThis is extracted content from Firecrawl.",
                "metadata": {
                    "title": "Test Page"
                }
            }
        });
        let markdown = response_json
            .get("data")
            .and_then(|d| d.get("markdown"))
            .and_then(|m| m.as_str())
            .unwrap_or("");
        assert!(markdown.contains("Hello World"));
        assert!(markdown.contains("extracted content"));
    }

    #[test]
    fn firecrawl_response_handles_missing_markdown() {
        let response_json = json!({
            "success": true,
            "data": {}
        });
        let markdown = response_json
            .get("data")
            .and_then(|d| d.get("markdown"))
            .and_then(|m| m.as_str())
            .unwrap_or("");
        assert!(markdown.is_empty());
    }

    #[test]
    fn firecrawl_response_handles_missing_data() {
        let response_json = json!({
            "success": false,
            "error": "Rate limit exceeded"
        });
        let markdown = response_json
            .get("data")
            .and_then(|d| d.get("markdown"))
            .and_then(|m| m.as_str())
            .unwrap_or("");
        assert!(markdown.is_empty());
    }

    // ── Boundary test: FIRECRAWL_MIN_BODY_LEN (100 chars) ────────────

    #[test]
    fn fallback_triggers_at_exactly_99_chars() {
        let tool = test_tool_with_firecrawl(FirecrawlConfig {
            enabled: true,
            ..FirecrawlConfig::default()
        });
        let result = ToolResult {
            success: true,
            output: "A".repeat(99).into(),
            error: None,
        };
        assert!(
            tool.should_fallback_to_firecrawl(&result, false),
            "99-char body (below threshold) should trigger fallback"
        );
    }

    #[test]
    fn fallback_skipped_at_exactly_100_chars() {
        let tool = test_tool_with_firecrawl(FirecrawlConfig {
            enabled: true,
            ..FirecrawlConfig::default()
        });
        let result = ToolResult {
            success: true,
            output: "A".repeat(100).into(),
            error: None,
        };
        assert!(
            !tool.should_fallback_to_firecrawl(&result, false),
            "100-char body (at threshold) should NOT trigger fallback"
        );
    }

    // ── Item 1: missing API key env var falls back gracefully ─────────

    #[tokio::test]
    async fn firecrawl_missing_api_key_returns_error() {
        // Ensure the env var is unset for this test
        // SAFETY: test-only, single-threaded test runner.
        unsafe { std::env::remove_var("FIRECRAWL_TEST_MISSING_KEY") };

        let tool = test_tool_with_firecrawl(FirecrawlConfig {
            enabled: true,
            api_key_env: "FIRECRAWL_TEST_MISSING_KEY".into(),
            ..FirecrawlConfig::default()
        });

        let result = tool.fetch_via_firecrawl("https://example.com").await;
        assert!(
            result.is_err(),
            "fetch_via_firecrawl should return Err when API key env var is missing"
        );
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("FIRECRAWL_TEST_MISSING_KEY"),
            "Error should mention the missing env var name, got: {err_msg}"
        );
    }

    // ── Item 2: double-failure returns original standard result ───────

    #[tokio::test]
    async fn execute_double_failure_returns_original_result() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let addr = server.address();

        // Standard fetch returns 403 (failure)
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(403))
            .mount(&server)
            .await;

        // Ensure Firecrawl API key env is missing so fallback also fails
        // SAFETY: test-only, single-threaded test runner.
        unsafe { std::env::remove_var("FIRECRAWL_DOUBLE_FAIL_KEY") };

        let security = Arc::new(SecurityPolicy {
            autonomy: AutonomyLevel::Supervised,
            ..SecurityPolicy::default()
        });
        let tool = WebFetchTool::new(
            security,
            vec!["*".into()],
            vec![],
            500_000,
            30,
            FirecrawlConfig {
                enabled: true,
                api_key_env: "FIRECRAWL_DOUBLE_FAIL_KEY".into(),
                api_url: format!("http://{addr}"),
                ..FirecrawlConfig::default()
            },
            vec![],
            vec![],
        )
        .unwrap();

        // Bypass SSRF-guarded execute() — call standard_fetch + fallback
        // logic directly so wiremock on 127.0.0.1 is reachable.
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap();

        let url = format!("http://{addr}/page");
        let standard_result = tool.standard_fetch(&client, &url).await;

        // standard_fetch should fail with 403
        assert!(!standard_result.success);
        assert!(tool.should_fallback_to_firecrawl(&standard_result, false));

        // Firecrawl fallback should also fail (missing API key)
        let firecrawl_result = Box::pin(tool.fetch_via_firecrawl(&url)).await;
        assert!(
            firecrawl_result.is_err() || !firecrawl_result.as_ref().unwrap().success,
            "Expected Firecrawl fallback to fail without API key"
        );

        // The orchestration should return the original 403 error
        assert!(
            standard_result
                .error
                .as_deref()
                .unwrap_or("")
                .contains("403"),
            "Expected original HTTP 403 error, got: {:?}",
            standard_result.error
        );
    }

    // ── Item 3: end-to-end fallback orchestration in execute() ───────

    #[tokio::test]
    async fn execute_falls_back_to_firecrawl_on_short_body() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        // Standard-fetch server: returns a very short body (JS-only placeholder)
        let standard_server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string("<html><body>Loading...</body></html>")
                    .insert_header("content-type", "text/html"),
            )
            .mount(&standard_server)
            .await;

        // Firecrawl server: returns rich markdown content
        let firecrawl_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/scrape"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "success": true,
                "data": {
                    "markdown": "# Real Content\n\nThis is the full page content extracted by Firecrawl, with enough text to be clearly above the minimum body length threshold."
                }
            })))
            .mount(&firecrawl_server)
            .await;

        // Set up API key env var for this test
        // SAFETY: test-only, single-threaded test runner.
        unsafe { std::env::set_var("FIRECRAWL_E2E_TEST_KEY", "test-key-12345") };

        let security = Arc::new(SecurityPolicy {
            autonomy: AutonomyLevel::Supervised,
            ..SecurityPolicy::default()
        });
        let standard_addr = standard_server.address();
        let firecrawl_addr = firecrawl_server.address();
        let tool = WebFetchTool::new(
            security,
            vec!["*".into()],
            vec![],
            500_000,
            30,
            FirecrawlConfig {
                enabled: true,
                api_key_env: "FIRECRAWL_E2E_TEST_KEY".into(),
                api_url: format!("http://{firecrawl_addr}"),
                ..FirecrawlConfig::default()
            },
            vec![],
            vec![],
        )
        .unwrap();

        // Bypass SSRF-guarded execute() — call standard_fetch + fallback
        // logic directly so wiremock on 127.0.0.1 is reachable.
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap();

        let url = format!("http://{standard_addr}/page");
        let standard_result = tool.standard_fetch(&client, &url).await;

        // Standard fetch returns short body, should trigger fallback
        assert!(tool.should_fallback_to_firecrawl(&standard_result, false));

        // Firecrawl fallback should succeed with rich content
        let result = Box::pin(tool.fetch_via_firecrawl(&url)).await.unwrap();

        assert!(result.success, "Expected successful Firecrawl fallback");
        assert!(
            result.output.contains("Real Content"),
            "Expected Firecrawl markdown content, got: {}",
            result.output
        );

        // Clean up env var
        // SAFETY: test-only, single-threaded test runner.
        unsafe { std::env::remove_var("FIRECRAWL_E2E_TEST_KEY") };
    }

    // ── Allowed private hosts ─────────────────────────────────────

    #[test]
    fn allowed_private_host_bypasses_ssrf_block() {
        let tool = test_tool_with_private_hosts(vec!["*"], vec![], vec!["192.168.1.5"]);
        assert!(tool.validate_url("https://192.168.1.5/api").is_ok());
    }

    #[test]
    fn allowed_private_domain_still_runs_metadata_check() {
        let allowed_domains = vec!["*".to_string()];
        let blocked_domains = vec![];
        let allowed_private_hosts = vec!["local.internal".to_string()];

        let result = validate_target_url_with_dns_check(
            "https://local.internal/api",
            &allowed_domains,
            &blocked_domains,
            &allowed_private_hosts,
            "web_fetch",
            |host, allow_private| {
                assert_eq!(host, "local.internal");
                assert!(allow_private);
                Ok(())
            },
        );

        assert!(
            result.is_ok(),
            "allowlisted private domain was rejected: {result:?}"
        );
    }

    #[test]
    fn private_wildcard_allows_domain_resolving_to_private_ip() {
        // allowed_private_hosts = ["*"] must permit a
        // regular domain that resolves to a private/internal IP, as long as the
        // name itself passes allowed_domains. Resolution still runs in the
        // metadata-only mode.
        let allowed_domains = vec!["example.com".to_string()];
        let blocked_domains = vec![];
        let allowed_private_hosts = vec!["*".to_string()];

        let result = validate_target_url_with_dns_check(
            "https://internal.example.com/api",
            &allowed_domains,
            &blocked_domains,
            &allowed_private_hosts,
            "web_fetch",
            |host, allow_private| {
                assert_eq!(host, "internal.example.com");
                assert!(allow_private);
                Ok(())
            },
        );

        assert!(
            result.is_ok(),
            "private wildcard should allow subdomain of allowed_domains: {result:?}"
        );
    }

    #[test]
    fn private_wildcard_allows_literal_private_ip_without_allowed_domains_entry() {
        // The "*" wildcard must keep its historical scope for *literal* private
        // hosts: an IP literal (or localhost/.local) is allowed even when it is
        // not listed in allowed_domains. Only ordinary domain names stay gated
        // on allowed_domains under "*".
        let allowed_domains = vec!["example.com".to_string()];
        let blocked_domains = vec![];
        let allowed_private_hosts = vec!["*".to_string()];

        let result = validate_target_url_with_dns_check(
            "https://10.0.0.1/api",
            &allowed_domains,
            &blocked_domains,
            &allowed_private_hosts,
            "web_fetch",
            |host, allow_private| {
                assert_eq!(host, "10.0.0.1");
                assert!(allow_private);
                Ok(())
            },
        );

        assert!(
            result.is_ok(),
            "private wildcard should allow a literal private IP: {result:?}"
        );
    }

    #[test]
    fn private_allowlist_explicit_entry_must_pass_allowed_domains() {
        // An explicit (non-private) entry in allowed_private_hosts is NOT a free
        // pass: a non-private host still has to be in allowed_domains.
        let allowed_domains = vec!["example.com".to_string()];
        let blocked_domains = vec![];
        let allowed_private_hosts = vec!["unrelated.com".to_string()];

        let err = validate_target_url_with_dns_check(
            "https://unrelated.com/api",
            &allowed_domains,
            &blocked_domains,
            &allowed_private_hosts,
            "web_fetch",
            |_, _| anyhow::Ok(()),
        )
        .unwrap_err()
        .to_string();

        assert!(err.contains("allowed_domains"), "unexpected error: {err}");
    }

    #[test]
    fn private_wildcard_still_requires_allowed_domains() {
        // The "*" private wildcard must NOT widen the name allowlist: a public
        // domain that is not in allowed_domains stays blocked.
        let allowed_domains = vec!["example.com".to_string()];
        let blocked_domains = vec![];
        let allowed_private_hosts = vec!["*".to_string()];

        let err = validate_target_url_with_dns_check(
            "https://evil.com/api",
            &allowed_domains,
            &blocked_domains,
            &allowed_private_hosts,
            "web_fetch",
            |_, _| anyhow::Ok(()),
        )
        .unwrap_err()
        .to_string();

        assert!(err.contains("allowed_domains"), "unexpected error: {err}");
    }

    #[test]
    fn unallowed_domain_resolving_private_ip_still_blocked() {
        let allowed_domains = vec!["*".to_string()];
        let blocked_domains = vec![];
        let allowed_private_hosts = vec![];

        let err = validate_target_url_with_dns_check(
            "https://local.internal/api",
            &allowed_domains,
            &blocked_domains,
            &allowed_private_hosts,
            "web_fetch",
            |host, allow_private| {
                validate_resolved_ips_for_ssrf(
                    host,
                    allow_private,
                    &[std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                        192, 168, 1, 5,
                    ))],
                    &[],
                )
            },
        )
        .unwrap_err()
        .to_string();

        assert!(
            err.contains("non-global address"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn private_allowlist_wildcard_does_not_allow_public_domain_miss() {
        let allowed_domains = vec!["example.com".to_string()];
        let blocked_domains = vec![];
        let allowed_private_hosts = vec!["*".to_string()];

        let err = validate_target_url_with_dns_check(
            "https://not-example.com/api",
            &allowed_domains,
            &blocked_domains,
            &allowed_private_hosts,
            "web_fetch",
            |_, _| anyhow::Ok(()),
        )
        .unwrap_err()
        .to_string();

        assert!(err.contains("allowed_domains"), "unexpected error: {err}");
    }

    #[test]
    fn blocklist_overrides_allowed_private_domain() {
        let allowed_domains = vec!["*".to_string()];
        let blocked_domains = vec!["local.internal".to_string()];
        let allowed_private_hosts = vec!["local.internal".to_string()];

        let err = validate_target_url_with_dns_check(
            "https://local.internal/api",
            &allowed_domains,
            &blocked_domains,
            &allowed_private_hosts,
            "web_fetch",
            |_, _| anyhow::bail!("blocklist should run before DNS validation"),
        )
        .unwrap_err()
        .to_string();

        assert!(err.contains("blocked_domains"), "unexpected error: {err}");
    }

    #[test]
    fn unallowed_private_host_still_blocked() {
        let tool = test_tool_with_private_hosts(vec!["*"], vec![], vec!["192.168.1.5"]);
        let err = tool
            .validate_url("https://10.0.0.1/admin")
            .unwrap_err()
            .to_string();
        assert!(err.contains("local/private"));
        assert!(err.contains("allowed_private_hosts"));
    }

    #[test]
    fn blocklist_overrides_allowed_private_host() {
        let tool =
            test_tool_with_private_hosts(vec!["*"], vec!["192.168.1.5"], vec!["192.168.1.5"]);
        let err = tool
            .validate_url("https://192.168.1.5/secret")
            .unwrap_err()
            .to_string();
        assert!(err.contains("blocked_domains"));
    }

    #[test]
    fn allowed_private_host_with_port() {
        let tool = test_tool_with_private_hosts(vec!["*"], vec![], vec!["192.168.1.5"]);
        assert!(tool.validate_url("https://192.168.1.5:8080/api").is_ok());
    }

    // ── network-specific NAT64 prefixes ──────────────────────────

    /// A globally-classified NAT64 prefix. The IPv6 documentation range is
    /// itself non-global, so a documentation prefix would be rejected for an
    /// unrelated reason and prove nothing about the NAT64 decode.
    const TEST_NAT64_PREFIX: &str = "2001:67c:2b0:db32:0:1::/96";

    fn nat64(prefix: &str) -> Vec<domain_guard::Nat64Prefix> {
        domain_guard::parse_nat64_prefixes(&[prefix.to_string()], "security.nat64_prefixes")
            .unwrap()
    }

    #[test]
    fn configured_nat64_prefix_rejects_embedded_private_v4() {
        let ips = vec!["2001:67c:2b0:db32:0:1:a00:1".parse().unwrap()];
        let err = validate_resolved_ips_for_ssrf(
            "attacker.example",
            false,
            &ips,
            &nat64(TEST_NAT64_PREFIX),
        )
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("non-global address 10.0.0.1"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn configured_nat64_prefix_rejects_embedded_metadata_v4_under_private_opt_in() {
        let ips = vec!["2001:67c:2b0:db32:0:1:a9fe:a9fe".parse().unwrap()];
        let err = validate_resolved_ips_for_ssrf(
            "attacker.example",
            true,
            &ips,
            &nat64(TEST_NAT64_PREFIX),
        )
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("cloud metadata address 169.254.169.254"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn nat64_embedded_addresses_pass_without_a_configured_prefix() {
        // Honest boundary: nothing in the address marks it as NAT64. Without a
        // declared `security.nat64_prefixes` entry the SSRF gate has no evidence
        // the deployment translates this prefix, so both a private-embedding and
        // a metadata-embedding answer are treated as ordinary global IPv6 and
        // pass. Declaring the prefix is what turns the decode on; see
        // `configured_nat64_prefix_rejects_embedded_metadata_v4_under_private_opt_in`.
        let private = vec!["2001:67c:2b0:db32:0:1:a00:1".parse().unwrap()];
        assert!(validate_resolved_ips_for_ssrf("attacker.example", false, &private, &[]).is_ok());
        let metadata = vec!["2001:67c:2b0:db32:0:1:a9fe:a9fe".parse().unwrap()];
        assert!(validate_resolved_ips_for_ssrf("attacker.example", true, &metadata, &[]).is_ok());
    }

    #[test]
    fn malformed_nat64_prefix_fails_tool_construction() {
        let security = Arc::new(SecurityPolicy::default());
        let err = WebFetchTool::new(
            security,
            vec!["example.com".into()],
            vec![],
            500_000,
            30,
            FirecrawlConfig::default(),
            vec![],
            vec![TEST_NAT64_PREFIX.to_string(), "2001:db8::/33".into()],
        )
        .err()
        .expect("malformed nat64 prefix must fail construction")
        .to_string();
        assert!(
            err.contains("security.nat64_prefixes"),
            "unexpected error: {err}"
        );
        assert!(err.contains("2001:db8::/33"), "unexpected error: {err}");
    }

    // ── Spill-to-workspace-file for oversized responses ───────────
    //
    // These drive `standard_fetch` through wiremock so the whole
    // read → convert → spill path is exercised, and root the tool at a
    // throwaway workspace so no test can write into the repo.

    /// A tool whose `SecurityPolicy.workspace_dir` — the canonical
    /// workspace root, same field `file_read`/`file_write` resolve
    /// against — points at a throwaway directory.
    fn spill_test_tool(workspace: &std::path::Path, max_response_size: usize) -> WebFetchTool {
        let security = Arc::new(SecurityPolicy {
            autonomy: AutonomyLevel::Supervised,
            workspace_dir: workspace.to_path_buf(),
            ..SecurityPolicy::default()
        });
        WebFetchTool::new(
            security,
            vec!["*".into()],
            vec![],
            max_response_size,
            30,
            FirecrawlConfig::default(),
            vec![],
        vec![],
    )
        .unwrap()
    }

    /// Serve `body` as `content_type` and run `standard_fetch` against it.
    async fn fetch_body(tool: &WebFetchTool, body: &str, content_type: &str) -> ToolResult {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        // `set_body_raw` takes the content type explicitly. `set_body_string`
        // + `insert_header("content-type", ...)` does NOT override it —
        // the body helper's `text/plain` wins, which silently routes every
        // such test down the plain-text branch.
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(body.as_bytes(), content_type))
            .mount(&server)
            .await;

        // Bypass SSRF-guarded execute() — call standard_fetch directly so
        // wiremock on 127.0.0.1 is reachable.
        let url = format!("http://{}/page", server.address());
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("reqwest client");
        tool.standard_fetch(&client, &url).await
    }

    /// Pins the pre-existing inline behaviour: a body comfortably under the
    /// spill threshold is returned verbatim and nothing is written to disk.
    #[tokio::test]
    async fn body_below_spill_threshold_is_returned_inline() {
        let workspace = tempfile::tempdir().expect("tempdir");
        let tool = spill_test_tool(workspace.path(), 500_000);
        let body = "b".repeat(1_000);

        let result = fetch_body(&tool, &body, "text/plain").await;

        assert!(result.success, "error={:?}", result.error);
        assert_eq!(
            result.output.as_str(),
            body,
            "sub-threshold body must be returned inline, unchanged"
        );
        assert!(
            !workspace.path().join("tmp").exists(),
            "sub-threshold fetch must not create the spill directory"
        );
    }

    /// Boundary: exactly `SPILL_THRESHOLD_BYTES` still returns inline.
    /// Only *above* the threshold spills.
    #[tokio::test]
    async fn body_at_exact_spill_threshold_is_returned_inline() {
        let workspace = tempfile::tempdir().expect("tempdir");
        let tool = spill_test_tool(workspace.path(), 500_000);
        let body = "c".repeat(SPILL_THRESHOLD_BYTES);

        let result = fetch_body(&tool, &body, "text/plain").await;

        assert!(result.success, "error={:?}", result.error);
        assert_eq!(
            result.output.as_str().len(),
            SPILL_THRESHOLD_BYTES,
            "a body of exactly the threshold must be returned inline"
        );
        assert!(
            !workspace.path().join("tmp").exists(),
            "threshold-sized fetch must not create the spill directory"
        );
    }

    /// Pull the `Saved to: <path>` line out of a spill message.
    fn saved_path(message: &str) -> &str {
        message
            .lines()
            .find_map(|line| line.strip_prefix("Saved to: "))
            .unwrap_or_else(|| panic!("no 'Saved to:' line in message:\n{message}"))
            .trim()
    }

    #[tokio::test]
    async fn body_above_spill_threshold_is_written_to_a_workspace_file() {
        let workspace = tempfile::tempdir().expect("tempdir");
        let tool = spill_test_tool(workspace.path(), 500_000);
        let body = "d".repeat(60_000);

        let result = fetch_body(&tool, &body, "text/plain").await;

        assert!(result.success, "error={:?}", result.error);
        let message = result.output.as_str();

        // The message replaces the body: short, and not the payload itself.
        assert!(
            message.len() < 1_000,
            "spill message should be short, got {} bytes",
            message.len()
        );
        assert!(
            !message.contains(&"d".repeat(1_000)),
            "spill message must not carry the body inline"
        );
        assert!(
            message.contains("60000 bytes"),
            "message must state the byte count, got:\n{message}"
        );
        assert!(
            message.contains("file_read") && message.contains("content_search"),
            "message must point at the workspace file tools, got:\n{message}"
        );
        assert!(
            !message.contains("max_response_size"),
            "no stream-cap note expected when the cap did not fire, got:\n{message}"
        );

        // The file holds the FULL converted text, with no truncation marker.
        let relative = saved_path(message);
        assert!(
            relative.starts_with("tmp/web_fetch/") && relative.ends_with(".txt"),
            "unexpected spill path: {relative}"
        );
        let written = std::fs::read_to_string(workspace.path().join(relative))
            .expect("spill file must exist at the advertised path");
        assert_eq!(
            written, body,
            "spill file must hold the full converted text"
        );
        assert!(
            !written.contains("[Response truncated"),
            "spilled file must not carry the inline truncation marker"
        );
    }

    /// The load-bearing safety property: the write lands inside the workspace
    /// root resolved from `SecurityPolicy::workspace_dir`, and nowhere else.
    #[tokio::test]
    async fn spilled_file_stays_inside_the_workspace_root() {
        let workspace = tempfile::tempdir().expect("tempdir");
        let tool = spill_test_tool(workspace.path(), 500_000);
        let body = "e".repeat(60_000);

        let result = fetch_body(&tool, &body, "text/plain").await;
        let relative = saved_path(result.output.as_str());

        let root = workspace
            .path()
            .canonicalize()
            .expect("canonical workspace");
        let written = workspace
            .path()
            .join(relative)
            .canonicalize()
            .expect("spill file must exist");

        assert!(
            written.starts_with(&root),
            "spill file {} escaped workspace root {}",
            written.display(),
            root.display()
        );
        assert!(
            !std::path::Path::new(relative).is_absolute(),
            "advertised path must be workspace-relative, got {relative}"
        );
        assert!(
            !relative.contains(".."),
            "advertised path must not contain parent traversal, got {relative}"
        );
    }

    /// The containment guard, exercised for real: a symlinked `tmp/` planted
    /// inside the workspace points at an outside directory. `create_dir_all`
    /// follows it, so the post-creation canonicalize + `starts_with` check is
    /// the only thing standing between the fetch and a write outside the
    /// sandbox. No page content may land outside the workspace root.
    #[cfg(unix)]
    #[tokio::test]
    async fn spill_refuses_to_write_through_a_symlink_out_of_the_workspace() {
        let workspace = tempfile::tempdir().expect("workspace tempdir");
        let outside = tempfile::tempdir().expect("outside tempdir");
        std::os::unix::fs::symlink(outside.path(), workspace.path().join("tmp"))
            .expect("plant symlink");

        let tool = spill_test_tool(workspace.path(), 500_000);
        let body = "i".repeat(60_000);

        let result = fetch_body(&tool, &body, "text/plain").await;

        // Falls back to the inline path rather than writing outside.
        assert!(result.success, "error={:?}", result.error);
        assert_eq!(
            result.output.as_str(),
            body,
            "a blocked spill must fall back to the inline body"
        );

        // Nothing — no page content at all — may exist outside the workspace.
        let escaped: Vec<_> = walk_files(outside.path());
        assert!(
            escaped.is_empty(),
            "page content escaped the workspace to {escaped:?}"
        );
    }

    /// Every regular file under `dir`, recursively.
    #[cfg(unix)]
    fn walk_files(dir: &std::path::Path) -> Vec<PathBuf> {
        let mut found = Vec::new();
        let Ok(entries) = std::fs::read_dir(dir) else {
            return found;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                found.extend(walk_files(&path));
            } else {
                found.push(path);
            }
        }
        found
    }

    #[tokio::test]
    async fn spill_uses_markdown_extension_for_converted_html() {
        let workspace = tempfile::tempdir().expect("tempdir");
        let tool = spill_test_tool(workspace.path(), 500_000);
        let body = format!(
            "<html><head><title>  Big \n Page  </title></head><body><p>{}</p></body></html>",
            "word ".repeat(15_000)
        );

        let result = fetch_body(&tool, &body, "text/html").await;

        assert!(result.success, "error={:?}", result.error);
        let message = result.output.as_str();
        let relative = saved_path(message);
        assert!(
            relative.ends_with(".md"),
            "converted HTML must spill as .md, got {relative}"
        );
        // Title is lifted from the raw HTML and whitespace-collapsed.
        assert!(
            message.contains("Title: Big Page"),
            "message must carry the page title, got:\n{message}"
        );
        // The file holds converted text, not the source markup.
        let written = std::fs::read_to_string(workspace.path().join(relative)).expect("spill file");
        assert!(
            !written.contains("<p>"),
            "spilled HTML must be stored converted, not raw"
        );
        assert!(written.contains("word"));
    }

    /// Stream-cap interaction: `max_response_size` stays the absolute guard,
    /// and when it fires the message says the saved content is incomplete.
    #[tokio::test]
    async fn spill_message_flags_stream_cap_truncation() {
        let workspace = tempfile::tempdir().expect("tempdir");
        // Cap below the body size but above the spill threshold, so the read
        // is cut short AND the surviving text still spills.
        let tool = spill_test_tool(workspace.path(), 60_000);
        let body = "f".repeat(80_000);

        let result = fetch_body(&tool, &body, "text/plain").await;

        assert!(result.success, "error={:?}", result.error);
        let message = result.output.as_str();
        assert!(
            message.contains("max_response_size"),
            "message must disclose the stream-cap truncation, got:\n{message}"
        );

        // The stream cap still bounds what was written: hard_cap is
        // max_response_size + 1, so the file holds 60_001 bytes, not 80_000.
        let written = std::fs::read_to_string(workspace.path().join(saved_path(message)))
            .expect("spill file");
        assert_eq!(
            written.len(),
            60_001,
            "stream cap must still bound the spilled bytes"
        );
    }

    /// A spilled result must not look like a JS-only page to the Firecrawl
    /// heuristic — the message is short by design, and `FIRECRAWL_MIN_BODY_LEN`
    /// is only 100 bytes.
    #[tokio::test]
    async fn spilled_result_does_not_trigger_firecrawl_fallback() {
        let workspace = tempfile::tempdir().expect("tempdir");
        let security = Arc::new(SecurityPolicy {
            autonomy: AutonomyLevel::Supervised,
            workspace_dir: workspace.path().to_path_buf(),
            ..SecurityPolicy::default()
        });
        let tool = WebFetchTool::new(
            security,
            vec!["*".into()],
            vec![],
            500_000,
            30,
            FirecrawlConfig {
                enabled: true,
                ..FirecrawlConfig::default()
            },
            vec![],
        vec![],
    )
        .unwrap();

        let result = fetch_body(&tool, &"g".repeat(60_000), "text/plain").await;

        assert!(result.success, "error={:?}", result.error);
        assert!(
            result.output.as_str().len() > FIRECRAWL_MIN_BODY_LEN,
            "spill message must stay above the Firecrawl short-body threshold"
        );
        assert!(
            !tool.should_fallback_to_firecrawl(&result, false),
            "a successful spill must not be mistaken for a JS-only page"
        );
    }

    /// No resolvable workspace → the pre-existing inline behaviour, never a
    /// write outside the sandbox and never a dropped response.
    #[tokio::test]
    async fn spill_falls_back_to_inline_when_workspace_is_unresolvable() {
        let workspace = tempfile::tempdir().expect("tempdir");
        let missing = workspace.path().join("no-such-workspace");
        let tool = spill_test_tool(&missing, 500_000);
        let body = "h".repeat(60_000);

        let result = fetch_body(&tool, &body, "text/plain").await;

        assert!(result.success, "error={:?}", result.error);
        assert_eq!(
            result.output.as_str(),
            body,
            "with no workspace the body must come back inline, unchanged"
        );
        assert!(
            !missing.exists(),
            "an unresolvable workspace must not be created behind the operator's back"
        );
    }

    // ── Spill filename ───────────────────────────────────────────

    #[test]
    fn spill_file_name_is_stable_for_the_same_host_and_content() {
        let text = "same content";
        let first = spill_file_name("https://example.com/a", text, "md");
        let second = spill_file_name("https://example.com/a", text, "md");
        assert_eq!(first, second, "same host + content must be deterministic");

        // Path within the host does not change the name; only host + content do.
        let other_path = spill_file_name("https://example.com/b", text, "md");
        assert_eq!(first, other_path);

        assert!(
            first.starts_with("example.com-") && first.ends_with(".md"),
            "unexpected name: {first}"
        );
    }

    #[test]
    fn spill_file_name_changes_with_content_and_host() {
        let base = spill_file_name("https://example.com/a", "content one", "md");
        assert_ne!(
            base,
            spill_file_name("https://example.com/a", "content two", "md"),
            "different content must not overwrite a different page's file"
        );
        assert_ne!(
            base,
            spill_file_name("https://other.example.org/a", "content one", "md"),
            "different host must produce a different file"
        );
    }

    #[test]
    fn spill_file_name_is_a_single_safe_component() {
        // Ports are already stripped by extract_host; prove the sanitizer
        // still yields one component with no separator or traversal.
        for url in [
            "https://example.com:8443/a",
            "http://sub.example.co.uk/x?y=1",
        ] {
            let name = spill_file_name(url, "body", "txt");
            assert!(!name.contains('/'), "{name} contains a separator");
            assert!(!name.contains('\\'), "{name} contains a separator");
            assert!(!name.contains(".."), "{name} contains traversal");
            assert_eq!(
                std::path::Path::new(&name).components().count(),
                1,
                "{name} is not a single path component"
            );
        }
    }

    #[test]
    fn sanitize_path_component_strips_separators_and_traversal() {
        // Separators become `-`, so a traversal string collapses into one
        // harmless filename component. `..` survives only as literal
        // characters inside a name, never as a path component.
        let hostile = sanitize_path_component("../../etc/passwd");
        assert_eq!(hostile, "-..-etc-passwd");
        assert_eq!(
            std::path::Path::new(&hostile).components().count(),
            1,
            "sanitized host must be a single path component"
        );
        assert_eq!(
            std::path::Path::new(&hostile).parent(),
            Some(std::path::Path::new("")),
            "sanitized host must not re-parent"
        );

        assert_eq!(sanitize_path_component(".."), "unknown-host");
        assert_eq!(sanitize_path_component("."), "unknown-host");
        assert_eq!(sanitize_path_component(""), "unknown-host");
        assert_eq!(sanitize_path_component("a/b\\c"), "a-b-c");
        assert_eq!(sanitize_path_component("exämple.com"), "ex-mple.com");
        assert!(sanitize_path_component(&"a".repeat(200)).len() <= 60);
    }

    // ── Spill extension mapping ──────────────────────────────────

    #[test]
    fn spill_extension_maps_content_types() {
        assert_eq!(spill_extension("text/html; charset=utf-8", "html"), "md");
        assert_eq!(spill_extension("", "html"), "md");
        assert_eq!(spill_extension("application/json", "plain"), "json");
        assert_eq!(spill_extension("text/markdown", "plain"), "md");
        assert_eq!(spill_extension("text/plain; charset=utf-8", "plain"), "txt");
    }

    // ── Title extraction ─────────────────────────────────────────

    #[test]
    fn extract_html_title_handles_case_whitespace_and_absence() {
        assert_eq!(
            extract_html_title("<HTML><HEAD><TITLE>  Hello \n World </TITLE>").as_deref(),
            Some("Hello World")
        );
        assert_eq!(
            extract_html_title("<title lang=\"en\">Attr Title</title>").as_deref(),
            Some("Attr Title")
        );
        assert_eq!(extract_html_title("<html><body>no title</body>"), None);
        assert_eq!(extract_html_title("<title>   </title>"), None);
        assert_eq!(extract_html_title("<title>unclosed"), None);

        // Multi-byte titles inside the scan window survive intact.
        let near = format!("{}<title>Späte Seite</title>", "€".repeat(100));
        assert_eq!(extract_html_title(&near).as_deref(), Some("Späte Seite"));

        // Beyond the scan window the title is simply not found — and, the
        // point of this case, the 64 KiB cut must not land mid-character and
        // panic. "€" is 3 bytes, so byte 65536 is never a char boundary.
        let far = format!("{}<title>Too Late</title>", "€".repeat(30_000));
        assert_eq!(
            extract_html_title(&far),
            None,
            "title past the scan limit is skipped, not a panic"
        );
    }
}
