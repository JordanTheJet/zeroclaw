//! Host-supervised native embedding-provider plugins.
//!
//! The child owns an ephemeral loopback HTTP listener. ZeroClaw authenticates
//! every request with a per-launch token delivered over stdin; neither value is
//! persisted or written back into operator configuration.

use anyhow::{Context, bail, ensure};
use async_trait::async_trait;
use futures_util::StreamExt;
use parking_lot::Mutex;
use ring::rand::{SecureRandom, SystemRandom};
use serde::Deserialize;
use std::collections::HashMap;
use std::fmt::Write as _;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use zeroclaw_api::embedding::{
    EmbeddingProvider, EmbeddingProviderFactory, ResolvedEmbeddingProvider,
};
use zeroclaw_config::schema::Config;
use zeroclaw_plugins::host::PluginHost;

#[cfg(feature = "reference-sidecar")]
pub mod reference;

pub const READINESS_PROTOCOL_VERSION: u32 = 1;
pub const LAUNCH_TOKEN_BYTES: usize = 32;
pub const LAUNCH_TOKEN_HEX_LEN: usize = LAUNCH_TOKEN_BYTES * 2;
const MAX_READINESS_BYTES: u64 = 1_024;
const DEFAULT_STARTUP_TIMEOUT: Duration = Duration::from_secs(300);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_CONCURRENT_REQUESTS: usize = 4;
const MAX_ERROR_RESPONSE_BYTES: usize = 4_096;
const EMBEDDING_JSON_BYTES_PER_VALUE: usize = 32;
const EMBEDDING_JSON_BASE_BYTES: usize = 65_536;
static SUPERVISOR: OnceLock<EmbeddingSupervisor> = OnceLock::new();

fn supervisor() -> &'static EmbeddingSupervisor {
    SUPERVISOR.get_or_init(EmbeddingSupervisor::default)
}

#[derive(Default)]
struct EmbeddingSupervisor {
    providers: Mutex<HashMap<String, Arc<ManagedEmbeddingProvider>>>,
}

impl EmbeddingSupervisor {
    fn acquire(
        &self,
        plugin_name: &str,
        identity: &str,
        launch: impl FnOnce() -> anyhow::Result<ManagedEmbeddingProvider>,
    ) -> anyhow::Result<Arc<ManagedEmbeddingProvider>> {
        let mut providers = self.providers.lock();
        if let Some(provider) = providers.get(identity)
            && provider.is_running()
        {
            return Ok(Arc::clone(provider));
        }
        providers.remove(identity);

        let logical_prefix = format!(
            "{}{}@",
            zeroclaw_api::embedding::MANAGED_EMBEDDING_PROVIDER_PREFIX,
            plugin_name
        );
        providers.retain(|key, provider| {
            !key.starts_with(&logical_prefix) || Arc::strong_count(provider) > 1
        });

        let provider = Arc::new(launch()?);
        providers.insert(identity.to_string(), Arc::clone(&provider));
        Ok(provider)
    }
}

/// Construct a memory backend from canonical config, enabling a managed
/// embedding plugin only when the resolved provider is `plugin:<name>`.
pub fn create_memory(
    config: &Config,
    workspace_dir: &Path,
    inherited_api_key: Option<&str>,
) -> anyhow::Result<Box<dyn zeroclaw_api::memory_traits::Memory>> {
    let backend = zeroclaw_memory::backend_kind_from_dotted(&config.memory.backend);
    let needs_embeddings = matches!(
        zeroclaw_memory::classify_memory_backend(&backend),
        zeroclaw_memory::MemoryBackendKind::Sqlite
            | zeroclaw_memory::MemoryBackendKind::Lucid
            | zeroclaw_memory::MemoryBackendKind::Qdrant
    );
    let factory = needs_embeddings
        .then(|| PluginEmbeddingFactory::from_config(config, inherited_api_key))
        .transpose()?
        .flatten();
    zeroclaw_memory::create_memory_with_storage_routes_and_embedding_factory(
        &config.memory,
        &config.embedding_routes,
        config.resolve_active_storage(),
        workspace_dir,
        inherited_api_key,
        Some(&config.providers.models),
        factory
            .as_ref()
            .map(|factory| factory as &dyn EmbeddingProviderFactory),
    )
}

/// Construct the canonical per-agent memory wrapper with managed embedding
/// plugin support when selected by config.
pub async fn create_memory_for_agent(
    config: &Config,
    agent_alias: &str,
    inherited_api_key: Option<&str>,
) -> anyhow::Result<Arc<dyn zeroclaw_api::memory_traits::Memory>> {
    let needs_embeddings = config.agents.get(agent_alias).is_some_and(|agent| {
        matches!(
            agent.memory.backend,
            zeroclaw_config::multi_agent::MemoryBackendKind::Sqlite
                | zeroclaw_config::multi_agent::MemoryBackendKind::Lucid
                | zeroclaw_config::multi_agent::MemoryBackendKind::Qdrant
        )
    });
    let factory = needs_embeddings
        .then(|| PluginEmbeddingFactory::from_config(config, inherited_api_key))
        .transpose()?
        .flatten();
    zeroclaw_memory::create_memory_for_agent_with_embedding_factory(
        config,
        agent_alias,
        inherited_api_key,
        factory
            .as_ref()
            .map(|factory| factory as &dyn EmbeddingProviderFactory),
    )
    .await
}

/// Resolves `plugin:<name>` provider selections through one verified plugin
/// host and launches the selected sidecar.
pub struct PluginEmbeddingFactory {
    host: PluginHost,
    startup_timeout: Duration,
}

impl PluginEmbeddingFactory {
    pub fn new(host: PluginHost) -> Self {
        Self {
            host,
            startup_timeout: DEFAULT_STARTUP_TIMEOUT,
        }
    }

    pub fn with_startup_timeout(host: PluginHost, startup_timeout: Duration) -> Self {
        Self {
            host,
            startup_timeout,
        }
    }

    /// Build a verified plugin resolver only when the canonical memory
    /// settings select `plugin:<name>`.
    pub fn from_config(
        config: &Config,
        inherited_api_key: Option<&str>,
    ) -> anyhow::Result<Option<Self>> {
        let settings = zeroclaw_memory::resolve_embedding_settings(
            &config.memory,
            &config.embedding_routes,
            inherited_api_key,
            Some(&config.providers.models),
        );
        if !settings
            .model_provider
            .starts_with(zeroclaw_api::embedding::MANAGED_EMBEDDING_PROVIDER_PREFIX)
        {
            return Ok(None);
        }
        ensure!(
            config.plugins.enabled,
            "memory selects an embedding plugin but plugins.enabled is false"
        );
        ensure!(
            config.plugins.allow_native_sidecars,
            "memory selects a native embedding plugin but plugins.allow_native_sidecars is false"
        );
        let signature_mode =
            PluginHost::resolve_signature_mode(&config.plugins.security.signature_mode);
        let host = PluginHost::from_plugins_dir_with_security(
            &config.plugins.resolved_plugins_dir(),
            signature_mode,
            config.plugins.security.trusted_publisher_keys.clone(),
        )?;
        Ok(Some(Self::with_startup_timeout(
            host,
            Duration::from_secs(config.plugins.native_sidecar_startup_timeout_secs),
        )))
    }

    /// Launch one installed provider after resolving its executable and
    /// literal arguments from the verified manifest.
    pub fn launch(
        &self,
        plugin_name: &str,
        model: &str,
        dimensions: usize,
    ) -> anyhow::Result<Arc<ManagedEmbeddingProvider>> {
        Ok(self.resolve(plugin_name, model, dimensions)?.0)
    }

    fn resolve(
        &self,
        plugin_name: &str,
        model: &str,
        dimensions: usize,
    ) -> anyhow::Result<(Arc<ManagedEmbeddingProvider>, String)> {
        ensure!(!plugin_name.is_empty(), "embedding plugin name is empty");
        ensure!(!model.trim().is_empty(), "embedding model is empty");
        ensure!(
            dimensions > 0,
            "embedding dimensions must be greater than zero"
        );

        let (manifest, plugin_dir, executable) = self
            .host
            .embedding_provider_details(plugin_name)
            .with_context(|| {
                format!("embedding-provider plugin '{plugin_name}' is not installed or valid")
            })?;
        let embedding = manifest.embedding_provider.as_ref().with_context(|| {
            format!("embedding-provider plugin '{plugin_name}' has no provider manifest")
        })?;
        ensure!(
            embedding.model == model,
            "embedding plugin '{plugin_name}' serves model {:?}; configuration requested {:?}",
            embedding.model,
            model
        );
        ensure!(
            embedding.dimensions == dimensions,
            "embedding plugin '{plugin_name}' serves {} dimensions; configuration requested {}",
            embedding.dimensions,
            dimensions
        );
        let identity = zeroclaw_plugins::host::embedding_provider_identity(manifest)?;
        let provider = supervisor().acquire(plugin_name, &identity, || {
            zeroclaw_plugins::host::verify_embedding_provider_payload(plugin_dir, embedding)?;
            ManagedEmbeddingProvider::launch(
                plugin_dir,
                &executable,
                &embedding.args,
                model,
                dimensions,
                self.startup_timeout,
            )
            .with_context(|| format!("failed to start embedding-provider plugin '{plugin_name}'"))
        })?;
        Ok((provider, identity))
    }
}

impl EmbeddingProviderFactory for PluginEmbeddingFactory {
    fn create(
        &self,
        model_provider: &str,
        _api_key: Option<&str>,
        model: &str,
        dimensions: usize,
    ) -> anyhow::Result<Option<ResolvedEmbeddingProvider>> {
        let Some(plugin_name) =
            model_provider.strip_prefix(zeroclaw_api::embedding::MANAGED_EMBEDDING_PROVIDER_PREFIX)
        else {
            return Ok(None);
        };
        let (managed, identity_provider) = self.resolve(plugin_name, model, dimensions)?;
        let provider: Arc<dyn EmbeddingProvider> = managed;
        Ok(Some(ResolvedEmbeddingProvider {
            provider,
            identity_provider,
        }))
    }
}

#[derive(Deserialize)]
struct ReadinessRecord {
    protocol_version: u32,
    base_url: String,
    model: String,
    dimensions: usize,
}

#[derive(Deserialize)]
struct EmbeddingsResponse {
    data: Vec<EmbeddingItem>,
}

#[derive(Deserialize)]
struct EmbeddingItem {
    index: usize,
    embedding: Vec<f32>,
}

/// One running child and its authenticated loopback client.
pub struct ManagedEmbeddingProvider {
    endpoint: reqwest::Url,
    token: String,
    model: String,
    dimensions: usize,
    client: reqwest::Client,
    request_slots: tokio::sync::Semaphore,
    child: Mutex<Option<ManagedChild>>,
}

struct ManagedChild {
    process: Child,
    control: Option<ChildStdin>,
}

impl ManagedEmbeddingProvider {
    fn launch(
        plugin_dir: &Path,
        executable: &Path,
        args: &[String],
        expected_model: &str,
        expected_dimensions: usize,
        startup_timeout: Duration,
    ) -> anyhow::Result<Self> {
        ensure!(executable.is_file(), "sidecar executable does not exist");
        let token = launch_token()?;
        let mut child = Command::new(executable)
            .args(args)
            .current_dir(plugin_dir)
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .with_context(|| format!("spawning {}", executable.display()))?;

        let startup_result = (|| -> anyhow::Result<(ReadinessRecord, reqwest::Url, ChildStdin)> {
            let mut stdin = child.stdin.take().context("sidecar stdin was not piped")?;
            writeln!(stdin, "{token}").context("sending sidecar launch token")?;
            stdin.flush().context("flushing sidecar launch token")?;

            let stdout = child
                .stdout
                .take()
                .context("sidecar stdout was not piped")?;
            let readiness = read_readiness(&mut child, stdout, startup_timeout)?;
            ensure!(
                readiness.protocol_version == READINESS_PROTOCOL_VERSION,
                "unsupported sidecar readiness protocol {}",
                readiness.protocol_version
            );
            ensure!(
                readiness.model == expected_model,
                "sidecar serves model {:?}; configuration requested {:?}",
                readiness.model,
                expected_model
            );
            ensure!(
                readiness.dimensions == expected_dimensions,
                "sidecar serves {} dimensions; configuration requested {}",
                readiness.dimensions,
                expected_dimensions
            );
            let endpoint = validate_loopback_endpoint(&readiness.base_url)?;
            if let Some(status) = child.try_wait().context("checking sidecar status")? {
                bail!("sidecar exited during startup with status {status}");
            }
            Ok((readiness, endpoint, stdin))
        })();

        let (readiness, endpoint, control) = match startup_result {
            Ok(ready) => ready,
            Err(error) => {
                terminate_child(&mut child);
                return Err(error);
            }
        };

        let client = match reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(3))
            .timeout(REQUEST_TIMEOUT)
            .build()
        {
            Ok(client) => client,
            Err(error) => {
                terminate_child(&mut child);
                return Err(error).context("building sidecar HTTP client");
            }
        };

        Ok(Self {
            endpoint,
            token,
            model: readiness.model,
            dimensions: readiness.dimensions,
            client,
            request_slots: tokio::sync::Semaphore::new(MAX_CONCURRENT_REQUESTS),
            child: Mutex::new(Some(ManagedChild {
                process: child,
                control: Some(control),
            })),
        })
    }

    pub fn base_url(&self) -> &str {
        self.endpoint.as_str()
    }

    pub fn child_id(&self) -> Option<u32> {
        self.child.lock().as_ref().map(|child| child.process.id())
    }

    /// Stop and reap the child. Calling this more than once is harmless.
    pub fn shutdown(&self) {
        if let Some(mut child) = self.child.lock().take() {
            terminate_managed_child(&mut child);
        }
    }

    fn is_running(&self) -> bool {
        let mut managed = self.child.lock();
        let Some(child) = managed.as_mut() else {
            return false;
        };
        match child.process.try_wait() {
            Ok(None) => true,
            Ok(Some(_)) => {
                child.control.take();
                managed.take();
                false
            }
            Err(_) => {
                if let Some(mut child) = managed.take() {
                    terminate_managed_child(&mut child);
                }
                false
            }
        }
    }

    fn embeddings_url(&self) -> anyhow::Result<reqwest::Url> {
        self.endpoint
            .join("v1/embeddings")
            .context("building sidecar embeddings URL")
    }
}

#[async_trait]
impl EmbeddingProvider for ManagedEmbeddingProvider {
    fn name(&self) -> &str {
        "plugin-embedding-sidecar"
    }

    fn dimensions(&self) -> usize {
        self.dimensions
    }

    async fn embed(&self, texts: &[&str]) -> anyhow::Result<Vec<Vec<f32>>> {
        if texts.is_empty() {
            return Ok(Vec::new());
        }

        let _permit = self
            .request_slots
            .acquire()
            .await
            .context("embedding sidecar request limiter closed")?;
        let response = self
            .client
            .post(self.embeddings_url()?)
            .bearer_auth(&self.token)
            .json(&serde_json::json!({
                "model": self.model,
                "input": texts,
                "encoding_format": "float",
            }))
            .send()
            .await
            .context("calling embedding sidecar")?;
        let status = response.status();
        if !status.is_success() {
            let body = read_response_limited(response, MAX_ERROR_RESPONSE_BYTES)
                .await
                .unwrap_or_default();
            let body = String::from_utf8_lossy(&body);
            bail!("embedding sidecar returned {status}: {body}");
        }

        let max_response_bytes = embedding_response_limit(texts.len(), self.dimensions)?;
        let bytes = read_response_limited(response, max_response_bytes).await?;
        let body: EmbeddingsResponse =
            serde_json::from_slice(&bytes).context("decoding embedding sidecar response")?;
        ensure!(
            body.data.len() == texts.len(),
            "embedding sidecar returned {} vectors for {} inputs",
            body.data.len(),
            texts.len()
        );

        let mut vectors = Vec::with_capacity(body.data.len());
        for (expected_index, item) in body.data.into_iter().enumerate() {
            ensure!(
                item.index == expected_index,
                "embedding sidecar returned out-of-order index {} at position {}",
                item.index,
                expected_index
            );
            ensure!(
                item.embedding.len() == self.dimensions,
                "embedding sidecar returned vector width {}; expected {}",
                item.embedding.len(),
                self.dimensions
            );
            ensure!(
                item.embedding.iter().all(|value| value.is_finite()),
                "embedding sidecar returned a non-finite vector value"
            );
            vectors.push(item.embedding);
        }
        Ok(vectors)
    }
}

impl Drop for ManagedEmbeddingProvider {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.get_mut().take() {
            terminate_managed_child(&mut child);
        }
    }
}

fn embedding_response_limit(input_count: usize, dimensions: usize) -> anyhow::Result<usize> {
    input_count
        .checked_mul(dimensions)
        .and_then(|values| values.checked_mul(EMBEDDING_JSON_BYTES_PER_VALUE))
        .and_then(|bytes| bytes.checked_add(EMBEDDING_JSON_BASE_BYTES))
        .context("embedding response size limit overflow")
}

async fn read_response_limited(
    response: reqwest::Response,
    limit: usize,
) -> anyhow::Result<Vec<u8>> {
    if let Some(length) = response.content_length() {
        ensure!(
            length <= limit as u64,
            "embedding sidecar response exceeds {limit} bytes"
        );
    }
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.context("reading embedding sidecar response")?;
        ensure!(
            body.len().saturating_add(chunk.len()) <= limit,
            "embedding sidecar response exceeds {limit} bytes"
        );
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn launch_token() -> anyhow::Result<String> {
    let mut bytes = [0_u8; LAUNCH_TOKEN_BYTES];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| anyhow::Error::msg("operating system random generator failed"))?;
    let mut token = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut token, "{byte:02x}")
            .map_err(|_| anyhow::Error::msg("formatting launch token failed"))?;
    }
    Ok(token)
}

fn read_readiness(
    child: &mut Child,
    stdout: impl std::io::Read + Send + 'static,
    timeout: Duration,
) -> anyhow::Result<ReadinessRecord> {
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    let reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let mut limited = BufReader::new(stdout).take(MAX_READINESS_BYTES + 1);
        let result = limited
            .read_until(b'\n', &mut bytes)
            .context("reading sidecar readiness")
            .and_then(|_| {
                ensure!(!bytes.is_empty(), "sidecar closed stdout before readiness");
                ensure!(
                    bytes.len() <= MAX_READINESS_BYTES as usize,
                    "sidecar readiness record exceeds {MAX_READINESS_BYTES} bytes"
                );
                ensure!(
                    bytes.ends_with(b"\n"),
                    "sidecar readiness is not newline terminated"
                );
                serde_json::from_slice::<ReadinessRecord>(&bytes)
                    .context("decoding sidecar readiness JSON")
            });
        let _ = tx.send(result);
    });

    let result = match rx.recv_timeout(timeout) {
        Ok(result) => result,
        Err(error) => {
            terminate_child(child);
            reader
                .join()
                .map_err(|_| anyhow::Error::msg("sidecar readiness reader panicked"))?;
            return Err(match error {
                std::sync::mpsc::RecvTimeoutError::Timeout => {
                    anyhow::Error::msg("timed out waiting for sidecar readiness")
                }
                std::sync::mpsc::RecvTimeoutError::Disconnected => {
                    anyhow::Error::msg("sidecar readiness reader stopped unexpectedly")
                }
            });
        }
    };
    reader
        .join()
        .map_err(|_| anyhow::Error::msg("sidecar readiness reader panicked"))?;
    result
}

fn validate_loopback_endpoint(raw: &str) -> anyhow::Result<reqwest::Url> {
    let url = reqwest::Url::parse(raw).context("parsing sidecar base URL")?;
    ensure!(url.scheme() == "http", "sidecar base URL must use http");
    ensure!(
        url.host_str() == Some("127.0.0.1"),
        "sidecar base URL must use 127.0.0.1"
    );
    ensure!(url.port().is_some(), "sidecar base URL must include a port");
    ensure!(
        url.username().is_empty(),
        "sidecar base URL must not include a username"
    );
    ensure!(
        url.password().is_none(),
        "sidecar base URL must not include a password"
    );
    ensure!(
        matches!(url.path(), "" | "/"),
        "sidecar base URL must not include a path"
    );
    ensure!(
        url.query().is_none(),
        "sidecar base URL must not include a query"
    );
    ensure!(
        url.fragment().is_none(),
        "sidecar base URL must not include a fragment"
    );
    Ok(url)
}

fn terminate_child(child: &mut Child) {
    match child.try_wait() {
        Ok(Some(_)) => {}
        Ok(None) | Err(_) => {
            let _ = child.kill();
        }
    }
    let _ = child.wait();
}

fn terminate_managed_child(child: &mut ManagedChild) {
    child.control.take();
    for _ in 0..20 {
        match child.process.try_wait() {
            Ok(Some(_)) => {
                let _ = child.process.wait();
                return;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(50)),
            Err(_) => break,
        }
    }
    terminate_child(&mut child.process);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn launch_tokens_are_256_bit_lowercase_hex() {
        let token = launch_token().unwrap();
        assert_eq!(token.len(), 64);
        assert!(
            token
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        );
    }

    #[test]
    fn readiness_endpoint_accepts_literal_loopback_http_only() {
        assert!(validate_loopback_endpoint("http://127.0.0.1:49152/").is_ok());

        for invalid in [
            "http://[::1]:49152/",
            "https://127.0.0.1:49152/",
            "http://localhost:49152/",
            "http://0.0.0.0:49152/",
            "http://127.0.0.1/",
            "http://user@127.0.0.1:49152/",
            "http://127.0.0.1:49152/path",
            "http://127.0.0.1:49152/?query=yes",
            "http://127.0.0.1:49152/#fragment",
        ] {
            assert!(
                validate_loopback_endpoint(invalid).is_err(),
                "unexpectedly accepted {invalid}"
            );
        }
    }

    #[test]
    fn response_limit_tracks_expected_vector_shape() {
        assert_eq!(
            embedding_response_limit(2, 64).unwrap(),
            EMBEDDING_JSON_BASE_BYTES + 2 * 64 * EMBEDDING_JSON_BYTES_PER_VALUE
        );
        assert!(embedding_response_limit(usize::MAX, 2).is_err());
    }
}
