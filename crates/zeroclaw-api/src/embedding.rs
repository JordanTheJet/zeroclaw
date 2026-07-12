//! Embedding provider boundary shared by memory implementations and plugins.

use async_trait::async_trait;
use std::sync::Arc;

pub const MANAGED_EMBEDDING_PROVIDER_PREFIX: &str = "plugin:";

/// Converts text into vectors in a single embedding space.
#[async_trait]
pub trait EmbeddingProvider: Send + Sync {
    /// Stable implementation name for diagnostics.
    fn name(&self) -> &str;

    /// Width of every vector returned by this provider.
    fn dimensions(&self) -> usize;

    /// Embed a batch of texts, preserving input order.
    async fn embed(&self, texts: &[&str]) -> anyhow::Result<Vec<Vec<f32>>>;

    /// Embed one text.
    async fn embed_one(&self, text: &str) -> anyhow::Result<Vec<f32>> {
        let mut results = self.embed(&[text]).await?;
        results
            .pop()
            .ok_or_else(|| anyhow::Error::msg("Empty embedding result"))
    }
}

/// Provider implementation plus the verified, transport-independent identity
/// that memory should persist for vector compatibility checks.
pub struct ResolvedEmbeddingProvider {
    pub provider: Arc<dyn EmbeddingProvider>,
    pub identity_provider: String,
}

/// Optional composition hook for embedding implementations supplied outside
/// `zeroclaw-memory`, such as a host-supervised plugin sidecar.
///
/// Returning `Ok(None)` leaves resolution to the built-in memory factory.
pub trait EmbeddingProviderFactory: Send + Sync {
    fn create(
        &self,
        model_provider: &str,
        api_key: Option<&str>,
        model: &str,
        dimensions: usize,
    ) -> anyhow::Result<Option<ResolvedEmbeddingProvider>>;
}
