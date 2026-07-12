pub use zeroclaw_memory::*;

/// Build the configured memory backend through the optional managed-plugin
/// composition layer. The plugin transport remains an implementation detail;
/// canonical selection still comes from `[memory]`.
pub fn create_configured_memory(
    config: &crate::config::schema::Config,
    workspace_dir: &std::path::Path,
    api_key: Option<&str>,
) -> anyhow::Result<Box<dyn zeroclaw_api::memory_traits::Memory>> {
    #[cfg(feature = "plugins-wasm")]
    {
        zeroclaw_embedding_sidecar::create_memory(config, workspace_dir, api_key)
    }

    #[cfg(not(feature = "plugins-wasm"))]
    {
        zeroclaw_memory::create_memory_with_storage_and_routes(
            &config.memory,
            &config.embedding_routes,
            config.resolve_active_storage(),
            workspace_dir,
            api_key,
            Some(&config.providers.models),
        )
    }
}

// These stay in root (depend on root crate types).
pub mod cli;

#[cfg(test)]
mod battle_tests;

// Re-declare traits as a file module so its #[cfg(test)] block compiles.
#[path = "traits.rs"]
pub mod traits;
