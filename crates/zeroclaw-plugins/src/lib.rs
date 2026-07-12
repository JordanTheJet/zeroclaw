//! WASM plugin system for ZeroClaw.
//!
//! Plugins are WebAssembly components loaded via wasmtime that can extend
//! ZeroClaw with custom tools and channels. Enable with a `plugins-wasm*` feature.

#[cfg(feature = "plugins-wasmtime")]
pub mod component;
#[cfg(feature = "plugins-wasmtime")]
mod component_logging;
pub mod error;
pub mod host;
pub mod registry;
#[cfg(feature = "plugins-wasmtime")]
pub mod runtime;
pub mod signature;
#[cfg(feature = "plugins-wasmtime")]
pub mod wasm_channel;
#[cfg(feature = "plugins-wasmtime")]
pub mod wasm_memory;
#[cfg(feature = "plugins-wasmtime")]
pub mod wasm_tool;

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// A plugin's declared manifest (loaded from manifest.toml alongside the .wasm).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginManifest {
    /// Plugin name (unique identifier)
    pub name: String,
    /// Plugin version
    pub version: String,
    /// Human-readable description
    pub description: Option<String>,
    /// Author name or organization
    pub author: Option<String>,
    /// Path to the .wasm file (relative to manifest).
    /// Required for tool/channel/memory/observer plugins; optional (and ignored)
    /// for skill-only plugins, which carry no WASM payload.
    #[serde(default)]
    pub wasm_path: Option<String>,
    /// Native embedding sidecar entrypoint and bundle artifacts. This table is
    /// the sole declaration; the embedding capability is derived from it.
    #[serde(default)]
    pub embedding_provider: Option<EmbeddingProviderManifest>,
    /// Capabilities this plugin provides
    pub capabilities: Vec<PluginCapability>,
    /// Permissions this plugin requests
    #[serde(default)]
    pub permissions: Vec<PluginPermission>,
    /// Ed25519 signature over the canonical manifest (base64url-encoded).
    /// Set by the plugin publisher when signing the manifest.
    #[serde(default)]
    pub signature: Option<String>,
    /// Hex-encoded Ed25519 public key of the publisher who signed this manifest.
    #[serde(default)]
    pub publisher_key: Option<String>,
}

/// What a plugin can do.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PluginCapability {
    /// Provides one or more tools
    Tool,
    /// Provides a channel implementation
    Channel,
    /// Provides a memory backend
    Memory,
    /// Provides an observer/metrics backend
    Observer,
    /// Provides one or more agentskills.io-format skills under `skills/`
    Skill,
    /// Provides an OpenAI-compatible embedding sidecar supervised by the host
    EmbeddingProvider,
}

/// Files that make up a host-supervised embedding provider bundle.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EmbeddingProviderManifest {
    /// Model identifier served by this bundle.
    pub model: String,
    /// Vector width served by this bundle.
    pub dimensions: usize,
    /// Native executable and its signed content digest.
    pub executable: EmbeddingArtifactManifest,
    /// Literal arguments passed directly to the executable (never through a shell).
    #[serde(default)]
    pub args: Vec<String>,
    /// Additional signed files or directory trees required by the executable.
    #[serde(default)]
    pub artifacts: Vec<EmbeddingArtifactManifest>,
}

/// One content-bound path inside a native plugin bundle.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EmbeddingArtifactManifest {
    pub path: String,
    /// Lowercase SHA-256 of the file or canonical directory tree.
    pub sha256: String,
}

/// Permissions a plugin may request.
#[derive(Debug, Clone, Hash, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PluginPermission {
    /// Can make HTTP requests
    HttpClient,
    /// Can read from the filesystem (within sandbox)
    FileRead,
    /// Can write to the filesystem (within sandbox)
    FileWrite,
    /// Can read its own resolved per-plugin config section
    #[serde(alias = "env_read")]
    ConfigRead,
    /// Can read agent memory
    MemoryRead,
    /// Can write agent memory
    MemoryWrite,
}

/// Information about a loaded plugin.
#[derive(Debug, Clone, Serialize)]
pub struct PluginInfo {
    pub name: String,
    pub version: String,
    pub description: Option<String>,
    pub capabilities: Vec<PluginCapability>,
    pub permissions: Vec<PluginPermission>,
    /// Resolved path to the WASM file. `None` for skill-only and native
    /// embedding-provider plugins.
    pub wasm_path: Option<PathBuf>,
    pub loaded: bool,
}
