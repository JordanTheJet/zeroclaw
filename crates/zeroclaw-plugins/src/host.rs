//! Plugin host: discovery, loading, lifecycle management.

use super::error::PluginError;
use super::signature::{self, SignatureMode, VerificationResult};
use super::{EmbeddingProviderManifest, PluginCapability, PluginInfo, PluginManifest};
use ring::digest::{Context as DigestContext, SHA256};
use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Subdirectory inside a skill-capable plugin that holds individual skills.
const SKILLS_SUBDIR: &str = "skills";

/// Manages the lifecycle of WASM plugins.
pub struct PluginHost {
    plugins_dir: PathBuf,
    loaded: HashMap<String, LoadedPlugin>,
    signature_mode: SignatureMode,
    trusted_publisher_keys: Vec<String>,
}

struct LoadedPlugin {
    manifest: PluginManifest,
    plugin_dir: PathBuf,
    /// Resolved path to the WASM file. `None` for skill-only plugins.
    wasm_path: Option<PathBuf>,
    #[allow(dead_code)]
    verification: VerificationResult,
}

impl PluginHost {
    /// Create a new plugin host rooted at `workspace_dir`, scanning its
    /// `plugins/` subdirectory.
    pub fn new(workspace_dir: &Path) -> Result<Self, PluginError> {
        Self::with_security(workspace_dir, SignatureMode::Disabled, Vec::new())
    }

    /// Create a host rooted at `workspace_dir` (scanning `workspace_dir/plugins`)
    /// with signature verification settings.
    pub fn with_security(
        workspace_dir: &Path,
        signature_mode: SignatureMode,
        trusted_publisher_keys: Vec<String>,
    ) -> Result<Self, PluginError> {
        Self::from_plugins_dir_with_security(
            &workspace_dir.join("plugins"),
            signature_mode,
            trusted_publisher_keys,
        )
    }

    /// Create a host that scans `plugins_dir` directly (no `plugins/` suffix is
    /// appended). Use this when the caller already holds the fully resolved
    /// plugin directory, e.g. `PluginsConfig::resolved_plugins_dir()`.
    pub fn from_plugins_dir(plugins_dir: &Path) -> Result<Self, PluginError> {
        Self::from_plugins_dir_with_security(plugins_dir, SignatureMode::Disabled, Vec::new())
    }

    /// [`Self::from_plugins_dir`] with signature verification settings.
    pub fn from_plugins_dir_with_security(
        plugins_dir: &Path,
        signature_mode: SignatureMode,
        trusted_publisher_keys: Vec<String>,
    ) -> Result<Self, PluginError> {
        if !plugins_dir.exists() {
            std::fs::create_dir_all(plugins_dir)?;
        }

        let mut host = Self {
            plugins_dir: plugins_dir.to_path_buf(),
            loaded: HashMap::new(),
            signature_mode,
            trusted_publisher_keys,
        };

        host.discover()?;
        Ok(host)
    }

    /// Parse the signature mode string from config into a `SignatureMode`.
    /// Parse a `[plugins.security] signature_mode` config string into a
    /// [`SignatureMode`]. Returns `None` for any unrecognized value so the
    /// caller can surface the misconfiguration under its attribution span
    /// instead of silently degrading to the weakest posture. Case-insensitive.
    pub fn parse_signature_mode(mode: &str) -> Option<SignatureMode> {
        match mode.to_lowercase().as_str() {
            "strict" => Some(SignatureMode::Strict),
            "permissive" => Some(SignatureMode::Permissive),
            "disabled" => Some(SignatureMode::Disabled),
            _ => None,
        }
    }

    /// Resolve a `[plugins.security] signature_mode` config string into a
    /// [`SignatureMode`], failing safe to [`SignatureMode::Strict`] on any
    /// unrecognized value. The misconfiguration WARN is emitted under a
    /// plugin-role attribution span so the record carries role context even
    /// from context-free config call sites.
    #[must_use]
    pub fn resolve_signature_mode(mode: &str) -> SignatureMode {
        Self::parse_signature_mode(mode).unwrap_or_else(|| {
            let span = ::zeroclaw_log::__private::tracing::info_span!(
                target: "zeroclaw_log_internal_attribution",
                "zeroclaw_attribution",
                zc_role_family = %::zeroclaw_api::attribution::Role::System.family_str(),
                zc_role_type = "",
                zc_attribution_field = %::zeroclaw_api::attribution::Role::System
                    .attribution_field()
                    .unwrap_or(""),
                zc_composite_prefix = "",
                zc_default_category = %::zeroclaw_api::attribution::Role::System.default_category(),
                zc_alias = "plugins",
            );
            span.in_scope(|| {
                ::zeroclaw_log::record!(
                    WARN,
                    ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Note)
                        .with_outcome(::zeroclaw_log::EventOutcome::Failure)
                        .with_attrs(::serde_json::json!({ "signature_mode": mode })),
                    "Unrecognized plugins.security.signature_mode; failing safe to strict"
                );
            });
            SignatureMode::Strict
        })
    }

    /// Discover plugins in the plugins directory.
    fn discover(&mut self) -> Result<(), PluginError> {
        if !self.plugins_dir.exists() {
            return Ok(());
        }

        let entries = std::fs::read_dir(&self.plugins_dir)?;
        for entry in entries.flatten() {
            let path = entry.path();
            if entry.file_type().is_ok_and(|file_type| file_type.is_dir()) {
                let manifest_path = path.join("manifest.toml");
                if manifest_path.exists()
                    && let Ok((manifest_toml, manifest)) = read_manifest(&manifest_path)
                {
                    let directory_name = entry.file_name();
                    if checked_plugin_name(&manifest.name).is_err()
                        || directory_name.to_str() != Some(manifest.name.as_str())
                    {
                        ::zeroclaw_log::record!(
                            WARN,
                            ::zeroclaw_log::Event::new(
                                module_path!(),
                                ::zeroclaw_log::Action::Note
                            )
                            .with_outcome(::zeroclaw_log::EventOutcome::Unknown)
                            .with_attrs(
                                ::serde_json::json!({"plugin": path.display().to_string()})
                            ),
                            "skipping plugin whose manifest name does not match its safe directory name"
                        );
                        continue;
                    }
                    if let Err(e) = validate_manifest_shape(&manifest, &path) {
                        ::zeroclaw_log::record!(WARN, ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Note).with_outcome(::zeroclaw_log::EventOutcome::Unknown).with_attrs(::serde_json::json!({"plugin": path.display().to_string(), "error": format!("{}", e)})), "skipping plugin due to invalid manifest shape");
                        continue;
                    }

                    // Verify plugin signature
                    match self.verify_plugin_signature(&manifest.name, &manifest_toml, &manifest) {
                        Ok(verification) => {
                            if let Some(embedding) = manifest.embedding_provider.as_ref()
                                && let Err(e) = verify_embedding_provider_payload(&path, embedding)
                            {
                                ::zeroclaw_log::record!(WARN, ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Note).with_outcome(::zeroclaw_log::EventOutcome::Unknown).with_attrs(::serde_json::json!({"plugin": path.display().to_string(), "error": format!("{}", e)})), "skipping plugin due to embedding payload verification failure");
                                continue;
                            }
                            let wasm_path = manifest.wasm_path.as_deref().map(|p| path.join(p));
                            self.loaded.insert(
                                manifest.name.clone(),
                                LoadedPlugin {
                                    manifest,
                                    plugin_dir: path.clone(),
                                    wasm_path,
                                    verification,
                                },
                            );
                        }
                        Err(e) => {
                            ::zeroclaw_log::record!(WARN, ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Note).with_outcome(::zeroclaw_log::EventOutcome::Unknown).with_attrs(::serde_json::json!({"plugin": path.display().to_string(), "error": format!("{}", e)})), "skipping plugin due to signature verification failure");
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Verify a plugin's signature against configured policy.
    fn verify_plugin_signature(
        &self,
        name: &str,
        manifest_toml: &str,
        manifest: &PluginManifest,
    ) -> Result<VerificationResult, PluginError> {
        signature::enforce_signature_policy(
            name,
            manifest_toml,
            manifest.signature.as_deref(),
            manifest.publisher_key.as_deref(),
            &self.trusted_publisher_keys,
            self.signature_mode,
        )
    }

    /// List all discovered plugins.
    pub fn list_plugins(&self) -> Vec<PluginInfo> {
        self.loaded.values().map(plugin_info_from_loaded).collect()
    }

    /// Get info about a specific plugin.
    pub fn get_plugin(&self, name: &str) -> Option<PluginInfo> {
        self.loaded.get(name).map(plugin_info_from_loaded)
    }

    /// Install a plugin from a directory path. Returns the installed
    /// plugin's manifest name so callers can key follow-up work (config
    /// seeding, messaging) off the canonical name rather than the source path.
    pub fn install(&mut self, source: &str) -> Result<String, PluginError> {
        let source_path = PathBuf::from(source);
        let manifest_path = if source_path.is_dir() {
            source_path.join("manifest.toml")
        } else {
            source_path.clone()
        };

        if !manifest_path.exists() {
            return Err(PluginError::NotFound(format!(
                "manifest.toml not found at {}",
                manifest_path.display()
            )));
        }

        let (manifest_toml, manifest) = read_manifest(&manifest_path)?;
        checked_plugin_name(&manifest.name)?;
        let source_dir = manifest_path
            .parent()
            .ok_or_else(|| PluginError::InvalidManifest("no parent directory".into()))?;

        validate_manifest_shape(&manifest, source_dir)?;

        let wasm_relative = manifest
            .wasm_path
            .as_deref()
            .map(checked_relative_path)
            .transpose()?;
        let wasm_source = wasm_relative.as_ref().map(|path| source_dir.join(path));
        if let Some(relative) = wasm_relative.as_ref() {
            let metadata = metadata_without_symlinked_components(source_dir, relative)?;
            if !metadata.file_type().is_file() {
                return Err(PluginError::InvalidManifest(format!(
                    "WASM payload is not a regular file: {}",
                    source_dir.join(relative).display()
                )));
            }
        }

        let embedding_entries = manifest
            .embedding_provider
            .as_ref()
            .map(|embedding| embedding_bundle_entries(source_dir, embedding))
            .transpose()?
            .unwrap_or_default();
        for (_, source, _) in &embedding_entries {
            if !source.exists() {
                return Err(PluginError::NotFound(format!(
                    "embedding-provider bundle entry not found: {}",
                    source.display()
                )));
            }
        }

        let dest_dir = self.plugins_dir.join(&manifest.name);
        if self.loaded.contains_key(&manifest.name) || dest_dir.exists() {
            return Err(PluginError::AlreadyLoaded(manifest.name));
        }

        // Verify plugin signature before installing
        let verification =
            self.verify_plugin_signature(&manifest.name, &manifest_toml, &manifest)?;
        if let Some(embedding) = manifest.embedding_provider.as_ref() {
            verify_embedding_provider_payload(source_dir, embedding)?;
        }

        // Assemble the complete bundle in a hidden sibling directory. The
        // final same-filesystem rename publishes only fully verified bytes.
        let staging_dir = create_install_staging_dir(&self.plugins_dir, &manifest.name)?;
        let staged_wasm_relative = wasm_relative;
        let stage_result = (|| -> Result<(), PluginError> {
            std::fs::write(staging_dir.join("manifest.toml"), &manifest_toml)?;

            if let (Some(rel), Some(src)) = (staged_wasm_relative.as_deref(), wasm_source.as_ref())
            {
                let dest = staging_dir.join(rel);
                if let Some(parent) = dest.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                std::fs::copy(src, dest)?;
            }

            if manifest.capabilities.contains(&PluginCapability::Skill) {
                let src_skills = source_dir.join(SKILLS_SUBDIR);
                let dest_skills = staging_dir.join(SKILLS_SUBDIR);
                if src_skills.is_dir() {
                    copy_dir_recursive(&src_skills, &dest_skills)?;
                }
            }

            for (relative, source, _) in &embedding_entries {
                copy_bundle_entry(source, &staging_dir.join(relative))?;
            }
            if let Some(embedding) = manifest.embedding_provider.as_ref() {
                verify_embedding_provider_payload(&staging_dir, embedding)?;
            }
            Ok(())
        })();
        if let Err(error) = stage_result {
            let _ = std::fs::remove_dir_all(&staging_dir);
            return Err(error);
        }
        if dest_dir.exists() {
            let _ = std::fs::remove_dir_all(&staging_dir);
            return Err(PluginError::AlreadyLoaded(manifest.name));
        }
        if let Err(error) = std::fs::rename(&staging_dir, &dest_dir) {
            let _ = std::fs::remove_dir_all(&staging_dir);
            return Err(error.into());
        }
        let wasm_dest = staged_wasm_relative.map(|relative| dest_dir.join(relative));

        let installed_name = manifest.name.clone();
        self.loaded.insert(
            manifest.name.clone(),
            LoadedPlugin {
                manifest,
                plugin_dir: dest_dir,
                wasm_path: wasm_dest,
                verification,
            },
        );

        Ok(installed_name)
    }

    /// Remove a plugin by name.
    pub fn remove(&mut self, name: &str) -> Result<(), PluginError> {
        checked_plugin_name(name)?;
        if self.loaded.remove(name).is_none() {
            return Err(PluginError::NotFound(name.to_string()));
        }

        let plugin_dir = self.plugins_dir.join(name);
        if plugin_dir.exists() {
            std::fs::remove_dir_all(plugin_dir)?;
        }

        Ok(())
    }

    /// Get tool-capable plugins.
    pub fn tool_plugins(&self) -> Vec<&PluginManifest> {
        self.loaded
            .values()
            .filter(|p| p.manifest.capabilities.contains(&PluginCapability::Tool))
            .map(|p| &p.manifest)
            .collect()
    }

    /// Get tool-capable plugins with their resolved WASM file paths.
    /// Returns `(manifest, resolved_wasm_path)` tuples for building `WasmTool`s.
    /// Tool plugins without a `wasm_path` are skipped.
    pub fn tool_plugin_details(&self) -> Vec<(&PluginManifest, &Path)> {
        self.loaded
            .values()
            .filter(|p| p.manifest.capabilities.contains(&PluginCapability::Tool))
            .filter_map(|p| p.wasm_path.as_deref().map(|wp| (&p.manifest, wp)))
            .collect()
    }

    /// Get channel-capable plugins.
    pub fn channel_plugins(&self) -> Vec<&PluginManifest> {
        self.loaded
            .values()
            .filter(|p| p.manifest.capabilities.contains(&PluginCapability::Channel))
            .map(|p| &p.manifest)
            .collect()
    }

    /// Get channel-capable plugins with their resolved WASM file paths.
    /// Returns `(manifest, resolved_wasm_path)` tuples for building
    /// `WasmChannel`s, mirroring [`Self::tool_plugin_details`]. Channel plugins
    /// without a `wasm_path` are skipped, so a manifest that declares the
    /// capability but ships no component is never registered as a live channel.
    pub fn channel_plugin_details(&self) -> Vec<(&PluginManifest, &Path)> {
        self.loaded
            .values()
            .filter(|p| p.manifest.capabilities.contains(&PluginCapability::Channel))
            .filter_map(|p| p.wasm_path.as_deref().map(|wp| (&p.manifest, wp)))
            .collect()
    }

    /// Get skill-capable plugins.
    pub fn skill_plugins(&self) -> Vec<&PluginManifest> {
        self.loaded
            .values()
            .filter(|p| p.manifest.capabilities.contains(&PluginCapability::Skill))
            .map(|p| &p.manifest)
            .collect()
    }

    /// Get skill-capable plugins paired with the absolute path to their `skills/`
    /// directory. Plugins without an existing `skills/` subdirectory are skipped.
    ///
    /// Callers (typically the runtime skill loader) should pass each `skills_dir`
    /// to `load_skills_from_directory` and then re-namespace the resulting skill
    /// names as `plugin:<plugin>/<skill>` to avoid collisions with user skills.
    pub fn skill_plugin_details(&self) -> Vec<(&PluginManifest, PathBuf)> {
        self.loaded
            .values()
            .filter(|p| p.manifest.capabilities.contains(&PluginCapability::Skill))
            .filter_map(|p| {
                let skills_dir = p.plugin_dir.join(SKILLS_SUBDIR);
                if skills_dir.is_dir() {
                    Some((&p.manifest, skills_dir))
                } else {
                    None
                }
            })
            .collect()
    }

    /// Resolve one installed embedding-provider plugin on demand. The
    /// executable path is derived from the manifest and plugin root rather
    /// than stored as a second copy of manifest state.
    pub fn embedding_provider_details(
        &self,
        name: &str,
    ) -> Option<(&PluginManifest, &Path, PathBuf)> {
        let loaded = self.loaded.get(name)?;
        let embedding = loaded.manifest.embedding_provider.as_ref()?;
        let executable = checked_relative_path(&embedding.executable.path).ok()?;
        Some((
            &loaded.manifest,
            &loaded.plugin_dir,
            loaded.plugin_dir.join(executable),
        ))
    }

    /// Returns the plugins directory path.
    pub fn plugins_dir(&self) -> &Path {
        &self.plugins_dir
    }
}

fn plugin_info_from_loaded(p: &LoadedPlugin) -> PluginInfo {
    let loaded = match &p.wasm_path {
        Some(path) => path.exists(),
        None if p.manifest.embedding_provider.is_some() => p
            .manifest
            .embedding_provider
            .as_ref()
            .and_then(|embedding| checked_relative_path(&embedding.executable.path).ok())
            .is_some_and(|path| p.plugin_dir.join(path).is_file()),
        // Skill-only plugins are "loaded" if their skills/ subtree exists.
        None => p.plugin_dir.join(SKILLS_SUBDIR).is_dir(),
    };
    let mut capabilities = p.manifest.capabilities.clone();
    if p.manifest.embedding_provider.is_some() {
        capabilities.push(PluginCapability::EmbeddingProvider);
    }
    PluginInfo {
        name: p.manifest.name.clone(),
        version: p.manifest.version.clone(),
        description: p.manifest.description.clone(),
        capabilities,
        permissions: p.manifest.permissions.clone(),
        wasm_path: p.wasm_path.clone(),
        loaded,
    }
}

fn read_manifest(path: &Path) -> Result<(String, PluginManifest), PluginError> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(PluginError::InvalidManifest(format!(
            "plugin manifest must be a regular file: {}",
            path.display()
        )));
    }
    let content = std::fs::read_to_string(path)?;
    let manifest = toml::from_str(&content)?;
    Ok((content, manifest))
}

/// Validate manifest shape: `wasm_path` is required for WASM-backed
/// capabilities. The `[embedding_provider]` table is the single declaration
/// of a native embedding bundle; `EmbeddingProvider` is derived for display
/// and must not also appear in the manifest's capability list.
fn validate_manifest_shape(
    manifest: &PluginManifest,
    plugin_dir: &Path,
) -> Result<(), PluginError> {
    if manifest.capabilities.is_empty() && manifest.embedding_provider.is_none() {
        return Err(PluginError::InvalidManifest(format!(
            "plugin '{}' declares no capabilities",
            manifest.name
        )));
    }

    if manifest
        .capabilities
        .contains(&PluginCapability::EmbeddingProvider)
    {
        return Err(PluginError::InvalidManifest(format!(
            "plugin '{}' must declare native embedding support only through `[embedding_provider]`",
            manifest.name
        )));
    }

    let needs_wasm = manifest
        .capabilities
        .iter()
        .any(|capability| !matches!(capability, PluginCapability::Skill));

    if needs_wasm && manifest.wasm_path.is_none() {
        return Err(PluginError::InvalidManifest(format!(
            "plugin '{}' is missing required `wasm_path` for WASM-backed capabilities",
            manifest.name
        )));
    }

    if let Some(wasm_path) = manifest.wasm_path.as_deref() {
        checked_relative_path(wasm_path)?;
    }

    if let Some(embedding) = manifest.embedding_provider.as_ref() {
        validate_embedding_provider_bundle(embedding, plugin_dir)?;
    }

    if manifest.capabilities.contains(&PluginCapability::Skill) {
        validate_skill_bundle(&manifest.name, plugin_dir)?;
    }

    Ok(())
}

fn validate_embedding_provider_bundle(
    embedding: &EmbeddingProviderManifest,
    plugin_dir: &Path,
) -> Result<(), PluginError> {
    if embedding.model.trim().is_empty() {
        return Err(PluginError::InvalidManifest(
            "embedding-provider model must not be empty".to_string(),
        ));
    }
    if embedding.dimensions == 0 {
        return Err(PluginError::InvalidManifest(
            "embedding-provider dimensions must be greater than zero".to_string(),
        ));
    }
    let entries = embedding_bundle_entries(plugin_dir, embedding)?;
    let executable = entries.first().ok_or_else(|| {
        PluginError::InvalidManifest("embedding provider has no executable".to_string())
    })?;
    let executable_metadata = metadata_without_symlinked_components(plugin_dir, &executable.0)?;
    if !executable_metadata.file_type().is_file() {
        return Err(PluginError::InvalidManifest(format!(
            "embedding-provider executable is not a regular file: {}",
            executable.1.display()
        )));
    }
    for (relative, entry, _) in entries.iter().skip(1) {
        let metadata = metadata_without_symlinked_components(plugin_dir, relative)?;
        if !metadata.file_type().is_file() && !metadata.file_type().is_dir() {
            return Err(PluginError::InvalidManifest(format!(
                "embedding-provider artifact is not a regular file or directory: {}",
                entry.display()
            )));
        }
    }
    Ok(())
}

fn embedding_bundle_entries(
    root: &Path,
    embedding: &EmbeddingProviderManifest,
) -> Result<Vec<(PathBuf, PathBuf, String)>, PluginError> {
    let mut entries = Vec::with_capacity(1 + embedding.artifacts.len());
    let mut seen = HashSet::with_capacity(1 + embedding.artifacts.len());
    let executable = checked_relative_path(&embedding.executable.path)?;
    validate_embedding_bundle_path(&executable)?;
    validate_sha256(&embedding.executable.sha256)?;
    seen.insert(executable.clone());
    entries.push((
        executable.clone(),
        root.join(&executable),
        embedding.executable.sha256.clone(),
    ));
    for artifact in &embedding.artifacts {
        let relative = checked_relative_path(&artifact.path)?;
        validate_embedding_bundle_path(&relative)?;
        if !seen.insert(relative.clone()) {
            return Err(PluginError::InvalidManifest(format!(
                "embedding-provider bundle path is declared more than once: {}",
                relative.display()
            )));
        }
        validate_sha256(&artifact.sha256)?;
        entries.push((
            relative.clone(),
            root.join(&relative),
            artifact.sha256.clone(),
        ));
    }
    Ok(entries)
}

/// Recompute every declared native payload digest. Call immediately before
/// launch so a signed manifest cannot authorize replaced bytes.
pub fn verify_embedding_provider_payload(
    plugin_dir: &Path,
    embedding: &EmbeddingProviderManifest,
) -> Result<(), PluginError> {
    for (relative, source, expected) in embedding_bundle_entries(plugin_dir, embedding)? {
        metadata_without_symlinked_components(plugin_dir, &relative)?;
        let actual = sha256_bundle_path(&source)?;
        if actual != expected {
            return Err(PluginError::InvalidManifest(format!(
                "embedding-provider payload digest mismatch for {}",
                relative.display()
            )));
        }
    }
    Ok(())
}

/// Content-bound logical identity for vector compatibility. The ephemeral
/// listener and token never participate.
pub fn embedding_provider_identity(manifest: &PluginManifest) -> Result<String, PluginError> {
    let embedding = manifest.embedding_provider.as_ref().ok_or_else(|| {
        PluginError::InvalidManifest("plugin has no embedding provider".to_string())
    })?;
    let mut hasher = DigestContext::new(&SHA256);
    hasher.update(b"zeroclaw-embedding-bundle-identity-v1\0");
    hash_identity_field(&mut hasher, manifest.name.as_bytes());
    hash_identity_field(&mut hasher, manifest.version.as_bytes());
    hash_identity_field(&mut hasher, embedding.model.as_bytes());
    hash_identity_field(&mut hasher, &embedding.dimensions.to_be_bytes());
    hash_identity_field(&mut hasher, embedding.executable.path.as_bytes());
    hash_identity_field(&mut hasher, embedding.executable.sha256.as_bytes());
    for argument in &embedding.args {
        hash_identity_field(&mut hasher, argument.as_bytes());
    }
    for artifact in &embedding.artifacts {
        hash_identity_field(&mut hasher, artifact.path.as_bytes());
        hash_identity_field(&mut hasher, artifact.sha256.as_bytes());
    }
    Ok(format!(
        "{}{}@sha256:{}",
        zeroclaw_api::embedding::MANAGED_EMBEDDING_PROVIDER_PREFIX,
        manifest.name,
        hex_digest(hasher.finish().as_ref())
    ))
}

fn hash_identity_field(hasher: &mut DigestContext, value: &[u8]) {
    hasher.update(&(value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn validate_sha256(value: &str) -> Result<(), PluginError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(PluginError::InvalidManifest(
            "embedding-provider sha256 must be 64 lowercase hexadecimal characters".to_string(),
        ));
    }
    Ok(())
}

/// SHA-256 for one file, or for a deterministic directory tree made from
/// sorted relative UTF-8 paths and each file's SHA-256.
pub fn sha256_bundle_path(path: &Path) -> Result<String, PluginError> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Err(PluginError::InvalidManifest(format!(
            "embedding-provider payload must not be a symlink: {}",
            path.display()
        )));
    }
    if metadata.is_file() {
        return Ok(hex_digest(&sha256_file(path)?));
    }
    if !metadata.is_dir() {
        return Err(PluginError::InvalidManifest(format!(
            "embedding-provider payload is not a file or directory: {}",
            path.display()
        )));
    }

    let mut files = Vec::new();
    collect_tree_files(path, path, &mut files)?;
    files.sort_by(|left, right| left.0.cmp(&right.0));
    let mut hasher = DigestContext::new(&SHA256);
    hasher.update(b"zeroclaw-plugin-directory-v1\0");
    for (relative, file) in files {
        hash_identity_field(&mut hasher, relative.as_bytes());
        hasher.update(&sha256_file(&file)?);
    }
    Ok(hex_digest(hasher.finish().as_ref()))
}

fn collect_tree_files(
    root: &Path,
    directory: &Path,
    files: &mut Vec<(String, PathBuf)>,
) -> Result<(), PluginError> {
    for entry in std::fs::read_dir(directory)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let path = entry.path();
        if file_type.is_symlink() {
            return Err(PluginError::InvalidManifest(format!(
                "embedding-provider artifact tree contains a symlink: {}",
                path.display()
            )));
        }
        if file_type.is_dir() {
            collect_tree_files(root, &path, files)?;
        } else if file_type.is_file() {
            let relative = path
                .strip_prefix(root)
                .map_err(|_| PluginError::InvalidManifest("artifact escaped its root".to_string()))?
                .to_str()
                .ok_or_else(|| {
                    PluginError::InvalidManifest(
                        "embedding-provider artifact paths must be UTF-8".to_string(),
                    )
                })?
                .replace(std::path::MAIN_SEPARATOR, "/");
            files.push((relative, path));
        } else {
            return Err(PluginError::InvalidManifest(format!(
                "embedding-provider artifact tree contains a special file: {}",
                path.display()
            )));
        }
    }
    Ok(())
}

fn sha256_file(path: &Path) -> Result<[u8; 32], PluginError> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = DigestContext::new(&SHA256);
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    hasher
        .finish()
        .as_ref()
        .try_into()
        .map_err(|_| PluginError::InvalidManifest("invalid SHA-256 output length".to_string()))
}

fn hex_digest(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn checked_relative_path(raw: &str) -> Result<PathBuf, PluginError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(PluginError::InvalidManifest(
            "plugin payload paths must not be empty".to_string(),
        ));
    }
    let path = Path::new(trimmed);
    if path
        .components()
        .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(PluginError::InvalidManifest(format!(
            "plugin payload path must stay inside the plugin directory: {trimmed}"
        )));
    }
    Ok(path.to_path_buf())
}

fn validate_embedding_bundle_path(path: &Path) -> Result<(), PluginError> {
    if path == Path::new("manifest.toml") {
        return Err(PluginError::InvalidManifest(
            "embedding-provider bundle paths must not replace manifest.toml".to_string(),
        ));
    }
    Ok(())
}

fn metadata_without_symlinked_components(
    root: &Path,
    relative: &Path,
) -> Result<std::fs::Metadata, PluginError> {
    let root_metadata = std::fs::symlink_metadata(root)?;
    if root_metadata.file_type().is_symlink() || !root_metadata.file_type().is_dir() {
        return Err(PluginError::InvalidManifest(format!(
            "plugin bundle root must be a real directory: {}",
            root.display()
        )));
    }

    let mut current = root.to_path_buf();
    let mut final_metadata = root_metadata;
    for component in relative.components() {
        let Component::Normal(component) = component else {
            return Err(PluginError::InvalidManifest(format!(
                "embedding-provider bundle path must stay inside the plugin directory: {}",
                relative.display()
            )));
        };
        current.push(component);
        final_metadata = std::fs::symlink_metadata(&current)?;
        if final_metadata.file_type().is_symlink() {
            return Err(PluginError::InvalidManifest(format!(
                "embedding-provider bundle path contains a symlink: {}",
                current.display()
            )));
        }
    }
    Ok(final_metadata)
}

fn checked_plugin_name(name: &str) -> Result<(), PluginError> {
    let valid = !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'));
    if !valid {
        return Err(PluginError::InvalidManifest(format!(
            "plugin name must contain only ASCII letters, digits, '-' or '_': {name:?}"
        )));
    }
    Ok(())
}

fn create_install_staging_dir(
    plugins_dir: &Path,
    plugin_name: &str,
) -> Result<PathBuf, PluginError> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    for attempt in 0_u8..100 {
        let candidate = plugins_dir.join(format!(
            ".{plugin_name}.installing-{}-{timestamp}-{attempt}",
            std::process::id()
        ));
        match std::fs::create_dir(&candidate) {
            Ok(()) => return Ok(candidate),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    }
    Err(PluginError::InvalidManifest(format!(
        "could not allocate staging directory for plugin '{plugin_name}'"
    )))
}

fn copy_bundle_entry(source: &Path, destination: &Path) -> Result<(), PluginError> {
    if source.is_dir() {
        return copy_dir_recursive(source, destination);
    }
    if let Some(parent) = destination.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::copy(source, destination)?;
    Ok(())
}

/// Validate a skill bundle: `<plugin_dir>/skills/` must exist, contain at least
/// one subdirectory, and each subdirectory must hold a `SKILL.md` whose YAML
/// frontmatter declares the agentskills.io-required `name` and `description`.
fn validate_skill_bundle(plugin_name: &str, plugin_dir: &Path) -> Result<(), PluginError> {
    let skills_dir = plugin_dir.join(SKILLS_SUBDIR);
    if !skills_dir.is_dir() {
        return Err(PluginError::InvalidManifest(format!(
            "skill plugin '{}' is missing `skills/` directory at {}",
            plugin_name,
            skills_dir.display()
        )));
    }

    let mut found_any = false;
    for entry in std::fs::read_dir(&skills_dir)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        found_any = true;
        let skill_md = path.join("SKILL.md");
        if !skill_md.is_file() {
            return Err(PluginError::InvalidManifest(format!(
                "skill plugin '{}' subdirectory '{}' is missing SKILL.md",
                plugin_name,
                path.file_name().and_then(|n| n.to_str()).unwrap_or("?")
            )));
        }
        validate_skill_md_frontmatter(plugin_name, &skill_md)?;
    }

    if !found_any {
        return Err(PluginError::InvalidManifest(format!(
            "skill plugin '{}' has empty `skills/` directory",
            plugin_name
        )));
    }

    Ok(())
}

fn validate_skill_md_frontmatter(plugin_name: &str, skill_md: &Path) -> Result<(), PluginError> {
    let content = std::fs::read_to_string(skill_md)?;
    let normalized = content.replace("\r\n", "\n");
    let rest = normalized.strip_prefix("---\n").ok_or_else(|| {
        PluginError::InvalidManifest(format!(
            "skill plugin '{}': {} is missing YAML frontmatter",
            plugin_name,
            skill_md.display()
        ))
    })?;
    let frontmatter = if let Some(idx) = rest.find("\n---\n") {
        &rest[..idx]
    } else if let Some(stripped) = rest.strip_suffix("\n---") {
        stripped
    } else {
        return Err(PluginError::InvalidManifest(format!(
            "skill plugin '{}': {} has unterminated frontmatter",
            plugin_name,
            skill_md.display()
        )));
    };

    let mut has_name = false;
    let mut has_description = false;
    for line in frontmatter.lines() {
        let trimmed = line.trim_start();
        if let Some((key, value)) = trimmed.split_once(':') {
            let key = key.trim();
            let value = value.trim();
            // Treat block-scalar markers as a non-empty value once a continuation
            // line is present; the simple check below is sufficient because the
            // runtime loader parses the actual content.
            let has_value = !value.is_empty();
            match key {
                "name" if has_value => has_name = true,
                "description" if has_value => has_description = true,
                _ => {}
            }
        }
    }

    if !has_name || !has_description {
        return Err(PluginError::InvalidManifest(format!(
            "skill plugin '{}': {} frontmatter must declare `name` and `description`",
            plugin_name,
            skill_md.display()
        )));
    }

    Ok(())
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<(), PluginError> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        let ft = entry.file_type()?;
        if ft.is_dir() {
            copy_dir_recursive(&from, &to)?;
        } else if ft.is_file() {
            std::fs::copy(&from, &to)?;
        }
        // Symlinks intentionally skipped to match the runtime skill auditor.
    }
    Ok(())
}

/// Move every plugin (a subdirectory containing a `manifest.toml`) from `from`
/// into `to`, returning the number moved.
///
/// Uses `rename`, falling back to a recursive copy + remove when the source and
/// destination live on different filesystems. An existing `to/<name>` is never
/// overwritten — that plugin is skipped. A missing or empty `from` is a no-op.
/// Used by `zeroclaw plugin migrate` to relocate plugins stranded in legacy
/// install directories into the configured one.
pub fn migrate_plugins_dir(from: &Path, to: &Path) -> Result<usize, PluginError> {
    let Ok(entries) = std::fs::read_dir(from) else {
        return Ok(0);
    };

    let mut moved = 0usize;
    for entry in entries.flatten() {
        let src = entry.path();
        if !src.is_dir() || !src.join("manifest.toml").exists() {
            continue;
        }
        let Some(name) = src.file_name() else {
            continue;
        };
        let dest = to.join(name);
        if dest.exists() {
            continue; // never clobber an existing plugin
        }
        std::fs::create_dir_all(to)?;
        // `rename` is atomic but fails across filesystems; fall back to copy+remove.
        if std::fs::rename(&src, &dest).is_err() {
            copy_dir_recursive(&src, &dest)?;
            std::fs::remove_dir_all(&src)?;
        }
        moved += 1;
    }
    Ok(moved)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_empty_plugin_dir() {
        let dir = tempdir().unwrap();
        let host = PluginHost::new(dir.path()).unwrap();
        assert!(host.list_plugins().is_empty());
    }

    #[test]
    fn test_discover_with_manifest() {
        let dir = tempdir().unwrap();
        let plugin_dir = dir.path().join("plugins").join("test-plugin");
        std::fs::create_dir_all(&plugin_dir).unwrap();

        std::fs::write(
            plugin_dir.join("manifest.toml"),
            r#"
name = "test-plugin"
version = "0.1.0"
description = "A test plugin"
wasm_path = "plugin.wasm"
capabilities = ["tool"]
permissions = []
"#,
        )
        .unwrap();

        let host = PluginHost::new(dir.path()).unwrap();
        let plugins = host.list_plugins();
        assert_eq!(plugins.len(), 1);
        assert_eq!(plugins[0].name, "test-plugin");
    }

    #[test]
    fn from_plugins_dir_scans_the_path_directly() {
        // Plugin lives directly under the given dir (no extra `plugins/` level).
        let dir = tempdir().unwrap();
        let plugin_dir = dir.path().join("direct-plugin");
        std::fs::create_dir_all(&plugin_dir).unwrap();
        std::fs::write(
            plugin_dir.join("manifest.toml"),
            r#"
name = "direct-plugin"
version = "0.1.0"
wasm_path = "plugin.wasm"
capabilities = ["tool"]
"#,
        )
        .unwrap();

        let host = PluginHost::from_plugins_dir(dir.path()).unwrap();
        let plugins = host.list_plugins();
        assert_eq!(plugins.len(), 1);
        assert_eq!(plugins[0].name, "direct-plugin");
    }

    #[test]
    fn new_still_appends_plugins_subdir() {
        // `new`/`with_security` keep the legacy "workspace dir" contract:
        // a (valid) plugin placed directly under the root is NOT discovered,
        // but the same one under `<root>/plugins/` is.
        let manifest = "name = \"p\"\nversion = \"0.1.0\"\nwasm_path = \"p.wasm\"\ncapabilities = [\"tool\"]\n";

        let dir = tempdir().unwrap();
        let stray = dir.path().join("p");
        std::fs::create_dir_all(&stray).unwrap();
        std::fs::write(stray.join("manifest.toml"), manifest).unwrap();

        let host = PluginHost::new(dir.path()).unwrap();
        assert!(
            host.list_plugins().is_empty(),
            "plugin directly under root must not be discovered by `new`"
        );

        // Same manifest under `<root>/plugins/` is found.
        let nested = dir.path().join("plugins").join("p");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(nested.join("manifest.toml"), manifest).unwrap();
        let host = PluginHost::new(dir.path()).unwrap();
        assert_eq!(host.list_plugins().len(), 1);
        assert_eq!(host.list_plugins()[0].name, "p");
    }

    #[test]
    fn install_then_discover_round_trip_uses_same_dir() {
        // Regression for the install/discovery path divergence (issue #6254):
        // a plugin installed into a resolved plugins dir must be discoverable
        // by a fresh host pointed at the *same* dir.
        let src = tempdir().unwrap();
        std::fs::write(
            src.path().join("manifest.toml"),
            r#"
name = "roundtrip"
version = "0.1.0"
wasm_path = "plugin.wasm"
capabilities = ["tool"]
"#,
        )
        .unwrap();
        std::fs::write(src.path().join("plugin.wasm"), b"\0asm").unwrap();

        let plugins_dir = tempdir().unwrap();
        let mut installer = PluginHost::from_plugins_dir(plugins_dir.path()).unwrap();
        installer
            .install(src.path().to_str().unwrap())
            .expect("install should succeed");

        // Fresh host over the same dir — mirrors the CLI install vs. runtime
        // discovery split, both now resolving via `from_plugins_dir`.
        let discoverer = PluginHost::from_plugins_dir(plugins_dir.path()).unwrap();
        let plugins = discoverer.list_plugins();
        assert_eq!(plugins.len(), 1);
        assert_eq!(plugins[0].name, "roundtrip");
    }

    fn write_manifest(dir: &Path, name: &str) {
        std::fs::create_dir_all(dir.join(name)).unwrap();
        std::fs::write(
            dir.join(name).join("manifest.toml"),
            format!("name = \"{name}\"\nversion = \"0.1.0\"\ncapabilities = [\"tool\"]\n"),
        )
        .unwrap();
    }

    #[test]
    fn migrate_plugins_dir_moves_and_never_clobbers() {
        let from = tempdir().unwrap();
        let to = tempdir().unwrap();
        write_manifest(from.path(), "alpha");
        write_manifest(from.path(), "beta");
        // `beta` already exists in the target → must be skipped, not overwritten.
        write_manifest(to.path(), "beta");

        let moved = migrate_plugins_dir(from.path(), to.path()).unwrap();

        assert_eq!(moved, 1, "only alpha should move; beta collides");
        assert!(to.path().join("alpha").join("manifest.toml").exists());
        assert!(!from.path().join("alpha").exists(), "alpha source removed");
        assert!(
            from.path().join("beta").exists(),
            "skipped source left in place"
        );
    }

    #[test]
    fn migrate_plugins_dir_is_noop_for_missing_or_empty() {
        let to = tempdir().unwrap();
        // Missing source.
        assert_eq!(
            migrate_plugins_dir(&to.path().join("nope"), to.path()).unwrap(),
            0
        );
        // Empty source.
        let empty = tempdir().unwrap();
        assert_eq!(migrate_plugins_dir(empty.path(), to.path()).unwrap(), 0);
    }

    #[test]
    fn test_tool_plugins_filter() {
        let dir = tempdir().unwrap();
        let plugins_base = dir.path().join("plugins");

        // Tool plugin
        let tool_dir = plugins_base.join("my-tool");
        std::fs::create_dir_all(&tool_dir).unwrap();
        std::fs::write(
            tool_dir.join("manifest.toml"),
            r#"
name = "my-tool"
version = "0.1.0"
wasm_path = "tool.wasm"
capabilities = ["tool"]
"#,
        )
        .unwrap();

        // Channel plugin
        let chan_dir = plugins_base.join("my-channel");
        std::fs::create_dir_all(&chan_dir).unwrap();
        std::fs::write(
            chan_dir.join("manifest.toml"),
            r#"
name = "my-channel"
version = "0.1.0"
wasm_path = "channel.wasm"
capabilities = ["channel"]
"#,
        )
        .unwrap();

        let host = PluginHost::new(dir.path()).unwrap();
        assert_eq!(host.list_plugins().len(), 2);
        assert_eq!(host.tool_plugins().len(), 1);
        assert_eq!(host.channel_plugins().len(), 1);
        assert_eq!(host.tool_plugins()[0].name, "my-tool");
    }

    #[test]
    fn test_get_plugin() {
        let dir = tempdir().unwrap();
        let plugin_dir = dir.path().join("plugins").join("lookup-test");
        std::fs::create_dir_all(&plugin_dir).unwrap();
        std::fs::write(
            plugin_dir.join("manifest.toml"),
            r#"
name = "lookup-test"
version = "1.0.0"
description = "Lookup test"
wasm_path = "plugin.wasm"
capabilities = ["tool"]
"#,
        )
        .unwrap();

        let host = PluginHost::new(dir.path()).unwrap();
        assert!(host.get_plugin("lookup-test").is_some());
        assert!(host.get_plugin("nonexistent").is_none());
    }

    #[test]
    fn test_remove_plugin() {
        let dir = tempdir().unwrap();
        let plugin_dir = dir.path().join("plugins").join("removable");
        std::fs::create_dir_all(&plugin_dir).unwrap();
        std::fs::write(
            plugin_dir.join("manifest.toml"),
            r#"
name = "removable"
version = "0.1.0"
wasm_path = "plugin.wasm"
capabilities = ["tool"]
"#,
        )
        .unwrap();

        let mut host = PluginHost::new(dir.path()).unwrap();
        assert_eq!(host.list_plugins().len(), 1);

        host.remove("removable").unwrap();
        assert!(host.list_plugins().is_empty());
        assert!(!plugin_dir.exists());
    }

    #[test]
    fn test_remove_nonexistent_returns_error() {
        let dir = tempdir().unwrap();
        let mut host = PluginHost::new(dir.path()).unwrap();
        assert!(host.remove("ghost").is_err());
    }

    fn write_skill_md(path: &Path, name: &str, description: &str) {
        std::fs::write(
            path,
            format!(
                "---\nname: {name}\ndescription: {description}\n---\n\nBody content for {name}.\n"
            ),
        )
        .unwrap();
    }

    fn write_skill_bundle_plugin(plugins_base: &Path, plugin_name: &str, skill_names: &[&str]) {
        let plugin_dir = plugins_base.join(plugin_name);
        std::fs::create_dir_all(&plugin_dir).unwrap();
        std::fs::write(
            plugin_dir.join("manifest.toml"),
            format!("name = \"{plugin_name}\"\nversion = \"0.1.0\"\ncapabilities = [\"skill\"]\n"),
        )
        .unwrap();
        let skills_dir = plugin_dir.join("skills");
        std::fs::create_dir_all(&skills_dir).unwrap();
        for skill in skill_names {
            let sd = skills_dir.join(skill);
            std::fs::create_dir_all(&sd).unwrap();
            write_skill_md(
                &sd.join("SKILL.md"),
                skill,
                &format!("Description for {skill}"),
            );
        }
    }

    #[test]
    fn test_skill_only_plugin_discovers_without_wasm_path() {
        let dir = tempdir().unwrap();
        let plugins_base = dir.path().join("plugins");
        write_skill_bundle_plugin(
            &plugins_base,
            "my-toolkit",
            &["design-review", "code-review"],
        );

        let host = PluginHost::new(dir.path()).unwrap();
        let plugins = host.list_plugins();
        assert_eq!(plugins.len(), 1);
        assert_eq!(plugins[0].name, "my-toolkit");
        assert!(plugins[0].wasm_path.is_none());
        assert!(plugins[0].loaded);

        let skill_plugins = host.skill_plugins();
        assert_eq!(skill_plugins.len(), 1);

        let details = host.skill_plugin_details();
        assert_eq!(details.len(), 1);
        assert_eq!(details[0].0.name, "my-toolkit");
        assert!(details[0].1.ends_with("skills"));
    }

    #[test]
    fn test_non_skill_plugin_without_wasm_path_is_rejected() {
        let dir = tempdir().unwrap();
        let plugin_dir = dir.path().join("plugins").join("broken");
        std::fs::create_dir_all(&plugin_dir).unwrap();
        std::fs::write(
            plugin_dir.join("manifest.toml"),
            "name = \"broken\"\nversion = \"0.1.0\"\ncapabilities = [\"tool\"]\n",
        )
        .unwrap();

        let host = PluginHost::new(dir.path()).unwrap();
        // Discovery skips invalid manifests rather than failing.
        assert!(host.list_plugins().is_empty());
    }

    #[test]
    fn test_skill_plugin_missing_skills_dir_is_rejected() {
        let dir = tempdir().unwrap();
        let plugin_dir = dir.path().join("plugins").join("empty-skills");
        std::fs::create_dir_all(&plugin_dir).unwrap();
        std::fs::write(
            plugin_dir.join("manifest.toml"),
            "name = \"empty-skills\"\nversion = \"0.1.0\"\ncapabilities = [\"skill\"]\n",
        )
        .unwrap();

        let host = PluginHost::new(dir.path()).unwrap();
        assert!(host.list_plugins().is_empty());
    }

    #[test]
    fn test_skill_plugin_rejects_skill_without_required_frontmatter() {
        let dir = tempdir().unwrap();
        let plugin_dir = dir.path().join("plugins").join("bad-frontmatter");
        std::fs::create_dir_all(&plugin_dir).unwrap();
        std::fs::write(
            plugin_dir.join("manifest.toml"),
            "name = \"bad-frontmatter\"\nversion = \"0.1.0\"\ncapabilities = [\"skill\"]\n",
        )
        .unwrap();
        let skill_dir = plugin_dir.join("skills").join("oops");
        std::fs::create_dir_all(&skill_dir).unwrap();
        // Missing description field
        std::fs::write(skill_dir.join("SKILL.md"), "---\nname: oops\n---\n\nbody\n").unwrap();

        let host = PluginHost::new(dir.path()).unwrap();
        assert!(host.list_plugins().is_empty());
    }

    #[test]
    fn test_skill_plugin_rejects_skill_without_skill_md() {
        let dir = tempdir().unwrap();
        let plugin_dir = dir.path().join("plugins").join("missing-md");
        std::fs::create_dir_all(&plugin_dir).unwrap();
        std::fs::write(
            plugin_dir.join("manifest.toml"),
            "name = \"missing-md\"\nversion = \"0.1.0\"\ncapabilities = [\"skill\"]\n",
        )
        .unwrap();
        let skill_dir = plugin_dir.join("skills").join("orphan");
        std::fs::create_dir_all(&skill_dir).unwrap();
        std::fs::write(skill_dir.join("notes.md"), "no SKILL.md here").unwrap();

        let host = PluginHost::new(dir.path()).unwrap();
        assert!(host.list_plugins().is_empty());
    }

    #[test]
    fn test_skill_plugin_does_not_appear_in_tool_or_channel_lists() {
        let dir = tempdir().unwrap();
        let plugins_base = dir.path().join("plugins");
        write_skill_bundle_plugin(&plugins_base, "skill-bundle", &["one"]);

        let host = PluginHost::new(dir.path()).unwrap();
        assert!(host.tool_plugins().is_empty());
        assert!(host.tool_plugin_details().is_empty());
        assert!(host.channel_plugins().is_empty());
        assert_eq!(host.skill_plugins().len(), 1);
    }

    fn write_unsigned_tool_plugin(plugins_dir: &Path, name: &str) {
        let plugin_dir = plugins_dir.join(name);
        std::fs::create_dir_all(&plugin_dir).unwrap();
        std::fs::write(
            plugin_dir.join("manifest.toml"),
            format!(
                "name = \"{name}\"\nversion = \"0.1.0\"\ncapabilities = [\"tool\"]\nwasm_path = \"plugin.wasm\"\n"
            ),
        )
        .unwrap();
        std::fs::write(plugin_dir.join("plugin.wasm"), b"\0asm").unwrap();
    }

    fn write_channel_plugin(plugins_dir: &Path, name: &str, with_wasm: bool) {
        let plugin_dir = plugins_dir.join(name);
        std::fs::create_dir_all(&plugin_dir).unwrap();
        let wasm_line = if with_wasm {
            "wasm_path = \"plugin.wasm\"\n"
        } else {
            ""
        };
        std::fs::write(
            plugin_dir.join("manifest.toml"),
            format!(
                "name = \"{name}\"\nversion = \"0.1.0\"\ncapabilities = [\"channel\"]\n{wasm_line}"
            ),
        )
        .unwrap();
        if with_wasm {
            std::fs::write(plugin_dir.join("plugin.wasm"), b"\0asm").unwrap();
        }
    }

    #[test]
    fn channel_plugin_details_yields_only_wasm_backed_channels() {
        let dir = tempdir().unwrap();
        let plugins_base = dir.path().join("plugins");
        write_channel_plugin(&plugins_base, "with-wasm", true);
        write_channel_plugin(&plugins_base, "no-wasm", false);

        let host = PluginHost::new(dir.path()).unwrap();
        let details = host.channel_plugin_details();
        assert_eq!(
            details.len(),
            1,
            "a channel manifest with no wasm_path is not registrable as a live channel"
        );
        assert_eq!(details[0].0.name, "with-wasm");
        assert!(details[0].1.ends_with("plugin.wasm"));
    }

    fn write_embedding_manifest(
        plugin_dir: &Path,
        capabilities: &str,
        executable_digest: &str,
        artifact_digest: Option<&str>,
    ) {
        let artifact = artifact_digest.map_or_else(String::new, |digest| {
            format!(
                r#"

[[embedding_provider.artifacts]]
path = "model"
sha256 = "{digest}"
"#
            )
        });
        std::fs::write(
            plugin_dir.join("manifest.toml"),
            format!(
                r#"name = "native-embed"
version = "0.1.0"
capabilities = [{capabilities}]

[embedding_provider]
model = "reference-model"
dimensions = 8

[embedding_provider.executable]
path = "bin/embed"
sha256 = "{executable_digest}"
{artifact}"#
            ),
        )
        .unwrap();
    }

    #[test]
    fn embedding_provider_capability_is_derived_from_manifest_table() {
        let dir = tempdir().unwrap();
        let plugin_dir = dir.path().join("native-embed");
        std::fs::create_dir_all(plugin_dir.join("bin")).unwrap();
        std::fs::write(plugin_dir.join("bin/embed"), b"fixture").unwrap();
        let digest = sha256_bundle_path(&plugin_dir.join("bin/embed")).unwrap();
        write_embedding_manifest(&plugin_dir, "", &digest, None);

        let host = PluginHost::from_plugins_dir(dir.path()).unwrap();
        let plugins = host.list_plugins();
        assert_eq!(plugins.len(), 1);
        assert_eq!(
            plugins[0].capabilities,
            [PluginCapability::EmbeddingProvider]
        );
        assert!(plugins[0].loaded);
    }

    #[test]
    fn embedding_provider_rejects_duplicate_declared_capability() {
        let dir = tempdir().unwrap();
        let plugin_dir = dir.path().join("native-embed");
        std::fs::create_dir_all(plugin_dir.join("bin")).unwrap();
        std::fs::write(plugin_dir.join("bin/embed"), b"fixture").unwrap();
        let digest = sha256_bundle_path(&plugin_dir.join("bin/embed")).unwrap();
        write_embedding_manifest(&plugin_dir, "\"embedding_provider\"", &digest, None);

        let host = PluginHost::from_plugins_dir(dir.path()).unwrap();
        assert!(host.list_plugins().is_empty());
    }

    #[test]
    fn embedding_provider_install_copies_declared_artifact_directories() {
        let source = tempdir().unwrap();
        std::fs::create_dir_all(source.path().join("bin")).unwrap();
        std::fs::create_dir_all(source.path().join("model")).unwrap();
        std::fs::write(source.path().join("bin/embed"), b"fixture").unwrap();
        std::fs::write(source.path().join("model/weights.bin"), b"weights").unwrap();
        let executable_digest = sha256_bundle_path(&source.path().join("bin/embed")).unwrap();
        let artifact_digest = sha256_bundle_path(&source.path().join("model")).unwrap();
        write_embedding_manifest(
            source.path(),
            "",
            &executable_digest,
            Some(&artifact_digest),
        );

        let installed = tempdir().unwrap();
        let mut host = PluginHost::from_plugins_dir(installed.path()).unwrap();
        host.install(source.path().to_str().unwrap()).unwrap();

        assert!(
            installed
                .path()
                .join("native-embed/model/weights.bin")
                .is_file()
        );
        let (_, _, executable) = host.embedding_provider_details("native-embed").unwrap();
        assert_eq!(executable, installed.path().join("native-embed/bin/embed"));
        assert!(
            std::fs::read_dir(installed.path())
                .unwrap()
                .flatten()
                .all(|entry| !entry.file_name().to_string_lossy().contains(".installing-")),
            "atomic install must not leave a staging directory"
        );
    }

    #[test]
    fn embedding_provider_rejects_payload_digest_mismatch() {
        let dir = tempdir().unwrap();
        let plugin_dir = dir.path().join("native-embed");
        std::fs::create_dir_all(plugin_dir.join("bin")).unwrap();
        std::fs::write(plugin_dir.join("bin/embed"), b"original").unwrap();
        let digest = sha256_bundle_path(&plugin_dir.join("bin/embed")).unwrap();
        write_embedding_manifest(&plugin_dir, "", &digest, None);
        std::fs::write(plugin_dir.join("bin/embed"), b"tampered").unwrap();

        let host = PluginHost::from_plugins_dir(dir.path()).unwrap();
        assert!(host.list_plugins().is_empty());
    }

    #[test]
    fn embedding_provider_rejects_path_traversal() {
        let dir = tempdir().unwrap();
        let plugin_dir = dir.path().join("native-embed");
        std::fs::create_dir_all(&plugin_dir).unwrap();
        std::fs::write(dir.path().join("escape"), b"fixture").unwrap();
        std::fs::write(
            plugin_dir.join("manifest.toml"),
            format!(
                r#"name = "native-embed"
version = "0.1.0"
capabilities = []

[embedding_provider]
model = "reference-model"
dimensions = 8

[embedding_provider.executable]
path = "../escape"
sha256 = "{}"
"#,
                sha256_bundle_path(&dir.path().join("escape")).unwrap()
            ),
        )
        .unwrap();

        let host = PluginHost::from_plugins_dir(dir.path()).unwrap();
        assert!(host.list_plugins().is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn embedding_provider_rejects_symlinked_path_component() {
        use std::os::unix::fs::symlink;

        let dir = tempdir().unwrap();
        let plugin_dir = dir.path().join("native-embed");
        let external_bin = dir.path().join("external-bin");
        std::fs::create_dir_all(&plugin_dir).unwrap();
        std::fs::create_dir_all(&external_bin).unwrap();
        std::fs::write(external_bin.join("embed"), b"fixture").unwrap();
        symlink(&external_bin, plugin_dir.join("bin")).unwrap();
        let digest = sha256_bundle_path(&external_bin.join("embed")).unwrap();
        write_embedding_manifest(&plugin_dir, "", &digest, None);

        let host = PluginHost::from_plugins_dir(dir.path()).unwrap();
        assert!(host.list_plugins().is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn install_rejects_symlinked_manifest() {
        use std::os::unix::fs::symlink;

        let source = tempdir().unwrap();
        let manifest = source.path().join("external-manifest.toml");
        std::fs::write(
            &manifest,
            "name = \"linked\"\nversion = \"0.1.0\"\ncapabilities = [\"tool\"]\nwasm_path = \"plugin.wasm\"\n",
        )
        .unwrap();
        symlink(&manifest, source.path().join("manifest.toml")).unwrap();
        let installed = tempdir().unwrap();
        let mut host = PluginHost::from_plugins_dir(installed.path()).unwrap();

        let error = host
            .install(source.path().to_str().unwrap())
            .expect_err("symlinked manifest must be rejected");
        assert!(error.to_string().contains("must be a regular file"));
    }

    #[test]
    fn install_rejects_unsafe_plugin_name_without_writing_outside_root() {
        let source = tempdir().unwrap();
        std::fs::write(
            source.path().join("manifest.toml"),
            "name = \"../escape\"\nversion = \"0.1.0\"\ncapabilities = [\"tool\"]\nwasm_path = \"plugin.wasm\"\n",
        )
        .unwrap();
        std::fs::write(source.path().join("plugin.wasm"), b"\0asm").unwrap();
        let installed = tempdir().unwrap();
        let mut host = PluginHost::from_plugins_dir(installed.path()).unwrap();

        assert!(host.install(source.path().to_str().unwrap()).is_err());
        assert!(!installed.path().parent().unwrap().join("escape").exists());
    }

    #[test]
    fn from_plugins_dir_with_security_strict_drops_unsigned_plugin() {
        let dir = tempdir().unwrap();
        write_unsigned_tool_plugin(dir.path(), "unsigned-tool");

        let host = PluginHost::from_plugins_dir_with_security(
            dir.path(),
            SignatureMode::Strict,
            Vec::new(),
        )
        .unwrap();

        assert!(
            host.list_plugins().is_empty(),
            "strict mode must reject an unsigned plugin during discovery"
        );
    }

    #[test]
    fn from_plugins_dir_with_security_disabled_loads_unsigned_plugin() {
        let dir = tempdir().unwrap();
        write_unsigned_tool_plugin(dir.path(), "unsigned-tool");

        let host = PluginHost::from_plugins_dir_with_security(
            dir.path(),
            SignatureMode::Disabled,
            Vec::new(),
        )
        .unwrap();

        assert_eq!(
            host.list_plugins().len(),
            1,
            "disabled mode must load an unsigned plugin"
        );
    }

    #[test]
    fn from_plugins_dir_with_security_permissive_loads_unsigned_plugin() {
        let dir = tempdir().unwrap();
        write_unsigned_tool_plugin(dir.path(), "unsigned-tool");

        let host = PluginHost::from_plugins_dir_with_security(
            dir.path(),
            SignatureMode::Permissive,
            Vec::new(),
        )
        .unwrap();

        assert_eq!(
            host.list_plugins().len(),
            1,
            "permissive mode must load an unsigned plugin (untrusted and invalid signatures also load with a warning in permissive mode, covered in signature.rs)"
        );
    }

    #[test]
    fn parse_signature_mode_maps_config_strings() {
        assert_eq!(
            PluginHost::parse_signature_mode("strict"),
            Some(SignatureMode::Strict)
        );
        assert_eq!(
            PluginHost::parse_signature_mode("permissive"),
            Some(SignatureMode::Permissive)
        );
        assert_eq!(
            PluginHost::parse_signature_mode("disabled"),
            Some(SignatureMode::Disabled)
        );
        // Case-insensitive: to_lowercase normalizes before matching.
        assert_eq!(
            PluginHost::parse_signature_mode("STRICT"),
            Some(SignatureMode::Strict)
        );
        // Unrecognized values return None so the caller fails safe instead of
        // silently degrading to the weakest posture on a config typo.
        assert_eq!(PluginHost::parse_signature_mode("nonsense"), None);
        assert_eq!(PluginHost::parse_signature_mode("sttict"), None);
    }
}
