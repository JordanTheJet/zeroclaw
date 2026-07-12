#![cfg(feature = "reference-sidecar")]

use rusqlite::Connection;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use zeroclaw_api::embedding::EmbeddingProvider;
use zeroclaw_api::memory_traits::MemoryCategory;
use zeroclaw_config::schema::{ActiveStorage, Config, MemoryConfig, SearchMode};
use zeroclaw_embedding_sidecar::PluginEmbeddingFactory;
use zeroclaw_embedding_sidecar::reference::{DIMENSIONS, MODEL_ID};
use zeroclaw_memory::create_memory_with_storage_routes_and_embedding_factory;
use zeroclaw_plugins::PluginManifest;
use zeroclaw_plugins::host::{PluginHost, sha256_bundle_path};

#[tokio::test]
async fn installed_sidecar_keeps_logical_identity_across_ephemeral_ports() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let source = root.path().join("source-plugin");
    let installed = root.path().join("installed-plugins");
    let workspace = root.path().join("agent-workspace");
    let manifest = write_plugin_bundle(&source)?;
    let plugin_name = manifest.name;

    let mut host = PluginHost::from_plugins_dir(&installed)?;
    assert_eq!(
        host.install(source.to_str().expect("UTF-8 temp path"))?,
        plugin_name
    );
    let factory = PluginEmbeddingFactory::new(host);
    let provider_name = format!("plugin:{plugin_name}");

    let provider_a = factory.launch(&plugin_name, MODEL_ID, DIMENSIONS)?;
    let endpoint_a = provider_a.base_url().to_string();
    let child_a = provider_a.child_id().expect("running child A");
    let shared_provider = factory.launch(&plugin_name, MODEL_ID, DIMENSIONS)?;
    assert!(Arc::ptr_eq(&provider_a, &shared_provider));
    assert_eq!(shared_provider.child_id(), Some(child_a));

    let unauthenticated = reqwest::Client::builder()
        .no_proxy()
        .build()?
        .post(format!("{endpoint_a}v1/embeddings"))
        .json(&serde_json::json!({"model": MODEL_ID, "input": ["test"]}))
        .send()
        .await?;
    assert_eq!(unauthenticated.status(), reqwest::StatusCode::UNAUTHORIZED);

    let vectors = provider_a
        .embed(&["garage vehicle", "ocean tide", "garage vehicle"])
        .await?;
    assert_eq!(vectors.len(), 3);
    assert_eq!(vectors[0], vectors[2]);
    assert!(vectors.iter().all(|vector| vector.len() == DIMENSIONS));
    assert!(vectors.iter().all(|vector| {
        let norm = vector.iter().map(|value| value * value).sum::<f32>().sqrt();
        (norm - 1.0).abs() < 1e-5
    }));

    let memory_config = MemoryConfig {
        backend: "sqlite".to_string(),
        embedding_provider: provider_name.clone(),
        embedding_model: MODEL_ID.to_string(),
        embedding_dimensions: DIMENSIONS,
        search_mode: SearchMode::Embedding,
        ..MemoryConfig::default()
    };

    let memory_a = create_memory_with_storage_routes_and_embedding_factory(
        &memory_config,
        &[],
        ActiveStorage::None,
        &workspace,
        None,
        None,
        Some(&factory),
    )?;
    memory_a
        .store(
            "vehicle-note",
            "the green vehicle is parked in the garage",
            MemoryCategory::Core,
            None,
        )
        .await?;
    memory_a
        .store(
            "ocean-note",
            "the tide reaches the quiet beach at dawn",
            MemoryCategory::Core,
            None,
        )
        .await?;
    let first_recall = memory_a.recall("garage", 1, None, None, None).await?;
    assert_eq!(
        first_recall.first().map(|entry| entry.key.as_str()),
        Some("vehicle-note")
    );
    drop(memory_a);

    assert_eq!(embedded_row_count(&workspace)?, 2);
    let metadata_a = embedding_metadata(&workspace)?;
    assert!(metadata_a.contains(&format!("{provider_name}@sha256:")));
    assert!(!metadata_a.contains("127.0.0.1"));

    // Stop A and occupy its old port so the restarted child must use a new
    // ephemeral transport endpoint. Its content-bound identity stays stable.
    provider_a.shutdown();
    let old_port = reqwest::Url::parse(&endpoint_a)?
        .port()
        .ok_or_else(|| anyhow::Error::msg("sidecar endpoint has no port"))?;
    let old_port_guard = std::net::TcpListener::bind(("127.0.0.1", old_port))?;
    let provider_b = factory.launch(&plugin_name, MODEL_ID, DIMENSIONS)?;
    let endpoint_b = provider_b.base_url().to_string();
    drop(old_port_guard);
    assert_ne!(endpoint_a, endpoint_b);
    assert_ne!(provider_b.child_id(), Some(child_a));
    let memory_b = create_memory_with_storage_routes_and_embedding_factory(
        &memory_config,
        &[],
        ActiveStorage::None,
        &workspace,
        None,
        None,
        Some(&factory),
    )?;

    // A changing transport endpoint must not invalidate vectors produced by
    // the same logical plugin/model/dimension identity.
    assert_eq!(embedded_row_count(&workspace)?, 2);
    assert_eq!(embedding_metadata(&workspace)?, metadata_a);
    let second_recall = memory_b.recall("garage", 1, None, None, None).await?;
    assert_eq!(
        second_recall.first().map(|entry| entry.key.as_str()),
        Some("vehicle-note")
    );
    drop(memory_b);

    // Exercise the production composition helper used by daemon/gateway:
    // canonical config selects the plugin by logical name and contains no URL.
    let mut config = Config {
        memory: memory_config,
        data_dir: workspace.clone(),
        plugins: zeroclaw_config::schema::PluginsConfig {
            enabled: true,
            allow_native_sidecars: true,
            plugins_dir: installed.to_string_lossy().into_owned(),
            ..zeroclaw_config::schema::PluginsConfig::default()
        },
        ..Config::default()
    };
    let configured_memory = zeroclaw_embedding_sidecar::create_memory(&config, &workspace, None)?;
    let configured_recall = configured_memory
        .recall("garage", 1, None, None, None)
        .await?;
    assert_eq!(
        configured_recall.first().map(|entry| entry.key.as_str()),
        Some("vehicle-note")
    );
    drop(configured_memory);

    config
        .agents
        .insert("fixture-agent".to_string(), Default::default());
    let agent_memory =
        zeroclaw_embedding_sidecar::create_memory_for_agent(&config, "fixture-agent", None).await?;
    agent_memory
        .store(
            "agent-note",
            "the amber bicycle is beside the garage",
            MemoryCategory::Core,
            None,
        )
        .await?;
    let agent_recall = agent_memory.recall("bicycle", 1, None, None, None).await?;
    assert_eq!(
        agent_recall.first().map(|entry| entry.key.as_str()),
        Some("agent-note")
    );
    drop(agent_memory);

    provider_b.shutdown();
    assert_eq!(provider_a.child_id(), None);
    assert_eq!(provider_b.child_id(), None);
    assert_ne!(child_a, 0);
    Ok(())
}

#[test]
fn readiness_timeout_kills_and_reaps_child() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let source = root.path().join("source-plugin");
    let installed = root.path().join("installed-plugins");
    let mut manifest = write_plugin_bundle(&source)?;
    manifest
        .embedding_provider
        .as_mut()
        .ok_or_else(|| anyhow::Error::msg("reference manifest has no embedding provider"))?
        .args = vec![
        "--fixture-delay-readiness-ms".to_string(),
        "5000".to_string(),
    ];
    std::fs::write(
        source.join("manifest.toml"),
        toml::to_string_pretty(&manifest)?,
    )?;

    let plugin_name = manifest.name;
    let mut host = PluginHost::from_plugins_dir(&installed)?;
    host.install(source.to_str().expect("UTF-8 temp path"))?;
    let factory =
        PluginEmbeddingFactory::with_startup_timeout(host, std::time::Duration::from_millis(50));
    let started = std::time::Instant::now();
    let error = factory
        .launch(&plugin_name, MODEL_ID, DIMENSIONS)
        .err()
        .ok_or_else(|| anyhow::Error::msg("delayed sidecar unexpectedly started"))?;
    assert!(format!("{error:#}").contains("timed out waiting for sidecar readiness"));
    assert!(started.elapsed() < std::time::Duration::from_secs(2));
    Ok(())
}

fn write_plugin_bundle(source: &Path) -> anyhow::Result<PluginManifest> {
    let template = Path::new(env!("CARGO_MANIFEST_DIR")).join("reference-plugin");
    copy_directory(&template, source)?;
    let manifest_text = std::fs::read_to_string(source.join("manifest.toml"))?;
    let mut manifest: PluginManifest = toml::from_str(&manifest_text)?;
    let relative_binary = manifest
        .embedding_provider
        .as_ref()
        .map(|provider| PathBuf::from(&provider.executable.path))
        .ok_or_else(|| anyhow::Error::msg("reference manifest has no embedding provider"))?;
    let binary = PathBuf::from(env!("CARGO_BIN_EXE_zeroclaw-reference-embedding-sidecar"));
    let destination = source.join(relative_binary);
    std::fs::create_dir_all(destination.parent().expect("binary parent"))?;
    std::fs::copy(binary, &destination)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = std::fs::metadata(&destination)?.permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(&destination, permissions)?;
    }
    manifest
        .embedding_provider
        .as_mut()
        .ok_or_else(|| anyhow::Error::msg("reference manifest has no embedding provider"))?
        .executable
        .sha256 = sha256_bundle_path(&destination)?;
    std::fs::write(
        source.join("manifest.toml"),
        toml::to_string_pretty(&manifest)?,
    )?;
    Ok(manifest)
}

fn copy_directory(source: &Path, destination: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(destination)?;
    for entry in std::fs::read_dir(source)? {
        let entry = entry?;
        let from = entry.path();
        let to = destination.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_directory(&from, &to)?;
        } else {
            std::fs::copy(from, to)?;
        }
    }
    Ok(())
}

fn embedded_row_count(workspace: &Path) -> anyhow::Result<i64> {
    let connection = Connection::open(workspace.join("memory/brain.db"))?;
    Ok(connection.query_row(
        "SELECT COUNT(*) FROM memories WHERE embedding IS NOT NULL",
        [],
        |row| row.get(0),
    )?)
}

fn embedding_metadata(workspace: &Path) -> anyhow::Result<String> {
    let connection = Connection::open(workspace.join("memory/brain.db"))?;
    let mut statement = connection.prepare(
        "SELECT key || '=' || value FROM memory_meta WHERE key LIKE 'embedding_%' ORDER BY key",
    )?;
    let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
    Ok(rows.collect::<Result<Vec<_>, _>>()?.join("\n"))
}
