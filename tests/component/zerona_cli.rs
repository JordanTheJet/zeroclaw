//! Process-boundary coverage for the interactive Zerona CLI.

use std::process::{Command, Stdio};

#[cfg(unix)]
use std::io::{Read as _, Write as _};
#[cfg(unix)]
use std::sync::mpsc;
#[cfg(unix)]
use std::time::{Duration, Instant};

#[cfg(unix)]
use portable_pty::{CommandBuilder, PtySize, native_pty_system};
#[cfg(unix)]
use wiremock::matchers::{method, path};
#[cfg(unix)]
use wiremock::{Mock, MockServer, ResponseTemplate};

#[test]
fn onboard_refuses_non_terminal_input_without_changing_config() {
    let config_dir = tempfile::tempdir().expect("temporary config directory");
    let config_path = config_dir.path().join("config.toml");
    let original = "schema_version = 3\n";
    std::fs::write(&config_path, original).expect("write minimal config");

    let output = Command::new(env!("CARGO_BIN_EXE_zeroclaw"))
        .env("RUST_LOG", "off")
        .args([
            "--config-dir",
            config_dir.path().to_str().expect("UTF-8 config path"),
            "onboard",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("run zeroclaw onboard without a terminal");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "non-terminal onboarding must fail closed\nstdout:\n{}\nstderr:\n{stderr}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        stderr.contains("requires an interactive terminal"),
        "the process boundary should explain the terminal requirement: {stderr}"
    );
    assert_eq!(
        std::fs::read_to_string(&config_path).expect("read config after refusal"),
        original,
        "the terminal guard must run before any config write"
    );
    assert!(
        !config_dir.path().join("agents").exists(),
        "the terminal guard must not create an agent workspace"
    );
}

#[cfg(unix)]
struct PtyRun {
    success: bool,
    transcript: String,
}

#[cfg(unix)]
fn drive_pty(config_dir: &std::path::Path, script: &[(&str, &str)], deadline: Duration) -> PtyRun {
    drive_pty_with_hook(config_dir, script, deadline, |_| {})
}

#[cfg(unix)]
fn drive_pty_with_hook(
    config_dir: &std::path::Path,
    script: &[(&str, &str)],
    deadline: Duration,
    mut before_answer: impl FnMut(usize),
) -> PtyRun {
    let pair = native_pty_system()
        .openpty(PtySize {
            rows: 40,
            cols: 180,
            pixel_width: 0,
            pixel_height: 0,
        })
        .expect("open pseudo-terminal");

    let mut command = CommandBuilder::new(env!("CARGO_BIN_EXE_zeroclaw"));
    command.arg("--config-dir");
    command.arg(config_dir);
    command.arg("onboard");
    command.env("RUST_LOG", "off");
    command.env("TERM", "dumb");

    let mut child = pair
        .slave
        .spawn_command(command)
        .expect("spawn Zerona in pseudo-terminal");
    drop(pair.slave);

    let mut reader = pair.master.try_clone_reader().expect("clone PTY reader");
    let (sender, receiver) = mpsc::channel::<Vec<u8>>();
    std::thread::spawn(move || {
        let mut buffer = [0_u8; 4096];
        loop {
            match reader.read(&mut buffer) {
                Ok(0) | Err(_) => break,
                Ok(read) => {
                    if sender.send(buffer[..read].to_vec()).is_err() {
                        break;
                    }
                }
            }
        }
    });

    let mut writer = pair.master.take_writer().expect("take PTY writer");
    let mut transcript = String::new();
    let mut script_index = 0;
    let expires = Instant::now() + deadline;
    let mut exit = None;

    while Instant::now() < expires {
        match receiver.recv_timeout(Duration::from_millis(100)) {
            Ok(chunk) => transcript.push_str(&String::from_utf8_lossy(&chunk)),
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                exit = child.try_wait().expect("poll Zerona child");
                break;
            }
        }

        if let Some((needle, answer)) = script.get(script_index)
            && transcript.contains(needle)
        {
            before_answer(script_index);
            writer
                .write_all(format!("{answer}\n").as_bytes())
                .expect("write scripted PTY answer");
            writer.flush().expect("flush scripted PTY answer");
            script_index += 1;
        }

        if let Some(status) = child.try_wait().expect("poll Zerona child") {
            exit = Some(status);
            break;
        }
    }

    if exit.is_none() {
        let _ = child.kill();
        exit = Some(child.wait().expect("wait for timed-out Zerona child"));
    }
    for chunk in receiver.try_iter() {
        transcript.push_str(&String::from_utf8_lossy(&chunk));
    }

    PtyRun {
        success: exit.expect("Zerona child exit status").success(),
        transcript,
    }
}

#[cfg(unix)]
fn provider_config(server_uri: &str) -> String {
    format!(
        r#"schema_version = 3

[memory]
backend = "none"

[reliability]
provider_retries = 0
provider_backoff_ms = 0

[providers.models.custom.fixture]
api_key = "fixture-placeholder"
uri = "{server_uri}"
model = "fixture-model"
wire_api = "chat_completions"
"#
    )
}

#[cfg(unix)]
#[tokio::test]
async fn real_terminal_cancel_makes_no_provider_call_or_config_write() {
    let server = MockServer::start().await;
    let config_dir = tempfile::tempdir().expect("temporary config directory");
    let config_path = config_dir.path().join("config.toml");
    let original = provider_config(&server.uri());
    std::fs::write(&config_path, &original).expect("write provider config");

    let config_dir_path = config_dir.path().to_path_buf();
    let run = tokio::task::spawn_blocking(move || {
        drive_pty(
            &config_dir_path,
            &[("You:", "quit")],
            Duration::from_secs(30),
        )
    })
    .await
    .expect("PTY task joins");

    assert!(
        run.success,
        "cancel should exit successfully\ntranscript:\n{}",
        run.transcript
    );
    assert!(run.transcript.contains("without applying"));
    assert_eq!(
        std::fs::read_to_string(&config_path).expect("read config after cancel"),
        original,
        "cancel must preserve the exact config source"
    );
    assert!(
        server
            .received_requests()
            .await
            .expect("request recording enabled")
            .is_empty(),
        "local quit must not spend a provider turn"
    );
}

#[cfg(unix)]
#[test]
fn real_terminal_refuses_stale_schema_without_running_load_time_migration() {
    let config_dir = tempfile::tempdir().expect("temporary config directory");
    let config_path = config_dir.path().join("config.toml");
    let legacy_source = "schema_version = 2\n";
    std::fs::write(&config_path, legacy_source).expect("write legacy config");
    let legacy_workspace = config_dir.path().join("workspace");
    std::fs::create_dir_all(&legacy_workspace).expect("create legacy workspace");
    std::fs::write(legacy_workspace.join("SOUL.md"), "legacy soul")
        .expect("write legacy personality");

    let run = drive_pty(config_dir.path(), &[], Duration::from_secs(30));

    assert!(
        !run.success,
        "stale schema should require explicit migration\ntranscript:\n{}",
        run.transcript
    );
    assert!(
        run.transcript.contains("Run `zeroclaw config migrate`"),
        "migration guidance should be operator-visible:\n{}",
        run.transcript
    );
    assert_eq!(
        std::fs::read_to_string(&config_path).expect("read legacy config"),
        legacy_source
    );
    assert_eq!(
        std::fs::read_to_string(legacy_workspace.join("SOUL.md"))
            .expect("legacy workspace remains"),
        "legacy soul"
    );
    assert!(!config_dir.path().join("agents/default/workspace").exists());
}

#[cfg(unix)]
#[tokio::test]
async fn config_change_ends_the_session_before_history_reaches_a_new_target() {
    let server = MockServer::start().await;
    let config_dir = tempfile::tempdir().expect("temporary config directory");
    let config_path = config_dir.path().join("config.toml");
    let original = provider_config(&server.uri());
    let changed = format!("{original}\n# external provider or policy edit\n");
    std::fs::write(&config_path, &original).expect("write provider config");

    let config_dir_path = config_dir.path().to_path_buf();
    let config_path_for_hook = config_path.clone();
    let changed_for_hook = changed.clone();
    let run = tokio::task::spawn_blocking(move || {
        drive_pty_with_hook(
            &config_dir_path,
            &[("You:", "Create a careful writing agent")],
            Duration::from_secs(30),
            move |step| {
                assert_eq!(step, 0);
                std::fs::write(&config_path_for_hook, &changed_for_hook)
                    .expect("simulate an external config edit");
            },
        )
    })
    .await
    .expect("PTY task joins");

    assert!(
        run.success,
        "detected config drift should exit cleanly\ntranscript:\n{}",
        run.transcript
    );
    assert!(
        run.transcript
            .contains("config.toml changed while Zerona was running"),
        "the operator should see why the conversation ended:\n{}",
        run.transcript
    );
    assert_eq!(
        std::fs::read_to_string(&config_path).expect("read externally edited config"),
        changed
    );
    assert!(
        server
            .received_requests()
            .await
            .expect("request recording enabled")
            .is_empty(),
        "conversation history must not cross a changed provider/config boundary"
    );
    assert!(!config_dir.path().join("agents").exists());
}

#[cfg(unix)]
#[tokio::test]
async fn real_terminal_apply_previews_then_persists_only_the_approved_agent() {
    let server = MockServer::start().await;
    let proposal = serde_json::json!({
        "agent_alias": "writer",
        "risk": "locked_down",
        "runtime": "tight",
        "memory": "markdown",
        "personality_files": [{
            "filename": "SOUL.md",
            "content": "# Soul\nWrite carefully."
        }]
    });
    let response = serde_json::json!({
        "choices": [{
            "message": {
                "role": "assistant",
                "content": format!("I have a contained draft.\nPROPOSAL: {proposal}")
            }
        }]
    });
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(response))
        .expect(1)
        .mount(&server)
        .await;

    let config_dir = tempfile::tempdir().expect("temporary config directory");
    let config_path = config_dir.path().join("config.toml");
    let original = provider_config(&server.uri());
    std::fs::write(&config_path, &original).expect("write provider config");

    let config_dir_path = config_dir.path().to_path_buf();
    let run = tokio::task::spawn_blocking(move || {
        drive_pty(
            &config_dir_path,
            &[
                ("You:", "Create a careful writing agent"),
                ("Type `apply`, `revise`, or `cancel`:", "apply"),
            ],
            Duration::from_secs(45),
        )
    })
    .await
    .expect("PTY task joins");

    assert!(
        run.success,
        "approved proposal should apply\ntranscript:\n{}",
        run.transcript
    );
    for expected in [
        "Proposed agent",
        "Agent: writer",
        "Model provider: custom.fixture",
        "Config path to update: agents.writer.memory.backend",
        "Type `apply`, `revise`, or `cancel`:",
        "Created agent `writer`",
    ] {
        assert!(
            run.transcript.contains(expected),
            "transcript omitted {expected:?}:\n{}",
            run.transcript
        );
    }

    let mut reloaded: zeroclaw_config::schema::Config =
        toml::from_str(&std::fs::read_to_string(&config_path).expect("read applied config"))
            .expect("parse applied config");
    reloaded.config_path = config_path.clone();
    reloaded.data_dir = config_dir.path().join("data");
    let agent = reloaded.agents.get("writer").expect("writer agent saved");
    assert_eq!(agent.model_provider.as_str(), "custom.fixture");
    assert_eq!(agent.risk_profile.as_str(), "locked_down");
    assert_eq!(agent.runtime_profile.as_str(), "tight");
    assert_eq!(
        agent.memory.backend,
        zeroclaw_config::multi_agent::MemoryBackendKind::Markdown
    );
    assert_eq!(
        reloaded.memory.backend, "none",
        "agent-scoped memory must not rewrite install-wide memory"
    );
    assert!(agent.channels.is_empty());
    let soul = reloaded.agent_workspace_dir("writer").join("SOUL.md");
    assert_eq!(
        std::fs::read_to_string(&soul).expect("read applied personality"),
        "# Soul\nWrite carefully."
    );
    use std::os::unix::fs::PermissionsExt as _;
    assert_eq!(
        std::fs::metadata(&soul)
            .expect("personality metadata")
            .permissions()
            .mode()
            & 0o077,
        0,
        "staged personality files must not become group/world-readable"
    );

    let requests = server
        .received_requests()
        .await
        .expect("request recording enabled");
    assert_eq!(requests.len(), 1);
    let request_body: serde_json::Value =
        serde_json::from_slice(&requests[0].body).expect("provider request JSON");
    assert!(
        request_body
            .get("tools")
            .is_none_or(serde_json::Value::is_null),
        "Zerona's real provider request must expose no tool catalogue: {request_body}"
    );
    let serialized_body = request_body.to_string();
    assert!(!serialized_body.contains("fixture-placeholder"));
    assert!(!serialized_body.contains(config_path.to_string_lossy().as_ref()));
}

#[cfg(unix)]
#[tokio::test]
async fn real_terminal_revision_loops_through_the_builtin_sop_without_tools() {
    let server = MockServer::start().await;
    let responses = std::sync::Arc::new(vec![
        serde_json::json!({
            "choices": [{
                "message": {
                    "role": "assistant",
                    "content": format!(
                        "First draft.\nPROPOSAL: {}",
                        serde_json::json!({
                            "agent_alias": "reviewer",
                            "risk": "locked_down",
                            "runtime": "tight",
                            "memory": "none",
                            "personality_files": [{
                                "filename": "SOUL.md",
                                "content": "# Soul\nBe expansive."
                            }]
                        })
                    )
                }
            }]
        }),
        serde_json::json!({
            "choices": [{
                "message": {
                    "role": "assistant",
                    "content": format!(
                        "Revised draft.\nPROPOSAL: {}",
                        serde_json::json!({
                            "agent_alias": "reviewer",
                            "risk": "locked_down",
                            "runtime": "tight",
                            "memory": "none",
                            "personality_files": [{
                                "filename": "SOUL.md",
                                "content": "# Soul\nBe terse."
                            }]
                        })
                    )
                }
            }]
        }),
    ]);
    let response_index = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with({
            let responses = responses.clone();
            let response_index = response_index.clone();
            move |_request: &wiremock::Request| {
                let index = response_index.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                ResponseTemplate::new(200).set_body_json(
                    responses
                        .get(index)
                        .cloned()
                        .unwrap_or_else(|| responses.last().unwrap().clone()),
                )
            }
        })
        .expect(2)
        .mount(&server)
        .await;

    let config_dir = tempfile::tempdir().expect("temporary config directory");
    let config_path = config_dir.path().join("config.toml");
    std::fs::write(&config_path, provider_config(&server.uri())).expect("write provider config");

    let config_dir_path = config_dir.path().to_path_buf();
    let run = tokio::task::spawn_blocking(move || {
        drive_pty(
            &config_dir_path,
            &[
                ("You:", "Create a reviewer"),
                ("Type `apply`, `revise`, or `cancel`:", "revise"),
                ("What should Zerona change?", "Make the personality terse"),
                ("Type `apply`, `revise`, or `cancel`:", "apply"),
            ],
            Duration::from_secs(45),
        )
    })
    .await
    .expect("PTY task joins");

    assert!(
        run.success,
        "revision should return to the SOP input step and apply\ntranscript:\n{}",
        run.transcript
    );
    let mut reloaded: zeroclaw_config::schema::Config =
        toml::from_str(&std::fs::read_to_string(&config_path).expect("read applied config"))
            .expect("parse applied config");
    reloaded.config_path = config_path;
    reloaded.data_dir = config_dir.path().join("data");
    assert_eq!(
        std::fs::read_to_string(reloaded.agent_workspace_dir("reviewer").join("SOUL.md"))
            .expect("read revised personality"),
        "# Soul\nBe terse."
    );

    let requests = server
        .received_requests()
        .await
        .expect("request recording enabled");
    assert_eq!(requests.len(), 2);
    for request in &requests {
        let body: serde_json::Value =
            serde_json::from_slice(&request.body).expect("provider request JSON");
        assert!(body.get("tools").is_none_or(serde_json::Value::is_null));
    }
    let second_body: serde_json::Value =
        serde_json::from_slice(&requests[1].body).expect("second provider request JSON");
    let serialized = second_body.to_string();
    assert!(serialized.contains("ZERONA_HOST_FEEDBACK"));
    assert!(serialized.contains("Make the personality terse"));
}
