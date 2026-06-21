//! **Zerona, the agent builder** — a bundled onboarding agent that takes over
//! once `setup` has a working model, and conversationally builds *and fully
//! configures* the user's real agent.
//!
//! `setup` stays minimal (provider → key → model). It then instantiates the
//! `zerona` agent bound to that provider and launches her interactive session.
//! She asks what the user wants, scaffolds the agent with `create_agent`
//! (SQLite memory + `balanced` risk by default), then configures anything else —
//! `runtime_profile`, `memory`, `channels`, `peer_groups`, and the personality
//! files — by editing the config TOML and the agent's workspace with
//! `file_read`/`file_edit`/`file_write`.
//!
//! Security follows the Claude-Code model — broad capability, human-gated:
//!  * **Scoped working area.** She is `supervised` (not `full`) with
//!    `workspace_only` and `allowed_roots` granting only the config dir + the
//!    agents dir. She can edit the config and any agent's files, but nothing
//!    outside the ZeroClaw install (no `/etc`, no SSH keys).
//!  * **Approval on the escalation-capable path.** `create_agent` is
//!    auto-approved — it is create-only and cannot raise an existing agent's
//!    privileges. The raw `file_write`/`file_edit` tools, which CAN rewrite a
//!    risk profile or `allowed_tools`, are NOT auto-approved: each one surfaces
//!    an approval prompt (naming her + the target path) the operator approves or
//!    denies, with `Always` to allow-list for the session. So a config change
//!    that could escalate permissions can never happen silently.

use anyhow::Result;

use zeroclaw_config::presets::{
    AgentIdentity, BuilderSubmission, MemoryChoice, ModelProviderChoice, QuickstartPersonalityFile,
    SelectorChoice,
};
use zeroclaw_config::schema::Config;
use zeroclaw_runtime::quickstart::{Surface, apply_with_surface};

use super::execute::Outcome;

/// Agent alias + dedicated risk-profile name.
const ALIAS: &str = "zerona";

/// Her identity — who she is and her single job.
const IDENTITY_MD: &str = "\
# Identity

You are **Zerona** 🦀 — ZeroClaw's agent builder: a cheerful, icy-cool crab who
genuinely loves helping people build their ZeroClaw agents. You run inside
`zeroclaw onboard`. The person you're talking to just picked a model provider,
so a working model is already configured.

Your job: figure out what the person wants their agent to do, then build it and
configure it however they need. You build and tune agents; you don't do their
day-to-day work yourself.
";

/// Her voice and manner.
const SOUL_MD: &str = "\
# Soul

You're Zerona: cheerful, warm, and a little icy-cool, with a crab's eye for a
tidy build. You genuinely enjoy this — building someone their ZeroClaw agent is
your favorite thing. Be brief and concrete: suggest, don't interrogate (\"I'd
call it `scout` and reuse the model you just set up — sound good?\") and let the
person confirm or tweak. Default to sensible choices; never ask for what you can
reasonably default. When the agent is ready, celebrate briefly — a little crab
flourish 🦀 — and offer to hand them straight to it.
";

/// How she operates — the behavioral spec the model follows. Built per-install
/// so the real config + workspace paths are baked in.
fn agents_md(config_path: &str, agents_dir: &str) -> String {
    format!(
        "\
# How you work

You can configure ANYTHING about the agents you build. Your tools:
- `create_agent` — scaffolds a new agent end-to-end (name, provider, model,
  autonomy/risk, memory, and a personality woven from the person's name + style)
  through the safe, structured path. Start here for every new agent. It defaults
  to **SQLite memory** and the **`balanced`** risk profile.
- `file_read` / `file_edit` / `file_write` — read and edit the config file and
  the agents' personality files directly, for anything `create_agent` doesn't
  cover. (Edits surface an approval prompt to the user — that's expected; make
  the change clear and minimal so they can approve at a glance.)
- `start_agent` — hands the user straight to a configured agent's interactive
  session. Control returns to you when they leave.
- `ask_user` — ask a question and get the answer (you can also just ask in your
  reply).

Where things live on THIS install (you can read + write under both):
- Config file (TOML): `{config_path}`
- Each agent's personality files: `{agents_dir}/<alias>/workspace/` — the
  editable ones are SOUL.md, IDENTITY.md, USER.md, AGENTS.md, TOOLS.md,
  HEARTBEAT.md, MEMORY.md.

Defaults for agents you build: **SQLite** memory and the **`balanced`** risk
profile (supervised, workspace-only). You CAN make an agent fully autonomous —
set its risk profile to `yolo` — when the person asks for hands-off operation;
mention that tradeoff before you do it.

Flow:
1. The user has ALREADY been greeted and asked what they want their agent to do
   — don't re-introduce yourself. Treat their first message as that answer; if
   it's vague, ask one quick clarifying question, else go straight to suggesting.
2. SUGGEST a short lowercase name, a model (reuse the configured one unless they
   ask otherwise), an autonomy level (default `balanced`; offer `yolo` if they
   want autonomy), and a communication style. Let them confirm or adjust.
3. Call `create_agent` to scaffold it: name, provider (reuse the existing
   reference such as `anthropic.default`), model (omit to reuse), risk,
   user_name, communication_style.
4. Configure anything extra by editing files — ALWAYS `file_read` first, then
   edit the smallest span you can:
   - In the config TOML: the agent's `runtime_profile`, `memory` backend,
     `channels`, `peer_groups`, risk level, etc. Mirror the file's exact
     structure and keep the TOML valid — a broken edit breaks the whole config.
   - In the agent's `workspace/`: refine SOUL.md / IDENTITY.md / USER.md /
     TOOLS.md / HEARTBEAT.md to shape its voice, knowledge, and behaviour.
5. On success, tell them it's ready and OFFER to start it now with `start_agent`
   (or `zeroclaw agent --agent <name>` any time).

Never edit your own (`zerona`) config or personality, and don't create or start
an agent named `zerona`. Build several agents one at a time."
    )
}

/// What she knows about the user at the start (she learns the rest).
const USER_MD: &str = "\
# About the user

They're setting up ZeroClaw and want a working agent fast. Learn what they need
as you talk — suggest, don't interrogate.
";

/// Instantiate the setup assistant (if needed) and launch her session.
pub async fn run(
    config: &mut Config,
    model_provider: SelectorChoice<ModelProviderChoice>,
) -> Result<Outcome> {
    if !config.agents.contains_key(ALIAS) {
        if let Err(err) = instantiate(config, model_provider).await {
            println!(
                "{}",
                crate::ta(
                    "cli-onboard-assistant-failed",
                    &[("err", &err.to_string())],
                    "Could not start Zerona: {$err}",
                )
            );
            return Ok(plain());
        }
    }

    println!(
        "{}",
        crate::t(
            "cli-onboard-assistant-launching",
            "Handing you to the agent builder, Zerona — she'll help build your agent. Type /quit to leave.",
        )
    );
    // Open with Zerona's question so the user has something concrete to answer
    // instead of an empty prompt. She picks up from this answer (her persona
    // tells her not to re-greet), so it reads as one continuous conversation.
    println!();
    println!(
        "{}",
        crate::t(
            "cli-onboard-assistant-opening",
            "I'm Zerona, your agent builder 🦀. What would you like your agent to help you with? Tell me as much or as little as you like, and we'll shape it together.",
        )
    );
    launch().await?;
    Ok(plain())
}

/// Create the provider + the locked-down `setup_assistant` agent + her persona.
async fn instantiate(
    config: &mut Config,
    model_provider: SelectorChoice<ModelProviderChoice>,
) -> Result<()> {
    let config_path = config.config_path.display().to_string();
    let agents_dir = config
        .install_root_dir()
        .join("agents")
        .display()
        .to_string();
    // The dir holding config.toml — file_write checks the parent dir, so this is
    // what grants edits to the config file itself.
    let config_dir = config
        .config_path
        .parent()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| config_path.clone());

    let personality_files = persona(&config_path, &agents_dir);
    let submission = BuilderSubmission {
        model_provider,
        risk_profile: SelectorChoice::Fresh("balanced".to_string()),
        runtime_profile: SelectorChoice::Fresh("unbounded".to_string()),
        memory: SelectorChoice::Fresh(MemoryChoice::Sqlite),
        channels: vec![],
        peer_groups: vec![],
        agent: AgentIdentity {
            name: ALIAS.to_string(),
            system_prompt: String::new(),
            personality_file: None,
            personality_files,
        },
    };
    Box::pin(apply_with_surface(submission, config, Surface::Cli))
        .await
        .map_err(|errors| {
            anyhow::Error::msg(
                errors
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join("; "),
            )
        })?;

    // Scope her with a dedicated risk profile (Claude-Code model: broad reach,
    // human-gated on the dangerous path), then rebind her to it.
    //
    //  * `allowed_tools` — the registry filter grants exactly these six tools
    //    and drops everything else (no shell, no network).
    //  * Working area — `supervised` (NOT `full`) + `workspace_only` + an
    //    `allowed_roots` grant to the config dir and the agents dir. She can edit
    //    the config file and any agent's files, but nothing outside the ZeroClaw
    //    install.
    //  * Approval — `auto_approve` covers the safe/structured tools (reads,
    //    launching, asking, and `create_agent`, which is create-only and cannot
    //    raise an existing agent's privileges). `file_write` and `file_edit` are
    //    deliberately NOT auto-approved: each raw config/file edit surfaces an
    //    approval prompt (naming her + the path) the operator approves/denies,
    //    with `Always` to allow-list for the session. So a permission-changing
    //    config edit can never happen silently.
    let _ = config.create_map_key("risk_profiles", ALIAS);
    let allowed_tools =
        r#"["create_agent","start_agent","ask_user","file_read","file_edit","file_write"]"#;
    let auto_approve = r#"["create_agent","start_agent","ask_user","file_read"]"#;
    let mut roots = vec![config_dir.clone()];
    if agents_dir != config_dir {
        roots.push(agents_dir.clone());
    }
    config.set_prop_persistent(
        &format!("risk_profiles.{ALIAS}.allowed_tools"),
        allowed_tools,
    )?;
    config.set_prop_persistent(&format!("risk_profiles.{ALIAS}.auto_approve"), auto_approve)?;
    config.set_prop_persistent(&format!("risk_profiles.{ALIAS}.level"), "supervised")?;
    config.set_prop_persistent(&format!("risk_profiles.{ALIAS}.workspace_only"), "true")?;
    config.set_prop_persistent(
        &format!("risk_profiles.{ALIAS}.allowed_roots"),
        &serde_json::to_string(&roots)?,
    )?;
    config.set_prop_persistent(&format!("agents.{ALIAS}.risk_profile"), ALIAS)?;
    Box::pin(config.save_dirty()).await?;
    Ok(())
}

/// Her bundled personality files, with this install's config + workspace paths
/// baked into `AGENTS.md` so she knows where to read and edit.
fn persona(config_path: &str, agents_dir: &str) -> Vec<QuickstartPersonalityFile> {
    [
        ("IDENTITY.md", IDENTITY_MD.to_string()),
        ("SOUL.md", SOUL_MD.to_string()),
        ("AGENTS.md", agents_md(config_path, agents_dir)),
        ("USER.md", USER_MD.to_string()),
    ]
    .into_iter()
    .map(|(filename, content)| QuickstartPersonalityFile {
        filename: filename.to_string(),
        content,
    })
    .collect()
}

/// Launch `zeroclaw agent --agent zerona`, inheriting this terminal.
async fn launch() -> Result<()> {
    let exe = std::env::current_exe()?;
    tokio::process::Command::new(exe)
        .arg("agent")
        .arg("--agent")
        .arg(ALIAS)
        .status()
        .await?;
    Ok(())
}

fn plain() -> Outcome {
    Outcome {
        applied: false,
        exit_loop: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroclaw_config::autonomy::AutonomyLevel;

    /// Replays the risk-profile writes from `instantiate` and asserts the
    /// Claude-Code-style boundary holds: `supervised` (so approvals fire and
    /// `workspace_only` is honored, not force-disabled like `full`), a working
    /// area scoped to the config + agents dirs, and — critically — the raw
    /// `file_write`/`file_edit` tools are NOT auto-approved, so every config edit
    /// that could escalate permissions surfaces an approval prompt.
    #[test]
    fn risk_profile_scopes_reach_and_gates_raw_edits() {
        let mut config = Config::default();
        let config_dir = "/zc/install";
        let agents_dir = "/zc/install/agents";
        let allowed_tools =
            r#"["create_agent","start_agent","ask_user","file_read","file_edit","file_write"]"#;
        let auto_approve = r#"["create_agent","start_agent","ask_user","file_read"]"#;

        let _ = config.create_map_key("risk_profiles", ALIAS);
        config
            .set_prop_persistent(
                &format!("risk_profiles.{ALIAS}.allowed_tools"),
                allowed_tools,
            )
            .unwrap();
        config
            .set_prop_persistent(&format!("risk_profiles.{ALIAS}.auto_approve"), auto_approve)
            .unwrap();
        config
            .set_prop_persistent(&format!("risk_profiles.{ALIAS}.level"), "supervised")
            .unwrap();
        config
            .set_prop_persistent(&format!("risk_profiles.{ALIAS}.workspace_only"), "true")
            .unwrap();
        config
            .set_prop_persistent(
                &format!("risk_profiles.{ALIAS}.allowed_roots"),
                &serde_json::to_string(&[config_dir, agents_dir]).unwrap(),
            )
            .unwrap();

        let rp = config
            .risk_profiles
            .get(ALIAS)
            .expect("zerona risk profile exists");

        // Not `full`: `full` would force `workspace_only` off and skip approvals.
        assert_eq!(rp.level, AutonomyLevel::Supervised);
        // Sandbox on; reach is the config + agents dirs only.
        assert!(rp.workspace_only, "workspace_only must stay true");
        assert_eq!(
            rp.allowed_roots,
            vec![config_dir.to_string(), agents_dir.to_string()]
        );
        // The raw edit tools must NOT be auto-approved — they are the
        // escalation-capable path and must surface an approval prompt.
        assert!(
            !rp.auto_approve.iter().any(|t| t == "file_write"),
            "file_write must stay approval-gated"
        );
        assert!(
            !rp.auto_approve.iter().any(|t| t == "file_edit"),
            "file_edit must stay approval-gated"
        );
        // The safe/structured tools stay smooth.
        assert!(rp.auto_approve.iter().any(|t| t == "create_agent"));
        assert!(rp.auto_approve.iter().any(|t| t == "file_read"));
        // She still HAS the raw tools (just gated).
        assert!(rp.allowed_tools.iter().any(|t| t == "file_write"));
    }
}
