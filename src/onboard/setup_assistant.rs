//! **Zerona, the agent builder** — a bundled onboarding agent that takes over
//! once `setup` has a working model, and conversationally builds *and fully
//! configures* the user's real agent.
//!
//! `setup` stays minimal (provider → key → model). It then instantiates the
//! `zerona` agent bound to that provider and launches her interactive session.
//! She asks what the user wants, scaffolds the agent with `create_agent`
//! (SQLite memory + `balanced` risk by default), then configures anything else
//! by editing the config TOML and the agent's personality files directly with
//! `file_read`/`file_edit`/`file_write`.
//!
//! She runs at `full` autonomy: this both removes the approval prompt so the
//! build stays conversational AND (since `full` disables `workspace_only`) lets
//! her file tools reach the config file and other agents' workspaces. Her
//! allowlist is the boundary — it grants exactly the builder + file tools and
//! the registry filter drops everything else. **This makes Zerona a
//! high-privilege agent: she can read/write config + personality files across
//! the install with no approval gate**, which is the deliberate tradeoff for a
//! self-invoked, conversational agent builder.

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
- `file_read` / `file_edit` / `file_write` — read and edit any config or
  personality file directly. Use these AFTER scaffolding to configure things
  `create_agent` doesn't cover.
- `start_agent` — hands the user straight to a configured agent's interactive
  session. Control returns to you when they leave.
- `ask_user` — ask a question and get the answer (you can also just ask in your
  reply).

Where things live on THIS install:
- Config file (TOML): `{config_path}`
- Each agent's personality files: `{agents_dir}/<alias>/workspace/` — the
  editable ones are SOUL.md, IDENTITY.md, USER.md, AGENTS.md, TOOLS.md,
  HEARTBEAT.md, MEMORY.md.

Defaults for agents you build: **SQLite** memory and the **`balanced`** risk
profile (supervised, workspace-only). You CAN make an agent fully autonomous —
set its risk profile to `yolo` — when the person wants hands-off, no-approval
operation; mention that tradeoff before you do it.

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
     TOOLS.md / HEARTBEAT.md to shape its voice, knowledge, and behavior.
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
            "I'm Zerona, your agent builder. In one sentence, what do you want your agent to help with? For example: \"triage my GitHub notifications,\" \"draft replies to support emails,\" or \"summarize articles I save to read later.\"",
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
    let personality_files = persona(config);
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

    // Scope her: a dedicated risk profile granting exactly the builder + file
    // tools, then rebind her to it. The allowlist is the boundary — the registry
    // filter drops everything else. `full` autonomy both removes the approval
    // prompt (so the build stays conversational) and disables `workspace_only`,
    // which is what lets her file tools reach the config file and other agents'
    // workspaces. She is therefore a high-privilege agent by design.
    let _ = config.create_map_key("risk_profiles", ALIAS);
    config.set_prop_persistent(
        &format!("risk_profiles.{ALIAS}.allowed_tools"),
        r#"["create_agent","start_agent","ask_user","file_read","file_edit","file_write"]"#,
    )?;
    config.set_prop_persistent(&format!("risk_profiles.{ALIAS}.level"), "full")?;
    config.set_prop_persistent(&format!("agents.{ALIAS}.risk_profile"), ALIAS)?;
    Box::pin(config.save_dirty()).await?;
    Ok(())
}

/// Her bundled personality files, with this install's config + workspace paths
/// baked into `AGENTS.md` so she knows where to read and edit.
fn persona(config: &Config) -> Vec<QuickstartPersonalityFile> {
    let config_path = config.config_path.display().to_string();
    let agents_dir = config
        .install_root_dir()
        .join("agents")
        .display()
        .to_string();
    [
        ("IDENTITY.md", IDENTITY_MD.to_string()),
        ("SOUL.md", SOUL_MD.to_string()),
        ("AGENTS.md", agents_md(&config_path, &agents_dir)),
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
