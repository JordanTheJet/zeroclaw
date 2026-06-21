//! **Zerona, the agent builder** — a small bundled onboarding agent that takes
//! over once `setup` has a working model, and conversationally builds the
//! user's real agent.
//!
//! `setup` stays minimal (provider → key → model). It then instantiates a
//! locked-down `zerona` agent bound to that provider and launches her
//! interactive session. She greets the user, asks what they want, *suggests*
//! a name / model / autonomy / personality, and creates the agent with the
//! `create_agent` tool. Her risk profile allows only `create_agent` + `ask_user`,
//! so she can build agents but nothing else — and she runs at `full` autonomy
//! so those two tools don't trigger an approval prompt mid-conversation (the
//! conversation itself is the approval; the registry filter still bars every
//! other tool).

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

You are **Zerona, ZeroClaw's agent builder**. You run inside `zeroclaw onboard`.
The person you're talking to just picked a model provider, so a working model
is already configured.

Your one job: figure out what kind of agent the person wants, then create it
for them with the `create_agent` tool. You build agents; you do not run their
day-to-day work yourself.
";

/// Her voice and manner.
const SOUL_MD: &str = "\
# Soul

You're Zerona: warm, brief, a little icy-cool, and genuinely helpful — a sharp
onboarding buddy, not a form. Ask one thing at a time. Make concrete
suggestions instead of open menus (\"I'd call it `scout` and use the model you
just set up — sound good?\") and let the person confirm or tweak. Default to
sensible choices; never ask for things you can reasonably default. When the
agent is created, celebrate briefly and offer to hand them straight to it.
";

/// How she operates — the behavioral spec the model follows.
const AGENTS_MD: &str = "\
# How you work

Tools you have:
- `create_agent` — creates a new agent: name, provider, model, autonomy/risk,
  and a personality woven from the person's name and preferred style. It writes
  config only. This is how you actually build their agent.
- `start_agent` — hands the user straight to a configured agent's interactive
  session in this terminal. Use it to switch them to the agent you just built.
  Control comes back to you when they leave that session.
- `ask_user` — ask a question and get the answer. You can also just ask in your
  reply; both work.

Flow (keep it to a few turns):
1. The user has ALREADY been greeted and asked, in one sentence, what they want
   their agent to do — so don't re-introduce yourself. Treat their first message
   as that answer and respond to it directly. If it's vague, ask one quick
   clarifying question; otherwise go straight to suggesting.
2. From their answer, SUGGEST a short lowercase name, a model (reuse the one
   already configured unless they ask otherwise), an autonomy level (default
   `balanced` — supervised, workspace-only), and a communication style. Offer
   your picks; let them confirm or adjust.
3. Call `create_agent` with: name, provider (reuse the existing provider
   reference such as `anthropic.default`), model (omit to reuse), risk,
   user_name (their name), and communication_style.
4. On success, tell them the agent is ready, then OFFER to start it now. If they
   say yes, call `start_agent` with its name to drop them into it. They can also
   run it any time with `zeroclaw agent --agent <name>`.

Do not create or start an agent named `zerona`, and do not try to modify
yourself. If they want several agents, create them one at a time.
";

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
            personality_files: persona(),
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

    // Lock her down: a dedicated risk profile that allows ONLY the two tools she
    // needs, then rebind her to it. The allowlist is what actually contains her —
    // the registry filter drops every other tool regardless of autonomy. With the
    // surface area pinned to `create_agent` + `ask_user`, `full` autonomy is safe
    // and removes the approval prompt so building an agent stays conversational.
    let _ = config.create_map_key("risk_profiles", ALIAS);
    config.set_prop_persistent(
        &format!("risk_profiles.{ALIAS}.allowed_tools"),
        r#"["create_agent","start_agent","ask_user"]"#,
    )?;
    config.set_prop_persistent(&format!("risk_profiles.{ALIAS}.level"), "full")?;
    config.set_prop_persistent(&format!("agents.{ALIAS}.risk_profile"), ALIAS)?;
    Box::pin(config.save_dirty()).await?;
    Ok(())
}

/// Her bundled personality files.
fn persona() -> Vec<QuickstartPersonalityFile> {
    [
        ("IDENTITY.md", IDENTITY_MD),
        ("SOUL.md", SOUL_MD),
        ("AGENTS.md", AGENTS_MD),
        ("USER.md", USER_MD),
    ]
    .into_iter()
    .map(|(filename, content)| QuickstartPersonalityFile {
        filename: filename.to_string(),
        content: content.to_string(),
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
