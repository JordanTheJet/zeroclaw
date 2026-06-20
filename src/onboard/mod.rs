//! Chat-based onboarding: the default `zeroclaw onboard` experience.
//!
//! Talk to ZeroClaw in plain language to inspect the install, configure
//! providers and agents, run guided setup, and get pointed at the next
//! step. Architecture (ported from OpenClaw's conversational setup helper):
//!
//! * [`overview`] — resolved-on-demand snapshot of the install.
//! * [`operation`] — closed command vocabulary + a deterministic parser.
//! * [`planner`] — LLM that maps free-form input to one allowed command,
//!   reached only when the deterministic parser fails and re-validated
//!   through the same parser, so model text never executes directly.
//! * [`execute`] — approval-gated executor over existing ZeroClaw surfaces.
//!
//! Three modes: interactive chat (default), `--message` one-shot, and
//! `--json` overview dump.

mod execute;
mod operation;
mod overview;
mod planner;
mod setup;

use std::io::IsTerminal;

use anyhow::Result;
use console::style;

use zeroclaw_config::schema::Config;

use operation::Operation;
use overview::Overview;

/// Entry point for `zeroclaw onboard`.
///
/// * `json` — print the overview as JSON and exit.
/// * `message` — resolve+run one request and exit (non-interactive).
/// * `yes` — auto-approve persistent actions (pairs with `message`).
pub async fn run(
    config: &mut Config,
    message: Option<String>,
    json: bool,
    yes: bool,
) -> Result<()> {
    if json {
        let overview = Overview::build(&*config).await;
        println!("{}", serde_json::to_string_pretty(&overview)?);
        return Ok(());
    }

    if let Some(msg) = message {
        return Box::pin(run_once(config, &msg, yes)).await;
    }

    Box::pin(run_interactive(config)).await
}

/// One-shot: resolve a single request and run it. Persistent operations are
/// only applied with `--yes`; otherwise their plan is printed.
async fn run_once(config: &mut Config, message: &str, yes: bool) -> Result<()> {
    let overview = Overview::build(&*config).await;
    let op = resolve(config, message, &overview).await;

    if op.is_persistent() && !yes {
        execute::print_plan(&op);
        let flag = style("--yes").cyan().to_string();
        println!(
            "{}",
            crate::ta(
                "cli-onboard-rerun-yes",
                &[("flag", &flag)],
                "Re-run with {$flag} to apply."
            )
        );
        return Ok(());
    }
    let approved = yes || !op.is_persistent();
    Box::pin(execute::execute(config, op, approved)).await?;
    Ok(())
}

/// Interactive chat loop. Requires a TTY on both stdin and stderr (dialoguer
/// reads keys from stdin and renders prompts on stderr).
async fn run_interactive(config: &mut Config) -> Result<()> {
    if !std::io::stdin().is_terminal() || !std::io::stderr().is_terminal() {
        anyhow::bail!(
            "{}",
            crate::t(
                "cli-onboard-needs-tty",
                "`zeroclaw onboard` is interactive and needs a terminal on stdin and stderr. \
                 Run it from an interactive shell, or use `zeroclaw onboard --message \"<request>\"` \
                 for a single non-interactive command.",
            )
        );
    }

    let mut overview = Overview::build(&*config).await;
    print_banner(&overview);
    println!();
    println!("{}", overview.format());
    println!();

    loop {
        let input: String = dialoguer::Input::new()
            .with_prompt(crate::t("cli-onboard-prompt", "you"))
            .allow_empty(true)
            .interact_text()?;
        let trimmed = input.trim();
        if trimmed.is_empty() {
            continue;
        }

        let op = resolve(config, trimmed, &overview).await;

        // Quit before doing any work.
        if let Operation::None {
            exit: true,
            message,
        } = &op
        {
            println!("{message}");
            break;
        }

        let outcome = if op.is_persistent() {
            execute::print_plan(&op);
            let approve = dialoguer::Confirm::new()
                .with_prompt(crate::t("cli-onboard-apply-prompt", "Apply this change?"))
                .default(false)
                .interact()?;
            if approve {
                Box::pin(execute::execute(config, op, true)).await?
            } else {
                println!("{}", crate::t("cli-onboard-skipped", "Skipped."));
                continue;
            }
        } else {
            execute::execute(config, op, true).await?
        };

        if outcome.exit_loop {
            break;
        }
        // Persistent changes can move the install's state; refresh grounding.
        if outcome.applied {
            overview = Overview::build(&*config).await;
        }
        println!();
    }

    Ok(())
}

/// Resolve user input to an operation: deterministic parse first, LLM planner
/// only on an unrecognized request. The planner's command is re-parsed here,
/// so it can never yield anything outside the command vocabulary.
async fn resolve(config: &Config, input: &str, overview: &Overview) -> Operation {
    let op = operation::parse(input);
    if !matches!(op, Operation::None { .. }) {
        return op;
    }
    // Don't burn an LLM call on quit/exit (no-model is handled in the planner,
    // which returns None when nothing is configured).
    if matches!(&op, Operation::None { exit: true, .. }) {
        return op;
    }

    if let Some(plan) = planner::plan(config, input, overview).await {
        let planned = operation::parse(&plan.command);
        if !matches!(planned, Operation::None { .. }) {
            // Planner output is untrusted model text — strip control/escape
            // characters before echoing it to the terminal.
            if let Some(reply) = &plan.reply {
                println!("{}", style(sanitize_model_text(reply)).dim());
            }
            println!(
                "{}",
                style(format!(
                    "[planner:{}] → {}",
                    sanitize_model_text(&plan.model_label),
                    sanitize_model_text(&plan.command)
                ))
                .dim()
            );
            return planned;
        }
    }
    op
}

/// Strip control/escape characters from model-generated text so it can't
/// inject terminal escape sequences when echoed.
fn sanitize_model_text(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).collect()
}

fn print_banner(overview: &Overview) {
    let title = crate::t("cli-onboard-banner-title", "ZeroClaw onboarding assistant");
    println!("{}", style(title).bold().cyan());
    let intro = if overview.configured() {
        crate::t(
            "cli-onboard-banner-intro-configured",
            "Tell me what to change or check — your install already has a working agent.",
        )
    } else {
        crate::t(
            "cli-onboard-banner-intro-fresh",
            "Tell me what you want, or say `setup` and I'll walk you through your first agent.",
        )
    };
    println!("{}", style(intro).dim());
    let help = crate::t(
        "cli-onboard-banner-help",
        "Type `help` for commands, or `quit` to leave.",
    );
    println!("{}", style(help).dim());
}
