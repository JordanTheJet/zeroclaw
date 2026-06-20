//! Execute a resolved [`Operation`] against the live config.
//!
//! Read-only operations print and return. Persistent operations are only
//! applied when `approved` is true (the loop and one-shot paths gate this);
//! when not approved they print the plan and apply nothing. Every config
//! write goes through `set_prop_persistent` + `save_dirty` (for direct
//! property edits) or the quickstart apply path (for `setup`) — there is no
//! other sanctioned write path, and nothing here caches config state.
//!
//! User-facing text routes through `crate::t`/`crate::ta` (Fluent `cli-onboard-*`
//! keys); leading indentation stays in the `println!` format string so the
//! localized prose lives entirely in the catalogue.

use std::io::IsTerminal;

use anyhow::{Context, Result};
use console::style;

use zeroclaw_config::schema::Config;

use super::operation::{GatewayAction, Operation};
use super::overview::Overview;

/// Hand off to the agent loop by running `zeroclaw agent --agent <alias>` as a
/// child that inherits this terminal (and `ZEROCLAW_CONFIG_DIR`). Control
/// returns to the onboard loop when the agent session ends.
async fn launch_agent(alias: &str) -> Result<()> {
    let exe = std::env::current_exe().context("could not locate the zeroclaw binary")?;
    tokio::process::Command::new(exe)
        .arg("agent")
        .arg("--agent")
        .arg(alias)
        .status()
        .await
        .context("could not launch the agent")?;
    Ok(())
}

/// Result of executing one operation.
pub struct Outcome {
    /// A persistent change was applied to disk.
    pub applied: bool,
    /// The interactive loop should exit after this operation.
    pub exit_loop: bool,
}

impl Outcome {
    fn plain() -> Self {
        Self {
            applied: false,
            exit_loop: false,
        }
    }
    fn applied() -> Self {
        Self {
            applied: true,
            exit_loop: false,
        }
    }
}

/// Run `op`. `approved` must be true for persistent operations to take effect.
pub async fn execute(config: &mut Config, op: Operation, approved: bool) -> Result<Outcome> {
    match op {
        Operation::None { message, exit } => {
            println!("{message}");
            Ok(Outcome {
                applied: false,
                exit_loop: exit,
            })
        }

        Operation::Help => {
            print_help();
            Ok(Outcome::plain())
        }

        Operation::Greeting => {
            println!(
                "{}",
                crate::t(
                    "cli-onboard-greeting",
                    "Hi! I help you set up and run ZeroClaw. Try `setup` to create an agent, `status` to see what's configured, or `help` for everything I can do.",
                )
            );
            Ok(Outcome::plain())
        }

        Operation::Overview => {
            let overview = Overview::build(&*config).await;
            println!("{}", overview.format());
            Ok(Outcome::plain())
        }

        Operation::Doctor => {
            crate::doctor::run(&*config).await?;
            Ok(Outcome::plain())
        }

        Operation::Models => {
            crate::doctor::run_configured_models(&*config, None, false).await?;
            Ok(Outcome::plain())
        }

        Operation::Agents => {
            let overview = Overview::build(&*config).await;
            if overview.agents.is_empty() {
                println!(
                    "{}",
                    crate::t(
                        "cli-onboard-agents-none",
                        "No agents configured yet. Run `setup` to create one.",
                    )
                );
            } else {
                println!("{}", crate::t("cli-onboard-agents-header", "Agents:"));
                for a in &overview.agents {
                    let model = a
                        .model
                        .clone()
                        .unwrap_or_else(|| crate::t("cli-onboard-agent-inherited", "(inherited)"));
                    let state = if a.enabled {
                        String::new()
                    } else {
                        format!(" {}", crate::t("cli-onboard-agent-disabled", "[disabled]"))
                    };
                    println!(
                        "  - {}",
                        crate::ta(
                            "cli-onboard-agent-row",
                            &[
                                ("alias", &a.alias),
                                ("provider", &a.model_provider),
                                ("model", &model),
                                ("state", &state),
                            ],
                            "{$alias} | provider={$provider} | model={$model}{$state}",
                        )
                    );
                }
            }
            Ok(Outcome::plain())
        }

        Operation::GatewayStatus => {
            let overview = Overview::build(&*config).await;
            let gw_state = if overview.gateway_reachable {
                crate::t("cli-onboard-reachable", "reachable")
            } else {
                crate::t("cli-onboard-not-reachable", "not reachable")
            };
            println!(
                "{}",
                crate::ta(
                    "cli-onboard-gateway-line",
                    &[("state", &gw_state), ("url", &overview.gateway_url)],
                    "Gateway: {$state} ({$url})",
                )
            );
            let svc_state = if overview.service_running {
                crate::t("cli-onboard-running", "running")
            } else {
                crate::t("cli-onboard-not-running", "not running")
            };
            println!(
                "{}",
                crate::ta(
                    "cli-onboard-service-line",
                    &[("state", &svc_state)],
                    "Service: {$state}",
                )
            );
            if !overview.gateway_reachable {
                let cmd = style("zeroclaw daemon").cyan().to_string();
                println!(
                    "{}",
                    crate::ta(
                        "cli-onboard-gateway-start-hint",
                        &[("cmd", &cmd)],
                        "Start it with: {$cmd}",
                    )
                );
            }
            Ok(Outcome::plain())
        }

        Operation::ValidateConfig => {
            let overview = Overview::build(&*config).await;
            if overview.config_issues.is_empty() {
                let glyph = style("✓").green().to_string();
                println!(
                    "{}",
                    crate::ta(
                        "cli-onboard-config-valid",
                        &[("glyph", &glyph), ("path", &overview.config_path)],
                        "{$glyph} config is valid ({$path})",
                    )
                );
            } else {
                let glyph = style("✗").red().to_string();
                println!(
                    "{}",
                    crate::ta(
                        "cli-onboard-config-issues",
                        &[("glyph", &glyph)],
                        "{$glyph} config has issues:",
                    )
                );
                for issue in &overview.config_issues {
                    println!("  - {issue}");
                }
                println!(
                    "{}",
                    crate::t(
                        "cli-onboard-run-doctor",
                        "Run `doctor` for the full diagnostic report.",
                    )
                );
            }
            Ok(Outcome::plain())
        }

        Operation::Gateway { action } => {
            // Lifecycle control runs the installed OS service / daemon, which
            // is outside onboarding scope — surface the exact command instead
            // of driving service management mid-setup.
            let cmd = match action {
                GatewayAction::Start => crate::t(
                    "cli-onboard-gateway-cmd-start",
                    "zeroclaw service start   (or `zeroclaw daemon` to run in the foreground)",
                ),
                GatewayAction::Stop => {
                    crate::t("cli-onboard-gateway-cmd-stop", "zeroclaw service stop")
                }
                GatewayAction::Restart => crate::t(
                    "cli-onboard-gateway-cmd-restart",
                    "zeroclaw service restart",
                ),
            };
            let styled = style(cmd.as_str()).cyan().to_string();
            println!(
                "{}",
                crate::ta(
                    "cli-onboard-gateway-run",
                    &[("action", action.as_str()), ("cmd", &styled)],
                    "To {$action} the gateway, run: {$cmd}",
                )
            );
            if matches!(action, GatewayAction::Stop | GatewayAction::Restart) {
                println!(
                    "{}",
                    crate::t(
                        "cli-onboard-gateway-service-note",
                        "(that command targets the installed service — check `zeroclaw service status` first)",
                    )
                );
            }
            Ok(Outcome::plain())
        }

        Operation::TalkToAgent { agent } => {
            let overview = Overview::build(&*config).await;
            let target = agent
                .filter(|a| overview.agents.iter().any(|s| &s.alias == a))
                .or_else(|| {
                    let enabled: Vec<&str> = overview
                        .agents
                        .iter()
                        .filter(|a| a.enabled)
                        .map(|a| a.alias.as_str())
                        .collect();
                    (enabled.len() == 1).then(|| enabled[0].to_string())
                });
            match target {
                Some(alias) => {
                    let interactive =
                        std::io::stdin().is_terminal() && std::io::stderr().is_terminal();
                    let launch = interactive
                        && dialoguer::Confirm::new()
                            .with_prompt(crate::ta(
                                "cli-onboard-talk-confirm",
                                &[("alias", &alias)],
                                "Start agent {$alias} now?",
                            ))
                            .default(true)
                            .interact()
                            .unwrap_or(false);
                    if launch {
                        println!(
                            "{}",
                            crate::ta(
                                "cli-onboard-talk-launching",
                                &[("alias", &alias)],
                                "Starting {$alias} — exit the agent to come back here.",
                            )
                        );
                        launch_agent(&alias).await?;
                    } else {
                        let cmd = style(format!("zeroclaw agent --agent {alias}"))
                            .cyan()
                            .to_string();
                        println!(
                            "{}",
                            crate::ta(
                                "cli-onboard-talk-start",
                                &[("cmd", &cmd)],
                                "Start your agent with: {$cmd}",
                            )
                        );
                    }
                }
                None if overview.agents.is_empty() => {
                    println!(
                        "{}",
                        crate::t(
                            "cli-onboard-talk-none",
                            "No agents configured yet. Run `setup` first.",
                        )
                    );
                }
                None => {
                    let cmd = style("zeroclaw agent --agent <alias>").cyan().to_string();
                    let list = overview
                        .agents
                        .iter()
                        .map(|a| a.alias.as_str())
                        .collect::<Vec<_>>()
                        .join(", ");
                    println!(
                        "{}",
                        crate::ta(
                            "cli-onboard-talk-pick",
                            &[("cmd", &cmd), ("list", &list)],
                            "Pick one and run: {$cmd} (configured: {$list})",
                        )
                    );
                }
            }
            Ok(Outcome::plain())
        }

        Operation::Setup => {
            // Setup self-gates (TTY check) and asks for its own approval after
            // collecting the (minimal) choices, so it is invoked directly
            // rather than through the generic persistent-op approval.
            Box::pin(super::setup::run(config)).await
        }

        Operation::SetDefaultModel { reference } => {
            let op = Operation::SetDefaultModel {
                reference: reference.clone(),
            };
            if !approved {
                print_plan(&op);
                return Ok(Outcome::plain());
            }
            let Some((prov_part, model)) = reference.split_once('/') else {
                println!(
                    "{}",
                    crate::t(
                        "cli-onboard-model-usage",
                        "Use the form `set default model <family>/<model-id>` (e.g. anthropic/claude-opus-4-8).",
                    )
                );
                return Ok(Outcome::plain());
            };
            let (family, alias) = prov_part.split_once('.').unwrap_or((prov_part, "default"));
            let model = model.trim();
            if model.is_empty() {
                println!(
                    "{}",
                    crate::t("cli-onboard-model-empty", "No model id given.")
                );
                return Ok(Outcome::plain());
            }
            if config.providers.models.find(family, alias).is_none() {
                let provref = format!("{family}.{alias}");
                println!(
                    "{}",
                    crate::ta(
                        "cli-onboard-provider-missing",
                        &[("provider", &provref)],
                        "No provider `{$provider}` is configured. Run `setup` to add one first.",
                    )
                );
                return Ok(Outcome::plain());
            }
            let path = format!("providers.models.{family}.{alias}.model");
            config.set_prop_persistent(&path, model)?;
            Box::pin(config.save_dirty()).await?;
            let glyph = style("✓").green().to_string();
            println!(
                "{}",
                crate::ta(
                    "cli-onboard-set-model-ok",
                    &[("glyph", &glyph), ("path", &path), ("model", model)],
                    "{$glyph} set {$path} = {$model}",
                )
            );
            Ok(Outcome::applied())
        }

        Operation::ConfigSet { path, value } => {
            let op = Operation::ConfigSet {
                path: path.clone(),
                value: value.clone(),
            };
            if !approved {
                print_plan(&op);
                return Ok(Outcome::plain());
            }
            config.set_prop_persistent(&path, &value)?;
            Box::pin(config.save_dirty()).await?;
            let glyph = style("✓").green().to_string();
            println!(
                "{}",
                crate::ta(
                    "cli-onboard-set-ok",
                    &[("glyph", &glyph), ("path", &path)],
                    "{$glyph} set {$path}",
                )
            );
            Ok(Outcome::applied())
        }
    }
}

/// Print the approval plan for a persistent operation.
pub fn print_plan(op: &Operation) {
    let glyph = style("?").yellow().to_string();
    let desc = op.describe();
    println!(
        "{}",
        crate::ta(
            "cli-onboard-plan",
            &[("glyph", &glyph), ("desc", &desc)],
            "{$glyph} Plan: {$desc}.",
        )
    );
}

fn print_help() {
    println!(
        "{}",
        crate::t(
            "cli-onboard-help-intro",
            "I can run these for you (just say it in plain language):",
        )
    );
    println!(
        "  {}",
        crate::t(
            "cli-onboard-help-inspect",
            "Inspect:  status · overview · doctor · models · agents · gateway status · validate config",
        )
    );
    println!(
        "  {}",
        crate::t(
            "cli-onboard-help-change",
            "Change:   setup · set default model <family>/<model> · config set <path> <value>",
        )
    );
    println!(
        "  {}",
        crate::t(
            "cli-onboard-help-go",
            "Go:       talk to agent · help · quit"
        )
    );
    println!(
        "{}",
        crate::t(
            "cli-onboard-help-note",
            "Changes are previewed and need your approval before they apply.",
        )
    );
}
