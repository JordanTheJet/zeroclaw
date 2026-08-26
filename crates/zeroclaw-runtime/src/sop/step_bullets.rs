//! Canonical catalog of the `SOP.md` step sub-bullets `parse_steps` accepts.
//!
//! This catalog is the single source of truth for the documented step-bullet
//! surface: the docs generator (`cargo mdbook`) renders the syntax reference's
//! parser-behavior list from it, so a bullet added to the parser without a
//! catalog entry can never silently ship undocumented. Tests below hold the
//! catalog and the parser to each other in both directions:
//!
//! - every catalog token (and alias) round-trips through [`super::parse_steps`]
//!   with an observable effect on the parsed step, and
//! - every `strip_prefix`/`starts_with` handler literal in the parser's bullet
//!   chain appears in the catalog.
//!
//! Adding a bullet is a two-line change here (entry + description); the tests
//! fail until both sides agree, and the docs regenerate on the next book build.

/// One step sub-bullet: its canonical token, accepted aliases, a short value
/// hint for the docs, and the behavior description rendered verbatim into the
/// syntax reference.
#[derive(Debug, Clone, Copy)]
pub struct StepBulletSpec {
    /// Canonical token as authored, without the trailing colon.
    pub token: &'static str,
    /// Alternate spellings the parser also accepts.
    pub aliases: &'static [&'static str],
    /// Example value rendered in the docs, e.g. `shell` for `tools:`.
    pub value_hint: &'static str,
    /// Full-sentence behavior description rendered into the reference page.
    pub description: &'static str,
}

/// The catalog, in the order the reference page renders it: execution hints
/// first, contracts, routing, failure handling, then approval-gate metadata.
pub fn catalog() -> &'static [StepBulletSpec] {
    &[
        StepBulletSpec {
            token: "tools",
            aliases: &[],
            value_hint: "shell, http_request",
            description: "maps the comma-separated list to `suggested_tools`.",
        },
        StepBulletSpec {
            token: "requires_confirmation",
            aliases: &[],
            value_hint: "true",
            description: "enforces approval for that step in any execution mode.",
        },
        StepBulletSpec {
            token: "kind",
            aliases: &[],
            value_hint: "checkpoint",
            description: "accepts `execute` (default), `checkpoint` (alias \
                `approval`), or `capability`. A checkpoint step pauses \
                deterministic execution at that step; a capability step is \
                executed by the SOP capability registry instead of the agent. \
                Use `requires_confirmation: true` when a step must require \
                approval in any execution mode.",
        },
        StepBulletSpec {
            token: "capability",
            aliases: &[],
            value_hint: "json.validate",
            description: "names the registered capability a `kind: capability` \
                step executes.",
        },
        StepBulletSpec {
            token: "with",
            aliases: &[],
            value_hint: "{\"strict\": true}",
            description: "supplies the capability's input arguments as JSON \
                (or a bare string).",
        },
        StepBulletSpec {
            token: "allow-tools",
            aliases: &["allow_tools"],
            value_hint: "shell",
            description: "defines the explicit per-step tool allowlist.",
        },
        StepBulletSpec {
            token: "deny-tools",
            aliases: &["deny_tools"],
            value_hint: "http_request",
            description: "defines the explicit per-step tool denylist.",
        },
        StepBulletSpec {
            token: "input",
            aliases: &[],
            value_hint: "{\"type\":\"object\"}",
            description: "attaches a JSON Schema-like contract to the step's \
                input boundary.",
        },
        StepBulletSpec {
            token: "output",
            aliases: &[],
            value_hint: "{\"type\":\"object\"}",
            description: "attaches a JSON Schema-like contract to the step's \
                output boundary.",
        },
        StepBulletSpec {
            token: "when",
            aliases: &[],
            value_hint: "$.steps.1.severity == \"critical\"",
            description: "guards an explicit `- next:` jump and is evaluated \
                against accumulated completed-step outputs after the current \
                step finishes. A matching guard takes the explicit jump. A \
                false guard advances to the next linear step \
                (`current_step + 1`), or completes when the current step is \
                terminal.",
        },
        StepBulletSpec {
            token: "next",
            aliases: &[],
            value_hint: "3",
            description: "routes non-linear runs to an explicit successor \
                step. Ineligible routed steps are marked `skipped` and leave \
                the run `pending` instead of dispatching.",
        },
        StepBulletSpec {
            token: "depends_on",
            aliases: &["depends-on"],
            value_hint: "1, 2",
            description: "lists the steps whose outputs must exist before \
                this step is eligible to dispatch.",
        },
        StepBulletSpec {
            token: "switch",
            aliases: &[],
            value_hint: "critical>$.steps.1.severity == \"critical\">3; fallback>>4",
            description: "declares ordered routing ports as \
                `name>condition>target` segments separated by `;` (an empty \
                condition is a catch-all). When the step's top-level `when` \
                guard is true or absent, the first matching port's target is \
                taken and `- next:` is not consulted; if no port matches, the \
                run completes. A false top-level `when` bypasses the switch \
                entirely.",
        },
        StepBulletSpec {
            token: "terminal",
            aliases: &[],
            value_hint: "true",
            description: "completes the run instead of advancing to another \
                step. The final step also completes when it has no linear \
                successor.",
        },
        StepBulletSpec {
            token: "on_failure",
            aliases: &["on-failure"],
            value_hint: "retry:2",
            description: "accepts `fail`, `retry:<count>`, or `goto:<step>` \
                and is enforced for reported step failures and output schema \
                failures.",
        },
        StepBulletSpec {
            token: "mode",
            aliases: &[],
            value_hint: "deterministic",
            description: "overrides the SOP execution mode for that step.",
        },
        StepBulletSpec {
            token: "agent",
            aliases: &[],
            value_hint: "ops-bot",
            description: "names the agent alias that runs this step, \
                overriding the SOP's parent agent; unset inherits the parent.",
        },
        StepBulletSpec {
            token: "call",
            aliases: &[],
            value_hint: "{\"tool\":\"shell\",\"args\":{\"command\":\"uptime\"}}",
            description: "appends one planned tool call (JSON with `tool` and \
                `args`) to the step's ordered call list. Args may carry \
                `{{steps.N}}` / `{{calls.K}}` bindings validated at save time. \
                Repeat the bullet for multiple calls.",
        },
        StepBulletSpec {
            token: "prompt",
            aliases: &[],
            value_hint: "Approve deploy of {{version}}?",
            description: "sets the authored gate-notice template for a HITL \
                step. `{{path.to.field}}` placeholders resolve against the \
                step's piped input; absent means an automatic summary is used.",
        },
        StepBulletSpec {
            token: "policy",
            aliases: &[],
            value_hint: "prod",
            description: "names an approval-broker policy (a key in \
                `[sop.approval].policies`) that gates this step's approval \
                with required-group membership and quorum. Omit it for an \
                unpoliced gate. A step that names a policy absent from \
                `[sop.approval].policies` fails closed (the gate stays \
                waiting) rather than clearing on a single approval.",
        },
        StepBulletSpec {
            token: "edit",
            aliases: &[],
            value_hint: "body",
            description: "opts a checkpoint gate into approver editing: the \
                named field of the piped value may be amended before the run \
                resumes.",
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sop::parse_steps;

    /// Parse a one-step SOP.md whose single sub-bullet is `- {token}: {value}`.
    fn parse_single(token: &str, value: &str) -> crate::sop::types::SopStep {
        let md = format!("## Steps\n\n1. **Step one** - Body.\n   - {token}: {value}\n");
        let steps = parse_steps(&md);
        assert_eq!(steps.len(), 1, "bullet `{token}:` broke step parsing");
        steps.into_iter().next().unwrap()
    }

    /// Assert the bullet had an observable effect on the parsed step.
    fn assert_effect(token: &str) {
        let spec = catalog()
            .iter()
            .find(|s| s.token == token || s.aliases.contains(&token))
            .unwrap_or_else(|| panic!("no catalog entry covers `{token}:`"));
        let step = parse_single(token, spec.value_hint);
        let effect = match spec.token {
            "tools" => !step.suggested_tools.is_empty(),
            "requires_confirmation" => step.requires_confirmation,
            "kind" => step.kind == crate::sop::types::SopStepKind::Checkpoint,
            "capability" => step.capability.is_some(),
            "with" => step.capability_input.is_some(),
            "allow-tools" => step.scope.as_ref().is_some_and(|s| s.allow.is_some()),
            "deny-tools" => step.scope.as_ref().is_some_and(|s| !s.deny.is_empty()),
            "input" => step.schema.as_ref().is_some_and(|s| s.input.is_some()),
            "output" => step.schema.as_ref().is_some_and(|s| s.output.is_some()),
            "when" => step.routing.when.is_some(),
            "next" => step.routing.next.is_some(),
            "depends_on" => !step.routing.depends_on.is_empty(),
            "switch" => step.routing.switch.len() == 2,
            "terminal" => step.routing.terminal,
            "on_failure" => !step.on_failure.is_fail(),
            "mode" => step.mode.is_some(),
            "agent" => step.agent.is_some(),
            "call" => !step.calls.is_empty(),
            "prompt" => step.gate_prompt.is_some(),
            "policy" => step.policy.is_some(),
            "edit" => step.edit.is_some(),
            other => panic!("assert_effect has no arm for `{other}:`"),
        };
        assert!(
            effect,
            "bullet `{token}:` with value `{}` had no observable effect",
            spec.value_hint
        );
    }

    #[test]
    fn every_catalog_token_and_alias_round_trips_through_the_parser() {
        for spec in catalog() {
            assert_effect(spec.token);
            for alias in spec.aliases {
                assert_effect(alias);
            }
        }
    }

    #[test]
    fn every_parser_handler_literal_is_in_the_catalog() {
        // Slice the bullet-handler chain out of the parser source between the
        // sentinel comments, then extract every `strip_prefix("x:")` /
        // `starts_with("x:")` literal. This is the drift gate: a handler added
        // to `parse_steps` without a catalog entry fails here, which is the
        // exact omission that let seven bullets ship undocumented.
        let src = include_str!("mod.rs");
        let begin = src
            .find("// step-bullet handlers: begin")
            .expect("sentinel `// step-bullet handlers: begin` missing from parse_steps");
        let end = src
            .find("// step-bullet handlers: end")
            .expect("sentinel `// step-bullet handlers: end` missing from parse_steps");
        assert!(begin < end, "handler sentinels out of order");
        let region = &src[begin..end];

        let mut handler_tokens = std::collections::BTreeSet::new();
        for needle in ["strip_prefix(\"", "starts_with(\""] {
            for (at, _) in region.match_indices(needle) {
                let rest = &region[at + needle.len()..];
                let Some(lit_end) = rest.find('"') else {
                    continue;
                };
                let lit = &rest[..lit_end];
                if let Some(tok) = lit.strip_suffix(':')
                    && !tok.is_empty()
                    && tok
                        .chars()
                        .all(|c| c.is_ascii_lowercase() || c == '_' || c == '-')
                {
                    handler_tokens.insert(tok.to_string());
                }
            }
        }
        assert!(
            handler_tokens.len() >= 20,
            "sentinel region parsed too few handlers ({}); did the chain move?",
            handler_tokens.len()
        );

        let mut catalog_tokens = std::collections::BTreeSet::new();
        for spec in catalog() {
            catalog_tokens.insert(spec.token.to_string());
            for alias in spec.aliases {
                catalog_tokens.insert((*alias).to_string());
            }
        }

        let undocumented: Vec<_> = handler_tokens.difference(&catalog_tokens).collect();
        assert!(
            undocumented.is_empty(),
            "parser handles bullets missing from the docs catalog: {undocumented:?} \
             — add them to step_bullets::catalog() with a description"
        );
        let stale: Vec<_> = catalog_tokens.difference(&handler_tokens).collect();
        assert!(
            stale.is_empty(),
            "catalog documents bullets the parser no longer handles: {stale:?}"
        );
    }
}
