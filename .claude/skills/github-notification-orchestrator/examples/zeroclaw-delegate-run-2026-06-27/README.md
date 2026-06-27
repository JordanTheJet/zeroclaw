# Example run — ZeroClaw-native delegate fan-out (2026-06-27)

A real run of the **scheduled (ZeroClaw) path**, captured verbatim. No Claude
Code involved: the orchestrator agent `gh_notif` reads new notifications, routes
each by reason/type, and hands it to one of six per-profile sub-agents through
ZeroClaw's built-in `delegate` tool. Delegation is **synchronous** (one sub-agent
at a time), bounded by the per-tick cap (5 newest). Everything here is
**draft-only** — read-only `gh`, local markdown out, nothing posted.

## What happened

Five new notifications were routed to **five distinct sub-agents**, then the PR
draft was handed to the adversarial **verifier**:

| File | Notification | reason / type | → sub-agent | model |
|---|---|---|---|---|
| [`items/0001-…7928…md`](items/0001-PullRequest-7928-feat-wasi-initial-wasm-component-model-plugin-host-code.md) | PR #7928 | review_requested / PR | `gh_notif_pr_reviewer` | opus |
| [`items/0002-…8033…md`](items/0002-PullRequest-8033-feat-onboard-two-path-onboard-tree-wired-end-to-end-llm-deterministic-over-rpc-and-cli.md) | PR #8033 | mention / PR | `gh_notif_mention` | sonnet |
| [`items/0003-CheckSuite…md`](items/0003-CheckSuite--sync-fork-with-upstream-workflow-run-failed-for-master-branch.md) | fork-sync CI | ci_activity / CheckSuite | `gh_notif_ci` | sonnet |
| [`items/0004-…5808…md`](items/0004-Issue-5808-bug-default-32k-context-budget-is-exceeded-by-system-prompt-tool-definitions-on-iteration-1-causing-perpetual-preemptive-trim.md) | Issue #5808 | author / Issue | `gh_notif_author` | sonnet |
| [`items/0005-…8360…md`](items/0005-Issue-8360-tracker-v0-8-3-provider-and-native-tool-message-serialization.md) | Issue #8360 | assign / Issue | `gh_notif_issue` | sonnet |

The **verifier** (`gh_notif_verifier`, opus) then re-checked the PR #7928 draft
against the live PR and appended a *"Verifier verdict"* section to `0001` (see the
bottom of that file).

Orchestrator's final one-line report:

```
delegated 5 (agents used: gh_notif_pr_reviewer, gh_notif_mention, gh_notif_ci,
gh_notif_author, gh_notif_issue), verified 1, deferred 0,
binder=…/workspace/gh-notif/triage/2026-06-27. Nothing was posted.
```

## Reproduced on the scheduled cron

The same flow was confirmed running **autonomously from the daemon's 30-minute
poll cron** (not just an interactive invocation): it routed new notifications to
the matching sub-agents, the verifier appended its verdict to the PR draft, and
the delta script committed state — all draft-only.

## How the fan-out is authorized

- `gh_notif` (orchestrator) risk profile: `delegation_policy = "allow"` + a
  `delegates` roster naming the six sub-agents; `delegate` is in the poll cron's
  `allowed_tools`.
- The six sub-agents share `gh_notif_worker`: identical to `gh_notif` on every
  axis **except** `delegation_policy = "forbidden"` (they cannot re-delegate or
  escalate — ZeroClaw enforces a no-escalation guard at delegate time).

See [`../../references/deployment-zeroclaw.md`](../../references/deployment-zeroclaw.md)
and [`deploy/zeroclaw-cron.template.toml`](deploy/zeroclaw-cron.template.toml) for
the full wiring.
