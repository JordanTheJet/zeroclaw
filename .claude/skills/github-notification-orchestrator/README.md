# github-notification-orchestrator

**Hackathon Lane 3 — Most Innovative Use of Multiple Agents and Skills.**

A multi-agent system that works through your *entire* GitHub notification inbox:
it **plans** the inbox, **fans out one sub-agent per notification** to draft a
response, runs an **adversarial verifier** over the high-stakes drafts, **composes
with the repo's specialist skills** to hand off deep work, and a **summarizer**
assembles a dated digest sorted newest-to-oldest. It drafts; it never posts.

> Built from scratch as an [agentskills.io](https://agentskills.io)-spec skill
> (`SKILL.md` + bundled `agents/`, `references/`, `scripts/`). Also satisfies
> Lane 1 — it is dual-eligible — but the design target is Lane 3.
>
> Full development lifecycle — scope, design bet, eval/iteration log, deploy &
> observe — is in [`ADLC.md`](ADLC.md).

---

## Why it's a Lane 3 entry

| Lane 3 asks for… | How this delivers |
|---|---|
| **Multi-agent orchestration** | A planner classifies 100+ notifications and fans out one model-matched sub-agent per item. |
| **Agent-to-agent delegation** | A second **`verifier`** agent (opus) adversarially re-checks high-stakes drafts before they're trusted — a two-layer pipeline with a quality gate, not a flat star. |
| **Skill composition** | Composes **five skills**: hands PR reviews to `github-pr-review-session` and issue-lifecycle actions to `github-issue-triage` (via a shared `tmp/handoff.md` contract), reuses `daily-notification-triage`'s identity/worktree helpers, and calls `github-prior-art` to dedup against pre-existing issues/PRs before drafting. |

### Mapped to the Deep Agents pattern (planner / sub-agents / virtual filesystem / detailed prompt)

| Component | Here |
|---|---|
| **Planner** | Orchestrator Phase 2 → `plan.md` (routes each notification by `reason` + type → profile + priority). |
| **Sub-agents** | 7 profiled agents in `agents/`, each with its own prompt, tool allow-list, and model. |
| **Virtual filesystem** | The dated `triage/<date>/` folder is the blackboard — agents coordinate **only through files** (`plan.md`, `items/*.md`, `INDEX.md`, `tmp/handoff.md`), so every step is restartable and the cross-skill hand-off is lossless. |
| **Detailed system prompt** | `SKILL.md` (orchestrator) + each `agents/*.md` (sub-agent). |

Two extensions make it novel: **skill composition** (`references/skill-composition.md`)
and the **adversarial verifier loop** (`agents/verifier.md`). Full write-up in
`references/deep-agents-mapping.md`.

---

## Pipeline

```
Phase 1  fetch        scripts/fetch_notifications.sh  → notifications.json/tsv (read-only gh)
Phase 2  plan         classify + prioritize           → plan.md
Phase 3  fan out      one sub-agent per item          → items/NNNN-*.md   (concurrent, model-matched)
Phase 3.5 verify      verifier (opus) refutes claims  → ## Verification: PASS/REVISE/HOLD
Phase 4  summarize    daily-summarizer (haiku)        → INDEX.md (build_index.py: newest→oldest, linked)
Phase 4.5 compose     route to specialist skills      → tmp/handoff.md
Phase 5  present       compact launchpad in chat
```

## The agents & model selection

The rationale (the Lane-1 "model-selection" artifact) is in
`references/model-selection.md`. The principle: **match model strength to task
difficulty and blast radius; use the cheapest model that clears the bar.**

| Agent | Model | Why |
|---|---|---|
| `pr-review-responder` | **opus** | Reads diffs, reasons about correctness/security — highest stakes. |
| `verifier` | **opus** | Refuting a code/CI claim needs the depth that produced it. |
| `issue-responder` | **sonnet** | Structured, high-volume triage — the cost/quality sweet spot. |
| `mention-responder` | **sonnet** | Drafting a contextual reply — language + light reasoning. |
| `author-activity-responder` | **sonnet** | Summarize new activity, propose the next move. |
| `ci-failure-investigator` | **sonnet** | Parse logs to root cause; escalate hard cases to opus. |
| `daily-summarizer` | **haiku** | Mechanical collation — a *script* does the sort, so the cheapest model writes the lede. |

## Safety — drafts only

Every agent is **read-only on GitHub** and writes drafts to local files. Nothing
is posted, reviewed, labeled, closed, or marked-read without an explicit,
per-action user OK. Posting is always a separate step the user initiates (and for
deep work, the specialist skill they invoke). See `references/safety.md`.

---

## Live demo — `examples/run-2026-06-27/`

A **real** end-to-end run against a 145-notification inbox (account `JordanTheJet`,
repo `zeroclaw-labs/zeroclaw`). The bundle contains the shaped input
(`notifications.tsv`), the `plan.md`, all five per-item reports, the verifier's
`## Verification` sections, the cross-skill `handoff.md`, and the final `INDEX.md`.

Real outcomes from that run:
- **PR #6619** — the opus reviewer recommended *request-changes* because the latest
  push **regressed the build**; the **verifier independently confirmed** both
  compile errors against the live CI logs *and* the source tree (Gate: PASS).
- **Issue #5808** — correctly upgraded to **P1**: a contributor verified the fix and
  is waiting on the author's greenlight; a ready-to-send reply is drafted.
- **CI on `JordanTheJet/dream-mode`** — root-caused to a missing `#[group]` attribute;
  verifier confirmed the later push fixed it **and caught a minor overstatement** in
  the draft's test-count framing.
- **Issue #7025** — routed to `github-issue-triage` (closed/fixed → sign-off).
- **Deferred, not dropped:** ~13 fork-sync CI failures + the bulk of 70 review
  requests are surfaced in aggregate (the skill never silently caps).

---

## Running it

In a Claude Code session with the skill installed and `gh` authenticated:

```
orchestrate my notifications          # full inbox: plan → fan out → verify → digest
... reviews                           # scope to review requests
... --limit 30                        # cap the fan-out (no silent caps — deferrals are reported)
... --dry-plan                        # stop after planning (cheap preview)
```

The two bundled scripts are independently runnable and tested:

```
bash scripts/fetch_notifications.sh <out-dir>     # read-only fetch → JSON + shaped TSV
python3 scripts/build_index.py <out-dir>          # deterministic INDEX.md (newest→oldest, linked)
```

## Layout

```
SKILL.md                      orchestrator (planner + workflow + safety contract)
agents/                       7 sub-agent profiles (5 workers + verifier + summarizer)
references/
  routing.md                  notification → profile mapping + heuristics
  report-template.md          enforced per-item output format (frontmatter = index sort key)
  model-selection.md          per-role model rationale (Lane-1 artifact)
  skill-composition.md        cross-skill hand-off protocol (Lane-3 core)
  deep-agents-mapping.md      mapping onto the Deep Agents four components
  safety.md                   draft-only boundary
scripts/
  fetch_notifications.sh      read-only gh fetch → cache + shaped TSV
  build_index.py              deterministic digest builder (no deps)
examples/run-2026-06-27/      a real end-to-end run (input → binder → digest → hand-off)
```

## Validation

Conforms to the agentskills.io `SKILL.md` spec (kebab-case name ≤64, description
≤1024 with no angle brackets, only allowed frontmatter keys). Validate with:

```
skills-ref validate .claude/skills/github-notification-orchestrator
```
