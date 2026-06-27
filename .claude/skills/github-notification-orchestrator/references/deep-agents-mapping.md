# Mapping to the Deep Agents pattern

This skill is a worked example of the four-component "deep agent" architecture
(planner / sub-agents / virtual filesystem / detailed system prompt), with two
extensions that make the composition novel: **skill composition** and an
**adversarial verifier loop**.

## The four components

| Component | In this skill |
|---|---|
| **Planner** | The orchestrator's Phase 2. It fetches the whole inbox once, classifies each notification by `reason` + subject `type` into an agent profile and a priority band (`references/routing.md`), and writes the routing decision to `plan.md`. Planning is cheap (one TSV read) and makes the expensive fan-out targeted. |
| **Sub-agents** | Seven profiled agents in `agents/`, each a focused specialist with its own detailed prompt, tool allow-list, and model: `pr-review-responder`, `issue-responder`, `mention-responder`, `author-activity-responder`, `ci-failure-investigator`, `verifier`, and `daily-summarizer`. One notification → one sub-agent; independent items run concurrently. |
| **Virtual filesystem** | The dated run folder `triage/<date>/` is the shared blackboard. Sub-agents don't talk to each other directly — they **coordinate through files**: the planner writes `plan.md`, each worker writes `items/NNNN-*.md`, the verifier edits those files in place, the summarizer reads them all to build `INDEX.md`, and the cross-skill `tmp/handoff.md` carries state to the specialist skills. State lives in files, so any step can be re-run and the hand-off is lossless. |
| **Detailed system prompt** | `SKILL.md` is the orchestrator's system prompt (workflow, scale discipline, safety contract); each `agents/*.md` is a sub-agent's detailed prompt. Progressive disclosure keeps each lean — the references load on demand. |

## Extension 1 — skill composition (agent-to-skill delegation)

The sub-agents draft; for deep, stateful work the orchestrator **routes to other
skills** rather than reimplementing them: PR reviews to `github-pr-review-session`,
issue-lifecycle actions to `github-issue-triage`, identity/worktree helpers from
`daily-notification-triage`. The delegation travels through the virtual
filesystem (`tmp/handoff.md`), so the specialist skill resumes with full context
and the same identity. This is the "multiple agents **and** multiple skills"
composition — see `references/skill-composition.md`.

## Extension 2 — adversarial verifier loop (agent-to-agent quality gate)

A fan-out's failure mode is a confident, wrong draft. So high-stakes drafts (PR
reviews, CI root-cause, "fixed/closed" claims) pass through a second agent — the
`verifier` (opus) — that tries to **refute** each load-bearing claim against the
source and stamps a PASS / REVISE / HOLD gate onto the report. This turns a flat
star topology (orchestrator → leaves) into a two-layer pipeline with a quality
gate, and is what lets the user trust the binder enough to act from it.

## The pipeline end to end

```
plan (planner)
  └─ fan out: one sub-agent per item, model-matched ──► items/*.md
        └─ high-stakes items ─► verifier (opus) edits the report with a gate
philosophy
  └─ route specialists ─► tmp/handoff.md ─► github-pr-review-session / github-issue-triage
        └─ summarizer (haiku) runs build_index.py ──► INDEX.md (newest→oldest, linked)
```

Every arrow is a file written to or read from the virtual filesystem — which is
exactly why the system is restartable, auditable, and composable with other
skills.
