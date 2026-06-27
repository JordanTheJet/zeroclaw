# Skill composition — routing across skills, not just agents

This skill is the **inbox router**. For deep, stateful work it does **not**
reimplement the specialist desks — it **composes** with the repo's other skills
and hands the work over with full context. That hand-off is the skill-
composition layer: agent-to-skill delegation through a shared file contract.

The same philosophy the lightweight `daily-notification-triage` skill follows —
"the triage skill is just the inbox; it routes work to the right specialist" —
applies here, one level up: the orchestrator plans and pre-drafts across the
*whole* inbox, then routes each class of work to the skill that owns it.

## The skills it composes with

| Notification class | Compose with | What the orchestrator hands over |
|---|---|---|
| `review_requested`, code-focused PR mentions | **`github-pr-review-session`** | The pre-review binder entry (diff read, findings tagged, verifier verdict) + a review queue in `tmp/handoff.md`. The specialist owns the posting protocol and posts in the reviewer's voice. |
| Issue lifecycle actions (label/close/dedup/stale) | **`github-issue-triage`** | The triage call + drafted comment from `issue-responder`, plus the issue number. The specialist enforces the RFC stale policy and authority bounds and executes the lifecycle action. |
| Identity + worktree build/test | **`daily-notification-triage`** helpers | Reuse its `reviewer:` resolution and `/tmp` worktree workflow instead of duplicating them. |
| Any issue/PR, *before* drafting | **`github-prior-art`** | Nothing is handed over — the `issue-responder` and `pr-review-responder` **call** its `prior_art_search.sh` to dedup (open+closed issues *and* PRs, by others) before drafting, so the binder flags a duplicate issue or a competing/duplicate PR instead of producing redundant work. It in turn hands lifecycle action to `github-issue-triage`. |

The orchestrator never re-implements those protocols — that would create drift
against the single source of truth. It drafts, then points.

## The shared contract: `tmp/handoff.md` (a virtual-filesystem blackboard)

Cross-skill state lives in one file that every participant reads and writes.
Both `github-pr-review-session` and `daily-notification-triage` already read it
at session start, so the orchestrator just has to write it well:

```markdown
reviewer: <login>            # resolved once; specialists reuse it (no redundant gh auth)
generated_by: github-notification-orchestrator
date: <YYYY-MM-DD>

## Review queue (pre-drafted — see binder)
- #6619 — pr-review-responder drafted · verifier: REVISE · binder: triage/<date>/items/0001-...md
- #8173 — pre-drafted · binder: ...

## Next focus
#6619 — run /github-pr-review-session 6619 (pre-review notes in the binder entry)

## Issue lifecycle
- #7025 — closed/fixed via #7245; for sign-off/close → /github-issue-triage 7025
```

Because the binder reports and the handoff are plain files, the specialist skill
picks up exactly where the orchestrator left off — same identity, same pre-read
context, no re-fetch. The file *is* the agent-to-agent channel.

## The hand-off protocol

1. The per-item sub-agent drafts its binder entry as usual (`items/*.md`).
2. For items routed to a specialist, the orchestrator appends a line to
   `tmp/handoff.md`: the number, the binder path, and (if a verifier ran) its
   verdict.
3. The orchestrator presents the digest and, for each hand-off, **names the
   exact specialist invocation** the user runs next (`/github-pr-review-session
   6619`). It does **not** invoke the posting skill itself — that skill posts
   under the user's account, so the user initiates it (see `safety.md`).
4. The specialist skill reads `tmp/handoff.md`, reuses `reviewer:`, loads the
   pre-review binder entry, and takes over.

## Why compose instead of absorb

- **Single source of truth.** `github-pr-review-session` owns the review
  protocol and the posting voice; `github-issue-triage` owns the lifecycle and
  stale policy. Re-implementing either here would drift the moment they change.
- **Right tool, right step.** The orchestrator is good at breadth (plan the
  whole inbox, pre-draft in parallel). The desks are good at depth (one PR, done
  to protocol). Composing gets both.
- **The hand-off is lossless** because it travels as files, not as a re-summary.
