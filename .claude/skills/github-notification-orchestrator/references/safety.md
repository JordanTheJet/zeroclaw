# Safety boundary — drafts only

This skill reads your GitHub inbox and **writes drafts to local files**. It does
not act on GitHub on your behalf. That boundary is the whole reason the digest
is trustworthy: every item in the binder is a *proposal* you can read, edit, and
decide on — not something an agent already said or did in your name.

## What every agent in this skill MAY do

- Read notifications (`gh api notifications`).
- Read thread context: PR diffs, issue bodies, comments, CI logs — all via
  **read-only** `gh` calls (`gh pr view`, `gh issue view`, `gh api <url>`,
  `gh run view`).
- Write report files and the index **inside the run's output folder**.
- Optionally build/test a PR branch in a throwaway worktree (read-only w.r.t.
  the repo's history — it never pushes).

## What NO agent in this skill may do without explicit, per-action approval

- `gh pr comment` / `gh issue comment` — posting a comment.
- `gh pr review` (approve / request-changes / comment) — submitting a review.
- `gh pr merge`, `gh issue close`, `gh issue edit`, label/assignee/milestone
  edits — mutating issue or PR state.
- `gh api -X PATCH notifications/threads/*` or `PUT notifications` — marking
  notifications read.
- `git push`, `gh pr create` — creating or moving branches/PRs.
- Any other state-changing call to GitHub or the repo.

## How a "send" happens

Posting a draft is a **separate, explicit step the user initiates** after
reading the binder. The flow is always: orchestrator presents the digest →
user picks a specific draft and says "post this" → the orchestrator (or the
relevant specialist skill) shows the exact command and the exact text, the user
confirms, and only then is one action taken. Batching ("post all of these") is
allowed only when the user explicitly asks for the batch and the count is shown
first.

## Why this matters

GitHub actions are outward-facing and hard to reverse — a posted review pings
maintainers, a wrong label triggers automation, a premature "marked read" buries
something the user needed. The cost of a wrong autonomous action is much higher
than the cost of one extra confirmation click. So the skill optimizes for the
user staying in control, and treats its own output as a first draft, not a
decision.
