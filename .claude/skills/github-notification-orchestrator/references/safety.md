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

Three deterministic shippers carry out a send (no LLM in the posting path):
- `scripts/ship_accepted.sh` — posts the `REPLY` block as a plain **comment**
  (acts on `status: accepted`; dry-run unless `--post`).
- `scripts/ship_review.sh` — submits a formal **PR review**. The **verdict is a
  ship-time `--verdict` flag the human supplies**, never read from agent-written
  frontmatter — so injected PR content can't stage an Approve. Reviews are always
  explicit: `--only` must resolve to exactly one draft, there is no cron path, the
  self-review check fails *closed*, and `approve`/`request-changes` require a
  deterministic **two-phase `--confirm <nonce>`**.
- `scripts/ship_pr.sh` — opens a **draft PR** from your fork (assigned issues).

**Residual risk — the real boundary is the worker sandbox.** The per-profile
worker agents run with a full shell and the user's `gh` token, so a fully
prompt-injected worker could call `gh pr review --approve` (or any write) directly,
bypassing these shippers. The shippers harden the *normal* human path; they are not
a containment boundary against a compromised worker. To close that gap, scope the
workers' `gh` token to read-only (or restrict their shell) — then the shippers
become the only sanctioned write path. Treat `approve`/`request-changes` as opt-in.

## Why this matters

GitHub actions are outward-facing and hard to reverse — a posted review pings
maintainers, a wrong label triggers automation, a premature "marked read" buries
something the user needed. The cost of a wrong autonomous action is much higher
than the cost of one extra confirmation click. So the skill optimizes for the
user staying in control, and treats its own output as a first draft, not a
decision.
