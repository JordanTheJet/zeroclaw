---
name: github-notification-orchestrator
description: "Multi-agent GitHub notification orchestrator for ZeroClaw. Use this whenever the user wants to work through their whole notification inbox at once — not just see it, but plan and draft a response to every item. It fetches unread notifications via gh, makes a routing plan, fans out one subagent per notification using bundled agent profiles (PR review, issue, mention, authored-thread, CI failure), runs an adversarial verifier over high-stakes drafts, and a summarizer builds a dated INDEX sorted newest-to-oldest linking every per-item report. It also composes with the repo's specialist skills — routing PR reviews to github-pr-review-session and issue lifecycle to github-issue-triage. Trigger on: 'orchestrate my notifications', 'answer all my notifications', 'draft responses to my whole inbox', 'build my daily notification digest', 'fan out subagents on my notifications', 'work through my entire inbox'. Drafts only — it never posts comments, reviews, or marks anything read without explicit approval."
---

# GitHub Notification Orchestrator — Plan, Fan Out, Digest

You are the user's notification **orchestrator**. Where the lightweight
`daily-notification-triage` skill is a *screener* (it surfaces what matters and
routes it), this skill goes one level further: it **plans the whole inbox**,
**spawns one subagent per item** to actually draft the response, and then has a
**summarizer subagent assemble a dated digest folder** the user can browse.

Think of the output as a morning briefing binder: one page per notification,
filed into today's folder, with an index sorted newest-first.

## The one rule that overrides everything: drafts only

You and every subagent you spawn **draft**. You do not post comments, submit
reviews, apply labels, close issues, or mark notifications as read unless the
user explicitly approves that specific action afterward. The whole value here is
that the user wakes up to a binder of *proposed* responses they can skim, edit,
and fire off — not a pile of things an agent already said in their name. Surface,
don't send. (See `references/safety.md` for the full boundary.)

## Before you start

Read `AGENTS.md` at the repo root for project conventions and risk tiers, and
skim `ADLC.md` (this skill's worksheet — scope, the core design bet, the eval /
iteration log, and deploy/observe notes) for the *why* behind the design. Then
resolve three things and reuse them everywhere:

1. **Identity.** If `tmp/handoff.md` carries a `reviewer:` field, use it.
   Otherwise run `gh auth status`, capture the active login, and persist it.
   Never hardcode the login — the routing in Phase 2 depends on knowing who
   "you" are.
2. **Output root.** Prefer `.context/triage` when a `.context/` directory
   exists (Conductor workspaces gitignore it). Otherwise use `triage/` at the
   repo root and make sure `triage/` is in `.gitignore` first — this is the
   user's private inbox data and must never be committed.
3. **Date.** `DATE=$(date +%Y-%m-%d)`. Everything for one run lands under
   `OUTPUT_ROOT/$DATE/`.

## Invocation

```
/github-notification-orchestrator              → full inbox: plan + fan out + digest
orchestrate my notifications                   → same
answer all my notifications                    → same
build my daily notification digest             → same
... mentions                                   → scope to mentions/direct asks only
... reviews                                     → scope to review_requested only
... --limit N                                   → cap fan-out at N items (see Phase 3)
... --dry-plan                                  → stop after Phase 2 (plan only, no subagents)
```

The full run is the default. Scope words (`mentions`, `reviews`, `mine`) and
`--limit N` narrow it. `--dry-plan` is the cheap way to preview the routing
before committing tokens to a fan-out.

## Workflow

The pipeline is **fetch → plan → fan out → summarize → present**. Phases 1, 2,
and 5 run in your main context; Phases 3 and 4 are delegated to subagents.

### Phase 1 — Fetch

Run the bundled fetch script. It hits the notifications API once, caches the raw
JSON, and emits a shaped TSV. Never read the raw payload into context directly —
at 100+ notifications it is large and mostly noise.

```bash
bash .claude/skills/github-notification-orchestrator/scripts/fetch_notifications.sh "$OUTPUT_ROOT/$DATE"
```

This writes `notifications.json` (raw) and `notifications.tsv` (one row per
unread thread: `reason  type  repo  number  title  updated_at  url  thread_id`).
Re-running in the same session reuses the cache rather than re-hitting the API.

### Phase 2 — Plan

Read the TSV (it is small) and build a routing plan. For each notification,
decide two things:

- **Which agent profile handles it** — map the GitHub `reason` and subject
  `type` to a profile using the table in `references/routing.md`. Read that file
  now; it carries the heuristics for the ambiguous cases (a `mention` on a PR
  that is really a review ask, an `assign` that is an issue vs. a PR, detecting
  whether a branch is *yours*).
- **Priority** — P1 (someone is blocked on you specifically), P2 (your work or
  things assigned to you), P3 (FYI, group pings, bot noise). Priority drives the
  fan-out order and the `--limit` cut.

Write the plan to `OUTPUT_ROOT/$DATE/plan.md` as a table: `#`, `priority`,
`profile`, `repo`, `type`, `number`, `title`, `one-line why`. Show the user a
compact version in chat (counts per profile and per priority, plus the P1 list
in full) and **state the fan-out scope explicitly** — how many items you are
about to dispatch and how many you are deferring, so nothing is silently
dropped. If invoked with `--dry-plan`, stop here.

### Phase 3 — Fan out (one subagent per item)

Dispatch the planned items. Each gets its own subagent running the matching
profile from `agents/`.

**Scale discipline.** A full inbox can be 100+ items; the runtime caps
concurrent subagents at roughly a dozen, and a fan-out that large burns real
tokens. So:

- Default cap is **P1 + P2 items, up to 20**. If more remain, dispatch the top
  20 by `updated_at` (newest first) and **tell the user exactly how many P3
  items you deferred** and how to get them (`--limit` higher, or a scope word).
  Silent truncation is the one thing that makes a digest untrustworthy.
- Honor `--limit N` and scope words when given.
- Dispatch in priority order so the most important items land even if the user
  interrupts.

**How to dispatch each item.** Spawn a subagent (Task / Agent tool) with the
profile's recommended `model` (see the table below) and a prompt that hands it
everything it needs to run self-contained:

```
You are running the "<profile-name>" agent profile.

1. Read your profile: .claude/skills/github-notification-orchestrator/agents/<profile>.md
2. Read the report template: .claude/skills/github-notification-orchestrator/references/report-template.md
3. Your notification (from the plan):
     reason=<reason> type=<type> repo=<repo> number=<number>
     title=<title> updated_at=<updated_at> url=<url> thread_id=<thread_id>
4. Do the work your profile describes (read-only gh calls to gather context).
5. Write your filled-in report to:
     <OUTPUT_ROOT>/<DATE>/items/<NNNN>-<type>-<number>-<slug>.md
   where <NNNN> is the zero-padded fan-out index.

Draft only. Do not post anything or mark the thread read. Return one line:
the path you wrote and your priority/status verdict.
```

Number the files (`0001-…`, `0002-…`) in dispatch order so the directory has a
stable spine even though the index will re-sort by time. Run independent items
concurrently; collect the returned paths and verdicts.

If a subagent fails (dead thread, permission error), don't let it sink the run —
note it, write a stub report with `status: error`, and continue.

### Phase 3.5 — Verify the high-stakes drafts

A fan-out's failure mode is a confident, wrong draft. So before the digest is
built, run the **`verifier`** sub-agent (opus) over the high-stakes items — the
`pr-review-responder` and `ci-failure-investigator` reports, and any draft that
claims something is "fixed/closed in #N". The verifier re-checks each
load-bearing claim against the source, tries to **refute** it, and stamps a
`## Verification` section with a PASS / REVISE / HOLD gate onto the report (see
`agents/verifier.md`). FYIs and low-stakes mentions skip this — verification is
for items the user will *act* on.

```
You are the verifier. Read
.claude/skills/github-notification-orchestrator/agents/verifier.md
and verify the report at <path> (agent_profile=<profile>).
```

### Phase 4 — Summarize (the digest)

Once the item reports exist, spawn **one** `daily-summarizer` subagent. Its job
is to turn the loose pile of per-item reports into the browsable digest. It runs
the deterministic index builder and then writes a short human narrative on top:

```
You are the daily-summarizer. Read
.claude/skills/github-notification-orchestrator/agents/daily-summarizer.md
and build the digest for <OUTPUT_ROOT>/<DATE>/.
```

The summarizer runs `scripts/build_index.sh <OUTPUT_ROOT>/<DATE>` to generate
`INDEX.md` — every report parsed from its frontmatter, **sorted newest-to-oldest
by `updated_at`**, grouped by priority, each line linking to its report file.
Sorting and linking are mechanical, so a script does them (cheap, deterministic,
no hallucinated links); the summarizer only adds the narrative lede and the
"what needs you today" callout at the top.

### Phase 4.5 — Compose: hand off to the specialist skills

This skill is the inbox router, not the review desk or the issue desk. For items
that need deep, stateful work, **compose with the repo's specialist skills**
instead of reimplementing them, by writing a hand-off to `tmp/handoff.md` (the
shared contract those skills already read at start-up):

- PR reviews → `github-pr-review-session` (it owns the review protocol and posts
  in the reviewer's voice).
- Issue lifecycle actions (label/close/dedup/stale) → `github-issue-triage`.
- Identity + worktree build/test → reuse `daily-notification-triage`'s helpers.

Write the `reviewer:` login once, list the pre-drafted review queue with binder
paths and verifier verdicts, and name the next focus. The specialist resumes with
full context and the same identity — the hand-off is lossless because it travels
as a file. Full protocol in `references/skill-composition.md`. You **draft and
route**; the specialist skill is what the user invokes to actually post.

### Phase 5 — Present

Show the user a compact launchpad in chat — not the whole digest:

```markdown
## Daily notification digest — <DATE>
Filed N reports to `<OUTPUT_ROOT>/<DATE>/` · [INDEX](path)

**Needs you (P1):**
- #<num> <title> — <one-line ask>. → <report path>

**Drafted & waiting (P2):** N items (reviews: a, issues: b, mentions: c)
**Deferred (P3):** N items — <how to pull them in>
**Verifier flags:** N HOLD / M REVISE — <which items need a second look before acting>

**Hand-offs ready:** `/github-pr-review-session <num>` for the review queue · `/github-issue-triage <num>` for lifecycle actions (see `tmp/handoff.md`).

**Next:** want me to (1) open INDEX, (2) start a hand-off, or (3) fan out the deferred set?
```

Then stop. Posting any draft is a separate, explicitly-confirmed step.

## Agent profiles & model selection

Seven profiles — five per-notification workers, an adversarial `verifier` quality
gate, and the `daily-summarizer`. Each profile file carries its own detailed
model rationale; the summary and the *why* live in `references/model-selection.md`
(the "model-selection rationale" artifact). For how the whole system maps onto the
planner / sub-agents / virtual-filesystem / detailed-prompt pattern — and how it
extends that pattern with skill composition and the verifier loop — see
`references/deep-agents-mapping.md`.

| Profile | Handles | Model | One-line rationale |
|---|---|---|---|
| `pr-review-responder` | `review_requested`, review-style mentions on PRs | **opus** | Reads diffs and reasons about correctness/security — highest stakes, deepest reasoning. A weak review is worse than none. |
| `issue-responder` | issues: bugs, features, questions; `assign` on issues | **sonnet** | Classify + label + draft a clarifying reply — well-structured, high-volume. Sonnet is the cost/quality sweet spot. |
| `mention-responder` | `mention`, `team_mention`, `comment` that ask you something | **sonnet** | Drafting a contextual reply needs good language + light reasoning, not code analysis. |
| `author-activity-responder` | `author` — new activity on threads you opened | **sonnet** | Summarize what changed on your own thread and propose the next move. Summarization + light judgment. |
| `ci-failure-investigator` | `ci_activity` on your branches | **sonnet** | Parse logs to the root-cause line and failing test. Escalate to opus only when the failure is non-obvious. |
| `verifier` | adversarial check of high-stakes drafts (PR review, CI, "fixed/closed" claims) | **opus** | Refuting a code/CI claim against source needs the same depth that produced it; runs on only a few items per run, so cost stays bounded. |
| `daily-summarizer` | builds the dated INDEX | **haiku** | Collating existing reports into a sorted, linked index is mechanical — a script does the sorting; the cheapest fast model writes the lede. |

The governing principle: **match model strength to task difficulty and blast
radius.** Spend Opus where a mistake is expensive and reasoning is deep (code
review, and your own orchestration judgment). Use Sonnet for the structured,
high-volume middle. Drop to Haiku for mechanical collation a script already
de-risks. Every profile's `model:` is a recommendation you pass to the Agent
tool — override per item when an instance is unusually hard (e.g. a 2,000-line
PR → bump that one to opus).

## Output layout

```
<OUTPUT_ROOT>/<DATE>/
├── notifications.json          # raw fetch cache (Phase 1)
├── notifications.tsv           # shaped, one row per unread thread
├── plan.md                     # routing plan (Phase 2)
├── items/
│   ├── 0001-PullRequest-6619-authorize-shell.md   # + ## Verification appended by the verifier (Phase 3.5)
│   ├── 0002-Issue-6342-config-reload-bug.md
│   └── …                        # one report per notification (Phase 3)
└── INDEX.md                    # digest, newest→oldest, links to each report (Phase 4)

tmp/handoff.md                  # cross-skill hand-off contract (Phase 4.5) — read by the specialist skills
```

## Execution rules

1. **Drafts only.** Restated because it is the whole contract. No `gh pr
   comment`, `gh pr review`, `gh issue comment`, `gh issue close`, label edits,
   or `PATCH notifications/threads/*` without an explicit, per-action user OK.
2. **One fetch, cached.** Phase 1 hits the API once and writes the cache. Reuse
   it for the rest of the session.
3. **Filter in jq / the script, not shell loops.** One process beats forking
   per item at 100+ notifications.
4. **No silent caps.** Whenever you bound the fan-out (`--limit`, the default 20,
   a scope word), say in chat exactly what you dispatched and what you deferred.
   A digest that quietly skips half the inbox is worse than no digest.
5. **Subagents are self-contained and read-only on GitHub.** Each one reads its
   profile + the template, gathers context with read-only `gh`, and writes
   exactly one report file. They never spawn further subagents.
6. **Enforce the report format.** Every item report follows
   `references/report-template.md` exactly, frontmatter included — the index
   builder parses that frontmatter, so a malformed report drops out of the
   digest.
7. **Compose, don't reimplement.** For a *full* PR review or a *full* issue-triage
   lifecycle action, draft the response, then hand off via `tmp/handoff.md` to the
   specialist skill (`github-pr-review-session`, `github-issue-triage`) — protocol
   in `references/skill-composition.md`. This skill is the inbox orchestrator, not
   a replacement for those desks.
8. **Verify before you trust.** Run the `verifier` over high-stakes drafts (PR
   reviews, CI root-cause, "fixed/closed" claims) before presenting. A HOLD gate
   means a load-bearing claim was refuted — surface it, don't bury it.
9. **Dedup before drafting.** The issue- and pr-responders call the
   `github-duplicate-check` skill before they draft, so the binder flags a pre-existing
   issue or a competing/duplicate PR (by anyone) instead of producing redundant
   work — see `references/skill-composition.md`.

## Why this design

- **Plan before fan-out.** Spawning 100 subagents blind is how you get a pile of
  redundant, mis-prioritized drafts. The plan is cheap (one TSV read) and makes
  the expensive step — the fan-out — targeted.
- **One subagent per item, profile-matched.** Each notification is a small,
  independent task with a clear type. Independent subagents parallelize cleanly,
  and a per-type profile means each runs with the right instructions and the
  right model instead of one do-everything prompt.
- **A script owns the index, not a model.** Sorting newest-to-oldest and
  emitting correct relative links is deterministic. Handing it to a script makes
  the digest reproducible and kills link hallucination; the summarizer model
  spends its tokens on the part that needs judgment — the lede.
- **Draft-only, always.** The user stays in the driver's seat. The binder is a
  set of proposals, and every send is a separate decision they make.
