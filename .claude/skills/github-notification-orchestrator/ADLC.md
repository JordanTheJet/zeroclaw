# ADLC Worksheet — github-notification-orchestrator

> Agent-Development-Lifecycle worksheet for the multi-agent GitHub-notification
> system. Read this for the *why* behind the design and the iteration log;
> `SKILL.md` is the operating manual, `references/model-selection.md` is the
> model rationale, `references/deep-agents-mapping.md` maps it to the
> planner/sub-agents/virtual-filesystem/detailed-prompt pattern.

## 1. Scope

**Request it serves:** "Go through my GitHub notifications, plan, draft a
response to each, and give me a dated digest." **Returns:** a dated binder
(`triage/<date>/`) of one markdown report per notification + a newest-first
`INDEX.md` linking them all + a cross-skill `tmp/handoff.md` — **all draft-only**.

**Concrete end-to-end success case:** 145 unread notifications on
`zeroclaw-labs/zeroclaw` → fetch → plan (route each by reason→profile→priority) →
fan out one sub-agent per item → adversarially verify the high-stakes drafts →
build the digest. In the real run, the opus reviewer caught that PR #6619's latest
push **regressed the build** (request-changes), and #5808 was auto-upgraded to P1
because a contributor was waiting on the author.

**Out of scope (explicit):**
- **Acting on GitHub** — no posting comments/reviews, no label/close/merge, no
  mark-read. The skill *drafts*; the human sends. (See `references/safety.md`.)
- **Full PR-review protocol & issue lifecycle** — delegated to the specialist
  skills (`github-pr-review-session`, `github-issue-triage`), not reimplemented.
- **Real-time webhook ingestion (Piece B)** — evaluated and descoped; polling is
  the right default for a personal inbox (see `references/deployment-zeroclaw.md`).

## 2. Design

**Agents (9 roles):** a **planner** (the orchestrator, main loop) → **7 profiled
sub-agents** (`pr-review-responder`, `issue-responder`, `mention-responder`,
`author-activity-responder`, `ci-failure-investigator` + a `verifier` quality
gate + a `daily-summarizer`) → and it **composes 4 other skills**
(`github-pr-review-session`, `github-issue-triage`, `daily-notification-triage`,
`github-duplicate-check`).

**Tools / data source:** read-only `gh` CLI against the **GitHub notifications
API**; deterministic bash/python scripts; the Claude Code Agent/Task tool for
fan-out (or ZeroClaw `DelegateTool` when deployed).

**Key design rules:**
- **Draft-only** is the overriding contract — every agent is read-only on GitHub.
- **Offline/fixture fallback:** `fetch_notifications.sh` caches `notifications.json`;
  `build_index.py` is fully offline; `examples/run-2026-06-27/` is a real fixture.
- **A script owns the mechanical parts** (sorting newest→oldest, links, dedup
  gathering); models only do judgment.

**Model choice (see `references/model-selection.md`):** **opus** for code review +
the verifier + orchestration (deep reasoning, high blast radius); **sonnet** for
structured high-volume drafting (issues, mentions, CI); **haiku** for the
mechanical digest collation. One line: *match model strength to task difficulty
and blast radius; use the cheapest model that clears the bar.*

**Core design bet:** a **deterministic index builder + an adversarial verifier
loop** make a fan-out of dozens of independent drafts *trustworthy enough to act
from* — the failure mode of multi-agent fan-out is a confident, wrong draft, and
the verifier is the gate that catches it.

## 3. Build

**Harness + size:** an agentskills.io skill (`SKILL.md` + `agents/` + `references/`
+ `scripts/`). ~2,860 lines for the orchestrator skill + ~480 for the composed
`github-duplicate-check` skill.

**Fixtures:** `examples/run-2026-06-27/` is a real run against the live
145-notification inbox (shaped TSV input → plan → 5 verified reports → digest →
hand-off).

**Skill vs SYSTEM:** everything lives inside the skill directory — no system
changes. ZeroClaw deployment is *config* (the A/C cron jobs) plus the portable
scripts; nothing patched into the runtime.

**Vibe-coded vs engineered:** the scripts were **deliberately engineered and
tested** (`build_index.py` lede-preservation; `notifications_delta.sh`
at-least-once/restart-safe delta). The architecture decision (batch vs proactive)
was **researched against ZeroClaw source**, not vibed. The agent prose was
authored then **adversarially reviewed** by verifier sub-agents.

## 4. Evaluate  ← the iteration log is the point

**Eval cases:** 2 full end-to-end runs on the live 145-notification inbox (a
5-item demo and a 3-item `--limit` run) + the bundled fixture. With-skill →
a structured, verified, dated binder; without-skill → ad-hoc, unverified, no
dedup, no audit trail.

**Iteration log:**
- **v1 — `build_index.py` lede wipe (bug).** Re-running the index builder reset
  the human "lede" back to the placeholder. Caught during the e2e integrity check
  (I re-ran the builder and the lede vanished). Fix: `existing_lede()` preserves a
  filled-in lede across rebuilds; regression-tested that a fresh dir still emits
  the placeholder.
- **v2 — `notifications_delta.sh` empty-first-file (bug).** The classic awk
  `FNR==NR` join mis-classified the first real notification as "already seen" when
  `seen.tsv` was empty, so the very first tick emitted 0 instead of 145. Caught in
  the build agent's own test. Fix: a `FILENAME`-based discriminator, immune to an
  empty first file.
- **v3 — fabricated concurrency cap (grounding error).** The deployment
  recommendation claimed the orchestrator "self-caps at `min(16, cores-2)`." An
  adversarial critic found that formula is **not in the codebase** — it's the
  Workflow tool's cap, conflated in. Fix: corrected to the real bound (a soft
  "P1+P2 up to 20" policy instruction) + framed the true compute lever as the
  model **provider's** tokens-per-minute limit, external to ZeroClaw.
- **v4 — hallucinated cron schedule variant (grounding error).** Research claimed
  an `After` relative-delay `Schedule` variant. The verifier found the enum is
  only `Cron`/`At`/`Every` (`after` is `cron_add` *tool input* sugar that converts
  to `At`). Fix: documented as tool-only; TOML/REST use `At` with an absolute ts.
- **v5 — `delete_after_run` TOML bug (grounding error).** The deployment doc
  showed `delete_after_run` as a declarative-TOML field. The config-grounding
  verifier found it's **not** a `CronJobDecl` field — it's derived from the
  schedule kind and silently ignored in TOML. Fix: removed from the TOML example.
- **v6 — "four searches" doc drift (doc error).** `github-duplicate-check` docs said the
  script runs four `gh` searches; the verifier counted three executable calls
  (`gh search issues --include-prs` covers issues+PRs in one). Fix: corrected to
  three.
- **v7 — ZeroClaw-native multi-agent delegate fan-out (architecture + 2 bugs).**
  Converted the single-agent ZeroClaw poll cron into a genuine **ZeroClaw-native
  fan-out with no Claude Code dependency**. The orchestrator agent `gh_notif`
  (sonnet) now runs the read-only delta script, routes each NEW notification by
  reason/type, and uses ZeroClaw's built-in `delegate` tool to hand each one to
  ONE of **six per-profile sub-agents** (`gh_notif_pr_reviewer`/opus,
  `gh_notif_issue`/sonnet, `gh_notif_mention`/sonnet, `gh_notif_author`/sonnet,
  `gh_notif_ci`/sonnet) plus an adversarial `gh_notif_verifier`/opus on PR-review
  drafts; still **draft-only** (read-only `gh`, one local markdown report each,
  nothing posted/commented/reviewed/labelled/closed/merged/marked-read).
  Delegation is **synchronous/serial** (one sub-agent at a time, bounded to the 5
  newest notifications per tick), then the delta script commits state. Two bugs
  found + fixed while wiring it: **(1)** the parent `gh_notif` risk profile still
  listed an allowed_root for the OLD skill name `github-prior-art` while the worker
  profile listed the RENAMED `github-duplicate-check`; because the child root was
  not a subset of the parent's, ZeroClaw's no-escalation guard rejected every
  delegation (`ReadWriteRootNotInParent`) — fixed by aligning both profiles to
  `github-duplicate-check` (also repairing a dangling path). **(2)** `background:true`
  delegations spawn the sub-agent in an in-process tokio task whose result is
  persisted to `workspace/delegate_results/{task_id}.json`; those tasks only
  complete inside the persistent daemon (a single-shot `zeroclaw agent` CLI process
  exits and aborts them) AND background re-entry requires the worker profile to have
  `delegation_policy=allow` — so we chose **synchronous** delegation as the robust
  default (works in CLI and daemon, lets workers stay `delegation_policy=forbidden`).
  **Verified live:** a real run drafted 5 notifications routed to 5 DISTINCT
  sub-agents (pr_reviewer, mention, ci, author, issue) plus 1 verifier verdict on
  the PR-review draft, then committed state — final reply: *"delegated 5 ..., verified
  1, deferred 0 ... Nothing was posted."*
- **v8 — delivery + acceptance, and Python removed.** Three changes. **(a)** Drafts
  now publish to a **private** GitHub repo (`publish_drafts.sh`) and the daily digest
  links each item to its rendered summary there — reachable from chat/mobile;
  `build_index` emits absolute github.com blob URLs when a `.drafts-remote` is set.
  Publish is **add-only** so a later poll tick never clobbers your accept/edits.
  **(b)** An opt-in **accept→post shipper** (`ship_accepted.sh`): flip a draft to
  `status: accepted` and it posts the marked reply block as a COMMENT via `gh` —
  deterministic (no LLM in the posting path), comments only (never review/approve/
  merge/close/label), dry-run by default, idempotent (→ `status: posted` + comment
  URL). Ships `enabled = false` (verified ZeroClaw honors that). **(c)** Per user
  request, **dropped the Python dependency**: `build_index.py` + `ship_accepted.py`
  rewritten in pure bash (bash/awk/sed/sort + `gh`/`jq` — all POSIX). Verified the
  bash index is **byte-identical** to the Python one, and the shipper
  post→flip→idempotency end-to-end against a throwaway issue. Bug caught + fixed
  mid-port: BSD `sed` lacks `\|` BRE alternation, so a bulk rename left broken
  `python3 ….sh` invocations — re-fixed with portable substitutions.
- **v9 — Discord control surface + Phase 3 PR shipper.** A ZeroClaw-native Discord
  layer: a `gh-draft` slash skill (`/gh-draft <text>` → ask/edit/show/accept/
  implement a draft) served by a `gh_notif_chat` agent bound to discord.default,
  with `[COMPONENTS:]` action buttons on `show`. Wiring gotchas (now in memory):
  skills only register as slash commands when loaded via a BUNDLE attached to the
  channel agent; interactions are gated by `[peer_groups].external_peers` (the
  user's Discord id). **Phase 3** (`ship_pr.sh`): accept a *code* draft → a DRAFT
  PR from the fork, built by a LOCAL Claude Code harness + the `github-pr` skill
  (claude.ai/code dropped — not automatable; ZeroClaw `zerocoder` = fallback).
  An adversarial review then hardened it: untrusted-draft fencing against prompt
  injection, a **deterministic** commit-msg hook that strips bot/AI attribution +
  a post-run verifier (the no-attribution repo rule had been only *instructed*),
  fork preflight, exact-basename `--only`, and `--open` refusing a bare mass-fire.

- **v10 — review-with-evidence + sandboxing.** Added `review_evidence.sh`: for a
  PR review draft, fetch the PR head (read-only) into a throwaway worktree, run the
  battery, and append a `## Build evidence` section (pass/fail + head SHA + output)
  to the draft. This is the harness's MAIN use (build/test others' PRs for grounded
  review) vs. `ship_pr.sh` (write a PR — only for assigned issues). Because building
  a PR executes its code, the battery runs in an **ephemeral container** by default
  (only the worktree mounted; host secrets unexposed) and **refuses** on the host
  unless `--allow-host`. Proven end-to-end on PR #8247 (`cargo check` ✅).

**Final:** spec-valid; **2 real bugs + 4 grounding/doc errors caught and fixed**
by the verifier / adversarial-critic layers before they shipped. The with-skill
output is a verified, linked, dated digest; the delta vs no-skill is the
difference between "a reviewed binder you can act from" and "a pile of unverified
guesses."

## 5. Deploy

**Quickstart (Claude Code):** install the skill, authenticate `gh`, say
*"orchestrate my notifications"*. The bundled scripts also run standalone:
`fetch_notifications.sh <dir>` and `build_index.py <dir>`.

**Live vs offline:** live = read-only `gh` against the notifications API; offline =
the cached `notifications.json` + `build_index.py` (no network).

**ZeroClaw (proactive) deployment:** add the **Piece A** poll-and-delegate cron
job + the **Piece C** daily-digest cron job from `references/deployment-zeroclaw.md`
(declarative TOML / `cron_add` / REST), point Piece A at a durable `STATE_DIR`,
and wire Piece C's `delivery` to your channel. **Configure:** `gh` auth, a model
provider, and (for the digest) a delivery channel id.

## 6. Observe

**Run footer / telemetry:** the multi-agent workflows emit `agent_count`,
`subagent_tokens`, `tool_uses`, `duration_ms` per run (e.g. the ZeroClaw research
workflow: 9 agents, ~573k tokens, ~14 min). Each item report carries
`priority`/`status` frontmatter; `INDEX.md` prints per-priority counts. A ZeroClaw
cron job records full run history (timestamp / status / output / duration).

**Where eval outputs land:** `triage/<date>/` (or `.context/triage/<date>/` in
Conductor) for live runs; `examples/run-2026-06-27/` for the committed fixture.

**What the traces taught (that pass-rates hid):**
1. Drafts can be **confidently wrong** — the verifier trace on PR #8173 flagged
   two overstatements (a "missing" dashboard hint that already shipped; a bogus
   XSS nit) that every surface check "passed." Pass/fail counts never see this;
   reading the refutation trace does.
2. The `notifications_delta` first-run trace exposed the `FNR==NR` bug only when
   read line-by-line — the aggregate "it ran, exit 0" looked green while it
   silently emitted 0 of 145.

## 7. Iterate

Next loop, in priority order (concrete + testable):
1. **Feed `github-duplicate-check` output into the digest's dedup section** so the
   summarizer reconciles related items across the inbox; measure the drop in
   redundant drafts on a run with known duplicates (e.g. the dream-mode cluster).
2. **Add an `evals/` set** (a trigger eval + a few golden notifications with
   expected routing/priority) and run the skill-creator description optimizer;
   target ≥90% trigger accuracy on held-out queries.
3. **Run Piece A on a live ZeroClaw instance for a day** and capture
   drafts/tick, tokens/day, and a restart test proving the at-least-once delta
   never replays a posted action (it can't — draft-only — but verify no duplicate
   draft storms).
