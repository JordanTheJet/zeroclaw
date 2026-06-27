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
