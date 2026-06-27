# Deployment — running the orchestrator on a ZeroClaw scheduler

This is the **deployment layer** for the notification orchestrator: how to run it
unattended on ZeroClaw's built-in cron, instead of (or alongside) the interactive
`/github-notification-orchestrator` skill. The interactive skill drains the *whole*
inbox on demand; the scheduled version keeps a binder fresh in the background by
draining only the **delta** on each tick, and ships a once-a-day digest.

## Execution model — read this first

A ZeroClaw **Agent cron job** runs **ZeroClaw's own agent** with a `prompt`. It
does **not** run a Claude Code skill directly. So the job doesn't "invoke the
orchestrator"; it hands ZeroClaw's agent a prompt that tells it to:

1. run the bundled bash scripts via its **shell tool**
   (`fetch_notifications.sh`, `notifications_delta.sh`, `build_index.py`), and
2. spawn per-item drafters via ZeroClaw's **`delegate` tool**, passing each the
   matching `agents/*.md` profile as its instructions.

The profiles, the report template, and `build_index.py` are **portable** — they
are reused as-is. What the cron prompts add (`agents/cron-poll-delegate.md`,
`agents/cron-daily-digest.md`) is the scheduling-and-delegation wrapper. Two
pieces:

- **Piece A — poll-and-delegate** (`cron-poll-delegate.md`): a repeating ~10-min
  agent job that drafts the delta into today's binder.
- **Piece C — daily digest** (`cron-daily-digest.md`): a once-a-day agent job that
  indexes the binder and announces it to a channel.

(A real-time webhook trigger — "Piece B" — was evaluated and **deliberately
descoped**; see the end for why polling is the right default here.)

> Every config block below is grounded in ZeroClaw's actual schema. Field names are
> exact. Where a surface genuinely lacks a field, that is called out in prose
> rather than invented.

---

## Piece A — poll-and-delegate (repeating agent job)

A repeating AGENT job, every ~10 minutes, `session_target = "isolated"` (fresh
session each tick so state lives only in the durable state-dir, not in session
memory), with `allowed_tools` restricted to the read-only / draft / delegate set.
The prompt points ZeroClaw's agent at `agents/cron-poll-delegate.md`.

### The durable state-dir and the delta → draft → commit loop

The job is stateless *in-session* (`isolated`) but stateful *on-disk*. A single
durable directory — `.context/triage/state/` — holds `seen.tsv`
(`<thread_id>\t<last-drafted updated_at>`). Each tick:

1. **delta** — `notifications_delta.sh delta <state-dir> <out-dir>` refreshes the
   snapshot (read-only `gh`) and emits `new.tsv`: only threads that are NEW
   (never seen) or RE-ACTIVATED (`updated_at` strictly newer than what was last
   drafted). `delta` **never** writes `seen.tsv` — it is pure read against durable
   state.
2. **draft** — one background `delegate` per new row, profile-matched, capped to a
   few concurrent; reports land in `<out-dir>/items/`.
3. **commit** — `notifications_delta.sh commit <state-dir> <out-dir>` folds the
   current snapshot into `seen.tsv` (upsert each thread to `max(seen, current)`),
   atomically (temp-file + `mv`). Idempotent: re-committing the same snapshot is
   byte-identical.

**At-least-once / restart-safety.** The split is deliberate. `delta` is read-only
on durable state; `commit` is the only writer and is idempotent. A crash between
draft and commit just re-emits those items next tick and re-drafts them — safe
because the whole skill is **draft-only**: a re-draft overwrites a local file;
nothing is posted, reviewed, or marked read. So a daemon restart with
`catch_up_on_startup=true` replays at most a few *draft writes*, never a backlog of
posted actions. (Re-activation uses lexical compare of fixed-width RFC3339
`...Z` timestamps, which is correct chronological order.)

> Because state is durable and the loop is idempotent, `session_target` is
> deliberately `"isolated"` (the default): a fresh session each tick, with the
> only memory being `seen.tsv`.

### A.1 — Declarative TOML

```toml
[cron.gh-notif-poll]
name = "GitHub notification poll-and-delegate"
job_type = "agent"
prompt = "Run the GitHub notification poll-and-delegate tick. Read your instructions at .claude/skills/github-notification-orchestrator/agents/cron-poll-delegate.md and follow it exactly. STATE_DIR=.context/triage/state (durable; holds seen.tsv). Binder out-dir = .context/triage/$(date +%Y-%m-%d). Run notifications_delta.sh delta, fan out one background delegate per new item with the matching agents/*.md profile (cap a few concurrent), file reports into the binder, then run notifications_delta.sh commit. Draft only: never post, review, label, close, or mark anything read."
schedule.kind = "every"
schedule.every_ms = 600000
session_target = "isolated"
uses_memory = false
enabled = true
allowed_tools = ["delegate", "file_read", "file_write", "shell"]
```

Field notes (all names from the `CronJobDecl` / `CronScheduleDecl` schema):
- `job_type = "agent"` — required for an agent job (default is `"shell"`).
- `schedule.kind = "every"` + `schedule.every_ms = 600000` — interval = 10 min in
  **milliseconds**. (For a fixed clock cadence you could use
  `schedule.kind = "cron"` + `schedule.expr = "*/10 * * * *"` instead.)
- `session_target = "isolated"` — fresh session each run.
- `uses_memory = false` — this is a stateless digest tick; state lives in
  `seen.tsv`, not memory. (Default is `true`.)
- `allowed_tools` — restrict to the read-only / draft / delegate set. It MUST NOT
  contain any GitHub-mutating tool. Note: when `allowed_tools` is set, scheduler
  mutation tools (`cron_add`, `cron_update`, `cron_remove`, `cron_run`, `schedule`)
  are NOT auto-added — which is what we want here.
  > Tool *names* are environment-specific. The set above (`delegate`, file
  > read/write, `shell`) is the intended capability; confirm the exact tool names
  > registered in your runtime and substitute them. The point is: read +
  > draft-write + delegate, and nothing that can post to GitHub.
- *(No `delete_after_run` in declarative TOML.)* It is **not** a `CronJobDecl`
  field — at config sync the runtime derives it from the schedule kind (one-shot
  `at` ⇒ delete-after-run, repeating ⇒ keep), so a repeating job like this is kept
  automatically. `delete_after_run` *is* a real field on the `cron_add` tool and
  REST surfaces below — just not in declarative TOML (where it's silently ignored).

This job has **no `delivery` block**: Piece A files drafts silently; Piece C is
what announces.

### A.2 — `cron_add` tool / CLI call

The `cron_add` tool takes the schedule as a **JSON object** with a `"kind"` tag:

```json
{
  "name": "GitHub notification poll-and-delegate",
  "schedule": { "kind": "every", "every_ms": 600000 },
  "job_type": "agent",
  "prompt": "Run the GitHub notification poll-and-delegate tick per .claude/skills/github-notification-orchestrator/agents/cron-poll-delegate.md. STATE_DIR=.context/triage/state; binder=.context/triage/<today>. delta -> background-delegate each new item with its agents/*.md profile (cap a few) -> commit. Draft only; never post/review/label/close/mark-read.",
  "session_target": "isolated",
  "allowed_tools": ["delegate", "file_read", "file_write", "shell"]
}
```

The four schedule variants for the tool are
`{"kind":"cron","expr":...,"tz":...}`, `{"kind":"at","at":...}`,
`{"kind":"every","every_ms":...}`, and `{"kind":"after","after_seconds":...}`.
For a fixed clock cadence use `{"kind":"cron","expr":"*/10 * * * *"}`. (The
`"after"` relative-delay variant exists **only** in this tool, not in TOML or
REST.)

### A.3 — REST `POST /api/cron`

The REST surface takes the schedule as a **plain cron string** plus a separate
`tz` field — and **currently supports only `kind="cron"`** schedules. So an
every-10-minutes job is expressed as the cron expression `*/10 * * * *`:

```json
{
  "agent": "default",
  "schedule": "*/10 * * * *",
  "job_type": "agent",
  "prompt": "Run the GitHub notification poll-and-delegate tick per .claude/skills/github-notification-orchestrator/agents/cron-poll-delegate.md. STATE_DIR=.context/triage/state; binder=.context/triage/<today>. delta -> background-delegate each new item -> commit. Draft only.",
  "session_target": "isolated",
  "allowed_tools": ["delegate", "file_read", "file_write", "shell"],
  "delete_after_run": false
}
```

`agent` names the target ZeroClaw agent. There is no `every_ms` on REST — a true
fixed-interval `every` job must use the `cron_add` tool or declarative TOML.

---

## Piece C — daily digest (once-a-day agent job)

A repeating AGENT job on a **cron** schedule, `"0 9 * * *"` (9am), with a `tz` so
the clock is anchored. It points ZeroClaw's agent at `agents/cron-daily-digest.md`,
which runs `build_index.py` over today's binder, writes the lede (or delegates the
`daily-summarizer`), and **announces** the result via the job's `delivery` block.

This is a non-latency-sensitive, once-a-day fan-out → an **ideal Batch-API
candidate** (50% cheaper) if the summary work ever grows. And it should **roll up
Piece A's existing drafts**, not re-draft them — the per-item reasoning already
happened on the 10-minute ticks.

### C.1 — Declarative TOML

```toml
[cron.gh-notif-digest]
name = "GitHub notification daily digest"
job_type = "agent"
prompt = "Build today's GitHub notification digest. Read .claude/skills/github-notification-orchestrator/agents/cron-daily-digest.md and follow it. Binder = .context/triage/$(date +%Y-%m-%d). Run build_index.py over the binder, write the lede, and return a compact summary (with the INDEX path) to be announced. Roll up the existing per-item drafts; do NOT re-draft. Read/write only inside the binder; no GitHub mutation."
schedule.kind = "cron"
schedule.expr = "0 9 * * *"
schedule.tz = "America/New_York"
session_target = "isolated"
uses_memory = false
enabled = true
allowed_tools = ["file_read", "file_write", "shell", "delegate"]

[cron.gh-notif-digest.delivery]
mode = "announce"
channel = "discord"
to = "123456789012345678"
best_effort = true
```

Field notes:
- `schedule.kind = "cron"`, `schedule.expr = "0 9 * * *"`, `schedule.tz = "..."` —
  the timezone anchors the clock; without it the cron fires in the daemon's
  timezone. (`tz` is an optional IANA name.)
- `delivery.mode = "announce"` — send the job's output. (Default is `"none"`,
  which would file the index silently.)
- `delivery.channel` — one of the supported channels: `telegram`, `discord`,
  `slack`, `mattermost`, `matrix`, `qq`, `whatsapp`, `webhook`, `lark`, `feishu`,
  `dingtalk`.
- `delivery.to` — the channel-specific destination (here a Discord channel ID).
- `delivery.best_effort = true` — don't fail the job if delivery fails (default
  `true`). `delivery.thread_id` is available too (optional; mainly for `webhook`
  callback routing) — omit it for a plain Discord/Slack/Telegram send.

### C.2 — `cron_add` tool / CLI call

```json
{
  "name": "GitHub notification daily digest",
  "schedule": { "kind": "cron", "expr": "0 9 * * *", "tz": "America/New_York" },
  "job_type": "agent",
  "prompt": "Build today's GitHub notification digest per .claude/skills/github-notification-orchestrator/agents/cron-daily-digest.md. Binder=.context/triage/<today>. build_index.py -> lede -> return compact summary with INDEX path. Roll up existing drafts; don't re-draft. No GitHub mutation.",
  "session_target": "isolated",
  "allowed_tools": ["file_read", "file_write", "shell", "delegate"],
  "delivery": {
    "mode": "announce",
    "channel": "discord",
    "to": "123456789012345678",
    "best_effort": true
  }
}
```

### C.3 — REST `POST /api/cron`

```json
{
  "agent": "default",
  "schedule": "0 9 * * *",
  "tz": "America/New_York",
  "job_type": "agent",
  "prompt": "Build today's GitHub notification digest per .claude/skills/github-notification-orchestrator/agents/cron-daily-digest.md. Binder=.context/triage/<today>. build_index.py -> lede -> compact summary with INDEX path. Roll up existing drafts; no GitHub mutation.",
  "session_target": "isolated",
  "allowed_tools": ["file_read", "file_write", "shell", "delegate"],
  "delivery": {
    "mode": "announce",
    "channel": "discord",
    "to": "123456789012345678",
    "best_effort": true
  }
}
```

On REST the cron expression is the bare `schedule` string and the timezone is the
separate `tz` field (REST converts them to a `cron` schedule internally).

---

## Scheduler tuning

These live in two separate sections. The poll cadence key
(`scheduler_poll_secs`) is in `[reliability]`, **not** `[scheduler]`.

```toml
[scheduler]
enabled = true
max_tasks = 64
max_concurrent = 4
catch_up_on_startup = false
max_run_history = 50

[reliability]
scheduler_poll_secs = 600
scheduler_retries = 2
```

Key notes (exact field names and defaults from `SchedulerConfig` /
`ReliabilityConfig`):
- `scheduler_poll_secs` (default `15`) — how often the scheduler loop checks for
  due jobs. The default 15s is fine; if Piece A is your only fast job you can relax
  it. Set it **lower than** your tightest schedule's interval so a due tick isn't
  missed — for a 10-min Piece A, anything ≤ 600 works; the example sets `600`.
- `scheduler_retries` (default `2`) — retries per cron execution attempt.
- `max_concurrent` (default `4`) — tasks run in parallel per polling cycle.
- `max_tasks` (default `64`), `max_run_history` (default `50`) — left at defaults.

### `catch_up_on_startup` and the restart-spike — neutralized by design

`catch_up_on_startup` defaults to **`true`**: on daemon restart, every job whose
`next_run` is in the past fires **once** before normal polling resumes. After a
long downtime that can be a thundering-herd of overdue ticks (the
**restart-replay-spike**).

For this skill that spike is **harmless**, because the delta/commit design makes a
replayed Piece A tick safe: it re-runs `delta` (read-only), re-drafts at most a
handful of un-committed items into local files (overwriting drafts, not posting),
and re-commits idempotently. There is no backlog of *posted* actions to replay —
nothing is ever posted. So you may leave `catch_up_on_startup = true` safely.

The example still sets `catch_up_on_startup = false` as the conservative default:
it avoids the burst entirely (no replayed ticks at all), and for a 10-min poller
you lose nothing — the next normal tick picks up the same delta within minutes.
Choose `true` only if you want strict catch-up of every missed window.

---

## Draft-only safety (the deployment-layer restatement)

Running unattended does **not** loosen the contract. The same boundary as the
interactive skill (`references/safety.md`) applies, enforced two ways:

1. **`allowed_tools` on every job MUST exclude every GitHub-mutating tool.** No
   tool that can run `gh pr comment` / `gh pr review` / `gh issue comment` /
   `gh issue close` / label edits / `PATCH notifications/threads/*` /
   `gh pr create` / `git push`. The allowlist is read + draft-write + delegate
   only.
2. **The prompts forbid it.** Both cron prompts (and every delegated profile)
   state draft-only explicitly; the drafters spawned via `delegate` inherit the
   parent's per-sender action budget (cloned `PerSenderTracker`), so a sub-agent
   can't bypass limits.

The scheduled agent never posts, never reviews, never marks read. It files draft
files into a binder; the user sends.

---

## What's net-new vs. reused

**Reused as-is (portable, no changes):**
- All five worker profiles (`pr-review-responder`, `issue-responder`,
  `mention-responder`, `author-activity-responder`, `ci-failure-investigator`),
  the `verifier`, and the `daily-summarizer`.
- `references/report-template.md`, `references/routing.md`, `references/safety.md`,
  `references/model-selection.md`.
- `scripts/fetch_notifications.sh` and `scripts/build_index.py`.

**Net-new for deployment:**
- `scripts/notifications_delta.sh` — the `delta`/`commit` state machine over a
  durable `seen.tsv` (the one thing the interactive skill didn't need, because it
  drains the whole inbox in one pass).
- `agents/cron-poll-delegate.md` (Piece A prompt) and `agents/cron-daily-digest.md`
  (Piece C prompt).
- This deployment reference and the cron/scheduler config.

---

## Why not a webhook ("Piece B") — evaluated and descoped

A real-time GitHub webhook (push) would cut latency from ~10 min to seconds. It
was considered and **deliberately not pursued** — for a personal inbox assistant,
polling (Piece A) is the better default:

- **Outbound-only, no attack surface.** Piece A polls GitHub. A webhook needs a
  public HTTPS endpoint accepting unsolicited POSTs + HMAC verification — a new
  surface to harden, plus a public URL and repo-admin rights you may not have.
- **Self-healing, no missed events.** Piece A re-scans the full unread set every
  tick, so a missed tick is recovered on the next one. Webhooks are best-effort —
  an event delivered while your endpoint is down is gone.
- **Fits the notifications API.** The orchestrator works your *notification inbox*
  (a polling API). GitHub webhooks deliver *repo events*, which aren't 1:1 with
  "what's in my inbox" and would need a webhook per repo + an "is this mine?" filter.
- **A few minutes' latency is fine** for drafting responses you edit and send
  yourself.

If you later own the repos, can host a hardened endpoint, and genuinely need
seconds-latency, a webhook can be layered on **in addition to** Piece A (keeping
the poll as the reconciliation backstop) — but it is out of scope here.

So the migration is additive: A and C don't change; B is a lower-latency front
door onto the same idempotent loop, and the at-least-once / draft-only properties
carry over unchanged.
