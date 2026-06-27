# Per-item report template (enforced format)

Every subagent writes exactly one report per notification using this structure.
The frontmatter is **not optional** — `scripts/build_index.py` parses it to build
the digest, so a report with missing or malformed frontmatter silently drops out
of `INDEX.md`. Fill every key. Keep prose tight; this is a briefing page, not an
essay.

## Frontmatter keys

| Key | Required | Meaning |
|---|---|---|
| `notification_id` | yes | The `thread_id` from the plan (needed later to mark read). |
| `updated_at` | yes | ISO-8601 timestamp from the notification. **The sort key for the index** — copy it verbatim, do not invent one. |
| `reason` | yes | GitHub notification reason (`review_requested`, `mention`, …). |
| `repo` | yes | `owner/name`. |
| `type` | yes | `PullRequest`, `Issue`, `Discussion`, `Release`, `CheckSuite`, … |
| `number` | yes | Issue/PR number, or empty string if not applicable. |
| `title` | yes | The thread title. Quote it if it contains a colon. |
| `url` | yes | The **html** URL (github.com/...), not the api.github.com URL. |
| `agent_profile` | yes | Which profile produced this report. |
| `priority` | yes | `P1` (blocked on you), `P2` (your work / assigned), `P3` (FYI). |
| `status` | yes | One of: `needs-reply`, `action-required`, `drafted`, `fyi`, `error`. You flip it to `accepted` to authorize posting the Ready-to-post comment; the shipper sets `posted` (and appends `posted_at` + `posted_comment_url`) after it posts. |

## The template

Copy this exactly, replacing the bracketed parts. Do not add or rename keys.
Every `REPLACE_…` token must be filled in — if a value is genuinely unavailable
(e.g. the orchestrator didn't pass a `thread_id`), use an empty string `""`
rather than leaving the literal placeholder in the file.

```markdown
---
notification_id: "REPLACE_THREAD_ID"
updated_at: "REPLACE_ISO8601"
reason: "REPLACE_REASON"
repo: "REPLACE_OWNER/REPO"
type: "REPLACE_TYPE"
number: "REPLACE_NUMBER"
title: "REPLACE_TITLE"
url: "REPLACE_HTML_URL"
agent_profile: "REPLACE_PROFILE_NAME"
priority: "P1"
status: "needs-reply"
---

# #NUMBER — TITLE

**Repo:** owner/name · **Type:** PullRequest · **Reason:** review_requested · **Updated:** 2026-06-27 15:59 UTC
**Link:** https://github.com/owner/name/pull/NUMBER

## What happened
One short paragraph: what this thread is and what changed since it last needed
you. Name the people involved. If you fetched the latest comment, ground this in
what it actually says — do not guess.

## Who needs what from you
The specific ask in one or two sentences, or `FYI only — no action needed.`
Be concrete: "Maria is asking whether the retry budget should be per-channel or
global before she finishes the impl."

## Suggested response
The draft. This is what the user will (after editing) actually send or do.
Match the medium to the type:
- PR review → bullet review notes, each tagged blocking / non-blocking / nit.
- Issue → the triage call (label, dedupe, repro ask) and a drafted comment.
- Mention/question → a drafted reply in the user's voice.
- Authored-thread → the recommended next move (merge, nudge, close, respond).
- CI failure → the root-cause line, the failing test, and a fix sketch.

Keep it ready-to-paste. Mark anything you are unsure about with `⚠`.

## Ready-to-post comment
The EXACT text that gets posted to the thread **verbatim** if the user accepts
this draft (sets `status: accepted`). Public reply ONLY — no analysis, priority,
or verifier notes. Leave the block EMPTY (nothing between the markers) if posting
a comment isn't the right move (e.g. CI-only, or the user will act in code). Keep
the two markers on their own lines exactly as shown; the shipper posts only what
is strictly between them.

<!-- REPLY:BEGIN -->
REPLACE_WITH_PUBLIC_REPLY_OR_LEAVE_EMPTY
<!-- REPLY:END -->

## Next action
- [ ] The single concrete step the user should take (e.g. "post the drafted
      reply", "checkout and run `cargo test channel::retry`", "close as dup of #6201").
```

## Notes for filling it in

- **Derive the html URL** from `repo` + `type` + `number`: PRs use
  `/pull/<n>`, issues use `/issues/<n>`. The notification's `subject.url` is an
  `api.github.com` link — convert it, don't paste it.
- **Slug** for the filename = lowercased title, non-alphanumerics → hyphens,
  trimmed to ~6 words. The orchestrator passes you the numeric prefix.
- **When in doubt about priority**, lean P1 for anything that reads like a direct
  question to the user, P3 for bot digests and group pings. The user can always
  down-rank; a missed P1 is the costly error.
