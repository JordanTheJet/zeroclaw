# Routing plan — 2026-06-27

Identity: `JordanTheJet` · Inbox: **145 unread**

## Inbox shape (by reason)
| count | reason | routed to |
|---|---|---|
| 70 | review_requested | pr-review-responder |
| 34 | mention | mention-responder (or pr-review-responder if code-focused) |
| 22 | ci_activity | ci-failure-investigator (most are fork-sync noise → suppress) |
| 14 | author | author-activity-responder |
| 3 | assign | issue-responder / pr-review-responder by type |
| 1 | state_change | author-activity-responder |
| 1 | comment | mention-responder |

## Scale decision (no silent caps)
A full P1+P2 fan-out of 145 is dozens of subagents. **For this demonstration run
the fan-out is capped at 5 representative items spanning 5 profiles** (below).
The remaining items are deferred — notably ~13 `sync fork with upstream` CI
failures on `JordanTheJet/zeroclaw:master`, which are recurring fork-maintenance
noise (Routing → bot/noise suppression), and the bulk of the 70 review requests.
Re-run with a higher `--limit` or a scope word to process more.

## Dispatched this run
| # | item | profile | model | priority | updated_at |
|---|---|---|---|---|---|
| 0001 | PR #6619 — fix(runtime/agent): authorize shell explicitly at autonomy.level=full | pr-review-responder | opus | P2 | 2026-06-27T11:12:26Z |
| 0002 | Issue #6407 — [Bug] i18n catalogs translate code literals (mention) | mention-responder | sonnet | P2 | 2026-06-26T13:58:31Z |
| 0003 | Issue #5808 — [Bug] Default 32k context budget exceeded by system prompt (author) | author-activity-responder | sonnet | P2 | 2026-06-27T07:04:12Z |
| 0004 | Issue #7025 — [Bug] read_skill cannot load plugin-bundled skills (assigned) | issue-responder | sonnet | P2 | 2026-06-22T05:16:31Z |
| 0005 | CI — Quality Gate failed on JordanTheJet/dream-mode | ci-failure-investigator | sonnet | P2 | 2026-06-16T21:11:29Z |

Then: `daily-summarizer` (haiku) builds `INDEX.md`.
