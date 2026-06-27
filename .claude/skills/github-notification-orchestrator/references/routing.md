# Routing: notification → agent profile

Phase 2 of the orchestrator maps each notification to exactly one profile. Start
from the GitHub `reason` and the subject `type`, then apply the heuristics below
for the ambiguous cases. When still unsure, prefer the profile that produces the
most useful *draft* — a review note is more actionable than a generic summary.

## Base mapping

| `reason` | subject `type` | Profile | Priority hint |
|---|---|---|---|
| `review_requested` | PullRequest | `pr-review-responder` | P2 (P1 if you are the *only* requested reviewer) |
| `mention` / `team_mention` | PullRequest | `pr-review-responder` if the comment asks about the code/review; else `mention-responder` | P1 if a direct question |
| `mention` / `team_mention` | Issue / Discussion | `mention-responder` | P1 if a direct question |
| `comment` | any | `mention-responder` | P2 |
| `assign` | Issue | `issue-responder` | P2 |
| `assign` | PullRequest | `pr-review-responder` | P2 |
| `author` | any | `author-activity-responder` | P2 |
| `ci_activity` | CheckSuite / PullRequest | `ci-failure-investigator` | P2 (P1 if it blocks your open PR) |
| `subscribed` | Issue / Discussion | `issue-responder` (read-mostly) or skip if pure noise | P3 |
| `state_change` | any | usually P3 FYI → `author-activity-responder` if it is your thread | P3 |
| `security_alert` | any | `issue-responder` and flag prominently | P1 |
| anything from a known bot / digest | any | skip the fan-out; summarize in aggregate | P3 |

## Heuristics for the hard cases

**Is a `mention` on a PR a review ask or a question?**
Fetch the latest comment (`gh api <latest_comment_url>` — read-only). If it
references the diff, asks "can you review", requests changes, or @-mentions you
next to a code question → `pr-review-responder`. If it is a general question or
a process ping → `mention-responder`. When the comment is short and ambiguous,
`mention-responder` is the safer default (it drafts a reply rather than a full
review).

**Is this branch / PR *yours*?**
You need the resolved login (from Phase 0). A PR is yours if `author == login`.
A branch is yours if it matches `<login>/*` (case-insensitive) or you authored
HEAD. `ci_activity` on your own PR is P1-adjacent (your work is red); on someone
else's, it is usually P3 noise unless you were explicitly pinged.

**`assign`: issue or PR?**
The subject `type` tells you. `assign` + Issue → `issue-responder`. `assign` +
PullRequest → `pr-review-responder` (you were assigned to review or to take it
over).

**Direct-ask detection (drives P1).** A notification is P1 when someone is
blocked on *you specifically*. Signals: the latest comment contains
`@<your-login>`, ends in a question mark with your name/handle nearby, or uses
imperative phrasing toward you ("can you", "please confirm", "what do you want
to do about", "need your call on"). If you are confident it is a direct ask,
P1. If not, P2 or P3 — a false P1 erodes trust in the binder faster than a
deferred P3.

## Bot / noise suppression

Do not spend a subagent on automated churn. Patterns to collapse into a single
aggregate line in the plan (and skip in the fan-out):

- Daily radar / digest bots, dependabot bumps with no @-mention.
- Repeated identical CI status pings on the same PR (keep the newest, drop the
  rest).
- `subscribed` notifications on busy threads you never interacted with.

Always *report the count* of what you suppressed (Execution Rule 4: no silent
caps) so the user can ask for them if they want.
