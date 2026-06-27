---
notification_id: "23587730271"
updated_at: "2026-06-27T07:03:51Z"
reason: "author"
repo: "zeroclaw-labs/zeroclaw"
type: "Issue"
number: "5808"
title: "[Bug]: Default 32k context budget is exceeded by system prompt + tool definitions on iteration 1, causing perpetual preemptive trim"
url: "https://github.com/zeroclaw-labs/zeroclaw/issues/5808"
agent_profile: "author-activity-responder"
priority: "P1"
status: "needs-reply"
---

# #5808 — [Bug]: Default 32k context budget is exceeded by system prompt + tool definitions on iteration 1, causing perpetual preemptive trim

**Repo:** zeroclaw-labs/zeroclaw · **Type:** Issue · **Reason:** author · **Updated:** 2026-06-27 07:03 UTC
**Link:** https://github.com/zeroclaw-labs/zeroclaw/issues/5808

## What happened

Since you filed this in April, the thread has accumulated significant diagnostic and resolution activity. The core re-run-loop failure (preemptive trim dropping the user turn → z.ai `1214` errors) was **fixed upstream by #8196** (whole-turn trim in v0.8.2), confirmed independently by both Audacity88 (MEMBER, 2026-06-26) and dwillitzer (CONTRIBUTOR, 2026-06-27). PR #7440 (IftekharUddin) was opened to add a behavioral guard and was subsequently rebased — its loop-skip code was dropped because the loop itself no longer exists, and it now delivers only the operator-observability improvement (a one-time `WARN` naming the resolved per-profile budget). As of today (2026-06-27 07:03 UTC), **dwillitzer's latest comment** closes the loop on verification against v0.8.2, declares #7440 can close as superseded for the missing-user-turn failure mode, and identifies one remaining open gap: the per-profile footgun where `effective_max_context_tokens` silently falls back to 32k when the agent's `runtime_profile` doesn't set the field, and no `WARN` surfaces which profile actually resolved the budget. The whole-turn trim still fires every iteration as a no-op loop under that condition. dwillitzer has offered to take a fresh PR targeting the current trim path if #7440 closes.

## Who needs what from you

Audacity88 and dwillitzer have done the verification legwork; the thread is now waiting on **you (the issue author / owner) to decide** two things:
1. Whether to formally close #7440 as superseded (Audacity88 flagged this on 2026-06-26; the rebase already implicitly confirmed it), OR direct dwillitzer to open a fresh PR against the current trim path.
2. Whether this issue stays open scoped to the residual per-profile `WARN` gap, or closes now and a new issue is filed for that gap.

## Suggested response

Recommended next move: **keep the issue open, scoped to the residual gap; close #7440 as superseded; and invite dwillitzer's fresh PR.**

Draft comment (edit before posting):

---

Thanks @dwillitzer — that's the verification I needed. The whole-turn trim in #8196 / v0.8.2 closing the missing-user-turn failure is clear; the bisection record stands as the 0.8.1 post-mortem.

Narrowing this issue's scope to the residual gap you identified: `effective_max_context_tokens` silently resolving to `32_000` when an agent's runtime profile doesn't set the field, with no signal that the value the operator configured on a *different* profile never reached the agent. The concrete fix target is a one-time `WARN` that names the **resolved per-profile** budget value and the profile key that owns it, surfaced at the same floor-detection site as the remediation hint. The whole-turn trim still firing as a no-op loop every iteration under that condition is the behavioral symptom to nail down.

@IftekharUddin — since #7440's loop-skip code was superseded, and the rebased PR is now purely delivering the floor-detection `WARN`, can you confirm whether you want to land that as-is or hand it off? If you're closing it, @dwillitzer please go ahead with a fresh PR targeting `history_trim.rs` on current `master`. Scope: per-profile budget resolution in the `WARN` message; no changes to trim mechanics, default budget, or tool surface (those stay in #7100).

⚠ Confirm the exact Rust path for the three emission sites (`agent/turn/mod.rs`, `context_recovery.rs`, loop path) before finalizing — I'm going from #7440's description and haven't re-read the post-#8196 code myself.

---

## Next action
- [ ] Post the drafted comment on #5808 (after editing the ⚠ note above once you've checked the current trim path), then wait for IftekharUddin to confirm #7440's status before greenlighting dwillitzer's fresh PR.
