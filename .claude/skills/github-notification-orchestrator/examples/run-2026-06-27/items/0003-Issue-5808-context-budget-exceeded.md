---
notification_id: "REPLACE_THREAD_ID"
updated_at: "2026-06-27T07:04:12Z"
reason: "author"
repo: "zeroclaw-labs/zeroclaw"
type: "Issue"
number: "5808"
title: "[Bug]: Default 32k context budget is exceeded by system prompt + tool definitions on iteration 1, causing perpetual preemptive trim"
url: "https://github.com/zeroclaw-labs/zeroclaw/issues/5808"
agent_profile: "author-activity-responder"
priority: "P1"
status: "action-required"
---

# #5808 — [Bug]: Default 32k context budget is exceeded by system prompt + tool definitions on iteration 1, causing perpetual preemptive trim

**Repo:** zeroclaw-labs/zeroclaw · **Type:** Issue · **Reason:** author · **Updated:** 2026-06-27 07:03 UTC
**Link:** https://github.com/zeroclaw-labs/zeroclaw/issues/5808

## What happened

Since you last looked, two contributors moved this issue significantly forward. On 2026-06-26, maintainer Audacity88 asked dwillitzer to verify whether the original missing-user-turn failure (#5636/1214 errors) still reproduces on current master after #7540 and #8196 landed — and flagged that PR #7440 (IftekharUddin's behavioral-guard fix) should rebase/retarget or close as superseded. Today (2026-06-27 07:03 UTC), dwillitzer posted a thorough verification comment confirming: the missing-user-turn failure **no longer reproduces on v0.8.2** — the new `trim_to_recent_turns` path in `history_trim.rs` from #8196 keeps the most recent user turn by construction and the old `Preemptive history prune applied … dropped=N` path is gone. dwillitzer also confirmed zero 1214 responses since upgrading. However, they called out a **residual gap** still live: `effective_max_context_tokens` silently falls back to 32k when an agent's runtime profile doesn't set the field, so operators who set `max_context_tokens` on the wrong profile hit the 32k floor with no warning — the whole-turn trim still fires every iteration as a no-op loop. dwillitzer offered to open a fresh PR targeting the new trim path for the one-time WARN with the resolved per-profile budget.

## Who needs what from you

dwillitzer is explicitly waiting on a signal from you (as the issue author) about whether to proceed with a fresh PR for the per-profile WARN, or whether you want to handle this differently. Audacity88's note was that the first preference is for #7440 to rebase/retarget — but if #7440 closes as superseded, a fresh PR from dwillitzer would be welcome. You need to close the loop: confirm whether #7440 is being closed, and greenlight or redirect dwillitzer's PR offer.

## Suggested response

The core bug (missing-user-turn / 1214 loop) is resolved by #8196. The residual gap (silent per-profile 32k fallback with no-op trim loop) is real and still warrants a fix. Given that #7440 was targeting the old code path and Audacity88 already flagged it for rebase-or-close, the cleanest path is:

1. Confirm #7440 closes as superseded (the failure mode it fixed is gone).
2. Accept dwillitzer's offer for a fresh PR targeting the new `history_trim.rs` path — scoped to: detect when `estimate_system_floor_tokens >= effective_max_context_tokens`, emit one `WARN` naming the **resolved per-profile** budget value (not just "raise `agent.max_context_tokens`"), and skip the destructive trim when only fixed overhead is over budget.
3. Update the issue's scope to reflect the narrowed residual gap.

Drafted comment (edit before posting):

---

Thanks for the verification, @dwillitzer — this is exactly the signal the issue needed.

Concurring: the original missing-user-turn / 1214 failure is closed by #8196. #7440 can close as superseded for that failure mode.

The residual gap you've identified — `effective_max_context_tokens` silently falling back to 32k when the agent's runtime profile doesn't set the field, with the whole-turn trim firing as a no-op loop — is worth a targeted fix. I'd welcome a PR from you scoped to that: detect the system-floor-over-budget condition, emit a one-time `WARN` naming the **resolved per-profile** budget (so operators know which profile actually needs updating), and skip the no-op trim. That's the behavioral guard from the original option 3, retargeted to the current `history_trim.rs` path post-#8196.

Please target `master` and keep it scoped to the per-profile discoverability gap; the budget default and tool-surface changes stay with #7100.

---

## Next action

- [ ] Post the drafted comment on #5808 to close the loop for dwillitzer and explicitly greenlight the fresh PR (edit the ⚠ implicit per-profile scope if needed before posting).
