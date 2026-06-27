---
notification_id: "UNKNOWN"
updated_at: "2026-06-26T13:58:31Z"
reason: "mention"
repo: "zeroclaw-labs/zeroclaw"
type: "Issue"
number: "6407"
title: "[Bug]: Generated i18n catalogs translate code literals and invent docs content"
url: "https://github.com/zeroclaw-labs/zeroclaw/issues/6407"
agent_profile: "mention-responder"
priority: "P2"
status: "fyi"
---

# #6407 — [Bug]: Generated i18n catalogs translate code literals and invent docs content

**Repo:** zeroclaw-labs/zeroclaw · **Type:** Issue · **Reason:** mention · **Updated:** 2026-06-26 13:58 UTC
**Link:** https://github.com/zeroclaw-labs/zeroclaw/issues/6407

## What happened

Dan Gilles (Audacity88) filed this S2 bug documenting that the zh-CN `.po` catalogs merged in PR #6170 contain content-correctness defects: CLI commands (`zeroclaw daemon`) and TOML config keys (`[observability]`, `runtime_trace_mode`) are translated rather than preserved, product names like `ZeroClaw Maturity Framework` are rendered as Chinese common nouns, and one short `msgid` entry was hallucinated into an entire invented API design document. The issue is now **CLOSED** and labelled `status:accepted` + `status:in-progress`, indicating the glossary-aware regeneration follow-up is being tracked elsewhere (milestone: v0.8.3).

The mention of `@JordanTheJet` appears in the "Related review context" section of the issue body: it cites that you deferred the fix to a glossary-aware regeneration pass instead of manual edits during the #6170 review. No question is addressed to you; this is a factual attribution in the bug report.

## Who needs what from you

FYI only — no action needed. The mention is a historical citation of a decision you made in the #6170 review, not a question or request. The issue is closed and the follow-up work is already accepted into the v0.8.3 milestone.

## Suggested response

FYI only — no action needed.

## Next action

- [ ] No reply required. Optionally verify that the glossary-aware regeneration follow-up PR for v0.8.3 exists and is making progress, if you want to confirm the deferred work is on track.
