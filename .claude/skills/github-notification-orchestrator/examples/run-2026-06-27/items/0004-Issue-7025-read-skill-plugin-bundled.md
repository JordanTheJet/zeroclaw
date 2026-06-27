---
notification_id: "REPLACE_THREAD_ID"
updated_at: "2026-06-22T05:16:31Z"
reason: "assign"
repo: "zeroclaw-labs/zeroclaw"
type: "Issue"
number: "7025"
title: "[Bug]: read_skill cannot load plugin-bundled skills the prompt advertises"
url: "https://github.com/zeroclaw-labs/zeroclaw/issues/7025"
agent_profile: "issue-responder"
priority: "P2"
status: "action-required"
---

# #7025 — [Bug]: read_skill cannot load plugin-bundled skills the prompt advertises

**Repo:** zeroclaw-labs/zeroclaw · **Type:** Issue · **Reason:** assign · **Updated:** 2026-06-22 05:16 UTC
**Link:** https://github.com/zeroclaw-labs/zeroclaw/issues/7025

## What happened

This S2 bug, filed by metalmon on 2026-05-30, documented a split between the prompt builder and `read_skill`: the prompt builder (via `load_skills_with_config`) extended plugin skills under `feature = "plugins-wasm"`, but `ReadSkillTool` only resolved through `load_skills_with_open_skills_settings`, which never called `load_plugin_skills_from_config`. The result was that any plugin-bundled skill listed under "## Available Skills" returned `Unknown skill '<name>'` when the model called `read_skill` in compact mode. The issue was already labeled `bug`, `runtime`, `skills`, `tool`, `priority:p2`, `status:in-progress`, and `status:accepted`. The issue is now CLOSED: member singlerider left a comment on 2026-06-22T05:16:09Z confirming the fix landed in PR #7245, which unified resolution through `load_skills_for_agent_from_config` → `load_skills_for_agent` → `load_skills_with_config` → `load_plugin_skills_from_config`. The linked PR used "Related" rather than "Closes", so the issue stayed open briefly before being closed.

## Who needs what from you

The issue is already closed and the fix is confirmed merged. You are assigned but no action is technically required; however, as an assignee you should verify the fix is satisfactory and confirm (or reopen if there's a gap) so the issue does not linger ambiguously on your plate.

## Suggested response

**Triage call:**
- Classification: bug (confirmed fixed)
- Labels already applied correctly: `bug`, `runtime`, `skills`, `tool`, `priority:p2`, `status:accepted` — no label changes needed.
- Duplicate search: no duplicates found. #7757 (gateway dashboard misses plugin skills) is topically related but a different surface; not a dup.
- Next action: `triaged / verified-fixed` — issue is closed, fix is in master via #7245.

**Drafted verification comment (post only if you want to leave a paper trail as assignee):**

> Thanks for the thorough root-cause writeup and for landing the fix, @singlerider. I've confirmed that `ReadSkillTool` now routes through `load_skills_for_agent_from_config`, which includes `load_plugin_skills_from_config` under `plugins-wasm`, matching the prompt builder's resolution path. The `read_skill` contract should now hold for every skill the model can see. Leaving this closed; will reopen if any edge case surfaces.

⚠ Verify on your own checkout against master to confirm #7245 is present before posting.

## Next action
- [ ] Confirm the fix in #7245 covers your use cases; if satisfied, no further action needed — you can simply dismiss the notification. If a gap is found, reopen the issue with a concrete repro.
