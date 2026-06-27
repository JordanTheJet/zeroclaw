---
notification_id: "24304122480"
updated_at: "2026-06-27T11:04:08Z"
reason: "mention"
repo: "zeroclaw-labs/zeroclaw"
type: "PullRequest"
number: "8033"
title: "feat(onboard): two-path onboard tree wired end to end (LLM + deterministic) over RPC and CLI"
url: "https://github.com/zeroclaw-labs/zeroclaw/pull/8033"
agent_profile: "mention-responder"
priority: "P1"
status: "needs-reply"
---

# #8033 — feat(onboard): two-path onboard tree wired end to end (LLM + deterministic) over RPC and CLI

**Repo:** zeroclaw-labs/zeroclaw · **Type:** PullRequest · **Reason:** mention · **Updated:** 2026-06-27 11:04 UTC
**Link:** https://github.com/zeroclaw-labs/zeroclaw/pull/8033

## What happened

This is your PR (`JordanTheJet`), open since 2026-06-20, adding the `zeroclaw-onboard` crate: a two-path onboarding state tree (Zerona LLM builder + deterministic enum/Select pickers) wired end-to-end over RPC socket and CLI. It targets milestone v0.8.3 and is labelled `risk:high`, `size:XL`. The review picture has gone through several rounds:

- **WareWolf-MoonWall** (CHANGES_REQUESTED → COMMENTED): Initial Fluent-string blockers are now resolved in subsequent heads; their re-review confirms that and adds UX-level warnings.
- **Audacity88** (CHANGES_REQUESTED, 2026-06-24): Blocked on two code defects — `start_agent` masking nonzero child exits as `success: true`, and command-surface guidance not being schema-backed. Both were against head `690a5166`.
- **singlerider** (re-reviewed 2026-06-26 at head `869375cd`, currently CHANGES_REQUESTED from their earlier UX-bake hold): Posted the triggering mention. They confirm the PR is a substantial restructure at `869375cd` that **removes the `start_agent`/`create_agent` tools entirely**, making Audacity88's code-level blockers obsolete against the new head. However, singlerider flags a fresh **merge conflict with master** (`CONFLICTING` per GitHub) as a new hard blocker, and their own UX-bake gate remains in place. Nillth (Marc Collins) has been requested to review but has not yet commented. The PR is not draft, `mergeable: true` per the API at the time of this fetch, but singlerider's review references GitHub reporting it as `CONFLICTING` — ⚠ verify current merge status before acting.

The mention of `@JordanTheJet` is in singlerider's 2026-06-26 review, calling out what needs to happen next.

## Who needs what from you

singlerider is directly asking you (as PR author) to: (1) merge master into the branch and resolve the conflict, (2) re-run the full validation battery against the post-merge head and update the PR's validation evidence with the new tails, and (3) flag Audacity88 that their 6/24 code-level blockers target code that no longer exists at `869375cd` and a fresh evaluation against the new structure is needed. The UX-bake gate from singlerider is also still standing, but that is a hold they will lift when ready — no direct action on your part resolves it.

## Suggested response

> @singlerider — thanks for the re-review at `869375cd` and for flagging the conflict.
>
> On the conflict: will merge master now, resolve, and push. I'll re-run the full battery (`cargo fmt`, `clippy --all-targets -- -D warnings`, `cargo test -p zeroclaw-onboard`, the dispatch/i18n/quickstart suites, `zeroclaw-config`, and `zeroclaw-tools ask`) against the post-merge head and update the validation evidence section with fresh tails.
>
> @Audacity88 — as singlerider notes, the `start_agent`/`create_agent` tools that your 6/24 review blocked on are no longer present at the current head (`869375cd`). The diff is now the onboard tree (`zeroclaw-onboard` lib/plan/run + `quickstart/host.rs`), i18n surface, ask-inputs, and RPC/CLI wiring. When you have a moment, a fresh look against the new structure rather than a carry-forward of the prior blockers would be appreciated — happy to walk through the new shape if that helps.
>
> @singlerider — UX-bake gate noted; I'm not requesting you lift it, just making sure the branch is clean and re-validated so it's in a mergeable state whenever you're ready.

⚠ Confirm current merge conflict status (`gh pr view 8033 --repo zeroclaw-labs/zeroclaw` → check `Mergeable:` field) before sending — the API returned `mergeable: true` at fetch time but singlerider's review (one day earlier) reported `CONFLICTING`.

## Next action
- [ ] Merge master into the branch, resolve any conflicts, re-run the full validation battery, update PR validation evidence with post-merge tails, then post the drafted reply above.
