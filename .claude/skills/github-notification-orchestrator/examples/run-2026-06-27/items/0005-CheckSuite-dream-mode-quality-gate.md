---
notification_id: ""
updated_at: "2026-06-16T21:11:29Z"
reason: "ci_activity"
repo: "zeroclaw-labs/zeroclaw"
type: "CheckSuite"
number: ""
title: "Quality Gate workflow run failed for JordanTheJet/dream-mode branch"
url: "https://github.com/zeroclaw-labs/zeroclaw/actions?query=branch%3AJordanTheJet%2Fdream-mode"
agent_profile: "ci-failure-investigator"
priority: "P2"
status: "action-required"
---

# — Quality Gate workflow run failed for JordanTheJet/dream-mode branch

**Repo:** zeroclaw-labs/zeroclaw · **Type:** CheckSuite · **Reason:** ci_activity · **Updated:** 2026-06-16 21:11 UTC
**Link:** https://github.com/zeroclaw-labs/zeroclaw/actions/runs/27647934283

## What happened

The Quality Gate CI run (run ID 27647934283, commit `a74ee9ff`) failed on PR #6693 "feat(memory): add dream mode for periodic memory consolidation." All other jobs (Format, Security, Lint, Benchmarks Compile, Docs Style, all platform builds) passed. Only the **Test** job failed, at test 1722/8739, causing early cancellation of the remaining 7,014 tests. The CI Required Gate then failed downstream as a result.

The failure is on the `JordanTheJet/dream-mode` branch as of 2026-06-16; a later push on 2026-06-20 (`96f44443`) passed Quality Gate cleanly, so this failure is already resolved on the branch.

## Who needs what from you

FYI only — the branch's Quality Gate is now green (2026-06-20 run 27855721379 passed). No action is required unless you want to understand the fix you made.

## Suggested response

**Root-cause line** (`crates/zeroclaw-config/src/sections.rs:1001`):

```
thread 'sections::tests::every_surfaced_root_has_a_group' panicked at crates/zeroclaw-config/src/sections.rs:1001:9:
these surfaced config roots resolve to SectionGroup::Other — add a `#[group = "..."]` to each in schema.rs
(or, if intentionally uncurated, to the UNGROUPED allowlist): ["dream_mode"]
```

**Failing test:** `zeroclaw-config::sections::tests::every_surfaced_root_has_a_group`

**What broke:** PR #6693 added a new `dream_mode` config root to `crates/zeroclaw-config/src/schema.rs` but omitted the `#[group = "..."]` attribute that the schema enforcement test requires. Every surfaced root must either carry a group annotation (e.g. `#[group = "Agent"]`) or be explicitly listed in the `UNGROUPED` allowlist in `sections.rs`.

**Fix sketch** (already applied in the 2026-06-20 push, noted for reference):
In `crates/zeroclaw-config/src/schema.rs`, on the `dream_mode` field, add:
```rust
#[group = "Agent"]   // or whichever SectionGroup fits — "Operations" is another candidate ⚠
pub dream_mode: Option<DreamModeConfig>,
```
Alternatively, if the field is intentionally ungrouped during development, add `"dream_mode"` to the `UNGROUPED` const slice in `sections.rs:986` as a temporary measure.

## Next action

- [ ] No action needed — Quality Gate is green on the current branch tip. Confirm PR #6693 is ready for review and merge when the feature is complete.

## Verification (verifier · opus)
**Gate: PASS**

Re-inspected the failed run (`gh run view 27647934283 --log-failed`), both endpoint commits' `schema.rs`, and the later run, on `zeroclaw-labs/zeroclaw` as `JordanTheJet`.

- **Root cause = missing `#[group="..."]` on the `dream_mode` config root** — confirmed: at the failed commit `a74ee9ff`, `crates/zeroclaw-config/src/schema.rs:244` declares `pub dream_mode: DreamModeConfig` with only `#[serde(default)]` + `#[nested]`, **no group attribute**. The field genuinely lives in `schema.rs` as stated. (confidence: high)
- **Failing test + panic line** — confirmed verbatim in the log: `thread 'sections::tests::every_surfaced_root_has_a_group' panicked at crates/zeroclaw-config/src/sections.rs:1001:9: these surfaced config roots resolve to SectionGroup::Other … ["dream_mode"]`. Test name and `sections.rs:1001` match exactly. (Note: tests ran against the `pull/6693/merge` tree `872cbd5`, where `sections.rs` is >1001 lines; the raw branch-head blob is only 680 lines — the line number is real in the tested merge tree, an artifact of PR-merge CI, not an error.) (confidence: high)
- **It's the cause, not fallout** — confirmed: of 16 jobs, only **Test** failed; **CI Required Gate** failed downstream emitting `One or more CI jobs failed or were cancelled`. Every other job (Format/Security/Lint/Checks/builds) passed. (confidence: high)
- **Fix already applied = add `#[group = "Agent"]`; Quality Gate now green** — confirmed: at the current branch tip / green commit `96f44443`, the same field now carries `#[group = "Agent"]` (schema.rs:267). Run **27855721379** (Quality Gate) is `success` at headSha `96f44443` with the **Test job green**. The report predicted `#[group = "Agent"]` as the primary fix and that is exactly what landed. (confidence: high)
- **"failed at test 1722/8739, cancelling the remaining 7,014"** — overstated: the nextest summary is `1725/8739 tests run: 1724 passed, 1 failed, 10 skipped`. `1722` is the failing test's display index, not a stop point; ~7,014 indeed never ran (default fail-fast), but the "failed at 1722 → cancelled 7,014" framing conflates the index with the run count. Immaterial to the root cause. (confidence: med)

**Note to user:** Trust the root cause and the "now green" conclusion — both verified against source (missing `#[group]` at `a74ee9ff` → `#[group = "Agent"]` at `96f44443`, Test job green at the tip). This is genuinely FYI/resolved; the `dream_mode` fix in the 06-20 push is real, though that push was also a large rebase onto master, so the green reflects rebase + the annotation, not the annotation alone. Only loose detail: the "1722/8739 → 7,014 cancelled" sentence (actually 1725 ran, 1 failed). Frontmatter `status: action-required` is stricter than the content warrants (FYI); left as-is — downgrade to `fyi`/`resolved` if you want the binder to reflect "no action."
