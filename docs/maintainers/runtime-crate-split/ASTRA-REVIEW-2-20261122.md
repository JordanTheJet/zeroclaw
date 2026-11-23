# Astra delta review of the revised runtime detangle documents

- **Reviewer:** Codex CLI 0.171.0, model `gpt-6.2-astra`, reasoning effort xhigh, read-only sandbox, 2026-11-22.
- **What it reviewed:** the documents, scripts and patches as revised after the first review (`ASTRA-REVIEW-20261122.md`). Line numbers refer to that revision.
- **What it could not do:** reach the build host or GitHub, or run cargo.
- **Outcome:** every finding below was acted on the same day; `REPORT.md` lists what changed.

The review text follows, unedited apart from local file paths and one personal name replaced for
publication.

---

## Verdict on the revised documents

**BLOCK** on landing the tooling as supplied: the regeneration driver can discard work and report success after failed checks, although the observability extraction is ready for PR review and the proposed RFC and scheduling holds are defensible.

## Status of each prior finding

1. **Resolved.** The resident list is explicitly a proposal. The plan requires an RFC snapshot and Core Team vote and keeps the current exception process in force meanwhile. Opening the RFC in parallel is defensible. [PLAN, governance decision](PLAN.md#L181)
2. **Resolved.** Deferring cron is justified. The design note now covers shell and agent execution, retry revalidation, admission through delivery and persistence, and isolated-run cleanup. PR 5’s size remains unknown. Put the note before PR 4 in the sequence if it gates all cron work. [PLAN, Phase 2](PLAN.md#L253)
3. **Partly resolved.** Recounting the source table reproduced all 60 saved rows, 55 kernel destinations, 50 naming agent/tools/RPC, 24 naming RPC, and the **43/14/3** module split. But 14 of the 43 also cover catalogs. Line 82 explicitly assigns its catalog to channels, so promising to archive all 43 prejudges the RFC. [Exception table](../../../crates/zeroclaw-runtime/AGENTS.md#L82) · [PLAN](PLAN.md#L206)
4. **Partly resolved.** The saved record supports the September 2 requests, September 23 approval, September 25 red master, September 30 semantic blocker and October deferral. Keeping #10546 open through the precondition work is sound. Keep #10557 open until an accepted design **and a named replacement PR** exist before closing it as superseded. [Reviews](https://github.com/zeroclaw-labs/zeroclaw/pull/10557) · [Closure rule](../../../docs/book/src/maintainers/superseding.md#L84)
5. **Partly resolved.** The requested `modgraph2.py` rerun reproduced **161,362 production / 283,582 test**, three excluded files (879 lines), and all three cycle groups at **110,130 / 30,223 / 2,620** production lines. Removing the selected 42 references leaves four cycles. The cron table is incomplete, and test stripping still counts eight of nine lines at `otel_config.rs:15–23`. [Graph output](graph-e02b7fb6f6.txt#L2)
6. **Partly resolved.** Joining both JSON snapshots gives **200 candidates, 196 targeting master, 112 baseline-clean, nine newly conflicting**, incrementally **1/2/6**. The author can defend those measurements. The general “stays mergeable” claim still exceeds them: SOP has a pure-move conflict, two of 35 break observations are rename/delete, and the simulator filters on source paths. [Exposure data](exposure-stack-e02b7fb6f6.json) · [Simulator](simmove.py#L74)
7. **Partly resolved.** Deferring hosts and SOP is sound. PLAN identifies the RPC function calls, fixture paths and macro-generated inherent implementation. ARCHITECTURE still prescribes moving the two SOP types separately, the design PLAN rejects. [ARCHITECTURE](ARCHITECTURE.md#L201) · [PLAN](PLAN.md#L333)
8. **Partly resolved.** Patch 2 keeps `elide_image_data` private and preserves scrub order across the two qualification edits. PLAN corrects the test-lock explanation and review diff. Its public-API count and hard behavior-preservation rule still need correction. [Patch 2](probe-patches/0002-refactor-providers-give-credential-redaction-one-own.patch#L95) · [PLAN](PLAN.md#L402)

## New findings

- **Blocking — The driver is unsafe to land.** It runs `git reset --hard` and `git clean -fdq crates` in the supplied worktree before validating the base. Extractor failures can disappear behind `head -1` without `pipefail`. Failed default-workspace and standalone checks merely print their exit codes. Require a clean disposable worktree and propagate every failed check. The saved run itself records success. [Driver](regen_probe.sh#L11)
- **Major — The compatibility inventory understates the change.** Patches 1–2 publish five formerly crate-private production items: `shell_escape`, three regex statics and `scrub_for_export`. Patch 3 also exposes `HOOK_TEST_LOCK` under `test-util`. Moving the logging calls changes emitted `zc_name` and source-file attribution. Accept that explicitly before merge and add the acknowledged retained-dependency registration. [Patch 2](probe-patches/0002-refactor-providers-give-credential-redaction-one-own.patch#L42) · [Logging macro](../../../crates/zeroclaw-log/src/macro.rs#L10) · [Registration test](../../../tests/fixtures/runtime-composition-consumer/src/dependency.rs#L94)
- **Major — Gate the generated `util` alias on `observability-otel`.** Its sole use is in `otel.rs`. The root dead-code rule does not categorically prohibit `allow(unused_imports)`, but the generator applies it to **every** alias, bypassing the feature-mismatch check CI expressly intends. For this patch, require the matching `cfg`. [Generator](extract_module.py#L251) · [Module gate](../../../crates/zeroclaw-runtime/src/observability/mod.rs#L5) · [CI rationale](../../../.github/workflows/ci.yml#L746)
- **Minor — Correct the tables.** The cron row omits `security` **2** (`SecurityPolicy`, config-owned) and `tools` **2** (`decode_shell_output`, planned relocation). The SOP row matches. Patch 3 alone has **11/12** exact renames, **10/12** against the original base. The 12 files contain **6,190** lines; the extractor adds 11 join separators when reporting 6,201. [Dependency table](ARCHITECTURE.md#L213) · [Extractor](extract_module.py#L159)

## Could not verify

No Cargo, build-host, network or merge replay. The saved log records warning-free all-target workspace checks excluding desktop, with OTel after each step and defaults on the final stack, plus a passing format check. The four standalone sets were empty, Prometheus, OTel and all three features together. `test-util` alone, tests, Clippy, rustdoc, downstream builds and live GitHub mergeability remain unverified. [Build log](regen-probe-final.log#L16)