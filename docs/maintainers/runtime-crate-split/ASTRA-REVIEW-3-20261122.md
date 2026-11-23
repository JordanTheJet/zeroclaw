# Astra third pass on the fixes

- **Reviewer:** Codex CLI 0.171.0, model `gpt-6.2-astra`, reasoning effort xhigh, read-only sandbox, 2026-11-22.
- **What it reviewed:** the fixes made after the second pass (`ASTRA-REVIEW-2-20261122.md`): the rewritten driver, the generator, the regenerated patches and log, and the three documents. Line numbers refer to that revision.
- **What it could not do:** reach the build host or GitHub, or run cargo.

The review text follows, unedited apart from local file paths and one personal name replaced for
publication.

---

**Verdict — APPROVE WITH FIXES for the documents and APPROVE the saved stack as compile evidence at `e02b7fb6f6`, but BLOCK landing the scripts because the driver can accept a dirty worktree and the generator can emit an incorrect feature gate.**

### Status of the pass-two findings

The saved review labels two findings Major and includes retained-dependency registration under compatibility.

- **Blocking driver — partly resolved.** No worktree reset or clean remains. Unknown bases, attached branches and visible changes are rejected before checkout. Generator, widener, final compile, format, add and commit failures propagate. Intermediate compile failures intentionally drive bounded retries. `PIPESTATUS[0]` catches checker failure. [Driver](regen_probe.sh#L22)
- **Major compatibility — resolved for this stack.** PLAN lists `shell_escape`, `SENSITIVE_KV_REGEX`, `SENSITIVE_KEY_REGEX`, `IMAGE_DATA_URI_REGEX`, `scrub_for_export`, the `test-util` lock `HOOK_TEST_LOCK`, and changed `zc_name` and `zc_file` attribution. Its move-review rule now requires disclosure. [PLAN](PLAN.md#L63)
- **Retained registration — correct in patch 3.** Replaying the patches in memory produced 17 normal entries. The new entry has a 186-byte reason and its owner, `crates/zeroclaw-runtime/src/lib.rs`, exists at the measured commit. [Patch 3](probe-patches/0003-refactor-observability-extract-observer-backends-int.patch#L293)
- **Major alias — resolved for patch 3 only.** `util` carries exactly `#[cfg(feature = "observability-otel")]` with no alias-level `allow`. The file retains unrelated crate-level Clippy allowances. [Generated lib.rs](probe-patches/0003-refactor-observability-extract-observer-backends-int.patch#L162)
- **Minor tables — resolved.** The cron row includes `security` 2 and `tools` 2. The 12 files total 6,190 lines. I verified 11 exact renames against patch 2 and 10 against the base.
- **Graph — resolved.** The rerun gave 160,631 production and 284,313 test lines. All three cycle memberships matched, at 109,688, 30,068 and 2,609 production lines. Inventory rows sum to 160,571/284,313, excluding exactly 60 production lines of `lib.rs`. `otel_config.rs:15–23` counts as nine test lines.
- **Exceptions — resolved.** The module split is 43/14/3. Fourteen of the 43 also cover catalogs, and archival now depends on the RFC.
- **Cron and #10557 — resolved.** Closure requires the accepted design and an open, named replacement. All PR 4–8 references agree on design, helpers, seam, extraction and precondition, respectively.
- **SOP — disposition resolved.** The row keeps the types together. Only `SopTriggerSource` is macro-generated. `SopEvent` is an explicit struct. [Source](../../../crates/zeroclaw-runtime/src/sop/types.rs#L717)
- **Mergeability — partly resolved.** REPORT softens the claim. The snapshots reproduce 200 candidates, 196 targeting master, 112 baseline-clean and nine new conflicts split 1/2/6. PLAN still says only additions break, despite recording two rename/delete observations. [PLAN](PLAN.md#L455)

### New findings

1. **Blocking for landing.** I verified `status.showUntrackedFiles=no` hides an untracked file from the exact preflight command. `git add -A` can then commit it. A failed `git status` with empty stdout also passes both cleanliness tests. `set -uo pipefail` leaves unchecked statuses live, including a failed `sed` after the retained checker. Compiler JSON warnings fail a successful check, but Cargo stderr is discarded, so Cargo-level warnings can pass. [Driver](regen_probe.sh#L23)
2. **Major for reuse.** With a parent gated on `outer`, child on `inner`, and the only alias use in the child, I reproduced `cfg(inner)`. Both features are required. `mod_gates` finds both and `alias_cfg` takes `g[:1]`. [Generator](extract_module.py#L207)
3. **Minor checker drift.** In-memory checks accepted a missing `build` object and a 50-element array as a reason. Rust rejects both. Python also counts Unicode characters where Rust counts UTF-8 bytes. [Checker](check_retained.py#L23) · [Rust rule](../../../tests/fixtures/runtime-composition-consumer/src/dependency.rs#L114)
4. **Minor documentation drift.** PLAN lines 422 and 501 omit or deny the fixture edit acknowledged at 505. ARCHITECTURE’s diagram still says 446K for 444,944 lines.

### Could not verify

No Cargo, build-host or live GitHub replay. The saved log records workspace OTel/default all-target checks and a no-default check without `--all-targets`, all excluding desktop. It also records all five standalone feature sets, format and retained-policy success. [Run log](regen-probe-final.log#L17)