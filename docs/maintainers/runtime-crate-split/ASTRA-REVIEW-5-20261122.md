# Astra fifth pass on the script fixes

- **Reviewer:** Codex CLI 0.171.0, model `gpt-6.2-astra`, reasoning effort xhigh, read-only sandbox, 2026-11-22.
- **What it reviewed:** the script changes made after the fourth pass (`ASTRA-REVIEW-4-20261122.md`), the two test files, the re-run log and patches, and the record of its verdicts in the documents.
- **What it could not do:** run the two test files (its sandbox denied temp-directory writes; it replayed the inputs in memory), reach the build host or GitHub, or run cargo.
- **State of the folder:** the scripts were not changed after this pass, so what is here is what it reviewed. Its four approval conditions for merging the scripts are recorded in `PLAN.md`, Phase 0.

The review text follows, unedited apart from local file paths and one personal name replaced for
publication.

---

## Verdict

- **Documents — APPROVE WITH FIXES.** REPORT’s table and closing paragraph accurately distinguish all four verdicts. Qualify “both fixed” in REPORT and PLAN. PLAN also omits “with fixes” from pass four’s document approval. [REPORT](REPORT.md#L99) · [PLAN](PLAN.md#L11)
- **Three-commit stack as compile evidence — APPROVE** at `e02b7fb6f6`. Replaying the patches in memory reproduced the **same Git tree at every commit** as pass four. The patches touch 5, 7 and 19 files and preserve the OTel-gated `util` alias and retained entry. All eleven check summaries equal `CLEAN`. The driver ends with `ALL CHECKS PASSED`, followed in the saved log by `DRIVER_EXIT:0` and `ALLDONE`. [Run log](regen-probe-final.log#L17)
- **Scripts as proof — APPROVE** for this saved run.
- **Scripts for repository merge — BLOCK.** My approval conditions are (1) preserve or refuse the generator cases below before mutation, (2) reject the demonstrated false-clean inputs and propagate Git and reporting failures, (3) enforce per-step staged paths, and (4) add regression fixtures for those cases, checker parity, widener edit scope, redaction rewrites and driver failure paths.

## Pass-four findings

- **Major generator — partly fixed.** Ordinary multiline `cfg`, `cfg_attr`, gated inline modules/functions and renamed `#[path]` targets refuse before moving. An adjacent single-line source gate carries correctly, including declaration and forwarding of a feature named only in `lib.rs` for a **new** crate.
- **Major driver — partly fixed.** ANSI-decorated and indented stderr warnings, empty streams, missing completion and failing Python checks stop success. Failed compile rounds retry boundedly. Pinning fixes `HEAD`. Checkout, status, symbolic-ref errors, add, commit, diff and show are checked.
- **Minor tests — partly fixed.** The 20 extractor cases strengthen declaration, membership and retained-entry assertions. The existing-crate case accepts a broken manifest. The 12 diagnostic cases assert clean/nonclean after `.strip()` and conflate compiler error with unsuccessful completion. [Extractor tests](test_extract_module.py#L285) · [Diagnostic tests](test_cargo_diag.py#L38)
- **Minor checker — named cases fixed.** `NaN` and ±`Infinity` refuse. Both reason checks count UTF-8 bytes. A short reason still fails after files move.
- **Staging — partly fixed.** Porcelain column two correctly catches unstaged changes and `??`. Staging all `crates/` absorbs unrelated files, and already-staged outside paths pass. [Driver](regen_probe.sh#L113)

## New findings

1. **Major — Silent gate changes.** In memory, `///` preserved a gate. A blank line, `/** doc */`, or a declaration inside a gated macro invocation produced unconditional `pub mod m;`. Same-line attribute/declaration, gated `use`/`impl`, and `cfg!(…)` refused. A file-level `#![cfg(unix)]` produced an unconditional alias. A simple `#[path]` ancestor refused, but a second path to the same file lost that route’s gate. A nested `#[cfg(test)]` directory correctly gated its alias. Moving the top-level test-only directory breaks the source test re-export because its dependency compiles without `cfg(test)`. [Generator](extract_module.py#L200)
2. **Major — Existing destination.** The fixture forwards `zeroclaw-low/outer` without declaring `outer` there. This branch also omits requested aliases. [Generator](extract_module.py#L405)
3. **Major — False clean.** Indented warning JSON, an indented truncated record after completion, and `"success":"false"` all returned `CLEAN`. I also reproduced final `grep` exit 2 reaching the banner and a failing `rev-parse HEAD~3` passing when stdout matched the base. [Parser](cargo_diag.py#L29) · [Driver](regen_probe.sh#L145)
4. **Minor — Checker parity.** Python accepted unused fields containing `1e400` or a lone surrogate. The fixture’s Rust parser rejects both. [Checker](check_retained.py#L17)

## Could not verify

The sandbox denied temporary directories for both suites. I inspected all 32 cases and replayed all 12 diagnostic inputs in memory. I did not rerun Cargo.