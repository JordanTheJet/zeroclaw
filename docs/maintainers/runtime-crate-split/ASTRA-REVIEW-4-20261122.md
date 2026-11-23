# Astra fourth pass on the script fixes

- **Reviewer:** Codex CLI 0.171.0, model `gpt-6.2-astra`, reasoning effort xhigh, read-only sandbox, 2026-11-22.
- **What it reviewed:** the script fixes made after the third pass (`ASTRA-REVIEW-3-20261122.md`), the new tests, and the small document fixes. Line numbers refer to that revision.
- **What it could not do:** run the fixture tests (its sandbox denied temp-directory writes), reach the build host or GitHub, or run cargo.

The review text follows, unedited apart from local file paths and one personal name replaced for
publication.

---

## Verdict

- **Documents — APPROVE WITH FIXES.** REPORT’s table records all three verdicts accurately. Its closing paragraph describes only the first block, obscuring that passes two and three explicitly blocked landing the tooling. [REPORT](REPORT.md#L97)
- **Three-commit stack as compile evidence — APPROVE** at `e02b7fb6f6`. The patch IDs match the log. It records format, three workspace checks excluding desktop (only OTel/default used `--all-targets`), five standalone feature sets, 17 retained entries and `ALL CHECKS PASSED`. Patch 3 retains the OTel-gated `util` alias and policy entry. [Log](regen-probe-final.log#L17) · [Patch 3](probe-patches/0003-refactor-observability-extract-observer-backends-int.patch#L177)
- **Scripts as proof — APPROVE** for this saved run.
- **Scripts for repository merge — BLOCK.** The driver can report success after missing warnings, and extraction can silently widen a public module’s availability.

## Pass-three findings

- **Blocking driver — Partly fixed.** The preflight exposed two files hidden by `status.showUntrackedFiles=no`. A simulated `git status` failure with empty stdout refused. Both status checks, the retained checker and `mktemp` now propagate failure.
- **Major generator — Original counterexample fixed.** Nested gates and two stacked single-line `cfg` attributes both produced `all(inner, outer)`. Alternative files contribute disjunctions.
- **Minor checker — Named cases fixed.** Both tables must be objects and both fields strings. Twenty-five `é` characters satisfy Rust’s 50-byte threshold.
- **Minor documents — Fixed.** PLAN lists all five modified files, identifies the implemented registration and distinguishes 33 additions from two rename/delete observations. ARCHITECTURE says 445K and correctly distinguishes the `SopEvent` struct from macro-generated `SopTriggerSource`.

## New findings

- **Major — Driver.** Successful `loop` and `must_check` calls reject plain `warning:`. Their shared check accepted ANSI-prefixed and indented warnings and `grep` exit 2, and rejected benign `warnings: none`. Failed retry rounds skip warning inspection. Empty or truncated compiler JSON reported zero warnings. Generator, widener, compile, format, stage and commit failures otherwise stop or exhaust bounded retries. An unexpected `symbolic-ref` error counts as detached. Final diff/log/show failures are ignored. Passing `HEAD` as base makes the review diff compare `HEAD` with itself. [Driver](regen_probe.sh#L63)
- **Major — Generator.** In memory, multiline `cfg`, `cfg_attr`, feature-gated inline modules and functions, and a renamed `#[path]` target all produced unconditional aliases. A single-line `#[path]` preserving the filename worked. An unused alias warns only if the matrix exercises that configuration with the lint enabled. A source `lib.rs` gate reaches the alias, yet the destination emits unconditional `pub mod m;`. A feature named only in `lib.rs` also lacks declaration and forwarding. This can break compilation or silently expose a platform-specific API. [Generator](extract_module.py#L329)
- **Minor — Tests.** The nine cases target their stated behaviors, including the exact nested reproduction. Manifest generation and forwarding get substring checks for one simple feature. The workspace-member assertion passes with only the dependency path present. `alias_line` checks only the preceding line. Retained insertion and `--to-crate` lack fixture coverage. [Tests](test_extract_module.py#L147)
- **Minor — Checker parity.** Python accepted `NaN` in an unused policy field that `serde_json` rejects. The generator still measures its reason in characters.
- **Staging.** `git add -A` skips ignored untracked files but includes tracked edits and nonignored Cargo or editor files created mid-run. That is acceptable for an exclusively owned disposable proof. Stage explicit paths in repository tooling.

## Could not verify

The sandbox denied fixture creation before case one. I inspected all nine cases and exercised the generator in memory. No Cargo, build-host or live GitHub replay.