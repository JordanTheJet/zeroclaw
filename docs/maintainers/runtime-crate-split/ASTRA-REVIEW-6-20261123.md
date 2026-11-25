# Astra sixth pass: the work plan and the issue diagrams

- **Reviewer:** Codex CLI 0.171.0, model `gpt-6.2-astra`, reasoning effort xhigh, read-only sandbox, 2026-11-23.
- **What it reviewed:** the first drafts of `WORK-PLAN.md` and `ISSUE-DIAGRAMS.md`, against `PLAN.md`, the saved data and the repository. Line numbers refer to those drafts.
- **What it could not do:** compile, check live GitHub mergeability, or render the diagrams.
- **Outcome:** every finding was checked against the source and accepted. `WORK-PLAN.md` was rewritten and the diagrams corrected; the seventh pass (`ASTRA-REVIEW-7-20261125.md`) reviews the result.

The review text follows, unedited apart from local file paths shortened for publication.

## Verdict

- **[WORK-PLAN.md](WORK-PLAN.md) — BLOCK** pending corrections to patch history, PR prerequisites, move-day validation, and governance and reviewer instructions.
- **[ISSUE-DIAGRAMS.md](ISSUE-DIAGRAMS.md) — APPROVE WITH FIXES** to the reference legend, host list, and prototype statuses.

## Findings

1. **High · D3–D7 and gate diagram.** PR 7 is missing PR 5 and decision 5 on the cron crate name. Cron references `health` six times and calls `tools::shell_output` twice. PR 5 needs a recipe for that nested decoder. `health` is top-level at `health/mod.rs` with 144 production lines. Keep PR 6, merged 0b, and amended #10546 as PR 7 gates. PRs 1–3 can precede 0b. D5 correctly closes #10557 once the note is accepted and PR 6 is **open**. Restore `Supersedes #10557` on PRs 6–8 and route #10836 separately or within PR 6.

2. **High · A1, lines 69–77.** Seven of the 83 commits touched four patch paths, including `Cargo.lock` (+113/−35), providers’ `lib.rs`, `agent/loop_.rs`, and `agent/turn/mod.rs`. All three patches still replayed cleanly in memory at `d8c1864f0d`. PRs 1 and 2 have disjoint paths in the providers prototype. Patch 2 passed standalone `git apply --check` on the measured tree. Validate that standalone head before opening it independently. Recheck overlap if decision 6 selects infra. PR 3 needs both predecessors.

3. **High · A4–A7.** Provide a PR-3-only recipe after PRs 1 and 2 merge. `regen_probe.sh` starts by moving `util` again, and `extract_module.py:468` puts two workspace members on one line after 0c. A5 matches the plan’s seven registration files, though risk-labeler has no observability rule to migrate. The estimated 55 lines bring +100/−6 to about 161 against the 150-line move limit. Measure or split registration. Apply move-day checks and conflict assistance from PR 1. Remeasure the six root-manifest conflicts on the actual post-0c candidate.

4. **Medium · Gate diagram, tracks B/C.** Reconcile 0c’s decision-2 gate with the tracker, which names only PRs 1–3. Show A5 before PR 3. Decisions 1 and 3 gate filing and review respectively. Both drafts can start now. B2 needs B1, B3 needs B2, and tooling approval belongs after C2’s proof. RFC disclosure and human accountability are correct. The normal 72-hour vote requires two explicit ballots for quorum. The default two-thirds threshold uses the final active electorate. A valid `REVISE` stops the snapshot, a final `REJECT` blocks acceptance, and deferral is possible.

5. **Medium · Lines 81–83, 125–142, 162.** Listed CODEOWNERS match. Add registration owners, especially `labeler.yml`’s Audacity88/IftekharUddin. Maintainer sponsorship of every PR is unsupported. PR 6’s traffic is hardly unique: 103 PRs touched `Cargo.lock`. A narrower resident list changes C3’s coverage. A tunnel probe leaves the doctor/RPC decision and SOP design outstanding.

6. **Medium · Diagram 2.** Restore `relay_dashboard` within 14.6K. Label providers as the prototype redaction home and infra as the alternative. Give infra mixed status because only `util` was built. Other sizes and proposed dependency directions match the target tables. Patch 3 declares both observability dependencies.

7. **Low · Diagram 1.** All 15 sizes, displayed bands, and 11 dotted counts match. The counts total 42, including three subsystem-to-subsystem references. `agent`→`tools` is 26 and the reverse is 64. The graph counts source references, so change “call each other … times.”

## Could not verify

Compilation, live GitHub mergeability, or rendering. By inspection, all three Mermaid blocks have quoted labels, balanced shapes, and consistent hexagon, subgraph-edge, and `classDef` syntax.