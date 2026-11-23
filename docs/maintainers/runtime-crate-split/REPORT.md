# Runtime split: report

2026-11-22, base `master` at `e02b7fb6f6`. This is a proposal for discussion: nothing in it is decided, and none of
the code has been opened as a pull request. Detail: `ARCHITECTURE.md`, `PLAN.md`. How it was produced and how to
re-run it: `README.md`.

## Recommendation

**Start the part that is proven: extract `observability`, and harden the move tooling before it lands. In parallel, open an RFC on which
modules stay in `zeroclaw-runtime`. Do not start cron until a short design note settles who owns execution admission.**

- **The exceptions come from two documents that disagree.** 55 of the 60 rows send code to `zeroclaw-kernel`, a crate
  nothing schedules. FND-001 (line 612) puts the agent loop, security policy, plugin host and IPC API in
  `zeroclaw-runtime`; the holding-crate contract lists the agent loop, security and skills for extraction. Settling
  that is a governance change and needs an RFC and a vote (FND-003 §8).
- **The crate is three layers, not one knot.** 42 references point up from seven subsystems into the core. `agent`
  and `tools` are one unit and stay together.
- **A move that does not edit the moved files breaks very few open pull requests.** Measured against all 588: moving
  `cron` byte-for-byte breaks 0 of the 23 that merge today; the same move with path edits inside the files breaks 9.
  For `sop` it is 1 against 12. What still breaks is a pull request that adds or deletes a file in the moved
  directory.

## The first three pull requests

Built by script and compile-checked on a Linux build host. They are local commits, **not opened as pull
requests**. The patches are in `probe-patches/` and apply in order to `e02b7fb6f6`.

| # | Change | Reviewer reads | Open PRs it breaks |
|---|---|---|---|
| 1 | `util` moves into `zeroclaw-infra` | 5 files, +7/−2 | 1 |
| 2 | Credential redaction gets one owner below the agent loop | 7 files, +54/−52 | 2 |
| 3 | `observability` becomes the crate `zeroclaw-observability` | 19 files, +100/−6; 11 of the 12 moved files are exact renames | 6 |

That is 9 of the 112 pull requests that touch these files and merge today. The breaks are in `Cargo.toml`,
`Cargo.lock`, `agent/loop_.rs` and the redaction file that step 2 both moves and edits. None is in a file that moved
without edits.

`regen_probe.sh` rebuilds and re-checks all three from a clean checkout in about 12 minutes, so a stale branch is
regenerated, never rebased.

## Decisions for the maintainers

1. **Open the governance RFC?** It would amend the holding-crate contract so named *resident* modules need no
   exception and only *held* modules do. Which modules are resident is the question the RFC has to settle; under the
   list proposed here, up to 43 of the 60 rows would no longer be needed (14 of those also cover locale catalogs, whose
   owner the RFC must settle too). Recommended: open it. It gates nothing else.
2. **Go ahead with the `observability` extraction?** It needs no governance decision. The three commits can be opened
   as pull requests as they are, once tests, clippy and rustdoc have run on them. The move scripts are a proof;
   the review below blocks merging them into the repository until four listed conditions are met.
3. **Cron: commission the design note.** #10557 stays open as the record until that note is accepted and the
   replacement pull request is open, then closes with a comment naming it. Do not rebase it.
4. **#10546's rule** that the old path is "deleted, not re-exported or shimmed". Relax it to: re-export allowed.
   That rule is what forced #10557 to edit about 25 caller files.
5. **Crate names**, which are permanent once published, starting with `zeroclaw-observability`.
6. **Home for the redaction helpers:** `zeroclaw-providers` (what the prototype does) or `zeroclaw-infra`.

## Review status

A second model (`gpt-6.2-astra`, called astra below) reviewed this adversarially five times; `REVIEW-LOG.md` has
each verdict and what it changed.

- **These documents: APPROVE WITH FIXES**, on each of the last three passes; the fixes are applied. The first pass was
  a BLOCK and was right: the first draft treated the governance question as settled and scheduled cron as if its seam were
  designed.
- **The three commits: APPROVE as compile evidence**, and ready for pull request review.
- **The move scripts: APPROVE as a proof, BLOCK for merging into the repository.** Astra gave four conditions for
  that (`PLAN.md`, Phase 0). The scripts are unchanged since its last pass.

## Not verified

- **Only `cargo check` and `cargo fmt --check` ran.** Whole workspace with default features, with OpenTelemetry
  added, and with no default features; and the new crate alone with each of its features. Tests, clippy, rustdoc,
  the all-features workspace build, macOS and Windows did not.
- **The prototype omits most registration edits** a new crate needs (labeler, CODEOWNERS, docs). It carries the one
  a test enforces, checked against the test's rule without running the test.
- **Conflict counts are textual and local.** A pull request that still merges may fail to compile after a move, and
  The measurement assumes GitHub merges the way local git 2.43 does.
- **Cron, the hosts and SOP** are analysed from the graph and the source, not built.
- **Astra could not reach the build host or GitHub,** so it checked the compile and the merges against saved logs only.
- **From secondary research, not re-checked against the source:** CI duration and merge-throughput statistics, the CODEOWNERS
  table, and the Core Team list.

## Noticed along the way

Three source files in the runtime crate are not compiled, because no `mod` declares them:
`platform/traits.rs`, `platform/wasm.rs` and `skills/symlink_tests.rs` (879 lines).
