# Review log: astra's five passes and what each changed

2026-11-22. This is the detail behind the "Review status" lines in `REPORT.md`. The reviewer is a second model,
`gpt-6.2-astra` (called astra here), run in a read-only sandbox and asked to attack the documents: recompute the
numbers, check quotes against their sources, and look for what the plan ignores. Its reviews are
`ASTRA-REVIEW-20261122.md` and `ASTRA-REVIEW-2-…` to `ASTRA-REVIEW-5-20261122.md` in this folder, unedited apart from
local file paths and one personal name replaced for publication. Astra could not reach the build host or GitHub,
or run cargo.

## The five verdicts

| Pass | Verdict | What it turned on |
|---|---|---|
| 1 | BLOCK | The drafts treated the governance question as settled and scheduled cron as if its seam were designed. Right on most of eight findings; documents revised |
| 2 | BLOCK, on one thing | Accepted the governance and scheduling changes and said the `observability` extraction is ready for pull request review. Blocked on the regeneration script, which could discard work and report success after a failed check |
| 3 | Documents: APPROVE WITH FIXES. The three commits: APPROVE as compile evidence. Scripts: BLOCK for merging into the repository | Three more holes in the scripts: untracked files hidden by a git setting, cargo's own warnings ignored, a wrong gate for nested features |
| 4 | Documents: APPROVE WITH FIXES. The three commits: APPROVE. Scripts as a proof: APPROVE. Scripts for merging: BLOCK | The move script guessed where it could not read a `cfg` exactly, and dropped a gate on the moved module itself; the driver's warning detection had gaps |
| 5 | The same four verdicts as pass 4. It replayed the patches and got the same tree at every commit | More inputs of the same kinds, and a closed list of four conditions for approving the scripts for merge (`PLAN.md`, Phase 0). The scripts are unchanged since this pass |

The scripts were not changed after pass 5, so the folder holds what it reviewed. Its four conditions for approving
them for merge are in `PLAN.md`, Phase 0.

## What the first pass changed

| Astra found | Status |
|---|---|
| The governance change needs an RFC and a vote, and FND-001 does not make today's whole `tools`, `security` and `rpc` directories permanent | Right. The draft had called it a docs change and overstated what FND-001 settles. Now an RFC running in parallel |
| The cron seam left execution admission unspecified: the scheduler revalidates it on shell paths too, at about 20 places | Right. Cron now starts with a design note, and its size is "unknown" until then |
| The draft dropped an exception row (60, not 59) and its resident/held split used a different module list than the plan | Right. Recounted: 60 rows, 55 to `zeroclaw-kernel`, 43/14/3 |
| The #10557 account overstated: both owners were requested on day one; git did follow the renames; no missed merge slot is on record | Right. Rewritten from the timeline |
| The graph script counted files nothing compiles, and `platform` is only a re-export of `zeroclaw-config` | Right. Script fixed; totals are 161K production, 284K test; the `platform` move is gone from the plan |
| The host and SOP phases were not implementable as sketched (`rpc` calls `doctor` functions; SOP trigger types are macro-generated) | Right. Both are now marked not ready to schedule |
| The conflict experiment needed caveats, and "zero conflicts after the members-list fix" was never simulated | Right. Caveats added and that claim removed. Every measured cell was confirmed as transcribed |
| The prototype made one helper public for no reason, and the "verbatim" claim ignored two path edits | Right. Helper is private again; wording fixed |
| A workspace build can hide a missing feature | Right, and it exposed a real defect: with the OTel feature off, which is the default build, the generated `lib.rs` had an unused import that CI's lint job would have rejected. Script fixed; the default build and the new crate on its own now compile with no warnings |

The second pass added four things, all fixed:

| Astra found | Status |
|---|---|
| The regeneration script ran `git reset --hard`, could hide a failed step, and only printed failed checks | Right, and blocking. It now refuses a dirty or on-branch worktree, never resets, and stops on any failed check or warning |
| The compatibility list was short: five items became public, not three, and log events change their recorded module and source file | Right. Both are now listed and each move must declare them |
| The generated alias should carry a feature gate, not a blanket `allow` | Right. Each alias now gets the same gate as the files that use it |
| #10557 should close only once a named replacement pull request exists; the cron table was incomplete; a line-count off-by-one overstated production code by 731 lines | Right. All three corrected |

The third pass confirmed the numbers again and found three more holes in the scripts, all fixed, none yet reviewed:

- **The driver could miss untracked files** when a git setting hides them, and then commit them. It now asks git for
  them explicitly; the case was reproduced and it refuses.
- **The driver ignored warnings cargo prints itself.** They now fail the run.
- **The alias gate was wrong for a module nested under two feature gates.** It now requires both, and
  `test_extract_module.py` covers that case and eight others.

The fourth pass found two more classes of fault in the scripts. The cases it named are fixed:

- **The move script guessed.** Where it could not read a `cfg` exactly (a multi-line attribute, `cfg_attr`,
  `#[path]`, conditional code inside a file) it emitted an ungated alias, and it dropped a gate on the moved module
  itself. It now carries a gate exactly or refuses and asks for it to be stated. Nothing in the `observability`
  move hits these cases, so the three commits are unchanged.
- **The driver could read a bad run as clean:** a coloured or indented cargo warning, an empty or cut-off result
  stream, or a git error. A run now counts as clean only on one exact result line, and 12 test cases pin down what
  must not pass. The move script has 20.

The fifth pass found further inputs of both kinds that still go wrong, for example a blank line between a `cfg`
attribute and its `mod`, or a malformed result record read as clean. None occurs in this repository's
`observability` code, and it confirmed the three commits are byte-for-byte what it approved before. The scripts were
left unchanged from there, so the folder holds exactly what was reviewed, and its four conditions for
merging them are recorded as the acceptance list for the tooling pull request.

What stands: the move method, the proof and the measurements, and astra's rechecks of the numbers
agree with them. Its first BLOCK was on treating the governance question as settled and on scheduling cron as
specified; both were accepted and the documents no longer do either. Its later BLOCKs are on merging the move scripts into the
repository, which is also accepted: they are a proof. It approved the `observability` extraction for pull request
review, and the three commits as compile evidence.
