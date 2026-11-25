# Detangling zeroclaw-runtime: a plan that merges

2026-11-22. Base: `master` at `e02b7fb6f6`. The current state behind this plan is in
`ARCHITECTURE.md`. This is a proposal for discussion; nothing in it is decided.

Revised the same day after five adversarial reviews by a second model (`gpt-6.2-astra`, called astra below). The first returned BLOCK on the
drafts; its text is in `ASTRA-REVIEW-20261122.md`. The second accepted the governance and scheduling changes and
blocked on the regeneration script, which could discard work and report success after a failed check; its text is in
`ASTRA-REVIEW-2-20261122.md`. The third (`ASTRA-REVIEW-3-20261122.md`) approved these documents with small fixes,
approved the three-commit stack as compile evidence, and still blocked landing the scripts in the repository, naming
three more holes. The fourth (`ASTRA-REVIEW-4-20261122.md`) approved the documents with fixes, the stack, and the
scripts as a proof, and blocked merging the scripts again: the move script guessed where it could not read a `cfg`
exactly. The fifth (`ASTRA-REVIEW-5-20261122.md`) gave the same four verdicts, confirmed the three commits are
unchanged, and set out four conditions for approving the scripts for merge; they are listed under Phase 0. The scripts have
not changed since, so the folder holds what it reviewed.

On the first review, each finding was checked against the sources and it was right on most. What changed: the
governance step needs an RFC and a vote, not a docs change; the cron seam is not ready to build and now starts with a
design note; the host and SOP phases are marked as not ready to schedule; the #10557 account is corrected; several
counts are corrected. What did not change: the move method, the proof, and the conflict measurements.

## The recommendation

1. **Do not move the agent out of the runtime. Move everything else out, and settle in an RFC which modules stay.**
   The architecture document's Phase 2 deliverable puts the agent loop, security policy, plugin host and IPC API in
   `zeroclaw-runtime`. The holding-crate contract and later documents send the same code to a future
   `zeroclaw-kernel` that nothing schedules. That disagreement produces most of the exception rows. Resolving it is a
   governance change, so it needs an RFC and a Core Team vote.
2. **Extract the rest one module at a time, by script, without editing the moved files.** The module keeps its name in
   the new crate and the runtime re-exports it, so no caller changes anywhere. This is built for `observability` and it
   compiles. Measured against today's open pull requests, the moved code breaks 0 to 4 of them per module, and the
   manifest edits a new crate needs add up to 6 more. The same move with path edits inside the files breaks 9 of 23
   for `cron` and 12 of 27 for `sop`.
3. **Separate the three things #10557 bundled.** Cut the wrong-way references first, as small changes in place. Move
   second, as a pure rename. Add features third, in the new crate. Every blocking code finding on #10557 was in the
   seam or the feature. None was in the move.
4. **Start with what is proven and do not wait for the rest.** The tooling and the `observability` extraction need no
   governance decision and no design work. Cron needs a design note first. The hosts and SOP are not ready to schedule.

## What the proof showed

The first three pull requests of this plan were built on a Linux build host. They are three local commits, not
opened as pull requests; the patches are in `probe-patches/`.

| Step | What it does | Files | Lines changed outside renames | Edits inside moved files |
|---|---|---:|---|---|
| 1 | `util` moves into `zeroclaw-infra` | 5 | +7/−2 | 1 line: `pub(crate) fn shell_escape` became `pub` |
| 2 | Redaction helpers get one owner below the agent loop | 7 | +54/−52 | Not a module move. Function bodies are unchanged except two path qualifications (`crate::approval::…` and `zeroclaw_providers::…` become local) |
| 3 | `observability` becomes `zeroclaw-observability` | 19 | +100/−6, of which 28 added lines are `Cargo.lock` | 2 lines: a test-only lock is re-gated behind `test-util` and made `pub` |

- **It compiles.** After each step, `cargo check --workspace --exclude zeroclaw-desktop --all-targets --features
  zeroclaw-runtime/observability-otel` passes with no warnings. On the finished stack the same check also passes
  with default features and with `--no-default-features`, the two rows CI runs (`ci.yml:745`, `ci.yml:753`), and
  `cargo fmt --all -- --check` passes. Log: `regen-probe-final.log`.
- **The review's feature point found a real defect.** The first runs only compiled with the OpenTelemetry feature on.
  With it off, which is the default build, the generated `lib.rs` had an unused alias, and CI treats warnings as
  errors. The script now gives each alias the same `cfg` as the files that use it, or refuses when it cannot read
  that `cfg` exactly (the reviews asked for a gate, not a blanket `allow`, and then for no guessing). The driver
  runs every build below and stops on any warning.
- **The moved files are unedited.** Of the 12 files in step 3, 10 are identical to the base. `mod.rs` differs by
  the two lines above. `otel.rs` differs by the one import line step 2 changed, so commit 3 on its own shows 11
  exact renames.
- **It is regenerated, not rebased.** `regen_probe.sh <base>` rebuilds all three commits from a clean checkout with no
  hand edits, in about 12 minutes on a 32-core build host including every check above. Almost all of that is compile time. It
  refuses to run in a worktree that has uncommitted or untracked changes or is on a branch, never resets one, and
  stops with a failure on the first check that does not pass cleanly, a warning from the compiler or from cargo
  included. The `pub` and `test-util` edits are not
  written by hand: `widen_vis.py` reads the compiler's errors and changes only the items the compiler names.
- **After step 2 the big cycle shrinks from 13 modules to 11.** `observability` and `hooks` drop out
  (`modgraph2.py` on the probe tree).
- **The new crate also compiles on its own**, with no features, with each of its three features alone, and with
  all of them, with no warnings (results: `regen-probe-final.log`). That matters because a workspace build unifies features and can hide a missing one.
- **The moves make five production items public that were crate-private:** `util::shell_escape`, the three regex
  statics (`SENSITIVE_KV_REGEX`, `SENSITIVE_KEY_REGEX`, `IMAGE_DATA_URI_REGEX`) and `scrub_for_export`, because
  other crates now use them. A sixth, the test lock, is public only under the `test-util` feature. These crates are
  published, so that is new public surface, and each pull request should list it under Compatibility.
- **Log attribution changes.** Every event records its module path (`zc_name`) and source file (`zc_file`,
  `crates/zeroclaw-log/src/macro.rs:10`). After the move both name the new crate. Nothing was found in the
  repository that keys on the old names.
- **What it does not show:** tests, clippy, rustdoc, the all-features workspace build and other platforms were not
  run. Of the registration edits a new crate needs (listed below), commit 3 carries the one a test enforces, checked
  against that test's rule without running it; the labeler, CODEOWNERS, risk-labeler and docs edits are not in the
  commits.

Scripts, all in this folder: `modgraph2.py` (the graph), `extract_module.py` (the move), `widen_vis.py` (visibility
from compiler errors), `prep_redact.py` (step 2), `regen_probe.sh` (the driver), `simmove.py` (conflict measurement).

### The measurement behind "it stays mergeable"

`simmove.py` builds each candidate move as a commit on master and three-way merges every open pull request head
against it with `git merge-tree`, the same merge machinery GitHub uses. A pull request counts only if it merges
cleanly with master today and stops merging once the move is in. Results are in `simmove-results-e02b7fb6f6.txt`.

| Module moved | Open PRs touching it | Candidates that merge cleanly today | Broken by a byte-for-byte move | Broken by the same move with in-file path edits |
|---|---:|---:|---:|---:|
| `observability` | 4 | 6 | 0 | 0 |
| `hooks` | 9 | 8 | 0 | |
| `cron` | 35 | 23 | **0** | **9** |
| `sop` | 42 | 27 | **1** | **12** |
| `security` | 22 | 15 | 2 | 2 |
| `skills` | 29 | 23 | 1 | |
| `daemon` | 65 | 23 | 0 | |
| `doctor` | 10 | 12 | 0 | |
| `quickstart` | 13 | 11 | 0 | |
| `control_plane` | 16 | 8 | 2 | |
| `rpc` | 118 | 58 | 1 | |
| `tools` | 112 | 66 | 4 | |
| `agent` | 122 | 83 | 4 | |
| Locale catalogs and `i18n` | 140 | 77 | 0 | |
| The whole crate, renamed | 345 | 215 | 20 | |

Candidates are the pull requests that touch the module or the runtime's `lib.rs`, where the one-line re-export goes.
An empty last column means that variant was not simulated. The rows overlap: the 35 breaks in the byte-for-byte
column are 20 distinct pull requests.

The last column is a proxy, not a rebuilt #10557. It applies the path rewrites a conventional extraction makes
(`crate::cron::x` to `crate::x`, references to other modules re-pointed) to every line that has one, comments
included. A real hand-built move edits more than that: #10557 changed `scheduler.rs` by +2,703/−636.

- **Why it works:** git follows an exact rename. A pull request that edits `cron/scheduler.rs` merges into the file's
  new location, as long as the move did not also edit that file.
- **What still breaks:** a pull request that *adds a new file* inside the moved directory. Git reports a "file
  location" conflict. That is 33 of the 35 breaks in the byte-for-byte column; the other two are rename/delete. The
  fix on the pull request is one `git mv`.
- **Which pull requests are tested.** Those that touch the module's files or the runtime's `lib.rs`. A pull
  request that touches neither cannot conflict textually with a byte-for-byte move, but it can still fail to
  compile after one.
- **Limits of the method.** It uses local git 2.43 with default settings. It assumes GitHub decides mergeability the
  same way, including for new files in a renamed directory; that was not confirmed. Pull requests whose base is not
  master (13 of 588) are compared against master here, which is not what GitHub does; two of them, #9245 and #11596,
  are the only cases where this baseline disagrees with GitHub's mergeable flag. Registration edits (labeler,
  CODEOWNERS) were not simulated.
- **What the table does not measure:** whether a pull request that still merges also still compiles. A pull request
  that adds a new upward reference to a moved module will fail CI after it rebases. The merge queue builds the merged
  result, so that cannot reach master.

The table simulates the code move only. The three real commits also edit manifests, so those were measured too
(`exposure-stack-e02b7fb6f6.json`): 196 open pull requests against master touch a file the commits
change, and 112 of them merge cleanly today.

| Commit | Newly broken | Where |
|---|---:|---|
| 1. `util` | 1 | `Cargo.lock` (#11676) |
| 2. Redaction prep | 2 | `agent/loop_.rs` (#10407) and the redaction file, which this step both moves and edits (#12553) |
| 3. `observability` | 6 | All in the root `Cargo.toml` |
| Total | 9 of 112 | None in a file that moved without edits |

- **The breaks come from manifests, not from moved code.** The workspace `members` list is a single 1,600-character line (44
  entries) next to the `exclude` line, so adding a crate collides with any pull request that vendors a dependency.
  Putting the list one entry per line should remove that; That was not simulated.
- **Where a manifest line goes matters.** The first run appended a new section at the end of
  `zeroclaw-infra/Cargo.toml` and broke 5 pull requests. Inserting it before `[dev-dependencies]` breaks 1. The script
  now does the second.

## Target layout

### What stays in `zeroclaw-runtime`

`agent`, `tools`, `composition`, `approval`, `skills`, `security`, `plugin_runtime`, `plugin_state`, `rpc`,
`live_config_authority`, `config_application`, `control_plane`, `i18n`, and the small helpers only they use (`rag`,
`cli_input`, `identity`, `cost`, `peers`, `subagent`, `verifiable_intent`, `agent_lifecycle`, `process_stats`). That
is about 107K of today's 161K production lines. About 49K leave, and about 4K are left undecided.

The starting point is `docs/book/src/foundations/fnd-001-intentional-architecture.md`, Phase 2 D1 (line 612): "the
agent orchestration loop, CLI channel, security policy, plugin host, and IPC API", plus the core tools of D5 (line
660). The list above is wider than that sentence: it keeps all of today's `tools`, `security` and `rpc` directories,
and `skills`. FND-001 does not say those whole directories are permanent, and
`crates/zeroclaw-runtime/AGENTS.md:5` lists the agent loop, security and skills for extraction. So this list is a
proposal for the RFC, not a reading of settled text.

### What leaves

| Destination | Modules | Prod lines | Direction | Status |
|---|---|---:|---|---|
| `zeroclaw-infra` (exists) | `util`, `health`, `tools/shell_output` | about 400 | Down | `util` proven |
| `zeroclaw-providers::redact` (exists) or `zeroclaw-infra` | Redaction helpers from `agent` and `approval` | about 290 | Down | Proven |
| `zeroclaw-observability` (new) | `observability` | 3,273 | Down | Proven |
| `zeroclaw-cron` (new) | `cron` | 6,317 | Down | Needs a design note, then a seam |
| One or more host crates (new) | `daemon`, `heartbeat`, `doctor`, `service`, `restart`, `tunnel`, `integrations`, `migration`; later `relay`, `enroll`, `relay_dashboard` | about 11,700, then 2,900 | **Up** | Not ready to schedule |
| `zeroclaw-sop` (new) | `sop`, `calendar` | 24,300 | Down | Not ready to schedule |

"Down" means the runtime depends on the new crate and re-exports it. "Up" means the new crate depends on the runtime,
so callers in the gateway, channels and the root binary are re-pointed in the same change.

Left for later, and not needed to end the exceptions: `quickstart`, `hooks`, `browse`, `routines`, `trust`.

### Where this departs from the RFC, and why

- **No `zeroclaw-kernel` crate.** FND-001 lines 185-198 and 612 say `zeroclaw-runtime`, while line 690 of the same
  document, `crates/zeroclaw-runtime/AGENTS.md` and `runtime-composition.md:223` say `zeroclaw-kernel`. No issue
  schedules it. Building it would mean moving 53K production and 133K test lines that 122
  and 112 open pull requests touch, to end up with the same code under a new name. If the name matters, rename the
  crate last: the measured cost of a whole-crate rename is 20 broken pull requests out of 215.
- **New crate names the RFC never listed.** FND-001 has no `zeroclaw-observability`, `-cron`, `-sop` or `-daemon`. The
  holding-crate contract (`crates/zeroclaw-runtime/AGENTS.md:5`) does say daemon, cron, observability and doctor
  "will each be extracted into dedicated crates or converted to WASM plugins", and issue #10546 names `zeroclaw-cron`. The names need a Core Team nod, because these crates are
  published (`tests/architecture/publish_contract.rs` requires `publish = true`).
- **Nothing here waits for WASM plugins.** The RFC makes channels and long-tail tools into plugins. None of the
  modules above is on that list: FND-001 keeps observability and the sandboxes compiled in (lines 341-356) and never
  assigns cron, SOP, daemon or doctor. The plugin route cannot retire a single exception row.
- **`security` and `rpc` stay,** although `AGENTS.md:5` lists security for extraction and several rows speak of a
  "kernel IPC extraction". FND-001 puts both in the runtime, `rpc` has 118 open pull requests, and neither blocks
  anything in the first three phases. `security` matters again for SOP (see Phase 4).
- **Draining `tools` into `zeroclaw-tools`** is the composition work (#10993, #10998, #11187). It is a separate stream
  and this plan does not depend on it.

## The governance decision

**This is the decision that stops the exceptions, and it needs an RFC and a vote.** FND-003 §8
(`docs/book/src/foundations/fnd-003-governance.md:554`) requires an RFC for "a governance, contribution-process, or
project-authority change" and for "a cross-cutting architectural refactor that changes ownership or contracts across
established boundaries". Changing what the holding-crate contract covers is both. ADR-016 says the same of itself.
The first draft called this a docs change with a recorded decision; the review was right that it is not.

The facts: 60 rows in nine weeks. 55 name a destination crate that does not exist. 43 cover only modules this plan
would keep. 35 open pull requests edit the table.

| Option | What it means | Verdict |
|---|---|---|
| A. Keep going | A row per feature until a kernel crate exists | No end condition: nothing schedules that crate |
| B. Split only | Extract the periphery, change no rule | Retires the 3 rows that name only departing modules and trims 14. The 43 rows for `agent`, `tools`, `rpc`, `security` keep coming |
| **C. Residents and held modules** | Amend the contract by RFC: named modules are **resident** and need no exception. Every other module is **held**, has a named destination, and keeps the ADR-016 process until it leaves | **Recommended** |
| D. Rename the crate to `zeroclaw-kernel` now | Same effect as C by renaming | Costs 20 broken pull requests and a mass rename that #10993 lists as a non-goal, for no gain over C |
| E. Extract `agent` and `tools` into a new kernel crate | The literal reading of the contract | The largest possible move, for the same end state |

What the RFC has to decide, because the documents do not:

- **Which modules are resident.** FND-001 line 612 supports the agent loop, security policy, plugin host and IPC API.
  It says nothing on whether all of `tools`, `security`, `rpc` and `skills` stay. The contract lists the agent loop,
  security and skills for extraction. A narrower resident list is a legitimate outcome.
- **Whether the name stays `zeroclaw-runtime`.**
- **What happens to the existing rows.** Under the list in this plan, up to 43 could be archived, 14 cut down to
  their held part, and 3 kept. Those numbers move with the list. 14 of the 43 also cover locale catalogs, so their
  fate depends on the next point too.
- **Who owns the locale catalogs.** 19 rows cover catalog edits, and one (line 82 of the contract) names
  `zeroclaw-channels` as its catalog's destination.
- **ADR-016's own status.** It is still `proposed` in its header although both acceptance conditions are met, and
  #10546 ties its acceptance to the cron extraction.

Until that vote, the current exception process stays in force. Nothing in Phases 0 and 1 below depends on it.

**On the hypothesis this work started from:** it is right, with two corrections. Splitting alone will not stop the exceptions,
and `agent` and `tools` do stay together (26 references one way, 64 the other). But `rpc` is a third cluster as large
as `tools` (24 rows). And the route is heavier than a contract edit: it is an RFC.

## The pull request sequence

Sizes are the diff a reviewer has to read, excluding files renamed without change. "Exposure" is the measured count
of open pull requests that merge today and would stop merging.

### Phase 0: rules and tools

| # | Change | Scope | Size | Exposure | Validation |
|---|---|---|---|---|---|
| 0a | **RFC:** resident and held modules in the holding-crate contract | An RFC issue with a stable snapshot and a Core Team vote (FND-003 §8.1, §8.2). After it passes: `crates/zeroclaw-runtime/AGENTS.md` and ADR-016 | The RFC text, then about 150 lines of docs | The 35 pull requests that edit the table | The vote |
| 0b | `chore(ci): add the module-move scripts and a dependency tripwire` | The move scripts under `scripts/`, plus a check that fails if a held module gains a new upward reference (the allowed list can only shrink) | About 1,100 lines, all new files | None | `fnd-003-governance.md:517`: "Structural compliance (import direction, dependency graph, lint, format) is enforced by CI" |
| 0c | `chore(workspace): list workspace members one per line` | Root `Cargo.toml` only | About 45 lines | The pull requests that edit the `exclude` line next to it, once | `cargo metadata` output unchanged |

- **0a runs in parallel.** It gates nothing below. It only decides how many exception rows keep being written.
- **0b is not ready to land as it stands.** The scripts in this folder are a proof, and astra blocked merging them
  three times, each time on something real:
  - Pass 2: the driver could discard work and pass after a failed check.
  - Pass 3: it could miss untracked files hidden by a git setting and ignore warnings cargo prints itself; the alias
    gate was wrong for a module nested under two feature gates.
  - Pass 4: the move script guessed where it could not read a `cfg` exactly, and dropped a gate on the moved module
    itself; the driver's warning detection had gaps.
  - Pass 5: more inputs of the same kinds (below).
  The cases named in passes 2 to 4 are fixed. The rule the move script now follows is: carry a `cfg` exactly, or
  refuse and ask for it to be stated. `test_extract_module.py` (20 cases) and `test_cargo_diag.py` (12 cases) cover
  the gates, the refusals, the manifests and what counts as a clean build.
- **What astra needs before it approves the scripts for merge** (its own closed list, pass 5):
  1. The move script carries or refuses, before it moves anything, the gate cases it still gets wrong: a blank
     line or a block doc comment between the attribute and the `mod`; a `mod` declared inside a gated macro call; a
     file-level `#![cfg(...)]`; a file reached by two paths; a top-level test-only module. Moving into an existing
     crate must declare the features it forwards and honour `--alias`.
  2. The build checker rejects the inputs it still reads as clean (an indented JSON record, `"success":"false"`),
     and the driver propagates the last unchecked failures (the final `grep`, a failing `git rev-parse`).
  3. Each step stages only the paths that step is expected to write.
  4. Regression fixtures for all of the above, for `widen_vis.py`'s edit scope, for the redaction rewrite, and for
     the driver's failure paths.
  None of these touch the `observability` move: pass 5 replayed the patches and got the same tree at every commit.
  They are the acceptance list for pull request 0b, which should be built and reviewed as code in the repository,
  with its tests in CI, and proven on a second module.
- **0b lands the tool once, reviewed once.** After that a move is reviewed as a recipe and its output. The tripwire is
  a text scanner with known blind spots (`ARCHITECTURE.md` lists them), so treat it as an early warning. The real
  enforcement arrives with each extraction: once a module is its own crate, the compiler refuses an upward reference.
- **0c** matters because this plan adds several crates and each one edits the same one-line list. Its effect on the
  six conflicts above is expected, not measured.

### Phase 1: the first extraction (built and compiled)

| # | Pull request | What moves | Cuts | Rows retired | Size | Exposure |
|---|---|---|---|---|---|---|
| 1 | `refactor(infra): move runtime util helpers into zeroclaw-infra` | `util.rs`, 319 lines, unchanged | Lets anything below the core use the truncation helpers | 0 | +7/−2 | 1 |
| 2 | `refactor(providers): give credential redaction one owner` | `agent/turn/redact.rs`, `approval::looks_like_secret_key`, `agent::loop_::scrub_for_export`. Old paths re-export | `observability`→`agent` (1), `hooks`→`agent` (2) | 0 | +54/−52 | 2 |
| 3 | `refactor(observability): extract observer backends into zeroclaw-observability` | 12 files, 6,190 lines, unchanged but for 2 lines | Removes `observability` and `hooks` from the cycle | 0 | +100/−6 plus about 55 lines of labeler, CODEOWNERS and docs registration | 6, all in the root `Cargo.toml` |

With its registration edits, pull request 3 comes to about 161 lines outside renames, over the 150-line limit in
rule 4 below. Measure the real figure, and split the docs registration into a follow-up if it stays over.

No row is retired here: `observability` appears in none. This phase exists to prove the method on the module with the
least traffic (4 open pull requests) before using it where it matters.

Open question for review on 2: the prototype puts redaction in `zeroclaw-providers`, beside the existing
`scrub_secret_patterns` that `scrub_for_export` calls. `zeroclaw-infra` is the other candidate and matches the
precedent tidux approved on #10557 for `shell_output`; it would mean moving `scrub_secret_patterns` down too.

### Phase 2: cron, replacing #10557

| # | Change | What it does | Size | Exposure |
|---|---|---|---|---|
| 4 | **Design note:** who owns execution admission for cron | A short written design, reviewed before any cron code. See below | 1 to 2 pages | None |
| 5 | `refactor(infra): move health and shell-output decoding down` | `health/mod.rs` (144 production lines) and `tools/shell_output.rs`, unchanged, re-exported. Cuts `cron`→`tools` (2) and `skills`→`tools` (2) | About 30 lines | `health` has 1 open pull request |
| 6 | `refactor(cron): put a host seam between the scheduler and the runtime` | **In place, no file moves.** Whatever 4 decides | Unknown until 4. Not small: `scheduler.rs` names the admission types at about 20 places | 35 open pull requests touch `cron`; this is the one change in the sequence that edits those files |
| 7 | `refactor(cron): extract cron into zeroclaw-cron` | `cron/` moves unchanged, by script | About 100 lines | 0 of 23 for the code (measured) |
| 8 | `feat(cron): add the precondition gate` | `precondition.rs`, the schema key and docs from #10557, now in `zeroclaw-cron` | About 900 lines | Normal feature review |

The note comes first because it can end the phase: one of its options is to leave cron where it is. Pull request 5
is useful either way (it also serves `skills`), but nothing after it starts until 4 is accepted.

`platform` needs no move: `crate::platform` is a one-line re-export of `zeroclaw_config::platform`, and
`SecurityPolicy` also comes from `zeroclaw-config`. The first draft had a `platform` relocation here; the review
caught that it was unnecessary.

**Why the seam needs a design note first.** The first draft said the scheduler would "stop naming the admission
types" once agent runs went through an executor. The review showed that is wrong. In
`crates/zeroclaw-runtime/src/cron/scheduler.rs` today:

- The scheduler resolves the target agent against admitted config (lines 623-650).
- It revalidates admission before shell execution and on retries (lines 865-870), not only for agent jobs.
- It holds the admission through delivery and history persistence.
- A failed isolated run triggers capability-scoped memory cleanup.

So an executor for agent turns alone leaves `cron` naming `live_config_authority`, which this plan keeps in the
runtime, and `cron` could not sit below it. The design note has to choose one of:

1. **An admission port.** `cron` defines a small trait for "an admission I can hold, revalidate and read config
   from"; the runtime supplies the real one. The scheduler keeps its control flow and its lifetimes.
2. **Move `live_config_authority` below cron.** It is 1.5K lines and three exception rows call it kernel-bound. It
   also uses `i18n`.
3. **Leave cron in the runtime.** Then #10546 is closed as not planned and the cron rows stay.

Other points for 4 and 6:

- **The #10557 review thread is the specification of what must not regress:** one shared action budget across
  scheduler and run; config and policy read per run, never held from startup; reconciliation checked on every path
  that selects work; claims released by token; hooks killed before a claim is freed.
- **Define any trait in `cron`, not in `zeroclaw-api`.** #10557 first put the request type in `zeroclaw-api`, which
  cannot see `zeroclaw-config`, so the request carried policy *inputs* and the 09-12 review found the budget and
  config regressions that followed.
- **It must carry master's current cron model:** `RunOutcomes`, `RunProvenance` and the `InternalPrincipal::Cron`
  envelope from #10425.
- **6 is a design change, not a prep move.** The size limit for prep changes does not apply to it. It is `risk:high`
  and `domain:security`: two Core Team approvals (`pr-workflow.md:22`).
- **Tests:** cron's tests use 17 helpers from `composition::test_support`, `tools::shell` and
  `live_config_authority`. The ones that drive a real agent turn move to the runtime side of the seam.
- **A cron string needs a catalog.** `cron` calls `crate::i18n` once; #10557 gave the crate its own catalog.

### Phase 3: the hosts, moved up (needs a probe first)

**Not ready to schedule.** The review found the sketch in the first draft was not implementable as written. What is
known:

- **The renames themselves are cheap:** `daemon` breaks 0 of 23 open pull requests and `doctor` 0 of 12 (measured).
- **`rpc` calls host functions, not only host types.** `rpc/dispatch.rs:4037` and `:4052` call
  `doctor::probe_models` and `doctor::run_structured_with_probe`; `:3961` calls `enroll::relay_profile`. If `rpc`
  stays in the runtime and the hosts move above it, those calls need a port or the callee stays.
- **Host tests find fixtures by crate path.** `service/mod.rs` and `daemon/mod.rs` each use `CARGO_MANIFEST_DIR`.
  Those paths change when the file changes crate, so these files cannot move untouched.
- **Callers above the runtime must be re-pointed,** about 60 references, including `src/main.rs`, which 68 open pull
  requests touch.
- **Not measured:** how many `pub(crate)` items in `agent` and `rpc` the hosts use.
- **It is not one move.** `service`, `tunnel`, `integrations` and `migration` have no ties to the others and can go
  one at a time. `daemon`, `heartbeat` and `restart` go together. `doctor` waits on the `rpc` question.

Next step, if wanted: a build-host probe of the smallest piece (`tunnel`: 2.2K lines, used by nothing in the crate, no
open pull requests) to see what an upward move costs in practice.

### Phase 4: SOP (needs a design note first)

**Not ready to schedule.** `sop` is the largest module that could leave (24K production lines, 3 rows, 42 open pull
requests), and it has the most ties to code that stays:

1. **Execution admission.** `sop` uses the `live_config_authority` admission types 7 times. Same question as cron,
   so cron's design note should cover SOP's case.
2. **Agent steps.** `sop` calls `agent::run`.
3. **Content safety.** `sop` uses 10 items from `security` (`ContentSafety`, `LeakDetector`, `cap_untrusted`).
4. **Localized text.** `sop` calls `crate::i18n` 10 times, and the catalogs live in the runtime. Moving the catalogs
   breaks 0 of the 77 mergeable pull requests that touch them (measured), so a shared catalog crate is cheaper than
   it looks; per-crate catalogs are the existing precedent (`zeroclaw-tools/src/i18n.rs`).
5. **The trigger types cannot be moved on their own.** `security` and `calendar` name `sop::types::SopEvent` and
   `SopTriggerSource`. The first draft proposed moving those two types to `zeroclaw-sop-graph`. The review showed
   that fails: `SopEvent` is a struct that holds a `SopTriggerSource`, and `SopTriggerSource` is generated by a
   derive macro, and `crates/zeroclaw-macros/src/lib.rs:2551` emits
   an inherent `impl crate::sop::types::SopTriggerSource` that refers to `crate::sop::trigger_registry`. An inherent
   impl must live in the type's crate. So the content-safety code that names these types has to move with SOP, or
   take the value through a trait.

One thing works in SOP's favour: because a moved module keeps its name, the macro's fixed `crate::sop::…` paths still
resolve inside a `zeroclaw-sop` crate. The macro would not need to change.

Do not start this before cron has landed. Cron tests the admission seam on a module a quarter the size.

## The landing method

Each rule below is judged against the repository's rules and against what happened to #10557.

### What actually stalled #10557

From the pull request's own record (`gh api .../pulls/10557/reviews`, comments, timeline and file list):

| Date | Event |
|---|---|
| 09-02 | Opened: 51 files, +4,978/−948. The move, a new seam and the precondition gate in one change. Audacity88 and tidux are requested as reviewers the same minute |
| 09-04 | First approval |
| 09-12 | Bot review of the new head: 6 findings marked blocking. A maintainer later upholds 5 as code defects, all in the seam (budget, stale config, manual runs, abandoned claims, ownership), and downgrades the sixth, a stale issue criterion, to cleanup |
| 09-21 | Conflicts with master (#10414, #9139). Asked to reconcile |
| 09-23 | Second approval, on the older head |
| 09-24 | Repairs pushed. Changes requested again the same day: 2 new blocking defects, both in the gate (startup catch-up, hook cancellation) |
| 09-25 | Master itself is red; the pull request's CI cannot go green until it is fixed |
| 09-26, 09-28 | Two approvals on head `9808cf03c1` |
| 09-29 | #10425 merges and rewrites `cron/store.rs` (+3,017) and `scheduler.rs` (+763) |
| 09-30 | The code-owner review requested on 09-02 arrives. Changes requested: 11 files conflict, 61 hunks in `scheduler.rs`. The reviewer notes that rename tracking carries the text across, and that the blocker is the design: the seam is built on a run-outcome and principal model master has replaced |
| 10-11 | Back to draft. No commit since 09-26 |
| 10-16 | The tracker (#7432) defers the cron extraction to a later release |

What the record supports:

1. **Three changes in one.** Seven upheld blocking findings, none about the move. The move waited 24 days for the
   seam and the feature to pass review.
2. **The moved files were also heavily edited.** `scheduler.rs` moved with +2,703/−636 and `store.rs` with +424/−31.
   Git still followed the rename, but both sides had rewritten the same regions, hence 61 hunks.
3. **The seam's design went stale, not only its text.** #10425 changed what a cron run returns and who it runs as.
   No regeneration script fixes that; only keeping the seam small and landing it quickly does.
4. **No re-exports.** Issue #10546 requires the old directory "deleted, not re-exported or shimmed". That forced
   edits in about 25 caller files: `gateway/src/api.rs` (+92/−110), `rpc/dispatch.rs` (+38/−38), a dozen tool
   files. The 09-30 review names collisions with #11172, #10621 and #11045; a later notice adds #11935.
5. **A code-owner review requested on day one arrived on day 28,** two days after the second approval on the final
   head. Requesting a reviewer was not enough; nobody had a date.

What the record does not support, and the first draft claimed: that there was an open merge slot on 09-28 that someone
missed (the code-owner review was still owed, and master had been red three days earlier), and that a script could
have rescued the branch after 09-30.

### The rules

**1. A move is generated by script and regenerated on fresh master. Never rebased.** *Adopt.*
The branch is disposable. On the day, run the recipe on master's tip and push. It is allowed by
the review rules: an approval "covers only the `headRefOid` it reviewed", and carry-forward is permitted "when the
later changes are mechanical integration" (`pr-workflow.md:222`). Give reviewers the proof in one command:

```
git diff -M --name-status <base> <head> | grep -v '^R100'
```

It prints every file that is not an exact rename: added, deleted, modified, and renamed with edits. That list must
match the pull request body (for `observability`: one renamed file with two changed lines, two new files, and five
modified ones: the root `Cargo.toml`, `Cargo.lock`, the runtime's `Cargo.toml` and `lib.rs`, and the
retained-dependency list). An earlier form of this command showed renames only and would have hidden an
added or modified file; the review caught that.

**2. A move changes no logic and edits no function body.** *Adopt, as a hard rule.*
This is `AGENTS.md`'s own rule ("Do not hide behavior changes inside refactors") made checkable. The allowed edits
inside moved files are the ones the compiler demands: `pub(crate)` to `pub`, and `#[cfg(test)]` to
`#[cfg(any(test, feature = "test-util"))]`. Two things still change for an outside observer, and each move must
declare them under Compatibility: log events name the new crate as their module and source file, and the items
made `pub` are new public surface. This is the answer to causes 1 and 2.

**3. Re-exports keep every caller stable.** *Adopt. This is the idea that matters most.*
The runtime's `lib.rs` changes one line, from `pub mod cron;` to `pub use zeroclaw_cron::cron;`. Every
`zeroclaw_runtime::cron::…` in the gateway and every `crate::cron::…` in the runtime keeps working. This is the answer to cause 4.

- This contradicts #10546's acceptance criterion. Ask to amend it to: re-export allowed, removal tracked.
- **When they are removed:** not on a date, and possibly never. Three groups use the old path: other workspace
  crates (`zeroclaw_runtime::<module>`), the runtime's own files (`crate::<module>`), and anyone outside the
  repository, since `zeroclaw-runtime` is published. The script in 0b counts the first two. Removing the line is a
  breaking change for the third, so it belongs in a release that says so.
- **The cost:** paths read `zeroclaw_cron::cron::Store` until someone adds `pub use cron::*;` at the new crate's
  root. That is cosmetic and can wait for a quiet week.
- **It only works downward.** For the hosts in Phase 3 the runtime cannot re-export a crate that depends on it.

**4. A size limit.** *Adopt, but measure the right thing.*
Limit what a reviewer must read: at most 150 lines outside pure renames for a move, and 400 for a prep change. One
move unit per pull request: a module, or the smallest set of modules that only compiles together. A seam such as
pull request 6 is neither a move nor a prep change and is sized by its design. The rename volume is not the risk, and it should not trip the size label either: the label counts
additions plus deletions (`docs/book/src/maintainers/labels.md:298`), and GitHub reports +0/−0 for an exact rename (it
did for `outbox.rs` and `types.rs` on #10557). The labeler was not run. If a move is ever labelled `size:XL`, the
body should answer the shape question (`pr-review-protocol.md:320`) up front.

**5. Freeze windows.** *Not needed. Use a move slot.*
The repository has no freeze concept, and the measurements say it does not need one: a byte-for-byte move breaks
almost only pull requests that add a file to that directory (33 of the 35 breaks observed; the other two deleted or
renamed one). Instead:

- Two days ahead, say which module moves and when.
- On the day, ask maintainers to hold merges that add files under that one directory for about an hour.
- Regenerate, wait for CI, enqueue.

**6. Helping the pull requests a move breaks.** *Adopt. It is a short list, known in advance.*
`simmove.py` prints the numbers. For a file-location conflict the fix is `git mv <new file> <new directory>` on the
author's branch. Post it on each, or push it where maintainers may edit. Pull requests that already conflict with
master (104 of the 285 that touch the runtime) are no worse off.

**7. Merge-queue timing.** *Adopt: enqueue the same hour it is regenerated.*
Live settings, checked today: master has a merge queue (ruleset 23991526: squash, up to 5 entries merged together).
Protection requires one approval and one check, `CI Required Gate`, and does not require the branch to be up to date.

- A pull request CI run takes a median 13.8 minutes and the queue's run 12.4. Runs stretch to 46 minutes when macOS
  and Windows runners are busy.
- So regenerate-to-merged is about 35 minutes on a good day. Master takes about 6 merges a day, 1.5 of them labelled
  `runtime`.
- Enqueue when the queue is empty, so nothing ahead of the move can add a file to the moved directory.

**8. Review and CI gates.** *Line up every owner on day one.*

- **Gate:** `CI Required Gate` only. Any change under `crates/zeroclaw-runtime/` already triggers the full
  path-gated set.
- **Approvals:** `risk:high` or `domain:security` needs two Core Team approvals; lower risk needs one. Risk is set by
  hand, and "path location alone does not select `risk:high`" (`pr-workflow.md:237`). So the seam (6) carries the high
  label and the rename (7) should not.
- **Code owners:** GitHub does not enforce code-owner review here, but policy does (`pr-workflow.md:145`). On #10557
  both owners were requested on day one and one review still came on day 28. So a request is not enough: get a named
  owner and a date for every touched path before the move day. For pull request 3 the owners are Audacity88
  (runtime, docs), JordanTheJet (`Cargo.toml`, `Cargo.lock`, the new crate) and tidux (`.github`, docs).
- **Review the recipe early, the output late.** Reviewers can approve the approach on a draft days ahead. On the day
  they confirm the regenerated head with the one command above.

### Move-day checklist

1. Run `simmove.py` for the module. Note the pull requests it will break.
2. Regenerate on master's tip. Run the workspace check, clippy, rustdoc and the tests.
3. Push. Confirm `git diff -M` shows only the listed edits. Reviewers re-confirm.
4. Enqueue when the queue is empty. The move slot covers the queue run.
5. After merge: post the `git mv` fix on the broken pull requests, and delete the module from the held list.

### What a new crate has to register

Found in the repository. Only the first is in the prototype commits:

- `tests/fixtures/runtime-composition-consumer/retained-dependencies.json`: every `zeroclaw-*` dependency of the
  runtime needs an owner file and a reason of at least 50 characters. `dependency.rs:94-130` fails the build
  otherwise. **This one is in commit 3**: the script writes the entry, and `check_retained.py` applies the test's
  rule without running the test.
- `.github/labeler.yml`: 44 hard-coded runtime paths. `observability` has five (lines 653-674). #10557 found that the
  `cron` label would have stopped matching.
- `.github/CODEOWNERS` and `.github/risk-labeler.yml`: same paths.
- `docs/book/src/architecture/crates.md` and the stability table in `docs/book/src/contributing/agent-guidelines.md`.
- `scripts/ci/parallel_runtime_test_scope.sh` and `plugin_backend_change_filter.sh`: they select tests by
  `crates/zeroclaw-runtime/*` and should know the new path.
- Nothing to edit for publishing: the order is computed, and the generated manifest already has `publish = true`.

`extract_module.py` writes the first. The rest are still manual.

## What to do with #10557

**Do not rebase it. Keep it open as the record until the cron design note (4) is accepted and the seam pull request
(6) is open, then close it with a comment that names that pull request.** That is the repository's own rule for
superseding (`docs/book/src/maintainers/superseding.md`, "Closing the superseded PRs"). The first draft said to close
it now; the reviews were right that closing before a replacement exists leaves nothing in its place.

- **Why not rebase:** 61 conflict hunks in one file at the end of September, in files that 35 open pull requests now
  touch, on a seam built for a cron model master has replaced.
- **Why not split it as it stands:** the move and the seam are tangled in the same hunks of `scheduler.rs`.
- **What carries over:** the invariants its three review rounds established, as the specification for 4 and 6; the
  regression tests named in the thread, as acceptance tests; `precondition.rs` and its docs, as 8; the
  `shell_output` move to `zeroclaw-infra`, as part of 5.
- **Paperwork:** `Supersedes #10557` on 6, 7 and 8. #10546 stays open until 8 lands, because its acceptance criteria
  include the precondition regressions, and its "not re-exported or shimmed" criterion needs amending first.
  #10836 (an open draft) is the ownership fix #10557 had folded in; it lands on its own or inside 6.

## Risks, and what not to do

**Risks**

- **A pull request that merges cleanly can still fail to compile after a move,** if it adds a call from a moved
  module up into the runtime. The author finds out on their next CI run. The tripwire in 0b flags new upward
  references from the day the prep change lands.
- **Log attribution changes.** Events record a module path (`zc_name`) and a source file (`zc_file`). After a move
  they say `zeroclaw_observability::…` and `crates/zeroclaw-observability/…` where they said `zeroclaw_runtime`.
  No code was found that keys on the old values, but an operator's saved log query might.
  `docs/book/src/architecture/logging.md:245` names the code path `zeroclaw_runtime::observability::broadcast`,
  which stays valid through the re-export.
- **Published crate names are permanent, and public surface grows.** Each new crate reaches crates.io, and every
  `pub(crate)` item another crate needs becomes `pub`. The prototype needed five, plus one under `test-util`.
- **Paths that depend on the crate.** `CARGO_MANIFEST_DIR` and relative `include_str!` appear in `i18n` (114 uses),
  `agent` (14), `tools` (11), and once or twice in `skills`, `security`, `composition`, `service` and `daemon`. A
  file that uses them cannot move untouched. `observability`, `cron` and `sop` have none. The move script refuses
  such a file.
- **Shared test helpers.** A `#[cfg(test)]` item used by another module's tests has to become a `test-util` item. The
  tool handles the case it met; expect variants in `cron` and `sop`.
- **Feature drift.** The new crate's features must be forwarded from the runtime's. The script does this for the
  features the moved files name. The workspace was compiled with the default set plus OpenTelemetry, and the new
  crate alone with each of its features. The workspace was also compiled with no default features. The
  all-features build was not run.
- **A shared test lock is now two locks.** `observability`'s own tests run in their own test binary with their own
  copy of the lock and of the hook it guards. The runtime's tests still share one. No race was found, and the tests were not
  run.
- **The measurement uses local git 2.43.** GitHub's merge should behave the same; confirm on the first real move by
  checking that the pull requests predicted to stay mergeable do.
- **Phases 2 to 4 are not proven.** Cron needs a design decision before any size can be given. The hosts and SOP
  are not ready to schedule.

**Do not**

- Mix a feature or a fix into a move.
- Tidy paths, imports or formatting inside moved files in the same change. That is what turns 0 broken pull requests
  into 9.
- Delete the re-export in the move.
- Rebase a move by hand. Regenerate it.
- Have two moves open against the same directory.
- Extract `agent` or `tools`, or rename the crate, before the held list is empty.
- Start the cron seam before its design note is accepted, or SOP before cron has landed.
- Treat the governance change as a docs edit. It is an RFC.
- Let an approved move sit overnight.
