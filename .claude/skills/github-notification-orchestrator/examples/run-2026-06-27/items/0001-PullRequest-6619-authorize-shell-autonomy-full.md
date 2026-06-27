---
notification_id: "23859692702"
updated_at: "2026-06-27T11:12:26Z"
reason: "review_requested"
repo: "zeroclaw-labs/zeroclaw"
type: "PullRequest"
number: "6619"
title: "fix(runtime/agent): authorize shell explicitly at autonomy.level=full (#6434)"
url: "https://github.com/zeroclaw-labs/zeroclaw/pull/6619"
agent_profile: "pr-review-responder"
priority: "P2"
status: "needs-reply"
---

# #6619 — fix(runtime/agent): authorize shell explicitly at autonomy.level=full (#6434)

**Repo:** zeroclaw-labs/zeroclaw · **Type:** PullRequest · **Reason:** review_requested · **Updated:** 2026-06-27 11:12 UTC
**Link:** https://github.com/zeroclaw-labs/zeroclaw/pull/6619

## What happened
Fix for #6434: at `[autonomy] level = "full"` the model returns simulated
refusal text ("blocked by the current security policy") without ever emitting a
`tool_call` — a pre-dispatch model-behavior bug, not an executor/approval-gate
rejection. yijunyu (author) adds one prompt block in
`crates/zeroclaw-runtime/src/agent/system_prompt.rs` that, only at
`AutonomyLevel::Full` and only when a registered power tool (`shell` /
`file_write` / `file_edit`) is present, names those tools as authorized to
attempt and tells the model not to self-refuse. Audacity88 (maintainer) filed
CHANGES_REQUESTED on May 20 with two blockers: (1) the original wording
("AUTHORIZED and NOT blocked by any security policy") was too broad, and (2) no
post-fix model/tool-dispatch evidence. singlerider (member) confirmed on a stale
sweep that both blockers were still open at head `5aa4ac1`. **Since then**,
yijunyu pushed `7a2279428` (2026-06-27 06:53Z) that narrows the wording, adds
the `full_autonomy_authorization_is_attempt_scoped_not_unconditional`
regression test, and posts a screenshot of 5 local tests passing — but the dispatch
smoke is still only promised ("to follow"). The current
review state is still `CHANGES_REQUESTED`; the latest push has not been
re-reviewed.

## Who needs what from you
You were re-requested as a reviewer on the freshly-pushed `7a2279428`. The ask:
judge whether the two standing blockers are now resolved and give a verdict. Net:
blocker #1 (wording) is genuinely fixed in code; blocker #2 (live dispatch
evidence) is still outstanding; **and the push introduced a new, hard blocker —
the PR no longer compiles against current `master`, so CI Lint + Test + the
required gate are red.**

## Suggested response
Paste as a review. Recommended verdict: **request-changes** (regression — the
latest push broke the build).

- **blocking — the new test module does not compile against current `master`; CI
  Lint + Test + "CI Required Gate" are all red on `7a2279428`.** Two compile
  errors, both in the `#[cfg(test)] mod tests` you added (the production prompt
  block is fine):
  - `error[E0422]: cannot find struct, variant or union type 'AutonomyConfig' in
    module 'zeroclaw_config::schema'`. There is no `AutonomyConfig` type — the
    autonomy config struct in the function signature is
    `zeroclaw_config::schema::RiskProfileConfig` (its `.level` field is the
    `AutonomyLevel`). Your `build_with_autonomy` helper constructs
    `zeroclaw_config::schema::AutonomyConfig { level, ..Default::default() }`;
    that path doesn't exist on master. Build a `RiskProfileConfig` instead (set
    its `level`), or set the level on whatever the current canonical risk-profile
    constructor is.
  - `error[E0061]: this function takes 13 arguments but 11 arguments were
    supplied`. `build_system_prompt_with_mode_and_autonomy` now takes 13 params
    on master (it gained `identity_config`, and split out `inject_memory` /
    `show_tool_calls`). Your test helper calls it with 11 positional args in the
    old shape. Update the call to the current 13-arg signature
    (`workspace, model, tools, skills, identity_config, bootstrap_max_chars,
    autonomy_config, native_tool_specs_present, skills_prompt_mode,
    compact_context, max_system_prompt_chars, inject_memory, show_tool_calls`).
  - Root cause is branch staleness: the test was written against an older
    signature/type and the branch was rebased without re-checking the test
    compiles. The screenshot "5 passed" was produced on your local branch, not
    against current master — please re-run `cargo test -p zeroclaw-runtime --lib
    agent::system_prompt` on a fresh rebase before re-requesting.
- **blocking (carried over from Audacity88, still open) — post-fix dispatch
  evidence is still missing.** This is a model-behavior bug; the four/five
  prompt-string tests only prove the text appears, not that the model now emits a
  `tool_call`. The PR body + latest comment still say the Full-autonomy
  `echo hello` dispatch smoke is "to follow." It hasn't landed. Either attach the
  redacted run (config shape + a `tool_call`/dispatch receipt or `hello` output)
  or take Audacity88 up on the offer to run it. ⚠ I cannot verify this from the
  diff — confirm before treating it as resolved.
- **non-blocking (resolves Audacity88 blocker #1) — wording is correctly
  narrowed; good.** The block now reads "registered and authorized to call (to
  attempt) under Full autonomy," forbids self-refusal, and explicitly keeps
  `forbidden_commands` / `forbidden_paths` / sandbox in force, ending with "Never
  invent a block that did not happen." The overbroad "NOT blocked by any security
  policy" string is gone, and
  `full_autonomy_authorization_is_attempt_scoped_not_unconditional` pins the
  distinction (asserts the attempt-scope language is present and the overbroad
  claim is absent). This blocker is satisfied once it compiles.
- **non-blocking — confirm the prompt asserts against the *Tool Authorization*
  section, not the whole prompt.** `full_autonomy_authorizes_shell_when_registered`
  asserts `prompt.contains("shell")` against the entire prompt; `shell` may
  already appear elsewhere (e.g. the tool list), so that line doesn't actually
  prove the authorization block names it. The other tests correctly slice on
  `split("## Tool Authorization")`. Minor, but tighten this one to the section
  for a real signal. ⚠ low-confidence — depends on whether the section-scoped
  asserts already cover it.
- **good** — the scoping is the right shape: gated on `AutonomyLevel::Full` AND
  on the registered power-tool list (so `shell` is never named when excluded via
  `non_cli_excluded_tools`), prompt-only with no runtime-gate change, and the
  `Supervised`/`ReadOnly` defaults emit byte-identical output. The "skip when no
  power tools registered" and "lists only registered power tools" tests cover
  that scoping well. The approach (mirror the existing Hardware Access
  counter-narrative) is sound and targets the correct layer.

Recommended verdict: **request-changes.** The fix design is right and the wording
blocker is resolved, but the latest push regressed the build (two compile errors
in the test module) and the dispatch-evidence blocker is still open. Both must
clear before approve. ⚠ Note this is `priority:p1` and a real Full-autonomy
footgun, and the PR is a stale candidate with a June 30 close deadline — worth a
quick nudge to the author to land the compile fix + smoke rather than letting it
age out.

## Next action
- [ ] Post the drafted review as **request-changes**: lead with the two compile
      errors (wrong type `AutonomyConfig`→`RiskProfileConfig`; wrong arity
      11→13 args) that put CI red on `7a2279428`, restate the still-open dispatch
      smoke, and acknowledge the wording fix is correct. Nudge the author to fix
      + re-run `cargo test -p zeroclaw-runtime --lib agent::system_prompt` on a
      fresh rebase before the June 30 stale deadline.

## Verification (verifier · opus)
**Gate: PASS**

Tried to refute the central regression claim against live CI and the source tree;
it holds on every load-bearing point. Head verified = `7a2279428…` (matches the
report). `reviewDecision = CHANGES_REQUESTED`, `mergeable = MERGEABLE`.

- **CI is red on the latest push (Lint + Test + CI Required Gate).** — *confirmed*:
  `statusCheckRollup` shows `Lint` FAILURE, `Test` FAILURE, `CI Required Gate`
  FAILURE on `7a2279428`; all `Build`/`Check*` jobs PASS. The Build-passes /
  Test-fails split is exactly what a `#[cfg(test)]`-only compile error produces
  (regular build never compiles the test mod), so it corroborates "production
  block is fine, test module doesn't compile." (confidence: high)
- **E0422: `AutonomyConfig` doesn't exist; type is `RiskProfileConfig`.** —
  *confirmed*: raw failed-job logs (Test job 83798703186 and Lint job 83798703188)
  both show verbatim `error[E0422]: cannot find struct, variant or union type
  'AutonomyConfig' in module 'zeroclaw_config::schema'` at `system_prompt.rs:503`
  (`let autonomy = zeroclaw_config::schema::AutonomyConfig {`). Source confirms the
  type genuinely does not exist: `grep -rE 'AutonomyConfig' crates/zeroclaw-config/src`
  returns nothing; only `RiskProfileConfig` is defined (`schema.rs:10509`), whose
  `level: AutonomyLevel` field (`schema.rs:10511`) is what the fn signature takes
  (`autonomy_config: Option<&…::RiskProfileConfig>`, `system_prompt.rs:150`). The
  report's suggested fix (build a `RiskProfileConfig`, set `.level`) is correct.
  (confidence: high)
- **E0061: fn takes 13 args, test supplies 11.** — *confirmed*: both failed-job
  logs show verbatim `error[E0061]: this function takes 13 arguments but 11
  arguments were supplied` at `system_prompt.rs:507`, "two arguments of type
  `bool` and `bool` are missing." Source confirms exactly 13 params
  (`system_prompt.rs:143-162`), and the two trailing ones are `inject_memory: bool`
  and `show_tool_calls: bool` — matching "two `bool` … missing." The report's
  enumerated 13-arg signature is byte-correct. (confidence: high)
- **Root cause = branch staleness, not a production-code bug.** — *confirmed*:
  both errors are at test-mod lines 503/507 inside the added `#[cfg(test)] mod
  tests`; the production prompt hunk compiles (Build/Check green). (confidence: high)
- **Wording blocker #1 is fixed in code.** — *confirmed*: diff shows the
  production block now says "registered and authorized to call (to attempt) under
  Full autonomy", "do NOT self-refuse", keeps `forbidden_commands` /
  `forbidden_paths` / sandbox in force, ends "Never invent a block that did not
  happen." The overbroad "NOT blocked by any security policy" string survives only
  as a *negative* test assertion (`!auth.contains("NOT blocked by any security
  policy")`). (confidence: high)
- **Dispatch-evidence blocker #2 is still open.** — *confirmed*: yijunyu's own
  latest PR comment states the Full-autonomy `echo hello` dispatch smoke "is to
  follow as a redacted run in a separate comment"; only a test-passing GIF is
  attached, no `tool_call`/dispatch receipt. Report's ⚠ caveat ("cannot verify
  from the diff") is appropriate. (confidence: high)
- **Non-blocking nit: `full_autonomy_authorizes_shell_when_registered` asserts
  `shell` against the whole prompt.** — *confirmed*: that test does
  `assert!(prompt.contains("shell"))` (no section slice), whereas the other two
  tests slice on `split("## Tool Authorization")`. The report's own low-confidence
  framing was warranted but the nit is in fact accurate. (confidence: high)

**Note to user:** Trust this draft as-is — the regression claim is real and
load-bearing (verified against both live CI logs and `master` source: `AutonomyConfig`
does not exist, the fn is 13-arg, both errors are in the test mod only). Safe to
post **request-changes** with the two compile errors leading. The only thing you
genuinely *can't* confirm from here is the dispatch-smoke (blocker #2) — that's a
"still missing," not a "broken," and the draft already flags it. No revisions needed.
