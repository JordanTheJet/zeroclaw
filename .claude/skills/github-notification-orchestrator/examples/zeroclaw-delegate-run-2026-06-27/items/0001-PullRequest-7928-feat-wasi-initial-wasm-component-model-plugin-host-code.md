---
notification_id: "24283224634"
updated_at: "2026-06-27T16:09:33Z"
reason: "review_requested"
repo: "zeroclaw-labs/zeroclaw"
type: "PullRequest"
number: "7928"
title: "feat(wasi): initial WASM component-model plugin host code"
url: "https://github.com/zeroclaw-labs/zeroclaw/pull/7928"
agent_profile: "pr-review-responder"
priority: "P1"
status: "needs-reply"
---

# #7928 — feat(wasi): initial WASM component-model plugin host code

**Repo:** zeroclaw-labs/zeroclaw · **Type:** PullRequest · **Reason:** review_requested · **Updated:** 2026-06-27 16:09 UTC
**Link:** https://github.com/zeroclaw-labs/zeroclaw/pull/7928

## What happened
This is the first pass at the **host side of the WIT v0 WASM component-model plugin
system** in `zeroclaw-plugins` by **bheatwole** (contributor, working from a fork):
`ComponentChannel`/`ComponentMemory`/`ComponentTool` adapters, a shared engine,
`FineGrainedPermissions` deny-by-default sandbox, and `PluginStore::instantiate_*`
entry points (`PluginHost` was renamed to `PluginStore`). It's +8696/−289 across 68
files, labeled `risk:high` / `size:XL`. The thread has two reviewers: **WareWolf-MoonWall**
(member) approved at `4989bb6e`, then re-reviewed and dropped to `--comment` because
**Audacity88** (member) filed **CHANGES_REQUESTED** at `301d5d31` with two 🔴 blockers
(HTTP permission also granted raw TCP connect; sync `Channel` methods called
`blocking_lock` from async paths) plus a 🟡 (no real component-boundary test). bheatwole
has since pushed fixes for all three, but in doing so **grew the PR substantially** —
adding the new `zeroclaw-plugin-sdk` guest crate with four real `wasm32-wasip2` example
plugins + integration tests, websocket/proxy support, a retry refactor into
`zeroclaw-infra`, and a wasmtime bump. He explicitly asked Audacity88 whether to review
it as one XL change or split it. **The current `reviewDecision` is still
`CHANGES_REQUESTED` — Audacity88's hold has not been cleared.** You are now requested as a
reviewer.

## Who needs what from you
You're asked to review a `risk:high`/`size:XL` plugin-host PR that is **technically
sound on its merits but blocked on an unanswered process question**: bheatwole asked
Audacity88 whether to keep this as one XL PR or split it, and that's the real decision
gate now (Audacity88's CHANGES_REQUESTED is still active). Your review should (a) confirm
the two original 🔴 blockers are genuinely resolved, and (b) weigh in on the split-vs-merge
question, since the scope is materially larger than what WareWolf-MoonWall first approved.

## Suggested response
Paste-ready review notes (tagged). Recommended verdict at the end.

**What looks good**
- 🟢 Deny-by-default `FineGrainedPermissions` is the right security posture — every file
  path, HTTP host, and TCP/UDP endpoint must be named, wildcards restricted to L3+
  subdomains. Strong foundation.
- 🟢 Both of Audacity88's 🔴 blockers now have concrete fixes **with regression tests**:
  HTTP no longer adds to `tcp_rules` (`spike_tcp_permission.rs`:
  `http_only_permission_denies_raw_tcp_connect` + `tcp_permission_allows_raw_tcp_connect`),
  and the `blocking_lock`/`call_plugin_sync!` path is removed entirely.
- 🟢 The new `zeroclaw-plugin-sdk` + four real `wasm32-wasip2` example plugins round-trip
  through the *unmodified* `PluginStore`, which is exactly the boundary proof Audacity88
  asked for — and it surfaced two real host bugs (`instantiate_async` vs sync variant;
  trappable-vs-async mismatch in `from_bytes` probes).
- 🟢 Zero production blast radius today: `instantiate_*` is not yet called from
  `zeroclaw-runtime`/`zeroclaw-gateway`, so the plumbing lands behind feature gates.

**Findings**
- **blocking (process, not code)** — Audacity88's CHANGES_REQUESTED is still the active
  review decision, and bheatwole's split-vs-keep question is unanswered. This is the real
  gate: confirm with Audacity88 whether to merge as one XL PR or split before this can
  proceed. ⚠ Defer to Audacity88 here — only they can clear their own hold.
- **blocking** — `zeroclaw-api::Channel::drop_self_messages` changes `fn` → `async fn`.
  This is a signature change to a central, widely-implemented trait. Confirmed in the diff
  (`crates/zeroclaw-api/src/channel.rs`) and the single in-tree call site in
  `zeroclaw-channels/src/orchestrator/mod.rs` is updated to `.await`. The PR's grep note
  says no other in-tree implementor overrides it, so others inherit the new async default.
  `zeroclaw-api` is Experimental (no stability guarantee), and the Compatibility section
  documents the out-of-tree upgrade path. ⚠ Worth one independent grep to confirm no
  override was missed before signing off, given how central this trait is.
- **non-blocking** — Validation Evidence still reads as a partial-feature local run
  ("885+ tests" / subset). For a `risk:high` XL PR the authoritative bar is the full
  workspace nextest run; ask the author to update the evidence section to reflect the
  post-SDK scope (CI is reported green).
- **non-blocking** — Scope has grown well beyond the originally-approved targeted host:
  SDK crate, websocket support, proxy support, retry extraction, wasmtime
  `43.0.2→45.0.1` + cranelift bump, and two new transitive deps (`cap-net-ext`,
  `dns-lookup`). Each is individually defensible, but the aggregate justifies the
  split-vs-keep decision above.
- **nit** — Commit history is dominated by `Merge branch 'wasi-plugins-host'…` merge
  commits (fork-sync noise), making incremental diffing against any commit boundary hard.
  A squash/rebase before final review would help.
- **non-blocking (security)** — The `AddressString` wildcard TCP/UDP matching relies on
  reverse DNS at connect time (TOCTOU-susceptible). Already raised earlier and the doc
  comment was clarified; just confirm the doc note is present and adequate.

**Recommended verdict: needs-more-info / request-changes (mirroring Audacity88).**
The code-level blockers appear resolved with tests, but you should not approve over
Audacity88's active CHANGES_REQUESTED. Post comment-level review confirming the fixes and
push the split-vs-keep decision to Audacity88 + the maintainer; convert to approve only
once that's settled and the async-trait grep is independently confirmed.

## Next action
- [ ] Post a comment-level review confirming the two 🔴 fixes + tests look right, and
      ask Audacity88 / the maintainer to settle the split-vs-keep-as-XL decision before
      this can clear; independently `grep` for any other `drop_self_messages` override
      before approving. (Do not approve over the active CHANGES_REQUESTED.)

---

## Verifier verdict

**Verified:** 2026-06-27 against live PR via read-only `gh` (head at verification:
`b8312e3c70298f228cd40232d2cf2931ac09f033`; CI run state: all 18 checks SUCCESS;
`reviewDecision: CHANGES_REQUESTED`; `mergeable: CONFLICTING`; state OPEN, not draft).

**Headline:** ⚠️ **The draft is materially stale and its core framing is now wrong.**
The draft narrates the PR as of head `771b88c8` (≈2026-06-22): two original blockers
fixed, only an unanswered "split-vs-keep" *process* question remaining. That is no
longer the situation. Since then there have been **two additional review rounds** and
the author has proposed **abandoning #7928**. The draft's "Recommended verdict" and
"Next action" are built on an obsolete state. Anyone acting on this draft would post a
review that is two cycles behind the live thread.

### What the draft missed (most important first)

1. **🔴 NEW unaddressed blocker — raw `wasi:http` host buffering (not in draft at all).**
   On **2026-06-26** Audacity88 filed a *fresh* `CHANGES_REQUESTED` (head `38c388ea`):
   `send_via_proxy_client` in `crates/zeroclaw-plugins/src/component/plugin_store.rs`
   still buffers the entire response body (`resp.bytes().await` → `Full::new(...)`) with
   no size cap, bypassing the helper-level `max-bytes`. **Confirmed still present at the
   current head** (`plugin_store.rs:207` `resp.bytes().await`, `:219` `Full::new`). This
   is a live, open, code-level blocker. singlerider concurred (2026-06-26). The draft's
   claim that the only remaining gate is a "process question" is **false as of today.**

2. **Author has proposed abandoning this PR (not in draft).** In the latest PR comment
   (**2026-06-27 15:56 UTC**) bheatwole states he is "comfortable with a plan of: making
   **8368 the initial push** for component model host code instead of 7928 / **abandoning
   7928** and selectively pulling in code to future PRs / opening an RFC" on the security
   model. singlerider (2026-06-26) also said he would build a competing implementation to
   reduce the line count (→ #8368). The split-vs-keep question the draft centers on has
   effectively been overtaken by an abandon-and-replace direction. Recommending "convert
   to approve once settled" is now the wrong action.

3. **A second resolved/blocked cycle the draft never reaches.** The draft does not
   mention the `download-to-attachment` `max_bytes` blocker (Audacity88, 2026-06-25,
   `db22a350`) or the `get-secret` scope-creep blocker (same review) — both later resolved
   (singlerider APPROVED at `1f8a85df`, 2026-06-25). The draft's reviewer cast and
   timeline are incomplete: it names only WareWolf-MoonWall and Audacity88, but
   **singlerider (member)** is also an active reviewer (one APPROVED, one concurring
   COMMENT).

### Claim-by-claim check (claims that ARE supported)

- ✅ **Metadata** — `+8696/−289`, 68 files, labels include `risk:high` + `size:XL`,
  author `bheatwole` from fork `bheatwole/zeroclaw`, base `master`, head
  `wasi-plugins-host`. All match live JSON.
- ✅ **`reviewDecision` is `CHANGES_REQUESTED`** — correct, *but* the draft attributes the
  hold to the June-21 review at `301d5d31`. The currently-active CHANGES_REQUESTED is the
  **June-26 `38c388ea`** review (the raw `wasi:http` blocker), a different and newer cause.
  Verdict: technically true, materially mis-explained.
- ✅ **Original two 🔴 blockers were genuinely fixed with regression tests.** Confirmed:
  `spike_tcp_permission.rs` contains `http_only_permission_denies_raw_tcp_connect` and
  `tcp_permission_allows_raw_tcp_connect`; `blocking_lock`/`call_plugin_sync!` removed;
  `drop_self_messages` is now `async fn` in `crates/zeroclaw-api/src/channel.rs:333` and
  the orchestrator awaits it (`orchestrator/mod.rs:4141`). Audacity88 himself marked both
  resolved (2026-06-22 and later). Supported.
- ✅ **`drop_self_messages` async signature change + single in-tree call site updated.**
  Confirmed. No other in-tree implementor override found (the in-tree `impl` is the
  default in `channel.rs`; the only call site is the orchestrator). Grep claim holds.
- ✅ **Deny-by-default `FineGrainedPermissions` design** — corroborated by all reviewers.
- ✅ **SDK + four `wasm32-wasip2` example plugins provide the boundary proof** — corroborated
  by Audacity88's and singlerider's resolved notes.
- ✅ **Validation Evidence "885+ tests" is a subset run; CI green** — supported (CI is green;
  multiple reviewers flag the 885 figure as a partial-feature run).
- ✅ **Merge-commit-dominated history; TOCTOU reverse-DNS note** — both corroborated.
- ✅ **wasmtime `43.0.2→45.0.1` + cranelift bump, new deps `cap-net-ext`/`dns-lookup`,
  websocket/proxy/retry scope growth** — corroborated by WareWolf-MoonWall's review.

### Overstatements / inaccuracies to flag

- ❌ **"technically sound on its merits but blocked on an unanswered process question"** —
  **Overstatement / now false.** There is an open *technical* code blocker (raw
  `wasi:http` buffering, host-memory DoS) that is unaddressed at the current head.
- ❌ **"The current `reviewDecision` is still `CHANGES_REQUESTED` — Audacity88's hold has
  not been cleared"** framed as the *June-21* hold — **stale.** The June-21 hold *was*
  cleared (marked resolved); the active hold is a *newer, different* June-26 blocker.
- ❌ **"bheatwole … grew the PR substantially … He explicitly asked Audacity88 whether to
  review it as one XL change or split it"** as the live decision gate — **overtaken by
  events.** The live direction (2026-06-27) is abandon #7928 → base on #8368 + RFC.
- ⚠️ **Reviewer roster incomplete** — omits singlerider entirely.
- ⚠️ **"Zero production blast radius … behind feature gates"** — directionally supported
  (instantiation paths unused by runtime), but does not neutralize the host-side
  `wasi:http` memory-DoS surface Audacity88 raises, since that hook is reachable whenever
  the component feature is exercised.

### Build / CI regression check

- ✅ **No build regression.** All 18 CI checks are SUCCESS at the current head (Format,
  Lint, Test, Build x86_64, Check all-features / no-default / 32-bit, Check aarch64 &
  Windows, Security, Docs Style, Nix, Installer Drift, Zerocode RPC Boundary, Benchmarks
  Compile, CI Required Gate, main). The draft's "CI is reported green" claim holds.
- ⚠️ **`mergeable: CONFLICTING`** — the PR currently has merge conflicts against `master`
  (not a CI failure, but a merge blocker the draft does not mention).

### Recommended correction to the draft's verdict

Do **not** post the draft's "confirm the two 🔴 fixes + push the split-vs-keep decision"
review — it is two cycles behind. The accurate current posture is: prior blockers
resolved, **one live unaddressed 🔴 (raw `wasi:http` host buffering, `plugin_store.rs:207`)**,
PR is `CONFLICTING`, and the author has proposed **abandoning #7928 in favor of #8368**
plus an RFC on the permission/secret/config model. Any review should acknowledge the
abandon-and-replace direction rather than pushing toward approval of #7928.

*(Read-only verification; nothing was posted to GitHub.)*
