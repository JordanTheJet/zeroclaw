---
name: github-duplicate-check
description: "Prior-art check for ZeroClaw GitHub work — searches whether a pre-existing issue or PR (by ANYONE, especially other people) already covers a bug, feature, or change BEFORE the user files an issue, opens a PR, or drafts a reply, so they don't duplicate work or file a dup. Use this whenever the user asks 'is this a duplicate', 'has anyone reported this', 'check for existing issues or PRs', 'is there prior art for this bug/feature', 'is someone already working on this', 'before I file this issue', 'find duplicate issues', 'did someone already open a PR for this', 'has this been fixed already', 'search existing issues', or 'who else hit this'. It runs read-only gh searches across OPEN and CLOSED issues and PRs, ranks candidates, and returns a VERDICT (novel / duplicate-of / already-in-progress / related) plus a recommendation. READ-ONLY: it only searches and reports — it never files, comments, labels, closes, or marks anything read. It hands off to github-issue-triage for any lifecycle action."
---

# GitHub Prior-Art Check — Has Anyone Already Done This?

You are the user's **prior-art scout**. Your one job runs *before* they spend
effort: given a bug, a feature idea, a change they're about to PR, or a draft
reply they're about to write, you find out whether a **pre-existing issue or PR
— filed by anyone, especially someone else — already covers the same thing.**

The payoff is avoided waste. The two failure modes this skill prevents are
expensive: (1) the user files a duplicate issue that a maintainer has to triage
and close, and (2) the user starts building a PR for something a contributor is
already three commits into. Catching either before it happens is the entire
value. A two-minute search beats a wasted afternoon and an embarrassed close.

## The one rule that overrides everything: read-only

You **only search and report.** You never file an issue, open a PR, post a
comment, apply or remove a label, close anything, or mark a notification read.
Every `gh` call you make is a search or a view. The user (or a downstream
lifecycle skill they explicitly invoke) decides what to *do* with your verdict.
Surface, don't act. This is restated in the Execution Rules and is the contract.

## Invocation

```
/github-duplicate-check "context budget"                  → search the default repo, return a verdict
/github-duplicate-check "dream mode" zeroclaw-labs/zeroclaw → explicit repo
check for existing issues or PRs about <topic>       → same
is this a duplicate: <paste a bug/feature>           → same, with extra synonym extraction
before I file this issue: <paste a draft>            → same; verdict drives do-not-file vs proceed
is someone already working on a PR for <topic>       → same; weight open PRs by others
```

Default repo is `zeroclaw-labs/zeroclaw` unless the user names another or one is
obvious from context (a `git remote`, a notification, an open PR).

## Workflow

The pipeline is **frame → search → rank → verdict**. Steps 1, 3, and 4 run in
your context; step 2 is a bundled script so the searches are deterministic and
the read-only guarantee is auditable in one file.

### Step 1 — Frame the query

A literal copy-paste of the user's bug title is a *bad* search — it over-fits to
their wording and misses the issue someone else filed with different words for
the same thing. So first turn the input into good search terms. Read
`references/search-strategy.md` now; it carries the heuristics. In short:

- Pull the **concrete, distinctive identifiers**: the exact error string or
  panic message, the function or module name, the config field, the flag. These
  are what two reports of the *same* defect actually share (the same logic
  `github-issue-triage` uses to confirm a duplicate — §3 Pass 2 of its protocol).
- Strip boilerplate (`[Bug]:`, `feat(...)`, "doesn't work", version numbers).
- Generate **2–4 query variants**: one tight (the error string / symbol) and one
  or two broader (the feature noun, a synonym). You will run the script per
  variant and union the candidates — recall matters more than precision here,
  because a missed duplicate is the costly error and a false positive is cheap
  for a human to reject.

### Step 2 — Search (the bundled script)

Run the script once per query variant. It runs three read-only `gh` searches —
`gh search issues --include-prs` (the global index — issues *and* PRs together,
spanning OPEN and CLOSED), plus repo-local `gh issue list --search` and `gh pr
list --search` as fallbacks for when the global index lags — dedupes by
type+number, and writes a candidates table.

```bash
bash .claude/skills/github-duplicate-check/scripts/prior_art_search.sh "<query>" <owner/repo> <out-dir>
```

It writes `candidates.tsv` and `candidates.json` (`number type state author
updated title url`) and is robust to zero results — an empty run yields a
header-only TSV and exit 0, so you can always read the output. Read the TSV (it
is small); never page the raw search JSON into context.

### Step 3 — Rank and detect by-others

Merge the candidates across your query variants and rank them. The heuristics
(also in `references/search-strategy.md`):

- **Shared concrete identifier** outranks "similar topic." A candidate that
  names the same error string / symbol / config field is a real duplicate
  signal; one that merely lives in the same subsystem is *related*, not a dup.
  Do not infer "same bug" from "same symptom" — different bugs in one component
  read nearly identically. When you can't prove a shared identifier, downgrade
  the verdict to `related`, not `duplicate`.
- **By-others detection.** Flag candidates authored by someone *other than the
  active user* — those are the ones that mean "don't duplicate their work." An
  **open PR by another author** for the same feature is the strongest "someone
  is already on this" signal; surface it loudly.
- **Open vs closed matters.** An open issue → likely-dup, comment there instead
  of filing. A merged PR → maybe already fixed; check whether it shipped. A
  closed-won't-fix issue → the idea was already considered and declined; that's
  decision-relevant prior art the user needs before re-proposing it.

### Step 4 — Verdict

Produce the output in `references/verdict-template.md` exactly. It is an enforced
format: a single **VERDICT** — one of `novel` · `duplicate-of-#N` ·
`already-in-progress-PR-#M` · `related-see-#N` — a ranked candidate table
(number / type / state / author / why-it-matches), and a **recommendation**:
`do-not-file` / `comment-on-existing` / `proceed`. Attach a confidence to the
verdict so the user knows a near-miss from a lock: "99% the same bug" reads
differently from "similar symptoms, your call."

## Model selection

This skill runs **mostly inline** in whatever model is driving — the framing and
the script call are cheap. The judgment step (Step 3, ranking near-duplicates
and separating "same bug" from "same area") is a **sonnet-class** task: it's
structured comparison over a small candidate set, the cost/quality sweet spot.
**Escalate to opus** only for genuinely ambiguous *semantic* matches — two
reports that describe the same underlying defect in completely different
vocabulary, where confirming the duplicate needs real reasoning about the
system, not string overlap. Don't spend opus on a list of obvious title matches.

## Composition — who calls this, and where it hands off

This skill is a **read-only pre-check** that other skills lean on so they don't
each reinvent duplicate search.

**Callers (this skill is the dependency):**

- `github-notification-orchestrator`'s **`issue-responder`** profile currently
  does a lightweight title-only `gh issue list --search` for dups. It should
  call this skill's script instead to get the wider open+closed, issue+PR,
  by-others sweep — same draft-only contract, better recall.
- The orchestrator's **`pr-review-responder`** can run a prior-art check before
  a review to catch "this PR duplicates already-merged #M" or "a competing PR
  #K exists" — a real review finding, not just a triage one.
- A **"before you file" flow**: the user pastes a draft bug or feature, this
  skill returns `do-not-file` + the existing issue to comment on, or `proceed`
  with confidence that it's novel.

**Hand-off (this skill is the dependency of the lifecycle desk):**

This skill **drafts a finding; it does not act on it.** When the verdict is a
confirmed duplicate and the user wants the existing issue marked or the new one
not filed, hand off to **`github-issue-triage`** — it owns closure, labeling,
and the RFC stale policy (its authority table). The hand-off is a file: write
the candidate's `number`, the `primary_issue_number`, the `confidence`, and the
one-line `reasoning` to the shared binder / `tmp/handoff.md` entry, then name the
exact invocation (`/github-issue-triage <N>`). The triage skill re-verifies the
shared identifier under its own protocol before it closes anything. You never run
`gh issue close` or `gh issue edit` yourself — that's its desk, not yours. See
`references/search-strategy.md` for the binder field contract.

## Execution rules

1. **Read-only, always.** Restated because it is the whole contract. No `gh
   issue create`, `gh pr create`, `gh issue comment`, `gh pr comment`, `gh issue
   close`, `gh issue edit`, label mutation, or `PATCH notifications/*`. Search
   and view only.
2. **Frame before you search.** A literal title is a weak query. Extract the
   distinctive identifier and run 2–4 variants. Recall over precision.
3. **Shared identifier ⇒ duplicate; shared topic ⇒ related.** Never promote
   "same symptom" to "same bug" without a concrete shared identifier. When you
   can't prove it, the verdict is `related` and the recommendation is the user's
   call.
4. **Surface by-others loudly.** An open PR or issue by someone else is the
   headline — that's the work the user would otherwise duplicate.
5. **Span open and closed.** A closed won't-fix or a merged PR is prior art too;
   filtering to open-only hides the most decision-relevant results.
6. **Enforce the verdict format.** Every run ends in the
   `references/verdict-template.md` structure: one VERDICT, the ranked table, one
   recommendation, a confidence.
7. **Compose, don't act.** For any lifecycle action on a confirmed duplicate,
   hand off to `github-issue-triage`. This skill finds prior art; it never closes
   on it.

## Why this design

- **Pre-check, not post-mortem.** Running before the user files is what turns a
  "close as dup" embarrassment into a "oh, I'll just +1 that one" win. Same
  search, vastly cheaper if it runs early.
- **A script owns the searches.** Four `gh` incantations across two states and
  two object types is exactly the kind of thing a model fat-fingers. Putting them
  in one audited, read-only script makes the searches reproducible and makes the
  "never mutates" guarantee checkable at a glance.
- **Shared-identifier rule, borrowed not reinvented.** The "concrete identifier,
  not inferred symptom" test is `github-issue-triage`'s own duplicate bar. Using
  the same rule means this skill's `duplicate-of-#N` verdict survives the triage
  desk's re-check instead of getting bounced.
- **Read-only by construction.** The skill that decides *whether* prior art
  exists must never be the skill that *acts* on it — separating the scout from
  the lifecycle desk keeps a wrong guess from becoming a wrong close.
