# Search strategy — turning a bug/feature/PR into prior-art queries

The quality of a prior-art check is set almost entirely at query time. A literal
copy of the user's title finds only items worded like theirs and misses the one
someone *else* filed for the same defect in different words. This file is the
recipe for good queries, ranking, and avoiding false positives.

## 1. Extract distinctive identifiers (not boilerplate)

Two reports of the **same** thing share concrete tokens. Two reports of
*different* things in the same area share only vibes. Pull the concrete tokens:

| Input is a… | Pull these | Drop these |
|---|---|---|
| Bug | exact error/panic string, failing function/module, config field, flag, the precise wrong behavior | `[Bug]:`, "doesn't work", OS/version numbers, stack-frame line numbers, timestamps |
| Feature | the feature noun + 1–2 synonyms ("dream mode" / "memory consolidation" / "reflection"), the surface it touches (chat command, gateway, config key) | `[Feature]:`, "it would be nice", marketing adjectives |
| PR you're about to open | the subsystem + the change verb, the symbol/file you'll touch, any issue it would close | `feat(...)`, `fix(...)`, branch names |

The identifier you most want is the one `github-issue-triage` uses to *confirm* a
duplicate: an exact error string, a specific code path/function, an explicit
cross-reference, or a config field. If your query is built around one of those,
a hit is a strong duplicate signal rather than a topical coincidence.

## 2. Generate 2–4 query variants

Run the script once per variant and union the results. Recall beats precision: a
missed duplicate is the costly error; a false positive costs a human two seconds
to reject.

- **Tight variant** — the error string or the symbol verbatim. High precision,
  catches the exact dup.
- **Broad variant(s)** — the feature noun, a synonym, the subsystem name. Catches
  the same idea filed with different words.
- For a feature, deliberately include a **synonym you didn't use**: someone else
  may have named it differently ("dream mode" vs "sleep-time compute" vs
  "reflective memory"). The whole point is to find *their* wording.

Quote multi-word phrases. Keep each query short — `gh search` ranks by relevance,
so 2–4 strong terms beat a sentence.

## 3. Rank candidates

Order the merged candidate set by how strongly each predicts a real duplicate:

1. **Shared concrete identifier + open** — same error string / symbol / config
   field, still open. Top of the list; this is `comment-on-existing` territory.
2. **Open PR by another author** — someone is actively building it. The headline
   for "is someone already working on this." Surface even if the title match is
   only moderate.
3. **Merged PR naming the symptom** — it may already be fixed/shipped; check
   whether the fix covers the user's exact case before declaring it done.
4. **Closed won't-fix / declined issue** — the idea was considered and rejected.
   Decision-relevant prior art: the user should read *why* before re-proposing.
5. **Same-subsystem, no shared identifier** — *related*, not duplicate. Useful
   context, but do not let it drive a `duplicate-of` verdict.

If the repo uses area labels (`channel:*`, `provider:*`, `tool:*`,
`memory`, …), a label-scoped pass (`--label`) is a cheap way to pull
same-area items before a full text search — use it to seed the "related" bucket.

## 4. By-others detection

The active user's login comes from `gh auth status` (the orchestrator may have
already resolved it as `reviewer:` in `tmp/handoff.md` — reuse it, don't re-shell).
Split candidates into **yours** and **others'**:

- **Others' open issue/PR for the same thing** → the duplicate-work warning.
  This is what the user most needs to see before filing or building.
- **Your own prior issue/PR** → still worth flagging (you may have forgotten you
  filed it), but it's not "someone else is on this."

Never treat the user's own draft as prior art for itself.

## 5. Avoiding false positives

- **Same symptom ≠ same bug.** Two reporters hitting different defects in one
  component produce nearly identical surface descriptions. Require a shared
  concrete identifier before calling `duplicate`; otherwise it's `related`.
- **Topical neighbor ≠ duplicate.** An issue about the same *feature area* that
  asks for a different behavior is related context, not a dup. (Example from the
  orchestrator's own run notes: an item "topically related but a different
  surface" was correctly classified *not* a duplicate.)
- **Stale generic terms.** A one-word query like "memory" or "config" returns
  the whole backlog. If a variant returns a flood of unrelated trackers/RFCs,
  it was too broad — tighten it and re-rank, don't dump the flood on the user.
- **Truncation guard.** If the script's candidate count for a variant equals the
  `--limit`, results were likely cut off — note it and consider a tighter,
  higher-signal query rather than trusting a clipped list.

## 6. Hand-off binder contract (to github-issue-triage)

When a verdict is a confirmed duplicate and the user wants lifecycle action,
write the finding to the shared binder / `tmp/handoff.md` entry — do **not** act
on it here. The fields the triage desk reads:

```markdown
## Prior-art finding
- number: <the user's new/draft item, or "" if not yet filed>
- primary_issue_number: <N — the pre-existing item it duplicates>
- type: issue | pr
- confidence: high | medium | low
- reasoning: <one line — the shared identifier, e.g. "same panic string
  `trim budget exceeded` + same fn `compute_budget`">
- by_other_author: <login or "self">
```

`github-issue-triage` re-verifies the shared identifier under its §3 Pass 2
protocol before closing anything. Your job ends at the finding; the close is its
authority. Name the exact invocation for the user (`/github-issue-triage <N>`).
