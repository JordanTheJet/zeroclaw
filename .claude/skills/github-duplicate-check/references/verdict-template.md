# Verdict template (enforced output format)

Every prior-art run ends in this structure. It exists so the answer is always
*decidable*: the user sees one verdict, the evidence behind it, and exactly what
to do next — file, comment, or proceed. Do not free-form a summary instead;
fill this in.

## The four verdicts (pick exactly one)

| Verdict | Means | Default recommendation |
|---|---|---|
| `novel` | No pre-existing issue or PR covers this. The user's idea/bug is new. | `proceed` — file it / open the PR / write the reply. |
| `duplicate-of-#N` | A pre-existing issue (open) already reports this same thing, confirmed by a shared concrete identifier. | `comment-on-existing` — add your detail / +1 on #N instead of filing. |
| `already-in-progress-PR-#M` | An **open PR** (usually by someone else) is already implementing this. | `do-not-file` a competing PR — review / collaborate on #M; comment if you have requirements. |
| `related-see-#N` | Same area or symptom, but no provable shared identifier — topically related, not a confirmed dup. | `proceed` with a cross-reference to #N, or ask the user — it's a judgment call. |

If a merged PR appears to have **already fixed** the bug, use `duplicate-of-#N`
pointing at the fix and recommend `do-not-file` — but only after checking the fix
covers the user's exact case (note any doubt in confidence).

## Confidence (required, on the verdict)

State one: `high` (a shared error string / symbol / config field — a near-lock),
`medium` (strong topical + partial identifier overlap), `low` (similar symptoms,
needs a human call). Be honest: "99% the same bug" and "looks related, your call"
must not read identically. Low confidence on a `duplicate-of` should usually be
downgraded to `related-see` instead.

## The template

Copy this, fill the brackets, drop nothing.

```markdown
## Prior-art verdict: <novel | duplicate-of-#N | already-in-progress-PR-#M | related-see-#N>
**Confidence:** <high | medium | low> · **Query variants run:** <"v1", "v2", …> · **Repo:** owner/name

**Bottom line:** <one sentence — e.g. "An open PR #6693 by another contributor
already implements dream mode; don't open a competing PR.">

### Candidates (ranked)
| # | type | state | author | why it matches |
|---|---|---|---|---|
| #N | issue | open | someone-else | shares the panic string `...` and the fn `...` — same defect |
| #M | pr | open | someone-else | implements the same feature; 4 commits in |
| #K | issue | closed (won't-fix) | maintainer | same idea, declined — read the reason before re-proposing |
| #J | issue | open | you | your own earlier report of this |

(If zero candidates: state "No issues or PRs matched any variant." and verdict `novel`.)

### Recommendation: <do-not-file | comment-on-existing | proceed>
<One or two sentences. If comment-on-existing, name the issue/PR to comment on
and what to say. If proceed, say what's safe to file and whether to cross-link a
related item. If do-not-file, name the in-progress PR to engage with instead.>

### Hand-off (only if a lifecycle action is wanted)
If the user wants the existing item marked or the dup handled, this is
github-issue-triage's job, not this skill's. Binder finding:
- primary_issue_number: <N>
- confidence: <high|medium|low>
- reasoning: <the shared identifier, one line>
Then: run `/github-issue-triage <N>`.
```

## Rules for filling it in

- **One verdict, always.** Don't hedge with two. If you can't choose between
  `duplicate-of` and `related-see`, the honest answer is `related-see` at the
  matching confidence.
- **"Why it matches" must be concrete.** Cite the shared identifier, not "feels
  similar." A row that can't name what it shares belongs in `related`, not the
  duplicate slot — or not in the table at all.
- **By-others first.** Rank another author's open work above the user's own and
  above closed items; that's the result that changes their next move.
- **Never act in the template.** The hand-off block *names* an invocation; it
  does not run it. This skill is read-only — the close, label, or comment is the
  user's explicit next step via github-issue-triage.
