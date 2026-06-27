# Model selection rationale

This skill is multi-agent: an orchestrator plans, a fleet of per-item subagents
draft responses, and a summarizer assembles the digest. Each of those roles has
a different difficulty, blast radius, and call volume — so each gets a different
model. The governing principle:

> **Match model strength to the task's difficulty and blast radius; use the
> cheapest model that clears the bar; reserve the expensive tiers for reasoning
> that is deep *and* where a mistake is costly.**

Spending Opus on a job Haiku does correctly is waste; spending Haiku on a code
review is a false economy that produces a confidently-wrong draft. The fan-out
makes both errors expensive at scale — a full inbox is dozens of subagent calls.

## The model menu (authoritative IDs and pricing)

Pricing is per 1M tokens. Use the **alias** when spawning subagents; the Agent
tool accepts the short names `opus` / `sonnet` / `haiku` / `fable`.

| Tier | Alias | Full ID | Context | Input | Output | Character |
|---|---|---|---|---|---|---|
| Fable 5 | `fable` | `claude-fable-5` | 1M | $10 | $50 | Most intelligent; a tier above Opus. Reserve for the genuinely hardest reasoning. |
| Opus 4.8 | `opus` | `claude-opus-4-8` | 1M | $5 | $25 | Most capable Opus; state-of-the-art long-horizon agentic + code reasoning. |
| Sonnet 4.6 | `sonnet` | `claude-sonnet-4-6` | 1M | $3 | $15 | Best speed/intelligence balance. The high-volume workhorse. |
| Haiku 4.5 | `haiku` | `claude-haiku-4-5` | 200K | $1 | $5 | Fastest and cheapest. Mechanical, speed-critical, well-structured tasks. |

Output tokens dominate cost here (drafts are output-heavy). The ratios that
drive the assignments: Opus output is **5×** Haiku and Sonnet output is **3×**
Haiku; Sonnet output is **60%** of Opus. Fable's effort `max` and Opus/Sonnet's
effort `max` are available; Haiku supports neither `max` nor the effort knob,
which is fine — its jobs here don't need deep thinking.

## Per-role assignments

| Role | Model | Why this tier, and why not one lower/higher |
|---|---|---|
| **Orchestrator** (the skill itself, in the main loop) | **opus** | Plans a heterogeneous 100+ item inbox, classifies each ambiguous notification, and routes the fan-out. Misroutes cascade — every downstream subagent inherits the orchestrator's mistake — so this is the one place to pay for the strongest general reasoning. Not Fable: planning is hard but not at the frontier, and the orchestrator runs in the user's main session where Opus is already the default. |
| **pr-review-responder** | **opus** | Reads diffs and reasons about correctness, security, and edge cases. Highest blast radius in the fleet: a plausible-but-wrong review draft that the user pastes is worse than no review. Code reasoning is exactly where Opus's lead over Sonnet is largest. Bump an individual item to **fable** only for an unusually large or safety-critical PR. |
| **issue-responder** | **sonnet** | Classify the issue, propose labels/dedup, draft a clarifying reply. Well-structured, medium difficulty, and **high volume** (issues + assignments are the bulk of a busy inbox). Sonnet is the cost/quality sweet spot; Opus would triple the output cost for little quality gain on a structured task. Not Haiku: judging duplicate-vs-distinct and writing a good clarifying question needs real comprehension. |
| **mention-responder** | **sonnet** | Draft a contextual reply to a direct question in the user's voice. Needs good language and light reasoning, not code analysis. Sonnet handles tone and context well at 60% of Opus's output cost. |
| **author-activity-responder** | **sonnet** | Summarize what changed on a thread the user opened and recommend the next move (merge / nudge / close / reply). Summarization + light judgment — Sonnet's wheelhouse. |
| **ci-failure-investigator** | **sonnet** | Parse CI logs to the root-cause line and the failing test, sketch a fix. Mostly pattern extraction with some reasoning. Sonnet by default; escalate a specific item to **opus** when the failure is non-obvious (flaky, cross-crate, or a miscompile). Not Haiku: logs are noisy and the root cause is often not the last error line. |
| **verifier** | **opus** | The adversarial quality gate over high-stakes drafts — it tries to *refute* PR-review findings, CI root-causes, and "fixed/closed in #N" claims against the source. Refuting a code claim needs the same reasoning depth that produced it, so this is Opus even though it only runs on a few items per run (cost stays bounded). Verification is the cheapest place to catch a confident-but-wrong draft before the user acts on it. |
| **daily-summarizer** | **haiku** | Collate the already-written item reports into a sorted, linked `INDEX.md` and write a short lede. The sorting and linking are done by `scripts/build_index.py` (deterministic — no model needed), so the model only writes a few sentences over pre-structured data. The cheapest, fastest model is ideal; paying Opus here would be pure waste. |

## What this costs on a realistic inbox

For the 145-notification inbox this skill was built against (≈27 review
requests, 12 mentions, 6 authored, a couple CI + assignments), a default
P1+P2-capped run dispatches on the order of a dozen subagents. The split keeps
the **expensive Opus calls scoped to the few PR reviews**, runs the **dozen-ish
structured drafts on Sonnet**, and does the single collation pass on **Haiku**.
Routing every subagent to Opus "to be safe" would roughly **3–5× the output
bill** of the high-volume roles for no quality gain on the structured ones —
the whole point of per-role selection.

## Overrides

`model:` in each agent profile's frontmatter is a **recommendation the
orchestrator passes to the Agent tool**, not a hard binding. Override per item
when an instance is unusually hard:

- A 2,000-line PR or a security-sensitive change → bump that `pr-review-responder`
  item to **fable**.
- A gnarly, non-obvious CI failure → bump that `ci-failure-investigator` item to
  **opus**.
- A trivial "thanks, LGTM" mention → you may drop that `mention-responder` item
  to **haiku**.

The table is the default that's right most of the time; the override is how you
spend more only where a specific item earns it.

## Thinking & effort

Subagents inherit adaptive thinking from the harness. For the Opus
`pr-review-responder`, prefer **high** effort — review is intelligence-sensitive
and a missed bug is the costly error. For the Sonnet roles, **medium** effort is
the balance. The Haiku summarizer needs neither (and Haiku doesn't expose the
effort knob); its work is mechanical.
