---
id: ADR-016
title: Cron is extracted into its own crate, with a bounded exception until it is
date: 2026-09-02
status: proposed
relates-to:
  - ADR-007
  - crates/zeroclaw-runtime/AGENTS.md
  - crates/zeroclaw-runtime/src/cron
  - docs/book/src/foundations/fnd-001-intentional-architecture.md
  - docs/book/src/architecture/background-work-lifecycle.md
  - https://github.com/zeroclaw-labs/zeroclaw/issues/5607
  - https://github.com/zeroclaw-labs/zeroclaw/issues/10546
---

# ADR-016: Cron Is Extracted Into Its Own Crate, With a Bounded Exception Until It Is

## Context

`crates/zeroclaw-runtime/AGENTS.md` declares that crate a transitional holding area, instructs contributors not to add new functionality there, and names cron among the subsystems awaiting extraction into a dedicated crate. That instruction has no expiry and no exception process. It is a standing scoped contract, not advice.

Cron has not been extracted. `crates/zeroclaw-runtime/src/cron` still owns the scheduler, the SQLite job and run store, schedule parsing, declarative reconciliation, and the execution path that resolves an owning agent and runs under that agent's security policy. There is no `zeroclaw-cron` crate to target, and no accepted record of what such a crate would own.

This produces a standing contradiction. Accepted work that touches cron has nowhere permitted to live. The contract forbids adding functionality to the only crate that has the subsystem, and the destination crate does not exist. Contributors have resolved this ad hoc by adding to `zeroclaw-runtime` anyway, which deepens the coupling the contract exists to unwind, or by asking for a per-pull-request exception, which the contract does not provide and which a pull request cannot grant itself.

The immediate occasion is the accepted cron precondition gate in [#5607](https://github.com/zeroclaw-labs/zeroclaw/issues/5607), which adds a new security-relevant command-execution path to `crates/zeroclaw-runtime/src/cron`. Review correctly identified the placement as a contract violation and correctly declined to let the pull request waive the instruction for itself. The occasion is specific; the problem is not. Any future cron change faces the same wall.

The alternatives are to require extraction before any further cron work, to relax the holding-crate instruction generally, or to record the extraction as the committed target and grant a narrow, expiring exception for work that lands before it.

## Decision

We will extract cron into a dedicated `zeroclaw-cron` crate, and we grant a bounded exception for cron work that lands before that extraction completes.

### The target owner

`zeroclaw-cron` owns scheduling and job lifecycle: schedule parsing and next-run computation, the job and run store, declarative reconciliation against config, in-flight claim ownership, execution outcome classification, run history, and precondition evaluation.

It does not own agent execution, security policy construction, channel delivery, or configuration schema. It depends on those through existing contracts rather than absorbing them. The security policy that authorizes a cron command remains owned by the security layer and is resolved, not reimplemented.

### The exception, and its limits

Until `zeroclaw-cron` exists, cron changes may land in `crates/zeroclaw-runtime/src/cron` under these conditions, all of which must hold:

1. The change is confined to `crates/zeroclaw-runtime/src/cron` and its tests, plus whatever config schema and caller updates it strictly requires.
2. The change does not add a new dependency from cron onto another subsystem that the extracted crate would then have to break.
3. The change references this record, so the extraction issue can enumerate what must move.
4. The exception expires when `zeroclaw-cron` lands, or when the Core Team withdraws it, whichever comes first.

This exception is deliberately narrow. It permits continuing work on a subsystem that already lives in the holding crate. It does not permit adding new subsystems there, and it does not generalize to the other subsystems the holding-crate contract names.

### The obligation attached to it

The exception is granted against [#10546](https://github.com/zeroclaw-labs/zeroclaw/issues/10546), a tracked extraction with acceptance criteria, not against an intention. If that issue is closed without extraction, or goes stale, the exception lapses and cron work returns to being blocked on extraction.

## Consequences

Cron work stops being blocked on a crate that does not exist, and stops silently deepening the holding crate without a record. The cost is carried explicitly: every change landing under this exception adds to what the extraction must move, and the extraction issue is where that debt is counted.

The holding-crate contract keeps its force for every other subsystem it names. This record does not weaken it; it supplies the exception process the contract lacked, scoped to one subsystem and one deadline.

The extraction itself gets harder in proportion to how long the exception runs. That is the intended pressure. The exception is uncomfortable on purpose, so that it ends.

## Acceptance

ADR-016 remains proposed until all of the following hold:

- `zeroclaw-cron` exists and owns the scheduler, store, schedule parsing, declarative reconciliation, claim ownership, outcome classification, and precondition evaluation.
- `crates/zeroclaw-runtime/src/cron` is gone, not merely re-exported.
- The cron crate depends on security policy, config, and delivery through their existing contracts, and none of those depends on cron.
- `crates/zeroclaw-runtime/AGENTS.md` no longer names cron as awaiting extraction.
- [#10546](https://github.com/zeroclaw-labs/zeroclaw/issues/10546) is closed by the extraction, not by expiry.
