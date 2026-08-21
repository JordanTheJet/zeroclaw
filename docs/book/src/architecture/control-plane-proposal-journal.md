# Design: durable proposal journal and crash recovery

> **Status: proposed.** Nothing on this page is implemented. There is no
> proposal journal, no transaction worker, and no control-plane recovery service
> anywhere on `master`. This page describes what phase 5 of the parent
> architecture would have to build in order to be reviewable. It is not an
> accepted design and it does not authorize implementation.

This page is subordinate to
`docs/book/src/architecture/chat-management-control-plane.md`, which is itself
marked proposed and currently lives on an unmerged documentation branch rather
than on `master`. Where the parent document already states a rule, this page
cites it and refines the mechanism. It never restates a parent rule more
loosely and never introduces a path by which an unapproved change reaches disk.
If the two disagree, the parent document wins and this page is wrong.

## Scope

The parent document's phased delivery defines phase 5 as:

> 5\. **Durable approval-backed apply.** Add the proposal/transaction journal,
> source and dependency locking, approval consumption, crash recovery,
> status, and verification.

Phase 5 depends on phases 3 and 4 having landed. The principal model, client
registration, and approval receipts that this page consumes are designed in
`control-plane-principals-and-approvals.md`. The genesis record and trust epoch
that scope the journal are designed in `control-plane-trust-genesis.md`. The
read-only wire surface that predates all of this is specified in
`control-plane-mcp-protocol-v1.md`, which deliberately exposes no Status tool
because no journal exists at that phase.

## Where the journal lives

The journal database lives under the registered instance data root and is
covered by the target registry's ownership, permission, symlink, and
trust-epoch checks. It is not a file a requester can name, open, or reach: no
tool accepts an arbitrary target path, and the stdio process pins its config and
data roots at startup.

The control-plane crate is named `zeroclaw-control`. That name is staged,
unmerged work; no such crate exists under `crates/` on `master`, and neither
does any journal schema.

## The journal state machine

Reproduced verbatim from the parent document, because every rule below is
defined in terms of these exact state names:

```text
prepared -> awaiting_approval -> approved -> applying -> applied -> verified
                |-> rejected         |          |-> failed
                |-> expired          |          |-> recovery_required
```

Status uses these names. It may add bounded progress details but does not
collapse `approved`, `applying`, or `recovery_required` into a generic pending
result. That rule exists so an operator can always tell the difference between
"nothing has happened yet", "a receipt has been consumed and work is in
flight", and "a human must resolve this".

### State definitions

| State | Meaning | Entered by | Durable facts at entry |
|---|---|---|---|
| `prepared` | An immutable proposal exists and is bound to its target, revision, requester, payload digest, dependencies, effects, and expiration | A successful Request apply | Proposal, owner binding, dependency digest, expiration |
| `awaiting_approval` | The proposal has been presented to an eligible operator backchannel | The broker presenting a fresh challenge | Challenge binding and operator eligibility evaluation |
| `rejected` | An operator decided against it | An authenticated reject decision | The rejection receipt. A rejection is a recorded fact, not an absence |
| `expired` | A binding fact changed or the deadline passed before a decision | Expiration evaluation | Reason for expiry |
| `approved` | A valid receipt exists and has been recorded, but not consumed | The broker recording a valid receipt and the transition in one durable journal transaction | Receipt, unconsumed |
| `applying` | The receipt has been consumed and effects are being written | The atomic claim described below | Receipt consumed, apply order, pre-images |
| `applied` | Every declared effect reached its expected post-image | Successful completion of the recorded apply order | Post-image digests |
| `verified` | The verification plan confirmed effective runtime state | Successful verification | Verification results |
| `failed` | Apply stopped with every effect classified and any rollback artifact applied | A classified failure during `applying` | Classification per effect |
| `recovery_required` | At least one effect could not be classified, or an ambiguity survived recovery | Interruption or an ambiguous classification | Everything known, plus the unclassified effect list |

`prepared` and `awaiting_approval` are the only states a requester's own action
can create. Every transition from `approved` onward is performed by the host
transaction worker or the recovery service. There is no model-callable Finalize
operation, and no requester-facing tool accepts a receipt.

## Request apply and durable parking

Conversational drafts may remain process-local. Once Request apply succeeds,
the immutable proposal, owner binding, dependency digest, and expiration are
durable.

The proposal is immutable and bound to:

- target instance identity and pinned roots;
- exact source-config revision;
- registered requester identity, client session attribution, and owner token;
- canonical operation payload and digest;
- host-derived dependency set and pinned external facts;
- declared effects and verification plan; and
- expiration time.

Isolation rules for parked proposals:

- persisted proposals are not enumerable across owners;
- an opaque client resume secret can access only one proposal bound to the same
  registered client or native agent identity;
- the store keeps only the verifier for that resume secret, never the secret;
- relaunching stdio requires both the client credential and the resume secret;
  and
- neither conveys approval authority, and both expire with the proposal.

Read-only mode refuses Request apply and creates no parked proposal. That is a
hard behavioral boundary, not a filtered response: nothing durable is written.

## The atomic approved to applying claim

This is the single most safety-critical transition in the design, because it is
where an authorization becomes an irrevocable licence to write. The parent
document specifies it as an ordered sequence, reproduced here because the
ordering is the property:

Before entering `applying`, the host:

1. acquires the exclusive instance config and transaction lock;
2. re-reads the source revision and framework-derived dependencies;
3. verifies every pinned external fact represented in the preview;
4. starts one journal-database transaction;
5. verifies and consumes the approval receipt while changing `approved` to
   `applying`; and
6. commits and syncs that transaction before changing config.

### Why each step is where it is

- **Step 1 first** because everything after it must observe a config and
  journal state no other writer can move. The config lock must reject concurrent
  apply and root-selection races.
- **Steps 2 and 3 before the transaction** because they can fail for ordinary
  reasons, and a proposal whose source revision, dependency set, provider
  target, plugin package, OAuth scope set, endpoint identity, policy, or other
  previewed fact has changed must expire rather than apply. The instance
  fingerprint is recomputed under lock here, so replacing a registered root or
  redirecting it through a symlink expires the proposal.
- **Step 5 inside the transaction** because receipt consumption and the
  `applying` record must be one atomic durable fact. If they were two facts, a
  crash between them would either lose a receipt or leave one consumable twice.
- **Step 6 before any config change** because the journal must be ahead of the
  filesystem at all times. A journal that trails the config cannot classify what
  happened.

### The two crash windows

The parent document states the outcome of each window, and the recovery service
implements exactly these two readings and no third:

| Crash point | Durable state | Receipt | Recovery action |
|---|---|---|---|
| Before the step 6 commit | `approved` | Unconsumed | The operation has not begun. It may proceed later under the same receipt if nothing else expired it |
| After the step 6 commit | `applying` | Consumed | The recovery service is authorized to continue or classify **only that exact operation** |

The phrase "only that exact operation" is a scope limit on the recovery
service, not a convenience. The recovery service can resume or classify an
already-authorized journal entry and can never approve a new proposal. It
cannot generalize a consumed receipt to a similar operation, a retried
operation, or a re-derived operation.

A terminal or recovery outcome is durable before another request with the same
operation identifier can proceed. Reverting an applied change does not make its
approval reusable.

## Per-effect-artifact classification

The config commit uses the existing expected-source transaction and records the
expected post-image digest. Because a config-file rename and a journal update
cannot be one filesystem transaction, restart recovery compares the current
config digest with the recorded pre-image and post-image.

The parent document extends this rule beyond `config.toml`:

> The same rule covers every declared effect artifact, not only `config.toml`.
> An adapter records pre-state, expected post-state, and rollback or
> classification logic for plugin bytes, personality files, credential-store
> entries, service state, and other durable effects.

### What each effect records

Every declared effect in a proposal carries, before `applying` begins:

| Field | Contents |
|---|---|
| `effect_id` | Stable identifier, referenced by the recorded apply order |
| `artifact_kind` | `config`, `plugin_bytes`, `personality_file`, `credential_store_entry`, `service_state`, or another declared kind |
| `pre_image` | Digest or equivalent identity of the artifact before apply |
| `expected_post_image` | Digest or equivalent identity the artifact must have after apply |
| `rollback_artifact` | The recoverable snapshot, or an explicit declaration of why no rollback artifact is possible |
| `classifier` | The adapter-provided logic that maps an observed artifact state to one of the three classifications below |
| `reversible` | Whether the effect can be undone without a new approval |
| `irreversible_external` | Whether the effect has an irreversible external side effect |

Apply ordering is recorded in the journal before the first effect is written,
so recovery knows which effects should have been attempted and in what order.

### The three classifications

For each effect, recovery observes the current artifact and classifies it as
exactly one of:

| Classification | Observation | Consequence |
|---|---|---|
| Not applied | The artifact matches its recorded pre-image | The effect did not happen. It may be attempted under the existing consumed receipt as part of continuing that same operation |
| Applied but not verified | The artifact matches its recorded expected post-image | The effect happened. It must not be repeated. Verification still owes an answer about effective runtime state |
| Ambiguous | The artifact matches neither image | Nothing may be inferred. The whole operation parks in `recovery_required` |

Recovery never blindly repeats a mutation. That is the rule the classification
exists to enforce: an effect is repeated only when the artifact positively
matches its pre-image, never because a repeat "should be idempotent".

### Operation-level rules

- If any effect cannot be classified after interruption, the **whole** operation
  parks in `recovery_required`. Classification is not per-effect independent
  when one effect fails to classify.
- Recovery does not infer success from the config digest alone. A matching
  config post-image says nothing about plugin bytes, a personality file, a
  credential-store entry, or service state.
- Irreversible external side effects are identified in the preview and cannot
  occur before approval. An adapter that cannot honor that ordering cannot
  declare the effect.
- Operations that remove or replace state must create a recoverable snapshot or
  declare why no rollback artifact is possible, and the approval text identifies
  that difference. An operator approving an unrollbackable change must be told
  so at decision time.

## The `recovery_required` parking rule

An operation parks in `recovery_required` when any of the following holds:

1. an effect classification is ambiguous, meaning the artifact matches neither
   its pre-image nor its expected post-image;
2. an effect cannot be classified at all, for example because its artifact is
   unreadable or its classifier cannot run;
3. the apply order recorded in the journal cannot be reconciled with the
   observed artifact states; or
4. an audit-chain gap, rewrite, invalid tag, or unexpected trust-epoch value is
   detected while the entry is in flight. That condition disables mutations and
   enters recovery independently.

Parking rules:

- `recovery_required` is a parked state awaiting operator resolution, not a
  retry state. The recovery service does not exit it on its own, does not retry
  on a timer, and does not escalate to a repeat of the mutation.
- Status reports `recovery_required` by name and never collapses it into a
  generic pending result.
- The consumed receipt stays consumed. Parking does not restore approval
  authority and does not make the receipt reusable.
- Another request with the same operation identifier cannot proceed until a
  terminal or recovery outcome is durable.

The parent document says the ambiguous case parks "for operator resolution" but
does not define the resolution transition itself. That gap is recorded in "Open
questions" rather than invented here.

## Expiration and clock rules

Proposal, receipt, and resume-secret expiration use a server wall-clock
timestamp plus a monotonic deadline while the process remains alive. After a
restart, clock rollback or an ambiguous time source expires the credential
rather than extending it.

Derived rules:

- **Both bounds apply while the process lives.** The earlier of the wall-clock
  expiry and the monotonic deadline wins. A wall-clock jump forward cannot be
  used to extend a monotonic deadline, and a monotonic deadline cannot extend a
  passed wall-clock expiry.
- **Restart discards the monotonic bound.** A monotonic clock is meaningless
  across a restart, so after restart only the wall-clock timestamp remains, and
  it is evaluated against a clock that must be trusted before it is used.
- **Ambiguity expires, never extends.** Clock rollback, an unsynchronized
  source, or any state the host cannot resolve into a trustworthy current time
  expires the affected proposal, receipt, and resume secret.
- **Expiration is host-evaluated.** No client-supplied timestamp, no
  `server_time` value previously returned to a client, and no
  backchannel-supplied time participates in the decision.
- **Fact changes expire independently of the clock.** If the source revision,
  dependency set, provider target, plugin package, OAuth scope set, endpoint
  identity, policy, capability digest, instance fingerprint, or other previewed
  fact changes before apply, the proposal expires regardless of remaining time,
  and the caller must request a new preview.
- **Health observations are never frozen.** Observations that cannot be frozen
  are labeled as observations and repeated during verification, rather than
  presented as apply-time guarantees.

Wall-clock rollback, restart ambiguity, and expired resume credentials must
never extend a proposal or receipt lifetime, and CI must prove it.

## Per-requester quotas

Each requester has bounded prepared and awaiting-approval quotas, request rate,
and total parked bytes.

| Quota | Bounds | Notes |
|---|---|---|
| `prepared` entries | Maximum concurrent entries in `prepared` | Counted per requester principal, not per session |
| `awaiting_approval` entries | Maximum concurrent entries in `awaiting_approval` | Prevents one requester flooding an operator backchannel |
| Request rate | Requests per interval | Applies to Request apply specifically, separately from read operations |
| Parked bytes | Total durable bytes attributable to the requester | Bounds journal growth including proposals, effect metadata, and pre-images |

Enforcement rules, stated by the parent document and normative here:

- exceeding a quota **refuses a new proposal**;
- refusal must not evict another client's state. There is no eviction policy
  that lets a noisy requester displace a quiet one; and
- refusal must not generate operator notifications. A quota refusal is a
  requester-facing error, not an approval prompt. Otherwise a requester could
  manufacture operator attention at will.

Two further rules follow from the isolation properties elsewhere in this design
and are stated so an implementer does not have to infer them:

- quota accounting is per requester principal and must not disclose another
  requester's usage, which would violate the rule that persisted proposals are
  not enumerable across owners; and
- a quota refusal is not an expiry. It leaves existing entries untouched and
  does not consume, invalidate, or reorder them.

## Status reporting

Status reports the exact durable transaction state and bounded progress. It
performs no host effect and reads no secret.

- It uses the journal state names above, verbatim.
- It may add bounded progress details, for example how many declared effects
  have reached their expected post-image.
- It does not collapse `approved`, `applying`, or `recovery_required` into a
  generic pending result.
- It is scoped to the caller's own proposal. One client cannot access another
  client's pending proposal, and Status is not an enumeration surface.
- It discloses no path, no secret, no raw provider error body, and no fact about
  another registered target.

Verify performs verification reads and confirms effective state with bounded
diagnostics. Verification must detect partial or ineffective configuration
rather than trusting that a successful write implies a successful effect.

## Verification gates for phase 5

A phase-5 implementation is reviewable only when these behavior-boundary tests
pass. They are the subset of the parent document's required verification list
that this design owns:

- crash injection before and after every journal and config write produces a
  deterministic recoverable outcome and never repeats a mutation blindly;
- crash injection covers plugin, credential, personality, service, and other
  declared effect artifacts as well as config;
- crash injection around the atomic `approved` to `applying` claim leaves
  exactly one durable state and never loses or double-consumes a receipt;
- the config lock rejects concurrent apply and root-selection races;
- daemon and exclusive local-host modes produce the same inventory, preview,
  authorization, journal, and verification result;
- concurrent daemon and local-host startup leaves exactly one lock owner;
- stale source revisions and expired proposals fail before mutation;
- one client cannot access another client's pending proposal;
- wall-clock rollback, restart ambiguity, and expired resume credentials never
  extend a proposal or receipt lifetime;
- audit-chain gaps, rewrites, invalid tags, and trust-epoch mismatches disable
  mutation;
- verification detects partial or ineffective configuration; and
- read-only mode refuses Request apply and creates no parked proposal.

## Open questions

These are gaps or ambiguities in the parent architecture document. They are
recorded for the maintainer to settle and are deliberately not resolved here.

1. **The state machine has no verification-failure state.** The diagram ends
   `applied -> verified` with no transition out of `verified` or out of
   `applied` when verification fails. The required verification list separately
   demands that "verification detects partial or ineffective configuration". If
   verification detects an ineffective apply, the entry has nowhere to go: it is
   not `failed`, because apply succeeded; it is not `verified`; and
   `recovery_required` is defined for classification ambiguity rather than for a
   confirmed-but-ineffective result. A `verification_failed` state, or an
   explicit rule routing that case into `recovery_required`, appears to be
   missing.
2. **`recovery_required` has no defined exit.** The parent document says an
   ambiguous result "parks in `recovery_required` for operator resolution" but
   never defines what operator resolution is. It is unclear whether resolution
   is a meta-authority operation, whether it consumes a new receipt, which
   states it may transition to, and whether an operator may declare an
   ambiguous effect applied or not applied on their own judgement. Without that,
   an implementation has a state it can enter and never leave.
3. **`owner token` is undefined.** The proposal binding set includes "registered
   requester identity, client session attribution, and owner token", but `owner
   token` appears nowhere else in the parent document. It is unclear whether it
   is the resume secret, a distinct value, or a synonym for the registration
   identifier. It cannot be implemented as written. This gap is also recorded in
   `control-plane-principals-and-approvals.md`.
4. **"Ambiguous time source" is not defined.** The clock rule says an ambiguous
   time source expires a credential, but does not say what makes a source
   ambiguous. Candidate signals include an unsynchronized system clock, a
   backwards step since the last recorded journal timestamp, or a first boot
   with no reliable time. Which of these the host must detect, and with what,
   determines whether this rule is testable.
5. **Quota interaction with recovery and epoch change.** Recovery invalidates
   all pending proposals, client credentials, approval receipts, and resume
   secrets. The parent document does not say whether parked-byte and entry
   quotas are released at that moment, nor how quota is accounted for a
   requester whose grant collapsed while entries remain parked.
6. **Draft durability is an open decision with a quota consequence.** The parent
   document lists "whether pre-review conversational drafts survive restart" as
   an open decision while stating that parked mutation proposals are durable
   regardless. If drafts later become durable, they acquire per-client durable
   state and must be brought under the quota rules above; otherwise drafts
   become an unbounded write path that bypasses the Request apply quota.
7. **Rejection retention.** A rejection is a durable state, but the parent
   document does not say how long a `rejected` or `expired` entry is retained,
   whether it counts against quota, or whether a requester may resubmit an
   identical proposal immediately after rejection. Without a rule, a requester
   can re-prompt an operator indefinitely with the same operation.

## Governance status

This page is a proposal. The parent document states that the control plane
requires an accepted RFC before the mutating surface is treated as an
implementation detail, and that changes to approval authority, principal
assurance, plugin trust, or the stable control protocol require the matching
architecture decision or foundation amendment. No RFC has been accepted for this
work, and no architecture decision record covers the control-plane journal.
Publishing this page does not authorize implementation and must not be cited as
evidence that the design is accepted.
