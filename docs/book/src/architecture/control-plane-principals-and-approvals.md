# Design: control-plane principals, client registration, and approval receipts

> **Status: accepted** (maintainer decision, 2026-08-22; remaining open questions are tracked on the fork issue #26). Nothing on this page is implemented. There is no
> control-plane principal model, no client registration ceremony, and no
> approval receipt anywhere on `master`. This page describes what phases 3 and 4
> of the parent architecture would have to build in order to be reviewable. It
> is not an accepted design and it does not authorize implementation.

This page is subordinate to
`docs/book/src/architecture/chat-management-control-plane.md`, which is itself
marked proposed and currently lives on an unmerged documentation branch rather
than on `master`. Where the parent document already states a rule, this page
cites it and refines the mechanism. It never restates a parent rule more
loosely, never grants a capability the parent withholds, and never introduces a
path by which a requester could approve its own proposal. If the two disagree,
the parent document wins and this page is wrong.

## Scope

The parent document's phased delivery defines the two phases covered here:

> 3\. **Trust genesis and registration.** Add genesis, trust epochs, host and
> operator keys, external client registration, target registry, approved
> creation parents, and recovery entry points.
>
> 4\. **Principal and approval contract.** Add requester principal classes,
> high-assurance operator authentication, signed single-use approval
> receipts, backchannel reachability checks, meta-authority rules, and
> native/MCP authorization parity. No mutating tool exists before this phase
> passes its adversarial gates.

This page covers the principal model, the client registration record, the
credential-delivery assurance classes, approval receipts, operator backchannel
eligibility, and the permanently meta-authority operation set. Genesis and
recovery ceremonies themselves are designed in
`control-plane-trust-genesis.md`. The journal that consumes a receipt is
designed in `control-plane-proposal-journal.md`. The read-only wire surface is
specified in `control-plane-mcp-protocol-v1.md`.

## Foundations that exist on `master`

These four are verified present on `master` and are the only load-bearing
existing work this design builds on. Everything else is new construction.

| Foundation | Where | What it actually provides today |
|---|---|---|
| `KeySource` trait extraction, PR #9194, commit `b8489219e` (`feat(secrets): extract KeySource trait + FileKeySource backend`) | `crates/zeroclaw-config/src/secrets.rs` | `trait KeySource`, `FileKeySource`, `ProvisioningState`, and `SecretStore::from_key_source`. The trait exists but `SecretStore` is still its only consumer |
| ADR-013, PR #9361, commit `5df637ca1` (`docs(architecture): record key-source authority`) | `docs/book/src/architecture/decisions/ADR-013-key-source-authority.md` | The proposed rule that master key acquisition uses one configured key-source authority, resolved from typed `Config` and constructed once per process generation |
| Shared egress policy foundation, PR #9137, commit `0db7d999a` (`feat(plugins): add shared egress policy foundation`) | `crates/zeroclaw-plugins/src/egress.rs`, `crates/zeroclaw-infra/src/net_guard.rs` | `EgressPolicy`, `EgressPolicyResolver`, `EgressHostService`, and the shared host and address classification primitives |
| Typed plugin instance config validation, PR #9126, commit `78a801adb` (`feat(plugins): validate typed instance config`) | `crates/zeroclaw-plugins/src/config.rs` | Manifest-declared Draft 2020-12 `config_schema`, `validate_manifest_config`, `resolve_plugin_config`, and bounded admission limits |

The control-plane crate is named `zeroclaw-control`. That name is staged,
unmerged work: no such crate exists under `crates/` on `master`, and no
`zeroclaw control` subcommand exists either.

### What ADR-013 constrains here

ADR-013 is directly load bearing for approval receipts, because the receipt is
authenticated by a host key. Two of its recorded rules constrain this design:

- Key acquisition is owned by the `KeySource` boundary, one configured source is
  authoritative for a deployment at a time, and the assembly layer constructs
  one shared source authority per process generation. A consumer may not
  reconstruct an authority or read backend material directly.
- Scoped and derived key access is explicitly deferred: whether a
  non-encryption consumer receives scoped access or a derived subkey is
  recorded as a separate security decision, and until that decision exists "a
  non-encryption consumer must not silently reuse the raw encryption master
  key".

`deployment` in that first rule means the canonical install root: the
config-root and data-root pair that a genesis record names. Each instance root
is its own deployment and therefore its own key authority, so a child instance
on the same host holds its own authority instead of sharing its parent's. The
maintainer decided this on 2026-08-22 in
[issue #26](https://github.com/JordanTheJet/zeroclaw/issues/26#issuecomment-5383167800);
`control-plane-trust-genesis.md` carries the definition and its consequences.

The approval and audit key is a non-encryption consumer, so ADR-013 did not
authorize the control plane to obtain it until the deferred derivation decision
was made. That decision now exists. The maintainer decided on 2026-08-21 in
[issue #24](https://github.com/JordanTheJet/zeroclaw/issues/24#issuecomment-5376601651)
that the approval and audit key is an HKDF-SHA256 subkey derived from the single
ADR-013 authority, under the fixed domain-separation label
`zeroclaw/control-plane/approval-audit/v1`. It is never exportable and is
exposed only through sign and verify operations, which is what lets the broker
authenticate a receipt with a key the requester surface cannot read. Rotating
the master key re-derives, and therefore rotates, the approval key; that
tradeoff is accepted. The decision record is drafted as
`docs/book/src/architecture/decisions/ADR-015-control-plane-approval-audit-key.md`
on the `docs/control-plane-decision-drafts` branch.

ADR-013 also records that configured-source acquisition failure "must not
implicitly select unsigned TUI identity" and must fail closed. The same posture
applies here: if the approval and audit key source cannot be acquired,
mutations are unavailable. The host must not fall back to a weaker approval
mode, an unsigned receipt, or a locally generated replacement key.

## Principal classes

The parent document defines exactly four principal classes. They are reproduced
here because the whole authorization model depends on them, with one deliberate
correction noted immediately below the table:

| Principal class | Source | Authority |
|---|---|---|
| Agent requester | Runtime-derived agent identity | Inspect, propose, and request review only when granted; never approve |
| External requester | Registered MCP client identity | Inspect, propose, and request review only within its grant; never approve |
| Operator | Paired or user-presence-authenticated human identity | Approve within configured policy |
| Recovery service | Host startup recovery worker | Resume or classify an already-authorized journal entry; never approve a new proposal |

The table reproduces the parent document with one deliberate correction, made so
that no implementer reads an omission as permission: the agent-requester row
carries the explicit "never approve" clause that the parent document states only
on the external-requester row. No principal type in a requester class can
approve, which non-escalation rule 5 already states normatively. The parent
document should be amended to match. Adopted from the gap-sweep resolution
proposed in [issue #26](https://github.com/JordanTheJet/zeroclaw/issues/26),
item 3.

There is no fifth class. In particular there is no "local", "trusted", "admin",
"root", or "same-user" class, and no class that a process acquires by how it was
started.

### Classification inputs

A principal's class is derived by the host from facts the caller cannot choose:

- an **agent requester** is classified from the runtime-derived agent identity
  inside the daemon process. It is not a string the caller supplies;
- an **external requester** is classified from a registered client credential
  verified through the challenge exchange described in the parent document. The
  client-supplied registration identifier is attribution only;
- an **operator** is produced only by a trusted transport or OS user-presence
  adapter that emits an authentication assurance level. A client body, MCP
  argument, environment variable, loopback connection, TTY, process parent, or
  same-UID status cannot choose that level; and
- the **recovery service** is the host startup worker. It has no external entry
  point.

### Non-escalation rules

These rules are normative for the implementation. Each one traces to a
statement in the parent document.

1. **Transport provenance is not authentication.** Launching the stdio command
   does not create an operator principal. A TTY, loopback address, process
   parent, or same-UID check is insufficient by itself to approve a mutation.
2. **Shell launch does not upgrade a class.** An agent that invokes the stdio
   binary through shell is still only an external requester and cannot turn
   process launch into an approval.
3. **A self-launched unregistered server gets nothing.** It receives no
   inventory, proposal, or review tools; parent process, same UID, loopback,
   and environment variables never upgrade it.
4. **The approver is always distinct from the requester.** `ControlService`
   requests approval from an authenticated operator principal that is distinct
   from the requester. There is no configuration, grant, quorum setting, or
   deployment mode in which a requester approves its own proposal.
5. **Requester classes never approve.** Neither an agent requester nor an
   external requester can submit an approval decision, on any transport. Native
   and MCP transports create requester principals only.
6. **Authorization is an intersection, never a union.** Effective authority is
   the intersection of the requester grant, current policy, target
   registration, and operation class. A requester denied Inspect or Propose
   natively remains denied through MCP.
7. **Credential reachability collapses a grant.** The effective grant is
   intersected with every principal that can reach the credential, and one
   reachable ungranted principal collapses it to no configured-state access. An
   agent that can resolve a registered client's credential gains no authority
   from the claimed client name.
8. **Adapters have no authority over the framework.** An adapter cannot
   classify approval, mint principals, consume receipts, or change the
   framework's operation tier.
9. **There is no model-callable finalize.** A model cannot satisfy approval by
   passing `approved: true`, replaying a nonce, calling a second tool, or
   invoking a different transport.
10. **The recovery service never approves.** It may resume or classify an
    already-authorized journal entry only. It cannot authorize a new proposal,
    mint a receipt, or re-consume a consumed one.
11. **A requester cannot reach the trust root.** A requester cannot run
    genesis, replace its trust epoch, register a client, register a target, or
    approve a creation parent.
12. **Capability changes are not retroactive.** Existing sessions do not
    silently gain capabilities after config apply. Restart and reload semantics
    remain explicit.
13. **Meta-authority cannot be declassified.** Meta-authority changes always
    use the strongest confirmation tier and can never be placed in a
    no-approval class, including by a later adapter, policy value, or protocol
    minor version.

Rule 4 and rule 13 together are the property the adversarial gates in phase 4
must prove. Any proposed mechanism that appears to create an exception to
either is a design error, not a configuration option.

## Requester grants

Native agent grants and external client grants compile to the same
`ControlRequesterGrant`. A single type is deliberate: it is what makes native
and MCP authorization parity testable rather than aspirational.

A grant carries:

| Field | Meaning |
|---|---|
| `grant_id` | Stable identifier for the grant record |
| `subject` | Either a runtime-derived agent identity or a registration identifier |
| `target_ids` | Explicit registered instances. Never a wildcard, never a path |
| `read_domains` | Explicit Inspect view identifiers |
| `proposal_domains` | Explicit operation domains the subject may propose |
| `trust_epoch` | The epoch under which the grant was issued |
| `assurance_class` | For external subjects, the credential delivery assurance class |
| `status` | `active`, `suspended`, or `revoked` |
| `issued_by` | Digest of the meta-authority operation that created or last widened the grant |

A grant never carries an approval capability, an operator identity, a key
reference, or a path. Approval authority is not a field that could be set to
true; it is structurally absent from the type.

Authorization for a request resolves in this order, failing closed at the first
step that does not permit the request:

1. classify the principal;
2. resolve the grant for that principal under the current trust epoch;
3. intersect with current policy;
4. intersect with target registration for the requested target ID;
5. intersect with the operation class of the requested operation; and
6. apply the credential reachability collapse from rule 7.

Step 6 runs last on purpose. A grant that looks broad in its record can still
resolve to nothing once reachability is evaluated, and the audit record must
show both the recorded grant and the effective grant so an operator can see why
a request was refused.

## Client registration

An external MCP client must present a client credential created by an operator
registration ceremony. The credential identifies a client and grants explicit
instances, read domains, and proposal domains. It never grants approval.

Registration is a meta-authority operation, as are grant widening, revocation,
and credential rotation.

Meta-authority operations consume an approval receipt issued under the existing
trust epoch, and the receipt broker arrives in phase 4, so the first client
cannot be registered that way in phase 3. The maintainer decided on 2026-08-21
in
[issue #25](https://github.com/JordanTheJet/zeroclaw/issues/25#issuecomment-5376560807)
that the genesis and mutation-enablement ceremony may register the first client
or clients receipt-exempt, as a minimal bounded exception that closes when
mutation enablement completes. The bounds are specified in
`control-plane-trust-genesis.md` under "Bootstrap client registration", and the
decision record is drafted as
`docs/book/src/architecture/decisions/ADR-016-control-plane-registration-bootstrap.md`
on the `docs/control-plane-decision-drafts` branch.

Three consequences are normative here. A bootstrap-registered client receives no
approval authority, exactly like every other registered client. Any registration
attempted outside the ceremony requires a receipt and fails closed with a
"receipt broker not present" refusal until phase 4 exists. After mutation
enablement no registration is receipt-exempt at all.

### Registration record contents

| Field | Contents | Notes |
|---|---|---|
| `registration_id` | Stable opaque identifier | Appears in audit attribution. Not a credential |
| `client_label` | Human-readable client name | Display and attribution only. Never authoritative for authorization |
| `credential_verifier` | Verifier material only | The host stores a verifier, never the credential itself |
| `assurance_class` | `isolated_descriptor`, `sandbox_isolated_store`, or `uid_ambient` | See the next section |
| `delivery_mechanism` | Identity of the approved credential helper or the inherited-descriptor contract | Records how the credential reaches the client, so reachability can be re-evaluated |
| `target_ids` | Explicit registered instance IDs | No wildcard, no path |
| `read_domains` | Explicit Inspect view identifiers | Minimum required disclosure per operation |
| `proposal_domains` | Explicit operation domains | Proposing is not approving |
| `approval_authority` | Structurally absent | There is no field whose value could grant approval |
| `trust_epoch` | Epoch at issuance | Recovery invalidates credentials issued under a prior epoch |
| `rotation_generation` | Monotonic counter | Incremented by a meta-authority rotation |
| `created_by` | Digest of the approving meta-authority operation | Links the record to the receipt that authorized it. For a bootstrap registration made inside the genesis or mutation-enablement ceremony, it is the ceremony operation digest instead, because no receipt exists yet |
| `created_at`, `not_after` | Wall-clock bounds | Subject to the clock rules in the journal design |
| `status` | `active`, `suspended`, or `revoked` | Revocation is immediate and fails closed |
| `reachability_evaluation` | Timestamp, sandbox policy digest, enumerated reachable principals, and the resulting effective collapse | Re-evaluated on the triggers below |
| `audit_anchor` | Audit chain sequence of the registration row | Makes the record independently verifiable |

The record contains no absolute path to the credential store, no socket path,
and no key material. Those live outside every agent sandbox root and are never
disclosed through a requester-facing surface.

### Credential delivery assurance classes

The parent document defines exactly three classes:

- **isolated descriptor:** a supervising client passes the credential through an
  inherited descriptor unavailable to agent subprocesses;
- **sandbox-isolated store:** an approved helper reads a credential from a
  client store outside every enforced agent sandbox root; or
- **UID-ambient:** another process under the same OS account may obtain it.

The release rules are equally explicit and are not negotiable by configuration:

| Class | Inspect | Propose | Request apply | Configured-state tools |
|---|---|---|---|---|
| `isolated_descriptor` | Permitted within grant | Permitted within grant | Permitted within grant | Yes |
| `sandbox_isolated_store` | Permitted within grant | Permitted within grant | Permitted within grant | Yes |
| `uid_ambient` | Refused | Refused | Refused | None |

A host cannot classify a store as sandbox-isolated while any shell-capable
agent runs without an enforced sandbox that excludes the store and the control
socket. Classification is a proof obligation on the host, not a label the
operator can assert. If the host cannot prove that separation, the client
remains unregistered and the stdio endpoint exposes exactly Initialize, Ping,
ServerInfo, and RegistrationHelp.

Credential material is obtained by the stdio proxy through an approved
client-specific credential helper or an inherited descriptor. It is never
obtained from a command-line argument, an ordinary environment variable, a
prompt, or a model-visible config value.

### Re-evaluation triggers

Delivery assurance participates in requester reachability, authorization, and
audit attribution, and is re-evaluated when any of the following changes:

- an agent sandbox definition or its enforced roots;
- a shell grant held by any agent on the instance;
- an approved client helper, its executable identity, or its invocation
  contract; or
- a credential location.

Re-evaluation is a host action, not a client request. A client cannot trigger,
suppress, or observe the outcome beyond discovering that its own effective
grant changed.

A re-evaluation can collapse an effective grant to nothing. At the moment of
collapse the host expires that client's parked proposals, expires its issued but
unconsumed approval receipts, and aborts its in-flight applies that have not yet
passed the atomic receipt-consumption commit described in
`control-plane-proposal-journal.md`. A client keeps no authority it has just
lost, and letting outstanding state proceed on a collapsed grant would be
exactly that. Adopted from the gap-sweep resolution proposed in
[issue #26](https://github.com/JordanTheJet/zeroclaw/issues/26), item 7.

What happens to an operation that is already past that commit, so the receipt is
consumed and the entry is `applying` or later, is a separate question and is
still open. See open question 7.

## Approval receipts

The broker emits a single-use authenticated approval receipt. The parent
document fixes the binding set:

> An approval receipt is single-use and bound to the proposal digest, target
> instance, source revision, operator principal, decision, and expiration. The
> broker signs or authenticates it with a host key source unavailable to the
> requester tool surface.

### Binding fields

| Field | Bound value | Why it is bound |
|---|---|---|
| `proposal_digest` | Canonical digest of the immutable proposal | A receipt for one proposal cannot authorize a different one, including a re-serialized or semantically equivalent one |
| `target_instance` | Target ID plus the instance fingerprint recomputed under lock | Replacing a registered root or redirecting it through a symlink expires the proposal, so a receipt cannot follow the move |
| `source_revision` | Exact source-config revision the preview was computed against | A stale receipt cannot apply to a config that changed underneath it |
| `operator_principal` | The authenticated operator identity that decided | Attribution is not optional and the identity is verified, not asserted |
| `decision` | The explicit decision value | Approve and reject are both receipts. A rejection is a durable fact, not an absence |
| `expiration` | Wall-clock expiry plus the monotonic deadline rules | Expiry fails closed, and clock rollback shortens rather than extends validity |

The implementation should additionally bind, without weakening any rule above:

- `receipt_id`, a unique identifier used for consumption bookkeeping;
- `trust_epoch`, so a receipt cannot survive an epoch transition;
- `capability_digest`, because the parent document binds the capability digest
  into every proposal and a server capability change invalidates an outstanding
  preview;
- `challenge_id`, the fresh challenge bound to the proposal digest and operator
  identity that the backchannel answered; and
- `audit_sequence`, the audit chain row committed with the decision.

### Authentication of the receipt

The receipt is signed or authenticated by a host key source that is unavailable
to the requester tool surface. Concretely:

- the key is acquired through the `KeySource` boundary established by PR #9194,
  subject to the single-authority rule recorded in ADR-013;
- no requester-facing tool, adapter, plugin, or agent may resolve, read, or
  proxy that key. An adapter cannot mint principals or consume receipts;
- acquisition failure fails closed and disables mutation. It does not select a
  weaker approval mode, an unsigned receipt, or a generated replacement key,
  matching the ADR-013 posture that a source failure must not implicitly
  downgrade to an unsigned identity; and
- the approval and audit key is a non-encryption consumer of key material.
  ADR-013 deferred that case to a separate security decision, and that decision
  is now made: the key is a never-exportable HKDF-SHA256 subkey of the single
  ADR-013 authority, derived under the label
  `zeroclaw/control-plane/approval-audit/v1`. The broker asks the key source to
  sign or authenticate the canonical receipt fields and never receives key
  bytes, so the receipt contract does not change if a deployment later moves the
  signing key to a separate source or a secure element.

### Single-use consumption semantics

1. **One consumption, ever.** A receipt authorizes exactly one transition from
   `approved` to `applying` for exactly one journal entry.
2. **Consumption is atomic with the state change.** The host verifies and
   consumes the receipt while changing `approved` to `applying`, inside one
   journal-database transaction that is committed and synced before any config
   change. Receipt consumption and the `applying` record are one atomic durable
   fact.
3. **Crash windows are deterministic.** A crash before commit leaves `approved`
   with an unconsumed receipt. A crash after commit leaves `applying` with a
   consumed receipt, which authorizes the recovery service to continue or
   classify only that exact operation. The mechanics are designed in
   `control-plane-proposal-journal.md`.
4. **Reverting does not restore authority.** Reverting an applied change does
   not make its approval reusable. A revert is a new operation with its own
   proposal, preview, and approval.
5. **Everything invalid fails closed.** Forged, modified, expired, and replayed
   receipts fail closed. So does a receipt whose trust epoch, capability
   digest, instance fingerprint, or source revision no longer matches.
6. **Consumption is auditable.** The audit row for the consumption commits in
   the same journal transaction as the state transition it describes.

A receipt is not a bearer token in the ordinary sense: possessing it grants
nothing to a requester, because no requester-facing tool accepts one. The
transaction worker claims the parked proposal and its receipt; the requester
observes progress through Status.

## Operator backchannel eligibility

### Acceptable backchannels

The parent document permits three shapes:

- a paired Operator Console session;
- a configured channel identity whose credential is not available to the
  requester; or
- an OS-mediated user-presence ceremony.

An ordinary anonymous CLI invocation is a requester, not an operator. A channel
is high-assurance only when the host can distinguish the human responder from
the agent or bot identity. Management approval does not use model-visible
free-form text replies, and a text code, message content, or button payload
visible to the model is not sufficient.

Approval uses a fresh challenge bound to the proposal digest and operator
identity, authenticated through a paired credential, a platform user identity,
or an operator-device signature.

At least one high-assurance backchannel and an approval-signing key source
outside the requester tool surface are prerequisites for enabling mutations. For
a headless host, the first supported backchannel is a paired operator device or
an authenticated platform-user action delivered by a channel adapter that
preserves the human-versus-bot distinction.

### The conservative reachability rule

Before requesting or accepting approval, the host computes whether the
requester can act as the operator identity or access its signing credential.
That operator is ineligible when the requester can do so.

The rule for uncertainty is conservative and is quoted here because the safety
of the whole model depends on which way the default points:

> Reachability analysis is conservative. If the host cannot prove that a broad
> egress grant, plugin, delegated credential, or integration cannot reach or
> impersonate the operator identity, it treats that identity as reachable and
> ineligible for that requester.

Two consequences follow directly.

1. **The burden of proof is on eligibility, not on ineligibility.** An operator
   identity is eligible only when the host can positively demonstrate the
   requester cannot reach it. Absence of evidence of reach is not evidence of
   isolation.
2. **Fail closed when nothing remains.** If no eligible operator remains after a
   configuration change, mutations fail closed. The host does not fall back to a
   lower assurance backchannel, and it does not approve with the requester's own
   identity.

### Evidence the analysis needs

The analysis is per requester and per operator identity, and must consider at
least:

- **Egress.** Whether a granted egress destination could reach the transport
  that carries the operator identity. The shared egress policy foundation from
  PR #9137 provides `EgressPolicy` and `EgressPolicyResolver` in
  `crates/zeroclaw-plugins/src/egress.rs`, plus host and address classification
  in `crates/zeroclaw-infra/src/net_guard.rs`. Those are the inputs a
  reachability analysis would read. The analysis itself does not exist and
  would be new work; the existing policy answers "is this destination
  allowed", not "can this principal impersonate that operator".
- **Plugins.** Declared capabilities, permissions, and requested egress
  destinations of every plugin granted to the requesting agent. Typed instance
  config from PR #9126 in `crates/zeroclaw-plugins/src/config.rs` is what makes
  a plugin's configured surface inspectable rather than opaque.
- **Delegated credentials.** Any credential the requester can resolve that the
  backchannel also accepts.
- **Integrations and channels.** Whether a granted integration can post as, read
  for, or otherwise impersonate the operator identity on its channel.
- **Shell and filesystem grants.** Whether the requester can read the
  backchannel credential or the control socket.

Granting an agent, plugin, MCP server, provider, or integration access that
would expose or impersonate an approval identity is itself a meta-authority
operation, and it revalidates all configured backchannels.

## Permanently meta-authority operations

The parent document lists the operations that are permanently meta-authority.
They are reproduced here in full because "permanently" is the load-bearing word:
no adapter, policy value, protocol minor version, or deployment mode may move
one of these into a weaker class.

- enabling management mutations;
- changing approval modes, groups, quorum, principal links, or backchannels;
- changing management or audit key sources;
- registering target roots or approved creation parents;
- registering or widening an external client grant or changing its credential
  delivery assurance;
- creating a child instance or changing its inherited operator or trust set;
- changing a grant or binding that can expose or impersonate an operator
  backchannel identity;
- widening policy or granting management to the requester;
- trusting a plugin publisher or enabling the external WASM plugin system; and
- changing the rule that classifies an operation as requiring approval.

Registering target roots and approved creation parents recurs after every
trust-root recovery. Recovery discards the registered target roots and the
approved creation parents rather than carrying them into the new epoch, so an
operator registers each one again, and each re-registration is a meta-authority
operation consuming a receipt exactly like the original. The maintainer decided
this on 2026-08-22 in
[issue #26](https://github.com/JordanTheJet/zeroclaw/issues/26#issuecomment-5383167800);
see "What recovery invalidates" in `control-plane-trust-genesis.md`.

Confirmation tier rules:

- meta-authority changes always use the strongest confirmation tier;
- when at least two eligible operators exist, they require at least two
  distinct operator principals and no fewer than the configured quorum;
- a single-operator installation requires one user-presence-authenticated
  operator distinct from the requesting agent or MCP session; and
- an operator that the reachability analysis makes ineligible for this requester
  does not lower the required quorum. A host configured with two operators, one
  of which is ineligible for this requester, does not fall back to the
  single-operator path. It fails closed until the configured quorum of eligible
  operators is available. The single-operator rule describes an installation
  configured with one operator, never a multi-operator installation reduced to
  one by reachability, because the latter would let a requester reduce the
  required quorum by becoming able to reach an operator. Adopted from the
  gap-sweep resolution proposed in
  [issue #26](https://github.com/JordanTheJet/zeroclaw/issues/26), item 4.

The first stable protocol has no unapproved mutation class at all. Introducing
one later requires a new architecture decision and cannot include capability
widening, credentials, trust roots, executable installation, or authority
policy.

## Verification gates for phases 3 and 4

A phase-3 or phase-4 implementation is reviewable only when these
behavior-boundary tests pass. They are the subset of the parent document's
required verification list that this design owns:

- a requester cannot run genesis, replace its trust epoch, register a client,
  register a target, or approve a creation parent;
- a client credential reachable from an agent execution context cannot grant
  that agent the registered client's authority;
- one client cannot access another client's pending proposal;
- native and MCP callers receive the same requester authority;
- an unregistered stdio client exposes only Initialize, Ping, ServerInfo, and
  RegistrationHelp;
- an unregistered or ungranted agent that self-launches stdio cannot Inspect,
  Propose, request review, or approve;
- local control-channel challenge replay or peer-credential spoofing cannot
  replace registered-client authentication;
- granting an integration cannot make an approval identity reachable by the
  requesting agent without a meta-authority decision;
- forged, modified, expired, and replayed approval receipts fail closed;
- a caller cannot self-approve, alter principal classification, or widen its own
  grants;
- meta-authority changes cannot enter an unapproved operation class; and
- secret values are absent from inventory, preview, errors, logs, and MCP
  responses.

## Open questions

These are gaps or ambiguities in the parent architecture document or its
interaction with accepted records. Items marked **Resolved** carry a maintainer
decision recorded on 2026-08-21; they are kept here rather than deleted so the
question and its answer stay together. Items marked **Open** are recorded for
the maintainer to settle and are deliberately not resolved here.

1. **Resolved: ADR-013 does not authorize the approval and audit key.** The
   parent
   document requires the broker to authenticate receipts "with a host key source
   unavailable to the requester tool surface" and requires genesis to "generate
   and seal the host approval/audit key in a platform key source". ADR-013
   records that one configured source is authoritative per deployment and
   explicitly defers whether a non-encryption consumer gets scoped access or a
   derived subkey, stating that until that decision is recorded "a
   non-encryption consumer must not silently reuse the raw encryption master
   key". The control plane's approval and audit key is exactly such a consumer.
   Either the control plane needed its own key-source authority, which appears to
   conflict with ADR-013's one-source rule, or the deferred derived-subkey
   decision had to be made first.

   **Resolution.** The deferred decision was made. The approval and audit key is
   a never-exportable HKDF-SHA256 subkey of the single ADR-013 authority, derived
   under the label `zeroclaw/control-plane/approval-audit/v1` and exposed only
   through sign and verify operations. No second key-source authority is
   introduced. Decided by the maintainer on 2026-08-21 in
   [issue #24](https://github.com/JordanTheJet/zeroclaw/issues/24#issuecomment-5376601651);
   see "What ADR-013 constrains here" and "Authentication of the receipt" above,
   and the draft record
   `docs/book/src/architecture/decisions/ADR-015-control-plane-approval-audit-key.md`.
2. **Resolved: the agent requester row does not say "never approve".** The
   principal table
   says an external requester may "Inspect, propose, and request review only
   within its grant; never approve", but the agent requester row omits the
   "never approve" clause. Every other statement in the parent document implies
   agent requesters cannot approve either, and this page assumes that reading.
   The asymmetry in the table should be corrected so no implementer reads the
   omission as permission.

   **Resolution.** The agent-requester row on this page now carries the same
   explicit "never approve" clause as the external-requester row, and the
   correction is called out under "Principal classes" above. No principal type in
   a requester class can approve. The parent document still needs the matching
   amendment. Adopted from the gap-sweep resolution proposed in
   [issue #26](https://github.com/JordanTheJet/zeroclaw/issues/26), item 3.
3. **Resolved: phase 3 and phase 4 appear circularly ordered.** Phase 3 adds
   external
   client registration, but the parent document also states that client
   registration is a meta-authority operation, and meta-authority operations
   require a receipt issued under the existing trust epoch. Receipts arrive in
   phase 4. Only genesis and trust-root recovery are exempt from consuming a
   prior receipt. It is therefore unclear how the first client is registered:
   whether registration in phase 3 rides on the genesis ceremony itself, whether
   phase 3 ships registration without an approval path and phase 4 retrofits
   one, or whether the two phases must land together. This affects what a
   phase-3 pull request can honestly claim.

   **Resolution.** Registration in phase 3 rides on the genesis ceremony. The
   ceremony may register the first client or clients receipt-exempt, as a
   bounded exception that closes at mutation enablement; every later registration
   consumes a phase-4 receipt and fails closed until the broker exists. Decided
   by the maintainer on 2026-08-21 in
   [issue #25](https://github.com/JordanTheJet/zeroclaw/issues/25#issuecomment-5376560807);
   see "Client registration" above, the bounds in
   `control-plane-trust-genesis.md`, and the draft record
   `docs/book/src/architecture/decisions/ADR-016-control-plane-registration-bootstrap.md`.
4. **Resolved: quorum when a second operator exists but is ineligible.**
   Meta-authority
   requires two distinct operator principals "when at least two eligible
   operators exist", and a single-operator installation requires one. The
   parent document does not say what happens when a host has two configured
   operators but the reachability analysis makes one ineligible for this
   requester. Falling back to the single-operator path would let a requester
   reduce the required quorum by becoming able to reach one operator, which
   looks like an escalation path. Failing closed is the conservative reading but
   was not stated.

   **Resolution.** Fail closed. An ineligible operator does not lower the
   required quorum, and a multi-operator installation reduced to one eligible
   operator by reachability does not fall back to the single-operator path. See
   "Permanently meta-authority operations" above. Adopted from the gap-sweep
   resolution proposed in
   [issue #26](https://github.com/JordanTheJet/zeroclaw/issues/26), item 4.
5. **Resolved: `owner token` is undefined.** The proposal binding set includes
   "registered
   requester identity, client session attribution, and owner token". The term
   `owner token` does not appear anywhere else in the parent document. It is
   unclear whether it is the resume secret, a separate value, or a synonym for
   the registration identifier. It cannot be implemented as written.

   **Resolution.** `owner_token` is the client's `registration_id` and is
   attribution only. The proposal binding is the registered requester identity,
   the client session attribution, and the `registration_id`, none of which
   conveys approval authority. It is not the resume secret. The binding list is
   updated in `control-plane-proposal-journal.md`. Adopted from the gap-sweep
   resolution proposed in
   [issue #26](https://github.com/JordanTheJet/zeroclaw/issues/26), item 6.
6. **Resolved: effect of re-evaluation on outstanding state.** Delivery assurance
   is
   re-evaluated when sandboxes, shell grants, helpers, or credential locations
   change, and a collapse can reduce an effective grant to nothing. The parent
   document does not say what happens to that client's already-parked
   proposals, already-issued receipts, or in-flight applies at the moment of
   collapse. Expiring them is the conservative reading; silently continuing
   them would let a requester keep authority it has just lost.

   **Resolution.** Expire them. On collapse the host expires that client's parked
   proposals and issued unconsumed receipts and aborts its in-flight applies that
   have not yet passed the atomic receipt-consumption commit. See "Re-evaluation
   triggers" above. Adopted from the gap-sweep resolution proposed in
   [issue #26](https://github.com/JordanTheJet/zeroclaw/issues/26), item 7. The
   post-commit case is item 7 below and remains open.
7. **Open: registration revocation versus an in-flight apply.** Related to the
   previous item and not covered: whether revoking a client registration
   interrupts an apply already in `applying` for a proposal that client
   submitted, or whether the approved operation completes because the operator
   already authorized that exact effect.

## Governance status

This page is a proposal. The parent document states that the control plane
creates a default-distributed external protocol, a new configuration-mutation
authority, and new operator-principal policy, and therefore requires an accepted
RFC before the external MCP or mutating surface is treated as an implementation
detail. It further states that changes to approval authority, principal
assurance, plugin trust, or the stable control protocol require the matching
architecture decision or foundation amendment.

No RFC has been accepted for this work, and no architecture decision record
covers control-plane principals or approval authority. Under the RFC process in
`docs/book/src/contributing/rfcs.md`, this material meets the trigger for a new
security layer and a new project-wide capability boundary. Publishing this page
does not create any obligation, does not authorize implementation, and must not
be cited as evidence that the design is accepted.
