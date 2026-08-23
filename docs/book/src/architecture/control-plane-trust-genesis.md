# Design: control-plane trust genesis and recovery ceremonies

> **Status: accepted** (maintainer decision, 2026-08-22; remaining open questions are tracked on the fork issue #26). Nothing on this page is implemented on `master`. There is no
> control-plane genesis record, no trust epoch, no target registry, and no
> recovery ceremony anywhere on `master`. The genesis record, its fixed
> data-root path, its authentication tag, the target-registry data model, and
> the eligible / managed / recovery-only classification are implemented on the
> staged, unmerged `feat/control-trust-genesis` branch; the recovery ceremony
> itself is not implemented anywhere. This page describes what the trust
> half of phase 3 of the parent architecture would have to build in order to be
> reviewable. It is not an accepted design and it does not authorize
> implementation.

This page is subordinate to
`docs/book/src/architecture/chat-management-control-plane.md`, which is itself
marked proposed and currently lives on an unmerged documentation branch rather
than on `master`. Where the parent document already states a rule, this page
cites it and refines the mechanism. It never restates a parent rule more loosely
and never introduces a path by which a requester reaches the trust root. If the
two disagree, the parent document wins and this page is wrong.

## Scope

The parent document's phased delivery defines phase 3 as:

> 3\. **Trust genesis and registration.** Add genesis, trust epochs, host and
> operator keys, external client registration, target registry, approved
> creation parents, and recovery entry points.

This page covers genesis, trust epochs, the target registry as it is
established at genesis, and recovery. External client registration, the grant
model, and approval receipts are designed in
`control-plane-principals-and-approvals.md`. The journal whose entries a trust
epoch scopes is designed in `control-plane-proposal-journal.md`.

The control-plane crate is named `zeroclaw-control`. That name is staged,
unmerged work; no such crate exists under `crates/` on `master`, and neither
does any genesis record format.

## The defining property

Genesis and trust-root recovery are the only management transitions that do not
consume a prior management approval receipt. Everything else in the control
plane is authorized by a receipt issued under an existing trust epoch, and a
receipt requires a trust root that only genesis can create. That circularity is
why genesis is a ceremony rather than an operation.

The genesis and mutation-enablement ceremony may additionally register the first
client or clients receipt-exempt. That is a bounded exception performed inside
the ceremony rather than a third exempt transition, and it closes the moment
mutation enablement completes. See "Bootstrap client registration" below. The
maintainer decided this on 2026-08-21 in
[issue #25](https://github.com/JordanTheJet/zeroclaw/issues/25#issuecomment-5376560807);
the decision record is drafted as
`docs/book/src/architecture/decisions/ADR-016-control-plane-registration-bootstrap.md`
on the `docs/control-plane-decision-drafts` branch.

Two consequences are absolute:

1. **Neither ceremony is reachable through the control plane.** Genesis and
   recovery are not exposed through native tools or MCP. Recovery is
   additionally not reachable through `ControlService`, an anonymous CLI mode,
   or an approval backchannel being replaced.
2. **Both require genesis-equivalent assurance under the exclusive bootstrap
   lock.** There is no lower-assurance path, no headless shortcut on an
   interactive host, and no interactive shortcut on a headless one.

A requester cannot run genesis, replace its trust epoch, register a client,
register a target, or approve a creation parent. That is a phase-3 verification
gate, not a design aspiration.

## Key material and ADR-013

Genesis generates and seals the host approval and audit key. On `master` today,
key acquisition has exactly one recorded shape:

- PR #9194, commit `b8489219e` (`feat(secrets): extract KeySource trait +
  FileKeySource backend`) added `trait KeySource`, `FileKeySource`,
  `ProvisioningState`, and `SecretStore::from_key_source` in
  `crates/zeroclaw-config/src/secrets.rs`. The trait exists, but `SecretStore`
  remains its only consumer.
- ADR-013 (`ADR-013: Master Key Acquisition Uses One Configured Key-Source
  Authority`, PR #9361, commit `5df637ca1`, status proposed) records that one
  configured source is authoritative for a deployment at a time, that the
  assembly layer constructs one shared source authority per process generation,
  and that a consumer may not reconstruct an authority or read backend material
  directly.

Three ADR-013 rules constrain this ceremony directly:

- **Provisioning state is not availability.** A source must distinguish material
  that exists and verifies, material that needs initialization, and material
  that is externally provisioned with no local check. A provisioning probe must
  not unexpectedly execute a helper, contact a network service, prompt a user,
  or unlock a keychain. Genesis therefore probes before it prompts, and a probe
  is not a ceremony.
- **Initialization is not rotation.** File initialization must publish a
  complete restrictive file without replacing existing material or following
  symlinks. Genesis initializes; it never replaces.
- **Failure fails closed.** On failure the host must not silently fall back,
  generate replacement material, or try another backend, and raw key bytes must
  never reach logs or errors. If the platform cannot provide user presence or a
  key source outside the requester tool surface, the installation remains
  read-only.

ADR-013 also defers whether a non-encryption consumer receives scoped access or
a derived subkey, and states that until that decision exists such a consumer
must not silently reuse the raw encryption master key. The approval and audit
key is a non-encryption consumer, so that intersection had to be decided before
phase 3 could be implemented.

It is now decided. The maintainer decided on 2026-08-21 in
[issue #24](https://github.com/JordanTheJet/zeroclaw/issues/24#issuecomment-5376601651)
that the control-plane approval and audit key is an HKDF-SHA256 subkey derived
from the single ADR-013 key-source authority, under the fixed
domain-separation label `zeroclaw/control-plane/approval-audit/v1`. The derived
key is never exportable and is exposed only through sign and verify operations,
so no raw approval-key bytes cross the `KeySource` boundary and none reach a
requester-facing surface. Rotating the master key re-derives, and therefore
rotates, the approval key; that tradeoff is accepted, and independent
approval-key rotation is out of scope until a deployment needs it. The decision
record is drafted as
`docs/book/src/architecture/decisions/ADR-015-control-plane-approval-audit-key.md`
on the `docs/control-plane-decision-drafts` branch.

Genesis therefore does not select a second key source. It derives the approval
and audit key under the deployment's single authority and commits to it through
`host_key_commitment` in the genesis record.

### What a deployment is

ADR-013's rule that one configured key source is authoritative "for a
deployment" cannot be checked until `deployment` has a referent. The maintainer
decided on 2026-08-22 in
[issue #26](https://github.com/JordanTheJet/zeroclaw/issues/26#issuecomment-5383167800)
that a deployment is the canonical install root: the config-root and data-root
pair that the genesis record names in `canonical_roots`. Each instance root is
its own deployment, and therefore its own key authority.

Two consequences follow directly:

- a child instance on the same host is a distinct deployment, because it has
  distinct canonical roots. Parent and child holding distinct host keys is the
  single-authority rule applied once per deployment, not a violation of it; and
- a deployment is never the host and never the operating-system user. Two
  install roots under one login are two deployments, and one install root
  reached by two processes is still one deployment with one authority.

This closes the residual ADR-013 tension recorded as open question 3 below, and
it agrees with ADR-015, which derives the approval and audit key under whichever
single authority the deployment already has rather than introducing a second
one.

## Interactive genesis

An interactive installation uses an OS-mediated user-presence ceremony to
perform exactly these five steps, reproduced verbatim from the parent document:

1. generate and seal the host approval/audit key in a platform key source;
2. register the first operator public identity;
3. assign a stable instance identifier to the canonical config and data roots;
4. write and sync an immutable genesis record containing the trust epoch; and
5. leave mutations disabled until the operator separately enables them.

Step 5 is not a formality. Genesis establishes who may approve; it does not
enable approving. Mutation enablement is a separate host-owned bootstrap
ceremony requiring a configured high-assurance operator backchannel, a usable
approval and audit key source, and explicit user-presence confirmation of the
canonical target instance. That ceremony records the enabled capabilities and
does not grant management tools to any agent.

What does **not** satisfy interactive genesis:

- an ordinary terminal prompt;
- a loopback connection;
- an anonymous CLI invocation; or
- any combination of TTY, process parent, same UID, and environment.

`zeroclaw onboard` may guide a new installation through the mutation-enablement
ceremony, but it must call the same `ControlService` and approval primitives. It
does not retain a second apply route whose anonymous terminal approval bypasses
the control-plane principal rules.

## Headless genesis

A headless deployment supplies a genesis manifest through its deployment trust
root. The manifest contains:

| Field | Contents |
|---|---|
| Instance identity | The stable instance identifier being established |
| Canonical roots | The canonical config and data roots |
| First operator public key | The public identity of the first operator |
| Host key-source declaration | Which key source holds the approval and audit key, consistent with the single-authority rule in ADR-013 |
| Administrator signature or platform attestation | The authorization that makes the manifest trustworthy |

The corresponding operator private key remains on a separate operator device. A
headless agent, channel bot, or MCP client cannot create or replace that
manifest through `ControlService`.

The distinction that matters: on an interactive host the human is present and
the OS attests to that presence; on a headless host the human is absent and the
deployment trust root attests on their behalf, with the private key never
arriving on the host at all. Neither substitutes for the other, and a host that
can offer neither remains read-only.

### Where the deployment trust root comes from

Headless assurance rests entirely on the deployment trust root, so its own
provenance cannot be left to the installer's discretion. The maintainer decided
on 2026-08-22 in
[issue #26](https://github.com/JordanTheJet/zeroclaw/issues/26#issuecomment-5383167800)
that the root is established in exactly two ways and no others:

1. **At interactive genesis**, under the same OS-mediated user-presence
   ceremony that establishes the first operator. A host that can run interactive
   genesis can establish its own root while the human is attested present.
2. **Out of band, before first boot.** The administrator places the root on the
   host through whichever provisioning channel already owns that host, such as a
   machine image, configuration management, or a platform secret store. This is
   the path a headless host uses, and it completes before ZeroClaw first runs.

The load-bearing half of that decision is the exclusion. **ZeroClaw has no code
path that writes the deployment trust root.** No daemon, `ControlService`
operation, `zeroclaw onboard` step, native tool, MCP method, or recovery
ceremony creates, replaces, or extends it. Every ZeroClaw component is a reader
and verifier of the root and never a writer of it.

That is what answers the question the parent document left open, namely what
prevents the process that writes a manifest from also writing the trust root the
manifest is verified against. The separation is structural rather than a policy
the implementation must remember to enforce: the writer is the administrator or
the interactive genesis ceremony, the verifier is ZeroClaw, and the two are
different processes with different authority because ZeroClaw is not a writer at
all. A verification gate that finds any ZeroClaw write path to the root has
found a defect, not a configuration choice.

Changing an established root is therefore an out-of-band administrative act on
the host, carrying the same assurance as placing it, plus platform attestation
where the platform offers one. A host that can offer neither user presence nor
an administrator-placed root has no way to obtain one from ZeroClaw and remains
read-only, per the ADR-013 fail-closed rule above.

## Bootstrap client registration

Client registration is a meta-authority operation and normally consumes an
approval receipt issued under the existing trust epoch. The receipt broker
arrives in phase 4, so the first client could not otherwise be registered in
phase 3 at all. The maintainer decided on 2026-08-21 in
[issue #25](https://github.com/JordanTheJet/zeroclaw/issues/25#issuecomment-5376560807)
that the ceremony may register the first client or clients receipt-exempt, as a
minimal bounded exception.

The exception is bounded by all of the following, and an implementation that
relaxes any one of them is outside the decision:

- it applies only to registrations performed inside the genesis or
  mutation-enablement ceremony, under the same user-presence assurance
  (interactive host) or deployment-trust-root assurance (headless host) that
  establishes the first operator. There is no lower-assurance path;
- the bootstrap-registered client receives no approval authority, consistent
  with the rule that registration never grants approval;
- each bootstrap registration is recorded in the audit chain with its own
  anchor, and the registration record's `created_by` references the genesis or
  enablement operation digest rather than a receipt;
- the exception closes when mutation enablement completes. After that point no
  registration is receipt-exempt, and a registration attempted outside the
  ceremony fails closed until the phase-4 broker exists; and
- recovery invalidates bootstrap-registered clients unless they are
  re-established, as stated under "What recovery invalidates".

This does not widen who may register a client. A requester still cannot run
genesis, register a client, or reach the ceremony, and the ceremony remains
unreachable through `ControlService`, native tools, or MCP.

## The genesis record

The genesis record is the root of trust for later operator, client, target, and
key changes. It is written and synced as an immutable record.

| Field | Contents | Why it is bound |
|---|---|---|
| `instance_id` | Stable instance identifier | Everything else in the control plane is keyed by it |
| `canonical_roots` | Config root and data root | Apply resolves the target from the registry, never from a caller-supplied path |
| `trust_epoch` | The initial epoch value | Scopes every credential, grant, and receipt issued under it |
| `first_operator` | First operator public identity | The only identity that can approve before any meta-authority change |
| `host_key_commitment` | Commitment to the approval and audit key or its verifier | Lets a later epoch transition prove continuity |
| `key_source_declaration` | Which configured key source holds that key | ADR-013 requires the source to be resolved from typed config, not chosen ad hoc |
| `assurance_policy` | The assurance policy in force at genesis | Inherited by child instances by default |
| `deployment_trust_root` | For headless genesis, the trust root that authorized the manifest | Inherited by child instances by default |
| `genesis_anchor` | For a child instance, the parent operation digest | Links the child's audit chain to the parent's |
| `record_digest` | Digest of the record itself | Referenced by the instance fingerprint and by any later recovery manifest |

The record is immutable. A later operator change, client registration, target
registration, or key change is an ordinary meta-authority operation that does
require a receipt issued under the existing trust epoch. Those changes are
recorded in the audit chain anchored to this record; they do not rewrite it.

### The record is the managed-instance marker

The anti-reset rule below rests entirely on a durable marker, so the marker's
identity, location, and protection are pinned here rather than left to the
implementation. The maintainer decided on 2026-08-22 in
[issue #26](https://github.com/JordanTheJet/zeroclaw/issues/26#issuecomment-5383167800)
that the durable genesis record is itself the managed-instance marker. There is
no second marker file, and therefore no second artifact that can drift out of
agreement with the record it is supposed to mirror.

| Property | Decision |
|---|---|
| Identity | The genesis record is the marker. No other artifact marks a root as managed |
| Location | A fixed path under the canonical data root, outside every agent sandbox and not a path a requester can name in a proposal |
| Format | The record fields above, in a sealed envelope carrying a format version and a domain-separation label |
| Protection | Authenticated by the host key chain: an authentication tag over the record's canonical encoding produced by the ADR-015 approval and audit key, with `host_key_commitment` binding the record to that key |
| Verification | Recomputed on every startup and every audit read, before any mutation path is offered |
| Present but invalid | Recovery-only mode, never eligibility for first genesis |

The present-but-invalid row carries the most weight, because a damaged record is
far cheaper for an attacker to produce than a forged one. A record that exists
and fails its tag, its key commitment, its domain, its format version, or its
canonical-roots check is evidence that this root is managed and that its trust
material is damaged. That is recovery-only mode. An unreadable record is treated
the same way: a root the host cannot inspect is not a root the host may
re-initialize.

This much is built. The record format, the fixed data-root path, the
authentication tag, and the eligible, managed, and recovery-only classification
are implemented on the `feat/control-trust-genesis` branch, which is staged and
unmerged. None of it is on `master`, and nothing on this page should be read as
a description of shipped behavior.

### Relationship to the target registry

Genesis registers the default instance in the signed target registry. Each
registry record contains canonical config and data roots, ownership and
permission checks, allowed creation parent, instance fingerprint, trust epoch,
and status.

Registering another existing root, or an approved creation parent, is a
meta-authority operation rather than part of genesis. Apply resolves the target
ID from this registry under the registry and instance locks, and the caller
never supplies a path at apply time.

The registry is scoped to the trust epoch under which its entries were
registered. It does not survive a trust-root recovery: recovery discards every
registered target root and approved creation parent, and the operator registers
them again under the new epoch. See "What recovery invalidates" below.

The instance fingerprint commits to the instance ID, genesis-record digest,
trust epoch, canonical roots, filesystem object identity where available, owner,
and security-relevant permissions. The host recomputes it under lock before
preview and apply, so replacing a registered root or redirecting it through a
symlink expires the proposal.

## Trust epochs

A trust epoch is the scope under which credentials, grants, and receipts are
valid. Its purpose is to make a compromise or a key change a bounded event
rather than an open-ended one.

Rules:

- the genesis record establishes the initial epoch;
- a trust epoch is a monotonic counter scoped to one instance. It is recorded in
  the genesis record and repeated in every audit row;
- epoch values are per instance, never per host. A child instance's epoch is
  independent of its parent's, and two epoch values are comparable only within
  one instance's audit chain, so an inherited trust root never implies a shared
  epoch sequence;
- every audit row carries a monotonic sequence, trust epoch, operation
  identifier, previous-row digest, and host-key authentication tag;
- the journal transaction commits the audit row with the state transition it
  describes, so an audit row cannot exist without its transition or the reverse;
- startup and audit reads verify the chain from the genesis anchor; and
- a gap, rewrite, invalid tag, or unexpected epoch disables mutations and enters
  recovery.

### Planned key rotation

A planned host-key rotation appends an epoch-transition row authenticated under
the old key and committing to the new public key or verifier. The first row in
the new epoch commits to that transition. Continuity is therefore provable in
both directions: the old key attests that the change was intended, and the new
epoch attests to what it replaced.

Changing management or audit key sources is permanently a meta-authority
operation. ADR-013 additionally records that key-source selection is not live
applied and takes effect only after migration validation and a full daemon
reload or process restart, and that any future live handoff must define
generation fencing in a separate implementation decision. A control-plane key
rotation therefore cannot be a hot swap.

### Lost-key recovery

When the old host key is lost, a planned rotation is impossible and the epoch
break is authorized by the deployment trust root or the OS user-presence
authority instead. The first new-epoch row commits to the last verified
old-epoch chain head. The parent document is explicit that this is preferable to
"pretending the old key signed the change": the discontinuity is recorded rather
than disguised.

Deployments that need evidence beyond the host-compromise boundary may anchor
periodic chain heads in an external operator-owned store. That is an option, not
a requirement, and the threat model does not treat a caller that can already
overwrite the host executable, approval key source, and transaction store as
contained by this protocol.

## Trust-root recovery

Recovery requires at least genesis-equivalent assurance. An interactive host
uses the OS-mediated user-presence ceremony; a headless host requires a
deployment-trust-root-signed recovery manifest. Recovery runs under the
exclusive bootstrap lock.

Recovery is not reachable through `ControlService`, native tools, MCP, an
anonymous CLI mode, or an approval backchannel being replaced. That last
exclusion matters: the backchannel under repair cannot authorize its own
replacement.

### Recovery manifest binding

The recovery manifest binds:

| Field | Contents | Why it is bound |
|---|---|---|
| `instance_id` | The instance being recovered | A manifest for one instance cannot recover another |
| `prior_genesis_record_digest` | Digest of the genesis record being succeeded | Proves the manifest was written against this instance's actual history |
| `prior_audit_chain_head` | The last verified old-epoch chain head | Gives the new epoch something to commit to |
| `reason` | Why recovery is being performed | Recorded, not inferred |
| `new_operator_set` | The operator identities valid after recovery | Recovery is where an operator set can change without a prior receipt |
| `new_host_key_commitment` | Commitment to the new approval and audit key | Establishes the new epoch's authentication |
| `new_trust_epoch` | The epoch value being entered | Monotonic with respect to the prior epoch |

Interactive recovery binds those same facts into its user-presence-authorized
recovery record. The two paths differ in who attests, not in what is bound.

Authentication of the epoch transition depends on what survives:

- **Old host key available.** The epoch transition is authenticated by both the
  old and the new keys.
- **Old host key lost.** The deployment trust root or the OS user-presence
  authority authorizes the break, and the first new-epoch row commits to the
  last verified old-epoch chain head.

### What recovery invalidates

Recovery invalidates all pending proposals, client credentials, approval
receipts, and resume secrets. Nothing issued under the prior epoch survives into
the new one. A registered client must be registered again, and a parked proposal
must be proposed again with a fresh preview.

Bootstrap-registered clients are covered by that rule. A client registered
receipt-exempt inside a genesis or mutation-enablement ceremony does not survive
recovery, and is re-established only through the recovery ceremony's own
bootstrap step or, once mutations are re-enabled, through an ordinary
registration that consumes a receipt.

The target registry does not survive either. The maintainer decided on
2026-08-22 in
[issue #26](https://github.com/JordanTheJet/zeroclaw/issues/26#issuecomment-5383167800)
that recovery discards the registered target roots and the approved creation
parents, and that the operator re-registers them afterwards. The reason is
containment: a target root or creation parent registered under a compromised
epoch must not outlive the recovery whose purpose is to contain that compromise.
A registration is authority to reach and mutate another root, so preserving it
across an epoch break would preserve exactly the authority the break is meant to
withdraw.

The cost is accepted rather than hidden. A recovered host cannot reach
previously registered instances, and cannot create children under a previously
approved creation parent, until an operator registers each one again. Each of
those re-registrations is an ordinary meta-authority operation consuming a
receipt issued under the new epoch, so none of them is available until the
post-recovery mutation-enablement ceremony below has completed. Recovery
therefore returns the instance to a state where it holds a trust root, no
enabled mutation authority, and no reach beyond itself.

Recovery also resets mutation enablement to disabled. Genesis leaves mutations
disabled until a separate ceremony, and recovery replaces the operator set and
the host key, so the recovered instance is in the same position: it holds a
trust root and no enabled mutation authority. Re-enabling mutations is a
separate post-recovery ceremony with the same prerequisites as the original one,
namely a configured high-assurance operator backchannel, a usable approval and
audit key source, and explicit user-presence confirmation of the canonical
target instance.

## Why deleting files never re-enables first genesis

First genesis is permitted only when no control-plane genesis record or
managed-instance marker exists. Re-running it against an initialized instance
fails closed.

The parent document states the anti-reset rule directly:

> Startup distinguishes ordinary first genesis from recovery by the durable
> instance identity and prior genesis record. Deleting a key, journal, or
> current config file does not make an initialized instance eligible for first
> genesis. A managed root with a missing or invalid genesis record enters
> recovery-only mode and cannot create a replacement genesis through the
> first-run path.

The reasoning is worth stating plainly, because it is the property an attacker
would most want to break. If deleting a file re-enabled first genesis, then any
process that can unlink a file in the data root could downgrade the instance to
an uninitialized state and then perform genesis itself, registering its own
operator identity and its own host key. Every later approval would be
authentic under a trust root the attacker created. The whole approval model
would be bypassed without ever forging a receipt.

The design therefore separates two questions that a naive first-run check
conflates:

| Question | Answered by | Effect |
|---|---|---|
| Has this root ever been managed? | The durable instance identity and the managed-instance marker | If yes, first genesis is permanently unavailable for this root |
| Is the trust material currently present and valid? | The genesis record, key source, journal, and audit chain | If no, the instance enters recovery-only mode |

A missing genesis record answers the second question, never the first. The
resulting state is recovery-only: the host will not serve mutations, will not
run first genesis, and offers only the recovery ceremony, which demands
genesis-equivalent assurance and binds the prior genesis-record digest and prior
audit-chain head. An attacker who deleted those artifacts cannot supply either
binding, and cannot manufacture the user presence or deployment trust root
signature that recovery requires.

Deleting the marker itself is not a bypass in the threat model's terms: a
process that can do so already has direct write access to the ZeroClaw config
root and data root, and the parent document is explicit that such a process
already has authority outside this protocol. The rule's job is to ensure that
nothing short of that level of access resets the trust root, and that a reset
that does occur is visible as a recovery event rather than indistinguishable
from an ordinary first run.

### One tension this page does not resolve

Making the genesis record the sole marker, as decided in item 20, costs the last
clause of the paragraph above, and the loss is recorded here rather than papered
over.

While the record is present, the decision is coherent and strictly stronger than
the alternative: present-but-invalid, present-but-unreadable, present with a
mismatched key commitment, and present with mismatched canonical roots all land
in recovery-only mode. The gap is deletion. With no second durable artifact,
nothing under the data root remembers that the root was ever managed once the
record is gone, so deleting it does not produce a visible recovery event. It
produces a root that is indistinguishable from one that never ran genesis, which
is the outcome the quoted parent rule, covering a "missing or invalid genesis
record", says must not happen. The decision answers the invalid half of that
rule and narrows the missing half.

The staged implementation on `feat/control-trust-genesis` reaches the same
conclusion and pins it deliberately: one test asserts that deleting the genesis
record re-enables first genesis by design, and a sibling test asserts that
deleting the config, the target registry, or the key file never does. So the
containment argument that survives is the threat-model one in the paragraph
above, that only a process with write access to the data root can do this, and
not the stronger visibility claim.

Closing this needs one of two things the maintainer has not chosen between: a
second durable identity artifact, which item 20 deliberately rejected as a
sync hazard, or an amendment to the parent document's anti-reset wording so it
claims only what a single-artifact marker can deliver. It is flagged for the
maintainer and is not resolved on this page.

## Child instance genesis

Creating a new instance is a proposal against an already registered creation
parent and is always a meta-authority operation.

The host rejects symlink traversal, a non-empty unmanaged target, a root outside
that parent, and a root whose owner or permissions do not match policy.

Inheritance rules:

- by default, the child genesis record inherits the approving instance's
  operator set, assurance policy, and deployment trust root, while generating a
  distinct instance ID and host key;
- a proposal that names a different first operator, key source, or trust policy
  remains meta-authority and displays those values verbatim in the preview and
  the operator decision;
- a first operator must reference an operator identity already registered in the
  parent trust epoch, or a verifiable identity fingerprint validated by the
  parent operator backchannel;
- proposal-supplied opaque key material is not accepted, so a requester cannot
  smuggle a key it controls into a child's trust root;
- the parent audit chain records the child genesis digest, and the child records
  the parent operation digest as its genesis anchor; and
- the child remains read-only until its genesis record is durable and its own
  mutation-enablement ceremony completes.

The child is not a copy of the parent's authority. It inherits policy and starts
read-only, and its own mutation enablement is a separate ceremony on the child.

## Verification gates for the trust half of phase 3

A phase-3 implementation is reviewable only when these behavior-boundary tests
pass. They are the subset of the parent document's required verification list
that this design owns:

- a requester cannot run genesis, replace its trust epoch, register a client,
  register a target, or approve a creation parent;
- genesis and recovery reject races, re-initialization, symlinked roots, and an
  invalid deployment manifest;
- a managed root with a missing genesis record enters recovery-only mode and
  cannot run first genesis;
- bootstrap client registration happens only inside the genesis or
  mutation-enablement ceremony, grants the registered client no approval
  authority, and no registration is receipt-exempt after mutation enablement;
- recovery requires genesis-equivalent assurance, links audit epochs, and is
  unreachable through native tools or MCP;
- child creation inherits approved operators by default, previews any
  non-inherited operator set, and remains read-only until genesis is anchored;
- audit-chain gaps, rewrites, invalid tags, and trust-epoch mismatches disable
  mutation;
- planned key rotation and lost-key recovery preserve verifiable cross-epoch
  continuity;
- concurrent daemon and local-host startup leaves exactly one lock owner; and
- default-enabled management remains read-only until the operator ceremony.

One gate in that list is not currently satisfiable as written. "A managed root
with a missing genesis record enters recovery-only mode" presumes something
durable still identifies the root as managed after the record is gone, and the
item 20 decision leaves no such artifact. The gate holds for an invalid,
unreadable, or mismatched record and does not hold for a deleted one. The gate
text is left unchanged rather than quietly narrowed, because which way it should
be closed is the maintainer's call; see "One tension this page does not resolve"
above.

## Open questions

These are gaps or ambiguities in the parent architecture document or its
interaction with existing records. Items marked **Resolved** carry a maintainer
decision recorded on 2026-08-21 or 2026-08-22; they are kept here rather than
deleted so the question and its answer stay together. Items marked **Open** are
recorded for the maintainer to settle and are deliberately not resolved here.

Every item on this page is now resolved. The four trust-root items of the
[issue #26](https://github.com/JordanTheJet/zeroclaw/issues/26#issuecomment-5383167800)
gap sweep were decided on 2026-08-22 and folded into the body above; they appear
below as items 2 (sweep item 15), 3 (sweep item 16), 5 (sweep item 18), and 7
(sweep item 20). Sweep items 8, 9, 10, 13, and 26 remain open against the other
design pages and are phase 4 and 5 shaping rather than phase-3 blockers. Item 7
below carries a residual tension that its decision does not close, recorded
under "One tension this page does not resolve" above.

1. **Resolved: ADR-013's single-authority rule versus a separate control-plane
   key.**
   ADR-013 records that one configured key source is authoritative for a
   deployment at a time, and that the assembly layer constructs one shared
   source authority per process generation. The parent architecture requires
   genesis to seal a distinct host approval and audit key, and separately makes
   "changing management or audit key sources" its own meta-authority operation,
   which implies the management key source is independently selectable. Whether
   the control plane uses the deployment's single authority, or introduces a
   second authority that ADR-013 does not contemplate, was unresolved. This gap
   is also recorded in `control-plane-principals-and-approvals.md`.

   **Resolution.** The control plane uses the deployment's single authority. The
   approval and audit key is a never-exportable HKDF-SHA256 subkey derived under
   it, with the domain-separation label
   `zeroclaw/control-plane/approval-audit/v1`, exposed only through sign and
   verify operations. Decided by the maintainer on 2026-08-21 in
   [issue #24](https://github.com/JordanTheJet/zeroclaw/issues/24#issuecomment-5376601651);
   see "Key material and ADR-013" above and the draft record
   `docs/book/src/architecture/decisions/ADR-015-control-plane-approval-audit-key.md`.
   The parent document's "changing management or audit key sources" wording still
   needs the matching amendment, which is tracked with that record.
2. **Resolved: the deployment trust root has no defined provenance.** Headless
   genesis is
   authorized by "an administrator signature or platform attestation" verified
   against a deployment trust root, and headless recovery by a
   deployment-trust-root-signed manifest. The parent document never says how the
   deployment trust root itself is established on the host, who may change it, or
   what prevents the same process that writes the manifest from also writing the
   trust root it is verified against. Without that, headless genesis assurance is
   asserted rather than derived.

   **Resolution.** The root is established at interactive genesis under the
   OS-mediated user-presence ceremony, or placed out of band by the
   administrator before first boot. There is no third path, and ZeroClaw has no
   code path that writes it: every ZeroClaw component reads and verifies the root
   and none writes it, so writer and verifier are separated structurally rather
   than by policy. Decided by the maintainer on 2026-08-22 in
   [issue #26](https://github.com/JordanTheJet/zeroclaw/issues/26#issuecomment-5383167800),
   sweep item 15; see "Where the deployment trust root comes from" above.
3. **Resolved: child instances and the single key-source authority.** A child
   inherits the
   parent's deployment trust root while generating a distinct host key. If
   parent and child run on the same host, ADR-013's rule that one source is
   authoritative per deployment appears to be in tension with two instances
   holding distinct host keys. Whether "deployment" means the host, the install
   root, or the instance is not defined anywhere.

   **Resolution.** A deployment is the canonical install root, the config-root
   and data-root pair named in `canonical_roots`. Each instance root is its own
   deployment and its own key authority, so a child instance is a distinct
   deployment and the apparent tension disappears: parent and child holding
   distinct host keys is the single-authority rule applied once per deployment.
   Decided by the maintainer on 2026-08-22 in
   [issue #26](https://github.com/JordanTheJet/zeroclaw/issues/26#issuecomment-5383167800),
   sweep item 16; see "What a deployment is" above. This agrees with ADR-015 and
   is mirrored in `control-plane-principals-and-approvals.md`. The parent
   document and ADR-013 still need the matching wording.
4. **Resolved: trust epoch values are unspecified.** The parent document requires
   epochs to be monotonic and to appear in every audit row, but does not define
   their representation, whether they are per instance or per host, or how a
   child's epoch relates to its parent's. Two instances comparing epoch values
   across an inherited trust root would need that rule.

   **Resolution.** A trust epoch is a monotonic per-instance counter, recorded in
   the genesis record and in every audit row. A child's epoch is independent of
   its parent's, and epochs are compared only within one instance's chain. See
   "Trust epochs" above. Adopted from the gap-sweep resolution proposed in
   [issue #26](https://github.com/JordanTheJet/zeroclaw/issues/26), item 17.
5. **Resolved: recovery's effect on the target registry is unstated.** Recovery
   invalidates all pending proposals, client credentials, approval receipts, and
   resume secrets. It does not say whether registered target roots and approved
   creation parents survive recovery. Preserving them is convenient but means a
   registration made under a compromised epoch survives the recovery meant to
   contain that compromise. Discarding them is safer but leaves a recovered host
   unable to reach previously registered instances until an operator
   re-registers each one.

   **Resolution.** Recovery discards them. Registered target roots and approved
   creation parents do not survive an epoch break, and the operator re-registers
   each one afterwards through an ordinary meta-authority operation consuming a
   receipt under the new epoch. Containment was chosen over convenience
   deliberately, and the re-registration work is the accepted cost. Decided by
   the maintainer on 2026-08-22 in
   [issue #26](https://github.com/JordanTheJet/zeroclaw/issues/26#issuecomment-5383167800),
   sweep item 18; see "What recovery invalidates" and "Relationship to the target
   registry" above.
6. **Resolved: mutation enablement after recovery.** Genesis explicitly leaves
   mutations disabled until a separate ceremony. The parent document does not say
   whether recovery also resets mutation enablement to disabled. The conservative
   reading is that it does, since recovery replaces the operator set and host
   key, but this was not stated and the difference is observable.

   **Resolution.** Recovery resets mutation enablement to disabled, and
   re-enabling is a separate post-recovery ceremony with the original
   prerequisites. See "What recovery invalidates" above. Adopted from the
   gap-sweep resolution proposed in
   [issue #26](https://github.com/JordanTheJet/zeroclaw/issues/26), item 19.
7. **Resolved: the managed-instance marker is not specified.** The anti-reset
   rule
   depends
   on "the durable instance identity and prior genesis record" plus a
   "managed-instance marker", but the marker's location, format, and protection
   are undefined. Since the entire anti-reset property rests on it, its identity
   and the checks applied to it need to be pinned before implementation.

   **Resolution.** The durable genesis record is itself the marker. It lives at a
   fixed path under the canonical data root, is authenticated by the host key
   chain through an authentication tag and the `host_key_commitment` binding, is
   re-verified on every startup and audit read, and a record that is present but
   invalid enters recovery-only mode rather than becoming eligible for first
   genesis. There is no second marker file. Decided by the maintainer on
   2026-08-22 in
   [issue #26](https://github.com/JordanTheJet/zeroclaw/issues/26#issuecomment-5383167800),
   sweep item 20; see "The record is the managed-instance marker" above. This is
   implemented on the staged, unmerged `feat/control-trust-genesis` branch and is
   not on `master`.

   **Residual tension, not resolved.** A single-artifact marker cannot answer
   "has this root ever been managed?" once that artifact is deleted, so the
   parent document's rule covering a "missing or invalid genesis record" is
   narrowed to the invalid case. See "One tension this page does not resolve"
   above; closing it needs either a second durable artifact or an amendment to
   the parent wording, and neither has been chosen.

## Governance status

This page is a proposal. The parent document states that the control plane
creates a new configuration-mutation authority and new operator-principal
policy, and requires an accepted RFC before the external MCP or mutating surface
is treated as an implementation detail. Changes to approval authority, principal
assurance, plugin trust, or the stable control protocol require the matching
architecture decision or foundation amendment.

No RFC has been accepted for this work, and no architecture decision record
covers control-plane trust genesis. ADR-013 is itself still marked proposed and
its acceptance gates are not met, so this design depends on a record that is not
yet accepted. Publishing this page does not authorize implementation and must
not be cited as evidence that the design is accepted.
