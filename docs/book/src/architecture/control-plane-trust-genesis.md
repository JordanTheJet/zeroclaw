# Design: control-plane trust genesis and recovery ceremonies

> **Status: proposed.** Nothing on this page is implemented. There is no
> control-plane genesis record, no trust epoch, no target registry, and no
> recovery ceremony anywhere on `master`. This page describes what the trust
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
key is a non-encryption consumer. That unresolved intersection is recorded in
"Open questions" and is a genuine blocker for phase 3.

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

### Relationship to the target registry

Genesis registers the default instance in the signed target registry. Each
registry record contains canonical config and data roots, ownership and
permission checks, allowed creation parent, instance fingerprint, trust epoch,
and status.

Registering another existing root, or an approved creation parent, is a
meta-authority operation rather than part of genesis. Apply resolves the target
ID from this registry under the registry and instance locks, and the caller
never supplies a path at apply time.

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

## Open questions

These are gaps or ambiguities in the parent architecture document or its
interaction with existing records. They are recorded for the maintainer to
settle and are deliberately not resolved here.

1. **ADR-013's single-authority rule versus a separate control-plane key.**
   ADR-013 records that one configured key source is authoritative for a
   deployment at a time, and that the assembly layer constructs one shared
   source authority per process generation. The parent architecture requires
   genesis to seal a distinct host approval and audit key, and separately makes
   "changing management or audit key sources" its own meta-authority operation,
   which implies the management key source is independently selectable. Whether
   the control plane uses the deployment's single authority, or introduces a
   second authority that ADR-013 does not contemplate, is unresolved. It needs a
   decision record before phase 3 can be implemented. This gap is also recorded
   in `control-plane-principals-and-approvals.md`.
2. **The deployment trust root has no defined provenance.** Headless genesis is
   authorized by "an administrator signature or platform attestation" verified
   against a deployment trust root, and headless recovery by a
   deployment-trust-root-signed manifest. The parent document never says how the
   deployment trust root itself is established on the host, who may change it, or
   what prevents the same process that writes the manifest from also writing the
   trust root it is verified against. Without that, headless genesis assurance is
   asserted rather than derived.
3. **Child instances and the single key-source authority.** A child inherits the
   parent's deployment trust root while generating a distinct host key. If
   parent and child run on the same host, ADR-013's rule that one source is
   authoritative per deployment appears to be in tension with two instances
   holding distinct host keys. Whether "deployment" means the host, the install
   root, or the instance is not defined anywhere.
4. **Trust epoch values are unspecified.** The parent document requires epochs to
   be monotonic and to appear in every audit row, but does not define their
   representation, whether they are per instance or per host, or how a child's
   epoch relates to its parent's. Two instances comparing epoch values across an
   inherited trust root would need that rule.
5. **Recovery's effect on the target registry is unstated.** Recovery
   invalidates all pending proposals, client credentials, approval receipts, and
   resume secrets. It does not say whether registered target roots and approved
   creation parents survive recovery. Preserving them is convenient but means a
   registration made under a compromised epoch survives the recovery meant to
   contain that compromise. Discarding them is safer but leaves a recovered host
   unable to reach previously registered instances until an operator
   re-registers each one.
6. **Mutation enablement after recovery.** Genesis explicitly leaves mutations
   disabled until a separate ceremony. The parent document does not say whether
   recovery also resets mutation enablement to disabled. The conservative
   reading is that it does, since recovery replaces the operator set and host
   key, but this is not stated and the difference is observable.
7. **The managed-instance marker is not specified.** The anti-reset rule depends
   on "the durable instance identity and prior genesis record" plus a
   "managed-instance marker", but the marker's location, format, and protection
   are undefined. Since the entire anti-reset property rests on it, its identity
   and the checks applied to it need to be pinned before implementation.

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
