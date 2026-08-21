---
id: ADR-XXXX
title: First control-plane client is registered receipt-exempt inside the genesis ceremony
date: 2026-08-21
status: proposed
relates-to:
  - https://github.com/JordanTheJet/zeroclaw/issues/25
  - https://github.com/JordanTheJet/zeroclaw/issues/35
  - docs/book/src/architecture/control-plane-principals-and-approvals.md
  - docs/book/src/architecture/control-plane-trust-genesis.md
  - docs/book/src/architecture/chat-management-control-plane.md
---

# ADR-XXXX: First Control-Plane Client Is Registered Receipt-Exempt Inside The Genesis Ceremony

> **Draft decision record.** The `ADR-XXXX` identifier is a placeholder. ADR-014
> is already claimed on an off-`master` branch, so the maintainer allocates the
> final number when this record is accepted. Drafted for issue
> [#25](https://github.com/JordanTheJet/zeroclaw/issues/25); it proposes options
> and a recommendation for a human to decide, and does not authorize
> implementation.

## Context

The control-plane phases are circularly ordered as written. Phase 3 adds
external client registration. The principals design
(`control-plane-principals-and-approvals.md`) records that registration is a
meta-authority operation, alongside grant widening, revocation, and credential
rotation. Meta-authority operations require an approval receipt issued under the
existing trust epoch, and the receipt broker arrives in phase 4. Only trust-root
genesis and recovery are exempt from consuming a prior receipt.

So the first client cannot be registered in phase 3: registration needs a
receipt, receipts need the phase-4 broker, and the phase-4 broker needs an
authenticated operator and backchannel that genesis produces. Both design docs
record this as an open question that blocks phase 3 and affects what a phase-3
pull request can honestly claim.

The parent document already resolves the analogous problem for operators: genesis
establishes the first operator without a prior receipt, because there is no prior
authority to issue one. This record decides whether the first *client* is
established the same way, or whether the phases are reordered instead.

## Options considered

### Option 1: Genesis-time bootstrap registration

The genesis and mutation-enablement ceremony may register the first client or
clients under the same user-presence assurance (interactive host) or
deployment-trust-root assurance (headless host) that authorizes the first
operator, receipt-exempt, exactly as the first operator is established without a
prior receipt.

- Positive: mirrors the existing genesis exemption, so it adds no new *kind* of
  trust boundary. Phase 3 can ship registration honestly: the only receipt-exempt
  registration is the ceremony itself, and every later registration goes through
  the phase-4 receipt path. No phase reordering is required.
- Negative: it widens the receipt-exempt surface from "genesis and recovery" to
  "genesis, recovery, and first-client registration", which must be bounded
  precisely so it cannot become a general bypass. The first client is registered
  before mutations are enabled, so the ceremony must record it without granting
  any approval authority.

### Option 2: Reorder, land the receipt broker before registration

Ship the operator backchannel and approval-receipt broker (the phase-4 core)
first, then let registration consume a real receipt like every other
meta-authority operation. No exemption is added.

- Positive: zero new exemptions; registration is uniform with all later
  meta-authority operations from day one, the cleanest trust story.
- Negative: it does not actually remove the bootstrap step, it relocates it.
  Genesis must still seed the first operator receipt-free, and the first
  registration then needs that operator to approve over the backchannel. That is
  workable, but it means phase 3's registration cannot land until phase 4's
  broker is complete, collapsing the phase-3 and phase-4 boundary and producing a
  larger first landable unit that is harder to gate adversarially in small steps.

### Option 3: A narrow, enumerated bootstrap meta-authority class

Define a small, closed set of meta-authority operations (first-client
registration among them) authorized by genesis-equivalent assurance and valid
only during the bootstrap window, that is, before the operator enables mutations.
Once mutations are enabled, the bootstrap class is permanently closed and every
meta-authority operation requires a receipt.

- Positive: generalizes option 1 into a principled, auditable window tied to an
  observable state transition (mutation enablement) the design already defines.
  Each bootstrap operation is enumerated and gated, so the exemption cannot
  silently grow.
- Negative: more machinery than option 1: a window state, a closing transition,
  and an invariant that the class is empty afterward, each needing its own tests.
  The window is a distinct trust state that adversarial review must cover, for
  example what happens if it never closes, or whether recovery reopens it.

## Decision

Adopt **option 1 (genesis-time bootstrap registration), specified as the minimal
case of option 3's bootstrap window**: the receipt exemption is limited to
registrations performed inside the genesis and mutation-enablement ceremony, each
recorded in the audit chain with its own anchor, and no registration is
receipt-exempt after mutation enablement.

Rationale:

- It resolves the circularity with the least new trust surface. It reuses the
  exemption the design already grants genesis, under which the first operator is
  established without a receipt, and establishes the first client the same way
  under the same assurance.
- It keeps phase 3 honest and independently landable. Phase 3 ships registration
  whose only receipt-exempt path is the ceremony, and whose ordinary path is
  explicitly deferred to the phase-4 broker: a registration attempted outside the
  ceremony fails closed with a "receipt broker not present" refusal until phase 4
  exists. That is exactly what a phase-3 pull request can truthfully claim.
- It does not require reordering (option 2) or a general open-ended bootstrap
  class (full option 3). It takes option 3's key safety property, a bounded,
  enumerated set that closes at mutation enablement, without its full machinery,
  because the only bootstrap meta-authority operation in phase 3 is first-client
  registration.

The exemption is bound tightly:

- it applies only to registrations performed inside the genesis or
  mutation-enablement ceremony;
- the bootstrap-registered client receives no approval authority, consistent with
  the principals rule that registration never grants approval;
- the registration record's `created_by` references the genesis or enablement
  operation digest rather than a receipt; and
- recovery invalidates bootstrap-registered clients unless they are
  re-established, consistent with recovery invalidating credentials issued under a
  prior epoch, and with the genesis design's open question on recovery versus the
  target and registration registry.

### What this unblocks

Phase 3 (issue #29) can add client registration and the target registry with a
truthful trust story, and phase 4 (issue #30) then adds the receipt broker so
every post-enablement registration flows through it. Companion amendments are
required in `control-plane-principals-and-approvals.md` (the client-registration
section and its open question on the circular ordering) and
`control-plane-trust-genesis.md` (the interactive and headless genesis ceremonies
gain an explicit "may register the first client or clients, receipt-exempt,
within the ceremony" step, and recovery states its effect on bootstrap
registrations).

### Acceptance gates

This record remains proposed until all of these conditions are met:

- the genesis and mutation-enablement ceremonies define the first-client
  registration step, its assurance class, and its audit anchor;
- registration performed after mutation enablement is specified to require a
  phase-4 receipt and to fail closed until the broker exists;
- the bootstrap-registered client is confirmed to receive no approval authority
  and to carry `created_by` equal to the ceremony operation digest;
- recovery's effect on bootstrap-registered clients is stated as invalidate
  unless re-established; and
- the principals and genesis design documents are amended to cite this record.

## Consequences

Positive consequences:

- The phase-3 and phase-4 ordering is no longer circular, and phase 3 can land
  independently with an honest trust claim.
- The receipt-exempt surface stays small, enumerated, and closed at a defined
  state transition.
- The rule reuses the operator-bootstrap exemption the design already relies on,
  so it adds no new kind of trust boundary.

Negative consequences:

- The genesis ceremony gains a registration responsibility, and adversarial
  review must cover the bootstrap window's boundaries, including recovery.
- A deployment that wants no receipt-exempt client registration at all must
  choose option 2 instead and accept the collapsed phase boundary.

## References

- Issue [#25: Decision: client-registration bootstrap circularity (phases 3/4)](https://github.com/JordanTheJet/zeroclaw/issues/25)
- Issue [#35: Control plane initiative tracker](https://github.com/JordanTheJet/zeroclaw/issues/35)
- `docs/book/src/architecture/control-plane-principals-and-approvals.md`
- `docs/book/src/architecture/control-plane-trust-genesis.md`
- `docs/book/src/architecture/chat-management-control-plane.md` (parent architecture document)
