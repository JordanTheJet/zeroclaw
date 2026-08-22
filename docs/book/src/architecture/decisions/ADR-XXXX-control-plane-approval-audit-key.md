---
id: ADR-XXXX
title: Control-plane approval and audit key derives from the single ADR-013 authority
date: 2026-08-21
status: Proposed (direction decided by maintainer 2026-08-21; see issue #24)
relates-to:
  - https://github.com/JordanTheJet/zeroclaw/issues/24
  - https://github.com/JordanTheJet/zeroclaw/issues/35
  - docs/book/src/architecture/decisions/ADR-013-key-source-authority.md
  - docs/book/src/architecture/control-plane-trust-genesis.md
  - docs/book/src/architecture/control-plane-principals-and-approvals.md
  - docs/book/src/architecture/chat-management-control-plane.md
  - crates/zeroclaw-config/src/secrets.rs
---

# ADR-XXXX: Control-Plane Approval And Audit Key Derives From The Single ADR-013 Authority

> **Decided direction, record still proposed.** The `ADR-XXXX` identifier is a
> placeholder. ADR-014 is already claimed on an off-`master` branch, so the
> maintainer allocates the final number when this record is accepted. The
> maintainer decided the direction in
> [issue #24 on 2026-08-21](https://github.com/JordanTheJet/zeroclaw/issues/24#issuecomment-5376601651);
> the Decision section below records that decision rather than a recommendation.
> The record stays `proposed` until the acceptance gates are met, and it does not
> by itself authorize implementation.

## Context

The chat-management control plane requires a host key that authenticates
approval receipts and anchors the audit chain. The parent architecture document
(`docs/book/src/architecture/chat-management-control-plane.md`) requires trust
genesis to "generate and seal the host approval/audit key in a platform key
source", and requires the receipt broker to sign or authenticate a receipt "with
a host key source unavailable to the requester tool surface". The trust-genesis
design (`control-plane-trust-genesis.md`) and the principals design
(`control-plane-principals-and-approvals.md`) both record this as a genuine
phase-3 blocker in their open-question lists.

[ADR-013](./ADR-013-key-source-authority.md) governs deployment key material. It
decides that one configured key source is authoritative for a deployment at a
time, that the assembly layer constructs one shared source authority per process
generation, and that a consumer may not reconstruct an authority or read backend
material directly. It then defers one question that is exactly this ADR's
subject:

> Whether a non-encryption consumer receives scoped access to the source or
> derives a purpose-specific subkey is a separate security decision. This ADR
> requires canonical acquisition but does not choose a derivation or
> compatibility contract [...]. Until that decision is recorded, a
> non-encryption consumer must not silently reuse the raw encryption master key.

The control-plane approval and audit key is precisely such a non-encryption
consumer, so ADR-013 forbids the obvious implementation (reuse the encryption
master key) until this record exists.

Two facts complicate the choice:

1. ADR-013's rule is "one configured source is authoritative for a deployment at
   a time." A second, independently selectable approval key source is not
   contemplated by that rule.
2. The parent document separately makes "changing management or audit key
   sources" its own meta-authority operation, which reads as if the management
   key source were independently selectable, in tension with fact 1.

This record chooses how the approval and audit key is obtained, and how the
"changing management or audit key sources" wording is reconciled with ADR-013.

## Options considered

### Option 1: Derived subkey under the single ADR-013 authority

Keep ADR-013's single authoritative key source. Derive the approval and audit
key from the deployment master key material inside the same `KeySource`
boundary, using HKDF-SHA256 with a fixed domain-separation label (for example
`zeroclaw/control-plane/approval-audit/v1`). The derived key is never returned as
raw bytes to any requester-facing surface. "Changing the management or audit key
source" collapses to "changing the deployment key source", which ADR-013 already
governs through migration and rotation, plus a control-plane trust-epoch bump.

- Positive: one authority, fully ADR-013 compatible; no second selection
  surface; no new persistent-ciphertext migration owner, because the subkey is
  deterministic from the master. Domain separation prevents cross-use with
  `enc2:` encryption.
- Negative: the approval key lifecycle is tied to the encryption master key, so
  rotating the master re-derives the approval key. This may be acceptable, or
  even desirable, because recovery already rotates the host key. It also requires
  the master source to expose exportable 32-byte material; ADR-013 notes that a
  non-exportable secure element needs an operation-based boundary, so a
  signing-only element could not satisfy this option by itself.

### Option 2: Second registered key-source authority with explicit scope

Introduce a distinct control-plane key source, resolved from typed config,
separate from the encryption master source, with its own provisioning,
availability, and fail-closed lifecycle mirroring ADR-013, and an explicit scope
label so it can never encrypt `enc2:` values. "Changing the management or audit
key source" becomes a first-class meta-authority operation on this second source.

- Positive: matches the parent document's "changing management or audit key
  sources" wording directly; full lifecycle independence (rotate the approval key
  without touching encryption); naturally supports an operation-only secure
  element for approvals while a file source holds encryption.
- Negative: directly contradicts ADR-013's single-authority rule unless ADR-013
  is amended to scope that rule to the encryption authority. Two authorities mean
  two provisioning and fail-closed code paths and two migration stories, so more
  surface and more ways to misconfigure. The second key is a new durable owner
  that must enter the migration and rotation inventory.

### Option 3: Operation-based approval authority (sign and verify), no exportable approval key

Define the approval and audit authority as a sign-and-verify capability: the
broker asks the key source to authenticate a receipt and never receives key
bytes. The signing key may live under the single authority (option 1) or a
separate source (option 2); this option fixes the *interface* as operations, not
raw bytes.

- Positive: strongest posture; the raw approval key never crosses the boundary,
  aligning with ADR-013's operation-based-boundary note for non-exportable
  elements, and receipts stay unforgeable even if the requester surface is later
  widened. Compatible with either a derived key or a second source underneath.
- Negative: requires the receipt format to be a verifiable signature or MAC over
  the canonical receipt fields, which is more design than a symmetric
  authenticator. It does not by itself answer where the signing key lives, so it
  must be combined with option 1 or option 2.

## Decision

**Option 1 is decided.** The maintainer decided this direction on 2026-08-21 in
the [issue #24 decision comment](https://github.com/JordanTheJet/zeroclaw/issues/24#issuecomment-5376601651).

The control-plane approval and audit key is an HKDF-SHA256 subkey derived from
the single ADR-013 key-source authority, under the fixed domain-separation label
`zeroclaw/control-plane/approval-audit/v1`. The derived key is never exportable,
and it is exposed only through sign and verify operations, so raw approval-key
bytes never reach the requester surface and a later move to a separate key
source (option 2) would not change the interface. The operation-based interface
of option 3 is therefore required, not merely preferred.

The tradeoff is accepted explicitly: rotating the master key re-derives, and so
rotates, the approval key. Independent approval-key rotation is out of scope
until a deployment needs it, at which point option 2 is the recorded path and the
receipt contract does not change.

Rationale, as decided:

- It honors ADR-013's single-authority rule through domain separation rather than
  by adding a second key source.
- It adds no operational surface for solo and headless deployments, which have no
  second source to provision, make available, or fail closed on.
- Domain-separated HKDF derivation is the standard pattern used by TLS 1.3 and
  AWS request signing, so the construction is auditable against known practice.

Supporting rationale from the option analysis:

- It is the smallest deviation from ADR-013. It honors "one configured source is
  authoritative per deployment" and satisfies exactly the deferred clause: the
  approval key is not a *silent* reuse of the raw encryption master key, but a
  domain-separated derivation recorded in this record.
- Domain-separated HKDF is a standard, auditable construction; the label binds
  the subkey to the control-plane purpose and a version, so a later contract
  change is a new label rather than a silent reinterpretation.
- Specifying the receipt as a MAC or signature that the source computes keeps the
  approval key inside the boundary and lets a future deployment swap in an
  operation-only source (option 2 or a secure element) without changing the
  receipt contract. The design gains option 2's flexibility later without paying
  its two-authority cost now.
- The parent document's "changing management or audit key sources is a
  meta-authority operation" is reconciled as follows: on a single-authority
  deployment, changing the encryption key source is already an ADR-013 migration;
  because the approval key is derived from it, that migration re-derives the
  approval key, and the control plane records a trust-epoch transition. The parent
  document should be amended to say the management and audit key source is the
  deployment authority, not a second selectable source, unless and until option 2
  is adopted.

### What this unblocks

Phase 3 (issue #29) trust genesis can seal the approval and audit key by deriving
it and committing `host_key_commitment`, and phase 4 (issue #30) can authenticate
receipts, both without a second key-source authority and without violating
ADR-013. Companion amendments are required in `control-plane-trust-genesis.md`
(the "Key material and ADR-013" section and its open question 1) and
`control-plane-principals-and-approvals.md` (its open question 1), each updated to
cite this record.

### Acceptance gates

This record remains proposed until all of these conditions are met:

- the HKDF construction, the domain-separation label, and the requirement that
  the master source expose exportable 32-byte material (or fall back to an
  operation-only variant) are specified against the `KeySource` boundary in
  `crates/zeroclaw-config/src/secrets.rs`;
- the receipt authentication interface is defined as an operation over the
  canonical receipt fields (proposal digest, target instance, source revision,
  decision, trust epoch, receipt id), and the raw approval key is never returned
  to any requester-facing surface;
- genesis `host_key_commitment` and recovery `new_host_key_commitment` are
  defined as commitments to the derived approval and audit key;
- ADR-013's single-authority rule is confirmed to cover this consumer, with any
  scoping amendment filed against ADR-013 while it is still proposed; and
- the trust-genesis and principals design documents are amended to cite this
  record.

## Consequences

Positive consequences:

- Phase 3 and phase 4 gain a concrete, ADR-013-compatible key story instead of a
  deferred blocker.
- One key-source authority keeps the deployment's fail-closed lifecycle single
  and testable.
- An operation-based receipt interface means a later hardware or second-source
  upgrade does not change the receipt contract.

Negative consequences:

- The approval key inherits the master key's rotation and its synchronous
  exposure window; deployments that need an independent approval-key lifecycle
  must revisit option 2.
- A signing-only secure element cannot serve as the sole master source under this
  option; such deployments need the operation-only boundary ADR-013 anticipates.
- The parent document and ADR-013 both need small amendments to state the scoping
  explicitly.

## References

- Issue [#24: Decision: approval/audit key source vs ADR-013](https://github.com/JordanTheJet/zeroclaw/issues/24)
- Issue [#35: Control plane initiative tracker](https://github.com/JordanTheJet/zeroclaw/issues/35)
- [ADR-013: Master key acquisition uses one configured key-source authority](./ADR-013-key-source-authority.md)
- `docs/book/src/architecture/chat-management-control-plane.md` (parent architecture document)
- `docs/book/src/architecture/control-plane-trust-genesis.md`
- `docs/book/src/architecture/control-plane-principals-and-approvals.md`
- `crates/zeroclaw-config/src/secrets.rs`
