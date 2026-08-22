# Specification: read-only control MCP protocol v1

> **Status: proposed.** Nothing on this page is implemented. There is no
> `zeroclaw control` subcommand, no control MCP server, and no
> `zeroclaw-control` crate on `master`. This specification describes the
> surface that a future phase-2 implementation would have to build in order to
> be reviewable. It is not an accepted protocol and no compatibility promise
> attaches to it.

This page is subordinate to the parent architecture document
`docs/book/src/architecture/chat-management-control-plane.md`, which is itself
marked proposed and currently lives on an unmerged documentation branch rather
than on `master`. Where that document already states a rule, this page cites it
and refines the wire detail; it never restates a rule more loosely and never
grants a capability the parent withholds. If the two disagree, the parent
document wins and this page is wrong.

## Scope

The parent document's phased delivery defines phase 2 as:

> **Read-only MCP.** Add stdio initialization, Catalog, Describe, Inspect,
> Validate, and Preview for contained agent creation. Until client registration
> lands, fixture credentials are test-only and no default agent or external
> process receives a grant.

This specification covers exactly that surface. It deliberately does not
specify Request apply, Status, Verify, approval, registration mutation, or any
other operation that changes host state. Those belong to phases 3 through 5 and
are designed in the companion pages
`control-plane-principals-and-approvals.md`,
`control-plane-trust-genesis.md`, and `control-plane-proposal-journal.md`.

## What exists on `master` today

Verified against `master` at the time of writing:

- `crates/zeroclaw-tools/src/mcp_client.rs`, `mcp_protocol.rs`,
  `mcp_transport.rs`, `mcp_tool.rs`, and their siblings implement ZeroClaw as an
  MCP **client**. ZeroClaw consumes external MCP servers today.
- There is no MCP **server** surface, no `control` CLI subcommand, and no
  crate under `crates/` named `zeroclaw-control` or `zeroclaw-onboarding`.
- `zeroclaw-control` is the decided crate name for this work. It is staged,
  unmerged work that does not exist on `master`; every reference to it on this
  page is forward-looking.

Everything below is therefore new construction, not documentation of shipped
behavior.

## Normative source of truth

The parent document's first drift-prevention rule is binding here:

> MCP schemas are generated from the Rust request and response types.

That produces a strict ordering of authority:

1. The Rust request and response types in the staged `zeroclaw-control` crate
   **normatively define** the wire schema.
2. The JSON Schema documents served to clients are **generated** from those
   types by the build, not hand written.
3. This specification **documents** the intended shape so the design can be
   reviewed before the types exist. It has no independent authority.

A reviewer who finds a difference between this page and the compiled types
should treat the types as correct and this page as stale. CI must fail when the
generated schemas do not match the compiled types, and manual edits to a
generated schema artifact must fail CI. No client, skill, or prompt may carry a
second copy of the field list; clients call Catalog and Describe instead.

## Transport and process model

The external entry point is provisionally:

```text
zeroclaw control --mcp
```

The parent document flags the final command and product name as an open
decision, so the spelling above is provisional even though the request and
response shapes below are meant to be precise.

Binding process rules, all inherited from the parent document:

- The transport is stdio JSON-RPC. HTTP and remote MCP are out of scope and
  require a separate authenticated-principal and network-exposure design.
- The process starts on demand and has no resident mode.
- The process pins its config and data roots at startup. No tool accepts an
  arbitrary target path.
- Launching the command creates a **requester** principal only. A TTY, a
  loopback address, the process parent, the OS account, and any environment
  variable never upgrade that classification.
- MCP mode makes no model request. See "No model request" below.

Native in-process tools for ZeroClaw agents and this MCP surface must compile to
the same request and response types, and transport parity is a CI requirement:
the same operation submitted natively and over MCP must produce the same
canonical preview, operation digest, requester classification, and authorization
result.

## Tool inventory and gating

The parent document fixes the gating rule:

> If the host cannot prove that separation, the client remains unregistered and
> the stdio endpoint exposes exactly Initialize, Ping, ServerInfo, and
> RegistrationHelp. Catalog, Describe, Inspect, Validate, Preview, Request
> apply, Status, and Verify require a registered requester grant.

| Conceptual operation | Wire name | Availability in v1 | Host effect |
|---|---|---|---|
| Initialize | `initialize` (MCP lifecycle method) | Always | None |
| Ping | `control.ping` | Always | None |
| ServerInfo | `control.server_info` | Always | None |
| RegistrationHelp | `control.registration_help` | Always | None |
| Catalog | `control.catalog` | Registered grant | None |
| Describe | `control.describe` | Registered grant | None |
| Inspect | `control.inspect` | Registered grant | None |
| Validate | `control.validate` | Registered grant | None |
| Preview | `control.preview` | Registered grant | None |
| Request apply | not present in v1 | Never in v1 | n/a |
| Status | not present in v1 | Never in v1 | n/a |
| Verify | not present in v1 | Never in v1 | n/a |

The parent document states that exact names remain a protocol-design decision.
The `control.` prefix and the snake-case member names above are this page's
proposal, not a settled fact. See "Open questions".

An unregistered client that calls a grant-gated tool receives
`unregistered_client`. The tool must not appear in `tools/list` for that
session at all: absence is the primary control and the error is the backstop.
A tool name that does not exist in this version returns `unknown_operation`
rather than a partially implemented behavior.

## Result envelope

Every control tool returns MCP `structuredContent` conforming to its generated
schema, plus a `content` array holding one `text` item with the canonical JSON
serialization of the same value, for clients that cannot read
`structuredContent`. The two representations must be byte-identical after
canonical serialization; a CI test enforces that.

Every successful result carries an envelope header:

```json
{
  "control_protocol_version": "1.0",
  "capability_digest": "sha256:...",
  "result": {}
}
```

`capability_digest` is repeated on every response so a client can detect a
server capability change mid-session. The parent document binds the capability
digest into every proposal, so a change invalidates an outstanding preview.

## Errors

Errors are typed and fail closed. The error payload is:

```json
{
  "error": {
    "code": "grant_required",
    "message": "This client is not granted the requested read domain.",
    "operation": "control.inspect",
    "retryable": false,
    "details": {}
  }
}
```

Stable codes defined by v1:

| Code | Meaning |
|---|---|
| `unregistered_client` | The session has no registered client credential |
| `grant_required` | Registered, but the grant does not cover this target, domain, or view |
| `unknown_operation` | No such operation in this protocol version |
| `unsupported_protocol_version` | Client and server major versions do not intersect |
| `capability_digest_mismatch` | The client supplied a digest the server no longer advertises |
| `target_not_registered` | The requested target ID is not in the signed target registry |
| `validation_failed` | The typed operation did not validate; see `diagnostics` |
| `stale_source_revision` | The pinned source revision no longer matches |
| `internal_error` | Unclassified host failure |

`message` and `details` must never contain secret values, absolute config,
data, workspace, credential, or plugin paths, account identifiers, raw provider
error bodies, environment values, headers, or the existence of another
registered target. The parent document requires redaction to be covered by
fixture tests for both successful and error responses; that requirement applies
to every code in the table above.

## Initialization

`initialize` is the MCP lifecycle request rather than a tool. The parent
document names Initialize alongside three tools in its always-available list;
this specification maps that name onto the lifecycle method rather than
inventing a second initialization path.

That mapping is confirmed: Initialize is the MCP lifecycle method and is not a
callable tool. There is no `control.initialize`. Parity with the native
transport is met by the shared advertisement block, which both transports return
from the same canonical source, so nothing is lost by not exposing a second
initialization entry point. Adopted from the gap-sweep resolution proposed in
[issue #26](https://github.com/JordanTheJet/zeroclaw/issues/26), item 22.

Request parameters relevant to the control protocol:

```json
{
  "protocolVersion": "2025-06-18",
  "clientInfo": {
    "name": "claude-code",
    "version": "1.2.3"
  },
  "_meta": {
    "zeroclaw_control": {
      "supported_control_protocol_versions": ["1.0"],
      "client_registration_id": "reg_01J..."
    }
  }
}
```

`client_registration_id` is an attribution hint only. It is not a credential
and never authenticates the client. Credential material is obtained by the
stdio proxy through an approved client-specific credential helper or inherited
descriptor, never through an MCP argument, a command-line argument, an ordinary
environment variable, a prompt, or a model-visible config value.

### Advertisement block

Every MCP initialization response advertises, verbatim from the parent
document:

```json
{
  "zeroclaw_version": "0.9.0",
  "control_protocol_version": "1.0",
  "config_schema_version": 3,
  "capabilities": ["agents", "providers", "plugins"],
  "capability_digest": "sha256:..."
}
```

| Field | Type | Meaning |
|---|---|---|
| `zeroclaw_version` | string | Product version. Informational except where a package or adapter declares an explicit compatibility range |
| `control_protocol_version` | string | `major.minor` of this protocol. Major mismatch fails closed |
| `config_schema_version` | integer | Canonical config schema version. Interpretation is server-owned; clients submit adapter operations, not version-specific config fields |
| `capabilities` | array of string | Capability identifiers the running server implements |
| `capability_digest` | string | `sha256:` digest over the canonical capability set, bound into every proposal |

The example above is the parent document's illustration, not a phase-2
inventory. A phase-2 server implements contained agent creation only and
advertises `["agents"]`.

`capabilities` enumerates what the running server implements, never what the
product supports. That is confirmed, and only that reading is safe for
negotiation: a client that trusted a product-level list would attempt an
operation this server cannot perform, and the failure would surface as a
protocol error rather than as an honest capability mismatch. Adopted from the
gap-sweep resolution proposed in
[issue #26](https://github.com/JordanTheJet/zeroclaw/issues/26), item 24.

The block is returned in two places and the two must be byte-identical:

1. the `initialize` result, under `_meta.zeroclaw_control`; and
2. the `control.server_info` tool result.

The carrier location inside the `initialize` result is confirmed as
`_meta.zeroclaw_control`. The advertisement does not ride in
`capabilities.experimental`, which reads poorly for a protocol intended to
become stable and would suggest the block is optional or provisional. The two
carriers stay byte-identical after canonical serialization, and a CI test
enforces that byte identity. Adopted from the gap-sweep resolution proposed in
[issue #26](https://github.com/JordanTheJet/zeroclaw/issues/26), item 23.

### Version negotiation

From the parent document:

- the client declares a supported protocol range, and an unknown major version
  fails closed with `unsupported_protocol_version`;
- additive minor capabilities are negotiated from the running server;
- a server minor version may add capabilities but cannot change the meaning of
  an existing operation; and
- the server never weakens authorization, approval, redaction, replay, or drift
  checks to accommodate an older client.

An operation declares required server and operator-backchannel capabilities. If
either side cannot represent every effect and confirmation requirement, the
operation is rejected rather than downgraded. Protocol downgrade must not remove
a security-required capability, and CI must prove it.

## Always-available tools

These three tools are the entire surface of an unregistered session.

### `control.ping`

Liveness only. It discloses no configured state, no target identity, and no
registration status.

Request:

```json
{}
```

Response:

```json
{
  "control_protocol_version": "1.0",
  "capability_digest": "sha256:...",
  "result": {
    "ok": true,
    "server_time": "2026-08-21T09:14:02Z"
  }
}
```

`server_time` is the host wall clock in RFC 3339 UTC. It exists so a client can
detect gross clock skew before requesting a preview. It is not an authority for
expiration; expiration is host-evaluated as described in
`control-plane-proposal-journal.md`.

### `control.server_info`

Returns the advertisement block plus the bounded facts an unregistered client
needs to decide what to do next.

Request:

```json
{}
```

Response:

```json
{
  "control_protocol_version": "1.0",
  "capability_digest": "sha256:...",
  "result": {
    "advertisement": {
      "zeroclaw_version": "0.9.0",
      "control_protocol_version": "1.0",
      "config_schema_version": 3,
      "capabilities": ["agents"],
      "capability_digest": "sha256:..."
    },
    "session": {
      "registration_state": "unregistered",
      "requester_class": "external_requester",
      "assurance_class": null
    },
    "mutation_tools": [],
    "read_only": true
  }
}
```

Disclosure rules for this tool:

- `mutation_tools` is the empty array in v1 because no mutation tool exists in
  this protocol version. It is a statement about the protocol, not about the
  instance.
- `read_only` is likewise a constant `true` in v1.
- The tool must **not** report the instance's `[management] mutations_enabled`
  value, the number or identity of registered clients, any target ID, any path,
  or whether any instance is registered at all. Those are configured-instance
  facts and remain behind a grant.
- `registration_state` is limited to `"unregistered"` or `"registered"` for the
  calling session only. It says nothing about other sessions or clients.

### `control.registration_help`

Static, generated guidance that tells a human how to register this client. It
is the only always-available tool that acknowledges registration exists.

Request:

```json
{}
```

Response:

```json
{
  "control_protocol_version": "1.0",
  "capability_digest": "sha256:...",
  "result": {
    "registration_state": "unregistered",
    "registration_is_meta_authority": true,
    "accepted_assurance_classes": [
      "isolated_descriptor",
      "sandbox_isolated_store"
    ],
    "rejected_assurance_classes": ["uid_ambient"],
    "operator_steps": [
      "Registration is performed by an operator on the host, not through this MCP session.",
      "The operator selects a credential delivery mechanism in an accepted assurance class.",
      "The operator grants explicit instances, read domains, and proposal domains.",
      "Registration never grants approval authority."
    ],
    "documentation": "docs/book/src/architecture/control-plane-principals-and-approvals.md"
  }
}
```

Rules:

- The response is generated from canonical host metadata, not hand maintained
  in a skill or prompt.
- It contains no registration token, no nonce, no challenge, no path, and no
  callback the model could complete. A model can read this and still not
  register itself.
- Client registration, grant widening, revocation, and credential rotation are
  meta-authority operations performed by an operator. This tool describes that
  fact; it never initiates it.

## Grant-gated tools

Each of these requires a registered requester grant, and authorization is the
intersection of that grant, current policy, target registration, and operation
class. A requester denied Inspect or Propose natively is denied through MCP.

### `control.catalog`

Lists product-supported operation kinds. The parent document is explicit that
Catalog "describes product-supported operation kinds and contains no configured
instance state". Catalog output must therefore be identical for two registered
clients with the same grant on hosts with different configurations.

Request:

```json
{
  "domains": ["agent"]
}
```

`domains` is an optional filter. Omitting it returns every operation the grant
covers.

Catalog output is filtered by the grant's proposal domains, which is confirmed
rather than merely proposed. A narrowly granted client learns only about the
operations it could actually propose. This is compatible with the parent
document's rule that Catalog carries no configured instance state: the filter is
a function of the grant, which the client already knows, not of the host's
configuration, so two clients holding the same grant still see identical output
on differently configured hosts. Adopted from the gap-sweep resolution proposed
in [issue #26](https://github.com/JordanTheJet/zeroclaw/issues/26), item 25.

Response:

```json
{
  "control_protocol_version": "1.0",
  "capability_digest": "sha256:...",
  "result": {
    "config_schema_version": 3,
    "operations": [
      {
        "operation_id": "agent.create_contained",
        "domain": "agent",
        "title": "Create a contained agent",
        "summary": "Create one agent restricted to an existing provider, built-in risk and runtime presets, memory, and personality files.",
        "operation_class": "ordinary",
        "requires_approval": true,
        "meta_authority": false,
        "stability": "experimental",
        "since_control_protocol_version": "1.0",
        "effect_kinds": ["config", "personality_file"]
      }
    ]
  }
}
```

`requires_approval` is `true` for every mutating operation. The parent document
states that the first stable protocol has no unapproved mutation class. In v1
this field is descriptive only, because no apply path exists to exercise it.

### `control.describe`

Returns the current typed requirements for one operation, generated from the
adapter implementation and the canonical config schema.

Request:

```json
{
  "operation_id": "agent.create_contained",
  "target": { "target_id": "inst_01J..." }
}
```

Response:

```json
{
  "control_protocol_version": "1.0",
  "capability_digest": "sha256:...",
  "result": {
    "operation_id": "agent.create_contained",
    "config_schema_version": 3,
    "requirements_digest": "sha256:...",
    "request_schema": {},
    "response_schema": {},
    "required_server_capabilities": ["agents"],
    "required_backchannel_capabilities": ["render_agent_effects"],
    "dependency_kinds": ["provider_alias", "risk_profile", "runtime_preset"],
    "disclosure": {
      "read_domains": ["agent.summary", "provider.alias_list"]
    }
  }
}
```

`request_schema` and `response_schema` are the generated JSON Schema documents
for the compiled Rust types. They are embedded rather than referenced by URL so
an offline client can validate without network access.

`required_backchannel_capabilities` exists at phase 2 for shape parity even
though no backchannel is contacted in a read-only release. It lets a client
learn early that an operation could not be approved on this host once phases 3
and 4 land.

### `control.inspect`

Returns a redacted view of current relevant state, filtered by the requester's
target and domain grant.

Request:

```json
{
  "target": { "target_id": "inst_01J..." },
  "view": "agent.summary",
  "operation_id": "agent.create_contained"
}
```

`operation_id` is optional and narrows the view to the minimum disclosure that
operation declares. When it is present, the host resolves the smaller of the
two views.

Response:

```json
{
  "control_protocol_version": "1.0",
  "capability_digest": "sha256:...",
  "result": {
    "target": {
      "target_id": "inst_01J...",
      "instance_fingerprint": "sha256:..."
    },
    "view": "agent.summary",
    "source_revision": "rev_01J...",
    "items": [
      {
        "alias": "research",
        "kind": "agent",
        "availability": "configured",
        "health": "ok",
        "policy_summary": "contained; no shell; no egress exceptions"
      }
    ],
    "observations": [
      {
        "subject": "provider.default",
        "category": "reachable",
        "frozen": false
      }
    ]
  }
}
```

The parent document's disclosure denial list applies in full. An Inspect
response does not return secret or encrypted values, absolute config, data,
workspace, credential, or plugin paths, account identifiers, raw provider error
bodies, ungranted agent, integration, MCP, plugin, or policy aliases, raw logs,
environment values, headers, plugin configuration, or the existence of another
registered target.

`observations` carry `frozen: false` because health facts that cannot be frozen
are labeled as observations and repeated during verification rather than
presented as apply-time guarantees.

### `control.validate`

Validates a proposed typed operation. No host effect, no durable state.

Request:

```json
{
  "target": { "target_id": "inst_01J..." },
  "operation_id": "agent.create_contained",
  "operation": {}
}
```

`operation` conforms to the `request_schema` returned by Describe.

Response:

```json
{
  "control_protocol_version": "1.0",
  "capability_digest": "sha256:...",
  "result": {
    "valid": false,
    "operation_digest": "sha256:...",
    "source_revision": "rev_01J...",
    "config_schema_version": 3,
    "diagnostics": [
      {
        "severity": "error",
        "code": "provider_alias_unknown",
        "path": "provider_alias",
        "message": "No granted provider alias with that name."
      }
    ]
  }
}
```

`operation_digest` is computed by the host over the canonical serialization of
the typed operation. Neither the caller nor free-form model output selects the
fields that participate in the digest; the framework derives them from the
typed operation.

### `control.preview`

Returns canonical effects, risks, and the verification plan. No host effect in
v1.

Request:

```json
{
  "target": { "target_id": "inst_01J..." },
  "operation_id": "agent.create_contained",
  "operation": {}
}
```

Response:

```json
{
  "control_protocol_version": "1.0",
  "capability_digest": "sha256:...",
  "result": {
    "preview_id": "prv_01J...",
    "durable": false,
    "operation_digest": "sha256:...",
    "dependency_digest": "sha256:...",
    "target": {
      "target_id": "inst_01J...",
      "instance_fingerprint": "sha256:..."
    },
    "source_revision": "rev_01J...",
    "config_schema_version": 3,
    "expires_at": "2026-08-21T09:29:02Z",
    "effects": [
      {
        "effect_id": "e1",
        "artifact_kind": "config",
        "action": "create",
        "redacted_summary": "Add one contained agent entry.",
        "reversible": true,
        "rollback_artifact": "config_snapshot"
      },
      {
        "effect_id": "e2",
        "artifact_kind": "personality_file",
        "action": "create",
        "redacted_summary": "Write one personality file for the new agent.",
        "reversible": true,
        "rollback_artifact": "file_snapshot"
      }
    ],
    "apply_order": ["e1", "e2"],
    "irreversible_effects": [],
    "risks": [
      {
        "code": "new_agent_capability_surface",
        "severity": "medium",
        "summary": "A new agent gains the configured provider and preset."
      }
    ],
    "verification_plan": [
      {
        "check": "agent_present_in_effective_config",
        "expectation": "The alias resolves after reload."
      }
    ]
  }
}
```

Critical v1 constraints:

- `durable` is always `false` in v1. Preview creates no parked proposal, writes
  no journal row, and consumes no quota beyond process-local rate limiting.
  Durable parking arrives with Request apply in phase 5.
- `preview_id` is process-local in v1 and does not survive a restart. It is not
  a resume secret and conveys no authority.
- The preview is not an approval, and there is no tool in v1 that could turn it
  into one. The parent document is explicit that there is no model-callable
  Finalize operation and that a model cannot satisfy approval by passing
  `approved: true`, replaying a nonce, calling a second tool, or invoking a
  different transport.
- `irreversible_effects` must enumerate any effect that cannot be rolled back.
  The parent document requires irreversible external side effects to be
  identified in the preview and to be impossible before approval.

## No model request

MCP mode makes no LLM request. Concretely, in a phase-2 implementation:

- the control MCP entry point must not construct a model provider client, load
  provider credentials, or resolve a provider alias to an endpoint;
- Catalog, Describe, Inspect, Validate, and Preview are computed from the
  canonical schema, the adapter implementations, and the current configuration;
  none of them consults a model; and
- CI must include the parent document's required check that MCP mode makes no
  provider call, implemented as a behavior-boundary test that fails if any
  outbound provider request is attempted during a full read-only session.

Zerona remains an optional guided persona layered above this protocol. A caller
that already has a model conducting the conversation, such as Claude Code or
Codex, never needs a ZeroClaw model-provider call to use this surface.

## No mutation surface in v1

v1 defines no tool that changes host state. Specifically:

- there is no Request apply, Status, Verify, approve, register, rotate, or
  enable tool;
- there is no tool that writes `config.toml`, a personality file, a credential
  store entry, plugin bytes, or the journal;
- read-only mode refuses Request apply and creates no parked proposal, which in
  v1 is trivially satisfied because the operation does not exist; and
- a mutation tool may not be added by a minor version bump. Introducing a
  mutating operation is a major-version protocol change gated on phases 3
  through 5 passing their adversarial gates.

The parent document states that no mutating tool exists before the principal
and approval contract passes its adversarial gates. This specification is
written so that a reviewer can confirm that property by reading the tool list.

## Fixture-credential test contract

Phase 2 predates client registration, so grant-gated tools have to be
exercisable in tests without a registration ceremony existing. The parent
document permits this narrowly: "Until client registration lands, fixture
credentials are test-only and no default agent or external process receives a
grant."

The following contract must ship in the same change as the grant-gated tools,
and must be enforced by tests rather than by convention:

1. **Test-only compilation.** Fixture credentials and the code that mints a
   fixture grant are compiled only under `#[cfg(test)]` or a test-only Cargo
   feature that is not enabled by any released profile, workspace default, or
   distribution build.
2. **Absence from release artifacts.** A release-artifact test asserts that the
   fixture identifiers do not appear in the shipped binary. Building the default
   release profile and finding a fixture symbol or string is a CI failure.
3. **No runtime path to a fixture grant.** A fixture grant cannot be produced by
   a config value, environment variable, CLI flag, MCP argument, file placed on
   disk, or any other runtime input. Its only constructor is reachable from test
   code inside the test process.
4. **Distinct assurance class.** Fixture credentials carry the assurance class
   `test_only`. No production code path accepts `test_only`. When phase 3 lands,
   the accepted set is exactly `isolated_descriptor` and
   `sandbox_isolated_store`, and `test_only` is not added to it.
5. **Default-build behavior test.** A test builds the default release
   configuration, starts the stdio server with no registration, and asserts the
   session exposes exactly `initialize`, `control.ping`, `control.server_info`,
   and `control.registration_help`, and that every grant-gated tool is absent
   from `tools/list` and returns `unregistered_client` when called by name.
6. **No default grant.** A test asserts that no default agent and no external
   process receives a grant in a default installation, matching the parent
   document's phase-2 wording.
7. **Replacement, not extension.** When phase 3 registration ships, the fixture
   path is replaced. A test asserts that the production registration path and
   the fixture path do not share a credential verifier, so a future change
   cannot accidentally make `test_only` acceptable in production.
8. **Redaction fixtures.** Redaction is covered by fixture tests for both
   successful and error responses, per the parent document, including the error
   codes in the table above.

## Conformance checks for phase 2

A phase-2 implementation is reviewable only when CI proves, at minimum:

- generated schemas match the compiled types;
- native and MCP paths produce equivalent previews;
- native and MCP paths produce equivalent requester classification and
  authorization decisions;
- adapter effect fields map to the canonical config schema without an
  independently maintained duplicate;
- docs examples validate against current schemas;
- MCP mode makes no provider call;
- an unregistered stdio client exposes only Initialize, Ping, ServerInfo, and
  RegistrationHelp;
- an unregistered or ungranted agent that self-launches stdio cannot Inspect,
  Propose, request review, or approve;
- protocol downgrade cannot remove a security-required capability;
- secret values are absent from inventory, preview, errors, logs, and MCP
  responses; and
- the read-only mode exposes no mutation path.

These are the subset of the parent document's required verification list that
phase 2 can satisfy on its own. The remaining items depend on phases 3 through
5 and are tracked in the companion design pages.

## Open questions

These are gaps or ambiguities in the parent architecture document that this
specification cannot resolve on its own authority. Items marked **Resolved**
carry a maintainer decision recorded on 2026-08-21; they are kept here rather
than deleted so the question and its answer stay together. Items marked **Open**
are still for the maintainer to settle.

1. **Open: exact tool names are unsettled.** The parent document says exact names
   remain a protocol-design decision, and separately lists the final product and
   protocol name (`control`, `management`, or another term) as an open decision.
   The `control.` prefix used throughout this page is a proposal. A rename after
   v1 ships would be a major-version protocol change, so the name should be
   settled before any client package is generated.
2. **Resolved: Initialize is a lifecycle method, not a tool.** The parent
   document lists
   Initialize alongside Ping, ServerInfo, and RegistrationHelp as things an
   unregistered stdio endpoint "exposes". MCP models initialization as a
   lifecycle request rather than a tool. This page maps it to the lifecycle
   method. If the intent was a callable tool for parity with the native
   transport, the parent document should say so.

   **Resolution.** Confirmed as the lifecycle method. There is no callable
   `control.initialize`, and native-transport parity is met by the shared
   advertisement block. See "Initialization" above. Adopted from the gap-sweep
   resolution proposed in
   [issue #26](https://github.com/JordanTheJet/zeroclaw/issues/26), item 22.
3. **Resolved: carrier for the advertisement block.** The parent document
   specifies the advertisement contents but not where they sit in the MCP
   `initialize` result. This page proposes `_meta.zeroclaw_control`. The
   alternatives include `capabilities.experimental`, which reads poorly for a
   protocol intended to become stable.

   **Resolution.** Confirmed as `_meta.zeroclaw_control`, byte-identical to the
   `control.server_info` result and enforced by a byte-identity test. Not
   `capabilities.experimental`. See "Advertisement block" above. Adopted from the
   gap-sweep resolution proposed in
   [issue #26](https://github.com/JordanTheJet/zeroclaw/issues/26), item 23.
4. **Resolved: `capabilities` semantics.** The parent document's example
   advertises
   `["agents", "providers", "plugins"]` at `control_protocol_version` 1.0, but
   phase 2 implements contained agent creation only, and the provider, service,
   and plugin adapters arrive in phases 7 through 9. It is unclear whether
   `capabilities` enumerates capabilities the running server implements or
   capabilities the product supports. Only the former is safe for negotiation,
   because a client that trusts the latter would attempt an operation the server
   cannot perform. This page assumes the former.

   **Resolution.** Confirmed as the capabilities the running server implements,
   which is `["agents"]` at phase 2. See "Advertisement block" above. Adopted
   from the gap-sweep resolution proposed in
   [issue #26](https://github.com/JordanTheJet/zeroclaw/issues/26), item 24.
5. **Resolved: preview durability in read-only mode.** The parent document lists
   "whether pre-review conversational drafts survive restart" as an open
   decision, while stating that parked mutation proposals are durable
   regardless. v1 has no parked proposals, so this page makes `preview_id`
   process-local. If drafts are later made durable, the quota rules in
   `control-plane-proposal-journal.md` must extend to cover them, and a
   read-only release would then acquire durable per-client state that it does
   not have today.

   **Resolution.** Pre-review drafts stay non-durable in the read-only phase, so
   `preview_id` remains process-local and `durable` stays `false` in v1. If
   drafts are ever made durable they come under the per-client parked-byte and
   entry quotas in `control-plane-proposal-journal.md`. Adopted from the
   gap-sweep resolution proposed in
   [issue #26](https://github.com/JordanTheJet/zeroclaw/issues/26), item 14,
   which answers the same question on the journal side.
6. **Open: backchannel capability declaration before backchannels exist.** The
   parent
   document requires an operation to declare required operator-backchannel
   capabilities and to be rejected rather than downgraded when either side
   cannot represent every effect. In a read-only phase-2 release there is no
   backchannel to interrogate. This page exposes the declaration for shape
   parity, but the parent document does not say whether a phase-2 server should
   report those requirements at all, or whether doing so leaks anything about
   the intended operator configuration.
7. **Resolved: Catalog and grant interaction.** The parent document says Catalog
   contains no configured instance state, but also that Catalog requires a
   registered requester grant. Whether Catalog output is filtered by the grant's
   proposal domains, or is the full product catalog once any grant exists,
   changes what a narrowly granted client learns about the product. This page
   filters by grant as the conservative reading.

   **Resolution.** Confirmed: Catalog is filtered by the grant's proposal
   domains, so a narrowly granted client learns only what it could propose. See
   "`control.catalog`" above. Adopted from the gap-sweep resolution proposed in
   [issue #26](https://github.com/JordanTheJet/zeroclaw/issues/26), item 25.

## Governance status

This page is a proposal. The parent document states that the control plane
requires an accepted RFC before the external MCP or mutating surface is treated
as an implementation detail, and that changes to approval authority, principal
assurance, plugin trust, or the stable control protocol require the matching
architecture decision or foundation amendment. No RFC has been accepted for this
protocol and no architecture decision record covers it. Publishing this
specification does not create a compatibility obligation, does not authorize
implementation, and must not be cited as evidence that the design is accepted.
