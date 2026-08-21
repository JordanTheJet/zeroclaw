# SOP Observability & Audit

This page covers where SOP execution evidence is stored and how to inspect it.

## 1. Audit Persistence

SOP audit entries are persisted via `SopAuditLogger` into the configured Memory backend, category `sop`.

Common key patterns:

- `sop_run_{run_id}`: run snapshot (start + completion updates)
- `sop_step_{run_id}_{step_number}`: per-step result
- `sop_approval_{run_id}_{step_number}`: operator approval record
- `sop_timeout_approve_{run_id}_{step_number}`: timeout auto-approval record

Compiled-in interactive steps append `interactive_input_requested` and
`interactive_input_submitted` run events. These records contain step/revision,
transport attribution, byte count, and a random correlation marker only. Raw
operator text and value-derived digests are not copied into run results or
event payloads.

## 2. Inspection Paths

### 2.1 Definition-level CLI

<div class="os-tabs-src">

#### sh

```sh
zeroclaw sop list
zeroclaw sop validate [name]
zeroclaw sop show <name>
```

</div>

### 2.2 Runtime run-state tools

SOP run state is queried from in-agent tools:

- `sop_status`: active/finished runs and optional metrics
- `sop_status` with `include_gate_status: true`: trust phase and gate evaluator state (when available)
- `sop_approve`: approve waiting run step
- `sop_advance`: submit step result and move run forward

Interactive input currently has no general in-agent submit tool. It is reserved
for typed system workflows whose authenticated host owns the input surface.

## 3. Metrics

- `/metrics` exposes observer metrics when `[observability] backend = "prometheus"`.
- Current exported names are `zeroclaw_*` families (general runtime metrics).
- SOP-specific aggregates are available through `sop_status` with `include_metrics: true`.
