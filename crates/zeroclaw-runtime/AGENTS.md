# zeroclaw-runtime — Transitional Holding Crate

This crate is a **temporary holding area**, not a permanent home. It contains 126K LOC of subsystems extracted from the original monolith that have not yet been decomposed into their final crate structure.

Do not add new functionality here, except under an explicit, recorded, expiring exception. The RFC's Phase 2-4 roadmap defines the decomposition plan: agent loop, gateway, channels orchestrator, daemon, cron, security, observability, hardware, TUI, skills, and doctor will each be extracted into dedicated crates or converted to WASM plugins.

## Active exceptions

| Subsystem | Record | Expires |
| --- | --- | --- |
| `src/cron` | [ADR-016](../../docs/book/src/architecture/decisions/ADR-016-cron-extraction-and-transitional-exception.md) | when `zeroclaw-cron` lands, or on Core Team withdrawal |

An exception permits continued work on a subsystem already held here. It never permits adding a new subsystem, and it never generalises to the other subsystems named above. A pull request cannot grant itself an exception; the record has to exist first, and it has to name an expiry.

**Stability tier:** Experimental — no stability guarantee. Decomposition begins at v0.8.0.
