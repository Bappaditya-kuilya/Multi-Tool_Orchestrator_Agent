# ADR-0002: Rust workspace scaffold with crate boundaries

## Status

Accepted (scaffold)

## Date

2026-11-17

## Context

ScopeGate targets a Rust-based MCP gateway with separation of concerns (core primitives, gateway runtime, MCP front/pool, broker, store). The repository was transitioning from a Python prototype (`reference/`) while runtime integrations and production wiring were not yet implemented.

Constraints/forces:
- Need a compile-ready structure for incremental implementation and CI.
- Keep domain invariants (token/policy/audit/taint) testable independent of transport/storage integrations.
- Make migration mapping from legacy behavior explicit without claiming parity.

## Decision

Adopt a Cargo workspace with crates: `core`, `gateway`, `mcp-front`, `mcp-pool`, `broker`, and `store`.
- `core` hosts pure/domain primitives and unit-testable logic first.
- Other crates provide skeletons/placeholders for future integrations and lifecycle wiring.
- Legacy Python implementation remains under `reference/` as migration/reference material.

Out of scope for this decision: finalized public APIs, production integrations, and S1/S2 runtime validation.

## Alternatives considered

### Option A: Single crate monolith
- **Pros:** simpler initial setup.
- **Cons:** weak boundaries, harder to evolve integrations independently.
- **Why not:** boundaries are central to gateway/broker/store separation.

### Option B: Workspace with explicit crate boundaries (chosen)
- **Pros:** clear ownership seams, incremental implementation, targeted tests.
- **Cons:** more upfront scaffolding and interface churn risk.
- **Why chosen:** aligns with target architecture and staged milestones.

## Consequences

### Positive
- Establishes structure for M1–M3 implementation and CI checks.
- Enables documenting factual progress by crate.

### Negative / trade-offs
- Placeholder crates can overstate completeness if docs are not careful.
- Cross-crate contracts still need stabilization.

### Follow-ups
- [ ] Finalize crate contracts and end-to-end wiring.
- [ ] Replace skeletons with real integrations and verified behavior.

## References

- [Architecture](../architecture.md)
- [Status](../STATUS.md)
- [Migration map](../MIGRATION_MAP.md)