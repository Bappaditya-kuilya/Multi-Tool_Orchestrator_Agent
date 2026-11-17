# ADR-0004: Non-cryptographic audit hash-chain placeholder in core

## Status

Accepted (temporary scaffold)

## Date

2026-11-17

## Context

Tamper-evident, durable audit logging is a core target (hash-chained, append-before-return, verifiable). Full cryptographic and persistence integrations were not yet implemented, but early primitives and tests were needed to shape interfaces and invariants.

## Decision

Implement audit chain primitives in `crates/core` using **FNV-1a (non-cryptographic)** hashing with append/verify helpers and unit tests, and provide an in-memory store skeleton using the same primitives.

- Explicitly mark as **not cryptographic** and **not durable/runtime-wired**.
- Plan replacement with cryptographic hashing and durable append-before-return storage for production readiness.

## Alternatives considered

### Option A: Defer audit abstractions until crypto/storage ready
- **Pros:** avoids placeholder semantics.
- **Cons:** delays API design and invariant testing.
- **Why not:** slows M1/M3 scaffolding.

### Option B: Cryptographic implementation immediately
- **Pros:** stronger integrity early.
- **Cons:** larger integration scope before runtime path exists.
- **Why not:** out of scope for current scaffold milestone.

### Option C: Non-crypto placeholder with explicit limits (chosen)
- **Pros:** enables chain semantics/tests now; clear upgrade path.
- **Cons:** no real tamper resistance; risk if misinterpreted.
- **Why chosen:** pragmatic for scaffold while preserving target intent.

## Consequences

### Positive
- Provides testable append/verify behavior and shapes future interfaces.

### Negative / trade-offs
- Must never be presented as security-grade integrity evidence.

### Follow-ups
- [ ] Replace FNV-1a with cryptographic hash chaining.
- [ ] Implement durable writer/store integration and runtime verification surfaces.

## References

- `crates/core` audit primitives
- [Threat model](../threat-model.md)
- [Status](../STATUS.md)