# Architecture Decision Records (ADRs)

This directory contains Architecture Decision Records for ScopeGate.

## Purpose

ADRs capture significant technical decisions, their context, and consequences so future contributors (and agents) understand *why* the system is built the way it is.

## Status

| ADR | Title | Status | Date |
|-----|-------|--------|------|
| [0001](./0001-template.md) | ADR Template | Template | - |
| [0002](./0002-rust-workspace-scaffold.md) | Rust workspace scaffold with crate boundaries | Accepted (scaffold) | 2026-11-17 |
| [0003](./0003-fail-closed-scaffold-semantics.md) | Fail-closed semantics and explicit scaffold limits | Accepted (target intent; partially modeled) | 2026-11-17 |
| [0004](./0004-non-cryptographic-audit-hash-placeholder.md) | Non-cryptographic audit hash-chain placeholder in core | Accepted (temporary scaffold) | 2026-11-17 |
| [0005](./0005-bench-and-sdk-scaffolds.md) | Bench, dashboard, and SDK scaffolds ahead of runtime integration | Accepted (scaffold strategy) | 2026-11-17 |

> Add new ADRs to this index as they are created.

## Conventions

- **Location:** `docs/adr/`
- **Naming:** `NNNN-short-title.md` with zero-padded sequential numbers (e.g., `0002-capability-tokens.md`).
- **Lifecycle:** Proposed → Accepted → Superseded or Deprecated. Do not delete accepted ADRs; supersede them with a new ADR that links back.
- **Scope:** Record decisions that are hard to reverse or that shape architecture/security/operations (e.g., token format, policy engine, storage model, transport/auth choices).

## How to add an ADR

1. Copy [`0001-template.md`](./0001-template.md) to the next sequence number.
2. Fill in context, decision, alternatives, and consequences.
3. Set status to `Proposed` (or `Accepted` once agreed).
4. Add an entry to the index table above.

## Related docs

- [PRD](../PRD.md)
- [Architecture](../architecture.md)
- [Threat model](../threat-model.md)
