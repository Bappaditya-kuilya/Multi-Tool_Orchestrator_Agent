# ADR-0003: Fail-closed semantics and explicit scaffold limits

## Status

Accepted (target intent; partially modeled)

## Date

2026-11-17

## Context

ScopeGate's security posture depends on denying unsafe or indeterminate operations (policy/token errors, audit/store unavailability, approval timeout). During scaffold phase, many runtime paths are unimplemented, creating risk of overstating guarantees.

## Decision

- Treat **fail-closed** as the default safety intent for policy/token/audit-store errors and approval timeouts.
- Model key semantics in primitives where feasible now:
  - deny-by-default policy evaluation with `Forbid` precedence and `RequireApproval` outcomes.
  - approval timeout represented/treated as deny.
  - audit append/verify helpers in core/store skeletons (non-durable/non-cryptographic placeholders).
- Explicitly document gaps and non-production substitutes in `docs/STATUS.md`, `docs/threat-model.md`, `docs/runbook.md`, and root docs.

Out of scope: claiming production enforcement or verified runtime fail-closed behavior.

## Alternatives considered

### Option A: Fail-open/permissive placeholders for developer convenience
- **Pros:** easier demos early.
- **Cons:** dangerous defaults and misleading signals.
- **Why not:** conflicts with least-privilege goals.

### Option B: Fail-closed intent with honest placeholders (chosen)
- **Pros:** preserves security direction and clear expectations.
- **Cons:** slower path to "working" demo until integrations land.
- **Why chosen:** aligns with threat model and release gates.

## Consequences

### Positive
- Consistent messaging and API semantics for future implementation.
- Reduces chance of accidental permissive behavior.

### Negative / trade-offs
- Requires extra documentation discipline and verification evidence later.

### Follow-ups
- [ ] Implement and verify durable audit-before-return and runtime fail-closed paths.
- [ ] Add tests/bench evidence for timeout/deny and error handling.

## References

- [Threat model](../threat-model.md)
- [Runbook](../runbook.md)
- [Status](../STATUS.md)