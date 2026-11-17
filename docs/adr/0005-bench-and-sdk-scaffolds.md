# ADR-0005: Bench, dashboard, and SDK scaffolds ahead of runtime integration

## Status

Accepted (scaffold strategy)

## Date

2026-11-17

## Context

M4/M5 require benchmark and UI/SDK surfaces, but gateway/runtime APIs (M2/M3/M6) are incomplete. Waiting for full runtime readiness would delay harness structure, traceability, and developer-facing contracts.

## Decision

Maintain scaffold artifacts with factual status:
- `bench/`: pytest harness with 8 PRD attack-class placeholders (mode-aware; local checks and gateway-dependent xfails/skips until wired).
- `dashboard/`: Vite+React+TS UI shell/screens buildable without backend integration.
- `sdk/python`, `sdk/ts`: package metadata, READMEs, and minimal interface/client stubs (no working runtime transport/bindings).

E2E/scripts/docs capture intended flows and gaps rather than claiming enforcement evidence.

## Alternatives considered

### Option A: Implement only after runtime APIs stabilize
- **Pros:** less rework.
- **Cons:** no early structure, no CI/build/traceability signal.
- **Why not:** slows M4/M5/M7 preparation.

### Option B: Claim integrated/demo-ready surfaces now
- **Pros:** perceived progress.
- **Cons:** inaccurate and risky.
- **Why not:** violates evidence-based status tracking.

### Option C: Scaffold now with explicit non-integration (chosen)
- **Pros:** enables incremental wiring, visibility, and release-prep artifacts.
- **Cons:** placeholder maintenance and potential API churn.
- **Why chosen:** best balance for current milestone state.

## Consequences

### Positive
- Verified scaffold checks (bench collection/behavior, dashboard build) provide baseline confidence.
- SDK/interfaces can evolve alongside runtime contracts.

### Negative / trade-offs
- Stubs may need breaking changes; docs must remain precise.

### Follow-ups
- [ ] Wire bench cases to live gateway modes and publish evidence.
- [ ] Integrate dashboard with real APIs/telemetry.
- [ ] Replace SDK stubs with tested clients once APIs stabilize.

## References

- [Status](../STATUS.md)
- [E2E README](../../e2e/README.md)
- [Bench README](../../bench/README.md)