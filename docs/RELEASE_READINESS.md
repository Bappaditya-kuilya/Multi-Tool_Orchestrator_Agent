# ScopeGate — Release Readiness Notes

> Factual readiness snapshot for M0/M6/M7/M8 iteration prep. Updated: 2026-11-17. This is **not** a release sign-off.

## Intended release gates (target, PRD-aligned)

- CI green (fmt/clippy/check/tests) on a Rust-toolchain environment.
- End-to-end S1 path validated with fail-closed behavior on audit/store/policy/token errors.
- Durable, verifiable audit chain (append-before-return) with `audit verify` evidence.
- Bench baseline and enforce-mode results against a live gateway (attack classes measurable, artifacts published with mode/commit/env).
- Ops surfaces and drills: `/healthz`, `/readyz`, `/metrics`, tracing/rate-limit/taint hooks as applicable, backup/restore, rollback criteria exercised.
- Docs/SDK/config/policies consistent with implemented behavior; security review recorded.

## Current evidence (2026-11-17, verified green baseline)

| Area | Status | Evidence / notes |
|------|--------|------------------|
| Rust fmt | **Pass** | `cargo fmt --all --check` clean. |
| Rust clippy | **Pass** | `cargo clippy --all-targets -- -D warnings` clean. |
| Rust tests | **Pass** | `cargo test --all` all pass. |
| `crates/core` primitives | **Implemented (scaffold substitutes)** | Token/policy/audit (FNV-1a, non-crypto)/taint primitives + unit tests; runtime enforcement integration incomplete. |
| Gateway HTTP/MCP-dispatch | **Partial** | Axum server/routes (`/healthz,/readyz,/metrics,/v1/tasks,/v1/audit,/v1/approvals,/v1/policies,/v1/stream,/mcp`) and in-memory store wiring exist; minimal MCP methods/tools only, no full `rmcp`/upstream execution, no production auth/enforcement. |
| Bench (M4) | **Partial evidence** | **38 passed, 7 xfailed** (record mode/commit/logs). Not enforce-mode/live enforcement proof against fully wired gateway. |
| Dashboard (M5 scaffold) | **Build pass** | Vite build succeeds; UI static/non-integrated. |
| Docker/compose | **Scaffold/prep** | Cargo-oriented build/run scaffolds with fallback placeholder behavior possible; not production-ready. |
| E2E/scripts | **Working prep scripts** | `e2e/demo_flow.sh`, `scripts/*` run real cargo/gateway/bench steps where possible with overrides and log capture; results depend on environment/runtime completeness. |
| Audit (runtime durability) | **Not ready** | FNV-1a chain primitives and in-memory wiring exist; no cryptographic/durable append-before-return or persisted runtime verification. |
| Ops/limits/taint hooks (M6) | **Partial** | Basic health/ready/metrics/stream surfaces exist; tracing/OTel, enforced limits/taint, stable schemas incomplete. |
| S1/S2 validation (M7) | **Not done** | No runtime validation, HA/degraded-mode, or backup/restore drills. |
| SDKs | **HTTP clients (scaffold)** | Python/TS clients call current gateway APIs/MCP dispatch; no auth attenuation flows, integration tests, or publish workflow. |
| Security hardening/sign-off | **Not done** | No formal review or production security guarantees. |
| Hosted demo / v0.1.0 | **Not done** | No live hosted demo and no release artifacts/sign-off. |

## Blockers to M8 readiness (exact)

- **Real deps/runtime wiring:** Biscuit token verification/attenuation, Cedar policy engine + YAML compile/load, full `rmcp` MCP runtime/front-pool/upstream execution, secret broker/adapters with injection/redaction guarantees, approvals persistence/service.
- **Durable runtime path:** SQLx-backed stores and end-to-end fail-closed lifecycle with cryptographic, durable append-before-return audit and persisted verification; restart-safe state/revocation/budgets.
- **M6 hardening:** production tracing/OTel and stable observability schemas; enforced rate-limit/budget and taint propagation/egress hooks with auditable outcomes.
- **Integration/evidence:** bench/dashboard/SDKs validated against live, wired enforcement paths with enforce-mode artifacts (including 38p/7xf reproduction details and environment).
- **M7/M8 ops/release:** S1/S2 runtime validation, backup/restore, rollback drills, incident/runbook evidence, hosted demo, security hardening/sign-off, and versioned v0.1.0 release artifacts.

## References

- [`STATUS.md`](./STATUS.md) — milestone and verification truth
- [`runbook.md`](./runbook.md) — planned operations, rollback, e2e/CI notes
- [`threat-model.md`](./threat-model.md) — controls and explicit limits
- [`../scripts/RELEASE_CHECKLIST.md`](../scripts/RELEASE_CHECKLIST.md), [`../e2e/README.md`](../e2e/README.md) — prep/evidence artifacts
- [`.github/workflows/rust-ci.yml`](../.github/workflows/rust-ci.yml), [`.github/workflows/scaffold-checks.yml`](../.github/workflows/scaffold-checks.yml) — CI checks