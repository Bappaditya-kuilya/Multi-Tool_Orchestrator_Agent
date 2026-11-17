# Security Policy

**Status:** Draft. ScopeGate is currently a scaffold/partial implementation snapshot; many security controls described in docs are planned unless explicitly noted as implemented and verified.

## Reporting a vulnerability

- **Do not** open a public issue with exploit details.
- **Private reporting channel:** TBD (no finalized private intake yet). Until established, contact maintainers through a private repository communication channel if available and share a clear description, impact, affected components, and reproduction steps.
- Please avoid including secrets, credentials, or sensitive data in reports.

We will acknowledge reports and coordinate remediation/disclosure timelines once the process and contacts are finalized.

## Current security posture (important)

- **Not production-ready.** Many security-critical controls remain incomplete or non-production substitutes.
- **Implemented now (partial):** `crates/core` primitives (token attenuation/expiry/budget/revocation-ID placeholders, deny-by-default policy eval with forbid overrides, FNV-1a non-cryptographic audit chain, coarse taint decisions) with unit tests; `crates/gateway` exposes axum HTTP routes (`/healthz,/readyz,/metrics,/v1/tasks,/v1/audit,/v1/approvals,/v1/policies,/v1/stream,/mcp` minimal dispatch) with in-memory store wiring by default. These are not equivalent to production-grade enforcement.
- **Current verified baseline (2026-11-17):** `cargo fmt --all --check` pass, `cargo clippy --all-targets -- -D warnings` pass, `cargo test --all` pass, bench 38 passed/7 xfailed, dashboard build pass. This is not a security sign-off.
- **Known gaps/blockers:** real Biscuit crypto verification/attenuation and Cedar policy engine/YAML compile-load; full `rmcp` runtime and upstream front/pool execution; broker secret adapters/injection/redaction guarantees; durable SQLx-backed append-before-return audit with cryptographic chain and persisted verification; restart-safe approvals/state; enforced rate-limit/budget/taint propagation and egress controls; production observability/tracing schemas; end-to-end fail-closed/live enforcement evidence, S1/S2 validation, hosted demo, and v0.1.0 sign-off. No live hosted demo in this snapshot.

## Supported versions / disclosure

- Versioning and supported release lines: TBD (pre-release).
- Disclosure target policy: TBD (coordinated disclosure goal; process not finalized).

See `docs/threat-model.md`, `docs/architecture.md`, and `docs/STATUS.md` for explicit limits, planned controls, and verification state.
