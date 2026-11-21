# Security Policy

**Status (preview):** ScopeGate is an S1 preview / partial implementation. Do **not** treat this repository as production-hardened or security-audited. Many controls in docs/PRD are planned or non-production substitutes.

## Reporting a vulnerability (factual posture)

- **Do not** open a public issue with exploit details or sensitive reproduction data.
- **Private reporting channel:** not yet finalized/TBD. If you have access to a private maintainer contact or repository-private channel, report there with: affected component/commit, impact, reproduction steps, and any suggested mitigation. Avoid sharing secrets or personal data.
- **Acknowledgement/SLA/disclosure timeline:** not established yet (pre-release). We will coordinate in good faith when a report is received through an available private channel.
- **Supported releases/patch policy:** none yet (pre-release; no supported release line).

## Current security posture (important)

- **Not production-ready / no sign-off:** no cryptographic audit, no live enforce-mode proof, no S1/S2 runtime validation, no hosted demo, no release hardening sign-off.
- **Partial implementations (non-production substitutes):** core token/policy/taint primitives and non-cryptographic (FNV-1a) audit-chain primitives; gateway axum routes (`/healthz,/readyz,/metrics,/v1/tasks* ,/v1/approvals* ,/v1/audit* ,/v1/policies,/v1/stream,/mcp`) with in-memory default and optional SQLite wiring in places; minimal MCP dispatch and store-backed audit verification paths exist but are not proven as durable/complete end-to-end enforcement.
- **Known gaps/blockers:** real Biscuit verification/attenuation, Cedar engine/YAML compile-load, full `rmcp` front↔pool↔upstream runtime, gateway live-path credential injection/scrubbing integration and production secret broker/adapters with end-to-end guarantees, durable append-before-return cryptographic audit and persisted verification, restart-safe approvals/state, enforced rate-limit/budget/taint propagation/egress controls, production observability schemas, and validated fail-closed behavior across all runtime paths.

For factual limits and current evidence, see [`docs/threat-model.md`](docs/threat-model.md), [`docs/STATUS.md`](docs/STATUS.md), and [`docs/architecture.md`](docs/architecture.md). For target intent vs implementation drift, see [`docs/PRD.md`](docs/PRD.md) and [`README.md`](README.md).
