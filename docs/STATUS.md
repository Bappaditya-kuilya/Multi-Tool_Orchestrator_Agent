# ScopeGate — Status

> Factual milestone/status snapshot for the current repo. **Iteration:** M0/M6/M7/M8 loop (2026-11-17, docs/e2e/scripts/sdk/docker/policies/CI alignment). Not a release sign-off.

## Latest verification snapshot (current verified green baseline)

- **`cargo fmt --all --check`:** **pass**.
- **`cargo clippy --all-targets -- -D warnings`:** **pass**.
- **`cargo test --all`:** **pass**.
- **Bench:** **38 passed, 7 xfailed** (pytest harness; record mode `baseline|dryrun|enforce`, commit, command, env, and logs for evidence).
- **Dashboard:** **`npm run build` pass** (Vite/React/TS scaffold UI, no backend integration).

> Snapshot is reported for this iteration. Re-run in a clean, toolchain-equipped environment and capture logs/artifacts before claiming CI/release readiness. This does not constitute security sign-off or production readiness.

## Current repo state (summary)

- **Rust workspace:** `Cargo.toml` members: `crates/core`, `crates/gateway`, `crates/mcp-front`, `crates/mcp-pool`, `crates/broker`, `crates/store` (`rust-toolchain.toml` pinned).
- **Quality baseline:** fmt/clippy/tests green in verified baseline.
- **`crates/core` primitives (implemented, non-production substitutes):** token scope attenuation (`child ⊆ parent`), expiry/budget narrowing, revocation-ID placeholder checks; policy `Permit/Forbid/RequireApproval` with deny-by-default and `Forbid` overrides; FNV-1a (non-cryptographic) hash-chained audit append/verify; coarse/session-level taint with conflicted external-egress decisions. Unit tests exist.
- **`crates/gateway` runtime (partial, axum-based):** binary/HTTP server wiring present (`server::serve`, routes in `server.rs`/`api.rs`) with in-memory store wired by default in `main`. Exposed surfaces include `/healthz`, `/readyz`, `/metrics`, `/v1/tasks` (GET/POST), `/v1/audit` (GET/POST), `/v1/approvals` (POST), `/v1/policies` (GET/POST), `/v1/stream` (SSE), `/mcp` (JSON-RPC dispatch). MCP dispatch currently supports minimal methods (`initialize`, `tools/list`, `tools/call` for `gateway.health`) and fail-closes on unsupported methods; **not** full `rmcp` runtime or complete MCP tool proxy.
- **Other crates:** `broker` (approval/secret-ref/credential trait + noop placeholder, timeout-deny semantics modeled), `mcp-front`/`mcp-pool` stubs/placeholders, `store` provides traits and in-memory skeleton/helpers (core FNV-1a chain primitives used); durable SQLx-backed append-before-return path and full production store behavior not proven end-to-end.
- **Bench (M4):** `bench/` pytest harness, 8 attack-class coverage, `baseline|dryrun|enforce` modes. **38 passed, 7 xfailed** (not live enforce-mode proof against a fully wired/production-shaped gateway).
- **Dashboard (M5):** Vite+React+TS scaffold screens; **build passes**, no backend/API integration.
- **SDKs (M5):** `sdk/python` and `sdk/ts` now include stdlib/fetch HTTP client implementations toward current gateway API surfaces (`/healthz,/readyz,/metrics,/v1/tasks,/v1/audit,/v1/approvals,/v1/policies,/mcp`), with endpoint helpers and basic request/response mapping; still no auth token attenuation flows, retries/streaming, integration tests, or publish workflow.
- **E2E/scripts/docker/CI/policies:** `scripts/*` and `e2e/demo_flow.sh` run real cargo/gateway/pytest steps with env overrides and log capture; `docker/Dockerfile.gateway` and `compose.yml` support cargo-oriented builds/dev runs; workflows run fmt/clippy/tests and scaffold checks. Config/policy examples remain illustrative.
- **Reference artifacts:** `REPO_GRAPH.md`, `docs/MIGRATION_MAP.md`, `reference/`, `graphify-out/*`.

## Milestone status

| Milestone | Status | Notes (honest) |
|-----------|--------|----------------|
| **M0 — Scaffold** | Mostly complete | Workspace/crates/docs/config/policy/docker/sdk/e2e/scripts/CI in place; core primitives and gateway HTTP/MCP-dispatch scaffolding exist. Verified baseline fmt/clippy/tests green. |
| **M1 — Core security primitives** | Partial | Token/policy/audit/taint primitives + tests exist as non-production substitutes (no Biscuit signatures/attenuation crypto, no Cedar engine/YAML compile, non-cryptographic FNV-1a hash, coarse/session-level taint). Missing revocation sync/budget accounting integration, property/fuzz coverage, cross-crate enforcement. |
| **M2 — MCP gateway path** | Partial / incomplete | Axum HTTP server + `/mcp` JSON-RPC dispatch skeleton and v1/admin-style routes exist, but no full `rmcp` runtime/front-pool/upstream execution, no complete broker secret injection/redaction runtime, and no production end-to-end tool execution path. |
| **M3 — Persistence/approvals/audit durability** | Partial / incomplete | Store abstractions and in-memory wiring exist; audit/approval/policy/task APIs are exposed at HTTP layer. Durable SQLx-backed append-before-return audit, restart-safe approvals/state, and production persistence guarantees not implemented/verified. |
| **M4 — Bench/dashboard integration** | Partial | Bench harness progressing (38p/7xf). Dashboard build passes. No live backend integration and no authoritative enforce-mode/live enforcement evidence. |
| **M5 — SDKs & DX** | In progress | Python/TS SDKs provide HTTP client implementations toward current gateway APIs; still missing full transport parity, auth/approval streaming flows, tests, and publish workflow. |
| **M6 — Observability, limits, taint hooks** | Partial | Basic ops endpoints/metrics/SSE scaffolding exist in gateway, but tracing/OTel, stable schemas, enforced rate-limit/budget/taint runtime hooks, and production observability guarantees are incomplete. |
| **M7 — Ops/reliability hardening** | Not complete (prep improved) | Real cargo build/run/e2e scripts and docker/CI docs improved; no S1/S2 runtime validation, HA/degraded-mode behavior, backup/restore drills, or operational hardening evidence. |
| **M8 — Release/readiness** | Not complete | No release artifacts, signed-off end-to-end verification, security hardening sign-off, hosted demo, or benchmark evidence bundle. |

## M4 bench & dashboard verification (detail)

- **Bench:** 8 attack-class coverage with `baseline|dryrun|enforce` modes.
  - **Current baseline:** `38 passed, 7 xfailed`.
  - **Gap:** xfails and mode semantics require further runtime wiring for authoritative enforce-mode/live enforcement evidence; capture exact command, commit, mode, env, and logs.
- **Dashboard:** **Build passes**; UI static/non-integrated.

## M6 observability, limits, taint hooks (current vs remaining)

- **Current:** gateway exposes `/healthz`, `/readyz`, `/metrics` (Prometheus text), and `/v1/stream` SSE scaffolding; lifecycle emits events in places.
- **Remaining:** production-grade tracing/OTel, reason-coded schemas across full path, enforced rate-limit/budget hooks, taint propagation/egress enforcement, and validated failure semantics.

## S1/S2 operations (planned)

- **S1 (target):** single node, SQLite WAL store, in-process events/approvals, fail-closed on audit/store/policy errors.
- **S2 (target):** N stateless nodes, Postgres + Redis streams, shared approvals/audit/events.
- **Current:** `main` wires in-memory store by default; docker/compose/scripts/docs are prep scaffolds; no S1/S2 runtime validation.

## SDK / CI / config / policy notes

- **SDKs:** Python/TS HTTP clients target current gateway endpoints and MCP dispatch; behavior depends on evolving server contracts. No integration tests/publish workflow.
- **CI:** `.github/workflows/rust-ci.yml` enforces fmt/clippy/tests; audit/deny best-effort. `.github/workflows/scaffold-checks.yml` covers bench/dashboard. Keep logs/artifacts for evidence.
- **Config/policy:** `scopegate.toml.example` and `policies/examples/*` are illustrative; schema/loader/runtime enforcement not finalized.

## Remaining gaps / blockers (exact)

- **Real deps/runtime wiring:** Biscuit (`biscuit-auth`) verification/attenuation, Cedar (`cedar-policy` + YAML compile/load), full `rmcp` MCP runtime/front-pool/upstream execution, broker secret injection/redaction adapters, durable SQLx stores (SQLite/Postgres) with append-before-return guarantees, cryptographic audit hashing/signing/anchoring.
- **End-to-end enforcement path:** fail-closed request lifecycle across authn/policy/taint/approval/broker/pool/upstream/audit with restart-safe approvals and revocation/budget/rate-limit state.
- **M6/M7 evidence:** stable observability schemas, enforced limits/taint hooks, S1/S2 runtime validation, backup/restore/rollback drills, incident/runbook evidence.
- **Release (M8):** enforce-mode/live enforcement benchmark artifacts, SDK integration hardening/publish path, hosted demo, security hardening/sign-off, and versioned release artifacts.

## Next actions (near-term)

1. Keep verified baseline green in CI/local runs and capture logs/artifacts per evidence run.
2. Replace placeholder security/runtime components (Biscuit/Cedar/crypto audit/`rmcp`/sqlx/secret adapters) while preserving invariants.
3. Implement minimal S1 fail-closed path with durable append-before-return audit and restart-safe approval semantics.
4. Harden M6 hooks/surfaces (health/readiness/metrics/tracing/rate limits/taint) with stable contracts.
5. Integrate bench/dashboard/SDKs against live APIs/telemetry and record enforce-mode/live enforcement evidence (including 38p/7xf reproduction details).
6. Execute M7/M8 validation, drills, hosted demo, and release/sign-off documentation with factual evidence.