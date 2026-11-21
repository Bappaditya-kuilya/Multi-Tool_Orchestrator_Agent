# Migration

This document summarizes migration status and pointers for moving from the legacy Python prototype (`reference/`) toward the ScopeGate Rust workspace.

> **Iteration:** M0/M6/M7/M8 loop (2026-11-17 snapshot). Migration progress includes store/runtime/API/hardening work, but production runtime integration and release evidence remain incomplete.

## Current state (factual)

- **Legacy implementation:** preserved under `reference/` (Python orchestrator, manifests, tests, examples, CI). Treat as historical/reference behavior and test corpus source.
- **Target implementation:** Rust workspace in `crates/{core,gateway,mcp-front,mcp-pool,broker,store}` with partial runtime integrations.
  - **Gateway/runtime:** axum HTTP routes include ops/admin/MCP surfaces and `/v1/audit/verify`; task create/list/get/revoke, audit query/verify, approvals (POST), and policies handlers are wired to store-backed paths where available. Store wiring supports in-memory by default and optional SQLite (WAL/sqlx) via config/env with fail-closed init/connect/migrate behavior.
  - **Store/persistence progress:** SQLite/Postgres adapter and migration scaffolding exist; embedded migrations include migration tracking/idempotency progress via `_schema_migrations` (`apply_migrations`) and audit append/query/verify helpers. Durable append-before-return and restart-safe guarantees are not fully proven end-to-end.
  - **MCP/broker hardening progress:** `mcp-front` (parsing/validation/hook/transport seams), `mcp-pool` (transport/config/dispatch/runtime abstractions), and `broker` (approval timeout-deny/pause-resume/fail-closed sync+async store-persistence/reconciliation hooks plus secret env/file/scheme resolution, resolving injection, and request/response/map/pair scrubbing primitives; `cargo test -p broker` passes in this pass) have progressed toward live-path readiness as primitives, but full `rmcp` runtime, gateway/live-path integration (including credential injection/scrubbing on upstream dispatch paths), broader production secret adapters, and complete upstream execution remain incomplete.
  - **Interfaces/tooling:** Python/TS SDKs target current gateway HTTP/MCP surfaces (including audit verify/query), bench harness reports 38 passed/7 xfailed in current snapshot, dashboard build passes, and scripts/e2e/docker include SQLite-oriented dev conveniences and cargo-oriented flows.
- **Current verified baseline (snapshot):** `cargo fmt --all --check` pass, `cargo clippy --all-targets -- -D warnings` pass, `cargo test --all` pass, bench 38 passed/7 xfailed, dashboard build pass. Capture reproducible evidence (mode/commit/env/logs).
- **Migration artifacts:** detailed mapping in [`MIGRATION_MAP.md`](./MIGRATION_MAP.md); repo context in [`../REPO_GRAPH.md`](../REPO_GRAPH.md).

## Priorities (high level)

1. **Preserve and harden invariants:** keep scope attenuation/non-inflation, deny/fail-closed behavior, deterministic decision/audit primitives, and explicit reason surfaces while replacing non-production substitutes.
2. **Harden S1 runtime path:** extend optional SQLite wiring into a fully validated fail-closed path with durable append-before-return audit, restart-safe approvals/state/revocations, and proven recovery semantics.
3. **Complete runtime integrations:** Biscuit/Cedar/crypto audit, full `rmcp` front↔pool↔upstream execution, production secret adapters/broker injection-redaction guarantees, and stable API contracts.
4. **Bench/evidence traceability:** map/port legacy security & robustness cases, convert xfails to enforce-mode/live evidence, and capture reproducible artifacts (mode/commit/env/logs).
5. **Config/policy/manifest translation:** align `scopegate.toml.example`, `policies/examples/*`, and legacy manifests to finalized schemas/loaders/runtime behavior.

## Gaps / blockers (exact)

- **Real deps/integrations:** Biscuit, Cedar (+ YAML compile/load), cryptographic audit hashing/signing/anchoring, full `rmcp` runtime/upstream execution, production secret adapters, and approvals persistence guarantees.
- **Durable/runtime parity:** end-to-end fail-closed lifecycle (authn/policy/taint/approval/broker/pool/upstream/audit), durable append-before-return audit, restart-safe state/revocation/budget handling, and verified SQLite/Postgres behavior across all live paths.
- **Integration/evidence:** bench enforce-mode/live enforcement artifacts, dashboard↔live gateway E2E verification, SDK integration tests/publish readiness, M6 observability/limits/taint evidence, and S1/S2 runtime validation.
- **Release/sign-off:** hosted demo, hardening/security sign-off, and versioned release artifacts not complete. No crypto audit, live enforce-mode proof, S1/S2 validation, or release sign-off claimed.

See [`STATUS.md`](./STATUS.md) for milestone truth and [`MIGRATION_MAP.md`](./MIGRATION_MAP.md) for the actionable mapping.