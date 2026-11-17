# Migration

This document summarizes migration status and pointers for moving from the legacy Python prototype (`reference/`) toward the ScopeGate Rust workspace.

> **Iteration:** M0/M6/M7/M8 loop (2026-11-17). Migration remains blocked on real deps/integrations, runtime wiring, and fully green/reproducible verification.

## Current state (factual)

- **Legacy implementation:** preserved under `reference/` (Python orchestrator, manifests, tests, examples, CI). Treat as historical/reference behavior and test corpus source.
- **Target implementation:** Rust workspace in `crates/{core,gateway,mcp-front,mcp-pool,broker,store}` with partial `core` primitives, partial gateway runtime (axum HTTP routes + minimal `/mcp` JSON-RPC dispatch + in-memory store wiring), and SDK HTTP clients toward current APIs. No complete end-to-end production enforcement path yet.
- **Current verified baseline:** `cargo fmt --all --check` pass, `cargo clippy --all-targets -- -D warnings` pass, `cargo test --all` pass, bench 38 passed/7 xfailed, dashboard build pass. Capture reproducible evidence (mode/commit/env/logs).
- **Migration artifacts:** detailed mapping in [`MIGRATION_MAP.md`](./MIGRATION_MAP.md); repo context in [`../REPO_GRAPH.md`](../REPO_GRAPH.md).

## Priorities (high level)

1. **Unblock quality gates:** fix clippy/gateway issues; keep fmt/clippy/tests green with evidence.
2. **P0 invariants in `crates/core`:** preserve scope attenuation/non-inflation, confinement/intersection, depth/fail-closed behavior, deterministic decision/audit primitives while replacing non-production substitutes.
3. **Bench traceability:** map/port security & robustness cases from `reference/tests/*` and `reference/docs/audit.md` into `bench/` with stable IDs; convert xfails to enforce-mode evidence as runtime lands.
4. **Runtime wiring (S1):** MCP front → authn/policy/taint/approval/broker/pool → durable audit append-before-return with fail-closed semantics.
5. **Config/policy/manifest translation:** align `scopegate.toml.example`, `policies/examples/*`, and legacy manifests to finalized schemas/loaders and runtime behavior.

## Gaps / blockers (exact)

- **Integration/evidence:** bench xfails and mode/artifact capture remain for release-grade/live enforce evidence; end-to-end runtime proof is incomplete.
- **Real deps/integrations:** Biscuit, Cedar (+ YAML compile/load), cryptographic/durable audit chain, `rmcp`, HTTP server (axum/tower), sqlx stores/events, secret adapters/broker, approvals persistence.
- **Runtime parity/migration:** end-to-end S1 fail-closed path, M6 ops/limits/taint hooks, dashboard/SDK wiring to real APIs, and verified S1/S2 behavior/release evidence (M7/M8).
- **Planning:** authoritative PRD reconciliation (including §24 targets) and finalized crate-responsibility contracts/config schemas.

See [`STATUS.md`](./STATUS.md) for milestone truth and [`MIGRATION_MAP.md`](./MIGRATION_MAP.md) for the actionable mapping.