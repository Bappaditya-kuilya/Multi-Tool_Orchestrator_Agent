# ScopeGate

Least-privilege MCP gateway for AI agents — Rust workspace scaffold with evolving runtime integrations.

> **Status:** in active development, **not production-ready**.  
> Current milestone: verified local baseline (fmt/clippy/tests/bench/dashboard build pass); core gateway/runtime integrations remain incomplete.

## Verified baseline (local)

- `cargo fmt --all --check` — pass
- `cargo clippy --all-targets -- -D warnings` — pass
- `cargo test --all` — pass
- `python3 -m pytest bench -q` — **38 passed, 7 xfailed** (gateway/live-dependent cases expected without a configured live gateway)
- `dashboard`: `npm run build` — pass

## What’s in this repo

### Rust workspace (`crates/`)
- **`core`** — token/scope/attenuation primitives, deny-by-default policy evaluation with reasons/obligations/hooks, audit hash-chain primitives (pluggable/default hashing), taint and rate/budget models, unit/integration tests.
- **`gateway`** — axum-based HTTP server and lifecycle wiring: config loading, `/healthz`, `/readyz`, `/metrics`, `/v1/tasks`, `/v1/approvals`, `/v1/audit`, `/v1/policies`, `/v1/stream`, and `/mcp` JSON-RPC dispatch integration points with store/broker hooks and fail-closed behavior.
- **`mcp-front`** — MCP front abstractions/handlers (JSON-RPC parsing/validation/shaping, auth/policy/taint/approval hooks, transport seams).
- **`mcp-pool`** — upstream pool/client abstractions (connection lifecycle, dispatch/retry/timeout/circuit/health hooks, runtime seams).
- **`broker`** — approval workflow, notification hooks, credential resolution/redaction/injection interfaces, store-persistence bridge hooks.
- **`store`** — store trait/models, in-memory backend, SQLite/Postgres adapter scaffolding and migrations (including sqlite durable paths/tests), audit/query/verification helpers.

### Tooling and interfaces
- **`bench/`** — Python attack/behavior benchmark harness, scenarios, latency/reporting helpers, and CI-oriented outputs.
- **`dashboard/`** — Vite + React + TypeScript admin UI scaffold with typed API client/SSE integration points and mock fallback behavior.
- **`sdk/python`, `sdk/ts`** — SDK/client scaffolds oriented toward gateway API shapes.
- **`scripts/`, `e2e/`, `docker/`, `policies/`, `.github/workflows/`** — local run/build/check scripts, e2e flow scaffolds, container/policy/config examples, and CI workflows.
- **`reference/`** — archived legacy Python orchestrator implementation preserved for migration/reference.

## Current gaps (not yet complete)

- Real production integrations: **Biscuit** token crypto/attenuation, **Cedar** policy engine/schema loading, full **`rmcp`** front↔pool↔upstream runtime behavior.
- Durable end-to-end runtime: fully wired/exercised **sqlx** SQLite/Postgres operations in live paths, restart-safe approval/state handling, cryptographic append-before-return audit persistence/export/verification.
- Enforcement and evidence: live end-to-end fail-closed enforcement against a running gateway, enforce-mode/live benchmark artifacts, production-grade observability (OTel/metrics schemas), and runtime budget/taint/rate-limit enforcement coverage.
- Product/release readiness: dashboard↔live gateway E2E verification, SDK integration tests/publish readiness, S1/S2 deployment validation and drills, hosted demo, hardening/sign-off, and versioned release artifacts.

## Quick start

### Prerequisites
- Rust toolchain (see `rust-toolchain.toml`) with `cargo`, `rustfmt`, `clippy`
- Python 3 (for `bench/`)
- Node.js/npm (for `dashboard/`)

### Build, lint, and test (Rust)
```bash
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo test --all
```

### Run checks for other components
```bash
# Benchmark harness
python3 -m pytest bench -q

# Dashboard
cd dashboard && npm ci && npm run build
```

### Gateway (scaffold/runtime wiring in progress)
```bash
# Build
cargo build -p gateway

# Run (behavior/config depends on current implementation)
cargo run -p gateway
```

See `scopegate.toml.example`, `scripts/`, `e2e/`, and `docs/` for current run/e2e notes.

## Documentation

- [`docs/STATUS.md`](docs/STATUS.md) — current implementation and verification snapshot
- [`docs/architecture.md`](docs/architecture.md) — architecture and component mapping
- [`docs/threat-model.md`](docs/threat-model.md) — threat model and control intent
- [`docs/runbook.md`](docs/runbook.md) — operational notes
- [`docs/migration.md`](docs/migration.md) — migration notes from legacy implementation
- [`docs/RELEASE_READINESS.md`](docs/RELEASE_READINESS.md) — readiness/evidence tracking
- [`CONTRIBUTING.md`](CONTRIBUTING.md), [`SECURITY.md`](SECURITY.md)

## License

MIT — see [`LICENSE`](LICENSE).
