# ScopeGate (S1 preview)

Least-privilege MCP gateway for AI agents (Rust workspace). **Preview, not production-ready; no security/release sign-off.**

> **Verification (current source, 2026-11-21):** `cargo fmt --all --check`, `cargo clippy --all-targets -- -D warnings`, and `cargo test --all` **green**. Bench: **38 passed, 7 xfailed** unconfigured; configured clean-gateway sqlite+stdio capture **44 passed, 1 xfailed** (3 capability tests pass when configured; same-instance rerun contamination caveat; evidence only). Dashboard `npm run build` and SDK checks (`py_compile`, `tsc --noEmit`) **green**. Not sign-off.
>
> **Captured sqlite+stdio S1 proof:** [`e2e/logs/proof-s1-source-20261120T194149Z/`](e2e/logs/proof-s1-source-20261120T194149Z/) (`sqlite_wal`, stdio upstream demo; manifest `scopegate.e2e_evidence_manifest.v1`, commit `2e16912`). Shows managed runtime/API flow evidence including MCP allow, deny (fail-closed), approval pending-deny → approved-allow, and `/v1/audit/verify` (`ok:true`, `checked_events:14` in captured probe). Not S1/S2 validation or sign-off.
>
> **Captured sqlite+stdio restart evidence:** [`e2e/logs/proof-s1-source-restart-20261120T201236Z/`](e2e/logs/proof-s1-source-restart-20261120T201236Z/) (same sqlite_wal DB/config): pre-restart S1 flow + post-restart audit verify/continuity and task-state continuity captured. [`e2e/logs/smoke-scripts-restart-evidence/`](e2e/logs/smoke-scripts-restart-evidence/) provides additional two-phase restart smoke. Runtime endpoint evidence only; **not** full restart/durability/prod proof.
>
> **Evidence index:** [`e2e/FINAL_S1_EVIDENCE.md`](e2e/FINAL_S1_EVIDENCE.md).

## Quickstart (local S1-style preview)

**Prereqs:** Rust toolchain (`rust-toolchain.toml`), Python 3, Node/npm, optional `curl`.

```bash
# 1) Baseline checks
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo test --all
python3 -m pytest bench -q              # 38 passed, 7 xfailed unconfigured; 44 passed, 1 xfailed on configured clean-gateway capture
python3 -m py_compile sdk/python/src/scopegate_sdk/__init__.py
cd dashboard && npm ci && npm run build && cd ..

# 2) Run HTTP gateway with SQLite (preview)
./scripts/run_sqlite_demo.sh
# or: cargo build -p gateway && GATEWAY_STORE_BACKEND=sqlite_wal SCOPEGATE_DATABASE_URL=sqlite:///./.scopegate/scopegate.db cargo run -p gateway

# 3) Basic probes (separate shell)
curl -s http://127.0.0.1:8080/healthz
curl -s http://127.0.0.1:8080/readyz
curl -s http://127.0.0.1:8080/metrics | head

# 4) MCP stdio mode (preview)
# GATEWAY_CONFIG=./scopegate.toml.example cargo run -p gateway -- --stdio
```

Config/examples: `scopegate.toml.example`, `policies/examples/`. Dashboard: `VITE_API_BASE_URL=http://127.0.0.1:8080` (`dashboard/.env.example`), `npm run dev` (live API/SSE with fallback). SDKs: `sdk/python`, `sdk/ts` (preview HTTP/MCP clients).

## Demo & evidence commands

```bash
# Managed sqlite API/MCP/bench evidence capture (best-effort)
./e2e/capture_live_evidence.sh
# E2E_LOG_DIR=./e2e/logs/s1-evidence SCOPEGATE_CONFIG=./scopegate.toml.example ./e2e/capture_live_evidence.sh
# E2E_SQLITE=1 E2E_API_FLOW=1 E2E_MCP_FLOW=1 E2E_BENCH_LIVE=1 E2E_BENCH_MODES=all ./e2e/demo_flow.sh

# Sqlite+stdio live + restart evidence helper (captures phase1/phase2 artifacts)
./scripts/run_sqlite_stdio_restart_evidence.sh
```

Typical artifacts: `evidence-manifest.json` / `manifest.json`, API/MCP request-response/meta, gateway logs, audit verify probes, optional bench outputs under `E2E_LOG_DIR/bench/<mode>/`. Treat all artifacts as **evidence, not validation/sign-off**. See [`e2e/README.md`](e2e/README.md), [`docs/runbook.md`](docs/runbook.md).

## Status snapshot (preview)

- **Workspace:** `crates/{core,gateway,mcp-front,mcp-pool,broker,store}`. Axum gateway exposes ops/admin/MCP-dispatch routes (`/healthz`, `/readyz`, `/metrics`, `/v1/tasks*`, `/v1/approvals*`, `/v1/audit*`, `/v1/policies`, `/v1/stream`, `/mcp`) with fail-closed intent on key paths; not full `rmcp`/end-to-end upstream runtime.
- **Store:** in-memory default; optional SQLite (WAL/sqlx) wiring with store-backed audit verification (`/v1/audit/verify`) in part. Captured sqlite+stdio proof/restart artifacts exist; durable end-to-end guarantees unproven.
- **Bench/SDKs/dashboard:** 38p/7xf unconfigured baseline, 44p/1x configured clean-gateway capture (evidence only); dashboard build + Python/TS static checks pass; clients/UI target evolving preview surfaces.
- **Source of truth:** [`docs/STATUS.md`](docs/STATUS.md), [`docs/architecture.md`](docs/architecture.md), [`docs/RELEASE_READINESS.md`](docs/RELEASE_READINESS.md).

## Remaining gaps & limitations

- **No sign-off / production readiness:** no security hardening sign-off, no complete S1/S2 runtime validation, no live authoritative enforce-mode proof, no hosted demo/release artifacts.
- **Durability/restart not proven:** captured restart evidence is a persistence signal only; restart-safe approvals/state/revocation/budgets, append-before-return audit across all runtime paths, recovery semantics, and production store behavior remain unverified.
- **Capability gaps (current source):** unresolved xfails/gaps include untrusted tool-output taint propagation to egress enforcement, concurrent cross-task isolation in live MCP handling, manifest/schema pinning/drift detection/re-approval, and agent-visible secret redaction/boundary enforcement.
- **Incomplete runtime/security integrations:** real Biscuit verification/attenuation, Cedar policy engine/YAML compile-load, full `rmcp` front↔pool↔upstream execution, production secret broker/adapters/injection-redaction guarantees, cryptographic/durable audit across all paths, Postgres/Redis S2 path, hardened ops/observability/rate-limit/budget/taint enforcement.
- **Non-goals (preview):** not an agent framework/LLM planner, not prompt-injection classification, not upstream MCP hosting, not multi-tenant SaaS/billing, not OS sandbox replacement, not broad non-MCP protocol support.

## Documentation

- [`docs/STATUS.md`](docs/STATUS.md) — implementation & verification snapshot
- [`docs/architecture.md`](docs/architecture.md) — component mapping & gaps
- [`docs/runbook.md`](docs/runbook.md) — ops/evidence notes (preview)
- [`docs/PRD.md`](docs/PRD.md) — target design (aspirational; drift applies)
- [`docs/threat-model.md`](docs/threat-model.md), [`docs/RELEASE_READINESS.md`](docs/RELEASE_READINESS.md), [`docs/migration.md`](docs/migration.md), [`docs/MIGRATION_MAP.md`](docs/MIGRATION_MAP.md)
- [`CONTRIBUTING.md`](CONTRIBUTING.md), [`SECURITY.md`](SECURITY.md)

## License

MIT — see [`LICENSE`](LICENSE).
