# ScopeGate E2E / M7 Demo Flow (prep)

Practical, factual prep for running an M7-style demo/check flow as the runtime matures. Scripts here aim to exercise **real cargo/gateway commands when available**, while failing clearly and capturing logs when prerequisites or runtime surfaces are missing.

## Current state (factual)

- **Iteration:** M0/M6/M7/M8 loop (2026-11-17). Current verified baseline: `cargo fmt --all --check` pass, `cargo clippy --all-targets -- -D warnings` pass, `cargo test --all` pass, bench **38 passed, 7 xfailed**, dashboard build pass.
- **Gateway/runtime:** `crates/gateway` includes an axum HTTP server/binary with routes `/healthz,/readyz,/metrics,/v1/tasks,/v1/audit,/v1/approvals,/v1/policies,/v1/stream,/mcp` and in-memory store wiring by default. MCP dispatch is minimal (e.g. `initialize`, `tools/list`, `gateway.health`) and not a full `rmcp`/upstream execution path. Durable audit-before-return, production authz/enforcement, approvals persistence guarantees, and secret brokering remain incomplete.
- **Bench:** pytest harness in `bench/` with `baseline|dryrun|enforce` modes; gateway-coupled/live enforce proof is still incomplete.
- **Audit chain:** core/store primitives exist (FNV-1a, non-cryptographic) with in-memory wiring; no cryptographic/durable runtime export or `audit verify` CLI/API over persisted logs.
- **Ops endpoints:** `/healthz`, `/readyz`, `/metrics`, `/v1/stream` exist in gateway (scaffold-level behavior/schemas may evolve).

## Intended demo flow

1. **Toolchain & quality preflight**
   - `../scripts/check_rust_toolchain.sh` (optionally `CHECK_RUST_RUN=1`)
   - Records fmt/clippy/check/test readiness/evidence; clippy is currently a known blocker pending gateway fix.

2. **Build gateway (real cargo build when available)**
   - `../scripts/build_gateway.sh`
   - Tries `cargo build -p gateway` (and can emit binary path/info) so compose/local runs can use a real artifact when implemented.

3. **Run gateway (real cargo run/binary attempt)**
   - `../scripts/run_gateway.sh`
   - Attempts `cargo run -p gateway -- ...` (or configured binary) with config/bind/log env overrides. Foreground process; expect limited behavior until runtime lands.

4. **Run bench**
   - `../scripts/run_bench.sh [baseline|dryrun|enforce]`
   - Installs deps (best effort) and runs pytest; captures mode and exit status for evidence.

5. **Verify audit chain (best available proxy today)**
   - `../scripts/verify_audit_chain.sh`
   - Runs audit-related Rust tests/primitives as a proxy when toolchain is available; persisted runtime audit verification is future work.

6. **Release/readiness checklist**
   - `../scripts/release_checklist.sh` and `../scripts/RELEASE_CHECKLIST.md`

## `demo_flow.sh`

`demo_flow.sh` orchestrates the steps above, writes timestamped logs to `e2e/logs/` (or `E2E_LOG_DIR`), supports env overrides for config/bind/mode/run behavior, and continues to later evidence steps even if early runtime steps fail (configurable via `E2E_STRICT=1`).

**Not proof of a working system** — a runnable evidence/checklist harness.

### Common overrides

- `SCOPEGATE_CONFIG` (default: `scopegate.toml.example`)
- `SCOPEGATE_BIND_ADDR` (default: `127.0.0.1:8080`)
- `SCOPEGATE_BENCH_MODE` or arg to `run_bench.sh` (`baseline|dryrun|enforce`)
- `E2E_RUN_GATEWAY=1` to attempt starting the gateway (foreground; typically run in a separate terminal/tmux in real demos)
- `E2E_GATEWAY_TIMEOUT_SECONDS` to auto-stop a foreground gateway attempt after N seconds (if `timeout` available)
- `E2E_STRICT=1` to stop on first failing step
- `E2E_LOG_DIR` to choose log output directory

## Artifacts to capture

- Toolchain/quality command outputs (`fmt`, `clippy`, `test`) and commit hash
- Build logs and binary path/version
- Gateway config, env, runtime logs, and observed endpoint behavior (if any)
- Bench mode, counts (pass/xfail/fail/skip), and raw output
- Audit verification output (and exported audit segment when implemented)
- Gaps/deviations vs intended S1 flow

## Related docs

- `docs/STATUS.md` — factual status and latest verification snapshot
- `docs/runbook.md` — operations, S1/S2, rollback/incident guidance
- `docs/RELEASE_READINESS.md`, `scripts/RELEASE_CHECKLIST.md` — evidence/gates
- `docker/compose.yml` — local compose scaffold
