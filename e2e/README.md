# ScopeGate E2E / M7 Demo Flow (prep)

Practical, factual prep for running an M7-style demo/check flow as the runtime matures. Scripts here aim to exercise **real cargo/gateway commands when available**, while failing clearly and capturing logs when prerequisites or runtime surfaces are missing.

## Current state (factual)

- **Iteration:** M0/M6/M7/M8 loop (2026-11-17). Current verified baseline: `cargo fmt --all --check` pass, `cargo clippy --all-targets -- -D warnings` pass, `cargo test --all` pass, bench **38 passed, 7 xfailed** (no live gateway configured), dashboard build pass.
- **Gateway/runtime:** `crates/gateway` includes an axum HTTP server/binary with routes `/healthz,/readyz,/metrics,/v1/tasks,/v1/audit,/v1/approvals,/v1/policies,/v1/stream,/mcp`. SQLite WAL durable store can be configured via env/config; MCP dispatch can forward configured tools/call requests to upstreams (including stdio subprocess MCP servers) with policy/approval/audit hooks, but remains partial (not a full `rmcp` runtime, limited enforcement/secret brokering guarantees).
- **Bench:** pytest harness in `bench/` with `baseline|dryrun|enforce` modes. Unconfigured baseline: **38 passed, 7 xfailed**. With a configured local sqlite+stdio demo gateway, clean-gateway/data-dir capture recorded **45 passed, 0 xfailed** (`phase3a-t6-live-bench-20261121T170500Z`, includes capability + live-gateway integration tests; env-gated in unconfigured runs). Not enforce-mode sign-off/release bundle.
- **Audit chain:** core/store primitives exist (FNV-1a, non-cryptographic). Runtime `GET /v1/audit/verify` provides store-backed verification evidence for active runs (not complete persisted/cryptographic proof).
- **Ops endpoints:** `/healthz`, `/readyz`, `/metrics`, `/v1/stream` exist in gateway (scaffold-level behavior/schemas may evolve).

## Intended demo flow

1. **Toolchain & quality preflight**
   - `../scripts/check_rust_toolchain.sh` (optionally `CHECK_RUST_RUN=1`)
   - Records fmt/clippy/check/test readiness/evidence.

2. **Build gateway (real cargo build when available)**
   - `../scripts/build_gateway.sh`
   - Tries `cargo build -p gateway` (and can emit binary path/info) so compose/local runs can use a real artifact when implemented.

3. **Run gateway / managed HTTP API flow (optional)**
   - Foreground attempt: `../scripts/run_gateway.sh` via `E2E_RUN_GATEWAY=1` (real cargo run/binary attempt, limited by runtime maturity).
   - Managed API flow: `E2E_API_FLOW=1` starts gateway in background (best-effort), waits for readiness, exercises HTTP endpoints, captures request/response artifacts, then stops gateway.

4. **Run bench**
   - `../scripts/run_bench.sh [baseline|dryrun|enforce]`
   - Installs deps (best effort) and runs pytest; captures mode and exit status for evidence.

5. **Verify audit chain (proxy + optional runtime probe)**
   - `../scripts/verify_audit_chain.sh`
   - Runs audit-related Rust tests/primitives as a unit-test proxy when toolchain is available. Optionally probes runtime `GET /v1/audit/verify` when configured; probe results are best-effort endpoint evidence only, not persisted runtime proof.

6. **Release/readiness checklist**
   - `../scripts/release_checklist.sh` and `../scripts/RELEASE_CHECKLIST.md`

## `capture_live_evidence.sh` (S1/live-gateway evidence)

Convenience wrapper for runnable S1/live-gateway evidence capture. Generates a live runtime config, starts a real local SQLite gateway with one real stdio upstream demo (`e2e/stdio_demo_mcp_server.py`), exercises real HTTP/MCP flows (**allow/deny/approval** + audit query/verify), runs bench in `baseline,dryrun,enforce` modes against the live managed gateway when available, and captures structured artifacts.

```bash
./e2e/capture_live_evidence.sh
# custom output dir
E2E_LOG_DIR=./e2e/logs/s1-evidence ./e2e/capture_live_evidence.sh
```

Key outputs (environment-tolerant; missing deps/runtime recorded in logs/artifacts): `evidence-manifest.json`, `demo_flow.*.log`, `api_flow/` (generated live config, per-request HTTP/MCP req/resp/meta including allow/deny/approval evidence, managed gateway log/pid/summary, runtime audit verify probes), and `bench/<mode>/` per live bench mode (`bench-junit.xml`, `bench-summary.json`, `bench-report.md`, `bench-readme-table.md`, `bench-latency.json`, `bench-ci-env.json`). Baseline bench without gateway remains **38 passed, 7 xfailed**; a configured local sqlite+stdio demo clean-gateway/data-dir capture recorded **45 passed, 0 xfailed** (`phase3a-t6-live-bench-20261121T170500Z`; env-gated tests pass configured). Not enforce-mode sign-off.

## `demo_flow.sh`

`demo_flow.sh` orchestrates the steps above, writes timestamped logs to `e2e/logs/` (or `E2E_LOG_DIR`), supports env overrides for config/bind/mode/run behavior, and continues to later evidence steps even if early runtime steps fail (configurable via `E2E_STRICT=1`).

Enhancements for S1/live-gateway evidence capture: managed API flow can include best-effort MCP JSON-RPC flow captures (`/mcp` initialize/tools.list/tools.call), run bench in one or more modes against the live managed gateway before shutdown (`E2E_BENCH_MODES`, `E2E_BENCH_LIVE`), and emit a structured `evidence-manifest.json`.

**Not proof of a working system** — a runnable evidence/checklist harness.

### Common overrides

- `SCOPEGATE_CONFIG` (default: `scopegate.toml.example`)
- `SCOPEGATE_BIND_ADDR` (default: `127.0.0.1:8080`)
- `SCOPEGATE_BENCH_MODE` or arg to `run_bench.sh` (`baseline|dryrun|enforce`)
- `E2E_RUN_GATEWAY=1` to attempt starting the gateway (foreground; typically run in a separate terminal/tmux in real demos)
- `E2E_GATEWAY_TIMEOUT_SECONDS` to auto-stop a foreground gateway attempt after N seconds (if `timeout` available)
- `E2E_STRICT=1` to stop on first failing step
- `E2E_LOG_DIR` to choose log output directory
- `E2E_SQLITE=1` convenience to run gateway steps with `sqlite_wal` and a default DB under `E2E_LOG_DIR/scopegate-e2e.db` (unless overridden)
- `SCOPEGATE_STORE_BACKEND` / `GATEWAY_STORE_BACKEND` to configure gateway store mode (e.g. `inmemory`, `sqlite_wal`, `sqlite`; preserves gateway defaults when unset)
- `SCOPEGATE_DATABASE_URL` / `GATEWAY_DATABASE_URL` / `GATEWAY_STORE_URL` / `DATABASE_URL` for SQLite durable store URL/path (scripts create parent dirs best-effort)
- `E2E_API_FLOW=1` to start a managed background gateway and exercise HTTP API/MCP flows (captures artifacts; skips foreground `E2E_RUN_GATEWAY` path in the same run)
- `E2E_API_BASE_URL` to override API base URL (default: `http://$SCOPEGATE_BIND_ADDR`)
- `E2E_API_READY_TIMEOUT_SECONDS` readiness wait timeout for API flow (default: `60`)
- `E2E_API_ARTIFACT_DIR` response/meta artifact directory for API flow (default: `$E2E_LOG_DIR/api_flow`)
- `E2E_MCP_FLOW=1` include best-effort MCP JSON-RPC captures during managed flow (default: `1`)
- `E2E_BENCH_LIVE=1` run bench modes against the live managed gateway before shutdown (default: `1` when API flow is used)
- `E2E_BENCH_MODES` comma-separated bench modes for live managed flow (e.g. `baseline,dryrun,enforce` or `all`; default: `$SCOPEGATE_BENCH_MODE`)
- `E2E_BENCH_ARTIFACT_ROOT` per-mode live bench artifact root (default: `$E2E_LOG_DIR/bench`)
- `E2E_EVIDENCE_MANIFEST` structured evidence manifest path (default: `$E2E_LOG_DIR/evidence-manifest.json`)

### API/MCP flow coverage and live bench artifacts (`E2E_API_FLOW=1`, best-effort)

When enabled and `cargo`+`curl` are available, `demo_flow.sh` generates a live runtime config (SQLite + stdio upstream demo), starts a managed gateway, and captures artifacts under `E2E_API_ARTIFACT_DIR` (or `$E2E_LOG_DIR/api_flow`): `generated-scopegate-live.toml`, `*.json` responses, `*.meta` (method/url/status/request body ref), stderr files, `gateway.pid`, `summary.txt`, `api_flow.log`, and `runtime_audit_verify.*` probes.

Exercised flows (best-effort, runtime-dependent): `/healthz`, `/readyz`, `POST/GET /v1/tasks` (+ get/revoke), `POST /v1/approvals` create/resolve, `POST|GET /v1/audit` query, `GET /v1/audit/verify`, MCP JSON-RPC over `/mcp` (`initialize`, `tools/list`, `tools/call gateway.health`), and real stdio upstream demo evidence via `demo.echo`:
- **allow:** permitted `tools/call demo.echo` forwarded to stdio upstream demo
- **deny:** unpermitted `tools/call demo.forbidden` denied fail-closed by policy
- **approval:** pending approval denies, approved approval allows matching gated call
- post-action audit query/verify captures evidence

If the managed gateway is ready and `E2E_BENCH_LIVE=1`, bench modes in `E2E_BENCH_MODES` run against `E2E_API_BASE_URL` before shutdown. Per-mode artifacts are captured under `E2E_BENCH_ARTIFACT_ROOT/<mode>/` via `bench/ci_artifacts.sh`. Results are environment/runtime-dependent and recorded as evidence, not proof of complete runtime guarantees.

## Artifacts to capture

- Toolchain/quality command outputs (`fmt`, `clippy`, `test`) and commit hash
- Build logs and binary path/version
- Gateway config, env, runtime logs, and observed endpoint behavior (if any)
- API flow artifacts when enabled (`e2e/logs/api_flow/` or `E2E_API_ARTIFACT_DIR`): per-endpoint request/response/status/meta files, managed gateway log, PID, summary, and readiness probes
- Bench mode, counts (pass/xfail/fail/skip), and raw output
- Audit verification output (unit primitive proxy and/or runtime `GET /v1/audit/verify` probe when configured; exported persisted audit segment is future work)
- Gaps/deviations vs intended S1 flow

## Related docs

- `docs/STATUS.md` — factual status and latest verification snapshot
- `docs/runbook.md` — operations, S1/S2, rollback/incident guidance
- `docs/RELEASE_READINESS.md`, `scripts/RELEASE_CHECKLIST.md` — evidence/gates
- `docker/compose.yml` — local compose scaffold
