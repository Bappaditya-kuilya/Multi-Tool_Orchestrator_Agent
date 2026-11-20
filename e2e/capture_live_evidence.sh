#!/usr/bin/env bash
set -euo pipefail

# Convenience wrapper for runnable S1/live-gateway evidence capture.
# Starts/configures a real local sqlite gateway with one real stdio upstream demo, exercises
# real API/MCP flows (allow/deny/approval + audit query/verify), runs bench in
# baseline/dryrun/enforce modes against the live gateway when available, and captures
# structured artifacts (logs, per-mode junit/json/latency/md/env summaries, manifests).
#
# Environment-tolerant: missing cargo/curl/python/toolchain will be recorded as skips/failures
# per step; artifacts/logs are still produced where possible. Use E2E_STRICT=1 to fail fast.
#
# Usage:
#   ./e2e/capture_live_evidence.sh
#   E2E_LOG_DIR=./e2e/logs/s1-evidence ./e2e/capture_live_evidence.sh
#
# Common overrides (passed through to demo_flow.sh):
#   SCOPEGATE_CONFIG, SCOPEGATE_BIND_ADDR, SCOPEGATE_STORE_BACKEND, SCOPEGATE_DATABASE_URL,
#   E2E_API_READY_TIMEOUT_SECONDS, E2E_BENCH_MODES (default all), E2E_CHECK_RUST_RUN, E2E_STRICT

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ 2>/dev/null || echo now)"
DEFAULT_LOG_DIR="$ROOT/e2e/logs/s1-live-evidence-$STAMP"

export E2E_LOG_DIR="${E2E_LOG_DIR:-$DEFAULT_LOG_DIR}"
export E2E_SQLITE="${E2E_SQLITE:-1}"
export E2E_API_FLOW="${E2E_API_FLOW:-1}"
export E2E_MCP_FLOW="${E2E_MCP_FLOW:-1}"
export E2E_RESTART_CHECK="${E2E_RESTART_CHECK:-1}"
export E2E_BENCH_LIVE="${E2E_BENCH_LIVE:-1}"
export E2E_BENCH_MODES="${E2E_BENCH_MODES:-all}"
export SCOPEGATE_CONFIG="${SCOPEGATE_CONFIG:-$ROOT/scopegate.toml.example}"

mkdir -p "$E2E_LOG_DIR"

echo "[capture_live_evidence] root=$ROOT"
echo "[capture_live_evidence] log_dir=$E2E_LOG_DIR"
echo "[capture_live_evidence] config=$SCOPEGATE_CONFIG sqlite=$E2E_SQLITE bench_modes=$E2E_BENCH_MODES restart_check=$E2E_RESTART_CHECK"
echo "[capture_live_evidence] running e2e/demo_flow.sh (API/MCP flow + restart-persistence + live bench + audit verify)"

set +e
"$ROOT/e2e/demo_flow.sh"
rc=$?
set -e

echo "[capture_live_evidence] demo_flow rc=$rc"
echo "[capture_live_evidence] evidence manifest: ${E2E_EVIDENCE_MANIFEST:-$E2E_LOG_DIR/evidence-manifest.json}"
echo "[capture_live_evidence] key artifact roots:"
echo "  - logs/meta: $E2E_LOG_DIR/demo_flow.meta.log, $E2E_LOG_DIR/demo_flow.summary.log"
echo "  - api/mcp:   ${E2E_API_ARTIFACT_DIR:-$E2E_LOG_DIR/api_flow}"
echo "  - restart:   ${E2E_API_ARTIFACT_DIR:-$E2E_LOG_DIR/api_flow}/restart (restart-evidence-summary.json, post-restart audit/task probes)"
echo "  - bench:     ${E2E_BENCH_ARTIFACT_ROOT:-$E2E_LOG_DIR/bench}/<mode> (bench-junit.xml, bench-summary.json, bench-report.md, bench-latency.json, bench-ci-env.json, ...)"
echo "  - audit:     $E2E_LOG_DIR/verify_audit_chain.log and api_flow/runtime_audit_verify.* when captured"

exit "$rc"
