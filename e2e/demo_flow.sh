#!/usr/bin/env bash
set -euo pipefail

# E2E/M7 demo/check flow (prep, cargo/gateway-oriented).
# Orchestrates: toolchain/check -> build gateway -> (optional) run gateway ->
# run bench -> verify audit chain. Uses real cargo/gateway commands when available.
# Factual: runtime surfaces remain incomplete; failures may be expected. Captures
# logs/artifacts for evidence. Use E2E_STRICT=1 to stop on first failure.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPTS="$ROOT/scripts"
LOG_DIR="${E2E_LOG_DIR:-$ROOT/e2e/logs}"
mkdir -p "$LOG_DIR"

BENCH_MODE="${SCOPEGATE_BENCH_MODE:-baseline}"
RUN_GATEWAY="${E2E_RUN_GATEWAY:-0}"         # 1 = attempt to start gateway
GATEWAY_TIMEOUT="${E2E_GATEWAY_TIMEOUT_SECONDS:-0}" # 0 = no auto-timeout
STRICT="${E2E_STRICT:-0}"
CHECK_RUN="${E2E_CHECK_RUST_RUN:-0}"        # 1 = run fmt/clippy/check/test in preflight

timestamp() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }
step_fail=0
failures=()

run_step() {
  local name="$1"; shift
  local log="$1"; shift
  echo "[demo_flow] $(timestamp) STEP: $name" | tee "$log"
  if "$@" 2>&1 | tee -a "$log"; then
    echo "[demo_flow] RESULT: $name OK" | tee -a "$log"
    return 0
  else
    local code=$?
    echo "[demo_flow] RESULT: $name FAILED ($code)" | tee -a "$log"
    failures+=("$name:$code")
    step_fail=1
    if [[ "$STRICT" == "1" ]]; then
      echo "[demo_flow] STRICT mode enabled; stopping after failure." | tee -a "$log"
      exit "$code"
    fi
    return "$code"
  fi
}

{
  echo "[demo_flow] start=$(timestamp)"
  echo "[demo_flow] root=$ROOT"
  echo "[demo_flow] bench_mode=$BENCH_MODE run_gateway=$RUN_GATEWAY strict=$STRICT check_rust_run=$CHECK_RUN timeout=${GATEWAY_TIMEOUT}s"
  echo "[demo_flow] config=${SCOPEGATE_CONFIG:-$ROOT/scopegate.toml.example} bind=${SCOPEGATE_BIND_ADDR:-127.0.0.1:8080}"
  echo "[demo_flow] git_rev=$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"
} | tee "$LOG_DIR/demo_flow.meta.log"

echo "[demo_flow] Logs: $LOG_DIR"

echo "[demo_flow] Step 0/4: Rust toolchain/preflight"
if [[ "$CHECK_RUN" == "1" ]]; then
  run_step "check_rust_toolchain(run)" "$LOG_DIR/check_rust_toolchain.log" env CHECK_RUST_RUN=1 "$SCRIPTS/check_rust_toolchain.sh" || true
else
  run_step "check_rust_toolchain" "$LOG_DIR/check_rust_toolchain.log" "$SCRIPTS/check_rust_toolchain.sh" || true
fi

echo "[demo_flow] Step 1/4: Build gateway"
run_step "build_gateway" "$LOG_DIR/build_gateway.log" "$SCRIPTS/build_gateway.sh" || true

echo "[demo_flow] Step 1b: Probe gateway CLI via cargo (best-effort real run attempt)"
if command -v cargo >/dev/null 2>&1; then
  run_step "gateway_help_probe" "$LOG_DIR/gateway_help_probe.log" env SCOPEGATE_CONFIG="${SCOPEGATE_CONFIG:-$ROOT/scopegate.toml.example}" cargo run -q -p gateway -- --help || true
else
  echo "[demo_flow] gateway_help_probe skipped (cargo unavailable)" | tee "$LOG_DIR/gateway_help_probe.log"
fi

if [[ "$RUN_GATEWAY" == "1" ]]; then
  echo "[demo_flow] Step 2/4: Run gateway attempt (foreground/cargo run or binary)"
  echo "[demo_flow] NOTE: runtime may be incomplete; use a separate terminal for long-lived runs." | tee "$LOG_DIR/run_gateway.log"
  if [[ "$GATEWAY_TIMEOUT" =~ ^[0-9]+$ ]] && [[ "$GATEWAY_TIMEOUT" -gt 0 ]] && command -v timeout >/dev/null 2>&1; then
    run_step "run_gateway(timeout)" "$LOG_DIR/run_gateway.log" timeout "${GATEWAY_TIMEOUT}s" "$SCRIPTS/run_gateway.sh" || true
  else
    run_step "run_gateway" "$LOG_DIR/run_gateway.log" "$SCRIPTS/run_gateway.sh" || true
  fi
else
  echo "[demo_flow] Step 2/4: Run gateway skipped (set E2E_RUN_GATEWAY=1 to attempt)." | tee "$LOG_DIR/run_gateway.log"
fi

echo "[demo_flow] Step 3/4: Run bench"
run_step "run_bench" "$LOG_DIR/run_bench.log" "$SCRIPTS/run_bench.sh" "$BENCH_MODE" || true

echo "[demo_flow] Step 4/4: Verify audit chain"
run_step "verify_audit_chain" "$LOG_DIR/verify_audit_chain.log" "$SCRIPTS/verify_audit_chain.sh" || true

echo "[demo_flow] $(timestamp) Complete."
if [[ "$step_fail" -ne 0 ]]; then
  echo "[demo_flow] FAILURES: ${failures[*]}" | tee "$LOG_DIR/demo_flow.summary.log"
  echo "[demo_flow] Review logs in $LOG_DIR and scripts/RELEASE_CHECKLIST.md for evidence/gaps."
  exit 1
fi

echo "[demo_flow] All steps reported OK." | tee "$LOG_DIR/demo_flow.summary.log"
echo "[demo_flow] Review logs in $LOG_DIR for evidence artifacts." | tee -a "$LOG_DIR/demo_flow.summary.log"

