#!/usr/bin/env bash
set -euo pipefail

# Run ScopeGate bench suite (M4 harness). Supports raw pytest runs and evidence-capture
# artifacts (junit/json/md/latency/env/readme-table) for current-source sqlite+stdio S1 proof.
# Set BENCH_OUT_DIR to capture artifacts for the selected mode (delegates to bench/ci_artifacts.sh).
# Optional: SCOPEGATE_GATEWAY_URL for live gateway evidence, SCOPEGATE_BENCH_SKIP_PIP_INSTALL=1.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

MODE="${SCOPEGATE_BENCH_MODE:-${1:-baseline}}"
PYTHON="${PYTHON:-python3}"
PYTEST_ARGS_STR="${PYTEST_ARGS:-}"
BENCH_OUT_DIR="${BENCH_OUT_DIR:-${SCOPEGATE_BENCH_OUT_DIR:-}}"

if ! command -v "$PYTHON" >/dev/null 2>&1; then
  echo "[run_bench] python3 not found." >&2
  exit 127
fi

echo "[run_bench] root=$ROOT mode=$MODE python=$($PYTHON --version 2>&1 || echo unknown)"
echo "[run_bench] gateway_url=${SCOPEGATE_GATEWAY_URL:-<unset>} out_dir=${BENCH_OUT_DIR:-<none>}"
if [[ "${SCOPEGATE_BENCH_SKIP_PIP_INSTALL:-0}" == "1" ]]; then
  echo "[run_bench] skipping bench dependency install (SCOPEGATE_BENCH_SKIP_PIP_INSTALL=1)"
else
  echo "[run_bench] Installing bench deps: $PYTHON -m pip install -r bench/requirements.txt"
  if ! "$PYTHON" -m pip install -r bench/requirements.txt; then
    if "$PYTHON" -m pytest --version >/dev/null 2>&1; then
      echo "[run_bench] WARN: pip install failed but pytest is available; continuing with existing environment." >&2
    else
      echo "[run_bench] pytest unavailable after pip install failure." >&2
      exit 1
    fi
  fi
fi

if [[ -n "$BENCH_OUT_DIR" ]]; then
  export BENCH_OUT_DIR
  echo "[run_bench] evidence capture enabled: delegating to bench/ci_artifacts.sh (mode=$MODE out_dir=$BENCH_OUT_DIR)"
  exec "$ROOT/bench/ci_artifacts.sh" "$MODE"
fi

CMD=("$PYTHON" -m pytest bench -q "--bench-mode=$MODE")
if [[ -n "$PYTEST_ARGS_STR" ]]; then
  # shellcheck disable=SC2206
  EXTRA=( $PYTEST_ARGS_STR )
  CMD+=("${EXTRA[@]}")
fi

echo "[run_bench] Running: ${CMD[*]}"
"${CMD[@]}"
