#!/usr/bin/env bash
set -euo pipefail

# Run ScopeGate bench suite (M4 harness). Captures mode and raw pytest outcome.
# Current baseline snapshot (2026-11-17): 38 passed, 7 xfailed (record mode/env/commit for evidence).

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

MODE="${SCOPEGATE_BENCH_MODE:-${1:-baseline}}"
PYTHON="${PYTHON:-python3}"
PYTEST_ARGS_STR="${PYTEST_ARGS:-}"

if ! command -v "$PYTHON" >/dev/null 2>&1; then
  echo "[run_bench] python3 not found." >&2
  exit 127
fi

echo "[run_bench] root=$ROOT mode=$MODE python=$($PYTHON --version 2>&1 || echo unknown)"
echo "[run_bench] Installing bench deps: $PYTHON -m pip install -r bench/requirements.txt"
"$PYTHON" -m pip install -r bench/requirements.txt

CMD=("$PYTHON" -m pytest bench -q "--bench-mode=$MODE")
if [[ -n "$PYTEST_ARGS_STR" ]]; then
  # shellcheck disable=SC2206
  EXTRA=( $PYTEST_ARGS_STR )
  CMD+=("${EXTRA[@]}")
fi

echo "[run_bench] Running: ${CMD[*]}"
"${CMD[@]}"
