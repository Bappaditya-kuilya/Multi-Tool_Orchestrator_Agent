#!/usr/bin/env bash
set -euo pipefail

# Helper to run bench against a locally started ScopeGate gateway (live/enforce evidence).
# Usage:
#   SCOPEGATE_GATEWAY_URL=http://localhost:8080 ./bench/run_local_gateway.sh [baseline|dryrun|enforce]
# Env:
#   SCOPEGATE_GATEWAY_URL   - gateway base URL (required for live integration evidence)
#   SCOPEGATE_BENCH_MODE    - fallback mode when arg omitted
#   BENCH_OUT_DIR           - artifact output dir (default: bench/artifacts)
#
# To start a local gateway (from repo root), typical options:
#   ./scripts/run_gateway.sh
#   cargo run -p gateway
#   SCOPEGATE_CONFIG=./scopegate.toml.example SCOPEGATE_BIND_ADDR=127.0.0.1:8080 ./scripts/run_gateway.sh
# Then run this script in another shell with SCOPEGATE_GATEWAY_URL set (e.g. http://127.0.0.1:8080).

MODE="${1:-${SCOPEGATE_BENCH_MODE:-enforce}}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${BENCH_OUT_DIR:-$ROOT/bench/artifacts}"
mkdir -p "$OUT_DIR"

echo "== bench local-gateway run =="
echo "mode=$MODE gateway_url=${SCOPEGATE_GATEWAY_URL:-<unset>} out_dir=$OUT_DIR"

if [[ -z "${SCOPEGATE_GATEWAY_URL:-}" ]]; then
  echo "WARN: SCOPEGATE_GATEWAY_URL not set; live cases will xfail and no live enforcement evidence will be collected." >&2
  echo "      Start gateway locally (e.g. ./scripts/run_gateway.sh or 'cargo run -p gateway') and export SCOPEGATE_GATEWAY_URL." >&2
fi

cd "$ROOT"
# Live-only evidence run (captures live junit; non-blocking to allow full artifact/report generation).
set +e
python3 -m pytest bench -q -m live --bench-mode "$MODE" --junitxml "$OUT_DIR/bench-live-junit.xml"
LIVE_RC=$?
set -e

# Full suite run with instrumented latency export for CI artifacts.
BENCH_LATENCY_OUT="$OUT_DIR/bench-latency.json" python3 -m pytest bench -q --bench-mode "$MODE" --junitxml "$OUT_DIR/bench-junit.xml"
SUITE_RC=$?

python3 bench/report.py \
  --junitxml "$OUT_DIR/bench-junit.xml" \
  --latency-json "$OUT_DIR/bench-latency.json" \
  --json "$OUT_DIR/bench-summary.json" \
  --md "$OUT_DIR/bench-report.md" \
  --max-failures 0 --max-errors 0 --max-xpassed 0 \
  --format ci || true
python3 bench/report.py --junitxml "$OUT_DIR/bench-junit.xml" --format readme-table > "$OUT_DIR/bench-readme-table.md" || true

cat > "$OUT_DIR/bench-env.json" <<EOF
{
  "mode": "$MODE",
  "gateway_url": "${SCOPEGATE_GATEWAY_URL:-}",
  "gateway_configured": $( [[ -n "${SCOPEGATE_GATEWAY_URL:-}" ]] && echo true || echo false ),
  "live_pytest_rc": $LIVE_RC,
  "suite_pytest_rc": $SUITE_RC
}
EOF

echo "artifacts: $OUT_DIR"
ls -1 "$OUT_DIR"
exit $SUITE_RC
