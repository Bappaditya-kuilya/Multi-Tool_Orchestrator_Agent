#!/usr/bin/env bash
set -euo pipefail

# CI helper: run bench and emit standard artifacts (junit/json/md/latency/readme-table/env).
# Usage: ./bench/ci_artifacts.sh [baseline|dryrun|enforce]
# Env:
#   BENCH_OUT_DIR         - artifact output dir (default: bench/artifacts)
#   SCOPEGATE_GATEWAY_URL - optional live gateway URL (included in env artifact)
MODE="${1:-${SCOPEGATE_BENCH_MODE:-baseline}}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${BENCH_OUT_DIR:-$ROOT/bench/artifacts}"
mkdir -p "$OUT_DIR"

cd "$ROOT"
set +e
BENCH_LATENCY_OUT="$OUT_DIR/bench-latency.json" python3 -m pytest bench -q --bench-mode "$MODE" --junitxml "$OUT_DIR/bench-junit.xml"
PYTEST_RC=$?
set -e

set +e
python3 bench/report.py \
  --junitxml "$OUT_DIR/bench-junit.xml" \
  --latency-json "$OUT_DIR/bench-latency.json" \
  --json "$OUT_DIR/bench-summary.json" \
  --md "$OUT_DIR/bench-report.md" \
  --max-failures 0 --max-errors 0 --max-xpassed 0 \
  --format ci
REPORT_RC=$?
set -e
python3 bench/report.py --junitxml "$OUT_DIR/bench-junit.xml" --format readme-table > "$OUT_DIR/bench-readme-table.md" || true

cat > "$OUT_DIR/bench-ci-env.json" <<EOF
{
  "mode": "$MODE",
  "gateway_url": "${SCOPEGATE_GATEWAY_URL:-}",
  "gateway_configured": $( [[ -n "${SCOPEGATE_GATEWAY_URL:-}" ]] && echo true || echo false ),
  "pytest_rc": $PYTEST_RC,
  "report_rc": $REPORT_RC
}
EOF

echo "CI artifacts written to $OUT_DIR"
ls -1 "$OUT_DIR"

if [[ $PYTEST_RC -ne 0 ]]; then exit $PYTEST_RC; fi
exit $REPORT_RC
