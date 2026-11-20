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
  --bench-mode "$MODE" \
  --gateway-url "${SCOPEGATE_GATEWAY_URL:-}" \
  --max-failures 0 --max-errors 0 --max-xpassed 0 \
  --format ci
REPORT_RC=$?
set -e
python3 bench/report.py \
  --junitxml "$OUT_DIR/bench-junit.xml" \
  --bench-mode "$MODE" \
  --gateway-url "${SCOPEGATE_GATEWAY_URL:-}" \
  --format readme-table > "$OUT_DIR/bench-readme-table.md" || true

python3 - "$OUT_DIR/bench-ci-env.json" "$MODE" "${SCOPEGATE_GATEWAY_URL:-}" "$PYTEST_RC" "$REPORT_RC" "$ROOT" <<'PY'
import json, os, platform, subprocess, sys
from datetime import datetime, timezone

out, mode, gw_url, pytest_rc, report_rc, root = sys.argv[1:7]
sys.path.insert(0, os.path.join(root, "bench"))
ctx = {
    "mode": mode,
    "gateway_url": gw_url or None,
    "gateway_configured": bool(gw_url),
    "pytest_rc": int(pytest_rc),
    "report_rc": int(report_rc),
    "timestamp_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "cwd": os.getcwd(),
    "python": sys.version.split()[0],
    "platform": platform.platform(),
}
try:
    ctx["commit"] = subprocess.check_output(["git", "-C", root, "rev-parse", "HEAD"], text=True).strip()
    ctx["commit_short"] = subprocess.check_output(["git", "-C", root, "rev-parse", "--short", "HEAD"], text=True).strip()
except Exception:
    ctx["commit"] = None
    ctx["commit_short"] = None
try:
    from harness import gateway_env_summary
    g = gateway_env_summary(gw_url)
    ctx.update(g)
    ctx["mode"] = mode  # explicit run mode
except Exception as e:
    ctx["gateway_env_error"] = str(e)
ctx["expected_baseline"] = "non-live baseline: 38 passed, 7 xfailed; live-configured runs may pass reachable/enforced live integration cases"
with open(out, "w", encoding="utf-8") as f:
    json.dump(ctx, f, indent=2, sort_keys=True)
    f.write("\n")
PY

echo "CI artifacts written to $OUT_DIR"
ls -1 "$OUT_DIR"

if [[ $PYTEST_RC -ne 0 ]]; then exit $PYTEST_RC; fi
exit $REPORT_RC
