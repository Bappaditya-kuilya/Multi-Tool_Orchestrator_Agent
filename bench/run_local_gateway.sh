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
  --bench-mode "$MODE" \
  --gateway-url "${SCOPEGATE_GATEWAY_URL:-}" \
  --max-failures 0 --max-errors 0 --max-xpassed 0 \
  --format ci || true
python3 bench/report.py \
  --junitxml "$OUT_DIR/bench-junit.xml" \
  --bench-mode "$MODE" \
  --gateway-url "${SCOPEGATE_GATEWAY_URL:-}" \
  --format readme-table > "$OUT_DIR/bench-readme-table.md" || true

python3 - "$OUT_DIR/bench-env.json" "$MODE" "${SCOPEGATE_GATEWAY_URL:-}" "$LIVE_RC" "$SUITE_RC" "$ROOT" <<'PY'
import json, os, platform, subprocess, sys
from datetime import datetime, timezone

out, mode, gw_url, live_rc, suite_rc, root = sys.argv[1:7]
sys.path.insert(0, os.path.join(root, "bench"))
ctx = {
    "mode": mode,
    "gateway_url": gw_url or None,
    "gateway_configured": bool(gw_url),
    "live_pytest_rc": int(live_rc),
    "suite_pytest_rc": int(suite_rc),
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

echo "artifacts: $OUT_DIR"
ls -1 "$OUT_DIR"
exit $SUITE_RC
