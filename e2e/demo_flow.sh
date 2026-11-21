#!/usr/bin/env bash
set -euo pipefail

# E2E/S1 demo/check/evidence flow (cargo/gateway-oriented).
# Orchestrates: toolchain/check -> build gateway -> (optional) run gateway/API+MCP flow ->
# run bench (single or multi-mode; live when gateway available) -> verify audit chain.
# Uses real cargo/gateway commands when available. Runtime surfaces may be incomplete;
# failures may be expected. Captures logs/artifacts for evidence.
#
# Store options (optional; preserves gateway defaults/in-memory behavior when unset):
# - E2E_SQLITE=1: convenience to enable sqlite_wal durable store for this run.
# - SCOPEGATE_STORE_BACKEND / GATEWAY_STORE_BACKEND: backend override (e.g. sqlite_wal, sqlite, inmemory).
# - SCOPEGATE_DATABASE_URL / GATEWAY_DATABASE_URL / GATEWAY_STORE_URL / DATABASE_URL:
#     sqlite database URL/path for durable mode (defaults under E2E_LOG_DIR when E2E_SQLITE=1).
#
# Managed HTTP API/MCP + live bench evidence flow (starts gateway in background, exercises endpoints, stops it):
# - E2E_API_FLOW=1: run task create/list/get/revoke, approvals create/resolve,
#     audit query, GET /v1/audit/verify, and best-effort MCP JSON-RPC calls.
# - E2E_API_BASE_URL: override base URL (default: http://${SCOPEGATE_BIND_ADDR:-127.0.0.1:8080}).
# - E2E_API_READY_TIMEOUT_SECONDS: readiness wait timeout (default: 60).
# - E2E_API_ARTIFACT_DIR: response/meta artifact dir (default: $E2E_LOG_DIR/api_flow).
# - E2E_BENCH_MODES: comma-separated bench modes to run during live managed flow when gateway ready
#     (e.g. baseline,dryrun,enforce or "all"). Default: "$BENCH_MODE" (single mode). "all" => baseline,dryrun,enforce.
# - E2E_BENCH_LIVE=1: run bench modes against live managed gateway (default: 1 when E2E_API_FLOW=1).
# - E2E_BENCH_ARTIFACT_ROOT: root dir for per-mode bench artifacts (default: $E2E_LOG_DIR/bench).
# - E2E_MCP_FLOW=1: include best-effort MCP flow captures during managed flow (default: 1).
#
# Other:
# - E2E_RUN_GATEWAY=1: foreground gateway attempt (separate from managed API flow).
# - E2E_STRICT=1: stop on first failure.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPTS="$ROOT/scripts"
LOG_DIR="${E2E_LOG_DIR:-$ROOT/e2e/logs}"
mkdir -p "$LOG_DIR"
LOG_DIR="$(cd "$LOG_DIR" && pwd)"

BENCH_MODE="${SCOPEGATE_BENCH_MODE:-baseline}"
RUN_GATEWAY="${E2E_RUN_GATEWAY:-0}"         # 1 = attempt to start gateway (foreground)
GATEWAY_TIMEOUT="${E2E_GATEWAY_TIMEOUT_SECONDS:-0}" # 0 = no auto-timeout
STRICT="${E2E_STRICT:-0}"
CHECK_RUN="${E2E_CHECK_RUST_RUN:-0}"        # 1 = run fmt/clippy/check/test in preflight
E2E_SQLITE="${E2E_SQLITE:-0}"               # 1 = convenience sqlite_wal mode for gateway steps
API_FLOW="${E2E_API_FLOW:-0}"               # 1 = managed background gateway + HTTP API/MCP flow
API_BASE_URL="${E2E_API_BASE_URL:-}"        # default derived below
API_READY_TIMEOUT="${E2E_API_READY_TIMEOUT_SECONDS:-60}"
API_ARTIFACT_DIR="${E2E_API_ARTIFACT_DIR:-$LOG_DIR/api_flow}"
BENCH_MODES="${E2E_BENCH_MODES:-$BENCH_MODE}"
BENCH_LIVE="${E2E_BENCH_LIVE:-1}"
BENCH_ARTIFACT_ROOT="${E2E_BENCH_ARTIFACT_ROOT:-$LOG_DIR/bench}"
MCP_FLOW="${E2E_MCP_FLOW:-1}"
RESTART_CHECK="${E2E_RESTART_CHECK:-1}"
EVIDENCE_MANIFEST="${E2E_EVIDENCE_MANIFEST:-$LOG_DIR/evidence-manifest.json}"

# Resolve store config for gateway-related steps without overriding explicit user env unless convenience requested.
E2E_STORE_BACKEND="${SCOPEGATE_STORE_BACKEND:-${GATEWAY_STORE_BACKEND:-}}"
E2E_DATABASE_URL="${SCOPEGATE_DATABASE_URL:-${GATEWAY_DATABASE_URL:-${GATEWAY_STORE_URL:-${DATABASE_URL:-}}}}"
if [[ "$E2E_SQLITE" == "1" ]]; then
  if [[ -z "$E2E_STORE_BACKEND" ]]; then
    E2E_STORE_BACKEND="sqlite_wal"
  fi
  if [[ -z "$E2E_DATABASE_URL" ]]; then
    E2E_DATABASE_URL="sqlite:///${LOG_DIR%/}/scopegate-e2e.db"
  fi
  if [[ "$E2E_DATABASE_URL" == sqlite://* && "$E2E_DATABASE_URL" != *"?"* ]]; then
    E2E_DATABASE_URL="${E2E_DATABASE_URL}?mode=rwc"
  fi
  export SCOPEGATE_STORE_BACKEND="$E2E_STORE_BACKEND"
  export SCOPEGATE_DATABASE_URL="$E2E_DATABASE_URL"
fi
if [[ -n "$E2E_DATABASE_URL" ]]; then
  db_path=""
  case "$E2E_DATABASE_URL" in
    sqlite:///*) db_path="${E2E_DATABASE_URL#sqlite:///}"; db_path="/$db_path" ;;
    sqlite://*) db_path="${E2E_DATABASE_URL#sqlite://}" ;;
    /*|./*|../*) db_path="$E2E_DATABASE_URL" ;;
  esac
  db_path="${db_path%%\?*}"
  db_path="${db_path%%#*}"
  if [[ -n "$db_path" && "$db_path" != ":memory:" ]]; then
    mkdir -p "$(dirname "$db_path")" 2>/dev/null || true
  fi
fi

if [[ -z "$API_BASE_URL" ]]; then
  API_BASE_URL="http://${SCOPEGATE_BIND_ADDR:-127.0.0.1:8080}"
fi
API_BASE_URL="${API_BASE_URL%/}"

timestamp() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }
step_fail=0
failures=()
soft_failures=()
api_flow_bench_ran=0
api_flow_status="not_run"
restart_persistence_status="not_run"

run_step() {
  local name="$1"; shift
  local log="$1"; shift
  echo "[demo_flow] $(timestamp) STEP: $name" | tee "$log"
  local code=0
  "$@" > >(tee -a "$log") 2>&1 || code=$?
  if [[ "$code" -eq 0 ]]; then
    echo "[demo_flow] RESULT: $name OK" | tee -a "$log"
    return 0
  else
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

run_soft_step() {
  local name="$1"; shift
  local log="$1"; shift
  echo "[demo_flow] $(timestamp) STEP(soft): $name" | tee "$log"
  local code=0
  "$@" > >(tee -a "$log") 2>&1 || code=$?
  if [[ "$code" -eq 0 ]]; then
    echo "[demo_flow] RESULT: $name OK" | tee -a "$log"
    return 0
  else
    echo "[demo_flow] RESULT: $name SOFT-FAILED ($code) (non-blocking)" | tee -a "$log"
    soft_failures+=("$name:$code")
    return 0
  fi
}

api_http_call() {
  local name="$1"; shift
  local method="$1"; shift
  local url="$1"; shift
  local body="${1:-}"
  local out="$API_ARTIFACT_DIR/${name}.json"
  local meta="$API_ARTIFACT_DIR/${name}.meta"
  local err="$API_ARTIFACT_DIR/${name}.stderr"
  local code="000"
  if ! command -v curl >/dev/null 2>&1; then
    echo "skipped=curl_unavailable" > "$meta"
    echo "[api_flow] $name skipped (curl unavailable)" >> "$API_ARTIFACT_DIR/api_flow.log"
    echo "000"
    return 0
  fi
  if [[ -n "$body" ]]; then
    code="$(curl -sS -o "$out" -w '%{http_code}' -X "$method" -H 'content-type: application/json' --data "$body" "$url" 2>"$err" || echo "000")"
  else
    code="$(curl -sS -o "$out" -w '%{http_code}' -X "$method" "$url" 2>"$err" || echo "000")"
  fi
  {
    printf 'name=%s\nmethod=%s\nurl=%s\nhttp_code=%s\n' "$name" "$method" "$url" "$code"
    if [[ -n "$body" ]]; then
      printf 'request_body_file=%s\n' "$API_ARTIFACT_DIR/${name}.request.json"
      printf '%s\n' "$body" > "$API_ARTIFACT_DIR/${name}.request.json"
    fi
  } > "$meta"
  echo "[api_flow] $name $method $url -> $code" >> "$API_ARTIFACT_DIR/api_flow.log"
  echo "$code"
}

mcp_http_call() {
  local name="$1"; shift
  local url="$1"; shift
  local rpc="$1"; shift
  local body
  body="$(python3 - "$rpc" <<'PY'
import json,sys
print(json.dumps({"method":"","payload_json":sys.argv[1]}))
PY
)" || {
    echo "[api_flow] $name failed to build MCP envelope (python3 unavailable?)" >> "$API_ARTIFACT_DIR/api_flow.log"
    echo "000"
    return 0
  }
  api_http_call "$name" POST "$url" "$body"
}

normalize_bench_modes() {
  local raw="$1"
  raw="${raw// /}"
  if [[ "$raw" == "all" ]]; then
    echo "baseline,dryrun,enforce"
    return 0
  fi
  echo "$raw"
}

run_bench_modes_live() {
  local modes_csv="$1"; shift
  local gateway_url="$1"; shift
  local root_out="$1"; shift
  local log="$1"; shift
  local any_fail=0
  mkdir -p "$root_out"
  IFS=',' read -r -a modes <<< "$modes_csv"
  for m in "${modes[@]}"; do
    m="${m// /}"
    [[ -z "$m" ]] && continue
    local mdir="$root_out/$m"
    mkdir -p "$mdir"
    echo "[api_flow] running bench mode=$m gateway_url=$gateway_url out=$mdir" | tee -a "$log"
    if env SCOPEGATE_GATEWAY_URL="$gateway_url" BENCH_OUT_DIR="$mdir" SCOPEGATE_BENCH_MODE="$m" \
      "$ROOT/bench/ci_artifacts.sh" "$m" >"$mdir/ci_artifacts.stdout.log" 2>&1; then
      echo "[api_flow] bench mode=$m OK" | tee -a "$log"
      echo "mode=$m rc=0 out_dir=$mdir" >> "$API_ARTIFACT_DIR/bench_modes.summary.txt"
    else
      local rc=$?
      echo "[api_flow] bench mode=$m FAILED rc=$rc" | tee -a "$log"
      echo "mode=$m rc=$rc out_dir=$mdir" >> "$API_ARTIFACT_DIR/bench_modes.summary.txt"
      failures+=("bench_live_${m}:$rc")
      step_fail=1
      any_fail=1
      if [[ "$STRICT" == "1" ]]; then
        return "$rc"
      fi
    fi
  done
  return "$any_fail"
}

run_restart_persistence_flow() {
  local log="$LOG_DIR/restart_persistence.log"
  local summary="$API_ARTIFACT_DIR/restart_persistence.summary.txt"
  local restart_dir="$API_ARTIFACT_DIR/restart"
  mkdir -p "$restart_dir"
  : > "$log"
  : > "$summary"
  echo "[restart] start=$(timestamp) api_flow_status=$api_flow_status" | tee -a "$log"
  echo "start=$(timestamp)" >> "$summary"
  echo "api_flow_status=$api_flow_status" >> "$summary"

  if [[ "$API_FLOW" != "1" || "$api_flow_status" != "completed" ]]; then
    echo "[restart] skipped (requires completed managed API flow)" | tee -a "$log"
    echo "status=skipped_no_completed_api_flow" >> "$summary"
    restart_persistence_status="skipped_no_completed_api_flow"
    return 0
  fi
  if ! command -v cargo >/dev/null 2>&1; then
    echo "[restart] cargo unavailable; cannot restart gateway" | tee -a "$log"
    echo "status=skipped_no_cargo" >> "$summary"
    restart_persistence_status="skipped_no_cargo"
    return 127
  fi
  if ! command -v curl >/dev/null 2>&1; then
    echo "[restart] curl unavailable; cannot probe restarted gateway" | tee -a "$log"
    echo "status=skipped_no_curl" >> "$summary"
    restart_persistence_status="skipped_no_curl"
    return 127
  fi

  local db_url="${SCOPEGATE_DATABASE_URL:-${GATEWAY_DATABASE_URL:-${GATEWAY_STORE_URL:-${DATABASE_URL:-}}}}"
  local store_backend="${SCOPEGATE_STORE_BACKEND:-${GATEWAY_STORE_BACKEND:-}}"
  local cfg="${SCOPEGATE_CONFIG:-$API_ARTIFACT_DIR/generated-scopegate-live.toml}"
  if [[ ! -f "$cfg" && -f "$API_ARTIFACT_DIR/generated-scopegate-live.toml" ]]; then
    cfg="$API_ARTIFACT_DIR/generated-scopegate-live.toml"
  fi
  echo "database_url=$db_url" >> "$summary"
  echo "store_backend=$store_backend" >> "$summary"
  echo "config=$cfg" >> "$summary"

  local db_path=""
  case "$db_url" in
    sqlite:///*) db_path="${db_url#sqlite:///}"; db_path="/$db_path" ;;
    sqlite://*) db_path="${db_url#sqlite://}" ;;
    /*|./*|../*) db_path="$db_url" ;;
  esac
  db_path="${db_path%%\?*}"
  db_path="${db_path%%#*}"
  echo "database_path=$db_path" >> "$summary"
  if [[ -n "$db_path" && "$db_path" != ":memory:" && -f "$db_path" ]]; then
    echo "database_file_exists=true" >> "$summary"
  else
    echo "database_file_exists=false" >> "$summary"
  fi
  if [[ ! -f "$cfg" ]]; then
    echo "[restart] config not found ($cfg); cannot restart with same config" | tee -a "$log"
    echo "status=skipped_no_config" >> "$summary"
    restart_persistence_status="skipped_no_config"
    return 0
  fi

  local task_id="" approval_id="" approval_gate_id=""
  if [[ -f "$API_ARTIFACT_DIR/summary.txt" ]]; then
    task_id="$(grep '^task_id=' "$API_ARTIFACT_DIR/summary.txt" | tail -n1 | cut -d= -f2- || true)"
    approval_id="$(grep '^approval_id=' "$API_ARTIFACT_DIR/summary.txt" | tail -n1 | cut -d= -f2- || true)"
    approval_gate_id="$(grep '^approval_gate_id=' "$API_ARTIFACT_DIR/summary.txt" | tail -n1 | cut -d= -f2- || true)"
  fi
  echo "prior_task_id=${task_id}" >> "$summary"
  echo "prior_approval_id=${approval_id}" >> "$summary"
  echo "prior_approval_gate_id=${approval_gate_id}" >> "$summary"

  export SCOPEGATE_CONFIG="$cfg"
  export SCOPEGATE_STORE_BACKEND="$store_backend"
  export SCOPEGATE_DATABASE_URL="$db_url"
  export GATEWAY_DATABASE_URL="$db_url"
  export GATEWAY_ADDR="${SCOPEGATE_BIND_ADDR:-127.0.0.1:8080}"
  export RUST_LOG="${RUST_LOG:-info}"

  local gw_log="$LOG_DIR/api_flow_gateway_restart.log"
  local gw_cmd_desc="cargo run -q -p gateway --"
  if [[ -x "$ROOT/target/debug/gateway" ]]; then
    gw_cmd_desc="$ROOT/target/debug/gateway"
    echo "[restart] starting gateway (restart, background): $gw_cmd_desc" | tee -a "$log"
    (
      cd "$ROOT"
      exec "$ROOT/target/debug/gateway"
    ) >"$gw_log" 2>&1 &
  else
    echo "[restart] starting gateway (restart, background): $gw_cmd_desc" | tee -a "$log"
    (
      cd "$ROOT"
      exec cargo run -q -p gateway --
    ) >"$gw_log" 2>&1 &
  fi
  local gw_pid=$!
  echo "$gw_pid" > "$restart_dir/gateway.pid"
  echo "gateway_pid=$gw_pid" >> "$summary"
  cleanup_restart_gateway() {
    if kill -0 "$gw_pid" >/dev/null 2>&1; then
      kill "$gw_pid" >/dev/null 2>&1 || true
      sleep 1
      kill -9 "$gw_pid" >/dev/null 2>&1 || true
    fi
  }
  trap cleanup_restart_gateway EXIT

  local ready=0 waited=0 timeout_s="${API_READY_TIMEOUT:-60}"
  [[ "$timeout_s" =~ ^[0-9]+$ ]] || timeout_s=60
  echo "[restart] waiting for restarted gateway readiness (timeout=${timeout_s}s)" | tee -a "$log"
  while [[ "$waited" -lt "$timeout_s" ]]; do
    if curl -fsS "$API_BASE_URL/readyz" >/dev/null 2>&1 || curl -fsS "$API_BASE_URL/healthz" >/dev/null 2>&1; then
      ready=1
      break
    fi
    if ! kill -0 "$gw_pid" >/dev/null 2>&1; then
      echo "[restart] restarted gateway exited before ready" | tee -a "$log"
      break
    fi
    sleep 1
    waited=$((waited + 1))
  done
  echo "ready_wait_seconds=$waited" >> "$summary"
  echo "ready=$ready" >> "$summary"
  if [[ "$ready" -ne 1 ]]; then
    echo "[restart] restarted gateway not ready; capturing probes/tail" | tee -a "$log"
    local out="$restart_dir/00_readyz_probe.json" meta="$restart_dir/00_readyz_probe.meta" err="$restart_dir/00_readyz_probe.stderr" code="000"
    code="$(curl -sS -o "$out" -w '%{http_code}' "$API_BASE_URL/readyz" 2>"$err" || echo 000)"
    printf 'name=%s\nmethod=%s\nurl=%s\nhttp_code=%s\n' "00_readyz_probe" GET "$API_BASE_URL/readyz" "$code" > "$meta"
    tail -n 120 "$gw_log" > "$restart_dir/gateway.tail.log" 2>/dev/null || true
    cleanup_restart_gateway
    trap - EXIT
    echo "status=gateway_not_ready" >> "$summary"
    restart_persistence_status="gateway_not_ready"
    return 1
  fi

  restart_http_call() {
    local name="$1"; local method="$2"; local url="$3"; local body="${4:-}"
    local out="$restart_dir/${name}.json" meta="$restart_dir/${name}.meta" err="$restart_dir/${name}.stderr" code="000"
    if [[ -n "$body" ]]; then
      code="$(curl -sS -o "$out" -w '%{http_code}' -X "$method" -H 'content-type: application/json' --data "$body" "$url" 2>"$err" || echo 000)"
      printf '%s\n' "$body" > "$restart_dir/${name}.request.json"
    else
      code="$(curl -sS -o "$out" -w '%{http_code}' -X "$method" "$url" 2>"$err" || echo 000)"
    fi
    printf 'name=%s\nmethod=%s\nurl=%s\nhttp_code=%s\n' "$name" "$method" "$url" "$code" > "$meta"
    echo "[restart] $name $method $url -> $code" >> "$log"
    echo "$code"
  }

  restart_http_call "01_healthz" GET "$API_BASE_URL/healthz" || true
  restart_http_call "02_readyz" GET "$API_BASE_URL/readyz" || true
  restart_http_call "03_tasks_list" GET "$API_BASE_URL/v1/tasks" || true
  if [[ -n "$task_id" ]]; then
    restart_http_call "04_task_get" GET "$API_BASE_URL/v1/tasks/$task_id" || true
  fi
  restart_http_call "05_audit_query_get" GET "$API_BASE_URL/v1/audit?limit=100" || true
  if [[ -n "$task_id" ]]; then
    restart_http_call "06_audit_query_post_task" POST "$API_BASE_URL/v1/audit" "{\"task_id\":\"$task_id\",\"verify\":true,\"limit\":100}" || true
  fi
  restart_http_call "07_audit_verify_get" GET "$API_BASE_URL/v1/audit/verify" || true

  local evidence_json="$restart_dir/restart-evidence-summary.json"
  local evidence_txt="$restart_dir/restart-evidence-summary.txt"
  python3 - "$evidence_json" "$evidence_txt" "$restart_dir" "$API_ARTIFACT_DIR" "$task_id" "$db_url" "$store_backend" "$cfg" <<'PY' 2>/dev/null || true
import json, os, sys
out, txt, rdir, apidir, task_id, db_url, store_backend, cfg = sys.argv[1:9]
def load_json(path):
    try:
        with open(path, encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return None
def meta_code(name):
    p = os.path.join(rdir, f"{name}.meta")
    try:
        with open(p, encoding='utf-8') as f:
            for line in f:
                if line.startswith('http_code='):
                    return line.strip().split('=',1)[1]
    except Exception:
        pass
    return 'missing'
pre_verify = load_json(os.path.join(apidir, '23_audit_verify_get_post_actions.json')) or load_json(os.path.join(apidir, '10_audit_verify_get.json'))
post_verify = load_json(os.path.join(rdir, '07_audit_verify_get.json'))
pre_audit = load_json(os.path.join(apidir, '22_audit_query_get_post_actions.json'))
post_audit = load_json(os.path.join(rdir, '05_audit_query_get.json'))
pre_task = load_json(os.path.join(apidir, '12_task_get_after_revoke.json')) or load_json(os.path.join(apidir, '05_task_get.json'))
post_task = load_json(os.path.join(rdir, '04_task_get.json')) if task_id else None
tasks_list = load_json(os.path.join(rdir, '03_tasks_list.json'))
def verify_body(obj):
    if isinstance(obj, dict):
        b = obj.get('body') if isinstance(obj.get('body'), dict) else {}
        return {'ok': b.get('ok'), 'checked_events': b.get('checked_events'), 'first_bad_seq': b.get('first_bad_seq')}
    return {}
def audit_events(obj):
    if isinstance(obj, dict):
        b = obj.get('body') if isinstance(obj.get('body'), dict) else {}
        ev = b.get('events') if isinstance(b.get('events'), list) else None
        if ev is not None:
            return {'count': len(ev), 'chain_verified': b.get('chain_verified')}
    return {}
def task_state(obj):
    if isinstance(obj, dict):
        b = obj.get('body') if isinstance(obj.get('body'), dict) else {}
        return {'id': b.get('id'), 'revoked': b.get('revoked'), 'revocation_reason': b.get('revocation_reason'), 'token_id': b.get('token_id')}
    return {}
pre_v = verify_body(pre_verify); post_v = verify_body(post_verify)
pre_a = audit_events(pre_audit); post_a = audit_events(post_audit)
pre_t = task_state(pre_task); post_t = task_state(post_task) if post_task else {}
tl = tasks_list.get('body', {}) if isinstance(tasks_list, dict) else {}
tl_tasks = tl.get('tasks') if isinstance(tl, dict) and isinstance(tl.get('tasks'), list) else []
notes = []
if post_v.get('ok') is True:
    notes.append('audit chain verify ok after restart (runtime endpoint evidence)')
elif post_v:
    notes.append(f"audit chain verify after restart not ok/inconclusive: {post_v}")
else:
    notes.append('audit chain verify after restart artifact missing/unparsed')
if pre_a.get('count') is not None and post_a.get('count') is not None:
    if post_a.get('count') >= pre_a.get('count'):
        notes.append(f"audit events continuity: pre={pre_a.get('count')} post={post_a.get('count')} (non-decreasing observed)")
    else:
        notes.append(f"audit events continuity: pre={pre_a.get('count')} post={post_a.get('count')} (decreased; investigate)")
if task_id:
    found = any(isinstance(t, dict) and t.get('id') == task_id for t in tl_tasks)
    notes.append(f"task continuity: prior task_id {'present' if found else 'not found'} in tasks list after restart")
    if pre_t and post_t:
        same_revoked = pre_t.get('revoked') == post_t.get('revoked')
        notes.append(f"task state continuity (revoked): pre={pre_t.get('revoked')} post={post_t.get('revoked')} match={same_revoked}")
else:
    notes.append('task continuity: no prior task_id available for comparison')
data = {
    'schema': 'scopegate.e2e_restart_persistence_evidence.v1',
    'database_url': db_url or None,
    'store_backend': store_backend or None,
    'config': cfg,
    'prior_task_id': task_id or None,
    'http_codes': {k: meta_code(k) for k in ['01_healthz','02_readyz','03_tasks_list','04_task_get','05_audit_query_get','06_audit_query_post_task','07_audit_verify_get']},
    'pre_shutdown_audit_verify': pre_v,
    'post_restart_audit_verify': post_v,
    'pre_shutdown_audit_query': pre_a,
    'post_restart_audit_query': post_a,
    'pre_shutdown_task_state': pre_t,
    'post_restart_task_state': post_t,
    'tasks_count_after_restart': len(tl_tasks),
    'notes': notes,
}
with open(out, 'w', encoding='utf-8') as f:
    json.dump(data, f, indent=2, sort_keys=True); f.write('\n')
lines = [
    'schema=scopegate.e2e_restart_persistence_evidence.v1',
    f'database_url={db_url}',
    f'store_backend={store_backend}',
    f'config={cfg}',
    f'prior_task_id={task_id}',
    f'pre_shutdown_audit_verify_ok={pre_v.get("ok")}',
    f'post_restart_audit_verify_ok={post_v.get("ok")}',
    f'pre_shutdown_audit_events={pre_a.get("count")}',
    f'post_restart_audit_events={post_a.get("count")}',
    f'tasks_count_after_restart={len(tl_tasks)}',
]
for n in notes:
    lines.append('note=' + n)
with open(txt, 'w', encoding='utf-8') as f:
    f.write('\n'.join(lines) + '\n')
PY
  echo "restart_evidence_summary_json=$evidence_json" >> "$summary"
  echo "restart_evidence_summary_txt=$evidence_txt" >> "$summary"

  cleanup_restart_gateway
  trap - EXIT
  echo "[restart] completed restart-persistence checks; artifacts in $restart_dir" | tee -a "$log"
  echo "status=completed" >> "$summary"
  restart_persistence_status="completed"
  return 0
}

write_evidence_manifest() {
  python3 - "$EVIDENCE_MANIFEST" "$ROOT" "$LOG_DIR" "$API_ARTIFACT_DIR" "$BENCH_ARTIFACT_ROOT" "$BENCH_MODE" "$BENCH_MODES" "$API_FLOW" "$api_flow_status" "$api_flow_bench_ran" "$API_BASE_URL" "${SCOPEGATE_STORE_BACKEND:-${GATEWAY_STORE_BACKEND:-}}" "${SCOPEGATE_DATABASE_URL:-${GATEWAY_DATABASE_URL:-${GATEWAY_STORE_URL:-${DATABASE_URL:-}}}}" "$E2E_SQLITE" "$STRICT" "$restart_persistence_status" "$API_ARTIFACT_DIR/restart" <<'PY' || true
import json, os, subprocess, sys
from datetime import datetime, timezone

out, root, log_dir, api_dir, bench_root, bench_mode, bench_modes, api_flow, api_status, bench_ran, api_base, store_backend, db_url, e2e_sqlite, strict, restart_status, restart_dir = sys.argv[1:18]
def git_val(args):
    try:
        return subprocess.check_output(["git", "-C", root] + args, text=True).strip()
    except Exception:
        return None
manifest = {
    "schema": "scopegate.e2e_evidence_manifest.v1",
    "timestamp_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "root": root,
    "log_dir": log_dir,
    "commit": git_val(["rev-parse", "HEAD"]),
    "commit_short": git_val(["rev-parse", "--short", "HEAD"]),
    "config": {
        "bench_mode_default": bench_mode,
        "bench_modes_requested": bench_modes,
        "api_flow": api_flow == "1",
        "api_base_url": api_base,
        "store_backend": store_backend or None,
        "database_url": db_url or None,
        "e2e_sqlite": e2e_sqlite == "1",
        "strict": strict == "1",
    },
    "api_flow": {
        "status": api_status,
        "artifact_dir": api_dir,
        "bench_modes_ran_live": bench_ran == "1",
        "bench_artifact_root": bench_root,
    },
    "restart_persistence": {
        "status": restart_status,
        "artifact_dir": restart_dir,
    },
}
# collect known artifact pointers best-effort
art = {}
for rel in [
    "demo_flow.meta.log","demo_flow.summary.log","api_flow.step.log","api_flow.log",
    "restart_persistence.log","restart_persistence.step.log",
    "check_rust_toolchain.log","build_gateway.log","gateway_help_probe.log","run_gateway.log",
    "run_bench.log","verify_audit_chain.log","evidence-manifest.json"
]:
    p = os.path.join(log_dir, rel)
    if os.path.exists(p):
        art[rel] = p
for rel in [
    os.path.join(restart_dir, "restart-evidence-summary.json"),
    os.path.join(restart_dir, "restart-evidence-summary.txt"),
    os.path.join(api_dir, "restart_persistence.summary.txt"),
]:
    if os.path.exists(rel):
        art[os.path.basename(rel) if rel.startswith(restart_dir) else os.path.relpath(rel, log_dir)] = rel
manifest["artifacts"] = art
os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
with open(out, "w", encoding="utf-8") as f:
    json.dump(manifest, f, indent=2, sort_keys=True)
    f.write("\n")
PY
}

generate_live_gateway_config() {
  local out="$1"
  local db_url="$2"
  local store_backend="$3"
  local bind_addr="$4"
  python3 - "$out" "$db_url" "$store_backend" "$ROOT" "$bind_addr" <<'PY'
import os, sys
out, db_url, store_backend, root, bind_addr = sys.argv[1:6]
server = os.path.join(root, "e2e", "stdio_demo_mcp_server.py")
cfg = f'''# Generated by e2e/demo_flow.sh for live sqlite + stdio-upstream evidence

[gateway]
fail_closed = true
require_token_scope_for_action = false
egress_policy = "require_approval_on_conflict"
store_backend = "{store_backend or "sqlite_wal"}"
database_url = "{db_url}"
listen_addr = "{bind_addr or "127.0.0.1:8080"}"

[mcp]
mode = "http"
default_upstream = "demo-stdio"

[[mcp_upstream]]
id = "demo-stdio"
transport = "stdio"
program = "python3"
args = ["{server}"]

# Allow basic MCP + demo upstream tool for anonymous evidence calls; other tools denied (fail-closed)
[[rule]]
principal = "anonymous"
action = "tools/list"
resource = "tools/list"
decision = "permit"

[[rule]]
principal = "anonymous"
action = "tools/call"
resource = "gateway.health"
decision = "permit"

[[rule]]
principal = "anonymous"
action = "tools/call"
resource = "demo.echo"
decision = "permit"

# Keep task API demo path allowed for existing managed flow coverage
[[rule]]
principal = "agent"
action = "tool.invoke"
resource = "tool"
decision = "permit"
'''
os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
with open(out, "w", encoding="utf-8") as f:
    f.write(cfg)
PY
}

run_managed_api_flow() {
  local log="$LOG_DIR/api_flow.log"
  local gw_log="$LOG_DIR/api_flow_gateway.log"
  local summary="$API_ARTIFACT_DIR/summary.txt"
  mkdir -p "$API_ARTIFACT_DIR"
  : > "$log"
  : > "$summary"
  echo "[api_flow] start=$(timestamp) base_url=$API_BASE_URL sqlite=$E2E_SQLITE" | tee -a "$log"
  echo "start=$(timestamp)" >> "$summary"
  echo "base_url=$API_BASE_URL" >> "$summary"
  echo "store_backend=${SCOPEGATE_STORE_BACKEND:-${GATEWAY_STORE_BACKEND:-<gateway-default>}}" >> "$summary"
  echo "database_url=${SCOPEGATE_DATABASE_URL:-${GATEWAY_DATABASE_URL:-${GATEWAY_STORE_URL:-${DATABASE_URL:-<gateway-default>}}}}" >> "$summary"

  if [[ -z "${SCOPEGATE_BIND_ADDR:-}" ]]; then
    export SCOPEGATE_BIND_ADDR="127.0.0.1:8080"
  fi
  export GATEWAY_ADDR="$SCOPEGATE_BIND_ADDR"
  export RUST_LOG="${RUST_LOG:-info}"
  if [[ "$E2E_SQLITE" == "1" ]]; then
    export SCOPEGATE_STORE_BACKEND="${SCOPEGATE_STORE_BACKEND:-sqlite_wal}"
    export SCOPEGATE_DATABASE_URL="${SCOPEGATE_DATABASE_URL:-sqlite:///${LOG_DIR%/}/scopegate-e2e.db?mode=rwc}"
  fi
  if [[ "${SCOPEGATE_DATABASE_URL:-}" == sqlite://* && "${SCOPEGATE_DATABASE_URL:-}" != *"?"* ]]; then
    export SCOPEGATE_DATABASE_URL="${SCOPEGATE_DATABASE_URL}?mode=rwc"
  fi
  if [[ -n "${SCOPEGATE_DATABASE_URL:-}" ]]; then
    export GATEWAY_DATABASE_URL="$SCOPEGATE_DATABASE_URL"
  fi

  # Generate runtime config for real local sqlite gateway + stdio upstream demo evidence.
  local live_cfg="$API_ARTIFACT_DIR/generated-scopegate-live.toml"
  if generate_live_gateway_config "$live_cfg" "${SCOPEGATE_DATABASE_URL:-sqlite:///${LOG_DIR%/}/scopegate-e2e.db}" "${SCOPEGATE_STORE_BACKEND:-sqlite_wal}" "${SCOPEGATE_BIND_ADDR:-127.0.0.1:8080}" 2>>"$log"; then
    export SCOPEGATE_CONFIG="$live_cfg"
    echo "generated_config=$live_cfg" >> "$summary"
    echo "stdio_upstream_demo=$ROOT/e2e/stdio_demo_mcp_server.py" >> "$summary"
    echo "[api_flow] using generated live config: $live_cfg (sqlite + stdio upstream demo)" | tee -a "$log"
  else
    export SCOPEGATE_CONFIG="${SCOPEGATE_CONFIG:-$ROOT/scopegate.toml.example}"
    echo "generated_config=failed_fallback" >> "$summary"
    echo "[api_flow] WARN: failed to generate live config; falling back to $SCOPEGATE_CONFIG" | tee -a "$log"
  fi

  if ! command -v cargo >/dev/null 2>&1; then
    echo "[api_flow] cargo unavailable; cannot start managed gateway" | tee -a "$log"
    echo "status=skipped_no_cargo" >> "$summary"
    api_flow_status="skipped_no_cargo"
    return 127
  fi
  if ! command -v curl >/dev/null 2>&1; then
    echo "[api_flow] curl unavailable; cannot exercise HTTP endpoints (gateway start skipped)" | tee -a "$log"
    echo "status=skipped_no_curl" >> "$summary"
    api_flow_status="skipped_no_curl"
    return 127
  fi

  local gw_cmd_desc="cargo run -q -p gateway --"
  if [[ -x "$ROOT/target/debug/gateway" ]]; then
    gw_cmd_desc="$ROOT/target/debug/gateway"
    echo "[api_flow] starting gateway (background): $gw_cmd_desc" | tee -a "$log"
    (
      cd "$ROOT"
      exec "$ROOT/target/debug/gateway"
    ) >"$gw_log" 2>&1 &
  else
    echo "[api_flow] starting gateway (background): $gw_cmd_desc" | tee -a "$log"
    (
      cd "$ROOT"
      exec cargo run -q -p gateway --
    ) >"$gw_log" 2>&1 &
  fi
  local gw_pid=$!
  echo "$gw_pid" > "$API_ARTIFACT_DIR/gateway.pid"
  echo "gateway_pid=$gw_pid" >> "$summary"
  echo "[api_flow] gateway pid=$gw_pid log=$gw_log" | tee -a "$log"

  cleanup_api_gateway() {
    if kill -0 "$gw_pid" >/dev/null 2>&1; then
      kill "$gw_pid" >/dev/null 2>&1 || true
      sleep 1
      kill -9 "$gw_pid" >/dev/null 2>&1 || true
    fi
  }
  trap cleanup_api_gateway EXIT

  local ready=0
  local waited=0
  local timeout_s="${API_READY_TIMEOUT:-60}"
  [[ "$timeout_s" =~ ^[0-9]+$ ]] || timeout_s=60
  echo "[api_flow] waiting for gateway readiness/health (timeout=${timeout_s}s)" | tee -a "$log"
  while [[ "$waited" -lt "$timeout_s" ]]; do
    if curl -fsS "$API_BASE_URL/readyz" >/dev/null 2>&1 || curl -fsS "$API_BASE_URL/healthz" >/dev/null 2>&1; then
      ready=1
      break
    fi
    if ! kill -0 "$gw_pid" >/dev/null 2>&1; then
      echo "[api_flow] gateway process exited before ready" | tee -a "$log"
      break
    fi
    sleep 1
    waited=$((waited + 1))
  done
  echo "ready_wait_seconds=$waited" >> "$summary"
  echo "ready=$ready" >> "$summary"
  if [[ "$ready" -ne 1 ]]; then
    echo "[api_flow] gateway not ready; capturing probes and tail of gateway log" | tee -a "$log"
    api_http_call "00_healthz_probe" GET "$API_BASE_URL/healthz" || true
    api_http_call "00_readyz_probe" GET "$API_BASE_URL/readyz" || true
    tail -n 120 "$gw_log" > "$API_ARTIFACT_DIR/gateway.tail.log" 2>/dev/null || true
    cleanup_api_gateway
    trap - EXIT
    echo "status=gateway_not_ready" >> "$summary"
    api_flow_status="gateway_not_ready"
    return 1
  fi

  local ts now exp task_id rev_id approval_id approval_gate_id
  ts="$(date +%s 2>/dev/null || echo 0)"
  now="$ts"
  exp=$((ts + 3600))
  task_id="e2e-task-$$-$ts"
  rev_id="e2e-rev-$$-$ts"
  approval_id="e2e-appr-$$-$ts"
  approval_gate_id="e2e-appr-gate-$$-$ts"

  api_http_call "01_healthz" GET "$API_BASE_URL/healthz" || true
  api_http_call "02_readyz" GET "$API_BASE_URL/readyz" || true

  local task_create
  task_create=$(cat <<JSON
{"task_id":"$task_id","principal":"agent","action":"tool.invoke","resource":"tool","token":{"revocation_id":"$rev_id","scopes":["tool.invoke"],"max_calls":10,"expires_at":$exp},"operation":"local","now":$now}
JSON
)
  api_http_call "03_task_create" POST "$API_BASE_URL/v1/tasks" "$task_create" || true
  api_http_call "04_tasks_list" GET "$API_BASE_URL/v1/tasks" || true
  api_http_call "05_task_get" GET "$API_BASE_URL/v1/tasks/$task_id" || true

  local approval_create approval_resolve
  approval_create=$(cat <<JSON
{"id":"$approval_id","action":"create","principal":"agent","tool":"tool.invoke","resource":"tool","reason":"e2e-demo","args_hash":"e2e-args","now":$now}
JSON
)
  approval_resolve=$(cat <<JSON
{"id":"$approval_id","action":"approve","now":$((now+1))}
JSON
)
  api_http_call "06_approval_create" POST "$API_BASE_URL/v1/approvals" "$approval_create" || true
  api_http_call "07_approval_resolve" POST "$API_BASE_URL/v1/approvals" "$approval_resolve" || true

  local audit_query
  audit_query=$(cat <<JSON
{"task_id":"$task_id","verify":true,"limit":50}
JSON
)
  api_http_call "08_audit_query_post" POST "$API_BASE_URL/v1/audit" "$audit_query" || true
  api_http_call "09_audit_query_get" GET "$API_BASE_URL/v1/audit" || true
  api_http_call "10_audit_verify_get" GET "$API_BASE_URL/v1/audit/verify" || true

  local revoke_body
  revoke_body=$(cat <<JSON
{"reason":"e2e-demo","revoked_by":"e2e","revocation_id":"${rev_id}-revoke","now":$((now+2))}
JSON
)
  api_http_call "11_task_revoke" POST "$API_BASE_URL/v1/tasks/$task_id/revoke" "$revoke_body" || true
  api_http_call "12_task_get_after_revoke" GET "$API_BASE_URL/v1/tasks/$task_id" || true

  if [[ "$MCP_FLOW" == "1" ]]; then
    local mcp_init mcp_tools_list mcp_call
    mcp_init='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"scopegate-e2e","version":"0.1"}}}'
    mcp_tools_list='{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'
    mcp_call='{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"gateway.health","arguments":{}}}'
    # HTTP MCP expects McpRequest wrapper {method,payload_json}; wrap raw JSON-RPC payloads.
    mcp_http_call "13_mcp_initialize" "$API_BASE_URL/mcp" "$mcp_init" || true
    mcp_http_call "14_mcp_tools_list" "$API_BASE_URL/mcp" "$mcp_tools_list" || true
    mcp_http_call "15_mcp_gateway_health_call" "$API_BASE_URL/mcp" "$mcp_call" || true

    # Real stdio upstream demo via gateway MCP dispatch: allow/deny/approval evidence
    local mcp_demo_allow mcp_demo_deny mcp_demo_appr_pending mcp_demo_appr_approved
    mcp_demo_allow='{"jsonrpc":"2.0","id":16,"method":"tools/call","params":{"name":"demo.echo","arguments":{"message":"hello-from-live-stdio-upstream"}}}'
    mcp_demo_deny='{"jsonrpc":"2.0","id":17,"method":"tools/call","params":{"name":"demo.forbidden","arguments":{"message":"should-be-denied"}}}'
    mcp_http_call "16_mcp_demo_echo_allow" "$API_BASE_URL/mcp" "$mcp_demo_allow" || true
    mcp_http_call "17_mcp_demo_forbidden_deny" "$API_BASE_URL/mcp" "$mcp_demo_deny" || true

    local approval_gate_create approval_gate_approve
    approval_gate_create=$(cat <<JSON
{"id":"$approval_gate_id","action":"create","principal":"anonymous","tool":"demo.echo","resource":"e2e-approval-scope","reason":"e2e-approval-gate-demo","args_hash":"demo-echo-args","now":$((now+3))}
JSON
)
    approval_gate_approve=$(cat <<JSON
{"id":"$approval_gate_id","action":"approve","now":$((now+4))}
JSON
)
    api_http_call "18_approval_gate_create_pending" POST "$API_BASE_URL/v1/approvals" "$approval_gate_create" || true
    mcp_demo_appr_pending=$(cat <<JSON
{"jsonrpc":"2.0","id":19,"method":"tools/call","params":{"name":"demo.echo","arguments":{"message":"pending-approval"},"approval_id":"$approval_gate_id"}}
JSON
)
    mcp_http_call "19_mcp_demo_echo_approval_pending_deny" "$API_BASE_URL/mcp" "$mcp_demo_appr_pending" || true
    api_http_call "20_approval_gate_approve" POST "$API_BASE_URL/v1/approvals" "$approval_gate_approve" || true
    mcp_demo_appr_approved=$(cat <<JSON
{"jsonrpc":"2.0","id":21,"method":"tools/call","params":{"name":"demo.echo","arguments":{"message":"approved-call"},"approval_id":"$approval_gate_id"}}
JSON
)
    mcp_http_call "21_mcp_demo_echo_approval_approved_allow" "$API_BASE_URL/mcp" "$mcp_demo_appr_approved" || true
  fi

  # Post-action audit evidence (after MCP allow/deny/approval attempts)
  api_http_call "22_audit_query_get_post_actions" GET "$API_BASE_URL/v1/audit?limit=100" || true
  api_http_call "23_audit_verify_get_post_actions" GET "$API_BASE_URL/v1/audit/verify" || true

  local modes_norm
  modes_norm="$(normalize_bench_modes "$BENCH_MODES")"
  echo "bench_modes_requested=$modes_norm" >> "$summary"
  echo "bench_live=$BENCH_LIVE" >> "$summary"
  if [[ "$BENCH_LIVE" == "1" && -n "$modes_norm" ]]; then
    echo "[api_flow] running live bench modes against $API_BASE_URL: $modes_norm" | tee -a "$log"
    : > "$API_ARTIFACT_DIR/bench_modes.summary.txt"
    if run_bench_modes_live "$modes_norm" "$API_BASE_URL" "$BENCH_ARTIFACT_ROOT" "$log"; then
      echo "bench_live_status=ok" >> "$summary"
    else
      echo "bench_live_status=failed" >> "$summary"
    fi
    api_flow_bench_ran=1
  else
    echo "bench_live_status=skipped" >> "$summary"
  fi

  # Evidence summary (best-effort, artifact-backed): allow/deny/approval + audit verify
  local evidence_txt="$API_ARTIFACT_DIR/evidence-summary.txt"
  local evidence_json="$API_ARTIFACT_DIR/evidence-summary.json"
  {
    echo "schema=scopegate.e2e_live_s1_evidence.v1"
    echo "generated_utc=$(timestamp)"
    echo "sqlite_upstream_demo=true"
    echo "store_backend=${SCOPEGATE_STORE_BACKEND:-${GATEWAY_STORE_BACKEND:-}}"
    echo "database_url=${SCOPEGATE_DATABASE_URL:-${GATEWAY_DATABASE_URL:-${GATEWAY_STORE_URL:-${DATABASE_URL:-}}}}"
    echo "generated_config=${SCOPEGATE_CONFIG:-}"
    echo "stdio_upstream_server=$ROOT/e2e/stdio_demo_mcp_server.py"
    for name in 16_mcp_demo_echo_allow 17_mcp_demo_forbidden_deny 19_mcp_demo_echo_approval_pending_deny 21_mcp_demo_echo_approval_approved_allow 10_audit_verify_get 23_audit_verify_get_post_actions 22_audit_query_get_post_actions; do
      local m="$API_ARTIFACT_DIR/${name}.meta"
      local code="missing"
      if [[ -f "$m" ]]; then
        code="$(grep '^http_code=' "$m" | tail -n1 | cut -d= -f2- || echo unknown)"
      fi
      echo "${name}_http_code=${code}"
    done
  } > "$evidence_txt" 2>/dev/null || true
  python3 - "$evidence_json" "$evidence_txt" "$API_ARTIFACT_DIR" <<'PY' 2>/dev/null || true
import json, sys, os
out, txt, art = sys.argv[1:4]
data = {}
try:
    with open(txt, encoding='utf-8') as f:
        for line in f:
            line=line.rstrip('\n')
            if '=' in line:
                k,v=line.split('=',1)
                data[k]=v
except Exception:
    pass
for name in [
  '16_mcp_demo_echo_allow','17_mcp_demo_forbidden_deny',
  '19_mcp_demo_echo_approval_pending_deny','21_mcp_demo_echo_approval_approved_allow',
  '15_mcp_gateway_health_call','13_mcp_initialize','14_mcp_tools_list',
  '10_audit_verify_get','23_audit_verify_get_post_actions','22_audit_query_get_post_actions'
]:
    p=os.path.join(art,f'{name}.json')
    info={'present': os.path.exists(p)}
    if info['present']:
        try:
            with open(p,encoding='utf-8') as f: obj=json.load(f)
            if isinstance(obj,dict):
                info['ok']=obj.get('ok')
                info['fail_closed']=obj.get('fail_closed')
                pj=obj.get('payload_json')
                if isinstance(pj,str):
                    try:
                        inner=json.loads(pj)
                        if isinstance(inner,dict):
                            if 'error' in inner: info['mcp_error']=inner.get('error')
                            if 'result' in inner: info['mcp_result_present']=True
                    except Exception:
                        pass
                # audit verify endpoint shape
                if 'body' in obj and isinstance(obj.get('body'),dict):
                    info['audit_chain_ok']=obj['body'].get('ok')
                elif obj.get('status')=='Ok' and isinstance(obj.get('body'),dict):
                    info['audit_chain_ok']=obj['body'].get('ok')
        except Exception as e:
            info['parse_error']=str(e)
    data[name]=info

def mcp_note(info, allow_label):
    if not info.get('present'):
        return f"{allow_label}: artifact missing (capture gap)"
    if info.get('parse_error'):
        return f"{allow_label}: artifact parse_error={info.get('parse_error')}"
    if info.get('ok') and info.get('mcp_result_present'):
        return f"{allow_label}: observed ok with MCP result (stdio upstream forwarding evidenced)"
    err = info.get('mcp_error')
    if err:
        code = err.get('code') if isinstance(err, dict) else None
        msg = err.get('message') if isinstance(err, dict) else str(err)
        return f"{allow_label}: fail-closed/error observed (code={code}, message={msg}); see captured artifacts"
    if info.get('ok') is False:
        return f"{allow_label}: response marked not ok/fail-closed without parsed MCP error details; see captured artifacts"
    return f"{allow_label}: inconclusive; see captured artifacts"

notes = [
    mcp_note(data.get('16_mcp_demo_echo_allow', {}), "allow demo.echo"),
    mcp_note(data.get('17_mcp_demo_forbidden_deny', {}), "deny demo.forbidden"),
    mcp_note(data.get('19_mcp_demo_echo_approval_pending_deny', {}), "approval pending"),
    mcp_note(data.get('21_mcp_demo_echo_approval_approved_allow', {}), "approval approved call"),
]
av = data.get('23_audit_verify_get_post_actions') or data.get('10_audit_verify_get') or {}
if av.get('audit_chain_ok') is True:
    notes.append("audit: runtime audit verify endpoint reports chain ok (captured; runtime evidence, not persisted cryptographic proof)")
elif av.get('audit_chain_ok') is False:
    notes.append(f"audit: runtime audit verify reports chain not ok ({av}); see captured artifacts")
elif av.get('present'):
    notes.append("audit: audit verify artifact captured but chain status inconclusive; see captured artifacts")
else:
    notes.append("audit: audit verify artifact missing; capture gap")
data["notes"] = notes
with open(out,'w',encoding='utf-8') as f:
    json.dump(data,f,indent=2,sort_keys=True); f.write('\n')
PY
  echo "evidence_summary_txt=$evidence_txt" >> "$summary"
  echo "evidence_summary_json=$evidence_json" >> "$summary"

  # Runtime audit verify probe capture (best-effort) while gateway is up
  local audit_probe="$API_ARTIFACT_DIR/runtime_audit_verify.json"
  if curl -sS -D "$API_ARTIFACT_DIR/runtime_audit_verify.headers" -o "$audit_probe" "$API_BASE_URL/v1/audit/verify" 2>"$API_ARTIFACT_DIR/runtime_audit_verify.stderr"; then
    echo "runtime_audit_verify_probe=captured" >> "$summary"
  else
    echo "runtime_audit_verify_probe=failed_or_unavailable" >> "$summary"
  fi

  echo "[api_flow] completed requests; artifacts in $API_ARTIFACT_DIR" | tee -a "$log"
  echo "status=completed" >> "$summary"
  echo "task_id=$task_id" >> "$summary"
  echo "approval_id=$approval_id" >> "$summary"
  echo "approval_gate_id=$approval_gate_id" >> "$summary"
  api_flow_status="completed"
  cleanup_api_gateway
  trap - EXIT
  return 0
}

{
  echo "[demo_flow] start=$(timestamp)"
  echo "[demo_flow] root=$ROOT"
  echo "[demo_flow] bench_mode=$BENCH_MODE run_gateway=$RUN_GATEWAY api_flow=$API_FLOW strict=$STRICT check_rust_run=$CHECK_RUN timeout=${GATEWAY_TIMEOUT}s e2e_sqlite=$E2E_SQLITE"
  echo "[demo_flow] config=${SCOPEGATE_CONFIG:-$ROOT/scopegate.toml.example} bind=${SCOPEGATE_BIND_ADDR:-127.0.0.1:8080}"
  echo "[demo_flow] store_backend=${SCOPEGATE_STORE_BACKEND:-${GATEWAY_STORE_BACKEND:-<gateway-default>}} database_url=${SCOPEGATE_DATABASE_URL:-${GATEWAY_DATABASE_URL:-${GATEWAY_STORE_URL:-${DATABASE_URL:-<gateway-default>}}}}"
  echo "[demo_flow] api_base_url=$API_BASE_URL api_ready_timeout=${API_READY_TIMEOUT}s api_artifact_dir=$API_ARTIFACT_DIR"
  echo "[demo_flow] bench_modes=$BENCH_MODES bench_live=$BENCH_LIVE bench_artifact_root=$BENCH_ARTIFACT_ROOT mcp_flow=$MCP_FLOW"
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
run_build_gateway_step() {
  if ! command -v cargo >/dev/null 2>&1; then
    echo "[build_gateway] cargo not found. Run scripts/check_rust_toolchain.sh and/or scripts/install_rust_toolchain.sh." >&2
    echo "[build_gateway] Expected: cargo build -p gateway once toolchain/runtime are available." >&2
    return 127
  fi
  echo "[build_gateway] cargo=$(cargo --version 2>/dev/null || echo unknown) rustc=$(rustc --version 2>/dev/null || echo unknown)"
  echo "[build_gateway] root=$ROOT"
  echo "[build_gateway] Building: gateway package (cargo build -p gateway)"
  cargo build -p gateway
  if [[ -x "$ROOT/target/debug/gateway" ]]; then
    echo "[build_gateway] artifact: $ROOT/target/debug/gateway"
  elif [[ -x "$ROOT/target/release/gateway" ]]; then
    echo "[build_gateway] artifact: $ROOT/target/release/gateway"
  fi
  echo "[build_gateway] Build step completed."
}
run_step "build_gateway" "$LOG_DIR/build_gateway.log" run_build_gateway_step || true

echo "[demo_flow] Step 1b: Probe gateway CLI/binary (best-effort, non-blocking)"
if command -v timeout >/dev/null 2>&1; then
  if [[ -x "$ROOT/target/debug/gateway" ]]; then
    run_soft_step "gateway_help_probe" "$LOG_DIR/gateway_help_probe.log" timeout 5s env SCOPEGATE_CONFIG="${SCOPEGATE_CONFIG:-$ROOT/scopegate.toml.example}" "$ROOT/target/debug/gateway" --help
  elif command -v cargo >/dev/null 2>&1; then
    run_soft_step "gateway_help_probe" "$LOG_DIR/gateway_help_probe.log" timeout 20s env SCOPEGATE_CONFIG="${SCOPEGATE_CONFIG:-$ROOT/scopegate.toml.example}" cargo run -q -p gateway -- --help
  else
    echo "[demo_flow] gateway_help_probe skipped (no timeout-capable probe target)" | tee "$LOG_DIR/gateway_help_probe.log"
  fi
else
  echo "[demo_flow] gateway_help_probe skipped (timeout unavailable; gateway may not support --help without serving)" | tee "$LOG_DIR/gateway_help_probe.log"
fi

if [[ "$API_FLOW" == "1" ]]; then
  echo "[demo_flow] Step 2/4: Managed gateway + API/MCP flow (and live bench if configured)"
  echo "[demo_flow] NOTE: starts gateway in background, exercises API/MCP endpoints, optionally runs bench modes, captures artifacts, then stops." | tee "$LOG_DIR/api_flow.log"
  run_step "api_flow" "$LOG_DIR/api_flow.step.log" run_managed_api_flow || true
elif [[ "$RUN_GATEWAY" == "1" ]]; then
  echo "[demo_flow] Step 2/4: Run gateway attempt (foreground/cargo run or binary)"
  echo "[demo_flow] NOTE: runtime may be incomplete; use a separate terminal for long-lived runs." | tee "$LOG_DIR/run_gateway.log"
  if [[ "$GATEWAY_TIMEOUT" =~ ^[0-9]+$ ]] && [[ "$GATEWAY_TIMEOUT" -gt 0 ]] && command -v timeout >/dev/null 2>&1; then
    run_step "run_gateway(timeout)" "$LOG_DIR/run_gateway.log" timeout "${GATEWAY_TIMEOUT}s" "$SCRIPTS/run_gateway.sh" || true
  else
    run_step "run_gateway" "$LOG_DIR/run_gateway.log" "$SCRIPTS/run_gateway.sh" || true
  fi
else
  echo "[demo_flow] Step 2/4: Run gateway/API flow skipped (set E2E_RUN_GATEWAY=1 or E2E_API_FLOW=1)." | tee "$LOG_DIR/run_gateway.log"
fi

if [[ "$RESTART_CHECK" == "1" && "$API_FLOW" == "1" ]]; then
  echo "[demo_flow] Step 2b/4: Restart persistence check (same sqlite DB/config, best-effort)"
  run_step "restart_persistence" "$LOG_DIR/restart_persistence.step.log" run_restart_persistence_flow || true
else
  echo "[demo_flow] Step 2b/4: Restart persistence check skipped (E2E_RESTART_CHECK=$RESTART_CHECK API_FLOW=$API_FLOW)." | tee "$LOG_DIR/restart_persistence.step.log"
  if [[ "$restart_persistence_status" == "not_run" ]]; then
    restart_persistence_status="skipped"
  fi
fi

if [[ "$api_flow_bench_ran" == "1" ]]; then
  echo "[demo_flow] Step 3/4: Run bench skipped (live bench modes executed during managed API flow)." | tee "$LOG_DIR/run_bench.log"
  echo "bench_artifact_root=$BENCH_ARTIFACT_ROOT" | tee -a "$LOG_DIR/run_bench.log"
else
  echo "[demo_flow] Step 3/4: Run bench"
  run_step "run_bench" "$LOG_DIR/run_bench.log" "$SCRIPTS/run_bench.sh" "$BENCH_MODE" || true
fi

echo "[demo_flow] Step 4/4: Verify audit chain"
run_step "verify_audit_chain" "$LOG_DIR/verify_audit_chain.log" "$SCRIPTS/verify_audit_chain.sh" || true

write_evidence_manifest || true
echo "[demo_flow] Evidence manifest: $EVIDENCE_MANIFEST" | tee -a "$LOG_DIR/demo_flow.summary.log" 2>/dev/null || echo "[demo_flow] Evidence manifest: $EVIDENCE_MANIFEST"

echo "[demo_flow] $(timestamp) Complete."
if [[ "$step_fail" -ne 0 ]]; then
  echo "[demo_flow] FAILURES: ${failures[*]}" | tee "$LOG_DIR/demo_flow.summary.log"
  echo "[demo_flow] Review logs in $LOG_DIR and scripts/RELEASE_CHECKLIST.md for evidence/gaps."
  exit 1
fi

echo "[demo_flow] All steps reported OK." | tee "$LOG_DIR/demo_flow.summary.log"
echo "[demo_flow] Review logs in $LOG_DIR for evidence artifacts." | tee -a "$LOG_DIR/demo_flow.summary.log"
