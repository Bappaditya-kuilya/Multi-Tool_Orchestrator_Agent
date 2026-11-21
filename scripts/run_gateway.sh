#!/usr/bin/env bash
set -euo pipefail

# Run ScopeGate gateway (cargo/binary-oriented). Prefers real cargo run when
# toolchain/build is available. Factual: runtime may be scaffold/partial (no
# complete MCP/HTTP/ops surfaces yet); this script attempts execution and fails
# clearly with context.
#
# Store configuration (all optional; preserves gateway defaults when unset):
# - SCOPEGATE_STORE_BACKEND / GATEWAY_STORE_BACKEND: e.g. inmemory (default), sqlite_wal, sqlite
# - SCOPEGATE_DATABASE_URL / GATEWAY_DATABASE_URL / GATEWAY_STORE_URL / DATABASE_URL:
#     sqlite URL/path for durable store (e.g. sqlite:///data/scopegate.db or sqlite://./scopegate.db)
# - SCOPEGATE_SQLITE_DATA_DIR: convenience dir for sqlite file creation when using relative file URLs

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

CONFIG="${GATEWAY_CONFIG:-${SCOPEGATE_CONFIG:-$ROOT/scopegate.toml.example}}"
BIND="${GATEWAY_ADDR:-${SCOPEGATE_BIND_ADDR:-127.0.0.1:8080}}"
LOG_LEVEL="${RUST_LOG:-info}"
MODE="${SCOPEGATE_RUN_MODE:-auto}" # auto|cargo|binary
BIN="${SCOPEGATE_GATEWAY_BIN:-}"
PROFILE="${CARGO_PROFILE:-debug}"
STORE_BACKEND="${GATEWAY_STORE_BACKEND:-${SCOPEGATE_STORE_BACKEND:-}}"
STORE_DB_URL="${GATEWAY_DATABASE_URL:-${GATEWAY_STORE_URL:-${SCOPEGATE_DATABASE_URL:-${DATABASE_URL:-}}}}"

# Best-effort: ensure parent dir exists for sqlite file URLs/paths (fail-safe, no-op on parse issues).
ensure_sqlite_parent_dir() {
  local url="$1"
  [[ -z "$url" ]] && return 0
  local path=""
  case "$url" in
    sqlite:///*) path="${url#sqlite:///}"; path="/$path" ;;
    sqlite://*) path="${url#sqlite://}" ;;
    /*|./*|../*) path="$url" ;;
    *) return 0 ;;
  esac
  # Strip query params/fragments if present.
  path="${path%%\?*}"
  path="${path%%#*}"
  [[ -z "$path" || "$path" == ":memory:" ]] && return 0
  local dir
  dir="$(dirname "$path")"
  if [[ -n "$dir" && "$dir" != "." ]]; then
    mkdir -p "$dir" 2>/dev/null || true
  fi
}

normalize_sqlite_db_url() {
  local url="$1"
  [[ -z "$url" ]] && { printf '%s' "$url"; return 0; }
  case "$url" in
    sqlite:*|sqlite://*)
      [[ "$url" == *\?* ]] && { printf '%s' "$url"; return 0; }
      [[ "$url" == *:memory:* || "$url" == "sqlite::memory:" ]] && { printf '%s' "$url"; return 0; }
      printf '%s?mode=rwc' "$url"
      ;;
    *)
      printf '%s' "$url"
      ;;
  esac
}

if [[ -n "$STORE_DB_URL" ]]; then
  STORE_DB_URL="$(normalize_sqlite_db_url "$STORE_DB_URL")"
  ensure_sqlite_parent_dir "$STORE_DB_URL"
  export SCOPEGATE_DATABASE_URL="$STORE_DB_URL"
  export GATEWAY_DATABASE_URL="$STORE_DB_URL"
  export SCOPEGATE_STORE_URL="$STORE_DB_URL"
fi
if [[ -n "$STORE_BACKEND" ]]; then
  export SCOPEGATE_STORE_BACKEND="$STORE_BACKEND"
  export GATEWAY_STORE_BACKEND="$STORE_BACKEND"
fi
if [[ -n "${SCOPEGATE_SQLITE_DATA_DIR:-}" ]]; then
  mkdir -p "$SCOPEGATE_SQLITE_DATA_DIR" 2>/dev/null || true
fi

echo "[run_gateway] root=$ROOT"
echo "[run_gateway] config=$CONFIG bind=$BIND RUST_LOG=$LOG_LEVEL mode=$MODE"
echo "[run_gateway] store_backend=${STORE_BACKEND:-<gateway-default>} database_url=${STORE_DB_URL:-<gateway-default>}"
if [[ -n "${GATEWAY_MCP_UPSTREAM_URL:-}" || -n "${GATEWAY_MCP_UPSTREAM_CMD:-}" ]]; then
  echo "[run_gateway] upstream_env=present id=${GATEWAY_MCP_UPSTREAM_ID:-<default>} default=${GATEWAY_MCP_DEFAULT_UPSTREAM:-<auto>}"
fi
echo "[run_gateway] NOTE: gateway runtime may be scaffold/partial; expect limited behavior until durable/runtime surfaces are complete."

run_binary() {
  local bin="$1"
  shift || true
  if [[ -x "$bin" ]]; then
    echo "[run_gateway] launching binary: $bin $*"
    GATEWAY_CONFIG="$CONFIG" SCOPEGATE_CONFIG="$CONFIG" GATEWAY_ADDR="$BIND" SCOPEGATE_BIND_ADDR="$BIND" RUST_LOG="$LOG_LEVEL" exec "$bin" "$@"
  fi
  return 1
}

if [[ "$MODE" == "binary" || "$MODE" == "auto" ]]; then
  if [[ -n "$BIN" ]]; then
    run_binary "$BIN" "$@" || { echo "[run_gateway] configured binary not executable: $BIN" >&2; [[ "$MODE" == "binary" ]] && exit 1; }
  fi
  for candidate in "$ROOT/target/$PROFILE/gateway" "$ROOT/target/release/gateway" "$ROOT/target/$PROFILE/scopegate-gateway" "$ROOT/target/release/scopegate-gateway"; do
    if [[ "$MODE" == "binary" ]]; then
      run_binary "$candidate" "$@" || true
    else
      run_binary "$candidate" "$@" || true
    fi
  done
  if [[ "$MODE" == "binary" ]]; then
    echo "[run_gateway] no executable gateway binary found (set SCOPEGATE_GATEWAY_BIN or build first)." >&2
    exit 127
  fi
fi

if ! command -v cargo >/dev/null 2>&1; then
  echo "[run_gateway] cargo not found and no binary selected. Run scripts/check_rust_toolchain.sh / scripts/build_gateway.sh." >&2
  exit 127
fi

# Prefer workspace package name `gateway`; fall back to alternate names.
# Export common env names for gateway/config compatibility (cargo and child processes).
export GATEWAY_CONFIG="$CONFIG"
export SCOPEGATE_CONFIG="$CONFIG"
export GATEWAY_ADDR="$BIND"
export SCOPEGATE_BIND_ADDR="$BIND"
export RUST_LOG="$LOG_LEVEL"
if cargo metadata --no-deps --format-version 1 >/dev/null 2>&1; then
  if cargo run -p gateway -- "$@"; then
    exit 0
  fi
  if cargo run -p scopegate-gateway -- "$@"; then
    exit 0
  fi
else
  # metadata can fail in odd envs; still try direct runs
  cargo run -p gateway -- "$@" || cargo run -p scopegate-gateway -- "$@" || exit 1
  exit 0
fi

echo "[run_gateway] Unable to run gateway via cargo (package/binary target may differ or runtime incomplete)." >&2
echo "[run_gateway] Try: cargo run -p gateway -- --help (or inspect crates/gateway/Cargo.toml)." >&2
exit 1
