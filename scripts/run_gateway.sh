#!/usr/bin/env bash
set -euo pipefail

# Run ScopeGate gateway (cargo/binary-oriented). Prefers real cargo run when
# toolchain/build is available. Factual: runtime may be scaffold/partial (no
# complete MCP/HTTP/ops surfaces yet); this script attempts execution and fails
# clearly with context.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

CONFIG="${SCOPEGATE_CONFIG:-$ROOT/scopegate.toml.example}"
BIND="${SCOPEGATE_BIND_ADDR:-127.0.0.1:8080}"
LOG_LEVEL="${RUST_LOG:-info}"
MODE="${SCOPEGATE_RUN_MODE:-auto}" # auto|cargo|binary
BIN="${SCOPEGATE_GATEWAY_BIN:-}"
PROFILE="${CARGO_PROFILE:-debug}"

echo "[run_gateway] root=$ROOT"
echo "[run_gateway] config=$CONFIG bind=$BIND RUST_LOG=$LOG_LEVEL mode=$MODE"
echo "[run_gateway] NOTE: gateway runtime is not fully implemented; expect limited behavior until MCP/HTTP/durable audit/ops surfaces land."

run_binary() {
  local bin="$1"
  if [[ -x "$bin" ]]; then
    echo "[run_gateway] launching binary: $bin $*"
    SCOPEGATE_CONFIG="$CONFIG" SCOPEGATE_BIND_ADDR="$BIND" RUST_LOG="$LOG_LEVEL" exec "$bin" "$@"
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
