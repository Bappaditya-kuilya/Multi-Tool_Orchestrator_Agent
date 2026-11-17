#!/usr/bin/env bash
set -euo pipefail

# Build ScopeGate gateway (cargo-oriented). Prefers the gateway crate/package and
# reports artifact paths when possible. Factual: runtime wiring may be incomplete;
# a successful build does not imply runtime readiness.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PROFILE="${CARGO_PROFILE:-debug}" # debug|release (informational for path hints)
EXTRA_ARGS=("$@")

if ! command -v cargo >/dev/null 2>&1; then
  echo "[build_gateway] cargo not found. Run scripts/check_rust_toolchain.sh and/or scripts/install_rust_toolchain.sh." >&2
  echo "[build_gateway] Expected: cargo build -p gateway (or --release) once toolchain/runtime are available." >&2
  exit 127
fi

echo "[build_gateway] cargo=$(cargo --version 2>/dev/null || echo unknown) rustc=$(rustc --version 2>/dev/null || echo unknown)"
echo "[build_gateway] root=$ROOT"

try_build() {
  local desc="$1"; shift
  echo "[build_gateway] Building: $desc ($*)"
  "$@"
}

if try_build "gateway package" cargo build -p gateway "${EXTRA_ARGS[@]}"; then
  :
elif try_build "scopegate-gateway package (fallback name)" cargo build -p scopegate-gateway "${EXTRA_ARGS[@]}"; then
  :
else
  echo "[build_gateway] gateway package name not found; falling back to workspace build." >&2
  try_build "workspace" cargo build --workspace "${EXTRA_ARGS[@]}"
fi

# Best-effort artifact hints (actual path depends on profile/target flags).
if [[ " ${EXTRA_ARGS[*]} " == *" --release "* ]]; then
  PROFILE="release"
fi
for bin in gateway scopegate-gateway; do
  if [[ -x "$ROOT/target/$PROFILE/$bin" ]]; then
    echo "[build_gateway] artifact: $ROOT/target/$PROFILE/$bin"
    "$ROOT/target/$PROFILE/$bin" --version 2>/dev/null || true
  fi
done

echo "[build_gateway] Build step completed."