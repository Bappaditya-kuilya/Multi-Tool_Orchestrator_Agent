#!/usr/bin/env bash
set -euo pipefail

# Rust toolchain verification helper (prep for M0/M7 CI parity).
# Factual: Rust workspace exists but cargo/rustc may be unavailable in some environments.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

EXPECTED_TOOLCHAIN=""
if [[ -f "$ROOT/rust-toolchain.toml" ]]; then
  EXPECTED_TOOLCHAIN="$(grep -E '^[[:space:]]*channel[[:space:]]*=' "$ROOT/rust-toolchain.toml" | head -n1 | sed -E 's/.*=[[:space:]]*"([^"]+)".*/\1/' || true)"
fi

echo "[check_rust] repo: $ROOT"
if [[ -n "$EXPECTED_TOOLCHAIN" ]]; then
  echo "[check_rust] expected toolchain channel (rust-toolchain.toml): $EXPECTED_TOOLCHAIN"
else
  echo "[check_rust] expected toolchain channel: (not found in rust-toolchain.toml)"
fi

missing=0
for cmd in cargo rustc rustup; do
  if command -v "$cmd" >/dev/null 2>&1; then
    echo "[check_rust] found $cmd: $($cmd --version 2>/dev/null | head -n1)"
  else
    echo "[check_rust] missing: $cmd" >&2
    missing=1
  fi
done

if [[ "$missing" -ne 0 ]]; then
  echo "[check_rust] Rust toolchain incomplete/unavailable. Install via rustup (see scripts/install_rust_toolchain.sh)." >&2
  echo "[check_rust] CI parity commands (run when toolchain is available):" >&2
  echo "  cargo fmt --all --check" >&2
  echo "  cargo clippy --all-targets --all-features -- -D warnings" >&2
  echo "  cargo check --all" >&2
  echo "  cargo test --all" >&2
  exit 127
fi

if [[ "${CHECK_RUST_RUN:-0}" == "1" ]]; then
  echo "[check_rust] Running Rust checks (CHECK_RUST_RUN=1)..."
  cargo fmt --all --check
  cargo clippy --all-targets --all-features -- -D warnings
  cargo check --all
  cargo test --all
  echo "[check_rust] Rust checks completed successfully."
else
  echo "[check_rust] Toolchain present. Set CHECK_RUST_RUN=1 to run fmt/clippy/check/test."
fi
