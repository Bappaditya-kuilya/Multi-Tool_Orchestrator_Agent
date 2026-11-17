#!/usr/bin/env bash
set -euo pipefail

# Rust toolchain install helper (best-effort, factual).
# Prefers rustup and respects rust-toolchain.toml when present.
# Network/package-manager access and sudo availability vary by environment.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

EXPECTED_TOOLCHAIN=""
if [[ -f "$ROOT/rust-toolchain.toml" ]]; then
  EXPECTED_TOOLCHAIN="$(grep -E '^[[:space:]]*channel[[:space:]]*=' "$ROOT/rust-toolchain.toml" | head -n1 | sed -E 's/.*=[[:space:]]*"([^"]+)".*/\1/' || true)"
fi
: "${EXPECTED_TOOLCHAIN:=stable}"

if command -v cargo >/dev/null 2>&1 && command -v rustc >/dev/null 2>&1; then
  echo "[install_rust] Rust already installed: $(rustc --version)"
  if command -v rustup >/dev/null 2>&1; then
    echo "[install_rust] Ensuring toolchain/components via rustup (channel: $EXPECTED_TOOLCHAIN)..."
    rustup toolchain install "$EXPECTED_TOOLCHAIN" --component rustfmt --component clippy
    rustup default "$EXPECTED_TOOLCHAIN" || true
  fi
  exit 0
fi

echo "[install_rust] Rust toolchain not fully installed. Target channel: $EXPECTED_TOOLCHAIN"

if command -v rustup >/dev/null 2>&1; then
  echo "[install_rust] rustup found; installing toolchain/components..."
  rustup toolchain install "$EXPECTED_TOOLCHAIN" --component rustfmt --component clippy
  rustup default "$EXPECTED_TOOLCHAIN"
else
  echo "[install_rust] rustup not found."
  echo "[install_rust] Recommended install (official):"
  echo "  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain ${EXPECTED_TOOLCHAIN} --component rustfmt --component clippy"
  echo "[install_rust] Then reload shell env (e.g. 'source \"\$HOME/.cargo/env\"') and run scripts/check_rust_toolchain.sh"
  if [[ "${INSTALL_RUST_AUTO:-0}" == "1" ]]; then
    if command -v curl >/dev/null 2>&1; then
      echo "[install_rust] INSTALL_RUST_AUTO=1 set; attempting rustup install via curl..."
      curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain "$EXPECTED_TOOLCHAIN" --component rustfmt --component clippy
      # shellcheck disable=SC1090
      source "$HOME/.cargo/env" || true
    else
      echo "[install_rust] curl not available; cannot auto-install rustup." >&2
      exit 127
    fi
  else
    exit 127
  fi
fi

if command -v cargo >/dev/null 2>&1; then
  echo "[install_rust] Installed: $(cargo --version)"
  echo "[install_rust] Verify with: scripts/check_rust_toolchain.sh"
else
  echo "[install_rust] cargo still unavailable after install attempt. Ensure \$HOME/.cargo/bin is on PATH." >&2
  exit 1
fi
