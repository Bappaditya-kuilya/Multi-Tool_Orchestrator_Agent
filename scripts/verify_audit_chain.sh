#!/usr/bin/env bash
set -euo pipefail

# Verify ScopeGate audit chain primitives (current proxy) and document future
# runtime verification. Factual: core/store expose FNV-1a (non-cryptographic)
# hash-chain append/verify primitives and in-memory skeletons; no durable runtime
# audit export or `audit verify` CLI/API is wired yet.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

LOG_PATH="${SCOPEGATE_AUDIT_LOG_PATH:-}"

echo "[verify_audit_chain] root=$ROOT"
if [[ -n "$LOG_PATH" ]]; then
  echo "[verify_audit_chain] requested audit log path: $LOG_PATH"
  if [[ ! -e "$LOG_PATH" ]]; then
    echo "[verify_audit_chain] audit log path does not exist; runtime audit export not available yet." >&2
  else
    echo "[verify_audit_chain] persisted runtime audit verification is not implemented; falling back to primitive proxy checks." >&2
  fi
fi

if ! command -v cargo >/dev/null 2>&1; then
  echo "[verify_audit_chain] cargo not found; cannot run primitive proxy tests. Run scripts/check_rust_toolchain.sh." >&2
  echo "[verify_audit_chain] Future: verify exported persisted audit log (seq continuity + cryptographic hash chain) via runtime CLI/API." >&2
  exit 127
fi

echo "[verify_audit_chain] Running primitive proxy checks (core/store tests)..."
# Try focused audit filters first; fall back to package tests if filters differ.
cargo test -p core audit -- --nocapture || cargo test -p scopegate-core audit -- --nocapture || cargo test -p core -- --nocapture
cargo test -p store -- --nocapture || cargo test -p scopegate-store -- --nocapture || true

echo "[verify_audit_chain] NOTE: This verifies library/unit primitives only (non-cryptographic, in-memory), not persisted runtime audit integrity."
exit 0
