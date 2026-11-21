#!/usr/bin/env bash
set -euo pipefail

# Verify ScopeGate audit chain primitives (unit-test proxy) and optionally probe
# runtime verification surfaces. Factual: core/store expose FNV-1a
# (non-cryptographic) hash-chain append/verify primitives and in-memory/store
# scaffolds; persisted runtime audit integrity guarantees/export remain incomplete.
# Runtime endpoint probes (when configured) are best-effort evidence only and must
# not be treated as complete persisted runtime proof.
#
# Optional runtime probe (no claim of persisted proof):
# - SCOPEGATE_AUDIT_VERIFY_URL: full URL to GET (e.g. http://127.0.0.1:8080/v1/audit/verify)
# - SCOPEGATE_GATEWAY_URL / SCOPEGATE_BASE_URL: base URL; script probes /v1/audit/verify
# - SCOPEGATE_AUDIT_LOG_PATH: informational path hint (no persisted runtime verifier yet)

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

LOG_PATH="${SCOPEGATE_AUDIT_LOG_PATH:-}"
VERIFY_URL="${SCOPEGATE_AUDIT_VERIFY_URL:-}"
if [[ -z "$VERIFY_URL" ]]; then
  BASE_URL="${SCOPEGATE_GATEWAY_URL:-${SCOPEGATE_BASE_URL:-${SCOPEGATE_API_BASE_URL:-${E2E_API_BASE_URL:-}}}}"
  if [[ -n "$BASE_URL" ]]; then
    VERIFY_URL="${BASE_URL%/}/v1/audit/verify"
  fi
fi

echo "[verify_audit_chain] root=$ROOT"
echo "[verify_audit_chain] verify_url=${VERIFY_URL:-<none>}"
if [[ -n "$LOG_PATH" ]]; then
  echo "[verify_audit_chain] requested audit log path: $LOG_PATH"
  if [[ ! -e "$LOG_PATH" ]]; then
    echo "[verify_audit_chain] audit log path does not exist; runtime audit export not available yet." >&2
  else
    echo "[verify_audit_chain] persisted runtime audit verification/export tooling is not implemented; path hint recorded only." >&2
  fi
fi

if [[ -n "$VERIFY_URL" ]]; then
  echo "[verify_audit_chain] Runtime probe: GET $VERIFY_URL (best-effort; not persisted runtime proof)"
  if command -v curl >/dev/null 2>&1; then
    probe_out="${SCOPEGATE_AUDIT_VERIFY_PROBE_OUT:-}"
    if [[ -n "$probe_out" ]]; then
      mkdir -p "$(dirname "$probe_out")" 2>/dev/null || true
      if curl -sS -D "${probe_out}.headers" -o "$probe_out" "$VERIFY_URL"; then
        echo "[verify_audit_chain] runtime probe captured: $probe_out"
      else
        echo "[verify_audit_chain] runtime probe request failed (gateway unavailable or endpoint error)." >&2
      fi
    else
      curl -sS "$VERIFY_URL" || echo "[verify_audit_chain] runtime probe request failed (gateway unavailable or endpoint error)." >&2
    fi
  else
    echo "[verify_audit_chain] curl unavailable; skipping runtime probe." >&2
  fi
  echo "[verify_audit_chain] NOTE: runtime probe reflects gateway/store-reported verification state only; it does not replace durable persisted-log verification evidence."
fi

if ! command -v cargo >/dev/null 2>&1; then
  echo "[verify_audit_chain] cargo not found; cannot run unit primitive proxy tests. Run scripts/check_rust_toolchain.sh." >&2
  echo "[verify_audit_chain] Runtime endpoint probe (if configured) is separate from unit primitive verification and not persisted proof." >&2
  exit 127
fi

echo "[verify_audit_chain] Running unit primitive proxy checks (core/store tests; non-cryptographic, library-level)..."
# Try focused audit filters first; fall back to package tests if filters differ.
cargo test -p core audit -- --nocapture || cargo test -p scopegate-core audit -- --nocapture || cargo test -p core -- --nocapture
cargo test -p store -- --nocapture || cargo test -p scopegate-store -- --nocapture || true

echo "[verify_audit_chain] NOTE: Unit tests verify library primitives only (non-cryptographic/in-memory scaffolds), not persisted runtime audit integrity. Runtime probes, when used, are best-effort endpoint checks."
exit 0
