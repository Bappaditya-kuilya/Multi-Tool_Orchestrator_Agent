#!/usr/bin/env bash
set -euo pipefail

# Release readiness checklist helper (M7/M8 prep). Prints actionable gates and
# highlights latest reported status notes. Does not claim checks pass.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

cat <<'EOF'
ScopeGate release checklist (M7/M8 prep)
======================================

Current verified baseline (2026-11-17, capture fresh evidence/logs):
- cargo fmt --all --check: PASS
- cargo clippy --all-targets --all-features -- -D warnings: PASS
- cargo test --all: PASS
- bench: unconfigured 38 passed, 7 xfailed; configured clean-gateway/data-dir capture 44 passed, 1 xfailed (env-gated capability tests; same-instance rerun stateful contamination caveat; not enforce-mode sign-off). Record mode/commit/env/output
- dashboard build: PASS

Build & quality (Rust toolchain required)
- [ ] ./scripts/check_rust_toolchain.sh (and ./scripts/install_rust_toolchain.sh if needed)
- [ ] cargo fmt --all --check
- [ ] cargo clippy --all-targets --all-features -- -D warnings
- [ ] cargo check --all
- [ ] cargo test --all
- [ ] CI green (.github/workflows/rust-ci.yml, scaffold-checks.yml) with artifacts/logs

Bench / verification
- [ ] ./scripts/run_bench.sh baseline (capture results; note xfails/skips and gateway coupling)
- [ ] ./scripts/run_bench.sh enforce (when wired to live gateway) with published evidence
- [ ] ./scripts/verify_audit_chain.sh (primitive proxy today) and persisted runtime audit verify when implemented

Dashboard / SDK / docs
- [ ] (dashboard/) npm ci && npm run build
- [ ] Docs/config/policies consistent with implemented behavior (docs/STATUS.md, runbook, scopegate.toml.example, policies/examples/*)
- [ ] SDK API-shaped stubs reviewed; no publish claim without runtime bindings/tests

Runtime & ops (future gates, PRD intent)
- [ ] End-to-end S1 path validated (MCP front -> authn/policy/taint -> approval -> broker -> pool -> durable audit append-before-return)
- [ ] /healthz, /readyz, /metrics implemented and smoke-tested
- [ ] Fail-closed behavior on audit/store/policy/token errors verified
- [ ] Backup/restore and audit verify drill completed (S1 SQLite; S2 Postgres later)
- [ ] Rollback criteria/gates exercised (health failures, deny-rate anomaly, audit verify failure)

Evidence / sign-off
- [ ] Capture benchmark artifacts, bench mode, commit SHA, and environment details
- [ ] Capture e2e/demo logs (./e2e/demo_flow.sh, e2e/logs/*)
- [ ] Security hardening/sign-off recorded
- [ ] Release notes and version/tag plan prepared

See scripts/RELEASE_CHECKLIST.md and docs/RELEASE_READINESS.md for notes.
EOF
