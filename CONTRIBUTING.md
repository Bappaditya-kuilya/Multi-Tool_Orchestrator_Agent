# Contributing to ScopeGate

**Status:** Draft. The repository is a scaffold/partial implementation; runtime integrations, enforcement paths, and quality gates are still evolving.

## Before you start

- Read `docs/STATUS.md`, `docs/architecture.md`, `docs/threat-model.md`, and `docs/runbook.md` for current state, target design, and known gaps.
- Discuss significant changes in an issue first (especially security-sensitive behavior, token/policy/audit/taint semantics, or cross-crate APIs).
- Keep changes focused, preserve fail-closed intent, and update docs/examples when behavior or interfaces change.

## Ownership / scope notes

- This iteration's owned areas include `docs/**`, `e2e/**`, `scripts/**`, `sdk/**`, `docker/**`, `policies/**`, `.github/**`, and root docs/config examples. Other areas may be owned by parallel workstreams—avoid conflicting edits unless coordinated.
- Do not claim runtime/security guarantees or verification results that are not implemented and evidenced. Note current reality: gateway has partial HTTP/MCP-dispatch runtime (axum routes + in-memory store wiring), SDKs have HTTP clients toward current APIs, and scripts/e2e can run real cargo/gateway/bench steps; production deps/enforcement, durable audit, live enforce-mode evidence, S1/S2 validation, hosted demo, and v0.1.0 remain gaps.

## Local checks

### Rust (workspace)

Requires Rust toolchain (`cargo`/`rustc`, see `rust-toolchain.toml`). CI runs equivalent checks via `.github/workflows/rust-ci.yml`.

```bash
./scripts/check_rust_toolchain.sh
# Optional (network/tooling dependent): ./scripts/install_rust_toolchain.sh
# CI-parity: CHECK_RUST_RUN=1 ./scripts/check_rust_toolchain.sh

cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
cargo check --all
cargo test --all
```

**Current verified baseline (2026-11-17):** `cargo fmt --all --check` pass, `cargo clippy --all-targets -- -D warnings` pass, `cargo test --all` pass. Capture fresh logs/artifacts for your branch before claiming green.

### Bench (Python, M4)

```bash
./scripts/run_bench.sh baseline
# or
python3 -m pip install -r bench/requirements.txt
python3 -m pytest bench -q
```

**Current baseline:** 38 passed, 7 xfailed. Record mode (`baseline|dryrun|enforce`), commit, environment, and full output when reporting.

### Dashboard (Vite + React + TS, scaffold)

```bash
cd dashboard
npm ci
npm run build
```

**Current baseline:** build pass. UI remains non-integrated.

### E2E/demo prep

```bash
./e2e/demo_flow.sh
```

Runs build/run/bench/audit-verify steps with clear failure handling and log capture; not proof of a working runtime until gateway/ops surfaces are implemented.

## Pull requests

1. Create a focused branch.
2. Run relevant checks locally (or explain environment limits clearly and attach evidence where possible).
3. Include behavior/docs impact, verification performed (commands + outcomes), and remaining gaps/risks.
4. Keep `docs/STATUS.md` factual when milestones, blockers, or verification results change.

## Security

For vulnerability reporting, see `SECURITY.md`. Do not disclose exploit details in public issues.
