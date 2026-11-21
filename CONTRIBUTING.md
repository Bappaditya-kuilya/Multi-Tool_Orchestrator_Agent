# Contributing to ScopeGate (S1 preview)

ScopeGate is a preview/partial implementation: runtime integrations, enforcement paths, and release evidence are evolving. Keep contributions factual, scoped, and fail-closed in intent.

## Before you start

- Read [`docs/STATUS.md`](docs/STATUS.md), [`docs/architecture.md`](docs/architecture.md), [`docs/threat-model.md`](docs/threat-model.md), and [`docs/runbook.md`](docs/runbook.md).
- For target-vs-current drift, see [`docs/PRD.md`](docs/PRD.md) and [`README.md`](README.md).
- Discuss significant/security-sensitive changes first (token/policy/audit/taint semantics, approvals, store behavior, MCP dispatch).

## Scope and honesty

- Do not claim runtime/security guarantees or verification results that are not implemented and evidenced.
- Current reality: partial gateway HTTP/MCP-dispatch runtime with in-memory default and optional SQLite wiring in places; SDKs target current APIs; e2e/scripts can capture best-effort evidence. Production deps/enforcement, durable/crypto audit guarantees, live enforce-mode proof, S1/S2 validation, hosted demo, and release sign-off remain incomplete.
- Coordinate cross-workstream edits; avoid changing files outside the scope you own.

## Local checks (capture evidence)

### Rust
```bash
./scripts/check_rust_toolchain.sh
# CI-parity (if appropriate): CHECK_RUST_RUN=1 ./scripts/check_rust_toolchain.sh

cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
cargo check --all
cargo test --all
```

### Bench
```bash
python3 -m pip install -r bench/requirements.txt  # if needed
python3 -m pytest bench -q
# or: ./scripts/run_bench.sh baseline
```
Record mode (`baseline|dryrun|enforce`), commit, env, and full output. Current snapshot: **38 passed, 7 xfailed** (not live enforce-mode proof).

### Dashboard
```bash
cd dashboard
npm ci
npm run build
```

### E2E / demo evidence (best-effort)
```bash
./e2e/demo_flow.sh
# or: ./e2e/capture_live_evidence.sh
```
These may depend on local toolchain/runtime availability; artifacts/logs are evidence, not proof of complete guarantees.

## Pull requests

1. Keep changes focused and consistent with existing patterns.
2. Run relevant checks and include commands + outcomes (or environment limits).
3. Describe behavior/docs impact and remaining gaps/risks.
4. Update factual status docs when verification or blockers change.

## Security

See [`SECURITY.md`](SECURITY.md). Do not disclose exploit details in public issues.
