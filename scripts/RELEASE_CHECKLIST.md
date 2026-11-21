# ScopeGate Release Checklist (Notes)

> M0/M6/M7/M8 prep notes. Factual to repo state as of 2026-11-17; update when implementation/evidence changes.

## Latest reported snapshot (current verified green baseline, not a sign-off)

- `cargo fmt --all --check`: **pass**
- `cargo clippy --all-targets --all-features -- -D warnings`: **pass**
- `cargo test --all`: **pass**
- Bench: **38 passed, 7 xfailed** (capture mode, commit, env, full logs)
- Dashboard: **build pass**

## Current reality (do not overstate)

- Runtime is partial: core primitives and gateway axum HTTP/MCP-dispatch scaffolding exist (in-memory store wiring by default), but production enforcement is incomplete.
- Bench results are promising (**38 passed, 7 xfailed**) but not yet enforce-mode/live enforcement proof against a fully wired, production-shaped gateway.
- Audit chain primitives exist (`crates/core`, in-memory wiring) with **non-cryptographic FNV-1a** hashing; no cryptographic/durable append-before-return or persisted runtime `audit verify`.
- Real deps/integrations remain blocked/incomplete: Biscuit, Cedar, full `rmcp` runtime/upstream execution, SQLx durable stores, secret adapters/broker guarantees, approvals persistence, and hardened M6 rate-limit/taint/observability enforcement. No live hosted demo, no S2 validation, no v0.1.0 sign-off.

## Evidence to capture before release claims

- Toolchain/environment: OS, Rust version (`rust-toolchain.toml`), Python/Node versions, commit SHA.
- Commands and outcomes: `cargo fmt/clippy/check/test`, bench mode/results and xfail reasons, dashboard build, and e2e/demo logs/artifacts (`e2e/logs/*`).
- S1/live-gateway evidence (when runnable): `./e2e/capture_live_evidence.sh` (or managed `./e2e/demo_flow.sh` with `E2E_SQLITE=1 E2E_API_FLOW=1 E2E_MCP_FLOW=1 E2E_BENCH_LIVE=1 E2E_BENCH_MODES=all`) capturing sqlite gateway flow, tasks/approvals/audit query+verify/MCP checks, runtime audit verify probe, and per-mode bench artifacts (`baseline|dryrun|enforce`) with `evidence-manifest.json`.
- Audit integrity proof on persisted data (when available): export + verify, seq/hash continuity (runtime `GET /v1/audit/verify` probes are best-effort endpoint evidence, not complete persisted proof).
- Operational drills (when available): S1 backup/restore, readiness/fail-closed behavior, rollback triggers.

## Suggested release gate sequence (when runtime ready)

1. Keep fmt/clippy/check/test green in CI (`cargo fmt --all --check`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo check --all`, `cargo test --all`) and capture reproducible logs/artifacts.
2. Record reproducible bench baseline, then enforce-mode/live enforcement run against a wired gateway with documented pass criteria.
3. Complete e2e/demo flow (`./e2e/demo_flow.sh`) with durable audit verification artifact when implemented.
4. Validate ops: `/healthz`, `/readyz`, `/metrics`, tracing/OTel, rate-limit/taint hooks, fail-closed audit/store/policy/token errors, approval timeout-deny behavior.
5. Security review, hosted demo/S1-S2 validation, and release notes/tag.

## Known gaps to track

- Real Biscuit/Cedar/`rmcp` runtime wiring and end-to-end fail-closed enforcement path.
- Durable sqlx-backed ops and append-before-return audit with persisted export/verify.
- MCP front/pool/broker runtime execution and secret handling/redaction guarantees.
- `/healthz`, `/readyz`, `/metrics`, OTel/tracing, rate-limit/budget, and taint propagation/egress hooks.
- Live enforcement evidence, S1/S2 runtime validation, backup/restore drills, hosted demo, and release sign-off.

## See also

- `docs/RELEASE_READINESS.md` — readiness snapshot, evidence, blockers
- `docs/STATUS.md` — milestone/status truth
- `scripts/release_checklist.sh` — printable checklist helper
- `e2e/README.md` — demo flow prep and current limitations


