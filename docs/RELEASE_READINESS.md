# ScopeGate — Release Readiness (fast final update)

> Factual snapshot for M0/M6/M7/M8 gates. Updated: 2026-11-21. **Not a release sign-off.**
>
> **Evidence index:** [`e2e/FINAL_S1_EVIDENCE.md`](../e2e/FINAL_S1_EVIDENCE.md).

## S1 / S2 / M8 gate status (concise)

| Gate | Status | Captured evidence (local, env-dependent) | Gaps / why not met |
|------|--------|-------------------------------------------|--------------------|
| **S1** (single node, SQLite WAL, fail-closed, durable append-before-return audit + verify, restart-safe approvals/state/revocation/budget) | **Partial evidence, not validated/signed off** | `e2e/logs/manual-live-s1/evidence-manifest.json` (`scopegate.manual_live_s1_evidence.v1`, 2026-11-20): sqlite WAL gateway, policy deny (`demo.forbidden`), approval create/approve + pending-deny validation, audit query/verify captured; bench **41 passed, 4 xfailed, 0 failed** for `baseline|dryrun|enforce` (live managed). `e2e/logs/proof-s1-source-manual2/api_flow/23_audit_verify_get.json`: `ok:true`, `checked_events:5` (in-run). `e2e/logs/proof-s1-source-20261120T194149Z/` and `e2e/logs/proof-s1-source-restart-20261120T201236Z/` (`scopegate.e2e_evidence_manifest.v1`): sqlite_wal S1 allow/deny/approval/audit-verify artifacts; 201236Z adds post-restart audit verify/continuity and task-state continuity (runtime endpoint evidence; 194149Z/201236Z `demo_flow.summary.log` note `gateway_help_probe:124`). `e2e/logs/smoke-scripts-restart-evidence/manifest.json`: phase1/phase2 restart smoke captures. `e2e/logs/phase3a-t6-live-bench-20261121T170500Z/` (2026-11-21, commit `30bdcfc`, clean `/tmp/scopegate-t6-clean`, sqlite+stdio demo gateway, `SCOPEGATE_GATEWAY_URL` set): full bench **45 passed, 0 xfailed, 0 failed** (exit 0); includes 4 capability + 3 live-gateway integration tests passing when configured. **Evidence only; not enforce-mode sign-off/release bundle.** Prior `phase2c-live-bench-20261121T160243Z` (44p/1x) pre-dates confused-deputy live wiring. | No reproducible S1 sign-off bundle; no proven restart-safe/persisted-state behavior across *all* paths/process scenarios; no comprehensive fail-closed proof for audit/store/policy/token error classes; no durable append-before-return/crypto audit proof; upstream/runtime capability caveats remain; capability-gated bench xfails remain. |
| **S2** (Postgres + Redis streams, shared approvals/audit/events, HA/degraded-mode, migration/backup/restore/rollback drills) | **Not started / no evidence** | None captured. | No multi-node runtime, no shared-state validation, no HA/degraded-mode or drill evidence. |
| **M8** (reproducible green CI, live enforce-mode bundle, end-to-end validated enforcement/runtime, hardened ops/observability, security sign-off, hosted demo, versioned v0.1.0 artifacts/checksums) | **Not met** | Partial/subset checks only (2026-11-21): `cargo fmt -p broker` + `cargo test -p broker` (**32 passed**), dashboard `npm run build`, Python SDK `py_compile`, TS SDK `tsc --noEmit`. Prior reported baseline (2026-11-17, not rerun this pass): Rust fmt/clippy/tests pass; bench **38p/7xf**. | No reproducible CI/release bundle, no live wired enforce-mode proof, no validated end-to-end enforcement path, no security review/sign-off, no hosted demo, no release artifacts/checksums. |

## Blockers (exact, release-critical)

- **Runtime/security deps not production-complete:** Biscuit verification/attenuation, Cedar engine + YAML compile/load, full `rmcp` runtime/front-pool/upstream execution, production secret broker/adapters with injection/redaction guarantees, complete approvals/runtime behavior.
- **Durability/audit not proven:** end-to-end fail-closed store lifecycle across all runtime paths, durable append-before-return/crypto audit guarantees, and persisted/restart verification across all scenarios remain unproven. Approvals/revocation/task restart wiring improved; rate/budget counters snapshot-restorable (migration 003, fail-closed load/persist) but with caveats (per-request write, sync path, coarse gating, global snapshot) — not full sign-off proof.
- **M6 hardening incomplete:** production tracing/OTel, stable observability schemas, enforced rate-limit/budget/taint propagation/egress hooks with auditable outcomes.
- **Evidence gaps:** dashboard/SDK/live E2E integration against wired enforcement paths unverified; unconfigured bench baseline remains **38p/7x**. Configured-gateway local sqlite+stdio demo capture (2026-11-21, `e2e/logs/phase3a-t6-live-bench-20261121T170500Z/`, commit `30bdcfc`, clean data dir): **45 passed, 0 xfailed, 0 failed**. 4 capability + 3 live-gateway integration tests pass when configured; remain env-gated in unconfigured runs. **Not enforce-mode sign-off/release bundle.** No enforce-mode/live benchmark bundle suitable for release. Rate/budget counters now snapshot-restorable (migration 003, `persist_rate_limit_state` knob, dirty-persist on async+sync API/MCP paths) with caveats (full-snapshot per dirty persist, global snapshot, config-drift as-is).
- **Ops/release gaps:** no complete S1 validation bundle, no S2 validation/drills, no backup/restore/rollback evidence, no hosted demo, no security sign-off, no versioned artifacts/checksums.

## What remains for production/release readiness

1. **Close S1:** produce reproducible sqlite-WAL validation proving fail-closed on audit/store/policy/token error classes, durable append-before-return audit + `GET /v1/audit/verify` across restart/persisted state, and restart-safe approvals/task/revocation/budgets (captured logs/manifests, commit/env).
2. **Close S2:** validate Postgres + Redis streams multi-node behavior (shared approvals/audit/events, HA/degraded-mode) and complete migration/backup/restore/rollback drills with evidence.
3. **Harden runtime:** replace placeholder security/runtime components, wire full MCP/broker/enforcement paths, and prove end-to-end fail-closed behavior.
4. **Harden ops/observability:** stable schemas, tracing/OTel, enforced limits/taint/egress controls, and auditable failure outcomes.
5. **M8 release package:** reproducible CI-green baseline, live enforce-mode bench bundle against wired gateway (xfails explained), verified dashboard/SDK integrations, security review/sign-off, hosted demo proof, and versioned v0.1.0 artifacts/checksums. **No sign-off claimed.**

## References
- [`STATUS.md`](./STATUS.md), [`runbook.md`](./runbook.md), [`threat-model.md`](./threat-model.md)
- [`../scripts/RELEASE_CHECKLIST.md`](../scripts/RELEASE_CHECKLIST.md), [`../e2e/README.md`](../e2e/README.md)
