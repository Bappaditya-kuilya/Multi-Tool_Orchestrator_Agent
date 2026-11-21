# Phase 2 Todo

## Phase 2A
- [x] Task 1: Reproducible S1 proof bundle
  - Done: `e2e/demo_flow.sh` soft-fails `gateway_help_probe` (non-blocking). Quick capture `e2e/logs/task1-verify-20261121T150439Z` RC=0, api_flow+restart_persistence completed, bench baseline 38p/7x.
- [x] Task 2: Durable-audit fail-closed proof (foundations)
  - Done: core/store audit append-before-return+fail-closed docs/semantics reinforced; InMemory append uses AuditAppendPlan; sqlite write-failure + restart seq-gap tamper tests added. core 93p, store 37p.
  - Gap: full runtime/gateway/e2e fail-closed audit proof across all dispatch paths still needed.
- [~] Task 3: Restart-safe approvals/revocations/budgets/state
  - Done: hook prep on task create + durable revocation sync/fail-closed; rate/budget counters snapshot to store (migration 003) with `persist_rate_limit_state` knob, dirty-marker persist on async handle + sync API handle + MCP mutation (fail-closed). Store+gateway+core tests pass.
  - Gaps: full-snapshot-per-dirty-persist overhead (no batching), single global snapshot/no integrity signing, config-drift as-is, other sync callers must use explicit persist helper; full restart proof across all scenarios still needed.
- [~] Task 4: Close 4 capability xfails
  - [x] taint->egress: gateway MCP handler propagates/persists UntrustedContent, merges snapshots, fail-closed on store errors; Rust tests added. Bench case still xfail (live stdio+sqlite E2E not wired).
  - [~] cross-task isolation: handler request-binding/task-approval isolation tests added; xfail reason made precise. NOT proven: true concurrent multi-request isolation (server still serializes via global AppState mutex).
  - [x] manifest pin/drift/re-approval: tools/list pin hash baseline + drift deny/fail-closed (re-approval required, no auto flow). Store migration+trait+impls; Rust tests pass. Bench case still xfail (live E2E not wired).
  - [x] agent-visible secret redaction: MCP response/error marker scrub + fail-closed; Rust tests added. Bench case still xfail (live stdio+sqlite E2E not wired).
  - Verify: cargo test --all; pytest bench -q (xfails reduced only when proven)

## Checkpoint A
- [ ] S1 bundle reproducible/green
- [ ] Claims backed by tests+artifacts
- [ ] Docs/status/release/evidence updated factually
- [ ] fmt/clippy/test-all, bench, dashboard build, SDK checks green

## Phase 2B (external-gated)
- [ ] Task 5: Postgres parity + drills
- [ ] Task 6: Redis streams / HA / degraded-mode
- [ ] Task 7: Security sign-off + release package

## Phase 2C (in progress)
- [x] T1 Live evidence bundle: configured clean gateway bench 44p/1x, targeted 3 capability tests 3p; stateful contamination caveat captured; docs updated. Evidence: e2e/logs/phase2c-live-bench-20261121T160243Z/.
- [x] T2 Rate/budget snapshot hardening: persist_rate_limit_state knob, dirty persist, sync API/MCP persist coverage, config-drift tests/docs.
- [x] T3 Concurrent cross-task isolation: global AppState mutex removed; per-subsystem locks; concurrent router integration test (20 mixed requests) passes. Confused-deputy live concurrent HTTP bench test wired/env-gated (passes configured). (owner: T3/gateway+mcp crates)
- [~] T4 Audit fail-closed/crypto proof across paths. Hardened: MCP parse-error/tools/call scrub-before-audit, tools/list allow+task-context-deny, initialize, initialized-deny, task-create/revoke, approval-resolve, policy-upsert audit append fail-closed with injection tests. Gaps: not all MCP deny branches individually injection-tested, approval-create/other API mutations have no audit append by design/ambiguity, no audit-failure e2e, crypto audit/signing unproven.
- [x] T5 Docs/release readiness sync for checkpoint C/D snapshot. STATUS/RELEASE_READINESS/FINAL_S1_EVIDENCE/README/runbook/MIGRATION_MAP/threat-model/architecture/e2e README synced to 45p/0x configured capture; stale harness-not-wired refs removed.

## Checkpoint C status (factual snapshot, 2026-11-21, updated)
- Configured clean-gateway/data-dir bench capture: **44 passed, 1 xfailed** (`e2e/logs/phase2c-live-bench-20261121T160243Z/`); 3 named capability tests pass when configured but remain env-gated in unconfigured runs. Same-instance rerun showed stateful contamination; canonical results are clean captures only. Confused-deputy live concurrent HTTP bench now wired/env-gated and passed configured local sanity check (not in captured bundle). **Not enforce-mode sign-off/release bundle.**
- Rate/budget snapshot hardening done with documented caveats (full global snapshot per dirty persist, no integrity signing, config-drift as-is).
- Cross-task isolation has concurrent router-level Rust proof (global lock removed, per-subsystem locks, 20 mixed-request integration test). Confused-deputy live concurrent HTTP bench test wired (env-gated; passes configured, xfail unconfigured).
- Audit fail-closed/crypto proof still incomplete across all runtime paths; key MCP/API paths hardened with targeted injection tests.

## Phase 3 — Gap closure (production/S2/release)

### Phase 3A: S1 evidence + audit proof (in-repo)
- [x] T6 Fresh configured evidence bundle (evidence: `e2e/logs/phase3a-t6-live-bench-20261121T170500Z/`, 45p/0x configured clean sqlite+stdio, commit `30bdcfc`; not enforce-mode sign-off)
  - **Description:** Capture clean-gateway configured bench + key e2e artifacts after confused-deputy live wiring; produce manifest with commit/env/config/data-dir.
  - **Acceptance criteria:** clean-gateway/data-dir full `pytest bench -q` captured; confused-deputy passes configured; 3 live-gateway integration cases pass or precisely env-gated with reason; manifest includes commit, UTC, store backend, command, exit codes, contamination caveat.
  - **Verification:** `./scripts/run_sqlite_demo.sh` or equivalent clean data dir; `SCOPEGATE_GATEWAY_URL=... python3 -m pytest bench -q`; artifact in `e2e/logs/<ts>/`.
  - **Dependencies:** T4b committed (done). **Files:** `e2e/*`, `scripts/*`, `docs/STATUS.md`, `docs/RELEASE_READINESS.md`, `e2e/FINAL_S1_EVIDENCE.md`. **Scope:** M.
- [x] T7 Audit-failure injection proof across runtime paths (MCP tools/list allow+task-context-deny, initialize, initialized-deny; task-create; plus T11 added revoke/approval-resolve/policy-upsert). Remaining uncovered paths listed in docs/todo.
  - **Description:** Add smallest test seams/mocks to prove audit append failure fails closed on remaining important MCP deny/allow and API mutation paths; add e2e script only if feasible without invasive hooks.
  - **Acceptance criteria:** targeted injection tests cover selected uncovered paths; each tested path asserts fail-closed response + no partial side effect where applicable; uncovered paths listed in docs.
  - **Verification:** `cargo test -p gateway -p core -p store`; new tests named by path.
  - **Dependencies:** T4c done. **Files:** `crates/gateway/src/{mcp,api,lifecycle}.rs`, `crates/gateway/tests/*`, minimal `crates/store`/`crates/core` test helpers. **Scope:** M/L.
- [x] T8 Durability/restart proof matrix (`crates/gateway/tests/restart_persistence.rs`, 4 tests): clean restart restore task/approval/revocation/rate-budget snapshot; dirty-persist no-op/set/clear; persist knob off; config-drift as-is; global/full-snapshot caveats documented.
  - **Description:** Prove restart-safe behavior for approvals/revocations/task state/rate-budget snapshots across clean restart scenarios; document caveats.
  - **Acceptance criteria:** restart tests/captured run cover create->approve/deny->restart->verify, revocation->restart, rate/budget snapshot restore under configured knob; caveats (full-snapshot-per-dirty-persist, global snapshot, config drift, no integrity signing) explicitly documented.
  - **Verification:** `cargo test -p gateway -p store`; `e2e/restart_persistence.sh` or equivalent capture.
  - **Dependencies:** T2, T6. **Files:** `crates/store/*`, `crates/gateway/src/state.rs`, `e2e/*`, docs. **Scope:** M.
- [x] T9 Bench/doc/release-readiness factual sync (updated for phase3a-t6 45p/0x capture).
  - **Description:** Update STATUS/RELEASE_READINESS/FINAL_S1_EVIDENCE after T6-T8 with artifact-backed claims only.
  - **Acceptance criteria:** no stale harness-not-wired/confused-deputy wording; all numbers cite captured artifacts or "unconfigured baseline"; gaps remain explicit.
  - **Verification:** `rg -n "harness not wired|38p/7xf" docs e2e README.md` reviewed; docs match artifacts.
  - **Dependencies:** T6-T8. **Files:** `docs/*`, `e2e/FINAL_S1_EVIDENCE.md`, `README.md`. **Scope:** S.

### Checkpoint D — S1 evidence
- [ ] Fresh clean-gateway configured bundle captured with manifest/commit/env
- [ ] Audit fail-closed injection proof covers key runtime paths; uncovered paths listed
- [ ] Restart/durability matrix backed by tests/artifacts; caveats explicit
- [ ] fmt/clippy/test-all, bench, dashboard build, SDK checks green

### Phase 3B: Runtime hardening (in-repo, selective)
- [ ] T10 Rate/budget snapshot caveat reduction
  - **Description:** Reduce highest-risk caveats: batch/debounce dirty persist or document accepted overhead; add integrity/version guard if cheap; keep config-drift behavior explicit.
  - **Acceptance criteria:** measurable reduction or explicit accepted-risk doc; no regression in fail-closed behavior; tests for restore/version/config-drift.
  - **Verification:** `cargo test -p gateway -p store`; targeted perf/smoke note.
  - **Dependencies:** T8. **Files:** `crates/store/*`, `crates/gateway/src/state.rs`, migrations/docs. **Scope:** M.
- [~] T11 Scoped append-before-return hardening (task revoke, approval resolve, policy upsert audit fail-closed; hash-chain verify test). Gaps: mutation+audit non-atomic tradeoff, no crypto signing, approval-create/other API mutations ambiguous.
  - **Description:** Prove or implement missing append-before-return/crypto audit guarantees on scoped paths; do not claim full crypto audit.
  - **Acceptance criteria:** scoped paths have tests/evidence; unsupported claims removed from docs.
  - **Verification:** targeted cargo tests; evidence doc.
  - **Dependencies:** T7. **Files:** `crates/core/src/audit.rs`, `crates/store/src/lib.rs`, gateway audit paths. **Scope:** M/L.
- [~] T12 MCP/front/runtime enforcement hardening (upstream response shape fail-closed, tools/list no-fallback on upstream anomaly, error taxonomy split, mcp-pool missing-result/error fail-closed). Gaps: approval args-hash binding not enforced in MCP dispatch, no full rmcp/Biscuit/Cedar/secret-broker, limited deep result schema validation.
  - **Description:** Close remaining real enforcement gaps on MCP/front path (not full rmcp rewrite): tool exposure, approval binding, error taxonomy, fail-closed on upstream anomalies where practical.
  - **Acceptance criteria:** new tests for each closed gap; no overclaim of full rmcp/Biscuit/Cedar completion.
  - **Verification:** `cargo test -p gateway -p mcp-front -p mcp-pool`.
  - **Dependencies:** T7, T8. **Files:** `crates/mcp-front/*`, `crates/mcp-pool/*`, `crates/gateway/src/mcp.rs`. **Scope:** L.

### Checkpoint E — Runtime hardening
- [ ] Snapshot/audit/crypto caveats reduced or explicitly risk-accepted with evidence
- [ ] MCP/front enforcement gaps closed or precisely documented
- [ ] No fake full-rmcp/broker/Biscuit/Cedar completion claims

### Phase 3C: S2 / HA / drills (external-gated)
- [ ] T13 Postgres parity + migration/backup/restore/rollback drills
  - **Description:** Validate Postgres store parity, migration up/down/backup/restore/rollback with captured evidence.
  - **Acceptance criteria:** parity tests pass; drill artifacts captured; rollback path verified.
  - **Verification:** Postgres-backed `cargo test`/drill scripts; evidence manifest.
  - **Dependencies:** D, external Postgres env. **Files:** `crates/store/*`, `scripts/*`, `e2e/*`, docs. **Scope:** L.
- [ ] T14 Redis streams/shared state/HA/degraded-mode
  - **Description:** Implement/validate shared approvals/audit/events and HA/degraded-mode behavior with Redis streams.
  - **Acceptance criteria:** multi-node/shared-state tests or drills pass; degraded-mode fail-closed/observable.
  - **Verification:** env-gated integration/drill artifacts.
  - **Dependencies:** T13, external Redis env. **Files:** `crates/store/*`, `crates/gateway/*`, infra/scripts. **Scope:** XL (break up when started).
- [ ] T15 Load/failure drills and operational evidence
  - **Description:** Run load/failure/restart drills; capture SLO/latency/error/audit continuity evidence.
  - **Acceptance criteria:** drill manifests with pass/fail criteria and outcomes.
  - **Verification:** `scripts/*`, `e2e/*` drill outputs.
  - **Dependencies:** T14. **Files:** `scripts/*`, `e2e/*`, docs/runbook. **Scope:** L.

### Checkpoint F — S2
- [ ] Multi-node/shared-state evidence captured
- [ ] Backup/restore/rollback/HA/degraded-mode drills pass with artifacts

### Phase 3D: Security/release (external-gated/human)
- [ ] T16 Security hardening + independent review/sign-off
  - **Description:** Complete Biscuit/Cedar/broker/secret-handling hardening scope agreed for release; obtain security review/sign-off.
  - **Acceptance criteria:** threat model updated; findings triaged; sign-off artifact recorded.
  - **Verification:** review report/checklist in docs/evidence (no secrets).
  - **Dependencies:** E, security reviewer. **Files:** `crates/authz/*`, `crates/broker/*`, policy/docs. **Scope:** XL (break up).
- [ ] T17 Enforce-mode release bundle + reproducible CI
  - **Description:** Produce reproducible CI green and enforce-mode/live benchmark bundle against wired gateway.
  - **Acceptance criteria:** CI workflow green on clean commit; enforce-mode bundle captured with manifest; xfails/gates explained.
  - **Verification:** CI run URL/artifact, `e2e` manifest, bench logs.
  - **Dependencies:** D/E/F as applicable. **Files:** `.github/workflows/*`, `scripts/*`, `e2e/*`. **Scope:** L.
- [ ] T18 Hosted demo + v0.1.0 artifacts/checksums
  - **Description:** Publish hosted demo proof and versioned release artifacts/checksums.
  - **Acceptance criteria:** demo URL/proof captured; v0.1.0 artifacts + checksums published; release notes factual.
  - **Verification:** release checklist, artifact hashes, hosted smoke evidence.
  - **Dependencies:** T16, T17. **Files:** `docs/runbook.md`, `scripts/release_checklist.sh`, release artifacts. **Scope:** M.

### Checkpoint G — Release
- [ ] Reproducible CI green; enforce-mode bundle captured
- [ ] Security sign-off recorded
- [ ] Hosted demo proof; v0.1.0 artifacts/checksums published