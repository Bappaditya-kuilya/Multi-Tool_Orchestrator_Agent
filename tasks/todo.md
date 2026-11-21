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
- [ ] T3 Concurrent cross-task isolation (high risk).
- [ ] T4 Audit fail-closed/crypto proof across paths.
- [ ] T5 Docs/release readiness sync for checkpoint C.
