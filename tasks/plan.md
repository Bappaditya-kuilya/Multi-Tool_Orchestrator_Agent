# Implementation Plan — Gap Closure to Production/Release

## Overview
Close remaining S1 evidence/durability gaps, then S2/HA, then security/release sign-off. Every claim backed by tests/artifacts; no sign-off language without evidence.

## Current baseline (2026-11-21, `30bdcfc`)
- Green: `cargo fmt --all --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test --all`, dashboard build, SDK `py_compile`/`tsc --noEmit`.
- Bench: **38p/7x** unconfigured; configured clean-gateway sqlite+stdio capture **44p/1x** (evidence-only, stale before confused-deputy live wiring). 4 capability cases now live-gated/pass-when-configured; 3 live-gateway integration tests env-gated.
- Proven: concurrent router isolation (20 mixed requests), MCP taint/rug-pull/secret-redaction, tool pin/drift fail-closed, rate/budget snapshot persistence with caveats, key MCP/API audit fail-closed paths.
- Gaps: fresh configured enforce-mode/release evidence bundle; audit-failure injection/append-before-return/crypto proof across all runtime paths; durability caveats; S2 Postgres+Redis/HA/load/drills; Biscuit/Cedar/full rmcp/secret broker hardening; security sign-off; v0.1.0 artifacts/checksums.

## Architecture Decisions
- **Evidence before claims:** no xfail removal or “proven” wording without captured artifact/log/manifest.
- **Fail-closed default:** audit/store/policy/token/crypto uncertainty denies/fails closed.
- **Smallest viable proof:** add targeted injection seams/tests before broad refactors.
- **External-gated work isolated:** S2/HA/release packaging tracked separately; do not block S1 evidence closure on infra unavailable locally.

## Task List (Phase 3 — gap closure)

### Phase 3A: S1 evidence + audit proof (in-repo)
- [ ] T6 Fresh configured evidence bundle
- [ ] T7 Audit-failure injection proof across runtime paths
- [ ] T8 Durability/restart proof matrix
- [ ] T9 Bench/doc/release-readiness factual sync

### Checkpoint D (S1 evidence)
- [ ] Fresh clean-gateway configured bench/e2e bundle captured with manifest/commit/env
- [ ] Audit fail-closed proven by injection tests/evidence on covered runtime paths; remaining paths explicitly listed
- [ ] Restart/durability claims backed by tests/artifacts; caveats documented
- [ ] fmt/clippy/test-all, bench, dashboard build, SDK checks green

### Phase 3B: Runtime hardening (code, partly in-repo)
- [ ] T10 Rate/budget snapshot caveat reduction
- [ ] T11 Crypto audit/append-before-return hardening
- [ ] T12 MCP/front/runtime enforcement completeness

### Checkpoint E (runtime hardening)
- [ ] Snapshot/durability caveats reduced or explicitly risk-accepted with evidence
- [ ] Audit/crypto guarantees documented with proof scope
- [ ] No fake “full rmcp/broker/Biscuit/Cedar complete” claims

### Phase 3C: S2 / HA / drills (external-gated)
- [ ] T13 Postgres parity + migration/backup/restore/rollback drills
- [ ] T14 Redis streams / shared approvals/audit/events / HA / degraded-mode
- [ ] T15 Load/failure drills and operational evidence

### Checkpoint F (S2)
- [ ] Multi-node/shared-state evidence captured
- [ ] Backup/restore/rollback/HA/degraded-mode drills pass with artifacts

### Phase 3D: Security/release sign-off (external-gated/human)
- [ ] T16 Security hardening + independent review/sign-off
- [ ] T17 Enforce-mode release bundle + reproducible CI
- [ ] T18 Hosted demo + v0.1.0 artifacts/checksums

### Checkpoint G (Release)
- [ ] Reproducible CI green; enforce-mode bundle captured
- [ ] Security sign-off recorded
- [ ] Hosted demo proof; versioned v0.1.0 artifacts/checksums published

## Risks and Mitigations
| Risk | Impact | Mitigation |
|------|--------|------------|
| Configured bench contamination (same instance) | High | Always capture from clean gateway/data dir; record manifest/env/commit. |
| Audit injection seams require invasive refactors | Med | Add smallest test seam/mock store; prove covered paths, list uncovered. |
| S2 infra unavailable locally | High | Mark external-gated; produce runnable drill scripts/manifests before claiming. |
| Crypto/Biscuit/Cedar/rmcp scope creep | High | Ponytail: smallest provable increment; do not claim full completion. |
| Snapshot write overhead / consistency | Med | Batch/dirty-window only with correctness tests; document caveats if deferred. |

## Open Questions
- Target release scope: S1-only preview artifact or full S2/M8 v0.1.0?
- Where will hosted demo run (Fly/Koyeb/Render/other) and who owns secrets/domain?
- Is independent security review internal or third-party?
