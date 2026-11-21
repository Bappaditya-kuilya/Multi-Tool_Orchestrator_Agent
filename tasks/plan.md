# Phase 2 Plan — S1 hard-close, then S2/release gates

## Overview
Close S1 with reproducible evidence + real capability enforcement, then S2/release when env allows. Green checks at every checkpoint.

## Phase 2A — S1 hard-close (in-repo)
- [ ] Task 1: Reproducible S1 proof bundle (fix `gateway_help_probe:124`, clean manifest/summary)
- [ ] Task 2: Durable-audit fail-closed proof across runtime paths
- [ ] Task 3: Restart-safe approvals/revocations/budgets/state
- [ ] Task 4: Close 4 capability xfails with real enforcement or explicit fail-closed+doc

## Checkpoint A
- [ ] Reproducible S1 bundle green; restart/durable/approval claims backed by tests+artifacts
- [ ] 4 capability gaps closed or explicitly fail-closed+documented
- [ ] fmt/clippy/test-all, bench, dashboard build, SDK checks green; docs updated factually

## Phase 2B — external-gated
- [ ] Task 5: Postgres parity + migration/backup/restore/rollback drills
- [ ] Task 6: Redis streams / HA / degraded-mode
- [ ] Task 7: Security hardening/sign-off + release package (CI, enforce-mode bench, demo, v0.1.0 artifacts)
