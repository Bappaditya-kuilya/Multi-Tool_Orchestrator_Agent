# ScopeGate — Status

> Factual status snapshot (2026-11-21). Not a release sign-off.

## Current state (current source)

- **`cargo fmt --all --check`:** pass
- **`cargo clippy --all-targets -- -D warnings`:** pass
- **`cargo test --all`:** pass
- **Bench (`bench/` pytest harness):** **38 passed, 7 xfailed** (`baseline`; no authoritative enforce-mode/live proof across modes in captured runs)
- **Dashboard build:** pass (`cd dashboard && npm run build`)
- **SDK checks:** pass — Python `py_compile` (`sdk/python/src/scopegate_sdk/__init__.py`), TypeScript `tsc -p tsconfig.json --noEmit` (`sdk/ts`)

Command/artifact logs for these checks are not bundled in this doc; retain per-run evidence before any CI/release claim. Not security sign-off or production readiness.

## Captured S1 proof artifacts

- **Consolidated index:** [`e2e/FINAL_S1_EVIDENCE.md`](../e2e/FINAL_S1_EVIDENCE.md) (artifact paths, proved outcomes, gaps).
- **`e2e/logs/proof-s1-source-20261120T194149Z/`** (`evidence-manifest.json`, `scopegate.e2e_evidence_manifest.v1`, commit `2e16912`, UTC `2026-11-20T19:46:31Z`, `store_backend=sqlite_wal`): captured sqlite-backed source-runtime/API-flow evidence (`api_flow/`, health/ready/tasks/approvals/audit/policies/MCP dispatch paths exercised, audit verify 200, `verify_audit_chain.log`, sqlite db/wal/shm). `demo_flow.summary.log` records `FAILURES: gateway_help_probe:124`. Bench in this artifact: baseline `38 passed, 7 xfailed` (`run_bench.log`) without live-gateway-configured bench integration in that run context. **Evidence only; not S1 sign-off.**
- **`e2e/logs/manual-live-s1/`**: contains `evidence-manifest.json` (captured artifact present; not independently summarized here as sign-off).
- Other partial/incomplete local S1 artifacts observed (e.g. `e2e/logs/proof-s1-source-20261121*`, `e2e/logs/proof-s1-source-manual*`): not claimed as complete/green S1 proof bundles.

## Captured restart smoke / restart-related evidence paths

- **`e2e/logs/proof-s1-source-restart-20261120T201236Z/`** (`evidence-manifest.json`, `api_flow/restart/restart-evidence-summary.json`): completed restart-persistence capture (same sqlite_wal DB/config). Pre-restart S1 flow: allow/deny/approval pending→approved + audit query/verify ok. Post-restart: probes 200, audit verify `ok:true` (`checked_events=8`), audit continuity (pre/post count 8, chain verified), prior task/revocation state continuity. **Runtime endpoint evidence; not full restart/durability/sign-off proof.** (`demo_flow.summary.log` notes `FAILURES: gateway_help_probe:124`.)
- **`e2e/logs/smoke-scripts-restart-evidence/`**: scripted sqlite restart smoke evidence (`summary.txt`, `manifest.json`, generated config, `scopegate-restart-evidence.db*`, `phase1_*`/phase2 capture artifacts). Summary indicates phase1 start/stop and phase2 restart/readiness on the same sqlite db/config (`phase1_ok=1 phase2_ok=1`); manifest captures phase HTTP/MCP/audit responses. **Scripted smoke evidence only.**
- **`e2e/logs/proof-s1-source-restart-20261120T195527Z/`**: restart-related captured artifact directory present (`build_gateway.log`, `check_rust_toolchain.log`, `demo_flow.meta.log`, `scopegate-e2e.db*`); no manifest/summary found in dir — treat as partial/incomplete restart evidence, not proof.

## Honest remaining gaps

- **4 capability xfails (current source sqlite+stdio live path, unresolved):** untrusted tool-output taint propagation to egress enforcement; concurrent cross-task isolation in live MCP request handling; manifest/schema pinning/drift detection/re-approval flow; agent-visible secret redaction/boundary enforcement.
- **Full restart/durable proof across all paths:** not captured/proven (restart-safe approvals/state, append-before-return/durable audit guarantees across runtime paths, recovery semantics, and production persistence behavior remain unproven end-to-end beyond captured smoke artifacts).
- **S2/HA/load:** not implemented/validated (distributed Postgres+streams scaling, HA/degraded-mode behavior, load/perf validation).
- **Security sign-off:** not done (placeholder/non-production substitutes remain in places — e.g. Biscuit/Cedar/full rmcp/crypto audit hardening/runtime wiring not fully proven; no security hardening sign-off).
- **Release:** not ready (no enforce-mode/live benchmark evidence bundle, no operational hardening drills/sign-off, no release artifacts).
- **Bench gap:** 3 additional xfails environment/config-dependent in captured runs (live-gateway integration not configured in those invocations); no authoritative enforce-mode proof.
