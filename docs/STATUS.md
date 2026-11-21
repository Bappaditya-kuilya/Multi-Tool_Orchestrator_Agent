# ScopeGate — Status

> Factual status snapshot (2026-11-21). Not a release sign-off.

## Current state (current source)

- **`cargo fmt --all --check`:** pass
- **`cargo clippy --all-targets -- -D warnings`:** pass
- **`cargo test --all`:** pass
- **Bench (`bench/` pytest harness):** **38 passed, 7 xfailed** unconfigured; configured clean-gateway local sqlite+stdio capture **45 passed, 0 xfailed** (`e2e/logs/phase3a-t6-live-bench-20261121T170500Z/`, clean gateway/data dir, commit `30bdcfc`, evidence only — not enforce-mode sign-off). 4 capability + 3 live-gateway integration tests pass when configured but remain env-gated in unconfigured runs.
- **Dashboard build:** pass (`cd dashboard && npm run build`)
- **SDK checks:** pass — Python `py_compile` (`sdk/python/src/scopegate_sdk/__init__.py`), TypeScript `tsc -p tsconfig.json --noEmit` (`sdk/ts`)

## Captured S1 proof artifacts

- **Consolidated index:** [`e2e/FINAL_S1_EVIDENCE.md`](../e2e/FINAL_S1_EVIDENCE.md) (artifact paths, proved outcomes, gaps).
- **`e2e/logs/phase3a-t6-live-bench-20261121T170500Z/`** (configured live bench, 2026-11-21, commit `30bdcfc`, clean `/tmp/scopegate-t6-clean`): clean local sqlite_wal+stdio demo gateway; `bench -q` **45 passed, 0 xfailed, 0 failed** (exit 0). Includes 4 capability env-gated tests and 3 live-gateway integration tests passing when configured. **Evidence only; not enforce-mode sign-off/release bundle.**
- **`e2e/logs/phase2c-live-bench-20261121T160243Z/`** (configured live bench, 2026-11-21, commit `d12c9ee`): clean local sqlite_wal+stdio demo gateway; `bench -q` **44 passed, 1 xfailed, 0 failed**; pre-dates confused-deputy live wiring. Same-instance rerun contamination caveat. **Evidence only.**
- **`e2e/logs/task1-verify-20261121T150439Z/`** (quick verification capture, 2026-11-21): `demo_flow` **RC=0**, `api_flow`+`restart_persistence` completed, audit verify OK, bench baseline 38p/7x. Confirms `gateway_help_probe` soft-fail (124) is non-blocking. **Evidence only.**
- **`e2e/logs/proof-s1-source-20261120T194149Z/`** (`evidence-manifest.json`, `scopegate.e2e_evidence_manifest.v1`, commit `2e16912`, UTC `2026-11-20T19:46:31Z`, `store_backend=sqlite_wal`): captured sqlite-backed source-runtime/API-flow evidence. `demo_flow.summary.log` records `FAILURES: gateway_help_probe:124`. Bench in this artifact: baseline 38p/7x. **Evidence only; not S1 sign-off.**
- **`e2e/logs/proof-s1-source-restart-20261120T201236Z/`**: restart-persistence capture (same sqlite_wal DB/config), pre-restart S1 flow + post-restart audit verify/continuity and task-state continuity. **Evidence only.**

## Checkpoint C status (factual snapshot, 2026-11-21)

- **Green:** fmt/clippy/test-all pass, bench 38p/7xf unconfigured; configured clean-gateway sqlite+stdio capture 44p/1xf (evidence only).
- **Capability status:** taint/rug-pull/secret-redaction handler/store enforced with Rust tests and live-gated bench assertions passing when configured; cross-task isolation has concurrent router-level Rust proof (global `AppState` mutex removed, per-subsystem locks, 20 mixed-request integration test); confused-deputy live concurrent HTTP bench wired/env-gated (passes configured, xfails unconfigured).
- **Restart/durability:** rate/budget snapshot hardening done (`persist_rate_limit_state`, dirty persist, sync API/MCP persist coverage, fail-closed); caveats remain (full-snapshot-per-dirty-persist, single global snapshot/no integrity signing, config-drift as-is). Full append-before-return/crypto audit guarantees across all runtime paths unproven.
- **Not done:** S2/HA/load, Biscuit/Cedar/full rmcp/secret broker guarantees, security sign-off, enforce-mode/release bundle, v0.1.0 artifacts.

## Honest remaining gaps

- **Bench/evidence:** unconfigured 38p/7x; configured clean-capture 45p/0x evidence-only (`phase3a-t6-live-bench-20261121T170500Z`). 4 capability + 3 live-gateway integration tests env-gated in unconfigured runs; pass configured. No enforce-mode/live release bundle.
- **Durability/audit:** append-before-return/crypto audit guarantees across all runtime paths/scenarios unproven. Rate/budget snapshot caveats remain (full-snapshot-per-dirty-persist, global snapshot, config-drift as-is). Restart-safe proof across all scenarios incomplete.
- **S2/HA/load:** not implemented/validated.
- **Security/release:** no Biscuit/Cedar/full rmcp/secret broker hardening sign-off, no v0.1.0 release artifacts/checksums.
