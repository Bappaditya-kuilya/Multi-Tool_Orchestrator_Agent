# ScopeGate Attack Benchmark Methodology (M4)

Status: runnable pytest harness for PRD M4 with gateway-independent local models plus gateway-dependent/live integration cases. Provides local enforcement evidence, live-gateway enforcement evidence path (probe/policy/latency checks when endpoint configured), stronger enforce-mode assertions, latency/overhead reporting, and CI artifacts. Collection/execution succeed without a gateway (live cases xfail with explicit reasons when unconfigured).

**Non-live baseline expectation:** `38 passed, 7 xfailed` with explicit gateway-dependent reasons recorded in test output and report artifacts (4 capability-gated cases + 3 live-integration cases when gateway URL not configured).

## Semantics
- **pass**: modeled attack/edge case blocked or invariant preserved by local model/enforcement checks, or live gateway evidence observed (probe/policy denial/latency) when configured and enforced.
- **fail/error**: unexpected break (CI gate failure).
- **xfail**: capability not currently enforced/provable in runtime, or live endpoint not configured/reachable; reasoned, not silent.
Collection/execution succeed without a gateway. Live cases xfail cleanly when `--gateway-url` / `$SCOPEGATE_GATEWAY_URL` is unset/unreachable as applicable; when a live gateway is configured and reachable, live integration cases may pass while capability-gated cases remain xfailed with precise reasons. Reports/artifacts capture run mode and gateway URL/config/reachability context and list each xfailed case with its reason for evidence traceability.

## Attack classes (PRD / request mapping)

| Class | Marker | Intent | Local-model coverage |
|---|---|---|---|
| Injection exfil | `injection_exfil` | Untrusted tool/text steers agent to exfiltrate private data | xfail (needs gateway taint + egress) |
| Scope escalation | `scope_escalation` | Call/token exceeds granted scopes or parent authority | attenuation + no-inflation invariants |
| Confused deputy | `confused_deputy` | Gateway/tool acts with wrong principal/task authority | correlation invariant; isolation xfail |
| Tool poisoning | `tool_poisoning` | Poisoned manifest/metadata/output alters routing or privilege | no manifest-scope inflation; clean unknown-capability failure |
| Rug pull | `rug_pull` | Trusted tool changes behavior/schema after discovery/approval | xfail (needs drift/re-approval lifecycle) |
| Secret leak | `secret_leak` | Upstream secrets exposed to agent, logs, or responses | xfail (needs redaction boundaries) |
| DoS inputs | `dos_inputs` | Malformed/oversized/expensive inputs crash or hang gateway | depth/payload/pow budgets, typed clean failures |
| Audit tamper | `audit_tamper` | Audit entries missing/edited or chain unverifiable | SHA-256 hash-chain append/verify, tamper + removal detection |

Primary suite: `bench/test_attack_suite.py`. Harness primitives: `bench/harness.py`.

## Modes: baseline / dry-run / enforce and live integration

Run via `pytest --bench-mode=<mode>` (or `SCOPEGATE_BENCH_MODE`).

- **baseline**: Execute/record outcomes without requiring enforcement. Default for local-model assertions.
- **dry-run** (`dryrun`): Exercise observation/"would block" paths where supported.
- **enforce**: Attacks in scope must be blocked/contained per policy. Harness enforces stronger assertions (e.g. unauthorized scopes blocked, secret markers/redaction violations hard-fail, live policy checks must observe denial/block evidence when a configured gateway is reachable).
- **live gateway integration**: configure `--gateway-url` / `$SCOPEGATE_GATEWAY_URL` to run `live`-marked probes/policy/latency checks against a locally started gateway; missing endpoint yields explicit xfail.

### Running against a locally started gateway
1. Start gateway from repo root (best-effort real run; runtime may be partial):
   - `./scripts/run_gateway.sh`
   - or `cargo run -p gateway`
   - optional: `SCOPEGATE_CONFIG=./scopegate.toml.example SCOPEGATE_BIND_ADDR=127.0.0.1:8080 ./scripts/run_gateway.sh`
2. Run live bench against it:
   - `SCOPEGATE_GATEWAY_URL=http://127.0.0.1:8080 python3 -m pytest bench -q -m live --bench-mode enforce`
   - or `SCOPEGATE_GATEWAY_URL=http://127.0.0.1:8080 ./bench/run_local_gateway.sh enforce`

`run_local_gateway.sh` emits CI artifacts plus live junit/env evidence (`bench-live-junit.xml`, `bench-env.json`). Live checks attempt multiple common endpoints/payload shapes, record instrumented latency, and fail in enforce mode if reachability/denial evidence is not observed.

Markers: `baseline`, `dryrun`, `enforce`, `live` (suite default: `baseline`). Fixtures/options: `bench_mode`, `enforce`, `gateway_url`, `record_latency`, `BENCH_LATENCY_OUT` in `conftest.py`. Live helpers: `harness.LiveGateway`, `gateway_env_summary`.

## Latency/overhead measurement and reporting

- `bench/harness.py`: `TimingRecord`, `measure_call`, `time_block`, `summarize_latencies`, `write_latency_artifact` for per-operation latency/overhead capture (including by-status summary).
- `bench/conftest.py`: session `record_latency` fixture, terminal latency summary, and `BENCH_LATENCY_OUT` export of instrumented records for CI/report ingestion.
- `bench/report.py`: computes case-duration latency stats from JUnit (`avg/p50/p95/max/total`), ingests instrumented latency artifact via `--latency-json`, and emits both in markdown/JSON (`latency_ms`, `instrumented_latency`, `latency_ms_placeholders`).
- Thresholds: `--max-p95-case-ms`, `--max-time-s`, `--max-instrumented-p95-ms`.
- Live checks: `LiveGateway.probe/post_json` feed recorded probe/policy timings in live tests; `bench/run_local_gateway.sh` and `bench/ci_artifacts.sh` export latency artifacts for CI.

## Scenario mapping (reference -> bench)

| Bench case | Origin | Notes |
|---|---|---|
| `test_scope_escalation_child_exceeds_parent` | `reference/tests/test_security_confinement.py::test_child_cannot_run_scope_parent_never_granted` | child request outside parent grant denied/empty attenuation |
| `test_scope_escalation_no_inflation_from_requested_superset` | confinement + attenuation intent | requested superset cannot inflate granted scopes |
| `test_confused_deputy_cross_task_or_authority_confusion` | `reference/tests/test_security_queue.py` reply/correlation integrity intent (C/H-3 class) | local correlation invariant; gateway isolation xfail in companion case |
| `test_confused_deputy_gateway_isolation_enforcement` | `reference/tests/test_security_queue.py::test_forged_reply_on_reply_topic_is_rejected`, `test_concurrent_same_task_id_no_cross_delivery` | requires live queue/gateway isolation -> xfail |
| `test_tool_poisoning_malicious_manifest_or_metadata` | `reference/tests/test_security_tokens.py::test_token_not_inflated_by_poisoned_manifest` | poisoned manifest scope must not inflate issued/granted scope |
| `test_tool_poisoning_unknown_capability_fails_cleanly` | `reference/tests/test_security_routing.py::test_executor_unknown_capability_returns_failed_result`, `test_parallel_executor_unknown_capability_returns_failed_result` | unknown capability -> typed clean failure/None, no crash |
| `test_dos_inputs_malformed_or_resource_exhausting_payload` | `reference/tests/test_security_depth.py::test_nested_sub_tasks_beyond_depth_limit_fail_cleanly`, depth/bounds intent (CRASH-08) | budget depth/payload/size guards raise typed `BudgetExceeded` |
| `test_dos_inputs_bounded_exponentiation` | `reference/tests/test_security_pow.py::test_pow_exponent_bounded` | rejects oversized/chained exponentiation (C-2/CRASH-11 shape) |
| `test_dos_inputs_clean_failure_contract` | `reference/tests/test_attacks.py` CRASH-05/08/11 "no traceback/clean failure" contract | errors are catchable typed failures |
| `test_audit_tamper_chain_integrity_violation` | `reference/tests/test_auditor.py` integrity/tamper-evidence intent (append-only/read tolerance context) | hash-chain detects payload edit and missing-entry/chain break |
| `test_audit_tamper_append_only_head_and_ordering` | `reference/tests/test_auditor.py` append-only/read-integrity intent | chain head/order/seq linkage preserved across appends |
| `test_scope_escalation_attenuation_cases` | `reference/tests/test_security_confinement.py`, `test_security_tokens.py` attenuation intent | parametrized intersection/no-inflation cases |
| `test_tool_poisoning_unknown_capability_does_not_crash_lookup` | `reference/tests/test_security_routing.py::test_executor_unknown_capability_returns_failed_result` | clean `None`/typed failure on unknown capability |
| `test_dos_inputs_malformed_task_spec_rejected_cleanly` | `reference/tests/test_attacks.py::test_crash05_cli_malformed_task_file_no_traceback` (E3-E5 + duplicate ids/CRASH-09 shape) | local task-spec validation rejects malformed/duplicate structures with typed errors |
| `test_dos_inputs_empty_subtask_or_depth_spec_rejected` | `reference/tests/test_security_depth.py::{test_empty_sub_task_steps_fail,test_nested_sub_tasks_beyond_depth_limit_fail_cleanly}` | empty-subtask and >50 depth specs rejected cleanly |
| `test_dos_inputs_timing_measurement_placeholder_records_duration` | harness M4 timing placeholder requirement | `measure_call` captures `TimingRecord` latency placeholder/measurement |
| `test_audit_tamper_empty_log_verifies` | `reference/tests/test_auditor.py` integrity baseline intent | empty chain valid (GENESIS) |
| `test_scope_escalation_empty_requested_grants_nothing` | confinement/attenuation edge case | no request -> no grant |
| `test_scope_escalation_preserves_requested_order_for_grants` | confinement/attenuation intent | stable granted subset/order from requested ∩ parent, no inflation |
| `test_dos_inputs_too_many_items_rejected` | `reference/tests/test_security_depth.py`/CRASH-06 bounded-structure intent | bounded mapping item-count guard |
| `test_dos_inputs_too_many_sequence_items_rejected` | CRASH-06 bounded-structure/list intent | bounded sequence item-count guard, typed clean failure |
| `test_dos_inputs_task_spec_rejects_more_malformed_shapes` | `reference/tests/test_attacks.py::test_crash05_cli_malformed_task_file_no_traceback` (more variants) | additional malformed/non-object/empty-field shapes rejected with typed errors |
| `test_tool_poisoning_known_capability_routes_cleanly` | `reference/tests/test_security_routing.py` benign routing intent | known capability resolves cleanly (no poisoning side effects) |
| `test_injection_exfil_tool_output_to_external_egress` | PRD injection/exfil class (no direct ref exploit; policy/taint class) | gateway-dependent (taint+egress) -> xfail |
| `test_rug_pull_tool_changes_after_trust` | PRD rug-pull class | gateway-dependent (drift/re-approval) -> xfail |
| `test_secret_leak_agent_visible_credentials` | PRD secret-leak class | gateway-dependent (redaction/secret boundary) -> xfail |

## Mapping to `reference/tests/test_attacks.py` (finding-keyed)
- **CRASH-05** (malformed task files, no traceback/clean friendly errors): `test_dos_inputs_malformed_task_spec_rejected_cleanly`, `test_dos_inputs_task_spec_rejects_more_malformed_shapes`, `test_dos_inputs_empty_subtask_or_depth_spec_rejected`, `test_dos_inputs_clean_failure_contract` (local typed-failure contract port of E2-E5/duplicate/structural/empty-field variants).
- **CRASH-06** (bounded structure/items): `test_dos_inputs_too_many_items_rejected`, `test_dos_inputs_too_many_sequence_items_rejected`, `test_dos_inputs_expression_length_bounded`.
- **CRASH-08** (deep/empty sub-task bounds): `test_dos_inputs_malformed_or_resource_exhausting_payload`, `test_dos_inputs_empty_subtask_or_depth_spec_rejected`.
- **CRASH-11** (overflow/pow bounds, no invalid results): `test_dos_inputs_bounded_exponentiation`.
- **H-1/CRASH-03** (unknown capability clean failure): `test_tool_poisoning_unknown_capability_fails_cleanly`, `test_tool_poisoning_unknown_capability_does_not_crash_lookup`, `test_dos_inputs_clean_failure_contract`.
- **C-1 / confinement**: `test_scope_escalation_child_exceeds_parent`, `test_scope_escalation_no_inflation_from_requested_superset`, `test_scope_escalation_attenuation_cases`, `test_scope_escalation_empty_requested_grants_nothing`, `test_scope_escalation_preserves_requested_order_for_grants`, `test_scope_escalation_revocation_blocks_use`.
- **H-2** (token/manifest inflation): `test_tool_poisoning_malicious_manifest_or_metadata`.
- **H-3 / queue isolation**: `test_confused_deputy_cross_task_or_authority_confusion` (correlation invariant), `test_confused_deputy_task_budget_enforcement` (local overuse bound), plus gateway isolation xfail.
- **Audit integrity/tolerance intent** (auditor/CRASH-04/CRASH-10 context): `test_audit_tamper_*` hash-chain append/verify/tamper/removal/ordering/prev-hash/scale-overhead models.
- **Routing baseline/benign path**: `test_tool_poisoning_known_capability_routes_cleanly`.
- **Local models for gateway classes (enforcement-ready):** `test_injection_exfil_local_taint_egress_rule`, `test_secret_leak_local_redaction_enforcement`, `test_rug_pull_manifest_hash_drift_detection`.
- **Live gateway integration (xfail without endpoint):** `test_live_gateway_reachable_for_integration`, `test_live_gateway_policy_denies_out_of_scope`, `test_live_gateway_latency_probe`.

Also aligned with: `reference/tests/test_security_{confinement,depth,pow,queue,routing,tokens}.py`, `reference/tests/test_auditor.py`.

## Reporting and CI artifacts
`report.py` produces CI-style output and README table format with explicit run evidence metadata:
- `--bench-mode` / `--gateway-url`: record run mode and gateway URL/config context in reports (defaults from env).
- `--format ci` (default): full markdown report including run context (mode, gateway URL/configured/reachable/probe), totals, README-table block, explicit "XFailed cases (gateway-dependent / live-unconfigured)" reasons, per-class/case tables, case-duration + instrumented latency/overhead stats, and thresholds.
- `--format readme-table`: compact markdown table block for README/docs/status comments (includes mode/gateway context and xfail reasons when present).
- `--json`: machine-readable `run_context`, summary/cases, `xfail_cases` with reasons, thresholds, latency fields, `instrumented_latency`, and `readme_table_markdown`.
- `--md`: writes full CI markdown report to file.
- `--latency-json`: ingests instrumented latency artifact.
- Threshold gates: `--max-failures`, `--max-errors`, `--max-xpassed` (default 0), `--min-passed`, `--max-time-s`, `--max-p95-case-ms`, `--max-instrumented-p95-ms`.

CI artifacts helper (`bench/ci_artifacts.sh [mode]`, output `bench/artifacts/`): `bench-junit.xml`, `bench-latency.json`, `bench-summary.json`, `bench-report.md`, `bench-readme-table.md`, `bench-ci-env.json` (run mode + gateway config/probe context, expected baseline).
Live gateway helper (`bench/run_local_gateway.sh [mode]`): runs live-marked checks against a locally started gateway (if configured) and emits artifacts including `bench-live-junit.xml`, `bench-env.json`, latency, summary, and report outputs for enforcement evidence with explicit mode/gateway context and xfail reasons.

## Coverage and porting notes
- **Local-model (gateway-independent):** scope attenuation/no-inflation/ordering/revocation, benign + unknown-capability routing invariants, payload/depth/sequence-item/mapping-item/pow/expression/task-spec/budget bounds with typed clean failures, hash-chain append/order/tamper/removal/prev-hash/scale integrity checks, secret-redaction and taint-egress/rug-pull-drift models, stronger enforce-mode assertions, latency/overhead measurements and summaries.
- **Gateway-dependent/live (explicit xfail without endpoint):** injection exfil (taint+egress), confused-deputy isolation in live request handling, rug-pull drift/re-approval lifecycle, secret-leak redaction boundaries, and live health/policy/latency probes. When `SCOPEGATE_GATEWAY_URL` is configured, live cases run and provide endpoint-backed enforcement/latency evidence.
- **Reference alignment:** mapped to `reference/tests/test_attacks.py` and `reference/tests/test_security_{confinement,depth,pow,queue,routing,tokens}.py`, `reference/tests/test_auditor.py` as noted above; new cases extend malformed-shape/list-bound/ordering/benign-routing/enforcement/latency coverage while preserving typed clean-failure contracts.

## Running

```bash
python3 -m pip install -r bench/requirements.txt
python3 -m pytest bench -q
python3 -m pytest bench -q --bench-mode=enforce
python3 -m pytest bench -q -m dos_inputs

# start gateway locally (repo root), then:
#   ./scripts/run_gateway.sh   # or: cargo run -p gateway
SCOPEGATE_GATEWAY_URL=http://127.0.0.1:8080 python3 -m pytest bench -q -m live --bench-mode=enforce

./bench/ci_artifacts.sh baseline
SCOPEGATE_GATEWAY_URL=http://127.0.0.1:8080 ./bench/run_local_gateway.sh enforce
python3 bench/report.py --json bench-summary.json --md bench-report.md --max-failures 0 --max-errors 0 --max-xpassed 0 --max-p95-case-ms 2000
```

Collection and execution must succeed without a running gateway; gateway-dependent cases are explicit `xfail` with reasons (not silent skips). Live enforcement evidence requires a configured, reachable local gateway endpoint.
