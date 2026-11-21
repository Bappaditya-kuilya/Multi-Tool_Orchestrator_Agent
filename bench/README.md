# ScopeGate Bench (M4)

Pytest-based attack benchmark harness for ScopeGate (PRD M4 / F10). Maps PRD attack classes to named test cases, implements gateway-independent local models where possible, and marks gateway-dependent cases as **xfail** with explicit reasons. Supports live gateway integration for enforcement evidence when a local gateway endpoint is available.

## Pass/fail/xfail semantics
- **pass**: attack modeled locally and defense/invariant holds (or benign baseline behaves correctly, or live-enforced integration evidence observed).
- **fail/error**: invariant broken or harness/test defect (CI-failing).
- **xfail**: gateway-dependent capability not currently enforced/provable, or live integration case when endpoint not configured/reachable; documented reason in test output and captured explicitly in reports/artifacts, does not fail CI by default.
- **skip**: reserved for environment gating (not used for core coverage).
- **enforce mode**: stronger assertions require modeled attacks/denials to hold as blocked evidence; live policy checks must observe denial when reachable.
- **Baseline expectation (no live gateway configured):** `38 passed, 7 xfailed` — 4 gateway-capability cases + 3 live-integration cases xfailed with explicit reasons.
- **Live gateway configured (`SCOPEGATE_GATEWAY_URL` reachable):** live integration probe/policy-denial/latency cases can pass when enforced, reducing xfails to capability-gated cases that remain unimplemented (precise reasons retained).

## Layout
- `test_attack_suite.py` — named cases per PRD class (injection exfil, scope escalation, confused deputy, tool poisoning, rug pull, secret leak, DoS inputs, audit tamper), ported/reference-aligned to `reference/tests`.
- `harness.py` — local models: hash-chain audit log + tamper verification, scope attenuation/inflation checks, budget/DoS guards, task-spec validation, clean routing lookup, secret/taint/rug-pull/drift helpers, latency/timing measurements (`TimingRecord`, `measure_call`, `time_block`, `summarize_latencies`), and live gateway helpers (`LiveGateway`, `gateway_env_summary`).
- `conftest.py` — `--bench-mode` / `$SCOPEGATE_BENCH_MODE` (`baseline|dryrun|enforce`), `--gateway-url` / `$SCOPEGATE_GATEWAY_URL`, latency record collection, and `BENCH_LATENCY_OUT` artifact export.
- `report.py` — CI-style report generator (runs pytest or reads JUnit XML); emits markdown + JSON with run context (mode, gateway URL/config, reachability/probe), per-class/case tables, explicit xfailed-case reasons, case-duration and instrumented latency/overhead stats, thresholds, and README table output.
- `run_local_gateway.sh` — helper to run live/enforce bench against a local gateway and emit artifacts (including gateway context in env metadata).
- `ci_artifacts.sh` — CI helper to run bench and emit standard artifacts (junit, json, md, latency, readme-table, env metadata with gateway context).
- `pytest.ini` — markers for modes and attack classes.
- `METHODOLOGY.md` — class definitions, modes, live enforcement evidence, latency/overhead reporting, CI artifacts, scenario coverage, and porting notes/mapping to `reference/tests`.

## Quick run
```bash
python3 -m pip install -r bench/requirements.txt
python3 -m pytest bench -q
python3 bench/report.py
```

## Run against a locally started gateway (live/enforce evidence)
Bench is runnable without a live gateway (gateway-dependent/live cases xfail explicitly). To collect live integration and stronger enforce-mode evidence:

1. Start a local gateway from repo root (runtime may be partial/scaffold; scripts attempt real cargo/binary execution):
   ```bash
   # option A: repo helper
   ./scripts/run_gateway.sh
   # option B: direct cargo
   cargo run -p gateway
   # optional config/bind (as supported by the gateway runtime)
   SCOPEGATE_CONFIG=./scopegate.toml.example SCOPEGATE_BIND_ADDR=127.0.0.1:8080 ./scripts/run_gateway.sh
   ```
2. In another shell, point bench at the gateway and run live/enforce checks:
   ```bash
   export SCOPEGATE_GATEWAY_URL=http://127.0.0.1:8080
   python3 -m pytest bench -q -m live --bench-mode enforce
   # or full suite + artifacts helper:
   SCOPEGATE_GATEWAY_URL=http://127.0.0.1:8080 ./bench/run_local_gateway.sh enforce
   ```

`run_local_gateway.sh` writes `bench/artifacts/bench-live-junit.xml`, `bench-junit.xml`, `bench-latency.json`, `bench-summary.json`, `bench-report.md`, `bench-readme-table.md`, and `bench-env.json`. Live checks probe health/ops endpoints and best-effort policy-denial paths; in enforce mode denial evidence is required when the gateway is reachable. Artifacts record run mode and gateway URL/config/reachability context plus explicit xfail reasons.

## CI-friendly commands
Run from repo root (no live gateway required; xfails are expected/documented):

```bash
python3 -m pip install -r bench/requirements.txt
python3 -m pytest bench -q --junitxml bench-junit.xml
python3 bench/report.py --junitxml bench-junit.xml --json bench-summary.json --md bench-report.md
# compact table for README/status blocks:
python3 bench/report.py --junitxml bench-junit.xml --format readme-table
# threshold gate example (fails non-zero on violations):
python3 bench/report.py --junitxml bench-junit.xml --max-failures 0 --max-errors 0 --max-xpassed 0 --max-p95-case-ms 2000
# emit standard CI artifacts (junit/json/md/latency/readme-table/env):
./bench/ci_artifacts.sh baseline
```

- `pytest` exit code gates CI (xfail does not fail; fail/error/xpass do).
- `report.py` returns non-zero when failures/errors/xpasses are present and supports CI thresholds (`--max-failures`, `--max-errors`, `--max-xpassed`, `--min-passed`, `--max-time-s`, `--max-p95-case-ms`, `--max-instrumented-p95-ms`).
- Modes: `--bench-mode=baseline|dryrun|enforce` or `$SCOPEGATE_BENCH_MODE`.
- Live gateway integration: `--gateway-url` / `$SCOPEGATE_GATEWAY_URL` enables `live` cases (probe/policy/latency checks); without endpoint they xfail explicitly.
- Instrumented latency/overhead: set `BENCH_LATENCY_OUT=bench/artifacts/bench-latency.json` during pytest and pass `--latency-json` to `report.py`.
- Targeted runs: `python3 -m pytest bench -q -m dos_inputs` (or any attack marker, including `-m live`).

### GitHub Actions snippet
```yaml
- name: Bench
  run: |
    python3 -m pip install -r bench/requirements.txt
    ./bench/ci_artifacts.sh baseline
- uses: actions/upload-artifact@v4
  if: always()
  with:
    name: bench-report
    path: bench/artifacts/
```

Artifacts include `bench-junit.xml`, `bench-latency.json`, `bench-summary.json`, `bench-report.md`, `bench-readme-table.md`, and `bench-ci-env.json` (plus `bench-env.json`/`bench-live-junit.xml` for local gateway runs). Reports/env artifacts capture run mode, gateway URL/config/reachability context, and explicit xfail reasons.

## Report output formats
- `--format ci` (default): full markdown report with run context (mode/gateway), totals, README-table block, explicit "XFailed cases" reasons, per-class/case tables, latency/overhead stats (case-duration + instrumented), and thresholds.
- `--format readme-table`: compact markdown table block (status/mode/gateway context + metrics + by-class + xfail reasons when present) suitable for README/docs.
- `--json <path>`: machine-readable `run_context`, summary/cases, `xfail_cases` with reasons, thresholds, `latency_ms`/`latency_ms_placeholders`, `instrumented_latency`, and `readme_table_markdown`.
- `--md <path>`: writes full CI markdown report.
- `--latency-json <path>`: ingests instrumented latency artifact exported via `BENCH_LATENCY_OUT`.
- `--bench-mode` / `--gateway-url`: override report metadata (defaults: `$SCOPEGATE_BENCH_MODE`/`baseline`, `$SCOPEGATE_GATEWAY_URL`).

## Scenario coverage and porting notes
Local-model coverage includes scope attenuation/no-inflation/ordering/revocation, routing/tool-poisoning invariants (unknown-capability clean failures + benign routing), malformed/oversized/depth/list/pow/expression/budget DoS bounds with typed clean failures, hash-chain tamper/removal/ordering/integrity detection with scale/overhead checks, secret-redaction and taint/egress/rug-pull drift models, and latency/overhead measurement hooks. Gateway-dependent/live classes (injection exfil, confused-deputy isolation, rug pull, secret leak, live policy/health/latency probes) are explicit xfail until endpoint/configured and wired.

Live enforcement evidence path: run `SCOPEGATE_GATEWAY_URL=http://localhost:8080 ./bench/run_local_gateway.sh enforce` against a local gateway; live probe/policy/latency checks execute when reachable and artifacts capture JUnit, instrumented latency, JSON/MD reports, and README table output.

Porting is reference-aligned to `reference/tests/test_attacks.py` (CRASH-05/06/08/11, H-1/H-2/H-3/C-1 intents) and security/auditor suites (`test_security_confinement/depth/pow/queue/routing/tokens.py`, `test_auditor.py`). See `METHODOLOGY.md` for detailed case-by-case mapping and notes on what is modeled locally vs gateway-dependent/live.

## Status
Runnable without a live gateway; collection/execution succeeds with documented xfails for gateway-only classes. With `SCOPEGATE_GATEWAY_URL` configured, live integration/enforce checks provide endpoint-backed evidence and CI artifacts. See `METHODOLOGY.md`.
