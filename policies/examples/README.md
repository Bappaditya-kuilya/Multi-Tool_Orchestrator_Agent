# Policy examples

Illustrative policy/scope definitions for ScopeGate (deny-by-default intent).

## Files

- `allow-readonly.yaml` — **illustrative, not runtime-loaded** YAML example (planned schema shape; no YAML→engine loader in current gateway).
- `runtime-rules.example.toml` — **current-loader-aligned** `[[rule]]` snippet matching `crates/gateway` config parsing (`principal`, `action`, `resource`, `decision`).

## Current state / alignment

- **Not validated** end-to-end against a finalized Cedar/policy-store/enforcement path.
- `crates/gateway` currently loads policy-like rules from config `[[rule]]` entries (or env-driven config) into in-memory evaluation; `Permit` / `Forbid` / `RequireApproval`, deny-by-default, and `Forbid`-wins semantics apply in core primitives.
- `policies_path`/YAML policy loading, Cedar integration, taint/approval/budget condition evaluation, and full MCP tool/resource binding remain incomplete.

## Usage intent

- For a runnable preview today, copy rules from `runtime-rules.example.toml` into `scopegate.toml` / `scopegate.toml.example`-style config and run with `scripts/run_gateway.sh` or `scripts/run_sqlite_demo.sh`.
- Keep examples least-privilege and explicit; prefer `Forbid`/`RequireApproval` for risky actions and external egress under taint.
- Treat `allow-readonly.yaml` as future-facing design intent until a real loader/schema exists.

## Notes

- See `scopegate.toml.example`, `docs/architecture.md`, `docs/threat-model.md`, and `docs/STATUS.md` for current limits/blockers.
