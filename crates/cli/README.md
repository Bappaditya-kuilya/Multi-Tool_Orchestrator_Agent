# scopegatectl

Small CLI and full-screen TUI client for a running ScopeGate gateway.

It is a **client only**: it talks to the documented v1 HTTP API and never links
gateway internals. The only state it changes is an approval resolution through
`POST /v1/approvals/:id/resolve`.

## Run

```bash
cargo run -p scopegate-ctl -- status
cargo run -p scopegate-ctl -- --url http://127.0.0.1:8080 status
SCOPEGATE_URL=http://127.0.0.1:8080 SCOPEGATE_TOKEN=... cargo run -p scopegate-ctl -- tui
```

Start a local gateway first, for example `./scripts/run_sqlite_demo.sh`.

## Commands

| Command | Description |
|---|---|
| `status` | health, readiness, metrics summary |
| `tasks` | list tasks |
| `approvals list [--status pending]` | list approvals |
| `approvals resolve <id> <approve\|deny\|timeout>` | resolve an approval |
| `audit list [--limit N]` | show recent audit events |
| `audit verify` | verify the store-backed hash chain |
| `policies` | show the active policy |
| `tui` | full-screen dashboard |

Global flags: `--url` (`SCOPEGATE_URL`, default `http://127.0.0.1:8080`) and
`--token` (`SCOPEGATE_TOKEN`).

## TUI keys

`Tab` / `←` `→` switch tabs; `↑` `↓` select a row; `r` refresh (also auto-refreshes
every 2s); on the Approvals tab `a` approves, `d` denies, `x` times out the
selected approval; `q` or `Esc` quits.

## Notes

- Gateway error envelopes are surfaced verbatim, including `fail-closed` errors.
- A missing active policy is reported as an error, not shown as empty state.
- `tui` requires an interactive terminal; one-shot commands work anywhere.
- Output is plain tab-separated text so it can be piped or parsed.

This is preview tooling against a preview gateway. It is not a security or
sign-off surface.
