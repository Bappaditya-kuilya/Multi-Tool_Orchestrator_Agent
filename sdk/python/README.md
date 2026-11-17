# ScopeGate Python SDK (HTTP client, scaffold)

**Status:** stdlib HTTP client toward current gateway APIs (no external deps). Integration scaffold, not production-hardened.

## Current state (factual)

- `pyproject.toml`: package `scopegate-sdk` (`0.0.1.dev0`, `src/` layout), no runtime deps.
- `src/scopegate_sdk/__init__.py` implements `ScopeGateClient` using `urllib` for:
  - `GET /healthz`, `GET /readyz`, `GET /metrics`
  - `GET/POST /v1/tasks`, `GET/POST /v1/audit` (query/verify via params), `POST /v1/approvals`, `GET/POST /v1/policies`
  - `POST /mcp` JSON-RPC dispatch (`client.mcp(...)`) and `tools.call(...)` mapping (current gateway supports minimal MCP methods/tools, e.g. `gateway.health`)
- Endpoint helpers/types (`ENDPOINTS`, request/result models) included. Some surfaces remain partial/unimplemented by runtime (e.g. approvals GET-by-id not exposed; behavior depends on evolving gateway contracts).

## Usage

```python
from scopegate_sdk import ScopeGateClient

client = ScopeGateClient(base_url="http://localhost:8080")
print(client.health())
print(client.ready())
print(client.list_policies())
# MCP dispatch (minimal support today)
print(client.mcp("initialize", {"clientInfo": {"name": "sdk", "version": "dev"}}, req_id=1))
print(client.tools.call("gateway.health"))
```

## Remaining gaps

- Real Biscuit/Cedar-aware auth flows, task/token attenuation helpers, and stable error/decision semantics.
- Approval wait/poll/stream flows, audit export formats, retries/backoff, TLS/mTLS options hardening.
- Integration tests against live gateway, S1/S2 config, and publish workflow.

See `docs/STATUS.md` for verified baseline and blockers.
