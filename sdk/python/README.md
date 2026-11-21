# ScopeGate Python SDK (preview)

Stdlib HTTP client (`urllib`, no runtime deps) for current ScopeGate gateway preview APIs. **Not production-hardened; contracts/behavior may change.**

## Coverage (aligned to current gateway surfaces)

- Ops: `GET /healthz`, `GET /readyz`, `GET /metrics`
- Tasks: `GET/POST /v1/tasks`, `GET /v1/tasks/{id}`, `POST /v1/tasks/{id}/revoke`
- Audit: `POST /v1/audit` (query), `GET /v1/audit/verify`
- Approvals: `GET /v1/approvals`, `GET /v1/approvals/{id}`, `POST /v1/approvals`, `POST /v1/approvals/{id}/resolve` (with fallback behavior)
- Policies: `GET/POST /v1/policies`
- Stream: `GET /v1/stream` via `client.stream(...)` (SSE response handle)
- MCP: `POST /mcp` via `client.mcp(method, params, req_id, upstream=None)` (HTTP wrapper `{payload_json:"<json-rpc>", ...}`) and `client.tools.call(name, arguments)` helper; responses are MCP wrapper envelopes (`ok/payload_json/fail_closed`) subject to gateway policy/fail-closed behavior.

Responses are returned as parsed JSON/text as provided by the gateway (many endpoints use an `ApiResponse` envelope with `status/body/fail_closed/error`). Errors raise `ScopeGateHTTPError` (status/body/url) or `ScopeGateError`.

## Usage

```python
from scopegate_sdk import ScopeGateClient, ScopeGateHTTPError

client = ScopeGateClient(base_url="http://localhost:8080", timeout_s=10)

print(client.health())
print(client.ready())

# Tasks (payload shape follows gateway contract; may evolve)
task = client.create_task({
    "task_id": "task-demo-1",
    "principal": "demo-user",
    "action": "tool.call",
    "resource": "mcp:gateway.health",
    "persist": True,
})
print(client.list_tasks())
print(client.get_task("task-demo-1"))

# Audit
print(client.audit.query({"task_id": "task-demo-1", "limit": 20}))
print(client.audit.verify())

# Approvals / policies (availability depends on store/runtime wiring)
print(client.approvals.list())
print(client.list_policies())

# MCP (limited methods/tools in current preview, e.g. initialize/tools/list/gateway.health)
print(client.mcp("initialize", {"clientInfo": {"name": "sdk", "version": "preview"}}, req_id=1))
try:
    print(client.tools.call("gateway.health"))
except ScopeGateHTTPError as e:
    print("MCP/tool call not accepted:", e.status, e.body)

# SSE stream (long-lived; caller should iterate and close)
# resp = client.stream(timeout_s=None)
# try:
#     for line in resp:
#         print(line.decode("utf-8", "replace").rstrip())
# finally:
#     resp.close()
```

## Preview limitations

- Gateway enforcement/runtime is partial (no real Biscuit/Cedar/full `rmcp`, limited broker/secret handling, durability not production-proven).
- MCP tool execution/proxy support is minimal; denied/fail-closed responses are expected in many cases.
- No token attenuation/auth flows, retries/backoff, structured stream consumer, integration tests, or publish workflow.
- Verify against `docs/STATUS.md`, `docs/architecture.md`, and the running gateway build.
