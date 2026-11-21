# ScopeGate TypeScript SDK (HTTP client, scaffold)

**Status:** fetch-based HTTP client toward current gateway APIs. Integration scaffold, not production-hardened.

## Current state (factual)

- `package.json`: `@scopegate/sdk` (`0.0.1-dev`, private), exports `src/index.ts`.
- `src/index.ts` implements `ScopeGateClient` (uses `fetch`) for current gateway surfaces:
  - ops: `GET /healthz`, `GET /readyz`, `GET /metrics`
  - tasks: `GET/POST /v1/tasks`, `GET /v1/tasks/{id}`, `POST /v1/tasks/{id}/revoke`
  - audit: `POST /v1/audit` (query body), `GET /v1/audit/verify`
  - approvals: `GET /v1/approvals` (query params), `GET /v1/approvals/{id}`, create/resolve via `POST /v1/approvals` and path resolve fallback
  - policies: `GET/POST /v1/policies`
  - MCP: `POST /mcp` via gateway wrapper (`client.mcp(...)` sends `{ payload_json: "<json-rpc>", upstream? }`) and `client.tools.call(...)`
- Request handling: unwraps gateway `ApiResponse` envelopes to `body` for v1/ops responses, preserves MCP wrapper responses (`{ ok, payload_json, fail_closed }`), throws `ScopeGateError` on HTTP/envelope errors, and performs minimal retry once on transient failures (network / 502 / 503 / 504). MCP calls may be denied/fail-closed depending on policy/auth/runtime.
- Types/helpers aligned to current contracts where practical; behavior still depends on evolving gateway/store wiring (fail-closed semantics, limited MCP methods/tools, store-backed approvals/audit).

## Usage

```ts
import { ScopeGateClient } from "@scopegate/sdk";

const client = new ScopeGateClient({ baseUrl: "http://localhost:8080" });
console.log(await client.health());
console.log(await client.ready());
console.log(await client.listPolicies());
try {
  console.log(await client.approvals.list());
} catch (e) {
  console.error("approvals unavailable", e);
}
console.log(await client.mcp("initialize", { clientInfo: { name: "sdk", version: "dev" } }, 1));
console.log(await client.tools.call("gateway.health"));
```

## Remaining gaps

- Real Biscuit/Cedar-aware auth flows, token attenuation helpers, stable decision/error semantics across all failure modes.
- Approval wait/poll/stream consumers, richer retry/backoff strategies, tracing propagation, build artifacts/publish workflow.
- Integration tests against live gateway and S1/S2 configuration.

See `docs/STATUS.md` for verified baseline and blockers.
