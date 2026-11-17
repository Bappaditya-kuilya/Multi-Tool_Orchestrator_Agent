# ScopeGate TypeScript SDK (HTTP client, scaffold)

**Status:** fetch-based HTTP client toward current gateway APIs. Integration scaffold, not production-hardened.

## Current state (factual)

- `package.json`: `@scopegate/sdk` (`0.0.1-dev`, private), exports `src/index.ts`.
- `src/index.ts` implements `ScopeGateClient` (uses `fetch`) for:
  - `GET /healthz`, `GET /readyz`, `GET /metrics`
  - `GET/POST /v1/tasks`, `GET/POST /v1/audit`, `POST /v1/approvals`, `GET/POST /v1/policies`
  - `POST /mcp` JSON-RPC dispatch (`client.mcp(...)`) and `tools.call(...)` mapping (current gateway supports minimal MCP methods/tools, e.g. `gateway.health`)
- Endpoint helpers/types included. Some surfaces are partial/unimplemented by runtime (e.g. approvals GET-by-id not exposed); contracts may evolve.

## Usage

```ts
import { ScopeGateClient } from "@scopegate/sdk";

const client = new ScopeGateClient({ baseUrl: "http://localhost:8080" });
console.log(await client.health());
console.log(await client.ready());
console.log(await client.listPolicies());
console.log(await client.mcp("initialize", { clientInfo: { name: "sdk", version: "dev" } }, 1));
console.log(await client.tools.call("gateway.health"));
```

## Remaining gaps

- Real Biscuit/Cedar-aware auth flows, token attenuation helpers, stable decision/error semantics.
- Approval wait/poll/stream flows, retries/backoff, tracing propagation, build/test/publish workflow.
- Integration tests against live gateway and S1/S2 configuration.

See `docs/STATUS.md` for verified baseline and blockers.
