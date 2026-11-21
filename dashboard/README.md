# ScopeGate Dashboard

Vite + React + TypeScript dashboard scaffold for ScopeGate admin surfaces.

## Structure

- `index.html` — app entry
- `vite.config.ts` — Vite config
- `tsconfig*.json` — TypeScript config
- `.env.example` — API base URL/config
- `src/main.tsx` — React bootstrap
- `src/App.tsx` — navigation shell + SSE stream panel
- `src/types.ts` — API-aligned and view models
- `src/api/config.ts` — `VITE_API_BASE_URL`, token, stream path, timeout
- `src/api/client.ts` — typed gateway client for implemented ops/admin/MCP-adjacent HTTP endpoints
- `src/api/mockApi.ts` / `src/api/mockData.ts` — screen-facing API with gateway-first + mock fallback
- `src/api/useStream.ts` — EventSource hook for `/v1/stream` with reconnect + mock fallback
- `src/screens/` — Timeline, Task Tree, Approvals, Policies, Upstreams, Audit, Benchmark, Dry Run

## Run

- `npm install`
- `npm run dev`
- `npm run build` (`tsc -b && vite build`)

## Config

- `VITE_API_BASE_URL` — gateway base URL (see `.env.example`)
- `VITE_API_TOKEN` — optional bearer token
- `VITE_STREAM_PATH` — SSE path (default `/v1/stream`)
- `VITE_API_TIMEOUT_MS` — request timeout

When unset/unreachable, screens use mock data/fallback behavior and stream falls back to mock events where applicable.

## Current integration notes (factual)

- Typed client covers implemented gateway surfaces where available: `/healthz`, `/readyz`, `/metrics`, `/v1/tasks` (list/create/get/revoke), `/v1/approvals` (list/get/create/resolve), `/v1/audit` (query), `/v1/audit/verify`, `/v1/policies` (get/upsert), and `/v1/stream` (SSE). `/mcp` JSON-RPC dispatch is supported by SDK clients (not a primary dashboard screen flow).
- Approvals UI attempts list/get/resolve flows and degrades gracefully when store/runtime support is unavailable or returns fail-closed/errors.
- Audit view supports store-backed chain verification via `/v1/audit/verify` when available.
- `/v1/upstreams` is not an implemented gateway route in current builds; the Upstreams screen remains forward-compatible and falls back to mock data.
- Gateway responses are envelope-wrapped (`status/body/fail_closed/error`) in current axum handlers; client unwraps with error handling.
- Runtime/enforcement remains partial (no real Biscuit/Cedar/full `rmcp` runtime, limited auth/secret handling, durability not production-proven). Treat dashboard as scaffold/integration UI, not production admin evidence.

See `../docs/STATUS.md` for verified baseline and blockers.
