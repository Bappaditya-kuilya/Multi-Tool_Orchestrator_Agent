# ScopeGate Dashboard

Vite + React + TypeScript dashboard for milestone M5 (PRD-oriented admin views).

## Structure

- `index.html` — app entry
- `vite.config.ts` — Vite config
- `tsconfig*.json` — TypeScript config
- `.env.example` — API base URL config
- `src/main.tsx` — React bootstrap
- `src/App.tsx` — navigation shell + SSE stream panel
- `src/types.ts` — admin API-aligned data models and view models
- `src/api/config.ts` — `VITE_API_BASE_URL` resolution
- `src/api/client.ts` — typed gateway client for `/v1/*`, `/healthz`, `/metrics`
- `src/api/mockData.ts` / `src/api/mockApi.ts` — screen-facing API with gateway-first + mock fallback
- `src/api/useStream.ts` — EventSource hook for `/v1/stream` with fallback mock
- `src/screens/` — Timeline, Task Tree, Approvals, Policies, Upstreams, Audit, Benchmark, Dry Run

## Run

- `npm install`
- `npm run dev`
- `npm run build` (verified with `tsc -b && vite build`)

## Config

- `VITE_API_BASE_URL` — gateway base URL (see `.env.example`). When unset/unreachable, screens fall back to mock data and `/v1/stream` falls back to mock events.

## Notes

- Typed client covers admin endpoints: `/v1/tasks`, `/v1/approvals`, `/v1/approvals/{id}/resolve`, `/v1/audit`, `/v1/policies`, `/v1/upstreams`, `/healthz`, `/metrics`, `/v1/stream`.
- Screen data fetches handle errors via client-first + mock fallback; stream hook exposes connecting/open/error/fallback states.
- Accessibility basics included: labels/landmarks, skip link, table captions/scope, visible focus, contrast/status notes; full WCAG AA audit still recommended.
