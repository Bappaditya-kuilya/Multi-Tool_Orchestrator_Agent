# ScopeGate — Architecture

> Living architecture doc aligned to current scaffold/implementation state. Source intent: [PRD.md](./PRD.md). **Iteration:** M0/M6/M7/M8 prep loop (2026-11-17). Updated with verification-prep/script and explicit blocker notes.

## 1. Overview

**Target (one line):** least-privilege gateway for AI agents enforcing scoped/expiring capabilities, approvals for risky calls, credential brokering, and tamper-evident audit at the MCP tool boundary.

**Target flow:** Agent/MCP client → MCP Server Front → AuthN (Biscuit) → Policy (Cedar) → Taint check → [Approval?] → Credential Broker → MCP Client Pool → Upstream MCP tools, with durable audit on the path.

## 1.1 Current scaffold / implementation state (factual)

- **Rust workspace:** `crates/core`, `crates/gateway`, `crates/mcp-front`, `crates/mcp-pool`, `crates/broker`, `crates/store`.
- **`core` primitives (implemented, non-production substitutes):** token scope attenuation (`child ⊆ parent`), expiry/budget narrowing, revocation-ID placeholder checks; policy `Permit/Forbid/RequireApproval` with deny-by-default and `Forbid` overrides; FNV-1a (non-cryptographic) hash-chained audit append/verify; coarse/session-level taint decisions. Unit tests exist.
- **Gateway runtime (partial):** axum-based HTTP server and binary wiring exist (`crates/gateway/src/main.rs`, `server.rs`, `api.rs`, `mcp.rs`, `state.rs`). Config loading supports store wiring: in-memory by default, with optional SQLite (WAL/sqlx) store selection/init/connect/migrate via config/env and fail-closed handling on durable-store init/connect/migrate errors. Exposed routes include `/healthz`, `/readyz`, `/metrics`, `/v1/tasks` (GET/POST), `/v1/tasks/:id` (GET), `/v1/tasks/:id/revoke` (POST), `/v1/audit` (GET/POST), `/v1/audit/verify` (GET), `/v1/approvals` (GET/POST), `/v1/approvals/:id` (GET), `/v1/approvals/:id/resolve` (POST), `/v1/policies` (GET/POST), `/v1/stream` (SSE), `/mcp` (POST JSON-RPC dispatch wrapper; non-POST returns fail-closed).
- **Gateway API/MCP behavior (as implemented):** task create/list/get/revoke and policy/approval/audit query handlers are wired to store-backed paths where available; `GET /v1/audit/verify` performs store-backed hash-chain verification and can fail closed on unavailable store/invalid chain per config. MCP dispatch is minimal (`initialize`, `ping`, `tools/list`, local `gateway.health` tool, and pool-forwarding abstractions when configured) with policy/approval/audit checks in the MCP path; it is **not** a full `rmcp` runtime or complete upstream MCP execution/proxy.
- **Store/runtime persistence progress:** `store` provides traits/models, in-memory backend, SQLite (sqlx/WAL) and Postgres adapter/migration scaffolding. Embedded migrations and migration tracking/idempotency progress exist via `_schema_migrations` in `apply_migrations` (sqlite/postgres paths feature-gated), with audit append/query/verify helpers. Durable append-before-return, restart-safe approvals/state, and production persistence guarantees are not fully proven end-to-end.
- **MCP front/pool/broker progress:** `mcp-front` includes JSON-RPC/message parsing-validation and envelope/shaping/hook/transport seam abstractions; `mcp-pool` includes transport/server config modeling, forwarding/dispatch and connection/session abstractions with health/circuit/retry/timeout/concurrency policy types and async/runtime seams (feature-gated/runtime module); `broker` includes approval queue/service primitives (timeout-deny, idempotent resolve, pause/resume signals, fail-closed sync/async persistence + store-backed reconciliation hooks) and secret resolution/injection/redaction/scrubbing hooks (including env/file/scheme resolvers, resolving broker helpers, and request/response/map/pair scrub targets) with passing crate tests as live-path primitives. Gateway/runtime integration remains limited (lifecycle approval/token/budget hooks exist in parts, but broker credential resolution/injection/scrubbing is not fully wired into MCP upstream dispatch), production secret adapter breadth (e.g. vault/KMS) is absent, and end-to-end guarantees remain incomplete.
- **Tooling/interfaces:** `bench/` (pytest harness; 38 passed, 7 xfailed in current snapshot), `dashboard/` (Vite+React+TS scaffold with typed API client/SSE integration points, build-verified), `sdk/python` & `sdk/ts` (HTTP clients toward current gateway APIs including audit verify/query and MCP dispatch surfaces), `scripts/`, `e2e/`, `docker/` (cargo-oriented runs and SQLite store env/config conveniences), `policies/examples/`, CI workflows.
- **Latest verification snapshot (2026-11-17):** `cargo fmt --all --check` pass; `cargo clippy --all-targets -- -D warnings` pass; `cargo test --all` pass; bench **38 passed, 7 xfailed**; dashboard build pass. Real production deps/integrations (Biscuit, Cedar, full `rmcp`, cryptographic audit, complete secret/broker/runtime enforcement, S1/S2 validation, release sign-off) remain incomplete.

## 2. High-level architecture (target)

```
                         ┌────────────────────────── ScopeGate node (Rust) ───────────────────────────┐
 Agent / MCP client ───► │ MCP Server Front ─► AuthN (Biscuit verify) ─► Policy (Cedar) ─► Taint check │
 (Claude, Cursor,        │        │                                              │                      │
  custom)                │        │                          require-approval ◄──┤                      │
                         │        │                                  │           │ allow                │
                         │        │                         Approval Service     ▼                      │
                         │        │                         (pause/resume)   Credential Broker          │
                         │        │                                  │           │                      │
                         │        ▼                                  ▼           ▼                      │
                         │   Audit Writer ◄──────────────────────────┴──── MCP Client Pool ──► Upstream │
                         │   (hash chain)                                                      MCP tools│
                         └───────┬──────────────────────────────────────┬──────────────────────────────┘
                                 ▼                                      ▼
                          Store (SQLite → Postgres)             Events (in-proc → Redis streams)
                                 │                                      │
                                 └──────────► Admin API ◄───────────────┘
                                                  │
                                       Dashboard (React) · CLI · OTel/Prometheus
```

## 3. Components (target) and scaffold mapping

| Target component | Responsibility (target) | Current state |
|------------------|-------------------------|---------------|
| **MCP Server Front / gateway HTTP** | Accept agent/admin connections, parse/dispatch, expose ops | `gateway` exposes axum routes (`/healthz,/readyz,/metrics,/v1/tasks[/:id,/revoke],/v1/audit,/v1/audit/verify,/v1/approvals,/v1/policies,/v1/stream,/mcp`); `mcp-front` provides parsing/validation/hook/transport abstractions. `/mcp` is minimal dispatch (not full `rmcp` front/proxy). |
| **AuthN** | Verify Biscuit token signature, expiry, attenuation chain, revocation/budgets | `crates/core::token`: placeholder checks/attenuation + tests; **no Biscuit crypto/signature verification or revocation sync/runtime binding**. |
| **Policy** | Cedar evaluation over (principal, action, resource, context) | `crates/core::policy` in-memory evaluator + tests; MCP path includes policy checks in current implementation; **no Cedar engine, YAML→Cedar compile, or finalized runtime mapping**. |
| **Taint tracker** | Track session labels and drive egress/approval decisions | `crates/core::taint` coarse decisions + tests; propagation/enforcement hooks across full runtime incomplete. |
| **Approval Service** | Hold pending calls, notify, resolve (timeout = deny) | Approval APIs/broker queue semantics exist; broker has sync/async persistence bridge hooks/adapters and gateway `/v1/approvals` handling. Restart-safe workflow/persistence guarantees not proven end-to-end. |
| **Credential Broker** | Resolve secret refs, inject at call boundary, redact in logs/results | Resolution/redaction/injection abstractions and noop/static helpers exist; no production secret adapters or complete injection/redaction guarantees. |
| **MCP Client Pool** | Persistent upstream connections, health checks, circuit breaker | Transport/server config, forwarding/dispatch/session abstractions, policy types, and async/runtime seams exist; gateway can configure/dispatch via pool abstractions. No full `rmcp` upstream runtime/integration. |
| **Audit Writer** | Append hash-chained event durably before returning result | FNV-1a chain primitives and store append/query/verify helpers exist (including store-backed `GET /v1/audit/verify` path). Optional SQLite store wiring/migrations exist; **no cryptographic hash or fully proven durable append-before-return runtime guarantees**. |
| **Store** | Persist upstreams, policies, tasks, approvals, audit log | Trait + in-memory + SQLite (sqlx/WAL) adapter/migration tracking-idempotency progress + Postgres scaffolding. Gateway supports optional SQLite wiring/config; production durability/restart-safe guarantees unproven end-to-end. |
| **Events** | Approval/SSE/live propagation | `/v1/stream` SSE and internal event plumbing exist in gateway; durability/cross-node semantics not implemented. |
| **Admin/API surfaces** | Task/policy/approval/audit management | Task create/list/get/revoke, audit query/verify, approvals, and policies endpoints are exposed in gateway; contracts/behavior may evolve. |
| **Dashboard** | Timeline, policies, approvals, token/task views, audit, benchmark | Vite+React+TS scaffold with typed API client/SSE integration points (build verified; no live backend E2E verification). |
| **Ops surfaces** | Health/readiness/metrics/tracing | `/healthz,/readyz,/metrics` implemented (readiness/store checks in current wiring). Tracing/OTel and production observability incomplete. |

## 4. Target design details (current alignment)

### 4.1 Capability tokens
- **Target:** Biscuit tokens with attenuation, expiry, call budgets, offline verification, revocation IDs, key rotation (`kid`).
- **Current:** pure-Rust model/helpers in `core::token` enforce structural invariants and narrowing; not a security-grade Biscuit implementation.

### 4.2 Policy model
- **Target:** Cedar-based (principal, action, resource, context) with deny-by-default, forbid-overrides-permit, approval-required outcomes; YAML scopes compile to Cedar.
- **Current:** in-memory `Rule` evaluation in `core::policy` plus config/store-policy checks in gateway/MCP paths (minimal); no Cedar/runtime policy loading.

### 4.3 Data model
- **Target (v1):** `upstreams`, `policies`, `tasks`, `approvals`, `audit_log` (hash-chained, append-oriented), digests by default.
- **Current:** store models/traits and in-memory/SQLite-backed records and audit chain helpers exist for core entities; schema/migration/runtime coverage is partial.

### 4.4 APIs / surfaces (current vs planned)
- **MCP:** `/mcp` implemented as minimal JSON-RPC dispatch with fail-closed behavior on unsupported/denied paths; not full `rmcp` runtime/proxy.
- **Admin/API (current):** `/v1/tasks` (GET/POST), `/v1/tasks/:id` (GET), `/v1/tasks/:id/revoke` (POST), `/v1/audit` (GET/POST), `/v1/audit/verify` (GET), `/v1/approvals` (GET/POST), `/v1/approvals/:id` (GET), `/v1/approvals/:id/resolve` (POST), `/v1/policies` (GET/POST), `/v1/stream` (SSE).
- **Admin/API (planned/evolving):** task attenuation/minting/revocation semantics parity, richer approval workflows/endpoints, policy lifecycle/versioning contracts, and stable schemas.
- **Ops:** `/healthz`, `/readyz`, `/metrics` implemented (scaffold-level metrics/schemas).

### 4.5 Request lifecycle (target)
1. Receive MCP `tools/call` with task token.
2. Verify token (signature, expiry, revocation).
3. Check budgets/rate limits (**M6 hook**, planned/hardened).
4. Evaluate policy (scopes, taint, args).
5. Approval gate if required (timeout = deny).
6. Taint/egress enforcement (**M6 hook wiring**, planned/hardened).
7. Broker injects upstream secret.
8. Forward via pooled upstream client.
9. Redact result, update taint labels.
10. Append durable hash-chained audit entry, then return result.

**Current implementation notes:** gateway and MCP paths demonstrate partial in-process/store-backed behavior (policy/approval checks, audit append/verify hooks, optional SQLite store wiring, pool dispatch abstractions) but do not yet provide the full production fail-closed lifecycle across real authn/policy/secret/upstream/runtime components.

## 4.6 M6 observability, rate limits, and taint hooks (planned/partial)

- **Observability:** `/healthz`, `/readyz`, `/metrics`, and `/v1/stream` exist; tracing/OTel, stable reason-coded schemas, and production coverage remain incomplete.
- **Rate limits / budgets:** primitives/hints and hooks exist in parts of the codebase, but enforced runtime coverage and evidence are incomplete.
- **Taint hooks:** core taint primitives and partial propagation/decision hooks exist; full runtime propagation/egress enforcement remains incomplete.
- **Placement intent:** steps 3/4/6/10 in lifecycle to ensure fail-closed, observable decisions without leaking secrets.

## 5. Scalability / deployment plan

| Stage | Topology | Notes |
|-------|----------|-------|
| **S1** | Single binary, SQLite WAL, in-process events | Default/dev target; optional SQLite store wiring/config and migration tracking progress exist. No runtime validation/sign-off. |
| **S2** | N stateless nodes, Postgres, Redis streams | HA/multi-node target; shared approvals/audit/events. Not implemented/validated. |
| **S3** | Sharded/async audit pipeline (future) | High sustained audit rates. |

**Current state:** compose/runbook/scripts include SQLite-oriented dev conveniences and placeholders; S1/S2 runtime validation and release evidence are not complete.

## 6. Failure behavior (target, partially modeled)

| Failure | Target behavior | Current note |
|---------|-----------------|--------------|
| Policy engine error | Deny, log | `core` deny-by-default logic exists; runtime/error plumbing and full policy integration incomplete. |
| Token invalid/expired/revoked | Deny, log | Placeholder token checks exist; no Biscuit verification/runtime revocation binding. |
| Audit store unavailable | Reject calls (fail closed) | Fail-closed intent present in gateway/store paths in places (including durable-store init/connect/migrate and audit verify/query behavior), but end-to-end append-before-return guarantees are not fully proven. |
| Upstream down | Circuit open, return error, log | Pool abstractions/policy types exist; full upstream/runtime behavior incomplete. |
| Approval timeout | Deny | Timeout-deny semantics modeled in broker; restart-safe workflow guarantees incomplete. |
| Rate limit/budget exhausted | Deny/throttle per policy, observable | Partial hooks/primitives; enforced runtime coverage incomplete. |
| Taint policy violation / risky egress | Block or require approval, observable | Core primitives and partial hooks exist; runtime enforcement incomplete. |

## 7. Tech stack (planned/current)

| Layer | Target choice | Current state |
|-------|---------------|---------------|
| Language/runtime | Rust, tokio | Rust workspace implemented; async/runtime integration is partial. |
| HTTP | axum + tower | axum server/routes implemented in gateway (tower ecosystem partial). |
| MCP | `rmcp` | Not implemented; gateway/front/pool use custom/minimal dispatch and seam abstractions. |
| Tokens | `biscuit-auth` | Placeholder token model in `core`. |
| Policy | `cedar-policy` | Placeholder/in-memory evaluation in `core` plus minimal config/store policy checks. |
| Storage | SQLite (WAL) → Postgres via `sqlx` | In-memory + SQLite (sqlx/WAL) adapter/migrations/idempotency tracking progress + Postgres scaffolding; optional gateway SQLite wiring exists. |
| Events | tokio broadcast → Redis streams | In-process broadcast/SSE plumbing exists; Redis/cross-node not implemented. |
| Observability | `tracing`, OpenTelemetry, Prometheus | Basic health/ready/metrics/SSE implemented; tracing/OTel/schemas incomplete. |
| Dashboard | Vite + React + TypeScript | Scaffold with typed API client/SSE integration points; build verified, live E2E unverified. |
| Bench/SDKs | Python pytest harness, Python/TS SDKs | Bench harness active (38p/7xf snapshot); SDKs provide HTTP clients toward current gateway APIs/MCP surfaces. |

## 8. Repository layout (current)

- `crates/{core,gateway,mcp-front,mcp-pool,broker,store}` — Rust workspace crates (primitives/runtime scaffolding and partial integrations)
- `docs/` — PRD, architecture, threat model, runbook, STATUS, ADRs, migration map
- `policies/examples/`, `scopegate.toml.example` — config/policy examples/scaffolds
- `bench/` — Python pytest attack/behavior harness
- `dashboard/` — Vite+React+TS UI scaffold
- `sdk/python`, `sdk/ts` — SDK clients oriented toward current APIs
- `docker/`, `scripts/`, `e2e/` — compose/build/run/check/demo scaffolds and SQLite-oriented dev conveniences
- `.github/workflows/` — CI workflows
- `reference/`, `graphify-out/`, `REPO_GRAPH.md` — legacy/reference/migration artifacts

## 9. Open decisions / remaining gaps

- [ ] Real integrations: Biscuit, Cedar (+ schema/compile/load), full `rmcp` front/pool/upstream runtime, production secret adapters.
- [ ] End-to-end fail-closed wiring across authn/policy/taint/approval/broker/pool/upstream/audit, including durable append-before-return and restart-safe state.
- [ ] Cryptographic audit hashing/signing/anchoring and verified durable audit evidence/export paths.
- [ ] Harden SQLite/Postgres runtime usage across all live paths; validate S1/S2 behavior (including approvals/revocations/state recovery).
- [ ] Stable M6 contracts: tracing/OTel, metrics schemas, enforced rate-limit/budget/taint hooks with auditable outcomes.
- [ ] Bench/dashboard/SDK live integration and enforce-mode/runtime evidence (including reproducible 38p/7xf context and environment).
- [ ] Hosted demo, hardening/sign-off, and versioned release artifacts. No crypto audit, live enforce-mode proof, S1/S2 validation, or release sign-off claimed.
