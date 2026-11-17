# ScopeGate — Architecture

> Living architecture doc aligned to current scaffold/implementation state. Source intent: [PRD.md](./PRD.md). **Iteration:** M0/M6/M7/M8 prep loop (2026-11-17). Updated with verification-prep/script and explicit blocker notes.

## 1. Overview

**Target (one line):** least-privilege gateway for AI agents enforcing scoped/expiring capabilities, approvals for risky calls, credential brokering, and tamper-evident audit at the MCP tool boundary.

**Target flow:** Agent/MCP client → MCP Server Front → AuthN (Biscuit) → Policy (Cedar) → Taint check → [Approval?] → Credential Broker → MCP Client Pool → Upstream MCP tools, with durable audit on the path.

## 1.1 Current scaffold / implementation state (factual)

- **Rust workspace:** `crates/core`, `crates/gateway`, `crates/mcp-front`, `crates/mcp-pool`, `crates/broker`, `crates/store`.
- **`core` primitives (implemented, non-production substitutes):** token scope attenuation (`child ⊆ parent`), expiry/budget narrowing, revocation-ID placeholder checks; policy `Permit/Forbid/RequireApproval` with deny-by-default and `Forbid` overrides; FNV-1a (non-cryptographic) hash-chained audit append/verify; coarse/session-level taint with conflicted external-egress decisions. Unit tests exist.
- **Gateway runtime (partial):** axum-based HTTP server and binary wiring exist (`crates/gateway/src/main.rs`, `server.rs`, `api.rs`, `mcp.rs`, `state.rs`). Default `main` loads config/env, wires in-memory store, and serves routes: `/healthz`, `/readyz`, `/metrics`, `/v1/tasks` (GET/POST), `/v1/audit` (GET/POST), `/v1/approvals` (POST), `/v1/policies` (GET/POST), `/v1/stream` (SSE), `/mcp` (POST/GET JSON-RPC dispatch). MCP dispatch is minimal (`initialize`, `tools/list`, `tools/call` for `gateway.health`) and fail-closes on unsupported methods; no full `rmcp` runtime, no upstream MCP proxy/execution, no complete broker secret injection/redaction runtime.
- **Other crate state:** `broker` provides approval/secret-ref/credential abstractions and noop placeholder (timeout-deny semantics modeled); `mcp-front`/`mcp-pool` remain stubs/placeholders; `store` provides trait/in-memory helpers and chain primitives but durable SQLx-backed append-before-return and production persistence guarantees are not proven end-to-end.
- **Non-runtime/owned scaffolds:** `scopegate.toml.example`, `policies/examples/*`, `bench/` (pytest harness), `dashboard/` (Vite+React+TS shell, build-verified), `sdk/python` & `sdk/ts` (HTTP clients toward current gateway APIs), `docker/`, `e2e/`, `scripts/`, CI workflows.
- **Latest verification snapshot (2026-11-17):** `cargo fmt --all --check` pass; `cargo clippy --all-targets -- -D warnings` pass; `cargo test --all` pass; bench **38 passed, 7 xfailed** (capture mode/commit/logs); dashboard build pass. Real production deps/integrations (Biscuit, Cedar, full `rmcp`, durable sqlx stores/crypto audit, secret adapters, complete enforcement path) remain incomplete.

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
| **MCP Server Front / gateway HTTP** | Accept agent/admin connections, parse/dispatch, expose ops | `crates/gateway`: axum server/routes implemented (`/healthz,/readyz,/metrics,/v1/tasks,/v1/audit,/v1/approvals,/v1/policies,/v1/stream,/mcp`); `crates/mcp-front` remains placeholder. `/mcp` is minimal JSON-RPC dispatch (not full `rmcp` front/proxy). |
| **AuthN** | Verify Biscuit token signature, expiry, attenuation chain, revocation/budgets | `crates/core::token`: placeholder checks/attenuation + tests; **no Biscuit crypto/signature verification or revocation sync/runtime binding**. |
| **Policy** | Cedar evaluation over (principal, action, resource, context) | `crates/core::policy` in-memory evaluator + tests; **no Cedar engine, YAML→Cedar compile, or finalized policy store/cache/runtime mapping**. |
| **Taint tracker** | Track session labels and drive egress/approval decisions | `crates/core::taint` coarse decisions + tests; propagation/enforcement hooks across full runtime incomplete. |
| **Approval Service** | Hold pending calls, notify, resolve (timeout = deny) | Approval request/decision APIs and broker semantics exist in scaffold form; no production persistence/workflow guarantees. |
| **Credential Broker** | Resolve secret refs, inject at call boundary, redact in logs/results | `crates/broker`: trait + noop placeholder; no real adapters or injection/redaction guarantees. |
| **MCP Client Pool** | Persistent upstream connections, health checks, circuit breaker | `crates/mcp-pool`: stub handle/config/health API only; no upstream execution. |
| **Audit Writer** | Append hash-chained event durably before returning result | FNV-1a chain primitives + store abstractions exist; in-memory wiring default in gateway. **No cryptographic hash or proven durable append-before-return runtime path**. |
| **Store** | Persist upstreams, policies, tasks, approvals, audit log | Trait/in-memory implementation wired; SQLx durable backends/ops not proven in runtime. |
| **Events** | Approval/SSE/live propagation | `/v1/stream` SSE and internal event plumbing exist in gateway; durability/cross-node semantics not implemented. |
| **Admin/API surfaces** | Task/policy/approval/audit management | v1 handlers/routes exist in gateway; contracts/schemas/behavior may evolve. |
| **Dashboard** | Timeline, policies, approvals, token/task views, audit, benchmark | Vite+React+TS scaffold only (build verified; no backend integration). |
| **Ops surfaces** | Health/readiness/metrics/tracing | `/healthz,/readyz,/metrics` implemented in gateway; readiness reflects store/broker checks. Tracing/OTel and production observability incomplete. |

## 4. Target design details (current alignment)

### 4.1 Capability tokens
- **Target:** Biscuit tokens with attenuation, expiry, call budgets, offline verification, revocation IDs, key rotation (`kid`).
- **Current:** pure-Rust model/helpers in `core::token` enforce structural invariants and narrowing; not a security-grade Biscuit implementation.

### 4.2 Policy model
- **Target:** Cedar-based (principal, action, resource, context) with deny-by-default, forbid-overrides-permit, approval-required outcomes; YAML scopes compile to Cedar.
- **Current:** in-memory `Rule` evaluation in `core::policy` matching target decision semantics at a basic level; no Cedar/runtime policy loading.

### 4.3 Data model
- **Target (v1):** `upstreams`, `policies`, `tasks`, `approvals`, `audit_log` (hash-chained, append-oriented), digests by default.
- **Current:** `AuditEntry` shape and in-memory store skeleton only.

### 4.4 APIs / surfaces (planned)
- **MCP:** `/mcp` (agent-facing).
- **Admin:** task mint/attenuate/revoke, audit query/verify, approvals, policies, event stream.
- **Ops (M6):** `/healthz`, `/readyz`, `/metrics`.
- **Current:** none implemented.

### 4.5 Request lifecycle (target)
1. Receive MCP `tools/call` with task token.
2. Verify token (signature, expiry, revocation).
3. Check budgets/rate limits (**M6 hook**, planned).
4. Evaluate policy (scopes, taint, args).
5. Approval gate if required (timeout = deny).
6. Taint/egress enforcement (**M6 hook wiring**, planned).
7. Broker injects upstream secret.
8. Forward via pooled upstream client.
9. Redact result, update taint labels.
10. Append durable hash-chained audit entry, then return result.

**Current gateway skeleton:** demonstrates a subset in-process (token validity check, policy eval, approval-timeout-deny branch, noop broker inject/redact, audit-chain verify placeholder) with no network I/O, persistence, or upstream execution.

## 4.6 M6 observability, rate limits, and taint hooks (planned)

> Planned interfaces/surfaces only; not implemented.

- **Observability:** `/healthz`, `/readyz`, `/metrics`, structured tracing/OTel spans per lifecycle stage, and reason-coded decision visibility (allow/deny/require-approval/throttle/error).
- **Rate limits / budgets:** enforcement hooks for per-token/principal/upstream budgets and throttling; observable remaining/consumed budget and deny-throttle reasons.
- **Taint hooks:** propagation/update points and taint-aware policy/egress decisions with auditable label transitions and block/approval outcomes.
- **Placement intent:** step 3/4/6/10 in lifecycle to ensure fail-closed, observable decisions without leaking secrets.

## 5. Scalability / deployment plan

| Stage | Topology | Notes |
|-------|----------|-------|
| **S1** | Single binary, SQLite WAL, in-process events | Default/dev/demo; single-node assumptions; fail-closed on audit/store errors (target). |
| **S2** | N stateless nodes, Postgres, Redis streams | HA/multi-node; shared approvals/audit/events; hot path should avoid DB for verify/cached policy (target). |
| **S3** | Sharded/async audit pipeline (future) | High sustained audit rates. |

**Current state:** S1/S2 are documented/planned in compose/runbook; no runtime validation.

## 6. Failure behavior (target, partially modeled)

| Failure | Target behavior | Current scaffold note |
|---------|-----------------|-----------------------|
| Policy engine error | Deny, log | `core` deny-by-default logic exists; no runtime error plumbing. |
| Token invalid/expired/revoked | Deny, log | `core::token` checks available; gateway skeleton denies invalid token. |
| Audit store unavailable | Reject calls (fail closed) | Not implemented (store is in-memory skeleton). |
| Upstream down | Circuit open, return error, log | Not implemented (`mcp-pool` stub). |
| Approval timeout | Deny | `broker::ApprovalStatus::TimedOut` normalizes to deny; gateway skeleton enforces deny branch. |
| Rate limit/budget exhausted | Deny/throttle per policy, observable | Planned (M6). |
| Taint policy violation / risky egress | Block or require approval, observable | `core::taint` decision primitive exists; no runtime enforcement wiring. |

## 7. Tech stack (planned)

| Layer | Target choice | Current state |
|-------|---------------|---------------|
| Language/runtime | Rust, tokio | Rust crates scaffolded; async/runtime integrations not wired. |
| HTTP | axum + tower | Not implemented. |
| MCP | `rmcp` | Not implemented (placeholders only). |
| Tokens | `biscuit-auth` | Placeholder token model in `core`. |
| Policy | `cedar-policy` | Placeholder rule evaluator in `core`. |
| Storage | SQLite (WAL) → Postgres via `sqlx` | In-memory store skeleton only. |
| Events | tokio broadcast → Redis streams | Not implemented. |
| Observability | `tracing`, OpenTelemetry, Prometheus | Not implemented (M6 planned). |
| Dashboard | Vite + React + TypeScript | Scaffold built successfully; no integration. |
| Bench/SDKs | Python pytest harness, Python/TS SDKs | Bench placeholders verified (skips); SDKs include placeholder docs/manifests and minimal client interface stubs (no runtime integration/tests). |

## 8. Repository layout (current)

- `crates/{core,gateway,mcp-front,mcp-pool,broker,store}` — Rust workspace crates (primitives/skeletons)
- `docs/` — PRD, architecture, threat model, runbook, STATUS, ADRs, migration map
- `policies/examples/`, `scopegate.toml.example` — config/policy scaffolds
- `bench/` — Python pytest attack-suite scaffold (8 classes)
- `dashboard/` — Vite+React+TS UI scaffold
- `sdk/python`, `sdk/ts` — SDK placeholders
- `docker/` — compose/Dockerfile skeletons
- `.github/workflows/rust-ci.yml` — Rust CI workflow
- `reference/`, `graphify-out/`, `REPO_GRAPH.md` — legacy/reference/migration artifacts

## 9. Open decisions / remaining gaps

- [ ] Real integrations: Biscuit, Cedar, cryptographic audit chaining, `rmcp`, axum/tower, sqlx (SQLite/Postgres), tracing/OTel/Prometheus.
- [ ] Crate contracts and end-to-end wiring for fail-closed request path (including durable audit-before-return).
- [ ] Approval service/workflow persistence and admin/event APIs.
- [ ] Taint propagation schema and enforcement points; rate-limit/budget model and M6 metrics/tracing schemas.
- [ ] Secret source adapters and broker redaction guarantees.
- [ ] Bench/dashboard/SDK integration against runtime surfaces and production-grade verification.
- [ ] S1/S2 operational validation, backup/restore, and release readiness evidence.
