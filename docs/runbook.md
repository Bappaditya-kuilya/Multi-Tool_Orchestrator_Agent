# ScopeGate — Runbook

> Operational skeleton aligned to current scaffold state and PRD intent. **Iteration:** M0/M6/M7/M8 prep loop (2026-11-17).
> **Important:** many interfaces/behaviors below are **planned** (not implemented). Default safety intent is **fail closed** on audit store/policy/token errors.
> **Blockers:** real deps/integrations and runtime wiring remain incomplete; do not claim operational readiness. Current verified baseline (2026-11-17): fmt pass, clippy pass, tests pass, bench 38p/7xf, dashboard build pass (capture reproducible evidence/logs for each run).

## 1. Service overview

- **Service:** ScopeGate (least-privilege MCP gateway for AI agents)
- **Primary interfaces (planned):** MCP endpoint (`/mcp`), Admin API (`/v1/*`), Ops (`/healthz`, `/readyz`, `/metrics`)
- **Current runtime reality:** Rust crates with partial runtime wiring. `gateway` now includes an axum HTTP server/binary with ops/admin/MCP-dispatch routes and in-memory store wiring by default, but enforcement is incomplete (no real Biscuit/Cedar/`rmcp` full runtime, limited broker/secret handling, no proven durable append-before-return path, limited MCP tool execution). Do not treat as production-operable.
- **Key dependencies (target):** store, events, upstream MCP servers, secret sources
  - **S1:** SQLite WAL + in-process events (single node)
  - **S2:** Postgres + Redis streams (N stateless nodes, HA)

## 2. Deployment modes and ops notes

### 2.1 S1 — single binary / single node (default, target)

- **Store:** SQLite WAL, local volume. Single writer path for audit; avoid concurrent writers to same DB file.
- **Events/approvals:** in-process (tokio broadcast) in target design; no cross-node delivery.
- **Topology:** one instance (no horizontal scale/LB). Suitable for local dev/demo/small-team validation.
- **Safety intent:** fail closed on audit/store/policy/token errors; audit durability/integrity are safety-critical.
- **Current state:** documented in Docker/compose skeletons; S1 runtime path **not implemented/validated**.

### 2.2 S2 — stateless nodes behind load balancer (HA, target)

- **Store:** Postgres for upstreams/policies/tasks/approvals/audit.
- **Events:** Redis streams for approvals/SSE/live propagation.
- **Topology:** N nodes behind LB; hot path should avoid DB for token verify + cached policy decisions.
- **State:** no sticky sessions required by target design; hydrate taint/session snapshots from store on miss (TBD).
- **Current state:** placeholders in compose/config/docs only; **not implemented/validated**.

### 2.3 Docker / compose (skeleton/prep)

- **Files:** `docker/compose.yml`, `docker/Dockerfile.gateway`
- **Compose behavior (current):** gateway builds via cargo in image (with fallback placeholder artifact if build/target unavailable in snapshot) and mounts `scopegate.toml.example`; dashboard runs Vite dev scaffold. Postgres/Redis services are commented S2 placeholders.
- **Config/secrets:** mount config read-only; inject secrets via env/file/vault adapter refs when implemented (never commit raw secrets).
- **Ports:** gateway exposed on `8080`, dashboard on `3000`.
- **Bring-up:** `docker compose -f docker/compose.yml up --build`
- **Caveat:** gateway HTTP routes exist in code, but runtime behavior/endpoints may be limited depending on image/build and missing integrations; treat probes and flows as evidence-gathering, not readiness proof.

### 2.4 Configuration and preflight (planned)

- **Config:** `scopegate.toml` + environment overrides (see `scopegate.toml.example`; schema/loader not finalized).
- **Policies:** example policies under `policies/examples/` are illustrative only.
- **Preflight (planned):** config/policy checks before rollout; pin policy versions and keep rollback artifact/version ready.

## 3. Health, readiness, and rollback notes (partial)

| Endpoint | Purpose | Current behavior (factual) | Ops note |
|----------|---------|----------------------------|----------|
| `/healthz` | Liveness | Implemented in gateway HTTP server (`server.rs`/`api.rs`) | Use as basic liveness probe; does not prove full enforcement/runtime correctness. |
| `/readyz` | Readiness | Implemented with store/broker readiness checks in current wiring; may return unavailable/fail-closed reasons | Gate traffic on 200/ready semantics when meaningful; readiness criteria will evolve with durable deps. |
| `/metrics` | Prometheus scrape | Implemented (Prometheus text exposition from in-process metrics) | Metrics set/schemas are limited/scaffold-level; do not assume production coverage. |

**Rollback/release-gate intent (PRD-aligned, future):** health check fails twice, deny-rate anomaly vs baseline, or audit verify fails. Treat audit integrity failures as high severity and preserve evidence.

**Rollback/release-gate intent (PRD-aligned, future):** health check fails twice, deny-rate anomaly vs baseline, or audit verify fails.
- **Audit integrity failure:** high-severity incident; preserve evidence and fail closed if integrity cannot be assured.
- **Audit store unavailable:** expected default reject calls (fail closed). Restore durability before resuming traffic.

## 4. Common operations (target procedures)

### 4.1 Policy management (planned)
- Validate/check policies in CI/runtime tooling when available.
- Roll out pinned policy versions; support rollback to previous active version.
- Use dry-run/preview before tightening/loosening enforcement.

### 4.2 Task/token operations (planned)
- Mint root task token, attenuate child tokens, revoke task/subtree.
- Verify attenuation, expiry, budget, and revocation propagation (especially across restarts/S1→S2 migration).
- **Current core primitive:** in-memory token attenuation/expiry/budget/revocation checks exist in `crates/core` (non-Biscuit, unintegrated).

### 4.3 Approvals (planned)
- Monitor pending approval queue (age/volume). Timeout behavior = **deny**.
- Resolve approvals idempotently via Admin API/UI.
- **S1 target:** node-local/in-process unless persisted; restart may error in-flight calls.
- **S2 target:** approvals/events coordinated via store + Redis streams.
- **Current primitive:** broker approval status models timeout-as-deny; no approval service/persistence.

### 4.4 Audit (planned)
- Query/export audit records; correlate by audit seq/trace IDs.
- Verify hash chain (`audit verify` / API endpoint when implemented).
- Audit append should be durable before returning tool results in normal path.
- **Current primitives:** `core::audit` FNV-1a hash-chain append/verify (non-cryptographic) and `store` in-memory append/verify skeleton; **not durable and not wired to runtime path**.

## 5. Monitoring and alerts (M6 planned)

**Signals (target):**
- Metrics: calls by decision, decision latency, approvals pending, upstream errors, audit lag/write failures, circuit state, rate-limit/taint outcomes.
- Traces: per-call spans (verify, policy, approval wait, broker/pool/upstream, audit).
- Logs: structured JSON with correlation IDs (e.g. audit seq/trace).

**Suggested alerts (target):** deny-rate spike vs baseline, audit write failures, approval queue age threshold, audit chain verification failure, sustained readiness failures.

> No metrics/tracing/alerts are implemented yet.

## 6. Incident response (target guidance)

### 6.1 Audit integrity failure (`audit verify` fails)
1. Treat as high-severity integrity incident; stop relying on affected segment.
2. Preserve evidence (logs, DB snapshots/backups, chain-head anchors if published).
3. Fail closed if integrity cannot be assured per policy/config.
4. Escalate per security process; rotate credentials/tokens if compromise suspected.

### 6.2 Deny-rate anomaly / suspected attack
1. Inspect decision reasons, task IDs, tool targets, taint/approval patterns (when available).
2. Revoke affected task trees if needed.
3. Tighten policy or use dry-run analysis without weakening safety controls.
4. Capture benchmark/forensic artifacts and follow up.

### 6.3 Audit store unavailable
- **Target:** reject calls (fail closed). Restore store durability before resuming traffic.
- **S1 checks (future):** filesystem/volume, WAL/locks, disk-full.
- **S2 checks (future):** Postgres availability/migrations/lag/pool saturation; Redis for approval/event symptoms.

### 6.4 Node crash / restart during in-flight calls
- In-flight calls may error on reconnect.
- Pending approvals should survive in persistent store (target); verify queue/state after restart.
- In S2, drain/shift traffic and only serve after readiness is healthy.

## 7. Backup, restore, and rollback (target)

- **Policy rollback:** redeploy previous artifact and/or roll back active policy version (when implemented).
- **S1 backups:** consistent snapshot/copy of SQLite DB + WAL; verify restore and audit-chain verification on restored data.
- **S2 backups:** Postgres backups/PITR per platform policy; include schema/version compatibility checks.
- **Restore verification:** health/readiness, audit verify, and minimal policy/approval smoke flow before reopening traffic.

## 8. Release operations / CI notes

- **Versioning (planned):** SemVer (e.g. `v0.1.0` initial tag).
- **Release gates (planned):** CI green, benchmark passes, fresh-machine compose test, security/audit checks clean.
- **Current CI:** `.github/workflows/rust-ci.yml` runs fmt, clippy (`-D warnings`), tests; `cargo-audit`/`cargo-deny` are non-failing placeholders if tools are absent.
- **Verification note (2026-11-17):** current verified baseline is fmt pass / clippy pass / tests pass, bench 38 passed / 7 xfailed, dashboard build pass. Use `scripts/check_rust_toolchain.sh` (and `CHECK_RUST_RUN=1` when appropriate) to capture reproducible CI-parity evidence.
- **E2E/scripts:** `./e2e/demo_flow.sh` and `scripts/*` run real cargo/gateway/bench-oriented steps where possible and capture logs; failures may still occur due to incomplete runtime behavior/integrations.

## 9. Known gaps (operational)

- Gateway HTTP/admin/MCP-dispatch routes exist, but enforcement is partial: no real Biscuit/Cedar/`rmcp` full runtime, limited upstream execution/pool/front wiring, no production broker secret handling, and durability/append-before-return guarantees not proven.
- No S1/S2 runtime validation, backup/restore drills, alerting, or on-call/escalation process finalized.
- Config/policy schemas and runtime loaders are not finalized/validated; observability/rate-limit/taint controls need hardening and evidence.

## 10. References

- [PRD](./PRD.md)
- [Architecture](./architecture.md)
- [Threat model](./threat-model.md)
- [Status](./STATUS.md)
- [ADRs](./adr/README.md)
