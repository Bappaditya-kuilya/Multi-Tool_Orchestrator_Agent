# ScopeGate — Threat Model

> Aligned to [PRD.md §13/§14](./PRD.md) and current scaffold/implementation state. Updated: 2026-11-17.

## 1. Scope and assumptions

**Product (target):** ScopeGate, a least-privilege MCP gateway for AI agents.

**Security goals (target):**
- Enforce least privilege per task (attenuated, expiring capabilities).
- Prevent/contain common agent attacks (prompt-injection-driven misuse, scope escalation, exfiltration).
- Keep upstream secrets out of agent-visible context.
- Provide tamper-evident, queryable audit of tool calls and decisions.

**In scope (target):** MCP tool boundary (agent ↔ gateway ↔ upstream MCP tools), capability tokens, policy evaluation, approvals, credential brokering, audit integrity, dashboard/admin surfaces, and S1/S2 deployment modes.

**Current implementation status (factual):** controls are partially implemented; runtime/store wiring and hardening progress exists, but production-grade security guarantees are not established.
- `crates/core` implements **non-production** primitives with unit tests: token scope/expiry/budget/revocation-ID placeholder checks, rule-based permit/forbid/require-approval policy evaluation (deny-by-default, forbid overrides), FNV-1a (non-cryptographic) hash-chained audit append/verify, and coarse session taint decisions.
- `crates/gateway` includes axum HTTP server/routes (`/healthz,/readyz,/metrics,/v1/tasks[/:id,/revoke],/v1/audit,/v1/audit/verify,/v1/approvals,/v1/policies,/v1/stream,/mcp`) with store/broker/MCP runtime wiring progress. Store wiring supports in-memory by default and optional SQLite (WAL/sqlx) via config/env with fail-closed init/connect/migrate behavior. `GET /v1/audit/verify` performs store-backed hash-chain verification and can fail closed on unavailable store/invalid chain (per config). MCP dispatch is minimal and not a full `rmcp` front/pool/upstream runtime.
- `store` includes in-memory + SQLite (sqlx/WAL) and Postgres adapter/migration scaffolding, embedded migrations with migration tracking/idempotency progress (`_schema_migrations` in `apply_migrations`), and audit append/query/verification helpers. `broker`/`mcp-front`/`mcp-pool` include hardening progress (approval workflow hooks including async store-backed persistence/reconciliation primitives, credential env/file/scheme resolution/injection/redaction/scrubbing primitives with passing broker crate tests, parsing/validation/hook/transport seams, transport/config/dispatch/runtime abstractions), but gateway live-path integration, production adapters/runtime guarantees remain incomplete.
- **Not implemented/verified:** real Biscuit/Cedar enforcement, cryptographic audit hashing/signing/anchoring, fully proven durable append-before-return audit across runtime paths and restart-safe approvals/state, complete secret brokering/redaction guarantees, production-grade rate limiting and taint propagation/enforcement, stable observability schemas, live end-to-end fail-closed enforcement evidence, S1/S2 validation, or release sign-off.
- **Verification snapshot (2026-11-17):** `cargo fmt/clippy/test` pass, bench **38 passed, 7 xfailed**, dashboard build pass (reported baseline; capture logs/artifacts per run). No security sign-off. No crypto audit, live enforce-mode proof, S1/S2 validation, or release sign-off.

**Assumptions:** see PRD for runtime/topology assumptions. Treat S1/S2 ops behavior as target until validated.

## 2. Assets

| Asset | Why it matters |
|-------|----------------|
| Upstream credentials/secrets | Compromise enables direct abuse of external systems |
| Capability tokens (root/attenuated) | Authority to invoke tools within scopes/budgets |
| Policy definitions and active policy version | Defines allow/deny/approval behavior |
| Audit log (hash chain) | Accountability, incident response, integrity evidence |
| Tool call arguments/results (including digests/payloads) | May contain sensitive/private data |
| Approval decisions and pending queue state | Gates risky actions |
| Taint/session state | Drives egress and approval controls |
| Admin credentials/API keys | Control-plane access |

## 3. Trust boundaries and data flows (high level)

- **Agent ↔ Gateway (MCP):** untrusted/partially trusted instructions and outputs cross enforcement boundary.
- **Gateway ↔ Upstream MCP tools:** brokered, policy-checked calls; upstream responses treated as potentially untrusted.
- **Gateway ↔ Store/Events:** persistence/coordination for audit, approvals, revocation, taint/session state.
- **Admin/Dashboard ↔ Admin API:** privileged control plane (separate auth/surface planned).
- **Gateway ↔ Secret sources:** env/file/vault adapters (planned); secrets must not flow to agent/logs.

> TODO: add detailed data-flow diagram, component trust levels, and session/taint propagation model as implementation lands.

## 4. Threats and controls

| Threat | Example | Primary controls (target) | Current state / verification |
|--------|---------|---------------------------|-----------------------------|
| Prompt injection → tool misuse | Untrusted content steers exfiltration | Deny-by-default, scoped tokens, taint rules, approvals | `core` primitives and partial gateway/MCP policy/approval checks exist; end-to-end enforcement/wiring and runtime evidence incomplete. Bench not live enforce-mode proof. |
| Confused deputy | Low-priv task uses other authority | Per-task tokens, no ambient authority, binding checks | Token model has attenuation/revocation placeholders; no end-to-end binding/enforcement or Biscuit verification. |
| Scope escalation | Child requests parent-excluded scope | Biscuit attenuation (narrow-only), property tests | `core::token::attenuate` enforces subset/bounds in unit tests; not Biscuit/crypto-backed. |
| Tool poisoning | Changed tool metadata steers agent | Pin descriptions by hash, alert, re-approval on drift | Not implemented. |
| Rug pull | Tool behavior changes post-approval | Drift detection, re-approval | Not implemented. |
| Secret exfiltration | Agent reads/leaks upstream key | Credential broker, redaction, no secrets in agent/logs | Broker crate primitives include env/file/scheme secret resolution (fail-closed), resolving credential injection, and request/response/map/pair scrubbing hooks (crate-tested), but gateway live-path integration into upstream dispatch/request-response paths, broader production secret adapters, and end-to-end no-leak guarantees remain incomplete/unproven. |
| Audit tampering | History edited/reordered | Cryptographic hash chain, durable append, `audit verify` | FNV-1a (non-cryptographic) chain logic in core/store; store-backed `GET /v1/audit/verify` and SQLite append/verify helpers exist, but cryptographic hashing and fully proven durable append-before-return/runtime guarantees are not established. |
| Gateway DoS | Huge args, floods, slow upstream | Size limits, timeouts, rate limits/budgets, bounded queues, circuit breakers | Partial abstractions/policies/hooks exist in places; production enforcement/evidence incomplete. |
| Policy DoS | Pathological policy/input | Policy size/eval limits, fail closed | Not implemented/proven. |
| Admin takeover | Stolen admin credential | Separate admin surface, hashed keys, optional mTLS/OIDC, short sessions | Not implemented. |
| Supply chain | Vulnerable/malicious dependency/artifact | `cargo-deny`, `cargo-audit`, lockfile/SBOM/signed artifacts | CI/workflow scaffolding and checks exist; not a security sign-off. |
| Replay | Reused token/approval | Expiry, revocation checks, single-use approvals bound to args hash | Expiry/revocation placeholders and partial approval/task APIs exist; runtime binding/restart-safe guarantees not proven. |

## 5. Controls checklist

| Area | Control | Status |
|------|---------|--------|
| Authentication | Agent: Biscuit; Admin: API key (+ optional OIDC later) | Planned (token placeholder logic only). |
| Authorization | Cedar, deny-by-default; forbid overrides permit | Partially modeled/implemented in non-production forms (`core` + gateway/MCP policy checks); no Cedar/runtime enforcement. |
| Secrets | Env/file/vault adapters; never logged; zeroize where practical | Partial: broker crate provides env/file/scheme resolution plus resolving injection/redaction/scrubbing primitives (fail-closed hooks, crate-tested); vault adapters, zeroization hardening, gateway live-path upstream integration, and runtime guarantees incomplete. |
| Transport | TLS required off localhost; mTLS option to upstreams | Planned. |
| Input validation | Strict size limits, schema validation | Partial parsing/validation hardening in places; not complete. |
| Logging/audit | Digests by default, redaction, hash-chained audit | Partial: FNV-1a chain in core/store, store-backed `GET /v1/audit/verify`, optional SQLite store/migrations/audit helpers; no cryptographic hash and no fully proven durable append-before-return runtime path. |
| Rate limiting / budgets | Per-token/principal/upstream budgets and rate limits; fail-closed outcomes recorded | Partial primitives/hooks; not production-enforced/proven. |
| Taint / egress control | Session-level taint labels propagated to policy/egress decisions; block/approval on risky flows | Partial primitive/hooks; runtime propagation/enforcement incomplete. |
| Observability | `/healthz`, `/readyz`, `/metrics`, tracing, decision/limit/taint visibility | Partial: health/ready/metrics/SSE exist; tracing/OTel and stable schemas incomplete. |
| Dependencies/build | CI audits/gates, reproducible builds/SBOM/signing as maturity increases | CI workflows/checks/scaffolds present; not a release security sign-off. |
| Disclosure | `SECURITY.md`, private reporting, coordinated disclosure | Draft present; process/channel TBD. |

## 6. Explicit limits (publish honestly)

| Limit | Statement |
|-------|-----------|
| Malicious but authorized actions | If policy permits it, it runs. Policy quality matters. |
| Model reasoning | Not inspected; enforcement is at the tool boundary only. |
| Taint tracking granularity | Coarse/session-level labels, not full data-flow proofs. |
| Current crypto/integrity strength | Audit chaining uses FNV-1a (non-cryptographic) in current core/store paths. Store-backed verification and some durable-store helpers exist, but cryptographic hashing/signing and fully proven durable append-before-return/runtime guarantees are not in place. |
| Token/policy fidelity | `core::token`/`core::policy` and related runtime checks are non-production substitutes/placeholders, not Biscuit/Cedar implementations. |
| Evidence/sign-off | No crypto audit, no live enforce-mode proof, no S1/S2 validation, and no release sign-off are claimed. |

## 7. Attack benchmark mapping (M4 scaffold)

| Attack class | Pass condition (enforce mode, target) | Current bench state |
|--------------|----------------------------------------|---------------------|
| Injection exfil | Egress blocked or approval required | Placeholder (skipped) |
| Scope escalation | Denied | Placeholder (skipped) |
| Confused deputy | Denied | Placeholder (skipped) |
| Tool poisoning | Flagged, re-approval required | Placeholder (skipped) |
| Rug pull | Detected via hash drift | Placeholder (skipped) |
| Secret leak | Redacted, key never agent-visible | Placeholder (skipped) |
| DoS inputs | Rejected/timed out, node stays healthy | Placeholder (skipped) |
| Audit tamper | `audit verify` fails | Placeholder (skipped); core chain-verify unit tests exist for scaffold logic |

**Verification (2026-11-17):** `python3 -m pytest bench -q` → 8 skipped (collectible, not enforcement evidence). Method: target is (a) baseline, (b) dry-run, (c) enforce with published raw data once runtime is wired.

## 8. Failure and abuse-case behavior (target)

| Failure | Expected behavior |
|---------|-------------------|
| Policy engine error | Deny, log |
| Token invalid/expired/revoked | Deny, log |
| Audit store unavailable | Reject calls (fail closed); degraded mode off by default |
| Upstream down | Circuit open, return error, log |
| Approval timeout | Deny |
| Rate limit/budget exhausted | Deny or throttle per policy (default deny on safety-critical paths), log/metric/audit reason |
| Taint policy violation / risky egress | Block or require approval per policy, log/metric/audit reason |
| Node crash mid-call | Pending approvals survive in store (target); in-flight calls error on reconnect |

## 8.1 M6 observability, limits, and taint hooks (planned/partial)

- **Observability hooks:** basic `/healthz`, `/readyz`, `/metrics`, and `/v1/stream` surfaces exist; structured tracing/OTel and stable cross-path schemas remain incomplete.
- **Rate-limit hooks:** primitives/hints and partial hook points exist, but enforced runtime coverage and evidence are incomplete.
- **Taint hooks:** coarse/session-level primitives and partial decision/propagation hooks exist; full runtime propagation/egress enforcement remains incomplete.
- **Verification intent (future):** confirm deny-on-limit, taint-block/approval paths, and metric/audit emission without leaking secrets. Currently not fully implemented/verified.

## 9. Residual risks and follow-ups

- [ ] Replace FNV-1a hashing with cryptographic audit hashing/signing/anchoring and prove durable append-before-return behavior across runtime paths.
- [ ] Integrate Biscuit/Cedar and validate attenuation/policy invariants with property/fuzz/runtime tests.
- [ ] Complete secret adapter/broker injection-redaction guarantees and approval persistence/restart-safe workflow validation.
- [ ] Harden and validate SQLite/Postgres runtime paths (including migration tracking/idempotency behavior in deployments, restart/recovery, and audit verification evidence).
- [ ] Specify and implement M6 metrics/tracing/rate-limit/taint schemas and enforced hooks with auditable outcomes.
- [ ] Harden admin auth, transport security, input limits, and supply-chain/release controls.
- [ ] Validate S1/S2 failure semantics with live evidence (including enforce-mode benchmark artifacts) and record hardening/release sign-off when actually complete. Keep claims factual: no crypto audit, live enforce-mode proof, S1/S2 validation, or release sign-off yet.
