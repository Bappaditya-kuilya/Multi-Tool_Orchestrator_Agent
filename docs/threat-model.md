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

**Current implementation status (factual):** controls are partially implemented as scaffolds/non-production substitutes.
- `crates/core` implements **non-production** primitives with unit tests: token scope/expiry/budget narrowing + revocation-ID placeholder checks, rule-based permit/forbid/require-approval policy evaluation (deny-by-default, forbid overrides), FNV-1a (non-cryptographic) hash-chained audit append/verify, and coarse session taint labels with conflicted external-egress => `RequireApproval`.
- `crates/gateway` includes axum HTTP server/routes (`/healthz,/readyz,/metrics,/v1/tasks,/v1/audit,/v1/approvals,/v1/policies,/v1/stream,/mcp` minimal dispatch) with in-memory store wiring by default; upstream execution, full MCP front/pool/proxy, and production enforcement remain incomplete. `broker/mcp-front/mcp-pool/store` include stubs/placeholders or non-durable helpers.
- **Not implemented/verified:** real Biscuit/Cedar enforcement, cryptographic/durable append-before-return audit, secret brokering/redaction guarantees, production-grade rate limiting and taint propagation/enforcement, stable observability schemas, and end-to-end fail-closed runtime guarantees.
- **Verification (2026-11-17):** `cargo fmt/clippy/test` pass, bench **38 passed, 7 xfailed**, dashboard build pass (reported baseline; capture logs/artifacts per run). No security sign-off.

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
| Prompt injection → tool misuse | Untrusted content steers exfiltration | Deny-by-default, scoped tokens, taint rules, approvals | `core::policy` deny-by-default + `core::taint` conflicted-egress `RequireApproval` primitives exist; no runtime enforcement/wiring. Bench placeholder only. |
| Confused deputy | Low-priv task uses other authority | Per-task tokens, no ambient authority, binding checks | Token model has attenuation/revocation placeholders; no end-to-end binding/enforcement. |
| Scope escalation | Child requests parent-excluded scope | Biscuit attenuation (narrow-only), property tests | `core::token::attenuate` enforces subset/bounds in unit tests; not Biscuit/crypto-backed. |
| Tool poisoning | Changed tool metadata steers agent | Pin descriptions by hash, alert, re-approval on drift | Not implemented. |
| Rug pull | Tool behavior changes post-approval | Drift detection, re-approval | Not implemented. |
| Secret exfiltration | Agent reads/leaks upstream key | Credential broker, redaction, no secrets in agent/logs | Broker trait/noop placeholder only; no real secret handling. |
| Audit tampering | History edited/reordered | Cryptographic hash chain, durable append, `audit verify` | `core::audit` append/verify + tamper tests use **FNV-1a (non-cryptographic)**; no durable writer/store integrity guarantees. |
| Gateway DoS | Huge args, floods, slow upstream | Size limits, timeouts, rate limits/budgets, bounded queues, circuit breakers | Not implemented; M6 rate-limit hooks planned. Bench DoS placeholder only. |
| Policy DoS | Pathological policy/input | Policy size/eval limits, fail closed | Not implemented. |
| Admin takeover | Stolen admin credential | Separate admin surface, hashed keys, optional mTLS/OIDC, short sessions | Not implemented. |
| Supply chain | Vulnerable/malicious dependency/artifact | `cargo-deny`, `cargo-audit`, lockfile/SBOM/signed artifacts | CI has placeholder audit/deny steps (non-failing if missing); Rust checks unverified locally. |
| Replay | Reused token/approval | Expiry, revocation checks, single-use approvals bound to args hash | Expiry/revocation placeholders in token model; no runtime revocation/approval binding. |

## 5. Controls checklist

| Area | Control | Status |
|------|---------|--------|
| Authentication | Agent: Biscuit; Admin: API key (+ optional OIDC later) | Planned (token placeholder logic only). |
| Authorization | Cedar, deny-by-default; forbid overrides permit | Partially modeled in `core::policy` (non-Cedar) + tests; not enforced in runtime. |
| Secrets | Env/file/vault adapters; never logged; zeroize where practical | Planned (broker/store not implemented). |
| Transport | TLS required off localhost; mTLS option to upstreams | Planned. |
| Input validation | Strict size limits, schema validation | Planned. |
| Logging/audit | Digests by default, redaction, hash-chained audit | Partial: FNV-1a chain primitives and in-memory store wiring; no cryptographic/durable append-before-return audit path. |
| Rate limiting / budgets | Per-token/principal/upstream budgets and rate limits; fail-closed outcomes recorded | Planned/partial hooks only; not production-enforced. |
| Taint / egress control | Session-level taint labels propagated to policy/egress decisions; block/approval on risky flows | Partial primitive in `core::taint`; runtime propagation/enforcement incomplete. |
| Observability | `/healthz`, `/readyz`, `/metrics`, tracing, decision/limit/taint visibility | Partial: basic health/ready/metrics/SSE endpoints exist in gateway; tracing/OTel and stable schemas incomplete. |
| Dependencies/build | CI audits/gates, reproducible builds/SBOM/signing as maturity increases | Partially scaffolded in CI (placeholders for audit/deny). |
| Disclosure | `SECURITY.md`, private reporting, coordinated disclosure | Draft present; process/channel TBD. |

## 6. Explicit limits (publish honestly)

| Limit | Statement |
|-------|-----------|
| Malicious but authorized actions | If policy permits it, it runs. Policy quality matters. |
| Model reasoning | Not inspected; enforcement is at the tool boundary only. |
| Taint tracking granularity | Coarse/session-level labels, not full data-flow proofs. |
| Current crypto/integrity strength | `core::audit` uses FNV-1a for scaffold chaining (not cryptographic tamper resistance); production requires cryptographic hash chaining and durable storage. |
| Token/policy fidelity | `core::token`/`core::policy` are structural placeholders, not Biscuit/Cedar implementations. |

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

## 8.1 M6 observability, limits, and taint hooks (planned)

- **Observability hooks:** structured events/spans for authn, policy, taint, approval, broker/pool, and audit outcomes; `/healthz`, `/readyz`, `/metrics` for operational detection (not implemented).
- **Rate-limit hooks:** enforcement points before/with policy-gated execution (per-token/principal/upstream/call-budget) with observable counters/gauges and denial reasons.
- **Taint hooks:** record label additions and taint-driven decisions (allow/block/approval) in logs/metrics/audit; propagation remains coarse/session-level per limits.
- **Verification intent (future):** confirm deny-on-limit, taint-block/approval paths, and metric/audit emission without leaking secrets. Currently unimplemented/unverified.

## 9. Residual risks and follow-ups

- [ ] Replace FNV-1a scaffold hashing with cryptographic, durable, append-before-return audit chain.
- [ ] Integrate Biscuit/Cedar and validate attenuation/policy invariants with property/fuzz tests.
- [ ] Define secret handling/redaction guarantees and payload-capture/retention policy.
- [ ] Specify and implement M6 metrics/tracing/rate-limit/taint schemas and alerts (no sensitive leakage).
- [ ] Harden admin auth, transport security, input limits, and supply-chain/release controls.
- [ ] Validate S1/S2 failure semantics (fail-closed, restart/recovery, approval persistence) with evidence.
- [ ] Keep explicit limits and scaffold-vs-shipped statements in sync with verified capabilities.
