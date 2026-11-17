# Policy examples

Illustrative policy/scope definitions for ScopeGate (scaffold, deny-by-default intent).

## Files

- `allow-readonly.yaml` — example granting read/list-style access while denying mutating actions; includes commented placeholders for approval/taint/limit conditions.

## Current state / alignment

- **Not validated** against a finalized policy schema, Cedar model, or runtime loader/enforcement path.
- `crates/core::policy` implements in-memory rule evaluation with `Permit` / `Forbid` / `RequireApproval`, deny-by-default semantics, and `Forbid` overrides (no Cedar engine or YAML→Cedar compilation yet).
- Runtime gaps: policy store/cache, request/context mapping, taint/approval/rate-limit condition evaluation, and MCP tool/resource binding are not implemented.

## Usage intent (future)

- Point `[gateway].policies_path` in `scopegate.toml` (or `SCOPEGATE_CONFIG`) at a policy directory when loading is implemented.
- Keep examples least-privilege and explicit; prefer `Forbid`/`RequireApproval` for risky actions and external egress under taint.

## Notes

- Adjust structure/fields to match finalized schema (subjects, actions, resources, context/taint, approvals, budgets/rate limits).
- See `scopegate.toml.example`, `docs/architecture.md`, `docs/threat-model.md`, and `docs/STATUS.md` for current limits/blockers.
