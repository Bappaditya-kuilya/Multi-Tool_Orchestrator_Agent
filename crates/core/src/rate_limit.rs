//! Rate-limit and budget primitives plus enforcement APIs.
//!
//! Provides in-memory per-token/per-tool counters, fixed windows, budget checks,
//! and reusable enforcement interfaces that map to policy hints/decisions.

use std::collections::HashMap;

use crate::policy::{BudgetHint, CallCountHint, PolicyDecision, RateLimitHint};

/// Fixed-window rate limit configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowLimit {
    pub max_calls: u32,
    pub window_secs: u64,
}

/// Limits enforced by the tracker.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Limits {
    /// Windowed call limit per token across all tools.
    pub per_token_window: Option<WindowLimit>,
    /// Windowed call limit per (token, tool).
    pub per_token_tool_window: Option<WindowLimit>,
    /// Total call-count limit per token (lifetime while tracked).
    pub per_token_call_limit: Option<u32>,
    /// Unit budget per token (e.g. tokens/cost units).
    pub per_token_budget: Option<u64>,
}

/// Outcome of a rate/budget check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LimitDecision {
    /// Policy-aligned decision: permit when within limits, require approval when
    /// any configured limit/budget is exhausted/exceeded.
    pub decision: PolicyDecision,
    /// Human-readable reasons for non-permit decisions.
    pub reasons: Vec<String>,
    /// Hint suitable for `policy::Context::rate_limit` (token-tool window if
    /// configured, otherwise token window).
    pub rate_limit: Option<RateLimitHint>,
    /// Hint suitable for `policy::Context::budget`.
    pub budget: Option<BudgetHint>,
    /// Hint suitable for `policy::Context::call_count`.
    pub call_count: Option<CallCountHint>,
}

impl LimitDecision {
    pub fn is_allowed(&self) -> bool {
        self.decision == PolicyDecision::Permit
    }

    /// Apply this decision's hints to a policy context for runtime integration.
    pub fn apply_to_context(&self, mut ctx: crate::policy::Context) -> crate::policy::Context {
        if let Some(h) = &self.rate_limit {
            ctx.rate_limit = Some(h.clone());
        }
        if let Some(h) = &self.budget {
            ctx.budget = Some(h.clone());
        }
        if let Some(h) = &self.call_count {
            ctx.call_count = Some(h.clone());
        }
        ctx
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct WindowState {
    window_start: u64,
    count: u32,
}

impl WindowState {
    fn snapshot(&self, now: u64, limit: WindowLimit) -> (u32, bool) {
        let count = if is_same_window(self.window_start, now, limit.window_secs) {
            self.count
        } else {
            0
        };
        (count, count >= limit.max_calls)
    }

    fn advance(&mut self, now: u64, limit: WindowLimit) {
        if !is_same_window(self.window_start, now, limit.window_secs) {
            self.window_start = window_start(now, limit.window_secs);
            self.count = 0;
        }
    }

    fn record(&mut self, now: u64, limit: WindowLimit) {
        self.advance(now, limit);
        self.count = self.count.saturating_add(1);
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct TokenState {
    total_calls: u32,
    budget_used: u64,
    token_window: WindowState,
    tool_windows: HashMap<String, WindowState>,
    tool_calls: HashMap<String, u32>,
}

/// In-memory tracker for per-token/per-tool counters and budget usage.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct InMemoryRateLimitTracker {
    limits: Limits,
    tokens: HashMap<String, TokenState>,
}

impl InMemoryRateLimitTracker {
    pub fn new(limits: Limits) -> Self {
        Self {
            limits,
            tokens: HashMap::new(),
        }
    }

    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    /// Returns the current call count for a token within its configured window
    /// (or total calls when no token window is configured).
    pub fn token_calls(&self, token_id: &str, now: u64) -> u32 {
        let Some(state) = self.tokens.get(token_id) else {
            return 0;
        };
        if let Some(limit) = self.limits.per_token_window {
            state.token_window.snapshot(now, limit).0
        } else {
            state.total_calls
        }
    }

    /// Returns the current call count for a (token, tool) within its configured
    /// window (or lifetime tool calls when no tool window is configured).
    pub fn token_tool_calls(&self, token_id: &str, tool: &str, now: u64) -> u32 {
        let Some(state) = self.tokens.get(token_id) else {
            return 0;
        };
        if let Some(limit) = self.limits.per_token_tool_window {
            state
                .tool_windows
                .get(tool)
                .map(|w| w.snapshot(now, limit).0)
                .unwrap_or(0)
        } else {
            state.tool_calls.get(tool).copied().unwrap_or(0)
        }
    }

    pub fn token_budget_used(&self, token_id: &str) -> u64 {
        self.tokens
            .get(token_id)
            .map(|s| s.budget_used)
            .unwrap_or(0)
    }

    pub fn token_total_calls(&self, token_id: &str) -> u32 {
        self.tokens
            .get(token_id)
            .map(|s| s.total_calls)
            .unwrap_or(0)
    }

    /// Check limits/budget without mutating counters. `budget_units` represents
    /// units that would be consumed by the operation (0 for a plain call check).
    pub fn check(&self, token_id: &str, tool: &str, now: u64, budget_units: u64) -> LimitDecision {
        let state = self.tokens.get(token_id);
        let mut reasons = Vec::new();

        let rate_limit = self
            .limits
            .per_token_tool_window
            .map(|limit| {
                let calls = state
                    .and_then(|s| s.tool_windows.get(tool))
                    .map(|w| w.snapshot(now, limit).0)
                    .unwrap_or(0);
                RateLimitHint {
                    calls_in_window: calls,
                    limit: limit.max_calls,
                    exceeded: calls >= limit.max_calls,
                }
            })
            .or_else(|| {
                self.limits.per_token_window.map(|limit| {
                    let calls = state
                        .map(|s| s.token_window.snapshot(now, limit).0)
                        .unwrap_or(0);
                    RateLimitHint {
                        calls_in_window: calls,
                        limit: limit.max_calls,
                        exceeded: calls >= limit.max_calls,
                    }
                })
            });

        if rate_limit.as_ref().is_some_and(|h| h.exceeded) {
            reasons.push("rate limit exceeded".into());
        }

        let call_count = self.limits.per_token_call_limit.map(|limit| {
            let count = state.map(|s| s.total_calls).unwrap_or(0);
            CallCountHint {
                count,
                limit: Some(limit),
                exceeded: count >= limit,
            }
        });
        if call_count.as_ref().is_some_and(|h| h.exceeded) {
            reasons.push("call count exceeded".into());
        }

        let budget = self.limits.per_token_budget.map(|limit| {
            let used = state.map(|s| s.budget_used).unwrap_or(0);
            let exceeded = used >= limit || used.saturating_add(budget_units) > limit;
            BudgetHint {
                used,
                limit,
                exceeded,
            }
        });
        if budget.as_ref().is_some_and(|h| h.exceeded) {
            reasons.push("budget exceeded".into());
        }

        let decision = if reasons.is_empty() {
            PolicyDecision::Permit
        } else {
            // Conceptually aligned with policy hooks: limits/budget gate usage and
            // require approval/intervention rather than silently permitting.
            PolicyDecision::RequireApproval
        };

        LimitDecision {
            decision,
            reasons,
            rate_limit,
            budget,
            call_count,
        }
    }

    /// Record a call and consume budget units. Returns the decision after
    /// applying the consumption; if a limit was already exceeded, consumption is
    /// still recorded for observability but the decision remains non-permit.
    pub fn consume(
        &mut self,
        token_id: impl Into<String>,
        tool: impl Into<String>,
        now: u64,
        budget_units: u64,
    ) -> LimitDecision {
        let token_id = token_id.into();
        let tool = tool.into();
        let decision = self.check(&token_id, &tool, now, budget_units);
        let state = self.tokens.entry(token_id).or_default();

        state.total_calls = state.total_calls.saturating_add(1);
        *state.tool_calls.entry(tool.clone()).or_insert(0) += 1;

        if let Some(limit) = self.limits.per_token_window {
            state.token_window.record(now, limit);
        }
        if let Some(limit) = self.limits.per_token_tool_window {
            state
                .tool_windows
                .entry(tool)
                .or_default()
                .record(now, limit);
        }

        state.budget_used = state.budget_used.saturating_add(budget_units);
        decision
    }

    /// Enforcement helper: permit only when check passes, otherwise do not consume.
    pub fn enforce(
        &mut self,
        token_id: impl Into<String>,
        tool: impl Into<String>,
        now: u64,
        budget_units: u64,
    ) -> LimitDecision {
        let token_id = token_id.into();
        let tool = tool.into();
        let decision = self.check(&token_id, &tool, now, budget_units);
        if decision.is_allowed() {
            self.consume(token_id, tool, now, budget_units)
        } else {
            decision
        }
    }
}

/// Enforcement API abstraction for rate/budget/call-count gates.
pub trait RateBudgetEnforcer {
    fn check(&self, token_id: &str, tool: &str, now: u64, budget_units: u64) -> LimitDecision;
    fn enforce(&mut self, token_id: &str, tool: &str, now: u64, budget_units: u64)
        -> LimitDecision;
}

impl RateBudgetEnforcer for InMemoryRateLimitTracker {
    fn check(&self, token_id: &str, tool: &str, now: u64, budget_units: u64) -> LimitDecision {
        Self::check(self, token_id, tool, now, budget_units)
    }

    fn enforce(
        &mut self,
        token_id: &str,
        tool: &str,
        now: u64,
        budget_units: u64,
    ) -> LimitDecision {
        Self::enforce(
            self,
            token_id.to_string(),
            tool.to_string(),
            now,
            budget_units,
        )
    }
}

/// Runtime helper: enforce limits and project hints into a policy context.
pub fn enforce_into_context<E: RateBudgetEnforcer + ?Sized>(
    enforcer: &mut E,
    token_id: &str,
    tool: &str,
    now: u64,
    budget_units: u64,
    ctx: crate::policy::Context,
) -> (LimitDecision, crate::policy::Context) {
    let decision = enforcer.enforce(token_id, tool, now, budget_units);
    let mut ctx = decision.apply_to_context(ctx);
    ctx.normalize_limits();
    (decision, ctx)
}

fn is_same_window(window_start: u64, now: u64, window_secs: u64) -> bool {
    if window_secs == 0 {
        return true;
    }
    if now < window_start {
        return true;
    }
    now - window_start < window_secs
}

fn window_start(now: u64, window_secs: u64) -> u64 {
    now.checked_div(window_secs)
        .and_then(|w| w.checked_mul(window_secs))
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permits_when_no_limits_configured_and_tracks_counts() {
        let mut tracker = InMemoryRateLimitTracker::default();
        let d = tracker.consume("tok", "search", 100, 0);
        assert_eq!(d.decision, PolicyDecision::Permit);
        assert!(d.reasons.is_empty());
        assert_eq!(tracker.token_total_calls("tok"), 1);
        assert_eq!(tracker.token_tool_calls("tok", "search", 100), 1);
        assert_eq!(tracker.token_tool_calls("tok", "other", 100), 0);
    }

    #[test]
    fn enforces_per_token_window_and_resets_after_window() {
        let mut tracker = InMemoryRateLimitTracker::new(Limits {
            per_token_window: Some(WindowLimit {
                max_calls: 2,
                window_secs: 60,
            }),
            ..Limits::default()
        });
        assert!(tracker.consume("t", "a", 10, 0).is_allowed());
        assert!(tracker.consume("t", "b", 20, 0).is_allowed());
        let denied = tracker.check("t", "a", 30, 0);
        assert_eq!(denied.decision, PolicyDecision::RequireApproval);
        assert!(denied.reasons.iter().any(|r| r.contains("rate limit")));
        let hint = denied.rate_limit.expect("rate hint");
        assert_eq!(hint.calls_in_window, 2);
        assert_eq!(hint.limit, 2);
        assert!(hint.is_exceeded());

        // new window resets
        let ok = tracker.check("t", "a", 70, 0);
        assert_eq!(ok.decision, PolicyDecision::Permit);
        assert_eq!(ok.rate_limit.unwrap().calls_in_window, 0);
    }

    #[test]
    fn enforces_per_token_tool_window_separately() {
        let mut tracker = InMemoryRateLimitTracker::new(Limits {
            per_token_tool_window: Some(WindowLimit {
                max_calls: 1,
                window_secs: 60,
            }),
            ..Limits::default()
        });
        assert!(tracker.consume("t", "read", 1, 0).is_allowed());
        assert_eq!(
            tracker.check("t", "read", 2, 0).decision,
            PolicyDecision::RequireApproval
        );
        // different tool still allowed in its own counter
        assert_eq!(
            tracker.check("t", "write", 2, 0).decision,
            PolicyDecision::Permit
        );
        assert!(tracker.consume("t", "write", 2, 0).is_allowed());
        assert_eq!(tracker.token_tool_calls("t", "read", 2), 1);
        assert_eq!(tracker.token_tool_calls("t", "write", 2), 1);
    }

    #[test]
    fn enforces_total_call_limit_per_token() {
        let mut tracker = InMemoryRateLimitTracker::new(Limits {
            per_token_call_limit: Some(2),
            ..Limits::default()
        });
        tracker.consume("t", "a", 0, 0);
        tracker.consume("t", "b", 0, 0);
        let denied = tracker.check("t", "c", 0, 0);
        assert_eq!(denied.decision, PolicyDecision::RequireApproval);
        assert!(denied.reasons.iter().any(|r| r.contains("call count")));
        let cc = denied.call_count.expect("call count hint");
        assert_eq!(cc.count, 2);
        assert_eq!(cc.limit, Some(2));
        assert!(cc.is_exceeded());
    }

    #[test]
    fn enforces_budget_and_detects_exhaustion() {
        let mut tracker = InMemoryRateLimitTracker::new(Limits {
            per_token_budget: Some(100),
            ..Limits::default()
        });
        assert!(tracker.consume("t", "llm", 0, 40).is_allowed());
        assert_eq!(tracker.token_budget_used("t"), 40);
        let would_exceed = tracker.check("t", "llm", 0, 70);
        assert_eq!(would_exceed.decision, PolicyDecision::RequireApproval);
        assert!(would_exceed.reasons.iter().any(|r| r.contains("budget")));
        let b = would_exceed.budget.expect("budget hint");
        assert_eq!(b.used, 40);
        assert_eq!(b.limit, 100);
        assert!(b.is_exceeded());

        tracker.consume("t", "llm", 0, 60);
        assert_eq!(tracker.token_budget_used("t"), 100);
        let exhausted = tracker.check("t", "llm", 0, 0);
        assert_eq!(exhausted.decision, PolicyDecision::RequireApproval);
        assert!(exhausted.budget.unwrap().is_exceeded());
    }

    #[test]
    fn isolates_tokens_and_reports_multiple_reasons() {
        let mut tracker = InMemoryRateLimitTracker::new(Limits {
            per_token_call_limit: Some(1),
            per_token_budget: Some(5),
            ..Limits::default()
        });
        tracker.consume("a", "x", 0, 5);
        let d = tracker.check("a", "x", 0, 1);
        assert_eq!(d.decision, PolicyDecision::RequireApproval);
        assert!(d.reasons.iter().any(|r| r.contains("call count")));
        assert!(d.reasons.iter().any(|r| r.contains("budget")));
        // other token independent
        assert!(tracker.check("b", "x", 0, 1).is_allowed());
    }

    #[test]
    fn enforce_api_allows_then_blocks_without_extra_consumption() {
        let mut tracker = InMemoryRateLimitTracker::new(Limits {
            per_token_call_limit: Some(1),
            ..Limits::default()
        });
        let ok = tracker.enforce("t".to_string(), "x".to_string(), 0, 0);
        assert!(ok.is_allowed());
        assert_eq!(tracker.token_total_calls("t"), 1);
        let blocked = RateBudgetEnforcer::enforce(&mut tracker, "t", "x", 1, 0);
        assert_eq!(blocked.decision, PolicyDecision::RequireApproval);
        assert_eq!(tracker.token_total_calls("t"), 1); // not consumed on deny

        let checked = RateBudgetEnforcer::check(&tracker, "t", "x", 1, 0);
        assert_eq!(checked.decision, PolicyDecision::RequireApproval);
    }
}
