//! Policy model and evaluation seams (no Cedar dependency).
//!
//! Current engine is an in-memory rule evaluator with deny-by-default semantics and
//! `Forbid` override. Abstractions (`PolicyEngine`, `PolicyAuthorizer`) prepare for
//! plugging in `cedar-policy` later while keeping this crate pure/in-memory.

/// Principal making the request.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Principal {
    pub id: String,
}

impl Principal {
    pub fn new(id: impl Into<String>) -> Self {
        Self { id: id.into() }
    }
}

/// Action being requested.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Action {
    pub name: String,
}

impl Action {
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }
}

/// Resource targeted by the request.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Resource {
    pub id: String,
}

impl Resource {
    pub fn new(id: impl Into<String>) -> Self {
        Self { id: id.into() }
    }
}

/// Rate-limit hint attached to a request.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RateLimitHint {
    /// Calls observed in the current window.
    pub calls_in_window: u32,
    /// Maximum allowed calls in the window.
    pub limit: u32,
    /// True when the caller is currently rate-limited.
    pub exceeded: bool,
}

impl RateLimitHint {
    pub fn is_exceeded(&self) -> bool {
        self.exceeded || self.calls_in_window >= self.limit
    }

    /// Deterministic helper for integration paths: mark exceeded when at/over limit.
    pub fn normalize(mut self) -> Self {
        if self.calls_in_window >= self.limit {
            self.exceeded = true;
        }
        self
    }
}

/// Budget hint attached to a request.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BudgetHint {
    /// Consumed units (tokens/cost/etc., unit-agnostic).
    pub used: u64,
    /// Allowed units for the task/session.
    pub limit: u64,
    /// True when the budget is exhausted/exceeded.
    pub exceeded: bool,
}

impl BudgetHint {
    pub fn is_exceeded(&self) -> bool {
        self.exceeded || self.used >= self.limit
    }

    /// Deterministic helper for integration paths: mark exceeded when at/over limit.
    pub fn normalize(mut self) -> Self {
        if self.used >= self.limit {
            self.exceeded = true;
        }
        self
    }

    pub fn remaining(&self) -> u64 {
        self.limit.saturating_sub(self.used)
    }
}

/// Call-count hint attached to a request.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CallCountHint {
    /// Number of calls already made.
    pub count: u32,
    /// Maximum allowed calls, if bounded.
    pub limit: Option<u32>,
    /// True when a call-count limit is exceeded.
    pub exceeded: bool,
}

impl CallCountHint {
    pub fn is_exceeded(&self) -> bool {
        self.exceeded || self.limit.is_some_and(|l| self.count >= l)
    }

    /// Deterministic helper for integration paths: mark exceeded when at/over limit.
    pub fn normalize(mut self) -> Self {
        if self.limit.is_some_and(|l| self.count >= l) {
            self.exceeded = true;
        }
        self
    }
}

/// Taint hint attached to a request/session.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TaintHint {
    /// Labels/tags present (e.g. "untrusted", "pii", "secret").
    pub labels: Vec<String>,
    /// True when taint should block or gate the operation.
    pub sensitive: bool,
}

impl TaintHint {
    pub fn has_label(&self, label: &str) -> bool {
        self.labels.iter().any(|l| l == label)
    }
}

/// Request context for policy evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Context {
    /// Placeholder for approval annotations/signals (e.g. pre-approved token).
    pub approval: Option<ApprovalAnnotation>,
    /// Optional rate-limit hint.
    pub rate_limit: Option<RateLimitHint>,
    /// Optional budget hint.
    pub budget: Option<BudgetHint>,
    /// Optional call-count hint.
    pub call_count: Option<CallCountHint>,
    /// Optional taint hint.
    pub taint: Option<TaintHint>,
}

impl Context {
    pub fn with_approval(approval: Option<ApprovalAnnotation>) -> Self {
        Self {
            approval,
            ..Self::default()
        }
    }

    pub fn with_budget(mut self, budget: BudgetHint) -> Self {
        self.budget = Some(budget);
        self
    }

    pub fn with_rate_limit(mut self, rate_limit: RateLimitHint) -> Self {
        self.rate_limit = Some(rate_limit);
        self
    }

    pub fn with_call_count(mut self, call_count: CallCountHint) -> Self {
        self.call_count = Some(call_count);
        self
    }

    pub fn with_taint(mut self, taint: TaintHint) -> Self {
        self.taint = Some(taint);
        self
    }

    /// Integration helper: normalize budget/rate/call-count hints in place.
    pub fn normalize_limits(&mut self) {
        if let Some(h) = self.budget.take() {
            self.budget = Some(h.normalize());
        }
        if let Some(h) = self.rate_limit.take() {
            self.rate_limit = Some(h.normalize());
        }
        if let Some(h) = self.call_count.take() {
            self.call_count = Some(h.normalize());
        }
    }

    pub fn budget_exceeded(&self) -> bool {
        self.budget.as_ref().is_some_and(|h| h.is_exceeded())
    }

    pub fn rate_limit_exceeded(&self) -> bool {
        self.rate_limit.as_ref().is_some_and(|h| h.is_exceeded())
    }

    pub fn call_count_exceeded(&self) -> bool {
        self.call_count.as_ref().is_some_and(|h| h.is_exceeded())
    }

    pub fn any_limit_exceeded(&self) -> bool {
        self.budget_exceeded() || self.rate_limit_exceeded() || self.call_count_exceeded()
    }
}

/// Request presented to the policy engine.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PolicyRequest {
    pub principal: Principal,
    pub action: Action,
    pub resource: Resource,
    pub context: Context,
}

impl PolicyRequest {
    pub fn new(
        principal: impl Into<String>,
        action: impl Into<String>,
        resource: impl Into<String>,
    ) -> Self {
        Self {
            principal: Principal::new(principal),
            action: Action::new(action),
            resource: Resource::new(resource),
            context: Context::default(),
        }
    }

    /// Integration helper: normalize limit hints before evaluation.
    pub fn normalized_limits(mut self) -> Self {
        self.context.normalize_limits();
        self
    }
}

/// Policy decision outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PolicyDecision {
    Permit,
    #[default]
    Forbid,
    RequireApproval,
}

/// Human/automated approval annotation attached to a decision.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ApprovalAnnotation {
    pub approved_by: Option<String>,
    pub reason: Option<String>,
}

/// Structured reason for an evaluation outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyReason {
    pub code: String,
    pub message: String,
    pub rule_id: Option<String>,
}

impl PolicyReason {
    pub fn hook(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            rule_id: None,
        }
    }

    pub fn rule(
        code: impl Into<String>,
        message: impl Into<String>,
        rule_id: Option<String>,
    ) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            rule_id,
        }
    }
}

/// Obligation/required follow-up attached to a decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyObligation {
    RequireApproval { reason: String },
    Audit { event: String },
    RateLimit { scope: String },
    Budget { scope: String },
    TaintReview { labels: Vec<String> },
}

impl PolicyObligation {
    pub fn require_approval(reason: impl Into<String>) -> Self {
        Self::RequireApproval {
            reason: reason.into(),
        }
    }
}

/// Result of evaluating a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyEvaluation {
    pub decision: PolicyDecision,
    pub approval: Option<ApprovalAnnotation>,
    /// Hook/trigger reasons that influenced the decision (if any).
    pub reasons: Vec<String>,
    /// Structured reasons (backing detail for hooks/rules).
    pub detailed_reasons: Vec<PolicyReason>,
    /// Obligations implied by the decision/context.
    pub obligations: Vec<PolicyObligation>,
}

impl PolicyEvaluation {
    pub fn new(
        decision: PolicyDecision,
        approval: Option<ApprovalAnnotation>,
        reasons: Vec<String>,
        detailed_reasons: Vec<PolicyReason>,
        obligations: Vec<PolicyObligation>,
    ) -> Self {
        Self {
            decision,
            approval,
            reasons,
            detailed_reasons,
            obligations,
        }
    }

    pub fn requires_approval(&self) -> bool {
        self.decision == PolicyDecision::RequireApproval
    }

    pub fn is_forbidden(&self) -> bool {
        self.decision == PolicyDecision::Forbid
    }
}

/// Condition for matching a request field.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Match {
    /// Matches any value.
    #[default]
    Any,
    /// Exact string equality.
    Exact(String),
    /// Prefix match.
    Prefix(String),
    /// Suffix match.
    Suffix(String),
    /// Contains substring match.
    Contains(String),
    /// Matches if any inner match matches.
    AnyOf(Vec<Match>),
}

impl Match {
    pub fn exact(value: impl Into<String>) -> Self {
        Self::Exact(value.into())
    }
    pub fn prefix(value: impl Into<String>) -> Self {
        Self::Prefix(value.into())
    }
    pub fn suffix(value: impl Into<String>) -> Self {
        Self::Suffix(value.into())
    }
    pub fn contains(value: impl Into<String>) -> Self {
        Self::Contains(value.into())
    }
    pub fn any_of(matches: Vec<Match>) -> Self {
        Self::AnyOf(matches)
    }

    pub fn matches(&self, value: &str) -> bool {
        match self {
            Match::Any => true,
            Match::Exact(expected) => value == expected,
            Match::Prefix(prefix) => value.starts_with(prefix),
            Match::Suffix(suffix) => value.ends_with(suffix),
            Match::Contains(part) => value.contains(part),
            Match::AnyOf(inner) => inner.iter().any(|m| m.matches(value)),
        }
    }
}

/// A single policy rule. Field conditions default to match-any.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Rule {
    /// Optional stable id for reason/obligation attribution.
    pub id: Option<String>,
    /// Back-compat exact principal match; ignored if `principal_match` is set.
    pub principal: Option<String>,
    /// Back-compat exact action match; ignored if `action_match` is set.
    pub action: Option<String>,
    /// Back-compat exact resource match; ignored if `resource_match` is set.
    pub resource: Option<String>,
    /// Rich principal condition.
    pub principal_match: Option<Match>,
    /// Rich action/tool condition.
    pub action_match: Option<Match>,
    /// Rich resource condition.
    pub resource_match: Option<Match>,
    /// Effect when matched.
    pub effect: PolicyDecision,
    /// Optional human-readable reason for this rule.
    pub reason: Option<String>,
    /// When true, match only if any rate-limit/budget/call-count is exceeded.
    pub when_budget_or_rate_exceeded: bool,
    /// When true, match only if taint is present/sensitive.
    pub when_tainted: bool,
    /// Optional taint label required for `when_tainted` matches.
    pub taint_label: Option<String>,
}

impl Rule {
    /// Helper: create a rule matching a tool/action name.
    pub fn for_tool(action: impl Into<String>, effect: PolicyDecision) -> Self {
        Self {
            action_match: Some(Match::exact(action)),
            effect,
            ..Self::default()
        }
    }

    /// Helper: permit a specific tool/action.
    pub fn permit_tool(action: impl Into<String>) -> Self {
        Self::for_tool(action, PolicyDecision::Permit)
    }

    /// Helper: forbid a specific tool/action.
    pub fn forbid_tool(action: impl Into<String>) -> Self {
        Self::for_tool(action, PolicyDecision::Forbid)
    }

    /// Helper: require approval for a specific tool/action.
    pub fn require_approval_tool(action: impl Into<String>) -> Self {
        Self::for_tool(action, PolicyDecision::RequireApproval)
    }

    /// Helper: create a rule matching a resource.
    pub fn for_resource(resource: impl Into<String>, effect: PolicyDecision) -> Self {
        Self {
            resource_match: Some(Match::exact(resource)),
            effect,
            ..Self::default()
        }
    }

    /// Helper: create a rule matching principal, action, and resource exactly.
    pub fn exact(principal: &str, action: &str, resource: &str, effect: PolicyDecision) -> Self {
        Self {
            principal_match: Some(Match::exact(principal)),
            action_match: Some(Match::exact(action)),
            resource_match: Some(Match::exact(resource)),
            effect,
            ..Self::default()
        }
    }

    pub fn with_id(mut self, id: impl Into<String>) -> Self {
        self.id = Some(id.into());
        self
    }

    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = Some(reason.into());
        self
    }

    fn field_matches(specific: &Option<Match>, legacy: &Option<String>, value: &str) -> bool {
        if let Some(m) = specific {
            return m.matches(value);
        }
        legacy.as_ref().is_none_or(|v| v == value)
    }

    fn context_matches(&self, req: &PolicyRequest) -> bool {
        if self.when_budget_or_rate_exceeded {
            let exceeded = req
                .context
                .rate_limit
                .as_ref()
                .is_some_and(|h| h.is_exceeded())
                || req.context.budget.as_ref().is_some_and(|h| h.is_exceeded())
                || req
                    .context
                    .call_count
                    .as_ref()
                    .is_some_and(|h| h.is_exceeded());
            if !exceeded {
                return false;
            }
        }
        if self.when_tainted {
            let tainted = req.context.taint.as_ref().is_some_and(|h| {
                let label_ok = self.taint_label.as_ref().is_none_or(|l| h.has_label(l));
                label_ok && (h.sensitive || !h.labels.is_empty())
            });
            if !tainted {
                return false;
            }
        }
        true
    }

    fn matches(&self, req: &PolicyRequest) -> bool {
        Self::field_matches(&self.principal_match, &self.principal, &req.principal.id)
            && Self::field_matches(&self.action_match, &self.action, &req.action.name)
            && Self::field_matches(&self.resource_match, &self.resource, &req.resource.id)
            && self.context_matches(req)
    }
}

/// Integration helpers for budget/rate-limit decisions.
pub fn budget_decision_hint(
    budget: &BudgetHint,
) -> Option<(PolicyDecision, String, PolicyObligation)> {
    if budget.is_exceeded() {
        Some((
            PolicyDecision::RequireApproval,
            format!(
                "budget exceeded: used={} limit={}",
                budget.used, budget.limit
            ),
            PolicyObligation::Budget {
                scope: "request".into(),
            },
        ))
    } else {
        None
    }
}

pub fn rate_limit_decision_hint(
    rate: &RateLimitHint,
) -> Option<(PolicyDecision, String, PolicyObligation)> {
    if rate.is_exceeded() {
        Some((
            PolicyDecision::RequireApproval,
            format!(
                "rate limit exceeded: calls_in_window={} limit={}",
                rate.calls_in_window, rate.limit
            ),
            PolicyObligation::RateLimit {
                scope: "request".into(),
            },
        ))
    } else {
        None
    }
}

pub fn call_count_decision_hint(
    calls: &CallCountHint,
) -> Option<(PolicyDecision, String, PolicyObligation)> {
    if calls.is_exceeded() {
        Some((
            PolicyDecision::RequireApproval,
            format!(
                "call count exceeded: count={} limit={:?}",
                calls.count, calls.limit
            ),
            PolicyObligation::RateLimit {
                scope: "call_count".into(),
            },
        ))
    } else {
        None
    }
}

/// Hook: derive decisions implied by request context hints.
/// Returns triggered decisions with reasons. Deny-by-default is handled by
/// `evaluate`; hooks only add explicit constraints.
pub fn context_hooks(request: &PolicyRequest) -> Vec<(PolicyDecision, String)> {
    context_hooks_detailed(request)
        .into_iter()
        .map(|(d, r, _)| (d, r.message))
        .collect()
}

/// Detailed hook reasons/obligations for integration and auditing.
pub fn context_hooks_detailed(
    request: &PolicyRequest,
) -> Vec<(PolicyDecision, PolicyReason, PolicyObligation)> {
    let mut out = Vec::new();
    if let Some(b) = request.context.budget.as_ref() {
        if let Some((d, msg, obl)) = budget_decision_hint(b) {
            out.push((d, PolicyReason::hook("budget_exceeded", msg), obl));
        }
    }
    if let Some(r) = request.context.rate_limit.as_ref() {
        if let Some((d, msg, obl)) = rate_limit_decision_hint(r) {
            out.push((d, PolicyReason::hook("rate_limit_exceeded", msg), obl));
        }
    }
    if let Some(c) = request.context.call_count.as_ref() {
        if let Some((d, msg, obl)) = call_count_decision_hint(c) {
            out.push((d, PolicyReason::hook("call_count_exceeded", msg), obl));
        }
    }
    if let Some(t) = request.context.taint.as_ref() {
        if t.sensitive {
            let labels = t.labels.clone();
            out.push((
                PolicyDecision::RequireApproval,
                PolicyReason::hook("taint_sensitive", "taint sensitive"),
                PolicyObligation::TaintReview { labels },
            ));
        }
    }
    out
}

/// Evaluate rules against a request.
///
/// Semantics: deny-by-default, forbid overrides permit. A `RequireApproval`
/// match yields `RequireApproval` unless any matching rule forbids. Context
/// hooks may also require approval (e.g. budget exceeded) but cannot override
/// an explicit forbid. If a permit/approval requirement exists and context
/// carries approval, the result is annotated with it.
pub fn evaluate(request: &PolicyRequest, rules: &[Rule]) -> PolicyEvaluation {
    let mut saw_permit = false;
    let mut saw_require_approval = false;
    let mut saw_forbid = false;
    let mut reasons = Vec::new();
    let mut detailed_reasons = Vec::new();
    let mut obligations = Vec::new();

    for (idx, rule) in rules.iter().enumerate() {
        if !rule.matches(request) {
            continue;
        }
        let rid = rule.id.clone().or(Some(format!("rule#{idx}")));
        let code = match rule.effect {
            PolicyDecision::Forbid => "rule_forbid",
            PolicyDecision::Permit => "rule_permit",
            PolicyDecision::RequireApproval => "rule_require_approval",
        };
        let msg = rule.reason.clone().unwrap_or_else(|| match rule.effect {
            PolicyDecision::Forbid => "matched forbid rule".into(),
            PolicyDecision::Permit => "matched permit rule".into(),
            PolicyDecision::RequireApproval => "matched approval rule".into(),
        });
        detailed_reasons.push(PolicyReason::rule(code, msg.clone(), rid));
        reasons.push(msg.clone());
        match rule.effect {
            PolicyDecision::Forbid => {
                saw_forbid = true;
                obligations.push(PolicyObligation::Audit {
                    event: "policy.forbid".into(),
                });
            }
            PolicyDecision::Permit => {
                saw_permit = true;
            }
            PolicyDecision::RequireApproval => {
                saw_require_approval = true;
                obligations.push(PolicyObligation::require_approval(msg));
            }
        }
    }

    for (decision, reason, obligation) in context_hooks_detailed(request) {
        reasons.push(reason.message.clone());
        detailed_reasons.push(reason);
        obligations.push(obligation);
        match decision {
            PolicyDecision::Forbid => saw_forbid = true,
            PolicyDecision::RequireApproval => saw_require_approval = true,
            PolicyDecision::Permit => saw_permit = true,
        }
    }

    // Keep deterministic, de-duplicated obligations by value order-insensitive? preserve order, remove exact dups.
    let mut deduped = Vec::new();
    for o in obligations {
        if !deduped.contains(&o) {
            deduped.push(o);
        }
    }
    obligations = deduped;

    if saw_forbid {
        obligations.retain(|o| {
            !matches!(
                o,
                PolicyObligation::RequireApproval { .. } | PolicyObligation::TaintReview { .. }
            )
        });
        return PolicyEvaluation::new(
            PolicyDecision::Forbid,
            None,
            reasons,
            detailed_reasons,
            obligations,
        );
    }
    if saw_require_approval {
        return PolicyEvaluation::new(
            PolicyDecision::RequireApproval,
            request.context.approval.clone(),
            reasons,
            detailed_reasons,
            obligations,
        );
    }
    if saw_permit {
        return PolicyEvaluation::new(
            PolicyDecision::Permit,
            request.context.approval.clone(),
            reasons,
            detailed_reasons,
            obligations,
        );
    }
    PolicyEvaluation::new(
        PolicyDecision::Forbid,
        None,
        reasons,
        detailed_reasons,
        obligations,
    )
}

/// Minimal policy-engine abstraction to prepare for Cedar-backed evaluators.
pub trait PolicyEngine {
    fn evaluate(&self, request: &PolicyRequest) -> PolicyEvaluation;
}

/// Alias emphasizing authorization-style integrations.
pub trait PolicyAuthorizer {
    fn authorize(&self, request: &PolicyRequest) -> PolicyEvaluation;
}

/// Runtime integration hook for dynamic rule/policy sources.
pub trait PolicySource: Send + Sync {
    fn rules(&self) -> Vec<Rule>;
}

/// Hook interface for runtime policy pre/post evaluation (Cedar-like integration seam).
pub trait PolicyEvaluationHook: Send + Sync {
    fn before_evaluate(&self, _request: &PolicyRequest) {}
    fn after_evaluate(&self, _request: &PolicyRequest, _evaluation: &PolicyEvaluation) {}
}

/// In-memory rule-set engine (current implementation).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StaticPolicyEngine {
    pub rules: Vec<Rule>,
}

impl StaticPolicyEngine {
    pub fn new(rules: Vec<Rule>) -> Self {
        Self { rules }
    }
}

impl PolicyEngine for StaticPolicyEngine {
    fn evaluate(&self, request: &PolicyRequest) -> PolicyEvaluation {
        evaluate(request, &self.rules)
    }
}

impl PolicyAuthorizer for StaticPolicyEngine {
    fn authorize(&self, request: &PolicyRequest) -> PolicyEvaluation {
        self.evaluate(request)
    }
}

impl PolicySource for StaticPolicyEngine {
    fn rules(&self) -> Vec<Rule> {
        self.rules.clone()
    }
}

/// Runtime engine that evaluates requests using a dynamic policy source.
#[derive(Debug, Default)]
pub struct DynamicPolicyEngine<S> {
    pub source: S,
}

impl<S> DynamicPolicyEngine<S> {
    pub fn new(source: S) -> Self {
        Self { source }
    }
}

impl<S: PolicySource> PolicyEngine for DynamicPolicyEngine<S> {
    fn evaluate(&self, request: &PolicyRequest) -> PolicyEvaluation {
        request.evaluate_with_source(&self.source)
    }
}

impl<S: PolicySource> PolicyAuthorizer for DynamicPolicyEngine<S> {
    fn authorize(&self, request: &PolicyRequest) -> PolicyEvaluation {
        self.evaluate(request)
    }
}

impl PolicyRequest {
    /// Evaluate this request against an engine abstraction.
    pub fn evaluate_with<E: PolicyEngine + ?Sized>(&self, engine: &E) -> PolicyEvaluation {
        engine.evaluate(self)
    }

    /// Evaluate using a dynamic runtime policy source.
    pub fn evaluate_with_source<S: PolicySource + ?Sized>(&self, source: &S) -> PolicyEvaluation {
        evaluate(self, &source.rules())
    }
}

/// Feature-gated Cedar adapter hooks for runtime policy integrations.
#[cfg(feature = "cedar")]
pub mod cedar_adapter {
    use super::{PolicyEvaluation, PolicyRequest};

    /// Hook for evaluating requests via a Cedar-backed runtime authorizer.
    pub trait CedarAuthorizer {
        fn authorize_with_cedar(&self, request: &PolicyRequest) -> PolicyEvaluation;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(principal: &str, action: &str, resource: &str) -> PolicyRequest {
        PolicyRequest {
            principal: Principal {
                id: principal.into(),
            },
            action: Action {
                name: action.into(),
            },
            resource: Resource {
                id: resource.into(),
            },
            context: Context::default(),
        }
    }

    #[test]
    fn denies_by_default() {
        let eval = evaluate(&req("agent", "invoke", "tool"), &[]);
        assert_eq!(eval.decision, PolicyDecision::Forbid);
        assert!(eval.approval.is_none());
    }

    #[test]
    fn permits_matching_rule() {
        let rules = vec![Rule {
            principal: Some("agent".into()),
            action: Some("invoke".into()),
            resource: Some("tool".into()),
            effect: PolicyDecision::Permit,
            ..Rule::default()
        }];
        let eval = evaluate(&req("agent", "invoke", "tool"), &rules);
        assert_eq!(eval.decision, PolicyDecision::Permit);
    }

    #[test]
    fn requires_approval_when_rule_demands_it() {
        let rules = vec![Rule {
            action: Some("deploy".into()),
            effect: PolicyDecision::RequireApproval,
            ..Rule::default()
        }];
        let mut request = req("agent", "deploy", "prod");
        request.context.approval = Some(ApprovalAnnotation {
            approved_by: Some("alice".into()),
            reason: Some("ok".into()),
        });
        let eval = evaluate(&request, &rules);
        assert_eq!(eval.decision, PolicyDecision::RequireApproval);
        assert_eq!(
            eval.approval
                .as_ref()
                .and_then(|a| a.approved_by.as_deref()),
            Some("alice")
        );
    }

    #[test]
    fn forbid_overrides_permit_and_approval() {
        let rules = vec![
            Rule {
                action: Some("delete".into()),
                effect: PolicyDecision::Permit,
                ..Rule::default()
            },
            Rule {
                action: Some("delete".into()),
                effect: PolicyDecision::RequireApproval,
                ..Rule::default()
            },
            Rule {
                action: Some("delete".into()),
                effect: PolicyDecision::Forbid,
                ..Rule::default()
            },
        ];
        let eval = evaluate(&req("agent", "delete", "db"), &rules);
        assert_eq!(eval.decision, PolicyDecision::Forbid);
        assert!(eval.approval.is_none());
    }

    #[test]
    fn rich_match_helpers_and_conditions() {
        let rules = vec![
            Rule::for_tool("fs.read", PolicyDecision::Permit),
            Rule::for_resource("db:prod", PolicyDecision::RequireApproval),
        ];
        assert_eq!(
            evaluate(&req("a", "fs.read", "x"), &rules).decision,
            PolicyDecision::Permit
        );
        assert_eq!(
            evaluate(&req("a", "fs.write", "db:prod"), &rules).decision,
            PolicyDecision::RequireApproval
        );

        let prefix = Rule {
            action_match: Some(Match::prefix("fs.")),
            effect: PolicyDecision::Permit,
            ..Rule::default()
        };
        assert_eq!(
            evaluate(&req("a", "fs.delete", "x"), std::slice::from_ref(&prefix)).decision,
            PolicyDecision::Permit
        );
        assert_eq!(
            evaluate(&req("a", "net.get", "x"), &[prefix]).decision,
            PolicyDecision::Forbid
        );

        let suffix = Rule {
            resource_match: Some(Match::suffix(":prod")),
            effect: PolicyDecision::RequireApproval,
            ..Rule::default()
        };
        assert_eq!(
            evaluate(&req("a", "op", "db:prod"), &[suffix]).decision,
            PolicyDecision::RequireApproval
        );

        let contains = Rule {
            principal_match: Some(Match::contains("svc")),
            effect: PolicyDecision::Permit,
            ..Rule::default()
        };
        assert_eq!(
            evaluate(&req("my-svc-1", "op", "r"), &[contains]).decision,
            PolicyDecision::Permit
        );

        let any = Rule {
            action_match: Some(Match::any_of(vec![Match::exact("a"), Match::exact("b")])),
            effect: PolicyDecision::Permit,
            ..Rule::default()
        };
        assert_eq!(
            evaluate(&req("p", "b", "r"), std::slice::from_ref(&any)).decision,
            PolicyDecision::Permit
        );
        assert_eq!(
            evaluate(&req("p", "c", "r"), &[any]).decision,
            PolicyDecision::Forbid
        );
    }

    #[test]
    fn budget_exceeded_requires_approval_hook() {
        let mut request = req("agent", "invoke", "tool");
        request.context.budget = Some(BudgetHint {
            used: 10,
            limit: 10,
            exceeded: false,
        });
        let eval = evaluate(
            &request,
            &[Rule {
                effect: PolicyDecision::Permit,
                ..Rule::default()
            }],
        );
        assert_eq!(eval.decision, PolicyDecision::RequireApproval);
        assert!(eval.reasons.iter().any(|r| r.contains("budget")));
    }

    #[test]
    fn rate_limit_and_call_count_hooks_require_approval() {
        let mut r1 = req("agent", "invoke", "tool");
        r1.context.rate_limit = Some(RateLimitHint {
            calls_in_window: 5,
            limit: 5,
            exceeded: false,
        });
        let e1 = evaluate(&r1, &[]);
        assert_eq!(e1.decision, PolicyDecision::RequireApproval);
        assert!(e1.reasons.iter().any(|r| r.contains("rate")));

        let mut r2 = req("agent", "invoke", "tool");
        r2.context.call_count = Some(CallCountHint {
            count: 3,
            limit: Some(3),
            exceeded: false,
        });
        let e2 = evaluate(&r2, &[]);
        assert_eq!(e2.decision, PolicyDecision::RequireApproval);
        assert!(e2.reasons.iter().any(|r| r.contains("call count")));
    }

    #[test]
    fn taint_sensitive_requires_approval_but_forbid_rule_wins() {
        let mut request = req("agent", "invoke", "tool");
        request.context.taint = Some(TaintHint {
            labels: vec!["untrusted".into()],
            sensitive: true,
        });
        let eval = evaluate(&request, &[]);
        assert_eq!(eval.decision, PolicyDecision::RequireApproval);
        assert!(eval.reasons.iter().any(|r| r.contains("taint")));

        let forbid = vec![Rule {
            effect: PolicyDecision::Forbid,
            ..Rule::default()
        }];
        let eval_forbid = evaluate(&request, &forbid);
        assert_eq!(eval_forbid.decision, PolicyDecision::Forbid);
    }

    #[test]
    fn rule_can_match_on_exceeded_or_taint_hints() {
        let mut request = req("agent", "deploy", "prod");
        request.context.budget = Some(BudgetHint {
            used: 100,
            limit: 50,
            exceeded: true,
        });
        let rules = vec![Rule {
            when_budget_or_rate_exceeded: true,
            effect: PolicyDecision::Forbid,
            ..Rule::default()
        }];
        assert_eq!(evaluate(&request, &rules).decision, PolicyDecision::Forbid);

        let mut treq = req("agent", "egress", "net");
        treq.context.taint = Some(TaintHint {
            labels: vec!["pii".into()],
            sensitive: false,
        });
        let trules = vec![Rule {
            when_tainted: true,
            taint_label: Some("pii".into()),
            effect: PolicyDecision::RequireApproval,
            ..Rule::default()
        }];
        assert_eq!(
            evaluate(&treq, &trules).decision,
            PolicyDecision::RequireApproval
        );
        assert_eq!(
            evaluate(&req("agent", "egress", "net"), &trules).decision,
            PolicyDecision::Forbid
        );
    }

    #[test]
    fn exact_helper_and_legacy_fields_still_match() {
        let rule = Rule::exact("p", "a", "r", PolicyDecision::Permit);
        assert_eq!(
            evaluate(&req("p", "a", "r"), &[rule]).decision,
            PolicyDecision::Permit
        );
        let legacy = Rule {
            principal: Some("p".into()),
            action: Some("a".into()),
            resource: Some("r".into()),
            effect: PolicyDecision::Permit,
            ..Rule::default()
        };
        assert_eq!(
            evaluate(&req("p", "a", "r"), &[legacy]).decision,
            PolicyDecision::Permit
        );
    }

    #[test]
    fn deny_by_default_still_holds_without_matches() {
        let rules = vec![Rule {
            action: Some("other".into()),
            effect: PolicyDecision::Permit,
            ..Rule::default()
        }];
        assert_eq!(
            evaluate(&req("p", "a", "r"), &rules).decision,
            PolicyDecision::Forbid
        );
    }

    #[test]
    fn hint_helpers() {
        assert!(RateLimitHint {
            calls_in_window: 1,
            limit: 1,
            exceeded: false
        }
        .is_exceeded());
        assert!(BudgetHint {
            used: 0,
            limit: 0,
            exceeded: true
        }
        .is_exceeded());
        assert!(CallCountHint {
            count: 2,
            limit: Some(2),
            exceeded: false
        }
        .is_exceeded());
        let t = TaintHint {
            labels: vec!["x".into()],
            sensitive: false,
        };
        assert!(t.has_label("x"));
        assert!(!t.has_label("y"));
    }

    #[test]
    fn hint_normalize_and_budget_remaining() {
        let b = BudgetHint {
            used: 10,
            limit: 10,
            exceeded: false,
        }
        .normalize();
        assert!(b.is_exceeded());
        assert_eq!(
            BudgetHint {
                used: 3,
                limit: 10,
                exceeded: false
            }
            .remaining(),
            7
        );
        let r = RateLimitHint {
            calls_in_window: 5,
            limit: 5,
            exceeded: false,
        }
        .normalize();
        assert!(r.is_exceeded());
        let c = CallCountHint {
            count: 2,
            limit: Some(2),
            exceeded: false,
        }
        .normalize();
        assert!(c.is_exceeded());
    }

    #[test]
    fn context_limit_integration_helpers() {
        let mut ctx = Context::default()
            .with_budget(BudgetHint {
                used: 5,
                limit: 5,
                exceeded: false,
            })
            .with_rate_limit(RateLimitHint {
                calls_in_window: 1,
                limit: 2,
                exceeded: false,
            })
            .with_call_count(CallCountHint {
                count: 3,
                limit: Some(3),
                exceeded: false,
            });
        assert!(ctx.budget_exceeded());
        assert!(!ctx.rate_limit_exceeded());
        assert!(ctx.call_count_exceeded());
        assert!(ctx.any_limit_exceeded());
        ctx.normalize_limits();
        assert!(ctx.budget.as_ref().unwrap().exceeded);
        assert!(ctx.call_count.as_ref().unwrap().exceeded);
    }

    #[test]
    fn request_builder_and_normalized_limits() {
        let req = PolicyRequest::new("p", "a", "r").normalized_limits();
        assert_eq!(req.principal.id, "p");
        assert_eq!(req.action.name, "a");
        assert_eq!(req.resource.id, "r");
    }

    #[test]
    fn decision_hint_helpers_and_detailed_hooks() {
        let b = BudgetHint {
            used: 9,
            limit: 8,
            exceeded: false,
        };
        let (d, msg, obl) = budget_decision_hint(&b).unwrap();
        assert_eq!(d, PolicyDecision::RequireApproval);
        assert!(msg.contains("budget exceeded"));
        assert!(matches!(obl, PolicyObligation::Budget { .. }));

        let mut request = req("agent", "invoke", "tool");
        request.context.budget = Some(BudgetHint {
            used: 1,
            limit: 1,
            exceeded: false,
        });
        request.context.rate_limit = Some(RateLimitHint {
            calls_in_window: 2,
            limit: 2,
            exceeded: false,
        });
        request.context.call_count = Some(CallCountHint {
            count: 4,
            limit: Some(4),
            exceeded: false,
        });
        request.context.taint = Some(TaintHint {
            labels: vec!["pii".into()],
            sensitive: true,
        });
        let hooks = context_hooks_detailed(&request);
        assert!(hooks.iter().any(|(_, r, _)| r.code == "budget_exceeded"));
        assert!(hooks
            .iter()
            .any(|(_, r, _)| r.code == "rate_limit_exceeded"));
        assert!(hooks
            .iter()
            .any(|(_, r, _)| r.code == "call_count_exceeded"));
        assert!(hooks.iter().any(|(_, r, _)| r.code == "taint_sensitive"));
        assert!(hooks
            .iter()
            .any(|(_, _, o)| matches!(o, PolicyObligation::TaintReview { .. })));
        let simple = context_hooks(&request);
        assert!(simple.iter().any(|(_, m)| m.contains("budget exceeded")));
    }

    #[test]
    fn evaluation_includes_reasons_obligations_and_rule_metadata() {
        let rule = Rule::for_tool("deploy", PolicyDecision::RequireApproval)
            .with_id("r-approve-deploy")
            .with_reason("deploy needs approval");
        let eval = evaluate(&req("u", "deploy", "svc"), &[rule]);
        assert_eq!(eval.decision, PolicyDecision::RequireApproval);
        assert!(eval
            .reasons
            .iter()
            .any(|r| r.contains("deploy needs approval")));
        assert!(eval
            .detailed_reasons
            .iter()
            .any(|r| r.rule_id.as_deref() == Some("r-approve-deploy")));
        assert!(eval
            .obligations
            .iter()
            .any(|o| matches!(o, PolicyObligation::RequireApproval { .. })));
        assert!(eval.requires_approval());
        assert!(!eval.is_forbidden());
    }

    #[test]
    fn forbid_takes_precedence_and_clears_approval_obligations() {
        let mut request = req("u", "deploy", "svc");
        request.context.taint = Some(TaintHint {
            labels: vec!["secret".into()],
            sensitive: true,
        });
        let rules = vec![
            Rule::for_tool("deploy", PolicyDecision::RequireApproval).with_reason("needs approval"),
            Rule::for_tool("deploy", PolicyDecision::Forbid)
                .with_id("forbid-deploy")
                .with_reason("blocked"),
        ];
        let eval = evaluate(&request, &rules);
        assert_eq!(eval.decision, PolicyDecision::Forbid);
        assert!(eval.is_forbidden());
        assert!(eval
            .obligations
            .iter()
            .any(|o| matches!(o, PolicyObligation::Audit { .. })));
        assert!(!eval
            .obligations
            .iter()
            .any(|o| matches!(o, PolicyObligation::RequireApproval { .. })));
        assert!(!eval
            .obligations
            .iter()
            .any(|o| matches!(o, PolicyObligation::TaintReview { .. })));
    }

    #[test]
    fn default_deny_includes_no_match_reasons() {
        let eval = evaluate(
            &req("u", "a", "r"),
            &[Rule::for_tool("other", PolicyDecision::Permit)],
        );
        assert_eq!(eval.decision, PolicyDecision::Forbid);
        assert!(eval.reasons.is_empty());
        assert!(eval.detailed_reasons.is_empty());
    }

    #[test]
    fn obligations_are_deduped() {
        let mut request = req("u", "x", "r");
        request.context.budget = Some(BudgetHint {
            used: 1,
            limit: 1,
            exceeded: false,
        });
        let eval = evaluate(&request, &[]);
        let budget_count = eval
            .obligations
            .iter()
            .filter(|o| matches!(o, PolicyObligation::Budget { .. }))
            .count();
        assert_eq!(budget_count, 1);
    }

    #[test]
    fn policy_engine_abstractions() {
        let engine = StaticPolicyEngine::new(vec![Rule::permit_tool("read")]);
        let req = req("u", "read", "r");
        assert_eq!(engine.evaluate(&req).decision, PolicyDecision::Permit);
        assert_eq!(engine.authorize(&req).decision, PolicyDecision::Permit);
        assert_eq!(req.evaluate_with(&engine).decision, PolicyDecision::Permit);
    }
}
