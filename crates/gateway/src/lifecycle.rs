//! Gateway request lifecycle (M2/M3).
//!
//! Ordering: auth/verify -> budget+rate-limit hook -> policy -> taint -> approval -> broker inject ->
//! upstream placeholder -> audit append-before-return.
//!
//! Fail-closed: verification, limit, evaluation, injection, or audit failures deny.

use broker::{
    ApprovalQueue, ApprovalStatus, BrokerError, CredentialBroker, InjectedCredential,
    NoopCredentialBroker, SecretRef,
};
use scopegate_core::audit::{append_entry, verify_chain, AuditEntry};
use scopegate_core::policy::{
    evaluate, Action, BudgetHint, CallCountHint, Context, PolicyDecision, PolicyEvaluation,
    PolicyRequest, Principal, RateLimitHint, Resource, Rule, TaintHint,
};
use scopegate_core::rate_limit::InMemoryRateLimitTracker;
use scopegate_core::taint::{OperationTarget, SessionTaint, TaintDecision, TaintLabel};
use scopegate_core::token::{TaskToken, TokenError};

use crate::config::GatewayConfig;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    AuthVerify,
    BudgetRateLimit,
    Policy,
    Taint,
    Approval,
    Broker,
    Upstream,
    Audit,
    Denied,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GatewayError {
    AuthFailed(String),
    InvalidToken(String),
    BudgetOrRateLimited(String),
    PolicyDenied {
        reasons: Vec<String>,
        obligations: Vec<String>,
    },
    TaintBlocked,
    ApprovalDenied,
    Approval(BrokerError),
    Broker(BrokerError),
    AuditInvalid,
}

#[derive(Debug, Clone, Default)]
pub struct RequestHints {
    pub rate_limit: Option<RateLimitHint>,
    pub budget: Option<BudgetHint>,
    pub call_count: Option<CallCountHint>,
}

#[derive(Debug, Clone)]
pub struct InboundRequest {
    pub task_id: String,
    pub principal: String,
    pub action: String,
    pub resource: String,
    pub token: TaskToken,
    /// Target operation for taint evaluation (egress vs other).
    pub operation: OperationTarget,
    /// Pre-seeded taint labels for the session/request.
    pub taint_labels: Vec<TaintLabel>,
    pub secret: Option<SecretRef>,
    pub now: u64,
    pub approval_deadline: Option<u64>,
    /// Optional pre-resolved approval status for deterministic/non-interactive flows.
    /// If absent and approval is required, timeout semantics apply (deny).
    pub approval_resolution: Option<ApprovalStatus>,
    /// Budget/rate-limit/call-count hints evaluated by policy hooks and explicit gate.
    pub hints: RequestHints,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayOutcome {
    pub allowed: bool,
    pub stage: Stage,
    pub audit_verified: bool,
    pub audit_entries: usize,
    pub injected: Option<InjectedCredential>,
    pub error: Option<GatewayError>,
}

fn audit_decision(
    log: &mut Vec<AuditEntry>,
    req: &InboundRequest,
    decision: &str,
    reason: impl Into<String>,
    result_digest: &str,
) -> bool {
    append_entry(
        log,
        req.now,
        &req.task_id,
        &req.action,
        decision,
        reason,
        "args:redacted",
        result_digest,
    );
    verify_chain(log)
}

/// Backward-compatible entrypoint.
pub fn handle_request(
    req: &InboundRequest,
    rules: &[Rule],
    approvals: &mut ApprovalQueue,
    revoked_token_ids: &[&str],
) -> GatewayOutcome {
    let revoked: Vec<String> = revoked_token_ids.iter().map(|s| (*s).to_string()).collect();
    let config = GatewayConfig {
        rules: rules.to_vec(),
        revoked_token_ids: revoked,
        ..GatewayConfig::default()
    };
    handle_request_with_config(req, &config, approvals)
}

/// Runs full lifecycle with config.
pub fn handle_request_with_config(
    req: &InboundRequest,
    config: &GatewayConfig,
    approvals: &mut ApprovalQueue,
) -> GatewayOutcome {
    handle_request_with_hooks(req, config, approvals, None)
}

/// Like `handle_request_with_config` but allows an optional in-memory rate-limit/budget tracker hook.
pub fn handle_request_with_hooks(
    req: &InboundRequest,
    config: &GatewayConfig,
    approvals: &mut ApprovalQueue,
    rate_tracker: Option<&mut InMemoryRateLimitTracker>,
) -> GatewayOutcome {
    let mut log: Vec<AuditEntry> = Vec::new();
    let mut session_taint = SessionTaint::new();
    for label in &req.taint_labels {
        session_taint.add_label(*label);
    }

    // 1) auth verify
    if req.principal.trim().is_empty() {
        let _ = audit_decision(
            &mut log,
            req,
            "deny",
            "auth failed: empty principal",
            "auth_verify",
        );
        return deny(
            &log,
            Stage::Denied,
            GatewayError::AuthFailed("empty principal".into()),
            None,
        );
    }
    let revoked_refs: Vec<&str> = config
        .revoked_token_ids
        .iter()
        .map(|s| s.as_str())
        .collect();
    if let Err(e) = req.token.validate(req.now, &revoked_refs) {
        let _ = audit_decision(
            &mut log,
            req,
            "deny",
            format!("token invalid: {:?}", e),
            "auth_verify",
        );
        return deny(
            &log,
            Stage::Denied,
            GatewayError::InvalidToken(format!("{e:?}")),
            None,
        );
    }
    if config.require_token_scope_for_action && !req.token.allows_scope(&req.action) {
        let _ = audit_decision(
            &mut log,
            req,
            "deny",
            "token scope missing for action",
            "auth_verify",
        );
        return deny(
            &log,
            Stage::Denied,
            GatewayError::InvalidToken(format!(
                "{:?}",
                TokenError::ScopeNotSubset {
                    scope: req.action.clone()
                }
            )),
            None,
        );
    }
    if !audit_decision(&mut log, req, "allow", "auth/token verified", "auth_verify") {
        return deny(&log, Stage::Audit, GatewayError::AuditInvalid, None);
    }

    // 2) budget/rate-limit hook
    if let Some(reason) = exceeded_hint_reason(&req.hints) {
        let _ = audit_decision(&mut log, req, "deny", &reason, "budget_rate_limit");
        return deny(
            &log,
            Stage::Denied,
            GatewayError::BudgetOrRateLimited(reason),
            None,
        );
    }
    if let Some(tracker) = rate_tracker {
        let token_key = req.token.revocation_id.0.as_str();
        let units = req
            .hints
            .budget
            .as_ref()
            .map(|b| b.used.min(1))
            .unwrap_or(0);
        let limit_decision = tracker.consume(token_key, &req.action, req.now, units);
        if !limit_decision.is_allowed() {
            let reason = if limit_decision.reasons.is_empty() {
                "rate/budget tracker denied".to_string()
            } else {
                format!("tracker: {}", limit_decision.reasons.join(", "))
            };
            let _ = audit_decision(&mut log, req, "deny", &reason, "budget_rate_limit");
            return deny(
                &log,
                Stage::Denied,
                GatewayError::BudgetOrRateLimited(reason),
                None,
            );
        }
    }
    if !audit_decision(
        &mut log,
        req,
        "allow",
        "budget/rate-limit ok",
        "budget_rate_limit",
    ) {
        return deny(&log, Stage::Audit, GatewayError::AuditInvalid, None);
    }

    // 3) policy
    let taint_hint = if session_taint.labels().is_empty() {
        None
    } else {
        Some(TaintHint {
            labels: session_taint
                .label_names()
                .into_iter()
                .map(|s| s.to_string())
                .collect(),
            sensitive: session_taint.has_private_data() || session_taint.has_untrusted_content(),
        })
    };
    let policy_req = PolicyRequest {
        principal: Principal {
            id: req.principal.clone(),
        },
        action: Action {
            name: req.action.clone(),
        },
        resource: Resource {
            id: req.resource.clone(),
        },
        context: Context {
            approval: None,
            rate_limit: req.hints.rate_limit.clone(),
            budget: req.hints.budget.clone(),
            call_count: req.hints.call_count.clone(),
            taint: taint_hint,
        },
    };
    let policy_eval = evaluate(&policy_req, &config.rules);
    let policy_needs_approval = matches!(policy_eval.decision, PolicyDecision::RequireApproval);
    if matches!(policy_eval.decision, PolicyDecision::Forbid) {
        let _ = audit_decision(
            &mut log,
            req,
            "deny",
            policy_forbid_reason(&policy_eval),
            "policy",
        );
        return deny(
            &log,
            Stage::Denied,
            GatewayError::PolicyDenied {
                reasons: policy_eval.reasons.clone(),
                obligations: policy_eval
                    .obligations
                    .iter()
                    .map(|o| format!("{o:?}"))
                    .collect(),
            },
            None,
        );
    }
    if !audit_decision(
        &mut log,
        req,
        "allow",
        format!(
            "policy {:?} reasons={:?} obligations={:?}",
            policy_eval.decision, policy_eval.reasons, policy_eval.obligations
        ),
        "policy",
    ) {
        return deny(&log, Stage::Audit, GatewayError::AuditInvalid, None);
    }

    // 4) taint
    let taint_decision = if req.operation.is_external_egress() {
        session_taint.evaluate_egress_with(config.egress_policy)
    } else {
        session_taint.evaluate_target(&req.operation)
    };
    if matches!(taint_decision, TaintDecision::Block) {
        let _ = audit_decision(&mut log, req, "deny", "taint blocked", "taint");
        return deny(&log, Stage::Denied, GatewayError::TaintBlocked, None);
    }
    let taint_needs_approval = matches!(taint_decision, TaintDecision::RequireApproval);
    if !audit_decision(
        &mut log,
        req,
        "allow",
        format!(
            "taint {:?} labels={:?}",
            taint_decision,
            session_taint.label_names()
        ),
        "taint",
    ) {
        return deny(&log, Stage::Audit, GatewayError::AuditInvalid, None);
    }

    // 5) approval
    if policy_needs_approval || taint_needs_approval {
        let approval_id = format!("{}:{}", req.task_id, req.token.revocation_id.0);
        if approvals.get(&approval_id).is_none() {
            if let Err(e) = approvals.create(
                broker::ApprovalRequest {
                    id: approval_id.clone(),
                    principal: req.principal.clone(),
                    action: req.action.clone(),
                    resource: req.resource.clone(),
                    reason: Some("policy or taint requires approval".to_string()),
                },
                req.approval_deadline,
            ) {
                let _ = audit_decision(
                    &mut log,
                    req,
                    "deny",
                    format!("approval create failed: {:?}", e),
                    "approval",
                );
                return deny(&log, Stage::Denied, GatewayError::Approval(e), None);
            }
        }
        let status = if let Some(res) = req.approval_resolution {
            match approvals.resolve(&approval_id, res, req.now) {
                Ok(s) => s,
                Err(BrokerError::ApprovalAlreadyTerminal(_)) => approvals
                    .effective_status(&approval_id, req.now)
                    .unwrap_or(ApprovalStatus::Denied),
                Err(e) => {
                    let _ = audit_decision(
                        &mut log,
                        req,
                        "deny",
                        format!("approval resolve failed: {:?}", e),
                        "approval",
                    );
                    return deny(&log, Stage::Denied, GatewayError::Approval(e), None);
                }
            }
        } else {
            approvals.expire_timeouts(req.now);
            approvals
                .effective_status(&approval_id, req.now)
                .unwrap_or(ApprovalStatus::Denied)
        };
        if !status.allows() {
            let _ = audit_decision(
                &mut log,
                req,
                "deny",
                "approval not granted/timeout",
                "approval",
            );
            return deny(&log, Stage::Denied, GatewayError::ApprovalDenied, None);
        }
        if !audit_decision(&mut log, req, "allow", "approval granted", "approval") {
            return deny(&log, Stage::Audit, GatewayError::AuditInvalid, None);
        }
    } else if !audit_decision(&mut log, req, "allow", "approval not required", "approval") {
        return deny(&log, Stage::Audit, GatewayError::AuditInvalid, None);
    }

    // 6) broker inject
    let broker_impl = NoopCredentialBroker;
    let mut injected: Option<InjectedCredential> = None;
    if let Some(secret) = &req.secret {
        let mut target = String::new();
        match broker_impl.inject(&req.action, secret, &mut target) {
            Ok(meta) => {
                let _redacted_target = broker_impl.redact(&target);
                injected = Some(meta);
            }
            Err(e) => {
                let _ = audit_decision(
                    &mut log,
                    req,
                    "deny",
                    format!("broker inject failed: {:?}", e),
                    "broker",
                );
                return deny(&log, Stage::Denied, GatewayError::Broker(e), None);
            }
        }
    }
    if !audit_decision(
        &mut log,
        req,
        "allow",
        "credentials brokered/redacted",
        "broker",
    ) {
        return deny(&log, Stage::Audit, GatewayError::AuditInvalid, injected);
    }

    // 7) upstream placeholder
    let upstream_ok = true;
    if !upstream_ok {
        let _ = audit_decision(&mut log, req, "deny", "upstream failed", "upstream");
        return deny(
            &log,
            Stage::Denied,
            GatewayError::AuthFailed("upstream failed".into()),
            injected,
        );
    }
    if !audit_decision(
        &mut log,
        req,
        "allow",
        "upstream placeholder ok",
        "upstream",
    ) {
        return deny(&log, Stage::Audit, GatewayError::AuditInvalid, injected);
    }

    // 8) audit finalize
    let audit_verified = verify_chain(&log);
    if !audit_verified && config.fail_closed {
        return deny(&log, Stage::Audit, GatewayError::AuditInvalid, injected);
    }
    GatewayOutcome {
        allowed: true,
        stage: Stage::Audit,
        audit_verified: verify_chain(&log),
        audit_entries: log.len(),
        injected,
        error: None,
    }
}

fn exceeded_hint_reason(hints: &RequestHints) -> Option<String> {
    if hints.rate_limit.as_ref().is_some_and(|h| h.is_exceeded()) {
        return Some("rate limit exceeded".into());
    }
    if hints.budget.as_ref().is_some_and(|h| h.is_exceeded()) {
        return Some("budget exceeded".into());
    }
    if hints.call_count.as_ref().is_some_and(|h| h.is_exceeded()) {
        return Some("call count exceeded".into());
    }
    None
}

fn policy_forbid_reason(eval: &PolicyEvaluation) -> String {
    if eval.reasons.is_empty() {
        "policy forbid".to_string()
    } else {
        format!("policy forbid: {}", eval.reasons.join("; "))
    }
}

fn deny(
    log: &[AuditEntry],
    stage: Stage,
    error: GatewayError,
    injected: Option<InjectedCredential>,
) -> GatewayOutcome {
    GatewayOutcome {
        allowed: false,
        stage,
        audit_verified: verify_chain(log),
        audit_entries: log.len(),
        injected,
        error: Some(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use scopegate_core::token::{Budget, Expiry, RevocationId, Scope, TaskToken};

    fn base_req() -> InboundRequest {
        InboundRequest {
            task_id: "task-1".into(),
            principal: "agent".into(),
            action: "tool.invoke".into(),
            resource: "tool".into(),
            token: TaskToken {
                revocation_id: RevocationId("rev-1".into()),
                scopes: vec![Scope("tool.invoke".into())],
                budget: Budget { max_calls: Some(1) },
                expires_at: Some(Expiry(100)),
                attenuation: None,
            },
            operation: OperationTarget::other("local"),
            taint_labels: vec![],
            secret: Some(SecretRef("secret://s".into())),
            now: 1,
            approval_deadline: Some(10),
            approval_resolution: Some(ApprovalStatus::Approved),
            hints: RequestHints::default(),
        }
    }

    fn permit_rules() -> Vec<Rule> {
        vec![Rule::exact(
            "agent",
            "tool.invoke",
            "tool",
            PolicyDecision::Permit,
        )]
    }

    #[test]
    fn happy_path_runs_full_ordering_and_audits() {
        let req = base_req();
        let mut approvals = ApprovalQueue::new();
        let out = handle_request(&req, &permit_rules(), &mut approvals, &[]);
        assert!(out.allowed);
        assert_eq!(out.stage, Stage::Audit);
        assert!(out.audit_verified);
        assert!(out.audit_entries >= 7); // auth+budget+policy+taint+approval+broker+upstream
        assert!(out.injected.is_some());
        assert_eq!(out.injected.unwrap().redacted, "[REDACTED]");
    }

    #[test]
    fn invalid_token_fails_closed() {
        let mut req = base_req();
        req.token.expires_at = Some(Expiry(1));
        let mut approvals = ApprovalQueue::new();
        let out = handle_request(&req, &permit_rules(), &mut approvals, &[]);
        assert!(!out.allowed);
        assert!(matches!(out.error, Some(GatewayError::InvalidToken(_))));
    }

    #[test]
    fn taint_conflict_requires_approval_and_timeout_denies() {
        let mut req = base_req();
        req.operation = OperationTarget::ExternalEgress;
        req.taint_labels = vec![TaintLabel::UntrustedContent, TaintLabel::PrivateData];
        req.approval_deadline = Some(1);
        req.approval_resolution = None;
        let mut approvals = ApprovalQueue::new();
        let out = handle_request(&req, &permit_rules(), &mut approvals, &[]);
        assert!(!out.allowed);
        assert!(matches!(out.error, Some(GatewayError::ApprovalDenied)));
    }

    #[test]
    fn budget_or_rate_limit_hint_fails_closed() {
        let mut req = base_req();
        req.hints.rate_limit = Some(RateLimitHint {
            calls_in_window: 5,
            limit: 5,
            exceeded: false,
        });
        let mut approvals = ApprovalQueue::new();
        let out = handle_request(&req, &permit_rules(), &mut approvals, &[]);
        assert!(!out.allowed);
        assert!(matches!(
            out.error,
            Some(GatewayError::BudgetOrRateLimited(_))
        ));
    }

    #[test]
    fn rate_limit_tracker_hook_fails_closed_and_records() {
        let req = base_req();
        let config = GatewayConfig::default().with_rules(permit_rules());
        let mut approvals = ApprovalQueue::new();
        let mut tracker = scopegate_core::rate_limit::InMemoryRateLimitTracker::new(
            scopegate_core::rate_limit::Limits {
                per_token_call_limit: Some(1),
                ..scopegate_core::rate_limit::Limits::default()
            },
        );
        let ok = handle_request_with_hooks(&req, &config, &mut approvals, Some(&mut tracker));
        assert!(ok.allowed);
        let mut approvals2 = ApprovalQueue::new();
        let denied = handle_request_with_hooks(&req, &config, &mut approvals2, Some(&mut tracker));
        assert!(!denied.allowed);
        assert!(matches!(
            denied.error,
            Some(GatewayError::BudgetOrRateLimited(_))
        ));
    }

    #[test]
    fn auth_fails_closed_on_missing_scope_for_action() {
        let mut req = base_req();
        req.token.scopes = vec![Scope("other.action".into())];
        let mut approvals = ApprovalQueue::new();
        let out = handle_request(&req, &permit_rules(), &mut approvals, &[]);
        assert!(!out.allowed);
        assert!(matches!(out.error, Some(GatewayError::InvalidToken(_))));
    }

    #[test]
    fn config_controls_revocation_and_egress_policy() {
        let mut req = base_req();
        req.operation = OperationTarget::ExternalEgress;
        req.taint_labels = vec![TaintLabel::UntrustedContent, TaintLabel::PrivateData];
        let config = GatewayConfig::default()
            .with_rules(permit_rules())
            .with_egress_policy(scopegate_core::taint::EgressPolicy::BlockOnConflict);
        let mut approvals = ApprovalQueue::new();
        let out = handle_request_with_config(&req, &config, &mut approvals);
        assert!(!out.allowed);
        assert!(matches!(out.error, Some(GatewayError::TaintBlocked)));
    }
}
