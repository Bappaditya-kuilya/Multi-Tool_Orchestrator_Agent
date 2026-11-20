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
use store::AuditEvent as StoreAuditEvent;

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

/// Build a deterministic, redacted request args digest for audit metadata.
pub fn request_args_digest(req: &InboundRequest) -> String {
    let mut labels = req
        .taint_labels
        .iter()
        .map(|l| format!("{l:?}"))
        .collect::<Vec<_>>();
    labels.sort();
    let hints = format!(
        "rl={}|b={}|cc={}",
        req.hints.rate_limit.is_some(),
        req.hints.budget.is_some(),
        req.hints.call_count.is_some()
    );
    let payload = format!(
        "task={}|principal={}|action={}|resource={}|rev={}|op={}|taint=[{}]|secret={}|hints={}",
        req.task_id,
        req.principal,
        req.action,
        req.resource,
        req.token.revocation_id.0,
        req.operation.as_str(),
        labels.join(","),
        req.secret.is_some(),
        hints
    );
    scopegate_core::audit::digest(&payload)
}

/// Build a deterministic stage result digest for audit metadata.
pub fn stage_result_digest(stage: &str, decision: &str, detail: &str) -> String {
    scopegate_core::audit::digest(&format!(
        "stage={stage}|decision={decision}|detail={detail}"
    ))
}

/// Convert an in-memory lifecycle audit entry into a durable store audit event payload.
/// Store implementations assign sequence/hash chain fields during append.
pub fn to_store_audit_event(entry: &AuditEntry) -> StoreAuditEvent {
    StoreAuditEvent {
        seq: 0,
        ts: entry.ts.to_string(),
        task_id: (!entry.task_id.is_empty()).then(|| entry.task_id.clone()),
        tool: (!entry.tool.is_empty()).then(|| entry.tool.clone()),
        decision: entry.decision.clone(),
        reason: (!entry.reason.is_empty()).then(|| entry.reason.clone()),
        args_digest: (!entry.args_digest.is_empty()).then(|| entry.args_digest.clone()),
        result_digest: (!entry.result_digest.is_empty()).then(|| entry.result_digest.clone()),
        prev_hash: None,
        hash: None,
    }
}

/// Fail-closed outcome helper for durable audit persistence failures (append-before-return).
pub fn audit_persistence_denied(log: &[AuditEntry], detail: impl Into<String>) -> GatewayOutcome {
    deny(log, Stage::Audit, GatewayError::AuditInvalid, None).with_error_detail(detail)
}

/// Fail-closed outcome helper for store/runtime integration failures outside lifecycle internals.
/// Preserves API-compatible structured errors for callers; details are expected in audit/logging.
pub fn runtime_integration_denied(
    log: &[AuditEntry],
    stage: Stage,
    detail: impl Into<String>,
) -> GatewayOutcome {
    deny(
        log,
        stage,
        GatewayError::BudgetOrRateLimited(detail.into()),
        None,
    )
}

impl GatewayOutcome {
    pub fn denied_with_error(mut self, error: GatewayError) -> Self {
        self.allowed = false;
        self.error = Some(error);
        self
    }

    pub fn with_error_detail(self, _detail: impl Into<String>) -> Self {
        // Preserve structured error compatibility; details are expected to be recorded in audit/logging.
        self
    }
}

fn audit_decision(
    log: &mut Vec<AuditEntry>,
    req: &InboundRequest,
    stage: &str,
    decision: &str,
    reason: impl Into<String>,
) -> bool {
    let reason = reason.into();
    append_entry(
        log,
        req.now,
        &req.task_id,
        &req.action,
        decision,
        &reason,
        request_args_digest(req),
        stage_result_digest(stage, decision, &reason),
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
    handle_request_with_hooks_and_log(req, config, approvals, rate_tracker).0
}

/// Runs the lifecycle and returns both the outcome and the in-memory hash-chained audit log.
/// Useful for durable/store-backed audit persistence hooks and fail-closed verification flows.
pub fn handle_request_with_hooks_and_log(
    req: &InboundRequest,
    config: &GatewayConfig,
    approvals: &mut ApprovalQueue,
    rate_tracker: Option<&mut InMemoryRateLimitTracker>,
) -> (GatewayOutcome, Vec<AuditEntry>) {
    let mut log: Vec<AuditEntry> = Vec::new();
    let mut session_taint = SessionTaint::new();
    for label in &req.taint_labels {
        session_taint.add_label(*label);
    }

    // 1) auth verify
    if req.principal.trim().is_empty() {
        if !audit_decision(
            &mut log,
            req,
            "auth_verify",
            "deny",
            "auth failed: empty principal",
        ) {
            return (
                deny(&log, Stage::Audit, GatewayError::AuditInvalid, None),
                log,
            );
        }
        return (
            deny(
                &log,
                Stage::Denied,
                GatewayError::AuthFailed("empty principal".into()),
                None,
            ),
            log,
        );
    }
    let revoked_refs: Vec<&str> = config
        .revoked_token_ids
        .iter()
        .map(|s| s.as_str())
        .collect();
    if let Err(e) = req.token.validate(req.now, &revoked_refs) {
        if !audit_decision(
            &mut log,
            req,
            "auth_verify",
            "deny",
            format!("token invalid: {:?}", e),
        ) {
            return (
                deny(&log, Stage::Audit, GatewayError::AuditInvalid, None),
                log,
            );
        }
        return (
            deny(
                &log,
                Stage::Denied,
                GatewayError::InvalidToken(format!("{e:?}")),
                None,
            ),
            log,
        );
    }
    if config.require_token_scope_for_action && !req.token.allows_scope(&req.action) {
        if !audit_decision(
            &mut log,
            req,
            "auth_verify",
            "deny",
            "token scope missing for action",
        ) {
            return (
                deny(&log, Stage::Audit, GatewayError::AuditInvalid, None),
                log,
            );
        }
        return (
            deny(
                &log,
                Stage::Denied,
                GatewayError::InvalidToken(format!(
                    "{:?}",
                    TokenError::ScopeNotSubset {
                        scope: req.action.clone()
                    }
                )),
                None,
            ),
            log,
        );
    }
    if !audit_decision(
        &mut log,
        req,
        "auth_verify",
        "allow",
        format!("auth/token verified rev={}", req.token.revocation_id.0),
    ) {
        return (
            deny(&log, Stage::Audit, GatewayError::AuditInvalid, None),
            log,
        );
    }

    // 2) budget/rate-limit hook
    if let Some(reason) = exceeded_hint_reason(&req.hints) {
        if !audit_decision(&mut log, req, "budget_rate_limit", "deny", &reason) {
            return (
                deny(&log, Stage::Audit, GatewayError::AuditInvalid, None),
                log,
            );
        }
        return (
            deny(
                &log,
                Stage::Denied,
                GatewayError::BudgetOrRateLimited(reason),
                None,
            ),
            log,
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
            if !audit_decision(&mut log, req, "budget_rate_limit", "deny", &reason) {
                return (
                    deny(&log, Stage::Audit, GatewayError::AuditInvalid, None),
                    log,
                );
            }
            return (
                deny(
                    &log,
                    Stage::Denied,
                    GatewayError::BudgetOrRateLimited(reason),
                    None,
                ),
                log,
            );
        }
    }
    if !audit_decision(
        &mut log,
        req,
        "budget_rate_limit",
        "allow",
        "budget/rate-limit ok",
    ) {
        return (
            deny(&log, Stage::Audit, GatewayError::AuditInvalid, None),
            log,
        );
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
            args: None,
        },
    };
    let policy_eval = evaluate(&policy_req, &config.rules);
    let policy_needs_approval = matches!(policy_eval.decision, PolicyDecision::RequireApproval);
    if matches!(policy_eval.decision, PolicyDecision::Forbid) {
        if !audit_decision(
            &mut log,
            req,
            "policy",
            "deny",
            policy_forbid_reason(&policy_eval),
        ) {
            return (
                deny(&log, Stage::Audit, GatewayError::AuditInvalid, None),
                log,
            );
        }
        return (
            deny(
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
            ),
            log,
        );
    }
    if !audit_decision(
        &mut log,
        req,
        "policy",
        "allow",
        format!(
            "policy {:?} reasons={:?} obligations={:?}",
            policy_eval.decision, policy_eval.reasons, policy_eval.obligations
        ),
    ) {
        return (
            deny(&log, Stage::Audit, GatewayError::AuditInvalid, None),
            log,
        );
    }

    // 4) taint
    let taint_decision = if req.operation.is_external_egress() {
        session_taint.evaluate_egress_with(config.egress_policy)
    } else {
        session_taint.evaluate_target(&req.operation)
    };
    if matches!(taint_decision, TaintDecision::Block) {
        if !audit_decision(&mut log, req, "taint", "deny", "taint blocked") {
            return (
                deny(&log, Stage::Audit, GatewayError::AuditInvalid, None),
                log,
            );
        }
        return (
            deny(&log, Stage::Denied, GatewayError::TaintBlocked, None),
            log,
        );
    }
    let taint_needs_approval = matches!(taint_decision, TaintDecision::RequireApproval);
    if !audit_decision(
        &mut log,
        req,
        "taint",
        "allow",
        format!(
            "taint {:?} labels={:?}",
            taint_decision,
            session_taint.label_names()
        ),
    ) {
        return (
            deny(&log, Stage::Audit, GatewayError::AuditInvalid, None),
            log,
        );
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
                if !audit_decision(
                    &mut log,
                    req,
                    "approval",
                    "deny",
                    format!("approval create failed: {:?}", e),
                ) {
                    return (
                        deny(&log, Stage::Audit, GatewayError::AuditInvalid, None),
                        log,
                    );
                }
                return (
                    deny(&log, Stage::Denied, GatewayError::Approval(e), None),
                    log,
                );
            }
        }
        let status = if let Some(res) = req.approval_resolution {
            match approvals.resolve(&approval_id, res, req.now) {
                Ok(s) => s,
                Err(BrokerError::ApprovalAlreadyTerminal(_)) => approvals
                    .effective_status(&approval_id, req.now)
                    .unwrap_or(ApprovalStatus::Denied),
                Err(e) => {
                    if !audit_decision(
                        &mut log,
                        req,
                        "approval",
                        "deny",
                        format!("approval resolve failed: {:?}", e),
                    ) {
                        return (
                            deny(&log, Stage::Audit, GatewayError::AuditInvalid, None),
                            log,
                        );
                    }
                    return (
                        deny(&log, Stage::Denied, GatewayError::Approval(e), None),
                        log,
                    );
                }
            }
        } else {
            approvals.expire_timeouts(req.now);
            approvals
                .effective_status(&approval_id, req.now)
                .unwrap_or(ApprovalStatus::Denied)
        };
        if !status.allows() {
            if !audit_decision(
                &mut log,
                req,
                "approval",
                "deny",
                format!("approval not granted/timeout id={approval_id} status={status:?}"),
            ) {
                return (
                    deny(&log, Stage::Audit, GatewayError::AuditInvalid, None),
                    log,
                );
            }
            return (
                deny(&log, Stage::Denied, GatewayError::ApprovalDenied, None),
                log,
            );
        }
        if !audit_decision(
            &mut log,
            req,
            "approval",
            "allow",
            format!("approval granted id={approval_id}"),
        ) {
            return (
                deny(&log, Stage::Audit, GatewayError::AuditInvalid, None),
                log,
            );
        }
    } else if !audit_decision(&mut log, req, "approval", "allow", "approval not required") {
        return (
            deny(&log, Stage::Audit, GatewayError::AuditInvalid, None),
            log,
        );
    }

    // 6) broker inject
    let broker_impl = NoopCredentialBroker;
    let mut injected: Option<InjectedCredential> = None;
    let mut broker_audit_detail = "credentials brokered/redacted".to_string();
    if let Some(secret) = &req.secret {
        if config.runtime_hooks.enable_broker_injection {
            let mut target = String::new();
            match broker_impl.inject(&req.action, secret, &mut target) {
                Ok(meta) => {
                    let _redacted_target = broker_impl.redact(&target);
                    injected = Some(meta);
                }
                Err(e) => {
                    if !audit_decision(
                        &mut log,
                        req,
                        "broker",
                        "deny",
                        format!("broker inject failed: {:?}", e),
                    ) {
                        return (
                            deny(&log, Stage::Audit, GatewayError::AuditInvalid, None),
                            log,
                        );
                    }
                    return (
                        deny(&log, Stage::Denied, GatewayError::Broker(e), None),
                        log,
                    );
                }
            }
        } else {
            broker_audit_detail = "broker injection disabled by config".to_string();
        }
    }
    if !audit_decision(&mut log, req, "broker", "allow", broker_audit_detail) {
        return (
            deny(&log, Stage::Audit, GatewayError::AuditInvalid, injected),
            log,
        );
    }

    // 7) upstream placeholder
    let upstream_ok = true;
    if !upstream_ok {
        if !audit_decision(&mut log, req, "upstream", "deny", "upstream failed") {
            return (
                deny(
                    &log,
                    Stage::Audit,
                    GatewayError::AuditInvalid,
                    injected.clone(),
                ),
                log,
            );
        }
        return (
            deny(
                &log,
                Stage::Denied,
                GatewayError::AuthFailed("upstream failed".into()),
                injected,
            ),
            log,
        );
    }
    if !audit_decision(
        &mut log,
        req,
        "upstream",
        "allow",
        "upstream placeholder ok",
    ) {
        return (
            deny(&log, Stage::Audit, GatewayError::AuditInvalid, injected),
            log,
        );
    }

    // 8) audit finalize
    let audit_verified = verify_chain(&log);
    if !audit_verified && config.fail_closed {
        return (
            deny(&log, Stage::Audit, GatewayError::AuditInvalid, injected),
            log,
        );
    }
    (
        GatewayOutcome {
            allowed: true,
            stage: Stage::Audit,
            audit_verified: verify_chain(&log),
            audit_entries: log.len(),
            injected,
            error: None,
        },
        log,
    )
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

    #[test]
    fn request_args_digest_is_redacted_and_deterministic() {
        let mut req = base_req();
        req.secret = Some(SecretRef("secret://super-sensitive".into()));
        let d1 = request_args_digest(&req);
        let d2 = request_args_digest(&req);
        assert_eq!(d1, d2);
        assert_ne!(d1, "args:redacted");
        assert!(!d1.contains("super-sensitive"));
        req.action = "other.action".into();
        assert_ne!(d1, request_args_digest(&req));
    }

    #[test]
    fn audit_log_exposes_richer_metadata_for_durable_hooks() {
        let req = base_req();
        let config = GatewayConfig::default().with_rules(permit_rules());
        let mut approvals = ApprovalQueue::new();
        let (out, log) = handle_request_with_hooks_and_log(&req, &config, &mut approvals, None);
        assert!(out.allowed);
        assert!(verify_chain(&log));
        assert!(log.iter().all(|e| e.args_digest != "args:redacted"));
        assert!(log.iter().all(|e| e.digests_well_formed()));
        assert!(log
            .iter()
            .any(|e| e.decision == "allow" && e.reason.contains("auth/token verified rev=rev-1")));
    }

    #[test]
    fn denied_paths_still_return_verified_audit_log() {
        let mut req = base_req();
        req.hints.rate_limit = Some(RateLimitHint {
            calls_in_window: 10,
            limit: 1,
            exceeded: false,
        });
        let config = GatewayConfig::default().with_rules(permit_rules());
        let mut approvals = ApprovalQueue::new();
        let (out, log) = handle_request_with_hooks_and_log(&req, &config, &mut approvals, None);
        assert!(!out.allowed);
        assert!(out.audit_verified);
        assert!(verify_chain(&log));
        assert!(log
            .iter()
            .any(|e| e.decision == "deny" && e.reason.contains("rate limit exceeded")));
    }

    #[test]
    fn store_audit_event_conversion_preserves_core_fields() {
        let req = base_req();
        let config = GatewayConfig::default().with_rules(permit_rules());
        let mut approvals = ApprovalQueue::new();
        let (_out, log) = handle_request_with_hooks_and_log(&req, &config, &mut approvals, None);
        let first = &log[0];
        let ev = to_store_audit_event(first);
        assert_eq!(ev.ts, first.ts.to_string());
        assert_eq!(ev.task_id.as_deref(), Some(first.task_id.as_str()));
        assert_eq!(ev.tool.as_deref(), Some(first.tool.as_str()));
        assert_eq!(ev.decision, first.decision);
        assert!(ev.seq == 0 && ev.prev_hash.is_none() && ev.hash.is_none());
    }

    #[test]
    fn broker_injection_can_be_disabled_by_runtime_hook() {
        let req = base_req();
        let mut config = GatewayConfig::default().with_rules(permit_rules());
        config.runtime_hooks.enable_broker_injection = false;
        let mut approvals = ApprovalQueue::new();
        let (out, log) = handle_request_with_hooks_and_log(&req, &config, &mut approvals, None);
        assert!(out.allowed);
        assert!(out.injected.is_none());
        assert!(
            log.iter()
                .any(|e| e.reason.contains("broker injection disabled by config")),
            "broker disable audit reason missing; entries: {:?}",
            log.iter()
                .map(|e| (e.tool.clone(), e.decision.clone(), e.reason.clone()))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn audit_persistence_denied_is_fail_closed_and_api_compatible() {
        let req = base_req();
        let config = GatewayConfig::default().with_rules(permit_rules());
        let mut approvals = ApprovalQueue::new();
        let (_, log) = handle_request_with_hooks_and_log(&req, &config, &mut approvals, None);
        assert!(verify_chain(&log));
        let out = audit_persistence_denied(&log, "store append failed");
        assert!(!out.allowed);
        assert_eq!(out.stage, Stage::Audit);
        assert_eq!(out.audit_entries, log.len());
        assert!(out.audit_verified);
        assert!(matches!(out.error, Some(GatewayError::AuditInvalid)));
    }

    #[test]
    fn runtime_integration_denied_preserves_stage_and_structured_error() {
        let req = base_req();
        let config = GatewayConfig::default().with_rules(permit_rules());
        let mut approvals = ApprovalQueue::new();
        let (_, log) = handle_request_with_hooks_and_log(&req, &config, &mut approvals, None);
        let out = runtime_integration_denied(&log, Stage::Approval, "approval store unavailable");
        assert!(!out.allowed);
        assert_eq!(out.stage, Stage::Approval);
        assert!(out.audit_verified);
        assert!(matches!(
            out.error,
            Some(GatewayError::BudgetOrRateLimited(ref msg)) if msg == "approval store unavailable"
        ));
    }

    #[test]
    fn policy_forbid_denies_fail_closed_with_verified_audit() {
        let req = base_req();
        let rules = vec![Rule::exact(
            "agent",
            "tool.invoke",
            "tool",
            PolicyDecision::Forbid,
        )];
        let config = GatewayConfig::default().with_rules(rules);
        let mut approvals = ApprovalQueue::new();
        let (out, log) = handle_request_with_hooks_and_log(&req, &config, &mut approvals, None);
        assert!(!out.allowed);
        assert_eq!(out.stage, Stage::Denied);
        assert!(out.audit_verified);
        assert!(verify_chain(&log));
        assert!(matches!(out.error, Some(GatewayError::PolicyDenied { .. })));
        assert!(log.iter().any(|e| {
            e.tool == req.action && e.decision == "deny" && e.reason.contains("policy forbid")
        }));
    }

    #[test]
    fn revoked_token_denies_fail_closed() {
        let req = base_req();
        let mut config = GatewayConfig::default().with_rules(permit_rules());
        config.revoked_token_ids = vec![req.token.revocation_id.0.clone()];
        let mut approvals = ApprovalQueue::new();
        let (out, log) = handle_request_with_hooks_and_log(&req, &config, &mut approvals, None);
        assert!(!out.allowed);
        assert_eq!(out.stage, Stage::Denied);
        assert!(matches!(out.error, Some(GatewayError::InvalidToken(_))));
        assert!(out.audit_verified);
        assert!(scopegate_core::audit::verify_chain(&log));
        assert!(log.iter().any(|e| {
            e.tool == req.action && e.decision == "deny" && e.reason.contains("token invalid")
        }));
    }

    #[test]
    fn policy_require_approval_allows_with_explicit_resolution_and_preserves_audit_log() {
        let req = base_req();
        let rules = vec![scopegate_core::policy::Rule::exact(
            "agent",
            "tool.invoke",
            "tool",
            scopegate_core::policy::PolicyDecision::RequireApproval,
        )];
        let config = GatewayConfig::default().with_rules(rules);
        let mut approvals = ApprovalQueue::new();
        let (out, log) = handle_request_with_hooks_and_log(&req, &config, &mut approvals, None);
        assert!(out.allowed, "expected allow, got {out:?}");
        assert_eq!(out.stage, Stage::Audit);
        assert!(out.audit_verified);
        assert!(out.error.is_none());
        assert!(scopegate_core::audit::verify_chain(&log));
        assert!(log.iter().any(|e| {
            e.tool == req.action
                && e.decision == "allow"
                && e.reason.contains("policy RequireApproval")
        }));
        assert!(log.iter().any(|e| {
            e.tool == req.action && e.decision == "allow" && e.reason.contains("approval granted")
        }));
        for e in &log {
            let ev = to_store_audit_event(e);
            assert_eq!(ev.decision, e.decision);
            assert_eq!(ev.task_id.as_deref(), Some(e.task_id.as_str()));
            assert_eq!(ev.tool.as_deref(), Some(e.tool.as_str()));
        }
    }

    #[test]
    fn policy_require_approval_timeout_denies_fail_closed() {
        let mut req = base_req();
        req.approval_resolution = None;
        req.approval_deadline = Some(1);
        req.now = 2;
        let rules = vec![scopegate_core::policy::Rule::exact(
            "agent",
            "tool.invoke",
            "tool",
            scopegate_core::policy::PolicyDecision::RequireApproval,
        )];
        let config = GatewayConfig::default().with_rules(rules);
        let mut approvals = ApprovalQueue::new();
        let (out, log) = handle_request_with_hooks_and_log(&req, &config, &mut approvals, None);
        assert!(!out.allowed);
        assert_eq!(out.stage, Stage::Denied);
        assert!(matches!(out.error, Some(GatewayError::ApprovalDenied)));
        assert!(out.audit_verified);
        assert!(scopegate_core::audit::verify_chain(&log));
        assert!(log.iter().any(|e| {
            e.tool == req.action
                && e.decision == "deny"
                && e.reason.contains("approval not granted/timeout")
        }));
    }

    #[test]
    fn taint_require_approval_on_conflict_allows_when_explicitly_approved() {
        let mut req = base_req();
        req.operation = scopegate_core::taint::OperationTarget::ExternalEgress;
        req.taint_labels = vec![
            scopegate_core::taint::TaintLabel::UntrustedContent,
            scopegate_core::taint::TaintLabel::PrivateData,
        ];
        req.approval_resolution = Some(ApprovalStatus::Approved);
        let config = GatewayConfig::default()
            .with_rules(permit_rules())
            .with_egress_policy(scopegate_core::taint::EgressPolicy::RequireApprovalOnConflict);
        let mut approvals = ApprovalQueue::new();
        let (out, log) = handle_request_with_hooks_and_log(&req, &config, &mut approvals, None);
        assert!(out.allowed, "expected allow, got {out:?}");
        assert_eq!(out.stage, Stage::Audit);
        assert!(out.audit_verified);
        assert!(scopegate_core::audit::verify_chain(&log));
        assert!(log.iter().any(|e| {
            e.tool == req.action
                && e.decision == "allow"
                && e.reason.contains("taint RequireApproval")
        }));
        assert!(log.iter().any(|e| {
            e.tool == req.action && e.decision == "allow" && e.reason.contains("approval granted")
        }));
    }

    #[test]
    fn rate_limit_hint_denial_records_budget_rate_stage_audit_for_persistence() {
        let mut req = base_req();
        req.hints.rate_limit = Some(scopegate_core::policy::RateLimitHint {
            calls_in_window: 10,
            limit: 1,
            exceeded: false,
        });
        let config = GatewayConfig::default().with_rules(permit_rules());
        let mut approvals = ApprovalQueue::new();
        let (out, log) = handle_request_with_hooks_and_log(&req, &config, &mut approvals, None);
        assert!(!out.allowed);
        assert_eq!(out.stage, Stage::Denied);
        assert!(matches!(
            out.error,
            Some(GatewayError::BudgetOrRateLimited(_))
        ));
        assert!(out.audit_verified);
        assert!(scopegate_core::audit::verify_chain(&log));
        assert!(log.iter().any(|e| {
            e.tool == req.action && e.decision == "deny" && e.reason.contains("rate limit exceeded")
        }));
        assert!(log.iter().all(|e| to_store_audit_event(e).seq == 0));
    }
}
