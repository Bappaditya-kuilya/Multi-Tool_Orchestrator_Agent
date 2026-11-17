use core::{
    append_entry, context_hooks_detailed, evaluate, inspect_chain, verify_chain, Action,
    ApprovalAnnotation, Attenuation, Budget, BudgetHint, Context, EgressPolicy, Expiry,
    InMemoryRateLimitTracker, LimitDecision, Limits, OperationTarget, PolicyDecision,
    PolicyRequest, Principal, RateLimitHint, Resource, RevocationId, Rule, Scope, SessionTaint,
    TaintDecision, TaintHint, TaintLabel, TaskToken, TokenError, WindowLimit,
};

#[test]
fn token_to_policy_budget_hook_integration() {
    let mut token = TaskToken {
        revocation_id: RevocationId::from("root"),
        scopes: vec![Scope::from("tool:deploy")],
        budget: Budget::limited(1),
        expires_at: Some(Expiry(100)),
        attenuation: None,
    };
    token.validate(10, &[]).expect("valid token");
    token.consume_call().expect("consume one call");
    assert_eq!(token.remaining_calls(), Some(0));

    let budget_hint = BudgetHint {
        used: 1,
        limit: 1,
        exceeded: false,
    }
    .normalize();

    let req = PolicyRequest {
        principal: Principal::new("agent"),
        action: Action::new("tool:deploy"),
        resource: Resource::new("svc"),
        context: Context::default().with_budget(budget_hint),
    };
    let eval = evaluate(
        &req,
        &[Rule::for_tool("tool:deploy", PolicyDecision::Permit)],
    );
    assert_eq!(eval.decision, PolicyDecision::RequireApproval);
    assert!(eval.reasons.iter().any(|r| r.contains("budget")));
}

#[test]
fn taint_policy_and_egress_policy_align() {
    let mut req = PolicyRequest::new("agent", "egress", "external");
    req.context.taint = Some(TaintHint {
        labels: vec!["untrusted".into(), "pii".into()],
        sensitive: true,
    });
    let hooks = context_hooks_detailed(&req);
    assert!(hooks.iter().any(|(_, r, _)| r.code == "taint_sensitive"));

    let eval = evaluate(&req, &[Rule::for_tool("egress", PolicyDecision::Permit)]);
    assert_eq!(eval.decision, PolicyDecision::RequireApproval);

    let taint = SessionTaint::new()
        .with_label(TaintLabel::UntrustedContent)
        .with_label(TaintLabel::PrivateData);
    assert_eq!(
        taint.evaluate_target_with(
            &OperationTarget::ExternalEgress,
            EgressPolicy::BlockOnConflict
        ),
        TaintDecision::Block
    );
    assert_eq!(
        taint.evaluate_target(&OperationTarget::ExternalEgress),
        TaintDecision::RequireApproval
    );
}

#[test]
fn rate_limit_hints_feed_policy_and_audit_chain() {
    let mut tracker = InMemoryRateLimitTracker::new(Limits {
        per_token_tool_window: Some(WindowLimit {
            max_calls: 1,
            window_secs: 60,
        }),
        ..Limits::default()
    });
    let first: LimitDecision = tracker.consume("tok", "search", 10, 0);
    assert!(first.is_allowed());
    let second = tracker.check("tok", "search", 20, 0);
    assert_eq!(second.decision, PolicyDecision::RequireApproval);
    let hint: RateLimitHint = second.rate_limit.clone().expect("rate hint");

    let req = PolicyRequest::new("tok", "search", "index").normalized_limits();
    let mut req = req;
    req.context.rate_limit = Some(hint.normalize());
    let eval = evaluate(&req, &[Rule::for_tool("search", PolicyDecision::Permit)]);
    assert_eq!(eval.decision, PolicyDecision::RequireApproval);

    let mut log = Vec::new();
    append_entry(
        &mut log,
        10,
        "task-1",
        "search",
        "allow",
        "first call",
        core::digest("a1"),
        core::digest("r1"),
    );
    append_entry(
        &mut log,
        20,
        "task-1",
        "search",
        "require_approval",
        "rate limited",
        core::digest("a2"),
        core::digest("r2"),
    );
    assert!(verify_chain(&log));
    let summary = inspect_chain(&log);
    assert!(summary.valid);
    assert_eq!(summary.length, 2);
    assert_eq!(summary.malformed_digest_count, 0);
}

#[test]
fn token_attenuation_preserves_narrowing_and_policy_permit() {
    let parent = TaskToken {
        revocation_id: RevocationId::from("parent"),
        scopes: vec![Scope::from("fs.read"), Scope::from("fs.write")],
        budget: Budget::limited(5),
        expires_at: Some(Expiry(1000)),
        attenuation: None,
    };
    let child = parent
        .attenuate(
            Attenuation {
                scopes: vec![Scope::from("fs.read")],
                budget: Budget::limited(2),
                expires_at: Some(Expiry(500)),
            },
            RevocationId::from("child"),
            0,
        )
        .expect("attenuate");

    assert!(child.allows_scope("fs.read"));
    assert!(!child.allows_scope("fs.write"));

    let req = PolicyRequest {
        principal: Principal::new("child"),
        action: Action::new("fs.read"),
        resource: Resource::new("file:/a"),
        context: Context::with_approval(Some(ApprovalAnnotation {
            approved_by: Some("user".into()),
            reason: Some("ok".into()),
        })),
    };
    let eval = evaluate(
        &req,
        &[
            Rule::for_tool("fs.read", PolicyDecision::Permit),
            Rule::for_tool("fs.write", PolicyDecision::Forbid),
        ],
    );
    assert_eq!(eval.decision, PolicyDecision::Permit);
    assert!(eval.approval.is_some());
}

#[test]
fn core_exports_and_constructors_are_integration_ready() {
    let token = TaskToken::new(
        RevocationId::from(String::from("rev")),
        vec![Scope::from(String::from("tool:x")), Scope::new("tool:y")],
        Budget::limited(2),
        Some(Expiry(10)),
    );
    assert!(token.is_valid(0));

    let permit = Rule::permit_tool("tool:x").with_id("allow-x");
    let forbid = Rule::forbid_tool("tool:z");
    let needs = Rule::require_approval_tool("tool:y").with_reason("approve");
    let req = PolicyRequest::new("p", "tool:y", "r");
    let eval = evaluate(&req, &[permit, forbid, needs]);
    assert_eq!(eval.decision, PolicyDecision::RequireApproval);

    assert_eq!(TokenError::BudgetExhausted.to_string(), "budget exhausted");
}
