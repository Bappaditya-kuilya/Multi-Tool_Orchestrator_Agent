use std::sync::Arc;

use gateway::config::{GatewayConfig, RuntimeIntegrationHooks, StoreSelection};
use gateway::lifecycle::{InboundRequest, RequestHints, Stage};
use gateway::state::AppState;
use scopegate_core::policy::{PolicyDecision, Rule};
use scopegate_core::rate_limit::Limits;
use scopegate_core::taint::OperationTarget;
use scopegate_core::token::{Budget, Expiry, RevocationId, Scope, TaskToken};
use store::{
    ApprovalRecord, ApprovalStatus, BackendKind, InMemoryStore, RateLimitSnapshotRecord,
    RevocationRecord, Store, StoreConfig, TaskRecord,
};

async fn sqlite_store(path: &str) -> Arc<dyn Store> {
    let _ = std::fs::create_dir_all("/tmp/opencode");
    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_file(format!("{path}-shm"));
    let _ = std::fs::remove_file(format!("{path}-wal"));
    let url = format!("sqlite://{path}?mode=rwc");
    let mut s = store::SqliteStore::new(StoreConfig {
        backend: BackendKind::SqliteWal,
        database_url: url,
        fail_closed_on_audit_error: true,
    })
    .unwrap();
    s.connect().await.unwrap();
    s.migrate().await.unwrap();
    Arc::new(s) as Arc<dyn Store>
}

async fn reopen_sqlite_store(path: &str) -> Arc<dyn Store> {
    let url = format!("sqlite://{path}?mode=rwc");
    let mut s = store::SqliteStore::new(StoreConfig {
        backend: BackendKind::SqliteWal,
        database_url: url,
        fail_closed_on_audit_error: true,
    })
    .unwrap();
    s.connect().await.unwrap();
    Arc::new(s) as Arc<dyn Store>
}

fn cleanup_sqlite(path: &str) {
    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_file(format!("{path}-shm"));
    let _ = std::fs::remove_file(format!("{path}-wal"));
}

fn base_req(task_id: &str, rev_id: &str) -> InboundRequest {
    InboundRequest {
        task_id: task_id.into(),
        principal: "agent".into(),
        action: "tool.invoke".into(),
        resource: "tool".into(),
        token: TaskToken {
            revocation_id: RevocationId(rev_id.into()),
            scopes: vec![Scope("tool.invoke".into())],
            budget: Budget {
                max_calls: Some(10),
            },
            expires_at: Some(Expiry(100)),
            attenuation: None,
        },
        operation: OperationTarget::other("local"),
        taint_labels: vec![],
        secret: None,
        now: 1,
        approval_deadline: Some(10),
        approval_resolution: Some(broker::ApprovalStatus::Approved),
        hints: RequestHints::default(),
    }
}

fn config_with_rate_snapshot_persist() -> GatewayConfig {
    let mut cfg = GatewayConfig::default().with_rules(vec![Rule::exact(
        "agent",
        "tool.invoke",
        "tool",
        PolicyDecision::Permit,
    )]);
    cfg.store_selection = StoreSelection::SqliteWal;
    cfg.runtime_hooks = RuntimeIntegrationHooks {
        persist_audit_events: false,
        sync_revocations_from_store: true,
        use_approval_store: true,
        enable_rate_limit_state: true,
        persist_rate_limit_state: true,
        enable_broker_injection: true,
    };
    cfg.rate_limits = Limits {
        per_token_call_limit: Some(2),
        ..Limits::default()
    };
    cfg
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restart_reload_restores_task_approval_revocation_and_rate_budget_snapshot() {
    let path = format!(
        "/tmp/opencode/gw-restart-combined-{}-{}.db",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let store = sqlite_store(&path).await;

    // "Before restart": persist task, pending approval, revocation, and rate/budget counters.
    store
        .upsert_task(TaskRecord {
            id: "task-r1".into(),
            token_id: "tok-r1".into(),
            scopes: r#"["tool.invoke"]"#.into(),
            budget: 10,
            expires_at: "100".into(),
            ..Default::default()
        })
        .await
        .unwrap();
    store
        .create_approval(ApprovalRecord {
            id: "ap-r1".into(),
            task_id: "task-r1".into(),
            tool: "tool.invoke".into(),
            args_hash: "hash-r1".into(),
            status: ApprovalStatus::Pending,
            created_at: "1".into(),
            ..Default::default()
        })
        .await
        .unwrap();
    store
        .record_revocation(RevocationRecord {
            id: "rev-rec-1".into(),
            target_kind: "token".into(),
            target_id: "revoked-token-1".into(),
            reason: Some("restart-proof".into()),
            revoked_at: "1".into(),
            revoked_by: Some("test".into()),
        })
        .await
        .unwrap();

    let mut state = AppState::fail_closed().with_store(store.clone());
    state.config = config_with_rate_snapshot_persist();
    state.prepare_runtime_hooks().await.unwrap();

    // Consume one rate-limit slot and durably persist snapshot via handle_and_persist_audit.
    let req = base_req("task-r1", "active-token");
    let (out, _) = state.handle_and_persist_audit(&req).await;
    assert!(out.allowed, "first call should be allowed: {:?}", out.stage);

    // Simulate clean restart: drop state, reopen same durable store, create fresh AppState.
    drop(state);
    let reopened_store = reopen_sqlite_store(&path).await;
    let mut restarted = AppState::fail_closed().with_store(reopened_store.clone());
    restarted.config = config_with_rate_snapshot_persist();
    restarted.prepare_runtime_hooks().await.unwrap();

    // Task state restored from durable store.
    let task = reopened_store.get_task("task-r1").await.unwrap().unwrap();
    assert_eq!(task.token_id, "tok-r1");

    // Approval state restored into in-memory queue from durable pending approvals.
    assert!(restarted
        .approvals
        .lock()
        .expect("approvals lock")
        .get("ap-r1")
        .is_some());

    // Revocation state restored via store sync hook.
    let revoked = restarted.effective_revoked_token_ids().await.unwrap();
    assert!(revoked.iter().any(|id| id == "revoked-token-1"));

    // Rate/budget snapshot restored: second call allowed, third denied by restored counter.
    let req2 = base_req("task-r1", "active-token");
    let (out2, _) = restarted.handle_and_persist_audit(&req2).await;
    assert!(out2.allowed, "second call after restart should be allowed");
    let req3 = base_req("task-r1", "active-token");
    let (out3, _) = restarted.handle_and_persist_audit(&req3).await;
    assert!(
        !out3.allowed,
        "third call should be denied by restored budget"
    );
    assert_eq!(out3.stage, Stage::Denied);
    assert!(matches!(
        out3.error,
        Some(gateway::lifecycle::GatewayError::BudgetOrRateLimited(_))
    ));

    cleanup_sqlite(&path);
}

#[tokio::test]
async fn rate_snapshot_dirty_persist_only_writes_when_mutated_and_knob_controls_restore() {
    let store = Arc::new(InMemoryStore::default()) as Arc<dyn Store>;

    let mut state = AppState::fail_closed().with_store(store.clone());
    state.config = GatewayConfig::default().with_rules(vec![Rule::exact(
        "agent",
        "tool.invoke",
        "tool",
        PolicyDecision::Permit,
    )]);
    state.config.runtime_hooks.enable_rate_limit_state = true;
    state.config.runtime_hooks.persist_rate_limit_state = true;
    state.config.rate_limits.per_token_call_limit = Some(5);
    state.prepare_runtime_hooks().await.unwrap();

    // No mutation yet: dirty persist should be a no-op.
    let persisted = state.persist_rate_limit_snapshot_if_dirty().await.unwrap();
    assert!(!persisted);
    assert!(store.load_rate_limit_snapshot().await.unwrap().is_none());

    // Mutation marks dirty and persists snapshot.
    let req = base_req("task-dirty", "rev-dirty");
    let (out, _) = state.handle_with_audit_log(&req);
    assert!(out.allowed);
    let persisted = state.persist_rate_limit_snapshot_if_dirty().await.unwrap();
    assert!(persisted, "mutation should mark snapshot dirty");
    let persisted_again = state.persist_rate_limit_snapshot_if_dirty().await.unwrap();
    assert!(
        !persisted_again,
        "dirty flag must clear after successful persist"
    );
    let snap = store.load_rate_limit_snapshot().await.unwrap().unwrap();
    assert!(snap.snapshot_json.contains("tokens"));

    // Simulate restart with persist knob disabled: snapshot remains in store but is not restored.
    let mut restarted = AppState::fail_closed().with_store(store.clone());
    restarted.config = GatewayConfig::default().with_rules(vec![Rule::exact(
        "agent",
        "tool.invoke",
        "tool",
        PolicyDecision::Permit,
    )]);
    restarted.config.runtime_hooks.enable_rate_limit_state = true;
    restarted.config.runtime_hooks.persist_rate_limit_state = false;
    restarted.config.rate_limits.per_token_call_limit = Some(1);
    restarted.prepare_runtime_hooks().await.unwrap();
    // With no restore, first call is allowed despite previous snapshot having consumed calls.
    let (out, _) = restarted.handle_with_audit_log(&base_req("task-dirty", "rev-dirty"));
    assert!(out.allowed, "knob-off restart should not restore counters");
}

#[tokio::test]
async fn restart_caveat_config_drift_is_applied_as_is_and_enforced_by_current_limits() {
    // Caveat: rate/budget snapshot restore is global/full-snapshot-per-dirty-persist and has no
    // integrity signing. Config drift is applied as-is: restored counters are evaluated against
    // current configured limits (fail-closed toward enforcement, not silent reset).
    let store = Arc::new(InMemoryStore::default()) as Arc<dyn Store>;

    let mut writer = AppState::fail_closed().with_store(store.clone());
    writer.config = GatewayConfig::default().with_rules(vec![Rule::exact(
        "agent",
        "tool.invoke",
        "tool",
        PolicyDecision::Permit,
    )]);
    writer.config.runtime_hooks.enable_rate_limit_state = true;
    writer.config.runtime_hooks.persist_rate_limit_state = true;
    writer.config.rate_limits.per_token_call_limit = Some(10);
    writer.prepare_runtime_hooks().await.unwrap();
    for _ in 0..3 {
        let (out, _) = writer
            .handle_and_persist_audit(&base_req("task-drift", "rev-drift"))
            .await;
        assert!(out.allowed);
    }

    // Restart with stricter config: restored count (3) should deny under new limit (2).
    let mut restarted = AppState::fail_closed().with_store(store.clone());
    restarted.config = GatewayConfig::default().with_rules(vec![Rule::exact(
        "agent",
        "tool.invoke",
        "tool",
        PolicyDecision::Permit,
    )]);
    restarted.config.runtime_hooks.enable_rate_limit_state = true;
    restarted.config.runtime_hooks.persist_rate_limit_state = true;
    restarted.config.rate_limits.per_token_call_limit = Some(2);
    restarted.prepare_runtime_hooks().await.unwrap();
    let (out, _) = restarted.handle_with_audit_log(&base_req("task-drift", "rev-drift"));
    assert!(
        !out.allowed,
        "config drift applies restored counters as-is under new limits"
    );
    assert_eq!(out.stage, Stage::Denied);
    assert!(matches!(
        out.error,
        Some(gateway::lifecycle::GatewayError::BudgetOrRateLimited(_))
    ));
}

#[tokio::test]
async fn restart_caveat_full_snapshot_global_no_integrity_signature_is_documented_behavior() {
    // Caveat (documented, not fixed here): persistence writes a full global rate-limit snapshot on
    // each dirty persist; there is no per-token delta/checkpoint and no integrity signature.
    // This test proves the observable contract: snapshot is global and restores all token counters.
    let store = Arc::new(InMemoryStore::default()) as Arc<dyn Store>;

    let mut state = AppState::fail_closed().with_store(store.clone());
    state.config = GatewayConfig::default().with_rules(vec![Rule::exact(
        "agent",
        "tool.invoke",
        "tool",
        PolicyDecision::Permit,
    )]);
    state.config.runtime_hooks.enable_rate_limit_state = true;
    state.config.runtime_hooks.persist_rate_limit_state = true;
    state.config.rate_limits.per_token_call_limit = Some(1);
    state.prepare_runtime_hooks().await.unwrap();

    let (a, _) = state
        .handle_and_persist_audit(&base_req("task-a", "rev-a"))
        .await;
    let (b, _) = state
        .handle_and_persist_audit(&base_req("task-b", "rev-b"))
        .await;
    assert!(a.allowed && b.allowed);

    let rec: RateLimitSnapshotRecord = store.load_rate_limit_snapshot().await.unwrap().unwrap();
    // Global snapshot contains both token entries (observable full-snapshot/global behavior).
    assert!(rec.snapshot_json.contains("rev-a"));
    assert!(rec.snapshot_json.contains("rev-b"));

    drop(state);
    let mut restarted = AppState::fail_closed().with_store(store);
    restarted.config = GatewayConfig::default().with_rules(vec![Rule::exact(
        "agent",
        "tool.invoke",
        "tool",
        PolicyDecision::Permit,
    )]);
    restarted.config.runtime_hooks.enable_rate_limit_state = true;
    restarted.config.runtime_hooks.persist_rate_limit_state = true;
    restarted.config.rate_limits.per_token_call_limit = Some(1);
    restarted.prepare_runtime_hooks().await.unwrap();

    let (a2, _) = restarted.handle_with_audit_log(&base_req("task-a", "rev-a"));
    let (b2, _) = restarted.handle_with_audit_log(&base_req("task-b", "rev-b"));
    assert!(
        !a2.allowed && !b2.allowed,
        "global snapshot restores all token counters"
    );
}
