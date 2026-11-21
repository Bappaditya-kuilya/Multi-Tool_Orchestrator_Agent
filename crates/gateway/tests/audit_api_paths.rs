use std::sync::Arc;

use gateway::api::{
    handle_v1_approval_resolve, handle_v1_approvals, handle_v1_audit_verify, handle_v1_policies,
    handle_v1_task_revoke, handle_v1_tasks, ApprovalDecisionRequest, ApprovalPathResolveRequest,
    HttpStatus, PolicyUpsertRequest, TaskCreateRequest, TaskRevokeRequest, TaskTokenDto,
};
use gateway::state::AppState;
use scopegate_core::policy::{PolicyDecision, Rule};
use store::{AuditEvent, AuditQuery, InMemoryStore, Store, StoreError};

fn state_with_store() -> AppState {
    let mut st = AppState::fail_closed().with_store(Arc::new(InMemoryStore::default()));
    st.config = st.config.clone().with_rules(vec![Rule::exact(
        "agent",
        "tool.invoke",
        "tool",
        PolicyDecision::Permit,
    )]);
    st
}

fn task_req(task_id: &str) -> TaskCreateRequest {
    TaskCreateRequest {
        task_id: task_id.into(),
        principal: "agent".into(),
        action: "tool.invoke".into(),
        resource: "tool".into(),
        token: Some(TaskTokenDto {
            revocation_id: format!("rev-{task_id}"),
            scopes: vec!["tool.invoke".into()],
            max_calls: Some(1),
            expires_at: Some(1_000_000_000),
        }),
        operation: Some("local".into()),
        taint_labels: vec![],
        secret_ref: None,
        now: Some(1),
        approval_deadline: None,
        approval_resolution: None,
        hints: None,
        persist: Some(true),
    }
}

#[tokio::test]
async fn task_revoke_appends_audit_and_chain_verifies() {
    let st = state_with_store();
    let create = handle_v1_tasks(&st, task_req("t1")).await;
    assert_eq!(create.status, HttpStatus::Ok);

    let revoked = handle_v1_task_revoke(
        &st,
        "t1",
        TaskRevokeRequest {
            reason: Some("manual".into()),
            revoked_by: Some("admin".into()),
            ..Default::default()
        },
    )
    .await;
    assert_eq!(revoked.status, HttpStatus::Ok);
    assert!(revoked.body.as_ref().unwrap().revoked);

    let store = st.store.as_ref().unwrap();
    let events = store
        .query_audit(AuditQuery {
            task_id: Some("t1".into()),
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(events
        .iter()
        .any(|e| e.tool.as_deref() == Some("task.revoke") && e.decision == "revoked"));
    let verify = handle_v1_audit_verify(&st).await;
    assert_eq!(verify.status, HttpStatus::Ok);
    assert!(verify.body.unwrap().ok);
}

#[tokio::test]
async fn task_revoke_fails_closed_when_audit_append_fails() {
    let inner = Arc::new(InMemoryStore::default());
    inner
        .upsert_task(store::TaskRecord {
            id: "t1".into(),
            parent_id: None,
            token_id: "tok".into(),
            scopes: "[\"tool.invoke\"]".into(),
            budget: 1,
            expires_at: "1000000000".into(),
            revoked: false,
            revocation_reason: None,
            taint_snapshot_id: None,
        })
        .await
        .unwrap();

    #[derive(Clone)]
    struct FailAudit {
        inner: Arc<InMemoryStore>,
    }
    #[async_trait::async_trait]
    impl Store for FailAudit {
        fn backend(&self) -> store::BackendKind {
            self.inner.backend()
        }
        async fn append_audit_event(&self, _event: AuditEvent) -> store::StoreResult<AuditEvent> {
            Err(StoreError::Unavailable(
                "simulated audit append failure".into(),
            ))
        }
        async fn query_audit(&self, q: AuditQuery) -> store::StoreResult<Vec<AuditEvent>> {
            self.inner.query_audit(q).await
        }
        async fn verify_audit_chain(&self) -> store::StoreResult<store::AuditVerificationReport> {
            self.inner.verify_audit_chain().await
        }
        async fn create_approval(
            &self,
            a: store::ApprovalRecord,
        ) -> store::StoreResult<store::ApprovalRecord> {
            self.inner.create_approval(a).await
        }
        async fn get_approval(
            &self,
            id: &str,
        ) -> store::StoreResult<Option<store::ApprovalRecord>> {
            self.inner.get_approval(id).await
        }
        async fn list_approvals(
            &self,
            q: store::ApprovalQuery,
        ) -> store::StoreResult<Vec<store::ApprovalRecord>> {
            self.inner.list_approvals(q).await
        }
        async fn resolve_approval(
            &self,
            id: &str,
            status: store::ApprovalStatus,
            resolver: Option<String>,
            resolved_at: String,
        ) -> store::StoreResult<store::ApprovalRecord> {
            self.inner
                .resolve_approval(id, status, resolver, resolved_at)
                .await
        }
        async fn upsert_task(&self, t: store::TaskRecord) -> store::StoreResult<store::TaskRecord> {
            self.inner.upsert_task(t).await
        }
        async fn get_task(&self, id: &str) -> store::StoreResult<Option<store::TaskRecord>> {
            self.inner.get_task(id).await
        }
        async fn list_tasks(
            &self,
            q: store::TaskQuery,
        ) -> store::StoreResult<Vec<store::TaskRecord>> {
            self.inner.list_tasks(q).await
        }
        async fn upsert_policy(
            &self,
            p: store::PolicyRecord,
        ) -> store::StoreResult<store::PolicyRecord> {
            self.inner.upsert_policy(p).await
        }
        async fn get_active_policy(&self) -> store::StoreResult<Option<store::PolicyRecord>> {
            self.inner.get_active_policy().await
        }
        async fn record_revocation(
            &self,
            r: store::RevocationRecord,
        ) -> store::StoreResult<store::RevocationRecord> {
            self.inner.record_revocation(r).await
        }
        async fn list_revocations(
            &self,
            q: store::RevocationQuery,
        ) -> store::StoreResult<Vec<store::RevocationRecord>> {
            self.inner.list_revocations(q).await
        }
        async fn record_taint_snapshot(
            &self,
            s: store::TaintSnapshotRecord,
        ) -> store::StoreResult<store::TaintSnapshotRecord> {
            self.inner.record_taint_snapshot(s).await
        }
        async fn list_taint_snapshots(
            &self,
            q: store::TaintSnapshotQuery,
        ) -> store::StoreResult<Vec<store::TaintSnapshotRecord>> {
            self.inner.list_taint_snapshots(q).await
        }
        async fn get_tool_pin(
            &self,
            u: &str,
            t: &str,
        ) -> store::StoreResult<Option<store::ToolPinRecord>> {
            self.inner.get_tool_pin(u, t).await
        }
        async fn upsert_tool_pin(
            &self,
            r: store::ToolPinRecord,
        ) -> store::StoreResult<store::ToolPinRecord> {
            self.inner.upsert_tool_pin(r).await
        }
        async fn save_rate_limit_snapshot(
            &self,
            s: store::RateLimitSnapshotRecord,
        ) -> store::StoreResult<store::RateLimitSnapshotRecord> {
            self.inner.save_rate_limit_snapshot(s).await
        }
        async fn load_rate_limit_snapshot(
            &self,
        ) -> store::StoreResult<Option<store::RateLimitSnapshotRecord>> {
            self.inner.load_rate_limit_snapshot().await
        }
        async fn health_check(&self) -> store::StoreResult<()> {
            self.inner.health_check().await
        }
    }

    let st = AppState::fail_closed().with_store(Arc::new(FailAudit { inner }));
    let resp = handle_v1_task_revoke(
        &st,
        "t1",
        TaskRevokeRequest {
            reason: Some("manual".into()),
            ..Default::default()
        },
    )
    .await;
    assert_eq!(resp.status, HttpStatus::ServiceUnavailable);
    assert!(resp.fail_closed);
    assert!(resp
        .error
        .unwrap_or_default()
        .contains("audit append failed (fail-closed)"));
}

#[tokio::test]
async fn approval_resolve_appends_audit_and_chain_verifies() {
    let st = state_with_store();
    let created = handle_v1_approvals(
        &st,
        ApprovalDecisionRequest {
            id: "a1".into(),
            action: Some("create".into()),
            principal: Some("u".into()),
            tool: Some("act".into()),
            resource: Some("task-a".into()),
            now: Some(1),
            ..Default::default()
        },
    )
    .await;
    assert_eq!(created.status, HttpStatus::Ok);

    let resolved = handle_v1_approval_resolve(
        &st,
        "a1",
        ApprovalPathResolveRequest {
            action: Some("approve".into()),
            principal: Some("admin".into()),
            now: Some(2),
            ..Default::default()
        },
    )
    .await;
    assert_eq!(resolved.status, HttpStatus::Ok);

    let store = st.store.as_ref().unwrap();
    let events = store.query_audit(AuditQuery::default()).await.unwrap();
    assert!(events
        .iter()
        .any(|e| e.tool.as_deref() == Some("approval.resolve") && e.decision == "approved"));
    let verify = handle_v1_audit_verify(&st).await;
    assert_eq!(verify.status, HttpStatus::Ok);
    assert!(verify.body.unwrap().ok);
}

#[tokio::test]
async fn policy_upsert_appends_audit_and_chain_verifies() {
    let st = state_with_store();
    let up = handle_v1_policies(
        &st,
        Some(PolicyUpsertRequest {
            id: "p1".into(),
            body: r#"{"allow":true}"#.into(),
            version: Some(1),
            active: Some(true),
            rule: None,
        }),
    )
    .await;
    assert_eq!(up.status, HttpStatus::Ok);

    let store = st.store.as_ref().unwrap();
    let events = store.query_audit(AuditQuery::default()).await.unwrap();
    assert!(events
        .iter()
        .any(|e| e.tool.as_deref() == Some("policy.upsert") && e.decision == "upserted"));
    let verify = handle_v1_audit_verify(&st).await;
    assert_eq!(verify.status, HttpStatus::Ok);
    assert!(verify.body.unwrap().ok);
}

#[tokio::test]
async fn mutation_audit_chain_remains_verifiable_across_paths() {
    // Small provable hash-chain guarantee: mixed mutation audit appends preserve chain integrity.
    let st = state_with_store();
    let _ = handle_v1_tasks(&st, task_req("t1")).await;
    let _ = handle_v1_policies(
        &st,
        Some(PolicyUpsertRequest {
            id: "p1".into(),
            body: r#"{"allow":true}"#.into(),
            version: Some(1),
            active: Some(true),
            rule: None,
        }),
    )
    .await;
    let _ = handle_v1_approvals(
        &st,
        ApprovalDecisionRequest {
            id: "a1".into(),
            action: Some("create".into()),
            principal: Some("u".into()),
            tool: Some("act".into()),
            resource: Some("task-a".into()),
            now: Some(1),
            ..Default::default()
        },
    )
    .await;
    let _ = handle_v1_approval_resolve(
        &st,
        "a1",
        ApprovalPathResolveRequest {
            action: Some("deny".into()),
            now: Some(2),
            ..Default::default()
        },
    )
    .await;
    let _ = handle_v1_task_revoke(&st, "t1", TaskRevokeRequest::default()).await;

    let verify = handle_v1_audit_verify(&st).await;
    assert_eq!(verify.status, HttpStatus::Ok);
    let rep = verify.body.unwrap();
    assert!(
        rep.ok,
        "audit chain should verify after mixed mutations: {rep:?}"
    );
    assert!(rep.checked_events >= 4);
}
