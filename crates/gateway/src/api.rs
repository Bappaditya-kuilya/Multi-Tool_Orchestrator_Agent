//! HTTP/admin API route constants, DTOs, and handlers wired to gateway state.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::config::GatewayConfig;
use crate::lifecycle::{InboundRequest, RequestHints, Stage};
use crate::state::AppState;
use broker::{ApprovalRequest, ApprovalStatus};
use scopegate_core::policy::{BudgetHint, CallCountHint, RateLimitHint};
use scopegate_core::taint::{OperationTarget, TaintLabel};
use scopegate_core::token::{Budget, Expiry, RevocationId, Scope, TaskToken};
use store::{AuditEvent, AuditQuery, PolicyRecord, StoreError, TaskQuery, TaskRecord};

/// Route table.
pub mod routes {
    pub const HEALTHZ: &str = "/healthz";
    pub const READYZ: &str = "/readyz";
    pub const METRICS: &str = "/metrics";
    pub const V1_TASKS: &str = "/v1/tasks";
    pub const V1_AUDIT: &str = "/v1/audit";
    pub const V1_APPROVALS: &str = "/v1/approvals";
    pub const V1_POLICIES: &str = "/v1/policies";
    pub const V1_STREAM: &str = "/v1/stream";
    pub const ALL: &[&str] = &[
        HEALTHZ,
        READYZ,
        METRICS,
        V1_TASKS,
        V1_AUDIT,
        V1_APPROVALS,
        V1_POLICIES,
        V1_STREAM,
    ];
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HttpStatus {
    Ok,
    Accepted,
    BadRequest,
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    ServiceUnavailable,
    NotImplemented,
    InternalServerError,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiResponse<T> {
    pub status: HttpStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<T>,
    pub fail_closed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl<T> ApiResponse<T> {
    pub fn ok(body: T) -> Self {
        Self {
            status: HttpStatus::Ok,
            body: Some(body),
            fail_closed: false,
            error: None,
        }
    }
    pub fn fail(status: HttpStatus, error: impl Into<String>) -> Self {
        Self {
            status,
            body: None,
            fail_closed: true,
            error: Some(error.into()),
        }
    }
    pub fn unavailable(error: impl Into<String>) -> Self {
        Self::fail(HttpStatus::ServiceUnavailable, error)
    }
    pub fn bad_request(error: impl Into<String>) -> Self {
        Self::fail(HttpStatus::BadRequest, error)
    }
    pub fn forbidden(error: impl Into<String>) -> Self {
        Self::fail(HttpStatus::Forbidden, error)
    }
    pub fn conflict(error: impl Into<String>) -> Self {
        Self::fail(HttpStatus::Conflict, error)
    }
    pub fn internal(error: impl Into<String>) -> Self {
        Self::fail(HttpStatus::InternalServerError, error)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthzResponse {
    pub status: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadyzResponse {
    pub ready: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetricsResponse {
    pub format: String,
    pub body: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskTokenDto {
    pub revocation_id: String,
    #[serde(default)]
    pub scopes: Vec<String>,
    pub max_calls: Option<u32>,
    pub expires_at: Option<u64>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskHintsDto {
    pub rate_calls_in_window: Option<u32>,
    pub rate_limit: Option<u32>,
    pub rate_exceeded: Option<bool>,
    pub budget_used: Option<u64>,
    pub budget_limit: Option<u64>,
    pub budget_exceeded: Option<bool>,
    pub call_count: Option<u64>,
    pub call_count_limit: Option<u64>,
    pub call_count_exceeded: Option<bool>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct TaskCreateRequest {
    pub task_id: String,
    pub principal: String,
    pub action: String,
    pub resource: String,
    #[serde(default)]
    pub token: Option<TaskTokenDto>,
    #[serde(default)]
    pub operation: Option<String>, // "egress" or other target
    #[serde(default)]
    pub taint_labels: Vec<String>,
    #[serde(default)]
    pub secret_ref: Option<String>,
    #[serde(default)]
    pub now: Option<u64>,
    #[serde(default)]
    pub approval_deadline: Option<u64>,
    #[serde(default)]
    pub approval_resolution: Option<String>,
    #[serde(default)]
    pub hints: Option<TaskHintsDto>,
    #[serde(default)]
    pub persist: Option<bool>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct TaskRecordView {
    pub id: String,
    pub state: String,
    pub stage: Option<String>,
    pub allowed: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audit_verified: Option<bool>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TaskListResponse {
    pub tasks: Vec<TaskRecord>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditQueryRequest {
    pub task_id: Option<String>,
    pub decision: Option<String>,
    pub limit: Option<u32>,
    pub offset: Option<u32>,
    pub verify: Option<bool>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuditQueryResponse {
    pub events: Vec<AuditEvent>,
    pub chain_verified: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification: Option<store::AuditVerificationReport>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalDecisionRequest {
    pub id: String,
    #[serde(default)]
    pub action: Option<String>, // create|approve|deny
    pub decision: Option<String>,
    pub principal: Option<String>,
    pub tool: Option<String>,
    pub resource: Option<String>,
    pub reason: Option<String>,
    pub expires_at: Option<u64>,
    pub now: Option<u64>,
    pub args_hash: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ApprovalView {
    pub id: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct PolicyUpsertRequest {
    pub id: String,
    #[serde(default)]
    pub body: String,
    #[serde(default)]
    pub version: Option<i64>,
    #[serde(default)]
    pub active: Option<bool>,
    #[serde(default)]
    pub rule: Option<PolicyRuleDto>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct PolicyRuleDto {
    pub principal: String,
    pub action: String,
    pub resource: String,
    pub decision: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct PolicyView {
    pub id: String,
    pub active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<Value>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamSubscribeRequest {
    pub task_id: Option<String>,
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn parse_taint(label: &str) -> Option<TaintLabel> {
    match label.to_ascii_lowercase().as_str() {
        "private_data" | "private" | "pii" => Some(TaintLabel::PrivateData),
        "untrusted_content" | "untrusted" => Some(TaintLabel::UntrustedContent),
        _ => None,
    }
}

fn parse_op(op: Option<&str>) -> OperationTarget {
    match op.map(|s| s.to_ascii_lowercase()) {
        Some(ref s) if s == "egress" || s == "external_egress" => OperationTarget::ExternalEgress,
        Some(s) => OperationTarget::other(s),
        None => OperationTarget::other("unspecified"),
    }
}

fn approval_status_from_str(s: &str) -> Option<ApprovalStatus> {
    match s.to_ascii_lowercase().as_str() {
        "approved" | "approve" | "allow" => Some(ApprovalStatus::Approved),
        "denied" | "deny" | "reject" => Some(ApprovalStatus::Denied),
        "timed_out" | "timeout" | "expired" => Some(ApprovalStatus::TimedOut),
        _ => None,
    }
}

fn to_inbound(req: &TaskCreateRequest) -> Result<InboundRequest, String> {
    if req.task_id.trim().is_empty()
        || req.principal.trim().is_empty()
        || req.action.trim().is_empty()
        || req.resource.trim().is_empty()
    {
        return Err("task_id/principal/action/resource required".into());
    }
    let tok = req
        .token
        .as_ref()
        .ok_or("token required for lifecycle execution (fail-closed)")?;
    if tok.revocation_id.trim().is_empty() {
        return Err("token.revocation_id required".into());
    }
    let scopes = if tok.scopes.is_empty() {
        vec![Scope::new(req.action.clone())]
    } else {
        tok.scopes.iter().cloned().map(Scope::new).collect()
    };
    let token = TaskToken::new(
        RevocationId::new(tok.revocation_id.clone()),
        scopes,
        Budget {
            max_calls: tok.max_calls,
        },
        tok.expires_at.map(Expiry),
    );
    let hints = req.hints.as_ref();
    let rl = hints.and_then(|h| match (h.rate_calls_in_window, h.rate_limit) {
        (Some(calls), Some(limit)) => Some(RateLimitHint {
            calls_in_window: calls,
            limit,
            exceeded: h.rate_exceeded.unwrap_or(false),
        }),
        _ => None,
    });
    let budget = hints.and_then(|h| match (h.budget_used, h.budget_limit) {
        (Some(used), Some(limit)) => Some(BudgetHint {
            used,
            limit,
            exceeded: h.budget_exceeded.unwrap_or(false),
        }),
        _ => None,
    });
    let call_count = hints.and_then(|h| match (h.call_count, h.call_count_limit) {
        (Some(count), Some(limit)) => Some(CallCountHint {
            count: count.min(u32::MAX as u64) as u32,
            limit: Some(limit.min(u32::MAX as u64) as u32),
            exceeded: h.call_count_exceeded.unwrap_or(false),
        }),
        _ => None,
    });
    Ok(InboundRequest {
        task_id: req.task_id.clone(),
        principal: req.principal.clone(),
        action: req.action.clone(),
        resource: req.resource.clone(),
        token,
        operation: parse_op(req.operation.as_deref()),
        taint_labels: req
            .taint_labels
            .iter()
            .filter_map(|s| parse_taint(s))
            .collect(),
        secret: req
            .secret_ref
            .as_ref()
            .map(|s| broker::SecretRef(s.clone())),
        now: req.now.unwrap_or_else(now_unix),
        approval_deadline: req.approval_deadline,
        approval_resolution: req
            .approval_resolution
            .as_deref()
            .and_then(approval_status_from_str),
        hints: RequestHints {
            rate_limit: rl,
            budget,
            call_count,
        },
    })
}

pub fn handle_healthz(_config: &GatewayConfig) -> ApiResponse<HealthzResponse> {
    ApiResponse::ok(HealthzResponse {
        status: "ok".to_string(),
    })
}

pub async fn handle_readyz(state: &AppState) -> ApiResponse<ReadyzResponse> {
    let store_ok = state.has_store() && state.store_healthy().await;
    let broker_ok = state.has_broker();
    if store_ok && broker_ok {
        ApiResponse::ok(ReadyzResponse {
            ready: true,
            reason: None,
        })
    } else {
        let reason = if !store_ok {
            "store_unavailable"
        } else {
            "broker_unavailable"
        };
        ApiResponse {
            status: HttpStatus::ServiceUnavailable,
            body: Some(ReadyzResponse {
                ready: false,
                reason: Some(reason.into()),
            }),
            fail_closed: true,
            error: Some(reason.into()),
        }
    }
}

pub fn handle_metrics(state: &AppState) -> ApiResponse<MetricsResponse> {
    ApiResponse::ok(MetricsResponse {
        format: "text/plain; version=0.0.4".into(),
        body: state.metrics.snapshot_prometheus(),
    })
}

pub async fn handle_v1_tasks(
    state: &mut AppState,
    req: TaskCreateRequest,
) -> ApiResponse<TaskRecordView> {
    let Some(store) = state.store.clone() else {
        return ApiResponse::unavailable("store unavailable (fail-closed)");
    };
    let inbound = match to_inbound(&req) {
        Ok(v) => v,
        Err(e) => return ApiResponse::bad_request(e),
    };
    let out = state.handle(&inbound);
    let stage = format!("{:?}", out.stage);
    let state_str = if out.allowed { "allowed" } else { "denied" };

    // Persist task record (lifecycle+store wiring). Fail closed on persistence errors when required.
    let task = TaskRecord {
        id: inbound.task_id.clone(),
        parent_id: None,
        token_id: inbound.token.revocation_id.0.clone(),
        scopes: serde_json::to_string(
            &inbound
                .token
                .scopes
                .iter()
                .map(|s| s.0.clone())
                .collect::<Vec<_>>(),
        )
        .unwrap_or_else(|_| "[]".into()),
        budget: inbound.token.budget.max_calls.unwrap_or(0) as i64,
        expires_at: inbound
            .token
            .expires_at
            .map(|e| e.0.to_string())
            .unwrap_or_default(),
        revoked: false,
        revocation_reason: None,
        taint_snapshot_id: None,
    };
    if let Err(e) = store.upsert_task(task).await {
        state
            .metrics
            .audit_append_failures
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if state.config.fail_closed {
            return ApiResponse::unavailable(format!("task persistence failed (fail-closed): {e}"));
        }
    }

    // Append lifecycle summary audit event to store when available (append-before-return semantics by store).
    let audit = AuditEvent {
        seq: 0,
        ts: inbound.now.to_string(),
        task_id: Some(inbound.task_id.clone()),
        tool: Some(inbound.action.clone()),
        decision: state_str.to_string(),
        reason: out.error.as_ref().map(|e| format!("{e:?}")),
        args_digest: Some(scopegate_core::audit::digest(&format!(
            "{}:{}",
            inbound.action, inbound.resource
        ))),
        result_digest: Some(scopegate_core::audit::digest(&stage)),
        prev_hash: None,
        hash: None,
    };
    match store.append_audit_event(audit).await {
        Ok(_) => {
            state
                .metrics
                .audit_appends
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        Err(e) => {
            state
                .metrics
                .audit_append_failures
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if state.config.fail_closed {
                return ApiResponse::unavailable(format!("audit append failed (fail-closed): {e}"));
            }
        }
    }

    let status = if out.allowed {
        HttpStatus::Ok
    } else if matches!(out.stage, Stage::Denied) {
        HttpStatus::Forbidden
    } else {
        HttpStatus::ServiceUnavailable
    };
    ApiResponse {
        status,
        body: Some(TaskRecordView {
            id: inbound.task_id,
            state: state_str.into(),
            stage: Some(stage),
            allowed: Some(out.allowed),
            error: out.error.map(|e| format!("{e:?}")),
            audit_verified: Some(out.audit_verified),
        }),
        fail_closed: !out.allowed,
        error: None,
    }
}

pub async fn handle_v1_tasks_list(state: &AppState) -> ApiResponse<TaskListResponse> {
    let Some(store) = &state.store else {
        return ApiResponse::unavailable("store unavailable (fail-closed)");
    };
    match store
        .list_tasks(TaskQuery {
            limit: Some(100),
            ..Default::default()
        })
        .await
    {
        Ok(tasks) => ApiResponse::ok(TaskListResponse { tasks }),
        Err(e) => map_store_err(e),
    }
}

pub async fn handle_v1_audit(
    state: &AppState,
    req: AuditQueryRequest,
) -> ApiResponse<AuditQueryResponse> {
    let Some(store) = &state.store else {
        return ApiResponse::unavailable("store unavailable (fail-closed)");
    };
    let events = match store
        .query_audit(AuditQuery {
            task_id: req.task_id,
            decision: req.decision,
            limit: req.limit,
            offset: req.offset,
            ..Default::default()
        })
        .await
    {
        Ok(v) => v,
        Err(e) => return map_store_err(e),
    };
    let verification = match store.verify_audit_chain().await {
        Ok(rep) => Some(rep),
        Err(StoreError::Integrity(msg)) => Some(store::AuditVerificationReport {
            ok: false,
            checked_events: 0,
            first_bad_seq: None,
            message: Some(msg),
            expected_hash_hex: None,
            actual_hash_hex: None,
        }),
        Err(e) => return map_store_err(e),
    };
    let chain_verified = verification.as_ref().map(|v| v.ok).unwrap_or(false);
    if state.config.fail_closed && !chain_verified {
        return ApiResponse {
            status: HttpStatus::ServiceUnavailable,
            body: Some(AuditQueryResponse {
                events,
                chain_verified,
                verification,
            }),
            fail_closed: true,
            error: Some("audit chain verification failed (fail-closed)".into()),
        };
    }
    ApiResponse::ok(AuditQueryResponse {
        events,
        chain_verified,
        verification,
    })
}

pub async fn handle_v1_approvals(
    state: &mut AppState,
    req: ApprovalDecisionRequest,
) -> ApiResponse<ApprovalView> {
    let Some(store) = state.store.clone() else {
        return ApiResponse::unavailable("store unavailable (fail-closed)");
    };
    let now = req.now.unwrap_or_else(now_unix);
    let action = req
        .action
        .as_deref()
        .or(req.decision.as_deref())
        .unwrap_or("");
    if req.id.trim().is_empty() {
        return ApiResponse::bad_request("id required");
    }

    // "create" path: create approval in broker queue and persist to store.
    if matches!(action, "create" | "pending") {
        let areq = ApprovalRequest {
            id: req.id.clone(),
            principal: req.principal.clone().unwrap_or_else(|| "unknown".into()),
            action: req.tool.clone().unwrap_or_else(|| "unknown".into()),
            resource: req.resource.clone().unwrap_or_else(|| "unknown".into()),
            reason: req.reason.clone(),
        };
        if let Err(e) =
            state
                .approvals
                .create_with_binding(areq.clone(), req.expires_at, req.args_hash.clone())
        {
            // allow conflict if same record semantics not critical; fail closed otherwise
            if !matches!(e, broker::BrokerError::DuplicateApproval(_)) {
                return ApiResponse::conflict(format!("approval create failed: {e:?}"));
            }
        }
        let rec = store::ApprovalRecord {
            id: req.id.clone(),
            task_id: req.resource.clone().unwrap_or_else(|| req.id.clone()),
            tool: areq.action,
            args_hash: req.args_hash.unwrap_or_default(),
            status: store::ApprovalStatus::Pending,
            created_at: now.to_string(),
            resolved_at: None,
            resolver: None,
        };
        match store.create_approval(rec).await {
            Ok(_) | Err(StoreError::Conflict(_)) => {
                state.emit_event(crate::state::StreamEvent {
                    kind: "approval.pending".into(),
                    message: req.id.clone(),
                    task_id: None,
                });
                return ApiResponse::ok(ApprovalView {
                    id: req.id,
                    status: "pending".into(),
                    source: Some("broker+store".into()),
                });
            }
            Err(e) => return map_store_err(e),
        }
    }

    // resolve path
    let Some(decision) = approval_status_from_str(action)
        .or_else(|| req.decision.as_deref().and_then(approval_status_from_str))
    else {
        return ApiResponse::bad_request("decision/action must be create|approve|deny|timeout");
    };
    // update broker best-effort
    let _ = state.approvals.resolve(&req.id, decision, now);
    let store_status = match decision.effective() {
        ApprovalStatus::Approved => store::ApprovalStatus::Approved,
        ApprovalStatus::Denied | ApprovalStatus::TimedOut => store::ApprovalStatus::Denied,
        ApprovalStatus::Pending => store::ApprovalStatus::Pending,
    };
    match store
        .resolve_approval(
            &req.id,
            store_status,
            req.principal.clone(),
            now.to_string(),
        )
        .await
    {
        Ok(r) => {
            state.emit_event(crate::state::StreamEvent {
                kind: "approval.resolved".into(),
                message: format!("{}:{:?}", r.id, r.status),
                task_id: None,
            });
            ApiResponse::ok(ApprovalView {
                id: r.id,
                status: format!("{:?}", r.status).to_lowercase(),
                source: Some("broker+store".into()),
            })
        }
        Err(e) => map_store_err(e),
    }
}

pub async fn handle_v1_policies(
    state: &AppState,
    req: Option<PolicyUpsertRequest>,
) -> ApiResponse<PolicyView> {
    let Some(store) = &state.store else {
        return ApiResponse::unavailable("store unavailable (fail-closed)");
    };
    if let Some(req) = req {
        if req.id.trim().is_empty() {
            return ApiResponse::bad_request("id required");
        }
        let body = if !req.body.is_empty() {
            req.body
        } else if let Some(rule) = req.rule {
            serde_json::to_string(&serde_json::json!({"principal":rule.principal,"action":rule.action,"resource":rule.resource,"decision":rule.decision})).unwrap_or_else(|_| "{}".into())
        } else {
            "{}".into()
        };
        let record = PolicyRecord {
            id: req.id.clone(),
            version: req.version.unwrap_or(1),
            body,
            created_at: now_unix().to_string(),
            active: req.active.unwrap_or(true),
        };
        match store.upsert_policy(record).await {
            Ok(p) => ApiResponse::ok(PolicyView {
                id: p.id,
                active: p.active,
                body: serde_json::from_str(&p.body).ok(),
            }),
            Err(e) => map_store_err(e),
        }
    } else {
        match store.get_active_policy().await {
            Ok(Some(p)) => ApiResponse::ok(PolicyView {
                id: p.id,
                active: p.active,
                body: serde_json::from_str(&p.body).ok(),
            }),
            Ok(None) => ApiResponse::fail(HttpStatus::NotFound, "no active policy"),
            Err(e) => map_store_err(e),
        }
    }
}

fn map_store_err<T>(e: StoreError) -> ApiResponse<T> {
    match e {
        StoreError::NotFound(msg) => ApiResponse::fail(HttpStatus::NotFound, msg),
        StoreError::Conflict(msg) => ApiResponse::conflict(msg),
        StoreError::Invalid(msg) => ApiResponse::bad_request(msg),
        StoreError::Integrity(msg) => {
            ApiResponse::unavailable(format!("integrity failure (fail-closed): {msg}"))
        }
        StoreError::Unavailable(msg) => ApiResponse::unavailable(msg),
        StoreError::NotImplemented(msg) => ApiResponse::unavailable(format!(
            "store backend not implemented (fail-closed): {msg}"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use scopegate_core::policy::{PolicyDecision, Rule};
    use std::sync::Arc;
    use store::InMemoryStore;

    fn state_with_store() -> AppState {
        let mut s = AppState::fail_closed().with_store(Arc::new(InMemoryStore::default()));
        s.config = s.config.clone().with_rules(vec![Rule::exact(
            "agent",
            "tool.invoke",
            "tool",
            PolicyDecision::Permit,
        )]);
        s
    }

    fn task_req() -> TaskCreateRequest {
        TaskCreateRequest {
            task_id: "t1".into(),
            principal: "agent".into(),
            action: "tool.invoke".into(),
            resource: "tool".into(),
            token: Some(TaskTokenDto {
                revocation_id: "r1".into(),
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

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Runtime::new().unwrap()
    }

    #[test]
    fn readyz_fails_closed_without_store() {
        rt().block_on(async {
            let st = AppState::fail_closed();
            let resp = handle_readyz(&st).await;
            assert_eq!(resp.status, HttpStatus::ServiceUnavailable);
            assert!(resp.fail_closed);
        });
    }

    #[test]
    fn tasks_wired_to_lifecycle_and_store() {
        rt().block_on(async {
            let mut st = state_with_store();
            let resp = handle_v1_tasks(&mut st, task_req()).await;
            assert_eq!(resp.status, HttpStatus::Ok);
            let body = resp.body.unwrap();
            assert_eq!(body.state, "allowed");
            let list = handle_v1_tasks_list(&st).await;
            assert_eq!(list.body.unwrap().tasks.len(), 1);
        });
    }

    #[test]
    fn audit_query_and_verify_from_store() {
        rt().block_on(async {
            let mut st = state_with_store();
            let _ = handle_v1_tasks(&mut st, task_req()).await;
            let resp = handle_v1_audit(
                &st,
                AuditQueryRequest {
                    task_id: Some("t1".into()),
                    ..Default::default()
                },
            )
            .await;
            assert_eq!(resp.status, HttpStatus::Ok);
            let body = resp.body.unwrap();
            assert!(!body.events.is_empty());
            assert!(body.chain_verified);
        });
    }

    #[test]
    fn policies_upsert_and_get_active() {
        rt().block_on(async {
            let st = state_with_store();
            let up = handle_v1_policies(
                &st,
                Some(PolicyUpsertRequest {
                    id: "p1".into(),
                    body: r#"{"allow":"all"}"#.into(),
                    version: Some(1),
                    active: Some(true),
                    rule: None,
                }),
            )
            .await;
            assert_eq!(up.status, HttpStatus::Ok);
            let got = handle_v1_policies(&st, None).await;
            assert_eq!(got.status, HttpStatus::Ok);
            assert_eq!(got.body.unwrap().id, "p1");
        });
    }

    #[test]
    fn approvals_broker_and_store_flow() {
        rt().block_on(async {
            let mut st = state_with_store();
            let created = handle_v1_approvals(
                &mut st,
                ApprovalDecisionRequest {
                    id: "a1".into(),
                    action: Some("create".into()),
                    principal: Some("u".into()),
                    tool: Some("act".into()),
                    resource: Some("res".into()),
                    now: Some(1),
                    ..Default::default()
                },
            )
            .await;
            assert_eq!(created.status, HttpStatus::Ok);
            let resolved = handle_v1_approvals(
                &mut st,
                ApprovalDecisionRequest {
                    id: "a1".into(),
                    action: Some("approve".into()),
                    now: Some(2),
                    ..Default::default()
                },
            )
            .await;
            assert_eq!(resolved.status, HttpStatus::Ok);
            assert_eq!(resolved.body.unwrap().status, "approved");
        });
    }

    #[test]
    fn metrics_reflect_activity() {
        let st = state_with_store();
        let resp = handle_metrics(&st);
        assert!(resp.body.unwrap().body.contains("gateway_requests_total"));
    }

    #[test]
    fn mcp_dispatch_integration_point() {
        let resp = crate::mcp::handle_mcp_request(
            crate::mcp::McpRequest {
                method: String::new(),
                payload_json: r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#.into(),
                upstream: None,
            },
            None,
        );
        assert!(resp.ok);
        assert!(!resp.fail_closed);
        let bad = crate::mcp::handle_mcp_request(
            crate::mcp::McpRequest {
                method: String::new(),
                payload_json:
                    r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"nope"}}"#
                        .into(),
                upstream: None,
            },
            None,
        );
        assert!(!bad.ok);
        assert!(bad.fail_closed);
    }
}
