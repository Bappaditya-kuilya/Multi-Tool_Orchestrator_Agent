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

use store::{
    AuditEvent, AuditQuery, PolicyRecord, RevocationRecord, StoreError, TaskQuery, TaskRecord,
};

/// Route table.
pub mod routes {
    pub const HEALTHZ: &str = "/healthz";
    pub const READYZ: &str = "/readyz";
    pub const METRICS: &str = "/metrics";
    pub const V1_TASKS: &str = "/v1/tasks";
    pub const V1_TASKS_ID: &str = "/v1/tasks/:id";
    pub const V1_TASKS_REVOKE: &str = "/v1/tasks/:id/revoke";
    pub const V1_AUDIT: &str = "/v1/audit";
    pub const V1_AUDIT_VERIFY: &str = "/v1/audit/verify";
    pub const V1_APPROVALS: &str = "/v1/approvals";
    pub const V1_APPROVALS_ID: &str = "/v1/approvals/:id";
    pub const V1_APPROVALS_RESOLVE: &str = "/v1/approvals/:id/resolve";
    pub const V1_POLICIES: &str = "/v1/policies";
    pub const V1_STREAM: &str = "/v1/stream";
    pub const ALL: &[&str] = &[
        HEALTHZ,
        READYZ,
        METRICS,
        V1_TASKS,
        V1_TASKS_ID,
        V1_TASKS_REVOKE,
        V1_AUDIT,
        V1_AUDIT_VERIFY,
        V1_APPROVALS,
        V1_APPROVALS_ID,
        V1_APPROVALS_RESOLVE,
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
pub struct TaskRevokeRequest {
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub revoked_by: Option<String>,
    #[serde(default)]
    pub revocation_id: Option<String>,
    #[serde(default)]
    pub now: Option<u64>,
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

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalListQueryRequest {
    #[serde(default)]
    pub task_id: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub limit: Option<u32>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ApprovalListResponse {
    pub approvals: Vec<store::ApprovalRecord>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalPathResolveRequest {
    #[serde(default)]
    pub action: Option<String>, // approve|deny|timeout
    #[serde(default)]
    pub decision: Option<String>,
    #[serde(default)]
    pub principal: Option<String>,
    #[serde(default)]
    pub now: Option<u64>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ApprovalView {
    pub id: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub task_id: Option<String>,
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
    pub version: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
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

    // Sync durable runtime state (revocations/approvals/rate hooks) before lifecycle evaluation.
    // Fail closed when required hook state cannot be loaded/verified.
    if let Err(e) = state.prepare_runtime_hooks().await {
        return ApiResponse::unavailable(format!(
            "runtime hook preparation failed (fail-closed): {e}"
        ));
    }

    // Idempotency/conflict: task creation is not replay-safe because lifecycle evaluation
    // and audit append are side-effecting. Fail closed on duplicate IDs.
    match store.get_task(&inbound.task_id).await {
        Ok(Some(_)) => {
            return ApiResponse::conflict(format!("task '{}' already exists", inbound.task_id))
        }
        Ok(None) => {}
        Err(e) => return map_store_err(e),
    }

    let mut out = state.handle(&inbound);
    if out.allowed {
        if let Err(e) = state.persist_rate_limit_snapshot_if_dirty().await {
            state
                .metrics
                .requests_allowed
                .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
            state
                .metrics
                .requests_denied
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            out = crate::lifecycle::runtime_integration_denied(
                &[],
                crate::lifecycle::Stage::BudgetRateLimit,
                format!("rate limit snapshot persistence failed (fail-closed): {e}"),
            );
        }
    } else {
        // Still persist consumed counters on denied outcomes when dirty; fail-closed on error.
        if let Err(e) = state.persist_rate_limit_snapshot_if_dirty().await {
            out = crate::lifecycle::runtime_integration_denied(
                &[],
                crate::lifecycle::Stage::BudgetRateLimit,
                format!("rate limit snapshot persistence failed (fail-closed): {e}"),
            );
        }
    }
    let stage = format!("{:?}", out.stage);
    let state_str = if out.allowed { "allowed" } else { "denied" };

    // Append lifecycle summary audit event before persisting task state so the decision
    // is durably recorded when the store enforces append-before-return semantics.
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
        if state.config.fail_closed {
            return ApiResponse::unavailable(format!("task persistence failed (fail-closed): {e}"));
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

pub async fn handle_v1_task_get(state: &AppState, id: &str) -> ApiResponse<TaskRecord> {
    let Some(store) = &state.store else {
        return ApiResponse::unavailable("store unavailable (fail-closed)");
    };
    if id.trim().is_empty() {
        return ApiResponse::bad_request("task id required");
    }
    match store.get_task(id).await {
        Ok(Some(task)) => ApiResponse::ok(task),
        Ok(None) => ApiResponse::fail(HttpStatus::NotFound, "task not found"),
        Err(e) => map_store_err(e),
    }
}

pub async fn handle_v1_task_revoke(
    state: &AppState,
    id: &str,
    req: TaskRevokeRequest,
) -> ApiResponse<TaskRecord> {
    let Some(store) = &state.store else {
        return ApiResponse::unavailable("store unavailable (fail-closed)");
    };
    if id.trim().is_empty() {
        return ApiResponse::bad_request("task id required");
    }
    let existing = match store.get_task(id).await {
        Ok(Some(t)) => t,
        Ok(None) => return ApiResponse::fail(HttpStatus::NotFound, "task not found"),
        Err(e) => return map_store_err(e),
    };
    if existing.revoked {
        // Idempotent revoke: preserve durable state and avoid duplicate revocation records.
        return ApiResponse::ok(existing);
    }

    let reason = req.reason.clone();
    let rec = RevocationRecord {
        id: req
            .revocation_id
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
        target_kind: "task".to_string(),
        target_id: existing.id.clone(),
        reason: reason.clone(),
        revoked_at: req.now.unwrap_or_else(now_unix).to_string(),
        revoked_by: req.revoked_by,
    };
    if let Err(e) = store.record_revocation(rec).await {
        return map_store_err(e);
    }

    let mut task = existing;
    task.revoked = true;
    task.revocation_reason = reason.or(task.revocation_reason);
    if let Err(e) = store.upsert_task(task.clone()).await {
        return map_store_err(e);
    }
    ApiResponse::ok(task)
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

/// Verify audit hash chain via store. Fail-closed when store unavailable or chain invalid.
pub async fn handle_v1_audit_verify(
    state: &AppState,
) -> ApiResponse<store::AuditVerificationReport> {
    let Some(store) = &state.store else {
        return ApiResponse::unavailable("store unavailable (fail-closed)");
    };
    match store.verify_audit_chain().await {
        Ok(rep) => {
            if !rep.ok && state.config.fail_closed {
                ApiResponse {
                    status: HttpStatus::ServiceUnavailable,
                    body: Some(rep),
                    fail_closed: true,
                    error: Some("audit chain verification failed (fail-closed)".into()),
                }
            } else {
                ApiResponse::ok(rep)
            }
        }
        Err(StoreError::Integrity(msg)) => ApiResponse {
            status: HttpStatus::ServiceUnavailable,
            body: Some(store::AuditVerificationReport {
                ok: false,
                checked_events: 0,
                first_bad_seq: None,
                message: Some(msg),
                expected_hash_hex: None,
                actual_hash_hex: None,
            }),
            fail_closed: true,
            error: Some("audit chain verification failed (fail-closed)".into()),
        },
        Err(e) => map_store_err(e),
    }
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
        let expected_task_id = req.resource.clone().unwrap_or_else(|| req.id.clone());
        let expected_tool = areq.action.clone();
        let expected_args_hash = req.args_hash.clone().unwrap_or_default();

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
            task_id: expected_task_id.clone(),
            tool: expected_tool.clone(),
            args_hash: expected_args_hash.clone(),
            status: store::ApprovalStatus::Pending,
            created_at: now.to_string(),
            resolved_at: None,
            resolver: None,
        };
        match store.create_approval(rec).await {
            Ok(created) => {
                state.emit_event(crate::state::StreamEvent {
                    kind: "approval.pending".into(),
                    message: created.id.clone(),
                    task_id: Some(created.task_id.clone()),
                });
                return ApiResponse::ok(ApprovalView {
                    id: created.id,
                    status: "pending".into(),
                    task_id: Some(created.task_id),
                    source: Some("broker+store".into()),
                });
            }
            Err(StoreError::Conflict(_)) => match store.get_approval(&req.id).await {
                Ok(Some(existing)) => {
                    // Idempotent replay only for the same create payload; fail closed on drift.
                    if existing.task_id != expected_task_id
                        || existing.tool != expected_tool
                        || existing.args_hash != expected_args_hash
                    {
                        return ApiResponse::conflict(
                            "approval create conflict with different payload (fail-closed)",
                        );
                    }
                    return ApiResponse::ok(ApprovalView {
                        id: existing.id,
                        status: format!("{:?}", existing.status).to_lowercase(),
                        task_id: Some(existing.task_id),
                        source: Some("broker+store".into()),
                    });
                }
                Ok(None) => {
                    return ApiResponse::conflict(
                        "approval create conflict but store record missing (fail-closed)",
                    );
                }
                Err(e) => return map_store_err(e),
            },
            Err(e) => return map_store_err(e),
        }
    }

    // resolve path
    let Some(decision) = approval_status_from_str(action)
        .or_else(|| req.decision.as_deref().and_then(approval_status_from_str))
    else {
        return ApiResponse::bad_request("decision/action must be create|approve|deny|timeout");
    };
    let store_status = match decision {
        ApprovalStatus::Approved => store::ApprovalStatus::Approved,
        ApprovalStatus::Denied => store::ApprovalStatus::Denied,
        // Preserve timeout semantics in durable store records.
        ApprovalStatus::TimedOut => store::ApprovalStatus::Expired,
        ApprovalStatus::Pending => store::ApprovalStatus::Pending,
    };
    // Persist first so durable store remains source of truth before returning.
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
            // Update broker best-effort for in-process consistency.
            let _ = state.approvals.resolve(&req.id, decision, now);
            state.emit_event(crate::state::StreamEvent {
                kind: "approval.resolved".into(),
                message: format!("{}:{:?}", r.id, r.status),
                task_id: None,
            });
            ApiResponse::ok(ApprovalView {
                id: r.id,
                status: format!("{:?}", r.status).to_lowercase(),
                task_id: Some(r.task_id),
                source: Some("broker+store".into()),
            })
        }
        Err(StoreError::Conflict(msg)) if msg.contains("approval not pending") => {
            match store.get_approval(&req.id).await {
                Ok(Some(existing)) if existing.status == store_status => {
                    // Idempotent resolve replay for the same terminal decision.
                    let _ = state.approvals.resolve(&req.id, decision, now);
                    ApiResponse::ok(ApprovalView {
                        id: existing.id,
                        status: format!("{:?}", existing.status).to_lowercase(),
                        task_id: Some(existing.task_id),
                        source: Some("broker+store".into()),
                    })
                }
                Ok(Some(existing)) => ApiResponse::conflict(format!(
                    "approval {} already resolved as {:?}",
                    existing.id, existing.status
                )),
                Ok(None) => ApiResponse::conflict(msg),
                Err(e) => map_store_err(e),
            }
        }
        Err(e) => map_store_err(e),
    }
}

fn approval_status_matches_filter(status: store::ApprovalStatus, filter: &str) -> bool {
    let f = filter.to_ascii_lowercase();
    match status {
        store::ApprovalStatus::Pending => matches!(f.as_str(), "pending"),
        store::ApprovalStatus::Approved => matches!(f.as_str(), "approved" | "approve"),
        store::ApprovalStatus::Denied => matches!(f.as_str(), "denied" | "deny" | "rejected"),
        store::ApprovalStatus::Expired => {
            matches!(f.as_str(), "expired" | "timeout" | "timed_out")
        }
    }
}

pub async fn handle_v1_approvals_list(
    state: &AppState,
    req: ApprovalListQueryRequest,
) -> ApiResponse<ApprovalListResponse> {
    let Some(store) = &state.store else {
        return ApiResponse::unavailable("store unavailable (fail-closed)");
    };

    // Read matching records from durable store as source of truth, and union broker-known IDs
    // for consistency (including pending approvals rehydrated at startup).
    let store_status_filter = match req.status.as_deref() {
        Some(s) => match s.to_ascii_lowercase().as_str() {
            "pending" => Some(store::ApprovalStatus::Pending),
            "approved" | "approve" => Some(store::ApprovalStatus::Approved),
            "denied" | "deny" | "rejected" => Some(store::ApprovalStatus::Denied),
            "expired" | "timeout" | "timed_out" => Some(store::ApprovalStatus::Expired),
            _ => return ApiResponse::bad_request("invalid approval status filter"),
        },
        None => None,
    };

    let mut approvals = match store
        .list_approvals(store::ApprovalQuery {
            task_id: req.task_id.clone(),
            status: store_status_filter,
            ..Default::default()
        })
        .await
    {
        Ok(v) => v,
        Err(e) => return map_store_err(e),
    };

    // Include broker-known records that may not be captured by the filtered store query
    // (best-effort consistency with in-process state).
    let mut seen = approvals
        .iter()
        .map(|a| a.id.clone())
        .collect::<std::collections::HashSet<_>>();
    let mut ids = state
        .approvals
        .snapshot()
        .into_iter()
        .map(|r| r.request.id)
        .collect::<Vec<_>>();
    ids.sort();
    ids.dedup();
    for id in ids {
        if seen.contains(&id) {
            continue;
        }
        match store.get_approval(&id).await {
            Ok(Some(rec)) => {
                if let Some(task_id) = &req.task_id {
                    if &rec.task_id != task_id {
                        continue;
                    }
                }
                if let Some(status) = &req.status {
                    if !approval_status_matches_filter(rec.status, status) {
                        continue;
                    }
                }
                seen.insert(rec.id.clone());
                approvals.push(rec);
            }
            Ok(None) => {}
            Err(e) => return map_store_err(e),
        }
    }

    approvals.sort_by(|a, b| a.created_at.cmp(&b.created_at).then(a.id.cmp(&b.id)));
    approvals.dedup_by(|a, b| a.id == b.id);
    if let Some(limit) = req.limit {
        approvals.truncate(limit as usize);
    }

    ApiResponse::ok(ApprovalListResponse { approvals })
}

pub async fn handle_v1_approval_get(
    state: &AppState,
    id: &str,
) -> ApiResponse<store::ApprovalRecord> {
    let Some(store) = &state.store else {
        return ApiResponse::unavailable("store unavailable (fail-closed)");
    };
    if id.trim().is_empty() {
        return ApiResponse::bad_request("approval id required");
    }
    match store.get_approval(id).await {
        Ok(Some(rec)) => ApiResponse::ok(rec),
        Ok(None) => ApiResponse::fail(HttpStatus::NotFound, "approval not found"),
        Err(e) => map_store_err(e),
    }
}

pub async fn handle_v1_approval_resolve(
    state: &mut AppState,
    id: &str,
    req: ApprovalPathResolveRequest,
) -> ApiResponse<ApprovalView> {
    if id.trim().is_empty() {
        return ApiResponse::bad_request("approval id required");
    }
    let action = req
        .action
        .as_deref()
        .or(req.decision.as_deref())
        .unwrap_or("");
    if action.trim().is_empty() || matches!(action, "create" | "pending") {
        return ApiResponse::bad_request("decision/action must be approve|deny|timeout");
    }
    handle_v1_approvals(
        state,
        ApprovalDecisionRequest {
            id: id.to_string(),
            action: req.action,
            decision: req.decision,
            principal: req.principal,
            tool: None,
            resource: None,
            reason: None,
            expires_at: None,
            now: req.now,
            args_hash: None,
        },
    )
    .await
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
                version: Some(p.version),
                created_at: Some(p.created_at),
                body: serde_json::from_str(&p.body).ok(),
            }),
            Err(e) => map_store_err(e),
        }
    } else {
        match store.get_active_policy().await {
            Ok(Some(p)) => ApiResponse::ok(PolicyView {
                id: p.id,
                active: p.active,
                version: Some(p.version),
                created_at: Some(p.created_at),
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

    fn deny_all_rules_state() -> AppState {
        let mut s = AppState::fail_closed().with_store(Arc::new(InMemoryStore::default()));
        s.config = s.config.clone().with_rules(vec![Rule::exact(
            "agent",
            "tool.invoke",
            "tool",
            PolicyDecision::Forbid,
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
    fn task_get_and_revoke_endpoints() {
        rt().block_on(async {
            let mut st = state_with_store();
            let _ = handle_v1_tasks(&mut st, task_req()).await;

            let got = handle_v1_task_get(&st, "t1").await;
            assert_eq!(got.status, HttpStatus::Ok);
            let task = got.body.unwrap();
            assert_eq!(task.id, "t1");
            assert!(!task.revoked);

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
            let task = revoked.body.unwrap();
            assert!(task.revoked);
            assert_eq!(task.revocation_reason.as_deref(), Some("manual"));

            let missing = handle_v1_task_get(&st, "nope").await;
            assert_eq!(missing.status, HttpStatus::NotFound);
            assert!(missing.fail_closed);

            let missing_revoke =
                handle_v1_task_revoke(&st, "nope", TaskRevokeRequest::default()).await;
            assert_eq!(missing_revoke.status, HttpStatus::NotFound);
            assert!(missing_revoke.fail_closed);
        });
    }

    #[test]
    fn task_get_and_revoke_fail_closed_without_store() {
        rt().block_on(async {
            let st = AppState::fail_closed();
            let got = handle_v1_task_get(&st, "t1").await;
            assert_eq!(got.status, HttpStatus::ServiceUnavailable);
            assert!(got.fail_closed);
            let revoked = handle_v1_task_revoke(&st, "t1", TaskRevokeRequest::default()).await;
            assert_eq!(revoked.status, HttpStatus::ServiceUnavailable);
            assert!(revoked.fail_closed);
        });
    }

    #[test]
    fn task_get_and_revoke_validate_id() {
        rt().block_on(async {
            let st = state_with_store();
            let got = handle_v1_task_get(&st, " ").await;
            assert_eq!(got.status, HttpStatus::BadRequest);
            assert!(got.fail_closed);
            let revoked = handle_v1_task_revoke(&st, "", TaskRevokeRequest::default()).await;
            assert_eq!(revoked.status, HttpStatus::BadRequest);
            assert!(revoked.fail_closed);
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
    fn approval_resolve_is_idempotent_for_same_decision() {
        rt().block_on(async {
            let mut st = state_with_store();
            let _ = handle_v1_approvals(
                &mut st,
                ApprovalDecisionRequest {
                    id: "a-idem".into(),
                    action: Some("create".into()),
                    principal: Some("u".into()),
                    tool: Some("act".into()),
                    resource: Some("task-x".into()),
                    now: Some(1),
                    ..Default::default()
                },
            )
            .await;
            let first = handle_v1_approval_resolve(
                &mut st,
                "a-idem",
                ApprovalPathResolveRequest {
                    action: Some("approve".into()),
                    now: Some(2),
                    ..Default::default()
                },
            )
            .await;
            assert_eq!(first.status, HttpStatus::Ok);
            let second = handle_v1_approval_resolve(
                &mut st,
                "a-idem",
                ApprovalPathResolveRequest {
                    action: Some("approve".into()),
                    now: Some(3),
                    ..Default::default()
                },
            )
            .await;
            assert_eq!(second.status, HttpStatus::Ok);
            let body = second.body.unwrap();
            assert_eq!(body.status, "approved");
            assert_eq!(body.task_id.as_deref(), Some("task-x"));
        });
    }

    #[test]
    fn approval_list_rejects_invalid_status_filter() {
        rt().block_on(async {
            let st = state_with_store();
            let resp = handle_v1_approvals_list(
                &st,
                ApprovalListQueryRequest {
                    status: Some("bogus".into()),
                    ..Default::default()
                },
            )
            .await;
            assert_eq!(resp.status, HttpStatus::BadRequest);
            assert!(resp.fail_closed);
        });
    }

    #[test]
    fn approvals_list_get_and_path_resolve() {
        rt().block_on(async {
            let mut st = state_with_store();
            let _ = handle_v1_approvals(
                &mut st,
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
            let _ = handle_v1_approvals(
                &mut st,
                ApprovalDecisionRequest {
                    id: "a2".into(),
                    action: Some("create".into()),
                    principal: Some("u".into()),
                    tool: Some("act2".into()),
                    resource: Some("task-b".into()),
                    now: Some(1),
                    ..Default::default()
                },
            )
            .await;

            let list = handle_v1_approvals_list(&st, ApprovalListQueryRequest::default()).await;
            assert_eq!(list.status, HttpStatus::Ok);
            assert_eq!(list.body.unwrap().approvals.len(), 2);

            let filtered = handle_v1_approvals_list(
                &st,
                ApprovalListQueryRequest {
                    task_id: Some("task-a".into()),
                    status: Some("pending".into()),
                    limit: Some(10),
                },
            )
            .await;
            assert_eq!(filtered.status, HttpStatus::Ok);
            let approvals = filtered.body.unwrap().approvals;
            assert_eq!(approvals.len(), 1);
            assert_eq!(approvals[0].id, "a1");

            let got = handle_v1_approval_get(&st, "a1").await;
            assert_eq!(got.status, HttpStatus::Ok);
            assert_eq!(got.body.unwrap().task_id, "task-a");

            let resolved = handle_v1_approval_resolve(
                &mut st,
                "a2",
                ApprovalPathResolveRequest {
                    action: Some("deny".into()),
                    principal: Some("admin".into()),
                    now: Some(3),
                    ..Default::default()
                },
            )
            .await;
            assert_eq!(resolved.status, HttpStatus::Ok);
            assert_eq!(resolved.body.unwrap().status, "denied");

            let missing = handle_v1_approval_get(&st, "nope").await;
            assert_eq!(missing.status, HttpStatus::NotFound);
            assert!(missing.fail_closed);
        });
    }

    #[test]
    fn approvals_list_get_resolve_fail_closed_without_store() {
        rt().block_on(async {
            let mut st = AppState::fail_closed();
            let list = handle_v1_approvals_list(&st, ApprovalListQueryRequest::default()).await;
            assert_eq!(list.status, HttpStatus::ServiceUnavailable);
            assert!(list.fail_closed);

            let got = handle_v1_approval_get(&st, "a1").await;
            assert_eq!(got.status, HttpStatus::ServiceUnavailable);
            assert!(got.fail_closed);

            let resolved = handle_v1_approval_resolve(
                &mut st,
                "a1",
                ApprovalPathResolveRequest {
                    action: Some("approve".into()),
                    ..Default::default()
                },
            )
            .await;
            assert_eq!(resolved.status, HttpStatus::ServiceUnavailable);
            assert!(resolved.fail_closed);
        });
    }

    #[test]
    fn approval_get_and_path_resolve_validate_id() {
        rt().block_on(async {
            let mut st = state_with_store();
            let got = handle_v1_approval_get(&st, "").await;
            assert_eq!(got.status, HttpStatus::BadRequest);
            assert!(got.fail_closed);
            let resolved = handle_v1_approval_resolve(
                &mut st,
                " ",
                ApprovalPathResolveRequest {
                    action: Some("approve".into()),
                    ..Default::default()
                },
            )
            .await;
            assert_eq!(resolved.status, HttpStatus::BadRequest);
            assert!(resolved.fail_closed);
        });
    }

    #[test]
    fn approvals_list_reads_store_records_even_without_broker_snapshot() {
        rt().block_on(async {
            let st = state_with_store();
            let store = st.store.clone().unwrap();
            store
                .create_approval(store::ApprovalRecord {
                    id: "rehyd".into(),
                    task_id: "task-rehyd".into(),
                    tool: "act".into(),
                    args_hash: "h".into(),
                    status: store::ApprovalStatus::Pending,
                    created_at: "1".into(),
                    resolved_at: None,
                    resolver: None,
                })
                .await
                .unwrap();

            let list = handle_v1_approvals_list(&st, ApprovalListQueryRequest::default()).await;
            assert_eq!(list.status, HttpStatus::Ok);
            let approvals = list.body.unwrap().approvals;
            assert_eq!(approvals.len(), 1);
            assert_eq!(approvals[0].id, "rehyd");
            assert_eq!(approvals[0].task_id, "task-rehyd");
        });
    }

    #[test]
    fn denied_task_persists_deny_audit_before_return() {
        rt().block_on(async {
            let mut st = deny_all_rules_state();
            let resp = handle_v1_tasks(&mut st, task_req()).await;
            assert_eq!(resp.status, HttpStatus::Forbidden);
            assert!(resp.fail_closed);
            assert_eq!(resp.body.as_ref().unwrap().state, "denied");

            let audit = handle_v1_audit(
                &st,
                AuditQueryRequest {
                    task_id: Some("t1".into()),
                    ..Default::default()
                },
            )
            .await;
            assert_eq!(audit.status, HttpStatus::Ok);
            let events = audit.body.unwrap().events;
            assert!(!events.is_empty());
            assert_eq!(events.last().unwrap().decision, "denied");
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

    #[test]
    fn tasks_require_token_and_fail_closed_on_bad_input() {
        rt().block_on(async {
            let mut st = state_with_store();
            let mut bad = task_req();
            bad.token = None;
            let resp = handle_v1_tasks(&mut st, bad).await;
            assert_eq!(resp.status, HttpStatus::BadRequest);
            assert!(resp.fail_closed);
            assert!(resp.error.unwrap_or_default().contains("token"));
        });
    }

    #[test]
    fn tasks_require_core_fields() {
        rt().block_on(async {
            let mut st = state_with_store();
            for req in [
                {
                    let mut r = task_req();
                    r.task_id = "".into();
                    r
                },
                {
                    let mut r = task_req();
                    r.principal = " ".into();
                    r
                },
                {
                    let mut r = task_req();
                    r.action = "".into();
                    r
                },
                {
                    let mut r = task_req();
                    r.resource = "".into();
                    r
                },
            ] {
                let resp = handle_v1_tasks(&mut st, req).await;
                assert_eq!(resp.status, HttpStatus::BadRequest);
                assert!(resp.fail_closed);
            }
        });
    }

    #[test]
    fn task_create_duplicate_is_conflict() {
        rt().block_on(async {
            let mut st = state_with_store();
            let first = handle_v1_tasks(&mut st, task_req()).await;
            assert_eq!(first.status, HttpStatus::Ok);
            let second = handle_v1_tasks(&mut st, task_req()).await;
            assert_eq!(second.status, HttpStatus::Conflict);
            assert!(second.fail_closed);
            assert!(second.error.unwrap_or_default().contains("already exists"));
        });
    }

    #[test]
    fn task_revoke_is_idempotent() {
        rt().block_on(async {
            let mut st = state_with_store();
            let _ = handle_v1_tasks(&mut st, task_req()).await;
            let first = handle_v1_task_revoke(
                &st,
                "t1",
                TaskRevokeRequest {
                    reason: Some("manual".into()),
                    revoked_by: Some("admin".into()),
                    ..Default::default()
                },
            )
            .await;
            assert_eq!(first.status, HttpStatus::Ok);
            assert!(first.body.as_ref().unwrap().revoked);
            let second = handle_v1_task_revoke(&st, "t1", TaskRevokeRequest::default()).await;
            assert_eq!(second.status, HttpStatus::Ok);
            let body = second.body.unwrap();
            assert!(body.revoked);
            assert_eq!(body.revocation_reason.as_deref(), Some("manual"));
        });
    }

    #[test]
    fn policy_view_includes_metadata() {
        rt().block_on(async {
            let st = state_with_store();
            let up = handle_v1_policies(
                &st,
                Some(PolicyUpsertRequest {
                    id: "p-meta".into(),
                    body: r#"{"allow":true}"#.into(),
                    version: Some(7),
                    active: Some(true),
                    rule: None,
                }),
            )
            .await;
            assert_eq!(up.status, HttpStatus::Ok);
            let body = up.body.unwrap();
            assert_eq!(body.id, "p-meta");
            assert_eq!(body.version, Some(7));
            assert!(body.created_at.is_some());
            assert!(body.body.is_some());
        });
    }

    #[test]
    fn approval_create_conflict_is_store_backed_and_timeout_maps_to_expired() {
        rt().block_on(async {
            let mut st = state_with_store();
            let created = handle_v1_approvals(
                &mut st,
                ApprovalDecisionRequest {
                    id: "a-conf".into(),
                    action: Some("create".into()),
                    principal: Some("u".into()),
                    tool: Some("act".into()),
                    resource: Some("task-x".into()),
                    now: Some(1),
                    ..Default::default()
                },
            )
            .await;
            assert_eq!(created.status, HttpStatus::Ok);
            let created_body = created.body.unwrap();
            assert_eq!(created_body.status, "pending");
            assert_eq!(created_body.task_id.as_deref(), Some("task-x"));

            // idempotent create returns existing pending record
            let created_again = handle_v1_approvals(
                &mut st,
                ApprovalDecisionRequest {
                    id: "a-conf".into(),
                    action: Some("create".into()),
                    principal: Some("u".into()),
                    tool: Some("act".into()),
                    resource: Some("task-x".into()),
                    now: Some(2),
                    ..Default::default()
                },
            )
            .await;
            assert_eq!(created_again.status, HttpStatus::Ok);
            assert_eq!(created_again.body.unwrap().status, "pending");

            // mismatched create payload for same ID fails closed as conflict
            let mismatched = handle_v1_approvals(
                &mut st,
                ApprovalDecisionRequest {
                    id: "a-conf".into(),
                    action: Some("create".into()),
                    principal: Some("u".into()),
                    tool: Some("different-tool".into()),
                    resource: Some("task-x".into()),
                    now: Some(2),
                    ..Default::default()
                },
            )
            .await;
            assert_eq!(mismatched.status, HttpStatus::Conflict);
            assert!(mismatched.fail_closed);
            assert!(mismatched
                .error
                .unwrap_or_default()
                .contains("different payload"));

            // timeout resolves to expired in store-backed view
            let timed_out = handle_v1_approval_resolve(
                &mut st,
                "a-conf",
                ApprovalPathResolveRequest {
                    action: Some("timeout".into()),
                    principal: Some("system".into()),
                    now: Some(3),
                    ..Default::default()
                },
            )
            .await;
            assert_eq!(timed_out.status, HttpStatus::Ok);
            let to_body = timed_out.body.unwrap();
            assert_eq!(to_body.status, "expired");
            assert_eq!(to_body.task_id.as_deref(), Some("task-x"));

            let rec = handle_v1_approval_get(&st, "a-conf").await.body.unwrap();
            assert_eq!(rec.status, store::ApprovalStatus::Expired);

            // idempotent create replay after terminal resolution remains store-backed
            let replay_after_timeout = handle_v1_approvals(
                &mut st,
                ApprovalDecisionRequest {
                    id: "a-conf".into(),
                    action: Some("create".into()),
                    principal: Some("u".into()),
                    tool: Some("act".into()),
                    resource: Some("task-x".into()),
                    now: Some(4),
                    ..Default::default()
                },
            )
            .await;
            assert_eq!(replay_after_timeout.status, HttpStatus::Ok);
            assert_eq!(replay_after_timeout.body.unwrap().status, "expired");
        });
    }

    #[test]
    fn audit_verify_endpoint_reports_store_state() {
        rt().block_on(async {
            let mut st = state_with_store();
            let _ = handle_v1_tasks(&mut st, task_req()).await;
            let resp = handle_v1_audit_verify(&st).await;
            assert_eq!(resp.status, HttpStatus::Ok);
            assert!(resp.body.unwrap().ok);
        });
    }

    #[test]
    fn audit_endpoints_fail_closed_without_store() {
        rt().block_on(async {
            let st = AppState::fail_closed();
            let q = handle_v1_audit(&st, AuditQueryRequest::default()).await;
            assert_eq!(q.status, HttpStatus::ServiceUnavailable);
            assert!(q.fail_closed);
            let v = handle_v1_audit_verify(&st).await;
            assert_eq!(v.status, HttpStatus::ServiceUnavailable);
            assert!(v.fail_closed);
        });
    }

    #[test]
    fn policies_store_backed_get_and_upsert_fail_closed_without_store() {
        rt().block_on(async {
            let st = AppState::fail_closed();
            let got = handle_v1_policies(&st, None).await;
            assert_eq!(got.status, HttpStatus::ServiceUnavailable);
            assert!(got.fail_closed);
            let up = handle_v1_policies(
                &st,
                Some(PolicyUpsertRequest {
                    id: "p".into(),
                    body: "{}".into(),
                    ..Default::default()
                }),
            )
            .await;
            assert_eq!(up.status, HttpStatus::ServiceUnavailable);
            assert!(up.fail_closed);
        });
    }

    #[test]
    fn policies_get_returns_not_found_when_no_active_policy() {
        rt().block_on(async {
            let st = state_with_store();
            let got = handle_v1_policies(&st, None).await;
            assert_eq!(got.status, HttpStatus::NotFound);
            assert!(got.fail_closed);
        });
    }

    #[test]
    fn policies_upsert_requires_id() {
        rt().block_on(async {
            let st = state_with_store();
            let up = handle_v1_policies(
                &st,
                Some(PolicyUpsertRequest {
                    id: " ".into(),
                    body: "{}".into(),
                    ..Default::default()
                }),
            )
            .await;
            assert_eq!(up.status, HttpStatus::BadRequest);
            assert!(up.fail_closed);
        });
    }

    #[test]
    fn task_audit_policy_flows_survive_restart_persisted_store_state() {
        rt().block_on(async {
            let store = Arc::new(InMemoryStore::default()) as Arc<dyn store::Store>;

            // "Pre-restart" state: create task, upsert active policy.
            let mut st1 = AppState::fail_closed().with_store(store.clone());
            st1.config = st1.config.clone().with_rules(vec![Rule::exact(
                "agent",
                "tool.invoke",
                "tool",
                PolicyDecision::Permit,
            )]);

            let created = handle_v1_tasks(&mut st1, task_req()).await;
            assert_eq!(created.status, HttpStatus::Ok);

            let policy_up = handle_v1_policies(
                &st1,
                Some(PolicyUpsertRequest {
                    id: "p-restart".into(),
                    body: r#"{"allow":"persisted"}"#.into(),
                    version: Some(1),
                    active: Some(true),
                    rule: None,
                }),
            )
            .await;
            assert_eq!(policy_up.status, HttpStatus::Ok);

            // "Post-restart" fresh state against same durable store.
            let mut st2 = AppState::fail_closed().with_store(store.clone());
            st2.config = st2.config.clone().with_rules(vec![Rule::exact(
                "agent",
                "tool.invoke",
                "tool",
                PolicyDecision::Permit,
            )]);

            let got = handle_v1_task_get(&st2, "t1").await;
            assert_eq!(got.status, HttpStatus::Ok);
            let list = handle_v1_tasks_list(&st2).await;
            assert_eq!(list.status, HttpStatus::Ok);
            assert_eq!(list.body.unwrap().tasks.len(), 1);

            let dup = handle_v1_tasks(&mut st2, task_req()).await;
            assert_eq!(dup.status, HttpStatus::Conflict);
            assert!(dup.fail_closed);

            let audit = handle_v1_audit(
                &st2,
                AuditQueryRequest {
                    task_id: Some("t1".into()),
                    ..Default::default()
                },
            )
            .await;
            assert_eq!(audit.status, HttpStatus::Ok);
            let audit_body = audit.body.unwrap();
            assert!(!audit_body.events.is_empty());
            assert!(audit_body.chain_verified);
            let verify = handle_v1_audit_verify(&st2).await;
            assert_eq!(verify.status, HttpStatus::Ok);
            assert!(verify.body.unwrap().ok);

            let policy = handle_v1_policies(&st2, None).await;
            assert_eq!(policy.status, HttpStatus::Ok);
            assert_eq!(policy.body.unwrap().id, "p-restart");
        });
    }

    #[test]
    fn approval_flows_survive_restart_persisted_store_state() {
        rt().block_on(async {
            let store = Arc::new(InMemoryStore::default()) as Arc<dyn store::Store>;

            // Pre-restart: create pending approvals in durable store.
            let mut st1 = AppState::fail_closed().with_store(store.clone());
            let created = handle_v1_approvals(
                &mut st1,
                ApprovalDecisionRequest {
                    id: "a-restart".into(),
                    action: Some("create".into()),
                    principal: Some("u".into()),
                    tool: Some("act".into()),
                    resource: Some("task-r".into()),
                    now: Some(1),
                    ..Default::default()
                },
            )
            .await;
            assert_eq!(created.status, HttpStatus::Ok);

            let _ = handle_v1_approvals(
                &mut st1,
                ApprovalDecisionRequest {
                    id: "a-restart-timeout".into(),
                    action: Some("create".into()),
                    principal: Some("u".into()),
                    tool: Some("act".into()),
                    resource: Some("task-t".into()),
                    now: Some(1),
                    ..Default::default()
                },
            )
            .await;

            // Post-restart: fresh broker/runtime state, same durable store.
            let mut st2 = AppState::fail_closed().with_store(store.clone());

            let listed = handle_v1_approvals_list(&st2, ApprovalListQueryRequest::default()).await;
            assert_eq!(listed.status, HttpStatus::Ok);
            assert_eq!(listed.body.unwrap().approvals.len(), 2);

            let got = handle_v1_approval_get(&st2, "a-restart").await;
            assert_eq!(got.status, HttpStatus::Ok);
            assert_eq!(got.body.unwrap().status, store::ApprovalStatus::Pending);

            // Resolve after restart must persist durably and be idempotent.
            let resolved = handle_v1_approval_resolve(
                &mut st2,
                "a-restart",
                ApprovalPathResolveRequest {
                    action: Some("approve".into()),
                    principal: Some("admin".into()),
                    now: Some(2),
                    ..Default::default()
                },
            )
            .await;
            assert_eq!(resolved.status, HttpStatus::Ok);
            assert_eq!(resolved.body.unwrap().status, "approved");

            let resolved_again = handle_v1_approval_resolve(
                &mut st2,
                "a-restart",
                ApprovalPathResolveRequest {
                    action: Some("approve".into()),
                    now: Some(3),
                    ..Default::default()
                },
            )
            .await;
            assert_eq!(resolved_again.status, HttpStatus::Ok);

            let timed = handle_v1_approval_resolve(
                &mut st2,
                "a-restart-timeout",
                ApprovalPathResolveRequest {
                    action: Some("timeout".into()),
                    now: Some(3),
                    ..Default::default()
                },
            )
            .await;
            assert_eq!(timed.status, HttpStatus::Ok);
            assert_eq!(timed.body.unwrap().status, "expired");

            // "Restart again": durable terminal states remain visible/correct.
            let st3 = AppState::fail_closed().with_store(store);
            let got_a = handle_v1_approval_get(&st3, "a-restart").await;
            assert_eq!(got_a.body.unwrap().status, store::ApprovalStatus::Approved);
            let got_t = handle_v1_approval_get(&st3, "a-restart-timeout").await;
            assert_eq!(got_t.body.unwrap().status, store::ApprovalStatus::Expired);
            let filtered = handle_v1_approvals_list(
                &st3,
                ApprovalListQueryRequest {
                    status: Some("approved".into()),
                    ..Default::default()
                },
            )
            .await;
            assert_eq!(filtered.status, HttpStatus::Ok);
            assert_eq!(filtered.body.unwrap().approvals.len(), 1);
        });
    }

    #[test]
    fn task_create_syncs_durable_revocations_fail_closed_before_lifecycle() {
        rt().block_on(async {
            let store = Arc::new(InMemoryStore::default()) as Arc<dyn store::Store>;
            store
                .record_revocation(store::RevocationRecord {
                    id: "rev-1".into(),
                    target_kind: "token".into(),
                    target_id: "r1".into(),
                    reason: Some("compromised".into()),
                    revoked_at: "1".into(),
                    revoked_by: Some("admin".into()),
                })
                .await
                .unwrap();

            let mut st = AppState::fail_closed().with_store(store);
            st.config = st.config.clone().with_rules(vec![Rule::exact(
                "agent",
                "tool.invoke",
                "tool",
                PolicyDecision::Permit,
            )]);
            st.config.runtime_hooks.sync_revocations_from_store = true;

            // No manual sync: API path must prepare runtime hooks and deny with restored revocation.
            let resp = handle_v1_tasks(&mut st, task_req()).await;
            assert_eq!(resp.status, HttpStatus::Forbidden);
            assert!(resp.fail_closed);
            let body = resp.body.unwrap();
            assert_eq!(body.state, "denied");
            assert!(body
                .error
                .as_deref()
                .unwrap_or_default()
                .contains("InvalidToken"));
            assert!(st.config.revoked_token_ids.iter().any(|id| id == "r1"));
        });
    }

    #[test]
    fn task_create_fails_closed_when_required_revocation_sync_store_missing() {
        rt().block_on(async {
            let mut st = AppState::fail_closed();
            st.config = st.config.clone().with_rules(vec![Rule::exact(
                "agent",
                "tool.invoke",
                "tool",
                PolicyDecision::Permit,
            )]);
            st.config.runtime_hooks.sync_revocations_from_store = true;

            let resp = handle_v1_tasks(&mut st, task_req()).await;
            assert_eq!(resp.status, HttpStatus::ServiceUnavailable);
            assert!(resp.fail_closed);
            let err = resp.error.unwrap_or_default();
            assert!(
                err.contains("store unavailable")
                    || err.contains("runtime hook preparation failed"),
                "unexpected error: {err}"
            );
        });
    }
}
