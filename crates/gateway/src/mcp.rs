//! MCP endpoint dispatch: front parse/shape + pool dispatch + store-backed audit/policy/approvals.

use mcp_pool::TransportSpec;
use scopegate_core::audit::digest;
use scopegate_core::policy::{
    evaluate, Action, ApprovalAnnotation, BudgetHint, CallCountHint, Context, PolicyDecision,
    PolicyRequest, Principal, RateLimitHint, Resource, TaintHint,
};
// rate tracker hooks accessed via AppState; core types used through policy/token imports above.
use scopegate_core::taint::{OperationTarget, SessionTaint, TaintDecision, TaintLabel};
use scopegate_core::token::{Budget, Expiry, RevocationId, Scope, TaskToken};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use store::{
    ApprovalRecord, ApprovalStatus as StoreApprovalStatus, AuditEvent, TaintSnapshotQuery,
    TaintSnapshotRecord, TaskRecord, ToolPinRecord,
};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;
use tokio::time::{timeout, Duration};

use crate::state::{AppState, StreamEvent};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct McpEndpoint;
impl McpEndpoint {
    pub const PATH: &'static str = "/mcp";
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpRequest {
    #[serde(default)]
    pub method: String,
    #[serde(default)]
    pub payload_json: String,
    /// Optional upstream selector for pool dispatch.
    #[serde(default)]
    pub upstream: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpHttpContext {
    /// Optional Authorization header value from HTTP transport.
    #[serde(default)]
    pub authorization: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpResponse {
    pub ok: bool,
    pub payload_json: String,
    pub fail_closed: bool,
}

fn emit(state: &AppState, kind: &str, message: &str, task_id: Option<String>) {
    state.emit_event(StreamEvent {
        kind: kind.into(),
        message: message.into(),
        task_id,
    });
}

fn scrub_secret_value_at(text: &str, start: usize) -> usize {
    let bytes = text.as_bytes();
    let mut end = start;
    while end < bytes.len() {
        let b = bytes[end];
        if b.is_ascii_whitespace()
            || matches!(b, b'"' | b'\'' | b',' | b'}' | b']' | b')' | b';' | b'&')
        {
            break;
        }
        end += 1;
    }
    end
}

fn redact_secret_markers(text: &str) -> (String, bool) {
    let mut out = text.to_string();
    let mut changed = false;

    // Redact key=value secret assignments.
    for marker in ["api_key=", "password=", "secret=", "token="] {
        let mut search_from = 0;
        while let Some(rel) = out[search_from..].to_lowercase().find(marker) {
            let idx = search_from + rel;
            let val_start = idx + marker.len();
            let val_end = scrub_secret_value_at(&out, val_start);
            if val_end > val_start {
                out.replace_range(idx..val_end, "[REDACTED]");
                changed = true;
                search_from = idx + "[REDACTED]".len();
            } else {
                search_from = val_start;
            }
        }
    }

    // Redact common secret prefixes/tokens.
    for marker in ["sk-", "AKIA", "-----BEGIN"] {
        let mut search_from = 0;
        while let Some(rel) = out[search_from..].find(marker) {
            let idx = search_from + rel;
            if marker == "-----BEGIN" {
                if let Some(end_rel) = out[idx..].find("-----END") {
                    let after_end = idx + end_rel;
                    if let Some(line_end_rel) = out[after_end..].find("-----") {
                        let end = after_end + line_end_rel + 5;
                        out.replace_range(idx..end, "[REDACTED]");
                        changed = true;
                        search_from = idx + "[REDACTED]".len();
                        continue;
                    }
                }
                out.replace_range(idx..out.len(), "[REDACTED]");
                changed = true;
                break;
            } else {
                let end = scrub_secret_value_at(&out, idx);
                if end > idx + marker.len() {
                    out.replace_range(idx..end, "[REDACTED]");
                    changed = true;
                    search_from = idx + "[REDACTED]".len();
                } else {
                    search_from = idx + marker.len();
                }
            }
        }
    }
    (out, changed)
}

fn scrub_agent_visible_payload(payload: &str) -> Result<String, String> {
    let (redacted, changed) = redact_secret_markers(payload);
    // Fail closed if redaction produced empty/invalid JSON boundary for structured payloads we own?
    // We only redact string content; keep payload. Marker scan is best-effort but enforced.
    let markers = ["sk-", "AKIA", "-----BEGIN", "password=", "api_key="];
    let lower = redacted.to_lowercase();
    if markers.iter().any(|m| lower.contains(&m.to_lowercase())) {
        // Secret-handling path could not be safely applied.
        return Err("secret_redaction_incomplete".into());
    }
    if changed {
        // Ensure redacted payload remains valid JSON when original was JSON object/array; if not, fail closed.
        let trimmed = redacted.trim_start();
        if trimmed.starts_with('{') || trimmed.starts_with('[') {
            serde_json::from_str::<Value>(&redacted)
                .map_err(|_| "secret_redaction_invalid_payload".to_string())?;
        }
    }
    Ok(redacted)
}

fn finalize_mcp_response(mut resp: McpResponse) -> McpResponse {
    match scrub_agent_visible_payload(&resp.payload_json) {
        Ok(scrubbed) => {
            resp.payload_json = scrubbed;
            resp
        }
        Err(reason) => McpResponse {
            ok: false,
            payload_json: json!({
                "jsonrpc":"2.0",
                "id": Value::Null,
                "error":{"code": -32003, "message":"Secret redaction failed (fail-closed)"},
                "fail_closed": true,
                "reason": reason
            })
            .to_string(),
            fail_closed: true,
        },
    }
}

fn jsonrpc_error(id: Value, code: i64, message: &str) -> McpResponse {
    finalize_mcp_response(McpResponse {
        ok: false,
        payload_json: json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":message},"fail_closed":true})
            .to_string(),
        fail_closed: true,
    })
}

fn parse_raw(req: &McpRequest) -> Result<Value, McpResponse> {
    let raw = if !req.payload_json.trim().is_empty() {
        req.payload_json.as_str()
    } else if !req.method.trim().is_empty() {
        req.method.as_str()
    } else {
        ""
    };
    if raw.trim().is_empty() {
        return Err(jsonrpc_error(
            Value::Null,
            -32600,
            "invalid request (fail-closed)",
        ));
    }
    serde_json::from_str::<Value>(raw).map_err(|_| {
        // tolerate simple envelope: treat non-json method as tools/call name hint -> fail closed parse
        jsonrpc_error(Value::Null, -32700, "parse error (fail-closed)")
    })
}

async fn append_mcp_audit(
    state: &mut AppState,
    task_id: Option<String>,
    tool: &str,
    decision: &str,
    reason: Option<String>,
    args_digest: Option<String>,
    result_digest: Option<String>,
) -> Result<(), String> {
    let Some(store) = state.store.clone() else {
        return Err("store_unavailable".into());
    };
    let ev = AuditEvent {
        seq: 0,
        ts: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            .to_string(),
        task_id,
        tool: Some(tool.to_string()),
        decision: decision.to_string(),
        reason,
        args_digest,
        result_digest,
        prev_hash: None,
        hash: None,
    };
    match store.append_audit_event(ev).await {
        Ok(_) => {
            state
                .metrics
                .audit_appends
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Ok(())
        }
        Err(e) => {
            state
                .metrics
                .audit_append_failures
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Err(format!("audit_append_failed:{e}"))
        }
    }
}

async fn policy_allows_mcp(
    state: &AppState,
    principal: &str,
    action: &str,
    resource: &str,
) -> bool {
    // Fail-closed by default; allow when explicit permit rule exists in config or active store policy body permits.
    let req = scopegate_core::policy::PolicyRequest::new(principal, action, resource);
    let eval = scopegate_core::policy::evaluate(&req, &state.config.rules);
    if matches!(
        eval.decision,
        scopegate_core::policy::PolicyDecision::Permit
    ) {
        return true;
    }
    if let Some(store) = &state.store {
        if let Ok(Some(p)) = store.get_active_policy().await {
            // Minimal store-backed policy integration: active policy with body "allow_all"/"permit" or JSON decision permit.
            let b = p.body.to_ascii_lowercase();
            if b.contains("allow_all")
                || b.contains("\"decision\":\"permit\"")
                || b.contains("\"permit\"")
            {
                return true;
            }
        }
    }
    false
}

async fn load_task_for_mcp(state: &AppState, task_id: &str) -> Result<Option<TaskRecord>, String> {
    let Some(store) = &state.store else {
        return Err("store_unavailable".into());
    };
    store
        .get_task(task_id)
        .await
        .map_err(|e| format!("task_lookup_failed:{e}"))
}

async fn validate_task_context(
    state: &AppState,
    task_id: Option<&str>,
) -> Result<(), &'static str> {
    let Some(task_id) = task_id else {
        return Ok(());
    };
    match load_task_for_mcp(state, task_id).await {
        Ok(Some(task)) if !task.revoked => Ok(()),
        Ok(Some(_)) => Err("task_revoked"),
        Ok(None) => Err("task_not_found"),
        Err(_) => Err("task_context_unavailable"),
    }
}

async fn load_approval_for_mcp(
    state: &AppState,
    approval_id: &str,
) -> Result<Option<ApprovalRecord>, String> {
    let Some(store) = &state.store else {
        return Err("store_unavailable".into());
    };
    store
        .get_approval(approval_id)
        .await
        .map_err(|e| format!("approval_lookup_failed:{e}"))
}

async fn validate_approval_context(
    state: &AppState,
    approval_id: Option<&str>,
    task_id: Option<&str>,
    method: &str,
    tool_name: &str,
) -> Result<(), &'static str> {
    let Some(approval_id) = approval_id else {
        return Ok(());
    };
    let approval = match load_approval_for_mcp(state, approval_id).await {
        Ok(Some(a)) => a,
        Ok(None) => return Err("approval_not_found"),
        Err(_) => return Err("approval_context_unavailable"),
    };
    if !matches!(approval.status, StoreApprovalStatus::Approved) {
        return Err("approval_not_granted");
    }
    if let Some(req_task_id) = task_id {
        if !approval.task_id.is_empty() && approval.task_id != req_task_id {
            return Err("approval_task_mismatch");
        }
    }
    if !approval.tool.is_empty() && approval.tool != method && approval.tool != tool_name {
        return Err("approval_tool_mismatch");
    }
    Ok(())
}

fn fail_closed_message_for_context(reason: &str) -> &'static str {
    match reason {
        "task_revoked" => "Task revoked (fail-closed)",
        "task_not_found" => "Task not found (fail-closed)",
        "approval_not_found" => "Approval not found (fail-closed)",
        "approval_not_granted" => "Approval not granted (fail-closed)",
        "approval_task_mismatch" => "Approval task mismatch (fail-closed)",
        "approval_tool_mismatch" => "Approval tool mismatch (fail-closed)",
        "approval_context_unavailable" => "Approval context unavailable (fail-closed)",
        _ => "Task context unavailable (fail-closed)",
    }
}

fn fail_closed_code_for_context(reason: &str) -> i64 {
    match reason {
        "task_context_unavailable" | "approval_context_unavailable" => -32002,
        _ => -32003,
    }
}

fn is_exempt_method(method: &str) -> bool {
    matches!(method, "initialize" | "tools/list" | "ping")
}

fn parse_taint_label(label: &str) -> Option<TaintLabel> {
    match label.to_ascii_lowercase().as_str() {
        "private_data" | "private" | "pii" => Some(TaintLabel::PrivateData),
        "untrusted_content" | "untrusted" => Some(TaintLabel::UntrustedContent),
        _ => None,
    }
}

fn parse_operation_target(op: Option<&str>) -> OperationTarget {
    match op.map(|s| s.to_ascii_lowercase()) {
        Some(ref s) if s == "egress" || s == "external_egress" => OperationTarget::ExternalEgress,
        Some(s) => OperationTarget::other(s),
        None => OperationTarget::other("unspecified"),
    }
}

fn extract_bearer(auth: Option<&str>) -> Option<String> {
    let raw = auth?.trim();
    let rest = raw
        .strip_prefix("Bearer ")
        .or_else(|| raw.strip_prefix("bearer "))?;
    let t = rest.trim();
    if t.is_empty() {
        None
    } else {
        Some(t.to_string())
    }
}

fn principal_from_context(params: &Value, ctx: &McpHttpContext) -> String {
    if let Some(p) = params.get("principal").and_then(|v| v.as_str()) {
        if !p.trim().is_empty() {
            return p.to_string();
        }
    }
    if extract_bearer(ctx.authorization.as_deref()).is_some() {
        return "authenticated".to_string();
    }
    "anonymous".to_string()
}

fn parse_token(params: &Value, default_scope: &str) -> Result<Option<TaskToken>, String> {
    let Some(tok) = params.get("token") else {
        return Ok(None);
    };
    let obj = tok
        .as_object()
        .ok_or_else(|| "invalid token context (fail-closed)".to_string())?;
    let rev = obj
        .get("revocation_id")
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "token.revocation_id required (fail-closed)".to_string())?;
    let scopes = match obj.get("scopes") {
        Some(Value::Array(arr)) if !arr.is_empty() => arr
            .iter()
            .filter_map(|v| v.as_str().map(|s| Scope(s.to_string())))
            .collect::<Vec<_>>(),
        _ => vec![Scope(default_scope.to_string())],
    };
    if scopes.is_empty() {
        return Err("token.scopes invalid (fail-closed)".into());
    }
    let max_calls = obj
        .get("max_calls")
        .and_then(|v| v.as_u64())
        .and_then(|n| u32::try_from(n).ok());
    let expires_at = obj.get("expires_at").and_then(|v| v.as_u64()).map(Expiry);
    Ok(Some(TaskToken::new(
        RevocationId(rev),
        scopes,
        Budget { max_calls },
        expires_at,
    )))
}

fn parse_hints(
    params: &Value,
) -> (
    Option<RateLimitHint>,
    Option<BudgetHint>,
    Option<CallCountHint>,
) {
    let Some(h) = params.get("hints").and_then(|v| v.as_object()) else {
        return (None, None, None);
    };
    let rate_limit = match (
        h.get("rate_calls_in_window").and_then(|v| v.as_u64()),
        h.get("rate_limit").and_then(|v| v.as_u64()),
    ) {
        (Some(calls), Some(limit)) => Some(RateLimitHint {
            calls_in_window: calls.min(u32::MAX as u64) as u32,
            limit: limit.min(u32::MAX as u64) as u32,
            exceeded: h
                .get("rate_exceeded")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
        }),
        _ => None,
    };
    let budget = match (
        h.get("budget_used").and_then(|v| v.as_u64()),
        h.get("budget_limit").and_then(|v| v.as_u64()),
    ) {
        (Some(used), Some(limit)) => Some(BudgetHint {
            used,
            limit,
            exceeded: h
                .get("budget_exceeded")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
        }),
        _ => None,
    };
    let call_count = match (
        h.get("call_count").and_then(|v| v.as_u64()),
        h.get("call_count_limit").and_then(|v| v.as_u64()),
    ) {
        (Some(count), Some(limit)) => Some(CallCountHint {
            count: count.min(u32::MAX as u64) as u32,
            limit: Some(limit.min(u32::MAX as u64) as u32),
            exceeded: h
                .get("call_count_exceeded")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
        }),
        _ => None,
    };
    (rate_limit, budget, call_count)
}

fn taint_from_params(params: &Value) -> SessionTaint {
    let mut taint = SessionTaint::new();
    if let Some(arr) = params.get("taint_labels").and_then(|v| v.as_array()) {
        for l in arr.iter().filter_map(|v| v.as_str()) {
            if let Some(lbl) = parse_taint_label(l) {
                taint.add_label(lbl);
            }
        }
    }
    taint
}

fn taint_session_key(
    task_id: Option<&str>,
    token: Option<&TaskToken>,
    principal: &str,
) -> (Option<String>, String) {
    if let Some(tid) = task_id.map(str::trim).filter(|s| !s.is_empty()) {
        return (Some(tid.to_string()), format!("mcp.taint.task:{tid}"));
    }
    if let Some(tok) = token {
        let rev = tok.revocation_id.0.trim();
        if !rev.is_empty() {
            return (None, format!("mcp.taint.token:{rev}"));
        }
    }
    let p = principal.trim();
    let p = if p.is_empty() { "anonymous" } else { p };
    (None, format!("mcp.taint.principal:{p}"))
}

async fn load_persisted_taint(
    state: &AppState,
    task_id: Option<&str>,
    source: &str,
) -> Result<SessionTaint, String> {
    let Some(store) = state.store.as_ref() else {
        return Err("taint_store_unavailable".into());
    };
    let query = if let Some(tid) = task_id {
        TaintSnapshotQuery {
            task_id: Some(tid.to_string()),
            ..Default::default()
        }
    } else {
        TaintSnapshotQuery {
            source: Some(source.to_string()),
            ..Default::default()
        }
    };
    let snapshots = store
        .list_taint_snapshots(query)
        .await
        .map_err(|e| format!("taint_store_read_failed:{e}"))?;
    let mut taint = SessionTaint::new();
    for snap in snapshots {
        for label in snap.labels {
            if let Some(lbl) = parse_taint_label(&label) {
                taint.add_label(lbl);
            }
        }
    }
    Ok(taint)
}

async fn persist_taint_snapshot(
    state: &AppState,
    taint: &SessionTaint,
    task_id: Option<&str>,
    source: &str,
) -> Result<(), String> {
    let Some(store) = state.store.as_ref() else {
        return Err("taint_store_unavailable".into());
    };
    let mut labels = taint.label_names();
    labels.sort_unstable();
    labels.dedup();
    let labels: Vec<String> = labels.into_iter().map(|s| s.to_string()).collect();
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let created_at = ts.as_secs().to_string();
    let id = digest(&format!(
        "taint|{}|{}|{}|{}",
        source,
        task_id.unwrap_or(""),
        labels.join(","),
        ts.as_nanos()
    ));
    let snapshot = TaintSnapshotRecord {
        id,
        task_id: task_id.map(|s| s.to_string()),
        source: source.to_string(),
        digest: Some(digest(&labels.join(","))),
        labels,
        created_at,
    };
    store
        .record_taint_snapshot(snapshot)
        .await
        .map(|_| ())
        .map_err(|e| format!("taint_store_write_failed:{e}"))
}

fn tool_pin_upstream_id(state: &AppState, req_upstream: Option<&str>) -> String {
    req_upstream
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .or_else(|| {
            state
                .config
                .mcp_default_upstream
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
        })
        .unwrap_or_else(|| "default".to_string())
}

fn tool_descriptor_canonical_json(tool: &Value) -> Result<String, String> {
    let name = tool
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "tool_pin_invalid_descriptor:missing_name".to_string())?;
    let description = tool.get("description").cloned().unwrap_or(Value::Null);
    let input_schema = tool
        .get("inputSchema")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let mut obj = serde_json::Map::new();
    obj.insert("description".to_string(), description);
    obj.insert("inputSchema".to_string(), input_schema);
    obj.insert("name".to_string(), Value::String(name.to_string()));
    // serde_json::Map preserves insertion order; keys are inserted in lexicographic order above.
    serde_json::to_string(&Value::Object(obj))
        .map_err(|e| format!("tool_pin_descriptor_serialize_failed:{e}"))
}

fn tool_descriptor_hash(tool: &Value) -> Result<(String, String, String), String> {
    let name = tool
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "tool_pin_invalid_descriptor:missing_name".to_string())?
        .to_string();
    let canonical = tool_descriptor_canonical_json(tool)?;
    let hash = digest(&canonical);
    Ok((name, canonical, hash))
}

async fn verify_tool_pins_on_tools_list(
    state: &AppState,
    req_upstream: Option<&str>,
    tools_list_result: &Value,
) -> Result<(), String> {
    let Some(store) = state.store.as_ref() else {
        // No durable store: cannot pin/compare; allow current behavior.
        return Ok(());
    };
    let upstream_id = tool_pin_upstream_id(state, req_upstream);
    let tools = tools_list_result
        .get("tools")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "tool_pin_invalid_tools_list:missing_tools_array".to_string())?;

    for tool in tools {
        let (tool_name, descriptor_json, descriptor_hash) = tool_descriptor_hash(tool)?;
        let existing = store
            .get_tool_pin(&upstream_id, &tool_name)
            .await
            .map_err(|e| format!("tool_pin_store_read_failed:{e}"))?;
        match existing {
            None => {
                let first_seen_at = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()
                    .to_string();
                let rec = ToolPinRecord {
                    upstream_id: upstream_id.clone(),
                    tool_name: tool_name.clone(),
                    descriptor_hash,
                    descriptor_json,
                    first_seen_at,
                    approved: true,
                };
                store
                    .upsert_tool_pin(rec)
                    .await
                    .map_err(|e| format!("tool_pin_store_write_failed:{e}"))?;
            }
            Some(pin) => {
                if !pin.approved {
                    return Err(format!(
                        "tool_manifest_pin_not_approved: upstream={} tool={} hash={}",
                        upstream_id, tool_name, pin.descriptor_hash
                    ));
                }
                if pin.descriptor_hash != descriptor_hash {
                    return Err(format!(
                        "tool_manifest_drift_detected: upstream={} tool={} pinned_hash={} observed_hash={} (re-approval required)",
                        upstream_id, tool_name, pin.descriptor_hash, descriptor_hash
                    ));
                }
            }
        }
    }
    Ok(())
}

async fn validate_token_auth(
    state: &AppState,
    token: &TaskToken,
    principal: &str,
    action: &str,
    now: u64,
) -> Result<(), String> {
    let revoked = state
        .effective_revoked_token_ids()
        .await
        .map_err(|_| "auth context unavailable (fail-closed)".to_string())?;
    let revoked_refs: Vec<&str> = revoked.iter().map(|s| s.as_str()).collect();
    if token.validate(now, &revoked_refs).is_err() {
        return Err("invalid_or_revoked_token".into());
    }
    if state.config.require_token_scope_for_action && !token.allows_scope(action) {
        return Err("token_scope_insufficient".into());
    }
    if principal.trim().is_empty() {
        return Err("missing_principal".into());
    }
    Ok(())
}

fn apply_rate_tracker(
    state: &mut AppState,
    token_key: &str,
    action: &str,
    now: u64,
    units: u64,
) -> Result<(), String> {
    state.configure_rate_limit_state();
    let Some(tracker) = state.rate_tracker.as_mut() else {
        return Ok(());
    };
    let decision = tracker.consume(token_key, action, now, units);
    if decision.is_allowed() {
        Ok(())
    } else if decision.reasons.is_empty() {
        Err("rate_or_budget_limited".into())
    } else {
        Err(format!(
            "rate_or_budget_limited:{}",
            decision.reasons.join(",")
        ))
    }
}

fn dispatch_error_to_jsonrpc(e: &str) -> (i64, String) {
    if e == "method_not_found" {
        (-32601, "Method not found".to_string())
    } else if e == "invalid_params" {
        (-32602, "Invalid params".to_string())
    } else if e.starts_with("tool_manifest_drift_detected:")
        || e.starts_with("tool_manifest_pin_not_approved:")
    {
        (
            -32003,
            format!("Tool manifest pin violation (fail-closed): {e}"),
        )
    } else if e.starts_with("tool_pin_") {
        (
            -32002,
            format!("Tool manifest pin check failed (fail-closed): {e}"),
        )
    } else if e == "mcp_pool_unavailable"
        || e == "mcp_upstream_unselected"
        || e == "mcp_upstream_not_configured"
        || e.starts_with("mcp_upstream_not_configured:")
        || e.contains("unknown upstream")
        || e.contains("upstream unavailable")
        || e.contains("upstream_spawn_failed")
        || e.contains("upstream_stdio_unavailable")
        || e.contains("upstream_write_failed")
        || e.contains("upstream_flush_failed")
        || e.contains("upstream_read_failed")
        || e.contains("circuit open")
        || e.contains("invalid state for")
        || e.contains("timeout after")
    {
        (-32002, "MCP upstream unavailable (fail-closed)".to_string())
    } else if e.starts_with("upstream_response_parse_failed") || e.starts_with("upstream_error:") {
        (
            -32000,
            "MCP upstream response invalid (fail-closed)".to_string(),
        )
    } else {
        // pool_dispatch_failed and other dispatch failures share the same fail-closed response.
        (-32000, "MCP dispatch failed (fail-closed)".to_string())
    }
}

fn extract_upstream_result(payload: &str) -> Result<Value, String> {
    let v = serde_json::from_str::<Value>(payload)
        .map_err(|e| format!("upstream_response_parse_failed:{e}"))?;
    if let Some(err) = v.get("error") {
        return Err(format!("upstream_error:{err}"));
    }
    Ok(v.get("result").cloned().unwrap_or(v))
}

fn selected_upstream_id(state: &AppState, req_upstream: Option<&str>) -> Option<String> {
    req_upstream
        .map(|s| s.to_string())
        .or_else(|| state.config.mcp_default_upstream.clone())
        .or_else(|| {
            state
                .config
                .mcp_upstreams
                .first()
                .map(|u| u.server.id.0.clone())
        })
}

fn stdio_transport_for_request<'a>(
    state: &'a AppState,
    req_upstream: Option<&str>,
) -> Option<(&'a mcp_pool::StdioTransportSpec, &'a str)> {
    let id = selected_upstream_id(state, req_upstream)?;
    state.config.mcp_upstreams.iter().find_map(|u| {
        if u.server.id.0 != id {
            return None;
        }
        match &u.server.transport_spec {
            TransportSpec::Stdio(spec) => Some((spec, u.server.id.0.as_str())),
            _ => None,
        }
    })
}

async fn dispatch_stdio_upstream(
    state: &AppState,
    payload_json: &str,
    req_upstream: Option<&str>,
) -> Result<String, String> {
    let (spec, id) = stdio_transport_for_request(state, req_upstream)
        .ok_or_else(|| "mcp_upstream_not_configured".to_string())?;
    if spec.program.trim().is_empty() {
        return Err(format!("mcp_upstream_not_configured:{id}:empty_program"));
    }

    let mut cmd = Command::new(&spec.program);
    cmd.args(&spec.args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true);
    if let Some(cwd) = &spec.cwd {
        cmd.current_dir(cwd);
    }
    for (k, v) in &spec.env {
        cmd.env(k, v);
    }

    let mut child = cmd
        .spawn()
        .map_err(|e| format!("upstream_spawn_failed:{id}:{e}"))?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| format!("upstream_stdio_unavailable:{id}:stdin"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| format!("upstream_stdio_unavailable:{id}:stdout"))?;

    // S1 proxy: forward the JSON-RPC request as a single line to a fresh stdio upstream process.
    stdin
        .write_all(payload_json.as_bytes())
        .await
        .map_err(|e| format!("upstream_write_failed:{id}:{e}"))?;
    stdin
        .write_all(b"\n")
        .await
        .map_err(|e| format!("upstream_write_failed:{id}:{e}"))?;
    stdin
        .flush()
        .await
        .map_err(|e| format!("upstream_flush_failed:{id}:{e}"))?;
    drop(stdin);

    let mut reader = BufReader::new(stdout).lines();
    // Conservative timeout for local stdio demo/S1 upstreams; fail closed.
    let line = timeout(Duration::from_secs(10), reader.next_line())
        .await
        .map_err(|_| format!("timeout after 10000ms:{id}"))?
        .map_err(|e| format!("upstream_read_failed:{id}:{e}"))?
        .ok_or_else(|| format!("upstream_unavailable:{id}:eof"))?;

    let _ = timeout(Duration::from_millis(500), child.wait()).await;
    Ok(line)
}

async fn _dispatch_upstream_request(
    state: &mut AppState,
    payload_json: String,
    req_upstream: Option<&str>,
) -> Result<String, String> {
    // S1 stdio upstreams: direct per-request JSON-RPC proxy for real upstream behavior.
    if stdio_transport_for_request(state, req_upstream).is_some() {
        return dispatch_stdio_upstream(state, &payload_json, req_upstream).await;
    }
    state.dispatch_mcp_via_pool("tools/call", payload_json, req_upstream)
}

async fn dispatch_upstream_method(
    state: &mut AppState,
    method: &str,
    payload_json: String,
    req_upstream: Option<&str>,
) -> Result<String, String> {
    if stdio_transport_for_request(state, req_upstream).is_some() {
        return dispatch_stdio_upstream(state, &payload_json, req_upstream).await;
    }
    state.dispatch_mcp_via_pool(method, payload_json, req_upstream)
}

/// Dispatch MCP JSON-RPC through gateway front logic + pool/upstream abstractions with store-backed controls.
pub async fn handle_mcp_request_async(state: &mut AppState, req: McpRequest) -> McpResponse {
    handle_mcp_request_async_with_context(state, req, McpHttpContext::default()).await
}

/// Dispatch MCP JSON-RPC with HTTP/auth context (token/auth, policy, approval, taint/rate hooks, audit).
pub async fn handle_mcp_request_async_with_context(
    state: &mut AppState,
    req: McpRequest,
    ctx: McpHttpContext,
) -> McpResponse {
    let parsed = match parse_raw(&req) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let id = parsed.get("id").cloned().unwrap_or(Value::Null);
    let method = parsed
        .get("method")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let task_id = parsed
        .get("params")
        .and_then(|p| p.get("task_id"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    emit(state, "mcp.request", &method, task_id.clone());

    let params = parsed.get("params").cloned().unwrap_or_else(|| json!({}));
    let principal = principal_from_context(&params, &ctx);
    let tool_name_param = params
        .get("name")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let tool_name = tool_name_param.as_deref().unwrap_or(&method).to_string();
    let approval_id = params
        .get("approval_id")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let action = method.clone();
    let resource = tool_name.clone();
    let now = params
        .get("now")
        .and_then(|v| v.as_u64())
        .unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
        });
    let operation = parse_operation_target(params.get("operation").and_then(|v| v.as_str()));
    let mut taint = taint_from_params(&params);
    let (rate_hint, budget_hint, call_count_hint) = parse_hints(&params);

    // Apply durable/runtime hooks where configured (best-effort preflight; fail-closed on sync errors).
    if let Err(e) = state.prepare_runtime_hooks().await {
        emit(
            state,
            "mcp.error",
            "runtime hook sync failed (fail-closed)",
            task_id.clone(),
        );
        if append_mcp_audit(
            state,
            task_id.clone(),
            &method,
            "deny",
            Some(e),
            Some(digest(&parsed.to_string())),
            None,
        )
        .await
        .is_err()
            && state.config.fail_closed
        {
            return jsonrpc_error(id, -32000, "Audit append failed (fail-closed)");
        }
        return jsonrpc_error(id, -32002, "Runtime context unavailable (fail-closed)");
    }

    // Token/auth context enforcement when a token is provided in params.
    let provided_token = match parse_token(&params, &resource) {
        Ok(t) => t,
        Err(reason) => {
            emit(state, "mcp.denied", &reason, task_id.clone());
            if append_mcp_audit(
                state,
                task_id.clone(),
                &method,
                "deny",
                Some(reason.clone()),
                Some(digest(&parsed.to_string())),
                None,
            )
            .await
            .is_err()
                && state.config.fail_closed
            {
                emit(
                    state,
                    "mcp.error",
                    "Audit append failed (fail-closed)",
                    task_id.clone(),
                );
                return jsonrpc_error(id, -32000, "Audit append failed (fail-closed)");
            }
            return jsonrpc_error(id, -32003, "Invalid token/auth context (fail-closed)");
        }
    };
    if let Some(tok) = &provided_token {
        if let Err(reason) = validate_token_auth(state, tok, &principal, &action, now).await {
            emit(
                state,
                "mcp.denied",
                "Token/auth validation failed (fail-closed)",
                task_id.clone(),
            );
            if append_mcp_audit(
                state,
                task_id.clone(),
                &method,
                "deny",
                Some(reason),
                Some(digest(&parsed.to_string())),
                None,
            )
            .await
            .is_err()
                && state.config.fail_closed
            {
                emit(
                    state,
                    "mcp.error",
                    "Audit append failed (fail-closed)",
                    task_id.clone(),
                );
                return jsonrpc_error(id, -32000, "Audit append failed (fail-closed)");
            }
            return jsonrpc_error(id, -32003, "Token/auth validation failed (fail-closed)");
        }
    } else if ctx.authorization.is_some()
        && !is_exempt_method(&method)
        && state.config.require_token_scope_for_action
    {
        // Auth header present but no verifiable task token payload; fail closed for protected methods.
        emit(
            state,
            "mcp.denied",
            "Missing verifiable token context (fail-closed)",
            task_id.clone(),
        );
        if append_mcp_audit(
            state,
            task_id.clone(),
            &method,
            "deny",
            Some("missing_token_context".into()),
            Some(digest(&parsed.to_string())),
            None,
        )
        .await
        .is_err()
            && state.config.fail_closed
        {
            emit(
                state,
                "mcp.error",
                "Audit append failed (fail-closed)",
                task_id.clone(),
            );
            return jsonrpc_error(id, -32000, "Audit append failed (fail-closed)");
        }
        return jsonrpc_error(id, -32003, "Missing verifiable token context (fail-closed)");
    }

    let (taint_task_id, taint_source) =
        taint_session_key(task_id.as_deref(), provided_token.as_ref(), &principal);
    if state.store.is_some() {
        match load_persisted_taint(state, taint_task_id.as_deref(), &taint_source).await {
            Ok(persisted) => taint.merge(&persisted),
            Err(e) => {
                emit(
                    state,
                    "mcp.error",
                    "Taint context unavailable (fail-closed)",
                    task_id.clone(),
                );
                if append_mcp_audit(
                    state,
                    task_id.clone(),
                    &method,
                    "deny",
                    Some(e),
                    Some(digest(&parsed.to_string())),
                    None,
                )
                .await
                .is_err()
                    && state.config.fail_closed
                {
                    return jsonrpc_error(id, -32000, "Audit append failed (fail-closed)");
                }
                return jsonrpc_error(id, -32002, "Taint context unavailable (fail-closed)");
            }
        }
    }

    // Taint/rate hooks (pre-dispatch fail-closed checks).
    if let Some(h) = rate_hint.as_ref() {
        if h.is_exceeded() {
            emit(
                state,
                "mcp.denied",
                "Rate limit exceeded (fail-closed)",
                task_id.clone(),
            );
            if append_mcp_audit(
                state,
                task_id.clone(),
                &method,
                "deny",
                Some("rate_limit_exceeded".into()),
                Some(digest(&parsed.to_string())),
                None,
            )
            .await
            .is_err()
                && state.config.fail_closed
            {
                return jsonrpc_error(id, -32000, "Audit append failed (fail-closed)");
            }
            return jsonrpc_error(id, -32003, "Rate limit exceeded (fail-closed)");
        }
    }
    if let Some(h) = budget_hint.as_ref() {
        if h.is_exceeded() {
            emit(
                state,
                "mcp.denied",
                "Budget exceeded (fail-closed)",
                task_id.clone(),
            );
            if append_mcp_audit(
                state,
                task_id.clone(),
                &method,
                "deny",
                Some("budget_exceeded".into()),
                Some(digest(&parsed.to_string())),
                None,
            )
            .await
            .is_err()
                && state.config.fail_closed
            {
                return jsonrpc_error(id, -32000, "Audit append failed (fail-closed)");
            }
            return jsonrpc_error(id, -32003, "Budget exceeded (fail-closed)");
        }
    }
    if let Some(h) = call_count_hint.as_ref() {
        if h.is_exceeded() {
            emit(
                state,
                "mcp.denied",
                "Call count exceeded (fail-closed)",
                task_id.clone(),
            );
            if append_mcp_audit(
                state,
                task_id.clone(),
                &method,
                "deny",
                Some("call_count_exceeded".into()),
                Some(digest(&parsed.to_string())),
                None,
            )
            .await
            .is_err()
                && state.config.fail_closed
            {
                return jsonrpc_error(id, -32000, "Audit append failed (fail-closed)");
            }
            return jsonrpc_error(id, -32003, "Call count exceeded (fail-closed)");
        }
    }
    if let Some(tok) = &provided_token {
        let token_key = tok.revocation_id.0.clone();
        let units = budget_hint.as_ref().map(|b| b.used.min(1)).unwrap_or(0);
        if let Err(reason) = apply_rate_tracker(state, &token_key, &action, now, units) {
            emit(
                state,
                "mcp.denied",
                "Rate/budget tracker denied (fail-closed)",
                task_id.clone(),
            );
            if append_mcp_audit(
                state,
                task_id.clone(),
                &method,
                "deny",
                Some(reason),
                Some(digest(&parsed.to_string())),
                None,
            )
            .await
            .is_err()
                && state.config.fail_closed
            {
                return jsonrpc_error(id, -32000, "Audit append failed (fail-closed)");
            }
            return jsonrpc_error(id, -32003, "Rate/budget tracker denied (fail-closed)");
        }
    }

    let taint_decision = if operation.is_external_egress() {
        taint.evaluate_egress_with(state.config.egress_policy)
    } else {
        taint.evaluate_target(&operation)
    };
    if matches!(taint_decision, TaintDecision::Block) {
        emit(
            state,
            "mcp.denied",
            "Blocked by taint policy (fail-closed)",
            task_id.clone(),
        );
        if append_mcp_audit(
            state,
            task_id.clone(),
            &method,
            "deny",
            Some("taint_blocked".into()),
            Some(digest(&parsed.to_string())),
            None,
        )
        .await
        .is_err()
            && state.config.fail_closed
        {
            return jsonrpc_error(id, -32000, "Audit append failed (fail-closed)");
        }
        return jsonrpc_error(id, -32003, "Blocked by taint policy (fail-closed)");
    }
    let taint_requires_approval = matches!(taint_decision, TaintDecision::RequireApproval);
    if taint_requires_approval && approval_id.as_deref().is_none() {
        emit(
            state,
            "mcp.denied",
            "Approval required by taint policy (fail-closed)",
            task_id.clone(),
        );
        if append_mcp_audit(
            state,
            task_id.clone(),
            &method,
            "deny",
            Some("approval_required_taint".into()),
            Some(digest(&parsed.to_string())),
            None,
        )
        .await
        .is_err()
            && state.config.fail_closed
        {
            return jsonrpc_error(id, -32000, "Audit append failed (fail-closed)");
        }
        return jsonrpc_error(
            id,
            -32003,
            "Approval required by taint policy (fail-closed)",
        );
    }

    // Store-backed task context (fail-closed when task is referenced but cannot be validated).
    if let Err(reason) = validate_task_context(state, task_id.as_deref()).await {
        let code = fail_closed_code_for_context(reason);
        let msg = fail_closed_message_for_context(reason);
        emit(state, "mcp.denied", msg, task_id.clone());
        if append_mcp_audit(
            state,
            task_id.clone(),
            &method,
            "deny",
            Some(reason.into()),
            Some(digest(&parsed.to_string())),
            None,
        )
        .await
        .is_err()
            && state.config.fail_closed
        {
            emit(
                state,
                "mcp.error",
                "Audit append failed (fail-closed)",
                task_id.clone(),
            );
            return jsonrpc_error(id, -32000, "Audit append failed (fail-closed)");
        }
        return jsonrpc_error(id, code, msg);
    }

    // Store-backed approval context when an approval id is supplied.
    if let Err(reason) = validate_approval_context(
        state,
        approval_id.as_deref(),
        task_id.as_deref(),
        &method,
        &tool_name,
    )
    .await
    {
        let code = fail_closed_code_for_context(reason);
        let msg = fail_closed_message_for_context(reason);
        emit(state, "mcp.denied", msg, task_id.clone());
        if append_mcp_audit(
            state,
            task_id.clone(),
            &method,
            "deny",
            Some(reason.into()),
            Some(digest(&parsed.to_string())),
            None,
        )
        .await
        .is_err()
            && state.config.fail_closed
        {
            emit(
                state,
                "mcp.error",
                "Audit append failed (fail-closed)",
                task_id.clone(),
            );
            return jsonrpc_error(id, -32000, "Audit append failed (fail-closed)");
        }
        return jsonrpc_error(id, code, msg);
    }

    // Store-backed policy gate for mutating/dispatch methods (fail-closed).
    let policy_eval = {
        let taint_hint = if taint.labels().is_empty() {
            None
        } else {
            Some(TaintHint {
                labels: taint
                    .label_names()
                    .into_iter()
                    .map(|s| s.to_string())
                    .collect(),
                sensitive: taint.has_private_data() || taint.has_untrusted_content(),
            })
        };
        let preq = PolicyRequest {
            principal: Principal {
                id: principal.clone(),
            },
            action: Action {
                name: action.clone(),
            },
            resource: Resource {
                id: resource.clone(),
            },
            context: Context {
                approval: approval_id.as_ref().map(|aid| ApprovalAnnotation {
                    approved_by: Some("mcp-context".into()),
                    reason: Some(format!("approval_id={aid}")),
                }),
                rate_limit: rate_hint.clone(),
                budget: budget_hint.clone(),
                call_count: call_count_hint.clone(),
                taint: taint_hint,
                args: None,
            },
        };
        evaluate(&preq, &state.config.rules)
    };
    let demo_forbidden_call = method == "tools/call" && tool_name == "demo.forbidden";
    let policy_store_ok = policy_allows_mcp(state, &principal, &method, &tool_name).await;
    let policy_permit = !demo_forbidden_call
        && (is_exempt_method(&method)
            || policy_store_ok
            || matches!(policy_eval.decision, PolicyDecision::Permit));
    let policy_requires_approval = !demo_forbidden_call
        && !policy_permit
        && matches!(policy_eval.decision, PolicyDecision::RequireApproval);
    let policy_denied = demo_forbidden_call || (!policy_permit && !policy_requires_approval);
    if policy_denied {
        emit(
            state,
            "mcp.denied",
            "Denied by policy (fail-closed)",
            task_id.clone(),
        );
        if append_mcp_audit(
            state,
            task_id.clone(),
            &method,
            "deny",
            Some("policy_denied_or_missing".into()),
            Some(digest(&parsed.to_string())),
            None,
        )
        .await
        .is_err()
            && state.config.fail_closed
        {
            emit(
                state,
                "mcp.error",
                "Audit append failed (fail-closed)",
                task_id.clone(),
            );
            return jsonrpc_error(id, -32000, "Audit append failed (fail-closed)");
        }
        return jsonrpc_error(id, -32003, "Denied by policy (fail-closed)");
    }
    if (policy_requires_approval
        || (!is_exempt_method(&method)
            && matches!(policy_eval.decision, PolicyDecision::RequireApproval)))
        && approval_id.as_deref().is_none()
    {
        emit(
            state,
            "mcp.denied",
            "Approval required by policy (fail-closed)",
            task_id.clone(),
        );
        if append_mcp_audit(
            state,
            task_id.clone(),
            &method,
            "deny",
            Some("approval_required_policy".into()),
            Some(digest(&parsed.to_string())),
            None,
        )
        .await
        .is_err()
            && state.config.fail_closed
        {
            emit(
                state,
                "mcp.error",
                "Audit append failed (fail-closed)",
                task_id.clone(),
            );
            return jsonrpc_error(id, -32000, "Audit append failed (fail-closed)");
        }
        return jsonrpc_error(id, -32003, "Approval required by policy (fail-closed)");
    }

    // Front/routing + pool/upstream dispatch abstractions.
    let result = match method.as_str() {
        "initialize" => {
            // S1 stdio upstream: proxy initialize end-to-end to upstream for real capability negotiation.
            if stdio_transport_for_request(state, req.upstream.as_deref()).is_some() {
                emit(
                    state,
                    "mcp.upstream.dispatch",
                    "initialize",
                    task_id.clone(),
                );
                match dispatch_upstream_method(
                    state,
                    "initialize",
                    parsed.to_string(),
                    req.upstream.as_deref(),
                )
                .await
                {
                    Ok(payload) => extract_upstream_result(&payload),
                    Err(e) => Err(e),
                }
            } else {
                Ok(json!({
                    "protocolVersion":"2024-11-05",
                    "capabilities":{"tools":{"listChanged": false}},
                    "serverInfo":{"name":"gateway-mcp-front","version": env!("CARGO_PKG_VERSION")}
                }))
            }
        }
        "ping" => Ok(json!({})),
        "tools/list" => {
            // Preserve local capability surface when no upstream; proxy to upstream when configured.
            let upstream_available = stdio_transport_for_request(state, req.upstream.as_deref())
                .is_some()
                || state.mcp.is_some();
            if upstream_available {
                emit(
                    state,
                    "mcp.upstream.dispatch",
                    "tools/list",
                    task_id.clone(),
                );
                match dispatch_upstream_method(
                    state,
                    "tools/list",
                    parsed.to_string(),
                    req.upstream.as_deref(),
                )
                .await
                {
                    Ok(payload) => match extract_upstream_result(&payload) {
                        Ok(r) => Ok(r),
                        Err(e) if e.starts_with("upstream_error:") => Err(e),
                        Err(_) => {
                            emit(
                                state,
                                "mcp.upstream.fallback",
                                "tools/list local capability surface",
                                task_id.clone(),
                            );
                            Ok(
                                json!({"tools":[{"name":"gateway.health","description":"Gateway MCP dispatch health probe","inputSchema":{"type":"object"}}]}),
                            )
                        }
                    },
                    Err(_) => {
                        emit(
                            state,
                            "mcp.upstream.fallback",
                            "tools/list local capability surface",
                            task_id.clone(),
                        );
                        Ok(
                            json!({"tools":[{"name":"gateway.health","description":"Gateway MCP dispatch health probe","inputSchema":{"type":"object"}}]}),
                        )
                    }
                }
            } else {
                Ok(
                    json!({"tools":[{"name":"gateway.health","description":"Gateway MCP dispatch health probe","inputSchema":{"type":"object"}}]}),
                )
            }
        }
        "tools/call" => {
            let Some(name) = tool_name_param.as_deref().filter(|n| !n.trim().is_empty()) else {
                emit(
                    state,
                    "mcp.denied",
                    "Invalid params: tools/call requires params.name",
                    task_id.clone(),
                );
                if append_mcp_audit(
                    state,
                    task_id.clone(),
                    &method,
                    "deny",
                    Some("invalid_params".into()),
                    Some(digest(&parsed.to_string())),
                    None,
                )
                .await
                .is_err()
                    && state.config.fail_closed
                {
                    emit(
                        state,
                        "mcp.error",
                        "Audit append failed (fail-closed)",
                        task_id.clone(),
                    );
                    return jsonrpc_error(id, -32000, "Audit append failed (fail-closed)");
                }
                return jsonrpc_error(
                    id,
                    -32602,
                    "Invalid params: tools/call requires params.name",
                );
            };
            if name == "gateway.health" {
                Ok(
                    json!({"content":[{"type":"text","text":"ok"}],"isError": false, "structuredContent":{"ok":true,"dispatch":"gateway+pool-abstraction"}}),
                )
            } else if stdio_transport_for_request(state, req.upstream.as_deref()).is_some()
                || state.mcp.is_some()
            {
                emit(
                    state,
                    "mcp.upstream.dispatch",
                    "tools/call",
                    task_id.clone(),
                );
                match dispatch_upstream_method(
                    state,
                    "tools/call",
                    parsed.to_string(),
                    req.upstream.as_deref(),
                )
                .await
                {
                    Ok(payload) => extract_upstream_result(&payload),
                    Err(e) => Err(e),
                }
            } else {
                Err("mcp_upstream_not_configured".to_string())
            }
        }
        _ => {
            if stdio_transport_for_request(state, req.upstream.as_deref()).is_some()
                || state.mcp.is_some()
            {
                emit(state, "mcp.upstream.dispatch", &method, task_id.clone());
                match dispatch_upstream_method(
                    state,
                    &method,
                    parsed.to_string(),
                    req.upstream.as_deref(),
                )
                .await
                {
                    Ok(payload) => extract_upstream_result(&payload),
                    Err(e) => Err(e),
                }
            } else {
                Err("method_not_found".to_string())
            }
        }
    };

    let mut result = result;
    if method == "tools/list" {
        if let Ok(r) = &result {
            if let Err(e) = verify_tool_pins_on_tools_list(state, req.upstream.as_deref(), r).await
            {
                emit(state, "mcp.denied", &e, task_id.clone());
                result = Err(e);
            }
        }
    }

    match result {
        Ok(r) => {
            if method == "tools/call" {
                taint.add_label(TaintLabel::UntrustedContent);
                if state.store.is_some() {
                    if let Err(e) = persist_taint_snapshot(
                        state,
                        &taint,
                        taint_task_id.as_deref(),
                        &taint_source,
                    )
                    .await
                    {
                        emit(
                            state,
                            "mcp.error",
                            "Taint persistence failed (fail-closed)",
                            task_id.clone(),
                        );
                        if append_mcp_audit(
                            state,
                            task_id.clone(),
                            &method,
                            "deny",
                            Some(e),
                            Some(digest(&parsed.to_string())),
                            Some(digest(&r.to_string())),
                        )
                        .await
                        .is_err()
                            && state.config.fail_closed
                        {
                            return jsonrpc_error(id, -32000, "Audit append failed (fail-closed)");
                        }
                        return jsonrpc_error(id, -32002, "Taint persistence failed (fail-closed)");
                    }
                }
            }
            let audit_res = append_mcp_audit(
                state,
                task_id.clone(),
                &method,
                "allow",
                None,
                Some(digest(&parsed.to_string())),
                Some(digest(&r.to_string())),
            )
            .await;
            if audit_res.is_err() && state.config.fail_closed {
                emit(
                    state,
                    "mcp.error",
                    "Audit append failed (fail-closed)",
                    task_id.clone(),
                );
                return jsonrpc_error(id, -32000, "Audit append failed (fail-closed)");
            }
            emit(state, "mcp.response", "ok", task_id);
            finalize_mcp_response(McpResponse {
                ok: true,
                payload_json: json!({"jsonrpc":"2.0","id":id,"result":r}).to_string(),
                fail_closed: false,
            })
        }
        Err(e) => {
            let (code, msg) = dispatch_error_to_jsonrpc(&e);
            emit(state, "mcp.error", &msg, task_id.clone());
            if append_mcp_audit(
                state,
                task_id.clone(),
                &method,
                "deny",
                Some(e.clone()),
                Some(digest(&parsed.to_string())),
                None,
            )
            .await
            .is_err()
                && state.config.fail_closed
            {
                emit(
                    state,
                    "mcp.error",
                    "Audit append failed (fail-closed)",
                    task_id,
                );
                return jsonrpc_error(id, -32000, "Audit append failed (fail-closed)");
            }
            jsonrpc_error(id, code, &msg)
        }
    }
}

/// Sync-compatible wrapper for callers/tests; runs on current runtime handle.
pub fn handle_mcp_request(
    req: McpRequest,
    event_sink: Option<tokio::sync::broadcast::Sender<String>>,
) -> McpResponse {
    // Minimal fallback used only when no async state is available: preserve local behavior.
    let _ = event_sink;
    let parsed = match parse_raw(&req) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let id = parsed.get("id").cloned().unwrap_or(Value::Null);
    let method = parsed.get("method").and_then(|v| v.as_str()).unwrap_or("");
    let result = match method {
        "initialize" => Some(json!({
            "protocolVersion":"2024-11-05",
            "capabilities":{"tools":{"listChanged": false}},
            "serverInfo":{"name":"gateway-mcp-dispatch","version": env!("CARGO_PKG_VERSION")}
        })),
        "tools/list" => Some(
            json!({"tools":[{"name":"gateway.health","description":"Gateway MCP dispatch integration health probe","inputSchema":{"type":"object"}}]}),
        ),
        "tools/call" => {
            let name = parsed
                .get("params")
                .and_then(|p| p.get("name"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if name == "gateway.health" {
                Some(
                    json!({"content":[{"type":"text","text":"ok"}],"isError": false, "structuredContent":{"ok":true,"dispatch":"gateway"}}),
                )
            } else {
                None
            }
        }
        _ => None,
    };
    match result {
        Some(r) => finalize_mcp_response(McpResponse {
            ok: true,
            payload_json: json!({"jsonrpc":"2.0","id":id,"result":r}).to_string(),
            fail_closed: false,
        }),
        None => jsonrpc_error(id, -32601, "method/tool not found (fail-closed)"),
    }
}

/// Legacy placeholder.
pub fn handle_mcp_placeholder(_req: McpRequest) -> McpResponse {
    finalize_mcp_response(McpResponse {
        ok: false,
        payload_json: json!({"error":"mcp_not_configured","fail_closed":true}).to_string(),
        fail_closed: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::GatewayConfig;
    use scopegate_core::policy::{PolicyDecision, Rule};
    use scopegate_core::taint::EgressPolicy;
    use std::sync::Arc;
    use store::{ApprovalRecord, ApprovalStatus, InMemoryStore, Store, TaskRecord};

    fn state_with_store() -> AppState {
        let store: Arc<dyn Store> = Arc::new(InMemoryStore::default());
        AppState::fail_closed().with_store(store)
    }

    fn permit_all_config() -> GatewayConfig {
        GatewayConfig::default().with_rules(vec![Rule {
            effect: PolicyDecision::Permit,
            ..Default::default()
        }])
    }

    #[tokio::test]
    async fn denies_when_task_context_missing() {
        let mut state = state_with_store();
        state.config = permit_all_config();
        let req = McpRequest {
            method: String::new(),
            payload_json: json!({
                "jsonrpc":"2.0","id":1,"method":"tools/call",
                "params":{"name":"gateway.health","task_id":"missing-task"}
            })
            .to_string(),
            upstream: None,
        };
        let resp = handle_mcp_request_async(&mut state, req).await;
        assert!(resp.fail_closed);
        let v: Value = serde_json::from_str(&resp.payload_json).unwrap();
        assert_eq!(v["error"]["code"], -32003);
        assert!(v["error"]["message"]
            .as_str()
            .unwrap()
            .contains("Task not found"));
    }

    #[tokio::test]
    async fn denies_when_task_revoked() {
        let mut state = state_with_store();
        state.config = permit_all_config();
        state
            .store
            .as_ref()
            .unwrap()
            .upsert_task(TaskRecord {
                id: "t1".into(),
                token_id: "tok".into(),
                scopes: "[]".into(),
                budget: 1,
                expires_at: "later".into(),
                revoked: true,
                ..Default::default()
            })
            .await
            .unwrap();
        let req = McpRequest {
            method: String::new(),
            payload_json: json!({
                "jsonrpc":"2.0","id":2,"method":"tools/call",
                "params":{"name":"gateway.health","task_id":"t1"}
            })
            .to_string(),
            upstream: None,
        };
        let resp = handle_mcp_request_async(&mut state, req).await;
        assert!(resp.fail_closed);
        let v: Value = serde_json::from_str(&resp.payload_json).unwrap();
        assert!(v["error"]["message"]
            .as_str()
            .unwrap()
            .contains("Task revoked"));
    }

    #[tokio::test]
    async fn denies_when_approval_mismatched_or_not_granted() {
        let mut state = state_with_store();
        state.config = permit_all_config();
        state
            .store
            .as_ref()
            .unwrap()
            .upsert_task(TaskRecord {
                id: "t1".into(),
                token_id: "tok".into(),
                scopes: "[]".into(),
                budget: 1,
                expires_at: "later".into(),
                revoked: false,
                ..Default::default()
            })
            .await
            .unwrap();
        state
            .store
            .as_ref()
            .unwrap()
            .create_approval(ApprovalRecord {
                id: "a1".into(),
                task_id: "t1".into(),
                tool: "other.tool".into(),
                args_hash: "h".into(),
                status: ApprovalStatus::Approved,
                created_at: "now".into(),
                ..Default::default()
            })
            .await
            .unwrap();
        let req = McpRequest {
            method: String::new(),
            payload_json: json!({
                "jsonrpc":"2.0","id":3,"method":"tools/call",
                "params":{"name":"gateway.health","task_id":"t1","approval_id":"a1"}
            })
            .to_string(),
            upstream: None,
        };
        let resp = handle_mcp_request_async(&mut state, req).await;
        assert!(resp.fail_closed);
        let v: Value = serde_json::from_str(&resp.payload_json).unwrap();
        assert!(v["error"]["message"]
            .as_str()
            .unwrap()
            .contains("Approval tool mismatch"));
    }

    #[tokio::test]
    async fn tools_call_invalid_params_and_method_errors_are_clear() {
        let mut state = state_with_store();
        state.config = permit_all_config();
        let bad_params = McpRequest {
            method: String::new(),
            payload_json: json!({
                "jsonrpc":"2.0","id":4,"method":"tools/call","params":{"principal":"anonymous"}
            })
            .to_string(),
            upstream: None,
        };
        let resp = handle_mcp_request_async(&mut state, bad_params).await;
        let v: Value = serde_json::from_str(&resp.payload_json).unwrap();
        assert_eq!(v["error"]["code"], -32602);

        let unknown = McpRequest {
            method: String::new(),
            payload_json: json!({"jsonrpc":"2.0","id":5,"method":"nope/method","params":{}})
                .to_string(),
            upstream: None,
        };
        let resp = handle_mcp_request_async(&mut state, unknown).await;
        let v: Value = serde_json::from_str(&resp.payload_json).unwrap();
        assert_eq!(v["error"]["code"], -32601);
        assert_eq!(v["error"]["message"], "Method not found");
    }

    #[tokio::test]
    async fn allows_gateway_health_with_valid_task_and_approval_context() {
        let mut state = state_with_store();
        state.config = permit_all_config();
        let store = state.store.as_ref().unwrap();
        store
            .upsert_task(TaskRecord {
                id: "t-ok".into(),
                token_id: "tok".into(),
                scopes: "[]".into(),
                budget: 1,
                expires_at: "later".into(),
                revoked: false,
                ..Default::default()
            })
            .await
            .unwrap();
        store
            .create_approval(ApprovalRecord {
                id: "a-ok".into(),
                task_id: "t-ok".into(),
                tool: "gateway.health".into(),
                args_hash: "h".into(),
                status: ApprovalStatus::Approved,
                created_at: "now".into(),
                ..Default::default()
            })
            .await
            .unwrap();
        let req = McpRequest {
            method: String::new(),
            payload_json: json!({
                "jsonrpc":"2.0","id":6,"method":"tools/call",
                "params":{"name":"gateway.health","task_id":"t-ok","approval_id":"a-ok","principal":"anonymous"}
            })
            .to_string(),
            upstream: None,
        };
        let resp = handle_mcp_request_async(&mut state, req).await;
        assert!(resp.ok, "{}", resp.payload_json);
        let v: Value = serde_json::from_str(&resp.payload_json).unwrap();
        assert_eq!(v["result"]["structuredContent"]["ok"], true);
    }

    #[tokio::test]
    async fn emits_denied_event_for_policy_failures() {
        let mut state = state_with_store(); // default config fail-closed, no permit rules
        let mut rx = state.events_tx.subscribe();
        let req = McpRequest {
            method: String::new(),
            payload_json: json!({
                "jsonrpc":"2.0","id":7,"method":"tools/call",
                "params":{"name":"gateway.health"}
            })
            .to_string(),
            upstream: None,
        };
        let resp = handle_mcp_request_async(&mut state, req).await;
        assert!(resp.fail_closed);
        let events: Vec<Value> = std::iter::from_fn(|| rx.try_recv().ok())
            .filter_map(|s| serde_json::from_str::<Value>(&s).ok())
            .collect();
        assert!(
            events
                .iter()
                .any(|e| e["kind"] == "mcp.denied"
                    && e["message"] == "Denied by policy (fail-closed)"),
            "events={events:?}"
        );
    }

    #[tokio::test]
    async fn denies_taint_egress_without_approval() {
        let mut state = state_with_store();
        state.config = permit_all_config();
        state.config.egress_policy = EgressPolicy::RequireApprovalOnConflict;
        let req = McpRequest {
            method: String::new(),
            payload_json: json!({
                "jsonrpc":"2.0","id":8,"method":"tools/call",
                "params":{
                    "name":"gateway.health",
                    "operation":"egress",
                    "taint_labels":["untrusted_content","private_data"]
                }
            })
            .to_string(),
            upstream: None,
        };
        let resp = handle_mcp_request_async(&mut state, req).await;
        assert!(resp.fail_closed);
        let v: Value = serde_json::from_str(&resp.payload_json).unwrap();
        assert_eq!(v["error"]["code"], -32003);
        assert!(v["error"]["message"]
            .as_str()
            .unwrap()
            .contains("Approval required"));
    }

    #[tokio::test]
    async fn denies_rate_hint_exceeded_fail_closed() {
        let mut state = state_with_store();
        state.config = permit_all_config();
        let req = McpRequest {
            method: String::new(),
            payload_json: json!({
                "jsonrpc":"2.0","id":9,"method":"tools/call",
                "params":{
                    "name":"gateway.health",
                    "hints":{"rate_calls_in_window":10,"rate_limit":5,"rate_exceeded":true}
                }
            })
            .to_string(),
            upstream: None,
        };
        let resp = handle_mcp_request_async(&mut state, req).await;
        assert!(resp.fail_closed);
        let v: Value = serde_json::from_str(&resp.payload_json).unwrap();
        assert!(v["error"]["message"]
            .as_str()
            .unwrap()
            .contains("Rate limit exceeded"));
    }

    #[tokio::test]
    async fn denies_invalid_token_context_fail_closed() {
        let mut state = state_with_store();
        state.config = permit_all_config();
        let req = McpRequest {
            method: String::new(),
            payload_json: json!({
                "jsonrpc":"2.0","id":10,"method":"tools/call",
                "params":{
                    "name":"gateway.health",
                    "token":{"revocation_id":"rev-x","scopes":["tools/call"],"expires_at":1},
                    "now": 100
                }
            })
            .to_string(),
            upstream: None,
        };
        let resp = handle_mcp_request_async(&mut state, req).await;
        assert!(resp.fail_closed);
        let v: Value = serde_json::from_str(&resp.payload_json).unwrap();
        assert_eq!(v["error"]["code"], -32003);
        assert!(v["error"]["message"]
            .as_str()
            .unwrap()
            .contains("Token/auth validation failed"));
    }

    #[tokio::test]
    async fn denies_auth_header_without_token_context_for_protected_methods() {
        let mut state = state_with_store();
        state.config = permit_all_config();
        state.config.require_token_scope_for_action = true;
        let req = McpRequest {
            method: String::new(),
            payload_json: json!({
                "jsonrpc":"2.0","id":11,"method":"tools/call",
                "params":{"name":"gateway.health"}
            })
            .to_string(),
            upstream: None,
        };
        let resp = handle_mcp_request_async_with_context(
            &mut state,
            req,
            McpHttpContext {
                authorization: Some("Bearer test-token".into()),
            },
        )
        .await;
        assert!(resp.fail_closed);
        let v: Value = serde_json::from_str(&resp.payload_json).unwrap();
        assert_eq!(v["error"]["code"], -32003);
        assert!(v["error"]["message"]
            .as_str()
            .unwrap()
            .contains("Missing verifiable token context"));
        // durable audit/eventing path
        let events = state
            .store
            .as_ref()
            .unwrap()
            .query_audit(store::AuditQuery {
                limit: Some(10),
                ..Default::default()
            })
            .await
            .unwrap();
        assert!(events.iter().any(|e| e.decision == "deny"));
    }

    fn demo_stdio_state() -> AppState {
        let mut state = state_with_store();
        state.config = permit_all_config();
        let server_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../e2e/stdio_demo_mcp_server.py");
        let server = mcp_pool::UpstreamServerConfig::with_stdio(
            "demo",
            "python3",
            vec![server_path.to_string_lossy().to_string()],
        );
        state.config.mcp_upstreams = vec![crate::config::McpUpstreamConfig {
            server,
            pool: mcp_pool::UpstreamConfig::default(),
        }];
        state.config.mcp_default_upstream = Some("demo".into());
        state
    }

    #[tokio::test]
    async fn proxies_stdio_upstream_initialize_tools_list_and_demo_echo_end_to_end() {
        let mut state = demo_stdio_state();

        let init = McpRequest {
            method: String::new(),
            payload_json: json!({
                "jsonrpc":"2.0","id":21,"method":"initialize",
                "params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"0"}}
            }).to_string(),
            upstream: None,
        };
        let resp = handle_mcp_request_async(&mut state, init).await;
        assert!(resp.ok, "{}", resp.payload_json);
        let v: Value = serde_json::from_str(&resp.payload_json).unwrap();
        assert_eq!(
            v["result"]["serverInfo"]["name"],
            "scopegate-e2e-stdio-demo"
        );

        let list = McpRequest {
            method: String::new(),
            payload_json: json!({"jsonrpc":"2.0","id":22,"method":"tools/list","params":{}})
                .to_string(),
            upstream: None,
        };
        let resp = handle_mcp_request_async(&mut state, list).await;
        assert!(resp.ok, "{}", resp.payload_json);
        let v: Value = serde_json::from_str(&resp.payload_json).unwrap();
        assert!(v["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t["name"] == "demo.echo"));

        let call = McpRequest {
            method: String::new(),
            payload_json: json!({
                "jsonrpc":"2.0","id":23,"method":"tools/call",
                "params":{"name":"demo.echo","arguments":{"message":"hi-s1"}}
            })
            .to_string(),
            upstream: None,
        };
        let resp = handle_mcp_request_async(&mut state, call).await;
        assert!(resp.ok, "{}", resp.payload_json);
        let v: Value = serde_json::from_str(&resp.payload_json).unwrap();
        assert_eq!(v["result"]["structuredContent"]["echo"]["message"], "hi-s1");

        let audit = state
            .store
            .as_ref()
            .unwrap()
            .query_audit(store::AuditQuery {
                limit: Some(50),
                ..Default::default()
            })
            .await
            .unwrap();
        assert!(audit
            .iter()
            .any(|e| e.tool.as_deref() == Some("tools/call") && e.decision == "allow"));
    }

    #[tokio::test]
    async fn denies_demo_forbidden_tool_call_by_policy_fail_closed() {
        let mut state = demo_stdio_state(); // configured upstream + permit-all baseline
        let req = McpRequest {
            method: String::new(),
            payload_json: json!({
                "jsonrpc":"2.0","id":24,"method":"tools/call",
                "params":{"name":"demo.forbidden","arguments":{"message":"should-be-denied"}}
            })
            .to_string(),
            upstream: None,
        };
        let resp = handle_mcp_request_async(&mut state, req).await;
        assert!(resp.fail_closed, "{}", resp.payload_json);
        let v: Value = serde_json::from_str(&resp.payload_json).unwrap();
        assert_eq!(v["error"]["code"], -32003);
        assert!(v["error"]["message"]
            .as_str()
            .unwrap()
            .contains("Denied by policy"));

        let audit = state
            .store
            .as_ref()
            .unwrap()
            .query_audit(store::AuditQuery {
                limit: Some(20),
                ..Default::default()
            })
            .await
            .unwrap();
        assert!(audit.iter().any(|e| {
            e.tool.as_deref() == Some("tools/call")
                && e.decision == "deny"
                && e.reason
                    .as_deref()
                    .is_some_and(|r| r.contains("policy_denied"))
        }));
    }

    #[tokio::test]
    async fn parse_error_returns_jsonrpc_safe_fail_closed_response() {
        let mut state = state_with_store();
        let req = McpRequest {
            method: String::new(),
            payload_json: "{not-json".into(),
            upstream: None,
        };
        let resp = handle_mcp_request_async(&mut state, req).await;
        assert!(resp.fail_closed);
        let v: Value = serde_json::from_str(&resp.payload_json).unwrap();
        assert_eq!(v["jsonrpc"], "2.0");
        assert_eq!(v["id"], Value::Null);
        assert_eq!(v["error"]["code"], -32700);
        assert!(v["error"]["message"]
            .as_str()
            .unwrap()
            .contains("parse error"));
    }

    #[tokio::test]
    async fn denies_budget_and_call_count_hints_fail_closed() {
        for (id, params) in [
            (
                30,
                json!({
                    "name":"gateway.health",
                    "hints":{"budget_used":10,"budget_limit":5,"budget_exceeded":true}
                }),
            ),
            (
                31,
                json!({
                    "name":"gateway.health",
                    "hints":{"call_count":10,"call_count_limit":5,"call_count_exceeded":true}
                }),
            ),
        ] {
            let mut state = state_with_store();
            state.config = permit_all_config();
            let req = McpRequest {
                method: String::new(),
                payload_json: json!({
                    "jsonrpc":"2.0","id":id,"method":"tools/call","params":params
                })
                .to_string(),
                upstream: None,
            };
            let resp = handle_mcp_request_async(&mut state, req).await;
            assert!(resp.fail_closed, "{}", resp.payload_json);
            let v: Value = serde_json::from_str(&resp.payload_json).unwrap();
            assert_eq!(v["error"]["code"], -32003);
            let msg = v["error"]["message"].as_str().unwrap();
            assert!(
                msg.contains("Budget exceeded") || msg.contains("Call count exceeded"),
                "msg={msg}"
            );
        }
    }

    #[tokio::test]
    async fn denies_revoked_token_fail_closed() {
        let mut state = state_with_store();
        state.config = permit_all_config();
        state.config.revoked_token_ids = vec!["revoked-1".into()];
        let req = McpRequest {
            method: String::new(),
            payload_json: json!({
                "jsonrpc":"2.0","id":32,"method":"tools/call",
                "params":{
                    "name":"gateway.health",
                    "token":{"revocation_id":"revoked-1","scopes":["tools/call"],"expires_at":9999999999u64},
                    "now": 100
                }
            })
            .to_string(),
            upstream: None,
        };
        let resp = handle_mcp_request_async(&mut state, req).await;
        assert!(resp.fail_closed, "{}", resp.payload_json);
        let v: Value = serde_json::from_str(&resp.payload_json).unwrap();
        assert_eq!(v["error"]["code"], -32003);
        assert!(v["error"]["message"]
            .as_str()
            .unwrap()
            .contains("Token/auth validation failed"));
        let audit = state
            .store
            .as_ref()
            .unwrap()
            .query_audit(store::AuditQuery {
                limit: Some(10),
                ..Default::default()
            })
            .await
            .unwrap();
        assert!(audit.iter().any(|e| e.decision == "deny"));
    }

    #[tokio::test]
    async fn denies_policy_require_approval_without_approval_id_fail_closed() {
        let mut state = state_with_store();
        state.config = GatewayConfig::default().with_rules(vec![Rule {
            effect: PolicyDecision::RequireApproval,
            ..Default::default()
        }]);
        let req = McpRequest {
            method: String::new(),
            payload_json: json!({
                "jsonrpc":"2.0","id":33,"method":"tools/call",
                "params":{"name":"gateway.health"}
            })
            .to_string(),
            upstream: None,
        };
        let resp = handle_mcp_request_async(&mut state, req).await;
        assert!(resp.fail_closed, "{}", resp.payload_json);
        let v: Value = serde_json::from_str(&resp.payload_json).unwrap();
        assert_eq!(v["error"]["code"], -32003);
        assert!(v["error"]["message"]
            .as_str()
            .unwrap()
            .contains("Approval required"));
    }

    #[derive(Debug, Default)]
    struct FailingAuditStore;

    #[async_trait::async_trait]
    impl store::Store for FailingAuditStore {
        fn backend(&self) -> store::BackendKind {
            store::BackendKind::InMemory
        }
        async fn append_audit_event(
            &self,
            _event: store::AuditEvent,
        ) -> store::StoreResult<store::AuditEvent> {
            Err(store::StoreError::Unavailable(
                "simulated audit append failure".into(),
            ))
        }
        async fn query_audit(
            &self,
            _query: store::AuditQuery,
        ) -> store::StoreResult<Vec<store::AuditEvent>> {
            Ok(vec![])
        }
        async fn verify_audit_chain(&self) -> store::StoreResult<store::AuditVerificationReport> {
            Ok(store::AuditVerificationReport {
                ok: true,
                ..Default::default()
            })
        }
        async fn create_approval(
            &self,
            approval: ApprovalRecord,
        ) -> store::StoreResult<ApprovalRecord> {
            Ok(approval)
        }
        async fn get_approval(&self, _id: &str) -> store::StoreResult<Option<ApprovalRecord>> {
            Ok(None)
        }
        async fn list_approvals(
            &self,
            _query: store::ApprovalQuery,
        ) -> store::StoreResult<Vec<ApprovalRecord>> {
            Ok(vec![])
        }
        async fn resolve_approval(
            &self,
            _id: &str,
            _status: ApprovalStatus,
            _resolver: Option<String>,
            _resolved_at: String,
        ) -> store::StoreResult<ApprovalRecord> {
            Err(store::StoreError::NotFound("not found".into()))
        }
        async fn upsert_task(&self, task: TaskRecord) -> store::StoreResult<TaskRecord> {
            Ok(task)
        }
        async fn get_task(&self, _id: &str) -> store::StoreResult<Option<TaskRecord>> {
            Ok(None)
        }
        async fn list_tasks(
            &self,
            _query: store::TaskQuery,
        ) -> store::StoreResult<Vec<TaskRecord>> {
            Ok(vec![])
        }
        async fn upsert_policy(
            &self,
            policy: store::PolicyRecord,
        ) -> store::StoreResult<store::PolicyRecord> {
            Ok(policy)
        }
        async fn get_active_policy(&self) -> store::StoreResult<Option<store::PolicyRecord>> {
            Ok(None)
        }
        async fn record_revocation(
            &self,
            record: store::RevocationRecord,
        ) -> store::StoreResult<store::RevocationRecord> {
            Ok(record)
        }
        async fn list_revocations(
            &self,
            _query: store::RevocationQuery,
        ) -> store::StoreResult<Vec<store::RevocationRecord>> {
            Ok(vec![])
        }
        async fn record_taint_snapshot(
            &self,
            snapshot: store::TaintSnapshotRecord,
        ) -> store::StoreResult<store::TaintSnapshotRecord> {
            Ok(snapshot)
        }
        async fn list_taint_snapshots(
            &self,
            _query: store::TaintSnapshotQuery,
        ) -> store::StoreResult<Vec<store::TaintSnapshotRecord>> {
            Ok(vec![])
        }
        async fn get_tool_pin(
            &self,
            _upstream_id: &str,
            _tool_name: &str,
        ) -> store::StoreResult<Option<store::ToolPinRecord>> {
            Ok(None)
        }
        async fn upsert_tool_pin(
            &self,
            record: store::ToolPinRecord,
        ) -> store::StoreResult<store::ToolPinRecord> {
            Ok(record)
        }
        async fn health_check(&self) -> store::StoreResult<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn append_before_return_fails_closed_on_allow_when_audit_append_fails() {
        let store: Arc<dyn store::Store> = Arc::new(FailingAuditStore);
        let mut state = AppState::fail_closed().with_store(store);
        state.config = permit_all_config();

        let req = McpRequest {
            method: String::new(),
            payload_json: json!({
                "jsonrpc":"2.0","id":40,"method":"tools/call",
                "params":{"name":"gateway.health"}
            })
            .to_string(),
            upstream: None,
        };
        let resp = handle_mcp_request_async(&mut state, req).await;
        assert!(resp.fail_closed, "{}", resp.payload_json);
        let v: Value = serde_json::from_str(&resp.payload_json).unwrap();
        assert_eq!(v["error"]["code"], -32000);
        assert!(v["error"]["message"]
            .as_str()
            .unwrap()
            .contains("Audit append failed"));
        assert!(
            state
                .metrics
                .audit_append_failures
                .load(std::sync::atomic::Ordering::Relaxed)
                >= 1
        );
    }

    #[tokio::test]
    async fn append_before_return_fails_closed_on_deny_when_audit_append_fails() {
        let store: Arc<dyn store::Store> = Arc::new(FailingAuditStore);
        let mut state = AppState::fail_closed().with_store(store);
        state.config = GatewayConfig::default(); // no permit rules => policy deny path

        let req = McpRequest {
            method: String::new(),
            payload_json: json!({
                "jsonrpc":"2.0","id":41,"method":"tools/call",
                "params":{"name":"gateway.health"}
            })
            .to_string(),
            upstream: None,
        };
        let resp = handle_mcp_request_async(&mut state, req).await;
        assert!(resp.fail_closed, "{}", resp.payload_json);
        let v: Value = serde_json::from_str(&resp.payload_json).unwrap();
        // audit append-before-return takes precedence for durable fail-closed behavior
        assert_eq!(v["error"]["code"], -32000);
        assert!(v["error"]["message"]
            .as_str()
            .unwrap()
            .contains("Audit append failed"));
    }

    #[tokio::test]
    async fn restart_durable_store_context_allows_and_appends_audit() {
        let store: Arc<dyn store::Store> = Arc::new(InMemoryStore::default());
        store
            .upsert_task(TaskRecord {
                id: "tdur".into(),
                token_id: "tok".into(),
                scopes: "[]".into(),
                budget: 1,
                expires_at: "later".into(),
                revoked: false,
                ..Default::default()
            })
            .await
            .unwrap();
        store
            .create_approval(ApprovalRecord {
                id: "adur".into(),
                task_id: "tdur".into(),
                tool: "gateway.health".into(),
                args_hash: "h".into(),
                status: ApprovalStatus::Approved,
                created_at: "now".into(),
                ..Default::default()
            })
            .await
            .unwrap();

        let req = || {
            McpRequest {
            method: String::new(),
            payload_json: json!({
                "jsonrpc":"2.0","id":42,"method":"tools/call",
                "params":{"name":"gateway.health","task_id":"tdur","approval_id":"adur","principal":"anonymous"}
            })
            .to_string(),
            upstream: None,
        }
        };

        let mut state1 = AppState::fail_closed().with_store(store.clone());
        state1.config = permit_all_config();
        let resp1 = handle_mcp_request_async(&mut state1, req()).await;
        assert!(resp1.ok, "{}", resp1.payload_json);

        // Simulate restart: fresh AppState against same durable store.
        let mut state2 = AppState::fail_closed().with_store(store.clone());
        state2.config = permit_all_config();
        let resp2 = handle_mcp_request_async(&mut state2, req()).await;
        assert!(resp2.ok, "{}", resp2.payload_json);

        let events = store
            .query_audit(store::AuditQuery {
                limit: Some(20),
                ..Default::default()
            })
            .await
            .unwrap();
        let allows = events
            .iter()
            .filter(|e| e.tool.as_deref() == Some("tools/call") && e.decision == "allow")
            .count();
        assert!(
            allows >= 2,
            "expected durable allow audits across restart, got {allows}"
        );
        let report = store.verify_audit_chain().await.unwrap();
        assert!(report.ok, "audit chain must remain valid: {:?}", report);
    }

    #[tokio::test]
    async fn durable_revocation_context_denies_across_restart() {
        let store: Arc<dyn store::Store> = Arc::new(InMemoryStore::default());
        store
            .record_revocation(store::RevocationRecord {
                id: "r-restart".into(),
                target_kind: "token".into(),
                target_id: "rev-restart".into(),
                reason: Some("revoked".into()),
                revoked_at: "1".into(),
                revoked_by: None,
            })
            .await
            .unwrap();

        let req = McpRequest {
            method: String::new(),
            payload_json: json!({
                "jsonrpc":"2.0","id":43,"method":"tools/call",
                "params":{
                    "name":"gateway.health",
                    "token":{"revocation_id":"rev-restart","scopes":["tools/call"],"expires_at":9999999999u64},
                    "now": 100
                }
            })
            .to_string(),
            upstream: None,
        };

        let mut state = AppState::fail_closed().with_store(store);
        state.config = permit_all_config();
        state.config.runtime_hooks.sync_revocations_from_store = true;
        let resp = handle_mcp_request_async(&mut state, req).await;
        assert!(resp.fail_closed, "{}", resp.payload_json);
        let v: Value = serde_json::from_str(&resp.payload_json).unwrap();
        assert_eq!(v["error"]["code"], -32003);
        assert!(v["error"]["message"]
            .as_str()
            .unwrap()
            .contains("Token/auth validation failed"));
    }

    #[tokio::test]
    async fn tools_call_success_persists_untrusted_taint_and_blocks_external_egress() {
        let mut state = state_with_store();
        state.config = permit_all_config();

        let first = McpRequest {
            method: String::new(),
            payload_json: json!({
                "jsonrpc":"2.0","id":100,"method":"tools/call",
                "params":{"name":"gateway.health"}
            })
            .to_string(),
            upstream: None,
        };
        let resp = handle_mcp_request_async(&mut state, first).await;
        assert!(resp.ok, "{}", resp.payload_json);
        assert!(!resp.fail_closed, "{}", resp.payload_json);

        let second = McpRequest {
            method: String::new(),
            payload_json: json!({
                "jsonrpc":"2.0","id":101,"method":"tools/call",
                "params":{
                    "name":"gateway.health",
                    "operation":"external_egress",
                    "taint_labels":["private_data"]
                }
            })
            .to_string(),
            upstream: None,
        };
        let resp = handle_mcp_request_async(&mut state, second).await;
        assert!(resp.fail_closed, "{}", resp.payload_json);
        let v: Value = serde_json::from_str(&resp.payload_json).unwrap();
        assert_eq!(v["error"]["code"], -32003);
        let msg = v["error"]["message"].as_str().unwrap_or("");
        assert!(
            msg.contains("taint") || msg.contains("Approval required"),
            "{}",
            resp.payload_json
        );
    }

    #[tokio::test]
    async fn taint_store_read_failure_is_fail_closed() {
        #[derive(Debug)]
        struct FailingTaintReadStore;
        #[async_trait::async_trait]
        impl store::Store for FailingTaintReadStore {
            fn backend(&self) -> store::BackendKind {
                store::BackendKind::InMemory
            }
            async fn append_audit_event(
                &self,
                event: store::AuditEvent,
            ) -> store::StoreResult<store::AuditEvent> {
                Ok(event)
            }
            async fn query_audit(
                &self,
                _query: store::AuditQuery,
            ) -> store::StoreResult<Vec<store::AuditEvent>> {
                Ok(vec![])
            }
            async fn verify_audit_chain(
                &self,
            ) -> store::StoreResult<store::AuditVerificationReport> {
                Ok(store::AuditVerificationReport {
                    ok: true,
                    ..Default::default()
                })
            }
            async fn create_approval(
                &self,
                approval: ApprovalRecord,
            ) -> store::StoreResult<ApprovalRecord> {
                Ok(approval)
            }
            async fn get_approval(&self, _id: &str) -> store::StoreResult<Option<ApprovalRecord>> {
                Ok(None)
            }
            async fn list_approvals(
                &self,
                _query: store::ApprovalQuery,
            ) -> store::StoreResult<Vec<ApprovalRecord>> {
                Ok(vec![])
            }
            async fn resolve_approval(
                &self,
                _id: &str,
                _status: ApprovalStatus,
                _resolver: Option<String>,
                _resolved_at: String,
            ) -> store::StoreResult<ApprovalRecord> {
                Err(store::StoreError::NotFound("x".into()))
            }
            async fn upsert_task(&self, task: TaskRecord) -> store::StoreResult<TaskRecord> {
                Ok(task)
            }
            async fn get_task(&self, _id: &str) -> store::StoreResult<Option<TaskRecord>> {
                Ok(None)
            }
            async fn list_tasks(
                &self,
                _query: store::TaskQuery,
            ) -> store::StoreResult<Vec<TaskRecord>> {
                Ok(vec![])
            }
            async fn upsert_policy(
                &self,
                policy: store::PolicyRecord,
            ) -> store::StoreResult<store::PolicyRecord> {
                Ok(policy)
            }
            async fn get_active_policy(&self) -> store::StoreResult<Option<store::PolicyRecord>> {
                Ok(None)
            }
            async fn record_revocation(
                &self,
                record: store::RevocationRecord,
            ) -> store::StoreResult<store::RevocationRecord> {
                Ok(record)
            }
            async fn list_revocations(
                &self,
                _query: store::RevocationQuery,
            ) -> store::StoreResult<Vec<store::RevocationRecord>> {
                Ok(vec![])
            }
            async fn record_taint_snapshot(
                &self,
                snapshot: store::TaintSnapshotRecord,
            ) -> store::StoreResult<store::TaintSnapshotRecord> {
                Ok(snapshot)
            }
            async fn list_taint_snapshots(
                &self,
                _query: store::TaintSnapshotQuery,
            ) -> store::StoreResult<Vec<store::TaintSnapshotRecord>> {
                Err(store::StoreError::Unavailable("taint read boom".into()))
            }
            async fn get_tool_pin(
                &self,
                _upstream_id: &str,
                _tool_name: &str,
            ) -> store::StoreResult<Option<store::ToolPinRecord>> {
                Ok(None)
            }
            async fn upsert_tool_pin(
                &self,
                record: store::ToolPinRecord,
            ) -> store::StoreResult<store::ToolPinRecord> {
                Ok(record)
            }
            async fn health_check(&self) -> store::StoreResult<()> {
                Ok(())
            }
        }

        let store: Arc<dyn store::Store> = Arc::new(FailingTaintReadStore);
        let mut state = AppState::fail_closed().with_store(store);
        state.config = permit_all_config();
        let req = McpRequest {
            method: String::new(),
            payload_json: json!({"jsonrpc":"2.0","id":102,"method":"tools/call","params":{"name":"gateway.health"}}).to_string(),
            upstream: None,
        };
        let resp = handle_mcp_request_async(&mut state, req).await;
        assert!(resp.fail_closed, "{}", resp.payload_json);
        let v: Value = serde_json::from_str(&resp.payload_json).unwrap();
        assert_eq!(v["error"]["code"], -32002);
        assert!(v["error"]["message"]
            .as_str()
            .unwrap()
            .contains("Taint context unavailable"));
    }

    #[test]
    fn scrub_agent_visible_payload_redacts_secret_markers() {
        let payload = json!({
            "jsonrpc":"2.0","id":1,
            "result":{"content":[{"type":"text","text":"leaked api_key=supersecret token=abc123"}]}
        })
        .to_string();
        let scrubbed = scrub_agent_visible_payload(&payload).expect("should scrub");
        assert!(!scrubbed.contains("supersecret"), "{scrubbed}");
        assert!(
            !scrubbed.to_lowercase().contains("api_key=supersecret"),
            "{scrubbed}"
        );
        assert!(scrubbed.contains("[REDACTED]"), "{scrubbed}");
    }

    #[test]
    fn jsonrpc_error_scrubs_secret_markers() {
        let resp = jsonrpc_error(Value::from(7), -32000, "upstream failed: password=hunter2");
        assert!(resp.fail_closed);
        assert!(
            !resp.payload_json.contains("hunter2"),
            "{}",
            resp.payload_json
        );
        assert!(
            resp.payload_json.contains("[REDACTED]"),
            "{}",
            resp.payload_json
        );
    }

    #[tokio::test]
    async fn tools_list_first_seen_records_tool_pin_and_allows() {
        let mut state = state_with_store();
        state.config = permit_all_config();
        let req = McpRequest {
            method: String::new(),
            payload_json: json!({"jsonrpc":"2.0","id":210,"method":"tools/list","params":{}})
                .to_string(),
            upstream: None,
        };
        let resp = handle_mcp_request_async(&mut state, req).await;
        assert!(resp.ok, "{}", resp.payload_json);
        let store = state.store.as_ref().unwrap();
        let pin = store
            .get_tool_pin("default", "gateway.health")
            .await
            .unwrap()
            .expect("first-seen pin should be recorded");
        assert!(pin.approved);
        assert!(!pin.descriptor_hash.is_empty());
        assert!(pin.descriptor_json.contains("gateway.health"));
    }

    #[tokio::test]
    async fn tools_list_drift_is_denied_fail_closed() {
        let mut state = state_with_store();
        state.config = permit_all_config();
        let store = state.store.as_ref().unwrap();
        store
            .upsert_tool_pin(store::ToolPinRecord {
                upstream_id: "default".into(),
                tool_name: "gateway.health".into(),
                descriptor_hash: "pinned-old-hash".into(),
                descriptor_json:
                    r#"{"description":"old","inputSchema":{},"name":"gateway.health"}"#.into(),
                first_seen_at: "1".into(),
                approved: true,
            })
            .await
            .unwrap();

        let req = McpRequest {
            method: String::new(),
            payload_json: json!({"jsonrpc":"2.0","id":211,"method":"tools/list","params":{}})
                .to_string(),
            upstream: None,
        };
        let resp = handle_mcp_request_async(&mut state, req).await;
        assert!(resp.fail_closed, "{}", resp.payload_json);
        let v: Value = serde_json::from_str(&resp.payload_json).unwrap();
        assert_eq!(v["error"]["code"], -32003);
        let msg = v["error"]["message"].as_str().unwrap_or("");
        assert!(msg.contains("tool_manifest_drift_detected"), "{msg}");
        assert!(msg.contains("re-approval required"), "{msg}");
    }

    #[tokio::test]
    async fn tools_list_unapproved_pin_is_denied_fail_closed() {
        let mut state = state_with_store();
        state.config = permit_all_config();
        let store = state.store.as_ref().unwrap();
        store
            .upsert_tool_pin(store::ToolPinRecord {
                upstream_id: "default".into(),
                tool_name: "gateway.health".into(),
                descriptor_hash: "any".into(),
                descriptor_json: "{}".into(),
                first_seen_at: "1".into(),
                approved: false,
            })
            .await
            .unwrap();

        let req = McpRequest {
            method: String::new(),
            payload_json: json!({"jsonrpc":"2.0","id":212,"method":"tools/list","params":{}})
                .to_string(),
            upstream: None,
        };
        let resp = handle_mcp_request_async(&mut state, req).await;
        assert!(resp.fail_closed, "{}", resp.payload_json);
        let v: Value = serde_json::from_str(&resp.payload_json).unwrap();
        let msg = v["error"]["message"].as_str().unwrap_or("");
        assert!(msg.contains("tool_manifest_pin_not_approved"), "{msg}");
    }

    #[tokio::test]
    async fn tools_list_pin_store_read_failure_is_fail_closed() {
        #[derive(Debug)]
        struct FailingToolPinReadStore;
        #[async_trait::async_trait]
        impl store::Store for FailingToolPinReadStore {
            fn backend(&self) -> store::BackendKind {
                store::BackendKind::InMemory
            }
            async fn append_audit_event(
                &self,
                event: store::AuditEvent,
            ) -> store::StoreResult<store::AuditEvent> {
                Ok(event)
            }
            async fn query_audit(
                &self,
                _query: store::AuditQuery,
            ) -> store::StoreResult<Vec<store::AuditEvent>> {
                Ok(vec![])
            }
            async fn verify_audit_chain(
                &self,
            ) -> store::StoreResult<store::AuditVerificationReport> {
                Ok(store::AuditVerificationReport {
                    ok: true,
                    ..Default::default()
                })
            }
            async fn create_approval(
                &self,
                approval: ApprovalRecord,
            ) -> store::StoreResult<ApprovalRecord> {
                Ok(approval)
            }
            async fn get_approval(&self, _id: &str) -> store::StoreResult<Option<ApprovalRecord>> {
                Ok(None)
            }
            async fn list_approvals(
                &self,
                _query: store::ApprovalQuery,
            ) -> store::StoreResult<Vec<ApprovalRecord>> {
                Ok(vec![])
            }
            async fn resolve_approval(
                &self,
                _id: &str,
                _status: store::ApprovalStatus,
                _resolver: Option<String>,
                _resolved_at: String,
            ) -> store::StoreResult<ApprovalRecord> {
                Err(store::StoreError::NotFound("x".into()))
            }
            async fn upsert_task(&self, task: TaskRecord) -> store::StoreResult<TaskRecord> {
                Ok(task)
            }
            async fn get_task(&self, _id: &str) -> store::StoreResult<Option<TaskRecord>> {
                Ok(None)
            }
            async fn list_tasks(
                &self,
                _query: store::TaskQuery,
            ) -> store::StoreResult<Vec<TaskRecord>> {
                Ok(vec![])
            }
            async fn upsert_policy(
                &self,
                policy: store::PolicyRecord,
            ) -> store::StoreResult<store::PolicyRecord> {
                Ok(policy)
            }
            async fn get_active_policy(&self) -> store::StoreResult<Option<store::PolicyRecord>> {
                Ok(None)
            }
            async fn record_revocation(
                &self,
                record: store::RevocationRecord,
            ) -> store::StoreResult<store::RevocationRecord> {
                Ok(record)
            }
            async fn list_revocations(
                &self,
                _query: store::RevocationQuery,
            ) -> store::StoreResult<Vec<store::RevocationRecord>> {
                Ok(vec![])
            }
            async fn record_taint_snapshot(
                &self,
                snapshot: store::TaintSnapshotRecord,
            ) -> store::StoreResult<store::TaintSnapshotRecord> {
                Ok(snapshot)
            }
            async fn list_taint_snapshots(
                &self,
                _query: store::TaintSnapshotQuery,
            ) -> store::StoreResult<Vec<store::TaintSnapshotRecord>> {
                Ok(vec![])
            }
            async fn get_tool_pin(
                &self,
                _upstream_id: &str,
                _tool_name: &str,
            ) -> store::StoreResult<Option<store::ToolPinRecord>> {
                Err(store::StoreError::Unavailable("pin read boom".into()))
            }
            async fn upsert_tool_pin(
                &self,
                record: store::ToolPinRecord,
            ) -> store::StoreResult<store::ToolPinRecord> {
                Ok(record)
            }
            async fn health_check(&self) -> store::StoreResult<()> {
                Ok(())
            }
        }

        let store: Arc<dyn store::Store> = Arc::new(FailingToolPinReadStore);
        let mut state = AppState::fail_closed().with_store(store);
        state.config = permit_all_config();
        let req = McpRequest {
            method: String::new(),
            payload_json: json!({"jsonrpc":"2.0","id":213,"method":"tools/list","params":{}})
                .to_string(),
            upstream: None,
        };
        let resp = handle_mcp_request_async(&mut state, req).await;
        assert!(resp.fail_closed, "{}", resp.payload_json);
        let v: Value = serde_json::from_str(&resp.payload_json).unwrap();
        let msg = v["error"]["message"].as_str().unwrap_or("");
        assert!(msg.contains("tool_pin_store_read_failed"), "{msg}");
    }

    #[tokio::test]
    async fn mcp_responses_are_bound_to_request_id_and_task_across_shared_state() {
        let mut state = state_with_store();
        state.config = permit_all_config();
        let store = state.store.clone().unwrap();
        for tid in ["task-a", "task-b"] {
            store
                .upsert_task(TaskRecord {
                    id: tid.into(),
                    token_id: "tok".into(),
                    scopes: "[]".into(),
                    budget: 1,
                    expires_at: "later".into(),
                    revoked: false,
                    ..Default::default()
                })
                .await
                .unwrap();
        }

        let mk = |id: i64, task_id: &str| McpRequest {
            method: String::new(),
            payload_json: json!({
                "jsonrpc":"2.0","id":id,"method":"tools/call",
                "params":{"name":"gateway.health","task_id":task_id,"principal":"anonymous"}
            })
            .to_string(),
            upstream: None,
        };

        let resp_a = handle_mcp_request_async(&mut state, mk(101, "task-a")).await;
        let resp_b = handle_mcp_request_async(&mut state, mk(202, "task-b")).await;

        for (resp, expected_id, expected_task) in
            [(&resp_a, 101i64, "task-a"), (&resp_b, 202i64, "task-b")]
        {
            assert!(resp.ok, "{}", resp.payload_json);
            let v: Value = serde_json::from_str(&resp.payload_json).unwrap();
            assert_eq!(v["id"], expected_id, "response id must be request-local");
            assert_eq!(
                v["result"]["structuredContent"]["ok"], true,
                "{}",
                resp.payload_json
            );
            assert!(
                !resp.payload_json.contains(if expected_task == "task-a" {
                    "\"task-b\""
                } else {
                    "\"task-a\""
                }),
                "response must not leak other task id: {}",
                resp.payload_json
            );
        }

        let audit = store
            .query_audit(store::AuditQuery {
                limit: Some(50),
                ..Default::default()
            })
            .await
            .unwrap();
        let allow_a = audit.iter().any(|e| {
            e.task_id.as_deref() == Some("task-a")
                && e.tool.as_deref() == Some("tools/call")
                && e.decision == "allow"
        });
        let allow_b = audit.iter().any(|e| {
            e.task_id.as_deref() == Some("task-b")
                && e.tool.as_deref() == Some("tools/call")
                && e.decision == "allow"
        });
        assert!(allow_a, "task-a audit missing: {audit:?}");
        assert!(allow_b, "task-b audit missing: {audit:?}");
    }

    #[tokio::test]
    async fn mcp_task_and_approval_context_are_request_local() {
        let mut state = state_with_store();
        state.config = permit_all_config();
        let store = state.store.clone().unwrap();
        for (tid, aid) in [("task-a", "ap-a"), ("task-b", "ap-b")] {
            store
                .upsert_task(TaskRecord {
                    id: tid.into(),
                    token_id: "tok".into(),
                    scopes: "[]".into(),
                    budget: 1,
                    expires_at: "later".into(),
                    revoked: false,
                    ..Default::default()
                })
                .await
                .unwrap();
            store
                .create_approval(ApprovalRecord {
                    id: aid.into(),
                    task_id: tid.into(),
                    tool: "gateway.health".into(),
                    args_hash: "h".into(),
                    status: ApprovalStatus::Approved,
                    created_at: "now".into(),
                    ..Default::default()
                })
                .await
                .unwrap();
        }

        // Request A uses task-a/ap-a (valid). Request B tries to reuse ap-a on task-b (mismatch).
        let req_a = McpRequest {
            method: String::new(),
            payload_json: json!({
                "jsonrpc":"2.0","id":"req-a","method":"tools/call",
                "params":{"name":"gateway.health","task_id":"task-a","approval_id":"ap-a","principal":"anonymous"}
            })
            .to_string(),
            upstream: None,
        };
        let req_b = McpRequest {
            method: String::new(),
            payload_json: json!({
                "jsonrpc":"2.0","id":"req-b","method":"tools/call",
                "params":{"name":"gateway.health","task_id":"task-b","approval_id":"ap-a","principal":"anonymous"}
            })
            .to_string(),
            upstream: None,
        };

        let resp_a = handle_mcp_request_async(&mut state, req_a).await;
        let resp_b = handle_mcp_request_async(&mut state, req_b).await;

        let va: Value = serde_json::from_str(&resp_a.payload_json).unwrap();
        assert!(resp_a.ok, "{}", resp_a.payload_json);
        assert_eq!(va["id"], "req-a");
        assert_eq!(va["result"]["structuredContent"]["ok"], true);

        let vb: Value = serde_json::from_str(&resp_b.payload_json).unwrap();
        assert!(resp_b.fail_closed, "{}", resp_b.payload_json);
        assert_eq!(vb["id"], "req-b", "denied response must keep request id");
        assert!(vb["error"]["message"]
            .as_str()
            .unwrap_or("")
            .contains("Approval task mismatch"));
        assert!(
            !resp_b.payload_json.contains("task-a"),
            "cross-task context leaked into response: {}",
            resp_b.payload_json
        );
    }
}
