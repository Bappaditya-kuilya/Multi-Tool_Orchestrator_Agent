//! MCP endpoint dispatch: front parse/shape + pool dispatch + store-backed audit/policy/approvals.

use scopegate_core::audit::digest;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use store::{ApprovalStatus as StoreApprovalStatus, AuditEvent};

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

fn jsonrpc_error(id: Value, code: i64, message: &str) -> McpResponse {
    McpResponse {
        ok: false,
        payload_json: json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":message},"fail_closed":true}).to_string(),
        fail_closed: true,
    }
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

async fn approval_allows_mcp(state: &AppState, approval_id: &str) -> bool {
    let Some(store) = &state.store else {
        return false;
    };
    match store.get_approval(approval_id).await {
        Ok(Some(a)) => matches!(a.status, StoreApprovalStatus::Approved),
        _ => false,
    }
}

/// Dispatch MCP JSON-RPC through gateway front logic + pool/upstream abstractions with store-backed controls.
pub async fn handle_mcp_request_async(state: &mut AppState, req: McpRequest) -> McpResponse {
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

    // Store-backed policy gate for mutating/dispatch methods (fail-closed).
    let principal = parsed
        .get("params")
        .and_then(|p| p.get("principal"))
        .and_then(|v| v.as_str())
        .unwrap_or("anonymous");
    let tool_name = parsed
        .get("params")
        .and_then(|p| p.get("name"))
        .and_then(|v| v.as_str())
        .unwrap_or(&method);
    let policy_ok = policy_allows_mcp(state, principal, &method, tool_name).await;
    let approval_id = parsed
        .get("params")
        .and_then(|p| p.get("approval_id"))
        .and_then(|v| v.as_str());
    let approval_ok = match approval_id {
        Some(aid) => approval_allows_mcp(state, aid).await,
        None => {
            !state.config.fail_closed
                || method == "initialize"
                || method == "tools/list"
                || method == "ping"
        }
    };

    if !policy_ok && !(method == "initialize" || method == "tools/list" || method == "ping") {
        let _ = append_mcp_audit(
            state,
            task_id.clone(),
            &method,
            "deny",
            Some("policy_denied_or_missing".into()),
            Some(digest(&parsed.to_string())),
            None,
        )
        .await;
        return jsonrpc_error(id, -32003, "denied by policy (fail-closed)");
    }
    if method == "tools/call" && approval_id.is_some() && !approval_ok {
        let _ = append_mcp_audit(
            state,
            task_id.clone(),
            &method,
            "deny",
            Some("approval_required_or_denied".into()),
            Some(digest(&parsed.to_string())),
            None,
        )
        .await;
        return jsonrpc_error(id, -32003, "denied: approval not granted (fail-closed)");
    }

    // Front/routing + pool/upstream dispatch abstractions.
    let result = match method.as_str() {
        "initialize" => Ok(json!({
            "protocolVersion":"2024-11-05",
            "capabilities":{"tools":{"listChanged": false}},
            "serverInfo":{"name":"gateway-mcp-front","version": env!("CARGO_PKG_VERSION")}
        })),
        "ping" => Ok(json!({})),
        "tools/list" => {
            // If pool/upstream configured, try forwarding; else provide local capability surface.
            if state.mcp.is_some() {
                match state.dispatch_mcp_via_pool("tools/list", parsed.to_string(), req.upstream.as_deref()) {
                    Ok(payload) => serde_json::from_str::<Value>(&payload)
                        .map(|v| v.get("result").cloned().unwrap_or(v))
                        .or_else(|_| Ok(json!({"tools":[{"name":"gateway.health","description":"Gateway MCP dispatch health probe","inputSchema":{"type":"object"}}]}))),
                    Err(_) => Ok(json!({"tools":[{"name":"gateway.health","description":"Gateway MCP dispatch health probe","inputSchema":{"type":"object"}}]})),
                }
            } else {
                Ok(
                    json!({"tools":[{"name":"gateway.health","description":"Gateway MCP dispatch health probe","inputSchema":{"type":"object"}}]}),
                )
            }
        }
        "tools/call" => {
            let name = parsed
                .get("params")
                .and_then(|p| p.get("name"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if name == "gateway.health" {
                Ok(
                    json!({"content":[{"type":"text","text":"ok"}],"isError": false, "structuredContent":{"ok":true,"dispatch":"gateway+pool-abstraction"}}),
                )
            } else if state.mcp.is_some() {
                match state.dispatch_mcp_via_pool(
                    "tools/call",
                    parsed.to_string(),
                    req.upstream.as_deref(),
                ) {
                    Ok(payload) => serde_json::from_str::<Value>(&payload)
                        .map(|v| v.get("result").cloned().unwrap_or(v))
                        .map_err(|e| format!("upstream_response_parse_failed:{e}")),
                    Err(e) => Err(e),
                }
            } else {
                Err("mcp_upstream_not_configured".to_string())
            }
        }
        _ => {
            // Generic method forwarding through pool if configured (front→pool→upstream path).
            if state.mcp.is_some() {
                match state.dispatch_mcp_via_pool(
                    &method,
                    parsed.to_string(),
                    req.upstream.as_deref(),
                ) {
                    Ok(payload) => serde_json::from_str::<Value>(&payload)
                        .map(|v| v.get("result").cloned().unwrap_or(v))
                        .map_err(|e| format!("upstream_response_parse_failed:{e}")),
                    Err(e) => Err(e),
                }
            } else {
                Err("method_not_found".to_string())
            }
        }
    };

    match result {
        Ok(r) => {
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
                return jsonrpc_error(id, -32000, "audit append failed (fail-closed)");
            }
            emit(state, "mcp.response", "ok", task_id);
            McpResponse {
                ok: true,
                payload_json: json!({"jsonrpc":"2.0","id":id,"result":r}).to_string(),
                fail_closed: false,
            }
        }
        Err(e) => {
            let _ = append_mcp_audit(
                state,
                task_id.clone(),
                &method,
                "deny",
                Some(e.clone()),
                Some(digest(&parsed.to_string())),
                None,
            )
            .await;
            let msg = if e == "method_not_found" {
                "method/tool not found (fail-closed)"
            } else if e == "mcp_upstream_not_configured" {
                "upstream not configured (fail-closed)"
            } else {
                "dispatch failed (fail-closed)"
            };
            jsonrpc_error(
                id,
                if e == "method_not_found" {
                    -32601
                } else {
                    -32000
                },
                msg,
            )
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
        Some(r) => McpResponse {
            ok: true,
            payload_json: json!({"jsonrpc":"2.0","id":id,"result":r}).to_string(),
            fail_closed: false,
        },
        None => jsonrpc_error(id, -32601, "method/tool not found (fail-closed)"),
    }
}

/// Legacy placeholder.
pub fn handle_mcp_placeholder(_req: McpRequest) -> McpResponse {
    McpResponse {
        ok: false,
        payload_json: json!({"error":"mcp_not_configured","fail_closed":true}).to_string(),
        fail_closed: true,
    }
}
