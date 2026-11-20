//! Axum HTTP server wiring for gateway runtime.

use std::{convert::Infallible, net::SocketAddr, sync::Arc, time::Duration};

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{
    sse::{Event, KeepAlive, Sse},
    IntoResponse, Response,
};
use axum::routing::{any, get, post};
use axum::{Json, Router};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio_stream::{wrappers::BroadcastStream, StreamExt};

use crate::api::{self, routes, ApiResponse, HttpStatus};
use crate::mcp;
use crate::state::AppState;

pub type SharedState = Arc<Mutex<AppState>>;

pub fn router(state: SharedState) -> Router {
    let app: Router<SharedState> = Router::new()
        .route(routes::HEALTHZ, get(healthz))
        .route(routes::READYZ, get(readyz))
        .route(routes::METRICS, get(metrics))
        .route(routes::V1_TASKS, post(v1_tasks).get(v1_tasks_list))
        .route(routes::V1_TASKS_REVOKE, post(v1_task_revoke))
        .route(routes::V1_TASKS_ID, get(v1_task_get))
        .route(routes::V1_AUDIT, get(v1_audit_get).post(v1_audit_post))
        .route(routes::V1_AUDIT_VERIFY, get(v1_audit_verify))
        .route(
            routes::V1_APPROVALS,
            get(v1_approvals_list).post(v1_approvals),
        )
        .route(routes::V1_APPROVALS_ID, get(v1_approval_get))
        .route(routes::V1_APPROVALS_RESOLVE, post(v1_approval_resolve))
        .route(
            routes::V1_POLICIES,
            get(v1_policies_get).post(v1_policies_post),
        )
        .route(routes::V1_STREAM, get(v1_stream))
        .route(mcp::McpEndpoint::PATH, any(mcp_handler))
        .fallback(fail_closed_fallback);
    app.with_state(state)
}

pub async fn serve(addr: SocketAddr, state: SharedState) -> anyhow::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    axum::serve(listener, router(state)).await?;
    Ok(())
}

fn status_code(s: HttpStatus) -> StatusCode {
    match s {
        HttpStatus::Ok => StatusCode::OK,
        HttpStatus::Accepted => StatusCode::ACCEPTED,
        HttpStatus::BadRequest => StatusCode::BAD_REQUEST,
        HttpStatus::Unauthorized => StatusCode::UNAUTHORIZED,
        HttpStatus::Forbidden => StatusCode::FORBIDDEN,
        HttpStatus::NotFound => StatusCode::NOT_FOUND,
        HttpStatus::Conflict => StatusCode::CONFLICT,
        HttpStatus::ServiceUnavailable => StatusCode::SERVICE_UNAVAILABLE,
        HttpStatus::NotImplemented => StatusCode::NOT_IMPLEMENTED,
        HttpStatus::InternalServerError => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

fn json_response<T: serde::Serialize>(resp: ApiResponse<T>) -> Response {
    (status_code(resp.status), Json(resp)).into_response()
}

async fn fail_closed_fallback(uri: axum::http::Uri) -> Response {
    let path = uri.path();
    if path == "/v1" || path.starts_with("/v1/") {
        json_response(ApiResponse::<()>::fail(
            HttpStatus::NotFound,
            format!("not found (fail-closed): {path}"),
        ))
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}

fn jsonrpc_error_value(id: serde_json::Value, code: i64, message: &str) -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": code, "message": message },
        "fail_closed": true
    })
}

async fn healthz(State(state): State<SharedState>) -> Response {
    let st = state.lock().await;
    json_response(api::handle_healthz(&st.config))
}

async fn readyz(State(state): State<SharedState>) -> Response {
    let (has_store, has_broker, store) = {
        let st = state.lock().await;
        (st.has_store(), st.has_broker(), st.store.clone())
    };
    let ready_store = if has_store {
        match store {
            Some(s) => s.health_check().await.is_ok(),
            None => false,
        }
    } else {
        false
    };
    let resp = if ready_store && has_broker {
        ApiResponse::ok(api::ReadyzResponse {
            ready: true,
            reason: None,
        })
    } else {
        let reason = if !ready_store {
            "store_unavailable"
        } else {
            "broker_unavailable"
        }
        .to_string();
        ApiResponse {
            status: HttpStatus::ServiceUnavailable,
            body: Some(api::ReadyzResponse {
                ready: false,
                reason: Some(reason.clone()),
            }),
            fail_closed: true,
            error: Some(reason),
        }
    };
    json_response(resp)
}

async fn metrics(State(state): State<SharedState>) -> Response {
    let st = state.lock().await;
    let resp = api::handle_metrics(&st);
    let body = resp.body.map(|b| b.body).unwrap_or_default();
    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4")],
        body,
    )
        .into_response()
}

async fn v1_tasks(
    State(state): State<SharedState>,
    Json(req): Json<api::TaskCreateRequest>,
) -> Response {
    let mut st = state.lock().await;
    let resp = api::handle_v1_tasks(&mut st, req).await;
    json_response(resp)
}

async fn v1_tasks_list(State(state): State<SharedState>) -> Response {
    let st = state.lock().await;
    let resp = api::handle_v1_tasks_list(&st).await;
    json_response(resp)
}

async fn v1_task_get(State(state): State<SharedState>, Path(id): Path<String>) -> Response {
    let st = state.lock().await;
    let resp = api::handle_v1_task_get(&st, &id).await;
    json_response(resp)
}

async fn v1_task_revoke(
    State(state): State<SharedState>,
    Path(id): Path<String>,
    body: Bytes,
) -> Response {
    let req = if body.is_empty() {
        api::TaskRevokeRequest::default()
    } else {
        serde_json::from_slice::<api::TaskRevokeRequest>(&body).unwrap_or_default()
    };
    let st = state.lock().await;
    let resp = api::handle_v1_task_revoke(&st, &id, req).await;
    json_response(resp)
}

async fn v1_audit_get(
    State(state): State<SharedState>,
    Query(req): Query<api::AuditQueryRequest>,
) -> Response {
    let st = state.lock().await;
    let resp = api::handle_v1_audit(&st, req).await;
    json_response(resp)
}

async fn v1_audit_post(
    State(state): State<SharedState>,
    Json(req): Json<api::AuditQueryRequest>,
) -> Response {
    let st = state.lock().await;
    let resp = api::handle_v1_audit(&st, req).await;
    json_response(resp)
}

async fn v1_audit_verify(State(state): State<SharedState>) -> Response {
    let st = state.lock().await;
    let resp = api::handle_v1_audit_verify(&st).await;
    json_response(resp)
}

async fn v1_approvals(
    State(state): State<SharedState>,
    Json(req): Json<api::ApprovalDecisionRequest>,
) -> Response {
    let mut st = state.lock().await;
    let resp = api::handle_v1_approvals(&mut st, req).await;
    json_response(resp)
}

async fn v1_approvals_list(
    State(state): State<SharedState>,
    Query(req): Query<api::ApprovalListQueryRequest>,
) -> Response {
    let st = state.lock().await;
    let resp = api::handle_v1_approvals_list(&st, req).await;
    json_response(resp)
}

async fn v1_approval_get(State(state): State<SharedState>, Path(id): Path<String>) -> Response {
    let st = state.lock().await;
    let resp = api::handle_v1_approval_get(&st, &id).await;
    json_response(resp)
}

async fn v1_approval_resolve(
    State(state): State<SharedState>,
    Path(id): Path<String>,
    body: Bytes,
) -> Response {
    let req = if body.is_empty() {
        api::ApprovalPathResolveRequest::default()
    } else {
        serde_json::from_slice::<api::ApprovalPathResolveRequest>(&body).unwrap_or_default()
    };
    let mut st = state.lock().await;
    let resp = api::handle_v1_approval_resolve(&mut st, &id, req).await;
    json_response(resp)
}

async fn v1_policies_get(State(state): State<SharedState>) -> Response {
    let st = state.lock().await;
    let resp = api::handle_v1_policies(&st, None).await;
    json_response(resp)
}

async fn v1_policies_post(
    State(state): State<SharedState>,
    Json(req): Json<api::PolicyUpsertRequest>,
) -> Response {
    let st = state.lock().await;
    let resp = api::handle_v1_policies(&st, Some(req)).await;
    json_response(resp)
}

async fn v1_stream(State(state): State<SharedState>) -> Response {
    let rx = {
        let st = state.lock().await;
        st.events_tx.subscribe()
    };
    let stream = BroadcastStream::new(rx).filter_map(|msg| match msg {
        Ok(data) => Some(Ok::<Event, Infallible>(
            Event::default().event("gateway").data(data),
        )),
        Err(tokio_stream::wrappers::errors::BroadcastStreamRecvError::Lagged(n)) => {
            let payload =
                format!("{{\"kind\":\"stream.lagged\",\"message\":\"missed {n} events\"}}");
            Some(Ok::<Event, Infallible>(
                Event::default().event("gateway").data(payload),
            ))
        }
    });
    Sse::new(stream)
        .keep_alive(
            KeepAlive::new()
                .interval(Duration::from_secs(15))
                .text("keepalive"),
        )
        .into_response()
}

fn mcp_http_status(resp: &mcp::McpResponse) -> StatusCode {
    if !resp.fail_closed {
        return StatusCode::OK;
    }
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&resp.payload_json) {
        if let Some(code) = v
            .get("error")
            .and_then(|e| e.get("code"))
            .and_then(|c| c.as_i64())
        {
            return match code {
                -32700 | -32600 | -32602 => StatusCode::BAD_REQUEST,
                -32601 => StatusCode::NOT_FOUND,
                -32003 => StatusCode::FORBIDDEN,
                _ => StatusCode::SERVICE_UNAVAILABLE,
            };
        }
    }
    StatusCode::SERVICE_UNAVAILABLE
}

async fn mcp_handler(
    State(state): State<SharedState>,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if method != Method::POST {
        return (
            StatusCode::METHOD_NOT_ALLOWED,
            Json(jsonrpc_error_value(
                serde_json::Value::Null,
                -32600,
                "POST required (fail-closed)",
            )),
        )
            .into_response();
    }
    if body.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(jsonrpc_error_value(
                serde_json::Value::Null,
                -32700,
                "Invalid or missing JSON body (fail-closed)",
            )),
        )
            .into_response();
    }
    let value = match serde_json::from_slice::<serde_json::Value>(&body) {
        Ok(v) => v,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(jsonrpc_error_value(
                    serde_json::Value::Null,
                    -32700,
                    "Invalid or missing JSON body (fail-closed)",
                )),
            )
                .into_response();
        }
    };
    let raw_jsonrpc = value.get("jsonrpc").is_some()
        && value.get("payload_json").is_none()
        && value.get("upstream").is_none();
    let mut req = match serde_json::from_value::<mcp::McpRequest>(value.clone()) {
        Ok(r) => r,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(jsonrpc_error_value(
                    value.get("id").cloned().unwrap_or(serde_json::Value::Null),
                    -32600,
                    "Invalid MCP request (fail-closed)",
                )),
            )
                .into_response();
        }
    };
    if req.payload_json.trim().is_empty() && raw_jsonrpc {
        req.payload_json = String::from_utf8_lossy(&body).into_owned();
    }
    // Fail-closed: empty payloads are invalid for MCP dispatch (raw or envelope form).
    if req.payload_json.trim().is_empty() && req.method.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(jsonrpc_error_value(
                value.get("id").cloned().unwrap_or(serde_json::Value::Null),
                -32600,
                "Invalid MCP request (fail-closed)",
            )),
        )
            .into_response();
    }
    let auth = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let resp = {
        let mut st = state.lock().await;
        mcp::handle_mcp_request_async_with_context(
            &mut st,
            req,
            mcp::McpHttpContext {
                authorization: auth,
            },
        )
        .await
    };
    let status = mcp_http_status(&resp);
    if raw_jsonrpc {
        if let Ok(payload) = serde_json::from_str::<serde_json::Value>(&resp.payload_json) {
            return (status, Json(payload)).into_response();
        }
        return (status, resp.payload_json).into_response();
    }
    (status, Json(resp)).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{to_bytes, Body};
    use axum::http::Request;
    use serde_json::json;
    use tower::ServiceExt;

    fn app_state() -> SharedState {
        let store = Arc::new(store::InMemoryStore::default()) as Arc<dyn store::Store>;
        Arc::new(Mutex::new(AppState::fail_closed().with_store(store)))
    }

    #[tokio::test]
    async fn mcp_get_is_fail_closed_method_not_allowed() {
        let app = router(app_state());
        let res = app
            .oneshot(Request::builder().uri("/mcp").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::METHOD_NOT_ALLOWED);
        let body: serde_json::Value =
            serde_json::from_slice(&to_bytes(res.into_body(), usize::MAX).await.unwrap()).unwrap();
        assert_eq!(body["jsonrpc"], "2.0");
        assert_eq!(body["fail_closed"], true);
        assert_eq!(body["error"]["code"], -32600);
        assert!(body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("POST required"));
    }

    #[tokio::test]
    async fn mcp_post_without_json_body_is_fail_closed_bad_request() {
        let app = router(app_state());
        let res = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mcp")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        let body: serde_json::Value =
            serde_json::from_slice(&to_bytes(res.into_body(), usize::MAX).await.unwrap()).unwrap();
        assert_eq!(body["jsonrpc"], "2.0");
        assert_eq!(body["id"], serde_json::Value::Null);
        assert_eq!(body["error"]["code"], -32700);
        assert_eq!(body["fail_closed"], true);
    }

    #[tokio::test]
    async fn mcp_post_with_invalid_json_is_fail_closed_bad_request() {
        let app = router(app_state());
        let res = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mcp")
                    .header("content-type", "application/json")
                    .body(Body::from("{not-json"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        let body: serde_json::Value =
            serde_json::from_slice(&to_bytes(res.into_body(), usize::MAX).await.unwrap()).unwrap();
        assert_eq!(body["jsonrpc"], "2.0");
        assert_eq!(body["id"], serde_json::Value::Null);
        assert_eq!(body["error"]["code"], -32700);
        assert_eq!(body["fail_closed"], true);
    }

    #[tokio::test]
    async fn mcp_policy_denial_maps_to_http_forbidden() {
        let app = router(app_state());
        let req = json!({
            "method":"",
            "payload_json": json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"gateway.health","principal":"anonymous"}}).to_string()
        });
        let res = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mcp")
                    .header("content-type", "application/json")
                    .body(Body::from(req.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
        let body: serde_json::Value =
            serde_json::from_slice(&to_bytes(res.into_body(), usize::MAX).await.unwrap()).unwrap();
        assert_eq!(body["fail_closed"], true);
        let inner: serde_json::Value =
            serde_json::from_str(body["payload_json"].as_str().unwrap()).unwrap();
        assert_eq!(inner["error"]["code"], -32003);
    }

    #[tokio::test]
    async fn metrics_and_sse_endpoints_available() {
        let app = router(app_state());
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let ct = res.headers().get("content-type").unwrap().to_str().unwrap();
        assert!(ct.contains("text/plain"));
        let body = to_bytes(res.into_body(), usize::MAX).await.unwrap();
        assert!(String::from_utf8(body.to_vec())
            .unwrap()
            .contains("gateway_requests_total"));

        let res = app
            .oneshot(
                Request::builder()
                    .uri("/v1/stream")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let ct = res.headers().get("content-type").unwrap().to_str().unwrap();
        assert!(ct.contains("text/event-stream"));
    }

    #[tokio::test]
    async fn unknown_v1_route_is_fail_closed_not_found() {
        let app = router(app_state());
        let res = app
            .oneshot(
                Request::builder()
                    .uri("/v1/does-not-exist")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
        let body: serde_json::Value =
            serde_json::from_slice(&to_bytes(res.into_body(), usize::MAX).await.unwrap()).unwrap();
        assert_eq!(body["fail_closed"], true);
        assert_eq!(body["status"], "NotFound");
        assert!(body["error"]
            .as_str()
            .unwrap()
            .contains("not found (fail-closed)"));
    }

    #[tokio::test]
    async fn unknown_non_v1_route_is_plain_not_found() {
        let app = router(app_state());
        let res = app
            .oneshot(
                Request::builder()
                    .uri("/does-not-exist")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
        let body = to_bytes(res.into_body(), usize::MAX).await.unwrap();
        assert!(body.is_empty());
    }

    #[tokio::test]
    async fn v1_audit_get_accepts_query_params() {
        let app = router(app_state());
        let res = app
            .oneshot(
                Request::builder()
                    .uri("/v1/audit?task_id=t1&verify=true&limit=5")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_slice(&to_bytes(res.into_body(), usize::MAX).await.unwrap()).unwrap();
        assert_eq!(body["status"], "Ok");
        assert_eq!(body["fail_closed"], false);
        assert!(body["body"]["events"].is_array());
        assert!(body["body"]["chain_verified"].is_boolean());
        assert!(body["body"]["verification"].is_object());
    }

    #[tokio::test]
    async fn v1_audit_verify_route_available() {
        let app = router(app_state());
        let res = app
            .oneshot(
                Request::builder()
                    .uri("/v1/audit/verify")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_slice(&to_bytes(res.into_body(), usize::MAX).await.unwrap()).unwrap();
        assert_eq!(body["status"], "Ok");
        assert_eq!(body["fail_closed"], false);
        assert!(body["body"].is_object());
    }

    #[tokio::test]
    async fn mcp_envelope_initialize_returns_envelope_contract() {
        let app = router(app_state());
        let req = json!({
            "method": "initialize",
            "upstream": "gateway",
            "payload_json": json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}).to_string()
        });
        let res = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mcp")
                    .header("content-type", "application/json")
                    .body(Body::from(req.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_slice(&to_bytes(res.into_body(), usize::MAX).await.unwrap()).unwrap();
        assert_eq!(body["ok"], true);
        assert_eq!(body["fail_closed"], false);
        assert!(body.get("payload_json").is_some());
        let inner: serde_json::Value =
            serde_json::from_str(body["payload_json"].as_str().unwrap()).unwrap();
        assert_eq!(inner["jsonrpc"], "2.0");
        assert_eq!(inner["id"], 1);
        assert!(inner.get("result").is_some());
    }

    #[tokio::test]
    async fn mcp_accepts_raw_jsonrpc_over_http() {
        let app = router(app_state());
        let req = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {}
        });
        let res = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mcp")
                    .header("content-type", "application/json")
                    .body(Body::from(req.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_slice(&to_bytes(res.into_body(), usize::MAX).await.unwrap()).unwrap();
        assert_eq!(body["jsonrpc"], "2.0");
        assert_eq!(body["id"], 1);
        assert!(body.get("result").is_some());
        assert!(body.get("payload_json").is_none());
    }

    #[tokio::test]
    async fn mcp_raw_jsonrpc_policy_denial_maps_status_and_stays_raw() {
        let app = router(app_state());
        let req = json!({
            "jsonrpc":"2.0",
            "id": 7,
            "method":"tools/call",
            "params":{"name":"gateway.health","principal":"anonymous"}
        });
        let res = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mcp")
                    .header("content-type", "application/json")
                    .body(Body::from(req.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
        let body: serde_json::Value =
            serde_json::from_slice(&to_bytes(res.into_body(), usize::MAX).await.unwrap()).unwrap();
        assert_eq!(body["jsonrpc"], "2.0");
        assert_eq!(body["id"], 7);
        assert_eq!(body["error"]["code"], -32003);
        assert_eq!(body["fail_closed"], true);
        assert!(body.get("payload_json").is_none());
    }
}
