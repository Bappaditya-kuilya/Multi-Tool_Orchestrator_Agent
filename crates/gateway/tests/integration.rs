use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use gateway::{config, mcp, server, state::AppState};
use serde_json::json;
use store::InMemoryStore;
use tower::ServiceExt;

fn app_state() -> Arc<AppState> {
    let store = Arc::new(InMemoryStore::default()) as Arc<dyn store::Store>;
    let mut cfg = config::GatewayConfig::default().with_rules(vec![
        scopegate_core::policy::Rule::exact(
            "agent",
            "tool.invoke",
            "tool",
            scopegate_core::policy::PolicyDecision::Permit,
        ),
        scopegate_core::policy::Rule::exact(
            "anonymous",
            "tools/call",
            "gateway.health",
            scopegate_core::policy::PolicyDecision::Permit,
        ),
        scopegate_core::policy::Rule::exact(
            "anonymous",
            "tools/list",
            "tools/list",
            scopegate_core::policy::PolicyDecision::Permit,
        ),
    ]);
    cfg.mcp_default_upstream = None;
    let mut app = AppState::fail_closed().with_store(store);
    app.config = cfg;
    app.configure_mcp_runtime();
    Arc::new(app)
}

#[tokio::test]
async fn http_endpoints_and_mcp_end_to_end_with_store() {
    let state = app_state();
    let app = server::router(state.clone());

    // healthz
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/healthz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // readyz (store wired)
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/readyz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // metrics
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
    let body = to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let text = String::from_utf8(body.to_vec()).unwrap();
    assert!(text.contains("gateway_requests_total"));

    // upsert active store policy permitting MCP
    let policy_req = json!({
        "id":"p1","body":"{\"allow_all\":true,\"decision\":\"permit\"}","version":1,"active":true
    });
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/policies")
                .header("content-type", "application/json")
                .body(Body::from(policy_req.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // MCP initialize via HTTP endpoint (front/dispatch path + store audit integration)
    let mcp_init = json!({
        "method":"",
        "payload_json": json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}).to_string()
    });
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header("content-type", "application/json")
                .body(Body::from(mcp_init.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body: serde_json::Value =
        serde_json::from_slice(&to_bytes(res.into_body(), usize::MAX).await.unwrap()).unwrap();
    assert_eq!(body["ok"], true);
    assert!(body["payload_json"]
        .as_str()
        .unwrap()
        .contains("\"result\""));

    // MCP tools/call gateway.health (store-backed policy/audit path)
    let mcp_call = json!({
        "method":"",
        "payload_json": json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"gateway.health","principal":"anonymous"}}).to_string()
    });
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header("content-type", "application/json")
                .body(Body::from(mcp_call.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // audit query reflects MCP/store-backed appends
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/audit")
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body: serde_json::Value =
        serde_json::from_slice(&to_bytes(res.into_body(), usize::MAX).await.unwrap()).unwrap();
    assert!(body["body"]["events"]
        .as_array()
        .map(|a| !a.is_empty())
        .unwrap_or(false));

    // tasks lifecycle API still wired
    let task = json!({
        "task_id":"t-int","principal":"agent","action":"tool.invoke","resource":"tool",
        "token":{"revocation_id":"r1","scopes":["tool.invoke"],"max_calls":1,"expires_at":1000000000},
        "now":1
    });
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/tasks")
                .header("content-type", "application/json")
                .body(Body::from(task.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // approvals store-backed flow
    let create = json!({"id":"a-int","action":"create","principal":"u","tool":"tools/call","resource":"r","now":1});
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/approvals")
                .header("content-type", "application/json")
                .body(Body::from(create.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let resolve = json!({"id":"a-int","action":"approve","now":2});
    let res = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/approvals")
                .header("content-type", "application/json")
                .body(Body::from(resolve.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
async fn mcp_fails_closed_when_denied() {
    let store = Arc::new(InMemoryStore::default()) as Arc<dyn store::Store>;
    let app_state = {
        let mut app = AppState::fail_closed().with_store(store);
        app.config = config::GatewayConfig::default(); // no permit rules, no active policy
        Arc::new(app)
    };
    let req = mcp::McpRequest {
        method: String::new(),
        payload_json: json!({"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"gateway.health","principal":"anonymous"}}).to_string(),
        upstream: None,
    };
    let resp = mcp::handle_mcp_request_async(&app_state, req).await;
    assert!(resp.fail_closed);
    assert!(!resp.ok);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mcp_concurrent_requests_are_isolated_through_router() {
    let state = app_state();
    {
        let st = state.clone();
        let store = st.store.as_ref().unwrap();
        for (tid, aid) in [("task-a", "ap-a"), ("task-b", "ap-b")] {
            store
                .upsert_task(store::TaskRecord {
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
                .create_approval(store::ApprovalRecord {
                    id: aid.into(),
                    task_id: tid.into(),
                    tool: "gateway.health".into(),
                    args_hash: "h".into(),
                    status: store::ApprovalStatus::Approved,
                    created_at: "now".into(),
                    ..Default::default()
                })
                .await
                .unwrap();
        }
    }

    let app = server::router(state.clone());

    let mk = |id: i64, task_id: &str, approval_id: &str| {
        let payload = json!({
            "jsonrpc":"2.0","id":id,"method":"tools/call",
            "params":{"name":"gateway.health","task_id":task_id,"approval_id":approval_id,"principal":"anonymous"}
        });
        Request::builder()
            .method("POST")
            .uri("/mcp")
            .header("content-type", "application/json")
            .body(Body::from(payload.to_string()))
            .unwrap()
    };

    let mut set = tokio::task::JoinSet::new();
    for i in 0..20i64 {
        let app = app.clone();
        let (id, tid, aid, other_tid) = if i % 2 == 0 {
            (1000 + i, "task-a", "ap-a", "task-b")
        } else {
            (1000 + i, "task-b", "ap-b", "task-a")
        };
        set.spawn(async move {
            let res = app.oneshot(mk(id, tid, aid)).await.unwrap();
            let status = res.status();
            let body: serde_json::Value =
                serde_json::from_slice(&to_bytes(res.into_body(), usize::MAX).await.unwrap())
                    .unwrap();
            (id, tid.to_string(), other_tid.to_string(), status, body)
        });
    }

    while let Some(res) = set.join_next().await {
        let (id, tid, other_tid, status, body) = res.unwrap();
        assert_eq!(status, StatusCode::OK, "id={id} tid={tid} body={body}");
        // Router returns raw JSON-RPC for raw JSON-RPC requests.
        assert_eq!(body["id"], id, "jsonrpc id must be request-local: {body}");
        assert_eq!(
            body["result"]["structuredContent"]["ok"], true,
            "id={id} body={body}"
        );
        let payload_str = body.to_string();
        assert!(
            !payload_str.contains(&format!("\"{}\"", other_tid)),
            "cross-task leakage for id={id} tid={tid}: {payload_str}"
        );
    }
}
