//! Axum HTTP server wiring for gateway runtime.

use std::{convert::Infallible, net::SocketAddr, sync::Arc, time::Duration};

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{
    sse::{Event, KeepAlive, Sse},
    IntoResponse,
};
use axum::routing::{get, post};
use axum::{Json, Router};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio_stream::{wrappers::BroadcastStream, StreamExt};

use crate::api::{self, routes, ApiResponse, HttpStatus};
use crate::mcp;
use crate::state::AppState;

pub type SharedState = Arc<Mutex<AppState>>;

pub fn router(state: SharedState) -> Router {
    Router::new()
        .route(routes::HEALTHZ, get(healthz))
        .route(routes::READYZ, get(readyz))
        .route(routes::METRICS, get(metrics))
        .route(routes::V1_TASKS, post(v1_tasks).get(v1_tasks_list))
        .route(routes::V1_AUDIT, get(v1_audit).post(v1_audit))
        .route(routes::V1_APPROVALS, post(v1_approvals))
        .route(routes::V1_POLICIES, get(v1_policies).post(v1_policies))
        .route(routes::V1_STREAM, get(v1_stream))
        .route(mcp::McpEndpoint::PATH, post(mcp_handler).get(mcp_handler))
        .with_state(state)
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

fn json_response<T: serde::Serialize>(resp: ApiResponse<T>) -> impl IntoResponse {
    (status_code(resp.status), Json(resp))
}

async fn healthz(State(state): State<SharedState>) -> impl IntoResponse {
    let st = state.lock().await;
    json_response(api::handle_healthz(&st.config))
}

async fn readyz(State(state): State<SharedState>) -> impl IntoResponse {
    // compute readiness without holding mutable lifecycle lock longer than needed
    let resp = {
        let st = state.lock().await;
        // need async health check; clone store/config flags snapshot
        let ready_store = st.has_store() && st.store_healthy().await;
        if ready_store && st.has_broker() {
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
        }
    };
    json_response(resp)
}

async fn metrics(State(state): State<SharedState>) -> impl IntoResponse {
    let st = state.lock().await;
    let resp = api::handle_metrics(&st);
    let body = resp.body.map(|b| b.body).unwrap_or_default();
    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4")],
        body,
    )
}

async fn v1_tasks(
    State(state): State<SharedState>,
    Json(req): Json<api::TaskCreateRequest>,
) -> impl IntoResponse {
    let mut st = state.lock().await;
    let resp = api::handle_v1_tasks(&mut st, req).await;
    json_response(resp)
}

async fn v1_tasks_list(State(state): State<SharedState>) -> impl IntoResponse {
    let st = state.lock().await;
    let resp = api::handle_v1_tasks_list(&st).await;
    json_response(resp)
}

async fn v1_audit(
    State(state): State<SharedState>,
    payload: Option<Json<api::AuditQueryRequest>>,
) -> impl IntoResponse {
    let st = state.lock().await;
    let req = payload.map(|Json(r)| r).unwrap_or_default();
    let resp = api::handle_v1_audit(&st, req).await;
    json_response(resp)
}

async fn v1_approvals(
    State(state): State<SharedState>,
    Json(req): Json<api::ApprovalDecisionRequest>,
) -> impl IntoResponse {
    let mut st = state.lock().await;
    let resp = api::handle_v1_approvals(&mut st, req).await;
    json_response(resp)
}

async fn v1_policies(
    State(state): State<SharedState>,
    payload: Option<Json<api::PolicyUpsertRequest>>,
) -> impl IntoResponse {
    let st = state.lock().await;
    let req = payload.map(|Json(r)| r);
    let resp = api::handle_v1_policies(&st, req).await;
    json_response(resp)
}

async fn v1_stream(State(state): State<SharedState>) -> impl IntoResponse {
    let rx = {
        let st = state.lock().await;
        st.events_tx.subscribe()
    };
    let stream = BroadcastStream::new(rx).filter_map(|msg| match msg {
        Ok(data) => Some(Ok::<Event, Infallible>(
            Event::default().event("gateway").data(data),
        )),
        Err(_) => None, // lagged/missed; keep stream alive fail-open for stream transport only
    });
    Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("keepalive"),
    )
}

async fn mcp_handler(
    State(state): State<SharedState>,
    payload: Option<Json<mcp::McpRequest>>,
) -> impl IntoResponse {
    let req = payload.map(|Json(r)| r).unwrap_or_default();
    let resp = {
        let mut st = state.lock().await;
        mcp::handle_mcp_request_async(&mut st, req).await
    };
    let status = if resp.fail_closed {
        StatusCode::SERVICE_UNAVAILABLE
    } else {
        StatusCode::OK
    };
    (status, Json(resp))
}
