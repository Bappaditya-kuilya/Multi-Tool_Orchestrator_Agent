//! Request/runtime state integrating core, broker, store, and event hooks.

use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

use broker::ApprovalQueue;
use mcp_pool::{CallRequest, McpPool, PlaceholderSession, SessionDispatcher, UpstreamId};
use scopegate_core::rate_limit::InMemoryRateLimitTracker;
use serde::Serialize;
use store::Store;
use tokio::sync::broadcast;

use crate::config::GatewayConfig;
use crate::lifecycle::{handle_request_with_hooks, GatewayOutcome, InboundRequest};

#[derive(Debug, Default)]
pub struct Metrics {
    pub requests_total: AtomicU64,
    pub requests_denied: AtomicU64,
    pub requests_allowed: AtomicU64,
    pub audit_appends: AtomicU64,
    pub audit_append_failures: AtomicU64,
}

impl Metrics {
    pub fn snapshot_prometheus(&self) -> String {
        let total = self.requests_total.load(Ordering::Relaxed);
        let denied = self.requests_denied.load(Ordering::Relaxed);
        let allowed = self.requests_allowed.load(Ordering::Relaxed);
        let app = self.audit_appends.load(Ordering::Relaxed);
        let app_fail = self.audit_append_failures.load(Ordering::Relaxed);
        format!(
            "# HELP gateway_requests_total Total handled requests\n# TYPE gateway_requests_total counter\ngateway_requests_total {total}\n# HELP gateway_requests_denied_total Denied requests\n# TYPE gateway_requests_denied_total counter\ngateway_requests_denied_total {denied}\n# HELP gateway_requests_allowed_total Allowed requests\n# TYPE gateway_requests_allowed_total counter\ngateway_requests_allowed_total {allowed}\n# HELP gateway_audit_appends_total Audit append attempts persisted\n# TYPE gateway_audit_appends_total counter\ngateway_audit_appends_total {app}\n# HELP gateway_audit_append_failures_total Audit append failures\n# TYPE gateway_audit_append_failures_total counter\ngateway_audit_append_failures_total {app_fail}\n"
        )
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct StreamEvent {
    pub kind: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub task_id: Option<String>,
}

/// MCP pool runtime wiring (front→pool→upstream dispatch abstractions).
pub struct McpRuntime {
    pub pool: McpPool,
    pub dispatcher: SessionDispatcher<PlaceholderSession>,
    pub default_upstream: Option<UpstreamId>,
}

/// Gateway application state.
/// Store is abstracted behind `store::Store` trait; handlers fail closed when unavailable.
pub struct AppState {
    pub config: GatewayConfig,
    pub approvals: ApprovalQueue,
    pub rate_tracker: Option<InMemoryRateLimitTracker>,
    pub store: Option<Arc<dyn Store>>,
    pub metrics: Arc<Metrics>,
    pub events_tx: broadcast::Sender<String>,
    pub mcp: Option<McpRuntime>,
}

impl Default for AppState {
    fn default() -> Self {
        Self::fail_closed()
    }
}

impl AppState {
    /// Construct fail-closed state with default config and no external dependencies.
    pub fn fail_closed() -> Self {
        let (events_tx, _) = broadcast::channel(128);
        Self {
            config: GatewayConfig::default(),
            approvals: ApprovalQueue::new(),
            rate_tracker: None,
            store: None,
            metrics: Arc::new(Metrics::default()),
            events_tx,
            mcp: None,
        }
    }

    pub fn with_store(mut self, store: Arc<dyn Store>) -> Self {
        self.store = Some(store);
        self
    }

    pub fn has_store(&self) -> bool {
        self.store.is_some()
    }
    pub fn has_broker(&self) -> bool {
        true
    }

    pub fn emit_event(&self, event: StreamEvent) {
        if let Ok(json) = serde_json::to_string(&event) {
            let _ = self.events_tx.send(json);
        }
    }

    pub async fn store_healthy(&self) -> bool {
        match &self.store {
            Some(s) => s.health_check().await.is_ok(),
            None => false,
        }
    }

    /// Configure MCP pool runtime from config. Fail-closed: invalid/missing upstream config leaves mcp disabled.
    pub fn configure_mcp_runtime(&mut self) {
        if self.config.mcp_upstreams.is_empty() {
            self.mcp = None;
            return;
        }
        let mut pool = McpPool::default();
        let mut default_upstream: Option<UpstreamId> = self
            .config
            .mcp_default_upstream
            .as_ref()
            .map(|s| UpstreamId(s.clone()));
        for up in &self.config.mcp_upstreams {
            pool.register_with_server_config(up.server.clone(), up.pool);
            let _ = pool.connect(&up.server.id);
            if default_upstream.is_none() {
                default_upstream = Some(up.server.id.clone());
            }
        }
        let selected = match default_upstream.clone() {
            Some(id) => id,
            None => {
                self.mcp = None;
                return;
            }
        };
        // Session dispatcher abstraction for upstream forwarding path.
        let dispatcher = SessionDispatcher::new(PlaceholderSession::ready(selected.clone()));
        self.mcp = Some(McpRuntime {
            pool,
            dispatcher,
            default_upstream: Some(selected),
        });
    }

    /// Dispatch an MCP call through pool→upstream abstraction. Fail-closed on any error.
    pub fn dispatch_mcp_via_pool(
        &mut self,
        method: &str,
        payload: String,
        upstream: Option<&str>,
    ) -> Result<String, String> {
        let Some(rt) = self.mcp.as_mut() else {
            // If no upstream configured, allow local placeholder dispatch behavior via pool-less path caller.
            return Err("mcp_pool_unavailable".into());
        };
        let upstream_id = upstream
            .map(|s| UpstreamId(s.to_string()))
            .or_else(|| rt.default_upstream.clone())
            .ok_or_else(|| "mcp_upstream_unselected".to_string())?;
        let req = CallRequest {
            method: method.to_string(),
            payload,
        };
        match rt.pool.dispatch(&upstream_id, &req, &mut rt.dispatcher) {
            Ok(out) => Ok(out.response.payload),
            Err(e) => Err(format!("pool_dispatch_failed:{e}")),
        }
    }

    /// Execute request lifecycle using integrated abstractions.
    pub fn handle(&mut self, req: &InboundRequest) -> GatewayOutcome {
        let out = match self.rate_tracker.as_mut() {
            Some(tracker) => {
                handle_request_with_hooks(req, &self.config, &mut self.approvals, Some(tracker))
            }
            None => handle_request_with_hooks(req, &self.config, &mut self.approvals, None),
        };
        self.metrics.requests_total.fetch_add(1, Ordering::Relaxed);
        if out.allowed {
            self.metrics
                .requests_allowed
                .fetch_add(1, Ordering::Relaxed);
        } else {
            self.metrics.requests_denied.fetch_add(1, Ordering::Relaxed);
        }
        self.emit_event(StreamEvent {
            kind: if out.allowed {
                "task.allowed"
            } else {
                "task.denied"
            }
            .into(),
            message: format!("stage={:?}", out.stage),
            task_id: Some(req.task_id.clone()),
        });
        out
    }
}
