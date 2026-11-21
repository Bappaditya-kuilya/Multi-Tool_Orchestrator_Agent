//! Request/runtime state integrating core, broker, store, and event hooks.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc,
};

use broker::{ApprovalQueue, ApprovalRequest};
use mcp_pool::{
    CallRequest, Dispatcher, ForwardRequest, ForwardResponse, McpClientSession, McpPool, PoolError,
    TransportKind, TransportSpec, UpstreamId,
};
use scopegate_core::audit::AuditEntry;
use scopegate_core::rate_limit::InMemoryRateLimitTracker;
use serde::Serialize;
use serde_json::Value;
use store::{
    ApprovalQuery, ApprovalRecord, ApprovalStatus as StoreApprovalStatus, AuditEvent,
    RateLimitSnapshotRecord, RevocationQuery, Store,
};
use tokio::sync::broadcast;

use crate::config::GatewayConfig;
use crate::lifecycle::{
    audit_persistence_denied, handle_request_with_hooks_and_log, runtime_integration_denied,
    to_store_audit_event, GatewayOutcome, InboundRequest, Stage,
};

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

    pub fn record_audit_append_success(&self) {
        self.audit_appends.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_audit_append_failure(&self) {
        self.audit_append_failures.fetch_add(1, Ordering::Relaxed);
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct StreamEvent {
    pub kind: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub task_id: Option<String>,
}

/// Live MCP session handle used by gateway pool dispatch.
/// Stdio upstreams are backed by a spawned subprocess with line-delimited JSON-RPC.
/// Non-stdio transports fail closed until a concrete runtime/session is wired.
pub enum McpSession {
    Stdio(StdioLineSession),
}

impl McpClientSession for McpSession {
    fn is_ready(&self) -> bool {
        match self {
            McpSession::Stdio(s) => s.is_ready(),
        }
    }

    fn ping(&mut self) -> Result<(), PoolError> {
        match self {
            McpSession::Stdio(s) => s.ping(),
        }
    }

    fn forward(&mut self, request: &ForwardRequest) -> Result<ForwardResponse, PoolError> {
        match self {
            McpSession::Stdio(s) => s.forward(request),
        }
    }
}

/// Synchronous stdio JSON-RPC session (newline-delimited) for configured MCP upstreams.
/// Supports forwarding MCP envelopes such as initialize/tools/list/tools/call.
struct StdioInner {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    next_id: i64,
    ready: bool,
}

pub struct StdioLineSession {
    inner: std::sync::Mutex<StdioInner>,
}

impl std::fmt::Debug for StdioLineSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (pid, next_id, ready) = match self.inner.lock() {
            Ok(g) => (Some(g.child.id()), g.next_id, g.ready),
            Err(_) => (None, 0, false),
        };
        f.debug_struct("StdioLineSession")
            .field("pid", &pid)
            .field("next_id", &next_id)
            .field("ready", &ready)
            .finish()
    }
}

impl StdioLineSession {
    fn spawn(server: &mcp_pool::UpstreamServerConfig) -> Result<Self, PoolError> {
        let spec = match &server.transport_spec {
            TransportSpec::Stdio(s) => s,
            _ => {
                return Err(PoolError::Unavailable(
                    "stdio transport spec required".into(),
                ))
            }
        };
        let mut cmd = Command::new(&spec.program);
        cmd.args(&spec.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        if let Some(cwd) = &spec.cwd {
            cmd.current_dir(cwd);
        }
        for (k, v) in &spec.env {
            cmd.env(k, v);
        }
        let mut child = cmd
            .spawn()
            .map_err(|e| PoolError::Unavailable(format!("spawn failed: {e}")))?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| PoolError::Unavailable("missing stdin".into()))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| PoolError::Unavailable("missing stdout".into()))?;
        Ok(Self {
            inner: std::sync::Mutex::new(StdioInner {
                child,
                stdin,
                stdout: BufReader::new(stdout),
                next_id: 1,
                ready: true,
            }),
        })
    }

    fn send_value(&self, mut request: Value) -> Result<Value, PoolError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| PoolError::Unavailable("session lock poisoned".into()))?;
        if !inner.ready {
            return Err(PoolError::Unavailable("stdio session not ready".into()));
        }
        if let Ok(Some(_)) = inner.child.try_wait() {
            inner.ready = false;
            return Err(PoolError::Unavailable("stdio process exited".into()));
        }
        if request.get("id").is_none() {
            let id = inner.next_id;
            inner.next_id = inner.next_id.saturating_add(1);
            request["id"] = Value::from(id);
        }
        if request.get("jsonrpc").is_none() {
            request["jsonrpc"] = Value::from("2.0");
        }
        let expected_id = request.get("id").cloned();
        let mut line = serde_json::to_string(&request)
            .map_err(|e| PoolError::DispatchFailed(format!("encode: {e}")))?;
        line.push('\n');
        inner.stdin.write_all(line.as_bytes()).map_err(|e| {
            inner.ready = false;
            PoolError::DispatchFailed(format!("stdin write: {e}"))
        })?;
        inner.stdin.flush().map_err(|e| {
            inner.ready = false;
            PoolError::DispatchFailed(format!("stdin flush: {e}"))
        })?;
        loop {
            let mut out = String::new();
            let n = inner.stdout.read_line(&mut out).map_err(|e| {
                inner.ready = false;
                PoolError::DispatchFailed(format!("stdout read: {e}"))
            })?;
            if n == 0 {
                inner.ready = false;
                return Err(PoolError::Unavailable("stdio closed".into()));
            }
            let trimmed = out.trim_end();
            if trimmed.is_empty() {
                continue;
            }
            let msg: Value = match serde_json::from_str(trimmed) {
                Ok(v) => v,
                Err(e) => {
                    // Fail-closed: corrupted/desynced stdio stream is not reusable.
                    inner.ready = false;
                    let _ = inner.child.kill();
                    return Err(PoolError::DispatchFailed(format!("decode: {e}")));
                }
            };
            // Skip server->client notifications/requests while waiting for this response.
            if let Some(exp) = &expected_id {
                if msg.get("id") == Some(exp) {
                    return Ok(msg);
                }
                if msg.get("id").is_none() {
                    continue;
                }
                // Response to a different id (unexpected in single-flight stdio session): keep waiting.
                continue;
            }
            return Ok(msg);
        }
    }
}

impl McpClientSession for StdioLineSession {
    fn is_ready(&self) -> bool {
        let mut inner = match self.inner.lock() {
            Ok(g) => g,
            Err(_) => return false,
        };
        if inner.ready {
            if let Ok(Some(_)) = inner.child.try_wait() {
                inner.ready = false;
            }
        }
        inner.ready
    }

    fn ping(&mut self) -> Result<(), PoolError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| PoolError::Unavailable("session lock poisoned".into()))?;
        if let Ok(Some(_)) = inner.child.try_wait() {
            inner.ready = false;
        }
        if inner.ready {
            Ok(())
        } else {
            Err(PoolError::Unavailable("stdio session not ready".into()))
        }
    }

    fn forward(&mut self, request: &ForwardRequest) -> Result<ForwardResponse, PoolError> {
        let payload_val: Value = serde_json::from_str(&request.payload)
            .unwrap_or(Value::String(request.payload.clone()));
        let req = match payload_val {
            Value::Object(mut obj) => {
                let looks_like_envelope = obj.contains_key("jsonrpc")
                    || obj.contains_key("method")
                    || obj.contains_key("id");
                if looks_like_envelope {
                    if !obj.contains_key("jsonrpc") {
                        obj.insert("jsonrpc".into(), Value::String("2.0".into()));
                    }
                    if !obj.contains_key("method") {
                        obj.insert("method".into(), Value::String(request.method.clone()));
                    }
                    Value::Object(obj)
                } else {
                    serde_json::json!({
                        "jsonrpc":"2.0",
                        "method": request.method,
                        "params": Value::Object(obj),
                    })
                }
            }
            other => serde_json::json!({
                "jsonrpc":"2.0",
                "method": request.method,
                "params": other,
            }),
        };
        let resp = self.send_value(req)?;
        // Return raw JSON-RPC response payload for front/gateway extraction.
        Ok(ForwardResponse {
            payload: resp.to_string(),
        })
    }
}

impl Drop for StdioLineSession {
    fn drop(&mut self) {
        if let Ok(mut inner) = self.inner.lock() {
            let _ = inner.child.kill();
            let _ = inner.child.wait();
        }
    }
}

struct RuntimeSessionDispatcher<'a> {
    sessions: &'a mut HashMap<UpstreamId, McpSession>,
}

impl Dispatcher for RuntimeSessionDispatcher<'_> {
    fn call(
        &mut self,
        upstream: &UpstreamId,
        request: &CallRequest,
    ) -> Result<mcp_pool::CallResponse, PoolError> {
        let session = self.sessions.get_mut(upstream).ok_or_else(|| {
            PoolError::Unavailable(format!("no session for upstream {}", upstream.0))
        })?;
        if !session.is_ready() {
            return Err(PoolError::Unavailable(format!(
                "session not ready for upstream {}",
                upstream.0
            )));
        }
        session.forward(request)
    }
}

/// MCP pool runtime wiring (front→pool→upstream dispatch abstractions).
pub struct McpRuntime {
    pub pool: McpPool,
    pub sessions: HashMap<UpstreamId, McpSession>,
    pub default_upstream: Option<UpstreamId>,
}

/// Gateway application state.
/// Store is abstracted behind `store::Store` trait; handlers fail closed when unavailable.
/// Mutable subsystems use internal locks so MCP/API handlers can run concurrently without
/// holding a global state mutex across async dispatch.
pub struct AppState {
    pub config: GatewayConfig,
    /// Runtime-synced revocation IDs merged into lifecycle/config checks without requiring &mut config.
    pub(crate) synced_revocations: std::sync::Mutex<Vec<String>>,
    pub approvals: std::sync::Mutex<ApprovalQueue>,
    pub rate_tracker: std::sync::Mutex<Option<InMemoryRateLimitTracker>>,
    pub store: Option<Arc<dyn Store>>,
    pub metrics: Arc<Metrics>,
    pub events_tx: broadcast::Sender<String>,
    pub mcp: tokio::sync::Mutex<Option<McpRuntime>>,
    /// Tracks whether in-memory rate/budget counters changed since last durable snapshot persist.
    pub(crate) rate_limit_snapshot_dirty: AtomicBool,
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
            synced_revocations: std::sync::Mutex::new(Vec::new()),
            approvals: std::sync::Mutex::new(ApprovalQueue::new()),
            rate_tracker: std::sync::Mutex::new(None),
            store: None,
            metrics: Arc::new(Metrics::default()),
            events_tx,
            mcp: tokio::sync::Mutex::new(None),
            rate_limit_snapshot_dirty: AtomicBool::new(false),
        }
    }

    pub fn with_store(mut self, store: Arc<dyn Store>) -> Self {
        self.store = Some(store);
        self
    }

    pub fn with_rate_tracker(self, tracker: InMemoryRateLimitTracker) -> Self {
        // Builder on owned state; no concurrent access possible.
        *self.rate_tracker.lock().expect("fresh state lock") = Some(tracker);
        self
    }

    pub fn has_store(&self) -> bool {
        self.store.is_some()
    }
    pub fn has_broker(&self) -> bool {
        true
    }

    pub fn has_rate_tracker(&self) -> bool {
        self.rate_tracker
            .lock()
            .expect("rate tracker lock")
            .is_some()
    }

    pub async fn has_mcp_runtime(&self) -> bool {
        self.mcp.lock().await.is_some()
    }

    /// Helper for durable/store-backed integrations: whether audit persistence can be attempted.
    pub fn audit_persistence_configured(&self) -> bool {
        self.store.is_some() && self.config.runtime_hooks.persist_audit_events
    }

    /// Configure in-memory rate/budget tracker state from config hooks (fail-closed defaults).
    /// Preserves an existing tracker across repeated hook preparation to keep runtime rate/budget
    /// state continuity (S1 restart-safe/runtime lifecycle behavior) unless hooks are disabled.
    pub fn configure_rate_limit_state(&self) {
        let mut rt = self.rate_tracker.lock().expect("rate tracker lock");
        if !self.config.runtime_hooks.enable_rate_limit_state {
            *rt = None;
            self.rate_limit_snapshot_dirty
                .store(false, Ordering::Relaxed);
            return;
        }
        if rt.is_some() {
            return;
        }
        let limits = self.config.rate_limits.clone();
        let configured = limits.per_token_window.is_some()
            || limits.per_token_tool_window.is_some()
            || limits.per_token_call_limit.is_some()
            || limits.per_token_budget.is_some();
        if configured {
            *rt = Some(InMemoryRateLimitTracker::new(limits));
            self.rate_limit_snapshot_dirty
                .store(false, Ordering::Relaxed);
        }
    }

    /// Effective revocation ids merged from config and store (durable hook).
    /// Fails closed (returns error) if a configured store query fails.
    pub async fn effective_revoked_token_ids(&self) -> Result<Vec<String>, String> {
        let mut merged = self.config.revoked_token_ids.clone();
        if let Ok(synced) = self.synced_revocations.lock() {
            for id in synced.iter() {
                if !merged.iter().any(|x| x == id) {
                    merged.push(id.clone());
                }
            }
        }
        if self.store.is_some() && self.config.runtime_hooks.sync_revocations_from_store {
            let ids = self.load_revoked_token_ids_from_store().await?;
            for id in ids {
                if !merged.iter().any(|x| x == &id) {
                    merged.push(id);
                }
            }
        }
        Ok(merged)
    }

    async fn load_revoked_token_ids_from_store(&self) -> Result<Vec<String>, String> {
        let Some(store) = &self.store else {
            return Ok(Vec::new());
        };
        let recs = store
            .list_revocations(RevocationQuery::default())
            .await
            .map_err(|e| format!("store revocation query failed: {e}"))?;
        Ok(recs
            .into_iter()
            .map(|r| r.target_id)
            .filter(|s| !s.trim().is_empty())
            .collect())
    }

    /// Sync store-backed revocations into config for synchronous lifecycle checks.
    /// Fail-closed: returns error on store failure or when durable sync is required but unavailable.
    pub async fn sync_revocations_from_store(&self) -> Result<usize, String> {
        if !self.config.runtime_hooks.sync_revocations_from_store {
            return Ok(0);
        }
        if self.store.is_none() {
            return Err("revocation sync hook requires store (fail-closed)".into());
        }
        let ids = self.load_revoked_token_ids_from_store().await?;
        let mut added = 0usize;
        let mut synced = self
            .synced_revocations
            .lock()
            .expect("synced revocations lock");
        for id in ids {
            if !self.config.revoked_token_ids.iter().any(|x| x == &id)
                && !synced.iter().any(|x| x == &id)
            {
                synced.push(id);
                added += 1;
            }
        }
        Ok(added)
    }

    /// Persist in-memory lifecycle audit entries to durable store (append-before-return hook).
    /// Fail-closed: returns error on append/verification failure and records metrics.
    pub async fn persist_audit_log(&self, log: &[AuditEntry]) -> Result<Vec<AuditEvent>, String> {
        let Some(store) = &self.store else {
            return Err("audit persistence unavailable: no store configured".into());
        };
        let mut persisted = Vec::with_capacity(log.len());
        for entry in log {
            match store.append_audit_event(to_store_audit_event(entry)).await {
                Ok(ev) => {
                    self.metrics.record_audit_append_success();
                    persisted.push(ev);
                }
                Err(e) => {
                    self.metrics.record_audit_append_failure();
                    return Err(format!("audit append failed (fail-closed): {e}"));
                }
            }
        }
        // Extra integrity check hook for durable fail-closed behavior.
        match store.verify_audit_chain().await {
            Ok(report) if report.ok => {}
            Ok(report) => {
                self.metrics.record_audit_append_failure();
                return Err(format!(
                    "audit chain verification failed after persist: {}",
                    report
                        .message
                        .unwrap_or_else(|| "integrity violation".into())
                ));
            }
            Err(e) => {
                self.metrics.record_audit_append_failure();
                return Err(format!("audit chain verification unavailable: {e}"));
            }
        }
        Ok(persisted)
    }

    /// Approval integration hook: query store-backed approval records.
    pub async fn list_store_approvals(
        &self,
        query: ApprovalQuery,
    ) -> Result<Vec<ApprovalRecord>, String> {
        let Some(store) = &self.store else {
            return Err("approval store unavailable".into());
        };
        store
            .list_approvals(query)
            .await
            .map_err(|e| format!("approval query failed: {e}"))
    }

    /// Rehydrate pending approvals from durable store into in-memory approval queue.
    /// Restart-safe helper; idempotent for already-present approvals.
    /// Fail-closed when approval-store hook is enabled but store is unavailable.
    pub async fn rehydrate_pending_approvals_from_store(&self) -> Result<usize, String> {
        let Some(store) = &self.store else {
            if self.config.runtime_hooks.use_approval_store {
                return Err("approval store hook requires store (fail-closed)".into());
            }
            return Ok(0);
        };
        let pending = store
            .list_approvals(ApprovalQuery {
                status: Some(StoreApprovalStatus::Pending),
                ..Default::default()
            })
            .await
            .map_err(|e| format!("approval rehydration query failed (fail-closed): {e}"))?;
        let mut restored = 0usize;
        let mut approvals = self.approvals.lock().expect("approvals lock");
        for rec in pending {
            let req = ApprovalRequest {
                id: rec.id.clone(),
                principal: "rehydrated".to_string(),
                action: rec.tool.clone(),
                resource: rec.task_id.clone(),
                reason: None,
            };
            let args_hash = if rec.args_hash.is_empty() {
                None
            } else {
                Some(rec.args_hash.clone())
            };
            match approvals.create_with_binding(req, None, args_hash) {
                Ok(()) => restored += 1,
                Err(broker::BrokerError::DuplicateApproval(_)) => {}
                Err(e) => {
                    return Err(format!(
                        "approval rehydration failed for {} (fail-closed): {e:?}",
                        rec.id
                    ));
                }
            }
        }
        Ok(restored)
    }

    /// Load persisted rate/budget counters into the in-memory tracker.
    /// Fail-closed on store read/deserialize errors when persistence is enabled with a store.
    ///
    /// Config-drift semantics: restored counters are applied as-is; current configured limits are
    /// enforced on subsequent checks. If limits changed across restart, restored counts may be
    /// evaluated against the new limits (intentional, fail-closed toward enforcement).
    pub async fn load_rate_limit_snapshot_from_store(&self) -> Result<bool, String> {
        if !self.config.runtime_hooks.enable_rate_limit_state
            || !self.config.runtime_hooks.persist_rate_limit_state
        {
            return Ok(false);
        }
        let Some(store) = &self.store else {
            return Ok(false);
        };
        let rec = store
            .load_rate_limit_snapshot()
            .await
            .map_err(|e| format!("rate limit snapshot load failed (fail-closed): {e}"))?;
        let Some(rec) = rec else {
            return Ok(false);
        };
        let snapshot: scopegate_core::rate_limit::RateLimitTrackerSnapshot =
            serde_json::from_str(&rec.snapshot_json).map_err(|e| {
                format!("rate limit snapshot deserialize failed (fail-closed): {e}")
            })?;
        self.configure_rate_limit_state();
        let mut rt = self.rate_tracker.lock().expect("rate tracker lock");
        let Some(tracker) = rt.as_mut() else {
            return Ok(false);
        };
        tracker.restore_snapshot(snapshot);
        self.rate_limit_snapshot_dirty
            .store(false, Ordering::Relaxed);
        Ok(true)
    }

    /// Persist current rate/budget counters for restart-safe recovery.
    /// Fail-closed on serialize/store errors when persistence is enabled with a store.
    /// shortcut: writes a full global snapshot (no batching/checkpoint); callers that need lower
    /// overhead should batch at a higher layer while preserving fail-closed semantics.
    pub async fn persist_rate_limit_snapshot_to_store(&self) -> Result<bool, String> {
        if !self.config.runtime_hooks.enable_rate_limit_state
            || !self.config.runtime_hooks.persist_rate_limit_state
        {
            self.rate_limit_snapshot_dirty
                .store(false, Ordering::Relaxed);
            return Ok(false);
        }
        let Some(store) = self.store.clone() else {
            return Ok(false);
        };
        let snapshot_json = {
            let rt = self.rate_tracker.lock().expect("rate tracker lock");
            let Some(tracker) = rt.as_ref() else {
                return Ok(false);
            };
            serde_json::to_string(&tracker.snapshot())
                .map_err(|e| format!("rate limit snapshot serialize failed (fail-closed): {e}"))?
        };
        let updated_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis().to_string())
            .unwrap_or_else(|_| "0".to_string());
        let rec = RateLimitSnapshotRecord {
            snapshot_json,
            updated_at,
        };
        store
            .save_rate_limit_snapshot(rec)
            .await
            .map_err(|e| format!("rate limit snapshot save failed (fail-closed): {e}"))?;
        self.rate_limit_snapshot_dirty
            .store(false, Ordering::Relaxed);
        Ok(true)
    }

    /// Persist rate/budget snapshot only when in-memory counters changed since last persist.
    /// This is the explicit async helper for sync handle paths that cannot await persistence.
    pub async fn persist_rate_limit_snapshot_if_dirty(&self) -> Result<bool, String> {
        if !self.rate_limit_snapshot_dirty.load(Ordering::Relaxed) {
            return Ok(false);
        }
        self.persist_rate_limit_snapshot_to_store().await
    }

    /// Apply configured durable hooks before handling (sync-revocations/rate-limit/approval state).
    /// Fail-closed on store sync/rehydration errors when hooks require durable state.
    pub async fn prepare_runtime_hooks(&self) -> Result<(), String> {
        self.configure_rate_limit_state();
        if self.config.runtime_hooks.sync_revocations_from_store && self.store.is_none() {
            return Err("revocation sync hook requires store (fail-closed)".into());
        }
        self.sync_revocations_from_store().await.map(|_| ())?;
        self.load_rate_limit_snapshot_from_store().await?;
        if self.config.runtime_hooks.use_approval_store {
            if self.store.is_none() {
                return Err("approval store hook requires store (fail-closed)".into());
            }
            self.rehydrate_pending_approvals_from_store().await?;
        }
        Ok(())
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

    fn connect_mcp_upstream(
        pool: &mut McpPool,
        sessions: &mut HashMap<UpstreamId, McpSession>,
        upstream: &UpstreamId,
    ) -> Result<(), PoolError> {
        let server = pool
            .server_config(upstream)
            .cloned()
            .ok_or_else(|| PoolError::UnknownUpstream(upstream.0.clone()))?;
        if let Some(existing) = sessions.get(upstream) {
            if existing.is_ready()
                && matches!(
                    pool.state(upstream),
                    Some(mcp_pool::ConnectionState::Connected)
                )
            {
                return Ok(());
            }
        }
        // Drop/replace any stale session before reconnect.
        sessions.remove(upstream);
        let _ = pool.set_state(upstream, mcp_pool::ConnectionState::Connecting);
        match server.transport {
            TransportKind::Stdio => match StdioLineSession::spawn(&server) {
                Ok(sess) => {
                    sessions.insert(upstream.clone(), McpSession::Stdio(sess));
                    if let Err(e) = pool.set_state(upstream, mcp_pool::ConnectionState::Connected) {
                        sessions.remove(upstream);
                        let _ = pool.set_state(upstream, mcp_pool::ConnectionState::Unhealthy);
                        return Err(e);
                    }
                    Ok(())
                }
                Err(e) => {
                    let _ = pool.set_state(upstream, mcp_pool::ConnectionState::Unhealthy);
                    Err(e)
                }
            },
            _ => {
                let _ = pool.set_state(upstream, mcp_pool::ConnectionState::Unhealthy);
                Err(PoolError::Unavailable(format!(
                    "unsupported transport for live dispatch: {:?}",
                    server.transport
                )))
            }
        }
    }

    /// Configure MCP pool runtime from config. Fail-closed: invalid/missing upstream config leaves mcp disabled.
    pub fn configure_mcp_runtime(&self) {
        if self.config.mcp_upstreams.is_empty() {
            *self.mcp.try_lock().expect("startup mcp lock") = None;
            return;
        }
        let mut pool = McpPool::default();
        let mut sessions = HashMap::new();
        let mut default_upstream: Option<UpstreamId> = self
            .config
            .mcp_default_upstream
            .as_ref()
            .map(|s| UpstreamId(s.clone()));
        for up in &self.config.mcp_upstreams {
            pool.register_with_server_config(up.server.clone(), up.pool);
            if Self::connect_mcp_upstream(&mut pool, &mut sessions, &up.server.id).is_err() {
                // Keep upstream registered but unavailable (fail-closed per dispatch).
                let _ = pool.set_state(&up.server.id, mcp_pool::ConnectionState::Unhealthy);
            }
            if default_upstream.is_none() {
                default_upstream = Some(up.server.id.clone());
            }
        }
        let selected = match default_upstream.clone() {
            Some(id) if pool.server_config(&id).is_some() => id,
            _ => {
                *self.mcp.try_lock().expect("startup mcp lock") = None;
                return;
            }
        };
        // Keep runtime available for registered upstreams (dispatch remains fail-closed if unavailable).
        *self.mcp.try_lock().expect("startup mcp lock") = Some(McpRuntime {
            pool,
            sessions,
            default_upstream: Some(selected),
        });
    }

    /// Dispatch an MCP call through pool→upstream abstraction with live stdio session forwarding.
    /// Fail-closed on unavailable/connect/dispatch errors; preserves pool health/metrics hooks.
    /// Uses internal MCP runtime lock so concurrent MCP requests do not serialize on global AppState.
    pub async fn dispatch_mcp_via_pool(
        &self,
        method: &str,
        payload: String,
        upstream: Option<&str>,
    ) -> Result<String, String> {
        let mut mcp = self.mcp.lock().await;
        let Some(rt) = mcp.as_mut() else {
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

        // Ensure a live session exists for stdio upstreams before pool dispatch/acquire.
        let session_ready = rt
            .sessions
            .get(&upstream_id)
            .map(|s| s.is_ready())
            .unwrap_or(false);
        if !session_ready
            || !matches!(
                rt.pool.state(&upstream_id),
                Some(mcp_pool::ConnectionState::Connected)
            )
        {
            if let Err(e) = Self::connect_mcp_upstream(&mut rt.pool, &mut rt.sessions, &upstream_id)
            {
                return Err(format!("pool_dispatch_failed:{e}"));
            }
        }

        let mut dispatcher = RuntimeSessionDispatcher {
            sessions: &mut rt.sessions,
        };
        match rt.pool.dispatch(&upstream_id, &req, &mut dispatcher) {
            Ok(out) => Ok(out.response.payload),
            Err(e) => {
                // Fail-closed: any dispatch failure may leave runtime/session state suspect.
                // Drop session and mark unhealthy so next call reconnects cleanly.
                rt.sessions.remove(&upstream_id);
                let _ = rt
                    .pool
                    .set_state(&upstream_id, mcp_pool::ConnectionState::Unhealthy);
                Err(format!("pool_dispatch_failed:{e}"))
            }
        }
    }

    /// Execute request lifecycle using integrated abstractions.
    ///
    /// Note: sync path; rate/budget counter mutations are not durably persisted here.
    /// Use `handle_and_persist_audit` or `persist_rate_limit_snapshot_if_dirty` for restart safety.
    pub fn handle(&self, req: &InboundRequest) -> GatewayOutcome {
        let (out, _audit_log) = self.handle_with_audit_log(req);
        out
    }

    fn effective_config_for_lifecycle(&self) -> GatewayConfig {
        let mut cfg = self.config.clone();
        if let Ok(synced) = self.synced_revocations.lock() {
            for id in synced.iter() {
                if !cfg.revoked_token_ids.iter().any(|x| x == id) {
                    cfg.revoked_token_ids.push(id.clone());
                }
            }
        }
        cfg
    }

    /// Execute request lifecycle and return the in-memory audit log for durable/store-backed hooks.
    /// Preserves existing lifecycle behavior and fail-closed semantics.
    pub fn handle_with_audit_log(&self, req: &InboundRequest) -> (GatewayOutcome, Vec<AuditEntry>) {
        let cfg = self.effective_config_for_lifecycle();
        let (out, audit_log) = {
            let mut approvals = self.approvals.lock().expect("approvals lock");
            let mut rate_tracker = self.rate_tracker.lock().expect("rate tracker lock");
            let rate_mut_before = rate_tracker.as_ref().map(|t| t.mutation_count());
            let (out, audit_log) = match rate_tracker.as_mut() {
                Some(tracker) => {
                    handle_request_with_hooks_and_log(req, &cfg, &mut approvals, Some(tracker))
                }
                None => handle_request_with_hooks_and_log(req, &cfg, &mut approvals, None),
            };
            if let Some(before) = rate_mut_before {
                if rate_tracker
                    .as_ref()
                    .is_some_and(|t| t.mutation_count() != before)
                {
                    self.rate_limit_snapshot_dirty
                        .store(true, Ordering::Relaxed);
                }
            }
            (out, audit_log)
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
        (out, audit_log)
    }

    /// Execute lifecycle and enforce durable audit append-before-return when configured.
    /// Fail-closed: persistence errors or missing durable audit store deny the outcome.
    pub async fn handle_and_persist_audit(
        &self,
        req: &InboundRequest,
    ) -> (GatewayOutcome, Vec<AuditEntry>) {
        let persist_required = self.config.runtime_hooks.persist_audit_events;
        let (out, audit_log) = self.handle_with_audit_log(req);
        if persist_required {
            if self.store.is_none() {
                if out.allowed {
                    self.metrics
                        .requests_allowed
                        .fetch_sub(1, Ordering::Relaxed);
                    self.metrics.requests_denied.fetch_add(1, Ordering::Relaxed);
                }
                self.emit_event(StreamEvent {
                    kind: "audit.persist_denied".into(),
                    message: "audit persistence required but store unavailable".into(),
                    task_id: Some(req.task_id.clone()),
                });
                return (
                    audit_persistence_denied(
                        &audit_log,
                        "audit persistence required but store unavailable",
                    ),
                    audit_log,
                );
            }
            if let Err(e) = self.persist_audit_log(&audit_log).await {
                if out.allowed {
                    self.metrics
                        .requests_allowed
                        .fetch_sub(1, Ordering::Relaxed);
                    self.metrics.requests_denied.fetch_add(1, Ordering::Relaxed);
                }
                self.emit_event(StreamEvent {
                    kind: "audit.persist_denied".into(),
                    message: format!("audit persistence failed: {e}"),
                    task_id: Some(req.task_id.clone()),
                });
                return (audit_persistence_denied(&audit_log, e), audit_log);
            }
        }
        if self.rate_limit_snapshot_dirty.load(Ordering::Relaxed) {
            if let Err(e) = self.persist_rate_limit_snapshot_if_dirty().await {
                if out.allowed {
                    self.metrics
                        .requests_allowed
                        .fetch_sub(1, Ordering::Relaxed);
                    self.metrics.requests_denied.fetch_add(1, Ordering::Relaxed);
                }
                self.emit_event(StreamEvent {
                    kind: "rate_limit.persist_denied".into(),
                    message: format!("rate limit snapshot persist failed: {e}"),
                    task_id: Some(req.task_id.clone()),
                });
                return (
                    runtime_integration_denied(
                        &audit_log,
                        Stage::BudgetRateLimit,
                        format!("rate limit snapshot persistence failed (fail-closed): {e}"),
                    ),
                    audit_log,
                );
            }
        }
        (out, audit_log)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::StoreSelection;
    use crate::lifecycle::{RequestHints, Stage};
    use broker::ApprovalStatus;
    use scopegate_core::policy::{PolicyDecision, Rule};
    use scopegate_core::rate_limit::InMemoryRateLimitTracker;
    use scopegate_core::taint::OperationTarget;
    use scopegate_core::token::{Budget, Expiry, RevocationId, Scope, TaskToken};
    use std::sync::Arc;
    use store::{InMemoryStore, RevocationRecord, StoreConfig};

    fn base_req() -> InboundRequest {
        InboundRequest {
            task_id: "task-state-1".into(),
            principal: "agent".into(),
            action: "tool.invoke".into(),
            resource: "tool".into(),
            token: TaskToken {
                revocation_id: RevocationId("rev-state-1".into()),
                scopes: vec![Scope("tool.invoke".into())],
                budget: Budget { max_calls: Some(1) },
                expires_at: Some(Expiry(100)),
                attenuation: None,
            },
            operation: OperationTarget::other("local"),
            taint_labels: vec![],
            secret: None,
            now: 1,
            approval_deadline: Some(10),
            approval_resolution: Some(ApprovalStatus::Approved),
            hints: RequestHints::default(),
        }
    }

    #[test]
    fn handle_with_audit_log_returns_chain_for_store_hooks() {
        let mut state = AppState::fail_closed();
        state.config = state.config.clone().with_rules(vec![Rule::exact(
            "agent",
            "tool.invoke",
            "tool",
            PolicyDecision::Permit,
        )]);
        let req = base_req();
        let (out, log) = state.handle_with_audit_log(&req);
        assert!(out.allowed);
        assert!(!log.is_empty());
        assert!(scopegate_core::audit::verify_chain(&log));
        assert_eq!(state.metrics.requests_total.load(Ordering::Relaxed), 1);
        assert_eq!(state.metrics.requests_allowed.load(Ordering::Relaxed), 1);
        assert_eq!(state.metrics.requests_denied.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn handle_preserves_fail_closed_denials_and_metrics() {
        let state = AppState::fail_closed();
        let req = base_req(); // no permit rules => policy deny/fail-closed
        let out = state.handle(&req);
        assert!(!out.allowed);
        assert_eq!(out.stage, Stage::Denied);
        assert_eq!(state.metrics.requests_total.load(Ordering::Relaxed), 1);
        assert_eq!(state.metrics.requests_denied.load(Ordering::Relaxed), 1);
        assert_eq!(state.metrics.requests_allowed.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn state_helpers_reflect_store_and_rate_tracker_configuration() {
        let mut state = AppState::fail_closed();
        assert!(!state.audit_persistence_configured());
        assert!(!state.has_rate_tracker());
        state.config.runtime_hooks.persist_audit_events = true;
        let store = Arc::new(InMemoryStore::new(StoreConfig {
            backend: store::BackendKind::InMemory,
            database_url: "memory://".into(),
            fail_closed_on_audit_error: true,
        })) as Arc<dyn Store>;
        state = state.with_store(store);
        assert!(state.audit_persistence_configured());
        state = state.with_rate_tracker(InMemoryRateLimitTracker::new(
            scopegate_core::rate_limit::Limits::default(),
        ));
        assert!(state.has_rate_tracker());
        state.metrics.record_audit_append_success();
        state.metrics.record_audit_append_failure();
        assert_eq!(state.metrics.audit_appends.load(Ordering::Relaxed), 1);
        assert_eq!(
            state.metrics.audit_append_failures.load(Ordering::Relaxed),
            1
        );
    }

    #[test]
    fn configure_rate_limit_state_from_config_hooks() {
        let mut state = AppState::fail_closed();
        state.config.runtime_hooks.enable_rate_limit_state = true;
        state.config.rate_limits.per_token_call_limit = Some(2);
        state.configure_rate_limit_state();
        assert!(state.has_rate_tracker());
        state.config.runtime_hooks.enable_rate_limit_state = false;
        state.configure_rate_limit_state();
        assert!(!state.has_rate_tracker());
    }

    #[tokio::test]
    async fn syncs_revocations_from_store_and_persists_audit_fail_closed() {
        let store = Arc::new(InMemoryStore::default()) as Arc<dyn Store>;
        store
            .record_revocation(RevocationRecord {
                id: "r1".into(),
                target_kind: "token".into(),
                target_id: "rev-state-1".into(),
                reason: Some("test".into()),
                revoked_at: "1".into(),
                revoked_by: None,
            })
            .await
            .unwrap();

        let mut state = AppState::fail_closed().with_store(store);
        state.config.store_selection = StoreSelection::SqliteWal; // durable hook context
        state.config.runtime_hooks.sync_revocations_from_store = true;
        state.config.runtime_hooks.persist_audit_events = true;
        let added = state.sync_revocations_from_store().await.unwrap();
        assert_eq!(added, 1);
        assert!(state
            .effective_revoked_token_ids()
            .await
            .unwrap()
            .iter()
            .any(|s| s == "rev-state-1"));

        let req = base_req();
        state.config = state.config.clone().with_rules(vec![Rule::exact(
            "agent",
            "tool.invoke",
            "tool",
            PolicyDecision::Permit,
        )]);
        let (out, log) = state.handle_with_audit_log(&req);
        assert!(!out.allowed); // revoked by synced id
        let persisted = state.persist_audit_log(&log).await.unwrap();
        assert_eq!(persisted.len(), log.len());
        assert!(state.metrics.audit_appends.load(Ordering::Relaxed) as usize >= log.len());
    }

    #[tokio::test]
    async fn persist_audit_fails_closed_without_store() {
        let state = AppState::fail_closed();
        let err = state.persist_audit_log(&[]).await.unwrap_err();
        assert!(err.contains("no store configured"));
    }

    #[tokio::test]
    async fn handle_and_persist_audit_enforces_append_before_return_when_configured() {
        let store = Arc::new(InMemoryStore::default()) as Arc<dyn Store>;
        let mut state = AppState::fail_closed().with_store(store);
        state.config = state.config.clone().with_rules(vec![Rule::exact(
            "agent",
            "tool.invoke",
            "tool",
            PolicyDecision::Permit,
        )]);
        state.config.runtime_hooks.persist_audit_events = true;

        let req = base_req();
        let (out, log) = state.handle_and_persist_audit(&req).await;
        assert!(out.allowed);
        assert!(out.audit_verified);
        assert!(!log.is_empty());
        assert!(state.metrics.audit_appends.load(Ordering::Relaxed) as usize >= log.len());

        // No persistence configured => original outcome returned without store dependency.
        let mut no_persist = AppState::fail_closed();
        no_persist.config = no_persist.config.clone().with_rules(vec![Rule::exact(
            "agent",
            "tool.invoke",
            "tool",
            PolicyDecision::Permit,
        )]);
        let (out2, _) = no_persist.handle_and_persist_audit(&base_req()).await;
        assert!(out2.allowed);
    }

    #[tokio::test]
    async fn handle_and_persist_audit_fails_closed_when_required_store_missing() {
        let mut state = AppState::fail_closed();
        state.config = state.config.clone().with_rules(vec![Rule::exact(
            "agent",
            "tool.invoke",
            "tool",
            PolicyDecision::Permit,
        )]);
        state.config.runtime_hooks.persist_audit_events = true;

        let (out, log) = state.handle_and_persist_audit(&base_req()).await;
        assert!(
            !out.allowed,
            "must deny when append-before-return unavailable"
        );
        assert_eq!(out.stage, Stage::Audit);
        assert!(matches!(
            out.error,
            Some(crate::lifecycle::GatewayError::AuditInvalid)
        ));
        assert!(!log.is_empty());
        assert_eq!(state.metrics.requests_total.load(Ordering::Relaxed), 1);
        assert_eq!(state.metrics.requests_allowed.load(Ordering::Relaxed), 0);
        assert_eq!(state.metrics.requests_denied.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn prepare_runtime_hooks_rehydrates_pending_approvals_when_enabled() {
        let store = Arc::new(InMemoryStore::default()) as Arc<dyn Store>;
        store
            .create_approval(store::ApprovalRecord {
                id: "ap-1".into(),
                task_id: "task-state-1".into(),
                tool: "tool.invoke".into(),
                args_hash: "h1".into(),
                status: store::ApprovalStatus::Pending,
                created_at: "1".into(),
                resolved_at: None,
                resolver: None,
            })
            .await
            .unwrap();

        let mut state = AppState::fail_closed().with_store(store);
        state.config.runtime_hooks.use_approval_store = true;
        state.prepare_runtime_hooks().await.unwrap();
        assert!(state
            .approvals
            .lock()
            .expect("approvals lock")
            .get("ap-1")
            .is_some());

        // idempotent sync
        state.prepare_runtime_hooks().await.unwrap();
        assert!(state
            .approvals
            .lock()
            .expect("approvals lock")
            .get("ap-1")
            .is_some());
    }

    #[tokio::test]
    async fn rehydrate_pending_approvals_is_restart_safe_without_store() {
        let state = AppState::fail_closed();
        let restored = state
            .rehydrate_pending_approvals_from_store()
            .await
            .unwrap();
        assert_eq!(restored, 0);
    }

    #[tokio::test]
    async fn durable_hooks_fail_closed_when_store_missing() {
        let mut rev = AppState::fail_closed();
        rev.config.runtime_hooks.sync_revocations_from_store = true;
        assert!(rev.prepare_runtime_hooks().await.is_err());
        assert!(rev.sync_revocations_from_store().await.is_err());

        let mut appr = AppState::fail_closed();
        appr.config.runtime_hooks.use_approval_store = true;
        assert!(appr.prepare_runtime_hooks().await.is_err());
        assert!(appr.rehydrate_pending_approvals_from_store().await.is_err());
    }

    fn fake_stdio_mcp_server_args() -> Vec<String> {
        let script = r#"
import sys, json
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        req = json.loads(line)
    except Exception:
        continue
    mid = req.get("id")
    method = req.get("method")
    if method == "initialize":
        res = {
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": "fake-stdio", "version": "1"},
        }
    elif method == "tools/list":
        res = {"tools": [{"name": "echo", "inputSchema": {"type": "object"}}]}
    elif method == "tools/call":
        res = {"content": [{"type": "text", "text": "called"}], "isError": False}
    elif method == "ping":
        res = {}
    else:
        print(json.dumps({"jsonrpc":"2.0","id":mid,"error":{"code":-32601,"message":"method not found"}}), flush=True)
        continue
    print(json.dumps({"jsonrpc":"2.0","id":mid,"result":res}), flush=True)
"#;
        vec!["-u".into(), "-c".into(), script.into()]
    }

    #[tokio::test]
    async fn configure_mcp_runtime_dispatches_stdio_initialize_list_and_call() {
        let mut state = AppState::fail_closed();
        let server = mcp_pool::UpstreamServerConfig::with_stdio(
            "fake",
            "python3",
            fake_stdio_mcp_server_args(),
        );
        state.config.mcp_upstreams = vec![crate::config::McpUpstreamConfig {
            server,
            pool: mcp_pool::UpstreamConfig::default(),
        }];
        state.config.mcp_default_upstream = Some("fake".into());

        state.configure_mcp_runtime();
        let rt_guard = state.mcp.lock().await;
        let rt = rt_guard.as_ref().expect("mcp runtime configured");
        assert_eq!(
            rt.pool.state(&UpstreamId("fake".into())),
            Some(mcp_pool::ConnectionState::Connected)
        );
        assert!(rt
            .sessions
            .get(&UpstreamId("fake".into()))
            .is_some_and(|s| s.is_ready()));
        drop(rt_guard);

        // Non-envelope params form should still dispatch to initialize (forward normalization path).
        let init_obj = state
            .dispatch_mcp_via_pool(
                "initialize",
                r#"{"protocolVersion":"2024-11-05","capabilities":{}}"#.to_string(),
                None,
            )
            .await
            .expect("initialize via params normalization");
        assert!(init_obj.contains("protocolVersion"), "init_obj={init_obj}");

        for (method, payload, needle) in [
            (
                "initialize",
                r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
                "protocolVersion",
            ),
            (
                "tools/list",
                r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#,
                "\"tools\"",
            ),
            (
                "tools/call",
                r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":{}}}"#,
                "called",
            ),
        ] {
            let out = state
                .dispatch_mcp_via_pool(method, payload.to_string(), None)
                .await
                .expect(method);
            assert!(out.contains(needle), "method={method} out={out}");
        }
    }

    #[tokio::test]
    async fn configure_mcp_runtime_fail_closed_on_stdio_connect_error() {
        let mut state = AppState::fail_closed();
        let server = mcp_pool::UpstreamServerConfig::with_stdio(
            "bad",
            "/definitely/missing-mcp-binary",
            vec![],
        );
        state.config.mcp_upstreams = vec![crate::config::McpUpstreamConfig {
            server,
            pool: mcp_pool::UpstreamConfig::default(),
        }];
        state.config.mcp_default_upstream = Some("bad".into());

        state.configure_mcp_runtime();
        let err = state
            .dispatch_mcp_via_pool(
                "initialize",
                r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#.into(),
                None,
            )
            .await
            .expect_err("dispatch must fail closed when stdio connect unavailable");
        assert!(err.contains("pool_dispatch_failed"), "{err}");
    }

    #[tokio::test]
    async fn dispatch_mcp_via_pool_fails_closed_without_runtime() {
        let state = AppState::fail_closed();
        let err = state
            .dispatch_mcp_via_pool(
                "initialize",
                r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#.into(),
                None,
            )
            .await
            .expect_err("no runtime");
        assert_eq!(err, "mcp_pool_unavailable");
    }

    #[tokio::test]
    async fn prepare_runtime_hooks_configures_rate_tracker_for_s1_live_proof() {
        let mut state = AppState::fail_closed();
        state.config.runtime_hooks.enable_rate_limit_state = true;
        state.config.rate_limits.per_token_call_limit = Some(1);
        state.prepare_runtime_hooks().await.unwrap();
        assert!(state.has_rate_tracker());
    }

    #[tokio::test]
    async fn rate_limit_snapshot_restarts_restore_counters_fail_closed() {
        let store = Arc::new(InMemoryStore::default()) as Arc<dyn Store>;
        let mut state1 = AppState::fail_closed().with_store(store.clone());
        state1.config = state1.config.clone().with_rules(vec![Rule::exact(
            "agent",
            "tool.invoke",
            "tool",
            PolicyDecision::Permit,
        )]);
        state1.config.runtime_hooks.enable_rate_limit_state = true;
        state1.config.rate_limits.per_token_call_limit = Some(2);
        state1.prepare_runtime_hooks().await.unwrap();

        let req = base_req();
        let (out1, _) = state1.handle_and_persist_audit(&req).await;
        assert!(
            out1.allowed,
            "first call should be allowed: {:?}",
            out1.error
        );

        let mut state2 = AppState::fail_closed().with_store(store);
        state2.config = state2.config.clone().with_rules(vec![Rule::exact(
            "agent",
            "tool.invoke",
            "tool",
            PolicyDecision::Permit,
        )]);
        state2.config.runtime_hooks.enable_rate_limit_state = true;
        state2.config.rate_limits.per_token_call_limit = Some(2);
        state2.prepare_runtime_hooks().await.unwrap();

        let count = {
            let g = state2.rate_tracker.lock().expect("rate tracker lock");
            g.as_ref()
                .expect("tracker restored")
                .token_total_calls(&base_req().token.revocation_id.0)
        };
        assert_eq!(count, 1);

        let (out2, _) = state2.handle_and_persist_audit(&base_req()).await;
        assert!(out2.allowed, "second call after restart should be allowed");
        let (out3, _) = state2.handle_and_persist_audit(&base_req()).await;
        assert!(
            !out3.allowed,
            "third call should be denied by restored counter"
        );
        assert!(matches!(
            out3.error,
            Some(crate::lifecycle::GatewayError::BudgetOrRateLimited(_))
        ));
    }

    #[tokio::test]
    async fn rate_limit_snapshot_config_drift_applies_new_limits_to_restored_counts() {
        let store = Arc::new(InMemoryStore::default()) as Arc<dyn Store>;
        let mut state1 = AppState::fail_closed().with_store(store.clone());
        state1.config = state1.config.clone().with_rules(vec![Rule::exact(
            "agent",
            "tool.invoke",
            "tool",
            PolicyDecision::Permit,
        )]);
        state1.config.runtime_hooks.enable_rate_limit_state = true;
        state1.config.runtime_hooks.persist_rate_limit_state = true;
        state1.config.rate_limits.per_token_call_limit = Some(2);
        state1.prepare_runtime_hooks().await.unwrap();
        let (out1, _) = state1.handle_and_persist_audit(&base_req()).await;
        assert!(out1.allowed);

        // Restart with stricter limit: restored count=1 should be evaluated against new limit=1.
        let mut state2 = AppState::fail_closed().with_store(store);
        state2.config = state2.config.clone().with_rules(vec![Rule::exact(
            "agent",
            "tool.invoke",
            "tool",
            PolicyDecision::Permit,
        )]);
        state2.config.runtime_hooks.enable_rate_limit_state = true;
        state2.config.runtime_hooks.persist_rate_limit_state = true;
        state2.config.rate_limits.per_token_call_limit = Some(1);
        state2.prepare_runtime_hooks().await.unwrap();
        let (out2, _) = state2.handle_and_persist_audit(&base_req()).await;
        assert!(
            !out2.allowed,
            "restored count should be enforced against new stricter limit"
        );
        assert!(matches!(
            out2.error,
            Some(crate::lifecycle::GatewayError::BudgetOrRateLimited(_))
        ));
    }

    #[tokio::test]
    async fn sync_handle_path_marks_dirty_and_explicit_persist_recovers() {
        let store = Arc::new(InMemoryStore::default()) as Arc<dyn Store>;
        let mut state = AppState::fail_closed().with_store(store.clone());
        state.config = state.config.clone().with_rules(vec![Rule::exact(
            "agent",
            "tool.invoke",
            "tool",
            PolicyDecision::Permit,
        )]);
        state.config.runtime_hooks.enable_rate_limit_state = true;
        state.config.runtime_hooks.persist_rate_limit_state = true;
        state.config.rate_limits.per_token_call_limit = Some(2);
        state.prepare_runtime_hooks().await.unwrap();

        let (out, _) = state.handle_with_audit_log(&base_req());
        assert!(out.allowed);
        assert!(
            state
                .rate_limit_snapshot_dirty
                .load(std::sync::atomic::Ordering::Relaxed),
            "sync handle should mark rate snapshot dirty"
        );
        let persisted = state.persist_rate_limit_snapshot_if_dirty().await.unwrap();
        assert!(persisted);

        let mut restarted = AppState::fail_closed().with_store(store);
        restarted.config = restarted.config.clone().with_rules(vec![Rule::exact(
            "agent",
            "tool.invoke",
            "tool",
            PolicyDecision::Permit,
        )]);
        restarted.config.runtime_hooks.enable_rate_limit_state = true;
        restarted.config.runtime_hooks.persist_rate_limit_state = true;
        restarted.config.rate_limits.per_token_call_limit = Some(2);
        restarted.prepare_runtime_hooks().await.unwrap();
        let tracker = restarted.rate_tracker.lock().expect("rate tracker lock");
        let tracker = tracker.as_ref().expect("tracker restored");
        assert_eq!(
            tracker.token_total_calls(&base_req().token.revocation_id.0),
            1
        );
    }

    #[tokio::test]
    async fn dispatch_mcp_stdio_decode_failure_is_fail_closed_and_clears_session() {
        let mut state = AppState::fail_closed();
        let script = r#"
import sys
line = sys.stdin.readline()
print("NOT_JSON", flush=True)
sys.stdout.flush()
try:
    sys.stdin.readline()
except Exception:
    pass
"#;
        let server = mcp_pool::UpstreamServerConfig::with_stdio(
            "badjson",
            "python3",
            vec!["-u".into(), "-c".into(), script.into()],
        );
        state.config.mcp_upstreams = vec![crate::config::McpUpstreamConfig {
            server,
            pool: mcp_pool::UpstreamConfig::default(),
        }];
        state.config.mcp_default_upstream = Some("badjson".into());
        state.configure_mcp_runtime();

        let err = state
            .dispatch_mcp_via_pool(
                "initialize",
                r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#.into(),
                None,
            )
            .await
            .expect_err("decode failure must fail closed");
        assert!(err.contains("pool_dispatch_failed"), "{err}");

        let rt = state.mcp.lock().await;
        let rt = rt.as_ref().expect("runtime present");
        assert!(
            !rt.sessions.contains_key(&UpstreamId("badjson".into())),
            "corrupt session must be removed for reconnect-on-next-call"
        );
        assert_eq!(
            rt.pool.state(&UpstreamId("badjson".into())),
            Some(mcp_pool::ConnectionState::Unhealthy)
        );
    }

    #[tokio::test]
    async fn dispatch_mcp_stdio_closed_upstream_is_fail_closed_and_clears_session() {
        let mut state = AppState::fail_closed();
        let script = r#"
import sys
sys.stdin.readline()
# exit without response to simulate closed/broken stdio upstream
"#;
        let server = mcp_pool::UpstreamServerConfig::with_stdio(
            "closed",
            "python3",
            vec!["-u".into(), "-c".into(), script.into()],
        );
        state.config.mcp_upstreams = vec![crate::config::McpUpstreamConfig {
            server,
            pool: mcp_pool::UpstreamConfig::default(),
        }];
        state.config.mcp_default_upstream = Some("closed".into());
        state.configure_mcp_runtime();

        let err = state
            .dispatch_mcp_via_pool(
                "initialize",
                r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#.into(),
                None,
            )
            .await
            .expect_err("closed upstream must fail closed");
        assert!(err.contains("pool_dispatch_failed"), "{err}");

        let rt = state.mcp.lock().await;
        let rt = rt.as_ref().expect("runtime present");
        assert!(
            !rt.sessions.contains_key(&UpstreamId("closed".into())),
            "closed session must be removed"
        );
        assert_eq!(
            rt.pool.state(&UpstreamId("closed".into())),
            Some(mcp_pool::ConnectionState::Unhealthy)
        );
    }

    #[derive(Debug, Default)]
    struct FailingAuditStore;

    #[async_trait::async_trait]
    impl Store for FailingAuditStore {
        fn backend(&self) -> store::BackendKind {
            store::BackendKind::InMemory
        }
        async fn append_audit_event(
            &self,
            _event: store::AuditEvent,
        ) -> store::StoreResult<store::AuditEvent> {
            Err(store::StoreError::Unavailable(
                "simulated append failure".into(),
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
            approval: store::ApprovalRecord,
        ) -> store::StoreResult<store::ApprovalRecord> {
            Ok(approval)
        }
        async fn get_approval(
            &self,
            _id: &str,
        ) -> store::StoreResult<Option<store::ApprovalRecord>> {
            Ok(None)
        }
        async fn list_approvals(
            &self,
            _query: store::ApprovalQuery,
        ) -> store::StoreResult<Vec<store::ApprovalRecord>> {
            Ok(vec![])
        }
        async fn resolve_approval(
            &self,
            _id: &str,
            _status: store::ApprovalStatus,
            _resolver: Option<String>,
            _resolved_at: String,
        ) -> store::StoreResult<store::ApprovalRecord> {
            Err(store::StoreError::NotFound("not found".into()))
        }
        async fn upsert_task(
            &self,
            task: store::TaskRecord,
        ) -> store::StoreResult<store::TaskRecord> {
            Ok(task)
        }
        async fn get_task(&self, _id: &str) -> store::StoreResult<Option<store::TaskRecord>> {
            Ok(None)
        }
        async fn list_tasks(
            &self,
            _query: store::TaskQuery,
        ) -> store::StoreResult<Vec<store::TaskRecord>> {
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
        async fn save_rate_limit_snapshot(
            &self,
            snapshot: store::RateLimitSnapshotRecord,
        ) -> store::StoreResult<store::RateLimitSnapshotRecord> {
            Ok(snapshot)
        }
        async fn load_rate_limit_snapshot(
            &self,
        ) -> store::StoreResult<Option<store::RateLimitSnapshotRecord>> {
            Ok(None)
        }
        async fn health_check(&self) -> store::StoreResult<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn handle_and_persist_audit_fails_closed_on_append_error() {
        let store = Arc::new(FailingAuditStore) as Arc<dyn Store>;
        let mut state = AppState::fail_closed().with_store(store);
        state.config = state.config.clone().with_rules(vec![Rule::exact(
            "agent",
            "tool.invoke",
            "tool",
            PolicyDecision::Permit,
        )]);
        state.config.runtime_hooks.persist_audit_events = true;

        let (out, log) = state.handle_and_persist_audit(&base_req()).await;
        assert!(!out.allowed, "append-before-return failure must deny");
        assert_eq!(out.stage, Stage::Audit);
        assert!(matches!(
            out.error,
            Some(crate::lifecycle::GatewayError::AuditInvalid)
        ));
        assert!(!log.is_empty());
        assert_eq!(state.metrics.requests_total.load(Ordering::Relaxed), 1);
        assert_eq!(state.metrics.requests_allowed.load(Ordering::Relaxed), 0);
        assert_eq!(state.metrics.requests_denied.load(Ordering::Relaxed), 1);
        assert!(
            state.metrics.audit_append_failures.load(Ordering::Relaxed) >= 1,
            "append failure must be recorded"
        );
    }

    #[tokio::test]
    async fn effective_revoked_token_ids_fails_closed_on_store_query_error() {
        #[derive(Debug, Default)]
        struct FailingRevocationStore;
        #[async_trait::async_trait]
        impl Store for FailingRevocationStore {
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
                approval: store::ApprovalRecord,
            ) -> store::StoreResult<store::ApprovalRecord> {
                Ok(approval)
            }
            async fn get_approval(
                &self,
                _id: &str,
            ) -> store::StoreResult<Option<store::ApprovalRecord>> {
                Ok(None)
            }
            async fn list_approvals(
                &self,
                _query: store::ApprovalQuery,
            ) -> store::StoreResult<Vec<store::ApprovalRecord>> {
                Ok(vec![])
            }
            async fn resolve_approval(
                &self,
                _id: &str,
                _status: store::ApprovalStatus,
                _resolver: Option<String>,
                _resolved_at: String,
            ) -> store::StoreResult<store::ApprovalRecord> {
                Err(store::StoreError::NotFound("not found".into()))
            }
            async fn upsert_task(
                &self,
                task: store::TaskRecord,
            ) -> store::StoreResult<store::TaskRecord> {
                Ok(task)
            }
            async fn get_task(&self, _id: &str) -> store::StoreResult<Option<store::TaskRecord>> {
                Ok(None)
            }
            async fn list_tasks(
                &self,
                _query: store::TaskQuery,
            ) -> store::StoreResult<Vec<store::TaskRecord>> {
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
                Err(store::StoreError::Unavailable(
                    "revocation query boom".into(),
                ))
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
            async fn save_rate_limit_snapshot(
                &self,
                snapshot: store::RateLimitSnapshotRecord,
            ) -> store::StoreResult<store::RateLimitSnapshotRecord> {
                Ok(snapshot)
            }
            async fn load_rate_limit_snapshot(
                &self,
            ) -> store::StoreResult<Option<store::RateLimitSnapshotRecord>> {
                Ok(None)
            }
            async fn health_check(&self) -> store::StoreResult<()> {
                Ok(())
            }
        }

        let mut state = AppState::fail_closed().with_store(Arc::new(FailingRevocationStore));
        state.config.runtime_hooks.sync_revocations_from_store = true;
        let err = state
            .effective_revoked_token_ids()
            .await
            .expect_err("revocation store query failure must fail closed");
        assert!(err.contains("revocation query"), "{err}");
    }

    #[tokio::test]
    async fn prepare_runtime_hooks_preserves_rate_tracker_state_across_repeated_calls() {
        let mut state = AppState::fail_closed();
        state.config.runtime_hooks.enable_rate_limit_state = true;
        state.config.rate_limits.per_token_call_limit = Some(5);

        state.prepare_runtime_hooks().await.unwrap();
        {
            let mut rt = state.rate_tracker.lock().expect("rate tracker lock");
            let tracker = rt.as_mut().expect("tracker configured");
            tracker.consume("tok-rt", "tool.echo", 1, 0);
            assert_eq!(tracker.token_total_calls("tok-rt"), 1);
        }

        state.prepare_runtime_hooks().await.unwrap();
        let tracker = state.rate_tracker.lock().expect("rate tracker lock");
        let tracker = tracker.as_ref().expect("tracker preserved");
        assert_eq!(
            tracker.token_total_calls("tok-rt"),
            1,
            "repeated hook prep must not reset in-process rate/budget counters"
        );
    }
}
