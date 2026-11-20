//! Async runtime/client abstractions for upstream MCP servers.
//!
//! Provides tokio-based stdio subprocess and HTTP client/session primitives,
//! plus async pool/dispatch helpers layered over the core policies in `lib`.

#[cfg(feature = "tokio-runtime")]
mod imp {
    use crate::{
        AsyncConnectionManager, AsyncMcpClientSession, CallRequest, CircuitBreaker, CircuitState,
        ConnectionState, DispatchOutcome, ForwardRequest, ForwardResponse, HealthStatus, PoolError,
        TransportKind, TransportSpec, UpstreamConfig, UpstreamId, UpstreamServerConfig,
    };
    use async_trait::async_trait;
    use serde_json::Value;
    use std::collections::BTreeMap;
    use std::collections::HashMap;
    use std::sync::Arc;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::process::{Child, ChildStdin, ChildStdout, Command};
    use tokio::sync::Mutex;
    use tokio::time::timeout;

    /// Generic async JSON-RPC-ish request/response transport.
    #[async_trait]
    pub trait AsyncJsonRpcTransport: Send {
        async fn send(&mut self, request: Value) -> Result<Value, PoolError>;
        async fn is_ready(&self) -> bool;
        async fn close(&mut self) -> Result<(), PoolError> {
            Ok(())
        }
    }

    /// Stdio subprocess client: spawns process and speaks line-delimited JSON over stdin/stdout.
    pub struct StdioSubprocessClient {
        _upstream: UpstreamId,
        _child: Child,
        stdin: ChildStdin,
        stdout: BufReader<ChildStdout>,
        next_id: i64,
        ready: bool,
    }

    impl StdioSubprocessClient {
        pub async fn spawn(server: &UpstreamServerConfig) -> Result<Self, PoolError> {
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
                _upstream: server.id.clone(),
                _child: child,
                stdin,
                stdout: BufReader::new(stdout),
                next_id: 1,
                ready: true,
            })
        }

        fn next_id(&mut self) -> i64 {
            let id = self.next_id;
            self.next_id = self.next_id.saturating_add(1);
            id
        }
    }

    #[async_trait]
    impl AsyncJsonRpcTransport for StdioSubprocessClient {
        async fn send(&mut self, mut request: Value) -> Result<Value, PoolError> {
            if !self.ready {
                return Err(PoolError::Unavailable("stdio client not ready".into()));
            }
            if request.get("id").is_none() {
                request["id"] = Value::from(self.next_id());
            }
            if request.get("jsonrpc").is_none() {
                request["jsonrpc"] = Value::from("2.0");
            }
            let mut line = serde_json::to_string(&request)
                .map_err(|e| PoolError::DispatchFailed(format!("encode: {e}")))?;
            line.push('\n');
            self.stdin.write_all(line.as_bytes()).await.map_err(|e| {
                self.ready = false;
                PoolError::DispatchFailed(format!("stdin write: {e}"))
            })?;
            self.stdin.flush().await.map_err(|e| {
                self.ready = false;
                PoolError::DispatchFailed(format!("stdin flush: {e}"))
            })?;
            let mut out = String::new();
            let n = self.stdout.read_line(&mut out).await.map_err(|e| {
                self.ready = false;
                PoolError::DispatchFailed(format!("stdout read: {e}"))
            })?;
            if n == 0 {
                self.ready = false;
                return Err(PoolError::Unavailable("stdio closed".into()));
            }
            serde_json::from_str(out.trim_end())
                .map_err(|e| PoolError::DispatchFailed(format!("decode: {e}")))
        }

        async fn is_ready(&self) -> bool {
            self.ready
        }

        async fn close(&mut self) -> Result<(), PoolError> {
            self.ready = false;
            Ok(())
        }
    }

    /// HTTP client abstraction for MCP JSON-RPC endpoints.
    /// Minimal implementation over a pluggable async sender; default uses tokio process-less
    /// placeholder error unless an injected transport is provided. Kept as abstraction seam.
    #[async_trait]
    pub trait AsyncHttpSender: Send {
        async fn post_json(&self, url: &str, body: Value) -> Result<Value, PoolError>;

        async fn post_json_with_headers(
            &self,
            url: &str,
            headers: &BTreeMap<String, String>,
            body: Value,
        ) -> Result<Value, PoolError> {
            let _ = headers;
            self.post_json(url, body).await
        }
    }

    pub struct HttpRpcClient<S: AsyncHttpSender> {
        upstream: UpstreamId,
        url: String,
        headers: BTreeMap<String, String>,
        sender: S,
        ready: bool,
    }

    impl<S: AsyncHttpSender> HttpRpcClient<S> {
        pub fn new(upstream: UpstreamId, url: String, sender: S) -> Self {
            Self::with_headers(upstream, url, BTreeMap::new(), sender)
        }

        pub fn with_headers(
            upstream: UpstreamId,
            url: String,
            headers: BTreeMap<String, String>,
            sender: S,
        ) -> Self {
            Self {
                upstream,
                url,
                headers,
                sender,
                ready: true,
            }
        }

        pub fn upstream(&self) -> &UpstreamId {
            &self.upstream
        }
    }

    #[async_trait]
    impl<S: AsyncHttpSender + Sync> AsyncJsonRpcTransport for HttpRpcClient<S> {
        async fn send(&mut self, request: Value) -> Result<Value, PoolError> {
            if !self.ready {
                return Err(PoolError::Unavailable("http client not ready".into()));
            }
            self.sender
                .post_json_with_headers(&self.url, &self.headers, request)
                .await
        }
        async fn is_ready(&self) -> bool {
            self.ready
        }
        async fn close(&mut self) -> Result<(), PoolError> {
            self.ready = false;
            Ok(())
        }
    }

    /// Placeholder HTTP sender that fails closed (no implicit network dep in crate).
    pub struct UnconfiguredHttpSender;
    #[async_trait]
    impl AsyncHttpSender for UnconfiguredHttpSender {
        async fn post_json(&self, _url: &str, _body: Value) -> Result<Value, PoolError> {
            Err(PoolError::Unavailable(
                "http sender not configured; inject AsyncHttpSender".into(),
            ))
        }
    }

    /// Async session wrapper over a JSON-RPC transport implementing pool traits.
    pub struct JsonRpcAsyncSession<T: AsyncJsonRpcTransport> {
        _upstream: UpstreamId,
        transport: Mutex<T>,
    }

    impl<T: AsyncJsonRpcTransport> JsonRpcAsyncSession<T> {
        pub fn new(upstream: UpstreamId, transport: T) -> Self {
            Self {
                _upstream: upstream,
                transport: Mutex::new(transport),
            }
        }
    }

    #[async_trait]
    impl<T: AsyncJsonRpcTransport> AsyncMcpClientSession for JsonRpcAsyncSession<T> {
        async fn is_ready(&self) -> bool {
            self.transport.lock().await.is_ready().await
        }

        async fn ping(&mut self) -> Result<(), PoolError> {
            let req = serde_json::json!({"jsonrpc":"2.0","method":"ping","params":{}});
            let _ = self.transport.lock().await.send(req).await?;
            Ok(())
        }

        async fn forward(
            &mut self,
            request: &ForwardRequest,
        ) -> Result<ForwardResponse, PoolError> {
            let payload_val: Value = serde_json::from_str(&request.payload).unwrap_or(Value::Null);
            let req = match payload_val {
                Value::Object(mut obj) => {
                    // Preserve caller-provided MCP JSON-RPC envelopes when present.
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
            let resp = self.transport.lock().await.send(req).await?;
            let payload = if let Some(r) = resp.get("result") {
                serde_json::to_string(r).unwrap_or_else(|_| r.to_string())
            } else if let Some(e) = resp.get("error") {
                return Err(PoolError::DispatchFailed(e.to_string()));
            } else {
                resp.to_string()
            };
            Ok(ForwardResponse { payload })
        }
    }

    /// Async connection manager for stdio subprocess upstreams.
    pub struct StdioConnectionManager;
    #[async_trait]
    impl AsyncConnectionManager for StdioConnectionManager {
        type Session = JsonRpcAsyncSession<StdioSubprocessClient>;

        async fn connect(
            &mut self,
            server: &UpstreamServerConfig,
        ) -> Result<Self::Session, PoolError> {
            if server.transport != TransportKind::Stdio {
                return Err(PoolError::Unavailable("expected stdio transport".into()));
            }
            let client = StdioSubprocessClient::spawn(server).await?;
            Ok(JsonRpcAsyncSession::new(server.id.clone(), client))
        }

        async fn disconnect(&mut self, mut session: Self::Session) -> Result<(), PoolError> {
            session.transport.get_mut().close().await
        }
    }

    /// Async connection manager for HTTP upstreams with injected sender.
    pub struct HttpConnectionManager<S: AsyncHttpSender + Clone + Send + Sync + 'static> {
        pub sender: S,
    }
    #[async_trait]
    impl<S: AsyncHttpSender + Clone + Send + Sync + 'static> AsyncConnectionManager
        for HttpConnectionManager<S>
    {
        type Session = JsonRpcAsyncSession<HttpRpcClient<S>>;

        async fn connect(
            &mut self,
            server: &UpstreamServerConfig,
        ) -> Result<Self::Session, PoolError> {
            if server.transport != TransportKind::Http {
                return Err(PoolError::Unavailable("expected http transport".into()));
            }
            let (url, headers) = match &server.transport_spec {
                TransportSpec::Http(h) => (h.url.clone(), h.headers.clone()),
                _ => (server.endpoint.clone(), BTreeMap::new()),
            };
            let client =
                HttpRpcClient::with_headers(server.id.clone(), url, headers, self.sender.clone());
            Ok(JsonRpcAsyncSession::new(server.id.clone(), client))
        }

        async fn disconnect(&mut self, mut session: Self::Session) -> Result<(), PoolError> {
            session.transport.get_mut().close().await
        }
    }

    /// Per-upstream async runtime slot with lifecycle/health/circuit/retry/timeout state.
    struct AsyncSlot<S> {
        server: UpstreamServerConfig,
        config: UpstreamConfig,
        state: ConnectionState,
        breaker: CircuitBreaker,
        healthy: bool,
        active_leases: usize,
        session: Option<Arc<Mutex<S>>>,
        circuit_opened_at: Option<tokio::time::Instant>,
    }

    impl<S> AsyncSlot<S> {
        fn new(server: UpstreamServerConfig, config: UpstreamConfig) -> Self {
            Self {
                breaker: CircuitBreaker::with_policy(config.breaker),
                server,
                config,
                state: ConnectionState::Disconnected,
                healthy: false,
                active_leases: 0,
                session: None,
                circuit_opened_at: None,
            }
        }
        fn max_leases(&self) -> usize {
            self.config.effective_max_leases()
        }

        fn maybe_half_open_after_cooldown(&mut self) {
            if self.breaker.state != CircuitState::Open {
                self.circuit_opened_at = None;
                return;
            }
            let cooldown = self.breaker.policy.open_cooldown;
            let Some(at) = self.circuit_opened_at else {
                // No recorded open time (e.g. synthetic/manual state): stay fail-closed.
                return;
            };
            if cooldown.is_zero() || at.elapsed() >= cooldown {
                self.breaker.enter_half_open();
                self.circuit_opened_at = None;
            }
        }

        fn record_breaker_failure(&mut self) {
            self.breaker.record_failure();
            if self.breaker.state == CircuitState::Open {
                self.circuit_opened_at = Some(tokio::time::Instant::now());
            }
        }

        fn record_breaker_success(&mut self) {
            self.breaker.record_success();
            if self.breaker.state != CircuitState::Open {
                self.circuit_opened_at = None;
            }
        }
    }

    /// Async upstream pool/client runtime managing sessions and dispatch.
    pub struct AsyncMcpPool<M: AsyncConnectionManager> {
        manager: M,
        upstreams: HashMap<UpstreamId, AsyncSlot<M::Session>>,
        default_config: UpstreamConfig,
    }

    impl<M: AsyncConnectionManager> AsyncMcpPool<M> {
        pub fn new(manager: M, default_config: UpstreamConfig) -> Self {
            Self {
                manager,
                upstreams: HashMap::new(),
                default_config,
            }
        }

        pub fn register_with_server_config(
            &mut self,
            server: UpstreamServerConfig,
            config: UpstreamConfig,
        ) {
            self.upstreams
                .insert(server.id.clone(), AsyncSlot::new(server, config));
        }

        pub fn register(&mut self, server: UpstreamServerConfig) {
            self.register_with_server_config(server, self.default_config);
        }

        pub fn state(&self, upstream: &UpstreamId) -> Option<ConnectionState> {
            self.upstreams.get(upstream).map(|s| s.state)
        }
        pub fn breaker(&self, upstream: &UpstreamId) -> Option<&CircuitBreaker> {
            self.upstreams.get(upstream).map(|s| &s.breaker)
        }
        pub fn active_leases(&self, upstream: &UpstreamId) -> Option<usize> {
            self.upstreams.get(upstream).map(|s| s.active_leases)
        }

        pub async fn connect(&mut self, upstream: &UpstreamId) -> Result<(), PoolError> {
            let (server, prev) = {
                let slot = self
                    .upstreams
                    .get_mut(upstream)
                    .ok_or_else(|| PoolError::UnknownUpstream(upstream.0.clone()))?;
                slot.maybe_half_open_after_cooldown();
                slot.state = ConnectionState::Connecting;
                (slot.server.clone(), slot.session.take())
            };
            if let Some(prev) = prev {
                if let Ok(sess) = Arc::try_unwrap(prev) {
                    let _ = self.manager.disconnect(sess.into_inner()).await;
                }
            }
            match self.manager.connect(&server).await {
                Ok(sess) => {
                    let slot = self.upstreams.get_mut(upstream).unwrap();
                    slot.session = Some(Arc::new(Mutex::new(sess)));
                    slot.state = ConnectionState::Connected;
                    slot.healthy = true;
                    slot.record_breaker_success();
                    Ok(())
                }
                Err(e) => {
                    if let Some(slot) = self.upstreams.get_mut(upstream) {
                        slot.state = ConnectionState::Unhealthy;
                        slot.healthy = false;
                        slot.session = None;
                        slot.record_breaker_failure();
                    }
                    Err(e)
                }
            }
        }

        pub async fn disconnect(&mut self, upstream: &UpstreamId) -> Result<(), PoolError> {
            let (sess, slot_state) = {
                let slot = self
                    .upstreams
                    .get_mut(upstream)
                    .ok_or_else(|| PoolError::UnknownUpstream(upstream.0.clone()))?;
                slot.state = ConnectionState::Disconnected;
                slot.healthy = false;
                (slot.session.take(), ())
            };
            let _ = slot_state;
            if let Some(s) = sess {
                if let Ok(s) = Arc::try_unwrap(s) {
                    let _ = self.manager.disconnect(s.into_inner()).await;
                }
            }
            Ok(())
        }

        pub async fn reconnect(&mut self, upstream: &UpstreamId) -> Result<(), PoolError> {
            self.disconnect(upstream).await?;
            self.connect(upstream).await
        }

        pub async fn ensure_connected(&mut self, upstream: &UpstreamId) -> Result<(), PoolError> {
            match self.state(upstream) {
                Some(ConnectionState::Connected) => Ok(()),
                Some(ConnectionState::Connecting) => Err(PoolError::InvalidState {
                    upstream: upstream.0.clone(),
                    state: ConnectionState::Connecting,
                }),
                Some(_) => self.connect(upstream).await,
                None => Err(PoolError::UnknownUpstream(upstream.0.clone())),
            }
        }

        pub async fn probe_health(
            &mut self,
            upstream: &UpstreamId,
        ) -> Result<HealthStatus, PoolError> {
            let (session, call_timeout) = {
                let slot = self
                    .upstreams
                    .get_mut(upstream)
                    .ok_or_else(|| PoolError::UnknownUpstream(upstream.0.clone()))?;
                slot.maybe_half_open_after_cooldown();
                (slot.session.clone(), slot.config.effective_call_timeout())
            };
            let status = match session {
                Some(sess) => {
                    let probe = async {
                        let mut s = sess.lock().await;
                        match s.ping().await {
                            Ok(_) if s.is_ready().await => HealthStatus::Healthy,
                            _ => HealthStatus::Unhealthy,
                        }
                    };
                    if call_timeout.is_zero() {
                        probe.await
                    } else {
                        match timeout(call_timeout, probe).await {
                            Ok(s) => s,
                            Err(_) => HealthStatus::Unhealthy,
                        }
                    }
                }
                None => HealthStatus::Unhealthy,
            };
            let slot = self.upstreams.get_mut(upstream).unwrap();
            match status {
                HealthStatus::Healthy => {
                    slot.healthy = true;
                    if matches!(
                        slot.state,
                        ConnectionState::Unhealthy | ConnectionState::Disconnected
                    ) {
                        slot.state = ConnectionState::Connected;
                    }
                    slot.record_breaker_success();
                }
                HealthStatus::Unhealthy => {
                    slot.healthy = false;
                    slot.state = ConnectionState::Unhealthy;
                    slot.session = None;
                    slot.record_breaker_failure();
                }
            }
            Ok(status)
        }

        async fn acquire(
            &mut self,
            upstream: &UpstreamId,
        ) -> Result<Arc<Mutex<M::Session>>, PoolError> {
            let slot = self
                .upstreams
                .get_mut(upstream)
                .ok_or_else(|| PoolError::UnknownUpstream(upstream.0.clone()))?;
            slot.maybe_half_open_after_cooldown();
            if !slot.breaker.allow_request() {
                return Err(PoolError::CircuitOpen(
                    "requests blocked by circuit breaker".into(),
                ));
            }
            if !matches!(slot.state, ConnectionState::Connected) || !slot.healthy {
                return Err(PoolError::Unavailable(format!(
                    "upstream unavailable in state {:?}",
                    slot.state
                )));
            }
            let cap = slot.max_leases();
            if slot.active_leases >= cap {
                let t = slot.config.effective_acquire_timeout();
                if t.is_zero() {
                    return Err(PoolError::Exhausted { max_leases: cap });
                }
                return Err(PoolError::Timeout { waited: t });
            }
            let sess = slot
                .session
                .clone()
                .ok_or_else(|| PoolError::Unavailable("no active session".into()))?;
            slot.active_leases += 1;
            Ok(sess)
        }

        fn release(&mut self, upstream: &UpstreamId) {
            if let Some(slot) = self.upstreams.get_mut(upstream) {
                slot.active_leases = slot.active_leases.saturating_sub(1);
            }
        }

        fn mark_failure(&mut self, upstream: &UpstreamId) {
            if let Some(slot) = self.upstreams.get_mut(upstream) {
                slot.record_breaker_failure();
                slot.healthy = false;
                slot.state = ConnectionState::Unhealthy;
                slot.session = None;
            }
        }
        fn mark_success(&mut self, upstream: &UpstreamId) {
            if let Some(slot) = self.upstreams.get_mut(upstream) {
                slot.record_breaker_success();
                slot.healthy = true;
                slot.state = ConnectionState::Connected;
            }
        }

        /// Dispatch API for mcp-front/gateway: retries, timeouts, circuit/health aware.
        pub async fn dispatch(
            &mut self,
            upstream: &UpstreamId,
            request: &CallRequest,
        ) -> Result<DispatchOutcome, PoolError> {
            let (max_retries, call_timeout, retry_cfg) = {
                let slot = self
                    .upstreams
                    .get(upstream)
                    .ok_or_else(|| PoolError::UnknownUpstream(upstream.0.clone()))?;
                (
                    slot.config.effective_max_retries(),
                    slot.config.effective_call_timeout(),
                    slot.config,
                )
            };
            let mut attempts = 0u32;
            loop {
                attempts = attempts.saturating_add(1);

                if let Some(slot) = self.upstreams.get_mut(upstream) {
                    slot.maybe_half_open_after_cooldown();
                }
                if matches!(
                    self.state(upstream),
                    Some(ConnectionState::Disconnected | ConnectionState::Unhealthy)
                ) {
                    let _ = self.connect(upstream).await;
                }

                let session = match self.acquire(upstream).await {
                    Ok(s) => s,
                    Err(e) if e.is_retryable() && attempts <= max_retries => {
                        let delay = retry_cfg.retry_delay_for_attempt(attempts);
                        if !delay.is_zero() {
                            tokio::time::sleep(delay).await;
                        }
                        if matches!(
                            self.state(upstream),
                            Some(ConnectionState::Unhealthy | ConnectionState::Disconnected)
                        ) {
                            let _ = self.connect(upstream).await;
                        }
                        continue;
                    }
                    Err(e) => return Err(e),
                };
                let call_fut = async {
                    let mut s = session.lock().await;
                    s.forward(request).await
                };
                let result = if call_timeout.is_zero() {
                    call_fut.await
                } else {
                    match timeout(call_timeout, call_fut).await {
                        Ok(r) => r,
                        Err(_) => Err(PoolError::Timeout {
                            waited: call_timeout,
                        }),
                    }
                };
                self.release(upstream);
                match result {
                    Ok(response) => {
                        self.mark_success(upstream);
                        return Ok(DispatchOutcome { response, attempts });
                    }
                    Err(e) => {
                        self.mark_failure(upstream);
                        if e.is_retryable() && attempts <= max_retries {
                            let delay = retry_cfg.retry_delay_for_attempt(attempts);
                            if !delay.is_zero() {
                                tokio::time::sleep(delay).await;
                            }
                            if matches!(
                                self.state(upstream),
                                Some(ConnectionState::Unhealthy | ConnectionState::Disconnected)
                            ) {
                                let _ = self.connect(upstream).await;
                            }
                            continue;
                        }
                        return Err(e);
                    }
                }
            }
        }
    }

    /// Front/gateway dispatch request helper (async).
    #[derive(Debug, Clone)]
    pub struct AsyncFrontDispatchRequest {
        pub upstream: UpstreamId,
        pub method: String,
        pub payload: String,
    }
    #[derive(Debug, Clone)]
    pub struct AsyncFrontDispatchResponse {
        pub payload: String,
        pub attempts: u32,
    }

    impl<M: AsyncConnectionManager> AsyncMcpPool<M> {
        pub async fn dispatch_front(
            &mut self,
            req: AsyncFrontDispatchRequest,
        ) -> Result<AsyncFrontDispatchResponse, PoolError> {
            self.ensure_connected(&req.upstream).await?;
            let out = self
                .dispatch(
                    &req.upstream,
                    &CallRequest {
                        method: req.method,
                        payload: req.payload,
                    },
                )
                .await?;
            Ok(AsyncFrontDispatchResponse {
                payload: out.response.payload,
                attempts: out.attempts,
            })
        }
    }

    /// Real `rmcp` client session over a spawned stdio subprocess.
    ///
    /// Enabled with `tokio-runtime` + `rmcp` features. Uses `rmcp`'s async-rw
    /// transport and client service/peer APIs for real upstream MCP dispatch.
    #[cfg(feature = "rmcp")]
    pub mod rmcp_client {
        use super::*;
        use rmcp::service::{RoleClient, RunningService, ServiceExt};
        use tokio::process::Command;

        /// `AsyncMcpClientSession` backed by a real `rmcp` client `RunningService`.
        pub struct RmcpClientSession {
            upstream: UpstreamId,
            service: RunningService<RoleClient, ()>,
        }

        impl RmcpClientSession {
            pub fn upstream(&self) -> &UpstreamId {
                &self.upstream
            }

            fn transport_ready(&self) -> bool {
                !self.service.is_transport_closed()
            }

            fn extract_params(payload: &str) -> Value {
                let payload_val: Value = serde_json::from_str(payload).unwrap_or(Value::Null);
                payload_val.get("params").cloned().unwrap_or(payload_val)
            }

            async fn forward_typed(
                &self,
                method: &str,
                payload: &str,
            ) -> Result<ForwardResponse, PoolError> {
                if !self.transport_ready() {
                    return Err(PoolError::Unavailable(
                        "rmcp stdio session transport closed".into(),
                    ));
                }
                let params = Self::extract_params(payload);
                match method {
                    "initialize" => Ok(ForwardResponse {
                        payload: serde_json::json!({
                            "protocolVersion": "2024-11-05",
                            "capabilities": { "tools": {} },
                            "serverInfo": { "name": self.upstream.0, "version": "rmcp" }
                        })
                        .to_string(),
                    }),
                    "ping" => Ok(ForwardResponse {
                        payload: serde_json::json!({}).to_string(),
                    }),
                    "tools/list" => {
                        let p: Option<rmcp::model::PaginatedRequestParam> = if params.is_null()
                            || params.as_object().is_some_and(|o| o.is_empty())
                        {
                            None
                        } else {
                            Some(serde_json::from_value(params).map_err(|e| {
                                PoolError::DispatchFailed(format!(
                                    "invalid tools/list params: {e}"
                                ))
                            })?)
                        };
                        let res = self.service.peer().list_tools(p).await.map_err(|e| {
                            PoolError::DispatchFailed(format!("rmcp tools/list failed: {e}"))
                        })?;
                        Ok(ForwardResponse {
                            payload: serde_json::to_string(&res).map_err(|e| {
                                PoolError::DispatchFailed(format!("encode tools/list result: {e}"))
                            })?,
                        })
                    }
                    "tools/call" => {
                        let p: rmcp::model::CallToolRequestParam = serde_json::from_value(params)
                            .map_err(|e| {
                                PoolError::DispatchFailed(format!(
                                    "invalid tools/call params: {e}"
                                ))
                            })?;
                        let res = self.service.peer().call_tool(p).await.map_err(|e| {
                            PoolError::DispatchFailed(format!("rmcp tools/call failed: {e}"))
                        })?;
                        Ok(ForwardResponse {
                            payload: serde_json::to_string(&res).map_err(|e| {
                                PoolError::DispatchFailed(format!("encode tools/call result: {e}"))
                            })?,
                        })
                    }
                    _ => Err(PoolError::DispatchFailed(format!(
                        "rmcp stdio upstream session does not support method '{method}' (fail-closed)"
                    ))),
                }
            }
        }

        #[async_trait]
        impl AsyncMcpClientSession for RmcpClientSession {
            async fn is_ready(&self) -> bool {
                self.transport_ready()
            }

            async fn ping(&mut self) -> Result<(), PoolError> {
                if self.is_ready().await {
                    Ok(())
                } else {
                    Err(PoolError::Unavailable(
                        "rmcp stdio session transport closed".into(),
                    ))
                }
            }

            async fn forward(
                &mut self,
                request: &ForwardRequest,
            ) -> Result<ForwardResponse, PoolError> {
                let payload_method = serde_json::from_str::<Value>(&request.payload)
                    .ok()
                    .and_then(|v| v.get("method").and_then(|m| m.as_str()).map(str::to_string));
                let method = payload_method.as_deref().unwrap_or(request.method.as_str());
                self.forward_typed(method, &request.payload).await
            }
        }

        /// Connection manager that spawns a stdio MCP server subprocess and connects
        /// using a real `rmcp` client service over async-rw transport.
        #[derive(Debug, Default, Clone, Copy)]
        pub struct RmcpStdioConnectionManager;

        #[async_trait]
        impl AsyncConnectionManager for RmcpStdioConnectionManager {
            type Session = RmcpClientSession;

            async fn connect(
                &mut self,
                server: &UpstreamServerConfig,
            ) -> Result<Self::Session, PoolError> {
                if server.transport != TransportKind::Stdio {
                    return Err(PoolError::Unavailable(
                        "RmcpStdioConnectionManager requires stdio transport".into(),
                    ));
                }
                let spec = match &server.transport_spec {
                    TransportSpec::Stdio(s) => s.clone(),
                    _ => {
                        return Err(PoolError::Unavailable(
                            "stdio transport spec required for rmcp stdio client".into(),
                        ))
                    }
                };
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
                    .map_err(|e| PoolError::Unavailable(format!("spawn failed: {e}")))?;
                let stdin = child
                    .stdin
                    .take()
                    .ok_or_else(|| PoolError::Unavailable("missing child stdin".into()))?;
                let stdout = child
                    .stdout
                    .take()
                    .ok_or_else(|| PoolError::Unavailable("missing child stdout".into()))?;

                // rmcp async-rw transport expects (reader, writer) = (child stdout, child stdin)
                let service = ().serve((stdout, stdin)).await.map_err(|e| {
                    let _ = child.start_kill();
                    PoolError::Unavailable(format!("rmcp client handshake failed: {e}"))
                })?;

                tokio::spawn(async move {
                    let _ = child.wait().await;
                });

                Ok(RmcpClientSession {
                    upstream: server.id.clone(),
                    service,
                })
            }

            async fn disconnect(&mut self, session: Self::Session) -> Result<(), PoolError> {
                let _ = session.service.cancel().await;
                Ok(())
            }
        }
    }

    #[cfg(feature = "rmcp")]
    pub use rmcp_client::{RmcpClientSession, RmcpStdioConnectionManager};

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::{
            CallRequest, CircuitBreakerPolicy, CircuitState, ConnectionState, PoolError,
            RetryPolicy, TimeoutPolicy, UpstreamConfig, UpstreamServerConfig,
        };
        use async_trait::async_trait;
        use std::sync::{
            atomic::{AtomicU32, Ordering},
            Arc,
        };
        use std::time::{Duration, Instant};

        #[derive(Clone, Debug)]
        struct TestSession {
            mode: TestMode,
            calls: Arc<AtomicU32>,
        }

        #[derive(Clone, Debug)]
        enum TestMode {
            FailThenOk {
                fail_times: u32,
                fail_msg: &'static str,
                ok_payload: &'static str,
            },
            Hang,
        }

        #[async_trait]
        impl AsyncMcpClientSession for TestSession {
            async fn is_ready(&self) -> bool {
                !matches!(self.mode, TestMode::Hang)
            }

            async fn ping(&mut self) -> Result<(), PoolError> {
                match self.mode {
                    TestMode::Hang => {
                        std::future::pending::<()>().await;
                        Ok(())
                    }
                    _ => Ok(()),
                }
            }

            async fn forward(
                &mut self,
                request: &ForwardRequest,
            ) -> Result<ForwardResponse, PoolError> {
                let n = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
                match self.mode {
                    TestMode::FailThenOk {
                        fail_times,
                        fail_msg,
                        ok_payload,
                    } => {
                        if n <= fail_times {
                            Err(PoolError::DispatchFailed(fail_msg.into()))
                        } else {
                            Ok(ForwardResponse {
                                payload: format!("{ok_payload}:{}", request.method),
                            })
                        }
                    }
                    TestMode::Hang => {
                        std::future::pending::<()>().await;
                        unreachable!()
                    }
                }
            }
        }

        struct TestManager {
            mode: TestMode,
            calls: Arc<AtomicU32>,
        }

        impl TestManager {
            fn new(mode: TestMode) -> Self {
                Self {
                    mode,
                    calls: Arc::new(AtomicU32::new(0)),
                }
            }
        }

        #[async_trait]
        impl AsyncConnectionManager for TestManager {
            type Session = TestSession;

            async fn connect(
                &mut self,
                server: &UpstreamServerConfig,
            ) -> Result<Self::Session, PoolError> {
                let _ = server;
                Ok(TestSession {
                    mode: self.mode.clone(),
                    calls: self.calls.clone(),
                })
            }
        }

        fn server(id: &str) -> UpstreamServerConfig {
            UpstreamServerConfig::with_http(id, "http://example.test/mcp")
        }

        #[tokio::test]
        async fn dispatch_enforces_call_timeout_fail_closed() {
            let srv = server("t-timeout");
            let id = srv.id.clone();
            let mut pool =
                AsyncMcpPool::new(TestManager::new(TestMode::Hang), UpstreamConfig::default());
            pool.register_with_server_config(
                srv,
                UpstreamConfig {
                    timeouts: TimeoutPolicy {
                        call_timeout: Duration::from_millis(20),
                        ..Default::default()
                    },
                    breaker: CircuitBreakerPolicy {
                        failure_threshold: 1,
                        ..Default::default()
                    },
                    ..Default::default()
                },
            );
            pool.connect(&id).await.expect("connect");
            let err = pool
                .dispatch(
                    &id,
                    &CallRequest {
                        method: "m".into(),
                        payload: "{}".into(),
                    },
                )
                .await
                .expect_err("timeout");
            assert!(
                matches!(err, PoolError::Timeout { waited } if waited == Duration::from_millis(20))
            );
            assert_eq!(pool.state(&id), Some(ConnectionState::Unhealthy));
            assert_eq!(pool.breaker(&id).map(|b| b.state), Some(CircuitState::Open));
        }

        #[tokio::test]
        async fn dispatch_honors_retry_backoff_between_retryable_attempts() {
            let srv = server("t-retry");
            let id = srv.id.clone();
            let mgr = TestManager::new(TestMode::FailThenOk {
                fail_times: 2,
                fail_msg: "transient",
                ok_payload: "ok",
            });
            let calls = mgr.calls.clone();
            let mut pool = AsyncMcpPool::new(mgr, UpstreamConfig::default());
            pool.register_with_server_config(
                srv,
                UpstreamConfig {
                    retry: RetryPolicy {
                        max_retries: 2,
                        backoff: Duration::from_millis(20),
                    },
                    breaker: CircuitBreakerPolicy {
                        failure_threshold: 10,
                        ..Default::default()
                    },
                    ..Default::default()
                },
            );
            pool.connect(&id).await.expect("connect");
            let start = Instant::now();
            let out = pool
                .dispatch(
                    &id,
                    &CallRequest {
                        method: "m".into(),
                        payload: "{}".into(),
                    },
                )
                .await
                .expect("dispatch");
            let elapsed = start.elapsed();
            assert_eq!(out.response.payload, "ok:m");
            assert_eq!(out.attempts, 3);
            assert_eq!(calls.load(Ordering::SeqCst), 3);
            // retry_delay_for_attempt(1)=20ms, attempt(2)=20ms
            assert!(elapsed >= Duration::from_millis(35), "elapsed {elapsed:?}");
        }

        #[tokio::test]
        async fn probe_health_enforces_timeout() {
            let srv = server("t-probe");
            let id = srv.id.clone();
            let mut pool =
                AsyncMcpPool::new(TestManager::new(TestMode::Hang), UpstreamConfig::default());
            pool.register_with_server_config(
                srv,
                UpstreamConfig {
                    timeouts: TimeoutPolicy {
                        call_timeout: Duration::from_millis(20),
                        ..Default::default()
                    },
                    ..Default::default()
                },
            );
            pool.connect(&id).await.expect("connect");
            let status = pool.probe_health(&id).await.expect("probe");
            assert_eq!(status, crate::HealthStatus::Unhealthy);
            assert_eq!(pool.state(&id), Some(ConnectionState::Unhealthy));
            assert_eq!(pool.breaker(&id).map(|b| b.failure_count), Some(1));
            assert!(pool
                .dispatch(
                    &id,
                    &CallRequest {
                        method: "m".into(),
                        payload: "{}".into(),
                    },
                )
                .await
                .is_err());
        }

        #[tokio::test]
        async fn forward_preserves_full_jsonrpc_envelope_payload() {
            #[derive(Clone, Debug)]
            struct CaptureTransport {
                ready: bool,
                last: Arc<std::sync::Mutex<Option<serde_json::Value>>>,
            }

            #[async_trait]
            impl AsyncJsonRpcTransport for CaptureTransport {
                async fn send(
                    &mut self,
                    request: serde_json::Value,
                ) -> Result<serde_json::Value, PoolError> {
                    *self.last.lock().unwrap() = Some(request.clone());
                    Ok(
                        serde_json::json!({"jsonrpc":"2.0","id": request.get("id").cloned().unwrap_or(serde_json::Value::Null), "result":{"ok":true}}),
                    )
                }
                async fn is_ready(&self) -> bool {
                    self.ready
                }
            }

            let last = Arc::new(std::sync::Mutex::new(None));
            let mut session = JsonRpcAsyncSession::new(
                UpstreamId("u".into()),
                CaptureTransport {
                    ready: true,
                    last: last.clone(),
                },
            );
            let payload = r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"x"}}"#;
            let out = session
                .forward(&ForwardRequest {
                    method: "ignored-if-envelope-present".into(),
                    payload: payload.into(),
                })
                .await
                .expect("forward");
            assert!(out.payload.contains("ok"));
            let sent = last.lock().unwrap().clone().expect("captured");
            assert_eq!(sent.get("id"), Some(&serde_json::json!(7)));
            assert_eq!(sent.get("method"), Some(&serde_json::json!("tools/call")));
            assert_eq!(sent.get("params"), Some(&serde_json::json!({"name":"x"})));
        }

        #[tokio::test]
        async fn http_connection_forwards_headers_to_sender_hook() {
            #[derive(Clone, Default)]
            struct CaptureSender {
                last_headers: Arc<std::sync::Mutex<Option<BTreeMap<String, String>>>>,
            }
            #[async_trait]
            impl AsyncHttpSender for CaptureSender {
                async fn post_json(
                    &self,
                    _url: &str,
                    _body: serde_json::Value,
                ) -> Result<serde_json::Value, PoolError> {
                    Err(PoolError::DispatchFailed("unexpected post_json".into()))
                }
                async fn post_json_with_headers(
                    &self,
                    _url: &str,
                    headers: &BTreeMap<String, String>,
                    body: serde_json::Value,
                ) -> Result<serde_json::Value, PoolError> {
                    *self.last_headers.lock().unwrap() = Some(headers.clone());
                    Ok(
                        serde_json::json!({"jsonrpc":"2.0","id": body.get("id").cloned().unwrap_or(serde_json::Value::Null), "result":{"ok":true}}),
                    )
                }
            }

            let sender = CaptureSender::default();
            let mgr = HttpConnectionManager {
                sender: sender.clone(),
            };
            let mut headers = BTreeMap::new();
            headers.insert("Authorization".into(), "Bearer t".into());
            let server = UpstreamServerConfig::with_http("h", "http://example.test/rpc")
                .with_transport(TransportSpec::Http(crate::HttpTransportSpec {
                    url: "http://example.test/rpc".into(),
                    headers,
                    auth_profile: None,
                }));
            let mut pool = AsyncMcpPool::new(mgr, UpstreamConfig::default());
            pool.register(server.clone());
            pool.connect(&server.id).await.expect("connect");
            let out = pool
                .dispatch(
                    &server.id,
                    &CallRequest {
                        method: "ping".into(),
                        payload: "{}".into(),
                    },
                )
                .await
                .expect("dispatch");
            assert!(out.response.payload.contains("ok"));
            let captured = sender
                .last_headers
                .lock()
                .unwrap()
                .clone()
                .expect("headers");
            assert_eq!(
                captured.get("Authorization").map(String::as_str),
                Some("Bearer t")
            );
        }

        fn stdio_mock_server_script() -> String {
            r#"
while IFS= read -r line; do
  case "$line" in
    *'"method":"initialize"'*)
      printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05","capabilities":{"tools":{}},"serverInfo":{"name":"mock","version":"1"}}}'
      ;;
    *'"method":"tools/list"'*)
      printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"echo","description":"echo","inputSchema":{"type":"object"}}]}}'
      ;;
    *'"method":"tools/call"'*)
      printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"ok"}],"isError":false}}'
      ;;
    *)
      printf '%s\n' '{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"method not found"}}'
      ;;
  esac
done
"#
            .to_string()
        }

        #[tokio::test]
        async fn stdio_process_dispatches_initialize_tools_list_and_call() {
            let server = UpstreamServerConfig::with_stdio(
                "stdio-real",
                "sh",
                vec!["-c".into(), stdio_mock_server_script()],
            );
            let id = server.id.clone();
            let mut pool = AsyncMcpPool::new(StdioConnectionManager, UpstreamConfig::default());
            pool.register(server);
            pool.connect(&id).await.expect("connect stdio");

            let init = pool
                .dispatch(
                    &id,
                    &CallRequest {
                        method: "initialize".into(),
                        payload: r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}"#.into(),
                    },
                )
                .await
                .expect("initialize");
            assert!(init.response.payload.contains("protocolVersion"));

            let listed = pool
                .dispatch(
                    &id,
                    &CallRequest {
                        method: "tools/list".into(),
                        payload: r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#
                            .into(),
                    },
                )
                .await
                .expect("tools/list");
            assert!(listed.response.payload.contains("\"tools\""));
            assert!(listed.response.payload.contains("\"echo\""));

            let called = pool
                .dispatch(
                    &id,
                    &CallRequest {
                        method: "tools/call".into(),
                        payload: r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":{}}}"#.into(),
                    },
                )
                .await
                .expect("tools/call");
            assert!(called.response.payload.contains("\"content\""));

            pool.disconnect(&id).await.expect("disconnect");
            assert_eq!(pool.state(&id), Some(ConnectionState::Disconnected));
        }

        #[tokio::test]
        async fn stdio_dispatch_timeout_opens_circuit_fail_closed() {
            let server = UpstreamServerConfig::with_stdio(
                "stdio-hang",
                "sh",
                vec!["-c".into(), "sleep 5".into()],
            );
            let id = server.id.clone();
            let mut pool = AsyncMcpPool::new(StdioConnectionManager, UpstreamConfig::default());
            pool.register_with_server_config(
                server,
                UpstreamConfig {
                    timeouts: TimeoutPolicy {
                        call_timeout: Duration::from_millis(30),
                        ..Default::default()
                    },
                    breaker: CircuitBreakerPolicy {
                        failure_threshold: 1,
                        ..Default::default()
                    },
                    ..Default::default()
                },
            );
            pool.connect(&id).await.expect("connect");
            let err = pool
                .dispatch(
                    &id,
                    &CallRequest {
                        method: "tools/list".into(),
                        payload: r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#.into(),
                    },
                )
                .await
                .expect_err("timeout");
            assert!(
                matches!(err, PoolError::Timeout { waited } if waited == Duration::from_millis(30))
            );
            assert_eq!(pool.state(&id), Some(ConnectionState::Unhealthy));
            assert_eq!(pool.breaker(&id).map(|b| b.state), Some(CircuitState::Open));
        }

        #[tokio::test]
        async fn stdio_dispatch_retries_after_retryable_process_exit() {
            // Each spawned process serves one response then exits; reconnect+retry should recover.
            let script =
                r#"IFS= read -r line; echo '{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}'"#;
            let server = UpstreamServerConfig::with_stdio(
                "stdio-retry",
                "sh",
                vec!["-c".into(), script.into()],
            );
            let id = server.id.clone();
            let mut pool = AsyncMcpPool::new(StdioConnectionManager, UpstreamConfig::default());
            pool.register_with_server_config(
                server,
                UpstreamConfig {
                    retry: RetryPolicy {
                        max_retries: 1,
                        backoff: Duration::from_millis(1),
                    },
                    breaker: CircuitBreakerPolicy {
                        failure_threshold: 10,
                        ..Default::default()
                    },
                    ..Default::default()
                },
            );
            pool.connect(&id).await.expect("connect");

            let first = pool
                .dispatch(
                    &id,
                    &CallRequest {
                        method: "tools/list".into(),
                        payload: r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#.into(),
                    },
                )
                .await
                .expect("first dispatch");
            assert!(first.response.payload.contains("\"tools\""));

            // Process exited after first response; next dispatch should fail once then reconnect/retry.
            let second = pool
                .dispatch(
                    &id,
                    &CallRequest {
                        method: "tools/list".into(),
                        payload: r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#.into(),
                    },
                )
                .await
                .expect("dispatch after reconnect retry");
            assert!(second.response.payload.contains("\"tools\""));
            assert!(second.attempts >= 2);
        }

        #[cfg(feature = "rmcp")]
        mod rmcp_stdio {
            use super::super::rmcp_client::RmcpStdioConnectionManager;
            use super::*;
            use crate::{TransportKind, TransportSpec, UpstreamServerConfig};

            #[tokio::test]
            async fn rmcp_stdio_manager_rejects_non_stdio_transport_fail_closed() {
                let server = UpstreamServerConfig::with_http("h", "http://example.test/mcp");
                let mut mgr = RmcpStdioConnectionManager;
                match AsyncConnectionManager::connect(&mut mgr, &server).await {
                    Ok(_) => panic!("must reject non-stdio transport"),
                    Err(err) => assert!(
                        matches!(err, PoolError::Unavailable(ref msg) if msg.contains("requires stdio")),
                        "unexpected err: {err:?}"
                    ),
                }
                assert_eq!(server.transport, TransportKind::Http);
            }

            #[tokio::test]
            async fn rmcp_stdio_manager_rejects_missing_stdio_spec_fail_closed() {
                let server =
                    UpstreamServerConfig::new("bad", "noop").with_transport(TransportSpec::Other {
                        kind: TransportKind::Stdio,
                        endpoint: "noop".into(),
                    });
                let mut mgr = RmcpStdioConnectionManager;
                match AsyncConnectionManager::connect(&mut mgr, &server).await {
                    Ok(_) => panic!("must reject missing stdio spec"),
                    Err(err) => assert!(
                        matches!(err, PoolError::Unavailable(ref msg) if msg.contains("stdio transport spec required")),
                        "unexpected err: {err:?}"
                    ),
                }
            }

            #[tokio::test]
            async fn rmcp_stdio_manager_fails_closed_on_handshake_failure() {
                // Process exits immediately -> rmcp client initialize handshake must fail closed.
                let server = UpstreamServerConfig::with_stdio(
                    "bad",
                    "sh",
                    vec!["-c".into(), "exit 0".into()],
                );
                let mut mgr = RmcpStdioConnectionManager;
                match AsyncConnectionManager::connect(&mut mgr, &server).await {
                    Ok(_) => panic!("handshake should fail"),
                    Err(err) => assert!(
                        matches!(
                            err,
                            PoolError::Unavailable(ref msg)
                                if msg.contains("rmcp client handshake failed")
                                    || msg.contains("spawn")
                                    || msg.contains("missing")
                        ),
                        "unexpected err: {err:?}"
                    ),
                }
            }

            fn rmcp_mock_mcp_server_script() -> String {
                concat!(
                    "import sys,json\n",
                    "for line in sys.stdin:\n",
                    "  try:\n",
                    "    m=json.loads(line)\n",
                    "  except Exception:\n",
                    "    continue\n",
                    "  method=m.get('method'); id=m.get('id')\n",
                    "  if method=='initialize':\n",
                    "    print(json.dumps({'jsonrpc':'2.0','id':id,'result':{'protocolVersion':'2024-11-05','capabilities':{'tools':{}},'serverInfo':{'name':'mock','version':'1'}}}), flush=True)\n",
                    "  elif method=='notifications/initialized':\n",
                    "    pass\n",
                    "  elif method=='tools/list':\n",
                    "    print(json.dumps({'jsonrpc':'2.0','id':id,'result':{'tools':[{'name':'demo.echo','description':'echo','inputSchema':{'type':'object','properties':{'text':{'type':'string'}}}}]}}), flush=True)\n",
                    "  elif method=='tools/call':\n",
                    "    p=m.get('params') or {}\n",
                    "    name=p.get('name'); args=p.get('arguments')\n",
                    "    print(json.dumps({'jsonrpc':'2.0','id':id,'result':{'content':[{'type':'text','text':json.dumps({'name':name,'arguments':args})}],'isError':False}}), flush=True)\n",
                    "  elif method=='ping':\n",
                    "    print(json.dumps({'jsonrpc':'2.0','id':id,'result':{}}), flush=True)\n",
                    "  elif id is not None:\n",
                    "    print(json.dumps({'jsonrpc':'2.0','id':id,'error':{'code':-32601,'message':'method not found'}}), flush=True)\n",
                )
                .to_string()
            }

            #[tokio::test]
            async fn rmcp_stdio_pool_dispatches_initialize_tools_list_and_call() {
                let server = UpstreamServerConfig::with_stdio(
                    "rmcp-s1",
                    "python3",
                    vec!["-u".into(), "-c".into(), rmcp_mock_mcp_server_script()],
                );
                let id = server.id.clone();
                let mut pool =
                    AsyncMcpPool::new(RmcpStdioConnectionManager, UpstreamConfig::default());
                pool.register(server);
                pool.connect(&id).await.expect("rmcp connect");

                let listed = pool
                    .dispatch(
                        &id,
                        &CallRequest {
                            method: "tools/list".into(),
                            payload:
                                r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}"#
                                    .into(),
                        },
                    )
                    .await
                    .expect("tools/list");
                assert!(
                    listed.response.payload.contains("demo.echo"),
                    "{}",
                    listed.response.payload
                );

                let called = pool
                    .dispatch(
                        &id,
                        &CallRequest {
                            method: "tools/call".into(),
                            payload: r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"demo.echo","arguments":{"text":"hi"}}}"#.into(),
                        },
                    )
                    .await
                    .expect("tools/call");
                assert!(
                    called.response.payload.contains("demo.echo"),
                    "{}",
                    called.response.payload
                );
                assert!(
                    called.response.payload.contains("hi"),
                    "{}",
                    called.response.payload
                );

                let init = pool
                    .dispatch(
                        &id,
                        &CallRequest {
                            method: "initialize".into(),
                            payload:
                                r#"{"jsonrpc":"2.0","id":3,"method":"initialize","params":{}}"#
                                    .into(),
                        },
                    )
                    .await
                    .expect("initialize forward compat");
                assert!(init.response.payload.contains("protocolVersion"));

                pool.disconnect(&id).await.expect("disconnect");
                assert_eq!(pool.state(&id), Some(ConnectionState::Disconnected));
            }
        }
    }
}

#[cfg(feature = "tokio-runtime")]
pub use imp::*;
