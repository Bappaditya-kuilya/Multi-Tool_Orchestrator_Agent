//! Async runtime/client abstractions for upstream MCP servers.
//!
//! Provides tokio-based stdio subprocess and HTTP client/session primitives,
//! plus async pool/dispatch helpers layered over the core policies in `lib`.

#[cfg(feature = "tokio-runtime")]
mod imp {
    use crate::{
        AsyncConnectionManager, AsyncMcpClientSession, CallRequest, CircuitBreaker,
        ConnectionState, DispatchOutcome, ForwardRequest, ForwardResponse, HealthStatus, PoolError,
        TransportKind, TransportSpec, UpstreamConfig, UpstreamId, UpstreamServerConfig,
    };
    use async_trait::async_trait;
    use serde_json::Value;
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
        upstream: UpstreamId,
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
                upstream: server.id.clone(),
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
    }

    pub struct HttpRpcClient<S: AsyncHttpSender> {
        upstream: UpstreamId,
        url: String,
        sender: S,
        ready: bool,
    }

    impl<S: AsyncHttpSender> HttpRpcClient<S> {
        pub fn new(upstream: UpstreamId, url: String, sender: S) -> Self {
            Self {
                upstream,
                url,
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
            self.sender.post_json(&self.url, request).await
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
        upstream: UpstreamId,
        transport: Mutex<T>,
    }

    impl<T: AsyncJsonRpcTransport> JsonRpcAsyncSession<T> {
        pub fn new(upstream: UpstreamId, transport: T) -> Self {
            Self {
                upstream,
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
            let req = serde_json::json!({
                "jsonrpc":"2.0",
                "method": request.method,
                "params": payload_val,
            });
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
            let url = match &server.transport_spec {
                TransportSpec::Http(h) => h.url.clone(),
                _ => server.endpoint.clone(),
            };
            let client = HttpRpcClient::new(server.id.clone(), url, self.sender.clone());
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
            }
        }
        fn max_leases(&self) -> usize {
            self.config.effective_max_leases()
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
                    slot.breaker.record_success();
                    Ok(())
                }
                Err(e) => {
                    if let Some(slot) = self.upstreams.get_mut(upstream) {
                        slot.state = ConnectionState::Unhealthy;
                        slot.healthy = false;
                        slot.breaker.record_failure();
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
            let session = {
                let slot = self
                    .upstreams
                    .get_mut(upstream)
                    .ok_or_else(|| PoolError::UnknownUpstream(upstream.0.clone()))?;
                slot.session.clone()
            };
            let status = match session {
                Some(sess) => {
                    let mut s = sess.lock().await;
                    match s.ping().await {
                        Ok(_) if s.is_ready().await => HealthStatus::Healthy,
                        _ => HealthStatus::Unhealthy,
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
                    slot.breaker.record_success();
                }
                HealthStatus::Unhealthy => {
                    slot.healthy = false;
                    slot.state = ConnectionState::Unhealthy;
                    slot.breaker.record_failure();
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
            if !slot.breaker.allow_request() {
                return Err(PoolError::CircuitOpen(
                    "requests blocked by circuit breaker".into(),
                ));
            }
            if !matches!(slot.state, ConnectionState::Connected) || !slot.healthy {
                return Err(PoolError::Unavailable(format!("state {:?}", slot.state)));
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
                .ok_or_else(|| PoolError::Unavailable("no session".into()))?;
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
                slot.breaker.record_failure();
                slot.healthy = false;
                slot.state = ConnectionState::Unhealthy;
            }
        }
        fn mark_success(&mut self, upstream: &UpstreamId) {
            if let Some(slot) = self.upstreams.get_mut(upstream) {
                slot.breaker.record_success();
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
            let (max_retries, call_timeout, backoff) = {
                let slot = self
                    .upstreams
                    .get(upstream)
                    .ok_or_else(|| PoolError::UnknownUpstream(upstream.0.clone()))?;
                (
                    slot.config.effective_max_retries(),
                    slot.config.effective_call_timeout(),
                    slot.config.effective_retry_backoff(),
                )
            };
            let mut attempts = 0u32;
            loop {
                attempts = attempts.saturating_add(1);
                let session = match self.acquire(upstream).await {
                    Ok(s) => s,
                    Err(e) if e.is_retryable() && attempts <= max_retries => {
                        if !backoff.is_zero() {
                            tokio::time::sleep(backoff.saturating_mul(attempts)).await;
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
                            if !backoff.is_zero() {
                                tokio::time::sleep(backoff.saturating_mul(attempts)).await;
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
}

#[cfg(feature = "tokio-runtime")]
pub use imp::*;
