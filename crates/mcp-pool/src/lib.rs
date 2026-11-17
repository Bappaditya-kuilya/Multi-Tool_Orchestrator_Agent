//! Upstream MCP client pool with per-upstream server config, connection
//! lifecycle, request/response forwarding abstractions, health/circuit/retry/
//! timeout policies, and concurrency cap placeholders.
//!
//! Prepares for `rmcp` client integration via transport/config/session traits.
//!
//! Sync APIs remain the default skeleton path; async-ready traits/hooks are
//! provided for future tokio + `rmcp` wiring without forcing runtime deps now.

use async_trait::async_trait;
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::time::Duration;

#[cfg(feature = "tokio-runtime")]
pub mod runtime;

/// Identifier for an upstream MCP server/connection target.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UpstreamId(pub String);

/// Upstream transport kind.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum TransportKind {
    #[default]
    Stdio,
    Http,
    WebSocket,
    Other(String),
}

/// Stdio transport parameters (for future `rmcp` child-process transports).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StdioTransportSpec {
    pub program: String,
    pub args: Vec<String>,
    pub env: BTreeMap<String, String>,
    pub cwd: Option<String>,
}

/// HTTP/SSE transport parameters (for future `rmcp` HTTP transports).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HttpTransportSpec {
    pub url: String,
    pub headers: BTreeMap<String, String>,
    /// Optional bearer token/profile reference resolved by caller.
    pub auth_profile: Option<String>,
}

/// Transport abstraction for upstream MCP connectivity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportSpec {
    Stdio(StdioTransportSpec),
    Http(HttpTransportSpec),
    /// Placeholder for transports not yet modeled explicitly.
    Other {
        kind: TransportKind,
        endpoint: String,
    },
}

impl TransportSpec {
    pub fn kind(&self) -> TransportKind {
        match self {
            TransportSpec::Stdio(_) => TransportKind::Stdio,
            TransportSpec::Http(_) => TransportKind::Http,
            TransportSpec::Other { kind, .. } => kind.clone(),
        }
    }

    pub fn endpoint_hint(&self) -> String {
        match self {
            TransportSpec::Stdio(s) => s.program.clone(),
            TransportSpec::Http(h) => h.url.clone(),
            TransportSpec::Other { endpoint, .. } => endpoint.clone(),
        }
    }
}

/// Upstream MCP server configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamServerConfig {
    pub id: UpstreamId,
    pub endpoint: String,
    pub transport: TransportKind,
    pub transport_spec: TransportSpec,
    /// Placeholder for auth material wiring (env ref, token id, etc).
    pub auth_profile: Option<String>,
}

impl UpstreamServerConfig {
    pub fn new(id: impl Into<String>, endpoint: impl Into<String>) -> Self {
        let id = UpstreamId(id.into());
        let endpoint = endpoint.into();
        Self {
            id,
            endpoint: endpoint.clone(),
            transport: TransportKind::Stdio,
            transport_spec: TransportSpec::Other {
                kind: TransportKind::Stdio,
                endpoint,
            },
            auth_profile: None,
        }
    }

    pub fn with_stdio(
        id: impl Into<String>,
        program: impl Into<String>,
        args: Vec<String>,
    ) -> Self {
        let id = UpstreamId(id.into());
        let program = program.into();
        Self {
            id,
            endpoint: program.clone(),
            transport: TransportKind::Stdio,
            transport_spec: TransportSpec::Stdio(StdioTransportSpec {
                program,
                args,
                env: BTreeMap::new(),
                cwd: None,
            }),
            auth_profile: None,
        }
    }

    pub fn with_http(id: impl Into<String>, url: impl Into<String>) -> Self {
        let id = UpstreamId(id.into());
        let url = url.into();
        Self {
            id,
            endpoint: url.clone(),
            transport: TransportKind::Http,
            transport_spec: TransportSpec::Http(HttpTransportSpec {
                url,
                headers: BTreeMap::new(),
                auth_profile: None,
            }),
            auth_profile: None,
        }
    }

    pub fn with_transport(mut self, transport_spec: TransportSpec) -> Self {
        self.transport = transport_spec.kind();
        self.endpoint = transport_spec.endpoint_hint();
        self.transport_spec = transport_spec;
        self
    }

    pub fn with_auth_profile(mut self, profile: impl Into<String>) -> Self {
        let profile = profile.into();
        self.auth_profile = Some(profile.clone());
        if let TransportSpec::Http(ref mut h) = self.transport_spec {
            h.auth_profile = Some(profile);
        }
        self
    }

    /// Build from a loose config map (integration hook for mcp-front/config loaders).
    /// Recognized keys: `transport` (stdio|http), `program`/`command`, `args` (csv),
    /// `url`/`endpoint`, `cwd`, `auth_profile`, `header.<k>`, `env.<k>`.
    pub fn from_config_map(
        id: impl Into<String>,
        cfg: &BTreeMap<String, String>,
    ) -> Result<Self, PoolError> {
        let id_s = id.into();
        let transport = cfg
            .get("transport")
            .map(|s| s.to_ascii_lowercase())
            .unwrap_or_else(|| {
                if cfg.contains_key("url") || cfg.contains_key("http_url") {
                    "http".into()
                } else {
                    "stdio".into()
                }
            });
        let mut server = match transport.as_str() {
            "http" | "https" | "sse" => {
                let url = cfg
                    .get("url")
                    .or_else(|| cfg.get("http_url"))
                    .or_else(|| cfg.get("endpoint"))
                    .cloned()
                    .ok_or_else(|| {
                        PoolError::DispatchFailed(format!("missing http url for upstream {id_s}"))
                    })?;
                let mut srv = Self::with_http(id_s.clone(), url);
                if let TransportSpec::Http(ref mut h) = srv.transport_spec {
                    for (k, v) in cfg {
                        if let Some(hk) = k.strip_prefix("header.") {
                            h.headers.insert(hk.to_string(), v.clone());
                        }
                    }
                }
                srv
            }
            _ => {
                let program = cfg
                    .get("program")
                    .or_else(|| cfg.get("command"))
                    .or_else(|| cfg.get("endpoint"))
                    .cloned()
                    .ok_or_else(|| {
                        PoolError::DispatchFailed(format!(
                            "missing stdio program/command for upstream {id_s}"
                        ))
                    })?;
                let args = cfg
                    .get("args")
                    .map(|s| {
                        s.split(',')
                            .map(|a| a.trim().to_string())
                            .filter(|a| !a.is_empty())
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                let mut srv = Self::with_stdio(id_s.clone(), program, args);
                if let TransportSpec::Stdio(ref mut s) = srv.transport_spec {
                    s.cwd = cfg.get("cwd").cloned();
                    for (k, v) in cfg {
                        if let Some(ek) = k.strip_prefix("env.") {
                            s.env.insert(ek.to_string(), v.clone());
                        }
                    }
                }
                srv
            }
        };
        if let Some(profile) = cfg.get("auth_profile") {
            server = server.with_auth_profile(profile.clone());
        }
        server.validate_basic()?;
        Ok(server)
    }

    pub fn validate_basic(&self) -> Result<(), PoolError> {
        if self.id.0.trim().is_empty() {
            return Err(PoolError::DispatchFailed(
                "upstream id must be non-empty".into(),
            ));
        }
        match &self.transport_spec {
            TransportSpec::Stdio(s) if s.program.trim().is_empty() => Err(
                PoolError::DispatchFailed("stdio program must be non-empty".into()),
            ),
            TransportSpec::Http(h) if h.url.trim().is_empty() => Err(PoolError::DispatchFailed(
                "http url must be non-empty".into(),
            )),
            _ => Ok(()),
        }
    }
}

/// Placeholder pooled connection/session handle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientConnection {
    pub upstream: UpstreamId,
    pub endpoint: String,
    pub transport: TransportKind,
    pub healthy: bool,
}

/// A logical call/request to an upstream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallRequest {
    pub method: String,
    pub payload: String,
}

/// Successful call response placeholder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallResponse {
    pub payload: String,
}

/// Request/response forwarding aliases (clearer boundary naming).
pub type ForwardRequest = CallRequest;
pub type ForwardResponse = CallResponse;

/// Dispatch/call forwarding interface.
///
/// TODO(rmcp): replace with real MCP client call execution.
pub trait Dispatcher: Send {
    fn call(
        &mut self,
        upstream: &UpstreamId,
        request: &CallRequest,
    ) -> Result<CallResponse, PoolError>;
}

/// Explicit request/response forwarding abstraction.
pub trait RequestForwarder: Send {
    fn forward(
        &mut self,
        upstream: &UpstreamId,
        request: &ForwardRequest,
    ) -> Result<ForwardResponse, PoolError>;
}

impl<T: Dispatcher + ?Sized> RequestForwarder for T {
    fn forward(
        &mut self,
        upstream: &UpstreamId,
        request: &ForwardRequest,
    ) -> Result<ForwardResponse, PoolError> {
        self.call(upstream, request)
    }
}

/// Async-ready dispatch seam for tokio/`rmcp` integration.
#[async_trait]
pub trait AsyncDispatcher: Send {
    async fn call(
        &mut self,
        upstream: &UpstreamId,
        request: &CallRequest,
    ) -> Result<CallResponse, PoolError>;
}

#[async_trait]
pub trait AsyncRequestForwarder: Send {
    async fn forward(
        &mut self,
        upstream: &UpstreamId,
        request: &ForwardRequest,
    ) -> Result<ForwardResponse, PoolError>;
}

#[async_trait]
impl<T: AsyncDispatcher + ?Sized> AsyncRequestForwarder for T {
    async fn forward(
        &mut self,
        upstream: &UpstreamId,
        request: &ForwardRequest,
    ) -> Result<ForwardResponse, PoolError> {
        self.call(upstream, request).await
    }
}

/// Session abstraction for a real upstream MCP client (future `rmcp` adapter target).
pub trait McpClientSession: Send {
    fn is_ready(&self) -> bool;
    fn ping(&mut self) -> Result<(), PoolError> {
        if self.is_ready() {
            Ok(())
        } else {
            Err(PoolError::Unavailable("session not ready".into()))
        }
    }
    fn forward(&mut self, request: &ForwardRequest) -> Result<ForwardResponse, PoolError>;
}

/// Async-ready session seam for `rmcp` client wrappers.
#[async_trait]
pub trait AsyncMcpClientSession: Send {
    async fn is_ready(&self) -> bool;
    async fn ping(&mut self) -> Result<(), PoolError> {
        if self.is_ready().await {
            Ok(())
        } else {
            Err(PoolError::Unavailable("session not ready".into()))
        }
    }
    async fn forward(&mut self, request: &ForwardRequest) -> Result<ForwardResponse, PoolError>;
}

/// Connection lifecycle/management abstraction for upstream sessions.
pub trait ConnectionManager: Send {
    type Session: McpClientSession;

    fn connect(&mut self, server: &UpstreamServerConfig) -> Result<Self::Session, PoolError>;
    fn disconnect(&mut self, _session: Self::Session) -> Result<(), PoolError> {
        Ok(())
    }
    fn reconnect(
        &mut self,
        server: &UpstreamServerConfig,
        _session: Option<Self::Session>,
    ) -> Result<Self::Session, PoolError> {
        self.connect(server)
    }
}

/// Async-ready lifecycle seam for `rmcp` transport/session factories.
#[async_trait]
pub trait AsyncConnectionManager: Send {
    type Session: AsyncMcpClientSession;

    async fn connect(&mut self, server: &UpstreamServerConfig) -> Result<Self::Session, PoolError>;
    async fn disconnect(&mut self, _session: Self::Session) -> Result<(), PoolError> {
        Ok(())
    }
    async fn reconnect(
        &mut self,
        server: &UpstreamServerConfig,
        _session: Option<Self::Session>,
    ) -> Result<Self::Session, PoolError> {
        self.connect(server).await
    }
}

/// Connection lifecycle state for an upstream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    Connected,
    Unhealthy,
}

/// Lease returned on successful acquire; must be released to free capacity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PooledLease {
    pub upstream: UpstreamId,
    lease_id: u64,
}

impl PooledLease {
    pub fn lease_id(&self) -> u64 {
        self.lease_id
    }

    pub fn upstream(&self) -> &UpstreamId {
        &self.upstream
    }
}

/// Circuit breaker state for an upstream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    Closed,
    Open,
    HalfOpen,
}

/// Circuit breaker policy parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CircuitBreakerPolicy {
    pub failure_threshold: u32,
    pub half_open_success_threshold: u32,
    /// Placeholder for future timer-based open->half-open transition.
    pub open_cooldown: Duration,
}

impl Default for CircuitBreakerPolicy {
    fn default() -> Self {
        Self {
            failure_threshold: 3,
            half_open_success_threshold: 1,
            open_cooldown: Duration::from_secs(0),
        }
    }
}

/// Retry policy (placeholder; runtime backoff/timers wired later).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    pub max_retries: u32,
    pub backoff: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_retries: 0,
            backoff: Duration::from_secs(0),
        }
    }
}

/// Timeout policy (placeholder; runtime timers wired later).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeoutPolicy {
    pub acquire_timeout: Duration,
    pub call_timeout: Duration,
}

impl Default for TimeoutPolicy {
    fn default() -> Self {
        Self {
            acquire_timeout: Duration::from_secs(0),
            call_timeout: Duration::from_secs(0),
        }
    }
}

/// Concurrency cap placeholders.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConcurrencyPolicy {
    pub max_leases: usize,
    /// Placeholder for future in-flight request cap separate from leases.
    pub max_in_flight: usize,
}

impl Default for ConcurrencyPolicy {
    fn default() -> Self {
        Self {
            max_leases: 1,
            max_in_flight: 1,
        }
    }
}

/// Circuit breaker state machine with policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CircuitBreaker {
    pub state: CircuitState,
    pub failure_count: u32,
    pub success_count: u32,
    pub policy: CircuitBreakerPolicy,
}

impl CircuitBreaker {
    pub fn new(failure_threshold: u32) -> Self {
        Self::with_policy(CircuitBreakerPolicy {
            failure_threshold: failure_threshold.max(1),
            ..CircuitBreakerPolicy::default()
        })
    }

    pub fn with_policy(policy: CircuitBreakerPolicy) -> Self {
        Self {
            state: CircuitState::Closed,
            failure_count: 0,
            success_count: 0,
            policy: CircuitBreakerPolicy {
                failure_threshold: policy.failure_threshold.max(1),
                half_open_success_threshold: policy.half_open_success_threshold.max(1),
                open_cooldown: policy.open_cooldown,
            },
        }
    }

    /// TODO(rmcp/runtime): call when cooldown elapses to allow a probe request.
    pub fn enter_half_open(&mut self) {
        if self.state == CircuitState::Open {
            self.state = CircuitState::HalfOpen;
            self.success_count = 0;
        }
    }

    /// Placeholder cooldown hook: caller decides when elapsed; if cooldown is zero treat as immediately probeable.
    pub fn can_probe_after(&self, open_for: Duration) -> bool {
        self.state == CircuitState::Open && open_for >= self.policy.open_cooldown
    }

    pub fn allow_request(&self) -> bool {
        match self.state {
            CircuitState::Closed | CircuitState::HalfOpen => true,
            CircuitState::Open => false,
        }
    }

    pub fn record_success(&mut self) {
        match self.state {
            CircuitState::HalfOpen => {
                self.success_count = self.success_count.saturating_add(1);
                if self.success_count >= self.policy.half_open_success_threshold {
                    self.state = CircuitState::Closed;
                    self.failure_count = 0;
                    self.success_count = 0;
                }
            }
            CircuitState::Closed | CircuitState::Open => {
                self.failure_count = 0;
                self.success_count = 0;
                self.state = CircuitState::Closed;
            }
        }
    }

    pub fn record_failure(&mut self) {
        match self.state {
            CircuitState::HalfOpen => {
                self.state = CircuitState::Open;
                self.failure_count = self.policy.failure_threshold;
                self.success_count = 0;
            }
            CircuitState::Closed | CircuitState::Open => {
                self.failure_count = self.failure_count.saturating_add(1);
                if self.failure_count >= self.policy.failure_threshold {
                    self.state = CircuitState::Open;
                }
            }
        }
    }
}

/// Health status reported for an upstream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthStatus {
    Healthy,
    Unhealthy,
}

/// Health probe abstraction.
///
/// TODO(rmcp): implement via MCP initialize/ping/capability checks.
pub trait HealthCheck {
    fn check(&self, conn: &ClientConnection) -> HealthStatus;
}

/// Default placeholder health check.
#[derive(Debug, Default, Clone, Copy)]
pub struct PlaceholderHealthCheck;

impl HealthCheck for PlaceholderHealthCheck {
    fn check(&self, conn: &ClientConnection) -> HealthStatus {
        if conn.healthy {
            HealthStatus::Healthy
        } else {
            HealthStatus::Unhealthy
        }
    }
}

/// Per-upstream pool/call configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UpstreamConfig {
    pub max_leases: usize,
    pub acquire_timeout: Duration,
    pub call_timeout: Duration,
    pub max_retries: u32,
    pub retry_backoff: Duration,
    pub breaker: CircuitBreakerPolicy,
    pub retry: RetryPolicy,
    pub timeouts: TimeoutPolicy,
    pub concurrency: ConcurrencyPolicy,
}

impl Default for UpstreamConfig {
    fn default() -> Self {
        Self {
            max_leases: 1,
            acquire_timeout: Duration::from_secs(0),
            call_timeout: Duration::from_secs(0),
            max_retries: 0,
            retry_backoff: Duration::from_secs(0),
            breaker: CircuitBreakerPolicy::default(),
            retry: RetryPolicy::default(),
            timeouts: TimeoutPolicy::default(),
            concurrency: ConcurrencyPolicy::default(),
        }
    }
}

impl UpstreamConfig {
    /// Effective retry count (prefers explicit policy).
    pub fn effective_max_retries(&self) -> u32 {
        if self.retry.max_retries > 0 || self.max_retries == 0 {
            self.retry.max_retries
        } else {
            self.max_retries
        }
    }

    pub fn effective_retry_backoff(&self) -> Duration {
        if self.retry.backoff > Duration::ZERO || self.retry_backoff.is_zero() {
            self.retry.backoff
        } else {
            self.retry_backoff
        }
    }

    pub fn effective_acquire_timeout(&self) -> Duration {
        if self.timeouts.acquire_timeout > Duration::ZERO || self.acquire_timeout.is_zero() {
            self.timeouts.acquire_timeout
        } else {
            self.acquire_timeout
        }
    }

    pub fn effective_call_timeout(&self) -> Duration {
        if self.timeouts.call_timeout > Duration::ZERO || self.call_timeout.is_zero() {
            self.timeouts.call_timeout
        } else {
            self.call_timeout
        }
    }

    pub fn effective_max_leases(&self) -> usize {
        self.max_leases.max(self.concurrency.max_leases).max(1)
    }

    /// Simple linear backoff schedule hook for runtime retry loops.
    pub fn retry_delay_for_attempt(&self, attempt: u32) -> Duration {
        let base = self.effective_retry_backoff();
        if base.is_zero() || attempt <= 1 {
            base
        } else {
            base.saturating_mul(attempt.saturating_sub(1))
        }
    }
}

/// Backward-compatible alias for earlier single-upstream config name.
pub type PoolConfig = UpstreamConfig;

/// Pool and dispatch errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PoolError {
    UnknownUpstream(String),
    InvalidState {
        upstream: String,
        state: ConnectionState,
    },
    Unavailable(String),
    CircuitOpen(String),
    Timeout {
        waited: Duration,
    },
    Exhausted {
        max_leases: usize,
    },
    InvalidLease(u64),
    DispatchFailed(String),
}

impl PoolError {
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            PoolError::Unavailable(_) | PoolError::Timeout { .. } | PoolError::DispatchFailed(_)
        )
    }
}

impl fmt::Display for PoolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PoolError::UnknownUpstream(id) => write!(f, "unknown upstream: {id}"),
            PoolError::InvalidState { upstream, state } => {
                write!(f, "invalid state for {upstream}: {state:?}")
            }
            PoolError::Unavailable(msg) => write!(f, "upstream unavailable: {msg}"),
            PoolError::CircuitOpen(msg) => write!(f, "circuit open: {msg}"),
            PoolError::Timeout { waited } => write!(f, "timeout after {waited:?}"),
            PoolError::Exhausted { max_leases } => {
                write!(f, "pool exhausted (max_leases={max_leases})")
            }
            PoolError::InvalidLease(id) => write!(f, "invalid lease: {id}"),
            PoolError::DispatchFailed(msg) => write!(f, "dispatch failed: {msg}"),
        }
    }
}

impl std::error::Error for PoolError {}

/// Placeholder dispatcher that always succeeds with an echo payload.
#[derive(Debug, Default, Clone, Copy)]
pub struct PlaceholderDispatcher;

impl Dispatcher for PlaceholderDispatcher {
    fn call(
        &mut self,
        _upstream: &UpstreamId,
        request: &CallRequest,
    ) -> Result<CallResponse, PoolError> {
        Ok(CallResponse {
            payload: format!("ok:{}", request.method),
        })
    }
}

/// Adapts a live `McpClientSession` into the pool's `Dispatcher` interface.
/// This is the seam for a future `rmcp` client/session wrapper.
#[derive(Debug)]
pub struct SessionDispatcher<S> {
    session: S,
}

impl<S> SessionDispatcher<S> {
    pub fn new(session: S) -> Self {
        Self { session }
    }

    pub fn session(&self) -> &S {
        &self.session
    }

    pub fn session_mut(&mut self) -> &mut S {
        &mut self.session
    }

    pub fn into_inner(self) -> S {
        self.session
    }
}

impl<S: McpClientSession> Dispatcher for SessionDispatcher<S> {
    fn call(
        &mut self,
        _upstream: &UpstreamId,
        request: &CallRequest,
    ) -> Result<CallResponse, PoolError> {
        self.session.forward(request)
    }
}

/// Placeholder connection manager for std-only/test wiring.
/// Replace with an `rmcp` transport/session factory in integration.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopConnectionManager;

impl ConnectionManager for NoopConnectionManager {
    type Session = PlaceholderSession;

    fn connect(&mut self, server: &UpstreamServerConfig) -> Result<Self::Session, PoolError> {
        Ok(PlaceholderSession::ready(server.id.clone()))
    }
}

/// Minimal in-memory session used for tests and as an integration placeholder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlaceholderSession {
    pub upstream: UpstreamId,
    ready: bool,
    fail_next: bool,
}

impl PlaceholderSession {
    pub fn ready(upstream: UpstreamId) -> Self {
        Self {
            upstream,
            ready: true,
            fail_next: false,
        }
    }

    pub fn disconnected(upstream: UpstreamId) -> Self {
        Self {
            upstream,
            ready: false,
            fail_next: false,
        }
    }

    pub fn fail_next(mut self) -> Self {
        self.fail_next = true;
        self
    }
}

impl McpClientSession for PlaceholderSession {
    fn is_ready(&self) -> bool {
        self.ready
    }

    fn ping(&mut self) -> Result<(), PoolError> {
        if self.ready {
            Ok(())
        } else {
            Err(PoolError::Unavailable(format!(
                "session not ready for {}",
                self.upstream.0
            )))
        }
    }

    fn forward(&mut self, request: &ForwardRequest) -> Result<ForwardResponse, PoolError> {
        if !self.ready {
            return Err(PoolError::Unavailable("session not connected".into()));
        }
        if self.fail_next {
            self.fail_next = false;
            self.ready = false;
            return Err(PoolError::DispatchFailed("session forward failed".into()));
        }
        Ok(ForwardResponse {
            payload: format!("session:{}:{}", self.upstream.0, request.method),
        })
    }
}

/// Dispatch outcome with retry/timeout accounting placeholders.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DispatchOutcome {
    pub response: CallResponse,
    pub attempts: u32,
}

/// Integration hook for mcp-front: minimal dispatch request/response view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrontDispatchRequest {
    pub upstream: UpstreamId,
    pub method: String,
    pub payload: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrontDispatchResponse {
    pub payload: String,
    pub attempts: u32,
}

/// Thin adapter that forwards mcp-front-shaped requests through `McpPool`.
#[derive(Debug)]
pub struct PoolFrontBridge<'a, H, D> {
    pub pool: &'a mut McpPool<H>,
    pub dispatcher: &'a mut D,
}

impl<'a, H: HealthCheck, D: Dispatcher> PoolFrontBridge<'a, H, D> {
    pub fn new(pool: &'a mut McpPool<H>, dispatcher: &'a mut D) -> Self {
        Self { pool, dispatcher }
    }

    pub fn dispatch(
        &mut self,
        req: FrontDispatchRequest,
    ) -> Result<FrontDispatchResponse, PoolError> {
        self.pool.ensure_connected(&req.upstream)?;
        let out = self.pool.dispatch(
            &req.upstream,
            &CallRequest {
                method: req.method,
                payload: req.payload,
            },
            self.dispatcher,
        )?;
        Ok(FrontDispatchResponse {
            payload: out.response.payload,
            attempts: out.attempts,
        })
    }
}

/// Convenience: choose an upstream id for a tool/method (hook for front routing integration).
pub fn select_upstream_for_tool<'a, I>(upstreams: I, _tool_name: &str) -> Option<UpstreamId>
where
    I: IntoIterator<Item = &'a UpstreamId>,
{
    // shortcut: deterministic first upstream; replace with capability/affinity routing.
    upstreams.into_iter().next().cloned()
}

#[derive(Debug, Clone)]
struct UpstreamSlot {
    server: UpstreamServerConfig,
    config: UpstreamConfig,
    state: ConnectionState,
    connection: ClientConnection,
    breaker: CircuitBreaker,
    active_leases: usize,
    next_lease_id: u64,
}

impl UpstreamSlot {
    fn new(server: UpstreamServerConfig, config: UpstreamConfig) -> Self {
        let connection = ClientConnection {
            upstream: server.id.clone(),
            endpoint: server.endpoint.clone(),
            transport: server.transport.clone(),
            healthy: false,
        };
        Self {
            server,
            breaker: CircuitBreaker::with_policy(config.breaker),
            config,
            state: ConnectionState::Disconnected,
            connection,
            active_leases: 0,
            next_lease_id: 1,
        }
    }

    fn max_leases(&self) -> usize {
        self.config.effective_max_leases()
    }
}

/// Multi-upstream MCP client pool.
#[derive(Debug, Clone)]
pub struct McpPool<H = PlaceholderHealthCheck> {
    upstreams: HashMap<UpstreamId, UpstreamSlot>,
    health_check: H,
    default_config: UpstreamConfig,
}

impl Default for McpPool<PlaceholderHealthCheck> {
    fn default() -> Self {
        Self::new(PlaceholderHealthCheck, UpstreamConfig::default())
    }
}

impl<H> McpPool<H> {
    pub fn new(health_check: H, default_config: UpstreamConfig) -> Self {
        Self {
            upstreams: HashMap::new(),
            health_check,
            default_config,
        }
    }

    /// Register or replace an upstream using the pool's default config.
    /// shortcut: starts connected for std-only skeleton compatibility.
    pub fn register(&mut self, upstream: UpstreamId) {
        self.register_with_config(upstream, self.default_config);
    }

    /// Register or replace an upstream with per-upstream config.
    pub fn register_with_config(&mut self, upstream: UpstreamId, config: UpstreamConfig) {
        let server = UpstreamServerConfig::new(upstream.0.clone(), upstream.0.clone());
        self.register_with_server_config(server, config);
        let _ = self.set_state(&upstream, ConnectionState::Connected);
        if let Some(slot) = self.upstreams.get_mut(&upstream) {
            slot.connection.healthy = true;
        }
    }

    /// Register or replace an upstream from explicit server config (starts disconnected).
    pub fn register_with_server_config(
        &mut self,
        server: UpstreamServerConfig,
        config: UpstreamConfig,
    ) {
        self.upstreams
            .insert(server.id.clone(), UpstreamSlot::new(server, config));
    }

    /// Connection lifecycle placeholder: transition to connected.
    pub fn connect(&mut self, upstream: &UpstreamId) -> Result<(), PoolError> {
        let slot = self
            .upstreams
            .get_mut(upstream)
            .ok_or_else(|| PoolError::UnknownUpstream(upstream.0.clone()))?;
        slot.state = ConnectionState::Connecting;
        // TODO(rmcp): establish real transport/session handshake.
        slot.state = ConnectionState::Connected;
        slot.connection.healthy = true;
        Ok(())
    }

    /// Connection lifecycle placeholder: disconnect and mark unhealthy.
    pub fn disconnect(&mut self, upstream: &UpstreamId) -> Result<(), PoolError> {
        let slot = self
            .upstreams
            .get_mut(upstream)
            .ok_or_else(|| PoolError::UnknownUpstream(upstream.0.clone()))?;
        slot.state = ConnectionState::Disconnected;
        slot.connection.healthy = false;
        Ok(())
    }

    /// Connection lifecycle placeholder: reconnect by cycling through connect.
    pub fn reconnect(&mut self, upstream: &UpstreamId) -> Result<(), PoolError> {
        self.disconnect(upstream)?;
        self.connect(upstream)
    }

    /// Integration hook: connect using a `ConnectionManager`/session factory seam.
    pub fn connect_with_manager<M: ConnectionManager>(
        &mut self,
        upstream: &UpstreamId,
        manager: &mut M,
    ) -> Result<M::Session, PoolError> {
        let slot = self
            .upstreams
            .get_mut(upstream)
            .ok_or_else(|| PoolError::UnknownUpstream(upstream.0.clone()))?;
        slot.state = ConnectionState::Connecting;
        let mut session = manager.connect(&slot.server)?;
        session.ping().inspect_err(|_| {
            slot.state = ConnectionState::Unhealthy;
            slot.connection.healthy = false;
        })?;
        slot.state = ConnectionState::Connected;
        slot.connection.healthy = true;
        Ok(session)
    }

    /// Ensure connected before dispatch/acquire (idempotent for connected slots).
    pub fn ensure_connected(&mut self, upstream: &UpstreamId) -> Result<(), PoolError> {
        match self.state(upstream) {
            Some(ConnectionState::Connected) => Ok(()),
            Some(ConnectionState::Connecting) => Err(PoolError::InvalidState {
                upstream: upstream.0.clone(),
                state: ConnectionState::Connecting,
            }),
            Some(_) => self.connect(upstream),
            None => Err(PoolError::UnknownUpstream(upstream.0.clone())),
        }
    }

    /// Probe with configured health check and update state/breaker accordingly.
    pub fn probe_health(&mut self, upstream: &UpstreamId) -> Result<HealthStatus, PoolError>
    where
        H: HealthCheck,
    {
        let slot = self
            .upstreams
            .get_mut(upstream)
            .ok_or_else(|| PoolError::UnknownUpstream(upstream.0.clone()))?;
        let status = self.health_check.check(&slot.connection);
        match status {
            HealthStatus::Healthy => {
                slot.connection.healthy = true;
                if matches!(
                    slot.state,
                    ConnectionState::Unhealthy | ConnectionState::Disconnected
                ) {
                    slot.state = ConnectionState::Connected;
                }
                slot.breaker.record_success();
            }
            HealthStatus::Unhealthy => {
                slot.connection.healthy = false;
                slot.state = ConnectionState::Unhealthy;
                slot.breaker.record_failure();
            }
        }
        Ok(status)
    }

    pub fn server_config(&self, upstream: &UpstreamId) -> Option<&UpstreamServerConfig> {
        self.upstreams.get(upstream).map(|s| &s.server)
    }

    pub fn config(&self, upstream: &UpstreamId) -> Option<&UpstreamConfig> {
        self.upstreams.get(upstream).map(|s| &s.config)
    }

    pub fn state(&self, upstream: &UpstreamId) -> Option<ConnectionState> {
        self.upstreams.get(upstream).map(|s| s.state)
    }

    pub fn breaker(&self, upstream: &UpstreamId) -> Option<&CircuitBreaker> {
        self.upstreams.get(upstream).map(|s| &s.breaker)
    }

    pub fn breaker_mut(&mut self, upstream: &UpstreamId) -> Option<&mut CircuitBreaker> {
        self.upstreams.get_mut(upstream).map(|s| &mut s.breaker)
    }

    pub fn active_leases(&self, upstream: &UpstreamId) -> Option<usize> {
        self.upstreams.get(upstream).map(|s| s.active_leases)
    }

    pub fn available_leases(&self, upstream: &UpstreamId) -> Option<usize> {
        self.upstreams
            .get(upstream)
            .map(|s| s.max_leases().saturating_sub(s.active_leases))
    }

    pub fn set_state(
        &mut self,
        upstream: &UpstreamId,
        state: ConnectionState,
    ) -> Result<(), PoolError> {
        let slot = self
            .upstreams
            .get_mut(upstream)
            .ok_or_else(|| PoolError::UnknownUpstream(upstream.0.clone()))?;
        slot.state = state;
        slot.connection.healthy = !matches!(
            state,
            ConnectionState::Unhealthy | ConnectionState::Disconnected
        );
        Ok(())
    }
}

impl<H: HealthCheck> McpPool<H> {
    /// Acquire a lease for an upstream using its configured timeout policy.
    pub fn acquire(&mut self, upstream: &UpstreamId) -> Result<PooledLease, PoolError> {
        let timeout = self
            .upstreams
            .get(upstream)
            .ok_or_else(|| PoolError::UnknownUpstream(upstream.0.clone()))?
            .config
            .effective_acquire_timeout();
        self.acquire_with_timeout(upstream, timeout)
    }

    pub fn acquire_with_timeout(
        &mut self,
        upstream: &UpstreamId,
        timeout: Duration,
    ) -> Result<PooledLease, PoolError> {
        let slot = self
            .upstreams
            .get_mut(upstream)
            .ok_or_else(|| PoolError::UnknownUpstream(upstream.0.clone()))?;

        if !slot.breaker.allow_request() {
            return Err(PoolError::CircuitOpen(
                "requests blocked by circuit breaker".into(),
            ));
        }
        if !matches!(slot.state, ConnectionState::Connected) {
            return Err(PoolError::Unavailable(format!("state {:?}", slot.state)));
        }
        let cap = slot.max_leases();
        if slot.active_leases >= cap {
            // shortcut: no wait queue/timer in std-only skeleton; timeout==0 means fail fast.
            if timeout.is_zero() {
                return Err(PoolError::Exhausted { max_leases: cap });
            }
            // TODO(runtime): wait up to timeout for a lease to be released.
            return Err(PoolError::Timeout { waited: timeout });
        }

        match self.health_check.check(&slot.connection) {
            HealthStatus::Healthy => {
                slot.breaker.record_success();
                let lease = PooledLease {
                    upstream: slot.connection.upstream.clone(),
                    lease_id: slot.next_lease_id,
                };
                slot.next_lease_id = slot.next_lease_id.saturating_add(1);
                slot.active_leases += 1;
                Ok(lease)
            }
            HealthStatus::Unhealthy => {
                slot.breaker.record_failure();
                slot.state = ConnectionState::Unhealthy;
                slot.connection.healthy = false;
                Err(PoolError::Unavailable("health check failed".into()))
            }
        }
    }

    /// Release a previously acquired lease.
    pub fn release(&mut self, lease: PooledLease) -> Result<(), PoolError> {
        let slot = self
            .upstreams
            .get_mut(&lease.upstream)
            .ok_or_else(|| PoolError::UnknownUpstream(lease.upstream.0.clone()))?;
        if lease.lease_id == 0 || lease.lease_id >= slot.next_lease_id || slot.active_leases == 0 {
            return Err(PoolError::InvalidLease(lease.lease_id));
        }
        slot.active_leases -= 1;
        Ok(())
    }

    /// Mark an upstream unhealthy and record breaker failure.
    pub fn mark_unhealthy(&mut self, upstream: &UpstreamId) -> Result<(), PoolError> {
        let slot = self
            .upstreams
            .get_mut(upstream)
            .ok_or_else(|| PoolError::UnknownUpstream(upstream.0.clone()))?;
        slot.state = ConnectionState::Unhealthy;
        slot.connection.healthy = false;
        slot.breaker.record_failure();
        Ok(())
    }

    /// Dispatch/forward a request through acquire/release with retry/timeout placeholders.
    pub fn dispatch<D: Dispatcher>(
        &mut self,
        upstream: &UpstreamId,
        request: &CallRequest,
        dispatcher: &mut D,
    ) -> Result<DispatchOutcome, PoolError> {
        let (max_retries, call_timeout) = {
            let slot = self
                .upstreams
                .get(upstream)
                .ok_or_else(|| PoolError::UnknownUpstream(upstream.0.clone()))?;
            (
                slot.config.effective_max_retries(),
                slot.config.effective_call_timeout(),
            )
        };

        let mut attempts = 0u32;
        loop {
            attempts = attempts.saturating_add(1);
            let lease = match self.acquire(upstream) {
                Ok(l) => l,
                Err(e) if Self::retryable(&e) && attempts <= max_retries => {
                    // TODO(runtime): honor retry_backoff/call_timeout with timers.
                    let _ = call_timeout;
                    continue;
                }
                Err(e) => return Err(e),
            };

            let call_res = dispatcher.call(upstream, request);
            let _ = self.release(lease);
            match call_res {
                Ok(response) => {
                    if let Some(slot) = self.upstreams.get_mut(upstream) {
                        slot.breaker.record_success();
                        if slot.state == ConnectionState::Unhealthy {
                            slot.state = ConnectionState::Connected;
                            slot.connection.healthy = true;
                        }
                    }
                    return Ok(DispatchOutcome { response, attempts });
                }
                Err(e) => {
                    if Self::retryable(&e) && attempts <= max_retries {
                        if let Some(slot) = self.upstreams.get_mut(upstream) {
                            slot.breaker.record_failure();
                        }
                        // TODO(runtime): honor retry_backoff/call_timeout with timers.
                        continue;
                    }
                    let _ = self.mark_unhealthy(upstream);
                    return Err(e);
                }
            }
        }
    }

    fn retryable(err: &PoolError) -> bool {
        err.is_retryable()
    }

    /// Returns configured upstream IDs (order unspecified).
    pub fn upstream_ids(&self) -> impl Iterator<Item = &UpstreamId> {
        self.upstreams.keys()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Default)]
    struct FlakyDispatcher {
        fail_times: u32,
        calls: u32,
    }

    impl Dispatcher for FlakyDispatcher {
        fn call(
            &mut self,
            _upstream: &UpstreamId,
            req: &CallRequest,
        ) -> Result<CallResponse, PoolError> {
            self.calls += 1;
            if self.calls <= self.fail_times {
                Err(PoolError::DispatchFailed("transient".into()))
            } else {
                Ok(CallResponse {
                    payload: format!("ok:{}", req.method),
                })
            }
        }
    }

    #[derive(Debug, Default)]
    struct FailingDispatcher;

    impl Dispatcher for FailingDispatcher {
        fn call(
            &mut self,
            _upstream: &UpstreamId,
            _req: &CallRequest,
        ) -> Result<CallResponse, PoolError> {
            Err(PoolError::DispatchFailed("boom".into()))
        }
    }

    #[test]
    fn per_upstream_config_and_lease_isolation() {
        let mut pool = McpPool::default();
        let a = UpstreamId("a".into());
        let b = UpstreamId("b".into());
        pool.register_with_config(
            a.clone(),
            UpstreamConfig {
                max_leases: 1,
                ..Default::default()
            },
        );
        pool.register_with_config(
            b.clone(),
            UpstreamConfig {
                max_leases: 2,
                ..Default::default()
            },
        );

        let la = pool.acquire(&a).expect("a lease");
        assert!(matches!(pool.acquire(&a), Err(PoolError::Exhausted { .. })));
        let lb1 = pool.acquire(&b).expect("b1");
        let lb2 = pool.acquire(&b).expect("b2");
        assert_eq!(pool.active_leases(&a), Some(1));
        assert_eq!(pool.active_leases(&b), Some(2));
        pool.release(la).unwrap();
        pool.release(lb1).unwrap();
        pool.release(lb2).unwrap();
        assert_eq!(pool.active_leases(&a), Some(0));
        assert_eq!(pool.active_leases(&b), Some(0));
    }

    #[test]
    fn acquire_exhausted_and_timeout_placeholder() {
        let mut pool = McpPool::default();
        let id = UpstreamId("u".into());
        pool.register_with_config(
            id.clone(),
            UpstreamConfig {
                max_leases: 1,
                acquire_timeout: Duration::from_secs(0),
                ..Default::default()
            },
        );
        let _lease = pool.acquire(&id).expect("first");
        assert!(matches!(
            pool.acquire(&id),
            Err(PoolError::Exhausted { .. })
        ));
        let err = pool
            .acquire_with_timeout(&id, Duration::from_millis(5))
            .expect_err("timeout");
        assert!(matches!(err, PoolError::Timeout { .. }));
    }

    #[test]
    fn connection_state_and_health_check() {
        let mut pool = McpPool::default();
        let id = UpstreamId("u".into());
        pool.register(id.clone());
        assert_eq!(pool.state(&id), Some(ConnectionState::Connected));
        pool.set_state(&id, ConnectionState::Unhealthy).unwrap();
        assert!(matches!(pool.acquire(&id), Err(PoolError::Unavailable(_))));
        pool.set_state(&id, ConnectionState::Connected).unwrap();
        // slot is marked connected again but connection.healthy follows state in set_state; recover
        if let Some(slot) = pool.upstreams.get_mut(&id) {
            slot.connection.healthy = true;
        }
        assert!(pool.acquire(&id).is_ok());
    }

    #[test]
    fn circuit_breaker_policy_transitions() {
        let mut breaker = CircuitBreaker::with_policy(CircuitBreakerPolicy {
            failure_threshold: 2,
            half_open_success_threshold: 2,
            open_cooldown: Duration::from_secs(1),
        });
        breaker.record_failure();
        assert_eq!(breaker.state, CircuitState::Closed);
        breaker.record_failure();
        assert_eq!(breaker.state, CircuitState::Open);
        assert!(!breaker.allow_request());
        breaker.enter_half_open();
        breaker.record_success();
        assert_eq!(breaker.state, CircuitState::HalfOpen);
        breaker.record_success();
        assert_eq!(breaker.state, CircuitState::Closed);
        breaker.record_failure();
        breaker.record_failure();
        breaker.enter_half_open();
        breaker.record_failure();
        assert_eq!(breaker.state, CircuitState::Open);
    }

    #[test]
    fn dispatch_success_and_retries_placeholder() {
        let mut pool = McpPool::default();
        let id = UpstreamId("u".into());
        pool.register_with_config(
            id.clone(),
            UpstreamConfig {
                max_retries: 2,
                breaker: CircuitBreakerPolicy {
                    failure_threshold: 10,
                    ..Default::default()
                },
                ..Default::default()
            },
        );
        let req = CallRequest {
            method: "ping".into(),
            payload: "".into(),
        };
        let mut disp = FlakyDispatcher {
            fail_times: 1,
            calls: 0,
        };
        let out = pool.dispatch(&id, &req, &mut disp).expect("dispatch");
        assert_eq!(out.response.payload, "ok:ping");
        assert_eq!(out.attempts, 2);
        assert_eq!(disp.calls, 2);
    }

    #[test]
    fn dispatch_failure_marks_unhealthy_and_opens_circuit() {
        let mut pool = McpPool::default();
        let id = UpstreamId("u".into());
        pool.register_with_config(
            id.clone(),
            UpstreamConfig {
                max_retries: 0,
                breaker: CircuitBreakerPolicy {
                    failure_threshold: 1,
                    ..Default::default()
                },
                ..Default::default()
            },
        );
        let req = CallRequest {
            method: "x".into(),
            payload: "".into(),
        };
        let mut disp = FailingDispatcher;
        let err = pool.dispatch(&id, &req, &mut disp).expect_err("fail");
        assert!(matches!(err, PoolError::DispatchFailed(_)));
        assert_eq!(pool.state(&id), Some(ConnectionState::Unhealthy));
        assert_eq!(pool.breaker(&id).map(|b| b.state), Some(CircuitState::Open));
    }

    #[test]
    fn release_rejects_invalid_lease() {
        let mut pool = McpPool::default();
        let id = UpstreamId("u".into());
        pool.register(id.clone());
        let err = pool
            .release(PooledLease {
                upstream: id,
                lease_id: 999,
            })
            .expect_err("invalid");
        assert!(matches!(err, PoolError::InvalidLease(999)));
    }

    #[test]
    fn unknown_upstream_errors() {
        let mut pool = McpPool::default();
        let id = UpstreamId("missing".into());
        assert!(matches!(
            pool.acquire(&id),
            Err(PoolError::UnknownUpstream(_))
        ));
        assert!(matches!(
            pool.set_state(&id, ConnectionState::Connected),
            Err(PoolError::UnknownUpstream(_))
        ));
        let mut disp = PlaceholderDispatcher;
        let req = CallRequest {
            method: "m".into(),
            payload: String::new(),
        };
        assert!(matches!(
            pool.dispatch(&id, &req, &mut disp),
            Err(PoolError::UnknownUpstream(_))
        ));
    }

    #[test]
    fn circuit_open_blocks_acquire_and_dispatch() {
        let mut pool = McpPool::default();
        let id = UpstreamId("u".into());
        pool.register(id.clone());
        if let Some(b) = pool.breaker_mut(&id) {
            b.state = CircuitState::Open;
        }
        assert!(matches!(pool.acquire(&id), Err(PoolError::CircuitOpen(_))));
        let mut disp = PlaceholderDispatcher;
        let req = CallRequest {
            method: "m".into(),
            payload: String::new(),
        };
        assert!(matches!(
            pool.dispatch(&id, &req, &mut disp),
            Err(PoolError::CircuitOpen(_))
        ));
    }

    #[test]
    fn register_replaces_config() {
        let mut pool = McpPool::default();
        let id = UpstreamId("u".into());
        pool.register_with_config(
            id.clone(),
            UpstreamConfig {
                max_leases: 1,
                ..Default::default()
            },
        );
        pool.register_with_config(
            id.clone(),
            UpstreamConfig {
                max_leases: 5,
                ..Default::default()
            },
        );
        assert_eq!(pool.config(&id).map(|c| c.max_leases), Some(5));
    }

    #[test]
    fn server_config_and_connection_lifecycle_placeholders() {
        let mut pool = McpPool::default();
        let server = UpstreamServerConfig::with_http("srv", "http://localhost:1234");
        let mut server = server;
        server.auth_profile = Some("dev".into());
        if let TransportSpec::Http(ref mut h) = server.transport_spec {
            h.auth_profile = Some("dev".into());
        }
        pool.register_with_server_config(server.clone(), UpstreamConfig::default());
        assert_eq!(pool.state(&server.id), Some(ConnectionState::Disconnected));
        assert_eq!(pool.server_config(&server.id), Some(&server));
        assert!(matches!(
            pool.acquire(&server.id),
            Err(PoolError::Unavailable(_))
        ));

        pool.connect(&server.id).unwrap();
        assert_eq!(pool.state(&server.id), Some(ConnectionState::Connected));
        let lease = pool.acquire(&server.id).expect("connected lease");
        pool.release(lease).unwrap();

        pool.disconnect(&server.id).unwrap();
        assert_eq!(pool.state(&server.id), Some(ConnectionState::Disconnected));
        pool.reconnect(&server.id).unwrap();
        assert_eq!(pool.state(&server.id), Some(ConnectionState::Connected));
    }

    #[test]
    fn request_response_forwarding_abstraction() {
        let mut pool = McpPool::default();
        let id = UpstreamId("u".into());
        pool.register(id.clone());
        let req = ForwardRequest {
            method: "tools/list".into(),
            payload: "{}".into(),
        };
        let mut fwd = PlaceholderDispatcher;
        let out = RequestForwarder::forward(&mut fwd, &id, &req).expect("forward");
        assert_eq!(out.payload, "ok:tools/list");
        let disp_out = pool.dispatch(&id, &req, &mut fwd).expect("dispatch");
        assert_eq!(disp_out.response, out);
    }

    #[test]
    fn retry_timeout_and_concurrency_policy_placeholders() {
        let mut pool = McpPool::default();
        let id = UpstreamId("u".into());
        let cfg = UpstreamConfig {
            max_leases: 1,
            retry: RetryPolicy {
                max_retries: 3,
                backoff: Duration::from_millis(10),
            },
            timeouts: TimeoutPolicy {
                acquire_timeout: Duration::from_millis(7),
                call_timeout: Duration::from_millis(9),
            },
            concurrency: ConcurrencyPolicy {
                max_leases: 2,
                max_in_flight: 4,
            },
            ..Default::default()
        };
        pool.register_with_config(id.clone(), cfg);
        assert_eq!(pool.config(&id).map(|c| c.effective_max_retries()), Some(3));
        assert_eq!(
            pool.config(&id).map(|c| c.effective_call_timeout()),
            Some(Duration::from_millis(9))
        );
        assert_eq!(pool.config(&id).map(|c| c.effective_max_leases()), Some(2));
        assert_eq!(pool.available_leases(&id), Some(2));

        let l1 = pool.acquire(&id).unwrap();
        let l2 = pool.acquire(&id).unwrap();
        assert_eq!(pool.available_leases(&id), Some(0));
        let err = pool.acquire(&id).expect_err("cap");
        assert!(matches!(
            err,
            PoolError::Timeout { waited } if waited == Duration::from_millis(7)
        ));
        let err = pool
            .acquire_with_timeout(&id, Duration::from_millis(3))
            .expect_err("timeout");
        assert!(matches!(err, PoolError::Timeout { waited } if waited == Duration::from_millis(3)));
        pool.release(l1).unwrap();
        pool.release(l2).unwrap();
    }

    #[test]
    fn stdio_and_http_transport_specs() {
        let stdio = UpstreamServerConfig::with_stdio(
            "stdio-srv",
            "node",
            vec!["server.js".into(), "--flag".into()],
        );
        assert_eq!(stdio.transport, TransportKind::Stdio);
        match &stdio.transport_spec {
            TransportSpec::Stdio(s) => {
                assert_eq!(s.program, "node");
                assert_eq!(s.args, vec!["server.js", "--flag"]);
            }
            _ => panic!("expected stdio spec"),
        }

        let http = UpstreamServerConfig::with_http("http-srv", "https://mcp.example/rpc");
        assert_eq!(http.transport, TransportKind::Http);
        assert_eq!(http.endpoint, "https://mcp.example/rpc");
        match &http.transport_spec {
            TransportSpec::Http(h) => assert_eq!(h.url, "https://mcp.example/rpc"),
            _ => panic!("expected http spec"),
        }
    }

    #[test]
    fn session_dispatcher_forwards_requests() {
        let id = UpstreamId("u".into());
        let session = PlaceholderSession::ready(id.clone());
        let mut disp = SessionDispatcher::new(session);
        let req = CallRequest {
            method: "tools/call".into(),
            payload: r#"{"name":"x"}"#.into(),
        };
        let out = disp.call(&id, &req).expect("forward");
        assert_eq!(out.payload, "session:u:tools/call");
        assert!(disp.session().is_ready());
    }

    #[test]
    fn pool_dispatch_through_session_dispatcher() {
        let mut pool = McpPool::default();
        let id = UpstreamId("u".into());
        pool.register(id.clone());
        let mut disp = SessionDispatcher::new(PlaceholderSession::ready(id.clone()));
        let req = CallRequest {
            method: "tools/list".into(),
            payload: "{}".into(),
        };
        let out = pool.dispatch(&id, &req, &mut disp).expect("dispatch");
        assert_eq!(out.response.payload, "session:u:tools/list");
        assert_eq!(out.attempts, 1);
    }

    #[test]
    fn session_forward_failure_marks_pool_unhealthy() {
        let mut pool = McpPool::default();
        let id = UpstreamId("u".into());
        pool.register_with_config(
            id.clone(),
            UpstreamConfig {
                max_retries: 0,
                breaker: CircuitBreakerPolicy {
                    failure_threshold: 1,
                    ..Default::default()
                },
                ..Default::default()
            },
        );
        let mut disp = SessionDispatcher::new(PlaceholderSession::ready(id.clone()).fail_next());
        let req = CallRequest {
            method: "tools/call".into(),
            payload: "{}".into(),
        };
        let err = pool.dispatch(&id, &req, &mut disp).expect_err("fail");
        assert!(matches!(err, PoolError::DispatchFailed(_)));
        assert_eq!(pool.state(&id), Some(ConnectionState::Unhealthy));
        assert_eq!(pool.breaker(&id).map(|b| b.state), Some(CircuitState::Open));
    }

    #[test]
    fn connection_manager_placeholder_connects_ready_session() {
        let server = UpstreamServerConfig::with_stdio("srv", "mcp-server", vec![]);
        let mut mgr = NoopConnectionManager;
        let mut session = mgr.connect(&server).expect("connect");
        assert!(session.ping().is_ok());
        let res = session
            .forward(&CallRequest {
                method: "initialize".into(),
                payload: "{}".into(),
            })
            .expect("forward");
        assert_eq!(res.payload, "session:srv:initialize");
    }

    #[test]
    fn config_map_builds_stdio_and_http_specs() {
        let mut stdio_cfg = BTreeMap::new();
        stdio_cfg.insert("transport".into(), "stdio".into());
        stdio_cfg.insert("program".into(), "node".into());
        stdio_cfg.insert("args".into(), "server.js,--flag".into());
        stdio_cfg.insert("cwd".into(), "/tmp/work".into());
        stdio_cfg.insert("env.TOKEN".into(), "x".into());
        stdio_cfg.insert("auth_profile".into(), "dev".into());
        let stdio = UpstreamServerConfig::from_config_map("s", &stdio_cfg).expect("stdio");
        assert_eq!(stdio.transport, TransportKind::Stdio);
        assert_eq!(stdio.auth_profile.as_deref(), Some("dev"));
        match stdio.transport_spec {
            TransportSpec::Stdio(s) => {
                assert_eq!(s.program, "node");
                assert_eq!(s.args, vec!["server.js", "--flag"]);
                assert_eq!(s.cwd.as_deref(), Some("/tmp/work"));
                assert_eq!(s.env.get("TOKEN").map(String::as_str), Some("x"));
            }
            _ => panic!("expected stdio"),
        }

        let mut http_cfg = BTreeMap::new();
        http_cfg.insert("transport".into(), "http".into());
        http_cfg.insert("url".into(), "https://mcp.example/rpc".into());
        http_cfg.insert("header.Authorization".into(), "Bearer t".into());
        http_cfg.insert("auth_profile".into(), "prod".into());
        let http = UpstreamServerConfig::from_config_map("h", &http_cfg).expect("http");
        assert_eq!(http.transport, TransportKind::Http);
        match http.transport_spec {
            TransportSpec::Http(h) => {
                assert_eq!(h.url, "https://mcp.example/rpc");
                assert_eq!(
                    h.headers.get("Authorization").map(String::as_str),
                    Some("Bearer t")
                );
                assert_eq!(h.auth_profile.as_deref(), Some("prod"));
            }
            _ => panic!("expected http"),
        }
    }

    #[test]
    fn config_map_validation_errors() {
        let mut bad_stdio = BTreeMap::new();
        bad_stdio.insert("transport".into(), "stdio".into());
        assert!(UpstreamServerConfig::from_config_map("s", &bad_stdio).is_err());
        let mut bad_http = BTreeMap::new();
        bad_http.insert("transport".into(), "http".into());
        assert!(UpstreamServerConfig::from_config_map("h", &bad_http).is_err());
    }

    #[test]
    fn connect_with_manager_and_probe_health_hooks() {
        let mut pool = McpPool::default();
        let server = UpstreamServerConfig::with_stdio("srv", "cmd", vec![]);
        let id = server.id.clone();
        pool.register_with_server_config(server, UpstreamConfig::default());
        assert_eq!(pool.state(&id), Some(ConnectionState::Disconnected));
        let mut mgr = NoopConnectionManager;
        let _session = pool.connect_with_manager(&id, &mut mgr).expect("connect");
        assert_eq!(pool.state(&id), Some(ConnectionState::Connected));
        pool.disconnect(&id).unwrap();
        let status = pool.probe_health(&id).expect("probe");
        assert_eq!(status, HealthStatus::Unhealthy);
        assert_eq!(pool.state(&id), Some(ConnectionState::Unhealthy));
        assert_eq!(pool.breaker(&id).map(|b| b.failure_count), Some(1));
    }

    #[test]
    fn retry_delay_and_circuit_probe_hooks() {
        let cfg = UpstreamConfig {
            retry: RetryPolicy {
                max_retries: 3,
                backoff: Duration::from_millis(50),
            },
            breaker: CircuitBreakerPolicy {
                failure_threshold: 1,
                half_open_success_threshold: 1,
                open_cooldown: Duration::from_secs(2),
            },
            ..Default::default()
        };
        assert_eq!(cfg.retry_delay_for_attempt(1), Duration::from_millis(50));
        assert_eq!(cfg.retry_delay_for_attempt(3), Duration::from_millis(100));
        let mut breaker = CircuitBreaker::with_policy(cfg.breaker);
        breaker.record_failure();
        assert_eq!(breaker.state, CircuitState::Open);
        assert!(!breaker.can_probe_after(Duration::from_secs(1)));
        assert!(breaker.can_probe_after(Duration::from_secs(2)));
    }

    #[test]
    fn pool_front_bridge_dispatch_hook() {
        let mut pool = McpPool::default();
        let id = UpstreamId("u".into());
        pool.register(id.clone());
        let mut disp = PlaceholderDispatcher;
        let mut bridge = PoolFrontBridge::new(&mut pool, &mut disp);
        let resp = bridge
            .dispatch(FrontDispatchRequest {
                upstream: id,
                method: "tools/call".into(),
                payload: "{}".into(),
            })
            .expect("dispatch");
        assert_eq!(resp.payload, "ok:tools/call");
        assert_eq!(resp.attempts, 1);
    }
}
