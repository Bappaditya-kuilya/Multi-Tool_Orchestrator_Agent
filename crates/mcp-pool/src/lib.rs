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
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
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
pub trait McpClientSession: Send + Sync {
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
pub trait AsyncMcpClientSession: Send + Sync {
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

fn json_escape_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c <= '\u{1F}' => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn find_json_value_end(s: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    if i >= bytes.len() {
        return None;
    }
    match bytes[i] {
        b'"' => {
            i += 1;
            while i < bytes.len() {
                match bytes[i] {
                    b'\\' => i = i.saturating_add(2),
                    b'"' => return Some(i + 1),
                    _ => i += 1,
                }
            }
            None
        }
        b'{' | b'[' => {
            let mut stack: Vec<u8> = vec![bytes[i]];
            i += 1;
            let mut in_str = false;
            while i < bytes.len() {
                let b = bytes[i];
                if in_str {
                    match b {
                        b'\\' => i = i.saturating_add(2),
                        b'"' => {
                            in_str = false;
                            i += 1;
                        }
                        _ => i += 1,
                    }
                    continue;
                }
                match b {
                    b'"' => {
                        in_str = true;
                        i += 1;
                    }
                    b'{' | b'[' => {
                        stack.push(b);
                        i += 1;
                    }
                    b'}' => {
                        if stack.pop() != Some(b'{') {
                            return None;
                        }
                        i += 1;
                        if stack.is_empty() {
                            return Some(i);
                        }
                    }
                    b']' => {
                        if stack.pop() != Some(b'[') {
                            return None;
                        }
                        i += 1;
                        if stack.is_empty() {
                            return Some(i);
                        }
                    }
                    _ => i += 1,
                }
            }
            None
        }
        b't' if s[i..].starts_with("true") => Some(i + 4),
        b'f' if s[i..].starts_with("false") => Some(i + 5),
        b'n' if s[i..].starts_with("null") => Some(i + 4),
        b'-' | b'0'..=b'9' => {
            i += 1;
            while i < bytes.len() {
                match bytes[i] {
                    b'0'..=b'9' | b'+' | b'-' | b'.' | b'e' | b'E' => i += 1,
                    _ => break,
                }
            }
            Some(i)
        }
        _ => None,
    }
}

fn extract_json_field_value(json: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\"");
    let mut search = json;
    let mut offset = 0usize;
    while let Some(pos) = search.find(&needle) {
        let abs = offset + pos;
        let after_key = &json[abs + needle.len()..];
        let trimmed = after_key.trim_start();
        if let Some(rest) = trimmed.strip_prefix(':') {
            let rest_trimmed = rest.trim_start();
            let end = find_json_value_end(rest_trimmed)?;
            return Some(rest_trimmed[..end].to_string());
        }
        offset = abs + needle.len();
        if offset >= json.len() {
            break;
        }
        search = &json[offset..];
    }
    None
}

fn extract_json_result_or_error(json: &str) -> Result<String, PoolError> {
    if let Some(err_val) = extract_json_field_value(json, "error") {
        if err_val != "null" {
            return Err(PoolError::DispatchFailed(format!(
                "upstream error: {}",
                err_val
            )));
        }
    }
    if let Some(result) = extract_json_field_value(json, "result") {
        return Ok(result);
    }
    Ok(json.trim().to_string())
}

fn build_stdio_request_line(request: &ForwardRequest, id: i64) -> Result<String, PoolError> {
    let payload = request.payload.trim();
    if payload.starts_with('{') {
        // Preserve caller-provided envelope when present; ensure jsonrpc/id/method minimally.
        if payload.contains("\"jsonrpc\"")
            || payload.contains("\"method\"")
            || payload.contains("\"id\"")
        {
            let mut out = payload.to_string();
            if !out.contains("\"jsonrpc\"") {
                out.insert_str(1, "\"jsonrpc\":\"2.0\",");
            }
            if !out.contains("\"id\"") {
                out.insert_str(1, &format!("\"id\":{id},"));
            }
            if !out.contains("\"method\"") {
                out.insert_str(
                    1,
                    &format!("\"method\":{},", json_escape_string(&request.method)),
                );
            }
            return Ok(out);
        }
        // Treat JSON object payload as params object.
        return Ok(format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":{id},\"method\":{},\"params\":{}}}",
            json_escape_string(&request.method),
            payload
        ));
    }
    if payload.is_empty() || payload == "null" {
        return Ok(format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":{id},\"method\":{},\"params\":{{}}}}",
            json_escape_string(&request.method)
        ));
    }
    // Non-object payload -> params as JSON string value.
    Ok(format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":{id},\"method\":{},\"params\":{}}}",
        json_escape_string(&request.method),
        json_escape_string(&request.payload)
    ))
}

/// Blocking stdio subprocess MCP session (line-delimited JSON-RPC) for sync pool/gateway paths.
struct StdioInner {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    next_id: i64,
    ready: bool,
}

pub struct StdioProcessSession {
    upstream: UpstreamId,
    inner: std::sync::Mutex<StdioInner>,
}

impl fmt::Debug for StdioProcessSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ready = self.inner.lock().map(|g| g.ready).unwrap_or(false);
        f.debug_struct("StdioProcessSession")
            .field("upstream", &self.upstream)
            .field("ready", &ready)
            .finish_non_exhaustive()
    }
}

impl StdioProcessSession {
    pub fn spawn(server: &UpstreamServerConfig) -> Result<Self, PoolError> {
        let spec = match &server.transport_spec {
            TransportSpec::Stdio(s) => s,
            _ => {
                return Err(PoolError::Unavailable(
                    "stdio transport spec required".into(),
                ))
            }
        };
        if spec.program.trim().is_empty() {
            return Err(PoolError::Unavailable(
                "stdio program must be non-empty".into(),
            ));
        }
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
            upstream: server.id.clone(),
            inner: std::sync::Mutex::new(StdioInner {
                child,
                stdin,
                stdout: BufReader::new(stdout),
                next_id: 1,
                ready: true,
            }),
        })
    }
}

impl Drop for StdioProcessSession {
    fn drop(&mut self) {
        if let Ok(mut inner) = self.inner.lock() {
            let _ = inner.child.kill();
            let _ = inner.child.wait();
        }
    }
}

impl McpClientSession for StdioProcessSession {
    fn is_ready(&self) -> bool {
        self.inner.lock().map(|g| g.ready).unwrap_or(false)
    }

    fn ping(&mut self) -> Result<(), PoolError> {
        if self.is_ready() {
            Ok(())
        } else {
            Err(PoolError::Unavailable(format!(
                "session not ready for {}",
                self.upstream.0
            )))
        }
    }

    fn forward(&mut self, request: &ForwardRequest) -> Result<ForwardResponse, PoolError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| PoolError::Unavailable("session lock poisoned".into()))?;
        if !inner.ready {
            return Err(PoolError::Unavailable("session not connected".into()));
        }
        let id = inner.next_id;
        inner.next_id = inner.next_id.saturating_add(1);
        let line = build_stdio_request_line(request, id)?;
        writeln!(inner.stdin, "{line}").map_err(|e| {
            inner.ready = false;
            PoolError::DispatchFailed(format!("stdin write: {e}"))
        })?;
        inner.stdin.flush().map_err(|e| {
            inner.ready = false;
            PoolError::DispatchFailed(format!("stdin flush: {e}"))
        })?;
        let mut out = String::new();
        let n = inner.stdout.read_line(&mut out).map_err(|e| {
            inner.ready = false;
            PoolError::DispatchFailed(format!("stdout read: {e}"))
        })?;
        if n == 0 {
            inner.ready = false;
            return Err(PoolError::Unavailable("stdio closed".into()));
        }
        let payload = extract_json_result_or_error(&out)?;
        Ok(ForwardResponse { payload })
    }
}

/// Blocking stdio connection manager for real subprocess-backed upstream sessions.
#[derive(Debug, Default, Clone, Copy)]
pub struct StdioConnectionManager;

impl ConnectionManager for StdioConnectionManager {
    type Session = StdioProcessSession;

    fn connect(&mut self, server: &UpstreamServerConfig) -> Result<Self::Session, PoolError> {
        StdioProcessSession::spawn(server)
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

struct UpstreamSlot {
    server: UpstreamServerConfig,
    config: UpstreamConfig,
    state: ConnectionState,
    connection: ClientConnection,
    breaker: CircuitBreaker,
    active_leases: usize,
    next_lease_id: u64,
    circuit_opened_at: Option<std::time::Instant>,
    /// Managed upstream session for direct sync dispatch (e.g. stdio subprocess).
    session: Option<Box<dyn McpClientSession + Send + Sync>>,
}

impl fmt::Debug for UpstreamSlot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UpstreamSlot")
            .field("server", &self.server)
            .field("config", &self.config)
            .field("state", &self.state)
            .field("connection", &self.connection)
            .field("breaker", &self.breaker)
            .field("active_leases", &self.active_leases)
            .field("next_lease_id", &self.next_lease_id)
            .field("circuit_opened_at", &self.circuit_opened_at)
            .field(
                "session_ready",
                &self.session.as_ref().map(|s| s.is_ready()),
            )
            .finish()
    }
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
            circuit_opened_at: None,
            session: None,
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
            self.circuit_opened_at = Some(std::time::Instant::now());
        }
    }

    fn record_breaker_success(&mut self) {
        self.breaker.record_success();
        if self.breaker.state != CircuitState::Open {
            self.circuit_opened_at = None;
        }
    }
}

/// Multi-upstream MCP client pool.
pub struct McpPool<H = PlaceholderHealthCheck> {
    upstreams: HashMap<UpstreamId, UpstreamSlot>,
    health_check: H,
    default_config: UpstreamConfig,
}

impl<H: fmt::Debug> fmt::Debug for McpPool<H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("McpPool")
            .field("upstreams", &self.upstreams)
            .field("health_check", &self.health_check)
            .field("default_config", &self.default_config)
            .finish()
    }
}

/// Manual clone for compatibility. Live managed sessions are not cloned.
impl<H: Clone> Clone for McpPool<H> {
    fn clone(&self) -> Self {
        Self {
            upstreams: HashMap::new(),
            health_check: self.health_check.clone(),
            default_config: self.default_config,
        }
    }
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

    /// Connection lifecycle: establish a real upstream session when possible (stdio),
    /// otherwise fall back to connected placeholder state for compatibility.
    pub fn connect(&mut self, upstream: &UpstreamId) -> Result<(), PoolError> {
        let slot = self
            .upstreams
            .get_mut(upstream)
            .ok_or_else(|| PoolError::UnknownUpstream(upstream.0.clone()))?;
        slot.state = ConnectionState::Connecting;
        slot.session = None;
        match (&slot.server.transport, &slot.server.transport_spec) {
            (TransportKind::Stdio, TransportSpec::Stdio(_)) => {
                let server = slot.server.clone();
                match StdioProcessSession::spawn(&server) {
                    Ok(mut session) => {
                        if let Err(e) = session.ping() {
                            slot.state = ConnectionState::Unhealthy;
                            slot.connection.healthy = false;
                            return Err(e);
                        }
                        slot.session = Some(Box::new(session));
                        slot.state = ConnectionState::Connected;
                        slot.connection.healthy = true;
                        Ok(())
                    }
                    Err(e) => {
                        slot.state = ConnectionState::Unhealthy;
                        slot.connection.healthy = false;
                        Err(e)
                    }
                }
            }
            _ => {
                // Non-stdio sync transports: placeholder connected state; dispatch must use
                // a provided/managed session dispatcher seam (or runtime async path).
                slot.state = ConnectionState::Connected;
                slot.connection.healthy = true;
                Ok(())
            }
        }
    }

    /// Connection lifecycle: disconnect and drop any managed session.
    pub fn disconnect(&mut self, upstream: &UpstreamId) -> Result<(), PoolError> {
        let slot = self
            .upstreams
            .get_mut(upstream)
            .ok_or_else(|| PoolError::UnknownUpstream(upstream.0.clone()))?;
        slot.session = None;
        slot.state = ConnectionState::Disconnected;
        slot.connection.healthy = false;
        Ok(())
    }

    /// Connection lifecycle: reconnect by cycling through connect.
    pub fn reconnect(&mut self, upstream: &UpstreamId) -> Result<(), PoolError> {
        self.disconnect(upstream)?;
        self.connect(upstream)
    }

    /// Integration hook: connect using a `ConnectionManager`/session factory seam.
    /// The returned session is caller-managed for compatibility; pool state/health are updated.
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
        slot.session = None;
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
        slot.maybe_half_open_after_cooldown();
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
                slot.record_breaker_success();
            }
            HealthStatus::Unhealthy => {
                slot.connection.healthy = false;
                slot.state = ConnectionState::Unhealthy;
                slot.session = None;
                slot.record_breaker_failure();
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

        slot.maybe_half_open_after_cooldown();
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
            // std-only sync path has no wait queue/timers: fail closed immediately.
            // timeout==0 preserves Exhausted semantics; nonzero reports Timeout policy.
            if timeout.is_zero() {
                return Err(PoolError::Exhausted { max_leases: cap });
            }
            // TODO(runtime): wait up to timeout for a lease to be released.
            return Err(PoolError::Timeout { waited: timeout });
        }

        match self.health_check.check(&slot.connection) {
            HealthStatus::Healthy => {
                slot.record_breaker_success();
                let lease = PooledLease {
                    upstream: slot.connection.upstream.clone(),
                    lease_id: slot.next_lease_id,
                };
                slot.next_lease_id = slot.next_lease_id.saturating_add(1);
                slot.active_leases += 1;
                Ok(lease)
            }
            HealthStatus::Unhealthy => {
                slot.record_breaker_failure();
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
        slot.session = None;
        slot.record_breaker_failure();
        Ok(())
    }

    fn has_managed_session(&self, upstream: &UpstreamId) -> bool {
        self.upstreams
            .get(upstream)
            .and_then(|s| s.session.as_ref())
            .is_some()
    }

    fn forward_via_managed_session(
        &mut self,
        upstream: &UpstreamId,
        request: &CallRequest,
    ) -> Result<CallResponse, PoolError> {
        let slot = self
            .upstreams
            .get_mut(upstream)
            .ok_or_else(|| PoolError::UnknownUpstream(upstream.0.clone()))?;
        let Some(session) = slot.session.as_mut() else {
            return Err(PoolError::Unavailable(
                "managed upstream session unavailable".into(),
            ));
        };
        session.forward(request)
    }

    /// Dispatch/forward a request through acquire/release with retry/backoff in sync paths.
    ///
    /// Uses a pool-managed upstream session when present (enabling real stdio upstream calls
    /// from gateway S1 path), otherwise falls back to the provided dispatcher for compatibility.
    /// Attempts best-effort connection recovery for disconnected/unhealthy upstreams.
    /// Call timeout is consulted from config but cannot be enforced preemptively for
    /// blocking synchronous dispatchers; async/runtime integrations must enforce it.
    pub fn dispatch<D: Dispatcher>(
        &mut self,
        upstream: &UpstreamId,
        request: &CallRequest,
        dispatcher: &mut D,
    ) -> Result<DispatchOutcome, PoolError> {
        let (max_retries, _call_timeout, retry_cfg) = {
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

            // Best-effort recovery for retryable lifecycle states before acquire.
            match self.state(upstream) {
                Some(ConnectionState::Disconnected) | Some(ConnectionState::Unhealthy) => {
                    let _ = self.connect(upstream);
                }
                Some(ConnectionState::Connecting) => {
                    // Fail closed; caller/runtime should not dispatch mid-handshake.
                }
                Some(ConnectionState::Connected) | None => {}
            }

            let lease = match self.acquire(upstream) {
                Ok(l) => l,
                Err(e) if Self::retryable(&e) && attempts <= max_retries => {
                    let delay = retry_cfg.retry_delay_for_attempt(attempts);
                    if !delay.is_zero() {
                        std::thread::sleep(delay);
                    }
                    continue;
                }
                Err(e) => return Err(e),
            };

            // TODO(runtime): enforce call_timeout for blocking sync dispatcher calls.
            let call_res = if self.has_managed_session(upstream) {
                self.forward_via_managed_session(upstream, request)
            } else {
                dispatcher.call(upstream, request)
            };
            let _ = self.release(lease);
            match call_res {
                Ok(response) => {
                    if let Some(slot) = self.upstreams.get_mut(upstream) {
                        slot.record_breaker_success();
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
                            slot.record_breaker_failure();
                            slot.state = ConnectionState::Unhealthy;
                            slot.connection.healthy = false;
                            slot.session = None;
                        }
                        let delay = retry_cfg.retry_delay_for_attempt(attempts);
                        if !delay.is_zero() {
                            std::thread::sleep(delay);
                        }
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

    #[test]
    fn dispatch_honors_retry_backoff_between_attempts() {
        let mut pool = McpPool::default();
        let id = UpstreamId("u".into());
        pool.register_with_config(
            id.clone(),
            UpstreamConfig {
                max_retries: 2,
                retry_backoff: Duration::from_millis(12),
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
            fail_times: 2,
            calls: 0,
        };
        let start = std::time::Instant::now();
        let out = pool.dispatch(&id, &req, &mut disp).expect("dispatch");
        let elapsed = start.elapsed();
        assert_eq!(out.response.payload, "ok:ping");
        assert_eq!(out.attempts, 3);
        assert_eq!(disp.calls, 3);
        assert!(elapsed >= Duration::from_millis(20), "elapsed {elapsed:?}");
    }

    #[test]
    fn dispatch_honors_backoff_on_retryable_acquire_timeout() {
        let mut pool = McpPool::default();
        let id = UpstreamId("u".into());
        pool.register_with_config(
            id.clone(),
            UpstreamConfig {
                max_leases: 1,
                acquire_timeout: Duration::from_millis(1),
                max_retries: 2,
                retry_backoff: Duration::from_millis(10),
                ..Default::default()
            },
        );
        let _held = pool.acquire(&id).expect("held lease");
        let req = CallRequest {
            method: "ping".into(),
            payload: "".into(),
        };
        let mut disp = PlaceholderDispatcher;
        let start = std::time::Instant::now();
        let err = pool.dispatch(&id, &req, &mut disp).expect_err("timeout");
        let elapsed = start.elapsed();
        assert!(matches!(err, PoolError::Timeout { .. }));
        assert!(elapsed >= Duration::from_millis(18), "elapsed {elapsed:?}");
    }

    #[test]
    fn dispatch_recovers_from_unhealthy_state_via_reconnect() {
        let mut pool = McpPool::default();
        let id = UpstreamId("u".into());
        pool.register(id.clone());
        pool.set_state(&id, ConnectionState::Unhealthy).unwrap();
        if let Some(slot) = pool.upstreams.get_mut(&id) {
            slot.connection.healthy = false;
        }
        let mut disp = PlaceholderDispatcher;
        let out = pool
            .dispatch(
                &id,
                &CallRequest {
                    method: "ping".into(),
                    payload: "{}".into(),
                },
                &mut disp,
            )
            .expect("dispatch after recovery");
        assert_eq!(out.response.payload, "ok:ping");
        assert_eq!(pool.state(&id), Some(ConnectionState::Connected));
    }

    #[test]
    fn circuit_open_with_zero_cooldown_allows_half_open_probe_on_acquire() {
        let mut pool = McpPool::default();
        let id = UpstreamId("u".into());
        pool.register_with_config(
            id.clone(),
            UpstreamConfig {
                breaker: CircuitBreakerPolicy {
                    failure_threshold: 1,
                    half_open_success_threshold: 1,
                    open_cooldown: Duration::from_secs(0),
                },
                ..Default::default()
            },
        );
        if let Some(slot) = pool.upstreams.get_mut(&id) {
            slot.breaker.state = CircuitState::Open;
            slot.breaker.failure_count = 1;
            slot.circuit_opened_at = Some(std::time::Instant::now());
        }
        let lease = pool.acquire(&id).expect("half-open acquire");
        pool.release(lease).unwrap();
        assert_eq!(
            pool.breaker(&id).map(|b| b.state),
            Some(CircuitState::Closed)
        );
    }

    #[test]
    fn dispatch_recovers_after_recorded_open_with_zero_cooldown() {
        let mut pool = McpPool::default();
        let id = UpstreamId("u".into());
        pool.register_with_config(
            id.clone(),
            UpstreamConfig {
                max_retries: 0,
                breaker: CircuitBreakerPolicy {
                    failure_threshold: 1,
                    half_open_success_threshold: 1,
                    open_cooldown: Duration::from_secs(0),
                },
                ..Default::default()
            },
        );
        let mut failing = FailingDispatcher;
        let req = CallRequest {
            method: "x".into(),
            payload: "{}".into(),
        };
        assert!(pool.dispatch(&id, &req, &mut failing).is_err());
        assert_eq!(pool.breaker(&id).map(|b| b.state), Some(CircuitState::Open));

        let mut ok = PlaceholderDispatcher;
        let out = pool
            .dispatch(&id, &req, &mut ok)
            .expect("recovered dispatch after cooldown probe");
        assert_eq!(out.response.payload, "ok:x");
        assert_eq!(pool.state(&id), Some(ConnectionState::Connected));
    }

    #[test]
    fn sync_stdio_pool_dispatch_reaches_real_upstream_for_mcp_methods() {
        let script = r#"
while IFS= read -r line; do
  case "$line" in
    *'"method":"initialize"'*|*"initialize"*)
      echo '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05","capabilities":{"tools":{"listChanged":false}},"serverInfo":{"name":"mock-stdio"}}}'
      ;;
    *'"method":"tools/list"'*|*"tools/list"*)
      echo '{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"gateway.health","inputSchema":{"type":"object"}}]}}'
      ;;
    *'"method":"tools/call"'*|*"tools/call"*)
      echo '{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"ok"}],"isError":false}}'
      ;;
    *'"method":"ping"'*|*"ping"*)
      echo '{"jsonrpc":"2.0","id":1,"result":{}}'
      ;;
    *)
      echo '{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"method not found"}}'
      ;;
  esac
done
"#;
        let server =
            UpstreamServerConfig::with_stdio("stdio-up", "sh", vec!["-c".into(), script.into()]);
        let id = server.id.clone();
        let mut pool = McpPool::default();
        pool.register_with_server_config(server, UpstreamConfig::default());
        pool.connect(&id).expect("connect real stdio upstream");

        // Gateway S1 compatibility: external placeholder dispatcher provided, but pool-managed
        // real stdio session must receive forwarded initialize/tools/list/tools/call requests.
        let mut external = PlaceholderDispatcher;
        for method in ["initialize", "tools/list", "tools/call"] {
            let payload =
                format!("{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"{method}\",\"params\":{{}}}}");
            let out = pool
                .dispatch(
                    &id,
                    &CallRequest {
                        method: method.into(),
                        payload,
                    },
                    &mut external,
                )
                .expect("dispatch to real stdio upstream");
            assert_eq!(out.attempts, 1, "method {method}");
            assert!(
                !out.response.payload.contains("ok:"),
                "must not use placeholder dispatcher for managed stdio session: {}",
                out.response.payload
            );
        }

        // Bridge/front seam remains compatible and reaches the same managed session.
        let mut bridge = PoolFrontBridge::new(&mut pool, &mut external);
        let resp = bridge
            .dispatch(FrontDispatchRequest {
                upstream: id.clone(),
                method: "tools/call".into(),
                payload: r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"gateway.health","arguments":{}}}"#.into(),
            })
            .expect("front bridge dispatch");
        assert!(resp.payload.contains("content") || resp.payload.contains("ok"));
    }

    #[test]
    fn sync_stdio_pool_dispatches_s1_with_demo_server() {
        let demo = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../e2e/stdio_demo_mcp_server.py");
        assert!(
            demo.exists(),
            "demo server script missing at {}",
            demo.display()
        );
        let server = UpstreamServerConfig::with_stdio(
            "demo",
            "python3",
            vec!["-u".into(), demo.to_string_lossy().into_owned()],
        );
        let id = server.id.clone();
        let mut pool = McpPool::default();
        pool.register_with_server_config(server, UpstreamConfig::default());
        pool.connect(&id).expect("connect demo stdio upstream");
        let mut external = PlaceholderDispatcher;

        let init = pool
            .dispatch(
                &id,
                &CallRequest {
                    method: "initialize".into(),
                    payload: r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}"#.into(),
                },
                &mut external,
            )
            .expect("initialize");
        assert!(
            init.response.payload.contains("protocolVersion"),
            "{}",
            init.response.payload
        );

        let listed = pool
            .dispatch(
                &id,
                &CallRequest {
                    method: "tools/list".into(),
                    payload: r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#.into(),
                },
                &mut external,
            )
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
                    payload: r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"demo.echo","arguments":{"message":"hello"}}}"#.into(),
                },
                &mut external,
            )
            .expect("tools/call");
        assert!(
            called.response.payload.contains("hello"),
            "{}",
            called.response.payload
        );

        pool.disconnect(&id).expect("disconnect");
        assert_eq!(pool.state(&id), Some(ConnectionState::Disconnected));
    }

    #[test]
    fn sync_stdio_pool_recovers_after_upstream_restart_s1() {
        // One-request-per-process server: simulates stdio upstream exit between calls.
        // With no retries, dispatch must fail closed on dead session; reconnect restarts it.
        let script = r#"IFS= read -r line; echo '{"jsonrpc":"2.0","id":1,"result":{"ok":true}}'"#;
        let server = UpstreamServerConfig::with_stdio(
            "stdio-restart",
            "sh",
            vec!["-c".into(), script.into()],
        );
        let id = server.id.clone();
        let mut pool = McpPool::default();
        pool.register_with_server_config(
            server,
            UpstreamConfig {
                max_retries: 0,
                retry: RetryPolicy {
                    max_retries: 0,
                    backoff: Duration::from_millis(0),
                },
                ..Default::default()
            },
        );
        pool.connect(&id).expect("connect");
        let mut external = PlaceholderDispatcher;

        let first = pool
            .dispatch(
                &id,
                &CallRequest {
                    method: "ping".into(),
                    payload: "{}".into(),
                },
                &mut external,
            )
            .expect("first dispatch");
        assert!(first.response.payload.contains("ok"));

        let second = pool.dispatch(
            &id,
            &CallRequest {
                method: "ping".into(),
                payload: "{}".into(),
            },
            &mut external,
        );
        assert!(second.is_err(), "dead stdio session must fail closed");
        assert!(matches!(
            pool.state(&id),
            Some(ConnectionState::Unhealthy | ConnectionState::Disconnected)
        ));

        pool.reconnect(&id).expect("reconnect/restart");
        let third = pool
            .dispatch(
                &id,
                &CallRequest {
                    method: "ping".into(),
                    payload: "{}".into(),
                },
                &mut external,
            )
            .expect("dispatch after restart");
        assert!(third.response.payload.contains("ok"));
    }
}
