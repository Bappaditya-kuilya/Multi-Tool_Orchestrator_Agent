//! Approval queue and credential broker primitives (M3).
//!
//! Enhancements: secret ref resolution abstraction, redaction rules,
//! approval queue idempotent resolve/args-hash binding placeholder/notification hooks,
//! approval persistence interface hooks, credential injection/redaction flows,
//! request/response redaction helpers, and idempotent/timeout behavior with
//! integration-ready types.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use tokio::sync::Notify;

/// Reference to a secret managed outside request payloads.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SecretRef(pub String);

impl fmt::Display for SecretRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
/// Context for resolving a secret reference (tool/action binding).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretResolutionContext {
    pub tool: String,
    pub principal: Option<String>,
    /// Placeholder for future request-arg binding (e.g. hash) used by resolvers/policy.
    pub args_hash: Option<String>,
}

/// Resolved secret material. Never log/serialize raw value in production paths.
#[derive(Clone, PartialEq, Eq)]
pub struct ResolvedSecret {
    pub reference: SecretRef,
    pub value: String,
}

impl fmt::Debug for ResolvedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResolvedSecret")
            .field("reference", &self.reference)
            .field("value", &"[REDACTED]")
            .finish()
    }
}

/// Abstraction for resolving secret references to concrete secret material.
pub trait SecretResolver {
    type Error;
    fn resolve(
        &self,
        secret: &SecretRef,
        ctx: &SecretResolutionContext,
    ) -> Result<ResolvedSecret, Self::Error>;
}

/// Simple in-memory resolver for tests/integration wiring.
#[derive(Debug, Default, Clone)]
pub struct StaticSecretResolver {
    secrets: HashMap<SecretRef, String>,
}

impl StaticSecretResolver {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn insert(&mut self, reference: SecretRef, value: impl Into<String>) {
        self.secrets.insert(reference, value.into());
    }
}

impl SecretResolver for StaticSecretResolver {
    type Error = BrokerError;
    fn resolve(
        &self,
        secret: &SecretRef,
        _ctx: &SecretResolutionContext,
    ) -> Result<ResolvedSecret, Self::Error> {
        let value = self
            .secrets
            .get(secret)
            .cloned()
            .ok_or_else(|| BrokerError::SecretNotFound(secret.clone()))?;
        Ok(ResolvedSecret {
            reference: secret.clone(),
            value,
        })
    }
}

/// Resolves secrets from process environment variables (`env:NAME` or raw name). Fail-closed.
#[derive(Debug, Default, Clone, Copy)]
pub struct EnvSecretResolver;

impl SecretResolver for EnvSecretResolver {
    type Error = BrokerError;
    fn resolve(
        &self,
        secret: &SecretRef,
        _ctx: &SecretResolutionContext,
    ) -> Result<ResolvedSecret, Self::Error> {
        let name = secret.0.strip_prefix("env:").unwrap_or(&secret.0).trim();
        if name.is_empty() {
            return Err(BrokerError::SecretNotFound(secret.clone()));
        }
        match std::env::var(name) {
            Ok(v) if !v.is_empty() => Ok(ResolvedSecret {
                reference: secret.clone(),
                value: v,
            }),
            Ok(_) => Err(BrokerError::ResolutionFailed(format!(
                "empty env secret: {name}"
            ))),
            Err(_) => Err(BrokerError::SecretNotFound(secret.clone())),
        }
    }
}

/// Resolves secrets from files (`file:/path` or raw path). Fail-closed.
#[derive(Debug, Default, Clone, Copy)]
pub struct FileSecretResolver;

impl SecretResolver for FileSecretResolver {
    type Error = BrokerError;
    fn resolve(
        &self,
        secret: &SecretRef,
        _ctx: &SecretResolutionContext,
    ) -> Result<ResolvedSecret, Self::Error> {
        let path = secret.0.strip_prefix("file:").unwrap_or(&secret.0).trim();
        if path.is_empty() {
            return Err(BrokerError::SecretNotFound(secret.clone()));
        }
        let value = std::fs::read_to_string(path).map_err(|e| {
            BrokerError::ResolutionFailed(format!("file secret read failed for {path}: {e}"))
        })?;
        if value.is_empty() {
            return Err(BrokerError::ResolutionFailed(format!(
                "empty file secret: {path}"
            )));
        }
        Ok(ResolvedSecret {
            reference: secret.clone(),
            value,
        })
    }
}

/// Routes `env:` refs to env resolution and `file:` refs to file resolution.
/// Unknown schemes are fail-closed (`SecretNotFound`).
#[derive(Debug, Default, Clone, Copy)]
pub struct SchemeResolvingSecretResolver;

impl SecretResolver for SchemeResolvingSecretResolver {
    type Error = BrokerError;
    fn resolve(
        &self,
        secret: &SecretRef,
        ctx: &SecretResolutionContext,
    ) -> Result<ResolvedSecret, Self::Error> {
        let s = secret.0.trim();
        if s.starts_with("env:") {
            EnvSecretResolver.resolve(secret, ctx)
        } else if s.starts_with("file:") {
            FileSecretResolver.resolve(secret, ctx)
        } else {
            Err(BrokerError::SecretNotFound(secret.clone()))
        }
    }
}

/// Redaction rule applied to sensitive values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RedactionRule {
    /// Replace entire value with a fixed marker.
    Full { marker: String },
    /// Keep first `prefix` and last `suffix` chars, redact middle.
    KeepEdges {
        prefix: usize,
        suffix: usize,
        mask: char,
    },
}

/// Redaction policy composed of ordered rules (applied sequentially).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactionPolicy {
    pub rules: Vec<RedactionRule>,
}

impl Default for RedactionPolicy {
    fn default() -> Self {
        Self {
            rules: vec![RedactionRule::Full {
                marker: "[REDACTED]".to_string(),
            }],
        }
    }
}

impl RedactionPolicy {
    pub fn apply(&self, value: &str) -> String {
        let mut out = value.to_string();
        for rule in &self.rules {
            out = match rule {
                RedactionRule::Full { marker } => marker.clone(),
                RedactionRule::KeepEdges {
                    prefix,
                    suffix,
                    mask,
                } => {
                    let chars: Vec<char> = out.chars().collect();
                    if chars.len() <= prefix + suffix {
                        mask.to_string().repeat(chars.len().max(1))
                    } else {
                        let mut s = String::new();
                        for c in chars.iter().take(*prefix) {
                            s.push(*c);
                        }
                        for _ in 0..(chars.len() - prefix - suffix) {
                            s.push(*mask);
                        }
                        for c in chars.iter().skip(chars.len() - suffix) {
                            s.push(*c);
                        }
                        s
                    }
                }
            };
        }
        out
    }
}

/// Redactor abstraction (integration-ready).
pub trait Redactor {
    fn redact(&self, value: &str) -> String;
}

impl Redactor for RedactionPolicy {
    fn redact(&self, value: &str) -> String {
        self.apply(value)
    }
}

/// Scrubs known secret plaintext from request/response payload text.
/// Intended for live-path logging/forwarding safety; callers must register all
/// resolved sensitive values before redaction.
#[derive(Debug, Clone, Default)]
pub struct SecretScrubber {
    replacements: Vec<(String, String)>,
}

impl SecretScrubber {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a secret value and its redacted replacement. Empty secrets are ignored.
    pub fn register_secret(
        &mut self,
        secret_value: impl AsRef<str>,
        replacement: impl Into<String>,
    ) {
        let secret = secret_value.as_ref();
        if secret.is_empty() {
            return;
        }
        self.replacements
            .push((secret.to_string(), replacement.into()));
    }

    /// Register a resolved secret using the provided redaction policy.
    pub fn register_resolved(&mut self, resolved: &ResolvedSecret, policy: &RedactionPolicy) {
        self.register_secret(&resolved.value, policy.redact(&resolved.value));
    }

    /// Redact all registered secrets from request payload text.
    pub fn redact_request(&self, payload: &str) -> String {
        self.scrub(payload)
    }

    /// Redact all registered secrets from response payload text.
    pub fn redact_response(&self, payload: &str) -> String {
        self.scrub(payload)
    }

    /// Redact all registered secrets from arbitrary text.
    pub fn scrub(&self, payload: &str) -> String {
        let mut out = payload.to_string();
        // Prefer longer secrets first to avoid partial overlaps leaking suffixes.
        let mut reps = self.replacements.clone();
        reps.sort_by_key(|(s, _)| std::cmp::Reverse(s.len()));
        for (secret, replacement) in reps {
            if !secret.is_empty() {
                out = out.replace(&secret, &replacement);
            }
        }
        out
    }

    /// Scrub all registered secrets from string map values in-place (live-path request/response target).
    pub fn scrub_map(&self, target: &mut HashMap<String, String>) {
        for value in target.values_mut() {
            *value = self.scrub(value);
        }
    }

    /// Scrub all registered secrets from pair-list values in-place (live-path header/param target).
    pub fn scrub_pairs(&self, target: &mut [(String, String)]) {
        for (_, value) in target.iter_mut() {
            *value = self.scrub(value);
        }
    }
}

/// Hook target for injecting resolved secrets into upstream request representations.
pub trait SecretInjectionTarget {
    fn inject_secret_value(&mut self, key: &str, secret_value: &str);
}

impl SecretInjectionTarget for HashMap<String, String> {
    fn inject_secret_value(&mut self, key: &str, secret_value: &str) {
        self.insert(key.to_string(), secret_value.to_string());
    }
}

impl SecretInjectionTarget for Vec<(String, String)> {
    fn inject_secret_value(&mut self, key: &str, secret_value: &str) {
        self.push((key.to_string(), secret_value.to_string()));
    }
}

impl SecretInjectionTarget for String {
    fn inject_secret_value(&mut self, _key: &str, secret_value: &str) {
        *self = secret_value.to_string();
    }
}

/// Request for human/automated approval before proceeding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalRequest {
    pub id: String,
    pub principal: String,
    pub action: String,
    pub resource: String,
    pub reason: Option<String>,
}

/// Approval outcome. Timeout is treated as deny.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalStatus {
    Pending,
    Approved,
    Denied,
    TimedOut,
}

impl ApprovalStatus {
    /// Resolve status to an allow/deny decision. Timeout => deny.
    pub fn allows(self) -> bool {
        matches!(self, Self::Approved)
    }

    /// Normalize terminal timeout to explicit deny for downstream logic.
    pub fn effective(self) -> Self {
        match self {
            Self::TimedOut => Self::Denied,
            other => other,
        }
    }

    pub fn is_terminal(self) -> bool {
        !matches!(self, Self::Pending)
    }
}

/// In-memory approval record with optional expiry (unix ts seconds).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalRecord {
    pub request: ApprovalRequest,
    pub status: ApprovalStatus,
    pub expires_at: Option<u64>,
    /// Args hash binding placeholder (integration hook).
    pub args_hash: Option<String>,
}

/// Notification events emitted by approval queue behaviors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApprovalEvent {
    Created {
        id: String,
        expires_at: Option<u64>,
        args_hash: Option<String>,
    },
    Resolved {
        id: String,
        status: ApprovalStatus,
        effective: ApprovalStatus,
        idempotent: bool,
    },
    TimedOut {
        id: String,
    },
}

/// Hook for approval notifications (integration-ready).
pub trait ApprovalNotifier: Send + Sync {
    fn notify(&self, event: ApprovalEvent);
}

/// No-op notifier.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopApprovalNotifier;
impl ApprovalNotifier for NoopApprovalNotifier {
    fn notify(&self, _event: ApprovalEvent) {}
}

/// Event interface alias for integrations that prefer sink/listener naming.
pub trait ApprovalEventSink: ApprovalNotifier {}
impl<T: ApprovalNotifier + ?Sized> ApprovalEventSink for T {}

/// Notification channel stub for future Slack integration (no network I/O).
#[derive(Debug, Clone, Default)]
pub struct SlackNotifierStub {
    pub channel: Option<String>,
    pub events: std::sync::Arc<std::sync::Mutex<Vec<ApprovalEvent>>>,
}

impl SlackNotifierStub {
    pub fn new(channel: impl Into<String>) -> Self {
        Self {
            channel: Some(channel.into()),
            ..Self::default()
        }
    }
    pub fn payload_hint(&self, event: &ApprovalEvent) -> String {
        let ch = self.channel.as_deref().unwrap_or("#approvals");
        format!("slack:{ch}:{event:?}")
    }
}

impl ApprovalNotifier for SlackNotifierStub {
    fn notify(&self, event: ApprovalEvent) {
        if let Ok(mut events) = self.events.lock() {
            events.push(event);
        }
    }
}

/// Notification channel stub for future webhook integration (no network I/O).
#[derive(Debug, Clone, Default)]
pub struct WebhookNotifierStub {
    pub endpoint: Option<String>,
    pub events: std::sync::Arc<std::sync::Mutex<Vec<ApprovalEvent>>>,
}

impl WebhookNotifierStub {
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: Some(endpoint.into()),
            ..Self::default()
        }
    }
    pub fn payload_hint(&self, event: &ApprovalEvent) -> String {
        let ep = self.endpoint.as_deref().unwrap_or("<unset-webhook>");
        format!("webhook:{ep}:{event:?}")
    }
}

impl ApprovalNotifier for WebhookNotifierStub {
    fn notify(&self, event: ApprovalEvent) {
        if let Ok(mut events) = self.events.lock() {
            events.push(event);
        }
    }
}

/// Broadcast notifier for fanning out events to multiple channels/hooks.
#[derive(Clone, Default)]
pub struct BroadcastNotifier {
    sinks: Vec<Arc<dyn ApprovalNotifier>>,
}

impl fmt::Debug for BroadcastNotifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BroadcastNotifier")
            .field("sinks", &self.sinks.len())
            .finish()
    }
}

impl BroadcastNotifier {
    pub fn new(sinks: Vec<Arc<dyn ApprovalNotifier>>) -> Self {
        Self { sinks }
    }
}

impl ApprovalNotifier for BroadcastNotifier {
    fn notify(&self, event: ApprovalEvent) {
        for sink in &self.sinks {
            sink.notify(event.clone());
        }
    }
}

/// Approval persistence hook compatible with store-trait approval operations.
/// Implementations may bridge to `store::Store` (create/get/resolve approval records).
pub trait ApprovalPersistence: Send + Sync {
    type Error: fmt::Display + fmt::Debug + Send + Sync + 'static;

    /// Persist a newly created pending approval.
    fn persist_create(&self, record: &ApprovalRecord) -> Result<(), Self::Error>;
    /// Persist a resolved/terminal state transition (idempotent implementations recommended).
    fn persist_resolve(
        &self,
        id: &str,
        status: ApprovalStatus,
        effective: ApprovalStatus,
        resolver: Option<&str>,
        args_hash: Option<&str>,
    ) -> Result<(), Self::Error>;
    /// Persist timeout transition (effective deny).
    fn persist_timeout(&self, id: &str) -> Result<(), Self::Error>;
    /// Load a persisted approval record by id.
    fn load(&self, id: &str) -> Result<Option<ApprovalRecord>, Self::Error>;
}

/// Store-abstraction view of approval status for persistence bridges.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreApprovalStatus {
    Pending,
    Approved,
    Denied,
    Expired,
}

impl From<ApprovalStatus> for StoreApprovalStatus {
    fn from(status: ApprovalStatus) -> Self {
        match status {
            ApprovalStatus::Pending => Self::Pending,
            ApprovalStatus::Approved => Self::Approved,
            ApprovalStatus::Denied => Self::Denied,
            ApprovalStatus::TimedOut => Self::Expired,
        }
    }
}

impl From<StoreApprovalStatus> for ApprovalStatus {
    fn from(status: StoreApprovalStatus) -> Self {
        match status {
            StoreApprovalStatus::Pending => Self::Pending,
            StoreApprovalStatus::Approved => Self::Approved,
            StoreApprovalStatus::Denied => Self::Denied,
            StoreApprovalStatus::Expired => Self::TimedOut,
        }
    }
}

/// Store-abstraction approval record shape for bridging broker <-> store backends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreApprovalSnapshot {
    pub id: String,
    pub task_id: String,
    pub tool: String,
    pub args_hash: String,
    pub status: StoreApprovalStatus,
    pub created_at: String,
    pub resolved_at: Option<String>,
    pub resolver: Option<String>,
    pub principal: String,
    pub resource: String,
    pub reason: Option<String>,
    pub expires_at: Option<u64>,
}

impl From<&ApprovalRecord> for StoreApprovalSnapshot {
    fn from(rec: &ApprovalRecord) -> Self {
        Self {
            id: rec.request.id.clone(),
            task_id: rec.request.id.clone(),
            tool: rec.request.action.clone(),
            args_hash: rec.args_hash.clone().unwrap_or_default(),
            status: StoreApprovalStatus::from(rec.status),
            created_at: "0".to_string(),
            resolved_at: None,
            resolver: None,
            principal: rec.request.principal.clone(),
            resource: rec.request.resource.clone(),
            reason: rec.request.reason.clone(),
            expires_at: rec.expires_at,
        }
    }
}

impl TryFrom<StoreApprovalSnapshot> for ApprovalRecord {
    type Error = BrokerError;
    fn try_from(s: StoreApprovalSnapshot) -> Result<Self, Self::Error> {
        if s.id.trim().is_empty() {
            return Err(BrokerError::InvalidApprovalId);
        }
        Ok(Self {
            request: ApprovalRequest {
                id: s.id,
                principal: s.principal,
                action: s.tool,
                resource: s.resource,
                reason: s.reason,
            },
            status: ApprovalStatus::from(s.status),
            expires_at: s.expires_at,
            args_hash: if s.args_hash.is_empty() {
                None
            } else {
                Some(s.args_hash)
            },
        })
    }
}

/// Sync bridge to store-style approval operations (adapter layer over store abstractions).
pub trait StoreApprovalBridge: Send + Sync {
    type Error: fmt::Display + fmt::Debug + Send + Sync + 'static;
    fn create(&self, approval: StoreApprovalSnapshot)
        -> Result<StoreApprovalSnapshot, Self::Error>;
    fn get(&self, id: &str) -> Result<Option<StoreApprovalSnapshot>, Self::Error>;
    fn resolve(
        &self,
        id: &str,
        status: StoreApprovalStatus,
        resolver: Option<String>,
        resolved_at: Option<String>,
        args_hash: Option<String>,
    ) -> Result<StoreApprovalSnapshot, Self::Error>;
}

/// Adapter that exposes a `StoreApprovalBridge` as broker `ApprovalPersistence`.
#[derive(Clone)]
pub struct StoreApprovalPersistenceAdapter<B> {
    bridge: Arc<B>,
}

impl<B> StoreApprovalPersistenceAdapter<B> {
    pub fn new(bridge: Arc<B>) -> Self {
        Self { bridge }
    }
}

impl<B> ApprovalPersistence for StoreApprovalPersistenceAdapter<B>
where
    B: StoreApprovalBridge,
    B::Error: fmt::Display + fmt::Debug + Send + Sync + 'static,
{
    type Error = BrokerError;
    fn persist_create(&self, record: &ApprovalRecord) -> Result<(), Self::Error> {
        self.bridge
            .create(StoreApprovalSnapshot::from(record))
            .map(|_| ())
            .map_err(|e| BrokerError::PersistenceFailed(e.to_string()))
    }
    fn persist_resolve(
        &self,
        id: &str,
        _status: ApprovalStatus,
        effective: ApprovalStatus,
        resolver: Option<&str>,
        args_hash: Option<&str>,
    ) -> Result<(), Self::Error> {
        self.bridge
            .resolve(
                id,
                StoreApprovalStatus::from(effective),
                resolver.map(str::to_string),
                Some("0".to_string()),
                args_hash.map(str::to_string),
            )
            .map(|_| ())
            .map_err(|e| BrokerError::PersistenceFailed(e.to_string()))
    }
    fn persist_timeout(&self, id: &str) -> Result<(), Self::Error> {
        self.persist_resolve(
            id,
            ApprovalStatus::TimedOut,
            ApprovalStatus::Denied,
            None,
            None,
        )
    }
    fn load(&self, id: &str) -> Result<Option<ApprovalRecord>, Self::Error> {
        let snap = self
            .bridge
            .get(id)
            .map_err(|e| BrokerError::PersistenceFailed(e.to_string()))?;
        snap.map(ApprovalRecord::try_from).transpose()
    }
}

/// No-op persistence hook.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopApprovalPersistence;
impl ApprovalPersistence for NoopApprovalPersistence {
    type Error = BrokerError;
    fn persist_create(&self, _record: &ApprovalRecord) -> Result<(), Self::Error> {
        Ok(())
    }
    fn persist_resolve(
        &self,
        _id: &str,
        _status: ApprovalStatus,
        _effective: ApprovalStatus,
        _resolver: Option<&str>,
        _args_hash: Option<&str>,
    ) -> Result<(), Self::Error> {
        Ok(())
    }
    fn persist_timeout(&self, _id: &str) -> Result<(), Self::Error> {
        Ok(())
    }
    fn load(&self, _id: &str) -> Result<Option<ApprovalRecord>, Self::Error> {
        Ok(None)
    }
}

/// Async persistence hook for durable approval lifecycle integration.
#[async_trait]
pub trait AsyncApprovalPersistence: Send + Sync {
    type Error: fmt::Display + fmt::Debug + Send + Sync + 'static;

    /// Persist a newly created pending approval.
    async fn persist_create(&self, record: &ApprovalRecord) -> Result<(), Self::Error>;
    /// Persist a resolved/terminal state transition (idempotent implementations recommended).
    async fn persist_resolve(
        &self,
        id: &str,
        status: ApprovalStatus,
        effective: ApprovalStatus,
        resolver: Option<&str>,
        args_hash: Option<&str>,
    ) -> Result<(), Self::Error>;
    /// Persist timeout transition (effective deny).
    async fn persist_timeout(&self, id: &str) -> Result<(), Self::Error>;
    /// Load a persisted approval record by id (if supported by backend).
    async fn load(&self, id: &str) -> Result<Option<ApprovalRecord>, Self::Error>;
}

/// No-op async persistence hook.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopAsyncApprovalPersistence;

#[async_trait]
impl AsyncApprovalPersistence for NoopAsyncApprovalPersistence {
    type Error = BrokerError;

    async fn persist_create(&self, _record: &ApprovalRecord) -> Result<(), Self::Error> {
        Ok(())
    }

    async fn persist_resolve(
        &self,
        _id: &str,
        _status: ApprovalStatus,
        _effective: ApprovalStatus,
        _resolver: Option<&str>,
        _args_hash: Option<&str>,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    async fn persist_timeout(&self, _id: &str) -> Result<(), Self::Error> {
        Ok(())
    }

    async fn load(&self, _id: &str) -> Result<Option<ApprovalRecord>, Self::Error> {
        Ok(None)
    }
}

fn broker_to_store_approval_status(status: ApprovalStatus) -> store::ApprovalStatus {
    match status {
        ApprovalStatus::Pending => store::ApprovalStatus::Pending,
        ApprovalStatus::Approved => store::ApprovalStatus::Approved,
        ApprovalStatus::Denied => store::ApprovalStatus::Denied,
        ApprovalStatus::TimedOut => store::ApprovalStatus::Expired,
    }
}

fn store_to_broker_approval_status(status: store::ApprovalStatus) -> ApprovalStatus {
    match status {
        store::ApprovalStatus::Pending => ApprovalStatus::Pending,
        store::ApprovalStatus::Approved => ApprovalStatus::Approved,
        store::ApprovalStatus::Denied => ApprovalStatus::Denied,
        store::ApprovalStatus::Expired => ApprovalStatus::TimedOut,
    }
}

fn broker_record_to_store_approval(record: &ApprovalRecord) -> store::ApprovalRecord {
    store::ApprovalRecord {
        id: record.request.id.clone(),
        task_id: record.request.id.clone(),
        tool: record.request.action.clone(),
        args_hash: record.args_hash.clone().unwrap_or_default(),
        status: broker_to_store_approval_status(record.status),
        created_at: "0".to_string(),
        resolved_at: None,
        resolver: None,
    }
}

fn store_approval_to_broker_record(record: store::ApprovalRecord) -> ApprovalRecord {
    ApprovalRecord {
        request: ApprovalRequest {
            id: record.id.clone(),
            principal: "unknown".to_string(),
            action: record.tool.clone(),
            resource: record.tool,
            reason: None,
        },
        status: store_to_broker_approval_status(record.status),
        expires_at: None,
        args_hash: if record.args_hash.is_empty() {
            None
        } else {
            Some(record.args_hash)
        },
    }
}

/// Concrete async persistence adapter/bridge backed by a `store::Store` implementation.
///
/// Maps broker approval lifecycle operations onto the current store approval API.
/// Fields not represented in the store schema (principal/resource/reason/expires_at)
/// are restored with conservative placeholders on load; timeout persistence uses the
/// store `Expired` status.
#[derive(Clone)]
pub struct StoreBackedAsyncApprovalPersistence<S: store::Store + ?Sized> {
    store: Arc<S>,
}

impl<S: store::Store + ?Sized> StoreBackedAsyncApprovalPersistence<S> {
    pub fn new(store: Arc<S>) -> Self {
        Self { store }
    }
}

impl<S: store::Store + ?Sized> fmt::Debug for StoreBackedAsyncApprovalPersistence<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StoreBackedAsyncApprovalPersistence")
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl<S: store::Store + Send + Sync + ?Sized + 'static> AsyncApprovalPersistence
    for StoreBackedAsyncApprovalPersistence<S>
{
    type Error = BrokerError;

    async fn persist_create(&self, record: &ApprovalRecord) -> Result<(), Self::Error> {
        let store_rec = broker_record_to_store_approval(record);
        match self.store.create_approval(store_rec).await {
            Ok(_) => Ok(()),
            Err(e) => {
                // Idempotent create hook: tolerate existing compatible records.
                if matches!(e, store::StoreError::Conflict(_)) {
                    if let Some(existing) = self
                        .store
                        .get_approval(&record.request.id)
                        .await
                        .map_err(|e| BrokerError::PersistenceFailed(e.to_string()))?
                    {
                        let desired = broker_to_store_approval_status(record.status);
                        if existing.status == desired
                            && existing.tool == record.request.action
                            && existing.args_hash == record.args_hash.clone().unwrap_or_default()
                        {
                            return Ok(());
                        }
                    }
                }
                Err(BrokerError::PersistenceFailed(e.to_string()))
            }
        }
    }

    async fn persist_resolve(
        &self,
        id: &str,
        _status: ApprovalStatus,
        effective: ApprovalStatus,
        resolver: Option<&str>,
        _args_hash: Option<&str>,
    ) -> Result<(), Self::Error> {
        let effective = effective.effective();
        let desired_store_status = broker_to_store_approval_status(effective);
        let existing = self
            .store
            .get_approval(id)
            .await
            .map_err(|e| BrokerError::PersistenceFailed(e.to_string()))?
            .ok_or_else(|| {
                BrokerError::PersistenceFailed(format!("approval not found in store: {id}"))
            })?;
        if existing.status != store::ApprovalStatus::Pending {
            let same_terminal = match effective {
                ApprovalStatus::Approved => existing.status == store::ApprovalStatus::Approved,
                ApprovalStatus::Denied => matches!(
                    existing.status,
                    store::ApprovalStatus::Denied | store::ApprovalStatus::Expired
                ),
                ApprovalStatus::Pending | ApprovalStatus::TimedOut => false,
            };
            if same_terminal {
                return Ok(());
            }
            return Err(BrokerError::PersistenceFailed(format!(
                "conflicting terminal state for approval {id}"
            )));
        }

        match self
            .store
            .resolve_approval(
                id,
                desired_store_status,
                resolver.map(str::to_string),
                "0".to_string(),
            )
            .await
        {
            Ok(_) => Ok(()),
            Err(e) => {
                // Re-read for idempotent/conflicting terminal outcomes (race-safe hook).
                if let Some(existing) = self
                    .store
                    .get_approval(id)
                    .await
                    .map_err(|e| BrokerError::PersistenceFailed(e.to_string()))?
                {
                    let same_terminal = match effective {
                        ApprovalStatus::Approved => {
                            existing.status == store::ApprovalStatus::Approved
                        }
                        ApprovalStatus::Denied => matches!(
                            existing.status,
                            store::ApprovalStatus::Denied | store::ApprovalStatus::Expired
                        ),
                        ApprovalStatus::Pending | ApprovalStatus::TimedOut => false,
                    };
                    if same_terminal {
                        return Ok(());
                    }
                }
                Err(BrokerError::PersistenceFailed(e.to_string()))
            }
        }
    }

    async fn persist_timeout(&self, id: &str) -> Result<(), Self::Error> {
        let desired_store_status = store::ApprovalStatus::Expired;
        let existing = self
            .store
            .get_approval(id)
            .await
            .map_err(|e| BrokerError::PersistenceFailed(e.to_string()))?
            .ok_or_else(|| {
                BrokerError::PersistenceFailed(format!("approval not found in store: {id}"))
            })?;
        if existing.status != store::ApprovalStatus::Pending {
            if matches!(
                existing.status,
                store::ApprovalStatus::Denied | store::ApprovalStatus::Expired
            ) {
                return Ok(());
            }
            return Err(BrokerError::PersistenceFailed(format!(
                "conflicting terminal state for approval {id}"
            )));
        }

        match self
            .store
            .resolve_approval(id, desired_store_status, None, "0".to_string())
            .await
        {
            Ok(_) => Ok(()),
            Err(e) => {
                if let Some(existing) = self
                    .store
                    .get_approval(id)
                    .await
                    .map_err(|e| BrokerError::PersistenceFailed(e.to_string()))?
                {
                    if matches!(
                        existing.status,
                        store::ApprovalStatus::Denied | store::ApprovalStatus::Expired
                    ) {
                        return Ok(());
                    }
                }
                Err(BrokerError::PersistenceFailed(e.to_string()))
            }
        }
    }

    async fn load(&self, id: &str) -> Result<Option<ApprovalRecord>, Self::Error> {
        let rec = self
            .store
            .get_approval(id)
            .await
            .map_err(|e| BrokerError::PersistenceFailed(e.to_string()))?;
        Ok(rec.map(store_approval_to_broker_record))
    }
}

/// Metadata for richer approval workflow resolution.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ApprovalDecisionMeta {
    pub resolver: Option<String>,
    pub args_hash: Option<String>,
    /// When true, provided/bound args hash must match (fail-closed on mismatch/missing when bound).
    pub enforce_args_hash_binding: bool,
}

/// Effective approval decision snapshot for gateway/runtime callers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalDecision {
    pub id: String,
    pub status: ApprovalStatus,
    pub effective: ApprovalStatus,
}

impl ApprovalDecision {
    pub fn allows(self) -> bool {
        self.effective.allows()
    }
}

/// Simple in-memory approval queue. Terminal states reject conflicting re-resolution;
/// `resolve` is idempotent for same effective outcome. Timeout => deny.
#[derive(Clone, Default)]
pub struct ApprovalQueue {
    records: HashMap<String, ApprovalRecord>,
    notifier: Option<Arc<dyn ApprovalNotifier>>,
    persistence: Option<Arc<dyn ApprovalPersistence<Error = BrokerError>>>,
    async_persistence: Option<Arc<dyn AsyncApprovalPersistence<Error = BrokerError>>>,
    /// Pause/resume runtime signals keyed by approval id; notified on terminal transitions.
    signals: HashMap<String, Arc<Notify>>,
}

impl fmt::Debug for ApprovalQueue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApprovalQueue")
            .field("records", &self.records)
            .field("notifier", &self.notifier.as_ref().map(|_| "<hook>"))
            .field("persistence", &self.persistence.as_ref().map(|_| "<hook>"))
            .field(
                "async_persistence",
                &self.async_persistence.as_ref().map(|_| "<hook>"),
            )
            .field("signals", &self.signals.len())
            .finish()
    }
}

impl ApprovalQueue {
    pub fn new() -> Self {
        Self::default()
    }

    /// Attach a notifications hook.
    pub fn with_notifier(mut self, notifier: Arc<dyn ApprovalNotifier>) -> Self {
        self.notifier = Some(notifier);
        self
    }

    pub fn set_notifier(&mut self, notifier: Arc<dyn ApprovalNotifier>) {
        self.notifier = Some(notifier);
    }

    /// Attach an approval persistence hook compatible with store-backed persistence flows.
    pub fn with_persistence(
        mut self,
        persistence: Arc<dyn ApprovalPersistence<Error = BrokerError>>,
    ) -> Self {
        self.persistence = Some(persistence);
        self
    }

    pub fn set_persistence(
        &mut self,
        persistence: Arc<dyn ApprovalPersistence<Error = BrokerError>>,
    ) {
        self.persistence = Some(persistence);
    }

    /// Attach an async approval persistence hook (e.g. store-backed bridge).
    pub fn with_async_persistence(
        mut self,
        persistence: Arc<dyn AsyncApprovalPersistence<Error = BrokerError>>,
    ) -> Self {
        self.async_persistence = Some(persistence);
        self
    }

    pub fn set_async_persistence(
        &mut self,
        persistence: Arc<dyn AsyncApprovalPersistence<Error = BrokerError>>,
    ) {
        self.async_persistence = Some(persistence);
    }

    fn emit(&self, event: ApprovalEvent) {
        if let Some(n) = &self.notifier {
            n.notify(event);
        }
    }

    fn persist_err<E: fmt::Display>(e: E) -> BrokerError {
        BrokerError::PersistenceFailed(e.to_string())
    }

    /// Returns a pause/resume signal for `id`, creating it if missing.
    /// Gateway callers can await `notified()` while polling/evaluating for terminal decisions.
    pub fn resume_signal(&mut self, id: &str) -> Arc<Notify> {
        self.signals
            .entry(id.to_string())
            .or_insert_with(|| Arc::new(Notify::new()))
            .clone()
    }

    /// Returns an existing pause/resume signal for `id`, if any.
    pub fn resume_signal_if_exists(&self, id: &str) -> Option<Arc<Notify>> {
        self.signals.get(id).cloned()
    }

    /// Notify waiters that approval state may have progressed (e.g. resolved/timed out).
    pub fn notify_resume(&self, id: &str) {
        if let Some(s) = self.signals.get(id) {
            s.notify_waiters();
        }
    }

    /// Create/register a pending approval request.
    pub fn create(
        &mut self,
        request: ApprovalRequest,
        expires_at: Option<u64>,
    ) -> Result<(), BrokerError> {
        self.create_with_binding(request, expires_at, None)
    }

    /// Create/register a pending approval request with args hash binding placeholder.
    pub fn create_with_binding(
        &mut self,
        request: ApprovalRequest,
        expires_at: Option<u64>,
        args_hash: Option<String>,
    ) -> Result<(), BrokerError> {
        if request.id.trim().is_empty() {
            return Err(BrokerError::InvalidApprovalId);
        }
        if self.records.contains_key(&request.id) {
            return Err(BrokerError::DuplicateApproval(request.id));
        }
        let id = request.id.clone();
        let record = ApprovalRecord {
            request,
            status: ApprovalStatus::Pending,
            expires_at,
            args_hash: args_hash.clone(),
        };
        if let Some(p) = &self.persistence {
            p.persist_create(&record).map_err(Self::persist_err)?;
        }
        self.records.insert(id.clone(), record);
        self.emit(ApprovalEvent::Created {
            id,
            expires_at,
            args_hash,
        });
        Ok(())
    }

    pub fn get(&self, id: &str) -> Option<&ApprovalRecord> {
        self.records.get(id)
    }

    /// List pending approvals, expiring any whose deadline has passed.
    /// Uses best-effort timeout persistence; see `try_pending` for fail-closed behavior.
    pub fn pending(&mut self, now: u64) -> Vec<ApprovalRequest> {
        let _ = self.try_expire_timeouts(now);
        self.records
            .values()
            .filter(|r| r.status == ApprovalStatus::Pending)
            .map(|r| r.request.clone())
            .collect()
    }

    /// Fail-closed variant of `pending` that propagates timeout persistence errors.
    pub fn try_pending(&mut self, now: u64) -> Result<Vec<ApprovalRequest>, BrokerError> {
        self.try_expire_timeouts(now)?;
        Ok(self
            .records
            .values()
            .filter(|r| r.status == ApprovalStatus::Pending)
            .map(|r| r.request.clone())
            .collect())
    }

    /// Resolve a pending request. Idempotent if request is already terminal and the
    /// requested resolution normalizes to the same effective outcome.
    pub fn resolve(
        &mut self,
        id: &str,
        status: ApprovalStatus,
        now: u64,
    ) -> Result<ApprovalStatus, BrokerError> {
        self.resolve_with_meta(id, status, now, ApprovalDecisionMeta::default())
    }

    /// Resolve with richer workflow metadata (resolver/args-hash binding).
    /// Fail-closed: invalid resolution, missing approval, args-hash mismatch when enforced.
    pub fn resolve_with_meta(
        &mut self,
        id: &str,
        status: ApprovalStatus,
        now: u64,
        meta: ApprovalDecisionMeta,
    ) -> Result<ApprovalStatus, BrokerError> {
        self.try_expire_timeouts(now)?;
        let desired = match status {
            ApprovalStatus::Pending => return Err(BrokerError::InvalidResolution),
            ApprovalStatus::Approved => ApprovalStatus::Approved,
            ApprovalStatus::Denied | ApprovalStatus::TimedOut => ApprovalStatus::Denied,
        };
        let (current_status, current_effective, bound_args_hash, is_terminal) = {
            let rec = self
                .records
                .get(id)
                .ok_or_else(|| BrokerError::ApprovalNotFound(id.to_string()))?;
            (
                rec.status,
                rec.status.effective(),
                rec.args_hash.clone(),
                rec.status.is_terminal(),
            )
        };
        if meta.enforce_args_hash_binding
            && !Self::args_hash_binding_ok(bound_args_hash.as_deref(), meta.args_hash.as_deref())
        {
            return Err(BrokerError::InjectionDenied(format!(
                "args hash binding mismatch for approval {id}"
            )));
        }
        let persist_args_hash = meta.args_hash.as_deref().or(bound_args_hash.as_deref());
        if is_terminal && current_effective == desired {
            if let Some(p) = &self.persistence {
                p.persist_resolve(
                    id,
                    current_status,
                    current_effective,
                    meta.resolver.as_deref(),
                    persist_args_hash,
                )
                .map_err(Self::persist_err)?;
            }
            self.emit(ApprovalEvent::Resolved {
                id: id.to_string(),
                status: current_status,
                effective: current_effective,
                idempotent: true,
            });
            self.notify_resume(id);
            return Ok(current_effective);
        }
        if is_terminal {
            return Err(BrokerError::ApprovalAlreadyTerminal(id.to_string()));
        }
        if let Some(p) = &self.persistence {
            p.persist_resolve(
                id,
                desired,
                desired.effective(),
                meta.resolver.as_deref(),
                persist_args_hash,
            )
            .map_err(Self::persist_err)?;
        }
        let effective = {
            let rec = self
                .records
                .get_mut(id)
                .ok_or_else(|| BrokerError::ApprovalNotFound(id.to_string()))?;
            rec.status = desired;
            rec.status.effective()
        };
        self.emit(ApprovalEvent::Resolved {
            id: id.to_string(),
            status: desired,
            effective,
            idempotent: false,
        });
        self.notify_resume(id);
        Ok(effective)
    }

    /// Explicit idempotent resolve helper (same behavior as `resolve`).
    pub fn resolve_idempotent(
        &mut self,
        id: &str,
        status: ApprovalStatus,
        now: u64,
    ) -> Result<ApprovalStatus, BrokerError> {
        self.resolve(id, status, now)
    }

    fn args_hash_binding_ok(bound: Option<&str>, provided: Option<&str>) -> bool {
        match (bound, provided) {
            (None, _) => true,
            (Some(b), Some(p)) => b == p,
            (Some(_), None) => false,
        }
    }

    /// Fail-closed args-hash binding check for request-time credential/approval flows.
    pub fn require_args_hash_binding(
        &self,
        id: &str,
        args_hash: Option<&str>,
    ) -> Result<(), BrokerError> {
        match self.args_hash_matches(id, args_hash) {
            Some(true) => Ok(()),
            Some(false) => Err(BrokerError::InjectionDenied(format!(
                "args hash binding mismatch for approval {id}"
            ))),
            None => Err(BrokerError::ApprovalNotFound(id.to_string())),
        }
    }

    pub fn records(&self) -> impl Iterator<Item = &ApprovalRecord> {
        self.records.values()
    }

    /// Return a cloned snapshot of all records (gateway/runtime-friendly).
    pub fn snapshot(&self) -> Vec<ApprovalRecord> {
        self.records.values().cloned().collect()
    }

    /// Gateway/runtime convenience: evaluate current effective decision for an approval.
    /// Expires pending approvals as needed, then enforces args-hash binding when provided.
    pub fn evaluate(
        &mut self,
        id: &str,
        now: u64,
        args_hash: Option<&str>,
    ) -> Result<ApprovalDecision, BrokerError> {
        let effective = self
            .try_effective_status(id, now)?
            .ok_or_else(|| BrokerError::ApprovalNotFound(id.to_string()))?;
        if args_hash.is_some() || self.get(id).and_then(|r| r.args_hash.as_ref()).is_some() {
            self.require_args_hash_binding(id, args_hash)?;
        }
        Ok(ApprovalDecision {
            id: id.to_string(),
            status: self.get(id).map(|r| r.status).unwrap_or(effective),
            effective,
        })
    }

    /// Mark expired pending approvals as TimedOut (effective deny).
    /// Persistence hook failures are surfaced as `BrokerError` when using `try_expire_timeouts`.
    pub fn expire_timeouts(&mut self, now: u64) {
        let _ = self.try_expire_timeouts(now);
    }

    /// Mark expired pending approvals as TimedOut (effective deny), failing closed on
    /// persistence errors.
    pub fn try_expire_timeouts(&mut self, now: u64) -> Result<Vec<String>, BrokerError> {
        let timed_out_ids: Vec<String> = self
            .records
            .iter()
            .filter_map(|(id, rec)| {
                if rec.status == ApprovalStatus::Pending
                    && rec.expires_at.is_some_and(|exp| now >= exp)
                {
                    return Some(id.clone());
                }
                None
            })
            .collect();
        for id in &timed_out_ids {
            if let Some(p) = &self.persistence {
                p.persist_timeout(id).map_err(Self::persist_err)?;
            }
        }
        for id in &timed_out_ids {
            if let Some(rec) = self.records.get_mut(id) {
                if rec.status == ApprovalStatus::Pending {
                    rec.status = ApprovalStatus::TimedOut;
                }
            }
            self.emit(ApprovalEvent::TimedOut { id: id.clone() });
            self.notify_resume(id);
        }
        Ok(timed_out_ids)
    }

    /// Effective status for decisioning (timeout normalized to deny). Expires if needed.
    pub fn effective_status(&mut self, id: &str, now: u64) -> Option<ApprovalStatus> {
        let _ = self.try_expire_timeouts(now);
        self.records.get(id).map(|r| r.status.effective())
    }

    /// Fail-closed variant of `effective_status`.
    pub fn try_effective_status(
        &mut self,
        id: &str,
        now: u64,
    ) -> Result<Option<ApprovalStatus>, BrokerError> {
        self.try_expire_timeouts(now)?;
        Ok(self.records.get(id).map(|r| r.status.effective()))
    }

    /// Args-hash binding hook: returns true when no binding is recorded or hashes match.
    /// Gateway can use this before honoring an approval for a specific request payload.
    pub fn args_hash_matches(&self, id: &str, args_hash: Option<&str>) -> Option<bool> {
        self.records
            .get(id)
            .map(|r| match (&r.args_hash, args_hash) {
                (None, _) => true,
                (Some(bound), Some(provided)) => bound == provided,
                (Some(_), None) => false,
            })
    }

    /// Load a single approval from the configured persistence hook and upsert into memory.
    pub fn rehydrate(&mut self, id: &str) -> Result<Option<ApprovalRecord>, BrokerError> {
        let Some(p) = &self.persistence else {
            return Ok(self.records.get(id).cloned());
        };
        if let Some(rec) = p.load(id).map_err(Self::persist_err)? {
            let merged = Self::merge_rehydrated_record(self.records.get(id), rec);
            self.records
                .insert(merged.request.id.clone(), merged.clone());
            return Ok(Some(merged));
        }
        Ok(None)
    }

    fn merge_rehydrated_record(
        existing: Option<&ApprovalRecord>,
        mut loaded: ApprovalRecord,
    ) -> ApprovalRecord {
        let Some(existing) = existing else {
            return loaded;
        };
        // Preserve richer in-memory request metadata when durable adapters return placeholders.
        if loaded.request.principal == "unknown" {
            loaded.request.principal = existing.request.principal.clone();
        }
        if (loaded.request.resource.is_empty() || loaded.request.resource == loaded.request.action)
            && (existing.request.resource != existing.request.action
                || !existing.request.resource.is_empty())
        {
            loaded.request.resource = existing.request.resource.clone();
        }
        if loaded.request.reason.is_none() {
            loaded.request.reason = existing.request.reason.clone();
        }
        if loaded.expires_at.is_none() {
            loaded.expires_at = existing.expires_at;
        }
        loaded
    }
}

impl ApprovalQueue {
    async fn persist_create_async(&self, record: &ApprovalRecord) -> Result<(), BrokerError> {
        if let Some(p) = &self.async_persistence {
            p.persist_create(record).await.map_err(Self::persist_err)?;
        } else if let Some(p) = &self.persistence {
            p.persist_create(record).map_err(Self::persist_err)?;
        }
        Ok(())
    }

    async fn persist_resolve_async(
        &self,
        id: &str,
        status: ApprovalStatus,
        effective: ApprovalStatus,
        resolver: Option<&str>,
        args_hash: Option<&str>,
    ) -> Result<(), BrokerError> {
        if let Some(p) = &self.async_persistence {
            p.persist_resolve(id, status, effective, resolver, args_hash)
                .await
                .map_err(Self::persist_err)?;
        } else if let Some(p) = &self.persistence {
            p.persist_resolve(id, status, effective, resolver, args_hash)
                .map_err(Self::persist_err)?;
        }
        Ok(())
    }

    async fn persist_timeout_async(&self, id: &str) -> Result<(), BrokerError> {
        if let Some(p) = &self.async_persistence {
            p.persist_timeout(id).await.map_err(Self::persist_err)?;
        } else if let Some(p) = &self.persistence {
            p.persist_timeout(id).map_err(Self::persist_err)?;
        }
        Ok(())
    }

    async fn load_async(&self, id: &str) -> Result<Option<ApprovalRecord>, BrokerError> {
        if let Some(p) = &self.async_persistence {
            return p.load(id).await.map_err(Self::persist_err);
        }
        if let Some(p) = &self.persistence {
            return p.load(id).map_err(Self::persist_err);
        }
        Ok(None)
    }

    /// Async create/register flow with async store-backed persistence hook support.
    pub async fn create_async(
        &mut self,
        request: ApprovalRequest,
        expires_at: Option<u64>,
    ) -> Result<(), BrokerError> {
        self.create_with_binding_async(request, expires_at, None)
            .await
    }

    /// Async create/register flow with args hash binding and async persistence hooks.
    pub async fn create_with_binding_async(
        &mut self,
        request: ApprovalRequest,
        expires_at: Option<u64>,
        args_hash: Option<String>,
    ) -> Result<(), BrokerError> {
        if request.id.trim().is_empty() {
            return Err(BrokerError::InvalidApprovalId);
        }
        if self.records.contains_key(&request.id) {
            return Err(BrokerError::DuplicateApproval(request.id));
        }
        let id = request.id.clone();
        let record = ApprovalRecord {
            request,
            status: ApprovalStatus::Pending,
            expires_at,
            args_hash: args_hash.clone(),
        };
        self.persist_create_async(&record).await?;
        self.records.insert(id.clone(), record);
        self.resume_signal(&id);
        self.emit(ApprovalEvent::Created {
            id,
            expires_at,
            args_hash,
        });
        Ok(())
    }

    /// Mark expired pending approvals as TimedOut (effective deny), failing closed on
    /// persistence errors. Uses async persistence hooks when configured.
    pub async fn try_expire_timeouts_async(
        &mut self,
        now: u64,
    ) -> Result<Vec<String>, BrokerError> {
        let timed_out_ids: Vec<String> = self
            .records
            .iter()
            .filter_map(|(id, rec)| {
                if rec.status == ApprovalStatus::Pending
                    && rec.expires_at.is_some_and(|exp| now >= exp)
                {
                    return Some(id.clone());
                }
                None
            })
            .collect();
        for id in &timed_out_ids {
            self.persist_timeout_async(id).await?;
        }
        for id in &timed_out_ids {
            if let Some(rec) = self.records.get_mut(id) {
                if rec.status == ApprovalStatus::Pending {
                    rec.status = ApprovalStatus::TimedOut;
                }
            }
            self.emit(ApprovalEvent::TimedOut { id: id.clone() });
            self.notify_resume(id);
        }
        Ok(timed_out_ids)
    }

    /// Async fail-closed pending listing with timeout hooks.
    pub async fn try_pending_async(
        &mut self,
        now: u64,
    ) -> Result<Vec<ApprovalRequest>, BrokerError> {
        self.try_expire_timeouts_async(now).await?;
        Ok(self
            .records
            .values()
            .filter(|r| r.status == ApprovalStatus::Pending)
            .map(|r| r.request.clone())
            .collect())
    }

    /// Async resolve flow using async store-backed persistence hooks when configured.
    pub async fn resolve_async(
        &mut self,
        id: &str,
        status: ApprovalStatus,
        now: u64,
    ) -> Result<ApprovalStatus, BrokerError> {
        self.resolve_with_meta_async(id, status, now, ApprovalDecisionMeta::default())
            .await
    }

    /// Async resolve flow with metadata and async persistence hooks.
    pub async fn resolve_with_meta_async(
        &mut self,
        id: &str,
        status: ApprovalStatus,
        now: u64,
        meta: ApprovalDecisionMeta,
    ) -> Result<ApprovalStatus, BrokerError> {
        self.try_expire_timeouts_async(now).await?;
        let desired = match status {
            ApprovalStatus::Pending => return Err(BrokerError::InvalidResolution),
            ApprovalStatus::Approved => ApprovalStatus::Approved,
            ApprovalStatus::Denied | ApprovalStatus::TimedOut => ApprovalStatus::Denied,
        };
        let (current_status, current_effective, bound_args_hash, is_terminal) = {
            let rec = self
                .records
                .get(id)
                .ok_or_else(|| BrokerError::ApprovalNotFound(id.to_string()))?;
            (
                rec.status,
                rec.status.effective(),
                rec.args_hash.clone(),
                rec.status.is_terminal(),
            )
        };
        if meta.enforce_args_hash_binding
            && !Self::args_hash_binding_ok(bound_args_hash.as_deref(), meta.args_hash.as_deref())
        {
            return Err(BrokerError::InjectionDenied(format!(
                "args hash binding mismatch for approval {id}"
            )));
        }
        let persist_args_hash = meta.args_hash.as_deref().or(bound_args_hash.as_deref());
        if is_terminal && current_effective == desired {
            self.persist_resolve_async(
                id,
                current_status,
                current_effective,
                meta.resolver.as_deref(),
                persist_args_hash,
            )
            .await?;
            self.emit(ApprovalEvent::Resolved {
                id: id.to_string(),
                status: current_status,
                effective: current_effective,
                idempotent: true,
            });
            self.notify_resume(id);
            return Ok(current_effective);
        }
        if is_terminal {
            return Err(BrokerError::ApprovalAlreadyTerminal(id.to_string()));
        }
        self.persist_resolve_async(
            id,
            desired,
            desired.effective(),
            meta.resolver.as_deref(),
            persist_args_hash,
        )
        .await?;
        let effective = {
            let rec = self
                .records
                .get_mut(id)
                .ok_or_else(|| BrokerError::ApprovalNotFound(id.to_string()))?;
            rec.status = desired;
            rec.status.effective()
        };
        self.emit(ApprovalEvent::Resolved {
            id: id.to_string(),
            status: desired,
            effective,
            idempotent: false,
        });
        self.notify_resume(id);
        Ok(effective)
    }

    /// Async fail-closed effective status with timeout hooks.
    pub async fn try_effective_status_async(
        &mut self,
        id: &str,
        now: u64,
    ) -> Result<Option<ApprovalStatus>, BrokerError> {
        self.try_expire_timeouts_async(now).await?;
        Ok(self.records.get(id).map(|r| r.status.effective()))
    }

    /// Async evaluation with timeout hooks and args-hash binding enforcement.
    pub async fn evaluate_async(
        &mut self,
        id: &str,
        now: u64,
        args_hash: Option<&str>,
    ) -> Result<ApprovalDecision, BrokerError> {
        let effective = self
            .try_effective_status_async(id, now)
            .await?
            .ok_or_else(|| BrokerError::ApprovalNotFound(id.to_string()))?;
        if args_hash.is_some() || self.get(id).and_then(|r| r.args_hash.as_ref()).is_some() {
            self.require_args_hash_binding(id, args_hash)?;
        }
        Ok(ApprovalDecision {
            id: id.to_string(),
            status: self.get(id).map(|r| r.status).unwrap_or(effective),
            effective,
        })
    }

    /// Store-backed reconciliation helper: rehydrate and apply timeout/idempotent terminal state.
    /// Alias for `reconcile_async` to make gateway/runtime intent explicit.
    pub async fn reconcile_idempotent_async(
        &mut self,
        id: &str,
        now: u64,
    ) -> Result<Option<ApprovalRecord>, BrokerError> {
        self.reconcile_async(id, now).await
    }

    /// Load a single approval from async/sync persistence hooks and upsert into memory.
    pub async fn rehydrate_async(
        &mut self,
        id: &str,
    ) -> Result<Option<ApprovalRecord>, BrokerError> {
        if self.async_persistence.is_none() && self.persistence.is_none() {
            return Ok(self.records.get(id).cloned());
        }
        if let Some(rec) = self.load_async(id).await? {
            let merged = Self::merge_rehydrated_record(self.records.get(id), rec);
            self.records
                .insert(merged.request.id.clone(), merged.clone());
            return Ok(Some(merged));
        }
        Ok(None)
    }

    /// Reconcile an approval from durable async/sync persistence into in-memory state.
    ///
    /// Loads persisted state (when available), merges it with in-memory metadata, then
    /// applies timeout handling hooks so expired pending approvals become effective denies.
    pub async fn reconcile_async(
        &mut self,
        id: &str,
        now: u64,
    ) -> Result<Option<ApprovalRecord>, BrokerError> {
        let loaded = self.load_async(id).await?;
        if let Some(rec) = loaded {
            let merged = Self::merge_rehydrated_record(self.records.get(id), rec);
            self.records
                .insert(merged.request.id.clone(), merged.clone());
        } else if !self.records.contains_key(id) {
            return Ok(None);
        }

        let should_timeout = self.records.get(id).is_some_and(|rec| {
            rec.status == ApprovalStatus::Pending && rec.expires_at.is_some_and(|exp| now >= exp)
        });
        if should_timeout {
            self.persist_timeout_async(id).await?;
            if let Some(rec) = self.records.get_mut(id) {
                if rec.status == ApprovalStatus::Pending {
                    rec.status = ApprovalStatus::TimedOut;
                }
            }
            self.emit(ApprovalEvent::TimedOut { id: id.to_string() });
            self.notify_resume(id);
        }
        Ok(self.records.get(id).cloned())
    }
}

struct ApprovalQueueGuard {
    inner: Arc<Mutex<ApprovalQueue>>,
    queue: Option<ApprovalQueue>,
}

impl Drop for ApprovalQueueGuard {
    fn drop(&mut self) {
        if let Some(queue) = self.queue.take() {
            if let Ok(mut guard) = self.inner.lock() {
                *guard = queue;
            }
        }
    }
}

/// Thread-safe runtime wrapper for gateway integration over `ApprovalQueue`.
#[derive(Clone, Default)]
pub struct ApprovalBrokerService {
    inner: Arc<Mutex<ApprovalQueue>>,
}

impl fmt::Debug for ApprovalBrokerService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApprovalBrokerService")
            .finish_non_exhaustive()
    }
}

impl ApprovalBrokerService {
    pub fn new(queue: ApprovalQueue) -> Self {
        Self {
            inner: Arc::new(Mutex::new(queue)),
        }
    }

    pub fn shared(inner: Arc<Mutex<ApprovalQueue>>) -> Self {
        Self { inner }
    }

    pub fn inner(&self) -> Arc<Mutex<ApprovalQueue>> {
        Arc::clone(&self.inner)
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, ApprovalQueue>, BrokerError> {
        self.inner
            .lock()
            .map_err(|_| BrokerError::PersistenceFailed("approval queue mutex poisoned".into()))
    }

    fn begin_async(&self) -> Result<ApprovalQueueGuard, BrokerError> {
        let queue = std::mem::take(&mut *self.lock()?);
        Ok(ApprovalQueueGuard {
            inner: Arc::clone(&self.inner),
            queue: Some(queue),
        })
    }

    pub fn create(
        &self,
        request: ApprovalRequest,
        expires_at: Option<u64>,
    ) -> Result<(), BrokerError> {
        self.lock()?.create(request, expires_at)
    }

    pub fn create_with_binding(
        &self,
        request: ApprovalRequest,
        expires_at: Option<u64>,
        args_hash: Option<String>,
    ) -> Result<(), BrokerError> {
        self.lock()?
            .create_with_binding(request, expires_at, args_hash)
    }

    pub fn get(&self, id: &str) -> Result<Option<ApprovalRecord>, BrokerError> {
        Ok(self.lock()?.get(id).cloned())
    }

    pub fn pending(&self, now: u64) -> Result<Vec<ApprovalRequest>, BrokerError> {
        self.lock()?.try_pending(now)
    }

    pub fn resolve(
        &self,
        id: &str,
        status: ApprovalStatus,
        now: u64,
    ) -> Result<ApprovalStatus, BrokerError> {
        self.lock()?.resolve(id, status, now)
    }

    pub fn resolve_with_meta(
        &self,
        id: &str,
        status: ApprovalStatus,
        now: u64,
        meta: ApprovalDecisionMeta,
    ) -> Result<ApprovalStatus, BrokerError> {
        self.lock()?.resolve_with_meta(id, status, now, meta)
    }

    pub fn expire_timeouts(&self, now: u64) -> Result<Vec<String>, BrokerError> {
        self.lock()?.try_expire_timeouts(now)
    }

    pub fn effective_status(
        &self,
        id: &str,
        now: u64,
    ) -> Result<Option<ApprovalStatus>, BrokerError> {
        self.lock()?.try_effective_status(id, now)
    }

    pub fn require_args_hash_binding(
        &self,
        id: &str,
        args_hash: Option<&str>,
    ) -> Result<(), BrokerError> {
        self.lock()?.require_args_hash_binding(id, args_hash)
    }

    pub fn evaluate(
        &self,
        id: &str,
        now: u64,
        args_hash: Option<&str>,
    ) -> Result<ApprovalDecision, BrokerError> {
        self.lock()?.evaluate(id, now, args_hash)
    }

    pub fn rehydrate(&self, id: &str) -> Result<Option<ApprovalRecord>, BrokerError> {
        self.lock()?.rehydrate(id)
    }

    /// Returns a pause/resume signal for the approval, creating it if missing.
    /// Gateway callers can await `notified()` and then re-evaluate/reconcile by id.
    pub fn resume_signal(&self, id: &str) -> Result<Arc<Notify>, BrokerError> {
        Ok(self.lock()?.resume_signal(id))
    }

    /// Returns an existing pause/resume signal for the approval, if present.
    pub fn resume_signal_if_exists(&self, id: &str) -> Result<Option<Arc<Notify>>, BrokerError> {
        Ok(self.lock()?.resume_signal_if_exists(id))
    }

    /// Notify waiters that approval state may have progressed.
    pub fn notify_resume(&self, id: &str) -> Result<(), BrokerError> {
        self.lock()?.notify_resume(id);
        Ok(())
    }

    pub async fn create_async(
        &self,
        request: ApprovalRequest,
        expires_at: Option<u64>,
    ) -> Result<(), BrokerError> {
        let mut guard = self.begin_async()?;
        guard
            .queue
            .as_mut()
            .expect("queue")
            .create_async(request, expires_at)
            .await
    }

    pub async fn create_with_binding_async(
        &self,
        request: ApprovalRequest,
        expires_at: Option<u64>,
        args_hash: Option<String>,
    ) -> Result<(), BrokerError> {
        let mut guard = self.begin_async()?;
        guard
            .queue
            .as_mut()
            .expect("queue")
            .create_with_binding_async(request, expires_at, args_hash)
            .await
    }

    pub async fn pending_async(&self, now: u64) -> Result<Vec<ApprovalRequest>, BrokerError> {
        let mut guard = self.begin_async()?;
        guard
            .queue
            .as_mut()
            .expect("queue")
            .try_pending_async(now)
            .await
    }

    pub async fn resolve_async(
        &self,
        id: &str,
        status: ApprovalStatus,
        now: u64,
    ) -> Result<ApprovalStatus, BrokerError> {
        let mut guard = self.begin_async()?;
        guard
            .queue
            .as_mut()
            .expect("queue")
            .resolve_async(id, status, now)
            .await
    }

    pub async fn resolve_with_meta_async(
        &self,
        id: &str,
        status: ApprovalStatus,
        now: u64,
        meta: ApprovalDecisionMeta,
    ) -> Result<ApprovalStatus, BrokerError> {
        let mut guard = self.begin_async()?;
        guard
            .queue
            .as_mut()
            .expect("queue")
            .resolve_with_meta_async(id, status, now, meta)
            .await
    }

    pub async fn expire_timeouts_async(&self, now: u64) -> Result<Vec<String>, BrokerError> {
        let mut guard = self.begin_async()?;
        guard
            .queue
            .as_mut()
            .expect("queue")
            .try_expire_timeouts_async(now)
            .await
    }

    pub async fn effective_status_async(
        &self,
        id: &str,
        now: u64,
    ) -> Result<Option<ApprovalStatus>, BrokerError> {
        let mut guard = self.begin_async()?;
        guard
            .queue
            .as_mut()
            .expect("queue")
            .try_effective_status_async(id, now)
            .await
    }

    pub async fn evaluate_async(
        &self,
        id: &str,
        now: u64,
        args_hash: Option<&str>,
    ) -> Result<ApprovalDecision, BrokerError> {
        let mut guard = self.begin_async()?;
        guard
            .queue
            .as_mut()
            .expect("queue")
            .evaluate_async(id, now, args_hash)
            .await
    }

    pub async fn rehydrate_async(&self, id: &str) -> Result<Option<ApprovalRecord>, BrokerError> {
        let mut guard = self.begin_async()?;
        guard
            .queue
            .as_mut()
            .expect("queue")
            .rehydrate_async(id)
            .await
    }

    pub async fn reconcile_async(
        &self,
        id: &str,
        now: u64,
    ) -> Result<Option<ApprovalRecord>, BrokerError> {
        let mut guard = self.begin_async()?;
        guard
            .queue
            .as_mut()
            .expect("queue")
            .reconcile_async(id, now)
            .await
    }

    /// Store-backed idempotent reconciliation helper for gateway/runtime callers.
    pub async fn reconcile_idempotent_async(
        &self,
        id: &str,
        now: u64,
    ) -> Result<Option<ApprovalRecord>, BrokerError> {
        let mut guard = self.begin_async()?;
        guard
            .queue
            .as_mut()
            .expect("queue")
            .reconcile_idempotent_async(id, now)
            .await
    }
}

/// Broker errors for approval/credential operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrokerError {
    InvalidApprovalId,
    DuplicateApproval(String),
    ApprovalNotFound(String),
    ApprovalAlreadyTerminal(String),
    InvalidResolution,
    SecretNotFound(SecretRef),
    InjectionDenied(String),
    ResolutionFailed(String),
    PersistenceFailed(String),
}

impl fmt::Display for BrokerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidApprovalId => f.write_str("invalid approval id"),
            Self::DuplicateApproval(id) => write!(f, "duplicate approval: {id}"),
            Self::ApprovalNotFound(id) => write!(f, "approval not found: {id}"),
            Self::ApprovalAlreadyTerminal(id) => write!(f, "approval already terminal: {id}"),
            Self::InvalidResolution => f.write_str("invalid approval resolution"),
            Self::SecretNotFound(r) => write!(f, "secret not found: {r}"),
            Self::InjectionDenied(msg) => write!(f, "credential injection denied: {msg}"),
            Self::ResolutionFailed(msg) => write!(f, "secret resolution failed: {msg}"),
            Self::PersistenceFailed(msg) => write!(f, "approval persistence failed: {msg}"),
        }
    }
}

impl std::error::Error for BrokerError {}
/// Result of credential injection with redaction-safe metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InjectedCredential {
    pub tool: String,
    pub secret: SecretRef,
    /// Redacted placeholder safe for logs/audit.
    pub redacted: String,
}

/// Credential injection/redaction boundary.
/// Implementations resolve secret references by tool context and never expose raw values.
pub trait CredentialBroker {
    type Error;

    /// Inject credential for `tool` using `secret` into `target`, returning redacted metadata.
    fn inject(
        &self,
        tool: &str,
        secret: &SecretRef,
        target: &mut String,
    ) -> Result<InjectedCredential, Self::Error>;

    /// Redact sensitive material from `value` before logging/returning.
    fn redact(&self, value: &str) -> String;
}

/// No-op broker placeholder: injects a redaction marker only.
/// Backward-compatible unit struct (default full redaction).
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopCredentialBroker;

impl CredentialBroker for NoopCredentialBroker {
    type Error = BrokerError;

    fn inject(
        &self,
        tool: &str,
        secret: &SecretRef,
        target: &mut String,
    ) -> Result<InjectedCredential, Self::Error> {
        if tool.trim().is_empty() {
            return Err(BrokerError::InjectionDenied("empty tool".to_string()));
        }
        let redacted = self.redact(&secret.0);
        *target = redacted.clone();
        Ok(InjectedCredential {
            tool: tool.to_string(),
            secret: secret.clone(),
            redacted,
        })
    }

    fn redact(&self, _value: &str) -> String {
        RedactionPolicy::default().apply(_value)
    }
}

/// Configurable rule-based broker for redaction-only injection flows.
#[derive(Debug, Clone, Default)]
pub struct RuleBasedCredentialBroker {
    policy: RedactionPolicy,
}

impl RuleBasedCredentialBroker {
    pub fn new(policy: RedactionPolicy) -> Self {
        Self { policy }
    }
}

impl CredentialBroker for RuleBasedCredentialBroker {
    type Error = BrokerError;
    fn inject(
        &self,
        tool: &str,
        secret: &SecretRef,
        target: &mut String,
    ) -> Result<InjectedCredential, Self::Error> {
        if tool.trim().is_empty() {
            return Err(BrokerError::InjectionDenied("empty tool".to_string()));
        }
        let redacted = self.redact(&secret.0);
        *target = redacted.clone();
        Ok(InjectedCredential {
            tool: tool.to_string(),
            secret: secret.clone(),
            redacted,
        })
    }
    fn redact(&self, value: &str) -> String {
        self.policy.redact(value)
    }
}

/// Integration-ready broker that resolves secrets and injects/redacts via policy.
#[derive(Debug, Default, Clone)]
pub struct ResolvingCredentialBroker<R: SecretResolver> {
    resolver: R,
    policy: RedactionPolicy,
}

impl<R: SecretResolver> ResolvingCredentialBroker<R> {
    pub fn new(resolver: R) -> Self {
        Self {
            resolver,
            policy: RedactionPolicy::default(),
        }
    }
    pub fn with_policy(mut self, policy: RedactionPolicy) -> Self {
        self.policy = policy;
        self
    }

    pub fn inject_resolved(
        &self,
        tool: &str,
        secret: &SecretRef,
        ctx: &SecretResolutionContext,
        target: &mut String,
    ) -> Result<InjectedCredential, BrokerError>
    where
        R::Error: fmt::Display,
    {
        self.inject_resolved_into(tool, secret, ctx, "", target)
    }

    /// Resolve and inject a secret into an upstream request target (header/map/body hook).
    /// Fail-closed on resolver errors, denied/empty tool, or missing secrets.
    pub fn inject_resolved_into<T: SecretInjectionTarget>(
        &self,
        tool: &str,
        secret: &SecretRef,
        ctx: &SecretResolutionContext,
        target_key: &str,
        target: &mut T,
    ) -> Result<InjectedCredential, BrokerError>
    where
        R::Error: fmt::Display,
    {
        if tool.trim().is_empty() {
            return Err(BrokerError::InjectionDenied("empty tool".to_string()));
        }
        let resolved = self
            .resolver
            .resolve(secret, ctx)
            .map_err(|e| BrokerError::ResolutionFailed(e.to_string()))?;
        target.inject_secret_value(target_key, &resolved.value);
        Ok(InjectedCredential {
            tool: tool.to_string(),
            secret: secret.clone(),
            redacted: self.policy.redact(&resolved.value),
        })
    }

    /// Upstream hook: resolve/inject secret and register it for request/response redaction.
    pub fn inject_for_upstream_call<T: SecretInjectionTarget>(
        &self,
        tool: &str,
        secret: &SecretRef,
        ctx: &SecretResolutionContext,
        target_key: &str,
        target: &mut T,
        scrubber: &mut SecretScrubber,
    ) -> Result<InjectedCredential, BrokerError>
    where
        R::Error: fmt::Display,
    {
        if tool.trim().is_empty() {
            return Err(BrokerError::InjectionDenied("empty tool".to_string()));
        }
        let resolved = self
            .resolver
            .resolve(secret, ctx)
            .map_err(|e| BrokerError::ResolutionFailed(e.to_string()))?;
        target.inject_secret_value(target_key, &resolved.value);
        scrubber.register_resolved(&resolved, &self.policy);
        Ok(InjectedCredential {
            tool: tool.to_string(),
            secret: secret.clone(),
            redacted: self.policy.redact(&resolved.value),
        })
    }
}

impl<R: SecretResolver> CredentialBroker for ResolvingCredentialBroker<R>
where
    R::Error: fmt::Display,
{
    type Error = BrokerError;
    fn inject(
        &self,
        tool: &str,
        secret: &SecretRef,
        target: &mut String,
    ) -> Result<InjectedCredential, Self::Error> {
        let ctx = SecretResolutionContext {
            tool: tool.to_string(),
            principal: None,
            args_hash: None,
        };
        self.inject_resolved(tool, secret, &ctx, target)
    }
    fn redact(&self, value: &str) -> String {
        self.policy.redact(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use store::Store as _;

    #[derive(Default)]
    struct RecordingNotifier {
        events: Mutex<Vec<ApprovalEvent>>,
    }
    impl ApprovalNotifier for RecordingNotifier {
        fn notify(&self, event: ApprovalEvent) {
            self.events.lock().unwrap().push(event);
        }
    }

    #[test]
    fn timeout_denies_and_effective() {
        assert!(!ApprovalStatus::TimedOut.allows());
        assert_eq!(ApprovalStatus::TimedOut.effective(), ApprovalStatus::Denied);
        assert!(ApprovalStatus::Approved.allows());
        assert!(!ApprovalStatus::Denied.allows());
    }

    #[test]
    fn approval_queue_create_resolve_pending() {
        let mut q = ApprovalQueue::new();
        let req = ApprovalRequest {
            id: "a1".into(),
            principal: "p".into(),
            action: "act".into(),
            resource: "res".into(),
            reason: None,
        };
        q.create(req.clone(), Some(10)).unwrap();
        assert_eq!(q.pending(0).len(), 1);
        assert_eq!(
            q.resolve("a1", ApprovalStatus::Approved, 1).unwrap(),
            ApprovalStatus::Approved
        );
        assert_eq!(q.get("a1").unwrap().status, ApprovalStatus::Approved);
        // idempotent same effective outcome
        assert_eq!(
            q.resolve("a1", ApprovalStatus::Approved, 2).unwrap(),
            ApprovalStatus::Approved
        );
    }

    #[test]
    fn approval_queue_timeout_becomes_deny() {
        let mut q = ApprovalQueue::new();
        q.create(
            ApprovalRequest {
                id: "t1".into(),
                principal: "p".into(),
                action: "a".into(),
                resource: "r".into(),
                reason: None,
            },
            Some(5),
        )
        .unwrap();
        assert_eq!(q.effective_status("t1", 5), Some(ApprovalStatus::Denied));
        assert_eq!(q.get("t1").unwrap().status, ApprovalStatus::TimedOut);
        assert!(q.pending(6).is_empty());
        // idempotent deny on timed out
        assert_eq!(
            q.resolve("t1", ApprovalStatus::Denied, 6).unwrap(),
            ApprovalStatus::Denied
        );
    }

    #[test]
    fn approval_queue_idempotent_args_hash_placeholder_and_notifications() {
        let notifier = Arc::new(RecordingNotifier::default());
        let mut q = ApprovalQueue::new().with_notifier(notifier.clone());
        let req = ApprovalRequest {
            id: "h1".into(),
            principal: "p".into(),
            action: "act".into(),
            resource: "res".into(),
            reason: Some("needs approval".into()),
        };
        q.create_with_binding(req, Some(20), Some("sha256:placeholder".into()))
            .unwrap();
        assert_eq!(
            q.get("h1").unwrap().args_hash.as_deref(),
            Some("sha256:placeholder")
        );
        assert_eq!(
            q.args_hash_matches("h1", Some("sha256:placeholder")),
            Some(true)
        );
        assert_eq!(q.args_hash_matches("h1", Some("sha256:other")), Some(false));
        assert_eq!(q.args_hash_matches("h1", None), Some(false));
        assert_eq!(
            q.resolve_idempotent("h1", ApprovalStatus::Denied, 1)
                .unwrap(),
            ApprovalStatus::Denied
        );
        // conflicting terminal transition rejected
        assert!(matches!(
            q.resolve("h1", ApprovalStatus::Approved, 2),
            Err(BrokerError::ApprovalAlreadyTerminal(_))
        ));
        let events = notifier.events.lock().unwrap().clone();
        assert!(events.iter().any(|e| matches!(e, ApprovalEvent::Created { id, args_hash, .. } if id == "h1" && args_hash.as_deref() == Some("sha256:placeholder"))));
        assert!(events.iter().any(
            |e| matches!(e, ApprovalEvent::Resolved { id, idempotent: false, .. } if id == "h1")
        ));
        // unbound approval matches any provided hash by hook contract
        q.create(
            ApprovalRequest {
                id: "h2".into(),
                principal: "p".into(),
                action: "a".into(),
                resource: "r".into(),
                reason: None,
            },
            Some(30),
        )
        .unwrap();
        assert_eq!(q.args_hash_matches("h2", Some("any")), Some(true));
        assert_eq!(q.args_hash_matches("missing", Some("x")), None);
    }

    #[test]
    fn broker_error_display_is_clear() {
        assert_eq!(
            BrokerError::InvalidApprovalId.to_string(),
            "invalid approval id"
        );
        assert_eq!(
            BrokerError::SecretNotFound(SecretRef("s://x".into())).to_string(),
            "secret not found: s://x"
        );
    }
    #[test]
    fn noop_broker_injects_redacted_by_tool_and_secret_ref() {
        let broker = NoopCredentialBroker;
        let mut target = "sensitive".to_string();
        let secret = SecretRef("secret://db".into());
        let injected = broker.inject("tool.read", &secret, &mut target).unwrap();
        assert_eq!(target, "[REDACTED]");
        assert_eq!(injected.tool, "tool.read");
        assert_eq!(injected.secret, secret);
        assert_eq!(injected.redacted, "[REDACTED]");
        assert_eq!(broker.redact("anything"), "[REDACTED]");
        assert!(broker
            .inject("", &SecretRef("x".into()), &mut target)
            .is_err());
    }

    #[test]
    fn redaction_rules_and_resolver_abstraction() {
        let policy = RedactionPolicy {
            rules: vec![RedactionRule::KeepEdges {
                prefix: 2,
                suffix: 2,
                mask: '*',
            }],
        };
        assert_eq!(policy.apply("supersecret"), "su*******et");
        let mut resolver = StaticSecretResolver::new();
        resolver.insert(SecretRef("secret://api".into()), "token-123456");
        let broker = ResolvingCredentialBroker::new(resolver).with_policy(policy);
        let ctx = SecretResolutionContext {
            tool: "tool.call".into(),
            principal: Some("agent".into()),
            args_hash: Some("hash:ph".into()),
        };
        let mut target = String::new();
        let injected = broker
            .inject_resolved(
                "tool.call",
                &SecretRef("secret://api".into()),
                &ctx,
                &mut target,
            )
            .unwrap();
        assert_eq!(target, "token-123456");
        assert_eq!(injected.redacted, "to********56");
        let mut target2 = String::new();
        assert!(matches!(
            broker.inject("tool.call", &SecretRef("missing".into()), &mut target2),
            Err(BrokerError::ResolutionFailed(_))
        ));
    }

    #[test]
    fn rule_based_broker_uses_policy() {
        let broker = RuleBasedCredentialBroker::new(RedactionPolicy {
            rules: vec![RedactionRule::Full {
                marker: "***".into(),
            }],
        });
        let mut target = "x".into();
        let injected = broker
            .inject("t", &SecretRef("secret://x".into()), &mut target)
            .unwrap();
        assert_eq!(target, "***");
        assert_eq!(injected.redacted, "***");
    }

    #[test]
    fn resolved_secret_debug_is_redacted() {
        let s = ResolvedSecret {
            reference: SecretRef("s".into()),
            value: "topsecret".into(),
        };
        let dbg = format!("{:?}", s);
        assert!(!dbg.contains("topsecret"));
        assert!(dbg.contains("REDACTED"));
    }

    #[test]
    fn timeout_emits_notification() {
        let notifier = Arc::new(RecordingNotifier::default());
        let mut q = ApprovalQueue::new().with_notifier(notifier.clone());
        q.create(
            ApprovalRequest {
                id: "n1".into(),
                principal: "p".into(),
                action: "a".into(),
                resource: "r".into(),
                reason: None,
            },
            Some(1),
        )
        .unwrap();
        q.expire_timeouts(1);
        let events = notifier.events.lock().unwrap().clone();
        assert!(events
            .iter()
            .any(|e| matches!(e, ApprovalEvent::TimedOut { id } if id == "n1")));
    }

    type ResolveCall = (String, ApprovalStatus, ApprovalStatus, Option<String>);

    #[derive(Default)]
    struct RecordingPersistence {
        creates: Mutex<Vec<ApprovalRecord>>,
        resolves: Mutex<Vec<ResolveCall>>,
        timeouts: Mutex<Vec<String>>,
        store: Mutex<HashMap<String, ApprovalRecord>>,
        fail: Mutex<bool>,
    }
    impl RecordingPersistence {
        fn set_fail(&self, v: bool) {
            *self.fail.lock().unwrap() = v;
        }
    }
    impl ApprovalPersistence for RecordingPersistence {
        type Error = BrokerError;
        fn persist_create(&self, record: &ApprovalRecord) -> Result<(), Self::Error> {
            if *self.fail.lock().unwrap() {
                return Err(BrokerError::PersistenceFailed("boom".into()));
            }
            self.creates.lock().unwrap().push(record.clone());
            self.store
                .lock()
                .unwrap()
                .insert(record.request.id.clone(), record.clone());
            Ok(())
        }
        fn persist_resolve(
            &self,
            id: &str,
            status: ApprovalStatus,
            effective: ApprovalStatus,
            _resolver: Option<&str>,
            _args_hash: Option<&str>,
        ) -> Result<(), Self::Error> {
            if *self.fail.lock().unwrap() {
                return Err(BrokerError::PersistenceFailed("boom".into()));
            }
            self.resolves.lock().unwrap().push((
                id.to_string(),
                status,
                effective,
                _args_hash.map(str::to_string),
            ));
            if let Some(r) = self.store.lock().unwrap().get_mut(id) {
                r.status = effective;
            }
            Ok(())
        }
        fn persist_timeout(&self, id: &str) -> Result<(), Self::Error> {
            if *self.fail.lock().unwrap() {
                return Err(BrokerError::PersistenceFailed("boom".into()));
            }
            self.timeouts.lock().unwrap().push(id.to_string());
            if let Some(r) = self.store.lock().unwrap().get_mut(id) {
                r.status = ApprovalStatus::TimedOut;
            }
            Ok(())
        }
        fn load(&self, id: &str) -> Result<Option<ApprovalRecord>, Self::Error> {
            if *self.fail.lock().unwrap() {
                return Err(BrokerError::PersistenceFailed("boom".into()));
            }
            Ok(self.store.lock().unwrap().get(id).cloned())
        }
    }

    #[test]
    fn persistence_hooks_and_rehydrate_idempotent_timeout_flow() {
        let p = Arc::new(RecordingPersistence::default());
        let mut q = ApprovalQueue::new().with_persistence(p.clone());
        let req = ApprovalRequest {
            id: "p1".into(),
            principal: "u".into(),
            action: "a".into(),
            resource: "r".into(),
            reason: None,
        };
        q.create_with_binding(req.clone(), Some(10), Some("h1".into()))
            .unwrap();
        assert_eq!(p.creates.lock().unwrap().len(), 1);
        assert_eq!(q.try_pending(1).unwrap().len(), 1);
        assert!(q
            .try_expire_timeouts(10)
            .unwrap()
            .contains(&"p1".to_string()));
        assert_eq!(q.effective_status("p1", 11), Some(ApprovalStatus::Denied));
        assert_eq!(
            q.resolve("p1", ApprovalStatus::Denied, 11).unwrap(),
            ApprovalStatus::Denied
        ); // idempotent
        let resolves = p.resolves.lock().unwrap().clone();
        assert!(resolves.iter().any(|(id, _, eff, h)| id == "p1"
            && *eff == ApprovalStatus::Denied
            && h.as_deref() == Some("h1")));
        assert!(!p.timeouts.lock().unwrap().is_empty());

        let mut q2 = ApprovalQueue::new().with_persistence(p.clone());
        let loaded = q2.rehydrate("p1").unwrap().unwrap();
        assert_eq!(loaded.request.id, "p1");
        assert!(q2.get("p1").is_some());
    }

    #[test]
    fn persistence_failure_is_fail_closed() {
        let p = Arc::new(RecordingPersistence::default());
        p.set_fail(true);
        let mut q = ApprovalQueue::new().with_persistence(p);
        let req = ApprovalRequest {
            id: "e1".into(),
            principal: "u".into(),
            action: "a".into(),
            resource: "r".into(),
            reason: None,
        };
        assert!(matches!(
            q.create(req, Some(5)),
            Err(BrokerError::PersistenceFailed(_))
        ));
        assert!(q.get("e1").is_none());
        assert!(matches!(NoopApprovalPersistence.load("x"), Ok(None)));
        assert_eq!(
            BrokerError::PersistenceFailed("x".into()).to_string(),
            "approval persistence failed: x"
        );
    }

    #[test]
    fn credential_injection_and_redaction_flows() {
        let mut resolver = StaticSecretResolver::new();
        resolver.insert(SecretRef("s://k".into()), "abcd1234wxyz");
        let broker = ResolvingCredentialBroker::new(resolver).with_policy(RedactionPolicy {
            rules: vec![RedactionRule::KeepEdges {
                prefix: 2,
                suffix: 2,
                mask: '#',
            }],
        });
        let mut target = String::new();
        let injected = broker
            .inject("tool.http", &SecretRef("s://k".into()), &mut target)
            .unwrap();
        assert_eq!(target, "abcd1234wxyz");
        assert_eq!(injected.redacted, "ab########yz");
        assert_eq!(broker.redact(&target), "ab########yz");
        // empty tool denied
        let mut t2 = String::new();
        assert!(matches!(
            broker.inject("", &SecretRef("s://k".into()), &mut t2),
            Err(BrokerError::InjectionDenied(_))
        ));
    }

    #[test]
    fn notification_channel_stubs_and_broadcast() {
        let slack = Arc::new(SlackNotifierStub::new("#ops"));
        let webhook = Arc::new(WebhookNotifierStub::new("https://hook.local/approvals"));
        let fanout = Arc::new(BroadcastNotifier::new(vec![
            slack.clone() as Arc<dyn ApprovalNotifier>,
            webhook.clone() as Arc<dyn ApprovalNotifier>,
        ]));
        let mut q = ApprovalQueue::new().with_notifier(fanout);
        q.create(
            ApprovalRequest {
                id: "nch".into(),
                principal: "p".into(),
                action: "a".into(),
                resource: "r".into(),
                reason: None,
            },
            None,
        )
        .unwrap();
        assert_eq!(slack.events.lock().unwrap().len(), 1);
        assert_eq!(webhook.events.lock().unwrap().len(), 1);
        assert!(slack
            .payload_hint(&ApprovalEvent::TimedOut { id: "x".into() })
            .contains("slack:#ops:"));
        assert!(webhook
            .payload_hint(&ApprovalEvent::TimedOut { id: "x".into() })
            .contains("webhook:https://hook.local/approvals:"));
    }

    #[derive(Default)]
    struct InMemoryStoreBridge {
        rows: Mutex<HashMap<String, StoreApprovalSnapshot>>,
        fail: Mutex<bool>,
    }
    impl StoreApprovalBridge for InMemoryStoreBridge {
        type Error = String;
        fn create(
            &self,
            approval: StoreApprovalSnapshot,
        ) -> Result<StoreApprovalSnapshot, Self::Error> {
            if *self.fail.lock().unwrap() {
                return Err("store down".into());
            }
            self.rows
                .lock()
                .unwrap()
                .insert(approval.id.clone(), approval.clone());
            Ok(approval)
        }
        fn get(&self, id: &str) -> Result<Option<StoreApprovalSnapshot>, Self::Error> {
            if *self.fail.lock().unwrap() {
                return Err("store down".into());
            }
            Ok(self.rows.lock().unwrap().get(id).cloned())
        }
        fn resolve(
            &self,
            id: &str,
            status: StoreApprovalStatus,
            resolver: Option<String>,
            resolved_at: Option<String>,
            args_hash: Option<String>,
        ) -> Result<StoreApprovalSnapshot, Self::Error> {
            if *self.fail.lock().unwrap() {
                return Err("store down".into());
            }
            let mut rows = self.rows.lock().unwrap();
            let row = rows.get_mut(id).ok_or_else(|| "missing".to_string())?;
            row.status = status;
            row.resolver = resolver;
            row.resolved_at = resolved_at;
            if let Some(h) = args_hash {
                row.args_hash = h;
            }
            Ok(row.clone())
        }
    }

    #[test]
    fn store_abstraction_persistence_adapter_roundtrip() {
        let bridge = Arc::new(InMemoryStoreBridge::default());
        let persistence = Arc::new(StoreApprovalPersistenceAdapter::new(bridge.clone()));
        let mut q = ApprovalQueue::new().with_persistence(persistence);
        let req = ApprovalRequest {
            id: "sa1".into(),
            principal: "p".into(),
            action: "tool.call".into(),
            resource: "res".into(),
            reason: Some("why".into()),
        };
        q.create_with_binding(req, Some(10), Some("h:1".into()))
            .unwrap();
        assert!(bridge.rows.lock().unwrap().contains_key("sa1"));
        q.resolve_with_meta(
            "sa1",
            ApprovalStatus::Approved,
            1,
            ApprovalDecisionMeta {
                resolver: Some("alice".into()),
                args_hash: Some("h:1".into()),
                enforce_args_hash_binding: true,
            },
        )
        .unwrap();
        let stored = bridge.rows.lock().unwrap().get("sa1").cloned().unwrap();
        assert_eq!(stored.status, StoreApprovalStatus::Approved);
        assert_eq!(stored.resolver.as_deref(), Some("alice"));
        let mut q2 = ApprovalQueue::new().with_persistence(Arc::new(
            StoreApprovalPersistenceAdapter::new(bridge.clone()),
        ));
        let loaded = q2.rehydrate("sa1").unwrap().unwrap();
        assert_eq!(loaded.status, ApprovalStatus::Approved);
        assert_eq!(loaded.args_hash.as_deref(), Some("h:1"));

        *bridge.fail.lock().unwrap() = true;
        let mut q3 = ApprovalQueue::new()
            .with_persistence(Arc::new(StoreApprovalPersistenceAdapter::new(bridge)));
        assert!(matches!(
            q3.rehydrate("sa1"),
            Err(BrokerError::PersistenceFailed(_))
        ));
    }

    #[test]
    fn richer_workflow_enforces_args_hash_binding_fail_closed() {
        let mut q = ApprovalQueue::new();
        q.create_with_binding(
            ApprovalRequest {
                id: "b1".into(),
                principal: "p".into(),
                action: "a".into(),
                resource: "r".into(),
                reason: None,
            },
            Some(50),
            Some("bound".into()),
        )
        .unwrap();
        assert!(matches!(
            q.require_args_hash_binding("b1", Some("wrong")),
            Err(BrokerError::InjectionDenied(_))
        ));
        assert!(q.require_args_hash_binding("b1", Some("bound")).is_ok());
        assert!(matches!(
            q.require_args_hash_binding("missing", Some("bound")),
            Err(BrokerError::ApprovalNotFound(_))
        ));
        assert!(matches!(
            q.resolve_with_meta(
                "b1",
                ApprovalStatus::Approved,
                1,
                ApprovalDecisionMeta {
                    resolver: Some("r".into()),
                    args_hash: Some("wrong".into()),
                    enforce_args_hash_binding: true,
                },
            ),
            Err(BrokerError::InjectionDenied(_))
        ));
        assert_eq!(
            q.resolve_with_meta(
                "b1",
                ApprovalStatus::Approved,
                2,
                ApprovalDecisionMeta {
                    resolver: Some("r".into()),
                    args_hash: Some("bound".into()),
                    enforce_args_hash_binding: true,
                },
            )
            .unwrap(),
            ApprovalStatus::Approved
        );
        assert!(q.records().any(|r| r.request.id == "b1"));
    }

    #[test]
    fn runtime_service_evaluate_and_timeout_flow() {
        let svc = ApprovalBrokerService::new(ApprovalQueue::new());
        svc.create_with_binding(
            ApprovalRequest {
                id: "svc1".into(),
                principal: "p".into(),
                action: "act".into(),
                resource: "res".into(),
                reason: None,
            },
            Some(5),
            Some("ah".into()),
        )
        .unwrap();
        assert_eq!(svc.pending(1).unwrap().len(), 1);
        assert!(matches!(
            svc.evaluate("svc1", 1, Some("wrong")),
            Err(BrokerError::InjectionDenied(_))
        ));
        let d = svc.evaluate("svc1", 1, Some("ah")).unwrap();
        assert_eq!(d.effective, ApprovalStatus::Pending);
        assert!(!d.allows());
        assert_eq!(svc.expire_timeouts(5).unwrap(), vec!["svc1".to_string()]);
        let denied = svc.evaluate("svc1", 6, Some("ah")).unwrap();
        assert_eq!(denied.effective, ApprovalStatus::Denied);
        assert!(!denied.allows());
        assert_eq!(
            svc.resolve("svc1", ApprovalStatus::Denied, 6).unwrap(),
            ApprovalStatus::Denied
        );
        assert!(svc.get("svc1").unwrap().is_some());
    }

    #[tokio::test]
    async fn async_store_backed_persistence_create_load_resolve() {
        let store = Arc::new(store::InMemoryStore::default());
        let persistence = StoreBackedAsyncApprovalPersistence::new(store.clone());

        let rec = ApprovalRecord {
            request: ApprovalRequest {
                id: "async-1".into(),
                principal: "alice".into(),
                action: "tool.run".into(),
                resource: "res://x".into(),
                reason: Some("why".into()),
            },
            status: ApprovalStatus::Pending,
            expires_at: Some(99),
            args_hash: Some("h1".into()),
        };

        persistence.persist_create(&rec).await.unwrap();
        let stored = store.get_approval("async-1").await.unwrap().unwrap();
        assert_eq!(stored.status, store::ApprovalStatus::Pending);
        assert_eq!(stored.tool, "tool.run");
        assert_eq!(stored.args_hash, "h1");
        assert_eq!(stored.task_id, "async-1");

        let loaded = persistence.load("async-1").await.unwrap().unwrap();
        assert_eq!(loaded.request.id, "async-1");
        assert_eq!(loaded.request.action, "tool.run");
        assert_eq!(loaded.status, ApprovalStatus::Pending);
        assert_eq!(loaded.args_hash.as_deref(), Some("h1"));

        persistence
            .persist_resolve(
                "async-1",
                ApprovalStatus::Approved,
                ApprovalStatus::Approved,
                Some("bob"),
                Some("h1"),
            )
            .await
            .unwrap();
        let resolved = store.get_approval("async-1").await.unwrap().unwrap();
        assert_eq!(resolved.status, store::ApprovalStatus::Approved);
        assert_eq!(resolved.resolver.as_deref(), Some("bob"));

        // idempotent same effective outcome
        persistence
            .persist_resolve(
                "async-1",
                ApprovalStatus::Approved,
                ApprovalStatus::Approved,
                Some("bob"),
                Some("h1"),
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn async_store_backed_persistence_timeout_and_deny_idempotency() {
        let store = Arc::new(store::InMemoryStore::default());
        let persistence = StoreBackedAsyncApprovalPersistence::new(store.clone());
        let rec = ApprovalRecord {
            request: ApprovalRequest {
                id: "async-t".into(),
                principal: "p".into(),
                action: "a".into(),
                resource: "r".into(),
                reason: None,
            },
            status: ApprovalStatus::Pending,
            expires_at: Some(1),
            args_hash: None,
        };
        persistence.persist_create(&rec).await.unwrap();
        persistence.persist_timeout("async-t").await.unwrap();

        let stored = store.get_approval("async-t").await.unwrap().unwrap();
        assert_eq!(stored.status, store::ApprovalStatus::Expired);
        let loaded = persistence.load("async-t").await.unwrap().unwrap();
        assert_eq!(loaded.status, ApprovalStatus::TimedOut);
        assert_eq!(loaded.status.effective(), ApprovalStatus::Denied);

        // compatible effective-deny idempotency
        persistence
            .persist_resolve(
                "async-t",
                ApprovalStatus::Denied,
                ApprovalStatus::Denied,
                None,
                None,
            )
            .await
            .unwrap();
        persistence.persist_timeout("async-t").await.unwrap();
    }

    #[tokio::test]
    async fn async_store_backed_persistence_fail_closed_missing() {
        let store = Arc::new(store::InMemoryStore::default());
        let persistence = StoreBackedAsyncApprovalPersistence::new(store);
        assert!(matches!(
            persistence
                .persist_resolve(
                    "missing",
                    ApprovalStatus::Denied,
                    ApprovalStatus::Denied,
                    None,
                    None
                )
                .await,
            Err(BrokerError::PersistenceFailed(_))
        ));
        assert!(matches!(
            persistence.persist_timeout("missing").await,
            Err(BrokerError::PersistenceFailed(_))
        ));
        assert!(matches!(persistence.load("missing").await, Ok(None)));
    }

    #[tokio::test]
    async fn async_queue_flow_create_resolve_rehydrate_reconcile_with_store() {
        let store = Arc::new(store::InMemoryStore::default());
        let persistence = Arc::new(StoreBackedAsyncApprovalPersistence::new(store.clone()));
        let mut q = ApprovalQueue::new().with_async_persistence(persistence);

        q.create_with_binding_async(
            ApprovalRequest {
                id: "aq1".into(),
                principal: "alice".into(),
                action: "tool.run".into(),
                resource: "res://x".into(),
                reason: Some("why".into()),
            },
            Some(50),
            Some("h1".into()),
        )
        .await
        .unwrap();

        let stored = store.get_approval("aq1").await.unwrap().unwrap();
        assert_eq!(stored.status, store::ApprovalStatus::Pending);
        assert_eq!(stored.args_hash, "h1");

        assert_eq!(
            q.resolve_with_meta_async(
                "aq1",
                ApprovalStatus::Approved,
                1,
                ApprovalDecisionMeta {
                    resolver: Some("bob".into()),
                    args_hash: Some("h1".into()),
                    enforce_args_hash_binding: true,
                },
            )
            .await
            .unwrap(),
            ApprovalStatus::Approved
        );
        // idempotent resolve/reconcile-safe persistence
        assert_eq!(
            q.resolve_async("aq1", ApprovalStatus::Approved, 2)
                .await
                .unwrap(),
            ApprovalStatus::Approved
        );

        let mut q2 = ApprovalQueue::new().with_async_persistence(Arc::new(
            StoreBackedAsyncApprovalPersistence::new(store.clone()),
        ));
        let loaded = q2.rehydrate_async("aq1").await.unwrap().unwrap();
        assert_eq!(loaded.status, ApprovalStatus::Approved);
        assert_eq!(loaded.args_hash.as_deref(), Some("h1"));
        let reconciled = q2.reconcile_async("aq1", 3).await.unwrap().unwrap();
        assert_eq!(reconciled.status, ApprovalStatus::Approved);
    }

    #[tokio::test]
    async fn async_queue_timeout_hooks_and_reconcile_fail_closed_idempotent() {
        let store = Arc::new(store::InMemoryStore::default());
        let persistence = Arc::new(StoreBackedAsyncApprovalPersistence::new(store.clone()));
        let mut q = ApprovalQueue::new().with_async_persistence(persistence);

        q.create_with_binding_async(
            ApprovalRequest {
                id: "aqt".into(),
                principal: "p".into(),
                action: "a".into(),
                resource: "r".into(),
                reason: None,
            },
            Some(10),
            Some("bound".into()),
        )
        .await
        .unwrap();

        assert_eq!(q.try_pending_async(9).await.unwrap().len(), 1);
        let expired = q.try_expire_timeouts_async(10).await.unwrap();
        assert_eq!(expired, vec!["aqt".to_string()]);
        assert_eq!(
            q.try_effective_status_async("aqt", 11).await.unwrap(),
            Some(ApprovalStatus::Denied)
        );
        let stored = store.get_approval("aqt").await.unwrap().unwrap();
        assert_eq!(stored.status, store::ApprovalStatus::Expired);

        // idempotent timeout/reconcile hooks
        assert!(q.try_expire_timeouts_async(12).await.unwrap().is_empty());
        let reconciled = q.reconcile_async("aqt", 12).await.unwrap().unwrap();
        assert_eq!(reconciled.status.effective(), ApprovalStatus::Denied);

        // fail-closed binding enforcement in async evaluate flow
        assert!(matches!(
            q.evaluate_async("aqt", 12, Some("wrong")).await,
            Err(BrokerError::InjectionDenied(_))
        ));
        assert!(q.evaluate_async("aqt", 12, Some("bound")).await.is_ok());
        assert!(matches!(
            q.resolve_async("aqt", ApprovalStatus::Approved, 12).await,
            Err(BrokerError::ApprovalAlreadyTerminal(_))
        ));
    }

    #[tokio::test]
    async fn async_service_flow_with_store_backed_persistence_and_reconcile() {
        let store = Arc::new(store::InMemoryStore::default());
        let persistence = Arc::new(StoreBackedAsyncApprovalPersistence::new(store.clone()));
        let svc =
            ApprovalBrokerService::new(ApprovalQueue::new().with_async_persistence(persistence));

        svc.create_with_binding_async(
            ApprovalRequest {
                id: "svc-async".into(),
                principal: "p".into(),
                action: "act".into(),
                resource: "res".into(),
                reason: None,
            },
            Some(5),
            Some("ah".into()),
        )
        .await
        .unwrap();
        assert_eq!(svc.pending_async(1).await.unwrap().len(), 1);
        assert!(matches!(
            svc.evaluate_async("svc-async", 1, Some("wrong")).await,
            Err(BrokerError::InjectionDenied(_))
        ));
        assert_eq!(
            svc.resolve_with_meta_async(
                "svc-async",
                ApprovalStatus::Denied,
                2,
                ApprovalDecisionMeta {
                    resolver: Some("r".into()),
                    args_hash: Some("ah".into()),
                    enforce_args_hash_binding: true,
                },
            )
            .await
            .unwrap(),
            ApprovalStatus::Denied
        );
        let rec = svc.rehydrate_async("svc-async").await.unwrap().unwrap();
        assert_eq!(rec.status.effective(), ApprovalStatus::Denied);

        // timeout reconcile path via service for a second record
        svc.create_async(
            ApprovalRequest {
                id: "svc-timeout".into(),
                principal: "p".into(),
                action: "act".into(),
                resource: "res".into(),
                reason: None,
            },
            Some(7),
        )
        .await
        .unwrap();
        let timed = svc
            .reconcile_async("svc-timeout", 7)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(timed.status, ApprovalStatus::TimedOut);
        let denied = svc.evaluate_async("svc-timeout", 8, None).await.unwrap();
        assert_eq!(denied.effective, ApprovalStatus::Denied);
        assert!(!denied.allows());
    }

    #[test]
    fn env_secret_resolver_is_fail_closed() {
        let r = EnvSecretResolver;
        let ctx = SecretResolutionContext {
            tool: "t".into(),
            principal: None,
            args_hash: None,
        };
        assert!(matches!(
            r.resolve(&SecretRef("env:__BROKER_MISSING_ENV__".into()), &ctx),
            Err(BrokerError::SecretNotFound(_))
        ));
        assert!(matches!(
            r.resolve(&SecretRef("env:   ".into()), &ctx),
            Err(BrokerError::SecretNotFound(_))
        ));
    }

    #[test]
    fn file_secret_resolver_is_fail_closed() {
        let r = FileSecretResolver;
        let ctx = SecretResolutionContext {
            tool: "t".into(),
            principal: None,
            args_hash: None,
        };
        assert!(matches!(
            r.resolve(
                &SecretRef("file:/tmp/__broker_missing_secret_file__".into()),
                &ctx
            ),
            Err(BrokerError::ResolutionFailed(_))
        ));
        assert!(matches!(
            r.resolve(&SecretRef("file:".into()), &ctx),
            Err(BrokerError::SecretNotFound(_))
        ));
    }

    #[test]
    fn scheme_resolver_routes_env_file_and_fails_closed() {
        let r = SchemeResolvingSecretResolver;
        let ctx = SecretResolutionContext {
            tool: "t".into(),
            principal: None,
            args_hash: None,
        };
        let key = "BROKER_SCHEME_RESOLVER_KEY";
        std::env::set_var(key, "env-val");
        let resolved = r.resolve(&SecretRef(format!("env:{key}")), &ctx).unwrap();
        assert_eq!(resolved.value, "env-val");
        std::env::remove_var(key);

        let path = std::env::temp_dir().join("broker_scheme_resolver_secret.txt");
        std::fs::write(&path, "file-val").unwrap();
        let pstr = path.to_string_lossy().to_string();
        let fres = r.resolve(&SecretRef(format!("file:{pstr}")), &ctx).unwrap();
        assert_eq!(fres.value, "file-val");
        std::fs::remove_file(&path).unwrap();

        assert!(matches!(
            r.resolve(&SecretRef("unknown:secret".into()), &ctx),
            Err(BrokerError::SecretNotFound(_))
        ));
    }

    #[test]
    fn env_file_backends_inject_and_redact_fail_closed() {
        let key = "BROKER_TEST_INJECT_ENV";
        std::env::set_var(key, "supersecret");
        let env_broker =
            ResolvingCredentialBroker::new(EnvSecretResolver).with_policy(RedactionPolicy {
                rules: vec![RedactionRule::KeepEdges {
                    prefix: 2,
                    suffix: 2,
                    mask: '*',
                }],
            });
        let mut target = String::new();
        let injected = env_broker
            .inject("tool.http", &SecretRef(format!("env:{key}")), &mut target)
            .unwrap();
        assert_eq!(target, "supersecret");
        assert_eq!(injected.redacted, "su*******et");
        std::env::remove_var(key);
        let mut t2 = String::new();
        assert!(env_broker
            .inject("tool.http", &SecretRef(format!("env:{key}")), &mut t2)
            .is_err());

        let dir = std::env::temp_dir();
        let path = dir.join("broker_test_inject_file.txt");
        std::fs::write(&path, "file-secret").unwrap();
        let pstr = path.to_string_lossy().to_string();
        let file_broker = ResolvingCredentialBroker::new(FileSecretResolver);
        let mut ft = String::new();
        let finj = file_broker
            .inject("tool.fs", &SecretRef(format!("file:{pstr}")), &mut ft)
            .unwrap();
        assert_eq!(ft, "file-secret");
        assert_eq!(finj.redacted, "[REDACTED]");
        std::fs::remove_file(&path).unwrap();
        let mut ft2 = String::new();
        assert!(file_broker
            .inject("tool.fs", &SecretRef(format!("file:{pstr}")), &mut ft2)
            .is_err());
    }

    #[test]
    fn request_response_scrubber_redacts_registered_secrets() {
        let mut scrubber = SecretScrubber::new();
        let resolved = ResolvedSecret {
            reference: SecretRef("s://k".into()),
            value: "supersecret".into(),
        };
        scrubber.register_resolved(&resolved, &RedactionPolicy::default());
        let req = "POST /api Authorization: supersecret body=ok";
        let resp = "{\"token\":\"supersecret\",\"ok\":true}";
        assert_eq!(
            scrubber.redact_request(req),
            "POST /api Authorization: [REDACTED] body=ok"
        );
        assert_eq!(
            scrubber.redact_response(resp),
            "{\"token\":\"[REDACTED]\",\"ok\":true}"
        );
        assert!(!scrubber.scrub("no secrets here").contains("REDACTED"));
    }

    #[test]
    fn scrub_targets_redact_map_and_pairs_fail_closed_no_secret_leak() {
        let mut scrubber = SecretScrubber::new();
        scrubber.register_secret("topsecret", "[REDACTED]");
        let mut headers = HashMap::from([
            ("authorization".to_string(), "Bearer topsecret".to_string()),
            ("x-ok".to_string(), "safe".to_string()),
        ]);
        scrubber.scrub_map(&mut headers);
        assert_eq!(
            headers.get("authorization").map(String::as_str),
            Some("Bearer [REDACTED]")
        );
        assert_eq!(headers.get("x-ok").map(String::as_str), Some("safe"));

        let mut pairs = vec![
            ("token".to_string(), "topsecret".to_string()),
            ("plain".to_string(), "value".to_string()),
        ];
        scrubber.scrub_pairs(&mut pairs);
        assert_eq!(pairs[0].1, "[REDACTED]");
        assert_eq!(pairs[1].1, "value");

        // no-op/unknown content remains unchanged and no panic
        let mut empty = HashMap::<String, String>::new();
        scrubber.scrub_map(&mut empty);
        assert!(empty.is_empty());
    }

    #[test]
    fn upstream_injection_hooks_redact_and_fail_closed() {
        let mut resolver = StaticSecretResolver::new();
        resolver.insert(SecretRef("env:API_KEY".into()), "live-secret");
        let broker = ResolvingCredentialBroker::new(resolver).with_policy(RedactionPolicy {
            rules: vec![RedactionRule::KeepEdges {
                prefix: 2,
                suffix: 2,
                mask: '*',
            }],
        });
        let ctx = SecretResolutionContext {
            tool: "tool.http".into(),
            principal: Some("p".into()),
            args_hash: Some("h".into()),
        };
        let mut headers = HashMap::new();
        let mut scrubber = SecretScrubber::new();
        let injected = broker
            .inject_for_upstream_call(
                "tool.http",
                &SecretRef("env:API_KEY".into()),
                &ctx,
                "authorization",
                &mut headers,
                &mut scrubber,
            )
            .unwrap();
        assert_eq!(
            headers.get("authorization").map(String::as_str),
            Some("live-secret")
        );
        assert_eq!(injected.redacted, "li*******et");
        assert_eq!(
            scrubber.redact_request("authorization=live-secret"),
            "authorization=li*******et"
        );
        assert_eq!(
            scrubber.redact_response("leaked live-secret"),
            "leaked li*******et"
        );

        let mut pairs: Vec<(String, String)> = Vec::new();
        let mut t = String::new();
        let inj2 = broker
            .inject_resolved_into(
                "tool.http",
                &SecretRef("env:API_KEY".into()),
                &ctx,
                "Authorization",
                &mut pairs,
            )
            .unwrap();
        assert_eq!(pairs, vec![("Authorization".into(), "live-secret".into())]);
        assert_eq!(inj2.redacted, "li*******et");
        broker
            .inject_resolved_into(
                "tool.http",
                &SecretRef("env:API_KEY".into()),
                &ctx,
                "",
                &mut t,
            )
            .unwrap();
        assert_eq!(t, "live-secret");

        let mut denied = HashMap::new();
        assert!(matches!(
            broker.inject_resolved_into(
                "tool.http",
                &SecretRef("missing".into()),
                &ctx,
                "authorization",
                &mut denied,
            ),
            Err(BrokerError::ResolutionFailed(_))
        ));
        assert!(denied.is_empty());
    }

    #[tokio::test]
    async fn approval_pause_resume_signal_wakes_on_resolve() {
        let svc = ApprovalBrokerService::new(ApprovalQueue::new());
        svc.create_with_binding_async(
            ApprovalRequest {
                id: "sig1".into(),
                principal: "p".into(),
                action: "a".into(),
                resource: "r".into(),
                reason: None,
            },
            Some(100),
            Some("h".into()),
        )
        .await
        .unwrap();
        let signal = svc.resume_signal("sig1").unwrap();
        let waiter = tokio::spawn(async move {
            signal.notified().await;
        });
        tokio::task::yield_now().await;
        svc.resolve_async("sig1", ApprovalStatus::Approved, 1)
            .await
            .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(1), waiter)
            .await
            .expect("resume signal")
            .unwrap();
        let decision = svc.evaluate_async("sig1", 2, Some("h")).await.unwrap();
        assert!(decision.allows());
    }

    #[tokio::test]
    async fn approval_pause_resume_signal_wakes_on_timeout_and_reconcile_idempotent() {
        let store = Arc::new(store::InMemoryStore::default());
        let persistence = Arc::new(StoreBackedAsyncApprovalPersistence::new(store));
        let svc =
            ApprovalBrokerService::new(ApprovalQueue::new().with_async_persistence(persistence));
        svc.create_async(
            ApprovalRequest {
                id: "sig2".into(),
                principal: "p".into(),
                action: "a".into(),
                resource: "r".into(),
                reason: None,
            },
            Some(5),
        )
        .await
        .unwrap();
        let signal = svc.resume_signal("sig2").unwrap();
        let waiter = tokio::spawn(async move {
            signal.notified().await;
        });
        tokio::task::yield_now().await;
        let expired = svc.expire_timeouts_async(5).await.unwrap();
        assert_eq!(expired, vec!["sig2".to_string()]);
        tokio::time::timeout(std::time::Duration::from_secs(1), waiter)
            .await
            .expect("timeout resume signal")
            .unwrap();
        let rec = svc
            .reconcile_idempotent_async("sig2", 6)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(rec.status.effective(), ApprovalStatus::Denied);
        // idempotent reconcile/evaluate
        let rec2 = svc
            .reconcile_idempotent_async("sig2", 7)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(rec2.status.effective(), ApprovalStatus::Denied);
        assert!(!svc.evaluate_async("sig2", 7, None).await.unwrap().allows());
    }
}
