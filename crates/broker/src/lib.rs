//! Approval queue and credential broker primitives (M3).
//!
//! Enhancements: secret ref resolution abstraction, redaction rules,
//! approval queue idempotent resolve/args-hash binding placeholder/notification hooks,
//! approval persistence interface hooks, credential injection/redaction flows, and
//! idempotent/timeout behavior with integration-ready types.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};

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
}

impl fmt::Debug for ApprovalQueue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApprovalQueue")
            .field("records", &self.records)
            .field("notifier", &self.notifier.as_ref().map(|_| "<hook>"))
            .field("persistence", &self.persistence.as_ref().map(|_| "<hook>"))
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

    fn emit(&self, event: ApprovalEvent) {
        if let Some(n) = &self.notifier {
            n.notify(event);
        }
    }

    fn persist_err<E: fmt::Display>(e: E) -> BrokerError {
        BrokerError::PersistenceFailed(e.to_string())
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
            self.records.insert(rec.request.id.clone(), rec.clone());
            return Ok(Some(rec));
        }
        Ok(None)
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
        if tool.trim().is_empty() {
            return Err(BrokerError::InjectionDenied("empty tool".to_string()));
        }
        let resolved = self
            .resolver
            .resolve(secret, ctx)
            .map_err(|e| BrokerError::ResolutionFailed(e.to_string()))?;
        // Inject real value into target; metadata remains redacted.
        *target = resolved.value.clone();
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
}
