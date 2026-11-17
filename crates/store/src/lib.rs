//! Store crate: persistence boundaries for ScopeGate.
//!
//! In-memory implementation for dev/test plus schema-aligned models, query
//! abstractions, hook placeholders, and SQLite/Postgres adapter scaffolding.
//! Enforces append-before-return semantics and hash-chained audit integrity.
//!
//! Durable adapters are structured for `sqlx` behind `sqlite-sqlx`/`postgres-sqlx`
//! feature flags with migration helpers and transaction-semantics placeholders.

pub mod durable;
pub mod migrations;
pub mod postgres;
pub mod sqlite;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};

pub use durable::{map_durable_error, AuditAppendPlan, TransactionContext};
pub use migrations::{
    apply_migrations, migrations_for, postgres_migrations, sqlite_migrations, Migration,
};
pub use postgres::PostgresStore;
pub use sqlite::SqliteStore;

pub type StoreResult<T> = Result<T, StoreError>;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("not implemented: {0}")]
    NotImplemented(&'static str),
    #[error("storage unavailable: {0}")]
    Unavailable(String),
    #[error("integrity violation: {0}")]
    Integrity(String),
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("invalid data: {0}")]
    Invalid(String),
    #[error("not found: {0}")]
    NotFound(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendKind {
    SqliteWal,
    Postgres,
    InMemory,
}

impl fmt::Display for BackendKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SqliteWal => write!(f, "sqlite_wal"),
            Self::Postgres => write!(f, "postgres"),
            Self::InMemory => write!(f, "in_memory"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoreConfig {
    pub backend: BackendKind,
    /// e.g. sqlite path / postgres URL. Real implementations should source secrets safely.
    pub database_url: String,
    /// Fail closed on audit persistence/integrity failures (PRD default behavior).
    pub fail_closed_on_audit_error: bool,
}

impl Default for StoreConfig {
    fn default() -> Self {
        Self {
            backend: BackendKind::SqliteWal,
            database_url: "sqlite://scopegate.db".to_string(),
            fail_closed_on_audit_error: true,
        }
    }
}

// --- Schema-aligned domain models & query abstractions ---

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PolicyRecord {
    pub id: String,
    pub version: i64,
    pub body: String,
    pub created_at: String,
    pub active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TaskRecord {
    pub id: String,
    pub parent_id: Option<String>,
    pub token_id: String,
    /// Serialized scopes/caveats placeholder (JSON string in early adapters).
    pub scopes: String,
    pub budget: i64,
    pub expires_at: String,
    pub revoked: bool,
    pub revocation_reason: Option<String>,
    pub taint_snapshot_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalStatus {
    #[default]
    Pending,
    Approved,
    Denied,
    Expired,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ApprovalRecord {
    pub id: String,
    pub task_id: String,
    pub tool: String,
    pub args_hash: String,
    pub status: ApprovalStatus,
    pub created_at: String,
    pub resolved_at: Option<String>,
    pub resolver: Option<String>,
}

/// Hash-chained audit event.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AuditEvent {
    /// Monotonic sequence assigned by the store/backend.
    pub seq: i64,
    pub ts: String,
    pub task_id: Option<String>,
    pub tool: Option<String>,
    pub decision: String,
    pub reason: Option<String>,
    pub args_digest: Option<String>,
    pub result_digest: Option<String>,
    pub prev_hash: Option<Vec<u8>>,
    pub hash: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AuditVerificationReport {
    pub ok: bool,
    pub checked_events: u64,
    pub first_bad_seq: Option<i64>,
    pub message: Option<String>,
    /// Hex-encoded expected hash at failure point (if computed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_hash_hex: Option<String>,
    /// Hex-encoded actual stored hash at failure point.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actual_hash_hex: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AuditQuery {
    pub task_id: Option<String>,
    pub decision: Option<String>,
    pub from_ts: Option<String>,
    pub to_ts: Option<String>,
    pub offset: Option<u32>,
    pub limit: Option<u32>,
}

/// Schema-aligned revocation row.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RevocationRecord {
    pub id: String,
    pub target_kind: String, // e.g. task/token/session
    pub target_id: String,
    pub reason: Option<String>,
    pub revoked_at: String,
    pub revoked_by: Option<String>,
}

/// Schema-aligned taint snapshot row (state snapshot for audit/revocation decisions).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TaintSnapshotRecord {
    pub id: String,
    pub task_id: Option<String>,
    pub source: String,
    pub labels: Vec<String>,
    pub digest: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TaskQuery {
    pub revoked: Option<bool>,
    pub parent_id: Option<String>,
    pub token_id: Option<String>,
    pub taint_snapshot_id: Option<String>,
    pub offset: Option<u32>,
    pub limit: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RevocationQuery {
    pub target_kind: Option<String>,
    pub target_id: Option<String>,
    pub offset: Option<u32>,
    pub limit: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TaintSnapshotQuery {
    pub task_id: Option<String>,
    pub source: Option<String>,
    pub offset: Option<u32>,
    pub limit: Option<u32>,
}

/// Hook placeholders for revocation/taint snapshot side effects.
pub trait RevocationHook: Send + Sync {
    fn on_revocation(&self, _record: &RevocationRecord) -> StoreResult<()> {
        Ok(())
    }
}
pub trait TaintSnapshotHook: Send + Sync {
    fn on_snapshot(&self, _record: &TaintSnapshotRecord) -> StoreResult<()> {
        Ok(())
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct NoopRevocationHook;
impl RevocationHook for NoopRevocationHook {}
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopTaintSnapshotHook;
impl TaintSnapshotHook for NoopTaintSnapshotHook {}

#[async_trait]
pub trait Store: Send + Sync {
    fn backend(&self) -> BackendKind;
    async fn append_audit_event(&self, event: AuditEvent) -> StoreResult<AuditEvent>;
    async fn query_audit(&self, query: AuditQuery) -> StoreResult<Vec<AuditEvent>>;
    async fn verify_audit_chain(&self) -> StoreResult<AuditVerificationReport>;
    async fn create_approval(&self, approval: ApprovalRecord) -> StoreResult<ApprovalRecord>;
    async fn get_approval(&self, id: &str) -> StoreResult<Option<ApprovalRecord>>;
    async fn resolve_approval(
        &self,
        id: &str,
        status: ApprovalStatus,
        resolver: Option<String>,
        resolved_at: String,
    ) -> StoreResult<ApprovalRecord>;
    async fn upsert_task(&self, task: TaskRecord) -> StoreResult<TaskRecord>;
    async fn get_task(&self, id: &str) -> StoreResult<Option<TaskRecord>>;
    async fn list_tasks(&self, query: TaskQuery) -> StoreResult<Vec<TaskRecord>>;
    async fn upsert_policy(&self, policy: PolicyRecord) -> StoreResult<PolicyRecord>;
    async fn get_active_policy(&self) -> StoreResult<Option<PolicyRecord>>;
    async fn record_revocation(&self, record: RevocationRecord) -> StoreResult<RevocationRecord>;
    async fn list_revocations(&self, query: RevocationQuery) -> StoreResult<Vec<RevocationRecord>>;
    async fn record_taint_snapshot(
        &self,
        snapshot: TaintSnapshotRecord,
    ) -> StoreResult<TaintSnapshotRecord>;
    async fn list_taint_snapshots(
        &self,
        query: TaintSnapshotQuery,
    ) -> StoreResult<Vec<TaintSnapshotRecord>>;
    async fn health_check(&self) -> StoreResult<()>;
}

#[derive(Debug, Default)]
pub struct UnimplementedStore;

#[async_trait]
impl Store for UnimplementedStore {
    fn backend(&self) -> BackendKind {
        BackendKind::SqliteWal
    }
    async fn append_audit_event(&self, _event: AuditEvent) -> StoreResult<AuditEvent> {
        Err(StoreError::NotImplemented("append_audit_event"))
    }
    async fn query_audit(&self, _query: AuditQuery) -> StoreResult<Vec<AuditEvent>> {
        Err(StoreError::NotImplemented("query_audit"))
    }
    async fn verify_audit_chain(&self) -> StoreResult<AuditVerificationReport> {
        Err(StoreError::NotImplemented("verify_audit_chain"))
    }
    async fn create_approval(&self, _approval: ApprovalRecord) -> StoreResult<ApprovalRecord> {
        Err(StoreError::NotImplemented("create_approval"))
    }
    async fn get_approval(&self, _id: &str) -> StoreResult<Option<ApprovalRecord>> {
        Err(StoreError::NotImplemented("get_approval"))
    }
    async fn resolve_approval(
        &self,
        _id: &str,
        _status: ApprovalStatus,
        _resolver: Option<String>,
        _resolved_at: String,
    ) -> StoreResult<ApprovalRecord> {
        Err(StoreError::NotImplemented("resolve_approval"))
    }
    async fn upsert_task(&self, _task: TaskRecord) -> StoreResult<TaskRecord> {
        Err(StoreError::NotImplemented("upsert_task"))
    }
    async fn get_task(&self, _id: &str) -> StoreResult<Option<TaskRecord>> {
        Err(StoreError::NotImplemented("get_task"))
    }
    async fn list_tasks(&self, _query: TaskQuery) -> StoreResult<Vec<TaskRecord>> {
        Err(StoreError::NotImplemented("list_tasks"))
    }
    async fn upsert_policy(&self, _policy: PolicyRecord) -> StoreResult<PolicyRecord> {
        Err(StoreError::NotImplemented("upsert_policy"))
    }
    async fn get_active_policy(&self) -> StoreResult<Option<PolicyRecord>> {
        Err(StoreError::NotImplemented("get_active_policy"))
    }
    async fn record_revocation(&self, _record: RevocationRecord) -> StoreResult<RevocationRecord> {
        Err(StoreError::NotImplemented("record_revocation"))
    }
    async fn list_revocations(
        &self,
        _query: RevocationQuery,
    ) -> StoreResult<Vec<RevocationRecord>> {
        Err(StoreError::NotImplemented("list_revocations"))
    }
    async fn record_taint_snapshot(
        &self,
        _snapshot: TaintSnapshotRecord,
    ) -> StoreResult<TaintSnapshotRecord> {
        Err(StoreError::NotImplemented("record_taint_snapshot"))
    }
    async fn list_taint_snapshots(
        &self,
        _query: TaintSnapshotQuery,
    ) -> StoreResult<Vec<TaintSnapshotRecord>> {
        Err(StoreError::NotImplemented("list_taint_snapshots"))
    }
    async fn health_check(&self) -> StoreResult<()> {
        Err(StoreError::NotImplemented("health_check"))
    }
}

/// Compute the canonical hash for an audit event (includes `prev_hash`).
pub fn compute_audit_hash(ev: &AuditEvent) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(ev.seq.to_be_bytes());
    h.update(ev.ts.as_bytes());
    h.update([0]);
    h.update(ev.task_id.as_deref().unwrap_or("").as_bytes());
    h.update([0]);
    h.update(ev.tool.as_deref().unwrap_or("").as_bytes());
    h.update([0]);
    h.update(ev.decision.as_bytes());
    h.update([0]);
    h.update(ev.reason.as_deref().unwrap_or("").as_bytes());
    h.update([0]);
    h.update(ev.args_digest.as_deref().unwrap_or("").as_bytes());
    h.update([0]);
    h.update(ev.result_digest.as_deref().unwrap_or("").as_bytes());
    h.update([0]);
    if let Some(p) = &ev.prev_hash {
        h.update(p);
    }
    h.finalize().to_vec()
}

/// Verify a sequence of audit events as an ordered hash chain.
/// Reports the first integrity break with diagnostic hashes.
pub fn verify_audit_chain_events(events: &[AuditEvent]) -> AuditVerificationReport {
    let mut prev: Option<Vec<u8>> = None;
    for (i, ev) in events.iter().enumerate() {
        if ev.prev_hash != prev {
            return AuditVerificationReport {
                ok: false,
                checked_events: i as u64,
                first_bad_seq: Some(ev.seq),
                message: Some("prev_hash mismatch".into()),
                expected_hash_hex: prev.as_ref().map(hex::encode),
                actual_hash_hex: ev.prev_hash.as_ref().map(hex::encode),
            };
        }
        let expected = compute_audit_hash(ev);
        if ev.hash.as_ref() != Some(&expected) {
            return AuditVerificationReport {
                ok: false,
                checked_events: i as u64,
                first_bad_seq: Some(ev.seq),
                message: Some("hash mismatch".into()),
                expected_hash_hex: Some(hex::encode(&expected)),
                actual_hash_hex: ev.hash.as_ref().map(hex::encode),
            };
        }
        prev = ev.hash.clone();
    }
    AuditVerificationReport {
        ok: true,
        checked_events: events.len() as u64,
        first_bad_seq: None,
        message: None,
        expected_hash_hex: None,
        actual_hash_hex: None,
    }
}

/// Resolve latest taint snapshot for a task from a snapshot list (by `created_at`, then id).
pub fn latest_taint_snapshot_for_task<'a>(
    snapshots: impl IntoIterator<Item = &'a TaintSnapshotRecord>,
    task_id: &str,
) -> Option<&'a TaintSnapshotRecord> {
    snapshots
        .into_iter()
        .filter(|s| s.task_id.as_deref() == Some(task_id))
        .max_by(|a, b| a.created_at.cmp(&b.created_at).then(a.id.cmp(&b.id)))
}

// --- In-memory store ---

#[derive(Default)]
struct InMemoryState {
    audit: Vec<AuditEvent>,
    approvals: HashMap<String, ApprovalRecord>,
    tasks: HashMap<String, TaskRecord>,
    policies: HashMap<String, PolicyRecord>,
    revocations: HashMap<String, RevocationRecord>,
    taint_snapshots: HashMap<String, TaintSnapshotRecord>,
    next_seq: i64,
}

#[derive(Clone)]
pub struct InMemoryStore {
    config: StoreConfig,
    state: Arc<Mutex<InMemoryState>>,
    revocation_hook: Arc<dyn RevocationHook>,
    taint_snapshot_hook: Arc<dyn TaintSnapshotHook>,
}

impl InMemoryStore {
    pub fn new(config: StoreConfig) -> Self {
        Self::with_hooks(
            config,
            Arc::new(NoopRevocationHook),
            Arc::new(NoopTaintSnapshotHook),
        )
    }

    pub fn with_hooks(
        config: StoreConfig,
        revocation_hook: Arc<dyn RevocationHook>,
        taint_snapshot_hook: Arc<dyn TaintSnapshotHook>,
    ) -> Self {
        Self {
            config,
            state: Arc::new(Mutex::new(InMemoryState {
                next_seq: 1,
                ..Default::default()
            })),
            revocation_hook,
            taint_snapshot_hook,
        }
    }

    fn lock(&self) -> StoreResult<std::sync::MutexGuard<'_, InMemoryState>> {
        self.state
            .lock()
            .map_err(|_| StoreError::Unavailable("mutex poisoned".into()))
    }

    fn compute_hash(ev: &AuditEvent) -> Vec<u8> {
        compute_audit_hash(ev)
    }
}

impl Default for InMemoryStore {
    fn default() -> Self {
        Self::new(StoreConfig {
            backend: BackendKind::InMemory,
            database_url: "memory://".into(),
            fail_closed_on_audit_error: true,
        })
    }
}

#[async_trait]
impl Store for InMemoryStore {
    fn backend(&self) -> BackendKind {
        BackendKind::InMemory
    }

    async fn append_audit_event(&self, mut event: AuditEvent) -> StoreResult<AuditEvent> {
        let mut st = self.lock()?;
        let seq = st.next_seq;
        st.next_seq += 1;
        event.seq = seq;
        event.prev_hash = st.audit.last().and_then(|e| e.hash.clone());
        event.hash = Some(Self::compute_hash(&event));
        // append-before-return
        st.audit.push(event.clone());
        Ok(event)
    }

    async fn query_audit(&self, query: AuditQuery) -> StoreResult<Vec<AuditEvent>> {
        let st = self.lock()?;
        let mut out: Vec<AuditEvent> = st
            .audit
            .iter()
            .filter(|e| {
                if let Some(t) = &query.task_id {
                    if e.task_id.as_deref() != Some(t.as_str()) {
                        return false;
                    }
                }
                if let Some(d) = &query.decision {
                    if &e.decision != d {
                        return false;
                    }
                }
                if let Some(from) = &query.from_ts {
                    if &e.ts < from {
                        return false;
                    }
                }
                if let Some(to) = &query.to_ts {
                    if &e.ts > to {
                        return false;
                    }
                }
                true
            })
            .cloned()
            .collect();
        let offset = query.offset.unwrap_or(0) as usize;
        if offset > 0 {
            if offset >= out.len() {
                out.clear();
            } else {
                out.drain(0..offset);
            }
        }
        if let Some(lim) = query.limit {
            out.truncate(lim as usize);
        }
        Ok(out)
    }

    async fn verify_audit_chain(&self) -> StoreResult<AuditVerificationReport> {
        let st = self.lock()?;
        let rep = verify_audit_chain_events(&st.audit);
        if !rep.ok && self.config.fail_closed_on_audit_error {
            return Err(StoreError::Integrity(
                rep.message
                    .clone()
                    .unwrap_or_else(|| "audit chain invalid".into()),
            ));
        }
        Ok(rep)
    }

    async fn create_approval(&self, approval: ApprovalRecord) -> StoreResult<ApprovalRecord> {
        if approval.id.is_empty() {
            return Err(StoreError::Invalid("approval id required".into()));
        }
        let mut st = self.lock()?;
        if st.approvals.contains_key(&approval.id) {
            return Err(StoreError::Conflict(format!(
                "approval {} exists",
                approval.id
            )));
        }
        st.approvals.insert(approval.id.clone(), approval.clone());
        Ok(approval)
    }

    async fn get_approval(&self, id: &str) -> StoreResult<Option<ApprovalRecord>> {
        let st = self.lock()?;
        Ok(st.approvals.get(id).cloned())
    }

    async fn resolve_approval(
        &self,
        id: &str,
        status: ApprovalStatus,
        resolver: Option<String>,
        resolved_at: String,
    ) -> StoreResult<ApprovalRecord> {
        let mut st = self.lock()?;
        let a = st
            .approvals
            .get_mut(id)
            .ok_or_else(|| StoreError::NotFound(format!("approval {id}")))?;
        if a.status != ApprovalStatus::Pending {
            return Err(StoreError::Conflict("approval not pending".into()));
        }
        a.status = status;
        a.resolver = resolver;
        a.resolved_at = Some(resolved_at);
        Ok(a.clone())
    }

    async fn upsert_task(&self, task: TaskRecord) -> StoreResult<TaskRecord> {
        if task.id.is_empty() {
            return Err(StoreError::Invalid("task id required".into()));
        }
        let mut st = self.lock()?;
        st.tasks.insert(task.id.clone(), task.clone());
        Ok(task)
    }

    async fn get_task(&self, id: &str) -> StoreResult<Option<TaskRecord>> {
        let st = self.lock()?;
        Ok(st.tasks.get(id).cloned())
    }

    async fn list_tasks(&self, query: TaskQuery) -> StoreResult<Vec<TaskRecord>> {
        let st = self.lock()?;
        let mut out: Vec<TaskRecord> = st
            .tasks
            .values()
            .filter(|t| {
                if let Some(r) = query.revoked {
                    if t.revoked != r {
                        return false;
                    }
                }
                if let Some(p) = &query.parent_id {
                    if t.parent_id.as_deref() != Some(p.as_str()) {
                        return false;
                    }
                }
                if let Some(tok) = &query.token_id {
                    if &t.token_id != tok {
                        return false;
                    }
                }
                if let Some(snap) = &query.taint_snapshot_id {
                    if t.taint_snapshot_id.as_deref() != Some(snap.as_str()) {
                        return false;
                    }
                }
                true
            })
            .cloned()
            .collect();
        out.sort_by(|a, b| a.id.cmp(&b.id));
        let offset = query.offset.unwrap_or(0) as usize;
        if offset > 0 {
            if offset >= out.len() {
                out.clear();
            } else {
                out.drain(0..offset);
            }
        }
        if let Some(lim) = query.limit {
            out.truncate(lim as usize);
        }
        Ok(out)
    }

    async fn upsert_policy(&self, policy: PolicyRecord) -> StoreResult<PolicyRecord> {
        if policy.id.is_empty() {
            return Err(StoreError::Invalid("policy id required".into()));
        }
        let mut st = self.lock()?;
        if policy.active {
            for p in st.policies.values_mut() {
                p.active = false;
            }
        }
        st.policies.insert(policy.id.clone(), policy.clone());
        Ok(policy)
    }

    async fn get_active_policy(&self) -> StoreResult<Option<PolicyRecord>> {
        let st = self.lock()?;
        Ok(st
            .policies
            .values()
            .filter(|p| p.active)
            .max_by_key(|p| p.version)
            .cloned())
    }

    async fn record_revocation(&self, record: RevocationRecord) -> StoreResult<RevocationRecord> {
        if record.id.is_empty() || record.target_id.is_empty() || record.target_kind.is_empty() {
            return Err(StoreError::Invalid(
                "revocation id/target_kind/target_id required".into(),
            ));
        }
        self.revocation_hook.on_revocation(&record)?;
        let mut st = self.lock()?;
        st.revocations.insert(record.id.clone(), record.clone());
        if record.target_kind == "task" {
            if let Some(task) = st.tasks.get_mut(&record.target_id) {
                task.revoked = true;
                task.revocation_reason = record.reason.clone();
            }
        }
        Ok(record)
    }

    async fn list_revocations(&self, query: RevocationQuery) -> StoreResult<Vec<RevocationRecord>> {
        let st = self.lock()?;
        let mut out: Vec<RevocationRecord> = st
            .revocations
            .values()
            .filter(|r| {
                if let Some(k) = &query.target_kind {
                    if &r.target_kind != k {
                        return false;
                    }
                }
                if let Some(id) = &query.target_id {
                    if &r.target_id != id {
                        return false;
                    }
                }
                true
            })
            .cloned()
            .collect();
        out.sort_by(|a, b| a.revoked_at.cmp(&b.revoked_at).then(a.id.cmp(&b.id)));
        let offset = query.offset.unwrap_or(0) as usize;
        if offset > 0 {
            if offset >= out.len() {
                out.clear();
            } else {
                out.drain(0..offset);
            }
        }
        if let Some(lim) = query.limit {
            out.truncate(lim as usize);
        }
        Ok(out)
    }

    async fn record_taint_snapshot(
        &self,
        snapshot: TaintSnapshotRecord,
    ) -> StoreResult<TaintSnapshotRecord> {
        if snapshot.id.is_empty() || snapshot.source.is_empty() {
            return Err(StoreError::Invalid(
                "taint snapshot id/source required".into(),
            ));
        }
        self.taint_snapshot_hook.on_snapshot(&snapshot)?;
        let mut st = self.lock()?;
        st.taint_snapshots
            .insert(snapshot.id.clone(), snapshot.clone());
        if let Some(task_id) = &snapshot.task_id {
            if let Some(task) = st.tasks.get_mut(task_id) {
                // Integrate: link latest-known snapshot id to task record.
                task.taint_snapshot_id = Some(snapshot.id.clone());
            }
        }
        Ok(snapshot)
    }

    async fn list_taint_snapshots(
        &self,
        query: TaintSnapshotQuery,
    ) -> StoreResult<Vec<TaintSnapshotRecord>> {
        let st = self.lock()?;
        let mut out: Vec<TaintSnapshotRecord> = st
            .taint_snapshots
            .values()
            .filter(|s| {
                if let Some(t) = &query.task_id {
                    if s.task_id.as_deref() != Some(t.as_str()) {
                        return false;
                    }
                }
                if let Some(src) = &query.source {
                    if &s.source != src {
                        return false;
                    }
                }
                true
            })
            .cloned()
            .collect();
        out.sort_by(|a, b| a.created_at.cmp(&b.created_at).then(a.id.cmp(&b.id)));
        let offset = query.offset.unwrap_or(0) as usize;
        if offset > 0 {
            if offset >= out.len() {
                out.clear();
            } else {
                out.drain(0..offset);
            }
        }
        if let Some(lim) = query.limit {
            out.truncate(lim as usize);
        }
        Ok(out)
    }

    async fn health_check(&self) -> StoreResult<()> {
        self.lock().map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn audit_append_verify_ok() {
        let store = InMemoryStore::default();
        store
            .append_audit_event(AuditEvent {
                ts: "t1".into(),
                decision: "allow".into(),
                ..Default::default()
            })
            .await
            .unwrap();
        store
            .append_audit_event(AuditEvent {
                ts: "t2".into(),
                decision: "deny".into(),
                reason: Some("nope".into()),
                ..Default::default()
            })
            .await
            .unwrap();
        let rep = store.verify_audit_chain().await.unwrap();
        assert!(rep.ok && rep.checked_events == 2);
        let q = store
            .query_audit(AuditQuery {
                limit: Some(1),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(q.len(), 1);
        assert_eq!(q[0].seq, 1);
    }

    #[tokio::test]
    async fn audit_verify_detects_tamper_fail_closed() {
        let store = InMemoryStore::default();
        store
            .append_audit_event(AuditEvent {
                ts: "t1".into(),
                decision: "allow".into(),
                ..Default::default()
            })
            .await
            .unwrap();
        {
            let mut st = store.lock().unwrap();
            st.audit[0].decision = "tampered".into();
        }
        let err = store.verify_audit_chain().await.unwrap_err();
        assert!(matches!(err, StoreError::Integrity(_)));
    }

    #[tokio::test]
    async fn approval_flow_in_memory() {
        let store = InMemoryStore::default();
        let a = store
            .create_approval(ApprovalRecord {
                id: "ap1".into(),
                task_id: "task1".into(),
                tool: "echo".into(),
                args_hash: "h".into(),
                status: ApprovalStatus::Pending,
                created_at: "t".into(),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(a.status, ApprovalStatus::Pending);
        let got = store.get_approval("ap1").await.unwrap().unwrap();
        assert_eq!(got.tool, "echo");
        let resolved = store
            .resolve_approval(
                "ap1",
                ApprovalStatus::Approved,
                Some("user".into()),
                "t2".into(),
            )
            .await
            .unwrap();
        assert_eq!(resolved.status, ApprovalStatus::Approved);
        assert_eq!(resolved.resolver.as_deref(), Some("user"));
        let conflict = store
            .resolve_approval("ap1", ApprovalStatus::Denied, None, "t3".into())
            .await;
        assert!(matches!(conflict, Err(StoreError::Conflict(_))));
    }

    #[tokio::test]
    async fn revocation_marks_task_and_records_hook() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        struct Hook(Arc<AtomicUsize>);
        impl RevocationHook for Hook {
            fn on_revocation(&self, _record: &RevocationRecord) -> StoreResult<()> {
                self.0.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        }
        let hits = Arc::new(AtomicUsize::new(0));
        let store = InMemoryStore::with_hooks(
            StoreConfig {
                backend: BackendKind::InMemory,
                database_url: "memory://".into(),
                fail_closed_on_audit_error: true,
            },
            Arc::new(Hook(hits.clone())),
            Arc::new(NoopTaintSnapshotHook),
        );
        store
            .upsert_task(TaskRecord {
                id: "t1".into(),
                token_id: "tok".into(),
                scopes: "[]".into(),
                budget: 1,
                expires_at: "later".into(),
                ..Default::default()
            })
            .await
            .unwrap();
        store
            .record_revocation(RevocationRecord {
                id: "r1".into(),
                target_kind: "task".into(),
                target_id: "t1".into(),
                reason: Some("bad".into()),
                revoked_at: "now".into(),
                revoked_by: Some("sys".into()),
            })
            .await
            .unwrap();
        let task = store.get_task("t1").await.unwrap().unwrap();
        assert!(task.revoked);
        assert_eq!(task.revocation_reason.as_deref(), Some("bad"));
        let revs = store
            .list_revocations(RevocationQuery {
                target_id: Some("t1".into()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(revs.len(), 1);
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        let revoked = store
            .list_tasks(TaskQuery {
                revoked: Some(true),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(revoked.len(), 1);
    }

    #[tokio::test]
    async fn taint_snapshot_links_task() {
        let store = InMemoryStore::default();
        store
            .upsert_task(TaskRecord {
                id: "t2".into(),
                token_id: "tok".into(),
                scopes: "[]".into(),
                budget: 1,
                expires_at: "later".into(),
                ..Default::default()
            })
            .await
            .unwrap();
        store
            .record_taint_snapshot(TaintSnapshotRecord {
                id: "s1".into(),
                task_id: Some("t2".into()),
                source: "broker".into(),
                labels: vec!["pii".into()],
                digest: Some("d".into()),
                created_at: "now".into(),
            })
            .await
            .unwrap();
        let task = store.get_task("t2").await.unwrap().unwrap();
        assert_eq!(task.taint_snapshot_id.as_deref(), Some("s1"));
        let snaps = store
            .list_taint_snapshots(TaintSnapshotQuery {
                task_id: Some("t2".into()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(snaps.len(), 1);
        assert_eq!(snaps[0].labels, vec!["pii".to_string()]);
    }

    #[tokio::test]
    async fn audit_query_filters_and_offset() {
        let store = InMemoryStore::default();
        store
            .append_audit_event(AuditEvent {
                ts: "t1".into(),
                decision: "allow".into(),
                task_id: Some("a".into()),
                ..Default::default()
            })
            .await
            .unwrap();
        store
            .append_audit_event(AuditEvent {
                ts: "t2".into(),
                decision: "deny".into(),
                task_id: Some("a".into()),
                ..Default::default()
            })
            .await
            .unwrap();
        store
            .append_audit_event(AuditEvent {
                ts: "t3".into(),
                decision: "deny".into(),
                task_id: Some("b".into()),
                ..Default::default()
            })
            .await
            .unwrap();
        let deny = store
            .query_audit(AuditQuery {
                decision: Some("deny".into()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(deny.len(), 2);
        let page = store
            .query_audit(AuditQuery {
                decision: Some("deny".into()),
                offset: Some(1),
                limit: Some(1),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(page.len(), 1);
        assert_eq!(page[0].task_id.as_deref(), Some("b"));
    }

    #[tokio::test]
    async fn audit_verify_reports_hash_details() {
        let store = InMemoryStore::new(StoreConfig {
            backend: BackendKind::InMemory,
            database_url: "memory://".into(),
            fail_closed_on_audit_error: false,
        });
        store
            .append_audit_event(AuditEvent {
                ts: "t1".into(),
                decision: "allow".into(),
                ..Default::default()
            })
            .await
            .unwrap();
        {
            let mut st = store.lock().unwrap();
            st.audit[0].decision = "tampered".into();
        }
        let rep = store.verify_audit_chain().await.unwrap();
        assert!(!rep.ok);
        assert_eq!(rep.message.as_deref(), Some("hash mismatch"));
        assert!(rep.expected_hash_hex.is_some() && rep.actual_hash_hex.is_some());
    }

    #[tokio::test]
    async fn task_query_supports_token_and_offset() {
        let store = InMemoryStore::default();
        store
            .upsert_task(TaskRecord {
                id: "t1".into(),
                token_id: "tok-a".into(),
                scopes: "[]".into(),
                budget: 1,
                expires_at: "x".into(),
                ..Default::default()
            })
            .await
            .unwrap();
        store
            .upsert_task(TaskRecord {
                id: "t2".into(),
                token_id: "tok-b".into(),
                scopes: "[]".into(),
                budget: 1,
                expires_at: "x".into(),
                ..Default::default()
            })
            .await
            .unwrap();
        store
            .upsert_task(TaskRecord {
                id: "t3".into(),
                token_id: "tok-a".into(),
                scopes: "[]".into(),
                budget: 1,
                expires_at: "x".into(),
                ..Default::default()
            })
            .await
            .unwrap();
        let tok_a = store
            .list_tasks(TaskQuery {
                token_id: Some("tok-a".into()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(
            tok_a.iter().map(|t| t.id.as_str()).collect::<Vec<_>>(),
            vec!["t1", "t3"]
        );
        let paged = store
            .list_tasks(TaskQuery {
                token_id: Some("tok-a".into()),
                offset: Some(1),
                limit: Some(1),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(paged[0].id, "t3");
    }

    #[tokio::test]
    async fn taint_snapshot_latest_helper_and_source_filter() {
        let store = InMemoryStore::default();
        store
            .record_taint_snapshot(TaintSnapshotRecord {
                id: "s1".into(),
                task_id: Some("t".into()),
                source: "a".into(),
                labels: vec![],
                created_at: "2026-01-01".into(),
                ..Default::default()
            })
            .await
            .unwrap();
        store
            .record_taint_snapshot(TaintSnapshotRecord {
                id: "s2".into(),
                task_id: Some("t".into()),
                source: "b".into(),
                labels: vec![],
                created_at: "2026-01-02".into(),
                ..Default::default()
            })
            .await
            .unwrap();
        let all = store
            .list_taint_snapshots(TaintSnapshotQuery {
                task_id: Some("t".into()),
                ..Default::default()
            })
            .await
            .unwrap();
        let latest = latest_taint_snapshot_for_task(&all, "t").unwrap();
        assert_eq!(latest.id, "s2");
        let src_a = store
            .list_taint_snapshots(TaintSnapshotQuery {
                task_id: Some("t".into()),
                source: Some("a".into()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(src_a.len(), 1);
        assert_eq!(src_a[0].id, "s1");
    }

    #[test]
    fn verify_helper_detects_prev_hash_mismatch() {
        let e1 = AuditEvent {
            seq: 1,
            ts: "t1".into(),
            decision: "allow".into(),
            prev_hash: None,
            hash: None,
            ..Default::default()
        };
        let e1 = AuditEvent {
            hash: Some(compute_audit_hash(&e1)),
            ..e1
        };
        let mut e2 = AuditEvent {
            seq: 2,
            ts: "t2".into(),
            decision: "deny".into(),
            prev_hash: Some(vec![9, 9, 9]),
            hash: None,
            ..Default::default()
        };
        e2.hash = Some(compute_audit_hash(&e2));
        let rep = verify_audit_chain_events(&[e1, e2]);
        assert!(!rep.ok);
        assert_eq!(rep.message.as_deref(), Some("prev_hash mismatch"));
    }

    #[test]
    fn migrations_and_durable_helpers_exposed() {
        let sqlite = migrations_for(BackendKind::SqliteWal).unwrap();
        let pg = migrations_for(BackendKind::Postgres).unwrap();
        assert_eq!(sqlite[0].version, 1);
        assert_eq!(pg[0].name, "001_init");
        let plan = AuditAppendPlan {
            event: AuditEvent {
                ts: "t".into(),
                decision: "allow".into(),
                ..Default::default()
            },
            expected_prev_hash: None,
        };
        let ev = plan.materialize(1, None).unwrap();
        assert_eq!(ev.prev_hash, None);
        assert!(ev.hash.is_some());
    }

    #[tokio::test]
    async fn sqlite_postgres_construct_and_report_state() {
        let sqlite = SqliteStore::new(StoreConfig {
            backend: BackendKind::SqliteWal,
            database_url: "sqlite://x.db".into(),
            fail_closed_on_audit_error: true,
        })
        .unwrap();
        assert_eq!(sqlite.backend(), BackendKind::SqliteWal);
        // without connect(), durable ops must fail closed/unavailable (not silently succeed)
        let err = sqlite.health_check().await.unwrap_err();
        assert!(matches!(
            err,
            StoreError::Unavailable(_) | StoreError::NotImplemented(_)
        ));

        let pg = PostgresStore::new(StoreConfig {
            backend: BackendKind::Postgres,
            database_url: "postgres://localhost/db".into(),
            fail_closed_on_audit_error: true,
        })
        .unwrap();
        assert_eq!(pg.backend(), BackendKind::Postgres);
        let err = pg.query_audit(AuditQuery::default()).await.unwrap_err();
        assert!(matches!(
            err,
            StoreError::NotImplemented(_) | StoreError::Unavailable(_)
        ));

        let bad = SqliteStore::new(StoreConfig {
            backend: BackendKind::Postgres,
            ..Default::default()
        })
        .unwrap_err();
        assert!(matches!(bad, StoreError::Invalid(_)));
    }
}
