//! PostgreSQL store adapter.
//!
//! Structured for `sqlx::PgPool` behind `postgres-sqlx` feature.
//! Default build keeps operations explicitly not implemented pending pool-backed wiring.

use async_trait::async_trait;

use crate::{
    apply_migrations, migrations::postgres_migrations, ApprovalRecord, ApprovalStatus, AuditEvent,
    AuditQuery, AuditVerificationReport, BackendKind, PolicyRecord, RevocationQuery,
    RevocationRecord, Store, StoreConfig, StoreError, StoreResult, TaintSnapshotQuery,
    TaintSnapshotRecord, TaskQuery, TaskRecord,
};

#[cfg(feature = "postgres-sqlx")]
use {crate::durable::map_durable_error, sqlx::PgPool};

/// PostgreSQL store adapter scaffold.
#[derive(Debug, Clone)]
pub struct PostgresStore {
    config: StoreConfig,
    #[cfg(feature = "postgres-sqlx")]
    pool: Option<PgPool>,
}

impl PostgresStore {
    pub fn new(config: StoreConfig) -> StoreResult<Self> {
        if config.backend != BackendKind::Postgres {
            return Err(StoreError::Invalid(format!(
                "PostgresStore requires postgres backend, got {}",
                config.backend
            )));
        }
        Ok(Self {
            config,
            #[cfg(feature = "postgres-sqlx")]
            pool: None,
        })
    }

    /// Connect a durable pool (feature-gated).
    #[cfg(feature = "postgres-sqlx")]
    pub async fn connect(&mut self) -> StoreResult<()> {
        let pool = PgPool::connect(&self.config.database_url)
            .await
            .map_err(|e| map_durable_error("postgres connect", e))?;
        self.pool = Some(pool);
        Ok(())
    }

    /// Apply embedded SQL migrations in order.
    pub async fn migrate(&self) -> StoreResult<Vec<i64>> {
        let _planned: Vec<i64> = postgres_migrations().iter().map(|m| m.version).collect();
        apply_migrations(BackendKind::Postgres, &self.config.database_url).await
    }

    pub fn config(&self) -> &StoreConfig {
        &self.config
    }

    fn durable_unavailable(&self, op: &'static str) -> StoreError {
        let _ = &self.config.database_url;
        #[cfg(feature = "postgres-sqlx")]
        if self.pool.is_none() {
            return StoreError::Unavailable(format!("{op}: postgres pool not connected"));
        }
        StoreError::NotImplemented(op)
    }

    #[allow(dead_code)]
    fn audit_append_sql() -> &'static str {
        // Append-before-return shape (transaction):
        // BEGIN; SELECT ... FOR UPDATE on chain head/allocator as needed;
        // compute prev_hash/hash; INSERT audit_events ...; COMMIT;
        "INSERT INTO audit_events (seq, ts, task_id, tool, decision, reason, args_digest, result_digest, prev_hash, hash) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING seq"
    }
}

#[async_trait]
impl Store for PostgresStore {
    fn backend(&self) -> BackendKind {
        BackendKind::Postgres
    }

    async fn append_audit_event(&self, _event: AuditEvent) -> StoreResult<AuditEvent> {
        // TODO(sqlx): tx append-before-return with prev/hash computation and RETURNING.
        Err(self.durable_unavailable("postgres append_audit_event (sqlx tx TODO)"))
    }

    async fn query_audit(&self, _query: AuditQuery) -> StoreResult<Vec<AuditEvent>> {
        Err(self.durable_unavailable("postgres query_audit (sqlx TODO)"))
    }

    async fn verify_audit_chain(&self) -> StoreResult<AuditVerificationReport> {
        Err(self.durable_unavailable("postgres verify_audit_chain (sqlx TODO)"))
    }

    async fn create_approval(&self, _approval: ApprovalRecord) -> StoreResult<ApprovalRecord> {
        Err(self.durable_unavailable("postgres create_approval (sqlx TODO)"))
    }

    async fn get_approval(&self, _id: &str) -> StoreResult<Option<ApprovalRecord>> {
        Err(self.durable_unavailable("postgres get_approval (sqlx TODO)"))
    }

    async fn resolve_approval(
        &self,
        _id: &str,
        _status: ApprovalStatus,
        _resolver: Option<String>,
        _resolved_at: String,
    ) -> StoreResult<ApprovalRecord> {
        Err(self.durable_unavailable("postgres resolve_approval (sqlx TODO)"))
    }

    async fn upsert_task(&self, _task: TaskRecord) -> StoreResult<TaskRecord> {
        Err(self.durable_unavailable("postgres upsert_task (sqlx TODO)"))
    }

    async fn get_task(&self, _id: &str) -> StoreResult<Option<TaskRecord>> {
        Err(self.durable_unavailable("postgres get_task (sqlx TODO)"))
    }

    async fn list_tasks(&self, _query: TaskQuery) -> StoreResult<Vec<TaskRecord>> {
        Err(self.durable_unavailable("postgres list_tasks (sqlx TODO)"))
    }

    async fn upsert_policy(&self, _policy: PolicyRecord) -> StoreResult<PolicyRecord> {
        Err(self.durable_unavailable("postgres upsert_policy (sqlx TODO)"))
    }

    async fn get_active_policy(&self) -> StoreResult<Option<PolicyRecord>> {
        Err(self.durable_unavailable("postgres get_active_policy (sqlx TODO)"))
    }

    async fn record_revocation(&self, _record: RevocationRecord) -> StoreResult<RevocationRecord> {
        Err(self.durable_unavailable("postgres record_revocation (sqlx TODO)"))
    }

    async fn list_revocations(
        &self,
        _query: RevocationQuery,
    ) -> StoreResult<Vec<RevocationRecord>> {
        Err(self.durable_unavailable("postgres list_revocations (sqlx TODO)"))
    }

    async fn record_taint_snapshot(
        &self,
        _snapshot: TaintSnapshotRecord,
    ) -> StoreResult<TaintSnapshotRecord> {
        Err(self.durable_unavailable("postgres record_taint_snapshot (sqlx TODO)"))
    }

    async fn list_taint_snapshots(
        &self,
        _query: TaintSnapshotQuery,
    ) -> StoreResult<Vec<TaintSnapshotRecord>> {
        Err(self.durable_unavailable("postgres list_taint_snapshots (sqlx TODO)"))
    }

    async fn health_check(&self) -> StoreResult<()> {
        Err(self.durable_unavailable("postgres health_check (sqlx TODO)"))
    }
}
