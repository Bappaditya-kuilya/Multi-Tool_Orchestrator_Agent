//! PostgreSQL store adapter.
//!
//! Durable adapter for `sqlx::PgPool` behind `postgres-sqlx` feature.
//! Mirrors `SqliteStore` behavior as closely as practical.

use async_trait::async_trait;

use crate::{
    apply_migrations, ApprovalQuery, ApprovalRecord, ApprovalStatus, AuditEvent, AuditQuery,
    AuditVerificationReport, BackendKind, PolicyRecord, RevocationQuery, RevocationRecord, Store,
    StoreConfig, StoreError, StoreResult, TaintSnapshotQuery, TaintSnapshotRecord, TaskQuery,
    TaskRecord, ToolPinRecord,
};

#[cfg(feature = "postgres-sqlx")]
use crate::verify_audit_chain_events;

#[cfg(feature = "postgres-sqlx")]
use {
    crate::durable::map_durable_error,
    sqlx::{PgPool, Row},
};

/// PostgreSQL store adapter.
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
    ///
    /// Restart-safe/idempotent via shared migration tracking.
    pub async fn migrate(&self) -> StoreResult<Vec<i64>> {
        apply_migrations(BackendKind::Postgres, &self.config.database_url).await
    }

    pub fn config(&self) -> &StoreConfig {
        &self.config
    }

    #[cfg(feature = "postgres-sqlx")]
    fn pool(&self) -> StoreResult<&PgPool> {
        self.pool
            .as_ref()
            .ok_or_else(|| StoreError::Unavailable("postgres pool not connected".into()))
    }

    #[cfg(not(feature = "postgres-sqlx"))]
    fn durable_unavailable(&self, op: &'static str) -> StoreError {
        let _ = &self.config.database_url;
        StoreError::NotImplemented(op)
    }
}

#[cfg(feature = "postgres-sqlx")]
fn row_to_audit(row: &sqlx::postgres::PgRow) -> StoreResult<AuditEvent> {
    Ok(AuditEvent {
        seq: row
            .try_get("seq")
            .map_err(|e| StoreError::Invalid(e.to_string()))?,
        ts: row
            .try_get("ts")
            .map_err(|e| StoreError::Invalid(e.to_string()))?,
        task_id: row.try_get::<Option<String>, _>("task_id").unwrap_or(None),
        tool: row.try_get::<Option<String>, _>("tool").unwrap_or(None),
        decision: row
            .try_get("decision")
            .map_err(|e| StoreError::Invalid(e.to_string()))?,
        reason: row.try_get::<Option<String>, _>("reason").unwrap_or(None),
        args_digest: row
            .try_get::<Option<String>, _>("args_digest")
            .unwrap_or(None),
        result_digest: row
            .try_get::<Option<String>, _>("result_digest")
            .unwrap_or(None),
        prev_hash: row
            .try_get::<Option<Vec<u8>>, _>("prev_hash")
            .unwrap_or(None),
        hash: row.try_get::<Option<Vec<u8>>, _>("hash").unwrap_or(None),
    })
}

#[cfg(feature = "postgres-sqlx")]
fn approval_status_from_str(s: &str) -> StoreResult<ApprovalStatus> {
    match s {
        "pending" => Ok(ApprovalStatus::Pending),
        "approved" => Ok(ApprovalStatus::Approved),
        "denied" => Ok(ApprovalStatus::Denied),
        "expired" => Ok(ApprovalStatus::Expired),
        _ => Err(StoreError::Invalid(format!("unknown approval status {s}"))),
    }
}

#[cfg(feature = "postgres-sqlx")]
fn approval_status_to_str(s: ApprovalStatus) -> &'static str {
    match s {
        ApprovalStatus::Pending => "pending",
        ApprovalStatus::Approved => "approved",
        ApprovalStatus::Denied => "denied",
        ApprovalStatus::Expired => "expired",
    }
}

#[cfg(feature = "postgres-sqlx")]
fn is_unique_violation(err: &sqlx::Error) -> bool {
    match err {
        sqlx::Error::Database(db) => db.code().as_deref() == Some("23505"),
        _ => false,
    }
}

#[async_trait]
impl Store for PostgresStore {
    fn backend(&self) -> BackendKind {
        BackendKind::Postgres
    }

    async fn append_audit_event(&self, event: AuditEvent) -> StoreResult<AuditEvent> {
        #[cfg(not(feature = "postgres-sqlx"))]
        let _ = &event;
        #[cfg(feature = "postgres-sqlx")]
        {
            event.validate_for_append()?;
            let pool = self.pool()?;
            let mut tx = pool
                .begin()
                .await
                .map_err(|e| map_durable_error("postgres begin audit append", e))?;
            // Serialize audit appends for hash-chain integrity.
            sqlx::query("LOCK TABLE audit_events IN EXCLUSIVE MODE")
                .execute(&mut *tx)
                .await
                .map_err(|e| map_durable_error("postgres lock audit table", e))?;
            let head = sqlx::query("SELECT seq, hash FROM audit_events ORDER BY seq DESC LIMIT 1")
                .fetch_optional(&mut *tx)
                .await
                .map_err(|e| map_durable_error("postgres read audit head", e))?;
            let (next_seq, prev_hash): (i64, Option<Vec<u8>>) = if let Some(r) = head {
                let s: i64 = r
                    .try_get("seq")
                    .map_err(|e| StoreError::Invalid(e.to_string()))?;
                let h: Option<Vec<u8>> = r.try_get::<Option<Vec<u8>>, _>("hash").unwrap_or(None);
                (s + 1, h)
            } else {
                (1, None)
            };
            let event = crate::AuditAppendPlan::for_tail(event, prev_hash.clone())
                .materialize(next_seq, prev_hash)?;
            let ins = sqlx::query(
                "INSERT INTO audit_events (seq, ts, task_id, tool, decision, reason, args_digest, result_digest, prev_hash, hash)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
            )
            .bind(event.seq)
            .bind(&event.ts)
            .bind(&event.task_id)
            .bind(&event.tool)
            .bind(&event.decision)
            .bind(&event.reason)
            .bind(&event.args_digest)
            .bind(&event.result_digest)
            .bind(&event.prev_hash)
            .bind(&event.hash)
            .execute(&mut *tx)
            .await;
            if let Err(e) = ins {
                if is_unique_violation(&e) {
                    return Err(StoreError::Conflict(format!(
                        "audit append conflict at seq {}",
                        event.seq
                    )));
                }
                return Err(map_durable_error("postgres insert audit event", e));
            }
            tx.commit()
                .await
                .map_err(|e| map_durable_error("postgres commit audit append", e))?;
            return Ok(event);
        }
        #[cfg(not(feature = "postgres-sqlx"))]
        Err(self.durable_unavailable("postgres append_audit_event"))
    }

    async fn query_audit(&self, query: AuditQuery) -> StoreResult<Vec<AuditEvent>> {
        #[cfg(feature = "postgres-sqlx")]
        {
            let pool = self.pool()?;
            let mut sql = String::from(
                "SELECT seq, ts, task_id, tool, decision, reason, args_digest, result_digest, prev_hash, hash FROM audit_events WHERE 1=1",
            );
            let mut binds_i: i32 = 0;
            if query.task_id.is_some() {
                binds_i += 1;
                sql.push_str(&format!(" AND task_id = ${binds_i}"));
            }
            if query.decision.is_some() {
                binds_i += 1;
                sql.push_str(&format!(" AND decision = ${binds_i}"));
            }
            if query.from_ts.is_some() {
                binds_i += 1;
                sql.push_str(&format!(" AND ts >= ${binds_i}"));
            }
            if query.to_ts.is_some() {
                binds_i += 1;
                sql.push_str(&format!(" AND ts <= ${binds_i}"));
            }
            let limit_idx = binds_i + 1;
            let offset_idx = binds_i + 2;
            sql.push_str(&format!(
                " ORDER BY seq ASC LIMIT ${limit_idx} OFFSET ${offset_idx}"
            ));
            let limit = query.limit.map(|v| v as i64).unwrap_or(i64::MAX);
            let offset = query.offset.map(|v| v as i64).unwrap_or(0);
            let mut q = sqlx::query(&sql);
            if let Some(v) = query.task_id {
                q = q.bind(v);
            }
            if let Some(v) = query.decision {
                q = q.bind(v);
            }
            if let Some(v) = query.from_ts {
                q = q.bind(v);
            }
            if let Some(v) = query.to_ts {
                q = q.bind(v);
            }
            q = q.bind(limit).bind(offset);
            let rows = q
                .fetch_all(pool)
                .await
                .map_err(|e| map_durable_error("postgres query audit", e))?;
            return rows.iter().map(row_to_audit).collect();
        }
        #[cfg(not(feature = "postgres-sqlx"))]
        {
            let _ = query;
            Err(self.durable_unavailable("postgres query_audit"))
        }
    }

    async fn verify_audit_chain(&self) -> StoreResult<AuditVerificationReport> {
        #[cfg(feature = "postgres-sqlx")]
        {
            let pool = self.pool()?;
            let rows = sqlx::query(
                "SELECT seq, ts, task_id, tool, decision, reason, args_digest, result_digest, prev_hash, hash FROM audit_events ORDER BY seq ASC",
            )
            .fetch_all(pool)
            .await
            .map_err(|e| map_durable_error("postgres verify audit read", e))?;
            let events: Vec<AuditEvent> =
                rows.iter().map(row_to_audit).collect::<StoreResult<_>>()?;
            let rep = verify_audit_chain_events(&events);
            if !rep.ok && self.config.fail_closed_on_audit_error {
                return Err(StoreError::Integrity(
                    rep.message
                        .clone()
                        .unwrap_or_else(|| "audit chain invalid".into()),
                ));
            }
            return Ok(rep);
        }
        #[cfg(not(feature = "postgres-sqlx"))]
        Err(self.durable_unavailable("postgres verify_audit_chain"))
    }

    async fn create_approval(&self, approval: ApprovalRecord) -> StoreResult<ApprovalRecord> {
        #[cfg(feature = "postgres-sqlx")]
        {
            if approval.id.is_empty() {
                return Err(StoreError::Invalid("approval id required".into()));
            }
            let pool = self.pool()?;
            let res = sqlx::query(
                "INSERT INTO approvals (id, task_id, tool, args_hash, status, created_at, resolved_at, resolver)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
            )
            .bind(&approval.id)
            .bind(&approval.task_id)
            .bind(&approval.tool)
            .bind(&approval.args_hash)
            .bind(approval_status_to_str(approval.status))
            .bind(&approval.created_at)
            .bind(&approval.resolved_at)
            .bind(&approval.resolver)
            .execute(pool)
            .await;
            match res {
                Ok(_) => return Ok(approval),
                Err(e) => {
                    if is_unique_violation(&e) {
                        return Err(StoreError::Conflict(format!(
                            "approval {} exists",
                            approval.id
                        )));
                    }
                    return Err(map_durable_error("postgres create approval", e));
                }
            }
        }
        #[cfg(not(feature = "postgres-sqlx"))]
        {
            let _ = approval;
            Err(self.durable_unavailable("postgres create_approval"))
        }
    }

    async fn get_approval(&self, id: &str) -> StoreResult<Option<ApprovalRecord>> {
        #[cfg(feature = "postgres-sqlx")]
        {
            let pool = self.pool()?;
            let row = sqlx::query(
                "SELECT id, task_id, tool, args_hash, status, created_at, resolved_at, resolver FROM approvals WHERE id = $1",
            )
            .bind(id)
            .fetch_optional(pool)
            .await
            .map_err(|e| map_durable_error("postgres get approval", e))?;
            if let Some(r) = row {
                let status_s: String = r
                    .try_get("status")
                    .map_err(|e| StoreError::Invalid(e.to_string()))?;
                return Ok(Some(ApprovalRecord {
                    id: r
                        .try_get("id")
                        .map_err(|e| StoreError::Invalid(e.to_string()))?,
                    task_id: r
                        .try_get("task_id")
                        .map_err(|e| StoreError::Invalid(e.to_string()))?,
                    tool: r
                        .try_get("tool")
                        .map_err(|e| StoreError::Invalid(e.to_string()))?,
                    args_hash: r
                        .try_get("args_hash")
                        .map_err(|e| StoreError::Invalid(e.to_string()))?,
                    status: approval_status_from_str(&status_s)?,
                    created_at: r
                        .try_get("created_at")
                        .map_err(|e| StoreError::Invalid(e.to_string()))?,
                    resolved_at: r
                        .try_get::<Option<String>, _>("resolved_at")
                        .unwrap_or(None),
                    resolver: r.try_get::<Option<String>, _>("resolver").unwrap_or(None),
                }));
            }
            return Ok(None);
        }
        #[cfg(not(feature = "postgres-sqlx"))]
        {
            let _ = id;
            Err(self.durable_unavailable("postgres get_approval"))
        }
    }

    async fn list_approvals(&self, query: ApprovalQuery) -> StoreResult<Vec<ApprovalRecord>> {
        #[cfg(feature = "postgres-sqlx")]
        {
            let pool = self.pool()?;
            let mut sql = String::from(
                "SELECT id, task_id, tool, args_hash, status, created_at, resolved_at, resolver FROM approvals WHERE 1=1",
            );
            let mut binds_i: i32 = 0;
            if query.task_id.is_some() {
                binds_i += 1;
                sql.push_str(&format!(" AND task_id = ${binds_i}"));
            }
            if query.status.is_some() {
                binds_i += 1;
                sql.push_str(&format!(" AND status = ${binds_i}"));
            }
            let limit_idx = binds_i + 1;
            let offset_idx = binds_i + 2;
            sql.push_str(&format!(
                " ORDER BY created_at ASC, id ASC LIMIT ${limit_idx} OFFSET ${offset_idx}"
            ));
            let limit = query.limit.map(|v| v as i64).unwrap_or(i64::MAX);
            let offset = query.offset.map(|v| v as i64).unwrap_or(0);
            let mut q = sqlx::query(&sql);
            if let Some(v) = query.task_id {
                q = q.bind(v);
            }
            if let Some(v) = query.status {
                q = q.bind(approval_status_to_str(v));
            }
            q = q.bind(limit).bind(offset);
            let rows = q
                .fetch_all(pool)
                .await
                .map_err(|e| map_durable_error("postgres list approvals", e))?;
            let mut out = Vec::with_capacity(rows.len());
            for r in rows {
                let status_s: String = r
                    .try_get("status")
                    .map_err(|e| StoreError::Invalid(e.to_string()))?;
                out.push(ApprovalRecord {
                    id: r
                        .try_get("id")
                        .map_err(|e| StoreError::Invalid(e.to_string()))?,
                    task_id: r
                        .try_get("task_id")
                        .map_err(|e| StoreError::Invalid(e.to_string()))?,
                    tool: r
                        .try_get("tool")
                        .map_err(|e| StoreError::Invalid(e.to_string()))?,
                    args_hash: r
                        .try_get("args_hash")
                        .map_err(|e| StoreError::Invalid(e.to_string()))?,
                    status: approval_status_from_str(&status_s)?,
                    created_at: r
                        .try_get("created_at")
                        .map_err(|e| StoreError::Invalid(e.to_string()))?,
                    resolved_at: r
                        .try_get::<Option<String>, _>("resolved_at")
                        .unwrap_or(None),
                    resolver: r.try_get::<Option<String>, _>("resolver").unwrap_or(None),
                });
            }
            return Ok(out);
        }
        #[cfg(not(feature = "postgres-sqlx"))]
        {
            let _ = query;
            Err(self.durable_unavailable("postgres list_approvals"))
        }
    }

    async fn resolve_approval(
        &self,
        id: &str,
        status: ApprovalStatus,
        resolver: Option<String>,
        resolved_at: String,
    ) -> StoreResult<ApprovalRecord> {
        #[cfg(feature = "postgres-sqlx")]
        {
            if status == ApprovalStatus::Pending {
                return Err(StoreError::Invalid(
                    "cannot resolve approval to pending".into(),
                ));
            }
            let pool = self.pool()?;
            let mut tx = pool
                .begin()
                .await
                .map_err(|e| map_durable_error("postgres begin resolve approval", e))?;
            let row = sqlx::query(
                "SELECT id, task_id, tool, args_hash, status, created_at, resolved_at, resolver FROM approvals WHERE id = $1",
            )
            .bind(id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| map_durable_error("postgres load approval", e))?
            .ok_or_else(|| StoreError::NotFound(format!("approval {id}")))?;
            let status_s: String = row
                .try_get("status")
                .map_err(|e| StoreError::Invalid(e.to_string()))?;
            let cur = approval_status_from_str(&status_s)?;
            if cur != ApprovalStatus::Pending {
                return Err(StoreError::Conflict("approval not pending".into()));
            }
            let res = sqlx::query(
                "UPDATE approvals SET status = $1, resolved_at = $2, resolver = $3 WHERE id = $4 AND status = 'pending'",
            )
            .bind(approval_status_to_str(status))
            .bind(&resolved_at)
            .bind(&resolver)
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(|e| map_durable_error("postgres resolve approval", e))?;
            if res.rows_affected() == 0 {
                return Err(StoreError::Conflict("approval not pending".into()));
            }
            tx.commit()
                .await
                .map_err(|e| map_durable_error("postgres commit resolve approval", e))?;
            return Ok(ApprovalRecord {
                id: row
                    .try_get("id")
                    .map_err(|e| StoreError::Invalid(e.to_string()))?,
                task_id: row
                    .try_get("task_id")
                    .map_err(|e| StoreError::Invalid(e.to_string()))?,
                tool: row
                    .try_get("tool")
                    .map_err(|e| StoreError::Invalid(e.to_string()))?,
                args_hash: row
                    .try_get("args_hash")
                    .map_err(|e| StoreError::Invalid(e.to_string()))?,
                status,
                created_at: row
                    .try_get("created_at")
                    .map_err(|e| StoreError::Invalid(e.to_string()))?,
                resolved_at: Some(resolved_at),
                resolver,
            });
        }
        #[cfg(not(feature = "postgres-sqlx"))]
        {
            let _ = (id, status, resolver, resolved_at);
            Err(self.durable_unavailable("postgres resolve_approval"))
        }
    }

    async fn upsert_task(&self, task: TaskRecord) -> StoreResult<TaskRecord> {
        #[cfg(feature = "postgres-sqlx")]
        {
            if task.id.is_empty() {
                return Err(StoreError::Invalid("task id required".into()));
            }
            let pool = self.pool()?;
            sqlx::query(
                "INSERT INTO tasks (id, parent_id, token_id, scopes, budget, expires_at, revoked, revocation_reason, taint_snapshot_id)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                 ON CONFLICT(id) DO UPDATE SET
                   parent_id=excluded.parent_id, token_id=excluded.token_id, scopes=excluded.scopes,
                   budget=excluded.budget, expires_at=excluded.expires_at, revoked=excluded.revoked,
                   revocation_reason=excluded.revocation_reason, taint_snapshot_id=excluded.taint_snapshot_id",
            )
            .bind(&task.id)
            .bind(&task.parent_id)
            .bind(&task.token_id)
            .bind(&task.scopes)
            .bind(task.budget)
            .bind(&task.expires_at)
            .bind(task.revoked)
            .bind(&task.revocation_reason)
            .bind(&task.taint_snapshot_id)
            .execute(pool)
            .await
            .map_err(|e| map_durable_error("postgres upsert task", e))?;
            return Ok(task);
        }
        #[cfg(not(feature = "postgres-sqlx"))]
        {
            let _ = task;
            Err(self.durable_unavailable("postgres upsert_task"))
        }
    }

    async fn get_task(&self, id: &str) -> StoreResult<Option<TaskRecord>> {
        #[cfg(feature = "postgres-sqlx")]
        {
            let pool = self.pool()?;
            let row = sqlx::query(
                "SELECT id, parent_id, token_id, scopes, budget, expires_at, revoked, revocation_reason, taint_snapshot_id FROM tasks WHERE id = $1",
            )
            .bind(id)
            .fetch_optional(pool)
            .await
            .map_err(|e| map_durable_error("postgres get task", e))?;
            if let Some(r) = row {
                let revoked: bool = r
                    .try_get("revoked")
                    .map_err(|e| StoreError::Invalid(e.to_string()))?;
                return Ok(Some(TaskRecord {
                    id: r
                        .try_get("id")
                        .map_err(|e| StoreError::Invalid(e.to_string()))?,
                    parent_id: r.try_get::<Option<String>, _>("parent_id").unwrap_or(None),
                    token_id: r
                        .try_get("token_id")
                        .map_err(|e| StoreError::Invalid(e.to_string()))?,
                    scopes: r
                        .try_get("scopes")
                        .map_err(|e| StoreError::Invalid(e.to_string()))?,
                    budget: r
                        .try_get("budget")
                        .map_err(|e| StoreError::Invalid(e.to_string()))?,
                    expires_at: r
                        .try_get("expires_at")
                        .map_err(|e| StoreError::Invalid(e.to_string()))?,
                    revoked,
                    revocation_reason: r
                        .try_get::<Option<String>, _>("revocation_reason")
                        .unwrap_or(None),
                    taint_snapshot_id: r
                        .try_get::<Option<String>, _>("taint_snapshot_id")
                        .unwrap_or(None),
                }));
            }
            return Ok(None);
        }
        #[cfg(not(feature = "postgres-sqlx"))]
        {
            let _ = id;
            Err(self.durable_unavailable("postgres get_task"))
        }
    }

    async fn list_tasks(&self, query: TaskQuery) -> StoreResult<Vec<TaskRecord>> {
        #[cfg(feature = "postgres-sqlx")]
        {
            let pool = self.pool()?;
            let mut sql = String::from(
                "SELECT id, parent_id, token_id, scopes, budget, expires_at, revoked, revocation_reason, taint_snapshot_id FROM tasks WHERE 1=1",
            );
            let mut binds_i: i32 = 0;
            if query.revoked.is_some() {
                binds_i += 1;
                sql.push_str(&format!(" AND revoked = ${binds_i}"));
            }
            if query.parent_id.is_some() {
                binds_i += 1;
                sql.push_str(&format!(" AND parent_id = ${binds_i}"));
            }
            if query.token_id.is_some() {
                binds_i += 1;
                sql.push_str(&format!(" AND token_id = ${binds_i}"));
            }
            if query.taint_snapshot_id.is_some() {
                binds_i += 1;
                sql.push_str(&format!(" AND taint_snapshot_id = ${binds_i}"));
            }
            let limit_idx = binds_i + 1;
            let offset_idx = binds_i + 2;
            sql.push_str(&format!(
                " ORDER BY id ASC LIMIT ${limit_idx} OFFSET ${offset_idx}"
            ));
            let limit = query.limit.map(|v| v as i64).unwrap_or(i64::MAX);
            let offset = query.offset.map(|v| v as i64).unwrap_or(0);
            let mut q = sqlx::query(&sql);
            if let Some(v) = query.revoked {
                q = q.bind(v);
            }
            if let Some(v) = query.parent_id {
                q = q.bind(v);
            }
            if let Some(v) = query.token_id {
                q = q.bind(v);
            }
            if let Some(v) = query.taint_snapshot_id {
                q = q.bind(v);
            }
            q = q.bind(limit).bind(offset);
            let rows = q
                .fetch_all(pool)
                .await
                .map_err(|e| map_durable_error("postgres list tasks", e))?;
            let mut out = Vec::with_capacity(rows.len());
            for r in rows {
                let revoked: bool = r
                    .try_get("revoked")
                    .map_err(|e| StoreError::Invalid(e.to_string()))?;
                out.push(TaskRecord {
                    id: r
                        .try_get("id")
                        .map_err(|e| StoreError::Invalid(e.to_string()))?,
                    parent_id: r.try_get::<Option<String>, _>("parent_id").unwrap_or(None),
                    token_id: r
                        .try_get("token_id")
                        .map_err(|e| StoreError::Invalid(e.to_string()))?,
                    scopes: r
                        .try_get("scopes")
                        .map_err(|e| StoreError::Invalid(e.to_string()))?,
                    budget: r
                        .try_get("budget")
                        .map_err(|e| StoreError::Invalid(e.to_string()))?,
                    expires_at: r
                        .try_get("expires_at")
                        .map_err(|e| StoreError::Invalid(e.to_string()))?,
                    revoked,
                    revocation_reason: r
                        .try_get::<Option<String>, _>("revocation_reason")
                        .unwrap_or(None),
                    taint_snapshot_id: r
                        .try_get::<Option<String>, _>("taint_snapshot_id")
                        .unwrap_or(None),
                });
            }
            return Ok(out);
        }
        #[cfg(not(feature = "postgres-sqlx"))]
        {
            let _ = query;
            Err(self.durable_unavailable("postgres list_tasks"))
        }
    }

    async fn upsert_policy(&self, policy: PolicyRecord) -> StoreResult<PolicyRecord> {
        #[cfg(feature = "postgres-sqlx")]
        {
            if policy.id.is_empty() {
                return Err(StoreError::Invalid("policy id required".into()));
            }
            let pool = self.pool()?;
            let mut tx = pool
                .begin()
                .await
                .map_err(|e| map_durable_error("postgres begin upsert policy", e))?;
            if policy.active {
                sqlx::query("UPDATE policies SET active = FALSE")
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| map_durable_error("postgres deactivate policies", e))?;
            }
            sqlx::query(
                "INSERT INTO policies (id, version, body, created_at, active)
                 VALUES ($1, $2, $3, $4, $5)
                 ON CONFLICT(id) DO UPDATE SET version=excluded.version, body=excluded.body, created_at=excluded.created_at, active=excluded.active",
            )
            .bind(&policy.id)
            .bind(policy.version)
            .bind(&policy.body)
            .bind(&policy.created_at)
            .bind(policy.active)
            .execute(&mut *tx)
            .await
            .map_err(|e| map_durable_error("postgres upsert policy", e))?;
            tx.commit()
                .await
                .map_err(|e| map_durable_error("postgres commit upsert policy", e))?;
            return Ok(policy);
        }
        #[cfg(not(feature = "postgres-sqlx"))]
        {
            let _ = policy;
            Err(self.durable_unavailable("postgres upsert_policy"))
        }
    }

    async fn get_active_policy(&self) -> StoreResult<Option<PolicyRecord>> {
        #[cfg(feature = "postgres-sqlx")]
        {
            let pool = self.pool()?;
            let row = sqlx::query(
                "SELECT id, version, body, created_at, active FROM policies WHERE active = TRUE ORDER BY version DESC LIMIT 1",
            )
            .fetch_optional(pool)
            .await
            .map_err(|e| map_durable_error("postgres get active policy", e))?;
            if let Some(r) = row {
                let active: bool = r
                    .try_get("active")
                    .map_err(|e| StoreError::Invalid(e.to_string()))?;
                return Ok(Some(PolicyRecord {
                    id: r
                        .try_get("id")
                        .map_err(|e| StoreError::Invalid(e.to_string()))?,
                    version: r
                        .try_get("version")
                        .map_err(|e| StoreError::Invalid(e.to_string()))?,
                    body: r
                        .try_get("body")
                        .map_err(|e| StoreError::Invalid(e.to_string()))?,
                    created_at: r
                        .try_get("created_at")
                        .map_err(|e| StoreError::Invalid(e.to_string()))?,
                    active,
                }));
            }
            return Ok(None);
        }
        #[cfg(not(feature = "postgres-sqlx"))]
        Err(self.durable_unavailable("postgres get_active_policy"))
    }

    async fn record_revocation(&self, record: RevocationRecord) -> StoreResult<RevocationRecord> {
        #[cfg(feature = "postgres-sqlx")]
        {
            if record.id.is_empty() || record.target_id.is_empty() || record.target_kind.is_empty()
            {
                return Err(StoreError::Invalid(
                    "revocation id/target_kind/target_id required".into(),
                ));
            }
            let pool = self.pool()?;
            let mut tx = pool
                .begin()
                .await
                .map_err(|e| map_durable_error("postgres begin revocation", e))?;
            let ins = sqlx::query(
                "INSERT INTO revocations (id, target_kind, target_id, reason, revoked_at, revoked_by)
                 VALUES ($1, $2, $3, $4, $5, $6)",
            )
            .bind(&record.id)
            .bind(&record.target_kind)
            .bind(&record.target_id)
            .bind(&record.reason)
            .bind(&record.revoked_at)
            .bind(&record.revoked_by)
            .execute(&mut *tx)
            .await;
            if let Err(e) = ins {
                if is_unique_violation(&e) {
                    return Err(StoreError::Conflict(format!(
                        "revocation {} exists",
                        record.id
                    )));
                }
                return Err(map_durable_error("postgres insert revocation", e));
            }
            if record.target_kind == "task" {
                sqlx::query(
                    "UPDATE tasks SET revoked = TRUE, revocation_reason = $1 WHERE id = $2",
                )
                .bind(&record.reason)
                .bind(&record.target_id)
                .execute(&mut *tx)
                .await
                .map_err(|e| map_durable_error("postgres mark task revoked", e))?;
            }
            tx.commit()
                .await
                .map_err(|e| map_durable_error("postgres commit revocation", e))?;
            return Ok(record);
        }
        #[cfg(not(feature = "postgres-sqlx"))]
        {
            let _ = record;
            Err(self.durable_unavailable("postgres record_revocation"))
        }
    }

    async fn list_revocations(&self, query: RevocationQuery) -> StoreResult<Vec<RevocationRecord>> {
        #[cfg(feature = "postgres-sqlx")]
        {
            let pool = self.pool()?;
            let mut sql = String::from(
                "SELECT id, target_kind, target_id, reason, revoked_at, revoked_by FROM revocations WHERE 1=1",
            );
            let mut binds_i: i32 = 0;
            if query.target_kind.is_some() {
                binds_i += 1;
                sql.push_str(&format!(" AND target_kind = ${binds_i}"));
            }
            if query.target_id.is_some() {
                binds_i += 1;
                sql.push_str(&format!(" AND target_id = ${binds_i}"));
            }
            let limit_idx = binds_i + 1;
            let offset_idx = binds_i + 2;
            sql.push_str(&format!(
                " ORDER BY revoked_at ASC, id ASC LIMIT ${limit_idx} OFFSET ${offset_idx}"
            ));
            let limit = query.limit.map(|v| v as i64).unwrap_or(i64::MAX);
            let offset = query.offset.map(|v| v as i64).unwrap_or(0);
            let mut q = sqlx::query(&sql);
            if let Some(v) = query.target_kind {
                q = q.bind(v);
            }
            if let Some(v) = query.target_id {
                q = q.bind(v);
            }
            q = q.bind(limit).bind(offset);
            let rows = q
                .fetch_all(pool)
                .await
                .map_err(|e| map_durable_error("postgres list revocations", e))?;
            let mut out = Vec::with_capacity(rows.len());
            for r in rows {
                out.push(RevocationRecord {
                    id: r
                        .try_get("id")
                        .map_err(|e| StoreError::Invalid(e.to_string()))?,
                    target_kind: r
                        .try_get("target_kind")
                        .map_err(|e| StoreError::Invalid(e.to_string()))?,
                    target_id: r
                        .try_get("target_id")
                        .map_err(|e| StoreError::Invalid(e.to_string()))?,
                    reason: r.try_get::<Option<String>, _>("reason").unwrap_or(None),
                    revoked_at: r
                        .try_get("revoked_at")
                        .map_err(|e| StoreError::Invalid(e.to_string()))?,
                    revoked_by: r.try_get::<Option<String>, _>("revoked_by").unwrap_or(None),
                });
            }
            return Ok(out);
        }
        #[cfg(not(feature = "postgres-sqlx"))]
        {
            let _ = query;
            Err(self.durable_unavailable("postgres list_revocations"))
        }
    }

    async fn record_taint_snapshot(
        &self,
        snapshot: TaintSnapshotRecord,
    ) -> StoreResult<TaintSnapshotRecord> {
        #[cfg(feature = "postgres-sqlx")]
        {
            if snapshot.id.is_empty() || snapshot.source.is_empty() {
                return Err(StoreError::Invalid(
                    "taint snapshot id/source required".into(),
                ));
            }
            let labels_json = serde_json::to_string(&snapshot.labels)
                .map_err(|e| StoreError::Invalid(format!("labels serialize: {e}")))?;
            let pool = self.pool()?;
            let mut tx = pool
                .begin()
                .await
                .map_err(|e| map_durable_error("postgres begin taint snapshot", e))?;
            let ins = sqlx::query(
                "INSERT INTO taint_snapshots (id, task_id, source, labels_json, digest, created_at)
                 VALUES ($1, $2, $3, $4, $5, $6)",
            )
            .bind(&snapshot.id)
            .bind(&snapshot.task_id)
            .bind(&snapshot.source)
            .bind(&labels_json)
            .bind(&snapshot.digest)
            .bind(&snapshot.created_at)
            .execute(&mut *tx)
            .await;
            if let Err(e) = ins {
                if is_unique_violation(&e) {
                    return Err(StoreError::Conflict(format!(
                        "taint snapshot {} exists",
                        snapshot.id
                    )));
                }
                return Err(map_durable_error("postgres insert taint snapshot", e));
            }
            if let Some(task_id) = &snapshot.task_id {
                let cur: Option<(Option<String>, Option<String>)> =
                    sqlx::query_as::<_, (Option<String>, Option<String>)>(
                        "SELECT ts.created_at, ts.id
                     FROM tasks t
                     LEFT JOIN taint_snapshots ts ON ts.id = t.taint_snapshot_id
                     WHERE t.id = $1",
                    )
                    .bind(task_id)
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(|e| map_durable_error("postgres read task taint link", e))?;

                let should_link = match cur {
                    None => false, // task missing
                    Some((None, _)) => true,
                    Some((Some(cur_created), Some(cur_id))) => {
                        (snapshot.created_at.as_str(), snapshot.id.as_str())
                            >= (cur_created.as_str(), cur_id.as_str())
                    }
                    Some((Some(_), None)) => true,
                };
                if should_link {
                    sqlx::query("UPDATE tasks SET taint_snapshot_id = $1 WHERE id = $2")
                        .bind(&snapshot.id)
                        .bind(task_id)
                        .execute(&mut *tx)
                        .await
                        .map_err(|e| {
                            map_durable_error("postgres link taint snapshot to task", e)
                        })?;
                }
            }
            tx.commit()
                .await
                .map_err(|e| map_durable_error("postgres commit taint snapshot", e))?;
            return Ok(snapshot);
        }
        #[cfg(not(feature = "postgres-sqlx"))]
        {
            let _ = snapshot;
            Err(self.durable_unavailable("postgres record_taint_snapshot"))
        }
    }

    async fn list_taint_snapshots(
        &self,
        query: TaintSnapshotQuery,
    ) -> StoreResult<Vec<TaintSnapshotRecord>> {
        #[cfg(feature = "postgres-sqlx")]
        {
            let pool = self.pool()?;
            let mut sql = String::from(
                "SELECT id, task_id, source, labels_json, digest, created_at FROM taint_snapshots WHERE 1=1",
            );
            let mut binds_i: i32 = 0;
            if query.task_id.is_some() {
                binds_i += 1;
                sql.push_str(&format!(" AND task_id = ${binds_i}"));
            }
            if query.source.is_some() {
                binds_i += 1;
                sql.push_str(&format!(" AND source = ${binds_i}"));
            }
            let limit_idx = binds_i + 1;
            let offset_idx = binds_i + 2;
            sql.push_str(&format!(
                " ORDER BY created_at ASC, id ASC LIMIT ${limit_idx} OFFSET ${offset_idx}"
            ));
            let limit = query.limit.map(|v| v as i64).unwrap_or(i64::MAX);
            let offset = query.offset.map(|v| v as i64).unwrap_or(0);
            let mut q = sqlx::query(&sql);
            if let Some(v) = query.task_id {
                q = q.bind(v);
            }
            if let Some(v) = query.source {
                q = q.bind(v);
            }
            q = q.bind(limit).bind(offset);
            let rows = q
                .fetch_all(pool)
                .await
                .map_err(|e| map_durable_error("postgres list taint snapshots", e))?;
            let mut out = Vec::with_capacity(rows.len());
            for r in rows {
                let labels_json: String = r
                    .try_get("labels_json")
                    .map_err(|e| StoreError::Invalid(e.to_string()))?;
                let labels: Vec<String> = serde_json::from_str(&labels_json)
                    .map_err(|e| StoreError::Invalid(format!("labels parse: {e}")))?;
                out.push(TaintSnapshotRecord {
                    id: r
                        .try_get("id")
                        .map_err(|e| StoreError::Invalid(e.to_string()))?,
                    task_id: r.try_get::<Option<String>, _>("task_id").unwrap_or(None),
                    source: r
                        .try_get("source")
                        .map_err(|e| StoreError::Invalid(e.to_string()))?,
                    labels,
                    digest: r.try_get::<Option<String>, _>("digest").unwrap_or(None),
                    created_at: r
                        .try_get("created_at")
                        .map_err(|e| StoreError::Invalid(e.to_string()))?,
                });
            }
            return Ok(out);
        }
        #[cfg(not(feature = "postgres-sqlx"))]
        {
            let _ = query;
            Err(self.durable_unavailable("postgres list_taint_snapshots"))
        }
    }

    async fn get_tool_pin(
        &self,
        upstream_id: &str,
        tool_name: &str,
    ) -> StoreResult<Option<ToolPinRecord>> {
        #[cfg(feature = "postgres-sqlx")]
        {
            let pool = self.pool()?;
            let row = sqlx::query(
                "SELECT upstream_id, tool_name, descriptor_hash, descriptor_json, first_seen_at, approved \
                 FROM tool_pins WHERE upstream_id = $1 AND tool_name = $2",
            )
            .bind(upstream_id)
            .bind(tool_name)
            .fetch_optional(pool)
            .await
            .map_err(|e| map_durable_error("postgres get tool pin", e))?;
            if let Some(r) = row {
                return Ok(Some(ToolPinRecord {
                    upstream_id: r
                        .try_get("upstream_id")
                        .map_err(|e| StoreError::Invalid(e.to_string()))?,
                    tool_name: r
                        .try_get("tool_name")
                        .map_err(|e| StoreError::Invalid(e.to_string()))?,
                    descriptor_hash: r
                        .try_get("descriptor_hash")
                        .map_err(|e| StoreError::Invalid(e.to_string()))?,
                    descriptor_json: r
                        .try_get("descriptor_json")
                        .map_err(|e| StoreError::Invalid(e.to_string()))?,
                    first_seen_at: r
                        .try_get("first_seen_at")
                        .map_err(|e| StoreError::Invalid(e.to_string()))?,
                    approved: r
                        .try_get("approved")
                        .map_err(|e| StoreError::Invalid(e.to_string()))?,
                }));
            }
            return Ok(None);
        }
        #[cfg(not(feature = "postgres-sqlx"))]
        {
            let _ = (upstream_id, tool_name);
            Err(self.durable_unavailable("postgres get_tool_pin"))
        }
    }

    async fn upsert_tool_pin(&self, record: ToolPinRecord) -> StoreResult<ToolPinRecord> {
        #[cfg(feature = "postgres-sqlx")]
        {
            if record.upstream_id.trim().is_empty() || record.tool_name.trim().is_empty() {
                return Err(StoreError::Invalid(
                    "tool pin upstream_id/tool_name required".into(),
                ));
            }
            if record.descriptor_hash.trim().is_empty() {
                return Err(StoreError::Invalid(
                    "tool pin descriptor_hash required".into(),
                ));
            }
            let pool = self.pool()?;
            sqlx::query(
                "INSERT INTO tool_pins (upstream_id, tool_name, descriptor_hash, descriptor_json, first_seen_at, approved) \
                 VALUES ($1, $2, $3, $4, $5, $6) \
                 ON CONFLICT(upstream_id, tool_name) DO UPDATE SET \
                   descriptor_hash=EXCLUDED.descriptor_hash, \
                   descriptor_json=EXCLUDED.descriptor_json, \
                   first_seen_at=EXCLUDED.first_seen_at, \
                   approved=EXCLUDED.approved",
            )
            .bind(&record.upstream_id)
            .bind(&record.tool_name)
            .bind(&record.descriptor_hash)
            .bind(&record.descriptor_json)
            .bind(&record.first_seen_at)
            .bind(record.approved)
            .execute(pool)
            .await
            .map_err(|e| map_durable_error("postgres upsert tool pin", e))?;
            return Ok(record);
        }
        #[cfg(not(feature = "postgres-sqlx"))]
        {
            let _ = record;
            Err(self.durable_unavailable("postgres upsert_tool_pin"))
        }
    }

    async fn save_rate_limit_snapshot(
        &self,
        snapshot: crate::RateLimitSnapshotRecord,
    ) -> StoreResult<crate::RateLimitSnapshotRecord> {
        #[cfg(feature = "postgres-sqlx")]
        {
            if snapshot.snapshot_json.trim().is_empty() {
                return Err(StoreError::Invalid(
                    "rate limit snapshot_json required".into(),
                ));
            }
            let pool = self.pool()?;
            sqlx::query(
                "INSERT INTO rate_limit_snapshots (id, snapshot_json, updated_at) \
                 VALUES ($1, $2, $3) \
                 ON CONFLICT(id) DO UPDATE SET \
                   snapshot_json=EXCLUDED.snapshot_json, \
                   updated_at=EXCLUDED.updated_at",
            )
            .bind("global")
            .bind(&snapshot.snapshot_json)
            .bind(&snapshot.updated_at)
            .execute(pool)
            .await
            .map_err(|e| map_durable_error("postgres save rate limit snapshot", e))?;
            return Ok(snapshot);
        }
        #[cfg(not(feature = "postgres-sqlx"))]
        {
            let _ = snapshot;
            Err(self.durable_unavailable("postgres save_rate_limit_snapshot"))
        }
    }

    async fn load_rate_limit_snapshot(
        &self,
    ) -> StoreResult<Option<crate::RateLimitSnapshotRecord>> {
        #[cfg(feature = "postgres-sqlx")]
        {
            let pool = self.pool()?;
            let row = sqlx::query(
                "SELECT snapshot_json, updated_at FROM rate_limit_snapshots WHERE id = $1",
            )
            .bind("global")
            .fetch_optional(pool)
            .await
            .map_err(|e| map_durable_error("postgres load rate limit snapshot", e))?;
            if let Some(r) = row {
                return Ok(Some(crate::RateLimitSnapshotRecord {
                    snapshot_json: r
                        .try_get("snapshot_json")
                        .map_err(|e| StoreError::Invalid(e.to_string()))?,
                    updated_at: r
                        .try_get("updated_at")
                        .map_err(|e| StoreError::Invalid(e.to_string()))?,
                }));
            }
            return Ok(None);
        }
        #[cfg(not(feature = "postgres-sqlx"))]
        {
            Err(self.durable_unavailable("postgres load_rate_limit_snapshot"))
        }
    }

    async fn health_check(&self) -> StoreResult<()> {
        #[cfg(feature = "postgres-sqlx")]
        {
            let pool = self.pool()?;
            sqlx::query("SELECT 1")
                .execute(pool)
                .await
                .map_err(|e| map_durable_error("postgres health_check", e))?;
            return Ok(());
        }
        #[cfg(not(feature = "postgres-sqlx"))]
        Err(self.durable_unavailable("postgres health_check"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BackendKind, StoreConfig, StoreError};

    #[test]
    fn postgres_new_rejects_wrong_backend() {
        let err = PostgresStore::new(StoreConfig {
            backend: BackendKind::SqliteWal,
            ..Default::default()
        })
        .unwrap_err();
        assert!(matches!(err, StoreError::Invalid(_)));
    }

    #[cfg(feature = "postgres-sqlx")]
    #[test]
    fn approval_status_str_roundtrip() {
        assert_eq!(approval_status_to_str(ApprovalStatus::Pending), "pending");
        assert_eq!(approval_status_to_str(ApprovalStatus::Approved), "approved");
        assert_eq!(approval_status_to_str(ApprovalStatus::Denied), "denied");
        assert_eq!(approval_status_to_str(ApprovalStatus::Expired), "expired");
        assert!(matches!(
            approval_status_from_str("approved"),
            Ok(ApprovalStatus::Approved)
        ));
        assert!(matches!(
            approval_status_from_str("nope"),
            Err(StoreError::Invalid(_))
        ));
    }

    #[cfg(feature = "postgres-sqlx")]
    #[tokio::test]
    async fn postgres_unconnected_ops_fail_unavailable() {
        use crate::{
            ApprovalQuery, ApprovalRecord, ApprovalStatus, AuditEvent, AuditQuery, PolicyRecord,
            RevocationQuery, RevocationRecord, Store, TaintSnapshotQuery, TaintSnapshotRecord,
            TaskQuery, TaskRecord,
        };

        let store = PostgresStore::new(StoreConfig {
            backend: BackendKind::Postgres,
            database_url: "postgres://localhost/scopegate".into(),
            fail_closed_on_audit_error: true,
        })
        .unwrap();
        assert_eq!(store.backend(), BackendKind::Postgres);
        assert_eq!(store.config().backend, BackendKind::Postgres);
        assert!(matches!(
            store.health_check().await,
            Err(StoreError::Unavailable(_))
        ));
        assert!(matches!(
            store
                .append_audit_event(AuditEvent {
                    ts: "t".into(),
                    decision: "allow".into(),
                    ..Default::default()
                })
                .await,
            Err(StoreError::Unavailable(_))
        ));
        assert!(matches!(
            store.query_audit(AuditQuery::default()).await,
            Err(StoreError::Unavailable(_))
        ));
        assert!(matches!(
            store.verify_audit_chain().await,
            Err(StoreError::Unavailable(_))
        ));
        assert!(matches!(
            store
                .create_approval(ApprovalRecord {
                    id: "a".into(),
                    task_id: "t".into(),
                    tool: "x".into(),
                    args_hash: "h".into(),
                    status: ApprovalStatus::Pending,
                    created_at: "c".into(),
                    ..Default::default()
                })
                .await,
            Err(StoreError::Unavailable(_))
        ));
        assert!(matches!(
            store.get_approval("a").await,
            Err(StoreError::Unavailable(_))
        ));
        assert!(matches!(
            store.list_approvals(ApprovalQuery::default()).await,
            Err(StoreError::Unavailable(_))
        ));
        assert!(matches!(
            store
                .resolve_approval("a", ApprovalStatus::Approved, None, "r".into())
                .await,
            Err(StoreError::Unavailable(_))
        ));
        assert!(matches!(
            store
                .upsert_task(TaskRecord {
                    id: "t1".into(),
                    token_id: "tok".into(),
                    scopes: "[]".into(),
                    budget: 1,
                    expires_at: "e".into(),
                    ..Default::default()
                })
                .await,
            Err(StoreError::Unavailable(_))
        ));
        assert!(matches!(
            store.get_task("t1").await,
            Err(StoreError::Unavailable(_))
        ));
        assert!(matches!(
            store.list_tasks(TaskQuery::default()).await,
            Err(StoreError::Unavailable(_))
        ));
        assert!(matches!(
            store
                .upsert_policy(PolicyRecord {
                    id: "p1".into(),
                    version: 1,
                    body: "b".into(),
                    created_at: "c".into(),
                    active: true,
                })
                .await,
            Err(StoreError::Unavailable(_))
        ));
        assert!(matches!(
            store.get_active_policy().await,
            Err(StoreError::Unavailable(_))
        ));
        assert!(matches!(
            store
                .record_revocation(RevocationRecord {
                    id: "r1".into(),
                    target_kind: "task".into(),
                    target_id: "t1".into(),
                    revoked_at: "now".into(),
                    ..Default::default()
                })
                .await,
            Err(StoreError::Unavailable(_))
        ));
        assert!(matches!(
            store.list_revocations(RevocationQuery::default()).await,
            Err(StoreError::Unavailable(_))
        ));
        assert!(matches!(
            store
                .record_taint_snapshot(TaintSnapshotRecord {
                    id: "s1".into(),
                    task_id: Some("t1".into()),
                    source: "src".into(),
                    labels: vec![],
                    created_at: "c".into(),
                    ..Default::default()
                })
                .await,
            Err(StoreError::Unavailable(_))
        ));
        assert!(matches!(
            store
                .list_taint_snapshots(TaintSnapshotQuery::default())
                .await,
            Err(StoreError::Unavailable(_))
        ));
    }
}
