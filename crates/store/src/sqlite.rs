//! SQLite (WAL) durable store adapter (sqlx-backed).

use async_trait::async_trait;

use crate::{
    apply_migrations, verify_audit_chain_events, ApprovalQuery, ApprovalRecord, ApprovalStatus,
    AuditEvent, AuditQuery, AuditVerificationReport, BackendKind, PolicyRecord, RevocationQuery,
    RevocationRecord, Store, StoreConfig, StoreError, StoreResult, TaintSnapshotQuery,
    TaintSnapshotRecord, TaskQuery, TaskRecord,
};

#[cfg(feature = "sqlite-sqlx")]
use {
    crate::durable::map_durable_error,
    sqlx::{Row, SqlitePool},
};

/// SQLite store adapter.
#[derive(Debug, Clone)]
pub struct SqliteStore {
    config: StoreConfig,
    #[cfg(feature = "sqlite-sqlx")]
    pool: Option<SqlitePool>,
}

impl SqliteStore {
    pub fn new(config: StoreConfig) -> StoreResult<Self> {
        if config.backend != BackendKind::SqliteWal {
            return Err(StoreError::Invalid(format!(
                "SqliteStore requires sqlite_wal backend, got {}",
                config.backend
            )));
        }
        Ok(Self {
            config,
            #[cfg(feature = "sqlite-sqlx")]
            pool: None,
        })
    }

    /// Connect a durable pool and apply WAL/durability pragmas.
    #[cfg(feature = "sqlite-sqlx")]
    pub async fn connect(&mut self) -> StoreResult<()> {
        use sqlx::sqlite::SqlitePoolOptions;
        use std::str::FromStr;

        // Per-connection pragmas: foreign_keys/busy_timeout/synchronous are connection-scoped.
        let pool = SqlitePoolOptions::new()
            .after_connect(|conn, _meta| {
                Box::pin(async move {
                    sqlx::query("PRAGMA foreign_keys=ON;")
                        .execute(&mut *conn)
                        .await?;
                    sqlx::query("PRAGMA synchronous=FULL;")
                        .execute(&mut *conn)
                        .await?;
                    sqlx::query("PRAGMA busy_timeout=5000;")
                        .execute(&mut *conn)
                        .await?;
                    Ok(())
                })
            })
            .connect_with(
                sqlx::sqlite::SqliteConnectOptions::from_str(&self.config.database_url)
                    .map_err(|e| StoreError::Invalid(format!("sqlite database_url: {e}")))?,
            )
            .await
            .map_err(|e| map_durable_error("sqlite connect", e))?;

        // journal_mode is database-scoped (persistent for file DBs); set once on connect.
        // In-memory/shared-cache URLs may report `memory` instead of `wal`.
        sqlx::query("PRAGMA journal_mode=WAL;")
            .execute(&pool)
            .await
            .map_err(|e| map_durable_error("sqlite pragma journal_mode=WAL", e))?;

        self.pool = Some(pool);
        Ok(())
    }

    /// Apply embedded SQL migrations in order.
    ///
    /// Idempotent/restart-safe: delegates to shared migration tracking.
    pub async fn migrate(&self) -> StoreResult<Vec<i64>> {
        apply_migrations(BackendKind::SqliteWal, &self.config.database_url).await
    }

    pub fn config(&self) -> &StoreConfig {
        &self.config
    }

    #[cfg(feature = "sqlite-sqlx")]
    fn pool(&self) -> StoreResult<&SqlitePool> {
        self.pool
            .as_ref()
            .ok_or_else(|| StoreError::Unavailable("sqlite pool not connected".into()))
    }

    #[cfg(not(feature = "sqlite-sqlx"))]
    fn durable_unavailable(&self, op: &'static str) -> StoreError {
        let _ = &self.config.database_url;
        StoreError::NotImplemented(op)
    }
}

#[cfg(feature = "sqlite-sqlx")]
fn row_to_audit(row: &sqlx::sqlite::SqliteRow) -> StoreResult<AuditEvent> {
    Ok(AuditEvent {
        seq: row
            .try_get("seq")
            .map_err(|e| StoreError::Invalid(e.to_string()))?,
        ts: row
            .try_get("ts")
            .map_err(|e| StoreError::Invalid(e.to_string()))?,
        task_id: row.try_get("task_id").ok(),
        tool: row.try_get("tool").ok(),
        decision: row
            .try_get("decision")
            .map_err(|e| StoreError::Invalid(e.to_string()))?,
        reason: row.try_get("reason").ok(),
        args_digest: row.try_get("args_digest").ok(),
        result_digest: row.try_get("result_digest").ok(),
        prev_hash: row
            .try_get::<Option<Vec<u8>>, _>("prev_hash")
            .unwrap_or(None),
        hash: row.try_get::<Option<Vec<u8>>, _>("hash").unwrap_or(None),
    })
}

#[cfg(feature = "sqlite-sqlx")]
fn approval_status_from_str(s: &str) -> StoreResult<ApprovalStatus> {
    match s {
        "pending" => Ok(ApprovalStatus::Pending),
        "approved" => Ok(ApprovalStatus::Approved),
        "denied" => Ok(ApprovalStatus::Denied),
        "expired" => Ok(ApprovalStatus::Expired),
        _ => Err(StoreError::Invalid(format!("unknown approval status {s}"))),
    }
}

#[cfg(feature = "sqlite-sqlx")]
fn approval_status_to_str(s: ApprovalStatus) -> &'static str {
    match s {
        ApprovalStatus::Pending => "pending",
        ApprovalStatus::Approved => "approved",
        ApprovalStatus::Denied => "denied",
        ApprovalStatus::Expired => "expired",
    }
}

#[async_trait]
impl Store for SqliteStore {
    fn backend(&self) -> BackendKind {
        BackendKind::SqliteWal
    }

    async fn append_audit_event(&self, event: AuditEvent) -> StoreResult<AuditEvent> {
        #[cfg(feature = "sqlite-sqlx")]
        {
            event.validate_for_append()?;
            let pool = self.pool()?;
            // Immediate tx serializes writers so seq/head chain is stable; commit before return.
            let mut conn = pool
                .acquire()
                .await
                .map_err(|e| map_durable_error("sqlite acquire audit append", e))?;
            sqlx::query("BEGIN IMMEDIATE")
                .execute(&mut *conn)
                .await
                .map_err(|e| map_durable_error("sqlite begin audit append", e))?;

            let head =
                match sqlx::query("SELECT seq, hash FROM audit_events ORDER BY seq DESC LIMIT 1")
                    .fetch_optional(&mut *conn)
                    .await
                {
                    Ok(v) => v,
                    Err(e) => {
                        let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                        return Err(map_durable_error("sqlite read audit head", e));
                    }
                };
            let (next_seq, prev_hash): (i64, Option<Vec<u8>>) = if let Some(r) = head {
                let s: i64 = match r.try_get("seq") {
                    Ok(v) => v,
                    Err(e) => {
                        let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                        return Err(StoreError::Invalid(e.to_string()));
                    }
                };
                let h: Option<Vec<u8>> = r.try_get("hash").ok();
                (s + 1, h)
            } else {
                (1, None)
            };
            let event = match crate::AuditAppendPlan::for_tail(event, prev_hash.clone())
                .materialize(next_seq, prev_hash)
            {
                Ok(ev) => ev,
                Err(e) => {
                    let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                    return Err(e);
                }
            };
            let ins = sqlx::query(
                "INSERT INTO audit_events (seq, ts, task_id, tool, decision, reason, args_digest, result_digest, prev_hash, hash)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
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
            .execute(&mut *conn)
            .await;
            if let Err(e) = ins {
                let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                let msg = e.to_string();
                if msg.contains("UNIQUE") || msg.contains("PRIMARY KEY") {
                    return Err(StoreError::Conflict(format!(
                        "audit append conflict at seq {}: {msg}",
                        event.seq
                    )));
                }
                return Err(map_durable_error("sqlite insert audit event", e));
            }
            if let Err(e) = sqlx::query("COMMIT").execute(&mut *conn).await {
                let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                return Err(map_durable_error("sqlite commit audit append", e));
            }
            return Ok(event);
        }
        #[cfg(not(feature = "sqlite-sqlx"))]
        {
            let _ = event;
            Err(self.durable_unavailable("sqlite append_audit_event"))
        }
    }

    async fn query_audit(&self, query: AuditQuery) -> StoreResult<Vec<AuditEvent>> {
        #[cfg(feature = "sqlite-sqlx")]
        {
            let pool = self.pool()?;
            let mut sql = String::from(
                "SELECT seq, ts, task_id, tool, decision, reason, args_digest, result_digest, prev_hash, hash FROM audit_events WHERE 1=1",
            );
            let mut binds_i: i32 = 0;
            if query.task_id.is_some() {
                binds_i += 1;
                sql.push_str(&format!(" AND task_id = ?{binds_i}"));
            }
            if query.decision.is_some() {
                binds_i += 1;
                sql.push_str(&format!(" AND decision = ?{binds_i}"));
            }
            if query.from_ts.is_some() {
                binds_i += 1;
                sql.push_str(&format!(" AND ts >= ?{binds_i}"));
            }
            if query.to_ts.is_some() {
                binds_i += 1;
                sql.push_str(&format!(" AND ts <= ?{binds_i}"));
            }
            let limit_idx = binds_i + 1;
            let offset_idx = binds_i + 2;
            sql.push_str(&format!(
                " ORDER BY seq ASC LIMIT ?{limit_idx} OFFSET ?{offset_idx}"
            ));
            let limit = query.limit.map(|v| v as i64).unwrap_or(-1); // -1 = no limit in sqlite
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
                .map_err(|e| map_durable_error("sqlite query audit", e))?;
            return rows.iter().map(row_to_audit).collect();
        }
        #[cfg(not(feature = "sqlite-sqlx"))]
        {
            let _ = query;
            Err(self.durable_unavailable("sqlite query_audit"))
        }
    }

    async fn verify_audit_chain(&self) -> StoreResult<AuditVerificationReport> {
        #[cfg(feature = "sqlite-sqlx")]
        {
            let pool = self.pool()?;
            let rows = sqlx::query(
                "SELECT seq, ts, task_id, tool, decision, reason, args_digest, result_digest, prev_hash, hash FROM audit_events ORDER BY seq ASC",
            )
            .fetch_all(pool)
            .await
            .map_err(|e| map_durable_error("sqlite verify audit read", e))?;
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
        #[cfg(not(feature = "sqlite-sqlx"))]
        Err(self.durable_unavailable("sqlite verify_audit_chain"))
    }

    async fn create_approval(&self, approval: ApprovalRecord) -> StoreResult<ApprovalRecord> {
        #[cfg(feature = "sqlite-sqlx")]
        {
            if approval.id.is_empty() {
                return Err(StoreError::Invalid("approval id required".into()));
            }
            let pool = self.pool()?;
            let res = sqlx::query(
                "INSERT INTO approvals (id, task_id, tool, args_hash, status, created_at, resolved_at, resolver)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
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
                    let msg = e.to_string();
                    if msg.contains("UNIQUE") {
                        return Err(StoreError::Conflict(format!(
                            "approval {} exists",
                            approval.id
                        )));
                    }
                    return Err(map_durable_error("sqlite create approval", e));
                }
            }
        }
        #[cfg(not(feature = "sqlite-sqlx"))]
        {
            let _ = approval;
            Err(self.durable_unavailable("sqlite create_approval"))
        }
    }

    async fn get_approval(&self, id: &str) -> StoreResult<Option<ApprovalRecord>> {
        #[cfg(feature = "sqlite-sqlx")]
        {
            let pool = self.pool()?;
            let row = sqlx::query(
                "SELECT id, task_id, tool, args_hash, status, created_at, resolved_at, resolver FROM approvals WHERE id = ?1",
            )
            .bind(id)
            .fetch_optional(pool)
            .await
            .map_err(|e| map_durable_error("sqlite get approval", e))?;
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
                    resolved_at: r.try_get("resolved_at").ok(),
                    resolver: r.try_get("resolver").ok(),
                }));
            }
            return Ok(None);
        }
        #[cfg(not(feature = "sqlite-sqlx"))]
        {
            let _ = id;
            Err(self.durable_unavailable("sqlite get_approval"))
        }
    }

    async fn list_approvals(&self, query: ApprovalQuery) -> StoreResult<Vec<ApprovalRecord>> {
        #[cfg(feature = "sqlite-sqlx")]
        {
            let pool = self.pool()?;
            let mut sql = String::from(
                "SELECT id, task_id, tool, args_hash, status, created_at, resolved_at, resolver FROM approvals WHERE 1=1",
            );
            let mut binds_i: i32 = 0;
            if query.task_id.is_some() {
                binds_i += 1;
                sql.push_str(&format!(" AND task_id = ?{binds_i}"));
            }
            if query.status.is_some() {
                binds_i += 1;
                sql.push_str(&format!(" AND status = ?{binds_i}"));
            }
            let limit_idx = binds_i + 1;
            let offset_idx = binds_i + 2;
            sql.push_str(&format!(
                " ORDER BY created_at ASC, id ASC LIMIT ?{limit_idx} OFFSET ?{offset_idx}"
            ));
            let limit = query.limit.map(|v| v as i64).unwrap_or(-1);
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
                .map_err(|e| map_durable_error("sqlite list approvals", e))?;
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
                    resolved_at: r.try_get("resolved_at").ok(),
                    resolver: r.try_get("resolver").ok(),
                });
            }
            return Ok(out);
        }
        #[cfg(not(feature = "sqlite-sqlx"))]
        {
            let _ = query;
            Err(self.durable_unavailable("sqlite list_approvals"))
        }
    }

    async fn resolve_approval(
        &self,
        id: &str,
        status: ApprovalStatus,
        resolver: Option<String>,
        resolved_at: String,
    ) -> StoreResult<ApprovalRecord> {
        #[cfg(feature = "sqlite-sqlx")]
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
                .map_err(|e| map_durable_error("sqlite begin resolve approval", e))?;
            let row = sqlx::query(
                "SELECT id, task_id, tool, args_hash, status, created_at, resolved_at, resolver FROM approvals WHERE id = ?1",
            )
            .bind(id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| map_durable_error("sqlite load approval", e))?
            .ok_or_else(|| StoreError::NotFound(format!("approval {id}")))?;
            let status_s: String = row
                .try_get("status")
                .map_err(|e| StoreError::Invalid(e.to_string()))?;
            let cur = approval_status_from_str(&status_s)?;
            if cur != ApprovalStatus::Pending {
                return Err(StoreError::Conflict("approval not pending".into()));
            }
            let res = sqlx::query(
                "UPDATE approvals SET status = ?1, resolved_at = ?2, resolver = ?3 WHERE id = ?4 AND status = 'pending'",
            )
            .bind(approval_status_to_str(status))
            .bind(&resolved_at)
            .bind(&resolver)
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(|e| map_durable_error("sqlite resolve approval", e))?;
            if res.rows_affected() == 0 {
                return Err(StoreError::Conflict("approval not pending".into()));
            }
            tx.commit()
                .await
                .map_err(|e| map_durable_error("sqlite commit resolve approval", e))?;
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
        #[cfg(not(feature = "sqlite-sqlx"))]
        {
            let _ = (id, status, resolver, resolved_at);
            Err(self.durable_unavailable("sqlite resolve_approval"))
        }
    }

    async fn upsert_task(&self, task: TaskRecord) -> StoreResult<TaskRecord> {
        #[cfg(feature = "sqlite-sqlx")]
        {
            if task.id.is_empty() {
                return Err(StoreError::Invalid("task id required".into()));
            }
            let pool = self.pool()?;
            sqlx::query(
                "INSERT INTO tasks (id, parent_id, token_id, scopes, budget, expires_at, revoked, revocation_reason, taint_snapshot_id)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
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
            .bind(if task.revoked { 1_i64 } else { 0_i64 })
            .bind(&task.revocation_reason)
            .bind(&task.taint_snapshot_id)
            .execute(pool)
            .await
            .map_err(|e| map_durable_error("sqlite upsert task", e))?;
            return Ok(task);
        }
        #[cfg(not(feature = "sqlite-sqlx"))]
        {
            let _ = task;
            Err(self.durable_unavailable("sqlite upsert_task"))
        }
    }

    async fn get_task(&self, id: &str) -> StoreResult<Option<TaskRecord>> {
        #[cfg(feature = "sqlite-sqlx")]
        {
            let pool = self.pool()?;
            let row = sqlx::query(
                "SELECT id, parent_id, token_id, scopes, budget, expires_at, revoked, revocation_reason, taint_snapshot_id FROM tasks WHERE id = ?1",
            )
            .bind(id)
            .fetch_optional(pool)
            .await
            .map_err(|e| map_durable_error("sqlite get task", e))?;
            if let Some(r) = row {
                let revoked_i: i64 = r
                    .try_get("revoked")
                    .map_err(|e| StoreError::Invalid(e.to_string()))?;
                return Ok(Some(TaskRecord {
                    id: r
                        .try_get("id")
                        .map_err(|e| StoreError::Invalid(e.to_string()))?,
                    parent_id: r.try_get("parent_id").ok(),
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
                    revoked: revoked_i != 0,
                    revocation_reason: r.try_get("revocation_reason").ok(),
                    taint_snapshot_id: r.try_get("taint_snapshot_id").ok(),
                }));
            }
            return Ok(None);
        }
        #[cfg(not(feature = "sqlite-sqlx"))]
        {
            let _ = id;
            Err(self.durable_unavailable("sqlite get_task"))
        }
    }

    async fn list_tasks(&self, query: TaskQuery) -> StoreResult<Vec<TaskRecord>> {
        #[cfg(feature = "sqlite-sqlx")]
        {
            let pool = self.pool()?;
            let mut sql = String::from(
                "SELECT id, parent_id, token_id, scopes, budget, expires_at, revoked, revocation_reason, taint_snapshot_id FROM tasks WHERE 1=1",
            );
            let mut binds_i: i32 = 0;
            if query.revoked.is_some() {
                binds_i += 1;
                sql.push_str(&format!(" AND revoked = ?{binds_i}"));
            }
            if query.parent_id.is_some() {
                binds_i += 1;
                sql.push_str(&format!(" AND parent_id = ?{binds_i}"));
            }
            if query.token_id.is_some() {
                binds_i += 1;
                sql.push_str(&format!(" AND token_id = ?{binds_i}"));
            }
            if query.taint_snapshot_id.is_some() {
                binds_i += 1;
                sql.push_str(&format!(" AND taint_snapshot_id = ?{binds_i}"));
            }
            let limit_idx = binds_i + 1;
            let offset_idx = binds_i + 2;
            sql.push_str(&format!(
                " ORDER BY id ASC LIMIT ?{limit_idx} OFFSET ?{offset_idx}"
            ));
            let limit = query.limit.map(|v| v as i64).unwrap_or(-1);
            let offset = query.offset.map(|v| v as i64).unwrap_or(0);
            let mut q = sqlx::query(&sql);
            if let Some(v) = query.revoked {
                q = q.bind(if v { 1_i64 } else { 0_i64 });
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
                .map_err(|e| map_durable_error("sqlite list tasks", e))?;
            let mut out = Vec::with_capacity(rows.len());
            for r in rows {
                let revoked_i: i64 = r
                    .try_get("revoked")
                    .map_err(|e| StoreError::Invalid(e.to_string()))?;
                out.push(TaskRecord {
                    id: r
                        .try_get("id")
                        .map_err(|e| StoreError::Invalid(e.to_string()))?,
                    parent_id: r.try_get("parent_id").ok(),
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
                    revoked: revoked_i != 0,
                    revocation_reason: r.try_get("revocation_reason").ok(),
                    taint_snapshot_id: r.try_get("taint_snapshot_id").ok(),
                });
            }
            return Ok(out);
        }
        #[cfg(not(feature = "sqlite-sqlx"))]
        {
            let _ = query;
            Err(self.durable_unavailable("sqlite list_tasks"))
        }
    }

    async fn upsert_policy(&self, policy: PolicyRecord) -> StoreResult<PolicyRecord> {
        #[cfg(feature = "sqlite-sqlx")]
        {
            if policy.id.is_empty() {
                return Err(StoreError::Invalid("policy id required".into()));
            }
            let pool = self.pool()?;
            let mut tx = pool
                .begin()
                .await
                .map_err(|e| map_durable_error("sqlite begin upsert policy", e))?;
            // tx semantics placeholder: deactivate-others + upsert as one unit
            if policy.active {
                sqlx::query("UPDATE policies SET active = 0")
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| map_durable_error("sqlite deactivate policies", e))?;
            }
            sqlx::query(
                "INSERT INTO policies (id, version, body, created_at, active)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(id) DO UPDATE SET version=excluded.version, body=excluded.body, created_at=excluded.created_at, active=excluded.active",
            )
            .bind(&policy.id)
            .bind(policy.version)
            .bind(&policy.body)
            .bind(&policy.created_at)
            .bind(if policy.active { 1_i64 } else { 0_i64 })
            .execute(&mut *tx)
            .await
            .map_err(|e| map_durable_error("sqlite upsert policy", e))?;
            tx.commit()
                .await
                .map_err(|e| map_durable_error("sqlite commit upsert policy", e))?;
            return Ok(policy);
        }
        #[cfg(not(feature = "sqlite-sqlx"))]
        {
            let _ = policy;
            Err(self.durable_unavailable("sqlite upsert_policy"))
        }
    }

    async fn get_active_policy(&self) -> StoreResult<Option<PolicyRecord>> {
        #[cfg(feature = "sqlite-sqlx")]
        {
            let pool = self.pool()?;
            let row = sqlx::query(
                "SELECT id, version, body, created_at, active FROM policies WHERE active = 1 ORDER BY version DESC LIMIT 1",
            )
            .fetch_optional(pool)
            .await
            .map_err(|e| map_durable_error("sqlite get active policy", e))?;
            if let Some(r) = row {
                let active_i: i64 = r
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
                    active: active_i != 0,
                }));
            }
            return Ok(None);
        }
        #[cfg(not(feature = "sqlite-sqlx"))]
        Err(self.durable_unavailable("sqlite get_active_policy"))
    }

    async fn record_revocation(&self, record: RevocationRecord) -> StoreResult<RevocationRecord> {
        #[cfg(feature = "sqlite-sqlx")]
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
                .map_err(|e| map_durable_error("sqlite begin revocation", e))?;
            let ins = sqlx::query(
                "INSERT INTO revocations (id, target_kind, target_id, reason, revoked_at, revoked_by)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
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
                let msg = e.to_string();
                if msg.contains("UNIQUE") {
                    return Err(StoreError::Conflict(format!(
                        "revocation {} exists",
                        record.id
                    )));
                }
                return Err(map_durable_error("sqlite insert revocation", e));
            }
            if record.target_kind == "task" {
                sqlx::query("UPDATE tasks SET revoked = 1, revocation_reason = ?1 WHERE id = ?2")
                    .bind(&record.reason)
                    .bind(&record.target_id)
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| map_durable_error("sqlite mark task revoked", e))?;
            }
            tx.commit()
                .await
                .map_err(|e| map_durable_error("sqlite commit revocation", e))?;
            return Ok(record);
        }
        #[cfg(not(feature = "sqlite-sqlx"))]
        {
            let _ = record;
            Err(self.durable_unavailable("sqlite record_revocation"))
        }
    }

    async fn list_revocations(&self, query: RevocationQuery) -> StoreResult<Vec<RevocationRecord>> {
        #[cfg(feature = "sqlite-sqlx")]
        {
            let pool = self.pool()?;
            let mut sql = String::from(
                "SELECT id, target_kind, target_id, reason, revoked_at, revoked_by FROM revocations WHERE 1=1",
            );
            let mut binds_i: i32 = 0;
            if query.target_kind.is_some() {
                binds_i += 1;
                sql.push_str(&format!(" AND target_kind = ?{binds_i}"));
            }
            if query.target_id.is_some() {
                binds_i += 1;
                sql.push_str(&format!(" AND target_id = ?{binds_i}"));
            }
            let limit_idx = binds_i + 1;
            let offset_idx = binds_i + 2;
            sql.push_str(&format!(
                " ORDER BY revoked_at ASC, id ASC LIMIT ?{limit_idx} OFFSET ?{offset_idx}"
            ));
            let limit = query.limit.map(|v| v as i64).unwrap_or(-1);
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
                .map_err(|e| map_durable_error("sqlite list revocations", e))?;
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
                    reason: r.try_get("reason").ok(),
                    revoked_at: r
                        .try_get("revoked_at")
                        .map_err(|e| StoreError::Invalid(e.to_string()))?,
                    revoked_by: r.try_get("revoked_by").ok(),
                });
            }
            return Ok(out);
        }
        #[cfg(not(feature = "sqlite-sqlx"))]
        {
            let _ = query;
            Err(self.durable_unavailable("sqlite list_revocations"))
        }
    }

    async fn record_taint_snapshot(
        &self,
        snapshot: TaintSnapshotRecord,
    ) -> StoreResult<TaintSnapshotRecord> {
        #[cfg(feature = "sqlite-sqlx")]
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
                .map_err(|e| map_durable_error("sqlite begin taint snapshot", e))?;
            let ins = sqlx::query(
                "INSERT INTO taint_snapshots (id, task_id, source, labels_json, digest, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
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
                let msg = e.to_string();
                if msg.contains("UNIQUE") {
                    return Err(StoreError::Conflict(format!(
                        "taint snapshot {} exists",
                        snapshot.id
                    )));
                }
                return Err(map_durable_error("sqlite insert taint snapshot", e));
            }
            if let Some(task_id) = &snapshot.task_id {
                let cur: Option<(Option<String>, Option<String>)> =
                    sqlx::query_as::<_, (Option<String>, Option<String>)>(
                        "SELECT ts.created_at, ts.id
                     FROM tasks t
                     LEFT JOIN taint_snapshots ts ON ts.id = t.taint_snapshot_id
                     WHERE t.id = ?1",
                    )
                    .bind(task_id)
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(|e| map_durable_error("sqlite read task taint link", e))?;

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
                    sqlx::query("UPDATE tasks SET taint_snapshot_id = ?1 WHERE id = ?2")
                        .bind(&snapshot.id)
                        .bind(task_id)
                        .execute(&mut *tx)
                        .await
                        .map_err(|e| map_durable_error("sqlite link taint snapshot to task", e))?;
                }
            }
            tx.commit()
                .await
                .map_err(|e| map_durable_error("sqlite commit taint snapshot", e))?;
            return Ok(snapshot);
        }
        #[cfg(not(feature = "sqlite-sqlx"))]
        {
            let _ = snapshot;
            Err(self.durable_unavailable("sqlite record_taint_snapshot"))
        }
    }

    async fn list_taint_snapshots(
        &self,
        query: TaintSnapshotQuery,
    ) -> StoreResult<Vec<TaintSnapshotRecord>> {
        #[cfg(feature = "sqlite-sqlx")]
        {
            let pool = self.pool()?;
            let mut sql = String::from(
                "SELECT id, task_id, source, labels_json, digest, created_at FROM taint_snapshots WHERE 1=1",
            );
            let mut binds_i: i32 = 0;
            if query.task_id.is_some() {
                binds_i += 1;
                sql.push_str(&format!(" AND task_id = ?{binds_i}"));
            }
            if query.source.is_some() {
                binds_i += 1;
                sql.push_str(&format!(" AND source = ?{binds_i}"));
            }
            let limit_idx = binds_i + 1;
            let offset_idx = binds_i + 2;
            sql.push_str(&format!(
                " ORDER BY created_at ASC, id ASC LIMIT ?{limit_idx} OFFSET ?{offset_idx}"
            ));
            let limit = query.limit.map(|v| v as i64).unwrap_or(-1);
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
                .map_err(|e| map_durable_error("sqlite list taint snapshots", e))?;
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
                    task_id: r.try_get("task_id").ok(),
                    source: r
                        .try_get("source")
                        .map_err(|e| StoreError::Invalid(e.to_string()))?,
                    labels,
                    digest: r.try_get("digest").ok(),
                    created_at: r
                        .try_get("created_at")
                        .map_err(|e| StoreError::Invalid(e.to_string()))?,
                });
            }
            return Ok(out);
        }
        #[cfg(not(feature = "sqlite-sqlx"))]
        {
            let _ = query;
            Err(self.durable_unavailable("sqlite list_taint_snapshots"))
        }
    }

    async fn health_check(&self) -> StoreResult<()> {
        #[cfg(feature = "sqlite-sqlx")]
        {
            let pool = self.pool()?;
            sqlx::query("SELECT 1")
                .execute(pool)
                .await
                .map_err(|e| map_durable_error("sqlite health_check", e))?;
            return Ok(());
        }
        #[cfg(not(feature = "sqlite-sqlx"))]
        Err(self.durable_unavailable("sqlite health_check"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "sqlite-sqlx")]
    async fn setup(name: &str) -> SqliteStore {
        // shared-cache in-memory for cross-connection pool visibility in tests
        let url = format!("sqlite:file:{name}?mode=memory&cache=shared");
        let mut s = SqliteStore::new(StoreConfig {
            backend: BackendKind::SqliteWal,
            database_url: url,
            fail_closed_on_audit_error: true,
        })
        .unwrap();
        s.connect().await.unwrap();
        s.migrate().await.unwrap();
        s
    }

    #[cfg(feature = "sqlite-sqlx")]
    #[tokio::test]
    async fn sqlite_audit_append_verify_and_query_parity() {
        let store = setup("audit_parity").await;
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
        let rep = store.verify_audit_chain().await.unwrap();
        assert!(rep.ok && rep.checked_events == 3);
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

    #[cfg(feature = "sqlite-sqlx")]
    #[tokio::test]
    async fn sqlite_crud_parity_core_flows() {
        let store = setup("crud_parity").await;
        let ap = store
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
        assert_eq!(ap.status, ApprovalStatus::Pending);
        assert_eq!(
            store.get_approval("ap1").await.unwrap().unwrap().tool,
            "echo"
        );
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
        let listed = store
            .list_approvals(ApprovalQuery {
                task_id: Some("task1".into()),
                status: Some(ApprovalStatus::Approved),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, "ap1");

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
        let tok_a = store
            .list_tasks(TaskQuery {
                token_id: Some("tok-a".into()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(tok_a.len(), 1);

        store
            .upsert_policy(PolicyRecord {
                id: "p1".into(),
                version: 1,
                body: "a".into(),
                created_at: "t".into(),
                active: true,
            })
            .await
            .unwrap();
        store
            .upsert_policy(PolicyRecord {
                id: "p2".into(),
                version: 2,
                body: "b".into(),
                created_at: "t".into(),
                active: true,
            })
            .await
            .unwrap();
        let active = store.get_active_policy().await.unwrap().unwrap();
        assert_eq!(active.id, "p2");

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
        let revs = store
            .list_revocations(RevocationQuery {
                target_id: Some("t1".into()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(revs.len(), 1);

        store
            .record_taint_snapshot(TaintSnapshotRecord {
                id: "s1".into(),
                task_id: Some("t2".into()),
                source: "broker".into(),
                labels: vec!["pii".into()],
                digest: Some("d".into()),
                created_at: "2026-01-01".into(),
            })
            .await
            .unwrap();
        store
            .record_taint_snapshot(TaintSnapshotRecord {
                id: "s2".into(),
                task_id: Some("t2".into()),
                source: "broker".into(),
                labels: vec!["pii".into(), "x".into()],
                digest: None,
                created_at: "2026-01-02".into(),
            })
            .await
            .unwrap();
        let task2 = store.get_task("t2").await.unwrap().unwrap();
        assert_eq!(task2.taint_snapshot_id.as_deref(), Some("s2"));
        let snaps = store
            .list_taint_snapshots(TaintSnapshotQuery {
                task_id: Some("t2".into()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(snaps.len(), 2);
        assert_eq!(snaps[1].labels.len(), 2);
    }

    #[cfg(feature = "sqlite-sqlx")]
    #[tokio::test]
    async fn sqlite_file_db_persists_across_connections() {
        let path = format!("/tmp/opencode/store-file-test-{}.db", std::process::id());
        let url = format!("sqlite://{path}?mode=rwc");
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{path}-shm"));
        let _ = std::fs::remove_file(format!("{path}-wal"));

        let mut store = SqliteStore::new(StoreConfig {
            backend: BackendKind::SqliteWal,
            database_url: url.clone(),
            fail_closed_on_audit_error: true,
        })
        .unwrap();
        store.connect().await.unwrap();
        store.migrate().await.unwrap();
        store
            .append_audit_event(AuditEvent {
                ts: "t1".into(),
                decision: "allow".into(),
                ..Default::default()
            })
            .await
            .unwrap();
        drop(store);

        let mut reopened = SqliteStore::new(StoreConfig {
            backend: BackendKind::SqliteWal,
            database_url: url,
            fail_closed_on_audit_error: true,
        })
        .unwrap();
        reopened.connect().await.unwrap();
        let rep = reopened.verify_audit_chain().await.unwrap();
        assert!(rep.ok && rep.checked_events == 1);

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{path}-shm"));
        let _ = std::fs::remove_file(format!("{path}-wal"));
    }

    #[cfg(feature = "sqlite-sqlx")]
    #[tokio::test]
    async fn sqlite_taint_snapshot_conflict_and_latest_link() {
        let store = setup("taint_latest_link").await;
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
                id: "s-new".into(),
                task_id: Some("t2".into()),
                source: "broker".into(),
                labels: vec!["new".into()],
                digest: None,
                created_at: "2026-01-02".into(),
            })
            .await
            .unwrap();
        store
            .record_taint_snapshot(TaintSnapshotRecord {
                id: "s-old".into(),
                task_id: Some("t2".into()),
                source: "broker".into(),
                labels: vec!["old".into()],
                digest: None,
                created_at: "2026-01-01".into(),
            })
            .await
            .unwrap();
        let task = store.get_task("t2").await.unwrap().unwrap();
        assert_eq!(task.taint_snapshot_id.as_deref(), Some("s-new"));

        let err = store
            .record_taint_snapshot(TaintSnapshotRecord {
                id: "s-new".into(),
                task_id: Some("t2".into()),
                source: "broker".into(),
                labels: vec![],
                digest: None,
                created_at: "2026-01-02".into(),
            })
            .await
            .unwrap_err();
        assert!(matches!(err, StoreError::Conflict(_)));
    }

    #[cfg(feature = "sqlite-sqlx")]
    #[tokio::test]
    async fn sqlite_taint_snapshot_for_missing_task_persists_without_link() {
        let store = setup("taint_missing_task").await;
        store
            .record_taint_snapshot(TaintSnapshotRecord {
                id: "s-orphan".into(),
                task_id: Some("nope".into()),
                source: "broker".into(),
                labels: vec!["x".into()],
                digest: None,
                created_at: "t1".into(),
            })
            .await
            .unwrap();
        assert!(store.get_task("nope").await.unwrap().is_none());
        let snaps = store
            .list_taint_snapshots(TaintSnapshotQuery {
                task_id: Some("nope".into()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(snaps.len(), 1);
        assert_eq!(snaps[0].id, "s-orphan");
    }

    #[cfg(feature = "sqlite-sqlx")]
    #[tokio::test]
    async fn sqlite_file_db_restart_safe_state_and_migrations() {
        let path = format!(
            "/tmp/opencode/store-restart-{}-{}.db",
            std::process::id(),
            "s1"
        );
        let url = format!("sqlite://{path}?mode=rwc");
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{path}-shm"));
        let _ = std::fs::remove_file(format!("{path}-wal"));

        let mut store = SqliteStore::new(StoreConfig {
            backend: BackendKind::SqliteWal,
            database_url: url.clone(),
            fail_closed_on_audit_error: true,
        })
        .unwrap();
        store.connect().await.unwrap();
        let first_mig = store.migrate().await.unwrap();
        assert_eq!(first_mig, vec![1]);

        store
            .upsert_policy(PolicyRecord {
                id: "p1".into(),
                version: 1,
                body: "a".into(),
                created_at: "t1".into(),
                active: true,
            })
            .await
            .unwrap();
        store
            .upsert_task(TaskRecord {
                id: "task1".into(),
                token_id: "tok".into(),
                scopes: "[]".into(),
                budget: 3,
                expires_at: "later".into(),
                ..Default::default()
            })
            .await
            .unwrap();
        store
            .create_approval(ApprovalRecord {
                id: "ap1".into(),
                task_id: "task1".into(),
                tool: "echo".into(),
                args_hash: "h".into(),
                status: ApprovalStatus::Pending,
                created_at: "t1".into(),
                ..Default::default()
            })
            .await
            .unwrap();
        store
            .resolve_approval(
                "ap1",
                ApprovalStatus::Approved,
                Some("u".into()),
                "t2".into(),
            )
            .await
            .unwrap();
        store
            .append_audit_event(AuditEvent {
                ts: "t1".into(),
                decision: "allow".into(),
                task_id: Some("task1".into()),
                ..Default::default()
            })
            .await
            .unwrap();
        store
            .append_audit_event(AuditEvent {
                ts: "t2".into(),
                decision: "deny".into(),
                task_id: Some("task1".into()),
                reason: Some("no".into()),
                ..Default::default()
            })
            .await
            .unwrap();
        store
            .record_revocation(RevocationRecord {
                id: "r1".into(),
                target_kind: "task".into(),
                target_id: "task1".into(),
                reason: Some("bad".into()),
                revoked_at: "t3".into(),
                revoked_by: Some("sys".into()),
            })
            .await
            .unwrap();
        store
            .record_taint_snapshot(TaintSnapshotRecord {
                id: "s1".into(),
                task_id: Some("task1".into()),
                source: "broker".into(),
                labels: vec!["pii".into()],
                digest: Some("d".into()),
                created_at: "t4".into(),
            })
            .await
            .unwrap();
        drop(store);

        let mut reopened = SqliteStore::new(StoreConfig {
            backend: BackendKind::SqliteWal,
            database_url: url.clone(),
            fail_closed_on_audit_error: true,
        })
        .unwrap();
        reopened.connect().await.unwrap();
        let second_mig = reopened.migrate().await.unwrap();
        assert!(
            second_mig.is_empty(),
            "migrations must be idempotent on reopen"
        );

        let rep = reopened.verify_audit_chain().await.unwrap();
        assert!(rep.ok && rep.checked_events == 2);
        let evs = reopened.query_audit(AuditQuery::default()).await.unwrap();
        assert_eq!(evs.len(), 2);
        assert_eq!(evs[1].prev_hash, evs[0].hash);

        let policy = reopened.get_active_policy().await.unwrap().unwrap();
        assert_eq!(policy.id, "p1");
        let task = reopened.get_task("task1").await.unwrap().unwrap();
        assert!(task.revoked);
        assert_eq!(task.revocation_reason.as_deref(), Some("bad"));
        assert_eq!(task.taint_snapshot_id.as_deref(), Some("s1"));
        let ap = reopened.get_approval("ap1").await.unwrap().unwrap();
        assert_eq!(ap.status, ApprovalStatus::Approved);
        assert_eq!(ap.resolver.as_deref(), Some("u"));
        let revs = reopened
            .list_revocations(RevocationQuery {
                target_id: Some("task1".into()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(revs.len(), 1);
        let snaps = reopened
            .list_taint_snapshots(TaintSnapshotQuery {
                task_id: Some("task1".into()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(snaps.len(), 1);
        assert_eq!(snaps[0].labels, vec!["pii".to_string()]);

        // idempotency/conflict persists across restart
        let dup_rev = reopened
            .record_revocation(RevocationRecord {
                id: "r1".into(),
                target_kind: "task".into(),
                target_id: "task1".into(),
                reason: Some("bad".into()),
                revoked_at: "t3".into(),
                revoked_by: Some("sys".into()),
            })
            .await
            .unwrap_err();
        assert!(matches!(dup_rev, StoreError::Conflict(_)));
        let dup_snap = reopened
            .record_taint_snapshot(TaintSnapshotRecord {
                id: "s1".into(),
                task_id: Some("task1".into()),
                source: "broker".into(),
                labels: vec![],
                digest: None,
                created_at: "t4".into(),
            })
            .await
            .unwrap_err();
        assert!(matches!(dup_snap, StoreError::Conflict(_)));
        let dup_ap = reopened
            .create_approval(ApprovalRecord {
                id: "ap1".into(),
                task_id: "task1".into(),
                tool: "echo".into(),
                args_hash: "h".into(),
                status: ApprovalStatus::Pending,
                created_at: "t1".into(),
                ..Default::default()
            })
            .await
            .unwrap_err();
        assert!(matches!(dup_ap, StoreError::Conflict(_)));

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{path}-shm"));
        let _ = std::fs::remove_file(format!("{path}-wal"));
    }

    #[cfg(feature = "sqlite-sqlx")]
    #[tokio::test]
    async fn sqlite_durable_tamper_detected_fail_closed() {
        let path = format!(
            "/tmp/opencode/store-tamper-{}-{}.db",
            std::process::id(),
            "s1"
        );
        let url = format!("sqlite://{path}?mode=rwc");
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{path}-shm"));
        let _ = std::fs::remove_file(format!("{path}-wal"));

        let mut store = SqliteStore::new(StoreConfig {
            backend: BackendKind::SqliteWal,
            database_url: url.clone(),
            fail_closed_on_audit_error: true,
        })
        .unwrap();
        store.connect().await.unwrap();
        store.migrate().await.unwrap();
        store
            .append_audit_event(AuditEvent {
                ts: "t1".into(),
                decision: "allow".into(),
                ..Default::default()
            })
            .await
            .unwrap();
        drop(store);

        // Tamper persisted row directly.
        let pool = sqlx::SqlitePool::connect(&url).await.unwrap();
        sqlx::query("UPDATE audit_events SET decision = 'tampered' WHERE seq = 1")
            .execute(&pool)
            .await
            .unwrap();
        drop(pool);

        let mut reopened = SqliteStore::new(StoreConfig {
            backend: BackendKind::SqliteWal,
            database_url: url.clone(),
            fail_closed_on_audit_error: true,
        })
        .unwrap();
        reopened.connect().await.unwrap();
        let err = reopened.verify_audit_chain().await.unwrap_err();
        assert!(matches!(err, StoreError::Integrity(_)));

        // Fail-open reporting path: return integrity report instead of error.
        let mut reopened_report = SqliteStore::new(StoreConfig {
            backend: BackendKind::SqliteWal,
            database_url: url.clone(),
            fail_closed_on_audit_error: false,
        })
        .unwrap();
        reopened_report.connect().await.unwrap();
        let rep = reopened_report.verify_audit_chain().await.unwrap();
        assert!(!rep.ok);
        assert_eq!(rep.message.as_deref(), Some("hash mismatch"));

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{path}-shm"));
        let _ = std::fs::remove_file(format!("{path}-wal"));
    }

    #[cfg(feature = "sqlite-sqlx")]
    #[tokio::test]
    async fn sqlite_pragmas_fail_closed_and_restart_safe() {
        let path = format!(
            "/tmp/opencode/store-pragmas-{}-{}.db",
            std::process::id(),
            "s1"
        );
        let url = format!("sqlite://{path}?mode=rwc");
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{path}-shm"));
        let _ = std::fs::remove_file(format!("{path}-wal"));

        let mut store = SqliteStore::new(StoreConfig {
            backend: BackendKind::SqliteWal,
            database_url: url.clone(),
            fail_closed_on_audit_error: true,
        })
        .unwrap();
        // fail-closed before connect
        let err = store
            .upsert_task(TaskRecord {
                id: "t1".into(),
                token_id: "tok".into(),
                scopes: "[]".into(),
                budget: 1,
                expires_at: "x".into(),
                ..Default::default()
            })
            .await
            .unwrap_err();
        assert!(matches!(err, StoreError::Unavailable(_)));

        store.connect().await.unwrap();
        let pool = store.pool().unwrap();
        let jm: String = sqlx::query_scalar("PRAGMA journal_mode;")
            .fetch_one(pool)
            .await
            .unwrap();
        assert_eq!(jm.to_lowercase(), "wal");
        let sync: i64 = sqlx::query_scalar("PRAGMA synchronous;")
            .fetch_one(pool)
            .await
            .unwrap();
        assert_eq!(sync, 2, "FULL");
        let fk: i64 = sqlx::query_scalar("PRAGMA foreign_keys;")
            .fetch_one(pool)
            .await
            .unwrap();
        assert_eq!(fk, 1);
        let busy: i64 = sqlx::query_scalar("PRAGMA busy_timeout;")
            .fetch_one(pool)
            .await
            .unwrap();
        assert_eq!(busy, 5000);

        store.migrate().await.unwrap();
        store
            .append_audit_event(AuditEvent {
                ts: "t1".into(),
                decision: "allow".into(),
                ..Default::default()
            })
            .await
            .unwrap();
        drop(store);

        let mut reopened = SqliteStore::new(StoreConfig {
            backend: BackendKind::SqliteWal,
            database_url: url.clone(),
            fail_closed_on_audit_error: true,
        })
        .unwrap();
        reopened.connect().await.unwrap();
        let jm2: String = sqlx::query_scalar("PRAGMA journal_mode;")
            .fetch_one(reopened.pool().unwrap())
            .await
            .unwrap();
        assert_eq!(jm2.to_lowercase(), "wal");
        let rep = reopened.verify_audit_chain().await.unwrap();
        assert!(rep.ok && rep.checked_events == 1);

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{path}-shm"));
        let _ = std::fs::remove_file(format!("{path}-wal"));
    }

    #[cfg(feature = "sqlite-sqlx")]
    #[tokio::test]
    async fn sqlite_conflicts_and_idempotency_guards() {
        let store = setup("conflicts_idempotency").await;
        store
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
        let dup = store
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
            .unwrap_err();
        assert!(matches!(dup, StoreError::Conflict(_)));
        let bad = store
            .resolve_approval("ap1", ApprovalStatus::Pending, None, "t2".into())
            .await
            .unwrap_err();
        assert!(matches!(bad, StoreError::Invalid(_)));
        store
            .resolve_approval("ap1", ApprovalStatus::Denied, Some("u".into()), "t2".into())
            .await
            .unwrap();
        let again = store
            .resolve_approval(
                "ap1",
                ApprovalStatus::Approved,
                Some("u2".into()),
                "t3".into(),
            )
            .await
            .unwrap_err();
        assert!(matches!(again, StoreError::Conflict(_)));

        store
            .upsert_task(TaskRecord {
                id: "t1".into(),
                token_id: "tok".into(),
                scopes: "[]".into(),
                budget: 1,
                expires_at: "x".into(),
                ..Default::default()
            })
            .await
            .unwrap();
        let rev = RevocationRecord {
            id: "r1".into(),
            target_kind: "task".into(),
            target_id: "t1".into(),
            reason: Some("bad".into()),
            revoked_at: "now".into(),
            revoked_by: None,
        };
        store.record_revocation(rev.clone()).await.unwrap();
        let dup_rev = store.record_revocation(rev).await.unwrap_err();
        assert!(matches!(dup_rev, StoreError::Conflict(_)));

        let bad_audit = store
            .append_audit_event(AuditEvent {
                ts: "".into(),
                decision: "allow".into(),
                ..Default::default()
            })
            .await
            .unwrap_err();
        assert!(matches!(bad_audit, StoreError::Invalid(_)));
    }

    #[cfg(feature = "sqlite-sqlx")]
    #[tokio::test]
    async fn sqlite_append_before_return_restart_live_proof() {
        let path = format!(
            "/tmp/opencode/store-live-proof-{}-{}.db",
            std::process::id(),
            "s1"
        );
        let url = format!("sqlite://{path}?mode=rwc");
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{path}-shm"));
        let _ = std::fs::remove_file(format!("{path}-wal"));

        let mut store = SqliteStore::new(StoreConfig {
            backend: BackendKind::SqliteWal,
            database_url: url.clone(),
            fail_closed_on_audit_error: true,
        })
        .unwrap();
        store.connect().await.unwrap();
        store.migrate().await.unwrap();

        let e1 = store
            .append_audit_event(AuditEvent {
                ts: "t1".into(),
                decision: "allow".into(),
                task_id: Some("task-live".into()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(e1.seq, 1);
        assert!(e1.prev_hash.is_none());
        assert!(e1.hash.is_some());
        let rep = store.verify_audit_chain().await.unwrap();
        assert!(rep.ok && rep.checked_events == 1);
        drop(store);

        let mut reopened = SqliteStore::new(StoreConfig {
            backend: BackendKind::SqliteWal,
            database_url: url.clone(),
            fail_closed_on_audit_error: true,
        })
        .unwrap();
        reopened.connect().await.unwrap();
        let rep = reopened.verify_audit_chain().await.unwrap();
        assert!(rep.ok && rep.checked_events == 1);
        let evs = reopened.query_audit(AuditQuery::default()).await.unwrap();
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].hash, e1.hash);

        let e2 = reopened
            .append_audit_event(AuditEvent {
                ts: "t2".into(),
                decision: "deny".into(),
                task_id: Some("task-live".into()),
                reason: Some("blocked".into()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(e2.seq, 2);
        assert_eq!(e2.prev_hash, e1.hash);
        let rep = reopened.verify_audit_chain().await.unwrap();
        assert!(rep.ok && rep.checked_events == 2);
        drop(reopened);

        let mut reopened2 = SqliteStore::new(StoreConfig {
            backend: BackendKind::SqliteWal,
            database_url: url.clone(),
            fail_closed_on_audit_error: true,
        })
        .unwrap();
        reopened2.connect().await.unwrap();
        let rep = reopened2.verify_audit_chain().await.unwrap();
        assert!(rep.ok && rep.checked_events == 2);
        let evs = reopened2.query_audit(AuditQuery::default()).await.unwrap();
        assert_eq!(evs[1].prev_hash, evs[0].hash);

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{path}-shm"));
        let _ = std::fs::remove_file(format!("{path}-wal"));
    }
}
