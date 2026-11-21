//! Embedded migration metadata and application helpers.
//!
//! Provides schema-aligned SQL bundles for SQLite/Postgres and wiring points
//! for `sqlx` migration execution (feature-gated / TODO where pools are absent).

use crate::{BackendKind, StoreError, StoreResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Migration {
    pub version: i64,
    pub name: &'static str,
    pub sql: &'static str,
}

pub const SCHEMA_MIGRATIONS_TABLE: &str = "_schema_migrations";
pub const SQLITE_001_INIT: &str = include_str!("../migrations/sqlite/001_init.sql");
pub const SQLITE_002_TOOL_PINS: &str = include_str!("../migrations/sqlite/002_tool_pins.sql");
pub const POSTGRES_001_INIT: &str = include_str!("../migrations/postgres/001_init.sql");
pub const POSTGRES_002_TOOL_PINS: &str = include_str!("../migrations/postgres/002_tool_pins.sql");

pub fn sqlite_migrations() -> &'static [Migration] {
    &[
        Migration {
            version: 1,
            name: "001_init",
            sql: SQLITE_001_INIT,
        },
        Migration {
            version: 2,
            name: "002_tool_pins",
            sql: SQLITE_002_TOOL_PINS,
        },
    ]
}

pub fn postgres_migrations() -> &'static [Migration] {
    &[
        Migration {
            version: 1,
            name: "001_init",
            sql: POSTGRES_001_INIT,
        },
        Migration {
            version: 2,
            name: "002_tool_pins",
            sql: POSTGRES_002_TOOL_PINS,
        },
    ]
}

pub fn migrations_for(backend: BackendKind) -> StoreResult<&'static [Migration]> {
    match backend {
        BackendKind::SqliteWal => Ok(sqlite_migrations()),
        BackendKind::Postgres => Ok(postgres_migrations()),
        BackendKind::InMemory => Err(StoreError::Invalid(
            "in-memory backend has no SQL migrations".into(),
        )),
    }
}

/// Validate embedded migration metadata for deterministic, idempotent tracking.
pub fn validate_migrations(migrations: &[Migration]) -> StoreResult<()> {
    for (expected, m) in (1_i64..).zip(migrations.iter()) {
        if m.version != expected {
            return Err(StoreError::Invalid(format!(
                "migration sequence gap/order: expected version {expected}, got {} ({})",
                m.version, m.name
            )));
        }
        if m.name.trim().is_empty() {
            return Err(StoreError::Invalid(format!(
                "migration {} has empty name",
                m.version
            )));
        }
        if m.sql.trim().is_empty() {
            return Err(StoreError::Invalid(format!(
                "migration {} ({}) has empty sql",
                m.version, m.name
            )));
        }
    }
    Ok(())
}

/// Return migration versions not present in `applied_versions` (set/list-agnostic input).
pub fn pending_migration_versions(
    migrations: &[Migration],
    applied_versions: &[i64],
) -> StoreResult<Vec<i64>> {
    validate_migrations(migrations)?;
    let mut applied = applied_versions.to_vec();
    applied.sort_unstable();
    applied.dedup();
    for v in &applied {
        if *v < 1 || *v > migrations.last().map(|m| m.version).unwrap_or(0) {
            return Err(StoreError::Invalid(format!(
                "applied migration version {v} is outside known range"
            )));
        }
    }
    let mut pending = Vec::new();
    for m in migrations {
        if !applied.binary_search(&m.version).is_ok() {
            pending.push(m.version);
        }
    }
    Ok(pending)
}

/// Apply embedded migrations using backend-native SQL execution.
///
/// Tracks applied versions in `_schema_migrations` so repeated runs are
/// restart-safe/idempotent and only unapplied migrations are executed.
pub async fn apply_migrations(backend: BackendKind, database_url: &str) -> StoreResult<Vec<i64>> {
    let migrations = migrations_for(backend)?;
    validate_migrations(migrations)?;
    match backend {
        BackendKind::SqliteWal => {
            #[cfg(feature = "sqlite-sqlx")]
            {
                use sqlx::{Connection, Executor, Row, SqliteConnection};
                use std::collections::HashSet;

                let mut conn = SqliteConnection::connect(database_url)
                    .await
                    .map_err(|e| crate::durable::map_durable_error("sqlite connect", e))?;

                conn.execute(
                    "CREATE TABLE IF NOT EXISTS _schema_migrations (\
                        version INTEGER PRIMARY KEY, \
                        name TEXT NOT NULL, \
                        applied_at TEXT NOT NULL\
                    )",
                )
                .await
                .map_err(|e| {
                    crate::durable::map_durable_error("sqlite ensure _schema_migrations", e)
                })?;

                let applied_rows = sqlx::query("SELECT version FROM _schema_migrations")
                    .fetch_all(&mut conn)
                    .await
                    .map_err(|e| {
                        crate::durable::map_durable_error("sqlite read _schema_migrations", e)
                    })?;
                let applied: HashSet<i64> = applied_rows
                    .into_iter()
                    .map(|row| row.get::<i64, _>("version"))
                    .collect();

                let mut newly_applied = Vec::new();
                for m in migrations {
                    if applied.contains(&m.version) {
                        continue;
                    }

                    conn.execute("BEGIN IMMEDIATE").await.map_err(|e| {
                        crate::durable::map_durable_error("sqlite begin migration tx", e)
                    })?;

                    if let Err(e) = conn.execute(m.sql).await {
                        let _ = conn.execute("ROLLBACK").await;
                        return Err(crate::durable::map_durable_error(
                            &format!("sqlite migrate {}", m.name),
                            e,
                        ));
                    }

                    if let Err(e) = sqlx::query(
                        "INSERT INTO _schema_migrations(version, name, applied_at) \
                         VALUES (?, ?, strftime('%Y-%m-%dT%H:%M:%fZ','now'))",
                    )
                    .bind(m.version)
                    .bind(m.name)
                    .execute(&mut conn)
                    .await
                    {
                        let _ = conn.execute("ROLLBACK").await;
                        let msg = e.to_string();
                        if msg.contains("UNIQUE") {
                            // Concurrent migrator recorded it; idempotent outcome.
                            continue;
                        }
                        return Err(crate::durable::map_durable_error(
                            &format!("sqlite record migration {}", m.name),
                            e,
                        ));
                    }

                    conn.execute("COMMIT").await.map_err(|e| {
                        crate::durable::map_durable_error("sqlite commit migration tx", e)
                    })?;
                    newly_applied.push(m.version);
                }

                Ok(newly_applied)
            }
            #[cfg(not(feature = "sqlite-sqlx"))]
            {
                let _ = (database_url, migrations);
                Err(StoreError::NotImplemented(
                    "sqlite migration apply requires sqlite-sqlx feature",
                ))
            }
        }
        BackendKind::Postgres => {
            #[cfg(feature = "postgres-sqlx")]
            {
                use sqlx::{Connection, Executor, PgConnection, Row};
                use std::collections::HashSet;

                let mut conn = PgConnection::connect(database_url)
                    .await
                    .map_err(|e| crate::durable::map_durable_error("postgres connect", e))?;

                conn.execute(
                    "CREATE TABLE IF NOT EXISTS _schema_migrations (\
                        version BIGINT PRIMARY KEY, \
                        name TEXT NOT NULL, \
                        applied_at TEXT NOT NULL\
                    )",
                )
                .await
                .map_err(|e| {
                    crate::durable::map_durable_error("postgres ensure _schema_migrations", e)
                })?;

                let applied_rows = sqlx::query("SELECT version FROM _schema_migrations")
                    .fetch_all(&mut conn)
                    .await
                    .map_err(|e| {
                        crate::durable::map_durable_error("postgres read _schema_migrations", e)
                    })?;
                let applied: HashSet<i64> = applied_rows
                    .into_iter()
                    .map(|row| row.get::<i64, _>("version"))
                    .collect();

                let mut newly_applied = Vec::new();
                for m in migrations {
                    if applied.contains(&m.version) {
                        continue;
                    }

                    conn.execute("BEGIN").await.map_err(|e| {
                        crate::durable::map_durable_error("postgres begin migration tx", e)
                    })?;

                    if let Err(e) = conn.execute(m.sql).await {
                        let _ = conn.execute("ROLLBACK").await;
                        return Err(crate::durable::map_durable_error(
                            &format!("postgres migrate {}", m.name),
                            e,
                        ));
                    }

                    if let Err(e) = sqlx::query(
                        "INSERT INTO _schema_migrations(version, name, applied_at) \
                         VALUES ($1, $2, now()::text)",
                    )
                    .bind(m.version)
                    .bind(m.name)
                    .execute(&mut conn)
                    .await
                    {
                        let _ = conn.execute("ROLLBACK").await;
                        let is_unique = match &e {
                            sqlx::Error::Database(db) => db.code().as_deref() == Some("23505"),
                            _ => false,
                        };
                        if is_unique {
                            // Concurrent migrator recorded it; idempotent outcome.
                            continue;
                        }
                        return Err(crate::durable::map_durable_error(
                            &format!("postgres record migration {}", m.name),
                            e,
                        ));
                    }

                    conn.execute("COMMIT").await.map_err(|e| {
                        crate::durable::map_durable_error("postgres commit migration tx", e)
                    })?;
                    newly_applied.push(m.version);
                }

                Ok(newly_applied)
            }
            #[cfg(not(feature = "postgres-sqlx"))]
            {
                let _ = (database_url, migrations);
                Err(StoreError::NotImplemented(
                    "postgres migration apply requires postgres-sqlx feature",
                ))
            }
        }
        BackendKind::InMemory => unreachable!("filtered above"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_migrations_present() {
        let sqlite = sqlite_migrations();
        let pg = postgres_migrations();
        assert_eq!(sqlite.len(), 2);
        assert_eq!(pg.len(), 2);
        assert!(sqlite[0]
            .sql
            .contains("CREATE TABLE IF NOT EXISTS audit_events"));
        assert!(sqlite[1]
            .sql
            .contains("CREATE TABLE IF NOT EXISTS tool_pins"));
        assert!(pg[0].sql.contains("hash BYTEA"));
        assert!(pg[0].sql.contains("labels_json TEXT"));
        assert!(pg[1].sql.contains("CREATE TABLE IF NOT EXISTS tool_pins"));
    }

    #[test]
    fn migration_sequence_valid_and_pending_helpers() {
        let migrations = sqlite_migrations();
        validate_migrations(migrations).unwrap();
        assert_eq!(
            pending_migration_versions(migrations, &[]).unwrap(),
            vec![1, 2]
        );
        assert_eq!(
            pending_migration_versions(migrations, &[1]).unwrap(),
            vec![2]
        );
        assert!(pending_migration_versions(migrations, &[1, 2])
            .unwrap()
            .is_empty());
        let err = pending_migration_versions(migrations, &[3]).unwrap_err();
        assert!(matches!(err, StoreError::Invalid(_)));

        let bad = [Migration {
            version: 2,
            name: "002_bad",
            sql: "SELECT 1;",
        }];
        assert!(matches!(
            validate_migrations(&bad),
            Err(StoreError::Invalid(_))
        ));
    }

    #[cfg(feature = "sqlite-sqlx")]
    #[tokio::test]
    async fn sqlite_apply_migrations_runs() {
        let url = "sqlite:file:mig_apply?mode=memory&cache=shared";
        let versions = apply_migrations(BackendKind::SqliteWal, url).await.unwrap();
        assert_eq!(versions, vec![1, 2]);
    }

    #[cfg(feature = "sqlite-sqlx")]
    #[tokio::test]
    async fn sqlite_apply_migrations_is_idempotent() {
        use sqlx::{Connection, SqliteConnection};

        let url = "sqlite:file:mig_apply_idempotent?mode=memory&cache=shared";
        let mut _keeper = SqliteConnection::connect(url).await.unwrap();
        let first = apply_migrations(BackendKind::SqliteWal, url).await.unwrap();
        assert_eq!(first, vec![1, 2]);
        let second = apply_migrations(BackendKind::SqliteWal, url).await.unwrap();
        assert!(second.is_empty());

        let mut conn = SqliteConnection::connect(url).await.unwrap();
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM _schema_migrations")
            .fetch_one(&mut conn)
            .await
            .unwrap();
        assert_eq!(count, 2);
    }
}
