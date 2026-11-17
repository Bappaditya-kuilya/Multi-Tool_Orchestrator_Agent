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

pub const SQLITE_001_INIT: &str = include_str!("../migrations/sqlite/001_init.sql");
pub const POSTGRES_001_INIT: &str = include_str!("../migrations/postgres/001_init.sql");

pub fn sqlite_migrations() -> &'static [Migration] {
    &[Migration {
        version: 1,
        name: "001_init",
        sql: SQLITE_001_INIT,
    }]
}

pub fn postgres_migrations() -> &'static [Migration] {
    &[Migration {
        version: 1,
        name: "001_init",
        sql: POSTGRES_001_INIT,
    }]
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

/// Apply embedded migrations using backend-native SQL execution.
pub async fn apply_migrations(backend: BackendKind, database_url: &str) -> StoreResult<Vec<i64>> {
    let versions: Vec<i64> = migrations_for(backend)?.iter().map(|m| m.version).collect();
    match backend {
        BackendKind::SqliteWal => {
            #[cfg(feature = "sqlite-sqlx")]
            {
                use sqlx::{Connection, Executor, SqliteConnection};
                let mut conn = SqliteConnection::connect(database_url)
                    .await
                    .map_err(|e| crate::durable::map_durable_error("sqlite connect", e))?;
                for m in migrations_for(backend)? {
                    conn.execute(m.sql).await.map_err(|e| {
                        crate::durable::map_durable_error(&format!("sqlite migrate {}", m.name), e)
                    })?;
                }
                Ok(versions)
            }
            #[cfg(not(feature = "sqlite-sqlx"))]
            {
                let _ = database_url;
                Err(StoreError::NotImplemented(
                    "sqlite migration apply requires sqlite-sqlx feature",
                ))
            }
        }
        BackendKind::Postgres => {
            #[cfg(feature = "postgres-sqlx")]
            {
                use sqlx::{Connection, Executor, PgConnection};
                let mut conn = PgConnection::connect(database_url)
                    .await
                    .map_err(|e| crate::durable::map_durable_error("postgres connect", e))?;
                for m in migrations_for(backend)? {
                    conn.execute(m.sql).await.map_err(|e| {
                        crate::durable::map_durable_error(
                            &format!("postgres migrate {}", m.name),
                            e,
                        )
                    })?;
                }
                Ok(versions)
            }
            #[cfg(not(feature = "postgres-sqlx"))]
            {
                let _ = database_url;
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
        assert_eq!(sqlite.len(), 1);
        assert_eq!(pg.len(), 1);
        assert!(sqlite[0]
            .sql
            .contains("CREATE TABLE IF NOT EXISTS audit_events"));
        assert!(pg[0].sql.contains("hash BYTEA"));
        assert!(pg[0].sql.contains("labels_json TEXT"));
    }

    #[cfg(feature = "sqlite-sqlx")]
    #[tokio::test]
    async fn sqlite_apply_migrations_runs() {
        let url = "sqlite:file:mig_apply?mode=memory&cache=shared";
        let versions = apply_migrations(BackendKind::SqliteWal, url).await.unwrap();
        assert_eq!(versions, vec![1]);
    }
}
