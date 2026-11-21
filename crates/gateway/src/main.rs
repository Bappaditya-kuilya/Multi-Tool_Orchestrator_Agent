//! Gateway binary entrypoint.

use std::net::SocketAddr;
use std::sync::Arc;

use gateway::{config, mcp, server, state::AppState};
use store::{BackendKind, InMemoryStore, PostgresStore, SqliteStore, Store, StoreConfig};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

fn stdio_mode_requested(args: impl IntoIterator<Item = String>) -> bool {
    args.into_iter().any(|a| a == "--stdio" || a == "stdio")
}

fn sqlite_database_url_or_default(configured: Option<&str>) -> String {
    configured
        .filter(|s| !s.trim().is_empty())
        .unwrap_or("sqlite://scopegate.db")
        .to_string()
}

fn main() -> anyhow::Result<()> {
    // Keep MCP stdio stdout clean for protocol traffic.
    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .try_init();
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(async_main())
}

async fn serve_stdio(state: Arc<AppState>) -> anyhow::Result<()> {
    let stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let mut lines = BufReader::new(stdin).lines();
    while let Some(line) = lines.next_line().await? {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let req = mcp::McpRequest {
            method: String::new(),
            payload_json: trimmed.to_string(),
            upstream: None,
        };
        let resp = mcp::handle_mcp_request_async(&state, req).await;
        stdout.write_all(resp.payload_json.as_bytes()).await?;
        stdout.write_all(b"\n").await?;
        stdout.flush().await?;
    }
    Ok(())
}

// (URL heuristics handled in config; startup honors explicit store selection)

async fn async_main() -> anyhow::Result<()> {
    // Load config from scopegate.toml if present, else env/defaults; keep fail-closed.
    let path = std::env::var("GATEWAY_CONFIG")
        .or_else(|_| std::env::var("SCOPEGATE_CONFIG"))
        .unwrap_or_else(|_| "scopegate.toml".to_string());
    let mut cfg = config::load_gateway_config_from_path(&path);
    if cfg.rules.is_empty() {
        // Safe default demo/dev rule set can be overridden by config; still fail-closed otherwise.
        cfg = cfg.with_rules(vec![
            scopegate_core::policy::Rule::exact(
                "agent",
                "tool.invoke",
                "tool",
                scopegate_core::policy::PolicyDecision::Permit,
            ),
            scopegate_core::policy::Rule::exact(
                "anonymous",
                "tools/list",
                "tools/list",
                scopegate_core::policy::PolicyDecision::Permit,
            ),
            scopegate_core::policy::Rule::exact(
                "anonymous",
                "tools/call",
                "gateway.health",
                scopegate_core::policy::PolicyDecision::Permit,
            ),
            scopegate_core::policy::Rule::exact(
                "anonymous",
                "tools/call",
                "tools/call",
                scopegate_core::policy::PolicyDecision::Permit,
            ),
        ]);
    }
    // CLI override for stdio proof/source runs.
    if stdio_mode_requested(std::env::args()) {
        cfg.mcp_mode = config::McpMode::Stdio;
    }

    let addr_str = std::env::var("GATEWAY_ADDR")
        .ok()
        .or_else(|| cfg.listen_addr.clone())
        .unwrap_or_else(|| "127.0.0.1:8080".to_string());
    let addr: SocketAddr = addr_str
        .parse()
        .unwrap_or_else(|_| SocketAddr::from(([127, 0, 0, 1], 8080)));

    // Attach store by explicit selection; durable backends fail closed on
    // init/connect/migrate/health errors.
    let store: Arc<dyn Store> = match cfg.store_selection {
        config::StoreSelection::Postgres => {
            let db_url = cfg.store_database_url.clone().ok_or_else(|| {
                anyhow::anyhow!("postgres store selected but database URL missing (fail-closed)")
            })?;
            let store_cfg = StoreConfig {
                backend: BackendKind::Postgres,
                database_url: db_url.clone(),
                fail_closed_on_audit_error: cfg.fail_closed,
            };
            let mut pg = PostgresStore::new(store_cfg)
                .map_err(|e| anyhow::anyhow!("postgres store init failed (fail-closed): {e}"))?;
            pg.connect()
                .await
                .map_err(|e| anyhow::anyhow!("postgres store connect failed (fail-closed): {e}"))?;
            pg.migrate()
                .await
                .map_err(|e| anyhow::anyhow!("postgres store migrate failed (fail-closed): {e}"))?;
            pg.health_check().await.map_err(|e| {
                anyhow::anyhow!("postgres store health check failed (fail-closed): {e}")
            })?;
            tracing::info!(database_url = %db_url, "using postgres durable store");
            Arc::new(pg)
        }
        config::StoreSelection::SqliteWal => {
            let db_url = sqlite_database_url_or_default(cfg.store_database_url.as_deref());
            let store_cfg = StoreConfig {
                backend: BackendKind::SqliteWal,
                database_url: db_url.clone(),
                fail_closed_on_audit_error: cfg.fail_closed,
            };
            let mut sqlite = SqliteStore::new(store_cfg)
                .map_err(|e| anyhow::anyhow!("sqlite store init failed (fail-closed): {e}"))?;
            sqlite
                .connect()
                .await
                .map_err(|e| anyhow::anyhow!("sqlite store connect failed (fail-closed): {e}"))?;
            sqlite
                .migrate()
                .await
                .map_err(|e| anyhow::anyhow!("sqlite store migrate failed (fail-closed): {e}"))?;
            sqlite.health_check().await.map_err(|e| {
                anyhow::anyhow!("sqlite store health check failed (fail-closed): {e}")
            })?;
            tracing::info!(database_url = %db_url, "using sqlite durable store");
            Arc::new(sqlite)
        }
        config::StoreSelection::InMemory => Arc::new(InMemoryStore::default()),
    };
    let store_kind = store.backend().to_string();

    let mut app = AppState::fail_closed().with_store(store);
    app.config = cfg;
    app.configure_mcp_runtime();
    // Fail closed when MCP upstreams are configured but runtime wiring is unavailable.
    if !app.config.mcp_upstreams.is_empty() && !app.has_mcp_runtime().await {
        anyhow::bail!(
            "startup MCP runtime wiring failed (fail-closed): configured upstreams unavailable"
        );
    }
    // Startup hook checks/state prep (rate-limit state, revocation sync, optional approval rehydration). Fail closed.
    app.prepare_runtime_hooks().await.map_err(|e| {
        anyhow::anyhow!("startup runtime hook preparation failed (fail-closed): {e}")
    })?;

    // S1 startup rehydration (fail-closed) to keep broker/store views consistent across restarts.
    // Avoid duplicate query when approval-store hook already rehydrated during prepare.
    if !app.config.runtime_hooks.use_approval_store {
        app.rehydrate_pending_approvals_from_store()
            .await
            .map_err(|e| {
                anyhow::anyhow!("startup approval rehydration failed (fail-closed): {e}")
            })?;
    }

    let mode = app.config.mcp_mode;
    let state = Arc::new(app);

    match mode {
        config::McpMode::Stdio => {
            tracing::info!(store = %store_kind, "starting gateway MCP stdio server (store wired, fail-closed defaults)");
            serve_stdio(state).await
        }
        config::McpMode::Http => {
            tracing::info!(%addr, store = %store_kind, "starting gateway HTTP server (store wired, fail-closed defaults)");
            server::serve(addr, state).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{sqlite_database_url_or_default, stdio_mode_requested};

    #[test]
    fn stdio_mode_requested_accepts_flag_and_subcommand() {
        assert!(stdio_mode_requested(vec![
            "gateway".to_string(),
            "--stdio".to_string()
        ]));
        assert!(stdio_mode_requested(vec![
            "gateway".to_string(),
            "stdio".to_string()
        ]));
        assert!(!stdio_mode_requested(vec![
            "gateway".to_string(),
            "--http".to_string()
        ]));
        assert!(!stdio_mode_requested(Vec::<String>::new()));
    }

    #[test]
    fn sqlite_database_url_defaults_for_missing_or_blank_values() {
        assert_eq!(
            sqlite_database_url_or_default(None),
            "sqlite://scopegate.db"
        );
        assert_eq!(
            sqlite_database_url_or_default(Some("")),
            "sqlite://scopegate.db"
        );
        assert_eq!(
            sqlite_database_url_or_default(Some("   ")),
            "sqlite://scopegate.db"
        );
        assert_eq!(
            sqlite_database_url_or_default(Some("sqlite://./.scopegate/s1.db")),
            "sqlite://./.scopegate/s1.db"
        );
    }
}
