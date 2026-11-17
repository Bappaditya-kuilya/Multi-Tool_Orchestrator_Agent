//! Gateway binary entrypoint.

use std::net::SocketAddr;
use std::sync::Arc;

use gateway::{config, mcp, server, state::AppState};
use store::InMemoryStore;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::Mutex;

fn main() -> anyhow::Result<()> {
    let _ = tracing_subscriber::fmt::try_init();
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(async_main())
}

async fn serve_stdio(state: Arc<Mutex<AppState>>) -> anyhow::Result<()> {
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
        let resp = {
            let mut st = state.lock().await;
            mcp::handle_mcp_request_async(&mut st, req).await
        };
        stdout.write_all(resp.payload_json.as_bytes()).await?;
        stdout.write_all(b"\n").await?;
        stdout.flush().await?;
    }
    Ok(())
}

async fn async_main() -> anyhow::Result<()> {
    // Load config from scopegate.toml if present, else env/defaults; keep fail-closed.
    let path = std::env::var("GATEWAY_CONFIG").unwrap_or_else(|_| "scopegate.toml".to_string());
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

    let addr_str = std::env::var("GATEWAY_ADDR")
        .ok()
        .or_else(|| cfg.listen_addr.clone())
        .unwrap_or_else(|| "127.0.0.1:8080".to_string());
    let addr: SocketAddr = addr_str
        .parse()
        .unwrap_or_else(|_| SocketAddr::from(([127, 0, 0, 1], 8080)));

    // Attach in-memory store by default so readiness/audit/policy/approvals APIs function;
    // durable adapters can replace this wiring.
    let store = Arc::new(InMemoryStore::default()) as Arc<dyn store::Store>;
    let mut app = AppState::fail_closed().with_store(store);
    app.config = cfg;
    if std::env::args().any(|a| a == "--stdio" || a == "stdio") {
        app.config.mcp_mode = config::McpMode::Stdio;
    }
    app.configure_mcp_runtime();
    let mode = app.config.mcp_mode;
    let state = Arc::new(Mutex::new(app));

    match mode {
        config::McpMode::Stdio => {
            tracing::info!("starting gateway MCP stdio server (store wired, fail-closed defaults)");
            serve_stdio(state).await
        }
        config::McpMode::Http => {
            tracing::info!(%addr, "starting gateway HTTP server (store wired, fail-closed defaults)");
            server::serve(addr, state).await
        }
    }
}
