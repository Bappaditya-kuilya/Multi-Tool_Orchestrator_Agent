#![cfg(feature = "tokio-runtime")]

use mcp_pool::{
    runtime::{
        AsyncFrontDispatchRequest, AsyncHttpSender, AsyncMcpPool, HttpConnectionManager,
        StdioConnectionManager,
    },
    CallRequest, CircuitBreakerPolicy, ConnectionState, PoolError, RetryPolicy, TimeoutPolicy,
    UpstreamConfig, UpstreamServerConfig,
};
use serde_json::{json, Value};
use std::time::Duration;

#[derive(Clone)]
struct EchoHttpSender;
#[async_trait::async_trait]
impl AsyncHttpSender for EchoHttpSender {
    async fn post_json(&self, _url: &str, body: Value) -> Result<Value, PoolError> {
        Ok(
            json!({"jsonrpc":"2.0","id": body.get("id").cloned().unwrap_or(Value::Null), "result": {"echo": body.get("method").cloned().unwrap_or(Value::Null)}}),
        )
    }
}

#[tokio::test]
async fn async_http_pool_dispatch_lifecycle_and_retry_timeout_hooks() {
    let server = UpstreamServerConfig::with_http("http-up", "http://example.test/mcp");
    let id = server.id.clone();
    let cfg = UpstreamConfig {
        breaker: CircuitBreakerPolicy {
            failure_threshold: 2,
            ..Default::default()
        },
        retry: RetryPolicy {
            max_retries: 1,
            backoff: Duration::from_millis(1),
        },
        timeouts: TimeoutPolicy {
            call_timeout: Duration::from_millis(200),
            ..Default::default()
        },
        ..Default::default()
    };
    let mut pool = AsyncMcpPool::new(
        HttpConnectionManager {
            sender: EchoHttpSender,
        },
        UpstreamConfig::default(),
    );
    pool.register_with_server_config(server, cfg);
    assert_eq!(pool.state(&id), Some(ConnectionState::Disconnected));
    pool.connect(&id).await.expect("connect");
    assert_eq!(pool.state(&id), Some(ConnectionState::Connected));
    let out = pool
        .dispatch(
            &id,
            &CallRequest {
                method: "tools/list".into(),
                payload: "{}".into(),
            },
        )
        .await
        .expect("dispatch");
    assert!(out.response.payload.contains("tools/list"));
    assert_eq!(out.attempts, 1);
    let front = pool
        .dispatch_front(AsyncFrontDispatchRequest {
            upstream: id.clone(),
            method: "tools/call".into(),
            payload: "{}".into(),
        })
        .await
        .expect("front dispatch");
    assert!(front.payload.contains("tools/call"));
    pool.disconnect(&id).await.expect("disconnect");
    assert_eq!(pool.state(&id), Some(ConnectionState::Disconnected));
}

#[tokio::test]
async fn async_stdio_subprocess_client_roundtrip() {
    let script = r#"IFS= read -r line; echo '{"jsonrpc":"2.0","id":1,"result":{"ok":true}}'"#;
    let server =
        UpstreamServerConfig::with_stdio("stdio-up", "sh", vec!["-c".into(), script.into()]);
    let id = server.id.clone();
    let mut pool = AsyncMcpPool::new(StdioConnectionManager, UpstreamConfig::default());
    pool.register(server);
    pool.connect(&id).await.expect("connect stdio");
    let out = pool
        .dispatch(
            &id,
            &CallRequest {
                method: "ping".into(),
                payload: "{}".into(),
            },
        )
        .await
        .expect("dispatch stdio");
    assert!(out.response.payload.contains("ok"));
    pool.disconnect(&id).await.ok();
}

#[tokio::test]
async fn async_stdio_pool_dispatches_s1_with_demo_server() {
    let demo = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../e2e/stdio_demo_mcp_server.py");
    assert!(
        demo.exists(),
        "demo server script missing at {}",
        demo.display()
    );
    let server = UpstreamServerConfig::with_stdio(
        "demo",
        "python3",
        vec!["-u".into(), demo.to_string_lossy().into_owned()],
    );
    let id = server.id.clone();
    let mut pool = AsyncMcpPool::new(StdioConnectionManager, UpstreamConfig::default());
    pool.register(server);
    pool.connect(&id).await.expect("connect demo stdio");

    let init = pool
        .dispatch(
            &id,
            &CallRequest {
                method: "initialize".into(),
                payload: r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}"#
                    .into(),
            },
        )
        .await
        .expect("initialize");
    assert!(
        init.response.payload.contains("protocolVersion"),
        "{}",
        init.response.payload
    );

    let listed = pool
        .dispatch(
            &id,
            &CallRequest {
                method: "tools/list".into(),
                payload: r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#.into(),
            },
        )
        .await
        .expect("tools/list");
    assert!(
        listed.response.payload.contains("demo.echo"),
        "{}",
        listed.response.payload
    );

    let called = pool
        .dispatch(
            &id,
            &CallRequest {
                method: "tools/call".into(),
                payload: r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"demo.echo","arguments":{"message":"hello"}}}"#
                    .into(),
            },
        )
        .await
        .expect("tools/call");
    assert!(
        called.response.payload.contains("hello"),
        "{}",
        called.response.payload
    );

    pool.disconnect(&id).await.expect("disconnect");
}

#[cfg(feature = "rmcp")]
#[tokio::test]
async fn rmcp_stdio_pool_dispatches_s1_with_demo_server() {
    use mcp_pool::runtime::RmcpStdioConnectionManager;

    let demo = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../e2e/stdio_demo_mcp_server.py");
    assert!(
        demo.exists(),
        "demo server script missing at {}",
        demo.display()
    );
    let server = UpstreamServerConfig::with_stdio(
        "demo-rmcp",
        "python3",
        vec!["-u".into(), demo.to_string_lossy().into_owned()],
    );
    let id = server.id.clone();
    let mut pool = AsyncMcpPool::new(RmcpStdioConnectionManager, UpstreamConfig::default());
    pool.register(server);
    pool.connect(&id).await.expect("rmcp connect demo");

    let listed = pool
        .dispatch(
            &id,
            &CallRequest {
                method: "tools/list".into(),
                payload: r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}"#.into(),
            },
        )
        .await
        .expect("tools/list");
    assert!(
        listed.response.payload.contains("demo.echo"),
        "{}",
        listed.response.payload
    );

    let called = pool
        .dispatch(
            &id,
            &CallRequest {
                method: "tools/call".into(),
                payload: r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"demo.echo","arguments":{"message":"hello"}}}"#
                    .into(),
            },
        )
        .await
        .expect("tools/call");
    assert!(
        called.response.payload.contains("hello"),
        "{}",
        called.response.payload
    );

    let init = pool
        .dispatch(
            &id,
            &CallRequest {
                method: "initialize".into(),
                payload: r#"{"jsonrpc":"2.0","id":3,"method":"initialize","params":{}}"#.into(),
            },
        )
        .await
        .expect("initialize compat");
    assert!(init.response.payload.contains("protocolVersion"));

    pool.disconnect(&id).await.expect("disconnect");
}

#[tokio::test]
async fn async_stdio_pool_recovers_after_upstream_restart_s1() {
    // One-request-per-process server: simulates stdio upstream exit between calls.
    // Dispatch must fail closed on dead session, then succeed after reconnect/restart.
    let script = r#"IFS= read -r line; echo '{"jsonrpc":"2.0","id":1,"result":{"ok":true}}'"#;
    let server =
        UpstreamServerConfig::with_stdio("stdio-restart", "sh", vec!["-c".into(), script.into()]);
    let id = server.id.clone();
    let mut pool = AsyncMcpPool::new(StdioConnectionManager, UpstreamConfig::default());
    pool.register(server);
    pool.connect(&id).await.expect("connect");

    let first = pool
        .dispatch(
            &id,
            &CallRequest {
                method: "ping".into(),
                payload: "{}".into(),
            },
        )
        .await
        .expect("first dispatch");
    assert!(first.response.payload.contains("ok"));

    let second = pool
        .dispatch(
            &id,
            &CallRequest {
                method: "ping".into(),
                payload: "{}".into(),
            },
        )
        .await;
    assert!(
        second.is_err(),
        "dead stdio session must fail closed before restart"
    );
    assert!(
        matches!(
            pool.state(&id),
            Some(ConnectionState::Unhealthy | ConnectionState::Disconnected)
        ),
        "state={:?}",
        pool.state(&id)
    );

    pool.connect(&id).await.expect("reconnect/restart");
    let third = pool
        .dispatch(
            &id,
            &CallRequest {
                method: "ping".into(),
                payload: "{}".into(),
            },
        )
        .await
        .expect("dispatch after restart");
    assert!(third.response.payload.contains("ok"));

    pool.disconnect(&id).await.ok();
}
