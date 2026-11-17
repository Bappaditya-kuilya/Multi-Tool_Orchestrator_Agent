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
