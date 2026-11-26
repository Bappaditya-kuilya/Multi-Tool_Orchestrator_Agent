//! Small, network-free tests for the client's pure logic.
//! These are written before the implementation (RED).

use scopegate_ctl::client::{join_url, resolve_action_to_decision};
use scopegate_ctl::model::Envelope;

#[test]
fn join_url_normalizes_slashes() {
    assert_eq!(
        join_url("http://127.0.0.1:8080/", "/v1/tasks"),
        "http://127.0.0.1:8080/v1/tasks"
    );
    assert_eq!(
        join_url("http://127.0.0.1:8080", "healthz"),
        "http://127.0.0.1:8080/healthz"
    );
}

#[test]
fn resolve_action_maps_human_words_to_api_decisions() {
    assert_eq!(resolve_action_to_decision("approve"), Some("approve"));
    assert_eq!(resolve_action_to_decision("deny"), Some("deny"));
    assert_eq!(resolve_action_to_decision("timeout"), Some("timeout"));
    assert_eq!(resolve_action_to_decision("nonsense"), None);
}

#[test]
fn envelope_ok_returns_body() {
    let json = r#"{"status":"Ok","body":{"status":"ok"},"fail_closed":false}"#;
    let env: Envelope<serde_json::Value> = serde_json::from_str(json).expect("valid envelope");
    let body = env.into_result().expect("ok envelope");
    assert_eq!(body["status"], "ok");
}

#[test]
fn envelope_fail_uses_gateway_error_message() {
    let json = r#"{"status":"ServiceUnavailable","body":null,"fail_closed":true,"error":"store unavailable (fail-closed)"}"#;
    let env: Envelope<serde_json::Value> = serde_json::from_str(json).expect("valid envelope");
    let err = env.into_result().expect_err("fail envelope");
    assert!(err.contains("store unavailable"), "{err}");
}

#[test]
fn envelope_fail_without_error_mentions_status() {
    let json = r#"{"status":"Forbidden","body":null,"fail_closed":true}"#;
    let env: Envelope<serde_json::Value> = serde_json::from_str(json).expect("valid envelope");
    let err = env.into_result().expect_err("fail envelope");
    assert!(err.contains("Forbidden"), "{err}");
}
