//! Thin HTTP client over ScopeGate's v1 API. Uses no gateway internals.

use std::time::Duration;

use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::model::{
    ApprovalListView, ApprovalRecordView, ApprovalView, AuditQueryView, Envelope, Health, Metrics,
    PolicyView, Ready, TaskListView, TaskRecordView, VerifyReport,
};

/// Join a base URL and a path with exactly one slash.
pub fn join_url(base: &str, path: &str) -> String {
    let base = base.trim_end_matches('/');
    let path = path.trim_start_matches('/');
    format!("{base}/{path}")
}

/// Map a human word to the `decision` value accepted by `/v1/approvals/:id/resolve`.
pub fn resolve_action_to_decision(action: &str) -> Option<&'static str> {
    match action.to_ascii_lowercase().as_str() {
        "approve" | "approved" | "allow" => Some("approve"),
        "deny" | "denied" | "reject" => Some("deny"),
        "timeout" | "timed_out" | "expired" => Some("timeout"),
        _ => None,
    }
}

#[derive(Clone)]
pub struct Client {
    agent: ureq::Agent,
    base: String,
    token: Option<String>,
}

impl Client {
    pub fn new(base: impl Into<String>, token: Option<String>) -> Self {
        let config = ureq::Agent::config_builder()
            // Read 4xx/5xx bodies so we can surface the gateway's fail-closed error.
            .http_status_as_error(false)
            .timeout_global(Some(Duration::from_secs(5)))
            .build();
        Self {
            agent: config.into(),
            base: base.into(),
            token,
        }
    }

    pub fn endpoint(&self) -> &str {
        &self.base
    }

    fn with_auth<B>(&self, req: ureq::RequestBuilder<B>) -> ureq::RequestBuilder<B> {
        match &self.token {
            Some(token) => req.header("Authorization", format!("Bearer {token}")),
            None => req,
        }
    }

    fn get_envelope<T: DeserializeOwned>(&self, path: &str) -> Result<Envelope<T>, String> {
        let request = self.with_auth(self.agent.get(join_url(&self.base, path)));
        let mut response = request.call().map_err(|e| format!("request failed: {e}"))?;
        let status = response.status().as_u16();
        let body = response
            .body_mut()
            .read_to_string()
            .map_err(|e| format!("failed to read response body: {e}"))?;
        parse_envelope(&body, status)
    }

    fn post_envelope<T: DeserializeOwned>(
        &self,
        path: &str,
        payload: &Value,
    ) -> Result<Envelope<T>, String> {
        let request = self
            .with_auth(self.agent.post(join_url(&self.base, path)))
            .header("Content-Type", "application/json");
        let mut response = request
            .send(payload.to_string())
            .map_err(|e| format!("request failed: {e}"))?;
        let status = response.status().as_u16();
        let body = response
            .body_mut()
            .read_to_string()
            .map_err(|e| format!("failed to read response body: {e}"))?;
        parse_envelope(&body, status)
    }

    pub fn health(&self) -> Result<Health, String> {
        self.get_envelope("/healthz")?.into_result()
    }

    pub fn ready(&self) -> Result<Ready, String> {
        self.get_envelope("/readyz")?.into_result()
    }

    /// `/metrics` is the one route that returns raw Prometheus text, not an
    /// `ApiResponse<T>` envelope (`crates/gateway/src/server.rs:135`).
    pub fn metrics(&self) -> Result<Metrics, String> {
        let request = self.with_auth(self.agent.get(join_url(&self.base, "/metrics")));
        let mut response = request.call().map_err(|e| format!("request failed: {e}"))?;
        let status = response.status().as_u16();
        let body = response
            .body_mut()
            .read_to_string()
            .map_err(|e| format!("failed to read response body: {e}"))?;
        metrics_from_text(status, body)
    }

    pub fn tasks(&self) -> Result<Vec<TaskRecordView>, String> {
        self.get_envelope::<TaskListView>("/v1/tasks")?
            .into_result()
            .map(|v| v.tasks)
    }

    pub fn approvals(&self, status: Option<&str>) -> Result<Vec<ApprovalRecordView>, String> {
        let path = match status {
            Some(s) if !s.trim().is_empty() => format!("/v1/approvals?status={s}"),
            _ => "/v1/approvals".to_string(),
        };
        self.get_envelope::<ApprovalListView>(&path)?
            .into_result()
            .map(|v| v.approvals)
    }

    pub fn resolve(&self, id: &str, decision: &str) -> Result<ApprovalView, String> {
        let decision = resolve_action_to_decision(decision)
            .ok_or_else(|| format!("unknown decision: {decision}"))?;
        let path = format!("/v1/approvals/{id}/resolve");
        self.post_envelope(&path, &serde_json::json!({ "decision": decision }))?
            .into_result()
    }

    pub fn audit(&self, limit: u32) -> Result<AuditQueryView, String> {
        self.get_envelope(&format!("/v1/audit?limit={limit}"))?
            .into_result()
    }

    pub fn audit_verify(&self) -> Result<VerifyReport, String> {
        self.get_envelope("/v1/audit/verify")?.into_result()
    }

    pub fn policy(&self) -> Result<PolicyView, String> {
        self.get_envelope("/v1/policies")?.into_result()
    }
}

/// Keep the raw Prometheus body; only reject non-success HTTP statuses.
pub fn metrics_from_text(status: u16, body: String) -> Result<Metrics, String> {
    if status >= 400 {
        return Err(format!("metrics unavailable (HTTP {status})"));
    }
    Ok(Metrics {
        format: "text/plain; version=0.0.4".to_string(),
        body,
    })
}

fn parse_envelope<T: DeserializeOwned>(body: &str, status: u16) -> Result<Envelope<T>, String> {
    serde_json::from_str(body).map_err(|e| {
        format!(
            "invalid JSON from gateway (HTTP {status}): {e}; body: {}",
            truncate(body)
        )
    })
}

fn truncate(s: &str) -> String {
    const MAX: usize = 200;
    if s.chars().count() <= MAX {
        return s.to_string();
    }
    let head: String = s.chars().take(MAX).collect();
    format!("{head}... (truncated)")
}
