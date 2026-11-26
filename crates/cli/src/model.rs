//! Wire models for the gateway's `ApiResponse<T>` envelope and its `body` payloads.
//!
//! These are deliberately loose: the gateway API is an evolving preview surface
//! (`README.md:57`), so optional fields default instead of failing the client.

use serde::Deserialize;

/// `ApiResponse<T>` from `crates/gateway/src/api.rs:64`.
#[derive(Debug, Clone, Deserialize)]
pub struct Envelope<T> {
    #[serde(default)]
    pub status: String,
    pub body: Option<T>,
    #[serde(default)]
    pub fail_closed: bool,
    #[serde(default)]
    pub error: Option<String>,
}

impl<T> Envelope<T> {
    /// Turn a gateway envelope into a body or a human-readable error.
    pub fn into_result(self) -> Result<T, String> {
        if let Some(body) = self.body {
            return Ok(body);
        }
        let detail = self
            .error
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| {
                if self.status.is_empty() {
                    "empty response".to_string()
                } else {
                    format!("gateway returned {}", self.status)
                }
            });
        let suffix = if self.fail_closed {
            " (fail-closed)"
        } else {
            ""
        };
        Err(format!("{detail}{suffix}"))
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct Health {
    #[serde(default)]
    pub status: String,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct Ready {
    #[serde(default)]
    pub ready: bool,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct Metrics {
    #[serde(default)]
    pub format: String,
    #[serde(default)]
    pub body: String,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct VerifyReport {
    #[serde(default)]
    pub ok: bool,
    #[serde(default)]
    pub checked_events: u64,
    #[serde(default)]
    pub first_bad_seq: Option<i64>,
    #[serde(default)]
    pub message: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct AuditEventView {
    #[serde(default)]
    pub seq: i64,
    #[serde(default)]
    pub ts: String,
    #[serde(default)]
    pub task_id: Option<String>,
    #[serde(default)]
    pub tool: Option<String>,
    #[serde(default)]
    pub decision: String,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct AuditQueryView {
    #[serde(default)]
    pub events: Vec<AuditEventView>,
    #[serde(default)]
    pub chain_verified: bool,
    #[serde(default)]
    pub verification: Option<VerifyReport>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ApprovalRecordView {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub task_id: String,
    #[serde(default)]
    pub tool: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub created_at: String,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ApprovalListView {
    #[serde(default)]
    pub approvals: Vec<ApprovalRecordView>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ApprovalView {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub task_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct TaskRecordView {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub token_id: String,
    #[serde(default)]
    pub budget: i64,
    #[serde(default)]
    pub expires_at: String,
    #[serde(default)]
    pub revoked: bool,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct TaskListView {
    #[serde(default)]
    pub tasks: Vec<TaskRecordView>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct PolicyView {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub active: bool,
    #[serde(default)]
    pub version: Option<i64>,
    #[serde(default)]
    pub body: Option<serde_json::Value>,
}
