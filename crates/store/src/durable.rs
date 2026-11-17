//! Durable-store protocol placeholders and transaction semantics notes.
//!
//! These types document intended `sqlx` transaction boundaries for append-before-return
//! audit writes and related persistence operations.

use crate::{compute_audit_hash, AuditEvent, StoreError, StoreResult};

/// Placeholder transaction handle for future sqlx-backed adapters.
#[derive(Debug, Default)]
pub struct TransactionContext {
    pub backend: &'static str,
    pub active: bool,
}

/// Describes an audit append that must commit before returning to callers.
#[derive(Debug, Clone)]
pub struct AuditAppendPlan {
    pub event: AuditEvent,
    pub expected_prev_hash: Option<Vec<u8>>,
}

impl AuditAppendPlan {
    /// Compute sequence/hash fields for an append operation given prior chain tail.
    pub fn materialize(mut self, seq: i64, prev_hash: Option<Vec<u8>>) -> StoreResult<AuditEvent> {
        if self.expected_prev_hash != prev_hash {
            return Err(StoreError::Conflict(
                "audit prev_hash changed during append planning".into(),
            ));
        }
        self.event.seq = seq;
        self.event.prev_hash = prev_hash;
        self.event.hash = Some(compute_audit_hash(&self.event));
        Ok(self.event)
    }
}

/// Placeholder for durable query execution with retry/timeout policy hooks.
///
/// TODO(sqlx): wire statement timeout, isolation level, and fail-closed mapping.
pub fn map_durable_error(context: &str, err: impl std::fmt::Display) -> StoreError {
    StoreError::Unavailable(format!("{context}: {err}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_append_plan_sets_hash_chain_fields() {
        let plan = AuditAppendPlan {
            event: AuditEvent {
                ts: "t".into(),
                decision: "allow".into(),
                ..Default::default()
            },
            expected_prev_hash: None,
        };
        let ev = plan.materialize(7, None).unwrap();
        assert_eq!(ev.seq, 7);
        assert!(ev.prev_hash.is_none());
        assert!(ev.hash.is_some());
        assert_eq!(ev.hash.unwrap().len(), 32);
    }
}
