//! Durable-store protocol placeholders and transaction semantics notes.
//!
//! These types document intended `sqlx` transaction boundaries for append-before-return
//! audit writes and related persistence operations.

use crate::{compute_audit_hash, AuditEvent, StoreError, StoreResult};

/// Placeholder transaction handle for future sqlx-backed adapters.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
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
    /// Plan append against the current chain tail.
    pub fn for_tail(event: AuditEvent, expected_prev_hash: Option<Vec<u8>>) -> Self {
        Self {
            event,
            expected_prev_hash,
        }
    }

    /// Compute sequence/hash fields for an append operation given prior chain tail.
    /// Fails closed on tail drift, invalid sequence, or missing required fields.
    pub fn materialize(mut self, seq: i64, prev_hash: Option<Vec<u8>>) -> StoreResult<AuditEvent> {
        if seq < 1 {
            return Err(StoreError::Invalid("audit seq must be >= 1".into()));
        }
        if self.expected_prev_hash != prev_hash {
            return Err(StoreError::Conflict(
                "audit prev_hash changed during append planning".into(),
            ));
        }
        self.event.validate_for_append()?;
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

    #[test]
    fn audit_append_plan_fail_closed_on_tail_drift_and_invalid_input() {
        let plan = AuditAppendPlan::for_tail(
            AuditEvent {
                ts: "t".into(),
                decision: "allow".into(),
                ..Default::default()
            },
            Some(vec![1]),
        );
        let err = plan.clone().materialize(2, Some(vec![2])).unwrap_err();
        assert!(matches!(err, StoreError::Conflict(_)));

        let bad = AuditAppendPlan::for_tail(
            AuditEvent {
                ts: "".into(),
                decision: "allow".into(),
                ..Default::default()
            },
            None,
        );
        let err = bad.materialize(1, None).unwrap_err();
        assert!(matches!(err, StoreError::Invalid(_)));
    }
}
