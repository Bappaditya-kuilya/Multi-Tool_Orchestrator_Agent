//! Core primitives for ScopeGate: tokens, policy, audit, taint, and rate limiting.
//!
//! This crate is dependency-free and provides deterministic building blocks for:
//! - capability attenuation and validation (`token`)
//! - deny-by-default policy evaluation with hooks/obligations (`policy`)
//! - hash-chained audit logging (`audit`)
//! - session taint tracking and egress decisions (`taint`)
//! - in-memory rate/budget/call-count enforcement (`rate_limit`)

pub mod audit;
pub mod policy;
pub mod rate_limit;
pub mod taint;
pub mod token;

#[cfg(feature = "sha2")]
pub use audit::digest_sha256;
#[cfg(feature = "sha2")]
pub use audit::Sha256Hasher;
pub use audit::{
    append_entry, append_entry_with, chain_head, chain_tail, default_runtime_hasher, digest,
    digest_or_raw, digest_or_raw_with, digest_with, filter_by_decision, filter_by_task_id,
    filter_by_tool, find_by_seq, fnv1a_hex, inspect_chain, inspect_chain_with, verify_chain,
    verify_chain_detailed, verify_chain_detailed_with, verify_chain_range, verify_chain_range_with,
    verify_chain_with, AuditEntry, AuditEventBuilder, AuditHasher, ChainConsistency, Fnv1a64Hasher,
    VerifyError, VerifyErrorKind,
};
#[cfg(feature = "cedar")]
pub use policy::cedar_adapter;
pub use policy::{
    budget_decision_hint, call_count_decision_hint, context_hooks, context_hooks_detailed,
    evaluate, rate_limit_decision_hint, Action, ApprovalAnnotation, BudgetHint, CallCountHint,
    Context, DynamicPolicyEngine, Match, PolicyAuthorizer, PolicyDecision, PolicyEngine,
    PolicyEvaluation, PolicyEvaluationHook, PolicyObligation, PolicyReason, PolicyRequest,
    PolicySource, Principal, RateLimitHint, Resource, Rule, StaticPolicyEngine, TaintHint,
};
pub use rate_limit::{
    enforce_into_context, InMemoryRateLimitTracker, LimitDecision, Limits, RateBudgetEnforcer,
    WindowLimit,
};
pub use taint::{
    EgressPolicy, InMemorySessionTaintStore, OperationTarget, PropagationModel, SessionTaint,
    SessionTaintStore, TaintDecision, TaintEnforcer, TaintFlow, TaintLabel, TaintPropagator,
    TaintSummary, TaintTransition,
};
#[cfg(feature = "biscuit")]
pub use token::biscuit_adapter;
pub use token::{
    Attenuation, Budget, Expiry, InMemoryTokenEngine, RevocationId, RevocationStore,
    RevocationStoreTokenEngine, Scope, TaskToken, TokenAttenuator, TokenError, TokenVerifier,
    VerificationContext, VerificationResult,
};
