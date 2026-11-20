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
pub use audit::sha256_runtime_hasher;
#[cfg(feature = "sha2")]
pub use audit::Sha256Hasher;
pub use audit::{
    append_entry, append_entry_continuing, append_entry_with, append_entry_with_continuing,
    append_staged, append_staged_continuing, append_staged_continuing_with, append_staged_with,
    canonical_metadata, chain_head, chain_tail, default_runtime_algorithm, default_runtime_hasher,
    digest, digest_or_raw, digest_or_raw_with, digest_with, filter_by_decision, filter_by_task_id,
    filter_by_tool, find_by_seq, fnv1a_hex, inspect_chain, inspect_chain_with, runtime_hasher,
    stage_entry, stage_entry_continuing, stage_entry_with, stage_entry_with_continuing,
    try_append_entry, try_append_entry_continuing, try_append_entry_with,
    try_append_entry_with_continuing, verify_chain, verify_chain_continuation,
    verify_chain_continuation_state, verify_chain_continuation_state_with,
    verify_chain_continuation_with, verify_chain_detailed, verify_chain_detailed_with,
    verify_chain_range, verify_chain_range_with, verify_chain_state, verify_chain_state_with,
    verify_chain_with, AuditEntry, AuditEventBuilder, AuditHasher, ChainConsistency, ChainState,
    Fnv1a64Hasher, VerifyError, VerifyErrorKind,
};
#[cfg(feature = "cedar")]
pub use policy::cedar_adapter;
pub use policy::{
    budget_decision_hint, call_count_decision_hint, context_hooks, context_hooks_detailed,
    evaluate, rate_limit_decision_hint, Action, ApprovalAnnotation, ArgsHint, BudgetHint,
    CallCountHint, Context, DynamicPolicyEngine, Match, PolicyAuthorizer, PolicyDecision,
    PolicyEngine, PolicyEvaluation, PolicyEvaluationHook, PolicyObligation, PolicyReason,
    PolicyRequest, PolicySource, Principal, RateLimitHint, Resource, Rule, StaticPolicyEngine,
    TaintHint,
};
pub use rate_limit::{
    enforce_into_context, enforce_task_into_context, InMemoryRateLimitTracker, LimitDecision,
    Limits, RateBudgetEnforcer, WindowLimit,
};
pub use taint::{
    EgressPolicy, InMemorySessionTaintStore, NoopTaintHook, OperationTarget, PropagationModel,
    SessionTaint, SessionTaintStore, TaintDecision, TaintEnforcer, TaintFlow, TaintHook,
    TaintLabel, TaintPropagator, TaintSummary, TaintTransition,
};
#[cfg(feature = "biscuit")]
pub use token::biscuit_adapter;
pub use token::{
    Attenuation, Budget, Expiry, InMemoryTokenEngine, InMemoryTokenIssuer, RevocationId,
    RevocationStore, RevocationStoreTokenEngine, Scope, TaskToken, TokenAttenuator, TokenError,
    TokenIssuer, TokenVerifier, VerificationContext, VerificationResult,
};
