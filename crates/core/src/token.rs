//! Biscuit-oriented task token model (minimal, no external deps).
//!
//! Provides in-memory token data plus small abstraction seams to prepare for
//! `biscuit-auth` integration: attenuation/verification traits and contexts.
//! Current behavior is deterministic and dependency-free (`child ⊆ parent`,
//! expiry/call-budget narrowing, revocation checks).

use std::collections::BTreeSet;

/// Opaque scope identifier granted by a task token.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Scope(pub String);

impl Scope {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_valid(&self) -> bool {
        let s = self.0.trim();
        !s.is_empty() && !s.chars().any(|c| c.is_control()) && !s.chars().any(char::is_whitespace)
    }
}

impl From<&str> for Scope {
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

impl From<String> for Scope {
    fn from(value: String) -> Self {
        Self(value)
    }
}

/// Call-budget limit attached to a token. `max_calls` is interpreted as remaining calls.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Budget {
    /// Remaining number of tool invocations allowed. `None` means unlimited.
    pub max_calls: Option<u32>,
}

impl Budget {
    pub fn limited(max_calls: u32) -> Self {
        Self {
            max_calls: Some(max_calls),
        }
    }

    pub fn unlimited() -> Self {
        Self { max_calls: None }
    }

    pub fn remaining_calls(&self) -> Option<u32> {
        self.max_calls
    }

    pub fn is_exhausted(&self) -> bool {
        matches!(self.max_calls, Some(0))
    }

    pub fn can_consume(&self, n: u32) -> bool {
        match self.max_calls {
            None => true,
            Some(remaining) => remaining >= n,
        }
    }

    pub fn consume(&mut self, n: u32) -> Result<(), TokenError> {
        match self.max_calls {
            None => Ok(()),
            Some(remaining) if remaining >= n => {
                self.max_calls = Some(remaining - n);
                Ok(())
            }
            Some(_) => Err(TokenError::BudgetExhausted),
        }
    }
}

/// Token expiry (unix timestamp seconds). A token is valid only while `now < expires_at`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Expiry(pub u64);

impl Expiry {
    pub fn is_valid_at(&self, now_unix: u64) -> bool {
        now_unix < self.0
    }
}

/// Identifier used to revoke a specific token.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RevocationId(pub String);

impl RevocationId {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_valid(&self) -> bool {
        let s = self.0.trim();
        !s.is_empty()
            && s == self.0
            && !s.chars().any(char::is_control)
            && !s.chars().any(char::is_whitespace)
    }

    pub fn is_revoked_in<'a, I>(&self, revoked_ids: I) -> bool
    where
        I: IntoIterator<Item = &'a str>,
    {
        revoked_ids.into_iter().any(|id| id == self.0)
    }
}

impl From<&str> for RevocationId {
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

impl From<String> for RevocationId {
    fn from(value: String) -> Self {
        Self(value)
    }
}

/// Attenuation record describing narrowed capabilities derived from a parent token.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Attenuation {
    pub scopes: Vec<Scope>,
    pub budget: Budget,
    pub expires_at: Option<Expiry>,
}

/// Placeholder task token representation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskToken {
    pub revocation_id: RevocationId,
    pub scopes: Vec<Scope>,
    pub budget: Budget,
    pub expires_at: Option<Expiry>,
    /// Optional record of the attenuation applied to produce this token.
    pub attenuation: Option<Attenuation>,
}

/// Errors returned by token validation, attenuation, or consumption.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenError {
    EmptyRevocationId,
    Revoked,
    Expired,
    MissingScopes,
    EmptyScope,
    ScopeNotSubset {
        scope: String,
    },
    /// Runtime enforcement denied access for a required scope (fail-closed).
    ScopeDenied {
        scope: String,
    },
    BudgetWidened,
    BudgetExhausted,
    InvalidBudget,
    ExpiryWidened,
    InvalidExpiry,
}

impl std::fmt::Display for TokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyRevocationId => f.write_str("empty revocation id"),
            Self::Revoked => f.write_str("token revoked"),
            Self::Expired => f.write_str("token expired"),
            Self::MissingScopes => f.write_str("missing scopes"),
            Self::EmptyScope => f.write_str("empty scope"),
            Self::ScopeNotSubset { scope } => write!(f, "scope not subset: {scope}"),
            Self::ScopeDenied { scope } => write!(f, "scope denied: {scope}"),
            Self::BudgetWidened => f.write_str("budget widened"),
            Self::BudgetExhausted => f.write_str("budget exhausted"),
            Self::InvalidBudget => f.write_str("invalid budget"),
            Self::ExpiryWidened => f.write_str("expiry widened"),
            Self::InvalidExpiry => f.write_str("invalid expiry"),
        }
    }
}

impl std::error::Error for TokenError {}

impl TaskToken {
    /// Construct a token without attenuation metadata.
    pub fn new(
        revocation_id: impl Into<RevocationId>,
        scopes: Vec<Scope>,
        budget: Budget,
        expires_at: Option<Expiry>,
    ) -> Self {
        Self {
            revocation_id: revocation_id.into(),
            scopes,
            budget,
            expires_at,
            attenuation: None,
        }
    }

    /// Builder: set attenuation metadata (for runtime adapters).
    pub fn with_attenuation(mut self, attenuation: Attenuation) -> Self {
        self.attenuation = Some(attenuation);
        self
    }

    /// Validate structural/token constraints with placeholder revocation checks.
    /// `revoked_ids` contains revocation IDs considered revoked by the caller.
    pub fn validate(&self, now_unix: u64, revoked_ids: &[&str]) -> Result<(), TokenError> {
        if !self.revocation_id.is_valid() {
            return Err(TokenError::EmptyRevocationId);
        }
        if self.is_revoked(revoked_ids) {
            return Err(TokenError::Revoked);
        }
        if self.is_expired(now_unix) {
            return Err(TokenError::Expired);
        }
        validate_scopes(&self.scopes)?;
        // `max_calls: Some(0)` is a valid exhausted budget (not structurally invalid).
        // Consumption attempts fail with `BudgetExhausted`.
        Ok(())
    }

    /// Backward-compatible validity check (no external revocation list, only expiry/id/shape).
    pub fn is_valid(&self, now_unix: u64) -> bool {
        self.validate(now_unix, &[]).is_ok()
    }

    pub fn is_expired(&self, now_unix: u64) -> bool {
        self.expires_at
            .map(|exp| !exp.is_valid_at(now_unix))
            .unwrap_or(false)
    }

    /// Returns `true` if the token grants the requested scope.
    pub fn allows_scope(&self, scope: &str) -> bool {
        self.scopes.iter().any(|s| s.as_str() == scope)
    }

    /// Fail-closed runtime scope enforcement for gateway/tool dispatch paths.
    pub fn require_scope(&self, scope: &str) -> Result<(), TokenError> {
        if self.allows_scope(scope) {
            Ok(())
        } else {
            Err(TokenError::ScopeDenied {
                scope: scope.to_string(),
            })
        }
    }

    /// Fail-closed runtime enforcement that all required scopes are granted.
    pub fn require_all_scopes<'a, I>(&self, scopes: I) -> Result<(), TokenError>
    where
        I: IntoIterator<Item = &'a str>,
    {
        for scope in scopes {
            self.require_scope(scope)?;
        }
        Ok(())
    }

    /// Placeholder revocation check against a caller-provided revoked ID list.
    pub fn is_revoked(&self, revoked_ids: &[&str]) -> bool {
        self.revocation_id
            .is_revoked_in(revoked_ids.iter().copied())
    }

    pub fn remaining_calls(&self) -> Option<u32> {
        self.budget.remaining_calls()
    }

    pub fn can_consume_call(&self) -> bool {
        self.budget.can_consume(1)
    }

    pub fn consume_call(&mut self) -> Result<(), TokenError> {
        self.consume_calls(1)
    }

    pub fn consume_calls(&mut self, n: u32) -> Result<(), TokenError> {
        self.budget.consume(n)
    }

    /// Produce a narrowed child token from this parent token.
    ///
    /// Rules:
    /// - child scopes must be a non-empty subset of parent scopes (`child ⊆ parent`)
    /// - child budget must not be wider than parent remaining budget
    /// - child expiry must not be later than parent expiry
    /// - resulting token must be valid at `now_unix`
    pub fn attenuate(
        &self,
        attenuation: Attenuation,
        child_revocation_id: RevocationId,
        now_unix: u64,
    ) -> Result<Self, TokenError> {
        // Parent must be currently valid to derive from.
        self.validate(now_unix, &[])?;
        if !child_revocation_id.is_valid() {
            return Err(TokenError::EmptyRevocationId);
        }

        validate_scopes(&attenuation.scopes)?;

        let parent_scopes: BTreeSet<&str> = self.scopes.iter().map(|s| s.as_str()).collect();
        for scope in &attenuation.scopes {
            if !parent_scopes.contains(scope.as_str()) {
                return Err(TokenError::ScopeNotSubset {
                    scope: scope.0.clone(),
                });
            }
        }

        let child_budget = attenuate_budget(self.budget, attenuation.budget)?;

        let child_expires_at = match (self.expires_at, attenuation.expires_at) {
            (Some(parent), Some(child)) => {
                if child.0 > parent.0 {
                    return Err(TokenError::ExpiryWidened);
                }
                if !child.is_valid_at(now_unix) {
                    return Err(TokenError::InvalidExpiry);
                }
                Some(child)
            }
            (Some(parent), None) => Some(parent), // keep parent bound
            (None, Some(child)) => {
                if !child.is_valid_at(now_unix) {
                    return Err(TokenError::InvalidExpiry);
                }
                Some(child)
            }
            (None, None) => None,
        };

        // Normalize child scopes to deterministic unique subset order.
        let mut uniq = BTreeSet::new();
        for s in &attenuation.scopes {
            uniq.insert(s.clone());
        }
        let child_scopes: Vec<Scope> = uniq.into_iter().collect();

        let child = TaskToken {
            revocation_id: child_revocation_id,
            scopes: child_scopes,
            budget: child_budget,
            expires_at: child_expires_at,
            attenuation: Some(attenuation),
        };

        child.validate(now_unix, &[])?;
        Ok(child)
    }
}

fn validate_scopes(scopes: &[Scope]) -> Result<(), TokenError> {
    if scopes.is_empty() {
        return Err(TokenError::MissingScopes);
    }
    if scopes.iter().any(|s| !s.is_valid()) {
        return Err(TokenError::EmptyScope);
    }
    Ok(())
}

fn attenuate_budget(parent: Budget, requested: Budget) -> Result<Budget, TokenError> {
    let max_calls = match (parent.max_calls, requested.max_calls) {
        (Some(p), Some(c)) => {
            if c > p {
                return Err(TokenError::BudgetWidened);
            }
            Some(c)
        }
        (Some(p), None) => Some(p), // keep parent bound; None would widen
        (None, Some(c)) => Some(c), // narrowing from unlimited
        (None, None) => None,
    };
    Ok(Budget { max_calls })
}

/// Context for token verification (placeholder for future Biscuit verifier inputs).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VerificationContext<'a> {
    pub now_unix: u64,
    pub revoked_ids: &'a [&'a str],
}

impl<'a> VerificationContext<'a> {
    pub fn new(now_unix: u64, revoked_ids: &'a [&'a str]) -> Self {
        Self {
            now_unix,
            revoked_ids,
        }
    }
}

/// Result of token verification with a validated token value.
pub type VerificationResult<T> = Result<T, TokenError>;

/// Abstraction for verifying serialized/encoded tokens (prepare for `biscuit-auth`).
pub trait TokenVerifier {
    type Token;
    fn verify(
        &self,
        encoded: &str,
        ctx: &VerificationContext<'_>,
    ) -> VerificationResult<Self::Token>;
}

/// Abstraction for attenuating an existing token into a narrower token.
pub trait TokenAttenuator {
    type Token;
    fn attenuate(
        &self,
        parent: &Self::Token,
        attenuation: Attenuation,
        child_revocation_id: RevocationId,
        now_unix: u64,
    ) -> Result<Self::Token, TokenError>;
}

/// Runtime integration hook for revocation checks (in-memory, DB, cache, etc.).
pub trait RevocationStore: Send + Sync {
    fn is_revoked(&self, revocation_id: &str) -> bool;
}

impl RevocationStore for std::collections::HashSet<String> {
    fn is_revoked(&self, revocation_id: &str) -> bool {
        self.contains(revocation_id)
    }
}

impl RevocationStore for std::collections::BTreeSet<String> {
    fn is_revoked(&self, revocation_id: &str) -> bool {
        self.contains(revocation_id)
    }
}

impl RevocationStore for Vec<&str> {
    fn is_revoked(&self, revocation_id: &str) -> bool {
        self.contains(&revocation_id)
    }
}

impl<'a> RevocationStore for &'a [&'a str] {
    fn is_revoked(&self, revocation_id: &str) -> bool {
        self.contains(&revocation_id)
    }
}

impl RevocationStore for Vec<String> {
    fn is_revoked(&self, revocation_id: &str) -> bool {
        self.iter().any(|id| id == revocation_id)
    }
}

impl RevocationStore for [String] {
    fn is_revoked(&self, revocation_id: &str) -> bool {
        self.iter().any(|id| id == revocation_id)
    }
}

impl<T: RevocationStore + ?Sized> RevocationStore for &T {
    fn is_revoked(&self, revocation_id: &str) -> bool {
        (**self).is_revoked(revocation_id)
    }
}

impl<T: RevocationStore + ?Sized> RevocationStore for std::sync::Arc<T> {
    fn is_revoked(&self, revocation_id: &str) -> bool {
        (**self).is_revoked(revocation_id)
    }
}

impl<T: RevocationStore + ?Sized> RevocationStore for Box<T> {
    fn is_revoked(&self, revocation_id: &str) -> bool {
        (**self).is_revoked(revocation_id)
    }
}

/// Pure in-memory verifier/attenuator for `TaskToken` placeholders.
#[derive(Debug, Clone, Copy, Default)]
pub struct InMemoryTokenEngine;

impl TokenVerifier for InMemoryTokenEngine {
    type Token = TaskToken;
    fn verify(
        &self,
        _encoded: &str,
        _ctx: &VerificationContext<'_>,
    ) -> VerificationResult<Self::Token> {
        // No serialized/encoded format for in-memory tokens; fail closed.
        Err(TokenError::Revoked)
    }
}

impl TokenAttenuator for InMemoryTokenEngine {
    type Token = TaskToken;
    fn attenuate(
        &self,
        parent: &Self::Token,
        attenuation: Attenuation,
        child_revocation_id: RevocationId,
        now_unix: u64,
    ) -> Result<Self::Token, TokenError> {
        parent.attenuate(attenuation, child_revocation_id, now_unix)
    }
}

/// Runtime engine that verifies already-materialized tokens against a revocation store.
#[derive(Debug, Clone)]
pub struct RevocationStoreTokenEngine<S> {
    pub store: S,
}

impl<S> RevocationStoreTokenEngine<S> {
    pub fn new(store: S) -> Self {
        Self { store }
    }
}

impl<S: RevocationStore> RevocationStoreTokenEngine<S> {
    pub fn verify_token(&self, token: &TaskToken, now_unix: u64) -> Result<(), TokenError> {
        token.verify_with_store(&self.store, now_unix)
    }

    /// Runtime helper: verify (revocation/expiry/scope shape) then enforce a required scope.
    pub fn verify_token_require_scope(
        &self,
        token: &TaskToken,
        now_unix: u64,
        scope: &str,
    ) -> Result<(), TokenError> {
        self.verify_token(token, now_unix)?;
        token.require_scope(scope)
    }

    /// Runtime helper: verify then enforce all required scopes.
    pub fn verify_token_require_all_scopes<'a, I>(
        &self,
        token: &TaskToken,
        now_unix: u64,
        scopes: I,
    ) -> Result<(), TokenError>
    where
        I: IntoIterator<Item = &'a str>,
    {
        self.verify_token(token, now_unix)?;
        token.require_all_scopes(scopes)
    }

    /// Runtime helper: verify, enforce scope, then consume one call budget unit (fail-closed).
    pub fn verify_require_scope_and_consume_call(
        &self,
        token: &mut TaskToken,
        now_unix: u64,
        scope: &str,
    ) -> Result<(), TokenError> {
        self.verify_token_require_scope(token, now_unix, scope)?;
        token.consume_call()
    }

    /// Runtime helper: verify, enforce scope, then consume `n` call budget units (fail-closed).
    pub fn verify_require_scope_and_consume_calls(
        &self,
        token: &mut TaskToken,
        now_unix: u64,
        scope: &str,
        n: u32,
    ) -> Result<(), TokenError> {
        self.verify_token_require_scope(token, now_unix, scope)?;
        token.consume_calls(n)
    }

    /// Runtime helper: verify, enforce all required scopes, then consume one call budget unit (fail-closed).
    pub fn verify_token_require_all_scopes_and_consume_call<'a, I>(
        &self,
        token: &mut TaskToken,
        now_unix: u64,
        scopes: I,
    ) -> Result<(), TokenError>
    where
        I: IntoIterator<Item = &'a str>,
    {
        self.verify_token_require_all_scopes(token, now_unix, scopes)?;
        token.consume_call()
    }

    pub fn attenuate_token(
        &self,
        parent: &TaskToken,
        attenuation: Attenuation,
        child_revocation_id: RevocationId,
        now_unix: u64,
    ) -> Result<TaskToken, TokenError> {
        self.verify_token(parent, now_unix)?;
        parent.attenuate(attenuation, child_revocation_id, now_unix)
    }
}

/// Abstraction for issuing a materialized token (validated for live gateway/runtime use).
pub trait TokenIssuer {
    type Output;
    fn issue(&self, token: &TaskToken, now_unix: u64) -> Result<Self::Output, TokenError>;
}

/// Default in-memory issuer: validates token shape/revocation context/expiry/budget semantics.
#[derive(Debug, Clone, Copy, Default)]
pub struct InMemoryTokenIssuer;

impl TokenIssuer for InMemoryTokenIssuer {
    type Output = TaskToken;
    fn issue(&self, token: &TaskToken, now_unix: u64) -> Result<Self::Output, TokenError> {
        token.validate(now_unix, &[])?;
        Ok(token.clone())
    }
}

impl TaskToken {
    /// Validate and return a token suitable for issuance/runtime use (no external revocations).
    pub fn issue_validated(self, now_unix: u64) -> Result<Self, TokenError> {
        self.validate(now_unix, &[])?;
        Ok(self)
    }

    /// Verifies this already-materialized token against a context.
    pub fn verify_with(&self, ctx: &VerificationContext<'_>) -> Result<(), TokenError> {
        self.validate(ctx.now_unix, ctx.revoked_ids)
    }

    /// Fail-closed runtime enforcement: verify against context, then require a scope.
    pub fn verify_requiring_scope(
        &self,
        ctx: &VerificationContext<'_>,
        scope: &str,
    ) -> Result<(), TokenError> {
        self.verify_with(ctx)?;
        self.require_scope(scope)
    }

    /// Fail-closed runtime enforcement: verify against context, then require all scopes.
    pub fn verify_requiring_all_scopes<'a, I>(
        &self,
        ctx: &VerificationContext<'_>,
        scopes: I,
    ) -> Result<(), TokenError>
    where
        I: IntoIterator<Item = &'a str>,
    {
        self.verify_with(ctx)?;
        self.require_all_scopes(scopes)
    }

    /// Fail-closed runtime enforcement: verify, require scope, then consume one call.
    pub fn verify_requiring_scope_and_consume_call(
        &mut self,
        ctx: &VerificationContext<'_>,
        scope: &str,
    ) -> Result<(), TokenError> {
        self.verify_requiring_scope(ctx, scope)?;
        self.consume_call()
    }

    /// Fail-closed runtime enforcement: verify, require scope, then consume `n` calls.
    pub fn verify_requiring_scope_and_consume_calls(
        &mut self,
        ctx: &VerificationContext<'_>,
        scope: &str,
        n: u32,
    ) -> Result<(), TokenError> {
        self.verify_requiring_scope(ctx, scope)?;
        self.consume_calls(n)
    }

    /// Fail-closed runtime enforcement: verify, require all scopes, then consume one call.
    pub fn verify_requiring_all_scopes_and_consume_call<'a, I>(
        &mut self,
        ctx: &VerificationContext<'_>,
        scopes: I,
    ) -> Result<(), TokenError>
    where
        I: IntoIterator<Item = &'a str>,
    {
        self.verify_requiring_all_scopes(ctx, scopes)?;
        self.consume_call()
    }

    /// Fail-closed runtime enforcement: verify, require all scopes, then consume `n` calls.
    pub fn verify_requiring_all_scopes_and_consume_calls<'a, I>(
        &mut self,
        ctx: &VerificationContext<'_>,
        scopes: I,
        n: u32,
    ) -> Result<(), TokenError>
    where
        I: IntoIterator<Item = &'a str>,
    {
        self.verify_requiring_all_scopes(ctx, scopes)?;
        self.consume_calls(n)
    }

    /// Verifies against a runtime revocation store integration.
    pub fn verify_with_store<S: RevocationStore + ?Sized>(
        &self,
        store: &S,
        now_unix: u64,
    ) -> Result<(), TokenError> {
        if !self.revocation_id.is_valid() {
            return Err(TokenError::EmptyRevocationId);
        }
        if store.is_revoked(self.revocation_id.as_str()) {
            return Err(TokenError::Revoked);
        }
        if self.is_expired(now_unix) {
            return Err(TokenError::Expired);
        }
        validate_scopes(&self.scopes)
    }

    /// Fail-closed runtime enforcement: verify via revocation store, then require a scope.
    pub fn verify_with_store_requiring_scope<S: RevocationStore + ?Sized>(
        &self,
        store: &S,
        now_unix: u64,
        scope: &str,
    ) -> Result<(), TokenError> {
        self.verify_with_store(store, now_unix)?;
        self.require_scope(scope)
    }

    /// Fail-closed runtime enforcement: verify via revocation store, then require all scopes.
    pub fn verify_with_store_requiring_all_scopes<'a, S, I>(
        &self,
        store: &S,
        now_unix: u64,
        scopes: I,
    ) -> Result<(), TokenError>
    where
        S: RevocationStore + ?Sized,
        I: IntoIterator<Item = &'a str>,
    {
        self.verify_with_store(store, now_unix)?;
        self.require_all_scopes(scopes)
    }

    /// Fail-closed runtime enforcement: verify via revocation store, require scope, then consume one call.
    pub fn verify_with_store_requiring_scope_and_consume_call<S: RevocationStore + ?Sized>(
        &mut self,
        store: &S,
        now_unix: u64,
        scope: &str,
    ) -> Result<(), TokenError> {
        self.verify_with_store_requiring_scope(store, now_unix, scope)?;
        self.consume_call()
    }

    /// Fail-closed runtime enforcement: verify via revocation store, require scope, then consume `n` calls.
    pub fn verify_with_store_requiring_scope_and_consume_calls<S: RevocationStore + ?Sized>(
        &mut self,
        store: &S,
        now_unix: u64,
        scope: &str,
        n: u32,
    ) -> Result<(), TokenError> {
        self.verify_with_store_requiring_scope(store, now_unix, scope)?;
        self.consume_calls(n)
    }

    /// Fail-closed runtime enforcement: verify via revocation store, require all scopes, then consume one call.
    pub fn verify_with_store_requiring_all_scopes_and_consume_call<'a, S, I>(
        &mut self,
        store: &S,
        now_unix: u64,
        scopes: I,
    ) -> Result<(), TokenError>
    where
        S: RevocationStore + ?Sized,
        I: IntoIterator<Item = &'a str>,
    {
        self.verify_with_store_requiring_all_scopes(store, now_unix, scopes)?;
        self.consume_call()
    }

    /// Fail-closed runtime enforcement: verify via revocation store, require all scopes, then consume `n` calls.
    pub fn verify_with_store_requiring_all_scopes_and_consume_calls<'a, S, I>(
        &mut self,
        store: &S,
        now_unix: u64,
        scopes: I,
        n: u32,
    ) -> Result<(), TokenError>
    where
        S: RevocationStore + ?Sized,
        I: IntoIterator<Item = &'a str>,
    {
        self.verify_with_store_requiring_all_scopes(store, now_unix, scopes)?;
        self.consume_calls(n)
    }

    /// Fail-closed call-budget gate (does not consume).
    pub fn require_calls_available(&self, n: u32) -> Result<(), TokenError> {
        if self.budget.can_consume(n) {
            Ok(())
        } else {
            Err(TokenError::BudgetExhausted)
        }
    }

    /// Attenuate after verifying the parent against an explicit revocation/context (fail-closed).
    pub fn attenuate_verified(
        &self,
        attenuation: Attenuation,
        child_revocation_id: RevocationId,
        ctx: &VerificationContext<'_>,
    ) -> Result<Self, TokenError> {
        self.verify_with(ctx)?;
        self.attenuate(attenuation, child_revocation_id, ctx.now_unix)
    }

    /// Attenuate after verifying the parent against a revocation store (fail-closed).
    pub fn attenuate_with_store<S: RevocationStore + ?Sized>(
        &self,
        store: &S,
        attenuation: Attenuation,
        child_revocation_id: RevocationId,
        now_unix: u64,
    ) -> Result<Self, TokenError> {
        self.verify_with_store(store, now_unix)?;
        self.attenuate(attenuation, child_revocation_id, now_unix)
    }

    /// Maps the current effective token budget to a policy call-count hint.
    /// `calls_made` represents calls already consumed in the runtime session.
    pub fn call_count_hint(&self, calls_made: u32) -> crate::policy::CallCountHint {
        crate::policy::CallCountHint {
            count: calls_made,
            limit: self.remaining_calls(),
            exceeded: self
                .remaining_calls()
                .is_some_and(|limit| calls_made >= limit),
        }
        .normalize()
    }

    /// Maps a runtime-consumed budget amount to a policy budget hint.
    /// Useful for integrations that account usage/cost units separately from token call limits.
    pub fn budget_hint(&self, used: u64, limit: u64) -> crate::policy::BudgetHint {
        crate::policy::BudgetHint {
            used,
            limit,
            exceeded: used >= limit,
        }
        .normalize()
    }
}

/// Feature-gated Biscuit adapter hooks for runtime integrations.
/// Implementations can bridge `biscuit-auth` parsing/attenuation without
/// forcing the dependency in default builds.
#[cfg(feature = "biscuit")]
pub mod biscuit_adapter {
    use super::{
        validate_scopes, Attenuation, Budget, Expiry, RevocationId, Scope, TaskToken, TokenError,
        TokenVerifier, VerificationContext, VerificationResult,
    };
    use std::collections::BTreeSet;

    /// Hook for parsing/verifying Biscuit-encoded tokens into runtime tokens.
    pub trait BiscuitTokenVerifier {
        fn verify_biscuit(
            &self,
            encoded: &str,
            ctx: &VerificationContext<'_>,
        ) -> Result<TaskToken, TokenError>;
    }

    /// Hook for attenuating Biscuit-backed tokens via runtime integrations.
    pub trait BiscuitTokenAttenuator {
        fn attenuate_biscuit(
            &self,
            parent_encoded: &str,
            attenuation: Attenuation,
            child_revocation_id: RevocationId,
            now_unix: u64,
        ) -> Result<String, TokenError>;
    }

    /// Minimal Biscuit-backed token engine for ScopeGate task tokens.
    ///
    /// Mapping (encoded as signed Biscuit facts/checks, latest SG block wins):
    /// - scopes: `sg_scope("<scope>")` facts
    /// - budget: `sg_budget(<n>)` or `sg_budget_unlimited(true)`
    /// - expiry: `sg_expiry(<unix>)` fact and `check if time($time), $time < <RFC3339>`
    /// - revocation: `sg_revocation_id("<id>")` fact; checked against `VerificationContext`
    ///
    /// Limitations: ScopeGate claim extraction is convention-based (not pure Datalog authority),
    /// attenuation enforces narrowing in Rust before appending a signed block, and call-budget
    /// consumption remains runtime state (initial/effective limit is encoded).
    pub struct BiscuitTokenEngine {
        root_public_key: biscuit_auth::PublicKey,
        keypair: Option<biscuit_auth::KeyPair>,
    }

    impl std::fmt::Debug for BiscuitTokenEngine {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("BiscuitTokenEngine")
                .field("can_sign", &self.keypair.is_some())
                .finish_non_exhaustive()
        }
    }

    impl BiscuitTokenEngine {
        pub fn new(keypair: biscuit_auth::KeyPair) -> Self {
            Self {
                root_public_key: keypair.public(),
                keypair: Some(keypair),
            }
        }

        /// Verify/attenuate-only engine for deployments that must not hold the root signing key.
        /// `issue` fails closed without a signer; attenuation and verification use the root public key.
        pub fn verifier(root_public_key: biscuit_auth::PublicKey) -> Self {
            Self {
                root_public_key,
                keypair: None,
            }
        }

        pub fn root_public_key(&self) -> biscuit_auth::PublicKey {
            self.root_public_key
        }

        pub fn can_sign(&self) -> bool {
            self.keypair.is_some()
        }

        /// Create and serialize a Biscuit token representing `token`.
        /// Fails closed if the engine has no signing key.
        pub fn issue(&self, token: &TaskToken) -> Result<String, TokenError> {
            let keypair = self.keypair.as_ref().ok_or(TokenError::Revoked)?;
            if !token.revocation_id.is_valid() {
                return Err(TokenError::EmptyRevocationId);
            }
            validate_scopes(&token.scopes)?;
            let normalized_scopes = normalize_scopes(&token.scopes);
            let code = render_claims(
                token.revocation_id.as_str(),
                &normalized_scopes,
                token.budget,
                token.expires_at,
                true,
            );
            let mut builder = biscuit_auth::Biscuit::builder();
            builder.add_code(code).map_err(|_| TokenError::Revoked)?;
            let biscuit = builder.build(keypair).map_err(|_| TokenError::Revoked)?;
            biscuit.to_base64().map_err(|_| TokenError::Revoked)
        }

        /// Verify/parse a Biscuit token and extract ScopeGate claims.
        pub fn verify(
            &self,
            encoded: &str,
            ctx: &VerificationContext<'_>,
        ) -> Result<TaskToken, TokenError> {
            let biscuit = biscuit_auth::Biscuit::from_base64(encoded, self.root_public_key)
                .map_err(|_| TokenError::Revoked)?;

            if let Err(e) = authorize_with_time(&biscuit, ctx.now_unix) {
                // If signed token is otherwise readable, prefer precise expiry/revocation mapping.
                if let Ok(claims) = extract_sg_claims(&biscuit) {
                    if claims
                        .expires_at
                        .map(|e| !e.is_valid_at(ctx.now_unix))
                        .unwrap_or(false)
                    {
                        return Err(TokenError::Expired);
                    }
                    if ctx.revoked_ids.contains(&claims.revocation_id.as_str()) {
                        return Err(TokenError::Revoked);
                    }
                }
                return Err(map_biscuit_error(e));
            }

            let claims = extract_sg_claims(&biscuit)?;
            let token = TaskToken::new(
                claims.revocation_id,
                claims.scopes,
                claims.budget,
                claims.expires_at,
            );
            token.verify_with(ctx)?;
            Ok(token)
        }

        /// Verify/parse a Biscuit token and check revocation via a runtime store.
        /// Fails closed on parse/signature/expiry errors and store revocations.
        pub fn verify_with_store<S: super::RevocationStore + ?Sized>(
            &self,
            encoded: &str,
            store: &S,
            now_unix: u64,
        ) -> Result<TaskToken, TokenError> {
            let biscuit = biscuit_auth::Biscuit::from_base64(encoded, self.root_public_key)
                .map_err(|_| TokenError::Revoked)?;

            if let Err(e) = authorize_with_time(&biscuit, now_unix) {
                if let Ok(claims) = extract_sg_claims(&biscuit) {
                    if claims
                        .expires_at
                        .map(|e| !e.is_valid_at(now_unix))
                        .unwrap_or(false)
                    {
                        return Err(TokenError::Expired);
                    }
                    if store.is_revoked(claims.revocation_id.as_str()) {
                        return Err(TokenError::Revoked);
                    }
                }
                return Err(map_biscuit_error(e));
            }

            let claims = extract_sg_claims(&biscuit)?;
            let token = TaskToken::new(
                claims.revocation_id,
                claims.scopes,
                claims.budget,
                claims.expires_at,
            );
            token.verify_with_store(store, now_unix)?;
            Ok(token)
        }

        /// Attenuate a Biscuit token by appending a narrowed SG claims block.
        /// Parent is verified with an empty revocation list for backward compatibility;
        /// use `attenuate_with_revoked` for external revocation checks.
        pub fn attenuate(
            &self,
            parent_encoded: &str,
            attenuation: Attenuation,
            child_revocation_id: RevocationId,
            now_unix: u64,
        ) -> Result<String, TokenError> {
            self.attenuate_with_revoked(
                parent_encoded,
                attenuation,
                child_revocation_id,
                now_unix,
                &[],
            )
        }

        /// Attenuate a Biscuit token while checking parent revocation against caller-provided IDs.
        pub fn attenuate_with_revoked(
            &self,
            parent_encoded: &str,
            attenuation: Attenuation,
            child_revocation_id: RevocationId,
            now_unix: u64,
            revoked_ids: &[&str],
        ) -> Result<String, TokenError> {
            let ctx = VerificationContext::new(now_unix, revoked_ids);
            let parent = self.verify(parent_encoded, &ctx)?;
            let child = parent.attenuate(attenuation, child_revocation_id, now_unix)?;
            let biscuit = biscuit_auth::Biscuit::from_base64(parent_encoded, self.root_public_key)
                .map_err(|_| TokenError::Revoked)?;
            let mut block = biscuit_auth::builder::BlockBuilder::new();
            let code = render_claims(
                child.revocation_id.as_str(),
                &child.scopes,
                child.budget,
                child.expires_at,
                true,
            );
            block
                .add_code(code)
                .map_err(|_| TokenError::InvalidBudget)?;
            let attenuated = biscuit.append(block).map_err(|_| TokenError::Revoked)?;
            attenuated.to_base64().map_err(|_| TokenError::Revoked)
        }

        /// Attenuate a Biscuit token while checking parent revocation via a runtime store.
        pub fn attenuate_with_store<S: super::RevocationStore + ?Sized>(
            &self,
            parent_encoded: &str,
            attenuation: Attenuation,
            child_revocation_id: RevocationId,
            store: &S,
            now_unix: u64,
        ) -> Result<String, TokenError> {
            let parent = self.verify_with_store(parent_encoded, store, now_unix)?;
            let child = parent.attenuate(attenuation, child_revocation_id, now_unix)?;
            let biscuit = biscuit_auth::Biscuit::from_base64(parent_encoded, self.root_public_key)
                .map_err(|_| TokenError::Revoked)?;
            let mut block = biscuit_auth::builder::BlockBuilder::new();
            let code = render_claims(
                child.revocation_id.as_str(),
                &child.scopes,
                child.budget,
                child.expires_at,
                true,
            );
            block
                .add_code(code)
                .map_err(|_| TokenError::InvalidBudget)?;
            let attenuated = biscuit.append(block).map_err(|_| TokenError::Revoked)?;
            attenuated.to_base64().map_err(|_| TokenError::Revoked)
        }

        /// Runtime helper (gateway): verify encoded token and enforce a required scope.
        pub fn verify_enforcing_scope(
            &self,
            encoded: &str,
            ctx: &VerificationContext<'_>,
            scope: &str,
        ) -> Result<TaskToken, TokenError> {
            let token = self.verify(encoded, ctx)?;
            token.require_scope(scope)?;
            Ok(token)
        }

        /// Runtime helper (gateway): verify encoded token and enforce all required scopes.
        pub fn verify_enforcing_all_scopes<'a, I>(
            &self,
            encoded: &str,
            ctx: &VerificationContext<'_>,
            scopes: I,
        ) -> Result<TaskToken, TokenError>
        where
            I: IntoIterator<Item = &'a str>,
        {
            let token = self.verify(encoded, ctx)?;
            token.require_all_scopes(scopes)?;
            Ok(token)
        }

        /// Runtime helper (gateway): verify against revocation store and enforce a required scope.
        pub fn verify_with_store_enforcing_scope<S: super::RevocationStore + ?Sized>(
            &self,
            encoded: &str,
            store: &S,
            now_unix: u64,
            scope: &str,
        ) -> Result<TaskToken, TokenError> {
            let token = self.verify_with_store(encoded, store, now_unix)?;
            token.require_scope(scope)?;
            Ok(token)
        }

        /// Runtime helper (gateway): verify against revocation store and enforce all required scopes.
        pub fn verify_with_store_enforcing_all_scopes<'a, S, I>(
            &self,
            encoded: &str,
            store: &S,
            now_unix: u64,
            scopes: I,
        ) -> Result<TaskToken, TokenError>
        where
            S: super::RevocationStore + ?Sized,
            I: IntoIterator<Item = &'a str>,
        {
            let token = self.verify_with_store(encoded, store, now_unix)?;
            token.require_all_scopes(scopes)?;
            Ok(token)
        }

        /// Runtime helper (gateway): verify, enforce scope, and fail-closed on exhausted call budget.
        /// Note: call-budget consumption is runtime state on the returned token.
        pub fn verify_with_store_enforcing_scope_and_budget<S: super::RevocationStore + ?Sized>(
            &self,
            encoded: &str,
            store: &S,
            now_unix: u64,
            scope: &str,
            calls: u32,
        ) -> Result<TaskToken, TokenError> {
            let token = self.verify_with_store_enforcing_scope(encoded, store, now_unix, scope)?;
            token.require_calls_available(calls)?;
            Ok(token)
        }

        /// Key-handling hook: verify an encoded token using any accepted root public key.
        /// Fails closed if no key verifies (or if revocation/expiry/scope checks fail).
        pub fn verify_with_any_root_key<I>(
            encoded: &str,
            ctx: &VerificationContext<'_>,
            root_public_keys: I,
        ) -> Result<TaskToken, TokenError>
        where
            I: IntoIterator<Item = biscuit_auth::PublicKey>,
        {
            let mut saw_key = false;
            for root_public_key in root_public_keys {
                saw_key = true;
                let engine = Self::verifier(root_public_key);
                match engine.verify(encoded, ctx) {
                    Ok(token) => return Ok(token),
                    Err(TokenError::Revoked) => continue,
                    Err(e) => return Err(e),
                }
            }
            if saw_key {
                Err(TokenError::Revoked)
            } else {
                Err(TokenError::Revoked)
            }
        }

        /// Key-handling hook: verify an encoded token using any accepted root public key and a revocation store.
        /// Fails closed if no key verifies.
        pub fn verify_with_store_any_root_key<I, S>(
            encoded: &str,
            store: &S,
            now_unix: u64,
            root_public_keys: I,
        ) -> Result<TaskToken, TokenError>
        where
            I: IntoIterator<Item = biscuit_auth::PublicKey>,
            S: super::RevocationStore + ?Sized,
        {
            let mut saw_key = false;
            for root_public_key in root_public_keys {
                saw_key = true;
                let engine = Self::verifier(root_public_key);
                match engine.verify_with_store(encoded, store, now_unix) {
                    Ok(token) => return Ok(token),
                    Err(TokenError::Revoked) => continue,
                    Err(e) => return Err(e),
                }
            }
            let _ = saw_key;
            Err(TokenError::Revoked)
        }

        /// Key-handling hook: verify with any accepted root key, enforce scope, and fail closed.
        pub fn verify_with_store_enforcing_scope_any_root_key<I, S>(
            encoded: &str,
            store: &S,
            now_unix: u64,
            scope: &str,
            root_public_keys: I,
        ) -> Result<TaskToken, TokenError>
        where
            I: IntoIterator<Item = biscuit_auth::PublicKey>,
            S: super::RevocationStore + ?Sized,
        {
            let token =
                Self::verify_with_store_any_root_key(encoded, store, now_unix, root_public_keys)?;
            token.require_scope(scope)?;
            Ok(token)
        }
    }

    impl TokenVerifier for BiscuitTokenEngine {
        type Token = TaskToken;
        fn verify(
            &self,
            encoded: &str,
            ctx: &VerificationContext<'_>,
        ) -> VerificationResult<Self::Token> {
            BiscuitTokenEngine::verify(self, encoded, ctx)
        }
    }

    impl BiscuitTokenVerifier for BiscuitTokenEngine {
        fn verify_biscuit(
            &self,
            encoded: &str,
            ctx: &VerificationContext<'_>,
        ) -> Result<TaskToken, TokenError> {
            BiscuitTokenEngine::verify(self, encoded, ctx)
        }
    }

    impl BiscuitTokenAttenuator for BiscuitTokenEngine {
        fn attenuate_biscuit(
            &self,
            parent_encoded: &str,
            attenuation: Attenuation,
            child_revocation_id: RevocationId,
            now_unix: u64,
        ) -> Result<String, TokenError> {
            BiscuitTokenEngine::attenuate(
                self,
                parent_encoded,
                attenuation,
                child_revocation_id,
                now_unix,
            )
        }
    }

    /// Issuer abstraction for Biscuit-encoded task tokens (fail-closed).
    impl super::TokenIssuer for BiscuitTokenEngine {
        type Output = String;
        fn issue(
            &self,
            token: &super::TaskToken,
            _now_unix: u64,
        ) -> Result<Self::Output, super::TokenError> {
            BiscuitTokenEngine::issue(self, token)
        }
    }

    #[derive(Debug, Clone)]
    struct ExtractedClaims {
        revocation_id: RevocationId,
        scopes: Vec<Scope>,
        budget: Budget,
        expires_at: Option<Expiry>,
    }

    fn authorize_with_time(
        biscuit: &biscuit_auth::Biscuit,
        now_unix: u64,
    ) -> Result<(), biscuit_auth::error::Token> {
        let mut authorizer = biscuit.authorizer()?;
        // Ambient time for expiry checks: `check if time($time), $time < expiry`.
        authorizer.add_code(format!(
            "time({});\nallow if true;",
            unix_secs_to_rfc3339(now_unix)
        ))?;
        authorizer.authorize()?;
        Ok(())
    }

    fn map_biscuit_error(_e: biscuit_auth::error::Token) -> TokenError {
        // Fail closed. Specific mappings are refined by extracted claims when available.
        TokenError::Revoked
    }

    fn normalize_scopes(scopes: &[Scope]) -> Vec<Scope> {
        let mut uniq = BTreeSet::new();
        for s in scopes {
            uniq.insert(s.clone());
        }
        uniq.into_iter().collect()
    }

    fn escape_datalog_string(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        for c in s.chars() {
            match c {
                '\\' => out.push_str("\\\\"),
                '"' => out.push_str("\\\""),
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                '\t' => out.push_str("\\t"),
                _ => out.push(c),
            }
        }
        out
    }

    fn render_claims(
        revocation_id: &str,
        scopes: &[Scope],
        budget: Budget,
        expires_at: Option<Expiry>,
        include_expiry_check: bool,
    ) -> String {
        let mut code = String::new();
        code.push_str("sg_claims(\"v1\");\n");
        code.push_str(&format!(
            "sg_revocation_id(\"{}\");\n",
            escape_datalog_string(revocation_id)
        ));
        for scope in scopes {
            code.push_str(&format!(
                "sg_scope(\"{}\");\n",
                escape_datalog_string(scope.as_str())
            ));
        }
        match budget.max_calls {
            Some(n) => code.push_str(&format!("sg_budget({n});\n")),
            None => code.push_str("sg_budget_unlimited(true);\n"),
        }
        if let Some(exp) = expires_at {
            code.push_str(&format!("sg_expiry({});\n", exp.0));
            if include_expiry_check {
                // Match TaskToken semantics: valid while now < expires_at.
                code.push_str(&format!(
                    "check if time($time), $time < {};\n",
                    unix_secs_to_rfc3339(exp.0)
                ));
            }
        }
        code
    }

    fn extract_sg_claims(biscuit: &biscuit_auth::Biscuit) -> Result<ExtractedClaims, TokenError> {
        // Prefer the latest block containing SG claims (attenuation appends a new block).
        let count = biscuit.block_count();
        for idx in (0..count).rev() {
            let src = biscuit
                .print_block_source(idx)
                .map_err(|_| TokenError::Revoked)?;
            if src.contains("sg_claims(\"v1\")") {
                return parse_claims_from_source(&src);
            }
        }
        Err(TokenError::MissingScopes)
    }

    fn parse_claims_from_source(src: &str) -> Result<ExtractedClaims, TokenError> {
        let mut revocation_id: Option<String> = None;
        let mut scopes: Vec<Scope> = Vec::new();
        let mut budget: Option<Budget> = None;
        let mut expires_at: Option<Expiry> = None;
        let mut saw_claims = false;

        for raw_line in src.lines() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with("//") || line.starts_with("check if ") {
                continue;
            }
            let Some(stmt) = line.strip_suffix(';') else {
                continue;
            };
            let stmt = stmt.trim();
            if stmt == "sg_claims(\"v1\")" {
                saw_claims = true;
                continue;
            }
            if let Some(v) = parse_string_fact(stmt, "sg_revocation_id") {
                revocation_id = Some(v);
                continue;
            }
            if let Some(v) = parse_string_fact(stmt, "sg_scope") {
                scopes.push(Scope::new(v));
                continue;
            }
            if let Some(v) = parse_int_fact(stmt, "sg_budget") {
                if v < 0 {
                    return Err(TokenError::InvalidBudget);
                }
                budget = Some(Budget::limited(v as u32));
                continue;
            }
            if stmt == "sg_budget_unlimited(true)" {
                budget = Some(Budget::unlimited());
                continue;
            }
            if let Some(v) = parse_int_fact(stmt, "sg_expiry") {
                if v < 0 {
                    return Err(TokenError::InvalidExpiry);
                }
                expires_at = Some(Expiry(v as u64));
                continue;
            }
        }

        if !saw_claims {
            return Err(TokenError::MissingScopes);
        }
        let revocation_id = RevocationId::new(revocation_id.ok_or(TokenError::EmptyRevocationId)?);
        if !revocation_id.is_valid() {
            return Err(TokenError::EmptyRevocationId);
        }
        if scopes.is_empty() {
            return Err(TokenError::MissingScopes);
        }
        // Preserve canonical subset ordering as in TaskToken::attenuate.
        let mut uniq = BTreeSet::new();
        for s in scopes {
            uniq.insert(s);
        }
        let scopes: Vec<Scope> = uniq.into_iter().collect();
        if scopes.iter().any(|s| !s.is_valid()) {
            return Err(TokenError::EmptyScope);
        }
        let budget = budget.ok_or(TokenError::InvalidBudget)?;

        Ok(ExtractedClaims {
            revocation_id,
            scopes,
            budget,
            expires_at,
        })
    }

    fn unix_secs_to_rfc3339(secs: u64) -> String {
        // Civil date from days since 1970-01-01 (UTC), seconds precision.
        let days = secs / 86_400;
        let sod = secs % 86_400;
        let hour = sod / 3_600;
        let minute = (sod % 3_600) / 60;
        let second = sod % 60;

        let z = days as i64 + 719_468;
        let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
        let doe = z - era * 146_097;
        let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
        let mut year = yoe + era * 400;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let day = doy - (153 * mp + 2) / 5 + 1;
        let month = if mp < 10 { mp + 3 } else { mp - 9 };
        if month <= 2 {
            year += 1;
        }

        format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
    }

    fn parse_string_fact(stmt: &str, name: &str) -> Option<String> {
        let prefix = format!("{name}(\"");
        let suffix = "\")";
        if !(stmt.starts_with(&prefix) && stmt.ends_with(suffix)) {
            return None;
        }
        let inner = &stmt[prefix.len()..stmt.len() - suffix.len()];
        unescape_datalog_string(inner)
    }

    fn unescape_datalog_string(s: &str) -> Option<String> {
        let mut out = String::with_capacity(s.len());
        let mut chars = s.chars();
        while let Some(c) = chars.next() {
            if c == '\\' {
                let n = chars.next()?;
                match n {
                    '\\' => out.push('\\'),
                    '"' => out.push('"'),
                    'n' => out.push('\n'),
                    'r' => out.push('\r'),
                    't' => out.push('\t'),
                    _ => return None,
                }
            } else {
                out.push(c);
            }
        }
        Some(out)
    }

    fn parse_int_fact(stmt: &str, name: &str) -> Option<i64> {
        let prefix = format!("{name}(");
        if !(stmt.starts_with(&prefix) && stmt.ends_with(')')) {
            return None;
        }
        let inner = stmt[prefix.len()..stmt.len() - 1].trim();
        inner.parse::<i64>().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parent_token() -> TaskToken {
        TaskToken {
            revocation_id: RevocationId::new("parent-rev"),
            scopes: vec![Scope::new("tool:read"), Scope::new("tool:write")],
            budget: Budget {
                max_calls: Some(10),
            },
            expires_at: Some(Expiry(1_000)),
            attenuation: None,
        }
    }

    #[test]
    fn token_smoke_valid_when_revocation_present() {
        let token = TaskToken {
            revocation_id: RevocationId::new("rev-1"),
            scopes: vec![Scope::new("tool:read")],
            budget: Budget { max_calls: Some(1) },
            expires_at: Some(Expiry(1)),
            attenuation: None,
        };
        assert!(token.is_valid(0));
    }

    #[test]
    fn validate_rejects_empty_revocation_expired_and_revoked() {
        let empty = TaskToken {
            revocation_id: RevocationId::new(""),
            scopes: vec![Scope::new("a")],
            budget: Budget::default(),
            expires_at: None,
            attenuation: None,
        };
        assert_eq!(empty.validate(0, &[]), Err(TokenError::EmptyRevocationId));
        let ws = TaskToken {
            revocation_id: RevocationId::new("   "),
            ..empty.clone()
        };
        assert_eq!(ws.validate(0, &[]), Err(TokenError::EmptyRevocationId));

        let expired = TaskToken {
            expires_at: Some(Expiry(10)),
            ..parent_token()
        };
        assert_eq!(expired.validate(10, &[]), Err(TokenError::Expired));
        assert_eq!(expired.validate(11, &[]), Err(TokenError::Expired));

        let revoked = parent_token();
        assert!(revoked.is_revoked(&["parent-rev", "other"]));
        assert_eq!(
            revoked.validate(0, &["parent-rev"]),
            Err(TokenError::Revoked)
        );
        assert!(!revoked.is_revoked(&["other-rev"]));
    }

    #[test]
    fn validate_rejects_empty_scope_entries_and_requires_scopes() {
        let missing = TaskToken {
            scopes: vec![],
            ..parent_token()
        };
        assert_eq!(missing.validate(0, &[]), Err(TokenError::MissingScopes));

        let empty_scope = TaskToken {
            scopes: vec![Scope::new("tool:read"), Scope::new("  ")],
            ..parent_token()
        };
        assert_eq!(empty_scope.validate(0, &[]), Err(TokenError::EmptyScope));
    }

    #[test]
    fn budget_consume_tracks_remaining_and_exhausts() {
        let mut token = TaskToken {
            budget: Budget::limited(2),
            ..parent_token()
        };
        assert_eq!(token.remaining_calls(), Some(2));
        assert!(token.can_consume_call());
        token.consume_call().expect("first call");
        assert_eq!(token.remaining_calls(), Some(1));
        token.consume_calls(1).expect("second call");
        assert_eq!(token.remaining_calls(), Some(0));
        assert!(!token.can_consume_call());
        assert_eq!(token.consume_call(), Err(TokenError::BudgetExhausted));
        assert_eq!(token.consume_calls(2), Err(TokenError::BudgetExhausted));

        let mut unlimited = TaskToken {
            budget: Budget::unlimited(),
            ..parent_token()
        };
        assert_eq!(unlimited.remaining_calls(), None);
        unlimited
            .consume_calls(100)
            .expect("unlimited never exhausts");
        assert_eq!(unlimited.remaining_calls(), None);
    }

    #[test]
    fn attenuate_narrows_scopes_budget_and_expiry() {
        let parent = parent_token();
        let child = parent
            .attenuate(
                Attenuation {
                    scopes: vec![Scope::new("tool:read")],
                    budget: Budget { max_calls: Some(3) },
                    expires_at: Some(Expiry(500)),
                },
                RevocationId::new("child-rev"),
                0,
            )
            .expect("narrow attenuation should succeed");

        assert_eq!(child.revocation_id, RevocationId::new("child-rev"));
        assert_eq!(child.scopes, vec![Scope::new("tool:read")]);
        assert_eq!(child.budget.max_calls, Some(3));
        assert_eq!(child.expires_at, Some(Expiry(500)));
        assert!(child.attenuation.is_some());
        assert!(child.allows_scope("tool:read"));
        assert!(!child.allows_scope("tool:write"));
    }

    #[test]
    fn attenuate_cannot_widen_scopes() {
        let parent = parent_token();
        let err = parent
            .attenuate(
                Attenuation {
                    scopes: vec![Scope::new("tool:read"), Scope::new("tool:admin")],
                    budget: Budget { max_calls: Some(1) },
                    expires_at: Some(Expiry(500)),
                },
                RevocationId::new("child-rev"),
                0,
            )
            .unwrap_err();
        assert_eq!(
            err,
            TokenError::ScopeNotSubset {
                scope: "tool:admin".to_string()
            }
        );
    }

    #[test]
    fn attenuate_cannot_widen_budget_or_expiry() {
        let parent = parent_token();

        let budget_err = parent
            .attenuate(
                Attenuation {
                    scopes: vec![Scope::new("tool:read")],
                    budget: Budget {
                        max_calls: Some(11),
                    },
                    expires_at: Some(Expiry(500)),
                },
                RevocationId::new("child-rev"),
                0,
            )
            .unwrap_err();
        assert_eq!(budget_err, TokenError::BudgetWidened);

        let expiry_err = parent
            .attenuate(
                Attenuation {
                    scopes: vec![Scope::new("tool:read")],
                    budget: Budget { max_calls: Some(1) },
                    expires_at: Some(Expiry(1_001)),
                },
                RevocationId::new("child-rev"),
                0,
            )
            .unwrap_err();
        assert_eq!(expiry_err, TokenError::ExpiryWidened);

        let unlimited_parent = TaskToken {
            budget: Budget { max_calls: None },
            expires_at: None,
            ..parent_token()
        };
        let child = unlimited_parent
            .attenuate(
                Attenuation {
                    scopes: vec![Scope::new("tool:read")],
                    budget: Budget { max_calls: Some(5) },
                    expires_at: Some(Expiry(500)),
                },
                RevocationId::new("child-rev"),
                0,
            )
            .expect("can narrow from unlimited/unbounded");
        assert_eq!(child.budget.max_calls, Some(5));
        assert_eq!(child.expires_at, Some(Expiry(500)));
    }

    #[test]
    fn attenuate_chain_preserves_narrowing_and_blocks_widening() {
        let mut root = parent_token();
        root.consume_calls(3).expect("consume parent budget");
        assert_eq!(root.remaining_calls(), Some(7));

        let child = root
            .attenuate(
                Attenuation {
                    scopes: vec![Scope::new("tool:read"), Scope::new("tool:write")],
                    budget: Budget::limited(5),
                    expires_at: Some(Expiry(800)),
                },
                RevocationId::new("child"),
                0,
            )
            .expect("narrow from remaining");
        assert_eq!(child.remaining_calls(), Some(5));

        let grandchild = child
            .attenuate(
                Attenuation {
                    scopes: vec![Scope::new("tool:read")],
                    budget: Budget::limited(2),
                    expires_at: Some(Expiry(400)),
                },
                RevocationId::new("grandchild"),
                0,
            )
            .expect("chain narrows");
        assert_eq!(grandchild.scopes, vec![Scope::new("tool:read")]);
        assert_eq!(grandchild.remaining_calls(), Some(2));
        assert_eq!(grandchild.expires_at, Some(Expiry(400)));

        let widen_budget = grandchild.attenuate(
            Attenuation {
                scopes: vec![Scope::new("tool:read")],
                budget: Budget::limited(3),
                expires_at: Some(Expiry(400)),
            },
            RevocationId::new("bad"),
            0,
        );
        assert_eq!(widen_budget, Err(TokenError::BudgetWidened));

        let widen_scope = grandchild.attenuate(
            Attenuation {
                scopes: vec![Scope::new("tool:write")],
                budget: Budget::limited(1),
                expires_at: Some(Expiry(400)),
            },
            RevocationId::new("bad"),
            0,
        );
        assert_eq!(
            widen_scope,
            Err(TokenError::ScopeNotSubset {
                scope: "tool:write".into()
            })
        );
    }

    #[test]
    fn attenuate_rejects_empty_or_invalid_scopes_child_revocation_and_expiry() {
        let parent = parent_token();
        assert_eq!(
            parent.attenuate(
                Attenuation {
                    scopes: vec![],
                    budget: Budget { max_calls: Some(1) },
                    expires_at: Some(Expiry(500))
                },
                RevocationId::new("child-rev"),
                0,
            ),
            Err(TokenError::MissingScopes)
        );
        assert_eq!(
            parent.attenuate(
                Attenuation {
                    scopes: vec![Scope::new("")],
                    budget: Budget { max_calls: Some(1) },
                    expires_at: Some(Expiry(500))
                },
                RevocationId::new("child-rev"),
                0,
            ),
            Err(TokenError::EmptyScope)
        );
        assert_eq!(
            parent.attenuate(
                Attenuation {
                    scopes: vec![Scope::new("tool:read")],
                    budget: Budget { max_calls: Some(1) },
                    expires_at: Some(Expiry(500))
                },
                RevocationId::new(""),
                0,
            ),
            Err(TokenError::EmptyRevocationId)
        );
        assert_eq!(
            parent.attenuate(
                Attenuation {
                    scopes: vec![Scope::new("tool:read")],
                    budget: Budget { max_calls: Some(1) },
                    expires_at: Some(Expiry(0))
                },
                RevocationId::new("child-rev"),
                0,
            ),
            Err(TokenError::InvalidExpiry)
        );
        assert_eq!(
            parent.attenuate(
                Attenuation {
                    scopes: vec![Scope::new("tool:read")],
                    budget: Budget { max_calls: Some(1) },
                    expires_at: Some(Expiry(100))
                },
                RevocationId::new("child-rev"),
                100,
            ),
            Err(TokenError::InvalidExpiry)
        );
    }

    #[test]
    fn attenuate_keeps_parent_bounds_when_request_omits_them() {
        let parent = parent_token();
        let child = parent
            .attenuate(
                Attenuation {
                    scopes: vec![Scope::new("tool:write"), Scope::new("tool:write")],
                    budget: Budget { max_calls: None },
                    expires_at: None,
                },
                RevocationId::new("child-rev"),
                0,
            )
            .expect("omitted bounds should not widen");
        assert_eq!(child.scopes, vec![Scope::new("tool:write")]);
        assert_eq!(child.budget.max_calls, Some(10));
        assert_eq!(child.expires_at, Some(Expiry(1_000)));
    }

    #[test]
    fn revoked_and_expired_tokens_cannot_be_attenuated_or_confused() {
        let revoked = parent_token();
        assert_eq!(
            revoked
                .attenuate(
                    Attenuation {
                        scopes: vec![Scope::new("tool:read")],
                        budget: Budget::limited(1),
                        expires_at: Some(Expiry(10))
                    },
                    RevocationId::new("child"),
                    0,
                )
                .err(),
            None
        ); // valid parent case sanity
        let expired = TaskToken {
            expires_at: Some(Expiry(5)),
            ..parent_token()
        };
        assert_eq!(
            expired.attenuate(
                Attenuation {
                    scopes: vec![Scope::new("tool:read")],
                    budget: Budget::limited(1),
                    expires_at: Some(Expiry(4))
                },
                RevocationId::new("child"),
                5,
            ),
            Err(TokenError::Expired)
        );
        assert!(RevocationId::new("x").is_revoked_in(["a", "x", "b"].into_iter()));
    }

    #[test]
    fn call_count_and_budget_hint_mapping() {
        let mut token = TaskToken::new(
            RevocationId::new("r1"),
            vec![Scope::new("tool:a")],
            Budget::limited(3),
            Some(Expiry(100)),
        );
        token.consume_call().expect("consume");
        let call_hint = token.call_count_hint(2);
        assert_eq!(call_hint.count, 2);
        assert_eq!(call_hint.limit, Some(2));
        assert!(call_hint.is_exceeded());

        let budget_hint = token.budget_hint(5, 5);
        assert_eq!(budget_hint.used, 5);
        assert_eq!(budget_hint.limit, 5);
        assert!(budget_hint.is_exceeded());
    }

    #[test]
    fn verification_context_and_abstractions() {
        let token = parent_token();
        let ctx = VerificationContext::new(0, &[]);
        assert!(token.verify_with(&ctx).is_ok());
        let revoked_ctx = VerificationContext::new(0, &["parent-rev"]);
        assert_eq!(token.verify_with(&revoked_ctx), Err(TokenError::Revoked));

        let engine = InMemoryTokenEngine;
        let child = TokenAttenuator::attenuate(
            &engine,
            &token,
            Attenuation {
                scopes: vec![Scope::new("tool:read")],
                budget: Budget::limited(1),
                expires_at: Some(Expiry(100)),
            },
            RevocationId::new("child"),
            0,
        )
        .unwrap();
        assert_eq!(child.revocation_id.as_str(), "child");
        // Placeholder verifier seam: encoded parsing not implemented yet.
        let err = TokenVerifier::verify(&engine, "opaque", &ctx).unwrap_err();
        assert!(matches!(
            err,
            TokenError::MissingScopes | TokenError::Revoked
        ));
    }

    mod proptests {
        use super::*;
        use proptest::collection::btree_set;
        use proptest::prelude::*;
        use std::collections::BTreeSet;

        fn arb_scope_string() -> impl Strategy<Value = String> {
            "[A-Za-z0-9._:/-]{1,16}"
        }

        fn arb_revocation_id() -> impl Strategy<Value = RevocationId> {
            "[A-Za-z0-9._:-]{1,16}".prop_map(RevocationId::new)
        }

        fn arb_scope_set(min: usize, max: usize) -> impl Strategy<Value = BTreeSet<String>> {
            btree_set(arb_scope_string(), min..=max)
        }

        fn scopes_from_set(set: &BTreeSet<String>) -> Vec<Scope> {
            set.iter().cloned().map(Scope::new).collect()
        }

        fn scope_set_of(scopes: &[Scope]) -> BTreeSet<String> {
            scopes.iter().map(|s| s.as_str().to_string()).collect()
        }

        fn arb_parent_budget() -> impl Strategy<Value = Budget> {
            prop_oneof![
                Just(Budget::unlimited()),
                (0u32..=20u32).prop_map(Budget::limited),
            ]
        }

        #[derive(Debug, Clone)]
        struct ValidParent {
            token: TaskToken,
            now: u64,
            scope_set: BTreeSet<String>,
        }

        fn arb_valid_parent() -> impl Strategy<Value = ValidParent> {
            (
                arb_revocation_id(),
                arb_scope_set(1, 6),
                arb_parent_budget(),
                prop_oneof![Just(None::<u64>), (1u64..=10_000u64).prop_map(Some)],
                0u64..=5_000u64,
            )
                .prop_filter(
                    "parent must not be expired at now",
                    |(_, _, _, exp, now): &(
                        RevocationId,
                        BTreeSet<String>,
                        Budget,
                        Option<u64>,
                        u64,
                    )| { exp.map(|e| e > *now).unwrap_or(true) },
                )
                .prop_map(|(rev, scope_set, budget, expires_at, now)| {
                    let token = TaskToken::new(
                        rev,
                        scopes_from_set(&scope_set),
                        budget,
                        expires_at.map(Expiry),
                    );
                    ValidParent {
                        token,
                        now,
                        scope_set,
                    }
                })
        }

        fn arb_narrowed_budget(parent: Budget) -> BoxedStrategy<Budget> {
            match parent.max_calls {
                Some(p) => prop_oneof![
                    Just(Budget::limited(p)),
                    (0u32..=p).prop_map(Budget::limited),
                ]
                .boxed(),
                None => prop_oneof![
                    Just(Budget::unlimited()),
                    (0u32..=20u32).prop_map(Budget::limited),
                ]
                .boxed(),
            }
        }

        fn arb_narrowed_expiry(parent: Option<Expiry>, now: u64) -> BoxedStrategy<Option<Expiry>> {
            match parent {
                Some(p) => {
                    let min = now.saturating_add(1);
                    if min > p.0 {
                        Just(Some(p)).boxed()
                    } else {
                        prop_oneof![
                            Just(None),
                            Just(Some(p)),
                            (min..=p.0).prop_map(|e| Some(Expiry(e))),
                        ]
                        .boxed()
                    }
                }
                None => prop_oneof![
                    Just(None),
                    ((now.saturating_add(1))..=(now.saturating_add(10_000)))
                        .prop_map(|e| Some(Expiry(e))),
                ]
                .boxed(),
            }
        }

        fn arb_scope_subset_vec(parent: &BTreeSet<String>) -> BoxedStrategy<Vec<Scope>> {
            let parent_vec: Vec<String> = parent.iter().cloned().collect();
            let len = parent_vec.len().max(1);
            prop::collection::vec(prop::sample::select(parent_vec), 1..=len)
                .prop_map(|vals| vals.into_iter().map(Scope::new).collect())
                .boxed()
        }

        fn arb_valid_narrowing_case(
        ) -> impl Strategy<Value = (ValidParent, RevocationId, Attenuation)> {
            arb_valid_parent().prop_flat_map(|parent| {
                let scope_strat = arb_scope_subset_vec(&parent.scope_set);
                let budget_strat = arb_narrowed_budget(parent.token.budget);
                let expiry_strat = arb_narrowed_expiry(parent.token.expires_at, parent.now);
                (
                    Just(parent),
                    arb_revocation_id(),
                    scope_strat,
                    budget_strat,
                    expiry_strat,
                )
                    .prop_map(|(parent, child_rev, scopes, budget, expires_at)| {
                        (
                            parent,
                            child_rev,
                            Attenuation {
                                scopes,
                                budget,
                                expires_at,
                            },
                        )
                    })
            })
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(128))]

            /// Valid attenuations never widen: child scopes ⊆ parent, budget/expiry do not exceed parent.
            #[test]
            fn attenuate_valid_narrowing_never_widens(
                (parent, child_rev, attenuation) in arb_valid_narrowing_case(),
            ) {
                prop_assume!(child_rev.is_valid());

                let child = parent
                    .token
                    .attenuate(attenuation, child_rev.clone(), parent.now)
                    .expect("valid narrowing must succeed");

                let child_set = scope_set_of(&child.scopes);
                prop_assert!(child_set.is_subset(&parent.scope_set), "child scopes must be subset of parent");
                prop_assert!(!child.scopes.is_empty(), "child must have at least one scope");

                match (parent.token.budget.max_calls, child.budget.max_calls) {
                    (Some(p), Some(c)) => prop_assert!(c <= p, "child budget must not exceed parent budget"),
                    (Some(_), None) => prop_assert!(false, "child budget must not become unlimited when parent limited"),
                    (None, Some(_)) => {}
                    (None, None) => {}
                }

                match (parent.token.expires_at, child.expires_at) {
                    (Some(p), Some(c)) => prop_assert!(c.0 <= p.0, "child expiry must not be later than parent"),
                    (Some(_), None) => prop_assert!(false, "child expiry must not become unbounded when parent bounded"),
                    (None, Some(_)) => {}
                    (None, None) => {}
                }

                prop_assert!(child.is_valid(parent.now));
                prop_assert_eq!(child.revocation_id, child_rev);
            }

            /// Any scope outside the parent set is rejected (widening attempt).
            #[test]
            fn attenuate_rejects_scope_widening(
                parent in arb_valid_parent(),
                child_rev in arb_revocation_id(),
                extra_scope in "[A-Za-z0-9._:/-]{1,16}",
                include_parent in any::<bool>(),
            ) {
                prop_assume!(child_rev.is_valid());
                prop_assume!(!parent.scope_set.contains(&extra_scope));

                let mut scopes = vec![Scope::new(extra_scope)];
                if include_parent {
                    if let Some(existing) = parent.scope_set.iter().next() {
                        scopes.push(Scope::new(existing.clone()));
                    }
                }

                let err = parent
                    .token
                    .attenuate(
                        Attenuation {
                            scopes,
                            budget: match parent.token.budget.max_calls {
                                Some(p) => Budget::limited(p),
                                None => Budget::unlimited(),
                            },
                            expires_at: parent.token.expires_at,
                        },
                        child_rev,
                        parent.now,
                    )
                    .unwrap_err();

                prop_assert!(
                    matches!(err, TokenError::ScopeNotSubset { .. }),
                    "expected ScopeNotSubset, got {err:?}"
                );
            }

            /// Budget larger than parent remaining is rejected.
            #[test]
            fn attenuate_rejects_budget_widening(
                parent in arb_valid_parent(),
                child_rev in arb_revocation_id(),
                extra in 1u32..=20u32,
            ) {
                prop_assume!(child_rev.is_valid());
                prop_assume!(parent.token.budget.max_calls.is_some());
                let p = parent.token.budget.max_calls.unwrap();

                let first_scope = parent
                    .scope_set
                    .iter()
                    .next()
                    .cloned()
                    .expect("parent has scopes");
                let err = parent
                    .token
                    .attenuate(
                        Attenuation {
                            scopes: vec![Scope::new(first_scope)],
                            budget: Budget::limited(p.saturating_add(extra)),
                            expires_at: parent.token.expires_at,
                        },
                        child_rev,
                        parent.now,
                    )
                    .unwrap_err();

                prop_assert_eq!(err, TokenError::BudgetWidened);
            }

            /// Expiry later than parent is rejected.
            #[test]
            fn attenuate_rejects_expiry_widening(
                parent in arb_valid_parent(),
                child_rev in arb_revocation_id(),
                extra in 1u64..=10_000u64,
            ) {
                prop_assume!(child_rev.is_valid());
                prop_assume!(parent.token.expires_at.is_some());
                let p = parent.token.expires_at.unwrap();

                let first_scope = parent
                    .scope_set
                    .iter()
                    .next()
                    .cloned()
                    .expect("parent has scopes");
                let err = parent
                    .token
                    .attenuate(
                        Attenuation {
                            scopes: vec![Scope::new(first_scope)],
                            budget: match parent.token.budget.max_calls {
                                Some(n) => Budget::limited(n),
                                None => Budget::unlimited(),
                            },
                            expires_at: Some(Expiry(p.0.saturating_add(extra))),
                        },
                        child_rev,
                        parent.now,
                    )
                    .unwrap_err();

                prop_assert_eq!(err, TokenError::ExpiryWidened);
            }
        }
    }

    #[test]
    fn require_scope_helpers_fail_closed() {
        let token = parent_token();
        assert!(token.require_scope("tool:read").is_ok());
        assert_eq!(
            token.require_scope("tool:admin"),
            Err(TokenError::ScopeDenied {
                scope: "tool:admin".to_string(),
            })
        );
        assert!(token
            .require_all_scopes(["tool:read", "tool:write"])
            .is_ok());
        assert_eq!(
            token.require_all_scopes(["tool:read", "tool:admin"]),
            Err(TokenError::ScopeDenied {
                scope: "tool:admin".to_string(),
            })
        );
    }

    #[test]
    fn revocation_store_engine_runtime_scope_helpers() {
        let token = parent_token();
        let empty: std::collections::HashSet<String> = std::collections::HashSet::new();
        let engine = RevocationStoreTokenEngine::new(&empty);
        engine
            .verify_token_require_scope(&token, 0, "tool:read")
            .expect("scope granted");
        assert_eq!(
            engine.verify_token_require_scope(&token, 0, "tool:admin"),
            Err(TokenError::ScopeDenied {
                scope: "tool:admin".to_string(),
            })
        );
        engine
            .verify_token_require_all_scopes(&token, 0, ["tool:read", "tool:write"])
            .expect("all scopes granted");

        let revoked = std::collections::HashSet::from(["parent-rev".to_string()]);
        let revoked_engine = RevocationStoreTokenEngine::new(&revoked);
        assert_eq!(
            revoked_engine.verify_token_require_scope(&token, 0, "tool:read"),
            Err(TokenError::Revoked)
        );

        let expired = TaskToken {
            expires_at: Some(Expiry(5)),
            ..parent_token()
        };
        assert_eq!(
            engine.verify_token_require_scope(&expired, 5, "tool:read"),
            Err(TokenError::Expired)
        );
    }

    #[test]
    fn revocation_store_impls_for_wrappers_and_btreeset() {
        let set = std::collections::BTreeSet::from(["rev-a".to_string()]);
        assert!(set.is_revoked("rev-a"));
        assert!(!set.is_revoked("rev-b"));

        let arc = std::sync::Arc::new(std::collections::HashSet::from(["rev-a".to_string()]));
        assert!(RevocationStore::is_revoked(&arc, "rev-a"));
        assert!(!RevocationStore::is_revoked(&arc, "rev-b"));

        let boxed: Box<dyn RevocationStore> = Box::new(vec!["rev-a".to_string()]);
        assert!(RevocationStore::is_revoked(&*boxed, "rev-a"));
        assert!(!RevocationStore::is_revoked(&*boxed, "rev-b"));
    }

    #[test]
    fn task_token_issue_validated_and_call_budget_gate_fail_closed() {
        let token = TaskToken::new(
            RevocationId::new("r1"),
            vec![Scope::new("tool:read")],
            Budget::limited(1),
            Some(Expiry(100)),
        );
        let issued = token.clone().issue_validated(10).expect("valid at now");
        assert_eq!(issued.revocation_id.as_str(), "r1");
        assert_eq!(token.clone().issue_validated(100), Err(TokenError::Expired));

        let mut limited = issued;
        limited.require_calls_available(1).expect("has budget");
        limited.consume_call().expect("consume");
        assert_eq!(
            limited.require_calls_available(1),
            Err(TokenError::BudgetExhausted)
        );
    }

    #[test]
    fn task_token_verify_and_attenuate_with_store_or_context_fail_closed() {
        let token = parent_token();
        let ctx = VerificationContext::new(0, &[]);
        token
            .verify_requiring_scope(&ctx, "tool:read")
            .expect("scope ok");
        assert_eq!(
            token.verify_requiring_scope(&ctx, "tool:admin"),
            Err(TokenError::ScopeDenied {
                scope: "tool:admin".to_string(),
            })
        );

        let revoked_ctx = VerificationContext::new(0, &["parent-rev"]);
        assert_eq!(
            token.verify_requiring_all_scopes(&revoked_ctx, ["tool:read"]),
            Err(TokenError::Revoked)
        );

        let store = std::collections::HashSet::from(["parent-rev".to_string()]);
        assert_eq!(
            token.verify_with_store_requiring_scope(&store, 0, "tool:read"),
            Err(TokenError::Revoked)
        );
        let empty: std::collections::HashSet<String> = std::collections::HashSet::new();
        token
            .verify_with_store_requiring_all_scopes(&empty, 0, ["tool:read", "tool:write"])
            .expect("store verify ok");

        let child = token
            .attenuate_verified(
                Attenuation {
                    scopes: vec![Scope::new("tool:read")],
                    budget: Budget::limited(1),
                    expires_at: Some(Expiry(500)),
                },
                RevocationId::new("child-v"),
                &ctx,
            )
            .expect("attenuate with verified context");
        assert_eq!(child.scopes, vec![Scope::new("tool:read")]);
        assert_eq!(
            token.attenuate_verified(
                Attenuation {
                    scopes: vec![Scope::new("tool:read")],
                    budget: Budget::limited(1),
                    expires_at: Some(Expiry(500)),
                },
                RevocationId::new("child-v"),
                &revoked_ctx,
            ),
            Err(TokenError::Revoked)
        );

        let child_store = token
            .attenuate_with_store(
                &empty,
                Attenuation {
                    scopes: vec![Scope::new("tool:write")],
                    budget: Budget::limited(1),
                    expires_at: Some(Expiry(500)),
                },
                RevocationId::new("child-s"),
                0,
            )
            .expect("attenuate with store");
        assert_eq!(child_store.scopes, vec![Scope::new("tool:write")]);
        assert_eq!(
            token.attenuate_with_store(
                &store,
                Attenuation {
                    scopes: vec![Scope::new("tool:write")],
                    budget: Budget::limited(1),
                    expires_at: Some(Expiry(500)),
                },
                RevocationId::new("child-s"),
                0,
            ),
            Err(TokenError::Revoked)
        );
    }

    #[test]
    fn revocation_store_engine_consume_and_inmemory_issuer_fail_closed() {
        let mut token = TaskToken::new(
            RevocationId::new("r1"),
            vec![Scope::new("tool:read")],
            Budget::limited(1),
            Some(Expiry(100)),
        );
        let empty: std::collections::HashSet<String> = std::collections::HashSet::new();
        let engine = RevocationStoreTokenEngine::new(&empty);
        engine
            .verify_require_scope_and_consume_call(&mut token, 0, "tool:read")
            .expect("verify+scope+consume");
        assert_eq!(token.remaining_calls(), Some(0));
        assert_eq!(
            engine.verify_require_scope_and_consume_call(&mut token, 0, "tool:read"),
            Err(TokenError::BudgetExhausted)
        );

        let issuer = InMemoryTokenIssuer;
        let ok = issuer
            .issue(&parent_token(), 0)
            .expect("valid token issuance");
        assert_eq!(ok.revocation_id.as_str(), "parent-rev");
        let expired = TaskToken {
            expires_at: Some(Expiry(5)),
            ..parent_token()
        };
        assert_eq!(issuer.issue(&expired, 5), Err(TokenError::Expired));

        let verifier = InMemoryTokenEngine;
        assert_eq!(
            TokenVerifier::verify(&verifier, "opaque", &VerificationContext::new(0, &[])),
            Err(TokenError::Revoked)
        );
    }

    #[test]
    fn task_token_verify_require_scope_and_consume_call_and_string_slice_store() {
        let ctx = VerificationContext::new(0, &[]);
        let mut token = TaskToken::new(
            RevocationId::new("r1"),
            vec![Scope::new("tool:read")],
            Budget::limited(1),
            Some(Expiry(100)),
        );
        token
            .verify_requiring_scope_and_consume_call(&ctx, "tool:read")
            .expect("verify+scope+consume");
        assert_eq!(token.remaining_calls(), Some(0));
        assert_eq!(
            token.verify_requiring_scope_and_consume_call(&ctx, "tool:read"),
            Err(TokenError::BudgetExhausted)
        );

        let mut denied = TaskToken::new(
            RevocationId::new("r2"),
            vec![Scope::new("tool:read")],
            Budget::limited(1),
            Some(Expiry(100)),
        );
        assert_eq!(
            denied.verify_requiring_scope_and_consume_call(&ctx, "tool:admin"),
            Err(TokenError::ScopeDenied {
                scope: "tool:admin".to_string(),
            })
        );
        assert_eq!(
            denied.remaining_calls(),
            Some(1),
            "scope denial must not consume"
        );

        let revoked = ["r3".to_string()];
        let mut t3 = TaskToken::new(
            RevocationId::new("r3"),
            vec![Scope::new("tool:read")],
            Budget::limited(1),
            Some(Expiry(100)),
        );
        assert_eq!(
            t3.verify_with_store_requiring_scope_and_consume_call(&revoked[..], 0, "tool:read"),
            Err(TokenError::Revoked)
        );
        assert_eq!(t3.remaining_calls(), Some(1), "revocation must not consume");

        let empty: Vec<String> = vec![];
        t3.verify_with_store_requiring_scope_and_consume_call(&empty[..], 0, "tool:read")
            .expect("string-slice store verify+scope+consume");
        assert_eq!(t3.remaining_calls(), Some(0));
    }

    #[test]
    fn live_enforcement_verify_scope_budget_consume_fail_closed() {
        let ctx = VerificationContext::new(0, &[]);
        let mut token = TaskToken::new(
            RevocationId::new("r-live"),
            vec![Scope::new("tool:read"), Scope::new("tool:write")],
            Budget::limited(2),
            Some(Expiry(100)),
        );
        token
            .verify_requiring_scope_and_consume_calls(&ctx, "tool:read", 2)
            .expect("verify+scope+consume n");
        assert_eq!(token.remaining_calls(), Some(0));
        assert_eq!(
            token.verify_requiring_scope_and_consume_calls(&ctx, "tool:read", 1),
            Err(TokenError::BudgetExhausted)
        );

        let mut denied = TaskToken::new(
            RevocationId::new("r-live2"),
            vec![Scope::new("tool:read")],
            Budget::limited(2),
            Some(Expiry(100)),
        );
        assert_eq!(
            denied.verify_requiring_scope_and_consume_calls(&ctx, "tool:admin", 1),
            Err(TokenError::ScopeDenied {
                scope: "tool:admin".to_string(),
            })
        );
        assert_eq!(
            denied.remaining_calls(),
            Some(2),
            "scope denial must not consume"
        );

        let mut all_scopes = TaskToken::new(
            RevocationId::new("r-live3"),
            vec![Scope::new("tool:read"), Scope::new("tool:write")],
            Budget::limited(1),
            Some(Expiry(100)),
        );
        all_scopes
            .verify_requiring_all_scopes_and_consume_call(&ctx, ["tool:read", "tool:write"])
            .expect("all scopes + consume");
        assert_eq!(all_scopes.remaining_calls(), Some(0));

        let mut missing = TaskToken::new(
            RevocationId::new("r-live4"),
            vec![Scope::new("tool:read")],
            Budget::limited(1),
            Some(Expiry(100)),
        );
        assert_eq!(
            missing.verify_requiring_all_scopes_and_consume_call(&ctx, ["tool:read", "tool:admin"]),
            Err(TokenError::ScopeDenied {
                scope: "tool:admin".to_string(),
            })
        );
        assert_eq!(
            missing.remaining_calls(),
            Some(1),
            "missing scope must not consume"
        );

        let mut batch = TaskToken::new(
            RevocationId::new("r-live5"),
            vec![Scope::new("tool:read"), Scope::new("tool:write")],
            Budget::limited(3),
            Some(Expiry(100)),
        );
        batch
            .verify_requiring_all_scopes_and_consume_calls(&ctx, ["tool:read", "tool:write"], 2)
            .expect("all scopes + consume n");
        assert_eq!(batch.remaining_calls(), Some(1));

        let empty: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut store_tok = TaskToken::new(
            RevocationId::new("r-live6"),
            vec![Scope::new("tool:read"), Scope::new("tool:write")],
            Budget::limited(2),
            Some(Expiry(100)),
        );
        store_tok
            .verify_with_store_requiring_scope_and_consume_calls(&empty, 0, "tool:read", 2)
            .expect("store verify+scope+consume n");
        assert_eq!(store_tok.remaining_calls(), Some(0));

        let revoked = std::collections::HashSet::from(["r-live7".to_string()]);
        let mut revoked_tok = TaskToken::new(
            RevocationId::new("r-live7"),
            vec![Scope::new("tool:read")],
            Budget::limited(1),
            Some(Expiry(100)),
        );
        assert_eq!(
            revoked_tok.verify_with_store_requiring_all_scopes_and_consume_call(
                &revoked,
                0,
                ["tool:read"]
            ),
            Err(TokenError::Revoked)
        );
        assert_eq!(
            revoked_tok.remaining_calls(),
            Some(1),
            "revocation must not consume"
        );

        let engine = RevocationStoreTokenEngine::new(&empty);
        let mut engine_tok = TaskToken::new(
            RevocationId::new("r-live8"),
            vec![Scope::new("tool:read"), Scope::new("tool:write")],
            Budget::limited(3),
            Some(Expiry(100)),
        );
        engine
            .verify_require_scope_and_consume_calls(&mut engine_tok, 0, "tool:read", 2)
            .expect("engine consume n");
        assert_eq!(engine_tok.remaining_calls(), Some(1));
        engine
            .verify_token_require_all_scopes_and_consume_call(
                &mut engine_tok,
                0,
                ["tool:read", "tool:write"],
            )
            .expect("engine all scopes consume");
        assert_eq!(engine_tok.remaining_calls(), Some(0));
        assert_eq!(
            engine.verify_require_scope_and_consume_calls(&mut engine_tok, 0, "tool:read", 1),
            Err(TokenError::BudgetExhausted)
        );

        let expired = TaskToken::new(
            RevocationId::new("r-live9"),
            vec![Scope::new("tool:read")],
            Budget::limited(1),
            Some(Expiry(5)),
        );
        assert_eq!(
            expired
                .clone()
                .issue_validated(5)
                .err()
                .unwrap_or(TokenError::Revoked),
            TokenError::Expired
        );
        let expired_tok = expired;
        assert_eq!(
            engine.verify_token_require_scope(&expired_tok, 5, "tool:read"),
            Err(TokenError::Expired)
        );
    }
}

#[cfg(all(test, feature = "biscuit"))]
mod biscuit_tests {
    use super::biscuit_adapter::{
        BiscuitTokenAttenuator, BiscuitTokenEngine, BiscuitTokenVerifier,
    };
    use super::*;

    fn engine() -> BiscuitTokenEngine {
        BiscuitTokenEngine::new(biscuit_auth::KeyPair::new())
    }

    fn sample_token() -> TaskToken {
        TaskToken::new(
            RevocationId::new("root-rev"),
            vec![Scope::new("tool:read"), Scope::new("tool:write")],
            Budget::limited(5),
            Some(Expiry(1_000)),
        )
    }

    #[test]
    fn issue_and_verify_roundtrip_maps_scopegate_claims() {
        let engine = engine();
        let token = sample_token();
        let encoded = engine.issue(&token).expect("issue biscuit token");

        let verified = engine
            .verify(&encoded, &VerificationContext::new(10, &[]))
            .expect("verify issued token");

        assert_eq!(verified.revocation_id, token.revocation_id);
        assert_eq!(
            verified.scopes,
            vec![Scope::new("tool:read"), Scope::new("tool:write")]
        );
        assert_eq!(verified.budget, token.budget);
        assert_eq!(verified.expires_at, token.expires_at);
        assert!(verified.attenuation.is_none());
        assert!(verified.allows_scope("tool:read"));
        assert!(verified.allows_scope("tool:write"));
    }

    #[test]
    fn verify_fails_closed_for_revoked_expired_and_invalid_tokens() {
        let engine = engine();
        let token = sample_token();
        let encoded = engine.issue(&token).expect("issue biscuit token");

        let revoked = engine.verify(&encoded, &VerificationContext::new(10, &["root-rev"]));
        assert_eq!(revoked, Err(TokenError::Revoked));

        let expired = engine.verify(&encoded, &VerificationContext::new(1_000, &[]));
        assert_eq!(expired, Err(TokenError::Expired));

        let bad = engine.verify("not-a-biscuit", &VerificationContext::new(10, &[]));
        assert!(bad.is_err());
    }

    #[test]
    fn attenuate_narrows_claims_and_rejects_widening_via_biscuit() {
        let engine = engine();
        let parent = sample_token();
        let parent_encoded = engine.issue(&parent).expect("issue parent");

        let child_encoded = engine
            .attenuate(
                &parent_encoded,
                Attenuation {
                    scopes: vec![Scope::new("tool:read")],
                    budget: Budget::limited(2),
                    expires_at: Some(Expiry(500)),
                },
                RevocationId::new("child-rev"),
                10,
            )
            .expect("attenuate child");
        let child = engine
            .verify(&child_encoded, &VerificationContext::new(10, &[]))
            .expect("verify child");
        assert_eq!(child.revocation_id, RevocationId::new("child-rev"));
        assert_eq!(child.scopes, vec![Scope::new("tool:read")]);
        assert_eq!(child.budget, Budget::limited(2));
        assert_eq!(child.expires_at, Some(Expiry(500)));

        let widen_scope = engine.attenuate(
            &child_encoded,
            Attenuation {
                scopes: vec![Scope::new("tool:write")],
                budget: Budget::limited(1),
                expires_at: Some(Expiry(400)),
            },
            RevocationId::new("grandchild"),
            10,
        );
        assert!(matches!(
            widen_scope,
            Err(TokenError::ScopeNotSubset { .. })
        ));

        let widen_budget = engine.attenuate(
            &child_encoded,
            Attenuation {
                scopes: vec![Scope::new("tool:read")],
                budget: Budget::limited(3),
                expires_at: Some(Expiry(400)),
            },
            RevocationId::new("grandchild"),
            10,
        );
        assert_eq!(widen_budget, Err(TokenError::BudgetWidened));

        let widen_expiry = engine.attenuate(
            &child_encoded,
            Attenuation {
                scopes: vec![Scope::new("tool:read")],
                budget: Budget::limited(1),
                expires_at: Some(Expiry(600)),
            },
            RevocationId::new("grandchild"),
            10,
        );
        assert_eq!(widen_expiry, Err(TokenError::ExpiryWidened));
    }

    #[test]
    fn trait_hooks_verify_and_attenuate() {
        let engine = engine();
        let encoded = engine.issue(&sample_token()).expect("issue");
        let ctx = VerificationContext::new(10, &[]);
        let verified =
            BiscuitTokenVerifier::verify_biscuit(&engine, &encoded, &ctx).expect("verify");
        assert_eq!(verified.revocation_id.as_str(), "root-rev");

        let child_encoded = BiscuitTokenAttenuator::attenuate_biscuit(
            &engine,
            &encoded,
            Attenuation {
                scopes: vec![Scope::new("tool:write")],
                budget: Budget::limited(1),
                expires_at: Some(Expiry(900)),
            },
            RevocationId::new("child"),
            10,
        )
        .expect("attenuate via trait");
        let child = TokenVerifier::verify(&engine, &child_encoded, &ctx).expect("verify child");
        assert_eq!(child.scopes, vec![Scope::new("tool:write")]);
    }

    #[test]
    fn store_aware_verify_and_attenuate_fail_closed_on_revocation() {
        let engine = engine();
        let encoded = engine.issue(&sample_token()).expect("issue");
        let revoked = std::collections::HashSet::from(["root-rev".to_string()]);

        assert_eq!(
            engine.verify_with_store(&encoded, &revoked, 10),
            Err(TokenError::Revoked)
        );

        let err = engine.attenuate_with_store(
            &encoded,
            Attenuation {
                scopes: vec![Scope::new("tool:read")],
                budget: Budget::limited(1),
                expires_at: Some(Expiry(500)),
            },
            RevocationId::new("child"),
            &revoked,
            10,
        );
        assert_eq!(err, Err(TokenError::Revoked));

        let empty: std::collections::HashSet<String> = std::collections::HashSet::new();
        let child_encoded = engine
            .attenuate_with_store(
                &encoded,
                Attenuation {
                    scopes: vec![Scope::new("tool:read")],
                    budget: Budget::limited(1),
                    expires_at: Some(Expiry(500)),
                },
                RevocationId::new("child"),
                &empty,
                10,
            )
            .expect("attenuate with empty store");
        let child = engine
            .verify_with_store(&child_encoded, &empty, 10)
            .expect("verify child");
        assert_eq!(child.revocation_id.as_str(), "child");
    }

    #[test]
    fn attenuate_with_revoked_checks_parent_fail_closed() {
        let engine = engine();
        let encoded = engine.issue(&sample_token()).expect("issue");
        let err = engine.attenuate_with_revoked(
            &encoded,
            Attenuation {
                scopes: vec![Scope::new("tool:read")],
                budget: Budget::limited(1),
                expires_at: Some(Expiry(500)),
            },
            RevocationId::new("child"),
            10,
            &["root-rev"],
        );
        assert_eq!(err, Err(TokenError::Revoked));
    }

    #[test]
    fn verifier_engine_can_verify_and_attenuate_but_cannot_issue() {
        let signer = engine();
        let encoded = signer.issue(&sample_token()).expect("issue");
        let verifier = BiscuitTokenEngine::verifier(signer.root_public_key());
        assert!(!verifier.can_sign());
        assert_eq!(verifier.issue(&sample_token()), Err(TokenError::Revoked));

        let ctx = VerificationContext::new(10, &[]);
        let verified = verifier
            .verify(&encoded, &ctx)
            .expect("verify with public key only");
        assert_eq!(verified.revocation_id.as_str(), "root-rev");

        let child = verifier
            .attenuate(
                &encoded,
                Attenuation {
                    scopes: vec![Scope::new("tool:read")],
                    budget: Budget::limited(1),
                    expires_at: Some(Expiry(500)),
                },
                RevocationId::new("child-v"),
                10,
            )
            .expect("attenuate with public key only");
        let child_verified = signer.verify(&child, &ctx).expect("signer verifies child");
        assert_eq!(child_verified.revocation_id.as_str(), "child-v");
        assert_eq!(child_verified.scopes, vec![Scope::new("tool:read")]);
        assert_eq!(child_verified.budget, Budget::limited(1));
        assert_eq!(child_verified.expires_at, Some(Expiry(500)));
    }

    #[test]
    fn wrong_public_key_and_tampered_token_fail_closed() {
        let signer = engine();
        let encoded = signer.issue(&sample_token()).expect("issue");
        let other = BiscuitTokenEngine::verifier(engine().root_public_key());
        let ctx = VerificationContext::new(10, &[]);

        assert!(matches!(
            other.verify(&encoded, &ctx),
            Err(TokenError::Revoked | TokenError::Expired | TokenError::MissingScopes)
        ));

        let mut tampered = encoded.clone();
        tampered.pop();
        tampered.push(if encoded.ends_with('a') { 'b' } else { 'a' });
        assert!(signer.verify(&tampered, &ctx).is_err());
    }

    #[test]
    fn verify_enforcing_scope_helpers_and_fail_closed_denials() {
        let engine = engine();
        let encoded = engine.issue(&sample_token()).expect("issue");
        let ctx = VerificationContext::new(10, &[]);

        let ok = engine
            .verify_enforcing_scope(&encoded, &ctx, "tool:read")
            .expect("scope granted");
        assert_eq!(ok.revocation_id.as_str(), "root-rev");
        assert_eq!(
            engine.verify_enforcing_scope(&encoded, &ctx, "tool:admin"),
            Err(TokenError::ScopeDenied {
                scope: "tool:admin".to_string(),
            })
        );
        engine
            .verify_enforcing_all_scopes(&encoded, &ctx, ["tool:read", "tool:write"])
            .expect("all granted");

        let empty: std::collections::HashSet<String> = std::collections::HashSet::new();
        engine
            .verify_with_store_enforcing_scope(&encoded, &empty, 10, "tool:write")
            .expect("store verify + scope");
        assert_eq!(
            engine.verify_with_store_enforcing_scope(&encoded, &empty, 10, "tool:admin"),
            Err(TokenError::ScopeDenied {
                scope: "tool:admin".to_string(),
            })
        );
        engine
            .verify_with_store_enforcing_all_scopes(&encoded, &empty, 10, ["tool:read"])
            .expect("store verify + all scopes");

        let revoked = std::collections::HashSet::from(["root-rev".to_string()]);
        assert_eq!(
            engine.verify_with_store_enforcing_scope(&encoded, &revoked, 10, "tool:read"),
            Err(TokenError::Revoked)
        );
    }

    #[test]
    fn verify_with_any_root_key_hooks_fail_closed_and_support_rotation() {
        let signer_a = engine();
        let signer_b = engine();
        let encoded_a = signer_a.issue(&sample_token()).expect("issue a");
        let ctx = VerificationContext::new(10, &[]);

        let verified = BiscuitTokenEngine::verify_with_any_root_key(
            &encoded_a,
            &ctx,
            [signer_b.root_public_key(), signer_a.root_public_key()],
        )
        .expect("matching key in set should verify");
        assert_eq!(verified.revocation_id.as_str(), "root-rev");

        assert!(matches!(
            BiscuitTokenEngine::verify_with_any_root_key(
                &encoded_a,
                &ctx,
                [signer_b.root_public_key()]
            ),
            Err(TokenError::Revoked)
        ));
        assert_eq!(
            BiscuitTokenEngine::verify_with_any_root_key(
                &encoded_a,
                &ctx,
                std::iter::empty::<biscuit_auth::PublicKey>()
            ),
            Err(TokenError::Revoked)
        );

        let empty: std::collections::HashSet<String> = std::collections::HashSet::new();
        let verified_store = BiscuitTokenEngine::verify_with_store_any_root_key(
            &encoded_a,
            &empty,
            10,
            [signer_b.root_public_key(), signer_a.root_public_key()],
        )
        .expect("matching key in set should verify with store");
        assert_eq!(verified_store.revocation_id.as_str(), "root-rev");
        assert_eq!(
            BiscuitTokenEngine::verify_with_store_any_root_key(
                &encoded_a,
                &empty,
                10,
                [signer_b.root_public_key()]
            ),
            Err(TokenError::Revoked)
        );
    }

    #[test]
    fn issuer_and_store_budget_scope_helpers_enforce_live_path_constraints() {
        let signer = engine();
        let encoded =
            super::TokenIssuer::issue(&signer, &sample_token(), 10).expect("issue via trait");
        let empty: std::collections::HashSet<String> = std::collections::HashSet::new();

        let tok = signer
            .verify_with_store_enforcing_scope_and_budget(&encoded, &empty, 10, "tool:read", 1)
            .expect("scope+budget ok");
        assert!(tok.can_consume_call());
        assert_eq!(
            signer.verify_with_store_enforcing_scope_and_budget(
                &encoded,
                &empty,
                10,
                "tool:admin",
                1
            ),
            Err(TokenError::ScopeDenied {
                scope: "tool:admin".to_string(),
            })
        );
        let exhausted = TaskToken::new(
            RevocationId::new("root-rev"),
            vec![Scope::new("tool:read"), Scope::new("tool:write")],
            Budget::limited(0),
            Some(Expiry(1_000)),
        );
        let enc_exhausted = signer.issue(&exhausted).expect("issue exhausted");
        assert_eq!(
            signer.verify_with_store_enforcing_scope_and_budget(
                &enc_exhausted,
                &empty,
                10,
                "tool:read",
                1
            ),
            Err(TokenError::BudgetExhausted)
        );

        let other = engine();
        let verified = BiscuitTokenEngine::verify_with_store_enforcing_scope_any_root_key(
            &encoded,
            &empty,
            10,
            "tool:write",
            [other.root_public_key(), signer.root_public_key()],
        )
        .expect("rotation set + scope enforcement");
        assert_eq!(verified.revocation_id.as_str(), "root-rev");
        assert_eq!(
            BiscuitTokenEngine::verify_with_store_enforcing_scope_any_root_key(
                &encoded,
                &empty,
                10,
                "tool:admin",
                [signer.root_public_key()],
            ),
            Err(TokenError::ScopeDenied {
                scope: "tool:admin".to_string(),
            })
        );
    }
}
