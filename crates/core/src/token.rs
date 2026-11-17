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
    ScopeNotSubset { scope: String },
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

/// Pure in-memory verifier/attenuator for `TaskToken` placeholders.
#[derive(Debug, Clone, Copy, Default)]
pub struct InMemoryTokenEngine;

impl TokenVerifier for InMemoryTokenEngine {
    type Token = TaskToken;
    fn verify(
        &self,
        _encoded: &str,
        ctx: &VerificationContext<'_>,
    ) -> VerificationResult<Self::Token> {
        // No serialized format yet; real Biscuit parsing plugs in later.
        Err(if ctx.revoked_ids.is_empty() {
            TokenError::MissingScopes
        } else {
            TokenError::Revoked
        })
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

impl TaskToken {
    /// Verifies this already-materialized token against a context.
    pub fn verify_with(&self, ctx: &VerificationContext<'_>) -> Result<(), TokenError> {
        self.validate(ctx.now_unix, ctx.revoked_ids)
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
}

/// Feature-gated Biscuit adapter hooks for runtime integrations.
/// Implementations can bridge `biscuit-auth` parsing/attenuation without
/// forcing the dependency in default builds.
#[cfg(feature = "biscuit")]
pub mod biscuit_adapter {
    use super::{Attenuation, RevocationId, TaskToken, TokenError, VerificationContext};

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
}
