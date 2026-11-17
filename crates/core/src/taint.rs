//! Session taint tracking and propagation primitives.
//!
//! Tracks untrusted/private-data influence, models propagation across
//! operations/data flows, and evaluates egress decisions (allow/block/require
//! approval) in a pure in-memory form.

/// Labels representing sensitive/untrusted influences on a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TaintLabel {
    /// Content originated from an untrusted source (user/tool/input).
    UntrustedContent,
    /// Content derived from private or sensitive data.
    PrivateData,
}

impl TaintLabel {
    /// Stable name for the label (integration/debug/provenance helper).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UntrustedContent => "untrusted_content",
            Self::PrivateData => "private_data",
        }
    }

    /// Short provenance-oriented description of what this label means.
    pub fn provenance(self) -> &'static str {
        match self {
            Self::UntrustedContent => "influenced by untrusted input/content",
            Self::PrivateData => "influenced by private or sensitive data",
        }
    }
}

/// Operation or destination being attempted by the session.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum OperationTarget {
    /// Sending data outside the trust boundary (network, external tool, etc.).
    ExternalEgress,
    /// A named operation/target not classified as external egress.
    Other(String),
}

impl OperationTarget {
    /// Convenience constructor for non-egress operations.
    pub fn other(name: impl Into<String>) -> Self {
        Self::Other(name.into())
    }

    /// Parses common operation names into typed targets.
    pub fn from_operation(operation: &str) -> Self {
        match operation {
            "external_egress" | "egress" => Self::ExternalEgress,
            other => Self::other(other),
        }
    }

    /// Returns true when this target represents external egress.
    pub fn is_external_egress(&self) -> bool {
        matches!(self, Self::ExternalEgress)
    }

    /// Stable target name for summaries/integration.
    pub fn as_str(&self) -> &str {
        match self {
            Self::ExternalEgress => "external_egress",
            Self::Other(name) => name.as_str(),
        }
    }
}

/// Decision for a taint-checked operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaintDecision {
    /// Operation is allowed.
    Allow,
    /// Operation must be blocked.
    Block,
    /// Operation may proceed only with explicit approval.
    RequireApproval,
}

impl TaintDecision {
    /// Returns true if the operation may proceed without approval.
    pub fn is_allowed(self) -> bool {
        matches!(self, Self::Allow)
    }

    /// Returns true if the operation is blocked outright.
    pub fn is_blocked(self) -> bool {
        matches!(self, Self::Block)
    }

    /// Returns true if explicit approval is required.
    pub fn requires_approval(self) -> bool {
        matches!(self, Self::RequireApproval)
    }
}

/// Policy for handling external egress when untrusted and private taint conflict.
///
/// This makes the separation between allow/block/require-approval explicit for
/// conflicted egress cases while keeping non-egress operations unaffected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EgressPolicy {
    /// Conflicted egress may proceed only with explicit approval.
    #[default]
    RequireApprovalOnConflict,
    /// Conflicted egress is blocked outright.
    BlockOnConflict,
}

/// Result of applying a state transition/update to a taint label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaintTransition {
    pub label: TaintLabel,
    pub changed: bool,
    pub present: bool,
}

/// Snapshot/summary of taint state for integration and diagnostics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaintSummary {
    pub labels: Vec<TaintLabel>,
    pub label_names: Vec<&'static str>,
    pub label_provenance: Vec<&'static str>,
    pub has_untrusted_content: bool,
    pub has_private_data: bool,
    pub conflicted_for_egress: bool,
}

impl TaintSummary {
    /// Returns true when the summary contains no taint labels.
    pub fn is_clean(&self) -> bool {
        self.labels.is_empty()
    }
}

/// A session's accumulated taint state.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SessionTaint {
    labels: Vec<TaintLabel>,
}

impl SessionTaint {
    /// Creates an empty taint state.
    pub fn new() -> Self {
        Self { labels: Vec::new() }
    }

    /// Adds a taint label if not already present.
    pub fn add_label(&mut self, label: TaintLabel) {
        self.apply_label(label);
    }

    /// Backward-compatible alias for [`Self::add_label`].
    pub fn add(&mut self, label: TaintLabel) {
        self.add_label(label);
    }

    /// Applies/records a taint label and reports the transition.
    pub fn apply_label(&mut self, label: TaintLabel) -> TaintTransition {
        let changed = if self.labels.contains(&label) {
            false
        } else {
            self.labels.push(label);
            true
        };
        TaintTransition {
            label,
            changed,
            present: true,
        }
    }

    /// Builder-style transition: adds a label and returns the updated state.
    pub fn with_label(mut self, label: TaintLabel) -> Self {
        self.add_label(label);
        self
    }

    /// Removes a taint label if present. Returns true if it was removed.
    pub fn remove_label(&mut self, label: TaintLabel) -> bool {
        self.clear_label(label).changed
    }

    /// Clears/unrecords a taint label and reports the transition.
    pub fn clear_label(&mut self, label: TaintLabel) -> TaintTransition {
        let changed = if let Some(pos) = self.labels.iter().position(|l| *l == label) {
            self.labels.remove(pos);
            true
        } else {
            false
        };
        TaintTransition {
            label,
            changed,
            present: false,
        }
    }

    /// Builder-style transition: removes a label and returns the updated state.
    pub fn without_label(mut self, label: TaintLabel) -> Self {
        self.remove_label(label);
        self
    }

    /// Merges labels from another taint state into this one.
    pub fn merge(&mut self, other: &SessionTaint) {
        for label in &other.labels {
            self.add_label(*label);
        }
    }

    /// Clears all taint labels from the session.
    pub fn clear(&mut self) {
        self.labels.clear();
    }

    /// Returns true if the session has the given label.
    pub fn contains(&self, label: TaintLabel) -> bool {
        self.labels.contains(&label)
    }

    /// Returns the current labels.
    pub fn labels(&self) -> &[TaintLabel] {
        &self.labels
    }

    /// Returns stable label names for current taint labels.
    pub fn label_names(&self) -> Vec<&'static str> {
        self.labels.iter().map(|l| l.as_str()).collect()
    }

    /// Returns provenance descriptions for current taint labels.
    pub fn label_provenance(&self) -> Vec<&'static str> {
        self.labels.iter().map(|l| l.provenance()).collect()
    }

    /// Returns a summary snapshot of the current taint state.
    pub fn summary(&self) -> TaintSummary {
        TaintSummary {
            labels: self.labels.clone(),
            label_names: self.label_names(),
            label_provenance: self.label_provenance(),
            has_untrusted_content: self.has_untrusted_content(),
            has_private_data: self.has_private_data(),
            conflicted_for_egress: self.is_conflicted_for_egress(),
        }
    }

    /// Returns true when the session is influenced by untrusted content.
    pub fn has_untrusted_content(&self) -> bool {
        self.contains(TaintLabel::UntrustedContent)
    }

    /// Returns true when the session is influenced by private data.
    pub fn has_private_data(&self) -> bool {
        self.contains(TaintLabel::PrivateData)
    }

    /// Returns true when both untrusted content and private data are present.
    pub fn is_conflicted_for_egress(&self) -> bool {
        self.has_untrusted_content() && self.has_private_data()
    }

    /// Evaluates external egress with an explicit conflicted-egress policy.
    ///
    /// - no conflict: [`TaintDecision::Allow`]
    /// - conflict + [`EgressPolicy::RequireApprovalOnConflict`]: [`TaintDecision::RequireApproval`]
    /// - conflict + [`EgressPolicy::BlockOnConflict`]: [`TaintDecision::Block`]
    pub fn evaluate_egress_with(&self, policy: EgressPolicy) -> TaintDecision {
        if !self.is_conflicted_for_egress() {
            return TaintDecision::Allow;
        }
        match policy {
            EgressPolicy::RequireApprovalOnConflict => TaintDecision::RequireApproval,
            EgressPolicy::BlockOnConflict => TaintDecision::Block,
        }
    }

    /// Evaluates an external egress attempt using the default conflicted-egress policy.
    pub fn egress_decision(&self) -> TaintDecision {
        self.evaluate_egress_with(EgressPolicy::default())
    }

    /// Evaluates a target operation against taint rules with an explicit egress policy.
    ///
    /// External egress uses the provided conflicted-egress policy. Non-egress targets
    /// are allowed by taint state alone.
    pub fn evaluate_target_with(
        &self,
        target: &OperationTarget,
        egress_policy: EgressPolicy,
    ) -> TaintDecision {
        if target.is_external_egress() {
            self.evaluate_egress_with(egress_policy)
        } else {
            TaintDecision::Allow
        }
    }

    /// Evaluates a target operation against taint rules.
    ///
    /// External egress uses [`Self::egress_decision`] (conflicted egress requires
    /// approval by default). Non-egress targets are allowed by taint state alone.
    pub fn evaluate_target(&self, target: &OperationTarget) -> TaintDecision {
        self.evaluate_target_with(target, EgressPolicy::default())
    }

    /// Evaluates a named operation string with an explicit egress policy.
    pub fn evaluate_operation_with(
        &self,
        operation: &str,
        egress_policy: EgressPolicy,
    ) -> TaintDecision {
        self.evaluate_target_with(&OperationTarget::from_operation(operation), egress_policy)
    }

    /// Evaluates a named operation string; `"external_egress"` and `"egress"`
    /// are treated as external egress targets.
    pub fn evaluate_operation(&self, operation: &str) -> TaintDecision {
        self.evaluate_operation_with(operation, EgressPolicy::default())
    }

    /// Returns true when the operation is allowed without approval.
    pub fn allows_operation(&self, operation: &str) -> bool {
        self.evaluate_operation(operation).is_allowed()
    }

    /// Returns true when the operation is blocked outright.
    pub fn blocks_operation(&self, operation: &str) -> bool {
        self.evaluate_operation(operation).is_blocked()
    }

    /// Returns true when the operation requires explicit approval.
    pub fn requires_approval_for(&self, operation: &str) -> bool {
        self.evaluate_operation(operation).requires_approval()
    }
}

/// Direction/kind of taint flow in a propagation model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaintFlow {
    /// Input taints the session/context.
    InputToSession,
    /// Session/context taints an operation output/result.
    SessionToOutput,
    /// Direct data-flow from a source taint set to a sink taint set.
    DataFlow,
}

/// Propagation model describing how labels should move.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PropagationModel {
    pub flow: TaintFlow,
    pub source_labels: Vec<TaintLabel>,
    /// When true, session labels propagate wholesale to outputs.
    pub propagate_all_session_labels: bool,
}

impl PropagationModel {
    pub fn input_to_session(labels: Vec<TaintLabel>) -> Self {
        Self {
            flow: TaintFlow::InputToSession,
            source_labels: labels,
            propagate_all_session_labels: false,
        }
    }

    pub fn session_to_output() -> Self {
        Self {
            flow: TaintFlow::SessionToOutput,
            source_labels: Vec::new(),
            propagate_all_session_labels: true,
        }
    }

    pub fn data_flow(source_labels: Vec<TaintLabel>) -> Self {
        Self {
            flow: TaintFlow::DataFlow,
            source_labels,
            propagate_all_session_labels: false,
        }
    }
}

/// Pure in-memory taint propagation helper.
#[derive(Debug, Clone, Copy, Default)]
pub struct TaintPropagator;

impl TaintPropagator {
    /// Propagate labels into a session according to a model.
    pub fn propagate_into_session(model: &PropagationModel, session: &mut SessionTaint) {
        match model.flow {
            TaintFlow::InputToSession | TaintFlow::DataFlow => {
                for label in &model.source_labels {
                    session.add_label(*label);
                }
            }
            TaintFlow::SessionToOutput => {}
        }
    }

    /// Compute labels propagated to an output given a session and model.
    pub fn propagate_to_output(
        model: &PropagationModel,
        session: &SessionTaint,
    ) -> Vec<TaintLabel> {
        match model.flow {
            TaintFlow::SessionToOutput => session.labels().to_vec(),
            TaintFlow::InputToSession | TaintFlow::DataFlow => {
                if model.propagate_all_session_labels {
                    session.labels().to_vec()
                } else {
                    model
                        .source_labels
                        .iter()
                        .copied()
                        .filter(|l| session.contains(*l) || model.source_labels.contains(l))
                        .fold(Vec::new(), |mut acc, l| {
                            if !acc.contains(&l) {
                                acc.push(l);
                            }
                            acc
                        })
                }
            }
        }
    }
}

impl SessionTaint {
    /// Apply propagation model into this session (input/data-flow).
    pub fn propagate_in(&mut self, model: &PropagationModel) {
        TaintPropagator::propagate_into_session(model, self);
    }

    /// Compute output taint labels from this session using a propagation model.
    pub fn propagate_out(&self, model: &PropagationModel) -> Vec<TaintLabel> {
        TaintPropagator::propagate_to_output(model, self)
    }
}

/// Runtime integration hook for session-scoped taint state persistence/lookup.
pub trait SessionTaintStore: Send + Sync {
    fn load(&self, session_id: &str) -> Option<SessionTaint>;
    fn save(&self, session_id: &str, taint: &SessionTaint);
}

/// Simple in-memory runtime store for session taint state.
#[derive(Debug, Default)]
pub struct InMemorySessionTaintStore {
    sessions: std::sync::RwLock<std::collections::HashMap<String, SessionTaint>>,
}

impl InMemorySessionTaintStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl SessionTaintStore for InMemorySessionTaintStore {
    fn load(&self, session_id: &str) -> Option<SessionTaint> {
        self.sessions.read().ok()?.get(session_id).cloned()
    }

    fn save(&self, session_id: &str, taint: &SessionTaint) {
        if let Ok(mut sessions) = self.sessions.write() {
            sessions.insert(session_id.to_string(), taint.clone());
        }
    }
}

/// Runtime taint enforcement API: record propagation and gate operations by policy.
#[derive(Debug, Clone, Copy, Default)]
pub struct TaintEnforcer;

impl TaintEnforcer {
    /// Apply input/data-flow labels to a loaded session state.
    pub fn apply_propagation(session: &mut SessionTaint, model: &PropagationModel) {
        session.propagate_in(model);
    }

    /// Evaluate an operation against current taint with an explicit egress policy.
    pub fn enforce_operation(
        session: &SessionTaint,
        operation: &str,
        egress_policy: EgressPolicy,
    ) -> TaintDecision {
        session.evaluate_operation_with(operation, egress_policy)
    }

    /// Load session taint, apply propagation, persist, and enforce an operation.
    pub fn apply_and_enforce<S: SessionTaintStore + ?Sized>(
        store: &S,
        session_id: &str,
        propagation: Option<&PropagationModel>,
        operation: &str,
        egress_policy: EgressPolicy,
    ) -> TaintDecision {
        let mut session = store.load(session_id).unwrap_or_default();
        if let Some(model) = propagation {
            Self::apply_propagation(&mut session, model);
        }
        let decision = Self::enforce_operation(&session, operation, egress_policy);
        store.save(session_id, &session);
        decision
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tracks_labels_without_duplicates() {
        let mut taint = SessionTaint::new();
        taint.add_label(TaintLabel::UntrustedContent);
        taint.add_label(TaintLabel::UntrustedContent);
        taint.add_label(TaintLabel::PrivateData);

        assert_eq!(taint.labels().len(), 2);
        assert!(taint.contains(TaintLabel::UntrustedContent));
        assert!(taint.contains(TaintLabel::PrivateData));
    }

    #[test]
    fn update_methods_mutate_state() {
        let mut taint = SessionTaint::new();
        taint.add(TaintLabel::UntrustedContent);
        assert!(taint.has_untrusted_content());
        assert!(taint.remove_label(TaintLabel::UntrustedContent));
        assert!(!taint.has_untrusted_content());
        assert!(!taint.remove_label(TaintLabel::UntrustedContent));

        taint.add_label(TaintLabel::PrivateData);
        taint.clear();
        assert!(taint.labels().is_empty());
    }

    #[test]
    fn transition_api_reports_changes() {
        let mut taint = SessionTaint::new();
        let added = taint.apply_label(TaintLabel::UntrustedContent);
        assert!(added.changed && added.present);
        let dup = taint.apply_label(TaintLabel::UntrustedContent);
        assert!(!dup.changed && dup.present);

        let cleared = taint.clear_label(TaintLabel::UntrustedContent);
        assert!(cleared.changed && !cleared.present);
        let missing = taint.clear_label(TaintLabel::UntrustedContent);
        assert!(!missing.changed && !missing.present);

        let merged = SessionTaint::new()
            .with_label(TaintLabel::UntrustedContent)
            .with_label(TaintLabel::PrivateData);
        taint.merge(&merged);
        assert!(taint.is_conflicted_for_egress());
        let without = taint.clone().without_label(TaintLabel::PrivateData);
        assert!(!without.has_private_data());
    }

    #[test]
    fn provenance_and_summary_helpers() {
        let taint = SessionTaint::new()
            .with_label(TaintLabel::UntrustedContent)
            .with_label(TaintLabel::PrivateData);
        assert_eq!(TaintLabel::UntrustedContent.as_str(), "untrusted_content");
        assert_eq!(
            TaintLabel::PrivateData.provenance(),
            "influenced by private or sensitive data"
        );
        assert_eq!(
            taint.label_names(),
            vec!["untrusted_content", "private_data"]
        );
        let summary = taint.summary();
        assert!(!summary.is_clean());
        assert!(summary.conflicted_for_egress);
        assert_eq!(summary.label_provenance.len(), 2);
    }

    #[test]
    fn conflicted_taint_requires_approval_for_external_egress() {
        let mut taint = SessionTaint::new();
        taint.add_label(TaintLabel::UntrustedContent);
        taint.add_label(TaintLabel::PrivateData);

        assert!(taint.is_conflicted_for_egress());
        assert_eq!(
            taint.evaluate_target(&OperationTarget::ExternalEgress),
            TaintDecision::RequireApproval
        );
        assert_eq!(
            taint.evaluate_operation("external_egress"),
            TaintDecision::RequireApproval
        );
        assert_eq!(
            taint.evaluate_operation("egress"),
            TaintDecision::RequireApproval
        );
        assert!(!taint.allows_operation("external_egress"));
        assert!(taint.requires_approval_for("external_egress"));
        assert!(!taint.blocks_operation("external_egress"));
    }

    #[test]
    fn egress_policy_separates_allow_block_require_approval() {
        let conflicted = SessionTaint::new()
            .with_label(TaintLabel::UntrustedContent)
            .with_label(TaintLabel::PrivateData);
        assert_eq!(
            conflicted.evaluate_egress_with(EgressPolicy::RequireApprovalOnConflict),
            TaintDecision::RequireApproval
        );
        assert_eq!(
            conflicted.evaluate_egress_with(EgressPolicy::BlockOnConflict),
            TaintDecision::Block
        );
        assert_eq!(conflicted.egress_decision(), TaintDecision::RequireApproval);
        assert_eq!(
            conflicted.evaluate_operation_with("external_egress", EgressPolicy::BlockOnConflict),
            TaintDecision::Block
        );
        assert_eq!(
            conflicted.evaluate_target_with(
                &OperationTarget::ExternalEgress,
                EgressPolicy::BlockOnConflict
            ),
            TaintDecision::Block
        );
        assert_eq!(
            conflicted.evaluate_operation_with("local_read", EgressPolicy::BlockOnConflict),
            TaintDecision::Allow
        );

        let clean = SessionTaint::new();
        assert_eq!(
            clean.evaluate_egress_with(EgressPolicy::RequireApprovalOnConflict),
            TaintDecision::Allow
        );
        assert_eq!(
            clean.evaluate_egress_with(EgressPolicy::BlockOnConflict),
            TaintDecision::Allow
        );
    }

    #[test]
    fn non_egress_operations_allowed_even_when_conflicted() {
        let mut taint = SessionTaint::new();
        taint.add_label(TaintLabel::UntrustedContent);
        taint.add_label(TaintLabel::PrivateData);

        assert_eq!(
            taint.evaluate_target(&OperationTarget::other("local_read")),
            TaintDecision::Allow
        );
        assert!(taint.allows_operation("local_read"));
        assert_eq!(
            taint.evaluate_target(&OperationTarget::from_operation("local_write")),
            TaintDecision::Allow
        );
    }

    #[test]
    fn egress_allowed_when_not_conflicted() {
        let mut only_untrusted = SessionTaint::new();
        only_untrusted.add_label(TaintLabel::UntrustedContent);
        assert_eq!(
            only_untrusted.evaluate_target(&OperationTarget::ExternalEgress),
            TaintDecision::Allow
        );

        let mut only_private = SessionTaint::new();
        only_private.add_label(TaintLabel::PrivateData);
        assert_eq!(
            only_private.evaluate_operation("egress"),
            TaintDecision::Allow
        );

        let clean = SessionTaint::new();
        assert_eq!(
            clean.evaluate_target(&OperationTarget::ExternalEgress),
            TaintDecision::Allow
        );
    }

    #[test]
    fn propagation_models_input_output_and_data_flow() {
        let mut session = SessionTaint::new();
        let input = PropagationModel::input_to_session(vec![TaintLabel::UntrustedContent]);
        session.propagate_in(&input);
        assert!(session.has_untrusted_content());

        let df = PropagationModel::data_flow(vec![TaintLabel::PrivateData]);
        session.propagate_in(&df);
        assert!(session.is_conflicted_for_egress());

        let out_model = PropagationModel::session_to_output();
        let out = session.propagate_out(&out_model);
        assert_eq!(out.len(), 2);
        assert!(out.contains(&TaintLabel::UntrustedContent));
        assert!(out.contains(&TaintLabel::PrivateData));

        let clean = SessionTaint::new();
        assert!(clean.propagate_out(&out_model).is_empty());
    }
}
