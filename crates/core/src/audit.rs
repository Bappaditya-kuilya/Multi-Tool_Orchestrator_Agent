//! Hash-chained audit log primitives with a pluggable hash interface.
//!
//! Default hashing remains a pure in-memory FNV-1a placeholder (no external
//! crypto deps) so stronger hash implementations can be injected later.
//! A SHA-256 hasher is available behind the `sha2` feature for runtime use.
//!
//! For durable append-before-return flows, stage an entry, persist it in the
//! durable store, then append the staged entry only after persistence succeeds.
//! Verification/staging helpers are fail-closed and return `VerifyError` on
//! chain/hash mismatches without mutating the in-memory log.

/// A single audit log entry linked to the previous entry by hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEntry {
    pub seq: u64,
    pub ts: u64,
    pub task_id: String,
    pub tool: String,
    pub decision: String,
    pub reason: String,
    pub args_digest: String,
    pub result_digest: String,
    pub prev_hash: String,
    pub hash: String,
    /// Optional key/value metadata included in canonical hashing when non-empty.
    /// Canonicalization sorts metadata by key then value for deterministic hashes.
    pub metadata: Vec<(String, String)>,
}

/// Pluggable hash interface for audit chaining (placeholder for crypto hashes).
pub trait AuditHasher: Send + Sync {
    /// Stable algorithm identifier (e.g. "fnv1a64", "sha256").
    fn algorithm(&self) -> &'static str;
    /// Hash canonical bytes/text to a hex string.
    fn hash_hex(&self, input: &str) -> String;
}

/// Default dependency-free hasher (FNV-1a 64-bit).
#[derive(Debug, Clone, Copy, Default)]
pub struct Fnv1a64Hasher;

impl AuditHasher for Fnv1a64Hasher {
    fn algorithm(&self) -> &'static str {
        "fnv1a64"
    }

    fn hash_hex(&self, input: &str) -> String {
        let mut hash: u64 = 0xcbf29ce484222325;
        for b in input.as_bytes() {
            hash ^= *b as u64;
            hash = hash.wrapping_mul(0x100000001b3);
        }
        format!("{hash:016x}")
    }
}

static DEFAULT_HASHER: Fnv1a64Hasher = Fnv1a64Hasher;

/// SHA-256 audit hasher for runtime integrity chains (requires `sha2` feature).
#[cfg(feature = "sha2")]
#[derive(Debug, Clone, Copy, Default)]
pub struct Sha256Hasher;

#[cfg(feature = "sha2")]
impl AuditHasher for Sha256Hasher {
    fn algorithm(&self) -> &'static str {
        "sha256"
    }

    fn hash_hex(&self, input: &str) -> String {
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(input.as_bytes());
        hex::encode(digest)
    }
}

/// Returns the crate's preferred runtime hasher when SHA-256 support is compiled in.
/// Falls back to the deterministic in-memory FNV-1a hasher in default builds.
pub fn default_runtime_hasher() -> Box<dyn AuditHasher> {
    #[cfg(feature = "sha2")]
    {
        Box::new(Sha256Hasher)
    }
    #[cfg(not(feature = "sha2"))]
    {
        Box::new(Fnv1a64Hasher)
    }
}

/// Deterministic FNV-1a 64-bit hash over UTF-8 bytes, rendered as 16-char hex.
pub fn fnv1a_hex(input: &str) -> String {
    DEFAULT_HASHER.hash_hex(input)
}

/// Deterministic digest for args/results payloads using the legacy FNV-1a hasher.
/// Use [`digest_with`] for stronger/alternate hash algorithms.
pub fn digest(input: &str) -> String {
    fnv1a_hex(input)
}

/// Deterministic digest for args/results payloads using a pluggable hasher.
pub fn digest_with<H: AuditHasher + ?Sized>(hasher: &H, input: &str) -> String {
    hasher.hash_hex(input)
}

/// SHA-256 digest helper when the `sha2` feature is enabled.
#[cfg(feature = "sha2")]
pub fn digest_sha256(input: &str) -> String {
    digest_with(&Sha256Hasher, input)
}

/// Digest consistency helper: prefer precomputed digest, else hash raw payload.
pub fn digest_or_raw(digest_value: Option<&str>, raw: &str) -> String {
    match digest_value {
        Some(d) if !d.is_empty() => d.to_string(),
        _ => digest(raw),
    }
}

/// Digest consistency helper using a pluggable hasher for raw payload fallback.
pub fn digest_or_raw_with<H: AuditHasher + ?Sized>(
    hasher: &H,
    digest_value: Option<&str>,
    raw: &str,
) -> String {
    match digest_value {
        Some(d) if !d.is_empty() => d.to_string(),
        _ => digest_with(hasher, raw),
    }
}

/// Builder for creating consistent audit entries.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AuditEventBuilder {
    pub ts: u64,
    pub task_id: String,
    pub tool: String,
    pub decision: String,
    pub reason: String,
    pub args_digest: String,
    pub result_digest: String,
    pub metadata: Vec<(String, String)>,
}

impl AuditEventBuilder {
    pub fn new(
        task_id: impl Into<String>,
        tool: impl Into<String>,
        decision: impl Into<String>,
    ) -> Self {
        Self {
            task_id: task_id.into(),
            tool: tool.into(),
            decision: decision.into(),
            ..Self::default()
        }
    }

    pub fn ts(mut self, ts: u64) -> Self {
        self.ts = ts;
        self
    }

    pub fn reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = reason.into();
        self
    }

    pub fn args_digest(mut self, args_digest: impl Into<String>) -> Self {
        self.args_digest = args_digest.into();
        self
    }

    pub fn result_digest(mut self, result_digest: impl Into<String>) -> Self {
        self.result_digest = result_digest.into();
        self
    }

    pub fn args_raw(mut self, raw: &str) -> Self {
        self.args_digest = digest(raw);
        self
    }

    pub fn result_raw(mut self, raw: &str) -> Self {
        self.result_digest = digest(raw);
        self
    }

    pub fn args_raw_with<H: AuditHasher + ?Sized>(mut self, hasher: &H, raw: &str) -> Self {
        self.args_digest = digest_with(hasher, raw);
        self
    }

    pub fn result_raw_with<H: AuditHasher + ?Sized>(mut self, hasher: &H, raw: &str) -> Self {
        self.result_digest = digest_with(hasher, raw);
        self
    }

    /// Add a metadata key/value pair (included in canonical hash when present).
    pub fn meta(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.push((key.into(), value.into()));
        self
    }

    /// Replace metadata entries.
    pub fn with_metadata(mut self, metadata: Vec<(String, String)>) -> Self {
        self.metadata = metadata;
        self
    }

    /// Stage a fully hashed entry using the default hasher without mutating the log.
    /// Useful for append-before-return durable flows (persist, then append).
    pub fn stage(self, entries: &[AuditEntry]) -> AuditEntry {
        stage_entry_with(
            entries,
            &DEFAULT_HASHER,
            self.ts,
            self.task_id,
            self.tool,
            self.decision,
            self.reason,
            self.args_digest,
            self.result_digest,
            self.metadata,
        )
    }

    /// Stage a fully hashed entry using a pluggable hasher without mutating the log.
    pub fn stage_with<H: AuditHasher + ?Sized>(
        self,
        entries: &[AuditEntry],
        hasher: &H,
    ) -> AuditEntry {
        stage_entry_with(
            entries,
            hasher,
            self.ts,
            self.task_id,
            self.tool,
            self.decision,
            self.reason,
            self.args_digest,
            self.result_digest,
            self.metadata,
        )
    }

    /// Stage a fully hashed entry continuing from an explicit durable chain state.
    pub fn stage_continuing<H: AuditHasher + ?Sized>(
        self,
        hasher: &H,
        state: ChainState,
    ) -> AuditEntry {
        stage_entry_with_continuing(
            hasher,
            state,
            self.ts,
            self.task_id,
            self.tool,
            self.decision,
            self.reason,
            self.args_digest,
            self.result_digest,
            self.metadata,
        )
    }

    /// Append using this builder, producing a chained entry.
    /// Panics only if staging/append invariants are violated (programmer error).
    /// Prefer [`Self::try_append`] for live fail-closed enforcement flows.
    pub fn append(self, entries: &mut Vec<AuditEntry>) -> &AuditEntry {
        self.try_append(entries)
            .expect("staged entry must link to current tail")
    }

    /// Fail-closed append using this builder, returning linkage/hash errors.
    pub fn try_append(self, entries: &mut Vec<AuditEntry>) -> Result<&AuditEntry, VerifyError> {
        let entry = self.stage(entries);
        append_staged(entries, entry)
    }

    /// Append using this builder and a pluggable hasher.
    /// Panics only if staging/append invariants are violated (programmer error).
    /// Prefer [`Self::try_append_with`] for live fail-closed enforcement flows.
    pub fn append_with<'a, H: AuditHasher + ?Sized>(
        self,
        entries: &'a mut Vec<AuditEntry>,
        hasher: &H,
    ) -> &'a AuditEntry {
        self.try_append_with(entries, hasher)
            .expect("staged entry must link to current tail for hasher")
    }

    /// Fail-closed append using this builder and hasher, returning linkage/hash errors.
    pub fn try_append_with<'a, H: AuditHasher + ?Sized>(
        self,
        entries: &'a mut Vec<AuditEntry>,
        hasher: &H,
    ) -> Result<&'a AuditEntry, VerifyError> {
        let entry = self.stage_with(entries, hasher);
        append_staged_with(entries, hasher, entry)
    }

    /// Append using this builder from an explicit durable continuation state.
    /// Validates against `state` (not necessarily `entries` tail), enabling segment building.
    /// Panics only if staging/append invariants are violated (programmer error).
    /// Prefer [`Self::try_append_continuing`] for live fail-closed enforcement flows.
    pub fn append_continuing(
        self,
        entries: &mut Vec<AuditEntry>,
        state: ChainState,
    ) -> &AuditEntry {
        self.try_append_continuing(entries, state)
            .expect("continuation entry must match expected state")
    }

    /// Fail-closed continuation append from an explicit durable state.
    pub fn try_append_continuing(
        self,
        entries: &mut Vec<AuditEntry>,
        state: ChainState,
    ) -> Result<&AuditEntry, VerifyError> {
        let expected = state.clone();
        let entry = self.stage_continuing(&DEFAULT_HASHER, state);
        append_staged_continuing(entries, expected, entry)
    }

    /// Append using this builder and hasher from an explicit durable continuation state.
    /// Validates against `state` (not necessarily `entries` tail), enabling segment building.
    /// Panics only if staging/append invariants are violated (programmer error).
    /// Prefer [`Self::try_append_continuing_with`] for live fail-closed enforcement flows.
    pub fn append_continuing_with<'a, H: AuditHasher + ?Sized>(
        self,
        entries: &'a mut Vec<AuditEntry>,
        hasher: &H,
        state: ChainState,
    ) -> &'a AuditEntry {
        self.try_append_continuing_with(entries, hasher, state)
            .expect("continuation entry must match expected state for hasher")
    }

    /// Fail-closed continuation append from an explicit durable state with a pluggable hasher.
    pub fn try_append_continuing_with<'a, H: AuditHasher + ?Sized>(
        self,
        entries: &'a mut Vec<AuditEntry>,
        hasher: &H,
        state: ChainState,
    ) -> Result<&'a AuditEntry, VerifyError> {
        let expected = state.clone();
        let entry = self.stage_continuing(hasher, state);
        append_staged_continuing_with(entries, hasher, expected, entry)
    }
}

impl AuditEntry {
    /// Canonical serialized form used for hashing (field order is fixed).
    /// When metadata is non-empty, a deterministic sorted metadata section is appended.
    pub fn canonical_payload(&self) -> String {
        let mut payload = format!(
            "seq={}\nts={}\ntask_id={}\ntool={}\ndecision={}\nreason={}\nargs_digest={}\nresult_digest={}\nprev_hash={}",
            self.seq,
            self.ts,
            self.task_id,
            self.tool,
            self.decision,
            self.reason,
            self.args_digest,
            self.result_digest,
            self.prev_hash
        );
        if !self.metadata.is_empty() {
            let meta = canonical_metadata(&self.metadata);
            payload.push_str(&format!("\nmeta_count={}", meta.len()));
            for (idx, (k, v)) in meta.iter().enumerate() {
                payload.push_str(&format!("\nmeta.{idx}.key={k}\nmeta.{idx}.value={v}"));
            }
        }
        payload
    }

    /// Compute this entry's hash from its canonical payload using the default hasher.
    pub fn compute_hash(&self) -> String {
        self.compute_hash_with(&DEFAULT_HASHER)
    }

    /// Compute this entry's hash from its canonical payload using a pluggable hasher.
    pub fn compute_hash_with<H: AuditHasher + ?Sized>(&self, hasher: &H) -> String {
        hasher.hash_hex(&self.canonical_payload())
    }

    /// True when stored hash matches recomputed canonical hash.
    pub fn hash_consistent(&self) -> bool {
        self.hash_consistent_with(&DEFAULT_HASHER)
    }

    /// True when stored hash matches recomputed canonical hash for a given hasher.
    pub fn hash_consistent_with<H: AuditHasher + ?Sized>(&self, hasher: &H) -> bool {
        self.hash == self.compute_hash_with(hasher)
    }

    /// True when digests look consistent with deterministic digest format.
    /// Accepts legacy 16-hex digests and stronger 32/64-hex digests.
    pub fn digests_well_formed(&self) -> bool {
        fn is_hex_digest(s: &str) -> bool {
            matches!(s.len(), 16 | 32 | 64) && s.chars().all(|c| c.is_ascii_hexdigit())
        }
        (self.args_digest.is_empty() || is_hex_digest(&self.args_digest))
            && (self.result_digest.is_empty() || is_hex_digest(&self.result_digest))
    }
}

/// Deterministic canonical metadata ordering used in hash payloads.
pub fn canonical_metadata(metadata: &[(String, String)]) -> Vec<(String, String)> {
    let mut out = metadata.to_vec();
    out.sort();
    out
}

/// Append a new hash-chained entry using the default hasher.
#[allow(clippy::too_many_arguments)]
pub fn append_entry(
    entries: &mut Vec<AuditEntry>,
    ts: u64,
    task_id: impl Into<String>,
    tool: impl Into<String>,
    decision: impl Into<String>,
    reason: impl Into<String>,
    args_digest: impl Into<String>,
    result_digest: impl Into<String>,
) -> &AuditEntry {
    append_entry_with(
        entries,
        &DEFAULT_HASHER,
        ts,
        task_id,
        tool,
        decision,
        reason,
        args_digest,
        result_digest,
    )
}

/// Append a new hash-chained entry using a pluggable hasher.
#[allow(clippy::too_many_arguments)]
pub fn append_entry_with<'a, H: AuditHasher + ?Sized>(
    entries: &'a mut Vec<AuditEntry>,
    hasher: &H,
    ts: u64,
    task_id: impl Into<String>,
    tool: impl Into<String>,
    decision: impl Into<String>,
    reason: impl Into<String>,
    args_digest: impl Into<String>,
    result_digest: impl Into<String>,
) -> &'a AuditEntry {
    let entry = stage_entry_with(
        entries,
        hasher,
        ts,
        task_id,
        tool,
        decision,
        reason,
        args_digest,
        result_digest,
        Vec::new(),
    );
    append_staged_with(entries, hasher, entry).expect("staged entry must link to current tail")
}

/// Stage a fully chained, hashed entry from the current tail without mutating the log.
#[allow(clippy::too_many_arguments)]
pub fn stage_entry_with<H: AuditHasher + ?Sized>(
    entries: &[AuditEntry],
    hasher: &H,
    ts: u64,
    task_id: impl Into<String>,
    tool: impl Into<String>,
    decision: impl Into<String>,
    reason: impl Into<String>,
    args_digest: impl Into<String>,
    result_digest: impl Into<String>,
    metadata: Vec<(String, String)>,
) -> AuditEntry {
    stage_entry_with_continuing(
        hasher,
        ChainState::from_tail(entries),
        ts,
        task_id,
        tool,
        decision,
        reason,
        args_digest,
        result_digest,
        metadata,
    )
}

/// Stage a fully chained, hashed entry from the current tail using the default hasher.
#[allow(clippy::too_many_arguments)]
pub fn stage_entry(
    entries: &[AuditEntry],
    ts: u64,
    task_id: impl Into<String>,
    tool: impl Into<String>,
    decision: impl Into<String>,
    reason: impl Into<String>,
    args_digest: impl Into<String>,
    result_digest: impl Into<String>,
    metadata: Vec<(String, String)>,
) -> AuditEntry {
    stage_entry_with(
        entries,
        &DEFAULT_HASHER,
        ts,
        task_id,
        tool,
        decision,
        reason,
        args_digest,
        result_digest,
        metadata,
    )
}

/// Stage a fully chained, hashed entry from an explicit durable continuation state.
#[allow(clippy::too_many_arguments)]
pub fn stage_entry_with_continuing<H: AuditHasher + ?Sized>(
    hasher: &H,
    state: ChainState,
    ts: u64,
    task_id: impl Into<String>,
    tool: impl Into<String>,
    decision: impl Into<String>,
    reason: impl Into<String>,
    args_digest: impl Into<String>,
    result_digest: impl Into<String>,
    metadata: Vec<(String, String)>,
) -> AuditEntry {
    let mut entry = AuditEntry {
        seq: state.next_seq,
        ts,
        task_id: task_id.into(),
        tool: tool.into(),
        decision: decision.into(),
        reason: reason.into(),
        args_digest: args_digest.into(),
        result_digest: result_digest.into(),
        prev_hash: state.prev_hash,
        hash: String::new(),
        metadata,
    };
    entry.hash = entry.compute_hash_with(hasher);
    entry
}

/// Stage a fully chained, hashed entry from an explicit continuation state using the default hasher.
#[allow(clippy::too_many_arguments)]
pub fn stage_entry_continuing(
    state: ChainState,
    ts: u64,
    task_id: impl Into<String>,
    tool: impl Into<String>,
    decision: impl Into<String>,
    reason: impl Into<String>,
    args_digest: impl Into<String>,
    result_digest: impl Into<String>,
    metadata: Vec<(String, String)>,
) -> AuditEntry {
    stage_entry_with_continuing(
        &DEFAULT_HASHER,
        state,
        ts,
        task_id,
        tool,
        decision,
        reason,
        args_digest,
        result_digest,
        metadata,
    )
}

/// Append a pre-staged entry, verifying linkage/hash against the current tail (default hasher).
pub fn append_staged(
    entries: &mut Vec<AuditEntry>,
    entry: AuditEntry,
) -> Result<&AuditEntry, VerifyError> {
    append_staged_with(entries, &DEFAULT_HASHER, entry)
}

/// Append a pre-staged entry, verifying linkage/hash against the current tail for a hasher.
/// Fail-closed: rejects seq/prev_hash/hash mismatches without mutating the log.
pub fn append_staged_with<'a, H: AuditHasher + ?Sized>(
    entries: &'a mut Vec<AuditEntry>,
    hasher: &H,
    entry: AuditEntry,
) -> Result<&'a AuditEntry, VerifyError> {
    let expected_state = ChainState::from_tail(entries);
    append_staged_continuing_with(entries, hasher, expected_state, entry)
}

/// Append a pre-staged entry continuing from an explicit expected state (default hasher).
/// Fail-closed: validates entry seq/prev_hash/hash against `expected_state` and hasher.
pub fn append_staged_continuing(
    entries: &mut Vec<AuditEntry>,
    expected_state: ChainState,
    entry: AuditEntry,
) -> Result<&AuditEntry, VerifyError> {
    append_staged_continuing_with(entries, &DEFAULT_HASHER, expected_state, entry)
}

/// Append a pre-staged entry continuing from an explicit expected state for a hasher.
/// Fail-closed: validates entry seq/prev_hash/hash against `expected_state` and hasher.
pub fn append_staged_continuing_with<'a, H: AuditHasher + ?Sized>(
    entries: &'a mut Vec<AuditEntry>,
    hasher: &H,
    expected_state: ChainState,
    entry: AuditEntry,
) -> Result<&'a AuditEntry, VerifyError> {
    let index = entries.len();
    if entry.seq != expected_state.next_seq {
        return Err(VerifyError {
            index,
            kind: VerifyErrorKind::SeqMismatch {
                expected: expected_state.next_seq,
                found: entry.seq,
            },
        });
    }
    if entry.prev_hash != expected_state.prev_hash {
        return Err(VerifyError {
            index,
            kind: VerifyErrorKind::PrevHashMismatch {
                expected: expected_state.prev_hash,
                found: entry.prev_hash,
            },
        });
    }
    let computed = entry.compute_hash_with(hasher);
    if computed != entry.hash {
        return Err(VerifyError {
            index,
            kind: VerifyErrorKind::HashMismatch {
                expected: computed,
                found: entry.hash,
            },
        });
    }
    entries.push(entry);
    Ok(entries.last().expect("just pushed"))
}

/// Try to append a new hash-chained entry (default hasher), returning fail-closed errors.
#[allow(clippy::too_many_arguments)]
pub fn try_append_entry(
    entries: &mut Vec<AuditEntry>,
    ts: u64,
    task_id: impl Into<String>,
    tool: impl Into<String>,
    decision: impl Into<String>,
    reason: impl Into<String>,
    args_digest: impl Into<String>,
    result_digest: impl Into<String>,
) -> Result<&AuditEntry, VerifyError> {
    try_append_entry_with(
        entries,
        &DEFAULT_HASHER,
        ts,
        task_id,
        tool,
        decision,
        reason,
        args_digest,
        result_digest,
    )
}

/// Try to append a new hash-chained entry with a pluggable hasher, returning fail-closed errors.
#[allow(clippy::too_many_arguments)]
pub fn try_append_entry_with<'a, H: AuditHasher + ?Sized>(
    entries: &'a mut Vec<AuditEntry>,
    hasher: &H,
    ts: u64,
    task_id: impl Into<String>,
    tool: impl Into<String>,
    decision: impl Into<String>,
    reason: impl Into<String>,
    args_digest: impl Into<String>,
    result_digest: impl Into<String>,
) -> Result<&'a AuditEntry, VerifyError> {
    let entry = stage_entry_with(
        entries,
        hasher,
        ts,
        task_id,
        tool,
        decision,
        reason,
        args_digest,
        result_digest,
        Vec::new(),
    );
    append_staged_with(entries, hasher, entry)
}

/// Try to append a new hash-chained entry continuing from an explicit durable chain state.
#[allow(clippy::too_many_arguments)]
pub fn try_append_entry_continuing(
    entries: &mut Vec<AuditEntry>,
    state: ChainState,
    ts: u64,
    task_id: impl Into<String>,
    tool: impl Into<String>,
    decision: impl Into<String>,
    reason: impl Into<String>,
    args_digest: impl Into<String>,
    result_digest: impl Into<String>,
) -> Result<&AuditEntry, VerifyError> {
    try_append_entry_with_continuing(
        entries,
        &DEFAULT_HASHER,
        state,
        ts,
        task_id,
        tool,
        decision,
        reason,
        args_digest,
        result_digest,
    )
}

/// Try to append a continuation entry with a pluggable hasher, returning fail-closed errors.
#[allow(clippy::too_many_arguments)]
pub fn try_append_entry_with_continuing<'a, H: AuditHasher + ?Sized>(
    entries: &'a mut Vec<AuditEntry>,
    hasher: &H,
    state: ChainState,
    ts: u64,
    task_id: impl Into<String>,
    tool: impl Into<String>,
    decision: impl Into<String>,
    reason: impl Into<String>,
    args_digest: impl Into<String>,
    result_digest: impl Into<String>,
) -> Result<&'a AuditEntry, VerifyError> {
    let expected = state.clone();
    let entry = stage_entry_with_continuing(
        hasher,
        state,
        ts,
        task_id,
        tool,
        decision,
        reason,
        args_digest,
        result_digest,
        Vec::new(),
    );
    append_staged_continuing_with(entries, hasher, expected, entry)
}

/// First entry in the chain.
pub fn chain_head(entries: &[AuditEntry]) -> Option<&AuditEntry> {
    entries.first()
}

/// Last entry in the chain.
pub fn chain_tail(entries: &[AuditEntry]) -> Option<&AuditEntry> {
    entries.last()
}

/// Filter entries by task id.
pub fn filter_by_task_id<'a>(entries: &'a [AuditEntry], task_id: &str) -> Vec<&'a AuditEntry> {
    entries.iter().filter(|e| e.task_id == task_id).collect()
}

/// Filter entries by tool name.
pub fn filter_by_tool<'a>(entries: &'a [AuditEntry], tool: &str) -> Vec<&'a AuditEntry> {
    entries.iter().filter(|e| e.tool == tool).collect()
}

/// Filter entries by decision.
pub fn filter_by_decision<'a>(entries: &'a [AuditEntry], decision: &str) -> Vec<&'a AuditEntry> {
    entries.iter().filter(|e| e.decision == decision).collect()
}

/// Find an entry by sequence number.
pub fn find_by_seq(entries: &[AuditEntry], seq: u64) -> Option<&AuditEntry> {
    entries.iter().find(|e| e.seq == seq)
}

/// Durable chain cursor/state for appending or verifying continuation segments.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ChainState {
    pub next_seq: u64,
    pub prev_hash: String,
}

impl ChainState {
    pub fn genesis() -> Self {
        Self {
            next_seq: 0,
            prev_hash: "genesis".to_string(),
        }
    }

    pub fn is_genesis(&self) -> bool {
        self.next_seq == 0 && self.prev_hash == "genesis"
    }

    pub fn from_tail(entries: &[AuditEntry]) -> Self {
        match entries.last() {
            Some(tail) => Self::after_entry(tail),
            None => Self::genesis(),
        }
    }

    /// State cursor immediately after a known entry.
    pub fn after_entry(entry: &AuditEntry) -> Self {
        Self {
            next_seq: entry.seq.saturating_add(1),
            prev_hash: entry.hash.clone(),
        }
    }

    /// Fail-closed continuation cursor: verifies the full chain before returning tail state.
    pub fn from_tail_verified(entries: &[AuditEntry]) -> Result<Self, VerifyError> {
        Self::from_tail_verified_with(entries, &DEFAULT_HASHER)
    }

    /// Fail-closed continuation cursor with a pluggable hasher.
    pub fn from_tail_verified_with<H: AuditHasher + ?Sized>(
        entries: &[AuditEntry],
        hasher: &H,
    ) -> Result<Self, VerifyError> {
        verify_chain_detailed_with(entries, hasher)?;
        Ok(Self::from_tail(entries))
    }

    /// Return the next state after appending an entry with the given hash.
    pub fn advanced(&self, hash: impl Into<String>) -> Self {
        Self {
            next_seq: self.next_seq.saturating_add(1),
            prev_hash: hash.into(),
        }
    }
}

/// Returns the crate's preferred runtime hash algorithm identifier.
pub fn default_runtime_algorithm() -> &'static str {
    #[cfg(feature = "sha2")]
    {
        "sha256"
    }
    #[cfg(not(feature = "sha2"))]
    {
        "fnv1a64"
    }
}

/// Returns a runtime hasher for a requested algorithm when supported.
/// Supported: "sha256" (with `sha2` feature), "fnv1a64". Unknown algorithms return `None`.
pub fn runtime_hasher(algorithm: &str) -> Option<Box<dyn AuditHasher>> {
    match algorithm {
        "fnv1a64" => Some(Box::new(Fnv1a64Hasher)),
        #[cfg(feature = "sha2")]
        "sha256" => Some(Box::new(Sha256Hasher)),
        _ => None,
    }
}

/// SHA-256 runtime hasher hook when compiled with `sha2` support.
#[cfg(feature = "sha2")]
pub fn sha256_runtime_hasher() -> Sha256Hasher {
    Sha256Hasher
}

/// Append a new hash-chained entry continuing from an explicit durable chain state.
#[allow(clippy::too_many_arguments)]
pub fn append_entry_continuing(
    entries: &mut Vec<AuditEntry>,
    state: ChainState,
    ts: u64,
    task_id: impl Into<String>,
    tool: impl Into<String>,
    decision: impl Into<String>,
    reason: impl Into<String>,
    args_digest: impl Into<String>,
    result_digest: impl Into<String>,
) -> &AuditEntry {
    append_entry_with_continuing(
        entries,
        &DEFAULT_HASHER,
        state,
        ts,
        task_id,
        tool,
        decision,
        reason,
        args_digest,
        result_digest,
    )
}

/// Append a new hash-chained entry continuing from an explicit durable chain state
/// using a pluggable hasher.
#[allow(clippy::too_many_arguments)]
pub fn append_entry_with_continuing<'a, H: AuditHasher + ?Sized>(
    entries: &'a mut Vec<AuditEntry>,
    hasher: &H,
    state: ChainState,
    ts: u64,
    task_id: impl Into<String>,
    tool: impl Into<String>,
    decision: impl Into<String>,
    reason: impl Into<String>,
    args_digest: impl Into<String>,
    result_digest: impl Into<String>,
) -> &'a AuditEntry {
    let expected = state.clone();
    let entry = stage_entry_with_continuing(
        hasher,
        state,
        ts,
        task_id,
        tool,
        decision,
        reason,
        args_digest,
        result_digest,
        Vec::new(),
    );
    append_staged_continuing_with(entries, hasher, expected, entry)
        .expect("continuation entry must match expected state")
}

/// Verify a chain segment that continues from a known durable cursor.
pub fn verify_chain_continuation(
    entries: &[AuditEntry],
    expected_start_seq: u64,
    expected_prev_hash: &str,
) -> Result<(), VerifyError> {
    verify_chain_continuation_with(
        entries,
        &DEFAULT_HASHER,
        expected_start_seq,
        expected_prev_hash,
    )
}

/// Verify a chain segment continuation using a pluggable hasher.
pub fn verify_chain_continuation_with<H: AuditHasher + ?Sized>(
    entries: &[AuditEntry],
    hasher: &H,
    expected_start_seq: u64,
    expected_prev_hash: &str,
) -> Result<(), VerifyError> {
    verify_chain_continuation_state_with(entries, hasher, expected_start_seq, expected_prev_hash)
        .map(|_| ())
}

/// Verify a chain segment continuation and return the end state for durable replay/append.
pub fn verify_chain_continuation_state(
    entries: &[AuditEntry],
    expected_start_seq: u64,
    expected_prev_hash: &str,
) -> Result<ChainState, VerifyError> {
    verify_chain_continuation_state_with(
        entries,
        &DEFAULT_HASHER,
        expected_start_seq,
        expected_prev_hash,
    )
}

/// Verify a chain segment continuation with a pluggable hasher and return the end state.
pub fn verify_chain_continuation_state_with<H: AuditHasher + ?Sized>(
    entries: &[AuditEntry],
    hasher: &H,
    expected_start_seq: u64,
    expected_prev_hash: &str,
) -> Result<ChainState, VerifyError> {
    let mut expected_seq = expected_start_seq;
    let mut expected_prev = expected_prev_hash.to_string();
    for (index, entry) in entries.iter().enumerate() {
        if entry.seq != expected_seq {
            return Err(VerifyError {
                index,
                kind: VerifyErrorKind::SeqMismatch {
                    expected: expected_seq,
                    found: entry.seq,
                },
            });
        }
        if entry.prev_hash != expected_prev {
            return Err(VerifyError {
                index,
                kind: VerifyErrorKind::PrevHashMismatch {
                    expected: expected_prev,
                    found: entry.prev_hash.clone(),
                },
            });
        }
        let computed = entry.compute_hash_with(hasher);
        if computed != entry.hash {
            return Err(VerifyError {
                index,
                kind: VerifyErrorKind::HashMismatch {
                    expected: computed,
                    found: entry.hash.clone(),
                },
            });
        }
        expected_prev = entry.hash.clone();
        expected_seq = expected_seq.saturating_add(1);
    }
    Ok(ChainState {
        next_seq: expected_seq,
        prev_hash: expected_prev,
    })
}

/// Chain verification failure with the failing index and reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyError {
    pub index: usize,
    pub kind: VerifyErrorKind,
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "audit verify error at index {}: {}",
            self.index, self.kind
        )
    }
}

impl std::error::Error for VerifyError {}

/// Specific reason a chain failed verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyErrorKind {
    SeqMismatch { expected: u64, found: u64 },
    PrevHashMismatch { expected: String, found: String },
    HashMismatch { expected: String, found: String },
}

impl std::fmt::Display for VerifyErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SeqMismatch { expected, found } => {
                write!(f, "sequence mismatch (expected {expected}, found {found})")
            }
            Self::PrevHashMismatch { expected, found } => {
                write!(f, "prev_hash mismatch (expected {expected}, found {found})")
            }
            Self::HashMismatch { expected, found } => {
                write!(f, "hash mismatch (expected {expected}, found {found})")
            }
        }
    }
}

/// Verify chain integrity and report the first failing index, if any.
pub fn verify_chain_detailed(entries: &[AuditEntry]) -> Result<(), VerifyError> {
    verify_chain_detailed_with(entries, &DEFAULT_HASHER)
}

/// Verify chain integrity using a pluggable hasher.
pub fn verify_chain_detailed_with<H: AuditHasher + ?Sized>(
    entries: &[AuditEntry],
    hasher: &H,
) -> Result<(), VerifyError> {
    let mut expected_prev = "genesis".to_string();
    for (expected_seq, (index, entry)) in entries.iter().enumerate().enumerate() {
        let expected_seq = expected_seq as u64;
        if entry.seq != expected_seq {
            return Err(VerifyError {
                index,
                kind: VerifyErrorKind::SeqMismatch {
                    expected: expected_seq,
                    found: entry.seq,
                },
            });
        }
        if entry.prev_hash != expected_prev {
            return Err(VerifyError {
                index,
                kind: VerifyErrorKind::PrevHashMismatch {
                    expected: expected_prev,
                    found: entry.prev_hash.clone(),
                },
            });
        }
        let computed = entry.compute_hash_with(hasher);
        if computed != entry.hash {
            return Err(VerifyError {
                index,
                kind: VerifyErrorKind::HashMismatch {
                    expected: computed,
                    found: entry.hash.clone(),
                },
            });
        }
        expected_prev = entry.hash.clone();
    }
    Ok(())
}

/// Verify chain integrity and return the end continuation state for fail-closed live flows.
pub fn verify_chain_state(entries: &[AuditEntry]) -> Result<ChainState, VerifyError> {
    verify_chain_state_with(entries, &DEFAULT_HASHER)
}

/// Verify chain integrity with a pluggable hasher and return the end continuation state.
pub fn verify_chain_state_with<H: AuditHasher + ?Sized>(
    entries: &[AuditEntry],
    hasher: &H,
) -> Result<ChainState, VerifyError> {
    verify_chain_detailed_with(entries, hasher)?;
    Ok(ChainState::from_tail(entries))
}

/// Verify chain integrity: seq continuity, prev_hash linkage, and recomputed hashes.
pub fn verify_chain(entries: &[AuditEntry]) -> bool {
    verify_chain_with(entries, &DEFAULT_HASHER)
}

/// Verify chain integrity using a pluggable hasher.
pub fn verify_chain_with<H: AuditHasher + ?Sized>(entries: &[AuditEntry], hasher: &H) -> bool {
    verify_chain_detailed_with(entries, hasher).is_ok()
}

/// Verify a contiguous subrange [start, end) of a chain.
pub fn verify_chain_range(
    entries: &[AuditEntry],
    start: usize,
    end: usize,
) -> Result<(), VerifyError> {
    verify_chain_range_with(entries, &DEFAULT_HASHER, start, end)
}

/// Verify a contiguous subrange [start, end) of a chain using a pluggable hasher.
pub fn verify_chain_range_with<H: AuditHasher + ?Sized>(
    entries: &[AuditEntry],
    hasher: &H,
    start: usize,
    end: usize,
) -> Result<(), VerifyError> {
    if start >= end || end > entries.len() {
        return Ok(());
    }
    let mut expected_prev = if start == 0 {
        "genesis".to_string()
    } else {
        entries[start - 1].hash.clone()
    };
    for (expected_seq, (offset, entry)) in
        (entries[start].seq..).zip(entries[start..end].iter().enumerate())
    {
        let index = start + offset;
        if entry.seq != expected_seq {
            return Err(VerifyError {
                index,
                kind: VerifyErrorKind::SeqMismatch {
                    expected: expected_seq,
                    found: entry.seq,
                },
            });
        }
        if entry.prev_hash != expected_prev {
            return Err(VerifyError {
                index,
                kind: VerifyErrorKind::PrevHashMismatch {
                    expected: expected_prev,
                    found: entry.prev_hash.clone(),
                },
            });
        }
        let computed = entry.compute_hash_with(hasher);
        if computed != entry.hash {
            return Err(VerifyError {
                index,
                kind: VerifyErrorKind::HashMismatch {
                    expected: computed,
                    found: entry.hash.clone(),
                },
            });
        }
        expected_prev = entry.hash.clone();
    }
    Ok(())
}

/// Consistency summary for a chain (structural + digest/hash form checks).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ChainConsistency {
    pub length: usize,
    pub valid: bool,
    pub first_error: Option<VerifyError>,
    pub malformed_digest_count: usize,
}

/// Inspect a chain and report verification + digest-form consistency.
pub fn inspect_chain(entries: &[AuditEntry]) -> ChainConsistency {
    inspect_chain_with(entries, &DEFAULT_HASHER)
}

/// Inspect a chain using a pluggable hasher.
pub fn inspect_chain_with<H: AuditHasher + ?Sized>(
    entries: &[AuditEntry],
    hasher: &H,
) -> ChainConsistency {
    let first_error = verify_chain_detailed_with(entries, hasher).err();
    let malformed_digest_count = entries.iter().filter(|e| !e.digests_well_formed()).count();
    ChainConsistency {
        length: entries.len(),
        valid: first_error.is_none(),
        first_error,
        malformed_digest_count,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_chain_verifies() {
        let mut log = Vec::new();
        append_entry(
            &mut log,
            1,
            "task-1",
            "read_file",
            "allow",
            "ok",
            "args-a",
            "res-a",
        );
        append_entry(
            &mut log,
            2,
            "task-1",
            "write_file",
            "deny",
            "policy",
            "args-b",
            "res-b",
        );
        assert_eq!(log.len(), 2);
        assert_eq!(log[0].seq, 0);
        assert_eq!(log[1].seq, 1);
        assert_eq!(log[1].prev_hash, log[0].hash);
        assert!(verify_chain(&log));
        assert!(verify_chain(&[]));
        assert_eq!(verify_chain_detailed(&log), Ok(()));
    }

    #[test]
    fn tamper_edit_detected() {
        let mut log = Vec::new();
        append_entry(&mut log, 1, "t", "tool", "allow", "", "a", "r");
        append_entry(&mut log, 2, "t", "tool", "allow", "", "b", "r2");
        assert!(verify_chain(&log));
        log[0].decision = "deny".to_string();
        assert!(!verify_chain(&log));
        assert_eq!(
            verify_chain_detailed(&log),
            Err(VerifyError {
                index: 0,
                kind: VerifyErrorKind::HashMismatch {
                    expected: log[0].compute_hash(),
                    found: log[0].hash.clone(),
                },
            })
        );
    }

    #[test]
    fn broken_link_detected() {
        let mut log = Vec::new();
        append_entry(&mut log, 1, "t", "tool", "allow", "", "a", "r");
        append_entry(&mut log, 2, "t", "tool", "allow", "", "b", "r2");
        assert!(verify_chain(&log));
        log[1].prev_hash = "bogus".to_string();
        log[1].hash = log[1].compute_hash();
        assert!(!verify_chain(&log));
        assert_eq!(
            verify_chain_detailed(&log),
            Err(VerifyError {
                index: 1,
                kind: VerifyErrorKind::PrevHashMismatch {
                    expected: log[0].hash.clone(),
                    found: "bogus".to_string(),
                },
            })
        );
    }

    #[test]
    fn multi_entry_chain_and_head_tail() {
        let mut log = Vec::new();
        for i in 0..5 {
            append_entry(
                &mut log,
                i,
                "task",
                "tool",
                "allow",
                "",
                format!("a{i}"),
                format!("r{i}"),
            );
        }
        assert_eq!(log.len(), 5);
        assert!(verify_chain(&log));
        assert_eq!(chain_head(&log).unwrap().seq, 0);
        assert_eq!(chain_tail(&log).unwrap().seq, 4);
        for i in 1..log.len() {
            assert_eq!(log[i].prev_hash, log[i - 1].hash);
        }
    }

    #[test]
    fn tamper_at_middle_detected_with_index() {
        let mut log = Vec::new();
        for i in 0..4 {
            append_entry(
                &mut log,
                i,
                "task",
                "tool",
                "allow",
                "",
                format!("a{i}"),
                format!("r{i}"),
            );
        }
        assert!(verify_chain(&log));
        log[1].reason = "tampered".to_string();
        let err = verify_chain_detailed(&log).unwrap_err();
        assert_eq!(err.index, 1);
        assert!(matches!(err.kind, VerifyErrorKind::HashMismatch { .. }));
    }

    #[test]
    fn digest_stability() {
        let a = digest("hello world");
        let b = digest("hello world");
        let c = digest("hello worle");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.len(), 16);
    }

    #[test]
    fn query_helpers() {
        let mut log = Vec::new();
        append_entry(&mut log, 1, "t1", "read", "allow", "", "a", "r");
        append_entry(&mut log, 2, "t2", "write", "deny", "", "b", "r");
        append_entry(&mut log, 3, "t1", "write", "allow", "", "c", "r");
        assert_eq!(filter_by_task_id(&log, "t1").len(), 2);
        assert_eq!(filter_by_tool(&log, "write").len(), 2);
        assert_eq!(filter_by_decision(&log, "deny").len(), 1);
        assert_eq!(find_by_seq(&log, 2).unwrap().tool, "write");
        assert!(find_by_seq(&log, 99).is_none());
        assert!(chain_head(&[] as &[AuditEntry]).is_none());
        assert!(chain_tail(&[] as &[AuditEntry]).is_none());
    }

    #[test]
    fn event_builder_and_digest_consistency_helpers() {
        let mut log = Vec::new();
        let e = AuditEventBuilder::new("task-x", "tool.y", "allow")
            .ts(42)
            .reason("ok")
            .args_raw("{\"a\":1}")
            .result_raw("done")
            .append(&mut log);
        assert_eq!(e.seq, 0);
        assert_eq!(e.ts, 42);
        assert_eq!(e.task_id, "task-x");
        assert_eq!(e.args_digest, digest("{\"a\":1}"));
        assert_eq!(e.result_digest, digest("done"));
        assert!(e.hash_consistent());
        assert!(e.digests_well_formed());
        assert_eq!(
            digest_or_raw(Some(&e.args_digest), "ignored"),
            e.args_digest
        );
        assert_eq!(digest_or_raw(None, "raw"), digest("raw"));
        assert_eq!(digest_or_raw(Some(""), "raw"), digest("raw"));
    }

    #[test]
    fn digest_form_and_hash_consistency_checks() {
        let mut log = Vec::new();
        append_entry(&mut log, 1, "t", "tool", "allow", "", digest("a"), "");
        assert!(log[0].digests_well_formed());
        assert!(log[0].hash_consistent());
        log[0].args_digest = "not-a-digest".into();
        assert!(!log[0].digests_well_formed());
        log[0].hash = "bad".into();
        assert!(!log[0].hash_consistent());
    }

    #[test]
    fn verify_chain_range_and_inspect_chain() {
        let mut log = Vec::new();
        for i in 0..4 {
            append_entry(
                &mut log,
                i as u64,
                "task",
                "tool",
                "allow",
                "",
                digest(&format!("a{i}")),
                digest(&format!("r{i}")),
            );
        }
        assert_eq!(verify_chain_range(&log, 1, 3), Ok(()));
        assert_eq!(verify_chain_range(&log, 10, 12), Ok(()));

        let summary = inspect_chain(&log);
        assert_eq!(summary.length, 4);
        assert!(summary.valid);
        assert!(summary.first_error.is_none());
        assert_eq!(summary.malformed_digest_count, 0);

        log[2].args_digest = "oops".into();
        log[2].hash = log[2].compute_hash();
        // keep structural chain valid after payload/hash change
        if log.len() > 3 {
            log[3].prev_hash = log[2].hash.clone();
            log[3].hash = log[3].compute_hash();
        }
        let summary2 = inspect_chain(&log);
        assert!(summary2.valid);
        assert_eq!(summary2.malformed_digest_count, 1);

        log[1].prev_hash = "broken".into();
        log[1].hash = log[1].compute_hash();
        // propagate so linkage error is at index 1 only
        log[2].prev_hash = log[1].hash.clone();
        log[2].hash = log[2].compute_hash();
        log[3].prev_hash = log[2].hash.clone();
        log[3].hash = log[3].compute_hash();
        let err = verify_chain_range(&log, 1, 4).unwrap_err();
        assert_eq!(err.index, 1);
        let summary3 = inspect_chain(&log);
        assert!(!summary3.valid);
        assert!(summary3.first_error.is_some());
    }

    #[derive(Clone, Copy)]
    struct PrefixHasher;
    impl AuditHasher for PrefixHasher {
        fn algorithm(&self) -> &'static str {
            "prefix"
        }
        fn hash_hex(&self, input: &str) -> String {
            format!("pfx-{}", fnv1a_hex(input))
        }
    }

    #[test]
    fn pluggable_hasher_interface() {
        let hasher = PrefixHasher;
        assert_eq!(hasher.algorithm(), "prefix");
        let mut log = Vec::new();
        append_entry_with(&mut log, &hasher, 1, "t", "tool", "allow", "", "a", "b");
        append_entry_with(&mut log, &hasher, 2, "t", "tool", "allow", "", "c", "d");
        assert!(log.iter().all(|e| e.hash.starts_with("pfx-")));
        assert!(verify_chain_with(&log, &hasher));
        assert!(inspect_chain_with(&log, &hasher).valid);
        assert!(!verify_chain_with(&log, &Fnv1a64Hasher));
    }

    #[cfg(feature = "sha2")]
    #[test]
    fn sha256_hasher_chains_and_verifies() {
        let hasher = Sha256Hasher;
        assert_eq!(hasher.algorithm(), "sha256");
        let h = hasher.hash_hex("hello");
        assert_eq!(h.len(), 64);
        let mut log = Vec::new();
        append_entry_with(&mut log, &hasher, 1, "task", "tool", "allow", "", "a", "b");
        append_entry_with(&mut log, &hasher, 2, "task", "tool", "deny", "", "c", "d");
        assert!(log.iter().all(|e| e.hash.len() == 64));
        assert!(verify_chain_with(&log, &hasher));
        assert!(inspect_chain_with(&log, &hasher).valid);
        log[0].reason = "tampered".into();
        assert!(!verify_chain_with(&log, &hasher));
    }

    #[test]
    fn durable_chain_continuation_helpers() {
        let mut log = Vec::new();
        append_entry(&mut log, 1, "task", "tool", "allow", "", "a1", "r1");
        append_entry(&mut log, 2, "task", "tool", "allow", "", "a2", "r2");
        let state = ChainState::from_tail(&log);
        assert_eq!(state.next_seq, 2);
        assert_eq!(state.prev_hash, log[1].hash);

        let mut segment = Vec::new();
        append_entry_continuing(
            &mut segment,
            state.clone(),
            3,
            "task",
            "tool",
            "allow",
            "",
            "a3",
            "r3",
        );
        let prev = segment[0].hash.clone();
        append_entry_continuing(
            &mut segment,
            ChainState {
                next_seq: state.next_seq + 1,
                prev_hash: prev,
            },
            4,
            "task",
            "tool",
            "deny",
            "",
            "a4",
            "r4",
        );
        assert!(verify_chain_continuation(&segment, 2, &log[1].hash).is_ok());

        let mut full = log.clone();
        full.extend(segment.clone());
        assert!(verify_chain(&full));

        let bad = verify_chain_continuation(&segment, 3, &log[1].hash).unwrap_err();
        assert!(matches!(bad.kind, VerifyErrorKind::SeqMismatch { .. }));
    }

    #[test]
    fn metadata_is_hashed_deterministically_and_backward_compatible_when_empty() {
        let mut log_plain = Vec::new();
        AuditEventBuilder::new("t", "tool", "allow")
            .ts(1)
            .args_digest("a")
            .result_digest("r")
            .append(&mut log_plain);
        assert!(log_plain[0].metadata.is_empty());
        assert!(!log_plain[0].canonical_payload().contains("meta_count="));
        assert!(verify_chain(&log_plain));

        let mut log_meta = Vec::new();
        AuditEventBuilder::new("t", "tool", "allow")
            .ts(1)
            .args_digest("a")
            .result_digest("r")
            .with_metadata(vec![("b".into(), "2".into()), ("a".into(), "1".into())])
            .append(&mut log_meta);
        assert_eq!(
            log_meta[0].canonical_payload(),
            format!(
                "{}\nmeta_count=2\nmeta.0.key=a\nmeta.0.value=1\nmeta.1.key=b\nmeta.1.value=2",
                AuditEventBuilder::new("t", "tool", "allow")
                    .ts(1)
                    .args_digest("a")
                    .result_digest("r")
                    .stage(&[])
                    .canonical_payload()
            )
        );
        assert_ne!(log_plain[0].hash, log_meta[0].hash);
        assert!(verify_chain(&log_meta));

        let mut log_meta_reordered = Vec::new();
        AuditEventBuilder::new("t", "tool", "allow")
            .ts(1)
            .args_digest("a")
            .result_digest("r")
            .meta("a", "1")
            .meta("b", "2")
            .append(&mut log_meta_reordered);
        assert_eq!(log_meta[0].hash, log_meta_reordered[0].hash);
    }

    #[test]
    fn stage_and_append_staged_support_append_before_return_and_fail_closed() {
        let mut log = Vec::new();
        append_entry(&mut log, 1, "task", "tool", "allow", "", "a1", "r1");

        let staged = AuditEventBuilder::new("task", "tool", "allow")
            .ts(2)
            .args_digest("a2")
            .result_digest("r2")
            .meta("durable", "pending")
            .stage(&log);
        assert_eq!(log.len(), 1, "staging must not mutate log");
        assert_eq!(staged.seq, 1);
        assert_eq!(staged.prev_hash, log[0].hash);
        assert!(staged.hash_consistent());

        let mut tampered = staged.clone();
        tampered.reason = "tampered".into();
        let err = append_staged(&mut log, tampered).unwrap_err();
        assert!(matches!(err.kind, VerifyErrorKind::HashMismatch { .. }));
        assert_eq!(log.len(), 1, "failed append must not mutate log");

        append_staged(&mut log, staged).unwrap();
        assert_eq!(log.len(), 2);
        assert!(verify_chain(&log));
    }

    #[test]
    fn continuation_staging_and_state_helpers_enable_durable_segments() {
        let mut persisted = Vec::new();
        append_entry(&mut persisted, 1, "task", "tool", "allow", "", "a1", "r1");
        append_entry(&mut persisted, 2, "task", "tool", "allow", "", "a2", "r2");
        let cursor = ChainState::from_tail(&persisted);
        assert_eq!(cursor, ChainState::after_entry(persisted.last().unwrap()));

        let staged = AuditEventBuilder::new("task", "tool", "allow")
            .ts(3)
            .args_digest("a3")
            .result_digest("r3")
            .stage_continuing(&DEFAULT_HASHER, cursor.clone());
        assert_eq!(staged.seq, cursor.next_seq);
        assert_eq!(staged.prev_hash, cursor.prev_hash);
        let next = cursor.advanced(staged.hash.clone());
        assert_eq!(next.next_seq, staged.seq + 1);
        assert_eq!(next.prev_hash, staged.hash);

        let mut segment = Vec::new();
        AuditEventBuilder::new("task", "tool", "allow")
            .ts(3)
            .args_digest("a3")
            .result_digest("r3")
            .append_continuing(&mut segment, ChainState::from_tail(&persisted));
        let mut tmp = persisted.clone();
        tmp.extend(segment.clone());
        let next_state = ChainState::from_tail(&tmp);
        AuditEventBuilder::new("task", "tool", "deny")
            .ts(4)
            .args_digest("a4")
            .result_digest("r4")
            .append_continuing(&mut segment, next_state);
        assert!(verify_chain_continuation(&segment, 2, &persisted[1].hash).is_ok());
        let mut full = persisted;
        full.extend(segment);
        assert!(verify_chain(&full));
    }

    #[test]
    fn runtime_hasher_hooks_select_supported_algorithms() {
        assert_eq!(runtime_hasher("fnv1a64").unwrap().algorithm(), "fnv1a64");
        assert!(runtime_hasher("unknown-algo").is_none());
        let algo = default_runtime_algorithm();
        let h = runtime_hasher(algo).expect("default runtime algo must be supported");
        assert_eq!(h.algorithm(), algo);
        let mut log = Vec::new();
        append_entry_with(&mut log, h.as_ref(), 1, "t", "tool", "allow", "", "a", "b");
        assert!(verify_chain_with(&log, h.as_ref()));
    }

    #[cfg(feature = "sha2")]
    #[test]
    fn runtime_sha256_hook_roundtrips() {
        assert_eq!(default_runtime_algorithm(), "sha256");
        let h = runtime_hasher("sha256").unwrap();
        assert_eq!(h.algorithm(), "sha256");
        let mut log = Vec::new();
        let e = AuditEventBuilder::new("task", "tool", "allow")
            .ts(1)
            .args_raw_with(h.as_ref(), "args")
            .result_raw_with(h.as_ref(), "result")
            .meta("integrity", "sha256")
            .append_continuing_with(&mut log, h.as_ref(), ChainState::genesis());
        assert_eq!(e.hash.len(), 64);
        assert!(verify_chain_continuation_with(&log, h.as_ref(), 0, "genesis").is_ok());
    }

    mod proptests {
        use super::*;
        use proptest::prelude::*;

        fn arb_audit_text() -> impl Strategy<Value = String> {
            "[A-Za-z0-9 _.:/-]{0,24}"
        }

        fn arb_audit_digest() -> impl Strategy<Value = String> {
            prop_oneof![
                Just(String::new()),
                "[0-9a-f]{16}",
                "[0-9a-f]{32}",
                "[0-9a-f]{64}",
                arb_audit_text(),
            ]
        }

        #[derive(Debug, Clone)]
        struct AuditEventData {
            ts: u64,
            task_id: String,
            tool: String,
            decision: String,
            reason: String,
            args_digest: String,
            result_digest: String,
        }

        fn arb_audit_event() -> impl Strategy<Value = AuditEventData> {
            (
                0u64..=1_000_000u64,
                "[A-Za-z0-9_-]{1,12}",
                "[A-Za-z0-9_.:-]{1,12}",
                prop_oneof![
                    Just("allow".to_string()),
                    Just("deny".to_string()),
                    Just("require_approval".to_string()),
                    "[A-Za-z0-9_-]{1,12}",
                ],
                arb_audit_text(),
                arb_audit_digest(),
                arb_audit_digest(),
            )
                .prop_map(
                    |(ts, task_id, tool, decision, reason, args_digest, result_digest)| {
                        AuditEventData {
                            ts,
                            task_id,
                            tool,
                            decision,
                            reason,
                            args_digest,
                            result_digest,
                        }
                    },
                )
        }

        fn build_chain(events: &[AuditEventData]) -> Vec<AuditEntry> {
            let mut log = Vec::with_capacity(events.len());
            for e in events {
                append_entry(
                    &mut log,
                    e.ts,
                    e.task_id.clone(),
                    e.tool.clone(),
                    e.decision.clone(),
                    e.reason.clone(),
                    e.args_digest.clone(),
                    e.result_digest.clone(),
                );
            }
            log
        }

        #[derive(Debug, Clone, Copy)]
        enum TamperKind {
            Decision,
            Reason,
            TaskId,
            Tool,
            ArgsDigest,
            ResultDigest,
            Timestamp,
            Seq,
            PrevHashKeepHash,
            PrevHashRecompute,
        }

        fn apply_tamper(mut log: Vec<AuditEntry>, idx: usize, kind: TamperKind) -> Vec<AuditEntry> {
            match kind {
                TamperKind::Decision => log[idx].decision.push_str("_tampered"),
                TamperKind::Reason => log[idx].reason.push_str("_tampered"),
                TamperKind::TaskId => log[idx].task_id.push_str("_tampered"),
                TamperKind::Tool => log[idx].tool.push_str("_tampered"),
                TamperKind::ArgsDigest => log[idx].args_digest.push('f'),
                TamperKind::ResultDigest => log[idx].result_digest.push('f'),
                TamperKind::Timestamp => log[idx].ts = log[idx].ts.saturating_add(1),
                TamperKind::Seq => log[idx].seq = log[idx].seq.saturating_add(99),
                TamperKind::PrevHashKeepHash => log[idx].prev_hash = "tampered-prev".to_string(),
                TamperKind::PrevHashRecompute => {
                    log[idx].prev_hash = "tampered-prev".to_string();
                    log[idx].hash = log[idx].compute_hash();
                }
            }
            log
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(96))]

            /// Appending arbitrary events produces a valid, verifiable hash chain.
            #[test]
            fn audit_append_and_verify_succeeds(
                events in prop::collection::vec(arb_audit_event(), 0..30),
            ) {
                let log = build_chain(&events);
                prop_assert!(verify_chain(&log));
                prop_assert_eq!(verify_chain_detailed(&log), Ok(()));

                for (i, entry) in log.iter().enumerate() {
                    prop_assert_eq!(entry.seq, i as u64);
                    if i == 0 {
                        prop_assert_eq!(&entry.prev_hash, "genesis");
                    } else {
                        prop_assert_eq!(&entry.prev_hash, &log[i - 1].hash);
                    }
                    prop_assert_eq!(entry.hash.clone(), entry.compute_hash());
                }
            }

            /// Any field edit or chain-link tamper is detected by verification.
            #[test]
            fn audit_tamper_or_edit_is_detected(
                events in prop::collection::vec(arb_audit_event(), 1..30),
                idx_factor in any::<usize>(),
                kind in prop_oneof![
                    Just(TamperKind::Decision),
                    Just(TamperKind::Reason),
                    Just(TamperKind::TaskId),
                    Just(TamperKind::Tool),
                    Just(TamperKind::ArgsDigest),
                    Just(TamperKind::ResultDigest),
                    Just(TamperKind::Timestamp),
                    Just(TamperKind::Seq),
                    Just(TamperKind::PrevHashKeepHash),
                    Just(TamperKind::PrevHashRecompute),
                ],
            ) {
                let log = build_chain(&events);
                prop_assert!(verify_chain(&log));
                let idx = idx_factor % log.len();
                let tampered = apply_tamper(log, idx, kind);

                prop_assert!(!verify_chain(&tampered), "tampered chain must not verify");
                let err = verify_chain_detailed(&tampered)
                    .expect_err("tampered chain must produce verification error");

                match kind {
                    TamperKind::Seq => {
                        prop_assert_eq!(err.index, idx);
                        let is_seq_mismatch = matches!(err.kind, VerifyErrorKind::SeqMismatch { .. });
                        prop_assert!(is_seq_mismatch, "expected SeqMismatch, got {:?}", err.kind);
                    }
                    TamperKind::PrevHashKeepHash | TamperKind::PrevHashRecompute => {
                        prop_assert_eq!(err.index, idx);
                        let is_prev_hash_mismatch =
                            matches!(err.kind, VerifyErrorKind::PrevHashMismatch { .. });
                        prop_assert!(
                            is_prev_hash_mismatch,
                            "expected PrevHashMismatch, got {:?}",
                            err.kind
                        );
                    }
                    TamperKind::Decision
                    | TamperKind::Reason
                    | TamperKind::TaskId
                    | TamperKind::Tool
                    | TamperKind::ArgsDigest
                    | TamperKind::ResultDigest
                    | TamperKind::Timestamp => {
                        prop_assert_eq!(err.index, idx);
                        let is_hash_mismatch =
                            matches!(err.kind, VerifyErrorKind::HashMismatch { .. });
                        prop_assert!(
                            is_hash_mismatch,
                            "expected HashMismatch, got {:?}",
                            err.kind
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn try_append_builder_methods_fail_closed_without_mutation() {
        let mut log = Vec::new();
        AuditEventBuilder::new("task", "tool", "allow")
            .ts(1)
            .args_digest("a1")
            .result_digest("r1")
            .try_append(&mut log)
            .unwrap();
        let staged = AuditEventBuilder::new("task", "tool", "allow")
            .ts(2)
            .args_digest("a2")
            .result_digest("r2")
            .stage(&log);
        let mut tampered = staged.clone();
        tampered.hash = "bad".into();
        let err = append_staged(&mut log, tampered).unwrap_err();
        assert!(matches!(err.kind, VerifyErrorKind::HashMismatch { .. }));
        assert_eq!(log.len(), 1);

        let bad_state = ChainState {
            next_seq: 99,
            prev_hash: log[0].hash.clone(),
        };
        let staged_bad = AuditEventBuilder::new("task", "tool", "deny")
            .ts(3)
            .args_digest("a3")
            .result_digest("r3")
            .stage_continuing(&DEFAULT_HASHER, bad_state);
        let expected_state = ChainState::from_tail(&log);
        let err = append_staged_continuing(&mut log, expected_state, staged_bad).unwrap_err();
        assert!(matches!(err.kind, VerifyErrorKind::SeqMismatch { .. }));
        assert_eq!(log.len(), 1);

        let state = ChainState::from_tail(&log);
        AuditEventBuilder::new("task", "tool", "deny")
            .ts(2)
            .args_digest("a2")
            .result_digest("r2")
            .try_append_continuing(&mut log, state)
            .unwrap();
        assert!(verify_chain(&log));
    }

    #[test]
    fn fail_closed_state_and_try_append_helpers_for_live_paths() {
        let mut log = Vec::new();
        let end = try_append_entry(&mut log, 1, "t", "tool", "allow", "", "a1", "r1")
            .unwrap()
            .hash
            .clone();
        assert_eq!(ChainState::from_tail(&log).prev_hash, end);
        assert_eq!(
            verify_chain_state(&log).unwrap(),
            ChainState::from_tail(&log)
        );
        let verified_state = ChainState::from_tail_verified(&log).unwrap();
        assert_eq!(verified_state.next_seq, 1);

        let staged = stage_entry(&log, 2, "t", "tool", "allow", "", "a2", "r2", vec![]);
        let before = log.clone();
        let mut tampered = staged.clone();
        tampered.prev_hash = "bogus".into();
        tampered.hash = tampered.compute_hash();
        let err = append_staged(&mut log, tampered).unwrap_err();
        assert!(matches!(err.kind, VerifyErrorKind::PrevHashMismatch { .. }));
        assert_eq!(log, before);
        append_staged(&mut log, staged).unwrap();

        let mut segment = Vec::new();
        let cont = ChainState::from_tail(&log);
        let s1 = stage_entry_continuing(
            cont.clone(),
            3,
            "t",
            "tool",
            "allow",
            "",
            "a3",
            "r3",
            vec![],
        );
        try_append_entry_continuing(&mut segment, cont, 3, "t", "tool", "allow", "", "a3", "r3")
            .unwrap();
        assert_eq!(segment[0].hash, s1.hash);
        let seg_end = verify_chain_continuation_state(&segment, 2, &log[1].hash).unwrap();
        assert_eq!(
            seg_end,
            ChainState::from_tail(&{
                let mut full = log.clone();
                full.extend(segment.clone());
                full
            })
        );

        let mut log2 = log.clone();
        let seg_state = ChainState::from_tail(&{
            let mut full = log.clone();
            full.extend(segment.clone());
            full
        });
        let bad_cursor = verify_chain_continuation_state(&segment, 99, &log[1].hash).unwrap_err();
        assert!(matches!(
            bad_cursor.kind,
            VerifyErrorKind::SeqMismatch { .. }
        ));
        let err = try_append_entry_continuing(
            &mut log2,
            ChainState {
                next_seq: seg_state.next_seq + 1,
                prev_hash: "wrong".into(),
            },
            4,
            "t",
            "tool",
            "deny",
            "",
            "a4",
            "r4",
        );
        assert!(
            err.is_ok(),
            "append validates against provided continuation cursor"
        );
        // but resulting chain continuation from seg_state must fail closed
        let mut tail_segment = vec![stage_entry_continuing(
            ChainState {
                next_seq: seg_state.next_seq,
                prev_hash: "wrong".into(),
            },
            4,
            "t",
            "tool",
            "deny",
            "",
            "a4",
            "r4",
            vec![],
        )];
        let mismatch = verify_chain_continuation_state(
            &tail_segment,
            seg_state.next_seq,
            &seg_state.prev_hash,
        )
        .unwrap_err();
        assert!(matches!(
            mismatch.kind,
            VerifyErrorKind::PrevHashMismatch { .. }
        ));
        tail_segment.clear();
        assert!(tail_segment.is_empty());

        // tampered chain must fail closed for verified continuation cursor
        let mut tampered_log = log.clone();
        tampered_log[0].decision = "deny".into();
        assert!(ChainState::from_tail_verified(&tampered_log).is_err());
    }

    #[cfg(feature = "sha2")]
    #[test]
    fn sha256_runtime_hook_and_state_helpers() {
        let h = sha256_runtime_hasher();
        assert_eq!(h.algorithm(), "sha256");
        let mut log = Vec::new();
        try_append_entry_with(&mut log, &h, 1, "t", "tool", "allow", "", "a", "b").unwrap();
        let state = verify_chain_state_with(&log, &h).unwrap();
        let seg = vec![stage_entry_with_continuing(
            &h,
            state.clone(),
            2,
            "t",
            "tool",
            "allow",
            "",
            "c",
            "d",
            vec![("alg".into(), "sha256".into())],
        )];
        let end = verify_chain_continuation_state_with(&seg, &h, state.next_seq, &state.prev_hash)
            .unwrap();
        assert_eq!(end.prev_hash.len(), 64);
    }
}
