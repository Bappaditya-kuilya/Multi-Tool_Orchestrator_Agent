//! Hash-chained audit log primitives with a pluggable hash interface.
//!
//! Default hashing remains a pure in-memory FNV-1a placeholder (no external
//! crypto deps) so stronger hash implementations can be injected later.
//! A SHA-256 hasher is available behind the `sha2` feature for runtime use.

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

    /// Append using this builder, producing a chained entry.
    pub fn append(self, entries: &mut Vec<AuditEntry>) -> &AuditEntry {
        append_entry(
            entries,
            self.ts,
            self.task_id,
            self.tool,
            self.decision,
            self.reason,
            self.args_digest,
            self.result_digest,
        )
    }

    /// Append using this builder and a pluggable hasher.
    pub fn append_with<'a, H: AuditHasher + ?Sized>(
        self,
        entries: &'a mut Vec<AuditEntry>,
        hasher: &H,
    ) -> &'a AuditEntry {
        append_entry_with(
            entries,
            hasher,
            self.ts,
            self.task_id,
            self.tool,
            self.decision,
            self.reason,
            self.args_digest,
            self.result_digest,
        )
    }
}

impl AuditEntry {
    /// Canonical serialized form used for hashing (field order is fixed).
    pub fn canonical_payload(&self) -> String {
        format!(
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
        )
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
    let seq = entries.last().map(|e| e.seq + 1).unwrap_or(0);
    let prev_hash = entries
        .last()
        .map(|e| e.hash.clone())
        .unwrap_or_else(|| "genesis".to_string());
    let mut entry = AuditEntry {
        seq,
        ts,
        task_id: task_id.into(),
        tool: tool.into(),
        decision: decision.into(),
        reason: reason.into(),
        args_digest: args_digest.into(),
        result_digest: result_digest.into(),
        prev_hash,
        hash: String::new(),
    };
    entry.hash = entry.compute_hash_with(hasher);
    entries.push(entry);
    entries.last().expect("just pushed")
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

/// Chain verification failure with the failing index and reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyError {
    pub index: usize,
    pub kind: VerifyErrorKind,
}

/// Specific reason a chain failed verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyErrorKind {
    SeqMismatch { expected: u64, found: u64 },
    PrevHashMismatch { expected: String, found: String },
    HashMismatch { expected: String, found: String },
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
}
