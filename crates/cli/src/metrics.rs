//! Parse the gateway's Prometheus counters into sparkline samples.
//!
//! Counter names come from `crates/gateway/src/state.rs:49`.

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counters {
    pub requests: u64,
    pub denied: u64,
    pub allowed: u64,
    pub audit_appends: u64,
    pub audit_failures: u64,
}

impl Counters {
    /// Per-refresh activity. Saturating subtraction survives a gateway restart
    /// (counter reset) without producing a nonsense negative spike.
    pub fn delta(&self, next: &Counters) -> Counters {
        Counters {
            requests: next.requests.saturating_sub(self.requests),
            denied: next.denied.saturating_sub(self.denied),
            allowed: next.allowed.saturating_sub(self.allowed),
            audit_appends: next.audit_appends.saturating_sub(self.audit_appends),
            audit_failures: next.audit_failures.saturating_sub(self.audit_failures),
        }
    }
}

/// Extract the five gateway counters from Prometheus text. Unknown lines are
/// ignored; malformed values do not poison the other counters.
pub fn parse_counters(text: &str) -> Counters {
    let mut out = Counters::default();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split_whitespace();
        let (Some(name), Some(value)) = (parts.next(), parts.next()) else {
            continue;
        };
        let Ok(value) = value.parse::<u64>() else {
            continue;
        };
        match name {
            "gateway_requests_total" => out.requests = value,
            "gateway_requests_denied_total" => out.denied = value,
            "gateway_requests_allowed_total" => out.allowed = value,
            "gateway_audit_appends_total" => out.audit_appends = value,
            "gateway_audit_append_failures_total" => out.audit_failures = value,
            _ => {}
        }
    }
    out
}

/// Append a sample and keep only the most recent `cap` values.
pub fn push_history(history: &mut Vec<u64>, value: u64, cap: usize) {
    if cap == 0 {
        history.clear();
        return;
    }
    history.push(value);
    if history.len() > cap {
        let excess = history.len() - cap;
        history.drain(..excess);
    }
}
