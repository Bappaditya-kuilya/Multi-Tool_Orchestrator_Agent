//! Network-free tests for the traffic sparkline data path (written first, RED).

use scopegate_ctl::metrics::{parse_counters, push_history, Counters};

const SAMPLE: &str = "\
# HELP gateway_requests_total Total handled requests
# TYPE gateway_requests_total counter
gateway_requests_total 128
gateway_requests_denied_total 3
gateway_requests_allowed_total 125
gateway_audit_appends_total 12
gateway_audit_append_failures_total 0
";

#[test]
fn parse_counters_reads_gateway_metric_names() {
    let c = parse_counters(SAMPLE);
    assert_eq!(c.requests, 128);
    assert_eq!(c.denied, 3);
    assert_eq!(c.allowed, 125);
    assert_eq!(c.audit_appends, 12);
    assert_eq!(c.audit_failures, 0);
}

#[test]
fn parse_counters_is_zero_for_empty_or_malformed_metrics() {
    let c = parse_counters("garbage\n\nrequests_total not-a-number\n");
    assert_eq!(c, Counters::default());
}

#[test]
fn delta_never_underflows_on_counter_reset() {
    let before = Counters {
        requests: 100,
        denied: 5,
        ..Default::default()
    };
    let after = Counters {
        requests: 4,
        denied: 1,
        ..Default::default()
    };
    let d = before.delta(&after);
    assert_eq!(d.requests, 0);
    assert_eq!(d.denied, 0);
}

#[test]
fn delta_reports_traffic_between_refreshes() {
    let before = Counters {
        requests: 100,
        denied: 5,
        audit_appends: 20,
        ..Default::default()
    };
    let after = Counters {
        requests: 108,
        denied: 6,
        audit_appends: 23,
        ..Default::default()
    };
    let d = before.delta(&after);
    assert_eq!(d.requests, 8);
    assert_eq!(d.denied, 1);
    assert_eq!(d.audit_appends, 3);
}

#[test]
fn push_history_caps_the_sparkline_window() {
    let mut h = Vec::new();
    for v in 0..100 {
        push_history(&mut h, v, 8);
    }
    assert_eq!(h.len(), 8);
    assert_eq!(h.last().copied(), Some(99));
}
