//! ScopeGate CLI/TUI client library.
//!
//! `scopegatectl` is a thin client over the gateway's v1 HTTP API. It lives in
//! its own crate so it never links gateway internals and cannot accidentally
//! bypass a fail-closed check.

pub mod client;
pub mod commands;
pub mod metrics;
pub mod model;
pub mod tui;
