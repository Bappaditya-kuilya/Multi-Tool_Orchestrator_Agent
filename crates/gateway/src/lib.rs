#![forbid(unsafe_code)]

//! Gateway crate: request lifecycle, config, HTTP/admin API, MCP integration points, and axum server.

pub mod api;
pub mod config;
pub mod lifecycle;
pub mod mcp;
pub mod server;
pub mod state;

pub use config::*;
pub use lifecycle::*;
