//! Configuration loading from `scopegate.toml`/env with fail-closed defaults.

use mcp_pool::{UpstreamConfig, UpstreamServerConfig};
use scopegate_core::policy::{PolicyDecision, Rule};
use scopegate_core::taint::EgressPolicy;
use serde::Deserialize;
use std::{collections::BTreeMap, fs, path::Path};

/// MCP runtime mode for gateway binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum McpMode {
    #[default]
    Http,
    Stdio,
}

/// Parsed MCP upstream configuration (pool wiring).
#[derive(Debug, Clone)]
pub struct McpUpstreamConfig {
    pub server: UpstreamServerConfig,
    pub pool: UpstreamConfig,
}

/// Gateway runtime/configuration knobs. Fail-closed by default.
#[derive(Debug, Clone)]
pub struct GatewayConfig {
    pub rules: Vec<Rule>,
    pub revoked_token_ids: Vec<String>,
    pub egress_policy: EgressPolicy,
    pub require_token_scope_for_action: bool,
    pub fail_closed: bool,
    /// Optional bind address override (parsed by main/server callers).
    pub listen_addr: Option<String>,
    /// MCP upstreams for front→pool→upstream dispatch.
    pub mcp_upstreams: Vec<McpUpstreamConfig>,
    /// Default upstream id when request does not specify one.
    pub mcp_default_upstream: Option<String>,
    /// Runtime mode for `gateway` binary.
    pub mcp_mode: McpMode,
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            rules: Vec::new(),
            revoked_token_ids: Vec::new(),
            egress_policy: EgressPolicy::RequireApprovalOnConflict,
            require_token_scope_for_action: true,
            fail_closed: true,
            listen_addr: None,
            mcp_upstreams: Vec::new(),
            mcp_default_upstream: None,
            mcp_mode: McpMode::Http,
        }
    }
}

impl GatewayConfig {
    pub fn with_rules(mut self, rules: Vec<Rule>) -> Self {
        self.rules = rules;
        self
    }
    pub fn with_revoked(mut self, revoked: Vec<String>) -> Self {
        self.revoked_token_ids = revoked;
        self
    }
    pub fn with_egress_policy(mut self, policy: EgressPolicy) -> Self {
        self.egress_policy = policy;
        self
    }
}

#[derive(Debug, Default, Deserialize)]
struct FileConfig {
    #[serde(default)]
    gateway: GatewaySection,
    #[serde(default)]
    rule: Vec<RuleSection>,
    #[serde(default)]
    mcp: McpSection,
    #[serde(default, rename = "mcp_upstream")]
    mcp_upstreams: Vec<McpUpstreamSection>,
}

#[derive(Debug, Default, Deserialize)]
struct GatewaySection {
    fail_closed: Option<bool>,
    require_token_scope_for_action: Option<bool>,
    egress_policy: Option<String>,
    revoked_token_ids: Option<Vec<String>>,
    listen_addr: Option<String>,
}

#[derive(Debug, Default, Deserialize, Clone)]
struct RuleSection {
    principal: String,
    action: String,
    resource: String,
    #[serde(default)]
    decision: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct McpSection {
    mode: Option<String>,
    default_upstream: Option<String>,
}

#[derive(Debug, Default, Deserialize, Clone)]
struct McpUpstreamSection {
    id: String,
    #[serde(default)]
    transport: Option<String>,
    endpoint: Option<String>,
    url: Option<String>,
    program: Option<String>,
    #[serde(default)]
    args: Vec<String>,
    cwd: Option<String>,
    auth_profile: Option<String>,
    #[serde(default)]
    env: BTreeMap<String, String>,
    #[serde(default)]
    headers: BTreeMap<String, String>,
    max_leases: Option<usize>,
    max_retries: Option<u32>,
}

fn parse_decision(s: &str) -> PolicyDecision {
    match s.to_ascii_lowercase().as_str() {
        "permit" | "allow" => PolicyDecision::Permit,
        "require_approval" | "approval" => PolicyDecision::RequireApproval,
        _ => PolicyDecision::Forbid,
    }
}

fn parse_egress(s: &str) -> EgressPolicy {
    match s.to_ascii_lowercase().as_str() {
        "block" | "block_on_conflict" => EgressPolicy::BlockOnConflict,
        "require_approval" | "require_approval_on_conflict" => {
            EgressPolicy::RequireApprovalOnConflict
        }
        _ => EgressPolicy::RequireApprovalOnConflict, // fail-closed default
    }
}

fn parse_mode(s: &str) -> McpMode {
    match s.to_ascii_lowercase().as_str() {
        "stdio" => McpMode::Stdio,
        _ => McpMode::Http,
    }
}

fn upstream_from_section(sec: &McpUpstreamSection) -> Option<McpUpstreamConfig> {
    let mut map = BTreeMap::new();
    let transport = sec.transport.clone().unwrap_or_else(|| {
        if sec.program.is_some() {
            "stdio"
        } else {
            "http"
        }
        .to_string()
    });
    map.insert("transport".into(), transport);
    if let Some(v) = &sec.endpoint {
        map.insert("endpoint".into(), v.clone());
        map.insert("url".into(), v.clone());
    }
    if let Some(v) = &sec.url {
        map.insert("url".into(), v.clone());
    }
    if let Some(v) = &sec.program {
        map.insert("program".into(), v.clone());
    }
    if !sec.args.is_empty() {
        map.insert("args".into(), sec.args.join(","));
    }
    if let Some(v) = &sec.cwd {
        map.insert("cwd".into(), v.clone());
    }
    if let Some(v) = &sec.auth_profile {
        map.insert("auth_profile".into(), v.clone());
    }
    for (k, v) in &sec.env {
        map.insert(format!("env.{k}"), v.clone());
    }
    for (k, v) in &sec.headers {
        map.insert(format!("header.{k}"), v.clone());
    }
    let server = UpstreamServerConfig::from_config_map(&sec.id, &map).ok()?;
    let mut pool = UpstreamConfig::default();
    if let Some(v) = sec.max_leases {
        pool.max_leases = v.max(1);
        pool.concurrency.max_leases = v.max(1);
    }
    if let Some(v) = sec.max_retries {
        pool.max_retries = v;
        pool.retry.max_retries = v;
    }
    Some(McpUpstreamConfig { server, pool })
}

fn apply_env(mut cfg: GatewayConfig) -> GatewayConfig {
    if let Ok(v) = std::env::var("GATEWAY_FAIL_CLOSED") {
        cfg.fail_closed = !matches!(v.as_str(), "0" | "false" | "FALSE" | "no");
    }
    if let Ok(v) = std::env::var("GATEWAY_REQUIRE_TOKEN_SCOPE") {
        cfg.require_token_scope_for_action = !matches!(v.as_str(), "0" | "false" | "FALSE" | "no");
    }
    if let Ok(v) = std::env::var("GATEWAY_EGRESS_POLICY") {
        cfg.egress_policy = parse_egress(&v);
    }
    if let Ok(v) = std::env::var("GATEWAY_REVOKED_TOKEN_IDS") {
        cfg.revoked_token_ids = v
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
    }
    if let Ok(v) = std::env::var("GATEWAY_ADDR") {
        if !v.trim().is_empty() {
            cfg.listen_addr = Some(v);
        }
    }
    if let Ok(v) = std::env::var("GATEWAY_MCP_MODE") {
        cfg.mcp_mode = parse_mode(&v);
    }
    if let Ok(v) = std::env::var("GATEWAY_MCP_DEFAULT_UPSTREAM") {
        if !v.trim().is_empty() {
            cfg.mcp_default_upstream = Some(v);
        }
    }
    // Env shortcut: single HTTP upstream via endpoint URL.
    if let Ok(url) = std::env::var("GATEWAY_MCP_UPSTREAM_URL") {
        if !url.trim().is_empty() {
            let id = std::env::var("GATEWAY_MCP_UPSTREAM_ID").unwrap_or_else(|_| "default".into());
            let mut map = BTreeMap::new();
            map.insert("transport".into(), "http".into());
            map.insert("url".into(), url.clone());
            if let Ok(server) = UpstreamServerConfig::from_config_map(&id, &map) {
                cfg.mcp_upstreams.push(McpUpstreamConfig {
                    server,
                    pool: UpstreamConfig::default(),
                });
                if cfg.mcp_default_upstream.is_none() {
                    cfg.mcp_default_upstream = Some(id);
                }
            }
        }
    }
    // Env shortcut: single stdio upstream via command.
    if let Ok(program) = std::env::var("GATEWAY_MCP_UPSTREAM_CMD") {
        if !program.trim().is_empty() {
            let id = std::env::var("GATEWAY_MCP_UPSTREAM_ID").unwrap_or_else(|_| "default".into());
            let mut map = BTreeMap::new();
            map.insert("transport".into(), "stdio".into());
            map.insert("program".into(), program);
            if let Ok(args) = std::env::var("GATEWAY_MCP_UPSTREAM_ARGS") {
                map.insert("args".into(), args);
            }
            if let Ok(server) = UpstreamServerConfig::from_config_map(&id, &map) {
                cfg.mcp_upstreams.push(McpUpstreamConfig {
                    server,
                    pool: UpstreamConfig::default(),
                });
                if cfg.mcp_default_upstream.is_none() {
                    cfg.mcp_default_upstream = Some(id);
                }
            }
        }
    }
    cfg
}

/// Parse config from TOML content. Invalid/unknown values fail closed toward defaults.
pub fn parse_gateway_config(source: &str) -> GatewayConfig {
    let Ok(parsed) = toml::from_str::<FileConfig>(source) else {
        return GatewayConfig::default();
    };
    let mut cfg = GatewayConfig::default();
    if let Some(v) = parsed.gateway.fail_closed {
        cfg.fail_closed = v;
    }
    if let Some(v) = parsed.gateway.require_token_scope_for_action {
        cfg.require_token_scope_for_action = v;
    }
    if let Some(v) = parsed.gateway.egress_policy {
        cfg.egress_policy = parse_egress(&v);
    }
    if let Some(v) = parsed.gateway.revoked_token_ids {
        cfg.revoked_token_ids = v;
    }
    if let Some(v) = parsed.gateway.listen_addr {
        cfg.listen_addr = Some(v);
    }
    for r in parsed.rule {
        let decision = r
            .decision
            .as_deref()
            .map(parse_decision)
            .unwrap_or(PolicyDecision::Forbid);
        cfg.rules
            .push(Rule::exact(&r.principal, &r.action, &r.resource, decision));
    }
    if let Some(mode) = parsed.mcp.mode {
        cfg.mcp_mode = parse_mode(&mode);
    }
    cfg.mcp_default_upstream = parsed.mcp.default_upstream;
    for sec in parsed.mcp_upstreams {
        if sec.id.trim().is_empty() {
            continue;
        }
        if let Some(up) = upstream_from_section(&sec) {
            cfg.mcp_upstreams.push(up);
        }
    }
    if cfg.mcp_default_upstream.is_none() {
        cfg.mcp_default_upstream = cfg.mcp_upstreams.first().map(|u| u.server.id.0.clone());
    }
    cfg
}

/// Load config from env with fail-closed defaults.
pub fn load_gateway_config_from_env() -> GatewayConfig {
    apply_env(GatewayConfig::default())
}

/// Load config from file path; missing/unreadable/invalid => fail-closed defaults.
pub fn load_gateway_config_from_path(path: impl AsRef<Path>) -> GatewayConfig {
    let path = path.as_ref();
    let Ok(text) = fs::read_to_string(path) else {
        return load_gateway_config_from_env();
    };
    apply_env(parse_gateway_config(&text))
}

/// Compatibility placeholders (used by existing callers).
pub fn parse_gateway_config_placeholder(source: &str) -> GatewayConfig {
    parse_gateway_config(source)
}
pub fn load_gateway_config_from_env_placeholder() -> GatewayConfig {
    load_gateway_config_from_env()
}
pub fn load_gateway_config_from_path_placeholder(path: &str) -> GatewayConfig {
    load_gateway_config_from_path(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_config_fails_closed_default() {
        let cfg = parse_gateway_config("not = [toml");
        assert!(cfg.fail_closed);
        assert!(cfg.rules.is_empty());
    }

    #[test]
    fn parses_rules_and_policy() {
        let toml = r#"
[gateway]
fail_closed = true
egress_policy = "block"

[[rule]]
principal = "agent"
action = "tool.invoke"
resource = "tool"
decision = "permit"
"#;
        let cfg = parse_gateway_config(toml);
        assert!(cfg.fail_closed);
        assert_eq!(cfg.rules.len(), 1);
        assert!(matches!(cfg.egress_policy, EgressPolicy::BlockOnConflict));
    }
}
