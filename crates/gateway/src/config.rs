//! Configuration loading from `scopegate.toml`/env with fail-closed defaults.

use mcp_pool::{UpstreamConfig, UpstreamServerConfig};
use scopegate_core::policy::{PolicyDecision, Rule};
use scopegate_core::rate_limit::Limits;
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

/// Store backend selection for gateway runtime wiring (compat field for existing callers).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StoreBackend {
    /// Default: in-memory (non-durable, dev/test compatible with existing behavior).
    #[default]
    InMemory,
    /// Durable SQLite (WAL) store via sqlx adapter (S1-oriented).
    SqliteWal,
}

/// Effective store selection hook (includes postgres). `store_backend` remains a
/// compatibility projection for existing runtime wiring.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StoreSelection {
    #[default]
    InMemory,
    SqliteWal,
    Postgres,
}

impl StoreSelection {
    pub fn is_durable(self) -> bool {
        !matches!(self, Self::InMemory)
    }
}

/// Hooks for optional runtime state integrations (fail-closed defaults).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeIntegrationHooks {
    /// Attempt to persist lifecycle audit entries via configured store (async callers).
    pub persist_audit_events: bool,
    /// Sync revoked token ids from store revocation records when available.
    pub sync_revocations_from_store: bool,
    /// Enable approval store integration hooks where callers/state support them.
    pub use_approval_store: bool,
    /// Enable in-memory rate-limit/budget tracker state when limits are configured.
    pub enable_rate_limit_state: bool,
    /// Persist rate/budget tracker snapshots to durable store when rate-limit state is enabled.
    /// Defaults to true for backward-compatible fail-closed restart behavior; set false to keep
    /// rate-limit state in-memory only (no restart recovery).
    pub persist_rate_limit_state: bool,
    /// Enable broker credential injection in lifecycle when secret refs are present.
    pub enable_broker_injection: bool,
}

impl Default for RuntimeIntegrationHooks {
    fn default() -> Self {
        Self {
            persist_audit_events: false,
            sync_revocations_from_store: false,
            use_approval_store: false,
            enable_rate_limit_state: true,
            persist_rate_limit_state: true,
            enable_broker_injection: true,
        }
    }
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
    /// Store backend to wire in `gateway` main/runtime entrypoints (compat projection).
    pub store_backend: StoreBackend,
    /// Effective store selection hook (sqlite/postgres).
    pub store_selection: StoreSelection,
    /// Store/database URL for durable backends (e.g. sqlite/postgres URL).
    pub store_database_url: Option<String>,
    /// Runtime integration hooks for store/audit/approval/revocation/rate-limit state.
    pub runtime_hooks: RuntimeIntegrationHooks,
    /// Optional rate/budget limits for in-memory tracker state initialization.
    pub rate_limits: Limits,
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
            store_backend: StoreBackend::InMemory,
            store_selection: StoreSelection::InMemory,
            store_database_url: None,
            runtime_hooks: RuntimeIntegrationHooks::default(),
            rate_limits: Limits::default(),
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
    pub fn with_store_selection(
        mut self,
        selection: StoreSelection,
        database_url: Option<String>,
    ) -> Self {
        self.set_store_selection(selection, database_url);
        self
    }
    pub fn with_rate_limits(mut self, limits: Limits) -> Self {
        self.rate_limits = limits;
        self
    }

    /// Set effective store selection and keep compatibility `store_backend` in sync.
    /// Postgres selection is represented as durable in compat field to preserve fail-closed
    /// startup behavior in existing wiring.
    pub fn set_store_selection(&mut self, selection: StoreSelection, database_url: Option<String>) {
        self.store_selection = selection;
        self.store_backend = match selection {
            StoreSelection::InMemory => StoreBackend::InMemory,
            StoreSelection::SqliteWal | StoreSelection::Postgres => StoreBackend::SqliteWal,
        };
        if database_url.is_some() {
            self.store_database_url = database_url;
        }
    }

    pub fn is_postgres_selected(&self) -> bool {
        matches!(self.store_selection, StoreSelection::Postgres)
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
    store_backend: Option<String>,
    database_url: Option<String>,
    store_database_url: Option<String>,
    persist_audit_events: Option<bool>,
    sync_revocations_from_store: Option<bool>,
    use_approval_store: Option<bool>,
    enable_rate_limit_state: Option<bool>,
    persist_rate_limit_state: Option<bool>,
    enable_broker_injection: Option<bool>,
    rate_limit_per_token_call_limit: Option<u32>,
    rate_limit_per_token_budget: Option<u64>,
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

fn parse_store_selection(s: &str) -> StoreSelection {
    match s.to_ascii_lowercase().as_str() {
        "sqlite" | "sqlite_wal" | "sqlite-wal" | "sqlite3" => StoreSelection::SqliteWal,
        "postgres" | "postgresql" | "pg" => StoreSelection::Postgres,
        "memory" | "inmemory" | "in_memory" | "in-memory" => StoreSelection::InMemory,
        _ => StoreSelection::InMemory, // fail closed to safe/default behavior
    }
}

#[allow(dead_code)]
fn parse_store_backend(s: &str) -> StoreBackend {
    match parse_store_selection(s) {
        StoreSelection::SqliteWal | StoreSelection::Postgres => StoreBackend::SqliteWal,
        StoreSelection::InMemory => StoreBackend::InMemory,
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

fn env_truthy(v: &str) -> bool {
    !matches!(
        v.trim().to_ascii_lowercase().as_str(),
        "0" | "false" | "no" | "off"
    )
}

#[derive(Debug, Clone, Copy, Default)]
struct ExplicitRuntimeHooks {
    persist_audit_events: bool,
    sync_revocations_from_store: bool,
    use_approval_store: bool,
}

fn apply_live_proof_runtime_hook_defaults(cfg: &mut GatewayConfig, explicit: ExplicitRuntimeHooks) {
    if !cfg.store_selection.is_durable() {
        return;
    }
    // Durable sqlite/postgres live-proof flows require store-backed audit/approval/revocation hooks.
    // Enable by default only when not explicitly configured (fail-closed-compatible defaults).
    if !explicit.persist_audit_events {
        cfg.runtime_hooks.persist_audit_events = true;
    }
    if !explicit.sync_revocations_from_store {
        cfg.runtime_hooks.sync_revocations_from_store = true;
    }
    if !explicit.use_approval_store {
        cfg.runtime_hooks.use_approval_store = true;
    }
}

fn apply_env(mut cfg: GatewayConfig, file_explicit_hooks: ExplicitRuntimeHooks) -> GatewayConfig {
    if let Ok(v) = std::env::var("GATEWAY_FAIL_CLOSED") {
        cfg.fail_closed = env_truthy(&v);
    }
    if let Ok(v) = std::env::var("GATEWAY_REQUIRE_TOKEN_SCOPE") {
        cfg.require_token_scope_for_action = env_truthy(&v);
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
    if let Ok(v) =
        std::env::var("GATEWAY_STORE_BACKEND").or_else(|_| std::env::var("SCOPEGATE_STORE_BACKEND"))
    {
        if !v.trim().is_empty() {
            let sel = parse_store_selection(&v);
            cfg.set_store_selection(sel, None);
        }
    }
    let mut store_url_from_env = false;
    if let Ok(v) = std::env::var("GATEWAY_STORE_URL")
        .or_else(|_| std::env::var("SCOPEGATE_STORE_URL"))
        .or_else(|_| std::env::var("GATEWAY_DATABASE_URL"))
        .or_else(|_| std::env::var("SCOPEGATE_DATABASE_URL"))
        .or_else(|_| std::env::var("DATABASE_URL"))
    {
        if !v.trim().is_empty() {
            store_url_from_env = true;
            cfg.store_database_url = Some(v.clone());
            // If a durable URL is explicitly provided, prefer inferred durable backend unless overridden.
            if matches!(cfg.store_selection, StoreSelection::InMemory)
                && std::env::var("GATEWAY_STORE_BACKEND").is_err()
                && std::env::var("SCOPEGATE_STORE_BACKEND").is_err()
            {
                cfg.set_store_selection(infer_store_selection_from_url(&v), Some(v));
            }
        }
    }
    // Durable store selection (from file/env/URL inference) should enable sqlite+stdio live-proof hooks
    // by default when neither file nor env explicitly configured them.
    if cfg.store_selection.is_durable() {
        if std::env::var("GATEWAY_PERSIST_AUDIT_EVENTS").is_err()
            && !file_explicit_hooks.persist_audit_events
        {
            cfg.runtime_hooks.persist_audit_events = true;
        }
        if std::env::var("GATEWAY_SYNC_REVOCATIONS_FROM_STORE").is_err()
            && !file_explicit_hooks.sync_revocations_from_store
        {
            cfg.runtime_hooks.sync_revocations_from_store = true;
        }
        if std::env::var("GATEWAY_USE_APPROVAL_STORE").is_err()
            && !file_explicit_hooks.use_approval_store
        {
            cfg.runtime_hooks.use_approval_store = true;
        }
    }
    let _ = store_url_from_env;
    if let Ok(v) = std::env::var("GATEWAY_PERSIST_AUDIT_EVENTS") {
        cfg.runtime_hooks.persist_audit_events = env_truthy(&v);
    }
    if let Ok(v) = std::env::var("GATEWAY_SYNC_REVOCATIONS_FROM_STORE") {
        cfg.runtime_hooks.sync_revocations_from_store = env_truthy(&v);
    }
    if let Ok(v) = std::env::var("GATEWAY_USE_APPROVAL_STORE") {
        cfg.runtime_hooks.use_approval_store = env_truthy(&v);
    }
    if let Ok(v) = std::env::var("GATEWAY_ENABLE_RATE_LIMIT_STATE") {
        cfg.runtime_hooks.enable_rate_limit_state = env_truthy(&v);
    }
    if let Ok(v) = std::env::var("GATEWAY_PERSIST_RATE_LIMIT_STATE") {
        cfg.runtime_hooks.persist_rate_limit_state = env_truthy(&v);
    }
    if let Ok(v) = std::env::var("GATEWAY_ENABLE_BROKER_INJECTION") {
        cfg.runtime_hooks.enable_broker_injection = env_truthy(&v);
    }
    if let Ok(v) = std::env::var("GATEWAY_RATE_LIMIT_PER_TOKEN_CALL_LIMIT") {
        if let Ok(n) = v.trim().parse::<u32>() {
            cfg.rate_limits.per_token_call_limit = Some(n);
        }
    }
    if let Ok(v) = std::env::var("GATEWAY_RATE_LIMIT_PER_TOKEN_BUDGET") {
        if let Ok(n) = v.trim().parse::<u64>() {
            cfg.rate_limits.per_token_budget = Some(n);
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

fn infer_store_selection_from_url(url: &str) -> StoreSelection {
    let lower = url.trim().to_ascii_lowercase();
    if lower.starts_with("postgres://") || lower.starts_with("postgresql://") {
        StoreSelection::Postgres
    } else {
        StoreSelection::SqliteWal
    }
}

/// Parse config from TOML content. Invalid/unknown values fail closed toward defaults.
pub fn parse_gateway_config(source: &str) -> GatewayConfig {
    parse_gateway_config_inner(source).0
}

fn parse_gateway_config_inner(source: &str) -> (GatewayConfig, ExplicitRuntimeHooks) {
    let Ok(parsed) = toml::from_str::<FileConfig>(source) else {
        return (GatewayConfig::default(), ExplicitRuntimeHooks::default());
    };
    let mut cfg = GatewayConfig::default();
    let backend_specified = parsed.gateway.store_backend.is_some();
    let explicit_hooks = ExplicitRuntimeHooks {
        persist_audit_events: parsed.gateway.persist_audit_events.is_some(),
        sync_revocations_from_store: parsed.gateway.sync_revocations_from_store.is_some(),
        use_approval_store: parsed.gateway.use_approval_store.is_some(),
    };
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
    if let Some(v) = parsed.gateway.store_backend {
        cfg.set_store_selection(parse_store_selection(&v), None);
    }
    if let Some(v) = parsed
        .gateway
        .store_database_url
        .or(parsed.gateway.database_url)
    {
        if !v.trim().is_empty() {
            cfg.store_database_url = Some(v.clone());
            if !backend_specified && matches!(cfg.store_selection, StoreSelection::InMemory) {
                cfg.set_store_selection(infer_store_selection_from_url(&v), Some(v));
            }
        }
    }
    if let Some(v) = parsed.gateway.persist_audit_events {
        cfg.runtime_hooks.persist_audit_events = v;
    }
    if let Some(v) = parsed.gateway.sync_revocations_from_store {
        cfg.runtime_hooks.sync_revocations_from_store = v;
    }
    if let Some(v) = parsed.gateway.use_approval_store {
        cfg.runtime_hooks.use_approval_store = v;
    }
    if let Some(v) = parsed.gateway.enable_rate_limit_state {
        cfg.runtime_hooks.enable_rate_limit_state = v;
    }
    if let Some(v) = parsed.gateway.persist_rate_limit_state {
        cfg.runtime_hooks.persist_rate_limit_state = v;
    }
    if let Some(v) = parsed.gateway.enable_broker_injection {
        cfg.runtime_hooks.enable_broker_injection = v;
    }
    if let Some(v) = parsed.gateway.rate_limit_per_token_call_limit {
        cfg.rate_limits.per_token_call_limit = Some(v);
    }
    if let Some(v) = parsed.gateway.rate_limit_per_token_budget {
        cfg.rate_limits.per_token_budget = Some(v);
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
    // Durable sqlite/postgres selections enable live-proof hooks by default unless explicitly set.
    apply_live_proof_runtime_hook_defaults(&mut cfg, explicit_hooks);
    (cfg, explicit_hooks)
}

/// Load config from env with fail-closed defaults.
pub fn load_gateway_config_from_env() -> GatewayConfig {
    apply_env(GatewayConfig::default(), ExplicitRuntimeHooks::default())
}

/// Load config from file path; missing/unreadable/invalid => fail-closed defaults.
pub fn load_gateway_config_from_path(path: impl AsRef<Path>) -> GatewayConfig {
    let path = path.as_ref();
    let Ok(text) = fs::read_to_string(path) else {
        return load_gateway_config_from_env();
    };
    let (cfg, explicit_hooks) = parse_gateway_config_inner(&text);
    apply_env(cfg, explicit_hooks)
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
        assert!(matches!(cfg.store_selection, StoreSelection::InMemory));
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

    #[test]
    fn parses_postgres_store_selection_and_runtime_hooks() {
        let toml = r#"
[gateway]
store_backend = "postgres"
store_database_url = "postgres://user:pass@localhost/db"
persist_audit_events = true
sync_revocations_from_store = true
use_approval_store = true
enable_rate_limit_state = false
rate_limit_per_token_call_limit = 7
rate_limit_per_token_budget = 42
"#;
        let cfg = parse_gateway_config(toml);
        assert!(matches!(cfg.store_selection, StoreSelection::Postgres));
        assert!(matches!(cfg.store_backend, StoreBackend::SqliteWal)); // compat projection
        assert_eq!(
            cfg.store_database_url.as_deref(),
            Some("postgres://user:pass@localhost/db")
        );
        assert!(cfg.runtime_hooks.persist_audit_events);
        assert!(cfg.runtime_hooks.sync_revocations_from_store);
        assert!(cfg.runtime_hooks.use_approval_store);
        assert!(!cfg.runtime_hooks.enable_rate_limit_state);
        assert!(cfg.runtime_hooks.persist_rate_limit_state);
        assert!(cfg.runtime_hooks.enable_broker_injection);
        assert_eq!(cfg.rate_limits.per_token_call_limit, Some(7));
        assert_eq!(cfg.rate_limits.per_token_budget, Some(42));
    }

    #[test]
    fn durable_store_enables_live_proof_runtime_hooks_by_default() {
        let toml = r#"
[gateway]
store_backend = "sqlite_wal"
database_url = "sqlite://./.scopegate/scopegate.db"

[mcp]
mode = "stdio"
"#;
        let cfg = parse_gateway_config(toml);
        assert!(matches!(cfg.store_selection, StoreSelection::SqliteWal));
        assert!(cfg.runtime_hooks.persist_audit_events);
        assert!(cfg.runtime_hooks.sync_revocations_from_store);
        assert!(cfg.runtime_hooks.use_approval_store);
    }

    #[test]
    fn durable_store_runtime_hook_defaults_can_be_explicitly_disabled() {
        let toml = r#"
[gateway]
store_backend = "sqlite_wal"
database_url = "sqlite://./.scopegate/scopegate.db"
persist_audit_events = false
sync_revocations_from_store = false
use_approval_store = false
"#;
        let cfg = parse_gateway_config(toml);
        assert!(matches!(cfg.store_selection, StoreSelection::SqliteWal));
        assert!(!cfg.runtime_hooks.persist_audit_events);
        assert!(!cfg.runtime_hooks.sync_revocations_from_store);
        assert!(!cfg.runtime_hooks.use_approval_store);
    }

    #[test]
    fn inferred_durable_store_from_url_enables_live_proof_hooks() {
        let toml = r#"
[gateway]
database_url = "sqlite://./.scopegate/s1.db"

[mcp]
mode = "stdio"
"#;
        let cfg = parse_gateway_config(toml);
        assert!(matches!(cfg.store_selection, StoreSelection::SqliteWal));
        assert!(cfg.runtime_hooks.persist_audit_events);
        assert!(cfg.runtime_hooks.sync_revocations_from_store);
        assert!(cfg.runtime_hooks.use_approval_store);
    }

    #[test]
    fn parses_broker_and_store_hook_knobs() {
        let toml = r#"
[gateway]
store_backend = "sqlite_wal"
enable_broker_injection = false
use_approval_store = true
"#;
        let cfg = parse_gateway_config(toml);
        assert!(matches!(cfg.store_selection, StoreSelection::SqliteWal));
        assert!(!cfg.runtime_hooks.enable_broker_injection);
        assert!(cfg.runtime_hooks.use_approval_store);
        assert!(cfg.runtime_hooks.enable_rate_limit_state);
        // Durable defaults still enable other live-proof hooks when unspecified.
        assert!(cfg.runtime_hooks.persist_audit_events);
        assert!(cfg.runtime_hooks.sync_revocations_from_store);
    }

    #[test]
    fn parses_stdio_mode_and_sqlite_store_for_s1_config() {
        let toml = r#"
[gateway]
store_backend = "sqlite_wal"
database_url = "sqlite://./.scopegate/scopegate.db"
listen_addr = "127.0.0.1:8080"

[mcp]
mode = "stdio"
"#;
        let cfg = parse_gateway_config(toml);
        assert!(matches!(cfg.mcp_mode, McpMode::Stdio));
        assert!(matches!(cfg.store_selection, StoreSelection::SqliteWal));
        assert_eq!(
            cfg.store_database_url.as_deref(),
            Some("sqlite://./.scopegate/scopegate.db")
        );
        assert_eq!(cfg.listen_addr.as_deref(), Some("127.0.0.1:8080"));
        assert!(cfg.runtime_hooks.persist_audit_events);
        assert!(cfg.runtime_hooks.sync_revocations_from_store);
        assert!(cfg.runtime_hooks.use_approval_store);
    }

    #[test]
    fn infers_sqlite_store_from_database_url_when_backend_unspecified() {
        let toml = r#"
[gateway]
database_url = "sqlite://./.scopegate/s1.db"

[mcp]
mode = "stdio"
"#;
        let cfg = parse_gateway_config(toml);
        assert!(matches!(cfg.mcp_mode, McpMode::Stdio));
        assert!(matches!(cfg.store_selection, StoreSelection::SqliteWal));
        assert_eq!(
            cfg.store_database_url.as_deref(),
            Some("sqlite://./.scopegate/s1.db")
        );
    }

    #[test]
    fn infers_postgres_store_from_database_url_when_backend_unspecified() {
        let toml = r#"
[gateway]
store_database_url = "postgres://user:pass@localhost/db"
"#;
        let cfg = parse_gateway_config(toml);
        assert!(matches!(cfg.store_selection, StoreSelection::Postgres));
        assert!(cfg.is_postgres_selected());
    }

    #[test]
    fn explicit_store_backend_takes_precedence_over_url_inference() {
        let toml = r#"
[gateway]
store_backend = "memory"
database_url = "sqlite://./.scopegate/s1.db"
"#;
        let cfg = parse_gateway_config(toml);
        assert!(matches!(cfg.store_selection, StoreSelection::InMemory));
        assert_eq!(
            cfg.store_database_url.as_deref(),
            Some("sqlite://./.scopegate/s1.db")
        );
    }

    #[test]
    fn default_runtime_hooks_fail_closed_but_preserve_core_behavior() {
        let cfg = GatewayConfig::default();
        assert!(!cfg.runtime_hooks.persist_audit_events);
        assert!(!cfg.runtime_hooks.sync_revocations_from_store);
        assert!(!cfg.runtime_hooks.use_approval_store);
        assert!(cfg.runtime_hooks.enable_rate_limit_state);
        assert!(cfg.runtime_hooks.persist_rate_limit_state);
        assert!(cfg.runtime_hooks.enable_broker_injection);
    }

    #[test]
    fn env_truthy_defaults_to_fail_closed() {
        assert!(env_truthy("1"));
        assert!(env_truthy("true"));
        assert!(!env_truthy("0"));
        assert!(!env_truthy("false"));
        assert!(!env_truthy("no"));
    }
}
