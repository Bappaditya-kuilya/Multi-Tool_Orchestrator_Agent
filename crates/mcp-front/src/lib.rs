//! MCP server front: accept, decode envelopes, authenticate, route, and dispatch.
//!
//! Owns server-front abstractions: JSON-RPC/MCP message stubs, request/response
//! types, parsing/validation, auth/policy/taint/approval hooks, transport trait
//! stubs (stdio/HTTP), tool listing/call abstractions, and dispatch interface.
//!
//! TODO(rmcp): replace stubs with real `rmcp` transport/types, streaming,
//! notifications, and full protocol metadata. `rmcp`-ready seam types live in
//! [`rmcp_stubs`] and are intentionally compile-intent/fail-closed.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::io::{self, BufRead, Write};

// ---------------------------------------------------------------------------
// JSON-RPC / MCP message stubs
// ---------------------------------------------------------------------------

/// JSON-RPC id (string or integer in MCP; stub supports string form).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum JsonRpcId {
    Str(String),
    Int(i64),
}

impl Default for JsonRpcId {
    fn default() -> Self {
        Self::Str("unknown".into())
    }
}

impl JsonRpcId {
    pub fn as_request_id(&self) -> String {
        match self {
            JsonRpcId::Str(s) => s.clone(),
            JsonRpcId::Int(i) => i.to_string(),
        }
    }
}

impl From<String> for JsonRpcId {
    fn from(s: String) -> Self {
        Self::Str(s)
    }
}
impl From<&str> for JsonRpcId {
    fn from(s: &str) -> Self {
        Self::Str(s.to_string())
    }
}

/// JSON-RPC 2.0 request stub.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    #[serde(default)]
    pub id: Option<JsonRpcId>,
    pub method: String,
    #[serde(default)]
    pub params: Option<serde_json::Value>,
}

impl JsonRpcRequest {
    pub fn new(
        id: impl Into<JsonRpcId>,
        method: impl Into<String>,
        params: Option<serde_json::Value>,
    ) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            id: Some(id.into()),
            method: method.into(),
            params,
        }
    }
}

/// JSON-RPC 2.0 notification stub (no id).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JsonRpcNotification {
    pub jsonrpc: String,
    pub method: String,
    #[serde(default)]
    pub params: Option<serde_json::Value>,
}

/// JSON-RPC error object stub.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

/// JSON-RPC 2.0 response stub.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    pub id: JsonRpcId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

impl JsonRpcResponse {
    pub fn success(id: impl Into<JsonRpcId>, result: serde_json::Value) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            id: id.into(),
            result: Some(result),
            error: None,
        }
    }
    pub fn failure(id: impl Into<JsonRpcId>, error: JsonRpcError) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            id: id.into(),
            result: None,
            error: Some(error),
        }
    }
}

/// Inbound message kind stub.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum JsonRpcMessage {
    Request(JsonRpcRequest),
    Response(JsonRpcResponse),
}

/// MCP tool descriptor (tools/list).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct McpTool {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// JSON schema for input (preferred structured form).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "inputSchema"
    )]
    pub input_schema: Option<serde_json::Value>,
    /// Optional annotations/title metadata stub for MCP evolution.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
}

/// Result shape for `tools/list`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct ToolListResult {
    #[serde(default)]
    pub tools: Vec<McpTool>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "nextCursor"
    )]
    pub next_cursor: Option<String>,
}

/// Params for `tools/call`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct CallToolParams {
    pub name: String,
    #[serde(default)]
    pub arguments: Option<serde_json::Value>,
}

/// Minimal MCP content item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ContentItem {
    #[serde(rename = "text")]
    Text { text: String },
}

impl ContentItem {
    pub fn text(s: impl Into<String>) -> Self {
        Self::Text { text: s.into() }
    }
}

/// Structured `tools/call` result shape (MCP-like).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct CallToolResultPayload {
    #[serde(default)]
    pub content: Vec<ContentItem>,
    #[serde(default, rename = "isError")]
    pub is_error: bool,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "structuredContent"
    )]
    pub structured_content: Option<serde_json::Value>,
}

/// `initialize` request/result stubs (ready to wire to rmcp types).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct InitializeParams {
    #[serde(default, rename = "protocolVersion")]
    pub protocol_version: Option<String>,
    #[serde(default)]
    pub capabilities: Option<serde_json::Value>,
    #[serde(default, rename = "clientInfo")]
    pub client_info: Option<serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InitializeResult {
    #[serde(default, rename = "protocolVersion")]
    pub protocol_version: String,
    #[serde(default)]
    pub capabilities: serde_json::Value,
    #[serde(default, rename = "serverInfo")]
    pub server_info: serde_json::Value,
}

impl Default for InitializeResult {
    fn default() -> Self {
        Self {
            protocol_version: "2024-11-05".into(),
            capabilities: serde_json::json!({"tools": {"listChanged": false}}),
            server_info: serde_json::json!({"name": "mcp-front", "version": env!("CARGO_PKG_VERSION")}),
        }
    }
}

// ---------------------------------------------------------------------------
// Front envelope types (existing API preserved)
// ---------------------------------------------------------------------------

/// Request/response correlation id placeholder.
pub type RequestId = String;

/// Transport/session metadata surfaced to front hooks.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct TransportMetadata {
    pub peer: Option<String>,
    pub session_id: Option<String>,
    pub headers: BTreeMap<String, String>,
    pub attributes: BTreeMap<String, String>,
}

impl TransportMetadata {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(name)
            .or_else(|| self.headers.get(&name.to_ascii_lowercase()))
            .or_else(|| {
                let needle = name.to_ascii_lowercase();
                self.headers
                    .iter()
                    .find(|(k, _)| k.to_ascii_lowercase() == needle)
                    .map(|(_, v)| v)
            })
            .map(String::as_str)
    }

    pub fn attribute(&self, name: &str) -> Option<&str> {
        self.attributes.get(name).map(String::as_str)
    }
}

/// Tool call envelope (MCP tools/call shape, simplified for skeleton).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ToolCall {
    pub name: String,
    /// Flat string args for backward compat; structured JSON in `raw_arguments`.
    #[serde(default)]
    pub arguments: BTreeMap<String, String>,
    /// Structured arguments stub (preferred for JSON-RPC path).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_arguments: Option<serde_json::Value>,
}

/// Structured request params placeholder.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct RequestParams {
    pub tool_call: Option<ToolCall>,
    /// TODO(rmcp): preserve arbitrary JSON params/object fields.
    #[serde(default)]
    pub fields: BTreeMap<String, String>,
}

/// Inbound MCP request envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpRequestEnvelope {
    pub id: RequestId,
    pub method: String,
    pub params: RequestParams,
    /// Raw payload retained for transport/debug and rmcp bridging.
    pub raw: String,
    /// TODO(rmcp): populate from transport metadata.
    #[serde(default)]
    pub transport: TransportMetadata,
}

impl McpRequestEnvelope {
    pub fn tool_call(&self) -> Option<&ToolCall> {
        self.params.tool_call.as_ref()
    }

    pub fn is_tools_call(&self) -> bool {
        self.method == "tools/call"
    }

    pub fn is_tools_list(&self) -> bool {
        self.method == "tools/list"
    }

    pub fn is_notification_like(&self) -> bool {
        self.method.starts_with("notifications/")
    }
}

/// Tool call result placeholder with structured-content compatibility.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolCallResult {
    /// Legacy text content (kept for compatibility); also mirrored into MCP content.
    pub content: String,
    #[serde(default)]
    pub is_error: bool,
    /// Structured content/metadata (MCP `structuredContent` seam).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub structured: Option<serde_json::Value>,
}

impl ToolCallResult {
    pub fn as_call_tool_payload(&self) -> CallToolResultPayload {
        CallToolResultPayload {
            content: vec![ContentItem::text(self.content.clone())],
            is_error: self.is_error,
            structured_content: self.structured.clone(),
        }
    }
}

/// Error body aligned with JSON-RPC/MCP error shape.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct McpErrorBody {
    pub code: i32,
    pub message: String,
    /// Structured JSON error data (preferred).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

impl From<&FrontError> for McpErrorBody {
    fn from(e: &FrontError) -> Self {
        e.to_error_body()
    }
}

/// Outbound MCP response envelope.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct McpResponseEnvelope {
    pub id: RequestId,
    /// Tool-call style result (legacy/compat path).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<ToolCallResult>,
    /// Raw JSON-RPC/MCP result value (preferred for protocol methods like tools/list, initialize, ping).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub json_result: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<McpErrorBody>,
}

impl McpResponseEnvelope {
    pub fn to_json_rpc(&self) -> JsonRpcResponse {
        if let Some(err) = &self.error {
            JsonRpcResponse::failure(
                JsonRpcId::Str(self.id.clone()),
                JsonRpcError {
                    code: err.code,
                    message: err.message.clone(),
                    data: err.data.clone(),
                },
            )
        } else if let Some(val) = &self.json_result {
            JsonRpcResponse::success(JsonRpcId::Str(self.id.clone()), val.clone())
        } else {
            let val = self.result.as_ref().map(|r| {
                serde_json::to_value(r.as_call_tool_payload()).unwrap_or_else(|_| {
                    serde_json::json!({
                        "content":[{"type":"text","text":r.content}],
                        "isError":r.is_error
                    })
                })
            });
            JsonRpcResponse::success(
                JsonRpcId::Str(self.id.clone()),
                val.unwrap_or(serde_json::Value::Null),
            )
        }
    }
}

// ---------------------------------------------------------------------------
// Auth / decision / hook types
// ---------------------------------------------------------------------------

/// Token/context material surfaced by auth hooks.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct TokenContext {
    pub token: Option<String>,
    pub scheme: Option<String>,
    pub tenant_id: Option<String>,
    pub session_id: Option<String>,
    pub subject_hint: Option<String>,
    pub scopes: Vec<String>,
    pub claims: BTreeMap<String, String>,
}

impl TokenContext {
    pub fn is_present(&self) -> bool {
        self.token
            .as_ref()
            .map(|t| !t.trim().is_empty())
            .unwrap_or(false)
    }
}

/// Authentication/authorization context placeholder.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct AuthContext {
    pub subject: Option<String>,
    pub scopes: Vec<String>,
    pub token_present: bool,
    pub token: TokenContext,
    pub attributes: BTreeMap<String, String>,
}

/// Routing target selected for an upstream pool.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpstreamTarget {
    pub upstream_id: String,
    pub tool_name: Option<String>,
    pub method: String,
}

/// Dispatch request passed to pool adapters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DispatchRequest {
    pub target: UpstreamTarget,
    pub id: RequestId,
    pub method: String,
    pub tool_call: Option<ToolCall>,
    pub raw: String,
}

/// Policy/taint/approval decision points.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyDecision {
    Allow,
    Deny,
    RequireApproval,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TaintLevel {
    Clean,
    Tainted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApprovalDecision {
    NotRequired,
    Required,
    Approved,
    Denied,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionOutcome {
    pub policy: PolicyDecision,
    pub taint: TaintLevel,
    pub approval: ApprovalDecision,
    pub reason: Option<String>,
}

impl Default for DecisionOutcome {
    fn default() -> Self {
        Self {
            policy: PolicyDecision::Allow,
            taint: TaintLevel::Clean,
            approval: ApprovalDecision::NotRequired,
            reason: None,
        }
    }
}

/// Aggregated hook input for external/core integration adapters.
#[derive(Debug, Clone)]
pub struct HookContext<'a> {
    pub request: &'a McpRequestEnvelope,
    pub auth: &'a AuthContext,
    pub tool_call: Option<&'a ToolCall>,
    pub decision: Option<&'a DecisionOutcome>,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Front-layer errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrontError {
    Parse(String),
    Validation(String),
    MethodNotFound(String),
    Auth(String),
    Denied(String),
    Route(String),
    Dispatch(String),
    Internal(String),
}

impl fmt::Display for FrontError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FrontError::Parse(msg) => write!(f, "parse error: {msg}"),
            FrontError::Validation(msg) => write!(f, "validation error: {msg}"),
            FrontError::MethodNotFound(msg) => write!(f, "method not found: {msg}"),
            FrontError::Auth(msg) => write!(f, "auth error: {msg}"),
            FrontError::Denied(msg) => write!(f, "denied: {msg}"),
            FrontError::Route(msg) => write!(f, "route error: {msg}"),
            FrontError::Dispatch(msg) => write!(f, "dispatch error: {msg}"),
            FrontError::Internal(msg) => write!(f, "internal error: {msg}"),
        }
    }
}

impl std::error::Error for FrontError {}

impl FrontError {
    /// Maps front errors to JSON-RPC/MCP-style error codes.
    pub fn code(&self) -> i32 {
        match self {
            FrontError::Parse(_) => -32700,
            FrontError::Validation(_) => -32602,
            FrontError::MethodNotFound(_) => -32601,
            FrontError::Auth(_) => -32001,
            FrontError::Denied(_) => -32003,
            FrontError::Route(_) => -32004,
            FrontError::Dispatch(_) => -32000,
            FrontError::Internal(_) => -32603,
        }
    }

    pub fn to_error_body(&self) -> McpErrorBody {
        McpErrorBody {
            code: self.code(),
            message: self.to_string(),
            data: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Core traits (parsing, validation, hooks, routing, dispatch)
// ---------------------------------------------------------------------------

pub trait RequestParser {
    fn parse(&self, raw: &str) -> Result<McpRequestEnvelope, FrontError>;
}

pub trait RequestValidator {
    fn validate(&self, req: &McpRequestEnvelope) -> Result<(), FrontError>;
}

pub trait ToolCallExtractor {
    fn extract(&self, req: &McpRequestEnvelope) -> Result<Option<ToolCall>, FrontError>;
}

pub trait TokenContextProvider {
    fn token_context(&self, req: &McpRequestEnvelope) -> Result<TokenContext, FrontError>;
}

pub trait Authenticator {
    fn authenticate(
        &self,
        req: &McpRequestEnvelope,
        token: &TokenContext,
    ) -> Result<AuthContext, FrontError>;
}

pub trait PolicyEvaluator {
    fn evaluate(
        &self,
        req: &McpRequestEnvelope,
        auth: &AuthContext,
        tool_call: Option<&ToolCall>,
    ) -> Result<PolicyDecision, FrontError>;
}

pub trait TaintTracker {
    fn assess(
        &self,
        req: &McpRequestEnvelope,
        auth: &AuthContext,
        tool_call: Option<&ToolCall>,
    ) -> Result<TaintLevel, FrontError>;
}

pub trait ApprovalGate {
    fn decide(
        &self,
        req: &McpRequestEnvelope,
        auth: &AuthContext,
        tool_call: Option<&ToolCall>,
        taint: TaintLevel,
        policy: PolicyDecision,
    ) -> Result<ApprovalDecision, FrontError>;
}

/// Optional post-decision hook for audit/telemetry integration points.
pub trait DecisionObserver {
    fn on_decision(&self, _ctx: &HookContext<'_>, _outcome: &DecisionOutcome) {}
}

pub trait RequestRouter {
    fn route(
        &self,
        req: &McpRequestEnvelope,
        auth: &AuthContext,
        tool_call: Option<&ToolCall>,
    ) -> Result<UpstreamTarget, FrontError>;
}

pub trait UpstreamDispatcher {
    fn dispatch(&self, request: &DispatchRequest) -> Result<McpResponseEnvelope, FrontError>;
}

// ---------------------------------------------------------------------------
// Tool listing / call handling abstractions
// ---------------------------------------------------------------------------

/// Provides available tools for `tools/list`.
pub trait ToolListProvider {
    fn list_tools(&self, req: &McpRequestEnvelope) -> Result<ToolListResult, FrontError>;
}

/// Handles a resolved `tools/call`.
pub trait ToolCallHandler {
    fn call_tool(
        &self,
        req: &McpRequestEnvelope,
        auth: &AuthContext,
        call: &ToolCall,
    ) -> Result<ToolCallResult, FrontError>;
}

/// Optional protocol capability provider (initialize, ping, etc.).
pub trait ProtocolHandler {
    fn initialize(
        &self,
        _req: &McpRequestEnvelope,
        _params: Option<&InitializeParams>,
    ) -> Result<InitializeResult, FrontError> {
        Ok(InitializeResult::default())
    }
    fn ping(&self, _req: &McpRequestEnvelope) -> Result<serde_json::Value, FrontError> {
        Ok(serde_json::json!({}))
    }
}

/// Combined registry abstraction for listing and calling tools.
pub trait ToolRegistry: ToolListProvider + ToolCallHandler + ProtocolHandler {}

impl<T: ToolListProvider + ToolCallHandler + ProtocolHandler> ToolRegistry for T {}

/// In-memory tool registry stub.
#[derive(Debug, Default, Clone)]
pub struct InMemoryToolRegistry {
    tools: Vec<McpTool>,
}

impl InMemoryToolRegistry {
    pub fn new(tools: Vec<McpTool>) -> Self {
        Self { tools }
    }
    pub fn register(&mut self, tool: McpTool) {
        self.tools.push(tool);
    }
}

impl ToolListProvider for InMemoryToolRegistry {
    fn list_tools(&self, _req: &McpRequestEnvelope) -> Result<ToolListResult, FrontError> {
        Ok(ToolListResult {
            tools: self.tools.clone(),
            next_cursor: None,
        })
    }
}

impl ToolCallHandler for InMemoryToolRegistry {
    fn call_tool(
        &self,
        _req: &McpRequestEnvelope,
        _auth: &AuthContext,
        call: &ToolCall,
    ) -> Result<ToolCallResult, FrontError> {
        if !self.tools.iter().any(|t| t.name == call.name) {
            return Err(FrontError::MethodNotFound(format!("tool '{}'", call.name)));
        }
        Ok(ToolCallResult {
            content: format!("handled:{}", call.name),
            is_error: false,
            structured: None,
        })
    }
}

impl ProtocolHandler for InMemoryToolRegistry {}

/// Dispatcher that serves tools/list and tools/call from a registry, else forwards.
pub struct RegistryDispatcher<R, F> {
    pub registry: R,
    pub fallback: F,
}

impl<R: ToolRegistry, F: UpstreamDispatcher> UpstreamDispatcher for RegistryDispatcher<R, F> {
    fn dispatch(&self, request: &DispatchRequest) -> Result<McpResponseEnvelope, FrontError> {
        let req = McpRequestEnvelope {
            id: request.id.clone(),
            method: request.method.clone(),
            params: RequestParams {
                tool_call: request.tool_call.clone(),
                fields: BTreeMap::new(),
            },
            raw: request.raw.clone(),
            transport: TransportMetadata::default(),
        };
        match request.method.as_str() {
            "initialize" => {
                let params = serde_json::from_str::<JsonRpcRequest>(&request.raw)
                    .ok()
                    .and_then(|r| r.params)
                    .and_then(|p| serde_json::from_value::<InitializeParams>(p).ok());
                let init = self.registry.initialize(&req, params.as_ref())?;
                Ok(ResponseShaper::success_json(
                    request.id.clone(),
                    serde_json::to_value(init).unwrap_or(serde_json::json!({})),
                ))
            }
            "ping" => {
                let out = self.registry.ping(&req)?;
                Ok(ResponseShaper::success_json(request.id.clone(), out))
            }
            "tools/list" => {
                let list = self.registry.list_tools(&req)?;
                Ok(ResponseShaper::success_json(
                    request.id.clone(),
                    serde_json::to_value(list).unwrap_or_else(|_| serde_json::json!({"tools":[] })),
                ))
            }
            "tools/call" => {
                let call = request.tool_call.clone().ok_or_else(|| {
                    FrontError::Validation("tools/call requires tool_call".into())
                })?;
                let auth = AuthContext::default();
                match self.registry.call_tool(&req, &auth, &call) {
                    Ok(result) => Ok(ResponseShaper::success_tool(request.id.clone(), result)),
                    Err(FrontError::MethodNotFound(_)) => self.fallback.dispatch(request),
                    Err(e) => Err(e),
                }
            }
            _ => self.fallback.dispatch(request),
        }
    }
}

// ---------------------------------------------------------------------------
// Transport trait stubs (stdio / HTTP)
// ---------------------------------------------------------------------------

/// Generic message transport (frame in/out). Stub for rmcp integration.
pub trait Transport {
    fn receive(&mut self) -> Result<Option<String>, FrontError>;
    fn send(&mut self, payload: &str) -> Result<(), FrontError>;
}

/// Stdio transport stub using line-delimited JSON-RPC frames.
#[derive(Debug)]
pub struct StdioTransport<R, W> {
    reader: io::Lines<io::BufReader<R>>,
    writer: W,
}

impl<R: io::Read, W: Write> StdioTransport<R, W> {
    pub fn new(reader: R, writer: W) -> Self {
        Self {
            reader: io::BufReader::new(reader).lines(),
            writer,
        }
    }
}

impl<R: io::Read, W: Write> Transport for StdioTransport<R, W> {
    fn receive(&mut self) -> Result<Option<String>, FrontError> {
        match self.reader.next() {
            None => Ok(None),
            Some(Ok(line)) => {
                let t = line.trim().to_string();
                if t.is_empty() {
                    Ok(None)
                } else {
                    Ok(Some(t))
                }
            }
            Some(Err(e)) => Err(FrontError::Parse(format!("stdio read: {e}"))),
        }
    }

    fn send(&mut self, payload: &str) -> Result<(), FrontError> {
        writeln!(self.writer, "{payload}")
            .map_err(|e| FrontError::Internal(format!("stdio write: {e}")))?;
        self.writer
            .flush()
            .map_err(|e| FrontError::Internal(format!("stdio flush: {e}")))?;
        Ok(())
    }
}

/// HTTP transport stub (request/response framing handled by external server).
#[derive(Debug, Default, Clone)]
pub struct HttpTransportStub {
    pub endpoint: Option<String>,
    /// Buffered inbound messages (simulated request queue).
    pub inbox: Vec<String>,
    /// Captured outbound messages.
    pub outbox: Vec<String>,
}

impl HttpTransportStub {
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: Some(endpoint.into()),
            inbox: Vec::new(),
            outbox: Vec::new(),
        }
    }
    pub fn push_inbound(&mut self, msg: impl Into<String>) {
        self.inbox.push(msg.into());
    }
}

impl Transport for HttpTransportStub {
    fn receive(&mut self) -> Result<Option<String>, FrontError> {
        if self.inbox.is_empty() {
            Ok(None)
        } else {
            Ok(Some(self.inbox.remove(0)))
        }
    }
    fn send(&mut self, payload: &str) -> Result<(), FrontError> {
        self.outbox.push(payload.to_string());
        Ok(())
    }
}

/// Runs a simple receive/handle/send loop over a transport.
pub fn serve_transport<T: Transport, F>(transport: &mut T, mut handle: F) -> Result<(), FrontError>
where
    F: FnMut(&str) -> McpResponseEnvelope,
{
    while let Some(msg) = transport.receive()? {
        let resp = handle(&msg);
        let payload = serde_json::to_string(&resp.to_json_rpc())
            .map_err(|e| FrontError::Internal(format!("serialize: {e}")))?;
        transport.send(&payload)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Parsers and default implementations (existing + JSON-RPC)
// ---------------------------------------------------------------------------

/// Default parser: minimal `id|method|tool|k=v,...` format for skeleton/tests.
/// TODO(rmcp): replace with real MCP/JSON-RPC decoding.
#[derive(Debug, Default, Clone, Copy)]
pub struct SkeletonParser;

impl RequestParser for SkeletonParser {
    fn parse(&self, raw: &str) -> Result<McpRequestEnvelope, FrontError> {
        let raw = raw.trim();
        if raw.is_empty() {
            return Err(FrontError::Parse("empty request".into()));
        }

        let mut parts = raw.splitn(4, '|');
        let id = parts.next().unwrap_or_default().trim().to_string();
        let method = parts.next().unwrap_or_default().trim().to_string();
        if id.is_empty() || method.is_empty() {
            return Err(FrontError::Parse("expected id|method|...".into()));
        }

        let mut params = RequestParams::default();
        match (parts.next(), parts.next()) {
            (Some(name), Some(args)) if !name.trim().is_empty() => {
                params.tool_call = Some(ToolCall {
                    name: name.trim().to_string(),
                    arguments: parse_args(args),
                    raw_arguments: None,
                });
            }
            (Some(name), None) if !name.trim().is_empty() && method == "tools/call" => {
                params.tool_call = Some(ToolCall {
                    name: name.trim().to_string(),
                    arguments: BTreeMap::new(),
                    raw_arguments: None,
                });
            }
            (Some(field_blob), None) if method != "tools/call" && !field_blob.trim().is_empty() => {
                params.fields = parse_args(field_blob);
            }
            _ => {}
        }

        Ok(McpRequestEnvelope {
            id,
            method,
            params,
            raw: raw.to_string(),
            transport: TransportMetadata::default(),
        })
    }
}

fn parse_args(raw: &str) -> BTreeMap<String, String> {
    raw.split(',')
        .filter_map(|pair| {
            let pair = pair.trim();
            if pair.is_empty() {
                return None;
            }
            let mut kv = pair.splitn(2, '=');
            let k = kv.next()?.trim();
            let v = kv.next().unwrap_or("").trim();
            if k.is_empty() {
                None
            } else {
                Some((k.to_string(), v.to_string()))
            }
        })
        .collect()
}

/// JSON-RPC parser stub for MCP messages (`tools/call`, `tools/list`, etc.).
///
/// Parses protocol envelope fields, preserves best-effort string params for hooks,
/// and extracts structured `tools/call` arguments for front-to-pool bridging.
#[derive(Debug, Default, Clone, Copy)]
pub struct JsonRpcParser;

impl RequestParser for JsonRpcParser {
    fn parse(&self, raw: &str) -> Result<McpRequestEnvelope, FrontError> {
        let raw = raw.trim();
        if raw.is_empty() {
            return Err(FrontError::Parse("empty request".into()));
        }
        let value: serde_json::Value = serde_json::from_str(raw)
            .map_err(|e| FrontError::Parse(format!("invalid json-rpc: {e}")))?;
        let obj = value
            .as_object()
            .ok_or_else(|| FrontError::Parse("json-rpc request must be an object".into()))?;
        if obj.get("jsonrpc").and_then(|v| v.as_str()) != Some("2.0") {
            return Err(FrontError::Parse("jsonrpc must be '2.0'".into()));
        }
        let method = obj
            .get("method")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FrontError::Parse("json-rpc method must be a string".into()))?
            .to_string();
        let id = match obj.get("id") {
            None | Some(serde_json::Value::Null) => "notification".into(),
            Some(serde_json::Value::String(s)) => s.clone(),
            Some(serde_json::Value::Number(n)) => n.to_string(),
            Some(_) => {
                return Err(FrontError::Parse(
                    "json-rpc id must be a string, number, or null".into(),
                ))
            }
        };

        let mut params = RequestParams::default();
        match obj.get("params") {
            None | Some(serde_json::Value::Null) => {}
            Some(p) => {
                // Best-effort flat fields for auth/policy/routing hooks.
                if let Some(map) = p.as_object() {
                    for (k, v) in map {
                        match v {
                            serde_json::Value::String(s) => {
                                params.fields.insert(k.clone(), s.clone());
                            }
                            serde_json::Value::Number(n) => {
                                params.fields.insert(k.clone(), n.to_string());
                            }
                            serde_json::Value::Bool(b) => {
                                params.fields.insert(k.clone(), b.to_string());
                            }
                            _ => {}
                        }
                    }
                }

                if method == "tools/call" {
                    // Validate/extract via rmcp's protocol model for upstream compatibility,
                    // then preserve front's flat/raw argument views for hooks and dispatch.
                    let rmcp_call: rmcp::model::CallToolRequestParam =
                        serde_json::from_value(p.clone()).map_err(|e| {
                            FrontError::Validation(format!("invalid tools/call params: {e}"))
                        })?;
                    let raw_arguments = rmcp_call
                        .arguments
                        .as_ref()
                        .map(|m| serde_json::Value::Object(m.clone()));
                    let mut flat = BTreeMap::new();
                    if let Some(map) = &rmcp_call.arguments {
                        for (k, v) in map {
                            if let Some(s) = v.as_str() {
                                flat.insert(k.clone(), s.to_string());
                            } else {
                                flat.insert(k.clone(), v.to_string());
                            }
                        }
                    }
                    params.tool_call = Some(ToolCall {
                        name: rmcp_call.name.to_string(),
                        arguments: flat,
                        raw_arguments,
                    });
                }
            }
        }

        Ok(McpRequestEnvelope {
            id,
            method,
            params,
            raw: raw.to_string(),
            transport: TransportMetadata::default(),
        })
    }
}

/// Auto parser: tries JSON-RPC for JSON payloads, else skeleton format.
#[derive(Debug, Default, Clone, Copy)]
pub struct AutoParser;

impl RequestParser for AutoParser {
    fn parse(&self, raw: &str) -> Result<McpRequestEnvelope, FrontError> {
        let trimmed = raw.trim();
        if trimmed.starts_with('{') || trimmed.starts_with('[') {
            JsonRpcParser.parse(trimmed)
        } else {
            SkeletonParser.parse(trimmed)
        }
    }
}

/// Basic semantic validator for envelopes.
#[derive(Debug, Default, Clone, Copy)]
pub struct BasicRequestValidator;

impl RequestValidator for BasicRequestValidator {
    fn validate(&self, req: &McpRequestEnvelope) -> Result<(), FrontError> {
        if req.id.trim().is_empty() {
            return Err(FrontError::Validation("id must be non-empty".into()));
        }
        if req.method.trim().is_empty() {
            return Err(FrontError::Validation("method must be non-empty".into()));
        }
        match req.method.as_str() {
            "tools/call" => {
                let tc = req.tool_call().ok_or_else(|| {
                    FrontError::Validation("tools/call requires tool_call".into())
                })?;
                if tc.name.trim().is_empty() {
                    return Err(FrontError::Validation("tool name must be non-empty".into()));
                }
            }
            "tools/list" | "ping" | "initialize" => {}
            m if m.starts_with("prompts/")
                || m.starts_with("resources/")
                || m.starts_with("completion/")
                || m.starts_with("logging/")
                || m.starts_with("notifications/") => {}
            _ => {
                // TODO(rmcp): tighten once protocol surface is fully modeled.
            }
        }
        Ok(())
    }
}

/// Default extractor: returns cloned tool call if present.
#[derive(Debug, Default, Clone, Copy)]
pub struct DefaultToolCallExtractor;

impl ToolCallExtractor for DefaultToolCallExtractor {
    fn extract(&self, req: &McpRequestEnvelope) -> Result<Option<ToolCall>, FrontError> {
        Ok(req.params.tool_call.clone())
    }
}

/// Token hook that extracts bearer tokens and selected metadata from transport/params.
#[derive(Debug, Default, Clone, Copy)]
pub struct HeaderTokenContextProvider;

impl TokenContextProvider for HeaderTokenContextProvider {
    fn token_context(&self, req: &McpRequestEnvelope) -> Result<TokenContext, FrontError> {
        let mut ctx = TokenContext {
            session_id: req
                .transport
                .session_id
                .clone()
                .or_else(|| req.transport.header("mcp-session-id").map(str::to_string))
                .or_else(|| req.params.fields.get("session_id").cloned()),
            ..Default::default()
        };

        if let Some(raw) = req
            .transport
            .header("authorization")
            .or_else(|| req.params.fields.get("authorization").map(String::as_str))
        {
            let raw = raw.trim();
            if let Some(token) = raw
                .strip_prefix("Bearer ")
                .or_else(|| raw.strip_prefix("bearer "))
            {
                let token = token.trim();
                if token.is_empty() {
                    return Err(FrontError::Auth("empty bearer token".into()));
                }
                ctx.scheme = Some("bearer".into());
                ctx.token = Some(token.to_string());
            } else if !raw.is_empty() {
                ctx.scheme = Some("opaque".into());
                ctx.token = Some(raw.to_string());
            }
        }

        ctx.tenant_id = req
            .transport
            .header("x-tenant-id")
            .map(str::to_string)
            .or_else(|| req.params.fields.get("tenant_id").cloned());
        ctx.subject_hint = req
            .transport
            .header("x-subject")
            .map(str::to_string)
            .or_else(|| req.params.fields.get("subject").cloned());

        if let Some(scopes) = req
            .transport
            .header("x-scopes")
            .or_else(|| req.params.fields.get("scopes").map(String::as_str))
        {
            ctx.scopes = scopes
                .split(|c: char| c == ',' || c.is_whitespace())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
                .collect();
        }

        for (k, v) in &req.transport.headers {
            ctx.claims.insert(format!("header.{k}"), v.clone());
        }
        Ok(ctx)
    }
}

/// Default authenticator placeholder using token context hook.
#[derive(Debug, Default, Clone, Copy)]
pub struct PlaceholderAuthenticator;

impl Authenticator for PlaceholderAuthenticator {
    fn authenticate(
        &self,
        req: &McpRequestEnvelope,
        token: &TokenContext,
    ) -> Result<AuthContext, FrontError> {
        if req.id.is_empty() {
            return Err(FrontError::Auth("missing request id".into()));
        }
        let mut scopes = if token.scopes.is_empty() {
            vec!["mcp:call".into()]
        } else {
            token.scopes.clone()
        };
        scopes.sort();
        scopes.dedup();
        let mut attributes = BTreeMap::new();
        if let Some(t) = &token.tenant_id {
            attributes.insert("tenant_id".into(), t.clone());
        }
        if let Some(s) = &token.session_id {
            attributes.insert("session_id".into(), s.clone());
        }
        Ok(AuthContext {
            subject: token
                .subject_hint
                .clone()
                .or_else(|| Some("anonymous".into())),
            scopes,
            token_present: token.is_present(),
            token: token.clone(),
            attributes,
        })
    }
}

/// Authenticator that requires a present token.
#[derive(Debug, Default, Clone, Copy)]
pub struct RequireTokenAuthenticator;

impl Authenticator for RequireTokenAuthenticator {
    fn authenticate(
        &self,
        req: &McpRequestEnvelope,
        token: &TokenContext,
    ) -> Result<AuthContext, FrontError> {
        let auth = PlaceholderAuthenticator.authenticate(req, token)?;
        if !auth.token_present {
            return Err(FrontError::Auth("missing token".into()));
        }
        Ok(auth)
    }
}

/// Permissive policy/taint/approval placeholders.
#[derive(Debug, Default, Clone, Copy)]
pub struct AllowAllPolicy;
impl PolicyEvaluator for AllowAllPolicy {
    fn evaluate(
        &self,
        _req: &McpRequestEnvelope,
        _auth: &AuthContext,
        _tool_call: Option<&ToolCall>,
    ) -> Result<PolicyDecision, FrontError> {
        Ok(PolicyDecision::Allow)
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct CleanTaintTracker;
impl TaintTracker for CleanTaintTracker {
    fn assess(
        &self,
        _req: &McpRequestEnvelope,
        _auth: &AuthContext,
        _tool_call: Option<&ToolCall>,
    ) -> Result<TaintLevel, FrontError> {
        Ok(TaintLevel::Clean)
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct NoApprovalGate;
impl ApprovalGate for NoApprovalGate {
    fn decide(
        &self,
        _req: &McpRequestEnvelope,
        _auth: &AuthContext,
        _tool_call: Option<&ToolCall>,
        _taint: TaintLevel,
        policy: PolicyDecision,
    ) -> Result<ApprovalDecision, FrontError> {
        Ok(match policy {
            PolicyDecision::RequireApproval => ApprovalDecision::Required,
            _ => ApprovalDecision::NotRequired,
        })
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct NoopDecisionObserver;
impl DecisionObserver for NoopDecisionObserver {}

/// Default router: routes tool calls to `default` upstream by tool name.
#[derive(Debug, Default, Clone, Copy)]
pub struct PlaceholderRouter;

impl RequestRouter for PlaceholderRouter {
    fn route(
        &self,
        req: &McpRequestEnvelope,
        auth: &AuthContext,
        tool_call: Option<&ToolCall>,
    ) -> Result<UpstreamTarget, FrontError> {
        if auth.scopes.is_empty() {
            return Err(FrontError::Route("missing scopes".into()));
        }
        let tool_name = tool_call.map(|t| t.name.clone());
        if req.is_tools_call() && tool_name.as_deref().unwrap_or("").is_empty() {
            return Err(FrontError::Route("tools/call requires tool name".into()));
        }
        Ok(UpstreamTarget {
            upstream_id: "default".into(),
            tool_name,
            method: req.method.clone(),
        })
    }
}

/// Router that honors an explicit upstream hint from transport attributes/params.
///
/// Falls back to `PlaceholderRouter` behavior (including scope/tool validation) and
/// only overrides `upstream_id` when a non-empty hint is present.
#[derive(Debug, Default, Clone, Copy)]
pub struct UpstreamHintRouter;

impl UpstreamHintRouter {
    pub fn hinted_upstream(req: &McpRequestEnvelope) -> Option<String> {
        req.transport
            .attribute("upstream")
            .or_else(|| req.transport.attribute("upstream_id"))
            .or_else(|| req.params.fields.get("upstream").map(String::as_str))
            .or_else(|| req.params.fields.get("upstream_id").map(String::as_str))
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    }
}

impl RequestRouter for UpstreamHintRouter {
    fn route(
        &self,
        req: &McpRequestEnvelope,
        auth: &AuthContext,
        tool_call: Option<&ToolCall>,
    ) -> Result<UpstreamTarget, FrontError> {
        let mut target = PlaceholderRouter.route(req, auth, tool_call)?;
        if let Some(upstream) = Self::hinted_upstream(req) {
            target.upstream_id = upstream;
        }
        Ok(target)
    }
}

/// Default dispatcher placeholder producing a routed response envelope.
#[derive(Debug, Default, Clone, Copy)]
pub struct PlaceholderDispatcher;

impl UpstreamDispatcher for PlaceholderDispatcher {
    fn dispatch(&self, request: &DispatchRequest) -> Result<McpResponseEnvelope, FrontError> {
        Ok(ResponseShaper::success(
            request.id.clone(),
            format!(
                "routed:{}:{}",
                request.target.upstream_id,
                request
                    .target
                    .tool_name
                    .as_deref()
                    .unwrap_or(request.method.as_str())
            ),
        ))
    }
}

/// Shapes responses and maps errors into MCP envelopes.
#[derive(Debug, Default, Clone, Copy)]
pub struct ResponseShaper;

impl ResponseShaper {
    pub fn success(id: RequestId, content: String) -> McpResponseEnvelope {
        McpResponseEnvelope {
            id,
            result: Some(ToolCallResult {
                content,
                is_error: false,
                structured: None,
            }),
            json_result: None,
            error: None,
        }
    }

    pub fn success_json(id: RequestId, value: serde_json::Value) -> McpResponseEnvelope {
        McpResponseEnvelope {
            id,
            result: None,
            json_result: Some(value),
            error: None,
        }
    }

    pub fn success_tool(id: RequestId, result: ToolCallResult) -> McpResponseEnvelope {
        McpResponseEnvelope {
            id,
            result: Some(result),
            json_result: None,
            error: None,
        }
    }

    pub fn map_error(id: RequestId, err: &FrontError) -> McpResponseEnvelope {
        McpResponseEnvelope {
            id,
            result: None,
            json_result: None,
            error: Some(err.to_error_body()),
        }
    }

    pub fn shape_upstream(mut resp: McpResponseEnvelope) -> McpResponseEnvelope {
        // Normalize protocol-facing success envelopes for JSON-RPC/rmcp bridges.
        if resp.error.is_none() && resp.json_result.is_none() && resp.result.is_none() {
            resp.json_result = Some(serde_json::Value::Null);
        }
        resp
    }
}

// ---------------------------------------------------------------------------
// MCP front facade
// ---------------------------------------------------------------------------

/// MCP front facade: parse -> validate/extract -> auth -> decisions -> route -> dispatch -> shape.
#[derive(Debug, Clone)]
pub struct McpFront<
    P = SkeletonParser,
    V = BasicRequestValidator,
    E = DefaultToolCallExtractor,
    T = HeaderTokenContextProvider,
    A = PlaceholderAuthenticator,
    Pol = AllowAllPolicy,
    Ta = CleanTaintTracker,
    Ap = NoApprovalGate,
    R = UpstreamHintRouter,
    D = PlaceholderDispatcher,
> {
    parser: P,
    validator: V,
    extractor: E,
    token_provider: T,
    authenticator: A,
    policy: Pol,
    taint: Ta,
    approval: Ap,
    router: R,
    dispatcher: D,
}

impl Default for McpFront {
    fn default() -> Self {
        Self::new(
            SkeletonParser,
            BasicRequestValidator,
            DefaultToolCallExtractor,
            HeaderTokenContextProvider,
            PlaceholderAuthenticator,
            AllowAllPolicy,
            CleanTaintTracker,
            NoApprovalGate,
            UpstreamHintRouter,
            PlaceholderDispatcher,
        )
    }
}

impl<P, V, E, T, A, Pol, Ta, Ap, R, D> McpFront<P, V, E, T, A, Pol, Ta, Ap, R, D> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        parser: P,
        validator: V,
        extractor: E,
        token_provider: T,
        authenticator: A,
        policy: Pol,
        taint: Ta,
        approval: Ap,
        router: R,
        dispatcher: D,
    ) -> Self {
        Self {
            parser,
            validator,
            extractor,
            token_provider,
            authenticator,
            policy,
            taint,
            approval,
            router,
            dispatcher,
        }
    }
}

impl<P, V, E, T, A, Pol, Ta, Ap, R, D> McpFront<P, V, E, T, A, Pol, Ta, Ap, R, D>
where
    P: RequestParser,
    V: RequestValidator,
    E: ToolCallExtractor,
    T: TokenContextProvider,
    A: Authenticator,
    Pol: PolicyEvaluator,
    Ta: TaintTracker,
    Ap: ApprovalGate,
    R: RequestRouter,
    D: UpstreamDispatcher,
{
    /// Accepts raw input and returns a response envelope.
    pub fn accept(&self, raw: &str) -> Result<McpResponseEnvelope, FrontError> {
        let req = self.parser.parse(raw)?;
        self.accept_request(req)
    }

    /// Accepts raw input with transport metadata and returns a response envelope.
    ///
    /// This preserves auth/policy/taint hook context for runtime transports while
    /// keeping parsing and dispatch fail-closed.
    pub fn accept_with_transport(
        &self,
        raw: &str,
        transport: TransportMetadata,
    ) -> Result<McpResponseEnvelope, FrontError> {
        let mut req = self.parser.parse(raw)?;
        req.transport = transport;
        self.accept_request(req)
    }

    /// Accepts a parsed/constructed request and returns a response envelope.
    pub fn accept_request(
        &self,
        req: McpRequestEnvelope,
    ) -> Result<McpResponseEnvelope, FrontError> {
        self.validator.validate(&req)?;
        let tool_call = self.extractor.extract(&req)?;
        let token = self.token_provider.token_context(&req)?;
        let auth = self.authenticator.authenticate(&req, &token)?;
        let _decision = self.evaluate_decisions(&req, &auth, tool_call.as_ref())?;
        let target = self.router.route(&req, &auth, tool_call.as_ref())?;
        let dispatch_req = DispatchRequest {
            target,
            id: req.id.clone(),
            method: req.method.clone(),
            tool_call,
            raw: req.raw.clone(),
        };
        let resp = self.dispatcher.dispatch(&dispatch_req)?;
        Ok(ResponseShaper::shape_upstream(resp))
    }

    /// Accepts raw input and maps any front error to a shaped error response when possible.
    pub fn accept_mapped(&self, raw: &str) -> McpResponseEnvelope {
        match self.accept(raw) {
            Ok(resp) => resp,
            Err(err) => ResponseShaper::map_error(Self::best_effort_id(raw), &err),
        }
    }

    /// Accepts raw input with transport metadata and maps errors to shaped responses.
    pub fn accept_mapped_with_transport(
        &self,
        raw: &str,
        transport: TransportMetadata,
    ) -> McpResponseEnvelope {
        match self.accept_with_transport(raw, transport) {
            Ok(resp) => resp,
            Err(err) => ResponseShaper::map_error(Self::best_effort_id(raw), &err),
        }
    }

    pub fn evaluate_decisions(
        &self,
        req: &McpRequestEnvelope,
        auth: &AuthContext,
        tool_call: Option<&ToolCall>,
    ) -> Result<DecisionOutcome, FrontError> {
        let policy = self.policy.evaluate(req, auth, tool_call)?;
        let taint = self.taint.assess(req, auth, tool_call)?;
        let approval = self.approval.decide(req, auth, tool_call, taint, policy)?;
        let outcome = DecisionOutcome {
            policy,
            taint,
            approval,
            reason: None,
        };

        match policy {
            PolicyDecision::Deny => return Err(FrontError::Denied("policy denied".into())),
            PolicyDecision::RequireApproval => {
                if !matches!(approval, ApprovalDecision::Approved) {
                    return Err(FrontError::Denied("approval required".into()));
                }
            }
            PolicyDecision::Allow => {}
        }

        match approval {
            ApprovalDecision::Denied | ApprovalDecision::Required => {
                return Err(FrontError::Denied(format!("approval {:?}", approval)))
            }
            ApprovalDecision::Approved | ApprovalDecision::NotRequired => {}
        }

        Ok(outcome)
    }

    fn best_effort_id(raw: &str) -> RequestId {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return "unknown".into();
        }
        if trimmed.starts_with('{') || trimmed.starts_with('[') {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(trimmed) {
                if let Some(id) = v.get("id") {
                    return match id {
                        serde_json::Value::String(s) => s.clone(),
                        serde_json::Value::Number(n) => n.to_string(),
                        _ => "unknown".into(),
                    };
                }
            }
            return "unknown".into();
        }
        trimmed
            .split('|')
            .next()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("unknown")
            .to_string()
    }
}

// ---------------------------------------------------------------------------
// Integration seams / rmcp-ready transport stubs
// ---------------------------------------------------------------------------

/// Async transport seam (rmcp/tokio-ready). Implementations should be fail-closed.
#[async_trait::async_trait]
pub trait AsyncTransport: Send {
    async fn receive(&mut self) -> Result<Option<String>, FrontError>;
    async fn send(&mut self, payload: &str) -> Result<(), FrontError>;
}

/// Async stdio seam stub; wire to tokio::io in transport implementation crates/adapters.
#[derive(Debug, Default)]
pub struct AsyncStdioTransportStub {
    pub inbox: Vec<String>,
    pub outbox: Vec<String>,
}

#[async_trait::async_trait]
impl AsyncTransport for AsyncStdioTransportStub {
    async fn receive(&mut self) -> Result<Option<String>, FrontError> {
        Ok(if self.inbox.is_empty() {
            None
        } else {
            Some(self.inbox.remove(0))
        })
    }
    async fn send(&mut self, payload: &str) -> Result<(), FrontError> {
        self.outbox.push(payload.to_string());
        Ok(())
    }
}

/// HTTP/SSE/WebSocket transport integration stub with rmcp wiring points.
#[derive(Debug, Clone, Default)]
pub struct RmcpHttpTransportConfig {
    pub bind_or_endpoint: Option<String>,
    pub auth_required: bool,
    pub tls_enabled: bool,
}

#[derive(Debug, Clone, Default)]
pub struct RmcpTransportAdapter {
    pub kind: String,
    pub config: RmcpHttpTransportConfig,
}

impl RmcpTransportAdapter {
    pub fn stdio() -> Self {
        Self {
            kind: "stdio".into(),
            config: RmcpHttpTransportConfig::default(),
        }
    }
    pub fn http(endpoint: impl Into<String>) -> Self {
        Self {
            kind: "http".into(),
            config: RmcpHttpTransportConfig {
                bind_or_endpoint: Some(endpoint.into()),
                auth_required: true,
                tls_enabled: false,
            },
        }
    }
}

/// rmcp dependency is present for compile-intent wiring; replace stubs with real types incrementally.
#[doc(hidden)]
pub use rmcp as _rmcp_dep_ready;

/// Fail-closed placeholder for rmcp session/service bridge.
///
/// TODO(rmcp): replace with `rmcp::ServiceExt` / server session wiring when
/// protocol handlers are connected to real transports.
#[derive(Debug, Default, Clone)]
pub struct RmcpServiceBridgeStub {
    pub protocol_version: String,
    pub ready: bool,
}

impl RmcpServiceBridgeStub {
    pub fn new() -> Self {
        Self {
            protocol_version: "2024-11-05".into(),
            ready: false,
        }
    }
    pub fn ensure_ready(&self) -> Result<(), FrontError> {
        if self.ready {
            Ok(())
        } else {
            Err(FrontError::Internal(
                "rmcp bridge not wired (stub, fail-closed)".into(),
            ))
        }
    }
}

/// Core-integration seams (auth/policy/taint/approval) for external evaluators.
///
/// These are intentionally narrow so `core`/`broker` adapters can be plugged in
/// without changing front control flow.
pub trait CorePolicyAdapter: Send + Sync {
    fn evaluate(&self, ctx: &HookContext<'_>) -> Result<PolicyDecision, FrontError>;
}
pub trait CoreTaintAdapter: Send + Sync {
    fn assess(&self, ctx: &HookContext<'_>) -> Result<TaintLevel, FrontError>;
}
pub trait CoreApprovalAdapter: Send + Sync {
    fn decide(
        &self,
        ctx: &HookContext<'_>,
        policy: PolicyDecision,
        taint: TaintLevel,
    ) -> Result<ApprovalDecision, FrontError>;
}

/// Fail-closed adapter defaults (deny/tainted/required) for safe composition.
#[derive(Debug, Default, Clone, Copy)]
pub struct FailClosedCoreAdapters;

impl CorePolicyAdapter for FailClosedCoreAdapters {
    fn evaluate(&self, _ctx: &HookContext<'_>) -> Result<PolicyDecision, FrontError> {
        Ok(PolicyDecision::Deny)
    }
}
impl CoreTaintAdapter for FailClosedCoreAdapters {
    fn assess(&self, _ctx: &HookContext<'_>) -> Result<TaintLevel, FrontError> {
        Ok(TaintLevel::Tainted)
    }
}
impl CoreApprovalAdapter for FailClosedCoreAdapters {
    fn decide(
        &self,
        _ctx: &HookContext<'_>,
        _policy: PolicyDecision,
        _taint: TaintLevel,
    ) -> Result<ApprovalDecision, FrontError> {
        Ok(ApprovalDecision::Denied)
    }
}

// ---------------------------------------------------------------------------
// Pool dispatch integration hooks (mcp-pool)
// ---------------------------------------------------------------------------

fn is_jsonrpc_notification_raw(raw: &str) -> bool {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(raw.trim()) else {
        return false;
    };
    let Some(obj) = v.as_object() else {
        return false;
    };
    obj.contains_key("method") && !obj.contains_key("id")
}

fn dispatch_pool_jsonrpc_payload(request: &DispatchRequest) -> String {
    // Prefer forwarding the original JSON-RPC envelope when present so arbitrary
    // method params/ids are preserved for rmcp/front-to-pool runtime bridges.
    if let Ok(mut v) = serde_json::from_str::<serde_json::Value>(&request.raw) {
        if let Some(obj) = v.as_object_mut() {
            obj.entry("jsonrpc".to_string())
                .or_insert_with(|| serde_json::json!("2.0"));
            if obj.get("id").is_none() && !is_jsonrpc_notification_raw(&request.raw) {
                obj.insert("id".to_string(), serde_json::json!(request.id));
            }
            if obj.get("method").is_none() {
                obj.insert("method".to_string(), serde_json::json!(request.method));
            }
            if obj.get("params").is_none() {
                if let Some(tc) = &request.tool_call {
                    obj.insert(
                        "params".to_string(),
                        serde_json::json!({
                            "name": tc.name,
                            "arguments": tc.raw_arguments.clone().unwrap_or_else(|| {
                                serde_json::to_value(&tc.arguments).unwrap_or(serde_json::json!({}))
                            }),
                        }),
                    );
                }
            }
            return v.to_string();
        }
    }

    if is_jsonrpc_notification_raw(&request.raw) {
        return serde_json::json!({
            "jsonrpc": "2.0",
            "method": request.method,
            "params": request.tool_call.as_ref().map(|tc| serde_json::json!({
                "name": tc.name,
                "arguments": tc.raw_arguments.clone().unwrap_or_else(|| {
                    serde_json::to_value(&tc.arguments).unwrap_or(serde_json::json!({}))
                }),
            })),
        })
        .to_string();
    }

    serde_json::json!({
        "jsonrpc": "2.0",
        "id": request.id,
        "method": request.method,
        "params": request.tool_call.as_ref().map(|tc| serde_json::json!({
            "name": tc.name,
            "arguments": tc.raw_arguments.clone().unwrap_or_else(|| {
                serde_json::to_value(&tc.arguments).unwrap_or(serde_json::json!({}))
            }),
        })),
    })
    .to_string()
}

fn decode_pool_forward_response(request_id: &str, payload: &str) -> McpResponseEnvelope {
    let trimmed = payload.trim();
    if trimmed.is_empty() {
        return ResponseShaper::map_error(
            request_id.to_string(),
            &FrontError::Dispatch("empty upstream response payload".into()),
        );
    }

    if let Ok(resp) = serde_json::from_str::<JsonRpcResponse>(trimmed) {
        if resp.result.is_none() && resp.error.is_none() {
            return ResponseShaper::map_error(
                request_id.to_string(),
                &FrontError::Dispatch("upstream response missing result/error".into()),
            );
        }
        return McpResponseEnvelope {
            id: resp.id.as_request_id(),
            result: None,
            json_result: resp.result,
            error: resp.error.map(|e| McpErrorBody {
                code: e.code,
                message: e.message,
                data: e.data,
            }),
        };
    }

    let Ok(value) = serde_json::from_str::<serde_json::Value>(trimmed) else {
        return ResponseShaper::map_error(
            request_id.to_string(),
            &FrontError::Dispatch("upstream response is not valid JSON".into()),
        );
    };

    let Some(obj) = value.as_object() else {
        return ResponseShaper::map_error(
            request_id.to_string(),
            &FrontError::Dispatch("upstream response must be a JSON-RPC object".into()),
        );
    };

    // Fail-closed normalization: only accept response-shaped JSON-RPC objects.
    let has_result = obj.contains_key("result");
    let has_error = obj.contains_key("error");
    if !has_result && !has_error {
        return ResponseShaper::map_error(
            request_id.to_string(),
            &FrontError::Dispatch("upstream response missing result/error".into()),
        );
    }

    let id = match obj.get("id") {
        Some(serde_json::Value::String(s)) => s.clone(),
        Some(serde_json::Value::Number(n)) => n.to_string(),
        Some(serde_json::Value::Null) | None => request_id.to_string(),
        Some(_) => {
            return ResponseShaper::map_error(
                request_id.to_string(),
                &FrontError::Dispatch("upstream response id has invalid type".into()),
            );
        }
    };

    let error = match obj.get("error") {
        None | Some(serde_json::Value::Null) => None,
        Some(err_val) => {
            let Some(err_obj) = err_val.as_object() else {
                return ResponseShaper::map_error(
                    request_id.to_string(),
                    &FrontError::Dispatch("upstream response error must be an object".into()),
                );
            };
            let Some(code) = err_obj.get("code").and_then(serde_json::Value::as_i64) else {
                return ResponseShaper::map_error(
                    request_id.to_string(),
                    &FrontError::Dispatch("upstream response error.code must be an integer".into()),
                );
            };
            let Ok(code) = i32::try_from(code) else {
                return ResponseShaper::map_error(
                    request_id.to_string(),
                    &FrontError::Dispatch("upstream response error.code out of range".into()),
                );
            };
            let message = err_obj
                .get("message")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("upstream error")
                .to_string();
            Some(McpErrorBody {
                code,
                message,
                data: err_obj.get("data").cloned(),
            })
        }
    };

    McpResponseEnvelope {
        id,
        result: None,
        json_result: obj
            .get("result")
            .cloned()
            .filter(|v| !v.is_null() || error.is_none()),
        error,
    }
}

/// Adapts an `mcp_pool::RequestForwarder` as an `UpstreamDispatcher`.
///
/// Tool calls and protocol requests are forwarded as JSON-RPC envelopes.
/// For JSON requests, original params/id are preserved when possible to keep
/// front-to-pool bridging close to rmcp-compatible runtime flows.
pub struct PoolRequestForwarderDispatcher<F> {
    pub forwarder: F,
    pub upstream_id: mcp_pool::UpstreamId,
}

impl<F> PoolRequestForwarderDispatcher<F> {
    pub fn new(forwarder: F, upstream_id: impl Into<String>) -> Self {
        Self {
            forwarder,
            upstream_id: mcp_pool::UpstreamId(upstream_id.into()),
        }
    }

    fn resolve_upstream_id(&self, request: &DispatchRequest) -> mcp_pool::UpstreamId {
        let target = request.target.upstream_id.trim();
        if target.is_empty() {
            self.upstream_id.clone()
        } else {
            mcp_pool::UpstreamId(target.to_string())
        }
    }
}

impl<F: mcp_pool::RequestForwarder> UpstreamDispatcher for PoolRequestForwarderDispatcher<F> {
    fn dispatch(&self, _request: &DispatchRequest) -> Result<McpResponseEnvelope, FrontError> {
        // RequestForwarder takes &mut self in pool API; immutable dispatch is fail-closed.
        // Use `dispatch_mut` or `SharedPoolForwarderDispatcher`.
        Err(FrontError::Dispatch(
            "PoolRequestForwarderDispatcher requires mutable forwarder; use dispatch_mut or SharedPoolForwarderDispatcher".into(),
        ))
    }
}

impl<F: mcp_pool::RequestForwarder> PoolRequestForwarderDispatcher<F> {
    /// Mutable dispatch hook for pool forwarders.
    pub fn dispatch_mut(
        &mut self,
        request: &DispatchRequest,
    ) -> Result<McpResponseEnvelope, FrontError> {
        let upstream_id = self.resolve_upstream_id(request);
        let payload = dispatch_pool_jsonrpc_payload(request);
        let fwd = mcp_pool::CallRequest {
            method: request.method.clone(),
            payload,
        };
        let out = self
            .forwarder
            .forward(&upstream_id, &fwd)
            .map_err(|e| FrontError::Dispatch(format!("pool forward failed: {e}")))?;
        Ok(decode_pool_forward_response(&request.id, &out.payload))
    }
}

/// Wrapper to use a mutable pool forwarder behind a shared mutex for `UpstreamDispatcher`.
pub struct SharedPoolForwarderDispatcher<F> {
    pub forwarder: std::sync::Arc<std::sync::Mutex<F>>,
    pub upstream_id: mcp_pool::UpstreamId,
}

impl<F> SharedPoolForwarderDispatcher<F> {
    pub fn new(
        forwarder: std::sync::Arc<std::sync::Mutex<F>>,
        upstream_id: impl Into<String>,
    ) -> Self {
        Self {
            forwarder,
            upstream_id: mcp_pool::UpstreamId(upstream_id.into()),
        }
    }

    fn resolve_upstream_id(&self, request: &DispatchRequest) -> mcp_pool::UpstreamId {
        let target = request.target.upstream_id.trim();
        if target.is_empty() {
            self.upstream_id.clone()
        } else {
            mcp_pool::UpstreamId(target.to_string())
        }
    }
}

impl<F: mcp_pool::RequestForwarder> UpstreamDispatcher for SharedPoolForwarderDispatcher<F> {
    fn dispatch(&self, request: &DispatchRequest) -> Result<McpResponseEnvelope, FrontError> {
        let upstream_id = self.resolve_upstream_id(request);
        let mut g = self
            .forwarder
            .lock()
            .map_err(|_| FrontError::Dispatch("pool forwarder mutex poisoned".into()))?;
        let payload = dispatch_pool_jsonrpc_payload(request);
        let fwd = mcp_pool::CallRequest {
            method: request.method.clone(),
            payload,
        };
        let out = g
            .forward(&upstream_id, &fwd)
            .map_err(|e| FrontError::Dispatch(format!("pool forward failed: {e}")))?;
        Ok(decode_pool_forward_response(&request.id, &out.payload))
    }
}

// ---------------------------------------------------------------------------
// Core enforcement integration (auth/policy/taint/approval) - fail-closed
// ---------------------------------------------------------------------------

/// Maps front hook context into `core::policy` request/context hints for evaluation.
pub fn core_policy_request_from_hook(
    ctx: &HookContext<'_>,
) -> (
    scopegate_core::policy::Principal,
    scopegate_core::policy::Action,
    scopegate_core::policy::Resource,
    scopegate_core::policy::Context,
) {
    let principal = scopegate_core::policy::Principal::new(
        ctx.auth
            .subject
            .clone()
            .unwrap_or_else(|| "anonymous".into()),
    );
    let action = scopegate_core::policy::Action::new(ctx.request.method.clone());
    let resource = scopegate_core::policy::Resource::new(
        ctx.tool_call
            .map(|t| t.name.clone())
            .unwrap_or_else(|| ctx.request.method.clone()),
    );
    let mut pctx = scopegate_core::policy::Context::default();
    if let Some(dec) = ctx.decision {
        pctx = pctx.with_taint(scopegate_core::policy::TaintHint {
            labels: vec![match dec.taint {
                TaintLevel::Clean => "clean".into(),
                TaintLevel::Tainted => "untrusted".into(),
            }],
            sensitive: matches!(dec.taint, TaintLevel::Tainted),
        });
    }
    (principal, action, resource, pctx)
}

/// Policy evaluator backed by `scopegate_core::policy::PolicyEngine` with deny-by-default behavior.
pub struct CorePolicyEvaluator<E> {
    pub engine: E,
}

impl<E: scopegate_core::policy::PolicyEngine> PolicyEvaluator for CorePolicyEvaluator<E> {
    fn evaluate(
        &self,
        req: &McpRequestEnvelope,
        auth: &AuthContext,
        tool_call: Option<&ToolCall>,
    ) -> Result<PolicyDecision, FrontError> {
        let ctx = HookContext {
            request: req,
            auth,
            tool_call,
            decision: None,
        };
        let (principal, action, resource, context) = core_policy_request_from_hook(&ctx);
        let request = scopegate_core::policy::PolicyRequest {
            principal,
            action,
            resource,
            context,
        };
        let eval = self.engine.evaluate(&request);
        match eval.decision {
            scopegate_core::policy::PolicyDecision::Permit => Ok(PolicyDecision::Allow),
            scopegate_core::policy::PolicyDecision::RequireApproval => {
                Ok(PolicyDecision::RequireApproval)
            }
            scopegate_core::policy::PolicyDecision::Forbid => {
                if eval.obligations.iter().any(|o| {
                    matches!(
                        o,
                        scopegate_core::policy::PolicyObligation::RequireApproval { .. }
                    )
                }) {
                    Ok(PolicyDecision::RequireApproval)
                } else {
                    Ok(PolicyDecision::Deny)
                }
            }
        }
    }
}

/// Taint tracker integrating with `core::taint` session model (fail-closed on tainted egress).
#[derive(Debug, Default, Clone)]
pub struct CoreTaintTracker {
    pub session: scopegate_core::taint::SessionTaint,
}

impl TaintTracker for CoreTaintTracker {
    fn assess(
        &self,
        req: &McpRequestEnvelope,
        _auth: &AuthContext,
        _tool_call: Option<&ToolCall>,
    ) -> Result<TaintLevel, FrontError> {
        let _ = scopegate_core::taint::OperationTarget::from_operation(&req.method);
        Ok(if self.session.summary().is_clean() {
            TaintLevel::Clean
        } else {
            TaintLevel::Tainted
        })
    }
}

/// Approval gate integrating policy/taint outcomes with fail-closed behavior.
#[derive(Debug, Default, Clone, Copy)]
pub struct CoreAwareApprovalGate;

impl ApprovalGate for CoreAwareApprovalGate {
    fn decide(
        &self,
        req: &McpRequestEnvelope,
        _auth: &AuthContext,
        _tool_call: Option<&ToolCall>,
        taint: TaintLevel,
        policy: PolicyDecision,
    ) -> Result<ApprovalDecision, FrontError> {
        let target = scopegate_core::taint::OperationTarget::from_operation(&req.method);
        if matches!(policy, PolicyDecision::Deny) {
            return Ok(ApprovalDecision::Denied);
        }
        if matches!(policy, PolicyDecision::RequireApproval) {
            return Ok(ApprovalDecision::Required);
        }
        // fail-closed: tainted external egress requires approval
        if matches!(taint, TaintLevel::Tainted) && target.is_external_egress() {
            return Ok(ApprovalDecision::Required);
        }
        Ok(ApprovalDecision::NotRequired)
    }
}

// ---------------------------------------------------------------------------
// Gateway HTTP endpoint handler integration (gateway types)
// ---------------------------------------------------------------------------

/// Build raw JSON-RPC input and transport metadata from gateway MCP request/context.
///
/// Preserves `req.upstream` as a transport attribute for upstream-selecting routers/dispatch.
/// Injects HTTP authorization into transport headers when provided.
pub fn gateway_bridge_input(
    req: &gateway::mcp::McpRequest,
    ctx: Option<&gateway::mcp::McpHttpContext>,
) -> (String, TransportMetadata) {
    let raw = if !req.payload_json.trim().is_empty() {
        req.payload_json.clone()
    } else if !req.method.trim().is_empty() {
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": format!("gw-{}", req.method),
            "method": req.method,
        })
        .to_string()
    } else {
        String::new()
    };
    let mut transport = TransportMetadata::default();
    if let Some(ctx) = ctx {
        if let Some(auth) = ctx
            .authorization
            .as_ref()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
        {
            transport
                .headers
                .insert("authorization".into(), auth.to_string());
        }
    }
    if let Some(upstream) = req
        .upstream
        .as_ref()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
    {
        transport
            .attributes
            .insert("upstream".into(), upstream.to_string());
    }
    (raw, transport)
}

/// Handle a gateway MCP endpoint request through the front pipeline.
///
/// Integrates with `gateway::mcp::{McpRequest,McpResponse}` types while keeping
/// behavior fail-closed on parse/dispatch/enforcement errors.
pub fn handle_gateway_mcp_request<F>(
    front: &F,
    req: gateway::mcp::McpRequest,
) -> gateway::mcp::McpResponse
where
    F: Fn(&str) -> McpResponseEnvelope,
{
    handle_gateway_mcp_request_with_context(front, req, None)
}

/// Handle a gateway MCP request with HTTP/auth context and upstream hint propagation.
pub fn handle_gateway_mcp_request_with_context<F>(
    front: &F,
    req: gateway::mcp::McpRequest,
    ctx: Option<&gateway::mcp::McpHttpContext>,
) -> gateway::mcp::McpResponse
where
    F: Fn(&str) -> McpResponseEnvelope,
{
    let (raw, _transport) = gateway_bridge_input(&req, ctx);
    // Closure-based bridge cannot receive transport; callers needing transport-aware
    // handling should use `handle_gateway_mcp_with_front_context`.
    let resp = front(&raw);
    let payload_json = serde_json::to_string(&resp.to_json_rpc()).unwrap_or_else(|_| {
        "{\"jsonrpc\":\"2.0\",\"id\":\"unknown\",\"error\":{\"code\":-32603,\"message\":\"serialization failed\"}}"
            .to_string()
    });
    gateway::mcp::McpResponse {
        ok: resp.error.is_none(),
        payload_json,
        fail_closed: resp.error.is_some(),
    }
}

/// Transport-aware gateway bridge using `McpFront` directly.
pub fn handle_gateway_mcp_with_front_context<P, V, E, T, A, Pol, Ta, Ap, R, D>(
    front: &McpFront<P, V, E, T, A, Pol, Ta, Ap, R, D>,
    req: gateway::mcp::McpRequest,
    ctx: Option<&gateway::mcp::McpHttpContext>,
) -> gateway::mcp::McpResponse
where
    P: RequestParser,
    V: RequestValidator,
    E: ToolCallExtractor,
    T: TokenContextProvider,
    A: Authenticator,
    Pol: PolicyEvaluator,
    Ta: TaintTracker,
    Ap: ApprovalGate,
    R: RequestRouter,
    D: UpstreamDispatcher,
{
    let (raw, transport) = gateway_bridge_input(&req, ctx);
    let resp = front.accept_mapped_with_transport(&raw, transport);
    let payload_json = serde_json::to_string(&resp.to_json_rpc()).unwrap_or_else(|_| {
        "{\"jsonrpc\":\"2.0\",\"id\":\"unknown\",\"error\":{\"code\":-32603,\"message\":\"serialization failed\"}}"
            .to_string()
    });
    gateway::mcp::McpResponse {
        ok: resp.error.is_none(),
        payload_json,
        fail_closed: resp.error.is_some(),
    }
}

/// Convenience adapter using `McpFront::accept_mapped`.
pub fn handle_gateway_mcp(
    front: &McpFront,
    req: gateway::mcp::McpRequest,
) -> gateway::mcp::McpResponse {
    handle_gateway_mcp_request(&|raw| front.accept_mapped(raw), req)
}

/// Handle raw JSON-RPC body for HTTP transports; returns serialized JSON-RPC response.
/// Fail-closed on parse/serialization issues.
pub fn handle_http_jsonrpc<P, V, E, T, A, Pol, Ta, Ap, R, D>(
    front: &McpFront<P, V, E, T, A, Pol, Ta, Ap, R, D>,
    body: &str,
) -> String
where
    P: RequestParser,
    V: RequestValidator,
    E: ToolCallExtractor,
    T: TokenContextProvider,
    A: Authenticator,
    Pol: PolicyEvaluator,
    Ta: TaintTracker,
    Ap: ApprovalGate,
    R: RequestRouter,
    D: UpstreamDispatcher,
{
    let resp = front.accept_mapped(body);
    serde_json::to_string(&resp.to_json_rpc())
        .unwrap_or_else(|_| "{\"jsonrpc\":\"2.0\",\"id\":\"unknown\",\"error\":{\"code\":-32603,\"message\":\"internal serialization error\"}}".to_string())
}

// ---------------------------------------------------------------------------
// Runnable stdio server loop (async, tokio)
// ---------------------------------------------------------------------------

/// Process a single line/frame through the front and return serialized JSON-RPC.
/// JSON-RPC notifications (requests without `id`) are processed but produce no response.
pub fn process_line<P, V, E, T, A, Pol, Ta, Ap, R, D>(
    front: &McpFront<P, V, E, T, A, Pol, Ta, Ap, R, D>,
    line: &str,
) -> Option<String>
where
    P: RequestParser,
    V: RequestValidator,
    E: ToolCallExtractor,
    T: TokenContextProvider,
    A: Authenticator,
    Pol: PolicyEvaluator,
    Ta: TaintTracker,
    Ap: ApprovalGate,
    R: RequestRouter,
    D: UpstreamDispatcher,
{
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }
    let resp = front.accept_mapped(trimmed);
    if is_jsonrpc_notification_raw(trimmed) {
        return None;
    }
    serde_json::to_string(&resp.to_json_rpc()).ok()
}

/// Async stdio server loop (line-delimited JSON-RPC). Reads stdin, writes stdout.
/// Returns when input closes or an unrecoverable IO error occurs.
pub async fn serve_stdio_async<P, V, E, T, A, Pol, Ta, Ap, R, D>(
    front: &McpFront<P, V, E, T, A, Pol, Ta, Ap, R, D>,
) -> Result<(), FrontError>
where
    P: RequestParser,
    V: RequestValidator,
    E: ToolCallExtractor,
    T: TokenContextProvider,
    A: Authenticator,
    Pol: PolicyEvaluator,
    Ta: TaintTracker,
    Ap: ApprovalGate,
    R: RequestRouter,
    D: UpstreamDispatcher,
{
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let mut lines = BufReader::new(stdin).lines();
    while let Some(line) = lines
        .next_line()
        .await
        .map_err(|e| FrontError::Parse(format!("stdio read: {e}")))?
    {
        if let Some(out) = process_line(front, &line) {
            stdout
                .write_all(out.as_bytes())
                .await
                .map_err(|e| FrontError::Internal(format!("stdio write: {e}")))?;
            stdout
                .write_all(b"\n")
                .await
                .map_err(|e| FrontError::Internal(format!("stdio write: {e}")))?;
            stdout
                .flush()
                .await
                .map_err(|e| FrontError::Internal(format!("stdio flush: {e}")))?;
        }
    }
    Ok(())
}

/// Run stdio server loop with default front. Intended as binary/runtime entry hook.
pub async fn run_stdio_server() -> Result<(), FrontError> {
    let front = McpFront::default();
    serve_stdio_async(&front).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn parses_tool_call_envelope() {
        let p = SkeletonParser;
        let req = p
            .parse("1|tools/call|echo|text=hi,flag=true")
            .expect("parse");
        assert_eq!(req.method, "tools/call");
        let tc = req.tool_call().expect("tool call");
        assert_eq!(tc.name, "echo");
        assert_eq!(tc.arguments.get("text").map(String::as_str), Some("hi"));
        assert_eq!(tc.arguments.get("flag").map(String::as_str), Some("true"));
    }

    #[test]
    fn parses_non_tool_method_fields() {
        let req = SkeletonParser
            .parse("1|initialize|client=demo,version=1")
            .expect("parse");
        assert!(req.tool_call().is_none());
        assert_eq!(
            req.params.fields.get("client").map(String::as_str),
            Some("demo")
        );
    }

    #[test]
    fn extracts_tool_call() {
        let req = SkeletonParser
            .parse("1|tools/call|echo|x=1")
            .expect("parse");
        let tc = DefaultToolCallExtractor
            .extract(&req)
            .expect("extract")
            .expect("some");
        assert_eq!(tc.name, "echo");
        assert_eq!(tc.arguments.get("x").map(String::as_str), Some("1"));
    }

    #[test]
    fn validates_tools_call_requires_tool() {
        let req = McpRequestEnvelope {
            id: "1".into(),
            method: "tools/call".into(),
            params: RequestParams::default(),
            raw: "1|tools/call".into(),
            transport: TransportMetadata::default(),
        };
        let err = BasicRequestValidator.validate(&req).expect_err("invalid");
        assert!(matches!(err, FrontError::Validation(_)));
        assert_eq!(err.code(), -32602);
    }

    #[test]
    fn routes_and_dispatches_to_upstream() {
        let front = McpFront::default();
        let resp = front.accept("1|tools/call|echo|text=hi").expect("ok");
        let result = resp.result.expect("result");
        assert_eq!(result.content, "routed:default:echo");
        assert!(!result.is_error);
    }

    #[test]
    fn default_front_honors_transport_upstream_hint() {
        let front = McpFront::default();
        let mut transport = TransportMetadata::default();
        transport
            .attributes
            .insert("upstream".into(), "pool-a".into());
        let resp = front
            .accept_with_transport("1|tools/call|echo|text=hi", transport)
            .expect("ok");
        assert_eq!(resp.result.expect("result").content, "routed:pool-a:echo");
    }

    #[test]
    fn rejects_empty_request() {
        let front = McpFront::default();
        let err = front.accept("   ").expect_err("parse");
        assert!(matches!(err, FrontError::Parse(_)));
        assert_eq!(err.code(), -32700);
    }

    #[test]
    fn rejects_tools_call_without_tool_at_validation() {
        let front = McpFront::default();
        let err = front.accept("1|tools/call").expect_err("validation");
        assert!(matches!(err, FrontError::Validation(_)));
    }

    #[test]
    fn token_context_extraction_and_auth_placeholder() {
        let mut req = SkeletonParser.parse("1|ping").expect("parse");
        req.transport
            .headers
            .insert("authorization".into(), "Bearer abc.def".into());
        req.transport
            .headers
            .insert("x-tenant-id".into(), "t1".into());
        req.transport
            .headers
            .insert("x-subject".into(), "user1".into());
        req.transport
            .headers
            .insert("x-scopes".into(), "mcp:call,tools:read".into());

        let token = HeaderTokenContextProvider
            .token_context(&req)
            .expect("token");
        assert!(token.is_present());
        assert_eq!(token.scheme.as_deref(), Some("bearer"));
        assert_eq!(token.tenant_id.as_deref(), Some("t1"));

        let auth = PlaceholderAuthenticator
            .authenticate(&req, &token)
            .expect("auth");
        assert_eq!(auth.subject.as_deref(), Some("user1"));
        assert!(auth.scopes.contains(&"mcp:call".to_string()));
        assert!(auth.scopes.contains(&"tools:read".to_string()));
        assert!(auth.token_present);
    }

    #[test]
    fn require_token_authenticator_rejects_missing_token() {
        let req = SkeletonParser.parse("1|ping").expect("parse");
        let token = HeaderTokenContextProvider
            .token_context(&req)
            .expect("token");
        let err = RequireTokenAuthenticator
            .authenticate(&req, &token)
            .expect_err("auth");
        assert!(matches!(err, FrontError::Auth(_)));
        assert_eq!(err.code(), -32001);
    }

    #[test]
    fn maps_errors_to_jsonrpc_like_codes() {
        let front = McpFront::default();
        let resp = front.accept_mapped("   ");
        let err = resp.error.expect("error");
        assert_eq!(err.code, -32700);
        assert_eq!(resp.id, "unknown");

        let resp = front.accept_mapped("1|tools/call");
        let err = resp.error.expect("error");
        assert_eq!(err.code, -32602);
        assert_eq!(resp.id, "1");
    }

    #[derive(Clone, Copy)]
    struct DenyPolicy;
    impl PolicyEvaluator for DenyPolicy {
        fn evaluate(
            &self,
            _req: &McpRequestEnvelope,
            _auth: &AuthContext,
            _tool_call: Option<&ToolCall>,
        ) -> Result<PolicyDecision, FrontError> {
            Ok(PolicyDecision::Deny)
        }
    }

    #[test]
    fn policy_decision_point_can_deny() {
        let front = McpFront::new(
            SkeletonParser,
            BasicRequestValidator,
            DefaultToolCallExtractor,
            HeaderTokenContextProvider,
            PlaceholderAuthenticator,
            DenyPolicy,
            CleanTaintTracker,
            NoApprovalGate,
            PlaceholderRouter,
            PlaceholderDispatcher,
        );
        let resp = front.accept_mapped("1|tools/call|echo|x=1");
        let err = resp.error.expect("denied");
        assert_eq!(err.code, -32003);
    }

    #[derive(Clone, Copy)]
    struct NeedsApproval;
    impl ApprovalGate for NeedsApproval {
        fn decide(
            &self,
            _req: &McpRequestEnvelope,
            _auth: &AuthContext,
            _tool_call: Option<&ToolCall>,
            taint: TaintLevel,
            _policy: PolicyDecision,
        ) -> Result<ApprovalDecision, FrontError> {
            Ok(if taint == TaintLevel::Tainted {
                ApprovalDecision::Required
            } else {
                ApprovalDecision::NotRequired
            })
        }
    }
    #[derive(Clone, Copy)]
    struct Tainted;
    impl TaintTracker for Tainted {
        fn assess(
            &self,
            _req: &McpRequestEnvelope,
            _auth: &AuthContext,
            _tool_call: Option<&ToolCall>,
        ) -> Result<TaintLevel, FrontError> {
            Ok(TaintLevel::Tainted)
        }
    }

    #[test]
    fn taint_and_approval_decision_points_gate_dispatch() {
        let front = McpFront::new(
            SkeletonParser,
            BasicRequestValidator,
            DefaultToolCallExtractor,
            HeaderTokenContextProvider,
            PlaceholderAuthenticator,
            AllowAllPolicy,
            Tainted,
            NeedsApproval,
            PlaceholderRouter,
            PlaceholderDispatcher,
        );
        let resp = front.accept_mapped("1|tools/call|echo|x=1");
        let err = resp.error.expect("denied");
        assert_eq!(err.code, -32003);
    }

    #[test]
    fn policy_can_require_approval_and_gate_can_approve() {
        #[derive(Clone, Copy)]
        struct RequireApprovalPolicy;
        impl PolicyEvaluator for RequireApprovalPolicy {
            fn evaluate(
                &self,
                _req: &McpRequestEnvelope,
                _auth: &AuthContext,
                _tool_call: Option<&ToolCall>,
            ) -> Result<PolicyDecision, FrontError> {
                Ok(PolicyDecision::RequireApproval)
            }
        }
        #[derive(Clone, Copy)]
        struct ApproveGate;
        impl ApprovalGate for ApproveGate {
            fn decide(
                &self,
                _req: &McpRequestEnvelope,
                _auth: &AuthContext,
                _tool_call: Option<&ToolCall>,
                _taint: TaintLevel,
                _policy: PolicyDecision,
            ) -> Result<ApprovalDecision, FrontError> {
                Ok(ApprovalDecision::Approved)
            }
        }
        let front = McpFront::new(
            SkeletonParser,
            BasicRequestValidator,
            DefaultToolCallExtractor,
            HeaderTokenContextProvider,
            PlaceholderAuthenticator,
            RequireApprovalPolicy,
            CleanTaintTracker,
            ApproveGate,
            PlaceholderRouter,
            PlaceholderDispatcher,
        );
        let resp = front.accept("1|tools/call|echo|x=1").expect("approved");
        assert!(resp.error.is_none());
    }

    #[derive(Clone, Copy)]
    struct CaptureDispatcher;
    impl UpstreamDispatcher for CaptureDispatcher {
        fn dispatch(&self, request: &DispatchRequest) -> Result<McpResponseEnvelope, FrontError> {
            Ok(ResponseShaper::success(
                request.id.clone(),
                format!(
                    "dispatch:{}:{}:{}",
                    request.target.method,
                    request.target.upstream_id,
                    request
                        .tool_call
                        .as_ref()
                        .map(|t| t.name.as_str())
                        .unwrap_or("-")
                ),
            ))
        }
    }

    #[test]
    fn dispatch_interface_receives_request_context() {
        let front = McpFront::new(
            SkeletonParser,
            BasicRequestValidator,
            DefaultToolCallExtractor,
            HeaderTokenContextProvider,
            PlaceholderAuthenticator,
            AllowAllPolicy,
            CleanTaintTracker,
            NoApprovalGate,
            PlaceholderRouter,
            CaptureDispatcher,
        );
        let resp = front.accept("9|tools/call|echo|x=1").expect("ok");
        assert_eq!(
            resp.result.unwrap().content,
            "dispatch:tools/call:default:echo"
        );
    }

    #[test]
    fn response_shaper_shapes_success_and_error() {
        let ok = ResponseShaper::success("1".into(), "hi".into());
        assert_eq!(ok.result.unwrap().content, "hi");
        let err = ResponseShaper::map_error("2".into(), &FrontError::Dispatch("boom".into()));
        assert_eq!(err.error.unwrap().code, -32000);
    }

    #[test]
    fn best_effort_id_fallback_is_unknown() {
        let resp = McpFront::default().accept_mapped("");
        assert_eq!(resp.id, "unknown");
    }

    // --- new tests ---

    #[test]
    fn jsonrpc_parser_handles_tools_call_and_list() {
        let call = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hi"}}}"#;
        let req = JsonRpcParser.parse(call).expect("parse call");
        assert_eq!(req.method, "tools/call");
        assert_eq!(req.id, "1");
        let tc = req.tool_call().expect("tc");
        assert_eq!(tc.name, "echo");
        assert_eq!(tc.arguments.get("text").map(String::as_str), Some("hi"));

        let list = r#"{"jsonrpc":"2.0","id":"a","method":"tools/list"}"#;
        let req = JsonRpcParser.parse(list).expect("parse list");
        assert!(req.is_tools_list());
        assert!(req.tool_call().is_none());
    }

    #[test]
    fn jsonrpc_parser_uses_rmcp_model_for_tools_call_structured_args() {
        let call = r#"{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"sum","arguments":{"a":1,"b":true,"s":"x","obj":{"k":"v"}}}}"#;
        let req = JsonRpcParser.parse(call).expect("parse call");
        let tc = req.tool_call().expect("tc");
        assert_eq!(tc.name, "sum");
        assert_eq!(tc.arguments.get("s").map(String::as_str), Some("x"));
        // flat view stringifies non-string values for hook compatibility
        assert_eq!(tc.arguments.get("a").map(String::as_str), Some("1"));
        assert_eq!(tc.arguments.get("b").map(String::as_str), Some("true"));
        let raw = tc.raw_arguments.as_ref().expect("raw args");
        assert_eq!(raw["a"], serde_json::json!(1));
        assert_eq!(raw["b"], serde_json::json!(true));
        assert_eq!(raw["obj"]["k"], serde_json::json!("v"));
    }

    #[test]
    fn jsonrpc_parser_preserves_flat_params_for_hooks() {
        let raw = r#"{"jsonrpc":"2.0","id":"r1","method":"resources/read","params":{"uri":"file:///tmp/x","tenant":"t1","n":2,"ok":true}}"#;
        let req = JsonRpcParser.parse(raw).expect("parse");
        assert_eq!(req.method, "resources/read");
        assert_eq!(
            req.params.fields.get("uri").map(String::as_str),
            Some("file:///tmp/x")
        );
        assert_eq!(
            req.params.fields.get("tenant").map(String::as_str),
            Some("t1")
        );
        assert_eq!(req.params.fields.get("n").map(String::as_str), Some("2"));
        assert_eq!(
            req.params.fields.get("ok").map(String::as_str),
            Some("true")
        );
        assert!(req.tool_call().is_none());
    }

    #[test]
    fn auto_parser_selects_json_or_skeleton() {
        let req = AutoParser
            .parse(r#"{"jsonrpc":"2.0","id":"x","method":"ping"}"#)
            .expect("json");
        assert_eq!(req.method, "ping");
        let req = AutoParser.parse("1|ping").expect("skeleton");
        assert_eq!(req.method, "ping");
    }

    #[test]
    fn response_to_jsonrpc_stub() {
        let ok = ResponseShaper::success("7".into(), "routed:default:echo".into());
        let j = ok.to_json_rpc();
        assert_eq!(j.id, JsonRpcId::Str("7".into()));
        assert!(j.error.is_none());
        let err = ResponseShaper::map_error("8".into(), &FrontError::MethodNotFound("x".into()));
        assert_eq!(err.to_json_rpc().error.unwrap().code, -32601);
    }

    #[test]
    fn in_memory_tool_registry_lists_and_calls() {
        let mut reg = InMemoryToolRegistry::default();
        reg.register(McpTool {
            name: "echo".into(),
            description: Some("echo tool".into()),
            input_schema: None,
            title: None,
        });
        let req = SkeletonParser.parse("1|tools/list").expect("parse");
        let list = reg.list_tools(&req).expect("list");
        assert_eq!(list.tools.len(), 1);
        let call = ToolCall {
            name: "echo".into(),
            arguments: BTreeMap::new(),
            raw_arguments: None,
        };
        let auth = AuthContext::default();
        let res = reg.call_tool(&req, &auth, &call).expect("call");
        assert_eq!(res.content, "handled:echo");
        let missing = ToolCall {
            name: "nope".into(),
            arguments: BTreeMap::new(),
            raw_arguments: None,
        };
        assert!(matches!(
            reg.call_tool(&req, &auth, &missing),
            Err(FrontError::MethodNotFound(_))
        ));
    }

    #[test]
    fn registry_dispatcher_serves_tools_list() {
        let mut reg = InMemoryToolRegistry::default();
        reg.register(McpTool {
            name: "a".into(),
            description: None,
            input_schema: None,
            title: None,
        });
        let disp = RegistryDispatcher {
            registry: reg,
            fallback: PlaceholderDispatcher,
        };
        let dr = DispatchRequest {
            target: UpstreamTarget {
                upstream_id: "local".into(),
                tool_name: None,
                method: "tools/list".into(),
            },
            id: "1".into(),
            method: "tools/list".into(),
            tool_call: None,
            raw: "1|tools/list".into(),
        };
        let resp = disp.dispatch(&dr).expect("dispatch");
        let v = resp.json_result.clone().expect("json result");
        assert_eq!(v["tools"][0]["name"], "a");
        let j = resp.to_json_rpc();
        assert_eq!(j.id, JsonRpcId::Str("1".into()));
    }

    #[test]
    fn stdio_transport_roundtrip() {
        let input =
            Cursor::new(b"{\"jsonrpc\":\"2.0\",\"id\":\"1\",\"method\":\"ping\"}\n".to_vec());
        let output = Vec::new();
        let mut t = StdioTransport::new(input, output);
        let msg = t.receive().expect("recv").expect("some");
        assert!(msg.contains("ping"));
        t.send("{\"ok\":true}").expect("send");
        assert!(t.writer.ends_with(b"{\"ok\":true}\n"));
    }

    #[test]
    fn http_transport_stub_buffers() {
        let mut t = HttpTransportStub::new("http://localhost/mcp");
        t.push_inbound("1|ping");
        assert_eq!(t.receive().unwrap().as_deref(), Some("1|ping"));
        assert!(t.receive().unwrap().is_none());
        t.send("resp").unwrap();
        assert_eq!(t.outbox, vec!["resp".to_string()]);
        assert_eq!(t.endpoint.as_deref(), Some("http://localhost/mcp"));
    }

    #[test]
    fn serve_transport_loop_emits_jsonrpc() {
        let input = Cursor::new(b"1|ping\n".to_vec());
        let output = Vec::new();
        let mut t = StdioTransport::new(input, output);
        serve_transport(&mut t, |raw| McpFront::default().accept_mapped(raw)).expect("serve");
        let out = String::from_utf8(t.writer).expect("utf8");
        assert!(out.contains("\"jsonrpc\":\"2.0\""));
        assert!(out.contains("\"id\""));
    }

    #[test]
    fn hook_context_and_outcome_defaults_integrate() {
        let req = SkeletonParser.parse("1|ping").expect("parse");
        let token = HeaderTokenContextProvider
            .token_context(&req)
            .expect("token");
        let auth = PlaceholderAuthenticator
            .authenticate(&req, &token)
            .expect("auth");
        let front = McpFront::default();
        let outcome = front.evaluate_decisions(&req, &auth, None).expect("ok");
        assert_eq!(outcome, DecisionOutcome::default());
        let ctx = HookContext {
            request: &req,
            auth: &auth,
            tool_call: None,
            decision: Some(&outcome),
        };
        assert_eq!(ctx.auth.subject.as_deref(), Some("anonymous"));
        NoopDecisionObserver.on_decision(&ctx, &outcome);
    }

    #[test]
    fn jsonrpc_rejects_invalid_version_and_bad_params_fail_closed() {
        let err = JsonRpcParser
            .parse(r#"{"jsonrpc":"1.0","id":1,"method":"ping"}"#)
            .expect_err("bad version");
        assert!(matches!(err, FrontError::Parse(_)));
        let err = JsonRpcParser
            .parse(r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":""}}"#)
            .expect("parse"); // parser extracts; validator enforces
        assert!(BasicRequestValidator.validate(&err).is_err());
    }

    #[test]
    fn registry_dispatcher_handles_initialize_and_ping() {
        let reg = InMemoryToolRegistry::default();
        let disp = RegistryDispatcher {
            registry: reg,
            fallback: PlaceholderDispatcher,
        };
        let init_req = DispatchRequest {
            target: UpstreamTarget { upstream_id: "local".into(), tool_name: None, method: "initialize".into() },
            id: "i".into(),
            method: "initialize".into(),
            tool_call: None,
            raw: r#"{"jsonrpc":"2.0","id":"i","method":"initialize","params":{"protocolVersion":"2024-11-05"}}"#.into(),
        };
        let resp = disp.dispatch(&init_req).expect("init");
        assert_eq!(
            resp.json_result.as_ref().unwrap()["protocolVersion"],
            "2024-11-05"
        );
        let ping_req = DispatchRequest {
            target: UpstreamTarget {
                upstream_id: "local".into(),
                tool_name: None,
                method: "ping".into(),
            },
            id: "p".into(),
            method: "ping".into(),
            tool_call: None,
            raw: r#"{"jsonrpc":"2.0","id":"p","method":"ping"}"#.into(),
        };
        let resp = disp.dispatch(&ping_req).expect("ping");
        assert_eq!(resp.to_json_rpc().result, Some(serde_json::json!({})));
    }

    #[test]
    fn rmcp_stubs_and_fail_closed_seams() {
        let bridge = RmcpServiceBridgeStub::new();
        assert!(bridge.ensure_ready().is_err());
        let adapter = RmcpTransportAdapter::http("https://example/mcp");
        assert_eq!(adapter.kind, "http");
        assert!(adapter.config.auth_required);
        let req = SkeletonParser.parse("1|ping").expect("parse");
        let token = HeaderTokenContextProvider
            .token_context(&req)
            .expect("token");
        let auth = PlaceholderAuthenticator
            .authenticate(&req, &token)
            .expect("auth");
        let ctx = HookContext {
            request: &req,
            auth: &auth,
            tool_call: None,
            decision: None,
        };
        let deny = FailClosedCoreAdapters;
        assert_eq!(deny.evaluate(&ctx).unwrap(), PolicyDecision::Deny);
        assert_eq!(deny.assess(&ctx).unwrap(), TaintLevel::Tainted);
        assert_eq!(
            deny.decide(&ctx, PolicyDecision::Allow, TaintLevel::Clean)
                .unwrap(),
            ApprovalDecision::Denied
        );
    }

    #[tokio::test]
    async fn async_stdio_transport_stub_roundtrip() {
        let mut t = AsyncStdioTransportStub {
            inbox: vec!["1|ping".into()],
            outbox: vec![],
        };
        assert_eq!(t.receive().await.unwrap().as_deref(), Some("1|ping"));
        t.send("ok").await.unwrap();
        assert_eq!(t.outbox, vec!["ok".to_string()]);
    }

    fn jsonrpc_front() -> McpFront<AutoParser> {
        McpFront::new(
            AutoParser,
            BasicRequestValidator,
            DefaultToolCallExtractor,
            HeaderTokenContextProvider,
            PlaceholderAuthenticator,
            AllowAllPolicy,
            CleanTaintTracker,
            NoApprovalGate,
            UpstreamHintRouter,
            PlaceholderDispatcher,
        )
    }

    #[test]
    fn gateway_mcp_handler_integrates_and_fail_closed() {
        let front = jsonrpc_front();
        let req = gateway::mcp::McpRequest {
            method: "ping".into(),
            payload_json: r#"{"jsonrpc":"2.0","id":"g1","method":"ping"}"#.into(),
            upstream: None,
        };
        let resp = handle_gateway_mcp_request(&|raw| front.accept_mapped(raw), req);
        assert!(resp.ok, "{}", resp.payload_json);
        assert!(!resp.fail_closed);
        assert!(resp.payload_json.contains("\"jsonrpc\":\"2.0\""));

        let method_only = gateway::mcp::McpRequest {
            method: "ping".into(),
            payload_json: "".into(),
            upstream: None,
        };
        let resp = handle_gateway_mcp_request(&|raw| front.accept_mapped(raw), method_only);
        assert!(resp.ok, "{}", resp.payload_json);
        assert!(resp.payload_json.contains("\"jsonrpc\":\"2.0\""));

        let bad = gateway::mcp::McpRequest {
            method: "".into(),
            payload_json: "".into(),
            upstream: None,
        };
        let resp = handle_gateway_mcp_request(&|raw| front.accept_mapped(raw), bad);
        assert!(!resp.ok);
        assert!(resp.fail_closed);
    }

    #[test]
    fn http_jsonrpc_handler_returns_serialized_response() {
        let front = jsonrpc_front();
        let out = handle_http_jsonrpc(&front, r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#);
        assert!(out.contains("\"jsonrpc\":\"2.0\""), "{out}");
        assert!(
            out.contains("\"tools\"") || out.contains("\"result\""),
            "{out}"
        );
    }

    #[test]
    fn accept_with_transport_preserves_auth_hook_context() {
        let front = McpFront::new(
            AutoParser,
            BasicRequestValidator,
            DefaultToolCallExtractor,
            HeaderTokenContextProvider,
            RequireTokenAuthenticator,
            AllowAllPolicy,
            CleanTaintTracker,
            NoApprovalGate,
            PlaceholderRouter,
            PlaceholderDispatcher,
        );
        let mut transport = TransportMetadata::default();
        transport
            .headers
            .insert("authorization".into(), "Bearer tok".into());
        let resp = front
            .accept_with_transport(r#"{"jsonrpc":"2.0","id":"t1","method":"ping"}"#, transport)
            .expect("authorized");
        assert!(resp.error.is_none());
    }

    #[test]
    fn shape_upstream_normalizes_empty_success_to_null_result() {
        let shaped = ResponseShaper::shape_upstream(McpResponseEnvelope {
            id: "n".into(),
            result: None,
            json_result: None,
            error: None,
        });
        assert_eq!(shaped.to_json_rpc().result, Some(serde_json::Value::Null));
    }

    #[test]
    fn process_line_skips_empty_and_handles_request() {
        let front = McpFront::default();
        assert!(process_line(&front, "   ").is_none());
        let out =
            process_line(&front, r#"{"jsonrpc":"2.0","id":"x","method":"ping"}"#).expect("out");
        assert!(out.contains("\"jsonrpc\""));
    }

    struct OkForwarder;
    impl mcp_pool::RequestForwarder for OkForwarder {
        fn forward(
            &mut self,
            _upstream: &mcp_pool::UpstreamId,
            request: &mcp_pool::CallRequest,
        ) -> Result<mcp_pool::CallResponse, mcp_pool::PoolError> {
            Ok(mcp_pool::CallResponse {
                payload: format!(
                    "{{\"jsonrpc\":\"2.0\",\"id\":\"1\",\"result\":{{\"echo\":\"{}\"}}}}",
                    request.method
                ),
            })
        }
    }

    #[test]
    fn shared_pool_forwarder_dispatches_to_pool_hook() {
        let fwd = std::sync::Arc::new(std::sync::Mutex::new(OkForwarder));
        let disp = SharedPoolForwarderDispatcher::new(fwd, "up1");
        let req = DispatchRequest {
            target: UpstreamTarget {
                upstream_id: "up1".into(),
                tool_name: Some("echo".into()),
                method: "tools/call".into(),
            },
            id: "1".into(),
            method: "tools/call".into(),
            tool_call: Some(ToolCall {
                name: "echo".into(),
                arguments: BTreeMap::new(),
                raw_arguments: None,
            }),
            raw: r#"{"jsonrpc":"2.0","id":"1","method":"tools/call","params":{"name":"echo"}}"#
                .into(),
        };
        let resp = disp.dispatch(&req).expect("dispatch");
        assert!(resp.error.is_none());
        assert!(resp.json_result.is_some());
    }

    struct CaptureForwarder {
        last_payload: Option<String>,
    }
    impl mcp_pool::RequestForwarder for CaptureForwarder {
        fn forward(
            &mut self,
            _upstream: &mcp_pool::UpstreamId,
            request: &mcp_pool::CallRequest,
        ) -> Result<mcp_pool::CallResponse, mcp_pool::PoolError> {
            self.last_payload = Some(request.payload.clone());
            Ok(mcp_pool::CallResponse {
                payload: r#"{"jsonrpc":"2.0","id":7,"result":{"ok":true}}"#.into(),
            })
        }
    }

    #[test]
    fn shared_pool_forwarder_preserves_raw_jsonrpc_params_and_id() {
        let fwd = std::sync::Arc::new(std::sync::Mutex::new(CaptureForwarder {
            last_payload: None,
        }));
        let disp = SharedPoolForwarderDispatcher::new(fwd.clone(), "up1");
        let req = DispatchRequest {
            target: UpstreamTarget {
                upstream_id: "up1".into(),
                tool_name: None,
                method: "resources/read".into(),
            },
            id: "7".into(),
            method: "resources/read".into(),
            tool_call: None,
            raw: r#"{"jsonrpc":"2.0","id":7,"method":"resources/read","params":{"uri":"x"}}"#
                .into(),
        };
        let resp = disp.dispatch(&req).expect("dispatch");
        assert_eq!(resp.id, "7");
        let g = fwd.lock().unwrap();
        let payload: serde_json::Value =
            serde_json::from_str(g.last_payload.as_ref().expect("payload")).expect("json");
        assert_eq!(payload["method"], "resources/read");
        assert_eq!(payload["params"]["uri"], "x");
        assert_eq!(payload["id"], 7);
    }

    #[test]
    fn core_aware_approval_gate_fail_closed_for_tainted_egress() {
        let gate = CoreAwareApprovalGate;
        let req = McpRequestEnvelope {
            id: "1".into(),
            method: "external_egress".into(),
            params: RequestParams::default(),
            raw: "1|external_egress".into(),
            transport: TransportMetadata::default(),
        };
        let auth = AuthContext::default();
        let d = gate
            .decide(
                &req,
                &auth,
                None,
                TaintLevel::Tainted,
                PolicyDecision::Allow,
            )
            .expect("decide");
        assert_eq!(d, ApprovalDecision::Required);
        let d = gate
            .decide(&req, &auth, None, TaintLevel::Clean, PolicyDecision::Allow)
            .expect("decide");
        assert_eq!(d, ApprovalDecision::NotRequired);
        let d = gate
            .decide(&req, &auth, None, TaintLevel::Clean, PolicyDecision::Deny)
            .expect("decide");
        assert_eq!(d, ApprovalDecision::Denied);
    }

    #[test]
    fn core_taint_tracker_reflects_session_state() {
        let req = SkeletonParser.parse("1|ping").expect("parse");
        let auth = AuthContext::default();
        let clean = CoreTaintTracker::default();
        assert_eq!(clean.assess(&req, &auth, None).unwrap(), TaintLevel::Clean);
        let mut tainted_session = scopegate_core::taint::SessionTaint::default();
        tainted_session.add_label(scopegate_core::taint::TaintLabel::UntrustedContent);
        let tainted = CoreTaintTracker {
            session: tainted_session,
        };
        assert_eq!(
            tainted.assess(&req, &auth, None).unwrap(),
            TaintLevel::Tainted
        );
    }

    #[test]
    fn core_policy_evaluator_deny_by_default_engine() {
        let engine = scopegate_core::policy::StaticPolicyEngine::new(vec![]);
        let eval = CorePolicyEvaluator { engine };
        let req = SkeletonParser
            .parse("1|tools/call|echo|x=1")
            .expect("parse");
        let token = HeaderTokenContextProvider.token_context(&req).expect("t");
        let auth = PlaceholderAuthenticator
            .authenticate(&req, &token)
            .expect("a");
        let d = eval.evaluate(&req, &auth, req.tool_call()).expect("eval");
        assert!(matches!(d, PolicyDecision::Deny));
    }

    #[test]
    fn async_stdio_serve_processes_one_line_path() {
        // serve_stdio_async reads process stdin; exercise process_line path for unit testability.
        let front = jsonrpc_front();
        let out =
            process_line(&front, r#"{"jsonrpc":"2.0","id":"s","method":"ping"}"#).expect("out");
        assert!(
            out.contains("\"id\":\"s\"")
                || out.contains("\"id\": \"s\"")
                || out.contains("\"id\":2"),
            "{out}"
        );
    }

    #[test]
    fn jsonrpc_parse_errors_preserve_request_id_when_mappable() {
        let front = jsonrpc_front();
        let resp = front.accept_mapped(r#"{"jsonrpc":"1.0","id":7,"method":"ping"}"#);
        let err = resp.error.expect("parse error");
        assert_eq!(err.code, -32700);
        assert_eq!(resp.id, "7");

        let resp = front.accept_mapped(r#"{"jsonrpc":"2.0","id":"abc","method":123}"#);
        let err = resp.error.expect("parse error");
        assert_eq!(err.code, -32700);
        assert_eq!(resp.id, "abc");
    }

    #[test]
    fn auto_parser_rejects_json_batch_fail_closed() {
        let err = AutoParser
            .parse(r#"[{"jsonrpc":"2.0","id":1,"method":"ping"}]"#)
            .expect_err("batch rejected");
        assert!(matches!(err, FrontError::Parse(_)));

        let front = jsonrpc_front();
        let resp = front.accept_mapped(r#"[{"jsonrpc":"2.0","id":1,"method":"ping"}]"#);
        let err = resp.error.expect("parse error");
        assert_eq!(err.code, -32700);
        assert_eq!(resp.id, "unknown");
    }

    #[test]
    fn jsonrpc_parser_rejects_malformed_or_unsupported_shapes_fail_closed() {
        let err = JsonRpcParser
            .parse(r#"["not","an","object"]"#)
            .expect_err("array");
        assert!(matches!(err, FrontError::Parse(_)));

        let err = JsonRpcParser
            .parse(r#"{"jsonrpc":"2.0","id":1}"#)
            .expect_err("missing method");
        assert!(matches!(err, FrontError::Parse(_)));

        let err = JsonRpcParser
            .parse(r#"{"jsonrpc":"2.0","id":{"bad":1},"method":"ping"}"#)
            .expect_err("invalid id type");
        assert!(matches!(err, FrontError::Parse(_)));

        let err = JsonRpcParser
            .parse(r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":"nope"}"#)
            .expect_err("invalid params");
        assert!(matches!(err, FrontError::Validation(_)));
    }

    #[test]
    fn require_token_front_rejects_missing_authorization_fail_closed() {
        let front = McpFront::new(
            AutoParser,
            BasicRequestValidator,
            DefaultToolCallExtractor,
            HeaderTokenContextProvider,
            RequireTokenAuthenticator,
            AllowAllPolicy,
            CleanTaintTracker,
            NoApprovalGate,
            PlaceholderRouter,
            PlaceholderDispatcher,
        );
        let resp = front.accept_mapped(r#"{"jsonrpc":"2.0","id":"auth1","method":"ping"}"#);
        let err = resp.error.expect("auth error");
        assert_eq!(err.code, -32001);
        assert_eq!(resp.id, "auth1");
    }

    #[test]
    fn pool_dispatch_payload_preserves_raw_params_for_non_tool_methods() {
        let req = DispatchRequest {
            target: UpstreamTarget {
                upstream_id: "up1".into(),
                tool_name: None,
                method: "resources/read".into(),
            },
            id: "x".into(),
            method: "resources/read".into(),
            tool_call: None,
            raw: r#"{"jsonrpc":"2.0","id":"x","method":"resources/read","params":{"uri":"file://a"}}"#
                .into(),
        };
        let payload = dispatch_pool_jsonrpc_payload(&req);
        let v: serde_json::Value = serde_json::from_str(&payload).expect("json");
        assert_eq!(v["params"]["uri"], "file://a");
        assert_eq!(v["id"], "x");
    }

    #[test]
    fn transport_metadata_header_lookup_is_case_insensitive() {
        let mut t = TransportMetadata::default();
        t.headers.insert("Mcp-Session-Id".into(), "sess-1".into());
        t.headers
            .insert("Authorization".into(), "Bearer tok".into());
        assert_eq!(t.header("mcp-session-id"), Some("sess-1"));
        assert_eq!(t.header("authorization"), Some("Bearer tok"));
    }

    #[test]
    fn token_context_extracts_mcp_session_header() {
        let mut req = SkeletonParser.parse("1|ping").expect("parse");
        req.transport
            .headers
            .insert("Mcp-Session-Id".into(), "s42".into());
        let token = HeaderTokenContextProvider
            .token_context(&req)
            .expect("token");
        assert_eq!(token.session_id.as_deref(), Some("s42"));
    }

    #[test]
    fn process_line_suppresses_jsonrpc_notification_response() {
        let front = jsonrpc_front();
        let out = process_line(
            &front,
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        );
        assert!(out.is_none());
        let out = process_line(&front, r#"{"jsonrpc":"2.0","id":"p","method":"ping"}"#);
        assert!(out.is_some());
    }

    #[test]
    fn pool_dispatch_payload_preserves_notification_without_id() {
        let req = DispatchRequest {
            target: UpstreamTarget {
                upstream_id: "up1".into(),
                tool_name: None,
                method: "notifications/initialized".into(),
            },
            id: "notification".into(),
            method: "notifications/initialized".into(),
            tool_call: None,
            raw: r#"{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}"#.into(),
        };
        let payload = dispatch_pool_jsonrpc_payload(&req);
        let v: serde_json::Value = serde_json::from_str(&payload).expect("json");
        assert!(v.get("id").is_none(), "{payload}");
        assert_eq!(v["method"], "notifications/initialized");
    }

    #[test]
    fn shared_pool_forwarder_uses_routed_target_upstream() {
        #[derive(Default)]
        struct CaptureForwarder {
            seen: Vec<String>,
        }
        impl mcp_pool::RequestForwarder for CaptureForwarder {
            fn forward(
                &mut self,
                upstream: &mcp_pool::UpstreamId,
                request: &mcp_pool::CallRequest,
            ) -> Result<mcp_pool::CallResponse, mcp_pool::PoolError> {
                self.seen.push(upstream.0.clone());
                Ok(mcp_pool::CallResponse {
                    payload: format!(
                        r#"{{"jsonrpc":"2.0","id":"1","result":{{"method":"{}"}}}}"#,
                        request.method
                    ),
                })
            }
        }

        let fwd = std::sync::Arc::new(std::sync::Mutex::new(CaptureForwarder::default()));
        let disp = SharedPoolForwarderDispatcher::new(fwd.clone(), "fallback-upstream");
        let req = DispatchRequest {
            target: UpstreamTarget {
                upstream_id: "routed-upstream".into(),
                tool_name: Some("echo".into()),
                method: "tools/call".into(),
            },
            id: "1".into(),
            method: "tools/call".into(),
            tool_call: Some(ToolCall {
                name: "echo".into(),
                arguments: BTreeMap::new(),
                raw_arguments: Some(serde_json::json!({})),
            }),
            raw: r#"{"jsonrpc":"2.0","id":"1","method":"tools/call","params":{"name":"echo","arguments":{}}}"#.into(),
        };
        let resp = disp.dispatch(&req).expect("dispatch");
        assert!(resp.error.is_none(), "{resp:?}");
        let seen = fwd.lock().unwrap().seen.clone();
        assert_eq!(seen, vec!["routed-upstream".to_string()]);
    }

    #[test]
    fn gateway_bridge_input_propagates_http_auth_and_upstream_hint() {
        let req = gateway::mcp::McpRequest {
            method: "".into(),
            payload_json: r#"{"jsonrpc":"2.0","id":"g","method":"ping"}"#.into(),
            upstream: Some("pool-a".into()),
        };
        let ctx = gateway::mcp::McpHttpContext {
            authorization: Some("Bearer secret".into()),
        };
        let (raw, transport) = gateway_bridge_input(&req, Some(&ctx));
        assert!(raw.contains("\"ping\""));
        assert_eq!(transport.header("authorization"), Some("Bearer secret"));
        assert_eq!(transport.attribute("upstream"), Some("pool-a"));
    }

    #[test]
    fn gateway_front_context_bridge_injects_auth_for_require_token_front() {
        let front = McpFront::new(
            AutoParser,
            BasicRequestValidator,
            DefaultToolCallExtractor,
            HeaderTokenContextProvider,
            RequireTokenAuthenticator,
            AllowAllPolicy,
            CleanTaintTracker,
            NoApprovalGate,
            PlaceholderRouter,
            PlaceholderDispatcher,
        );
        let req = gateway::mcp::McpRequest {
            method: "ping".into(),
            payload_json: r#"{"jsonrpc":"2.0","id":"ga","method":"ping"}"#.into(),
            upstream: None,
        };
        let no_ctx = handle_gateway_mcp_with_front_context(&front, req.clone(), None);
        assert!(!no_ctx.ok);
        let ctx = gateway::mcp::McpHttpContext {
            authorization: Some("Bearer ok".into()),
        };
        let ok = handle_gateway_mcp_with_front_context(&front, req, Some(&ctx));
        assert!(ok.ok, "{}", ok.payload_json);
        assert!(ok.payload_json.contains("\"jsonrpc\":\"2.0\""));
    }

    #[test]
    fn upstream_hint_router_routes_to_selected_upstream() {
        let front = McpFront::new(
            AutoParser,
            BasicRequestValidator,
            DefaultToolCallExtractor,
            HeaderTokenContextProvider,
            PlaceholderAuthenticator,
            AllowAllPolicy,
            CleanTaintTracker,
            NoApprovalGate,
            UpstreamHintRouter,
            PlaceholderDispatcher,
        );
        let req = gateway::mcp::McpRequest {
            method: "".into(),
            payload_json: r#"{"jsonrpc":"2.0","id":"u1","method":"tools/call","params":{"name":"echo","arguments":{}}}"#.into(),
            upstream: Some("upstream-x".into()),
        };
        let resp = handle_gateway_mcp_with_front_context(&front, req, None);
        assert!(resp.ok, "{}", resp.payload_json);
        assert!(
            resp.payload_json.contains("routed:upstream-x:echo"),
            "{}",
            resp.payload_json
        );
    }

    #[test]
    fn accept_mapped_with_transport_applies_auth_context() {
        let front = McpFront::new(
            AutoParser,
            BasicRequestValidator,
            DefaultToolCallExtractor,
            HeaderTokenContextProvider,
            RequireTokenAuthenticator,
            AllowAllPolicy,
            CleanTaintTracker,
            NoApprovalGate,
            PlaceholderRouter,
            PlaceholderDispatcher,
        );
        let mut transport = TransportMetadata::default();
        transport
            .headers
            .insert("authorization".into(), "Bearer mapped".into());
        let resp = front.accept_mapped_with_transport(
            r#"{"jsonrpc":"2.0","id":"m","method":"ping"}"#,
            transport,
        );
        assert!(resp.error.is_none());
        assert_eq!(resp.to_json_rpc().id, JsonRpcId::Str("m".into()));
    }

    #[test]
    fn pool_dispatch_preserves_tools_call_payload_and_upstream_error() {
        #[derive(Default)]
        struct Capture {
            last_payload: Option<String>,
            last_upstream: Option<String>,
        }
        impl mcp_pool::RequestForwarder for Capture {
            fn forward(
                &mut self,
                upstream: &mcp_pool::UpstreamId,
                request: &mcp_pool::CallRequest,
            ) -> Result<mcp_pool::CallResponse, mcp_pool::PoolError> {
                self.last_payload = Some(request.payload.clone());
                self.last_upstream = Some(upstream.0.clone());
                Ok(mcp_pool::CallResponse {
                    payload: r#"{"jsonrpc":"2.0","id":"c1","error":{"code":-32099,"message":"upstream boom","data":{"x":1}}}"#.into(),
                })
            }
        }

        let fwd = std::sync::Arc::new(std::sync::Mutex::new(Capture::default()));
        let disp = SharedPoolForwarderDispatcher::new(fwd.clone(), "fallback");
        let req = DispatchRequest {
            target: UpstreamTarget {
                upstream_id: "pool-z".into(),
                tool_name: Some("sum".into()),
                method: "tools/call".into(),
            },
            id: "c1".into(),
            method: "tools/call".into(),
            tool_call: Some(ToolCall {
                name: "sum".into(),
                arguments: BTreeMap::from([("a".into(), "1".into())]),
                raw_arguments: Some(serde_json::json!({"a": 1, "b": 2})),
            }),
            raw: r#"{"jsonrpc":"2.0","id":"c1","method":"tools/call","params":{"name":"sum","arguments":{"a":1,"b":2}}}"#.into(),
        };
        let resp = disp.dispatch(&req).expect("dispatch");
        assert_eq!(resp.id, "c1");
        let err = resp.error.as_ref().expect("upstream error preserved");
        assert_eq!(err.code, -32099);
        assert_eq!(err.message, "upstream boom");
        assert_eq!(err.data, Some(serde_json::json!({"x":1})));
        let j = resp.to_json_rpc();
        assert_eq!(j.error.as_ref().unwrap().code, -32099);

        let g = fwd.lock().unwrap();
        assert_eq!(g.last_upstream.as_deref(), Some("pool-z"));
        let payload: serde_json::Value =
            serde_json::from_str(g.last_payload.as_deref().unwrap()).expect("json");
        assert_eq!(payload["jsonrpc"], "2.0");
        assert_eq!(payload["id"], "c1");
        assert_eq!(payload["method"], "tools/call");
        assert_eq!(payload["params"]["name"], "sum");
        assert_eq!(payload["params"]["arguments"]["a"], 1);
        assert_eq!(payload["params"]["arguments"]["b"], 2);
    }

    #[test]
    fn pool_dispatch_preserves_initialize_and_tools_list_for_proxy() {
        #[derive(Default)]
        struct Capture {
            payloads: Vec<String>,
        }
        impl mcp_pool::RequestForwarder for Capture {
            fn forward(
                &mut self,
                _upstream: &mcp_pool::UpstreamId,
                request: &mcp_pool::CallRequest,
            ) -> Result<mcp_pool::CallResponse, mcp_pool::PoolError> {
                self.payloads.push(request.payload.clone());
                let v: serde_json::Value = serde_json::from_str(&request.payload).unwrap();
                let id = v.get("id").cloned().unwrap_or(serde_json::Value::Null);
                Ok(mcp_pool::CallResponse {
                    payload: serde_json::json!({"jsonrpc":"2.0","id":id,"result":{"ok":true}})
                        .to_string(),
                })
            }
        }

        let fwd = std::sync::Arc::new(std::sync::Mutex::new(Capture::default()));
        let disp = SharedPoolForwarderDispatcher::new(fwd.clone(), "pool-a");

        let init_req = DispatchRequest {
            target: UpstreamTarget { upstream_id: "pool-a".into(), tool_name: None, method: "initialize".into() },
            id: "init-1".into(),
            method: "initialize".into(),
            tool_call: None,
            raw: r#"{"jsonrpc":"2.0","id":"init-1","method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"c","version":"1"}}}"#.into(),
        };
        let resp = disp.dispatch(&init_req).expect("init");
        assert!(resp.error.is_none(), "{resp:?}");
        assert_eq!(resp.to_json_rpc().id, JsonRpcId::Str("init-1".into()));

        let list_req = DispatchRequest {
            target: UpstreamTarget {
                upstream_id: "pool-a".into(),
                tool_name: None,
                method: "tools/list".into(),
            },
            id: "list-1".into(),
            method: "tools/list".into(),
            tool_call: None,
            raw: r#"{"jsonrpc":"2.0","id":"list-1","method":"tools/list","params":{}}"#.into(),
        };
        let resp = disp.dispatch(&list_req).expect("list");
        assert!(resp.error.is_none(), "{resp:?}");

        let payloads = fwd.lock().unwrap().payloads.clone();
        assert_eq!(payloads.len(), 2);
        let init: serde_json::Value = serde_json::from_str(&payloads[0]).unwrap();
        assert_eq!(init["method"], "initialize");
        assert_eq!(init["params"]["protocolVersion"], "2025-03-26");
        assert_eq!(init["params"]["clientInfo"]["name"], "c");
        let list: serde_json::Value = serde_json::from_str(&payloads[1]).unwrap();
        assert_eq!(list["method"], "tools/list");
        assert_eq!(list["id"], "list-1");
    }

    #[test]
    fn decode_pool_forward_response_normalizes_lenient_and_fails_closed() {
        // Lenient JSON-RPC-ish response without jsonrpc field, null id mapped to request id.
        let resp = decode_pool_forward_response(
            "req-1",
            r#"{"id":null,"error":{"code":-32000,"message":"boom","data":{"k":"v"}}}"#,
        );
        assert_eq!(resp.id, "req-1");
        let err = resp.error.expect("error");
        assert_eq!(err.code, -32000);
        assert_eq!(err.message, "boom");
        assert_eq!(err.data, Some(serde_json::json!({"k":"v"})));

        // Success result preserved.
        let resp = decode_pool_forward_response(
            "req-2",
            r#"{"jsonrpc":"2.0","id":"up","result":{"tools":[]}}"#,
        );
        assert_eq!(resp.id, "up");
        assert_eq!(resp.json_result, Some(serde_json::json!({"tools": []})));

        for (label, payload) in [
            ("empty", "   "),
            ("non-json", "not-json"),
            ("non-object", "[1,2,3]"),
            ("missing result/error", r#"{"jsonrpc":"2.0","id":"x"}"#),
            ("invalid error shape", r#"{"id":"x","error":"boom"}"#),
            (
                "missing error code",
                r#"{"id":"x","error":{"message":"m"}}"#,
            ),
            ("invalid id type", r#"{"id":{"bad":1},"result":{}}"#),
        ] {
            let resp = decode_pool_forward_response("req-x", payload);
            let err = resp
                .error
                .unwrap_or_else(|| panic!("{label}: expected error"));
            assert_eq!(err.code, FrontError::Dispatch("x".into()).code(), "{label}");
            assert!(resp.json_result.is_none(), "{label}");
        }
    }

    #[test]
    fn shared_pool_forwarder_fail_closed_on_malformed_upstream_payload() {
        struct BadForwarder;
        impl mcp_pool::RequestForwarder for BadForwarder {
            fn forward(
                &mut self,
                _upstream: &mcp_pool::UpstreamId,
                _request: &mcp_pool::CallRequest,
            ) -> Result<mcp_pool::CallResponse, mcp_pool::PoolError> {
                Ok(mcp_pool::CallResponse {
                    payload: r#"{"unexpected":"shape"}"#.into(),
                })
            }
        }

        let fwd = std::sync::Arc::new(std::sync::Mutex::new(BadForwarder));
        let disp = SharedPoolForwarderDispatcher::new(fwd, "pool-a");
        let req = DispatchRequest {
            target: UpstreamTarget {
                upstream_id: "pool-a".into(),
                tool_name: None,
                method: "ping".into(),
            },
            id: "p1".into(),
            method: "ping".into(),
            tool_call: None,
            raw: r#"{"jsonrpc":"2.0","id":"p1","method":"ping"}"#.into(),
        };
        let resp = disp.dispatch(&req).expect("mapped dispatch result");
        let err = resp
            .error
            .expect("fail-closed on malformed upstream payload");
        assert_eq!(err.code, -32000);
        assert_eq!(resp.id, "p1");
    }
}
