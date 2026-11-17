"""ScopeGate Python SDK (HTTP client toward current gateway API).

Provides a small stdlib HTTP client for implemented/planned gateway surfaces:
`/healthz`, `/readyz`, `/metrics`, `/v1/tasks`, `/v1/audit`, `/v1/approvals`,
`/v1/policies`, and `/mcp` (JSON-RPC dispatch). This is an integration-oriented
scaffold, not a hardened/complete production SDK.

Factual state (2026-11-17): gateway has axum server wiring and in-memory/store-
backed handlers; enforcement/runtime remains partial (no real Biscuit/Cedar/`rmcp`
full runtime, limited auth/secret handling, durability semantics depend on store
wiring). Treat responses as best-effort and verify behavior against current code.
Track progress in docs/STATUS.md.
"""

from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, Optional, Protocol, runtime_checkable

__all__ = [
    "ScopeGateError",
    "ScopeGateHTTPError",
    "ScopeGateNotImplementedError",
    "ClientOptions",
    "ToolCallRequest",
    "ToolCallResult",
    "ApprovalRequest",
    "ApprovalResolution",
    "AuditQuery",
    "AuditEvent",
    "ToolsAPI",
    "ApprovalsAPI",
    "AuditAPI",
    "ENDPOINTS",
    "ScopeGateClient",
]
__version__ = "0.0.1-dev"

# Endpoint paths aligned to current gateway routes where available.
ENDPOINTS = {
    "health": "/healthz",
    "ready": "/readyz",
    "metrics": "/metrics",
    "tasks": "/v1/tasks",
    "audit": "/v1/audit",
    "approvals": "/v1/approvals",
    "policies": "/v1/policies",
    "stream": "/v1/stream",
    "mcp": "/mcp",
    # Planned/compat aliases
    "tool_call": "/mcp",
    "audit_query": "/v1/audit",
    "audit_verify": "/v1/audit",
}


class ScopeGateError(Exception):
    """Base SDK error."""


class ScopeGateNotImplementedError(ScopeGateError, NotImplementedError):
    """Raised for API surfaces not available in the current runtime."""


class ScopeGateHTTPError(ScopeGateError):
    """HTTP/API error wrapper preserving status and body when available."""

    def __init__(self, status: int, message: str, body: Any = None, url: str = "") -> None:
        super().__init__(f"HTTP {status} {message} ({url})".strip())
        self.status = status
        self.body = body
        self.url = url


@dataclass
class ClientOptions:
    base_url: str = "http://localhost:8080"
    token: Optional[str] = None
    timeout_s: float = 30.0
    verify_tls: bool = True
    headers: Dict[str, str] = field(default_factory=dict)


@dataclass
class ToolCallRequest:
    tool: str
    arguments: Dict[str, Any] = field(default_factory=dict)
    task_id: Optional[str] = None
    trace_id: Optional[str] = None
    approval_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ToolCallResult:
    ok: bool
    output: Any = None
    error: Optional[str] = None
    decision: Optional[str] = None
    approval_id: Optional[str] = None
    audit_id: Optional[str] = None
    task_id: Optional[str] = None
    trace_id: Optional[str] = None
    raw: Optional[Mapping[str, Any]] = None


@dataclass
class ApprovalRequest:
    approval_id: str
    status: str = "pending"
    tool: Optional[str] = None
    reason: Optional[str] = None
    raw: Optional[Mapping[str, Any]] = None


@dataclass
class ApprovalResolution:
    approval_id: str
    decision: str
    reason: Optional[str] = None


@dataclass
class AuditQuery:
    task_id: Optional[str] = None
    decision: Optional[str] = None
    limit: Optional[int] = None
    offset: Optional[int] = None
    verify: Optional[bool] = None
    trace_id: Optional[str] = None  # accepted for forward-compat; may be ignored by API
    cursor: Optional[str] = None


@dataclass
class AuditEvent:
    audit_id: Optional[str] = None
    seq: Optional[int] = None
    event_type: Optional[str] = None
    decision: Optional[str] = None
    timestamp: Optional[str] = None
    raw: Optional[Mapping[str, Any]] = None


@runtime_checkable
class ToolsAPI(Protocol):
    def call(self, tool: str, arguments: Optional[Dict[str, Any]] = None, **kwargs: Any) -> ToolCallResult: ...


@runtime_checkable
class ApprovalsAPI(Protocol):
    def get(self, approval_id: str) -> ApprovalRequest: ...
    def resolve(self, approval_id: str, decision: str, reason: Optional[str] = None) -> ApprovalRequest: ...


@runtime_checkable
class AuditAPI(Protocol):
    def query(self, query: Optional[AuditQuery] = None, **kwargs: Any) -> Any: ...
    def verify(self, scope: Optional[str] = None) -> Any: ...


@dataclass
class ScopeGateClient:
    """Small HTTP client for current ScopeGate gateway/admin/MCP surfaces."""

    base_url: str = "http://localhost:8080"
    token: Optional[str] = None
    timeout_s: float = 30.0
    verify_tls: bool = True
    headers: Dict[str, str] = field(default_factory=dict)
    options: ClientOptions = field(init=False)
    tools: ToolsAPI = field(init=False)
    approvals: ApprovalsAPI = field(init=False)
    audit: AuditAPI = field(init=False)

    def __post_init__(self) -> None:
        self.base_url = self.base_url.rstrip("/")
        self.options = ClientOptions(
            base_url=self.base_url,
            token=self.token,
            timeout_s=self.timeout_s,
            verify_tls=self.verify_tls,
            headers=dict(self.headers),
        )
        self.tools = _HttpTools(self)
        self.approvals = _HttpApprovals(self)
        self.audit = _HttpAudit(self)

    def endpoint(self, name: str, **params: Any) -> str:
        path = ENDPOINTS.get(name)
        if not path:
            raise ScopeGateError(f"Unknown endpoint: {name}")
        try:
            return path.format(**params)
        except KeyError as e:
            raise ScopeGateError(f"Missing endpoint parameter: {e.args[0]}") from e

    def _url(self, path: str) -> str:
        if path.startswith("http://") or path.startswith("https://"):
            return path
        if not path.startswith("/"):
            path = "/" + path
        return self.base_url + path

    def request(
        self,
        method: str,
        path: str,
        *,
        json_body: Any = None,
        params: Optional[Mapping[str, Any]] = None,
        headers: Optional[Mapping[str, str]] = None,
        expect_json: bool = True,
    ) -> Any:
        url = self._url(path)
        if params:
            q = {k: v for k, v in params.items() if v is not None}
            if q:
                url += ("&" if "?" in url else "?") + urllib.parse.urlencode(q)
        data = None
        req_headers: Dict[str, str] = {"Accept": "application/json, text/plain;q=0.9, */*;q=0.8"}
        if self.token:
            req_headers["Authorization"] = f"Bearer {self.token}"
        req_headers.update(self.options.headers)
        if headers:
            req_headers.update(dict(headers))
        if json_body is not None:
            data = json.dumps(json_body).encode("utf-8")
            req_headers.setdefault("Content-Type", "application/json")
        req = urllib.request.Request(url, data=data, headers=req_headers, method=method.upper())
        context = None
        if url.startswith("https://") and not self.verify_tls:
            context = ssl._create_unverified_context()
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_s, context=context) as resp:
                raw = resp.read()
                ctype = resp.headers.get("Content-Type", "")
                if not expect_json or "text/plain" in ctype or "text/" in ctype and "json" not in ctype:
                    try:
                        return raw.decode("utf-8")
                    except Exception:
                        return raw
                if not raw:
                    return None
                try:
                    return json.loads(raw.decode("utf-8"))
                except Exception:
                    return raw.decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            raw = e.read()
            body: Any
            try:
                body = json.loads(raw.decode("utf-8")) if raw else None
            except Exception:
                body = raw.decode("utf-8", errors="replace") if raw else None
            raise ScopeGateHTTPError(e.code, e.reason, body=body, url=url) from None
        except urllib.error.URLError as e:
            raise ScopeGateError(f"Request failed for {url}: {e}") from e

    # Ops / convenience
    def health(self) -> Any:
        return self.request("GET", self.endpoint("health"))

    def ready(self) -> Any:
        return self.request("GET", self.endpoint("ready"))

    def metrics(self) -> Any:
        return self.request("GET", self.endpoint("metrics"), expect_json=False)

    # Tasks
    def create_task(self, payload: Mapping[str, Any]) -> Any:
        return self.request("POST", self.endpoint("tasks"), json_body=dict(payload))

    def list_tasks(self) -> Any:
        return self.request("GET", self.endpoint("tasks"))

    # MCP (JSON-RPC dispatch; limited methods supported by current gateway)
    def mcp(self, method: str, params: Optional[Mapping[str, Any]] = None, req_id: Any = 1) -> Any:
        payload = {"jsonrpc": "2.0", "id": req_id, "method": method}
        if params is not None:
            payload["params"] = dict(params)
        return self.request("POST", self.endpoint("mcp"), json_body=payload)

    # Approvals
    def create_approval(self, payload: Mapping[str, Any]) -> Any:
        return self.request("POST", self.endpoint("approvals"), json_body=dict(payload))

    # Policies
    def list_policies(self) -> Any:
        return self.request("GET", self.endpoint("policies"))

    def upsert_policy(self, payload: Mapping[str, Any]) -> Any:
        return self.request("POST", self.endpoint("policies"), json_body=dict(payload))

    def close(self) -> None:
        return None


class _HttpTools(ToolsAPI):
    def __init__(self, client: ScopeGateClient) -> None:
        self._client = client

    def call(self, tool: str, arguments: Optional[Dict[str, Any]] = None, **kwargs: Any) -> ToolCallResult:
        # Current gateway MCP dispatch supports limited methods/tools (e.g. initialize/tools.list/gateway.health).
        # We attempt tools/call and normalize the envelope; unsupported tools may return fail-closed MCP errors.
        req_id = kwargs.get("id", 1)
        resp = self._client.mcp("tools/call", {"name": tool, "arguments": arguments or {}}, req_id=req_id)
        raw = resp if isinstance(resp, Mapping) else {"value": resp}
        if isinstance(raw, Mapping) and "error" in raw:
            err = raw.get("error")
            msg = err.get("message") if isinstance(err, Mapping) else str(err)
            return ToolCallResult(ok=False, error=msg, decision="error", output=None, raw=dict(raw))
        result = raw.get("result") if isinstance(raw, Mapping) else None
        ok = bool(raw.get("ok", True)) if isinstance(raw, Mapping) else True
        return ToolCallResult(ok=ok, output=result, error=None, raw=dict(raw) if isinstance(raw, Mapping) else None)


class _HttpApprovals(ApprovalsAPI):
    def __init__(self, client: ScopeGateClient) -> None:
        self._client = client

    def get(self, approval_id: str) -> ApprovalRequest:
        raise ScopeGateNotImplementedError(
            f"Approvals GET by id is not implemented by current gateway API (approval_id={approval_id!r}). "
            "Use create/resolve via approvals endpoint payloads as supported."
        )

    def resolve(self, approval_id: str, decision: str, reason: Optional[str] = None) -> ApprovalRequest:
        payload: Dict[str, Any] = {"id": approval_id, "action": decision, "decision": decision}
        if reason:
            payload["reason"] = reason
        resp = self._client.request("POST", self._client.endpoint("approvals"), json_body=payload)
        raw = resp if isinstance(resp, Mapping) else {"value": resp}
        body = raw.get("body") if isinstance(raw, Mapping) else None
        status = "resolved"
        if isinstance(body, Mapping) and body.get("status"):
            status = str(body.get("status"))
        return ApprovalRequest(approval_id=approval_id, status=status, reason=reason, raw=dict(raw) if isinstance(raw, Mapping) else None)


class _HttpAudit(AuditAPI):
    def __init__(self, client: ScopeGateClient) -> None:
        self._client = client

    def query(self, query: Optional[AuditQuery] = None, **kwargs: Any) -> Any:
        q = query or AuditQuery(**kwargs)
        params = {
            "task_id": q.task_id,
            "decision": q.decision,
            "limit": q.limit,
            "offset": q.offset,
            "verify": "true" if q.verify else ("false" if q.verify is False else None),
        }
        return self._client.request("GET", self._client.endpoint("audit"), params=params)

    def verify(self, scope: Optional[str] = None) -> Any:
        params = {"verify": "true"}
        if scope:
            params["task_id"] = scope
        return self.query(AuditQuery(task_id=scope, verify=True))
