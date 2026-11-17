/**
 * ScopeGate TypeScript SDK (HTTP client toward current gateway API).
 *
 * Small fetch-based client for implemented/planned surfaces: /healthz, /readyz,
 * /metrics, /v1/tasks, /v1/audit, /v1/approvals, /v1/policies, /mcp (JSON-RPC
 * dispatch). Integration-oriented scaffold, not a hardened production SDK.
 *
 * Factual state (2026-11-17): gateway has axum server wiring and in-memory/store-
 * backed handlers; enforcement/runtime remains partial (no real Biscuit/Cedar/
 * rmcp full runtime, limited auth/secret handling, durability depends on store).
 * Track progress in docs/STATUS.md.
 */

export const VERSION = "0.0.1-dev";

export const ENDPOINTS = {
  health: "/healthz",
  ready: "/readyz",
  metrics: "/metrics",
  tasks: "/v1/tasks",
  audit: "/v1/audit",
  approvals: "/v1/approvals",
  policies: "/v1/policies",
  stream: "/v1/stream",
  mcp: "/mcp",
  // compat aliases
  toolCall: "/mcp",
  auditQuery: "/v1/audit",
  auditVerify: "/v1/audit",
} as const;

export type Decision = "allow" | "deny" | "require_approval" | "throttle" | "error" | string;
export type ApprovalStatus = "pending" | "approved" | "denied" | "timed_out" | string;

export interface ScopeGateClientOptions {
  baseUrl?: string;
  token?: string;
  timeoutMs?: number;
  headers?: Record<string, string>;
  fetchImpl?: typeof fetch;
}

export interface ToolCallRequest {
  tool: string;
  arguments?: Record<string, unknown>;
  taskId?: string;
  traceId?: string;
  approvalId?: string;
  metadata?: Record<string, unknown>;
}

export interface ToolCallResult<T = unknown> {
  ok: boolean;
  output?: T;
  error?: string;
  decision?: Decision;
  approvalId?: string;
  auditId?: string;
  taskId?: string;
  traceId?: string;
  raw?: Record<string, unknown>;
}

export interface ApprovalRequest {
  approvalId: string;
  status: ApprovalStatus;
  tool?: string;
  reason?: string;
  raw?: Record<string, unknown>;
}

export interface AuditQuery {
  taskId?: string;
  decision?: string;
  limit?: number;
  offset?: number;
  verify?: boolean;
  traceId?: string;
  cursor?: string;
}

export interface AuditEvent {
  auditId?: string;
  seq?: number;
  eventType?: string;
  decision?: Decision;
  timestamp?: string;
  raw?: Record<string, unknown>;
}

export class ScopeGateError extends Error {
  status?: number;
  body?: unknown;
  url?: string;
  constructor(message: string, opts: { status?: number; body?: unknown; url?: string } = {}) {
    super(message);
    this.name = "ScopeGateError";
    this.status = opts.status;
    this.body = opts.body;
    this.url = opts.url;
  }
}

export class ScopeGateNotImplementedError extends ScopeGateError {
  constructor(message: string) {
    super(message);
    this.name = "ScopeGateNotImplementedError";
  }
}

export interface ToolsClient {
  call<T = unknown>(
    tool: string,
    args?: Record<string, unknown>,
    options?: Partial<ToolCallRequest>,
  ): Promise<ToolCallResult<T>>;
}

export interface ApprovalsClient {
  get(approvalId: string): Promise<ApprovalRequest>;
  resolve(approvalId: string, decision: "approve" | "deny", reason?: string): Promise<ApprovalRequest>;
}

export interface AuditClient {
  query(query?: AuditQuery): Promise<any>;
  verify(scope?: string): Promise<any>;
}

class HttpToolsClient implements ToolsClient {
  constructor(private readonly client: ScopeGateClient) {}
  async call<T = unknown>(tool: string, args: Record<string, unknown> = {}, _options: Partial<ToolCallRequest> = {}): Promise<ToolCallResult<T>> {
    const resp: any = await this.client.mcp("tools/call", { name: tool, arguments: args }, 1);
    if (resp && typeof resp === "object" && "error" in resp) {
      const e = (resp as any).error;
      const msg = e && typeof e === "object" ? e.message : String(e);
      return { ok: false, error: String(msg), decision: "error", raw: resp };
    }
    return { ok: Boolean((resp as any)?.ok ?? true), output: (resp as any)?.result, raw: resp };
  }
}

class HttpApprovalsClient implements ApprovalsClient {
  constructor(private readonly client: ScopeGateClient) {}
  async get(approvalId: string): Promise<ApprovalRequest> {
    throw new ScopeGateNotImplementedError(
      `Approvals GET by id is not implemented by current gateway API (approvalId=${approvalId}). Use POST /v1/approvals flows as supported.`,
    );
  }
  async resolve(approvalId: string, decision: "approve" | "deny", reason?: string): Promise<ApprovalRequest> {
    const payload: Record<string, unknown> = { id: approvalId, action: decision, decision };
    if (reason) payload.reason = reason;
    const resp: any = await this.client.request("POST", ENDPOINTS.approvals, payload);
    const body = resp && typeof resp === "object" ? resp.body : undefined;
    return { approvalId, status: String(body?.status ?? "resolved"), reason, raw: resp };
  }
}

class HttpAuditClient implements AuditClient {
  constructor(private readonly client: ScopeGateClient) {}
  async query(query: AuditQuery = {}): Promise<any> {
    const params: Record<string, any> = {};
    if (query.taskId) params.task_id = query.taskId;
    if (query.decision) params.decision = query.decision;
    if (query.limit != null) params.limit = String(query.limit);
    if (query.offset != null) params.offset = String(query.offset);
    if (query.verify != null) params.verify = query.verify ? "true" : "false";
    return this.client.request("GET", ENDPOINTS.audit, undefined, params);
  }
  async verify(scope?: string): Promise<any> {
    return this.query({ taskId: scope, verify: true });
  }
}

export class ScopeGateClient {
  readonly baseUrl: string;
  readonly token?: string;
  readonly timeoutMs: number;
  readonly headers: Record<string, string>;
  readonly fetchImpl: typeof fetch;
  readonly tools: ToolsClient;
  readonly approvals: ApprovalsClient;
  readonly audit: AuditClient;

  constructor(options: ScopeGateClientOptions = {}) {
    this.baseUrl = (options.baseUrl ?? "http://localhost:8080").replace(/\/$/, "");
    this.token = options.token;
    this.timeoutMs = options.timeoutMs ?? 30_000;
    this.headers = options.headers ?? {};
    this.fetchImpl = options.fetchImpl ?? (globalThis.fetch as typeof fetch);
    if (!this.fetchImpl) throw new ScopeGateError("No fetch implementation available. Provide options.fetchImpl.");
    this.tools = new HttpToolsClient(this);
    this.approvals = new HttpApprovalsClient(this);
    this.audit = new HttpAuditClient(this);
  }

  endpoint(name: keyof typeof ENDPOINTS, params: Record<string, string | number> = {}): string {
    let path: string = ENDPOINTS[name];
    for (const [k, v] of Object.entries(params)) {
      path = path.replace(`{${k}}`, encodeURIComponent(String(v)));
    }
    return path;
  }

  async request(method: string, path: string, body?: unknown, params?: Record<string, string | undefined>): Promise<any> {
    let url = path.startsWith("http") ? path : `${this.baseUrl}${path.startsWith("/") ? "" : "/"}${path}`;
    if (params) {
      const q = new URLSearchParams();
      for (const [k, v] of Object.entries(params)) if (v != null) q.set(k, v);
      const qs = q.toString();
      if (qs) url += (url.includes("?") ? "&" : "?") + qs;
    }
    const headers: Record<string, string> = { Accept: "application/json, text/plain;q=0.9, */*;q=0.8", ...this.headers };
    if (this.token) headers.Authorization = `Bearer ${this.token}`;
    let payload: string | undefined;
    if (body !== undefined) {
      payload = JSON.stringify(body);
      headers["Content-Type"] = headers["Content-Type"] ?? "application/json";
    }
    const ctrl = typeof AbortController !== "undefined" ? new AbortController() : undefined;
    const timer = ctrl ? setTimeout(() => ctrl.abort(), this.timeoutMs) : undefined;
    try {
      const resp = await this.fetchImpl(url, { method, headers, body: payload, signal: ctrl?.signal as any });
      const ctype = resp.headers.get("content-type") || "";
      const text = await resp.text();
      const isJson = ctype.includes("json");
      const data = isJson ? (text ? JSON.parse(text) : null) : text;
      if (!resp.ok) throw new ScopeGateError(`HTTP ${resp.status} ${resp.statusText}`, { status: resp.status, body: data, url });
      return data;
    } catch (e: any) {
      if (e instanceof ScopeGateError) throw e;
      throw new ScopeGateError(`Request failed: ${e?.message || String(e)}`, { url });
    } finally {
      if (timer) clearTimeout(timer);
    }
  }

  async health(): Promise<any> { return this.request("GET", ENDPOINTS.health); }
  async ready(): Promise<any> { return this.request("GET", ENDPOINTS.ready); }
  async metrics(): Promise<any> { return this.request("GET", ENDPOINTS.metrics); }
  async createTask(payload: Record<string, unknown>): Promise<any> { return this.request("POST", ENDPOINTS.tasks, payload); }
  async listTasks(): Promise<any> { return this.request("GET", ENDPOINTS.tasks); }
  async mcp(method: string, params?: Record<string, unknown>, id: any = 1): Promise<any> {
    const payload: any = { jsonrpc: "2.0", id, method };
    if (params !== undefined) payload.params = params;
    return this.request("POST", ENDPOINTS.mcp, payload);
  }
  async createApproval(payload: Record<string, unknown>): Promise<any> { return this.request("POST", ENDPOINTS.approvals, payload); }
  async listPolicies(): Promise<any> { return this.request("GET", ENDPOINTS.policies); }
  async upsertPolicy(payload: Record<string, unknown>): Promise<any> { return this.request("POST", ENDPOINTS.policies, payload); }
  async close(): Promise<void> {}
}

export default ScopeGateClient;

