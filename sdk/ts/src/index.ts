/**
 * ScopeGate TypeScript SDK (HTTP client toward current gateway API).
 *
 * Small fetch-based client for implemented surfaces: /healthz, /readyz, /metrics,
 * /v1/tasks (list/create/get/revoke), /v1/audit, /v1/audit/verify, /v1/approvals
 * (list/get/create/resolve where available), /v1/policies, /v1/stream, and /mcp
 * (JSON-RPC dispatch). Integration-oriented scaffold, not hardened/complete.
 *
 * Factual state: gateway runtime/enforcement remains partial (no real Biscuit/Cedar/
 * full rmcp runtime, limited auth/secret handling, durability semantics depend on
 * store wiring and are not production-proven). Track progress in docs/STATUS.md.
 */

export const VERSION = "0.0.1-dev";

export const ENDPOINTS = {
  health: "/healthz",
  ready: "/readyz",
  metrics: "/metrics",
  tasks: "/v1/tasks",
  task: "/v1/tasks/{id}",
  taskRevoke: "/v1/tasks/{id}/revoke",
  audit: "/v1/audit",
  auditVerify: "/v1/audit/verify",
  approvals: "/v1/approvals",
  policies: "/v1/policies",
  stream: "/v1/stream",
  mcp: "/mcp",
  // compat aliases
  toolCall: "/mcp",
  auditQuery: "/v1/audit",
} as const;

export type Decision = "allow" | "deny" | "require_approval" | "throttle" | "error" | string;
export type ApprovalStatus = "pending" | "approved" | "denied" | "expired" | "timed_out" | string;

export interface ApiEnvelope<T = unknown> {
  status?: string;
  body?: T;
  fail_closed?: boolean;
  error?: string | null;
}

export interface TaskRecord {
  id: string;
  parent_id?: string | null;
  token_id?: string;
  scopes?: string[] | string;
  budget?: number;
  expires_at?: string;
  revoked?: boolean;
  revocation_reason?: string | null;
  taint_snapshot_id?: string | null;
  [k: string]: unknown;
}

export interface TaskRecordView {
  id: string;
  state?: string;
  stage?: string | null;
  allowed?: boolean | null;
  error?: string | null;
  audit_verified?: boolean | null;
  [k: string]: unknown;
}

export interface ApprovalRecord {
  id: string;
  task_id?: string;
  tool?: string;
  args_hash?: string;
  status: ApprovalStatus;
  created_at?: string;
  resolved_at?: string | null;
  resolver?: string | null;
  [k: string]: unknown;
}

export interface AuditVerificationReport {
  ok: boolean;
  checked_events: number;
  first_bad_seq?: number | null;
  message?: string | null;
  expected_hash_hex?: string | null;
  actual_hash_hex?: string | null;
  [k: string]: unknown;
}

export interface PolicyView {
  id: string;
  active: boolean;
  version?: number;
  created_at?: string;
  body?: unknown;
  [k: string]: unknown;
}

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
  taskId?: string;
  tool?: string;
  argsHash?: string;
  createdAt?: string;
  resolvedAt?: string | null;
  resolver?: string | null;
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
  seq?: number;
  ts?: string;
  task_id?: string | null;
  tool?: string | null;
  decision?: Decision;
  reason?: string | null;
  args_digest?: string | null;
  result_digest?: string | null;
  prev_hash?: string | number[] | null;
  hash?: string | number[] | null;
  raw?: Record<string, unknown>;
}

export interface AuditQueryResponse {
  events: AuditEvent[];
  chain_verified: boolean;
  verification?: AuditVerificationReport | unknown;
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
  list(params?: { task_id?: string; status?: string; limit?: number }): Promise<ApprovalRecord[] | { approvals: ApprovalRecord[] }>;
  get(approvalId: string): Promise<ApprovalRequest>;
  create(payload: Record<string, unknown>): Promise<any>;
  resolve(approvalId: string, decision: "approve" | "deny" | "timeout", reason?: string): Promise<ApprovalRequest>;
}

export interface AuditClient {
  query(query?: AuditQuery): Promise<AuditQueryResponse | any>;
  verify(scope?: string): Promise<AuditVerificationReport | any>;
}

class HttpToolsClient implements ToolsClient {
  constructor(private readonly client: ScopeGateClient) {}
  async call<T = unknown>(tool: string, args: Record<string, unknown> = {}, options: Partial<ToolCallRequest> = {}): Promise<ToolCallResult<T>> {
    const params: Record<string, unknown> = { name: tool, arguments: args };
    if (options.taskId) params.task_id = options.taskId;
    if (options.traceId) params.trace_id = options.traceId;
    if (options.approvalId) params.approval_id = options.approvalId;
    if (options.metadata) params.metadata = options.metadata;
    const resp: any = await this.client.mcp("tools/call", params, 1);
    if (resp && typeof resp === "object") {
      // MCP HTTP wrapper {ok,payload_json,fail_closed}
      if (typeof resp.payload_json === "string") {
        try {
          const inner = JSON.parse(resp.payload_json);
          if (inner?.error) return { ok: false, error: String(inner.error.message ?? inner.error), decision: "error", raw: resp };
          return { ok: resp.ok !== false, output: inner?.result ?? inner, raw: resp };
        } catch { /* fall through */ }
      }
      if (resp.error) {
        const e = resp.error;
        return { ok: false, error: String(e?.message ?? e), decision: "error", raw: resp };
      }
      if ("result" in resp) return { ok: true, output: resp.result as T, raw: resp };
    }
    return { ok: Boolean(resp?.ok ?? true), output: (resp as any)?.result, raw: resp };
  }
}

class HttpApprovalsClient implements ApprovalsClient {
  constructor(private readonly client: ScopeGateClient) {}
  async list(params: { task_id?: string; status?: string; limit?: number } = {}): Promise<ApprovalRecord[] | { approvals: ApprovalRecord[] }> {
    const q: Record<string, string | undefined> = {}
    if (params.task_id) q.task_id = params.task_id
    if (params.status) q.status = params.status
    if (params.limit != null) q.limit = String(params.limit)
    return this.client.request("GET", ENDPOINTS.approvals, undefined, Object.keys(q).length ? q : undefined);
  }
  async get(approvalId: string): Promise<ApprovalRequest> {
    const body: any = await this.client.request("GET", `${ENDPOINTS.approvals}/${encodeURIComponent(approvalId)}`);
    const r = body && typeof body === "object" ? body : {};
    return {
      approvalId: String(r.id ?? approvalId),
      status: String(r.status ?? "unknown"),
      taskId: r.task_id,
      tool: r.tool,
      argsHash: r.args_hash,
      createdAt: r.created_at,
      resolvedAt: r.resolved_at ?? null,
      resolver: r.resolver ?? null,
      raw: r,
    };
  }
  async create(payload: Record<string, unknown>): Promise<any> {
    return this.client.request("POST", ENDPOINTS.approvals, { action: "create", ...payload });
  }
  async resolve(approvalId: string, decision: "approve" | "deny" | "timeout", reason?: string): Promise<ApprovalRequest> {
    const payload: Record<string, unknown> = { id: approvalId, action: decision, decision };
    if (reason) payload.reason = reason;
    let resp: any;
    try {
      const pathBody: Record<string, unknown> = { action: decision, decision };
      if (reason) pathBody.reason = reason;
      resp = await this.client.request("POST", `${ENDPOINTS.approvals}/${encodeURIComponent(approvalId)}/resolve`, pathBody);
    } catch (e) {
      if (e instanceof ScopeGateError && (e.status === 404 || e.status === 405 || e.status === 501)) {
        resp = await this.client.request("POST", ENDPOINTS.approvals, payload);
      } else {
        throw e;
      }
    }
    const b = resp && typeof resp === "object" ? resp : {};
    return { approvalId: String(b.id ?? approvalId), status: String(b.status ?? "resolved"), taskId: b.task_id, reason, raw: b };
  }
}

class HttpAuditClient implements AuditClient {
  constructor(private readonly client: ScopeGateClient) {}
  async query(query: AuditQuery = {}): Promise<AuditQueryResponse | any> {
    const body: Record<string, any> = {};
    if (query.taskId != null) body.task_id = query.taskId;
    if (query.decision != null) body.decision = query.decision;
    if (query.limit != null) body.limit = query.limit;
    if (query.offset != null) body.offset = query.offset;
    if (query.verify != null) body.verify = query.verify;
    return this.client.request("POST", ENDPOINTS.audit, body);
  }
  async verify(scope?: string): Promise<AuditVerificationReport | any> {
    void scope;
    try {
      return await this.client.request("GET", ENDPOINTS.auditVerify);
    } catch (e) {
      // fail-closed 503 may still carry a verification report in envelope body
      if (e instanceof ScopeGateError && e.body && typeof e.body === "object") {
        const raw: any = e.body;
        const rep = raw?.body && typeof raw.body === "object" && "ok" in raw.body ? raw.body : ("ok" in raw ? raw : null);
        if (rep) return rep as AuditVerificationReport;
      }
      throw e;
    }
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

  private unwrap(data: any): any {
    if (!data || typeof data !== "object" || Array.isArray(data)) return data;
    const isMcp = "payload_json" in data && "ok" in data;
    const isEnvelope = !isMcp && ("status" in data) && ("body" in data || "fail_closed" in data || "error" in data);
    if (!isEnvelope) return data;
    // For success envelopes, prefer body. For fail_closed/error envelopes callers usually get thrown,
    // but if returned, expose body when present.
    return Object.prototype.hasOwnProperty.call(data, "body") ? data.body : data;
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

    const attempt = async (): Promise<any> => {
      const ctrl = typeof AbortController !== "undefined" ? new AbortController() : undefined;
      const timer = ctrl ? setTimeout(() => ctrl.abort(), this.timeoutMs) : undefined;
      try {
        const resp = await this.fetchImpl(url, { method, headers, body: payload, signal: ctrl?.signal as any });
        const ctype = resp.headers.get("content-type") || "";
        const text = await resp.text();
        let data: any = text;
        if (text) {
          if (ctype.includes("json")) {
            try { data = JSON.parse(text); } catch { data = text; }
          }
        } else {
          data = ctype.includes("json") ? null : text;
        }
        if (!resp.ok) throw new ScopeGateError(`HTTP ${resp.status} ${resp.statusText}`, { status: resp.status, body: data, url });
        return this.unwrap(data);
      } finally {
        if (timer) clearTimeout(timer);
      }
    };

    const shouldRetry = (e: any) => {
      if (e instanceof ScopeGateError) return e.status === 502 || e.status === 503 || e.status === 504;
      return true; // network/fetch errors
    };

    try {
      return await attempt();
    } catch (e: any) {
      if (e instanceof ScopeGateError && !shouldRetry(e)) throw e;
      if (!(e instanceof ScopeGateError) && e?.name === "AbortError") {
        // timeout: do not auto-retry by default except once below? treat as retryable once
      }
      if (shouldRetry(e) || (!(e instanceof ScopeGateError) && e)) {
        await new Promise(r => setTimeout(r, 150));
        try {
          return await attempt();
        } catch (e2: any) {
          if (e2 instanceof ScopeGateError) throw e2;
          throw new ScopeGateError(`Request failed: ${e2?.message || String(e2)}`, { url });
        }
      }
      throw new ScopeGateError(`Request failed: ${e?.message || String(e)}`, { url });
    }
  }

  async health(): Promise<any> { return this.request("GET", ENDPOINTS.health); }
  async ready(): Promise<any> { return this.request("GET", ENDPOINTS.ready); }
  async metrics(): Promise<string> { return this.request("GET", ENDPOINTS.metrics); }
  async createTask(payload: Record<string, unknown>): Promise<TaskRecordView | any> { return this.request("POST", ENDPOINTS.tasks, payload); }
  async listTasks(): Promise<TaskRecord[] | { tasks: TaskRecord[] } | any> { return this.request("GET", ENDPOINTS.tasks); }
  async getTask(taskId: string): Promise<TaskRecord | any> { return this.request("GET", this.endpoint("task", { id: taskId })); }
  async revokeTask(taskId: string, payload?: Record<string, unknown>): Promise<TaskRecord | any> { return this.request("POST", this.endpoint("taskRevoke", { id: taskId }), payload); }
  async mcp(method: string, params?: Record<string, unknown>, id: any = 1, upstream?: string): Promise<any> {
    const rpc: any = { jsonrpc: "2.0", id, method };
    if (params !== undefined) rpc.params = params;
    const payload: any = { payload_json: JSON.stringify(rpc) };
    if (upstream) payload.upstream = upstream;
    return this.request("POST", ENDPOINTS.mcp, payload);
  }
  async createApproval(payload: Record<string, unknown>): Promise<any> { return this.approvals.create(payload); }
  async listPolicies(): Promise<PolicyView | PolicyView[] | any> { return this.request("GET", ENDPOINTS.policies); }
  async upsertPolicy(payload: Record<string, unknown>): Promise<PolicyView | any> { return this.request("POST", ENDPOINTS.policies, payload); }
  streamUrl(path: string = ENDPOINTS.stream): string {
    const p = path.startsWith("/") ? path : `/${path}`;
    return `${this.baseUrl}${p}`;
  }
  async close(): Promise<void> {}
}

export default ScopeGateClient;

