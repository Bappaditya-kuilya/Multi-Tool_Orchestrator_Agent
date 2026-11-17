import { apiUrl, API_TOKEN, API_TIMEOUT_MS, STREAM_PATH } from './config'
import type { ApiApproval, ApiAuditLog, ApiPolicy, ApiTask, ApiUpstream } from '../types'

export type HealthStatus = { status?: string; ready?: boolean; reason?: string | null; [k: string]: unknown }
export type MetricsResponse = string
export type AuditResponse = { events: ApiAuditLog[]; chain_verified: boolean; verification?: unknown }
export type TasksResponse = { tasks: ApiTask[] }
export type GatewayEnvelope<T = any> = { status?: string; body?: T; fail_closed?: boolean; error?: string | null }

export class ApiError extends Error {
  status?: number
  body?: unknown
  constructor(message: string, status?: number, body?: unknown) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.body = body
  }
}

function envelopeBody<T>(v: any): T {
  // Gateway axum handlers return ApiResponse envelope {status, body, fail_closed, error}
  if (v && typeof v === 'object' && !Array.isArray(v) && ('body' in v || 'fail_closed' in v || ('status' in v && ('error' in v || 'body' in v)))) {
    if (v.fail_closed && v.error) throw new ApiError(String(v.error), undefined, v)
    if (v.error && v.body == null) throw new ApiError(String(v.error), undefined, v)
    return (v.body ?? ({} as any)) as T
  }
  return v as T
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const headers: Record<string, string> = { Accept: 'application/json', ...(init?.headers as Record<string, string> || {}) }
  if (API_TOKEN) headers.Authorization = `Bearer ${API_TOKEN}`
  const ctrl = typeof AbortController !== 'undefined' ? new AbortController() : null
  const timer = ctrl ? setTimeout(() => ctrl.abort(), API_TIMEOUT_MS) : null
  try {
    const res = await fetch(apiUrl(path), { ...init, headers, signal: ctrl?.signal ?? init?.signal })
    const ct = res.headers.get('content-type') || ''
    const raw = ct.includes('application/json') ? await res.json().catch(() => undefined) : await res.text().catch(() => '')
    if (!res.ok) {
      const env = raw && typeof raw === 'object' ? (raw as any) : null
      const msg = env?.error || env?.message || (typeof raw === 'string' && raw) || `HTTP ${res.status} ${res.statusText}`.trim()
      throw new ApiError(String(msg), res.status, raw)
    }
    if (typeof raw === 'string') return raw as unknown as T
    return envelopeBody<T>(raw)
  } catch (e) {
    if (e instanceof ApiError) throw e
    if (e && typeof e === 'object' && (e as any).name === 'AbortError') throw new ApiError(`request timeout after ${API_TIMEOUT_MS}ms`)
    throw new ApiError(e instanceof Error ? e.message : 'network error')
  } finally {
    if (timer) clearTimeout(timer)
  }
}

const asArray = <T>(v: any): T[] => (Array.isArray(v) ? v : [])
const asText = (v: any) => (typeof v === 'string' ? v : v == null ? '' : String(v))

function policyBodyToText(body: unknown): string {
  if (typeof body === 'string') return body
  if (body == null) return ''
  try { return JSON.stringify(body, null, 2) } catch { return String(body) }
}

export const client = {
  healthz: () => request<HealthStatus>('/healthz'),
  readyz: () => request<HealthStatus>('/readyz'),
  metrics: async () => asText(await request<unknown>('/metrics')),
  getTasks: async () => {
    const body = await request<TasksResponse | ApiTask[]>('/v1/tasks')
    return asArray<ApiTask>((body as any)?.tasks ?? body)
  },
  // Gateway currently executes/creates task via POST /v1/tasks; no GET /v1/tasks/:id.
  runTask: (payload: Record<string, unknown>) =>
    request<any>('/v1/tasks', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) }),
  // No list endpoint in current gateway routes; resolve/create supported.
  resolveApproval: (id: string, action: 'approve' | 'deny' | 'create' | 'timeout', extra: Record<string, unknown> = {}) =>
    request<ApiApproval>('/v1/approvals', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ id, action, ...extra }) }),
  getAudit: async () => {
    const body = await request<AuditResponse | ApiAuditLog[]>('/v1/audit')
    if (Array.isArray(body)) return { events: body, chain_verified: false } as AuditResponse
    return { events: asArray<ApiAuditLog>((body as any)?.events), chain_verified: !!(body as any)?.chain_verified, verification: (body as any)?.verification }
  },
  getPolicy: async (): Promise<ApiPolicy | undefined> => {
    const body = await request<ApiPolicy>('/v1/policies')
    if (!body) return undefined
    return { ...body, body: policyBodyToText((body as any).body) }
  },
  putPolicy: async (bodyText: string, id = 'default') => {
    let parsed: unknown = bodyText
    try { parsed = JSON.parse(bodyText) } catch { /* keep raw string */ }
    const res = await request<ApiPolicy>('/v1/policies', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ id, body: typeof parsed === 'string' ? parsed : bodyText, active: true }) })
    return { ...res, body: policyBodyToText((res as any).body ?? parsed ?? bodyText) }
  },
  // No /v1/upstreams route in current gateway server; kept for forward compatibility.
  getUpstreams: async () => asArray<ApiUpstream>((await request<any>('/v1/upstreams')) as any),
  streamUrl: () => apiUrl(STREAM_PATH),
}

