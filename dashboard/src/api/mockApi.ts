import { client, ApiError } from './client'
import { isApiConfigured } from './config'
import { mock } from './mockData'
import type { ApiAuditLog, ApiTask, Approval, ApprovalStatus, AuditEntry, Benchmark, Policy, TaskNode, TimelineEvent, Upstream } from '../types'

export type Source = 'live' | 'mock'
export type WithSource<T> = { data: T; source: Source; error?: string }

const errMsg = (e: unknown) => (e instanceof ApiError ? e.message : e instanceof Error ? e.message : 'request failed')

async function tryLive<T>(fn: () => Promise<T>, fallback: () => Promise<T>): Promise<WithSource<T>> {
  if (!isApiConfigured()) return { data: await fallback(), source: 'mock', error: 'API base URL not configured' }
  try { return { data: await fn(), source: 'live' } }
  catch (e) { return { data: await fallback(), source: 'mock', error: errMsg(e) } }
}

function hashText(v: ApiAuditLog['hash'] | ApiAuditLog['prev_hash']): string {
  if (v == null) return ''
  if (typeof v === 'string') return v
  if (Array.isArray(v)) {
    try { return v.map(b => Number(b).toString(16).padStart(2, '0')).join('') || '' } catch { return String(v.length ? `[${v.length} bytes]` : '') }
  }
  return String(v)
}
function text(v: unknown, fb = ''): string { return typeof v === 'string' ? v : v == null ? fb : String(v) }
function scopesText(scopes: ApiTask['scopes']): string {
  if (Array.isArray(scopes)) return scopes.join(', ')
  if (typeof scopes === 'string') { try { const p = JSON.parse(scopes); return Array.isArray(p) ? p.join(', ') : scopes } catch { return scopes } }
  return '—'
}

const toApproval = (a: any): Approval => ({
  id: String(a.id),
  requestedAt: a.created_at || a.requestedAt || '',
  requester: a.resolver || a.requester || a.principal || 'gateway',
  action: a.tool || a.action || 'approval',
  risk: a.risk || 'medium',
  details: a.details || (a.args_hash ? `args_hash ${a.args_hash}` : a.message || ''),
  status: (a.status as ApprovalStatus) || 'pending',
  history: Array.isArray(a.history) && a.history.length ? a.history : [{ at: a.created_at || '', status: (a.status as ApprovalStatus) || 'pending', note: 'from gateway' }],
  api: a,
})

const toAudit = (e: ApiAuditLog): AuditEntry => {
  const prevHash = hashText(e.prev_hash)
  const hash = hashText(e.hash)
  const dec = String(e.decision || '')
  return {
    id: String(e.seq),
    seq: e.seq,
    time: text(e.ts, ''),
    severity: dec === 'error' || dec === 'fail' ? 'fail' : dec === 'warn' || dec.includes('require') ? 'warn' : 'info',
    source: 'gateway',
    event: text(e.tool, 'event'),
    detail: text(e.reason, ''),
    prevHash,
    hash,
    api: { ...e, prev_hash: prevHash, hash } as any,
  }
}

const toTimeline = (e: ApiAuditLog): TimelineEvent => {
  const d = String(e.decision || '').toLowerCase()
  const decision = d === 'permit' || d === 'allow' || d === 'allowed' ? 'permit' : d === 'forbid' || d === 'deny' || d === 'denied' || d === 'block' ? 'forbid' : d.includes('require') || d.includes('approval') ? 'require-approval' : d === 'warn' ? 'warn' : 'permit'
  return { id: `aud-${e.seq}`, seq: e.seq, time: text(e.ts, ''), actor: text(e.task_id, 'gateway'), action: text(e.tool, 'event'), decision, reason: text(e.reason, ''), taskId: e.task_id ?? undefined, tokens: 0, api: { ts: text(e.ts), task_id: text(e.task_id), tool: text(e.tool), decision: text(e.decision), reason: text(e.reason), args_digest: text(e.args_digest), result_digest: text(e.result_digest) } }
}

const taskStatus = (t: ApiTask): TaskNode['status'] => t.revoked ? 'revoked' : (t.expires_at && Date.parse(t.expires_at) && Date.parse(t.expires_at) < Date.now() ? 'expired' : (t.allowed === false ? 'blocked' : 'active'))

const tasksToTree = (tasks: ApiTask[]): TaskNode[] => {
  const byId = new Map<string, TaskNode>()
  for (const t of tasks) byId.set(t.id, { id: t.id, title: t.id, status: taskStatus(t), tokens: 0, detail: `scopes: ${scopesText(t.scopes)} · budget: ${t.budget ?? '—'}`, api: t, children: [] })
  const roots: TaskNode[] = []
  for (const n of byId.values()) {
    const p = (n.api as any)?.parent_id
    if (p && byId.has(p)) byId.get(p)!.children!.push(n)
    else roots.push(n)
  }
  const prune = (n: TaskNode) => { if (!n.children?.length) delete n.children; else n.children.forEach(prune) }
  roots.forEach(prune)
  return roots
}

const toUpstream = (u: any): Upstream => ({
  id: String(u.id),
  name: u.name || String(u.id),
  endpoint: u.target || u.endpoint || '',
  transport: u.transport || 'streamable-http',
  secretRef: u.secret_ref || u.secretRef || '',
  enabled: u.enabled === false ? false : !!u.enabled,
  status: u.status || (u.enabled === false ? 'down' : 'healthy'),
  latencyMs: typeof u.latencyMs === 'number' ? u.latencyMs : (typeof u.latency_ms === 'number' ? u.latency_ms : 0),
  lastCheck: u.lastCheck || u.last_check || '—',
  note: u.note || 'from gateway',
  api: u,
})

const toPolicy = (p: any): Policy => {
  const body = typeof p?.body === 'string' ? p.body : (p?.body != null ? (() => { try { return JSON.stringify(p.body, null, 2) } catch { return String(p.body) } })() : (p?.draft ?? ''))
  return { id: String(p.id ?? 'policy'), draft: body, version: Number(p.version ?? 1), active: !!p.active, createdAt: p.created_at ?? p.createdAt ?? '', api: p }
}

export const api = {
  async getTimeline(): Promise<WithSource<TimelineEvent[]>> {
    return tryLive(async () => {
      const res = await client.getAudit()
      return (res.events || []).slice().sort((a,b) => a.seq - b.seq).map(toTimeline)
    }, mock.getTimeline)
  },
  async getTaskTree(): Promise<WithSource<TaskNode[]>> {
    return tryLive(async () => tasksToTree(await client.getTasks()), mock.getTaskTree)
  },
  async getApprovals(): Promise<WithSource<Approval[]>> {
    // Gateway currently exposes create/resolve via POST /v1/approvals but no list endpoint.
    return tryLive(async () => { throw new Error('approvals list endpoint not available on gateway (POST /v1/approvals supports create/resolve)') }, mock.getApprovals)
  },
  async decideApproval(id: string, status: ApprovalStatus, note: string): Promise<WithSource<Approval>> {
    if (!isApiConfigured()) return { data: await mock.decideApproval(id, status, note), source: 'mock', error: 'API base URL not configured' }
    try {
      const action = status === 'approved' ? 'approve' : status === 'denied' ? 'deny' : status === 'timeout' ? 'timeout' : status
      const a = await client.resolveApproval(id, action as any, { principal: 'dashboard' })
      const ap = toApproval(a)
      ap.history = [...(ap.history || []), { at: (a as any)?.resolved_at || new Date().toISOString(), status: (ap.status as ApprovalStatus) || status, note }]
      return { data: ap, source: 'live' }
    } catch (e) {
      return { data: await mock.decideApproval(id, status, note), source: 'mock', error: errMsg(e) }
    }
  },
  async getAudit(): Promise<WithSource<AuditEntry[]>> {
    return tryLive(async () => ((await client.getAudit()).events || []).map(toAudit), mock.getAudit)
  },
  async verifyAuditChain(): Promise<WithSource<boolean>> {
    return tryLive(async () => {
      const res = await client.getAudit()
      if (typeof res.chain_verified === 'boolean') return res.chain_verified
      const sorted = (res.events || []).slice().sort((a,b)=>a.seq-b.seq)
      return sorted.every((e, i) => !!e.hash && hashText(e.prev_hash) === (i ? hashText(sorted[i - 1].hash) : 'GENESIS'))
    }, mock.verifyAuditChain)
  },
  async getBenchmarks(): Promise<WithSource<Benchmark[]>> {
    return tryLive(async () => { throw new Error('benchmark endpoint not configured') }, mock.getBenchmarks)
  },
  async getUpstreams(): Promise<WithSource<Upstream[]>> {
    return tryLive(async () => (await client.getUpstreams()).map(toUpstream), mock.getUpstreams)
  },
  async getPolicy(): Promise<WithSource<Policy>> {
    return tryLive(async () => {
      const p = await client.getPolicy()
      if (!p) throw new Error('no active policy returned')
      return toPolicy(p)
    }, mock.getPolicy)
  },
  async savePolicy(draft: string): Promise<WithSource<Policy>> {
    if (!isApiConfigured()) return { data: await mock.savePolicy(draft), source: 'mock', error: 'API base URL not configured' }
    try {
      const p = await client.putPolicy(draft)
      return { data: toPolicy(p), source: 'live' }
    } catch (e) {
      return { data: await mock.savePolicy(draft), source: 'mock', error: errMsg(e) }
    }
  },
  async resetPolicy(): Promise<WithSource<Policy>> {
    return { data: await mock.resetPolicy(), source: 'mock' }
  },
  async getStreamEvents(): Promise<WithSource<import('../types').StreamEvent[]>> {
    return { data: await mock.getStreamEvents(), source: 'mock' }
  },
  async getDryRunScenarios(): Promise<WithSource<{ id: string; tool: string; taskId: string; args: string; decision: string; reason: string; policy: string }[]>> {
    return { data: await mock.getDryRunScenarios(), source: 'mock' }
  },
  client,
}

