// UI/domain enums
export type DecisionKind = 'permit' | 'forbid' | 'allow' | 'deny' | 'blocked' | 'warn' | 'require-approval'
export type Severity = 'info' | 'warn' | 'fail'
export type Risk = 'low' | 'medium' | 'high'
export type ApprovalStatus = 'pending' | 'approved' | 'denied' | 'escalated' | 'timeout' | 'expired'
export type TaskStatus = 'active' | 'done' | 'running' | 'pending' | 'blocked' | 'revoked' | 'expired'

// Admin API-aligned shapes (actual gateway /v1/* where available; some fields optional for compatibility)
export interface ApiTask {
  id: string
  parent_id?: string | null
  token_id?: string
  scopes?: string[] | string
  budget?: number
  expires_at?: string
  revoked?: boolean
  state?: string
  stage?: string | null
  allowed?: boolean | null
}

export interface ApiApproval {
  id: string
  task_id?: string
  tool?: string
  args_hash?: string
  status: string
  created_at?: string
  resolved_at?: string | null
  resolver?: string | null
  source?: string | null
}

export interface ApiAuditLog {
  seq: number
  ts?: string
  task_id?: string | null
  tool?: string | null
  decision: string
  reason?: string | null
  args_digest?: string | null
  result_digest?: string | null
  prev_hash?: string | number[] | null
  hash?: string | number[] | null
}

export interface ApiPolicy {
  id: string
  version?: number
  body?: unknown
  created_at?: string
  active: boolean
}

export interface ApiUpstream {
  id: string
  name: string
  transport: 'stdio' | 'streamable-http' | string
  target: string
  secret_ref?: string
  enabled: boolean
}

export interface StreamEvent {
  type: string
  id?: string
  ts?: string
  summary: string
  kind?: string
  message?: string
  task_id?: string | null
}

// View models (screen-friendly, derived from/admin-aligned)
export interface TimelineEvent {
  id: string
  seq?: number
  time: string
  actor: string
  action: string
  decision: DecisionKind
  reason: string
  taskId?: string
  tokens: number
  api?: Pick<ApiAuditLog, 'ts' | 'task_id' | 'tool' | 'decision' | 'reason' | 'args_digest' | 'result_digest'>
}

export interface TaskNode {
  id: string
  title: string
  status: TaskStatus
  owner?: string
  tokens: number
  detail: string
  children?: TaskNode[]
  api?: ApiTask
}

export interface Approval {
  id: string
  requestedAt: string
  requester: string
  action: string
  risk: Risk
  details: string
  status: ApprovalStatus
  history: { at: string; status: ApprovalStatus; note: string }[]
  api?: ApiApproval
}

export interface AuditEntry {
  id: string
  seq: number
  time: string
  severity: Severity
  source: string
  event: string
  detail: string
  prevHash: string
  hash: string
  api?: ApiAuditLog
}

export interface Benchmark {
  name: string
  score: number
  baseline: number
  unit: string
  status: 'pass' | 'warn' | 'fail'
  history: number[]
  dryRun?: { wouldBlock: number; wouldAllow: number; wouldApprove: number }
}

export interface Policy {
  id: string
  draft: string
  version: number
  active: boolean
  createdAt: string
  api?: ApiPolicy
}

export interface Upstream {
  id: string
  name: string
  endpoint: string
  transport: 'stdio' | 'streamable-http'
  secretRef: string
  enabled: boolean
  status: 'healthy' | 'degraded' | 'down'
  latencyMs: number
  lastCheck: string
  note: string
  api?: ApiUpstream
}
