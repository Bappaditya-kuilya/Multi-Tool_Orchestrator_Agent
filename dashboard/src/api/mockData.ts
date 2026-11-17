import type { Approval, ApprovalStatus, AuditEntry, Benchmark, Policy, StreamEvent, TaskNode, TimelineEvent, Upstream } from '../types'

const now = '2026-11-17T09:15:00Z'

const timeline: TimelineEvent[] = [
  { id: 'evt-1042', seq: 1042, time: '2026-11-17 09:14:02', actor: 'orchestrator', action: 'Route task: summarize incident', decision: 'permit', reason: 'Matched allow.read; confidence 0.96.', taskId: 't1-1', tokens: 1240, api: { ts: '2026-11-17T09:14:02Z', task_id: 't1-1', tool: 'summarize', decision: 'permit', reason: 'Matched allow.read', args_digest: 'sha256:aa12', result_digest: 'sha256:bb34' } },
  { id: 'evt-1041', seq: 1041, time: '2026-11-17 09:12:47', actor: 'agent:builder', action: 'Request shell: npm install', decision: 'require-approval', reason: 'Network installs require approval per net.install.', taskId: 't1-2', tokens: 420, api: { ts: '2026-11-17T09:12:47Z', task_id: 't1-2', tool: 'shell.exec', decision: 'require-approval', reason: 'net.install', args_digest: 'sha256:cc56', result_digest: '' } },
  { id: 'evt-1040', seq: 1040, time: '2026-11-17 09:10:11', actor: 'agent:researcher', action: 'Fetch upstream: docs/api', decision: 'permit', reason: 'Domain on allowlist; read-only operation.', taskId: 't1', tokens: 2100, api: { ts: '2026-11-17T09:10:11Z', task_id: 't1', tool: 'http.fetch', decision: 'permit', reason: 'allowlist', args_digest: 'sha256:dd78', result_digest: 'sha256:ee90' } },
  { id: 'evt-1039', seq: 1039, time: '2026-11-17 09:08:55', actor: 'orchestrator', action: 'Spawn subtask: audit scan', decision: 'warn', reason: 'High token estimate; within budget threshold.', taskId: 't1-4c', tokens: 6800, api: { ts: '2026-11-17T09:08:55Z', task_id: 't1-4c', tool: 'task.spawn', decision: 'warn', reason: 'budget threshold', args_digest: 'sha256:ff12', result_digest: 'sha256:0011' } },
  { id: 'evt-1038', seq: 1038, time: '2026-11-17 09:05:30', actor: 'agent:builder', action: 'Write file: dashboard/App.tsx', decision: 'permit', reason: 'Path within owned workspace scope.', taskId: 't1-2', tokens: 860, api: { ts: '2026-11-17T09:05:30Z', task_id: 't1-2', tool: 'fs.write', decision: 'permit', reason: 'scope match', args_digest: 'sha256:2233', result_digest: 'sha256:4455' } },
]

const taskTree: TaskNode[] = [
  { id: 'task-001', title: 'M5: Dashboard buildout', status: 'running', owner: 'subagent:dashboard', tokens: 9420, detail: 'Improve dashboard toward PRD screens and admin API models.', api: { id: 'task-001', parent_id: null, token_id: 'tok-root', scopes: ['dashboard:**', 'tool:read'], budget: 20000, expires_at: '2026-11-17T12:00:00Z', revoked: false }, children: [
    { id: 'task-001-1', title: 'Timeline (audit-aligned events)', status: 'done', tokens: 1240, detail: 'Chronological decisions with API-shaped fields.', api: { id: 'task-001-1', parent_id: 'task-001', token_id: 'tok-001-1', scopes: ['dashboard:src/**'], budget: 3000, expires_at: '2026-11-17T11:00:00Z', revoked: false } },
    { id: 'task-001-2', title: 'Task tree view', status: 'running', tokens: 1280, detail: 'Hierarchical tasks with scopes/budget drilldown.', owner: 'agent:builder', api: { id: 'task-001-2', parent_id: 'task-001', token_id: 'tok-001-2', scopes: ['dashboard:src/screens/**'], budget: 4000, expires_at: '2026-11-17T11:00:00Z', revoked: false } },
    { id: 'task-001-3', title: 'Approvals queue', status: 'pending', tokens: 600, detail: 'Resolve approvals with transitions and history.', api: { id: 'task-001-3', parent_id: 'task-001', token_id: 'tok-001-3', scopes: ['dashboard:src/screens/Approvals.tsx'], budget: 2000, expires_at: '2026-11-17T11:00:00Z', revoked: false } },
    { id: 'task-001-4', title: 'Dry-run, benchmark, SSE', status: 'running', tokens: 6300, detail: 'Dry-run view, benchmark compare, /v1/stream placeholder.', children: [
      { id: 'task-001-4a', title: 'Policy editor (version/body/active)', status: 'done', tokens: 400, detail: 'Editable draft mapped to policy API shape.' },
      { id: 'task-001-4b', title: 'Upstreams health panel', status: 'done', tokens: 500, detail: 'Transport/target/secret_ref view.' },
      { id: 'task-001-4c', title: 'Audit log + verify', status: 'done', tokens: 3200, detail: 'Hash chain fields and verify interaction.' },
      { id: 'task-001-4d', title: 'Dry-run and benchmark views', status: 'running', tokens: 2200, detail: 'Would-block/allow simulation and metric comparison.' },
    ]},
  ]},
  { id: 'task-002', title: 'Integration checks', status: 'pending', owner: 'orchestrator', tokens: 300, detail: 'Build and render verification.', api: { id: 'task-002', parent_id: null, token_id: 'tok-int', scopes: ['dashboard:**'], budget: 1000, expires_at: '2026-11-17T13:00:00Z', revoked: false } },
]

let approvals: Approval[] = [
  { id: 'apr-301', requestedAt: '09:12:47', requester: 'agent:builder', action: 'Run: npm install', risk: 'medium', details: 'Install deps; network egress required.', status: 'pending', history: [{ at: '09:12:47', status: 'pending', note: 'Requested' }], api: { id: 'apr-301', task_id: 'task-001-2', tool: 'shell.exec', args_hash: 'sha256:apr301', status: 'pending', created_at: '2026-11-17T09:12:47Z', resolved_at: null, resolver: null } },
  { id: 'apr-302', requestedAt: '09:09:03', requester: 'agent:researcher', action: 'Read: /etc/hosts', risk: 'low', details: 'Inspect host mappings for upstream debug.', status: 'pending', history: [{ at: '09:09:03', status: 'pending', note: 'Requested' }], api: { id: 'apr-302', task_id: 'task-001', tool: 'fs.read', args_hash: 'sha256:apr302', status: 'pending', created_at: '2026-11-17T09:09:03Z', resolved_at: null, resolver: null } },
  { id: 'apr-303', requestedAt: '08:58:21', requester: 'orchestrator', action: 'Write: policy.yaml', risk: 'high', details: 'Proposed policy update to relax shell allowlist.', status: 'pending', history: [{ at: '08:58:21', status: 'pending', note: 'Requested' }], api: { id: 'apr-303', task_id: 'task-001-3', tool: 'policy.write', args_hash: 'sha256:apr303', status: 'pending', created_at: '2026-11-17T08:58:21Z', resolved_at: null, resolver: null } },
]

const audit: AuditEntry[] = [
  { id: 'aud-897', seq: 897, time: '09:08:55', severity: 'warn', source: 'budget', event: 'token.threshold', detail: 'Estimated 42k tokens; within warn band.', prevHash: 'GENESIS', hash: 'h1a9f', api: { seq: 897, ts: '2026-11-17T09:08:55Z', task_id: 'task-001-4c', tool: 'budget.check', decision: 'warn', reason: 'threshold', args_digest: 'sha256:a897', result_digest: 'sha256:r897', prev_hash: 'GENESIS', hash: 'h1a9f' } },
  { id: 'aud-898', seq: 898, time: '09:10:11', severity: 'info', source: 'upstream.docs', event: 'fetch.ok', detail: 'Fetched docs/api (200, 18kb).', prevHash: 'h1a9f', hash: 'h2b4c', api: { seq: 898, ts: '2026-11-17T09:10:11Z', task_id: 'task-001', tool: 'http.fetch', decision: 'permit', reason: 'ok', args_digest: 'sha256:a898', result_digest: 'sha256:r898', prev_hash: 'h1a9f', hash: 'h2b4c' } },
  { id: 'aud-899', seq: 899, time: '09:12:40', severity: 'fail', source: 'upstream.audit', event: 'sink.unreachable', detail: 'Audit sink refused; 3 events buffered.', prevHash: 'h2b4c', hash: 'h3c7d', api: { seq: 899, ts: '2026-11-17T09:12:40Z', task_id: 'task-001-4b', tool: 'audit.write', decision: 'error', reason: 'sink unreachable', args_digest: 'sha256:a899', result_digest: 'sha256:r899', prev_hash: 'h2b4c', hash: 'h3c7d' } },
  { id: 'aud-900', seq: 900, time: '09:12:47', severity: 'warn', source: 'policy', event: 'decision.approval_required', detail: 'net.install triggered for npm install.', prevHash: 'h3c7d', hash: 'h4d2e', api: { seq: 900, ts: '2026-11-17T09:12:47Z', task_id: 'task-001-2', tool: 'shell.exec', decision: 'require-approval', reason: 'net.install', args_digest: 'sha256:a900', result_digest: '', prev_hash: 'h3c7d', hash: 'h4d2e' } },
  { id: 'aud-901', seq: 901, time: '09:14:02', severity: 'info', source: 'policy', event: 'decision.allowed', detail: 'allow.read matched for dashboard/src/App.tsx.', prevHash: 'h4d2e', hash: 'h5e11', api: { seq: 901, ts: '2026-11-17T09:14:02Z', task_id: 'task-001-1', tool: 'fs.read', decision: 'permit', reason: 'allow.read', args_digest: 'sha256:a901', result_digest: 'sha256:r901', prev_hash: 'h4d2e', hash: 'h5e11' } },
]

const benchmarks: Benchmark[] = [
  { name: 'Task success rate', score: 92, baseline: 90, unit: '%', status: 'pass', history: [88, 89, 90, 91, 92], dryRun: { wouldBlock: 3, wouldAllow: 94, wouldApprove: 3 } },
  { name: 'Avg latency (p50)', score: 840, baseline: 900, unit: 'ms', status: 'pass', history: [980, 940, 910, 870, 840], dryRun: { wouldBlock: 0, wouldAllow: 100, wouldApprove: 0 } },
  { name: 'Policy block accuracy', score: 97, baseline: 95, unit: '%', status: 'pass', history: [94, 95, 95, 96, 97], dryRun: { wouldBlock: 12, wouldAllow: 85, wouldApprove: 3 } },
  { name: 'Tool error rate', score: 4.8, baseline: 3, unit: '%', status: 'warn', history: [2.5, 3.1, 3.9, 4.2, 4.8], dryRun: { wouldBlock: 1, wouldAllow: 97, wouldApprove: 2 } },
  { name: 'Cost per task', score: 0.031, baseline: 0.025, unit: 'USD', status: 'warn', history: [0.022, 0.024, 0.027, 0.029, 0.031], dryRun: { wouldBlock: 0, wouldAllow: 100, wouldApprove: 0 } },
]

const upstreams: Upstream[] = [
  { id: 'up-1', name: 'LLM Gateway', endpoint: 'https://llm.internal/v1', transport: 'streamable-http', secretRef: 'env:LLM_KEY', enabled: true, status: 'healthy', latencyMs: 142, lastCheck: '09:14:10', note: 'Primary model pool responding.', api: { id: 'up-1', name: 'LLM Gateway', transport: 'streamable-http', target: 'https://llm.internal/v1', secret_ref: 'env:LLM_KEY', enabled: 1 as unknown as boolean } },
  { id: 'up-2', name: 'Vector Store', endpoint: 'https://vec.internal:8080', transport: 'streamable-http', secretRef: 'env:VEC_KEY', enabled: true, status: 'healthy', latencyMs: 38, lastCheck: '09:14:08', note: 'Index warm, 0 errors.', api: { id: 'up-2', name: 'Vector Store', transport: 'streamable-http', target: 'https://vec.internal:8080', secret_ref: 'env:VEC_KEY', enabled: 1 as unknown as boolean } },
  { id: 'up-3', name: 'Policy Service', endpoint: 'https://policy.internal', transport: 'streamable-http', secretRef: 'env:POLICY_KEY', enabled: true, status: 'degraded', latencyMs: 620, lastCheck: '09:13:55', note: 'Elevated latency on rule eval.', api: { id: 'up-3', name: 'Policy Service', transport: 'streamable-http', target: 'https://policy.internal', secret_ref: 'env:POLICY_KEY', enabled: 1 as unknown as boolean } },
  { id: 'up-4', name: 'Audit Sink', endpoint: 'https://audit.internal/ingest', transport: 'streamable-http', secretRef: 'env:AUDIT_KEY', enabled: true, status: 'down', latencyMs: 0, lastCheck: '09:12:40', note: 'Connection refused; buffering locally.', api: { id: 'up-4', name: 'Audit Sink', transport: 'streamable-http', target: 'https://audit.internal/ingest', secret_ref: 'env:AUDIT_KEY', enabled: 1 as unknown as boolean } },
]

let policy: Policy = { id: 'pol-1', version: 1, active: true, createdAt: '2026-11-17T08:00:00Z', draft: `version: 1\ndefaults:\n  decision: deny\nrules:\n  - id: allow.read\n    match: { op: read }\n    decision: allow\n  - id: net.install\n    match: { op: shell, pattern: "npm install*" }\n    decision: require_approval\n  - id: block.secrets\n    match: { op: read, path: "**/.env*" }\n    decision: deny\n`, api: { id: 'pol-1', version: 1, body: '', created_at: '2026-11-17T08:00:00Z', active: true } }
policy.api = { id: policy.id, version: policy.version, body: policy.draft, created_at: policy.createdAt, active: policy.active }
const basePolicy: Policy = JSON.parse(JSON.stringify(policy))

const streamEvents: StreamEvent[] = [
  { type: 'audit', id: 'aud-901', ts: '09:14:02', summary: 'permit fs.read task-001-1 (allow.read)' },
  { type: 'approval', id: 'apr-301', ts: '09:12:47', summary: 'pending shell.exec task-001-2 requires approval' },
  { type: 'upstream', id: 'up-4', ts: '09:12:40', summary: 'audit sink down, buffering locally' },
  { type: 'task', id: 'task-001-4', ts: '09:08:55', summary: 'task running: dry-run/benchmark/SSE' },
]

const dryRunScenarios = [
  { id: 'dr-1', tool: 'shell.exec', taskId: 'task-001-2', args: 'npm install', decision: 'require-approval', reason: 'net.install (dry-run, not blocked)', policy: 'pol-1@v1' },
  { id: 'dr-2', tool: 'fs.read', taskId: 'task-001-1', args: 'docs/PRD.md', decision: 'permit', reason: 'allow.read', policy: 'pol-1@v1' },
  { id: 'dr-3', tool: 'fs.read', taskId: 'task-001', args: '.env', decision: 'forbid', reason: 'block.secrets', policy: 'pol-1@v1' },
  { id: 'dr-4', tool: 'http.fetch', taskId: 'task-001', args: 'https://unknown.example', decision: 'forbid', reason: 'default deny', policy: 'pol-1@v1' },
]

const delay = <T,>(v: T) => Promise.resolve(v)

export const mock = {
  getTimeline: () => delay([...timeline]),
  getTaskTree: () => delay(JSON.parse(JSON.stringify(taskTree)) as TaskNode[]),
  getApprovals: () => delay(approvals.map(a => ({ ...a, history: [...a.history], api: a.api ? { ...a.api } : undefined }))),
  decideApproval: (id: string, status: ApprovalStatus, note: string) => {
    approvals = approvals.map(a => a.id === id ? { ...a, status, history: [...a.history, { at: '09:15:00', status, note }], api: a.api ? { ...a.api, status, resolved_at: now, resolver: 'dashboard-user' } : a.api } : a)
    return delay(approvals.find(a => a.id === id)!)
  },
  getAudit: () => delay(audit.map(e => ({ ...e, api: e.api ? { ...e.api } : undefined }))),
  verifyAuditChain: () => delay(audit.every((e, i) => e.prevHash === (i ? audit[i - 1].hash : 'GENESIS') && !!e.hash)),
  getBenchmarks: () => delay(benchmarks.map(b => ({ ...b, history: [...b.history], dryRun: b.dryRun ? { ...b.dryRun } : undefined }))),
  getUpstreams: () => delay(upstreams.map(u => ({ ...u, api: u.api ? { ...u.api } : undefined }))),
  getPolicy: () => delay({ ...policy, api: policy.api ? { ...policy.api } : undefined }),
  savePolicy: (draft: string) => {
    policy = { ...policy, version: policy.version + 1, draft, createdAt: now, api: { id: policy.id, version: policy.version + 1, body: draft, created_at: now, active: true } }
    return delay({ ...policy, api: policy.api ? { ...policy.api } : undefined })
  },
  resetPolicy: () => {
    policy = JSON.parse(JSON.stringify(basePolicy))
    return delay({ ...policy, api: policy.api ? { ...policy.api } : undefined })
  },
  getStreamEvents: () => delay([...streamEvents]),
  getDryRunScenarios: () => delay(dryRunScenarios.map(s => ({ ...s }))),
}

export const mockStreamEvents = mock.getStreamEvents
