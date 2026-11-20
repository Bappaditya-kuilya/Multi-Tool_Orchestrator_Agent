import { useEffect, useState } from 'react'
import { api } from '../api/mockApi'
import type { TaskNode } from '../types'

function badge(status: TaskNode['status']) {
  const cls = status === 'done' ? 'approved' : status === 'running' || status === 'active' ? 'info' : status === 'blocked' || status === 'revoked' || status === 'expired' ? 'blocked' : 'pending'
  return <span className={`badge ${cls}`}>{status}</span>
}

function Node({ node, selected, onSelect }: { node: TaskNode; selected?: string; onSelect: (n: TaskNode) => void }) {
  return (
    <li>
      <button type="button" className={`node row as-btn ${selected === node.id ? 'selected' : ''}`} onClick={() => onSelect(node)} aria-pressed={selected === node.id}>
        <span className="node-title">{node.title}</span>{badge(node.status)}
        <span className="muted">{node.tokens} tok</span>{node.owner && <span className="muted">· {node.owner}</span>}
      </button>
      {node.children?.length ? <ul>{node.children.map(c => <Node key={c.id} node={c} selected={selected} onSelect={onSelect} />)}</ul> : null}
    </li>
  )
}

export default function TaskTree() {
  const [tree, setTree] = useState<TaskNode[]>([])
  const [selected, setSelected] = useState<TaskNode | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [source, setSource] = useState<'live' | 'mock'>('mock')
  const [busy, setBusy] = useState<string | null>(null)

  const load = async () => {
    setLoading(true)
    const res = await api.getTaskTree()
    setTree(res.data)
    setSelected(prev => {
      const flat = (nodes: TaskNode[]): TaskNode[] => nodes.flatMap(n => [n, ...flat(n.children || [])])
      return prev ? (flat(res.data).find(n => n.id === prev.id) ?? res.data[0] ?? null) : (res.data[0] ?? null)
    })
    setSource(res.source)
    setError(res.error || null)
    setLoading(false)
  }
  useEffect(() => { void load() }, [])

  const refreshSelected = async () => {
    if (!selected) return
    setBusy(`get:${selected.id}`)
    const res = await api.getTask(selected.id)
    if (res.error) setError(res.error)
    setSource(res.source)
    setSelected(res.data)
    setBusy(null)
  }

  const revokeSelected = async () => {
    if (!selected) return
    const reason = typeof prompt === 'function' ? (prompt('Revocation reason (optional)', 'manual revoke') ?? undefined) : undefined
    setBusy(`revoke:${selected.id}`)
    const res = await api.revokeTask(selected.id, reason ? { reason } : {})
    if (res.error) setError(res.error)
    setBusy(null)
    await load()
    if (res.data?.id) {
      const sel = res.data
      setSelected(sel)
    }
  }

  return (
    <section className="screen">
      <h1>Task Tree</h1>
      <p className="subtitle">Hierarchical tasks from /v1/tasks when available. Supports GET /v1/tasks/:id and POST /v1/tasks/:id/revoke when gateway provides them.</p>
      <div className="panel filters">
        <button className="btn" type="button" onClick={() => void load()} disabled={loading}>Refresh</button>
        <span className={`badge ${source === 'live' ? 'healthy' : 'info'}`}>{source}</span>
        {error && <span className="muted"><span className="badge warn">gateway error</span> {error}</span>}
      </div>
      <div className="split">
        <div className="panel" aria-label="Task hierarchy">
          {loading ? <p className="muted">Loading tasks…</p> : tree.length === 0 ? <p className="muted">No tasks.</p> : <ul className="tree">{tree.map(n => <Node key={n.id} node={n} selected={selected?.id} onSelect={setSelected} />)}</ul>}
        </div>
        <div className="panel">
          <h2>Task details</h2>
          {selected ? (
            <div>
              <p><strong>{selected.api?.id ?? selected.id}</strong> {badge(selected.status)}</p>
              <p>{selected.title}</p>
              <p className="muted">{selected.detail}</p>
              <div className="actions wrap" style={{ marginBottom: 8 }}>
                <button className="btn" type="button" onClick={() => void refreshSelected()} disabled={!!busy}> {busy?.startsWith('get:') ? 'Refreshing…' : 'Refresh task'} </button>
                <button className="btn deny" type="button" onClick={() => void revokeSelected()} disabled={!!busy || !!selected.api?.revoked}> {busy?.startsWith('revoke:') ? 'Revoking…' : 'Revoke task'} </button>
              </div>
              <table aria-label="Selected task fields"><tbody>
                <tr><th scope="row">parent_id</th><td className="mono">{selected.api?.parent_id ?? '—'}</td></tr>
                <tr><th scope="row">token_id</th><td className="mono">{selected.api?.token_id ?? '—'}</td></tr>
                <tr><th scope="row">scopes</th><td className="mono">{Array.isArray(selected.api?.scopes) ? (selected.api?.scopes.join(', ') || '—') : (selected.api?.scopes || '—')}</td></tr>
                <tr><th scope="row">budget / used</th><td>{selected.api?.budget ?? '—'} / {selected.tokens}</td></tr>
                <tr><th scope="row">expires_at</th><td className="mono">{selected.api?.expires_at ?? '—'}</td></tr>
                <tr><th scope="row">revoked</th><td>{String(selected.api?.revoked ?? false)}</td></tr>
                <tr><th scope="row">revocation_reason</th><td className="mono">{(selected.api as any)?.revocation_reason ?? '—'}</td></tr>
                <tr><th scope="row">children</th><td>{selected.children?.length ?? 0}</td></tr>
              </tbody></table>
            </div>
          ) : <p className="muted">Select a task.</p>}
        </div>
      </div>
    </section>
  )
}

