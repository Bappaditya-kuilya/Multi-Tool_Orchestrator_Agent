import { useEffect, useState } from 'react'
import { api } from '../api/mockApi'
import type { Approval, ApprovalStatus } from '../types'

const transitions: Record<ApprovalStatus, ApprovalStatus[]> = {
  pending: ['approved', 'denied', 'escalated'],
  approved: ['escalated'],
  denied: ['pending'],
  escalated: ['approved', 'denied'],
  timeout: ['pending'],
  expired: ['pending'],
}

export default function Approvals() {
  const [items, setItems] = useState<Approval[]>([])
  const [loading, setLoading] = useState(true)
  const [busy, setBusy] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [source, setSource] = useState<'live' | 'mock'>('mock')

  const load = async () => {
    setLoading(true)
    const res = await api.getApprovals()
    setItems(res.data)
    setSource(res.source)
    setError(res.error || null)
    setLoading(false)
  }
  useEffect(() => { void load() }, [])

  const act = async (id: string, status: ApprovalStatus) => {
    setBusy(id)
    const res = await api.decideApproval(id, status, `resolve -> ${status} via dashboard`)
    if (res.error) setError(res.error)
    await load()
    setBusy(null)
  }

  const pending = items.filter(i => i.status === 'pending').length
  return (
    <section className="screen">
      <h1>Approvals</h1>
      <p className="subtitle">Queue with resolve actions via POST /v1/approvals (id/action). Gateway currently has no list endpoint; live mode may fall back to mock data with an error message.</p>
      <div className="panel filters">
        <button className="btn" type="button" onClick={() => void load()} disabled={loading}>Refresh</button>
        <span className={`badge ${source === 'live' ? 'healthy' : 'info'}`}>{source}</span>
        <span className="badge warn" aria-label={`${pending} pending approvals`}>{pending} pending</span>
        {error && <span className="muted"><span className="badge denied">error</span> {error}</span>}
      </div>
      <div className="panel">
        {loading ? <p className="muted">Loading approvals…</p> : items.length === 0 ? <p className="muted">No approvals.</p> : (
          <table aria-label="Approvals queue">
            <caption className="sr-only">Approval requests with state transitions and API fields</caption>
            <thead><tr><th scope="col">ID</th><th scope="col">Task/Tool</th><th scope="col">Args hash</th><th scope="col">Risk</th><th scope="col">Status</th><th scope="col">Created/Resolved</th><th scope="col">Actions</th><th scope="col">History</th></tr></thead>
            <tbody>
              {items.map(it => (
                <tr key={it.id}>
                  <td className="mono">{it.api?.id ?? it.id}</td>
                  <td><div className="mono">{it.api?.task_id ?? '—'}</div><div>{it.api?.tool ?? it.action}</div><div className="muted small">{it.details}</div></td>
                  <td className="mono muted">{it.api?.args_hash ?? '—'}</td>
                  <td><span className={`badge ${it.risk === 'high' ? 'denied' : it.risk === 'medium' ? 'warn' : 'info'}`}>{it.risk}</span></td>
                  <td><span className={`badge ${it.status}`}>{it.api?.status ?? it.status}</span></td>
                  <td className="muted small mono"><div>c: {it.api?.created_at ?? it.requestedAt}</div><div>r: {it.api?.resolved_at ?? '—'}</div><div>by: {it.api?.resolver ?? '—'}</div></td>
                  <td><div className="actions wrap" aria-label={`Actions for ${it.id}`}>
                    {(transitions[it.status] || []).map(s => <button key={s} className={`btn ${s === 'approved' ? 'approve' : s === 'denied' ? 'deny' : ''}`} onClick={() => void act(it.id, s)} type="button" disabled={busy === it.id} aria-label={`${s} ${it.id}`}>{busy === it.id ? '…' : s}</button>)}
                    {!transitions[it.status]?.length && <span className="muted small">no actions</span>}
                  </div></td>
                  <td className="muted small">{(it.history || []).map((h, i) => <div key={h.at + h.status + i}>{h.at}: {h.status} — {h.note}</div>)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </section>
  )
}

