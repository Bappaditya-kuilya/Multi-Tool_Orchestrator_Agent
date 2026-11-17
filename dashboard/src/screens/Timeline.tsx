import { useEffect, useMemo, useState } from 'react'
import { api } from '../api/mockApi'
import type { TimelineEvent } from '../types'

export default function Timeline() {
  const [events, setEvents] = useState<TimelineEvent[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [source, setSource] = useState<'live' | 'mock'>('mock')
  const [query, setQuery] = useState('')
  const [decision, setDecision] = useState<'all' | TimelineEvent['decision']>('all')
  const [actor, setActor] = useState('all')

  const load = async () => {
    setLoading(true)
    const res = await api.getTimeline()
    setEvents(res.data)
    setSource(res.source)
    setError(res.error || null)
    setLoading(false)
  }
  useEffect(() => { void load() }, [])

  const actors = useMemo(() => ['all', ...Array.from(new Set(events.map(e => e.actor)))], [events])
  const filtered = events.filter(e =>
    (decision === 'all' || e.decision === decision) &&
    (actor === 'all' || e.actor === actor) &&
    (!query || `${e.id} ${e.action} ${e.reason} ${e.api?.tool ?? ''}`.toLowerCase().includes(query.toLowerCase()))
  )
  const totalTokens = filtered.reduce((s, e) => s + e.tokens, 0)

  return (
    <section className="screen">
      <h1>Timeline</h1>
      <p className="subtitle">Chronological decisions/reasons derived from admin audit/task data when available (ts/task_id/tool/decision/digests)</p>
      <div className="panel filters" role="search" aria-label="Timeline filters">
        <button className="btn" type="button" onClick={() => void load()} disabled={loading}>Refresh</button>
        <span className={`badge ${source === 'live' ? 'healthy' : 'info'}`}>{source}</span>
        <label>Search <input placeholder="action/reason/id/tool" value={query} onChange={e => setQuery(e.target.value)} /></label>
        <label>Decision <select value={decision} onChange={e => setDecision(e.target.value as any)}>
          <option value="all">all</option><option value="permit">permit</option><option value="require-approval">require-approval</option><option value="forbid">forbid</option><option value="warn">warn</option>
        </select></label>
        <label>Actor <select value={actor} onChange={e => setActor(e.target.value)}>{actors.map(a => <option key={a} value={a}>{a}</option>)}</select></label>
        <span className="muted">{filtered.length} events · {totalTokens} tokens</span>
      </div>
      {error && <div className="panel" role="status"><span className="badge warn">gateway error</span> <span className="muted">{error} (showing fallback data)</span></div>}
      <div className="panel">
        {loading ? <p className="muted">Loading timeline…</p> : filtered.length === 0 ? <p className="muted">No timeline events.</p> : (
          <table aria-label="Timeline of decisions">
            <caption className="sr-only">Timeline events with decision, reason, and admin API-aligned audit fields</caption>
            <thead><tr><th scope="col">Seq</th><th scope="col">Time</th><th scope="col">Task</th><th scope="col">Tool/Action</th><th scope="col">Decision</th><th scope="col">Reason</th><th scope="col">Args digest</th><th scope="col">Result digest</th><th scope="col">Tokens</th></tr></thead>
            <tbody>
              {filtered.map(e => (
                <tr key={e.id}>
                  <td className="mono">{e.seq ?? '—'}</td>
                  <td className="muted mono">{e.api?.ts ?? e.time}</td>
                  <td className="mono">{e.api?.task_id ?? e.taskId ?? '—'}</td>
                  <td><strong>{e.api?.tool ?? e.action}</strong><div className="muted small">{e.actor}</div></td>
                  <td><span className={`badge ${e.decision === 'permit' ? 'allowed' : e.decision === 'forbid' ? 'blocked' : e.decision === 'require-approval' ? 'warn' : 'info'}`}>{e.api?.decision ?? e.decision}</span></td>
                  <td>{e.api?.reason ?? e.reason}</td>
                  <td className="mono muted">{e.api?.args_digest || '—'}</td>
                  <td className="mono muted">{e.api?.result_digest || '—'}</td>
                  <td>{e.tokens}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </section>
  )
}

