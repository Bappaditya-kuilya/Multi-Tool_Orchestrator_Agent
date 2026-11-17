import { useEffect, useState } from 'react'
import { api } from '../api/mockApi'
import type { AuditEntry } from '../types'

export default function Audit() {
  const [entries, setEntries] = useState<AuditEntry[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [source, setSource] = useState<'live' | 'mock'>('mock')
  const [verified, setVerified] = useState<boolean | null>(null)
  const [verifySource, setVerifySource] = useState<'live' | 'mock' | null>(null)

  const load = async () => {
    setLoading(true)
    const res = await api.getAudit()
    setEntries(res.data)
    setSource(res.source)
    setError(res.error || null)
    setVerified(null); setVerifySource(null)
    setLoading(false)
  }
  useEffect(() => { void load() }, [])
  const verify = async () => { const res = await api.verifyAuditChain(); setVerified(res.data); setVerifySource(res.source) }

  return (
    <section className="screen">
      <h1>Audit</h1>
      <p className="subtitle">Hash-chained audit log from GET /v1/audit when available (envelope-wrapped events, chain_verified). Hash fields may be hex strings or byte arrays.</p>
      <div className="panel filters" aria-label="Audit chain verification">
        <button className="btn" type="button" onClick={() => void load()} disabled={loading}>Refresh</button>
        <span className={`badge ${source === 'live' ? 'healthy' : 'info'}`}>{source}</span>
        <button className="btn" type="button" onClick={() => void verify()} aria-label="Verify audit hash chain">Verify chain</button>
        {verified !== null && <span className={`badge ${verified ? 'approved' : 'denied'}`} role="status">{verified ? 'chain valid' : 'chain broken'}{verifySource ? ` (${verifySource})` : ''}</span>}
        {error && <span className="muted"><span className="badge warn">gateway</span> {error}</span>}
      </div>
      <div className="panel">
        {loading ? <p className="muted">Loading audit log…</p> : entries.length === 0 ? <p className="muted">No audit entries.</p> : (
          <table aria-label="Audit log entries">
            <caption className="sr-only">Audit log with hash chain fields</caption>
            <thead><tr><th scope="col">seq</th><th scope="col">ts</th><th scope="col">task_id</th><th scope="col">tool/event</th><th scope="col">decision</th><th scope="col">reason/detail</th><th scope="col">args/result digest</th><th scope="col">prev_hash</th><th scope="col">hash</th></tr></thead>
            <tbody>
              {entries.map(e => (
                <tr key={e.id}>
                  <td className="mono">{e.api?.seq ?? e.seq}</td>
                  <td className="muted mono">{e.api?.ts ?? e.time}</td>
                  <td className="mono">{e.api?.task_id ?? '—'}</td>
                  <td><strong>{e.api?.tool ?? e.event}</strong><div className="muted small">{e.source} · <span className={`badge ${e.severity}`}>{e.severity}</span></div></td>
                  <td><span className={`badge ${e.api?.decision === 'permit' ? 'allowed' : e.api?.decision === 'require-approval' ? 'warn' : e.api?.decision === 'error' || e.api?.decision === 'fail' ? 'fail' : 'info'}`}>{e.api?.decision ?? '—'}</span></td>
                  <td>{e.api?.reason ?? e.detail}</td>
                  <td className="mono muted small"><div>a: {e.api?.args_digest || '—'}</div><div>r: {e.api?.result_digest || '—'}</div></td>
                  <td className="muted mono">{e.prevHash}</td><td className="mono">{e.hash}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </section>
  )
}

