import { useEffect, useState } from 'react'
import { api } from '../api/mockApi'

type Scenario = { id: string; tool: string; taskId: string; args: string; decision: string; reason: string; policy: string }

export default function DryRun() {
  const [rows, setRows] = useState<Scenario[]>([])
  const [loading, setLoading] = useState(true)
  const [source, setSource] = useState<'live' | 'mock'>('mock')
  useEffect(() => { (async () => { const res = await api.getDryRunScenarios(); setRows(res.data); setSource(res.source); setLoading(false) })() }, [])
  const counts = rows.reduce((a, r) => ({ ...a, [r.decision]: (a[r.decision] || 0) + 1 }), {} as Record<string, number>)
  return (
    <section className="screen">
      <h1>Dry Run</h1>
      <p className="subtitle">Mock/preview simulated policy decisions (UI scaffold only; no gateway dry-run API endpoint). Shows example outcomes without blocking. Mode: <span className="badge info">dry-run</span> <span className={`badge ${source === 'live' ? 'healthy' : 'info'}`}>{source}</span></p>
      {loading ? <div className="panel"><p className="muted">Loading scenarios…</p></div> : (
        <>
          <div className="grid" style={{ marginBottom: 16 }}>
            {['permit', 'require-approval', 'forbid', 'warn'].map(k => (
              <div key={k} className="stat"><div className="label">Would {k}</div><div className="value">{counts[k] || 0}</div><div className="muted">scenarios</div></div>
            ))}
          </div>
          <div className="panel">
            <h2>Simulated calls</h2>
            {rows.length === 0 ? <p className="muted">No scenarios.</p> : (
              <table aria-label="Dry-run simulated policy decisions">
                <caption className="sr-only">Dry-run scenarios showing what policy would decide without enforcing</caption>
                <thead><tr><th scope="col">ID</th><th scope="col">Task</th><th scope="col">Tool</th><th scope="col">Args</th><th scope="col">Would decide</th><th scope="col">Reason</th><th scope="col">Policy</th></tr></thead>
                <tbody>
                  {rows.map(r => (
                    <tr key={r.id}>
                      <td className="mono">{r.id}</td><td className="mono">{r.taskId}</td><td>{r.tool}</td><td className="mono">{r.args}</td>
                      <td><span className={`badge ${r.decision === 'permit' ? 'allowed' : r.decision === 'forbid' ? 'blocked' : r.decision === 'require-approval' ? 'warn' : 'info'}`}>{r.decision}</span></td>
                      <td>{r.reason}</td><td className="muted mono">{r.policy}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
          <div className="panel">
            <h2>How to read</h2>
            <ul>
              <li>Dry-run uses same policy shapes as enforcement but returns decisions without side effects.</li>
              <li><strong>forbid</strong> = would block; <strong>require-approval</strong> = would pause for approval.</li>
              <li>Wire to admin API dry-run endpoint when available; this view uses mock scenarios.</li>
            </ul>
          </div>
        </>
      )}
    </section>
  )
}

