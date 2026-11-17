import { useEffect, useState } from 'react'
import { api } from '../api/mockApi'
import type { Upstream } from '../types'

export default function Upstreams() {
  const [upstreams, setUpstreams] = useState<Upstream[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [source, setSource] = useState<'live' | 'mock'>('mock')

  const load = async () => {
    setLoading(true)
    const res = await api.getUpstreams()
    setUpstreams(res.data)
    setSource(res.source)
    setError(res.error || null)
    setLoading(false)
  }
  useEffect(() => { void load() }, [])

  return (
    <section className="screen">
      <h1>Upstreams</h1>
      <p className="subtitle">Connected MCP services from GET /v1/upstreams when available (id/name/transport/target/secret_ref/enabled)</p>
      <div className="panel filters">
        <button className="btn" type="button" onClick={() => void load()} disabled={loading}>Refresh</button>
        <span className={`badge ${source === 'live' ? 'healthy' : 'info'}`}>{source}</span>
        {error && <span className="muted"><span className="badge warn">gateway</span> {error}</span>}
      </div>
      <div className="panel">
        {loading ? <p className="muted">Loading upstreams…</p> : upstreams.length === 0 ? <p className="muted">No upstreams.</p> : (
          <table aria-label="Upstream services">
            <caption className="sr-only">Upstream MCP servers, transport, secret references, and health</caption>
            <thead><tr><th scope="col">ID</th><th scope="col">Name</th><th scope="col">Transport</th><th scope="col">Target</th><th scope="col">Secret ref</th><th scope="col">Enabled</th><th scope="col">Health</th><th scope="col">Latency</th><th scope="col">Note</th></tr></thead>
            <tbody>
              {upstreams.map(u => (
                <tr key={u.id}>
                  <td className="mono">{u.api?.id ?? u.id}</td>
                  <td><strong>{u.name}</strong></td>
                  <td className="mono">{u.transport}</td>
                  <td className="muted mono">{u.api?.target ?? u.endpoint}</td>
                  <td className="mono muted">{u.api?.secret_ref ?? u.secretRef}</td>
                  <td><span className={`badge ${u.enabled ? 'healthy' : 'blocked'}`}>{String(u.enabled)}</span></td>
                  <td><span className={`badge ${u.status}`}>{u.status}</span></td>
                  <td>{u.latencyMs ? `${u.latencyMs} ms` : '—'}<div className="muted small">{u.lastCheck}</div></td>
                  <td>{u.note}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </section>
  )
}

