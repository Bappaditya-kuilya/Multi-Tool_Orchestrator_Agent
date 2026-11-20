import { useEffect, useState } from 'react'
import { api } from '../api/mockApi'
import { isApiConfigured } from '../api/config'
import type { StreamEvent } from '../types'

function pretty(v: unknown) {
  if (typeof v === 'string') return v
  try { return JSON.stringify(v, null, 2) } catch { return String(v) }
}

export default function Ops() {
  const [loading, setLoading] = useState(true)
  const [health, setHealth] = useState<unknown>(null)
  const [ready, setReady] = useState<unknown>(null)
  const [metrics, setMetrics] = useState('')
  const [source, setSource] = useState<'live' | 'mock'>('mock')
  const [error, setError] = useState<string | null>(null)
  const [mcpStatus, setMcpStatus] = useState<string>('idle')
  const [mcpResult, setMcpResult] = useState<string>('')

  const load = async () => {
    setLoading(true)
    const res = await api.getOps()
    setHealth(res.data.health)
    setReady(res.data.ready)
    setMetrics(res.data.metrics)
    setSource(res.source)
    setError(res.error || null)
    setLoading(false)
  }
  useEffect(() => { void load() }, [])

  const probeMcp = async () => {
    if (!isApiConfigured()) { setMcpStatus('mock/unavailable'); setMcpResult('API base URL not configured'); return }
    setMcpStatus('probing…')
    try {
      const init = await api.client.mcp('initialize', {})
      const tools = await api.client.mcp('tools/list', {})
      const innerInit = typeof init?.payload_json === 'string' ? init.payload_json : JSON.stringify(init?.body ?? init)
      const innerTools = typeof tools?.payload_json === 'string' ? tools.payload_json : JSON.stringify(tools?.body ?? tools)
      setMcpStatus(init?.ok === false || init?.fail_closed ? 'fail-closed/error' : 'ok')
      setMcpResult(`initialize: ${innerInit}\n\ntools/list: ${innerTools}`)
    } catch (e) {
      setMcpStatus('error')
      setMcpResult(e instanceof Error ? e.message : String(e))
    }
  }

  const streamNote: StreamEvent = { type: 'ops', id: 'ops', ts: '', summary: 'SSE stream panel is shown in sidebar (GET /v1/stream, event gateway).' }

  return (
    <section className="screen">
      <h1>Ops / MCP</h1>
      <p className="subtitle">Gateway ops endpoints (healthz, readyz, metrics) and MCP probe against current API. Stream shown in sidebar.</p>
      <div className="panel filters">
        <button className="btn" type="button" onClick={() => void load()} disabled={loading}>Refresh ops</button>
        <span className={`badge ${source === 'live' ? 'healthy' : 'info'}`}>{source}</span>
        {error && <span className="muted"><span className="badge warn">gateway</span> {error}</span>}
      </div>
      <div className="grid" style={{ marginBottom: 16 }}>
        <div className="panel"><h2>/healthz</h2>{loading ? <p className="muted">Loading…</p> : <pre className="mono small" style={{ whiteSpace: 'pre-wrap', margin: 0 }}>{pretty(health)}</pre>}</div>
        <div className="panel"><h2>/readyz</h2>{loading ? <p className="muted">Loading…</p> : <pre className="mono small" style={{ whiteSpace: 'pre-wrap', margin: 0 }}>{pretty(ready)}</pre>}</div>
      </div>
      <div className="panel">
        <h2>/metrics (Prometheus text)</h2>
        {loading ? <p className="muted">Loading…</p> : metrics ? <pre className="mono small" style={{ whiteSpace: 'pre-wrap', maxHeight: 260, overflow: 'auto', margin: 0 }}>{metrics}</pre> : <p className="muted">No metrics body.</p>}
      </div>
      <div className="panel">
        <h2>MCP probe (/mcp)</h2>
        <p className="muted small">Sends JSON-RPC initialize + tools/list via gateway MCP dispatch (policy/availability dependent, fail-closed on denial/unavailable upstream contexts).</p>
        <div className="actions" style={{ marginBottom: 8 }}>
          <button className="btn" type="button" onClick={() => void probeMcp()}>Probe MCP</button>
          <span className={`badge ${mcpStatus === 'ok' ? 'healthy' : mcpStatus === 'idle' || mcpStatus === 'probing…' ? 'info' : 'warn'}`}>{mcpStatus}</span>
        </div>
        {mcpResult && <pre className="mono small" style={{ whiteSpace: 'pre-wrap', margin: 0 }}>{mcpResult}</pre>}
        {!mcpResult && <p className="muted small">No probe yet. {streamNote.summary}</p>}
      </div>
    </section>
  )
}
