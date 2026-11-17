import { useEffect, useState } from 'react'
import { api } from '../api/mockApi'
import type { Policy } from '../types'

export default function Policies() {
  const [policy, setPolicy] = useState<Policy | null>(null)
  const [draft, setDraft] = useState('')
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [status, setStatus] = useState('loading')
  const [error, setError] = useState<string | null>(null)
  const [source, setSource] = useState<'live' | 'mock'>('mock')

  const load = async () => {
    setLoading(true)
    const res = await api.getPolicy()
    setPolicy(res.data)
    setDraft(res.data.draft || '')
    setSource(res.source)
    setError(res.error || null)
    setStatus(res.error ? 'loaded with fallback' : 'loaded')
    setLoading(false)
  }
  useEffect(() => { void load() }, [])

  const ruleCount = (draft.match(/- id:/g) || []).length
  const save = async () => {
    setSaving(true)
    const res = await api.savePolicy(draft)
    setPolicy(res.data)
    setDraft(res.data.draft)
    setSource(res.source)
    setError(res.error || null)
    setStatus(res.source === 'live' ? 'saved to gateway' : (res.error ? `save failed, kept local: ${res.error}` : 'saved (mock)'))
    setSaving(false)
  }
  const reset = async () => { const res = await api.resetPolicy(); setPolicy(res.data); setDraft(res.data.draft); setSource(res.source); setStatus('reset to mock baseline') }

  return (
    <section className="screen">
      <h1>Policies</h1>
      <p className="subtitle">Policy editor mapped to admin API shape (id, version, body, created_at, active)</p>
      <div className="panel filters">
        <button className="btn" type="button" onClick={() => void load()} disabled={loading || saving}>Refresh</button>
        <span className={`badge ${source === 'live' ? 'healthy' : 'info'}`}>{source}</span>
        {error && <span className="muted"><span className="badge warn">gateway</span> {error}</span>}
      </div>
      <div className="panel">
        <h2>Active policy draft</h2>
        {loading ? <p className="muted">Loading policy…</p> : (
          <>
            <label htmlFor="policy-editor"><strong>Policy body (YAML/Cedar source)</strong></label>
            <textarea id="policy-editor" className="editor" value={draft} onChange={(e) => { setDraft(e.target.value); setStatus('unsaved changes') }} spellCheck={false} aria-describedby="policy-help" />
            <div id="policy-help" className="muted small">Loads active policy from GET /v1/policies and saves via POST /v1/policies when gateway is available; falls back to local mock on error.</div>
            <div className="actions" style={{ marginTop: 8 }}>
              <button className="btn approve" type="button" onClick={() => void save()} disabled={saving}>{saving ? 'Saving…' : 'Save draft'}</button>
              <button className="btn" type="button" onClick={() => void reset()} disabled={saving}>Reset mock</button>
              <span className="muted">Status: <strong>{status}</strong></span>
            </div>
          </>
        )}
      </div>
      <div className="panel">
        <h2>API-aligned summary</h2>
        <table aria-label="Policy metadata"><tbody>
          <tr><th scope="row">id</th><td className="mono">{policy?.id ?? '—'}</td></tr>
          <tr><th scope="row">version</th><td>{policy?.version ?? 0}</td></tr>
          <tr><th scope="row">active</th><td>{String(policy?.active ?? false)}</td></tr>
          <tr><th scope="row">created_at</th><td className="mono">{policy?.createdAt ?? '—'}</td></tr>
          <tr><th scope="row">rule count (approx)</th><td>{ruleCount}</td></tr>
          <tr><th scope="row">source</th><td><span className={`badge ${source === 'live' ? 'healthy' : 'info'}`}>{source}</span></td></tr>
        </tbody></table>
      </div>
    </section>
  )
}

