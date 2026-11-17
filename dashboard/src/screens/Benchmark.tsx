import { useEffect, useState } from 'react'
import { api } from '../api/mockApi'
import type { Benchmark } from '../types'

function Spark({ values }: { values: number[] }) {
  const max = Math.max(...values, 1)
  return <div className="spark" aria-label={`trend ${values.join(', ')}`}>{values.map((v, i) => <span key={i} title={`${v}`} style={{ height: `${Math.max(10, (v / max) * 100)}%` }} />)}</div>
}

export default function Benchmark() {
  const [runs, setRuns] = useState<Benchmark[]>([])
  const [loading, setLoading] = useState(true)
  const [source, setSource] = useState<'live' | 'mock'>('mock')
  const [error, setError] = useState<string | null>(null)
  useEffect(() => { (async () => { const res = await api.getBenchmarks(); setRuns(res.data); setSource(res.source); setError(res.error || null); setLoading(false) })() }, [])
  const pass = runs.filter(r => r.status === 'pass').length
  const warn = runs.filter(r => r.status === 'warn').length
  return (
    <section className="screen">
      <h1>Benchmark</h1>
      <p className="subtitle">Latest run vs baseline, with dry-run outcome counts and chart placeholders <span className={`badge ${source === 'live' ? 'healthy' : 'info'}`}>{source}</span></p>
      {error && <div className="panel"><span className="muted"><span className="badge info">note</span> {error} (using mock benchmark data)</span></div>}
      {loading ? <div className="panel"><p className="muted">Loading benchmarks…</p></div> : (
        <>
          <div className="grid" style={{ marginBottom: 16 }}>
            <div className="stat"><div className="label">Overall</div><div className="value">{pass >= 4 ? 'B+' : 'B'}</div><div className="muted">{pass} pass · {warn} warn</div></div>
            <div className="stat"><div className="label">Run ID</div><div className="value">bench-77</div><div className="muted">2026-11-17 09:00 (mock)</div></div>
            <div className="stat"><div className="label">Suite</div><div className="value">core-v2</div><div className="muted">{runs.length} scenarios</div></div>
          </div>
          <div className="panel">
            <h2>Metrics table</h2>
            <table aria-label="Benchmark metrics compared to baseline">
              <caption className="sr-only">Benchmark scores, baselines, status, trend and dry-run counts</caption>
              <thead><tr><th scope="col">Metric</th><th scope="col">Score</th><th scope="col">Baseline</th><th scope="col">Status</th><th scope="col">Dry-run (block/allow/approve)</th><th scope="col">Relative</th><th scope="col">Trend</th></tr></thead>
              <tbody>
                {runs.map(r => {
                  const pct = Math.min(100, Math.max(5, (r.score / (r.baseline * 1.5)) * 100))
                  return (
                    <tr key={r.name}>
                      <td><strong>{r.name}</strong></td><td>{r.score} {r.unit}</td><td className="muted">{r.baseline} {r.unit}</td>
                      <td><span className={`badge ${r.status}`}>{r.status}</span></td>
                      <td className="mono small">{r.dryRun ? `${r.dryRun.wouldBlock}/${r.dryRun.wouldAllow}/${r.dryRun.wouldApprove}` : '—'}</td>
                      <td style={{ minWidth: 120 }}><div className="bar" aria-label={`${Math.round(pct)} percent relative`}><span style={{ width: `${pct}%` }} /></div></td>
                      <td style={{ minWidth: 120 }}><Spark values={r.history} /></td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
          <div className="panel">
            <h2>Views</h2>
            <div className="grid">
              <div><h3 className="small-h">Chart placeholder</h3><div className="chart-placeholder">Trend/compare chart area (wire to real chart lib later)</div></div>
              <div><h3 className="small-h">Dry-run comparison</h3><ul>
                <li>Dry-run counts show would-block/allow/approve per benchmark scenario group (mock).</li>
                <li>Use to compare policy strictness against baseline before enforcing.</li>
                <li>See dedicated <strong>Dry Run</strong> screen for call-level simulations.</li>
              </ul></div>
            </div>
          </div>
        </>
      )}
      <div className="panel a11y-note" aria-label="Accessibility notes">
        <h2>Accessibility basics (notes)</h2>
        <ul>
          <li>Labels/landmarks: skip link, nav <code>aria-label</code>, main landmark, table captions/scope, form labels.</li>
          <li>Focus: visible <code>:focus-visible</code> outlines on interactive controls.</li>
          <li>Contrast: text/badges tuned for dark-on-light readability; status not color-only (text + badge label). Verify WCAG AA in real theme pass.</li>
          <li>Live updates: SSE stream uses <code>aria-live="polite"</code>; production stream should announce meaningful changes.</li>
        </ul>
      </div>
    </section>
  )
}

