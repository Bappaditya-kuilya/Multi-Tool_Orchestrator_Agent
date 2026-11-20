import { useState } from 'react'
import Timeline from './screens/Timeline'
import TaskTree from './screens/TaskTree'
import Approvals from './screens/Approvals'
import Policies from './screens/Policies'
import Upstreams from './screens/Upstreams'
import Audit from './screens/Audit'
import Benchmark from './screens/Benchmark'
import DryRun from './screens/DryRun'
import Ops from './screens/Ops'
import { API_BASE_URL, isApiConfigured, STREAM_PATH, useStream } from './api'

const screens = [
  { id: 'timeline', label: 'Timeline', component: Timeline },
  { id: 'task-tree', label: 'Task Tree', component: TaskTree },
  { id: 'approvals', label: 'Approvals', component: Approvals },
  { id: 'policies', label: 'Policies', component: Policies },
  { id: 'upstreams', label: 'Upstreams', component: Upstreams },
  { id: 'audit', label: 'Audit', component: Audit },
  { id: 'ops', label: 'Ops/MCP', component: Ops },
  { id: 'benchmark', label: 'Benchmark', component: Benchmark },
  { id: 'dry-run', label: 'Dry Run', component: DryRun },
] as const

function StreamPanel() {
  const { events, status, error, source } = useStream(true)
  const badge = status === 'open' ? 'healthy' : status === 'fallback' ? 'info' : status === 'connecting' ? 'warn' : 'denied'
  const label = status === 'fallback' ? 'mock-fallback' : status
  return (
    <aside className="panel stream" aria-label="Gateway event stream">
      <div className="stream-head">
        <strong>GET {STREAM_PATH} (SSE)</strong>
        <span className={`badge ${badge}`}>{label}</span>
      </div>
      <p className="muted small">Connects to real gateway SSE when configured (event: <code>gateway</code>); retries with backoff on disconnect, then falls back to mock events.</p>
      <p className="muted small">Source: <strong>{source}</strong></p>
      {error && <p className="muted small" role="status">Stream: {error}</p>}
      {events.length === 0 ? <p className="muted small">No events yet.</p> : (
        <ul className="stream-list" aria-live="polite">
          {events.map((e, i) => <li key={String(e.type) + String(e.id) + String(e.ts) + i}><span className="muted mono">{e.ts}</span> <span className="badge info">{e.type}</span> {e.summary}{e.task_id ? <span className="muted"> · task {e.task_id}</span> : null} <span className="muted">({e.id})</span></li>)}
        </ul>
      )}
    </aside>
  )
}

export default function App() {
  const [active, setActive] = useState<(typeof screens)[number]['id']>('timeline')
  const ActiveScreen = screens.find((s) => s.id === active)?.component ?? Timeline
  const configured = isApiConfigured()

  return (
    <div className="app">
      <a href="#main-content" className="skip-link">Skip to content</a>
      <header className="topbar">
        <div>
          <div className="brand">ScopeGate Dashboard</div>
          <div className="muted small">Admin API (/v1/tasks, approvals, audit, policies, upstreams) · SSE stream · env-driven config with mock fallback</div>
          <div className="muted small">API base: <code>{configured ? API_BASE_URL : '(not set, using mock data)'}</code></div>
        </div>
      </header>
      <nav className="nav" aria-label="Primary screens">
        {screens.map((screen) => (
          <button
            key={screen.id}
            className={screen.id === active ? 'active' : ''}
            onClick={() => setActive(screen.id)}
            type="button"
            aria-current={screen.id === active ? 'page' : undefined}
          >
            {screen.label}
          </button>
        ))}
      </nav>
      <div className="layout">
        <main id="main-content" className="content" tabIndex={-1}>
          <ActiveScreen />
        </main>
        <div className="side"><StreamPanel /></div>
      </div>
    </div>
  )
}

