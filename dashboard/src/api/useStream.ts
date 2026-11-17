import { useEffect, useRef, useState } from 'react'
import { client } from './client'
import { isApiConfigured } from './config'
import { mockStreamEvents } from './mockData'
import type { StreamEvent } from '../types'

export type StreamStatus = 'connecting' | 'open' | 'error' | 'fallback'

function normalize(ev: MessageEvent): StreamEvent {
  try {
    const parsed = JSON.parse(ev.data) as any
    const kind = String(parsed?.kind ?? parsed?.type ?? (ev as any).type ?? 'event')
    const type = kind.includes('approval') ? 'approval' : kind.includes('task') ? 'task' : kind.includes('upstream') ? 'upstream' : kind.includes('audit') ? 'audit' : kind
    const ts = String(parsed?.ts ?? parsed?.time ?? parsed?.created_at ?? new Date().toISOString())
    return {
      type,
      id: String(parsed?.id ?? parsed?.seq ?? parsed?.event_id ?? parsed?.task_id ?? Date.now()),
      ts,
      summary: String(parsed?.summary ?? parsed?.message ?? parsed?.detail ?? parsed?.reason ?? ev.data),
      kind,
      message: parsed?.message,
      task_id: parsed?.task_id ?? null,
    }
  } catch {
    const txt = String(ev.data || 'event')
    if (txt === 'keepalive') return { type: 'keepalive', id: String(Date.now()), ts: new Date().toISOString(), summary: 'keepalive' }
    return { type: 'audit', id: String(Date.now()), ts: new Date().toISOString(), summary: txt }
  }
}

export function useStream(enabled = true) {
  const [events, setEvents] = useState<StreamEvent[]>([])
  const [status, setStatus] = useState<StreamStatus>('connecting')
  const [error, setError] = useState<string | null>(null)
  const [source, setSource] = useState<'live' | 'mock'>('live')
  const esRef = useRef<EventSource | null>(null)
  const retryRef = useRef(0)
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  useEffect(() => {
    if (!enabled) return
    let cancelled = false
    const loadFallback = async (msg?: string) => {
      if (cancelled) return
      try { esRef.current?.close() } catch {}
      try {
        const data = await mockStreamEvents()
        if (cancelled) return
        setEvents(prev => prev.length ? prev : data)
      } catch {}
      if (cancelled) return
      setStatus('fallback')
      setSource('mock')
      setError(msg || 'using mock stream')
    }

    const connect = () => {
      if (cancelled) return
      const url = client.streamUrl()
      if (!isApiConfigured() || !url || typeof EventSource === 'undefined') { void loadFallback(isApiConfigured() ? 'EventSource unavailable' : 'API base URL not configured'); return }
      try {
        setStatus('connecting')
        const es = new EventSource(url)
        esRef.current = es
        const onEvent = (ev: MessageEvent) => {
          if (cancelled) return
          const n = normalize(ev)
          if (n.type === 'keepalive') return
          setEvents(prev => [n, ...prev].slice(0, 50))
        }
        es.onopen = () => { if (cancelled) return; retryRef.current = 0; setStatus('open'); setSource('live'); setError(null) }
        es.onmessage = onEvent
        es.addEventListener('gateway', onEvent as EventListener)
        es.onerror = () => {
          if (cancelled) return
          try { es.close() } catch {}
          const attempt = (retryRef.current += 1)
          if (attempt > 3) { void loadFallback('stream unavailable, using mock events'); return }
          setStatus('error')
          setError(`stream disconnected (retry ${attempt}/3)`)
          timerRef.current = setTimeout(connect, Math.min(1000 * attempt, 4000))
        }
      } catch (e) {
        void loadFallback(e instanceof Error ? e.message : 'stream error')
      }
    }

    connect()
    return () => {
      cancelled = true
      try { esRef.current?.close() } catch {}
      if (timerRef.current) clearTimeout(timerRef.current)
    }
  }, [enabled])

  return { events, status, error, source }
}

