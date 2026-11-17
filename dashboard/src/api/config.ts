const raw = (import.meta.env.VITE_API_BASE_URL ?? '').trim()
export const API_BASE_URL = raw.replace(/\/$/, '')
export const API_TOKEN = (import.meta.env.VITE_API_TOKEN ?? '').trim()
export const STREAM_PATH = (import.meta.env.VITE_STREAM_PATH ?? '/v1/stream').trim() || '/v1/stream'
export const API_TIMEOUT_MS = Number(import.meta.env.VITE_API_TIMEOUT_MS ?? 10000) || 10000

export const apiUrl = (path: string) => `${API_BASE_URL}${path.startsWith('/') ? path : `/${path}`}`
export const isApiConfigured = () => API_BASE_URL.length > 0

