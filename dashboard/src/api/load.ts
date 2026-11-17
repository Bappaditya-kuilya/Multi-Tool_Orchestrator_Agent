export type LoadState<T> =
  | { status: 'loading'; data?: T; source?: 'live' | 'mock'; error?: string }
  | { status: 'ready'; data: T; source: 'live' | 'mock'; error?: string }
  | { status: 'error'; data?: T; source?: 'live' | 'mock'; error: string }

export const loading = <T>(prev?: T): LoadState<T> => ({ status: 'loading', data: prev })
export const ready = <T>(data: T, source: 'live' | 'mock' = 'live', error?: string): LoadState<T> => ({ status: 'ready', data, source, error })
export const failed = <T>(error: string, data?: T, source?: 'live' | 'mock'): LoadState<T> => ({ status: 'error', error, data, source })
