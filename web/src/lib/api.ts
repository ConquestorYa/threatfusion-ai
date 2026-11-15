// Typed calls to the loopback FastAPI backend. Same origin only: in development
// Vite forwards /api to 127.0.0.1:8600; in production FastAPI serves this page.

export type Language = 'en' | 'tr'
export type Mark = 'known' | 'unsure' | 'suspicious'

export interface ReviewItem {
  key: string
  kind: 'connection' | 'dns' | 'attempt'
  threat: boolean
  title: string
  label: string
  metric: string
  devices: string[]
  destination: { host: string; port: number | string | null } | null
  owner: string | null
  when: string | null
  what: string[]
  advice: string
  facts: string[]
  links: { name: string; url: string }[]
  mark: Mark | null
}

export interface KnownItem {
  key: string
  title: string
  label: string
}

export type ReviewResponse =
  | { state: 'not_configured' | 'no_snapshot' | 'unreadable' }
  | {
      state: 'ok'
      updated_at: string
      window_hours: number
      stale: boolean
      coverage_incomplete: boolean
      counts: { to_check: number; suspicious: number; threat: number; known: number }
      items: ReviewItem[]
      items_truncated: boolean
      known: KnownItem[]
    }

export class ApiError extends Error {
  readonly status: number

  constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, { credentials: 'same-origin', ...init })
  if (!response.ok) {
    let detail = response.statusText
    try {
      const body = (await response.json()) as { detail?: unknown }
      if (typeof body.detail === 'string') detail = body.detail
    } catch {
      // Not JSON; keep the status text.
    }
    throw new ApiError(response.status, detail)
  }
  return (response.status === 204 ? undefined : await response.json()) as T
}

export const fetchReview = (lang: Language) =>
  request<ReviewResponse>(`/api/review?lang=${lang}`)

export const fetchStrings = (lang: Language) =>
  request<Record<string, string>>(`/api/i18n?lang=${lang}`)

export const saveMark = (key: string, mark: Mark | null) =>
  request<void>('/api/review/marks', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ key, mark }),
  })

export const fetchAppInfo = () => request<{ streamlit_url: string }>('/api/app')
