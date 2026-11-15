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

// ---- Details tab (mirrors ui_collector._render_details) ----

export type BlockKind = 'caption' | 'text' | 'warning' | 'info' | 'heading'
export interface Block {
  kind: BlockKind
  text: string
}
export type Cell = string | number | boolean | null
export interface Table {
  columns: string[]
  rows: Cell[][]
}
export interface Metric {
  label: string
  value: number | string
}

export interface DetailsOk {
  state: 'ok'
  revision: string
  guide: string
  captions: string[]
  metrics: Metric[]
  notices: Block[]
  review_summary: { metrics: Metric[]; captions: string[] }
  identity_warning: string | null
  connections: Table & {
    total: number
    more: string | null
    empty: string
    groups: { group: number; label: string }[]
    timeline_missing: string | null
  }
  attempts: (Table & { title: string; notices: Block[]; empty: string }) | null
  dns: {
    title: string
    missing?: string
    empty_window?: string
    metrics?: Metric[]
    captions?: string[]
    notices_before?: Block[]
    notices?: Block[]
    observations_label?: string
    columns?: string[]
    rows?: Cell[][]
    total?: number
    empty?: string
    more?: string | null
    footer?: string
    investigation?: {
      title: string
      missing: string | null
      devices: { value: string; label: string }[]
      domains: { group: number; device: string; target: string }[]
    } | null
  }
  downloads: {
    full: { generated_at: string; caption: string; label: string } | null
    snapshot: { label: string; file: string }
    caption: string
  }
}
export type DetailsResponse = DetailsOk | { state: 'not_configured' | 'no_snapshot' | 'unreadable' }

export interface DetailsOptions {
  local_ips: boolean
  reviews_only: boolean
  include_expected: boolean
  dns_observations: boolean
}

export interface Timeline {
  revision: string
  group: number
  guidance: Block[]
  notices: Block[]
  chart?: { kind: 'line' | 'bar'; x_title: string; y_title: string; points: { t: string; v: number }[] }
  table?: Table
  footer?: string
}

const flags = (options: Record<string, boolean>) =>
  Object.entries(options)
    .map(([name, value]) => `${name}=${value}`)
    .join('&')

export const fetchDetails = (lang: Language, options: DetailsOptions) =>
  request<DetailsResponse>(`/api/details?lang=${lang}&${flags({ ...options })}`)

export const fetchTimeline = (kind: 'connection' | 'dns', lang: Language, group: number, localIps: boolean) =>
  request<Timeline>(`/api/details/${kind}-timeline?lang=${lang}&group=${group}&local_ips=${localIps}`)
