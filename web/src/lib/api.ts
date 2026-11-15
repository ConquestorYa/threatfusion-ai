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

export const fetchAppInfo = () =>
  request<{ streamlit_url: string; setup_available: boolean; first_setup: boolean }>('/api/app')

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

// ---- Quick lookup (mirrors ui_quick_lookup.render_quick_lookup_result) ----

export type Tone = 'safe' | 'review' | 'danger' | 'critical' | 'info' | 'neutral' | 'low'
export interface Notice {
  kind: 'warning' | 'info' | 'error' | 'caption'
  text: string
}
export interface LookupStatus {
  ready: boolean
  notices: Notice[]
  label?: string
  placeholder?: string
  button?: string
  caption?: string
  empty_input?: string
}
export interface SignalNode {
  tone: Tone
  label: string
  value: string
  sub: string
}
export interface AgeBlock extends SignalNode {
  caption: string | null
}
export interface LookupResult {
  error?: string
  notices: Notice[]
  banner: { tone: Tone; icon: string; kicker: string; title: string; summary: string; target: string; meta: [string, string][] }
  overview_title: string
  ml_card: {
    tone: Tone
    level: string
    subtitle: string
    score: number
    kicker: string
    scale: string[] | null
    explanation: string
    note: string
  } | null
  console: SignalNode[]
  console_caption: string
  reasons_title: string
  reasons: string[]
  registry:
    | { kind: 'owner'; title: string; owner: { label: string; value: string; sub: string } | null; unknown: string }
    | { kind: 'age'; title: string; domain: string | null; unavailable: string | null; button: string; caption: string | null; result: AgeBlock | null }
    | null
  links_title: string
  links_caption: string
  links: { name: string; url: string }[]
  evidence_title: string
  evidence_state: { tone: Tone; heading: string; copy: string }
  evidence: Table
  technical: { title: string; caption: string; metrics: Metric[] }
  footer: string
}

const json = (body: unknown): RequestInit => ({
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(body),
})

export const fetchLookupStatus = (lang: Language) => request<LookupStatus>(`/api/lookup/status?lang=${lang}`)
export const runLookup = (lang: Language, value: string) => request<LookupResult>(`/api/lookup?lang=${lang}`, json({ value }))
export const checkDomainAge = (lang: Language, domain: string) =>
  request<AgeBlock>(`/api/lookup/domain-age?lang=${lang}`, json({ domain }))

// ---- Setup & CTI updates (mirrors ui_local_settings.render_local_settings) ----

export interface SetupOk {
  state: 'ok'
  caption: string
  mode: { title: string; value: 'cti-only' | 'demo'; options: { value: 'cti-only' | 'demo'; label: string }[] }
  application: { title: string; caption: string }
  demo_note?: string
  keys?: { title: string; caption: string; saved: string; missing: string | null }
  cti?: {
    title: string
    running: boolean
    force_label: string
    force_help: string
    button: string
    busy: string
    started: string
    due: string | null
    progress: { percent: number; label: string; caption: string } | null
    summary: { kind: 'success' | 'info' | 'warning'; text: string; finished_at: string } | null
    status: Block[]
  }
  schedule?: {
    title: string
    automatic: boolean
    automatic_label: string
    interval_hours: number
    interval_label: string
    options: number[]
    caption: string
    button: string
  }
  sources?: (Table & { title: string; caption: string }) | null
}
export type SetupResponse = SetupOk | { state: 'not_managed' | 'unreadable' }

const put = (body: unknown): RequestInit => ({ ...json(body), method: 'PUT' })

export const fetchSetup = (lang: Language) => request<SetupResponse>(`/api/setup?lang=${lang}`)
export const saveMode = (mode: 'cti-only' | 'demo') => request<void>('/api/setup/mode', put({ mode }))
export const saveSchedule = (automatic: boolean, interval_hours: number) =>
  request<void>('/api/setup/schedule', put({ automatic, interval_hours }))
export const startRefresh = (force: boolean) => request<{ started: boolean }>('/api/setup/refresh', json({ force }))
