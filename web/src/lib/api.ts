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

export interface AppInfo {
  streamlit_url: string
  setup_available: boolean
  first_setup: boolean
  /** Same rule as Streamlit: hidden in CTI-only mode without the on-device behavior model. */
  evaluation_available: boolean
  /** AppConfig.history_enabled: a trusted model, not CTI-only, not public. */
  history_available: boolean
}
export const fetchAppInfo = () => request<AppInfo>('/api/app')

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
  /** "Behavior on this computer (experimental ML)"; null without a local behavior model. */
  behavior: { title: string; cards: BehaviorCard[]; empty: string | null } | null
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
  application: { title: string; caption: string; stop: string; stopping: string; not_running: string }
  demo_note?: string
  keys?: {
    title: string
    caption: string
    saved: string
    missing: string | null
    fields: { name: 'threatfox' | 'urlhaus'; label: string }[]
    apply: string
    applied: string
    invalid: string
    forget: string
  }
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
export const saveKeys = (keys: { threatfox: string; urlhaus: string }) => request<void>('/api/setup/keys', put(keys))
export const forgetKeys = () => request<void>('/api/setup/keys/forget', json({}))
export const stopApplication = () => request<{ stopping: boolean }>('/api/app/stop', json({}))

// ---- Analyze telemetry (mirrors streamlit_app "Analyze telemetry") ----

export interface AnalyzeStatus {
  ready: boolean
  notices: Block[]
  intake?: string
  format_label?: string
  formats?: { value: string; label: string; caption: string; required: string; upload: string; types: string[]; help: string }[]
  requirements_title?: string
  requirements_note?: string
  privacy?: string
  analyze?: string
  max_bytes?: number
  too_large?: string
  empty_title?: string
  empty_text?: string
}

export interface AnalysisOverview {
  id: string
  file: string
  input_quality_title: string
  input_quality: string[]
  priority_title: string
  priority_caption: string
  priority: { domain: string; verdict: string; verdict_label: string; events: number; sources: string; evidence: string }[]
  priority_more: string | null
  priority_empty: string
  distribution_title: string
  overview_title: string
  metrics: { label: string; value: number; tone: 'threat' | 'high' | 'review' | 'low' | null }[]
  metrics_caption: string
  tabs: Record<'findings' | 'devices' | 'connections' | 'investigation' | 'ioc' | 'related' | 'export', string>
  findings: Table & {
    verdicts: string[]
    sources: string[][]
    domains: string[]
    search_label: string
    search_placeholder: string
    verdict_label: string
    source_label: string
    all: string
    verdict_options: { value: string; label: string }[]
    empty_title: string
    empty_text: string
  }
  ioc: {
    corroboration_title: string
    corroboration_caption: string
    corroboration: Table | null
    matches_title: string
    matches: Table | null
    empty: string
  }
  related: {
    notices: Block[]
    clusters_title?: string
    clusters?: Table
    relationships_title?: string
    relationships?: Table
    relationships_caption?: string
  }
  investigation: { label: string; domains: string[]; empty_title: string; empty_text: string }
  export: { include_ips_label: string; json: string; csv: string; caption: string; save: string | null }
  /** "Include N locally suppressed finding(s)"; null when nothing is suppressed. */
  suppressed_label: string | null
}

export interface DomainDetail {
  title: string
  domain: string
  verdict: string
  verdict_label: string
  why_title: string
  why: string[]
  why_empty: string
  known_note: string | null
  primary: { title: string; summary: string; metrics: Metric[]; all_title: string; all: Table } | null
  no_evidence: string
  context_title: string
  context: Metric[]
  behavior_title: string
  behavior: string[]
  /** History-only local analyst policy (previous review, suppression); null without history. */
  policy: AnalystPolicy | null
}

export interface AnalysisDevices extends Table {
  captions: string[]
  include_ips_label: string | null
  include_observe_label: string
  empty: string
  footer: string
  more: string | null
  investigation: {
    title: string
    missing: string | null
    devices: { value: string; label: string }[]
    domains: { group: number; device: string; target: string }[]
  } | null
  download: string
  download_caption: string
}

export interface AnalysisConnections extends Partial<Table> {
  captions: string[]
  missing?: string
  include_ips_label?: string | null
  reviews_only_label?: string
  summary?: { metrics: Metric[]; captions: string[] }
  empty?: string
  more?: string | null
  investigation_title?: string
  select_label?: string
  groups?: { group: number; label: string }[]
  attempts?: (Table & { title: string; notices: Block[]; empty: string }) | null
  download?: string
  download_caption?: string
}

export class UploadError extends Error {}

export const fetchAnalyzeStatus = (lang: Language) => request<AnalyzeStatus>(`/api/analyze/status?lang=${lang}`)

export async function uploadTelemetry(lang: Language, format: string, file: File): Promise<AnalysisOverview> {
  const query = new URLSearchParams({ format, name: file.name, lang })
  return request<AnalysisOverview>(`/api/analyze?${query}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/octet-stream' },
    body: file,
  })
}

export const fetchAnalysis = (id: string, lang: Language, includeSuppressed = false) =>
  request<AnalysisOverview>(`/api/analyze/${id}?lang=${lang}&include_suppressed=${includeSuppressed}`)
export const fetchDomainDetail = (id: string, lang: Language, name: string) =>
  request<DomainDetail>(`/api/analyze/${id}/domain?${new URLSearchParams({ name, lang })}`)
export const fetchAnalysisDevices = (id: string, lang: Language, includeIps: boolean, includeObserve: boolean) =>
  request<AnalysisDevices>(`/api/analyze/${id}/devices?lang=${lang}&include_ips=${includeIps}&include_observe=${includeObserve}`)
export const fetchAnalysisConnections = (id: string, lang: Language, includeIps: boolean, reviewsOnly: boolean) =>
  request<AnalysisConnections>(`/api/analyze/${id}/connections?lang=${lang}&include_ips=${includeIps}&reviews_only=${reviewsOnly}`)
export const fetchAnalysisTimeline = (id: string, kind: 'device' | 'connection', lang: Language, group: number) =>
  request<Timeline>(`/api/analyze/${id}/${kind}-timeline?lang=${lang}&group=${group}`)

// ---- Experimental ML (mirrors ui_new_destinations + ui_behavior) ----

export interface BehaviorCard {
  key: string
  kind: 'ml' | 'new'
  title: string
  mark: Mark | null
  /** Mark shown on the card; a site marked suspicious elsewhere also shows here. */
  shown_mark: Mark | null
  device: string
  destination: string
  owner: string | null
  others: string | null
  score_label: string
  score: string
  level: string | null
  why_label: string
  why: string[]
  rhythm: { caption: string; times: number[] } | null
  advice_title: string
  advice: string
  command: string
  links_caption: string
  links: { name: string; url: string }[]
}

export interface BehaviorNotice {
  kind: 'info' | 'success'
  text: string
}

export interface BehaviorOk {
  state: 'ok'
  caption: string
  new: {
    state: 'no_data' | 'unreadable' | 'ok'
    title: string
    empty?: string
    warning?: string
    summary?: string | null
    notice: BehaviorNotice | null
    cards: BehaviorCard[]
    captions: string[]
    guide_title: string
    guide: string
  }
  model: {
    state: 'learning' | 'unreadable' | 'ok'
    title: string
    captions?: string[]
    warning?: string
    heading?: string
    summary?: string
    metrics?: (Metric & { help?: string })[]
    cards?: BehaviorCard[]
    below?: (Table & { title: string }) | null
    guide_title?: string
    guide?: string
    model_caption?: string
  }
}

export type BehaviorResponse = BehaviorOk | { state: 'not_configured' }

export const fetchBehavior = (lang: Language) => request<BehaviorResponse>(`/api/behavior?lang=${lang}`)
export const saveBehaviorMark = (key: string, mark: Mark | null) =>
  request<void>('/api/behavior/marks', put({ key, mark }))

// ---- Model evaluation (mirrors ui_behavior.render_behavior_evaluation / ui_evaluation) ----

export type BehaviorEvaluation =
  | { kind: 'behavior'; state: 'unreadable'; warning: string }
  | {
      kind: 'behavior'
      state: 'ok'
      title: string
      caption: string
      metrics: Metric[]
      verdict: { kind: 'success' | 'warning'; text: string } | null
      declared: (Table & { title: string }) | null
      data: Table
      importance: (Table & { title: string; bars: { label: string; value: number }[] }) | null
      limits_title: string
      limits: string
      guide_title: string
      guide: string
    }

interface LexicalBase {
  kind: 'lexical'
  guide_title: string
  guide: string
  guide_open: boolean
}
export type LexicalEvaluation = LexicalBase &
  (
    | { state: 'not_evaluated'; title: string; text: string; caption: string; command_title: string; command: string }
    | { state: 'unreadable'; error: string; caption: string }
    | {
        state: 'ok'
        loaded: string
        model: string
        artifact: string
        scope: string
        dates: string
        metrics: Metric[]
        operating_title: string
        operating: Table
        chart: { title: string; series: string[]; groups: { label: string; values: number[] }[] }
        sources: (Table & { title: string; caption: string }) | null
        ppv: string
        protocol: string[]
      }
  )

export type EvaluationResponse =
  | { state: 'hidden' }
  | { state: 'ok'; subtitle: string; report: BehaviorEvaluation | LexicalEvaluation }

export const fetchEvaluation = (lang: Language) => request<EvaluationResponse>(`/api/evaluation?lang=${lang}`)

// ---- Analysis history (mirrors ui_history._show_history) ----

export interface AnalystPolicy {
  previous: string | null
  suppressed: string | null
  title: string
  remove: string
  suppress_title: string
  reason_label: string
  expiry_label: string
  save: string
  saved: string
}

export type FeedbackLabel = 'Confirmed Threat' | 'Benign' | 'Uncertain'
export interface Choice {
  value: string
  label: string
}

export interface HistoryOk {
  state: 'ok'
  subtitle: string
  runs: Table
  all_runs_title: string
  all_runs: Table
  run_label: string
  run_ids: number[]
  run: number
  metadata_title: string
  metadata:
    | { legacy: string }
    | {
        captured: string
        artifact: string
        checksum: string
        schemas: string
        thresholds: string | null
        sources: (Table & { title: string }) | null
        no_sources: string | null
      }
  comparison: {
    title: string
    caption: string
    metrics: Metric[]
    new: (Table & { title: string }) | null
    removed: (Table & { title: string }) | null
    changes: (Table & { title: string }) | null
  }
  findings: Table & {
    domains: string[]
    verdicts: string[]
    feedback: string[]
    sources: string[][]
    verdict_label: string
    verdict_options: Choice[]
    review_label: string
    review_options: Choice[]
    source_label: string
    source_options: Choice[]
    empty: string
  }
  review: {
    title: string
    caption: string
    options: Choice[]
    current: Record<string, { label: string; note: string }>
    bulk_title: string
    bulk_domains_label: string
    bulk_label: string
    bulk_note_label: string
    bulk_confirm: string
    bulk_button: string
    domain_label: string
    label: string
    note_label: string
    button: string
    saved: string
    bulk_saved: string
  }
  retention: {
    title: string
    warning: string
    delete_confirm: string
    delete_button: string
    deleted: string
    keep_label: string
    keep_default: number
    keep_confirm: string
    keep_button: string
    kept_none: string
  }
}

export type HistoryResponse = HistoryOk | { state: 'disabled' } | { state: 'empty'; subtitle: string; title: string; text: string }

export const fetchHistory = (lang: Language, run: number | null) =>
  request<HistoryResponse>(`/api/history?lang=${lang}${run === null ? '' : `&run=${run}`}`)
export const saveFeedback = (run: number, body: { domain: string; label: FeedbackLabel; note: string }) =>
  request<void>(`/api/history/${run}/feedback`, put(body))
export const saveBulkFeedback = (run: number, body: { domains: string[]; label: FeedbackLabel; note: string }) =>
  request<{ count: number }>(`/api/history/${run}/feedback/bulk`, put({ ...body, confirm: true }))
export const deleteRun = (run: number) => request<{ deleted: boolean }>(`/api/history/${run}/delete`, json({ confirm: true }))
export const applyRetention = (lang: Language, keep_latest: number) =>
  request<{ message: string }>(`/api/history/retention?lang=${lang}`, json({ keep_latest, confirm: true }))
export const saveAnalysis = (id: string, lang: Language) =>
  request<{ message: string }>(`/api/analyze/${id}/save?lang=${lang}`, json({}))
export const suppressDomain = (domain: string, reason: string, expiry_days: number) =>
  request<void>('/api/analyze/suppression', put({ domain, reason, expiry_days }))
export const unsuppressDomain = (domain: string) => request<void>('/api/analyze/suppression/remove', json({ domain }))
