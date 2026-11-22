import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { ChevronDown, Download, FileUp, Lock } from 'lucide-react'
import { useId, useMemo, useRef, useState, type ChangeEvent, type ReactNode } from 'react'

import { Blocks, MetricStrip, Notice } from '@/components/data/Blocks'
import { Check, Select, TimelineView, useSelection } from '@/components/data/Controls'
import { DataTable } from '@/components/data/DataTable'
import { Button } from '@/components/ui/button'
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import {
  fetchAnalysis,
  fetchAnalysisConnections,
  fetchAnalysisDevices,
  fetchAnalysisTimeline,
  fetchAnalyzeStatus,
  fetchDomainDetail,
  saveAnalysis,
  suppressDomain,
  unsuppressDomain,
  uploadTelemetry,
  type AnalysisOverview,
  type AnalystPolicy,
  type AnalyzeStatus,
} from '@/lib/api'
import { usePreferences } from '@/lib/preferences'
import { cn } from 'cn'

// The last analysis survives switching screens, like Streamlit's session state.
// The file itself never leaves this computer: it goes only to the local API.
let lastAnalysis: string | null = null

const VERDICT_RAIL: Record<string, string> = {
  'Known Threat': 'bg-threat',
  'High Risk': 'bg-threat/70',
  Review: 'bg-review',
  Low: 'bg-border',
}

export function Analyze() {
  const { lang, t, chrome } = usePreferences()
  const status = useQuery({ queryKey: ['analyze-status', lang], queryFn: () => fetchAnalyzeStatus(lang) })
  const [analysisId, setAnalysisId] = useState<string | null>(lastAnalysis)
  // Streamlit: locally suppressed priority findings stay hidden unless this is ticked.
  const [includeSuppressed, setIncludeSuppressed] = useState(false)
  const overview = useQuery({
    queryKey: ['analysis', analysisId, lang, includeSuppressed],
    queryFn: () => fetchAnalysis(analysisId!, lang, includeSuppressed),
    enabled: analysisId !== null,
    placeholderData: keepPreviousData,
    retry: false,
  })
  const heading = <h1 className="text-lg font-semibold tracking-tight">{t('Analyze telemetry')}</h1>

  if (status.isPending) {
    return (
      <>
        {heading}
        <p className="py-12 text-muted-foreground">{chrome('loading')}</p>
      </>
    )
  }
  if (status.isError) {
    return (
      <>
        {heading}
        <Notice tone="warn">{chrome('offline')}</Notice>
      </>
    )
  }
  const info = status.data
  return (
    <div className="space-y-4">
      <div className="space-y-1">
        {heading}
        <p className="text-xs text-muted-foreground">{info.intake}</p>
      </div>
      <Blocks blocks={info.notices} />
      {info.ready && (
        <Intake
          info={info}
          onAnalyzed={(result) => {
            lastAnalysis = result.id
            setAnalysisId(result.id)
          }}
        />
      )}
      {overview.isError && <Notice tone="warn">{overview.error.message}</Notice>}
      {overview.data ? (
        <Result data={overview.data} includeSuppressed={includeSuppressed} onIncludeSuppressed={setIncludeSuppressed} />
      ) : (
        <div className="rounded-sm border border-dashed px-4 py-8 text-center">
          <p className="font-medium">{info.empty_title}</p>
          <p className="text-xs text-muted-foreground">{info.empty_text}</p>
        </div>
      )}
    </div>
  )
}

function Intake({ info, onAnalyzed }: { info: AnalyzeStatus; onAnalyzed: (r: AnalysisOverview) => void }) {
  const { lang, chrome } = usePreferences()
  const fileId = useId()
  const input = useRef<HTMLInputElement>(null)
  const formats = info.formats ?? []
  const [format, setFormat] = useState(formats[0]?.value ?? 'Auto-detect')
  const [file, setFile] = useState<File | null>(null)
  const [tooLarge, setTooLarge] = useState(false)
  const run = useMutation({
    mutationFn: (selected: File) => uploadTelemetry(lang, format, selected),
    onSuccess: onAnalyzed,
  })
  const choose = (event: ChangeEvent<HTMLInputElement>) => {
    const selected = event.target.files?.[0] ?? null
    run.reset()
    setTooLarge(Boolean(selected && info.max_bytes && selected.size > info.max_bytes))
    setFile(selected)
  }
  const spec = formats.find((item) => item.value === format) ?? formats[0]
  if (!spec) return null
  const changeFormat = (value: string) => {
    setFormat(value)
    setFile(null)
    setTooLarge(false)
    run.reset()
    if (input.current) input.current.value = ''
  }
  return (
    <section aria-label={spec.upload} className="space-y-3 rounded-sm border bg-card p-3">
      <div className="grid gap-3 md:grid-cols-[minmax(0,16rem)_minmax(0,1fr)]">
        <Select
          label={info.format_label ?? ''}
          value={format}
          options={formats.map((item) => ({ value: item.value, label: item.label }))}
          onChange={changeFormat}
        />
        <div className="flex flex-col gap-1">
          <label htmlFor={fileId} className="text-xs text-muted-foreground">
            {spec.upload}
          </label>
          {/* The native file button shows the browser's own language; ours follows the page. */}
          <div className="flex min-w-0 items-center gap-2 rounded-sm border bg-background p-1">
            <Button type="button" variant="secondary" size="sm" onClick={() => input.current?.click()}>
              <FileUp aria-hidden /> {chrome('chooseFile')}
            </Button>
            <span className="min-w-0 truncate font-mono text-xs text-muted-foreground" aria-live="polite">
              {file ? file.name : chrome('noFile')}
            </span>
          </div>
          <input
            id={fileId}
            ref={input}
            type="file"
            accept={spec.types.map((type) => `.${type}`).join(',')}
            onChange={choose}
            title={spec.help}
            className="sr-only"
          />
        </div>
      </div>
      <p className="text-xs text-muted-foreground">{spec.caption}</p>
      <Collapsible>
        <CollapsibleTrigger className="group flex items-center gap-1.5 text-xs font-medium text-muted-foreground hover:text-foreground">
          <ChevronDown aria-hidden className="size-3.5 transition-transform group-data-[state=open]:rotate-180" />
          {info.requirements_title}
        </CollapsibleTrigger>
        <CollapsibleContent className="space-y-1 pt-1.5 pl-5 text-xs">
          <p>{spec.required}</p>
          <p className="text-muted-foreground">{info.requirements_note}</p>
          <p className="text-muted-foreground">{spec.help}</p>
        </CollapsibleContent>
      </Collapsible>
      <p className="flex items-start gap-1.5 text-xs text-muted-foreground">
        <Lock aria-hidden className="mt-0.5 size-3.5 shrink-0" />
        <span>
          {info.privacy} {chrome('fileStaysLocal')}
        </span>
      </p>
      {tooLarge && <Notice tone="warn">{info.too_large}</Notice>}
      <Button disabled={!file || tooLarge || run.isPending} onClick={() => file && run.mutate(file)}>
        {run.isPending ? chrome('analyzing') : info.analyze}
      </Button>
      {run.isError && <Notice tone="warn">{run.error.message}</Notice>}
    </section>
  )
}

function Result({
  data,
  includeSuppressed,
  onIncludeSuppressed,
}: {
  data: AnalysisOverview
  includeSuppressed: boolean
  onIncludeSuppressed: (value: boolean) => void
}) {
  const max = Math.max(1, ...data.metrics.slice(2).map((metric) => metric.value))
  return (
    <div className="space-y-4">
      <Collapsible className="rounded-sm border bg-card">
        <CollapsibleTrigger className="group flex w-full items-center gap-2 px-3 py-2 text-left text-[13px] font-medium focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none">
          <ChevronDown aria-hidden className="size-4 transition-transform group-data-[state=open]:rotate-180" />
          {data.input_quality_title} · <span className="font-mono text-xs text-muted-foreground">{data.file}</span>
        </CollapsibleTrigger>
        <CollapsibleContent className="space-y-1 border-t px-3 py-2">
          {data.input_quality.map((line) => (
            <p key={line} className="text-xs text-muted-foreground">
              {line}
            </p>
          ))}
        </CollapsibleContent>
      </Collapsible>

      <div className="grid gap-4 lg:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]">
        <section aria-label={data.priority_title} className="space-y-2">
          <h2 className="text-base font-semibold tracking-tight">{data.priority_title}</h2>
          <p className="text-xs text-muted-foreground">{data.priority_caption}</p>
          {data.suppressed_label && <Check label={data.suppressed_label} checked={includeSuppressed} onChange={onIncludeSuppressed} />}
          {data.priority.length ? (
            <ul className="divide-y overflow-hidden rounded-sm border bg-card">
              {data.priority.map((row) => (
                <li key={row.domain} className="relative py-2 pr-3 pl-4">
                  <span aria-hidden className={cn('absolute inset-y-0 left-0 w-1', VERDICT_RAIL[row.verdict] ?? 'bg-border')} />
                  <div className="flex flex-wrap items-baseline justify-between gap-x-3">
                    <span className="font-semibold break-all">{row.domain}</span>
                    <span className={cn('text-xs font-semibold', row.verdict === 'Known Threat' ? 'text-threat' : 'text-review')}>
                      {row.verdict_label}
                    </span>
                  </div>
                  <p className="text-xs text-muted-foreground">
                    {row.events} · {row.sources}
                  </p>
                  <p className="text-[13px]">{row.evidence}</p>
                </li>
              ))}
            </ul>
          ) : (
            <Notice tone="info">{data.priority_empty}</Notice>
          )}
          {data.priority_more && <p className="text-xs text-muted-foreground">{data.priority_more}</p>}
        </section>
        <section aria-label={data.distribution_title} className="space-y-2">
          <h2 className="text-base font-semibold tracking-tight">{data.distribution_title}</h2>
          <ul className="space-y-1.5 rounded-sm border bg-card p-3">
            {data.metrics.slice(2).map((metric) => (
              <li
                key={metric.label}
                data-verdict={metric.tone ?? 'low'}
                className="grid grid-cols-[7rem_minmax(0,1fr)_2.5rem] items-center gap-2 text-xs"
              >
                <span className="text-muted-foreground">{metric.label}</span>
                <span className="h-2 overflow-hidden rounded-sm bg-muted">
                  <span
                    className={cn(
                      'block h-full',
                      metric.tone === 'threat' ? 'bg-threat' : metric.tone === 'high' ? 'bg-threat/70' : metric.tone === 'review' ? 'bg-review' : 'bg-chart-series',
                    )}
                    style={{ width: `${(metric.value / max) * 100}%` }}
                  />
                </span>
                <span className="text-right font-semibold tabular-nums">{metric.value}</span>
              </li>
            ))}
          </ul>
        </section>
      </div>

      <section aria-label={data.overview_title} className="space-y-1.5">
        <h2 className="text-base font-semibold tracking-tight">{data.overview_title}</h2>
        <MetricStrip metrics={data.metrics} />
        <p className="text-xs text-muted-foreground">{data.metrics_caption}</p>
      </section>

      <Tabs defaultValue="findings" className="gap-3">
        <TabsList className="h-auto w-full justify-start overflow-x-auto">
          {(Object.keys(data.tabs) as (keyof AnalysisOverview['tabs'])[]).map((key) => (
            <TabsTrigger key={key} value={key} className="flex-none text-xs">
              {data.tabs[key]}
            </TabsTrigger>
          ))}
        </TabsList>
        <TabsContent value="findings">
          <Findings data={data} />
        </TabsContent>
        <TabsContent value="devices">
          <Devices id={data.id} />
        </TabsContent>
        <TabsContent value="connections">
          <Connections id={data.id} />
        </TabsContent>
        <TabsContent value="investigation">
          <Investigation data={data} />
        </TabsContent>
        <TabsContent value="ioc">
          <Ioc data={data} />
        </TabsContent>
        <TabsContent value="related">
          <Related data={data} />
        </TabsContent>
        <TabsContent value="export">
          <Export data={data} />
        </TabsContent>
      </Tabs>
    </div>
  )
}

function Findings({ data }: { data: AnalysisOverview }) {
  const { chrome } = usePreferences()
  const searchId = useId()
  const findings = data.findings
  const [query, setQuery] = useState('')
  const [verdict, setVerdict] = useState('All')
  const [source, setSource] = useState('All')
  const sources = useMemo(() => [...new Set(findings.sources.flat())].sort(), [findings.sources])
  // ui_components.filter_findings: literal search, original order kept.
  const rows = findings.rows.filter((_, index) => {
    const needle = query.trim().toLowerCase()
    return (
      (!needle || findings.domains[index].toLowerCase().includes(needle)) &&
      (verdict === 'All' || findings.verdicts[index] === verdict) &&
      (source === 'All' || findings.sources[index].includes(source))
    )
  })
  if (!findings.rows.length) {
    return (
      <Notice tone="info">
        <strong>{findings.empty_title}</strong> {findings.empty_text}
      </Notice>
    )
  }
  return (
    <div className="space-y-2">
      <div className="grid gap-2 sm:grid-cols-[minmax(0,2fr)_minmax(0,1fr)_minmax(0,1fr)]">
        <div className="flex flex-col gap-1">
          <label htmlFor={searchId} className="text-xs text-muted-foreground">
            {findings.search_label}
          </label>
          <input
            id={searchId}
            value={query}
            placeholder={findings.search_placeholder}
            onChange={(event) => setQuery(event.target.value)}
            className="h-9 rounded-sm border bg-card px-2 text-[13px] focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
          />
        </div>
        <Select
          label={findings.verdict_label}
          value={verdict}
          options={[{ value: 'All', label: findings.all }, ...findings.verdict_options]}
          onChange={setVerdict}
        />
        <Select
          label={findings.source_label}
          value={source}
          options={[{ value: 'All', label: findings.all }, ...sources.map((item) => ({ value: item, label: item }))]}
          onChange={setSource}
        />
      </div>
      <DataTable table={{ columns: findings.columns, rows }} label={`${data.tabs.findings} · ${chrome('table')}`} />
    </div>
  )
}

function Devices({ id }: { id: string }) {
  const { lang, t, chrome } = usePreferences()
  const [includeIps, setIncludeIps] = useState(false)
  const [includeObserve, setIncludeObserve] = useState(false)
  const devices = useQuery({
    queryKey: ['analysis-devices', id, lang, includeIps, includeObserve],
    queryFn: () => fetchAnalysisDevices(id, lang, includeIps, includeObserve),
    placeholderData: keepPreviousData,
  })
  const investigation = devices.data?.investigation
  const deviceValues = investigation?.devices.map((d) => d.value) ?? []
  const revision = `${id}:${includeIps}:${includeObserve}`
  const [device, setDevice] = useSelection(revision, deviceValues)
  const domains = (investigation?.domains ?? []).filter((d) => d.device === device)
  const [group, setGroup] = useSelection(`${revision}:${device}`, domains.map((d) => d.group))
  if (!devices.data) return <p className="text-xs text-muted-foreground">{chrome('loading')}</p>
  const data = devices.data
  return (
    <div className="space-y-2.5">
      {data.captions.map((caption) => (
        <p key={caption} className="text-xs text-muted-foreground">
          {caption}
        </p>
      ))}
      <div className="flex flex-wrap gap-x-5">
        {data.include_ips_label && <Check label={data.include_ips_label} checked={includeIps} onChange={setIncludeIps} />}
        <Check label={data.include_observe_label} checked={includeObserve} onChange={setIncludeObserve} />
      </div>
      {data.rows.length ? (
        <DataTable table={data} label={`${chrome('deviceTriage')} · ${chrome('table')}`} />
      ) : (
        <Notice tone="info">{data.empty}</Notice>
      )}
      <p className="text-xs text-muted-foreground">{data.footer}</p>
      {data.more && <p className="text-xs text-muted-foreground">{data.more}</p>}
      {investigation && device !== null && group !== null && !investigation.missing && (
        <div className="space-y-2.5 pt-1">
          <h3 className="text-[13px] font-semibold">{investigation.title}</h3>
          <div className="grid gap-3 sm:grid-cols-2">
            <Select label={t('Select an observed device')}
                      mono value={device} options={investigation.devices} onChange={setDevice} />
            <Select
              label={t('Select a queried domain')}
                      mono
              value={String(group)}
              options={domains.map((d) => ({ value: String(d.group), label: d.target }))}
              onChange={(value) => setGroup(Number(value))}
            />
          </div>
          <TimelineView
            queryKey={['analysis-timeline', 'device', id, lang, group, revision]}
            load={() => fetchAnalysisTimeline(id, 'device', lang, group)}
          />
        </div>
      )}
      <DownloadLink href={`/api/analyze/${id}/download/devices?include_ips=${includeIps}`} label={data.download} />
      <p className="text-xs text-muted-foreground">{data.download_caption}</p>
    </div>
  )
}

function Connections({ id }: { id: string }) {
  const { lang, chrome } = usePreferences()
  const [includeIps, setIncludeIps] = useState(false)
  const [reviewsOnly, setReviewsOnly] = useState(true)
  const connections = useQuery({
    queryKey: ['analysis-connections', id, lang, includeIps, reviewsOnly],
    queryFn: () => fetchAnalysisConnections(id, lang, includeIps, reviewsOnly),
    placeholderData: keepPreviousData,
  })
  const revision = `${id}:${includeIps}:${reviewsOnly}`
  const [group, setGroup] = useSelection(revision, (connections.data?.groups ?? []).map((g) => g.group))
  if (!connections.data) return <p className="text-xs text-muted-foreground">{chrome('loading')}</p>
  const data = connections.data
  return (
    <div className="space-y-2.5">
      {data.captions.map((caption) => (
        <p key={caption} className="text-xs text-muted-foreground">
          {caption}
        </p>
      ))}
      {data.missing ? (
        <Notice tone="info">{data.missing}</Notice>
      ) : (
        <>
          {data.include_ips_label && <Check label={data.include_ips_label} checked={includeIps} onChange={setIncludeIps} />}
          {data.summary && <MetricStrip metrics={data.summary.metrics} />}
          {data.summary?.captions.map((caption) => (
            <p key={caption} className="text-xs text-muted-foreground">
              {caption}
            </p>
          ))}
          <Check label={data.reviews_only_label ?? ''} checked={reviewsOnly} onChange={setReviewsOnly} />
          {data.rows && data.rows.length ? (
            <DataTable table={{ columns: data.columns ?? [], rows: data.rows }} label={`${chrome('connectionActivity')} · ${chrome('table')}`} />
          ) : (
            <Notice tone="info">{data.empty}</Notice>
          )}
          {data.more && <p className="text-xs text-muted-foreground">{data.more}</p>}
          {group !== null && (
            <div className="space-y-2.5 pt-1">
              <h3 className="text-[13px] font-semibold">{data.investigation_title}</h3>
              <Select
                label={data.select_label ?? ''}
                mono
                value={String(group)}
                options={(data.groups ?? []).map((g) => ({ value: String(g.group), label: g.label }))}
                onChange={(value) => setGroup(Number(value))}
              />
              <TimelineView
                queryKey={['analysis-timeline', 'connection', id, lang, group, revision]}
                load={() => fetchAnalysisTimeline(id, 'connection', lang, group)}
              />
            </div>
          )}
          {data.attempts && (
            <div className="space-y-2 pt-1">
              <h3 className="text-[13px] font-semibold">{data.attempts.title}</h3>
              <Blocks blocks={data.attempts.notices} />
              {data.attempts.rows.length ? (
                <DataTable table={data.attempts} label={`${data.attempts.title} · ${chrome('table')}`} />
              ) : (
                <Notice tone="info">{data.attempts.empty}</Notice>
              )}
            </div>
          )}
          <DownloadLink href={`/api/analyze/${id}/download/connections?include_ips=${includeIps}`} label={data.download ?? ''} />
          <p className="text-xs text-muted-foreground">{data.download_caption}</p>
        </>
      )}
    </div>
  )
}

function Investigation({ data }: { data: AnalysisOverview }) {
  const { lang, chrome } = usePreferences()
  const domains = data.investigation.domains
  const [domain, setDomain] = useSelection(data.id, domains)
  const detail = useQuery({
    queryKey: ['analysis-domain', data.id, lang, domain],
    queryFn: () => fetchDomainDetail(data.id, lang, domain!),
    enabled: domain !== null,
    placeholderData: keepPreviousData,
  })
  if (!domains.length || domain === null) {
    return (
      <Notice tone="info">
        <strong>{data.investigation.empty_title}</strong> {data.investigation.empty_text}
      </Notice>
    )
  }
  const d = detail.data
  return (
    <div className="space-y-3">
      <Select mono label={data.investigation.label} value={domain} options={domains.map((name) => ({ value: name, label: name }))} onChange={setDomain} />
      {!d ? (
        <p className="text-xs text-muted-foreground">{chrome('loading')}</p>
      ) : (
        <section aria-label={d.title} className="relative space-y-3 overflow-hidden rounded-sm border bg-card p-3 pl-4">
          <span aria-hidden className={cn('absolute inset-y-0 left-0 w-1', VERDICT_RAIL[d.verdict] ?? 'bg-border')} />
          <div className="flex flex-wrap items-baseline justify-between gap-2">
            <div>
              <p className="text-xs text-muted-foreground">{d.title}</p>
              <p className="font-mono text-base font-semibold break-all">{d.domain}</p>
            </div>
            <span className={cn('text-sm font-semibold', d.verdict === 'Known Threat' ? 'text-threat' : 'text-review')}>{d.verdict_label}</span>
          </div>
          {d.policy?.previous && <Notice tone="info">{d.policy.previous}</Notice>}
          {d.policy?.suppressed && <Notice tone="warn">{d.policy.suppressed}</Notice>}
          <Part title={d.why_title}>
            {d.why.length ? (
              <ul className="list-disc space-y-0.5 pl-5 text-[13px]">
                {d.why.map((item) => (
                  <li key={item}>{item}</li>
                ))}
              </ul>
            ) : (
              <p className="text-xs text-muted-foreground">{d.why_empty}</p>
            )}
            {d.known_note && <p className="text-xs text-muted-foreground">{d.known_note}</p>}
          </Part>
          {d.primary ? (
            <Part title={d.primary.title}>
              <p className="text-[13px]">{d.primary.summary}</p>
              <MetricStrip metrics={d.primary.metrics} />
              <Collapsible>
                <CollapsibleTrigger className="group flex items-center gap-1.5 text-xs font-medium text-muted-foreground hover:text-foreground">
                  <ChevronDown aria-hidden className="size-3.5 transition-transform group-data-[state=open]:rotate-180" />
                  {d.primary.all_title}
                </CollapsibleTrigger>
                <CollapsibleContent className="pt-2">
                  <DataTable table={d.primary.all} label={`${d.primary.title} · ${chrome('table')}`} maxHeight="max-h-72" />
                </CollapsibleContent>
              </Collapsible>
            </Part>
          ) : (
            <p className="text-xs text-muted-foreground">{d.no_evidence}</p>
          )}
          <Part title={d.context_title}>
            <MetricStrip metrics={d.context} />
            <Collapsible>
              <CollapsibleTrigger className="group flex items-center gap-1.5 text-xs font-medium text-muted-foreground hover:text-foreground">
                <ChevronDown aria-hidden className="size-3.5 transition-transform group-data-[state=open]:rotate-180" />
                {d.behavior_title}
              </CollapsibleTrigger>
              <CollapsibleContent className="space-y-0.5 pt-1.5 pl-5">
                {d.behavior.map((line) => (
                  <p key={line} className="text-xs text-muted-foreground">
                    {line}
                  </p>
                ))}
              </CollapsibleContent>
            </Collapsible>
          </Part>
          {d.policy && <Policy policy={d.policy} domain={d.domain} />}
        </section>
      )}
    </div>
  )
}

/** ui_investigation "Local analyst policy": suppress from priority triage, or remove the suppression. */
function Policy({ policy, domain }: { policy: AnalystPolicy; domain: string }) {
  const queryClient = useQueryClient()
  const reasonId = useId()
  const expiryId = useId()
  const [reason, setReason] = useState('')
  const [days, setDays] = useState(0)
  const [saved, setSaved] = useState(false)
  const refresh = () => {
    queryClient.invalidateQueries({ queryKey: ['analysis'] })
    queryClient.invalidateQueries({ queryKey: ['analysis-domain'] })
  }
  const save = useMutation({
    mutationFn: () => suppressDomain(domain, reason, days),
    onSuccess: () => {
      setSaved(true)
      setReason('')
      refresh()
    },
  })
  const remove = useMutation({ mutationFn: () => unsuppressDomain(domain), onSuccess: refresh })
  return (
    <Part title={policy.title}>
      {policy.suppressed ? (
        <Button variant="outline" size="sm" disabled={remove.isPending} onClick={() => remove.mutate()}>
          {policy.remove}
        </Button>
      ) : (
        <Collapsible className="rounded-sm border">
          <CollapsibleTrigger className="group flex min-h-11 w-full items-center gap-2 px-3 py-2 text-left text-[13px] font-medium focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none lg:min-h-0">
            <ChevronDown aria-hidden className="size-4 transition-transform group-data-[state=open]:rotate-180" />
            {policy.suppress_title}
          </CollapsibleTrigger>
          <CollapsibleContent className="border-t p-3">
            <form
              className="grid gap-2 sm:grid-cols-[minmax(0,1fr)_12rem_auto] sm:items-end"
              onSubmit={(event) => {
                event.preventDefault()
                save.mutate()
              }}
            >
              <label htmlFor={reasonId} className="flex flex-col gap-1 text-xs text-muted-foreground">
                {policy.reason_label}
                <input
                  id={reasonId}
                  value={reason}
                  maxLength={300}
                  onChange={(event) => setReason(event.target.value)}
                  className="h-9 rounded-sm border bg-card px-2 text-[13px] text-foreground focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
                />
              </label>
              <label htmlFor={expiryId} className="flex flex-col gap-1 text-xs text-muted-foreground">
                {policy.expiry_label}
                <input
                  id={expiryId}
                  type="number"
                  min={0}
                  max={3650}
                  value={days}
                  onChange={(event) => setDays(Math.max(0, Math.min(3650, Number(event.target.value) || 0)))}
                  className="h-9 rounded-sm border bg-card px-2 text-[13px] text-foreground tabular-nums focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
                />
              </label>
              <Button type="submit" size="sm" className="h-9" disabled={save.isPending || !reason.trim()}>
                {policy.save}
              </Button>
            </form>
            {save.isError && <Notice tone="warn">{save.error.message}</Notice>}
          </CollapsibleContent>
        </Collapsible>
      )}
      {saved && !policy.suppressed && <p className="text-xs text-muted-foreground">{policy.saved}</p>}
    </Part>
  )
}

function Part({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div className="space-y-1.5">
      <h3 className="text-[13px] font-semibold">{title}</h3>
      {children}
    </div>
  )
}

function Ioc({ data }: { data: AnalysisOverview }) {
  const { chrome } = usePreferences()
  const ioc = data.ioc
  return (
    <div className="space-y-3">
      {ioc.corroboration && (
        <Part title={ioc.corroboration_title}>
          <p className="text-xs text-muted-foreground">{ioc.corroboration_caption}</p>
          <DataTable table={ioc.corroboration} label={`${ioc.corroboration_title} · ${chrome('table')}`} />
        </Part>
      )}
      {ioc.matches ? (
        <Part title={ioc.matches_title}>
          <DataTable table={ioc.matches} label={`${ioc.matches_title} · ${chrome('table')}`} />
        </Part>
      ) : (
        <Notice tone="info">{ioc.empty}</Notice>
      )}
    </div>
  )
}

function Related({ data }: { data: AnalysisOverview }) {
  const { chrome } = usePreferences()
  const related = data.related
  return (
    <div className="space-y-3">
      <Blocks blocks={related.notices} />
      {related.clusters && (
        <Part title={related.clusters_title ?? ''}>
          <DataTable table={related.clusters} label={`${related.clusters_title} · ${chrome('table')}`} />
        </Part>
      )}
      {related.relationships && (
        <Collapsible>
          <CollapsibleTrigger className="group flex items-center gap-1.5 text-xs font-medium text-muted-foreground hover:text-foreground">
            <ChevronDown aria-hidden className="size-3.5 transition-transform group-data-[state=open]:rotate-180" />
            {related.relationships_title}
          </CollapsibleTrigger>
          <CollapsibleContent className="space-y-1.5 pt-2">
            <DataTable table={related.relationships} label={`${related.relationships_title} · ${chrome('table')}`} />
            <p className="text-xs text-muted-foreground">{related.relationships_caption}</p>
          </CollapsibleContent>
        </Collapsible>
      )}
    </div>
  )
}

function Export({ data }: { data: AnalysisOverview }) {
  const [includeIps, setIncludeIps] = useState(false)
  return (
    <div className="space-y-2.5">
      <Check label={data.export.include_ips_label} checked={includeIps} onChange={setIncludeIps} />
      <div className="flex flex-wrap gap-2">
        <DownloadLink href={`/api/analyze/${data.id}/download/json?include_ips=${includeIps}`} label={data.export.json} />
        <DownloadLink href={`/api/analyze/${data.id}/download/csv?include_ips=${includeIps}`} label={data.export.csv} />
      </div>
      <p className="text-xs text-muted-foreground">{data.export.caption}</p>
      {data.export.save && <SaveToHistory id={data.id} label={data.export.save} />}
    </div>
  )
}

/** "Save aggregate analysis history" (only when history is enabled, as in Streamlit). */
function SaveToHistory({ id, label }: { id: string; label: string }) {
  const { lang } = usePreferences()
  const queryClient = useQueryClient()
  const save = useMutation({
    mutationFn: () => saveAnalysis(id, lang),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['history'] }),
  })
  return (
    <div className="space-y-2 border-t pt-3">
      <Button size="sm" disabled={save.isPending} onClick={() => save.mutate()}>
        {label}
      </Button>
      {save.data && (
        <p role="status" className="text-xs text-muted-foreground">
          {save.data.message}
        </p>
      )}
      {save.isError && <Notice tone="warn">{save.error.message}</Notice>}
    </div>
  )
}

function DownloadLink({ href, label }: { href: string; label: string }) {
  return (
    <Button asChild variant="outline" size="sm">
      <a href={href} download>
        <Download aria-hidden /> {label}
      </a>
    </Button>
  )
}
