import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { ChevronDown, Download } from 'lucide-react'
import { useEffect, useId, useState, type ReactNode } from 'react'

import { Blocks, MetricStrip, Notice } from '@/components/data/Blocks'
import { DataTable } from '@/components/data/DataTable'
import { Markdown } from '@/components/data/Markdown'
import { TimeChart } from '@/components/data/TimeChart'
import { Button } from '@/components/ui/button'
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible'
import { fetchDetails, fetchTimeline, type DetailsOk, type DetailsOptions } from '@/lib/api'
import { usePreferences } from '@/lib/preferences'

// Same refresh as the Streamlit collector fragment.
const REFRESH_MS = 10_000

export function Details() {
  const { lang, t, chrome } = usePreferences()
  // Streamlit defaults: local IPs on, reviews only on, expected off, DNS observations off.
  const [options, setOptions] = useState<DetailsOptions>({
    local_ips: true,
    reviews_only: true,
    include_expected: false,
    dns_observations: false,
  })
  const details = useQuery({
    queryKey: ['details', lang, options],
    queryFn: () => fetchDetails(lang, options),
    refetchInterval: REFRESH_MS,
    placeholderData: keepPreviousData,
    retry: 1,
  })
  const set = (name: keyof DetailsOptions) => (value: boolean) => setOptions((current) => ({ ...current, [name]: value }))
  const heading = <h1 className="text-lg font-semibold tracking-tight">{t('Details')}</h1>

  if (details.isPending) {
    return (
      <>
        {heading}
        <p className="py-12 text-muted-foreground">{chrome('loading')}</p>
      </>
    )
  }
  if (details.isError) {
    return (
      <>
        {heading}
        <Notice tone="warn">{chrome('offline')}</Notice>
      </>
    )
  }
  const data = details.data
  if (data.state !== 'ok') {
    return (
      <>
        {heading}
        <Notice tone={data.state === 'unreadable' ? 'warn' : 'info'}>
          {data.state === 'not_configured'
            ? t('Configure a local collector to show automatically collected connections.')
            : data.state === 'no_snapshot'
              ? t('No collector snapshot yet. Start the local collector.')
              : t('Collector snapshot could not be read. Check private permissions and supported schema.')}
        </Notice>
      </>
    )
  }

  return (
    <div className="space-y-4">
      <div className="space-y-1">
        {heading}
        {data.captions.map((caption) => (
          <p key={caption} className="text-xs text-muted-foreground">
            {caption}
          </p>
        ))}
      </div>

      <Collapsible className="rounded-sm border bg-card">
        <CollapsibleTrigger className="group flex w-full items-center gap-2 px-3 py-2 text-left text-[13px] font-medium focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none">
          <ChevronDown aria-hidden className="size-4 transition-transform group-data-[state=open]:rotate-180" />
          {t('What does this page do?')}
        </CollapsibleTrigger>
        <CollapsibleContent className="border-t px-3 py-3">
          <Markdown text={data.guide} />
        </CollapsibleContent>
      </Collapsible>

      <MetricStrip metrics={data.metrics} />
      {data.notices.length > 0 && <Blocks blocks={data.notices} />}

      <MetricStrip metrics={data.review_summary.metrics} />
      <div className="space-y-1">
        {data.review_summary.captions.map((caption) => (
          <p key={caption} className="max-w-[100ch] text-xs text-muted-foreground">
            {caption}
          </p>
        ))}
      </div>

      <fieldset className="flex flex-wrap gap-x-5 gap-y-2">
        <Check label={t('Show observed endpoint IPs locally; downloads keep aliases')} checked={options.local_ips} onChange={set('local_ips')} />
        <Check label={t('Show only connection reviews')} checked={options.reviews_only} onChange={set('reviews_only')} />
        <Check label={t('Include declared expected activity')} checked={options.include_expected} onChange={set('include_expected')} />
      </fieldset>
      {data.identity_warning && <Notice tone="warn">{data.identity_warning}</Notice>}

      {data.connections.rows.length ? (
        <DataTable table={data.connections} label={`${t('Details')} · ${chrome('table')}`} />
      ) : (
        <Notice tone="info">{data.connections.empty}</Notice>
      )}
      {data.connections.more && <p className="text-xs text-muted-foreground">{data.connections.more}</p>}

      <ConnectionInvestigation data={data} localIps={options.local_ips} />
      <Attempts data={data} />
      <Dns data={data} observations={options.dns_observations} onObservations={set('dns_observations')} localIps={options.local_ips} />
      <Downloads data={data} />
    </div>
  )
}

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section aria-label={title} className="space-y-2.5 border-t pt-4">
      <h2 className="text-base font-semibold tracking-tight">{title}</h2>
      {children}
    </section>
  )
}

function Check({ label, checked, onChange }: { label: string; checked: boolean; onChange: (value: boolean) => void }) {
  return (
    <label className="inline-flex min-h-8 cursor-pointer items-center gap-2 text-[13px]">
      <input
        type="checkbox"
        checked={checked}
        onChange={(event) => onChange(event.target.checked)}
        className="size-4 accent-foreground"
      />
      {label}
    </label>
  )
}

function Select({
  label,
  value,
  options,
  onChange,
}: {
  label: string
  value: string
  options: { value: string; label: string }[]
  onChange: (value: string) => void
}) {
  const id = useId()
  return (
    <div className="flex max-w-xl flex-col gap-1">
      <label htmlFor={id} className="text-xs text-muted-foreground">
        {label}
      </label>
      <select
        id={id}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        className="h-9 w-full rounded-sm border bg-card px-2 font-mono text-[13px] focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
      >
        {options.map((option) => (
          <option key={option.value} value={option.value}>
            {option.label}
          </option>
        ))}
      </select>
    </div>
  )
}

/** Selection resets when the snapshot generation changes, as in Streamlit. */
function useSelection<T extends string | number>(revision: string, values: T[]) {
  const [state, setState] = useState<{ revision: string; value: T | null }>({ revision, value: null })
  useEffect(() => {
    if (state.revision !== revision) setState({ revision, value: null })
  }, [revision, state.revision])
  const value = state.value !== null && values.includes(state.value) ? state.value : (values[0] ?? null)
  return [value, (next: T) => setState({ revision, value: next })] as const
}

function ConnectionInvestigation({ data, localIps }: { data: DetailsOk; localIps: boolean }) {
  const { t } = usePreferences()
  const groups = data.connections.groups
  const [group, setGroup] = useSelection(data.revision, groups.map((g) => g.group))
  if (!data.connections.rows.length) return null
  return (
    <Section title={t('Connection investigation')}>
      {data.connections.timeline_missing || group === null ? (
        <Notice tone="info">{data.connections.timeline_missing}</Notice>
      ) : (
        <>
          <Select
            label={t('Select a connection group')}
            value={String(group)}
            options={groups.map((g) => ({ value: String(g.group), label: g.label }))}
            onChange={(value) => setGroup(Number(value))}
          />
          <TimelineView kind="connection" group={group} revision={data.revision} localIps={localIps} />
        </>
      )}
    </Section>
  )
}

function TimelineView({ kind, group, revision, localIps }: { kind: 'connection' | 'dns'; group: number; revision: string; localIps: boolean }) {
  const { lang, chrome } = usePreferences()
  const timeline = useQuery({
    queryKey: ['timeline', kind, lang, group, revision, localIps],
    queryFn: () => fetchTimeline(kind, lang, group, localIps),
    placeholderData: keepPreviousData,
  })
  if (timeline.isPending) return <p className="text-xs text-muted-foreground">{chrome('loading')}</p>
  if (timeline.isError) return <Notice tone="warn">{timeline.error.message}</Notice>
  const data = timeline.data
  return (
    <div className="space-y-3">
      <div className="rounded-sm border bg-card px-3 py-2.5">
        <Blocks blocks={data.guidance} />
      </div>
      {data.notices.length > 0 && <Blocks blocks={data.notices} />}
      {data.chart && (
        <div className="rounded-sm border bg-card p-2">
          <TimeChart points={data.chart.points} kind={data.chart.kind} xTitle={data.chart.x_title} yTitle={data.chart.y_title} />
        </div>
      )}
      {data.table && (
        // The chart is the default view; the bucket table is one click away.
        <Collapsible className="rounded-sm border bg-card">
          <CollapsibleTrigger className="group flex w-full items-center gap-2 px-3 py-2 text-left text-[13px] font-medium focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none">
            <ChevronDown aria-hidden className="size-4 transition-transform group-data-[state=open]:rotate-180" />
            {chrome('showTable')}
          </CollapsibleTrigger>
          <CollapsibleContent className="border-t p-2">
            <DataTable table={data.table} label={`${data.chart?.y_title ?? ''} · ${chrome('table')}`} maxHeight="max-h-72" />
          </CollapsibleContent>
        </Collapsible>
      )}
      {data.footer && <p className="text-xs text-muted-foreground">{data.footer}</p>}
    </div>
  )
}

function Attempts({ data }: { data: DetailsOk }) {
  const { chrome } = usePreferences()
  const attempts = data.attempts
  if (!attempts) return null
  return (
    <Section title={attempts.title}>
      <Blocks blocks={attempts.notices} />
      {attempts.rows.length ? <DataTable table={attempts} label={`${attempts.title} · ${chrome('table')}`} /> : <Notice tone="info">{attempts.empty}</Notice>}
    </Section>
  )
}

function Dns({
  data,
  observations,
  onObservations,
  localIps,
}: {
  data: DetailsOk
  observations: boolean
  onObservations: (value: boolean) => void
  localIps: boolean
}) {
  const { t, chrome } = usePreferences()
  const dns = data.dns
  const investigation = dns.investigation
  const devices = investigation?.devices ?? []
  const [device, setDevice] = useSelection(data.revision, devices.map((d) => d.value))
  const domains = (investigation?.domains ?? []).filter((d) => d.device === device)
  const [group, setGroup] = useSelection(`${data.revision}:${device}`, domains.map((d) => d.group))

  if (dns.missing) return <p className="border-t pt-4 text-xs text-muted-foreground">{dns.missing}</p>
  return (
    <Section title={dns.title}>
      {dns.empty_window ? (
        <Notice tone="info">{dns.empty_window}</Notice>
      ) : (
        <>
          {dns.notices_before && dns.notices_before.length > 0 && <Blocks blocks={dns.notices_before} />}
          {dns.metrics && <MetricStrip metrics={dns.metrics} />}
          {dns.captions?.map((caption) => (
            <p key={caption} className="text-xs text-muted-foreground">
              {caption}
            </p>
          ))}
          {dns.notices && dns.notices.length > 0 && <Blocks blocks={dns.notices} />}
          <Check label={dns.observations_label ?? ''} checked={observations} onChange={onObservations} />
          {dns.rows && dns.rows.length ? (
            <DataTable table={{ columns: dns.columns ?? [], rows: dns.rows }} label={`${dns.title} · ${chrome('table')}`} />
          ) : (
            <Notice tone="info">{dns.empty}</Notice>
          )}
          {dns.more && <p className="text-xs text-muted-foreground">{dns.more}</p>}
          <p className="text-xs text-muted-foreground">{chrome('mlInStreamlit')}</p>
          {investigation && (
            <div className="space-y-2.5 pt-2">
              <h3 className="text-[13px] font-semibold">{investigation.title}</h3>
              {investigation.missing || device === null || group === null ? (
                <Notice tone="info">{investigation.missing}</Notice>
              ) : (
                <>
                  <div className="grid gap-3 sm:grid-cols-2">
                    <Select
                      label={t('Select an observed device')}
                      value={device}
                      options={devices.map((d) => ({ value: d.value, label: d.label }))}
                      onChange={setDevice}
                    />
                    <Select
                      label={t('Select a queried domain')}
                      value={String(group)}
                      options={domains.map((d) => ({ value: String(d.group), label: d.target }))}
                      onChange={(value) => setGroup(Number(value))}
                    />
                  </div>
                  <TimelineView kind="dns" group={group} revision={data.revision} localIps={localIps} />
                </>
              )}
            </div>
          )}
          {dns.footer && <p className="text-xs text-muted-foreground">{dns.footer}</p>}
        </>
      )}
    </Section>
  )
}

function Downloads({ data }: { data: DetailsOk }) {
  const { full, snapshot, caption } = data.downloads
  return (
    <section className="space-y-2 border-t pt-4">
      {full && <p className="text-xs text-muted-foreground">{full.caption}</p>}
      <div className="flex flex-wrap gap-2">
        {full && (
          <Button asChild variant="outline" size="sm">
            <a href="/api/details/download/full" download="threatfusion_collected_connections.full.json.gz">
              <Download aria-hidden /> {full.label}
            </a>
          </Button>
        )}
        <Button asChild variant="outline" size="sm">
          <a href="/api/details/download/snapshot" download={snapshot.file}>
            <Download aria-hidden /> {snapshot.label}
          </a>
        </Button>
      </div>
      <p className="text-xs text-muted-foreground">{caption}</p>
    </section>
  )
}
