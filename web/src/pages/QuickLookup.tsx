import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { AlertOctagon, AlertTriangle, CalendarClock, Check, ChevronDown, ExternalLink, Info, Search } from 'lucide-react'
import { useId, useState, type FormEvent } from 'react'

import { MetricStrip, Notice as NoticeBox } from '@/components/data/Blocks'
import { DataTable } from '@/components/data/DataTable'
import { Button } from '@/components/ui/button'
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible'
import {
  checkDomainAge,
  fetchLookupStatus,
  runLookup,
  type LookupResult,
  type Notice,
  type SignalNode,
  type Tone,
} from '@/lib/api'
import { usePreferences } from '@/lib/preferences'
import { cn } from 'cn'

// The last checked value survives switching screens, like Streamlit's session state.
let lastValue = ''

const TONE_TEXT: Record<Tone, string> = {
  safe: 'text-live',
  low: 'text-review',
  review: 'text-review',
  danger: 'text-threat',
  critical: 'text-threat',
  info: 'text-foreground',
  neutral: 'text-muted-foreground',
}
const TONE_RAIL: Record<Tone, string> = {
  safe: 'bg-live',
  low: 'bg-review',
  review: 'bg-review',
  danger: 'bg-threat',
  critical: 'bg-threat',
  info: 'bg-muted-foreground',
  neutral: 'bg-border',
}

export function QuickLookup() {
  const { lang, t, chrome } = usePreferences()
  const inputId = useId()
  const [draft, setDraft] = useState(lastValue)
  const [submitted, setSubmitted] = useState(lastValue)
  const [emptyWarning, setEmptyWarning] = useState(false)

  const status = useQuery({ queryKey: ['lookup-status', lang], queryFn: () => fetchLookupStatus(lang) })
  const result = useQuery({
    queryKey: ['lookup', lang, submitted],
    queryFn: () => runLookup(lang, submitted),
    enabled: submitted.trim().length > 0,
    staleTime: Infinity,
    retry: false,
  })

  const submit = (event: FormEvent) => {
    event.preventDefault()
    if (!draft.trim()) {
      setEmptyWarning(true)
      return
    }
    setEmptyWarning(false)
    lastValue = draft
    setSubmitted(draft)
  }

  const heading = <h1 className="text-lg font-semibold tracking-tight">{t('Quick lookup')}</h1>
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
        <NoticeBox tone="warn">{chrome('offline')}</NoticeBox>
      </>
    )
  }
  const info = status.data

  return (
    <div className="space-y-4">
      <div className="space-y-1">
        {heading}
        <p className="text-xs text-muted-foreground">{t('Check one URL, domain or IP against your local threat intelligence without visiting it.')}</p>
      </div>
      <Notices notices={info.notices} />
      {info.ready && (
        <form onSubmit={submit} className="space-y-1.5" role="search">
          <label htmlFor={inputId} className="text-xs text-muted-foreground">
            {info.label}
          </label>
          <div className="flex gap-2">
            <input
              id={inputId}
              value={draft}
              maxLength={4096}
              placeholder={info.placeholder}
              autoComplete="off"
              spellCheck={false}
              onChange={(event) => setDraft(event.target.value)}
              className="h-10 min-w-0 flex-1 rounded-sm border bg-card px-3 font-mono text-[13px] placeholder:font-sans placeholder:text-muted-foreground focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
            />
            <Button type="submit" className="h-10 px-4" disabled={result.isFetching}>
              <Search aria-hidden /> {info.button}
            </Button>
          </div>
          <p className="text-xs text-muted-foreground">{info.caption}</p>
        </form>
      )}
      {emptyWarning && <NoticeBox tone="warn">{info.empty_input}</NoticeBox>}
      {result.isError && <NoticeBox tone="warn">{result.error.message}</NoticeBox>}
      {result.isFetching && !result.data && <p className="text-xs text-muted-foreground">{chrome('loading')}</p>}
      {result.data && (result.data.error ? <NoticeBox tone="warn">{result.data.error}</NoticeBox> : <Result data={result.data} />)}
    </div>
  )
}

function Notices({ notices }: { notices: Notice[] }) {
  return (
    <>
      {notices.map((notice) =>
        notice.kind === 'caption' ? (
          <p key={notice.text} className="text-xs text-muted-foreground">
            {notice.text}
          </p>
        ) : (
          <NoticeBox key={notice.text} tone={notice.kind === 'info' ? 'info' : 'warn'}>
            {notice.text}
          </NoticeBox>
        ),
      )}
    </>
  )
}

function SectionTitle({ children }: { children: string }) {
  return <h2 className="pt-2 text-[13px] font-semibold">{children}</h2>
}

function Node({ node }: { node: SignalNode }) {
  return (
    <div className="relative min-w-0 overflow-hidden rounded-sm border bg-card px-3 py-2 pl-4">
      <span aria-hidden className={cn('absolute inset-y-0 left-0 w-1', TONE_RAIL[node.tone])} />
      <p className="text-xs text-muted-foreground">{node.label}</p>
      <p className={cn('font-semibold break-words', TONE_TEXT[node.tone])}>{node.value}</p>
      <p className="text-xs text-muted-foreground">{node.sub}</p>
    </div>
  )
}

function Result({ data }: { data: LookupResult }) {
  const { chrome } = usePreferences()
  const banner = data.banner
  const BannerIcon = banner.tone === 'safe' ? Check : banner.tone === 'critical' ? AlertOctagon : AlertTriangle
  return (
    <div className="space-y-3">
      <Notices notices={data.notices} />

      <section
        aria-label={banner.kicker}
        className="relative overflow-hidden rounded-sm border bg-card px-4 py-3 pl-5"
      >
        <span aria-hidden className={cn('absolute inset-y-0 left-0 w-1', TONE_RAIL[banner.tone])} />
        <div className="flex flex-wrap items-start gap-x-6 gap-y-2">
          <div className="flex min-w-0 flex-1 gap-3">
            <BannerIcon aria-hidden className={cn('mt-0.5 size-5 shrink-0', TONE_TEXT[banner.tone])} />
            <div className="min-w-0">
              <p className={cn('text-xs font-semibold', TONE_TEXT[banner.tone])}>{banner.kicker}</p>
              <p className="text-base font-semibold">{banner.title}</p>
              <p className="max-w-[80ch] text-[13px] text-muted-foreground">{banner.summary}</p>
            </div>
          </div>
          <p className="max-w-full font-mono text-[13px] break-all">{banner.target}</p>
        </div>
        <dl className="mt-2.5 flex flex-wrap gap-x-5 gap-y-1 border-t pt-2 text-xs">
          {banner.meta.map(([label, value]) => (
            <div key={label} className="flex gap-1.5">
              <dt className="font-semibold">{label}:</dt>
              <dd className="text-muted-foreground">{value}</dd>
            </div>
          ))}
        </dl>
      </section>

      <SectionTitle>{data.overview_title}</SectionTitle>
      <div className={cn('grid gap-3', data.ml_card && 'lg:grid-cols-[minmax(0,1fr)_minmax(0,1.65fr)]')}>
        {data.ml_card && <MlCard card={data.ml_card} />}
        <div className="space-y-1.5">
          <div className={cn('grid gap-2 sm:grid-cols-2', !data.ml_card && data.console.length === 3 && 'lg:grid-cols-3')}>
            {data.console.map((node) => (
              <Node key={node.label} node={node} />
            ))}
          </div>
          <p className="text-xs text-muted-foreground">{data.console_caption}</p>
        </div>
      </div>

      <SectionTitle>{data.reasons_title}</SectionTitle>
      <ul className="space-y-1 text-[13px]">
        {data.reasons.map((reason) => (
          <li key={reason} className="flex gap-2">
            <span aria-hidden className="text-muted-foreground">›</span>
            <span className="max-w-[90ch]">{reason}</span>
          </li>
        ))}
      </ul>

      {data.registry && <Registry registry={data.registry} />}
      {data.links.length > 0 && (
        <>
          <SectionTitle>{data.links_title}</SectionTitle>
          <p className="text-xs text-muted-foreground">{data.links_caption}</p>
          <div className="flex flex-wrap gap-2">
            {data.links.map((link) => (
              <Button key={link.name} asChild variant="outline" size="sm">
                <a href={link.url} target="_blank" rel="noopener noreferrer">
                  {link.name} <ExternalLink aria-hidden />
                </a>
              </Button>
            ))}
          </div>
          <p className="text-xs text-muted-foreground">{chrome('behaviorInStreamlit')}</p>
        </>
      )}

      <SectionTitle>{data.evidence_title}</SectionTitle>
      <div className="relative overflow-hidden rounded-sm border bg-card px-3 py-2 pl-4">
        <span aria-hidden className={cn('absolute inset-y-0 left-0 w-1', TONE_RAIL[data.evidence_state.tone])} />
        <p className={cn('text-[13px] font-semibold', TONE_TEXT[data.evidence_state.tone])}>{data.evidence_state.heading}</p>
        <p className="text-xs text-muted-foreground">{data.evidence_state.copy}</p>
      </div>
      {data.evidence.rows.length > 0 && (
        <DataTable table={data.evidence} label={`${data.evidence_title} · ${chrome('table')}`} maxHeight="max-h-80" />
      )}

      <Collapsible className="rounded-sm border bg-card">
        <CollapsibleTrigger className="group flex w-full items-center gap-2 px-3 py-2 text-left text-[13px] font-medium focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none">
          <ChevronDown aria-hidden className="size-4 transition-transform group-data-[state=open]:rotate-180" />
          {data.technical.title}
        </CollapsibleTrigger>
        <CollapsibleContent className="space-y-2 border-t px-3 py-3">
          <p className="text-xs text-muted-foreground">{data.technical.caption}</p>
          <MetricStrip metrics={data.technical.metrics} />
        </CollapsibleContent>
      </Collapsible>

      <p className="max-w-[110ch] text-xs text-muted-foreground">{data.footer}</p>
    </div>
  )
}

function MlCard({ card }: { card: NonNullable<LookupResult['ml_card']> }) {
  return (
    <div className="relative overflow-hidden rounded-sm border bg-card px-3 py-2.5 pl-4">
      <span aria-hidden className={cn('absolute inset-y-0 left-0 w-1', TONE_RAIL[card.tone])} />
      <div className="flex items-start justify-between gap-3">
        <div>
          <p className="text-xs text-muted-foreground">{card.kicker}</p>
          <p className={cn('text-base font-semibold', TONE_TEXT[card.tone])}>{card.level}</p>
        </div>
        <p className="font-semibold tabular-nums">
          <span className="text-xl">{card.score}</span>
          <span className="text-xs text-muted-foreground">/100</span>
        </p>
      </div>
      <p className="text-xs text-muted-foreground">{card.subtitle}</p>
      <div
        role="meter"
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={card.score}
        aria-label={card.kicker}
        className="mt-2 h-1.5 overflow-hidden rounded-sm bg-muted"
      >
        <span className={cn('block h-full', TONE_RAIL[card.tone])} style={{ width: `${card.score}%` }} />
      </div>
      {card.scale && (
        <div className="mt-1 flex justify-between text-[11px] text-muted-foreground">
          {card.scale.map((step) => (
            <span key={step}>{step}</span>
          ))}
        </div>
      )}
      <p className="mt-2 text-[13px]">{card.explanation}</p>
      <p className="text-xs text-muted-foreground">{card.note}</p>
    </div>
  )
}

function Registry({ registry }: { registry: NonNullable<LookupResult['registry']> }) {
  const { lang } = usePreferences()
  const queryClient = useQueryClient()
  const age = useMutation({
    mutationFn: (domain: string) => checkDomainAge(lang, domain),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['lookup'] }),
  })

  if (registry.kind === 'owner') {
    return (
      <>
        <SectionTitle>{registry.title}</SectionTitle>
        {registry.owner ? (
          <Node node={{ tone: 'info', label: registry.owner.label, value: registry.owner.value, sub: registry.owner.sub }} />
        ) : (
          <p className="text-xs text-muted-foreground">{registry.unknown}</p>
        )}
      </>
    )
  }
  const shown = age.data ?? registry.result
  return (
    <>
      <SectionTitle>{registry.title}</SectionTitle>
      {registry.unavailable ? (
        <p className="text-xs text-muted-foreground">{registry.unavailable}</p>
      ) : shown ? (
        <>
          <Node node={shown} />
          {shown.caption && <p className="text-xs text-muted-foreground">{shown.caption}</p>}
        </>
      ) : (
        <div className="space-y-1.5">
          <Button
            variant="outline"
            size="sm"
            disabled={age.isPending || !registry.domain}
            onClick={() => registry.domain && age.mutate(registry.domain)}
          >
            <CalendarClock aria-hidden /> {registry.button}
          </Button>
          {age.isError && <NoticeBox tone="warn">{age.error.message}</NoticeBox>}
          <p className="flex items-start gap-1.5 text-xs text-muted-foreground">
            <Info aria-hidden className="mt-0.5 size-3.5 shrink-0" />
            {registry.caption}
          </p>
        </div>
      )}
    </>
  )
}
