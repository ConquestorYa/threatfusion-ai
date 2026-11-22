import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { AlertTriangle, Check, ChevronDown, ExternalLink, HelpCircle, Info, RefreshCw } from 'lucide-react'
import { useState, type ReactNode } from 'react'

import { MarkBadge, MarkButtons } from '@/components/data/MarkButtons'
import { Button } from '@/components/ui/button'
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible'
import { ToggleGroup, ToggleGroupItem } from '@/components/ui/toggle-group'
import { fetchReview, saveMark, type Mark, type ReviewItem } from '@/lib/api'
import { usePreferences } from '@/lib/preferences'
import { cn } from 'cn'

const REFRESH_MS = 10_000
const MAX_SHOWN = 200

// Same filters, in the same order, as the Streamlit list.
const FILTERS = {
  All: () => true,
  'Not marked': (item: ReviewItem) => !item.mark,
  Suspicious: (item: ReviewItem) => item.mark === 'suspicious',
  'Threat lists': (item: ReviewItem) => item.threat,
  Connections: (item: ReviewItem) => item.kind === 'connection',
  'Name lookups': (item: ReviewItem) => item.kind === 'dns',
} as const
type Filter = keyof typeof FILTERS

// Desktop table columns (≥1024 px); narrower screens stack each row.
const COLUMNS =
  'lg:grid lg:grid-cols-[4px_minmax(130px,1fr)_minmax(130px,1fr)_minmax(220px,1.4fr)_minmax(90px,0.7fr)_6.5rem_17.75rem] lg:items-center'

export function WhatToCheck() {
  const { lang, t, chrome } = usePreferences()
  const queryClient = useQueryClient()
  const [filter, setFilter] = useState<Filter>('All')
  const [saveError, setSaveError] = useState(false)

  const review = useQuery({
    queryKey: ['review', lang],
    queryFn: () => fetchReview(lang),
    refetchInterval: REFRESH_MS,
    refetchIntervalInBackground: false,
    // Keep rows (and their open explanations) on screen while another language loads.
    placeholderData: keepPreviousData,
    retry: 1,
  })
  const mark = useMutation({
    mutationFn: ({ key, value }: { key: string; value: Mark | null }) => saveMark(key, value),
    onMutate: () => setSaveError(false),
    onError: () => setSaveError(true),
    onSettled: () => queryClient.invalidateQueries({ queryKey: ['review'] }),
  })

  const heading = <h1 className="text-lg font-semibold tracking-tight">{t('What to check')}</h1>

  if (review.isPending) {
    return (
      <>
        {heading}
        <p className="py-12 text-muted-foreground">{chrome('loading')}</p>
      </>
    )
  }
  if (review.isError) {
    return (
      <>
        {heading}
        <Notice tone="warn">
          <span>{chrome('offline')}</span>
          <Button variant="outline" size="sm" className="ml-auto" onClick={() => review.refetch()}>
            <RefreshCw aria-hidden /> {chrome('retry')}
          </Button>
        </Notice>
      </>
    )
  }

  const data = review.data
  if (data.state !== 'ok') {
    return (
      <>
        {heading}
        {data.state === 'not_configured' ? (
          <Notice tone="info">
            <div className="space-y-2">
              <p>{t('Configure a local collector to show automatically collected connections.')}</p>
              <code className="block rounded-sm bg-muted px-3 py-2 font-mono text-[13px]">
                threatfusion-ai collect --input-dir /path/to/zeek/logs
              </code>
            </div>
          </Notice>
        ) : data.state === 'no_snapshot' ? (
          <Notice tone="info">{t('No collector snapshot yet. Start the local collector.')}</Notice>
        ) : (
          <Notice tone="warn">
            {t('Collector snapshot could not be read. Check private permissions and supported schema.')}
          </Notice>
        )}
      </>
    )
  }

  const shown = data.items.filter(FILTERS[filter])
  const busyKey = mark.isPending ? mark.variables?.key : undefined
  const setMark = (key: string, value: Mark | null) => mark.mutate({ key, value })

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-baseline gap-x-4 gap-y-1">
        {heading}
        <span className="text-xs text-muted-foreground">
          {t('Last {hours} hours · threat lists + unusual behavior · updates every 10 s', { hours: data.window_hours })}
        </span>
        <span className="inline-flex items-center gap-1.5 text-xs text-muted-foreground" title={data.updated_at}>
          <span aria-hidden className={cn('size-1.5 rounded-full', data.stale ? 'bg-review' : 'bg-live')} />
          {chrome('updated').replace('{time}', new Date(data.updated_at).toLocaleTimeString(lang, { hour: '2-digit', minute: '2-digit' }))}
        </span>
      </div>

      {data.stale && (
        <Notice tone="warn">
          {t('This snapshot is older than one minute. Check whether the collector is still running.')}
        </Notice>
      )}
      {data.coverage_incomplete && (
        <Notice tone="warn">
          {t('Some collected data is missing, so this list may be incomplete. Details shows why.')}
        </Notice>
      )}

      <div className="flex flex-wrap items-stretch rounded-sm border bg-card">
        <dl className="grid w-full grid-cols-2 sm:flex sm:w-auto">
          <Count label={t('To check')} value={data.counts.to_check} />
          <Count label={t('Suspicious')} value={data.counts.suspicious} tone="suspect" />
          <Count label={t('On a threat list')} value={data.counts.threat} tone="threat" />
          <Count label={t('Known')} value={data.counts.known} />
        </dl>
        {data.items.length > 0 && (
          <ToggleGroup
            type="single"
            size="sm"
            spacing={1}
            value={filter}
            aria-label={t('Show')}
            onValueChange={(value) => value && setFilter(value as Filter)}
            className="ml-auto flex-wrap p-1.5"
          >
            {(Object.keys(FILTERS) as Filter[]).map((name) => (
              <ToggleGroupItem key={name} value={name} className="h-7 px-2.5 text-xs">
                {t(name)}
              </ToggleGroupItem>
            ))}
          </ToggleGroup>
        )}
      </div>

      {data.items.length === 0 ? (
        <p className="rounded-sm border border-dashed px-4 py-8 text-center text-muted-foreground">
          {t('Nothing to check. Everything collected is under Details.')}
        </p>
      ) : (
        <section aria-label={t('What to check')} className="space-y-2">
          <p className="text-xs text-muted-foreground">
            {t(
              'A flag means look, not danger. Most are normal programs. Mark each one: ' +
                'I know this hides it next time, Suspicious keeps it on top.',
            )}
          </p>
          {saveError && <Notice tone="warn">{t('Could not save. Check the folder permissions.')}</Notice>}
          <div className="overflow-hidden rounded-sm border bg-card">
            <div
              aria-hidden
              className={cn(
                'hidden gap-x-3 border-b bg-surface-2 px-0 py-1.5 pr-3 text-xs font-medium text-muted-foreground',
                COLUMNS,
              )}
            >
              <span />
              <span>{chrome('target')}</span>
              <span>{chrome('reason')}</span>
              <span>{chrome('deviceTarget')}</span>
              <span>{chrome('owner')}</span>
              <span>{chrome('time')}</span>
              <span>{chrome('mark')}</span>
            </div>
            <ul className="divide-y">
              {shown.slice(0, MAX_SHOWN).map((item) => (
                <ReviewRow key={item.key} item={item} busy={busyKey === item.key} onMark={setMark} />
              ))}
            </ul>
          </div>
          <MarkLegend />
          {(shown.length > MAX_SHOWN || data.items_truncated) && (
            <p className="text-xs text-muted-foreground">{t('Showing the first 200. Details lists everything.')}</p>
          )}
        </section>
      )}

      {data.known.length > 0 && (
        <Collapsible className="rounded-sm border bg-card">
          <CollapsibleTrigger className="group flex w-full items-center gap-2 px-3 py-2 text-left text-[13px] font-medium focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none">
            <ChevronDown aria-hidden className="size-4 transition-transform group-data-[state=open]:rotate-180" />
            {t('Known ({count})', { count: data.counts.known })}
          </CollapsibleTrigger>
          <CollapsibleContent>
            <ul className="divide-y border-t">
              {data.known.map((item) => (
                <li key={item.key} className="flex items-center gap-3 px-3 py-1.5 text-[13px]">
                  <span className="min-w-0 flex-1 truncate">
                    <span className="font-medium">{item.title}</span>
                    <span className="text-muted-foreground"> · {item.label}</span>
                  </span>
                  <Button variant="outline" size="xs" disabled={busyKey === item.key} onClick={() => setMark(item.key, null)}>
                    {t('Show again')}
                  </Button>
                </li>
              ))}
            </ul>
          </CollapsibleContent>
        </Collapsible>
      )}
    </div>
  )
}

function ReviewRow({
  item,
  busy,
  onMark,
}: {
  item: ReviewItem
  busy: boolean
  onMark: (key: string, mark: Mark | null) => void
}) {
  const { t, chrome } = usePreferences()
  const [open, setOpen] = useState(false)
  const tone = item.mark === 'suspicious' ? 'suspect' : item.threat ? 'threat' : 'review'
  const rail = { suspect: 'bg-suspect', threat: 'bg-threat', review: 'bg-review' }[tone]
  const [start, end] = (item.when ?? '').split(' – ')

  return (
    <li className="relative">
      <Collapsible open={open} onOpenChange={setOpen}>
        <div className={cn('flex flex-col gap-1.5 py-2 pr-3 pl-4 lg:gap-x-3 lg:py-1.5 lg:pl-0', COLUMNS)}>
          <span aria-hidden className={cn('absolute inset-y-0 left-0 w-1 lg:static lg:h-full lg:min-h-8', rail)} />
          <div className="flex min-w-0 flex-wrap items-center gap-x-2 gap-y-1">
            <span className="font-semibold break-all">{item.title}</span>
            <MarkBadge mark={item.mark} />
          </div>
          <p className="min-w-0 text-[13px]">
            <span className={cn('font-medium', item.threat && 'text-threat')}>{item.label}</span>
            <span className="text-muted-foreground"> · {item.metric}</span>
          </p>
          <div className="min-w-0 text-[13px]">
            <p className="font-mono text-[12.5px] [overflow-wrap:anywhere]">
              <span className="whitespace-nowrap">{item.devices.join(', ')}</span>
              {item.destination && (
                <>
                  <span className="text-muted-foreground"> → </span>
                  <span className="whitespace-nowrap">
                    {item.destination.host}:{item.destination.port}
                  </span>
                </>
              )}
            </p>
            {item.owner && <p className="text-xs text-muted-foreground lg:hidden">{item.owner}</p>}
          </div>
          <p className="hidden min-w-0 text-xs text-muted-foreground lg:block">{item.owner ?? '—'}</p>
          <p className="font-mono text-xs leading-4 text-muted-foreground">
            <span className="lg:block">{start}</span>
            {end && <span className="lg:block"> – {end}</span>}
          </p>
          <div className="flex items-center gap-1">
            <MarkButtons mark={item.mark} busy={busy} onMark={(mark) => onMark(item.key, mark)} />
            <CollapsibleTrigger asChild>
              <Button
                variant="ghost"
                size="icon-sm"
                aria-label={open ? chrome('hideDetails') : chrome('details')}
                title={t('Why? What to do?')}
                className="ml-auto size-11 lg:ml-0 lg:size-7"
              >
                <ChevronDown aria-hidden className={cn('transition-transform', open && 'rotate-180')} />
              </Button>
            </CollapsibleTrigger>
          </div>
        </div>
        <CollapsibleContent>
          <div className="space-y-1.5 border-t border-dashed py-2.5 pr-3 pl-4 text-[13px] lg:pl-6">
            <p className="max-w-[86ch]">{item.what.join(' ')}</p>
            <p className="max-w-[86ch] font-semibold">{item.advice}</p>
            {item.facts.length > 0 && <p className="text-xs text-muted-foreground">{item.facts.join(' · ')}</p>}
            {item.links.length > 0 && (
              <div className="space-y-1.5 pt-0.5">
                <p className="text-xs text-muted-foreground">
                  {t('Look up on outside sites (opens in a new tab; the name or IP is sent to that site):')}
                </p>
                <div className="flex flex-wrap gap-1.5">
                  {item.links.map((link) => (
                    <Button key={link.name} asChild variant="outline" size="xs">
                      <a href={link.url} target="_blank" rel="noopener noreferrer">
                        {link.name}
                        <ExternalLink aria-hidden />
                      </a>
                    </Button>
                  ))}
                </div>
              </div>
            )}
          </div>
        </CollapsibleContent>
      </Collapsible>
    </li>
  )
}

function MarkLegend() {
  const { chrome } = usePreferences()
  const entries = [
    { Icon: Check, text: chrome('marksLegendKnown') },
    { Icon: HelpCircle, text: chrome('marksLegendUnsure') },
    { Icon: AlertTriangle, text: chrome('marksLegendSuspicious') },
  ]
  return (
    <p className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted-foreground lg:hidden">
      {entries.map(({ Icon, text }) => (
        <span key={text} className="inline-flex items-center gap-1.5">
          <Icon aria-hidden className="size-3.5" />
          {text}
        </span>
      ))}
    </p>
  )
}

function Count({ label, value, tone }: { label: string; value: number; tone?: 'threat' | 'suspect' }) {
  return (
    <div className="flex items-baseline gap-2 border-b px-3 py-2 odd:border-r sm:border-r sm:border-b-0 sm:px-3.5 sm:last:border-r-0">
      <dt className="text-xs text-muted-foreground">{label}</dt>
      <dd
        className={cn(
          'order-first text-lg leading-none font-semibold tabular-nums',
          value > 0 && tone === 'threat' && 'text-threat',
          value > 0 && tone === 'suspect' && 'text-suspect',
        )}
      >
        {value}
      </dd>
    </div>
  )
}

function Notice({ tone, children }: { tone: 'info' | 'warn'; children: ReactNode }) {
  const Icon = tone === 'warn' ? AlertTriangle : Info
  return (
    <div
      role={tone === 'warn' ? 'alert' : 'status'}
      className={cn(
        'flex flex-wrap items-center gap-x-3 gap-y-2 rounded-sm border px-3 py-2 text-[13px]',
        tone === 'warn' ? 'border-review/50 bg-review/10' : 'bg-card',
      )}
    >
      <Icon aria-hidden className={cn('size-4 shrink-0', tone === 'warn' ? 'text-review' : 'text-muted-foreground')} />
      {children}
    </div>
  )
}
