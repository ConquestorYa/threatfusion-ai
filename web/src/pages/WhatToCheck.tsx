import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { AlertTriangle, ChevronDown, Info, RefreshCw } from 'lucide-react'
import { useState } from 'react'

import { Alert, AlertDescription } from '@/components/ui/alert'
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

const MARK_BUTTONS: { mark: Mark; text: string }[] = [
  { mark: 'known', text: '✓ I know this' },
  { mark: 'unsure', text: '? Not sure' },
  { mark: 'suspicious', text: '⚠ Suspicious' },
]

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
    retry: 1,
  })
  const mark = useMutation({
    mutationFn: ({ key, value }: { key: string; value: Mark | null }) => saveMark(key, value),
    onMutate: () => setSaveError(false),
    onError: () => setSaveError(true),
    onSettled: () => queryClient.invalidateQueries({ queryKey: ['review'] }),
  })

  if (review.isPending) {
    return <p className="py-16 text-muted-foreground">{chrome('loading')}</p>
  }
  if (review.isError) {
    return (
      <Notice tone="warn">
        <span>{chrome('offline')}</span>
        <Button variant="outline" size="sm" className="ml-auto" onClick={() => review.refetch()}>
          <RefreshCw /> {chrome('retry')}
        </Button>
      </Notice>
    )
  }

  const data = review.data
  if (data.state !== 'ok') {
    if (data.state === 'not_configured') {
      return (
        <Notice tone="info">
          <div className="space-y-2">
            <p>{t('Configure a local collector to show automatically collected connections.')}</p>
            <code className="block rounded-md bg-muted px-3 py-2 font-mono text-sm">
              threatfusion-ai collect --input-dir /path/to/zeek/logs
            </code>
          </div>
        </Notice>
      )
    }
    return data.state === 'no_snapshot' ? (
      <Notice tone="info">{t('No collector snapshot yet. Start the local collector.')}</Notice>
    ) : (
      <Notice tone="warn">
        {t('Collector snapshot could not be read. Check private permissions and supported schema.')}
      </Notice>
    )
  }

  const shown = data.items.filter(FILTERS[filter])
  const busyKey = mark.isPending ? mark.variables?.key : undefined
  const setMark = (key: string, value: Mark | null) => mark.mutate({ key, value })

  return (
    <div className="space-y-6">
      <p className="flex flex-wrap gap-x-3 text-sm text-muted-foreground">
        <span>{t('Last {hours} hours · threat lists + unusual behavior · updates every 10 s', {
          hours: data.window_hours,
        })}</span>
        <span className="whitespace-nowrap tabular-nums" title={data.updated_at}>
          {chrome('updated')} {new Date(data.updated_at).toLocaleTimeString(lang)}
        </span>
      </p>

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

      <dl className="grid grid-cols-2 gap-px overflow-hidden rounded-lg border bg-border sm:grid-cols-4">
        <Count label={t('To check')} value={data.counts.to_check} />
        <Count label={t('Suspicious')} value={data.counts.suspicious} tone="suspect" />
        <Count label={t('On a threat list')} value={data.counts.threat} tone="threat" />
        <Count label={t('Known')} value={data.counts.known} />
      </dl>

      {data.items.length === 0 ? (
        <p className="rounded-lg border border-dashed px-4 py-10 text-center text-muted-foreground">
          {t('Nothing to check. Everything collected is under Details.')}
        </p>
      ) : (
        <section className="space-y-3" aria-label={t('What to check')}>
          <ToggleGroup
            type="single"
            variant="outline"
            size="sm"
            value={filter}
            onValueChange={(value) => value && setFilter(value as Filter)}
            className="flex-wrap"
          >
            {(Object.keys(FILTERS) as Filter[]).map((name) => (
              <ToggleGroupItem key={name} value={name}>
                {t(name)}
              </ToggleGroupItem>
            ))}
          </ToggleGroup>
          <p className="max-w-[72ch] text-sm text-muted-foreground">
            {t(
              'A flag means look, not danger. Most are normal programs. Mark each one: ' +
                'I know this hides it next time, Suspicious keeps it on top.',
            )}
          </p>
          {saveError && (
            <Notice tone="warn">{t('Could not save. Check the folder permissions.')}</Notice>
          )}
          <ul className="divide-y overflow-hidden rounded-lg border bg-card">
            {shown.slice(0, MAX_SHOWN).map((item) => (
              <ReviewRow key={item.key} item={item} busy={busyKey === item.key} onMark={setMark} />
            ))}
          </ul>
          {(shown.length > MAX_SHOWN || data.items_truncated) && (
            <p className="text-sm text-muted-foreground">{t('Showing the first 200. Details lists everything.')}</p>
          )}
        </section>
      )}

      {data.known.length > 0 && (
        <Collapsible className="rounded-lg border">
          <CollapsibleTrigger className="group flex w-full items-center gap-2 px-4 py-3 text-left text-sm font-medium">
            <ChevronDown className="size-4 transition-transform group-data-[state=open]:rotate-180" />
            {t('Known ({count})', { count: data.counts.known })}
          </CollapsibleTrigger>
          <CollapsibleContent>
            <ul className="divide-y border-t">
              {data.known.map((item) => (
                <li key={item.key} className="flex items-center gap-3 px-4 py-2 text-sm">
                  <span className="min-w-0 flex-1 truncate">
                    <span className="font-medium">{item.title}</span>
                    <span className="text-muted-foreground"> · {item.label}</span>
                  </span>
                  <Button
                    variant="ghost"
                    size="sm"
                    disabled={busyKey === item.key}
                    onClick={() => setMark(item.key, null)}
                  >
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
  const { t } = usePreferences()
  const rail = item.mark === 'suspicious' ? 'bg-suspect' : item.threat ? 'bg-threat' : 'bg-review'
  const badge = item.mark === 'suspicious' ? '🟣 Suspicious' : item.mark === 'unsure' ? '⚪ Not sure' : null
  const devices = item.devices.join(', ')

  return (
    <li className="relative">
      <span aria-hidden className={cn('absolute inset-y-0 left-0 w-1', rail)} />
      <Collapsible>
        <div className="grid gap-x-6 gap-y-2 py-3 pr-4 pl-5 md:grid-cols-[minmax(0,5fr)_minmax(0,4fr)_11rem]">
          <div className="min-w-0">
            <p className="flex flex-wrap items-baseline gap-x-2">
              <span className="font-semibold break-all">{item.title}</span>
              {badge && <span className="text-xs text-suspect">{t(badge)}</span>}
            </p>
            <p className="text-sm">
              <span className={cn('font-medium', item.threat ? 'text-threat' : 'text-foreground')}>{item.label}</span>
              <span className="text-muted-foreground"> · {item.metric}</span>
            </p>
          </div>
          <div className="min-w-0 text-sm">
            <p className="font-mono text-[0.8rem] break-all">
              {devices}
              {item.destination && (
                <>
                  <span className="text-muted-foreground"> → </span>
                  {item.destination.host}:{item.destination.port}
                </>
              )}
            </p>
            {item.owner && <p className="text-muted-foreground">{item.owner}</p>}
          </div>
          <p className="text-sm text-muted-foreground tabular-nums md:text-right">{item.when}</p>

          <div className="flex flex-wrap items-center gap-1.5 md:col-span-3">
            {MARK_BUTTONS.map(({ mark, text }) => {
              const selected = item.mark === mark
              return (
                <Button
                  key={mark}
                  size="sm"
                  variant={selected ? 'default' : 'outline'}
                  aria-pressed={selected}
                  title={selected ? t('Click again to remove the mark') : undefined}
                  disabled={busy}
                  onClick={() => onMark(item.key, selected ? null : mark)}
                >
                  {t(text)}
                </Button>
              )
            })}
            <CollapsibleTrigger asChild>
              <Button variant="ghost" size="sm" className="group ml-auto">
                {t('Why? What to do?')}
                <ChevronDown className="transition-transform group-data-[state=open]:rotate-180" />
              </Button>
            </CollapsibleTrigger>
          </div>
        </div>
        <CollapsibleContent className="data-[state=open]:animate-in data-[state=open]:fade-in-0">
          <div className="max-w-[80ch] space-y-3 border-t bg-muted/40 py-3 pr-4 pl-5 text-sm">
            <p>{item.what.join(' ')}</p>
            <p className="font-semibold">{item.advice}</p>
            {item.facts.length > 0 && <p className="text-muted-foreground">{item.facts.join(' · ')}</p>}
            {item.links.length > 0 && (
              <div className="space-y-1.5">
                <p className="text-muted-foreground">
                  {t('Look up on outside sites (opens in a new tab; the name or IP is sent to that site):')}
                </p>
                <div className="flex flex-wrap gap-1.5">
                  {item.links.map((link) => (
                    <Button key={link.name} asChild variant="outline" size="sm">
                      <a href={link.url} target="_blank" rel="noopener noreferrer">
                        {link.name}
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

function Count({ label, value, tone }: { label: string; value: number; tone?: 'threat' | 'suspect' }) {
  return (
    <div className="bg-card px-4 py-3">
      <dt className="text-sm text-muted-foreground">{label}</dt>
      <dd
        className={cn(
          'text-3xl font-semibold tabular-nums',
          value > 0 && tone === 'threat' && 'text-threat',
          value > 0 && tone === 'suspect' && 'text-suspect',
        )}
      >
        {value}
      </dd>
    </div>
  )
}

function Notice({ tone, children }: { tone: 'info' | 'warn'; children: React.ReactNode }) {
  const Icon = tone === 'warn' ? AlertTriangle : Info
  return (
    <Alert className={cn(tone === 'warn' && 'border-review/60 bg-review-soft')}>
      <Icon className={cn(tone === 'warn' && 'text-review')} />
      <AlertDescription className="flex flex-wrap items-center gap-3 text-foreground">{children}</AlertDescription>
    </Alert>
  )
}
