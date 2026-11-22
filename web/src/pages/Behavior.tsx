import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { CheckCircle2, ChevronDown } from 'lucide-react'
import { useState, type ReactNode } from 'react'

import { BehaviorCard } from '@/components/data/BehaviorCard'
import { MetricStrip, Notice } from '@/components/data/Blocks'
import { DataTable } from '@/components/data/DataTable'
import { Markdown } from '@/components/data/Markdown'
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible'
import { fetchBehavior, saveBehaviorMark, type BehaviorNotice, type BehaviorOk, type Mark } from '@/lib/api'
import { usePreferences } from '@/lib/preferences'

// Scores are recomputed at most every 5 minutes on the server (ui_behavior.REFRESH_SECONDS).
const REFRESH_MS = 60_000

/** The collector's "Experimental ML" tab: new rhythmic destinations, then the behavior model. */
export function Behavior() {
  const { lang, t, chrome } = usePreferences()
  const queryClient = useQueryClient()
  const [saveError, setSaveError] = useState(false)
  const behavior = useQuery({
    queryKey: ['behavior', lang],
    queryFn: () => fetchBehavior(lang),
    refetchInterval: REFRESH_MS,
    placeholderData: keepPreviousData,
    retry: 1,
  })
  const mark = useMutation({
    mutationFn: ({ key, value }: { key: string; value: Mark | null }) => saveBehaviorMark(key, value),
    onMutate: () => setSaveError(false),
    onError: () => setSaveError(true),
    onSettled: () => queryClient.invalidateQueries({ queryKey: ['behavior'] }),
  })
  const onMark = (key: string, value: Mark | null) => mark.mutate({ key, value })
  const heading = <h1 className="text-lg font-semibold tracking-tight">{t('Experimental ML')}</h1>

  if (behavior.isPending) {
    return (
      <>
        {heading}
        <p className="py-12 text-muted-foreground">{chrome('loading')}</p>
      </>
    )
  }
  if (behavior.isError) {
    return (
      <>
        {heading}
        <Notice tone="warn">{chrome('offline')}</Notice>
      </>
    )
  }
  const data = behavior.data
  if (data.state !== 'ok') {
    return (
      <>
        {heading}
        <Notice tone="info">{t('Configure a local collector to show automatically collected connections.')}</Notice>
      </>
    )
  }
  return (
    <div className="space-y-4">
      <div className="space-y-1">
        {heading}
        <p className="text-xs text-muted-foreground">{data.caption}</p>
      </div>
      {saveError && <Notice tone="warn">{t('Could not save. Check the folder permissions.')}</Notice>}
      <NewDestinations data={data} busy={mark.isPending} onMark={onMark} />
      <Model data={data} busy={mark.isPending} onMark={onMark} />
    </div>
  )
}

function Part({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section aria-label={title} className="space-y-2.5 border-t pt-4">
      <h2 className="text-base font-semibold tracking-tight">{title}</h2>
      {children}
    </section>
  )
}

function Guide({ title, text }: { title: string; text: string }) {
  return (
    <Collapsible className="rounded-sm border bg-card">
      <CollapsibleTrigger className="group flex min-h-11 w-full items-center gap-2 px-3 py-2 text-left text-[13px] font-medium focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none lg:min-h-0">
        <ChevronDown aria-hidden className="size-4 transition-transform group-data-[state=open]:rotate-180" />
        {title}
      </CollapsibleTrigger>
      <CollapsibleContent className="border-t px-3 py-3">
        <Markdown text={text} />
      </CollapsibleContent>
    </Collapsible>
  )
}

function Status({ notice }: { notice: BehaviorNotice }) {
  if (notice.kind === 'info') return <Notice tone="info">{notice.text}</Notice>
  return (
    <div role="status" className="flex items-center gap-3 rounded-sm border bg-card px-3 py-2 text-[13px]">
      <CheckCircle2 aria-hidden className="size-4 shrink-0 text-live" />
      {notice.text}
    </div>
  )
}

function Captions({ captions }: { captions: string[] }) {
  return (
    <>
      {captions.map((caption) => (
        <p key={caption} className="max-w-[100ch] text-xs text-muted-foreground">
          {caption}
        </p>
      ))}
    </>
  )
}

type CardProps = { data: BehaviorOk; busy: boolean; onMark: (key: string, mark: Mark | null) => void }

function NewDestinations({ data, busy, onMark }: CardProps) {
  const part = data.new
  return (
    <Part title={part.title}>
      {part.state === 'no_data' && <p className="text-xs text-muted-foreground">{part.empty}</p>}
      {part.state === 'unreadable' && <Notice tone="warn">{part.warning}</Notice>}
      {part.state === 'ok' && (
        <>
          {part.notice && <Status notice={part.notice} />}
          {part.summary && <p className="text-xs text-muted-foreground">{part.summary}</p>}
          {part.cards.length > 0 && (
            <div className="grid gap-2.5">
              {part.cards.map((card) => (
                <BehaviorCard key={card.key} card={card} busy={busy} onMark={onMark} />
              ))}
            </div>
          )}
          <Captions captions={part.captions} />
          <Guide title={part.guide_title} text={part.guide} />
        </>
      )}
    </Part>
  )
}

function Model({ data, busy, onMark }: CardProps) {
  const { chrome } = usePreferences()
  const model = data.model
  if (model.state === 'learning') {
    return (
      <Part title={model.title}>
        <Captions captions={model.captions ?? []} />
      </Part>
    )
  }
  if (model.state === 'unreadable') {
    return (
      <Part title={model.title}>
        <Notice tone="warn">{model.warning}</Notice>
      </Part>
    )
  }
  return (
    <Part title={model.title}>
      <div className="rounded-sm border bg-card px-3 py-2.5">
        <p className="text-base font-semibold">{model.heading}</p>
        <p className="text-xs text-muted-foreground">{model.summary}</p>
      </div>
      <MetricStrip metrics={model.metrics ?? []} />
      <Captions captions={(model.metrics ?? []).flatMap((metric) => (metric.help ? [`${metric.label}: ${metric.help}`] : []))} />
      {(model.cards ?? []).length > 0 && (
        <div className="grid gap-2.5">
          {(model.cards ?? []).map((card) => (
            <BehaviorCard key={card.key} card={card} busy={busy} onMark={onMark} />
          ))}
        </div>
      )}
      <Captions captions={model.captions ?? []} />
      {model.below && (
        <Collapsible className="rounded-sm border bg-card">
          <CollapsibleTrigger className="group flex min-h-11 w-full items-center gap-2 px-3 py-2 text-left text-[13px] font-medium focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none lg:min-h-0">
            <ChevronDown aria-hidden className="size-4 transition-transform group-data-[state=open]:rotate-180" />
            {model.below.title}
          </CollapsibleTrigger>
          <CollapsibleContent className="border-t p-2">
            <DataTable table={model.below} label={`${model.below.title} · ${chrome('table')}`} maxHeight="max-h-72" />
          </CollapsibleContent>
        </Collapsible>
      )}
      {model.guide_title && model.guide && <Guide title={model.guide_title} text={model.guide} />}
      {model.model_caption && <p className="font-mono text-xs text-muted-foreground">{model.model_caption}</p>}
    </Part>
  )
}
