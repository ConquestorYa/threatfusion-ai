import { useQuery } from '@tanstack/react-query'
import { CheckCircle2, ChevronDown } from 'lucide-react'
import type { ReactNode } from 'react'

import { GroupedRateBars, HorizontalBars } from '@/components/data/Bars'
import { MetricStrip, Notice } from '@/components/data/Blocks'
import { DataTable } from '@/components/data/DataTable'
import { Markdown } from '@/components/data/Markdown'
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible'
import { fetchEvaluation, type BehaviorEvaluation, type LexicalEvaluation } from '@/lib/api'
import { usePreferences } from '@/lib/preferences'

/** "Model evaluation": the on-device behavior model's report, or the frozen lexical holdout report. */
export function Evaluation() {
  const { lang, t, chrome } = usePreferences()
  const evaluation = useQuery({ queryKey: ['evaluation', lang], queryFn: () => fetchEvaluation(lang), retry: 1 })
  const heading = <h1 className="text-lg font-semibold tracking-tight">{t('Model evaluation')}</h1>
  if (evaluation.isPending) {
    return (
      <>
        {heading}
        <p className="py-12 text-muted-foreground">{chrome('loading')}</p>
      </>
    )
  }
  if (evaluation.isError || evaluation.data.state !== 'ok') {
    return (
      <>
        {heading}
        <Notice tone="warn">{chrome('offline')}</Notice>
      </>
    )
  }
  const { subtitle, report } = evaluation.data
  return (
    <div className="space-y-4">
      <div className="space-y-1">
        {heading}
        <p className="text-xs text-muted-foreground">{subtitle}</p>
      </div>
      {report.kind === 'behavior' ? <Behavior report={report} /> : <Lexical report={report} />}
    </div>
  )
}

function Fold({ title, open = false, children }: { title: string; open?: boolean; children: ReactNode }) {
  return (
    <Collapsible defaultOpen={open} className="rounded-sm border bg-card">
      <CollapsibleTrigger className="group flex min-h-11 w-full items-center gap-2 px-3 py-2 text-left text-[13px] font-medium focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none lg:min-h-0">
        <ChevronDown aria-hidden className="size-4 transition-transform group-data-[state=open]:rotate-180" />
        {title}
      </CollapsibleTrigger>
      <CollapsibleContent className="space-y-2 border-t px-3 py-3">{children}</CollapsibleContent>
    </Collapsible>
  )
}

function Passed({ children }: { children: ReactNode }) {
  return (
    <div role="status" className="flex items-center gap-3 rounded-sm border bg-card px-3 py-2 text-[13px]">
      <CheckCircle2 aria-hidden className="size-4 shrink-0 text-live" />
      {children}
    </div>
  )
}

function Subtitle({ children }: { children: string }) {
  return <h2 className="pt-1 text-[13px] font-semibold">{children}</h2>
}

function Behavior({ report }: { report: BehaviorEvaluation }) {
  const { chrome } = usePreferences()
  if (report.state === 'unreadable') return <Notice tone="warn">{report.warning}</Notice>
  return (
    <section aria-label={report.title} className="space-y-3">
      <div className="space-y-0.5">
        <h2 className="text-base font-semibold tracking-tight">{report.title}</h2>
        <p className="text-xs text-muted-foreground">{report.caption}</p>
      </div>
      <MetricStrip metrics={report.metrics} />
      {report.verdict &&
        (report.verdict.kind === 'success' ? <Passed>{report.verdict.text}</Passed> : <Notice tone="warn">{report.verdict.text}</Notice>)}
      {report.declared && (
        <>
          <Subtitle>{report.declared.title}</Subtitle>
          <DataTable table={report.declared} label={`${report.declared.title} · ${chrome('table')}`} />
        </>
      )}
      <DataTable table={report.data} label={`${report.title} · ${chrome('table')}`} />
      {report.importance && (
        <div className="space-y-2">
          <Subtitle>{report.importance.title}</Subtitle>
          <div className="rounded-sm border bg-card p-3">
            <HorizontalBars bars={report.importance.bars} label={report.importance.title} format={(value) => value.toFixed(3)} />
          </div>
          <Fold title={chrome('showTable')}>
            <DataTable
              table={report.importance}
              label={`${report.importance.title} · ${chrome('table')}`}
            />
          </Fold>
        </div>
      )}
      <Subtitle>{report.limits_title}</Subtitle>
      <Markdown text={report.limits} />
      <Fold title={report.guide_title}>
        <Markdown text={report.guide} />
      </Fold>
    </section>
  )
}

function Lexical({ report }: { report: LexicalEvaluation }) {
  const { chrome } = usePreferences()
  return (
    <div className="space-y-3">
      <Fold title={report.guide_title} open={report.guide_open}>
        <Markdown text={report.guide} />
      </Fold>
      {report.state === 'not_evaluated' && (
        <section aria-label={report.title} className="space-y-1.5 rounded-sm border bg-card px-3 py-2.5">
          <h2 className="text-base font-semibold">{report.title}</h2>
          <p className="text-[13px]">{report.text}</p>
          <p className="text-xs text-muted-foreground">{report.caption}</p>
          <Fold title={report.command_title}>
            <pre className="overflow-x-auto rounded-sm bg-muted px-2 py-1.5 font-mono text-[12px] whitespace-pre-wrap">{report.command}</pre>
          </Fold>
        </section>
      )}
      {report.state === 'unreadable' && (
        <>
          <Notice tone="warn">{report.error}</Notice>
          <p className="text-xs text-muted-foreground">{report.caption}</p>
        </>
      )}
      {report.state === 'ok' && (
        <>
          <Passed>{report.loaded}</Passed>
          <p className="text-[13px] font-semibold">{report.model}</p>
          <p className="font-mono text-xs break-all text-muted-foreground">{report.artifact}</p>
          <Notice tone="info">{report.scope}</Notice>
          <p className="text-[13px]">{report.dates}</p>
          <MetricStrip metrics={report.metrics} />
          <Subtitle>{report.operating_title}</Subtitle>
          <div className="rounded-sm border bg-card p-3">
            <GroupedRateBars {...report.chart} />
          </div>
          <DataTable table={report.operating} label={`${report.operating_title} · ${chrome('table')}`} />
          {report.sources && (
            <Fold title={report.sources.title}>
              <DataTable table={report.sources} label={`${report.sources.title} · ${chrome('table')}`} />
              <p className="text-xs text-muted-foreground">{report.sources.caption}</p>
            </Fold>
          )}
          <Notice tone="info">{report.ppv}</Notice>
          {report.protocol.map((line) => (
            <p key={line} className="max-w-[100ch] text-xs text-muted-foreground">
              {line}
            </p>
          ))}
        </>
      )}
    </div>
  )
}
