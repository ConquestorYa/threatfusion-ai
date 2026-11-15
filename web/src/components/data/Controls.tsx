import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { ChevronDown } from 'lucide-react'
import { useEffect, useId, useState, type ReactNode } from 'react'

import { Blocks, Notice } from '@/components/data/Blocks'
import { DataTable } from '@/components/data/DataTable'
import { TimeChart } from '@/components/data/TimeChart'
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible'
import type { Timeline } from '@/lib/api'
import { usePreferences } from '@/lib/preferences'

// Shared controls of the data screens (Details, Analyze telemetry).

export function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section aria-label={title} className="space-y-2.5 border-t pt-4">
      <h2 className="text-base font-semibold tracking-tight">{title}</h2>
      {children}
    </section>
  )
}

export function Check({ label, checked, onChange }: { label: string; checked: boolean; onChange: (value: boolean) => void }) {
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

export function Select({
  label,
  value,
  options,
  onChange,
  mono = false,
}: {
  label: string
  value: string
  options: { value: string; label: string }[]
  onChange: (value: string) => void
  /** Monospace for addresses and names; plain text otherwise. */
  mono?: boolean
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
        className={`h-9 w-full rounded-sm border bg-card px-2 text-[13px] focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none ${mono ? 'font-mono' : ''}`}
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
export function useSelection<T extends string | number>(revision: string, values: T[]) {
  const [state, setState] = useState<{ revision: string; value: T | null }>({ revision, value: null })
  useEffect(() => {
    if (state.revision !== revision) setState({ revision, value: null })
  }, [revision, state.revision])
  const value = state.value !== null && values.includes(state.value) ? state.value : (values[0] ?? null)
  return [value, (next: T) => setState({ revision, value: next })] as const
}

/** Guidance, chart and (collapsed) bucket table for one selected group. */
export function TimelineView({ queryKey, load }: { queryKey: unknown[]; load: () => Promise<Timeline> }) {
  const { chrome } = usePreferences()
  const timeline = useQuery({ queryKey, queryFn: load, placeholderData: keepPreviousData })
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

