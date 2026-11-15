import { AlertTriangle, Info } from 'lucide-react'
import type { ReactNode } from 'react'

import type { Block } from '@/lib/api'
import { cn } from 'cn'

/** One Streamlit element (caption, text, warning, info, bold heading) per block. */
export function Blocks({ blocks }: { blocks: Block[] }) {
  return (
    <div className="space-y-1.5">
      {blocks.map((block, index) => (
        <BlockView key={index} block={block} />
      ))}
    </div>
  )
}

function BlockView({ block }: { block: Block }) {
  switch (block.kind) {
    case 'heading':
      return <p className="pt-1 text-[13px] font-semibold">{block.text}</p>
    case 'caption':
      return <p className="max-w-[100ch] text-xs text-muted-foreground">{block.text}</p>
    case 'text':
      return <p className="max-w-[100ch] text-[13px]">{block.text}</p>
    case 'warning':
    case 'info':
      return <Notice tone={block.kind === 'warning' ? 'warn' : 'info'}>{block.text}</Notice>
  }
}

export function Notice({ tone, children }: { tone: 'info' | 'warn'; children: ReactNode }) {
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
      <div className="min-w-0 flex-1">{children}</div>
    </div>
  )
}

/** A row of labelled numbers (Streamlit st.metric columns). */
export function MetricStrip({ metrics }: { metrics: { label: string; value: number | string }[] }) {
  return (
    <dl className="grid grid-cols-2 overflow-hidden rounded-sm border bg-card sm:flex">
      {metrics.map((metric) => (
        <div
          key={metric.label}
          className="flex min-w-0 flex-col justify-between gap-1 border-b px-3 py-2 odd:border-r sm:flex-1 sm:border-r sm:border-b-0 sm:last:border-r-0"
        >
          <dt className="text-xs text-muted-foreground">{metric.label}</dt>
          <dd className="text-lg leading-none font-semibold tabular-nums">{metric.value}</dd>
        </div>
      ))}
    </dl>
  )
}
