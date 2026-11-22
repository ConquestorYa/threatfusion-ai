import { ChevronDown, ExternalLink } from 'lucide-react'

import { Markdown } from '@/components/data/Markdown'
import { MarkBadge, MarkButtons } from '@/components/data/MarkButtons'
import { RhythmChart } from '@/components/data/RhythmChart'
import { Button } from '@/components/ui/button'
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible'
import type { BehaviorCard as Card, Mark } from '@/lib/api'
import { cn } from 'cn'

/** One Streamlit behavior / new-destination card (ui_behavior._render_card, ui_new_destinations._card). */
export function BehaviorCard({
  card,
  busy,
  onMark,
}: {
  card: Card
  busy: boolean
  onMark: (key: string, mark: Mark | null) => void
}) {
  const rail = card.shown_mark === 'suspicious' ? 'bg-suspect' : 'bg-review'
  return (
    <article aria-label={card.title} className="relative overflow-hidden rounded-sm border bg-card">
      <span aria-hidden className={cn('absolute inset-y-0 left-0 w-1', rail)} />
      <div className="space-y-2 py-2.5 pr-3 pl-4">
        <div className="flex flex-wrap items-start justify-between gap-x-4 gap-y-1.5">
          <div className="min-w-0 flex-1 space-y-0.5">
            <div className="flex min-w-0 flex-wrap items-center gap-x-2 gap-y-1">
              <h3 className="font-semibold break-all">{card.title}</h3>
              <MarkBadge mark={card.shown_mark} />
            </div>
            <p className="font-mono text-[12.5px] [overflow-wrap:anywhere]">
              <span className="whitespace-nowrap">{card.device}</span>
              <span className="text-muted-foreground"> → </span>
              <span className="whitespace-nowrap">{card.destination}</span>
            </p>
            {card.owner && <p className="text-xs text-muted-foreground">{card.owner}</p>}
            {card.others && <p className="text-xs text-muted-foreground [overflow-wrap:anywhere]">{card.others}</p>}
          </div>
          <dl className="text-right">
            <dt className="text-xs text-muted-foreground">{card.score_label}</dt>
            <dd className="text-lg leading-tight font-semibold tabular-nums">{card.score}</dd>
            {card.level && <dd className="text-xs text-muted-foreground">{card.level}</dd>}
          </dl>
        </div>
        {card.why.length > 0 && (
          <p className="text-[13px]">
            <span className="font-semibold">{card.why_label}:</span> {card.why.join(' · ')}
          </p>
        )}
        {card.rhythm && (
          <div className="space-y-1">
            <p className="text-xs text-muted-foreground">{card.rhythm.caption}</p>
            <RhythmChart times={card.rhythm.times} label={card.rhythm.caption} />
          </div>
        )}
        <MarkButtons mark={card.mark} busy={busy} onMark={(mark) => onMark(card.key, mark)} alwaysText />
      </div>
      <Collapsible className="border-t">
        <CollapsibleTrigger className="group flex min-h-11 w-full items-center gap-2 px-4 py-2 text-left text-[13px] font-medium focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none lg:min-h-0">
          <ChevronDown aria-hidden className="size-4 transition-transform group-data-[state=open]:rotate-180" />
          {card.advice_title}
        </CollapsibleTrigger>
        <CollapsibleContent className="space-y-2 border-t border-dashed px-4 py-2.5">
          <Markdown text={card.advice} />
          <pre className="overflow-x-auto rounded-sm bg-muted px-2 py-1.5 font-mono text-[12px]">{card.command}</pre>
          {card.links.length > 0 && (
            <>
              <p className="text-xs text-muted-foreground">{card.links_caption}</p>
              <div className="flex flex-wrap gap-1.5">
                {card.links.map((link) => (
                  <Button key={link.name} asChild variant="outline" size="xs">
                    <a href={link.url} target="_blank" rel="noopener noreferrer">
                      {link.name}
                      <ExternalLink aria-hidden />
                    </a>
                  </Button>
                ))}
              </div>
            </>
          )}
        </CollapsibleContent>
      </Collapsible>
    </article>
  )
}
