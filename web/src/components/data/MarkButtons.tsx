import { AlertTriangle, Check, HelpCircle } from 'lucide-react'

import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import type { Mark } from '@/lib/api'
import { usePreferences } from '@/lib/preferences'
import { cn } from 'cn'

// Streamlit labels start with a symbol ("✓ I know this", "⚪ Not sure"); the
// icon carries that meaning here. Strip only those symbols: \W would also
// strip Turkish letters such as "Ş".
export const plain = (text: string) => text.replace(/^(?:[✓?⚠⚪\u{1F7E3}]️?\s*)+/u, '')

export const MARKS: { mark: Mark; text: string; plain: string; Icon: typeof Check }[] = [
  { mark: 'known', text: '✓ I know this', plain: 'I know this', Icon: Check },
  { mark: 'unsure', text: '? Not sure', plain: 'Not sure', Icon: HelpCircle },
  { mark: 'suspicious', text: '⚠ Suspicious', plain: 'Suspicious', Icon: AlertTriangle },
]

/**
 * The three mark buttons: text on ≥1024 px, icon buttons with tooltip and
 * aria-label below it, ≥44 px touch targets. Clicking the chosen mark clears it.
 */
export function MarkButtons({
  mark,
  busy,
  onMark,
  alwaysText = false,
}: {
  mark: Mark | null
  busy: boolean
  onMark: (mark: Mark | null) => void
  /** Cards have room for the words at every width. */
  alwaysText?: boolean
}) {
  const { t, chrome } = usePreferences()
  return (
    <div role="group" aria-label={chrome('mark')} className="inline-flex overflow-hidden rounded-sm border">
      {MARKS.map(({ mark: value, text, plain: plainText, Icon }) => {
        const selected = mark === value
        const label = plain(t(text)) || plainText
        return (
          <Tooltip key={value}>
            <TooltipTrigger asChild>
              <button
                type="button"
                aria-pressed={selected}
                aria-label={label}
                disabled={busy}
                onClick={() => onMark(selected ? null : value)}
                className={cn(
                  'inline-flex h-11 min-w-11 items-center justify-center gap-1.5 px-2 text-xs text-muted-foreground not-first:border-l hover:bg-accent hover:text-foreground focus-visible:z-10 focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none disabled:opacity-50 lg:h-7 lg:px-1.5',
                  selected && 'bg-selected text-selected-foreground hover:bg-selected hover:text-selected-foreground',
                )}
              >
                <Icon aria-hidden className="size-3.5" />
                <span className={cn('whitespace-nowrap', alwaysText ? 'inline' : 'hidden lg:inline')}>{label}</span>
              </button>
            </TooltipTrigger>
            <TooltipContent className={alwaysText ? 'hidden' : 'lg:hidden'}>
              {selected ? `${label} · ${t('Click again to remove the mark')}` : label}
            </TooltipContent>
          </Tooltip>
        )
      })}
    </div>
  )
}

/** "Suspicious" / "Not sure" badge beside a title (nothing for known or unmarked). */
export function MarkBadge({ mark }: { mark: Mark | null }) {
  const { t } = usePreferences()
  if (!mark || mark === 'known') return null
  return (
    <span
      className={cn(
        'rounded-sm border px-1.5 text-[11px] leading-4 font-medium',
        mark === 'suspicious' ? 'border-suspect text-suspect' : 'border-border text-muted-foreground',
      )}
    >
      {plain(t(mark === 'suspicious' ? '🟣 Suspicious' : '⚪ Not sure'))}
    </span>
  )
}
