import type { Cell, Table } from '@/lib/api'
import { usePreferences } from '@/lib/preferences'
import { cn } from 'cn'

const ADDRESS = /^(?:\d{1,3}\.){3}\d{1,3}$|^[0-9a-f:]+:[0-9a-f:]*$/i
// ISO times from the snapshot ("2026-11-15T16:38:20.45+00:00") and
// format_timestamp output ("2026-11-15 16:38 UTC").
const TIME = /^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:\d{2}| UTC)?$/

const pad = (n: number) => String(n).padStart(2, '0')

/** Short time like the rest of the app: local "dd.mm HH:MM"; UTC when the column says UTC. */
export function shortTime(value: string, utc = false): string {
  const date = new Date(value.replace(' UTC', 'Z').replace(' ', 'T'))
  if (Number.isNaN(date.getTime())) return value
  const [day, month, year, hours, minutes] = utc
    ? [date.getUTCDate(), date.getUTCMonth() + 1, date.getUTCFullYear(), date.getUTCHours(), date.getUTCMinutes()]
    : [date.getDate(), date.getMonth() + 1, date.getFullYear(), date.getHours(), date.getMinutes()]
  const sameYear = year === new Date().getFullYear()
  return `${pad(day)}.${pad(month)}${sameYear ? '' : `.${year}`} ${pad(hours)}:${pad(minutes)}`
}

/**
 * Dense, horizontally scrollable table (the page itself never scrolls sideways).
 * Numbers are right-aligned with tabular figures; booleans read Yes/No.
 */
export function DataTable({ table, label, maxHeight = 'max-h-[28rem]' }: { table: Table; label: string; maxHeight?: string }) {
  const { t } = usePreferences()
  const numeric = table.columns.map((_, index) =>
    table.rows.every((row) => row[index] === null || typeof row[index] === 'number'),
  )
  // Long free text (evidence, limits) gets room so rows stay one or two lines.
  const long = table.columns.map((_, index) =>
    table.rows.some((row) => typeof row[index] === 'string' && (row[index] as string).length > 48),
  )
  const utc = table.columns.map((column) => /UTC/.test(column))
  const show = (value: Cell, index: number) => {
    if (value === null || value === '') return '—'
    if (typeof value === 'boolean') return value ? t('Yes') : t('No')
    if (typeof value === 'string' && TIME.test(value)) return shortTime(value, utc[index])
    return String(value)
  }
  return (
    <div
      role="region"
      aria-label={label}
      tabIndex={0}
      className={cn('overflow-auto rounded-sm border bg-card focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none', maxHeight)}
    >
      <table className="w-full border-collapse text-xs">
        <thead className="sticky top-0 z-10 bg-surface-2">
          <tr>
            {table.columns.map((column, index) => (
              <th
                key={column}
                scope="col"
                className={cn(
                  'border-b px-2.5 py-1.5 text-left font-medium whitespace-nowrap text-muted-foreground',
                  numeric[index] && 'text-right',
                  // The first column stays in view while the table scrolls sideways.
                  index === 0 && 'sticky left-0 z-[1] border-r bg-surface-2',
                )}
              >
                {column}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {table.rows.map((row, rowIndex) => (
            <tr key={rowIndex} className="border-b last:border-b-0">
              {row.map((value, index) => (
                <td
                  key={index}
                  className={cn(
                    'px-2.5 py-1 align-top',
                    index === 0 && 'sticky left-0 z-[1] border-r bg-card',
                    numeric[index]
                      ? 'text-right whitespace-nowrap tabular-nums'
                      : long[index]
                        ? 'max-w-[34rem] min-w-[20rem]'
                        : 'whitespace-nowrap',
                    typeof value === 'string' && ADDRESS.test(value) && 'font-mono whitespace-nowrap',
                    typeof value === 'string' && TIME.test(value) && 'font-mono whitespace-nowrap',
                    (value === null || value === '') && 'text-muted-foreground',
                  )}
                >
                  {show(value, index)}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
