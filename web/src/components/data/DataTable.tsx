import type { Cell, Table } from '@/lib/api'
import { usePreferences } from '@/lib/preferences'
import { cn } from 'cn'

const ADDRESS = /^(?:\d{1,3}\.){3}\d{1,3}$|^[0-9a-f:]+:[0-9a-f:]*$/i

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
  const show = (value: Cell) => {
    if (value === null || value === '') return '—'
    if (typeof value === 'boolean') return value ? t('Yes') : t('No')
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
                )}
              >
                {column}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {table.rows.map((row, rowIndex) => (
            <tr key={rowIndex} className="border-b last:border-b-0 hover:bg-accent/50">
              {row.map((value, index) => (
                <td
                  key={index}
                  className={cn(
                    'px-2.5 py-1 align-top',
                    numeric[index]
                      ? 'text-right whitespace-nowrap tabular-nums'
                      : long[index]
                        ? 'max-w-[34rem] min-w-[20rem]'
                        : 'whitespace-nowrap',
                    typeof value === 'string' && ADDRESS.test(value) && 'font-mono whitespace-nowrap',
                    (value === null || value === '') && 'text-muted-foreground',
                  )}
                >
                  {show(value)}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
