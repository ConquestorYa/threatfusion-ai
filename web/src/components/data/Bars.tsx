// Horizontal bar charts (dataviz method): bars start at zero, one validated
// series colour (--chart-series) and a muted second series, values printed at
// the bar end so no tooltip is needed; the same numbers are in a table below.

export function HorizontalBars({ bars, label, format = (value) => String(value) }: {
  bars: { label: string; value: number }[]
  label: string
  format?: (value: number) => string
}) {
  const top = Math.max(...bars.map((bar) => bar.value), 0) || 1
  return (
    <figure aria-label={label} role="img" className="space-y-1.5">
      {bars.map((bar) => (
        <div key={bar.label} className="grid grid-cols-[minmax(0,12rem)_minmax(0,1fr)] items-center gap-2 text-xs sm:grid-cols-[16rem_minmax(0,1fr)]">
          <span className="truncate text-muted-foreground" title={bar.label}>
            {bar.label}
          </span>
          <span className="flex min-w-0 items-center gap-1.5">
            <span className="block h-3 rounded-r-sm bg-chart-series" style={{ width: `${(bar.value / top) * 85}%` }} />
            <span className="shrink-0 tabular-nums">{format(bar.value)}</span>
          </span>
        </div>
      ))}
    </figure>
  )
}

const SERIES = ['bg-chart-series', 'bg-muted-foreground']

/** Grouped bars for rates (0–1), e.g. recall vs false-positive rate per operating point. */
export function GroupedRateBars({ title, series, groups }: {
  title: string
  series: string[]
  groups: { label: string; values: number[] }[]
}) {
  const percent = (value: number) => `${(value * 100).toFixed(0)}%`
  return (
    <figure aria-label={title} role="img" className="space-y-2">
      <figcaption className="text-[13px] font-semibold">{title}</figcaption>
      <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted-foreground">
        {series.map((name, index) => (
          <span key={name} className="inline-flex items-center gap-1.5">
            <span aria-hidden className={`size-2.5 rounded-sm ${SERIES[index]}`} />
            {name}
          </span>
        ))}
      </div>
      {groups.map((group) => (
        <div key={group.label} className="grid grid-cols-[6rem_minmax(0,1fr)] gap-2 text-xs">
          <span className="pt-0.5 text-muted-foreground">{group.label}</span>
          <div className="space-y-1">
            {group.values.map((value, index) => (
              <span key={series[index]} className="flex min-w-0 items-center gap-1.5">
                <span className={`block h-3 rounded-r-sm ${SERIES[index]}`} style={{ width: `${Math.max(value * 85, 0.5)}%` }} />
                <span className="shrink-0 tabular-nums">{percent(value)}</span>
              </span>
            ))}
          </div>
        </div>
      ))}
    </figure>
  )
}
