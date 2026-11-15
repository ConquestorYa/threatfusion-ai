import { useEffect, useRef, useState, type KeyboardEvent } from 'react'

// Single-series UTC time chart (dataviz method): one validated series colour
// (--chart-series), recessive grid, 2px line or bars with a 2px gap and 4px
// rounded tops, crosshair + tooltip on hover and arrow keys. The bucket table
// below each chart is the table view. Axis reads the same in every language.

export interface TimePoint {
  t: string
  v: number
}

const MARGIN = { top: 12, right: 12, bottom: 26, left: 40 }
const HEIGHT = 220

const pad = (n: number) => String(n).padStart(2, '0')
export function utcLabel(iso: string, withYear = false) {
  const d = new Date(iso)
  const day = `${pad(d.getUTCDate())}.${pad(d.getUTCMonth() + 1)}${withYear ? `.${d.getUTCFullYear()}` : ''}`
  return `${day} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}`
}

function niceMax(value: number) {
  if (value <= 4) return 4
  const step = 10 ** Math.floor(Math.log10(value))
  for (const factor of [1, 2, 2.5, 5, 10]) if (factor * step >= value) return factor * step
  return value
}

function useWidth() {
  const ref = useRef<HTMLDivElement>(null)
  const [width, setWidth] = useState(640)
  useEffect(() => {
    const element = ref.current
    if (!element) return
    const update = () => setWidth(Math.max(240, Math.floor(element.getBoundingClientRect().width)))
    update()
    const observer = new ResizeObserver(update)
    observer.observe(element)
    return () => observer.disconnect()
  }, [])
  return [ref, width] as const
}

export function TimeChart({
  points,
  kind,
  xTitle,
  yTitle,
}: {
  points: TimePoint[]
  kind: 'line' | 'bar'
  xTitle: string
  yTitle: string
}) {
  const [ref, width] = useWidth()
  const [active, setActive] = useState<number | null>(null)
  const innerW = width - MARGIN.left - MARGIN.right
  const innerH = HEIGHT - MARGIN.top - MARGIN.bottom
  const count = points.length
  const band = innerW / Math.max(count, 1)
  const top = niceMax(Math.max(...points.map((p) => p.v), 0))
  const y = (v: number) => MARGIN.top + innerH - (v / top) * innerH
  const cx = (i: number) => MARGIN.left + band * i + band / 2
  const ticks = [0, 0.25, 0.5, 0.75, 1].map((f) => Math.round(top * f))
  const every = Math.max(1, Math.ceil(116 / band)) // label width ~70px plus a gap
  const showMarkers = band >= 12

  const linePath = points.map((p, i) => `${i ? 'L' : 'M'}${cx(i).toFixed(1)},${y(p.v).toFixed(1)}`).join('')
  const bar = (p: TimePoint, i: number) => {
    const x = MARGIN.left + band * i + 1
    const w = Math.max(1, band - 2)
    const h = p.v > 0 ? Math.max(1, (p.v / top) * innerH) : 0
    if (!h) return null
    const r = Math.min(4, w / 2, h)
    const base = MARGIN.top + innerH
    return `M${x},${base}V${base - h + r}Q${x},${base - h} ${x + r},${base - h}H${x + w - r}Q${x + w},${base - h} ${x + w},${base - h + r}V${base}Z`
  }

  const onKey = (event: KeyboardEvent) => {
    if (event.key === 'ArrowRight') setActive((i) => Math.min(count - 1, (i ?? -1) + 1))
    else if (event.key === 'ArrowLeft') setActive((i) => Math.max(0, (i ?? count) - 1))
    else if (event.key === 'Escape') setActive(null)
    else return
    event.preventDefault()
  }

  const point = active === null ? null : points[active]
  const tipLeft = active === null ? 0 : Math.min(Math.max(cx(active) - 80, 0), width - 160)

  return (
    <div ref={ref} className="relative w-full select-none">
      <svg
        width={width}
        height={HEIGHT}
        role="img"
        aria-label={`${yTitle} · ${xTitle} (UTC)`}
        tabIndex={0}
        onKeyDown={onKey}
        onBlur={() => setActive(null)}
        onMouseLeave={() => setActive(null)}
        className="block rounded-sm focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
      >
        <title>{`${yTitle} · ${xTitle}`}</title>
        {ticks.map((tick) => (
          <g key={tick}>
            <line x1={MARGIN.left} x2={width - MARGIN.right} y1={y(tick)} y2={y(tick)} className="stroke-border" strokeWidth={1} />
            <text x={MARGIN.left - 6} y={y(tick)} dy="0.32em" textAnchor="end" className="fill-muted-foreground text-[10px] tabular-nums">
              {tick}
            </text>
          </g>
        ))}
        {points.map((p, i) =>
          i % every === 0 && cx(i) <= width - MARGIN.right - 36 ? (
            <text
              key={p.t}
              x={cx(i)}
              y={HEIGHT - 8}
              textAnchor={cx(i) < MARGIN.left + 36 ? 'start' : 'middle'}
              className="fill-muted-foreground font-mono text-[10px]"
            >
              {utcLabel(p.t)}
            </text>
          ) : null,
        )}
        {active !== null && (
          <line x1={cx(active)} x2={cx(active)} y1={MARGIN.top} y2={MARGIN.top + innerH} className="stroke-muted-foreground" strokeDasharray="3 3" />
        )}
        {kind === 'bar' ? (
          points.map((p, i) => {
            const d = bar(p, i)
            return d ? <path key={p.t} d={d} className="fill-chart-series" opacity={active === null || active === i ? 1 : 0.55} /> : null
          })
        ) : (
          <>
            <path d={linePath} fill="none" className="stroke-chart-series" strokeWidth={2} strokeLinejoin="round" />
            {showMarkers &&
              points.map((p, i) => <circle key={p.t} cx={cx(i)} cy={y(p.v)} r={4} className="fill-chart-series stroke-card" strokeWidth={2} />)}
            {point && active !== null && (
              <circle cx={cx(active)} cy={y(point.v)} r={5} className="fill-chart-series stroke-card" strokeWidth={2} />
            )}
          </>
        )}
        {points.map((p, i) => (
          <rect
            key={p.t}
            x={MARGIN.left + band * i}
            y={MARGIN.top}
            width={band}
            height={innerH}
            fill="transparent"
            onMouseEnter={() => setActive(i)}
          />
        ))}
      </svg>
      {point && (
        <div
          role="status"
          className="pointer-events-none absolute top-1 z-10 w-40 rounded-sm border bg-popover px-2 py-1.5 text-xs text-popover-foreground"
          style={{ left: tipLeft }}
        >
          <p className="font-mono">{utcLabel(point.t, true)} UTC</p>
          <p>
            <span className="text-muted-foreground">{yTitle}: </span>
            <span className="font-semibold tabular-nums">{point.v}</span>
          </p>
        </div>
      )}
    </div>
  )
}
