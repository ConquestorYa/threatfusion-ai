import { useEffect, useRef, useState } from 'react'

// Streamlit's "connection rhythm" (ui_behavior._rhythm_chart): every
// connection is a tick on a local-time line, so a steady check-in looks like
// an even comb. One series colour, recessive axis, local "dd.mm HH:MM" labels.

const HEIGHT = 56
const AXIS = 16
const pad = (n: number) => String(n).padStart(2, '0')
const clock = (seconds: number) => {
  const d = new Date(seconds * 1000)
  return `${pad(d.getDate())}.${pad(d.getMonth() + 1)} ${pad(d.getHours())}:${pad(d.getMinutes())}`
}

export function RhythmChart({ times, label }: { times: number[]; label: string }) {
  const ref = useRef<HTMLDivElement>(null)
  const [width, setWidth] = useState(480)
  useEffect(() => {
    const element = ref.current
    if (!element) return
    const update = () => setWidth(Math.max(200, Math.floor(element.getBoundingClientRect().width)))
    update()
    const observer = new ResizeObserver(update)
    observer.observe(element)
    return () => observer.disconnect()
  }, [])
  if (!times.length) return null
  const first = Math.min(...times)
  const last = Math.max(...times)
  const span = Math.max(last - first, 1)
  const inner = width - 8
  const x = (t: number) => 4 + ((t - first) / span) * inner
  const labels = width >= 360 ? [first, first + span / 2, last] : [first, last]
  return (
    <div ref={ref} className="w-full">
      <svg width={width} height={HEIGHT} role="img" aria-label={label} className="block">
        <title>{label}</title>
        <line x1={4} x2={width - 4} y1={HEIGHT - AXIS} y2={HEIGHT - AXIS} className="stroke-border" strokeWidth={1} />
        {times.map((t, index) => (
          <line
            key={index}
            x1={x(t)}
            x2={x(t)}
            y1={6}
            y2={HEIGHT - AXIS}
            className="stroke-chart-series"
            strokeWidth={2}
          />
        ))}
        {labels.map((t, index) => (
          <text
            key={index}
            x={x(t)}
            y={HEIGHT - 3}
            textAnchor={index === 0 ? 'start' : index === labels.length - 1 ? 'end' : 'middle'}
            className="fill-muted-foreground font-mono text-[10px]"
          >
            {clock(t)}
          </text>
        ))}
      </svg>
    </div>
  )
}
