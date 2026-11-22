import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { RefreshCw } from 'lucide-react'
import { useEffect, useId, useState, type FormEvent, type ReactNode } from 'react'

import { Blocks, Notice } from '@/components/data/Blocks'
import { DataTable } from '@/components/data/DataTable'
import { Markdown } from '@/components/data/Markdown'
import { Button } from '@/components/ui/button'
import {
  fetchSetup,
  forgetKeys,
  saveKeys,
  saveMode,
  saveSchedule,
  startRefresh,
  stopApplication,
  type SetupOk,
} from '@/lib/api'
import { usePreferences } from '@/lib/preferences'
import { cn } from 'cn'

export function Setup() {
  const { lang, t, chrome } = usePreferences()
  const setup = useQuery({
    queryKey: ['setup', lang],
    queryFn: () => fetchSetup(lang),
    // Streamlit polls a running update every 2 s and the status every 10 s.
    refetchInterval: (query) => (query.state.data?.state === 'ok' && query.state.data.cti?.running ? 2_000 : 10_000),
  })
  const heading = <h1 className="text-lg font-semibold tracking-tight">{t('Setup & CTI updates')}</h1>

  if (setup.isPending) {
    return (
      <>
        {heading}
        <p className="py-12 text-muted-foreground">{chrome('loading')}</p>
      </>
    )
  }
  if (setup.isError) {
    return (
      <>
        {heading}
        <Notice tone="warn">{chrome('offline')}</Notice>
      </>
    )
  }
  const data = setup.data
  if (data.state !== 'ok') {
    return (
      <>
        {heading}
        <Notice tone={data.state === 'unreadable' ? 'warn' : 'info'}>
          {data.state === 'unreadable'
            ? t('Local settings could not be read. Check private file permissions.')
            : chrome('setupManagedOnly')}
        </Notice>
      </>
    )
  }
  return (
    <div className="space-y-4">
      <div className="space-y-1">
        {heading}
        <p className="text-xs text-muted-foreground">{t('Operating mode, your own API keys and threat-intelligence updates.')}</p>
        <p className="text-xs text-muted-foreground">{data.caption}</p>
      </div>
      <div className="grid gap-4 lg:grid-cols-2 lg:gap-6">
        <div className="space-y-4">
          <Mode data={data} />
          {data.demo_note && <Notice tone="info">{data.demo_note}</Notice>}
          {data.keys && <Keys keys={data.keys} />}
        </div>
        {data.cti && data.schedule && (
          <div className="space-y-4">
            <Cti cti={data.cti} />
            <Schedule schedule={data.schedule} />
          </div>
        )}
      </div>
      <Panel title={data.application.title}>
        <p className="text-xs text-muted-foreground">{data.application.caption}</p>
        <StopApplication application={data.application} />
        <CommandHint text={data.application.streamlit} />
      </Panel>
      {data.sources && (
        <Panel title={data.sources.title}>
          <DataTable table={data.sources} label={`${data.sources.title} · ${chrome('table')}`} maxHeight="max-h-80" />
          <p className="text-xs text-muted-foreground">{data.sources.caption}</p>
        </Panel>
      )}
    </div>
  )
}

function Panel({ title, children, className }: { title: string; children: ReactNode; className?: string }) {
  return (
    <section aria-label={title} className={cn('space-y-2.5 rounded-sm border bg-card p-3', className)}>
      <h2 className="text-[13px] font-semibold">{title}</h2>
      {children}
    </section>
  )
}

/** Sentence in the UI font, the command itself (after the colon) in the data font. */
function CommandHint({ text }: { text: string }) {
  const [sentence, command] = text.split(/:\s+(?=threatfusion-ai)/)
  return (
    <p className="text-xs text-muted-foreground">
      {command ? (
        <>
          {sentence}: <code className="rounded-sm bg-muted px-1 font-mono text-foreground">{command}</code>
        </>
      ) : (
        text
      )}
    </p>
  )
}

/** "Stop local application": asks the launcher to stop (ui_local_settings). */
function StopApplication({ application }: { application: SetupOk['application'] }) {
  const stop = useMutation({ mutationFn: stopApplication })
  return (
    <div className="space-y-2">
      <Button variant="outline" size="sm" disabled={stop.isPending || stop.data?.stopping} onClick={() => stop.mutate()}>
        {application.stop}
      </Button>
      {stop.data && <Notice tone="info">{stop.data.stopping ? application.stopping : application.not_running}</Notice>}
      {stop.isError && <Notice tone="warn">{stop.error.message}</Notice>}
    </div>
  )
}

function Mode({ data }: { data: SetupOk }) {
  const queryClient = useQueryClient()
  const id = useId()
  const change = useMutation({
    mutationFn: saveMode,
    // Earlier results used the previous mode's data (Streamlit clears them too).
    onSettled: () => queryClient.invalidateQueries(),
  })
  return (
    <Panel title={data.mode.title}>
      <label htmlFor={id} className="sr-only">
        {data.mode.title}
      </label>
      <select
        id={id}
        value={data.mode.value}
        disabled={change.isPending}
        onChange={(event) => change.mutate(event.target.value as 'cti-only' | 'demo')}
        className="h-9 w-full rounded-sm border bg-background px-2 text-[13px] focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
      >
        {data.mode.options.map((option) => (
          <option key={option.value} value={option.value}>
            {option.label}
          </option>
        ))}
      </select>
      {change.isError && <Notice tone="warn">{change.error.message}</Notice>}
    </Panel>
  )
}

function Keys({ keys }: { keys: NonNullable<SetupOk['keys']> }) {
  const { chrome } = usePreferences()
  const queryClient = useQueryClient()
  const formId = useId()
  const [values, setValues] = useState({ threatfox: '', urlhaus: '' })
  const [result, setResult] = useState<'applied' | 'invalid' | null>(null)
  const apply = useMutation({
    mutationFn: saveKeys,
    onSuccess: () => setResult('applied'),
    onError: () => setResult('invalid'),
    onSettled: () => {
      setValues({ threatfox: '', urlhaus: '' }) // never keep keys in the page (clear_on_submit)
      queryClient.invalidateQueries({ queryKey: ['setup'] })
    },
  })
  const forget = useMutation({
    mutationFn: forgetKeys,
    onSettled: () => {
      setResult(null)
      queryClient.invalidateQueries({ queryKey: ['setup'] })
    },
  })
  const submit = (event: FormEvent) => {
    event.preventDefault()
    apply.mutate(values)
  }
  return (
    <Panel title={keys.title}>
      <p className="text-xs text-muted-foreground">{keys.caption}</p>
      <p className="text-xs text-muted-foreground">{keys.saved}</p>
      {keys.missing && (
        <Notice tone="info">
          <Markdown text={keys.missing} />
        </Notice>
      )}
      <form onSubmit={submit} className="space-y-2.5" autoComplete="off">
        {keys.fields.map((field) => (
          <div key={field.name} className="flex flex-col gap-1">
            <label htmlFor={`${formId}-${field.name}`} className="text-xs text-muted-foreground">
              {field.label}
            </label>
            <input
              id={`${formId}-${field.name}`}
              type="password"
              autoComplete="new-password"
              spellCheck={false}
              maxLength={512}
              value={values[field.name]}
              onChange={(event) => setValues((current) => ({ ...current, [field.name]: event.target.value }))}
              className="h-9 rounded-sm border bg-background px-2 font-mono text-[13px] focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
            />
          </div>
        ))}
        <p className="text-xs text-muted-foreground">{chrome('keysStorage')}</p>
        <div className="flex flex-wrap gap-2">
          <Button type="submit" variant="outline" disabled={apply.isPending}>
            {keys.apply}
          </Button>
          <Button type="button" variant="ghost" disabled={forget.isPending} onClick={() => forget.mutate()}>
            {keys.forget}
          </Button>
        </div>
      </form>
      {result === 'applied' && <Notice tone="info">{keys.applied}</Notice>}
      {result === 'invalid' && <Notice tone="warn">{keys.invalid}</Notice>}
    </Panel>
  )
}

function Cti({ cti }: { cti: NonNullable<SetupOk['cti']> }) {
  const queryClient = useQueryClient()
  const forceId = useId()
  const [force, setForce] = useState(false)
  const [started, setStarted] = useState(false)
  const refresh = useMutation({
    mutationFn: startRefresh,
    onSuccess: (result) => {
      setStarted(result.started)
      setForce(false) // one-shot, like Streamlit
    },
    onSettled: () => queryClient.invalidateQueries({ queryKey: ['setup'] }),
  })
  useEffect(() => {
    if (!cti.running) return
    const timer = window.setTimeout(() => setStarted(false), 4000)
    return () => window.clearTimeout(timer)
  }, [cti.running])

  return (
    <Panel title={cti.title}>
      <label htmlFor={forceId} className="flex min-h-8 cursor-pointer items-start gap-2 text-[13px]" title={cti.force_help}>
        <input
          id={forceId}
          type="checkbox"
          checked={force}
          disabled={cti.running}
          onChange={(event) => setForce(event.target.checked)}
          className="mt-0.5 size-4 accent-foreground"
        />
        <span>
          {cti.force_label}
          <span className="block text-xs text-muted-foreground">{cti.force_help}</span>
        </span>
      </label>
      <Button
        disabled={cti.running || refresh.isPending}
        title={cti.running ? cti.busy : undefined}
        onClick={() => refresh.mutate(force)}
      >
        <RefreshCw aria-hidden className={cn(cti.running && 'animate-spin')} /> {cti.button}
      </Button>
      {started && <Notice tone="info">{cti.started}</Notice>}
      {refresh.isError && <Notice tone="warn">{refresh.error.message}</Notice>}
      {cti.due && <p className="text-xs text-muted-foreground">{cti.due}</p>}
      {cti.progress && (
        <div className="space-y-1">
          <div
            role="progressbar"
            aria-valuemin={0}
            aria-valuemax={100}
            aria-valuenow={cti.progress.percent}
            aria-label={cti.progress.label}
            className="h-1.5 overflow-hidden rounded-sm bg-muted"
          >
            <span className="block h-full bg-foreground transition-[width]" style={{ width: `${cti.progress.percent}%` }} />
          </div>
          <p className="text-xs">{cti.progress.label}</p>
          <p className="text-xs text-muted-foreground">{cti.progress.caption}</p>
        </div>
      )}
      {cti.summary && <Notice tone={cti.summary.kind === 'warning' ? 'warn' : 'info'}>{cti.summary.text}</Notice>}
      <Blocks blocks={cti.status} />
    </Panel>
  )
}

function Schedule({ schedule }: { schedule: NonNullable<SetupOk['schedule']> }) {
  const queryClient = useQueryClient()
  const automaticId = useId()
  const intervalId = useId()
  const [automatic, setAutomatic] = useState(schedule.automatic)
  const [hours, setHours] = useState(schedule.interval_hours)
  const save = useMutation({
    mutationFn: () => saveSchedule(automatic, hours),
    onSettled: () => queryClient.invalidateQueries({ queryKey: ['setup'] }),
  })
  const submit = (event: FormEvent) => {
    event.preventDefault()
    save.mutate()
  }
  return (
    <Panel title={schedule.title}>
      <form onSubmit={submit} className="space-y-2.5">
        <label htmlFor={automaticId} className="flex min-h-8 cursor-pointer items-center gap-2 text-[13px]">
          <input
            id={automaticId}
            type="checkbox"
            checked={automatic}
            onChange={(event) => setAutomatic(event.target.checked)}
            className="size-4 accent-foreground"
          />
          {schedule.automatic_label}
        </label>
        <div className="flex flex-col gap-1">
          <label htmlFor={intervalId} className="text-xs text-muted-foreground">
            {schedule.interval_label}
          </label>
          <select
            id={intervalId}
            value={hours}
            onChange={(event) => setHours(Number(event.target.value))}
            className="h-9 w-32 rounded-sm border bg-background px-2 text-[13px] tabular-nums focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
          >
            {schedule.options.map((option) => (
              <option key={option} value={option}>
                {option}
              </option>
            ))}
          </select>
        </div>
        <p className="text-xs text-muted-foreground">{schedule.caption}</p>
        <Button type="submit" variant="outline" disabled={save.isPending}>
          {schedule.button}
        </Button>
        {save.isError && <Notice tone="warn">{save.error.message}</Notice>}
      </form>
    </Panel>
  )
}
