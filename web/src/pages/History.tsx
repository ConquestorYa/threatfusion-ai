import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { ChevronDown } from 'lucide-react'
import { useId, useMemo, useState, type ReactNode } from 'react'

import { MetricStrip, Notice } from '@/components/data/Blocks'
import { Check, Select } from '@/components/data/Controls'
import { DataTable } from '@/components/data/DataTable'
import { Button } from '@/components/ui/button'
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible'
import {
  applyRetention,
  deleteRun,
  fetchHistory,
  saveBulkFeedback,
  saveFeedback,
  type FeedbackLabel,
  type HistoryOk,
  type Table,
} from '@/lib/api'
import { usePreferences } from '@/lib/preferences'

/** "Analysis history": saved runs, comparison and analyst decisions (ui_history._show_history). */
export function History() {
  const { lang, t, chrome } = usePreferences()
  const [run, setRun] = useState<number | null>(null)
  // Outcome of a deletion survives the run it described disappearing.
  const [notice, setNotice] = useState<string | null>(null)
  const history = useQuery({
    queryKey: ['history', lang, run],
    queryFn: () => fetchHistory(lang, run),
    placeholderData: keepPreviousData,
    retry: 1,
  })
  const heading = <h1 className="text-lg font-semibold tracking-tight">{t('Analysis history')}</h1>
  if (history.isPending) {
    return (
      <>
        {heading}
        <p className="py-12 text-muted-foreground">{chrome('loading')}</p>
      </>
    )
  }
  if (history.isError || history.data.state === 'disabled') {
    return (
      <>
        {heading}
        <Notice tone="warn">{chrome('offline')}</Notice>
      </>
    )
  }
  const data = history.data
  return (
    <div className="space-y-4">
      <div className="space-y-1">
        {heading}
        <p className="text-xs text-muted-foreground">{data.subtitle}</p>
      </div>
      {notice && (
        <p role="status" className="rounded-sm border bg-card px-3 py-2 text-[13px]">
          {notice}
        </p>
      )}
      {data.state === 'empty' ? (
        <div className="rounded-sm border border-dashed px-4 py-8 text-center">
          <p className="font-medium">{data.title}</p>
          <p className="text-xs text-muted-foreground">{data.text}</p>
        </div>
      ) : (
        <Saved data={data} onRun={setRun} onNotice={setNotice} />
      )}
    </div>
  )
}

function Fold({ title, children }: { title: string; children: ReactNode }) {
  return (
    <Collapsible className="rounded-sm border bg-card">
      <CollapsibleTrigger className="group flex min-h-11 w-full items-center gap-2 px-3 py-2 text-left text-[13px] font-medium focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none lg:min-h-0">
        <ChevronDown aria-hidden className="size-4 transition-transform group-data-[state=open]:rotate-180" />
        {title}
      </CollapsibleTrigger>
      <CollapsibleContent className="space-y-2 border-t px-3 py-3">{children}</CollapsibleContent>
    </Collapsible>
  )
}

function Titled({ table }: { table: (Table & { title: string }) | null }) {
  const { chrome } = usePreferences()
  if (!table) return null
  return (
    <>
      <p className="text-[13px] font-semibold">{table.title}</p>
      <DataTable table={table} label={`${table.title} · ${chrome('table')}`} maxHeight="max-h-72" />
    </>
  )
}

function Saved({
  data,
  onRun,
  onNotice,
}: {
  data: HistoryOk
  onRun: (run: number | null) => void
  onNotice: (message: string) => void
}) {
  const { t, chrome } = usePreferences()
  const meta = data.metadata
  return (
    <>
      <DataTable table={data.runs} label={`${t('Analysis history')} · ${chrome('table')}`} maxHeight="max-h-72" />
      <Fold title={data.all_runs_title}>
        <DataTable table={data.all_runs} label={`${data.all_runs_title} · ${chrome('table')}`} maxHeight="max-h-72" />
      </Fold>
      <Select
        label={data.run_label}
        value={String(data.run)}
        options={data.run_ids.map((id) => ({ value: String(id), label: String(id) }))}
        onChange={(value) => onRun(Number(value))}
      />
      <Fold title={data.metadata_title}>
        {'legacy' in meta ? (
          <p className="text-xs text-muted-foreground">{meta.legacy}</p>
        ) : (
          <>
            <p className="text-[13px]">{meta.captured}</p>
            <p className="text-[13px]">{meta.artifact}</p>
            <pre className="overflow-x-auto rounded-sm bg-muted px-2 py-1.5 font-mono text-[12px]">{meta.checksum}</pre>
            <p className="text-xs text-muted-foreground">{meta.schemas}</p>
            {meta.thresholds && <p className="text-[13px] tabular-nums">{meta.thresholds}</p>}
            <Titled table={meta.sources} />
            {meta.no_sources && <p className="text-xs text-muted-foreground">{meta.no_sources}</p>}
          </>
        )}
      </Fold>
      <Fold title={data.comparison.title}>
        <p className="text-xs text-muted-foreground">{data.comparison.caption}</p>
        <MetricStrip metrics={data.comparison.metrics} />
        <Titled table={data.comparison.new} />
        <Titled table={data.comparison.removed} />
        <Titled table={data.comparison.changes} />
      </Fold>
      <Findings key={data.run} data={data} />
      <Retention key={`r${data.run}`} data={data} onRun={onRun} onNotice={onNotice} />
    </>
  )
}

function Findings({ data }: { data: HistoryOk }) {
  const { chrome } = usePreferences()
  const findings = data.findings
  const [verdict, setVerdict] = useState('All')
  const [review, setReview] = useState('All')
  const [source, setSource] = useState('All')
  // Same filters as Streamlit, applied to the rows the server built.
  const visible = useMemo(
    () =>
      findings.rows.flatMap((_row, index) => {
        const feedback = findings.feedback[index]
        if (verdict !== 'All' && findings.verdicts[index] !== verdict) return []
        if (review === 'Unreviewed' && feedback !== 'Not reviewed') return []
        if (review === 'Reviewed' && feedback === 'Not reviewed') return []
        if (!['All', 'Unreviewed', 'Reviewed'].includes(review) && feedback !== review) return []
        if (source !== 'All' && !findings.sources[index].includes(source)) return []
        return [index]
      }),
    [findings, verdict, review, source],
  )
  const domains = visible.length ? visible.map((index) => findings.domains[index]) : findings.domains
  return (
    <>
      <div className="grid gap-3 sm:grid-cols-3">
        <Select label={findings.verdict_label} value={verdict} options={findings.verdict_options} onChange={setVerdict} />
        <Select label={findings.review_label} value={review} options={findings.review_options} onChange={setReview} />
        <Select label={findings.source_label} value={source} options={findings.source_options} onChange={setSource} />
      </div>
      {visible.length ? (
        <DataTable
          table={{ columns: findings.columns, rows: visible.map((index) => findings.rows[index]) }}
          label={`${data.review.title} · ${chrome('table')}`}
        />
      ) : (
        <Notice tone="info">{findings.empty}</Notice>
      )}
      <Review data={data} domains={domains} />
    </>
  )
}

function Review({ data, domains }: { data: HistoryOk; domains: string[] }) {
  const { t } = usePreferences()
  const queryClient = useQueryClient()
  const review = data.review
  const noteId = useId()
  const [chosen, setChosen] = useState<string | null>(null)
  const domain = chosen !== null && domains.includes(chosen) ? chosen : domains[0]
  const current = review.current[domain]
  const [draft, setDraft] = useState<{ domain: string; label: FeedbackLabel; note: string } | null>(null)
  const form =
    draft?.domain === domain
      ? draft
      : {
          domain,
          label: (['Confirmed Threat', 'Benign', 'Uncertain'].includes(current?.label ?? '') ? current!.label : 'Uncertain') as FeedbackLabel,
          note: current?.note ?? '',
        }
  const [message, setMessage] = useState<string | null>(null)
  const save = useMutation({
    mutationFn: () => saveFeedback(data.run, { domain: form.domain, label: form.label, note: form.note }),
    onSuccess: () => {
      setMessage(review.saved)
      setDraft(null)
      queryClient.invalidateQueries({ queryKey: ['history'] })
    },
  })
  return (
    <section aria-label={review.title} className="space-y-2.5 border-t pt-4">
      <h2 className="text-base font-semibold tracking-tight">{review.title}</h2>
      <p className="max-w-[100ch] text-xs text-muted-foreground">{review.caption}</p>
      <Bulk data={data} candidates={domains} onSaved={setMessage} />
      <form
        className="space-y-2 rounded-sm border bg-card p-3"
        onSubmit={(event) => {
          event.preventDefault()
          save.mutate()
        }}
      >
        <div className="grid gap-3 sm:grid-cols-2">
          <Select mono label={review.domain_label} value={domain} options={domains.map((d) => ({ value: d, label: d }))} onChange={setChosen} />
          <Select
            label={review.label}
            value={form.label}
            options={review.options}
            onChange={(value) => setDraft({ ...form, label: value as FeedbackLabel })}
          />
        </div>
        <label htmlFor={noteId} className="flex flex-col gap-1 text-xs text-muted-foreground">
          {review.note_label}
          <textarea
            id={noteId}
            value={form.note}
            maxLength={500}
            rows={2}
            onChange={(event) => setDraft({ ...form, note: event.target.value })}
            className="rounded-sm border bg-card px-2 py-1.5 text-[13px] text-foreground focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
          />
        </label>
        <Button type="submit" size="sm" disabled={save.isPending}>
          {review.button}
        </Button>
        {save.isError && <Notice tone="warn">{t('Could not save. Check the folder permissions.')}</Notice>}
      </form>
      {message && (
        <p role="status" className="text-xs text-muted-foreground">
          {message}
        </p>
      )}
    </section>
  )
}

function Bulk({ data, candidates, onSaved }: { data: HistoryOk; candidates: string[]; onSaved: (message: string) => void }) {
  const queryClient = useQueryClient()
  const review = data.review
  const noteId = useId()
  const [selected, setSelected] = useState<string[]>([])
  const [label, setLabel] = useState<FeedbackLabel>('Confirmed Threat')
  const [note, setNote] = useState('')
  const [confirm, setConfirm] = useState(false)
  const chosen = selected.filter((domain) => candidates.includes(domain))
  const save = useMutation({
    mutationFn: () => saveBulkFeedback(data.run, { domains: chosen, label, note }),
    onSuccess: (result) => {
      onSaved(review.bulk_saved.replace('{count}', String(result.count)))
      setSelected([])
      setConfirm(false)
      queryClient.invalidateQueries({ queryKey: ['history'] })
    },
  })
  return (
    <Fold title={review.bulk_title}>
      <fieldset className="space-y-1">
        <legend className="text-xs text-muted-foreground">{review.bulk_domains_label}</legend>
        <div className="max-h-48 space-y-0.5 overflow-y-auto rounded-sm border px-2 py-1">
          {candidates.map((domain) => (
            <label key={domain} className="flex min-h-8 cursor-pointer items-center gap-2 font-mono text-[12.5px] break-all">
              <input
                type="checkbox"
                className="size-4 shrink-0 accent-foreground"
                checked={chosen.includes(domain)}
                onChange={(event) =>
                  setSelected((current) => (event.target.checked ? [...current, domain] : current.filter((d) => d !== domain)))
                }
              />
              {domain}
            </label>
          ))}
        </div>
      </fieldset>
      <Select label={review.bulk_label} value={label} options={review.options} onChange={(value) => setLabel(value as FeedbackLabel)} />
      <label htmlFor={noteId} className="flex flex-col gap-1 text-xs text-muted-foreground">
        {review.bulk_note_label}
        <textarea
          id={noteId}
          value={note}
          maxLength={500}
          rows={2}
          onChange={(event) => setNote(event.target.value)}
          className="rounded-sm border bg-card px-2 py-1.5 text-[13px] text-foreground focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
        />
      </label>
      <Check label={review.bulk_confirm} checked={confirm} onChange={setConfirm} />
      <Button size="sm" disabled={!chosen.length || !confirm || save.isPending} onClick={() => save.mutate()}>
        {review.bulk_button}
      </Button>
    </Fold>
  )
}

function Retention({
  data,
  onRun,
  onNotice,
}: {
  data: HistoryOk
  onRun: (run: number | null) => void
  onNotice: (message: string) => void
}) {
  const { lang } = usePreferences()
  const queryClient = useQueryClient()
  const retention = data.retention
  const keepId = useId()
  const [deleteConfirm, setDeleteConfirm] = useState(false)
  const [keep, setKeep] = useState(retention.keep_default)
  const [keepConfirm, setKeepConfirm] = useState(false)
  const remove = useMutation({
    mutationFn: () => deleteRun(data.run),
    onSuccess: () => {
      onNotice(retention.deleted)
      onRun(null)
      queryClient.invalidateQueries({ queryKey: ['history'] })
    },
  })
  const trim = useMutation({
    mutationFn: () => applyRetention(lang, keep),
    onSuccess: (result) => {
      onNotice(result.message)
      setKeepConfirm(false)
      onRun(null)
      queryClient.invalidateQueries({ queryKey: ['history'] })
    },
  })
  return (
    <Fold title={retention.title}>
      <Notice tone="warn">{retention.warning}</Notice>
      <Check label={retention.delete_confirm} checked={deleteConfirm} onChange={setDeleteConfirm} />
      <Button variant="outline" size="sm" disabled={!deleteConfirm || remove.isPending} onClick={() => remove.mutate()}>
        {retention.delete_button}
      </Button>
      <div className="space-y-2 border-t pt-3">
        <label htmlFor={keepId} className="flex max-w-xs flex-col gap-1 text-xs text-muted-foreground">
          {retention.keep_label}
          <input
            id={keepId}
            type="number"
            min={1}
            max={1000}
            value={keep}
            onChange={(event) => setKeep(Math.max(1, Math.min(1000, Number(event.target.value) || 1)))}
            className="h-9 rounded-sm border bg-card px-2 text-[13px] text-foreground tabular-nums focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
          />
        </label>
        <Check label={retention.keep_confirm} checked={keepConfirm} onChange={setKeepConfirm} />
        <Button variant="outline" size="sm" disabled={!keepConfirm || trim.isPending} onClick={() => trim.mutate()}>
          {retention.keep_button}
        </Button>
      </div>
    </Fold>
  )
}
