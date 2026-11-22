import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { PreferencesProvider } from '@/lib/preferences'
import { History } from './History'

const option = (value: string) => ({ value, label: value })
const BODY = {
  state: 'ok',
  subtitle: 'Revisit saved runs, compare changes and record analyst decisions.',
  runs: { columns: ['Run ID', 'Created at', 'Domains'], rows: [[2, '2026-11-22 10:00 UTC', 2], [1, '2026-11-21 10:00 UTC', 2]] },
  all_runs_title: 'All run statistics',
  all_runs: { columns: ['Run ID'], rows: [[2], [1]] },
  run_label: 'Inspect saved run',
  run_ids: [2, 1],
  run: 2,
  metadata_title: 'Reproducibility metadata',
  metadata: { legacy: 'This is a legacy saved run created before audit metadata was added.' },
  comparison: { title: 'Compare with previous analysis', caption: 'Comparing run #2 with previous run #1.', metrics: [], new: null, removed: null, changes: null },
  findings: {
    columns: ['Domain', 'Verdict', 'Analyst feedback'],
    rows: [
      ['bad.example.test', 'Known Threat', 'Not reviewed'],
      ['docs.example.test', 'Low', 'Benign'],
    ],
    domains: ['bad.example.test', 'docs.example.test'],
    verdicts: ['Known Threat', 'Low'],
    feedback: ['Not reviewed', 'Benign'],
    sources: [['Synthetic demo'], []],
    verdict_label: 'Verdict',
    verdict_options: [option('All'), option('Known Threat'), option('Low')],
    review_label: 'Review state',
    review_options: ['All', 'Unreviewed', 'Reviewed', 'Confirmed Threat', 'Benign', 'Uncertain'].map(option),
    source_label: 'CTI source',
    source_options: [option('All'), option('Synthetic demo')],
    empty: 'No saved findings match the current triage filters.',
  },
  review: {
    title: 'Analyst review',
    caption: 'Feedback is local analyst context only.',
    options: ['Confirmed Threat', 'Benign', 'Uncertain'].map(option),
    current: { 'docs.example.test': { label: 'Benign', note: 'updater' } },
    bulk_title: 'Bulk review selected findings',
    bulk_domains_label: 'Findings to review',
    bulk_label: 'Bulk analyst label',
    bulk_note_label: 'Optional bulk analyst note',
    bulk_confirm: 'Apply this label only to the selected findings.',
    bulk_button: 'Apply bulk review',
    domain_label: 'Finding to review',
    label: 'Analyst label',
    note_label: 'Optional analyst note',
    button: 'Save analyst feedback',
    saved: 'Analyst feedback saved. The original ThreatFusion verdict was not changed.',
    bulk_saved: 'Saved analyst feedback for {count} selected findings.',
  },
  retention: {
    title: 'History retention and deletion',
    warning: 'These controls permanently delete local saved history.',
    delete_confirm: 'I understand run #2 will be permanently deleted.',
    delete_button: 'Delete saved run #2',
    deleted: 'Saved run #2 was deleted.',
    keep_label: 'Retention: keep latest N saved runs',
    keep_default: 2,
    keep_confirm: 'I understand older saved runs beyond this limit will be permanently deleted.',
    keep_button: 'Apply retention cleanup',
    kept_none: 'No saved runs were old enough to delete.',
  },
}

let writes: { url: string; method: string; body: string }[]
beforeEach(() => {
  window.localStorage.setItem('tf-lang', 'en')
  writes = []
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string, init?: RequestInit) => {
      if (init?.method && init.method !== 'GET') {
        writes.push({ url, method: init.method, body: String(init.body) })
        if (url.includes('/bulk')) return Response.json({ count: 1 })
        if (url.includes('/delete')) return Response.json({ deleted: true })
        return new Response(null, { status: 204 })
      }
      if (url.startsWith('/api/history')) return Response.json(BODY)
      return Response.json({})
    }),
  )
})
afterEach(() => vi.unstubAllGlobals())

const renderPage = () =>
  render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <PreferencesProvider>
        <History />
      </PreferencesProvider>
    </QueryClientProvider>,
  )

describe('Analysis history', () => {
  it('lists runs and filters saved findings like Streamlit', async () => {
    renderPage()
    expect(await screen.findByRole('region', { name: 'Analysis history · table' })).toHaveTextContent('2')
    const findings = () => screen.getByRole('region', { name: 'Analyst review · table' })
    expect(within(findings()).getAllByRole('row')).toHaveLength(3)
    await userEvent.selectOptions(screen.getByLabelText('Review state'), 'Unreviewed')
    expect(within(findings()).getAllByRole('row')).toHaveLength(2)
    expect(findings()).toHaveTextContent('bad.example.test')
    await userEvent.selectOptions(screen.getByLabelText('CTI source'), 'Synthetic demo')
    await userEvent.selectOptions(screen.getByLabelText('Verdict'), 'Low')
    expect(screen.getByText('No saved findings match the current triage filters.')).toBeInTheDocument()
  })

  it('saves one finding with its current label and note prefilled', async () => {
    renderPage()
    const domain = await screen.findByLabelText('Finding to review')
    await userEvent.selectOptions(domain, 'docs.example.test')
    expect(screen.getByLabelText('Analyst label')).toHaveValue('Benign')
    expect(screen.getByLabelText('Optional analyst note')).toHaveValue('updater')
    await userEvent.selectOptions(screen.getByLabelText('Analyst label'), 'Confirmed Threat')
    await userEvent.click(screen.getByRole('button', { name: 'Save analyst feedback' }))
    expect(writes).toEqual([
      {
        url: '/api/history/2/feedback',
        method: 'PUT',
        body: JSON.stringify({ domain: 'docs.example.test', label: 'Confirmed Threat', note: 'updater' }),
      },
    ])
    expect(await screen.findByText(BODY.review.saved)).toBeInTheDocument()
  })

  it('bulk review and deletion stay disabled until confirmed', async () => {
    renderPage()
    await userEvent.click(await screen.findByRole('button', { name: 'Bulk review selected findings' }))
    const apply = screen.getByRole('button', { name: 'Apply bulk review' })
    await userEvent.click(screen.getByRole('checkbox', { name: 'bad.example.test' }))
    expect(apply).toBeDisabled()
    await userEvent.click(screen.getByRole('checkbox', { name: BODY.review.bulk_confirm }))
    await userEvent.click(apply)
    expect(writes[0].url).toBe('/api/history/2/feedback/bulk')
    expect(JSON.parse(writes[0].body)).toEqual({ domains: ['bad.example.test'], label: 'Confirmed Threat', note: '', confirm: true })

    await userEvent.click(screen.getByRole('button', { name: 'History retention and deletion' }))
    const remove = screen.getByRole('button', { name: 'Delete saved run #2' })
    expect(remove).toBeDisabled()
    await userEvent.click(screen.getByRole('checkbox', { name: BODY.retention.delete_confirm }))
    await userEvent.click(remove)
    expect(writes[1]).toEqual({ url: '/api/history/2/delete', method: 'POST', body: JSON.stringify({ confirm: true }) })
    expect(await screen.findByText('Saved run #2 was deleted.')).toBeInTheDocument()
  })
})
