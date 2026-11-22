import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { PreferencesProvider } from '@/lib/preferences'
import { Evaluation } from './Evaluation'

const BEHAVIOR = {
  state: 'ok',
  subtitle: "Inspect the frozen model's measured performance and its limits.",
  report: {
    kind: 'behavior',
    state: 'ok',
    title: 'Experimental behavior model',
    caption: 'Model synthetic-demo · trained 22.11 12:46 · test grade: development',
    metrics: [{ label: 'Caught in testing', value: '%56' }, { label: 'Score line', value: 80 }],
    verdict: { kind: 'warning', text: 'Did not pass every declared test; treat its hints with extra care.' },
    declared: { title: 'Declared tests (fixed before the results were seen)', columns: ['Test', 'Result', 'Limit', 'Passed'], rows: [['T1', '%71', '≥ %50', true]] },
    data: { columns: ['Data', 'Caught'], rows: [['Never-seen test recordings', '%56']] },
    importance: { title: 'What the model looks at most', bars: [{ label: 'Steady rhythm', value: 1 }], columns: ['Feature', 'Importance'], rows: [['Steady rhythm', 1]] },
    limits_title: 'Limits',
    limits: '- The malware recordings are lab infections.\n- Labels are approximate.',
    guide_title: 'What is this?',
    guide: '**What is this?** A model.',
  },
}
const LEXICAL = {
  state: 'ok',
  subtitle: 's',
  report: {
    kind: 'lexical',
    state: 'not_evaluated',
    guide_title: 'What does this page do?',
    guide: '**What it is for:** a test.',
    guide_open: true,
    title: 'Final holdout not evaluated',
    text: 'Not measured yet.',
    caption: 'Development status.',
    command_title: 'Show final-evaluation command',
    command: 'python scripts/evaluate_ml_final_holdout.py',
  },
}

let body: unknown
beforeEach(() => {
  window.localStorage.setItem('tf-lang', 'en')
  body = BEHAVIOR
  vi.stubGlobal('fetch', vi.fn(async (url: string) => (url.startsWith('/api/evaluation') ? Response.json(body) : Response.json({}))))
})
afterEach(() => vi.unstubAllGlobals())

const renderPage = () =>
  render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <PreferencesProvider>
        <Evaluation />
      </PreferencesProvider>
    </QueryClientProvider>,
  )

describe('Model evaluation', () => {
  it('shows the behavior model report with tests, chart and bulleted limits', async () => {
    renderPage()
    const report = await screen.findByRole('region', { name: 'Experimental behavior model' })
    expect(report).toHaveTextContent('%56')
    expect(screen.getByRole('alert')).toHaveTextContent('Did not pass every declared test')
    expect(screen.getByRole('region', { name: 'Declared tests (fixed before the results were seen) · table' })).toHaveTextContent('Yes')
    expect(screen.getByRole('img', { name: 'What the model looks at most' })).toHaveTextContent('Steady rhythm')
    expect(screen.getAllByRole('listitem').map((item) => item.textContent)).toEqual([
      'The malware recordings are lab infections.',
      'Labels are approximate.',
    ])
  })

  it('shows the not-evaluated lexical state with its guide open and the command folded', async () => {
    body = LEXICAL
    renderPage()
    expect(await screen.findByRole('region', { name: 'Final holdout not evaluated' })).toHaveTextContent('Not measured yet.')
    expect(screen.getByRole('button', { name: 'What does this page do?' })).toHaveAttribute('aria-expanded', 'true')
    await userEvent.click(screen.getByRole('button', { name: 'Show final-evaluation command' }))
    expect(screen.getByText('python scripts/evaluate_ml_final_holdout.py')).toBeInTheDocument()
  })
})
