import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { TooltipProvider } from '@/components/ui/tooltip'
import { PreferencesProvider } from '@/lib/preferences'
import { Behavior } from './Behavior'

const CARD = {
  key: 'ml:198.51.100.20:443',
  kind: 'ml',
  title: '198.51.100.20',
  mark: null,
  shown_mark: null,
  device: '192.0.2.10',
  destination: '198.51.100.20:443/tcp',
  owner: null,
  others: null,
  score_label: 'Behavior score',
  score: '95/100',
  level: 'High',
  why_label: 'Why it stands out',
  why: ['Repeats at steady intervals', 'No website name (direct IP)'],
  rhythm: { caption: 'Connection rhythm · 3 connections, 22.11 10:00 – 22.11 10:10', times: [1763805600, 1763805900, 1763806200] },
  advice_title: 'What should I do?',
  advice: '1. **Do you recognize it?** Mark it.',
  command: 'ss -tunp dst 198.51.100.20',
  links_caption: 'Opens in a new tab; the name or IP is sent to that site.',
  links: [{ name: 'AbuseIPDB', url: 'https://www.abuseipdb.com/check/198.51.100.20' }],
}
const BODY = {
  state: 'ok',
  caption: 'Experimental · a machine-learning hint beside What to check, never a verdict',
  new: {
    state: 'ok',
    title: 'New for this computer',
    summary: null,
    notice: { kind: 'info', text: 'Learning what is normal for this computer.' },
    cards: [],
    captions: [],
    guide_title: 'What is this?',
    guide: '**What is this?** New destinations.',
  },
  model: {
    state: 'ok',
    title: 'Behavior model',
    heading: '1 connection(s) stand out',
    summary: 'In the last 48 hours the model checked how 1 device(s) talked to 2 destination(s).',
    metrics: [
      { label: 'Stands out', value: 1 },
      { label: 'Caught in testing', value: '%56', help: 'Share of never-seen malware recordings.' },
    ],
    cards: [CARD],
    captions: [],
    below: { title: 'Highest scores below the line', columns: ['Destination', 'Score'], rows: [['quiet.example.test', '10/100 · Low']] },
    guide_title: 'What is this?',
    guide: '**How to use it:** a reason to look.',
    model_caption: 'Model synthetic-demo · trained 22.11 10:00 · test grade: development',
  },
}

let puts: { url: string; body: string }[]
beforeEach(() => {
  window.localStorage.setItem('tf-lang', 'en')
  puts = []
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string, init?: RequestInit) => {
      if (url.startsWith('/api/behavior/marks')) {
        puts.push({ url, body: String(init?.body) })
        return new Response(null, { status: 204 })
      }
      if (url.startsWith('/api/behavior')) return Response.json(BODY)
      return Response.json({})
    }),
  )
})
afterEach(() => vi.unstubAllGlobals())

const renderPage = () =>
  render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <PreferencesProvider>
        <TooltipProvider>
          <Behavior />
        </TooltipProvider>
      </PreferencesProvider>
    </QueryClientProvider>,
  )

describe('Experimental ML', () => {
  it('shows new destinations, then the model with its card, rhythm and metrics', async () => {
    renderPage()
    const card = await screen.findByRole('article', { name: '198.51.100.20' })
    expect(screen.getByRole('heading', { level: 1 })).toHaveTextContent('Experimental ML')
    const parts = screen.getAllByRole('region')
    expect(parts[0]).toHaveAccessibleName('New for this computer')
    expect(within(parts[0]).getByRole('status')).toHaveTextContent('Learning what is normal')
    expect(card).toHaveTextContent('95/100')
    expect(card).toHaveTextContent('Why it stands out: Repeats at steady intervals · No website name (direct IP)')
    expect(within(card).getByRole('img', { name: /Connection rhythm/ })).toBeInTheDocument()
    expect(screen.getByText('Caught in testing: Share of never-seen malware recordings.')).toBeInTheDocument()
    expect(screen.getByText(/Model synthetic-demo/)).toBeInTheDocument()
  })

  it('marks a card through the behavior endpoint and opens the advice', async () => {
    renderPage()
    const card = await screen.findByRole('article', { name: '198.51.100.20' })
    await userEvent.click(within(card).getByRole('button', { name: 'I know this' }))
    expect(puts).toEqual([{ url: '/api/behavior/marks', body: JSON.stringify({ key: CARD.key, mark: 'known' }) }])
    await userEvent.click(within(card).getByRole('button', { name: 'What should I do?' }))
    expect(within(card).getByText('ss -tunp dst 198.51.100.20')).toBeInTheDocument()
    expect(within(card).getByRole('link', { name: 'AbuseIPDB' })).toHaveAttribute('rel', 'noopener noreferrer')
  })

  it('explains when no collector is configured', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => Response.json({ state: 'not_configured' })))
    renderPage()
    expect(await screen.findByRole('status')).toHaveTextContent('Configure a local collector')
  })
})
