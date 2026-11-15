import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import type { ReviewItem, ReviewResponse } from '@/lib/api'
import { TooltipProvider } from '@/components/ui/tooltip'
import { PreferencesProvider } from '@/lib/preferences'
import { WhatToCheck } from './WhatToCheck'

const item = (overrides: Partial<ReviewItem>): ReviewItem => ({
  key: 'dns:cdn.example.test',
  kind: 'dns',
  threat: false,
  title: 'cdn.example.test',
  label: 'Frequent lookups',
  metric: '12 lookups',
  devices: ['Device 001'],
  destination: null,
  owner: null,
  when: '10.10 10:00 – 10.10 11:00',
  what: ['This name was looked up very often.'],
  advice: 'Know the name? Then it is likely fine.',
  facts: [],
  links: [{ name: 'VirusTotal', url: 'https://www.virustotal.com/gui/search/cdn.example.test' }],
  mark: null,
  ...overrides,
})

const OK: ReviewResponse = {
  state: 'ok',
  updated_at: new Date().toISOString(),
  window_hours: 24,
  stale: false,
  coverage_incomplete: false,
  counts: { to_check: 2, suspicious: 0, threat: 1, known: 1 },
  items: [
    item({
      key: 'connection:listed.example.test',
      kind: 'connection',
      threat: true,
      title: 'listed.example.test',
      label: 'On a threat list',
      destination: { host: '203.0.113.7', port: 443 },
      owner: 'Example Net · NL',
    }),
    item({}),
  ],
  items_truncated: false,
  known: [{ key: 'dns:known.example.test', title: 'known.example.test', label: 'Regular lookups' }],
}

let review: ReviewResponse
let calls: { url: string; init?: RequestInit }[]

beforeEach(() => {
  review = OK
  calls = []
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string, init?: RequestInit) => {
      calls.push({ url, init })
      if (url.startsWith('/api/i18n')) {
        const tr = url.endsWith('lang=tr')
        return Response.json(
          tr ? { 'To check': 'Bakılacak', 'Why? What to do?': 'Neden? Ne yapmalı?', '⚠ Suspicious': '⚠ Şüpheli' } : {},
        )
      }
      if (url.startsWith('/api/review/marks')) return new Response(null, { status: 204 })
      return Response.json(review)
    }),
  )
})

afterEach(() => {
  vi.unstubAllGlobals()
  window.localStorage.clear()
})

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={client}>
      <PreferencesProvider>
        <TooltipProvider>
          <WhatToCheck />
        </TooltipProvider>
      </PreferencesProvider>
    </QueryClientProvider>,
  )
}

describe('What to check', () => {
  it('shows counts, items with their evidence and the threat first', async () => {
    renderPage()
    const rows = await screen.findAllByRole('listitem')
    expect(within(rows[0]).getByText('listed.example.test')).toBeInTheDocument()
    expect(within(rows[0]).getByText(/203\.0\.113\.7:443/)).toBeInTheDocument()
    expect(within(rows[0]).getByText('Example Net · NL')).toBeInTheDocument()
    expect(screen.getByText('To check').nextElementSibling).toHaveTextContent('2')
  })

  it('sends a mark as same-origin JSON and clears it on a second click', async () => {
    review = { ...OK, items: [item({ mark: 'suspicious' })] }
    renderPage()
    const user = userEvent.setup()
    const pressed = await screen.findByRole('button', { name: 'Suspicious', pressed: true })
    await user.click(pressed)
    await waitFor(() => expect(calls.some((call) => call.url === '/api/review/marks')).toBe(true))
    const put = calls.find((call) => call.url === '/api/review/marks')!
    expect(put.init?.method).toBe('PUT')
    expect(new Headers(put.init?.headers).get('Content-Type')).toBe('application/json')
    expect(JSON.parse(String(put.init?.body))).toEqual({ key: 'dns:cdn.example.test', mark: null })
  })

  it('filters by kind and opens outside links safely', async () => {
    renderPage()
    const user = userEvent.setup()
    await screen.findByText('cdn.example.test')
    await user.click(screen.getByRole('radio', { name: 'Threat lists' }))
    expect(screen.queryByText('cdn.example.test')).not.toBeInTheDocument()
    await user.click(screen.getByRole('radio', { name: 'Name lookups' }))
    await user.click(screen.getByRole('button', { name: 'Show why and what to do' }))
    const link = screen.getByRole('link', { name: 'VirusTotal' })
    expect(link).toHaveAttribute('target', '_blank')
    expect(link).toHaveAttribute('rel', 'noopener noreferrer')
  })

  it('uses Turkish wording from the server dictionary', async () => {
    window.localStorage.setItem('tf-lang', 'tr')
    renderPage()
    expect(await screen.findByText('Bakılacak')).toBeInTheDocument()
    // Only the symbol is dropped from "⚠ Şüpheli"; the Turkish letter stays.
    expect(screen.getAllByRole('button', { name: 'Şüpheli' })).toHaveLength(2)
    expect(calls.some((call) => call.url === '/api/review?lang=tr')).toBe(true)
  })

  it('explains an empty, missing or unreachable collector', async () => {
    review = { state: 'no_snapshot' }
    const { unmount } = renderPage()
    expect(await screen.findByText('No collector snapshot yet. Start the local collector.')).toBeInTheDocument()
    unmount()
    review = { ...OK, items: [], known: [], counts: { to_check: 0, suspicious: 0, threat: 0, known: 0 } }
    renderPage()
    expect(await screen.findByText('Nothing to check. Everything collected is under Details.')).toBeInTheDocument()
  })
})
