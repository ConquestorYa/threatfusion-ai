import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { PreferencesProvider } from '@/lib/preferences'
import { QuickLookup } from './QuickLookup'

const STATUS = {
  ready: true,
  notices: [{ kind: 'warning', text: 'CTI cache is empty. CTI-only lookup has no known-indicator evidence.' }],
  label: 'URL, domain or IP',
  placeholder: 'example.com',
  button: 'Check',
  caption: 'Passive by design · no page visit · no DNS resolution · no download',
  empty_input: 'Enter a URL, domain or IP before checking it.',
}
const RESULT = {
  notices: [],
  banner: { tone: 'critical', icon: '×', kicker: 'Known threat', title: 'Threat intelligence match found', summary: 's', target: 'bad.example.test', meta: [['Input', 'domain']] },
  overview_title: 'Signal overview',
  ml_card: null,
  console: [{ tone: 'danger', label: 'Local threat intelligence', value: '1 CTI match', sub: 'cache' }],
  console_caption: 'c',
  reasons_title: 'Why this result?',
  reasons: ['Exact known-domain IOC match'],
  registry: null,
  links_title: 'Look up elsewhere',
  links_caption: 'l',
  links: [],
  evidence_title: 'Threat intelligence evidence',
  evidence_state: { tone: 'danger', heading: 'Known threat intelligence matched', copy: 'c' },
  evidence: { columns: ['Source'], rows: [['Synthetic demo']] },
  technical: { title: 'Technical domain details', caption: 'c', metrics: [] },
  footer: 'f',
}

let posts: { url: string; body: string }[]
beforeEach(() => {
  window.localStorage.setItem('tf-lang', 'en')
  posts = []
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string, init?: RequestInit) => {
      if (url.startsWith('/api/lookup/status')) return Response.json(STATUS)
      if (url.startsWith('/api/lookup')) {
        posts.push({ url, body: String(init?.body) })
        return Response.json(RESULT)
      }
      return Response.json({})
    }),
  )
})
afterEach(() => vi.unstubAllGlobals())

const renderPage = () =>
  render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <PreferencesProvider>
        <QuickLookup />
      </PreferencesProvider>
    </QueryClientProvider>,
  )

describe('Quick lookup', () => {
  it('warns on empty input without calling the API, like Streamlit', async () => {
    renderPage()
    await userEvent.click(await screen.findByRole('button', { name: 'Check' }))
    expect(screen.getByText('Enter a URL, domain or IP before checking it.')).toBeInTheDocument()
    expect(posts).toHaveLength(0)
    expect(screen.getAllByRole('alert')[0]).toHaveTextContent('CTI cache is empty')
  })

  it('posts the value as JSON and shows the verdict and evidence', async () => {
    renderPage()
    await userEvent.type(await screen.findByLabelText('URL, domain or IP'), 'bad.example.test{Enter}')
    expect(await screen.findByRole('region', { name: 'Known threat' })).toHaveTextContent('Threat intelligence match found')
    expect(posts[0]).toEqual({ url: '/api/lookup?lang=en', body: JSON.stringify({ value: 'bad.example.test' }) })
    expect(screen.getByRole('region', { name: 'Threat intelligence evidence · table' })).toHaveTextContent('Synthetic demo')
  })
})
