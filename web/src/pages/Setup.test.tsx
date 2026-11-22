import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { PreferencesProvider } from '@/lib/preferences'
import { Setup } from './Setup'

const OK = {
  state: 'ok',
  caption: 'This installation uses your own credentials.',
  mode: { title: 'Operating mode', value: 'cti-only', options: [{ value: 'cti-only', label: 'Real CTI' }, { value: 'demo', label: 'Synthetic demo' }] },
  application: {
    title: 'Application',
    caption: 'Reopen from the applications menu.',
    stop: 'Stop local application',
    stopping: 'The local application is stopping. You can close this tab.',
    not_running: 'This page is not running under the local launcher.',
  },
  keys: {
    title: 'API keys', caption: 'SGB works without a key.', saved: 'Saved keys: None', missing: 'Get one at [auth.abuse.ch](https://auth.abuse.ch/).',
    fields: [{ name: 'threatfox', label: 'ThreatFox API key' }, { name: 'urlhaus', label: 'URLhaus API key' }],
    apply: 'Apply keys', applied: 'Keys applied. Empty fields remove keys from this selection.',
    invalid: 'Invalid API key format. No credentials were saved.', forget: 'Forget saved and session keys',
  },
  cti: {
    title: 'CTI data', running: false, force_label: 'Download again even if sources are still fresh', force_help: 'h',
    button: 'Update CTI now', busy: 'An update is already running.', started: 'CTI update started.', due: null,
    progress: null, summary: null, status: [{ kind: 'caption', text: 'SGB · Cache still fresh' }],
  },
  schedule: { title: 'Automatic updates', automatic: false, automatic_label: 'Automatic updates while the app is running', interval_hours: 6, interval_label: 'Update interval (hours)', options: [6, 12, 24], caption: 'c', button: 'Save update settings' },
  sources: null,
}

let calls: { url: string; init?: RequestInit }[]
let state: unknown
beforeEach(() => {
  window.localStorage.setItem('tf-lang', 'en')
  calls = []
  state = OK
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string, init?: RequestInit) => {
      calls.push({ url, init })
      if (url.startsWith('/api/setup/refresh')) return Response.json({ started: true })
      if (url.startsWith('/api/setup/')) return new Response(null, { status: 204 })
      if (url.startsWith('/api/setup')) return Response.json(state)
      return Response.json({ setup_available: true, first_setup: false })
    }),
  )
})
afterEach(() => vi.unstubAllGlobals())

const renderPage = () =>
  render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <PreferencesProvider>
        <Setup />
      </PreferencesProvider>
    </QueryClientProvider>,
  )

describe('Setup & CTI updates', () => {
  it('starts a forced update once and clears the force choice', async () => {
    renderPage()
    const force = await screen.findByLabelText(/Download again even if sources are still fresh/)
    await userEvent.click(force)
    await userEvent.click(screen.getByRole('button', { name: 'Update CTI now' }))
    const post = calls.find((call) => call.url === '/api/setup/refresh')!
    expect(JSON.parse(String(post.init?.body))).toEqual({ force: true })
    expect(await screen.findByText('CTI update started.')).toBeInTheDocument()
    expect(force).not.toBeChecked()
  })

  it('saves the schedule and the mode as JSON writes', async () => {
    renderPage()
    await userEvent.selectOptions(await screen.findByLabelText('Update interval (hours)'), '24')
    await userEvent.click(screen.getByRole('button', { name: 'Save update settings' }))
    const schedule = calls.find((call) => call.url === '/api/setup/schedule')!
    expect(schedule.init?.method).toBe('PUT')
    expect(JSON.parse(String(schedule.init?.body))).toEqual({ automatic: false, interval_hours: 24 })
    await userEvent.selectOptions(screen.getByRole('combobox', { name: 'Operating mode' }), 'demo')
    expect(JSON.parse(String(calls.find((call) => call.url === '/api/setup/mode')!.init?.body))).toEqual({ mode: 'demo' })
  })

  it('sends keys once as JSON, clears the fields and can forget them', async () => {
    renderPage()
    const threatfox = await screen.findByLabelText('ThreatFox API key')
    expect(threatfox).toHaveAttribute('type', 'password')
    await userEvent.type(threatfox, 'synthetic-key')
    await userEvent.click(screen.getByRole('button', { name: 'Apply keys' }))
    const put = calls.find((call) => call.url === '/api/setup/keys')!
    expect(put.init?.method).toBe('PUT')
    expect(JSON.parse(String(put.init?.body))).toEqual({ threatfox: 'synthetic-key', urlhaus: '' })
    expect(await screen.findByText('Keys applied. Empty fields remove keys from this selection.')).toBeInTheDocument()
    expect(threatfox).toHaveValue('')
    await userEvent.click(screen.getByRole('button', { name: 'Forget saved and session keys' }))
    expect(calls.some((call) => call.url === '/api/setup/keys/forget')).toBe(true)
  })

  it('explains that Setup needs a managed installation', async () => {
    state = { state: 'not_managed' }
    renderPage()
    expect(await screen.findByText(/available in a managed installation/)).toBeInTheDocument()
  })
})
