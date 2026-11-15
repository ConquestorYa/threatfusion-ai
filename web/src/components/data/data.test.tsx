import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import type { ReactNode } from 'react'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { PreferencesProvider } from '@/lib/preferences'
import { DataTable, shortTime } from './DataTable'
import { Markdown } from './Markdown'
import { TimeChart, utcLabel } from './TimeChart'

beforeEach(() => {
  window.localStorage.setItem('tf-lang', 'en')
  vi.stubGlobal('fetch', vi.fn(async () => Response.json({})))
})

function wrap(children: ReactNode) {
  return render(
    <QueryClientProvider client={new QueryClient()}>
      <PreferencesProvider>{children}</PreferencesProvider>
    </QueryClientProvider>,
  )
}

describe('Markdown', () => {
  it('renders the guide subset as elements, never as HTML', () => {
    render(<Markdown text={'**What:** run `collect`.\n\n1. Groups\n2. Compares\n<b>raw</b>'} />)
    expect(screen.getByText('What:').tagName).toBe('STRONG')
    expect(screen.getByText('collect').tagName).toBe('CODE')
    expect(screen.getAllByRole('listitem')).toHaveLength(2)
    expect(screen.getByText('<b>raw</b>')).toBeInTheDocument() // shown as text
  })

  it('links only https targets, in a new tab without referrer', () => {
    render(<Markdown text={'Get a key at [auth.abuse.ch](https://auth.abuse.ch/). Not [this](javascript:alert(1)).'} />)
    const link = screen.getByRole('link', { name: 'auth.abuse.ch' })
    expect(link).toHaveAttribute('href', 'https://auth.abuse.ch/')
    expect(link).toHaveAttribute('rel', 'noopener noreferrer')
    expect(screen.queryByRole('link', { name: 'this' })).toBeNull()
  })
})

describe('DataTable', () => {
  it('shows booleans as Yes/No, empty cells as a dash and right-aligns numbers', () => {
    wrap(<DataTable label="Rows" table={{ columns: ['Host', 'Count', 'CTI'], rows: [['192.0.2.1', 3, true], ['', null, false]] }} />)
    const table = screen.getByRole('region', { name: 'Rows' })
    expect(within(table).getByText('Yes')).toBeInTheDocument()
    expect(within(table).getByText('No')).toBeInTheDocument()
    expect(within(table).getAllByText('—')).toHaveLength(2)
    expect(within(table).getByText('3').className).toContain('text-right')
    expect(within(table).getByText('192.0.2.1').className).toContain('font-mono')
  })
})

describe('table times', () => {
  it('formats ISO and UTC text times short; UTC columns stay UTC', () => {
    const year = new Date().getFullYear()
    expect(shortTime(`${year}-11-15T16:38:20.452105+00:00`, true)).toBe('15.11 16:38')
    expect(shortTime(`${year}-11-15 16:38 UTC`, true)).toBe('15.11 16:38')
    expect(shortTime('2024-01-02T03:04:00Z', true)).toBe('02.01.2024 03:04')
    expect(shortTime('not a time')).toBe('not a time')
  })

  it('shows times short in cells and pins the first column', () => {
    wrap(
      <DataTable
        label="Times"
        table={{ columns: ['Group', 'First observed', 'UTC bucket start'], rows: [[1, '2026-11-15T16:38:20.45+00:00', '2026-11-15T16:30:00+00:00']] }}
      />,
    )
    const table = screen.getByRole('region', { name: 'Times' })
    expect(within(table).queryByText(/2026-11-15T/)).toBeNull()
    expect(within(table).getByText(/^15\.11(\.2026)? 16:30$/)).toBeInTheDocument() // UTC column stays UTC
    expect(within(table).getByRole('columnheader', { name: 'Group' }).className).toContain('sticky')
  })
})

describe('TimeChart', () => {
  const points = [
    { t: '2026-11-15T10:00:00+00:00', v: 2 },
    { t: '2026-11-15T10:10:00+00:00', v: 0 },
    { t: '2026-11-15T10:20:00+00:00', v: 5 },
  ]

  it('formats UTC the same in every language', () => {
    expect(utcLabel('2026-11-15T21:05:00+03:00')).toBe('15.11 18:05')
    expect(utcLabel('2026-11-15T18:05:00+00:00', true)).toBe('15.11.2026 18:05')
  })

  it('draws bars only for non-zero buckets and shows a tooltip from the keyboard', async () => {
    const { container } = render(<TimeChart points={points} kind="bar" xTitle="UTC bucket start" yTitle="DNS queries" />)
    expect(container.querySelectorAll('path.fill-chart-series')).toHaveLength(2)
    const chart = screen.getByRole('img', { name: 'DNS queries · UTC bucket start (UTC)' })
    chart.focus()
    await userEvent.keyboard('{ArrowRight}{ArrowRight}{ArrowRight}')
    expect(screen.getByRole('status')).toHaveTextContent('15.11.2026 10:20 UTC')
    expect(screen.getByRole('status')).toHaveTextContent('DNS queries: 5')
  })

  it('draws a 2px line for connection starts', () => {
    const { container } = render(<TimeChart points={points} kind="line" xTitle="x" yTitle="Connection starts" />)
    expect(container.querySelector('path.stroke-chart-series')?.getAttribute('stroke-width')).toBe('2')
  })
})
