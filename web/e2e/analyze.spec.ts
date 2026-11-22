import { expect, test, type Page } from '@playwright/test'
import path from 'node:path'

import { expectNoHorizontalScroll, turkishScreenshots, watchConsole } from './helpers.ts'

const SAMPLES = path.resolve(import.meta.dirname, '../../data/samples/demo')

async function openAnalyze(page: Page) {
  await page.getByRole('navigation').getByRole('button', { name: /^(Analyze telemetry|Telemetriyi analiz et)$/ }).click()
  await expect(page.getByRole('heading', { level: 1 })).toHaveText(/^(Analyze telemetry|Telemetriyi analiz et)$/)
}

/** The red Known Threat bar of the verdict distribution, with its count. */
async function expectKnownThreat(page: Page, label = 'Known Threat') {
  const row = page.getByRole('region', { name: /^(Verdict distribution|Sonuç dağılımı)$/ }).locator('li[data-verdict="threat"]')
  await expect(row).toContainText(label)
  const count = Number(await row.locator('span').last().textContent())
  expect(count).toBeGreaterThanOrEqual(1)
  const bar = row.locator('span span')
  await expect(bar).toHaveClass(/bg-threat/)
  expect(await bar.evaluate((el) => el.getBoundingClientRect().width)).toBeGreaterThan(0)
}

async function analyze(page: Page, file: string) {
  await page.locator('input[type=file]').setInputFiles(path.join(SAMPLES, file))
  await page.getByRole('button', { name: /^(Analyze|Analiz et)$/ }).click()
}

test('a clean visit to Analyze telemetry is dark and Turkish', async ({ page }) => {
  await page.goto('/')
  await openAnalyze(page)
  await expect(page.locator('html')).toHaveClass(/dark/)
  await expect(page.getByRole('button', { name: 'Analiz et', exact: true })).toBeDisabled() // nothing chosen yet
  await expect(page.getByText('Dosya yalnızca bu bilgisayardaki yerel sunucuya gider')).toBeVisible()
  await analyze(page, 'dns.log')
  await expectKnownThreat(page, 'Bilinen Tehdit') // the red result the demo shows
})

test.describe('in English', () => {
  test.beforeEach(async ({ page }) => {
    await page.addInitScript(() => {
      if (!window.localStorage.getItem('tf-lang')) window.localStorage.setItem('tf-lang', 'en')
    })
    await page.goto('/')
    await openAnalyze(page)
  })

  test('the Zeek dns.log sample: threat-list match and regular lookups', async ({ page }) => {
    const console = watchConsole(page)
    const requests: string[] = []
    page.on('request', (request) => requests.push(new URL(request.url()).host))
    await analyze(page, 'dns.log')
    const priority = page.getByRole('region', { name: 'Priority findings' })
    await expect(priority).toContainText('malicious.example.test')
    await expect(priority).toContainText('Known Threat')
    await expectKnownThreat(page)
    await page.getByRole('tab', { name: 'Device triage' }).click()
    const devices = page.getByRole('region', { name: 'Device triage · table' })
    await expect(devices).toContainText('updates.example.test')
    await expect(devices).toContainText('Sustained periodic DNS')
    await page.getByRole('tab', { name: 'Domain investigation' }).click()
    await expect(page.getByRole('region', { name: 'Domain investigation' })).toContainText('Exact known-domain IOC match')
    expect(new Set(requests)).toEqual(new Set(['127.0.0.1:8611'])) // the file went nowhere else
    await expectNoHorizontalScroll(page)
    console.expectClean()
  })

  test('the Zeek conn.log sample: listed address, regular repeats and failed attempts', async ({ page }) => {
    await analyze(page, 'conn.log')
    await expect(page.getByRole('region', { name: 'Priority findings' })).toContainText('203.0.113.7')
    await page.getByRole('tab', { name: 'Connection activity' }).click()
    const connections = page.getByRole('region', { name: 'Connection activity · table' })
    await expect(connections).toContainText('Sustained periodic successful TCP connections')
    await page.getByLabel('Show connection endpoint IPs in this view and export').check()
    await expect(connections).toContainText('198.51.100.30')
    await expect(page.getByRole('region', { name: 'TCP attempt reviews · table' })).toContainText('Failed attempts across multiple ports')
    await expect(page.getByRole('img', { name: /Connection starts/ })).toBeVisible()
  })

  test('an expected-connection file is read locally; an invalid one applies nothing', async ({ page }) => {
    const console = watchConsole(page)
    await analyze(page, 'conn.log')
    await page.getByRole('tab', { name: 'Connection activity' }).click()
    await expect(page.getByText('Expected activity is your declaration, not verified software identity.', { exact: false })).toBeVisible()
    const upload = page.waitForRequest((request) => request.url().includes('/expected') && request.method() === 'PUT')
    await page.getByLabel('Optional expected-connection JSON (local session only)').setInputFiles({
      name: 'expected.json',
      mimeType: 'application/json',
      buffer: Buffer.from('{"schema_version": 1, "rules": [{"id": "x"}]}'),
    })
    expect((await upload).postDataJSON()).toEqual({ content: '{"schema_version": 1, "rules": [{"id": "x"}]}' })
    await expect(page.getByRole('alert').filter({ hasText: 'Invalid expected-connection file. No declarations applied.' })).toBeVisible()
    await expect(page.getByLabel('Include declared expected activity')).toHaveCount(0)
    await expectNoHorizontalScroll(page)
    // The 422 answer is the expected outcome here, not a page error.
    expect(console.errors.filter((error) => !error.includes('422'))).toEqual([])
  })

  test('the DNS CSV sample tells the same story, and filters work', async ({ page }) => {
    await analyze(page, 'dns_queries.csv')
    await page.getByRole('button', { name: /^Input quality/ }).click()
    await expect(page.getByText(/Detected input: Delimited DNS table/)).toBeVisible()
    const table = page.getByRole('region', { name: 'Domain findings · table' })
    await page.getByLabel('Verdict', { exact: true }).selectOption('Known Threat')
    await expect(table.locator('tbody tr')).toHaveCount(1)
    await expect(table).toContainText('malicious.example.test')
    await expectKnownThreat(page)
    await page.getByLabel('Verdict', { exact: true }).selectOption('All')
    await page.getByLabel('Search domains').fill('updates')
    await expect(table.locator('tbody tr')).toHaveCount(1)
  })

  test('exports keep aggregate data only', async ({ page }) => {
    await analyze(page, 'dns.log')
    await page.getByRole('tab', { name: 'Export & save' }).click()
    const [download] = await Promise.all([page.waitForEvent('download'), page.getByRole('link', { name: 'Download JSON report' }).click()])
    expect(download.suggestedFilename()).toBe('threatfusion_analysis.json')
    const text = Buffer.concat(await (await download.createReadStream()).toArray()).toString()
    expect(text).toContain('malicious.example.test')
    expect(text).not.toContain('192.0.2.21')
  })

  test('a wrong file type is refused by the local server', async ({ page }) => {
    await page.getByLabel('Telemetry format').selectOption('Generic DNS CSV')
    await analyze(page, 'dns.log')
    await expect(page.getByText('This file type is not accepted for the selected format.')).toBeVisible()
  })

  test('the result is kept when switching screens', async ({ page }) => {
    await analyze(page, 'dns.log')
    await expect(page.getByRole('region', { name: 'Priority findings' })).toContainText('malicious.example.test')
    await page.getByRole('navigation').getByRole('button', { name: 'What to check' }).click()
    await openAnalyze(page)
    await expect(page.getByRole('region', { name: 'Priority findings' })).toContainText('malicious.example.test')
  })

  test('review screenshots in Turkish: dark then light', async ({ page }, testInfo) => {
    const console = watchConsole(page)
    await analyze(page, 'conn.log')
    await expect(page.getByRole('region', { name: 'Priority findings' })).toContainText('203.0.113.7')
    await turkishScreenshots(page, testInfo, 'analyze')
    console.expectClean()
  })
})
