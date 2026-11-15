import { expect, test, type Page } from '@playwright/test'

import { expectNoHorizontalScroll, watchConsole, turkishScreenshots } from './helpers.ts'

async function openLookup(page: Page) {
  await page.getByRole('navigation').getByRole('button', { name: /^(Quick lookup|Hızlı sorgu)$/ }).click()
  await expect(page.getByRole('heading', { level: 1 })).toHaveText(/^(Quick lookup|Hızlı sorgu)$/)
}

async function check(page: Page, value: string) {
  await page.getByRole('searchbox').or(page.getByLabel(/URL, domain/)).first().fill(value)
  await page.getByRole('button', { name: /^(Check|Kontrol et)$/ }).click()
}

test('a clean visit to Quick lookup is dark and Turkish', async ({ page }) => {
  await page.goto('/')
  await openLookup(page)
  await expect(page.locator('html')).toHaveClass(/dark/)
  await expect(page.getByRole('heading', { level: 1 })).toHaveText('Hızlı sorgu')
  await expect(page.getByRole('button', { name: 'Kontrol et' })).toBeVisible()
})

test.describe('in English', () => {
  test.beforeEach(async ({ page }) => {
    await page.addInitScript(() => {
      if (!window.localStorage.getItem('tf-lang')) window.localStorage.setItem('tf-lang', 'en')
    })
    await page.goto('/')
    await openLookup(page)
  })

  test('an empty check asks for input without calling the API', async ({ page }) => {
    let calls = 0
    page.on('request', (request) => {
      if (request.url().endsWith('/api/lookup?lang=en')) calls += 1
    })
    await page.getByRole('button', { name: 'Check', exact: true }).click()
    await expect(page.getByText('Enter a URL, domain or IP before checking it.')).toBeVisible()
    expect(calls).toBe(0)
  })

  test('a listed name is a known threat with its evidence', async ({ page }) => {
    const console = watchConsole(page)
    await check(page, 'https://malicious.example.test/login')
    await expect(page.getByRole('region', { name: 'Known threat' })).toContainText('Threat intelligence match found')
    await expect(page.getByText('Known threat intelligence matched')).toBeVisible()
    const evidence = page.getByRole('region', { name: 'Threat intelligence evidence · table' })
    await expect(evidence).toContainText('Synthetic demo')
    await expect(evidence).toContainText('phishing')
    await expect(page.getByRole('button', { name: 'Check site age' })).toBeVisible()
    await expect(page.getByText('Sends only example.test to the official domain registry')).toBeVisible()
    await expectNoHorizontalScroll(page)
    console.expectClean()
  })

  test('an IP over HTTP shows the warning, owner block and safe outside links', async ({ page }) => {
    await check(page, 'http://203.0.113.7/x')
    await expect(page.getByRole('alert').filter({ hasText: 'HTTP link detected' })).toBeVisible()
    await expect(page.getByRole('heading', { name: 'Network owner' })).toBeVisible()
    const link = page.getByRole('link', { name: 'AbuseIPDB' })
    await expect(link).toHaveAttribute('href', 'https://www.abuseipdb.com/check/203.0.113.7')
    await expect(link).toHaveAttribute('rel', 'noopener noreferrer')
  })

  test('the result is kept when switching screens and re-read in Turkish', async ({ page }) => {
    await check(page, 'quiet.example.test')
    await expect(page.getByText('No cached CTI match was found.')).toBeVisible()
    await page.getByRole('navigation').getByRole('button', { name: 'What to check' }).click()
    await openLookup(page)
    await expect(page.getByText('No cached CTI match was found.')).toBeVisible()
    await page.getByRole('radio', { name: 'TR' }).click()
    await expect(page.getByRole('heading', { level: 1 })).toHaveText('Hızlı sorgu')
    await expect(page.getByRole('region', { name: 'Düşük risk' })).toBeVisible()
  })

  test('review screenshots in Turkish: dark then light', async ({ page }, testInfo) => {
    const console = watchConsole(page)
    await check(page, 'https://malicious.example.test/login')
    await expect(page.getByText('Known threat intelligence matched')).toBeVisible()
    await page.getByRole('button', { name: 'Technical domain details' }).click()
    await expect(page.locator('html')).toHaveClass(/dark/)
    await expectNoHorizontalScroll(page)
    await turkishScreenshots(page, testInfo, 'lookup')
    console.expectClean()
  })
})
