import { expect, test, type Page } from '@playwright/test'

import { expectNoHorizontalScroll, watchConsole, turkishScreenshots } from './helpers.ts'

async function openDetails(page: Page) {
  await page.getByRole('navigation').getByRole('button', { name: /^(Details|Ayrıntılar)$/ }).click()
  await expect(page.getByRole('heading', { level: 1 })).toHaveText(/^(Details|Ayrıntılar)$/)
}

const connectionRows = (page: Page) => page.getByRole('region', { name: 'Details · table' }).locator('tbody tr')

test('a clean visit to Details is dark and Turkish', async ({ page }) => {
  await page.goto('/')
  await openDetails(page)
  await expect(page.locator('html')).toHaveClass(/dark/)
  await expect(page.getByRole('heading', { level: 1 })).toHaveText('Ayrıntılar')
})

test.describe('in English', () => {
  test.beforeEach(async ({ page }) => {
    await page.addInitScript(() => {
      if (!window.localStorage.getItem('tf-lang')) window.localStorage.setItem('tf-lang', 'en')
    })
    await page.goto('/')
    await openDetails(page)
  })

  test('shows the Streamlit blocks with real local addresses', async ({ page }) => {
    const console = watchConsole(page)
    await expect(page.getByText('Retained connections')).toBeVisible()
    await expect(page.getByText('Original TCP reviews')).toBeVisible()
    await expect(connectionRows(page)).toHaveCount(3)
    await expect(connectionRows(page).first()).toContainText('192.0.2.')
    await expect(page.getByRole('region', { name: 'TCP attempt reviews', exact: true })).toBeVisible()
    await expect(page.getByRole('region', { name: 'Collected DNS observations', exact: true })).toBeVisible()
    await expectNoHorizontalScroll(page)
    console.expectClean()
  })

  test('the checkboxes change the table like Streamlit', async ({ page }) => {
    await page.getByLabel('Show only connection reviews').uncheck()
    await expect(connectionRows(page)).not.toHaveCount(3)
    await page.getByLabel('Show only connection reviews').check()
    await expect(connectionRows(page)).toHaveCount(3)
    await page.getByLabel('Show observed endpoint IPs locally; downloads keep aliases').uncheck()
    await expect(connectionRows(page).first()).toContainText('Host ')
    await page.getByLabel('Show observed endpoint IPs locally; downloads keep aliases').check()
    await expect(connectionRows(page).first()).toContainText('192.0.2.')
  })

  test('connection and DNS timelines with chart tooltips', async ({ page }) => {
    const investigation = page.getByRole('region', { name: 'Connection investigation', exact: true })
    const select = investigation.getByLabel('Select a connection group')
    await expect(select.locator('option')).toHaveCount(3)
    await select.selectOption({ index: 2 })
    await expect(investigation.getByText('Review guidance')).toBeVisible()
    const chart = investigation.getByRole('img', { name: /Connection starts/ })
    await expect(chart).toBeVisible()
    await chart.focus()
    await page.keyboard.press('ArrowRight')
    await expect(investigation.getByRole('status')).toContainText('UTC')

    const dns = page.getByRole('region', { name: 'Collected DNS observations', exact: true })
    await expect(dns.getByLabel('Select a queried domain')).toHaveValue('1')
    await expect(dns.getByRole('img', { name: /DNS queries/ })).toBeVisible()
  })

  test('the snapshot download keeps aliases', async ({ page }) => {
    const [download] = await Promise.all([
      page.waitForEvent('download'),
      page.getByRole('link', { name: 'Download collected connection JSON' }).click(),
    ])
    expect(download.suggestedFilename()).toBe('threatfusion_collected_connections.json')
    const body = await (await download.createReadStream()).toArray()
    const text = Buffer.concat(body).toString()
    expect(text).toContain('"Host 001"')
    expect(text).not.toContain('192.0.2.10')
  })

  test('review screenshots in Turkish: dark then light', async ({ page }, testInfo) => {
    const console = watchConsole(page)
    const investigation = page.getByRole('region', { name: 'Connection investigation', exact: true })
    await investigation.getByLabel('Select a connection group').selectOption({ index: 2 })
    await expect(investigation.getByRole('img', { name: /Connection starts/ })).toBeVisible()
    await expect(page.locator('html')).toHaveClass(/dark/)
    await expectNoHorizontalScroll(page)
    await turkishScreenshots(page, testInfo, 'details')
    console.expectClean()
  })
})
