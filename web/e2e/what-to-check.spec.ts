import { expect, test } from '@playwright/test'

import { clearMarks, expectNoHorizontalScroll, watchConsole, turkishScreenshots } from './helpers.ts'

const count = (page: import('@playwright/test').Page, label: string) =>
  page.locator('dl dt', { hasText: new RegExp(`^${label}$`) }).locator('xpath=following-sibling::dd[1]')

const rows = (page: import('@playwright/test').Page, region = 'What to check') =>
  page.getByRole('region', { name: region }).getByRole('listitem')

test.beforeEach(async ({ page }) => {
  // These cases read English; Turkish is the default (theme.spec.ts covers it).
  await page.addInitScript(() => {
    if (!window.localStorage.getItem('tf-lang')) window.localStorage.setItem('tf-lang', 'en')
  })
  await page.goto('/')
  await clearMarks(page)
  await page.reload()
  await expect(rows(page)).toHaveCount(5)
})

test('shows the collector list with the threat first and real local addresses', async ({ page }, testInfo) => {
  const console = watchConsole(page)
  await page.reload()
  const first = rows(page).first()
  await expect(first).toContainText('203.0.113.7')
  await expect(first).toContainText('On a threat list')
  await expect(first).toContainText('192.0.2.10 → 203.0.113.7:443')
  if (testInfo.project.name === 'desktop') {
    // Network owner column: no owner table in the test state, so a dash.
    await expect(page.getByText('Network owner')).toBeVisible()
    await expect(first.getByText('—')).toBeVisible()
  }
  await expect(count(page, 'To check')).toHaveText('5')
  await expect(count(page, 'On a threat list')).toHaveText('1')
  await expectNoHorizontalScroll(page)
  console.expectClean()
})

test('marks move items, survive a reload and match the shared file', async ({ page }) => {
  const row = rows(page).filter({ hasText: 'updates.test' })
  await row.getByRole('button', { name: 'Suspicious' }).click()
  await expect(rows(page).first()).toContainText('updates.test')
  await expect(rows(page).first().getByRole('button', { name: 'Suspicious' })).toHaveAttribute('aria-pressed', 'true')
  await expect(count(page, 'Suspicious')).toHaveText('1')

  await rows(page).filter({ hasText: '198.51.100.77' }).getByRole('button', { name: 'I know this' }).click()
  await expect(rows(page)).toHaveCount(4)
  await page.reload()
  await expect(rows(page)).toHaveCount(4)
  await page.getByRole('button', { name: 'Known (1)' }).click()
  await page.getByRole('button', { name: 'Show again' }).click()
  await expect(rows(page)).toHaveCount(5)

  await rows(page).first().getByRole('button', { name: 'Suspicious' }).click() // click again: unmark
  await expect(count(page, 'Suspicious')).toHaveText('0')
})

test('a threat-list item stays visible when marked known', async ({ page }) => {
  await rows(page).first().getByRole('button', { name: 'I know this' }).click()
  await expect(rows(page)).toHaveCount(5)
  await expect(rows(page).first()).toContainText('203.0.113.7')
})

test('filters match the Streamlit options', async ({ page }) => {
  const filters = page.getByRole('radiogroup', { name: 'Show' })
  await filters.getByRole('radio', { name: 'Threat lists' }).click()
  await expect(rows(page)).toHaveCount(1)
  await filters.getByRole('radio', { name: 'Name lookups' }).click()
  await expect(rows(page)).toHaveCount(1)
  await expect(rows(page).first()).toContainText('updates.test')
  await filters.getByRole('radio', { name: 'Connections' }).click()
  await expect(rows(page)).toHaveCount(3)
  await filters.getByRole('radio', { name: 'All' }).click()
  await expect(rows(page)).toHaveCount(5)
})

test('the explanation opens with safe outside links', async ({ page }) => {
  const row = rows(page).filter({ hasText: '198.51.100.20' })
  await row.getByRole('button', { name: 'Show why and what to do' }).click()
  await expect(row).toContainText('The device contacted this address at very regular intervals.')
  const link = row.getByRole('link', { name: 'AbuseIPDB' })
  await expect(link).toHaveAttribute('href', 'https://www.abuseipdb.com/check/198.51.100.20')
  await expect(link).toHaveAttribute('rel', 'noopener noreferrer')
  await expect(link).toHaveAttribute('target', '_blank')
})

test('switching language keeps an open explanation open', async ({ page }) => {
  const row = rows(page).filter({ hasText: '198.51.100.20' })
  await row.getByRole('button', { name: 'Show why and what to do' }).click()
  await page.getByRole('radio', { name: 'TR' }).click()
  await expect(rows(page, 'Bakılacaklar').filter({ hasText: '198.51.100.20' })).toContainText('Cihaz bu adrese çok düzenli aralıklarla bağlandı.')
})

test('Turkish uses the shared dictionary', async ({ page }) => {
  await page.getByRole('radio', { name: 'TR' }).click()
  await expect(page.getByRole('heading', { name: 'Bakılacaklar' })).toBeVisible()
  await expect(rows(page, 'Bakılacaklar').first()).toContainText('Tehdit listesinde')
  await expect(rows(page, 'Bakılacaklar').first().getByRole('button', { name: 'Şüpheli' })).toBeAttached()
  await page.getByRole('radio', { name: 'EN' }).click()
})

test('there is no Streamlit link unless one is configured beside this workspace', async ({ page }) => {
  await expect(page.getByRole('heading', { level: 1 })).toBeVisible()
  await expect(page.getByRole('link', { name: 'Open in Streamlit' })).toHaveCount(0)
})

test('mark buttons show text on desktop and icon plus tooltip on narrow screens', async ({ page }, testInfo) => {
  const button = rows(page).nth(1).getByRole('button', { name: 'Not sure' })
  const text = button.locator('span')
  if (testInfo.project.name === 'desktop') {
    await expect(text).toBeVisible()
  } else {
    await expect(text).toBeHidden()
    const box = await button.boundingBox()
    expect(box!.height).toBeGreaterThanOrEqual(44)
    expect(box!.width).toBeGreaterThanOrEqual(44)
    await button.focus()
    await expect(page.getByRole('tooltip')).toContainText('Not sure')
  }
})

test('review screenshots in Turkish: dark then light', async ({ page }, testInfo) => {
  const console = watchConsole(page)
  await rows(page).filter({ hasText: '203.0.113.5' }).getByRole('button', { name: 'Suspicious' }).click()
  await rows(page).filter({ hasText: '198.51.100.20' }).getByRole('button', { name: 'Show why and what to do' }).click()
  await expect(page.locator('html')).toHaveClass(/dark/)
  await expectNoHorizontalScroll(page)
  await turkishScreenshots(page, testInfo, 'what-to-check')
  console.expectClean()
})
