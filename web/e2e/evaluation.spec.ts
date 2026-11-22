import { expect, test, type Page } from '@playwright/test'

import { expectNoHorizontalScroll, watchConsole, turkishScreenshots } from './helpers.ts'

// The browser-test installation is CTI-only with a synthetic behavior model
// (serve.sh), so the page shows that model's report, as Streamlit does.

async function openEvaluation(page: Page) {
  await page.getByRole('navigation').getByRole('button', { name: /^(Model evaluation|Model değerlendirmesi)$/ }).click()
  await expect(page.getByRole('heading', { level: 1 })).toHaveText(/^(Model evaluation|Model değerlendirmesi)$/)
}

test('a clean visit to Model evaluation is dark and Turkish', async ({ page }) => {
  const console = watchConsole(page)
  await page.goto('/')
  await openEvaluation(page)
  await expect(page.locator('html')).toHaveClass(/dark/)
  await expect(page.getByRole('region', { name: 'Deneysel davranış modeli', exact: true })).toBeVisible()
  await expectNoHorizontalScroll(page)
  console.expectClean()
})

test.describe('in English', () => {
  test.beforeEach(async ({ page }) => {
    await page.addInitScript(() => {
      if (!window.localStorage.getItem('tf-lang')) window.localStorage.setItem('tf-lang', 'en')
    })
    await page.goto('/')
    await openEvaluation(page)
  })

  test('shows the measured recipe, declared tests, the chart and the limits', async ({ page }) => {
    const console = watchConsole(page)
    const report = page.getByRole('region', { name: 'Experimental behavior model', exact: true })
    await expect(report.getByText(/^Model synthetic-demo · trained \d{2}\.\d{2} \d{2}:\d{2}/)).toBeVisible()
    await expect(report.getByText('Score line')).toBeVisible()
    await expect(page.getByRole('region', { name: 'Declared tests (fixed before the results were seen) · table' })).toBeVisible()
    await expect(page.getByRole('img', { name: 'What the model looks at most' })).toContainText('Steady rhythm')
    const table = page.getByRole('button', { name: 'Show table' })
    await expect(table).toHaveAttribute('aria-expanded', 'false')
    await expect(page.getByText('The malware recordings are lab infections from 2011–2024', { exact: false })).toBeVisible()
    await expectNoHorizontalScroll(page)
    console.expectClean()
  })

  test('review screenshots in Turkish: dark then light', async ({ page }, testInfo) => {
    const console = watchConsole(page)
    await expect(page.getByRole('region', { name: 'Experimental behavior model', exact: true })).toBeVisible()
    await turkishScreenshots(page, testInfo, 'evaluation')
    console.expectClean()
  })
})
