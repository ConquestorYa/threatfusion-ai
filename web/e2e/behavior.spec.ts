import { expect, test, type Page } from '@playwright/test'

import { expectNoHorizontalScroll, watchConsole, turkishScreenshots } from './helpers.ts'

// The browser-test installation has a synthetic, untrained behavior model
// (serve.sh, --behavior-model). Its documentation addresses are never scored
// (only internet addresses are), so the model checks 0 destinations here;
// cards are covered by Vitest and tests/test_api_behavior.py.

async function openBehavior(page: Page) {
  await page.getByRole('navigation').getByRole('button', { name: /^(Experimental ML|Deneysel ML)$/ }).click()
  await expect(page.getByRole('heading', { level: 1 })).toHaveText(/^(Experimental ML|Deneysel ML)$/)
}

test('a clean visit to Experimental ML is dark and Turkish', async ({ page }) => {
  const console = watchConsole(page)
  await page.goto('/')
  await openBehavior(page)
  await expect(page.locator('html')).toHaveClass(/dark/)
  await expect(page.getByRole('heading', { level: 1 })).toHaveText('Deneysel ML')
  await expect(page.getByRole('region', { name: 'Bu bilgisayar için yeni' })).toBeVisible()
  await expectNoHorizontalScroll(page)
  console.expectClean()
})

test.describe('in English', () => {
  test.beforeEach(async ({ page }) => {
    await page.addInitScript(() => {
      if (!window.localStorage.getItem('tf-lang')) window.localStorage.setItem('tf-lang', 'en')
    })
    await page.goto('/')
    await openBehavior(page)
  })

  test('shows new destinations, the model summary, its test figures and the guide', async ({ page }) => {
    const console = watchConsole(page)
    await expect(page.getByText('Experimental · a machine-learning hint beside What to check, never a verdict')).toBeVisible()
    const model = page.getByRole('region', { name: 'Behavior model' })
    await expect(model.getByText('Nothing unusual in how your devices talk')).toBeVisible()
    await expect(model.getByText('Destinations checked')).toBeVisible()
    await expect(model.getByText('Caught in testing', { exact: true })).toBeVisible()
    await expect(model.getByText(/^Model synthetic-demo · trained \d{2}\.\d{2} \d{2}:\d{2}/)).toBeVisible()
    await model.getByRole('button', { name: 'What is this?' }).click()
    await expect(model.getByText('How does it learn?', { exact: false })).toBeVisible()
    await expectNoHorizontalScroll(page)
    console.expectClean()
  })

  test('review screenshots in Turkish: dark then light', async ({ page }, testInfo) => {
    const console = watchConsole(page)
    await expect(page.getByRole('region', { name: 'Behavior model' })).toBeVisible()
    await turkishScreenshots(page, testInfo, 'behavior')
    console.expectClean()
  })
})
