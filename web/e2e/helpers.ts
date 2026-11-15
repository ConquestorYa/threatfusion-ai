import { expect, type Page, type TestInfo } from '@playwright/test'
import path from 'node:path'

/** Collects console errors and page errors; call expectClean() at the end of a test. */
export function watchConsole(page: Page) {
  const errors: string[] = []
  page.on('console', (message) => {
    if (message.type() === 'error') errors.push(message.text())
  })
  page.on('pageerror', (error) => errors.push(error.message))
  return {
    errors,
    expectClean: () => expect(errors, 'browser console errors').toEqual([]),
  }
}

/** The page must never need horizontal scrolling. */
export async function expectNoHorizontalScroll(page: Page) {
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth)
  expect(overflow).toBeLessThanOrEqual(0)
}

const SCREENSHOT_DIR = path.resolve(import.meta.dirname, '../../.playwright-mcp/screens')

/** Review screenshots (ignored by Git); only when SCREENSHOTS=1. */
export async function reviewScreenshot(page: Page, testInfo: TestInfo, name: string) {
  if (process.env.SCREENSHOTS !== '1') return
  const file = path.join(SCREENSHOT_DIR, `${name}-${testInfo.project.name}.png`)
  await page.screenshot({ path: file, fullPage: true, animations: 'disabled' })
}

/** Clear every mark in the current list, so tests do not depend on order. */
export async function clearMarks(page: Page) {
  const review = await (await page.request.get('/api/review')).json()
  const keys = [...review.items.filter((item: { mark: string | null }) => item.mark), ...review.known].map(
    (item: { key: string }) => item.key,
  )
  for (const key of keys) {
    const response = await page.request.put('/api/review/marks', {
      data: { key, mark: null },
      headers: { Origin: new URL(page.url() || 'http://127.0.0.1:8611').origin, 'Sec-Fetch-Site': 'same-origin' },
    })
    expect(response.status()).toBe(204)
  }
}
