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

/** Demo screenshots in Turkish (the default language): dark first, then light. */
export async function turkishScreenshots(page: Page, testInfo: TestInfo, name: string) {
  await page.getByRole('radio', { name: 'TR' }).click()
  await expect(page.locator('html')).toHaveAttribute('lang', 'tr')
  await expect(page.getByRole('button', { name: 'Açık temaya geç' })).toBeVisible()
  await page.waitForLoadState('networkidle')
  await expect(page.locator('html')).toHaveClass(/dark/)
  await expectNoHorizontalScroll(page)
  await reviewScreenshot(page, testInfo, `${name}-dark`)
  await page.getByRole('button', { name: 'Açık temaya geç' }).click()
  await expect(page.locator('html')).not.toHaveClass(/dark/)
  await expectNoHorizontalScroll(page)
  await reviewScreenshot(page, testInfo, `${name}-light`)
  await page.getByRole('button', { name: 'Koyu temaya geç' }).click()
}

// English UI words that must not appear on a Turkish page (tests/test_api_language.py).
const ENGLISH = new Set(
  `the and with for from after before into than this that these those are was were has have
interval periodic periodicity pattern inspect software activity score ratio timing sustained stale
observe investigate review query queries connection connections session sessions record records
match matches seen first last unknown fresh state reason needs insufficient exact response confidence
refreshed active events verdict same addresses unanswered rejected observed duration payload endings
closes duplicate conflicting originator responder count update updates download show table loading
group device target threat evidence coverage limits check lookup details setup mark suspicious
why open light dark theme language screens bucket bytes window distinct failed attempts known`.split(/\s+/),
)
// Data shown on purpose: CTI source/threat type/tags, file names, brand names.
const DATA = /\b[\w-]+(?:\.[\w-]+)+(?::\d+)?\b|https?:\/\/\S+|Synthetic demo|ThreatFox|URLhaus|VirusTotal|AbuseIPDB|urlscan|Streamlit/g

export async function visibleText(page: Page) {
  return page.evaluate(() => document.body.innerText)
}

export function englishWords(text: string) {
  const words = text.replace(DATA, ' ').match(/[A-Za-zÇĞİÖŞÜçğıöşü]+/g) ?? []
  return [...new Set(words.filter((word) => ENGLISH.has(word.toLowerCase())))]
}

