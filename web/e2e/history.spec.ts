import { expect, test, type Page } from '@playwright/test'
import path from 'node:path'

import { englishWords, expectNoHorizontalScroll, turkishScreenshots, visibleText, watchConsole } from './helpers.ts'

// Runs against serve-history.sh: the developer configuration with the
// synthetic demo domain artifact, so Analysis history is enabled (as in
// Streamlit). Runs accumulate across tests; each test saves its own.

const SAMPLES = path.resolve(import.meta.dirname, '../../data/samples/demo')

async function open(page: Page, name: RegExp) {
  await page.getByRole('navigation').getByRole('button', { name }).click()
  await expect(page.getByRole('heading', { level: 1 })).toHaveText(name)
}

async function analyzeAndSave(page: Page) {
  await open(page, /^(Analyze telemetry|Telemetriyi analiz et)$/)
  await page.locator('input[type=file]').setInputFiles(path.join(SAMPLES, 'dns.log'))
  await page.getByRole('button', { name: /^(Analyze|Analiz et)$/ }).click()
  await page.getByRole('tab', { name: /^(Export & save|Dışa aktar ve kaydet)$/ }).click()
  await page.getByRole('button', { name: /^(Save aggregate analysis history|Toplu analiz geçmişini kaydet)$/ }).click()
  const saved = page.getByRole('status').filter({ hasText: /#\d+/ })
  await expect(saved).toBeVisible()
  return Number((await saved.textContent())?.match(/#(\d+)/)?.[1])
}

test('a clean visit with history enabled is dark and Turkish and lists the history screen', async ({ page }) => {
  const console = watchConsole(page)
  await page.goto('/')
  await expect(page.locator('html')).toHaveClass(/dark/)
  const nav = page.getByRole('navigation')
  await expect(nav.getByRole('button', { name: 'Analiz geçmişi' })).toBeVisible()
  await expect(nav.getByRole('button', { name: 'Model değerlendirmesi' })).toBeVisible()
  await open(page, /^Analiz geçmişi$/)
  await expectNoHorizontalScroll(page)
  console.expectClean()
})

test.describe('in English', () => {
  test.beforeEach(async ({ page }) => {
    await page.addInitScript(() => {
      if (!window.localStorage.getItem('tf-lang')) window.localStorage.setItem('tf-lang', 'en')
    })
    await page.goto('/')
  })

  test('a saved analysis appears in history and takes an analyst decision', async ({ page }) => {
    const console = watchConsole(page)
    const run = await analyzeAndSave(page)
    await open(page, /^Analysis history$/)
    await expect(page.getByRole('region', { name: 'Analysis history · table' })).toContainText(String(run))
    await expect(page.getByLabel('Inspect saved run')).toHaveValue(String(run))
    await page.getByLabel('Finding to review').selectOption('malicious.example.test')
    await page.getByLabel('Analyst label').selectOption('Confirmed Threat')
    await page.getByLabel('Optional analyst note').fill('checked in the lab')
    await page.getByRole('button', { name: 'Save analyst feedback' }).click()
    await expect(page.getByText('Analyst feedback saved. The original ThreatFusion verdict was not changed.')).toBeVisible()
    await page.getByLabel('Review state').selectOption('Reviewed')
    const findings = page.getByRole('region', { name: 'Analyst review · table' })
    await expect(findings).toContainText('malicious.example.test')
    await expect(findings).toContainText('Confirmed Threat')
    await page.getByRole('button', { name: 'Compare with previous analysis' }).click()
    await expect(page.getByText(/^(Comparing run #\d+ with previous run #\d+\.|No earlier saved analysis exists\.)/)).toBeVisible()
    await expectNoHorizontalScroll(page)
    console.expectClean()
  })

  test('a local suppression hides a priority finding until it is included', async ({ page }) => {
    const console = watchConsole(page)
    await open(page, /^Analyze telemetry$/)
    await page.locator('input[type=file]').setInputFiles(path.join(SAMPLES, 'dns.log'))
    await page.getByRole('button', { name: 'Analyze', exact: true }).click()
    const priority = page.getByRole('region', { name: 'Priority findings' })
    await expect(priority).toContainText('malicious.example.test')
    await page.getByRole('tab', { name: 'Domain investigation' }).click()
    await page.getByLabel('Inspect a domain').selectOption('malicious.example.test')
    await page.getByRole('button', { name: 'Suppress from priority triage' }).click()
    await page.getByLabel('Suppression reason').fill('lab sample')
    await page.getByRole('button', { name: 'Save local suppression' }).click()
    await expect(page.getByText('Locally suppressed from the priority queue · lab sample · No expiry')).toBeVisible()
    await expect(priority).not.toContainText('malicious.example.test')
    await priority.getByLabel(/^Include 1 locally suppressed finding/).check()
    await expect(priority).toContainText('malicious.example.test')
    await page.getByRole('button', { name: 'Remove local suppression' }).click()
    await expect(page.getByRole('button', { name: 'Suppress from priority triage' })).toBeVisible()
    console.expectClean()
  })

  test('Model evaluation shows the lexical holdout state in this mode', async ({ page }) => {
    await open(page, /^Model evaluation$/)
    await expect(page.getByRole('region', { name: 'Final holdout not evaluated' })).toBeVisible()
    await expect(page.getByRole('button', { name: 'What does this page do?' })).toHaveAttribute('aria-expanded', 'true')
  })

  test('review screenshots in Turkish: dark then light', async ({ page }, testInfo) => {
    const console = watchConsole(page)
    await analyzeAndSave(page)
    await open(page, /^Analysis history$/)
    await turkishScreenshots(page, testInfo, 'history')
    console.expectClean()
  })
})

test('the Turkish history page has no English words and no raw ISO times', async ({ page }) => {
  await page.goto('/')
  await analyzeAndSave(page)
  await open(page, /^Analiz geçmişi$/)
  // Open every fold; each click removes one from the collapsed set, so always take the first.
  const collapsed = page.getByRole('main').getByRole('button', { expanded: false })
  for (let guard = 0; guard < 20 && (await collapsed.count()) > 0; guard++) await collapsed.first().click()
  await page.waitForLoadState('networkidle')
  const text = await visibleText(page)
  expect(englishWords(text)).toEqual([])
  expect(text).not.toMatch(/\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}/)
})
