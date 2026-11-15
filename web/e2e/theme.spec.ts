import { expect, test } from '@playwright/test'

import { watchConsole } from './helpers.ts'

// The browser context reports a light system theme (playwright.config.ts).

test('a clean first visit opens dark even when the system is light', async ({ page }) => {
  const console = watchConsole(page)
  await page.goto('/')
  await expect(page.locator('html')).toHaveClass(/dark/)
  await expect(page.getByRole('heading', { name: 'What to check' })).toBeVisible()
  const background = await page.evaluate(() => getComputedStyle(document.body).backgroundColor)
  expect(background).toBe('rgb(18, 21, 25)') // --background #121519
  expect(await page.evaluate(() => window.localStorage.getItem('tf-theme'))).toBeNull()
  console.expectClean()
})

test('the theme is applied before the app script runs (no light flash)', async ({ page }) => {
  // Block the React bundle: only index.html and theme-init.js run.
  await page.route('**/assets/*.js', (route) => route.abort())
  await page.goto('/')
  await expect(page.locator('html')).toHaveClass(/dark/)
  expect(await page.evaluate(() => document.getElementById('root')?.childElementCount)).toBe(0)
  const scheme = await page.evaluate(() => getComputedStyle(document.documentElement).colorScheme)
  expect(scheme).toBe('dark')
})

test('light is chosen only with the button and is remembered', async ({ page }) => {
  await page.goto('/')
  await page.getByRole('button', { name: 'Switch to light theme' }).click()
  await expect(page.locator('html')).not.toHaveClass(/dark/)
  expect(await page.evaluate(() => window.localStorage.getItem('tf-theme'))).toBe('light')

  await page.reload()
  await expect(page.locator('html')).not.toHaveClass(/dark/)
  await page.route('**/assets/*.js', (route) => route.abort())
  await page.reload()
  await expect(page.locator('html')).not.toHaveClass(/dark/) // remembered before the app runs

  await page.unroute('**/assets/*.js')
  await page.reload()
  await page.getByRole('button', { name: 'Switch to dark theme' }).click()
  await expect(page.locator('html')).toHaveClass(/dark/)
  expect(await page.evaluate(() => window.localStorage.getItem('tf-theme'))).toBe('dark')
})
