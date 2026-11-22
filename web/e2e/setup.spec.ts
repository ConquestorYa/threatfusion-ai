import { expect, test, type Page } from '@playwright/test'

import { expectNoHorizontalScroll, turkishScreenshots, watchConsole } from './helpers.ts'

async function openSetup(page: Page) {
  await page.getByRole('navigation').getByRole('button', { name: /^(Setup & CTI updates|Kurulum ve CTI güncellemeleri)$/ }).click()
  await expect(page.getByRole('heading', { level: 1 })).toHaveText(/^(Setup & CTI updates|Kurulum ve CTI güncellemeleri)$/)
}

test('a clean visit to Setup is dark and Turkish', async ({ page }) => {
  await page.goto('/')
  // A refresh record exists, so the app opens on What to check, not Setup.
  await expect(page.getByRole('heading', { level: 1 })).toHaveText('Bakılacaklar')
  await openSetup(page)
  await expect(page.locator('html')).toHaveClass(/dark/)
  await expect(page.getByRole('button', { name: 'CTI verilerini şimdi güncelle' })).toBeEnabled()
})

test.describe('in English', () => {
  test.beforeEach(async ({ page }) => {
    await page.addInitScript(() => {
      if (!window.localStorage.getItem('tf-lang')) window.localStorage.setItem('tf-lang', 'en')
    })
    await page.goto('/')
    await openSetup(page)
  })

  test('shows mode, keys, CTI status and sources like Streamlit', async ({ page }) => {
    const console = watchConsole(page)
    await expect(page.getByRole('region', { name: 'API keys' })).toContainText('Saved keys: None')
    await expect(page.getByRole('link', { name: 'auth.abuse.ch' })).toHaveAttribute('rel', 'noopener noreferrer')
    const cti = page.getByRole('region', { name: 'CTI data' })
    await expect(cti).toContainText('SGB · Cache still fresh')
    await expect(cti).toContainText('ThreatFox: skipped (no API key).')
    await expect(cti.getByRole('button', { name: 'Update CTI now' })).toBeEnabled() // not clicked: it downloads
    await expect(page.getByRole('region', { name: 'CTI sources · table' })).toContainText('Synthetic demo')
    await expectNoHorizontalScroll(page)
    console.expectClean()
  })

  test('Stop local application asks the launcher; this test server has none', async ({ page }) => {
    const console = watchConsole(page)
    const application = page.getByRole('region', { name: 'Application' })
    await application.getByRole('button', { name: 'Stop local application' }).click()
    await expect(application.getByRole('status')).toContainText('This page is not running under the local launcher.')
    await expect(application).not.toContainText('Streamlit')
    console.expectClean()
  })

  test('keys are saved without being shown again, then forgotten', async ({ page }) => {
    const keys = page.getByRole('region', { name: 'API keys' })
    await keys.getByLabel('ThreatFox API key').fill('synthetic-e2e-key')
    await keys.getByLabel('URLhaus API key').fill('synthetic-e2e-key')
    await keys.getByRole('button', { name: 'Apply keys' }).click()
    await expect(keys).toContainText('Saved keys: ThreatFox, URLhaus')
    await expect(keys.getByLabel('ThreatFox API key')).toHaveValue('')
    await expect(page.locator('body')).not.toContainText('synthetic-e2e-key')
    await keys.getByRole('button', { name: 'Forget saved and session keys' }).click()
    await expect(keys).toContainText('Saved keys: None')
  })

  test('automatic update settings are saved and survive a reload', async ({ page }) => {
    const schedule = page.getByRole('region', { name: 'Automatic updates' })
    await schedule.getByLabel('Automatic updates while the app is running').check()
    await schedule.getByLabel('Update interval (hours)').selectOption('12')
    await schedule.getByRole('button', { name: 'Save update settings' }).click()
    await page.reload()
    await openSetup(page)
    await expect(schedule.getByLabel('Automatic updates while the app is running')).toBeChecked()
    await expect(schedule.getByLabel('Update interval (hours)')).toHaveValue('12')
    await schedule.getByLabel('Automatic updates while the app is running').uncheck()
    await schedule.getByLabel('Update interval (hours)').selectOption('6')
    await schedule.getByRole('button', { name: 'Save update settings' }).click()
    await expect(schedule.getByLabel('Update interval (hours)')).toHaveValue('6')
  })

  test('switching to the synthetic demo hides keys and updates, and back', async ({ page }) => {
    const mode = page.getByRole('region', { name: 'Operating mode' }).getByRole('combobox')
    await mode.selectOption('demo')
    await expect(page.getByText('Demo data is synthetic. Switch to real CTI to configure sources and updates.')).toBeVisible()
    await expect(page.getByRole('region', { name: 'CTI data' })).toHaveCount(0)
    await mode.selectOption('cti-only')
    await expect(page.getByRole('region', { name: 'CTI data' })).toBeVisible()
  })

  test('review screenshots in Turkish: dark then light', async ({ page }, testInfo) => {
    const console = watchConsole(page)
    await expect(page.getByRole('region', { name: 'CTI data' })).toBeVisible()
    await turkishScreenshots(page, testInfo, 'setup')
    console.expectClean()
  })
})
