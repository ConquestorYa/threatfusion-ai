import { expect, test, type Page } from '@playwright/test'

// No screen mixes Turkish and English (Turkish is the default language), and
// no raw ISO time is shown. Same word list as tests/test_api_language.py.
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

async function visibleText(page: Page) {
  return page.evaluate(() => document.body.innerText)
}

function englishWords(text: string) {
  const words = text.replace(DATA, ' ').match(/[A-Za-zÇĞİÖŞÜçğıöşü]+/g) ?? []
  return [...new Set(words.filter((word) => ENGLISH.has(word.toLowerCase())))]
}

async function screen(page: Page, name: string) {
  await page.getByRole('navigation').getByRole('button', { name }).click()
  await expect(page.getByRole('heading', { level: 1 })).toHaveText(name)
  await page.waitForLoadState('networkidle')
}

test('every screen in Turkish has no English words and no raw ISO times', async ({ page }) => {
  await page.goto('/')
  await expect(page.getByRole('heading', { level: 1 })).toHaveText('Bakılacaklar')
  const found: Record<string, string[]> = {}

  await page.getByRole('button', { name: 'Nedenini ve ne yapılacağını göster' }).first().click()
  found['Bakılacaklar'] = englishWords(await visibleText(page))

  await screen(page, 'Ayrıntılar')
  await page.getByRole('button', { name: 'Bu sayfa ne işe yarar?' }).click()
  await page.getByLabel('Yalnızca inceleme gerektiren bağlantıları göster').uncheck()
  await page.getByLabel('İnceleme önceliği olmayan gözlemleri de göster').check()
  const details = await visibleText(page)
  found['Ayrıntılar'] = englishWords(details)
  expect(details).not.toMatch(/\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/)
  expect(details).not.toMatch(/\d{2}:\d{2}:\d{2}\.\d+/)

  await screen(page, 'Deneysel ML')
  for (const guide of await page.getByRole('button', { name: 'Bu nedir?' }).all()) await guide.click()
  const behavior = await visibleText(page)
  found['Deneysel ML'] = englishWords(behavior)
  expect(behavior).not.toMatch(/\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}/)

  await screen(page, 'Hızlı sorgu')
  await page.getByLabel('URL, domain veya IP').fill('https://malicious.example.test/login')
  await page.getByRole('button', { name: 'Kontrol et' }).click()
  await expect(page.getByText('Bilinen tehdit istihbaratı eşleşti')).toBeVisible()
  await page.getByRole('button', { name: 'Teknik domain ayrıntıları' }).click()
  const lookup = await visibleText(page)
  found['Hızlı sorgu'] = englishWords(lookup)
  expect(lookup).not.toMatch(/\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}/)

  await screen(page, 'Telemetriyi analiz et')
  await page.locator('input[type=file]').setInputFiles(new URL('../../data/samples/demo/dns.log', import.meta.url).pathname)
  await page.getByRole('button', { name: 'Analiz et', exact: true }).click()
  await expect(page.getByRole('region', { name: 'Öncelikli bulgular' })).toContainText('malicious.example.test')
  await page.getByRole('button', { name: /^Girdi kalitesi/ }).click()
  let analyze = await visibleText(page)
  for (const tab of ['Cihaz incelemesi', 'Domain incelemesi', 'IOC kanıtı', 'İlişkili etkinlik', 'Dışa aktar ve kaydet']) {
    await page.getByRole('tab', { name: tab }).click()
    await page.waitForLoadState('networkidle')
    analyze += '\n' + (await visibleText(page))
  }
  found['Telemetri'] = englishWords(analyze)
  expect(analyze).not.toMatch(/\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}/)

  await screen(page, 'Kurulum ve CTI güncellemeleri')
  const setup = await visibleText(page)
  found['Kurulum'] = englishWords(setup)
  expect(setup).not.toMatch(/\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}/)

  expect(found).toEqual({ 'Bakılacaklar': [], 'Ayrıntılar': [], 'Deneysel ML': [], 'Hızlı sorgu': [], 'Telemetri': [], 'Kurulum': [] })
})

test('bucket tables are closed by default; the chart is shown', async ({ page }) => {
  await page.goto('/')
  await screen(page, 'Ayrıntılar')
  const investigation = page.getByRole('region', { name: 'Bağlantı incelemesi', exact: true })
  await expect(investigation.getByRole('img')).toBeVisible()
  const toggle = investigation.getByRole('button', { name: 'Tabloyu göster' })
  await expect(toggle).toHaveAttribute('aria-expanded', 'false')
  await expect(investigation.getByRole('region', { name: /tablo$/ })).toHaveCount(0)
  await toggle.click()
  await expect(investigation.getByRole('region', { name: /tablo$/ })).toBeVisible()
})
