import { defineConfig, devices } from '@playwright/test'

// Browser tests against the real loopback API and the built page (npm run build).
// The system colour scheme is light on purpose: the app must still open dark.
const PORT = Number(process.env.E2E_PORT ?? 8611)
// Analysis history needs the developer configuration (a model, not CTI-only).
const HISTORY_PORT = Number(process.env.E2E_HISTORY_PORT ?? 8612)
const HISTORY = /history\.spec\.ts/

export default defineConfig({
  testDir: './e2e',
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: [['list']],
  use: {
    baseURL: `http://127.0.0.1:${PORT}`,
    colorScheme: 'light',
    trace: 'retain-on-failure',
  },
  projects: [
    { name: 'desktop', testIgnore: HISTORY, use: { ...devices['Desktop Chrome'], viewport: { width: 1280, height: 800 } } },
    {
      name: 'mobile',
      testIgnore: HISTORY,
      use: { ...devices['Desktop Chrome'], viewport: { width: 375, height: 812 }, hasTouch: true },
    },
    {
      name: 'history-desktop',
      testMatch: HISTORY,
      use: { ...devices['Desktop Chrome'], viewport: { width: 1280, height: 800 }, baseURL: `http://127.0.0.1:${HISTORY_PORT}` },
    },
    {
      name: 'history-mobile',
      testMatch: HISTORY,
      use: {
        ...devices['Desktop Chrome'],
        viewport: { width: 375, height: 812 },
        hasTouch: true,
        baseURL: `http://127.0.0.1:${HISTORY_PORT}`,
      },
    },
  ],
  webServer: [
    {
      command: 'bash e2e/serve.sh',
      url: `http://127.0.0.1:${PORT}/api/health`,
      reuseExistingServer: false,
      timeout: 60_000,
      env: { E2E_PORT: String(PORT) },
    },
    {
      command: 'bash e2e/serve-history.sh',
      url: `http://127.0.0.1:${HISTORY_PORT}/api/health`,
      reuseExistingServer: false,
      timeout: 60_000,
      env: { E2E_PORT: String(HISTORY_PORT) },
    },
  ],
})
