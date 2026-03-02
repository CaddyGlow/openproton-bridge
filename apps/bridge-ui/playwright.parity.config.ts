import { defineConfig, devices } from '@playwright/test'
import { existsSync } from 'node:fs'

function resolveChromiumPath(): string | undefined {
  const candidates = [
    process.env.PLAYWRIGHT_CHROMIUM_PATH,
    '/etc/profiles/per-user/rick/bin/chromium',
    '/usr/bin/chromium-browser',
    '/usr/bin/chromium',
  ]
  return candidates.find((candidate) => candidate && existsSync(candidate))
}

const executablePath = resolveChromiumPath()

export default defineConfig({
  testDir: './e2e',
  testMatch: /parity\.spec\.ts/,
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: 'list',
  use: {
    baseURL: 'http://127.0.0.1:4173',
    viewport: { width: 1440, height: 940 },
    locale: 'en-US',
    timezoneId: 'UTC',
    animations: 'disabled',
    launchOptions: executablePath ? { executablePath } : undefined,
  },
  projects: [
    {
      name: 'chromium-light',
      use: {
        ...devices['Desktop Chrome'],
        colorScheme: 'light',
      },
    },
  ],
  webServer: {
    command: 'bun run dev --host 127.0.0.1 --port 4173',
    url: 'http://127.0.0.1:4173',
    reuseExistingServer: true,
    timeout: 120_000,
  },
})
