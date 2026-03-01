import { expect, test } from '@playwright/test'

type VisualTarget = {
  name: string
  screen: 'accounts' | 'login' | 'settings'
}

const visualTargets: VisualTarget[] = [
  { name: 'accounts', screen: 'accounts' },
  { name: 'login-wizard', screen: 'login' },
  { name: 'settings', screen: 'settings' },
]

for (const target of visualTargets) {
  test(`${target.name} snapshot`, async ({ page }) => {
    await page.goto(`/__visual__?screen=${target.screen}`)
    await page.waitForLoadState('networkidle')
    await expect(page).toHaveScreenshot(`${target.name}.png`, {
      fullPage: true,
    })
  })
}
