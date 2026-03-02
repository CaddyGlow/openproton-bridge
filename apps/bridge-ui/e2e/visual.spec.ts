import { expect, test } from '@playwright/test'

type VisualTarget = {
  name: string
  screen: 'accounts' | 'login' | 'settings'
  state: string
  params?: Record<string, string>
}

const visualTargets: VisualTarget[] = [
  { name: 'login-welcome', screen: 'login', state: 'welcome' },
  { name: 'login-security-key', screen: 'login', state: 'security-key' },
  { name: 'login-client-selector', screen: 'login', state: 'client-selector' },
  { name: 'login-client-config', screen: 'login', state: 'client-config' },
  { name: 'accounts-sync-progress', screen: 'accounts', state: 'sync-progress', params: { progress: '4' } },
  { name: 'settings-general', screen: 'settings', state: 'general' },
  { name: 'settings-advanced', screen: 'settings', state: 'advanced' },
  { name: 'settings-maintenance', screen: 'settings', state: 'maintenance' },
  { name: 'settings-menu-open', screen: 'settings', state: 'menu-open', params: { progress: '6' } },
  { name: 'settings-cache-move', screen: 'settings', state: 'cache-move', params: { cacheState: 'moving', cacheProgress: '42' } },
]

for (const target of visualTargets) {
  test(`${target.name} snapshot`, async ({ page }) => {
    const query = new URLSearchParams({
      screen: target.screen,
      state: target.state,
      ...(target.params || {}),
    })
    await page.goto(`/__visual__?${query.toString()}`)
    await page.waitForLoadState('networkidle')
    await expect(page).toHaveScreenshot(`${target.name}.png`, {
      fullPage: true,
    })
  })
}
