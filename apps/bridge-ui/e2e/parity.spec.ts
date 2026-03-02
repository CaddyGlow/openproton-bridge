import { expect, test } from '@playwright/test'

test.describe('bridge-ui parity fixture flows', () => {
  test('auth flow fixture renders security key state', async ({ page }) => {
    await page.goto('/__visual__?screen=login&state=security-key&theme=dark')

    await expect(page.getByTestId('auth-security-key-title')).toHaveText('Security key authentication')
    await expect(page.getByTestId('auth-security-key-submit')).toHaveText('Authenticate')
    await expect(page.getByRole('link', { name: 'Use authenticator app instead' })).toBeVisible()
  })

  test('account flow fixture renders sync progress state', async ({ page }) => {
    await page.goto('/__visual__?screen=accounts&state=sync-progress&progress=4&theme=dark')

    await expect(page.getByTestId('sync-progress-label')).toHaveText('Synchronizing (4%)..')
    await expect(page.getByTestId('sync-progress-main')).toHaveText('Synchronizing (4%)...')
  })

  test('settings flow fixture renders cache move states', async ({ page }) => {
    await page.goto('/__visual__?screen=settings&state=cache-move&cacheState=moving&cacheProgress=42&theme=dark')
    await expect(page.getByTestId('cache-move-status')).toHaveText('Moving cache (42%)')

    await page.goto('/__visual__?screen=settings&state=cache-move&cacheState=done&theme=dark')
    await expect(page.getByTestId('cache-move-status')).toHaveText('Cache moved successfully')
  })
})
