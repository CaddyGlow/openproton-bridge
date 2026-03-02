import type { Page } from '@playwright/test'
import { expect, test } from '@playwright/test'
import {
  emitBridgeUiEvent,
  getTauriInvokeCalls,
  installTauriRuntimeMocks,
} from './helpers/tauri-runtime-mock'

async function ensureLoginWizardOpen(page: Page): Promise<void> {
  const wizardHeading = page.getByRole('heading', { name: 'Sign In Wizard' })
  if (!(await wizardHeading.isVisible().catch(() => false))) {
    await page.getByRole('button', { name: 'Open Sign-In Wizard' }).click()
  }
  await expect(wizardHeading).toBeVisible()
}

async function closeLoginWizardIfOpen(page: Page): Promise<void> {
  const closeButton = page.getByRole('button', { name: 'Close' })
  if (await closeButton.isVisible().catch(() => false)) {
    await closeButton.click()
  }
}

async function openSettingsSection(page: Page): Promise<void> {
  await closeLoginWizardIfOpen(page)
  await page.getByRole('button', { name: 'Settings', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Runtime' })).toBeVisible()
}

test.describe('bridge-ui parity runtime flows', () => {
  test('auth wizard opens in credentials welcome state', async ({ page }) => {
    await installTauriRuntimeMocks(page)
    await page.goto('/')

    await expect(page.getByRole('button', { name: 'A alice@proton.me Ready' })).toBeVisible()
    await ensureLoginWizardOpen(page)

    const wizardDialog = page.getByRole('dialog', { name: 'Proton login wizard' })
    await expect(wizardDialog.getByText('Account Credentials', { exact: true })).toBeVisible()
    await expect(wizardDialog.getByPlaceholder('user@proton.me')).toBeVisible()
    await expect(wizardDialog.getByPlaceholder('password')).toBeVisible()
    await expect(wizardDialog.getByRole('button', { name: 'Continue' })).toBeVisible()
  })

  test('auth wizard follows ui-event login transitions on the app route', async ({ page }) => {
    await installTauriRuntimeMocks(page)
    await page.goto('/')

    await expect(page.getByRole('button', { name: 'A alice@proton.me Ready' })).toBeVisible()
    await ensureLoginWizardOpen(page)
    const wizardDialog = page.getByRole('dialog', { name: 'Proton login wizard' })
    await expect(wizardDialog.getByText('Account Credentials', { exact: true })).toBeVisible()

    await emitBridgeUiEvent(page, {
      code: 'tfa_requested',
      message: '2FA code required',
    })
    await expect(page.getByRole('button', { name: 'Submit 2FA' })).toBeVisible()

    await emitBridgeUiEvent(page, {
      code: 'fido_pin_required',
      message: 'Security key PIN required',
    })
    await expect(page.getByRole('button', { name: 'Submit PIN' })).toBeVisible()

    await emitBridgeUiEvent(page, {
      code: 'login_finished',
      message: 'Sign-in completed',
    })
    await expect(wizardDialog.getByText('Account authentication finished successfully.')).toBeVisible()
  })

  test('client config wizard progresses through selector and configuration steps', async ({ page }) => {
    await installTauriRuntimeMocks(page)
    await page.goto('/')

    await expect(page.getByRole('button', { name: 'A alice@proton.me Ready' })).toBeVisible()
    await closeLoginWizardIfOpen(page)
    await page.getByRole('button', { name: 'Configure Email Client' }).click()

    const clientConfigDialog = page.getByRole('dialog', { name: 'Client configuration wizard' })
    await expect(clientConfigDialog.getByTestId('client-config-selector')).toBeVisible()
    await expect(clientConfigDialog.getByRole('button', { name: 'Apple Mail' })).toBeVisible()
    await expect(clientConfigDialog.getByRole('button', { name: 'Microsoft Outlook' })).toBeVisible()
    await expect(clientConfigDialog.getByRole('button', { name: 'Mozilla Thunderbird' })).toBeVisible()
    await expect(clientConfigDialog.getByRole('button', { name: 'Other' })).toBeVisible()
    await expect(clientConfigDialog.getByRole('button', { name: 'Setup later' })).toBeVisible()

    await clientConfigDialog.getByRole('button', { name: 'Apple Mail' }).click()
    await expect(clientConfigDialog.getByTestId('client-config-apple-mail')).toBeVisible()

    await clientConfigDialog.getByRole('button', { name: 'Continue' }).click()
    await expect(clientConfigDialog.getByTestId('client-config-parameters')).toBeVisible()
    await expect(clientConfigDialog.getByText('IMAP', { exact: true })).toBeVisible()
    await expect(clientConfigDialog.getByText('SMTP', { exact: true })).toBeVisible()
    await expect(clientConfigDialog.getByText('Account: alice@proton.me', { exact: true })).toBeVisible()

    await clientConfigDialog.getByRole('button', { name: 'Done' }).click()
    await expect(clientConfigDialog.getByTestId('client-config-done')).toBeVisible()
    await expect(clientConfigDialog.getByText('Configuration Ready')).toBeVisible()
  })

  test('sync events render user parity progress in Users card', async ({ page }) => {
    await installTauriRuntimeMocks(page)
    await page.goto('/')

    await expect(page.getByRole('button', { name: 'A alice@proton.me Ready' })).toBeVisible()

    await emitBridgeUiEvent(page, {
      code: 'sync_started',
      message: 'Synchronization started',
      refresh_hints: ['sync_user:u1', 'sync_username:alice@proton.me'],
    })
    await expect(page.getByText('Recovering')).toBeVisible()

    await emitBridgeUiEvent(page, {
      code: 'sync_finished',
      message: 'Synchronization complete',
      refresh_hints: ['sync_user:u1', 'sync_username:alice@proton.me'],
    })
    await expect(page.getByText('Synchronizing (100%)')).toBeVisible()
  })

  test('cache move status updates in settings after apply and disk-cache ui events', async ({ page }) => {
    await installTauriRuntimeMocks(page, {
      appSettings: {
        disk_cache_path: '/tmp/cache-a',
      },
    })
    await page.goto('/')

    await expect(page.getByRole('button', { name: 'A alice@proton.me Ready' })).toBeVisible()
    await closeLoginWizardIfOpen(page)
    await page.getByRole('button', { name: 'Settings', exact: true }).click()
    const generalSettingsCard = page.locator('article').filter({
      has: page.getByRole('heading', { name: 'General Settings' }),
    })

    const cachePathInput = generalSettingsCard.getByLabel('Disk Cache Path')

    await cachePathInput.fill('/tmp/cache-b')
    await page.getByRole('button', { name: 'Apply Settings' }).click()
    await expect(generalSettingsCard.getByText('Moving cache path...').first()).toBeVisible()
    await expect(generalSettingsCard.getByText('Waiting for cache operation confirmation...').first()).toBeVisible()

    await emitBridgeUiEvent(page, {
      code: 'disk_cache_saved',
      message: 'Disk cache moved to /tmp/cache-b',
    })
    await expect(generalSettingsCard.getByText('Cache move completed.').first()).toBeVisible()
    await expect(generalSettingsCard.getByText('Disk cache moved to /tmp/cache-b', { exact: true }).first()).toBeVisible()

    await cachePathInput.fill('/tmp/cache-c')
    await page.getByRole('button', { name: 'Apply Settings' }).click()
    await expect(generalSettingsCard.getByText('Moving cache path...').first()).toBeVisible()

    await emitBridgeUiEvent(page, {
      level: 'error',
      code: 'disk_cache_error',
      message: 'Permission denied while moving disk cache',
    })
    await expect(generalSettingsCard.getByText('Cache move failed.').first()).toBeVisible()
    await expect(
      generalSettingsCard.getByText('Permission denied while moving disk cache', { exact: true }).first(),
    ).toBeVisible()

    const diskCacheCommands = (await getTauriInvokeCalls(page))
      .filter((call) => call.cmd === 'bridge_set_disk_cache_path')
      .map((call) => String(call.args.path))

    expect(diskCacheCommands).toEqual(['/tmp/cache-b', '/tmp/cache-c'])
  })

  test('settings sections and maintenance controls progress through parity states', async ({ page }) => {
    await installTauriRuntimeMocks(page)
    await page.goto('/')

    await expect(page.getByRole('button', { name: 'A alice@proton.me Ready' })).toBeVisible()
    await openSettingsSection(page)

    await expect(page.getByRole('heading', { name: 'General Settings' })).toBeVisible()
    await expect(page.getByRole('heading', { name: 'TLS Settings' })).toBeVisible()

    const generalToggle = page.getByRole('button', { name: 'General' })
    const advancedToggle = page.getByRole('button', { name: 'Advanced' })
    const maintenanceToggle = page.getByRole('button', { name: 'Maintenance' })

    await expect(generalToggle).toHaveAttribute('aria-expanded', 'true')
    await expect(advancedToggle).toHaveAttribute('aria-expanded', 'true')
    await expect(maintenanceToggle).toHaveAttribute('aria-expanded', 'true')
    await expect(page.getByText('Autostart', { exact: true })).toBeVisible()
    await expect(page.getByText('Beta Channel', { exact: true })).toBeVisible()
    await expect(page.getByLabel('Disk Cache Path')).toBeVisible()

    await generalToggle.click()
    await expect(generalToggle).toHaveAttribute('aria-expanded', 'false')
    await expect(page.getByText('Autostart', { exact: true })).toHaveCount(0)
    await generalToggle.click()
    await expect(generalToggle).toHaveAttribute('aria-expanded', 'true')
    await expect(page.getByText('Autostart', { exact: true })).toBeVisible()

    await advancedToggle.click()
    await expect(advancedToggle).toHaveAttribute('aria-expanded', 'false')
    await expect(page.getByText('Beta Channel', { exact: true })).toHaveCount(0)
    await advancedToggle.click()
    await expect(advancedToggle).toHaveAttribute('aria-expanded', 'true')
    await expect(page.getByText('Beta Channel', { exact: true })).toBeVisible()

    await maintenanceToggle.click()
    await expect(maintenanceToggle).toHaveAttribute('aria-expanded', 'false')
    await expect(page.getByLabel('Disk Cache Path')).toHaveCount(0)
    await maintenanceToggle.click()
    await expect(maintenanceToggle).toHaveAttribute('aria-expanded', 'true')
    await expect(page.getByLabel('Disk Cache Path')).toBeVisible()

    await expect(page.getByRole('button', { name: 'Install TLS Certificate' })).toBeVisible()
    await expect(page.getByRole('button', { name: 'Export TLS Certificates' })).toBeVisible()

    await page.getByRole('button', { name: 'Install TLS Certificate' }).click()
    await expect(page.getByText('certificate installed', { exact: true })).toBeVisible()
    await page.getByLabel('Export Directory').fill('/tmp/runtime-certs')
    await page.getByRole('button', { name: 'Export TLS Certificates' }).click()
    await expect(page.getByText('export completed', { exact: true })).toBeVisible()

    const runtimeCommands = (await getTauriInvokeCalls(page)).map((call) => call.cmd)
    expect(runtimeCommands).toContain('bridge_install_tls_certificate')
    expect(runtimeCommands).toContain('bridge_export_tls_certificates')
  })

  test('settings overflow menu opens with runtime window actions', async ({ page }) => {
    await installTauriRuntimeMocks(page)
    await page.goto('/')

    await expect(page.getByRole('button', { name: 'A alice@proton.me Ready' })).toBeVisible()
    await openSettingsSection(page)

    await page.getByRole('button', { name: 'Open runtime settings menu' }).click()
    const runtimeMenu = page.getByTestId('runtime-settings-overflow-menu')
    await expect(runtimeMenu).toBeVisible()
    await expect(runtimeMenu.getByRole('menuitem', { name: 'Close window' })).toBeVisible()
    await expect(runtimeMenu.getByRole('menuitem', { name: 'Quit Bridge' })).toBeVisible()
  })
})
