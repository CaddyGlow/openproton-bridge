<script lang="ts">
  import { onMount } from 'svelte'
  import { fade, fly } from 'svelte/transition'
  import { get } from 'svelte/store'
  import {
    bridgeStatus,
    connect,
    disconnect,
    initBridgeStore,
    resetError,
    streamLog,
    updateConfigPath,
  } from './lib/stores/bridge'
  import {
    onBridgeUiEvent,
    onCaptchaToken,
    exportTlsCertificates,
    fetchUsers,
    getAppSettings,
    getHostname,
    getMailSettings,
    installTlsCertificate,
    isPortFree,
    isTlsCertificateInstalled,
    loginFido,
    login,
    login2fa,
    login2passwords,
    loginAbort,
    openCaptchaWindow,
    closeCaptchaWindow,
    fidoAssertionAbort,
    logoutUser,
    removeUser,
    setColorSchemeName,
    setDiskCachePath,
    setIsAllMailVisible,
    setIsAutostartOn,
    setIsBetaEnabled,
    setIsDohEnabled,
    setIsTelemetryDisabled,
    setUserSplitMode,
    setMailSettings,
    type AppSettings,
    type BridgeUiEvent,
    type MailSettings,
    type UserSummary,
  } from './lib/api/bridge'
  import { logger } from './lib/logging/logger'
  import BridgeConnectionCard from './lib/components/cards/BridgeConnectionCard.svelte'
  import LoginWizard from './lib/components/LoginWizard.svelte'
  import ErrorStateCard from './lib/components/cards/ErrorStateCard.svelte'
  import GeneralSettingsCard from './lib/components/cards/GeneralSettingsCard.svelte'
  import StreamEventsCard from './lib/components/cards/StreamEventsCard.svelte'
  import UsersCard from './lib/components/cards/UsersCard.svelte'
  import MailSettingsCard from './lib/components/cards/MailSettingsCard.svelte'
  import TlsSettingsCard from './lib/components/cards/TlsSettingsCard.svelte'
  import EventToastsCard from './lib/components/cards/EventToastsCard.svelte'

  const defaultAppSettings: AppSettings = {
    is_autostart_on: false,
    is_beta_enabled: false,
    is_all_mail_visible: true,
    is_telemetry_disabled: false,
    disk_cache_path: '',
    is_doh_enabled: true,
    color_scheme_name: 'system',
  }

  const sections = [
    { id: 'accounts', label: 'Accounts' },
    { id: 'mail', label: 'Mail' },
    { id: 'settings', label: 'Settings' },
    { id: 'activity', label: 'Activity' },
  ] as const

  type SectionId = (typeof sections)[number]['id']
  type ThemeMode = 'system' | 'light' | 'dark'

  let stop = $state<(() => void) | undefined>(undefined)
  let stopUi = $state<(() => void) | undefined>(undefined)
  let stopCaptchaToken = $state<(() => void) | undefined>(undefined)
  let activeSection = $state<SectionId>('accounts')
  let loginWizardOpen = $state(false)
  let lastLoginStepSeen = $state('credentials')
  let systemPrefersDark = $state(false)
  let prefersReducedMotion = $state(false)
  let sectionTransitionDuration = $derived(prefersReducedMotion ? 0 : 220)
  let configPathInput = $state('')
  let hostname = $state('')
  let users = $state<UserSummary[]>([])
  let usersLoading = $state(false)
  let appSettings = $state<AppSettings>({ ...defaultAppSettings })
  let settingsStatus = $state('')
  let diskCachePathInput = $state('')
  let colorSchemeNameInput = $state('system')
  let imapPort = $state('1143')
  let smtpPort = $state('1025')
  let useSslImap = $state(false)
  let useSslSmtp = $state(false)
  let saveStatus = $state('')
  let portToCheck = $state('1143')
  let portCheckResult = $state('')
  let loginUsername = $state('')
  let loginPassword = $state('')
  let twoFactorCode = $state('')
  let mailboxPassword = $state('')
  let fidoAssertionPayload = $state('')
  let hvVerificationUrl = $state('')
  let hvCaptchaToken = $state('')
  let loginStatus = $state('')
  let tlsInstalled = $state<boolean | null>(null)
  let tlsExportDir = $state('')
  let tlsStatus = $state('')
  let toastLog = $state<string[]>([])

  function normalizeThemeMode(value: string | undefined): ThemeMode {
    if (value === 'light' || value === 'dark') {
      return value
    }
    return 'system'
  }

  function formatLoginStep(step: string): string {
    return step.replaceAll('_', ' ')
  }

  function syncLoginStatusWithStep(step: string, force = false) {
    if (!force && step === lastLoginStepSeen) {
      return
    }
    lastLoginStepSeen = step

    if (step !== 'credentials') {
      activeSection = 'accounts'
      loginWizardOpen = true
    }

    if (step === '2fa') {
      loginStatus = 'CAPTCHA accepted. Enter your 2FA code.'
    } else if (step === '2fa_or_fido') {
      loginStatus = 'CAPTCHA accepted. Complete 2FA or security key verification.'
    } else if (step === 'fido' || step === 'fido_touch' || step === 'fido_pin') {
      loginStatus = 'CAPTCHA accepted. Complete security key verification.'
    } else if (step === 'mailbox_password') {
      loginStatus = 'Account verified. Enter mailbox password to unlock.'
    } else if (step === 'done') {
      loginStatus = 'Login completed.'
    }
  }

  function resolveTheme(mode: ThemeMode): 'light' | 'dark' {
    if (mode === 'system') {
      return systemPrefersDark ? 'dark' : 'light'
    }
    return mode
  }

  $effect(() => {
    if (typeof document === 'undefined') {
      return
    }
    const mode = normalizeThemeMode(colorSchemeNameInput)
    document.documentElement.dataset.theme = resolveTheme(mode)
  })

  async function persistThemeMode(nextMode: ThemeMode) {
    colorSchemeNameInput = nextMode
    appSettings.color_scheme_name = nextMode
    try {
      await setColorSchemeName(nextMode)
      settingsStatus = `theme set to ${nextMode}`
    } catch (error) {
      settingsStatus = `theme update failed: ${String(error)}`
      logger.error('app', 'set theme mode failed', { error: String(error), mode: nextMode })
    }
  }

  function cycleThemeMode() {
    const modes: ThemeMode[] = ['system', 'light', 'dark']
    const current = normalizeThemeMode(colorSchemeNameInput)
    const currentIndex = modes.indexOf(current)
    const nextMode = modes[(currentIndex + 1) % modes.length]
    void persistThemeMode(nextMode)
  }

  function openLoginWizard() {
    activeSection = 'accounts'
    loginWizardOpen = true
  }

  function closeLoginWizard() {
    loginWizardOpen = false
  }

  $effect(() => {
    syncLoginStatusWithStep($bridgeStatus.login_step)
  })

  function pushToast(message: string) {
    toastLog = [`${new Date().toLocaleTimeString()} ${message}`, ...toastLog].slice(0, 24)
  }

  function extractHvUrl(text: string): string | null {
    const match = text.match(/https:\/\/verify\.proton\.me\/\S+/i)
    if (!match) {
      return null
    }
    return match[0].replace(/[),.;]+$/, '')
  }

  async function openCaptchaVerificationWindow() {
    if (!hvVerificationUrl) {
      return
    }
    try {
      await openCaptchaWindow(hvVerificationUrl)
      loginStatus = 'complete CAPTCHA in the verification window, then click Retry CAPTCHA'
    } catch (error) {
      logger.error('app', 'open captcha window failed', { error: String(error) })
      loginStatus = `failed to open verification window: ${String(error)}`
    }
  }

  async function closeCaptchaVerificationWindow() {
    try {
      await closeCaptchaWindow()
    } catch (error) {
      logger.error('app', 'close captcha window failed', { error: String(error) })
    }
  }

  async function refreshUsersData() {
    hostname = await getHostname()
    users = await fetchUsers()
  }

  async function refreshMailServerSettings() {
    const settings: MailSettings = await getMailSettings()
    imapPort = String(settings.imap_port)
    smtpPort = String(settings.smtp_port)
    useSslImap = settings.use_ssl_for_imap
    useSslSmtp = settings.use_ssl_for_smtp
  }

  async function refreshGeneralSettings() {
    appSettings = await getAppSettings()
    diskCachePathInput = appSettings.disk_cache_path
    colorSchemeNameInput = appSettings.color_scheme_name
  }

  async function refreshTlsSettings() {
    tlsInstalled = await isTlsCertificateInstalled()
  }

  async function refreshBridgeData() {
    logger.debug('app', 'refresh bridge data started')
    usersLoading = true
    saveStatus = ''
    tlsStatus = ''
    settingsStatus = ''
    try {
      await Promise.all([
        refreshUsersData(),
        refreshMailServerSettings(),
        refreshGeneralSettings(),
        refreshTlsSettings(),
      ])
    } catch (error) {
      logger.error('app', 'refresh bridge data failed', { error: String(error) })
      saveStatus = `refresh failed: ${String(error)}`
    } finally {
      usersLoading = false
      logger.debug('app', 'refresh bridge data completed')
    }
  }

  async function connectAndLoad() {
    logger.info('app', 'connect and load requested')
    try {
      await connect()
      await refreshBridgeData()
      logger.info('app', 'connect and load completed')
    } catch (error) {
      logger.error('app', 'connect and load failed', { error: String(error) })
      throw error
    }
  }

  async function saveMailServerSettings() {
    logger.info('app', 'save mail settings requested', {
      imapPort,
      smtpPort,
      useSslImap,
      useSslSmtp,
    })
    saveStatus = 'saving...'
    try {
      await setMailSettings({
        imap_port: Number(imapPort),
        smtp_port: Number(smtpPort),
        use_ssl_for_imap: useSslImap,
        use_ssl_for_smtp: useSslSmtp,
      })
      saveStatus = 'saved (awaiting stream confirmation)'
      await refreshMailServerSettings()
    } catch (error) {
      logger.error('app', 'save mail settings failed', { error: String(error) })
      saveStatus = `save failed: ${String(error)}`
    }
  }

  async function checkPort() {
    logger.debug('app', 'port check requested', { portToCheck })
    portCheckResult = 'checking...'
    try {
      const free = await isPortFree(Number(portToCheck))
      portCheckResult = free ? 'free' : 'occupied'
    } catch (error) {
      logger.error('app', 'port check failed', { error: String(error) })
      portCheckResult = `error: ${String(error)}`
    }
  }

  async function submitCredentials() {
    logger.info('app', 'submit credentials requested', { username: loginUsername })
    loginStatus = 'submitting credentials...'
    lastLoginStepSeen = ''
    hvVerificationUrl = ''
    hvCaptchaToken = ''
    await closeCaptchaVerificationWindow()
    try {
      if (!get(bridgeStatus).stream_running) {
        logger.info('app', 'bridge stream not running, connecting before login')
        await connect()
      }
      await login(loginUsername, loginPassword)
      loginStatus = 'credentials submitted'
    } catch (error) {
      const message = String(error)
      logger.error('app', 'submit credentials failed', { error: String(error) })
      const hvUrl = extractHvUrl(message)
      if (hvUrl) {
        hvVerificationUrl = hvUrl
        await openCaptchaVerificationWindow()
      } else {
        loginStatus = `login failed: ${message}`
      }
    }
  }

  async function retryCaptchaLogin() {
    logger.info('app', 'retry captcha login requested', { username: loginUsername })
    if (!hvCaptchaToken) {
      loginStatus = 'complete CAPTCHA in the verification window first'
      return
    }
    loginStatus = 'retrying login with human verification token...'
    lastLoginStepSeen = ''
    try {
      if (!get(bridgeStatus).stream_running) {
        logger.info('app', 'bridge stream not running, reconnecting before captcha retry')
        await connect()
      }
      await login(loginUsername, loginPassword, true, hvCaptchaToken)
      const step = get(bridgeStatus).login_step
      syncLoginStatusWithStep(step, true)
      if (step === 'credentials' || step === 'idle') {
        loginStatus = 'CAPTCHA retry submitted. Waiting for next login step...'
      }
    } catch (error) {
      const message = String(error)
      logger.error('app', 'retry captcha login failed', { error: message })
      const hvUrl = extractHvUrl(message)
      if (hvUrl) {
        hvVerificationUrl = hvUrl
        await openCaptchaVerificationWindow()
      }
      loginStatus = `captcha retry failed: ${message}`
    }
  }

  async function submitTwoFactor() {
    logger.info('app', 'submit 2FA requested', { username: loginUsername })
    loginStatus = 'submitting 2FA...'
    try {
      await login2fa(loginUsername, twoFactorCode)
      loginStatus = '2FA submitted (awaiting stream)'
    } catch (error) {
      logger.error('app', 'submit 2FA failed', { error: String(error) })
      loginStatus = `2FA failed: ${String(error)}`
    }
  }

  async function submitMailboxPassword() {
    logger.info('app', 'submit mailbox password requested', { username: loginUsername })
    loginStatus = 'submitting mailbox password...'
    try {
      await login2passwords(loginUsername, mailboxPassword)
      loginStatus = 'mailbox password submitted (awaiting stream)'
    } catch (error) {
      logger.error('app', 'submit mailbox password failed', { error: String(error) })
      loginStatus = `mailbox password failed: ${String(error)}`
    }
  }

  async function submitFidoAssertion() {
    logger.info('app', 'submit FIDO assertion requested', { username: loginUsername })
    loginStatus = 'submitting FIDO assertion...'
    try {
      await loginFido(loginUsername, fidoAssertionPayload)
      loginStatus = 'FIDO assertion submitted (awaiting stream)'
    } catch (error) {
      logger.error('app', 'submit FIDO assertion failed', { error: String(error) })
      loginStatus = `FIDO failed: ${String(error)}`
    }
  }

  async function abortFidoFlow() {
    logger.info('app', 'abort FIDO assertion requested', { username: loginUsername })
    loginStatus = 'aborting FIDO assertion...'
    try {
      await fidoAssertionAbort(loginUsername)
      loginStatus = 'FIDO assertion aborted'
    } catch (error) {
      logger.error('app', 'abort FIDO assertion failed', { error: String(error) })
      loginStatus = `FIDO abort failed: ${String(error)}`
    }
  }

  async function abortLoginFlow() {
    logger.info('app', 'abort login requested', { username: loginUsername })
    loginStatus = 'aborting login...'
    try {
      await loginAbort(loginUsername)
      loginStatus = 'login aborted'
    } catch (error) {
      logger.error('app', 'abort login failed', { error: String(error) })
      loginStatus = `abort failed: ${String(error)}`
    }
  }

  async function logout(userId: string) {
    logger.info('app', 'logout user requested', { userId })
    await logoutUser(userId)
    await refreshBridgeData()
  }

  async function remove(userId: string) {
    logger.info('app', 'remove user requested', { userId })
    await removeUser(userId)
    await refreshBridgeData()
  }

  async function toggleSplitMode(userId: string, current: boolean) {
    logger.info('app', 'toggle split mode requested', { userId, next: !current })
    await setUserSplitMode(userId, !current)
    await refreshUsersData()
  }

  async function installTls() {
    logger.info('app', 'install tls requested')
    tlsStatus = 'installing certificate...'
    try {
      await installTlsCertificate()
      tlsInstalled = await isTlsCertificateInstalled()
      tlsStatus = 'certificate installed'
    } catch (error) {
      logger.error('app', 'install tls failed', { error: String(error) })
      tlsStatus = `install failed: ${String(error)}`
    }
  }

  async function exportTls() {
    logger.info('app', 'export tls requested', { output: tlsExportDir })
    tlsStatus = 'exporting certificate...'
    try {
      await exportTlsCertificates(tlsExportDir)
      tlsStatus = 'export completed'
    } catch (error) {
      logger.error('app', 'export tls failed', { error: String(error) })
      tlsStatus = `export failed: ${String(error)}`
    }
  }

  async function applyGeneralSettings() {
    logger.info('app', 'apply general settings requested', {
      is_autostart_on: appSettings.is_autostart_on,
      is_beta_enabled: appSettings.is_beta_enabled,
      is_all_mail_visible: appSettings.is_all_mail_visible,
      is_telemetry_disabled: appSettings.is_telemetry_disabled,
      is_doh_enabled: appSettings.is_doh_enabled,
      disk_cache_path: diskCachePathInput,
      color_scheme_name: colorSchemeNameInput,
    })
    settingsStatus = 'saving...'
    try {
      await setIsAutostartOn(appSettings.is_autostart_on)
      await setIsBetaEnabled(appSettings.is_beta_enabled)
      await setIsAllMailVisible(appSettings.is_all_mail_visible)
      await setIsTelemetryDisabled(appSettings.is_telemetry_disabled)
      await setIsDohEnabled(appSettings.is_doh_enabled)
      await setDiskCachePath(diskCachePathInput)
      await setColorSchemeName(colorSchemeNameInput)

      appSettings.disk_cache_path = diskCachePathInput
      appSettings.color_scheme_name = colorSchemeNameInput
      settingsStatus = 'saved'
    } catch (error) {
      logger.error('app', 'apply general settings failed', { error: String(error) })
      settingsStatus = `save failed: ${String(error)}`
    }
  }

  function handleUiEvent(event: BridgeUiEvent) {
    logger.debug('app', 'ui event received', event)
    const message = `${event.level.toUpperCase()}: ${event.message}`
    pushToast(message)

    if (event.code === 'mail_settings_saved') {
      saveStatus = 'saved (stream confirmed)'
    }
    if (event.code === 'login_finished') {
      hvVerificationUrl = ''
      hvCaptchaToken = ''
      void closeCaptchaVerificationWindow()
    }
    if (event.code === 'autostart_saved' || event.code === 'disk_cache_saved') {
      settingsStatus = 'saved (stream confirmed)'
    }
    if (
      event.code === 'tfa_requested' ||
      event.code === 'fido_requested' ||
      event.code === 'tfa_or_fido_requested' ||
      event.code === 'fido_touch_requested' ||
      event.code === 'fido_touch_completed' ||
      event.code === 'fido_pin_required'
    ) {
      loginStatus = event.message
    }
    if (event.level === 'error') {
      settingsStatus = event.message
      if (event.code === 'login_error') {
        const hvUrl = extractHvUrl(event.message)
        if (hvUrl) {
          hvVerificationUrl = hvUrl
          void openCaptchaVerificationWindow()
        }
        loginStatus = event.message
      }
    }

    if (event.refresh_hints.includes('users')) {
      void refreshUsersData()
    }
    if (event.refresh_hints.includes('mail_settings')) {
      void refreshMailServerSettings()
    }
    if (event.refresh_hints.includes('app_settings')) {
      void refreshGeneralSettings()
    }
    if (event.refresh_hints.includes('tls')) {
      void refreshTlsSettings()
    }
  }

  onMount(() => {
    const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)')
    const motionQuery = window.matchMedia('(prefers-reduced-motion: reduce)')
    const handleSystemThemeChange = () => {
      systemPrefersDark = mediaQuery.matches
    }
    const handleMotionChange = () => {
      prefersReducedMotion = motionQuery.matches
    }
    handleSystemThemeChange()
    handleMotionChange()

    if (typeof mediaQuery.addEventListener === 'function') {
      mediaQuery.addEventListener('change', handleSystemThemeChange)
      motionQuery.addEventListener('change', handleMotionChange)
    } else {
      mediaQuery.addListener(handleSystemThemeChange)
      motionQuery.addListener(handleMotionChange)
    }
    void (async () => {
      logger.info('app', 'mount start')
      stop = await initBridgeStore()
      stopUi = await onBridgeUiEvent((event) => handleUiEvent(event))
      stopCaptchaToken = await onCaptchaToken((token) => {
        hvCaptchaToken = token
        loginStatus = 'CAPTCHA token captured. Click Retry CAPTCHA to continue.'
        logger.info('app', 'captured captcha token from verification window', {
          token_len: token.length,
        })
      })
      configPathInput = get(bridgeStatus).config_path ?? ''
      await refreshBridgeData()
      logger.info('app', 'mount completed')
    })()

    return () => {
      logger.info('app', 'unmount cleanup')
      if (typeof mediaQuery.removeEventListener === 'function') {
        mediaQuery.removeEventListener('change', handleSystemThemeChange)
        motionQuery.removeEventListener('change', handleMotionChange)
      } else {
        mediaQuery.removeListener(handleSystemThemeChange)
        motionQuery.removeListener(handleMotionChange)
      }
      stop?.()
      stopUi?.()
      stopCaptchaToken?.()
      void closeCaptchaVerificationWindow()
    }
  })
</script>

<main class="app-shell">
  <header class="card app-header">
    <div>
      <h1>OpenProton Bridge</h1>
      <p class="muted">Desktop console for Proton account sessions, mail transport, and bridge health.</p>
      <div class="header-metrics">
        <span class={`status-pill ${$bridgeStatus.connected ? 'good' : 'danger'}`}>
          {$bridgeStatus.connected ? 'Bridge Connected' : 'Bridge Offline'}
        </span>
        <span class="status-pill muted">Step: {formatLoginStep($bridgeStatus.login_step)}</span>
        <span class={`status-pill ${$bridgeStatus.stream_running ? 'good' : 'muted'}`}>
          Stream {$bridgeStatus.stream_running ? 'Running' : 'Stopped'}
        </span>
      </div>
    </div>
    <div class="header-actions">
      <button class="secondary" onclick={() => void refreshBridgeData()}>Refresh Data</button>
      <button class="secondary" onclick={cycleThemeMode}>
        Theme: {normalizeThemeMode(colorSchemeNameInput)}
      </button>
    </div>
  </header>

  <section class="workspace">
    <aside class="left-rail">
      <article class="card nav-card">
        <h2>Navigation</h2>
        <p class="muted">Switch between account, mail, settings, and live activity views.</p>
        <div class="section-nav">
          {#each sections as section}
            <button
              class:active={activeSection === section.id}
              class="secondary nav-btn"
              onclick={() => {
                activeSection = section.id
              }}
            >
              {section.label}
            </button>
          {/each}
        </div>
      </article>

      <BridgeConnectionCard
        status={$bridgeStatus}
        bind:configPathInput
        onSetPath={(path) => updateConfigPath(path)}
        onConnect={connectAndLoad}
        onDisconnect={disconnect}
      />

      <article class="card">
        <h2>Host</h2>
        <p class="muted"><strong>Hostname:</strong> {hostname || '(not loaded)'}</p>
        <p class="muted"><strong>Users:</strong> {users.length}</p>
        <p class="muted"><strong>Theme:</strong> {resolveTheme(normalizeThemeMode(colorSchemeNameInput))}</p>
      </article>
    </aside>

    <section class="main-pane">
      {#key activeSection}
        <div
          class="section-stage"
          in:fly={{ y: 8, duration: sectionTransitionDuration, opacity: 0.65 }}
          out:fade={{ duration: Math.max(sectionTransitionDuration - 40, 0) }}
        >
          {#if activeSection === 'accounts'}
            <article class="card">
              <h2>Account Access</h2>
              <p class="muted">
                Use the sign-in wizard for Proton authentication. Current login step:
                <strong> {formatLoginStep($bridgeStatus.login_step)}</strong>
              </p>
              <div class="row">
                <button onclick={openLoginWizard}>Open Sign-In Wizard</button>
              </div>
            </article>

            <UsersCard
              hostname={hostname}
              usersLoading={usersLoading}
              users={users}
              onToggleSplitMode={(userId, current) => toggleSplitMode(userId, current)}
              onLogout={(userId) => logout(userId)}
              onRemove={(userId) => remove(userId)}
            />
          {:else if activeSection === 'mail'}
            <MailSettingsCard
              bind:imapPort
              bind:smtpPort
              bind:useSslImap
              bind:useSslSmtp
              saveStatus={saveStatus}
              bind:portToCheck
              portCheckResult={portCheckResult}
              onSaveMailSettings={saveMailServerSettings}
              onCheckPort={checkPort}
            />
          {:else if activeSection === 'settings'}
            <GeneralSettingsCard
              bind:appSettings
              bind:diskCachePathInput
              bind:colorSchemeNameInput
              settingsStatus={settingsStatus}
              onApplySettings={applyGeneralSettings}
            />

            <TlsSettingsCard
              tlsInstalled={tlsInstalled}
              bind:tlsExportDir
              tlsStatus={tlsStatus}
              onInstallTls={installTls}
              onExportTls={exportTls}
            />
          {:else}
            <StreamEventsCard events={$streamLog} />
          {/if}
        </div>
      {/key}
    </section>

    <aside class="status-rail">
      <article class="card">
        <h2>Status Rail</h2>
        <p class="muted"><strong>Stream:</strong> {$bridgeStatus.stream_running ? 'running' : 'stopped'}</p>
        <p class="muted"><strong>Login:</strong> {$bridgeStatus.login_step}</p>
        <p class="muted"><strong>TLS:</strong> {tlsInstalled === null ? 'unknown' : tlsInstalled ? 'installed' : 'missing'}</p>
      </article>

      <ErrorStateCard lastError={$bridgeStatus.last_error} onClearError={resetError} />
      <EventToastsCard toasts={toastLog} />
      <StreamEventsCard events={$streamLog.slice(0, 10)} />
    </aside>
  </section>

  <LoginWizard
    open={loginWizardOpen}
    loginStep={$bridgeStatus.login_step}
    bind:loginUsername
    bind:loginPassword
    bind:twoFactorCode
    bind:mailboxPassword
    bind:fidoAssertionPayload
    hvVerificationUrl={hvVerificationUrl}
    bind:hvCaptchaToken
    loginStatus={loginStatus}
    onSubmitCredentials={submitCredentials}
    onOpenCaptchaWindow={openCaptchaVerificationWindow}
    onCloseCaptchaWindow={closeCaptchaVerificationWindow}
    onRetryCaptcha={retryCaptchaLogin}
    onSubmitTwoFactor={submitTwoFactor}
    onSubmitMailboxPassword={submitMailboxPassword}
    onSubmitFidoAssertion={submitFidoAssertion}
    onAbortFidoFlow={abortFidoFlow}
    onAbortLoginFlow={abortLoginFlow}
    onClose={closeLoginWizard}
  />
</main>
