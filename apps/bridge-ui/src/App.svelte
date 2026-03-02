<script lang="ts">
  import { onMount } from 'svelte'
  import { fade, fly } from 'svelte/transition'
  import { connect } from './lib/stores/bridge'
  import {
    bridge_refresh_tray_users,
    onCaptchaToken,
    onCaptchaWindowClosed,
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
    quitBridge as requestBridgeQuit,
    openCaptchaWindow,
    closeCaptchaWindow,
    onTrayAction,
    fidoAssertionAbort,
    logoutUser,
    removeUser,
    setColorSchemeName,
    setCurrentKeychain,
    setDiskCachePath,
    setIsAllMailVisible,
    setIsAutostartOn,
    setIsBetaEnabled,
    setIsDohEnabled,
    setIsTelemetryDisabled,
    setUserSplitMode,
    setMailSettings,
    type AppSettings,
    type TrayAction,
    type MailSettings,
    type UserSummary,
  } from './lib/api/bridge'
  import { createParityStateStore, type ParityDomainState, type UiNotification } from './lib/parity-state'
  import { logger } from './lib/logging/logger'
  import LoginWizard from './lib/components/LoginWizard.svelte'
  import ClientConfigWizard from './lib/components/ClientConfigWizard.svelte'
  import GeneralSettingsCard from './lib/components/cards/GeneralSettingsCard.svelte'
  import StreamEventsCard from './lib/components/cards/StreamEventsCard.svelte'
  import UsersCard from './lib/components/cards/UsersCard.svelte'
  import MailSettingsCard from './lib/components/cards/MailSettingsCard.svelte'
  import TlsSettingsCard from './lib/components/cards/TlsSettingsCard.svelte'

  const defaultAppSettings: AppSettings = {
    is_autostart_on: false,
    is_beta_enabled: false,
    is_all_mail_visible: true,
    is_telemetry_disabled: false,
    disk_cache_path: '',
    is_doh_enabled: true,
    color_scheme_name: 'system',
    current_keychain: '',
    available_keychains: [],
  }

  const sections = [
    { id: 'accounts', label: 'Accounts' },
    { id: 'mail', label: 'Mail' },
    { id: 'settings', label: 'Settings' },
    { id: 'activity', label: 'Activity' },
  ] as const

  type SectionId = (typeof sections)[number]['id']
  type ThemeMode = 'system' | 'light' | 'dark'
  type SettingsSectionId = 'general' | 'advanced' | 'maintenance'
  type CacheMoveUiState = 'idle' | 'in_flight' | 'success' | 'failure'
  type UserParityHook = {
    syncProgress?: number | null
    disconnected?: boolean
    recovering?: boolean
    error?: string | null
  }

  const parityStore = createParityStateStore()
  let parityState = $state<ParityDomainState>(parityStore.getState())
  let stopParityListeners = $state<(() => void) | undefined>(undefined)
  let stopParitySubscription = $state<(() => void) | undefined>(undefined)
  let stopCaptchaToken = $state<(() => void) | undefined>(undefined)
  let stopCaptchaWindowClosed = $state<(() => void) | undefined>(undefined)
  let stopTrayActions = $state<(() => void) | undefined>(undefined)
  let activeSection = $state<SectionId>('accounts')
  let settingsOverflowOpen = $state(false)
  let loginWizardOpen = $state(false)
  let lastLoginStepSeen = $state('credentials')
  let systemPrefersDark = $state(false)
  let prefersReducedMotion = $state(false)
  let sectionTransitionDuration = $derived(prefersReducedMotion ? 0 : 220)
  let configPathInput = $state('')
  let hostname = $state('')
  let users = $state<UserSummary[]>([])
  let usersLoading = $state(false)
  let initialUsersLoadDone = $state(false)
  let onboardingOnlyMode = $state(false)
  let appSettings = $state<AppSettings>({ ...defaultAppSettings })
  let settingsStatus = $state('')
  let diskCachePathInput = $state('')
  let colorSchemeNameInput = $state('system')
  let currentKeychainInput = $state('')
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
  let captchaRetryInFlight = $state(false)
  let captchaWindowOpenInFlight = $state(false)
  let loginStatus = $state('')
  let tlsInstalled = $state<boolean | null>(null)
  let tlsExportDir = $state('')
  let tlsStatus = $state('')
  let settingsExpandedSections = $state<Record<SettingsSectionId, boolean>>({
    general: true,
    advanced: true,
    maintenance: true,
  })
  let cacheMoveState = $state<CacheMoveUiState>('idle')
  let cacheMoveStatus = $state('')
  let lastHandledNotificationId = $state(0)
  let userRuntimeParityById = $state<Record<string, UserParityHook>>({})
  let disconnectedUsernames = $state<Record<string, boolean>>({})
  let clientConfigWizardOpen = $state(false)
  let clientConfigUserId = $state('')
  let clientConfigPassword = $state('generated app password')

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
      loginStatus = 'Enter your 2FA code.'
    } else if (step === '2fa_or_fido') {
      loginStatus = 'Verify with 2FA or your security key.'
    } else if (step === 'fido' || step === 'fido_touch' || step === 'fido_pin') {
      loginStatus = 'Complete security key verification.'
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

  function avatarInitial(username: string): string {
    const trimmed = username.trim()
    if (trimmed.length === 0) {
      return '?'
    }
    return trimmed.charAt(0).toUpperCase()
  }

  function accountSummaryStatus(user: UserSummary): string {
    const parity = userParityById[user.id]
    if (parity?.disconnected) {
      return 'Disconnected'
    }
    if (typeof parity?.syncProgress === 'number' && parity.syncProgress >= 0 && parity.syncProgress < 100) {
      return `Synchronizing (${parity.syncProgress}%)`
    }
    if (parity?.recovering) {
      return 'Recovering session'
    }
    if (parity?.error) {
      return 'Needs attention'
    }
    if (Number(user.state) !== 2) {
      return 'Session paused'
    }
    return 'Ready'
  }

  function openLoginWizard() {
    activeSection = 'accounts'
    loginWizardOpen = true
  }

  function closeLoginWizard() {
    if (showOnboardingOnlyWizard) {
      return
    }
    loginWizardOpen = false
  }

  function resolveClientConfigPassword(): string {
    if (mailboxPassword.trim().length > 0) {
      return mailboxPassword.trim()
    }
    return 'generated app password'
  }

  function openClientConfigWizard(userId?: string) {
    const selectedUser = (userId ? users.find((user) => user.id === userId) : users[0]) ?? null
    if (!selectedUser) {
      settingsStatus = 'No account available for client configuration.'
      return
    }

    clientConfigUserId = selectedUser.id
    clientConfigPassword = resolveClientConfigPassword()
    clientConfigWizardOpen = true
    activeSection = 'accounts'
  }

  function closeClientConfigWizard() {
    clientConfigWizardOpen = false
  }

  let selectedClientConfigUser = $derived(users.find((user) => user.id === clientConfigUserId) ?? null)
  let userParityById = $derived(buildUserParityById(users, parityState, userRuntimeParityById, disconnectedUsernames))
  let activeAccountSummary = $derived(users.find((user) => user.id === clientConfigUserId) ?? users[0] ?? null)
  let showOnboardingOnlyWizard = $derived(onboardingOnlyMode && initialUsersLoadDone && users.length === 0)

  $effect(() => {
    syncLoginStatusWithStep(parityState.snapshot.login_step)
  })

  $effect(() => {
    if (users.length === 0) {
      if (clientConfigUserId !== '') {
        clientConfigUserId = ''
      }
      return
    }
    if (!users.some((user) => user.id === clientConfigUserId)) {
      clientConfigUserId = users[0].id
    }
  })

  $effect(() => {
    if (!onboardingOnlyMode) {
      return
    }
    if (users.length === 0) {
      loginWizardOpen = true
      activeSection = 'accounts'
      return
    }
    onboardingOnlyMode = false
  })

  $effect(() => {
    if (activeSection !== 'settings' && settingsOverflowOpen) {
      settingsOverflowOpen = false
    }
  })

  function extractHvUrl(text: string): string | null {
    const match = text.match(/https:\/\/verify\.proton\.me\/\S+/i)
    if (!match) {
      return null
    }
    return match[0].replace(/[),.;]+$/, '')
  }

  function userFacingLoginError(message: string): string {
    const lower = message.toLowerCase()
    if (lower.includes('2fa')) {
      return '2FA failed. Check your code and try again.'
    }
    if (lower.includes('fido') || lower.includes('security key')) {
      return 'Security key verification failed. Try again.'
    }
    if (lower.includes('mailbox')) {
      return 'Mailbox password failed. Try again.'
    }
    if (lower.includes('captcha') || lower.includes('human verification')) {
      return 'Verification is still required. Complete it and continue.'
    }
    if (lower.includes('abort')) {
      return 'Sign-in was canceled.'
    }
    return 'Sign-in failed. Try again.'
  }

  function normalizeSyncProgress(value: number): number {
    if (!Number.isFinite(value)) {
      return 0
    }
    if (value >= 0 && value <= 1) {
      return Math.round(value * 100)
    }
    return Math.round(Math.max(0, Math.min(100, value)))
  }

  function buildUserParityById(
    list: UserSummary[],
    state: ParityDomainState,
    runtimeById: Record<string, UserParityHook>,
    disconnectedByUsername: Record<string, boolean>,
  ): Record<string, UserParityHook> {
    const globalSyncProgress = state.sync.phase === 'syncing' ? state.sync.progress_percent : null
    const globalSyncError = state.sync.phase === 'error' ? state.sync.message : null

    const byId: Record<string, UserParityHook> = {}
    for (const user of list) {
      const runtime = runtimeById[user.id] ?? {}
      const backendDisconnected = Number(user.state) !== 2
      const usernameDisconnected = disconnectedByUsername[user.username] ?? false
      const disconnected =
        runtime.disconnected ?? (usernameDisconnected || backendDisconnected || !state.snapshot.connected)
      const recovering = runtime.recovering ?? (state.snapshot.connected && state.sync.phase === 'syncing')
      const syncProgress =
        runtime.syncProgress ?? (typeof globalSyncProgress === 'number' ? normalizeSyncProgress(globalSyncProgress) : null)
      const error = runtime.error ?? globalSyncError

      byId[user.id] = {
        syncProgress: typeof syncProgress === 'number' ? normalizeSyncProgress(syncProgress) : null,
        disconnected,
        recovering,
        error,
      }
    }
    return byId
  }

  function hintValue(hints: string[], prefix: string): string | null {
    const targetPrefix = `${prefix}:`
    const matched = hints.find((hint) => hint.startsWith(targetPrefix))
    if (!matched) {
      return null
    }
    return matched.slice(targetPrefix.length)
  }

  function updateUserRuntimeParity(userId: string, patch: Partial<UserParityHook>) {
    const current = userRuntimeParityById[userId] ?? {}
    userRuntimeParityById = {
      ...userRuntimeParityById,
      [userId]: {
        ...current,
        ...patch,
      },
    }
  }

  function applyUserNotificationEffects(notification: UiNotification) {
    const userId = hintValue(notification.refresh_hints, 'sync_user')
    const username = hintValue(notification.refresh_hints, 'sync_username')
    const progressHint = hintValue(notification.refresh_hints, 'sync_progress')
    const parsedProgress = progressHint ? Number.parseInt(progressHint, 10) : NaN
    const progress = Number.isFinite(parsedProgress) ? normalizeSyncProgress(parsedProgress) : null

    if (notification.code === 'sync_started' && userId) {
      updateUserRuntimeParity(userId, {
        syncProgress: 0,
        recovering: true,
        disconnected: false,
        error: null,
      })
      return
    }

    if (notification.code === 'sync_progress' && userId) {
      updateUserRuntimeParity(userId, {
        syncProgress: progress ?? 0,
        recovering: true,
        disconnected: false,
        error: null,
      })
      return
    }

    if (notification.code === 'sync_finished' && userId) {
      updateUserRuntimeParity(userId, {
        syncProgress: 100,
        recovering: false,
        disconnected: false,
        error: null,
      })
      return
    }

    if (notification.code === 'user_bad_event' && userId) {
      updateUserRuntimeParity(userId, {
        error: notification.message,
        recovering: false,
      })
      return
    }

    if (notification.code === 'user_disconnected') {
      if (username) {
        disconnectedUsernames = {
          ...disconnectedUsernames,
          [username]: true,
        }
        const disconnectedUser = users.find((user) => user.username === username)
        if (disconnectedUser) {
          updateUserRuntimeParity(disconnectedUser.id, {
            disconnected: true,
            recovering: false,
          })
        }
      }
      return
    }

    if (notification.code === 'imap_login_failed' && username) {
      const targetUser = users.find((user) => user.username === username)
      if (targetUser) {
        updateUserRuntimeParity(targetUser.id, {
          error: notification.message,
        })
      }
      return
    }

    if ((notification.code === 'users_updated' || notification.code === 'user_changed') && userId) {
      updateUserRuntimeParity(userId, {
        disconnected: false,
      })
    }
  }

  function pruneUserRuntimeParity(nextUsers: UserSummary[]) {
    const activeIds = new Set(nextUsers.map((user) => user.id))
    const activeUsernames = new Set(nextUsers.map((user) => user.username))

    userRuntimeParityById = Object.fromEntries(
      Object.entries(userRuntimeParityById).filter(([id]) => activeIds.has(id)),
    ) as Record<string, UserParityHook>

    disconnectedUsernames = Object.fromEntries(
      Object.entries(disconnectedUsernames).filter(([username]) => activeUsernames.has(username)),
    )
  }

  function toggleSettingsSection(section: SettingsSectionId, nextExpanded: boolean) {
    settingsExpandedSections = {
      ...settingsExpandedSections,
      [section]: nextExpanded,
    }
  }

  function consumeRefreshHint(hint: string, refreshFn: () => Promise<void>) {
    const count = parityState.refresh_hints[hint] ?? 0
    if (count < 1) {
      return
    }

    for (let index = 0; index < count; index += 1) {
      parityStore.dispatch({ type: 'ui.refresh-hint.consumed', hint })
    }

    void refreshFn()
  }

  function applyNotificationEffects(notification: UiNotification) {
    applyUserNotificationEffects(notification)

    if (notification.code === 'mail_settings_saved') {
      saveStatus = 'saved (stream confirmed)'
    }
    if (notification.code === 'login_finished') {
      hvVerificationUrl = ''
      hvCaptchaToken = ''
      void closeCaptchaVerificationWindow()
    }
    if (notification.code === 'autostart_saved' || notification.code === 'disk_cache_saved') {
      settingsStatus = 'saved (stream confirmed)'
    }
    if (
      notification.code === 'tfa_requested' ||
      notification.code === 'fido_requested' ||
      notification.code === 'tfa_or_fido_requested' ||
      notification.code === 'fido_touch_requested' ||
      notification.code === 'fido_touch_completed' ||
      notification.code === 'fido_pin_required'
    ) {
      loginStatus = notification.message
    }
    if (notification.level === 'error' && notification.code !== 'login_error') {
      settingsStatus = notification.message
    }
    if (notification.code === 'login_error') {
      const hvUrl = extractHvUrl(notification.message)
      if (hvUrl) {
        hvVerificationUrl = hvUrl
        logger.info('app', 'captcha challenge detected from stream event', { verification_url: hvUrl })
        void openCaptchaVerificationWindow()
      }
      loginStatus = userFacingLoginError(notification.message)
    }
    if (notification.code === 'disk_cache_saved') {
      cacheMoveState = 'success'
      cacheMoveStatus = notification.message
    }
    if (notification.code === 'disk_cache_error') {
      cacheMoveState = 'failure'
      cacheMoveStatus = notification.message
    }
  }

  $effect(() => {
    consumeRefreshHint('users', refreshUsersData)
    consumeRefreshHint('mail_settings', refreshMailServerSettings)
    consumeRefreshHint('app_settings', refreshGeneralSettings)
    consumeRefreshHint('tls', refreshTlsSettings)
  })

  $effect(() => {
    const latest = parityState.notifications[0]
    if (!latest || latest.id === lastHandledNotificationId) {
      return
    }
    lastHandledNotificationId = latest.id
    applyNotificationEffects(latest)
  })

  async function openCaptchaVerificationWindow() {
    if (!hvVerificationUrl) {
      return
    }
    captchaWindowOpenInFlight = true
    try {
      logger.info('app', 'opening captcha verification window', { verification_url: hvVerificationUrl })
      await openCaptchaWindow(hvVerificationUrl)
      loginStatus = 'Complete CAPTCHA in the verification window. Sign-in continues automatically.'
    } catch (error) {
      logger.error('app', 'open captcha window failed', {
        error: String(error),
        verification_url: hvVerificationUrl,
      })
      loginStatus = 'Could not open verification window. Try again.'
    } finally {
      queueMicrotask(() => {
        captchaWindowOpenInFlight = false
      })
    }
  }

  async function closeCaptchaVerificationWindow() {
    try {
      await closeCaptchaWindow()
    } catch (error) {
      logger.error('app', 'close captcha window failed', { error: String(error) })
    }
  }

  function handleTrayAction(action: TrayAction) {
    if (typeof action === 'object' && action.type === 'select_user') {
      activeSection = 'accounts'
      const selectedUser = users.find((user) => user.id === action.userId)
      if (selectedUser) {
        clientConfigUserId = selectedUser.id
      }
      return
    }

    if (action === 'show_settings') {
      activeSection = 'settings'
      if (!showOnboardingOnlyWizard) {
        loginWizardOpen = false
      }
      clientConfigWizardOpen = false
      return
    }

    if (action === 'show_help') {
      activeSection = 'activity'
      if (typeof window !== 'undefined') {
        window.open('https://proton.me/support/proton-mail-bridge', '_blank', 'noopener,noreferrer')
      }
      return
    }

    activeSection = 'accounts'
  }

  function openSupportPage() {
    if (typeof window !== 'undefined') {
      window.open('https://proton.me/support/proton-mail-bridge', '_blank', 'noopener,noreferrer')
    }
  }

  async function refreshUsersData() {
    hostname = await getHostname()
    const nextUsers = await fetchUsers()
    users = nextUsers
    await bridge_refresh_tray_users(nextUsers)
    pruneUserRuntimeParity(nextUsers)
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
    currentKeychainInput = appSettings.current_keychain ?? ''
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
    loginStatus = 'Signing in...'
    lastLoginStepSeen = ''
    hvVerificationUrl = ''
    hvCaptchaToken = ''
    await closeCaptchaVerificationWindow()
    try {
      if (!parityState.snapshot.stream_running) {
        logger.info('app', 'bridge stream not running, connecting before login')
        await connect()
      }
      await login(loginUsername, loginPassword)
      loginStatus = 'Sign-in submitted.'
    } catch (error) {
      const message = String(error)
      logger.error('app', 'submit credentials failed', { error: message })
      const hvUrl = extractHvUrl(message)
      if (hvUrl) {
        hvVerificationUrl = hvUrl
        logger.info('app', 'captcha challenge detected during login', { verification_url: hvUrl })
        await openCaptchaVerificationWindow()
      } else {
        loginStatus = userFacingLoginError(message)
      }
    }
  }

  async function retryCaptchaLogin(trigger: 'token' | 'window_closed' | 'manual' = 'manual') {
    if (!hvVerificationUrl) {
      return
    }
    if (captchaRetryInFlight) {
      return
    }
    const captchaToken = hvCaptchaToken.trim()
    logger.info('app', 'retry captcha login requested', {
      trigger,
      username: loginUsername,
      has_token: captchaToken.length > 0,
      token_len: captchaToken.length,
    })
    captchaRetryInFlight = true
    loginStatus = 'Continuing sign-in...'
    lastLoginStepSeen = ''
    try {
      if (!parityState.snapshot.stream_running) {
        logger.info('app', 'bridge stream not running, reconnecting before captcha retry')
        await connect()
      }
      await login(loginUsername, loginPassword, true, captchaToken.length > 0 ? captchaToken : undefined)
      const step = parityStore.getState().snapshot.login_step
      syncLoginStatusWithStep(step, true)
      if (step === 'credentials' || step === 'idle') {
        loginStatus = 'Verification submitted. Waiting for the next step...'
      }
    } catch (error) {
      const message = String(error)
      logger.error('app', 'retry captcha login failed', { error: message })
      const hvUrl = extractHvUrl(message)
      if (hvUrl) {
        hvVerificationUrl = hvUrl
        logger.info('app', 'captcha challenge reissued during retry', { verification_url: hvUrl })
        await openCaptchaVerificationWindow()
      }
      loginStatus = userFacingLoginError(message)
    } finally {
      captchaRetryInFlight = false
    }
  }

  async function submitTwoFactor() {
    logger.info('app', 'submit 2FA requested', { username: loginUsername })
    loginStatus = 'submitting 2FA...'
    try {
      await login2fa(loginUsername, twoFactorCode)
      loginStatus = '2FA accepted. Loading account data...'
      await refreshBridgeData()
      hvVerificationUrl = ''
      hvCaptchaToken = ''
      await closeCaptchaVerificationWindow()
      loginStatus = 'Login completed.'
    } catch (error) {
      const message = String(error)
      logger.error('app', 'submit 2FA failed', { error: message })
      loginStatus = userFacingLoginError(message)
    }
  }

  async function submitMailboxPassword() {
    logger.info('app', 'submit mailbox password requested', { username: loginUsername })
    loginStatus = 'submitting mailbox password...'
    try {
      await login2passwords(loginUsername, mailboxPassword)
      loginStatus = 'Mailbox password accepted. Loading account data...'
      await refreshBridgeData()
      loginStatus = 'Login completed.'
    } catch (error) {
      const message = String(error)
      logger.error('app', 'submit mailbox password failed', { error: message })
      loginStatus = userFacingLoginError(message)
    }
  }

  async function submitFidoAssertion() {
    logger.info('app', 'submit FIDO assertion requested', { username: loginUsername })
    loginStatus = 'submitting FIDO assertion...'
    try {
      await loginFido(loginUsername, fidoAssertionPayload)
      loginStatus = 'FIDO accepted. Loading account data...'
      await refreshBridgeData()
      loginStatus = 'Login completed.'
    } catch (error) {
      const message = String(error)
      logger.error('app', 'submit FIDO assertion failed', { error: message })
      loginStatus = userFacingLoginError(message)
    }
  }

  async function abortFidoFlow() {
    logger.info('app', 'abort FIDO assertion requested', { username: loginUsername })
    loginStatus = 'aborting FIDO assertion...'
    try {
      await fidoAssertionAbort(loginUsername)
      loginStatus = 'FIDO assertion aborted'
    } catch (error) {
      const message = String(error)
      logger.error('app', 'abort FIDO assertion failed', { error: message })
      loginStatus = userFacingLoginError(message)
    }
  }

  async function abortLoginFlow() {
    logger.info('app', 'abort login requested', { username: loginUsername })
    loginStatus = 'aborting login...'
    try {
      await loginAbort(loginUsername)
      loginStatus = 'login aborted'
    } catch (error) {
      const message = String(error)
      logger.error('app', 'abort login failed', { error: message })
      loginStatus = userFacingLoginError(message)
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
      current_keychain: currentKeychainInput,
    })
    const previousDiskCachePath = appSettings.disk_cache_path
    const diskCachePathChanged = previousDiskCachePath !== diskCachePathInput

    settingsStatus = 'saving...'
    if (diskCachePathChanged) {
      cacheMoveState = 'in_flight'
      cacheMoveStatus = 'Applying settings...'
    } else {
      cacheMoveState = 'idle'
      cacheMoveStatus = ''
    }
    try {
      await setIsAutostartOn(appSettings.is_autostart_on)
      await setIsBetaEnabled(appSettings.is_beta_enabled)
      await setIsAllMailVisible(appSettings.is_all_mail_visible)
      await setIsTelemetryDisabled(appSettings.is_telemetry_disabled)
      await setIsDohEnabled(appSettings.is_doh_enabled)
      await setDiskCachePath(diskCachePathInput)
      await setColorSchemeName(colorSchemeNameInput)
      if (currentKeychainInput.trim().length > 0) {
        await setCurrentKeychain(currentKeychainInput)
      }

      appSettings.disk_cache_path = diskCachePathInput
      appSettings.color_scheme_name = colorSchemeNameInput
      appSettings.current_keychain = currentKeychainInput
      settingsStatus = 'saved (awaiting stream confirmation)'
      if (diskCachePathChanged) {
        cacheMoveStatus = 'Waiting for cache operation confirmation...'
      }
    } catch (error) {
      logger.error('app', 'apply general settings failed', { error: String(error) })
      settingsStatus = `save failed: ${String(error)}`
      if (diskCachePathChanged) {
        cacheMoveState = 'failure'
        cacheMoveStatus = String(error)
      }
    }
  }

  function toggleSettingsOverflowMenu() {
    settingsOverflowOpen = !settingsOverflowOpen
  }

  async function closeRuntimeWindow() {
    settingsOverflowOpen = false
    settingsStatus = 'Closing window...'
    try {
      const { getCurrentWindow } = await import('@tauri-apps/api/window')
      await getCurrentWindow().close()
    } catch (error) {
      logger.warn('app', 'close window fallback used', { error: String(error) })
      if (typeof window !== 'undefined') {
        window.close()
      }
      settingsStatus = 'Close window requested.'
    }
  }

  async function quitBridge() {
    settingsOverflowOpen = false
    settingsStatus = 'Quitting Bridge...'
    try {
      await requestBridgeQuit()
    } catch (error) {
      logger.error('app', 'quit bridge failed', { error: String(error) })
      settingsStatus = `quit failed: ${String(error)}`
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
      stopParitySubscription = parityStore.subscribe((nextState) => {
        parityState = nextState
      })
      stopParityListeners = await parityStore.init()
      stopCaptchaToken = await onCaptchaToken((token) => {
        hvCaptchaToken = token
        loginStatus = 'Verification complete. Continuing sign-in...'
        logger.info('app', 'captured pm_captcha token from verification window', {
          pm_captcha_token: token,
          token_len: token.length,
        })
        void retryCaptchaLogin('token')
      })
      stopCaptchaWindowClosed = await onCaptchaWindowClosed(() => {
        if (captchaWindowOpenInFlight || !hvVerificationUrl) {
          return
        }
        logger.info('app', 'captcha window closed; retrying login continuation')
        void retryCaptchaLogin('window_closed')
      })
      stopTrayActions = await onTrayAction((action) => {
        handleTrayAction(action)
      })
      configPathInput = parityStore.getState().snapshot.config_path ?? ''
      await refreshBridgeData()
      initialUsersLoadDone = true
      if (users.length === 0) {
        onboardingOnlyMode = true
        loginWizardOpen = true
        activeSection = 'accounts'
      }
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
      stopParityListeners?.()
      stopParitySubscription?.()
      stopCaptchaToken?.()
      stopCaptchaWindowClosed?.()
      stopTrayActions?.()
      void closeCaptchaVerificationWindow()
    }
  })
</script>

<main class="app-shell">
  {#if !showOnboardingOnlyWizard}
    <section class="workspace">
    <aside class="left-rail">
      <article class="card account-summary-pane">
        <div class="shell-status-bar">
          <span class="status-inline">
            <span class="status-dot" aria-hidden="true"></span>
            {parityState.snapshot.connected ? 'Connected' : 'Offline'}
          </span>
          <div class="shell-icon-actions">
            <button class="icon-btn" aria-label="Help" title="Help" onclick={openSupportPage}>?</button>
            <button
              class={`icon-btn ${activeSection === 'settings' ? 'active' : ''}`}
              aria-label="Settings"
              title="Settings"
              onclick={() => {
                activeSection = 'settings'
              }}
            >
              ⚙
            </button>
            <button
              class="icon-btn"
              aria-label="Open runtime settings menu"
              aria-expanded={settingsOverflowOpen}
              title="Runtime menu"
              onclick={toggleSettingsOverflowMenu}
            >
              ⋮
            </button>
          </div>
        </div>

        <h2>Accounts</h2>
        <div class="account-chip-list">
          {#if users.length > 0}
            {#each users as user}
              <button
                class={`account-pane-chip ${activeAccountSummary?.id === user.id ? 'active' : ''}`}
                onclick={() => {
                  activeSection = 'accounts'
                  clientConfigUserId = user.id
                }}
              >
                <span class="avatar">{avatarInitial(user.username)}</span>
                <span class="account-chip-content">
                  <span class="account-chip-name">{user.username}</span>
                  <span class="account-chip-meta">{accountSummaryStatus(user)}</span>
                </span>
              </button>
            {/each}
          {:else}
            <div class="account-pane-chip empty">
              <span class="avatar">?</span>
              <span class="account-chip-content">
                <span class="account-chip-name">No account loaded</span>
                <span class="account-chip-meta">Open sign-in to add an account</span>
              </span>
            </div>
          {/if}
        </div>

        <div class="summary-metrics">
          <span class="chip">Host: {hostname || '(not loaded)'}</span>
          <span class="chip">Users: {users.length}</span>
          <span class="chip">Stream: {parityState.snapshot.stream_running ? 'running' : 'stopped'}</span>
        </div>

        <button
          class="secondary add-account-btn"
          aria-label="Open Sign-In Wizard"
          title="Open Sign-In Wizard"
          onclick={openLoginWizard}
        >
          +
        </button>

        {#if settingsOverflowOpen}
          <div class="settings-overflow-menu sidebar-overflow-menu" role="menu" data-testid="runtime-settings-overflow-menu">
            <button class="menu-item" role="menuitem" onclick={() => void closeRuntimeWindow()}>
              Close window
            </button>
            <button class="menu-item" role="menuitem" onclick={quitBridge}>Quit Bridge</button>
          </div>
        {/if}
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
                <strong> {formatLoginStep(parityState.snapshot.login_step)}</strong>
              </p>
              <div class="row">
                <button onclick={openLoginWizard}>Open Sign-In Wizard</button>
                <button class="secondary" onclick={() => openClientConfigWizard()} disabled={users.length === 0}>
                  Configure Email Client
                </button>
              </div>
            </article>

            <UsersCard
              hostname={hostname}
              usersLoading={usersLoading}
              users={users}
              userParityById={userParityById}
              syncPhase={parityState.sync.phase}
              syncProgressPercent={parityState.sync.progress_percent}
              syncMessage={parityState.sync.message}
              onConfigureClient={(userId) => openClientConfigWizard(userId)}
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
            <article class="card settings-heading-card">
              <div class="settings-title-row">
                <h1>Settings</h1>
                <h2>Runtime</h2>
              </div>
            </article>

            <GeneralSettingsCard
              bind:appSettings
              bind:diskCachePathInput
              bind:colorSchemeNameInput
              bind:currentKeychainInput
              settingsStatus={settingsStatus}
              expandedSections={settingsExpandedSections}
              onToggleSection={toggleSettingsSection}
              cacheMoveState={cacheMoveState}
              cacheMoveStatus={cacheMoveStatus}
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
            <StreamEventsCard events={parityState.stream_log} />
          {/if}
        </div>
      {/key}
    </section>
    </section>
  {/if}

  <LoginWizard
    open={loginWizardOpen}
    canClose={!showOnboardingOnlyWizard}
    loginStep={parityState.snapshot.login_step}
    bind:loginUsername
    bind:loginPassword
    bind:twoFactorCode
    bind:mailboxPassword
    bind:fidoAssertionPayload
    hvVerificationUrl={hvVerificationUrl}
    bind:hvCaptchaToken
    loginStatus={loginStatus}
    onSubmitCredentials={submitCredentials}
    onSubmitTwoFactor={submitTwoFactor}
    onSubmitMailboxPassword={submitMailboxPassword}
    onSubmitFidoAssertion={submitFidoAssertion}
    onAbortFidoFlow={abortFidoFlow}
    onAbortLoginFlow={abortLoginFlow}
    onClose={closeLoginWizard}
  />

  {#if !showOnboardingOnlyWizard}
    <ClientConfigWizard
      open={clientConfigWizardOpen}
      username={selectedClientConfigUser?.username ?? ''}
      addresses={selectedClientConfigUser?.addresses ?? []}
      hostname={hostname || '127.0.0.1'}
      imapPort={imapPort}
      smtpPort={smtpPort}
      password={clientConfigPassword}
      onClose={closeClientConfigWizard}
    />
  {/if}
</main>
