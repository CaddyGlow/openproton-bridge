import { invoke } from '@tauri-apps/api/core'
import { listen, type UnlistenFn } from '@tauri-apps/api/event'

export type BridgeSnapshot = {
  connected: boolean
  stream_running: boolean
  login_step: string
  last_error: string | null
  config_path: string | null
}

export type StreamTickEvent = {
  timestamp: string
  message: string
}

export type UserSummary = {
  id: string
  username: string
  state: number
  split_mode: boolean
  addresses: string[]
  used_bytes: number
  total_bytes: number
}

export type MailSettings = {
  imap_port: number
  smtp_port: number
  use_ssl_for_imap: boolean
  use_ssl_for_smtp: boolean
}

export type AppSettings = {
  is_autostart_on: boolean
  is_beta_enabled: boolean
  is_all_mail_visible: boolean
  is_telemetry_disabled: boolean
  disk_cache_path: string
  is_doh_enabled: boolean
  color_scheme_name: string
  current_keychain?: string
  available_keychains?: string[]
}

export type BridgeUiEvent = {
  level: string
  code: string
  message: string
  refresh_hints: string[]
}

export type TrayAction =
  | 'show_main'
  | 'show_help'
  | 'show_settings'
  | {
      type: 'select_user'
      userId: string
    }

export async function getBridgeStatus(): Promise<BridgeSnapshot> {
  return invoke<BridgeSnapshot>('bridge_status')
}

export async function connectBridge(): Promise<BridgeSnapshot> {
  return invoke<BridgeSnapshot>('bridge_connect')
}

export async function setConfigPath(path: string): Promise<BridgeSnapshot> {
  return invoke<BridgeSnapshot>('bridge_set_config_path', { path })
}

export async function disconnectBridge(): Promise<BridgeSnapshot> {
  return invoke<BridgeSnapshot>('bridge_disconnect')
}

function hasTauriInvoke(): boolean {
  if (typeof window === 'undefined') {
    return false
  }

  type TauriInternalsWindow = Window & {
    __TAURI_INTERNALS__?: {
      invoke?: unknown
    }
  }

  return typeof (window as TauriInternalsWindow).__TAURI_INTERNALS__?.invoke === 'function'
}

export async function quitBridge(): Promise<void> {
  if (!hasTauriInvoke()) {
    if (typeof window !== 'undefined') {
      window.close()
    }
    return
  }

  return invoke<void>('bridge_quit')
}

export async function clearError(): Promise<BridgeSnapshot> {
  return invoke<BridgeSnapshot>('bridge_clear_error')
}

export async function fetchUsers(): Promise<UserSummary[]> {
  return invoke<UserSummary[]>('bridge_fetch_users')
}

export async function bridge_refresh_tray_users(users: UserSummary[]): Promise<void> {
  return invoke<void>('bridge_refresh_tray_users', { users })
}

export async function login(
  username: string,
  password: string,
  useHvDetails?: boolean,
  humanVerificationToken?: string,
): Promise<void> {
  return invoke<void>('bridge_login', {
    username,
    password,
    use_hv_details: useHvDetails,
    useHvDetails,
    human_verification_token: humanVerificationToken,
    humanVerificationToken,
  })
}

export async function openCaptchaWindow(url: string): Promise<void> {
  return invoke<void>('bridge_open_captcha_window', { url })
}

export async function closeCaptchaWindow(): Promise<void> {
  return invoke<void>('bridge_close_captcha_window')
}

export async function login2fa(username: string, code: string): Promise<void> {
  return invoke<void>('bridge_login_2fa', { username, code })
}

export async function login2passwords(username: string, mailboxPassword: string): Promise<void> {
  return invoke<void>('bridge_login_2passwords', {
    username,
    mailbox_password: mailboxPassword,
    mailboxPassword,
  })
}

export async function loginAbort(username: string): Promise<void> {
  return invoke<void>('bridge_login_abort', { username })
}

export async function loginFido(username: string, assertionPayload: string): Promise<void> {
  return invoke<void>('bridge_login_fido', {
    username,
    assertion_payload: assertionPayload,
    assertionPayload,
  })
}

export async function fidoAssertionAbort(username: string): Promise<void> {
  return invoke<void>('bridge_fido_assertion_abort', { username })
}

export async function getHostname(): Promise<string> {
  return invoke<string>('bridge_get_hostname')
}

export async function getMailSettings(): Promise<MailSettings> {
  return invoke<MailSettings>('bridge_get_mail_settings')
}

export async function setMailSettings(settings: MailSettings): Promise<void> {
  return invoke<void>('bridge_set_mail_settings', { settings })
}

export async function isPortFree(port: number): Promise<boolean> {
  return invoke<boolean>('bridge_is_port_free', { port })
}

export async function logoutUser(userId: string): Promise<void> {
  return invoke<void>('bridge_logout_user', { user_id: userId })
}

export async function removeUser(userId: string): Promise<void> {
  return invoke<void>('bridge_remove_user', { user_id: userId })
}

export async function setUserSplitMode(userId: string, active: boolean): Promise<void> {
  return invoke<void>('bridge_set_user_split_mode', { user_id: userId, active })
}

export async function isTlsCertificateInstalled(): Promise<boolean> {
  return invoke<boolean>('bridge_is_tls_certificate_installed')
}

export async function installTlsCertificate(): Promise<void> {
  return invoke<void>('bridge_install_tls_certificate')
}

export async function exportTlsCertificates(outputDir: string): Promise<void> {
  return invoke<void>('bridge_export_tls_certificates', { output_dir: outputDir })
}

export async function getAppSettings(): Promise<AppSettings> {
  const settings = await invoke<AppSettings>('bridge_get_app_settings')
  return {
    ...settings,
    current_keychain: settings.current_keychain ?? '',
    available_keychains: settings.available_keychains ?? [],
  }
}

export async function setIsAutostartOn(enabled: boolean): Promise<void> {
  return invoke<void>('bridge_set_is_autostart_on', { enabled })
}

export async function setIsBetaEnabled(enabled: boolean): Promise<void> {
  return invoke<void>('bridge_set_is_beta_enabled', { enabled })
}

export async function setIsAllMailVisible(enabled: boolean): Promise<void> {
  return invoke<void>('bridge_set_is_all_mail_visible', { enabled })
}

export async function setIsTelemetryDisabled(disabled: boolean): Promise<void> {
  return invoke<void>('bridge_set_is_telemetry_disabled', { disabled })
}

export async function setDiskCachePath(path: string): Promise<void> {
  return invoke<void>('bridge_set_disk_cache_path', { path })
}

export async function setIsDohEnabled(enabled: boolean): Promise<void> {
  return invoke<void>('bridge_set_is_doh_enabled', { enabled })
}

export async function setColorSchemeName(name: string): Promise<void> {
  return invoke<void>('bridge_set_color_scheme_name', { name })
}

export async function setCurrentKeychain(name: string): Promise<void> {
  return invoke<void>('bridge_set_current_keychain', { name })
}

export async function onBridgeStateChanged(handler: (snapshot: BridgeSnapshot) => void): Promise<UnlistenFn> {
  return listen<BridgeSnapshot>('bridge://state-changed', (event) => handler(event.payload))
}

export async function onStreamTick(handler: (tick: StreamTickEvent) => void): Promise<UnlistenFn> {
  return listen<StreamTickEvent>('bridge://stream-tick', (event) => handler(event.payload))
}

export async function onBridgeUiEvent(handler: (event: BridgeUiEvent) => void): Promise<UnlistenFn> {
  return listen<BridgeUiEvent>('bridge://ui-event', (event) => handler(event.payload))
}

export async function onCaptchaToken(handler: (token: string) => void): Promise<UnlistenFn> {
  return listen<string>('bridge://captcha-token', (event) => handler(event.payload))
}

export async function onTrayAction(handler: (action: TrayAction) => void): Promise<UnlistenFn> {
  return listen<string>('bridge://tray-action', (event) => {
    if (event.payload === 'show_main' || event.payload === 'show_help' || event.payload === 'show_settings') {
      handler(event.payload)
      return
    }

    const selectUserPrefix = 'select_user:'
    if (event.payload.startsWith(selectUserPrefix)) {
      const userId = event.payload.slice(selectUserPrefix.length).trim()
      if (userId.length > 0) {
        handler({
          type: 'select_user',
          userId,
        })
      }
    }
  })
}
