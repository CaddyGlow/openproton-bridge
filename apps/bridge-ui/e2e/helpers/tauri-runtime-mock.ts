import type { Page } from '@playwright/test'

type BridgeSnapshot = {
  connected: boolean
  stream_running: boolean
  login_step: string
  last_error: string | null
  config_path: string | null
}

type UserSummary = {
  id: string
  username: string
  state: number
  split_mode: boolean
  addresses: string[]
  used_bytes: number
  total_bytes: number
}

type MailSettings = {
  imap_port: number
  smtp_port: number
  use_ssl_for_imap: boolean
  use_ssl_for_smtp: boolean
}

type AppSettings = {
  is_autostart_on: boolean
  is_beta_enabled: boolean
  is_all_mail_visible: boolean
  is_telemetry_disabled: boolean
  disk_cache_path: string
  is_doh_enabled: boolean
  color_scheme_name: string
}

type MockSeed = {
  snapshot: BridgeSnapshot
  users: UserSummary[]
  hostname: string
  mailSettings: MailSettings
  appSettings: AppSettings
  tlsInstalled: boolean
}

export type RuntimeMockOverrides = {
  snapshot?: Partial<BridgeSnapshot>
  users?: UserSummary[]
  hostname?: string
  mailSettings?: Partial<MailSettings>
  appSettings?: Partial<AppSettings>
  tlsInstalled?: boolean
}

export type BridgeUiEvent = {
  level?: string
  code: string
  message: string
  refresh_hints?: string[]
}

export type TauriInvokeCall = {
  cmd: string
  args: Record<string, unknown>
}

const defaultSeed: MockSeed = {
  snapshot: {
    connected: true,
    stream_running: true,
    login_step: 'credentials',
    last_error: null,
    config_path: '/tmp/openproton/config',
  },
  users: [
    {
      id: 'u1',
      username: 'alice@proton.me',
      state: 2,
      split_mode: false,
      addresses: ['alice@proton.me'],
      used_bytes: 2_000_000_000,
      total_bytes: 10_000_000_000,
    },
  ],
  hostname: 'bridge.local',
  mailSettings: {
    imap_port: 1143,
    smtp_port: 1025,
    use_ssl_for_imap: false,
    use_ssl_for_smtp: false,
  },
  appSettings: {
    is_autostart_on: false,
    is_beta_enabled: false,
    is_all_mail_visible: true,
    is_telemetry_disabled: false,
    disk_cache_path: '/tmp/cache-a',
    is_doh_enabled: true,
    color_scheme_name: 'system',
  },
  tlsInstalled: false,
}

function buildSeed(overrides: RuntimeMockOverrides): MockSeed {
  return {
    snapshot: { ...defaultSeed.snapshot, ...overrides.snapshot },
    users: overrides.users ?? defaultSeed.users,
    hostname: overrides.hostname ?? defaultSeed.hostname,
    mailSettings: { ...defaultSeed.mailSettings, ...overrides.mailSettings },
    appSettings: { ...defaultSeed.appSettings, ...overrides.appSettings },
    tlsInstalled: overrides.tlsInstalled ?? defaultSeed.tlsInstalled,
  }
}

export async function installTauriRuntimeMocks(page: Page, overrides: RuntimeMockOverrides = {}): Promise<void> {
  const seed = buildSeed(overrides)
  await page.addInitScript((inputSeed: MockSeed) => {
    const win = window as unknown as Record<string, unknown>
    const state = JSON.parse(JSON.stringify(inputSeed)) as MockSeed
    const invokeCalls: TauriInvokeCall[] = []
    const callbacks = new Map<number, (payload: unknown) => void>()
    const listenersByEvent = new Map<string, Map<number, number>>()
    let nextCallbackId = 1
    let nextListenerId = 1

    const clone = <T>(value: T): T => JSON.parse(JSON.stringify(value))

    const emit = (eventName: string, payload: unknown): void => {
      const listeners = listenersByEvent.get(eventName)
      if (!listeners) {
        return
      }

      for (const [listenerId, callbackId] of listeners.entries()) {
        const callback = callbacks.get(callbackId)
        if (!callback) {
          continue
        }
        callback({
          event: eventName,
          id: listenerId,
          payload,
        })
      }
    }

    const invoke = async (cmd: string, args: Record<string, unknown> = {}) => {
      invokeCalls.push({ cmd, args: clone(args) })
      switch (cmd) {
        case 'plugin:event|listen': {
          const eventName = String(args.event ?? '')
          const handlerId = Number(args.handler)
          const listenerId = nextListenerId
          nextListenerId += 1
          const listeners = listenersByEvent.get(eventName) ?? new Map<number, number>()
          listeners.set(listenerId, handlerId)
          listenersByEvent.set(eventName, listeners)
          return listenerId
        }
        case 'plugin:event|unlisten': {
          const eventName = String(args.event ?? '')
          const eventId = Number(args.eventId)
          listenersByEvent.get(eventName)?.delete(eventId)
          return null
        }
        case 'bridge_status':
          return clone(state.snapshot)
        case 'bridge_connect':
          state.snapshot.connected = true
          state.snapshot.stream_running = true
          return clone(state.snapshot)
        case 'bridge_disconnect':
          state.snapshot.connected = false
          state.snapshot.stream_running = false
          return clone(state.snapshot)
        case 'bridge_set_config_path':
          state.snapshot.config_path = String(args.path ?? '')
          return clone(state.snapshot)
        case 'bridge_clear_error':
          state.snapshot.last_error = null
          return clone(state.snapshot)
        case 'bridge_fetch_users':
          return clone(state.users)
        case 'bridge_get_hostname':
          return state.hostname
        case 'bridge_get_mail_settings':
          return clone(state.mailSettings)
        case 'bridge_set_mail_settings':
          if (typeof args.settings === 'object' && args.settings !== null) {
            state.mailSettings = {
              ...state.mailSettings,
              ...(args.settings as Partial<MailSettings>),
            }
          }
          return null
        case 'bridge_is_tls_certificate_installed':
          return state.tlsInstalled
        case 'bridge_get_app_settings':
          return clone(state.appSettings)
        case 'bridge_set_is_autostart_on':
          state.appSettings.is_autostart_on = Boolean(args.enabled)
          return null
        case 'bridge_set_is_beta_enabled':
          state.appSettings.is_beta_enabled = Boolean(args.enabled)
          return null
        case 'bridge_set_is_all_mail_visible':
          state.appSettings.is_all_mail_visible = Boolean(args.enabled)
          return null
        case 'bridge_set_is_telemetry_disabled':
          state.appSettings.is_telemetry_disabled = Boolean(args.disabled)
          return null
        case 'bridge_set_is_doh_enabled':
          state.appSettings.is_doh_enabled = Boolean(args.enabled)
          return null
        case 'bridge_set_disk_cache_path':
          state.appSettings.disk_cache_path = String(args.path ?? '')
          return null
        case 'bridge_set_color_scheme_name':
          state.appSettings.color_scheme_name = String(args.name ?? 'system')
          return null
        case 'bridge_frontend_log':
          return null
        default:
          return null
      }
    }

    win.__TAURI_INTERNALS__ = {
      invoke,
      transformCallback(callback: (payload: unknown) => void) {
        const id = nextCallbackId
        nextCallbackId += 1
        callbacks.set(id, callback)
        return id
      },
      unregisterCallback(callbackId: number) {
        callbacks.delete(callbackId)
      },
    }

    win.__TAURI_EVENT_PLUGIN_INTERNALS__ = {
      unregisterListener(eventName: string, eventId: number) {
        listenersByEvent.get(eventName)?.delete(eventId)
      },
    }

    win.__TAURI_MOCK__ = {
      emit,
      getInvokeCalls() {
        return clone(invokeCalls)
      },
    }

    win.__TAURI__ = {
      core: { invoke },
      mock: win.__TAURI_MOCK__,
    }
  }, seed)
}

export async function emitTauriEvent(page: Page, eventName: string, payload: unknown): Promise<void> {
  await page.evaluate(
    ({ targetEventName, targetPayload }) => {
      const tauriMock = (window as unknown as { __TAURI_MOCK__?: { emit: (name: string, data: unknown) => void } })
        .__TAURI_MOCK__
      tauriMock?.emit(targetEventName, targetPayload)
    },
    { targetEventName: eventName, targetPayload: payload },
  )
}

export async function emitBridgeUiEvent(page: Page, event: BridgeUiEvent): Promise<void> {
  await emitTauriEvent(page, 'bridge://ui-event', {
    level: event.level ?? 'info',
    code: event.code,
    message: event.message,
    refresh_hints: event.refresh_hints ?? [],
  })
}

export async function getTauriInvokeCalls(page: Page): Promise<TauriInvokeCall[]> {
  return page.evaluate(() => {
    const tauriMock = (window as unknown as { __TAURI_MOCK__?: { getInvokeCalls: () => TauriInvokeCall[] } }).__TAURI_MOCK__
    return tauriMock?.getInvokeCalls() ?? []
  })
}
