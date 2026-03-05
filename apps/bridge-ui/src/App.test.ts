import { fireEvent, render, screen, waitFor } from '@testing-library/svelte'
import { beforeEach, describe, expect, it, vi } from 'vitest'

const bridgeApi = vi.hoisted(() => {
  let bridgeStateHandler: ((snapshot: unknown) => void) | undefined

  const onBridgeStateChanged = vi.fn(async (handler: (snapshot: unknown) => void) => {
    bridgeStateHandler = handler
    return () => {
      if (bridgeStateHandler === handler) {
        bridgeStateHandler = undefined
      }
    }
  })

  const unlisten = vi.fn(() => undefined)

  return {
    bridge_refresh_tray_users: vi.fn(async () => undefined),
    onCaptchaToken: vi.fn(async () => unlisten),
    onCaptchaWindowClosed: vi.fn(async () => unlisten),
    exportTlsCertificates: vi.fn(async () => undefined),
    fetchUsers: vi.fn(async () => []),
    getAppSettings: vi.fn(async () => ({
      is_autostart_on: false,
      is_beta_enabled: false,
      is_all_mail_visible: true,
      is_telemetry_disabled: false,
      disk_cache_path: '',
      is_doh_enabled: true,
      color_scheme_name: 'system',
      current_keychain: '',
      available_keychains: [],
    })),
    getHostname: vi.fn(async () => '127.0.0.1'),
    getMailSettings: vi.fn(async () => ({
      imap_port: 1143,
      smtp_port: 1025,
      use_ssl_for_imap: false,
      use_ssl_for_smtp: false,
    })),
    installTlsCertificate: vi.fn(async () => undefined),
    isPortFree: vi.fn(async () => true),
    isTlsCertificateInstalled: vi.fn(async () => false),
    loginFido: vi.fn(async () => undefined),
    login: vi.fn(async () => undefined),
    login2fa: vi.fn(async () => undefined),
    login2passwords: vi.fn(async () => undefined),
    loginAbort: vi.fn(async () => undefined),
    quitBridge: vi.fn(async () => undefined),
    openCaptchaWindow: vi.fn(async () => undefined),
    closeCaptchaWindow: vi.fn(async () => undefined),
    onTrayAction: vi.fn(async () => unlisten),
    fidoAssertionAbort: vi.fn(async () => undefined),
    logoutUser: vi.fn(async () => undefined),
    removeUser: vi.fn(async () => undefined),
    setColorSchemeName: vi.fn(async () => undefined),
    setCurrentKeychain: vi.fn(async () => undefined),
    setDiskCachePath: vi.fn(async () => undefined),
    setIsAllMailVisible: vi.fn(async () => undefined),
    setIsAutostartOn: vi.fn(async () => undefined),
    setIsBetaEnabled: vi.fn(async () => undefined),
    setIsDohEnabled: vi.fn(async () => undefined),
    setIsTelemetryDisabled: vi.fn(async () => undefined),
    setUserSplitMode: vi.fn(async () => undefined),
    setMailSettings: vi.fn(async () => undefined),
    getBridgeStatus: vi.fn(async () => ({
      connected: false,
      stream_running: false,
      login_step: 'idle',
      last_error: null,
      config_path: null,
    })),
    connectBridge: vi.fn(async () => ({
      connected: true,
      stream_running: true,
      login_step: 'idle',
      last_error: null,
      config_path: null,
    })),
    disconnectBridge: vi.fn(async () => ({
      connected: false,
      stream_running: false,
      login_step: 'idle',
      last_error: null,
      config_path: null,
    })),
    setConfigPath: vi.fn(async () => ({
      connected: false,
      stream_running: false,
      login_step: 'idle',
      last_error: null,
      config_path: null,
    })),
    clearError: vi.fn(async () => ({
      connected: false,
      stream_running: false,
      login_step: 'idle',
      last_error: null,
      config_path: null,
    })),
    onBridgeStateChanged,
    onStreamTick: vi.fn(async () => unlisten),
    onBridgeUiEvent: vi.fn(async () => unlisten),
    emitBridgeState(snapshot: unknown) {
      bridgeStateHandler?.(snapshot)
    },
  }
})

vi.mock('./lib/logging/logger', () => ({
  logger: {
    debug: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  },
}))

vi.mock('./lib/api/bridge', () => bridgeApi)

import App from './App.svelte'

const connectedSnapshot = {
  connected: true,
  stream_running: true,
  login_step: 'idle',
  last_error: null,
  config_path: null,
}

const disconnectedSnapshot = {
  connected: false,
  stream_running: false,
  login_step: 'idle',
  last_error: null,
  config_path: null,
}

function deferred<T>() {
  let resolve: ((value: T) => void) | undefined
  let reject: ((reason?: unknown) => void) | undefined
  const promise = new Promise<T>((res, rej) => {
    resolve = res
    reject = rej
  })
  return { promise, resolve, reject }
}

describe('App bootstrap and connection flow', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    Object.defineProperty(window, 'matchMedia', {
      writable: true,
      value: vi.fn().mockImplementation(() => ({
        matches: false,
        media: '',
        onchange: null,
        addListener: vi.fn(),
        removeListener: vi.fn(),
        addEventListener: vi.fn(),
        removeEventListener: vi.fn(),
        dispatchEvent: vi.fn(),
      })),
    })

    bridgeApi.getBridgeStatus.mockResolvedValue({ ...disconnectedSnapshot })
    bridgeApi.fetchUsers.mockResolvedValue([] as any)
    bridgeApi.connectBridge.mockImplementation(async () => {
      bridgeApi.getBridgeStatus.mockResolvedValue({ ...connectedSnapshot })
      bridgeApi.emitBridgeState({ ...connectedSnapshot })
      return { ...connectedSnapshot }
    })
    bridgeApi.disconnectBridge.mockImplementation(async () => {
      bridgeApi.getBridgeStatus.mockResolvedValue({ ...disconnectedSnapshot })
      bridgeApi.emitBridgeState({ ...disconnectedSnapshot })
      return { ...disconnectedSnapshot }
    })
  })

  it('shows startup loading while grpc connection is still pending', async () => {
    const pendingConnection = deferred<typeof connectedSnapshot>()
    bridgeApi.connectBridge.mockImplementation(() => {
      bridgeApi.getBridgeStatus.mockResolvedValue({ ...connectedSnapshot })
      return pendingConnection.promise
    })

    render(App)

    expect(screen.getByTestId('startup-loading')).toBeInTheDocument()

    pendingConnection.resolve?.({ ...connectedSnapshot })

    await waitFor(() => {
      expect(screen.queryByTestId('startup-loading')).not.toBeInTheDocument()
    })
  })

  it('only opens the account wizard when there are zero accounts', async () => {
    bridgeApi.fetchUsers.mockResolvedValue([])

    const { unmount } = render(App)
    await waitFor(() => {
      expect(screen.queryByTestId('startup-loading')).not.toBeInTheDocument()
    })
    expect(screen.getByRole('dialog', { name: 'Proton login wizard' })).toBeInTheDocument()
    unmount()

    bridgeApi.fetchUsers.mockResolvedValue([
      {
        id: 'u1',
        username: 'alice@example.com',
        state: 2,
        split_mode: false,
        addresses: ['alice@example.com'],
        used_bytes: 10,
        total_bytes: 100,
      },
    ] as any)

    render(App)
    await waitFor(() => {
      expect(screen.queryByTestId('startup-loading')).not.toBeInTheDocument()
    })

    expect(screen.queryByRole('dialog', { name: 'Proton login wizard' })).not.toBeInTheDocument()
  })

  it('transitions from disconnected to connected after retry', async () => {
    bridgeApi.fetchUsers.mockResolvedValue([
      {
        id: 'u1',
        username: 'alice@example.com',
        state: 2,
        split_mode: false,
        addresses: ['alice@example.com'],
        used_bytes: 10,
        total_bytes: 100,
      },
    ] as any)

    render(App)

    await waitFor(() => {
      expect(screen.getByTestId('grpc-connection-status')).toHaveTextContent('Connected')
    })

    bridgeApi.emitBridgeState({ ...disconnectedSnapshot })

    await waitFor(() => {
      expect(screen.getByTestId('grpc-connection-status')).toHaveTextContent('Disconnected')
    })
    expect(screen.getByTestId('accounts-connection-state')).toBeInTheDocument()
    expect(screen.queryByText('No users returned.')).not.toBeInTheDocument()

    await fireEvent.click(screen.getByRole('button', { name: 'Retry' }))

    await waitFor(() => {
      expect(screen.getByTestId('grpc-connection-status')).toHaveTextContent('Connected')
    })

    expect(bridgeApi.connectBridge).toHaveBeenCalledTimes(2)
  })
})
