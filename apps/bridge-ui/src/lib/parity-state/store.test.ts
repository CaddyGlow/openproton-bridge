import { describe, expect, it, vi } from 'vitest'
import { createParityStateStore } from './store'
import type { BridgeSnapshot, BridgeUiEvent, StreamTickEvent } from '../api/bridge'

describe('createParityStateStore', () => {
  it('wires bridge listeners into reducer events', async () => {
    const store = createParityStateStore()
    const unsubscribeSnapshot = vi.fn()
    const unsubscribeTick = vi.fn()
    const unsubscribeUi = vi.fn()

    let snapshotHandler: ((snapshot: BridgeSnapshot) => void) | undefined
    let tickHandler: ((tick: StreamTickEvent) => void) | undefined
    let uiHandler: ((event: BridgeUiEvent) => void) | undefined

    const stop = await store.init({
      getSnapshot: async () => ({
        connected: true,
        stream_running: true,
        login_step: 'credentials',
        last_error: null,
        config_path: '/tmp/grpcServerConfig.json',
      }),
      onSnapshot: async (handler) => {
        snapshotHandler = handler
        return unsubscribeSnapshot
      },
      onStreamTick: async (handler) => {
        tickHandler = handler
        return unsubscribeTick
      },
      onUiEvent: async (handler) => {
        uiHandler = handler
        return unsubscribeUi
      },
    })

    if (!snapshotHandler || !tickHandler || !uiHandler) {
      throw new Error('parity store listeners were not installed')
    }

    snapshotHandler({
      connected: true,
      stream_running: true,
      login_step: '2fa',
      last_error: null,
      config_path: '/tmp/grpcServerConfig.json',
    })
    tickHandler({ timestamp: '[1]', message: 'stream event: user' })
    uiHandler({
      level: 'info',
      code: 'disk_cache_saved',
      message: 'Disk cache path updated',
      refresh_hints: ['app_settings'],
    })

    const state = store.getState()
    expect(state.login.current_step).toBe('2fa')
    expect(state.stream_log[0]).toBe('[1] stream event: user')
    expect(state.disk_cache_notice?.status).toBe('success')
    expect(state.refresh_hints.app_settings).toBe(1)

    stop()
    expect(unsubscribeSnapshot).toHaveBeenCalledTimes(1)
    expect(unsubscribeTick).toHaveBeenCalledTimes(1)
    expect(unsubscribeUi).toHaveBeenCalledTimes(1)
  })
})
