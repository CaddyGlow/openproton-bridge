import { beforeEach, describe, expect, it, vi } from 'vitest'

const { invokeMock } = vi.hoisted(() => ({
  invokeMock: vi.fn(),
}))

vi.mock('@tauri-apps/api/core', () => ({
  invoke: invokeMock,
}))

import { quitBridge } from './bridge'

describe('quitBridge', () => {
  beforeEach(() => {
    invokeMock.mockReset()
    delete (window as Window & { __TAURI_INTERNALS__?: unknown }).__TAURI_INTERNALS__
  })

  it('invokes bridge_quit when running in Tauri runtime', async () => {
    ;(window as Window & { __TAURI_INTERNALS__?: unknown }).__TAURI_INTERNALS__ = {
      invoke: () => undefined,
    }

    await quitBridge()

    expect(invokeMock).toHaveBeenCalledWith('bridge_quit')
  })

  it('falls back to window close when Tauri runtime is unavailable', async () => {
    const closeSpy = vi.spyOn(window, 'close').mockImplementation(() => undefined)

    await quitBridge()

    expect(invokeMock).not.toHaveBeenCalled()
    expect(closeSpy).toHaveBeenCalledTimes(1)
  })
})
