import { describe, expect, it } from 'vitest'
import { createInitialParityDomainState, parityStateReducer } from './reducer'
import type { ParityDomainState } from './types'

function applyEvents(
  events: Parameters<typeof parityStateReducer>[1][],
  initial: ParityDomainState = createInitialParityDomainState(),
): ParityDomainState {
  return events.reduce((state, event) => parityStateReducer(state, event), initial)
}

describe('parityStateReducer', () => {
  it('applies login step transitions from snapshot and ui events', () => {
    const state = applyEvents([
      {
        type: 'bridge.snapshot.received',
        snapshot: {
          connected: true,
          stream_running: true,
          login_step: 'credentials',
          last_error: null,
          config_path: '/tmp/grpcServerConfig.json',
        },
      },
      {
        type: 'bridge.ui.event.received',
        event: {
          level: 'info',
          code: 'tfa_requested',
          message: '2FA code required',
          refresh_hints: [],
        },
      },
      {
        type: 'bridge.ui.event.received',
        event: {
          level: 'info',
          code: 'fido_touch_requested',
          message: 'Touch your security key',
          refresh_hints: [],
        },
      },
      {
        type: 'bridge.snapshot.received',
        snapshot: {
          connected: true,
          stream_running: true,
          login_step: 'done',
          last_error: null,
          config_path: '/tmp/grpcServerConfig.json',
        },
      },
    ])

    expect(state.login.current_step).toBe('done')
    expect(state.login.previous_step).toBe('fido_touch')
    expect(state.snapshot.login_step).toBe('done')
  })

  it('handles sync progress transitions through ui events', () => {
    const state = applyEvents([
      {
        type: 'bridge.ui.event.received',
        event: {
          level: 'info',
          code: 'sync_started',
          message: 'Synchronizing mailbox',
          refresh_hints: ['users'],
        },
      },
      {
        type: 'bridge.ui.event.received',
        event: {
          level: 'info',
          code: 'sync_progress',
          message: 'Synchronizing (37%)',
          refresh_hints: [],
        },
      },
      {
        type: 'bridge.ui.event.received',
        event: {
          level: 'info',
          code: 'sync_progress',
          message: 'still syncing',
          refresh_hints: ['sync_progress:88'],
        },
      },
      {
        type: 'bridge.ui.event.received',
        event: {
          level: 'info',
          code: 'sync_finished',
          message: 'Synchronization complete',
          refresh_hints: ['users'],
        },
      },
    ])

    expect(state.sync.phase).toBe('complete')
    expect(state.sync.progress_percent).toBe(100)
    expect(state.sync.message).toBe('Synchronization complete')
  })

  it('records disk cache success and error notifications', () => {
    const state = applyEvents([
      {
        type: 'bridge.ui.event.received',
        event: {
          level: 'info',
          code: 'disk_cache_saved',
          message: 'Disk cache path updated',
          refresh_hints: ['app_settings'],
        },
      },
      {
        type: 'bridge.ui.event.received',
        event: {
          level: 'error',
          code: 'disk_cache_error',
          message: 'disk cache error (CANT_MOVE_DISK_CACHE_ERROR)',
          refresh_hints: ['app_settings'],
        },
      },
    ])

    expect(state.notifications[0].code).toBe('disk_cache_error')
    expect(state.notifications[1].code).toBe('disk_cache_saved')
    expect(state.disk_cache_notice?.status).toBe('error')
    expect(state.disk_cache_notice?.code).toBe('disk_cache_error')
  })

  it('aggregates and consumes refresh hints', () => {
    const state = applyEvents([
      {
        type: 'bridge.ui.event.received',
        event: {
          level: 'info',
          code: 'users_updated',
          message: 'User state updated',
          refresh_hints: ['users', 'users', 'app_settings'],
        },
      },
      {
        type: 'ui.refresh-hint.consumed',
        hint: 'users',
      },
      {
        type: 'ui.refresh-hint.consumed',
        hint: 'users',
      },
    ])

    expect(state.refresh_hints.users).toBeUndefined()
    expect(state.refresh_hints.app_settings).toBe(1)
  })

  it('prepends stream ticks and keeps bounded log length', () => {
    const events = Array.from({ length: 55 }, (_, index) => ({
      type: 'bridge.stream.tick.received' as const,
      tick: {
        timestamp: `[${index}]`,
        message: `event-${index}`,
      },
    }))

    const state = applyEvents(events)

    expect(state.stream_log.length).toBe(50)
    expect(state.stream_log[0]).toBe('[54] event-54')
    expect(state.stream_log[49]).toBe('[5] event-5')
  })
})
