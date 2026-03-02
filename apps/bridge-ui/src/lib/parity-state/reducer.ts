import type { BridgeSnapshot, BridgeUiEvent } from '../api/bridge'
import {
  INITIAL_BRIDGE_SNAPSHOT,
  MAX_NOTIFICATION_ENTRIES,
  MAX_STREAM_LOG_ENTRIES,
  type LoginStep,
  type ParityDomainEvent,
  type ParityDomainState,
  type RefreshHintState,
  type SyncState,
} from './types'

const KNOWN_LOGIN_STEPS = new Set<LoginStep>([
  'idle',
  'credentials',
  '2fa',
  'fido',
  '2fa_or_fido',
  'fido_touch',
  'fido_pin',
  'mailbox_password',
  'done',
  'unknown',
])

const LOGIN_STEP_CODES: Partial<Record<string, LoginStep>> = {
  tfa_requested: '2fa',
  fido_requested: 'fido',
  tfa_or_fido_requested: '2fa_or_fido',
  fido_touch_requested: 'fido_touch',
  fido_touch_completed: 'fido',
  fido_pin_required: 'fido_pin',
  login_finished: 'done',
  login_error: 'credentials',
}

const SYNC_STARTED_CODES = new Set(['sync_started'])
const SYNC_PROGRESS_CODES = new Set(['sync_progress'])
const SYNC_FINISHED_CODES = new Set(['sync_finished'])
const SYNC_ERROR_CODES = new Set(['sync_error', 'sync_failed'])

function normalizeLoginStep(step: string): LoginStep {
  if (KNOWN_LOGIN_STEPS.has(step as LoginStep)) {
    return step as LoginStep
  }
  return 'unknown'
}

function transitionLogin(state: ParityDomainState, nextStep: LoginStep): ParityDomainState {
  if (state.login.current_step === nextStep) {
    return state
  }
  return {
    ...state,
    login: {
      current_step: nextStep,
      previous_step: state.login.current_step,
    },
  }
}

function patchSnapshotLoginStep(snapshot: BridgeSnapshot, step: LoginStep): BridgeSnapshot {
  if (snapshot.login_step === step) {
    return snapshot
  }
  return {
    ...snapshot,
    login_step: step,
  }
}

function mergeRefreshHints(current: RefreshHintState, nextHints: string[]): RefreshHintState {
  if (nextHints.length === 0) {
    return current
  }

  const merged = { ...current }
  for (const hint of nextHints) {
    merged[hint] = (merged[hint] ?? 0) + 1
  }
  return merged
}

function extractSyncPercent(event: BridgeUiEvent): number | null {
  for (const hint of event.refresh_hints) {
    if (hint.startsWith('sync_progress:')) {
      const parsed = Number.parseInt(hint.slice('sync_progress:'.length), 10)
      if (Number.isFinite(parsed)) {
        return Math.max(0, Math.min(100, parsed))
      }
    }
  }

  const fromMessage = event.message.match(/(\d{1,3})\s*%/)
  if (!fromMessage) {
    return null
  }
  const parsed = Number.parseInt(fromMessage[1], 10)
  return Math.max(0, Math.min(100, parsed))
}

function transitionSync(sync: SyncState, event: BridgeUiEvent): SyncState {
  if (SYNC_STARTED_CODES.has(event.code)) {
    return {
      phase: 'syncing',
      progress_percent: 0,
      message: event.message,
      updated_at: new Date().toISOString(),
    }
  }

  if (SYNC_PROGRESS_CODES.has(event.code)) {
    return {
      phase: 'syncing',
      progress_percent: extractSyncPercent(event) ?? sync.progress_percent ?? 0,
      message: event.message,
      updated_at: new Date().toISOString(),
    }
  }

  if (SYNC_FINISHED_CODES.has(event.code)) {
    return {
      phase: 'complete',
      progress_percent: 100,
      message: event.message,
      updated_at: new Date().toISOString(),
    }
  }

  if (SYNC_ERROR_CODES.has(event.code)) {
    return {
      phase: 'error',
      progress_percent: sync.progress_percent,
      message: event.message,
      updated_at: new Date().toISOString(),
    }
  }

  return sync
}

export function createInitialParityDomainState(): ParityDomainState {
  return {
    snapshot: { ...INITIAL_BRIDGE_SNAPSHOT },
    login: {
      current_step: normalizeLoginStep(INITIAL_BRIDGE_SNAPSHOT.login_step),
      previous_step: null,
    },
    sync: {
      phase: 'idle',
      progress_percent: null,
      message: null,
      updated_at: null,
    },
    stream_log: [],
    notifications: [],
    disk_cache_notice: null,
    refresh_hints: {},
    last_ui_event: null,
    next_notification_id: 1,
  }
}

// One-way mapping from backend stream/snapshot events into domain state.
export function parityStateReducer(state: ParityDomainState, event: ParityDomainEvent): ParityDomainState {
  switch (event.type) {
    case 'bridge.snapshot.received': {
      const nextState = {
        ...state,
        snapshot: { ...event.snapshot },
      }
      return transitionLogin(nextState, normalizeLoginStep(event.snapshot.login_step))
    }
    case 'bridge.stream.tick.received': {
      const nextEntry = `${event.tick.timestamp} ${event.tick.message}`
      return {
        ...state,
        stream_log: [nextEntry, ...state.stream_log].slice(0, MAX_STREAM_LOG_ENTRIES),
      }
    }
    case 'bridge.ui.event.received': {
      const nowIso = new Date().toISOString()
      const notification = {
        id: state.next_notification_id,
        level: event.event.level,
        code: event.event.code,
        message: event.event.message,
        refresh_hints: [...event.event.refresh_hints],
        created_at: nowIso,
      }

      const withUi = {
        ...state,
        last_ui_event: { ...event.event },
        next_notification_id: state.next_notification_id + 1,
        notifications: [notification, ...state.notifications].slice(0, MAX_NOTIFICATION_ENTRIES),
        refresh_hints: mergeRefreshHints(state.refresh_hints, event.event.refresh_hints),
        sync: transitionSync(state.sync, event.event),
      }

      const mappedLoginStep = LOGIN_STEP_CODES[event.event.code]
      const withLogin =
        mappedLoginStep === undefined ? withUi : transitionLogin(withUi, mappedLoginStep)

      const snapshotWithLogin =
        mappedLoginStep === undefined
          ? withLogin.snapshot
          : patchSnapshotLoginStep(withLogin.snapshot, mappedLoginStep)

      const withSnapshot = {
        ...withLogin,
        snapshot: snapshotWithLogin,
      }

      if (event.event.code === 'disk_cache_saved') {
        return {
          ...withSnapshot,
          disk_cache_notice: {
            status: 'success',
            code: event.event.code,
            message: event.event.message,
            at: nowIso,
          },
        }
      }

      if (event.event.code === 'disk_cache_error') {
        return {
          ...withSnapshot,
          disk_cache_notice: {
            status: 'error',
            code: event.event.code,
            message: event.event.message,
            at: nowIso,
          },
        }
      }

      return withSnapshot
    }
    case 'ui.refresh-hint.consumed': {
      const current = state.refresh_hints[event.hint]
      if (current === undefined) {
        return state
      }

      const nextHints = { ...state.refresh_hints }
      if (current <= 1) {
        delete nextHints[event.hint]
      } else {
        nextHints[event.hint] = current - 1
      }

      return {
        ...state,
        refresh_hints: nextHints,
      }
    }
    case 'ui.refresh-hints.cleared':
      return {
        ...state,
        refresh_hints: {},
      }
    case 'ui.notifications.cleared':
      return {
        ...state,
        notifications: [],
      }
    case 'ui.disk-cache-notice.cleared':
      return {
        ...state,
        disk_cache_notice: null,
      }
    default:
      return state
  }
}
