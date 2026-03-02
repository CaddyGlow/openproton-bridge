import type { BridgeSnapshot, BridgeUiEvent, StreamTickEvent } from '../api/bridge'

export const MAX_STREAM_LOG_ENTRIES = 50
export const MAX_NOTIFICATION_ENTRIES = 100

export type LoginStep =
  | 'idle'
  | 'credentials'
  | '2fa'
  | 'fido'
  | '2fa_or_fido'
  | 'fido_touch'
  | 'fido_pin'
  | 'mailbox_password'
  | 'done'
  | 'unknown'

export type SyncPhase = 'idle' | 'syncing' | 'complete' | 'error'

export type SyncState = {
  phase: SyncPhase
  progress_percent: number | null
  message: string | null
  updated_at: string | null
}

export type LoginState = {
  current_step: LoginStep
  previous_step: LoginStep | null
}

export type UiNotification = {
  id: number
  level: string
  code: string
  message: string
  refresh_hints: string[]
  created_at: string
}

export type DiskCacheNotice = {
  status: 'success' | 'error'
  code: string
  message: string
  at: string
}

export type RefreshHintState = Record<string, number>

export type ParityDomainState = {
  snapshot: BridgeSnapshot
  login: LoginState
  sync: SyncState
  stream_log: string[]
  notifications: UiNotification[]
  disk_cache_notice: DiskCacheNotice | null
  refresh_hints: RefreshHintState
  last_ui_event: BridgeUiEvent | null
  next_notification_id: number
}

export type ParityDomainEvent =
  | { type: 'bridge.snapshot.received'; snapshot: BridgeSnapshot }
  | { type: 'bridge.stream.tick.received'; tick: StreamTickEvent }
  | { type: 'bridge.ui.event.received'; event: BridgeUiEvent }
  | { type: 'ui.refresh-hint.consumed'; hint: string }
  | { type: 'ui.refresh-hints.cleared' }
  | { type: 'ui.notifications.cleared' }
  | { type: 'ui.disk-cache-notice.cleared' }

export const INITIAL_BRIDGE_SNAPSHOT: BridgeSnapshot = {
  connected: false,
  stream_running: false,
  login_step: 'idle',
  last_error: null,
  config_path: null,
}
