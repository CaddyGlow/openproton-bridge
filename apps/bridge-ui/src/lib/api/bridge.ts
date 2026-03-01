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

export async function setLoginStep(step: string): Promise<BridgeSnapshot> {
  return invoke<BridgeSnapshot>('bridge_set_login_step', { step })
}

export async function pushMockError(message: string): Promise<BridgeSnapshot> {
  return invoke<BridgeSnapshot>('bridge_push_mock_error', { message })
}

export async function clearError(): Promise<BridgeSnapshot> {
  return invoke<BridgeSnapshot>('bridge_clear_error')
}

export async function onBridgeStateChanged(handler: (snapshot: BridgeSnapshot) => void): Promise<UnlistenFn> {
  return listen<BridgeSnapshot>('bridge://state-changed', (event) => handler(event.payload))
}

export async function onStreamTick(handler: (tick: StreamTickEvent) => void): Promise<UnlistenFn> {
  return listen<StreamTickEvent>('bridge://stream-tick', (event) => handler(event.payload))
}
