import { writable } from 'svelte/store'
import {
  clearError,
  connectBridge,
  disconnectBridge,
  getBridgeStatus,
  onBridgeStateChanged,
  onStreamTick,
  pushMockError,
  setConfigPath,
  setLoginStep,
  type BridgeSnapshot,
  type StreamTickEvent,
} from '../api/bridge'

const initialStatus: BridgeSnapshot = {
  connected: false,
  stream_running: false,
  login_step: 'idle',
  last_error: null,
  config_path: null,
}

export const bridgeStatus = writable<BridgeSnapshot>(initialStatus)
export const streamLog = writable<string[]>([])

function appendTick(tick: StreamTickEvent): void {
  streamLog.update((entries) => {
    const next = [`${tick.timestamp} ${tick.message}`, ...entries]
    return next.slice(0, 50)
  })
}

export async function initBridgeStore(): Promise<() => void> {
  bridgeStatus.set(await getBridgeStatus())

  const unlistenState = await onBridgeStateChanged((snapshot) => {
    bridgeStatus.set(snapshot)
  })

  const unlistenTick = await onStreamTick((tick) => {
    appendTick(tick)
  })

  return () => {
    unlistenState()
    unlistenTick()
  }
}

export async function connect(): Promise<void> {
  bridgeStatus.set(await connectBridge())
}

export async function updateConfigPath(path: string): Promise<void> {
  bridgeStatus.set(await setConfigPath(path))
}

export async function disconnect(): Promise<void> {
  bridgeStatus.set(await disconnectBridge())
}

export async function updateLoginStep(step: string): Promise<void> {
  bridgeStatus.set(await setLoginStep(step))
}

export async function fail(message: string): Promise<void> {
  bridgeStatus.set(await pushMockError(message))
}

export async function resetError(): Promise<void> {
  bridgeStatus.set(await clearError())
}
