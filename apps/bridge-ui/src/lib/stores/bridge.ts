import { writable } from 'svelte/store'
import {
  clearError,
  connectBridge,
  disconnectBridge,
  getBridgeStatus,
  onBridgeStateChanged,
  onStreamTick,
  setConfigPath,
  type BridgeSnapshot,
  type StreamTickEvent,
} from '../api/bridge'
import { logger } from '../logging/logger'

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
  logger.info('bridge.store', 'bridge store initialized')

  const unlistenState = await onBridgeStateChanged((snapshot) => {
    logger.debug('bridge.store', 'state changed event received', snapshot)
    bridgeStatus.set(snapshot)
  })

  const unlistenTick = await onStreamTick((tick) => {
    logger.debug('bridge.store', 'stream tick received', tick)
    appendTick(tick)
  })

  return () => {
    logger.info('bridge.store', 'bridge store listeners removed')
    unlistenState()
    unlistenTick()
  }
}

export async function connect(): Promise<void> {
  logger.info('bridge.store', 'connect requested')
  bridgeStatus.set(await connectBridge())
}

export async function updateConfigPath(path: string): Promise<void> {
  logger.info('bridge.store', 'config path update requested', { path })
  bridgeStatus.set(await setConfigPath(path))
}

export async function disconnect(): Promise<void> {
  logger.info('bridge.store', 'disconnect requested')
  bridgeStatus.set(await disconnectBridge())
}

export async function resetError(): Promise<void> {
  logger.info('bridge.store', 'clear error requested')
  bridgeStatus.set(await clearError())
}
