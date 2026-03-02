import { writable, type Readable } from 'svelte/store'
import type {
  BridgeSnapshot,
  BridgeUiEvent,
  StreamTickEvent,
} from '../api/bridge'
import {
  getBridgeStatus,
  onBridgeStateChanged,
  onBridgeUiEvent,
  onStreamTick,
} from '../api/bridge'
import { createInitialParityDomainState, parityStateReducer } from './reducer'
import type { ParityDomainEvent, ParityDomainState } from './types'

export type Unsubscribe = () => void

export type ParityStoreEventSource = {
  getSnapshot: () => Promise<BridgeSnapshot>
  onSnapshot: (handler: (snapshot: BridgeSnapshot) => void) => Promise<Unsubscribe>
  onStreamTick: (handler: (tick: StreamTickEvent) => void) => Promise<Unsubscribe>
  onUiEvent: (handler: (event: BridgeUiEvent) => void) => Promise<Unsubscribe>
}

const defaultEventSource: ParityStoreEventSource = {
  getSnapshot: getBridgeStatus,
  onSnapshot: onBridgeStateChanged,
  onStreamTick,
  onUiEvent: onBridgeUiEvent,
}

export type ParityStateStore = Readable<ParityDomainState> & {
  dispatch: (event: ParityDomainEvent) => void
  getState: () => ParityDomainState
  reset: () => void
  init: (source?: ParityStoreEventSource) => Promise<Unsubscribe>
}

export function createParityStateStore(initial?: ParityDomainState): ParityStateStore {
  let state = initial ?? createInitialParityDomainState()
  const store = writable(state)
  let stopListeners: Unsubscribe | null = null

  const dispatch = (event: ParityDomainEvent): void => {
    state = parityStateReducer(state, event)
    store.set(state)
  }

  const getState = (): ParityDomainState => state

  const reset = (): void => {
    stopListeners?.()
    stopListeners = null
    state = createInitialParityDomainState()
    store.set(state)
  }

  const init = async (source: ParityStoreEventSource = defaultEventSource): Promise<Unsubscribe> => {
    stopListeners?.()
    stopListeners = null

    dispatch({
      type: 'bridge.snapshot.received',
      snapshot: await source.getSnapshot(),
    })

    const unlistenSnapshot = await source.onSnapshot((snapshot) => {
      dispatch({ type: 'bridge.snapshot.received', snapshot })
    })

    // Stream and ui listeners feed the same reducer so App can consume one store.
    const unlistenTick = await source.onStreamTick((tick) => {
      dispatch({ type: 'bridge.stream.tick.received', tick })
    })

    const unlistenUi = await source.onUiEvent((event) => {
      dispatch({ type: 'bridge.ui.event.received', event })
    })

    stopListeners = () => {
      unlistenSnapshot()
      unlistenTick()
      unlistenUi()
    }

    return stopListeners
  }

  return {
    subscribe: store.subscribe,
    dispatch,
    getState,
    reset,
    init,
  }
}
