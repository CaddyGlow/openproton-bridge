import { fireEvent, render, screen } from '@testing-library/svelte'
import { describe, expect, it, vi } from 'vitest'
import BridgeConnectionCard from './BridgeConnectionCard.svelte'

const status = {
  connected: false,
  stream_running: false,
  login_step: 'credentials',
  last_error: null,
  config_path: null,
}

describe('BridgeConnectionCard', () => {
  it('shows bridge status', () => {
    render(BridgeConnectionCard, {
      props: {
        status,
      },
    })

    expect(screen.getByText('Connected:')).toBeInTheDocument()
    expect(screen.getByText('Stream:')).toBeInTheDocument()
    expect(screen.getByText('Login Step:')).toBeInTheDocument()
  })

  it('calls callbacks for connect, disconnect and set path', async () => {
    const onConnect = vi.fn()
    const onDisconnect = vi.fn()
    const onSetPath = vi.fn()

    render(BridgeConnectionCard, {
      props: {
        status,
        configPathInput: '',
        onConnect,
        onDisconnect,
        onSetPath,
      },
    })

    const input = screen.getByPlaceholderText('grpcServerConfig.json path (optional)')
    await fireEvent.input(input, { target: { value: '/tmp/grpcServerConfig.json' } })
    await fireEvent.click(screen.getByRole('button', { name: 'Set Path' }))
    await fireEvent.click(screen.getByRole('button', { name: 'Connect' }))
    await fireEvent.click(screen.getByRole('button', { name: 'Disconnect' }))

    expect(onSetPath).toHaveBeenCalledWith('/tmp/grpcServerConfig.json')
    expect(onConnect).toHaveBeenCalledTimes(1)
    expect(onDisconnect).toHaveBeenCalledTimes(1)
  })
})
