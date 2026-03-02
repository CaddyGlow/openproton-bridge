import { fireEvent, render, screen } from '@testing-library/svelte'
import { describe, expect, it, vi } from 'vitest'
import UsersCard from './UsersCard.svelte'

const users = [
  {
    id: 'u1',
    username: 'alex@proton.me',
    state: 1,
    split_mode: false,
    addresses: ['alex@proton.me'],
    used_bytes: 0,
    total_bytes: 0,
  },
]

describe('UsersCard', () => {
  it('renders sync progress parity hook when provided', () => {
    render(UsersCard, {
      props: {
        hostname: 'bridge.local',
        users,
        userParityById: {
          u1: {
            syncProgress: 42,
          },
        },
      },
    })

    expect(screen.getByText('Synchronizing (42%)')).toBeInTheDocument()
  })

  it('renders sync progress banner when syncing', () => {
    render(UsersCard, {
      props: {
        hostname: 'bridge.local',
        users,
        syncPhase: 'syncing',
        syncProgressPercent: 67,
        syncMessage: 'Synchronizing mailbox',
      },
    })

    const banner = screen.getByTestId('users-sync-progress')
    expect(banner).toBeInTheDocument()
    expect(screen.getByText(/Synchronizing\s*\(67%\)/)).toBeInTheDocument()
    expect(screen.getByRole('progressbar')).toHaveAttribute('aria-valuenow', '67')
    expect(screen.getByText('Synchronizing mailbox')).toBeInTheDocument()
  })

  it('renders disconnected and recovering parity hook states', () => {
    const { rerender } = render(UsersCard, {
      props: {
        hostname: 'bridge.local',
        users,
        userParityById: {
          u1: {
            disconnected: true,
          },
        },
      },
    })

    expect(screen.getByText('Disconnected')).toBeInTheDocument()

    rerender({
      hostname: 'bridge.local',
      users,
      userParityById: {
        u1: {
          recovering: true,
        },
      },
    })

    expect(screen.getByText('Recovering')).toBeInTheDocument()
  })

  it('renders error parity hook with message and takes precedence', () => {
    render(UsersCard, {
      props: {
        hostname: 'bridge.local',
        users,
        userParityById: {
          u1: {
            syncProgress: 88,
            recovering: true,
            disconnected: true,
            error: 'auth token expired',
          },
        },
      },
    })

    expect(screen.getByText('Error')).toBeInTheDocument()
    expect(screen.getByText('auth token expired')).toBeInTheDocument()
    expect(screen.queryByText('Synchronizing (88%)')).not.toBeInTheDocument()
  })

  it('triggers configure client callback from row action', async () => {
    const onConfigureClient = vi.fn()
    render(UsersCard, {
      props: {
        hostname: 'bridge.local',
        users,
        onConfigureClient,
      },
    })

    await fireEvent.click(screen.getByRole('button', { name: 'Configure Client' }))
    expect(onConfigureClient).toHaveBeenCalledWith('u1')
  })
})
