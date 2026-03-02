import { fireEvent, render, screen } from '@testing-library/svelte'
import { describe, expect, it, vi } from 'vitest'
import UsersCard from './UsersCard.svelte'

const users = [
  {
    id: 'u1',
    username: 'alex@proton.me',
    state: 2,
    split_mode: false,
    addresses: ['alex@proton.me'],
    used_bytes: 0,
    total_bytes: 0,
  },
  {
    id: 'u2',
    username: 'sam@proton.me',
    state: 2,
    split_mode: true,
    addresses: ['sam@proton.me'],
    used_bytes: 0,
    total_bytes: 0,
  },
]

describe('UsersCard', () => {
  it('renders only the selected sidebar user details', () => {
    render(UsersCard, {
      props: {
        hostname: '127.0.0.1',
        users,
        activeUserId: 'u2',
      },
    })

    expect(screen.getAllByText('sam@proton.me').length).toBeGreaterThan(0)
    expect(screen.queryByText('alex@proton.me')).not.toBeInTheDocument()
    expect(screen.getByText('Mailbox details')).toBeInTheDocument()
  })

  it('renders sync progress for the selected user', () => {
    render(UsersCard, {
      props: {
        hostname: '127.0.0.1',
        users,
        activeUserId: 'u1',
        userParityById: {
          u1: {
            syncProgress: 42,
          },
        },
      },
    })

    expect(screen.getByTestId('active-user-sync-status')).toHaveTextContent('Synchronizing (42%)...')
    expect(screen.getByRole('progressbar')).toHaveAttribute('aria-valuenow', '42')
  })

  it('fires configure callback from user details panel', async () => {
    const onConfigureClient = vi.fn()
    render(UsersCard, {
      props: {
        hostname: '127.0.0.1',
        users,
        activeUserId: 'u1',
        onConfigureClient,
      },
    })

    await fireEvent.click(screen.getByRole('button', { name: 'Configure email client' }))
    expect(onConfigureClient).toHaveBeenCalledWith('u1')
  })
})
