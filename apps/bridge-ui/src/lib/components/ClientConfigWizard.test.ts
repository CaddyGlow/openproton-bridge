import { fireEvent, render, screen } from '@testing-library/svelte'
import { describe, expect, it, vi } from 'vitest'
import ClientConfigWizard from './ClientConfigWizard.svelte'

describe('ClientConfigWizard', () => {
  it('routes apple mail selection through apple instructions to parameters', async () => {
    render(ClientConfigWizard, {
      props: {
        open: true,
        username: 'alice@proton.me',
        addresses: ['alice@proton.me'],
        hostname: '127.0.0.1',
        imapPort: '1143',
        smtpPort: '1025',
        password: 'bridge-pass',
      },
    })

    expect(screen.getByTestId('client-config-selector')).toBeInTheDocument()
    await fireEvent.click(screen.getByRole('button', { name: 'Apple Mail' }))
    expect(screen.getByTestId('client-config-apple-mail')).toBeInTheDocument()

    await fireEvent.click(screen.getByRole('button', { name: 'Continue' }))
    expect(screen.getByTestId('client-config-parameters')).toBeInTheDocument()
    expect(screen.getAllByText('bridge-pass').length).toBeGreaterThan(0)
  })

  it('completes non-apple flow and closes wizard', async () => {
    const onClose = vi.fn()
    render(ClientConfigWizard, {
      props: {
        open: true,
        username: 'alice@proton.me',
        addresses: ['alice@proton.me'],
        onClose,
      },
    })

    await fireEvent.click(screen.getByRole('button', { name: 'Other' }))
    expect(screen.getByTestId('client-config-parameters')).toBeInTheDocument()

    await fireEvent.click(screen.getByRole('button', { name: 'Done' }))
    expect(screen.getByTestId('client-config-done')).toBeInTheDocument()

    await fireEvent.click(screen.getByRole('button', { name: 'Close Wizard' }))
    expect(onClose).toHaveBeenCalledTimes(1)
  })
})
