import { fireEvent, render, screen } from '@testing-library/svelte'
import { describe, expect, it, vi } from 'vitest'
import LoginWizard from './LoginWizard.svelte'

describe('LoginWizard', () => {
  it('renders credentials state and submits credentials by default', async () => {
    const onSubmitCredentials = vi.fn()
    render(LoginWizard, {
      props: {
        open: true,
        loginStep: 'credentials',
        onSubmitCredentials,
      },
    })

    expect(screen.getByText('Sign In Wizard')).toBeInTheDocument()
    expect(screen.getAllByText('Account Credentials').length).toBeGreaterThan(0)

    await fireEvent.click(screen.getByRole('button', { name: 'Continue' }))
    expect(onSubmitCredentials).toHaveBeenCalledTimes(1)
  })

  it('submits 2FA when pressing Enter in 2fa state', async () => {
    const onSubmitTwoFactor = vi.fn()
    const onSubmitCredentials = vi.fn()

    render(LoginWizard, {
      props: {
        open: true,
        loginStep: '2fa',
        onSubmitTwoFactor,
        onSubmitCredentials,
      },
    })

    expect(screen.getByRole('button', { name: 'Submit 2FA' })).toBeInTheDocument()

    await fireEvent.keyDown(window, { key: 'Enter' })

    expect(onSubmitTwoFactor).toHaveBeenCalledTimes(1)
    expect(onSubmitCredentials).not.toHaveBeenCalled()
  })

  it('renders fido touch state and aborts only fido flow when requested', async () => {
    const onAbortFidoFlow = vi.fn()
    const onAbortLoginFlow = vi.fn()

    render(LoginWizard, {
      props: {
        open: true,
        loginStep: 'fido_touch',
        onAbortFidoFlow,
        onAbortLoginFlow,
      },
    })

    expect(screen.getAllByText('Touch your security key to continue.').length).toBeGreaterThan(0)

    await fireEvent.click(screen.getByRole('button', { name: 'Abort FIDO' }))

    expect(onAbortFidoFlow).toHaveBeenCalledTimes(1)
    expect(onAbortLoginFlow).toHaveBeenCalledTimes(0)
  })

  it('treats fido pin as sensitive input and submits assertion on Enter', async () => {
    const onSubmitFidoAssertion = vi.fn()

    render(LoginWizard, {
      props: {
        open: true,
        loginStep: 'fido_pin',
        onSubmitFidoAssertion,
      },
    })

    const pinInput = screen.getByPlaceholderText('enter security key PIN')
    expect(pinInput).toHaveAttribute('type', 'password')

    await fireEvent.keyDown(window, { key: 'Enter' })

    expect(onSubmitFidoAssertion).toHaveBeenCalledTimes(1)
  })

  it('shows automatic human verification state without manual action buttons', async () => {
    const onSubmitCredentials = vi.fn()

    render(LoginWizard, {
      props: {
        open: true,
        loginStep: 'credentials',
        hvVerificationUrl: 'https://verify.proton.me/challenge/example',
        onSubmitCredentials,
      },
    })

    await fireEvent.keyDown(window, { key: 'Enter' })

    expect(screen.queryByRole('button', { name: 'Open Verification Window' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Close Verification Window' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Continue Sign-In' })).not.toBeInTheDocument()
    expect(onSubmitCredentials).not.toHaveBeenCalled()
  })

  it('shows loading affordance in credentials state while action is pending', () => {
    render(LoginWizard, {
      props: {
        open: true,
        loginStep: 'credentials',
        loginStatus: 'Signing in...',
      },
    })

    expect(screen.getByRole('button', { name: 'Working...' })).toBeDisabled()
  })

  it('allows aborting entire login flow', async () => {
    const onAbortLoginFlow = vi.fn()
    render(LoginWizard, {
      props: {
        open: true,
        loginStep: '2fa',
        onAbortLoginFlow,
      },
    })

    await fireEvent.click(screen.getByRole('button', { name: 'Abort Login' }))
    expect(onAbortLoginFlow).toHaveBeenCalledTimes(1)
  })
})
