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

  it('supports human verification continuation and close controls', async () => {
    const onSubmitCredentials = vi.fn()
    const onRetryCaptcha = vi.fn()
    const onOpenCaptchaWindow = vi.fn()
    const onCloseCaptchaWindow = vi.fn()

    render(LoginWizard, {
      props: {
        open: true,
        loginStep: 'credentials',
        hvVerificationUrl: 'https://verify.proton.me/challenge/example',
        hvCaptchaToken: 'pm-token',
        onSubmitCredentials,
        onRetryCaptcha,
        onOpenCaptchaWindow,
        onCloseCaptchaWindow,
      },
    })

    await fireEvent.click(screen.getByRole('button', { name: 'Open Verification Window' }))
    await fireEvent.click(screen.getByRole('button', { name: 'Close Verification Window' }))
    await fireEvent.click(screen.getByRole('button', { name: 'Continue Sign-In' }))
    await fireEvent.keyDown(window, { key: 'Enter' })

    expect(onOpenCaptchaWindow).toHaveBeenCalledTimes(1)
    expect(onCloseCaptchaWindow).toHaveBeenCalledTimes(1)
    expect(onRetryCaptcha).toHaveBeenCalledTimes(2)
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
