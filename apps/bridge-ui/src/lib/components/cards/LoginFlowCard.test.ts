import { fireEvent, render, screen } from '@testing-library/svelte'
import { describe, expect, it, vi } from 'vitest'
import LoginFlowCard from './LoginFlowCard.svelte'

describe('LoginFlowCard', () => {
  it('renders both 2FA and FIDO inputs for the mixed step', () => {
    render(LoginFlowCard, {
      props: {
        loginStep: '2fa_or_fido',
      },
    })

    expect(screen.getByPlaceholderText('123456')).toBeInTheDocument()
    expect(screen.getByPlaceholderText('assertion payload')).toBeInTheDocument()
    expect(
      screen.getByText('You can complete this step with either 2FA code or FIDO assertion.'),
    ).toBeInTheDocument()
  })

  it('renders a touch prompt during fido_touch and triggers abort callback', async () => {
    const onAbortFidoFlow = vi.fn()
    render(LoginFlowCard, {
      props: {
        loginStep: 'fido_touch',
        onAbortFidoFlow,
      },
    })

    expect(screen.getAllByText('Touch your security key to continue.').length).toBeGreaterThan(0)
    await fireEvent.click(screen.getByRole('button', { name: 'Abort FIDO' }))
    expect(onAbortFidoFlow).toHaveBeenCalledTimes(1)
  })

  it('uses a password input when login step requires fido pin', () => {
    render(LoginFlowCard, {
      props: {
        loginStep: 'fido_pin',
      },
    })

    const pinInput = screen.getByPlaceholderText('enter security key PIN')
    expect(pinInput).toHaveAttribute('type', 'password')
  })

  it('calls submit credentials callback', async () => {
    const onSubmitCredentials = vi.fn()
    render(LoginFlowCard, {
      props: {
        loginStep: 'credentials',
        onSubmitCredentials,
      },
    })

    await fireEvent.click(screen.getByRole('button', { name: 'Submit Credentials' }))
    expect(onSubmitCredentials).toHaveBeenCalledTimes(1)
  })
})
