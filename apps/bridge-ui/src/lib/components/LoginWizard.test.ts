import { fireEvent, render, screen } from '@testing-library/svelte'
import { describe, expect, it, vi } from 'vitest'
import LoginWizard from './LoginWizard.svelte'

describe('LoginWizard', () => {
  it('renders credential step and triggers continue callback', async () => {
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

  it('renders verify step for fido touch and allows abort', async () => {
    const onAbortLoginFlow = vi.fn()
    render(LoginWizard, {
      props: {
        open: true,
        loginStep: 'fido_touch',
        onAbortLoginFlow,
      },
    })

    expect(screen.getAllByText('Verify Account').length).toBeGreaterThan(0)
    expect(screen.getAllByText('Touch your security key to continue.').length).toBeGreaterThan(0)
    await fireEvent.click(screen.getByRole('button', { name: 'Abort Login' }))
    expect(onAbortLoginFlow).toHaveBeenCalledTimes(1)
  })
})
