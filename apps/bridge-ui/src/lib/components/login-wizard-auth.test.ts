import { describe, expect, it } from 'vitest'
import {
  loginStatusIndicatesPending,
  loginWizardStepTitle,
  resolveLoginWizardState,
  supportsFidoAlternative,
} from './login-wizard-auth'

describe('login-wizard-auth', () => {
  it('normalizes backend login steps into explicit wizard states', () => {
    expect(resolveLoginWizardState('credentials')).toBe('credentials')
    expect(resolveLoginWizardState('2fa')).toBe('2fa')
    expect(resolveLoginWizardState('2fa_or_fido')).toBe('2fa')
    expect(resolveLoginWizardState('fido')).toBe('fido')
    expect(resolveLoginWizardState('fido_touch')).toBe('fido_touch')
    expect(resolveLoginWizardState('fido_pin')).toBe('fido_pin')
    expect(resolveLoginWizardState('mailbox_password')).toBe('mailbox_password')
    expect(resolveLoginWizardState('done')).toBe('done')
    expect(resolveLoginWizardState('idle')).toBe('credentials')
  })

  it('reports pending status from login copy', () => {
    expect(loginStatusIndicatesPending('Signing in...')).toBe(true)
    expect(loginStatusIndicatesPending('submitting 2FA...')).toBe(true)
    expect(loginStatusIndicatesPending('aborting login...')).toBe(true)
    expect(loginStatusIndicatesPending('Login completed.')).toBe(false)
  })

  it('keeps FIDO alternative available for mixed challenge state', () => {
    expect(supportsFidoAlternative('2fa_or_fido', '2fa')).toBe(true)
    expect(supportsFidoAlternative('2fa', '2fa')).toBe(false)
  })

  it('returns state-specific titles', () => {
    expect(loginWizardStepTitle('2fa')).toBe('Two-Factor Authentication')
    expect(loginWizardStepTitle('fido_touch')).toBe('Security Key Touch')
    expect(loginWizardStepTitle('mailbox_password')).toBe('Unlock Mailbox')
  })
})
