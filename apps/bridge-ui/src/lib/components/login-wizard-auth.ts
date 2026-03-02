export const loginWizardStateOrder = [
  'credentials',
  '2fa',
  'fido',
  'fido_touch',
  'fido_pin',
  'mailbox_password',
  'done',
] as const

export type LoginWizardState = (typeof loginWizardStateOrder)[number]

export function resolveLoginWizardState(step: string): LoginWizardState {
  switch (step) {
    case '2fa':
    case '2fa_or_fido':
      return '2fa'
    case 'fido':
    case 'fido_touch':
    case 'fido_pin':
    case 'mailbox_password':
    case 'done':
      return step
    case 'credentials':
    case 'idle':
    default:
      return 'credentials'
  }
}

export function loginWizardStepTitle(step: LoginWizardState): string {
  switch (step) {
    case '2fa':
      return 'Two-Factor Authentication'
    case 'fido':
      return 'Security Key Verification'
    case 'fido_touch':
      return 'Security Key Touch'
    case 'fido_pin':
      return 'Security Key PIN'
    case 'mailbox_password':
      return 'Unlock Mailbox'
    case 'done':
      return 'Login Complete'
    default:
      return 'Account Credentials'
  }
}

export function loginWizardStepHint(step: string, state: LoginWizardState): string {
  if (state === 'fido_touch') {
    return 'Touch your security key to continue.'
  }
  if (state === 'fido_pin') {
    return 'Enter the PIN for your security key.'
  }
  if (state === 'fido') {
    return 'Complete security key verification with your assertion payload.'
  }
  if (state === '2fa') {
    if (step === '2fa_or_fido') {
      return 'Use a 2FA code or continue with your security key.'
    }
    return 'Enter your 2FA code to verify your account.'
  }
  if (state === 'mailbox_password') {
    return 'Decrypt mailbox data with your mailbox password.'
  }
  if (state === 'done') {
    return 'Your account is now authenticated.'
  }
  return 'Enter your Proton account username and password.'
}

export function loginStatusIndicatesPending(status: string): boolean {
  const normalized = status.trim().toLowerCase()
  if (!normalized) {
    return false
  }

  if (normalized.endsWith('...')) {
    return true
  }

  return (
    normalized.includes('signing in') ||
    normalized.includes('submitting') ||
    normalized.includes('loading') ||
    normalized.includes('aborting') ||
    normalized.includes('continuing sign-in')
  )
}

export function isFidoAbortAvailable(state: LoginWizardState, rawStep: string): boolean {
  return state === 'fido' || state === 'fido_touch' || state === 'fido_pin' || rawStep === '2fa_or_fido'
}

export function supportsFidoAlternative(rawStep: string, state: LoginWizardState): boolean {
  return rawStep === '2fa_or_fido' || state === 'fido' || state === 'fido_pin'
}
