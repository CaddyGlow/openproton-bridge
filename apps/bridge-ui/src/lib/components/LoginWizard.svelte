<script lang="ts">
  type WizardStep = 'credentials' | 'verify' | 'unlock' | 'done'

  let {
    open = false,
    loginStep = 'credentials',
    loginStatus = '',
    loginUsername = $bindable(''),
    loginPassword = $bindable(''),
    twoFactorCode = $bindable(''),
    mailboxPassword = $bindable(''),
    fidoAssertionPayload = $bindable(''),
    onSubmitCredentials = () => {},
    onSubmitTwoFactor = () => {},
    onSubmitMailboxPassword = () => {},
    onSubmitFidoAssertion = () => {},
    onAbortFidoFlow = () => {},
    onAbortLoginFlow = () => {},
    onClose = () => {},
  }: {
    open?: boolean
    loginStep?: string
    loginStatus?: string
    loginUsername?: string
    loginPassword?: string
    twoFactorCode?: string
    mailboxPassword?: string
    fidoAssertionPayload?: string
    onSubmitCredentials?: () => void
    onSubmitTwoFactor?: () => void
    onSubmitMailboxPassword?: () => void
    onSubmitFidoAssertion?: () => void
    onAbortFidoFlow?: () => void
    onAbortLoginFlow?: () => void
    onClose?: () => void
  } = $props()

  function normalizeStep(step: string): WizardStep {
    if (step === '2fa' || step === '2fa_or_fido' || step === 'fido' || step === 'fido_touch' || step === 'fido_pin') {
      return 'verify'
    }
    if (step === 'mailbox_password') {
      return 'unlock'
    }
    if (step === 'done') {
      return 'done'
    }
    return 'credentials'
  }

  function stepTitle(step: WizardStep): string {
    if (step === 'verify') {
      return 'Verify Account'
    }
    if (step === 'unlock') {
      return 'Unlock Mailbox'
    }
    if (step === 'done') {
      return 'Login Complete'
    }
    return 'Account Credentials'
  }

  function stepHint(step: string): string {
    if (step === 'fido_touch') {
      return 'Touch your security key to continue.'
    }
    if (step === 'fido_pin') {
      return 'Enter your security key PIN.'
    }
    if (step === '2fa' || step === '2fa_or_fido' || step === 'fido') {
      return 'Use 2FA code or security key verification.'
    }
    if (step === 'mailbox_password') {
      return 'Decrypt mailbox data with your mailbox password.'
    }
    if (step === 'done') {
      return 'Your account is now authenticated.'
    }
    return 'Enter your Proton account username and password.'
  }
</script>

{#if open}
  <div class="wizard-backdrop" role="presentation">
    <div class="wizard-panel card" role="dialog" aria-modal="true" aria-label="Proton login wizard">
      <header class="wizard-header">
        <div>
          <h2>Sign In Wizard</h2>
          <p class="muted">Guided authentication flow for Proton account access.</p>
        </div>
        <button class="secondary" onclick={onClose}>Close</button>
      </header>

      <ol class="wizard-steps">
        <li class:active={normalizeStep(loginStep) === 'credentials'}>Credentials</li>
        <li class:active={normalizeStep(loginStep) === 'verify'}>Verify</li>
        <li class:active={normalizeStep(loginStep) === 'unlock'}>Unlock</li>
        <li class:active={normalizeStep(loginStep) === 'done'}>Done</li>
      </ol>

      <div class="wizard-body">
        <h3>{stepTitle(normalizeStep(loginStep))}</h3>
        <p class="muted">{stepHint(loginStep)}</p>

        {#if normalizeStep(loginStep) === 'credentials'}
          <div class="row wrap">
            <label class="grow">
              Username
              <input bind:value={loginUsername} placeholder="user@proton.me" />
            </label>
            <label class="grow">
              Password
              <input type="password" bind:value={loginPassword} placeholder="password" />
            </label>
          </div>
          <div class="row">
            <button onclick={onSubmitCredentials}>Continue</button>
          </div>
        {/if}

        {#if normalizeStep(loginStep) === 'verify'}
          {#if loginStep === '2fa' || loginStep === '2fa_or_fido'}
            <div class="row wrap">
              <label>
                2FA Code
                <input bind:value={twoFactorCode} placeholder="123456" />
              </label>
              <button onclick={onSubmitTwoFactor}>Submit 2FA</button>
            </div>
          {/if}

          {#if ['fido', '2fa_or_fido', 'fido_pin'].includes(loginStep)}
            <div class="row wrap">
              <label class="grow">
                {loginStep === 'fido_pin' ? 'FIDO PIN' : 'FIDO Assertion Payload'}
                <input
                  bind:value={fidoAssertionPayload}
                  type={loginStep === 'fido_pin' ? 'password' : 'text'}
                  placeholder={loginStep === 'fido_pin' ? 'enter security key PIN' : 'assertion payload'}
                />
              </label>
              <button onclick={onSubmitFidoAssertion}>Submit FIDO</button>
            </div>
          {/if}
        {/if}

        {#if normalizeStep(loginStep) === 'unlock'}
          <div class="row wrap">
            <label class="grow">
              Mailbox Password
              <input type="password" bind:value={mailboxPassword} placeholder="mailbox password" />
            </label>
            <button onclick={onSubmitMailboxPassword}>Unlock Mailbox</button>
          </div>
        {/if}

        {#if normalizeStep(loginStep) === 'done'}
          <div class="wizard-success">
            <p class="muted">Account authentication finished successfully.</p>
            <button onclick={onClose}>Close Wizard</button>
          </div>
        {/if}

        <p class="muted wizard-status">{loginStatus}</p>
      </div>

      {#if normalizeStep(loginStep) !== 'done'}
        <footer class="wizard-footer">
          {#if normalizeStep(loginStep) === 'verify'}
            <button class="secondary" onclick={onAbortFidoFlow}>Abort FIDO</button>
          {/if}
          <button class="secondary" onclick={onAbortLoginFlow}>Abort Login</button>
        </footer>
      {/if}
    </div>
  </div>
{/if}

<style>
  .wizard-backdrop {
    position: fixed;
    inset: 0;
    background: rgba(6, 12, 28, 0.56);
    display: grid;
    place-items: center;
    z-index: 1200;
    padding: 20px;
  }

  .wizard-panel {
    width: min(760px, 100%);
    max-height: calc(100vh - 40px);
    overflow: auto;
    display: grid;
    gap: 10px;
  }

  .wizard-header {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 10px;
  }

  .wizard-steps {
    margin: 0;
    padding: 0;
    list-style: none;
    display: grid;
    grid-template-columns: repeat(4, minmax(0, 1fr));
    gap: 6px;
  }

  .wizard-steps li {
    border: 1px solid var(--panel-border);
    border-radius: 999px;
    text-align: center;
    padding: 6px 8px;
    font-size: 0.76rem;
    color: var(--text-muted);
    background: var(--surface);
    font-weight: 600;
  }

  .wizard-steps li.active {
    border-color: var(--brand);
    background: var(--brand-soft);
    color: var(--text);
  }

  .wizard-body h3 {
    margin: 0 0 6px;
    font-size: 0.95rem;
  }

  .wizard-success {
    margin-top: 8px;
  }

  .wizard-status {
    margin-top: 8px;
  }

  .wizard-footer {
    display: flex;
    gap: 8px;
    justify-content: flex-end;
    flex-wrap: wrap;
  }
</style>
