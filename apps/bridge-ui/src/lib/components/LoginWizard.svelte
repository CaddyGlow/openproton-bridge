<script lang="ts">
  import {
    isFidoAbortAvailable,
    loginStatusIndicatesPending,
    loginWizardStepHint,
    loginWizardStepTitle,
    resolveLoginWizardState,
    supportsFidoAlternative,
  } from './login-wizard-auth'

  let {
    open = false,
    loginStep = 'credentials',
    loginStatus = '',
    canClose = true,
    isBusy: isBusyProp,
    loginUsername = $bindable(''),
    loginPassword = $bindable(''),
    twoFactorCode = $bindable(''),
    mailboxPassword = $bindable(''),
    fidoAssertionPayload = $bindable(''),
    hvVerificationUrl = '',
    hvCaptchaToken = $bindable(''),
    onSubmitCredentials = () => {},
    onOpenCaptchaWindow = () => {},
    onCloseCaptchaWindow = () => {},
    onRetryCaptcha = () => {},
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
    canClose?: boolean
    isBusy?: boolean
    loginUsername?: string
    loginPassword?: string
    twoFactorCode?: string
    mailboxPassword?: string
    fidoAssertionPayload?: string
    hvVerificationUrl?: string
    hvCaptchaToken?: string
    onSubmitCredentials?: () => void
    onOpenCaptchaWindow?: () => void
    onCloseCaptchaWindow?: () => void
    onRetryCaptcha?: () => void
    onSubmitTwoFactor?: () => void
    onSubmitMailboxPassword?: () => void
    onSubmitFidoAssertion?: () => void
    onAbortFidoFlow?: () => void
    onAbortLoginFlow?: () => void
    onClose?: () => void
  } = $props()
  const activeStep = $derived(resolveLoginWizardState(loginStep))
  const statusIndicatesPending = $derived(loginStatusIndicatesPending(loginStatus))
  const isBusy = $derived(isBusyProp ?? statusIndicatesPending)
  const hasHumanVerification = $derived(Boolean(hvVerificationUrl))
  const hasCaptchaToken = $derived(Boolean(hvCaptchaToken))
  const canContinueHumanVerification = $derived(hasHumanVerification && hasCaptchaToken && !isBusy)
  const showFidoAbort = $derived(isFidoAbortAvailable(activeStep, loginStep))
  const showFidoInput = $derived(supportsFidoAlternative(loginStep, activeStep))
  const expectsFidoPin = $derived(activeStep === 'fido_pin')

  function runEnterAction() {
    if (isBusy) {
      return
    }

    if (activeStep === 'credentials') {
      if (hasHumanVerification) {
        if (hasCaptchaToken) {
          onRetryCaptcha()
          return
        }
        onOpenCaptchaWindow()
        return
      }
      onSubmitCredentials()
      return
    }

    if (activeStep === 'mailbox_password') {
      onSubmitMailboxPassword()
      return
    }

    if (activeStep === '2fa') {
      onSubmitTwoFactor()
      return
    }

    if (activeStep === 'fido' || activeStep === 'fido_pin') {
      onSubmitFidoAssertion()
    }
  }

  function handleWindowKeydown(event: KeyboardEvent) {
    if (!open) {
      return
    }
    if (event.key === 'Escape' && canClose) {
      onClose()
      return
    }
    if (event.key !== 'Enter') {
      return
    }
    const target = event.target as HTMLElement | null
    if (target?.tagName === 'TEXTAREA') {
      return
    }
    event.preventDefault()
    runEnterAction()
  }
</script>

<svelte:window onkeydown={handleWindowKeydown} />

{#if open}
  <div class="wizard-backdrop" role="presentation">
    <div class="wizard-panel card" role="dialog" aria-modal="true" aria-label="Proton login wizard">
      <section class="wizard-main">
        <header class="wizard-header">
          <div>
            <p class="wizard-brand">OpenProton Mail Bridge</p>
            <h2>Sign In Wizard</h2>
            <p class="muted">{loginWizardStepTitle(activeStep)}</p>
          </div>
          {#if canClose}
            <button class="secondary" onclick={onClose}>Close</button>
          {/if}
        </header>

        <p class="muted wizard-step-hint">{loginWizardStepHint(loginStep, activeStep)}</p>

        <div class="wizard-body" aria-busy={isBusy}>
          <div class="wizard-illustration" aria-hidden="true">
            {#if activeStep === 'credentials'}
              <svg viewBox="0 0 80 80">
                <rect x="14" y="20" width="52" height="40" rx="8" />
                <line x1="24" y1="34" x2="56" y2="34" />
                <circle cx="30" cy="46" r="4" />
                <line x1="38" y1="46" x2="54" y2="46" />
              </svg>
            {:else if activeStep === '2fa' || activeStep === 'fido' || activeStep === 'fido_touch' || activeStep === 'fido_pin'}
              <svg viewBox="0 0 80 80">
                <path d="M40 14 62 22v18c0 15-9 24-22 28-13-4-22-13-22-28V22z" />
                <path d="m28 41 8 8 16-16" />
              </svg>
            {:else if activeStep === 'mailbox_password'}
              <svg viewBox="0 0 80 80">
                <rect x="18" y="34" width="44" height="28" rx="7" />
                <path d="M28 34v-6a12 12 0 1 1 24 0v6" />
                <circle cx="40" cy="48" r="4" />
              </svg>
            {:else}
              <svg viewBox="0 0 80 80">
                <circle cx="40" cy="40" r="26" />
                <path d="m28 40 8 9 16-18" />
              </svg>
            {/if}
          </div>

            {#if activeStep === 'credentials'}
              <div class="wizard-fields">
                <label>
                  Username
                  <input bind:value={loginUsername} autocomplete="username" placeholder="user@proton.me" />
                </label>
                <label>
                  Password
                  <input type="password" bind:value={loginPassword} autocomplete="current-password" placeholder="password" />
                </label>
                <button onclick={onSubmitCredentials} disabled={isBusy || hasHumanVerification}>
                  {isBusy ? 'Working...' : hasHumanVerification ? 'Pending Verification' : 'Continue'}
                </button>
              </div>
              {#if hasHumanVerification}
                <div class="wizard-awaiting">
                  <p>Human verification required.</p>
                  <p class="muted">Open the verification window, complete CAPTCHA, then continue sign-in.</p>
                  <div class="wizard-actions">
                    <button onclick={onOpenCaptchaWindow} disabled={isBusy}>Open Verification Window</button>
                    <button class="secondary" onclick={onCloseCaptchaWindow} disabled={isBusy}>
                      Close Verification Window
                    </button>
                    <button onclick={onRetryCaptcha} disabled={!canContinueHumanVerification}>Continue Sign-In</button>
                  </div>
                  {#if hasCaptchaToken}
                    <p class="muted">Verification token received. Continue sign-in when ready.</p>
                  {:else}
                    <p class="muted">Waiting for verification to complete.</p>
                  {/if}
                </div>
              {/if}
            {/if}

            {#if activeStep === '2fa'}
              <div class="wizard-fields">
                <label>
                  2FA Code
                  <input bind:value={twoFactorCode} inputmode="numeric" placeholder="123456" />
                </label>
                <button onclick={onSubmitTwoFactor} disabled={isBusy}>Submit 2FA</button>
              </div>

              {#if loginStep === '2fa_or_fido'}
                <p class="muted">You can also use your security key for this step.</p>
              {/if}
            {/if}

            {#if showFidoInput && (activeStep === '2fa' || activeStep === 'fido' || activeStep === 'fido_pin')}
              <div class="wizard-fields">
                <label>
                  {expectsFidoPin ? 'FIDO PIN' : 'FIDO Assertion Payload'}
                  <input
                    bind:value={fidoAssertionPayload}
                    type={expectsFidoPin ? 'password' : 'text'}
                    placeholder={expectsFidoPin ? 'enter security key PIN' : 'assertion payload'}
                  />
                </label>
                <button onclick={onSubmitFidoAssertion} disabled={isBusy}>
                  {expectsFidoPin ? 'Submit PIN' : 'Submit FIDO'}
                </button>
              </div>
            {/if}

            {#if activeStep === 'fido_touch'}
              <div class="wizard-awaiting">
                <p>Waiting for security key touch.</p>
                <p class="muted">Keep your key connected and confirm touch when prompted.</p>
              </div>
            {/if}

            {#if activeStep === 'mailbox_password'}
              <div class="wizard-fields">
                <label>
                  Mailbox Password
                  <input type="password" bind:value={mailboxPassword} placeholder="mailbox password" />
                </label>
                <button onclick={onSubmitMailboxPassword} disabled={isBusy}>Unlock Mailbox</button>
              </div>
            {/if}

            {#if activeStep === 'done'}
              <div class="wizard-success">
                <p>Account authentication finished successfully.</p>
                {#if canClose}
                  <button onclick={onClose}>Close Wizard</button>
                {/if}
              </div>
            {/if}

            <p class="muted wizard-status">{loginStatus}</p>
        </div>

        {#if activeStep !== 'done'}
          <footer class="wizard-footer">
            {#if showFidoAbort}
              <button class="secondary" onclick={onAbortFidoFlow}>Abort FIDO</button>
            {/if}
            <button class="secondary" onclick={onAbortLoginFlow}>Abort Login</button>
          </footer>
        {/if}
      </section>
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
    width: min(560px, 100%);
    max-height: calc(100vh - 40px);
    overflow: auto;
    padding: 14px;
  }

  .wizard-brand {
    margin: 0 0 2px;
    font-size: 0.74rem;
    font-weight: 700;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    color: var(--text-muted);
  }

  .wizard-illustration {
    margin-bottom: 2px;
    border: 1px solid var(--panel-border);
    border-radius: 14px;
    background: color-mix(in oklab, var(--surface) 70%, transparent);
    padding: 8px;
    display: grid;
    place-items: center;
    min-height: 90px;
  }

  .wizard-illustration svg {
    width: min(130px, 100%);
    height: auto;
    fill: none;
    stroke: color-mix(in oklab, var(--brand) 70%, var(--text));
    stroke-width: 3;
    stroke-linecap: round;
    stroke-linejoin: round;
  }

  .wizard-main {
    display: grid;
    gap: 10px;
    align-content: start;
  }

  .wizard-header {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 8px;
  }

  .wizard-step-hint {
    margin: 0;
    font-size: 0.77rem;
    line-height: 1.35;
  }

  .wizard-body {
    display: grid;
    gap: 10px;
  }

  .wizard-fields {
    display: grid;
    gap: 8px;
    max-width: 420px;
  }

  .wizard-fields button {
    width: fit-content;
  }

  .wizard-awaiting {
    border: 1px dashed var(--panel-border);
    border-radius: 10px;
    padding: 10px;
    max-width: 460px;
    background: color-mix(in oklab, var(--surface) 70%, transparent);
  }

  .wizard-awaiting p {
    margin: 0;
    font-size: 0.84rem;
  }

  .wizard-actions {
    margin-top: 8px;
    display: flex;
    gap: 8px;
    flex-wrap: wrap;
  }

  .wizard-success {
    margin-top: 2px;
    display: grid;
    gap: 8px;
  }

  .wizard-success p {
    margin: 0;
  }

  .wizard-status {
    margin-top: 2px;
    min-height: 18px;
  }

  .wizard-footer {
    display: flex;
    gap: 8px;
    justify-content: flex-end;
    flex-wrap: wrap;
  }

  @media (max-width: 760px) {
    .wizard-panel {
      padding: 12px;
    }
  }
</style>
