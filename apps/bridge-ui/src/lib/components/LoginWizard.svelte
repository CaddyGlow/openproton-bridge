<script lang="ts">
  type WizardStep = 'credentials' | 'verify' | 'unlock' | 'done'
  const stepOrder: WizardStep[] = ['credentials', 'verify', 'unlock', 'done']

  let {
    open = false,
    loginStep = 'credentials',
    loginStatus = '',
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
  let activeStep = $derived(normalizeStep(loginStep))

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

  function runEnterAction() {
    if (activeStep === 'credentials') {
      onSubmitCredentials()
      return
    }
    if (activeStep === 'unlock') {
      onSubmitMailboxPassword()
      return
    }
    if (activeStep === 'verify') {
      if (loginStep === '2fa' || loginStep === '2fa_or_fido') {
        onSubmitTwoFactor()
        return
      }
      if (loginStep === 'fido' || loginStep === 'fido_pin') {
        onSubmitFidoAssertion()
      }
    }
  }

  function handleWindowKeydown(event: KeyboardEvent) {
    if (!open) {
      return
    }
    if (event.key === 'Escape') {
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
      <div class="wizard-grid">
        <aside class="wizard-side">
          <div class="wizard-emblem">P</div>
          <p class="wizard-brand">OpenProton Mail Bridge</p>
          <div class="wizard-illustration" aria-hidden="true">
            {#if activeStep === 'credentials'}
              <svg viewBox="0 0 80 80">
                <rect x="14" y="20" width="52" height="40" rx="8" />
                <line x1="24" y1="34" x2="56" y2="34" />
                <circle cx="30" cy="46" r="4" />
                <line x1="38" y1="46" x2="54" y2="46" />
              </svg>
            {:else if activeStep === 'verify'}
              <svg viewBox="0 0 80 80">
                <path d="M40 14 62 22v18c0 15-9 24-22 28-13-4-22-13-22-28V22z" />
                <path d="m28 41 8 8 16-16" />
              </svg>
            {:else if activeStep === 'unlock'}
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
          <ol class="wizard-steps">
            {#each stepOrder as step}
              <li class:active={activeStep === step}>
                <span>{stepOrder.indexOf(step) + 1}</span>{stepTitle(step)}
              </li>
            {/each}
          </ol>
          <p class="muted wizard-step-hint">{stepHint(loginStep)}</p>
        </aside>

        <section class="wizard-main">
          <header class="wizard-header">
            <div>
              <h2>Sign In Wizard</h2>
              <p class="muted">{stepTitle(activeStep)}</p>
            </div>
            <button class="secondary" onclick={onClose}>Close</button>
          </header>

          <div class="wizard-body">
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
                <button onclick={onSubmitCredentials}>Continue</button>
              </div>
              {#if hvVerificationUrl}
                <div class="wizard-awaiting">
                  <p>Human verification required.</p>
                  <p class="muted">Complete CAPTCHA in the verification window, then retry login.</p>
                  <p class="muted break-anywhere">{hvVerificationUrl}</p>
                  <div class="wizard-actions">
                    <button onclick={onOpenCaptchaWindow}>Open CAPTCHA Window</button>
                    <button class="secondary" onclick={onCloseCaptchaWindow}>Close CAPTCHA Window</button>
                    <a class="button-like secondary" href={hvVerificationUrl} target="_blank" rel="noreferrer">
                      Open in Browser
                    </a>
                    <button onclick={onRetryCaptcha} disabled={!hvCaptchaToken}>Retry CAPTCHA</button>
                  </div>
                  <label class="wizard-token-field">
                    CAPTCHA token (optional)
                    <textarea
                      bind:value={hvCaptchaToken}
                      rows="3"
                      placeholder="Paste token here if webview capture is blocked"
                    ></textarea>
                  </label>
                  {#if hvCaptchaToken}
                    <p class="muted">CAPTCHA token captured ({hvCaptchaToken.length} chars).</p>
                  {:else}
                    <p class="muted">Waiting for `pm_captcha` token from verification window.</p>
                  {/if}
                </div>
              {/if}
            {/if}

            {#if activeStep === 'verify'}
              {#if loginStep === '2fa' || loginStep === '2fa_or_fido'}
                <div class="wizard-fields">
                  <label>
                    2FA Code
                    <input bind:value={twoFactorCode} inputmode="numeric" placeholder="123456" />
                  </label>
                  <button onclick={onSubmitTwoFactor}>Submit 2FA</button>
                </div>
              {/if}

              {#if ['fido', '2fa_or_fido', 'fido_pin'].includes(loginStep)}
                <div class="wizard-fields">
                  <label>
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

              {#if loginStep === 'fido_touch'}
                <div class="wizard-awaiting">
                  <p>Waiting for security key touch.</p>
                  <p class="muted">Keep your key connected and confirm touch when prompted.</p>
                </div>
              {/if}
            {/if}

            {#if activeStep === 'unlock'}
              <div class="wizard-fields">
                <label>
                  Mailbox Password
                  <input type="password" bind:value={mailboxPassword} placeholder="mailbox password" />
                </label>
                <button onclick={onSubmitMailboxPassword}>Unlock Mailbox</button>
              </div>
            {/if}

            {#if activeStep === 'done'}
              <div class="wizard-success">
                <p>Account authentication finished successfully.</p>
                <button onclick={onClose}>Close Wizard</button>
              </div>
            {/if}

            <p class="muted wizard-status">{loginStatus}</p>
          </div>

          {#if activeStep !== 'done'}
            <footer class="wizard-footer">
              {#if activeStep === 'verify'}
                <button class="secondary" onclick={onAbortFidoFlow}>Abort FIDO</button>
              {/if}
              <button class="secondary" onclick={onAbortLoginFlow}>Abort Login</button>
            </footer>
          {/if}
        </section>
      </div>
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
    width: min(880px, 100%);
    max-height: calc(100vh - 40px);
    overflow: auto;
    padding: 0;
  }

  .wizard-grid {
    display: grid;
    grid-template-columns: minmax(210px, 250px) minmax(0, 1fr);
    min-height: 440px;
  }

  .wizard-side {
    padding: 16px;
    border-right: 1px solid var(--panel-border);
    background: linear-gradient(165deg, color-mix(in oklab, var(--brand-soft) 60%, transparent), transparent 65%);
    display: grid;
    align-content: start;
    gap: 10px;
  }

  .wizard-emblem {
    width: 32px;
    height: 32px;
    border-radius: 8px;
    background: linear-gradient(130deg, var(--brand), var(--brand-2));
    color: #fff;
    display: grid;
    place-items: center;
    font-weight: 700;
    letter-spacing: 0.02em;
  }

  .wizard-brand {
    margin: 0;
    font-size: 0.78rem;
    font-weight: 600;
    color: var(--text-muted);
  }

  .wizard-illustration {
    border: 1px solid var(--panel-border);
    border-radius: 14px;
    background: color-mix(in oklab, var(--surface) 70%, transparent);
    padding: 8px;
    display: grid;
    place-items: center;
    min-height: 120px;
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
    padding: 14px;
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

  .wizard-steps {
    margin: 0;
    padding: 0;
    list-style: none;
    display: grid;
    gap: 5px;
  }

  .wizard-steps li {
    border-radius: 10px;
    text-align: left;
    padding: 7px 8px;
    font-size: 0.76rem;
    color: var(--text-muted);
    background: color-mix(in oklab, var(--surface) 70%, transparent);
    font-weight: 600;
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .wizard-steps span {
    display: inline-grid;
    place-items: center;
    width: 18px;
    height: 18px;
    border-radius: 50%;
    border: 1px solid var(--panel-border);
    font-size: 0.7rem;
  }

  .wizard-steps li.active {
    background: var(--brand-soft);
    color: var(--text);
  }

  .wizard-steps li.active span {
    border-color: var(--brand);
    background: color-mix(in oklab, var(--brand-soft) 30%, transparent);
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

  .wizard-token-field {
    margin-top: 8px;
    display: grid;
    gap: 6px;
    font-size: 0.84rem;
  }

  .button-like {
    text-decoration: none;
    display: inline-flex;
    align-items: center;
    justify-content: center;
  }

  .break-anywhere {
    overflow-wrap: anywhere;
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
    .wizard-grid {
      grid-template-columns: 1fr;
      min-height: auto;
    }

    .wizard-side {
      border-right: 0;
      border-bottom: 1px solid var(--panel-border);
    }
  }
</style>
