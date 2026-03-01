<script lang="ts">
  let {
    loginStep = 'credentials',
    loginUsername = $bindable(''),
    loginPassword = $bindable(''),
    twoFactorCode = $bindable(''),
    mailboxPassword = $bindable(''),
    fidoAssertionPayload = $bindable(''),
    loginStatus = '',
    onSubmitCredentials = () => {},
    onSubmitTwoFactor = () => {},
    onSubmitMailboxPassword = () => {},
    onSubmitFidoAssertion = () => {},
    onAbortFidoFlow = () => {},
    onAbortLoginFlow = () => {},
  }: {
    loginStep?: string
    loginUsername?: string
    loginPassword?: string
    twoFactorCode?: string
    mailboxPassword?: string
    fidoAssertionPayload?: string
    loginStatus?: string
    onSubmitCredentials?: () => void
    onSubmitTwoFactor?: () => void
    onSubmitMailboxPassword?: () => void
    onSubmitFidoAssertion?: () => void
    onAbortFidoFlow?: () => void
    onAbortLoginFlow?: () => void
  } = $props()

  const flowSteps = ['credentials', '2fa_or_fido', 'mailbox_password', 'done'] as const
  type FlowStep = (typeof flowSteps)[number]

  function normalizeFlowStep(step: string): FlowStep {
    if (step === '2fa' || step === 'fido' || step === 'fido_touch' || step === 'fido_pin') {
      return '2fa_or_fido'
    }
    if (step === 'mailbox_password') {
      return 'mailbox_password'
    }
    if (step === 'done') {
      return 'done'
    }
    return 'credentials'
  }

  function flowStepLabel(step: FlowStep): string {
    if (step === '2fa_or_fido') {
      return 'Verify'
    }
    if (step === 'mailbox_password') {
      return 'Unlock'
    }
    if (step === 'done') {
      return 'Ready'
    }
    return 'Sign In'
  }

  function flowHint(step: string): string {
    if (step === 'fido_touch') {
      return 'Touch your security key to continue.'
    }
    if (step === 'fido_pin') {
      return 'Enter your security key PIN.'
    }
    if (step === '2fa' || step === '2fa_or_fido' || step === 'fido') {
      return 'Complete account verification with 2FA code or FIDO assertion.'
    }
    if (step === 'mailbox_password') {
      return 'Provide mailbox password to unlock encrypted mail access.'
    }
    if (step === 'done') {
      return 'Authentication finished.'
    }
    return 'Enter Proton account credentials to start the login flow.'
  }
</script>

<article class="card">
  <h2>Login Flow</h2>
  <p class="muted"><strong>Current step:</strong> {loginStep}</p>
  <ol class="flow-stepper">
    {#each flowSteps as step}
      <li class:active={flowSteps.indexOf(step) === flowSteps.indexOf(normalizeFlowStep(loginStep))}>
        {flowStepLabel(step)}
      </li>
    {/each}
  </ol>
  <p class="muted flow-hint">{flowHint(loginStep)}</p>

  <div class="row wrap">
    <label>
      Username
      <input bind:value={loginUsername} placeholder="user@proton.me" />
    </label>
    <label>
      Password
      <input type="password" bind:value={loginPassword} placeholder="password" />
    </label>
    <button onclick={onSubmitCredentials}>Submit Credentials</button>
  </div>

  {#if loginStep === '2fa' || loginStep === '2fa_or_fido'}
    <div class="row wrap">
      <label>
        2FA Code
        <input bind:value={twoFactorCode} placeholder="123456" />
      </label>
      <button onclick={onSubmitTwoFactor}>Submit 2FA</button>
    </div>
  {/if}

  {#if loginStep === '2fa_or_fido'}
    <p class="muted">You can complete this step with either 2FA code or FIDO assertion.</p>
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
      <button class="secondary" onclick={onAbortFidoFlow}>Abort FIDO</button>
    </div>
  {/if}

  {#if loginStep === 'fido_touch'}
    <div class="row wrap">
      <p class="muted">Touch your security key to continue.</p>
      <button class="secondary" onclick={onAbortFidoFlow}>Abort FIDO</button>
    </div>
  {/if}

  {#if loginStep === 'mailbox_password'}
    <div class="row wrap">
      <label>
        Mailbox Password
        <input type="password" bind:value={mailboxPassword} placeholder="mailbox password" />
      </label>
      <button onclick={onSubmitMailboxPassword}>Submit Mailbox Password</button>
    </div>
  {/if}

  <div class="row">
    <button class="secondary" onclick={onAbortLoginFlow}>Abort Login</button>
  </div>
  <p class="muted">{loginStatus}</p>
</article>
