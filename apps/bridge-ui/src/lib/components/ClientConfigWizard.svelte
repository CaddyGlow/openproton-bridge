<script lang="ts">
  type ClientType = 'apple_mail' | 'outlook' | 'thunderbird' | 'other'
  type WizardStep = 'selector' | 'apple_mail' | 'parameters' | 'done'

  const clientOrder: ClientType[] = ['apple_mail', 'outlook', 'thunderbird', 'other']

  let {
    open = false,
    username = '',
    addresses = [],
    hostname = '127.0.0.1',
    imapPort = '1143',
    smtpPort = '1025',
    password = 'generated app password',
    onClose = () => {},
  }: {
    open?: boolean
    username?: string
    addresses?: string[]
    hostname?: string
    imapPort?: string
    smtpPort?: string
    password?: string
    onClose?: () => void
  } = $props()

  let step = $state<WizardStep>('selector')
  let selectedClient = $state<ClientType>('other')
  let previouslyOpen = $state(false)

  const selectedAddress = $derived(addresses[0] || username)

  $effect(() => {
    if (open && !previouslyOpen) {
      step = 'selector'
      selectedClient = 'other'
    }
    previouslyOpen = open
  })

  function clientLabel(client: ClientType): string {
    if (client === 'apple_mail') {
      return 'Apple Mail'
    }
    if (client === 'outlook') {
      return 'Microsoft Outlook'
    }
    if (client === 'thunderbird') {
      return 'Mozilla Thunderbird'
    }
    return 'Other'
  }

  function chooseClient(client: ClientType) {
    selectedClient = client
    step = client === 'apple_mail' ? 'apple_mail' : 'parameters'
  }

  function continueFromAppleMail() {
    step = 'parameters'
  }

  function back() {
    if (step === 'done') {
      step = 'parameters'
      return
    }
    if (step === 'parameters') {
      step = selectedClient === 'apple_mail' ? 'apple_mail' : 'selector'
      return
    }
    if (step === 'apple_mail') {
      step = 'selector'
    }
  }

  function finish() {
    step = 'done'
  }

  function handleWindowKeydown(event: KeyboardEvent) {
    if (!open) {
      return
    }
    if (event.key === 'Escape') {
      onClose()
    }
  }
</script>

<svelte:window onkeydown={handleWindowKeydown} />

{#if open}
  <div class="client-config-backdrop" role="presentation">
    <div class="client-config-panel card" role="dialog" aria-modal="true" aria-label="Client configuration wizard">
      <header class="client-config-header">
        <div>
          <h2>Configure Email Client</h2>
          <p class="muted">Account: {username || '(no account selected)'}</p>
        </div>
        <button class="secondary" onclick={onClose}>Close</button>
      </header>

      {#if step === 'selector'}
        <div class="client-config-body" data-testid="client-config-selector">
          <p class="muted">Select your email client to show setup instructions and parameters.</p>
          <div class="client-options">
            {#each clientOrder as client}
              <button class="secondary client-option" onclick={() => chooseClient(client)}>
                {clientLabel(client)}
              </button>
            {/each}
          </div>
          <div class="row">
            <button class="secondary" onclick={onClose}>Setup later</button>
          </div>
        </div>
      {:else if step === 'apple_mail'}
        <div class="client-config-body" data-testid="client-config-apple-mail">
          <h3>Apple Mail Setup</h3>
          <p class="muted">
            Apple Mail can be configured automatically for many accounts. If auto-setup is unavailable, continue to manual
            parameters.
          </p>
          <ul>
            <li>Open Apple Mail and choose Add Account.</li>
            <li>Select Proton Bridge generated account settings.</li>
            <li>If prompted, use the parameters from the next step.</li>
          </ul>
          <div class="row">
            <button class="secondary" onclick={back}>Back</button>
            <button onclick={continueFromAppleMail}>Continue</button>
          </div>
        </div>
      {:else if step === 'parameters'}
        <div class="client-config-body" data-testid="client-config-parameters">
          <h3>Client Parameters</h3>
          <p class="muted">Use these values in {clientLabel(selectedClient)}.</p>

          <div class="parameter-grid">
            <article class="parameter-card">
              <h4>IMAP</h4>
              <p><strong>Hostname</strong> {hostname}</p>
              <p><strong>Port</strong> {imapPort}</p>
              <p><strong>Username</strong> {selectedAddress}</p>
              <p><strong>Password</strong> {password}</p>
              <p><strong>Security</strong> STARTTLS</p>
            </article>

            <article class="parameter-card">
              <h4>SMTP</h4>
              <p><strong>Hostname</strong> {hostname}</p>
              <p><strong>Port</strong> {smtpPort}</p>
              <p><strong>Username</strong> {selectedAddress}</p>
              <p><strong>Password</strong> {password}</p>
              <p><strong>Security</strong> STARTTLS</p>
            </article>
          </div>

          <div class="row">
            <button class="secondary" onclick={back}>Back</button>
            <button onclick={finish}>Done</button>
          </div>
        </div>
      {:else}
        <div class="client-config-body" data-testid="client-config-done">
          <h3>Configuration Ready</h3>
          <p class="muted">Your client parameters are ready. Finish setup in your selected email client.</p>
          <div class="row">
            <button class="secondary" onclick={back}>Back</button>
            <button onclick={onClose}>Close Wizard</button>
          </div>
        </div>
      {/if}
    </div>
  </div>
{/if}

<style>
  .client-config-backdrop {
    position: fixed;
    inset: 0;
    background: rgba(8, 14, 30, 0.54);
    display: grid;
    place-items: center;
    z-index: 1190;
    padding: 18px;
  }

  .client-config-panel {
    width: min(920px, 100%);
    max-height: calc(100vh - 36px);
    overflow: auto;
    padding: 12px;
    display: grid;
    gap: 10px;
  }

  .client-config-header {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    gap: 12px;
  }

  .client-config-body {
    display: grid;
    gap: 10px;
  }

  .client-options {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 8px;
  }

  .client-option {
    min-height: 42px;
    text-align: left;
  }

  .parameter-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
    gap: 8px;
  }

  .parameter-card {
    border: 1px solid var(--panel-border);
    border-radius: 10px;
    padding: 10px;
    background: color-mix(in oklab, var(--surface) 84%, transparent);
  }

  .parameter-card h4 {
    margin: 0 0 8px;
    color: var(--text);
  }

  .parameter-card p {
    margin: 5px 0;
    font-size: 0.84rem;
  }
</style>
