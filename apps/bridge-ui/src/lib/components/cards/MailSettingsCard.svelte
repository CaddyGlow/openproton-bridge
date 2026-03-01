<script lang="ts">
  let {
    imapPort = $bindable('1143'),
    smtpPort = $bindable('1025'),
    useSslImap = $bindable(false),
    useSslSmtp = $bindable(false),
    saveStatus = '',
    portToCheck = $bindable('1143'),
    portCheckResult = '',
    onSaveMailSettings = () => {},
    onCheckPort = () => {},
  }: {
    imapPort?: string
    smtpPort?: string
    useSslImap?: boolean
    useSslSmtp?: boolean
    saveStatus?: string
    portToCheck?: string
    portCheckResult?: string
    onSaveMailSettings?: () => void
    onCheckPort?: () => void
  } = $props()
</script>

<article class="card span-2">
  <h2>Mail Settings</h2>
  <div class="row wrap">
    <label>
      IMAP Port
      <input type="number" bind:value={imapPort} />
    </label>
    <label>
      SMTP Port
      <input type="number" bind:value={smtpPort} />
    </label>
    <label class="checkbox">
      <input type="checkbox" bind:checked={useSslImap} />
      SSL for IMAP
    </label>
    <label class="checkbox">
      <input type="checkbox" bind:checked={useSslSmtp} />
      SSL for SMTP
    </label>
  </div>
  <div class="row">
    <button onclick={onSaveMailSettings}>Save Mail Settings</button>
    <span class="muted">{saveStatus}</span>
  </div>
  <div class="row wrap">
    <label>
      Port Check
      <input type="number" bind:value={portToCheck} />
    </label>
    <button class="secondary" onclick={onCheckPort}>Check Port</button>
    <span class="muted">{portCheckResult}</span>
  </div>
</article>
