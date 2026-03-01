<script lang="ts">
  let {
    tlsInstalled = null,
    tlsExportDir = $bindable(''),
    tlsStatus = '',
    onInstallTls = () => {},
    onExportTls = () => {},
  }: {
    tlsInstalled?: boolean | null
    tlsExportDir?: string
    tlsStatus?: string
    onInstallTls?: () => void
    onExportTls?: () => void
  } = $props()
</script>

<article class="card span-2">
  <h2>TLS Settings</h2>
  <p class="muted">
    <strong>Certificate installed:</strong>
    {#if tlsInstalled === null}
      (unknown)
    {:else if tlsInstalled}
      yes
    {:else}
      no
    {/if}
  </p>
  <div class="row">
    <button onclick={onInstallTls}>Install TLS Certificate</button>
  </div>
  <div class="row wrap">
    <label>
      Export Directory
      <input bind:value={tlsExportDir} placeholder="/tmp/bridge-certs" />
    </label>
    <button class="secondary" onclick={onExportTls}>Export TLS Certificates</button>
  </div>
  <p class="muted">{tlsStatus}</p>
</article>
