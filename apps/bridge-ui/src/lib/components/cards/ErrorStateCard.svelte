<script lang="ts">
  let {
    lastError = null,
    onClearError = () => {},
  }: {
    lastError?: string | null
    onClearError?: () => void
  } = $props()
</script>

<article class="card">
  <h2>Error State</h2>
  {#if lastError}
    <p class="error">{lastError}</p>
  {:else}
    <p class="muted">No active error.</p>
  {/if}

  <div class="row">
    <button class="secondary" onclick={onClearError}>Clear Error</button>
  </div>
</article>
