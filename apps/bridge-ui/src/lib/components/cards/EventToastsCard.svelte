<script lang="ts">
  let { toasts = [] }: { toasts?: string[] } = $props()
</script>

<article class="card span-2">
  <h2>Event Toasts</h2>
  {#if toasts.length === 0}
    <p class="muted">No toasts yet.</p>
  {:else}
    <ul>
      {#each toasts as toast}
        <li>{toast}</li>
      {/each}
    </ul>
  {/if}
</article>
