<script lang="ts">
  let { events = [] }: { events?: string[] } = $props()
</script>

<article class="card span-2">
  <h2>Stream Events</h2>
  {#if events.length === 0}
    <p class="muted">No stream events yet. Click Connect to start event streaming.</p>
  {:else}
    <ul>
      {#each events as item}
        <li>{item}</li>
      {/each}
    </ul>
  {/if}
</article>
