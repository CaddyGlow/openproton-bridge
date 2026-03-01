<script lang="ts">
  import { onMount } from 'svelte'
  import { get } from 'svelte/store'
  import {
    bridgeStatus,
    connect,
    disconnect,
    fail,
    initBridgeStore,
    resetError,
    streamLog,
    updateConfigPath,
    updateLoginStep,
  } from './lib/stores/bridge'

  const steps = ['idle', 'credentials', '2fa', 'mailbox_password', 'done']

  let stop: (() => void) | undefined
  let configPathInput = ''

  onMount(() => {
    void (async () => {
      stop = await initBridgeStore()
      configPathInput = get(bridgeStatus).config_path ?? ''
    })()

    return () => stop?.()
  })
</script>

<main>
  <section class="card">
    <h1>OpenProton Bridge UI</h1>
    <p class="muted">Tauri + Svelte scaffold with Bun and Rust-side bridge adapter wiring.</p>
  </section>

  <section class="grid">
    <article class="card">
      <h2>Bridge Connection</h2>
      <div class="status-block">
        <p><strong>Connected:</strong> {$bridgeStatus.connected ? 'yes' : 'no'}</p>
        <p><strong>Stream:</strong> {$bridgeStatus.stream_running ? 'running' : 'stopped'}</p>
        <p><strong>Login Step:</strong> {$bridgeStatus.login_step}</p>
        <p><strong>Config Path:</strong> {$bridgeStatus.config_path ?? '(auto-resolve)'}</p>
      </div>

      <div class="row config-row">
        <input bind:value={configPathInput} placeholder="grpcServerConfig.json path (optional)" />
        <button class="secondary" on:click={() => updateConfigPath(configPathInput)}>Set Path</button>
      </div>

      <div class="row">
        <button on:click={() => connect()}>Connect</button>
        <button class="secondary" on:click={() => disconnect()}>Disconnect</button>
      </div>
    </article>

    <article class="card">
      <h2>Login Flow Mock</h2>
      <div class="row wrap">
        {#each steps as step}
          <button class="secondary" on:click={() => updateLoginStep(step)}>{step}</button>
        {/each}
      </div>
    </article>

    <article class="card">
      <h2>Error State</h2>
      {#if $bridgeStatus.last_error}
        <p class="error">{$bridgeStatus.last_error}</p>
      {:else}
        <p class="muted">No active error.</p>
      {/if}

      <div class="row">
        <button class="danger" on:click={() => fail('Simulated gRPC failure')}>Push Error</button>
        <button class="secondary" on:click={() => resetError()}>Clear Error</button>
      </div>
    </article>

    <article class="card span-2">
      <h2>Stream Events</h2>
      {#if $streamLog.length === 0}
        <p class="muted">No stream events yet. Click Connect to start mock ticks.</p>
      {:else}
        <ul>
          {#each $streamLog as item}
            <li>{item}</li>
          {/each}
        </ul>
      {/if}
    </article>
  </section>
</main>
