<script lang="ts">
  import type { BridgeSnapshot } from '../../api/bridge'

  let {
    status,
    configPathInput = $bindable(''),
    onSetPath = (_path: string) => {},
    onConnect = () => {},
    onDisconnect = () => {},
  }: {
    status: BridgeSnapshot
    configPathInput?: string
    onSetPath?: (path: string) => void
    onConnect?: () => void
    onDisconnect?: () => void
  } = $props()
</script>

<article class="card">
  <h2>Bridge Connection</h2>
  <div class="status-block">
    <p><strong>Connected:</strong> {status.connected ? 'yes' : 'no'}</p>
    <p><strong>Stream:</strong> {status.stream_running ? 'running' : 'stopped'}</p>
    <p><strong>Login Step:</strong> {status.login_step}</p>
    <p><strong>Config Path:</strong> {status.config_path ?? '(auto-resolve)'}</p>
  </div>

  <div class="row config-row">
    <input bind:value={configPathInput} placeholder="grpcServerConfig.json path (optional)" />
    <button class="secondary" onclick={() => onSetPath(configPathInput)}>Set Path</button>
  </div>

  <div class="row">
    <button onclick={onConnect}>Connect</button>
    <button class="secondary" onclick={onDisconnect}>Disconnect</button>
  </div>
</article>
