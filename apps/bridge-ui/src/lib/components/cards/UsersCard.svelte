<script lang="ts">
  import type { UserSummary } from '../../api/bridge'

  type UserParityHook = {
    syncProgress?: number | null
    disconnected?: boolean
    recovering?: boolean
    error?: string | null
  }

  type UserParityPresentation = {
    label: string
    tone: 'good' | 'danger' | 'muted'
    detail?: string
  }

  let {
    hostname = '',
    usersLoading = false,
    users = [],
    userParityById = {},
    syncPhase = 'idle',
    syncProgressPercent = null,
    syncMessage = '',
    onConfigureClient = (_userId: string) => {},
    onToggleSplitMode = (_userId: string, _current: boolean) => {},
    onLogout = (_userId: string) => {},
    onRemove = (_userId: string) => {},
  }: {
    hostname?: string
    usersLoading?: boolean
    users?: UserSummary[]
    userParityById?: Record<string, UserParityHook>
    syncPhase?: 'idle' | 'syncing' | 'complete' | 'error'
    syncProgressPercent?: number | null
    syncMessage?: string | null
    onConfigureClient?: (userId: string) => void
    onToggleSplitMode?: (userId: string, current: boolean) => void
    onLogout?: (userId: string) => void
    onRemove?: (userId: string) => void
  } = $props()

  function stateLabel(state: string | number): string {
    const numeric = Number(state)
    if (numeric === 2) {
      return 'connected'
    }
    if (numeric === 1) {
      return 'locked'
    }
    if (numeric === 0) {
      return 'signed out'
    }
    return String(state)
  }

  function stateTone(state: string | number): string {
    const lower = String(state).toLowerCase()
    const numeric = Number(state)
    if (numeric === 2) {
      return 'good'
    }
    if (numeric === 1 || numeric === 0) {
      return 'muted'
    }
    if (lower.includes('connected') || lower.includes('active') || lower.includes('ready') || lower.includes('ok')) {
      return 'good'
    }
    if (lower.includes('error') || lower.includes('locked') || lower.includes('failed')) {
      return 'danger'
    }
    return 'muted'
  }

  function normalizeSyncPercent(value: number): number {
    if (!Number.isFinite(value)) {
      return 0
    }
    const percent = value >= 0 && value <= 1 ? value * 100 : value
    return Math.max(0, Math.min(100, Math.round(percent)))
  }

  function parityPresentationForUser(userId: string): UserParityPresentation | null {
    const hook = userParityById[userId]
    if (!hook) {
      return null
    }
    if (hook.error && hook.error.trim().length > 0) {
      return {
        label: 'Error',
        tone: 'danger',
        detail: hook.error,
      }
    }
    if (typeof hook.syncProgress === 'number') {
      const progress = normalizeSyncPercent(hook.syncProgress)
      return {
        label: `Synchronizing (${progress}%)`,
        tone: 'good',
      }
    }
    if (hook.recovering) {
      return {
        label: 'Recovering',
        tone: 'muted',
      }
    }
    if (hook.disconnected) {
      return {
        label: 'Disconnected',
        tone: 'muted',
      }
    }
    return null
  }

  const syncPercent = $derived(
    typeof syncProgressPercent === 'number' ? normalizeSyncPercent(syncProgressPercent) : null,
  )
  const showSyncProgress = $derived(syncPhase === 'syncing')
  const showSyncError = $derived(syncPhase === 'error' && Boolean(syncMessage))
</script>

<article class="card span-2">
  <h2>Users</h2>
  <p class="muted"><strong>Hostname:</strong> {hostname || '(not loaded)'}</p>
  {#if showSyncProgress}
    <div class="users-sync-banner" data-testid="users-sync-progress">
      <div class="users-sync-header">
        <span class="status-pill good">Synchronizing{#if syncPercent !== null} ({syncPercent}%){/if}</span>
      </div>
      <div class="users-sync-track" role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow={syncPercent ?? 0}>
        <div class="users-sync-fill" style={`width: ${syncPercent ?? 0}%`}></div>
      </div>
      {#if syncMessage}
        <p class="muted users-sync-message">{syncMessage}</p>
      {/if}
    </div>
  {:else if showSyncError}
    <div class="users-sync-banner" data-testid="users-sync-error">
      <span class="status-pill danger">Sync issue</span>
      <p class="muted users-sync-message">{syncMessage}</p>
    </div>
  {/if}
  {#if usersLoading}
    <p class="muted">Loading users...</p>
  {:else if users.length === 0}
    <p class="muted">No users returned.</p>
  {:else}
    <table>
      <thead>
        <tr>
          <th>Username</th>
          <th>State</th>
          <th>Split Mode</th>
          <th>Addresses</th>
          <th>Actions</th>
        </tr>
      </thead>
      <tbody>
        {#each users as user}
          {@const parity = parityPresentationForUser(user.id)}
          <tr>
            <td class="user-col">
              <div class="user-primary">{user.username}</div>
              <div class="user-secondary">{user.addresses[0] || 'no address'}</div>
            </td>
            <td>
              <span class={`status-pill ${stateTone(user.state)}`}>{stateLabel(user.state)}</span>
              {#if parity}
                <div class="user-secondary">
                  <span class={`status-pill ${parity.tone}`}>{parity.label}</span>
                </div>
                {#if parity.detail}
                  <div class="user-secondary">{parity.detail}</div>
                {/if}
              {/if}
            </td>
            <td>
              <span class={`status-pill ${user.split_mode ? 'good' : 'muted'}`}>
                {user.split_mode ? 'enabled' : 'disabled'}
              </span>
            </td>
            <td>{user.addresses.join(', ')}</td>
            <td class="user-actions">
              <div class="row">
                <button class="secondary" onclick={() => onConfigureClient(user.id)}>Configure Client</button>
                <button class="secondary" onclick={() => onToggleSplitMode(user.id, user.split_mode)}>
                  {user.split_mode ? 'Disable Split' : 'Enable Split'}
                </button>
                <button class="secondary" onclick={() => onLogout(user.id)}>Logout</button>
                <button class="danger" onclick={() => onRemove(user.id)}>Remove</button>
              </div>
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
  {/if}
</article>
