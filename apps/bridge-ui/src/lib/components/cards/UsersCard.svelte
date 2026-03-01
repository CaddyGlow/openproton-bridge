<script lang="ts">
  import type { UserSummary } from '../../api/bridge'

  let {
    hostname = '',
    usersLoading = false,
    users = [],
    onToggleSplitMode = (_userId: string, _current: boolean) => {},
    onLogout = (_userId: string) => {},
    onRemove = (_userId: string) => {},
  }: {
    hostname?: string
    usersLoading?: boolean
    users?: UserSummary[]
    onToggleSplitMode?: (userId: string, current: boolean) => void
    onLogout?: (userId: string) => void
    onRemove?: (userId: string) => void
  } = $props()

  function stateTone(state: string | number): string {
    const lower = String(state).toLowerCase()
    if (lower.includes('connected') || lower.includes('active') || lower.includes('ready') || lower.includes('ok')) {
      return 'good'
    }
    if (lower.includes('error') || lower.includes('locked') || lower.includes('failed')) {
      return 'danger'
    }
    return 'muted'
  }
</script>

<article class="card span-2">
  <h2>Users</h2>
  <p class="muted"><strong>Hostname:</strong> {hostname || '(not loaded)'}</p>
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
          <tr>
            <td class="user-col">
              <div class="user-primary">{user.username}</div>
              <div class="user-secondary">{user.addresses[0] || 'no address'}</div>
            </td>
            <td>
              <span class={`status-pill ${stateTone(user.state)}`}>{String(user.state)}</span>
            </td>
            <td>
              <span class={`status-pill ${user.split_mode ? 'good' : 'muted'}`}>
                {user.split_mode ? 'enabled' : 'disabled'}
              </span>
            </td>
            <td>{user.addresses.join(', ')}</td>
            <td class="user-actions">
              <div class="row">
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
