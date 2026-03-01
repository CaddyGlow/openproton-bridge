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
            <td>{user.username}</td>
            <td>{user.state}</td>
            <td>{user.split_mode ? 'on' : 'off'}</td>
            <td>{user.addresses.join(', ')}</td>
            <td>
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
