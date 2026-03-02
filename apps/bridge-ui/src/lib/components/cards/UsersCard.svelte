<script lang="ts">
  import type { UserSummary } from '../../api/bridge'

  type UserParityHook = {
    syncProgress?: number | null
    disconnected?: boolean
    recovering?: boolean
    error?: string | null
  }

  let {
    hostname = '',
    usersLoading = false,
    users = [],
    activeUserId = '',
    userParityById = {},
    syncPhase = 'idle',
    syncProgressPercent = null,
    imapPort = '1143',
    smtpPort = '1025',
    useSslImap = false,
    useSslSmtp = false,
    clientPassword = 'generated app password',
    onConfigureClient = (_userId: string) => {},
    onToggleSplitMode = (_userId: string, _current: boolean) => {},
    onLogout = (_userId: string) => {},
    onRemove = (_userId: string) => {},
  }: {
    hostname?: string
    usersLoading?: boolean
    users?: UserSummary[]
    activeUserId?: string
    userParityById?: Record<string, UserParityHook>
    syncPhase?: 'idle' | 'syncing' | 'complete' | 'error'
    syncProgressPercent?: number | null
    imapPort?: string
    smtpPort?: string
    useSslImap?: boolean
    useSslSmtp?: boolean
    clientPassword?: string
    onConfigureClient?: (userId: string) => void
    onToggleSplitMode?: (userId: string, current: boolean) => void
    onLogout?: (userId: string) => void
    onRemove?: (userId: string) => void
  } = $props()

  let clipboardNotice = $state('')
  let clipboardTimer: ReturnType<typeof setTimeout> | null = null

  function avatarInitial(username: string): string {
    const trimmed = username.trim()
    if (trimmed.length === 0) {
      return '?'
    }
    return trimmed.charAt(0).toUpperCase()
  }

  function normalizeSyncPercent(value: number): number {
    if (!Number.isFinite(value)) {
      return 0
    }
    const percent = value >= 0 && value <= 1 ? value * 100 : value
    return Math.max(0, Math.min(100, Math.round(percent)))
  }

  function securityLabel(sslEnabled: boolean): string {
    return sslEnabled ? 'SSL/TLS' : 'STARTTLS'
  }

  function syncProgressForUser(userId: string): number | null {
    const hookProgress = userParityById[userId]?.syncProgress
    if (typeof hookProgress === 'number') {
      return normalizeSyncPercent(hookProgress)
    }
    if (syncPhase === 'syncing' && typeof syncProgressPercent === 'number') {
      return normalizeSyncPercent(syncProgressPercent)
    }
    return null
  }

  function syncStatusForUser(user: UserSummary): string {
    const hook = userParityById[user.id]
    if (hook?.error) {
      return 'Needs attention'
    }
    const progress = syncProgressForUser(user.id)
    if (typeof progress === 'number' && progress < 100) {
      return `Synchronizing (${progress}%)...`
    }
    if (hook?.recovering) {
      return 'Recovering session...'
    }
    if (hook?.disconnected || Number(user.state) !== 2) {
      return 'Disconnected'
    }
    return 'Connected'
  }

  async function copyValue(label: string, value: string) {
    if (typeof navigator === 'undefined' || !navigator.clipboard?.writeText) {
      return
    }
    try {
      await navigator.clipboard.writeText(value)
      clipboardNotice = `${label} copied`
      if (clipboardTimer) {
        clearTimeout(clipboardTimer)
      }
      clipboardTimer = setTimeout(() => {
        clipboardNotice = ''
      }, 1200)
    } catch {
      clipboardNotice = ''
    }
  }

  const activeUser = $derived(
    users.find((user) => user.id === activeUserId) ??
      users[0] ??
      null,
  )

  const activeUserSyncStatus = $derived(activeUser ? syncStatusForUser(activeUser) : '')
  const activeUserSyncProgress = $derived(activeUser ? syncProgressForUser(activeUser.id) : null)

  const imapDetails = $derived(
    activeUser
      ? [
          { label: 'Hostname', value: hostname || '127.0.0.1' },
          { label: 'Port', value: imapPort },
          { label: 'Username', value: activeUser.username },
          { label: 'Password', value: clientPassword },
          { label: 'Security', value: securityLabel(useSslImap) },
        ]
      : [],
  )

  const smtpDetails = $derived(
    activeUser
      ? [
          { label: 'Hostname', value: hostname || '127.0.0.1' },
          { label: 'Port', value: smtpPort },
          { label: 'Username', value: activeUser.username },
          { label: 'Password', value: clientPassword },
          { label: 'Security', value: securityLabel(useSslSmtp) },
        ]
      : [],
  )
</script>

<article class="card user-view-card">
  {#if usersLoading}
    <p class="muted">Loading users...</p>
  {:else if !activeUser}
    <p class="muted">No users returned.</p>
  {:else}
    <header class="user-view-header">
      <div class="user-view-identity">
        <span class="avatar">{avatarInitial(activeUser.username)}</span>
        <div class="user-view-identity-text">
          <p class="user-view-username">{activeUser.username}</p>
          <p class="user-view-sync-status" data-testid="active-user-sync-status">{activeUserSyncStatus}</p>
          {#if typeof activeUserSyncProgress === 'number' && activeUserSyncProgress < 100}
            <div
              class="user-view-sync-track"
              role="progressbar"
              aria-valuemin="0"
              aria-valuemax="100"
              aria-valuenow={activeUserSyncProgress}
            >
              <div class="user-view-sync-fill" style={`width: ${activeUserSyncProgress}%`}></div>
            </div>
          {/if}
        </div>
      </div>
      <div class="user-view-actions">
        <button class="secondary" onclick={() => onLogout(activeUser.id)}>Sign out</button>
        <button class="secondary icon-only" aria-label="Remove account" title="Remove account" onclick={() => onRemove(activeUser.id)}>
          🗑
        </button>
      </div>
    </header>

    <section class="user-view-row">
      <div>
        <p class="user-view-row-title">Email clients</p>
        <p class="muted">Using the mailbox details below (re)configure your client.</p>
      </div>
      <button onclick={() => onConfigureClient(activeUser.id)}>Configure email client</button>
    </section>

    <section class="user-view-row split">
      <div>
        <p class="user-view-row-title">Split addresses</p>
        <p class="muted">Setup multiple email addresses individually.</p>
      </div>
      <button
        class={`switch ${activeUser.split_mode ? 'active' : ''}`}
        role="switch"
        aria-checked={activeUser.split_mode}
        aria-label="Toggle split addresses"
        onclick={() => onToggleSplitMode(activeUser.id, activeUser.split_mode)}
      >
        <span class="switch-knob"></span>
      </button>
    </section>

    <section class="mailbox-section">
      <h3>Mailbox details</h3>
      <div class="mailbox-grid">
        <article class="mailbox-card">
          <h4>IMAP</h4>
          {#each imapDetails as field}
            <div class="mailbox-field">
              <div>
                <p class="mailbox-label">{field.label}</p>
                <p class="mailbox-value">{field.value}</p>
              </div>
              <button class="copy-btn" aria-label={`Copy ${field.label}`} onclick={() => copyValue(field.label, field.value)}>
                ⧉
              </button>
            </div>
          {/each}
        </article>

        <article class="mailbox-card">
          <h4>SMTP</h4>
          {#each smtpDetails as field}
            <div class="mailbox-field">
              <div>
                <p class="mailbox-label">{field.label}</p>
                <p class="mailbox-value">{field.value}</p>
              </div>
              <button class="copy-btn" aria-label={`Copy ${field.label}`} onclick={() => copyValue(field.label, field.value)}>
                ⧉
              </button>
            </div>
          {/each}
        </article>
      </div>
      {#if clipboardNotice}
        <p class="muted clipboard-notice">{clipboardNotice}</p>
      {/if}
    </section>
  {/if}
</article>
