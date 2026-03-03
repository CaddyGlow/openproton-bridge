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
    activeUserIndex = -1,
    userParityById = {},
    syncPhase = 'idle',
    syncProgressPercent = null,
    imapPort = '1143',
    smtpPort = '1025',
    useSslImap = false,
    useSslSmtp = false,
    onConfigureClient = (_userId: string) => {},
    onToggleSplitMode = (_userId: string, _current: boolean) => {},
    onLogout = (_userId: string) => {},
    onRemove = (_userId: string) => {},
  }: {
    hostname?: string
    usersLoading?: boolean
    users?: UserSummary[]
    activeUserId?: string
    activeUserIndex?: number
    userParityById?: Record<string, UserParityHook>
    syncPhase?: 'idle' | 'syncing' | 'complete' | 'error'
    syncProgressPercent?: number | null
    imapPort?: string
    smtpPort?: string
    useSslImap?: boolean
    useSslSmtp?: boolean
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

  function formatStorage(bytes: number): string {
    if (!Number.isFinite(bytes) || bytes <= 0) {
      return '0 B'
    }
    const units = ['B', 'KB', 'MB', 'GB', 'TB']
    let value = bytes
    let unitIndex = 0
    while (value >= 1024 && unitIndex < units.length - 1) {
      value /= 1024
      unitIndex += 1
    }
    const decimals = value >= 100 || unitIndex === 0 ? 0 : 1
    return `${value.toFixed(decimals)} ${units[unitIndex]}`
  }

  function securityLabel(sslEnabled: boolean): string {
    return sslEnabled ? 'SSL/TLS' : 'STARTTLS'
  }

  function resolvePassword(user: UserSummary | null): string {
    const candidate = user?.password?.trim() ?? ''
    return candidate.length > 0 ? candidate : 'generated app password'
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
    (activeUserIndex >= 0 && activeUserIndex < users.length ? users[activeUserIndex] : null) ??
      users.find((user) => user.id === activeUserId) ??
      users[0] ??
      null,
  )
  const activeUserPassword = $derived(resolvePassword(activeUser))

  const activeUserSyncStatus = $derived(activeUser ? syncStatusForUser(activeUser) : '')
  const activeUserSyncProgress = $derived(activeUser ? syncProgressForUser(activeUser.id) : null)
  const activeUserStorage = $derived(
    activeUser && activeUser.total_bytes > 0
      ? {
          used: formatStorage(Math.max(0, activeUser.used_bytes)),
          total: formatStorage(activeUser.total_bytes),
          progress: Math.max(0, Math.min(100, Math.round((activeUser.used_bytes / activeUser.total_bytes) * 100))),
        }
      : null,
  )

  const imapDetails = $derived(
    activeUser
      ? [
          { label: 'Hostname', value: hostname || '127.0.0.1' },
          { label: 'Port', value: imapPort },
          { label: 'Username', value: activeUser.username },
          { label: 'Password', value: activeUserPassword },
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
          { label: 'Password', value: activeUserPassword },
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
          <p
            class={`user-view-sync-status ${activeUserStorage && activeUserSyncStatus === 'Connected' ? 'is-visually-hidden' : ''}`}
            data-testid="active-user-sync-status"
          >
            {activeUserSyncStatus}
          </p>
          {#if activeUserStorage}
            <p class="user-view-storage-summary">
              <span class="user-view-storage-used">{activeUserStorage.used}</span>
              <span class="user-view-storage-total"> / {activeUserStorage.total}</span>
            </p>
          {/if}
          {#if activeUserStorage}
            <div class="user-view-storage-track" role="presentation" aria-hidden="true">
              <div class="user-view-storage-fill" style={`width: ${activeUserStorage.progress}%`}></div>
            </div>
          {/if}
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
          <svg class="action-icon" viewBox="0 0 16 16" aria-hidden="true">
            <path d="M5 2.75h6M6.25 2.75V2A.75.75 0 0 1 7 1.25h2A.75.75 0 0 1 9.75 2v.75" />
            <path d="M3.5 4.25h9l-.75 8.5a1 1 0 0 1-1 .91H5.25a1 1 0 0 1-1-.91l-.75-8.5Z" />
            <path d="M6.75 6.25v5M9.25 6.25v5" />
          </svg>
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
                <svg class="action-icon" viewBox="0 0 16 16" aria-hidden="true">
                  <path d="M6 2.75h6.25A1.25 1.25 0 0 1 13.5 4v7.25a1.25 1.25 0 0 1-1.25 1.25H6A1.25 1.25 0 0 1 4.75 11.25V4A1.25 1.25 0 0 1 6 2.75Z" />
                  <path d="M11.25 2.75V2A1.25 1.25 0 0 0 10 0.75H3.75A1.25 1.25 0 0 0 2.5 2v7.25A1.25 1.25 0 0 0 3.75 10.5h1" />
                </svg>
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
                <svg class="action-icon" viewBox="0 0 16 16" aria-hidden="true">
                  <path d="M6 2.75h6.25A1.25 1.25 0 0 1 13.5 4v7.25a1.25 1.25 0 0 1-1.25 1.25H6A1.25 1.25 0 0 1 4.75 11.25V4A1.25 1.25 0 0 1 6 2.75Z" />
                  <path d="M11.25 2.75V2A1.25 1.25 0 0 0 10 0.75H3.75A1.25 1.25 0 0 0 2.5 2v7.25A1.25 1.25 0 0 0 3.75 10.5h1" />
                </svg>
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
