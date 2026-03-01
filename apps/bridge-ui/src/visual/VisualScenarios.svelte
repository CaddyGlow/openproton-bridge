<script lang="ts">
  import { onMount } from 'svelte'
  import LoginWizard from '../lib/components/LoginWizard.svelte'
  import UsersCard from '../lib/components/cards/UsersCard.svelte'
  import GeneralSettingsCard from '../lib/components/cards/GeneralSettingsCard.svelte'
  import type { AppSettings, UserSummary } from '../lib/api/bridge'

  type VisualScreen = 'accounts' | 'login' | 'settings'

  const visualUsers: UserSummary[] = [
    {
      id: 'u1',
      username: 'alex@proton.me',
      state: 1,
      split_mode: true,
      addresses: ['alex@proton.me', 'work@pm.me'],
      used_bytes: 15_200_000,
      total_bytes: 5_000_000_000,
    },
    {
      id: 'u2',
      username: 'sam@proton.me',
      state: 0,
      split_mode: false,
      addresses: ['sam@proton.me'],
      used_bytes: 4_800_000,
      total_bytes: 5_000_000_000,
    },
  ]

  const visualSettings: AppSettings = {
    is_autostart_on: true,
    is_beta_enabled: false,
    is_all_mail_visible: true,
    is_telemetry_disabled: false,
    disk_cache_path: '/home/demo/.cache/openproton-bridge',
    is_doh_enabled: true,
    color_scheme_name: 'system',
  }

  let screen = $state<VisualScreen>('accounts')
  let loginWizardOpen = $state(false)
  let appSettings = $state<AppSettings>({ ...visualSettings })
  let diskCachePathInput = $state(visualSettings.disk_cache_path)
  let colorSchemeNameInput = $state('system')
  let loginUsername = $state('alex@proton.me')
  let loginPassword = $state('••••••••')
  let twoFactorCode = $state('192004')
  let mailboxPassword = $state('')
  let fidoAssertionPayload = $state('')

  function parseScreen(value: string | null): VisualScreen {
    if (value === 'login' || value === 'settings') {
      return value
    }
    return 'accounts'
  }

  function applyThemeFromRuntime() {
    const query = new URLSearchParams(window.location.search)
    const explicitTheme = query.get('theme')
    if (explicitTheme === 'dark' || explicitTheme === 'light') {
      document.documentElement.dataset.theme = explicitTheme
      return
    }
    const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches
    document.documentElement.dataset.theme = prefersDark ? 'dark' : 'light'
  }

  onMount(() => {
    const query = new URLSearchParams(window.location.search)
    screen = parseScreen(query.get('screen'))
    loginWizardOpen = screen === 'login'
    applyThemeFromRuntime()
  })
</script>

<main class="app-shell">
  <header class="card app-header">
    <div>
      <h1>OpenProton Bridge</h1>
      <p class="muted">Visual regression harness for accounts, login wizard, and settings screens.</p>
      <div class="header-metrics">
        <span class="status-pill good">Bridge Connected</span>
        <span class="status-pill muted">Screen: {screen}</span>
        <span class="status-pill good">Stream Running</span>
      </div>
    </div>
    <div class="header-actions">
      <button class="secondary">Sign In Wizard</button>
      <button class="secondary">Refresh Data</button>
      <button class="secondary">Theme: system</button>
    </div>
  </header>

  <section class="workspace">
    <aside class="left-rail">
      <article class="card nav-card">
        <h2>Navigation</h2>
        <p class="muted">Visual fixture mode.</p>
        <div class="section-nav">
          <button class="secondary nav-btn" class:active={screen === 'accounts'}>Accounts</button>
          <button class="secondary nav-btn" class:active={screen === 'settings'}>Settings</button>
          <button class="secondary nav-btn" class:active={screen === 'login'}>Login</button>
        </div>
      </article>

      <article class="card">
        <h2>Host</h2>
        <p class="muted"><strong>Hostname:</strong> bridge.local</p>
        <p class="muted"><strong>Users:</strong> {visualUsers.length}</p>
        <p class="muted"><strong>TLS:</strong> installed</p>
      </article>
    </aside>

    <section class="main-pane">
      {#if screen === 'settings'}
        <GeneralSettingsCard
          bind:appSettings
          bind:diskCachePathInput
          bind:colorSchemeNameInput
          settingsStatus="saved"
          onApplySettings={() => {}}
        />
      {:else}
        <article class="card">
          <h2>Account Access</h2>
          <p class="muted">
            Proton login flow preview. Current login step:
            <strong> 2fa or fido</strong>
          </p>
          <div class="row">
            <button>Open Sign-In Wizard</button>
            <button class="secondary">Hide Wizard</button>
          </div>
        </article>
        <UsersCard users={visualUsers} hostname="bridge.local" usersLoading={false} />
      {/if}
    </section>

    <aside class="status-rail">
      <article class="card">
        <h2>Status Rail</h2>
        <p class="muted"><strong>Stream:</strong> running</p>
        <p class="muted"><strong>Login:</strong> 2fa_or_fido</p>
        <p class="muted"><strong>TLS:</strong> installed</p>
      </article>
    </aside>
  </section>

  <LoginWizard
    open={loginWizardOpen}
    loginStep="2fa_or_fido"
    bind:loginUsername
    bind:loginPassword
    bind:twoFactorCode
    bind:mailboxPassword
    bind:fidoAssertionPayload
    loginStatus="Verification challenge active."
  />
</main>
