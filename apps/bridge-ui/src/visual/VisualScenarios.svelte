<script lang="ts">
  import { onMount } from 'svelte'

  type VisualScreen = 'accounts' | 'login' | 'settings'
  type LoginState = 'welcome' | 'security-key' | 'client-selector' | 'client-config'
  type AccountsState = 'sync-progress'
  type SettingsState = 'general' | 'advanced' | 'maintenance' | 'menu-open' | 'cache-move'
  type CacheMoveState = 'moving' | 'done' | 'failed'
  type VisualState = LoginState | AccountsState | SettingsState

  const loginStates: LoginState[] = ['welcome', 'security-key', 'client-selector', 'client-config']
  const settingsStates: SettingsState[] = ['general', 'advanced', 'maintenance', 'menu-open', 'cache-move']

  let screen: VisualScreen = $state('accounts')
  let visualState: VisualState = $state('sync-progress')
  let syncProgress = $state(4)
  let cacheProgress = $state(42)
  let cacheMoveState: CacheMoveState = $state('moving')

  function parseScreen(value: string | null): VisualScreen {
    if (value === 'login' || value === 'settings') {
      return value
    }
    return 'accounts'
  }

  function defaultStateForScreen(nextScreen: VisualScreen): VisualState {
    if (nextScreen === 'login') {
      return 'welcome'
    }
    if (nextScreen === 'settings') {
      return 'general'
    }
    return 'sync-progress'
  }

  function parseState(nextScreen: VisualScreen, value: string | null): VisualState {
    if (nextScreen === 'login' && value && loginStates.includes(value as LoginState)) {
      return value as LoginState
    }
    if (nextScreen === 'settings' && value && settingsStates.includes(value as SettingsState)) {
      return value as SettingsState
    }
    if (nextScreen === 'accounts' && value === 'sync-progress') {
      return 'sync-progress'
    }
    return defaultStateForScreen(nextScreen)
  }

  function parsePercent(value: string | null, fallback: number): number {
    if (!value) {
      return fallback
    }
    const parsed = Number.parseInt(value, 10)
    if (Number.isNaN(parsed)) {
      return fallback
    }
    return Math.min(100, Math.max(0, parsed))
  }

  function parseCacheState(value: string | null): CacheMoveState {
    if (value === 'done' || value === 'failed') {
      return value
    }
    return 'moving'
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
    visualState = parseState(screen, query.get('state'))
    syncProgress = parsePercent(query.get('progress'), 4)
    cacheProgress = parsePercent(query.get('cacheProgress'), 42)
    cacheMoveState = parseCacheState(query.get('cacheState'))
    applyThemeFromRuntime()
  })
</script>

<main class="fixture-root" data-screen={screen} data-state={visualState}>
  {#if screen === 'login'}
    <section class="login-layout">
      <aside class="login-hero">
        <div class="hero-illustration" aria-hidden="true"></div>
        <h1>Welcome to Proton Mail Bridge</h1>
        <p>
          Bridge is the gateway between your Proton account and your email client. It runs in the background and encrypts
          and decrypts your messages seamlessly.
        </p>
        <a href="https://proton.me/support/proton-mail-bridge" aria-label="Why do I need Bridge">Why do I need Bridge?</a>
      </aside>

      <section class="login-panel" data-testid="login-state-panel">
        {#if visualState === 'welcome'}
          <h2>Step 1</h2>
          <p>Connect Bridge to your Proton account</p>
          <h2>Step 2</h2>
          <p>Connect your email client to Bridge</p>
          <button>Start setup</button>
        {:else if visualState === 'security-key'}
          <h2 data-testid="auth-security-key-title">Security key authentication</h2>
          <p class="muted">sheep5604</p>
          <p>Security key authentication is enabled. Please connect your security key.</p>
          <button data-testid="auth-security-key-submit">Authenticate</button>
          <button class="secondary">Cancel</button>
          <a href="https://proton.me/support/two-factor-authentication-2fa">Use authenticator app instead</a>
        {:else if visualState === 'client-selector'}
          <h2>Select your email client</h2>
          <button class="option">Apple Mail</button>
          <button class="option">Microsoft Outlook</button>
          <button class="option">Mozilla Thunderbird</button>
          <button class="option">Other</button>
          <button class="secondary">Setup later</button>
        {:else}
          <h2>Configure your email client</h2>
          <article class="notice">Copy the provided configuration parameters and use the generated password.</article>
          <div class="two-col">
            <article class="mail-card">
              <h3>IMAP</h3>
              <p><strong>Hostname</strong> 127.0.0.1</p>
              <p><strong>Port</strong> 1143</p>
              <p><strong>Username</strong> hca443@pm.me</p>
              <p><strong>Use this password</strong> 3ZLv_RPsFfGGuWjWPpbonA</p>
              <p><strong>Security</strong> STARTTLS</p>
            </article>
            <article class="mail-card">
              <h3>SMTP</h3>
              <p><strong>Hostname</strong> 127.0.0.1</p>
              <p><strong>Port</strong> 1025</p>
              <p><strong>Username</strong> hca443@pm.me</p>
              <p><strong>Use this password</strong> 3ZLv_RPsFfGGuWjWPpbonA</p>
              <p><strong>Security</strong> STARTTLS</p>
            </article>
          </div>
          <button>Continue</button>
        {/if}
      </section>
    </section>
  {:else}
    <section class="shell-layout">
      <aside class="sidebar">
        <p class="connected">Connected</p>
        <h2>Accounts</h2>
        <article class="account-chip">
          <div class="avatar">S</div>
          <div>
            <strong>hca443@pm.me</strong>
            <p data-testid="sync-progress-label">Synchronizing ({syncProgress}%)..</p>
          </div>
        </article>
        {#if visualState === 'menu-open'}
          <div class="overflow-menu" data-testid="settings-overflow-menu">
            <button class="menu-item">Close window</button>
            <button class="menu-item">Quit Bridge</button>
          </div>
        {/if}
      </aside>

      <section class="content">
        {#if screen === 'accounts'}
          <header class="content-header">
            <div>
              <h1>hca443@pm.me</h1>
              <p data-testid="sync-progress-main">Synchronizing ({syncProgress}%)...</p>
            </div>
            <button>Configure email client</button>
          </header>
          <article class="mailbox-block">
            <h2>Mailbox details</h2>
            <div class="two-col">
              <article class="mail-card">
                <h3>IMAP</h3>
                <p><strong>Hostname</strong> 127.0.0.1</p>
                <p><strong>Port</strong> 1143</p>
                <p><strong>Username</strong> hca443@pm.me</p>
                <p><strong>Password</strong> 3ZLv_RPsFfGGuWjWPpbonA</p>
                <p><strong>Security</strong> STARTTLS</p>
              </article>
              <article class="mail-card">
                <h3>SMTP</h3>
                <p><strong>Hostname</strong> 127.0.0.1</p>
                <p><strong>Port</strong> 1025</p>
                <p><strong>Username</strong> hca443@pm.me</p>
                <p><strong>Password</strong> 3ZLv_RPsFfGGuWjWPpbonA</p>
                <p><strong>Security</strong> STARTTLS</p>
              </article>
            </div>
          </article>
        {:else}
          <header class="content-header">
            <h1>Settings</h1>
          </header>

          {#if visualState === 'general'}
            <article class="settings-list">
              <div class="settings-row"><span>Automatic updates</span><span class="pill on">On</span></div>
              <div class="settings-row"><span>Open on startup</span><span class="pill on">On</span></div>
              <div class="settings-row"><span>Beta access</span><span class="pill off">Off</span></div>
              <div class="settings-row"><span>Advanced settings</span><span class="link">Expand</span></div>
            </article>
          {:else if visualState === 'advanced'}
            <article class="settings-list">
              <div class="settings-row"><span>Alternative routing</span><span class="pill off">Off</span></div>
              <div class="settings-row"><span>Dark mode</span><span class="pill on">On</span></div>
              <div class="settings-row"><span>Show Bridge icon in menu bar</span><span class="pill on">On</span></div>
              <div class="settings-row"><span>Show All Mail</span><span class="pill on">On</span></div>
              <div class="settings-row"><span>Collect usage diagnostics</span><span class="pill on">On</span></div>
              <div class="settings-row"><span>Default ports</span><button class="secondary">Change</button></div>
              <div class="settings-row"><span>Connection mode</span><button class="secondary">Change</button></div>
              <div class="settings-row"><span>Local cache</span><button class="secondary">Configure</button></div>
            </article>
          {:else if visualState === 'maintenance' || visualState === 'menu-open'}
            <article class="settings-list">
              <div class="settings-row"><span>Show All Mail</span><span class="pill on">On</span></div>
              <div class="settings-row"><span>Collect usage diagnostics</span><span class="pill on">On</span></div>
              <div class="settings-row"><span>Default ports</span><button class="secondary">Change</button></div>
              <div class="settings-row"><span>Connection mode</span><button class="secondary">Change</button></div>
              <div class="settings-row"><span>Local cache</span><button class="secondary">Configure</button></div>
              <div class="settings-row"><span>Export TLS certificates</span><button class="secondary">Export</button></div>
              <div class="settings-row"><span>Repair Bridge</span><button class="secondary">Repair</button></div>
              <div class="settings-row"><span>Reset Bridge</span><button class="secondary">Reset</button></div>
            </article>
          {:else}
            <article class="settings-list" data-testid="cache-move-panel">
              <div class="settings-row"><span>Local cache</span><span>/home/demo/.cache/openproton-bridge</span></div>
              <div class="settings-row"><span>New location</span><span>/mnt/fast-ssd/bridge-cache</span></div>
              <div class="settings-row"><span>Operation</span><span>Move cache files</span></div>
              <div class="settings-row">
                <span>Move status</span>
                <span data-testid="cache-move-status">
                  {#if cacheMoveState === 'moving'}
                    Moving cache ({cacheProgress}%)
                  {:else if cacheMoveState === 'done'}
                    Cache moved successfully
                  {:else}
                    Cache move failed
                  {/if}
                </span>
              </div>
              <div class="settings-row">
                <span>Actions</span>
                <button>{cacheMoveState === 'moving' ? 'Moving...' : 'Move cache now'}</button>
              </div>
            </article>
          {/if}
        {/if}
      </section>
    </section>
  {/if}
</main>

<style>
  :global(body) {
    margin: 0;
    min-height: 100vh;
    font-family: 'Inter', 'Segoe UI', sans-serif;
  }

  .fixture-root {
    min-height: 100vh;
    color: var(--text);
    background: linear-gradient(160deg, var(--bg-1), var(--bg-2));
  }

  .login-layout {
    min-height: 100vh;
    display: grid;
    grid-template-columns: minmax(320px, 1fr) minmax(420px, 1fr);
  }

  .login-hero {
    border-right: 1px solid var(--panel-border);
    padding: 80px 56px;
    display: grid;
    align-content: center;
    gap: 18px;
  }

  .hero-illustration {
    width: 260px;
    height: 150px;
    border-radius: 20px;
    background: linear-gradient(110deg, color-mix(in oklab, var(--brand) 72%, #ff785f), color-mix(in oklab, var(--brand) 70%, #4ec4ff));
    box-shadow: 0 20px 50px color-mix(in oklab, var(--brand) 26%, transparent);
  }

  .login-hero h1 {
    margin: 0;
    font-size: 56px;
    letter-spacing: -0.02em;
    line-height: 1;
    max-width: 460px;
  }

  .login-hero p,
  .login-hero a {
    max-width: 470px;
    font-size: 30px;
    line-height: 1.4;
  }

  .login-hero a {
    color: var(--brand-2);
    text-underline-offset: 4px;
  }

  .login-panel {
    padding: 96px 72px;
    display: grid;
    gap: 22px;
    align-content: center;
  }

  .login-panel h2 {
    margin: 0;
    font-size: 52px;
    text-transform: none;
    letter-spacing: -0.01em;
    color: var(--text);
  }

  .login-panel p,
  .login-panel a {
    margin: 0;
    font-size: 40px;
    line-height: 1.35;
    color: var(--text);
  }

  .login-panel .muted {
    color: var(--text-muted);
    font-size: 36px;
  }

  .login-panel button {
    justify-self: stretch;
    min-height: 68px;
    border-radius: 14px;
    font-size: 38px;
  }

  .login-panel button.secondary {
    background: color-mix(in oklab, var(--surface) 80%, transparent);
    color: var(--text);
  }

  .notice {
    border: 1px solid color-mix(in oklab, #f59f00 64%, var(--panel-border));
    border-radius: 14px;
    padding: 18px;
    font-size: 28px;
    line-height: 1.4;
    background: color-mix(in oklab, #f59f00 12%, transparent);
  }

  .option {
    text-align: left;
    padding-left: 22px;
  }

  .shell-layout {
    min-height: 100vh;
    display: grid;
    grid-template-columns: 300px minmax(0, 1fr);
  }

  .sidebar {
    border-right: 1px solid var(--panel-border);
    padding: 20px 14px;
    display: grid;
    gap: 16px;
    align-content: start;
    position: relative;
  }

  .connected {
    margin: 0;
    color: #1bb784;
    font-weight: 700;
  }

  .sidebar h2 {
    margin: 0;
    font-size: 28px;
    letter-spacing: 0;
    text-transform: none;
    color: var(--text);
  }

  .account-chip {
    border: 1px solid var(--panel-border);
    border-radius: 14px;
    padding: 14px;
    background: color-mix(in oklab, var(--surface) 78%, transparent);
    display: flex;
    align-items: center;
    gap: 12px;
  }

  .avatar {
    width: 44px;
    height: 44px;
    border-radius: 10px;
    display: grid;
    place-items: center;
    background: var(--brand);
    color: #fff;
    font-weight: 700;
  }

  .account-chip p {
    margin: 4px 0 0;
    color: var(--text-muted);
  }

  .overflow-menu {
    position: absolute;
    left: 252px;
    top: 68px;
    border: 1px solid var(--panel-border);
    border-radius: 12px;
    background: color-mix(in oklab, var(--surface) 86%, transparent);
    display: grid;
    min-width: 194px;
    padding: 8px;
    z-index: 10;
  }

  .menu-item {
    text-align: left;
    border: none;
    background: transparent;
    color: var(--text);
    padding: 10px;
    border-radius: 8px;
    font-size: 16px;
    min-height: 0;
  }

  .menu-item:hover {
    background: color-mix(in oklab, var(--brand-soft) 35%, transparent);
    transform: none;
  }

  .content {
    padding: 22px 34px;
    display: grid;
    align-content: start;
    gap: 18px;
  }

  .content-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 16px;
    border-bottom: 1px solid var(--panel-border);
    padding-bottom: 16px;
  }

  .content-header h1 {
    margin: 0;
    font-size: 46px;
    line-height: 1;
  }

  .content-header p {
    margin: 8px 0 0;
    font-size: 28px;
    color: var(--text-muted);
  }

  .mailbox-block h2 {
    margin: 0;
    text-transform: none;
    letter-spacing: 0;
    font-size: 30px;
    color: var(--text);
  }

  .two-col {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 18px;
  }

  .mail-card {
    border: 1px solid var(--panel-border);
    border-radius: 16px;
    padding: 18px;
    background: color-mix(in oklab, var(--surface) 72%, transparent);
    display: grid;
    gap: 8px;
  }

  .mail-card h3 {
    margin: 0 0 8px;
    font-size: 30px;
  }

  .mail-card p {
    margin: 0;
    font-size: 22px;
    line-height: 1.35;
    display: grid;
    gap: 4px;
  }

  .settings-list {
    border: 1px solid var(--panel-border);
    border-radius: 14px;
    overflow: hidden;
    background: color-mix(in oklab, var(--surface) 72%, transparent);
  }

  .settings-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 18px;
    padding: 16px 18px;
    border-bottom: 1px solid var(--panel-border);
    font-size: 22px;
  }

  .settings-row:last-child {
    border-bottom: none;
  }

  .settings-row button {
    min-height: 42px;
    font-size: 20px;
    padding: 6px 16px;
  }

  .pill {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    min-width: 58px;
    min-height: 32px;
    border-radius: 999px;
    font-size: 16px;
    font-weight: 700;
    border: 1px solid var(--panel-border);
  }

  .pill.on {
    background: color-mix(in oklab, var(--brand) 75%, transparent);
    color: #fff;
  }

  .pill.off {
    background: transparent;
    color: var(--text-muted);
  }

  .link {
    color: var(--brand-2);
    font-weight: 600;
  }

  @media (max-width: 1200px) {
    .login-layout {
      grid-template-columns: 1fr;
    }

    .login-hero,
    .login-panel {
      padding: 24px;
    }

    .shell-layout {
      grid-template-columns: 1fr;
    }

    .sidebar {
      border-right: none;
      border-bottom: 1px solid var(--panel-border);
    }

    .overflow-menu {
      left: 16px;
      top: 170px;
    }

    .two-col {
      grid-template-columns: 1fr;
    }
  }
</style>
