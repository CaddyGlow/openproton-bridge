<script lang="ts">
  import type { AppSettings } from '../../api/bridge'

  type SettingsSectionId = 'general' | 'advanced' | 'maintenance'
  type CacheMoveState = 'idle' | 'in_flight' | 'success' | 'failure'

  const defaultAppSettings: AppSettings = {
    is_autostart_on: false,
    is_beta_enabled: false,
    is_all_mail_visible: true,
    is_telemetry_disabled: false,
    disk_cache_path: '',
    is_doh_enabled: true,
    color_scheme_name: 'system',
    current_keychain: '',
    available_keychains: [],
  }

  let {
    appSettings = $bindable({ ...defaultAppSettings }),
    diskCachePathInput = $bindable(''),
    colorSchemeNameInput = $bindable('system'),
    currentKeychainInput = $bindable(''),
    settingsStatus = '',
    expandedSections = {},
    cacheMoveState = 'idle',
    cacheMoveStatus = '',
    onToggleSection = (_section: SettingsSectionId, _nextExpanded: boolean) => {},
    onApplySettings = () => {},
  }: {
    appSettings: AppSettings
    diskCachePathInput?: string
    colorSchemeNameInput?: string
    currentKeychainInput?: string
    settingsStatus?: string
    expandedSections?: Partial<Record<SettingsSectionId, boolean>>
    cacheMoveState?: CacheMoveState
    cacheMoveStatus?: string
    onToggleSection?: (section: SettingsSectionId, nextExpanded: boolean) => void
    onApplySettings?: () => void
  } = $props()

  const defaultExpandedSections: Record<SettingsSectionId, boolean> = {
    general: true,
    advanced: true,
    maintenance: true,
  }

  function isSectionExpanded(section: SettingsSectionId): boolean {
    const expanded = expandedSections[section]
    if (typeof expanded === 'boolean') {
      return expanded
    }
    return defaultExpandedSections[section]
  }

  function toggleSection(section: SettingsSectionId) {
    onToggleSection(section, !isSectionExpanded(section))
  }

  function cacheMoveSummaryFor(state: CacheMoveState): string {
    if (state === 'in_flight') {
      return 'Moving cache path...'
    }
    if (state === 'success') {
      return 'Cache move completed.'
    }
    if (state === 'failure') {
      return 'Cache move failed.'
    }
    return ''
  }

  function cacheMoveToneFor(state: CacheMoveState): 'good' | 'danger' | 'muted' {
    if (state === 'success') {
      return 'good'
    }
    if (state === 'failure') {
      return 'danger'
    }
    return 'muted'
  }
</script>

<article class="card span-2">
  <h2>General Settings</h2>
  <section>
    <div class="row">
      <button
        class="secondary"
        type="button"
        aria-expanded={isSectionExpanded('general')}
        aria-controls="general-settings-general"
        onclick={() => toggleSection('general')}
      >
        General
      </button>
    </div>
    {#if isSectionExpanded('general')}
      <div id="general-settings-general">
        <p class="muted">Core runtime behavior and appearance.</p>
        <div class="row wrap">
          <label class="checkbox">
            <input type="checkbox" bind:checked={appSettings.is_autostart_on} />
            Autostart
          </label>
          <label class="checkbox">
            <input type="checkbox" bind:checked={appSettings.is_all_mail_visible} />
            All Mail Visible
          </label>
        </div>
        <div class="row wrap">
          <label>
            Color Scheme
            <select bind:value={colorSchemeNameInput}>
              <option value="system">system</option>
              <option value="light">light</option>
              <option value="dark">dark</option>
            </select>
          </label>
        </div>
      </div>
    {/if}
  </section>
  <section>
    <div class="row">
      <button
        class="secondary"
        type="button"
        aria-expanded={isSectionExpanded('advanced')}
        aria-controls="general-settings-advanced"
        onclick={() => toggleSection('advanced')}
      >
        Advanced
      </button>
    </div>
    {#if isSectionExpanded('advanced')}
      <div id="general-settings-advanced">
        <p class="muted">Compatibility and experimental runtime controls.</p>
        <div class="row wrap">
          <label class="checkbox">
            <input type="checkbox" bind:checked={appSettings.is_beta_enabled} />
            Beta Channel
          </label>
          <label class="checkbox">
            <input type="checkbox" bind:checked={appSettings.is_telemetry_disabled} />
            Telemetry Disabled
          </label>
          <label class="checkbox">
            <input type="checkbox" bind:checked={appSettings.is_doh_enabled} />
            DNS-over-HTTPS
          </label>
        </div>
        <div class="row wrap">
          <label>
            Keychain
            <select bind:value={currentKeychainInput}>
              {#if (appSettings.available_keychains?.length ?? 0) === 0}
                <option value="">(unavailable)</option>
              {:else}
                {#each appSettings.available_keychains ?? [] as keychain}
                  <option value={keychain}>{keychain}</option>
                {/each}
              {/if}
            </select>
          </label>
        </div>
      </div>
    {/if}
  </section>
  <section>
    <div class="row">
      <button
        class="secondary"
        type="button"
        aria-expanded={isSectionExpanded('maintenance')}
        aria-controls="general-settings-maintenance"
        onclick={() => toggleSection('maintenance')}
      >
        Maintenance
      </button>
    </div>
    {#if isSectionExpanded('maintenance')}
      <div id="general-settings-maintenance">
        <p class="muted">Cache storage and runtime housekeeping.</p>
        <div class="row wrap">
          <label class="grow">
            Disk Cache Path
            <input bind:value={diskCachePathInput} placeholder="/path/to/cache" />
          </label>
        </div>
        {#if cacheMoveState !== 'idle' || cacheMoveStatus}
          <div class="row">
            {#if cacheMoveState !== 'idle'}
              <span class={`status-pill ${cacheMoveToneFor(cacheMoveState)}`}>
                {cacheMoveSummaryFor(cacheMoveState)}
              </span>
            {/if}
            {#if cacheMoveStatus}
              <span class="muted">{cacheMoveStatus}</span>
            {/if}
          </div>
        {/if}
      </div>
    {/if}
  </section>
  <div class="row">
    <button onclick={onApplySettings} disabled={cacheMoveState === 'in_flight'}>Apply Settings</button>
    <span class="muted">{settingsStatus}</span>
  </div>
</article>
