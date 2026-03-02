<script lang="ts">
  import type { AppSettings } from '../../api/bridge'

  type SettingsSectionId = 'preferences' | 'cache'
  type CacheMoveState = 'idle' | 'in_flight' | 'success' | 'failure'

  const defaultAppSettings: AppSettings = {
    is_autostart_on: false,
    is_beta_enabled: false,
    is_all_mail_visible: true,
    is_telemetry_disabled: false,
    disk_cache_path: '',
    is_doh_enabled: true,
    color_scheme_name: 'system',
  }

  let {
    appSettings = $bindable({ ...defaultAppSettings }),
    diskCachePathInput = $bindable(''),
    colorSchemeNameInput = $bindable('system'),
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
    settingsStatus?: string
    expandedSections?: Partial<Record<SettingsSectionId, boolean>>
    cacheMoveState?: CacheMoveState
    cacheMoveStatus?: string
    onToggleSection?: (section: SettingsSectionId, nextExpanded: boolean) => void
    onApplySettings?: () => void
  } = $props()

  const defaultExpandedSections: Record<SettingsSectionId, boolean> = {
    preferences: true,
    cache: true,
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
        aria-expanded={isSectionExpanded('preferences')}
        aria-controls="general-settings-preferences"
        onclick={() => toggleSection('preferences')}
      >
        Preferences
      </button>
    </div>
    {#if isSectionExpanded('preferences')}
      <div id="general-settings-preferences">
        <div class="row wrap">
          <label class="checkbox">
            <input type="checkbox" bind:checked={appSettings.is_autostart_on} />
            Autostart
          </label>
          <label class="checkbox">
            <input type="checkbox" bind:checked={appSettings.is_beta_enabled} />
            Beta Channel
          </label>
          <label class="checkbox">
            <input type="checkbox" bind:checked={appSettings.is_all_mail_visible} />
            All Mail Visible
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
        aria-expanded={isSectionExpanded('cache')}
        aria-controls="general-settings-cache"
        onclick={() => toggleSection('cache')}
      >
        Cache
      </button>
    </div>
    {#if isSectionExpanded('cache')}
      <div id="general-settings-cache">
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
