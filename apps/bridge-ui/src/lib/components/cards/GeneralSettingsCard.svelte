<script lang="ts">
  import type { AppSettings } from '../../api/bridge'

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
    onApplySettings = () => {},
  }: {
    appSettings: AppSettings
    diskCachePathInput?: string
    colorSchemeNameInput?: string
    settingsStatus?: string
    onApplySettings?: () => void
  } = $props()
</script>

<article class="card span-2">
  <h2>General Settings</h2>
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
    <label class="grow">
      Disk Cache Path
      <input bind:value={diskCachePathInput} placeholder="/path/to/cache" />
    </label>
    <label>
      Color Scheme
      <select bind:value={colorSchemeNameInput}>
        <option value="system">system</option>
        <option value="light">light</option>
        <option value="dark">dark</option>
      </select>
    </label>
  </div>
  <div class="row">
    <button onclick={onApplySettings}>Apply Settings</button>
    <span class="muted">{settingsStatus}</span>
  </div>
</article>
