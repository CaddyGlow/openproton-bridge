import { fireEvent, render, screen } from '@testing-library/svelte'
import { describe, expect, it, vi } from 'vitest'
import GeneralSettingsCard from './GeneralSettingsCard.svelte'

const baseAppSettings = {
  is_autostart_on: false,
  is_beta_enabled: false,
  is_all_mail_visible: true,
  is_telemetry_disabled: false,
  disk_cache_path: '/tmp/cache',
  is_doh_enabled: true,
  color_scheme_name: 'system',
}

describe('GeneralSettingsCard', () => {
  it('supports prop-driven expanded and collapsed sections', async () => {
    const onToggleSection = vi.fn()

    render(GeneralSettingsCard, {
      props: {
        appSettings: { ...baseAppSettings },
        expandedSections: {
          preferences: false,
          cache: true,
        },
        onToggleSection,
      },
    })

    const preferencesToggle = screen.getByRole('button', { name: 'Preferences' })
    expect(preferencesToggle).toHaveAttribute('aria-expanded', 'false')
    expect(screen.queryByLabelText('Autostart')).not.toBeInTheDocument()
    expect(screen.getByLabelText('Disk Cache Path')).toBeInTheDocument()

    await fireEvent.click(preferencesToggle)
    expect(onToggleSection).toHaveBeenCalledWith('preferences', true)
  })

  it('renders in-flight cache move state and disables apply action', () => {
    render(GeneralSettingsCard, {
      props: {
        appSettings: { ...baseAppSettings },
        cacheMoveState: 'in_flight',
      },
    })

    expect(screen.getByText('Moving cache path...')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Apply Settings' })).toBeDisabled()
  })

  it('renders success and failure cache move states from props', async () => {
    const { rerender } = render(GeneralSettingsCard, {
      props: {
        appSettings: { ...baseAppSettings },
        cacheMoveState: 'success',
        cacheMoveStatus: 'Moved to /tmp/new-cache',
      },
    })

    expect(screen.getByText('Cache move completed.')).toBeInTheDocument()
    expect(screen.getByText('Moved to /tmp/new-cache')).toBeInTheDocument()

    await rerender({
      appSettings: { ...baseAppSettings },
      cacheMoveState: 'failure',
      cacheMoveStatus: 'Permission denied',
    })

    expect(screen.getByText('Cache move failed.')).toBeInTheDocument()
    expect(screen.getByText('Permission denied')).toBeInTheDocument()
  })
})
