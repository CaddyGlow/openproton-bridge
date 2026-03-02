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
  current_keychain: 'secret-service',
  available_keychains: ['secret-service', 'pass'],
}

describe('GeneralSettingsCard', () => {
  it('supports prop-driven expanded and collapsed sections', async () => {
    const onToggleSection = vi.fn()

    render(GeneralSettingsCard, {
      props: {
        appSettings: { ...baseAppSettings },
        expandedSections: {
          general: false,
          advanced: true,
          maintenance: true,
        },
        onToggleSection,
      },
    })

    const generalToggle = screen.getByRole('button', { name: 'General' })
    expect(generalToggle).toHaveAttribute('aria-expanded', 'false')
    expect(screen.queryByLabelText('Autostart')).not.toBeInTheDocument()
    expect(screen.getByLabelText('Disk Cache Path')).toBeInTheDocument()

    await fireEvent.click(generalToggle)
    expect(onToggleSection).toHaveBeenCalledWith('general', true)
  })

  it('renders explicit settings group labels', () => {
    render(GeneralSettingsCard, {
      props: {
        appSettings: { ...baseAppSettings },
      },
    })

    expect(screen.getByRole('button', { name: 'General' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Advanced' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Maintenance' })).toBeInTheDocument()
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

  it('renders keychain selector options from app settings', () => {
    render(GeneralSettingsCard, {
      props: {
        appSettings: { ...baseAppSettings },
        currentKeychainInput: 'secret-service',
      },
    })

    const keychainSelect = screen.getByLabelText('Keychain')
    expect(keychainSelect).toHaveValue('secret-service')
    expect(screen.getByRole('option', { name: 'secret-service' })).toBeInTheDocument()
    expect(screen.getByRole('option', { name: 'pass' })).toBeInTheDocument()
  })
})
