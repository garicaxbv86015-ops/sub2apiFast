import { describe, expect, it, vi } from 'vitest'

vi.mock('@/stores/app', () => ({
  useAppStore: () => ({
    showError: vi.fn()
  })
}))

vi.mock('vue-i18n', () => ({
  useI18n: () => ({
    t: (key: string) => key
  })
}))

vi.mock('@/api/admin', () => ({
  adminAPI: {
    mirasim: {
      generateAuthUrl: vi.fn(),
      exchangeCode: vi.fn(),
      sendEmailCode: vi.fn(),
      verifyEmailCode: vi.fn(),
      refreshMirasimToken: vi.fn(),
      importLocalMirasim: vi.fn()
    }
  }
}))

import { useMirasimOAuth } from '@/composables/useMirasimOAuth'

describe('useMirasimOAuth.buildCredentials', () => {
  it('builds full credentials including device keys and fallback refresh token', () => {
    const oauth = useMirasimOAuth()

    const credentials = oauth.buildCredentials(
      {
        access_token: 'mrs-access-token',
        expires_at: 1_900_000_000,
        private_key: 'pem-private-key',
        device_id: 'device-uuid-1234',
        email: 'user@example.com',
        name: 'Mirasim User',
        plan: 'cloud_unlimited'
      },
      'fallback-refresh-token'
    )

    expect(credentials.api_key).toBe('mrs-access-token')
    expect(credentials.issuer_token).toBe('mrs-access-token')
    expect(credentials.auth_type).toBe('oauth')
    expect(credentials.base_url).toBe('https://relay.mirasim.ai')
    expect(credentials.refresh_token).toBe('fallback-refresh-token')
    expect(credentials.private_key).toBe('pem-private-key')
    expect(credentials.device_id).toBe('device-uuid-1234')
    expect(credentials.email).toBe('user@example.com')
    expect(credentials.name).toBe('Mirasim User')
    expect(credentials.plan).toBe('cloud_unlimited')
  })

  it('prefers a new refresh token returned by the response', () => {
    const oauth = useMirasimOAuth()

    const credentials = oauth.buildCredentials(
      {
        access_token: 'mrs-access-token',
        refresh_token: 'new-refresh-token',
        expires_at: 1_900_000_000
      },
      'old-refresh-token'
    )

    expect(credentials.refresh_token).toBe('new-refresh-token')
  })
})
