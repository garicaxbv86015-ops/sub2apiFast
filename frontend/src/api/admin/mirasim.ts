/**
 * Admin Mirasim API endpoints
 * Handles Mirasim Auth (OAuth / Email Code / Refresh / Local Import) flows for administrators
 */

import { apiClient } from '../client'

export interface MirasimAuthUrlResponse {
  auth_url: string
  session_id: string
  state: string
}

export interface MirasimAuthUrlRequest {
  provider?: string
  redirect_uri?: string
  proxy_id?: number
}

export interface MirasimExchangeCodeRequest {
  session_id?: string
  state?: string
  code?: string
  raw_callback_input?: string
  proxy_id?: number
}

export interface MirasimSendEmailCodeRequest {
  email: string
  proxy_id?: number
}

export interface MirasimSendEmailCodeResponse {
  dev_code: string
  message: string
}

export interface MirasimVerifyEmailCodeRequest {
  email: string
  code: string
  proxy_id?: number
}

export interface MirasimTokenInfo {
  access_token: string
  refresh_token?: string
  expires_in?: number
  expires_at?: number
  email?: string
  name?: string
  plan?: string
  plan_exp?: any
  device_id?: string
  private_key?: string
  public_key_b64?: string
  [key: string]: unknown
}

export async function generateAuthUrl(
  payload: MirasimAuthUrlRequest
): Promise<MirasimAuthUrlResponse> {
  const { data } = await apiClient.post<MirasimAuthUrlResponse>(
    '/admin/mirasim/oauth/auth-url',
    payload
  )
  return data
}

export async function exchangeCode(
  payload: MirasimExchangeCodeRequest
): Promise<MirasimTokenInfo> {
  const { data } = await apiClient.post<MirasimTokenInfo>(
    '/admin/mirasim/oauth/exchange-code',
    payload
  )
  return data
}

export async function sendEmailCode(
  payload: MirasimSendEmailCodeRequest
): Promise<MirasimSendEmailCodeResponse> {
  const { data } = await apiClient.post<MirasimSendEmailCodeResponse>(
    '/admin/mirasim/oauth/send-code',
    payload
  )
  return data
}

export async function verifyEmailCode(
  payload: MirasimVerifyEmailCodeRequest
): Promise<MirasimTokenInfo> {
  const { data } = await apiClient.post<MirasimTokenInfo>(
    '/admin/mirasim/oauth/verify-code',
    payload
  )
  return data
}

export async function refreshMirasimToken(
  refreshToken: string,
  proxyId?: number | null
): Promise<MirasimTokenInfo> {
  const payload: Record<string, any> = { refresh_token: refreshToken }
  if (proxyId) payload.proxy_id = proxyId

  const { data } = await apiClient.post<MirasimTokenInfo>(
    '/admin/mirasim/oauth/refresh-token',
    payload
  )
  return data
}

export async function importLocalMirasim(): Promise<MirasimTokenInfo> {
  const { data } = await apiClient.post<MirasimTokenInfo>(
    '/admin/mirasim/oauth/import-local',
    {}
  )
  return data
}

export default {
  generateAuthUrl,
  exchangeCode,
  sendEmailCode,
  verifyEmailCode,
  refreshMirasimToken,
  importLocalMirasim
}
