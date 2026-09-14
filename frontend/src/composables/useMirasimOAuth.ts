import { ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { useAppStore } from '@/stores/app'
import { adminAPI } from '@/api/admin'
import type { MirasimTokenInfo } from '@/api/admin/mirasim'
import { MIRASIM_BASE_URL } from '@/components/account/credentialsBuilder'

export function useMirasimOAuth() {
  const appStore = useAppStore()
  const { t } = useI18n()

  const authUrl = ref('')
  const sessionId = ref('')
  const state = ref('')
  const loading = ref(false)
  const error = ref('')

  // 邮箱验证码状态
  const email = ref('')
  const devCode = ref('')
  const emailCodeSent = ref(false)

  // 重置状态
  const resetState = () => {
    authUrl.value = ''
    sessionId.value = ''
    state.value = ''
    loading.value = false
    error.value = ''
    email.value = ''
    devCode.value = ''
    emailCodeSent.value = false
  }

  // 生成 OAuth 授权 URL
  const generateAuthUrl = async (
    proxyId?: number | null,
    provider: string = 'github',
    redirectUri?: string
  ): Promise<boolean> => {
    loading.value = true
    authUrl.value = ''
    sessionId.value = ''
    state.value = ''
    error.value = ''

    try {
      const payload: Record<string, unknown> = { provider }
      if (proxyId) payload.proxy_id = proxyId
      if (redirectUri) payload.redirect_uri = redirectUri

      const response = await adminAPI.mirasim.generateAuthUrl(payload as any)
      authUrl.value = response.auth_url
      sessionId.value = response.session_id
      state.value = response.state
      return true
    } catch (err: any) {
      error.value =
        err.response?.data?.detail || t('admin.accounts.oauth.mirasim.failedToGenerateUrl')
      appStore.showError(error.value)
      return false
    } finally {
      loading.value = false
    }
  }

  // 通过授权码/回调 URL 换取 Token 并自动派生设备公私钥
  const exchangeAuthCode = async (params: {
    code?: string
    rawCallbackInput?: string
    sessionId?: string
    state?: string
    proxyId?: number | null
  }): Promise<MirasimTokenInfo | null> => {
    loading.value = true
    error.value = ''

    try {
      const payload: Record<string, unknown> = {}
      if (params.code) payload.code = params.code.trim()
      if (params.rawCallbackInput) payload.raw_callback_input = params.rawCallbackInput.trim()
      if (params.sessionId) payload.session_id = params.sessionId.trim()
      if (params.state) payload.state = params.state.trim()
      if (params.proxyId) payload.proxy_id = params.proxyId

      const tokenInfo = await adminAPI.mirasim.exchangeCode(payload as any)
      return tokenInfo
    } catch (err: any) {
      error.value =
        err.response?.data?.detail || t('admin.accounts.oauth.mirasim.failedToExchangeCode')
      appStore.showError(error.value)
      return null
    } finally {
      loading.value = false
    }
  }

  // 发送邮箱验证码
  const sendEmailCode = async (
    targetEmail: string,
    proxyId?: number | null
  ): Promise<boolean> => {
    const trimmed = targetEmail.trim()
    if (!trimmed) {
      error.value = t('admin.accounts.oauth.mirasim.pleaseEnterEmail')
      return false
    }

    loading.value = true
    error.value = ''

    try {
      const payload: Record<string, unknown> = { email: trimmed }
      if (proxyId) payload.proxy_id = proxyId

      const res = await adminAPI.mirasim.sendEmailCode(payload as any)
      email.value = trimmed
      devCode.value = res.dev_code || ''
      emailCodeSent.value = true
      return true
    } catch (err: any) {
      error.value =
        err.response?.data?.detail || t('admin.accounts.oauth.mirasim.failedToSendCode')
      appStore.showError(error.value)
      return false
    } finally {
      loading.value = false
    }
  }

  // 验证邮箱验证码并换取 Token
  const verifyEmailCode = async (
    targetEmail: string,
    code: string,
    proxyId?: number | null
  ): Promise<MirasimTokenInfo | null> => {
    const trimmedEmail = targetEmail.trim()
    const trimmedCode = code.trim()
    if (!trimmedEmail || !trimmedCode) {
      error.value = t('admin.accounts.oauth.mirasim.missingEmailOrCode')
      return null
    }

    loading.value = true
    error.value = ''

    try {
      const payload: Record<string, unknown> = {
        email: trimmedEmail,
        code: trimmedCode
      }
      if (proxyId) payload.proxy_id = proxyId

      const tokenInfo = await adminAPI.mirasim.verifyEmailCode(payload as any)
      return tokenInfo
    } catch (err: any) {
      error.value =
        err.response?.data?.detail || t('admin.accounts.oauth.mirasim.failedToVerifyCode')
      appStore.showError(error.value)
      return null
    } finally {
      loading.value = false
    }
  }

  // 校验或刷新 Refresh Token
  const validateRefreshToken = async (
    refreshToken: string,
    proxyId?: number | null
  ): Promise<MirasimTokenInfo | null> => {
    if (!refreshToken.trim()) {
      error.value = t('admin.accounts.oauth.mirasim.pleaseEnterRefreshToken')
      return null
    }

    loading.value = true
    error.value = ''

    try {
      const tokenInfo = await adminAPI.mirasim.refreshMirasimToken(
        refreshToken.trim(),
        proxyId
      )
      return tokenInfo
    } catch (err: any) {
      error.value =
        err.response?.data?.detail || t('admin.accounts.oauth.mirasim.failedToValidateRT')
      return null
    } finally {
      loading.value = false
    }
  }

  // 一键导入本机 Mirasim.app 凭据
  const importLocalMirasim = async (): Promise<MirasimTokenInfo | null> => {
    loading.value = true
    error.value = ''

    try {
      const tokenInfo = await adminAPI.mirasim.importLocalMirasim()
      return tokenInfo
    } catch (err: any) {
      error.value =
        err.response?.data?.detail || t('admin.accounts.oauth.mirasim.failedToImportLocal')
      appStore.showError(error.value)
      return null
    } finally {
      loading.value = false
    }
  }

  // 构建完整的 Account credentials 存储字典
  const buildCredentials = (
    tokenInfo: MirasimTokenInfo,
    fallbackRefreshToken?: string
  ): Record<string, unknown> => {
    const refreshToken = tokenInfo.refresh_token?.trim()
      ? tokenInfo.refresh_token
      : fallbackRefreshToken

    const credentials: Record<string, unknown> = {
      api_key: tokenInfo.access_token,
      issuer_token: tokenInfo.access_token,
      base_url: MIRASIM_BASE_URL,
      auth_type: 'oauth',
      ...(tokenInfo.private_key ? { private_key: tokenInfo.private_key } : {}),
      ...(tokenInfo.device_id ? { device_id: tokenInfo.device_id } : {}),
      ...(refreshToken ? { refresh_token: refreshToken } : {}),
      ...(tokenInfo.expires_at ? { expires_at: tokenInfo.expires_at } : {}),
      ...(tokenInfo.email ? { email: tokenInfo.email } : {}),
      ...(tokenInfo.name ? { name: tokenInfo.name } : {}),
      ...(tokenInfo.plan ? { plan: tokenInfo.plan } : {}),
      ...(tokenInfo.plan_exp != null ? { plan_exp: tokenInfo.plan_exp } : {})
    }

    return credentials
  }

  /**
   * 构建 Mirasim 账号额外信息字典 (extra)
   * @param tokenInfo Mirasim 令牌与用户信息
   * @returns 额外信息字典
   */
  const buildExtraInfo = (tokenInfo: MirasimTokenInfo): Record<string, unknown> => {
    const extra: Record<string, unknown> = {}
    if (tokenInfo.email) extra.email = tokenInfo.email
    if (tokenInfo.name) extra.name = tokenInfo.name
    if (tokenInfo.plan) extra.plan = tokenInfo.plan
    if (tokenInfo.plan_exp != null) extra.plan_exp = tokenInfo.plan_exp
    return extra
  }

  return {
    authUrl,
    sessionId,
    state,
    loading,
    error,
    email,
    devCode,
    emailCodeSent,
    resetState,
    generateAuthUrl,
    exchangeAuthCode,
    sendEmailCode,
    verifyEmailCode,
    validateRefreshToken,
    importLocalMirasim,
    buildCredentials,
    buildExtraInfo
  }
}
