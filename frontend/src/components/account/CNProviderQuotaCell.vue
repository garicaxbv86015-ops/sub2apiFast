<template>
  <div
    v-if="visible"
    data-test="cn-provider-quota"
    class="min-w-[220px] space-y-1"
  >
    <!-- Tier rows: 5h + weekly utilization bars (snapshot renders on mount).
         复用账号页 UsageProgressBar：同阈值配色、同倒计时格式。
         Mirasim 有「7d Claude / 7d Fable」长标签，整格统一用加宽徽章保证纵向对齐；
         title 透传到行根节点，悬浮可查看窗口含义。 -->
    <div v-if="data?.success && data.tiers?.length" class="space-y-1">
      <UsageProgressBar
        v-for="tier in data.tiers"
        :key="tier.window"
        data-test="cn-provider-quota-tier"
        :label="windowLabel(tier.window)"
        :title="windowTooltip(tier.window)"
        :label-width="labelWidthMode"
        :color="windowColor(tier.window)"
        :utilization="tier.used_percent"
        :resets-at="tier.reset_at"
      />
    </div>

    <!-- Explicit refresh action (aligned with the OpenAI "Query" / Grok "Probe"
         buttons): a verb label tells users this chip is clickable. The previous
         noun label ("5h/weekly") read as a passive caption and users could not
         discover the manual refresh. -->
    <div class="flex flex-wrap items-center gap-1.5">
      <button
        type="button"
        data-test="cn-provider-quota-probe"
        class="inline-flex items-center gap-0.5 whitespace-nowrap rounded px-1.5 py-0.5 text-[10px] font-medium leading-4 text-blue-600 transition-colors hover:bg-blue-50 disabled:cursor-not-allowed disabled:opacity-50 dark:text-blue-400 dark:hover:bg-blue-900/30"
        :disabled="loading"
        :title="t('admin.accounts.cnProviders.probeTooltip')"
        @click="handleProbe()"
      >
        <svg
          class="h-2.5 w-2.5"
          :class="{ 'animate-spin': loading }"
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
        >
          <path
            stroke-linecap="round"
            stroke-linejoin="round"
            stroke-width="2"
            d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"
          />
        </svg>
        {{ t('admin.accounts.cnProviders.probe') }}
      </button>
    </div>

    <div
      v-if="error"
      class="truncate text-[10px] leading-4 text-red-600 dark:text-red-400"
      :title="error"
    >
      {{ truncatedError }}
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { adminAPI } from '@/api/admin'
import type { CNProviderQuotaProbeResult } from '@/api/admin/cnProviders'
import type { Account } from '@/types'
import { cnQuotaCellVisible } from './credentialsBuilder'
import UsageProgressBar from './UsageProgressBar.vue'

const props = defineProps<{
  account: Account
}>()

const { t } = useI18n()

const readMode = (): string => {
  const mode = props.account.credentials?.account_mode
  return typeof mode === 'string' ? mode : ''
}

const visible = computed(() => cnQuotaCellVisible(props.account.platform, readMode()))

const loading = ref(false)
const error = ref<string | null>(null)
const data = ref<CNProviderQuotaProbeResult | null>(null)

// 后端周期任务/手动探测写入的 extra 快照键（<provider>_ 前缀，与后端
// cnQuotaExtraUpdates 对齐）。页面加载即有数据，无需等待探测。
const SNAPSHOT_STALE_MS = 15 * 60 * 1000

// 自动探测去抖窗口与最近一次自动探测时间（模块级，跨实例共享）。
const AUTO_PROBE_DEBOUNCE_MS = 5 * 60 * 1000
const lastAutoProbeAt = new Map<number, number>()

const readExtraNumber = (key: string): number | null => {
  const v = (props.account.extra as Record<string, unknown> | undefined)?.[key]
  return typeof v === 'number' && Number.isFinite(v) ? v : null
}

const readExtraString = (key: string): string => {
  const v = (props.account.extra as Record<string, unknown> | undefined)?.[key]
  return typeof v === 'string' ? v : ''
}

// 从持久化快照构造展示数据（缺少任何已知窗口键时返回 null）。
// Mirasim 除标准 5h 外还有 7d / 7d_claude / 7d_fable 等扩展窗口，按名读取。
const MIRASIM_EXTRA_WINDOWS = ['7d', '7d_claude', '7d_fable'] as const

const snapshotData = computed<CNProviderQuotaProbeResult | null>(() => {
  const platform = props.account.platform
  const used5h = readExtraNumber(`${platform}_5h_used_percent`)
  const usedWeekly = readExtraNumber(`${platform}_weekly_used_percent`)
  const usedMonthly = readExtraNumber(`${platform}_monthly_used_percent`)
  const tiers: CNProviderQuotaProbeResult['tiers'] = []
  if (used5h != null) {
    tiers.push({ window: '5h', used_percent: used5h, reset_at: readExtraString(`${platform}_5h_reset_at`) || undefined })
  }
  if (usedWeekly != null) {
    tiers.push({ window: 'weekly', used_percent: usedWeekly, reset_at: readExtraString(`${platform}_weekly_reset_at`) || undefined })
  }
  if (usedMonthly != null) {
    tiers.push({ window: 'monthly', used_percent: usedMonthly, reset_at: readExtraString(`${platform}_monthly_reset_at`) || undefined })
  }
  // Mirasim 扩展窗口（后端 cnQuotaExtraUpdates 按 window 名落 <platform>_<window>_used_percent）
  if (platform === 'mirasim') {
    for (const w of MIRASIM_EXTRA_WINDOWS) {
      const used = readExtraNumber(`${platform}_${w}_used_percent`)
      if (used != null) {
        tiers.push({ window: w, used_percent: used, reset_at: readExtraString(`${platform}_${w}_reset_at`) || undefined })
      }
    }
  }
  if (tiers.length === 0) return null
  return { success: true, tiers } as CNProviderQuotaProbeResult
})

// 快照是否过期（无更新时间或超过 staleness 窗口）→ 挂载时需要自动探测。
const snapshotIsStale = computed(() => {
  const updatedAt = readExtraString(`${props.account.platform}_usage_updated_at`)
  if (!updatedAt) return true
  const ts = new Date(updatedAt).getTime()
  return Number.isNaN(ts) || Date.now() - ts > SNAPSHOT_STALE_MS
})

// 挂载时：先用持久化快照渲染；快照缺失或过期再自动探测一次（失败显示错误，
// 避免静默失败导致单元格空白无提示）。
onMounted(() => {
  if (!visible.value) return
  data.value = snapshotData.value
  if (!snapshotIsStale.value) return
  // 模块级去抖：列表页每行一个实例，翻页/筛选/刷新会重复挂载；同一账号
  // 短时间内已自动探测过则跳过，避免对上游形成探测风暴。
  const last = lastAutoProbeAt.get(props.account.id) ?? 0
  if (Date.now() - last < AUTO_PROBE_DEBOUNCE_MS) return
  lastAutoProbeAt.set(props.account.id, Date.now())
  handleProbe()
})

const extractErrorMessage = (e: unknown): string => {
  const err = e as {
    message?: string
    reason?: string
    response?: { data?: { message?: string; error?: string } }
  }
  return (
    err?.message ||
    err?.reason ||
    err?.response?.data?.message ||
    err?.response?.data?.error ||
    t('common.error')
  )
}

const truncatedError = computed(() => {
  if (!error.value) return ''
  return error.value.length > 80 ? `${error.value.slice(0, 80)}...` : error.value
})

// 标签徽章宽度：Mirasim 含「7d Claude / 7d Fable」长标签，整格用 wide 加宽定宽
// （同格及跨行进度条纵向对齐）；其余 CN 平台标签均为短标签，保持默认 fixed。
const labelWidthMode = computed<'fixed' | 'wide'>(() =>
  props.account.platform === 'mirasim' ? 'wide' : 'fixed'
)

/**
 * 窗口名 → 徽章展示文案。
 * @param window 后端窗口名（5h / weekly / monthly / Mirasim 的 7d / 7d_claude / 7d_fable）
 * @returns 本地化后的短标签；未知的 Mirasim 扩展窗口原样透传
 */
const windowLabel = (window: string) => {
  // Mirasim 的 7d 与标准 weekly 同义，统一显示为周窗口文案。
  if (window === 'weekly' || window === '7d') return t('admin.accounts.cnProviders.windowWeekly')
  if (window === 'monthly') return t('admin.accounts.cnProviders.windowMonthly')
  // Mirasim 模型家族周窗口：原生名带下划线（7d_claude）可读性差，换成「7d Claude」类文案。
  if (window === '7d_claude') return t('admin.accounts.cnProviders.window7dClaude')
  if (window === '7d_fable') return t('admin.accounts.cnProviders.window7dFable')
  // 后端新增的其他扩展窗口：原样透传，避免被误标成 5h。
  if (window.startsWith('7d')) return window
  return t('admin.accounts.cnProviders.window5h')
}

/**
 * 窗口名 → 悬浮说明（解释窗口含义及计入范围）。
 * @param window 后端窗口名
 * @returns 本地化说明文案；未知窗口返回原窗口名
 */
const windowTooltip = (window: string) => {
  if (window === '5h') return t('admin.accounts.cnProviders.window5hTooltip')
  if (window === 'weekly' || window === '7d') return t('admin.accounts.cnProviders.windowWeeklyTooltip')
  if (window === 'monthly') return t('admin.accounts.cnProviders.windowMonthlyTooltip')
  if (window === '7d_claude') return t('admin.accounts.cnProviders.window7dClaudeTooltip')
  if (window === '7d_fable') return t('admin.accounts.cnProviders.window7dFableTooltip')
  return window
}

/**
 * 窗口名 → 徽章配色：5h/月 靛蓝、周 翠绿；Mirasim 模型家族窗口分别用紫/琥珀，
 * 与共享周窗口区分开，一眼可辨是哪类额度。
 * @param window 后端窗口名
 * @returns UsageProgressBar 支持的色板名
 */
const windowColor = (window: string): 'indigo' | 'emerald' | 'purple' | 'amber' => {
  if (window === '7d_claude') return 'purple'
  if (window === '7d_fable') return 'amber'
  if (window === 'weekly' || window.startsWith('7d')) return 'emerald'
  return 'indigo'
}

const handleProbe = async () => {
  if (loading.value) return
  loading.value = true
  error.value = null
  try {
    const result = await adminAPI.cnProviders.queryQuota(props.account.id)
    // 失败时保留已渲染的快照条形图（仅显示错误行），成功才覆盖。
    if (result.success) {
      data.value = result
    } else {
      error.value = result.error || t('common.error')
    }
  } catch (e) {
    error.value = extractErrorMessage(e)
  } finally {
    loading.value = false
  }
}

watch(
  () => props.account.id,
  () => {
    data.value = null
    error.value = null
    loading.value = false
  }
)
</script>
