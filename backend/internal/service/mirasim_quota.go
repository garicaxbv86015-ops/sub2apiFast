package service

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// mirasimQuotaWindows 按最终模型返回共享窗口及所属家族窗口；Fable 同时受 Claude 总额度约束。
func mirasimQuotaWindows(model string) []string {
	windows := []string{"5h", "7d"}
	model = normalizeMirasimModelID(model)
	if strings.HasPrefix(model, "claude-") {
		windows = append(windows, "7d_claude")
		if isAnthropicFableModel(model) {
			windows = append(windows, "7d_fable")
		}
	}
	return windows
}

// mirasimQuotaRemaining 读取真实用量快照，按适用窗口中最晚的重置时间恢复调度。
func (a *Account) mirasimQuotaRemaining(requestedModel string, now time.Time) time.Duration {
	if !a.IsMirasim() {
		return 0
	}
	remaining := time.Duration(0)
	for _, window := range mirasimQuotaWindows(a.GetMappedModel(requestedModel)) {
		if schedulingPercentValue(a.Extra["mirasim_"+window+"_used_percent"]) < 100 {
			continue
		}
		reset := parseSchedulingResetAt(a.Extra["mirasim_"+window+"_reset_at"])
		if reset != nil && reset.Sub(now) > remaining {
			remaining = reset.Sub(now)
		}
	}
	return remaining
}

// persistMirasimExhaustedWindow 处理明确的额度耗尽错误，复用模型级限流，避免家族额度耗尽误停 GPT。
// 重置时间仅使用对应窗口快照或上游 Retry-After；缺失时告警，不猜测冷却时长。
func (s *RateLimitService) persistMirasimExhaustedWindow(ctx context.Context, account *Account, headers http.Header, body []byte) bool {
	if !account.IsMirasim() {
		return false
	}
	code := extractUpstreamErrorCode(body)
	window, exhausted := strings.CutPrefix(code, "credit_exhausted_")
	if !exhausted {
		return false
	}
	switch window {
	case "5h", "7d", "7d_claude", "7d_fable":
	default:
		return false
	}
	now := time.Now()
	reset := parseSchedulingResetAt(account.Extra["mirasim_"+window+"_reset_at"])
	if reset == nil || !reset.After(now) {
		reset = parseRetryAfterResetTime(headers, now)
	}
	if reset == nil || !reset.After(now) {
		slog.Warn("mirasim_quota_reset_missing", "account_id", account.ID, "window", window, "error_code", code)
		return true
	}
	scope := "mirasim:"+window
	// 同一窗口的较早响应不能缩短已经确认的冷却。
	if current := account.modelRateLimitResetAt(scope); current != nil && current.After(*reset) {
		reset = current
	}
	setAccountModelRateLimitSnapshot(account, scope, *reset, code, now)
	if err := s.accountRepo.SetModelRateLimit(ctx, account.ID, scope, *reset, code); err != nil {
		slog.Error("mirasim_quota_limit_persist_failed", "account_id", account.ID, "window", window, "error", err)
		return true
	}
	slog.Warn("mirasim_quota_window_exhausted", "account_id", account.ID, "window", window, "reset_at", reset.UTC())
	return true
}
