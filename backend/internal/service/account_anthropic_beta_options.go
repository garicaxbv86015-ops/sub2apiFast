package service

import (
	"net/http"
	"strings"

	"github.com/Wei-Shaw/sub2api/internal/pkg/claude"
)

const (
	anthropicDisableBetaExtraKey     = "anthropic_disable_beta"
	anthropicEnable1MContextExtraKey = "anthropic_enable_1m_context"
)

// supportsAnthropicAPIKeyBetaOptions 判断账号是否支持 Anthropic API Key 专属 beta 配置。
// 参数 account 为待判断的账号；返回值表示该账号是否可应用 beta 配置。
func supportsAnthropicAPIKeyBetaOptions(account *Account) bool {
	return account != nil && account.Platform == PlatformAnthropic && account.Type == AccountTypeAPIKey
}

// IsAnthropicBetaDisabled 判断账号是否要求移除所有 anthropic-beta 请求头。
// 参数为方法接收者账号；返回值表示关闭 beta 配置是否已启用。
func (a *Account) IsAnthropicBetaDisabled() bool {
	if !supportsAnthropicAPIKeyBetaOptions(a) || a.Extra == nil {
		return false
	}
	enabled, ok := a.Extra[anthropicDisableBetaExtraKey].(bool)
	return ok && enabled
}

// IsAnthropic1MContextEnabled 判断账号是否要求追加 1M 上下文 beta。
// 参数为方法接收者账号；返回值表示 1M 上下文配置是否已启用。
func (a *Account) IsAnthropic1MContextEnabled() bool {
	if !supportsAnthropicAPIKeyBetaOptions(a) || a.Extra == nil {
		return false
	}
	enabled, ok := a.Extra[anthropicEnable1MContextExtraKey].(bool)
	return ok && enabled
}

// resolveAnthropicAPIKeyBetaOptions 根据账号配置计算最终 anthropic-beta 请求头。
// 参数 account 为账号，betaHeader 为现有 beta 值，shouldSet 表示现有值是否需要发送；返回值为最终 beta 值及是否发送。
func resolveAnthropicAPIKeyBetaOptions(account *Account, betaHeader string, shouldSet bool) (string, bool) {
	if !supportsAnthropicAPIKeyBetaOptions(account) {
		return betaHeader, shouldSet
	}

	// 关闭 beta 的优先级最高，避免后续客户端透传或请求头覆写重新引入不兼容 token。
	if account.IsAnthropicBetaDisabled() {
		return "", false
	}
	if !account.IsAnthropic1MContextEnabled() {
		return betaHeader, shouldSet
	}

	return appendAnthropicBetaToken(betaHeader, claude.BetaContext1M), true
}

// appendAnthropicBetaToken 在保留原有顺序的前提下追加 beta token 并去重。
// 参数 betaHeader 为现有 beta 值，token 为待追加 token；返回值为规范化后的 beta 值。
func appendAnthropicBetaToken(betaHeader, token string) string {
	seen := make(map[string]struct{})
	result := make([]string, 0, len(parseAnthropicBetaHeader(betaHeader))+1)
	// add 负责跳过空值与重复值，并保留第一次出现的 token 顺序。
	add := func(value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		if _, exists := seen[value]; exists {
			return
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}

	for _, value := range parseAnthropicBetaHeader(betaHeader) {
		add(value)
	}
	add(token)
	return strings.Join(result, ",")
}

// writeResolvedAnthropicBetaHeader 将已计算的 beta 结果写入 HTTP 请求头。
// 参数 header 为目标请求头，betaHeader 为最终 beta 值，shouldSet 表示是否发送该请求头；无返回值。
func writeResolvedAnthropicBetaHeader(header http.Header, betaHeader string, shouldSet bool) {
	deleteHeaderAllForms(header, "anthropic-beta")
	if shouldSet {
		setHeaderRaw(header, "anthropic-beta", betaHeader)
	}
}
