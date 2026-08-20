//go:build unit

package service

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/pkg/claude"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

// newAnthropicAPIKeyAccountForBetaOptionTest 创建用于验证账号级 Anthropic beta 配置的 API Key 账号。
// 参数 extra 为写入账号扩展配置的开关集合；返回值为可构建上游请求的测试账号。
func newAnthropicAPIKeyAccountForBetaOptionTest(extra map[string]any) *Account {
	return &Account{
		ID:       908,
		Name:     "anthropic-beta-options-test",
		Platform: PlatformAnthropic,
		Type:     AccountTypeAPIKey,
		Credentials: map[string]any{
			"api_key": "upstream-key",
		},
		Extra:       extra,
		Status:      StatusActive,
		Schedulable: true,
	}
}

// newAnthropicBetaOptionTestContext 创建带可选 anthropic-beta 入站头的 Gin 测试上下文。
// 参数 beta 为模拟客户端发送的 beta 值；返回值为可用于构建上游请求的上下文。
func newAnthropicBetaOptionTestContext(beta string) *gin.Context {
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/v1/messages", nil)
	if beta != "" {
		ctx.Request.Header.Set("Anthropic-Beta", beta)
	}
	return ctx
}

// TestBuildUpstreamRequest_AnthropicAPIKeyDisableBeta 验证关闭 beta 会移除普通 messages 请求中的所有 beta。
// 参数由 Go testing 框架注入；返回值为空，断言失败时测试失败。
func TestBuildUpstreamRequest_AnthropicAPIKeyDisableBeta(t *testing.T) {
	account := newAnthropicAPIKeyAccountForBetaOptionTest(map[string]any{
		"anthropic_disable_beta": true,
	})
	svc := &GatewayService{cfg: &config.Config{}}

	req, _, err := svc.buildUpstreamRequest(
		context.Background(),
		newAnthropicBetaOptionTestContext(claude.BetaClaudeCode+",custom-beta"),
		account,
		[]byte(`{"model":"claude-opus-5","messages":[]}`),
		"upstream-key",
		"apikey",
		"claude-opus-5",
		false,
		false,
	)

	require.NoError(t, err)
	require.Empty(t, getHeaderRaw(req.Header, "anthropic-beta"), "关闭 beta 后不得把客户端或网关生成的 beta 发给上游")
}

// TestBuildUpstreamRequest_AnthropicAPIKeyEnableOneMillionContext 验证 1M 开关会追加并去重 beta。
// 参数由 Go testing 框架注入；返回值为空，断言失败时测试失败。
func TestBuildUpstreamRequest_AnthropicAPIKeyEnableOneMillionContext(t *testing.T) {
	account := newAnthropicAPIKeyAccountForBetaOptionTest(map[string]any{
		"anthropic_enable_1m_context": true,
	})
	svc := &GatewayService{cfg: &config.Config{}}
	ctx := newAnthropicBetaOptionTestContext("custom-beta," + claude.BetaContext1M + "," + claude.BetaContext1M)
	// 模拟默认全局策略会过滤非 Sonnet-5 的 1M beta；账号开关必须在该步骤之后补回它。
	ctx.Set(betaPolicyFilterSetKey, map[string]struct{}{claude.BetaContext1M: {}})

	req, _, err := svc.buildUpstreamRequest(
		context.Background(),
		ctx,
		account,
		[]byte(`{"model":"claude-fable-5","messages":[]}`),
		"upstream-key",
		"apikey",
		"claude-fable-5",
		false,
		false,
	)

	require.NoError(t, err)
	require.Equal(t, "custom-beta,"+claude.BetaContext1M, getHeaderRaw(req.Header, "anthropic-beta"),
		"1M 开关必须追加 context beta，并去除客户端携带的重复 token")
}

// TestBuildUpstreamRequest_AnthropicAPIKeyDisableBetaTakesPrecedence 验证两个开关同时开启时关闭 beta 优先。
// 参数由 Go testing 框架注入；返回值为空，断言失败时测试失败。
func TestBuildUpstreamRequest_AnthropicAPIKeyDisableBetaTakesPrecedence(t *testing.T) {
	account := newAnthropicAPIKeyAccountForBetaOptionTest(map[string]any{
		"anthropic_disable_beta":      true,
		"anthropic_enable_1m_context": true,
	})
	svc := &GatewayService{cfg: &config.Config{}}

	req, _, err := svc.buildUpstreamRequest(
		context.Background(),
		newAnthropicBetaOptionTestContext("custom-beta"),
		account,
		[]byte(`{"model":"claude-fable-5","messages":[]}`),
		"upstream-key",
		"apikey",
		"claude-fable-5",
		false,
		false,
	)

	require.NoError(t, err)
	require.Empty(t, getHeaderRaw(req.Header, "anthropic-beta"), "关闭 beta 必须优先于 1M 上下文开关")
}

// TestBuildUpstreamRequestAnthropicAPIKeyPassthrough_AppliesBetaOptions 验证自动透传 messages 出口也遵守账号级 beta 配置。
// 参数由 Go testing 框架注入；返回值为空，断言失败时测试失败。
func TestBuildUpstreamRequestAnthropicAPIKeyPassthrough_AppliesBetaOptions(t *testing.T) {
	t.Run("关闭 beta", func(t *testing.T) {
		account := newAnthropicAPIKeyAccountForBetaOptionTest(map[string]any{
			"anthropic_disable_beta": true,
			"anthropic_passthrough":  true,
		})
		svc := &GatewayService{cfg: &config.Config{}}

		req, _, err := svc.buildUpstreamRequestAnthropicAPIKeyPassthrough(
			context.Background(),
			newAnthropicBetaOptionTestContext(claude.BetaClaudeCode+",custom-beta"),
			account,
			[]byte(`{"model":"claude-opus-5","messages":[]}`),
			"upstream-key",
		)

		require.NoError(t, err)
		require.Empty(t, getHeaderRaw(req.Header, "anthropic-beta"))
	})

	t.Run("开启 1M 上下文", func(t *testing.T) {
		account := newAnthropicAPIKeyAccountForBetaOptionTest(map[string]any{
			"anthropic_enable_1m_context": true,
			"anthropic_passthrough":       true,
		})
		svc := &GatewayService{cfg: &config.Config{}}

		req, _, err := svc.buildUpstreamRequestAnthropicAPIKeyPassthrough(
			context.Background(),
			newAnthropicBetaOptionTestContext("custom-beta"),
			account,
			[]byte(`{"model":"claude-fable-5","messages":[]}`),
			"upstream-key",
		)

		require.NoError(t, err)
		require.Equal(t, "custom-beta,"+claude.BetaContext1M, getHeaderRaw(req.Header, "anthropic-beta"))
	})
}

// TestBuildCountTokensRequest_AnthropicAPIKeyAppliesBetaOptions 验证普通 count_tokens 出口遵守账号级 beta 配置。
// 参数由 Go testing 框架注入；返回值为空，断言失败时测试失败。
func TestBuildCountTokensRequest_AnthropicAPIKeyAppliesBetaOptions(t *testing.T) {
	account := newAnthropicAPIKeyAccountForBetaOptionTest(map[string]any{
		"anthropic_enable_1m_context": true,
	})
	svc := &GatewayService{cfg: &config.Config{}}

	req, _, err := svc.buildCountTokensRequest(
		context.Background(),
		newAnthropicBetaOptionTestContext("custom-beta"),
		account,
		[]byte(`{"model":"claude-fable-5","messages":[]}`),
		"upstream-key",
		"apikey",
		"claude-fable-5",
		false,
	)

	require.NoError(t, err)
	require.Equal(t, "custom-beta,"+claude.BetaContext1M, getHeaderRaw(req.Header, "anthropic-beta"))
}

// TestBuildCountTokensRequestAnthropicAPIKeyPassthrough_AppliesBetaOptions 验证自动透传 count_tokens 出口遵守账号级 beta 配置。
// 参数由 Go testing 框架注入；返回值为空，断言失败时测试失败。
func TestBuildCountTokensRequestAnthropicAPIKeyPassthrough_AppliesBetaOptions(t *testing.T) {
	account := newAnthropicAPIKeyAccountForBetaOptionTest(map[string]any{
		"anthropic_disable_beta": true,
		"anthropic_passthrough":  true,
	})
	svc := &GatewayService{cfg: &config.Config{}}

	req, err := svc.buildCountTokensRequestAnthropicAPIKeyPassthrough(
		context.Background(),
		newAnthropicBetaOptionTestContext(claude.BetaClaudeCode+",custom-beta"),
		account,
		[]byte(`{"model":"claude-opus-5","messages":[]}`),
		"upstream-key",
	)

	require.NoError(t, err)
	require.Empty(t, getHeaderRaw(req.Header, "anthropic-beta"))
}

// TestValidateAnthropicAPIKeyBetaOptionsExtra 验证管理接口仅接受 Anthropic API Key 账号的布尔 beta 配置。
// 参数由 Go testing 框架注入；返回值为空，断言失败时测试失败。
func TestValidateAnthropicAPIKeyBetaOptionsExtra(t *testing.T) {
	t.Run("有效布尔值", func(t *testing.T) {
		err := ValidateAnthropicAPIKeyBetaOptionsExtra(PlatformAnthropic, AccountTypeAPIKey, map[string]any{
			"anthropic_disable_beta":      true,
			"anthropic_enable_1m_context": false,
		})
		require.NoError(t, err)
	})

	t.Run("非法值被拒绝", func(t *testing.T) {
		err := ValidateAnthropicAPIKeyBetaOptionsExtra(PlatformAnthropic, AccountTypeAPIKey, map[string]any{
			"anthropic_enable_1m_context": "true",
		})
		require.Error(t, err)
	})

	t.Run("非目标账号忽略配置", func(t *testing.T) {
		err := ValidateAnthropicAPIKeyBetaOptionsExtra(PlatformOpenAI, AccountTypeAPIKey, map[string]any{
			"anthropic_enable_1m_context": "provider-owned",
		})
		require.NoError(t, err)
	})
}
