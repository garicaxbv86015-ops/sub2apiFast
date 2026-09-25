package service

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

// mirasimCapacityBody 是中继模型容量降载的典型响应体。
const mirasimCapacityBody = `{"error":{"type":"api_error","message":"no upstream available for model \"claude-opus-5-5\""}}`

// TestIsMirasimRelayModelCapacityExhausted 覆盖中继模型容量降载的识别边界。
func TestIsMirasimRelayModelCapacityExhausted(t *testing.T) {
	mirasim := &Account{Platform: PlatformMirasim}
	openai := &Account{Platform: PlatformOpenAI}

	t.Run("503 加文案命中", func(t *testing.T) {
		require.True(t, isMirasimRelayModelCapacityExhausted(
			mirasim, http.StatusServiceUnavailable, `no upstream available for model "claude-opus-5-5"`, []byte(mirasimCapacityBody)))
	})

	t.Run("仅凭响应体也能命中", func(t *testing.T) {
		require.True(t, isMirasimRelayModelCapacityExhausted(
			mirasim, http.StatusServiceUnavailable, "", []byte(mirasimCapacityBody)))
	})

	t.Run("结构化错误码命中", func(t *testing.T) {
		body := []byte(`{"error":{"code":"model_capacity_exhausted","message":"busy"}}`)
		require.True(t, isMirasimRelayModelCapacityExhausted(mirasim, http.StatusBadGateway, "", body))
	})

	t.Run("纯文本响应体命中", func(t *testing.T) {
		require.True(t, isMirasimRelayModelCapacityExhausted(
			mirasim, http.StatusServiceUnavailable, "", []byte(`no upstream available for model "claude-opus-5-5"`)))
	})

	t.Run("4xx 不命中", func(t *testing.T) {
		require.False(t, isMirasimRelayModelCapacityExhausted(
			mirasim, http.StatusNotFound, "", []byte(mirasimCapacityBody)))
	})

	t.Run("非 Mirasim 账号不命中", func(t *testing.T) {
		require.False(t, isMirasimRelayModelCapacityExhausted(
			openai, http.StatusServiceUnavailable, "", []byte(mirasimCapacityBody)))
	})

	t.Run("空账号不命中", func(t *testing.T) {
		require.False(t, isMirasimRelayModelCapacityExhausted(
			nil, http.StatusServiceUnavailable, "", []byte(mirasimCapacityBody)))
	})

	t.Run("其他 5xx 不误伤", func(t *testing.T) {
		require.False(t, isMirasimRelayModelCapacityExhausted(
			mirasim, http.StatusInternalServerError, "", []byte(`{"error":{"message":"internal error"}}`)))
	})
}

// TestApplyMirasimRelayCapacityFailover 验证重试策略的叠加与让位规则。
func TestApplyMirasimRelayCapacityFailover(t *testing.T) {
	mirasim := &Account{Platform: PlatformMirasim}

	t.Run("非池模式账号同样开启同账号重试", func(t *testing.T) {
		require.False(t, mirasim.IsPoolMode())
		failoverErr := &UpstreamFailoverError{StatusCode: http.StatusServiceUnavailable}
		applyMirasimRelayCapacityFailover(
			failoverErr, mirasim, http.StatusServiceUnavailable, "", []byte(mirasimCapacityBody), false)

		require.True(t, failoverErr.RetryableOnSameAccount)
		require.True(t, failoverErr.RequestScopedTransient)
		require.Equal(t, mirasimRelayCapacityRetryMax, failoverErr.SameAccountRetryMax)
		require.False(t, failoverErr.SameAccountRetryDeadline.IsZero())
		require.Equal(t, http.StatusServiceUnavailable, failoverErr.ClientStatusCode)
		require.Equal(t, mirasimRelayCapacityClientMessage, failoverErr.ClientMessage)
	})

	t.Run("账号已被判停调时不覆盖", func(t *testing.T) {
		failoverErr := &UpstreamFailoverError{StatusCode: http.StatusServiceUnavailable}
		applyMirasimRelayCapacityFailover(
			failoverErr, mirasim, http.StatusServiceUnavailable, "", []byte(mirasimCapacityBody), true)
		require.False(t, failoverErr.RetryableOnSameAccount)
		require.Zero(t, failoverErr.SameAccountRetryMax)
	})

	t.Run("非容量降载错误保持原样", func(t *testing.T) {
		failoverErr := &UpstreamFailoverError{StatusCode: http.StatusInternalServerError}
		applyMirasimRelayCapacityFailover(
			failoverErr, mirasim, http.StatusInternalServerError, "", []byte(`{"error":{"message":"boom"}}`), false)
		require.False(t, failoverErr.RetryableOnSameAccount)
		require.Zero(t, failoverErr.SameAccountRetryMax)
	})
}
