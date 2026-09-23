package service

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
)

// TestMirasimCountTokens_LocalOnly 验证两个计数入口不访问上游、不冷却账号，并拒绝非法请求。
// 参数 t 为测试上下文；无返回值，失败时报告路由或响应差异。
func TestMirasimCountTokens_LocalOnly(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, accountType := range []string{AccountTypeOAuth, AccountTypeAPIKey} {
		for _, native := range []bool{false, true} {
			for _, invalid := range []bool{false, true} {
				body := []byte(`{"model":"claude-opus-5","system":"请协助开发","messages":[{"role":"user","content":"检查计数请求"}],"tools":[{"name":"lookup","input_schema":{"type":"object"}}]}`)
				path := "/v1/messages/count_tokens"
				if native {
					body = []byte(`{"model":"gpt-6-astra","input":"检查计数请求"}`)
					path = "/v1/responses/input_tokens"
				}
				if invalid {
					body = []byte(`{"model":`)
				}
				rec := httptest.NewRecorder()
				c, _ := gin.CreateTestContext(rec)
				c.Request = httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
				upstream := &httpUpstreamRecorder{}
				repo := &countTokensRuntimeStateRepo{}
				svc := &OpenAIGatewayService{
					httpUpstream: upstream,
					rateLimitService: &RateLimitService{accountRepo: repo, cfg: &config.Config{}},
				}
				// 不提供凭据和私钥，确保本地计数不依赖换票、刷新或上游认证。
				account := &Account{ID: 1095, Platform: PlatformMirasim, Type: accountType}
				var err error
				if native {
					err = svc.ForwardResponsesInputTokens(context.Background(), c, account, body)
				} else {
					err = svc.ForwardCountTokensAsAnthropic(context.Background(), c, account, body, "")
				}
				if invalid {
					require.Error(t, err)
					require.Equal(t, http.StatusBadRequest, rec.Code)
				} else {
					require.NoError(t, err)
					require.Equal(t, http.StatusOK, rec.Code)
					require.Positive(t, gjson.Get(rec.Body.String(), "input_tokens").Int())
				}
				require.Nil(t, upstream.lastReq)
				require.Zero(t, repo.tempUnschedCalls)
				require.Zero(t, repo.setErrorCalls)
			}
		}
	}
}
