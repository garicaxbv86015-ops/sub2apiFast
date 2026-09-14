package admin

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupMirasimOAuthTestRouter 初始化用于单元测试的 Gin 路由环境。
// 返回值：
//   - *gin.Engine: 路由引擎
//   - *MirasimOAuthHandler: 处理器实例
func setupMirasimOAuthTestRouter() (*gin.Engine, *MirasimOAuthHandler) {
	gin.SetMode(gin.TestMode)
	r := gin.New()

	mirasimSvc := service.NewMirasimOAuthService(nil, nil)
	handler := NewMirasimOAuthHandler(mirasimSvc)

	group := r.Group("/admin/mirasim/oauth")
	{
		group.POST("/auth-url", handler.GenerateAuthURL)
		group.POST("/exchange-code", handler.ExchangeCode)
		group.POST("/send-code", handler.SendEmailCode)
		group.POST("/verify-code", handler.VerifyEmailCode)
		group.POST("/refresh-token", handler.RefreshToken)
		group.POST("/import-local", handler.ImportLocal)
	}

	return r, handler
}

// TestMirasimOAuthHandler_GenerateAuthURL 测试发起授权 URL 生成接口
func TestMirasimOAuthHandler_GenerateAuthURL(t *testing.T) {
	router, _ := setupMirasimOAuthTestRouter()

	reqBody := map[string]any{
		"provider": "github",
	}
	bodyBytes, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest(http.MethodPost, "/admin/mirasim/oauth/auth-url", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]any
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)

	data, ok := resp["data"].(map[string]any)
	require.True(t, ok)
	assert.NotEmpty(t, data["auth_url"])
	assert.NotEmpty(t, data["session_id"])
	assert.NotEmpty(t, data["state"])
}

// TestMirasimOAuthHandler_SendEmailCode_InvalidRequest 测试邮箱参数校验失败场景
func TestMirasimOAuthHandler_SendEmailCode_InvalidRequest(t *testing.T) {
	router, _ := setupMirasimOAuthTestRouter()

	// 缺少必填 email 字段
	reqBody := map[string]any{}
	bodyBytes, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest(http.MethodPost, "/admin/mirasim/oauth/send-code", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestMirasimOAuthHandler_VerifyEmailCode_InvalidRequest 测试验证码参数校验失败场景
func TestMirasimOAuthHandler_VerifyEmailCode_InvalidRequest(t *testing.T) {
	router, _ := setupMirasimOAuthTestRouter()

	// 缺少验证码 code
	reqBody := map[string]any{
		"email": "test@example.com",
	}
	bodyBytes, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest(http.MethodPost, "/admin/mirasim/oauth/verify-code", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestMirasimOAuthHandler_RefreshToken_InvalidRequest 测试刷新 Token 参数校验场景
func TestMirasimOAuthHandler_RefreshToken_InvalidRequest(t *testing.T) {
	router, _ := setupMirasimOAuthTestRouter()

	// 缺少 refresh_token
	reqBody := map[string]any{}
	bodyBytes, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest(http.MethodPost, "/admin/mirasim/oauth/refresh-token", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}
