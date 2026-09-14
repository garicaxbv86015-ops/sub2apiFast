package service

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/mirasim"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMirasimOAuthService_GenerateAuthURL 测试生成授权跳转链接与会话存储
func TestMirasimOAuthService_GenerateAuthURL(t *testing.T) {
	svc := NewMirasimOAuthService(nil, nil)
	require.NotNil(t, svc)

	ctx := context.Background()
	result, err := svc.GenerateAuthURL(ctx, nil, "github", "")
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.NotEmpty(t, result.AuthURL)
	assert.NotEmpty(t, result.SessionID)
	assert.NotEmpty(t, result.State)
	assert.Contains(t, result.AuthURL, "auth.mirasim.ai")
	assert.Contains(t, result.AuthURL, "github")
	assert.Contains(t, result.AuthURL, result.State)

	// 测试从 SessionStore 取出未完成的会话
	session, ok := svc.sessionStore.Get(result.SessionID)
	require.True(t, ok)
	assert.Equal(t, "github", session.Provider)
	assert.Equal(t, result.State, session.State)
}

// TestMirasimOAuthService_BuildAccountCredentials 测试凭据字典生成与公私钥校验
func TestMirasimOAuthService_BuildAccountCredentials(t *testing.T) {
	svc := NewMirasimOAuthService(nil, nil)
	require.NotNil(t, svc)

	privPEM, pubKeyB64, deviceID, err := mirasim.GenerateEd25519DeviceKey()
	require.NoError(t, err)

	now := time.Now().UTC()
	tokenInfo := &MirasimTokenInfo{
		AccessToken:  "test-access-token",
		RefreshToken: "test-refresh-token",
		ExpiresIn:    86400,
		ExpiresAt:    now.Add(24 * time.Hour).Unix(),
		PrivateKey:   privPEM,
		PublicKeyB64: pubKeyB64,
		DeviceID:     deviceID,
		Email:        "user@example.com",
		Name:         "Test User",
		Plan:         "pro",
	}

	creds := svc.BuildAccountCredentials(tokenInfo)
	require.NotNil(t, creds)

	assert.Equal(t, "test-access-token", creds["api_key"])
	assert.Equal(t, "test-access-token", creds["issuer_token"])
	assert.Equal(t, "test-refresh-token", creds["refresh_token"])
	assert.Equal(t, privPEM, creds["private_key"])
	assert.Equal(t, deviceID, creds["device_id"])
	assert.Equal(t, "oauth", creds["auth_type"])
	assert.Equal(t, "user@example.com", creds["email"])
	assert.Equal(t, "Test User", creds["name"])
	assert.Equal(t, "pro", creds["plan"])
}

// TestMirasimOAuthService_MockFlows 测试验证码与换 Token 等上游交互流程
func TestMirasimOAuthService_MockFlows(t *testing.T) {
	// 启动 mock 上游服务端
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/auth/code":
			// 发送验证码
			var req map[string]string
			_ = json.NewDecoder(r.Body).Decode(&req)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"dev_code": "mock-dev-code-123",
				"message":  "code sent",
			})
		case "/auth/verify":
			// 验证验证码并换取 Token
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token":  "mock-access-token",
				"refresh_token": "mock-refresh-token",
				"expires_in":    86400,
			})
		case "/auth/refresh":
			// 刷新 Token
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token":  "mock-refreshed-access-token",
				"refresh_token": "mock-refreshed-refresh-token",
				"expires_in":    7200,
			})
		case "/auth/me":
			// 获取用户信息
			_ = json.NewEncoder(w).Encode(map[string]any{
				"name":  "Test User",
				"email": "test@mirasim.ai",
				"plan":  "cloud_unlimited",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := mirasim.NewMirasimClient(server.URL, "")
	ctx := context.Background()

	// 1. 测试发送邮箱验证码
	devCode, err := client.SendEmailCode(ctx, "test@mirasim.ai")
	require.NoError(t, err)
	assert.Equal(t, "mock-dev-code-123", devCode)

	// 2. 测试验证验证码
	verifyResp, err := client.VerifyEmailCode(ctx, "test@mirasim.ai", "123456")
	require.NoError(t, err)
	assert.Equal(t, "mock-access-token", verifyResp.AccessToken)
	assert.Equal(t, "mock-refresh-token", verifyResp.RefreshToken)

	// 3. 测试获取用户信息
	userInfo, err := client.GetUserInfo(ctx, verifyResp.AccessToken)
	require.NoError(t, err)
	assert.Equal(t, "Test User", userInfo.Name)
	assert.Equal(t, "test@mirasim.ai", userInfo.Email)
	assert.Equal(t, "cloud_unlimited", userInfo.Plan)

	// 4. 测试刷新 Token
	refreshed, err := client.RefreshToken(ctx, verifyResp.RefreshToken)
	require.NoError(t, err)
	assert.Equal(t, "mock-refreshed-access-token", refreshed.AccessToken)
	assert.Equal(t, "mock-refreshed-refresh-token", refreshed.RefreshToken)
}
