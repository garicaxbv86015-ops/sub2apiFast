package service

import (
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/mirasim"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMirasimTokenRefresher_CacheKey 测试缓存键生成
func TestMirasimTokenRefresher_CacheKey(t *testing.T) {
	refresher := NewMirasimTokenRefresher(nil)
	require.NotNil(t, refresher)

	assert.Equal(t, "token:mirasim:unknown", refresher.CacheKey(nil))

	acc := &Account{ID: 1024, Platform: PlatformMirasim}
	assert.Equal(t, "token:mirasim:1024", refresher.CacheKey(acc))
}

// TestMirasimTokenRefresher_CanRefresh 测试是否支持刷新判定
func TestMirasimTokenRefresher_CanRefresh(t *testing.T) {
	refresher := NewMirasimTokenRefresher(nil)
	require.NotNil(t, refresher)

	assert.False(t, refresher.CanRefresh(nil))

	// 平台不匹配
	accWrongPlatform := &Account{ID: 1, Platform: PlatformAnthropic, Type: AccountTypeOAuth}
	assert.False(t, refresher.CanRefresh(accWrongPlatform))

	// OAuth 账号且为 Mirasim
	accOAuth := &Account{ID: 2, Platform: PlatformMirasim, Type: AccountTypeOAuth}
	assert.True(t, refresher.CanRefresh(accOAuth))

	// 包含 refresh_token 的 APIKey 账号
	accWithToken := &Account{
		ID:       3,
		Platform: PlatformMirasim,
		Type:     AccountTypeAPIKey,
		Credentials: map[string]any{
			"refresh_token": "some-refresh-token",
		},
	}
	assert.True(t, refresher.CanRefresh(accWithToken))
}

// TestMirasimTokenRefresher_NeedsRefresh 测试过期窗口判断
func TestMirasimTokenRefresher_NeedsRefresh(t *testing.T) {
	refresher := NewMirasimTokenRefresher(nil)
	require.NotNil(t, refresher)

	// 无 expires_at
	accNoExp := &Account{ID: 1, Platform: PlatformMirasim, Type: AccountTypeOAuth}
	assert.False(t, refresher.NeedsRefresh(accNoExp, 0))

	// 还有 2 小时才过期（未达 30 分钟窗口）
	futureExp := time.Now().Add(2 * time.Hour).Format(time.RFC3339)
	accFuture := &Account{
		ID:       2,
		Platform: PlatformMirasim,
		Type:     AccountTypeOAuth,
		Credentials: map[string]any{
			"expires_at": futureExp,
		},
	}
	assert.False(t, refresher.NeedsRefresh(accFuture, 0))

	// 还有 10 分钟过期（在 30 分钟窗口内，需要刷新）
	nearExp := time.Now().Add(10 * time.Minute).Format(time.RFC3339)
	accNear := &Account{
		ID:       3,
		Platform: PlatformMirasim,
		Type:     AccountTypeOAuth,
		Credentials: map[string]any{
			"expires_at": nearExp,
		},
	}
	assert.True(t, refresher.NeedsRefresh(accNear, 0))
}

// TestMirasimTokenRefresher_Refresh 测试凭据合并
func TestMirasimTokenRefresher_Refresh(t *testing.T) {
	// 验证 MergeCredentials 的合并机制
	privPEM, _, _, err := mirasim.GenerateEd25519DeviceKey()
	require.NoError(t, err)

	originalCreds := map[string]any{
		"token":              "old-token",
		"refresh_token":      "old-refresh-token",
		"device_private_key": privPEM,
		"custom_setting":     "keep_me",
	}

	newCreds := map[string]any{
		"token":         "new-token",
		"refresh_token": "new-refresh-token",
		"expires_at":    time.Now().Add(24 * time.Hour).Format(time.RFC3339),
	}

	merged := MergeCredentials(originalCreds, newCreds)
	assert.Equal(t, "new-token", merged["token"])
	assert.Equal(t, "new-refresh-token", merged["refresh_token"])
	assert.Equal(t, privPEM, merged["device_private_key"])
	assert.Equal(t, "keep_me", merged["custom_setting"])
}
