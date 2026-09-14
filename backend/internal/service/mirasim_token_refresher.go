package service

import (
	"context"
	"fmt"
	"time"
)

const (
	// mirasimRefreshWindow Mirasim Token 提前刷新时间窗口（30 分钟）
	mirasimRefreshWindow = 30 * time.Minute
)

// MirasimTokenRefresher 实现 TokenRefresher 与 OAuthRefreshExecutor 接口。
type MirasimTokenRefresher struct {
	mirasimOAuthService *MirasimOAuthService
}

// NewMirasimTokenRefresher 创建 Mirasim 令牌自动刷新器。
// 参数：
//   - mirasimOAuthService: Mirasim 授权服务
// 返回值：
//   - *MirasimTokenRefresher: 刷新器实例
func NewMirasimTokenRefresher(mirasimOAuthService *MirasimOAuthService) *MirasimTokenRefresher {
	return &MirasimTokenRefresher{
		mirasimOAuthService: mirasimOAuthService,
	}
}

// CacheKey 返回用于分布式刷新锁的缓存键名。
// 参数：
//   - account: 账户实体
// 返回值：
//   - string: 缓存键名
func (r *MirasimTokenRefresher) CacheKey(account *Account) string {
	if account == nil {
		return "token:mirasim:unknown"
	}
	return fmt.Sprintf("token:mirasim:%d", account.ID)
}

// CanRefresh 检查账户是否支持并具备刷新条件。
// 参数：
//   - account: 账户实体
// 返回值：
//   - bool: 是否可刷新
func (r *MirasimTokenRefresher) CanRefresh(account *Account) bool {
	if account == nil {
		return false
	}
	if account.Platform != PlatformMirasim {
		return false
	}
	// 支持类型为 oauth 或包含 refresh_token 的账户
	return account.Type == AccountTypeOAuth || account.GetCredential("refresh_token") != ""
}

// NeedsRefresh 检查账户凭证是否即将过期需要刷新。
// 参数：
//   - account: 账户实体
//   - globalWindow: 全局刷新窗口时长
// 返回值：
//   - bool: 是否需要刷新
func (r *MirasimTokenRefresher) NeedsRefresh(account *Account, globalWindow time.Duration) bool {
	if !r.CanRefresh(account) {
		return false
	}

	expiresAt := account.GetCredentialAsTime("expires_at")
	if expiresAt == nil {
		return false
	}

	window := mirasimRefreshWindow
	if globalWindow > 0 && globalWindow < window {
		window = globalWindow
	}

	return time.Until(*expiresAt) < window
}

// Refresh 执行 Mirasim 账户的 Token 刷新，并合并凭据。
// 参数：
//   - ctx: 上下文
//   - account: 账户实体
// 返回值：
//   - map[string]any: 刷新合并后的新凭据字典
//   - error: 刷新错误
func (r *MirasimTokenRefresher) Refresh(ctx context.Context, account *Account) (map[string]any, error) {
	if r.mirasimOAuthService == nil {
		return nil, fmt.Errorf("mirasim oauth service is nil")
	}

	// 步骤 1: 调用服务执行刷新
	tokenInfo, err := r.mirasimOAuthService.RefreshAccountToken(ctx, account)
	if err != nil {
		return nil, err
	}

	// 步骤 2: 构建新凭据并合并已有自定义配置（如自适应协议规则、私钥等）
	newCreds := r.mirasimOAuthService.BuildAccountCredentials(tokenInfo)
	merged := MergeCredentials(account.Credentials, newCreds)

	return merged, nil
}
