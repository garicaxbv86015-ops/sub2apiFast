package mirasim

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
)

const (
	// DefaultAuthBaseURL 是 Mirasim 官方鉴权服务基址。
	DefaultAuthBaseURL = "https://auth.mirasim.ai"
	// DefaultRelayBaseURL 是 Mirasim 官方中继服务基址。
	DefaultRelayBaseURL = "https://relay.mirasim.ai"
	// DefaultOAuthProvider 是默认 OAuth 认证源（GitHub）。
	DefaultOAuthProvider = "github"
	// DefaultRedirectURI 是默认回调地址。
	DefaultRedirectURI = "http://localhost:8085/callback"
	// SessionTTL 是 OAuth 授权会话的有效生命周期。
	SessionTTL = 30 * time.Minute
)

// OAuthSession 保存 Mirasim OAuth 流程的临时会话上下文。
type OAuthSession struct {
	// State 随机校验码，防止 CSRF
	State string `json:"state"`
	// Provider OAuth 认证提供商，如 github、google
	Provider string `json:"provider"`
	// RedirectURI 授权回调地址
	RedirectURI string `json:"redirect_uri"`
	// ProxyURL 绑定的代理节点地址
	ProxyURL string `json:"proxy_url,omitempty"`
	// CreatedAt 会话创建时间
	CreatedAt time.Time `json:"created_at"`
}

// SessionStore 管理 OAuth 会话的并发安全内存存储。
type SessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*OAuthSession
	stopCh   chan struct{}
}

// NewSessionStore 创建并启动会话存储与定时过期清理协程。
// 返回值：
//   - *SessionStore: 会话存储实例
func NewSessionStore() *SessionStore {
	store := &SessionStore{
		sessions: make(map[string]*OAuthSession),
		stopCh:   make(chan struct{}),
	}
	go store.cleanup()
	return store
}

// Set 存入指定会话 ID 的 OAuth 会话对象。
// 参数：
//   - sessionID: 会话唯一标识符
//   - session: 会话对象指针
func (s *SessionStore) Set(sessionID string, session *OAuthSession) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[sessionID] = session
}

// Get 根据会话 ID 读取未过期的 OAuth 会话。
// 参数：
//   - sessionID: 会话唯一标识符
// 返回值：
//   - *OAuthSession: 会话对象指针，不存在或已过期则为 nil
//   - bool: 是否成功获取
func (s *SessionStore) Get(sessionID string) (*OAuthSession, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	session, ok := s.sessions[sessionID]
	if !ok {
		return nil, false
	}
	if time.Since(session.CreatedAt) > SessionTTL {
		return nil, false
	}
	return session, true
}

// Delete 删除指定会话 ID 的记录。
// 参数：
//   - sessionID: 会话唯一标识符
func (s *SessionStore) Delete(sessionID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, sessionID)
}

// Stop 停止后台清理任务。
func (s *SessionStore) Stop() {
	select {
	case <-s.stopCh:
		return
	default:
		close(s.stopCh)
	}
}

// cleanup 后台定期清理过期会话。
func (s *SessionStore) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.mu.Lock()
			now := time.Now()
			for id, sess := range s.sessions {
				if now.Sub(sess.CreatedAt) > SessionTTL {
					delete(s.sessions, id)
				}
			}
			s.mu.Unlock()
		}
	}
}

// GenerateState 生成安全随机校验码 State。
// 返回值：
//   - string: URL 安全的 Base64 随机串
//   - error: 随机数生成错误
func GenerateState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// GenerateSessionID 生成内部跟踪会话 ID。
// 返回值：
//   - string: URL 安全的 Base64 随机串
//   - error: 随机数生成错误
func GenerateSessionID() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// BuildAuthorizationURL 构建跳转 Mirasim 授权中心的认证链接。
// 参数：
//   - authBaseURL: Mirasim 鉴权端点基址
//   - provider: OAuth 提供商名称（如 github、google）
//   - redirectURI: 客户端回调地址
//   - state: CSRF 校验码
// 返回值：
//   - string: 拼接后的授权重定向 URL
func BuildAuthorizationURL(authBaseURL, provider, redirectURI, state string) string {
	base := strings.TrimRight(strings.TrimSpace(authBaseURL), "/")
	if base == "" {
		base = DefaultAuthBaseURL
	}
	prov := strings.TrimSpace(provider)
	if prov == "" {
		prov = DefaultOAuthProvider
	}
	v := url.Values{}
	v.Set("redirect_uri", redirectURI)
	v.Set("state", state)
	return fmt.Sprintf("%s/auth/oauth/%s/login?%s", base, prov, v.Encode())
}

// AuthorizationInput 解析后的用户输入授权载荷。
type AuthorizationInput struct {
	// AccessToken 解析出的访问凭据
	AccessToken string
	// RefreshToken 解析出的刷新凭据
	RefreshToken string
	// State 附带的 state 校验码
	State string
	// RawCode 原始输入字符串
	RawCode string
}

// ParseAuthorizationInput 从回调 URL 或直接输入的 Token 中解析出凭证和 State。
// 参数：
//   - input: 用户复制的回调完整 URL 或原始 Token
// 返回值：
//   - AuthorizationInput: 解析后的结构体
func ParseAuthorizationInput(input string) AuthorizationInput {
	trimmed := strings.TrimSpace(input)
	res := AuthorizationInput{RawCode: trimmed}

	// 尝试作为完整 URL 解析
	if strings.HasPrefix(trimmed, "http://") || strings.HasPrefix(trimmed, "https://") || strings.Contains(trimmed, "?") {
		u, err := url.Parse(trimmed)
		if err == nil {
			q := u.Query()
			token := q.Get("access_token")
			if token == "" {
				token = q.Get("token")
			}
			if token == "" {
				token = q.Get("code")
			}
			res.AccessToken = strings.TrimSpace(token)
			res.RefreshToken = strings.TrimSpace(q.Get("refresh_token"))
			res.State = strings.TrimSpace(q.Get("state"))
			return res
		}
	}

	// 包含 key=value&key2=value2 的查询串格式
	if strings.Contains(trimmed, "=") && !strings.Contains(trimmed, " ") {
		q, err := url.ParseQuery(trimmed)
		if err == nil {
			token := q.Get("access_token")
			if token == "" {
				token = q.Get("token")
			}
			if token == "" {
				token = q.Get("code")
			}
			res.AccessToken = strings.TrimSpace(token)
			res.RefreshToken = strings.TrimSpace(q.Get("refresh_token"))
			res.State = strings.TrimSpace(q.Get("state"))
			if res.AccessToken != "" {
				return res
			}
		}
	}

	// 纯 Token 字符串输入
	res.AccessToken = trimmed
	return res
}

// GenerateEd25519DeviceKey 为新接入账号自动生成符合 Mirasim 规范的设备私钥与设备 ID。
// 私钥输出为标准 PKCS#8 PEM 格式，公钥计算为 SPKI Base64 格式，Device ID 自动通过 SHA-256 派生。
// 返回值：
//   - privPEM: PKCS#8 格式 PEM 编码私钥字符串
//   - pubKeyB64: SPKI DER 格式 Base64 编码公钥字符串
//   - deviceID: 22 字符 Base64URL 格式设备标识
//   - err: 生成或编码错误
func GenerateEd25519DeviceKey() (privPEM string, pubKeyB64 string, deviceID string, err error) {
	// 步骤 1: 生成原生 Ed25519 密钥对
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", "", fmt.Errorf("generate ed25519 key failed: %w", err)
	}

	// 步骤 2: 序列化私钥为 PKCS#8 DER 并包装为 PEM
	pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return "", "", "", fmt.Errorf("marshal pkcs8 failed: %w", err)
	}
	block := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: pkcs8Bytes,
	}
	privPEM = string(pem.EncodeToMemory(block))

	// 步骤 3: 序列化公钥为 SubjectPublicKeyInfo (SPKI) DER 并转为 Base64
	spkiBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", "", "", fmt.Errorf("marshal spki failed: %w", err)
	}
	pubKeyB64 = base64.StdEncoding.EncodeToString(spkiBytes)

	// 步骤 4: 计算 Device ID (SHA-256 哈希取前 22 字符 base64url)
	sum := sha256.Sum256([]byte(pubKeyB64))
	encoded := base64.RawURLEncoding.EncodeToString(sum[:])
	if len(encoded) > 22 {
		deviceID = encoded[:22]
	} else {
		deviceID = encoded
	}

	return privPEM, pubKeyB64, deviceID, nil
}

// TokenResponse Mirasim 鉴权端点返回的 Token 载荷。
type TokenResponse struct {
	// AccessToken JWT 访问凭据
	AccessToken string `json:"access_token"`
	// RefreshToken 刷新凭据
	RefreshToken string `json:"refresh_token"`
	// TokenType 凭据类型，如 Bearer
	TokenType string `json:"token_type"`
	// ExpiresIn 有效时长（秒）
	ExpiresIn int64 `json:"expires_in,omitempty"`
}

// ParseJWTExpiresAt 解析 JWT 的 exp 声明并返回 Unix 秒时间戳。
// 仅做 payload 解码（不验签），用于同步真实过期时间；兼容省略 Base64URL 填充的 JWT。
// 参数：
//   - token: 完整 JWT 字符串
// 返回值：
//   - int64: exp 时间戳（秒），无 exp 时返回 0
//   - error: 解析失败时返回错误
func ParseJWTExpiresAt(token string) (int64, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return 0, fmt.Errorf("empty jwt")
	}
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return 0, fmt.Errorf("invalid jwt format")
	}
	payload := parts[1]
	payload += strings.Repeat("=", (4-len(payload)%4)%4)
	raw, err := base64.URLEncoding.DecodeString(payload)
	if err != nil {
		return 0, fmt.Errorf("decode jwt payload: %w", err)
	}
	var claims struct {
		Exp int64 `json:"exp"`
	}
	if err := json.Unmarshal(raw, &claims); err != nil {
		return 0, fmt.Errorf("unmarshal jwt claims: %w", err)
	}
	return claims.Exp, nil
}

// ParseJWTSubject 解析 JWT 的 sub 声明并返回主体标识。
// 仅做 payload 解码（不验签），用于取出登录用户/设备票据的账号 ID；兼容省略 Base64URL 填充的 JWT。
// 参数：
//   - token: 完整 JWT 字符串
// 返回值：
//   - string: sub 声明的值，缺失时返回空串
//   - error: 解析失败时返回错误
func ParseJWTSubject(token string) (string, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return "", fmt.Errorf("empty jwt")
	}
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return "", fmt.Errorf("invalid jwt format")
	}
	payload := parts[1]
	// 补齐 Base64URL 填充，兼容省略 "=" 的 JWT。
	payload += strings.Repeat("=", (4-len(payload)%4)%4)
	raw, err := base64.URLEncoding.DecodeString(payload)
	if err != nil {
		return "", fmt.Errorf("decode jwt payload: %w", err)
	}
	var claims struct {
		Sub string `json:"sub"`
	}
	if err := json.Unmarshal(raw, &claims); err != nil {
		return "", fmt.Errorf("unmarshal jwt claims: %w", err)
	}
	return claims.Sub, nil
}

// UserInfo Mirasim /auth/me 返回的当前登录用户概要信息。
type UserInfo struct {
	// Email 用户邮箱地址
	Email string `json:"email"`
	// Name 用户昵称或显示名
	Name string `json:"name"`
	// Plan 当前权益方案（例如 pro、team 或 none）
	Plan string `json:"plan"`
	// PlanExp 权益到期时间戳或字符串
	PlanExp any `json:"plan_exp,omitempty"`
}

// MirasimClient 提供与 auth.mirasim.ai 的直接通信客户端。
type MirasimClient struct {
	authBaseURL string
	httpClient  *http.Client
}

// NewMirasimClient 创建 Mirasim API 交互客户端。
// 参数：
//   - authBaseURL: Mirasim 鉴权服务基址
//   - proxyURL: 可选代理节点地址
// 返回值：
//   - *MirasimClient: 客户端实例
func NewMirasimClient(authBaseURL string, proxyURL string) *MirasimClient {
	base := strings.TrimRight(strings.TrimSpace(authBaseURL), "/")
	if base == "" {
		base = DefaultAuthBaseURL
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	if strings.TrimSpace(proxyURL) != "" {
		if u, err := url.Parse(proxyURL); err == nil {
			transport.Proxy = http.ProxyURL(u)
		}
	}

	return &MirasimClient{
		authBaseURL: base,
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   15 * time.Second,
		},
	}
}

// SendEmailCode 发送邮箱登录验证码。
// 参数：
//   - ctx: 上下文
//   - email: 目标邮箱
// 返回值：
//   - string: 测试环境可能返回的 dev_code（生产环境为空）
//   - error: 请求或网络错误
func (c *MirasimClient) SendEmailCode(ctx context.Context, email string) (string, error) {
	email = strings.TrimSpace(email)
	if email == "" {
		return "", infraerrors.New(http.StatusBadRequest, "INVALID_EMAIL", "email cannot be empty")
	}

	// 步骤 1: 构造发送验证码请求体
	bodyObj := map[string]string{"email": email}
	bodyBytes, err := json.Marshal(bodyObj)
	if err != nil {
		return "", err
	}

	urlStr := fmt.Sprintf("%s/auth/code", c.authBaseURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, urlStr, bytes.NewReader(bodyBytes))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	// 步骤 2: 发送 HTTP 请求并解析响应
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("send email code failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read response failed: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", infraerrors.Newf(resp.StatusCode, "MIRASIM_AUTH_ERROR", "send code error (%d): %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		DevCode string `json:"dev_code"`
	}
	_ = json.Unmarshal(respBody, &result)

	return result.DevCode, nil
}

// VerifyEmailCode 校验邮箱验证码并换取 Token。
// 参数：
//   - ctx: 上下文
//   - email: 邮箱
//   - code: 验证码
// 返回值：
//   - *TokenResponse: 交换成功的 Token 载荷
//   - error: 校验或网络错误
func (c *MirasimClient) VerifyEmailCode(ctx context.Context, email, code string) (*TokenResponse, error) {
	email = strings.TrimSpace(email)
	code = strings.TrimSpace(code)
	if email == "" || code == "" {
		return nil, infraerrors.New(http.StatusBadRequest, "INVALID_INPUT", "email and code are required")
	}

	// 步骤 1: 构造校验验证码请求体
	bodyObj := map[string]string{
		"email": email,
		"code":  code,
	}
	bodyBytes, err := json.Marshal(bodyObj)
	if err != nil {
		return nil, err
	}

	urlStr := fmt.Sprintf("%s/auth/verify", c.authBaseURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, urlStr, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	// 步骤 2: 发送请求并读取 Token
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("verify email code failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response failed: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, infraerrors.Newf(resp.StatusCode, "MIRASIM_AUTH_ERROR", "verify code error (%d): %s", resp.StatusCode, string(respBody))
	}

	var tokenResp TokenResponse
	if err := json.Unmarshal(respBody, &tokenResp); err != nil {
		return nil, fmt.Errorf("unmarshal token response failed: %w", err)
	}
	if tokenResp.AccessToken == "" {
		// 尝试兼容 token 字段
		var fallback struct {
			Token        string `json:"token"`
			RefreshToken string `json:"refresh_token"`
		}
		_ = json.Unmarshal(respBody, &fallback)
		tokenResp.AccessToken = fallback.Token
		if tokenResp.RefreshToken == "" {
			tokenResp.RefreshToken = fallback.RefreshToken
		}
	}

	if tokenResp.AccessToken == "" {
		return nil, infraerrors.New(http.StatusUnauthorized, "NO_ACCESS_TOKEN", "response carried no access token")
	}

	return &tokenResp, nil
}

// RefreshToken 使用 RefreshToken 刷新换取新的 AccessToken。
// 参数：
//   - ctx: 上下文
//   - refreshToken: 现有有效的刷新令牌
// 返回值：
//   - *TokenResponse: 刷新换取后的新 Token 载荷
//   - error: 刷新或网络错误
func (c *MirasimClient) RefreshToken(ctx context.Context, refreshToken string) (*TokenResponse, error) {
	refreshToken = strings.TrimSpace(refreshToken)
	if refreshToken == "" {
		return nil, infraerrors.New(http.StatusBadRequest, "INVALID_REFRESH_TOKEN", "refresh token cannot be empty")
	}

	// 步骤 1: 构造刷新请求体
	bodyObj := map[string]string{"refresh_token": refreshToken}
	bodyBytes, err := json.Marshal(bodyObj)
	if err != nil {
		return nil, err
	}

	urlStr := fmt.Sprintf("%s/auth/refresh", c.authBaseURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, urlStr, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	// 步骤 2: 发送请求并读取刷新结果
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("refresh token failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response failed: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, infraerrors.Newf(resp.StatusCode, "MIRASIM_AUTH_ERROR", "refresh token error (%d): %s", resp.StatusCode, string(respBody))
	}

	var tokenResp TokenResponse
	if err := json.Unmarshal(respBody, &tokenResp); err != nil {
		return nil, fmt.Errorf("unmarshal token response failed: %w", err)
	}
	if tokenResp.AccessToken == "" {
		var fallback struct {
			Token        string `json:"token"`
			RefreshToken string `json:"refresh_token"`
		}
		_ = json.Unmarshal(respBody, &fallback)
		tokenResp.AccessToken = fallback.Token
		if tokenResp.RefreshToken == "" {
			tokenResp.RefreshToken = fallback.RefreshToken
		}
	}
	if tokenResp.RefreshToken == "" {
		// 若上游未轮转，沿用传入的 RefreshToken
		tokenResp.RefreshToken = refreshToken
	}

	return &tokenResp, nil
}

// GetUserInfo 调用 /auth/me 读取用户信息与权益状态。
// 参数：
//   - ctx: 上下文
//   - accessToken: 有效访问令牌
// 返回值：
//   - *UserInfo: 用户信息
//   - error: 读取或解析错误
func (c *MirasimClient) GetUserInfo(ctx context.Context, accessToken string) (*UserInfo, error) {
	accessToken = strings.TrimSpace(accessToken)
	if accessToken == "" {
		return nil, infraerrors.New(http.StatusUnauthorized, "UNAUTHORIZED", "access token is required")
	}

	// 步骤 1: 构造 GET /auth/me 请求
	urlStr := fmt.Sprintf("%s/auth/me", c.authBaseURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	// 步骤 2: 发送请求获取用户信息
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("get user info failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response failed: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, infraerrors.Newf(resp.StatusCode, "MIRASIM_AUTH_ERROR", "get user info error (%d): %s", resp.StatusCode, string(respBody))
	}

	var info UserInfo
	if err := json.Unmarshal(respBody, &info); err != nil {
		return nil, fmt.Errorf("unmarshal user info failed: %w", err)
	}

	return &info, nil
}
