package service

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/pkg/mirasim"
)

// MirasimOAuthService 提供 Mirasim 平台的授权管理、验证码交换、Token 刷新与设备凭据自动派生服务。
type MirasimOAuthService struct {
	sessionStore *mirasim.SessionStore
	proxyRepo    ProxyRepository
	cfg          *config.Config
}

// NewMirasimOAuthService 创建 Mirasim 授权业务服务实例。
// 参数：
//   - proxyRepo: 代理节点仓储
//   - cfg: 系统全局配置
// 返回值：
//   - *MirasimOAuthService: 授权服务实例
func NewMirasimOAuthService(proxyRepo ProxyRepository, cfg *config.Config) *MirasimOAuthService {
	return &MirasimOAuthService{
		sessionStore: mirasim.NewSessionStore(),
		proxyRepo:    proxyRepo,
		cfg:          cfg,
	}
}

// MirasimAuthURLResult 包含发起 Mirasim 授权跳转所需的链接及会话凭证。
type MirasimAuthURLResult struct {
	// AuthURL 客户端跳转授权端点地址
	AuthURL string `json:"auth_url"`
	// SessionID 临时会话跟踪标识符
	SessionID string `json:"session_id"`
	// State 防 CSRF 随机校验字符串
	State string `json:"state"`
}

// GenerateAuthURL 生成跳转 Mirasim 鉴权中心的 OAuth 授权 URL。
// 参数：
//   - ctx: 上下文
//   - proxyID: 可选代理节点 ID
//   - redirectURI: 客户端回调地址
//   - provider: 认证源（如 github、google，空则默认为 github）
// 返回值：
//   - *MirasimAuthURLResult: 授权 URL 生成结果
//   - error: 生成错误
func (s *MirasimOAuthService) GenerateAuthURL(ctx context.Context, proxyID *int64, redirectURI, provider string) (*MirasimAuthURLResult, error) {
	// 步骤 1: 生成安全随机 State 和会话 SessionID
	state, err := mirasim.GenerateState()
	if err != nil {
		return nil, fmt.Errorf("generate state failed: %w", err)
	}

	sessionID, err := mirasim.GenerateSessionID()
	if err != nil {
		return nil, fmt.Errorf("generate session_id failed: %w", err)
	}

	// 步骤 2: 解析并获取绑定代理地址（若指定）
	var proxyURL string
	if proxyID != nil && s.proxyRepo != nil {
		proxy, err := s.proxyRepo.GetByID(ctx, *proxyID)
		if err == nil && proxy != nil {
			proxyURL = proxy.URL()
		}
	}

	if strings.TrimSpace(redirectURI) == "" {
		redirectURI = mirasim.DefaultRedirectURI
	}
	if strings.TrimSpace(provider) == "" {
		provider = mirasim.DefaultOAuthProvider
	}

	// 步骤 3: 构造并存储会话状态
	session := &mirasim.OAuthSession{
		State:       state,
		Provider:    provider,
		RedirectURI: redirectURI,
		ProxyURL:    proxyURL,
		CreatedAt:   time.Now(),
	}
	s.sessionStore.Set(sessionID, session)

	// 步骤 4: 组装跳转 URL
	authURL := mirasim.BuildAuthorizationURL(mirasim.DefaultAuthBaseURL, provider, redirectURI, state)

	return &MirasimAuthURLResult{
		AuthURL:   authURL,
		SessionID: sessionID,
		State:     state,
	}, nil
}

// MirasimExchangeCodeInput 交换授权码或 Token 的输入参数。
type MirasimExchangeCodeInput struct {
	// SessionID 发起授权时创建的临时会话 ID
	SessionID string
	// State 回调携带的防 CSRF 状态码
	State string
	// Code 回调携带的 Code、完整重定向 URL 或 AccessToken
	Code string
	// ProxyID 可选代理节点 ID
	ProxyID *int64
}

// MirasimTokenInfo 包含 Mirasim 授权结果与派生的完整账号凭据。
type MirasimTokenInfo struct {
	// AccessToken 访问令牌（JWT）
	AccessToken string `json:"access_token"`
	// RefreshToken 刷新令牌
	RefreshToken string `json:"refresh_token,omitempty"`
	// ExpiresIn 有效期秒数
	ExpiresIn int64 `json:"expires_in,omitempty"`
	// ExpiresAt 过期时间戳（Unix 秒）
	ExpiresAt int64 `json:"expires_at,omitempty"`
	// Email 绑定邮箱
	Email string `json:"email,omitempty"`
	// Name 用户显示名称
	Name string `json:"name,omitempty"`
	// Plan 当前权益方案（如 pro、team 或 none）
	Plan string `json:"plan,omitempty"`
	// PlanExp 权益到期时间
	PlanExp any `json:"plan_exp,omitempty"`
	// DeviceID 自动派生的设备 ID
	DeviceID string `json:"device_id,omitempty"`
	// PrivateKey 自动生成的 Ed25519 PKCS#8 格式私钥 PEM
	PrivateKey string `json:"private_key,omitempty"`
	// PublicKeyB64 派生的 SPKI 公钥 Base64 字符串
	PublicKeyB64 string `json:"public_key_b64,omitempty"`
}

// ExchangeCode 将用户输入的回调信息或 Code 交换为有效的 Token，并自动生成设备公私钥。
// 参数：
//   - ctx: 上下文
//   - input: 交换输入载荷
// 返回值：
//   - *MirasimTokenInfo: 交换完成的 Token 与设备凭据
//   - error: 交换或校验错误
func (s *MirasimOAuthService) ExchangeCode(ctx context.Context, input *MirasimExchangeCodeInput) (*MirasimTokenInfo, error) {
	if input == nil {
		return nil, fmt.Errorf("input is required")
	}

	// 步骤 1: 解析输入载荷（兼容完整重定向 URL、Query 串或纯 Token）
	parsed := mirasim.ParseAuthorizationInput(input.Code)

	var proxyURL string
	// 步骤 2: 校验并处理会话 Session（若提供了 session_id）
	if strings.TrimSpace(input.SessionID) != "" {
		session, ok := s.sessionStore.Get(input.SessionID)
		if !ok {
			return nil, fmt.Errorf("session not found or expired")
		}
		expectedState := session.State
		givenState := strings.TrimSpace(input.State)
		if givenState == "" {
			givenState = parsed.State
		}
		if givenState != "" && expectedState != "" && givenState != expectedState {
			return nil, fmt.Errorf("invalid oauth state: state mismatch")
		}
		proxyURL = session.ProxyURL
		s.sessionStore.Delete(input.SessionID)
	}

	// 若输入中显式指定代理，则覆盖会话中的代理
	if input.ProxyID != nil && s.proxyRepo != nil {
		proxy, err := s.proxyRepo.GetByID(ctx, *input.ProxyID)
		if err == nil && proxy != nil {
			proxyURL = proxy.URL()
		}
	}

	// 步骤 3: 提取有效 AccessToken
	accessToken := strings.TrimSpace(parsed.AccessToken)
	if accessToken == "" {
		return nil, fmt.Errorf("no access token received")
	}

	// 步骤 4: 实例化客户端并读取用户基本资料
	cli := mirasim.NewMirasimClient(mirasim.DefaultAuthBaseURL, proxyURL)
	userInfo, err := cli.GetUserInfo(ctx, accessToken)
	if err != nil {
		// 获取用户信息失败时记录告警但不阻塞账号创建
		fmt.Printf("[MirasimOAuth] warning: get user info failed: %v\n", err)
	}

	// 步骤 5: 自动派生 Ed25519 设备身份密钥对
	privPEM, pubKeyB64, deviceID, err := mirasim.GenerateEd25519DeviceKey()
	if err != nil {
		return nil, fmt.Errorf("generate device key failed: %w", err)
	}

	res := &MirasimTokenInfo{
		AccessToken:  accessToken,
		RefreshToken: strings.TrimSpace(parsed.RefreshToken),
		ExpiresIn:    86400,
		ExpiresAt:    time.Now().Add(24 * time.Hour).Unix(),
		DeviceID:     deviceID,
		PrivateKey:   privPEM,
		PublicKeyB64: pubKeyB64,
	}

	if userInfo != nil {
		res.Email = userInfo.Email
		res.Name = userInfo.Name
		res.Plan = userInfo.Plan
		res.PlanExp = userInfo.PlanExp
	}

	return res, nil
}

// MirasimSendCodeResult 邮箱验证码发送结果。
type MirasimSendCodeResult struct {
	// Message 提示信息
	Message string `json:"message"`
	// DevCode 开发/测试环境下可能回传的验证码（生产环境下为空）
	DevCode string `json:"dev_code,omitempty"`
}

// SendEmailCode 发送 Mirasim 邮箱登录验证码。
// 参数：
//   - ctx: 上下文
//   - email: 接收验证码的邮箱
//   - proxyID: 可选代理节点 ID
// 返回值：
//   - *MirasimSendCodeResult: 发送结果
//   - error: 发送错误
func (s *MirasimOAuthService) SendEmailCode(ctx context.Context, email string, proxyID *int64) (*MirasimSendCodeResult, error) {
	email = strings.TrimSpace(email)
	if email == "" {
		return nil, fmt.Errorf("email is required")
	}

	var proxyURL string
	if proxyID != nil && s.proxyRepo != nil {
		proxy, err := s.proxyRepo.GetByID(ctx, *proxyID)
		if err == nil && proxy != nil {
			proxyURL = proxy.URL()
		}
	}

	cli := mirasim.NewMirasimClient(mirasim.DefaultAuthBaseURL, proxyURL)
	devCode, err := cli.SendEmailCode(ctx, email)
	if err != nil {
		return nil, fmt.Errorf("send email code failed: %w", err)
	}

	return &MirasimSendCodeResult{
		Message: "Verification code sent successfully",
		DevCode: devCode,
	}, nil
}

// VerifyEmailCode 校验邮箱验证码，换取 Token 并自动派生设备公私钥。
// 参数：
//   - ctx: 上下文
//   - email: 登录邮箱
//   - code: 收到的验证码
//   - proxyID: 可选代理节点 ID
// 返回值：
//   - *MirasimTokenInfo: 登录成功后的 Token 与设备凭据
//   - error: 校验或换取错误
func (s *MirasimOAuthService) VerifyEmailCode(ctx context.Context, email, code string, proxyID *int64) (*MirasimTokenInfo, error) {
	email = strings.TrimSpace(email)
	code = strings.TrimSpace(code)
	if email == "" || code == "" {
		return nil, fmt.Errorf("email and code are required")
	}

	var proxyURL string
	if proxyID != nil && s.proxyRepo != nil {
		proxy, err := s.proxyRepo.GetByID(ctx, *proxyID)
		if err == nil && proxy != nil {
			proxyURL = proxy.URL()
		}
	}

	// 步骤 1: 请求 Mirasim 校验验证码换取 Token
	cli := mirasim.NewMirasimClient(mirasim.DefaultAuthBaseURL, proxyURL)
	tokenResp, err := cli.VerifyEmailCode(ctx, email, code)
	if err != nil {
		return nil, fmt.Errorf("verify email code failed: %w", err)
	}

	// 步骤 2: 读取用户资料与权益方案
	userInfo, err := cli.GetUserInfo(ctx, tokenResp.AccessToken)
	if err != nil {
		fmt.Printf("[MirasimOAuth] warning: get user info failed: %v\n", err)
	}

	// 步骤 3: 自动派生 Ed25519 设备身份公私钥
	privPEM, pubKeyB64, deviceID, err := mirasim.GenerateEd25519DeviceKey()
	if err != nil {
		return nil, fmt.Errorf("generate device key failed: %w", err)
	}

	expiresIn := tokenResp.ExpiresIn
	if expiresIn <= 0 {
		expiresIn = 86400
	}

	res := &MirasimTokenInfo{
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
		ExpiresIn:    expiresIn,
		ExpiresAt:    time.Now().Add(time.Duration(expiresIn) * time.Second).Unix(),
		Email:        email,
		DeviceID:     deviceID,
		PrivateKey:   privPEM,
		PublicKeyB64: pubKeyB64,
	}

	if userInfo != nil {
		if userInfo.Email != "" {
			res.Email = userInfo.Email
		}
		res.Name = userInfo.Name
		res.Plan = userInfo.Plan
		res.PlanExp = userInfo.PlanExp
	}

	return res, nil
}

// ValidateRefreshToken 校验 RefreshToken，刷新获取最新的 AccessToken 并生成设备凭证。
// 参数：
//   - ctx: 上下文
//   - refreshToken: 现有有效的刷新令牌
//   - proxyID: 可选代理节点 ID
// 返回值：
//   - *MirasimTokenInfo: 刷新后的凭据信息
//   - error: 刷新错误
func (s *MirasimOAuthService) ValidateRefreshToken(ctx context.Context, refreshToken string, proxyID *int64) (*MirasimTokenInfo, error) {
	refreshToken = strings.TrimSpace(refreshToken)
	if refreshToken == "" {
		return nil, fmt.Errorf("refresh token is required")
	}

	var proxyURL string
	if proxyID != nil && s.proxyRepo != nil {
		proxy, err := s.proxyRepo.GetByID(ctx, *proxyID)
		if err == nil && proxy != nil {
			proxyURL = proxy.URL()
		}
	}

	// 步骤 1: 刷新换取 AccessToken
	cli := mirasim.NewMirasimClient(mirasim.DefaultAuthBaseURL, proxyURL)
	tokenResp, err := cli.RefreshToken(ctx, refreshToken)
	if err != nil {
		return nil, fmt.Errorf("refresh token failed: %w", err)
	}

	// 步骤 2: 读取用户资料
	userInfo, err := cli.GetUserInfo(ctx, tokenResp.AccessToken)
	if err != nil {
		fmt.Printf("[MirasimOAuth] warning: get user info failed: %v\n", err)
	}

	// 步骤 3: 自动生成设备密钥对
	privPEM, pubKeyB64, deviceID, err := mirasim.GenerateEd25519DeviceKey()
	if err != nil {
		return nil, fmt.Errorf("generate device key failed: %w", err)
	}

	expiresIn := tokenResp.ExpiresIn
	if expiresIn <= 0 {
		expiresIn = 86400
	}

	res := &MirasimTokenInfo{
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
		ExpiresIn:    expiresIn,
		ExpiresAt:    time.Now().Add(time.Duration(expiresIn) * time.Second).Unix(),
		DeviceID:     deviceID,
		PrivateKey:   privPEM,
		PublicKeyB64: pubKeyB64,
	}

	if userInfo != nil {
		res.Email = userInfo.Email
		res.Name = userInfo.Name
		res.Plan = userInfo.Plan
		res.PlanExp = userInfo.PlanExp
	}

	return res, nil
}

// ImportLocalMirasimApp 尝试从宿主机本地已运行的 Mirasim.app 配置文件中一键导入登录凭证与设备标识。
// 参数：
//   - ctx: 上下文
// 返回值：
//   - *MirasimTokenInfo: 导入解析出的凭据信息
//   - error: 找不到本地文件或解析错误
func (s *MirasimOAuthService) ImportLocalMirasimApp(ctx context.Context) (*MirasimTokenInfo, error) {
	// 步骤 1: 确定用户目录下的 ~/.mirasim 路径
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("locate home dir failed: %w", err)
	}

	settingFile := filepath.Join(homeDir, ".mirasim", "setting.json")
	deviceFile := filepath.Join(homeDir, ".mirasim", "device.json")

	// 检查配置文件是否存在
	if _, err := os.Stat(settingFile); os.IsNotExist(err) {
		return nil, fmt.Errorf("local mirasim setting.json not found at %s", settingFile)
	}

	settingBytes, err := os.ReadFile(settingFile)
	if err != nil {
		return nil, fmt.Errorf("read setting.json failed: %w", err)
	}

	var settingData struct {
		Auth struct {
			Token        string `json:"token"`
			RefreshToken string `json:"refreshToken"`
			Email        string `json:"email"`
			Name         string `json:"name"`
		} `json:"auth"`
		Device struct {
			PrivateKey string `json:"privateKey"`
		} `json:"device"`
	}
	if err := json.Unmarshal(settingBytes, &settingData); err != nil {
		return nil, fmt.Errorf("unmarshal setting.json failed: %w", err)
	}

	rawToken := strings.TrimSpace(settingData.Auth.Token)
	if rawToken == "" {
		return nil, fmt.Errorf("no auth.token found in local setting.json")
	}
	token, err := mirasim.DecryptMrs1String(rawToken)
	if err != nil {
		return nil, fmt.Errorf("decrypt local auth.token failed: %w", err)
	}

	rawRefreshToken := strings.TrimSpace(settingData.Auth.RefreshToken)
	refreshToken, err := mirasim.DecryptMrs1String(rawRefreshToken)
	if err != nil {
		refreshToken = rawRefreshToken
	}

	// 步骤 2: 读取 device.json 获取 deviceId
	var deviceID string
	if devBytes, err := os.ReadFile(deviceFile); err == nil {
		var devData struct {
			DeviceID string `json:"deviceId"`
		}
		if err := json.Unmarshal(devBytes, &devData); err == nil {
			deviceID = strings.TrimSpace(devData.DeviceID)
		}
	}

	// 步骤 3: 处理私钥（若为 mrs1: 密文则先解密，支持 PEM 与 32 字节私钥种子）
	rawPrivKey := strings.TrimSpace(settingData.Device.PrivateKey)
	privKeyStr, _ := mirasim.DecryptMrs1String(rawPrivKey)
	var privPEM, pubKeyB64 string
	if privKeyStr != "" {
		if seed, err := ParseEd25519Seed(privKeyStr); err == nil && len(seed) == 32 {
			privPEM = privKeyStr
			if signer, err := GetMirasimSigner(); err == nil {
				if pubBytes, err := signer.DerivePublicKey(ctx, seed); err == nil {
					if spkiPub, devID, err := DeriveSPKIPublicKey(pubBytes); err == nil {
						pubKeyB64 = spkiPub
						if deviceID == "" {
							deviceID = devID
						}
					}
				}
			}
		}
	}

	if privPEM == "" {
		// 生成全新的 Ed25519 密钥对
		genPriv, genPub, genDevID, err := mirasim.GenerateEd25519DeviceKey()
		if err == nil {
			privPEM = genPriv
			pubKeyB64 = genPub
			if deviceID == "" {
				deviceID = genDevID
			}
		}
	}

	// 步骤 4: 调用 /auth/me 获取最新信息
	cli := mirasim.NewMirasimClient(mirasim.DefaultAuthBaseURL, "")
	userInfo, err := cli.GetUserInfo(ctx, token)
	if err != nil {
		fmt.Printf("[MirasimOAuth] warning: get local user info failed: %v\n", err)
	}

	res := &MirasimTokenInfo{
		AccessToken:  token,
		RefreshToken: refreshToken,
		ExpiresIn:    86400,
		ExpiresAt:    time.Now().Add(24 * time.Hour).Unix(),
		Email:        settingData.Auth.Email,
		Name:         settingData.Auth.Name,
		DeviceID:     deviceID,
		PrivateKey:   privPEM,
		PublicKeyB64: pubKeyB64,
	}

	if userInfo != nil {
		if userInfo.Email != "" {
			res.Email = userInfo.Email
		}
		if userInfo.Name != "" {
			res.Name = userInfo.Name
		}
		res.Plan = userInfo.Plan
		res.PlanExp = userInfo.PlanExp
	}

	return res, nil
}

// BuildAccountCredentials 将 MirasimTokenInfo 组装为完整的 Account.Credentials 存储字典。
// 参数：
//   - tokenInfo: 授权信息
// 返回值：
//   - map[string]any: 规范化的 credentials 字典
func (s *MirasimOAuthService) BuildAccountCredentials(tokenInfo *MirasimTokenInfo) map[string]any {
	if tokenInfo == nil {
		return make(map[string]any)
	}

	creds := map[string]any{
		"api_key":            tokenInfo.AccessToken,
		"issuer_token":       tokenInfo.AccessToken,
		"base_url":           mirasim.DefaultRelayBaseURL,
		"private_key":        tokenInfo.PrivateKey,
		"device_private_key": tokenInfo.PrivateKey,
		"device_id":          tokenInfo.DeviceID,
		"auth_type":          "oauth",
	}

	if tokenInfo.RefreshToken != "" {
		creds["refresh_token"] = tokenInfo.RefreshToken
	}
	if tokenInfo.ExpiresAt > 0 {
		creds["expires_at"] = tokenInfo.ExpiresAt
	}
	if tokenInfo.Email != "" {
		creds["email"] = tokenInfo.Email
	}
	if tokenInfo.Name != "" {
		creds["name"] = tokenInfo.Name
	}
	if tokenInfo.Plan != "" {
		creds["plan"] = tokenInfo.Plan
	}
	if tokenInfo.PlanExp != nil {
		creds["plan_exp"] = tokenInfo.PlanExp
	}

	// 注入默认自适应分流规则
	rules := DefaultMirasimProtocolRules()
	ruleMaps := make([]map[string]any, 0, len(rules))
	for _, r := range rules {
		ruleMaps = append(ruleMaps, map[string]any{
			"pattern":  r.Pattern,
			"protocol": r.Protocol,
		})
	}
	creds[mirasimProtocolRulesKey] = ruleMaps

	return creds
}

// RefreshAccountToken 通过账户代理刷新访问 Token，代理无法解析时返回错误而不直连。
// 参数：
//   - ctx: 上下文
//   - account: 账户实体
// 返回值：
//   - *MirasimTokenInfo: 刷新结果
//   - error: 刷新错误
func (s *MirasimOAuthService) RefreshAccountToken(ctx context.Context, account *Account) (*MirasimTokenInfo, error) {
	if account == nil || account.Platform != PlatformMirasim {
		return nil, fmt.Errorf("invalid mirasim account")
	}

	refreshToken := strings.TrimSpace(account.GetCredential("refresh_token"))
	if refreshToken == "" {
		return nil, fmt.Errorf("no refresh_token found in account credentials")
	}

	// 优先复用账号已加载的代理，兼容连接测试中未注入代理仓库的调用。
	if account.ProxyID != nil && account.Proxy == nil && s.proxyRepo != nil {
		proxy, err := s.proxyRepo.GetByID(ctx, *account.ProxyID)
		if err == nil && proxy != nil {
			account.Proxy = proxy
		}
	}
	proxyURL, err := mirasimAccountProxyURL(account)
	if err != nil {
		return nil, err
	}

	// 步骤 1: 刷新 Token
	cli := mirasim.NewMirasimClient(mirasim.DefaultAuthBaseURL, proxyURL)
	tokenResp, err := cli.RefreshToken(ctx, refreshToken)
	if err != nil {
		return nil, fmt.Errorf("refresh token failed: %w", err)
	}

	// 步骤 2: 读取更新后的用户资料
	userInfo, err := cli.GetUserInfo(ctx, tokenResp.AccessToken)
	if err != nil {
		fmt.Printf("[MirasimOAuth] warning: get user info failed: %v\n", err)
	}

	expiresIn := tokenResp.ExpiresIn
	if expiresIn <= 0 {
		expiresIn = 3600
	}
	expiresAt := time.Now().Add(time.Duration(expiresIn) * time.Second).Unix()
	// 上游 /auth/refresh 未返回 expires_in 时，直接解析 access_token 的 JWT exp，
	// 避免兜底时长与上游实际 TTL（当前为 1 小时）不一致导致刷新器误判未过期。
	if jwtExp, err := mirasim.ParseJWTExpiresAt(tokenResp.AccessToken); err == nil && jwtExp > 0 {
		expiresAt = jwtExp
		secs := int64(time.Until(time.Unix(jwtExp, 0)).Seconds())
		if secs < 0 {
			secs = 0
		}
		expiresIn = secs
	}

	res := &MirasimTokenInfo{
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
		ExpiresIn:    expiresIn,
		ExpiresAt:    expiresAt,
		DeviceID:     strings.TrimSpace(account.GetCredential("device_id")),
		PrivateKey:   strings.TrimSpace(account.GetCredential("private_key")),
	}

	if userInfo != nil {
		res.Email = userInfo.Email
		res.Name = userInfo.Name
		res.Plan = userInfo.Plan
		res.PlanExp = userInfo.PlanExp
	} else {
		res.Email = strings.TrimSpace(account.GetCredential("email"))
		res.Name = strings.TrimSpace(account.GetCredential("name"))
		res.Plan = strings.TrimSpace(account.GetCredential("plan"))
	}

	return res, nil
}
