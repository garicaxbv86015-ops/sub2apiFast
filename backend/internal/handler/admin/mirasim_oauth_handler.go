package admin

import (
	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
)

// MirasimOAuthHandler 提供 Mirasim 平台的 OAuth、邮箱验证码及本地凭证导入接口。
type MirasimOAuthHandler struct {
	mirasimOAuthService *service.MirasimOAuthService
}

// NewMirasimOAuthHandler 创建 Mirasim OAuth HTTP 控制器实例。
// 参数：
//   - mirasimOAuthService: Mirasim 授权服务
// 返回值：
//   - *MirasimOAuthHandler: 控制器实例
func NewMirasimOAuthHandler(mirasimOAuthService *service.MirasimOAuthService) *MirasimOAuthHandler {
	return &MirasimOAuthHandler{mirasimOAuthService: mirasimOAuthService}
}

// MirasimGenerateAuthURLRequest 生成 Mirasim 授权链接请求体。
type MirasimGenerateAuthURLRequest struct {
	// ProxyID 绑定的代理节点 ID
	ProxyID *int64 `json:"proxy_id"`
	// RedirectURI 自定义回调重定向地址
	RedirectURI string `json:"redirect_uri"`
	// Provider OAuth 认证源（默认 github）
	Provider string `json:"provider"`
}

// GenerateAuthURL 生成 Mirasim OAuth 浏览器跳转授权链接。
// POST /api/v1/admin/mirasim/oauth/auth-url
// 参数：
//   - c: Gin 上下文
func (h *MirasimOAuthHandler) GenerateAuthURL(c *gin.Context) {
	var req MirasimGenerateAuthURLRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "请求无效: "+err.Error())
		return
	}

	result, err := h.mirasimOAuthService.GenerateAuthURL(c.Request.Context(), req.ProxyID, req.RedirectURI, req.Provider)
	if err != nil {
		response.InternalError(c, "生成授权链接失败: "+err.Error())
		return
	}

	response.Success(c, result)
}

// MirasimExchangeCodeRequest 交换授权码或回调 Token 请求体。
type MirasimExchangeCodeRequest struct {
	// SessionID 临时授权会话 ID
	SessionID string `json:"session_id"`
	// State 校验状态码
	State string `json:"state"`
	// Code 回调 URL 或 AccessToken
	Code string `json:"code" binding:"required"`
	// ProxyID 绑定的代理节点 ID
	ProxyID *int64 `json:"proxy_id"`
}

// ExchangeCode 用授权回调结果交换 Token 并自动生成设备身份。
// POST /api/v1/admin/mirasim/oauth/exchange-code
// 参数：
//   - c: Gin 上下文
func (h *MirasimOAuthHandler) ExchangeCode(c *gin.Context) {
	var req MirasimExchangeCodeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "请求无效: "+err.Error())
		return
	}

	tokenInfo, err := h.mirasimOAuthService.ExchangeCode(c.Request.Context(), &service.MirasimExchangeCodeInput{
		SessionID: req.SessionID,
		State:     req.State,
		Code:      req.Code,
		ProxyID:   req.ProxyID,
	})
	if err != nil {
		response.BadRequest(c, "Token 交换失败: "+err.Error())
		return
	}

	response.Success(c, tokenInfo)
}

// MirasimSendEmailCodeRequest 发送邮箱登录验证码请求体。
type MirasimSendEmailCodeRequest struct {
	// Email 目标邮箱地址
	Email string `json:"email" binding:"required,email"`
	// ProxyID 绑定的代理节点 ID
	ProxyID *int64 `json:"proxy_id"`
}

// SendEmailCode 发送 Mirasim 邮箱登录验证码。
// POST /api/v1/admin/mirasim/oauth/send-code
// 参数：
//   - c: Gin 上下文
func (h *MirasimOAuthHandler) SendEmailCode(c *gin.Context) {
	var req MirasimSendEmailCodeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "请求无效: "+err.Error())
		return
	}

	result, err := h.mirasimOAuthService.SendEmailCode(c.Request.Context(), req.Email, req.ProxyID)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}

	response.Success(c, result)
}

// MirasimVerifyEmailCodeRequest 校验邮箱验证码请求体。
type MirasimVerifyEmailCodeRequest struct {
	// Email 目标邮箱地址
	Email string `json:"email" binding:"required,email"`
	// Code 接收到的验证码
	Code string `json:"code" binding:"required"`
	// ProxyID 绑定的代理节点 ID
	ProxyID *int64 `json:"proxy_id"`
}

// VerifyEmailCode 校验邮箱验证码，换取登录凭据并自动派生设备公私钥。
// POST /api/v1/admin/mirasim/oauth/verify-code
// 参数：
//   - c: Gin 上下文
func (h *MirasimOAuthHandler) VerifyEmailCode(c *gin.Context) {
	var req MirasimVerifyEmailCodeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "请求无效: "+err.Error())
		return
	}

	tokenInfo, err := h.mirasimOAuthService.VerifyEmailCode(c.Request.Context(), req.Email, req.Code, req.ProxyID)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}

	response.Success(c, tokenInfo)
}

// MirasimRefreshTokenRequest 刷新 Token 请求体。
type MirasimRefreshTokenRequest struct {
	// RefreshToken 现有有效的刷新令牌
	RefreshToken string `json:"refresh_token" binding:"required"`
	// ProxyID 绑定的代理节点 ID
	ProxyID *int64 `json:"proxy_id"`
}

// RefreshToken 校验并刷新 Mirasim RefreshToken，返回完整凭据。
// POST /api/v1/admin/mirasim/oauth/refresh-token
// 参数：
//   - c: Gin 上下文
func (h *MirasimOAuthHandler) RefreshToken(c *gin.Context) {
	var req MirasimRefreshTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "请求无效: "+err.Error())
		return
	}

	tokenInfo, err := h.mirasimOAuthService.ValidateRefreshToken(c.Request.Context(), req.RefreshToken, req.ProxyID)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}

	response.Success(c, tokenInfo)
}

// ImportLocal 从本地宿主机已安装的 Mirasim.app 导入登录凭据。
// POST /api/v1/admin/mirasim/oauth/import-local
// 参数：
//   - c: Gin 上下文
func (h *MirasimOAuthHandler) ImportLocal(c *gin.Context) {
	tokenInfo, err := h.mirasimOAuthService.ImportLocalMirasimApp(c.Request.Context())
	if err != nil {
		response.BadRequest(c, "导入本地 Mirasim 凭据失败: "+err.Error())
		return
	}

	response.Success(c, tokenInfo)
}
