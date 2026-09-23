package service

import (
	"net/http"
	"crypto/sha256"
	"fmt"
	"strings"
)

// mirasimAuthKind 区分签名协议、设备票据、登录凭据以及未知认证失败。
type mirasimAuthKind string

const (
	mirasimAuthProtocol mirasimAuthKind = "protocol"
	mirasimAuthTicket mirasimAuthKind = "ticket"
	mirasimAuthLogin mirasimAuthKind = "login"
	mirasimAuthUnknown mirasimAuthKind = "unknown"
)

// classifyMirasimAuth 按上游错误码判断恢复方式；body 为错误响应，返回类别和面向管理员的说明。
// token_invalid 出现在模型接口时指当前设备票据，不能据此撤销登录凭据。
func classifyMirasimAuth(body []byte) (mirasimAuthKind, string) {
	code := extractUpstreamErrorCode(body)
	switch code {
	case "client_outdated":
		return mirasimAuthProtocol, "Mirasim 签名会话协议需要升级（client_outdated）"
	case "device_signature":
		return mirasimAuthProtocol, "Mirasim 设备签名校验失败（device_signature），请检查签名协议及设备密钥"
	case "device_clock_skew":
		return mirasimAuthProtocol, "Mirasim 设备时间偏差（device_clock_skew），请同步服务器时间"
	case "device_replay":
		return mirasimAuthProtocol, "Mirasim 检测到重复签名（device_replay），请检查请求是否被重复发送"
	case "token_missing", "token_invalid", "ticket_expired", "ticket_invalid", "session_expired":
		return mirasimAuthTicket, "Mirasim 设备票据失效（" + code + "），下一次请求将重新换票"
	case "credential_revoked", "issuer_token_invalid", "issuer_token_expired":
		return mirasimAuthLogin, "Mirasim 登录凭据失效（" + code + "）"
	case "upstream_auth":
		return mirasimAuthUnknown, "Mirasim 中继的上游认证失败（upstream_auth），请检查供应商状态"
	default:
		return mirasimAuthUnknown, "Mirasim 认证失败，未识别为登录凭据失效"
	}
}

// observeMirasimResponse 清理被 401 拒绝的实际票据；参数为账号、已签名请求和响应，无返回值。
// 不读取响应体、不自动重放模型请求，迟到的旧响应也不会清除新票据。
func observeMirasimResponse(account *Account, req *http.Request, resp *http.Response) {
	if account == nil || !account.IsMirasim() || req == nil || resp == nil || resp.StatusCode != http.StatusUnauthorized {
		return
	}
	ticket := strings.TrimPrefix(req.Header.Get("Authorization"), "Bearer ")
	if ticket != "" {
		GetMirasimTicketManager().Invalidate(account.ID, ticket)
	}
}

// mirasimIssuerFingerprint 返回账号登录令牌的摘要，用于限定强制刷新标记适用的凭据版本；参数为账号，返回摘要字符串。
func mirasimIssuerFingerprint(account *Account) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(account.GetMirasimIssuerToken())))
}

// mirasimMintAuthError 保留换票阶段的认证类别，避免把 issuer 失效误判成设备票据失效。
type mirasimMintAuthError struct {
	// kind 表示协议、登录或未知错误。
	kind mirasimAuthKind
	// reason 为不包含原始凭据的诊断说明。
	reason string
}

// Error 返回换票认证错误的诊断说明；无参数，返回可展示消息。
func (e *mirasimMintAuthError) Error() string { return e.reason }
