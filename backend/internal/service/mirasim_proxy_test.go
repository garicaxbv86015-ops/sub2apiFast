package service

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

// newMirasimProxyTestAccount 根据测试代理地址构造带设备私钥的账号；返回独立账号对象。
func newMirasimProxyTestAccount(t *testing.T, proxyURL string) *Account {
	t.Helper()
	parsed, err := url.Parse(proxyURL)
	require.NoError(t, err)
	port, err := strconv.Atoi(parsed.Port())
	require.NoError(t, err)
	proxyID := int64(25)
	return &Account{
		ID: 1094,
		Platform: PlatformMirasim,
		ProxyID: &proxyID,
		Proxy: &Proxy{ID: proxyID, Protocol: parsed.Scheme, Host: parsed.Hostname(), Port: port},
		Credentials: map[string]any{
			"private_key": base64.StdEncoding.EncodeToString(make([]byte, 32)),
			"issuer_token": "test-issuer",
			"refresh_token": "test-refresh",
		},
	}
}

// TestMirasimTicketManager_AccountProxy 验证换票确实经过账号代理，缓存随代理和端点变化失效。
// 参数 t 为测试上下文；无返回值，失败时报告断言。
func TestMirasimTicketManager_AccountProxy(t *testing.T) {
	var firstCalls, secondCalls atomic.Int32
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		firstCalls.Add(1)
		if r.Method != http.MethodPost || r.URL.Path != mirasimDeviceSessionPath || r.Header.Get(headerMirasimSig) == "" {
			http.Error(w, "invalid ticket request", http.StatusBadRequest)
			return
		}
		fmt.Fprint(w, `{"ticket":"first-ticket","expiresIn":3600}`)
	}))
	defer first.Close()
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secondCalls.Add(1)
		fmt.Fprint(w, `{"ticket":"second-ticket","expiresIn":3600}`)
	}))
	defer second.Close()
	signer, err := GetMirasimSigner()
	require.NoError(t, err)
	manager := &MirasimTicketManager{cache: make(map[int64]*MirasimTicketSession), signer: signer}
	account := newMirasimProxyTestAccount(t, first.URL)
	ctx := context.Background()

	// 目标域名不可直连，成功返回票据即可证明请求到达测试代理。
	ticket, err := manager.GetOrMintTicket(ctx, account, "http://relay.invalid")
	require.NoError(t, err)
	require.Equal(t, "first-ticket", ticket)
	_, err = manager.GetOrMintTicket(ctx, account, "http://relay.invalid")
	require.NoError(t, err)
	require.Equal(t, int32(1), firstCalls.Load())

	account.Proxy = newMirasimProxyTestAccount(t, second.URL).Proxy
	ticket, err = manager.GetOrMintTicket(ctx, account, "http://relay.invalid")
	require.NoError(t, err)
	require.Equal(t, "second-ticket", ticket)
	require.Equal(t, int32(1), secondCalls.Load())
	_, err = manager.GetOrMintTicket(ctx, account, "http://another-relay.invalid")
	require.NoError(t, err)
	require.Equal(t, int32(2), secondCalls.Load())

	// 即便有缓存，关联缺失也不允许绕过已配置的代理。
	account.Proxy = nil
	_, err = manager.GetOrMintTicket(ctx, account, "http://another-relay.invalid")
	require.ErrorContains(t, err, "proxy 25 is not loaded")
}

// TestMirasimTicketManager_ProxyFailureDoesNotDialOrigin 验证代理故障不会回退直连；t 为测试上下文，无返回值。
func TestMirasimTicketManager_ProxyFailureDoesNotDialOrigin(t *testing.T) {
	var originCalls atomic.Int32
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originCalls.Add(1)
		fmt.Fprint(w, `{"ticket":"must-not-be-used","expiresIn":3600}`)
	}))
	defer origin.Close()
	proxy := httptest.NewServer(http.NotFoundHandler())
	account := newMirasimProxyTestAccount(t, proxy.URL)
	proxy.Close()
	signer, err := GetMirasimSigner()
	require.NoError(t, err)
	manager := &MirasimTicketManager{cache: make(map[int64]*MirasimTicketSession), signer: signer}
	_, err = manager.GetOrMintTicket(context.Background(), account, origin.URL)
	require.ErrorContains(t, err, "mint ticket request failed")
	require.Zero(t, originCalls.Load())
}

// TestMirasimOAuthService_RefreshUsesLoadedProxy 验证未注入仓库时刷新仍使用账号代理；t 为测试上下文，无返回值。
func TestMirasimOAuthService_RefreshUsesLoadedProxy(t *testing.T) {
	var calls atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect && r.Host == "auth.mirasim.ai:443" {
			calls.Add(1)
		}
		http.Error(w, "test proxy reached", http.StatusBadGateway)
	}))
	defer proxy.Close()
	account := newMirasimProxyTestAccount(t, proxy.URL)
	svc := NewMirasimOAuthService(nil, nil)
	defer svc.sessionStore.Stop()
	_, err := svc.RefreshAccountToken(context.Background(), account)
	require.Error(t, err)
	require.Equal(t, int32(1), calls.Load())
	account.Proxy = nil
	_, err = svc.RefreshAccountToken(context.Background(), account)
	require.ErrorContains(t, err, "proxy 25 is not loaded")
	require.Equal(t, int32(1), calls.Load())
}
