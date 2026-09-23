//go:build unit

package service

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/stretchr/testify/require"
)

// TestMirasimTokenLifetime 验证 JWT 期限优先、过期令牌及历史错误期限；t 为测试上下文，无返回值。
func TestMirasimTokenLifetime(t *testing.T) {
	now := time.Unix(2000000000, 0)
	for _, tc := range []struct {
		name string
		payload string
		reported int64
		wantIn int64
		wantAt int64
	}{
		{"JWT 优先", `{"exp":2000000300}`, 86400, 300, 2000000300},
		{"已经过期", `{"exp":1999999999}`, 86400, 0, 1999999999},
		{"上游期限", `{}`, 120, 120, 2000000120},
		{"保守默认", `invalid`, 0, 3600, 2000003600},
	} {
		t.Run(tc.name, func(t *testing.T) {
			token := "header." + base64.RawURLEncoding.EncodeToString([]byte(tc.payload)) + ".signature"
			in, at := mirasimTokenLifetime(token, tc.reported, now)
			require.Equal(t, tc.wantIn, in)
			require.Equal(t, tc.wantAt, at)
		})
	}
	token := "header." + base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"exp":%d}`, time.Now().Add(-time.Minute).Unix()))) + ".signature"
	account := &Account{Platform: PlatformMirasim, Type: AccountTypeOAuth, Credentials: map[string]any{"issuer_token": token, "expires_at": time.Now().Add(24*time.Hour).Unix()}}
	require.True(t, NewMirasimTokenRefresher(nil).NeedsRefresh(account, time.Minute))
}

// TestMirasimTicketManagerConcurrentLifecycle 验证并发共享、等待者取消、配置变化与账号隔离；t 为测试上下文，无返回值。
func TestMirasimTicketManagerConcurrentLifecycle(t *testing.T) {
	var calls atomic.Int32
	entered, release := make(chan struct{}), make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		if n == 1 {
			close(entered)
			<-release
		}
		fmt.Fprintf(w, `{"ticket":"ticket-%d","expiresIn":600}`, n)
	}))
	defer server.Close()
	signer, err := GetMirasimSigner()
	require.NoError(t, err)
	manager := &MirasimTicketManager{signer: signer}
	account := newMirasimProxyTestAccount(t, server.URL)
	account.ProxyID, account.Proxy = nil, nil
	ctx, cancel := context.WithCancel(context.Background())
	first := make(chan error, 1)
	go func() { _, err := manager.GetOrMintTicket(ctx, account, server.URL); first <- err }()
	<-entered
	cancel()
	require.ErrorIs(t, <-first, context.Canceled)
	var wg sync.WaitGroup
	tickets, errs := make([]string, 24), make([]error, 24)
	for i := range tickets {
		wg.Add(1)
		go func(i int) { defer wg.Done(); tickets[i], errs[i] = manager.GetOrMintTicket(context.Background(), account, server.URL) }(i)
	}
	close(release)
	wg.Wait()
	for i := range tickets {
		require.NoError(t, errs[i])
		require.Equal(t, "ticket-1", tickets[i])
	}
	require.Equal(t, int32(1), calls.Load())
	for _, key := range []string{"issuer_token", "client_version", "private_key"} {
		value := "changed-"+key
		if key == "private_key" {
			value = base64.StdEncoding.EncodeToString([]byte("12345678901234567890123456789012"))
		}
		account.Credentials[key] = value
		before := calls.Load()
		_, err := manager.GetOrMintTicket(context.Background(), account, server.URL)
		require.NoError(t, err)
		require.Equal(t, before+1, calls.Load())
	}
	account.ID++
	_, err = manager.GetOrMintTicket(context.Background(), account, server.URL)
	require.NoError(t, err)
	require.Equal(t, int32(5), calls.Load())
	manager.Invalidate(account.ID, "ticket-1")
	_, err = manager.GetOrMintTicket(context.Background(), account, server.URL)
	require.NoError(t, err)
	require.Equal(t, int32(5), calls.Load(), "迟到的旧票据 401 不得清除新票据")
	manager.Invalidate(account.ID, "ticket-5")
	_, err = manager.GetOrMintTicket(context.Background(), account, server.URL)
	require.NoError(t, err)
	require.Equal(t, int32(6), calls.Load())
}

// TestMirasimTicketManagerInvalidationDuringMint 验证失效中的旧任务不能回填；t 为测试上下文，无返回值。
func TestMirasimTicketManagerInvalidationDuringMint(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		if n == 1 { close(entered); <-release }
		fmt.Fprintf(w, `{"ticket":"ticket-%d","expiresIn":600}`, n)
	}))
	defer server.Close()
	signer, err := GetMirasimSigner()
	require.NoError(t, err)
	manager := &MirasimTicketManager{signer: signer}
	account := newMirasimProxyTestAccount(t, server.URL)
	account.ProxyID, account.Proxy = nil, nil
	first := make(chan error, 1)
	go func() { _, err := manager.GetOrMintTicket(context.Background(), account, server.URL); first <- err }()
	<-entered
	manager.Invalidate(account.ID, "")
	ticket, err := manager.GetOrMintTicket(context.Background(), account, server.URL)
	close(release)
	require.NoError(t, err)
	require.Equal(t, "ticket-2", ticket)
	require.ErrorContains(t, <-first, "invalidated")
	ticket, err = manager.GetOrMintTicket(context.Background(), account, server.URL)
	require.NoError(t, err)
	require.Equal(t, "ticket-2", ticket)
}

// TestMirasimAuthClassification 验证协议、票据与未知错误不永久禁用无刷新令牌账号；t 为测试上下文，无返回值。
func TestMirasimAuthClassification(t *testing.T) {
	for _, code := range []string{"client_outdated", "device_signature", "device_clock_skew", "device_replay", "token_invalid", "token_missing", "upstream_auth", "unknown", "credential_revoked"} {
		t.Run(code, func(t *testing.T) {
			repo := &rateLimitAccountRepoStub{}
			invalidator := &tokenCacheInvalidatorRecorder{}
			svc := NewRateLimitService(repo, nil, &config.Config{}, nil, nil)
			svc.SetTokenCacheInvalidator(invalidator)
			account := &Account{ID: 1097, Platform: PlatformMirasim, Type: AccountTypeOAuth}
			body := []byte(fmt.Sprintf(`{"error":{"code":%q,"message":"authentication failed"}}`, code))
			require.True(t, svc.HandleUpstreamError(context.Background(), account, 401, http.Header{}, body))
			if code == "credential_revoked" {
				require.Equal(t, 1, repo.setErrorCalls)
				require.Len(t, invalidator.accounts, 1)
			} else {
				require.Zero(t, repo.setErrorCalls)
				require.Equal(t, 1, repo.tempCalls)
				require.Empty(t, invalidator.accounts)
				require.Contains(t, repo.lastTempReason, "Mirasim")
			}
		})
	}
}

// TestMirasimAuthResponseInvalidates 验证 401 按实际票据失效及无 Redis 的主动清理；t 为测试上下文，无返回值。
func TestMirasimAuthResponseInvalidates(t *testing.T) {
	account := newMirasimGatewayTestAccount(t)
	manager := GetMirasimTicketManager()
	_, err := manager.GetOrMintTicket(context.Background(), account, account.GetOpenAIBaseURL())
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, account.GetOpenAIBaseURL(), nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer gateway-ticket")
	observeMirasimResponse(account, req, &http.Response{StatusCode: 401})
	manager.mu.RLock()
	session := manager.cache[account.ID]
	manager.mu.RUnlock()
	require.Nil(t, session)
	_, err = manager.GetOrMintTicket(context.Background(), account, account.GetOpenAIBaseURL())
	require.NoError(t, err)
	require.NoError(t, NewCompositeTokenCacheInvalidator(nil).InvalidateToken(context.Background(), account))
	manager.mu.RLock()
	session = manager.cache[account.ID]
	manager.mu.RUnlock()
	require.Nil(t, session)
}

// TestMirasimAuthForcedRefresh 验证登录失败强制刷新，且旧标记不影响新令牌；t 为测试上下文，无返回值。
func TestMirasimAuthForcedRefresh(t *testing.T) {
	account := &Account{Platform: PlatformMirasim, Type: AccountTypeOAuth, Credentials: map[string]any{"issuer_token": "old", "expires_at": time.Now().Add(time.Hour).Unix()}}
	refresher := NewMirasimTokenRefresher(nil)
	require.False(t, refresher.NeedsRefresh(account, time.Minute))
	account.Extra = map[string]any{"mirasim_force_refresh_token": mirasimIssuerFingerprint(account)}
	require.True(t, refresher.NeedsRefresh(account, time.Minute))
	account.Credentials["issuer_token"] = "new"
	require.False(t, refresher.NeedsRefresh(account, time.Minute))
}

// TestMirasimTicketManagerMintFailure 验证换票阶段认证分类及失败后可重新换票；t 为测试上下文，无返回值。
func TestMirasimTicketManagerMintFailure(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":{"code":"token_invalid"}}`)
			return
		}
		fmt.Fprint(w, `{"ticket":"recovered","expiresIn":600}`)
	}))
	defer server.Close()
	signer, err := GetMirasimSigner()
	require.NoError(t, err)
	manager := &MirasimTicketManager{signer: signer}
	account := newMirasimProxyTestAccount(t, server.URL)
	account.ProxyID, account.Proxy = nil, nil
	_, err = manager.GetOrMintTicket(context.Background(), account, server.URL)
	var authErr *mirasimMintAuthError
	require.ErrorAs(t, err, &authErr)
	require.Equal(t, mirasimAuthLogin, authErr.kind)
	ticket, err := manager.GetOrMintTicket(context.Background(), account, server.URL)
	require.NoError(t, err)
	require.Equal(t, "recovered", ticket)
}

// TestMirasimAuthQuotaRetry 验证额度探测仅对票据错误重试一次，协议错误不刷新登录；t 为测试上下文，无返回值。
func TestMirasimAuthQuotaRetry(t *testing.T) {
	for _, code := range []string{"token_invalid", "client_outdated", "device_clock_skew", "upstream_auth"} {
		t.Run(code, func(t *testing.T) {
			account := newMirasimGatewayTestAccount(t)
			account.Credentials["expires_at"] = time.Now().Add(time.Hour).Unix()
			// 无刷新令牌仍可通过重新换票恢复，避免测试触达真实登录服务。
			delete(account.Credentials, "refresh_token")
			upstream := &httpUpstreamRecorder{responses: []*http.Response{
				{StatusCode: 401, Body: io.NopCloser(strings.NewReader(fmt.Sprintf(`{"error":{"code":%q}}`, code)))},
				{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"windows":[]}`))},
			}}
			cfg := &config.Config{}
			cfg.Security.URLAllowlist.AllowInsecureHTTP = true
			svc := NewCNProviderQuotaService(&rateLimitAccountRepoStub{}, nil, upstream, cfg)
			result, err := svc.queryUsageForAccount(context.Background(), account)
			require.NoError(t, err)
			if code == "token_invalid" {
				require.True(t, result.Success)
				require.Len(t, upstream.requests, 2)
			} else {
				require.False(t, result.Success)
				require.Len(t, upstream.requests, 1)
				require.Contains(t, result.Error, code)
			}
		})
	}
}
