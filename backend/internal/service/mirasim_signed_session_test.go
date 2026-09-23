//go:build unit

package service

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestMirasimSignedSessionEnvelope 验证空元数据和已有会话都封装设备签名，清除大小写混用的旧认证字段。
// 参数 t 为测试上下文；无返回值，失败时报告协议回归。
func TestMirasimSignedSessionEnvelope(t *testing.T) {
	for _, withMetadata := range []bool{false, true} {
		name := "无会话元数据"
		if withMetadata {
			name = "带会话元数据"
		}
		t.Run(name, func(t *testing.T) {
			account := newMirasimGatewayTestAccount(t)
			body := []byte(`{"model":"claude-fable-5-1","messages":[{"role":"user","content":"hi"}]}`)
			req, err := http.NewRequest(http.MethodPost, account.GetOpenAIBaseURL()+"/v1/messages", bytes.NewReader(body))
			require.NoError(t, err)
			for _, key := range []string{headerMirasimDevice, headerMirasimTS, headerMirasimNonce, headerMirasimSig, headerMirasimEnc, headerMirasimClient} {
				req.Header[key] = []string{"stale-value"}
				req.Header.Set(key, "another-stale-value")
			}
			if withMetadata {
				req.Header["x-mirasim-session"] = []string{"session-test"}
				req.Header.Set("X-Mirasim-Agent", "claude")
				req.Header.Set(headerMirasimProbe, "usage")
			}
			require.NoError(t, SignAndSealRelayRequest(context.Background(), req, account, body))
			requireMirasimGatewaySignature(t, account, &httpUpstreamRecorder{lastReq: req, lastBody: body})
			require.NotEqual(t, "stale-value", req.Header.Get(headerMirasimEnc))
			actualBody, err := io.ReadAll(req.Body)
			require.NoError(t, err)
			require.Equal(t, body, actualBody)
		})
	}
}

// TestMirasimRelaySignatureBindsMetadataAndBody 验证签名覆盖会话元数据和最终请求体，任意一项变更都会使签名失效。
// 参数 t 为测试上下文；无返回值。
func TestMirasimRelaySignatureBindsMetadataAndBody(t *testing.T) {
	account := newMirasimGatewayTestAccount(t)
	body := []byte(`{"model":"claude-fable-5-1","messages":[{"role":"user","content":"最终请求"}]}`)
	req, err := http.NewRequest(http.MethodPost, account.GetOpenAIBaseURL()+"/v1/messages", nil)
	require.NoError(t, err)
	metadata := map[string]string{"x-mirasim-session": "session-test", "x-mirasim-agent": "claude"}
	require.NoError(t, signMirasimRelayRequestWithMetadata(context.Background(), account, req, body, "gateway-ticket", metadata))
	seed, err := ParseEd25519Seed(account.GetMirasimPrivateKey())
	require.NoError(t, err)
	signer, err := GetMirasimSigner()
	require.NoError(t, err)
	for _, tc := range []struct {
		name string
		metadata map[string]string
		body []byte
		valid bool
	}{
		{name: "原始内容", metadata: metadata, body: body, valid: true},
		{name: "删除元数据", body: body},
		{name: "修改会话", metadata: map[string]string{"x-mirasim-session": "another-session", "x-mirasim-agent": "claude"}, body: body},
		{name: "修改最终请求体", metadata: metadata, body: []byte(`{"model":"another-model"}`)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			signature, err := signer.SignRelay(context.Background(), seed, req.Method, req.URL.Path,
				req.Header.Get(headerMirasimTS), req.Header.Get(headerMirasimNonce),
				req.Header.Get(headerMirasimDevice), req.Header.Get(headerMirasimClient),
				"gateway-ticket", tc.metadata, tc.body)
			require.NoError(t, err)
			require.Equal(t, tc.valid, signature == req.Header.Get(headerMirasimSig))
		})
	}
}

// TestMirasimSignedSessionRequiresDeviceKey 验证缺失私钥时在换票前明确失败，避免再次发送无签名请求。
// 参数 t 为测试上下文；无返回值。
func TestMirasimSignedSessionRequiresDeviceKey(t *testing.T) {
	account := &Account{ID: -1097, Platform: PlatformMirasim, Credentials: map[string]any{"issuer_token": "issuer"}}
	req, err := http.NewRequest(http.MethodPost, "https://relay.invalid/v1/messages", nil)
	require.NoError(t, err)
	require.ErrorContains(t, SignAndSealRelayRequest(context.Background(), req, account, nil), "requires private_key")
	require.Empty(t, req.Header.Get("Authorization"))
}
