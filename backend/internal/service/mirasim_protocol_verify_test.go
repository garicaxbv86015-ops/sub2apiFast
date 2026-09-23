//go:build unit

package service

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tetratelabs/wazero"
)

// mirasimTestCore 仅在测试接收端调用解封或规范化函数；参数为函数名及字节参数，返回复制后的结果（解密失败返回 nil）。
func mirasimTestCore(t *testing.T, name string, inputs ...[]byte) []byte {
	t.Helper()
	ctx := context.Background()
	signer, err := GetMirasimSigner()
	require.NoError(t, err)
	mod, err := signer.runtime.InstantiateModule(ctx, signer.compiled, wazero.NewModuleConfig().WithName(""))
	require.NoError(t, err)
	defer mod.Close(ctx)
	args := make([]uint64, 0, 2*len(inputs))
	for _, input := range inputs {
		allocated, err := mod.ExportedFunction("cc_alloc").Call(ctx, uint64(len(input)))
		require.NoError(t, err)
		require.True(t, mod.Memory().Write(uint32(allocated[0]), input))
		args = append(args, allocated[0], uint64(len(input)))
	}
	result, err := mod.ExportedFunction(name).Call(ctx, args...)
	require.NoError(t, err)
	ptr, length := uint32(result[0]>>32), uint32(result[0])
	if ptr == 0 || length == 0 { return nil }
	out, ok := mod.Memory().Read(ptr, length)
	require.True(t, ok)
	return append([]byte(nil), out...)
}

// mirasimIndependentVerify 用标准库 Ed25519 验证接收端规范串，绝不调用 SignRelay 重签。
// 参数为收到的请求、最终 body、解封元数据、票据和设备公钥；返回签名是否有效。
func mirasimIndependentVerify(t *testing.T, req *http.Request, body []byte, meta map[string]string, credential string, public ed25519.PublicKey) bool {
	t.Helper()
	fields := []byte(strings.Join([]string{req.Method, req.URL.Path, meta[headerMirasimTS], meta[headerMirasimNonce], meta[headerMirasimDevice], req.Header.Get(headerMirasimClient), credential}, "\x00"))
	keys := make([]string, 0, len(meta))
	for key := range meta {
		switch key {
		case headerMirasimDevice, headerMirasimTS, headerMirasimNonce, headerMirasimSig:
		default: keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	var parts []string
	for _, key := range keys { parts = append(parts, key, meta[key]) }
	canonical := mirasimTestCore(t, "cc_canonical", fields, []byte(strings.Join(parts, "\x00")), body)
	sig, err := base64.RawURLEncoding.DecodeString(meta[headerMirasimSig])
	require.NoError(t, err)
	return ed25519.Verify(public, canonical, sig)
}

// TestMirasimSignedSessionIndependentReceiver 在真实 HTTP 接收端解密封套并独立验签，同时验证前缀、query 和篡改失败。
// 参数 t 为测试上下文；无返回值，断言实际发出的请求体、票据及元数据共同受签名保护。
func TestMirasimSignedSessionIndependentReceiver(t *testing.T) {
	secret, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	seed := make([]byte, ed25519.SeedSize)
	public := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	body := []byte(`{"model":"claude-fable-5-1","messages":[{"role":"user","content":"最终内容"}]}`)
	type receivedRequest struct { req *http.Request; body []byte }
	received := make(chan receivedRequest, 3)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		received <- receivedRequest{r.Clone(context.Background()), data}
		if r.URL.Path == "/prefix/v1/device/session" {
			fmt.Fprint(w, `{"ticket":"verified-ticket","expiresIn":600}`)
			return
		}
		fmt.Fprint(w, `{"ok":true}`)
	}))
	defer server.Close()
	account := newMirasimProxyTestAccount(t, server.URL)
	account.ID = -1998
	account.ProxyID, account.Proxy = nil, nil
	account.Credentials["base_url"] = server.URL+"/prefix"
	req, err := http.NewRequest(http.MethodPost, server.URL+"/prefix/v1/messages?beta=true", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("x-mirasim-session", "session-test")
	req.Header.Set("x-mirasim-agent", "claude")
	require.NoError(t, signAndSealMirasimRequest(context.Background(), req, account, body, base64.StdEncoding.EncodeToString(secret.PublicKey().Bytes())))
	resp, err := server.Client().Do(req)
	require.NoError(t, err)
	resp.Body.Close()
	mint := <-received
	require.Equal(t, "/prefix/v1/device/session", mint.req.URL.Path)
	mintMeta := map[string]string{}
	for _, key := range []string{headerMirasimDevice, headerMirasimTS, headerMirasimNonce, headerMirasimSig} { mintMeta[key] = mint.req.Header.Get(key) }
	require.True(t, mirasimIndependentVerify(t, mint.req, mint.body, mintMeta, "test-issuer", public), "带前缀的换票请求必须可独立验签")
	actual := <-received
	require.Equal(t, "beta=true", actual.req.URL.RawQuery)
	require.Equal(t, body, actual.body)
	require.Equal(t, "Bearer verified-ticket", actual.req.Header.Get("Authorization"))
	for key := range actual.req.Header {
		if strings.HasPrefix(strings.ToLower(key), "x-mirasim-") { require.Contains(t, []string{headerMirasimClient, headerMirasimEnc}, strings.ToLower(key)) }
	}
	envelope, err := base64.RawURLEncoding.DecodeString(actual.req.Header.Get(headerMirasimEnc))
	require.NoError(t, err)
	aad := []byte("mrs-seal-v1\nPOST\n/prefix/v1/messages")
	plaintext := mirasimTestCore(t, "cc_open", secret.Bytes(), aad, envelope)
	require.NotEmpty(t, plaintext)
	meta := map[string]string{}
	require.NoError(t, json.Unmarshal(plaintext, &meta))
	for _, key := range []string{headerMirasimDevice, headerMirasimTS, headerMirasimNonce, headerMirasimSig} { require.NotEmpty(t, meta[key]) }
	require.Equal(t, "session-test", meta["x-mirasim-session"])
	require.Equal(t, "claude", meta["x-mirasim-agent"])
	require.True(t, mirasimIndependentVerify(t, actual.req, actual.body, meta, "verified-ticket", public))
	require.False(t, mirasimIndependentVerify(t, actual.req, []byte(`{"tampered":true}`), meta, "verified-ticket", public))
	require.False(t, mirasimIndependentVerify(t, actual.req, actual.body, meta, "wrong-ticket", public))
	meta["x-mirasim-session"] = "tampered"
	require.False(t, mirasimIndependentVerify(t, actual.req, actual.body, meta, "verified-ticket", public))
	for _, badAAD := range []string{"mrs-seal-v1\nGET\n/prefix/v1/messages", "mrs-seal-v1\nPOST\n/other"} {
		require.Empty(t, mirasimTestCore(t, "cc_open", secret.Bytes(), []byte(badAAD), envelope))
	}
	envelope[len(envelope)-1] ^= 1
	require.Empty(t, mirasimTestCore(t, "cc_open", secret.Bytes(), aad, envelope))
}
