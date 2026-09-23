//go:build unit

package service

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestMirasimRequestCapture 验证完整正文、线上自动头、凭据脱敏和响应流不受采集影响；t 为测试上下文，无返回值。
func TestMirasimRequestCapture(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("MIRASIM_CAPTURE_DIR", dir)
	t.Setenv("MIRASIM_CAPTURE_ACCOUNT_ID", "1094")
	t.Setenv("MIRASIM_CAPTURE_UNTIL", time.Now().Add(time.Minute).Format(time.RFC3339))
	mirasimCaptureCount.Store(0)
	t.Cleanup(func() { mirasimCaptureCount.Store(0) })
	const body = `{"model":"claude-opus-5","system":"你是 pi，请保留这些指令。","messages":[{"role":"user","content":"你好"}]}`
	var receivedBody, receivedAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		receivedBody = string(raw)
		receivedAuth = r.Header.Get("Authorization")
		w.Header().Set("Request-Id", "capture-test")
		w.Header().Set("Set-Cookie", "private-cookie")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"error":"invalid"}`)
	}))
	defer server.Close()
	req, err := http.NewRequest(http.MethodPost, server.URL+"/v1/messages", strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer private-ticket")
	req.Header.Set(headerMirasimSig, "private-signature")
	req.Header.Set(headerMirasimClient, "0.0.322")
	req, capture := beginMirasimRequestCapture(req, &Account{ID: 1094, Platform: "mirasim"})
	require.NotNil(t, capture)
	resp, err := server.Client().Do(req)
	capture.finish(resp, err)
	require.NoError(t, err)
	defer resp.Body.Close()
	responseBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, `{"error":"invalid"}`, string(responseBody))
	require.Equal(t, body, receivedBody)
	require.Equal(t, "Bearer private-ticket", receivedAuth)
	files, err := filepath.Glob(filepath.Join(dir, "request-*.json"))
	require.NoError(t, err)
	require.Len(t, files, 1)
	raw, err := os.ReadFile(files[0])
	require.NoError(t, err)
	require.NotContains(t, string(raw), "private-ticket")
	require.NotContains(t, string(raw), "private-signature")
	require.NotContains(t, string(raw), "private-cookie")
	var saved struct {
		Body string `json:"body"`
		WireHeaders http.Header `json:"wire_headers"`
		StatusCode int `json:"status_code"`
	}
	require.NoError(t, json.Unmarshal(raw, &saved))
	require.Equal(t, body, saved.Body)
	require.Equal(t, 400, saved.StatusCode)
	require.Equal(t, "gzip", saved.WireHeaders.Get("Accept-Encoding"))
	require.Equal(t, "Go-http-client/1.1", saved.WireHeaders.Get("User-Agent"))
	info, err := os.Stat(files[0])
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0600), info.Mode().Perm())
	// 未选中账号、过期和采集达到上限时，都必须直接返回原请求。
	unchanged, skipped := beginMirasimRequestCapture(req, &Account{ID: 1095, Platform: "mirasim"})
	require.Same(t, req, unchanged)
	require.Nil(t, skipped)
	mirasimCaptureCount.Store(12)
	_, skipped = beginMirasimRequestCapture(req, &Account{ID: 1094, Platform: "mirasim"})
	require.Nil(t, skipped)
	mirasimCaptureCount.Store(0)
	t.Setenv("MIRASIM_CAPTURE_UNTIL", time.Now().Add(-time.Minute).Format(time.RFC3339))
	_, skipped = beginMirasimRequestCapture(req, &Account{ID: 1094, Platform: "mirasim"})
	require.Nil(t, skipped)
}
