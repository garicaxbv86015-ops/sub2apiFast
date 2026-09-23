package service

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptrace"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// mirasimCaptureCount 限制单进程最多保存 12 次诊断，避免完整会话持续落盘。
var mirasimCaptureCount atomic.Int64

// mirasimRequestCapture 保存指定账号的出站快照；只在显式配置且未过期时启用。
type mirasimRequestCapture struct {
	mu sync.Mutex
	file *os.File
	data map[string]any
	wireHeaders http.Header
}

// redactMirasimCaptureHeader 对凭据头保留名称并隐藏值；参数为头名和值，返回独立的脱敏值副本。
func redactMirasimCaptureHeader(name string, values []string) []string {
	lower := strings.ToLower(name)
	if strings.Contains(lower, "authorization") || strings.Contains(lower, "cookie") ||
		strings.Contains(lower, "api-key") || strings.Contains(lower, "apikey") ||
		strings.Contains(lower, "token") || strings.Contains(lower, "secret") ||
		lower == headerMirasimSig || lower == headerMirasimEnc || lower == headerMirasimDevice {
		return []string{"[已隐藏]"}
	}
	return append([]string(nil), values...)
}

// mirasimCaptureHeaders 复制完整头集合并脱敏；参数为原始头，返回不共享值切片的诊断头集合。
func mirasimCaptureHeaders(headers http.Header) http.Header {
	out := make(http.Header, len(headers))
	for key, values := range headers {
		out[key] = redactMirasimCaptureHeader(key, values)
	}
	return out
}

// beginMirasimRequestCapture 在签名完成后捕获完整请求体，并挂接实际发出的传输头。
// 参数为最终请求与账号；返回附带跟踪上下文的请求和快照，未启用或采集失败时原样返回请求及 nil。
// MIRASIM_CAPTURE_DIR、MIRASIM_CAPTURE_ACCOUNT_ID、MIRASIM_CAPTURE_UNTIL（RFC3339）必须同时配置。
func beginMirasimRequestCapture(req *http.Request, account *Account) (*http.Request, *mirasimRequestCapture) {
	if req == nil || req.URL == nil || account == nil || !account.IsMirasim() || !strings.HasSuffix(req.URL.Path, "/v1/messages") {
		return req, nil
	}
	dir := os.Getenv("MIRASIM_CAPTURE_DIR")
	accountID, err := strconv.ParseInt(os.Getenv("MIRASIM_CAPTURE_ACCOUNT_ID"), 10, 64)
	if dir == "" || err != nil || accountID != account.ID {
		return req, nil
	}
	until, err := time.Parse(time.RFC3339, os.Getenv("MIRASIM_CAPTURE_UNTIL"))
	if err != nil || !time.Now().Before(until) || mirasimCaptureCount.Add(1) > 12 {
		return req, nil
	}
	// 只读取可复制请求体，诊断失败不消费原始流，也不阻止正常转发。
	if req.GetBody == nil {
		return req, nil
	}
	body, err := req.GetBody()
	if err != nil {
		return req, nil
	}
	defer body.Close()
	const maxCaptureBytes = 8 * 1024 * 1024
	raw, err := io.ReadAll(io.LimitReader(body, maxCaptureBytes+1))
	if err != nil || len(raw) > maxCaptureBytes {
		slog.Warn("mirasim_capture_body_skipped", "account_id", account.ID, "size_over_limit", len(raw) > maxCaptureBytes)
		return req, nil
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		slog.Warn("mirasim_capture_directory_failed", "account_id", account.ID)
		return req, nil
	}
	file, err := os.CreateTemp(dir, "request-*.json")
	if err != nil {
		slog.Warn("mirasim_capture_file_failed", "account_id", account.ID)
		return req, nil
	}
	// 诊断文件权限为 0600；请求体保留完整指令和消息，只在本次指定目录保存。
	digest := sha256.Sum256(raw)
	urlCopy := *req.URL
	urlCopy.User = nil
	query := urlCopy.Query()
	for key, values := range query {
		query[key] = redactMirasimCaptureHeader(key, values)
	}
	urlCopy.RawQuery = query.Encode()
	capture := &mirasimRequestCapture{
		file: file,
		wireHeaders: make(http.Header),
		data: map[string]any{
			"captured_at": time.Now().UTC().Format(time.RFC3339Nano),
			"account_id": account.ID,
			"method": req.Method,
			"url": urlCopy.String(),
			"host": req.Host,
			"content_length": req.ContentLength,
			"headers": mirasimCaptureHeaders(req.Header),
			"body": string(raw),
			"body_bytes": len(raw),
			"body_sha256": hex.EncodeToString(digest[:]),
		},
	}
	// httptrace 捕获 Transport 补入的 Accept-Encoding、User-Agent 等实际头，避免把构造阶段误认为线上完整头。
	trace := &httptrace.ClientTrace{WroteHeaderField: func(key string, values []string) {
		capture.mu.Lock()
		defer capture.mu.Unlock()
		capture.wireHeaders[key] = append(capture.wireHeaders[key], redactMirasimCaptureHeader(key, values)...)
	}}
	return req.WithContext(httptrace.WithClientTrace(req.Context(), trace)), capture
}

// finish 保存响应状态和脱敏响应头并关闭快照文件；参数为上游响应和传输错误，无返回值。
// 不读取响应体，保持 SSE 流、错误解析和计费链路的原有行为。
func (capture *mirasimRequestCapture) finish(resp *http.Response, requestErr error) {
	if capture == nil {
		return
	}
	defer capture.file.Close()
	capture.mu.Lock()
	defer capture.mu.Unlock()
	capture.data["wire_headers"] = capture.wireHeaders
	if resp != nil {
		capture.data["status_code"] = resp.StatusCode
		capture.data["response_protocol"] = resp.Proto
		capture.data["response_headers"] = mirasimCaptureHeaders(resp.Header)
	}
	capture.data["transport_failed"] = requestErr != nil
	encoder := json.NewEncoder(capture.file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(capture.data); err != nil {
		slog.Warn("mirasim_capture_write_failed", "path", capture.file.Name())
		return
	}
	slog.Info("mirasim_request_captured", "path", capture.file.Name(), "status_code", capture.data["status_code"])
}
