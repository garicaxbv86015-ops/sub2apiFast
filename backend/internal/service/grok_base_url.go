package service

import (
	"fmt"
	"net/url"
	"strings"
)

// normalizeGrokAPIBaseURL 规范化 Grok API Base URL。
// 参数 raw 表示已经通过安全策略校验的用户配置地址。
// 返回值为补齐并规范化后的 /v1 Base URL，错误表示路径或 URL 格式不符合 Grok API 约定。
func normalizeGrokAPIBaseURL(raw string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("invalid url: %s", raw)
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "https" && scheme != "http" {
		return "", fmt.Errorf("invalid url scheme: %s", parsed.Scheme)
	}
	path := strings.TrimRight(parsed.Path, "/")
	if path == "" {
		parsed.Path = "/v1"
		parsed.RawPath = ""
		return strings.TrimRight(parsed.String(), "/"), nil
	}
	if path != "/v1" {
		return "", fmt.Errorf("base URL path must be /v1")
	}
	parsed.Path = path
	parsed.RawPath = ""
	return strings.TrimRight(parsed.String(), "/"), nil
}

// buildGrokAPIEndpointURL 基于 Grok Base URL 拼接 API 端点。
// 参数 baseURL 表示 Grok API Base URL，endpointPath 表示不含前导 /v1 的端点路径。
// 返回值为完整上游请求地址，错误表示 Base URL 或端点路径无效。
func buildGrokAPIEndpointURL(baseURL string, endpointPath string) (string, error) {
	normalizedBaseURL, err := normalizeGrokAPIBaseURL(baseURL)
	if err != nil {
		return "", fmt.Errorf("invalid base url: %w", err)
	}
	endpointPath = strings.Trim(endpointPath, "/")
	if endpointPath == "" {
		return "", fmt.Errorf("endpoint path is required")
	}
	return normalizedBaseURL + "/" + endpointPath, nil
}

// buildGrokAPIVideoURL 基于 Grok Base URL 和视频请求 ID 拼接视频状态地址。
// 参数 baseURL 表示 Grok API Base URL，requestID 表示视频请求 ID。
// 返回值为完整视频状态查询地址，错误表示 Base URL 或请求 ID 无效。
func buildGrokAPIVideoURL(baseURL, requestID string) (string, error) {
	normalizedBaseURL, err := normalizeGrokAPIBaseURL(baseURL)
	if err != nil {
		return "", fmt.Errorf("invalid base url: %w", err)
	}
	requestID = strings.TrimSpace(requestID)
	if requestID == "" {
		return "", fmt.Errorf("request id is required")
	}
	return normalizedBaseURL + "/videos/" + url.PathEscape(requestID), nil
}
