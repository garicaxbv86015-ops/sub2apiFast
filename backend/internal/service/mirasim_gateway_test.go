//go:build unit

package service

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
)

// newMirasimGatewayTestAccount 创建仅连接本地换票服务的账号；t 为测试上下文，返回测试账号。
func newMirasimGatewayTestAccount(t *testing.T) *Account {
	t.Helper()
	mint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != mirasimDeviceSessionPath {
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, `{"ticket":"gateway-ticket","expiresIn":3600}`)
	}))
	t.Cleanup(mint.Close)
	account := newMirasimProxyTestAccount(t, mint.URL)
	account.ID = -1094
	account.Type = AccountTypeOAuth
	account.ProxyID = nil
	account.Proxy = nil
	account.Credentials["base_url"] = mint.URL
	account.Credentials["api_protocol"] = APIProtocolAdaptive
	account.Credentials["api_key"] = "issuer-token"
	account.Credentials["api_base_urls"] = map[string]any{APIProtocolAnthropic: mint.URL}
	account.Credentials["model_mapping"] = map[string]any{"client-alias": "claude-sonnet-5"}
	return account
}

// requireMirasimGatewaySignature 校验最终发送内容的签名及鉴权头；参数为测试上下文、账号和捕获的请求，无返回值。
func requireMirasimGatewaySignature(t *testing.T, account *Account, upstream *httpUpstreamRecorder) {
	t.Helper()
	req := upstream.lastReq
	require.NotNil(t, req)
	require.Equal(t, "Bearer gateway-ticket", req.Header.Get("Authorization"))
	authHeaders := 0
	for key := range req.Header {
		if strings.EqualFold(key, "authorization") {
			authHeaders++
		}
		require.False(t, strings.EqualFold(key, "x-api-key"))
		require.False(t, strings.EqualFold(key, "x-goog-api-key"))
	}
	require.Equal(t, 1, authHeaders)
	seed, err := ParseEd25519Seed(account.GetMirasimPrivateKey())
	require.NoError(t, err)
	signer, err := GetMirasimSigner()
	require.NoError(t, err)
	// 用实际发送的请求体校验，能发现模型映射或清洗后仍签原始入站内容的错误。
	expected, err := signer.SignRelay(context.Background(), seed, req.Method, req.URL.Path,
		req.Header.Get(headerMirasimTS), req.Header.Get(headerMirasimNonce),
		req.Header.Get(headerMirasimDevice), req.Header.Get(headerMirasimClient),
		"gateway-ticket", nil, upstream.lastBody)
	require.NoError(t, err)
	require.Equal(t, expected, req.Header.Get(headerMirasimSig))
}

// TestMirasimGateway_Messages 验证正式 Messages 转发的流式、非流式分支均在最终内容上签名；t 为测试上下文，无返回值。
func TestMirasimGateway_Messages(t *testing.T) {
	for _, stream := range []bool{false, true} {
		t.Run(fmt.Sprintf("stream=%v", stream), func(t *testing.T) {
			account := newMirasimGatewayTestAccount(t)
			body := []byte(fmt.Sprintf(`{"model":"client-alias","stream":%v,"max_tokens":32,"messages":[{"role":"user","content":[{"type":"text","text":""},{"type":"text","text":"hi"}]}]}`, stream))
			resp := nativeAnthropicBufferedResponse()
			if stream {
				resp = nativeAnthropicStreamResponse()
			}
			upstream := &httpUpstreamRecorder{resp: resp}
			svc := &OpenAIGatewayService{cfg: rawChatCompletionsTestConfig(), httpUpstream: upstream}
			result, err := svc.ForwardAsAnthropic(context.Background(), adaptiveProtocolTestContext("/v1/messages", body), account, body, "", "")
			require.NoError(t, err)
			require.NotNil(t, result)
			require.Equal(t, "claude-sonnet-5", gjson.GetBytes(upstream.lastBody, "model").String())
			require.Equal(t, int64(1), gjson.GetBytes(upstream.lastBody, "messages.0.content.#").Int())
			require.Equal(t, claudeCodeSystemPrompt, gjson.GetBytes(upstream.lastBody, "system.0.text").String())
			requireMirasimGatewaySignature(t, account, upstream)
		})
	}
}

// TestMirasimGateway_Responses 验证正式 GPT 入口使用 Mirasim 凭据、中继地址及最终请求签名。
// 参数 t 为测试上下文；无返回值，失败时报告转发路径差异。
func TestMirasimGateway_Responses(t *testing.T) {
	for _, stream := range []bool{false, true} {
		t.Run(fmt.Sprintf("stream=%v", stream), func(t *testing.T) {
			account := newMirasimGatewayTestAccount(t)
			account.Credentials["api_base_urls"].(map[string]any)[APIProtocolResponses] = account.GetCredential("base_url") + "/gpt/v1"
			account.Credentials["model_mapping"] = map[string]any{"client-gpt": "gpt-6-astra"}
			body := []byte(fmt.Sprintf(`{"model":"client-gpt","input":"hi","stream":%v}`, stream))
			responseJSON := `{"id":"resp_test","object":"response","status":"completed","model":"gpt-6-astra","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"OK"}]}],"usage":{"input_tokens":1,"output_tokens":1}}`
			upstream := &httpUpstreamRecorder{resp: &http.Response{
				StatusCode: http.StatusOK,
				Header: http.Header{"Content-Type": []string{"text/event-stream"}},
				Body: io.NopCloser(strings.NewReader("data: {\"type\":\"response.completed\",\"response\":" + responseJSON + "}\n\ndata: [DONE]\n\n")),
			}}
			// 保留真实 OpenAI TokenProvider，确保 Mirasim 不再误入其平台校验。
			svc := &OpenAIGatewayService{cfg: rawChatCompletionsTestConfig(), httpUpstream: upstream, openAITokenProvider: &OpenAITokenProvider{}}
			c := adaptiveProtocolTestContext("/v1/responses", body)
			result, err := svc.Forward(context.Background(), c, account, body)
			require.NoError(t, err)
			require.Equal(t, stream, result.Stream)
			require.Equal(t, http.StatusOK, c.Writer.Status())
			require.NotNil(t, upstream.lastReq)
			require.Equal(t, account.GetCredential("base_url")+"/gpt/v1/responses", upstream.lastReq.URL.String())
			require.NotEqual(t, "chatgpt.com", upstream.lastReq.Host)
			require.Empty(t, upstream.lastReq.Header.Get("Chatgpt-Account-Id"))
			require.True(t, gjson.GetBytes(upstream.lastBody, "stream").Bool())
			require.Equal(t, "hi", gjson.GetBytes(upstream.lastBody, "input.0.content.0.text").String())
			require.Equal(t, "text/event-stream", upstream.lastReq.Header.Get("Accept"))
			require.Equal(t, "gpt-6-astra", gjson.GetBytes(upstream.lastBody, "model").String())
			requireMirasimGatewaySignature(t, account, upstream)
		})
	}
}

// TestMirasimGateway_Transport 验证各 HTTP 出口覆盖签名且不消费待发送内容；t 为测试上下文，无返回值。
func TestMirasimGateway_Transport(t *testing.T) {
	for _, endpoint := range []string{"/v1/messages", "/v1/responses", "/v1/chat/completions"} {
		for _, copyable := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/copyable=%v", endpoint, copyable), func(t *testing.T) {
				account := newMirasimGatewayTestAccount(t)
				body := []byte(`{"model":"claude-sonnet-5","messages":[{"role":"user","content":"hi"}]}`)
				req, err := http.NewRequest(http.MethodPost, account.GetOpenAIBaseURL()+endpoint, bytes.NewReader(body))
				require.NoError(t, err)
				if !copyable {
					req.GetBody = nil
				}
				req.Header["authorization"] = []string{"Bearer old-token"}
				req.Header["x-api-key"] = []string{"old-key"}
				req.Header["X-Api-Key"] = []string{"another-old-key"}
				upstream := &httpUpstreamRecorder{resp: &http.Response{StatusCode: 200, Body: http.NoBody}}
				svc := &OpenAIGatewayService{httpUpstream: upstream}
				_, err = svc.doOpenAIUpstream(req, "", account)
				require.NoError(t, err)
				require.Equal(t, body, upstream.lastBody)
				requireMirasimGatewaySignature(t, account, upstream)
			})
		}
	}
}

// TestMirasimGateway_SigningFailureStopsDispatch 验证无法读取签名内容时不发送未签名请求；t 为测试上下文，无返回值。
func TestMirasimGateway_SigningFailureStopsDispatch(t *testing.T) {
	account := newMirasimGatewayTestAccount(t)
	req, err := http.NewRequest(http.MethodPost, account.GetOpenAIBaseURL()+"/v1/messages", nil)
	require.NoError(t, err)
	req.Body = passthroughErrReadCloser{err: io.ErrUnexpectedEOF}
	upstream := &httpUpstreamRecorder{}
	svc := &OpenAIGatewayService{httpUpstream: upstream}
	_, err = svc.doOpenAIUpstream(req, "", account)
	require.ErrorContains(t, err, "read mirasim request body")
	require.Empty(t, upstream.requests)
}

// TestMirasimGateway_SystemCompatibility 验证 system 补齐保留用户指令且对已有标识幂等；t 为测试上下文，无返回值。
func TestMirasimGateway_SystemCompatibility(t *testing.T) {
	cases := []struct {
		name string
		body string
		preserved string
		unchanged bool
	}{
		{name: "缺省", body: `{"model":"claude-sonnet-5","messages":[{"role":"user","content":"hi"}]}`},
		{name: "字符串", body: `{"model":"claude-sonnet-5","system":"请使用中文回答。","messages":[{"role":"user","content":"hi"}]}`, preserved: "请使用中文回答。"},
		{name: "数组", body: `{"model":"claude-sonnet-5","system":[{"type":"text","text":"保持原有业务指令。"}],"messages":[{"role":"user","content":"hi"}]}`, preserved: "保持原有业务指令。"},
		{name: "已有标识", body: `{"model":"claude-sonnet-5","system":[{"type":"text","text":"You are Claude Code, Anthropic's official CLI for Claude."}],"messages":[{"role":"user","content":"hi"}]}`, unchanged: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			account := newMirasimGatewayTestAccount(t)
			svc := &OpenAIGatewayService{}
			req, body, err := svc.buildNativeAnthropicUpstreamRequest(context.Background(), nil, account, []byte(tc.body), "issuer-token", account.GetOpenAIBaseURL()+"/v1/messages")
			require.NoError(t, err)
			defer req.Body.Close()
			require.True(t, systemIncludesClaudeCodePrompt(gjson.GetBytes(body, "system").Value()))
			if tc.preserved != "" {
				require.Contains(t, gjson.GetBytes(body, "system").Raw, tc.preserved)
			}
			if tc.unchanged {
				require.Equal(t, tc.body, string(body))
			}
			repeated, repeatedBody, err := svc.buildNativeAnthropicUpstreamRequest(context.Background(), nil, account, body, "issuer-token", account.GetOpenAIBaseURL()+"/v1/messages")
			require.NoError(t, err)
			defer repeated.Body.Close()
			require.Equal(t, body, repeatedBody)
		})
	}
}
