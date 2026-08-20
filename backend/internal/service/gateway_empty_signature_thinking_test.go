package service

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestStripEmptySignatureThinkingBlocks 验证空 signature 块会被安全剥离，且不会破坏其他历史内容。
// 参数 t 为 Go 测试上下文；返回值由测试框架根据断言结果决定。
func TestStripEmptySignatureThinkingBlocks(t *testing.T) {
	t.Run("删除空签名并保留同条消息的文本和工具块", func(t *testing.T) {
		input := []byte(`{"messages":[{"role":"user","content":[{"type":"text","text":"第一轮"}]},{"role":"assistant","content":[{"type":"thinking","thinking":"内部推理","signature":""},{"type":"text","text":"第一轮回答"},{"type":"tool_use","id":"tool_1","name":"lookup","input":{}}]},{"role":"user","content":[{"type":"text","text":"第二轮"}]}]}`)

		output := StripEmptySignatureThinkingBlocks(input)
		var request map[string]any
		require.NoError(t, json.Unmarshal(output, &request))

		messages := request["messages"].([]any)
		assistantContent := messages[1].(map[string]any)["content"].([]any)
		require.Len(t, assistantContent, 2)
		require.Equal(t, "text", assistantContent[0].(map[string]any)["type"])
		require.Equal(t, "第一轮回答", assistantContent[0].(map[string]any)["text"])
		require.Equal(t, "tool_use", assistantContent[1].(map[string]any)["type"])
	})

	t.Run("保留有效签名和用户消息中的内容", func(t *testing.T) {
		input := []byte(`{"messages":[{"role":"user","content":[{"type":"thinking","thinking":"用户内容","signature":""}]},{"role":"assistant","content":[{"type":"thinking","thinking":"内部推理","signature":"sig_valid"},{"type":"text","text":"回答"}]}]}`)

		output := StripEmptySignatureThinkingBlocks(input)
		require.True(t, bytes.Equal(input, output))
	})

	t.Run("不会制造空 assistant 消息", func(t *testing.T) {
		input := []byte(`{"messages":[{"role":"assistant","content":[{"type":"thinking","thinking":"内部推理","signature":""}]}]}`)

		output := StripEmptySignatureThinkingBlocks(input)
		require.True(t, bytes.Equal(input, output))
	})
}
