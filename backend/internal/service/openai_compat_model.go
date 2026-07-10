package service

import (
	"strings"

	"github.com/Wei-Shaw/sub2api/internal/pkg/apicompat"
)

// NormalizeOpenAICompatRequestedModel 去除 OpenAI 兼容模型名中的 reasoning 后缀。
// 参数：model 为客户端请求模型名。返回值：规范化后的基础模型名；无法识别时返回原模型名。
func NormalizeOpenAICompatRequestedModel(model string) string {
	trimmed := strings.TrimSpace(model)
	if trimmed == "" {
		return ""
	}

	normalized, _, ok := splitOpenAICompatReasoningModel(trimmed)
	if !ok || normalized == "" {
		return trimmed
	}
	return normalized
}

// applyOpenAICompatModelNormalization 将 Anthropic 兼容请求中的 OpenAI reasoning 后缀转换为 output_config.effort。
// 参数：req 为待改写的 Anthropic 兼容请求。返回值：无，函数会原地修改 req。
func applyOpenAICompatModelNormalization(req *apicompat.AnthropicRequest) {
	if req == nil {
		return
	}

	originalModel := strings.TrimSpace(req.Model)
	if originalModel == "" {
		return
	}

	normalizedModel, derivedEffort, hasReasoningSuffix := splitOpenAICompatReasoningModel(originalModel)
	if hasReasoningSuffix && normalizedModel != "" {
		req.Model = normalizedModel
	}

	if req.OutputConfig != nil && strings.TrimSpace(req.OutputConfig.Effort) != "" {
		return
	}

	claudeEffort := openAIReasoningEffortToClaudeOutputEffort(derivedEffort)
	if claudeEffort == "" {
		return
	}

	if req.OutputConfig == nil {
		req.OutputConfig = &apicompat.AnthropicOutputConfig{}
	}
	req.OutputConfig.Effort = claudeEffort
}

// splitOpenAICompatReasoningModel 拆分 OpenAI 兼容模型名中的 reasoning 后缀。
// 参数：model 为客户端请求模型名。返回值：基础模型名、推导出的思考深度，以及是否识别到后缀。
func splitOpenAICompatReasoningModel(model string) (normalizedModel string, reasoningEffort string, ok bool) {
	trimmed := strings.TrimSpace(model)
	if trimmed == "" {
		return "", "", false
	}

	modelID := trimmed
	if strings.Contains(modelID, "/") {
		parts := strings.Split(modelID, "/")
		modelID = parts[len(parts)-1]
	}
	modelID = strings.TrimSpace(modelID)
	if !strings.HasPrefix(strings.ToLower(modelID), "gpt-") {
		return trimmed, "", false
	}

	parts := strings.FieldsFunc(strings.ToLower(modelID), func(r rune) bool {
		switch r {
		case '-', '_', ' ':
			return true
		default:
			return false
		}
	})
	if len(parts) == 0 {
		return trimmed, "", false
	}

	last := strings.NewReplacer("-", "", "_", "", " ", "").Replace(parts[len(parts)-1])
	switch last {
	case "none", "minimal":
	case "low", "medium", "high":
		reasoningEffort = last
	case "xhigh", "extrahigh", "max":
		reasoningEffort = "xhigh"
	default:
		return trimmed, "", false
	}

	return normalizeCodexModel(modelID), reasoningEffort, true
}

// openAIReasoningEffortToClaudeOutputEffort 将 OpenAI reasoning effort 映射为 Claude output_config.effort。
// 参数：effort 为 OpenAI 规范化思考深度。返回值：Claude 兼容 effort；无法映射时返回空字符串。
func openAIReasoningEffortToClaudeOutputEffort(effort string) string {
	switch strings.TrimSpace(effort) {
	case "low", "medium", "high":
		return effort
	case "xhigh":
		return "max"
	default:
		return ""
	}
}
