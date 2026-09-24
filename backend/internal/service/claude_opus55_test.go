package service

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/stretchr/testify/require"
)

// TestClaudeOpus55Pricing 验证新价卡、未更新的远端价卡及内置价卡均不会误收 Opus 5 的价格。
func TestClaudeOpus55Pricing(t *testing.T) {
	body, err := os.ReadFile("../../resources/model-pricing/model_prices_and_context_window.json")
	require.NoError(t, err)
	var catalog map[string]*LiteLLMModelPricing
	require.NoError(t, json.Unmarshal(body, &catalog))
	require.Contains(t, catalog, "claude-opus-5-5")
	for name, prices := range map[string]*PricingService{
		"最新价卡": {pricingData: catalog},
		"旧价卡": {pricingData: map[string]*LiteLLMModelPricing{"claude-opus-5": {InputCostPerToken: 5e-6, OutputCostPerToken: 25e-6}}},
		"内置价卡": nil,
	} {
		t.Run(name, func(t *testing.T) {
			svc := NewBillingService(&config.Config{}, prices)
			for _, model := range []string{"claude-opus-5-5", "claude-opus-5-5-20260922"} {
				pricing, err := svc.GetModelPricing(model)
				require.NoError(t, err)
				require.InDelta(t, 4e-6, pricing.InputPricePerToken, 1e-12)
				require.InDelta(t, 20e-6, pricing.OutputPricePerToken, 1e-12)
				require.InDelta(t, 0.2e-6, pricing.CacheReadPricePerToken, 1e-12)
				require.InDelta(t, 5e-6, pricing.CacheCreation5mPrice, 1e-12)
				require.InDelta(t, 8e-6, pricing.CacheCreation1hPrice, 1e-12)
			}
			old, err := svc.GetModelPricing("claude-opus-5")
			require.NoError(t, err)
			require.InDelta(t, 5e-6, old.InputPricePerToken, 1e-12)
		})
	}
	// 仅有新型号价卡时，旧型号也不能反向误匹配新价格。
	newOnly := &PricingService{pricingData: map[string]*LiteLLMModelPricing{"claude-opus-5-5": catalog["claude-opus-5-5"]}}
	require.Nil(t, newOnly.GetModelPricing("claude-opus-5"))
}
