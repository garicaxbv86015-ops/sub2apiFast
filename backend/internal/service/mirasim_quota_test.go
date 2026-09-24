//go:build unit

package service

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestMirasimQuotaScopes 验证额度继承、模型别名及重置后恢复，不影响其他模型家族。
func TestMirasimQuotaScopes(t *testing.T) {
	for _, window := range []string{"5h", "7d", "7d_claude", "7d_fable"} {
		for _, model := range []string{"gpt-6-astra", "claude-sonnet-5", "claude-fable-5-1", "fable-alias"} {
			t.Run(window+"/"+model, func(t *testing.T) {
				reset := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
				account := &Account{ID: 1103, Platform: PlatformMirasim, Type: AccountTypeOAuth, Status: StatusActive, Schedulable: true,
					Credentials: map[string]any{"model_mapping": map[string]any{"fable-alias": "claude-fable-5-1"}},
					Extra: map[string]any{"mirasim_"+window+"_used_percent": 100.0, "mirasim_"+window+"_reset_at": reset}}
				blocked := window == "5h" || window == "7d" || (window == "7d_claude" && model != "gpt-6-astra") || (window == "7d_fable" && (model == "claude-fable-5-1" || model == "fable-alias"))
				require.Equal(t, !blocked, account.IsSchedulableForModel(model))
				require.Equal(t, blocked, account.GetModelRateLimitRemainingTime(model) > 0)
				require.True(t, account.IsSchedulable(), "模型窗口不能关闭账号调度开关")
				account.Extra["mirasim_"+window+"_reset_at"] = time.Now().Add(-time.Second).Format(time.RFC3339)
				require.True(t, account.IsSchedulableForModel(model), "重置后应恢复")
			})
		}
	}
}

// TestMirasimQuotaReactive429 验证快照尚未满但上游明确耗尽时，只冷却对应额度范围。
func TestMirasimQuotaReactive429(t *testing.T) {
	for _, window := range []string{"5h", "7d", "7d_claude", "7d_fable"} {
		t.Run(window, func(t *testing.T) {
			reset := time.Now().Add(time.Hour).Truncate(time.Second)
			account := &Account{ID: 1103, Platform: PlatformMirasim, Type: AccountTypeOAuth, Status: StatusActive, Schedulable: true,
				Extra: map[string]any{"mirasim_"+window+"_used_percent": 59.7, "mirasim_"+window+"_reset_at": reset.Format(time.RFC3339)}}
			repo := &anthropicWindowLimitRepo{}
			svc := NewRateLimitService(repo, nil, nil, nil, nil)
			body := []byte(fmt.Sprintf(`{"error":{"code":"credit_exhausted_%s","type":"rate_limit_error","message":"quota exhausted"}}`, window))
			svc.HandleUpstreamError(context.Background(), account, http.StatusTooManyRequests, http.Header{}, body, "claude-fable-5-1")
			require.Equal(t, 1, repo.modelRateLimitCalls)
			require.Equal(t, "mirasim:"+window, repo.lastModelRateLimitScope)
			require.True(t, reset.Equal(repo.lastModelRateLimitReset))
			require.Zero(t, repo.rateLimitCalls, "不能误停整个账号")
			require.Zero(t, repo.tempUnschedCalls)
			require.False(t, account.IsSchedulableForModel("claude-fable-5-1"))
			require.Equal(t, window != "5h" && window != "7d", account.IsSchedulableForModel("gpt-6-astra"))
			require.Equal(t, window == "7d_fable", account.IsSchedulableForModel("claude-sonnet-5"))
		})
	}
}

// TestMirasimQuotaAccountSwitch 验证优先账号额度耗尽时切换到 1104，GPT 仍选择 1103。
func TestMirasimQuotaAccountSwitch(t *testing.T) {
	for _, window := range []string{"7d_fable", "7d_claude"} {
		t.Run(window, func(t *testing.T) {
			first := Account{ID: 1103, Platform: PlatformMirasim, Type: AccountTypeOAuth, Status: StatusActive, Schedulable: true, Concurrency: 1,
				Extra: map[string]any{"mirasim_"+window+"_used_percent": 100.0, "mirasim_"+window+"_reset_at": time.Now().Add(time.Hour).Format(time.RFC3339)}}
			second := Account{ID: 1104, Platform: PlatformMirasim, Type: AccountTypeOAuth, Status: StatusActive, Schedulable: true, Concurrency: 1, Priority: 1}
			svc := &OpenAIGatewayService{accountRepo: stubOpenAIAccountRepo{accounts: []Account{first, second}}}
			for _, model := range []string{"claude-fable-5-1", "gpt-6-astra"} {
				selected, err := svc.selectAccountForModelWithExclusions(context.Background(), nil, PlatformMirasim, "", model, nil, false, 0, "", false)
				require.NoError(t, err)
				want := int64(1104)
				if model == "gpt-6-astra" {
					want = 1103
				}
				require.Equal(t, want, selected.ID)
				// 粘性会话也必须重新检查额度，不能继续命中已耗尽账号。
				svc.cache = &stubGatewayCache{sessionBindings: map[string]int64{"openai:quota-session": 1103}}
				selected, err = svc.selectAccountForModelWithExclusions(context.Background(), nil, PlatformMirasim, "quota-session", model, nil, false, 1103, "", false)
				require.NoError(t, err)
				require.Equal(t, want, selected.ID)
				svc.concurrencyService = NewConcurrencyService(stubConcurrencyCache{})
				selection, err := svc.selectAccountWithLoadAwareness(context.Background(), nil, PlatformMirasim, "", model, nil, false, "", false)
				require.NoError(t, err)
				require.Equal(t, want, selection.Account.ID)
				if selection.ReleaseFunc != nil {
					selection.ReleaseFunc()
				}
			}
		})
	}
}

// TestMirasimQuotaOverlappingWindows 验证子窗口重置后仍受未重置的 Claude 总窗口限制。
func TestMirasimQuotaOverlappingWindows(t *testing.T) {
	account := &Account{Platform: PlatformMirasim, Status: StatusActive, Schedulable: true, Extra: map[string]any{
		"mirasim_7d_fable_used_percent": 100.0,
		"mirasim_7d_fable_reset_at": time.Now().Add(-time.Minute).Format(time.RFC3339),
		"mirasim_7d_claude_used_percent": 100.0,
		"mirasim_7d_claude_reset_at": time.Now().Add(time.Hour).Format(time.RFC3339),
	}}
	require.False(t, account.IsSchedulableForModel("claude-fable-5-1"))
	require.True(t, account.IsSchedulableForModel("gpt-6-astra"))
	account.Extra["mirasim_7d_claude_used_percent"] = 99.9
	require.True(t, account.IsSchedulableForModel("claude-fable-5-1"))
}

// TestMirasimQuotaReactiveResetEvidence 验证上游给出的重置时间及缺失时的明确处理。
func TestMirasimQuotaReactiveResetEvidence(t *testing.T) {
	for _, retryAfter := range []string{"60", ""} {
		t.Run(retryAfter, func(t *testing.T) {
			account := &Account{ID: 1103, Platform: PlatformMirasim, Type: AccountTypeOAuth, Status: StatusActive, Schedulable: true}
			repo := &anthropicWindowLimitRepo{}
			svc := NewRateLimitService(repo, nil, nil, nil, nil)
			header := http.Header{"Retry-After": []string{retryAfter}}
			require.True(t, svc.persistMirasimExhaustedWindow(context.Background(), account, header, []byte(`{"error":{"code":"credit_exhausted_7d_fable"}}`)))
			require.Equal(t, retryAfter != "", repo.modelRateLimitCalls == 1)
			require.Zero(t, repo.rateLimitCalls)
			require.True(t, account.IsSchedulableForModel("gpt-6-astra"))
			require.False(t, svc.persistMirasimExhaustedWindow(context.Background(), account, header, []byte(`{"error":{"code":"7d_fable"}}`)))
		})
	}
}
