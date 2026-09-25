package service

import (
	"net/http"
	"strings"
	"time"

	"github.com/tidwall/gjson"
)

// Mirasim 中继在自身后端池没有某个模型的健康实例时，会返回 5xx +
// `no upstream available for model "<model>"`（官方 App 内部错误码
// model_capacity_exhausted）。这是中继侧的模型级容量抖动，不是模型不存在，
// 也不是账号凭据或账号健康问题：同一账号、同一模型在几十秒内可以交替成功与失败。
//
// 网关原有的判定链对这种形状全部漏判：
//   - isUpstreamModelNotFoundError 只认 404，拿不到模型级冷却；
//   - isOpenAICapacityShedMessage 只认 "server(s) (are|is) overloaded" 文案；
//   - isOpenAITransientProcessingError 对 503 直接返回 false；
//   - HandleUpstreamError 的 default 分支对 >=500 只打日志。
//
// 结果是每一次抖动都原样变成客户端可见的 502，没有任何退避，客户端重试又立刻
// 撞回同一个抖动窗口，把一次真实故障放大成一串错误。本文件补上请求内的同账号
// 短退避重试，让抖动在网关内部被吸收掉。
//
// 这里刻意不做官方 App 那套「连续失败后对 (账号,模型) 停用 60s」：App 面对的是
// 单用户单账号，停用只影响它自己；网关侧一旦号池里只剩一个可用账号（这正是本次
// 线上的实际形态），停用会把唯一的账号摘掉，那 60s 内每个请求都是无账号可调度的
// 硬 503，连撞上抖动间隙的机会都没有——比不停用更差。停用只有在确实存在备用账号
// 时才是正收益，若将来号池常态多账号，可以再按「该模型仍有其它可调度账号」为前提
// 加回来。

const (
	// mirasimRelayCapacityErrorCode 是官方 App 对该错误使用的内部错误码。
	mirasimRelayCapacityErrorCode = "model_capacity_exhausted"
	// mirasimRelayCapacityRetryMax 单次请求内的同账号重试上限，对齐官方 App 的
	// 网络层重试次数（3 次）。
	mirasimRelayCapacityRetryMax = 3
	// mirasimRelayCapacityRetryWindow 同账号重试的总时间预算。退避序列为
	// 0.5s / 1s / 2s（由 RequestScopedTransient 的指数退避产生），8s 足够跑满 3 次，
	// 同时保证抖动持续时不会把单个请求拖成分钟级等待。
	mirasimRelayCapacityRetryWindow = 8 * time.Second
	// mirasimRelayCapacityClientMessage 重试与换号都耗尽后返回给客户端的文案。
	mirasimRelayCapacityClientMessage = "Mirasim relay has no upstream capacity for this model right now, please retry later"
)

// mirasimRelayCapacityMessage 判断一段文本是否为中继的模型容量降载文案。
// text 为待判定文本；返回是否命中。
func mirasimRelayCapacityMessage(text string) bool {
	lower := strings.ToLower(strings.TrimSpace(text))
	if lower == "" {
		return false
	}
	return strings.Contains(lower, "no upstream available for model") ||
		strings.Contains(lower, "no upstream available")
}

// isMirasimRelayModelCapacityExhausted 判断上游响应是否为 Mirasim 中继的模型级
// 容量降载。
//
// account 为本次使用的账号（非 Mirasim 一律不命中）；statusCode 为上游 HTTP
// 状态码；upstreamMsg 为已提取并脱敏的上游错误消息；responseBody 为上游错误体。
// 返回是否命中该错误形状。
//
// 判定与官方 App 的 Zbn 对齐：只在 5xx 上成立（4xx 的同名文案属于请求问题，
// 不应进入重试），错误码优先，其次才看消息文案；JSON 错误体只信任显式的错误
// 字段，整体扫描仅用于非 JSON 的纯文本响应，避免请求内容回显造成误判。
func isMirasimRelayModelCapacityExhausted(account *Account, statusCode int, upstreamMsg string, responseBody []byte) bool {
	if account == nil || !account.IsMirasim() {
		return false
	}
	if statusCode < http.StatusInternalServerError {
		return false
	}
	// 步骤 1：优先按结构化错误码判定
	for _, path := range []string{"error.code", "error.type", "response.error.code", "code"} {
		if strings.EqualFold(strings.TrimSpace(gjson.GetBytes(responseBody, path).String()), mirasimRelayCapacityErrorCode) {
			return true
		}
	}
	// 步骤 2：回落到错误消息文案（中继当前只给文案，不给错误码）
	if mirasimRelayCapacityMessage(upstreamMsg) {
		return true
	}
	if mirasimRelayCapacityMessage(extractUpstreamErrorMessage(responseBody)) {
		return true
	}
	// 步骤 3：非 JSON 响应体才整体扫描
	return !gjson.ValidBytes(responseBody) && mirasimRelayCapacityMessage(string(responseBody))
}

// applyMirasimRelayCapacityFailover 把中继模型容量降载的重试策略叠加到 failover
// 错误上。
//
// failoverErr 为已构造好的 failover 错误（原地修改）；account 为本次账号；
// statusCode / upstreamMsg / responseBody 为上游响应；shouldDisable 表示账号级
// 处置是否已决定停调该账号。无返回值。
//
// 与既有的 OpenAI 容量降载处理同构：标记 RequestScopedTransient，使同账号重试
// 走指数退避且不会据此临时封禁账号——故障因素在下一个账号上完全相同，封禁只会
// 白白摘掉健康账号。重试开关不经过 IsPoolMode 门禁：中继容量抖动与账号是否属于
// 号池无关，非池模式账号同样需要这道刹车。
//
// shouldDisable 为 true 时直接放行：那代表管理员配置的自定义错误码或临时不可调度
// 规则已经命中，显式配置优先于这里的默认策略。
func applyMirasimRelayCapacityFailover(
	failoverErr *UpstreamFailoverError,
	account *Account,
	statusCode int,
	upstreamMsg string,
	responseBody []byte,
	shouldDisable bool,
) {
	if failoverErr == nil || shouldDisable {
		return
	}
	if !isMirasimRelayModelCapacityExhausted(account, statusCode, upstreamMsg, responseBody) {
		return
	}
	failoverErr.RetryableOnSameAccount = true
	failoverErr.RequestScopedTransient = true
	failoverErr.SameAccountRetryMax = mirasimRelayCapacityRetryMax
	failoverErr.SameAccountRetryDeadline = time.Now().Add(mirasimRelayCapacityRetryWindow)
	// 重试与换号都耗尽后，按可重试的 503 回给客户端（而不是笼统的 502），
	// 让 Claude Code 之类的客户端按服务不可用而非网关故障退避。
	failoverErr.ClientStatusCode = http.StatusServiceUnavailable
	failoverErr.ClientMessage = mirasimRelayCapacityClientMessage
}
