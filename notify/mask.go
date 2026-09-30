package notify

import "strings"

// MaskedPrefix 是掩码值的标记前缀。API 回显凭据时用带此前缀的值替换真实内容，
// 更新接口收到带此前缀的值即理解为「保持库中原值不变」。
//
// 用前缀而不是空串或某个固定常量，是为了能顺带带上一点可辨识信息
// （见 MaskedValue），让用户区分得出「这是哪个机器人」而不必重新粘贴密钥。
const MaskedPrefix = "__masked__"

// MaskedValue 生成一个掩码值：
//
//	"__masked__"              原值太短，不给任何提示
//	"__masked__:…ab12cd"      带上原值末 6 位作为辨识提示
//
// 只暴露末 6 位是刻意选择的：Webhook 地址的辨识信息在末段（如企业微信的 key、
// 飞书的机器人 id），而前缀部分各机器人相同、没有辨识价值。末 6 位不足以
// 还原凭据，但足以让配置者认出「是我那个群」。
func MaskedValue(secret string) string {
	if len(secret) <= 6 {
		return MaskedPrefix
	}
	return MaskedPrefix + ":…" + secret[len(secret)-6:]
}

// IsMasked 报告某个值是否为掩码值（即接口回显后未被修改）。
func IsMasked(v string) bool { return strings.HasPrefix(v, MaskedPrefix) }

// MaskConfig 返回配置的副本，把该渠道的凭据字段替换成掩码值。
//
// 未知渠道类型返回空 map 而不是原配置——宁可让 UI 显示「配置不可用」，
// 也不要在渠道类型无法识别时把可能含凭据的原始内容整个吐回去。
// 非凭据字段原样保留，UI 才能正常展示。
func MaskConfig(kind string, cfg map[string]any) map[string]any {
	channel, ok := Get(kind)
	if !ok {
		return map[string]any{}
	}
	secrets := map[string]bool{}
	for _, k := range channel.SecretKeys() {
		secrets[k] = true
	}
	out := make(map[string]any, len(cfg))
	for k, v := range cfg {
		if !secrets[k] {
			out[k] = v
			continue
		}
		// headers 这类嵌套结构整体按一个凭据处理：逐个子键判断需要每个渠道
		// 再声明一套「哪些子键是凭据」的规则，复杂度远超收益。
		if s, ok := v.(string); ok {
			out[k] = MaskedValue(s)
			continue
		}
		out[k] = MaskedPrefix
	}
	return out
}

// MergeConfig 把 incoming 合并到 stored 之上，用于更新渠道配置。
//
// 规则：
//   - incoming 里值为掩码的键 → 保留 stored 的原值（用户没改这个字段）
//   - incoming 里值为空串的键 → 视为显式清空，删除该键
//   - 其余键 → 用 incoming 的值覆盖
//   - stored 里有而 incoming 里没有的键 → 保留（局部更新语义）
//
// 空串是否算「清空」需要明确：前端表单把未填的字段提交为空串，
// 若把它当成有效值写入，会把「留空以保留原值」的字段真的清掉。
// 这里选择显式清空，因为要清除一个设错的字段时，用户没有别的表达方式
// （拖走字段可区分「未提供」与「提供空值」，但 UI 用不到这个区别）。
func MergeConfig(stored, incoming map[string]any) map[string]any {
	out := make(map[string]any, len(stored)+len(incoming))
	for k, v := range stored {
		out[k] = v
	}
	for k, v := range incoming {
		if s, ok := v.(string); ok {
			if IsMasked(s) {
				continue // 掩码值 = 未修改，保留 stored
			}
			if strings.TrimSpace(s) == "" {
				delete(out, k)
				continue
			}
			out[k] = s
			continue
		}
		out[k] = v
	}
	return out
}
