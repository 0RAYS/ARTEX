package notify

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"
)

// feishuChannel 实现飞书（含 Lark）自定义机器人，走交互式卡片。
//
// 平台特性：
//   - 加签算法与钉钉**不同**，且极易写错，见 feishuSign 注释。
//   - 与钉钉一样把业务错误塞在 HTTP 200 的 body 里（code != 0）。
//   - 卡片 header 支持颜色模板，用级别映射配色，让人在消息列表里一眼看出严重程度。
type feishuChannel struct{}

func (feishuChannel) Kind() string { return KindFeishu }

// 飞书自定义机器人约 5 次/秒，折合 100 次/分钟。
func (feishuChannel) DefaultRatePerMin() int { return 100 }

// Webhook 地址末段即机器人唯一标识，属凭据。
func (feishuChannel) SecretKeys() []string { return []string{"webhook", "secret"} }

func (feishuChannel) Validate(cfg map[string]any) error {
	hook := cfgString(cfg, "webhook")
	if hook == "" {
		return errors.New("缺少 Webhook 地址")
	}
	if err := validateHTTPURL(hook); err != nil {
		return fmt.Errorf("Webhook 地址无效: %w", err)
	}
	return nil
}

func (c feishuChannel) Send(ctx context.Context, cfg map[string]any, m Message) error {
	if err := c.Validate(cfg); err != nil {
		return Permanent(err)
	}
	payload := map[string]any{
		"msg_type": "interactive",
		"card":     feishuCard(m),
	}
	// 加签参数与消息同层，且只在配置了 secret 时出现。
	if secret := cfgString(cfg, "secret"); secret != "" {
		ts := strconv.FormatInt(time.Now().Unix(), 10)
		payload["timestamp"] = ts
		payload["sign"] = feishuSign(ts, secret)
	}
	raw, err := doJSON(ctx, "POST", cfgString(cfg, "webhook"), nil, payload)
	if err != nil {
		return err
	}
	var res struct {
		Code int    `json:"code"`
		Msg  string `json:"msg"`
		// 部分版本的飞书 hook 用这套字段名，一并兼容。
		StatusCode    int    `json:"StatusCode"`
		StatusMessage string `json:"StatusMessage"`
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		return fmt.Errorf("解析飞书响应失败: %w (%s)", err, snippet(raw))
	}
	if res.Code != 0 {
		return Permanent(fmt.Errorf("飞书返回错误 %d: %s", res.Code, res.Msg))
	}
	if res.StatusCode != 0 {
		return Permanent(fmt.Errorf("飞书返回错误 %d: %s", res.StatusCode, res.StatusMessage))
	}
	return nil
}

// feishuSign 按飞书官方规则计算签名。
//
// 这里特别容易踩坑：官方样例是
//
//	hmac.new(string_to_sign.encode(), digestmod=sha256)
//
// 也就是 **key = timestamp + "\n" + secret，message 为空**，而不是直觉上的
// 「key=secret, message=stringToSign」——那正是钉钉的算法。两边算法刚好反过来，
// 照着另一家的实现写必然签名校验失败（报 19021）。
func feishuSign(timestamp, secret string) string {
	stringToSign := timestamp + "\n" + secret
	mac := hmac.New(sha256.New, []byte(stringToSign))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// feishuSeverityTemplate 把漏洞级别映射到卡片 header 配色模板。
// 未知级别用 grey——不用 blue，免得和 low 混淆。
func feishuSeverityTemplate(severity string) string {
	switch severity {
	case "critical":
		return "red"
	case "high":
		return "orange"
	case "medium":
		return "yellow"
	case "low":
		return "blue"
	default:
		return "grey"
	}
}

// feishuCard 构造交互式卡片。
func feishuCard(m Message) map[string]any {
	elements := []any{}
	if m.Batch {
		elements = append(elements, feishuMarkdownDiv(markdownBatchIntro(m)))
		for i, it := range m.Items {
			elements = append(elements, feishuMarkdownDiv(feishuBatchLine(it, i+1)))
		}
		if m.HomeURL != "" {
			elements = append(elements, feishuButton("在平台中查看全部", m.HomeURL))
		}
	} else if len(m.Items) > 0 {
		it := m.Items[0]
		elements = append(elements, feishuMarkdownDiv(feishuItemLines(it)))
		if it.DetailURL != "" {
			elements = append(elements, feishuButton("查看详情", it.DetailURL))
		}
	}

	card := map[string]any{
		"config":   map[string]any{"wide_screen_mode": true},
		"header":   map[string]any{"title": map[string]any{"tag": "plain_text", "content": markdownTitle(m)}},
		"elements": elements,
	}
	if len(m.Items) > 0 {
		card["header"].(map[string]any)["template"] = feishuSeverityTemplate(m.Items[0].Severity)
	}
	return card
}

func feishuMarkdownDiv(content string) map[string]any {
	return map[string]any{"tag": "div", "text": map[string]any{"tag": "lark_md", "content": content}}
}

func feishuButton(label, url string) map[string]any {
	return map[string]any{
		"tag": "action",
		"actions": []any{map[string]any{
			"tag":  "button",
			"text": map[string]any{"tag": "lark_md", "content": label},
			"url":  url,
			"type": "primary",
		}},
	}
}

// feishuItemLines 渲染单个漏洞的 lark_md 正文。
func feishuItemLines(it Item) string {
	out := fmt.Sprintf("**%s · %s**", SeverityLabel(it.Severity), it.Title())
	if it.IsStatusChange() {
		out += fmt.Sprintf("\n**状态变更**：%s → %s", StatusLabel(it.FromStatus), StatusLabel(it.ToStatus))
	}
	if it.VulnClass != "" && it.VulnClass != it.Title() {
		out += fmt.Sprintf("\n**类型**：%s", it.VulnClass)
	}
	if a := assetLine(it.Assets, maxAssetsShown); a != "" {
		out += fmt.Sprintf("\n**资产**：%s", a)
	}
	if s := OneLine(it.Summary, maxSummaryRunes); s != "" {
		out += fmt.Sprintf("\n**摘要**：%s", s)
	}
	return out
}

// feishuBatchLine 渲染汇总卡片里的一条。
func feishuBatchLine(it Item, index int) string {
	line := fmt.Sprintf("**%d. %s · %s**", index, SeverityLabel(it.Severity), it.Title())
	if a := assetLine(it.Assets, maxAssetsShown); a != "" {
		line += " — " + a
	}
	return line
}
