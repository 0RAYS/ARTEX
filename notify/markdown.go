package notify

import (
	"fmt"
	"strings"
)

// 本文件是「Markdown 系」渠道（钉钉、企业微信）共用的消息渲染。
// 飞书用卡片 JSON、Telegram 用 HTML、邮件用 HTML，各自在适配器里渲染。

// maxAssetsShown 是消息里最多列出几个资产。一个漏洞可能锚定几十个资产，
// 全列会挤爆消息且没有信息价值——第 4 个之后的域名没人会在 IM 里看。
const maxAssetsShown = 3

// maxSummaryRunes 是摘要被压缩到多少字符。IM 消息是「提示去看详情」，
// 不是报告本体，完整内容在平台里。
const maxSummaryRunes = 120

// markdownTitle 返回消息标题（IM 平台的标题栏/卡片标题）。
func markdownTitle(m Message) string {
	if m.Batch {
		return fmt.Sprintf("漏洞汇总 · 共 %d 条", len(m.Items))
	}
	if len(m.Items) == 0 {
		return "漏洞通知"
	}
	it := m.Items[0]
	return fmt.Sprintf("[%s] %s", SeverityLabel(it.Severity), it.Title())
}

// markdownBody 渲染消息正文。maxBytes<=0 表示不截断；调用方按平台限制传入
// （企微 4096 字节是最紧的那个）。截断发生在整篇渲染之后，所以不会切坏
// markdown 语法之外的字符——但我们仍按字符边界切，见 TruncateBytes。
func markdownBody(m Message, maxBytes int) string {
	var b strings.Builder
	if m.Batch {
		b.WriteString(markdownBatchIntro(m))
		for i, it := range m.Items {
			writeItem(&b, it, fmt.Sprintf("%d. ", i+1), false)
		}
		if m.HomeURL != "" {
			fmt.Fprintf(&b, "\n[在平台中查看全部](%s)\n", m.HomeURL)
		}
		return TruncateBytes(b.String(), maxBytes)
	}
	if len(m.Items) == 0 {
		return ""
	}
	writeItem(&b, m.Items[0], "", true)
	return TruncateBytes(b.String(), maxBytes)
}

// markdownBatchIntro 渲染汇总消息的开头：时间窗与条数。有了这两项，收到汇总的
// 人不用点进平台就能判断这批需不需要立刻处理。
func markdownBatchIntro(m Message) string {
	var b strings.Builder
	if m.WindowMinutes > 0 {
		fmt.Fprintf(&b, "**近 %d 分钟新增 %d 个漏洞**", m.WindowMinutes, len(m.Items))
	} else {
		fmt.Fprintf(&b, "**新增 %d 个漏洞**", len(m.Items))
	}
	// 按级别给出分布，让读者一眼看到有没有严重项。
	counts := map[string]int{}
	for _, it := range m.Items {
		counts[it.Severity]++
	}
	// 固定按级别从高到低列出，未知级别不参与（避免出现「 2」这样的空标签）。
	var parts []string
	for _, sev := range []string{"critical", "high", "medium", "low"} {
		if n := counts[sev]; n > 0 {
			parts = append(parts, fmt.Sprintf("%s %d", SeverityLabel(sev), n))
		}
	}
	if len(parts) > 0 {
		b.WriteString("\n" + strings.Join(parts, " · "))
	}
	b.WriteString("\n\n")
	return b.String()
}

// writeItem 渲染单个漏洞条目。
//
// prefix 用于汇总列表的序号；single=true 时渲染完整版（含摘要与回链），
// 汇总列表里只渲染一行摘要——否则 50 条汇总会变成一篇长文档。
func writeItem(b *strings.Builder, it Item, prefix string, single bool) {
	line := fmt.Sprintf("%s**%s · %s**", prefix, SeverityLabel(it.Severity), it.Title())
	if !single {
		// 汇总模式：单行呈现，资产与摘要压缩后跟在后面。
		var extras []string
		if a := assetLine(it.Assets, maxAssetsShown); a != "" {
			extras = append(extras, a)
		}
		if it.Summary != "" {
			extras = append(extras, OneLine(it.Summary, 60))
		}
		if len(extras) > 0 {
			line += " — " + strings.Join(extras, " · ")
		}
		b.WriteString(line + "\n")
		return
	}
	b.WriteString(line + "\n")
	if it.IsStatusChange() {
		fmt.Fprintf(b, "**状态变更**：%s → %s\n", StatusLabel(it.FromStatus), StatusLabel(it.ToStatus))
	}
	if it.VulnClass != "" && it.VulnClass != it.Title() {
		fmt.Fprintf(b, "**类型**：%s\n", it.VulnClass)
	}
	if a := assetLine(it.Assets, maxAssetsShown); a != "" {
		fmt.Fprintf(b, "**资产**：%s\n", a)
	}
	if s := OneLine(it.Summary, maxSummaryRunes); s != "" {
		fmt.Fprintf(b, "**摘要**：%s\n", s)
	}
	if it.DetailURL != "" {
		fmt.Fprintf(b, "[查看详情](%s)\n", it.DetailURL)
	}
}
