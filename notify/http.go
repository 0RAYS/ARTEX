package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// httpClient 是所有渠道投递共用的客户端。
//
// 刻意**不**复用项目的全局出口代理（server 侧的 GlobalProxy）：那个代理是给渗透
// 目标流量用的，常是不稳定的隧道，而通知的可用性不该被目标网络的抖动绑架。
// IM 推送直连即可。超时设为 15 秒——比这更慢的对端实际上已经是故障状态。
//
// 拒绝跨主机重定向：本功能的投递地址都是「一个固定 endpoint」形态，正常不会
// 重定向到别的主机；而这几家的凭据（钉钉的 access_token、企微的 key、Telegram 的
// bot token）**就在 URL 里**，跟随跨主机跳转等于把凭据交给重定向目标。同主机
// 的跳转（如末尾补斜杠）仍允许。
var httpClient = &http.Client{
	Timeout: 15 * time.Second,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return errors.New("重定向次数过多")
		}
		if len(via) > 0 && req.URL.Host != via[0].URL.Host {
			return fmt.Errorf("拒绝跨主机重定向（%s → %s）", via[0].URL.Host, req.URL.Host)
		}
		return nil
	},
}

// respBodyLimit 限制读取响应体的大小。对端异常时可能吐回超大内容，而我们只需要
// 错误码和一小段错误描述用于展示在投递历史里。
const respBodyLimit = 8 << 10

// doJSON 发送一次请求并返回响应体（已限长）。
//
// payload 为 nil 时发送空 body（用于 GET 或平台不要求 body 的场景）。
// headers 里的键值原样附加，用于通用 Webhook 的自定义头。
//
// 错误分类是这个函数的核心职责：网络层失败与 5xx/408/429 归为「可重试」，
// 其余 4xx 归为「永久失败」——重试一个 403 只是把同一个错误刷 3 遍日志。
func doJSON(ctx context.Context, method, url string, headers map[string]string, payload any) ([]byte, error) {
	var body io.Reader
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			// 序列化失败是本地 bug（配置字段类型不对），重试也不会变好。
			return nil, Permanent(fmt.Errorf("构造请求体失败: %w", err))
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		// URL 非法——多半是用户把地址填错了，属于永久失败。
		// 这里同样不能透传 err：url.Parse 的错误文本里含完整地址。
		return nil, Permanent(fmt.Errorf("请求地址非法: %s", redactRequestTarget(url)))
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json; charset=utf-8")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		// 连接被拒、DNS 失败、超时——多为瞬时故障，交给退避重试。
		//
		// 错误文本必须脱敏后再往外传。原因：http.Client.Do 返回的是 *url.Error，
		// 它的 Error() 是 `Op "完整URL": 底层错误`，而本功能这几家的凭据**就在 URL 里**
		// （钉钉 access_token、企微 key、飞书 hook id、Telegram /bot<token>/）。
		// 不脱敏的话，凭据会顺着这条错误串流到四个地方：notification_deliveries
		// 的 last_error（明文落库）、投递历史接口的响应（**绕过渠道配置的掩码**）、
		// 服务端日志、以及测试发送接口回给前端的 502 文本。
		return nil, fmt.Errorf("请求失败: %s", redactTransportError(err))
	}
	defer resp.Body.Close()
	raw, readErr := io.ReadAll(io.LimitReader(resp.Body, respBodyLimit))
	if readErr != nil {
		return nil, fmt.Errorf("读取响应失败: %w", readErr)
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return raw, nil
	}
	// 429（限流）与 408（超时）值得重试；其余 4xx 是配置或权限问题，重试无意义。
	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusRequestTimeout {
		return nil, fmt.Errorf("对方限流或超时 (HTTP %d): %s", resp.StatusCode, snippet(raw))
	}
	if resp.StatusCode >= 500 {
		return nil, fmt.Errorf("对方服务异常 (HTTP %d): %s", resp.StatusCode, snippet(raw))
	}
	return nil, Permanent(fmt.Errorf("对方拒绝请求 (HTTP %d): %s", resp.StatusCode, snippet(raw)))
}

// snippet 把响应体压成一行短文本，用于错误信息。响应里可能带换行与大量空白，
// 直接塞进 last_error 会让投递历史页面排版崩掉。
func snippet(raw []byte) string {
	return OneLine(string(raw), 200)
}

// redactRequestTarget 把投递地址压成「scheme://host/…」，用于错误信息。
//
// 这是本包唯一的地址脱敏口径，刻意做得**足够粗暴**：除了 scheme 与 host，
// 其余一律丢弃。原因是没有一个「通用且安全」的方式判断 URL 的哪一段是凭据：
//
//	钉钉   凭据在 query      /robot/send?access_token=xxx
//	企微   凭据在 query      /cgi-bin/webhook/send?key=xxx
//	飞书   凭据在**路径末段** /open-apis/bot/v2/hook/<hook_id>
//	Telegram 凭据在**路径中段** /bot<token>/sendMessage
//
// 想「只保留有用部分」就得按渠道打补丁，而漏掉任何一家就是一次凭据泄露。
// 保留 host 已经够用于排查（DNS 解析不了、连不上、证书不对都能定位），
// 具体是哪个机器人由渠道配置里的掩码尾号提示去认。
//
// 解析失败时返回固定占位符——绝不把原始串回显出去。
func redactRequestTarget(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "(地址不可解析)"
	}
	return u.Scheme + "://" + u.Host + "/…"
}

// redactTransportError 从传输层错误里剥掉地址，只保留底层原因。
//
// *url.Error 的结构是 {Op, URL, Err}，Error() 会把 URL 一起打出来。
// 这里显式取 Err 字段，绕开它的 Error() ——比事后做字符串替换更可靠，
// 因为替换要正确应对 URL 编码/转义后的各种变体，容易漏。
func redactTransportError(err error) string {
	var uerr *url.Error
	if errors.As(err, &uerr) {
		host := ""
		if u, parseErr := url.Parse(uerr.URL); parseErr == nil {
			host = u.Host
		}
		if uerr.Err != nil {
			return fmt.Sprintf("%s %s: %s", uerr.Op, host, uerr.Err)
		}
		return fmt.Sprintf("%s %s: 未知错误", uerr.Op, host)
	}
	// 非 *url.Error（如重定向策略返回的错误）也可能带地址，统一走脱敏。
	return redactURLsInText(err.Error())
}

// redactURLsInText 把一段文本里出现的 http(s) 地址替换成脱敏形态。
//
// 用于兜底那些拿不到结构化字段的错误（重定向策略错误、第三方库的自定义错误）。
// 只识别 http/https 前缀，按空白与引号切分——地址不会包含这两类字符。
func redactURLsInText(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		rest := s[i:]
		if strings.HasPrefix(rest, "http://") || strings.HasPrefix(rest, "https://") {
			end := len(rest)
			if j := strings.IndexAny(rest, " \t\n\"'"); j >= 0 {
				end = j
			}
			b.WriteString(redactRequestTarget(rest[:end]))
			i += end
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}
