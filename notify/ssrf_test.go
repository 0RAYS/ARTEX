package notify

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
)

// 本文件覆盖两条相关的加固：
//   ① 投递地址不得把服务端当跳板打内网 / 云元数据（SSRF）
//   ② 地址校验的错误信息不得带出地址里的凭据
//
// 关于测试环境：本包大量用例用 127.0.0.1 上的 httptest 假接收端，守卫默认会拦下
// 它们。所以 TestMain 里统一打开 AllowLocalTargetsEnv，而下面每个 SSRF 用例都
// 显式把它清掉，以断言**默认拒绝**的行为。

func TestMain(m *testing.M) {
	// 让常规用例能连本地的假接收端；SSRF 用例会自己临时清空。
	_ = os.Setenv(AllowLocalTargetsEnv, "1")
	os.Exit(m.Run())
}

// TestDialGuardRejectsLoopbackByDefault 是 SSRF 防护的核心断言：
// 默认配置下，投递到环回地址必须被**连接层**拒绝。
func TestDialGuardRejectsLoopbackByDefault(t *testing.T) {
	var hit bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hit = true
		_, _ = io.WriteString(w, `{"errcode":0}`)
	}))
	defer srv.Close()

	t.Setenv(AllowLocalTargetsEnv, "") // 关掉逃生口 = 默认行为
	_, err := (dingTalkChannel{}).Send(context.Background(),
		map[string]any{"webhook": srv.URL + "/robot/send"}, Message{Items: []Item{{Severity: "high"}}})
	if err == nil {
		t.Fatal("默认不应允许投递到环回地址")
	}
	if hit {
		t.Fatal("请求已经打到了本机服务——守卫没生效")
	}
	// 错误信息要能指导用户怎么放开（本机 SMTP 中继是合法配置）。
	if !strings.Contains(err.Error(), AllowLocalTargetsEnv) {
		t.Errorf("拒绝信息应说明如何显式放开: %v", err)
	}
}

// TestDialGuardAllowsLoopbackWhenOptedIn 反向用例：显式打开后必须能用，
// 否则本机 postfix / 内网中继这类合法部署会被一刀切废掉。
func TestDialGuardAllowsLoopbackWhenOptedIn(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"errcode":0,"errmsg":"ok"}`)
	}))
	defer srv.Close()

	t.Setenv(AllowLocalTargetsEnv, "1")
	if _, err := (dingTalkChannel{}).Send(context.Background(),
		map[string]any{"webhook": srv.URL + "/robot/send"}, Message{Items: []Item{{Severity: "high"}}}); err != nil {
		t.Fatalf("显式放开后应可投递: %v", err)
	}
}

func TestIsBlockedDialIP(t *testing.T) {
	blocked := []string{
		"127.0.0.1", "127.1.2.3", "::1",
		"169.254.169.254", // 云元数据端点——本函数存在的主要理由
		"169.254.1.1", "fe80::1",
		"0.0.0.0", "::",
		"224.0.0.1", "ff02::1",
		"::ffff:127.0.0.1", // IPv4-mapped 形式必须还原后再判，否则是绕过口
		"",
	}
	for _, s := range blocked {
		if !isBlockedDialIP(net.ParseIP(s)) {
			t.Errorf("%s 应被拒绝", s)
		}
	}
	// RFC1918 私网**刻意放行**：内网自建 Mattermost / SMTP 中继是常见合法用法。
	// 这条断言把这个取舍固定下来——若将来有人顺手加上私网判断，这里会失败，
	// 从而逼出一次有意识的决定（而不是静默废掉一批部署）。
	allowed := []string{"10.0.0.5", "172.16.3.4", "192.168.1.10", "8.8.8.8", "2606:4700::1111"}
	for _, s := range allowed {
		if isBlockedDialIP(net.ParseIP(s)) {
			t.Errorf("%s 应被放行（私网是常见的合法投递目标）", s)
		}
	}
}

// TestValidateHTTPURLRejectsLiteralPrivateTargets 覆盖配置阶段的前置提示：
// 字面 IP 在保存时就该被拒，而不是等第一次投递失败。
func TestValidateHTTPURLRejectsLiteralPrivateTargets(t *testing.T) {
	t.Setenv(AllowLocalTargetsEnv, "")
	for _, raw := range []string{
		"http://127.0.0.1:8080/hook",
		"http://169.254.169.254/latest/meta-data/",
		"http://[::1]:8080/hook",
	} {
		if err := validateHTTPURL(raw); err == nil {
			t.Errorf("%s 应在配置阶段被拒绝", raw)
		}
	}
	// 公网地址与私网地址照常通过（私网留给拨号阶段，那里不拦）。
	for _, raw := range []string{"https://oapi.dingtalk.com/robot/send", "http://10.0.0.9/hook"} {
		if err := validateHTTPURL(raw); err != nil {
			t.Errorf("%s 应通过校验: %v", raw, err)
		}
	}
}

// TestValidateHTTPURLErrorNeverLeaksCredentials 是审计指出我上一轮遗漏的分支。
//
// url.Parse **失败**时会返回 *url.Error，其 Error() 含完整原始地址。上一轮我只
// 脱敏了 http.Client.Do 的返回错误，漏了这里；而当时补的「永久失败路径」用例
// （file://、gopher://、ftp://）其实都能被 url.Parse 解析成功、走的是 scheme 分支，
// 所以全绿也证明不了这条路径安全——是假保证。
func TestValidateHTTPURLErrorNeverLeaksCredentials(t *testing.T) {
	cases := []string{
		"http://127.0.0.1/%zz?access_token=" + leakProbeToken,         // 非法百分号转义
		"https://a.example.com:port/x?access_token=" + leakProbeToken, // 端口非数字
		"http://[::1?access_token=" + leakProbeToken,                  // 括号不配对
	}
	for _, raw := range cases {
		// 先确认这个输入**确实**让 url.Parse 失败。不做这一步的话，用例可能在
		// 毫无察觉的情况下走到别的分支（上一轮的假保证就是这么来的）。
		if _, err := url.Parse(raw); err == nil {
			t.Errorf("%q 本应解析失败，否则这条用例没有覆盖到目标分支", raw)
			continue
		}
		err := validateHTTPURL(raw)
		if err == nil {
			t.Errorf("%q 应校验失败", raw)
			continue
		}
		assertNoSecret(t, err.Error(), leakProbeToken)
	}
	// 确认渠道层的包装也没有把地址带出去。
	t.Setenv(AllowLocalTargetsEnv, "")
	err := (dingTalkChannel{}).Validate(map[string]any{"webhook": cases[0]})
	if err == nil {
		t.Fatal("非法地址应校验失败")
	}
	assertNoSecret(t, err.Error(), leakProbeToken)
}
