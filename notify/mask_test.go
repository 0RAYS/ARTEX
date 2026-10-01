package notify

import (
	"errors"
	"strings"
	"testing"
)

func TestMaskedValueHidesBodyButKeepsTailHint(t *testing.T) {
	const secret = "https://oapi.dingtalk.com/robot/send?access_token=abcdef123456"
	got := MaskedValue(secret)
	if strings.Contains(got, "abcdef123456") {
		t.Fatalf("掩码值泄露了完整凭据: %q", got)
	}
	if strings.Contains(got, "oapi.dingtalk.com") {
		t.Fatalf("掩码值不应暴露地址主体: %q", got)
	}
	// 末 6 位要保留，用户才能认出是哪个机器人。
	if !strings.HasSuffix(got, "123456") {
		t.Fatalf("应保留末 6 位作为辨识提示: %q", got)
	}
	if !IsMasked(got) {
		t.Fatalf("掩码值必须能被 IsMasked 识别: %q", got)
	}
}

func TestMaskedValueShortSecretGivesNoHint(t *testing.T) {
	// 短凭据如果也暴露末 6 位，等于把整个凭据暴露出去。
	for _, s := range []string{"abc", "abcdef", ""} {
		got := MaskedValue(s)
		if got != MaskedPrefix {
			t.Fatalf("长度 %d 的凭据不应给出尾部提示，得到 %q", len(s), got)
		}
		if s != "" && strings.Contains(got, s) {
			t.Fatalf("掩码值包含了原值: %q", got)
		}
	}
}

func TestMaskConfigMasksOnlySecrets(t *testing.T) {
	cfg := map[string]any{
		"webhook": "https://example.com/hook?token=SECRETVALUE",
		"secret":  "SECtest123456",
		"port":    float64(587),
		"host":    "smtp.example.com",
	}
	masked := MaskConfig(KindDingTalk, cfg)
	for _, k := range []string{"webhook", "secret"} {
		s, _ := masked[k].(string)
		if !IsMasked(s) {
			t.Errorf("%s 应被掩码，得到 %q", k, s)
		}
	}
	// 非凭据字段必须原样保留，否则 UI 无法展示。
	if masked["port"] != float64(587) {
		t.Errorf("非凭据字段 port 不应改动: %v", masked["port"])
	}
}

func TestMaskConfigUnknownKindReturnsEmpty(t *testing.T) {
	// 渠道类型无法识别时，宁可让 UI 显示空配置，也不要把可能含凭据的原始内容吐回去。
	got := MaskConfig("nope", map[string]any{"webhook": "https://x/y?token=LEAK"})
	if len(got) != 0 {
		t.Fatalf("未知渠道类型应返回空配置，得到 %v", got)
	}
}

func TestMaskConfigDoesNotMutateInput(t *testing.T) {
	// 掩码是展示层行为，不能反过来把库里的真值改掉。
	cfg := map[string]any{"webhook": "https://example.com/hook", "secret": "SECtest123456"}
	_ = MaskConfig(KindDingTalk, cfg)
	if IsMasked(cfg["secret"].(string)) {
		t.Fatal("MaskConfig 修改了入参，会导致真实凭据被掩码值覆盖")
	}
}

func TestMergeConfigKeepsStoredOnMaskedIncoming(t *testing.T) {
	stored := map[string]any{"webhook": "https://real/hook", "secret": "REALSECRET", "method": "POST"}
	// 用户只改了 method，浏览器提交的是掩码值+新 method。
	incoming := map[string]any{
		"webhook": MaskedValue("https://real/hook"),
		"secret":  MaskedValue("REALSECRET"),
		"method":  "PUT",
	}
	got := MergeConfig(stored, incoming)
	if got["webhook"] != "https://real/hook" || got["secret"] != "REALSECRET" {
		t.Fatalf("掩码字段应保留库中原值，得到 %v", got)
	}
	if got["method"] != "PUT" {
		t.Fatalf("被修改的字段应生效，得到 %v", got["method"])
	}
}

func TestMergeConfigEmptyStringClears(t *testing.T) {
	stored := map[string]any{"webhook": "https://real/hook", "secret": "REALSECRET"}
	got := MergeConfig(stored, map[string]any{"secret": ""})
	if _, ok := got["secret"]; ok {
		t.Fatalf("空串应清空该字段，得到 %v", got)
	}
	// 没提到的字段保留（局部更新语义）。
	if got["webhook"] != "https://real/hook" {
		t.Fatalf("未提及的字段应保留，得到 %v", got)
	}
}

func TestMergeConfigKeepsUnmentionedStoredKeys(t *testing.T) {
	stored := map[string]any{"host": "smtp.example.com", "port": float64(587), "password": "pw"}
	got := MergeConfig(stored, map[string]any{"port": float64(465)})
	if got["host"] != "smtp.example.com" || got["password"] != "pw" {
		t.Fatalf("未提及的字段应保留，得到 %v", got)
	}
	if got["port"] != float64(465) {
		t.Fatalf("已提及的字段应更新，得到 %v", got["port"])
	}
}

// TestPrepareConfigUpdateBlocksDestinationSwap 是本包最重要的一条安全不变量：
// **改目标地址不能把旧凭据带过去**。
//
// 这些用例用的正是攻击形状的输入（只改地址、对凭据避而不谈），
// 而不是「防御逻辑的正确输入」——只测后者的话，防御没生效也照样全绿。
func TestPrepareConfigUpdateBlocksDestinationSwap(t *testing.T) {
	cases := []struct {
		name     string
		kind     string
		stored   map[string]any
		incoming map[string]any
		// wantMissing 是预期被点名的凭据键。
		wantMissing string
	}{
		{
			name: "通用 Webhook 改地址想沿用 Authorization 头",
			kind: KindWebhook,
			stored: map[string]any{
				"url":     "https://legit.example.com/hook",
				"headers": map[string]any{"Authorization": "Bearer REAL-TOKEN"},
			},
			incoming:    map[string]any{"url": "https://attacker.tld/c"},
			wantMissing: "headers",
		},
		{
			name:        "Telegram 改 base_url 想把 Bot Token 发到自己的端点",
			kind:        KindTelegram,
			stored:      map[string]any{"bot_token": "123456:REAL", "chat_id": "1", "base_url": "https://api.telegram.org"},
			incoming:    map[string]any{"base_url": "https://attacker.tld"},
			wantMissing: "bot_token",
		},
		{
			name:        "邮件改 SMTP 主机想交出密码",
			kind:        KindEmail,
			stored:      map[string]any{"host": "smtp.corp.com", "port": 587, "password": "REALPW", "from": "a@b.c", "to": []any{"d@e.f"}},
			incoming:    map[string]any{"host": "smtp.attacker.tld"},
			wantMissing: "password",
		},
		{
			name:        "邮件关掉 TLS 也必须重新表态密码",
			kind:        KindEmail,
			stored:      map[string]any{"host": "smtp.corp.com", "port": 587, "tls": false, "password": "REALPW", "from": "a@b.c", "to": []any{"d@e.f"}},
			incoming:    map[string]any{"tls": true},
			wantMissing: "password",
		},
		{
			// 掩码值 = 「沿用旧凭据」，在地址变更的语境下同样必须拒绝。
			name:        "回传掩码凭据 + 新地址",
			kind:        KindTelegram,
			stored:      map[string]any{"bot_token": "123456:REAL", "chat_id": "1", "base_url": "https://api.telegram.org"},
			incoming:    map[string]any{"base_url": "https://attacker.tld", "bot_token": MaskedValue("123456:REAL")},
			wantMissing: "bot_token",
		},
		{
			name:        "钉钉改 Webhook 想沿用加签密钥",
			kind:        KindDingTalk,
			stored:      map[string]any{"webhook": "https://oapi.dingtalk.com/robot/send?access_token=OLD", "secret": "REALSEC"},
			incoming:    map[string]any{"webhook": "https://attacker.tld/hook"},
			wantMissing: "secret",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			merged, err := PrepareConfigUpdate(tc.kind, tc.stored, tc.incoming)
			if err == nil {
				t.Fatalf("改地址却未重新表态凭据，应当被拒绝；得到配置 %v", merged)
			}
			var target *ErrDestinationChangedWithoutCredentials
			if !errors.As(err, &target) {
				t.Fatalf("应返回专门的错误类型以便接口给出可操作提示，得到 %T: %v", err, err)
			}
			found := false
			for _, m := range target.Missing {
				if m == tc.wantMissing {
					found = true
				}
			}
			if !found {
				t.Fatalf("应点名缺失的凭据键 %q，得到 %v", tc.wantMissing, target.Missing)
			}
			// 错误信息要能指导操作者怎么修。
			if !strings.Contains(err.Error(), tc.wantMissing) {
				t.Errorf("错误信息应提到 %q: %v", tc.wantMissing, err)
			}
		})
	}
}

// TestPrepareConfigUpdateAllowsLegitimateEdits 反向用例：正常的编辑不能被误拦，
// 否则这个防护会因为「太烦」而被绕过或删掉。
func TestPrepareConfigUpdateAllowsLegitimateEdits(t *testing.T) {
	cases := []struct {
		name     string
		kind     string
		stored   map[string]any
		incoming map[string]any
	}{
		{
			name:     "只改名字（配置原样回传）",
			kind:     KindWebhook,
			stored:   map[string]any{"url": "https://legit.example.com/hook", "headers": map[string]any{"Authorization": "Bearer REAL"}},
			incoming: map[string]any{"url": MaskedValue("https://legit.example.com/hook")},
		},
		{
			name:     "只改请求方法，地址与凭据都不动",
			kind:     KindWebhook,
			stored:   map[string]any{"url": "https://legit.example.com/hook", "method": "POST"},
			incoming: map[string]any{"method": "PUT"},
		},
		{
			name:     "换地址并**同时**给新凭据",
			kind:     KindWebhook,
			stored:   map[string]any{"url": "https://old.example.com/hook", "headers": map[string]any{"Authorization": "Bearer OLD"}},
			incoming: map[string]any{"url": "https://new.example.com/hook", "headers": map[string]any{"Authorization": "Bearer NEW"}},
		},
		{
			name:     "换地址并显式声明不再需要凭据",
			kind:     KindWebhook,
			stored:   map[string]any{"url": "https://old.example.com/hook", "headers": map[string]any{"Authorization": "Bearer OLD"}},
			incoming: map[string]any{"url": "https://new.example.com/hook", "headers": ""},
		},
		{
			name:     "Telegram 改 chat_id（不是目的地）",
			kind:     KindTelegram,
			stored:   map[string]any{"bot_token": "t", "chat_id": "1", "base_url": "https://api.telegram.org"},
			incoming: map[string]any{"chat_id": "-100200"},
		},
		{
			name:     "邮件改收件人（不是目的地）",
			kind:     KindEmail,
			stored:   map[string]any{"host": "smtp.corp.com", "port": 587, "password": "PW", "from": "a@b.c", "to": []any{"x@y.z"}},
			incoming: map[string]any{"to": []any{"new@y.z"}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			merged, err := PrepareConfigUpdate(tc.kind, tc.stored, tc.incoming)
			if err != nil {
				t.Fatalf("合法编辑被误拦: %v", err)
			}
			if merged == nil {
				t.Fatal("应返回合并结果")
			}
		})
	}
}

// TestPrepareConfigUpdatePortTypeTolerance 覆盖一个容易误判的细节：
// 前端提交的端口是 JSON number（float64），库里读回来也是 float64，
// 但两个值的类型可能不同（如 int vs float64）。用 == 比较会把「没改」判成「改了」，
// 从而对只改了名字的用户弹出「请重新填写密码」——假警报会让人不再信任这个防护。
func TestPrepareConfigUpdatePortTypeTolerance(t *testing.T) {
	stored := map[string]any{"host": "smtp.corp.com", "port": float64(587), "password": "PW"}
	// 同一个端口，以 int 形式提交。
	if _, err := PrepareConfigUpdate(KindEmail, stored, map[string]any{"port": 587}); err != nil {
		t.Fatalf("端口值相同（仅类型不同）不应被判为地址变更: %v", err)
	}
	// 真的换了端口则必须拦。
	if _, err := PrepareConfigUpdate(KindEmail, stored, map[string]any{"port": 25}); err == nil {
		t.Fatal("端口变更应被拦下")
	}
}

func TestDestinationKeysDeclaredForEveryKind(t *testing.T) {
	// 与 SecretKeys 同理：渠道若忘记声明目的地键，PrepareConfigUpdate 就保护不到它。
	for kind, ch := range registry {
		if len(ch.DestinationKeys()) == 0 {
			t.Errorf("渠道 %s 未声明目的地键，改地址带出凭据的防护对它无效", kind)
		}
		if len(ch.SecretKeys()) == 0 {
			t.Errorf("渠道 %s 未声明凭据键", kind)
		}
	}
}

func TestSecretKeysDeclaredForEveryKind(t *testing.T) {
	// 编译器已经强制每个渠道实现 SecretKeys，这里再确认一遍「没有渠道在掩码上
	// 交白卷」——返回空切片的渠道意味着它的凭据会明文回显到浏览器。
	expect := map[string]bool{
		KindDingTalk: true, KindFeishu: true, KindWeCom: true,
		KindWebhook: true, KindTelegram: true, KindEmail: true,
	}
	for kind, ch := range registry {
		if !expect[kind] {
			t.Errorf("渠道 %s 未在测试中登记掩码预期", kind)
			continue
		}
		if len(ch.SecretKeys()) == 0 {
			t.Errorf("渠道 %s 未声明任何凭据字段，其配置会明文回显", kind)
		}
	}
}

// TestPrepareConfigUpdateRejectsMaskedInContainer 覆盖审计指出的一处口子：
// 把掩码哨兵塞进**非字符串**结构（如 webhook.headers 是个对象）时，
// MergeConfig 只认「字符串且带前缀」为掩码，于是字面量 "__masked__" 会被当成
// 真实头值存进库——后续鉴权静默失效，且没有任何报错。
func TestPrepareConfigUpdateRejectsMaskedInContainer(t *testing.T) {
	stored := map[string]any{
		"url":     "https://legit.example.com/hook",
		"headers": map[string]any{"Authorization": "Bearer REAL"},
	}
	// 对象内部夹带掩码哨兵。
	incoming := map[string]any{
		"headers": map[string]any{"Authorization": MaskedPrefix},
	}
	if _, err := PrepareConfigUpdate(KindWebhook, stored, incoming); err == nil {
		t.Fatal("结构体内部夹带掩码哨兵应被拒绝（否则会把字面量存进库）")
	}
	// 整体提交对象（真实新值）照常接受。
	ok := map[string]any{"headers": map[string]any{"Authorization": "Bearer NEW"}}
	if _, err := PrepareConfigUpdate(KindWebhook, stored, ok); err != nil {
		t.Fatalf("正常提交新请求头不应被拦: %v", err)
	}
}
