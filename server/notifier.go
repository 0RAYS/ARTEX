package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/notify"
)

// 全局设置键（存在 settings 键值表里，无需建表）。
const (
	// settingNotifyEnabled 是推送总开关。默认开：它用于维护期一键止血，
	// 而不是功能的启用条件——真正的启用条件是「有没有配渠道」。
	settingNotifyEnabled = "notify_enabled"
	// settingNotifyPublicBaseURL 是生成漏洞详情回链的外部访问地址
	// （如 https://artex.example.com）。留空则消息里不带回链按钮。
	// 项目里没有可复用的外部地址配置，所以这里新增一项。
	settingNotifyPublicBaseURL = "notify_public_base_url"
	// settingNotifyDigestMinutes 是汇总模式的周期（分钟）。
	settingNotifyDigestMinutes = "notify_digest_interval_min"
)

const (
	// notifyTick 是投递引擎的轮询间隔。3 秒是该引擎实时性的上限，
	// 也是「漏洞落库」到「消息到达 IM」之间的主要延迟来源。
	notifyTick = 3 * time.Second
	// notifyLease 是领取投递时的租约时长。必须显著大于单次投递的最坏耗时
	// （notify 包的 HTTP 客户端超时 15 秒），否则会出现同一行被两个
	// dispatcher 同时投递。
	notifyLease = 3 * time.Minute
	// notifyFanOutPerTick 限制每轮分派的事件数，避免首次启用渠道时
	// 一次性把历史积压全部展开成投递任务。
	notifyFanOutPerTick = 200
	// notifyDefaultDigestMinutes 是汇总周期的默认值。
	notifyDefaultDigestMinutes = 30
	// notifyUnlimitedBurstPerTick 是渠道未设限流时的每轮投递上限。
	// 存在的意义是防止「一个渠道配成不限流 + 一次扫出上千条漏洞」把
	// 单轮循环拖成长时间阻塞。
	notifyUnlimitedBurstPerTick = 50
)

// notifyBackoff 是失败重试的退避序列，下标为已尝试次数。
// 3 次机会（含首次）与 db.MaxNotifyAttempts 对应，两者必须一起改。
var notifyBackoff = []time.Duration{
	time.Second,
	5 * time.Second,
	30 * time.Second,
}

// Notifier 是漏洞推送的投递引擎。
//
// 与 Scheduler 并列，作为独立 goroutine 运行（见 server.New）。刻意不复用
// Scheduler 的 tick：推送的实时性要求（3 秒）与触发器的业务节奏不同，
// 且两者的失败互不牵连——推送卡住不该影响 agent 触发。
type Notifier struct {
	s  *Server
	pg *db.DB

	// mu 保护 buckets。渠道数量少、竞争低，一把互斥锁足够，
	// 不值得为它引入更细粒度的结构。
	mu      sync.Mutex
	buckets map[int64]*notifyBucket
}

// notifyBucket 是单渠道的令牌桶。
//
// 用令牌桶而不是「每分钟计数后清零」的滑动窗口，是因为后者的边界效应很糟：
// 在窗口末尾发满 20 条、下一瞬间再发 20 条，对平台来说是一秒内 40 条，
// 会被限流；令牌桶以恒定速率补充，天然避免这种突发。
type notifyBucket struct {
	tokens   float64
	lastFill time.Time
}

func newNotifier(s *Server) *Notifier {
	return &Notifier{s: s, pg: s.m.pg, buckets: map[int64]*notifyBucket{}}
}

// Run 循环直到 ctx 结束。由 server.New 启动一次。
func (n *Notifier) Run(ctx context.Context) {
	if n.pg == nil {
		return
	}
	t := time.NewTicker(notifyTick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			n.step(ctx)
		}
	}
}

// step 跑一轮：先分派新事件，再投递到期的任务。
//
// 任何一步失败都只记日志、不中断循环——通知系统的故障绝不能升级成进程级问题。
// 每个 tick 都是独立的，下一轮会自然重试。
func (n *Notifier) step(ctx context.Context) {
	if !n.enabled() {
		return
	}
	if _, _, err := n.pg.FanOutPendingEvents(ctx, notifyFanOutPerTick); err != nil {
		log.Printf("[notify] 分派事件失败: %v", err)
		return
	}
	channels, err := n.pg.ListNotificationChannels(ctx)
	if err != nil {
		log.Printf("[notify] 读取渠道失败: %v", err)
		return
	}
	baseURL := n.publicBaseURL()
	for _, ch := range channels {
		if !ch.IsEnabled() {
			continue
		}
		// 先问令牌桶这一轮还能发几条，再按这个数量去领——顺序不能反，
		// 否则被限流挡下的投递已经消耗过重试次数。
		allow := n.takeTokens(ch.ID, ch.RatePerMin, time.Now())
		if allow <= 0 {
			continue
		}
		if ch.Mode == db.NotifyModeDigest {
			n.stepDigest(ctx, ch, baseURL)
			continue
		}
		n.stepRealtime(ctx, ch, allow, baseURL)
	}
}

// stepRealtime 领取并投递某渠道的实时任务，一条漏洞一条消息。
func (n *Notifier) stepRealtime(ctx context.Context, ch *db.NotificationChannel, allow int, baseURL string) {
	deliveries, err := n.pg.ClaimRealtimeDeliveries(ctx, ch.ID, allow, notifyLease)
	if err != nil {
		log.Printf("[notify] 领取实时投递失败 channel=%d: %v", ch.ID, err)
		return
	}
	if len(deliveries) == 0 {
		return
	}
	channel, cfg, ok := n.adapt(ch)
	if !ok {
		_ = n.pg.FailDeliveries(ctx, deliveryIDs(deliveries), fmt.Sprintf("渠道类型 %q 未注册", ch.Kind))
		return
	}
	for _, dl := range deliveries {
		msg, err := n.renderSingle(ctx, dl, baseURL)
		if err != nil {
			// 渲染失败是本地数据问题，重试不会变好。
			_ = n.pg.FailDeliveries(ctx, []int64{dl.ID}, err.Error())
			continue
		}
		n.send(ctx, channel, cfg, msg, []*db.NotificationDelivery{dl})
	}
}

// stepDigest 在批次到期时把某渠道的待发投递聚合成一条消息发出。
func (n *Notifier) stepDigest(ctx context.Context, ch *db.NotificationChannel, baseURL string) {
	window := n.digestInterval()
	due, err := n.pg.DigestBatchDue(ctx, ch.ID, window)
	if err != nil {
		log.Printf("[notify] 判断汇总批次失败 channel=%d: %v", ch.ID, err)
		return
	}
	if !due {
		return
	}
	deliveries, err := n.pg.ClaimDigestBatch(ctx, ch.ID, notifyLease)
	if err != nil {
		log.Printf("[notify] 领取汇总批次失败 channel=%d: %v", ch.ID, err)
		return
	}
	if len(deliveries) == 0 {
		return
	}
	channel, cfg, ok := n.adapt(ch)
	if !ok {
		_ = n.pg.FailDeliveries(ctx, deliveryIDs(deliveries), fmt.Sprintf("渠道类型 %q 未注册", ch.Kind))
		return
	}
	msg, err := n.renderBatch(ctx, deliveries, baseURL, int(window.Minutes()))
	if err != nil {
		_ = n.pg.FailDeliveries(ctx, deliveryIDs(deliveries), err.Error())
		return
	}
	n.send(ctx, channel, cfg, msg, deliveries)
}

// send 投递并按结果流转状态。
//
// 同一批投递（汇总模式下可能几十条）共享一个发送结果：要么整批送达、要么整批
// 重试。不做逐条重试——汇总消息是一条，重发其中一部分会让批次语义错乱。
func (n *Notifier) send(ctx context.Context, channel notify.Channel, cfg map[string]any, msg notify.Message, deliveries []*db.NotificationDelivery) {
	ids := deliveryIDs(deliveries)
	attempts := maxAttempts(deliveries)

	// 单次投递设上限，避免某个渠道卡住把这一轮剩余渠道全部拖住。
	sendCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	err := channel.Send(sendCtx, cfg, msg)
	if err == nil {
		if err := n.pg.MarkDeliveriesSent(ctx, ids); err != nil {
			log.Printf("[notify] 标记已送达失败 channel=%s ids=%v: %v", channel.Kind(), ids, err)
		}
		return
	}
	// 永久失败与「重试次数用尽」都直接落 failed，等人工在投递历史里重发；
	// 其余按退避序列重排。
	if notify.IsPermanent(err) || attempts >= db.MaxNotifyAttempts {
		reason := err.Error()
		if !notify.IsPermanent(err) {
			reason = fmt.Sprintf("重试 %d 次后仍失败: %s", attempts, err)
		}
		if failErr := n.pg.FailDeliveries(ctx, ids, reason); failErr != nil {
			log.Printf("[notify] 标记失败状态出错 channel=%s ids=%v: %v", channel.Kind(), ids, failErr)
		}
		log.Printf("[notify] 投递失败 channel=%d kind=%s ids=%v: %s", deliveries[0].ChannelID, channel.Kind(), ids, reason)
		return
	}
	delay := notifyBackoff[min(attempts, len(notifyBackoff)-1)]
	if rErr := n.pg.RescheduleDeliveries(ctx, ids, delay, err.Error()); rErr != nil {
		log.Printf("[notify] 重排投递失败 channel=%s ids=%v: %v", channel.Kind(), ids, rErr)
	}
}

// adapt 取渠道实现并解析其配置。
// 返回 ok=false 表示类型未注册，投递应直接判失败而不是无限重试。
func (n *Notifier) adapt(ch *db.NotificationChannel) (notify.Channel, map[string]any, bool) {
	channel, ok := notify.Get(ch.Kind)
	if !ok {
		return nil, nil, false
	}
	var cfg map[string]any
	if len(ch.Config) > 0 {
		// 配置解析失败时给一个空 map：渠道自身的 Validate 会报出「缺哪个字段」，
		// 那个错误比 JSON 解析错误更能指导用户修复。
		_ = json.Unmarshal(ch.Config, &cfg)
	}
	if cfg == nil {
		cfg = map[string]any{}
	}
	return channel, cfg, true
}

// renderSingle 渲染单条漏洞消息。
func (n *Notifier) renderSingle(ctx context.Context, dl *db.NotificationDelivery, baseURL string) (notify.Message, error) {
	snap, err := parseSnapshot(dl)
	if err != nil {
		return notify.Message{}, err
	}
	item, err := n.itemFor(ctx, snap, baseURL)
	if err != nil {
		return notify.Message{}, err
	}
	return notify.Message{Items: []notify.Item{item}, HomeURL: baseURL}, nil
}

// renderBatch 渲染汇总消息。逐条解析快照——单条坏了只跳过那一条，
// 不让它把整批汇总拖没。
func (n *Notifier) renderBatch(ctx context.Context, deliveries []*db.NotificationDelivery, baseURL string, windowMinutes int) (notify.Message, error) {
	items := make([]notify.Item, 0, len(deliveries))
	for _, dl := range deliveries {
		snap, err := parseSnapshot(dl)
		if err != nil {
			log.Printf("[notify] 汇总批次中跳过无法解析的快照 delivery=%d: %v", dl.ID, err)
			continue
		}
		item, err := n.itemFor(ctx, snap, baseURL)
		if err != nil {
			return notify.Message{}, err
		}
		items = append(items, item)
	}
	if len(items) == 0 {
		return notify.Message{}, fmt.Errorf("汇总批次 %d 条投递全部无法解析", len(deliveries))
	}
	return notify.Message{
		Items:         items,
		Batch:         true,
		WindowMinutes: windowMinutes,
		HomeURL:       baseURL,
	}, nil
}

// itemFor 把事件快照渲染成待推送条目，顺带解析资产名与详情回链。
func (n *Notifier) itemFor(ctx context.Context, snap notify.Snapshot, baseURL string) (notify.Item, error) {
	assets, err := n.pg.NotificationAssetNames(ctx, snap.AssetIDs)
	if err != nil {
		// 资产名解析失败不该阻止推送：读不到名字比收不到通知轻得多，
		// 消息里少一行资产而已。
		log.Printf("[notify] 解析资产名失败 finding=%d: %v", snap.FindingID, err)
	}
	item := notify.Item{
		FindingID:  snap.FindingID,
		Name:       snap.Name,
		VulnClass:  snap.VulnClass,
		Severity:   snap.Severity,
		Summary:    snap.Summary,
		Assets:     assets,
		FromStatus: snap.FromStatus,
		ToStatus:   snap.ToStatus,
	}
	if baseURL != "" {
		// 详情页路由见 web/src/app/(main)/function/findings/detail/page.tsx，
		// 它从 query 参数 id 读取漏洞 id。
		item.DetailURL = fmt.Sprintf("%s/function/findings/detail?id=%d", baseURL, snap.FindingID)
	}
	return item, nil
}

// takeTokens 从渠道令牌桶里取出本轮可投递的条数。
//
// 桶容量为该渠道每分钟上限：积压时最多一次性冲这么多（平台规则允许），
// 之后按恒定速率补充。ratePerMin<=0 表示不限流，返回一个有限但足够大的值，
// 防止单轮循环被无限积压拖住。
func (n *Notifier) takeTokens(channelID int64, ratePerMin int, now time.Time) int {
	if ratePerMin <= 0 {
		return notifyUnlimitedBurstPerTick
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	b := n.buckets[channelID]
	if b == nil {
		b = &notifyBucket{tokens: float64(ratePerMin), lastFill: now}
		n.buckets[channelID] = b
	}
	// 按经过的真实时间补充，速率是 ratePerMin/60 每秒。
	if elapsed := now.Sub(b.lastFill).Seconds(); elapsed > 0 {
		b.tokens = minF(float64(ratePerMin), b.tokens+elapsed*float64(ratePerMin)/60)
		b.lastFill = now
	}
	// 加一个极小 epsilon 再取整：令牌数是浮点累加出来的，分两次补满时
	// 0.5 + 0.5 可能得到 0.9999999999，直接 int() 会被截成 0——
	// 数学上已满的桶却取不出令牌。1e-9 远小于一个令牌，不会放过真正的欠额。
	take := int(b.tokens + 1e-9)
	if take <= 0 {
		return 0
	}
	b.tokens -= float64(take)
	return take
}

// enabled 读取总开关。
func (n *Notifier) enabled() bool {
	return n.pg.GetBool(settingNotifyEnabled, true)
}

// publicBaseURL 返回回链用的外部地址，去掉尾部斜杠。
func (n *Notifier) publicBaseURL() string {
	v, ok, err := n.pg.GetSetting(settingNotifyPublicBaseURL)
	if err != nil || !ok {
		return ""
	}
	return trimTrailingSlash(v)
}

// digestInterval 返回汇总周期，非法或未配置时回落到默认值。
func (n *Notifier) digestInterval() time.Duration {
	v, ok, err := n.pg.GetSetting(settingNotifyDigestMinutes)
	if err != nil || !ok {
		return time.Duration(notifyDefaultDigestMinutes) * time.Minute
	}
	m := 0
	if _, err := fmt.Sscanf(v, "%d", &m); err != nil || m <= 0 {
		return time.Duration(notifyDefaultDigestMinutes) * time.Minute
	}
	return time.Duration(m) * time.Minute
}

// parseSnapshot 解析投递对应事件的快照。
func parseSnapshot(dl *db.NotificationDelivery) (notify.Snapshot, error) {
	var snap notify.Snapshot
	if len(dl.Snapshot) == 0 {
		return snap, fmt.Errorf("投递 %d 的事件快照为空", dl.ID)
	}
	if err := json.Unmarshal(dl.Snapshot, &snap); err != nil {
		return snap, fmt.Errorf("解析投递 %d 的事件快照失败: %w", dl.ID, err)
	}
	if snap.Kind == "" {
		// 事件类型以事件行为准，快照里那份可能由旧版本写过。
		snap.Kind = dl.EventKind
	}
	return snap, nil
}

func deliveryIDs(deliveries []*db.NotificationDelivery) []int64 {
	out := make([]int64, 0, len(deliveries))
	for _, dl := range deliveries {
		out = append(out, dl.ID)
	}
	return out
}

// maxAttempts 取批次里最大的已尝试次数。批次会一起成败，用最大值决定是否
// 还有重试预算，避免新加入的行被老行的次数拖下水（反之亦然）。
func maxAttempts(deliveries []*db.NotificationDelivery) int {
	m := 0
	for _, dl := range deliveries {
		if dl.Attempts > m {
			m = dl.Attempts
		}
	}
	return m
}

func trimTrailingSlash(s string) string {
	for len(s) > 0 && s[len(s)-1] == '/' {
		s = s[:len(s)-1]
	}
	return s
}

func minF(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
