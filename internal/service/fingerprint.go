package service

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"chatgpt2api/internal/storage"
	"chatgpt2api/internal/util"
)

// verifiedImpersonateVariants 是实测(2026-09,同一代理下复测)可通过
// Cloudflare 的 TLS 变体,共 11 个,分布在两个引擎:
//
//	surf      → Firefox148 全系(firefox/mac/linux/android/ios)
//	tls-client→ Chrome 103/110/111/112/117 与 Opera 91
//
// 引擎按 profile 名自动路由,见 tlsclient_engine.go。
//
// 机制注意:CF 不是按浏览器家族拉黑,而是按具体指纹签名拉黑(被爬虫大量
// 滥用的预设签名会进挑战名单)。同日实测:curl_cffi 的 chrome110/142/150、
// edge101、safari170 通过,chrome131/136/145/146、firefox144/147 被挑战;
// surf 的 chrome145 与 curl_cffi 的 chrome145 同版本且同样被挑战。
// 名单是动态的——这就是指纹验证接口存在的意义,应定期复测并在变体被拉黑时
// 更新此列表(需要 surf 升级提供新预设,或更换 HTTP 伪装库)。
// TLS 指纹无法随机伪造,可用的多样性只有"从实测变体中选"和"设备身份"两个维度。
// 引擎分布:firefox 系走 surf(Firefox148),chrome/opera 系走 tls-client。
var verifiedImpersonateVariants = []string{
	"firefox",
	"mac-firefox",
	"linux-firefox",
	"android-firefox",
	"ios-firefox",
	"chrome103",
	"chrome110",
	"chrome111",
	"chrome112",
	"chrome117",
	"opera91",
}

const (
	// fingerprintStickyTTL 是指纹的粘性时长;到期后下次使用自动轮换。
	fingerprintStickyTTL = 7 * 24 * time.Hour
	fingerprintDocument  = "account_fingerprints.json"
	// fingerprintSeedCount 是内置指纹池的身份数量:
	// 实测变体 × 各自独立的设备身份,首次使用时随机生成并持久化
	// (每个部署不同,避免跨部署共享设备 ID)。
	fingerprintSeedCount = 20
)

// poolIdentity 是指纹池的一个身份:TLS 变体 + 设备身份。
// 绑定到同一身份的账号对上游呈现为同一台设备;DeviceID/SessionID
// 为空表示该身份不共享设备(绑定时为每个账号独立生成)。
type poolIdentity struct {
	Label       string `json:"label"`
	Impersonate string `json:"impersonate"`
	DeviceID    string `json:"oai-device-id"`
	SessionID   string `json:"oai-session-id"`
}

// fingerprintEntry 是账号与池身份的绑定记录。
type fingerprintEntry struct {
	Impersonate string    `json:"impersonate"`
	DeviceID    string    `json:"oai-device-id"`
	SessionID   string    `json:"oai-session-id"`
	AssignedAt  time.Time `json:"assigned_at"`
	// PoolIndex 记录分配时在池中的位置,失败/到期轮换时顺延一位。
	PoolIndex int `json:"pool_index"`
}

func (e fingerprintEntry) fpMap() map[string]string {
	return map[string]string{
		"impersonate":    e.Impersonate,
		"oai-device-id":  e.DeviceID,
		"oai-session-id": e.SessionID,
	}
}

func fingerprintPoolIndex(profile string) int {
	for index, candidate := range verifiedImpersonateVariants {
		if candidate == profile {
			return index
		}
	}
	return 0
}

// fingerprintInitialIndex 用 token 哈希决定初始落位,让账号天然分散在池中。
// 不做取模,由 assignFingerprintLocked 按当前池大小归一。
func fingerprintInitialIndex(token string) int {
	sum := sha256.Sum256([]byte(token))
	return int(sum[0])
}

// activePoolLocked 返回当前生效的指纹池:用户在设置里配置的自定义池优先,
// 否则用首次生成的内置身份池(fingerprintSeedCount 个)。
func (s *AccountService) activePoolLocked() []poolIdentity {
	if custom := s.config.FingerprintPool(); len(custom) > 0 {
		pool := make([]poolIdentity, 0, len(custom))
		for _, entry := range custom {
			if profile := util.Clean(entry["impersonate"]); profile != "" {
				pool = append(pool, poolIdentity{
					Label:       util.Clean(entry["label"]),
					Impersonate: profile,
					DeviceID:    util.Clean(entry["oai-device-id"]),
					SessionID:   util.Clean(entry["oai-session-id"]),
				})
			}
		}
		if len(pool) > 0 {
			return pool
		}
	}
	s.ensureSeedPoolLocked()
	return s.seedPool
}

// ensureSeedPoolLocked 生成并持久化内置身份池(每个部署仅一次)。
func (s *AccountService) ensureSeedPoolLocked() {
	if len(s.seedPool) > 0 {
		return
	}
	s.seedPool = make([]poolIdentity, 0, fingerprintSeedCount)
	for i := 0; i < fingerprintSeedCount; i++ {
		s.seedPool = append(s.seedPool, poolIdentity{
			Label:       fmt.Sprintf("内置 %02d", i+1),
			Impersonate: verifiedImpersonateVariants[i%len(verifiedImpersonateVariants)],
			DeviceID:    util.NewUUID(),
			SessionID:   util.NewUUID(),
		})
	}
	s.saveFingerprintsLocked()
}

// FingerprintFor 返回账号绑定的指纹:命中且未过期(7 天)直接复用;
// 不存在或已过期则分配新的并持久化。账号 fp 里手工指定过 impersonate
// 的视为用户自管,原样返回、不做池化。
func (s *AccountService) FingerprintFor(accessToken string) map[string]string {
	token := util.Clean(accessToken)
	if token == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensureFingerprintsLoadedLocked()
	if manual := s.manualFingerprintLocked(token); manual != nil {
		return manual
	}
	// 账号不存在时不分配绑定,避免制造孤儿记录(加载时的回收只是兜底)
	if s.findIndexLocked(token) < 0 {
		return nil
	}
	if entry, ok := s.fingerprints[token]; ok && time.Since(entry.AssignedAt) < fingerprintStickyTTL {
		return entry.fpMap()
	}
	next := fingerprintInitialIndex(token)
	if entry, ok := s.fingerprints[token]; ok {
		next = entry.PoolIndex + 1
	}
	s.assignFingerprintLocked(token, next)
	return s.fingerprints[token].fpMap()
}

// ReportFingerprintFailure 在指纹不可用(如命中 Cloudflare 挑战)时舍弃粘性,
// 立即换池中下一个身份。
func (s *AccountService) ReportFingerprintFailure(accessToken string) {
	token := util.Clean(accessToken)
	if token == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensureFingerprintsLoadedLocked()
	if s.manualFingerprintLocked(token) != nil {
		return
	}
	entry, ok := s.fingerprints[token]
	if !ok {
		return
	}
	s.assignFingerprintLocked(token, entry.PoolIndex+1)
	s.logs.Add("轮换账号指纹", map[string]any{
		"module": "accounts",
		"token":  util.AnonymizeToken(token),
		"from":   entry.Impersonate,
		"to":     s.fingerprints[token].Impersonate,
	})
}

func (s *AccountService) manualFingerprintLocked(token string) map[string]string {
	idx := s.findIndexLocked(token)
	if idx < 0 {
		return nil
	}
	raw, ok := s.items[idx]["fp"].(map[string]any)
	if !ok || util.Clean(raw["impersonate"]) == "" {
		return nil
	}
	out := map[string]string{}
	for key, value := range raw {
		if text := util.Clean(value); text != "" {
			out[key] = text
		}
	}
	return out
}

// globalImpersonateLocked 返回设置里明确选择的全局伪装;空表示未选择,按池分配。
func (s *AccountService) globalImpersonateLocked() string {
	if s.proxy == nil || s.proxy.config == nil {
		return ""
	}
	return strings.TrimSpace(s.proxy.config.Impersonate())
}

// assignFingerprintLocked 把 token 绑定到池中第 poolIndex 个身份(按池大小取模)。
// 身份自带设备身份则直接共享;为空则生成每账号唯一的 UUID。
func (s *AccountService) assignFingerprintLocked(token string, poolIndex int) {
	pool := s.activePoolLocked()
	size := len(pool)
	if size == 0 {
		size = 1
	}
	index := ((poolIndex % size) + size) % size
	identity := pool[index]
	entry := fingerprintEntry{
		Impersonate: identity.Impersonate,
		DeviceID:    identity.DeviceID,
		SessionID:   identity.SessionID,
		AssignedAt:  time.Now(),
		PoolIndex:   index,
	}
	if entry.DeviceID == "" {
		entry.DeviceID = util.NewUUID()
	}
	if entry.SessionID == "" {
		entry.SessionID = util.NewUUID()
	}
	// 用户在设置里明确选择的全局伪装优先于池分配:固定所有账号的 TLS 指纹
	// (设备身份仍按池/账号独立),轮换时也保持固定。
	if global := s.globalImpersonateLocked(); global != "" {
		entry.Impersonate = global
	}
	s.fingerprints[token] = entry
	s.saveFingerprintsLocked()
}

func (s *AccountService) ensureFingerprintsLoadedLocked() {
	if s.fingerprintsLoaded {
		return
	}
	s.fingerprintsLoaded = true
	s.fingerprints = map[string]fingerprintEntry{}
	s.seedPool = nil
	docBackend, ok := s.storage.(storage.JSONDocumentBackend)
	if !ok {
		return
	}
	raw, err := docBackend.LoadJSONDocument(fingerprintDocument)
	if err != nil || raw == nil {
		return
	}
	encoded, err := json.Marshal(raw)
	if err != nil {
		return
	}
	var payload struct {
		Items map[string]fingerprintEntry `json:"items"`
		Seed  []poolIdentity              `json:"seed"`
	}
	if err := json.Unmarshal(encoded, &payload); err != nil {
		return
	}
	if payload.Items != nil {
		s.fingerprints = payload.Items
	}
	s.seedPool = payload.Seed
	// 账号删除时绑定不即时清理,这里在加载时按现存账号做一次回收
	live := make(map[string]fingerprintEntry, len(s.fingerprints))
	for _, item := range s.items {
		if token := util.Clean(item["access_token"]); token != "" {
			if entry, ok := s.fingerprints[token]; ok {
				live[token] = entry
			}
		}
	}
	if len(live) != len(s.fingerprints) {
		s.fingerprints = live
		s.saveFingerprintsLocked()
	}
}

func (s *AccountService) saveFingerprintsLocked() {
	docBackend, ok := s.storage.(storage.JSONDocumentBackend)
	if !ok {
		return
	}
	_ = docBackend.SaveJSONDocument(fingerprintDocument, map[string]any{
		"items": s.fingerprints,
		"seed":  s.seedPool,
	})
}

// isCloudflareChallengeErrorMessage 判断错误文本是否为 Cloudflare 挑战
// (backend.summarizeUpstreamErrorBody 生成的标准话术)。
func isCloudflareChallengeErrorMessage(message string) bool {
	lower := strings.ToLower(strings.TrimSpace(message))
	return lower != "" && (strings.Contains(lower, "cloudflare challenge") ||
		strings.Contains(lower, "cf_chl") ||
		strings.Contains(lower, "challenge-platform"))
}
