package service

import (
	"crypto/sha256"
	"encoding/json"
	"strings"
	"time"

	"chatgpt2api/internal/storage"
	"chatgpt2api/internal/util"
)

// fingerprintPool 是实测(2026-09,同一代理)可通过 Cloudflare 的伪装变体。
// 账号首次使用时按 token 哈希落位,之后失败或到期都顺序轮换到下一个;
// 多个账号共享同一 TLS 变体是预期行为,设备 ID 则每账号唯一。
var fingerprintPool = []string{
	"firefox",
	"mac-firefox",
	"linux-firefox",
	"android-firefox",
	"ios-firefox",
}

const (
	// fingerprintStickyTTL 是指纹的粘性时长;到期后下次使用自动轮换。
	fingerprintStickyTTL = 7 * 24 * time.Hour
	fingerprintDocument  = "account_fingerprints.json"
)

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
	for index, candidate := range fingerprintPool {
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

// fingerprintPoolSizeLocked 返回当前生效的池大小:自定义池优先,空则用内置池。
func (s *AccountService) fingerprintPoolSizeLocked() int {
	if custom := s.config.FingerprintPool(); len(custom) > 0 {
		return len(custom)
	}
	return len(fingerprintPool)
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
// 立即换池中下一个变体并生成新设备 ID。
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

// assignFingerprintLocked 把 token 绑定到池中第 poolIndex 个指纹(按池大小取模)。
// 自定义池条目自带设备身份(共享条目=共享设备身份),留空则生成新 UUID;
// 内置池始终生成每账号唯一的设备 ID。
func (s *AccountService) assignFingerprintLocked(token string, poolIndex int) {
	size := s.fingerprintPoolSizeLocked()
	if size == 0 {
		size = 1
	}
	index := ((poolIndex % size) + size) % size
	entry := fingerprintEntry{AssignedAt: time.Now(), PoolIndex: index}
	if custom := s.config.FingerprintPool(); len(custom) > 0 {
		source := custom[index]
		entry.Impersonate = util.Clean(source["impersonate"])
		entry.DeviceID = util.Clean(source["oai-device-id"])
		entry.SessionID = util.Clean(source["oai-session-id"])
	} else {
		entry.Impersonate = fingerprintPool[index]
	}
	if entry.DeviceID == "" {
		entry.DeviceID = util.NewUUID()
	}
	if entry.SessionID == "" {
		entry.SessionID = util.NewUUID()
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
	}
	if err := json.Unmarshal(encoded, &payload); err != nil {
		return
	}
	if payload.Items != nil {
		s.fingerprints = payload.Items
	}
}

func (s *AccountService) saveFingerprintsLocked() {
	docBackend, ok := s.storage.(storage.JSONDocumentBackend)
	if !ok {
		return
	}
	_ = docBackend.SaveJSONDocument(fingerprintDocument, map[string]any{"items": s.fingerprints})
}

// isCloudflareChallengeErrorMessage 判断错误文本是否为 Cloudflare 挑战
// (backend.summarizeUpstreamErrorBody 生成的标准话术)。
func isCloudflareChallengeErrorMessage(message string) bool {
	lower := strings.ToLower(strings.TrimSpace(message))
	return lower != "" && (strings.Contains(lower, "cloudflare challenge") ||
		strings.Contains(lower, "cf_chl") ||
		strings.Contains(lower, "challenge-platform"))
}
