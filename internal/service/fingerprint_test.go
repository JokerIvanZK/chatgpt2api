package service

import (
	"net/http"
	"reflect"
	"testing"
	"time"
)

func TestFingerprintStickyWithinTTL(t *testing.T) {
	s := newTestAccountService(t)
	token := "tok-fp-sticky"
	s.AddAccounts([]string{token})

	first := s.FingerprintFor(token)
	for _, key := range []string{"impersonate", "oai-device-id", "oai-session-id"} {
		if first[key] == "" {
			t.Fatalf("首次分配缺少 %s: %v", key, first)
		}
	}
	second := s.FingerprintFor(token)
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("TTL 内应粘性:\nfirst=%v\nsecond=%v", first, second)
	}
}

func TestFingerprintSurvivesRestart(t *testing.T) {
	backend := newTestStorageBackend(t)
	token := "tok-fp-restart"
	first := NewAccountService(backend, testAccountConfig{}, nil, NewLogService(backend))
	first.AddAccounts([]string{token})
	assigned := first.FingerprintFor(token)

	restarted := NewAccountService(backend, testAccountConfig{}, nil, NewLogService(backend))
	again := restarted.FingerprintFor(token)
	if !reflect.DeepEqual(assigned, again) {
		t.Fatalf("重启后指纹应不变:\n%v\n%v", assigned, again)
	}
}

func TestFingerprintRotatesOnFailure(t *testing.T) {
	s := newTestAccountService(t)
	token := "tok-fp-rotate"
	s.AddAccounts([]string{token})
	first := s.FingerprintFor(token)

	s.ReportFingerprintFailure(token)
	next := s.FingerprintFor(token)
	want := verifiedImpersonateVariants[(fingerprintPoolIndex(first["impersonate"])+1)%len(verifiedImpersonateVariants)]
	if next["impersonate"] != want {
		t.Fatalf("失败后应轮换到下一个: first=%s got=%s want=%s", first["impersonate"], next["impersonate"], want)
	}
	if next["oai-device-id"] == first["oai-device-id"] {
		t.Fatal("轮换后设备 ID 应更新")
	}
}

func TestFingerprintRotatesAfterTTL(t *testing.T) {
	s := newTestAccountService(t)
	token := "tok-fp-ttl"
	s.AddAccounts([]string{token})
	first := s.FingerprintFor(token)

	s.mu.Lock()
	entry := s.fingerprints[token]
	entry.AssignedAt = time.Now().Add(-fingerprintStickyTTL - time.Hour)
	s.fingerprints[token] = entry
	s.mu.Unlock()

	next := s.FingerprintFor(token)
	want := verifiedImpersonateVariants[(fingerprintPoolIndex(first["impersonate"])+1)%len(verifiedImpersonateVariants)]
	if next["impersonate"] != want {
		t.Fatalf("过期后应轮换: got=%s want=%s", next["impersonate"], want)
	}
}

func TestFingerprintManualOverrideRespected(t *testing.T) {
	s := newTestAccountService(t)
	token := "tok-fp-manual"
	s.AddAccounts([]string{token})
	s.UpdateAccount(token, map[string]any{"fp": map[string]any{"impersonate": "chrome145", "oai-device-id": "manual-dev"}})

	got := s.FingerprintFor(token)
	if got["impersonate"] != "chrome145" || got["oai-device-id"] != "manual-dev" {
		t.Fatalf("账号手工配置应原样生效: %v", got)
	}
	// 手工配置不受失败轮换影响
	s.ReportFingerprintFailure(token)
	if again := s.FingerprintFor(token); again["impersonate"] != "chrome145" {
		t.Fatalf("手工配置不应被轮换: %v", again)
	}
}

func TestFingerprintInitialIndexSpreads(t *testing.T) {
	seen := map[int]bool{}
	for i := 0; i < 50; i++ {
		seen[fingerprintInitialIndex("tok-"+string(rune('a'+i%26))+string(rune(i)))] = true
	}
	if len(seen) < 3 {
		t.Fatalf("初始哈希落位应分散,实际只覆盖 %d 个变体", len(seen))
	}
}

func TestFingerprintCustomPoolEntry(t *testing.T) {
	backend := newTestStorageBackend(t)
	cfg := testAccountConfig{fpPool: []map[string]string{
		{"impersonate": "mac-firefox", "oai-device-id": "pool-dev-1", "oai-session-id": "pool-sess-1"},
		{"impersonate": "linux-firefox"},
	}}
	s := NewAccountService(backend, cfg, NewProxyService(cfg), NewLogService(backend))
	token := "tok-custom-pool"
	s.AddAccounts([]string{token})

	first := s.FingerprintFor(token)
	if first["impersonate"] != "mac-firefox" && first["impersonate"] != "linux-firefox" {
		t.Fatalf("应落在自定义池条目上: %v", first)
	}
	if first["impersonate"] == "mac-firefox" {
		if first["oai-device-id"] != "pool-dev-1" || first["oai-session-id"] != "pool-sess-1" {
			t.Fatalf("自带设备身份的条目应原样使用: %v", first)
		}
	} else if first["oai-device-id"] == "" {
		t.Fatal("缺省设备身份的条目应自动生成")
	}

	// 失败轮换在两个条目间循环
	s.ReportFingerprintFailure(token)
	second := s.FingerprintFor(token)
	if second["impersonate"] == first["impersonate"] {
		t.Fatalf("应轮换到另一条目: %v", second)
	}
	s.ReportFingerprintFailure(token)
	third := s.FingerprintFor(token)
	if third["impersonate"] != first["impersonate"] {
		t.Fatal("两条目应循环轮换")
	}
}

func TestFingerprintGlobalSettingPinsProfile(t *testing.T) {
	backend := newTestStorageBackend(t)
	cfg := testAccountConfig{impersonate: "mac-firefox"}
	s := NewAccountService(backend, cfg, NewProxyService(cfg), NewLogService(backend))
	token := "tok-pin"
	s.AddAccounts([]string{token})
	for i := 0; i < 3; i++ {
		if got := s.FingerprintFor(token); got["impersonate"] != "mac-firefox" {
			t.Fatalf("全局固定应覆盖池分配(第 %d 次): %v", i+1, got)
		}
		s.ReportFingerprintFailure(token)
	}
}

func TestRemoteImpersonationUsesPoolBinding(t *testing.T) {
	s := newTestAccountService(t)
	token := "tok-remote-fp"
	s.AddAccounts([]string{token})
	binding := s.FingerprintFor(token)
	if got := s.remoteImpersonation(token); got != binding["impersonate"] {
		t.Fatalf("刷新链路应使用池绑定指纹: got=%s want=%s", got, binding["impersonate"])
	}
}

func TestRemoteHeadersUsePoolDeviceIdentity(t *testing.T) {
	s := newTestAccountService(t)
	token := "tok-remote-headers"
	s.AddAccounts([]string{token})
	binding := s.FingerprintFor(token)

	headers := s.remoteHeaders(token)
	if headers["oai-device-id"] != binding["oai-device-id"] {
		t.Fatalf("刷新链路应使用池绑定的 device-id: got=%s want=%s", headers["oai-device-id"], binding["oai-device-id"])
	}
	if headers["oai-session-id"] != binding["oai-session-id"] {
		t.Fatalf("刷新链路应使用池绑定的 session-id: got=%s want=%s", headers["oai-session-id"], binding["oai-session-id"])
	}

	// 手工配置仍然优先
	s.UpdateAccount(token, map[string]any{"fp": map[string]any{"oai-device-id": "manual-dev", "impersonate": "ios-firefox"}})
	headers = s.remoteHeaders(token)
	if headers["oai-device-id"] != "manual-dev" {
		t.Fatalf("手工配置应优先: got=%s", headers["oai-device-id"])
	}
}

func TestRegisterClientUsesImpersonatedTransport(t *testing.T) {
	client, err := registerHTTPClient("", 5*time.Second, "reg-device-1")
	if err != nil {
		t.Fatalf("registerHTTPClient() error = %v", err)
	}
	// 注册流量按设备哈希可能落到 surf 或 tls-client 任一引擎,均算伪装成功;
	// 裸 *http.Transport 才是失败。
	if _, plain := client.Transport.(*http.Transport); plain || client.Transport == nil {
		t.Fatalf("注册客户端应使用伪装传输层,实际 %T", client.Transport)
	}
	if client.Jar == nil {
		t.Fatal("注册流程自持的 cookie jar 不应丢失")
	}
}

func TestFingerprintOrphansReclaimedOnLoad(t *testing.T) {
	backend := newTestStorageBackend(t)
	cfg := testAccountConfig{}
	s1 := NewAccountService(backend, cfg, NewProxyService(cfg), NewLogService(backend))
	token := "tok-orphan"
	s1.AddAccounts([]string{token})
	first := s1.FingerprintFor(token)
	if first == nil {
		t.Fatal("正常账号应能分配绑定")
	}
	s1.DeleteAccounts([]string{token})

	s2 := NewAccountService(backend, cfg, NewProxyService(cfg), NewLogService(backend))
	s2.mu.Lock()
	s2.ensureFingerprintsLoadedLocked()
	_, orphaned := s2.fingerprints[token]
	s2.mu.Unlock()
	if orphaned {
		t.Fatal("已删账号的绑定应在加载时被回收")
	}

	// 源头防护:不存在的账号不应被分配绑定
	if fp := s2.FingerprintFor("tok-not-exist"); fp != nil {
		t.Fatal("不存在的账号不应返回指纹")
	}
	s2.mu.Lock()
	_, created := s2.fingerprints["tok-not-exist"]
	s2.mu.Unlock()
	if created {
		t.Fatal("不存在的账号不应产生绑定记录")
	}
}

func TestSeedPoolTwentyIdentities(t *testing.T) {
	s := newTestAccountService(t)
	token := "tok-seed-1"
	s.AddAccounts([]string{token})
	got := s.FingerprintFor(token)

	s.mu.Lock()
	seed := append([]poolIdentity(nil), s.seedPool...)
	s.mu.Unlock()
	if len(seed) != fingerprintSeedCount {
		t.Fatalf("内置池应生成 %d 个身份,实际 %d", fingerprintSeedCount, len(seed))
	}
	variants := map[string]bool{}
	for i, identity := range seed {
		if identity.DeviceID == "" || identity.SessionID == "" {
			t.Fatalf("内置身份 %d 缺少设备身份", i+1)
		}
		variants[identity.Impersonate] = true
	}
	if len(variants) != len(verifiedImpersonateVariants) {
		t.Fatalf("内置池应覆盖全部 %d 个实测变体,实际 %d", len(verifiedImpersonateVariants), len(variants))
	}
	// 绑定应精确来自种子身份
	want := seed[fingerprintInitialIndex(token)%len(seed)]
	if got["impersonate"] != want.Impersonate || got["oai-device-id"] != want.DeviceID {
		t.Fatalf("绑定应来自种子身份: got=%v want=%v", got, want)
	}
}

func TestSeedPoolPersistedAcrossRestart(t *testing.T) {
	backend := newTestStorageBackend(t)
	cfg := testAccountConfig{}
	s1 := NewAccountService(backend, cfg, NewProxyService(cfg), NewLogService(backend))
	tok1 := "tok-seed-r1"
	s1.AddAccounts([]string{tok1})
	s1.FingerprintFor(tok1)
	s1.mu.Lock()
	seed1 := append([]poolIdentity(nil), s1.seedPool...)
	s1.mu.Unlock()

	s2 := NewAccountService(backend, cfg, NewProxyService(cfg), NewLogService(backend))
	tok2 := "tok-seed-r2"
	s2.AddAccounts([]string{tok2})
	got := s2.FingerprintFor(tok2)
	s2.mu.Lock()
	seed2 := s2.seedPool
	s2.mu.Unlock()

	if len(seed1) == 0 || len(seed2) != len(seed1) {
		t.Fatalf("种子池应跨重启持久: %d vs %d", len(seed1), len(seed2))
	}
	for i := range seed1 {
		if seed1[i] != seed2[i] {
			t.Fatalf("种子身份 %d 重启后发生变化", i+1)
		}
	}
	want := seed2[fingerprintInitialIndex(tok2)%len(seed2)]
	if got["oai-device-id"] != want.DeviceID {
		t.Fatalf("重启后新账号应使用持久化的种子身份")
	}
}

func TestAcquireTextAccessTokenForPrefersSameToken(t *testing.T) {
	s := newTestAccountService(t)
	tokens := []string{"tok-pref-a", "tok-pref-b"}
	s.AddAccounts(tokens)

	// 先给 tok-pref-a 绑定指纹(模拟使用过)
	binding := s.FingerprintFor("tok-pref-a")
	if binding == nil {
		t.Fatal("tok-pref-a 应能分配绑定")
	}

	// 用 preferredToken 获取:应优先返回 tok-pref-a
	lease, err := s.AcquireTextAccessTokenFor(map[string]struct{}{}, "tok-pref-a")
	if err != nil {
		t.Fatalf("AcquireTextAccessTokenFor() error = %v", err)
	}
	lease.Release()
	if lease.Token != "tok-pref-a" {
		t.Fatalf("preferredToken 应被优先选中: got %s, want tok-pref-a", lease.Token)
	}

	// preferredToken 已耗尽时应退回常规调度
	exhausted := map[string]struct{}{"tok-pref-a": {}}
	lease2, err := s.AcquireTextAccessTokenFor(exhausted, "tok-pref-a")
	if err != nil {
		t.Fatalf("exhausted preferred 退回正常: %v", err)
	}
	lease2.Release()
	if lease2.Token == "tok-pref-a" {
		t.Fatal("已排除的 preferredToken 不应被选中")
	}

	// 空 preferredToken 走常规调度
	lease3, err := s.AcquireTextAccessTokenFor(map[string]struct{}{}, "")
	if err != nil {
		t.Fatal("空 preferred 应正常工作")
	}
	lease3.Release()
}
