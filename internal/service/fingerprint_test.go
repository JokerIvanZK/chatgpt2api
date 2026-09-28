package service

import (
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
	want := fingerprintPool[(fingerprintPoolIndex(first["impersonate"])+1)%len(fingerprintPool)]
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
	want := fingerprintPool[(fingerprintPoolIndex(first["impersonate"])+1)%len(fingerprintPool)]
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
