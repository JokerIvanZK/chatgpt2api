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
