package service

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestDualEngineRouting(t *testing.T) {
	// tls-client 系变体 → tlsClientRoundTripper
	for _, profile := range []string{"chrome110", "chrome_110", "opera91"} {
		client := browserHTTPClientForProfile("", profile, 5*time.Second)
		if client == nil {
			t.Fatalf("%s 返回 nil client", profile)
		}
		if _, ok := client.Transport.(*tlsClientRoundTripper); !ok {
			t.Fatalf("%s 应路由到 tls-client 引擎,实际 %T", profile, client.Transport)
		}
	}
	// firefox 系仍走 surf
	client := browserHTTPClientForProfile("", "mac-firefox", 5*time.Second)
	if _, ok := client.Transport.(*tlsClientRoundTripper); ok {
		t.Fatal("firefox 系不应路由到 tls-client")
	}
}

func TestProfileUserAgent(t *testing.T) {
	if ua := ProfileUserAgent("chrome110"); ua == "" || !contains(ua, "Chrome/110") {
		t.Fatalf("chrome110 应配 Chrome/110 UA: %q", ua)
	}
	if ua := ProfileUserAgent("opera91"); ua == "" || !contains(ua, "OPR/91") {
		t.Fatalf("opera91 应配 OPR/91 UA: %q", ua)
	}
	if ua := ProfileUserAgent("mac-firefox"); ua != "" {
		t.Fatalf("surf 系变体不应有引擎 UA: %q", ua)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

type fixedProxyConfig struct{ proxy string }

func (c fixedProxyConfig) Proxy() string                      { return c.proxy }
func (fixedProxyConfig) Impersonate() string                  { return "" }
func (fixedProxyConfig) FingerprintPool() []map[string]string { return nil }
func (fixedProxyConfig) AutoRemoveInvalidAccounts() bool      { return false }
func (fixedProxyConfig) AutoRemoveRateLimitedAccounts() bool  { return false }
func (fixedProxyConfig) TextAccountScheduleMode() string      { return "load_balance" }
func (fixedProxyConfig) ImageAccountScheduleMode() string     { return "load_balance" }

func TestVerifyProxyFallback(t *testing.T) {
	svc := NewProxyService(fixedProxyConfig{proxy: "http://global:1"})
	if got := svc.resolveProxyCandidate(""); got != "http://global:1" {
		t.Fatalf("空候选应回落全局代理,got %q", got)
	}
	if got := svc.resolveProxyCandidate("  http://explicit:2 "); got != "http://explicit:2" {
		t.Fatalf("显式候选应保留(裁剪空白),got %q", got)
	}
	direct := NewProxyService(fixedProxyConfig{})
	if got := direct.resolveProxyCandidate(""); got != "" {
		t.Fatalf("全局无代理时空候选应保持直连,got %q", got)
	}
}

func TestOrderedHeaderNamesDeterministic(t *testing.T) {
	header := http.Header{}
	for _, name := range []string{"Referer", "Sec-Ch-Ua", "Accept-Language", "Authorization", "X-Custom-1", "X-Custom-2", "Accept"} {
		header.Set(name, "v")
	}
	order := orderedHeaderNames(header)
	// 首选顺序中的头按既定次序排列
	want := []string{"Sec-Ch-Ua", "Authorization", "Accept", "Referer", "Accept-Language"}
	if len(order) < len(want) {
		t.Fatalf("顺序列表过短: %v", order)
	}
	for i, name := range want {
		if order[i] != name {
			t.Fatalf("顺序 %d = %s, want %s (full: %v)", i, order[i], name, order)
		}
	}
	// 未列入首选的头按字典序垫底
	if order[len(order)-2] != "X-Custom-1" || order[len(order)-1] != "X-Custom-2" {
		t.Fatalf("自定义头应按字典序垫底: %v", order)
	}
	// 重复调用结果一致(确定序)
	again := orderedHeaderNames(header)
	for i := range order {
		if order[i] != again[i] {
			t.Fatalf("顺序不稳定")
		}
	}
}

// 离线集成:同一客户端内 cookie 应跨请求保持(链内连续性)
func TestTLSClientCookieContinuity(t *testing.T) {
	var serverURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/set":
			http.SetCookie(w, &http.Cookie{Name: "chain", Value: "1", Path: "/"})
			w.WriteHeader(http.StatusNoContent)
		case "/check":
			if _, err := r.Cookie("chain"); err != nil {
				http.Error(w, "missing cookie", http.StatusPreconditionFailed)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	defer server.Close()
	serverURL = server.URL
	_ = serverURL

	client, err := tlsClientHTTPClient("", "chrome110", 10*time.Second)
	if err != nil {
		t.Fatalf("tlsClientHTTPClient() error = %v", err)
	}
	first, err := client.Get(server.URL + "/set")
	if err != nil {
		t.Fatalf("/set error = %v", err)
	}
	_ = first.Body.Close()
	second, err := client.Get(server.URL + "/check")
	if err != nil {
		t.Fatalf("/check error = %v", err)
	}
	defer second.Body.Close()
	if second.StatusCode != http.StatusNoContent {
		t.Fatalf("cookie 未在链内保持, status = %d", second.StatusCode)
	}
}
