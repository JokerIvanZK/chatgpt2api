package backend

import (
	"testing"

	"chatgpt2api/internal/service"
)

type fakeFingerprintProvider struct {
	account map[string]any
	fp      map[string]string
	asked   int
}

func (f *fakeFingerprintProvider) GetAccount(string) map[string]any { return f.account }

func (f *fakeFingerprintProvider) FingerprintFor(string) map[string]string {
	f.asked++
	return f.fp
}

func TestNewClientOverlaysAccountFingerprint(t *testing.T) {
	provider := &fakeFingerprintProvider{
		account: map[string]any{},
		fp: map[string]string{
			"impersonate":    "mac-firefox",
			"oai-device-id":  "dev-1",
			"oai-session-id": "sess-1",
		},
	}
	proxy := service.NewProxyService(fakeProxyConfig{})
	c := NewClient("token-1", provider, proxy)

	if got := c.fp["impersonate"]; got != "mac-firefox" {
		t.Fatalf("impersonate = %q, want mac-firefox", got)
	}
	if c.deviceID != "dev-1" || c.sessionID != "sess-1" {
		t.Fatalf("device/session 未覆盖: %q / %q", c.deviceID, c.sessionID)
	}
	if provider.asked != 1 {
		t.Fatalf("FingerprintFor 调用 %d 次, want 1", provider.asked)
	}
}

type fakeProxyConfig struct{}

func (fakeProxyConfig) Proxy() string              { return "" }
func (fakeProxyConfig) Impersonate() string        { return "" }
func (fakeProxyConfig) ProxyIdentityEnabled() bool { return false }
