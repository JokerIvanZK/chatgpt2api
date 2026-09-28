package service

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSOCKS5AddressModes(t *testing.T) {
	t.Run("socks5h keeps hostname for proxy-side DNS", func(t *testing.T) {
		got, err := socks5Address(context.Background(), "socks5h", "chatgpt.com:443")
		if err != nil {
			t.Fatalf("socks5Address() error = %v", err)
		}
		wantPrefix := []byte{0x03, byte(len("chatgpt.com"))}
		if string(got[:len(wantPrefix)]) != string(wantPrefix) {
			t.Fatalf("address prefix = %#v, want %#v", got[:len(wantPrefix)], wantPrefix)
		}
		if host := string(got[2 : 2+len("chatgpt.com")]); host != "chatgpt.com" {
			t.Fatalf("host = %q", host)
		}
		if got[len(got)-2] != 0x01 || got[len(got)-1] != 0xbb {
			t.Fatalf("port bytes = %#v", got[len(got)-2:])
		}
	})

	t.Run("socks5 sends numeric ip when target is ip literal", func(t *testing.T) {
		got, err := socks5Address(context.Background(), "socks5", net.JoinHostPort("127.0.0.1", "8080"))
		if err != nil {
			t.Fatalf("socks5Address() error = %v", err)
		}
		want := []byte{0x01, 127, 0, 0, 1, 0x1f, 0x90}
		if string(got) != string(want) {
			t.Fatalf("address = %#v, want %#v", got, want)
		}
	})
}

func TestBrowserHTTPClientKeepsSessionAndTimeout(t *testing.T) {
	client := browserHTTPClient("", 2*time.Second)
	if client == nil {
		t.Fatal("browserHTTPClient() returned nil")
	}
	if client.Jar == nil {
		t.Fatal("browserHTTPClient() should enable a cookie jar for browser-like sessions")
	}
	if client.Timeout != 2*time.Second {
		t.Fatalf("Timeout = %s, want %s", client.Timeout, 2*time.Second)
	}
}

func TestBrowserHTTPClientPreservesCallerAuthHeaders(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer token-1" {
			t.Fatalf("Authorization = %q", got)
		}
		if got := r.Header.Get("Origin"); got != "https://chatgpt.com" {
			t.Fatalf("Origin = %q", got)
		}
		if got := r.Header.Get("Referer"); got != "https://chatgpt.com/" {
			t.Fatalf("Referer = %q", got)
		}
		if got := r.Header.Get("User-Agent"); got == "" {
			t.Fatal("User-Agent should be populated by browser impersonation")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client := browserHTTPClient("", 2*time.Second)
	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer token-1")
	req.Header.Set("Origin", "https://chatgpt.com")
	req.Header.Set("Referer", "https://chatgpt.com/")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

// 回归：surf 的浏览器模板默认把 accept-language 强制为 en-US，
// 与请求里的 OAI-Language: zh-CN 自相矛盾；builder 层必须覆盖回配置值。
func TestBrowserHTTPClientSendsConfiguredAcceptLanguage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Accept-Language"); got != browserAcceptLanguage {
			t.Fatalf("Accept-Language = %q, want %q", got, browserAcceptLanguage)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client := browserHTTPClientForProfile("", "chrome145", 5*time.Second)
	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}
