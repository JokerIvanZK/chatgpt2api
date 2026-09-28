package util

import "testing"

func TestIsProxyUpstreamFailure(t *testing.T) {
	positive := []string{
		`bootstrap failed: Get "https://chatgpt.com/": Get "https://chatgpt.com/": Proxy responded with non 200 code: 504 Gateway Timeout`,
		`image failed: Proxy responded with non 200 code: 502 Bad Gateway`,
	}
	for _, in := range positive {
		if !IsProxyUpstreamFailure(in) {
			t.Fatalf("应识别为代理失败: %s", in)
		}
	}
	negative := []string{
		"bootstrap failed: status=403, upstream returned Cloudflare challenge page",
		"context deadline exceeded",
		"",
	}
	for _, in := range negative {
		if IsProxyUpstreamFailure(in) {
			t.Fatalf("不应识别为代理失败: %s", in)
		}
	}
}
