package util

import "strings"

const UpstreamConnectionFailureMessage = "upstream connection failed before TLS handshake completed; check proxy reachability to chatgpt.com or change proxy"

func SummarizeUpstreamConnectionError(message string) (string, bool) {
	text := strings.TrimSpace(message)
	if text == "" {
		return "", false
	}
	lower := strings.ToLower(text)
	if strings.Contains(lower, strings.ToLower(UpstreamConnectionFailureMessage)) ||
		strings.Contains(lower, "utls.handshakecontext") ||
		strings.Contains(lower, "http/2 request failed") ||
		strings.Contains(lower, "http/1.1 fallback failed") ||
		strings.Contains(lower, "tls connect error") ||
		strings.Contains(lower, "openssl_internal") ||
		strings.Contains(lower, "curl: (35)") ||
		((strings.Contains(lower, "tls") || strings.Contains(lower, "handshake")) && strings.Contains(lower, "eof")) {
		return UpstreamConnectionFailureMessage, true
	}
	return "", false
}

// IsProxyUpstreamFailure 判断是否为代理层返回的硬失败(如 Resin 的
// "Proxy responded with non 200 code: 504")。这类失败意味着该身份绑定的
// 出口节点已不可用,应当轮换身份(新哈希换新租约)而不是原地重试。
func IsProxyUpstreamFailure(message string) bool {
	lower := strings.ToLower(strings.TrimSpace(message))
	return lower != "" && strings.Contains(lower, "proxy responded with non 200 code")
}
