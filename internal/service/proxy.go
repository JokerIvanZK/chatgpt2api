package service

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"chatgpt2api/internal/util"

	"github.com/enetx/g"
	"github.com/enetx/surf"
)

// 与 backend.go 请求头里的 Accept-Language 保持一致；请求级的设置会被 surf
// 的浏览器模板覆盖，只有 builder 层的值能真正到达线缆。
const browserAcceptLanguage = "zh-CN,zh;q=0.9,en;q=0.8,en-US;q=0.7"

// DefaultImpersonateProfile 是未配置任何伪装时的兜底值。
// 2026-09 实测：Cloudflare 已识别 surf 的 Chrome 指纹（同一代理下所有 Chrome
// 系 profile 请求 chatgpt.com 首页一律 403 challenge），Firefox 系全部 200。
const DefaultImpersonateProfile = "firefox"

type ProxyConfig interface {
	Proxy() string
	Impersonate() string
	ProxyIdentityEnabled() bool
}

type ProxyService struct {
	config ProxyConfig
}

func NewProxyService(config ProxyConfig) *ProxyService {
	return &ProxyService{config: config}
}

func HTTPClientForProxy(proxy string, timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout, Transport: transportForProxy(proxy)}
}

func (s *ProxyService) HTTPClient(timeout time.Duration) *http.Client {
	return HTTPClientForProxy(s.config.Proxy(), timeout)
}

// ImpersonateProfile 返回实际生效的全局伪装配置：设置里的 impersonate 优先，
// 空则回退到 DefaultImpersonateProfile。nil 接收者安全。
func (s *ProxyService) ImpersonateProfile() string {
	if s == nil || s.config == nil {
		return DefaultImpersonateProfile
	}
	if value := strings.TrimSpace(s.config.Impersonate()); value != "" {
		return value
	}
	return DefaultImpersonateProfile
}

func (s *ProxyService) BrowserHTTPClient(timeout time.Duration) *http.Client {
	return browserHTTPClientForProfile(s.config.Proxy(), s.ImpersonateProfile(), timeout)
}

func (s *ProxyService) BrowserHTTPClientWithProfile(profile string, timeout time.Duration) *http.Client {
	return browserHTTPClientForProfile(s.config.Proxy(), profile, timeout)
}

func (s *ProxyService) Test(candidate string, timeout time.Duration) map[string]any {
	candidate = strings.TrimSpace(candidate)
	if candidate == "" {
		candidate = s.config.Proxy()
	}
	candidate = strings.TrimSpace(candidate)
	if candidate == "" {
		return map[string]any{"ok": false, "status": 0, "latency_ms": 0, "error": "proxy url is required"}
	}
	parsed, err := url.Parse(candidate)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https" && parsed.Scheme != "socks5" && parsed.Scheme != "socks5h") {
		return map[string]any{"ok": false, "status": 0, "latency_ms": 0, "error": "invalid proxy url"}
	}
	client := browserHTTPClientForProfile(candidate, s.ImpersonateProfile(), timeout)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://chatgpt.com/", nil)
	req.Header.Set("user-agent", "Mozilla/5.0 (chatgpt2api proxy test)")
	start := time.Now()
	resp, err := client.Do(req)
	latency := time.Since(start).Milliseconds()
	if err != nil {
		message := err.Error()
		if detail, ok := util.SummarizeUpstreamConnectionError(message); ok {
			message = detail
		}
		return map[string]any{"ok": false, "status": 0, "latency_ms": latency, "error": message}
	}
	defer resp.Body.Close()
	ok := resp.StatusCode < 500
	var message any
	if !ok {
		message = resp.Status
	}
	return map[string]any{"ok": ok, "status": resp.StatusCode, "latency_ms": latency, "error": message}
}

// proxyURLForIdentity 把 Basic 认证代理的用户名改写为 "<原用户名>.<账号标识>",
// 适配 Resin 类粘性池的 V1 凭证格式(<平台>.<账号>:<令牌>):
// 平台名保留在原用户名里,账号标识为 identityKey 的 sha256 前 16 位十六进制
// (不含 '.' 与 ':' 两个分隔符)。无用户信息的代理原样返回。
func proxyURLForIdentity(proxyURL, identityKey string) string {
	proxyURL = strings.TrimSpace(proxyURL)
	if proxyURL == "" || strings.TrimSpace(identityKey) == "" {
		return proxyURL
	}
	parsed, err := url.Parse(proxyURL)
	if err != nil || parsed.User == nil {
		return proxyURL
	}
	sum := sha256.Sum256([]byte(strings.TrimSpace(identityKey)))
	account := hex.EncodeToString(sum[:8])
	username := parsed.User.Username()
	if password, hasPassword := parsed.User.Password(); hasPassword {
		parsed.User = url.UserPassword(username+"."+account, password)
	} else {
		parsed.User = url.User(username + "." + account)
	}
	return parsed.String()
}

// IdentityEnabled 返回代理身份改写开关(nil 安全)。
func (s *ProxyService) IdentityEnabled() bool {
	if s == nil || s.config == nil {
		return false
	}
	return s.config.ProxyIdentityEnabled()
}

// ProxyForIdentity 返回按账号身份改写后的全局代理;未开启改写或全局代理
// 不含 Basic 用户信息时原样返回。
func (s *ProxyService) ProxyForIdentity(identityKey string) string {
	if s == nil || s.config == nil {
		return ""
	}
	global := strings.TrimSpace(s.config.Proxy())
	if !s.IdentityEnabled() {
		return global
	}
	return proxyURLForIdentity(global, identityKey)
}

// BrowserHTTPClientForIdentity 以账号身份代理 + 指定伪装构建浏览器客户端。
func (s *ProxyService) BrowserHTTPClientForIdentity(profile, identityKey string, timeout time.Duration) *http.Client {
	if s == nil || s.config == nil {
		return browserHTTPClientForProfile("", profile, timeout)
	}
	return browserHTTPClientForProfile(s.ProxyForIdentity(identityKey), profile, timeout)
}

// resolveProxyCandidate 空候选回落全局代理(全局也为空则允许直连)。
func (s *ProxyService) resolveProxyCandidate(candidate string) string {
	if strings.TrimSpace(candidate) != "" {
		return strings.TrimSpace(candidate)
	}
	return strings.TrimSpace(s.config.Proxy())
}

// VerifyImpersonate 用指定伪装 profile 走给定代理请求 chatgpt.com 首页,
// 实测该指纹当前能否通过 Cloudflare(candidate 为空则用全局代理,也允许
// 为空串表示直连)。返回结构与 Test 对齐,附带 cf-mitigated 判定。
func (s *ProxyService) VerifyImpersonate(candidate, profile string, timeout time.Duration) map[string]any {
	if profile = strings.TrimSpace(profile); profile == "" {
		profile = s.ImpersonateProfile()
	}
	// 与 Test/handleProxy 一致:未指定代理时回落全局代理,避免裸连导致全军覆没
	client := browserHTTPClientForProfile(s.resolveProxyCandidate(candidate), profile, timeout)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://chatgpt.com/", nil)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", browserAcceptLanguage)
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	start := time.Now()
	resp, err := client.Do(req)
	latency := time.Since(start).Milliseconds()
	if err != nil {
		message := err.Error()
		if detail, ok := util.SummarizeUpstreamConnectionError(message); ok {
			message = detail
		}
		return map[string]any{"ok": false, "status": 0, "latency_ms": latency, "error": message}
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	mitigated := resp.Header.Get("cf-mitigated")
	challenged := strings.Contains(strings.ToLower(mitigated), "challenge")
	var message any
	switch {
	case challenged:
		message = fmt.Sprintf("被 Cloudflare 挑战 (cf-mitigated=%s)", mitigated)
	case resp.StatusCode < 200 || resp.StatusCode >= 300:
		message = resp.Status
	}
	return map[string]any{
		"ok":           resp.StatusCode >= 200 && resp.StatusCode < 300 && !challenged,
		"status":       resp.StatusCode,
		"latency_ms":   latency,
		"cf_mitigated": mitigated,
		"error":        message,
	}
}

func browserHTTPClient(proxy string, timeout time.Duration) *http.Client {
	return browserHTTPClientForProfile(proxy, "", timeout)
}

func browserHTTPClientForProfile(proxy, profile string, timeout time.Duration) *http.Client {
	// tls-client 系变体(chrome103..117 / opera91)优先走对应引擎
	if _, supported := tlsClientProfile(profile); supported {
		if client, err := tlsClientHTTPClient(proxy, profile, timeout); err == nil {
			return client
		}
	}
	builder := surf.NewClient().
		Builder().
		SecureTLS()
	// surf 的浏览器模板会把请求里已设置的 accept-language 强制覆盖为 en-US，
	// 与 OAI-Language: zh-CN 自相矛盾；请求级设置拦不住，只能在 builder 层覆盖。
	builder = applyBrowserProfile(builder, profile).
		SetHeaders(map[string]string{"accept-language": browserAcceptLanguage}).
		Session().
		Timeout(timeout)

	if proxy = strings.TrimSpace(proxy); proxy != "" {
		builder = builder.Proxy(g.String(proxy))
	}

	client, err := builder.Build().Result()
	if err != nil {
		return &http.Client{Timeout: timeout, Transport: transportForProxy(proxy)}
	}
	return client.Std()
}

func applyBrowserProfile(builder *surf.Builder, profile string) *surf.Builder {
	impersonate := builder.Impersonate()
	normalized := strings.ToLower(strings.TrimSpace(profile))
	switch {
	case strings.Contains(normalized, "android"):
		impersonate = impersonate.Android()
	case strings.Contains(normalized, "ios"), strings.Contains(normalized, "iphone"), strings.Contains(normalized, "ipad"):
		impersonate = impersonate.IOS()
	case strings.Contains(normalized, "mac"), strings.Contains(normalized, "darwin"):
		impersonate = impersonate.MacOS()
	case strings.Contains(normalized, "linux"):
		impersonate = impersonate.Linux()
	default:
		impersonate = impersonate.Windows()
	}
	if strings.Contains(normalized, "firefox") || strings.Contains(normalized, "ff") {
		return impersonate.Firefox()
	}
	return impersonate.Chrome()
}

func transportForProxy(candidate string) *http.Transport {
	transport := baseTransport()
	if candidate == "" {
		return transport
	}
	proxyURL, err := url.Parse(candidate)
	if err != nil || proxyURL.Host == "" {
		return transport
	}
	return transportForProxyURL(proxyURL)
}

func transportForProxyURL(proxyURL *url.URL) *http.Transport {
	transport := baseTransport()
	switch strings.ToLower(proxyURL.Scheme) {
	case "http", "https":
		transport.Proxy = http.ProxyURL(proxyURL)
	case "socks5", "socks5h":
		transport.Proxy = nil
		transport.DialContext = socks5DialContext(proxyURL)
	}
	return transport
}

func baseTransport() *http.Transport {
	return &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}
}

func socks5DialContext(proxyURL *url.URL) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		dialer := &net.Dialer{}
		conn, err := dialer.DialContext(ctx, network, proxyURL.Host)
		if err != nil {
			return nil, err
		}
		if deadline, ok := ctx.Deadline(); ok {
			_ = conn.SetDeadline(deadline)
			defer func() {
				_ = conn.SetDeadline(time.Time{})
			}()
		}
		if err := socks5Handshake(ctx, conn, proxyURL, address); err != nil {
			_ = conn.Close()
			return nil, err
		}
		return conn, nil
	}
}

func socks5Handshake(ctx context.Context, conn net.Conn, proxyURL *url.URL, target string) error {
	methods := []byte{0x00}
	username := ""
	password := ""
	if proxyURL.User != nil {
		username = proxyURL.User.Username()
		password, _ = proxyURL.User.Password()
		if len(username) > 255 || len(password) > 255 {
			return fmt.Errorf("socks credentials are too long")
		}
		methods = append(methods, 0x02)
	}
	if _, err := conn.Write(append([]byte{0x05, byte(len(methods))}, methods...)); err != nil {
		return err
	}
	response := make([]byte, 2)
	if _, err := io.ReadFull(conn, response); err != nil {
		return err
	}
	if response[0] != 0x05 {
		return fmt.Errorf("invalid socks version %d", response[0])
	}
	switch response[1] {
	case 0x00:
	case 0x02:
		if username == "" && password == "" {
			return fmt.Errorf("socks proxy requires username/password authentication")
		}
		auth := []byte{0x01, byte(len(username))}
		auth = append(auth, []byte(username)...)
		auth = append(auth, byte(len(password)))
		auth = append(auth, []byte(password)...)
		if _, err := conn.Write(auth); err != nil {
			return err
		}
		if _, err := io.ReadFull(conn, response); err != nil {
			return err
		}
		if response[1] != 0x00 {
			return fmt.Errorf("socks authentication failed")
		}
	default:
		return fmt.Errorf("socks proxy rejected authentication methods")
	}
	address, err := socks5Address(ctx, proxyURL.Scheme, target)
	if err != nil {
		return err
	}
	request := []byte{0x05, 0x01, 0x00}
	request = append(request, address...)
	if _, err := conn.Write(request); err != nil {
		return err
	}
	return readSocks5ConnectResponse(conn)
}

func socks5Address(ctx context.Context, scheme, target string) ([]byte, error) {
	host, portText, err := net.SplitHostPort(target)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 0 || port > 65535 {
		return nil, fmt.Errorf("invalid target port %q", portText)
	}
	var out []byte
	if strings.EqualFold(scheme, "socks5h") {
		if len(host) > 255 {
			return nil, fmt.Errorf("target host is too long")
		}
		out = append(out, 0x03, byte(len(host)))
		out = append(out, []byte(host)...)
	} else if ip := net.ParseIP(host); ip != nil {
		out = appendSOCKSIP(out, ip)
	} else {
		ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, err
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("no address found for %s", host)
		}
		out = appendSOCKSIP(out, ips[0].IP)
	}
	var portBytes [2]byte
	binary.BigEndian.PutUint16(portBytes[:], uint16(port))
	out = append(out, portBytes[:]...)
	return out, nil
}

func appendSOCKSIP(out []byte, ip net.IP) []byte {
	if v4 := ip.To4(); v4 != nil {
		out = append(out, 0x01)
		return append(out, v4...)
	}
	out = append(out, 0x04)
	return append(out, ip.To16()...)
}

func readSocks5ConnectResponse(conn net.Conn) error {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return err
	}
	if header[0] != 0x05 {
		return fmt.Errorf("invalid socks version %d", header[0])
	}
	if header[1] != 0x00 {
		return fmt.Errorf("socks connect failed: %s", socks5Status(header[1]))
	}
	toRead := 0
	switch header[3] {
	case 0x01:
		toRead = net.IPv4len
	case 0x03:
		length := make([]byte, 1)
		if _, err := io.ReadFull(conn, length); err != nil {
			return err
		}
		toRead = int(length[0])
	case 0x04:
		toRead = net.IPv6len
	default:
		return fmt.Errorf("invalid socks address type %d", header[3])
	}
	if _, err := io.CopyN(io.Discard, conn, int64(toRead+2)); err != nil {
		return err
	}
	return nil
}

func socks5Status(code byte) string {
	switch code {
	case 0x01:
		return "general failure"
	case 0x02:
		return "connection not allowed"
	case 0x03:
		return "network unreachable"
	case 0x04:
		return "host unreachable"
	case 0x05:
		return "connection refused"
	case 0x06:
		return "ttl expired"
	case 0x07:
		return "command not supported"
	case 0x08:
		return "address type not supported"
	default:
		return fmt.Sprintf("status %d", code)
	}
}
