package service

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	fhttp "github.com/bogdanfinn/fhttp"
	tlsclient "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
)

// tlsClientProfiles 是经 tls-client 引擎支持的伪装(名字归一为无下划线)。
// 2026-09 经生产代理实测:chrome_103..117 与 opera_91 可通过 Cloudflare,
// chrome_120 起全系及 safari/firefox 系被按签名拉黑。
var tlsClientProfiles = map[string]profiles.ClientProfile{
	"chrome103": profiles.Chrome_103,
	"chrome110": profiles.Chrome_110,
	"chrome111": profiles.Chrome_111,
	"chrome112": profiles.Chrome_112,
	"chrome117": profiles.Chrome_117,
	"opera91":   profiles.Opera_91,
}

// profileUserAgents 给 tls-client 系变体配套同版本浏览器 UA,保证 TLS 与
// 头部自洽(surf 引擎会强制覆盖 UA,此处 tls-client 原样发送,必须自己配)。
var profileUserAgents = map[string]string{
	"chrome103": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
	"chrome110": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36",
	"chrome111": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36",
	"chrome112": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36",
	"chrome117": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36",
	"opera91":   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36 OPR/91.0.0.0",
}

// normalizeProfileName 统一别名(去下划线、转小写),如 "chrome_110" -> "chrome110"。
func normalizeProfileName(profile string) string {
	return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(profile), "_", ""))
}

// tlsClientProfile 返回 profile 对应的 tls-client 配置及是否支持。
func tlsClientProfile(profile string) (profiles.ClientProfile, bool) {
	p, ok := tlsClientProfiles[normalizeProfileName(profile)]
	return p, ok
}

// ProfileUserAgent 返回变体配套的默认 UA;非 tls-client 系返回空串。
func ProfileUserAgent(profile string) string {
	return profileUserAgents[normalizeProfileName(profile)]
}

// tlsClientHTTPClient 用 tls-client 引擎构建 *http.Client(适配回标准库类型)。
func tlsClientHTTPClient(proxy, profile string, timeout time.Duration) (*http.Client, error) {
	clientProfile, supported := tlsClientProfile(profile)
	if !supported {
		return nil, fmt.Errorf("unsupported tls-client profile: %s", profile)
	}
	options := []tlsclient.HttpClientOption{
		tlsclient.WithTimeoutSeconds(int(timeout.Seconds())),
		tlsclient.WithClientProfile(clientProfile),
	}
	if strings.TrimSpace(proxy) != "" {
		options = append(options, tlsclient.WithProxyUrl(proxy))
	}
	inner, err := tlsclient.NewHttpClient(tlsclient.NewNoopLogger(), options...)
	if err != nil {
		return nil, err
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: &tlsClientRoundTripper{client: inner},
	}, nil
}

// tlsClientRoundTripper 在标准库 http 与 tls-client 的 fhttp 之间转换,
// 请求头按设置顺序透传( tls-client 不覆盖请求头,这点与 surf 相反)。
type tlsClientRoundTripper struct {
	client tlsclient.HttpClient
}

func (t *tlsClientRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	var body io.ReadCloser
	if req.Body != nil {
		body = req.Body
	}
	fReq, err := fhttp.NewRequest(req.Method, req.URL.String(), body)
	if err != nil {
		return nil, err
	}
	for key, values := range req.Header {
		for _, value := range values {
			fReq.Header.Add(key, value)
		}
	}
	fResp, err := t.client.Do(fReq)
	if err != nil {
		return nil, err
	}
	resp := &http.Response{
		Status:           fResp.Status,
		StatusCode:       fResp.StatusCode,
		Proto:            fResp.Proto,
		ProtoMajor:       fResp.ProtoMajor,
		ProtoMinor:       fResp.ProtoMinor,
		Header:           make(http.Header, len(fResp.Header)),
		Body:             fResp.Body,
		ContentLength:    fResp.ContentLength,
		TransferEncoding: fResp.TransferEncoding,
		Close:            fResp.Close,
		Uncompressed:     fResp.Uncompressed,
		Request:          req,
	}
	for key, values := range fResp.Header {
		resp.Header[key] = append([]string(nil), values...)
	}
	return resp, nil
}
