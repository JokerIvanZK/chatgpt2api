package service

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	fhttp "github.com/bogdanfinn/fhttp"
	tlsclient "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
)

// 模拟 Azure Blob:带 Transfer-Encoding 的请求一律 400 UnsupportedHeader
func azureLikeServer(t *testing.T) (*httptest.Server, *int, *int) {
	var okCount, rejectCount int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Go 服务端会把 Transfer-Encoding 从 Header 挪到字段;未知长度时
		// ContentLength 为 -1 且 TransferEncoding 含 chunked
		if len(r.TransferEncoding) > 0 || r.ContentLength < 0 {
			rejectCount++
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `<Error><Code>UnsupportedHeader</Code><HeaderName>Transfer-Encoding</HeaderName></Error>`)
			return
		}
		okCount++
		w.WriteHeader(http.StatusCreated)
	}))
	t.Cleanup(server.Close)
	return server, &okCount, &rejectCount
}

func TestAzureUploadReproBeforeAfter(t *testing.T) {
	server, okCount, rejectCount := azureLikeServer(t)
	payload := bytes.Repeat([]byte("x"), 4096)

	// —— 修复前的行为:适配器丢 ContentLength(此处直接按旧逻辑构造)——
	legacyTransport := &tlsClientRoundTripper{client: func() tlsclient.HttpClient {
		c, err := tlsclient.NewHttpClient(tlsclient.NewNoopLogger(),
			tlsclient.WithTimeoutSeconds(10),
			tlsclient.WithClientProfile(profiles.Chrome_110))
		if err != nil {
			t.Fatal(err)
		}
		return c
	}()}
	legacy := &http.Client{Transport: &droppingAdapter{inner: legacyTransport}}

	req, _ := http.NewRequest(http.MethodPut, server.URL+"/blob", bytes.NewReader(payload))
	req.Header.Set("x-ms-blob-type", "BlockBlob")
	resp, err := legacy.Do(req)
	if err != nil {
		t.Fatalf("legacy PUT error: %v", err)
	}
	_ = resp.Body.Close()

	// —— 修复后的行为:真实适配器 ——
	fixed, err := tlsClientHTTPClient("", "chrome110", 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	req2, _ := http.NewRequest(http.MethodPut, server.URL+"/blob", bytes.NewReader(payload))
	req2.Header.Set("x-ms-blob-type", "BlockBlob")
	resp2, err := fixed.Do(req2)
	if err != nil {
		t.Fatalf("fixed PUT error: %v", err)
	}
	_ = resp2.Body.Close()

	t.Logf("结果: 旧行为拒绝=%d 成功=%d | 新行为累计拒绝=%d 成功=%d", *rejectCount, *okCount, *rejectCount, *okCount)
	if *rejectCount != 1 || *okCount != 1 {
		t.Fatalf("期望旧行为恰好被拒一次、新行为恰好成功一次,实际 reject=%d ok=%d", *rejectCount, *okCount)
	}
}

// droppingAdapter 复刻修复前的缺陷:转换时丢弃 ContentLength
type droppingAdapter struct{ inner *tlsClientRoundTripper }

func (d *droppingAdapter) RoundTrip(req *http.Request) (*http.Response, error) {
	fReq, err := fhttp.NewRequest(req.Method, req.URL.String(), req.Body)
	if err != nil {
		return nil, err
	}
	// 故意不设置 fReq.ContentLength —— 即修复前的行为
	for key, values := range req.Header {
		for _, v := range values {
			fReq.Header.Add(key, v)
		}
	}
	fResp, err := d.inner.client.Do(fReq)
	if err != nil {
		return nil, err
	}
	resp := &http.Response{
		Status: fResp.Status, StatusCode: fResp.StatusCode, Proto: fResp.Proto,
		Header: make(http.Header, len(fResp.Header)), Body: fResp.Body, Request: req,
	}
	for key, values := range fResp.Header {
		resp.Header[key] = append([]string(nil), values...)
	}
	return resp, nil
}
