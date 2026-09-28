package service

import (
	"strings"
	"testing"
	"time"
)

func TestProxyURLForIdentity(t *testing.T) {
	base := "http://image:image@192.168.0.4:2260"
	got := proxyURLForIdentity(base, "device-uuid-1")
	if !strings.HasPrefix(got, "http://image.") || !strings.HasSuffix(got, ":image@192.168.0.4:2260") {
		t.Fatalf("改写结果不符合预期: %s", got)
	}
	// 标识不含分隔符且确定
	account := strings.TrimSuffix(strings.TrimPrefix(got, "http://image."), ":image@192.168.0.4:2260")
	if len(account) != 16 || strings.ContainsAny(account, ".:") {
		t.Fatalf("账号标识应为 16 位无分隔符十六进制: %q", account)
	}
	if proxyURLForIdentity(base, "device-uuid-1") != got {
		t.Fatal("同一身份键应得到确定的结果")
	}
	if proxyURLForIdentity(base, "device-uuid-2") == got {
		t.Fatal("不同身份键应得到不同标识")
	}

	// 无密码写法
	got2 := proxyURLForIdentity("http://image@192.168.0.4:2260", "device-uuid-1")
	if !strings.HasPrefix(got2, "http://image.") || !strings.HasSuffix(got2, "@192.168.0.4:2260") {
		t.Fatalf("无密码写法改写不符合预期: %s", got2)
	}

	// 无用户信息 / 空值 原样返回
	if got3 := proxyURLForIdentity("http://192.168.0.4:2260", "key"); got3 != "http://192.168.0.4:2260" {
		t.Fatalf("无用户信息应原样返回: %s", got3)
	}
	if got4 := proxyURLForIdentity(base, "  "); got4 != base {
		t.Fatalf("空身份键应原样返回: %s", got4)
	}
}

func TestProxyForIdentitySwitch(t *testing.T) {
	global := "http://image:image@192.168.0.4:2260"
	// 关闭:原样
	off := NewProxyService(fixedProxyConfig{proxy: global, identity: false})
	if got := off.ProxyForIdentity("device-1"); got != global {
		t.Fatalf("未开启开关应原样返回: %s", got)
	}
	// 开启:改写
	on := NewProxyService(fixedProxyConfig{proxy: global, identity: true})
	if got := on.ProxyForIdentity("device-1"); got == global || !strings.HasPrefix(got, "http://image.") {
		t.Fatalf("开启开关应改写: %s", got)
	}
	// 客户端构建不报错
	if client := on.BrowserHTTPClientForIdentity("firefox", "device-1", 5*time.Second); client == nil {
		t.Fatal("客户端不应为 nil")
	}
}

func TestAccountProxyURLWithIdentity(t *testing.T) {
	backend := newTestStorageBackend(t)
	cfg := testAccountConfig{proxyIdentity: true}
	s := NewAccountService(backend, cfg, NewProxyService(cfg), NewLogService(backend))
	// cfg 无 Proxy() 方法返回全局代理?——testAccountConfig.Proxy() 返回空串,
	// 因此改写路径走全局为空,直接验证 URL 参数版本:
	in := "http://image:image@192.168.0.4:2260"
	if got := s.ProxyURLWithIdentity(in, "key-1"); got == in {
		t.Fatal("开启开关时应改写传入 URL")
	}
	s2 := NewAccountService(backend, testAccountConfig{}, nil, NewLogService(backend))
	if got := s2.ProxyURLWithIdentity(in, "key-1"); got != in {
		t.Fatal("未开启开关应原样返回")
	}
}
