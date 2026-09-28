package config

import (
	"encoding/json"
	"testing"
)

func TestNormalizeFingerprintPool(t *testing.T) {
	// 数组输入:缺 impersonate 的条目被过滤,其余保留
	got := normalizeFingerprintPool([]any{
		map[string]any{"impersonate": "mac-firefox", "oai-device-id": "d1"},
		map[string]any{"label": "无效条目"},
	})
	var entries []map[string]string
	if err := json.Unmarshal([]byte(got), &entries); err != nil {
		t.Fatalf("产物不是合法 JSON: %v", err)
	}
	if len(entries) != 1 || entries[0]["impersonate"] != "mac-firefox" || entries[0]["oai-device-id"] != "d1" {
		t.Fatalf("过滤结果不符合预期: %v", entries)
	}

	if normalizeFingerprintPool("not json") != "" {
		t.Fatal("非法 JSON 应归一为空")
	}
	if normalizeFingerprintPool("") != "" {
		t.Fatal("空串应保持为空")
	}
	if got := normalizeFingerprintPool(`[{"impersonate":"firefox"}]`); got != `[{"impersonate":"firefox"}]` {
		t.Fatalf("合法 JSON 字符串应原样保留: %s", got)
	}
	if normalizeFingerprintPool([]any{map[string]any{"label": "x"}}) != "" {
		t.Fatal("全部条目无效时应归一为空(回落内置池)")
	}
}
