package profile

import (
	"os"
	"path/filepath"
	"testing"
)

// TestLoadRepoProfile 解析仓库中已有的真实 profile, 验证解析器对实际档案的
// 兼容性 (只读, 不修改仓库文件)。文件缺失时跳过, 保证测试可独立运行。
func TestLoadRepoProfile(t *testing.T) {
	path := filepath.Join("..", "..", "profiles", "csdev.profile")
	if _, err := os.Stat(path); err != nil {
		t.Skipf("仓库 profile 不存在, 跳过: %v", err)
	}
	p, err := Load(path)
	if err != nil {
		t.Fatalf("解析 %s 失败: %v", path, err)
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("校验 %s 失败: %v", path, err)
	}

	// 多 URI 写法 (空格分隔) 必须拆成 URI 池
	uris := p.HTTPGet.URIs()
	wantURIs := []string{"/api/v2/telemetry", "/assets/1x1.gif", "/static/vendor.js", "/health/ping"}
	if !equalStrs(uris, wantURIs) {
		t.Errorf("http-get URI 池 = %v, 期望 %v", uris, wantURIs)
	}
	if got := p.HTTPPost.URIs(); !equalStrs(got, []string{"/api/v2/events"}) {
		t.Errorf("http-post URI 池 = %v", got)
	}

	if p.SleepTime != 37000 || p.Jitter != 35 {
		t.Errorf("sleeptime/jitter = %d/%d, 期望 37000/35", p.SleepTime, p.Jitter)
	}

	// metadata: base64 -> header "X-Request-Id"
	assertChain(t, "csdev http-get client metadata", p.HTTPGet.Client.Metadata, []Transform{
		{Name: TransformBase64},
		{Name: TransformHeader, Arg: "X-Request-Id"},
	})
	// id 块内单参数 parameter
	assertChain(t, "csdev http-post client id", p.HTTPPost.Client.ID, []Transform{
		{Name: TransformParameter, Arg: "session"},
	})
	if got := p.HTTPGet.Client.Headers["Accept-Language"]; got != "en-US,en;q=0.9" {
		t.Errorf("Accept-Language = %q", got)
	}

	// stage 块
	if p.Stage == nil {
		t.Fatal("stage 块缺失")
	}
	if p.Stage.Name != "npmproxy.dll" || p.Stage.Allocator != "HeapAlloc" {
		t.Errorf("stage 字段异常: %+v", p.Stage)
	}
	if !p.Stage.StompPE || !p.Stage.Obfuscate || !p.Stage.Cleanup || p.Stage.UserRWX {
		t.Errorf("stage 布尔项异常: %+v", p.Stage)
	}
	if !equalStrs(p.Stage.Strings, []string{"WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWW", "dGVzdA=="}) {
		t.Errorf("stage strings = %v", p.Stage.Strings)
	}

	// dns-beacon
	if p.DNS == nil || p.DNS.MaxDNS != 200 || p.DNS.GetA != "n." || p.DNS.GetAAAA != "v6." ||
		p.DNS.GetTXT != "t." || p.DNS.PutMetadata != "m." || p.DNS.PutOutput != "o." {
		t.Errorf("dns-beacon 字段异常: %+v", p.DNS)
	}

	if len(p.UnknownBlocks) != 0 {
		t.Errorf("不应有未知块: %v", p.UnknownBlocks)
	}
	if _, ok := p.UnknownOptions["sleep_mask"]; !ok {
		t.Error("sleep_mask 应被记录为未知选项")
	}
	t.Logf("解析 %s: sleep=%d jitter=%d uris=%v UA=%q", path, p.SleepTime, p.Jitter, uris, p.UserAgent)
}
