package profile

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fullProfile 载入并校验综合样例。
func fullProfile(t *testing.T) *Profile {
	t.Helper()
	path := filepath.Join("testdata", "full.profile")
	p, err := Load(path)
	if err != nil {
		t.Fatalf("Load(%s) 失败: %v", path, err)
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("Validate(%s) 失败: %v", path, err)
	}
	return p
}

func TestParseFullProfileRuns(t *testing.T) {
	path := filepath.Join("testdata", "full.profile")
	doc, err := ParseFile(path)
	if err != nil {
		t.Fatalf("ParseFile 失败: %v", err)
	}
	if doc.File != path {
		t.Errorf("Document.File = %q, 期望 %q", doc.File, path)
	}

	// 九个必需顶层块 + 三个额外信标块都必须解析出来
	wantBlocks := []string{
		"http-get", "http-post", "http-stager", "http-config",
		"https-certificate", "post-ex", "process-inject", "stage",
		"dns-beacon", "tcp-beacon", "smb-beacon",
	}
	for _, name := range wantBlocks {
		if doc.Block(name) == nil {
			t.Errorf("缺少顶层块 %q", name)
		}
		if got := len(doc.Blocks(name)); got != 1 {
			t.Errorf("块 %q 出现 %d 次, 期望 1 次", name, got)
		}
	}

	// 行号必须可用: 首个语句位于第 9 行 (1 起算)
	first := doc.Stmts[0]
	if first.Kind != KindSet || first.Name != "sleeptime" {
		t.Fatalf("首个语句 = %s/%s, 期望 set/sleeptime", first.Kind, first.Name)
	}
	if first.Pos.Line != 9 {
		t.Errorf("sleeptime 行号 = %d, 期望 9", first.Pos.Line)
	}
	if first.Pos.File != path {
		t.Errorf("位置文件名 = %q, 期望 %q", first.Pos.File, path)
	}

	// 子块结构
	getBlock := doc.Block("http-get")
	if len(getBlock.Body) == 0 {
		t.Fatal("http-get 块体为空")
	}
	var client, server *Stmt
	for _, st := range getBlock.Body {
		if st.Kind == KindBlock && st.Name == "client" {
			client = st
		}
		if st.Kind == KindBlock && st.Name == "server" {
			server = st
		}
	}
	if client == nil || server == nil {
		t.Fatal("http-get 缺少 client / server 子块")
	}
	if !hasChild(client, "metadata") || !hasChild(server, "output") {
		t.Error("http-get 缺少 metadata / output 子块")
	}
}

func hasChild(n *Stmt, name string) bool {
	for _, st := range n.Body {
		if st.Kind == KindBlock && st.Name == name {
			return true
		}
	}
	return false
}

func TestProfileGlobals(t *testing.T) {
	p := fullProfile(t)

	if p.SleepTime != 45000 {
		t.Errorf("SleepTime = %d, 期望 45000", p.SleepTime)
	}
	if p.Jitter != 12 {
		t.Errorf("Jitter = %d, 期望 12", p.Jitter)
	}
	wantKill := time.Date(2027, 1, 1, 0, 0, 0, 0, time.Local).Unix()
	if p.KillDate != wantKill {
		t.Errorf("KillDate = %d, 期望 %d", p.KillDate, wantKill)
	}
	if got := p.Global["sample_name"]; got != "Windows Telemetry Helper" {
		t.Errorf("Global[sample_name] = %q", got)
	}
	if got, ok := p.UnknownOptions["unknown_future_option"]; !ok || got != "keep-me" {
		t.Errorf("未知顶层选项未被记录: %q (ok=%v)", got, ok)
	}
	if len(p.UnknownBlocks) != 0 {
		t.Errorf("不应有未知块: %v", p.UnknownBlocks)
	}
}

func TestHTTPGetBlock(t *testing.T) {
	p := fullProfile(t)
	b := p.HTTPGet
	if b == nil {
		t.Fatal("HTTPGet 为空")
	}

	want := []string{"/cdn/1x1.gif", "/api/v1/ping", "/assets/app.js"}
	if got := b.URIs(); !equalStrs(got, want) {
		t.Errorf("URI 池 = %v, 期望 %v", got, want)
	}
	// 循环取用: 含越界与负数
	for i, exp := range []string{"/cdn/1x1.gif", "/api/v1/ping", "/assets/app.js", "/cdn/1x1.gif", "/api/v1/ping"} {
		if got := b.GetURI(i); got != exp {
			t.Errorf("GetURI(%d) = %q, 期望 %q", i, got, exp)
		}
	}
	if got := b.GetURI(-1); got != "/assets/app.js" {
		t.Errorf("GetURI(-1) = %q, 期望 /assets/app.js", got)
	}
	if got := b.Client.Verb; got != "GET" {
		t.Errorf("http-get verb = %q, 期望 GET", got)
	}

	// client 静态头
	if got := b.Client.Headers["Accept"]; got != "text/html,application/xhtml+xml" {
		t.Errorf("Accept = %q", got)
	}
	if got := b.Client.Headers["Cookie"]; got != "SID=abc123" {
		t.Errorf("Cookie = %q", got)
	}
	if got := b.Client.UserAgent; got != "Mozilla/5.0 (Windows NT 10.0; Win64; x64) csdev-get" {
		t.Errorf("client UA = %q", got)
	}
	// 声明顺序必须保留
	if len(b.Client.HeaderList) != 4 || b.Client.HeaderList[0].Name != "Accept" ||
		b.Client.HeaderList[3].Name != "User-Agent" {
		t.Errorf("HeaderList 顺序异常: %+v", b.Client.HeaderList)
	}

	// 优先级: client 的 User-Agent 头应提升为全局 UA
	wantUA := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) csdev-get"
	if p.UserAgent != wantUA {
		t.Errorf("Profile.UserAgent = %q, 期望 %q", p.UserAgent, wantUA)
	}

	// server 静态头
	if got := b.Server.Headers["Content-Type"]; got != "image/gif" {
		t.Errorf("server Content-Type = %q", got)
	}

	// 变换链
	wantMeta := []Transform{
		{Name: TransformBase64URL},
		{Name: TransformPrepend, Arg: "session="},
		{Name: TransformParameter, Arg: "sess"},
	}
	assertChain(t, "http-get client metadata", b.Client.Metadata, wantMeta)
	if pl := b.Client.MetadataPlace; pl.Kind != TransformParameter || pl.Name != "sess" {
		t.Errorf("metadata 落点 = %+v, 期望 parameter/sess", pl)
	}
	assertChain(t, "http-get server output", b.Server.Output, []Transform{
		{Name: TransformMask},
		{Name: TransformPrint},
	})
	if pl := b.Server.OutputPlace; !pl.IsZero() {
		t.Errorf("server output 不应有落点: %+v", pl)
	}
	if len(b.Client.ID) != 0 {
		t.Errorf("http-get client 不应有 id 链: %v", b.Client.ID)
	}
}

func TestHTTPPostBlock(t *testing.T) {
	p := fullProfile(t)
	b := p.HTTPPost
	if b == nil {
		t.Fatal("HTTPPost 为空")
	}
	if got := b.URIs(); !equalStrs(got, []string{"/api/v1/events"}) {
		t.Errorf("post URI = %v", got)
	}
	if got := b.Client.Verb; got != "POST" {
		t.Errorf("post verb = %q, 期望 POST", got)
	}
	if got := b.Client.UserAgent; got != "csdev-post-agent" {
		t.Errorf("块级 set useragent 未生效: %q", got)
	}
	if got := b.Client.Headers["Content-Type"]; got != "application/octet-stream" {
		t.Errorf("post Content-Type = %q", got)
	}

	assertChain(t, "http-post client id", b.Client.ID, []Transform{
		{Name: TransformBase64},
		{Name: TransformHeader, Arg: "X-Session-Id"},
	})
	if pl := b.Client.IDPlace; pl.Kind != TransformHeader || pl.Name != "X-Session-Id" {
		t.Errorf("id 落点 = %+v", pl)
	}
	assertChain(t, "http-post client output", b.Client.Output, []Transform{
		{Name: TransformBase64URL},
		{Name: TransformPrepend, Arg: "data="},
		{Name: TransformParameter, Arg: "d"},
	})
	assertChain(t, "http-post server output", b.Server.Output, []Transform{{Name: TransformPrint}})

	// Transforms 总链 = metadata + id + output
	if n := len(b.Client.Transforms); n != 5 {
		t.Errorf("Transforms 总链长度 = %d, 期望 5 (%v)", n, b.Client.Transforms)
	}
}

func TestHTTPStagerBlock(t *testing.T) {
	p := fullProfile(t)
	b := p.HTTPStager
	if b == nil {
		t.Fatal("HTTPStager 为空")
	}
	if b.URIx86 != "/jquery/jquery.min.js" {
		t.Errorf("URIx86 = %q", b.URIx86)
	}
	if b.URIx64 != "/jquery/jquery-3.7.1.min.js" {
		t.Errorf("URIx64 = %q", b.URIx64)
	}
	if got := b.Client.Parameters["id"]; got != "42" {
		t.Errorf("stager 静态参数 id = %q", got)
	}
	if got := b.Client.Headers["Referer"]; got != "https://www.example.com/index.html" {
		t.Errorf("stager Referer = %q", got)
	}
}

func TestHTTPConfigBlock(t *testing.T) {
	p := fullProfile(t)
	c := p.HTTPConfig
	if c == nil {
		t.Fatal("HTTPConfig 为空")
	}
	if len(c.Headers) != 2 {
		t.Fatalf("http-config headers 数量 = %d, 期望 2", len(c.Headers))
	}
	if c.Headers[0].Name != "Server" || c.Headers[0].Value != "nginx" {
		t.Errorf("headers[0] = %+v", c.Headers[0])
	}
	if c.Headers[1].Name != "X-Powered-By" || c.Headers[1].Value != "PHP/8.2" {
		t.Errorf("headers[1] = %+v", c.Headers[1])
	}
	if !c.TrustXForwardedFor {
		t.Error("trust_x_forwarded_for 未生效")
	}
	if !equalStrs(c.BlockUserAgents, []string{"curl", "wget"}) {
		t.Errorf("block_useragents = %v", c.BlockUserAgents)
	}
	if !equalStrs(c.AllowUserAgents, []string{"Mozilla*", "Opera*"}) {
		t.Errorf("allow_useragents = %v", c.AllowUserAgents)
	}
}

func TestCertificateAndPostEx(t *testing.T) {
	p := fullProfile(t)
	cert := p.SSLCertificate
	if cert == nil {
		t.Fatal("SSLCertificate 为空")
	}
	if cert.Keystore != "certs/dev.store" || cert.Password != "changeit" || cert.Validity != "365" {
		t.Errorf("证书基础字段异常: %+v", cert)
	}
	if cert.CN != "www.example.com" || cert.O != "Example Corp" || cert.OU != "IT Operations" ||
		cert.C != "US" || cert.L != "New York" || cert.ST != "New York" {
		t.Errorf("证书主题字段异常: %+v", cert)
	}

	pe := p.PostEx
	if pe == nil {
		t.Fatal("PostEx 为空")
	}
	// "\X" 非已知转义时保留反斜杠: 双写形式应折叠为单反斜杠
	if pe.SpawnToX86 != `%windir%\SysWOW64\rundll32.exe` {
		t.Errorf("spawnto_x86 = %q", pe.SpawnToX86)
	}
	if pe.SpawnToX64 != `%windir%\System32\rundll32.exe` {
		t.Errorf("spawnto_x64 = %q", pe.SpawnToX64)
	}
	if !pe.Obfuscate || !pe.SmartInject || !pe.AMSIDisable || !pe.Cleanup {
		t.Errorf("post-ex 布尔项异常: %+v", pe)
	}
	if pe.KeyLogger != "GetAsyncKeyState" || pe.PipeName != "postex_##" {
		t.Errorf("post-ex 字符串项异常: %+v", pe)
	}
}

func TestProcessInjectAndStage(t *testing.T) {
	p := fullProfile(t)
	pi := p.ProcessInject
	if pi == nil {
		t.Fatal("ProcessInject 为空")
	}
	if pi.Allocator != "NtMapViewOfSection" || pi.MinAlloc != "17500" || pi.Image != "true" {
		t.Errorf("process-inject 字段异常: %+v", pi)
	}
	if pi.StartRWX || pi.UserRWX {
		t.Errorf("startrwx/userwx 应为 false: %+v", pi)
	}
	if !equalStrs(pi.Execute, []string{"CreateThread", "RtlCreateUserThread"}) {
		t.Errorf("execute 多值解析错误: %v", pi.Execute)
	}
	assertChain(t, "transform-x86", pi.TransformX86, []Transform{{Name: TransformPrepend, Arg: "AAA"}})
	assertChain(t, "transform-x64", pi.TransformX64, []Transform{
		{Name: TransformPrepend, Arg: "BBBB"},
		{Name: TransformAppend, Arg: "CCCC"},
	})
	if len(pi.Transforms) != 3 {
		t.Errorf("process-inject 总链 = %v", pi.Transforms)
	}

	st := p.Stage
	if st == nil {
		t.Fatal("Stage 为空")
	}
	if st.Name != "npmproxy.dll" || st.Allocator != "HeapAlloc" || st.Checksum != "0" ||
		st.EntryPoint != "123456" || st.ImageSizeX86 != "512000" || st.ImageSizeX64 != "512000" {
		t.Errorf("stage 字段异常: %+v", st)
	}
	if !st.Obfuscate || !st.StompPE || !st.Cleanup || st.UserRWX {
		t.Errorf("stage 布尔项异常: %+v", st)
	}
	if !equalStrs(st.Strings, []string{"WWWWWWWWWWWWWWWW", "dGVzdA=="}) {
		t.Errorf("stage string 语句 = %v", st.Strings)
	}
	wantData := []byte{0x4d, 0x5a, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00}
	if string(st.Data) != string(wantData) {
		t.Errorf("stage data = %x, 期望 %x", st.Data, wantData)
	}
	if len(st.StrReps) != 1 || st.StrReps[0].From != "AAAAAAAA" || st.StrReps[0].To != "BBBBBBBB" {
		t.Errorf("stage strrep = %+v", st.StrReps)
	}
}

func TestBeaconBlocks(t *testing.T) {
	p := fullProfile(t)
	d := p.DNS
	if d == nil {
		t.Fatal("DNS 为空")
	}
	if d.MaxDNS != 200 || d.Beacon != "cdn.example.com" ||
		d.GetA != "www." || d.GetAAAA != "ipv6." || d.GetTXT != "txt." ||
		d.PutMetadata != "meta." || d.PutOutput != "out." {
		t.Errorf("dns-beacon 字段异常: %+v", d)
	}
	if d.Idle != "0.0.0.0" || d.TTL != "5" {
		t.Errorf("dns-beacon 附加字段异常: %+v", d)
	}

	if p.TCP == nil || p.TCP.Port != "4444" || p.TCP.PipeName != "tcp_##" ||
		p.TCP.PipeNameStager != "tcpstg_##" {
		t.Errorf("tcp-beacon 异常: %+v", p.TCP)
	}
	if p.SMB == nil || p.SMB.PipeName != "msagent_##" || p.SMB.PipeNameStager != "status_##" {
		t.Errorf("smb-beacon 异常: %+v", p.SMB)
	}
	// 管道优先级: smb-beacon 覆盖顶层 set pipename
	if p.SMBPipe != "msagent_##" {
		t.Errorf("SMBPipe = %q, 期望 msagent_##", p.SMBPipe)
	}
}

func TestEndpointChainsRoundTrip(t *testing.T) {
	p := fullProfile(t)
	get := p.HTTPGet
	plain := []byte("CS2K-frame-bytes-\x00\x01\xfe")

	// metadata: base64url -> prepend -> parameter
	wire, err := get.Client.ApplyMetadata(plain)
	if err != nil {
		t.Fatalf("ApplyMetadata 失败: %v", err)
	}
	if !strings.HasPrefix(string(wire), "session=") {
		t.Errorf("metadata 线上字节缺少前缀: %q", wire)
	}
	back, err := get.Client.RevertMetadata(wire)
	if err != nil {
		t.Fatalf("RevertMetadata 失败: %v", err)
	}
	if string(back) != string(plain) {
		t.Errorf("metadata 往返失败: %q != %q", back, plain)
	}

	// server output: mask -> print
	wire, err = get.Server.ApplyOutput(plain)
	if err != nil {
		t.Fatalf("ApplyOutput 失败: %v", err)
	}
	back, err = get.Server.RevertOutput(wire)
	if err != nil {
		t.Fatalf("RevertOutput 失败: %v", err)
	}
	if string(back) != string(plain) {
		t.Errorf("output 往返失败: %q != %q", back, plain)
	}
}

func TestDefaultProfile(t *testing.T) {
	p := Default()
	if p.SleepTime != DefaultSleepTime || DefaultSleepTime != 60000 {
		t.Errorf("默认 sleeptime = %d, 期望 60000", p.SleepTime)
	}
	if p.Jitter != 0 {
		t.Errorf("默认 jitter = %d, 期望 0", p.Jitter)
	}
	if p.UserAgent != DefaultUserAgent {
		t.Errorf("默认 UA = %q", p.UserAgent)
	}
	if got := p.GetURI(0); got != "/submit" {
		t.Errorf("默认 URI = %q, 期望 /submit", got)
	}
	if got := p.HTTPPost.Client.Verb; got != "POST" {
		t.Errorf("默认 post verb = %q", got)
	}
	if err := p.Validate(); err != nil {
		t.Errorf("默认 profile 校验失败: %v", err)
	}
}

// 未定义 http-post 时, 默认 URI 必须保留
func TestLoadKeepsDefaultsForAbsentBlocks(t *testing.T) {
	p, err := FromSource([]byte("set sleeptime \"1000\";\nhttp-get {\n client {\n set uri \"/x\";\n }\n}\n"), "mini.profile")
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if p.SleepTime != 1000 {
		t.Errorf("sleeptime = %d", p.SleepTime)
	}
	if got := p.GetURI(0); got != "/x" {
		t.Errorf("http-get URI = %q", got)
	}
	if got := p.HTTPPost.GetURI(0); got != DefaultURI {
		t.Errorf("缺失块应保留默认 URI, 实际 %q", got)
	}
	if err := p.Validate(); err != nil {
		t.Errorf("校验失败: %v", err)
	}
}

func TestUserAgentAndPipePrecedence(t *testing.T) {
	src := `
set useragent "top-ua";
http-config {
	set headers "User-Agent: config-ua" "Server: nginx";
}
tcp-beacon { set pipename "tcp-pipe"; }
`
	p, err := FromSource([]byte(src), "ua.profile")
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if p.UserAgent != "top-ua" {
		t.Errorf("UA = %q, 期望顶层 top-ua", p.UserAgent)
	}
	if p.SMBPipe != "tcp-pipe" {
		t.Errorf("管道理应由 tcp-beacon 提供, 实际 %q", p.SMBPipe)
	}

	// client 头优先于顶层 set
	src2 := `
set useragent "top-ua";
http-get { client { header "User-Agent" "client-ua"; } }
`
	p2, err := FromSource([]byte(src2), "ua2.profile")
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if p2.UserAgent != "client-ua" {
		t.Errorf("UA = %q, 期望 client-ua", p2.UserAgent)
	}
}

func TestSingleStringHeaderForm(t *testing.T) {
	src := `http-config { set headers "Cache-Control: no-store"; }`
	p, err := FromSource([]byte(src), "h.profile")
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if got := p.HTTPConfig.Headers[0].Value; got != "no-store" {
		t.Errorf("单串 header 解析 = %q", got)
	}
	if got := lookupHeader(p.HTTPConfig.HeaderMap, "cache-control"); got != "no-store" {
		t.Errorf("大小写不敏感查询失败: %q", got)
	}
}

// ------------------------------------------------------------------ 错误路径

func TestParseErrorsWithLineNumbers(t *testing.T) {
	cases := []struct {
		name     string
		src      string
		wantSubs []string // 错误消息必须同时包含的子串
		wantLine string   // 必须包含的行号标记
	}{
		{
			name:     "set 缺值",
			src:      "set foo;",
			wantSubs: []string{"未知语句", `"set foo"`},
			wantLine: "csdev.profile:1:",
		},
		{
			name:     "缺少分号",
			src:      "set uri \"/a\"\nset jitter \"1\";\n",
			wantSubs: []string{"缺少分号"},
			wantLine: ":2:",
		},
		{
			name:     "未闭合块",
			src:      "http-get {\n  set uri \"/a\";\n",
			wantSubs: []string{"块未闭合", "http-get"},
			wantLine: ":1:",
		},
		{
			name:     "未闭合字符串",
			src:      "set uri \"/a;\n",
			wantSubs: []string{"字符串未闭合"},
			wantLine: ":1:",
		},
		{
			name:     "未知裸语句",
			src:      "http-get {\n  client {\n    metadata {\n      foobar;\n    }\n  }\n}\n",
			wantSubs: []string{"未知语句", "foobar"},
			wantLine: ":4:",
		},
		{
			name:     "意外的右花括号",
			src:      "}\n",
			wantSubs: []string{`意外的 "}"`},
			wantLine: ":1:",
		},
		{
			name:     "意外的左花括号",
			src:      "http-get {\n{\n}\n",
			wantSubs: []string{`意外的 "{"`},
			wantLine: ":2:",
		},
		{
			name:     "变换缺参数",
			src:      "http-get { client { metadata { prepend; } } }\n",
			wantSubs: []string{"prepend", "需要字符串参数"},
			wantLine: ":1:",
		},
		{
			name:     "strrep 缺参数",
			src:      "stage {\n  strrep \"a\";\n}\n",
			wantSubs: []string{"strrep 需要两个字符串参数"},
			wantLine: ":2:",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc, err := Parse([]byte(tc.src), "csdev.profile")
			if err == nil {
				t.Fatalf("期望报错, 实际解析成功: %+v", doc)
			}
			var perr *Error
			if !asError(err, &perr) {
				t.Fatalf("错误类型 = %T, 期望 *profile.Error", err)
			}
			if perr.Pos.Line <= 0 {
				t.Errorf("错误缺少行号: %v", err)
			}
			msg := err.Error()
			for _, sub := range tc.wantSubs {
				if !strings.Contains(msg, sub) {
					t.Errorf("错误消息 %q 未包含 %q", msg, sub)
				}
			}
			if !strings.Contains(msg, tc.wantLine) {
				t.Errorf("错误消息 %q 未包含行号标记 %q", msg, tc.wantLine)
			}
			t.Logf("错误输出: %s", msg)
		})
	}
}

// 语义层错误同样必须带行号
func TestSemanticErrorsWithLineNumbers(t *testing.T) {
	// uri 不以 / 开头
	src := "http-get {\n  set uri \"api/ping\";\n}\n"
	p, err := FromSource([]byte(src), "csdev.profile")
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	err = p.Validate()
	if err == nil {
		t.Fatal("期望 Validate 报错 (uri 未以 / 开头)")
	}
	if !strings.Contains(err.Error(), ":2:") || !strings.Contains(err.Error(), "必须以 / 开头") {
		t.Errorf("uri 校验错误 = %v", err)
	}
	t.Logf("uri 校验错误: %s", err)

	// jitter 超界
	p2, err := FromSource([]byte("set jitter \"120\";\n"), "csdev.profile")
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if err = p2.Validate(); err == nil || !strings.Contains(err.Error(), "jitter") {
		t.Errorf("jitter 越界未报错: %v", err)
	}

	// sleeptime 非正
	p3, err := FromSource([]byte("set sleeptime \"0\";\n"), "csdev.profile")
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if err = p3.Validate(); err == nil || !strings.Contains(err.Error(), "sleeptime") {
		t.Errorf("sleeptime 非正未报错: %v", err)
	}
}

// 投影期 (语法树 -> 语义模型) 的错误同样必须带行号
func TestProjectionErrorsWithLineNumbers(t *testing.T) {
	cases := []struct {
		name     string
		src      string
		wantSubs []string
		wantLine string
	}{
		{
			name:     "http-config headers 缺冒号",
			src:      "http-config {\n  set headers \"no-colon\";\n}\n",
			wantSubs: []string{"缺少 \":\" 分隔"},
			wantLine: "csdev.profile:2:",
		},
		{
			name:     "jitter 非整数",
			src:      "set jitter \"abc\";\n",
			wantSubs: []string{"jitter", "不是整数"},
			wantLine: "csdev.profile:1:",
		},
		{
			name:     "sleeptime 非整数",
			src:      "set sleeptime \"soon\";\n",
			wantSubs: []string{"sleeptime", "不是整数"},
			wantLine: "csdev.profile:1:",
		},
		{
			name:     "killdate 格式非法",
			src:      "set killdate \"never\";\n",
			wantSubs: []string{"killdate"},
			wantLine: "csdev.profile:1:",
		},
		{
			name:     "布尔值非法",
			src:      "post-ex {\n  set obfuscate \"maybe\";\n}\n",
			wantSubs: []string{"obfuscate", "布尔"},
			wantLine: "csdev.profile:2:",
		},
		{
			name:     "stage data 非十六进制",
			src:      "stage {\n  data \"zz\";\n}\n",
			wantSubs: []string{"stage data"},
			wantLine: "csdev.profile:2:",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := FromSource([]byte(tc.src), "csdev.profile")
			if err == nil {
				t.Fatalf("期望报错, 实际构建成功: %+v", p)
			}
			msg := err.Error()
			for _, sub := range tc.wantSubs {
				if !strings.Contains(msg, sub) {
					t.Errorf("错误消息 %q 未包含 %q", msg, sub)
				}
			}
			if !strings.Contains(msg, tc.wantLine) {
				t.Errorf("错误消息 %q 未包含行号标记 %q", msg, tc.wantLine)
			}
			t.Logf("错误输出: %s", msg)
		})
	}
}

// 未知变换: 解析期与语义期都必须带行号报错
func TestUnknownTransform(t *testing.T) {
	// 解析期: 未知裸词
	_, err := Parse([]byte("http-post {\n  client {\n    output {\n      rot13;\n    }\n  }\n}\n"), "csdev.profile")
	if err == nil || !strings.Contains(err.Error(), "未知语句") || !strings.Contains(err.Error(), ":4:") {
		t.Fatalf("解析期未知变换报错异常: %v", err)
	}
	t.Logf("解析期错误: %s", err)

	// 语义期: 手工构造的链
	p := Default()
	p.HTTPGet.Client.Output = []Transform{
		{Name: TransformBase64, Pos: Pos{File: "csdev.profile", Line: 41}},
		{Name: "rot13", Pos: Pos{File: "csdev.profile", Line: 42}},
	}
	p.HTTPGet.Client.rebuildChain()
	err = p.Validate()
	if err == nil {
		t.Fatal("期望 Validate 报出未知变换")
	}
	msg := err.Error()
	if !strings.Contains(msg, "未知变换") || !strings.Contains(msg, `"rot13"`) ||
		!strings.Contains(msg, "csdev.profile:42:") {
		t.Errorf("未知变换错误 = %q", msg)
	}
	t.Logf("语义期错误: %s", msg)

	// 变换名归一化: uri_append 与 uri-append 等价
	if !KnownTransform("uri_append") || !KnownTransform("URI-Append") {
		t.Error("变换名归一化失败")
	}
	if KnownTransform("rot13") {
		t.Error("rot13 不应被识别")
	}

	// ApplyTransforms 遇未知变换必须报错而不是静默通过
	if _, err := ApplyTransforms([]Transform{{Name: "rot13"}}, []byte("x")); err == nil {
		t.Error("ApplyTransforms 未对未知变换报错")
	}
}

// 解析器对任意输入都不得 panic
func TestParseNeverPanics(t *testing.T) {
	inputs := []string{
		"", " ", "\n\n", "#", "#\n", "{", "}", "{}}", "set", "set ", "set x",
		"set x \"", "set x \"a", "http-get", "http-get {", "http-get {}",
		"\"unterminated", "\\", "\xff\xfe\x00binary", ";;;;", "set ;",
		"http-get { client { metadata { prepend } } }",
		"stage { data \"zz\"; }", "stage { data \"0\"; }",
		"set headers \"\";", "header;", "parameter \"a\";",
	}
	for _, in := range inputs {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("Parse(%q) panic: %v", in, r)
				}
			}()
			if _, err := Parse([]byte(in), "panic.profile"); err == nil {
				// 允许解析成功, 只要求不 panic
				_ = in
			}
		}()
	}

	// 伪随机畸形输入
	seed := uint32(0x2E2E2E2E)
	for i := 0; i < 2000; i++ {
		var sb strings.Builder
		n := int(seed % 40)
		for j := 0; j < n; j++ {
			seed = seed*1664525 + 1013904223
			sb.WriteByte(byte(seed >> 24))
		}
		in := sb.String()
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("Parse(随机输入 %q) panic: %v", in, r)
				}
			}()
			_, _ = Parse([]byte(in), "panic.profile")
		}()
	}
}

// ------------------------------------------------------------------ 辅助函数

func assertChain(t *testing.T, label string, got, want []Transform) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s 链长度 = %d (%v), 期望 %d (%v)", label, len(got), got, len(want), want)
	}
	for i := range want {
		if got[i].Name != want[i].Name || got[i].Arg != want[i].Arg {
			t.Errorf("%s[%d] = %s, 期望 %s", label, i, got[i], want[i])
		}
		if got[i].Pos.Line <= 0 {
			t.Errorf("%s[%d] 缺少源位置 (变换必须可定位)", label, i)
		}
	}
}

func equalStrs(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func asError(err error, target **Error) bool {
	e, ok := err.(*Error)
	if ok {
		*target = e
	}
	return ok
}
