package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ---------------------------------------------------------------- 测试夹具

// reportRequest 直接调用报告 handler, 可选携带 Bearer 令牌。
func reportRequest(t *testing.T, method, target string, h http.HandlerFunc, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h(rec, req)
	return rec
}

// seedReportData 造一组含转义陷阱的数据, 覆盖 CSV 与 HTML 两条导出路径。
func seedReportData(t *testing.T) {
	t.Helper()
	storeAdd(Credential{
		Kind: KindCredential, ID: nextStoreID("cr"), SID: "s-0001", CredK: 1,
		User: "alice,admin", Secret: "say \"hi\"\n第二行", Source: "lsass", TS: 1700000000,
	})
	storeAdd(Download{
		Kind: KindDownload, ID: nextStoreID("dl"), SID: "s-0001", Name: "报表,终版.xlsx",
		Path: `C:\dl\a.xlsx`, RemotePath: `C:\Users\a\报表,终版.xlsx`, Size: 2048, TS: 1700000100,
	})
	storeAdd(Screenshot{
		Kind: KindScreenshot, ID: nextStoreID("ss"), SID: "s-0001",
		Path: `C:\ss\1.jpg`, Size: 512, TS: 1700000200,
	})
	storeAdd(Keystroke{
		Kind: KindKeystroke, ID: nextStoreID("kl"), SID: "s-0001",
		Text: "password=中文", Source: "kbd", TS: 1700000300,
	})
	// 后台作业(报告 jobs 段需要至少一条数据)
	bgJobStore.mu.Lock()
	bgJobStore.jobs = nil
	bgJobStore.seq = 0
	bgJobStore.mu.Unlock()
	bgJobStart("s-0001", "socks", "SOCKS5 127.0.0.1:1080", 1080, true)
	bgJobStart("s-0001", "portscan", "端口扫描 10.0.0.1", 0, false)
	eventLog("operator", "", "登录", "alice,admin")
}

// ---------------------------------------------------------------- 转义

func TestCSVEscape(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"", ""},
		{"plain", "plain"},
		{"中文文本", "中文文本"},
		{"a,b", `"a,b"`},
		{`he said "hi"`, `"he said ""hi"""`},
		{"line1\nline2", "\"line1\nline2\""},
		{"crlf\r\nend", "\"crlf\r\nend\""},
		{"solo\rcr", "\"solo\rcr\""},
		{"中文,引号\"与换行\n", "\"中文,引号\"\"与换行\n\""},
		{" pad ", `" pad "`},
		{" lead", `" lead"`},
		{`""`, `""""""`},
	}
	for _, c := range cases {
		if got := csvEscape(c.in); got != c.want {
			t.Errorf("csvEscape(%q) = %q, 期望 %q", c.in, got, c.want)
		}
	}
}

func TestCSVRow(t *testing.T) {
	if got, want := csvRow("a", "b,c"), "a,\"b,c\"\r\n"; got != want {
		t.Errorf("csvRow = %q, 期望 %q", got, want)
	}
	if got, want := csvRow(""), "\r\n"; got != want {
		t.Errorf("单空字段行 = %q, 期望 %q", got, want)
	}
	if got, want := csvRow("中文", "多 个"), "中文,多 个\r\n"; got != want {
		t.Errorf("中文行 = %q, 期望 %q", got, want)
	}
	// 每行必须以 CRLF 结束 (RFC 4180)
	if !strings.HasSuffix(csvRow("x"), "\r\n") {
		t.Error("CSV 行必须以 CRLF 结束")
	}
}

func TestHTMLEscape(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"", ""},
		{"plain", "plain"},
		{"中文文本", "中文文本"},
		{"<script>alert(1)</script>", "&lt;script&gt;alert(1)&lt;/script&gt;"},
		{`<img src=x onerror=alert(1)>`, "&lt;img src=x onerror=alert(1)&gt;"},
		{"a & b", "a &amp; b"},
		{`"q" 'x'`, "&quot;q&quot; &#39;x&#39;"},
		{"中文<中文>", "中文&lt;中文&gt;"},
		// 单遍扫描: 已有实体不得被二次转义, 但裸 & 必须转义
		{"&lt;", "&amp;lt;"},
		{"&amp;", "&amp;amp;"},
	}
	for _, c := range cases {
		if got := htmlEscape(c.in); got != c.want {
			t.Errorf("htmlEscape(%q) = %q, 期望 %q", c.in, got, c.want)
		}
	}
	// 转义结果不得再含可执行标记
	if s := htmlEscape("<script>x</script>"); strings.Contains(s, "<") || strings.Contains(s, ">") {
		t.Errorf("转义后不应残留尖括号: %q", s)
	}
}

// ---------------------------------------------------------------- JSON 快照

func TestReportJSONSnapshot(t *testing.T) {
	openTestEnv(t)
	SetAuthEnabled(false)
	seedReportData(t)

	inj := `<script>alert(1)</script>`
	eventLog("operator", "", inj, inj)

	rec := reportRequest(t, http.MethodGet, "/api/report/json", handleReportJSON, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("应返回 200, 实际 %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Errorf("Content-Type 应为 JSON, 实际 %q", ct)
	}

	var snap reportSnapshot
	if err := json.Unmarshal(rec.Body.Bytes(), &snap); err != nil {
		t.Fatalf("报告 JSON 无法解析: %v", err)
	}

	if !snap.OK {
		t.Error("ok 应为 true")
	}
	if snap.GeneratedAt <= 0 || snap.Generated == "" {
		t.Error("报告必须带生成时间")
	}
	if snap.Server == "" || snap.Profile == "" {
		t.Error("报告应带服务端地址与 profile 名")
	}

	// 统计必须与实际条数一致
	if len(snap.Credentials) != 1 {
		t.Errorf("凭据应为 1 条, 实际 %d", len(snap.Credentials))
	}
	if len(snap.Downloads) != 1 || len(snap.Screenshots) != 1 || len(snap.Keylogs) != 1 {
		t.Errorf("下载/截屏/键盘记录条数不符: %d/%d/%d",
			len(snap.Downloads), len(snap.Screenshots), len(snap.Keylogs))
	}
	if len(snap.Events) != 2 {
		t.Errorf("事件应为 2 条, 实际 %d", len(snap.Events))
	}
	for _, k := range []string{"sessions", "credentials", "downloads", "screenshots", "keylogs", "events", "listeners"} {
		if _, has := snap.Stats[k]; !has {
			t.Errorf("统计缺少字段: %s", k)
		}
	}
	if snap.Stats["credentials"] != len(snap.Credentials) {
		t.Error("统计与凭据条数不一致")
	}
	if snap.Stats["events"] != len(snap.Events) {
		t.Error("统计与事件条数不一致")
	}

	// 事件按时间正序 (storeEvents 返回倒序, 报告需要正序)
	for i := 1; i < len(snap.Events); i++ {
		if snap.Events[i].TS < snap.Events[i-1].TS {
			t.Errorf("事件日志应按时间正序: [%d].TS=%d < [%d].TS=%d",
				i, snap.Events[i].TS, i-1, snap.Events[i-1].TS)
		}
	}

	// JSON 层保留原始值, 转义只发生在 HTML/CSV 层
	found := false
	for _, c := range snap.Credentials {
		if c.User == "alice,admin" {
			found = true
		}
	}
	if !found {
		t.Error("JSON 快照应保留原始用户名 (不做 CSV/HTML 转义)")
	}
	// 会话数组必须存在 (可为空)
	if snap.Sessions == nil || snap.Listeners == nil {
		t.Error("sessions / listeners 应为数组而非 null")
	}
}

// ---------------------------------------------------------------- CSV 导出

func TestReportCSVExport(t *testing.T) {
	openTestEnv(t)
	SetAuthEnabled(false)
	seedReportData(t)

	rec := reportRequest(t, http.MethodGet, "/api/report/csv?kind=credentials", handleReportCSV, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("应返回 200, 实际 %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/csv; charset=utf-8" {
		t.Errorf("Content-Type 不符: %q", ct)
	}
	cd := rec.Header().Get("Content-Disposition")
	if !strings.Contains(cd, "attachment") || !strings.Contains(cd, "credentials") {
		t.Errorf("Content-Disposition 不符: %q", cd)
	}

	raw := rec.Body.Bytes()
	if !bytes.HasPrefix(raw, []byte{0xEF, 0xBB, 0xBF}) {
		t.Fatal("CSV 必须带 UTF-8 BOM, 否则 Excel 中中文乱码")
	}
	text := string(raw[3:])

	if !strings.Contains(text, "用户名") || !strings.Contains(text, "时间") || !strings.Contains(text, "凭据类型") {
		t.Errorf("表头应为中文, 实际: %q", firstLine(text))
	}
	if !strings.Contains(text, `"alice,admin"`) {
		t.Error("含逗号的字段必须被引号包裹")
	}
	if !strings.Contains(text, `"say ""hi""`) {
		t.Error("含引号的字段必须包裹且内部引号翻倍")
	}
	if !strings.Contains(text, "第二行") {
		t.Error("字段内的换行不应丢失内容")
	}
	if !strings.HasSuffix(text, "\r\n") {
		t.Error("CSV 内容应以 CRLF 结束")
	}

	// 每一种 kind 都能导出且带 BOM
	for _, kind := range reportCSVKinds {
		rec := reportRequest(t, http.MethodGet, "/api/report/csv?kind="+kind, handleReportCSV, "")
		if rec.Code != http.StatusOK {
			t.Errorf("kind=%s 应导出成功, 实际 %d", kind, rec.Code)
			continue
		}
		body := rec.Body.Bytes()
		if !bytes.HasPrefix(body, []byte{0xEF, 0xBB, 0xBF}) {
			t.Errorf("kind=%s 缺少 BOM", kind)
		}
		// 测试环境没有植入体, 会话表只有表头; 其余类别都已播种数据
		lines := strings.Count(string(body[3:]), "\r\n")
		if lines < 1 {
			t.Errorf("kind=%s 至少应含表头行", kind)
		}
		if kind != "sessions" && lines < 2 {
			t.Errorf("kind=%s 应含表头与至少 1 行数据, 实际 %d 行", kind, lines)
		}
	}

	// 省略 kind 默认导出会话
	rec = reportRequest(t, http.MethodGet, "/api/report/csv", handleReportCSV, "")
	if rec.Code != http.StatusOK {
		t.Errorf("省略 kind 应成功, 实际 %d", rec.Code)
	}
	if !strings.Contains(string(rec.Body.Bytes()), "会话ID") {
		t.Error("省略 kind 时应默认导出会话表")
	}
	// 空白 kind 同样回落
	rec = reportRequest(t, http.MethodGet, "/api/report/csv?kind=%20", handleReportCSV, "")
	if rec.Code != http.StatusOK || !strings.Contains(string(rec.Body.Bytes()), "会话ID") {
		t.Errorf("空白 kind 应回落为会话表, 实际 %d", rec.Code)
	}

	// 中文数据在 CSV 中应可解析
	eventsCSV := reportRequest(t, http.MethodGet, "/api/report/csv?kind=events", handleReportCSV, "")
	if !strings.Contains(string(eventsCSV.Body.Bytes()), "登录") {
		t.Error("事件导出应包含中文动作")
	}
}

// firstLine 取首个 CRLF 之前的内容, 便于错误信息展示。
func firstLine(s string) string {
	if i := strings.Index(s, "\r\n"); i >= 0 {
		return s[:i]
	}
	return s
}

func TestReportCSVUnknownKind(t *testing.T) {
	openTestEnv(t)
	SetAuthEnabled(false)

	// 注意: "kind=sessions;drop" 这类含分号的查询会被 net/url 整段丢弃
	// (Go 1.17+ 的反分号分隔行为), Get("kind") 返回空串并回落为 sessions,
	// 因此这里只列出真正无法匹配的取值。
	for _, kind := range []string{"../../etc/passwd", "shells", "1", "sessions2", "creds"} {
		rec := reportRequest(t, http.MethodGet, "/api/report/csv?kind="+kind, handleReportCSV, "")
		if rec.Code != http.StatusBadRequest {
			t.Errorf("未知 kind %q 应返回 400, 实际 %d", kind, rec.Code)
		}
		if bytes.HasPrefix(rec.Body.Bytes(), []byte{0xEF, 0xBB, 0xBF}) {
			t.Errorf("kind=%s 的错误响应不得带 CSV BOM", kind)
		}
		var m map[string]interface{}
		if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
			t.Fatalf("kind=%s 错误响应应为 JSON: %v", kind, err)
		}
		if m["ok"] == true {
			t.Errorf("kind=%s 错误响应 ok 应为 false", kind)
		}
		if _, has := m["kinds"]; !has {
			t.Errorf("kind=%s 错误响应应列出可用 kind", kind)
		}
	}
}

// ---------------------------------------------------------------- HTML 导出

func TestReportHTMLSelfContainedAndEscaped(t *testing.T) {
	openTestEnv(t)
	SetAuthEnabled(false)
	seedReportData(t)

	inj := `<script>alert(1)</script>`
	eventLog("operator", "", inj, inj)
	storeAdd(Credential{
		Kind: KindCredential, ID: nextStoreID("cr"), SID: "s-x", CredK: 1,
		User: inj, Secret: `<img src=x onerror=alert(1)>`, Source: `"&'`, TS: 1700000400,
	})

	rec := reportRequest(t, http.MethodGet, "/api/report/html", handleReportHTML, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("应返回 200, 实际 %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Errorf("Content-Type 应为 HTML, 实际 %q", ct)
	}

	html := rec.Body.String()
	low := strings.ToLower(html)

	// 注入串不得以可执行形式出现
	if strings.Contains(html, inj) {
		t.Error("HTML 报告泄露了未转义的 <script> 注入串")
	}
	if strings.Contains(html, "<img src=x onerror=") {
		t.Error("HTML 报告泄露了未转义的 img onerror 注入串")
	}
	if !strings.Contains(html, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Error("script 注入串应被转义为 HTML 实体")
	}
	if !strings.Contains(html, "&lt;img src=x onerror=alert(1)&gt;") {
		t.Error("img 注入串应被转义为 HTML 实体")
	}
	if !strings.Contains(html, "&quot;&amp;&#39;") {
		t.Error("引号与 & 应被转义")
	}

	// 单文件: 无脚本、无外部资源
	if strings.Contains(low, "<script") {
		t.Error("报告不得包含 <script 标签")
	}
	if strings.Contains(low, "<link") || strings.Contains(low, "src=\"http") || strings.Contains(low, "href=\"http") {
		t.Error("报告不得引用外部资源")
	}
	if !strings.Contains(low, "<style>") {
		t.Error("CSS 应内嵌")
	}

	// 中文报告要素
	for _, want := range []string{"Rainmaker C2 活动报告", "统计概览", "监听器", "凭据", "下载文件", "截屏", "键盘记录", "事件日志", "生成时间"} {
		if !strings.Contains(html, want) {
			t.Errorf("HTML 报告缺少要素: %s", want)
		}
	}
	// 中文数据原样渲染
	if !strings.Contains(html, "报表,终版.xlsx") {
		t.Error("下载文件名应出现在报告中")
	}
	if !strings.Contains(html, "password=中文") {
		t.Error("键盘记录内容应出现在报告中")
	}
	// 空表占位 (本用例没有会话与监听器)
	if !strings.Contains(html, "（无数据）") {
		t.Error("空表应有占位提示")
	}
	// 统计卡片数字 (2 条凭据)
	if !strings.Contains(html, `<span class="n">2</span>`) {
		t.Error("统计卡片应反映真实条数")
	}
}

// ---------------------------------------------------------------- 鉴权

func TestReportEndpointsRequireAuth(t *testing.T) {
	openTestEnv(t)
	if err := flag.Set("auth", "on"); err != nil {
		t.Fatalf("flag.Set: %v", err)
	}
	SetAuthEnabled(true)

	cases := []struct {
		path string
		h    http.HandlerFunc
	}{
		{"/api/report/json", handleReportJSON},
		{"/api/report/html", handleReportHTML},
		{"/api/report/csv?kind=events", handleReportCSV},
	}
	for _, c := range cases {
		rec := reportRequest(t, http.MethodGet, c.path, c.h, "")
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s 未认证应返回 401, 实际 %d", c.path, rec.Code)
		}
		rec = reportRequest(t, http.MethodGet, c.path, c.h, "forged-token")
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s 伪造令牌应返回 401, 实际 %d", c.path, rec.Code)
		}
	}

	// 有效令牌放行
	tok, err := issueToken("boss", RoleAdmin)
	if err != nil {
		t.Fatalf("issueToken: %v", err)
	}
	for _, c := range cases {
		if rec := reportRequest(t, http.MethodGet, c.path, c.h, tok); rec.Code != http.StatusOK {
			t.Errorf("%s 有效令牌应放行, 实际 %d", c.path, rec.Code)
		}
	}

	// 旁路模式放行
	SetAuthEnabled(false)
	for _, c := range cases {
		if rec := reportRequest(t, http.MethodGet, c.path, c.h, ""); rec.Code != http.StatusOK {
			t.Errorf("%s 旁路模式应放行, 实际 %d", c.path, rec.Code)
		}
	}
}

// ---------------------------------------------------------------- 路由注册

func TestRegisterReportRoutes(t *testing.T) {
	openTestEnv(t)
	SetAuthEnabled(false)
	seedReportData(t)

	mux := http.NewServeMux()
	RegisterReportRoutes(mux)

	for _, path := range []string{"/api/report/json", "/api/report/html", "/api/report/csv?kind=sessions"} {
		rec := callAPI(t, mux, http.MethodGet, path, "", "")
		if rec.Code != http.StatusOK {
			t.Errorf("注册后的 %s 应返回 200, 实际 %d", path, rec.Code)
		}
	}
}
