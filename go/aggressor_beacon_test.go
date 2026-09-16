package main

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf16"
)

// fakeBridge 记录脚本下发的命令 / 输出, 用于验证 Beacon API 的映射
type fakeBridge struct {
	tasks   []string // "sid|cmd"
	printed []string // "sid|msg"
	info    map[string]map[string]string
}

func (f *fakeBridge) Task(sid, cmd string) error {
	f.tasks = append(f.tasks, sid+"|"+cmd)
	return nil
}
func (f *fakeBridge) Ids() []string { return []string{"B001"} }
func (f *fakeBridge) Info(sid string) map[string]string {
	if m, ok := f.info[sid]; ok {
		return m
	}
	return map[string]string{}
}
func (f *fakeBridge) Sleep(sid string, ms, jitter int) error { return nil }
func (f *fakeBridge) Exit(sid string) error                  { return nil }
func (f *fakeBridge) BOF(sid, path string, args []string) error {
	f.tasks = append(f.tasks, sid+"|bof "+path)
	return nil
}
func (f *fakeBridge) Print(msg string) { f.printed = append(f.printed, "|"+msg) }
func (f *fakeBridge) PrintSession(sid, msg string) {
	f.printed = append(f.printed, sid+"|"+msg)
}

// runBuiltin 直接调内置函数(绕过解析, 测映射逻辑本身)
func runBuiltin(t *testing.T, a *Aggressor, name string, args ...ScriptValue) ScriptValue {
	t.Helper()
	fn, ok := a.builtins[name]
	if !ok {
		t.Fatalf("内置函数 %s 未注册", name)
	}
	ctx := &ScriptCtx{env: map[string]ScriptValue{}, engine: a, visited: map[string]bool{}, lenient: true}
	v, err := fn(ctx, args)
	if err != nil {
		t.Fatalf("%s 执行失败: %v", name, err)
	}
	return v
}

// TestBeaconAPIMapping Beacon API 必须映射成真正下发的操作员命令 ——
// 这是"点了插件菜单项什么都不发生"那个问题的根因。
func TestBeaconAPIMapping(t *testing.T) {
	cases := []struct {
		fn      string
		args    []ScriptValue
		wantCmd string // 期望下发的命令(前缀匹配), 空表示只写输出不下发
	}{
		{"bshell", []ScriptValue{"B001", "whoami"}, "shell whoami"},
		{"brun", []ScriptValue{"B001", "C:\\Windows\\Temp\\x.exe", "/silent"}, "shell C:\\Windows\\Temp\\x.exe /silent"},
		{"bexecute_assembly", []ScriptValue{"B001", "C:\\a\\SharpGetInfo.exe"}, "execute-assembly C:\\a\\SharpGetInfo.exe"},
		{"bexecute_assembly", []ScriptValue{"B001", "C:\\a\\S.exe", "-a", "-b"}, "execute-assembly C:\\a\\S.exe -a -b"},
		{"bupload", []ScriptValue{"B001", "C:\\local\\a.exe"}, "upload C:\\local\\a.exe"},
		{"bupload", []ScriptValue{"B001", "C:\\local\\a.exe", "C:\\remote\\b.exe"}, "upload C:\\local\\a.exe C:\\remote\\b.exe"},
		{"bdownload", []ScriptValue{"B001", "C:\\secret.txt"}, "download C:\\secret.txt"},
		{"bcd", []ScriptValue{"B001", "C:\\Windows"}, "cd C:\\Windows"},
		{"bls", []ScriptValue{"B001", "C:\\"}, "ls C:\\"},
		{"brm", []ScriptValue{"B001", "C:\\x.txt"}, "rm C:\\x.txt"},
		{"bps", []ScriptValue{"B001"}, "ps"},
		{"bgetprivs", []ScriptValue{"B001"}, "token getprivs"},
		{"bgetsystem", []ScriptValue{"B001"}, "getsystem"},
		{"bhashdump", []ScriptValue{"B001"}, "hashdump"},
		{"bmimikatz", []ScriptValue{"B001", "sekurlsa::logonpasswords"}, "mimikatz sekurlsa::logonpasswords"},
		{"bnet", []ScriptValue{"B001", "user", "admin"}, "shell net user admin"},
		{"breg_queryv", []ScriptValue{"B001", `HKLM\SOFTWARE\X`}, `shell reg query HKLM\SOFTWARE\X`},
		{"bportscan", []ScriptValue{"B001", "10.0.0.1", "80,443"}, "portscan 10.0.0.1 80,443"},
		{"bshinject", []ScriptValue{"B001", "1234", "C:\\s.bin"}, "inject 1234 C:\\s.bin"},
		{"bjobs", []ScriptValue{"B001"}, "jobs"},
		{"bjobkill", []ScriptValue{"B001", "0"}, "jobkill 0"},
		{"btimestomp", nil, ""}, // 未注册项不该在这里(下面单独断言)
	}

	a := NewAggressor(nil)
	fb := &fakeBridge{}
	a.AttachC2(fb)

	for _, c := range cases {
		if c.fn == "btimestomp" {
			continue // 见 TestBeaconAPIUnregisteredStaysMissing
		}
		fb.tasks = nil
		runBuiltin(t, a, c.fn, c.args...)
		if len(fb.tasks) != 1 {
			t.Errorf("%s 应下发 1 条命令, 实得 %v", c.fn, fb.tasks)
			continue
		}
		got := strings.SplitN(fb.tasks[0], "|", 2)[1]
		if !strings.HasPrefix(got, c.wantCmd) {
			t.Errorf("%s -> %q, 期望以 %q 开头", c.fn, got, c.wantCmd)
		}
	}
}

// TestBeaconPowerShellEncoded powerpick / powershell_import 用 -EncodedCommand 下发,
// 不在目标机落脚本文件。断言编码内容能解回原文。
func TestBeaconPowerShellEncoded(t *testing.T) {
	a := NewAggressor(nil)
	fb := &fakeBridge{}
	a.AttachC2(fb)

	runBuiltin(t, a, "bpowerpick", "B001", "Get-Process | Select-Object -First 3")
	if len(fb.tasks) != 1 {
		t.Fatalf("bpowerpick 应下发命令, 实得 %v", fb.tasks)
	}
	cmd := strings.SplitN(fb.tasks[0], "|", 2)[1]
	if !strings.HasPrefix(cmd, "powershell ") || !strings.Contains(cmd, "-enc ") {
		t.Fatalf("应以 powershell -enc 下发, 实得 %q", cmd)
	}
	b64 := cmd[strings.Index(cmd, "-enc ")+5:]
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		t.Fatalf("base64 解不开: %v", err)
	}
	u := make([]uint16, len(raw)/2)
	for i := range u {
		u[i] = uint16(raw[i*2]) | uint16(raw[i*2+1])<<8
	}
	if got := string(utf16.Decode(u)); got != "Get-Process | Select-Object -First 3" {
		t.Fatalf("解码回原文不符: %q", got)
	}

	// powershell_import: 本地 .ps1 内容会被编码下发
	dir := t.TempDir()
	ps1 := filepath.Join(dir, "a.ps1")
	if err := os.WriteFile(ps1, []byte("Write-Host 'hi'"), 0o644); err != nil {
		t.Fatal(err)
	}
	fb.tasks = nil
	runBuiltin(t, a, "bpowershell_import", "B001", ps1)
	if len(fb.tasks) != 1 {
		t.Fatalf("bpowershell_import 应下发命令, 实得 %v", fb.tasks)
	}
	if c := strings.SplitN(fb.tasks[0], "|", 2)[1]; !strings.Contains(c, "-enc ") {
		t.Fatalf("应编码下发, 实得 %q", c)
	}

	// 本地文件不存在时退化为按路径执行(不静默跳过)
	fb.tasks = nil
	runBuiltin(t, a, "bpowershell_import", "B001", filepath.Join(dir, "nope.ps1"))
	if len(fb.tasks) != 1 || !strings.Contains(fb.tasks[0], "nope.ps1") {
		t.Fatalf("读不到脚本时应退化下发路径, 实得 %v", fb.tasks)
	}
}

// TestBeaconOutputGoesToSession blog/berror/binput 写进会话输出流, 不下发任务
func TestBeaconOutputGoesToSession(t *testing.T) {
	a := NewAggressor(nil)
	fb := &fakeBridge{}
	a.AttachC2(fb)

	runBuiltin(t, a, "blog", "B001", "开始收集")
	runBuiltin(t, a, "blog2", "B001", "第二条")
	runBuiltin(t, a, "berror", "B001", "出错了")
	runBuiltin(t, a, "binput", "B001", "hashdump")

	if len(fb.tasks) != 0 {
		t.Fatalf("输出类 API 不应下发任务, 实得 %v", fb.tasks)
	}
	if len(fb.printed) != 4 {
		t.Fatalf("应有 4 条输出, 实得 %v", fb.printed)
	}
	if fb.printed[0] != "B001|开始收集\r\n" {
		t.Fatalf("blog 输出不对: %q", fb.printed[0])
	}
	if !strings.HasPrefix(fb.printed[3], "B001|> ") {
		t.Fatalf("binput 应带 > 前缀: %q", fb.printed[3])
	}
}

// TestBeaconInfoGetters 取值类 API 从会话信息里取, 不下发任务
func TestBeaconInfoGetters(t *testing.T) {
	a := NewAggressor(nil)
	fb := &fakeBridge{info: map[string]map[string]string{
		"B001": {"host": "WIN10", "user": "admin", "pid": "1234", "arch": "x64", "internal": "10.0.0.5"},
	}}
	a.AttachC2(fb)

	for _, c := range []struct{ fn, want string }{
		{"bhost", "WIN10"}, {"buser", "admin"}, {"bpid", "1234"},
		{"barch", "x64"}, {"binfo", "WIN10"}, {"blocalip", "10.0.0.5"},
	} {
		got := toStr(runBuiltin(t, a, c.fn, "B001"))
		if got != c.want {
			t.Errorf("%s = %q, 期望 %q", c.fn, got, c.want)
		}
	}
	if len(fb.tasks) != 0 {
		t.Fatalf("取值类不应下发任务: %v", fb.tasks)
	}
}

// TestBeaconAPIUnregisteredStaysMissing 真做不到的(没有对应命令面)必须**不注册**,
// 继续走 missing 如实上报 —— 不假装支持。
func TestBeaconAPIUnregisteredStaysMissing(t *testing.T) {
	a := NewAggressor(nil)
	a.AttachC2(&fakeBridge{})
	for _, n := range []string{"bdcsync", "bblockdlls", "bstage", "bdllspawn", "bpassthehash"} {
		if _, ok := a.builtins[n]; ok {
			t.Errorf("%s 没有对应命令面, 不应注册(会假装支持)", n)
		}
	}
}

// TestRealPluginMenuUsesBeaconAPI 用真实插件菜单项验证端到端:
// 取 TaoWu/XieGongZi 里一个"一键收集"类菜单项跑一遍, 必须真的产生任务而不是被跳过。
func TestRealPluginMenuUsesBeaconAPI(t *testing.T) {
	root := `D:\Tools\1\tools\gui_other\Cobalt_Strike_4.7\plugin`
	main := filepath.Join(root, "TaoWu", "TaoWu.cna")
	if _, err := os.Stat(main); err != nil {
		t.Skip("插件目录不存在")
	}
	a := NewAggressor(nil)
	fb := &fakeBridge{}
	a.AttachC2(fb)
	if err := a.LoadFile(main); err != nil {
		t.Fatalf("加载失败: %v", err)
	}

	// 在整棵菜单树里找第一个"一键收集"类的可执行项
	var target *menuItem
	var walk func(items []*menuItem)
	walk = func(items []*menuItem) {
		for _, it := range items {
			if target != nil {
				return
			}
			if it.Kind != "sep" && it.Body != nil &&
				(strings.Contains(it.Name, "一键") || strings.Contains(it.Name, "收集")) {
				target = it
				return
			}
			walk(it.Children)
		}
	}
	for _, md := range a.Menus() {
		walk(md.Items)
	}
	if target == nil {
		t.Skip("该插件里没有名字含'一键/收集'的菜单项")
	}

	skipped, err := a.RunMenuItem(target, "B001")
	if err != nil {
		t.Fatalf("执行菜单项失败: %v", err)
	}
	if len(fb.tasks) == 0 {
		t.Fatalf("菜单项 %q 没有下发任何任务(被跳过: %v)", StripMnemonic(target.Name), skipped)
	}
	t.Logf("菜单项 %q -> 下发 %d 条命令, 跳过 %d 个函数", StripMnemonic(target.Name), len(fb.tasks), len(skipped))
	for i, c := range fb.tasks {
		if i >= 3 {
			break
		}
		t.Logf("   %s", c)
	}
}
