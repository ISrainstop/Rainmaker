package main

import (
	"os"
	"testing"
)

// countItems 递归统计菜单项
func countItems(items []*menuItem) int {
	n := 0
	for _, it := range items {
		n++
		n += countItems(it.Children)
	}
	return n
}

// TestLoadOriginalDefaultCna 用原版 Cobalt Strike default.cna 实测解析+加载。
// 这是"能不能加载原版 cna"的硬证据: 解析失败会直接 Fatal。
func TestLoadOriginalDefaultCna(t *testing.T) {
	path := `D:\csdev-c2\docs\_cs47_extract\scripts\default.cna`
	if _, err := os.Stat(path); err != nil {
		t.Skip("原版 default.cna 不在预期位置")
	}
	var printed []string
	a := NewAggressor(func(s string) { printed = append(printed, s) })
	if err := a.LoadFile(path); err != nil {
		t.Fatalf("加载原版 default.cna 失败: %v", err)
	}

	menus := a.Menus()
	total := 0
	for _, md := range menus {
		total += countItems(md.Items)
	}
	t.Logf("popup 数=%d 菜单项总数=%d 菜单栏=%d 命令=%d 钩子=%d",
		len(menus), total, len(a.menubar), len(a.CommandNames()), len(a.handlers))
	for i, mb := range a.menubar {
		if i < 3 {
			t.Logf("  menubar: %s -> %s", mb.Label, mb.ID)
		}
	}
	diag := a.Diag()
	t.Logf("加载期诊断 %d 条", len(diag))
	for i, d := range diag {
		if i < 10 {
			t.Logf("  %s", d)
		}
	}
	if len(menus) == 0 {
		t.Fatal("没有解析到任何 popup")
	}
	if total == 0 {
		t.Fatal("没有注册到任何菜单项")
	}
}

// TestLoadBundledExampleCna 保证扩展语法后自研示例脚本仍然可用(向后兼容)
func TestLoadBundledExampleCna(t *testing.T) {
	path := `D:\csdev-c2\scripts\example.cna`
	if _, err := os.Stat(path); err != nil {
		t.Skip("示例脚本不存在")
	}
	a := NewAggressor(nil)
	if err := a.LoadFile(path); err != nil {
		t.Fatalf("加载 example.cna 失败: %v", err)
	}
	if len(a.CommandNames()) < 3 {
		t.Fatalf("命令注册不全: %v", a.CommandNames())
	}
	if len(a.Menus()) == 0 {
		t.Fatal("菜单没有注册")
	}
	// 触发 ready 钩子, 确认子集脚本的求值链路仍然正常
	if n := a.Fire("ready"); n != 1 {
		t.Fatalf("ready 钩子触发次数=%d, 期望 1", n)
	}
	t.Logf("命令=%v 菜单=%d 诊断=%d", a.CommandNames(), len(a.Menus()), len(a.Diag()))
}

// TestSleepInterpolation 验证 $+ 无缝拼接与插值(原版脚本高频依赖)
func TestSleepInterpolation(t *testing.T) {
	a := NewAggressor(nil)
	if err := a.Load(`
		sub t {
			$x = "Hello World";
			$y = 3;
			return "$x $+ $y";
		}
	`, "interp-test"); err != nil {
		t.Fatalf("加载失败: %v", err)
	}
	got, err := invokeCallable("t", &ScriptCtx{env: map[string]ScriptValue{}, engine: a, visited: map[string]bool{}}, nil)
	if err != nil {
		t.Fatalf("调用失败: %v", err)
	}
	if toStr(got) != "Hello World3" {
		t.Fatalf("插值结果 %q, 期望 \"Hello World3\"", toStr(got))
	}
}

// TestStripMnemonic 助记符剥离: GUI 显示名与脚本名必须能对上
func TestStripMnemonic(t *testing.T) {
	cases := []struct{ in, want string }{
		{"&Interact", "Interact"},
		{"E&xport Data", "Export Data"},
		{"Make T&oken", "Make Token"},
		{"a && b", "a & b"},
		{"无&助记符", "无助记符"},
		{"", ""},
	}
	for _, c := range cases {
		if got := StripMnemonic(c.in); got != c.want {
			t.Errorf("StripMnemonic(%q) = %q, 期望 %q", c.in, got, c.want)
		}
	}
}

// TestFindAndRunMenuItem 插件菜单项的执行链路:
// LTS 侧按 (popup, 显示名) 定位菜单项 -> 跑 body -> 如实回报被跳过的未实现函数。
func TestFindAndRunMenuItem(t *testing.T) {
	a := NewAggressor(nil)
	err := a.Load(`
		popup beacon_bottom {
			menu "插件" {
				item "&Do Thing" {
					println("ran " . $1);
					cs_client_only_api("x");
				}
				separator();
				item "纯脚本项" {
					println("pure");
				}
			}
		}
	`, "menu-test")
	if err != nil {
		t.Fatalf("加载失败: %v", err)
	}

	// 定位: 用剥掉助记符的名字(也就是 GUI 显示的名字)
	it := a.FindMenuItem("beacon_bottom", "Do Thing")
	if it == nil {
		t.Fatal("按显示名找不到菜单项")
	}
	if a.FindMenuItem("beacon_bottom", "不存在") != nil {
		t.Fatal("不存在的菜单项不应被找到")
	}

	// 执行: 跳过未实现的 CS 客户端 API, 并把它回报出来
	skipped, err := a.RunMenuItem(it, "S1")
	if err != nil {
		t.Fatalf("菜单项执行失败: %v", err)
	}
	if len(skipped) != 1 || skipped[0] != "cs_client_only_api" {
		t.Fatalf("应回报 1 个被跳过的函数, 实得 %v", skipped)
	}

	// 纯脚本项不应有任何跳过
	it2 := a.FindMenuItem("beacon_bottom", "纯脚本项")
	if it2 == nil {
		t.Fatal("找不到纯脚本菜单项")
	}
	skipped2, err := a.RunMenuItem(it2, "S1")
	if err != nil || len(skipped2) != 0 {
		t.Fatalf("纯脚本项不应报错或被跳过: err=%v skipped=%v", err, skipped2)
	}

	// 分隔线不算可执行项
	names := a.MenuNames("beacon_bottom")
	if len(names) != 2 {
		t.Fatalf("可执行菜单项应为 2 个, 实得 %v", names)
	}
}
