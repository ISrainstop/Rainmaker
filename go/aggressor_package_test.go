package main

import (
	"os"
	"strings"
	"path/filepath"
	"testing"
)

// findMenuItemByName 在引擎的菜单树里按名字找一个菜单项(忽略 & 助记符)
func findMenuItemByName(a *Aggressor, parent, name string) *menuItem {
	var found *menuItem
	var walk func(items []*menuItem)
	walk = func(items []*menuItem) {
		for _, it := range items {
			if found != nil {
				return
			}
			if StripMnemonic(it.Name) == name {
				found = it
				return
			}
			walk(it.Children)
		}
	}
	for _, md := range a.Menus() {
		if parent != "" && md.Parent != parent && md.Name != parent {
			continue
		}
		walk(md.Items)
	}
	return found
}

func countMenuLeaves(items []*menuItem) int {
	n := 0
	for _, it := range items {
		if it.Kind != "menu" && !it.IsSepKind() {
			n++
		}
		n += countMenuLeaves(it.Children)
	}
	return n
}

// TestScriptResourceBaseIsTopScript script_resource() 的基准必须是**顶层主脚本**所在目录,
// 不是"当前正在执行的那个文件"所在目录。
//
// 证据来自真实插件: TaoWu/modules/credential access.cna(注意它在 modules/ 里)写的是
//   include(script_resource("modules/RdpThief.cna"));
// 目标是 TaoWu/modules/RdpThief.cna。若按"当前文件目录"解析会变成
// modules/modules/RdpThief.cna(不存在), 这条 include 就会失败。
// 同理 LSTAR/modules/AuthMaintain.cna 里的 script_resource("/scripts/...")
// 指向的是包根下的 LSTAR/scripts/, 不是 LSTAR/modules/scripts/。
func TestScriptResourceBaseIsTopScript(t *testing.T) {
	root := `D:\Tools\1\tools\gui_other\Cobalt_Strike_4.7\plugin`
	taowu := filepath.Join(root, "TaoWu", "TaoWu.cna")
	if _, err := os.Stat(taowu); err != nil {
		t.Skip("插件目录不存在")
	}
	a := NewAggressor(nil)
	if err := a.LoadFile(taowu); err != nil {
		t.Fatalf("加载 TaoWu 失败: %v", err)
	}

	// 嵌套 include 必须成功(modules/credential access.cna -> modules/RdpThief.cna)
	nested := filepath.Join(root, "TaoWu", "modules", "RdpThief.cna")
	found := false
	for _, p := range a.LoadedScripts() {
		if p == nested {
			found = true
			break
		}
	}
	if !found {
		var diagTail []string
		d := a.Diag()
		if len(d) > 6 {
			d = d[len(d)-6:]
		}
		diagTail = append(diagTail, d...)
		t.Fatalf("嵌套 include 未生效(基准目录错?): 期望加载 %s\n诊断尾部: %v", nested, diagTail)
	}

	// 不应再出现 "include 打不开 ...modules\\modules\\..." 这类路径
	for _, l := range a.Diag() {
		if strings.Contains(l, "modules"+string(os.PathSeparator)+"modules") {
			t.Fatalf("script_resource 基准仍然错(出现 modules/modules): %s", l)
		}
	}
	t.Logf("TaoWu 共加载 %d 个文件, 嵌套 include 命中 RdpThief.cna", len(a.LoadedScripts()))
}

// TestLoaderPackageInclude 真实第三方插件包是 loader 模式:
// 只加载主文件(如 LSTAR/LSTAR.cna), 它靠 include(script_resource("modules/*.cna"))
// 把子模块拉进来。这条测试验证:
//   - include 与 script_resource 都工作
//   - 被包含的模块菜单挂在主菜单下(不是变成一堆顶层 popup)
//   - 子模块里的 on/command 也注册了
func TestLoaderPackageInclude(t *testing.T) {
	root := `D:\Tools\1\tools\gui_other\Cobalt_Strike_4.7\plugin`
	if _, err := os.Stat(root); err != nil {
		t.Skip("插件目录不存在")
	}

	cases := []struct {
		mainFile  string // 相对 plugin 根
		mainMenu  string // 期望存在的菜单名(剥助记符后)
		minKids   int    // 该菜单下至少多少个子菜单
	}{
		{filepath.Join("LSTAR", "LSTAR.cna"), "LSTAR", 5},
		{filepath.Join("TaoWu", "TaoWu.cna"), "梼杌", 5},
		{filepath.Join("OLa", "OLa.cna"), "OLa(欧拉)", 5},
	}

	for _, c := range cases {
		main := filepath.Join(root, c.mainFile)
		if _, err := os.Stat(main); err != nil {
			t.Logf("跳过(不存在): %s", c.mainFile)
			continue
		}
		a := NewAggressor(nil)
		if err := a.LoadFile(main); err != nil {
			t.Errorf("%s 加载失败: %v", c.mainFile, err)
			continue
		}

		it := findMenuItemByName(a, "beacon_bottom", c.mainMenu)
		if it == nil {
			t.Errorf("%s: 菜单 %q 没建出来", c.mainFile, c.mainMenu)
			continue
		}
		kids := 0
		for _, k := range it.Children {
			if k.Kind == "menu" {
				kids++
			}
		}
		if kids < c.minKids {
			t.Errorf("%s: 菜单 %q 下只有 %d 个子菜单, 期望至少 %d (include 没生效?)",
				c.mainFile, c.mainMenu, kids, c.minKids)
		}
		leaves := countMenuLeaves(it.Children)
		if leaves < 10 {
			t.Errorf("%s: 菜单 %q 下只有 %d 个可执行项, include 的模块似乎没进来", c.mainFile, c.mainMenu, leaves)
		}
		t.Logf("%s -> 菜单 %q: %d 个子菜单 / %d 个叶子项 / 共加载 %d 个文件",
			c.mainFile, c.mainMenu, kids, leaves, len(a.LoadedScripts()))
	}
}
