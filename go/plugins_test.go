package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestPluginResolveMain 包入口定位:
//   目录里有与目录同名的 .cna -> 那是 loader 主文件(LSTAR/LSTAR.cna)
//   否则找 main.cna; 只有一个 .cna 就用它; 多个且无主文件 -> 明确报错
func TestPluginResolveMain(t *testing.T) {
	root := t.TempDir()

	mkdir := func(name string) string {
		p := filepath.Join(root, name)
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
		return p
	}
	write := func(p, body string) {
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// 1) 同名主文件优先
	d1 := mkdir("LSTAR")
	write(filepath.Join(d1, "LSTAR.cna"), "println(1);")
	write(filepath.Join(d1, "other.cna"), "println(2);")
	if got, err := pluginResolveMain(d1); err != nil || filepath.Base(got) != "LSTAR.cna" {
		t.Fatalf("同名主文件应优先, 实得 %q err=%v", got, err)
	}

	// 2) 退而求其次找 main.cna
	d2 := mkdir("XieGongZi")
	write(filepath.Join(d2, "main.cna"), "println(1);")
	write(filepath.Join(d2, "a.cna"), "println(2);")
	if got, err := pluginResolveMain(d2); err != nil || filepath.Base(got) != "main.cna" {
		t.Fatalf("应回退到 main.cna, 实得 %q err=%v", got, err)
	}

	// 3) 只有一个 .cna
	d3 := mkdir("PrivKit")
	write(filepath.Join(d3, "PrivCheck.cna"), "println(1);")
	if got, err := pluginResolveMain(d3); err != nil || filepath.Base(got) != "PrivCheck.cna" {
		t.Fatalf("唯一 .cna 应被采用, 实得 %q err=%v", got, err)
	}

	// 4) 多个 .cna 且目录名与文件名不同名 -> 必须报错(而不是瞎猜一个)
	d4 := mkdir("Ladon9.3.0_20221128")
	write(filepath.Join(d4, "Ladon.cna"), "println(1);")
	write(filepath.Join(d4, "Ladon-cn.cna"), "println(2);")
	if got, err := pluginResolveMain(d4); err == nil {
		t.Fatalf("无主文件且有多个 .cna 时应报错, 实得 %q", got)
	}

	// 5) 空目录
	d5 := mkdir("empty")
	if _, err := pluginResolveMain(d5); err == nil {
		t.Fatal("空目录应报错")
	}

	// 6) 直接给文件
	f := filepath.Join(root, "solo.cna")
	write(f, "println(1);")
	if got, err := pluginResolveMain(f); err != nil || got != f {
		t.Fatalf("文件应原样返回, 实得 %q err=%v", got, err)
	}

	// 7) 不存在的路径
	if _, err := pluginResolveMain(filepath.Join(root, "nope")); err == nil {
		t.Fatal("不存在的路径应报错")
	}
}

// TestPluginScanReal 真实插件目录扫描(目录=包 / 散装 .cna=包)
func TestPluginScanReal(t *testing.T) {
	root := `D:\Tools\1\tools\gui_other\Cobalt_Strike_4.7\plugin`
	if _, err := os.Stat(root); err != nil {
		t.Skip("插件目录不存在")
	}
	pluginState.mu.Lock()
	oldRoot := pluginState.root
	oldSel := pluginState.selected
	pluginState.root = root
	pluginState.selected = nil
	pluginState.mu.Unlock()
	defer func() {
		pluginState.mu.Lock()
		pluginState.root = oldRoot
		pluginState.selected = oldSel
		pluginState.mu.Unlock()
	}()

	list, err := pluginScan()
	if err != nil {
		t.Fatalf("扫描失败: %v", err)
	}
	if len(list) < 5 {
		t.Fatalf("应至少扫出 5 个候选包, 实得 %d", len(list))
	}
	byName := map[string]pluginInfo{}
	for _, p := range list {
		byName[p.Name] = p
	}
	lstar, ok := byName["LSTAR"]
	if !ok {
		t.Fatal("应扫出 LSTAR 包")
	}
	if !lstar.HasMain || filepath.Base(lstar.Main) != "LSTAR.cna" {
		t.Fatalf("LSTAR 入口定位错误: %+v", lstar)
	}
	if lstar.Files != 12 {
		t.Fatalf("LSTAR 包内应为 12 个 .cna, 实得 %d", lstar.Files)
	}
	if lstar.Bytes <= 0 {
		t.Fatal("应统计包内字节数")
	}
	// 无同名主文件的包必须带上可读的 err
	if ladon, ok := byName["Ladon9.3.0_20221128"]; ok {
		if ladon.HasMain || ladon.Err == "" {
			t.Fatalf("Ladon 包应标注无法定位入口: %+v", ladon)
		}
	}
	t.Logf("扫出 %d 个候选包: LSTAR(%d 文件) TaoWu(%d) OLa(%d)",
		len(list), lstar.Files, byName["TaoWu"].Files, byName["OLa"].Files)
}

// TestPluginExternalsClassify 选中集合的回显分类:
//   - 与某个已列出的包路径完全相同 -> 归 plugins[], 不进 external[]
//   - 包内嵌套文件(如 plugin\OLa\OLa.cna) -> 必须进 external[]
//     (曾经的实现按"是否在插件根目录下"过滤, 这类路径会两边都不在, 成了黑洞)
//   - 路径已失效 -> 进 external[] 且带 err
func TestPluginExternalsClassify(t *testing.T) {
	root := `D:\Tools\1\tools\gui_other\Cobalt_Strike_4.7\plugin`
	if _, err := os.Stat(root); err != nil {
		t.Skip("插件目录不存在")
	}
	pluginState.mu.Lock()
	oldRoot, oldSel := pluginState.root, pluginState.selected
	pluginState.root = root
	pluginState.selected = nil
	pluginState.mu.Unlock()
	defer func() {
		pluginState.mu.Lock()
		pluginState.root, pluginState.selected = oldRoot, oldSel
		pluginState.mu.Unlock()
	}()

	dirPkg := filepath.Join(root, "LSTAR")
	nested := filepath.Join(root, "OLa", "OLa.cna")
	gone := filepath.Join(root, "not-there", "x.cna")
	sel := []string{dirPkg, nested, gone}

	ext := pluginExternals(root, sel, nil)
	byPath := map[string]pluginExternal{}
	for _, e := range ext {
		byPath[e.Path] = e
	}
	if _, ok := byPath[dirPkg]; ok {
		t.Error("已作为包列出的目录不应出现在 external 里")
	}
	ne, ok := byPath[nested]
	if !ok {
		t.Fatal("包内嵌套文件必须出现在 external 里(否则既不在 plugins 也不在 external, 界面成黑洞)")
	}
	if !ne.Exists {
		t.Error("嵌套文件存在, exists 应为 true")
	}
	ge, ok := byPath[gone]
	if !ok {
		t.Fatal("失效路径必须在 external 里回显")
	}
	if ge.Exists || ge.Err == "" {
		t.Errorf("失效路径应 exists=false 且带 err: %+v", ge)
	}
	t.Logf("external 回显 %d 条: %s / %s", len(ext), ne.Name, ge.Name)
}

// TestPluginMenuCountBySrc 菜单项归属统计必须按来源文件算, 不是全引擎总数
func TestPluginMenuCountBySrc(t *testing.T) {
	root := `D:\Tools\1\tools\gui_other\Cobalt_Strike_4.7\plugin`
	mainA := filepath.Join(root, "LSTAR", "LSTAR.cna")
	mainB := filepath.Join(root, "TaoWu", "TaoWu.cna")
	if _, err := os.Stat(mainA); err != nil {
		t.Skip("插件目录不存在")
	}
	a := NewAggressor(nil)
	if err := a.LoadFile(mainA); err != nil {
		t.Fatalf("加载 LSTAR 失败: %v", err)
	}
	if err := a.LoadFile(mainB); err != nil {
		t.Fatalf("加载 TaoWu 失败: %v", err)
	}
	nA := pluginMenuCount(a, mainA)
	nB := pluginMenuCount(a, mainB)
	if nA <= 0 || nB <= 0 {
		t.Fatalf("两个包都应统计出菜单项: LSTAR=%d TaoWu=%d", nA, nB)
	}
	// 各自只算自己那份: 两个数字都必须小于总数
	total := 0
	for _, md := range a.Menus() {
		var walk func(items []*menuItem)
		walk = func(items []*menuItem) {
			for _, it := range items {
				total++
				walk(it.Children)
			}
		}
		walk(md.Items)
	}
	if nA >= total || nB >= total {
		t.Fatalf("归属统计串味了: LSTAR=%d TaoWu=%d 总数=%d", nA, nB, total)
	}
	t.Logf("LSTAR=%d 项 / TaoWu=%d 项 / 引擎总数=%d", nA, nB, total)
}
