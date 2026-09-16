package main

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

/* 插件包管理 —— "自己选择加载"。
 *
 * 背景: CS 的第三方插件大多是 **loader 包**: 一个目录里放主 .cna + modules/ 子目录,
 * 主文件用 include(script_resource("modules/x.cna")) 把子模块拉进来
 * (LSTAR / OLa / TaoWu / 谢公子 / Ladon 全是这个结构)。所以"加载一个插件"的正确单位
 * 是**包**(目录或单个 .cna), 不是散落的文件。
 *
 * 选中的集合持久化在 data/plugins.json, 启动时自动恢复。
 * 加载方式是"重建引擎 + 重新加载选中项"(不是精细卸载) —— 引擎的菜单/命令/子函数
 * 会互相引用, 重建比反向拆除可靠得多, 行为也可预期。
 */

type pluginInfo struct {
	Name     string `json:"name"`     // 显示名(目录名或文件名)
	Path     string `json:"path"`     // 绝对路径
	Kind     string `json:"kind"`     // dir / file
	Main     string `json:"main"`     // 实际加载的入口 .cna
	Files    int    `json:"files"`    // 包内 .cna 数量
	Bytes    int64  `json:"bytes"`    // 包内 .cna 总字节
	Loaded   bool   `json:"loaded"`   // 当前是否已选中加载
	Menus    int    `json:"menus"`    // 加载后贡献的菜单项数(仅已加载时)
	Err      string `json:"err,omitempty"`
	HasMain  bool   `json:"has_main"` // 目录里找到了同名主文件
}

var pluginState = struct {
	mu       sync.Mutex
	root     string   // 插件根目录(--plugins-dir)
	selected []string // 选中的包路径
}{}

func pluginSetRoot(dir string) {
	pluginState.mu.Lock()
	pluginState.root = dir
	pluginState.mu.Unlock()
}

func pluginRootDir() string {
	pluginState.mu.Lock()
	defer pluginState.mu.Unlock()
	return pluginState.root
}

// pluginStateFile 选中项的持久化位置
func pluginStateFile() string { return filepath.Join(dataDir, "plugins.json") }

type pluginStateJSON struct {
	Root     string   `json:"root"`
	Selected []string `json:"selected"`
}

func pluginSaveState() {
	pluginState.mu.Lock()
	st := pluginStateJSON{Root: pluginState.root, Selected: append([]string{}, pluginState.selected...)}
	pluginState.mu.Unlock()
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(pluginStateFile(), b, 0o644)
}

func pluginLoadState() {
	b, err := os.ReadFile(pluginStateFile())
	if err != nil {
		return
	}
	var st pluginStateJSON
	if json.Unmarshal(b, &st) != nil {
		return
	}
	pluginState.mu.Lock()
	if pluginState.root == "" {
		pluginState.root = st.Root
	}
	pluginState.selected = st.Selected
	pluginState.mu.Unlock()
}

func pluginSelected() []string {
	pluginState.mu.Lock()
	defer pluginState.mu.Unlock()
	return append([]string{}, pluginState.selected...)
}

/* pluginResolveMain 决定一个包该加载哪个文件。
 *   文件  -> 它自己
 *   目录  -> 目录里与目录同名的 .cna(loader 主文件, LSTAR/LSTAR.cna);
 *            找不到就退而求其次: 目录里唯一的 .cna;
 *            再不行 -> 报错, 让操作员手动指定文件
 */
func pluginResolveMain(path string) (string, error) {
	st, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if !st.IsDir() {
		return path, nil
	}
	base := filepath.Base(path)
	same := filepath.Join(path, base+".cna")
	if _, err := os.Stat(same); err == nil {
		return same, nil
	}
	entries, _ := os.ReadDir(path)
	var cnas []string
	for _, e := range entries {
		if !e.IsDir() && strings.EqualFold(filepath.Ext(e.Name()), ".cna") {
			cnas = append(cnas, filepath.Join(path, e.Name()))
		}
	}
	if len(cnas) == 1 {
		return cnas[0], nil
	}
	if len(cnas) > 1 {
		// 常见约定: main.cna
		for _, p := range cnas {
			if strings.EqualFold(filepath.Base(p), "main.cna") {
				return p, nil
			}
		}
		return "", fmt.Errorf("目录 %s 里有 %d 个 .cna 但没有同名主文件, 请直接指定要加载的文件", base, len(cnas))
	}
	return "", fmt.Errorf("目录 %s 里没有 .cna", base)
}

/* pluginExternal 是"手工添加的脚本": 没有被当作包列出来的选中路径。
 * 操作员可以拿文件对话框直接挑任意 .cna(甚至单个模块文件、或包里的某个嵌套文件),
 * 这些路径同样会被持久化, 所以扫描时要能回显给 GUI —— 否则重启后界面上看不到它们,
 * 但引擎里其实是加载着的。
 *
 * 注意不能用"是否在插件根目录下"来过滤: 操作员完全可能选中
 * `plugin\OLa\OLa.cna` 这种**包内嵌套文件**(它不是 `plugin\OLa` 目录本身,
 * 不会出现在 plugins[] 里), 那样既不在 plugins[] 也不在 external[] 就成了黑洞。
 * 正确的判据是"是否与某个已列出的包路径完全相同"。 */
type pluginExternal struct {
	Path   string `json:"path"`
	Name   string `json:"name"`
	Exists bool   `json:"exists"`
	Files  int    `json:"files"`
	Bytes  int64  `json:"bytes"`
	Menus  int    `json:"menus"`
	Err    string `json:"err,omitempty"`
}

// pluginExternals 从选中集合里挑出没有被当作包列出的条目
func pluginExternals(root string, selected []string, a *Aggressor) []pluginExternal {
	out := []pluginExternal{}
	listed := map[string]bool{}
	if list, err := pluginScan(); err == nil {
		for _, p := range list {
			listed[p.Path] = true
		}
	}
	for _, p := range selected {
		if listed[p] {
			continue // 已作为包出现在 plugins[] 里
		}
		pe := pluginExternal{Path: p, Name: filepath.Base(p)}
		st, err := os.Stat(p)
		if err != nil {
			pe.Err = "路径不存在(可能被移动或删除)"
			out = append(out, pe)
			continue
		}
		pe.Exists = true
		if st.IsDir() {
			main, merr := pluginResolveMain(p)
			if merr != nil {
				pe.Err = merr.Error()
				out = append(out, pe)
				continue
			}
			_ = filepath.WalkDir(p, func(q string, d fs.DirEntry, err error) error {
				if err != nil || d == nil || d.IsDir() {
					return nil
				}
				if strings.EqualFold(filepath.Ext(d.Name()), ".cna") {
					pe.Files++
					if i, e := d.Info(); e == nil {
						pe.Bytes += i.Size()
					}
				}
				return nil
			})
			if a != nil {
				pe.Menus = pluginMenuCount(a, main)
			}
		} else {
			pe.Files = 1
			pe.Bytes = st.Size()
			if a != nil {
				pe.Menus = pluginMenuCount(a, p)
			}
		}
		out = append(out, pe)
	}
	_ = root
	return out
}

// pluginScan 扫描插件根, 列出所有候选包(目录 + 散装 .cna)
func pluginScan() ([]pluginInfo, error) {
	root := pluginRootDir()
	if root == "" {
		return nil, fmt.Errorf("未配置插件目录(启动加 --plugins-dir <目录>)")
	}
	if _, err := os.Stat(root); err != nil {
		return nil, fmt.Errorf("插件目录不存在: %s", root)
	}
	sel := map[string]bool{}
	for _, p := range pluginSelected() {
		sel[p] = true
	}

	out := []pluginInfo{}
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	// 逐个条目: 目录 = 一个包; .cna 文件 = 一个包
	dirs := []string{}
	loose := []string{}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".") {
			continue
		}
		if e.IsDir() {
			dirs = append(dirs, filepath.Join(root, e.Name()))
		} else if strings.EqualFold(filepath.Ext(e.Name()), ".cna") {
			loose = append(loose, filepath.Join(root, e.Name()))
		}
	}
	sort.Strings(dirs)
	sort.Strings(loose)

	for _, dir := range dirs {
		pi := pluginInfo{Name: filepath.Base(dir), Path: dir, Kind: "dir", Loaded: sel[dir]}
		main, merr := pluginResolveMain(dir)
		if merr == nil {
			pi.Main = main
			pi.HasMain = true
		} else {
			pi.Err = merr.Error()
		}
		// 统计包内 .cna
		_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d == nil || d.IsDir() {
				return nil
			}
			if strings.EqualFold(filepath.Ext(d.Name()), ".cna") {
				pi.Files++
				if st, e := d.Info(); e == nil {
					pi.Bytes += st.Size()
				}
			}
			return nil
		})
		if pi.Files == 0 {
			continue // 不含脚本的目录不列
		}
		out = append(out, pi)
	}
	for _, f := range loose {
		pi := pluginInfo{Name: filepath.Base(f), Path: f, Kind: "file", Main: f, Files: 1, Loaded: sel[f]}
		if st, err := os.Stat(f); err == nil {
			pi.Bytes = st.Size()
		}
		out = append(out, pi)
	}
	return out, nil
}

/* pluginMenuCount 统计某个包贡献了多少菜单项 —— 按 menuDef.Src 的来源文件归属。
 * Src 在解析期记录(顶层 popup/menu)与 includeFile 里被包含文件上, 所以
 * "这个包加载出多少项"是精确的, 不是全引擎总数。 */
func pluginMenuCount(a *Aggressor, mainFile string) int {
	if a == nil {
		return 0
	}
	dir := filepath.Dir(mainFile)
	inPkg := func(src string) bool {
		if src == "" {
			return false
		}
		if src == mainFile {
			return true
		}
		return strings.HasPrefix(src, dir+string(os.PathSeparator))
	}
	n := 0
	var walk func(items []*menuItem)
	walk = func(items []*menuItem) {
		for _, it := range items {
			n++
			walk(it.Children)
		}
	}
	for _, md := range a.Menus() {
		if inPkg(md.Src) {
			walk(md.Items)
		}
	}
	return n
}

/* pluginRebuild 重建引擎并加载: scripts/*.cna(自研脚本, 永远加载) + 选中的插件包。
 * 用重建而不是卸载: 菜单/命令/子函数互相引用, 重建可靠且行为可预期。 */
func pluginRebuild() error {
	pluginState.mu.Lock()
	root := pluginState.root
	sel := append([]string{}, pluginState.selected...)
	pluginState.mu.Unlock()

	a := NewAggressor(scriptOut)
	a.AttachC2(v2Bridge{})
	a.RegisterC2Builtins()
	a.RegisterBeaconAPIs()

	loadedPaths := []string{}
	// 1) 目录脚本(scripts/*.cna) —— 自研脚本与示例, 保持"总是加载"
	dir := filepath.Join(devRoot, "scripts")
	if entries, err := os.ReadDir(dir); err == nil {
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(strings.ToLower(e.Name()), ".cna") {
				loadedPaths = append(loadedPaths, filepath.Join(dir, e.Name()))
			}
		}
	}
	// 2) --scripts 附加
	pluginState.mu.Lock()
	extra := append([]string{}, pluginExtraScripts...)
	pluginState.mu.Unlock()
	loadedPaths = append(loadedPaths, extra...)

	// 3) 选中的插件包(目录 -> 解析主文件)
	for _, p := range sel {
		main, err := pluginResolveMain(p)
		if err != nil {
			logf("[!] 插件 %s 无法定位入口: %v", p, err)
			continue
		}
		loadedPaths = append(loadedPaths, main)
	}

	failed := 0
	for _, p := range loadedPaths {
		if err := a.LoadFile(p); err != nil {
			logf("[!] 脚本加载失败 %s: %v", p, err)
			failed++
			continue
		}
		logf("[*] 已加载脚本: %s", p)
	}

	gScriptMu.Lock()
	gAggressor = a
	gScriptMu.Unlock()
	if len(loadedPaths) > 0 {
		n := a.Fire("ready")
		logf("[*] 脚本 ready 钩子执行: %d 个 (共加载 %d 个文件, 失败 %d)",
			n, len(loadedPaths)-failed, failed)
	}
	_ = root
	return nil
}

// pluginExtraScripts 由 --scripts 传入
var pluginExtraScripts []string

// ---------------------------------------------------------------- HTTP

func handlePlugins(w http.ResponseWriter, r *http.Request) {
	list, err := pluginScan()
	if err != nil {
		writeJSON(w, map[string]interface{}{"ok": false, "error": err.Error(),
			"root": pluginRootDir()})
		return
	}
	a := aggressorInstance()
	for i := range list {
		if list[i].Loaded && list[i].HasMain {
			list[i].Menus = pluginMenuCount(a, list[i].Main)
		}
	}
	root := pluginRootDir()
	sel := pluginSelected()
	writeJSON(w, map[string]interface{}{
		"ok":       true,
		"root":     root,
		"plugins":  list,
		"external": pluginExternals(root, sel, a), // 手工挑的、不在插件根下的脚本
		"selected": sel,
		"loaded":   a.LoadedScripts(),
	})
}

/* handlePluginSet 设定"选中的插件包"并重建引擎。
 * body: {"paths": ["D:\\...\\LSTAR", "D:\\...\\TaoWu"]}
 * 传空数组 = 全部卸载(只留 scripts/*.cna)。 */
func handlePluginSet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, map[string]interface{}{"ok": false, "error": "仅支持 POST"})
		return
	}
	var req struct {
		Paths []string `json:"paths"`
		Root  string   `json:"root"`
	}
	if err := decodeJSONBody(r, &req); err != nil {
		writeJSON(w, map[string]interface{}{"ok": false, "error": err.Error()})
		return
	}
	if req.Root != "" {
		pluginSetRoot(req.Root)
	}
	// 规范化 + 存在性校验: 不让不存在的路径悄悄进持久化文件
	clean := []string{}
	for _, p := range req.Paths {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		abs, err := filepath.Abs(p)
		if err != nil {
			continue
		}
		if _, err := os.Stat(abs); err != nil {
			writeJSON(w, map[string]interface{}{"ok": false, "error": "路径不存在: " + abs})
			return
		}
		if _, err := pluginResolveMain(abs); err != nil {
			writeJSON(w, map[string]interface{}{"ok": false, "error": err.Error()})
			return
		}
		clean = append(clean, abs)
	}
	pluginState.mu.Lock()
	pluginState.selected = clean
	pluginState.mu.Unlock()
	pluginSaveState()
	if err := pluginRebuild(); err != nil {
		writeJSON(w, map[string]interface{}{"ok": false, "error": err.Error()})
		return
	}
	a := aggressorInstance()
	eventLog("system", "", "插件加载集已更新", fmt.Sprintf("%d 个包", len(clean)))
	writeJSON(w, map[string]interface{}{
		"ok":       true,
		"selected": clean,
		"loaded":   a.LoadedScripts(),
		"commands": a.CommandNames(),
	})
}
