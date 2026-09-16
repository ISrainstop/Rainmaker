package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// TestLoadPluginCorpus 用真实第三方 .cna 插件做批量兼容性压测。
// 目录里是 78 个实战插件(Ladon / LSTAR / OLa / TaoWu / XieGongZi / CrossC2 等),
// 每一个都比自研示例复杂得多, 是"能不能吃原版生态"的硬指标。
func TestLoadPluginCorpus(t *testing.T) {
	root := `D:\Tools\1\tools\gui_other\Cobalt_Strike_4.7\plugin`
	if _, err := os.Stat(root); err != nil {
		t.Skip("插件目录不存在")
	}

	var files []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if !d.IsDir() && strings.HasSuffix(strings.ToLower(d.Name()), ".cna") {
			files = append(files, p)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("遍历失败: %v", err)
	}
	sort.Strings(files)

	type fail struct {
		path string
		err  string
	}
	var oks []string
	var fails []fail

	for _, p := range files {
		a := NewAggressor(nil)
		if lerr := a.LoadFile(p); lerr != nil {
			fails = append(fails, fail{path: relPath(root, p), err: lerr.Error()})
			continue
		}
		oks = append(oks, relPath(root, p))
	}

	t.Logf("==== 插件语料库加载结果: %d/%d 成功 ====", len(oks), len(files))
	if len(fails) > 0 {
		t.Logf("---- 失败 %d 个 ----", len(fails))
		limit := len(fails)
		if limit > 40 {
			limit = 40
		}
		for _, f := range fails[:limit] {
			t.Logf("  [X] %s\n        %s", f.path, f.err)
		}
	}
	// 错误归因: 按"错误文本特征"聚合, 方便定位缺哪类语法
	agg := map[string][]string{}
	for _, f := range fails {
		key := errSignature(f.err)
		agg[key] = append(agg[key], f.path)
	}
	keys := make([]string, 0, len(agg))
	for k := range agg {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return len(agg[keys[i]]) > len(agg[keys[j]]) })
	t.Logf("---- 失败归因(按频次) ----")
	for _, k := range keys {
		t.Logf("  %2d 个  %s", len(agg[k]), k)
	}
}

func relPath(root, p string) string {
	r, err := filepath.Rel(root, p)
	if err != nil {
		return p
	}
	return r
}

// errSignature 把错误信息归并成可聚合的特征串
func errSignature(e string) string {
	switch {
	case strings.Contains(e, "无法识别的字符"):
		if i := strings.Index(e, "无法识别的字符"); i >= 0 {
			return e[i:]
		}
	case strings.Contains(e, "无法解析的表达式"):
		if i := strings.Index(e, "无法解析的表达式"); i >= 0 {
			return e[i:]
		}
	case strings.Contains(e, "期望"):
		if i := strings.Index(e, "期望"); i >= 0 {
			return e[i:]
		}
	case strings.Contains(e, "未闭合"):
		return "字符串未闭合"
	}
	return e
}
