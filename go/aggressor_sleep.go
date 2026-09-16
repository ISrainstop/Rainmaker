package main

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

/* registerSleepBuiltins 补齐 Sleep 标准库与原版脚本高频依赖的数据类函数。
 *
 * 这些函数在原版 default.cna 的加载期就会被调用(菜单体在加载期执行),
 * 实测缺一个就少一块菜单。Cobalt Strike 客户端私有 UI 函数
 * (toolbar / colorPanel / insert_component / openXXXDialog 等)属于客户端实现,
 * 本引擎不假装支持: 它们走宽容模式记入"未实现函数"诊断。
 */
func (a *Aggressor) registerSleepBuiltins() {
	// concat(@a, @b, ...) —— 合并数组
	a.builtins["concat"] = func(c *ScriptCtx, args []ScriptValue) (ScriptValue, error) {
		out := []ScriptValue{}
		for _, v := range args {
			switch t := v.(type) {
			case []ScriptValue:
				out = append(out, t...)
			case nil:
			default:
				out = append(out, v)
			}
		}
		return out, nil
	}

	// reverse(@a)
	a.builtins["reverse"] = func(c *ScriptCtx, args []ScriptValue) (ScriptValue, error) {
		arr := argArray(args, 0)
		out := make([]ScriptValue, 0, len(arr))
		for i := len(arr) - 1; i >= 0; i-- {
			out = append(out, arr[i])
		}
		return out, nil
	}

	// sorta(@a) —— 默认顺序排序
	a.builtins["sorta"] = func(c *ScriptCtx, args []ScriptValue) (ScriptValue, error) {
		arr := append([]ScriptValue{}, argArray(args, 0)...)
		sort.SliceStable(arr, func(i, j int) bool { return compareValues(arr[i], arr[j]) < 0 })
		return arr, nil
	}

	// sort({ 比较器 }, @a) —— 比较器返回 <=> 风格的三值
	a.builtins["sort"] = func(c *ScriptCtx, args []ScriptValue) (ScriptValue, error) {
		if len(args) == 1 {
			arr := append([]ScriptValue{}, argArray(args, 0)...)
			sort.SliceStable(arr, func(i, j int) bool { return compareValues(arr[i], arr[j]) < 0 })
			return arr, nil
		}
		cmp := args[0]
		arr := append([]ScriptValue{}, argArray(args, 1)...)
		var sortErr error
		sort.SliceStable(arr, func(i, j int) bool {
			r, err := invokeCallable(cmp, c, []ScriptValue{arr[i], arr[j]})
			if err != nil {
				sortErr = err
				return false
			}
			return toInt(r) < 0
		})
		if sortErr != nil {
			// 比较器是脚本自定义函数时, 出错降级为默认排序而不是炸掉整个排序
			sort.SliceStable(arr, func(i, j int) bool { return compareValues(arr[i], arr[j]) < 0 })
		}
		return arr, nil
	}

	// map({ ... }, @a) / filter({ ... }, @a)
	a.builtins["map"] = func(c *ScriptCtx, args []ScriptValue) (ScriptValue, error) {
		if len(args) < 2 {
			return []ScriptValue{}, nil
		}
		fn := args[0]
		src := argArray(args, 1)
		out := make([]ScriptValue, 0, len(src))
		for _, v := range src {
			r, err := invokeCallable(fn, c, []ScriptValue{v})
			if err != nil {
				return nil, err
			}
			out = append(out, r)
		}
		return out, nil
	}
	a.builtins["filter"] = func(c *ScriptCtx, args []ScriptValue) (ScriptValue, error) {
		if len(args) < 2 {
			return []ScriptValue{}, nil
		}
		fn := args[0]
		src := argArray(args, 1)
		out := []ScriptValue{}
		for _, v := range src {
			r, err := invokeCallable(fn, c, []ScriptValue{v})
			if err != nil {
				return nil, err
			}
			if truthy(r) {
				out = append(out, v)
			}
		}
		return out, nil
	}

	// keys($hash) / values($hash, @keylist)
	a.builtins["keys"] = func(c *ScriptCtx, args []ScriptValue) (ScriptValue, error) {
		if m, ok := args[0].(map[string]ScriptValue); ok {
			ks := make([]string, 0, len(m))
			for k := range m {
				ks = append(ks, k)
			}
			sort.Strings(ks)
			out := make([]ScriptValue, 0, len(ks))
			for _, k := range ks {
				out = append(out, k)
			}
			return out, nil
		}
		return []ScriptValue{}, nil
	}
	a.builtins["values"] = func(c *ScriptCtx, args []ScriptValue) (ScriptValue, error) {
		m, ok := args[0].(map[string]ScriptValue)
		if !ok {
			return []ScriptValue{}, nil
		}
		out := []ScriptValue{}
		if len(args) > 1 {
			for _, k := range argArray(args, 1) {
				if v, ok := m[toStr(k)]; ok {
					out = append(out, v)
				} else {
					out = append(out, "")
				}
			}
			return out, nil
		}
		ks := make([]string, 0, len(m))
		for k := range m {
			ks = append(ks, k)
		}
		sort.Strings(ks)
		for _, k := range ks {
			out = append(out, m[k])
		}
		return out, nil
	}

	// copy($x) —— 浅拷贝, 避免脚本改到共享结构
	a.builtins["copy"] = func(c *ScriptCtx, args []ScriptValue) (ScriptValue, error) {
		if len(args) == 0 {
			return "", nil
		}
		switch t := args[0].(type) {
		case []ScriptValue:
			out := make([]ScriptValue, len(t))
			copy(out, t)
			return out, nil
		case map[string]ScriptValue:
			out := make(map[string]ScriptValue, len(t))
			for k, v := range t {
				out[k] = v
			}
			return out, nil
		}
		return args[0], nil
	}

	// pop / shift / unshift / push 家族
	a.builtins["pop"] = func(c *ScriptCtx, args []ScriptValue) (ScriptValue, error) {
		arr := argArray(args, 0)
		if len(arr) == 0 {
			return "", nil
		}
		return arr[len(arr)-1], nil
	}
	a.builtins["shift"] = func(c *ScriptCtx, args []ScriptValue) (ScriptValue, error) {
		arr := argArray(args, 0)
		if len(arr) == 0 {
			return "", nil
		}
		return arr[0], nil
	}
	a.builtins["unshift"] = func(c *ScriptCtx, args []ScriptValue) (ScriptValue, error) {
		if len(args) < 2 {
			return []ScriptValue{}, nil
		}
		out := []ScriptValue{args[1]}
		out = append(out, argArray(args, 0)...)
		return out, nil
	}

	// iff(cond, a, b)
	a.builtins["iff"] = func(c *ScriptCtx, args []ScriptValue) (ScriptValue, error) {
		if len(args) < 3 {
			return "", nil
		}
		if truthy(args[0]) {
			return args[1], nil
		}
		return args[2], nil
	}

	// 时间戳格式化: 原版脚本用它拼时间戳前缀
	a.builtins["dstamp"] = func(c *ScriptCtx, args []ScriptValue) (ScriptValue, error) {
		ms := int64(0)
		if len(args) > 0 {
			ms = toInt(args[0])
		}
		t := msToTime(ms)
		return t.Format("2006-01-02 15:04:05"), nil
	}
	a.builtins["tstamp"] = func(c *ScriptCtx, args []ScriptValue) (ScriptValue, error) {
		ms := int64(0)
		if len(args) > 0 {
			ms = toInt(args[0])
		}
		t := msToTime(ms)
		return t.Format("15:04:05"), nil
	}
	a.builtins["formatDate"] = func(c *ScriptCtx, args []ScriptValue) (ScriptValue, error) {
		layout := "2006-01-02 15:04:05"
		if len(args) > 0 {
			layout = javaDateToGoLayout(toStr(args[0]))
		}
		return time.Now().Format(layout), nil
	}
	a.builtins["ticks"] = a.builtins["ticks"] // 已在核心内置里, 保持原样

	// 客户端标识: 本引擎没有 IRC 同伴概念, 返回操作员名占位
	a.builtins["mynick"] = func(c *ScriptCtx, args []ScriptValue) (ScriptValue, error) {
		return "operator", nil
	}

	// beacons() / isactive($bid) —— 走 C2 桥接, 是真实会话数据
	a.builtins["beacons"] = func(c *ScriptCtx, args []ScriptValue) (ScriptValue, error) {
		b := a.bridge()
		if b == nil {
			return []ScriptValue{}, nil
		}
		out := []ScriptValue{}
		for _, id := range b.Ids() {
			out = append(out, id)
		}
		return out, nil
	}
	a.builtins["isactive"] = func(c *ScriptCtx, args []ScriptValue) (ScriptValue, error) {
		if len(args) == 0 {
			return int64(0), nil
		}
		b := a.bridge()
		if b == nil {
			return int64(0), nil
		}
		want := toStr(args[0])
		for _, id := range b.Ids() {
			if id == want {
				return int64(1), nil
			}
		}
		return int64(0), nil
	}
	a.builtins["beacon_remote_exploits"] = func(c *ScriptCtx, args []ScriptValue) (ScriptValue, error) {
		return []ScriptValue{}, nil
	}
}

// argArray 取第 idx 个参数并按数组处理
func argArray(args []ScriptValue, idx int) []ScriptValue {
	if idx >= len(args) {
		return nil
	}
	switch t := args[idx].(type) {
	case []ScriptValue:
		return t
	case nil:
		return nil
	default:
		return []ScriptValue{t}
	}
}

// compareValues 数字优先, 否则按字符串比较
func compareValues(a, b ScriptValue) int {
	as, bs := toStr(a), toStr(b)
	if an, aok := numericValue(a); aok {
		if bn, bok := numericValue(b); bok {
			switch {
			case an < bn:
				return -1
			case an > bn:
				return 1
			}
			return 0
		}
	}
	return strings.Compare(as, bs)
}

func numericValue(v ScriptValue) (float64, bool) {
	switch t := v.(type) {
	case int64:
		return float64(t), true
	case float64:
		return t, true
	case string:
		if t == "" {
			return 0, false
		}
		var f float64
		n, err := fmt.Sscanf(t, "%g", &f)
		if err != nil || n != 1 {
			return 0, false
		}
		// 拒绝把 "abc" 之类当成 0
		rest := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(t), fmt.Sprintf("%g", f)))
		if rest != "" {
			return 0, false
		}
		return f, true
	}
	return 0, false
}

// msToTime 0 表示"现在"
func msToTime(ms int64) time.Time {
	if ms <= 0 {
		return time.Now()
	}
	if ms > 1e12 { // 毫秒
		return time.UnixMilli(ms)
	}
	return time.Unix(ms, 0)
}

// javaDateToGoLayout 把 Java 风格日期格式转成 Go layout(仅覆盖常用记号)
func javaDateToGoLayout(f string) string {
	repl := []struct{ from, to string }{
		{"yyyy", "2006"}, {"yy", "06"},
		{"MM", "01"}, {"dd", "02"},
		{"HH", "15"}, {"mm", "04"}, {"ss", "05"},
		{"Z", "-0700"}, {"SSS", "000"},
	}
	out := f
	for _, r := range repl {
		out = strings.ReplaceAll(out, r.from, r.to)
	}
	if out == "" {
		return "2006-01-02 15:04:05"
	}
	return out
}
