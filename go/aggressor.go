// csdev :: aggressor.go  --  Aggressor 风格脚本引擎 (Sleep 语言实用子集)
//
// 对标 Cobalt Strike 的 Aggressor Script。目标是**能直接吃下原版 .cna**,
// 而不是要求脚本改写成本引擎的子集。
//
// 已支持
//   on <event> { ... }          事件钩子 (ready / beacon_initial / beacon_output ...)
//   command / alias / popup / menu / item      命令与菜单树
//   sub 名($a,$b) { ... }       自定义函数; set NAME { ... } 同样按函数处理
//   foreach $x (集合) / foreach $k => $v (哈希)  跳过重复元素的原版语义
//   for (init; cond; incr) / while / if/else if/else / break / continue
//   local('$a $b') / ($a,$b) = @_ / @arr = ... / $x .= ... / $i++
//   双引号插值 "$x $+ $y"(无缝拼接)、"$[5]pid"、\$x 与 \@x 引用标记
//   @(a,b) / %(k => v) / $h['k'] / $1[0]['x'] / $h['k'] = v
//   { ... } 匿名函数 / lambda({...}, \$x) / $fn(...) / [$obj method: a]
//   item("名", { ... }) 与 item "名" { ... } 混用 (菜单体在加载期求值)
//   中缀运算符: == != < > <= >= eq ne lt gt le ge isa ismatch iswm isin in !is <=>
//   前缀命令形式 -isadmin $bid、一元 !-isactive、^class.Name、command ? { }
//
// 未支持 (刻意留空, 避免"看起来支持其实跑不通")
//   Sleep 的对象系统 ($foo->bar)、try/catch、反射 API (callmethod/getObjectMethods)
//   以及 Cobalt Strike 客户端私有 UI 函数 (toolbar/colorPanel/insert_component/open*Dialog)。
//   后者在加载期以**宽容模式**处理: 记入诊断与 /api/scripts 的 missing 字段, 不中断加载。
//
// 实测: 原版 4.7 default.cna (1479 行) 原样加载 → 16 popup / 102 菜单项 / 7 menubar,
// 诊断仅 6 条 CS 客户端 UI 函数 (见 aggressor_cna_test.go)。
//
// 设计: 引擎本身不认识 C2, 所有 C2 能力通过 SetBuiltin 注入 (见 aggressor_builtins.go)。
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// ---------------------------------------------------------------- 值

// ScriptValue 是脚本里可流转的值: string / int64 / float64 / []ScriptValue
type ScriptValue interface{}

func toStr(v ScriptValue) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case int64:
		return fmt.Sprintf("%d", t)
	case float64:
		return strings.TrimRight(strings.TrimRight(fmt.Sprintf("%.6f", t), "0"), ".")
	case []ScriptValue:
		parts := make([]string, 0, len(t))
		for _, e := range t {
			parts = append(parts, toStr(e))
		}
		return strings.Join(parts, ",")
	case map[string]ScriptValue:
		/* 原版哈希 toString: {k1=v1, k2=v2}, 键按字典序保证可复现 */
		ks := make([]string, 0, len(t))
		for k := range t {
			ks = append(ks, k)
		}
		sort.Strings(ks)
		parts := make([]string, 0, len(ks))
		for _, k := range ks {
			parts = append(parts, k+"="+toStr(t[k]))
		}
		return "{" + strings.Join(parts, ", ") + "}"
	case *closure:
		return "closure"
	case *subDef:
		return "sub " + t.name
	}
	return fmt.Sprintf("%v", v)
}

func toInt(v ScriptValue) int64 {
	switch t := v.(type) {
	case int64:
		return t
	case float64:
		return int64(t)
	case string:
		var n int64
		fmt.Sscanf(t, "%d", &n)
		return n
	case bool:
		if t {
			return 1
		}
	}
	return 0
}

func truthy(v ScriptValue) bool {
	switch t := v.(type) {
	case nil:
		return false
	case bool:
		return t
	case int64:
		return t != 0
	case float64:
		return t != 0
	case string:
		return t != ""
	case []ScriptValue:
		return len(t) > 0
	case map[string]ScriptValue:
		return len(t) > 0
	}
	return true
}

// ---------------------------------------------------------------- 词法

type tokKind int

const (
	tkEOF tokKind = iota
	tkIdent
	tkStr
	tkNum
	tkVar    // $name
	tkArg    // @_ 或 @1
	tkLBrace // {
	tkRBrace // }
	tkLParen // (
	tkRParen // )
	tkLBrack // [
	tkRBrack // ]
	tkColon  // :
	tkSemi   // ;
	tkComma  // ,
	tkEq     // =
	tkPlus   // +
	tkMinus  // -
	tkDot    // .
	tkAt     // @  (数组字面量 @( 的起始)
	tkPercent // % (哈希字面量 %( 的起始)
	tkInterp  // 双引号插值字符串 (含未转义的 $ 变量)
	tkClass   // ^sleep.error.ClassName
	tkHashVar // %name
	tkFuncRef // &FuncName
	tkOp     // 其它运算符 (== != < > <= >= && || ! => $+)
)

type token struct {
	kind tokKind
	text string
	num  int64
	line int
}

type lexer struct {
	src  string
	pos  int
	line int
	name string
}

func (l *lexer) errf(format string, a ...interface{}) error {
	return fmt.Errorf("%s:%d: %s", l.name, l.line, fmt.Sprintf(format, a...))
}

func isIdentStart(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' || c >= 0x80
}
func isIdentChar(c byte) bool {
	return isIdentStart(c) || (c >= '0' && c <= '9') || c == '-' || c >= 0x80
}
func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// unescapeSleep 展开 Sleep 字符串里的转义序列
func unescapeSleep(s string) string {
	var sb []byte
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			i++
			switch s[i] {
			case 'n':
				sb = append(sb, '\n')
			case 't':
				sb = append(sb, '\t')
			case 'r':
				sb = append(sb, '\r')
			default:
				sb = append(sb, s[i])
			}
			continue
		}
		sb = append(sb, s[i])
	}
	return string(sb)
}

func (l *lexer) tokens() ([]token, error) {
	out := []token{}
	for l.pos < len(l.src) {
		c := l.src[l.pos]

		// 空白
		if c == ' ' || c == '\t' || c == '\r' {
			l.pos++
			continue
		}
		if c == '\n' {
			l.line++
			l.pos++
			continue
		}
		// 注释
		if c == '#' {
			for l.pos < len(l.src) && l.src[l.pos] != '\n' {
				l.pos++
			}
			continue
		}
		// 续行反斜杠
		if c == '\\' && l.pos+1 < len(l.src) &&
			(l.src[l.pos+1] == '\n' || l.src[l.pos+1] == '\r') {
			l.pos += 2
			l.line++
			continue
		}

		// 字符串: 双引号走 Sleep 插值, 单引号是字面量
		if c == '"' || c == '\'' {
			quote := c
			l.pos++
			var raw []byte
			hasVar := false
			for l.pos < len(l.src) && l.src[l.pos] != quote {
				if l.src[l.pos] == '\\' && l.pos+1 < len(l.src) {
					// 转义原样保留, 交给展开器(或插值扫描器)处理
					raw = append(raw, '\\', l.src[l.pos+1])
					l.pos += 2
					continue
				}
				if l.src[l.pos] == '\n' {
					l.line++
				}
				if quote == '"' && l.src[l.pos] == '$' {
					hasVar = true
				}
				raw = append(raw, l.src[l.pos])
				l.pos++
			}
			if l.pos >= len(l.src) {
				return nil, l.errf("字符串未闭合")
			}
			l.pos++ // 收尾引号
			if quote == '"' && hasVar {
				out = append(out, token{kind: tkInterp, text: string(raw), line: l.line})
			} else {
				out = append(out, token{kind: tkStr, text: unescapeSleep(string(raw)), line: l.line})
			}
			continue
		}

		// 数字
		if isDigit(c) {
			start := l.pos
			for l.pos < len(l.src) && (isIdentChar(l.src[l.pos]) || l.src[l.pos] == '.') {
				l.pos++
			}
			txt := l.src[start:l.pos]
			var n int64
			if strings.HasPrefix(txt, "0x") || strings.HasPrefix(txt, "0X") {
				fmt.Sscanf(txt[2:], "%x", &n)
			} else {
				fmt.Sscanf(txt, "%d", &n)
			}
			out = append(out, token{kind: tkNum, text: txt, num: n, line: l.line})
			continue
		}

		/* -name —— Sleep 的前缀命令/谓词调用 (例: if (-isadmin $bid)) */
		if c == '-' && l.pos+1 < len(l.src) && isIdentStart(l.src[l.pos+1]) {
			l.pos++
			start := l.pos
			for l.pos < len(l.src) && (isIdentChar(l.src[l.pos]) || l.src[l.pos] == '_') {
				l.pos++
			}
			out = append(out, token{kind: tkIdent, text: "-" + l.src[start:l.pos], line: l.line})
			continue
		}

		// 负数
		if c == '-' && l.pos+1 < len(l.src) && isDigit(l.src[l.pos+1]) {
			l.pos++
			start := l.pos
			for l.pos < len(l.src) && (isIdentChar(l.src[l.pos]) || l.src[l.pos] == '.') {
				l.pos++
			}
			txt := l.src[start:l.pos]
			var n int64
			fmt.Sscanf(txt, "%d", &n)
			out = append(out, token{kind: tkNum, text: "-" + txt, num: -n, line: l.line})
			continue
		}

		/* \$name / \@name —— 引用传递标记(lambda({...}, \$x)), 值语义等同 $name / @name */
		if c == '\\' && l.pos+1 < len(l.src) && (l.src[l.pos+1] == '$' || l.src[l.pos+1] == '@') {
			sigil := l.src[l.pos+1]
			l.pos += 2
			start := l.pos
			for l.pos < len(l.src) && (isIdentChar(l.src[l.pos]) || l.src[l.pos] == '_') {
				l.pos++
			}
			kind := tkVar
			if sigil == '@' {
				kind = tkArg
			}
			out = append(out, token{kind: kind, text: l.src[start:l.pos], line: l.line})
			continue
		}

		/* ^class.name —— Sleep 的类引用(原版脚本里只出现在 isa 判断中) */
		if c == '^' {
			l.pos++
			start := l.pos
			for l.pos < len(l.src) && (isIdentChar(l.src[l.pos]) || l.src[l.pos] == '.' || l.src[l.pos] == '$') {
				l.pos++
			}
			out = append(out, token{kind: tkClass, text: l.src[start:l.pos], line: l.line})
			continue
		}

		/* ? —— 原版脚本里有 command ? { ... } 这种符号命令名 */
		if c == '?' {
			l.pos++
			out = append(out, token{kind: tkIdent, text: "?", line: l.line})
			continue
		}

		// 变量 $name / $1 / $_; "$+" 是 Sleep 的拼接运算符, 归一化成 "+"
		if c == '$' {
			if l.pos+1 < len(l.src) && l.src[l.pos+1] == '+' {
				l.pos += 2
				out = append(out, token{kind: tkPlus, text: "+", line: l.line})
				continue
			}
			l.pos++
			start := l.pos
			for l.pos < len(l.src) && (isIdentChar(l.src[l.pos]) || l.src[l.pos] == '_' || l.src[l.pos] == ':' || l.src[l.pos] == '/') {
				l.pos++
			}
			out = append(out, token{kind: tkVar, text: l.src[start:l.pos], line: l.line})
			continue
		}

		/* %name —— Sleep 的哈希变量 (局部声明与赋值都用自己的记号) */
		if c == '%' && l.pos+1 < len(l.src) && (isIdentStart(l.src[l.pos+1]) || l.src[l.pos+1] == '_') {
			l.pos++
			start := l.pos
			for l.pos < len(l.src) && (isIdentChar(l.src[l.pos]) || l.src[l.pos] == '_') {
				l.pos++
			}
			out = append(out, token{kind: tkHashVar, text: l.src[start:l.pos], line: l.line})
			continue
		}

		// 数组字面量 @(...) 与参数 @_ / @1 的区分
		if c == '@' {
			if l.pos+1 < len(l.src) && l.src[l.pos+1] == '(' {
				l.pos++
				out = append(out, token{kind: tkAt, text: "@", line: l.line})
				continue
			}
			l.pos++
			start := l.pos
			for l.pos < len(l.src) && (isIdentChar(l.src[l.pos]) || l.src[l.pos] == '_') {
				l.pos++
			}
			out = append(out, token{kind: tkArg, text: l.src[start:l.pos], line: l.line})
			continue
		}

		// 哈希字面量 %(...)
		if c == '%' {
			l.pos++
			out = append(out, token{kind: tkPercent, text: "%", line: l.line})
			continue
		}

		// 方括号: 哈希取值 $h["k"]
		if c == '[' {
			l.pos++
			out = append(out, token{kind: tkLBrack, text: "[", line: l.line})
			continue
		}
		if c == ']' {
			l.pos++
			out = append(out, token{kind: tkRBrack, text: "]", line: l.line})
			continue
		}

		// 标识符
		if isIdentStart(c) {
			start := l.pos
			for l.pos < len(l.src) && isIdentChar(l.src[l.pos]) {
				l.pos++
			}
			/* Ns::Func —— 命名空间函数名 (SharpDPAPI::ParseMasterKeys 这类) */
			for l.pos+1 < len(l.src) && l.src[l.pos] == ':' && l.src[l.pos+1] == ':' {
				l.pos += 2
				for l.pos < len(l.src) && isIdentChar(l.src[l.pos]) {
					l.pos++
				}
			}
			txt := l.src[start:l.pos]
			/* foo!(...) —— Cobalt Strike 的"强制/异步调用"标记, 当同一函数处理 */
			if l.pos < len(l.src) && l.src[l.pos] == '!' &&
				(l.pos+1 >= len(l.src) || l.src[l.pos+1] != '=') {
				l.pos++
			}
			out = append(out, token{kind: tkIdent, text: txt, line: l.line})
			continue
		}

		/* &FuncName —— 函数引用(当值传递, 如 dialog(..., &SharpSchTask))。
		 * 名字里允许 - 与数字: &hack-browser-data / &open-3389 / &360bowser_upload */
		if c == '&' && l.pos+1 < len(l.src) &&
			(isIdentStart(l.src[l.pos+1]) || isDigit(l.src[l.pos+1])) {
			l.pos++
			start := l.pos
			for l.pos < len(l.src) && (isIdentChar(l.src[l.pos]) || l.src[l.pos] == '-') {
				l.pos++
			}
			if l.pos < len(l.src) && l.src[l.pos] == '!' {
				l.pos++
			}
			out = append(out, token{kind: tkFuncRef, text: l.src[start:l.pos], line: l.line})
			continue
		}

		// 符号
		switch c {
		case '{':
			out = append(out, token{kind: tkLBrace, text: "{", line: l.line})
			l.pos++
		case '}':
			out = append(out, token{kind: tkRBrace, text: "}", line: l.line})
			l.pos++
		case '(':
			out = append(out, token{kind: tkLParen, text: "(", line: l.line})
			l.pos++
		case ')':
			out = append(out, token{kind: tkRParen, text: ")", line: l.line})
			l.pos++
		case ';':
			out = append(out, token{kind: tkSemi, text: ";", line: l.line})
			l.pos++
		case ',':
			out = append(out, token{kind: tkComma, text: ",", line: l.line})
			l.pos++
		case ':':
			out = append(out, token{kind: tkColon, text: ":", line: l.line})
			l.pos++
		case '=':
			if l.pos+1 < len(l.src) && l.src[l.pos+1] == '=' {
				out = append(out, token{kind: tkOp, text: "==", line: l.line})
				l.pos += 2
			} else if l.pos+1 < len(l.src) && l.src[l.pos+1] == '~' {
				/* =~ —— 正则匹配运算符 */
				out = append(out, token{kind: tkOp, text: "=~", line: l.line})
				l.pos += 2
			} else if l.pos+1 < len(l.src) && l.src[l.pos+1] == '>' {
				/* 哈希字面量的键值分隔符 */
				out = append(out, token{kind: tkOp, text: "=>", line: l.line})
				l.pos += 2
			} else {
				out = append(out, token{kind: tkEq, text: "=", line: l.line})
				l.pos++
			}
		case '+':
			if l.pos+1 < len(l.src) && l.src[l.pos+1] == '+' {
				out = append(out, token{kind: tkOp, text: "++", line: l.line})
				l.pos += 2
				break
			}
			out = append(out, token{kind: tkPlus, text: "+", line: l.line})
			l.pos++
		case '-':
			if l.pos+1 < len(l.src) && l.src[l.pos+1] == '-' {
				out = append(out, token{kind: tkOp, text: "--", line: l.line})
				l.pos += 2
				break
			}
			out = append(out, token{kind: tkMinus, text: "-", line: l.line})
			l.pos++
		case '*', '/', '%':
			out = append(out, token{kind: tkOp, text: string(c), line: l.line})
			l.pos++
		case '.':
			out = append(out, token{kind: tkDot, text: ".", line: l.line})
			l.pos++
		case '!':
			if l.pos+1 < len(l.src) && l.src[l.pos+1] == '=' {
				out = append(out, token{kind: tkOp, text: "!=", line: l.line})
				l.pos += 2
			} else if l.pos+1 < len(l.src) && isIdentStart(l.src[l.pos+1]) {
				/* !eq !is !ne !in !isin !iswm ... —— Sleep 的"取反版"中缀运算符 */
				l.pos++
				start := l.pos
				for l.pos < len(l.src) && isIdentChar(l.src[l.pos]) {
					l.pos++
				}
				out = append(out, token{kind: tkOp, text: "!" + l.src[start:l.pos], line: l.line})
			} else {
				out = append(out, token{kind: tkOp, text: "!", line: l.line})
				l.pos++
			}
		case '<', '>', '&', '|':
			start := l.pos
			// <=> 三向比较(sort 的比较器里用)
			if l.src[l.pos] == '<' && l.pos+2 < len(l.src) &&
				l.src[l.pos+1] == '=' && l.src[l.pos+2] == '>' {
				l.pos += 3
				out = append(out, token{kind: tkOp, text: "<=>", line: l.line})
				break
			}
			l.pos++
			if l.pos < len(l.src) && (l.src[l.pos] == '=' ||
				(l.src[start] == '&' && l.src[l.pos] == '&') ||
				(l.src[start] == '|' && l.src[l.pos] == '|')) {
				l.pos++
			}
			out = append(out, token{kind: tkOp, text: l.src[start:l.pos], line: l.line})
		default:
			return nil, l.errf("无法识别的字符 %q", string(c))
		}
	}
	out = append(out, token{kind: tkEOF, line: l.line})
	return out, nil
}

// ---------------------------------------------------------------- AST

type node interface {
	eval(*ScriptCtx) (ScriptValue, error)
}

type blockNode struct{ stmts []node }

type literalNode struct{ v ScriptValue }

type varNode struct{ name string } // $name

type argNode struct{ name string } // @_ 或 @1

type callNode struct {
	name string
	args []node
	line int
}

type concatNode struct{ parts []node }

type assignNode struct {
	targets []string // 变量名(不含 $)
	value   node
}

type ifNode struct {
	cond node
	then *blockNode
	els  node
}

type whileNode struct {
	cond node
	body *blockNode
}

type returnNode struct{ value node }

type cmdInvokeNode struct{ // `whoami` 这类反引号命令(简化: ident 调用无括号)
	name string
}

/* ---------------------------------------------------------------- 扩展节点
 * 下面这些是为了能跑原版 .cna 补的。用 default.cna (1278 行) 统计过语法分布:
 *   $+ 拼接 97 次 / foreach 41 次 / item("名", { ... }) 74 次 / @() 9 次 /
 *   %() 4 次 / this 18 次 —— 缺任何一项, 原版脚本都在第一屏就解析失败。
 */

// 数组字面量 @(a, b, c)
type arrayNode struct{ items []node }

// 哈希字面量 %(k1 => v1, k2 => v2)
type hashNode struct {
	keys []string
	vals []node
}

// 匿名函数 { ... } 或 { ($a) => ... }(未带参数时沿用 @_)
type lambdaNode struct {
	params []string
	body   *blockNode
}

// 插值字符串 "a $x b"(Sleep 会展开双引号里的 $var)
type interpNode struct{ parts []node }

// foreach $x (集合) { ... } 或 foreach $k => $v (哈希) { ... }
type foreachNode struct {
	name string
	key  string
	coll node
	body *blockNode
}

// 下标取值 $h["k"]
type indexNode struct {
	obj node
	key node
}

// 变量形式的函数调用 $fn(a, b) —— lambda 存进变量后要能调
type varCallNode struct {
	varName string
	args    []node
}

// [$fn : a, b] —— 被调函数来自表达式求值结果
type dynCallNode struct {
	fn   node
	args []node
}

// 下标赋值 $h['k'] = v
type setIndexNode struct {
	target node
	value  node
}

// for (init; cond; incr) { ... }
type forNode struct {
	init node
	cond node
	incr node
	body *blockNode
}

// $i++ / $i--
type incNode struct {
	name  string
	delta int64
	dec   bool
}

// break / continue
type breakNode struct{}
type continueNode struct{}

// closure 是 lambda 求值后的值: 捕获定义处的环境
type closure struct {
	params []string
	body   *blockNode
	env    map[string]ScriptValue
}

// subDef 是顶层 sub 定义
type subDef struct {
	name   string
	params []string
	body   *blockNode
	line   int
}

// ---------------------------------------------------------------- 顶层定义

type handlerDef struct {
	Event string
	Body  *blockNode
	Line  int
}

type commandDef struct {
	Name   string
	Body   *blockNode
	IsAlias bool
	Line   int
}

type menuItem struct {
	Name     string
	Body     *blockNode
	Children []*menuItem
	Kind     string // item / menu / sep
	/* Base 是 script_resource() 的基准目录(= 定义/包含这个菜单项的**主脚本**所在目录)。
	 * 菜单项是**运行期**被点击执行的, 那时顶层加载早已结束, 所以基准必须固化在这里,
	 * 不能依赖"当前正在加载哪个文件"的全局状态 —— 否则插件里的
	 * script_resource('/scripts/x.exe') 会退化成相对路径, 服务端读不到文件
	 * (症状: 命令下发出去后植入体回"参数过短")。 */
	Base string
}

type menuDef struct {
	Parent string
	Name   string
	Items  []*menuItem
	Body   *blockNode // 调用形式(item(...)/separator())在加载期执行
	Line   int
	Src    string // 来源脚本文件(插件包归属统计用)
	Base   string // script_resource 基准目录(主脚本目录)
}

// menubarEntry 是 menubar("显示名", "popup id") 的登记项, 决定 GUI 菜单栏顺序
type menubarEntry struct {
	Label string
	ID    string
}

// ---------------------------------------------------------------- 解析

type parser struct {
	toks []token
	pos  int
	name string
	// sub/set 定义可能出现在任何位置(LSTAR 系列就把 sub 写在 popup 体里),
	// 解析期统一收集到这里, 由 parseProgram 合并。
	collected []*subDef
	// baseDir 是本次加载的**主脚本**目录, 会固化进 menuItem.Base
	// (script_resource 的基准, 见 menuItem.Base 的说明)
	baseDir string
}

/* parseSubDef 解析 sub 名(params) { ... } / set NAME { ... }。
 * 形参列表做宽松处理: 插件里常见 sub Foo (中文说明) { } 这种写法。 */
func (p *parser) parseSubDef(t token) (*subDef, error) {
	p.next()
	var nm string
	switch p.cur().kind {
	case tkIdent, tkStr, tkNum:
		/* 名字可能以数字开头: sub 360bowser_upload { } */
		nm = p.next().text
	default:
		return nil, p.errf("sub 后需要一个函数名")
	}
	sd := &subDef{name: nm, line: t.line}
	if p.cur().kind == tkLParen {
		p.next()
		for p.cur().kind != tkRParen && p.cur().kind != tkEOF {
			switch p.cur().kind {
			case tkVar, tkHashVar, tkArg:
				sd.params = append(sd.params, strings.TrimLeft(p.cur().text, "$%@"))
				p.next()
			case tkIdent:
				// 只在看起来像参数名时收: 中文说明一律跳过
				if isASCIIIdent(p.cur().text) {
					sd.params = append(sd.params, p.cur().text)
				}
				p.next()
			case tkComma:
				p.next()
			default:
				p.next()
			}
		}
		if _, err := p.expect(tkRParen, ")"); err != nil {
			return nil, err
		}
	}
	body, err := p.parseBlock()
	if err != nil {
		return nil, err
	}
	sd.body = body
	return sd, nil
}

// isASCIIIdent 判断是否是纯 ASCII 标识符(中文说明不是)
func isASCIIIdent(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

func (p *parser) cur() token  { return p.toks[p.pos] }
func (p *parser) next() token { t := p.toks[p.pos]; p.pos++; return t }

// peek 向前看 n 个 token, 越界时返回最后一个(EOF)
func (p *parser) peek(n int) token {
	i := p.pos + n
	if i >= len(p.toks) {
		return p.toks[len(p.toks)-1]
	}
	return p.toks[i]
}

func (p *parser) errf(format string, a ...interface{}) error {
	t := p.cur()
	return fmt.Errorf("%s:%d: %s", p.name, t.line, fmt.Sprintf(format, a...))
}

func (p *parser) expect(k tokKind, what string) (token, error) {
	if p.cur().kind != k {
		return token{}, p.errf("期望 %s, 实际是 %q", what, p.cur().text)
	}
	return p.next(), nil
}

func (p *parser) skipSemis() {
	for p.cur().kind == tkSemi {
		p.next()
	}
}

// program := { toplevel }
func (p *parser) parseProgram() (*blockNode, []*handlerDef, []*commandDef, []*menuDef, []*subDef, error) {
	prog := &blockNode{}
	var handlers []*handlerDef
	var commands []*commandDef
	var menus []*menuDef
	var subs []*subDef

	for p.cur().kind != tkEOF {
		p.skipSemis()
		if p.cur().kind == tkEOF {
			break
		}
		t := p.cur()
		if t.kind != tkIdent {
			/* 顶层允许任意语句: @beacons = @(); 之类(第三方插件很常见) */
			st, err := p.parseStmt()
			if err != nil {
				return nil, nil, nil, nil, nil, err
			}
			if st != nil {
				prog.stmts = append(prog.stmts, st)
			}
			p.skipSemis()
			continue
		}
		switch t.text {
		case "on":
			p.next()
			ev, err := p.expect(tkIdent, "事件名")
			if err != nil {
				return nil, nil, nil, nil, nil, err
			}
			body, err := p.parseBlock()
			if err != nil {
				return nil, nil, nil, nil, nil, err
			}
			e := ev.text
			// 支持 on beacon_initial_$arch 这类带变量的钩子名: 退化为前缀匹配
			handlers = append(handlers, &handlerDef{Event: e, Body: body, Line: t.line})
		case "command", "alias":
			isAlias := t.text == "alias"
			p.next()
			nm, err := p.expect(tkIdent, "命令名")
			if err != nil {
				return nil, nil, nil, nil, nil, err
			}
			body, err := p.parseBlock()
			if err != nil {
				return nil, nil, nil, nil, nil, err
			}
			commands = append(commands, &commandDef{Name: nm.text, Body: body, IsAlias: isAlias, Line: t.line})
		case "sub", "set":
			/* sub 名($a, $b) { ... } —— default.cna 用了 4 次, 但脚本生态里极常见。
			 * set NAME { ... } 是 Sleep 的动态函数定义, 这里按普通函数处理。 */
			sd, err := p.parseSubDef(t)
			if err != nil {
				return nil, nil, nil, nil, nil, err
			}
			subs = append(subs, sd)
		case "popup", "menu":
			p.next()
			parent := "beacon_bottom"
			group := ""
			if p.cur().kind == tkIdent {
				parent = p.next().text
			} else if p.cur().kind == tkStr {
				/* 顶层 menu "名" { ... } / popup "名" { ... }
				 * —— LSTAR / OLa / TaoWu / XieGongZi 全系列插件都是这么写的,
				 * 当成一个独立的菜单组保留下来。 */
				group = p.next().text
				parent = group
			}
			md, err := p.parseMenuBody(parent, t.line)
			if err != nil {
				return nil, nil, nil, nil, nil, err
			}
			md.Name = group
			md.Src = p.name
			md.Base = p.baseDir
			menus = append(menus, md)
		default:
			/* 顶层裸语句: menubar("&View","view"); debug(5); 等(原版 default.cna 有 8 处) */
			st, err := p.parseStmt()
			if err != nil {
				return nil, nil, nil, nil, nil, err
			}
			if st != nil {
				prog.stmts = append(prog.stmts, st)
			}
		}
		p.skipSemis()
	}
	subs = append(subs, p.collected...)
	return prog, handlers, commands, menus, subs, nil
}
func (p *parser) parseMenuBody(parent string, line int) (*menuDef, error) {
	md := &menuDef{Parent: parent, Line: line}
	items, body, err := p.parseMenuItems(parent)
	if err != nil {
		return nil, err
	}
	md.Items = items
	md.Body = body
	return md, nil
}

/* parseMenuItems 解析菜单块, 两种风格混用都要吃下:
 *   调用形式  item("&New", { ... });  separator();         <- 原版 default.cna(74+ 处)
 *   块形式    item "&New" { ... }     menu "&Visualization" { ... }
 * 调用形式的语句收集进 body, 由引擎在加载期执行(注册菜单项)。
 */
func (p *parser) parseMenuItems(label string) ([]*menuItem, *blockNode, error) {
	if _, err := p.expect(tkLBrace, "{"); err != nil {
		return nil, nil, err
	}
	var items []*menuItem
	body := &blockNode{}
	for p.cur().kind != tkRBrace && p.cur().kind != tkEOF {
		p.skipSemis()
		if p.cur().kind == tkRBrace {
			break
		}
		if p.cur().kind == tkIdent && (p.cur().text == "item" || p.cur().text == "menu" || p.cur().text == "submenu") {
			nx := p.peek(1)
			if nx.kind == tkStr || nx.kind == tkIdent {
				kind := p.next().text
				nm := p.next().text
				if kind == "item" {
					b, err := p.parseBlock()
					if err != nil {
						return nil, nil, err
					}
					items = append(items, &menuItem{Name: nm, Body: b, Kind: "item", Base: p.baseDir})
				} else {
					kids, sub, err := p.parseMenuItems(nm)
					if err != nil {
						return nil, nil, err
					}
					items = append(items, &menuItem{Name: nm, Children: kids, Body: sub, Kind: "menu", Base: p.baseDir})
				}
				continue
			}
		}
		st, err := p.parseStmt()
		if err != nil {
			return nil, nil, err
		}
		if st != nil {
			body.stmts = append(body.stmts, st)
		}
		p.skipSemis()
	}
	if _, err := p.expect(tkRBrace, "}"); err != nil {
		return nil, nil, err
	}
	return items, body, nil
}

func (p *parser) parseBlock() (*blockNode, error) {
	if _, err := p.expect(tkLBrace, "{"); err != nil {
		return nil, err
	}
	b := &blockNode{}
	for p.cur().kind != tkRBrace && p.cur().kind != tkEOF {
		p.skipSemis()
		if p.cur().kind == tkRBrace {
			break
		}
		st, err := p.parseStmt()
		if err != nil {
			return nil, err
		}
		if st != nil {
			b.stmts = append(b.stmts, st)
		}
		p.skipSemis()
	}
	if _, err := p.expect(tkRBrace, "}"); err != nil {
		return nil, err
	}
	return b, nil
}

func (p *parser) parseStmt() (node, error) {
	t := p.cur()

	if t.kind == tkIdent {
		switch t.text {
		case "local":
			p.next()
			// local('$a $b'); 或 local('$a') 或 local("$a")
			var names []string
			if p.cur().kind == tkLParen {
				p.next()
				for p.cur().kind != tkRParen && p.cur().kind != tkEOF {
					if p.cur().kind == tkStr {
						for _, f := range strings.Fields(p.cur().text) {
							names = append(names, strings.TrimLeft(f, "$%@"))
						}
					} else if p.cur().kind == tkComma {
						// 分隔符
					} else {
						names = append(names, p.cur().text)
					}
					p.next()
				}
				if _, err := p.expect(tkRParen, ")"); err != nil {
					return nil, err
				}
			}
			return &assignNode{targets: names, value: &literalNode{v: ""}}, nil
		case "if":
			p.next()
			cond, err := p.parseParenExpr()
			if err != nil {
				return nil, err
			}
			then, err := p.parseBlock()
			if err != nil {
				return nil, err
			}
			n := &ifNode{cond: cond, then: then}
			p.skipSemis()
			if p.cur().kind == tkIdent && p.cur().text == "else" {
				p.next()
				if p.cur().kind == tkIdent && p.cur().text == "if" {
					sub, err := p.parseStmt()
					if err != nil {
						return nil, err
					}
					n.els = sub
				} else {
					eb, err := p.parseBlock()
					if err != nil {
						return nil, err
					}
					n.els = eb
				}
			}
			return n, nil
		case "while":
			p.next()
			cond, err := p.parseParenExpr()
			if err != nil {
				return nil, err
			}
			body, err := p.parseBlock()
			if err != nil {
				return nil, err
			}
			return &whileNode{cond: cond, body: body}, nil
		case "return":
			p.next()
			if p.cur().kind == tkSemi || p.cur().kind == tkRBrace {
				return &returnNode{}, nil
			}
			v, err := p.parseExpr()
			if err != nil {
				return nil, err
			}
			return &returnNode{value: v}, nil
		case "foreach":
			/* foreach $x (集合) / foreach %h (集合) */
			p.next()
			if p.cur().kind != tkVar && p.cur().kind != tkHashVar {
				return nil, p.errf("foreach 后需要一个循环变量")
			}
			vn := p.next().text
			keyName := ""
			// foreach $k => $v (哈希)
			if p.cur().kind == tkOp && p.cur().text == "=>" {
				p.next()
				if p.cur().kind != tkVar && p.cur().kind != tkHashVar {
					return nil, p.errf("foreach 的 => 后需要一个变量")
				}
				keyName = vn
				vn = p.next().text
			}
			coll, err := p.parseParenExpr()
			if err != nil {
				return nil, err
			}
			body, err := p.parseBlock()
			if err != nil {
				return nil, err
			}
			return &foreachNode{name: vn, key: keyName, coll: coll, body: body}, nil
		case "foreach2":
			return nil, p.errf("尚未实现")
		case "sub", "set":
			/* 语句位置的 sub 定义 —— LSTAR / OLa / TaoWu 把 sub 写在 popup 体里,
			 * 这里收进解析器, 由 parseProgram 统一并进 subs 表。 */
			sd, err := p.parseSubDef(t)
			if err != nil {
				return nil, err
			}
			p.collected = append(p.collected, sd)
			return &literalNode{v: ""}, nil
		case "for":
			/* for (init; cond; incr) { ... } —— 原版脚本里用于进程树构建 */
			p.next()
			if _, err := p.expect(tkLParen, "("); err != nil {
				return nil, err
			}
			init, err := p.parseStmt()
			if err != nil {
				return nil, err
			}
			p.skipSemis()
			cond, err := p.parseExpr()
			if err != nil {
				return nil, err
			}
			p.skipSemis()
			incr, err := p.parseStmt()
			if err != nil {
				return nil, err
			}
			if _, err := p.expect(tkRParen, ")"); err != nil {
				return nil, err
			}
			body, err := p.parseBlock()
			if err != nil {
				return nil, err
			}
			return &forNode{init: init, cond: cond, incr: incr, body: body}, nil
		case "break":
			p.next()
			return &breakNode{}, nil
		case "continue":
			p.next()
			return &continueNode{}, nil
		}
	}

	// 赋值: ($a, $b) = expr;  或  $a = expr;
	if t.kind == tkLParen {
		save := p.pos
		p.next()
		var names []string
		ok := true
		for {
			if p.cur().kind == tkVar {
				names = append(names, p.next().text)
			} else {
				ok = false
				break
			}
			if p.cur().kind == tkComma {
				p.next()
				continue
			}
			break
		}
		if ok && p.cur().kind == tkRParen {
			p.next()
			if p.cur().kind == tkEq {
				p.next()
				v, err := p.parseExpr()
				if err != nil {
					return nil, err
				}
				return &assignNode{targets: names, value: v}, nil
			}
		}
		p.pos = save
	}

	if t.kind == tkVar {
		save := p.pos
		p.next()
		// 自增/自减语句: $i++ / $i--
		if p.cur().kind == tkOp && (p.cur().text == "++" || p.cur().text == "--") {
			op := p.next().text
			return &incNode{name: t.text, delta: 1, dec: op == "--"}, nil
		}
		if p.cur().kind == tkEq {
			p.next()
			v, err := p.parseExpr()
			if err != nil {
				return nil, err
			}
			return &assignNode{targets: []string{t.text}, value: v}, nil
		}
		/* 复合赋值: $out .= "..." —— 原版脚本用它拼日志文本 */
		if (p.cur().kind == tkDot || p.cur().kind == tkPlus) && p.peek(1).kind == tkEq {
			p.next()
			p.next()
			v, err := p.parseCallArg()
			if err != nil {
				return nil, err
			}
			self := &varNode{name: t.text}
			return &assignNode{targets: []string{t.text}, value: &concatNode{parts: []node{self, v}}}, nil
		}
		p.pos = save
	}

	// 数组变量赋值: @x = concat(@("ssh"), ...);  也支持 @x .= ...
	if t.kind == tkArg || t.kind == tkHashVar {
		save := p.pos
		p.next()
		if p.cur().kind == tkEq {
			p.next()
			v, err := p.parseExpr()
			if err != nil {
				return nil, err
			}
			return &assignNode{targets: []string{t.text}, value: v}, nil
		}
		if (p.cur().kind == tkDot || p.cur().kind == tkPlus) && p.peek(1).kind == tkEq {
			p.next()
			p.next()
			v, err := p.parseCallArg()
			if err != nil {
				return nil, err
			}
			self := &argNode{name: t.text}
			return &assignNode{targets: []string{t.text}, value: &concatNode{parts: []node{self, v}}}, nil
		}
		p.pos = save
	}

	// 下标赋值: $1[$i]['indent'] = "...";
	if t.kind == tkVar || t.kind == tkArg || t.kind == tkHashVar {
		save := p.pos
		if e, err := p.parsePrimary(); err == nil {
			if _, ok := e.(*indexNode); ok && p.cur().kind == tkEq {
				p.next()
				v, err := p.parseExpr()
				if err != nil {
					return nil, err
				}
				return &setIndexNode{target: e, value: v}, nil
			}
		}
		p.pos = save
	}

	e, err := p.parseExpr()
	if err != nil {
		return nil, err
	}
	return e, nil
}

func (p *parser) parseParenExpr() (node, error) {
	if _, err := p.expect(tkLParen, "("); err != nil {
		return nil, err
	}
	e, err := p.parseExpr()
	if err != nil {
		return nil, err
	}
	if _, err := p.expect(tkRParen, ")"); err != nil {
		return nil, err
	}
	return e, nil
}

// 表达式: 最低优先级是拼接 (+ 与 .), 再往上是 || && 比较 算术
func (p *parser) parseExpr() (node, error) {
	left, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	// 算术: - * / % (Sleep 要求运算符两侧有空白, 所以不会和负数混淆)
	for p.cur().kind == tkMinus ||
		(p.cur().kind == tkOp && (p.cur().text == "*" || p.cur().text == "/" || p.cur().text == "%")) {
		opTok := p.next()
		r, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		left = &callNode{name: "__op_" + opTok.text, args: []node{left, r}, line: opTok.line}
	}
	var parts []node
	parts = append(parts, left)
	for p.cur().kind == tkPlus || p.cur().kind == tkDot {
		/* $x.%hash[$k] —— 拼接时对哈希取值(InfoCollect 这类插件会这么写) */
		if p.cur().kind == tkDot &&
			(p.peek(1).kind == tkHashVar || p.peek(1).kind == tkVar) &&
			p.peek(2).kind == tkLBrack {
			p.next() // .
			vn := p.next()
			p.next() // [
			key, err := p.parseExpr()
			if err != nil {
				return nil, err
			}
			if _, err := p.expect(tkRBrack, "]"); err != nil {
				return nil, err
			}
			/* 下标可能还有后续层: $2[0]['PID'] */
			var idx node = &indexNode{obj: &varNode{name: vn.text}, key: key}
			idx, err = p.parseIndexSuffix(idx)
			if err != nil {
				return nil, err
			}
			parts = append(parts, idx)
			continue
		}
		p.next()
		r, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		parts = append(parts, r)
	}
	if len(parts) == 1 {
		return left, nil
	}
	return &concatNode{parts: parts}, nil
}

func (p *parser) parseOr() (node, error) {
	l, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for (p.cur().kind == tkOp && p.cur().text == "||") ||
		(p.cur().kind == tkIdent && p.cur().text == "or") {
		opTok := p.next()
		r, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		l = &callNode{name: "__op_||", args: []node{l, r}, line: opTok.line}
	}
	return l, nil
}

func (p *parser) parseAnd() (node, error) {
	l, err := p.parseComparison()
	if err != nil {
		return nil, err
	}
	for (p.cur().kind == tkOp && p.cur().text == "&&") ||
		(p.cur().kind == tkIdent && p.cur().text == "and") {
		opTok := p.next()
		r, err := p.parseComparison()
		if err != nil {
			return nil, err
		}
		l = &callNode{name: "__op_&&", args: []node{l, r}, line: opTok.line}
	}
	return l, nil
}

// comparison := primary { (== != < > <= >= eq ne lt gt le ge isa ismatch iswm isin in) primary }
func (p *parser) parseComparison() (node, error) {
	l, err := p.parsePrimary()
	if err != nil {
		return nil, err
	}
	for {
		if p.cur().kind == tkOp && p.cur().text != "&&" && p.cur().text != "||" && p.cur().text != "=>" {
			op := p.next().text
			r, err := p.parsePrimary()
			if err != nil {
				return nil, err
			}
			l = &callNode{name: "__op_" + op, args: []node{l, r}, line: p.cur().line}
			continue
		}
		if p.cur().kind == tkIdent {
			switch p.cur().text {
			case "isa", "is", "ismatch", "hasmatch", "iswm", "isin", "contains", "in", "eq", "ne", "lt", "gt", "le", "ge", "cmp":
				op := p.next().text
				r, err := p.parsePrimary()
				if err != nil {
					return nil, err
				}
				l = &callNode{name: "__op_" + op, args: []node{l, r}, line: p.cur().line}
				continue
			}
		}
		break
	}
	return l, nil
}

// parseCallArg 解析一个调用实参, 额外支持 lambda 的命名引用形式 $name => $value
func (p *parser) parseCallArg() (node, error) {
	e, err := p.parseExpr()
	if err != nil {
		return nil, err
	}
	if p.cur().kind == tkOp && p.cur().text == "=>" {
		opTok := p.next()
		r, err := p.parseExpr()
		if err != nil {
			return nil, err
		}
		return &callNode{name: "__op_=>", args: []node{e, r}, line: opTok.line}, nil
	}
	return e, nil
}

// parseIndexSuffix 解析调用结果后的下标链: binfo($1)['internal']
func (p *parser) parseIndexSuffix(base node) (node, error) {
	for p.cur().kind == tkLBrack {
		p.next()
		k, err := p.parseExpr()
		if err != nil {
			return nil, err
		}
		if _, err := p.expect(tkRBrack, "]"); err != nil {
			return nil, err
		}
		base = &indexNode{obj: base, key: k}
	}
	return base, nil
}

// isCommandArgStart 判断 token 能否作为前缀命令调用的实参起始
func isCommandArgStart(t token) bool {
	switch t.kind {
	case tkStr, tkInterp, tkNum, tkVar, tkArg, tkLParen, tkAt, tkPercent:
		return true
	case tkIdent:
		// 保留字/分隔符不当作参数
		switch t.text {
		case "else", "return", "local", "if", "foreach", "while", "sub":
			return false
		}
		return true
	}
	return false
}

func (p *parser) parsePrimary() (node, error) {
	t := p.cur()
	switch t.kind {
	case tkStr:
		p.next()
		return &literalNode{v: t.text}, nil
	case tkInterp:
		p.next()
		return buildInterp(t.text, t.line)
	case tkClass:
		p.next()
		return &literalNode{v: t.text}, nil
	case tkFuncRef:
		/* &FuncName —— 函数引用当值: 引擎用"函数名字符串"表示, invokeCallable 认得 */
		p.next()
		return &literalNode{v: t.text}, nil
	case tkNum:
		p.next()
		return &literalNode{v: t.num}, nil
	case tkVar, tkHashVar:
		p.next()
		/* $fn(...) —— lambda 存进变量后要能调 */
		if p.cur().kind == tkLParen {
			p.next()
			var args []node
			for p.cur().kind != tkRParen && p.cur().kind != tkEOF {
				/* 连续逗号 = 省略的参数, 原版插件里很常见 */
				if p.cur().kind == tkComma {
					args = append(args, &literalNode{v: ""})
					p.next()
					continue
				}
				a, err := p.parseCallArg()
				if err != nil {
					return nil, err
				}
				args = append(args, a)
				if p.cur().kind == tkComma {
					p.next()
					continue
				}
				break
			}
			if _, err := p.expect(tkRParen, ")"); err != nil {
				return nil, err
			}
			nc := node(&varCallNode{varName: t.text, args: args})
			return p.parseIndexSuffix(nc)
		}
		/* $h["k"] / $1[$i]['ppid'] —— 支持下标链 */
		var base node = &varNode{name: t.text}
		for p.cur().kind == tkLBrack {
			p.next()
			k, err := p.parseExpr()
			if err != nil {
				return nil, err
			}
			if _, err := p.expect(tkRBrack, "]"); err != nil {
				return nil, err
			}
			base = &indexNode{obj: base, key: k}
		}
		return base, nil
	case tkAt:
		/* 数组字面量 @(a, b, c) */
		p.next()
		if _, err := p.expect(tkLParen, "("); err != nil {
			return nil, err
		}
		n := &arrayNode{}
		for p.cur().kind != tkRParen && p.cur().kind != tkEOF {
			/* 连续逗号 = 省略的参数, 原版插件里很常见 */
			if p.cur().kind == tkComma {
				n.items = append(n.items, &literalNode{v: ""})
				p.next()
				continue
			}
			e, err := p.parseExpr()
			if err != nil {
				return nil, err
			}
			n.items = append(n.items, e)
			if p.cur().kind == tkComma {
				p.next()
				continue
			}
			break
		}
		if _, err := p.expect(tkRParen, ")"); err != nil {
			return nil, err
		}
		return n, nil
	case tkPercent:
		/* 哈希字面量 %(k1 => v1, ...) */
		p.next()
		if _, err := p.expect(tkLParen, "("); err != nil {
			return nil, err
		}
		n := &hashNode{}
		for p.cur().kind != tkRParen && p.cur().kind != tkEOF {
			/* 连续逗号 = 省略的参数, 原版插件里很常见 */
			if p.cur().kind == tkComma {
				n.vals = append(n.vals, &literalNode{v: ""})
				p.next()
				continue
			}
			/* 键可能含 / 或 - (例: cmd/path => "..."): 收集到 => 为止 */
			var kb strings.Builder
			for p.cur().kind != tkEOF && !(p.cur().kind == tkOp && p.cur().text == "=>") {
				if p.cur().kind == tkComma || p.cur().kind == tkRParen || p.cur().kind == tkSemi {
					return nil, p.errf("哈希字面量缺少 =>")
				}
				kb.WriteString(p.next().text)
			}
			if !(p.cur().kind == tkOp && p.cur().text == "=>") {
				return nil, p.errf("哈希字面量缺少 =>")
			}
			key := kb.String()
			p.next()
			v, err := p.parseCallArg()
			if err != nil {
				return nil, err
			}
			n.keys = append(n.keys, key)
			n.vals = append(n.vals, v)
			if p.cur().kind == tkComma {
				p.next()
				continue
			}
			break
		}
		if _, err := p.expect(tkRParen, ")"); err != nil {
			return nil, err
		}
		return n, nil
	case tkLBrace:
		/* 匿名函数 { ... } —— item("名", { ... }) 的第二个参数 */
		body, err := p.parseBlock()
		if err != nil {
			return nil, err
		}
		return &lambdaNode{body: body}, nil
	case tkLBrack:
		/* [$obj method] / [$obj method: a, b] / [&fn : a, b] —— Sleep 方括号调用。
		 * 本引擎没有 Java 对象, 统一映射成普通调用 method($obj, a, b), 由内置函数决定行为。 */
		p.next()
		var obj node
		var fname string
		if p.cur().kind == tkOp && p.cur().text == "&" {
			// [&fn : args]: 函数引用形式
			p.next()
			if p.cur().kind != tkIdent {
				return nil, p.errf("& 后需要函数名")
			}
			fname = p.next().text
		} else {
			o, err := p.parsePrimary()
			if err != nil {
				return nil, err
			}
			obj = o
			if p.cur().kind == tkIdent {
				fname = p.next().text
			} else if p.cur().kind == tkVar {
				fname = p.next().text
			} else if p.cur().kind == tkColon {
				// [$fn : args] 直接调用函数
				fname = ""
			} else if p.cur().kind == tkRBrack {
				if _, err := p.expect(tkRBrack, "]"); err != nil {
					return nil, err
				}
				return o, nil
			} else {
				return nil, p.errf("方括号调用缺少方法名, 遇到 %q", p.cur().text)
			}
		}
		var args []node
		if obj != nil {
			args = append(args, obj)
		}
		if p.cur().kind == tkColon {
			p.next()
			for p.cur().kind != tkRBrack && p.cur().kind != tkEOF {
				/* 连续逗号 = 省略的参数, 原版插件里很常见 */
				if p.cur().kind == tkComma {
					args = append(args, &literalNode{v: ""})
					p.next()
					continue
				}
				a, err := p.parseCallArg()
				if err != nil {
					return nil, err
				}
				args = append(args, a)
				if p.cur().kind == tkComma {
					p.next()
					continue
				}
				break
			}
		}
		if _, err := p.expect(tkRBrack, "]"); err != nil {
			return nil, err
		}
		if fname == "" {
			// [$fn : args]: 第一个元素是被调用的函数值
			if len(args) == 0 {
				return nil, p.errf("方括号调用缺少目标")
			}
			return &dynCallNode{fn: args[0], args: args[1:]}, nil
		}
		return &callNode{name: fname, args: args, line: t.line}, nil
	case tkOp:
		/* 一元 ! 运算符: 原版脚本里形如 if (!-isactive $bid) */
		if t.text == "!" {
			p.next()
			operand, err := p.parsePrimary()
			if err != nil {
				return nil, err
			}
			return &callNode{name: "__op_!", args: []node{operand}, line: t.line}, nil
		}
		return nil, p.errf("无法解析的表达式, 遇到 %q", t.text)
	case tkArg:
		p.next()
		var abase node = &argNode{name: t.text}
		/* @arr[$i] = ... 这类数组元素访问 */
		for p.cur().kind == tkLBrack {
			p.next()
			k, err := p.parseExpr()
			if err != nil {
				return nil, err
			}
			if _, err := p.expect(tkRBrack, "]"); err != nil {
				return nil, err
			}
			abase = &indexNode{obj: abase, key: k}
		}
		return abase, nil
	case tkLParen:
		/* (a) 是分组; (a, b, c) 是列表 —— 插件里当实参写时会带多余括号 */
		p.next()
		var items []node
		if p.cur().kind != tkRParen {
			for {
				if p.cur().kind == tkComma {
					items = append(items, &literalNode{v: ""})
					p.next()
					continue
				}
				e, err := p.parseCallArg()
				if err != nil {
					return nil, err
				}
				items = append(items, e)
				if p.cur().kind == tkComma {
					p.next()
					continue
				}
				break
			}
		}
		if _, err := p.expect(tkRParen, ")"); err != nil {
			return nil, err
		}
		if len(items) == 1 {
			return items[0], nil
		}
		return &arrayNode{items: items}, nil
	case tkIdent:
		p.next()
		/* -name arg1 arg2 —— Sleep 前缀命令调用, 参数以空白分隔:
		 *   原版脚本里形如 if (-isadmin $bid) { ... } */
		if strings.HasPrefix(t.text, "-") && len(t.text) > 1 {
			var args []node
			for isCommandArgStart(p.cur()) {
				a, err := p.parsePrimary()
				if err != nil {
					return nil, err
				}
				args = append(args, a)
			}
			return &callNode{name: t.text[1:], args: args, line: t.line}, nil
		}
		// 函数调用或裸标识符
		if p.cur().kind == tkLParen {
			p.next()
			var args []node
			for p.cur().kind != tkRParen && p.cur().kind != tkEOF {
				/* 连续逗号 = 省略的参数, 原版插件里很常见 */
				if p.cur().kind == tkComma {
					args = append(args, &literalNode{v: ""})
					p.next()
					continue
				}
				a, err := p.parseCallArg()
				if err != nil {
					return nil, err
				}
				args = append(args, a)
				if p.cur().kind == tkComma {
					p.next()
					continue
				}
				break
			}
			if _, err := p.expect(tkRParen, ")"); err != nil {
				return nil, err
			}
			nc := node(&callNode{name: t.text, args: args, line: t.line})
			return p.parseIndexSuffix(nc)
		}
		if t.text == "true" {
			return &literalNode{v: int64(1)}, nil
		}
		if t.text == "false" || t.text == "nil" {
			return &literalNode{v: int64(0)}, nil
		}
		return &callNode{name: t.text, line: t.line}, nil
	}
	return nil, p.errf("无法解析的表达式, 遇到 %q", t.text)
}

/* buildInterp 把双引号字符串编译成插值片段。Sleep 官方文档
 * ("A Quick Sleep Introduction") 规则:
 *   - 任何以空白分隔、以 $ 开头的 token 被替换成它的值
 *   - 特殊变量 $+ 把插值结果与相邻值无缝拼接(吞掉紧邻空白)
 *   - \$ 转义为字面 $, \n \t \r 正常展开
 */
func buildInterp(s string, line int) (node, error) {
	n := &interpNode{}
	var lit []byte
	flush := func() {
		if len(lit) > 0 {
			n.parts = append(n.parts, &literalNode{v: string(lit)})
			lit = lit[:0]
		}
	}
	for i := 0; i < len(s); {
		ch := s[i]
		if ch == '\\' && i+1 < len(s) {
			switch s[i+1] {
			case 'n':
				lit = append(lit, '\n')
			case 't':
				lit = append(lit, '\t')
			case 'r':
				lit = append(lit, '\r')
			default:
				lit = append(lit, s[i+1])
			}
			i += 2
			continue
		}
		if ch == '$' {
			if i+1 < len(s) && s[i+1] == '+' {
				for len(lit) > 0 && (lit[len(lit)-1] == ' ' || lit[len(lit)-1] == '\t') {
					lit = lit[:len(lit)-1]
				}
				i += 2
				for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
					i++
				}
				continue
			}
			/* $[N] —— 第 N 个参数 (原版脚本 "$[5]pid" 这种写法) */
			if i+1 < len(s) && s[i+1] == '[' {
				j := i + 2
				start := j
				for j < len(s) && s[j] != ']' {
					j++
				}
				if j < len(s) {
					idx := strings.TrimSpace(s[start:j])
					flush()
					if isAllDigits(idx) {
						n.parts = append(n.parts, &argNode{name: idx})
					} else {
						n.parts = append(n.parts, &varNode{name: idx})
					}
					i = j + 1
					continue
				}
			}
			j := i + 1
			for j < len(s) && (isIdentChar(s[j]) || s[j] == '_') {
				j++
			}
			if j == i+1 {
				lit = append(lit, '$')
				i++
				continue
			}
			name := s[i+1 : j]
			flush()
			n.parts = append(n.parts, &varNode{name: name})
			i = j
			continue
		}
		lit = append(lit, ch)
		i++
	}
	flush()
	if len(n.parts) == 0 {
		return &literalNode{v: ""}, nil
	}
	return n, nil
}

func (n *interpNode) eval(c *ScriptCtx) (ScriptValue, error) {
	var sb strings.Builder
	for _, p := range n.parts {
		v, err := p.eval(c)
		if err != nil {
			return nil, err
		}
		sb.WriteString(toStr(v))
	}
	return sb.String(), nil
}

// ---------------------------------------------------------------- 求值

const maxLoopIterations = 100000

type ScriptCtx struct {
	env     map[string]ScriptValue
	args    []ScriptValue
	engine  *Aggressor
	depth   int
	loops   int
	visited map[string]bool
	lenient bool   // 宽容模式: 未定义函数记一次警告并返回空值
	scriptPath string // 当前脚本文件路径(报错定位用)
	/* resourceBase 是 script_resource() 的基准目录 = **顶层被加载的主脚本**所在目录。
	 * 实测第三方插件包(CS 的 loader 结构)依赖这个语义:
	 *   TaoWu/TaoWu.cna            script_resource("modules/discovery.cna") -> 包根相对
	 *   TaoWu/modules/credential access.cna
	 *                              include(script_resource("modules/RdpThief.cna"))
	 *                              -> 目标其实是 TaoWu/modules/RdpThief.cna, 说明基准不是
	 *                                 "当前文件所在目录"(那样会变成 modules/modules/...)
	 *   LSTAR/modules/AuthMaintain.cna
	 *                              script_resource("/scripts/AuthMaintain/SchTask.exe")
	 *                              -> 目标是 LSTAR/scripts/... (包根下), 同样指向包根
	 * 所以 include 时 resourceBase 保持不变, 只更新 scriptPath。 */
	resourceBase string
}

func (c *ScriptCtx) child(args []ScriptValue) *ScriptCtx {
	nc := &ScriptCtx{env: map[string]ScriptValue{}, args: args, engine: c.engine, depth: c.depth + 1,
		visited: c.visited, lenient: c.lenient, scriptPath: c.scriptPath, resourceBase: c.resourceBase}
	return nc
}

func (c *ScriptCtx) get(name string) (ScriptValue, bool) {
	v, ok := c.env[name]
	return v, ok
}

func (c *ScriptCtx) set(name string, v ScriptValue) { c.env[name] = v }

type returnSignal struct{ v ScriptValue }

func (returnSignal) Error() string { return "return" }

type breakSignal struct{}
type continueSignal struct{}

func (breakSignal) Error() string    { return "break" }
func (continueSignal) Error() string { return "continue" }

func (n *forNode) eval(c *ScriptCtx) (ScriptValue, error) {
	if n.init != nil {
		if _, err := n.init.eval(c); err != nil {
			return nil, err
		}
	}
	c.loops = 0
	for {
		c.loops++
		if c.loops > maxLoopIterations {
			return nil, fmt.Errorf("循环超过 %d 次, 已中止 (防止脚本挂死)", maxLoopIterations)
		}
		cond, err := n.cond.eval(c)
		if err != nil {
			return nil, err
		}
		if !truthy(cond) {
			break
		}
		if _, err := n.body.eval(c); err != nil {
			if _, ok := err.(returnSignal); ok {
				return nil, err
			}
			if _, ok := err.(breakSignal); ok {
				break
			}
			if _, ok := err.(continueSignal); !ok {
				return nil, err
			}
		}
		if n.incr != nil {
			if _, err := n.incr.eval(c); err != nil {
				return nil, err
			}
		}
	}
	return "", nil
}

func (n *incNode) eval(c *ScriptCtx) (ScriptValue, error) {
	cur := int64(0)
	if v, ok := c.get(n.name); ok {
		cur = toInt(v)
	}
	if n.dec {
		cur--
	} else {
		cur++
	}
	c.set(n.name, cur)
	return cur, nil
}

func (n *breakNode) eval(c *ScriptCtx) (ScriptValue, error)    { return nil, breakSignal{} }
func (n *continueNode) eval(c *ScriptCtx) (ScriptValue, error) { return nil, continueSignal{} }

func (n *setIndexNode) eval(c *ScriptCtx) (ScriptValue, error) {
	ix, ok := n.target.(*indexNode)
	if !ok {
		return "", fmt.Errorf("不支持的赋值目标")
	}
	obj, err := ix.obj.eval(c)
	if err != nil {
		return nil, err
	}
	key, err := ix.key.eval(c)
	if err != nil {
		return nil, err
	}
	v, err := n.value.eval(c)
	if err != nil {
		return nil, err
	}
	switch m := obj.(type) {
	case map[string]ScriptValue:
		m[toStr(key)] = v
	case []ScriptValue:
		i := toInt(key)
		if i >= 1 && int(i) <= len(m) {
			m[i-1] = v
		}
	}
	return v, nil
}

func (b *blockNode) eval(c *ScriptCtx) (ScriptValue, error) {
	var last ScriptValue
	for _, st := range b.stmts {
		v, err := st.eval(c)
		if err != nil {
			return nil, err
		}
		last = v
	}
	return last, nil
}

func (n *literalNode) eval(*ScriptCtx) (ScriptValue, error) { return n.v, nil }

func (n *varNode) eval(c *ScriptCtx) (ScriptValue, error) {
	if n.name == "_" {
		return c.args, nil
	}
	if v, ok := c.get(n.name); ok {
		return v, nil
	}
	// 允许 $1 $2 形式
	if isAllDigits(n.name) {
		idx := toInt(n.name)
		if idx >= 1 && int(idx) <= len(c.args) {
			return c.args[idx-1], nil
		}
		return "", nil
	}
	return "", nil
}

func (n *argNode) eval(c *ScriptCtx) (ScriptValue, error) {
	if n.name == "_" {
		return c.args, nil
	}
	// @x 这类命名数组变量(与标量共用一个作用域, Sleep 里也允许这么用)
	if !isAllDigits(n.name) && n.name != "" {
		if v, ok := c.get(n.name); ok {
			return v, nil
		}
		if v, ok := c.get("@" + n.name); ok {
			return v, nil
		}
		return []ScriptValue{}, nil
	}
	idx := toInt(n.name)
	if idx >= 1 && int(idx) <= len(c.args) {
		return c.args[idx-1], nil
	}
	return "", nil
}

func (n *concatNode) eval(c *ScriptCtx) (ScriptValue, error) {
	var sb strings.Builder
	for _, p := range n.parts {
		v, err := p.eval(c)
		if err != nil {
			return nil, err
		}
		sb.WriteString(toStr(v))
	}
	return sb.String(), nil
}

func (n *assignNode) eval(c *ScriptCtx) (ScriptValue, error) {
	var v ScriptValue = ""
	if n.value != nil {
		got, err := n.value.eval(c)
		if err != nil {
			return nil, err
		}
		v = got
	}
	// 多个目标是解包: ($a,$b) = @_ 或 逗号值
	if len(n.targets) > 1 {
		if arr, ok := v.([]ScriptValue); ok {
			for i, t := range n.targets {
				if i < len(arr) {
					c.set(t, arr[i])
				} else {
					c.set(t, "")
				}
			}
			return v, nil
		}
		s := toStr(v)
		parts := strings.Split(s, ",")
		for i, t := range n.targets {
			if i < len(parts) {
				c.set(t, strings.TrimSpace(parts[i]))
			} else {
				c.set(t, "")
			}
		}
		return v, nil
	}
	c.set(n.targets[0], v)
	return v, nil
}

func (n *callNode) eval(c *ScriptCtx) (ScriptValue, error) {
	// 运算符
	if strings.HasPrefix(n.name, "__op_") {
		return evalOp(strings.TrimPrefix(n.name, "__op_"), n, c)
	}

	args := make([]ScriptValue, 0, len(n.args))
	for _, a := range n.args {
		v, err := a.eval(c)
		if err != nil {
			return nil, err
		}
		args = append(args, v)
	}

	if c.engine == nil {
		return "", fmt.Errorf("脚本引擎未初始化, 无法调用 %s", n.name)
	}
	if fn, ok := c.engine.builtins[n.name]; ok {
		return fn(c, args)
	}
	// 脚本自己定义的 sub
	if sub, ok := c.engine.lookupSub(n.name); ok {
		return callClosure(sub.params, sub.body, nil, c, args)
	}
	// 变量里存了闭包/函数名时, 裸名调用同样成立(菜单回调、item 定义常用)
	if fv, ok := c.get(n.name); ok {
		if rv, err := invokeCallable(fv, c, args); err == nil {
			return rv, nil
		}
	}
	if c.lenient {
		// 加载原版脚本时, 大量 Cobalt Strike 客户端 GUI API 本引擎没有实现:
		// 记录一次以便如实汇报, 但不中断加载。
		c.engine.noteMissing(n.name)
		return "", nil
	}
	return "", fmt.Errorf("%s:%d: 未定义的函数 %s", c.engine.currentName, n.line, n.name)
}

func evalOp(op string, n *callNode, c *ScriptCtx) (ScriptValue, error) {
	/* !eq / !is / !in / !isin ... —— 取反版中缀运算符 */
	if strings.HasPrefix(op, "!") && op != "!" {
		inner, err := evalOp(strings.TrimPrefix(op, "!"), n, c)
		if err != nil {
			return nil, err
		}
		return boolVal(!truthy(inner)), nil
	}
	a, err := n.args[0].eval(c)
	if err != nil {
		return nil, err
	}
	var b ScriptValue = ""
	if len(n.args) > 1 {
		b, err = n.args[1].eval(c)
		if err != nil {
			return nil, err
		}
	}
	ai, bi := toInt(a), toInt(b)
	as, bs := toStr(a), toStr(b)

	switch op {
	case "==":
		return boolVal(as == bs || (ai == bi && ai != 0)), nil
	case "!=":
		return boolVal(as != bs), nil
	case "!is":
		return boolVal(as != bs), nil
	case "is":
		return boolVal(as == bs), nil
	case "<":
		return boolVal(ai < bi), nil
	case "eq":
		return boolVal(as == bs), nil
	case "ne":
		return boolVal(as != bs), nil
	case "lt":
		return boolVal(ai < bi), nil
	case "gt":
		return boolVal(ai > bi), nil
	case "le":
		return boolVal(ai <= bi), nil
	case "ge":
		return boolVal(ai >= bi), nil
	case "cmp":
		/* ($a cmp $b) == 0 风格的三向比较 */
		return int64(compareValues(a, b)), nil
	case ">":
		return boolVal(ai > bi), nil
	case "<=":
		return boolVal(ai <= bi), nil
	case ">=":
		return boolVal(ai >= bi), nil
	case "&&":
		return boolVal(truthy(a) && truthy(b)), nil
	case "||":
		return boolVal(truthy(a) || truthy(b)), nil
	case "!":
		return boolVal(!truthy(a)), nil
	case "-":
		return ai - bi, nil
	case "*":
		return ai * bi, nil
	case "/":
		if bi == 0 {
			return int64(0), nil
		}
		return ai / bi, nil
	case "%":
		if bi == 0 {
			return int64(0), nil
		}
		return ai % bi, nil
	case "isa":
		/* 没有 Java 类型系统: 只在两边都是类名/字符串时做前缀比较 */
		return boolVal(as != "" && bs != "" && as == bs), nil
	case "ismatch", "hasmatch":
		re, err := regexp.Compile(bs)
		if err != nil {
			return boolVal(false), nil
		}
		m := re.FindStringSubmatch(as)
		if m == nil {
			return boolVal(false), nil
		}
		groups := make([]ScriptValue, 0, len(m)-1)
		for i := 1; i < len(m); i++ {
			groups = append(groups, m[i])
		}
		c.set("__matched__", groups)
		return boolVal(true), nil
	case "isin", "contains":
		return boolVal(strings.Contains(bs, as)), nil
	case "=~":
		re, err := regexp.Compile(bs)
		if err != nil {
			return boolVal(false), nil
		}
		return boolVal(re.MatchString(as)), nil
	case "in":
		switch t := b.(type) {
		case []ScriptValue:
			for _, e := range t {
				if toStr(e) == as {
					return boolVal(true), nil
				}
			}
			return boolVal(false), nil
		case map[string]ScriptValue:
			_, ok := t[as]
			return boolVal(ok), nil
		case string:
			return boolVal(strings.Contains(t, as)), nil
		}
		return boolVal(false), nil
	case "iswm":
		return boolVal(wildcardMatch(bs, as)), nil
	case "=>":
		/* lambda 的命名引用参数 $name => $value, 取值侧用右值 */
		return b, nil
	case "<=>":
		/* 三向比较, sort() 的比较器用 */
		switch {
		case ai < bi:
			return int64(-1), nil
		case ai > bi:
			return int64(1), nil
		}
		return int64(0), nil
	case "++":
		return ai + 1, nil
	case "--":
		return ai - 1, nil
	}
	return "", fmt.Errorf("不支持的运算符 %s", op)
}

func boolVal(b bool) ScriptValue {
	if b {
		return int64(1)
	}
	return int64(0)
}

// wildcardMatch 实现 Sleep 的 iswm (通配符 * 与 ?)
func wildcardMatch(pattern, s string) bool {
	var sb strings.Builder
	sb.WriteString("^")
	for i := 0; i < len(pattern); i++ {
		switch pattern[i] {
		case '*':
			sb.WriteString(".*")
		case '?':
			sb.WriteString(".")
		default:
			sb.WriteString(regexp.QuoteMeta(string(pattern[i])))
		}
	}
	sb.WriteString("$")
	re, err := regexp.Compile(sb.String())
	if err != nil {
		return false
	}
	return re.MatchString(s)
}

func (n *ifNode) eval(c *ScriptCtx) (ScriptValue, error) {
	cond, err := n.cond.eval(c)
	if err != nil {
		return nil, err
	}
	if truthy(cond) {
		return n.then.eval(c)
	}
	if n.els != nil {
		return n.els.eval(c)
	}
	return "", nil
}

func (n *whileNode) eval(c *ScriptCtx) (ScriptValue, error) {
	c.loops = 0
	for {
		c.loops++
		if c.loops > maxLoopIterations {
			return nil, fmt.Errorf("循环超过 %d 次, 已中止 (防止脚本挂死)", maxLoopIterations)
		}
		cond, err := n.cond.eval(c)
		if err != nil {
			return nil, err
		}
		if !truthy(cond) {
			break
		}
		if _, err := n.body.eval(c); err != nil {
			if _, ok := err.(returnSignal); ok {
				return nil, err
			}
			if _, ok := err.(breakSignal); ok {
				break
			}
			if _, ok := err.(continueSignal); ok {
				continue
			}
			return nil, err
		}
	}
	return "", nil
}

func (n *returnNode) eval(c *ScriptCtx) (ScriptValue, error) {
	var v ScriptValue = ""
	if n.value != nil {
		got, err := n.value.eval(c)
		if err != nil {
			return nil, err
		}
		v = got
	}
	return nil, returnSignal{v: v}
}

/* ---------------------------------------------------------------- 扩展求值 */

func (n *arrayNode) eval(c *ScriptCtx) (ScriptValue, error) {
	out := make([]ScriptValue, 0, len(n.items))
	for _, it := range n.items {
		v, err := it.eval(c)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

func (n *hashNode) eval(c *ScriptCtx) (ScriptValue, error) {
	m := map[string]ScriptValue{}
	for i, k := range n.keys {
		if i >= len(n.vals) {
			break
		}
		v, err := n.vals[i].eval(c)
		if err != nil {
			return nil, err
		}
		m[k] = v
	}
	return m, nil
}

func (n *lambdaNode) eval(c *ScriptCtx) (ScriptValue, error) {
	// 闭包捕获定义处环境(浅拷贝): 之后即使外层作用域退出, 闭包仍可用
	env := make(map[string]ScriptValue, len(c.env))
	for k, v := range c.env {
		env[k] = v
	}
	return &closure{params: n.params, body: n.body, env: env}, nil
}

// callClosure 调用闭包或 sub。参数按位置绑定, 未带形参时用 @_ 承载。
func callClosure(params []string, body *blockNode, env map[string]ScriptValue, c *ScriptCtx, args []ScriptValue) (ScriptValue, error) {
	nc := c.child(args)
	for k, v := range env {
		nc.env[k] = v
	}
	for i, p := range params {
		if i < len(args) {
			nc.env[p] = args[i]
		} else {
			nc.env[p] = ""
		}
	}
	v, err := body.eval(nc)
	if err != nil {
		if rs, ok := err.(returnSignal); ok {
			return rs.v, nil
		}
		return nil, err
	}
	return v, nil
}

func (n *foreachNode) eval(c *ScriptCtx) (ScriptValue, error) {
	coll, err := n.coll.eval(c)
	if err != nil {
		return nil, err
	}
	var items []foreachPair
	switch t := coll.(type) {
	case []ScriptValue:
		for i, it := range t {
			items = append(items, foreachPair{key: int64(i + 1), val: it})
		}
	case map[string]ScriptValue:
		ks := make([]string, 0, len(t))
		for k := range t {
			ks = append(ks, k)
		}
		sort.Strings(ks)
		for _, k := range ks {
			items = append(items, foreachPair{key: k, val: t[k]})
		}
	case string:
		if t != "" {
			items = append(items, foreachPair{key: int64(1), val: t})
		}
	}
	// 原版语义: 跳过重复元素(脚本常靠它去重)
	seen := map[string]bool{}
	for _, it := range items {
		key := toStr(it.val)
		if seen[key] {
			continue
		}
		seen[key] = true
		c.set(n.name, it.val)
		if n.key != "" {
			c.set(n.key, it.key)
		}
		if n.name == "_" {
			c.args = []ScriptValue{it.val}
		}
		_, err := n.body.eval(c)
		if err != nil {
			if rs, ok := err.(returnSignal); ok {
				return rs.v, nil
			}
			if _, ok := err.(breakSignal); ok {
				break
			}
			if _, ok := err.(continueSignal); ok {
				continue
			}
			return nil, err
		}
	}
	return "", nil
}

// foreachPair 让 foreach 同时能拿到键与值
type foreachPair struct {
	key ScriptValue
	val ScriptValue
}

func (n *indexNode) eval(c *ScriptCtx) (ScriptValue, error) {
	obj, err := n.obj.eval(c)
	if err != nil {
		return nil, err
	}
	k, err := n.key.eval(c)
	if err != nil {
		return nil, err
	}
	ks := toStr(k)
	switch t := obj.(type) {
	case map[string]ScriptValue:
		if v, ok := t[ks]; ok {
			return v, nil
		}
		return "", nil
	case []ScriptValue:
		// 原版数组下标从 1 开始
		i := toInt(k)
		if i >= 1 && int(i) <= len(t) {
			return t[i-1], nil
		}
		return "", nil
	case string:
		parts := strings.Split(t, "\n")
		i := toInt(k)
		if i >= 1 && int(i) <= len(parts) {
			return parts[i-1], nil
		}
		return "", nil
	}
	return "", nil
}

func (n *varCallNode) eval(c *ScriptCtx) (ScriptValue, error) {
	args := make([]ScriptValue, 0, len(n.args))
	for _, a := range n.args {
		v, err := a.eval(c)
		if err != nil {
			return nil, err
		}
		args = append(args, v)
	}
	fv, ok := c.get(n.varName)
	if !ok {
		return "", fmt.Errorf("未定义的函数变量 $%s", n.varName)
	}
	return invokeCallable(fv, c, args)
}

func (n *dynCallNode) eval(c *ScriptCtx) (ScriptValue, error) {
	fv, err := n.fn.eval(c)
	if err != nil {
		return nil, err
	}
	args := make([]ScriptValue, 0, len(n.args))
	for _, a := range n.args {
		v, err := a.eval(c)
		if err != nil {
			return nil, err
		}
		args = append(args, v)
	}
	return invokeCallable(fv, c, args)
}

// invokeCallable 统一处理 closure 值 / 名字字符串 / subDef
func invokeCallable(fv ScriptValue, c *ScriptCtx, args []ScriptValue) (ScriptValue, error) {
	switch f := fv.(type) {
	case *closure:
		return callClosure(f.params, f.body, f.env, c, args)
	case *subDef:
		return callClosure(f.params, f.body, nil, c, args)
	case string:
		if f != "" && c.engine != nil {
			if fn, ok := c.engine.builtins[f]; ok {
				return fn(c, args)
			}
			if sub, ok := c.engine.lookupSub(f); ok {
				return callClosure(sub.params, sub.body, nil, c, args)
			}
		}
	}
	return "", fmt.Errorf("不是可调用的值: %v", fv)
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isDigit(s[i]) {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------- 引擎

type builtinFn func(*ScriptCtx, []ScriptValue) (ScriptValue, error)

type Aggressor struct {
	mu          sync.Mutex
	builtins    map[string]builtinFn
	handlers    map[string][]*handlerDef
	commands    map[string]*commandDef
	subs        map[string]*subDef
	menus       []*menuDef
	menubar     []menubarEntry
	loaded      []string
	out         func(string)
	currentName string
	diag        []string
	missing     map[string]bool
	c2          C2Bridge
	includeSeen map[string]bool // include 去重(避免插件互相包含导致死循环)
	includeNest int
	/* topScriptDir 是"当前这次 LoadFile 的主脚本目录", 也就是 script_resource() 的基准。
	 * 由 Load 设置, include 期间保持不变(见 ScriptCtx.resourceBase 的说明)。 */
	topScriptDir string
}

// lookupSub 供 invokeCallable 使用, 不再单独上锁(调用链已在引擎锁内)
func (a *Aggressor) lookupSub(name string) (*subDef, bool) {
	s, ok := a.subs[name]
	return s, ok
}

func NewAggressor(out func(string)) *Aggressor {
	a := &Aggressor{
		builtins: map[string]builtinFn{},
		handlers: map[string][]*handlerDef{},
		commands: map[string]*commandDef{},
		subs:     map[string]*subDef{},
		out:      out,
	}
	a.registerCoreBuiltins()
	a.registerMenuBuiltins()
	a.registerSleepBuiltins()
	a.registerIncludeBuiltins()
	a.RegisterBeaconAPIs() // Beacon API 别名(b*): bridge 为空时静默, 所以放在这里安全
	return a
}

/* registerMenuBuiltins 提供原版 Aggressor 的菜单构建函数。
 * 原版脚本的 popup 体在**加载期**执行, item(...) 把菜单项注册进当前 popup。
 */
func (a *Aggressor) registerMenuBuiltins() {
	a.builtins["debug"] = func(c *ScriptCtx, args []ScriptValue) (ScriptValue, error) {
		return "", nil // debug(级别): 日志开关, 无需动作
	}
	a.builtins["menubar"] = func(c *ScriptCtx, args []ScriptValue) (ScriptValue, error) {
		if len(args) < 2 {
			return "", fmt.Errorf("menubar 需要 (显示名, popup id)")
		}
		a.mu.Lock()
		a.menubar = append(a.menubar, menubarEntry{Label: toStr(args[0]), ID: toStr(args[1])})
		a.mu.Unlock()
		return "", nil
	}
	a.builtins["separator"] = func(c *ScriptCtx, args []ScriptValue) (ScriptValue, error) {
		if tgt := menuTarget(c); tgt != nil {
			tgt.Children = append(tgt.Children, &menuItem{Name: "-", Kind: "sep"})
		}
		return "", nil
	}
	a.builtins["item"] = func(c *ScriptCtx, args []ScriptValue) (ScriptValue, error) {
		tgt := menuTarget(c)
		if tgt == nil {
			return "", nil // 不在菜单上下文中(例如菜单项回调里再调 item), 忽略
		}
		it := &menuItem{Kind: "item", Base: tgt.Base}
		if len(args) > 0 {
			it.Name = toStr(args[0])
		}
		if len(args) > 1 {
			switch h := args[1].(type) {
			case *closure:
				it.Body = h.body
			case *blockNode:
				it.Body = h
			}
		}
		tgt.Children = append(tgt.Children, it)
		return "", nil
	}
	a.builtins["menu"] = func(c *ScriptCtx, args []ScriptValue) (ScriptValue, error) {
		tgt := menuTarget(c)
		if tgt == nil || len(args) == 0 {
			return "", nil
		}
		it := &menuItem{Name: toStr(args[0]), Kind: "menu", Base: tgt.Base}
		if len(args) > 1 {
			switch h := args[1].(type) {
			case *closure:
				it.Body = h.body
			case *blockNode:
				it.Body = h
			}
		}
		tgt.Children = append(tgt.Children, it)
		return "", nil
	}
	a.builtins["popup"] = func(c *ScriptCtx, args []ScriptValue) (ScriptValue, error) {
		return "", nil // popup 块已在解析期建好
	}
	/* lambda({...}, \$x, $a => $b) —— 原版脚本用它给菜单项做回调。
	 * 本引擎的闭包在创建时捕获环境, 引用参数列表无需额外动作。 */
	a.builtins["lambda"] = func(c *ScriptCtx, args []ScriptValue) (ScriptValue, error) {
		if len(args) == 0 {
			return "", nil
		}
		if cl, ok := args[0].(*closure); ok {
			return cl, nil
		}
		if b, ok := args[0].(*blockNode); ok {
			return &closure{body: b}, nil
		}
		return "", nil
	}
	// matched() —— 返回上一次 ismatch 的捕获组(1 基下标, 与原版一致)
	a.builtins["matched"] = func(c *ScriptCtx, args []ScriptValue) (ScriptValue, error) {
		if v, ok := c.get("__matched__"); ok {
			return v, nil
		}
		return []ScriptValue{}, nil
	}
}

// menuTarget 取当前正在构建的菜单节点
func menuTarget(c *ScriptCtx) *menuItem {
	if c == nil {
		return nil
	}
	if v, ok := c.env["__menu__"]; ok {
		if mi, ok := v.(*menuItem); ok {
			return mi
		}
	}
	return nil
}

/* buildMenu 把解析期收集的菜单项合并进一个 popup, 并执行其调用形式语句。
 * 块形式的子菜单会先递归(子树里也可能有调用形式语句)。 */
func (a *Aggressor) buildMenu(md *menuDef, scriptPath string) {
	root := &menuItem{Name: md.Parent, Kind: "menu", Base: md.Base}
	a.buildMenuInto(md, root, scriptPath)
	md.Items = root.Children
}

// buildMenuInto 把 md 的项建进 target 下(顶层 popup 与 include 进来的菜单共用)
func (a *Aggressor) buildMenuInto(md *menuDef, target *menuItem, scriptPath string) {
	for _, it := range md.Items {
		target.Children = append(target.Children, it)
		if it.Kind == "menu" {
			a.execMenuBody(it, scriptPath)
		}
	}
	if md.Body != nil && len(md.Body.stmts) > 0 {
		old := target.Body
		target.Body = md.Body
		a.execMenuBody(target, scriptPath)
		target.Body = old
	}
}

// execMenuBody 执行菜单节点体内的语句(item(...)/separator()), 注册进该节点
func (a *Aggressor) execMenuBody(target *menuItem, scriptPath string) {
	if target == nil {
		return
	}
	body := target.Body
	target.Body = nil
	if body == nil || len(body.stmts) == 0 {
		return
	}
	ctx := &ScriptCtx{
		env:          map[string]ScriptValue{"__menu__": target},
		engine:       a,
		visited:      map[string]bool{},
		lenient:      true,
		scriptPath:   scriptPath,
		resourceBase: firstNonEmpty(target.Base, a.topScriptDir),
	}
	if _, err := body.eval(ctx); err != nil {
		if _, ok := err.(returnSignal); !ok {
			a.reportErr(0, err)
		}
	}
}

/* ---------------------------------------------------------------- include 家族
 *
 * 真实第三方插件包(LSTAR / OLa / TaoWu / 谢公子 / Ladon)全是 loader 模式:
 *   主文件 LSTAR/LSTAR.cna:
 *     popup beacon_bottom { menu "LSTAR"{ include(script_resource("modules/X.cna")); } }
 *   子模块 modules/X.cna:
 *     menu "☆ 信息收集" { item "..." { ... } }
 * 所以 include 必须:
 *   1. 以**调用它的那个脚本文件**为基准解析 script_resource()
 *   2. 把被包含文件的顶层菜单挂到**当前正在构建的菜单**下(而不是另开一个顶层 popup)
 *   3. 被包含文件里的 on/command/sub 照常注册
 */
func (a *Aggressor) registerIncludeBuiltins() {
	a.builtins["script_resource"] = func(c *ScriptCtx, args []ScriptValue) (ScriptValue, error) {
		if len(args) == 0 {
			return "", nil
		}
		rel := strings.TrimLeft(toStr(args[0]), "/\\") // 插件写成 "/scripts/x.exe" 这种
		rel = filepath.FromSlash(rel)
		base := ""
		if c != nil {
			base = c.resourceBase
			if base == "" {
				base = filepath.Dir(c.scriptPath)
			}
		}
		if base == "" {
			return rel, nil
		}
		return filepath.Join(base, rel), nil
	}
	a.builtins["include"] = func(c *ScriptCtx, args []ScriptValue) (ScriptValue, error) {
		if len(args) == 0 {
			return "", nil
		}
		path := toStr(args[0])
		if path == "" {
			return "", nil
		}
		if err := a.includeFile(path, c); err != nil {
			return "", err
		}
		return "", nil
	}
}

// includeFile 把一个 .cna 的内容并入当前引擎(见 registerIncludeBuiltins 的说明)
func (a *Aggressor) includeFile(path string, c *ScriptCtx) error {
	if a.includeNest > 32 {
		return fmt.Errorf("include 嵌套过深(疑似循环包含): %s", path)
	}
	a.mu.Lock()
	if a.includeSeen == nil {
		a.includeSeen = map[string]bool{}
	}
	if a.includeSeen[path] {
		a.mu.Unlock()
		return nil // 同一个文件只并入一次
	}
	a.includeSeen[path] = true
	a.mu.Unlock()

	b, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("include 打不开 %s: %v", path, err)
	}
	lx := &lexer{src: string(b), line: 1, name: path}
	toks, err := lx.tokens()
	if err != nil {
		return err
	}
	p := &parser{toks: toks, name: path, baseDir: a.topScriptDir}
	prog, handlers, commands, menus, subs, err := p.parseProgram()
	if err != nil {
		return err
	}

	a.mu.Lock()
	for _, h := range handlers {
		a.handlers[h.Event] = append(a.handlers[h.Event], h)
	}
	for _, cmd := range commands {
		a.commands[cmd.Name] = cmd
	}
	for _, s := range subs {
		a.subs[s.name] = s
	}
	a.loaded = append(a.loaded, path)
	a.mu.Unlock()

	a.includeNest++
	defer func() { a.includeNest-- }()

	parent := menuTarget(c)
	for _, md := range menus {
		md.Src = path
		nm := md.Name
		if nm == "" {
			nm = md.Parent
		}
		if parent != nil {
			it := &menuItem{Name: nm, Kind: "menu", Base: a.topScriptDir}
			a.buildMenuInto(md, it, path)
			parent.Children = append(parent.Children, it)
		} else {
			// 不在菜单上下文(例如顶层 include): 按普通 popup 注册
			a.buildMenu(md, path)
			a.mu.Lock()
			a.menus = append(a.menus, md)
			a.mu.Unlock()
		}
	}
	// 被包含文件里的顶层裸语句(欢迎语/变量初始化之类)
	if prog != nil && len(prog.stmts) > 0 {
		sub := &ScriptCtx{
			env:          map[string]ScriptValue{},
			args:         c.args,
			engine:       a,
			visited:      map[string]bool{},
			lenient:      true,
			scriptPath:   path,
			resourceBase: c.resourceBase, // 继承: script_resource 的基准是主脚本目录
		}
		if parent != nil {
			sub.env["__menu__"] = parent
		}
		if _, err := prog.eval(sub); err != nil {
			if _, ok := err.(returnSignal); !ok {
				a.reportErr(0, err)
			}
		}
	}
	return nil
}

func (a *Aggressor) SetBuiltin(name string, fn builtinFn) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.builtins[name] = fn
}

func (a *Aggressor) print(s string) {
	if a.out != nil {
		a.out(s)
	}
}

func (a *Aggressor) Diag() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]string, len(a.diag))
	copy(out, a.diag)
	return out
}

// LoadFile 加载一个 .cna 脚本。
// 它是"一次顶层加载": 本次加载期间 script_resource() 的基准目录 = 这个文件的目录,
// include 进来的子模块继承同一基准(第三方插件包依赖这个语义)。
func (a *Aggressor) LoadFile(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	prev := a.topScriptDir
	a.topScriptDir = filepath.Dir(path)
	defer func() { a.topScriptDir = prev }()
	return a.Load(string(b), path)
}

// Load 从源码加载
func (a *Aggressor) Load(src, name string) error {
	lx := &lexer{src: src, line: 1, name: name}
	toks, err := lx.tokens()
	if err != nil {
		return err
	}
	p := &parser{toks: toks, name: name, baseDir: filepath.Dir(name)}
	prog, handlers, commands, menus, subs, err := p.parseProgram()
	if err != nil {
		return err
	}

	a.mu.Lock()
	a.currentName = name
	for _, h := range handlers {
		a.handlers[h.Event] = append(a.handlers[h.Event], h)
	}
	for _, c := range commands {
		a.commands[c.Name] = c
	}
	for _, s := range subs {
		a.subs[s.name] = s
	}
	a.loaded = append(a.loaded, name)
	a.mu.Unlock()

	/* 菜单体与顶层裸语句在加载期求值: item()/separator() 注册菜单项,
	 * menubar() 登记菜单栏, debug() 是日志开关(空实现)。
	 * 必须放在锁外 —— 求值链会经 reportErr 再取同一把锁。 */
	for _, md := range menus {
		a.buildMenu(md, name)
	}
	if prog != nil && len(prog.stmts) > 0 {
		ctx := &ScriptCtx{env: map[string]ScriptValue{}, engine: a, visited: map[string]bool{},
			lenient: true, scriptPath: name}
		if _, err := prog.eval(ctx); err != nil {
			if _, ok := err.(returnSignal); !ok {
				a.reportErr(0, err)
			}
		}
	}

	a.mu.Lock()
	a.menus = append(a.menus, menus...)
	a.currentName = ""
	a.mu.Unlock()
	return nil
}

// Fire 触发事件钩子。返回处理过的钩子数。
func (a *Aggressor) Fire(event string, args ...ScriptValue) int {
	a.mu.Lock()
	hs := append([]*handlerDef{}, a.handlers[event]...)
	// 前缀匹配: on beacon_initial_$arch 这类钩子名在解析期被简化, 此处做前缀回退
	for ev, list := range a.handlers {
		if ev != event && strings.HasPrefix(ev, event+"_") {
			hs = append(hs, list...)
		}
	}
	a.mu.Unlock()

	n := 0
	for _, h := range hs {
		ctx := &ScriptCtx{env: map[string]ScriptValue{}, args: args, engine: a, visited: map[string]bool{}}
		if _, err := h.Body.eval(ctx); err != nil {
			if _, ok := err.(returnSignal); ok {
				n++
				continue
			}
			a.reportErr(h.Line, err)
			continue
		}
		n++
	}
	return n
}

// RunCommand 执行已注册的脚本命令。返回是否命中。
func (a *Aggressor) RunCommand(name string, args []ScriptValue) (bool, error) {
	a.mu.Lock()
	def, ok := a.commands[name]
	a.mu.Unlock()
	if !ok {
		return false, nil
	}
	ctx := &ScriptCtx{env: map[string]ScriptValue{}, args: args, engine: a, visited: map[string]bool{}}
	if _, err := def.Body.eval(ctx); err != nil {
		if rs, ok := err.(returnSignal); ok {
			_ = rs
			return true, nil
		}
		return true, err
	}
	return true, nil
}

// CommandNames 列出脚本注册的全部命令 (含 alias)
func (a *Aggressor) CommandNames() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]string, 0, len(a.commands))
	for k := range a.commands {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// IsAlias 判断某命令是否由 alias 定义
func (a *Aggressor) IsAlias(name string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	c, ok := a.commands[name]
	return ok && c.IsAlias
}

// Menus 返回菜单定义 (供 GUI 渲染)
func (a *Aggressor) Menus() []*menuDef {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]*menuDef, len(a.menus))
	copy(out, a.menus)
	return out
}

/* StripMnemonic 去掉 Aggressor 菜单名里的 & 助记符。
 * 显示侧与查找侧都要用它: 脚本写 "&Interact", GUI 显示 "Interact",
 * 两边必须能对上。&& 表示字面 &。 */
func StripMnemonic(s string) string {
	var sb strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '&' {
			if i+1 < len(s) && s[i+1] == '&' {
				sb.WriteByte('&')
				i++
				continue
			}
			continue
		}
		sb.WriteByte(s[i])
	}
	return sb.String()
}

/* FindMenuItem 按 (popup 名, 菜单项名) 查找可执行的菜单项。
 * 菜单项的名字只在脚本里存在(GUI 侧渲染的是脚本菜单树),
 * 所以这里是"点击插件菜单项"这条链路的唯一入口。
 * parent 为空时做全局兜底查找。 */
func (a *Aggressor) FindMenuItem(parent, name string) *menuItem {
	want := StripMnemonic(strings.TrimSpace(name))
	if want == "" {
		return nil
	}
	var found *menuItem
	var walk func(items []*menuItem)
	walk = func(items []*menuItem) {
		for _, it := range items {
			if found != nil {
				return
			}
			if it.Kind != "sep" && it.Body != nil && StripMnemonic(it.Name) == want {
				found = it
				return
			}
			walk(it.Children)
		}
	}
	menus := a.Menus()
	// 先按 parent 精确匹配
	for _, md := range menus {
		if md.Parent != parent && md.Name != parent {
			continue
		}
		walk(md.Items)
	}
	// 兜底: 有些 popup 的 parent 名与脚本里的写法不完全一致
	if found == nil && parent != "" {
		for _, md := range menus {
			walk(md.Items)
			if found != nil {
				break
			}
		}
	}
	return found
}

// MenuNames 列出某个 popup 下的可执行菜单项名(剥掉助记符), 供诊断/自检
func (a *Aggressor) MenuNames(parent string) []string {
	out := []string{}
	var walk func(items []*menuItem)
	walk = func(items []*menuItem) {
		for _, it := range items {
			if it.Kind != "sep" && it.Body != nil {
				out = append(out, StripMnemonic(it.Name))
			}
			walk(it.Children)
		}
	}
	for _, md := range a.Menus() {
		if md.Parent != parent && md.Name != parent {
			continue
		}
		walk(md.Items)
	}
	sort.Strings(out)
	return out
}

/* RunMenuItem 执行某个菜单项 body。
 *
 * 用宽容模式: 插件菜单项普遍会调 Cobalt Strike 客户端私有 API
 * (open*Dialog / show_message / insert_menu ...), 这些本引擎没有实现。
 * 直接抛错会让"点了没反应", 全静默又会骗人 —— 所以这里跳过它们,
 * 并**把本次跳过的函数名回报给调用方**, 由 GUI 显示成警告。
 * args 的第一个元素按约定是会话号($1)。
 */

// firstNonEmpty 取第一个非空字符串
func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func (a *Aggressor) RunMenuItem(it *menuItem, args ...ScriptValue) ([]string, error) {
	if it == nil || it.Body == nil {
		return nil, nil
	}
	before := map[string]bool{}
	a.mu.Lock()
	for k := range a.missing {
		before[k] = true
	}
	a.mu.Unlock()

	/* script_resource 的基准来自菜单项自己固化的 Base(定义它的主脚本目录)。
	 * 点击是运行期行为, 那时顶层加载早已结束, 拿不到"当前脚本"上下文。 */
	ctx := &ScriptCtx{env: map[string]ScriptValue{}, args: args, engine: a,
		visited: map[string]bool{}, lenient: true,
		scriptPath:   it.Base,
		resourceBase: firstNonEmpty(it.Base, a.topScriptDir)}
	_, err := it.Body.eval(ctx)
	if _, ok := err.(returnSignal); ok {
		err = nil
	}

	skipped := []string{}
	a.mu.Lock()
	for k := range a.missing {
		if !before[k] {
			skipped = append(skipped, k)
		}
	}
	a.mu.Unlock()
	sort.Strings(skipped)
	return skipped, err
}

// IsSepKind 判断是不是分隔线(渲染成 Separator)
func (it *menuItem) IsSepKind() bool { return it.Kind == "sep" }

// Menubar 返回 menubar("显示名","popup id") 登记项(决定 GUI 菜单栏顺序)
func (a *Aggressor) Menubar() []map[string]string {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]map[string]string, 0, len(a.menubar))
	for _, e := range a.menubar {
		out = append(out, map[string]string{"label": e.Label, "id": e.ID})
	}
	return out
}

// LoadedScripts 已加载脚本路径
func (a *Aggressor) LoadedScripts() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]string, len(a.loaded))
	copy(out, a.loaded)
	return out
}

// noteMissing 记录一次未实现的函数(去重), 供 /api/scripts 如实汇报
func (a *Aggressor) noteMissing(name string) {
	a.mu.Lock()
	if a.missing == nil {
		a.missing = map[string]bool{}
	}
	if a.missing[name] {
		a.mu.Unlock()
		return
	}
	a.missing[name] = true
	a.mu.Unlock()
	a.reportErr(0, fmt.Errorf("脚本调用了未实现的函数 %s [%s] (已跳过, 返回值按空处理)",
		name, MissingKind(name)))
}

/* MissingKind 给未实现的函数分类。
 * 这三类的含义完全不同, 混成一句"本引擎没有 CS 客户端 UI"会误导:
 *   Beacon API  —— 本来就是"给 beacon 下发任务", 我们应该适配(todo, 不是做不到)
 *   BOF/Beacon 注册类 —— 同上
 *   CS 客户端 UI —— 构建的是 CS 自己的界面, 我们确实没有, 不可能实现 */
func MissingKind(name string) string {
	if strings.HasPrefix(name, "beacon_") {
		return "Beacon/BOF API 未适配"
	}
	if len(name) > 1 && name[0] == 'b' && name[1] >= 'a' && name[1] <= 'z' {
		return "Beacon API 未适配"
	}
	if len(name) > 0 && name[0] >= 'A' && name[0] <= 'Z' {
		return "客户端显示格式函数"
	}
	return "CS 客户端 UI 函数"
}

// MissingFuncsDetailed 返回未实现函数及其分类(排序), 供 REST 汇报
func (a *Aggressor) MissingFuncsDetailed() []map[string]string {
	names := a.MissingFuncs()
	out := make([]map[string]string, 0, len(names))
	for _, n := range names {
		out = append(out, map[string]string{"name": n, "kind": MissingKind(n)})
	}
	return out
}

// MissingFuncs 返回被跳过的未实现函数名(排序)
func (a *Aggressor) MissingFuncs() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]string, 0, len(a.missing))
	for k := range a.missing {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func (a *Aggressor) reportErr(line int, err error) {
	msg := fmt.Sprintf("[!] 脚本错误 %s:%d: %v", a.currentName, line, err)
	a.mu.Lock()
	a.diag = append(a.diag, msg)
	if len(a.diag) > 200 {
		a.diag = a.diag[len(a.diag)-100:]
	}
	a.mu.Unlock()
	a.print(msg)
}
