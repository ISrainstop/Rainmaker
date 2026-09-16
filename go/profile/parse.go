// Package profile 实现与 Malleable C2 profile 语法兼容的解析器与运行期模型。
//
// 本包为完全自研实现: 仅遵循公开的 profile 语法约定, 不含任何第三方或商业
// C2 产品的原始代码, 且只依赖 Go 标准库。
//
// 文件分工:
//
//	parse.go  词法分析 + 语法分析, 产出与语义无关的语法树 (Document)
//	model.go  语义模型 (Profile/HTTPBlock/Endpoint/Transform) 与变换算法
//	load.go   语法树 -> 语义模型 的投影、默认值填充与校验
//
// 分层策略: 解析层严格 (位置与结构错误立即报错, 错误形如 "文件:行: 消息"),
// 语义层宽容 (未知块 / 未知选项被记录而不报错), 在语法兼容与错误可见之间取平衡。
package profile

import (
	"fmt"
	"os"
	"strings"
)

// ---------------------------------------------------------------- 位置与错误

// Pos 表示源文件中的一个位置。
type Pos struct {
	File string
	Line int
	Col  int
}

// String 返回 "文件:行:列" 形式的位置。
func (p Pos) String() string {
	file := p.File
	if file == "" {
		file = "<profile>"
	}
	return fmt.Sprintf("%s:%d:%d", file, p.Line, p.Col)
}

// Error 是带源位置的 profile 错误, 固定输出 "文件:行: 消息"。
type Error struct {
	Pos Pos
	Msg string
}

func (e *Error) Error() string {
	file := e.Pos.File
	if file == "" {
		file = "<profile>"
	}
	if e.Pos.Line <= 0 {
		return file + ": " + e.Msg
	}
	return fmt.Sprintf("%s:%d: %s", file, e.Pos.Line, e.Msg)
}

// errorf 构造带位置的错误。
func errorf(pos Pos, format string, args ...any) *Error {
	return &Error{Pos: pos, Msg: fmt.Sprintf(format, args...)}
}

// at 给普通错误补上位置前缀 (位置为空时原样返回)。
func at(pos Pos, err error) error {
	if err == nil {
		return nil
	}
	if pos.Line <= 0 {
		return err
	}
	return &Error{Pos: pos, Msg: err.Error()}
}

// ---------------------------------------------------------------- 语法树

// 语句种类常量。
const (
	KindSet       = "set"       // set name "value" ["value2" ...];
	KindSetBlock  = "set-block" // set name { ... }
	KindHeader    = "header"    // header "Name" "Value"; / header "Name"; / header "Name: Value";
	KindParameter = "parameter" // parameter "name" "value"; / parameter "name";
	KindTransform = "transform" // base64;  netbiosu;  prepend "x";
	KindString    = "string"    // string "...";
	KindData      = "data"      // data "...";
	KindStrRep    = "strrep"    // strrep "from" "to";
	KindBlock     = "block"     // name { ... }
)

// Stmt 是语法树中的一条语句或一个块。
type Stmt struct {
	Kind   string   // 见上面 Kind* 常量
	Name   string   // set 的键名 / header|parameter 名 / 块名 / 变换名
	Value  string   // 第一个字符串值
	Values []string // 全部字符串值 (set 支持多段字符串)
	Arg    string   // 变换参数, 例如 prepend|append 的字符串
	Pos    Pos      // 语句起始位置
	Body   []*Stmt  // 块体
}

// Document 是一个解析完成的 profile 文件。
type Document struct {
	File  string
	Stmts []*Stmt
}

// Block 返回首个指定名字的顶层块, 不存在返回 nil。
func (d *Document) Block(name string) *Stmt {
	for _, st := range d.Stmts {
		if st.Kind == KindBlock && st.Name == name {
			return st
		}
	}
	return nil
}

// Blocks 返回全部指定名字的顶层块。
func (d *Document) Blocks(name string) []*Stmt {
	var out []*Stmt
	for _, st := range d.Stmts {
		if st.Kind == KindBlock && st.Name == name {
			out = append(out, st)
		}
	}
	return out
}

// Sets 返回顶层 set 语句构成的映射 (同名后者覆盖前者)。
func (d *Document) Sets() map[string]string {
	out := map[string]string{}
	for _, st := range d.Stmts {
		if st.Kind == KindSet {
			out[st.Name] = st.Value
		}
	}
	return out
}

// ---------------------------------------------------------------- 词法分析

type tokenKind int

const (
	tokEOF tokenKind = iota
	tokIdent
	tokString
	tokLBrace
	tokRBrace
	tokSemi
)

type token struct {
	kind tokenKind
	text string
	pos  Pos
}

func (t token) describe() string {
	switch t.kind {
	case tokEOF:
		return "文件结束"
	case tokString:
		return fmt.Sprintf("字符串 %q", t.text)
	case tokLBrace:
		return `"{"`
	case tokRBrace:
		return `"}"`
	case tokSemi:
		return `";"`
	default:
		return fmt.Sprintf("%q", t.text)
	}
}

type scanner struct {
	src  []byte
	file string
	off  int
	line int
	col  int
}

func newScanner(src []byte, file string) *scanner {
	return &scanner{src: src, file: file, off: 0, line: 1, col: 1}
}

func (s *scanner) pos() Pos { return Pos{File: s.file, Line: s.line, Col: s.col} }

// advance 前进 n 个字节并同步行列号。
func (s *scanner) advance(n int) []byte {
	if n <= 0 {
		return nil
	}
	end := s.off + n
	if end > len(s.src) {
		end = len(s.src)
	}
	buf := s.src[s.off:end]
	s.off = end
	for _, c := range buf {
		if c == '\n' {
			s.line++
			s.col = 1
		} else {
			s.col++
		}
	}
	return buf
}

// isWordDelim 判断字节是否为词法分隔符。
func isWordDelim(c byte) bool {
	switch c {
	case ' ', '\t', '\r', '\n', '{', '}', ';', '"', '#':
		return true
	}
	return false
}

// skipSpaceAndComments 跳过空白与 "#" 行注释。
func (s *scanner) skipSpaceAndComments() {
	for s.off < len(s.src) {
		c := s.src[s.off]
		switch {
		case c == ' ' || c == '\t' || c == '\r' || c == '\n':
			s.advance(1)
		case c == '#':
			for s.off < len(s.src) && s.src[s.off] != '\n' {
				s.advance(1)
			}
		default:
			return
		}
	}
}

// scanWord 读取一个裸词 (标识符/键名/块名/变换名)。
func (s *scanner) scanWord() string {
	n := 0
	for s.off+n < len(s.src) && !isWordDelim(s.src[s.off+n]) {
		n++
	}
	if n == 0 {
		return ""
	}
	return string(s.advance(n))
}

func isHexDigit(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func hexDigitVal(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	}
	return 0
}

// scanString 读取双引号字符串。
//
// 转义规则刻意保持最小: 只识别 \" 与 \\, 其余 "\X" 原样保留 (含反斜杠)。
// 这样 Windows 路径 "%windir%\SysWOW64\rundll32.exe" 与双写形式
// "%windir%\\SysWOW64\\rundll32.exe" 都能得到同一个正确结果。
func (s *scanner) scanString() (string, error) {
	start := s.pos()
	s.advance(1) // 开引号
	var sb strings.Builder
	for {
		if s.off >= len(s.src) {
			return "", errorf(start, "字符串未闭合")
		}
		c := s.src[s.off]
		switch {
		case c == '\n':
			return "", errorf(start, "字符串未闭合: 字符串内出现裸换行")
		case c == '"':
			s.advance(1)
			return sb.String(), nil
		case c == '\\' && s.off+1 < len(s.src):
			e := s.src[s.off+1]
			switch e {
			case '"':
				sb.WriteByte('"')
				s.advance(2)
			case '\\':
				sb.WriteByte('\\')
				s.advance(2)
			default:
				// 未知转义: 保留反斜杠本身, 保证路径类值无损
				sb.WriteByte('\\')
				s.advance(1)
			}
		default:
			sb.WriteByte(c)
			s.advance(1)
		}
	}
}

// tokenize 把源码切成 token 流, 末尾必定有一个 tokEOF。
func tokenize(src []byte, file string) ([]token, error) {
	s := newScanner(src, file)
	var toks []token
	for {
		s.skipSpaceAndComments()
		if s.off >= len(s.src) {
			toks = append(toks, token{kind: tokEOF, pos: s.pos()})
			return toks, nil
		}
		pos := s.pos()
		switch c := s.src[s.off]; c {
		case '{':
			s.advance(1)
			toks = append(toks, token{kind: tokLBrace, text: "{", pos: pos})
		case '}':
			s.advance(1)
			toks = append(toks, token{kind: tokRBrace, text: "}", pos: pos})
		case ';':
			s.advance(1)
			toks = append(toks, token{kind: tokSemi, text: ";", pos: pos})
		case '"':
			val, err := s.scanString()
			if err != nil {
				return nil, err
			}
			toks = append(toks, token{kind: tokString, text: val, pos: pos})
		default:
			word := s.scanWord()
			if word == "" {
				return nil, errorf(pos, "无法识别的字符 %q", string(rune(c)))
			}
			toks = append(toks, token{kind: tokIdent, text: word, pos: pos})
		}
	}
}

// ---------------------------------------------------------------- 语法分析

// 可作为独立语句出现的变换名。
var transformWords = map[string]bool{
	TransformBase64:    true,
	TransformBase64URL: true,
	TransformNetBIOS:   true,
	TransformNetBIOSU:  true,
	TransformMask:      true,
	TransformPrint:     true,
	TransformURIAppend: true,
	TransformPrepend:   true,
	TransformAppend:    true,
}

type parser struct {
	toks []token
	i    int
	file string
}

// Parse 解析 profile 源码, filename 仅用于错误消息与语法树标记。
//
// 任何输入都不会导致 panic: 结构错误一律以 *Error 返回, 且带 文件:行。
func Parse(src []byte, filename string) (*Document, error) {
	if filename == "" {
		filename = "<profile>"
	}
	toks, err := tokenize(src, filename)
	if err != nil {
		return nil, err
	}
	p := &parser{toks: toks, file: filename}
	stmts, err := p.parseStmts(Pos{File: filename}, false, "顶层")
	if err != nil {
		return nil, err
	}
	return &Document{File: filename, Stmts: stmts}, nil
}

// ParseFile 读取并解析一个 profile 文件。
func ParseFile(path string) (*Document, error) {
	src, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取 profile 失败: %w", err)
	}
	return Parse(src, path)
}

func (p *parser) peek() token { return p.toks[p.i] }

// next 返回当前 token 并前进; 位于 EOF 时原地返回, 保证下标永不越界。
func (p *parser) next() token {
	t := p.toks[p.i]
	if t.kind != tokEOF {
		p.i++
	}
	return t
}

// preview 重建自 start 起同一条语句的原文, 用于错误提示 (例如 `set foo`)。
func (p *parser) preview(start int) string {
	if start >= len(p.toks) {
		return ""
	}
	line := p.toks[start].pos.Line
	var sb strings.Builder
	for i := start; i < len(p.toks) && i < start+4; i++ {
		t := p.toks[i]
		if t.kind == tokEOF || t.pos.Line != line {
			break
		}
		switch t.kind {
		case tokSemi, tokRBrace, tokLBrace:
			return strings.TrimSpace(sb.String())
		case tokString:
			if sb.Len() > 0 {
				sb.WriteByte(' ')
			}
			sb.WriteString(`"` + t.text + `"`)
		default:
			if sb.Len() > 0 {
				sb.WriteByte(' ')
			}
			sb.WriteString(t.text)
		}
	}
	return strings.TrimSpace(sb.String())
}

// parseStmts 解析语句序列; inBlock 为真时遇到 "}" 结束并消费该右花括号。
func (p *parser) parseStmts(blockPos Pos, inBlock bool, label string) ([]*Stmt, error) {
	var out []*Stmt
	for {
		t := p.peek()
		switch t.kind {
		case tokEOF:
			if inBlock {
				return nil, errorf(blockPos, "块未闭合: %s 在文件结束时仍未关闭", label)
			}
			return out, nil
		case tokRBrace:
			if !inBlock {
				return nil, errorf(t.pos, `意外的 "}" (没有与之配对的 "{")`)
			}
			p.next()
			return out, nil
		case tokSemi:
			p.next() // 容忍多余分号
			continue
		case tokLBrace:
			return nil, errorf(t.pos, `意外的 "{"`)
		}
		st, err := p.parseStmt()
		if err != nil {
			return nil, err
		}
		if st != nil {
			out = append(out, st)
		}
	}
}

func (p *parser) parseStmt() (*Stmt, error) {
	t := p.peek()
	if t.kind != tokIdent {
		return nil, errorf(t.pos, "未知语句 %q", p.preview(p.i))
	}
	switch t.text {
	case "set":
		return p.parseSet()
	case "header":
		return p.parseDecl(KindHeader, true)
	case "parameter":
		return p.parseDecl(KindParameter, true)
	case "string":
		return p.parseDecl(KindString, false)
	case "data":
		return p.parseDecl(KindData, false)
	case "strrep":
		return p.parseStrRep()
	}
	if transformWords[t.text] {
		return p.parseTransform()
	}
	if p.toks[p.i+1].kind == tokLBrace {
		return p.parseBlock()
	}
	return nil, errorf(t.pos, "未知语句 %q (既不是已知变换, 也不是已知语句或块)", p.preview(p.i))
}

// parseBlock 解析 `name { ... }`。
func (p *parser) parseBlock() (*Stmt, error) {
	nameTok := p.next()
	openTok := p.next()
	body, err := p.parseStmts(openTok.pos, true, fmt.Sprintf("块 %q", nameTok.text))
	if err != nil {
		return nil, err
	}
	return &Stmt{Kind: KindBlock, Name: nameTok.text, Pos: nameTok.pos, Body: body}, nil
}

// parseSet 解析 `set name "v1" ["v2" ...];` 与 `set name { ... }`。
func (p *parser) parseSet() (*Stmt, error) {
	start := p.i
	setTok := p.next()
	nameTok := p.peek()
	if nameTok.kind != tokIdent {
		return nil, errorf(setTok.pos, "未知语句 %q", p.preview(start))
	}
	p.next()

	switch p.peek().kind {
	case tokLBrace:
		openTok := p.next()
		body, err := p.parseStmts(openTok.pos, true, fmt.Sprintf("块 %q", "set "+nameTok.text))
		if err != nil {
			return nil, err
		}
		return &Stmt{
			Kind: KindSetBlock,
			Name: nameTok.text,
			Pos:  setTok.pos,
			Body: body,
		}, nil
	case tokString:
		var vals []string
		for p.peek().kind == tokString {
			vals = append(vals, p.next().text)
		}
		if p.peek().kind != tokSemi {
			return nil, errorf(p.peek().pos,
				"语句缺少分号: set %q 起始于第 %d 行, 其值之后遇到 %s",
				nameTok.text, setTok.pos.Line, p.peek().describe())
		}
		p.next()
		return &Stmt{
			Kind:   KindSet,
			Name:   nameTok.text,
			Value:  vals[0],
			Values: vals,
			Pos:    setTok.pos,
		}, nil
	default:
		// 无值 (set foo;) 或其它畸形写法: 统一按未知语句报出, 便于定位
		return nil, errorf(setTok.pos, "未知语句 %q", p.preview(start))
	}
}

// parseDecl 解析 header / parameter / string / data 语句。
//
// kv 为真时接受两种形式:
//
//	header "Name" "Value";   静态头
//	header "Name";           变换链中的放置声明, 或 "Name: Value" 单串形式
func (p *parser) parseDecl(kind string, kv bool) (*Stmt, error) {
	start := p.i
	kw := p.next()
	if p.peek().kind != tokString {
		return nil, errorf(kw.pos, "未知语句 %q", p.preview(start))
	}
	st := &Stmt{Kind: kind, Pos: kw.pos}
	first := p.next().text

	if kv {
		if p.peek().kind == tokString {
			second := p.next().text
			st.Name, st.Value = first, second
			st.Values = []string{first, second}
		} else {
			st.Name = first
			st.Values = []string{first}
			if i := strings.IndexByte(first, ':'); i > 0 {
				st.Name = strings.TrimSpace(first[:i])
				st.Value = strings.TrimSpace(first[i+1:])
				st.Values = []string{st.Name, st.Value, first}
			}
		}
	} else {
		st.Value = first
		st.Values = []string{first}
		for p.peek().kind == tokString { // 宽容: 允许多段字符串
			st.Values = append(st.Values, p.next().text)
		}
	}

	if p.peek().kind != tokSemi {
		return nil, errorf(p.peek().pos,
			"语句缺少分号: %s 起始于第 %d 行, 之后遇到 %s",
			kw.text, kw.pos.Line, p.peek().describe())
	}
	p.next()
	return st, nil
}

// parseStrRep 解析 `strrep "from" "to";`。
func (p *parser) parseStrRep() (*Stmt, error) {
	start := p.i
	kw := p.next()
	if p.peek().kind != tokString {
		return nil, errorf(kw.pos, "未知语句 %q", p.preview(start))
	}
	from := p.next().text
	if p.peek().kind != tokString {
		return nil, errorf(kw.pos, "strrep 需要两个字符串参数")
	}
	to := p.next().text
	if p.peek().kind != tokSemi {
		return nil, errorf(p.peek().pos, "语句缺少分号: strrep 之后遇到 %s", p.peek().describe())
	}
	p.next()
	return &Stmt{
		Kind:   KindStrRep,
		Name:   from,
		Value:  to,
		Arg:    to,
		Values: []string{from, to},
		Pos:    kw.pos,
	}, nil
}

// parseTransform 解析变换语句。
func (p *parser) parseTransform() (*Stmt, error) {
	t := p.next()
	st := &Stmt{Kind: KindTransform, Name: t.text, Pos: t.pos}
	switch t.text {
	case TransformPrepend, TransformAppend:
		if p.peek().kind != tokString {
			return nil, errorf(t.pos, "变换 %q 需要字符串参数, 实际遇到 %s",
				t.text, p.peek().describe())
		}
		st.Arg = p.next().text
		st.Value = st.Arg
		st.Values = []string{st.Arg}
	}
	if p.peek().kind != tokSemi {
		return nil, errorf(p.peek().pos, "语句缺少分号: 变换 %q 之后遇到 %s",
			t.text, p.peek().describe())
	}
	p.next()
	return st, nil
}
