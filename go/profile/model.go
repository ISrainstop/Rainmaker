package profile

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"
)

// ---------------------------------------------------------------- 变换常量

// 支持的变换名。head/parameter/uri-append 属于"放置类"变换: 它们标记数据
// 的落点, 本身不改变字节内容。
const (
	TransformBase64    = "base64"     // 标准 base64 (带 padding)
	TransformBase64URL = "base64url"  // URL-safe base64 (无 padding)
	TransformNetBIOS   = "netbios"    // 每字节拆两个 nibble, 'a'+nibble
	TransformNetBIOSU  = "netbiosu"   // 同上, 但用大写 'A'+nibble
	TransformMask      = "mask"       // 每字节 XOR 0x2E 后 base64
	TransformPrint     = "print"      // 恒等 (明文输出)
	TransformURIAppend = "uri-append" // 百分号编码, 用于附加到 URI
	TransformPrepend   = "prepend"    // 前缀字符串
	TransformAppend    = "append"     // 后缀字符串
	TransformHeader    = "header"     // 放置类: 放进指定 HTTP 头
	TransformParameter = "parameter"  // 放置类: 放进指定查询/表单参数
)

// maskXorKey 是 mask 变换使用的异或键。
const maskXorKey = 0x2E

// knownTransforms 是所有被认可的变换名 (归一化之后)。
var knownTransforms = map[string]bool{
	TransformBase64:    true,
	TransformBase64URL: true,
	TransformNetBIOS:   true,
	TransformNetBIOSU:  true,
	TransformMask:      true,
	TransformPrint:     true,
	TransformURIAppend: true,
	TransformPrepend:   true,
	TransformAppend:    true,
	TransformHeader:    true,
	TransformParameter: true,
}

// normalizeTransformName 归一化变换名: 小写化并统一用 "-" 作分隔符,
// 因此 uri_append / URIAppend 都会被识别为 uri-append。
// 注意 base64url 自身没有分隔符, 不受影响。
func normalizeTransformName(name string) string {
	return strings.ReplaceAll(strings.ToLower(strings.TrimSpace(name)), "_", "-")
}

// KnownTransform 报告某个变换名是否被支持。
func KnownTransform(name string) bool {
	return knownTransforms[normalizeTransformName(name)]
}

// ---------------------------------------------------------------- 变换模型

// Transform 是变换链中的一项。
//
// Arg 仅对 prepend / append 有意义 (前缀/后缀内容); 对 header / parameter
// 表示放置目标名 (header 名或参数名)。
type Transform struct {
	Name string
	Arg  string
	Pos  Pos
}

// String 返回可读表示, 便于日志与调试。
func (t Transform) String() string {
	if t.Arg != "" {
		return fmt.Sprintf("%s(%q)", t.Name, t.Arg)
	}
	return t.Name
}

// Apply 正向变换 (明文 -> 线上字节)。
func (t Transform) Apply(data []byte) ([]byte, error) {
	name := normalizeTransformName(t.Name)
	switch name {
	case TransformBase64:
		return b64Encode(data), nil
	case TransformBase64URL:
		return b64URLEncode(data), nil
	case TransformNetBIOS:
		return netbiosEncode(data, false), nil
	case TransformNetBIOSU:
		return netbiosEncode(data, true), nil
	case TransformMask:
		return maskEncode(data), nil
	case TransformPrint:
		return cloneBytes(data), nil
	case TransformURIAppend:
		return uriEncode(data), nil
	case TransformPrepend:
		return concatBytes([]byte(t.Arg), data), nil
	case TransformAppend:
		return concatBytes(data, []byte(t.Arg)), nil
	case TransformHeader, TransformParameter:
		// 放置类变换: 只标记落点, 不改字节
		return cloneBytes(data), nil
	default:
		return nil, at(t.Pos, fmt.Errorf("未知变换 %q", t.Name))
	}
}

// Revert 逆向变换 (线上字节 -> 明文)。
func (t Transform) Revert(data []byte) ([]byte, error) {
	name := normalizeTransformName(t.Name)
	switch name {
	case TransformBase64:
		out, err := b64Decode(data)
		return out, wrapTransformErr(t, "base64", err)
	case TransformBase64URL:
		out, err := b64URLDecode(data)
		return out, wrapTransformErr(t, "base64url", err)
	case TransformNetBIOS:
		out, err := netbiosDecode(data)
		return out, wrapTransformErr(t, "netbios", err)
	case TransformNetBIOSU:
		out, err := netbiosDecode(data)
		return out, wrapTransformErr(t, "netbiosu", err)
	case TransformMask:
		out, err := maskDecode(data)
		return out, wrapTransformErr(t, "mask", err)
	case TransformPrint:
		return cloneBytes(data), nil
	case TransformURIAppend:
		out, err := uriDecode(data)
		return out, wrapTransformErr(t, "uri-append", err)
	case TransformPrepend:
		out, err := stripPrefix([]byte(t.Arg), data)
		return out, wrapTransformErr(t, "prepend", err)
	case TransformAppend:
		out, err := stripSuffix([]byte(t.Arg), data)
		return out, wrapTransformErr(t, "append", err)
	case TransformHeader, TransformParameter:
		return cloneBytes(data), nil
	default:
		return nil, at(t.Pos, fmt.Errorf("未知变换 %q", t.Name))
	}
}

func wrapTransformErr(t Transform, name string, err error) error {
	if err == nil {
		return nil
	}
	return at(t.Pos, fmt.Errorf("%s 逆变换失败: %v", name, err))
}

// ApplyTransforms 按链顺序作用于数据; 返回新切片, 不修改入参。
func ApplyTransforms(chain []Transform, data []byte) ([]byte, error) {
	cur := cloneBytes(data)
	for _, t := range chain {
		next, err := t.Apply(cur)
		if err != nil {
			return nil, err
		}
		cur = next
	}
	return cur, nil
}

// RevertTransforms 按链的逆序还原数据; 返回新切片, 不修改入参。
func RevertTransforms(chain []Transform, data []byte) ([]byte, error) {
	cur := cloneBytes(data)
	for i := len(chain) - 1; i >= 0; i-- {
		next, err := chain[i].Revert(cur)
		if err != nil {
			return nil, err
		}
		cur = next
	}
	return cur, nil
}

// ---------------------------------------------------------------- 算法实现

func cloneBytes(b []byte) []byte {
	out := make([]byte, len(b))
	copy(out, b)
	return out
}

func concatBytes(parts ...[]byte) []byte {
	n := 0
	for _, p := range parts {
		n += len(p)
	}
	out := make([]byte, 0, n)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// b64Encode 标准 base64 (带 padding)。
func b64Encode(data []byte) []byte {
	out := make([]byte, base64.StdEncoding.EncodedLen(len(data)))
	base64.StdEncoding.Encode(out, data)
	return out
}

// b64Decode 标准 base64 解码, 容忍缺失的 padding 与首尾空白。
func b64Decode(data []byte) ([]byte, error) {
	s := stripSpace(data)
	if s == "" {
		return []byte{}, nil
	}
	if out, err := base64.StdEncoding.DecodeString(s); err == nil {
		return out, nil
	}
	out, err := base64.RawStdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// b64URLEncode URL-safe base64, 去掉 padding。
// 去 padding 是一一映射: 解码时按长度补回即可还原。
func b64URLEncode(data []byte) []byte {
	return []byte(base64.RawURLEncoding.EncodeToString(data))
}

// b64URLDecode URL-safe base64 解码, 同时容忍带 padding / 标准字母表的输入。
func b64URLDecode(data []byte) ([]byte, error) {
	s := stripSpace(data)
	if s == "" {
		return []byte{}, nil
	}
	if out, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return out, nil
	}
	if out, err := base64.URLEncoding.DecodeString(s); err == nil {
		return out, nil
	}
	out, err := base64.RawStdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// stripSpace 去掉 base64 文本中常见的空白 (换行/回车/空格/tab)。
func stripSpace(data []byte) string {
	var sb strings.Builder
	for _, c := range data {
		switch c {
		case ' ', '\t', '\r', '\n':
			continue
		}
		sb.WriteByte(c)
	}
	return sb.String()
}

// netbiosEncode 把每个字节拆成高/低 nibble, 各映射为一个字母。
//
//	netbios  : 'a'+hi, 'a'+lo
//	netbiosu : 'A'+hi, 'A'+lo
//
// 每个 nibble 恰好占一个字符, 因此编码是可逆的 (2 字符 = 1 字节)。
func netbiosEncode(data []byte, upper bool) []byte {
	base := byte('a')
	if upper {
		base = 'A'
	}
	out := make([]byte, 0, len(data)*2)
	for _, c := range data {
		out = append(out, base+(c>>4), base+(c&0x0F))
	}
	return out
}

// netbiosDecode 还原 netbios / netbiosu 编码。
//
// 解码对字母大小写不敏感: DNS 通道大小写不保证, 而 nibble 语义唯一,
// 因此大写与小写形式由同一函数还原 (netbios 编码的数据也能被还原, 反之亦然)。
func netbiosDecode(data []byte) ([]byte, error) {
	buf := stripSpace(data)
	if len(buf)%2 != 0 {
		return nil, fmt.Errorf("长度为奇数 (%d), 不是合法的 netbios 编码", len(buf))
	}
	out := make([]byte, 0, len(buf)/2)
	for i := 0; i < len(buf); i += 2 {
		hi, err := netbiosNibble(buf[i])
		if err != nil {
			return nil, fmt.Errorf("第 %d 个字符 %q 不是合法 nibble", i, string(buf[i]))
		}
		lo, err := netbiosNibble(buf[i+1])
		if err != nil {
			return nil, fmt.Errorf("第 %d 个字符 %q 不是合法 nibble", i+1, string(buf[i+1]))
		}
		out = append(out, hi<<4|lo)
	}
	return out, nil
}

// netbiosNibble 把一个字母还原为 4 bit 值 (大小写不敏感)。
func netbiosNibble(c byte) (byte, error) {
	switch {
	case c >= 'a' && c <= 'p':
		return c - 'a', nil
	case c >= 'A' && c <= 'P':
		return c - 'A', nil
	}
	return 0, fmt.Errorf("不是 a-p / A-P 范围内的字符")
}

// maskEncode 每字节与 0x2E 异或后做标准 base64。
func maskEncode(data []byte) []byte {
	buf := make([]byte, len(data))
	for i, c := range data {
		buf[i] = c ^ maskXorKey
	}
	return b64Encode(buf)
}

// maskDecode base64 解码后再与 0x2E 异或。
func maskDecode(data []byte) ([]byte, error) {
	raw, err := b64Decode(data)
	if err != nil {
		return nil, err
	}
	for i := range raw {
		raw[i] ^= maskXorKey
	}
	return raw, nil
}

// isURIUnreserved 判断字节是否属于 RFC 3986 unreserved 集合。
func isURIUnreserved(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	case c == '-', c == '_', c == '.', c == '~':
		return true
	}
	return false
}

// uriEncode 把数据做百分号编码: 仅保留 unreserved 字符, 其余一律 %XX。
// 因为 '%' 本身也会被编码为 %25, 所以编码结果无歧义、可逆。
func uriEncode(data []byte) []byte {
	const hexDigits = "0123456789ABCDEF"
	var sb strings.Builder
	sb.Grow(len(data) * 3)
	for _, c := range data {
		if isURIUnreserved(c) {
			sb.WriteByte(c)
			continue
		}
		sb.WriteByte('%')
		sb.WriteByte(hexDigits[c>>4])
		sb.WriteByte(hexDigits[c&0x0F])
	}
	return []byte(sb.String())
}

// uriDecode 还原百分号编码; 非法 %XX 报错而不是静默丢弃。
func uriDecode(data []byte) ([]byte, error) {
	out := make([]byte, 0, len(data))
	for i := 0; i < len(data); i++ {
		c := data[i]
		if c != '%' {
			out = append(out, c)
			continue
		}
		if i+2 >= len(data) {
			return nil, fmt.Errorf("第 %d 字节处百分号编码不完整", i)
		}
		if !isHexDigit(data[i+1]) || !isHexDigit(data[i+2]) {
			return nil, fmt.Errorf("第 %d 字节处百分号编码非法", i)
		}
		out = append(out, hexDigitVal(data[i+1])<<4|hexDigitVal(data[i+2]))
		i += 2
	}
	return out, nil
}

func stripPrefix(prefix []byte, data []byte) ([]byte, error) {
	if !bytes.HasPrefix(data, prefix) {
		return nil, fmt.Errorf("数据缺少前缀 %q", string(prefix))
	}
	return cloneBytes(data[len(prefix):]), nil
}

func stripSuffix(suffix []byte, data []byte) ([]byte, error) {
	if !bytes.HasSuffix(data, suffix) {
		return nil, fmt.Errorf("数据缺少后缀 %q", string(suffix))
	}
	return cloneBytes(data[:len(data)-len(suffix)]), nil
}

// ---------------------------------------------------------------- 端点模型

// Field 是一条有序的 header / parameter 声明。
type Field struct {
	Name  string
	Value string
	Pos   Pos
}

// Placement 描述某条变换链最终的落点。
type Placement struct {
	Kind string // "header" | "parameter" | "uri-append" | ""
	Name string // header 名或参数名
	Pos  Pos
}

// IsZero 报告是否没有落点声明。
func (pl Placement) IsZero() bool { return pl.Kind == "" }

// Endpoint 是 client / server 子块。
//
// Metadata、ID、Output 是三条彼此独立的变换链; Transforms 是三者按
// metadata -> id -> output 顺序拼接的总链, 仅供遍历与校验使用。
// 运行时对同一份数据编码必须用对应的独立链 (ApplyMetadata / ApplyID /
// ApplyOutput), 不能整体套用 Transforms。
type Endpoint struct {
	URIs      []string // set uri 拆出的 URI 池 (按出现顺序)
	URIPos    Pos      // set uri 所在位置, 供校验报错
	URIx86    string   // http-stager: set uri_x86
	URIx64    string   // http-stager: set uri_x64
	Verb      string   // set verb, 缺省由所属块决定
	UserAgent string   // 端点自身的 User-Agent (来自 header 或 set useragent)

	Headers       map[string]string   // 静态头 (同名后者覆盖)
	HeadersAll    map[string][]string // 静态头全部取值
	HeaderList    []Field             // 静态头, 保序
	Parameters    map[string]string   // 静态参数
	ParametersAll map[string][]string
	ParameterList []Field

	Metadata      []Transform
	ID            []Transform
	Output        []Transform
	Transforms    []Transform
	MetadataPlace Placement
	IDPlace       Placement
	OutputPlace   Placement

	Options map[string]string // 端点内其它未被识别的 set/键值
	Pos     Pos
}

// GetURI 循环取用 URI 池: i 为负或超界时按模回绕; 池空返回空串。
func (e *Endpoint) GetURI(i int) string {
	if e == nil || len(e.URIs) == 0 {
		return ""
	}
	return e.URIs[wrapIndex(i, len(e.URIs))]
}

// ApplyMetadata 编码 metadata 并返回线上字节。
func (e *Endpoint) ApplyMetadata(data []byte) ([]byte, error) {
	if e == nil {
		return nil, fmt.Errorf("endpoint 不存在")
	}
	return ApplyTransforms(e.Metadata, data)
}

// RevertMetadata 还原 metadata。
func (e *Endpoint) RevertMetadata(data []byte) ([]byte, error) {
	if e == nil {
		return nil, fmt.Errorf("endpoint 不存在")
	}
	return RevertTransforms(e.Metadata, data)
}

// ApplyID 编码 id。
func (e *Endpoint) ApplyID(data []byte) ([]byte, error) {
	if e == nil {
		return nil, fmt.Errorf("endpoint 不存在")
	}
	return ApplyTransforms(e.ID, data)
}

// RevertID 还原 id。
func (e *Endpoint) RevertID(data []byte) ([]byte, error) {
	if e == nil {
		return nil, fmt.Errorf("endpoint 不存在")
	}
	return RevertTransforms(e.ID, data)
}

// ApplyOutput 编码 output。
func (e *Endpoint) ApplyOutput(data []byte) ([]byte, error) {
	if e == nil {
		return nil, fmt.Errorf("endpoint 不存在")
	}
	return ApplyTransforms(e.Output, data)
}

// RevertOutput 还原 output。
func (e *Endpoint) RevertOutput(data []byte) ([]byte, error) {
	if e == nil {
		return nil, fmt.Errorf("endpoint 不存在")
	}
	return RevertTransforms(e.Output, data)
}

// rebuildChain 重算 Transforms 总链与各落点。
func (e *Endpoint) rebuildChain() {
	if e == nil {
		return
	}
	chain := make([]Transform, 0, len(e.Metadata)+len(e.ID)+len(e.Output))
	chain = append(chain, e.Metadata...)
	chain = append(chain, e.ID...)
	chain = append(chain, e.Output...)
	e.Transforms = chain
	e.MetadataPlace = derivePlacement(e.Metadata)
	e.IDPlace = derivePlacement(e.ID)
	e.OutputPlace = derivePlacement(e.Output)
}

// derivePlacement 从链里推导落点: 第一个 header/parameter/uri-append 决定。
func derivePlacement(chain []Transform) Placement {
	for _, t := range chain {
		switch normalizeTransformName(t.Name) {
		case TransformHeader, TransformParameter:
			return Placement{Kind: normalizeTransformName(t.Name), Name: t.Arg, Pos: t.Pos}
		case TransformURIAppend:
			return Placement{Kind: TransformURIAppend, Pos: t.Pos}
		}
	}
	return Placement{}
}

// validate 检查单条链的合法性。
func (e *Endpoint) validate() error {
	if e == nil {
		return nil
	}
	for _, u := range e.URIs {
		if !strings.HasPrefix(u, "/") {
			return errorf(e.URIPos, "uri %q 必须以 / 开头", u)
		}
	}
	for _, key := range []string{"uri_x86", "uri_x64"} {
		v := e.URIx86
		if key == "uri_x64" {
			v = e.URIx64
		}
		if v != "" && !strings.HasPrefix(v, "/") {
			return errorf(e.Pos, "%s %q 必须以 / 开头", key, v)
		}
	}
	for _, t := range e.Transforms {
		name := normalizeTransformName(t.Name)
		if name == "" || !knownTransforms[name] {
			return errorf(t.Pos, "未知变换 %q", t.Name)
		}
		if (name == TransformPrepend || name == TransformAppend) && t.Arg == "" {
			return errorf(t.Pos, "变换 %q 缺少字符串参数", name)
		}
		if (name == TransformHeader || name == TransformParameter) && t.Arg == "" {
			return errorf(t.Pos, "变换 %q 缺少目标名", name)
		}
	}
	return nil
}

// wrapIndex 把任意整数映射到 [0,n)。
func wrapIndex(i, n int) int {
	if n <= 0 {
		return 0
	}
	m := i % n
	if m < 0 {
		m += n
	}
	return m
}

// ---------------------------------------------------------------- HTTP 块

// HTTPBlock 是 http-get / http-post / http-stager 块。
type HTTPBlock struct {
	Name    string
	Client  *Endpoint
	Server  *Endpoint
	URIx86  string // http-stager: set uri_x86
	URIx64  string // http-stager: set uri_x64
	Options map[string]string
	Pos     Pos
}

// GetURI 循环取用 client 的 URI 池 (client 为空则退回 server)。
func (b *HTTPBlock) GetURI(i int) string {
	if b == nil {
		return ""
	}
	if u := b.Client.GetURI(i); u != "" {
		return u
	}
	return b.Server.GetURI(i)
}

// URIs 返回 client 的 URI 池。
func (b *HTTPBlock) URIs() []string {
	if b == nil || b.Client == nil {
		return nil
	}
	return b.Client.URIs
}

func (b *HTTPBlock) validate() error {
	if b == nil {
		return nil
	}
	if err := b.Client.validate(); err != nil {
		return err
	}
	if err := b.Server.validate(); err != nil {
		return err
	}
	for _, s := range []string{b.URIx86, b.URIx64} {
		if s != "" && !strings.HasPrefix(s, "/") {
			return errorf(b.Pos, "stager uri %q 必须以 / 开头", s)
		}
	}
	return nil
}

// ---------------------------------------------------------------- 其它块

// HTTPConfigBlock 对应 http-config 块。
type HTTPConfigBlock struct {
	Headers            []Field
	HeaderMap          map[string]string
	TrustXForwardedFor bool
	BlockUserAgents    []string
	AllowUserAgents    []string
	Options            map[string]string
	Pos                Pos
}

// CertificateBlock 对应 https-certificate 块。
type CertificateBlock struct {
	Keystore string
	Password string
	Validity string
	CN       string
	O        string
	OU       string
	C        string
	L        string
	ST       string
	Options  map[string]string
	Pos      Pos
}

// PostExBlock 对应 post-ex 块。
type PostExBlock struct {
	SpawnToX86  string
	SpawnToX64  string
	PipeName    string
	KeyLogger   string
	Obfuscate   bool
	SmartInject bool
	AMSIDisable bool
	Cleanup     bool
	Options     map[string]string
	Pos         Pos
}

// ProcessInjectBlock 对应 process-inject 块。
type ProcessInjectBlock struct {
	Allocator    string
	MinAlloc     string
	Image        string
	Execute      []string
	StartRWX     bool
	UserRWX      bool
	TransformX86 []Transform
	TransformX64 []Transform
	Transforms   []Transform // X86 + X64 拼接, 供校验
	Options      map[string]string
	Pos          Pos
}

// StageBlock 对应 stage 块。
type StageBlock struct {
	Allocator    string
	Name         string
	Checksum     string
	CompileTime  string
	EntryPoint   string
	ImageSizeX86 string
	ImageSizeX64 string
	RichHeader   string
	Obfuscate    bool
	StompPE      bool
	Cleanup      bool
	UserRWX      bool

	Strings []string
	Data    []byte
	StrReps []StrRep

	Options map[string]string
	Pos     Pos
}

// StrRep 是 stage 块里的一条字符串替换。
type StrRep struct {
	From string
	To   string
}

// DNSBlock 对应 dns-beacon 块。
type DNSBlock struct {
	MaxDNS      int
	Beacon      string
	GetA        string
	GetAAAA     string
	GetTXT      string
	PutMetadata string
	PutOutput   string
	Idle        string
	Sleep       string
	MaxTXT      string
	TTL         string
	Options     map[string]string
	Pos         Pos
}

// TCPBlock 对应 tcp-beacon 块。
type TCPBlock struct {
	Port           string
	PipeName       string
	PipeNameStager string
	Options        map[string]string
	Pos            Pos
}

// SMBBlock 对应 smb-beacon 块。
type SMBBlock struct {
	PipeName       string
	PipeNameStager string
	Options        map[string]string
	Pos            Pos
}

// ---------------------------------------------------------------- Profile

// Profile 是解析后的运行期配置。
type Profile struct {
	Source string

	Global map[string]string // 全部顶层 set 选项

	HTTPGet    *HTTPBlock
	HTTPPost   *HTTPBlock
	HTTPStager *HTTPBlock

	HTTPConfig     *HTTPConfigBlock
	SSLCertificate *CertificateBlock
	PostEx         *PostExBlock
	ProcessInject  *ProcessInjectBlock
	Stage          *StageBlock
	DNS            *DNSBlock
	TCP            *TCPBlock
	SMB            *SMBBlock

	SleepTime int   // 毫秒
	Jitter    int   // 0-99
	KillDate  int64 // Unix 秒, 0 表示不启用
	SMBPipe   string
	UserAgent string

	UnknownBlocks  []string          // 解析到但未建模的块名
	UnknownOptions map[string]string // 顶层未被识别的 set 选项
	Doc            *Document         // 原始语法树 (GUI 展示 / 回查用)

	// Positions 记录关键顶层选项 (sleeptime/jitter/killdate/pipename/useragent)
	// 的源位置, 供校验报错定位。
	Positions map[string]Pos
}

// 默认值。
const (
	// DefaultSleepTime 是 profile 缺省心跳间隔 (毫秒), 与 CS 默认档案一致。
	// 注意: 本仓库 protocol_v2.md 的运行时默认是 5000ms; profile 未显式
	// 覆盖时由监听器决定最终取值, 本字段只表达"档案语义"。
	DefaultSleepTime = 60000
	// DefaultJitter 是缺省抖动百分比。
	DefaultJitter = 0
	// DefaultURI 是缺省请求路径。
	DefaultURI = "/submit"
	// DefaultUserAgent 是缺省 User-Agent。
	DefaultUserAgent = "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0)"
)

// Default 返回没有 profile 时的最小可用配置。
func Default() *Profile {
	return &Profile{
		Global:         map[string]string{},
		HTTPGet:        defaultHTTPBlock("http-get", "GET"),
		HTTPPost:       defaultHTTPBlock("http-post", "POST"),
		HTTPStager:     defaultHTTPBlock("http-stager", "GET"),
		SleepTime:      DefaultSleepTime,
		Jitter:         DefaultJitter,
		UserAgent:      DefaultUserAgent,
		UnknownOptions: map[string]string{},
	}
}

func defaultHTTPBlock(name, verb string) *HTTPBlock {
	return &HTTPBlock{
		Name:    name,
		Client:  defaultEndpoint(verb),
		Server:  defaultEndpoint(verb),
		Options: map[string]string{},
	}
}

func defaultEndpoint(verb string) *Endpoint {
	ep := &Endpoint{
		URIs:          []string{DefaultURI},
		Verb:          verb,
		Headers:       map[string]string{},
		HeadersAll:    map[string][]string{},
		Parameters:    map[string]string{},
		ParametersAll: map[string][]string{},
		Options:       map[string]string{},
	}
	ep.rebuildChain()
	return ep
}

// GetURI 循环取用 http-get 的 URI (运行期上行走 http-get)。
func (p *Profile) GetURI(i int) string {
	if p == nil {
		return ""
	}
	return p.HTTPGet.GetURI(i)
}

// Options 返回合并后的全局选项视图 (含未知选项)。
func (p *Profile) Option(name string) (string, bool) {
	if p == nil {
		return "", false
	}
	v, ok := p.Global[name]
	return v, ok
}
