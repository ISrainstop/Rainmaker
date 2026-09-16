package profile

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ---------------------------------------------------------------- 入口

// Load 读取并解析 profile 文件, 填充默认值后返回运行期模型。
//
// 只做解析 + 默认值填充, 不做语义校验; 需要校验请显式调用 Validate。
func Load(path string) (*Profile, error) {
	doc, err := ParseFile(path)
	if err != nil {
		return nil, err
	}
	return FromDocument(doc)
}

// FromSource 直接解析内存中的 profile 源码 (filename 仅用于错误消息)。
func FromSource(src []byte, filename string) (*Profile, error) {
	doc, err := Parse(src, filename)
	if err != nil {
		return nil, err
	}
	return FromDocument(doc)
}

// FromDocument 把语法树投影为运行期模型。
func FromDocument(doc *Document) (*Profile, error) {
	if doc == nil {
		return nil, fmt.Errorf("profile 文档为空")
	}
	p := Default()
	p.Source = doc.File
	p.Doc = doc
	p.Global = map[string]string{}
	p.Positions = map[string]Pos{}

	topUA := ""
	for _, st := range doc.Stmts {
		switch st.Kind {
		case KindSet:
			p.Global[st.Name] = st.Value
			ua, err := p.applyGlobal(st)
			if err != nil {
				return nil, err
			}
			if ua != "" {
				topUA = ua
			}
		case KindBlock:
			if err := p.applyBlock(st); err != nil {
				return nil, err
			}
		default:
			p.UnknownBlocks = append(p.UnknownBlocks, st.Kind)
		}
	}

	p.resolveUserAgent(topUA)
	p.resolvePipe()
	return p, nil
}

// applyGlobal 应用一条顶层 set; 返回其声明的 User-Agent (无则空串)。
func (p *Profile) applyGlobal(st *Stmt) (string, error) {
	switch normalizeKey(st.Name) {
	case "sleeptime", "sleep", "sleep_time", "sleep_ms":
		n, err := parseIntValue(st.Value, "sleeptime")
		if err != nil {
			return "", errorf(st.Pos, "%v", err)
		}
		p.SleepTime = n
		p.Positions["sleeptime"] = st.Pos
	case "jitter":
		n, err := parseIntValue(st.Value, "jitter")
		if err != nil {
			return "", errorf(st.Pos, "%v", err)
		}
		p.Jitter = n
		p.Positions["jitter"] = st.Pos
	case "killdate", "kill_date":
		n, err := parseKillDate(st.Value)
		if err != nil {
			return "", errorf(st.Pos, "%v", err)
		}
		p.KillDate = n
		p.Positions["killdate"] = st.Pos
	case "useragent", "user_agent":
		p.UserAgent = st.Value
		p.Positions["useragent"] = st.Pos
		return st.Value, nil
	case "smbpipe", "smb_pipe", "pipename", "pipe_name":
		p.SMBPipe = st.Value
		p.Positions["pipename"] = st.Pos
	case "spawnto_x86":
		p.ensurePostEx().SpawnToX86 = st.Value
	case "spawnto_x64":
		p.ensurePostEx().SpawnToX64 = st.Value
	default:
		p.UnknownOptions[st.Name] = st.Value
	}
	return "", nil
}

// applyBlock 应用一个顶层块。
func (p *Profile) applyBlock(st *Stmt) error {
	switch normalizeKey(st.Name) {
	case "http-get":
		b, err := projectHTTPBlock(st, "GET", p.HTTPGet)
		if err != nil {
			return err
		}
		p.HTTPGet = b
	case "http-post":
		b, err := projectHTTPBlock(st, "POST", p.HTTPPost)
		if err != nil {
			return err
		}
		p.HTTPPost = b
	case "http-stager":
		b, err := projectHTTPBlock(st, "GET", p.HTTPStager)
		if err != nil {
			return err
		}
		p.HTTPStager = b
	case "http-config":
		b, err := projectHTTPConfig(st)
		if err != nil {
			return err
		}
		p.HTTPConfig = b
	case "https-certificate":
		p.SSLCertificate = projectCertificate(st)
	case "post-ex":
		b, err := projectPostEx(st, p.ensurePostEx())
		if err != nil {
			return err
		}
		p.PostEx = b
	case "process-inject":
		b, err := projectProcessInject(st)
		if err != nil {
			return err
		}
		p.ProcessInject = b
	case "stage":
		b, err := projectStage(st)
		if err != nil {
			return err
		}
		p.Stage = b
	case "dns-beacon":
		b, err := projectDNS(st)
		if err != nil {
			return err
		}
		p.DNS = b
	case "tcp-beacon":
		p.TCP = projectTCP(st)
	case "smb-beacon":
		p.SMB = projectSMB(st)
	default:
		p.UnknownBlocks = append(p.UnknownBlocks, st.Name)
	}
	return nil
}

// resolveUserAgent 按 client 头 > 顶层 set > http-config > 默认 的优先级确定 UA。
func (p *Profile) resolveUserAgent(topUA string) {
	switch {
	case blockUA(p.HTTPGet) != "":
		p.UserAgent = blockUA(p.HTTPGet)
	case blockUA(p.HTTPPost) != "":
		p.UserAgent = blockUA(p.HTTPPost)
	case topUA != "":
		p.UserAgent = topUA
	case p.HTTPConfig != nil:
		if ua := lookupHeader(p.HTTPConfig.HeaderMap, "User-Agent"); ua != "" {
			p.UserAgent = ua
		}
	}
}

// resolvePipe 按 smb-beacon > tcp-beacon 的优先级确定命名管道。
func (p *Profile) resolvePipe() {
	switch {
	case p.SMB != nil && p.SMB.PipeName != "":
		p.SMBPipe = p.SMB.PipeName
	case p.TCP != nil && p.TCP.PipeName != "" && p.SMBPipe == "":
		p.SMBPipe = p.TCP.PipeName
	}
}

func blockUA(b *HTTPBlock) string {
	if b == nil {
		return ""
	}
	return b.Client.UserAgent
}

func (p *Profile) ensurePostEx() *PostExBlock {
	if p.PostEx == nil {
		p.PostEx = &PostExBlock{Options: map[string]string{}}
	}
	return p.PostEx
}

// ---------------------------------------------------------------- HTTP 投影

func projectHTTPBlock(node *Stmt, defVerb string, base *HTTPBlock) (*HTTPBlock, error) {
	b := &HTTPBlock{Name: node.Name, Options: map[string]string{}, Pos: node.Pos}
	var baseClient, baseServer *Endpoint
	if base != nil {
		baseClient, baseServer = base.Client, base.Server
	}
	b.Client = newEndpointBase(baseClient, defVerb)
	b.Server = newEndpointBase(baseServer, defVerb)

	var clientNode, serverNode *Stmt
	for _, st := range node.Body {
		switch st.Kind {
		case KindSet:
			switch normalizeKey(st.Name) {
			case "uri":
				b.Client.URIs = splitURIs(st.Value)
				b.Client.URIPos = st.Pos
			case "uri_x86":
				b.URIx86 = st.Value
				b.Client.URIx86 = st.Value
			case "uri_x64":
				b.URIx64 = st.Value
				b.Client.URIx64 = st.Value
			case "verb":
				v := strings.ToUpper(strings.TrimSpace(st.Value))
				b.Client.Verb, b.Server.Verb = v, v
			case "useragent", "user_agent":
				b.Client.UserAgent = st.Value
			default:
				b.Options[st.Name] = st.Value
			}
		case KindSetBlock:
			b.Options["set "+st.Name] = "block"
		case KindHeader:
			applyField(b.Client, KindHeader, st)
		case KindParameter:
			applyField(b.Client, KindParameter, st)
		case KindBlock:
			switch normalizeKey(st.Name) {
			case "client":
				clientNode = st
			case "server":
				serverNode = st
			default:
				b.Options["block "+st.Name] = "block"
			}
		default:
			b.Options["stmt "+st.Kind] = st.Kind
		}
	}

	if clientNode != nil {
		ep, err := projectEndpoint(clientNode, b.Client)
		if err != nil {
			return nil, err
		}
		b.Client = ep
	}
	if serverNode != nil {
		ep, err := projectEndpoint(serverNode, b.Server)
		if err != nil {
			return nil, err
		}
		b.Server = ep
	}
	b.Client.rebuildChain()
	b.Server.rebuildChain()
	return b, nil
}

// projectEndpoint 在 base 之上投影一个 client / server 块。
func projectEndpoint(node *Stmt, base *Endpoint) (*Endpoint, error) {
	ep := newEndpointBase(base, "")
	ep.Options = map[string]string{}
	ep.Pos = node.Pos
	if base != nil {
		for k, v := range base.Options {
			ep.Options[k] = v
		}
	}

	for _, st := range node.Body {
		switch st.Kind {
		case KindSet:
			switch normalizeKey(st.Name) {
			case "uri":
				ep.URIs = splitURIs(st.Value)
				ep.URIPos = st.Pos
			case "uri_x86":
				ep.URIx86 = st.Value
			case "uri_x64":
				ep.URIx64 = st.Value
			case "verb":
				ep.Verb = strings.ToUpper(strings.TrimSpace(st.Value))
			case "useragent", "user_agent":
				ep.UserAgent = st.Value
			default:
				ep.Options[st.Name] = st.Value
			}
		case KindSetBlock:
			ep.Options["set "+st.Name] = "block"
		case KindHeader, KindParameter:
			applyField(ep, st.Kind, st)
		case KindBlock:
			switch normalizeKey(st.Name) {
			case "metadata":
				ep.Metadata = buildTransforms(st.Body)
			case "id":
				ep.ID = buildTransforms(st.Body)
			case "output":
				ep.Output = buildTransforms(st.Body)
			default:
				ep.Options["block "+st.Name] = "block"
			}
		case KindTransform:
			ep.Output = append(ep.Output, transformFromStmt(st))
		default:
			ep.Options["stmt "+st.Kind] = st.Kind
		}
	}
	ep.rebuildChain()
	return ep, nil
}

// applyField 把一条 header / parameter 语句写入端点。
//
// 两参数形式是静态声明; 单参数形式是变换链中的 "放置声明" (数据放到该
// header / 参数), 归入 metadata 链。
func applyField(ep *Endpoint, kind string, st *Stmt) {
	if ep == nil {
		return
	}
	if len(st.Values) >= 2 && st.Value != "" {
		switch kind {
		case KindHeader:
			ep.HeaderList = append(ep.HeaderList, Field{Name: st.Name, Value: st.Value, Pos: st.Pos})
			ep.Headers[st.Name] = st.Value
			ep.HeadersAll[st.Name] = append(ep.HeadersAll[st.Name], st.Value)
			if strings.EqualFold(st.Name, "user-agent") {
				ep.UserAgent = st.Value
			}
		default:
			ep.ParameterList = append(ep.ParameterList, Field{Name: st.Name, Value: st.Value, Pos: st.Pos})
			ep.Parameters[st.Name] = st.Value
			ep.ParametersAll[st.Name] = append(ep.ParametersAll[st.Name], st.Value)
		}
		return
	}
	ep.Metadata = append(ep.Metadata, Transform{
		Name: normalizeTransformName(kind),
		Arg:  st.Name,
		Pos:  st.Pos,
	})
}

// buildTransforms 把变换链块的语句翻译为变换序列。
func buildTransforms(body []*Stmt) []Transform {
	var chain []Transform
	for _, st := range body {
		switch st.Kind {
		case KindTransform:
			chain = append(chain, transformFromStmt(st))
		case KindHeader, KindParameter:
			chain = append(chain, Transform{
				Name: normalizeTransformName(st.Kind),
				Arg:  st.Name,
				Pos:  st.Pos,
			})
		}
	}
	return chain
}

func transformFromStmt(st *Stmt) Transform {
	return Transform{Name: normalizeTransformName(st.Name), Arg: st.Arg, Pos: st.Pos}
}

// newEndpointBase 以 base 为底生成新端点骨架 (仅继承 URI 池/verb/UA/落点),
// 静态 header 与变换链由 profile 自身决定。
func newEndpointBase(base *Endpoint, defVerb string) *Endpoint {
	ep := &Endpoint{
		Verb:          defVerb,
		Headers:       map[string]string{},
		HeadersAll:    map[string][]string{},
		Parameters:    map[string]string{},
		ParametersAll: map[string][]string{},
		Options:       map[string]string{},
	}
	if base != nil {
		ep.URIs = append([]string(nil), base.URIs...)
		ep.URIPos = base.URIPos
		ep.UserAgent = base.UserAgent
		if base.Verb != "" {
			ep.Verb = base.Verb
		}
	}
	return ep
}

// splitURIs 把 set uri 的值按空白拆成 URI 池。
func splitURIs(v string) []string {
	fields := strings.Fields(v)
	if len(fields) == 0 {
		return nil
	}
	return fields
}

// ---------------------------------------------------------------- 其它块投影

func projectHTTPConfig(node *Stmt) (*HTTPConfigBlock, error) {
	b := &HTTPConfigBlock{
		HeaderMap: map[string]string{},
		Options:   map[string]string{},
		Pos:       node.Pos,
	}
	for _, st := range node.Body {
		if st.Kind != KindSet {
			b.Options[st.Kind+" "+st.Name] = st.Kind
			continue
		}
		switch normalizeKey(st.Name) {
		case "headers":
			for _, line := range st.Values {
				name, value, ok := splitHeaderLine(line)
				if !ok {
					return nil, errorf(st.Pos, "http-config 的 headers 项 %q 缺少 \":\" 分隔", line)
				}
				b.Headers = append(b.Headers, Field{Name: name, Value: value, Pos: st.Pos})
				b.HeaderMap[name] = value
			}
		case "trust_x_forwarded_for":
			v, err := parseBoolValue(st.Value, "trust_x_forwarded_for")
			if err != nil {
				return nil, errorf(st.Pos, "%v", err)
			}
			b.TrustXForwardedFor = v
		case "block_useragents":
			b.BlockUserAgents = splitList(st.Value)
		case "allow_useragents":
			b.AllowUserAgents = splitList(st.Value)
		default:
			b.Options[st.Name] = st.Value
		}
	}
	return b, nil
}

func projectCertificate(node *Stmt) *CertificateBlock {
	b := &CertificateBlock{Options: map[string]string{}, Pos: node.Pos}
	for _, st := range node.Body {
		if st.Kind != KindSet {
			b.Options[st.Kind+" "+st.Name] = st.Kind
			continue
		}
		switch normalizeKey(st.Name) {
		case "keystore":
			b.Keystore = st.Value
		case "password":
			b.Password = st.Value
		case "validity":
			b.Validity = st.Value
		case "cn":
			b.CN = st.Value
		case "o":
			b.O = st.Value
		case "ou":
			b.OU = st.Value
		case "c":
			b.C = st.Value
		case "l":
			b.L = st.Value
		case "st":
			b.ST = st.Value
		default:
			b.Options[st.Name] = st.Value
		}
	}
	return b
}

func projectPostEx(node *Stmt, base *PostExBlock) (*PostExBlock, error) {
	b := &PostExBlock{Options: map[string]string{}, Pos: node.Pos}
	if base != nil {
		b.SpawnToX86 = base.SpawnToX86
		b.SpawnToX64 = base.SpawnToX64
		b.PipeName = base.PipeName
		b.KeyLogger = base.KeyLogger
		b.Obfuscate = base.Obfuscate
		b.SmartInject = base.SmartInject
		b.AMSIDisable = base.AMSIDisable
		b.Cleanup = base.Cleanup
		for k, v := range base.Options {
			b.Options[k] = v
		}
	}
	for _, st := range node.Body {
		if st.Kind != KindSet {
			b.Options[st.Kind+" "+st.Name] = st.Kind
			continue
		}
		switch normalizeKey(st.Name) {
		case "spawnto_x86":
			b.SpawnToX86 = st.Value
		case "spawnto_x64":
			b.SpawnToX64 = st.Value
		case "pipename", "pipe_name":
			b.PipeName = st.Value
		case "keylogger":
			b.KeyLogger = st.Value
		case "obfuscate":
			v, err := parseBoolValue(st.Value, "obfuscate")
			if err != nil {
				return nil, errorf(st.Pos, "%v", err)
			}
			b.Obfuscate = v
		case "smartinject":
			v, err := parseBoolValue(st.Value, "smartinject")
			if err != nil {
				return nil, errorf(st.Pos, "%v", err)
			}
			b.SmartInject = v
		case "amsi_disable":
			v, err := parseBoolValue(st.Value, "amsi_disable")
			if err != nil {
				return nil, errorf(st.Pos, "%v", err)
			}
			b.AMSIDisable = v
		case "cleanup":
			v, err := parseBoolValue(st.Value, "cleanup")
			if err != nil {
				return nil, errorf(st.Pos, "%v", err)
			}
			b.Cleanup = v
		default:
			b.Options[st.Name] = st.Value
		}
	}
	return b, nil
}

func projectProcessInject(node *Stmt) (*ProcessInjectBlock, error) {
	b := &ProcessInjectBlock{
		Options: map[string]string{},
		Pos:     node.Pos,
	}
	for _, st := range node.Body {
		switch st.Kind {
		case KindSet:
			switch normalizeKey(st.Name) {
			case "allocator":
				b.Allocator = st.Value
			case "min_alloc":
				b.MinAlloc = st.Value
			case "image":
				b.Image = st.Value
			case "execute":
				b.Execute = append(b.Execute, st.Values...)
			case "startrwx":
				v, err := parseBoolValue(st.Value, "startrwx")
				if err != nil {
					return nil, errorf(st.Pos, "%v", err)
				}
				b.StartRWX = v
			case "userwx":
				v, err := parseBoolValue(st.Value, "userwx")
				if err != nil {
					return nil, errorf(st.Pos, "%v", err)
				}
				b.UserRWX = v
			default:
				b.Options[st.Name] = st.Value
			}
		case KindSetBlock:
			switch normalizeKey(st.Name) {
			case "transform-x86":
				b.TransformX86 = buildTransforms(st.Body)
			case "transform-x64":
				b.TransformX64 = buildTransforms(st.Body)
			default:
				b.Options["set "+st.Name] = "block"
			}
		case KindBlock:
			switch normalizeKey(st.Name) {
			case "transform-x86":
				b.TransformX86 = buildTransforms(st.Body)
			case "transform-x64":
				b.TransformX64 = buildTransforms(st.Body)
			default:
				b.Options["block "+st.Name] = "block"
			}
		default:
			b.Options[st.Kind+" "+st.Name] = st.Kind
		}
	}
	b.Transforms = append(append([]Transform{}, b.TransformX86...), b.TransformX64...)
	return b, nil
}

func projectStage(node *Stmt) (*StageBlock, error) {
	b := &StageBlock{Options: map[string]string{}, Pos: node.Pos}
	for _, st := range node.Body {
		switch st.Kind {
		case KindSet:
			switch normalizeKey(st.Name) {
			case "allocator":
				b.Allocator = st.Value
			case "name":
				b.Name = st.Value
			case "checksum":
				b.Checksum = st.Value
			case "compile_time":
				b.CompileTime = st.Value
			case "entry_point":
				b.EntryPoint = st.Value
			case "image_size_x86":
				b.ImageSizeX86 = st.Value
			case "image_size_x64":
				b.ImageSizeX64 = st.Value
			case "rich_header":
				b.RichHeader = st.Value
			case "obfuscate":
				v, err := parseBoolValue(st.Value, "obfuscate")
				if err != nil {
					return nil, errorf(st.Pos, "%v", err)
				}
				b.Obfuscate = v
			case "stomppe", "stomp_pe":
				v, err := parseBoolValue(st.Value, "stomppe")
				if err != nil {
					return nil, errorf(st.Pos, "%v", err)
				}
				b.StompPE = v
			case "cleanup":
				v, err := parseBoolValue(st.Value, "cleanup")
				if err != nil {
					return nil, errorf(st.Pos, "%v", err)
				}
				b.Cleanup = v
			case "userwx":
				v, err := parseBoolValue(st.Value, "userwx")
				if err != nil {
					return nil, errorf(st.Pos, "%v", err)
				}
				b.UserRWX = v
			default:
				b.Options[st.Name] = st.Value
			}
		case KindString:
			b.Strings = append(b.Strings, st.Values...)
		case KindData:
			for _, hexStr := range st.Values {
				raw, err := decodeHex(hexStr)
				if err != nil {
					return nil, errorf(st.Pos, "stage data 解析失败: %v", err)
				}
				b.Data = append(b.Data, raw...)
			}
		case KindStrRep:
			b.StrReps = append(b.StrReps, StrRep{From: st.Name, To: st.Value})
		default:
			b.Options[st.Kind+" "+st.Name] = st.Kind
		}
	}
	return b, nil
}

func projectDNS(node *Stmt) (*DNSBlock, error) {
	b := &DNSBlock{Options: map[string]string{}, Pos: node.Pos}
	for _, st := range node.Body {
		if st.Kind != KindSet {
			b.Options[st.Kind+" "+st.Name] = st.Kind
			continue
		}
		switch normalizeKey(st.Name) {
		case "maxdns", "max_dns":
			n, err := parseIntValue(st.Value, "maxdns")
			if err != nil {
				return nil, errorf(st.Pos, "%v", err)
			}
			b.MaxDNS = n
		case "beacon":
			b.Beacon = st.Value
		case "get_a":
			b.GetA = st.Value
		case "get_aaaa":
			b.GetAAAA = st.Value
		case "get_txt":
			b.GetTXT = st.Value
		case "put_metadata":
			b.PutMetadata = st.Value
		case "put_output":
			b.PutOutput = st.Value
		case "dns_idle":
			b.Idle = st.Value
		case "dns_sleep":
			b.Sleep = st.Value
		case "dns_max_txt":
			b.MaxTXT = st.Value
		case "dns_ttl":
			b.TTL = st.Value
		default:
			b.Options[st.Name] = st.Value
		}
	}
	return b, nil
}

func projectTCP(node *Stmt) *TCPBlock {
	b := &TCPBlock{Options: map[string]string{}, Pos: node.Pos}
	for _, st := range node.Body {
		if st.Kind != KindSet {
			b.Options[st.Kind+" "+st.Name] = st.Kind
			continue
		}
		switch normalizeKey(st.Name) {
		case "port":
			b.Port = st.Value
		case "pipename", "pipe_name":
			b.PipeName = st.Value
		case "pipename_stager":
			b.PipeNameStager = st.Value
		default:
			b.Options[st.Name] = st.Value
		}
	}
	return b
}

func projectSMB(node *Stmt) *SMBBlock {
	b := &SMBBlock{Options: map[string]string{}, Pos: node.Pos}
	for _, st := range node.Body {
		if st.Kind != KindSet {
			b.Options[st.Kind+" "+st.Name] = st.Kind
			continue
		}
		switch normalizeKey(st.Name) {
		case "pipename", "pipe_name":
			b.PipeName = st.Value
		case "pipename_stager":
			b.PipeNameStager = st.Value
		default:
			b.Options[st.Name] = st.Value
		}
	}
	return b
}

// ---------------------------------------------------------------- 校验

// Validate 校验运行期模型的自洽性。
//
// 检查项: sleeptime > 0、jitter ∈ [0,99]、killdate >= 0、每个 URI 以 "/"
// 开头、变换链中不含未知变换、prepend/append 带参数。
// 所有错误都带定位信息 (文件:行), 便于直接回填到 profile 编辑界面。
func (p *Profile) Validate() error {
	if p == nil {
		return fmt.Errorf("profile 为空")
	}
	if p.SleepTime <= 0 {
		return errorf(p.optPos("sleeptime"), "sleeptime 必须为正数, 当前 %d", p.SleepTime)
	}
	if p.Jitter < 0 || p.Jitter > 99 {
		return errorf(p.optPos("jitter"), "jitter 必须在 0-99 之间, 当前 %d", p.Jitter)
	}
	if p.KillDate < 0 {
		return errorf(p.optPos("killdate"), "killdate 不能为负数, 当前 %d", p.KillDate)
	}
	for _, b := range []*HTTPBlock{p.HTTPGet, p.HTTPPost, p.HTTPStager} {
		if err := b.validate(); err != nil {
			return err
		}
	}
	if p.ProcessInject != nil {
		for _, t := range p.ProcessInject.Transforms {
			name := normalizeTransformName(t.Name)
			if name == "" || !knownTransforms[name] {
				return errorf(t.Pos, "未知变换 %q", t.Name)
			}
		}
	}
	if p.DNS != nil && p.DNS.MaxDNS < 0 {
		return errorf(p.DNS.Pos, "maxdns 不能为负数, 当前 %d", p.DNS.MaxDNS)
	}
	return nil
}

func (p *Profile) optPos(key string) Pos {
	if p.Positions != nil {
		if pos, ok := p.Positions[key]; ok {
			return pos
		}
	}
	return Pos{File: p.Source}
}

// ---------------------------------------------------------------- 小工具

// normalizeKey 归一化 set 键名 (小写, 去首尾空白)。
func normalizeKey(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

func parseIntValue(v string, key string) (int, error) {
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return 0, fmt.Errorf("%s 的值 %q 不是整数", key, v)
	}
	return n, nil
}

func parseBoolValue(v string, key string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "true", "1", "yes", "on":
		return true, nil
	case "false", "0", "no", "off", "":
		return false, nil
	}
	return false, fmt.Errorf("%s 的值 %q 不是合法布尔值", key, v)
}

// killDateLayouts 覆盖常见写法: Unix 秒、RFC3339、"YYYY-MM-DD HH:MM:SS"、纯日期。
var killDateLayouts = []string{
	"2006-01-02 15:04:05",
	time.RFC3339,
	"2006-01-02T15:04:05",
	"2006-01-02",
}

func parseKillDate(v string) (int64, error) {
	s := strings.TrimSpace(v)
	if s == "" {
		return 0, nil
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		return n, nil
	}
	for _, layout := range killDateLayouts {
		if t, err := time.ParseInLocation(layout, s, time.Local); err == nil {
			return t.Unix(), nil
		}
	}
	return 0, fmt.Errorf("killdate 的值 %q 既不是 Unix 秒, 也不是可识别的时间格式", v)
}

// splitHeaderLine 按第一个 ":" 拆出 "Name: Value"。
func splitHeaderLine(line string) (string, string, bool) {
	i := strings.IndexByte(line, ':')
	if i <= 0 {
		return "", "", false
	}
	return strings.TrimSpace(line[:i]), strings.TrimSpace(line[i+1:]), true
}

// splitList 按逗号/空白拆分列表值。
func splitList(v string) []string {
	fields := strings.FieldsFunc(v, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t'
	})
	var out []string
	for _, f := range fields {
		if f != "" {
			out = append(out, f)
		}
	}
	return out
}

// lookupHeader 大小写不敏感地查 header。
func lookupHeader(m map[string]string, name string) string {
	for k, v := range m {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return ""
}

// decodeHex 解码十六进制串 (容忍空白与换行)。
func decodeHex(s string) ([]byte, error) {
	clean := stripSpace([]byte(s))
	if clean == "" {
		return nil, nil
	}
	if len(clean)%2 != 0 {
		return nil, fmt.Errorf("十六进制长度为奇数 (%d)", len(clean))
	}
	out := make([]byte, len(clean)/2)
	for i := 0; i < len(clean); i += 2 {
		if !isHexDigit(clean[i]) || !isHexDigit(clean[i+1]) {
			return nil, fmt.Errorf("第 %d 个字符处不是合法十六进制", i)
		}
		out[i/2] = hexDigitVal(clean[i])<<4 | hexDigitVal(clean[i+1])
	}
	return out, nil
}
