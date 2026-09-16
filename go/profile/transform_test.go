package profile

import (
	"bytes"
	"encoding/base64"
	"testing"
)

// allTransformNames 覆盖任务要求的全部变换。
var allTransformNames = []string{
	TransformBase64,
	TransformBase64URL,
	TransformNetBIOS,
	TransformNetBIOSU,
	TransformMask,
	TransformPrint,
	TransformURIAppend,
	TransformPrepend,
	TransformAppend,
}

// sampleBlobs 是往返测试用的数据样本。
func sampleBlobs() map[string][]byte {
	blobs := map[string][]byte{
		"空":      {},
		"单字节0":   {0x00},
		"单字节FF":  {0xFF},
		"ASCII":  []byte("CS2K frame body"),
		"二进制含零":  {0x00, 0x01, 0x02, 0xFE, 0xFF, 0x00},
		"URI元字符": []byte("/submit?a=1&b=2 #frag%20"),
		"换行制表":   []byte("line1\nline2\ttab"),
		"帧头模拟":   []byte{0x43, 0x53, 0x32, 0x4B, 0x00, 0x00, 0x00, 0x01},
	}
	full := make([]byte, 256)
	for i := range full {
		full[i] = byte(i)
	}
	blobs["全256字节"] = full

	// 固定种子的伪随机数据 (避免依赖 math/rand 的版本差异)
	rnd := make([]byte, 512)
	seed := uint32(0x12345678)
	for i := range rnd {
		seed = seed*1664525 + 1013904223
		rnd[i] = byte(seed >> 24)
	}
	blobs["伪随机512"] = rnd
	return blobs
}

func transformByName(t *testing.T, name string) Transform {
	t.Helper()
	switch name {
	case TransformPrepend:
		return Transform{Name: name, Arg: "PRE>"}
	case TransformAppend:
		return Transform{Name: name, Arg: "<POST"}
	default:
		return Transform{Name: name}
	}
}

// TestTransformKnownVectors 逐个变换的固定向量。
func TestTransformKnownVectors(t *testing.T) {
	cases := []struct {
		name  string
		tr    Transform
		in    []byte
		want  string
		check bool // 只做正向断言时跳过逆向
	}{
		{"base64/hello", Transform{Name: TransformBase64}, []byte("hello"), "aGVsbG8=", true},
		{"base64/高位字节", Transform{Name: TransformBase64}, []byte{0xFB, 0xFF}, "+/8=", true},
		{"base64/空", Transform{Name: TransformBase64}, []byte{}, "", true},
		{"base64url/hello", Transform{Name: TransformBase64URL}, []byte("hello"), "aGVsbG8", true},
		{"base64url/高位字节", Transform{Name: TransformBase64URL}, []byte{0xFB, 0xFF}, "-_8", true},
		{"netbios/0x41", Transform{Name: TransformNetBIOS}, []byte{0x41}, "eb", true},
		{"netbios/0x00", Transform{Name: TransformNetBIOS}, []byte{0x00}, "aa", true},
		{"netbios/0xFF", Transform{Name: TransformNetBIOS}, []byte{0xFF}, "pp", true},
		{"netbiosu/0x41", Transform{Name: TransformNetBIOSU}, []byte{0x41}, "EB", true},
		{"netbiosu/0xFF", Transform{Name: TransformNetBIOSU}, []byte{0xFF}, "PP", true},
		{"netbiosu/MZ", Transform{Name: TransformNetBIOSU}, []byte("MZ"), "ENFK", true},
		{"mask/0x00", Transform{Name: TransformMask}, []byte{0x00}, "Lg==", true},
		{"mask/0x2E", Transform{Name: TransformMask}, []byte{0x2E}, "AA==", true},
		{"print/恒等", Transform{Name: TransformPrint}, []byte("plain\x00text"), "plain\x00text", true},
		{"uri-append/保留unreserved", Transform{Name: TransformURIAppend}, []byte("a b/c"), "a%20b%2Fc", true},
		{"uri-append/百分号", Transform{Name: TransformURIAppend}, []byte("100%"), "100%25", true},
		{"prepend/前缀", Transform{Name: TransformPrepend, Arg: "id="}, []byte("42"), "id=42", true},
		{"append/后缀", Transform{Name: TransformAppend, Arg: "\r\n"}, []byte("42"), "42\r\n", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.tr.Apply(tc.in)
			if err != nil {
				t.Fatalf("Apply 失败: %v", err)
			}
			if string(got) != tc.want {
				t.Fatalf("Apply(%q) = %q, 期望 %q", tc.in, got, tc.want)
			}
			if !tc.check || len(tc.in) == 0 {
				return
			}
			back, err := tc.tr.Revert(got)
			if err != nil {
				t.Fatalf("Revert 失败: %v", err)
			}
			if !bytes.Equal(back, tc.in) {
				t.Fatalf("往返不一致: %q != %q", back, tc.in)
			}
		})
	}
}

// TestTransformRoundTrip 全变换 × 全数据样本的可逆性。
func TestTransformRoundTrip(t *testing.T) {
	blobs := sampleBlobs()
	for _, name := range allTransformNames {
		tr := transformByName(t, name)
		for label, data := range blobs {
			t.Run(name+"/"+label, func(t *testing.T) {
				wire, err := tr.Apply(data)
				if err != nil {
					t.Fatalf("Apply 失败: %v", err)
				}
				// 编码结果不得与输入共享底层数组 (防止副作用)
				if len(data) > 0 && len(wire) == len(data) && &wire[0] == &data[0] {
					t.Error("Apply 返回了入参的别名切片")
				}
				back, err := tr.Revert(wire)
				if err != nil {
					t.Fatalf("Revert(Apply(x)) 失败: %v (wire=%q)", err, wire)
				}
				if !bytes.Equal(back, data) {
					t.Fatalf("往返不一致: %x != %x", back, data)
				}
			})
		}
	}
}

// TestTransformChainRoundTrip 组合链往返。
func TestTransformChainRoundTrip(t *testing.T) {
	chains := map[string][]Transform{
		"metadata(base64url+prepend+parameter)": {
			{Name: TransformBase64URL},
			{Name: TransformPrepend, Arg: "sess="},
			{Name: TransformParameter, Arg: "sess"},
		},
		"output(mask+print)": {
			{Name: TransformMask},
			{Name: TransformPrint},
		},
		"id(base64+header)": {
			{Name: TransformBase64},
			{Name: TransformHeader, Arg: "X-Id"},
		},
		"netbios链(append+netbios+append)": {
			{Name: TransformPrepend, Arg: "a"},
			{Name: TransformNetBIOS},
			{Name: TransformAppend, Arg: "p"},
		},
		"uri链(modelled)": {
			{Name: TransformURIAppend},
			{Name: TransformPrint},
		},
		"空链": {},
	}
	blobs := sampleBlobs()
	for label, chain := range chains {
		for blobLabel, data := range blobs {
			wire, err := ApplyTransforms(chain, data)
			if err != nil {
				t.Fatalf("%s/%s ApplyTransforms 失败: %v", label, blobLabel, err)
			}
			back, err := RevertTransforms(chain, wire)
			if err != nil {
				t.Fatalf("%s/%s RevertTransforms 失败: %v", label, blobLabel, err)
			}
			if !bytes.Equal(back, data) {
				t.Fatalf("%s/%s 链往返不一致: %x != %x", label, blobLabel, back, data)
			}
		}
	}
}

// TestApplyTransformsDoesNotMutateInput 链式编解码不得修改入参。
func TestApplyTransformsDoesNotMutateInput(t *testing.T) {
	orig := []byte("immutable-payload")
	data := append([]byte(nil), orig...)
	// mask / 异或类实现若原地改写会污染调用方数据
	chain := []Transform{{Name: TransformMask}, {Name: TransformBase64URL}}

	wire, err := ApplyTransforms(chain, data)
	if err != nil {
		t.Fatalf("ApplyTransforms 失败: %v", err)
	}
	if !bytes.Equal(data, orig) {
		t.Errorf("ApplyTransforms 修改了入参: %q", data)
	}

	wireCopy := append([]byte(nil), wire...)
	back, err := RevertTransforms(chain, wireCopy)
	if err != nil {
		t.Fatalf("RevertTransforms 失败: %v", err)
	}
	if !bytes.Equal(wireCopy, wire) {
		t.Errorf("RevertTransforms 修改了入参: %q", wireCopy)
	}
	if !bytes.Equal(back, orig) {
		t.Errorf("链往返不一致: %q != %q", back, orig)
	}
}

// TestDecodeTolerance 解码端必须容忍空白与缺失 padding (网络分块场景)。
func TestDecodeTolerance(t *testing.T) {
	// base64 缺失 padding
	if got, err := b64Decode([]byte("aGVsbG8")); err != nil || string(got) != "hello" {
		t.Errorf("b64Decode 缺失 padding: %q %v", got, err)
	}
	// 带换行的 base64
	if got, err := b64Decode([]byte("aGVs\nbG8=\n")); err != nil || string(got) != "hello" {
		t.Errorf("b64Decode 容忍换行失败: %q %v", got, err)
	}
	// netbios 大写/小写混合 + 空白
	if got, err := netbiosDecode([]byte("EB\neb")); err != nil || string(got) != "AA" {
		t.Errorf("netbiosDecode 混合大小写失败: %q %v", got, err)
	}
	// base64url 带 padding 也接受
	if got, err := b64URLDecode([]byte("aGVsbG8=")); err != nil || string(got) != "hello" {
		t.Errorf("b64URLDecode 带 padding 失败: %q %v", got, err)
	}
}

// TestTransformErrors 非法输入必须报错, 且带位置时保留位置。
func TestTransformErrors(t *testing.T) {
	cases := []struct {
		name string
		tr   Transform
		in   []byte
		sub  string
	}{
		{"netbios缺字节", Transform{Name: TransformNetBIOS}, []byte("abc"), "奇数"},
		{"netbios非法字符", Transform{Name: TransformNetBIOS}, []byte("zz"), "nibble"},
		{"base64非法", Transform{Name: TransformBase64}, []byte("!!!!"), "base64"},
		{"mask非法", Transform{Name: TransformMask}, []byte("!!!!"), "base64"},
		{"uri非法百分号", Transform{Name: TransformURIAppend}, []byte("a%2"), "不完整"},
		{"uri非法十六进制", Transform{Name: TransformURIAppend}, []byte("a%ZZ"), "非法"},
		{"prepend缺前缀", Transform{Name: TransformPrepend, Arg: "xx"}, []byte("yy"), "缺少前缀"},
		{"append缺后缀", Transform{Name: TransformAppend, Arg: "xx"}, []byte("yy"), "缺少后缀"},
		{"未知变换", Transform{Name: "rot13"}, []byte("yy"), "未知变换"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.tr.Revert(tc.in)
			if err == nil {
				t.Fatalf("Revert(%q) 期望报错", tc.in)
			}
			if !containsStr(err.Error(), tc.sub) {
				t.Errorf("错误 %q 未包含 %q", err.Error(), tc.sub)
			}
		})
	}

	// 带位置的变换: 错误消息必须带 文件:行
	tr := Transform{Name: "rot13", Pos: Pos{File: "csdev.profile", Line: 42}}
	if _, err := tr.Apply([]byte("x")); err == nil || !containsStr(err.Error(), "csdev.profile:42:") {
		t.Errorf("带位置的未知变换错误 = %v", err)
	}
	tr2 := Transform{Name: TransformPrepend, Arg: "xx", Pos: Pos{File: "csdev.profile", Line: 7}}
	if _, err := tr2.Revert([]byte("yy")); err == nil || !containsStr(err.Error(), "csdev.profile:7:") {
		t.Errorf("带位置的 prepend 逆变换错误 = %v", err)
	}
}

// TestNetBIOSIsFullNibbleEncoding 明确 nibble 编码语义:
// 每字节占两个字符, 因此信息无损、可逆。
func TestNetBIOSIsFullNibbleEncoding(t *testing.T) {
	for _, b := range []byte{0x00, 0x0F, 0x10, 0x7F, 0x80, 0xF0, 0xFF} {
		lo := netbiosEncode([]byte{b}, false)
		up := netbiosEncode([]byte{b}, true)
		if len(lo) != 2 || len(up) != 2 {
			t.Fatalf("字节 0x%02X 编码长度 = %d/%d, 期望 2/2 (仅取高 4 位会丢失信息)", b, len(lo), len(up))
		}
		if lo[0] < 'a' || lo[0] > 'p' || lo[1] < 'a' || lo[1] > 'p' {
			t.Errorf("netbios 输出越界: %s", lo)
		}
		if up[0] < 'A' || up[0] > 'P' || up[1] < 'A' || up[1] > 'P' {
			t.Errorf("netbiosu 输出越界: %s", up)
		}
		back, err := netbiosDecode(lo)
		if err != nil || back[0] != b {
			t.Errorf("netbios 往返失败 0x%02X -> %q -> %v (%v)", b, lo, back, err)
		}
	}
}

// TestMaskXorProperty mask = XOR 0x2E 后 base64, XOR 自逆。
func TestMaskXorProperty(t *testing.T) {
	data := []byte{0x00, 0x2E, 0x41, 0xFF}
	wire := maskEncode(data)
	raw, err := base64.StdEncoding.DecodeString(string(wire))
	if err != nil {
		t.Fatalf("mask 输出不是合法 base64: %v", err)
	}
	for i := range data {
		if raw[i] != data[i]^maskXorKey {
			t.Errorf("第 %d 字节 = 0x%02X, 期望 0x%02X", i, raw[i], data[i]^maskXorKey)
		}
	}
}

func containsStr(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && bytes.Contains([]byte(s), []byte(sub)))
}
