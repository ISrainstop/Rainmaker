// csdev :: proto/frame_test.go  --  帧编解码与 checkin 测试
package proto

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
)

func testKeys() (aes, mac []byte) {
	aes = bytes.Repeat([]byte{0x3C}, AESKeySize)
	mac = bytes.Repeat([]byte{0x7E}, HMACKeySize)
	return
}

func sealTestFrame(t *testing.T, sid, seq, flags uint32, plain []byte) (*Frame, []byte) {
	t.Helper()
	aesKey, macKey := testKeys()
	hdr := NewFrame(sid, seq, flags).Header()
	body, err := SealBody(aesKey, macKey, hdr, plain)
	if err != nil {
		t.Fatalf("SealBody 失败: %v", err)
	}
	raw := append(append([]byte{}, hdr...), body...)
	f, err := ParseFrame(raw)
	if err != nil {
		t.Fatalf("ParseFrame 失败: %v", err)
	}
	return f, raw
}

func TestSealBodyBackfillsBodyLen(t *testing.T) {
	aesKey, macKey := testKeys()
	plain := []byte("hello csdev v2")

	hdr := NewFrame(7, 3, F_HASRESULT).Header()
	if got := BE32(hdr[16:20]); got != 0 {
		t.Fatalf("初始 body_len 应为 0, 实际 %d", got)
	}
	body, err := SealBody(aesKey, macKey, hdr, plain)
	if err != nil {
		t.Fatalf("SealBody 失败: %v", err)
	}
	if got := BE32(hdr[16:20]); got != uint32(len(body)) {
		t.Fatalf("body_len 未回填: 帧头 %d, body %d", got, len(body))
	}
	if len(body) != 16+16+32 { // IV + 1 块密文(明文 15B→16B) + HMAC
		t.Fatalf("body 长度 %d, 期望 64", len(body))
	}
	if _, err := SealBody(aesKey, macKey, make([]byte, 19), plain); err == nil {
		t.Fatal("帧头长度不为 20 时必须报错")
	}
	if _, err := SealBody([]byte("bad"), macKey, hdr, plain); err == nil {
		t.Fatal("AES 密钥非法时必须报错")
	}
}

func TestFrameRoundTrip(t *testing.T) {
	aesKey, macKey := testKeys()
	for _, size := range []int{0, 1, 15, 16, 17, 100, 4096} {
		plain := make([]byte, size)
		if _, err := rand.Read(plain); err != nil {
			t.Fatal(err)
		}
		f := NewFrame(0x11223344, 9, F_HASRESULT)
		raw, err := f.Seal(aesKey, macKey, plain)
		if err != nil {
			t.Fatalf("明文 %d 字节: Seal 失败: %v", size, err)
		}
		if len(raw) != HeaderSize+len(f.Body) {
			t.Fatalf("明文 %d 字节: 帧长度 %d 与 body %d 不符", size, len(raw), len(f.Body))
		}

		got, err := ParseFrame(raw)
		if err != nil {
			t.Fatalf("明文 %d 字节: ParseFrame 失败: %v", size, err)
		}
		if got.SessionID != f.SessionID || got.Seq != f.Seq || got.Flags != f.Flags {
			t.Fatalf("明文 %d 字节: 帧头字段往返不一致: %s", size, got)
		}
		if !bytes.Equal(got.Encode(), raw) {
			t.Fatalf("明文 %d 字节: Encode 与原始帧不一致", size)
		}
		back, err := OpenBody(aesKey, macKey, got)
		if err != nil {
			t.Fatalf("明文 %d 字节: OpenBody 失败: %v", size, err)
		}
		if !bytes.Equal(back, plain) {
			t.Fatalf("明文 %d 字节: 明文往返不一致", size)
		}
	}
}

// TestOpenBodyRejectsHeaderTamper 逐字节翻转帧头, HMAC 必须全部拦住。
func TestOpenBodyRejectsHeaderTamper(t *testing.T) {
	aesKey, macKey := testKeys()
	plain := []byte("payload-1234567890")

	hdr := NewFrame(0x0A0B0C0D, 42, F_HASRESULT).Header()
	body, err := SealBody(aesKey, macKey, hdr, plain)
	if err != nil {
		t.Fatal(err)
	}
	raw := append(append([]byte{}, hdr...), body...)

	// 基线: 未篡改必须能解开
	base, err := ParseFrame(raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenBody(aesKey, macKey, base); err != nil {
		t.Fatalf("未篡改帧必须可解: %v", err)
	}

	for i := 0; i < HeaderSize; i++ {
		tampered := append([]byte{}, raw...)
		tampered[i] ^= 0x01

		f, err := ParseFrame(tampered)
		if err != nil {
			// 帧头被改成非法结构 (如 magic 或 body_len 越界) → ParseFrame 拦截, 同样算通过
			continue
		}
		if _, err := OpenBody(aesKey, macKey, f); err == nil {
			t.Fatalf("帧头第 %d 字节被翻转, OpenBody 未报错", i)
		} else if !errors.Is(err, ErrHMAC) {
			t.Fatalf("帧头第 %d 字节被翻转, 期望 ErrHMAC, 实际 %v", i, err)
		}
	}
}

func TestOpenBodyRejectsBodyTamper(t *testing.T) {
	aesKey, macKey := testKeys()
	f, raw := sealTestFrame(t, 5, 1, 0, []byte("body-tamper-check-abcdef"))

	for i := HeaderSize; i < len(raw); i++ {
		tampered := append([]byte{}, raw...)
		tampered[i] ^= 0x80
		got, err := ParseFrame(tampered)
		if err != nil {
			t.Fatalf("body 第 %d 字节翻转不应破坏帧结构: %v", i, err)
		}
		if _, err := OpenBody(aesKey, macKey, got); err == nil {
			t.Fatalf("body 第 %d 字节被翻转, OpenBody 未报错", i)
		}
	}
	// 错误密钥同样必须被拒
	if _, err := OpenBody(aesKey, bytes.Repeat([]byte{0x00}, HMACKeySize), f); err == nil {
		t.Fatal("HMAC 密钥不匹配必须报错")
	}
	if _, err := OpenBody(bytes.Repeat([]byte{0x00}, AESKeySize), macKey, f); err == nil {
		t.Fatal("AES 密钥不匹配必须报错")
	}
	if _, err := OpenBody(aesKey, macKey, nil); err == nil {
		t.Fatal("nil 帧必须报错")
	}
}

func TestParseFrameMalformed(t *testing.T) {
	aesKey, macKey := testKeys()
	_, raw := sealTestFrame(t, 1, 0, 0, []byte("x"))

	if _, err := ParseFrame(nil); !errors.Is(err, ErrTruncated) {
		t.Fatalf("空输入应报 ErrTruncated, 实际 %v", err)
	}
	for _, n := range []int{1, 19} {
		if _, err := ParseFrame(raw[:n]); err == nil {
			t.Fatalf("帧头 %d 字节时必须报错", n)
		}
	}
	bad := append([]byte{}, raw...)
	bad[0] = 0x00
	if _, err := ParseFrame(bad); !errors.Is(err, ErrMagic) {
		t.Fatalf("magic 错误应报 ErrMagic, 实际 %v", err)
	}
	badLen := append([]byte{}, raw...)
	PutBE32(badLen[16:20], uint32(len(raw))) // 声明超过实际可用字节
	if _, err := ParseFrame(badLen); !errors.Is(err, ErrTruncated) {
		t.Fatalf("body_len 越界应报 ErrTruncated, 实际 %v", err)
	}
	huge := append([]byte{}, raw...)
	PutBE32(huge[16:20], MaxFrameBody+1)
	if _, err := ParseFrame(huge); err == nil {
		t.Fatal("body_len 超 4MB 上限必须报错")
	}
	// 尾部多余字节被忽略
	if _, err := ParseFrame(append(append([]byte{}, raw...), 0xAA, 0xBB)); err != nil {
		t.Fatalf("尾部多余字节不应导致失败: %v", err)
	}

	// OpenBody 结构校验
	if _, err := OpenBody(aesKey, macKey, &Frame{Body: []byte{1, 2, 3}}); err == nil {
		t.Fatal("body 过短必须报错")
	}
	if _, err := OpenBody(aesKey, macKey, &Frame{Body: make([]byte, 16+32+16+1)}); err == nil {
		t.Fatal("密文长度非 16 整数倍必须报错")
	}
	if _, err := OpenBody(aesKey, macKey, &Frame{}); err == nil {
		t.Fatal("空 body 且无 F_NOHMAC 必须报错")
	}
	if _, err := OpenBody(aesKey, macKey, &Frame{Flags: F_NOHMAC, Body: []byte{1}}); err == nil {
		t.Fatal("声明 F_NOHMAC 却带 body 必须报错")
	}
	// 空应答: F_NOHMAC + body_len 0
	if pt, err := OpenBody(aesKey, macKey, &Frame{Flags: F_NOHMAC}); err != nil || pt != nil {
		t.Fatalf("空应答应返回 (nil, nil), 实际 (%v, %v)", pt, err)
	}
}

func TestFlagString(t *testing.T) {
	if got := FlagString(0); got != "0" {
		t.Fatalf("FlagString(0) = %q", got)
	}
	if got := FlagString(F_CHECKIN | F_NOHMAC); got != "CHECKIN|NOHMAC" {
		t.Fatalf("FlagString = %q", got)
	}
	if got := FlagString(1 << 20); got != "0x100000" {
		t.Fatalf("FlagString 未知名 = %q", got)
	}
}

// TestConcurrentSealOpen 多会话并发封帧/解帧 + SeqGuard 并发校验。
// 本机 race runtime 不可用 (-race 报 0xc0000139), 用它兜住并发正确性。
func TestConcurrentSealOpen(t *testing.T) {
	const workers = 32
	const rounds = 40

	guard := NewSeqGuard()
	errCh := make(chan error, workers)
	var wg sync.WaitGroup

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			aesKey := bytes.Repeat([]byte{byte(w)}, AESKeySize)
			macKey := bytes.Repeat([]byte{byte(w + 0x40)}, HMACKeySize)
			f := NewFrame(uint32(w+1), 0, F_HASRESULT)

			for r := 0; r < rounds; r++ {
				plain := []byte(fmt.Sprintf("session-%d-round-%d-payload", w, r))
				raw, err := f.Seal(aesKey, macKey, plain)
				if err != nil {
					errCh <- fmt.Errorf("worker %d: Seal: %w", w, err)
					return
				}
				got, err := ParseFrame(raw)
				if err != nil {
					errCh <- fmt.Errorf("worker %d: ParseFrame: %w", w, err)
					return
				}
				if err := guard.Accept(got.SessionID, got.Seq); err != nil {
					errCh <- fmt.Errorf("worker %d: SeqGuard: %w", w, err)
					return
				}
				back, err := OpenBody(aesKey, macKey, got)
				if err != nil {
					errCh <- fmt.Errorf("worker %d: OpenBody: %w", w, err)
					return
				}
				if !bytes.Equal(back, plain) {
					errCh <- fmt.Errorf("worker %d: 明文往返不一致", w)
					return
				}
				f.Seq++
			}
		}(w)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatal(err)
	}
}

// ---------------------------------------------------------------- checkin

func TestCheckinRoundTrip(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, RSAKeyBits)
	if err != nil {
		t.Fatal(err)
	}
	aesKey := bytes.Repeat([]byte{0x11}, AESKeySize)
	macKey := bytes.Repeat([]byte{0x22}, HMACKeySize)
	meta := []string{"WIN-7X2K9", "administrator", "x64", "4321", "812", "beacon.exe", "10.0.0.5", "Windows 10 Pro 19045"}

	plain := BuildCheckinPlain(aesKey, macKey, meta)
	if len(plain) != CheckinFixedLen+len(JoinMeta(meta)) {
		t.Fatalf("checkin 明文长度 %d 不符", len(plain))
	}
	if plain[80] != ProtoVersion {
		t.Fatalf("版本字节 0x%02X, 期望 0x%02X", plain[80], ProtoVersion)
	}
	if int(plain[81]) != len(JoinMeta(meta)) {
		t.Fatalf("meta 长度字节 %d, 期望 %d", plain[81], len(JoinMeta(meta)))
	}
	// iv_seed 保留字段必须全 0
	for i := 64; i < 80; i++ {
		if plain[i] != 0 {
			t.Fatalf("iv_seed 第 %d 字节非 0", i)
		}
	}

	ct, err := rsa.EncryptPKCS1v15(rand.Reader, &priv.PublicKey, plain)
	if err != nil {
		t.Fatalf("RSA 加密失败: %v", err)
	}
	info, err := ParseCheckin(priv, ct)
	if err != nil {
		t.Fatalf("ParseCheckin 失败: %v", err)
	}
	if !bytes.Equal(info.AESKey, aesKey) || !bytes.Equal(info.HMACKey, macKey) {
		t.Fatal("会话密钥往返不一致")
	}
	if info.Version != ProtoVersion {
		t.Fatalf("版本 %d", info.Version)
	}
	if len(info.Meta) != len(meta) {
		t.Fatalf("meta 字段数 %d, 期望 %d", len(info.Meta), len(meta))
	}
	for i := range meta {
		if info.Meta[i] != meta[i] {
			t.Fatalf("meta[%d] = %q, 期望 %q", i, info.Meta[i], meta[i])
		}
	}
}

func TestCheckinRejectsBadInput(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, RSAKeyBits)
	if err != nil {
		t.Fatal(err)
	}
	aesKey := bytes.Repeat([]byte{0x11}, AESKeySize)
	macKey := bytes.Repeat([]byte{0x22}, HMACKeySize)

	good, err := rsa.EncryptPKCS1v15(rand.Reader, &priv.PublicKey, BuildCheckinPlain(aesKey, macKey, []string{"h", "u"}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseCheckin(priv, good[:100]); err == nil {
		t.Fatal("密文长度不足必须报错")
	}
	if _, err := ParseCheckin(nil, good); err == nil {
		t.Fatal("nil 私钥必须报错")
	}

	other, err := rsa.GenerateKey(rand.Reader, RSAKeyBits)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseCheckin(other, good); err == nil {
		t.Fatal("错误私钥必须解密失败")
	}

	// 版本不符
	bad := BuildCheckinPlain(aesKey, macKey, []string{"h"})
	bad[80] = 0x09
	ct, err := rsa.EncryptPKCS1v15(rand.Reader, &priv.PublicKey, bad)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseCheckin(priv, ct); err == nil {
		t.Fatal("协议版本不符必须报错")
	}

	// meta 长度字段越界
	bad2 := BuildCheckinPlain(aesKey, macKey, []string{"h"})
	bad2[81] = 0xFF
	ct2, err := rsa.EncryptPKCS1v15(rand.Reader, &priv.PublicKey, bad2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseCheckin(priv, ct2); !errors.Is(err, ErrTruncated) {
		t.Fatalf("meta 越界应报 ErrTruncated, 实际 %v", err)
	}

	// 明文短于固定头
	short, err := rsa.EncryptPKCS1v15(rand.Reader, &priv.PublicKey, bytes.Repeat([]byte{0x41}, 40))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseCheckin(priv, short); !errors.Is(err, ErrTruncated) {
		t.Fatalf("明文过短应报 ErrTruncated, 实际 %v", err)
	}
}

// TestCheckinMetaCapacity 记录 checkin 明文受 PKCS#1 v1.5 上限约束的真实边界。
// RSA-2048 单块明文上限 = 256 - 11 = 245 字节, 固定头 82 字节 → meta 最多 163 字节。
func TestCheckinMetaCapacity(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, RSAKeyBits)
	if err != nil {
		t.Fatal(err)
	}
	const maxMeta = 256 - 11 - CheckinFixedLen // 163
	if maxMeta != 163 {
		t.Fatalf("推导出的 meta 上限 %d, 期望 163", maxMeta)
	}

	meta := make([]string, 2)
	meta[0] = "H"
	meta[1] = string(bytes.Repeat([]byte{'a'}, maxMeta-2)) // 2 (内容+分隔符) + 161 = 163
	plain := BuildCheckinPlain(make([]byte, AESKeySize), make([]byte, HMACKeySize), meta)
	if len(plain) != 256-11 {
		t.Fatalf("明文长度 %d, 期望 %d", len(plain), 256-11)
	}
	if _, err := rsa.EncryptPKCS1v15(rand.Reader, &priv.PublicKey, plain); err != nil {
		t.Fatalf("245 字节明文应能加密: %v", err)
	}

	over := BuildCheckinPlain(make([]byte, AESKeySize), make([]byte, HMACKeySize),
		[]string{string(bytes.Repeat([]byte{'a'}, maxMeta+1))})
	if _, err := rsa.EncryptPKCS1v15(rand.Reader, &priv.PublicKey, over); err == nil {
		t.Fatal("超过 245 字节的 checkin 明文必须被 RSA 拒绝")
	}
	t.Logf("checkin meta 实际容量上限 = %d 字节 (固定头 %d + meta <= 245)", maxMeta, CheckinFixedLen)
}

func TestBuildCheckinPlainClamps(t *testing.T) {
	// 密钥长度不足 → 右补零
	p := BuildCheckinPlain([]byte{1, 2, 3}, []byte{4}, []string{"h"})
	if len(p) != CheckinFixedLen+1 {
		t.Fatalf("明文长度 %d", len(p))
	}
	if p[0] != 1 || p[2] != 3 || p[3] != 0 || p[31] != 0 {
		t.Fatal("aes_key 未按 32 字节右补零")
	}
	if p[32] != 4 || p[33] != 0 || p[63] != 0 {
		t.Fatal("hmac_key 未按 32 字节右补零")
	}

	// 密钥超长 → 截断
	long := bytes.Repeat([]byte{0xEE}, 100)
	p2 := BuildCheckinPlain(long, long, nil)
	if len(p2) != CheckinFixedLen {
		t.Fatalf("明文长度 %d, 期望 %d", len(p2), CheckinFixedLen)
	}
	if p2[80] != ProtoVersion || p2[81] != 0 {
		t.Fatal("无 meta 时长度字节应为 0")
	}

	// meta 超 255 → 截断到完整字段边界
	meta := []string{string(bytes.Repeat([]byte{'x'}, 100)), string(bytes.Repeat([]byte{'y'}, 200))}
	p3 := BuildCheckinPlain(long, long, meta)
	if int(p3[81]) > CheckinMetaMax {
		t.Fatalf("meta 长度 %d 超出 1 字节字段", p3[81])
	}
	if got := string(p3[82 : 82+int(p3[81])]); got != strings.Repeat("x", 100) {
		t.Fatalf("截断后应为第一个完整字段, 实际 %q", got)
	}
}

func TestMetaJoinSplit(t *testing.T) {
	if got := SplitMeta(""); got != nil {
		t.Fatalf("空串应返回 nil, 实际 %v", got)
	}
	in := []string{"a", "b", "c"}
	if got := SplitMeta(JoinMeta(in)); len(got) != 3 || got[0] != "a" || got[2] != "c" {
		t.Fatalf("meta 往返不一致: %v", got)
	}
}

// ---------------------------------------------------------------- 防重放

func TestSeqGuard(t *testing.T) {
	g := NewSeqGuard()
	if err := g.Accept(0, 0); err != nil {
		t.Fatalf("checkin (sid=0) 不应参与防重放: %v", err)
	}
	// 单调递增: 允许跳号, 不允许重复与回退
	for _, seq := range []uint32{0, 1, 2, 5, 9} {
		if err := g.Accept(7, seq); err != nil {
			t.Fatalf("seq=%d 应被接受: %v", seq, err)
		}
	}
	for _, seq := range []uint32{0, 2, 5, 9, 3} {
		if err := g.Accept(7, seq); err == nil {
			t.Fatalf("seq=%d 是重放/乱序, 必须被拒", seq)
		}
	}
	if err := g.Accept(8, 0); err != nil {
		t.Fatalf("新会话不受影响: %v", err)
	}
	g.Forget(8)
	if err := g.Accept(8, 0); err != nil {
		t.Fatalf("Forget 后应重新接受: %v", err)
	}
	var nilGuard *SeqGuard
	if err := nilGuard.Accept(1, 1); err != nil {
		t.Fatalf("nil SeqGuard 应静默放行: %v", err)
	}
}
