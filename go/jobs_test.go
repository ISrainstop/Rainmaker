package main

import (
	"testing"
)

// resetBgJobs 清空作业表(单测之间隔离)
func resetBgJobs() {
	bgJobStore.mu.Lock()
	bgJobStore.seq = 0
	bgJobStore.jobs = nil
	bgJobStore.mu.Unlock()
}

// TestBgJobLifecycle 作业的登记/绑定/收尾
func TestBgJobLifecycle(t *testing.T) {
	resetBgJobs()

	j := bgJobStart("S1", "portscan", "端口扫描 10.0.0.1 1-1024", 0, false)
	if j.ID != "0" {
		t.Fatalf("第一个作业号应为 0, 实得 %q", j.ID)
	}
	if j.Status != "running" || j.Killable {
		t.Fatalf("作业初始状态不对: %+v", j)
	}
	bgJobBind(j.ID, 42)
	if bgJobRunningCount("S1") != 1 {
		t.Fatalf("running 计数应为 1")
	}

	// 结果回来 -> 收尾
	bgJobFinishTask("S1", 42, true)
	got := bgJobFind("0")
	if got.Status != "done" || got.Ended == 0 {
		t.Fatalf("作业应收尾为 done: %+v", got)
	}
	if bgJobRunningCount("S1") != 0 {
		t.Fatalf("收尾后 running 计数应为 0")
	}
}

// TestBgJobClassify 命令归类
func TestBgJobClassify(t *testing.T) {
	cases := []struct {
		cmd      string
		wantKind string
		wantOK   bool
		wantBind bool
	}{
		{"portscan 10.0.0.1 1-1024", "portscan", true, true},
		{"keylog start", "keylog", true, false},
		{"keylog", "keylog", true, false},
		{"keylog dump", "", false, false},
		{"keylog status", "", false, false},
		{"keylog stop", "", false, false},
		{"whoami", "", false, false},
		{"", "", false, false},
	}
	for _, c := range cases {
		kind, _, _, bind, ok := bgJobClassify(c.cmd)
		if ok != c.wantOK || kind != c.wantKind {
			t.Fatalf("bgJobClassify(%q) = (%q,%v), 期望 (%q,%v)", c.cmd, kind, ok, c.wantKind, c.wantOK)
		}
		if ok && bind != c.wantBind {
			t.Fatalf("bgJobClassify(%q) bind=%v, 期望 %v", c.cmd, bind, c.wantBind)
		}
	}
}

// TestBgJobKillNonKillable 不可中断的作业必须如实回报, 不能假装成功
func TestBgJobKillNonKillable(t *testing.T) {
	resetBgJobs()
	j := bgJobStart("S1", "portscan", "端口扫描", 0, false)
	msg, err := bgJobKill(j.ID)
	if err != nil {
		t.Fatalf("不可中断的作业不应返回错误: %v", err)
	}
	if msg == "" || bgJobFind(j.ID).Status != "running" {
		t.Fatalf("状态不应被改动: msg=%q job=%+v", msg, bgJobFind(j.ID))
	}
	if _, err := bgJobKill("999"); err == nil {
		t.Fatal("不存在的作业号应报错")
	}
}

// TestBgJobListLimited 已结束作业只保留最近若干条, running 全保留
func TestBgJobListLimited(t *testing.T) {
	resetBgJobs()
	for i := 0; i < 30; i++ {
		j := bgJobStart("S1", "portscan", "x", 0, false)
		bgJobBind(j.ID, uint32(i+1))
		bgJobFinishTask("S1", uint32(i+1), true)
	}
	running := bgJobStart("S1", "keylog", "键盘记录", 0, true)
	out := bgJobForSessionLimited("S1", 5)
	if len(out) != 6 {
		t.Fatalf("期望 5 条历史 + 1 条 running, 实得 %d", len(out))
	}
	if out[len(out)-1].ID != running.ID {
		t.Fatalf("running 作业应排在最前(时间顺序): %+v", out[len(out)-1])
	}
}
