// csdev :: targets.go  --  目标主机库 (GUI 的 Targets 视图数据源)
//
// 目标来源 (source 字段):
//   beacon  : 会话上线时自动登记
//   scan    : 端口扫描 / 存活探测结果
//   lateral : 横向移动发起的目标
//   manual  : 操作员手工录入
//
// 同一 host 只保留一条记录 (按 host 去重), 重复来源会更新时间与来源。
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type Target struct {
	Kind   RecordKind `json:"kind"`
	ID     uint64     `json:"id"`
	Host   string     `json:"host"`
	IP     string     `json:"ip"`
	OS     string     `json:"os"`
	Note   string     `json:"note"`
	Source string     `json:"source"`
	SID    string     `json:"sid"`
	TS     int64      `json:"ts"`
}

// targetUpsert 按 host 去重登记。已存在时刷新来源/备注/时间, 不新增记录。
func targetUpsert(host, ip, os, source, sid, note string) Target {
	host = strings.TrimSpace(host)
	if host == "" {
		return Target{}
	}

	stStore.mu.Lock()
	for i := range stStore.targets {
		if strings.EqualFold(stStore.targets[i].Host, host) {
			t := &stStore.targets[i]
			if ip != "" {
				t.IP = ip
			}
			if os != "" {
				t.OS = os
			}
			if sid != "" {
				t.SID = sid
			}
			if note != "" {
				t.Note = note
			}
			if source != "" && !strings.Contains(t.Source, source) {
				t.Source = t.Source + "," + source
			}
			t.TS = time.Now().Unix()
			out := *t
			stStore.mu.Unlock()
			storePersist(out)
			return out
		}
	}
	stStore.mu.Unlock()

	t := Target{
		Kind: KindTarget, ID: nextStoreID("tg"),
		Host: host, IP: ip, OS: os, Note: note,
		Source: source, SID: sid, TS: time.Now().Unix(),
	}
	storeAdd(t)
	return t
}

func storeTargets() []Target {
	stStore.mu.RLock()
	defer stStore.mu.RUnlock()
	out := make([]Target, len(stStore.targets))
	copy(out, stStore.targets)
	return out
}

func targetDelete(id uint64) bool {
	stStore.mu.Lock()
	defer stStore.mu.Unlock()
	for i := range stStore.targets {
		if stStore.targets[i].ID == id {
			stStore.targets = append(stStore.targets[:i], stStore.targets[i+1:]...)
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------- API

func handleTargets(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, map[string]interface{}{"ok": true, "targets": storeTargets()})

	case http.MethodPost:
		var req struct {
			Host   string `json:"host"`
			IP     string `json:"ip"`
			OS     string `json:"os"`
			Note   string `json:"note"`
			Delete uint64 `json:"delete"`
		}
		if err := decodeJSONBody(r, &req); err != nil {
			writeJSON(w, map[string]interface{}{"ok": false, "error": "bad json"})
			return
		}
		if req.Delete != 0 {
			if targetDelete(req.Delete) {
				eventLog("operator", "", "删除目标", fmt.Sprintf("#%d", req.Delete))
				writeJSON(w, map[string]interface{}{"ok": true})
			} else {
				writeJSON(w, map[string]interface{}{"ok": false, "error": "目标不存在"})
			}
			return
		}
		if strings.TrimSpace(req.Host) == "" {
			writeJSON(w, map[string]interface{}{"ok": false, "error": "host 不能为空"})
			return
		}
		t := targetUpsert(req.Host, req.IP, req.OS, "manual", "", req.Note)
		eventLog("operator", "", "新增目标", req.Host)
		writeJSON(w, map[string]interface{}{"ok": true, "target": t})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleTargetsCSV 导出目标表 (供报告用)
func handleTargetsCSV(w http.ResponseWriter, r *http.Request) {
	rows := storeTargets()
	var sb strings.Builder
	sb.WriteString("host,ip,os,source,sid,note,ts\n")
	for _, t := range rows {
		sb.WriteString(csvField(t.Host) + "," + csvField(t.IP) + "," + csvField(t.OS) + "," +
			csvField(t.Source) + "," + csvField(t.SID) + "," + csvField(t.Note) + "," +
			strconv.FormatInt(t.TS, 10) + "\n")
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=csdev_targets.csv")
	w.Write([]byte{0xEF, 0xBB, 0xBF}) // UTF-8 BOM: Excel 直接打开中文不乱码
	w.Write([]byte(sb.String()))
}

func csvField(s string) string {
	if strings.ContainsAny(s, ",\"\n\r") {
		return "\"" + strings.ReplaceAll(s, "\"", "\"\"") + "\""
	}
	return s
}

var _ = json.Marshal
