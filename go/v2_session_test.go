package main

import (
	"path/filepath"
	"testing"

	"csdev/proto"
)

// 回归测试: 同一 payload 并发跑多份时, 每个 checkin 都必须得到独立会话号。
// 之前按 host|user 去重会互相覆盖密钥、seq 互相打架 (HMAC 失败 + seq 回退)。
func TestConcurrentCheckinsDistinctSessions(t *testing.T) {
	oldDataDir, oldStoreFile := dataDir, storeFile
	dir := t.TempDir()
	dataDir = dir
	storeFile = filepath.Join(dir, "store.jsonl")
	defer func() { dataDir, storeFile = oldDataDir, oldStoreFile }()

	st := &V2State{byID: map[string]*V2Session{}, byNum: map[uint32]*V2Session{}}
	meta := []string{"HOST", "user", "x64", "1", "2", "proc", "-", "os", "5000", "10"}

	a := &proto.CheckinInfo{Meta: meta, AESKey: make([]byte, 32), HMACKey: make([]byte, 32)}
	b := &proto.CheckinInfo{Meta: meta, AESKey: make([]byte, 32), HMACKey: make([]byte, 32)}
	a.AESKey[0], b.AESKey[0] = 0x11, 0x22

	s1 := st.getOrCreate("1.1.1.1:1", a)
	s2 := st.getOrCreate("1.1.1.1:2", b)

	if s1.Num == s2.Num || s1.ID == s2.ID {
		t.Fatalf("并发 checkin 复用了同一会话 %s/%d", s1.ID, s1.Num)
	}
	t.Logf("OK: %s 与 %s 各自独立会话", s1.ID, s2.ID)
}
