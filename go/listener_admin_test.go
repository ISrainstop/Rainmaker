// csdev :: listener_admin_test.go  --  运行时 listener 增删的回归钉
//
// 钉住四件容易退化的事:
//   1. Add 成功 = 端口真的在监听; Remove = 端口真的释放 (不是只从表里删行)
//   2. 端口冲突必须如实报错, 不能"假装成功"
//   3. 主 HTTP listener 不允许删除
//   4. /api/listeners 的既有 8 字段契约逐字保持 (GUI 在用)
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func testPriv(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("生成测试密钥失败: %v", err)
	}
	return k
}

// freeTCPPort 取一个当前空闲的 TCP 端口 (取到就关闭, 立刻交给被测代码)
func freeTCPPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("取空闲端口失败: %v", err)
	}
	p := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return p
}

func addrOf(t *testing.T, id string) string {
	t.Helper()
	e := listenerGet(id)
	if e == nil {
		t.Fatalf("注册表里找不到 %s", id)
	}
	return e.Addr
}

func portOf(t *testing.T, addr string) int {
	t.Helper()
	_, p := splitHostPortSafe(addr)
	if p == 0 {
		t.Fatalf("地址里没有端口: %q", addr)
	}
	return p
}

// TestListenerTCPAddBindsAndRemoveReleasesPort 一次跑完"真的在监听 / 冲突报错 / 真的释放"。
func TestListenerTCPAddBindsAndRemoveReleasesPort(t *testing.T) {
	priv := testPriv(t)
	port := freeTCPPort(t)
	spec := fmt.Sprintf("127.0.0.1:%d", port)

	id, err := listenerAdd("tcp", spec, priv)
	if err != nil {
		t.Fatalf("Add tcp %s 失败: %v", spec, err)
	}
	defer listenerRemove(id)

	// 1) 真的在监听
	c, err := net.DialTimeout("tcp", spec, 2*time.Second)
	if err != nil {
		t.Fatalf("Add 成功但端口连不上, 说明没真在监听: %v", err)
	}
	c.Close()

	// 2) 端口冲突必须失败 (此刻该端口已被 listener 占用)
	if l2, e2 := net.Listen("tcp", spec); e2 == nil {
		l2.Close()
		t.Fatalf("Add 之后 %s 竟然还能被别的进程绑定", spec)
	}

	// 3) Remove 必须真的释放
	if err := listenerRemove(id); err != nil {
		t.Fatalf("Remove %s 失败: %v", id, err)
	}
	if listenerGet(id) != nil {
		t.Fatalf("Remove 之后 %s 仍在注册表里", id)
	}
	ln, err := net.Listen("tcp", spec)
	if err != nil {
		t.Fatalf("Remove 之后端口未释放: %v", err)
	}
	ln.Close()
}

// TestListenerAddDuplicatePortFails 同一个端口连续 Add 两次, 第二次必须明确失败。
func TestListenerAddDuplicatePortFails(t *testing.T) {
	priv := testPriv(t)
	port := freeTCPPort(t)
	spec := fmt.Sprintf("127.0.0.1:%d", port)

	id1, err := listenerAdd("tcp", spec, priv)
	if err != nil {
		t.Fatalf("第一次 Add 应成功, 却失败: %v", err)
	}
	defer listenerRemove(id1)

	id2, err := listenerAdd("tcp", spec, priv)
	if err == nil {
		listenerRemove(id2)
		t.Fatalf("第二次 Add 同一端口 %s 竟然成功了 (id=%s) —— 静默成功比报错更糟", spec, id2)
	}
	if !strings.Contains(err.Error(), "失败") && !strings.Contains(err.Error(), "address") &&
		!strings.Contains(err.Error(), "使用") {
		t.Logf("第二次 Add 的错误文本: %v", err)
	}
	t.Logf("重复 Add 的正确报错: %v", err)
}

// TestListenerRemoveMainRejected 主 HTTP 入口不允许通过 API 删除。
func TestListenerRemoveMainRejected(t *testing.T) {
	registerMainListener("csdev-v2-test", "http", "v2", "127.0.0.1", 8650, "/submit", false)
	defer func() {
		a := listenerReg
		a.mu.Lock()
		delete(a.m, "main")
		a.mu.Unlock()
	}()

	if err := listenerRemove("main"); err == nil {
		t.Fatal("主 listener 竟然被删掉了 —— 删它等于切断 /api 控制面")
	} else if !strings.Contains(err.Error(), "拒绝删除") {
		t.Fatalf("拒绝理由不明确: %v", err)
	} else {
		t.Logf("主 listener 拒绝删除的返回: %v", err)
	}
	if listenerGet("main") == nil {
		t.Fatal("拒绝删除之后主 listener 不该从注册表消失")
	}

	// 走 REST 层也必须是 ok=false + protected=true
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/listener/remove",
		strings.NewReader(`{"id":"main"}`))
	handleListenerRemove(rec, req)
	var resp map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("响应不是 JSON: %v (%s)", err, rec.Body.String())
	}
	if resp["ok"] != false || resp["protected"] != true {
		t.Fatalf("REST 拒绝响应不对: %s", rec.Body.String())
	}
}

// TestListenerAddHTTPRejected HTTP/HTTPS 运行期不支持新增 —— 必须明确报错。
func TestListenerAddHTTPRejected(t *testing.T) {
	priv := testPriv(t)
	if _, err := listenerAdd("http", "0.0.0.0:8651", priv); err == nil {
		t.Fatal("HTTP kind 应明确报错 (mux 启动期固化), 而不是假装成功")
	} else {
		t.Logf("HTTP kind 的明确报错: %v", err)
	}
	if _, err := listenerAdd("https", "0.0.0.0:8652", priv); err == nil {
		t.Fatal("HTTPS kind 应明确报错")
	}
}

// TestListenerAddBadKindAndAddr 非法 kind / 非法地址必须报错。
func TestListenerAddBadKindAndAddr(t *testing.T) {
	priv := testPriv(t)
	for _, c := range []struct{ kind, addr string }{
		{"websocket", "0.0.0.0:8651"},
		{"tcp", "no-port-here"},
		{"tcp", "0.0.0.0:99999"},
		{"dns", ""},
		{"", "0.0.0.0:8651"},
	} {
		if _, err := listenerAdd(c.kind, c.addr, priv); err == nil {
			t.Errorf("kind=%q addr=%q 应报错却成功了", c.kind, c.addr)
		}
	}
}

// TestListenerSMBAndDNS 另外两种承载也要能 Add / Remove。
func TestListenerSMBAndDNS(t *testing.T) {
	priv := testPriv(t)

	pipe := fmt.Sprintf("csdev_test_%d", time.Now().UnixNano()%1000000)
	sid, err := listenerAdd("smb", pipe, priv)
	if err != nil {
		t.Fatalf("Add smb 失败: %v", err)
	}
	if e := listenerGet(sid); e == nil || !strings.Contains(e.Addr, pipe) {
		t.Fatalf("SMB 注册的地址不对: %v", e)
	}
	if err := listenerRemove(sid); err != nil {
		t.Fatalf("Remove smb 失败: %v", err)
	}

	uid, err := listenerAdd("dns", "127.0.0.1:0", priv)
	if err != nil {
		t.Fatalf("Add dns 失败: %v", err)
	}
	dup := addrOf(t, uid)
	if _, _, perr := prepHostPort(dup); perr != nil {
		t.Fatalf("DNS 注册地址不是 ip:port: %q", dup)
	}
	if err := listenerRemove(uid); err != nil {
		t.Fatalf("Remove dns 失败: %v", err)
	}
	// UDP 端口释放: 能重新绑上就说明 Stop 真的关掉了 socket
	ua, _ := net.ResolveUDPAddr("udp", dup)
	uc, uerr := net.ListenUDP("udp", ua)
	if uerr != nil {
		t.Fatalf("Remove 之后 UDP 端口未释放: %v", uerr)
	}
	uc.Close()
}

// TestListenerListKeepsGUIContract 既有 8 字段契约 + 追加字段都在。
func TestListenerListKeepsGUIContract(t *testing.T) {
	priv := testPriv(t)
	registerMainListener("csdev-v2-test2", "http", "v2", "0.0.0.0", 8650, "/submit", false)
	defer func() {
		a := listenerReg
		a.mu.Lock()
		delete(a.m, "main")
		a.mu.Unlock()
	}()

	id, err := listenerAdd("tcp", "127.0.0.1:0", priv)
	if err != nil {
		t.Fatalf("Add tcp 失败: %v", err)
	}
	defer listenerRemove(id)

	b, err := json.Marshal(listenerList())
	if err != nil {
		t.Fatalf("序列化失败: %v", err)
	}
	var rows []map[string]interface{}
	if err := json.Unmarshal(b, &rows); err != nil {
		t.Fatalf("反序列化失败: %v", err)
	}
	if len(rows) < 2 {
		t.Fatalf("listeners 数量不对: %d", len(rows))
	}
	// GUI 读取的 8 个字段一个都不能少
	for _, k := range []string{"name", "type", "proto", "host", "port", "uri", "ssl", "up"} {
		if _, ok := rows[0][k]; !ok {
			t.Errorf("既有字段 %q 丢失 —— GUI 在用", k)
		}
	}
	// 追加字段
	for _, k := range []string{"id", "kind", "addr", "created", "sessions", "status", "protected", "manageable"} {
		if _, ok := rows[0][k]; !ok {
			t.Errorf("追加字段 %q 缺失", k)
		}
	}
	found := false
	for _, r := range rows {
		if r["id"] == id {
			found = true
			if r["kind"] != "tcp" {
				t.Errorf("kind 应为 tcp, 实际 %v", r["kind"])
			}
			if r["manageable"] != true {
				t.Errorf("API 新建的 listener 应 manageable=true")
			}
		}
	}
	if !found {
		t.Errorf("新加的 TCP listener (id=%s) 没出现在 /api/listeners 里", id)
	}
}

// TestListenerEventsLogged 创建/删除要写 eventLog("listener", ...)。
func TestListenerEventsLogged(t *testing.T) {
	priv := testPriv(t)
	id, err := listenerAdd("tcp", "127.0.0.1:0", priv)
	if err != nil {
		t.Fatalf("Add tcp 失败: %v", err)
	}
	if err := listenerRemove(id); err != nil {
		t.Fatalf("Remove tcp 失败: %v", err)
	}

	evs := storeEvents(50)
	var sawAdd, sawDel bool
	for _, e := range evs {
		if e.Cat != "listener" {
			continue
		}
		if e.Action == "add" && strings.Contains(e.Detail, id) {
			sawAdd = true
		}
		if e.Action == "remove" && strings.Contains(e.Detail, id) {
			sawDel = true
		}
	}
	if !sawAdd {
		t.Errorf("没有看到 listener/add 事件 (id=%s)", id)
	}
	if !sawDel {
		t.Errorf("没有看到 listener/remove 事件 (id=%s)", id)
	}
}

// TestListenerRESTAddRemove 走 REST 层跑完整闭环。
func TestListenerRESTAddRemove(t *testing.T) {
	listenerPriv = testPriv(t)
	port := freeTCPPort(t)

	body := fmt.Sprintf(`{"kind":"tcp","addr":"127.0.0.1:%d"}`, port)
	rec := httptest.NewRecorder()
	handleListenerAdd(rec, httptest.NewRequest(http.MethodPost, "/api/listener/add", strings.NewReader(body)))
	var add map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &add); err != nil {
		t.Fatalf("add 响应不是 JSON: %v (%s)", err, rec.Body.String())
	}
	if add["ok"] != true {
		t.Fatalf("REST add 失败: %s", rec.Body.String())
	}
	id, _ := add["id"].(string)
	if id == "" {
		t.Fatalf("REST add 没返回 id: %s", rec.Body.String())
	}
	defer listenerRemove(id)

	// 端口真的在监听
	if c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second); err != nil {
		t.Fatalf("REST add 之后端口连不上: %v", err)
	} else {
		c.Close()
	}

	// 删除
	rec2 := httptest.NewRecorder()
	handleListenerRemove(rec2, httptest.NewRequest(http.MethodPost, "/api/listener/remove",
		strings.NewReader(fmt.Sprintf(`{"id":%q}`, id))))
	var del map[string]interface{}
	if err := json.Unmarshal(rec2.Body.Bytes(), &del); err != nil {
		t.Fatalf("remove 响应不是 JSON: %v", err)
	}
	if del["ok"] != true || del["port_released"] != true {
		t.Fatalf("REST remove 响应不对: %s", rec2.Body.String())
	}
	if ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port)); err != nil {
		t.Fatalf("REST remove 之后端口未释放: %v", err)
	} else {
		ln.Close()
	}
}
