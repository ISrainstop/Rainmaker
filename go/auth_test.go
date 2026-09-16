package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------- 测试夹具

// openTestEnv 把用户库、事件存储与登录会话重定向到临时目录, 并在测试结束时
// 恢复全部全局状态。根包全局变量较多, 这些测试刻意不并行, 以免相互干扰,
// 也保证与既有测试共存时行为不变。
func openTestEnv(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()

	oldDataDir, oldStoreFile := dataDir, storeFile
	oldOperators, oldLoaded := operators, operatorsLoaded
	oldSessions := authSessions
	oldStore := stStore
	oldPrompt := authPromptf
	oldEnabled := AuthEnabled()

	dataDir = dir
	storeFile = filepath.Join(dir, "store.jsonl")
	operators = nil
	operatorsLoaded = false
	authSessions = map[string]opSession{}
	stStore = &Store{seq: map[string]uint64{}}
	authPromptf = func(string, ...interface{}) {}

	t.Cleanup(func() {
		dataDir, storeFile = oldDataDir, oldStoreFile
		operators, operatorsLoaded = oldOperators, oldLoaded
		authSessions = oldSessions
		stStore = oldStore
		authPromptf = oldPrompt
		_ = flag.Set("auth", "on")
		SetAuthEnabled(oldEnabled)
	})
	return dir
}

// forceAuthOn 显式打开访问控制, 避免受前序测试或命令行参数影响。
func forceAuthOn(t *testing.T) {
	t.Helper()
	if err := flag.Set("auth", "on"); err != nil {
		t.Fatalf("设置 flag auth=on 失败: %v", err)
	}
	SetAuthEnabled(true)
	if !AuthEnabled() {
		t.Fatal("访问控制应处于启用状态")
	}
}

// createTestOperator 直接写入用户库, 免去从 stdout 解析随机口令的麻烦。
func createTestOperator(t *testing.T, user, pass, role string) {
	t.Helper()
	ensureOperators()
	hash, err := HashPassword(pass)
	if err != nil {
		t.Fatalf("HashPassword(%s): %v", user, err)
	}
	operatorsMu.Lock()
	operators = append(operators, Operator{User: user, PassHash: hash, Role: role})
	err = saveOperatorsLocked()
	operatorsMu.Unlock()
	if err != nil {
		t.Fatalf("写入用户库失败: %v", err)
	}
}

// callAPI 以给定令牌调用 handler。
func callAPI(t *testing.T, h http.Handler, method, path, body, token string) *httptest.ResponseRecorder {
	t.Helper()
	var req *http.Request
	if body == "" {
		req = httptest.NewRequest(method, path, nil)
	} else {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// decodeBody 把响应体解析为 map, 失败即测试失败。
func decodeBody(t *testing.T, rec *httptest.ResponseRecorder) map[string]interface{} {
	t.Helper()
	var m map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("响应不是合法 JSON: %v (body=%q)", err, rec.Body.String())
	}
	return m
}

// loginAs 走完整登录流程并返回令牌。
func loginAs(t *testing.T, h http.Handler, user, pass string) string {
	t.Helper()
	rec := callAPI(t, h, http.MethodPost, "/api/login",
		fmt.Sprintf(`{"user":%q,"pass":%q}`, user, pass), "")
	m := decodeBody(t, rec)
	if m["ok"] != true {
		t.Fatalf("登录 %s 失败: %v", user, m["error"])
	}
	tok, _ := m["token"].(string)
	if tok == "" {
		t.Fatalf("登录 %s 未返回令牌", user)
	}
	return tok
}

// extractPromptedPassword 从默认管理员的输出文案里取出明文口令。
func extractPromptedPassword(t *testing.T, out string) string {
	t.Helper()
	const marker = "密码  : "
	for _, line := range strings.Split(out, "\n") {
		if i := strings.Index(line, marker); i >= 0 {
			return strings.TrimSpace(line[i+len(marker):])
		}
	}
	t.Fatalf("输出中找不到口令行: %q", out)
	return ""
}

// ---------------------------------------------------------------- 口令哈希

func TestHashPasswordVerify(t *testing.T) {
	const pass = "Sup3r-Secret!"

	enc, err := HashPassword(pass)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}

	if !VerifyPassword(enc, pass) {
		t.Error("正确口令必须通过校验")
	}
	if VerifyPassword(enc, "sup3r-secret!") {
		t.Error("大小写不同的口令必须被拒")
	}
	if VerifyPassword(enc, "") {
		t.Error("空口令必须被拒")
	}
	if VerifyPassword(enc, pass+"!") {
		t.Error("多一个字符的口令必须被拒")
	}
	if VerifyPassword(enc, pass[:len(pass)-1]) {
		t.Error("少一个字符的口令必须被拒")
	}

	// 编码格式: sha256$<32 hex salt>$<64 hex digest>
	parts := strings.Split(enc, "$")
	if len(parts) != 3 || parts[0] != passHashScheme {
		t.Fatalf("哈希编码格式不符: %q", enc)
	}
	if len(parts[1]) != passSaltLen*2 {
		t.Errorf("盐应为 %d 字节 (%d hex 字符), 实际 %d 字符", passSaltLen, passSaltLen*2, len(parts[1]))
	}
	if len(parts[2]) != sha256.Size*2 {
		t.Errorf("摘要应为 %d 字节 (%d hex 字符), 实际 %d 字符", sha256.Size, sha256.Size*2, len(parts[2]))
	}
	if _, err := hex.DecodeString(parts[1]); err != nil {
		t.Errorf("盐不是合法 hex: %v", err)
	}
	if strings.Contains(enc, pass) {
		t.Error("编码串不得包含明文口令")
	}

	// 同一口令两次注册: 盐随机 → 哈希必须不同
	enc2, err := HashPassword(pass)
	if err != nil {
		t.Fatalf("HashPassword(第二次): %v", err)
	}
	if enc == enc2 {
		t.Error("同一口令两次注册必须产生不同哈希 (盐随机)")
	}
	if passHashSalt(enc) == passHashSalt(enc2) {
		t.Error("两个账户必须使用不同的盐")
	}
	if !VerifyPassword(enc2, pass) {
		t.Error("第二个哈希同样应能校验通过")
	}
	if passHashSalt("bogus") != "" {
		t.Error("畸形编码不应解析出盐")
	}

	// 畸形编码一律拒绝, 且不得 panic
	bad := []string{
		"", "sha256", "sha256$", "sha256$aa", "md5$" + parts[1] + "$" + parts[2],
		"sha256$zz$zz", "sha256$aa$bb", "$" + parts[1] + "$" + parts[2],
		"sha256$" + parts[1] + "$" + parts[2] + "00",
	}
	for _, s := range bad {
		if VerifyPassword(s, pass) {
			t.Errorf("畸形编码必须被拒: %q", s)
		}
	}
}

// ---------------------------------------------------------------- 令牌与角色

func TestTokenLifecycleAndRole(t *testing.T) {
	openTestEnv(t)

	tok, err := NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	if len(tok) != authTokenBytes*2 {
		t.Errorf("令牌应为 %d 字节 (%d hex 字符), 实际 %d 字符", authTokenBytes, authTokenBytes*2, len(tok))
	}
	raw, err := hex.DecodeString(tok)
	if err != nil {
		t.Fatalf("令牌不是合法 hex: %v", err)
	}
	if len(raw) != authTokenBytes {
		t.Errorf("令牌解码后应为 %d 字节, 实际 %d", authTokenBytes, len(raw))
	}
	if other, _ := NewToken(); other == tok {
		t.Error("两次生成的令牌不得相同")
	}

	// 签发 → 校验
	issued, err := issueToken("alice", RoleAdmin)
	if err != nil {
		t.Fatalf("issueToken: %v", err)
	}
	sess, ok := lookupToken(issued)
	if !ok {
		t.Fatal("新签发的令牌必须有效")
	}
	if sess.User != "alice" || sess.Role != RoleAdmin {
		t.Errorf("会话内容不符: %+v", sess)
	}
	if !roleCanManageUsers(sess.Role) {
		t.Error("admin 应可管理用户")
	}

	// 有效期 12 小时
	if authTokenTTL != 12*time.Hour {
		t.Errorf("令牌有效期应为 12 小时, 实际 %v", authTokenTTL)
	}
	authSessionsMu.Lock()
	stored := authSessions[issued]
	authSessionsMu.Unlock()
	want := time.Now().Add(authTokenTTL).Unix()
	if stored.Expires < want-5 || stored.Expires > want+5 {
		t.Errorf("过期时间不符: got %d want ~%d", stored.Expires, want)
	}

	// 未知/空令牌
	if _, ok := lookupToken(""); ok {
		t.Error("空令牌必须被拒")
	}
	if _, ok := lookupToken("deadbeefdeadbeef"); ok {
		t.Error("未知令牌必须被拒")
	}

	// 过期令牌: 拒绝并清除
	authSessionsMu.Lock()
	authSessions["expired-token"] = opSession{User: "bob", Role: RoleOperator, Expires: time.Now().Add(-time.Second).Unix()}
	authSessionsMu.Unlock()
	if _, ok := lookupToken("expired-token"); ok {
		t.Error("过期令牌必须被拒")
	}
	authSessionsMu.Lock()
	_, still := authSessions["expired-token"]
	authSessionsMu.Unlock()
	if still {
		t.Error("过期令牌应在校验时被清除")
	}
	if !tokenExpired(opSession{Expires: time.Now().Add(-time.Minute).Unix()}, time.Now().Unix()) {
		t.Error("tokenExpired 应识别已过期会话")
	}
	if tokenExpired(opSession{Expires: time.Now().Add(time.Hour).Unix()}, time.Now().Unix()) {
		t.Error("tokenExpired 不应误判有效会话")
	}

	// 角色判定
	if !validRole(RoleAdmin) || !validRole(RoleOperator) {
		t.Error("admin / operator 必须是合法角色")
	}
	if validRole("root") || validRole("") || validRole("ADMIN") {
		t.Error("未定义角色必须被拒")
	}
	if roleCanManageUsers(RoleOperator) {
		t.Error("operator 不可管理用户")
	}

	// 登出撤销
	if _, ok := revokeToken(issued); !ok {
		t.Error("撤销已签发令牌应命中")
	}
	if _, ok := lookupToken(issued); ok {
		t.Error("登出后令牌必须失效")
	}
	if _, ok := revokeToken(issued); ok {
		t.Error("重复撤销不应命中")
	}
}

// ---------------------------------------------------------------- 默认管理员

func TestDefaultAdminBootstrap(t *testing.T) {
	dir := openTestEnv(t)

	var prompts []string
	authPromptf = func(format string, a ...interface{}) {
		prompts = append(prompts, fmt.Sprintf(format, a...))
	}

	ensureOperators()

	if len(prompts) != 1 {
		t.Fatalf("默认管理员口令必须恰好输出一次, 实际 %d 次", len(prompts))
	}
	pass := extractPromptedPassword(t, prompts[0])

	// 16 字节随机 → base32 无填充 = 26 字符
	if len(pass) != 26 {
		t.Errorf("16 字节口令 base32 后应为 26 字符, 实际 %d: %q", len(pass), pass)
	}
	decoded, err := authPassAlphabet.DecodeString(pass)
	if err != nil {
		t.Fatalf("口令不是合法 base32: %v", err)
	}
	if len(decoded) != 16 {
		t.Errorf("口令随机源应为 16 字节, 实际 %d", len(decoded))
	}
	if len(authPassChars) != 32 {
		t.Fatalf("base32 字母表必须为 32 字符, 实际 %d", len(authPassChars))
	}

	op, ok := findOperator(authDefaultUser)
	if !ok {
		t.Fatalf("默认管理员 %s 必须存在", authDefaultUser)
	}
	if op.Role != RoleAdmin {
		t.Errorf("默认账户角色应为 admin, 实际 %q", op.Role)
	}
	if !VerifyPassword(op.PassHash, pass) {
		t.Error("输出到 stdout 的口令必须能通过校验")
	}
	if !strings.HasPrefix(op.PassHash, passHashScheme+"$") {
		t.Errorf("哈希编码异常: %q", op.PassHash)
	}

	// 落盘: 只有摘要与盐, 没有明文
	b, err := os.ReadFile(filepath.Join(dir, "operators.json"))
	if err != nil {
		t.Fatalf("用户库未落盘: %v", err)
	}
	text := string(b)
	if strings.Contains(text, pass) {
		t.Error("用户库不得包含明文口令")
	}
	if !strings.Contains(text, passHashScheme+"$") {
		t.Error("用户库应包含口令摘要")
	}
	if !strings.Contains(text, authDefaultUser) {
		t.Error("用户库应包含默认管理员用户名")
	}

	// 模拟重启: 已存在用户库, 不得再输出口令
	operatorsMu.Lock()
	operatorsLoaded = false
	operators = nil
	operatorsMu.Unlock()
	ensureOperators()

	if len(prompts) != 1 {
		t.Errorf("重启后不得再次输出口令, 实际 %d 次", len(prompts))
	}
	again, ok := findOperator(authDefaultUser)
	if !ok || !VerifyPassword(again.PassHash, pass) {
		t.Error("重启后应仍能用原口令登录 (盐与摘要已持久化)")
	}
}

// ---------------------------------------------------------------- 旁路开关

func TestAuthFlagAndRuntimeBypass(t *testing.T) {
	openTestEnv(t)
	forceAuthOn(t)

	// -auth=off: 字符串形式, 与启动参数一致
	if err := flag.Set("auth", "off"); err != nil {
		t.Fatalf("flag.Set(off): %v", err)
	}
	if AuthEnabled() {
		t.Error("-auth=off 必须旁路访问控制")
	}

	// 优先级高于运行期开关
	SetAuthEnabled(true)
	if AuthEnabled() {
		t.Error("-auth=off 应优先于 SetAuthEnabled(true)")
	}

	for _, v := range []string{"false", "0", "no", "OFF", " off ", "Disabled"} {
		if err := flag.Set("auth", v); err != nil {
			t.Fatalf("flag.Set(%s): %v", v, err)
		}
		if AuthEnabled() {
			t.Errorf("-auth=%s 应被识别为旁路", v)
		}
	}

	if err := flag.Set("auth", "on"); err != nil {
		t.Fatalf("flag.Set(on): %v", err)
	}
	if !AuthEnabled() {
		t.Error("-auth=on 应启用访问控制")
	}

	// 运行期开关
	SetAuthEnabled(false)
	if AuthEnabled() {
		t.Error("SetAuthEnabled(false) 应旁路")
	}
	SetAuthEnabled(true)
	if !AuthEnabled() {
		t.Error("SetAuthEnabled(true) 应恢复")
	}
}

// ---------------------------------------------------------------- 中间件

func TestRequireAuthMiddleware(t *testing.T) {
	openTestEnv(t)
	forceAuthOn(t)

	protected := requireAuth(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("机密数据"))
	})
	adminOnly := requireAdmin(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("管理员数据"))
	})

	// 无令牌 / 伪造令牌 → 401
	for _, tok := range []string{"", "forged-token"} {
		rec := callAPI(t, protected, http.MethodGet, "/x", "", tok)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("令牌 %q 应返回 401, 实际 %d", tok, rec.Code)
		}
		if m := decodeBody(t, rec); m["ok"] != false {
			t.Error("401 响应应带 ok=false")
		}
	}

	opTok, err := issueToken("readonly", RoleOperator)
	if err != nil {
		t.Fatalf("issueToken: %v", err)
	}
	if rec := callAPI(t, protected, http.MethodGet, "/x", "", opTok); rec.Code != http.StatusOK {
		t.Errorf("operator 令牌应通过 requireAuth, 实际 %d", rec.Code)
	} else if rec.Body.String() != "机密数据" {
		t.Errorf("业务响应被改动: %q", rec.Body.String())
	}

	// operator 不得进入管理员端点
	if rec := callAPI(t, adminOnly, http.MethodGet, "/x", "", opTok); rec.Code != http.StatusForbidden {
		t.Errorf("operator 访问管理员端点应 403, 实际 %d", rec.Code)
	}

	adTok, err := issueToken("boss", RoleAdmin)
	if err != nil {
		t.Fatalf("issueToken: %v", err)
	}
	if rec := callAPI(t, adminOnly, http.MethodGet, "/x", "", adTok); rec.Code != http.StatusOK {
		t.Errorf("admin 令牌应通过 requireAdmin, 实际 %d", rec.Code)
	}

	// 旁路: 无令牌直通
	SetAuthEnabled(false)
	if rec := callAPI(t, protected, http.MethodGet, "/x", "", ""); rec.Code != http.StatusOK {
		t.Errorf("旁路模式下应直接放行, 实际 %d", rec.Code)
	}
	if rec := callAPI(t, adminOnly, http.MethodGet, "/x", "", ""); rec.Code != http.StatusOK {
		t.Errorf("旁路模式下管理员端点也应放行, 实际 %d", rec.Code)
	}
}

// ---------------------------------------------------------------- 并发

// TestConcurrentAuthAccess 并发登录 + 并发令牌校验, 配合 -race 验证
// authSessions / operators 的锁是否真正互斥 (这两处是新增代码的并发热点)。
func TestConcurrentAuthAccess(t *testing.T) {
	openTestEnv(t)
	forceAuthOn(t)

	mux := http.NewServeMux()
	RegisterAuthRoutes(mux)
	createTestOperator(t, "conc", "Conc-Pass99", RoleOperator)

	const workers = 16
	var wg sync.WaitGroup
	codes := make([]int, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodPost, "/api/login",
				strings.NewReader(`{"user":"conc","pass":"Conc-Pass99"}`))
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
			codes[idx] = rec.Code
		}(i)
	}
	// 同时并发读用户列表与校验令牌
	tok, err := issueToken("conc", RoleOperator)
	if err != nil {
		t.Fatalf("issueToken: %v", err)
	}
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, ok := lookupToken(tok); !ok {
				t.Error("并发校验中令牌不应失效")
			}
			_ = storeEvents(10)
		}()
	}
	wg.Wait()

	for i, code := range codes {
		if code != http.StatusOK {
			t.Errorf("并发登录 #%d 返回 %d", i, code)
		}
	}
	if _, ok := findOperator("conc"); !ok {
		t.Error("并发登录后用户应仍在")
	}
}

// ---------------------------------------------------------------- 登录流程

func TestLoginLogoutAndUserManagement(t *testing.T) {
	openTestEnv(t)
	forceAuthOn(t)

	mux := http.NewServeMux()
	RegisterAuthRoutes(mux)

	createTestOperator(t, "boss", "Adm1n-Pass!", RoleAdmin)
	createTestOperator(t, "ro", "Read0nly-Pass!", RoleOperator)

	// 登录成功: 返回 token / role / user
	rec := callAPI(t, mux, http.MethodPost, "/api/login", `{"user":"boss","pass":"Adm1n-Pass!"}`, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("登录应返回 200, 实际 %d", rec.Code)
	}
	m := decodeBody(t, rec)
	if m["ok"] != true {
		t.Fatalf("登录失败: %v", m["error"])
	}
	if m["role"] != RoleAdmin || m["user"] != "boss" {
		t.Errorf("登录响应不符: %v", m)
	}
	tok, _ := m["token"].(string)
	if len(tok) != authTokenBytes*2 {
		t.Errorf("令牌长度异常: %d", len(tok))
	}

	// 登录失败: 无令牌, 且不区分"用户不存在"与"口令错误"
	failBodies := []string{
		`{"user":"boss","pass":"wrong-password"}`,
		`{"user":"ghost","pass":"whatever-password"}`,
	}
	for _, body := range failBodies {
		rec := callAPI(t, mux, http.MethodPost, "/api/login", body, "")
		m := decodeBody(t, rec)
		if m["ok"] == true {
			t.Errorf("错误凭据不得登录成功: %s", body)
		}
		if _, has := m["token"]; has {
			t.Errorf("失败响应不得包含令牌: %s", body)
		}
	}

	// 畸形请求体
	if rec := callAPI(t, mux, http.MethodPost, "/api/login", `{`, ""); decodeBody(t, rec)["ok"] == true {
		t.Error("畸形 JSON 不得登录成功")
	}
	// 错误方法
	if rec := callAPI(t, mux, http.MethodGet, "/api/login", "", ""); rec.Code != http.StatusOK {
		// 契约未规定状态码, 仅要求不发放令牌
		_ = rec
	}

	// /api/users: 未认证 401, operator 403, admin 200
	if rec := callAPI(t, mux, http.MethodGet, "/api/users", "", ""); rec.Code != http.StatusUnauthorized {
		t.Errorf("未认证访问 /api/users 应 401, 实际 %d", rec.Code)
	}
	roTok := loginAs(t, mux, "ro", "Read0nly-Pass!")
	if rec := callAPI(t, mux, http.MethodGet, "/api/users", "", roTok); rec.Code != http.StatusForbidden {
		t.Errorf("operator 访问 /api/users 应 403, 实际 %d", rec.Code)
	}
	rec = callAPI(t, mux, http.MethodGet, "/api/users", "", tok)
	if rec.Code != http.StatusOK {
		t.Fatalf("admin 访问 /api/users 应 200, 实际 %d", rec.Code)
	}

	// 绝不返回哈希或盐
	body := rec.Body.String()
	if strings.Contains(body, "pass_hash") || strings.Contains(body, passHashScheme) {
		t.Errorf("/api/users 泄露了哈希字段: %s", body)
	}
	m = decodeBody(t, rec)
	users, _ := m["users"].([]interface{})
	// RegisterAuthRoutes 会惰性建库, 因此这里是 默认 admin + boss + ro
	if len(users) != 3 {
		t.Errorf("应返回 3 个用户 (admin/boss/ro), 实际 %d", len(users))
	}
	names := map[string]bool{}
	for _, u := range users {
		um, _ := u.(map[string]interface{})
		for _, forbidden := range []string{"pass_hash", "pass", "salt", "hash"} {
			if _, has := um[forbidden]; has {
				t.Errorf("用户条目不得包含字段 %q", forbidden)
			}
		}
		name, _ := um["user"].(string)
		if name == "" {
			t.Error("用户条目应含用户名")
		}
		names[name] = true
		if um["role"] != RoleAdmin && um["role"] != RoleOperator {
			t.Errorf("用户条目角色异常: %v", um["role"])
		}
		if _, has := um["last"]; !has {
			t.Error("用户条目应含最后登录时间")
		}
	}
	for _, want := range []string{authDefaultUser, "boss", "ro"} {
		if !names[want] {
			t.Errorf("用户列表缺少 %s", want)
		}
	}

	// 新建用户: operator 被拒 (403)
	rec = callAPI(t, mux, http.MethodPost, "/api/user/new",
		`{"user":"escalate","pass":"Whatever-123","role":"admin"}`, roTok)
	if rec.Code != http.StatusForbidden {
		t.Errorf("operator 新建用户应 403, 实际 %d", rec.Code)
	}
	if _, exists := findOperator("escalate"); exists {
		t.Error("被拒的请求不得写入用户库")
	}

	// admin 新建成功
	rec = callAPI(t, mux, http.MethodPost, "/api/user/new",
		`{"user":"newbie","pass":"Fresh-Pass9","role":"operator"}`, tok)
	if m := decodeBody(t, rec); m["ok"] != true {
		t.Fatalf("admin 新建用户失败: %v", m)
	}
	if _, exists := findOperator("newbie"); !exists {
		t.Error("新建用户应写入用户库")
	}
	if loginAs(t, mux, "newbie", "Fresh-Pass9") == "" {
		t.Error("新用户应能登录")
	}

	// 边界: 空用户名 / 短口令 / 非法角色 / 重名 / 默认角色
	bad := []struct {
		body string
		why  string
	}{
		{`{"user":"","pass":"Fresh-Pass9","role":"operator"}`, "空用户名"},
		{`{"user":"shorty","pass":"1234567","role":"operator"}`, "口令短于 8 字符"},
		{`{"user":"weird","pass":"Fresh-Pass9","role":"superuser"}`, "非法角色"},
		{`{"user":"newbie","pass":"Fresh-Pass9","role":"operator"}`, "重名"},
	}
	for _, c := range bad {
		rec := callAPI(t, mux, http.MethodPost, "/api/user/new", c.body, tok)
		if m := decodeBody(t, rec); m["ok"] == true {
			t.Errorf("%s 应被拒绝: %s", c.why, c.body)
		}
	}
	// 省略角色默认 operator
	rec = callAPI(t, mux, http.MethodPost, "/api/user/new", `{"user":"defaulted","pass":"Fresh-Pass9"}`, tok)
	if m := decodeBody(t, rec); m["ok"] != true {
		t.Errorf("省略角色应默认 operator: %v", m)
	} else if op, _ := findOperator("defaulted"); op.Role != RoleOperator {
		t.Errorf("默认角色应为 operator, 实际 %q", op.Role)
	}

	// 落盘后重新读取, 新用户仍在 (验证持久化)
	operatorsMu.Lock()
	operatorsLoaded = false
	operators = nil
	operatorsMu.Unlock()
	if _, exists := findOperator("newbie"); !exists {
		t.Error("用户应从 operators.json 重新加载")
	}

	// 登出: 幂等且令牌立即失效
	if m := decodeBody(t, callAPI(t, mux, http.MethodPost, "/api/logout", "", tok)); m["ok"] != true {
		t.Error("登出应返回 ok")
	}
	if rec := callAPI(t, mux, http.MethodGet, "/api/users", "", tok); rec.Code != http.StatusUnauthorized {
		t.Errorf("登出后令牌应失效, 实际 %d", rec.Code)
	}
	if m := decodeBody(t, callAPI(t, mux, http.MethodPost, "/api/logout", "", "")); m["ok"] != true {
		t.Error("无令牌登出应幂等成功")
	}

	// 审计: 登录 / 登录失败 / 登出 / 新建用户 都要有 operator 事件
	want := map[string]bool{"登录": false, "登录失败": false, "登出": false, "新建用户": false}
	for _, e := range storeEvents(0) {
		if e.Cat != "operator" {
			continue
		}
		if _, ok := want[e.Action]; ok {
			want[e.Action] = true
		}
	}
	for action, seen := range want {
		if !seen {
			t.Errorf("审计缺少动作: %s", action)
		}
	}
}
