// csdev :: auth.go  --  多操作员与访问控制
//
// 角色:
//
//	admin    —— 全部权限 (含用户管理)
//	operator —— 只读 + 下发命令 (不可管理用户)
//
// 用户库: data/operators.json (权限 0600, 临时文件 + rename 原子写)
//
//	PassHash 字段编码为 "sha256$<salt_hex>$<digest_hex>", 其中
//	salt 为该用户独立随机 16 字节, digest = sha256(salt || password)。
//	文件里只有盐与摘要, 不出现明文口令; /api/users 响应绝不含盐与摘要。
//
// 令牌: 32 字节随机数的 hex (64 字符), 保存在内存 (不落盘), 有效期 12 小时。
//
//	请求头: Authorization: Bearer <token>
//
// 旁路: 启动参数 -auth=off (单机使用), 或运行期 SetAuthEnabled(false)。
//
//	-auth=off 优先级最高, 覆盖 SetAuthEnabled 的设置; 旁路状态下所有受保护
//	端点放行, 等同控制台完全开放, 只应在回环/受信网络使用。
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ---------------------------------------------------------------- 常量

const (
	// RoleAdmin 全部权限; RoleOperator 只读 + 下发命令。
	RoleAdmin    = "admin"
	RoleOperator = "operator"

	authTokenTTL   = 12 * time.Hour // 令牌有效期
	authMaxUserLen = 64             // 用户名最大字符数 (按 rune 计)
	authMinPassLen = 8              // 新建用户的口令最小长度
	authTokenBytes = 32             // 令牌随机字节数 (hex 后 64 字符)

	authDefaultUser = "admin"  // 首次启动默认管理员用户名
	passHashScheme  = "sha256" // 哈希方案标识
	passSaltLen     = 16       // 每用户独立盐长度
)

// authPassChars 默认管理员口令的编码字母表: 32 个字符, 剔除易混淆的 I/O/0/1。
const authPassChars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

var authPassAlphabet = base32.NewEncoding(authPassChars).WithPadding(base32.NoPadding)

// ---------------------------------------------------------------- 类型

// Operator 单个操作员账户。Last 为最后登录 Unix 秒。
// PassHash 编码见文件头: "sha256$<salt_hex>$<digest_hex>"。
type Operator struct {
	User     string `json:"user"`
	PassHash string `json:"pass_hash"`
	Role     string `json:"role"`
	Last     int64  `json:"last"`
}

// operatorFile 落盘包装: 顶层留 version 便于后续演进而不破坏旧文件。
type operatorFile struct {
	Version   int        `json:"version"`
	Operators []Operator `json:"operators"`
}

// opSession 内存登录会话 (契约中的 Session{user, role, expires})。
// 命名为 opSession 以免与 server.go 的植入体会话类型 Session 冲突。
type opSession struct {
	User    string `json:"user"`
	Role    string `json:"role"`
	Expires int64  `json:"expires"`
}

// ---------------------------------------------------------------- 状态

var (
	operatorsMu     sync.RWMutex
	operators       []Operator
	operatorsLoaded bool

	authSessionsMu sync.Mutex
	authSessions   = map[string]opSession{}

	// authEnabled 运行期开关, 默认开启; -auth=off 优先于它。
	authEnabled = func() *atomic.Bool {
		b := &atomic.Bool{}
		b.Store(true)
		return b
	}()

	// authPromptf 默认管理员明文口令的输出通道 (stdout)。
	// 提为变量: 测试可替换以捕获输出, 避免污染测试日志。
	authPromptf = func(format string, a ...interface{}) { fmt.Printf(format, a...) }
)

func init() {
	// 仅当 main 未注册同名参数时再注册, 避免 flag 重复定义 panic。
	// 用字符串而非布尔: 契约要求 "-auth=off" 这种写法, 布尔 flag 会解析失败。
	if flag.Lookup("auth") == nil {
		flag.String("auth", "on", "访问控制开关: on=启用(默认) / off=旁路(单机使用)")
	}
}

// AuthEnabled 返回访问控制是否生效。-auth=off 时恒为 false (硬旁路)。
func AuthEnabled() bool {
	if f := flag.Lookup("auth"); f != nil && authFlagIsOff(f.Value.String()) {
		return false
	}
	return authEnabled.Load()
}

// SetAuthEnabled 运行期开关访问控制; 注意 -auth=off 的优先级高于本函数。
func SetAuthEnabled(on bool) { authEnabled.Store(on) }

func authFlagIsOff(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "off", "0", "false", "no", "disable", "disabled":
		return true
	}
	return false
}

// ---------------------------------------------------------------- 用户库

// operatorsPath 必须运行期计算: dataDir 在 main 启动时才会被重设为 devRoot/data。
func operatorsPath() string { return filepath.Join(dataDir, "operators.json") }

// ensureOperators 惰性加载用户库, 保证任何入口调用前用户库都可用。
func ensureOperators() {
	operatorsMu.Lock()
	defer operatorsMu.Unlock()
	if operatorsLoaded {
		return
	}
	operatorsLoaded = true
	loadOperatorsLocked()
}

// loadOperatorsLocked 读取 data/operators.json; 不存在则创建默认管理员,
// 损坏则备份为 .bak 后重建 (避免服务端因单文件损坏而永久无法登录)。
func loadOperatorsLocked() {
	b, err := os.ReadFile(operatorsPath())
	if err != nil {
		createDefaultAdminLocked()
		return
	}
	var f operatorFile
	if err := json.Unmarshal(b, &f); err != nil {
		logf("[!] %s 解析失败: %v — 已备份为 .bak 并重建默认管理员", operatorsPath(), err)
		_ = os.Rename(operatorsPath(), operatorsPath()+".bak")
		operators = nil
		createDefaultAdminLocked()
		return
	}
	if len(f.Operators) == 0 {
		logf("[!] %s 中没有任何操作员 — 重建默认管理员", operatorsPath())
		createDefaultAdminLocked()
		return
	}
	operators = f.Operators
}

// createDefaultAdminLocked 生成默认管理员: 16 字节随机口令, 明文仅向 stdout 输出一次。
func createDefaultAdminLocked() {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		logf("[!] 生成默认管理员口令失败: %v", err)
		return
	}
	pass := authPassAlphabet.EncodeToString(raw)

	hash, err := HashPassword(pass)
	if err != nil {
		logf("[!] 计算默认管理员口令摘要失败: %v", err)
		return
	}
	operators = append(operators, Operator{User: authDefaultUser, PassHash: hash, Role: RoleAdmin})
	if err := saveOperatorsLocked(); err != nil {
		// 写盘失败仍要输出口令, 否则操作员将永久失去入口。
		logf("[!] 写入 %s 失败: %v", operatorsPath(), err)
	}

	authPromptf("%s\n", strings.Join([]string{
		"============================================================",
		"  Rainmaker C2 首次启动: 已创建默认管理员 (明文仅本次输出)",
		"    用户名: " + authDefaultUser,
		"    密码  : " + pass,
		"  用户库: " + operatorsPath(),
		"  请立即保存。该口令无法从哈希还原, 也不会再次打印。",
		"============================================================",
	}, "\n"))
}

// saveOperatorsLocked 原子写用户库: 先写临时文件再 rename (Windows 支持覆盖)。
func saveOperatorsLocked() error {
	data, err := json.MarshalIndent(operatorFile{Version: 1, Operators: operators}, "", "  ")
	if err != nil {
		return err
	}
	path := operatorsPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		// 极端场景 (句柄占用/杀软拦截) rename 失败时回退直接覆盖写。
		if werr := os.WriteFile(path, data, 0o600); werr != nil {
			_ = os.Remove(tmp)
			return werr
		}
		_ = os.Remove(tmp)
	}
	return nil
}

// ---------------------------------------------------------------- 口令哈希

// HashPassword 为新口令生成独立随机盐并返回编码串。
func HashPassword(pass string) (string, error) {
	salt := make([]byte, passSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	return formatPassHash(salt, pass), nil
}

func formatPassHash(salt []byte, pass string) string {
	return passHashScheme + "$" + hex.EncodeToString(salt) + "$" + digestPassword(salt, pass)
}

// digestPassword = hex(sha256(salt || password))。
func digestPassword(salt []byte, pass string) string {
	buf := make([]byte, 0, len(salt)+len(pass))
	buf = append(buf, salt...)
	buf = append(buf, pass...)
	sum := sha256.Sum256(buf)
	return hex.EncodeToString(sum[:])
}

// VerifyPassword 恒定时间校验编码串; 任何格式异常一律返回 false。
func VerifyPassword(enc, pass string) bool {
	parts := strings.Split(enc, "$")
	if len(parts) != 3 || parts[0] != passHashScheme {
		return false
	}
	salt, err := hex.DecodeString(parts[1])
	if err != nil {
		return false
	}
	want, err := hex.DecodeString(parts[2])
	if err != nil || len(want) != sha256.Size {
		return false
	}
	buf := make([]byte, 0, len(salt)+len(pass))
	buf = append(buf, salt...)
	buf = append(buf, pass...)
	got := sha256.Sum256(buf)
	return subtle.ConstantTimeCompare(got[:], want) == 1
}

// passHashSalt 取出盐的 hex (仅供内部与测试检查盐的随机性, 不对外暴露)。
func passHashSalt(enc string) string {
	parts := strings.Split(enc, "$")
	if len(parts) != 3 {
		return ""
	}
	return parts[1]
}

// ---------------------------------------------------------------- 角色

func validRole(r string) bool { return r == RoleAdmin || r == RoleOperator }

// roleCanManageUsers 只有 admin 能管理用户; operator 只读 + 下发命令。
func roleCanManageUsers(role string) bool { return role == RoleAdmin }

// ---------------------------------------------------------------- 令牌

// NewToken 生成 32 字节随机令牌并返回其 hex (64 字符)。
func NewToken() (string, error) {
	b := make([]byte, authTokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func issueToken(user, role string) (string, error) {
	tok, err := NewToken()
	if err != nil {
		return "", err
	}
	authSessionsMu.Lock()
	authSessions[tok] = opSession{User: user, Role: role, Expires: time.Now().Add(authTokenTTL).Unix()}
	authSessionsMu.Unlock()
	return tok, nil
}

// lookupToken 校验令牌并返回会话; 命中过期条目时即时清除。
func lookupToken(tok string) (opSession, bool) {
	if tok == "" {
		return opSession{}, false
	}
	authSessionsMu.Lock()
	defer authSessionsMu.Unlock()
	s, ok := authSessions[tok]
	if !ok {
		return opSession{}, false
	}
	if tokenExpired(s, time.Now().Unix()) {
		delete(authSessions, tok)
		return opSession{}, false
	}
	return s, true
}

func tokenExpired(s opSession, now int64) bool { return s.Expires <= now }

// revokeToken 删除令牌并返回原会话 (登出审计需要用户名)。
func revokeToken(tok string) (opSession, bool) {
	authSessionsMu.Lock()
	defer authSessionsMu.Unlock()
	s, ok := authSessions[tok]
	if ok {
		delete(authSessions, tok)
	}
	return s, ok
}

// purgeExpiredTokens 清理过期会话, 避免内存随登录次数无限增长。
func purgeExpiredTokens() {
	now := time.Now().Unix()
	authSessionsMu.Lock()
	defer authSessionsMu.Unlock()
	for k, v := range authSessions {
		if tokenExpired(v, now) {
			delete(authSessions, k)
		}
	}
}

// ---------------------------------------------------------------- 查询

func findOperatorLocked(user string) (Operator, bool) {
	for _, o := range operators {
		if o.User == user {
			return o, true
		}
	}
	return Operator{}, false
}

// findOperator 保证用户库已加载后返回账户副本。
func findOperator(user string) (Operator, bool) {
	ensureOperators()
	operatorsMu.RLock()
	defer operatorsMu.RUnlock()
	return findOperatorLocked(user)
}

// touchOperatorLast 更新最后登录时间并落盘。
func touchOperatorLast(user string) {
	operatorsMu.Lock()
	defer operatorsMu.Unlock()
	for i := range operators {
		if operators[i].User == user {
			operators[i].Last = time.Now().Unix()
			break
		}
	}
	if err := saveOperatorsLocked(); err != nil {
		logf("[!] 更新 %s 失败: %v", operatorsPath(), err)
	}
}

// ---------------------------------------------------------------- 工具

// tsText Unix 秒 → 本地时间字符串; 非正值返回 "-"。
func tsText(ts int64) string {
	if ts <= 0 {
		return "-"
	}
	return time.Unix(ts, 0).Format("2006-01-02 15:04:05")
}

// sanitizeUser 裁剪空白、按 rune 限长并剔除控制字符, 防审计日志被注入换行。
func sanitizeUser(s string) string {
	s = strings.TrimSpace(s)
	runes := []rune(s)
	if len(runes) > authMaxUserLen {
		s = string(runes[:authMaxUserLen])
	}
	var b strings.Builder
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// authAudit 审计统一落点, 形如 eventLog("operator", "", "登录", user)。
func authAudit(action, user string) {
	eventLog("operator", "", action, sanitizeUser(user))
}

func bearerToken(r *http.Request) string {
	const prefix = "Bearer "
	h := strings.TrimSpace(r.Header.Get("Authorization"))
	if len(h) > len(prefix) && strings.EqualFold(h[:len(prefix)], prefix) {
		return strings.TrimSpace(h[len(prefix):])
	}
	return ""
}

// authFail 输出鉴权失败响应, 状态码区分 401 (未认证) 与 403 (权限不足)。
func authFail(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "error": msg})
}

// authCheck 统一鉴权入口。返回 true 表示放行。
// 旁路模式下 (AuthEnabled()==false) 恒放行, 会话以占位 admin 表示。
func authCheck(w http.ResponseWriter, r *http.Request, needAdmin bool) (opSession, bool) {
	if !AuthEnabled() {
		return opSession{User: "-", Role: RoleAdmin}, true
	}
	sess, ok := lookupToken(bearerToken(r))
	if !ok {
		authFail(w, http.StatusUnauthorized, "未认证或令牌已失效")
		return opSession{}, false
	}
	if needAdmin && !roleCanManageUsers(sess.Role) {
		authFail(w, http.StatusForbidden, "需要管理员(admin)权限")
		return opSession{}, false
	}
	return sess, true
}

// ---------------------------------------------------------------- 中间件

// requireAuth 校验 Authorization: Bearer <token>。
// 启动参数 -auth=off 或 SetAuthEnabled(false) 时直接放行。
func requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := authCheck(w, r, false); !ok {
			return
		}
		next(w, r)
	}
}

// requireAdmin 在 requireAuth 基础上要求 admin 角色。
func requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := authCheck(w, r, true); !ok {
			return
		}
		next(w, r)
	}
}

// ---------------------------------------------------------------- HTTP

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, map[string]interface{}{"ok": false, "error": "仅支持 POST"})
		return
	}
	var req struct {
		User string `json:"user"`
		Pass string `json:"pass"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, map[string]interface{}{"ok": false, "error": "请求体不是合法 JSON"})
		return
	}
	user := sanitizeUser(req.User)
	purgeExpiredTokens()

	op, found := findOperator(user)
	if !found || !VerifyPassword(op.PassHash, req.Pass) {
		// 不区分"用户不存在"与"口令错误", 避免账户枚举。
		authAudit("登录失败", user)
		writeJSON(w, map[string]interface{}{"ok": false, "error": "用户名或密码错误"})
		return
	}
	tok, err := issueToken(op.User, op.Role)
	if err != nil {
		writeJSON(w, map[string]interface{}{"ok": false, "error": "令牌生成失败"})
		return
	}
	touchOperatorLast(op.User)
	authAudit("登录", op.User)
	writeJSON(w, map[string]interface{}{
		"ok": true, "token": tok, "role": op.Role, "user": op.User,
	})
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	if tok := bearerToken(r); tok != "" {
		if s, ok := revokeToken(tok); ok {
			authAudit("登出", s.User)
		}
	}
	// 幂等: 无令牌或令牌已失效也返回成功, 便于前端清理本地状态。
	writeJSON(w, map[string]interface{}{"ok": true})
}

func handleUserNew(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, map[string]interface{}{"ok": false, "error": "仅支持 POST"})
		return
	}
	if _, ok := authCheck(w, r, true); !ok {
		return
	}
	var req struct {
		User string `json:"user"`
		Pass string `json:"pass"`
		Role string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, map[string]interface{}{"ok": false, "error": "请求体不是合法 JSON"})
		return
	}
	user := sanitizeUser(req.User)
	if user == "" {
		writeJSON(w, map[string]interface{}{"ok": false, "error": "用户名不能为空"})
		return
	}
	if len([]rune(req.Pass)) < authMinPassLen {
		writeJSON(w, map[string]interface{}{"ok": false, "error": fmt.Sprintf("口令至少 %d 个字符", authMinPassLen)})
		return
	}
	role := strings.ToLower(strings.TrimSpace(req.Role))
	if role == "" {
		role = RoleOperator
	}
	if !validRole(role) {
		writeJSON(w, map[string]interface{}{"ok": false, "error": "角色只能是 admin 或 operator"})
		return
	}

	ensureOperators()
	operatorsMu.Lock()
	if _, exists := findOperatorLocked(user); exists {
		operatorsMu.Unlock()
		writeJSON(w, map[string]interface{}{"ok": false, "error": "用户已存在"})
		return
	}
	hash, err := HashPassword(req.Pass)
	if err != nil {
		operatorsMu.Unlock()
		writeJSON(w, map[string]interface{}{"ok": false, "error": "口令摘要计算失败"})
		return
	}
	operators = append(operators, Operator{User: user, PassHash: hash, Role: role})
	saveErr := saveOperatorsLocked()
	operatorsMu.Unlock()
	if saveErr != nil {
		writeJSON(w, map[string]interface{}{"ok": false, "error": "写入用户库失败: " + saveErr.Error()})
		return
	}
	authAudit("新建用户", user+" ("+role+")")
	writeJSON(w, map[string]interface{}{"ok": true, "user": user, "role": role})
}

func handleUsers(w http.ResponseWriter, r *http.Request) {
	if _, ok := authCheck(w, r, true); !ok {
		return
	}
	writeUsersList(w)
}

/* handleUserDelete 删除一个操作员账号。
 *
 * body: {"user":"alice"}
 * 安全约束(按重要程度):
 *   1. 只有 admin 能删 (authCheck 第三参数 true)
 *   2. **不能删最后一个 admin** —— 否则再也没人能登录管理, 面板等于自锁
 *   3. 不能删自己 —— 虽然删完 token 还有效, 但会立刻失去管理能力, 容易踩坑
 * 删完顺手撤销该用户的所有 token, 不让已发出的凭证继续可用。 */
func handleUserDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, map[string]interface{}{"ok": false, "error": "仅支持 POST"})
		return
	}
	sess, ok := authCheck(w, r, true)
	if !ok {
		return
	}
	var req struct {
		User string `json:"user"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, map[string]interface{}{"ok": false, "error": "请求体不是合法 JSON"})
		return
	}
	user := sanitizeUser(req.User)
	if user == "" {
		writeJSON(w, map[string]interface{}{"ok": false, "error": "用户名不能为空"})
		return
	}
	if user == sess.User {
		writeJSON(w, map[string]interface{}{"ok": false, "error": "不能删除自己当前登录的账号"})
		return
	}

	ensureOperators()
	operatorsMu.Lock()
	idx := -1
	admins := 0
	for i, o := range operators {
		if o.User == user {
			idx = i
		}
		if o.Role == RoleAdmin {
			admins++
		}
	}
	if idx < 0 {
		operatorsMu.Unlock()
		writeJSON(w, map[string]interface{}{"ok": false, "error": "用户不存在"})
		return
	}
	if operators[idx].Role == RoleAdmin && admins <= 1 {
		operatorsMu.Unlock()
		writeJSON(w, map[string]interface{}{"ok": false, "error": "这是最后一个 admin, 删掉就没人能管理了"})
		return
	}
	operators = append(operators[:idx], operators[idx+1:]...)
	saveErr := saveOperatorsLocked()
	operatorsMu.Unlock()
	if saveErr != nil {
		writeJSON(w, map[string]interface{}{"ok": false, "error": "写入用户库失败: " + saveErr.Error()})
		return
	}
	revokeUserTokens(user) // 该用户已发出的 token 立即失效
	authAudit("删除用户", user)
	writeJSON(w, map[string]interface{}{"ok": true, "user": user})
}

/* handleUserPass 改口令。body: {"user":"alice","pass":"新口令"}
 *
 * 权限: admin 能改任何人; 非 admin **只能改自己** (否则任何人拿到 operator 账号
 * 就能改别人的口令)。
 * 改自己时保留当前 token (不然会把自己踢下线); 改别人时撤销他的全部 token。 */
func handleUserPass(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, map[string]interface{}{"ok": false, "error": "仅支持 POST"})
		return
	}
	sess, ok := authCheck(w, r, false) // 不要求 admin: operator 也要能改自己的
	if !ok {
		return
	}
	var req struct {
		User string `json:"user"`
		Pass string `json:"pass"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, map[string]interface{}{"ok": false, "error": "请求体不是合法 JSON"})
		return
	}
	user := sanitizeUser(req.User)
	if user == "" {
		user = sess.User // 不填就是改自己
	}
	if user == "" {
		writeJSON(w, map[string]interface{}{"ok": false, "error": "用户名不能为空"})
		return
	}
	if sess.Role != RoleAdmin && user != sess.User {
		writeJSON(w, map[string]interface{}{"ok": false, "error": "只有 admin 能改别人的口令"})
		return
	}
	if len([]rune(req.Pass)) < authMinPassLen {
		writeJSON(w, map[string]interface{}{"ok": false, "error": fmt.Sprintf("口令至少 %d 个字符", authMinPassLen)})
		return
	}
	hash, err := HashPassword(req.Pass)
	if err != nil {
		writeJSON(w, map[string]interface{}{"ok": false, "error": "口令摘要计算失败"})
		return
	}
	ensureOperators()
	operatorsMu.Lock()
	idx := -1
	for i, o := range operators {
		if o.User == user {
			idx = i
			break
		}
	}
	if idx < 0 {
		operatorsMu.Unlock()
		writeJSON(w, map[string]interface{}{"ok": false, "error": "用户不存在"})
		return
	}
	operators[idx].PassHash = hash
	saveErr := saveOperatorsLocked()
	operatorsMu.Unlock()
	if saveErr != nil {
		writeJSON(w, map[string]interface{}{"ok": false, "error": "写入用户库失败: " + saveErr.Error()})
		return
	}
	if user != sess.User {
		revokeUserTokens(user) // 改别人的口令 -> 他得重新登录
	}
	authAudit("改口令", user)
	writeJSON(w, map[string]interface{}{"ok": true, "user": user})
}

// revokeUserTokens 撤销某个用户已发出的全部 token
func revokeUserTokens(user string) {
	authSessionsMu.Lock()
	defer authSessionsMu.Unlock()
	for tok, s := range authSessions {
		if s.User == user {
			delete(authSessions, tok)
		}
	}
}

// writeUsersList 只输出用户名/角色/最后登录 —— 盐与摘要一律不出网。
func writeUsersList(w http.ResponseWriter) {
	ensureOperators()
	operatorsMu.RLock()
	list := make([]map[string]interface{}, 0, len(operators))
	for _, o := range operators {
		list = append(list, map[string]interface{}{
			"user": o.User, "role": o.Role, "last": o.Last, "last_text": tsText(o.Last),
		})
	}
	operatorsMu.RUnlock()
	writeJSON(w, map[string]interface{}{"ok": true, "users": list})
}

// RegisterAuthRoutes 由 main 调用: 注册登录/登出与用户管理端点, 并确保用户库就绪。
func RegisterAuthRoutes(mux *http.ServeMux) {
	ensureOperators()

	mux.HandleFunc("/api/login", handleLogin)
	mux.HandleFunc("/api/logout", handleLogout)
	mux.HandleFunc("/api/user/new", handleUserNew)
	mux.HandleFunc("/api/user/delete", handleUserDelete)
	mux.HandleFunc("/api/user/pass", handleUserPass)
	mux.HandleFunc("/api/users", handleUsers)

	if AuthEnabled() {
		logf("[*] 访问控制: 已启用 (登录后以 Authorization: Bearer <token> 访问)")
	} else {
		logf("[!] 访问控制: 已旁路 (-auth=off) — 控制台无鉴权, 勿暴露到非受信网络")
	}
}
