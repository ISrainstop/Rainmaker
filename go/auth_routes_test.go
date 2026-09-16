package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestConsoleRoutesRequireAuth 反向断言: consoleRoutes 里每一条在
// "启用访问控制 + 不带令牌" 时都必须回 401。
//
// 这个用例的价值在于**将来**: 新增控制台接口时只要忘了往 consoleRoutes 里放,
// 或者放了但注册时漏套 requireAuth, 这里立刻红 —— 而不是等到某个未登录的人
// 把会话列表、凭据、键盘记录整个拉走之后才发现。
//
// 不会真的执行到业务 handler: requireAuth 在无令牌时直接 401 返回, 不调用 next,
// 所以这个用例不碰全局 store, 可以安全地跑。
func TestConsoleRoutesRequireAuth(t *testing.T) {
	oldAuth := AuthEnabled()
	SetAuthEnabled(true)
	defer SetAuthEnabled(oldAuth)

	if !AuthEnabled() {
		t.Skip("-auth=off 生效中 (硬旁路优先级高于 SetAuthEnabled), 本用例不适用")
	}
	if len(consoleRoutes) == 0 {
		t.Fatal("consoleRoutes 为空 —— 控制台接口清单不该是空的")
	}

	mux := http.NewServeMux()
	registerConsoleRoutes(mux)

	for _, c := range consoleRoutes {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, c.path, nil)
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s 未带令牌应回 401, 实际 %d (正文: %s)", c.path, rec.Code, rec.Body.String())
		}
	}
}

// TestRequireAuthBypassWhenOff 旁路模式必须真的放行。
//
// 这里用 dummy handler 而不是真跑 consoleRoutes: 那些 handler 会读全局 store,
// 在单元测试里跑它们没有意义还容易 nil panic; 本用例要证明的只是
// "requireAuth 自己会因 -auth=off 而放行" 这一条。
func TestRequireAuthBypassWhenOff(t *testing.T) {
	oldAuth := AuthEnabled()
	SetAuthEnabled(true)
	defer SetAuthEnabled(oldAuth)

	if !AuthEnabled() {
		t.Skip("-auth=off 生效中, 无法在测试里切换访问控制")
	}

	called := false
	h := requireAuth(func(w http.ResponseWriter, r *http.Request) { called = true })

	// 旁路: 直接放行
	SetAuthEnabled(false)
	h(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/state", nil))
	if !called {
		t.Error("旁路模式 (SetAuthEnabled(false) / -auth=off) 下 requireAuth 应直接放行")
	}

	// 启用: 无令牌必须 401 且不落到业务 handler
	SetAuthEnabled(true)
	called = false
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodGet, "/api/state", nil))
	if called {
		t.Error("启用访问控制后, 无令牌的请求不该被放行到业务 handler")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("无令牌应回 401, 实际 %d", rec.Code)
	}
}

// TestImplantRoutesNotInConsoleList 植入体通道与静态入口不能被套上操作员认证。
//
// 植入体手里只有 RSA/AES 会话密钥, 没有 Bearer 令牌 —— 一旦这些路径要求认证,
// 结果是所有植入体一起掉线, 而且现场很难看出是被自己的认证层挡掉的。
func TestImplantRoutesNotInConsoleList(t *testing.T) {
	mustNotProtect := []string{"/submit", "/report", "/task", "/result", "/api/login", "/api/logout", "/"}
	for _, p := range mustNotProtect {
		for _, c := range consoleRoutes {
			if c.path == p {
				t.Errorf("%s 是植入体通道或登录/静态入口, 不该出现在需要操作员令牌的清单里", p)
			}
		}
	}
}
