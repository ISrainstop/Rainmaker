using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Windows;
using System.Windows.Media;
using System.Windows.Threading;

namespace CsdevGui
{
    public partial class App : Application
    {
        private static readonly string ErrorLog =
            Path.Combine(Path.GetTempPath(), "csdev-gui-error.log");

        protected override void OnStartup(StartupEventArgs e)
        {
            // 解析层自证入口: csdev-gui.exe --selftest (不创建任何窗口, 退出码 0/1)
            if (e != null && e.Args != null && HasFlag(e.Args, "--selftest"))
            {
                RunSelfTest();
                return;
            }

            // 插件包探针: csdev-gui.exe --plugins-probe <file.json> [--api <baseUrl>] [--api404 <路径>]
            // 用**界面同一条解析路径**处理一批真实数据并转储, 供无人值守复核 (不创建窗口)
            if (e != null && e.Args != null && HasFlag(e.Args, "--plugins-probe"))
            {
                RunPluginProbe(e.Args);
                return;
            }

            // 报告 / 下载 / checkin 探针: csdev-gui.exe --report-probe <baseUrl> [--token <t>] [--sid <会话号>]
            // 走**界面同一个 CsdevApi**, 把三个新入口的取数路径与文案打出来 (不创建窗口, 只读)
            if (e != null && e.Args != null && HasFlag(e.Args, "--report-probe"))
            {
                RunReportProbe(e.Args);
                return;
            }

            base.OnStartup(e);

            // 控制台不允许因未处理异常整体退出: 记录后继续 (状态栏仍可用)
            DispatcherUnhandledException += delegate(object s, DispatcherUnhandledExceptionEventArgs ev)
            {
                Log("UI", ev.Exception);
                ev.Handled = true;
            };
            AppDomain.CurrentDomain.UnhandledException += delegate(object s, UnhandledExceptionEventArgs ev)
            {
                Log("DOMAIN", ev.ExceptionObject as Exception);
            };

            // 设 CSDEV_GUI_TRACE=1 时把 WPF 数据绑定错误写进同一个日志, 便于排查绑定路径
            if (Environment.GetEnvironmentVariable("CSDEV_GUI_TRACE") == "1")
            {
                try
                {
                    PresentationTraceSources.Refresh();
                    var src = PresentationTraceSources.DataBindingSource;
                    src.Switch.Level = SourceLevels.Warning;
                    src.Listeners.Add(new BindingListener());
                }
                catch { }
            }

            // ---------------------------------------------------------------- 登录门
            // 与原版 C2 相同的顺序: 先出登录框 (服务端地址 + 账号 + 口令), 认证通过才建主窗口。
            // 不通过就直接退出 —— 不留一个"能看但没权限"的空壳界面。
            //
            // 先把 ShutdownMode 切成 OnExplicitShutdown: 否则登录框一关、还没有别的窗口,
            // WPF 会判定"最后一个窗口已关闭"直接把进程结束掉, 主窗口根本来不及建。
            bool skipLogin = false;
            try { skipLogin = Environment.GetEnvironmentVariable("CSDEV_GUI_SKIP_LOGIN") == "1"; }
            catch { }

            // 无人值守钩子 (CSDEV_GUI_SKIP_LOGIN=1): 跳过登录门直接进主窗口。
            // 存在的唯一理由 —— 截图 / 探针 / 自动附着这些回归手段本身需要一个窗口,
            // 不跳过的话它们会全部卡在登录框上。正常使用不要设这个变量。
            if (!skipLogin)
            {
                ShutdownMode = ShutdownMode.OnExplicitShutdown;
                try
                {
                    var gate = new LoginDialog();
                    if (gate.ShowDialog() != true)
                    {
                        Shutdown();
                        return;
                    }
                    PreAuth.BaseUrl = gate.ResultBaseUrl;
                    PreAuth.Token = gate.ResultToken;
                    PreAuth.User = gate.ResultUser;
                    PreAuth.Role = gate.ResultRole;
                }
                catch (Exception ex)
                {
                    Log("LOGIN", ex);
                    Shutdown();
                    return;
                }
                ShutdownMode = ShutdownMode.OnLastWindowClose;
            }

            var main = new MainWindow();
            MainWindow = main;
            main.Show();
        }

        private static bool HasFlag(string[] args, string flag)
        {
            if (args == null) return false;
            for (int i = 0; i < args.Length; i++)
            {
                if (string.Equals(args[i], flag, StringComparison.OrdinalIgnoreCase)) return true;
            }
            return false;
        }

        /// <summary>
        /// 无窗口自证: 跑 SelfTest 的样本集并把逐项结果打到标准输出。
        ///
        /// 输出走 Console.Out —— 从 pwsh 重定向运行时 stdio 句柄已就绪;
        /// WinExe 子系统在直接双击时没有控制台, 失败只影响可见性, 不影响结果。
        /// </summary>
        private void RunSelfTest()
        {
            ShutdownMode = ShutdownMode.OnExplicitShutdown;
            int code = 1;
            try
            {
                var rep = SelfTest.Run();
                string text = BuildSelfTestText(rep);

                try
                {
                    // 不用 Console.Write: Console.Out 按首次访问时的控制台代码页编码, 中文会变乱码
                    using (var stdout = Console.OpenStandardOutput())
                    using (var w = new StreamWriter(stdout, new UTF8Encoding(false)))
                    {
                        w.Write(text);
                        w.Flush();
                    }
                }
                catch { }

                // 可选: CSDEV_SELFTEST_OUT=<路径> 时落盘一份 UTF-8(BOM) 副本, 便于留档与复核
                string dump = Environment.GetEnvironmentVariable("CSDEV_SELFTEST_OUT");
                if (!string.IsNullOrEmpty(dump))
                {
                    try { File.WriteAllText(dump, text, new UTF8Encoding(true)); }
                    catch { }
                }

                code = rep.Ok ? 0 : 1;
            }
            catch (Exception ex)
            {
                try
                {
                    using (var err = Console.OpenStandardError())
                    using (var w = new StreamWriter(err, new UTF8Encoding(false)))
                    {
                        w.Write("自证运行异常: " + ex + "\n");
                        w.Flush();
                    }
                }
                catch { }
                code = 1;
            }
            Environment.ExitCode = code;
            Shutdown(code);
        }

        // ---------------------------------------------------------------- 插件包探针

        /// <summary>取 <c>--名字 值</c> 形式的参数值 (下一个参数以 -- 开头视为缺失)。</summary>
        private static string ArgValue(string[] args, string flag)
        {
            if (args == null) return "";
            for (int i = 0; i < args.Length - 1; i++)
            {
                if (!string.Equals(args[i], flag, StringComparison.OrdinalIgnoreCase)) continue;
                string v = args[i + 1];
                if (v == null || v.StartsWith("--", StringComparison.Ordinal)) return "";
                return v;
            }
            return "";
        }

        /// <summary>收集 --名字 值 的所有出现 (可重复, 用于 --extra / --drop)。</summary>
        private static List<string> ArgValues(string[] args, string flag)
        {
            var list = new List<string>();
            if (args == null) return list;
            for (int i = 0; i < args.Length - 1; i++)
            {
                if (!string.Equals(args[i], flag, StringComparison.OrdinalIgnoreCase)) continue;
                string v = args[i + 1];
                if (v == null || v.StartsWith("--", StringComparison.Ordinal)) continue;
                list.Add(v);
            }
            return list;
        }

        /// <summary>
        /// 插件包探针 (无人值守复核用): 把一批真实数据喂给**界面同一条解析路径**
        /// (PluginParse / ApiError) 并把结果逐项打到标准输出。
        ///
        ///   --plugins-probe &lt;file.json&gt;   离线: 解析已落盘的 GET /api/plugins 响应
        ///   --api &lt;baseUrl&gt;                在线: 直接用 CsdevApi 拉一次 /api/plugins
        ///   --api404 &lt;路径&gt;                在线: 请求一个不存在的路由, 打印界面会显示的错误文案
        ///   --extra &lt;路径&gt;                  模拟『浏览…』挑入的路径 (可重复)
        ///   --drop &lt;路径&gt;                   模拟 external 面板『移除』的路径 (可重复)
        /// 只读, 不改任何状态; 不传这些参数时行为完全不变。
        /// </summary>
        private void RunPluginProbe(string[] args)
        {
            ShutdownMode = ShutdownMode.OnExplicitShutdown;
            int code = 1;
            string text;
            try
            {
                text = BuildPluginProbeText(args, out code);
            }
            catch (Exception ex)
            {
                text = "插件包探针运行异常: " + ex + "\n";
                code = 1;
            }
            try
            {
                using (var stdout = Console.OpenStandardOutput())
                using (var w = new StreamWriter(stdout, new UTF8Encoding(false)))
                {
                    w.Write(text);
                    w.Flush();
                }
            }
            catch { }
            Environment.ExitCode = code;
            Shutdown(code);
        }

        private static string BuildPluginProbeText(string[] args, out int code)
        {
            string jsonPath = ArgValue(args, "--plugins-probe");
            string api = ArgValue(args, "--api");
            string api404 = ArgValue(args, "--api404");
            List<string> extras = ArgValues(args, "--extra");
            List<string> drops = ArgValues(args, "--drop");

            var sb = new StringBuilder();
            sb.AppendLine("csdev-gui 插件包探针 (与界面同一条解析路径: PluginParse / ApiError)");
            sb.AppendLine("================================================================");
            sb.AppendLine("[参数] json=" + (jsonPath.Length > 0 ? jsonPath : "(无)")
                        + "  api=" + (api.Length > 0 ? api : "(无)")
                        + "  api404=" + (api404.Length > 0 ? api404 : "(无)")
                        + "  extra=" + extras.Count + "  drop=" + drops.Count);

            JsonElement root = default(JsonElement);
            bool have = false;
            JsonDocument doc = null;
            if (jsonPath.Length > 0)
            {
                string full = Path.GetFullPath(jsonPath);
                sb.AppendLine("[输入] 离线 JSON 文件 = " + full + " (" + new FileInfo(full).Length + " 字节)");
                doc = JsonDocument.Parse(File.ReadAllText(full));
                root = doc.RootElement;
                have = true;
            }
            else if (api.Length > 0)
            {
                var c = new CsdevApi();
                c.BaseUrl = api;
                sb.AppendLine("[输入] 在线 GET " + c.BaseUrl + "/api/plugins");
                doc = c.GetPluginsAsync().GetAwaiter().GetResult();
                root = doc.RootElement;
                have = true;
            }
            else
            {
                sb.AppendLine("用法: csdev-gui.exe --plugins-probe <file.json> [--api <baseUrl>] [--api404 <路径>]"
                            + " [--extra <路径>]... [--drop <路径>]...");
                code = 2;
                return sb.ToString();
            }

            if (have) DumpPluginView(sb, root, extras, drops);

            if (api.Length > 0 && api404.Length > 0)
            {
                sb.AppendLine("---- [5] 404 / 路由缺失文案 (界面状态栏显示的就是这一句) ----");
                var c = new CsdevApi();
                c.BaseUrl = api;
                sb.AppendLine("请求: GET " + c.BaseUrl + api404);
                try
                {
                    using (var d = c.GetJsonAsync(api404, new HttpClient()).GetAwaiter().GetResult())
                        sb.AppendLine("  意外成功: " + d.RootElement.ToString());
                }
                catch (Exception ex)
                {
                    sb.AppendLine("  界面文案: " + ex.Message);
                }
            }

            sb.AppendLine("================================================================");
            sb.AppendLine("探针完成");
            code = 0;
            return sb.ToString();
        }

        // ---------------------------------------------------------------- 报告 / 下载 / checkin 探针

        /// <summary>
        /// 报告导出 / 下载内容 / 催心跳三个新入口的**在线探针**: 走界面同一个 CsdevApi
        /// (同样的 URL 拼装、同样的字节流接收、同样的异常文案), 把结果逐项打到标准输出。
        ///
        /// 只是"无人值守下把 GUI 的取数路径真的跑一遍" —— 不落盘、不改状态 (checkin 那条
        /// 会真的催一次心跳, 所以只在显式给 --sid 时才发)。
        /// </summary>
        private void RunReportProbe(string[] args)
        {
            ShutdownMode = ShutdownMode.OnExplicitShutdown;
            int code = 1;
            string text;
            try
            {
                text = BuildReportProbeText(args, out code);
            }
            catch (Exception ex)
            {
                text = "报告探针运行异常: " + ex + "\n";
                code = 1;
            }
            try
            {
                using (var stdout = Console.OpenStandardOutput())
                using (var w = new StreamWriter(stdout, new UTF8Encoding(false)))
                {
                    w.Write(text);
                    w.Flush();
                }
            }
            catch { }
            Environment.ExitCode = code;
            Shutdown(code);
        }

        private static string BuildReportProbeText(string[] args, out int code)
        {
            string baseUrl = ArgValue(args, "--report-probe");
            string token = ArgValue(args, "--token");
            string sid = ArgValue(args, "--sid");
            var sb = new StringBuilder();
            sb.AppendLine("csdev-gui 报告/下载/checkin 探针 (与界面同一条取数路径: CsdevApi + ReportParse + DownloadContent + SessionParse)");
            sb.AppendLine("================================================================");
            if (baseUrl.Length == 0)
            {
                sb.AppendLine("用法: csdev-gui.exe --report-probe <baseUrl> [--token <令牌>] [--sid <会话号>]");
                code = 2;
                return sb.ToString();
            }

            var api = new CsdevApi();
            api.BaseUrl = baseUrl;
            if (token.Length > 0) api.Token = token;
            sb.AppendLine("[输入] base=" + api.BaseUrl + "  token=" + (api.HasToken ? "已设置" : "(无)"));
            sb.AppendLine("");

            sb.AppendLine("---- [1] 报告导出 (三端点) ----");
            ProbeBytes(sb, "GET " + ReportParse.JsonUrl + "  -> 保存 .json", delegate { return api.GetReportJsonAsync().GetAwaiter().GetResult(); });
            ProbeBytes(sb, "GET " + ReportParse.HtmlUrl + "  -> 保存 .html", delegate { return api.GetReportHtmlAsync().GetAwaiter().GetResult(); });

            foreach (string kind in new string[] { "events", "sessions", "jobs" })
            {
                string url = ReportParse.CsvUrl(kind);
                string fn = ReportParse.FileName(kind, "csv", DateTime.Now);
                ProbeBytes(sb, "GET " + url + "  -> 保存 " + fn,
                           delegate { return api.GetReportCsvAsync(kind).GetAwaiter().GetResult(); });
            }
            ProbeBytes(sb, "GET " + ReportParse.CsvUrl("ftp") + "  (未知 kind: 服务端应回 400 + JSON 正文)",
                       delegate { return api.GetReportCsvAsync("ftp").GetAwaiter().GetResult(); });

            sb.AppendLine("---- [2] 下载文件内容 (GET /api/download/file) ----");
            ProbeBytes(sb, "GET /api/download/file?id=1  (界面『查看内容』走的就是这条, 判定后给文本或十六进制)",
                       delegate { return api.GetDownloadFileAsync(1).GetAwaiter().GetResult(); });

            sb.AppendLine("---- [3] 催心跳 (POST /api/session/checkin) ----");
            ProbeCheckin(sb, api, sid.Length > 0 ? sid : "B999");

            sb.AppendLine("================================================================");
            sb.AppendLine("探针完成 (所有数据只读; 未落盘任何文件)");
            code = 0;
            return sb.ToString();
        }

        /// <summary>跑一次"取字节"并把界面会看到的东西打出来 (状态码文案 / 字节数 / BOM / 判定结果)。</summary>
        private static void ProbeBytes(StringBuilder sb, string what, Func<byte[]> call)
        {
            sb.AppendLine("  " + what);
            try
            {
                byte[] b = call();
                string head = b.Length >= 3
                    ? string.Format("前 3 字节 = {0:x2} {1:x2} {2:x2}{3}",
                                    b[0], b[1], b[2],
                                    (b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF) ? "  <- UTF-8 BOM" : "")
                    : "(不足 3 字节)";
                sb.AppendLine("    取到 = " + ReportParse.BytesText(b.Length) + "   " + head);
                sb.AppendLine("    状态栏文案(若此刻保存) = " + ReportParse.SavedText("D:\\out\\" + "sample.bin", b.Length));
                var dc = DownloadContent.Parse(b);
                sb.AppendLine("    内容判定 = " + (dc.IsBinary ? "二进制" : "文本") + "   " + dc.RatioText());
                string body = dc.TextBody();
                string one = body.Replace("\r", "\\r").Replace("\n", "\\n");
                if (one.Length > 160) one = one.Substring(0, 160) + " ...";
                sb.AppendLine("    首 160 字符 = " + one);
            }
            catch (Exception ex)
            {
                int code; string body;
                SplitApiError(ex, out code, out body);
                sb.AppendLine("    HTTP 状态码 = " + (code > 0 ? code.ToString() : "(非 HTTP 失败)"));
                sb.AppendLine("    服务端正文 = " + body);
                sb.AppendLine("    报告导出失败文案 = " + ReportParse.SaveErrorText("报告导出", code, body, ""));
                sb.AppendLine("    下载内容失败文案 = " + DownloadContent.ErrorText("1", code, body));
            }
            sb.AppendLine("");
        }

        /// <summary>
        /// 自测钩子: 把 CsdevApi 失败异常的拆分逻辑暴露给 --selftest
        /// (SelfTest 与本类同程序集, 但 SplitApiError 是 private —— 与其放宽可见性,
        /// 不如只开一个只读的测试入口)。
        /// </summary>
        internal static void TestSplitApiError(Exception ex, out int code, out string body)
        {
            SplitApiError(ex, out code, out body);
        }
        /// <summary>
        /// CsdevApi 的失败异常文案形如 "HTTP 404  |  &lt;服务端正文&gt;" —— 这里拆回状态码与正文,
        /// 因为上层文案函数要的是分开的两样东西 (拿整条消息再喂一遍会得到
        /// "HTTP 400  ...  HTTP 400  ..." 这种重复)。
        /// </summary>
        private static void SplitApiError(Exception ex, out int code, out string body)
        {
            string m = ex == null ? "" : ex.Message;
            code = 0;
            body = m;

            // 形态 A: "HTTP 400  |  {服务端正文}"  (ApiError.Describe 的通用分支)
            if (m.StartsWith("HTTP ", StringComparison.Ordinal))
            {
                int i = 5;
                int n = 0;
                while (i < m.Length && char.IsDigit(m[i])) { n = n * 10 + (m[i] - '0'); i++; }
                code = n;

                int sep = m.IndexOf("  |  ", StringComparison.Ordinal);
                if (sep >= 0) body = m.Substring(sep + 5);
                else if (i < m.Length && m[i] == ':') body = m.Substring(i + 1).TrimStart();
                else body = "";
                return;
            }

            // 形态 B: 404 走的是 "服务端缺少该路由 <path> (HTTP 404): <提示>  |  <正文>"
            // —— 这一支以中文开头, 状态码夹在中间; 不认出来就会把整条提示当成"服务端正文"。
            int mark = m.IndexOf("(HTTP ", StringComparison.Ordinal);
            if (mark >= 0)
            {
                int i = mark + 6;
                int n = 0;
                bool got = false;
                while (i < m.Length && char.IsDigit(m[i])) { n = n * 10 + (m[i] - '0'); i++; got = true; }
                if (got)
                {
                    code = n;
                    // 正文要取回"服务端原话": 分隔符之后的那一段。
                    // 例如 "服务端缺少该路由 /api/download/file (HTTP 404): 通常是...  |  404 page not found"
                    // -> body = "404 page not found" (这一句才是 DownloadContent.ErrorText 判定记录不存在的依据)
                    int sep = m.IndexOf("  |  ", StringComparison.Ordinal);
                    body = sep >= 0 ? m.Substring(sep + 5) : "";
                }
            }
        }

        private static void ProbeCheckin(StringBuilder sb, CsdevApi api, string sid)
        {
            sb.AppendLine("  POST /api/session/checkin  {\"sid\":\"" + sid + "\"}");
            try
            {
                using (var doc = api.CheckinAsync(sid).GetAwaiter().GetResult())
                {
                    var op = SessionParse.FromJson(doc.RootElement, sid);
                    sb.AppendLine("    服务端原文 = " + doc.RootElement.ToString());
                    sb.AppendLine("    状态栏文案 = " + op.Text);
                }
            }
            catch (Exception ex)
            {
                var op = SessionParse.FromException(sid, ex);
                sb.AppendLine("    状态栏文案 = " + op.Text);
            }
            sb.AppendLine("");
        }
        /// <summary>把一份 /api/plugins 响应按解析层口径逐项转储 (与界面显示同源)。</summary>
        private static void DumpPluginView(StringBuilder sb, JsonElement root, List<string> extras, List<string> drops)
        {            var v = PluginParse.Parse(root);
            var rows = PluginParse.Rows(v, null);

            sb.AppendLine("---- [1] GET /api/plugins 解析 (PluginParse.Parse) ----");
            sb.AppendLine("Present=" + v.Present + "  Ok=" + v.Ok + "  root=" + (v.Root.Length > 0 ? v.Root : "(空)"));
            if (!v.Ok) sb.AppendLine("服务端 error = " + v.Error);
            sb.AppendLine("StatsText = " + v.StatsText());
            sb.AppendLine("包 " + v.Plugins.Count + " 个 (可勾选 " + v.SelectableCount + " · 无主文件 " + v.BlockedCount
                        + " · 已选中 " + v.LoadedCount + " · 菜单项合计 " + v.MenusTotal
                        + " · 已加载脚本文件 " + v.Loaded.Count + " 个):");
            for (int i = 0; i < v.Plugins.Count; i++)
            {
                PluginPack p = v.Plugins[i];
                sb.AppendLine("  [" + i + "] " + p.Name + " | " + p.KindText + " | 文件 " + p.FilesText
                            + " | " + p.SizeText + " | " + p.StatusText + " | menus=" + p.MenusText
                            + " | 勾选=" + p.Checked + " | " + p.DetailText
                            + (p.Selectable ? "" : "  [不可勾选: " + p.BlockWhy + "]"));
            }
            sb.AppendLine("selected 残留 (既不在 plugins 也不在 external) " + v.SelectedMissing.Count + " 个: "
                        + (v.SelectedMissing.Count > 0 ? string.Join(" · ", v.SelectedMissing.ToArray()) : "(无)"));

            sb.AppendLine("---- [2] 服务端 external[] " + v.External.Count + " 个 (失效 " + v.ExternalBroken
                        + " · 贡献菜单项 " + v.ExternalMenus + ") ----");
            for (int i = 0; i < v.External.Count; i++)
            {
                PluginExternalRow x = v.External[i];
                sb.AppendLine("  [" + i + "] " + x.Name + " | " + x.ExistsText + " (" + BrushName(x.ExistsBrush)
                            + ") | 文件 " + x.FilesText + " | " + x.SizeText + " | menus=" + x.MenusText
                            + " | " + x.DetailText);
            }

            sb.AppendLine("---- [3] external 面板行 (服务端 ∪ 本地登记, 移除已生效) ----");
            var ext = PluginParse.ExternalRows(v, extras, drops);
            for (int i = 0; i < ext.Count; i++)
            {
                PluginExternalRow x = ext[i];
                sb.AppendLine("  [" + i + "] " + x.Name + " | " + x.ExistsText + " (" + BrushName(x.ExistsBrush)
                            + "/行 " + BrushName(x.RowBrush) + ") | menus=" + x.MenusText
                            + " (" + BrushName(x.MenusBrush) + ") | " + x.DetailText
                            + (x.Local ? "  [本地待提交]" : ""));
            }
            sb.AppendLine("ExternalSummaryText = " + PluginParse.ExternalSummaryText(ext));
            sb.AppendLine("ExternalHint = " + PluginParse.ExternalHint(ext));

            sb.AppendLine("---- [4] 提交集合 paths (勾选包 + 手工添加, 去重) ----");
            var picked = PluginParse.PickedPaths(rows);
            for (int i = 0; i < picked.Count; i++) sb.AppendLine("  勾选包[" + i + "] " + picked[i]);
            for (int i = 0; i < extras.Count; i++) sb.AppendLine("  手工添加[" + i + "] " + extras[i]);
            for (int i = 0; i < drops.Count; i++) sb.AppendLine("  已移除[" + i + "] " + drops[i]);
            var merged = PluginParse.MergePaths(picked, extras, drops);
            sb.AppendLine("merged paths = " + merged.Count + " 条 (勾选 " + picked.Count
                        + " + 手工 " + extras.Count + " - 去重/移除):");
            for (int i = 0; i < merged.Count; i++)
            {
                string[] tag = ExtraSource(merged[i], picked, extras);
                sb.AppendLine("  [" + i + "] " + merged[i] + "   <- " + tag[0]
                            + (tag[1].Length > 0 ? " / " + tag[1] : ""));
            }
        }

        /// <summary>一条 merged 路径来自哪里 (勾选包 / 手工添加 / 两者都命中 —— 去重后只留一条)。</summary>
        private static string[] ExtraSource(string path, List<string> picked, List<string> extras)
        {
            bool inPicked = PluginParse.IndexOfPath(picked, path) >= 0;
            bool inExtra = PluginParse.IndexOfPath(extras, path) >= 0;
            string who = inPicked && inExtra ? "勾选包+手工添加(同一路径, 已去重)"
                     : inPicked ? "勾选包" : "手工添加";
            return new string[] { who, inPicked && inExtra ? "同一文件" : "" };
        }

        /// <summary>画刷 -> 可读名 (证据里要能看出"红/黄标出失效")。</summary>
        private static string BrushName(Brush b)        {
            if (ReferenceEquals(b, Palette.Err)) return "红 Err";
            if (ReferenceEquals(b, Palette.Warn)) return "橙 Warn";
            if (ReferenceEquals(b, Palette.Ok)) return "绿 Ok";
            if (ReferenceEquals(b, Palette.Accent)) return "蓝 Accent";
            if (ReferenceEquals(b, Palette.Dim)) return "灰 Dim";
            if (ReferenceEquals(b, Palette.Fg)) return "白 Fg";
            return "其它";
        }

        private static string BuildSelfTestText(SelfTest.Report rep)
        {
            var sb = new StringBuilder();
            sb.AppendLine("csdev-gui 解析层自证 (依据 kits/beacon/beacon2.c 的实测输出格式)");
            sb.AppendLine("================================================================");
            sb.Append(rep.Log);
            sb.AppendLine("================================================================");
            sb.AppendFormat("用例 {0} 个: 通过 {1}, 失败 {2}   |   断言 {3} 项, 失败 {4} 项\n",
                    rep.Cases, rep.PassedCases, rep.Cases - rep.PassedCases, rep.Checks, rep.Failures.Count);
            if (rep.Ok)
            {
                sb.AppendLine("结果: PASS");
            }
            else
            {
                sb.AppendLine("结果: FAIL");
                foreach (string f in rep.Failures) sb.Append("  x " + f + "\n");
            }
            return sb.ToString();
        }

        private static void Log(string tag, Exception ex)
        {
            try
            {
                File.AppendAllText(ErrorLog,
                    DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + " [" + tag + "] " +
                    (ex == null ? "(null exception)" : ex.ToString()) + Environment.NewLine,
                    new UTF8Encoding(true));
            }
            catch { }
        }

        private sealed class BindingListener : TraceListener
        {
            public override void Write(string message) { }

            public override void WriteLine(string message)
            {
                Log("BIND", new Exception(message));
            }
        }
    }
}
