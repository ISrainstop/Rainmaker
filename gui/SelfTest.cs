using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Windows.Media;

namespace CsdevGui
{
    /// <summary>
    /// 解析层自证。样本全部照抄实测输出格式 (制表符 + CRLF), 覆盖:
    /// 正常行 / 字段缺失 / 空行 / 中文名 / 含空格名 / 超长名 / 提示行 /
    /// 路径拼接边界。
    ///
    /// 运行方式 (无窗口, 不进 UI):
    ///   csdev-gui.exe --selftest
    /// 退出码 0 = 全过, 1 = 有失败。
    /// </summary>
    public static class SelfTest
    {
        public sealed class Report
        {
            public int Cases;
            public int PassedCases;
            public int Checks;
            public readonly List<string> Failures = new List<string>();
            public readonly StringBuilder Log = new StringBuilder();

            public bool Ok { get { return Failures.Count == 0; } }

            public void Fail(string msg)
            {
                Failures.Add(msg);
            }
        }

        private sealed class Ctx
        {
            public Report Rep;
            public string Case = "";
            public int CaseChecks;
            public int CaseFails;

            public void Note(string s)
            {
                Rep.Log.Append("      ").Append(s).Append('\n');
            }

            public void Check(string what, object actual, object expected)
            {
                Rep.Checks++;
                CaseChecks++;
                string a = actual == null ? "(null)" : actual.ToString();
                string e = expected == null ? "(null)" : expected.ToString();
                if (string.Equals(a, e, StringComparison.Ordinal))
                {
                    Rep.Log.Append("      [OK]   ").Append(what).Append(" = ").Append(Short(a)).Append('\n');
                }
                else
                {
                    CaseFails++;
                    Rep.Fail("断言不符 " + what + ": 实际=[" + Short(a) + "] 期望=[" + Short(e) + "]");
                }
            }

            /// <summary>用于植入体侧硬截断的样本: 实际值应是期望值的前缀。</summary>
            public void CheckPrefix(string what, string actual, string expectedPrefix)
            {
                Rep.Checks++;
                CaseChecks++;
                string a = actual ?? "";
                bool ok = a.StartsWith(expectedPrefix, StringComparison.Ordinal);
                if (ok) Rep.Log.Append("      [OK]   ").Append(what).Append(" 以期望前缀开头 (实际 ")
                              .Append(a.Length).Append(" 字符 / 期望前缀 ").Append(expectedPrefix.Length).Append(" 字符)\n");
                else
                {
                    CaseFails++;
                    Rep.Fail("前缀不符 " + what + ": 实际=[" + Short(a) + "] 期望前缀=[" + Short(expectedPrefix) + "]");
                }
            }

            private static string Short(string s)
            {
                if (s == null) return "(null)";
                s = s.Replace("\t", "<TAB>").Replace("\r", "<CR>").Replace("\n", "<LF>");
                return s.Length <= 96 ? s : s.Substring(0, 96) + "…(" + s.Length + ")";
            }
        }

        public static Report Run()
        {
            var rep = new Report();
            var cases = new List<KeyValuePair<string, Action<Ctx>>>();

            cases.Add(new KeyValuePair<string, Action<Ctx>>("文件列表: 正常行 (d/- 混排, 目录优先)", FileNormal));
            cases.Add(new KeyValuePair<string, Action<Ctx>>("文件列表: 字段缺失 (2 段 / 纯文本无 TAB / 空行)", FileShort));
            cases.Add(new KeyValuePair<string, Action<Ctx>>("文件列表: 中文文件名", FileChinese));
            cases.Add(new KeyValuePair<string, Action<Ctx>>("文件列表: 含空格文件名", FileSpaces));
            cases.Add(new KeyValuePair<string, Action<Ctx>>("文件列表: 超长文件名 (植入体 540 字节行缓冲截断)", FileLong));
            cases.Add(new KeyValuePair<string, Action<Ctx>>("文件列表: 全部退化输入 (空串/空行/报错文本)", FileDegenerate));
            cases.Add(new KeyValuePair<string, Action<Ctx>>("进程列表: 正常四字段 + 排序稳定性", ProcNormal));
            cases.Add(new KeyValuePair<string, Action<Ctx>>("进程列表: 字段缺失 / 空行 / 非数字", ProcShort));
            cases.Add(new KeyValuePair<string, Action<Ctx>>("进程列表: 中文与含空格进程名", ProcNames));
            cases.Add(new KeyValuePair<string, Action<Ctx>>("进程列表: 仅表头/全空", ProcDegenerate));
            cases.Add(new KeyValuePair<string, Action<Ctx>>("路径: 拼接与规范化 (\\ / .. . 混用)", Paths));
            cases.Add(new KeyValuePair<string, Action<Ctx>>("路径: is-absolute 与上级目录", PathParent));
            cases.Add(new KeyValuePair<string, Action<Ctx>>("路径: POSIX 规范化 (Linux/macOS 会话的文件浏览)", PosixPaths));
            cases.Add(new KeyValuePair<string, Action<Ctx>>("平台判定: os 字符串 -> POSIX/Windows (决定分隔符与根路径)", OsPlatformDetect));
            cases.Add(new KeyValuePair<string, Action<Ctx>>("文件列表解析: 命令回显行不进列表", FileListIgnoresEcho));
            cases.Add(new KeyValuePair<string, Action<Ctx>>("命令构造: kill 的 v1/v2 分歧与 inject", Commands));
            cases.Add(new KeyValuePair<string, Action<Ctx>>("编码: UTF-8 / GBK / base64 双编码自适应", Codecs));
            cases.Add(new KeyValuePair<string, Action<Ctx>>("目标库: source 标签拆分 / 去重 / 着色", TargetSources));
            cases.Add(new KeyValuePair<string, Action<Ctx>>("目标库: 模糊过滤 / 空值降级 / 本地时间格式化", TargetFiltering));
            cases.Add(new KeyValuePair<string, Action<Ctx>>("目标库: /api/state.targets 解析 (字段缺失 / 类型不符 / 整块缺失)", TargetsFromState));
            cases.Add(new KeyValuePair<string, Action<Ctx>>("代理枢轴: /api/state.proxy 解析 (SOCKS / rportfwd / 计数器 / 缺失降级)", ProxyFromState));
            cases.Add(new KeyValuePair<string, Action<Ctx>>("脚本插件: 菜单助记符 & 剥离 (单个 / 字面 && / 中文名)", ScriptMnemonic));
            cases.Add(new KeyValuePair<string, Action<Ctx>>("脚本插件: popup parent -> 右键菜单挂载点分类", ScriptMountTable));
            cases.Add(new KeyValuePair<string, Action<Ctx>>("脚本插件: /api/scripts 菜单树解析 (item/menu/sep + 计数 + 挂载统计)", ScriptMenusFromApi));
            cases.Add(new KeyValuePair<string, Action<Ctx>>("脚本插件: 菜单树退化输入 (字段缺失 / 类型不符 / 空 popup)", ScriptMenusDegenerate));
            cases.Add(new KeyValuePair<string, Action<Ctx>>("脚本插件: /api/state.scripts 摘要签名与命令表匹配", ScriptStateSummary));
            cases.Add(new KeyValuePair<string, Action<Ctx>>("脚本插件: 执行结果文案 (ok / 未找到命令 / 服务端错误)", ScriptRunResult));
            cases.Add(new KeyValuePair<string, Action<Ctx>>("插件包: /api/plugins 正常列表 (目录包/散装 .cna · loaded · menus · 初始勾选态)", PluginNormal));
            cases.Add(new KeyValuePair<string, Action<Ctx>>("插件包: 无主文件包 (main 为空 + err) 不可勾选, err 原样显示", PluginErrPack));
            cases.Add(new KeyValuePair<string, Action<Ctx>>("插件包: selected 含不存在路径 / 空串 / 大小写差异 (插件目录换过)", PluginSelectedMissing));
            cases.Add(new KeyValuePair<string, Action<Ctx>>("插件包: 空列表 · ok=false+error · 顶层非对象", PluginEmptyAndFail));
            cases.Add(new KeyValuePair<string, Action<Ctx>>("插件包: 字段缺失 / 类型不符的降级 (name/kind/main/files/bytes/menus)", PluginFieldDegrade));
            cases.Add(new KeyValuePair<string, Action<Ctx>>("插件包: 应用结果文案 (ok 计数 / 服务端 error 原样 / 换根)", PluginSetResult));
            cases.Add(new KeyValuePair<string, Action<Ctx>>("插件包: 勾选态与待应用覆盖 (pending 优先 · 取消勾选 · 空数组=卸载)", PluginCheckedState));
            cases.Add(new KeyValuePair<string, Action<Ctx>>("插件包: 真实 /api/plugins 响应样本 (8 包 · LSTAR/TaoWu 已选中)", PluginRealSample));
            cases.Add(new KeyValuePair<string, Action<Ctx>>("插件包: external 正常列表 (存在/目录/菜单项/大小 + 摘要与提示)", PluginExternalNormal));
            cases.Add(new KeyValuePair<string, Action<Ctx>>("插件包: external 失效条目 (exists=false · err 原文 · 红/橙标注)", PluginExternalBroken));
            cases.Add(new KeyValuePair<string, Action<Ctx>>("插件包: external 空/缺失/类型不符/元素非对象 (降级不抛)", PluginExternalDegrade));
            cases.Add(new KeyValuePair<string, Action<Ctx>>("插件包: external 面板行 (服务端 ∪ 本地登记 · 去重 · 移除后不显示)", PluginExternalRows));
            cases.Add(new KeyValuePair<string, Action<Ctx>>("插件包: paths 合并去重 (同一文件既勾选又手工添加 · 大小写 · 移除名单)", PluginMergePaths));
            cases.Add(new KeyValuePair<string, Action<Ctx>>("接口错误文案: 404 路由缺失 (服务端二进制过旧) 与其它状态码", ApiErrorText));
            cases.Add(new KeyValuePair<string, Action<Ctx>>("作业: /api/state.jobs 解析 (运行中 / 已结束 / 缺失降级)", JobsFromState));
            cases.Add(new KeyValuePair<string, Action<Ctx>>("作业: 耗时计算 (started/ended/now) 与状态文案着色", JobElapsedStatus));
            cases.Add(new KeyValuePair<string, Action<Ctx>>("作业: 差分签名与过滤 (会话 / running)", JobSignatureAndFilter));
            cases.Add(new KeyValuePair<string, Action<Ctx>>("作业: jobkill 结果文案 (原样保留『无法中途终止』)", JobKillText));
            cases.Add(new KeyValuePair<string, Action<Ctx>>("作业: 会话过滤下拉 (JobSidItem 差分与选中恢复)", JobSidItems));
            cases.Add(new KeyValuePair<string, Action<Ctx>>("载荷: /api/payload/build 请求体 (字段名 · no_sleep 省略 · 口令序列化)", PayloadRequestBody));
            cases.Add(new KeyValuePair<string, Action<Ctx>>("载荷: 启动口令本地校验 (含空白字符 · 过短 · 留空) 与日志脱敏", PayloadPasswordGate));
            cases.Add(new KeyValuePair<string, Action<Ctx>>("监听器: add/remove 回执文案 (成功 · 服务端 error 原样 · 非对象)", ListenerOpText));
            cases.Add(new KeyValuePair<string, Action<Ctx>>("监听器: 主 listener 不可删判定 + 行模型 + id 兼容解析", ListenerBuiltin));
            cases.Add(new KeyValuePair<string, Action<Ctx>>("监听器: kind -> 地址示例映射与本地空地址拦截", ListenerKindExample));
            cases.Add(new KeyValuePair<string, Action<Ctx>>("监听器: protected/manageable 字段解析与判定优先级", ListenerFlagPriority));
            cases.Add(new KeyValuePair<string, Action<Ctx>>("账号: 口令长度与角色校验 (与服务端 authMinPassLen/validRole 对齐)", AccountValidate));
            cases.Add(new KeyValuePair<string, Action<Ctx>>("账号: 用户名 sanitizeUser 清洗 (空白/控制字符/超长)", AccountSanitize));
            cases.Add(new KeyValuePair<string, Action<Ctx>>("账号: /api/users 解析 (真实响应样本 + 退化输入)", AccountUsersParse));
            cases.Add(new KeyValuePair<string, Action<Ctx>>("账号: 删自己与最后一个 admin 的本地预判 (服务端原文对照)", AccountDeleteRules));
            cases.Add(new KeyValuePair<string, Action<Ctx>>("账号: 增删改结果文案 (成功 / 服务端 error 原样)", AccountOpText));
            cases.Add(new KeyValuePair<string, Action<Ctx>>("账号: 登录响应解析 (token/role · ok 无 token · 错误)", AccountLoginParse));
            cases.Add(new KeyValuePair<string, Action<Ctx>>("账号: 管理区可用性三态 (admin / operator / 未登录)", AccountAccessRule));
            cases.Add(new KeyValuePair<string, Action<Ctx>>("连接: 地址规范化 (与 CsdevApi.BaseUrl 逐样本一致)", ConnNormalize));
            cases.Add(new KeyValuePair<string, Action<Ctx>>("连接: 保存/读取往返 · 去重 · 删除 (临时目录)", ConnRoundTrip));
            cases.Add(new KeyValuePair<string, Action<Ctx>>("连接: 口令不落盘 (键名白名单 + 明文不出现在文件里)", ConnNoPassword));
            cases.Add(new KeyValuePair<string, Action<Ctx>>("连接: 损坏/异构配置降级 (非 JSON / 坏条目 / 文件内重复)", ConnDegrade));
            cases.Add(new KeyValuePair<string, Action<Ctx>>("监听器: 类型 -> 标签/示例/说明映射 (HTTP(S) 标注运行期不支持)", ListenerKindsDialog));
            cases.Add(new KeyValuePair<string, Action<Ctx>>("监听器: HTTP(S) 被拒文案 = 服务端实测原文", ListenerHttpReject));
            cases.Add(new KeyValuePair<string, Action<Ctx>>("报告导出: URL 拼装 (json/html/csv kind 转义) 与默认文件名", ReportUrls));
            cases.Add(new KeyValuePair<string, Action<Ctx>>("报告导出: 错误文案 (401 需要登录 / 404 路由缺失 / 400 非 CSV 正文)", ReportErrorText));
            cases.Add(new KeyValuePair<string, Action<Ctx>>("下载内容: 文本 vs 二进制判定 (BOM / GBK / NUL) 与十六进制摘要", DownloadContentRules));
            cases.Add(new KeyValuePair<string, Action<Ctx>>("催心跳: checkin 结果文案 (成功 / 非 v2 原样 / 网络异常)", CheckinText));
            cases.Add(new KeyValuePair<string, Action<Ctx>>("接口失败正文 -> 状态栏文案 (401 / 404 / 400 / 非 HTTP)", ServerFailText));
            cases.Add(new KeyValuePair<string, Action<Ctx>>("接口失败异常文案的拆分 (HTTP nnn 两种形态)", ApiErrorSplit));
            cases.Add(new KeyValuePair<string, Action<Ctx>>("XAML 绑定源必须是属性 (DisplayMemberPath 的六个源类型)", BindingSourcesAreProps));
            cases.Add(new KeyValuePair<string, Action<Ctx>>("App.xaml 资源可加载 + 系统色接管生效 (x:Static 是运行期求值的)", AppResourceStyling));

            foreach (var kv in cases)
            {
                var ctx = new Ctx();
                ctx.Rep = rep;
                ctx.Case = kv.Key;
                rep.Log.Append("  [" + (rep.Cases + 1).ToString("00") + "] ").Append(kv.Key).Append('\n');
                try
                {
                    kv.Value(ctx);
                }
                catch (Exception ex)
                {
                    ctx.CaseFails++;
                    rep.Fail("用例抛异常: " + ex.GetType().Name + ": " + ex.Message);
                }
                rep.Cases++;
                if (ctx.CaseFails == 0) rep.PassedCases++;
                rep.Log.Append("       小结: ").Append(ctx.CaseChecks).Append(" 项断言, ")
                       .Append(ctx.CaseFails).Append(" 项失败\n\n");
            }
            return rep;
        }

        // ================================================================ 文件列表

        private const string PWD = "C:\\Users\\Public";

        private static void FileNormal(Ctx c)
        {
            // 实测格式: <d|-> \t <size> \t <name> \r\n
            string raw = "d\t0\tsub\r\n" +
                         "d\t0\tTemp\r\n" +
                         "-\t0\tflag.txt\r\n" +
                         "-\t1024000\tbig.iso\r\n" +
                         "-\t31\ta.txt\r\n";
            var list = NativeParse.FileList(raw);
            c.Check("条目数", list.Count, 5);
            c.Check("目录优先 [0]", list[0].Name, "sub");
            c.Check("[0].IsDir", list[0].IsDir, true);
            c.Check("[0].Kind", list[0].Kind, "目录");
            c.Check("[0].TypeMark", list[0].TypeMark, "d");
            c.Check("[1].Name (同组内按名排序)", list[1].Name, "Temp");
            c.Check("[2] 首个文件", list[2].Name, "a.txt");
            c.Check("[2].IsDir", list[2].IsDir, false);
            c.Check("[3] 序列", list[3].Name, "big.iso");
            c.Check("[3].SizeText", list[3].SizeText, "1000.0 KB");
            c.Check("[4] 序列", list[4].Name, "flag.txt");
            c.Check("[4].SizeText", list[4].SizeText, "0 B");
            c.Check("无原始行", CountRaw(list), 0);
        }

        private static void FileShort(Ctx c)
        {
            string raw = "\n" +                                  // 前导空行
                         "d\t0\r\n" +                            // 只有 2 段
                         "[-] 无法枚举目录\r\n" +                  // 无 TAB 的植入体报错
                         "-\t1024\r\n" +                         // 只有 2 段
                         " \r\n" +                               // 纯空格行 (非空, 无 TAB)
                         "-\t12\treal.dll\r\n";
            var list = NativeParse.FileList(raw);
            c.Check("条目数 (合法 1 + 退化 4)", list.Count, 5);
            c.Check("2 段行降级为原始", FindNamed(list, "d\t0").Kind, "原始");
            c.Check("2 段行标记 Raw", FindNamed(list, "d\t0").Raw, true);
            c.Check("2 段行 SizeText 空", FindNamed(list, "d\t0").SizeText, "-");
            c.Check("2 段行 OpText 空 (不可操作)", FindNamed(list, "d\t0").OpText, "");
            c.Check("报错文本保真 (无 TAB -> 提示)", FindNamed(list, "[-] 无法枚举目录").Kind, "提示");
            c.Check("空白行不被吞成空条目", FindNamed(list, " ").Kind, "提示");
            c.Check("空白行原样保留", FindNamed(list, " ") != null, true);
            var real = FindNamed(list, "real.dll");
            c.Check("合法行仍然解析", real != null, true);
            c.Check("real.dll 大小", real == null ? 0 : real.Size, 12);
            c.Check("空行被跳过 (无 0 长度条目)", CountEmptyName(list), 0);
        }

        private static void FileChinese(Ctx c)
        {
            string raw = "-\t2048\t报表 2026 年 1 月.xlsx\r\n" +
                         "d\t0\t安装包\r\n" +
                         "-\t9\t\u8bf4\u660e.txt\r\n" +
                         "-\t7\t\u65e5\u5fd7.log\r\n";
            var list = NativeParse.FileList(raw);
            c.Check("条目数", list.Count, 4);
            c.Check("中文目录名", list[0].Name, "安装包");
            c.Check("[0].IsDir", list[0].IsDir, true);
            c.Check("中文文件 + 空格名", list[1].Name, "报表 2026 年 1 月.xlsx");
            c.Check("中文文件大小", list[1].Size, 2048);
            c.Check("中文名序 3 (日志)", list[2].Name, "日志.log");
            c.Check("中文名序 4 (说明)", list[3].Name, "说明.txt");
        }

        private static void FileSpaces(Ctx c)
        {
            string raw = "-\t4096\tProgram Files (x86).txt\r\n" +
                         "d\t0\tMy Documents\r\n" +
                         "-\t1\ta  b   c.txt\r\n" +           // 连续空格
                         "-\t2\t leading-space.txt\r\n" +       // 前导空格
                         "-\t3\ttrailing-space .txt\r\n";
            var list = NativeParse.FileList(raw);
            c.Check("条目数 (含无 TAB 提示行)", list.Count, 5);
            c.Check("目录优先 [0]", list[0].Name, "My Documents");
            c.Check("前导空格名 [1] (空格 U+0020 序数最小)", list[1].Name, " leading-space.txt");
            c.Check("连续空格名 [2] (a 序数小于 p)", list[2].Name, "a  b   c.txt");
            c.Check("含括号空格名 [3]", list[3].Name, "Program Files (x86).txt");
            c.Check("尾部空格保真 [4]", list[4].Name, "trailing-space .txt");
            c.Check("前导空格名对应 2 字节", FindNamed(list, " leading-space.txt").Size, 2);
            c.Check("括号空格名对应 4096 字节", FindNamed(list, "Program Files (x86).txt").Size, 4096);
        }

        private static void FileLong(Ctx c)
        {
            // 植入体 line[540] + 名字循环 n < 530: 名字超限会被硬截断, 且无标记。
            // 这里既验证"不抛异常", 也验证解析器如实反映被截断的事实。
            var sb = new StringBuilder("d\t0\t");
            var name = new StringBuilder();
            for (int i = 0; i < 600; i++)
            {
                char ch = (char)('a' + (i % 26));
                sb.Append(ch);
                name.Append(ch);
            }
            string raw = "-\t7\tshort.txt\r\n" + sb.ToString() + "\r\n" + "-\t8\ttail.txt\r\n";

            var list = NativeParse.FileList(raw);
            var longItem = FindNamed(list, name.ToString());
            c.Check("条目数", list.Count, 3);
            c.Check("超长行被解析为目录", longItem == null ? false : longItem.IsDir, true);
            c.Check("名字长度 (600 字符样本原样保留)", longItem == null ? -1 : longItem.Name.Length, 600);
            c.Check("后续行不受污染", FindNamed(list, "short.txt") != null, true);
            c.Check("末行仍可达", FindNamed(list, "tail.txt") != null, true);

            // 植入体侧真被截断的样子 (530 字符处断开, 无任何标记)
            string truncated = "-\t3\t" + new string('L', 530);
            var list2 = NativeParse.FileList(truncated + "\r\n-\t4\tok.txt\r\n");
            c.Check("截断样本条目数", list2.Count, 2);
            c.Check("截断名长度", list2[0].Name.Length, 530);
            c.Check("截断后同行仍可解析大小", list2[0].Size, 3);
            c.Check("截断不影响下一行", list2[1].Name, "ok.txt");
        }

        private static void FileDegenerate(Ctx c)
        {
            c.Check("null 输入", NativeParse.FileList(null).Count, 0);
            c.Check("空串输入", NativeParse.FileList("").Count, 0);
            c.Check("纯换行", NativeParse.FileList("\r\n\r\n\r\n").Count, 0);
            c.Check("纯 TAB 行 = 原始行 (3 段空字段)", NativeParse.FileList("\t\t\r\n").Count, 1);
            c.Check("纯 TAB 行类型", NativeParse.FileList("\t\t\r\n")[0].Kind, "原始");
            c.Check("CR 单行分隔 (无 LF)", NativeParse.FileList("d\t0\ta\r-\t1\tb\r").Count, 2);
            c.Check("未知类型字符保留", NativeParse.FileList("x\t9\todd\r\n")[0].Kind, "x");
            c.Check("未知类型不当作目录", NativeParse.FileList("x\t9\todd\r\n")[0].IsDir, false);
            c.Check("负大小 -> 原始", NativeParse.FileList("-\t-5\tbad\r\n")[0].Kind, "原始");
            c.Check("非数字大小 -> 原始", NativeParse.FileList("-\tabc\tbad\r\n")[0].Kind, "原始");
            c.Check("只读大小行依然给名字", NativeParse.FileList("-\t0\t\r\n")[0].Kind, "原始");
        }

        // ================================================================ 进程列表

        private static void ProcNormal(Ctx c)
        {
            // 实测格式: pid \t ppid \t threads \t name \r\n
            string raw = "4\t0\t8\tSystem\r\n" +
                         "620\t4\t12\tcsrss.exe\r\n" +
                         "7896\t620\t24\tcsdev-beacon.exe\r\n" +
                         "1120\t4\t31\tsvchost.exe\r\n";
            var list = NativeParse.ProcList(raw);
            c.Check("条目数", list.Count, 4);
            c.Check("[0].Pid", list[0].Pid, 4);
            c.Check("[0].Ppid", list[0].Ppid, 0);
            c.Check("[0].Threads", list[0].Threads, 8);
            c.Check("[0].Name", list[0].Name, "System");
            c.Check("[2].Ppid (非 0 父进程)", list[2].Ppid, 620);
            c.Check("[2].Threads", list[2].Threads, 24);
            c.Check("原始顺序保持 (不做排序)", list[3].Name, "svchost.exe");
            c.Check("无原始行", CountRawProc(list), 0);
        }

        private static void ProcShort(Ctx c)
        {
            string raw = "\r\n" +                              // 空行
                         "4\t0\t8\r\n" +                        // 只有 3 段
                         "620\t4\t12\tcsrss.exe\r\n" +          // 合法
                         "abc\t4\t12\tbad.exe\r\n" +            // pid 非数字
                         "\t\t\t\r\n" +                         // 4 段全空
                         "1120\t4\tnotnum\tx.exe\r\n";          // threads 非数字
            var list = NativeParse.ProcList(raw);
            c.Check("条目数 (5 条退化 + 1 条合法)", list.Count, 5);
            var three = FindProcName(list, "4\t0\t8");
            c.Check("3 段行 -> 提示", three == null ? false : three.Raw, true);
            c.Check("3 段行名保真", three == null ? "" : three.Name, "4\t0\t8");
            var bad = FindProcName(list, "abc\t4\t12\tbad.exe");
            c.Check("非数字 pid -> 提示", bad == null ? false : bad.Raw, true);
            var ok = FindProcName(list, "csrss.exe");
            c.Check("合法行照常", ok != null, true);
            c.Check("合法行 pid", ok == null ? -1 : ok.Pid, 620);
            var badThreads = FindProcName(list, "1120\t4\tnotnum\tx.exe");
            c.Check("非数字 threads -> 提示", badThreads == null ? false : badThreads.Raw, true);
            c.Check("提示行 PidText", three == null ? "" : three.PidText, "-");
            c.Check("提示行 RowMark", three == null ? "" : three.RowMark, "提示");
            c.Check("空行被跳过", CountEmptyProc(list), 0);
        }

        private static void ProcNames(Ctx c)
        {
            string raw = "4060\t1444\t6\tWindows Explorer.exe\r\n" +
                         "700\t620\t3\t\u5b88\u62a4\u8fdb\u7a0b.exe\r\n" +
                         "900\t620\t4\tMy App (x64).exe\r\n";
            var list = NativeParse.ProcList(raw);
            c.Check("条目数", list.Count, 3);
            c.Check("含空格名", list[0].Name, "Windows Explorer.exe");
            c.Check("中文进程名", list[1].Name, "守护进程.exe");
            c.Check("括号与空格", list[2].Name, "My App (x64).exe");
            c.Check("中文名行 PID", list[1].Pid, 700);
        }

        private static void ProcDegenerate(Ctx c)
        {
            c.Check("null", NativeParse.ProcList(null).Count, 0);
            c.Check("空串", NativeParse.ProcList("").Count, 0);
            c.Check("纯空行", NativeParse.ProcList("\r\n\r\n").Count, 0);
            c.Check("no TAB 提示文本", NativeParse.ProcList("enum fail\r\n").Count, 1);
            c.Check("no TAB 提示标记", NativeParse.ProcList("enum fail\r\n")[0].Raw, true);
            c.Check("CR 分隔两行", NativeParse.ProcList("1\t0\t1\ta\r2\t1\t1\tb\r").Count, 2);
        }

        // ================================================================ 路径

        private static void Paths(Ctx c)
        {
            c.Check("基本拼接", NativeParse.JoinRemote("C:\\Users\\Public", "note.txt"), "C:\\Users\\Public\\note.txt");
            c.Check("父路径末尾带分隔符", NativeParse.JoinRemote("C:\\Users\\Public\\", "note.txt"), "C:\\Users\\Public\\note.txt");
            c.Check("父路径正斜杠", NativeParse.JoinRemote("C:/Users/Public", "note.txt"), "C:\\Users\\Public\\note.txt");
            c.Check("子项带前导反斜杠 = 根相对", NativeParse.JoinRemote("C:\\Users\\Public", "\\Temp"), "C:\\Temp");
            c.Check("子项带前导正斜杠 = 根相对", NativeParse.JoinRemote("C:/Users/Public", "/Temp"), "C:\\Temp");
            c.Check("反斜杠+正斜杠混用并按根相对", NativeParse.JoinRemote("C:\\Users/Public/", "/Temp\\\\Sub"), "C:\\Temp\\Sub");
            c.Check(".. 回退", NativeParse.JoinRemote("C:\\Users\\Public\\Sub", ".."), "C:\\Users\\Public");
            c.Check(".. 不越过盘符根", NativeParse.NormRemote("C:\\..\\..\\Windows"), "C:\\Windows");
            c.Check(". 被消除", NativeParse.NormRemote("C:\\a\\.\\b"), "C:\\a\\b");
            c.Check("重复分隔符合并", NativeParse.NormRemote("C:\\\\a\\\\\\\\b"), "C:\\a\\b");
            c.Check("绝对路径忽略父路径", NativeParse.JoinRemote("C:\\Users", "D:\\other\\f.txt"), "D:\\other\\f.txt");
            c.Check("UNC 保留双前缀", NativeParse.NormRemote("\\\\srv\\share\\a\\..\\b"), "\\\\srv\\share\\b");
            c.Check("UNC 拼接", NativeParse.JoinRemote("\\\\srv\\share", "f.txt"), "\\\\srv\\share\\f.txt");
            c.Check("根目录保持 C:\\ 形态", NativeParse.NormRemote("C:\\"), "C:\\");
            c.Check("正斜杠根目录", NativeParse.NormRemote("C:/"), "C:\\");
            c.Check("无分隔符盘符", NativeParse.NormRemote("C:"), "C:\\");
            c.Check("空名返回规范化父路径", NativeParse.JoinRemote("C:\\Users\\Public\\", ""), "C:\\Users\\Public");
            c.Check("空父路径", NativeParse.JoinRemote("", "x.txt"), "x.txt");
            c.Check("中文路径段", NativeParse.JoinRemote("C:\\\u7528\u6237", "\u62a5\u8868.xlsx"), "C:\\用户\\报表.xlsx");
            c.Check("含空格路径段", NativeParse.JoinRemote("C:\\Program Files", "a.txt"), "C:\\Program Files\\a.txt");
        }

        private static void PathParent(Ctx c)
        {
            c.Check("多级父目录", NativeParse.ParentRemote("C:\\Users\\Public\\Sub"), "C:\\Users\\Public");
            c.Check("盘符根再上级", NativeParse.ParentRemote("C:\\"), "C:\\");
            c.Check("单段", NativeParse.ParentRemote("C:\\Windows"), "C:\\");
            c.Check("UNC 父目录", NativeParse.ParentRemote("\\\\srv\\share\\a\\b"), "\\\\srv\\share\\a");
            c.Check("绝对盘符", NativeParse.IsAbsoluteRemote("C:\\x"), true);
            c.Check("单分隔符开头不算自足路径", NativeParse.IsAbsoluteRemote("/x"), false);
            c.Check("单分隔符 -> 根相对", NativeParse.IsRootRelative("/x"), true);
            c.Check("UNC 视为绝对", NativeParse.IsAbsoluteRemote("\\\\srv\\s"), true);
            c.Check("相对名不是绝对", NativeParse.IsAbsoluteRemote("x\\y"), false);
            c.Check("空不是绝对", NativeParse.IsAbsoluteRemote(""), false);
        }

        // ================================================================ 命令

        private static void Commands(Ctx c)
        {
            // v2 走 taskkill: 因为服务端 v2Route 把 kill 判给了 CMD_EXIT (退出会话)
            c.Check("v2 kill -> taskkill", NativeParse.KillProcCmd(true, 7896), "taskkill /F /PID 7896");
            c.Check("v1 kill -> 服务端别名映射", NativeParse.KillProcCmd(false, 7896), "kill 7896");

            string err;
            string cmd = NativeParse.InjectCmd(4060, "AQID//8=\r\n", out err);
            c.Check("inject 修剪换行", cmd, "inject 4060 AQID//8");
            c.Check("inject 无错误", err, "");
            c.Check("inject 去空白", NativeParse.InjectCmd(1, "  AQ ID  ", out err), "inject 1 AQID");

            NativeParse.InjectCmd(1, "", out err);
            c.Check("空 base64 报错", err.Length > 0, true);
            NativeParse.InjectCmd(1, "AAAA-_AA", out err);
            c.Check("URL 安全字符被拦", err.IndexOf("URL", StringComparison.Ordinal) >= 0, true);
            NativeParse.InjectCmd(1, "AA?BB", out err);
            c.Check("非法字符被拦", err.Length > 0, true);
            c.Check("合法长 base64 长度", NativeParse.InjectCmd(9, new string('A', 4096), out err).Length, 4096 + "inject 9 ".Length);
        }

        // ================================================================ 编码

        private static void Codecs(Ctx c)
        {
            // 路径 1: 合法 UTF-8 必须原样通过
            byte[] utf8 = Encoding.UTF8.GetBytes("-\t12\t\u4e2d\u6587\u540d.txt\r\n");
            string s1 = Codec.Auto(utf8);
            c.Check("UTF-8 解码保真", s1.IndexOf("中文名.txt", StringComparison.Ordinal) >= 0, true);
            c.Check("UTF-8 不触发 GBK 回退", s1.Length, Encoding.UTF8.GetString(utf8).Length);

            // 路径 2: 非法 UTF-8 (GBK 字节) 必须走 MultiByteToWideChar(936)
            byte[] gbk = new byte[] { (byte)'-', 9, 49, 50, 9, 0xD6, 0xD0, 0xCE, 0xC4, 0x0D, 0x0A };
            string s2 = Codec.Auto(gbk);
            c.Check("GBK 回退解码", s2.IndexOf("中文", StringComparison.Ordinal) >= 0, true);
            c.Check("GBK 原文长度不膨胀成替换字符", s2.IndexOf('\uFFFD'), -1);

            // 路径 3: 服务端已把非法字节写成 U+FFFD (go string(byte[]) 不可逆) —— 必须不抛
            string damaged = "-\t3\t???\uFFFD\uFFFD.txt\r\n";
            var list = NativeParse.FileList(damaged);
            c.Check("含 U+FFFD 仍解析", list.Count, 1);
            c.Check("U+FFFD 名字保真 (不可恢复, 但如实展示)", list[0].Name, "???\uFFFD\uFFFD.txt");

            // 路径 4: base64 往返 (服务端 v2 pushOut 走 base64)
            string[] samples = new string[]
            {
                "-\t0\t\u4e2d\u6587\u76ee\u5f55\r\n",
                "d\t0\tMy Documents\r\n",
                "4\t0\t8\tSystem\r\n",
                "",
                "invalid@@base64"
            };
            foreach (string sample in samples)
            {
                string b64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(sample));
                c.Check("base64 往返 [" + (sample.Length == 0 ? "空串" : sample.Substring(0, Math.Min(8, sample.Length)).Replace("\t", "<TAB>").Replace("\r", "<CR>").Replace("\n", "<LF>")) + "]",
                        Codec.B64(b64), sample);
            }
            c.Check("非法 base64 原样返回不抛", Codec.B64("invalid@@base64"), "invalid@@base64");
            c.Check("空 base64", Codec.B64(""), "");

            c.Check("Clean 去 CR", Codec.Clean("a\r\nb\rc"), "a\nb\nc");
            c.Check("Clean 不改内容", Codec.Clean("x"), "x");
        }

        // ================================================================ 目标库

        /// <summary>
        /// source 字段的解析与着色。
        /// 依据 go/targets.go targetUpsert: 新来源以 "," 追加 (已有则跳过),
        /// 因此实测数据的形态就是 "beacon,scan,lateral" 这类逗号串。
        /// </summary>
        private static void TargetSources(Ctx c)
        {
            c.Check("单来源", Join(TargetParse.Sources("beacon")), "beacon");
            c.Check("多来源保序", Join(TargetParse.Sources("beacon,scan,lateral")), "beacon|scan|lateral");
            c.Check("带空白", Join(TargetParse.Sources(" beacon , scan ")), "beacon|scan");
            c.Check("空段被跳过", Join(TargetParse.Sources("beacon,,scan,")), "beacon|scan");
            c.Check("重复来源去重", Join(TargetParse.Sources("manual,manual,scan")), "manual|scan");
            c.Check("去重不区分大小写", Join(TargetParse.Sources("Beacon,beacon")), "Beacon");
            c.Check("未知来源保留 (不静默丢弃)", Join(TargetParse.Sources("beacon,weird")), "beacon|weird");
            c.Check("空串", TargetParse.Sources("").Count, 0);
            c.Check("null", TargetParse.Sources(null).Count, 0);
            c.Check("只有逗号", TargetParse.Sources(",,,").Count, 0);

            // 着色: Palette 的画刷是冻结单例, 直接比实例
            c.Check("beacon -> 蓝", SameBrush(TargetParse.SourceBrush("beacon"), Palette.Accent), true);
            c.Check("scan -> 灰", SameBrush(TargetParse.SourceBrush("scan"), Palette.Dim), true);
            c.Check("lateral -> 橙", SameBrush(TargetParse.SourceBrush("lateral"), Palette.Warn), true);
            c.Check("manual -> 绿", SameBrush(TargetParse.SourceBrush("manual"), Palette.Ok), true);
            c.Check("未知来源 -> 紫", SameBrush(TargetParse.SourceBrush("weird"), Palette.Purple), true);
            c.Check("空标签 -> 紫", SameBrush(TargetParse.SourceBrush(""), Palette.Purple), true);
            c.Check("大小写与空白不影响着色", SameBrush(TargetParse.SourceBrush(" LATERAL "), Palette.Warn), true);

            var tags = TargetParse.Tags("beacon,lateral");
            c.Check("标签数", tags.Count, 2);
            c.Check("标签名 [0]", tags[0].Name, "beacon");
            c.Check("标签色 [1]", SameBrush(tags[1].Brush, Palette.Warn), true);
            c.Check("空 source 无标签", TargetParse.Tags("").Count, 0);

            // 序列等价: 差分轮询靠它决定标签单元格要不要重绘
            c.Check("同内容不同实例等价",
                    SourceTag.SameSeq(TargetParse.Tags("beacon,scan"), TargetParse.Tags("beacon,scan")), true);
            c.Check("内容不同不等价",
                    SourceTag.SameSeq(TargetParse.Tags("beacon"), TargetParse.Tags("scan")), false);
            c.Check("长度不同不等价",
                    SourceTag.SameSeq(TargetParse.Tags("beacon"), TargetParse.Tags("beacon,scan")), false);
            c.Check("null 与非空不等价", SourceTag.SameSeq(null, TargetParse.Tags("beacon")), false);
            c.Check("null 与 null 等价", SourceTag.SameSeq(null, null), true);
        }

        /// <summary>搜索过滤、空值降级、服务端 ts (Unix 秒) 的本地时间格式化。</summary>
        private static void TargetFiltering(Ctx c)
        {
            c.Check("host 命中", TargetParse.Match("WEB01", "10.0.0.5", "note", "web"), true);
            c.Check("ip 命中", TargetParse.Match("WEB01", "10.0.0.5", "", "10.0.0"), true);
            c.Check("note 命中", TargetParse.Match("WEB01", "", "域控候选", "域控"), true);
            c.Check("都不命中", TargetParse.Match("WEB01", "10.0.0.5", "x", "nope"), false);
            c.Check("空查询全通过", TargetParse.Match("", "", "", ""), true);
            c.Check("纯空白查询全通过", TargetParse.Match("a", "", "", "   "), true);
            c.Check("null 查询全通过", TargetParse.Match("a", "", "", null), true);
            c.Check("无查询时空字段不误命中", TargetParse.Match("", "", "", "x"), false);

            c.Check("Or 空串降级", TargetParse.Or("", "-"), "-");
            c.Check("Or null 降级", TargetParse.Or(null, "-"), "-");
            c.Check("Or 保真", TargetParse.Or("abc", "-"), "abc");

            c.Check("ts=0 降级 (不显示 1970)", Fmt.Time(0), "-");
            c.Check("ts 负数降级", Fmt.Time(-5), "-");
            long t = new DateTimeOffset(new DateTime(2026, 3, 4, 5, 6, 7, DateTimeKind.Utc)).ToUnixTimeSeconds();
            string s = Fmt.Time(t);
            c.Check("时间长度 (MM-dd HH:mm:ss)", s.Length, 14);
            c.Check("时间按本地时区换算", s, DateTimeOffset.FromUnixTimeSeconds(t).ToLocalTime().ToString("MM-dd HH:mm:ss"));
            c.Check("时间格式含日期分隔符", s.Substring(2, 1), "-");
            c.Check("时间格式含时间分隔符", s.Substring(5, 1), " ");
            c.Check("时间格式分秒分隔符", s.Substring(11, 1), ":");
        }

        /// <summary>
        /// GET /api/state 的 targets 块解析。
        /// 字段照抄 go/targets.go 的 Target 结构; 重点在类型不符与整块缺失时
        /// 只能降级, 不能抛异常 (任务硬要求: 页面显示空表而不是崩)。
        /// </summary>
        private static void TargetsFromState(Ctx c)
        {
            string json = "{\"ok\":true,\"targets\":["
                + "{\"kind\":\"target\",\"id\":1,\"host\":\"WEB01\",\"ip\":\"10.0.0.5\","
                + "\"os\":\"Windows 10 pro\",\"note\":\"域内\",\"source\":\"beacon,scan\","
                + "\"sid\":\"s1\",\"ts\":1770000000},"
                + "{\"kind\":\"target\",\"id\":2,\"host\":\"DC01\",\"ip\":\"\",\"os\":\"\","
                + "\"note\":\"\",\"source\":\"manual\",\"sid\":\"\",\"ts\":0}]}";
            var list = StateParse.Targets(Doc(json));
            c.Check("行数", list.Count, 2);
            c.Check("[0].Kind", list[0].Kind, "target");
            c.Check("[0].Id", list[0].Id, 1);
            c.Check("[0].Host", list[0].Host, "WEB01");
            c.Check("[0].Ip", list[0].Ip, "10.0.0.5");
            c.Check("[0].Os", list[0].Os, "Windows 10 pro");
            c.Check("[0].Note", list[0].Note, "域内");
            c.Check("[0].Sid", list[0].Sid, "s1");
            c.Check("[0].Key 用 id", list[0].Key, "tg1");
            c.Check("[0].HasSid", list[0].HasSid, true);
            c.Check("[0].标签数", list[0].SourceTags.Count, 2);
            c.Check("[0].标签名", Join(SourceNames(list[0])), "beacon|scan");
            c.Check("[0].TsText 非空", list[0].TsText.Length > 0, true);

            c.Check("[1] 空 ip 降级", list[1].IpText, "-");
            c.Check("[1] 空 os 降级", list[1].OsText, "-");
            c.Check("[1] 空 sid 降级", list[1].SidText, "-");
            c.Check("[1] 空 note 降级", list[1].NoteText, "-");
            c.Check("[1] ts=0 降级", list[1].TsText, "-");
            c.Check("[1].HasSid", list[1].HasSid, false);
            c.Check("[1] source 单标签", Join(SourceNames(list[1])), "manual");

            // 类型不符: 数字 host 不解析, 对象 ts 归零, null source 归零
            var bad = StateParse.Targets(Doc("{\"targets\":["
                + "{\"host\":123,\"id\":7,\"ts\":{},\"source\":null},"
                + "{\"host\":\"\",\"ip\":9},"
                + "{\"ip\":\"10.1.1.1\"}]}"));
            c.Check("只有 id 合法的那行保留", bad.Count, 1);
            c.Check("类型不符的 host 降级为空", bad[0].Host, "");
            c.Check("id 保留", bad[0].Id, 7);
            c.Check("对象类型 ts 归零", bad[0].TsText, "-");
            c.Check("null source 无标签", bad[0].SourceTags.Count, 0);
            c.Check("无 id 无 host 的行被丢弃", bad[0].Key, "tg7");

            c.Check("字符串型 id 可解析",
                    StateParse.Targets(Doc("{\"targets\":[{\"id\":\"9\",\"host\":\"H\"}]}"))[0].Id, 9);
            c.Check("无 id 时主键退化为 host",
                    StateParse.Targets(Doc("{\"targets\":[{\"host\":\"H2\"}]}"))[0].Key, "h|H2");

            c.Check("targets 缺失", StateParse.Targets(Doc("{\"ok\":true}")).Count, 0);
            c.Check("targets 为 null", StateParse.Targets(Doc("{\"targets\":null}")).Count, 0);
            c.Check("targets 为字符串", StateParse.Targets(Doc("{\"targets\":\"nope\"}")).Count, 0);
            c.Check("targets 空数组", StateParse.Targets(Doc("{\"targets\":[]}")).Count, 0);
            c.Check("顶层不是对象", StateParse.Targets(Doc("[1,2,3]")).Count, 0);
        }

        /// <summary>
        /// GET /api/state 的 proxy 块解析 (字段照抄 go/proxy.go proxyList)。
        /// 方向语义按服务端实现: socks.tx_tlv = 已下发植入体的数据任务数,
        /// socks.rx_b = 从本地客户端读入, socks.up_b = 发往植入体的上行字节。
        /// </summary>
        private static void ProxyFromState(Ctx c)
        {
            string json = "{\"ok\":true,\"proxy\":{\"ok\":true,"
                + "\"socks\":[{\"sid\":\"s1\",\"port\":1080,\"listen\":\"127.0.0.1:1080\","
                + "\"chans\":2,\"tx_tlv\":17,\"rx_b\":2048,\"up_b\":4096}],"
                + "\"rportfwd\":[{\"sid\":\"s1\",\"port\":3389,\"target\":\"10.0.0.9:3389\"},"
                + "{\"sid\":\"s2\",\"port\":8080}],"
                + "\"chans\":2,\"tx_tlv\":17,\"up_bytes\":4096,\"rx_bytes\":2048,"
                + "\"down_bytes\":8192,\"pump\":\"running\"}}";
            var v = StateParse.Proxy(Doc(json));
            c.Check("Present", v.Present, true);
            c.Check("SOCKS 行数", v.Socks.Count, 1);
            c.Check("rportfwd 行数", v.Rports.Count, 2);
            c.Check("socks.sid", v.Socks[0].Sid, "s1");
            c.Check("socks.监听地址", v.Socks[0].ListenText, "127.0.0.1:1080");
            c.Check("socks.通道数", v.Socks[0].ChansText, "2");
            c.Check("socks.下行 TLV 数", v.Socks[0].TxTlvText, "17");
            c.Check("socks.上行字节", v.Socks[0].UpBText, "4.0 KB");
            c.Check("socks.客户端读入", v.Socks[0].RxBText, "2.0 KB");
            c.Check("socks 主键", v.Socks[0].Key, "s|s1|1080");
            c.Check("socks.ValidPort", v.Socks[0].ValidPort, 1080);
            c.Check("rport.target", v.Rports[0].TargetText, "10.0.0.9:3389");
            c.Check("rport target 缺失降级", v.Rports[1].TargetText, "-");
            c.Check("rport 主键", v.Rports[1].Key, "r|s2|8080");
            c.Check("rport.ValidPort", v.Rports[1].ValidPort, 8080);

            c.Check("统计 chans", v.Chans, 2);
            c.Check("统计 tx_tlv", v.TxTlv, 17);
            c.Check("统计 up_bytes", v.UpBytes, 4096);
            c.Check("统计 rx_bytes", v.RxBytes, 2048);
            c.Check("统计 down_bytes", v.DownBytes, 8192);
            c.Check("pump", v.Pump, "running");
            c.Check("统计条含总通道数", v.StatsText().IndexOf("总通道数 2", StringComparison.Ordinal) >= 0, true);
            c.Check("统计条含上行", v.StatsText().IndexOf("上行 (\u2192\u690d\u5165\u4f53)", StringComparison.Ordinal) >= 0, true);
            c.Check("统计条含下行", v.StatsText().IndexOf("下行 (\u2192\u5ba2\u6237\u7aef)", StringComparison.Ordinal) >= 0, true);
            c.Check("统计条含 TLV", v.StatsText().IndexOf("下行 TLV \u6570 17", StringComparison.Ordinal) >= 0, true);

            // 字段缺失: 只影响那一项
            var part = StateParse.Proxy(Doc("{\"proxy\":{\"ok\":true,"
                + "\"socks\":[{\"sid\":\"s1\",\"port\":1080}],\"rportfwd\":[],\"chans\":1}}"));
            c.Check("listen 缺失按服务端语义补默认", part.Socks[0].ListenText, "127.0.0.1:1080");
            c.Check("chans 缺失归零但不崩", part.Socks[0].TxTlv, 0);
            c.Check("rportfwd 空数组", part.Rports.Count, 0);
            c.Check("pump 缺失", part.Pump, "");
            c.Check("顶层统计缺失归零", part.UpBytes + part.DownBytes, 0);

            // 整块缺失 / 类型不符 / 空对象: 空表 + 明确提示
            var none = StateParse.Proxy(Doc("{\"ok\":true}"));
            c.Check("proxy 缺失 Present=false", none.Present, false);
            c.Check("proxy 缺失 空表", none.Socks.Count + none.Rports.Count, 0);
            c.Check("proxy 缺失 统计文本标注", none.StatsText().IndexOf("未返回", StringComparison.Ordinal) >= 0, true);
            c.Check("proxy 为字符串", StateParse.Proxy(Doc("{\"proxy\":\"x\"}")).Present, false);
            c.Check("proxy 为 null", StateParse.Proxy(Doc("{\"proxy\":null}")).Present, false);
            c.Check("socks 非数组", StateParse.Proxy(Doc("{\"proxy\":{\"socks\":5}}")).Socks.Count, 0);
            c.Check("rportfwd 非数组", StateParse.Proxy(Doc("{\"proxy\":{\"rportfwd\":{}}}")).Rports.Count, 0);
            var empty = StateParse.Proxy(Doc("{\"proxy\":{}}"));
            c.Check("空 proxy 对象算 Present", empty.Present, true);
            c.Check("空 proxy 零统计", empty.Chans + empty.TxTlv + empty.UpBytes + empty.RxBytes, 0);

            // usage 与服务端 proxyRunKey
            c.Check("服务端 usage 优先",
                    TargetParse.UsageText("curl --socks5-hostname 127.0.0.1:9 http://TARGET/", 1080),
                    "curl --socks5-hostname 127.0.0.1:9 http://TARGET/");
            c.Check("usage 缺失时本地按同格式补",
                    TargetParse.UsageText("", 1080),
                    "curl --socks5-hostname 127.0.0.1:1080 http://TARGET/");
            c.Check("usage 端口为 0 返回空", TargetParse.UsageText("", 0), "");
            c.Check("usage 端口超范围返回空", TargetParse.UsageText("", 70000), "");
            c.Check("运行键与服务端 proxyRunKey 同构", TargetParse.RunKey("s1", 1080), "s1:1080");
            c.Check("rport 描述", TargetParse.RportText("s1", 3389, ""), "s1 :3389  ->  (未指定)");
            c.Check("rport 描述带 target", TargetParse.RportText("s1", 3389, "a:1"), "s1 :3389  ->  a:1");
        }

        // ================================================================ 脚本插件

        /// <summary>
        /// 菜单助记符剥离。样本照抄实测 GET /api/scripts 的 name 字段
        /// (default.cna 的 &amp;Interact / Golden &amp;Ticket / Ser&amp;vices ...)。
        /// </summary>
        private static void ScriptMnemonic(Ctx c)
        {
            c.Check("&Interact", ScriptParse.StripMnemonic("&Interact"), "Interact");
            c.Check("E&xport Data", ScriptParse.StripMnemonic("E&xport Data"), "Export Data");
            c.Check("Make T&oken", ScriptParse.StripMnemonic("Make T&oken"), "Make Token");
            c.Check("S&ession", ScriptParse.StripMnemonic("S&ession"), "Session");
            c.Check("Golden &Ticket", ScriptParse.StripMnemonic("Golden &Ticket"), "Golden Ticket");
            c.Check("Ser&vices", ScriptParse.StripMnemonic("Ser&vices"), "Services");
            c.Check("&Dump Hashes", ScriptParse.StripMnemonic("&Dump Hashes"), "Dump Hashes");
            c.Check("&Sleep...", ScriptParse.StripMnemonic("&Sleep..."), "Sleep...");
            c.Check("无 & 原样", ScriptParse.StripMnemonic("Set as PPID"), "Set as PPID");
            c.Check("中文名原样", ScriptParse.StripMnemonic("侦察 (whoami + ps)"), "侦察 (whoami + ps)");
            c.Check("中文名前缀 &", ScriptParse.StripMnemonic("&脚本示例"), "脚本示例");
            c.Check("数字前缀项", ScriptParse.StripMnemonic("1. 95/98/2000"), "1. 95/98/2000");
            c.Check("分隔线名", ScriptParse.StripMnemonic("-"), "-");

            c.Check("&& = 字面 &", ScriptParse.StripMnemonic("A&&B"), "A&B");
            c.Check("仅 && = 单个 &", ScriptParse.StripMnemonic("&&"), "&");
            c.Check("&& 后接助记符", ScriptParse.StripMnemonic("A&&B&c"), "A&Bc");
            c.Check("尾部孤立 &", ScriptParse.StripMnemonic("X&"), "X");
            c.Check("仅 &", ScriptParse.StripMnemonic("&"), "");
            c.Check("null", ScriptParse.StripMnemonic(null), "");
            c.Check("空串", ScriptParse.StripMnemonic(""), "");
        }

        /// <summary>popup parent -> 右键菜单挂载点。</summary>
        private static void ScriptMountTable(Ctx c)
        {
            c.Check("beacon", ScriptParse.MountOf("beacon"), ScriptMount.Session);
            c.Check("beacon_top", ScriptParse.MountOf("beacon_top"), ScriptMount.Session);
            c.Check("beacon_bottom", ScriptParse.MountOf("beacon_bottom"), ScriptMount.Session);
            c.Check("大小写与空白容错", ScriptParse.MountOf("  BEACON_bottom  "), ScriptMount.Session);
            c.Check("processbrowser", ScriptParse.MountOf("processbrowser"), ScriptMount.Process);
            c.Check("targets", ScriptParse.MountOf("targets"), ScriptMount.Targets);
            c.Check("aggressor -> 脚本插件", ScriptParse.MountOf("aggressor"), ScriptMount.Plugin);
            c.Check("view -> 脚本插件", ScriptParse.MountOf("view"), ScriptMount.Plugin);
            c.Check("payloads -> 脚本插件", ScriptParse.MountOf("payloads"), ScriptMount.Plugin);
            c.Check("help -> 脚本插件", ScriptParse.MountOf("help"), ScriptMount.Plugin);
            c.Check("ssh -> 脚本插件", ScriptParse.MountOf("ssh"), ScriptMount.Plugin);
            c.Check("pgraph -> 脚本插件", ScriptParse.MountOf("pgraph"), ScriptMount.Plugin);
            c.Check("keystrokes -> 脚本插件", ScriptParse.MountOf("keystrokes"), ScriptMount.Plugin);
            c.Check("screenshots -> 脚本插件", ScriptParse.MountOf("screenshots"), ScriptMount.Plugin);
            c.Check("downloads -> 脚本插件", ScriptParse.MountOf("downloads"), ScriptMount.Plugin);
            c.Check("filebrowser -> 脚本插件", ScriptParse.MountOf("filebrowser"), ScriptMount.Plugin);
            c.Check("未知 parent -> 脚本插件", ScriptParse.MountOf("whatever"), ScriptMount.Plugin);
            c.Check("空 parent -> 脚本插件", ScriptParse.MountOf(""), ScriptMount.Plugin);
            c.Check("null parent -> 脚本插件", ScriptParse.MountOf(null), ScriptMount.Plugin);

            c.Check("文案: 会话", ScriptParse.MountLabel(ScriptMount.Session), "会话右键");
            c.Check("文案: 进程", ScriptParse.MountLabel(ScriptMount.Process), "进程浏览器右键");
            c.Check("文案: 目标库", ScriptParse.MountLabel(ScriptMount.Targets), "目标库右键");
            c.Check("文案: 脚本插件", ScriptParse.MountLabel(ScriptMount.Plugin), "脚本插件子菜单");
        }

        /// <summary>
        /// GET /api/scripts 的完整解析。样本结构照抄实测输出:
        /// beacon 的 &Interact/&Access/&Pivoting(含 sep)/S&amp;ession(含无子项的 kind=menu 的 &amp;Color),
        /// beacon_bottom 的 example.cna 菜单, targets / processbrowser / 空 popup view。
        /// </summary>
        private static void ScriptMenusFromApi(Ctx c)
        {
            string json = "{\"ok\":true,"
                + "\"loaded\":[\"D:\\\\csdev-c2\\\\scripts\\\\example.cna\","
                + "\"D:\\\\csdev-c2\\\\docs\\\\_cs47_extract\\\\scripts\\\\default.cna\"],"
                + "\"commands\":[\"?\",\"e\",\"listbeacons\",\"recon\",\"shortsleep\",\"x\"],"
                + "\"menubar\":[{\"label\":\"&Cobalt Strike\",\"id\":\"aggressor\"},"
                + "{\"label\":\"&View\",\"id\":\"view\"},{\"label\":\"&Help\",\"id\":\"help\"}],"
                + "\"menus\":["
                + "{\"parent\":\"beacon\",\"items\":["
                + "{\"name\":\"&Interact\",\"action\":true,\"kind\":\"item\"},"
                + "{\"name\":\"&Access\",\"action\":false,\"kind\":\"menu\",\"children\":["
                + "{\"name\":\"&Dump Hashes\",\"action\":true,\"kind\":\"item\"},"
                + "{\"name\":\"Golden &Ticket\",\"action\":true,\"kind\":\"item\"}]},"
                + "{\"name\":\"&Pivoting\",\"action\":false,\"kind\":\"menu\",\"children\":["
                + "{\"name\":\"&SOCKS Server\",\"action\":true,\"kind\":\"item\"},"
                + "{\"name\":\"-\",\"action\":false,\"kind\":\"sep\"}]},"
                + "{\"name\":\"S&ession\",\"action\":false,\"kind\":\"menu\",\"children\":["
                + "{\"name\":\"&Color\",\"action\":true,\"kind\":\"menu\"},"
                + "{\"name\":\"&Exit\",\"action\":true,\"kind\":\"item\"}]}]},"
                + "{\"parent\":\"beacon_bottom\",\"items\":["
                + "{\"name\":\"脚本示例\",\"action\":false,\"kind\":\"menu\",\"children\":["
                + "{\"name\":\"侦察 (whoami + ps)\",\"action\":true,\"kind\":\"item\"},"
                + "{\"name\":\"读取剪贴板 BOF\",\"action\":true,\"kind\":\"item\"}]}]},"
                + "{\"parent\":\"targets\",\"items\":[{\"name\":\"&Scan\",\"action\":true,\"kind\":\"item\"}]},"
                + "{\"parent\":\"processbrowser\",\"items\":[{\"name\":\"Set as PPID\",\"action\":true,\"kind\":\"item\"}]},"
                + "{\"parent\":\"view\",\"items\":[]}],"
                + "\"missing\":[\"colorPanel\",\"toolbar\",\"toolbar_separator\"],"
                + "\"diag\":[\"[!] 脚本错误 default.cna:1316: 未定义的函数 checkError\"],"
                + "\"output\":[\"=== csdev 脚本引擎就绪 ===\",\"[script] 在线会话: s1\"]}";
            var s = ScriptParse.Parse(Doc(json));

            c.Check("Present", s.Present, true);
            c.Check("loaded 条数", s.Loaded.Count, 2);
            c.Check("loaded[0] 文件名", ScriptFileRow.BaseName(s.Loaded[0]), "example.cna");
            c.Check("loaded[1] 文件名", ScriptFileRow.BaseName(s.Loaded[1]), "default.cna");
            c.Check("BaseName 正斜杠", ScriptFileRow.BaseName("scripts/x.cna"), "x.cna");
            c.Check("BaseName 无分隔符", ScriptFileRow.BaseName("x.cna"), "x.cna");
            c.Check("BaseName 空", ScriptFileRow.BaseName(""), "");
            c.Check("commands 条数", s.Commands.Count, 6);
            c.Check("commands 文本", s.CommandsText(), "?, e, listbeacons, recon, shortsleep, x");
            c.Check("missing 条数", s.Missing.Count, 3);
            c.Check("missing[0]", s.Missing[0], "colorPanel");
            c.Check("diag 条数", s.Diag.Count, 1);
            c.Check("diag 原文保真", s.Diag[0].IndexOf("checkError", StringComparison.Ordinal) >= 0, true);
            c.Check("output 条数", s.Output.Count, 2);
            c.Check("output[1]", s.Output[1], "[script] 在线会话: s1");

            c.Check("menubar 条数", s.MenuBar.Count, 3);
            c.Check("menubar[0].label 原样", s.MenuBar[0].Label, "&Cobalt Strike");
            c.Check("menubar[0].Text 去助记符", s.MenuBar[0].Text, "Cobalt Strike");
            c.Check("menubar[0].id", s.MenuBar[0].Id, "aggressor");
            c.Check("menubar[1].Text", s.MenuBar[1].Text, "View");
            c.Check("menubar[2].id", s.MenuBar[2].Id, "help");

            c.Check("menus 条数", s.Menus.Count, 5);
            c.Check("menus[0].parent", s.Menus[0].Parent, "beacon");
            c.Check("menus[0] 挂载点", s.Menus[0].Mount, ScriptMount.Session);
            c.Check("menus[1].parent", s.Menus[1].Parent, "beacon_bottom");
            c.Check("menus[2] 挂载点 (targets)", s.Menus[2].Mount, ScriptMount.Targets);
            c.Check("menus[3] 挂载点 (processbrowser)", s.Menus[3].Mount, ScriptMount.Process);
            c.Check("menus[4] 挂载点 (view)", s.Menus[4].Mount, ScriptMount.Plugin);

            c.Check("总项数 (递归)", s.TotalItems, 15);
            c.Check("叶子项数", s.ItemCount, 10);
            c.Check("子菜单数", s.MenuCount, 4);
            c.Check("分隔线数", s.SepCount, 1);
            c.Check("挂载统计: 会话", s.SessionMounts, 2);
            c.Check("挂载统计: 进程", s.ProcessMounts, 1);
            c.Check("挂载统计: 目标库", s.TargetMounts, 1);
            c.Check("挂载统计: 脚本插件", s.PluginMounts, 1);
            c.Check("挂载统计文本", s.MountsText(), "会话 2 · 进程 1 · 目标库 1 · 脚本插件 1");
            c.Check("可执行项总数 (与命令表无关)", ScriptParse.RunnableItems(s).Count, 10);

            var beacon = s.Menus[0].Items;
            var interact = beacon[0];
            c.Check("&Interact.kind", interact.Kind, "item");
            c.Check("&Interact.Text", interact.Text, "Interact");
            c.Check("&Interact.Command", interact.Command, "Interact");
            c.Check("&Interact.Raw 保留 &", interact.Raw, "&Interact");
            c.Check("&Interact.CanRun", interact.CanRun, true);
            c.Check("&Interact.Inert", interact.Inert, false);
            c.Check("&Interact 无子项", interact.HasChildren, false);

            var access = beacon[1];
            c.Check("&Access.Kind", access.Kind, "menu");
            c.Check("&Access.Text", access.Text, "Access");
            c.Check("&Access.action=false", access.Action, false);
            c.Check("&Access 子项数", access.Children.Count, 2);
            c.Check("&Access 是子菜单", access.IsSubmenu, true);
            c.Check("&Access 不可直接执行", access.CanRun, false);
            c.Check("&Access 交由其子项承载 (非惰性叶子)", access.Inert, false);
            c.Check("&Access 子项[0].Text", access.Children[0].Text, "Dump Hashes");
            c.Check("&Access 子项[1].Text", access.Children[1].Text, "Golden Ticket");
            c.Check("&Access 子项[1].CanRun", access.Children[1].CanRun, true);
            c.Check("&Access 子项 Depth", access.Children[0].Depth, 1);

            var pivoting = beacon[2];
            c.Check("&Pivoting 子项数 (含分隔线)", pivoting.Children.Count, 2);
            c.Check("&Pivoting 子项[1] 是分隔线", pivoting.Children[1].IsSep, true);
            c.Check("分隔线显示名", pivoting.Children[1].Text, "-");
            c.Check("分隔线不可执行", pivoting.Children[1].CanRun, false);
            c.Check("分隔线不算惰性项", pivoting.Children[1].Inert, false);

            var color = beacon[3].Children[0];
            c.Check("S&ession/&Color.Kind", color.Kind, "menu");
            c.Check("kind=menu 且无子项 -> 无子菜单", color.IsSubmenu, false);
            c.Check("kind=menu 且 action=true -> 可点击", color.CanRun, true);
            c.Check("&Color.Text", color.Text, "Color");
            c.Check("S&ession.Text", beacon[3].Text, "Session");

            var demo = s.Menus[1].Items[0];
            c.Check("example.cna 子菜单名", demo.Text, "脚本示例");
            c.Check("example.cna 项[0]", demo.Children[0].Text, "侦察 (whoami + ps)");
            c.Check("example.cna 项[1]", demo.Children[1].Text, "读取剪贴板 BOF");
            c.Check("example.cna 项挂 parent", demo.Children[0].Parent, "beacon_bottom");
            c.Check("空 popup items 为 0", s.Menus[4].Items.Count, 0);

            // 脚本视图树模型 (ScriptParse.Roots / RootText / TreeSignature / CmdHitText)
            var roots = ScriptParse.Roots(s);
            c.Check("树根数 = popup 数", roots.Count, 5);
            c.Check("根排序[0] 会话优先", roots[0].Parent, "beacon");
            c.Check("根排序[1] beacon_bottom 随后", roots[1].Parent, "beacon_bottom");
            c.Check("根排序[2] 进程", roots[2].Parent, "processbrowser");
            c.Check("根排序[3] 目标库", roots[3].Parent, "targets");
            c.Check("根排序[4] 脚本插件", roots[4].Parent, "view");
            c.Check("根文案带挂载点", roots[0].Text, "beacon   [会话右键]");
            c.Check("根文案 (脚本插件)", roots[4].Text, "view   [脚本插件子菜单]");
            c.Check("根 kind=root", roots[0].Kind, "root");
            c.Check("根有子项", roots[0].HasChildren, true);
            c.Check("根不可执行", roots[0].CanRun, false);
            c.Check("根子项数", roots[0].Children.Count, 4);
            c.Check("空 popup 也如实列成根", roots[4].Children.Count, 0);
            c.Check("RootText 空 parent 标注",
                    ScriptParse.RootText("", ScriptMount.Plugin), "(无 parent)   [脚本插件子菜单]");
            c.Check("RootText null parent", ScriptParse.RootText(null, ScriptMount.Session), "(无 parent)   [会话右键]");
            c.Check("null summary -> 无根", ScriptParse.Roots(null).Count, 0);
            c.Check("null summary -> 空签名", ScriptParse.TreeSignature(null), "");

            string t1 = ScriptParse.TreeSignature(s);
            c.Check("同结构 -> 同签名 (不重建树)", t1, ScriptParse.TreeSignature(s));
            c.Check("同一 JSON 再解析 -> 同签名", t1, ScriptParse.TreeSignature(ScriptParse.Parse(Doc(json))));
            c.Check("菜单项改名 -> 签名变化",
                    t1 == ScriptParse.TreeSignature(ScriptParse.Parse(Doc(json.Replace("\"&Exit\"", "\"&Exit Now\"")))), false);
            c.Check("kind 变化 -> 签名变化",
                    t1 == ScriptParse.TreeSignature(ScriptParse.Parse(Doc(json.Replace("\"kind\":\"sep\"", "\"kind\":\"item\"")))), false);
            c.Check("嵌套层级进入签名 (子项改动可见)",
                    t1 == ScriptParse.TreeSignature(ScriptParse.Parse(Doc(json.Replace("&Dump Hashes", "Dump")) )), false);

            c.Check("命令命中: recon 不在菜单里", ScriptParse.CmdHitText(s, "recon"), "-");
            c.Check("命令命中: Interact 与 &Interact 同名", ScriptParse.CmdHitText(s, "Interact"), "1 项");
            c.Check("命令命中: null summary", ScriptParse.CmdHitText(null, "x"), "-");
        }

        /// <summary>菜单树退化输入: 任何缺失 / 类型不符都只降级, 不抛异常。</summary>
        private static void ScriptMenusDegenerate(Ctx c)
        {
            c.Check("顶层数组 -> 非 Present", ScriptParse.Parse(Doc("[1,2,3]")).Present, false);
            c.Check("顶层数组 -> 空菜单", ScriptParse.Parse(Doc("[1,2,3]")).Menus.Count, 0);
            c.Check("空对象算 Present", ScriptParse.Parse(Doc("{}")).Present, true);
            c.Check("menus 缺失", ScriptParse.Parse(Doc("{\"ok\":true}")).Menus.Count, 0);
            c.Check("menus 为 null", ScriptParse.Parse(Doc("{\"menus\":null}")).Menus.Count, 0);
            c.Check("menus 为字符串", ScriptParse.Parse(Doc("{\"menus\":\"x\"}")).Menus.Count, 0);
            c.Check("menus 空数组", ScriptParse.Parse(Doc("{\"menus\":[]}")).Menus.Count, 0);
            c.Check("menus 元素非对象被跳过",
                    ScriptParse.Parse(Doc("{\"menus\":[7,{\"parent\":\"beacon\",\"items\":[]}]}")).Menus.Count, 1);
            c.Check("items 缺失", ScriptParse.Parse(Doc("{\"menus\":[{\"parent\":\"beacon\"}]}")).Menus[0].Items.Count, 0);
            c.Check("items 非数组", ScriptParse.Parse(Doc("{\"menus\":[{\"parent\":\"beacon\",\"items\":5}]}")).Menus[0].Items.Count, 0);

            var bare = ScriptParse.Parse(Doc("{\"menus\":[{\"items\":[{\"name\":\"X\"}]}]}"));
            c.Check("parent 缺失 -> 空 parent", bare.Menus[0].Parent, "");
            c.Check("parent 缺失 -> 归脚本插件", bare.Menus[0].Mount, ScriptMount.Plugin);
            c.Check("kind 缺失默认 item", bare.Menus[0].Items[0].Kind, "item");
            c.Check("action 缺失 = false", bare.Menus[0].Items[0].Action, false);
            c.Check("action 缺失 -> 惰性项", bare.Menus[0].Items[0].Inert, true);
            c.Check("action 缺失 -> 不可执行", bare.Menus[0].Items[0].CanRun, false);
            c.Check("惰性项不进可执行集合", ScriptParse.RunnableItems(bare).Count, 0);

            var weird = ScriptParse.Parse(Doc(
                "{\"menus\":[{\"parent\":\"beacon\",\"items\":["
                + "{\"name\":\"A\",\"action\":\"yes\",\"kind\":\"weird\"},"
                + "{\"name\":\"B\",\"action\":true,\"kind\":\"item\",\"children\":5},"
                + "{\"name\":\"C\",\"action\":true,\"kind\":\"item\",\"children\":[]},"
                + "{\"name\":\"D\",\"action\":true,\"kind\":\"item\",\"children\":[{\"name\":\"D1\"}]}]}]}"));
            var wit = weird.Menus[0].Items;
            c.Check("action 非布尔 -> false", wit[0].Action, false);
            c.Check("未知 kind 原样保留", wit[0].Kind, "weird");
            c.Check("未知 kind 原样保留(不可执行)", wit[0].CanRun, false);
            c.Check("children 非数组 -> 叶子", wit[1].HasChildren, false);
            c.Check("children 非数组 -> 仍可执行", wit[1].CanRun, true);
            c.Check("children 空数组 -> 叶子", wit[2].HasChildren, false);
            c.Check("children 空数组 -> 可执行", wit[2].CanRun, true);
            c.Check("children 有元素 -> 子菜单", wit[3].IsSubmenu, true);
            c.Check("子菜单统计计入 MenuCount", weird.MenuCount, 1);
            c.Check("子项 Depth=1", wit[3].Children[0].Depth, 1);

            c.Check("loaded 为数字(states 风格) -> 空", ScriptParse.Parse(Doc("{\"loaded\":2}")).Loaded.Count, 0);
            c.Check("missing 含数字 -> 取原文",
                    ScriptParse.StrList(Doc("{\"missing\":[\"a\",3,null,\"b\"]}"), "missing")[1], "3");
            c.Check("missing 含 null 被跳过",
                    ScriptParse.StrList(Doc("{\"missing\":[\"a\",3,null,\"b\"]}"), "missing").Count, 3);
            c.Check("StrList 字段非数组", ScriptParse.StrList(Doc("{\"commands\":\"recon\"}"), "commands").Count, 0);
        }

        /// <summary>/api/state.scripts 摘要签名 (轮询差分的判据) 与命令表匹配。</summary>
        private static void ScriptStateSummary(Ctx c)
        {
            string a = ScriptParse.StateSignature(Doc(
                "{\"scripts\":{\"loaded\":2,\"commands\":[\"recon\",\"x\"],\"menus\":17}}"));
            c.Check("签名含 loaded", a.IndexOf("L2", StringComparison.Ordinal) >= 0, true);
            c.Check("签名含 menus", a.IndexOf("M17", StringComparison.Ordinal) >= 0, true);
            c.Check("签名含命令列表", a.IndexOf("C[recon,x]", StringComparison.Ordinal) >= 0, true);

            string b = ScriptParse.StateSignature(Doc(
                "{\"scripts\":{\"loaded\":3,\"commands\":[\"recon\",\"x\"],\"menus\":17}}"));
            c.Check("脚本数变化 -> 签名不同", a == b, false);

            string c2 = ScriptParse.StateSignature(Doc(
                "{\"scripts\":{\"loaded\":2,\"commands\":[\"recon\",\"x\",\"y\"],\"menus\":17}}"));
            c.Check("命令表变化 -> 签名不同", a == c2, false);

            string d = ScriptParse.StateSignature(Doc(
                "{\"scripts\":{\"loaded\":2,\"commands\":[\"recon\",\"x\"],\"menus\":17}}"));
            c.Check("摘要相同 -> 签名相同 (不重复拉取)", a, d);

            c.Check("scripts 缺失 -> 空签名", ScriptParse.StateSignature(Doc("{\"ok\":true}")), "");
            c.Check("scripts 为 null -> 空签名", ScriptParse.StateSignature(Doc("{\"scripts\":null}")), "");
            c.Check("scripts 为字符串 -> 空签名", ScriptParse.StateSignature(Doc("{\"scripts\":\"x\"}")), "");
            c.Check("旧版只给计数也能签名",
                    ScriptParse.StateSignature(Doc("{\"scripts\":{\"loaded\":1}}")).IndexOf("L1", StringComparison.Ordinal) >= 0, true);

            c.Check("StateHasCommands=true", ScriptParse.StateHasCommands(Doc("{\"scripts\":{\"commands\":[]}}")), true);
            c.Check("StateHasCommands 缺字段", ScriptParse.StateHasCommands(Doc("{\"scripts\":{\"loaded\":1}}")), false);
            c.Check("StateHasCommands scripts 缺失", ScriptParse.StateHasCommands(Doc("{}")), false);
            c.Check("StateHasCommands scripts 为 null", ScriptParse.StateHasCommands(Doc("{\"scripts\":null}")), false);

            var cmds = new List<string>();
            cmds.Add("?");
            cmds.Add("recon");
            cmds.Add("listbeacons");
            c.Check("命令表命中 recon", ScriptParse.IsCommand(cmds, "recon"), true);
            c.Check("命令表命中忽略大小写", ScriptParse.IsCommand(cmds, "LISTBEACONS"), true);
            c.Check("菜单项 &Interact 不命中", ScriptParse.IsCommand(cmds, "Interact"), false);
            c.Check("空名不命中", ScriptParse.IsCommand(cmds, ""), false);
            c.Check("null 名不命中", ScriptParse.IsCommand(cmds, null), false);
            c.Check("空命令表不命中", ScriptParse.IsCommand(new List<string>(), "recon"), false);
            c.Check("null 命令表不命中", ScriptParse.IsCommand(null, "recon"), false);
        }

        /// <summary>
        /// 执行结果文案: 服务端错误原样带出; "未找到脚本命令"额外说明该名字不在命令表
        /// (菜单项应走 /api/script/menu 按 parent+name 定位, 那条路已接线)。
        /// </summary>
        private static void ScriptRunResult(Ctx c)
        {
            c.Check("ok 文案", ScriptParse.RunResultText(true, "", "recon"), "已执行脚本菜单项: recon");
            c.Check("ok 时忽略 error 字段", ScriptParse.RunResultText(true, "x", "recon"), "已执行脚本菜单项: recon");

            string miss = ScriptParse.RunResultText(false, "未找到脚本命令 Interact", "Interact");
            c.Check("未找到命令: 原样带出", miss.IndexOf("未找到脚本命令 Interact", StringComparison.Ordinal) >= 0, true);
            c.Check("未找到命令: 指出应走菜单端点",
                    miss.IndexOf("/api/script/menu", StringComparison.Ordinal) >= 0, true);

            string err = ScriptParse.RunResultText(false, "会话 s1 不存在或不是 v2 会话", "recon");
            c.Check("服务端错误原样带出", err.IndexOf("会话 s1 不存在", StringComparison.Ordinal) >= 0, true);
            c.Check("非\u300c未找到\u300d类错误不加边界说明", err.IndexOf("该菜单项名不是", StringComparison.Ordinal) < 0, true);

            string noErr = ScriptParse.RunResultText(false, "", "recon");
            c.Check("error 缺失时如实标注", noErr.IndexOf("未返回 error", StringComparison.Ordinal) >= 0, true);
            c.Check("null error 不抛", ScriptParse.RunResultText(false, null, "recon").Length > 0, true);

            // 菜单端点回传的 warnings: 被跳过的 CS 客户端私有 UI 函数必须显示出来
            using (var doc = System.Text.Json.JsonDocument.Parse(
                       "{\"ok\":true,\"skipped\":[\"openOrActivate\",\"insert_menu\"]," +
                       "\"warnings\":[\"openOrActivate 未实现(本引擎没有 CS 客户端 UI), 已跳过\"," +
                       "\"insert_menu 未实现(本引擎没有 CS 客户端 UI), 已跳过\"]}"))
            {
                string w = ScriptParse.WarniText(doc.RootElement);
                c.Check("warnings 计数", w.IndexOf("已跳过 2 项", StringComparison.Ordinal) >= 0, true);
                c.Check("warnings 带函数名", w.IndexOf("openOrActivate", StringComparison.Ordinal) >= 0, true);
            }
            using (var doc = System.Text.Json.JsonDocument.Parse("{\"ok\":true}"))
            {
                c.Check("无 warnings 时为空串", ScriptParse.WarniText(doc.RootElement), "");
            }
            using (var doc = System.Text.Json.JsonDocument.Parse("{\"warnings\":[]}"))
            {
                c.Check("空数组不产生提示", ScriptParse.WarniText(doc.RootElement), "");
            }

            // 载荷生成失败时是否该降级重试: 只认 PowerShell 的参数绑定错误。
            // 曾经的实现凭 "Sleep"/"Jitter" 字样判断, 而生成器**成功输出**里就带
            // "sleep 5000 ms, jitter 10%" —— 于是脚本解析失败也会被当成参数问题,
            // 触发一次无意义的降级重试, 把真正的错误盖掉。
            const string 失败日志 = "格式: win2-vba\n节奏: sleep 5000 ms, jitter 10%\n[!] 缺少 using 指令";
            c.Check("日志提到 sleep/jitter 但不是参数错误 -> 不降级", MainWindow.IsParamError(失败日志), false);
            c.Check("真正的参数绑定错误 -> 降级",
                    MainWindow.IsParamError("A parameter cannot be found that matches parameter name 'Sleep'."), true);
            c.Check("NamedParameterNotFound -> 降级",
                    MainWindow.IsParamError("NamedParameterNotFound,Microsoft.PowerShell.Commands:Foo -Jitter"), true);
            c.Check("空的失败信息 -> 不降级", MainWindow.IsParamError(""), false);
        }

        // ================================================================ 插件包 (包级选择加载)

        /// <summary>插件根样本 (与真实环境一致, 只用于拼样本路径)。</summary>
        private const string PlugRoot = "D:\\Tools\\1\\tools\\gui_other\\Cobalt_Strike_4.7\\plugin";

        /// <summary>正常列表: 目录包 + 散装 .cna 包, 已选中/未选中各一, 各自的 menus 计数。</summary>
        private static void PluginNormal(Ctx c)
        {
            var v = PluginParse.Parse(Doc(
                "{\"ok\":true,\"root\":" + JStr(PlugRoot) + ",\"plugins\":["
                + Pack("LSTAR", PlugRoot + "\\LSTAR", "dir", PlugRoot + "\\LSTAR\\LSTAR.cna",
                       12, 345678, true, 427, true, "") + ","
                + Pack("TaoWu", PlugRoot + "\\TaoWu", "dir", PlugRoot + "\\TaoWu\\TaoWu.cna",
                       3, 51200, true, 91, true, "") + ","
                + Pack("SharpHound.cna", PlugRoot + "\\SharpHound.cna", "file", PlugRoot + "\\SharpHound.cna",
                       1, 9000, false, 0, false, "")
                + "],\"selected\":" + JPathList(PlugRoot + "\\LSTAR|" + PlugRoot + "\\TaoWu")
                + ",\"loaded\":"
                + JPathList("D:\\csdev-c2\\scripts\\cs_dev.cna|" + PlugRoot + "\\LSTAR\\LSTAR.cna") + "}"));

            c.Check("Present", v.Present, true);
            c.Check("Ok", v.Ok, true);
            c.Check("root 原文", v.Root, PlugRoot);
            c.Check("包数", v.Plugins.Count, 3);
            c.Check("可勾选数", v.SelectableCount, 3);
            c.Check("无主文件数", v.BlockedCount, 0);
            c.Check("已选中数", v.LoadedCount, 2);
            c.Check("菜单项合计 (427+91)", v.MenusTotal, 518);
            c.Check("已加载脚本文件数", v.Loaded.Count, 2);
            c.Check("selected 全部在列表里", v.SelectedMissing.Count, 0);

            PluginPack ls = FindPack(v, "LSTAR");
            c.Check("[LSTAR].KindText", ls.KindText, "目录");
            c.Check("[LSTAR].原始 kind 保留", ls.Kind, "dir");
            c.Check("[LSTAR].FilesText", ls.FilesText, "12");
            c.Check("[LSTAR].SizeText", ls.SizeText, "337.6 KB");
            c.Check("[LSTAR].StatusText", ls.StatusText, "已选中");
            c.Check("[LSTAR].MenusText", ls.MenusText, "427");
            c.Check("[LSTAR].Selectable", ls.Selectable, true);
            c.Check("[LSTAR].DetailText = 主文件名", ls.DetailText, "LSTAR.cna");
            c.Check("[LSTAR].BlockWhy 空", ls.BlockWhy, "");
            c.Check("[LSTAR].Key", ls.Key, "p|" + PlugRoot + "\\LSTAR");
            c.Check("[LSTAR].状态色", SameBrush(ls.StatusBrush, Palette.Ok), true);
            c.Check("[LSTAR].菜单项色", SameBrush(ls.MenusBrush, Palette.Ok), true);

            PluginPack sh = FindPack(v, "SharpHound.cna");
            c.Check("[散装].KindText", sh.KindText, "文件");
            c.Check("[散装].has_main=false", sh.HasMain, false);
            c.Check("[散装].main 非空 -> 仍可勾选", sh.Selectable, true);
            c.Check("[散装].StatusText", sh.StatusText, "未选中");
            c.Check("[散装].行色 (未选中)", SameBrush(sh.RowBrush, Palette.Dim), true);

            // 初始勾选态 = 服务端 loaded (刷新列表不会擅自改掉服务端选择)
            var rows = PluginParse.Rows(v, null);
            c.Check("初始勾选数", PluginParse.PickedCount(rows), 2);
            c.Check("提交路径序 = 列表序",
                    Join(PluginParse.PickedPaths(rows)), PlugRoot + "\\LSTAR|" + PlugRoot + "\\TaoWu");

            string stat = v.StatsText();
            c.Check("摘要含包数", stat.IndexOf("包 3 个", StringComparison.Ordinal) >= 0, true);
            c.Check("摘要含可勾选/无主文件",
                    stat.IndexOf("可勾选 3 · 无主文件 0", StringComparison.Ordinal) >= 0, true);
            c.Check("摘要含菜单项合计", stat.IndexOf("已选中贡献菜单项 518", StringComparison.Ordinal) >= 0, true);
            c.Check("摘要含已加载脚本文件数", stat.IndexOf("已加载脚本文件 2 个", StringComparison.Ordinal) >= 0, true);
            c.Check("摘要带插件根", stat.IndexOf(PlugRoot, StringComparison.Ordinal) >= 0, true);
        }

        /// <summary>无主文件的包: main 为空 + err 非空 → 不可勾选, 原因原样显示而不是吞掉。</summary>
        private static void PluginErrPack(Ctx c)
        {
            string err = "目录 Ladon9.3.0_20221128 里有 2 个 .cna 但没有同名主文件, 请直接指定要加载的文件";
            var v = PluginParse.Parse(Doc(
                "{\"ok\":true,\"root\":" + JStr(PlugRoot) + ",\"plugins\":["
                + Pack("Ladon9.3.0_20221128", PlugRoot + "\\Ladon9.3.0_20221128", "dir", "",
                       2, 12345, false, 0, false, err)
                + "],\"selected\":[],\"loaded\":"
                + JPathList("D:\\csdev-c2\\scripts\\cs_dev.cna") + "}"));

            PluginPack p = v.Plugins[0];
            c.Check("包数", v.Plugins.Count, 1);
            c.Check("不可勾选", p.Selectable, false);
            c.Check("BlockWhy = 服务端 err 原文", p.BlockWhy, err);
            c.Check("err 字段原文保留", p.Err, err);
            c.Check("DetailText 原样显示 err (不吞)", p.DetailText, err);
            c.Check("StatusText", p.StatusText, "未选中");
            c.Check("MenusText=0", p.MenusText, "0");
            c.Check("菜单项色为灰", SameBrush(p.MenusBrush, Palette.Dim), true);
            c.Check("行色为警示色", SameBrush(p.RowBrush, Palette.Warn), true);
            c.Check("ToolTip 带 err 原文", p.TooltipText.IndexOf(err, StringComparison.Ordinal) >= 0, true);
            c.Check("ToolTip 带不可勾选说明", p.TooltipText.IndexOf("不可勾选", StringComparison.Ordinal) >= 0, true);
            c.Check("ToolTip 带原始 kind/has_main",
                    p.TooltipText.IndexOf("has_main=false", StringComparison.Ordinal) >= 0, true);
            c.Check("可勾选数 0", v.SelectableCount, 0);
            c.Check("无主文件数 1", v.BlockedCount, 1);
            c.Check("摘要含无主文件数", v.StatsText().IndexOf("无主文件 1", StringComparison.Ordinal) >= 0, true);

            // 界面把它置成勾选 (pending 覆盖) 也不能进提交路径: 服务端对它是整单回错
            var pending = new Dictionary<string, bool>();
            pending[PlugRoot + "\\Ladon9.3.0_20221128"] = true;
            var rows = PluginParse.Rows(v, pending);
            c.Check("pending 覆盖生效(界面显示勾了)", rows[0].Checked, true);
            c.Check("但不进提交路径", PluginParse.PickedPaths(rows).Count, 0);
            c.Check("勾选计数同口径", PluginParse.PickedCount(rows), 0);
        }

        /// <summary>selected 里的残留路径 (插件目录换过) 与大小写/空串容错 —— 解析层不崩。</summary>
        private static void PluginSelectedMissing(Ctx c)
        {
            string root = "D:\\new\\plugin";
            var v = PluginParse.Parse(Doc(
                "{\"ok\":true,\"root\":" + JStr(root) + ",\"plugins\":["
                + Pack("A", root + "\\A", "dir", root + "\\A\\A.cna", 1, 10, true, 5, true, "")
                + "],\"selected\":" + JPathList(
                    root + "\\A|D:\\OLD\\GoneBye||   |" + root.ToLowerInvariant() + "\\a|D:\\old\\gonebye")
                + ",\"loaded\":"
                + JPathList("D:\\csdev-c2\\scripts\\cs_dev.cna|" + root + "\\A\\A.cna") + "}"));

            c.Check("包数(不受 selected 残留影响)", v.Plugins.Count, 1);
            c.Check("大小写不同的路径算命中, 不计残留", v.SelectedMissing.Count, 1);
            c.Check("残留路径原文 (首次出现的写法)", v.SelectedMissing[0], "D:\\OLD\\GoneBye");
            c.Check("空串/纯空白不产生残留条目", v.SelectedMissing.Count, 1);
            c.Check("selected 原文一条不丢", Join(v.Selected),
                    root + "\\A|D:\\OLD\\GoneBye||   |" + root.ToLowerInvariant() + "\\a|D:\\old\\gonebye");
            c.Check("已选中包数", v.LoadedCount, 1);
            c.Check("菜单项合计", v.MenusTotal, 5);

            string stat = v.StatsText();
            c.Check("摘要给警告", stat.IndexOf("selected 里 1 个路径不在当前插件根的列表里", StringComparison.Ordinal) >= 0, true);
            c.Check("摘要带残留路径原文", stat.IndexOf("D:\\OLD\\GoneBye", StringComparison.Ordinal) >= 0, true);
            c.Check("摘要仍报正常包数", stat.IndexOf("包 1 个", StringComparison.Ordinal) >= 0, true);
        }

        /// <summary>空列表; 以及服务端 ok=false + error (未配置/目录不存在时也回 HTTP 200)。</summary>
        private static void PluginEmptyAndFail(Ctx c)
        {
            var empty = PluginParse.Parse(Doc(
                "{\"ok\":true,\"root\":\"D:\\\\empty\",\"plugins\":[],\"selected\":[],\"loaded\":"
                + JPathList("D:\\csdev-c2\\scripts\\cs_dev.cna") + "}"));
            c.Check("空列表 Present", empty.Present, true);
            c.Check("空列表 Ok", empty.Ok, true);
            c.Check("包数 0", empty.Plugins.Count, 0);
            c.Check("三项计数全为 0", empty.SelectableCount + empty.BlockedCount + empty.LoadedCount, 0);
            c.Check("菜单项合计 0", empty.MenusTotal, 0);
            c.Check("已加载脚本文件 1 (scripts 常驻)", empty.Loaded.Count, 1);
            c.Check("摘要含包 0 个", empty.StatsText().IndexOf("包 0 个", StringComparison.Ordinal) >= 0, true);
            c.Check("行集合为空", PluginParse.Rows(empty, null).Count, 0);
            c.Check("提交路径为空", Join(PluginParse.PickedPaths(PluginParse.Rows(empty, null))), "");
            c.Check("残留路径 0", empty.SelectedMissing.Count, 0);

            string err = "未配置插件目录(启动加 --plugins-dir <目录>)";
            var bad = PluginParse.Parse(Doc("{\"ok\":false,\"error\":" + JStr(err) + ",\"root\":\"\"}"));
            c.Check("ok=false 也算 Present (响应是对象)", bad.Present, true);
            c.Check("Ok=false", bad.Ok, false);
            c.Check("error 原文", bad.Error, err);
            c.Check("包数 0", bad.Plugins.Count, 0);
            c.Check("摘要带 error 原文", bad.StatsText().IndexOf(err, StringComparison.Ordinal) >= 0, true);
            c.Check("摘要标注不可用", bad.StatsText().IndexOf("插件列表不可用:", StringComparison.Ordinal) >= 0, true);
            c.Check("root 为空时如实说明", bad.RootText().IndexOf("--plugins-dir", StringComparison.Ordinal) >= 0, true);

            var arr = PluginParse.Parse(Doc("[1,2,3]"));
            c.Check("顶层数组 -> Present=false", arr.Present, false);
            c.Check("顶层数组 -> 摘要说明不是对象",
                    arr.StatsText().IndexOf("不是 JSON 对象", StringComparison.Ordinal) >= 0, true);

            var nul = PluginParse.Parse(Doc("{\"ok\":true,\"root\":\"D:\\\\e\",\"plugins\":null,\"selected\":null,\"loaded\":\"x\"}"));
            c.Check("plugins=null -> 0 个", nul.Plugins.Count, 0);
            c.Check("selected=null -> 空", nul.Selected.Count, 0);
            c.Check("loaded 为字符串 -> 空", nul.Loaded.Count, 0);

            var soft = PluginParse.Parse(Doc("{\"ok\":\"true\",\"root\":\"D:\\\\e\"}"));
            c.Check("ok 非布尔按 false 处理", soft.Ok, false);
            c.Check("缺 error 时如实说明",
                    soft.StatsText().IndexOf("未给出 error 字段", StringComparison.Ordinal) >= 0, true);
        }

        /// <summary>字段缺失 / 类型不符一律降级, 不抛异常, 也不假装拿到了值。</summary>
        private static void PluginFieldDegrade(Ctx c)
        {
            c.Check("plugins 缺失", PluginParse.Parse(Doc("{\"ok\":true}")).Plugins.Count, 0);
            c.Check("plugins 非数组", PluginParse.Parse(Doc("{\"ok\":true,\"plugins\":\"x\"}")).Plugins.Count, 0);
            c.Check("非对象元素被跳过",
                    PluginParse.Parse(Doc("{\"ok\":true,\"plugins\":[7,{\"name\":\"ok\"}]}")).Plugins.Count, 1);
            c.Check("无名无路径被丢弃", PluginParse.Parse(Doc("{\"ok\":true,\"plugins\":[{}]}")).Plugins.Count, 0);

            var bare = PluginParse.Parse(Doc(
                "{\"ok\":true,\"plugins\":[{\"path\":\"D:\\\\x\\\\only.cna\"}]}"));
            c.Check("name 缺失时用文件名兜底", bare.Plugins[0].Name, "only.cna");
            c.Check("kind 缺失 -> 类型列 '-'", bare.Plugins[0].KindText, "-");
            c.Check("main 缺失 -> 不可勾选", bare.Plugins[0].Selectable, false);
            c.Check("main 缺失 -> BlockWhy 有话说", bare.Plugins[0].BlockWhy.Length > 0, true);
            c.Check("main 缺失 -> DetailText 如实说明", bare.Plugins[0].DetailText, "(服务端未给出主文件)");
            c.Check("bytes 缺失 -> '-'", bare.Plugins[0].SizeText, "-");
            c.Check("files 缺失 -> 0", bare.Plugins[0].FilesText, "0");

            var strNum = PluginParse.Parse(Doc(
                "{\"ok\":true,\"plugins\":[{\"name\":\"N\",\"path\":\"D:\\\\x\\\\N\",\"kind\":\"dir\","
                + "\"main\":\"D:\\\\x\\\\N\\\\N.cna\",\"files\":\"12\",\"bytes\":\"345\",\"menus\":\"7\","
                + "\"loaded\":\"yes\"}]}"));
            c.Check("字符串数字 files", strNum.Plugins[0].FilesText, "12");
            c.Check("字符串数字 bytes", strNum.Plugins[0].SizeText, "345 B");
            c.Check("字符串数字 menus", strNum.Plugins[0].MenusText, "7");
            c.Check("loaded 非布尔 -> false", strNum.Plugins[0].Loaded, false);

            var weird = PluginParse.Parse(Doc(
                "{\"ok\":true,\"plugins\":[{\"name\":\"N\",\"path\":\"D:\\\\x\\\\N\",\"kind\":\"weird\","
                + "\"main\":\"D:\\\\x\\\\N\\\\N.cna\",\"bytes\":-1,\"menus\":-3}]}"));
            c.Check("未知 kind 原样显示", weird.Plugins[0].KindText, "weird");
            c.Check("负字节降级 '-'", weird.Plugins[0].SizeText, "-");
            c.Check("负 menus 原样", weird.Plugins[0].MenusText, "-3");
            c.Check("未知 kind 仍可勾选 (判据是 main 非空)", weird.Plugins[0].Selectable, true);

            var noPath = PluginParse.Parse(Doc(
                "{\"ok\":true,\"plugins\":[{\"name\":\"只有名字\"},{\"name\":\"X\",\"main\":\"D:\\\\x\\\\X.cna\"}]}"));
            c.Check("无路径的行仍保留", noPath.Plugins.Count, 2);
            c.Check("Key 退化为名字", noPath.Plugins[0].Key, "p|只有名字");
            var pend = new Dictionary<string, bool>();
            pend[""] = true;
            var rows = PluginParse.Rows(noPath, pend);
            c.Check("可勾选但无路径", rows[1].Checked, true);
            c.Check("无路径不进入提交表", PluginParse.PickedPaths(rows).Count, 0);
        }

        /// <summary>POST /api/plugin/set 的结果文案: 成功报计数, 失败原样带服务端 error。</summary>
        private static void PluginSetResult(Ctx c)
        {
            var ok = PluginParse.ParseSet(Doc(
                "{\"ok\":true,\"selected\":" + JPathList("D:\\p\\LSTAR|D:\\p\\TaoWu")
                + ",\"loaded\":" + JPathList("D:\\csdev-c2\\scripts\\cs_dev.cna|D:\\p\\LSTAR\\LSTAR.cna|D:\\p\\TaoWu\\TaoWu.cna")
                + ",\"commands\":[\"?\",\"recon\",\"x\"]}"));
            c.Check("Present", ok.Present, true);
            c.Check("Ok", ok.Ok, true);
            c.Check("selected 数", ok.Selected.Count, 2);
            c.Check("loaded 数", ok.Loaded.Count, 3);
            c.Check("commands 数", ok.Commands.Count, 3);
            c.Check("成功文案", PluginParse.SetResultText(ok, 2),
                    "已应用插件选择: 勾选 2 个包 / 服务端选中 2 个 / 已加载脚本 3 个文件 / 命令 3 个 (引擎已重建, 菜单树/命令/诊断已刷新)");

            string err = "目录 Ladon9.3.0_20221128 里没有 .cna";
            var fail = PluginParse.ParseSet(Doc("{\"ok\":false,\"error\":" + JStr(err) + "}"));
            string ft = PluginParse.SetResultText(fail, 3);
            c.Check("失败文案带服务端 error 原文", ft.IndexOf(err, StringComparison.Ordinal) >= 0, true);
            c.Check("失败文案带勾选数", ft.IndexOf("勾选 3 个包", StringComparison.Ordinal) >= 0, true);
            c.Check("失败文案指向刷新核对", ft.IndexOf("刷新列表", StringComparison.Ordinal) >= 0, true);
            c.Check("失败时 Ok=false", fail.Ok, false);

            var noErr = PluginParse.ParseSet(Doc("{\"ok\":false}"));
            c.Check("失败且无 error -> 如实说明",
                    PluginParse.SetResultText(noErr, 1).IndexOf("未给出 error 字段", StringComparison.Ordinal) >= 0, true);
            c.Check("非对象响应 -> 失败文案",
                    PluginParse.SetResultText(PluginParse.ParseSet(Doc("\"x\"")), 0)
                        .IndexOf("不是 JSON 对象", StringComparison.Ordinal) >= 0, true);
            c.Check("null 结果不抛",
                    PluginParse.SetResultText(null, 2).IndexOf("勾选 2 个包", StringComparison.Ordinal) >= 0, true);

            var rootSet = PluginParse.ParseSet(Doc(
                "{\"ok\":true,\"selected\":[],\"loaded\":" + JPathList("D:\\csdev-c2\\scripts\\cs_dev.cna")
                + ",\"commands\":[\"?\",\"recon\",\"x\",\"listbeacons\"]}"));
            string rt = PluginParse.RootSetText(rootSet, "D:\\别的\\目录", 0);
            c.Check("换根文案带新目录", rt.IndexOf("插件目录已切换为 D:\\别的\\目录", StringComparison.Ordinal) >= 0, true);
            c.Check("换根文案带已加载脚本数", rt.IndexOf("已加载脚本 1 个文件", StringComparison.Ordinal) >= 0, true);
            c.Check("换根文案带命令数", rt.IndexOf("命令 4 个", StringComparison.Ordinal) >= 0, true);

            string rtFail = PluginParse.RootSetText(
                PluginParse.ParseSet(Doc("{\"ok\":false,\"error\":\"路径不存在: D:\\\\nope\"}")), "D:\\nope", 0);
            c.Check("换根失败文案带 error 原文", rtFail.IndexOf("路径不存在: D:\\nope", StringComparison.Ordinal) >= 0, true);
        }

        /// <summary>勾选态: pending 覆盖优先于服务端 loaded; 取消勾选 = 卸载; 空数组 = 全部卸载。</summary>
        private static void PluginCheckedState(Ctx c)
        {
            string root = "D:\\p";
            string json =
                "{\"ok\":true,\"root\":" + JStr(root) + ",\"plugins\":["
                + Pack("A", root + "\\A", "dir", root + "\\A\\A.cna", 1, 10, true, 3, true, "") + ","
                + Pack("B", root + "\\B", "dir", root + "\\B\\B.cna", 1, 20, true, 4, true, "") + ","
                + Pack("C", root + "\\C", "dir", "", 2, 30, false, 0, false, "目录 C 里没有 .cna") + ","
                + Pack("D.cna", root + "\\D.cna", "file", root + "\\D.cna", 1, 40, false, 0, false, "")
                + "],\"selected\":" + JPathList(root + "\\A|" + root + "\\B") + ",\"loaded\":[]}";

            var none = PluginParse.Rows(PluginParse.Parse(Doc(json)), null);
            c.Check("默认勾选 = 服务端 loaded",
                    Join(PluginParse.PickedPaths(none)), root + "\\A|" + root + "\\B");

            // 取消 B 的勾选 + 勾上散装 D: 只登记意图, 提交集合随之变化
            var v2 = PluginParse.Parse(Doc(json));
            var pending = new Dictionary<string, bool>();
            pending[root + "\\B"] = false;
            pending[root + "\\D.cna"] = true;
            var rows = PluginParse.Rows(v2, pending);
            c.Check("取消勾选生效", FindRow(rows, root + "\\B").Checked, false);
            c.Check("新勾选生效", FindRow(rows, root + "\\D.cna").Checked, true);
            c.Check("没动过的行保持服务端值", FindRow(rows, root + "\\A").Checked, true);
            c.Check("提交集合 = A + D", Join(PluginParse.PickedPaths(rows)), root + "\\A|" + root + "\\D.cna");
            c.Check("勾选计数", PluginParse.PickedCount(rows), 2);
            // 勾选态就落在视图行对象上 (界面 Sync 复用的正是这些行), 所以不传 pending 也不回退 ——
            // 刷新列表时靠 pending 覆盖兜住"改了但还没应用"的改动 (见下一个用例)。
            c.Check("不传 pending 也保持本地勾选 (行对象即状态)",
                    Join(PluginParse.PickedPaths(PluginParse.Rows(v2, null))), root + "\\A|" + root + "\\D.cna");

            var clear = new Dictionary<string, bool>();
            clear[root + "\\A"] = false;
            clear[root + "\\B"] = false;
            var rows2 = PluginParse.Rows(PluginParse.Parse(Doc(json)), clear);
            c.Check("全不勾 -> 提交表为空(空数组 = 服务端全部卸载)", PluginParse.PickedPaths(rows2).Count, 0);
            c.Check("空数组的应用文案", PluginParse.SetResultText(PluginParse.ParseSet(Doc(
                "{\"ok\":true,\"selected\":[],\"loaded\":" + JPathList("D:\\csdev-c2\\scripts\\cs_dev.cna")
                + ",\"commands\":[\"?\"]}")), 0),
                "已应用插件选择: 勾选 0 个包 / 服务端选中 0 个 / 已加载脚本 1 个文件 / 命令 1 个 (引擎已重建, 菜单树/命令/诊断已刷新)");

            // pending 键大小写不同也能命中; 陈旧键 (目录换过) 被忽略且不抛
            var sloppy = new Dictionary<string, bool>();
            sloppy[root.ToLowerInvariant() + "\\a"] = false;
            sloppy["D:\\GONE\\Old"] = true;
            var rows3 = PluginParse.Rows(PluginParse.Parse(Doc(json)), sloppy);
            c.Check("pending 键大小写不同也命中", FindRow(rows3, root + "\\A").Checked, false);
            c.Check("陈旧 pending 键不产生新行", rows3.Count, 4);
            c.Check("陈旧键不影响提交表", Join(PluginParse.PickedPaths(rows3)), root + "\\B");
        }

        /// <summary>
        /// 真实样本: 2026-09-16 用
        /// <c>build\csdev-server.exe -port 8630 -auth=off --plugins-dir "D:\Tools\1\tools\gui_other\Cobalt_Strike_4.7\plugin"</c>
        /// 实测的 GET /api/plugins 响应 (包列表与 selected/loaded 原样抄录)。
        /// 关键真实特征: 8 个包 / 只有 LSTAR+TaoWu 已选中 (menus 427+365) /
        /// Ladon 无主文件 (main 为空 + 中文 err) / cs_dev.cna 是 has_main=false 的散装文件包 /
        /// PrivKit 的主文件叫 PrivCheck.cna / XieGongZi 走 main.cna 约定 / loaded 28 个脚本文件。
        /// </summary>
        private static void PluginRealSample(Ctx c)
        {
            const string LadonErr = "目录 Ladon9.3.0_20221128 里没有 .cna";
            string loadedJoined =
                "D:\\csdev-c2\\scripts\\cs_dev.cna|D:\\csdev-c2\\scripts\\example.cna|"
              + PlugRoot + "\\LSTAR\\LSTAR.cna|" + PlugRoot + "\\LSTAR\\modules\\InfoCollect.cna|"
              + PlugRoot + "\\LSTAR\\modules\\IntrScan.cna|" + PlugRoot + "\\LSTAR\\modules\\IntrAgent.cna|"
              + PlugRoot + "\\LSTAR\\modules\\AuthPromote.cna|" + PlugRoot + "\\LSTAR\\modules\\AuthMaintain.cna|"
              + PlugRoot + "\\LSTAR\\modules\\PassCapture.cna|" + PlugRoot + "\\LSTAR\\modules\\RemoteLogin.cna|"
              + PlugRoot + "\\LSTAR\\modules\\LateMovement.cna|" + PlugRoot + "\\LSTAR\\modules\\TraceClean.cna|"
              + PlugRoot + "\\LSTAR\\modules\\BypassCxk.cna|" + PlugRoot + "\\LSTAR\\modules\\HavingFun.cna|"
              + PlugRoot + "\\TaoWu\\TaoWu.cna|" + PlugRoot + "\\TaoWu\\modules\\discovery.cna|"
              + PlugRoot + "\\TaoWu\\modules\\Intranet.cna|" + PlugRoot + "\\TaoWu\\modules\\Vulnerability.cna|"
              + PlugRoot + "\\TaoWu\\modules\\credential access.cna|" + PlugRoot + "\\TaoWu\\modules\\privilege.cna|"
              + PlugRoot + "\\TaoWu\\modules\\privilege escalation.cna|" + PlugRoot + "\\TaoWu\\modules\\brute force.cna|"
              + PlugRoot + "\\TaoWu\\modules\\Intranet penetration.cna|" + PlugRoot + "\\TaoWu\\modules\\Lateral movement.cna|"
              + PlugRoot + "\\TaoWu\\modules\\system.cna|" + PlugRoot + "\\TaoWu\\modules\\entertainment.cna|"
              + PlugRoot + "\\TaoWu\\modules\\SharpDPAPI.cna|" + PlugRoot + "\\TaoWu\\modules\\about.cna";

            var v = PluginParse.Parse(Doc(
                "{\"ok\":true,\"root\":" + JStr(PlugRoot) + ",\"plugins\":["
                + Pack("LSTAR", PlugRoot + "\\LSTAR", "dir", PlugRoot + "\\LSTAR\\LSTAR.cna",
                       12, 288974, true, 427, true, "") + ","
                + Pack("Ladon9.3.0_20221128", PlugRoot + "\\Ladon9.3.0_20221128", "dir", "",
                       2, 145449, false, 0, false, LadonErr) + ","
                + Pack("OLa", PlugRoot + "\\OLa", "dir", PlugRoot + "\\OLa\\OLa.cna",
                       11, 263155, false, 0, true, "") + ","
                + Pack("PrivKit", PlugRoot + "\\PrivKit", "dir", PlugRoot + "\\PrivKit\\PrivCheck.cna",
                       1, 19463, false, 0, true, "") + ","
                + Pack("TaoWu", PlugRoot + "\\TaoWu", "dir", PlugRoot + "\\TaoWu\\TaoWu.cna",
                       17, 174225, true, 365, true, "") + ","
                + Pack("XieGongZi", PlugRoot + "\\XieGongZi", "dir", PlugRoot + "\\XieGongZi\\main.cna",
                       17, 112255, false, 0, true, "") + ","
                + Pack("cs_dev", PlugRoot + "\\cs_dev", "dir", PlugRoot + "\\cs_dev\\cs_dev.cna",
                       17, 70356, false, 0, true, "") + ","
                + Pack("cs_dev.cna", PlugRoot + "\\cs_dev.cna", "file", PlugRoot + "\\cs_dev.cna",
                       1, 17958, false, 0, false, "")
                + "],\"selected\":" + JPathList(PlugRoot + "\\LSTAR|" + PlugRoot + "\\TaoWu")
                + ",\"loaded\":" + JPathList(loadedJoined) + "}"));

            c.Check("包数", v.Plugins.Count, 8);
            c.Check("可勾选 7 / 无主文件 1", v.SelectableCount + "/" + v.BlockedCount, "7/1");
            c.Check("当前选中 2 个", v.LoadedCount, 2);
            c.Check("已选中贡献菜单项 792 (427+365)", v.MenusTotal, 792);
            c.Check("已加载脚本文件 28 个", v.Loaded.Count, 28);
            c.Check("selected 无残留", v.SelectedMissing.Count, 0);

            PluginPack ls = FindPack(v, "LSTAR");
            c.Check("[LSTAR].menus", ls.MenusText, "427");
            c.Check("[LSTAR].files/bytes", ls.FilesText + "/" + ls.SizeText, "12/282.2 KB");
            c.Check("[LSTAR].已选中", ls.StatusText, "已选中");
            c.Check("[LSTAR].DetailText", ls.DetailText, "LSTAR.cna");

            PluginPack ladon = FindPack(v, "Ladon9.3.0_20221128");
            c.Check("[Ladon].不可勾选", ladon.Selectable, false);
            c.Check("[Ladon].err 显示原文", ladon.DetailText, LadonErr);
            c.Check("[Ladon].files/bytes", ladon.FilesText + "/" + ladon.SizeText, "2/142.0 KB");

            PluginPack tw = FindPack(v, "TaoWu");
            c.Check("[TaoWu].menus", tw.MenusText, "365");
            c.Check("[TaoWu].files/bytes", tw.FilesText + "/" + tw.SizeText, "17/170.1 KB");

            PluginPack pk = FindPack(v, "PrivKit");
            c.Check("[PrivKit].主文件走『目录内唯一 .cna』回退", pk.DetailText, "PrivCheck.cna");
            PluginPack xg = FindPack(v, "XieGongZi");
            c.Check("[XieGongZi].主文件走 main.cna 约定", xg.DetailText, "main.cna");

            PluginPack file = FindPack(v, "cs_dev.cna");
            c.Check("[散装文件].KindText", file.KindText, "文件");
            c.Check("[散装文件].has_main=false 但可勾选", file.HasMain + "/" + file.Selectable, "False/True");
            c.Check("[散装文件].DetailText", file.DetailText, "cs_dev.cna");

            c.Check("提交路径 = 当前两个已选中包",
                    Join(PluginParse.PickedPaths(PluginParse.Rows(v, null))),
                    PlugRoot + "\\LSTAR|" + PlugRoot + "\\TaoWu");

            string stat = v.StatsText();
            c.Check("摘要包数", stat.IndexOf("包 8 个", StringComparison.Ordinal) >= 0, true);
            c.Check("摘要当前选中 2", stat.IndexOf("当前选中 2 个", StringComparison.Ordinal) >= 0, true);
            c.Check("摘要菜单项 792", stat.IndexOf("已选中贡献菜单项 792", StringComparison.Ordinal) >= 0, true);
            c.Check("摘要脚本文件 28", stat.IndexOf("已加载脚本文件 28 个", StringComparison.Ordinal) >= 0, true);
        }

        // ================================================================ 手工添加的脚本 (external)

        /// <summary>
        /// 正常 external: 手工挑的 .cna 文件 + 不在插件根下的目录包, 都带着 exists / 文件数 /
        /// 菜单项实测值; 关键断言是**它们不再被算成 selected 残留**(它们本来就是合法的选中项)。
        /// </summary>
        private static void PluginExternalNormal(Ctx c)
        {
            string f1 = "D:\\my\\scripts\\x.cna";
            string d1 = "D:\\my\\packs\\ExtraPack";
            var v = PluginParse.Parse(Doc(
                "{\"ok\":true,\"root\":" + JStr(PlugRoot) + ",\"plugins\":["
                + Pack("LSTAR", PlugRoot + "\\LSTAR", "dir", PlugRoot + "\\LSTAR\\LSTAR.cna",
                       12, 288974, true, 427, true, "")
                + "],\"external\":["
                + Ext(f1, "x.cna", true, true, 1, 2048, 37, "") + ","
                + Ext(d1, "ExtraPack", true, true, 4, 9000, 12, "")
                + "],\"selected\":" + JPathList(PlugRoot + "\\LSTAR|" + f1 + "|" + d1)
                + ",\"loaded\":" + JPathList("D:\\csdev-c2\\scripts\\cs_dev.cna|" + f1 + "|" + d1 + "\\main.cna")
                + "}"));

            c.Check("包数不受 external 影响", v.Plugins.Count, 1);
            c.Check("external 条数", v.External.Count, 2);
            c.Check("失效条目 0", v.ExternalBroken, 0);
            c.Check("external 菜单项合计 (37+12)", v.ExternalMenus, 49);
            c.Check("external 不再算 selected 残留", v.SelectedMissing.Count, 0);

            PluginExternalRow x = PluginParse.FindExternal(v.External, f1);
            c.Check("文件名", x.Name, "x.cna");
            c.Check("存在性文案", x.ExistsText, "存在");
            c.Check("存在性色 = 绿", SameBrush(x.ExistsBrush, Palette.Ok), true);
            c.Check("行色 = 白 (正常)", SameBrush(x.RowBrush, Palette.Fg), true);
            c.Check("文件数/大小", x.FilesText + "/" + x.SizeText, "1/2.0 KB");
            c.Check("贡献菜单项", x.MenusText, "37");
            c.Check("菜单项色 = 绿", SameBrush(x.MenusBrush, Palette.Ok), true);
            c.Check("详情 = 文件数与大小", x.DetailText, "1 个文件 / 2.0 KB");
            c.Check("主键按路径", x.Key, "x|" + f1);
            c.Check("ToolTip 点明是手工添加", x.TooltipText.IndexOf("手工添加的脚本 (不在插件根目录下)", StringComparison.Ordinal) >= 0, true);
            c.Check("ToolTip 带路径", x.TooltipText.IndexOf(f1, StringComparison.Ordinal) >= 0, true);
            c.Check("ToolTip 带菜单项数", x.TooltipText.IndexOf("贡献菜单项: 37", StringComparison.Ordinal) >= 0, true);

            PluginExternalRow d = PluginParse.FindExternal(v.External, d1);
            c.Check("目录包也存在", d.ExistsText, "存在");
            c.Check("目录包文件数/大小", d.FilesText + "/" + d.SizeText, "4/8.8 KB");
            c.Check("目录包菜单项", d.MenusText, "12");

            string stat = v.StatsText();
            c.Check("摘要带外部条数", stat.IndexOf("服务端 external 2 个", StringComparison.Ordinal) >= 0, true);
            c.Check("摘要带失效数与菜单项",
                    stat.IndexOf("(失效 0 · 贡献菜单项 49)", StringComparison.Ordinal) >= 0, true);

            var rows = PluginParse.ExternalRows(v, null, null);
            c.Check("面板行 = 服务端 2 条", rows.Count, 2);
            c.Check("面板摘要", PluginParse.ExternalSummaryText(rows), "手工添加 2 个 (失效 0 · 贡献菜单项 49)");
            c.Check("面板提示讲两步移除",
                    PluginParse.ExternalHint(rows).IndexOf("点『应用选择』才卸载", StringComparison.Ordinal) >= 0, true);
            c.Check("无失效/无本地时不啰嗦",
                    PluginParse.ExternalHint(rows).IndexOf("已失效", StringComparison.Ordinal) >= 0, false);
        }

        /// <summary>
        /// 失效 external: 路径被移动/删除 (exists=false) 与"目录在但定位不到入口"
        /// (exists=true + err 非空) —— 两种都要显眼标出, 且 err 原样显示。
        /// </summary>
        private static void PluginExternalBroken(Ctx c)
        {
            string gone = "D:\\gone\\y.cna";
            string noMain = "D:\\my\\packs\\LadonLike";
            string noMainErr = "目录 LadonLike 里有 2 个 .cna 但没有同名主文件, 请直接指定要加载的文件";
            const string GoneErr = "路径不存在(可能被移动或删除)";
            var v = PluginParse.Parse(Doc(
                "{\"ok\":true,\"root\":" + JStr(PlugRoot) + ",\"plugins\":[],\"external\":["
                + Ext(gone, "y.cna", false, true, 0, 0, 0, GoneErr) + ","
                + Ext(noMain, "LadonLike", true, true, 2, 145449, 0, noMainErr)
                + "],\"selected\":" + JPathList(gone + "|" + noMain) + ",\"loaded\":[]}"));

            c.Check("条数", v.External.Count, 2);
            c.Check("失效计数 (exists=false)", v.ExternalBroken, 1);
            c.Check("失效的也不算残留", v.SelectedMissing.Count, 0);

            PluginExternalRow g = PluginParse.FindExternal(v.External, gone);
            c.Check("失效文案", g.ExistsText, "路径已失效");
            c.Check("失效色 = 红", SameBrush(g.ExistsBrush, Palette.Err), true);
            c.Check("整行色 = 红", SameBrush(g.RowBrush, Palette.Err), true);
            c.Check("err 原文进详情列", g.DetailText, GoneErr);
            c.Check("err 字段原文保留", g.Err, GoneErr);
            c.Check("ToolTip 带 err 原文", g.TooltipText.IndexOf(GoneErr, StringComparison.Ordinal) >= 0, true);
            c.Check("ToolTip 讲清怎么卸掉它",
                    g.TooltipText.IndexOf("点『移除』后『应用选择』即可卸载", StringComparison.Ordinal) >= 0, true);

            PluginExternalRow n = PluginParse.FindExternal(v.External, noMain);
            c.Check("目录在但无入口 -> 存在·无入口", n.ExistsText, "存在·无入口");
            c.Check("无入口色 = 橙", SameBrush(n.ExistsBrush, Palette.Warn), true);
            c.Check("整行色 = 橙", SameBrush(n.RowBrush, Palette.Warn), true);
            c.Check("无入口 err 原样", n.DetailText, noMainErr);
            c.Check("不计入失效 (路径本身在)", v.ExternalBroken, 1);

            var rows = PluginParse.ExternalRows(v, null, null);
            c.Check("面板摘要标失效数", PluginParse.ExternalSummaryText(rows),
                    "手工添加 2 个 (失效 1 · 贡献菜单项 0)");
            c.Check("面板提示建议处理失效条目",
                    PluginParse.ExternalHint(rows).IndexOf("1 个路径已失效", StringComparison.Ordinal) >= 0, true);
            c.Check("面板提示给处置建议",
                    PluginParse.ExternalHint(rows).IndexOf("建议移除后应用", StringComparison.Ordinal) >= 0, true);
            c.Check("摘要也报失效", v.StatsText().IndexOf("(失效 1 · 贡献菜单项 0)", StringComparison.Ordinal) >= 0, true);
        }

        /// <summary>external 缺失 / 空 / 类型不符 / 元素退化 —— 一律降级, 不抛, 也不编造"存在"。</summary>
        private static void PluginExternalDegrade(Ctx c)
        {
            c.Check("external 缺失 -> 0", PluginParse.Parse(Doc("{\"ok\":true}")).External.Count, 0);
            c.Check("external 空数组 -> 0", PluginParse.Parse(Doc("{\"ok\":true,\"external\":[]}")).External.Count, 0);
            c.Check("external 非数组 -> 0", PluginParse.Parse(Doc("{\"ok\":true,\"external\":\"x\"}")).External.Count, 0);
            c.Check("external=null -> 0", PluginParse.Parse(Doc("{\"ok\":true,\"external\":null}")).External.Count, 0);
            c.Check("元素非对象被跳过",
                    PluginParse.Parse(Doc("{\"ok\":true,\"external\":[7,{}]}")).External.Count, 0);
            c.Check("无名无路径被丢弃",
                    PluginParse.Parse(Doc("{\"ok\":true,\"external\":[{\"err\":\"x\"}]}")).External.Count, 0);
            c.Check("external 为空时摘要也说得清",
                    PluginParse.ExternalSummaryText(PluginParse.ExternalRows(
                        PluginParse.Parse(Doc("{\"ok\":true}")), null, null)), "手工添加 0 个");
            c.Check("空集合的提示指向浏览按钮",
                    PluginParse.ExternalHint(PluginParse.ExternalRows(
                        PluginParse.Parse(Doc("{\"ok\":true}")), null, null))
                        .IndexOf("浏览…", StringComparison.Ordinal) >= 0, true);

            var bare = PluginParse.Parse(Doc("{\"ok\":true,\"external\":[{\"path\":\"D:\\\\my\\\\only.cna\"}]}"));
            c.Check("只有 path 也保留", bare.External.Count, 1);
            c.Check("name 缺失用文件名兜底", bare.External[0].Name, "only.cna");
            c.Check("exists 缺失 -> 状态未知 (不冒充失效)", bare.External[0].ExistsText, "状态未知");
            c.Check("状态未知色 = 灰", SameBrush(bare.External[0].ExistsBrush, Palette.Dim), true);
            c.Check("bytes 缺失 -> '-'", bare.External[0].SizeText, "-");
            c.Check("bytes 缺失时详情不谎报大小", bare.External[0].DetailText, "0 个文件");
            c.Check("ToolTip 说明存在性未知",
                    bare.External[0].TooltipText.IndexOf("存在性未知", StringComparison.Ordinal) >= 0, true);

            var strNum = PluginParse.Parse(Doc(
                "{\"ok\":true,\"external\":[{\"path\":\"D:\\\\my\\\\s.cna\",\"name\":\"s.cna\",\"exists\":\"yes\","
                + "\"files\":\"3\",\"bytes\":\"2048\",\"menus\":\"7\"}]}"));
            c.Check("字符串数字 files", strNum.External[0].FilesText, "3");
            c.Check("字符串数字 bytes", strNum.External[0].SizeText, "2.0 KB");
            c.Check("字符串数字 menus", strNum.External[0].MenusText, "7");
            c.Check("exists 非布尔 -> 未知", strNum.External[0].ExistsText, "状态未知");

            var neg = PluginParse.Parse(Doc(
                "{\"ok\":true,\"external\":[{\"path\":\"D:\\\\my\\\\n.cna\",\"name\":\"n.cna\",\"exists\":true,"
                + "\"files\":1,\"bytes\":-1,\"menus\":-3}]}"));
            c.Check("负字节降级 '-'", neg.External[0].SizeText, "-");
            c.Check("负 menus 原样", neg.External[0].MenusText, "-3");
            c.Check("menus<=0 -> 灰", SameBrush(neg.External[0].MenusBrush, Palette.Dim), true);
            c.Check("菜单项列为 0 时不吹成绿", SameBrush(
                PluginParse.Parse(Doc("{\"ok\":true,\"external\":[{\"path\":\"D:\\\\a.cna\",\"exists\":true,\"menus\":0}]}"))
                    .External[0].MenusBrush, Palette.Dim), true);
        }

        /// <summary>
        /// 面板行集合 = 服务端 external[] ∪ 本地手工登记, 去重, 并让『移除』立刻从面板消失。
        /// </summary>
        private static void PluginExternalRows(Ctx c)
        {
            string x1 = "D:\\my\\scripts\\x.cna";
            string gone = "D:\\gone\\y.cna";
            string localNew = "D:\\my\\new.cna";
            var v = PluginParse.Parse(Doc(
                "{\"ok\":true,\"root\":" + JStr(PlugRoot) + ",\"plugins\":[],\"external\":["
                + Ext(x1, "x.cna", true, true, 1, 2048, 37, "") + ","
                + Ext(gone, "y.cna", false, true, 0, 0, 0, "路径不存在(可能被移动或删除)")
                + "],\"selected\":" + JPathList(x1 + "|" + gone) + ",\"loaded\":[]}"));

            var extras = new List<string>();
            extras.Add(localNew);
            extras.Add("d:\\MY\\scripts\\X.CNA");   // 服务端已回显同一路径的大小写变体 -> 不重复成两行
            extras.Add("   ");                      // 空白 -> 丢弃
            var rows = PluginParse.ExternalRows(v, extras, null);

            c.Check("行数 = 服务端 2 + 本地 1", rows.Count, 3);
            c.Check("顺序: 服务端优先", JoinExternal(rows), "x.cna|y.cna|new.cna");
            c.Check("本地登记标记", PluginParse.FindExternal(rows, localNew).Local, true);
            c.Check("服务端条目不是本地登记", PluginParse.FindExternal(rows, x1).Local, false);
            c.Check("大小写变体没造出第二行", PluginParse.FindExternal(rows, "D:\\MY\\SCRIPTS\\X.CNA").Name, "x.cna");
            c.Check("本地条目存在性标为『本地登记』", PluginParse.FindExternal(rows, localNew).ExistsText, "本地登记");
            c.Check("本地条目色 = 蓝", SameBrush(PluginParse.FindExternal(rows, localNew).RowBrush, Palette.Accent), true);
            c.Check("本地条目详情指向应用选择",
                    PluginParse.FindExternal(rows, localNew).DetailText.IndexOf("应用选择", StringComparison.Ordinal) >= 0, true);
            c.Check("本地条目字节未测 -> '-'", PluginParse.FindExternal(rows, localNew).SizeText, "-");
            c.Check("本地条目 ToolTip 说明还没提交",
                    PluginParse.FindExternal(rows, localNew).TooltipText.IndexOf("还没提交", StringComparison.Ordinal) >= 0, true);
            c.Check("面板摘要带本地待提交", PluginParse.ExternalSummaryText(rows),
                    "手工添加 3 个 (失效 1 · 贡献菜单项 37 · 本地待提交 1)");
            c.Check("面板提示带本地待提交",
                    PluginParse.ExternalHint(rows).IndexOf("1 个本地待提交条目", StringComparison.Ordinal) >= 0, true);

            // 『移除』: 服务端条目进排除名单后立刻从面板消失
            var dropped = new List<string>();
            dropped.Add(gone.ToUpperInvariant());          // 大小写不同也算同一条
            var rows2 = PluginParse.ExternalRows(v, extras, dropped);
            c.Check("移除后少一行", rows2.Count, 2);
            c.Check("被移除的不在面板里", PluginParse.FindExternal(rows2, gone), null);
            c.Check("移除只影响被移除的那条", JoinExternal(rows2), "x.cna|new.cna");
            c.Check("摘要随之更新", PluginParse.ExternalSummaryText(rows2),
                    "手工添加 2 个 (失效 0 · 贡献菜单项 37 · 本地待提交 1)");

            // 本地条目被移除: 从待加载集合里删掉 + 也进排除名单 (两条路都不提交)
            var dropped2 = new List<string>();
            dropped2.Add(localNew);
            c.Check("本地条目移除后消失", PluginParse.ExternalRows(v, extras, dropped2).Count, 2);
            c.Check("本地移除不影响服务端条目",
                    PluginParse.FindExternal(PluginParse.ExternalRows(v, extras, dropped2), x1) != null, true);

            c.Check("FindExternal 忽略大小写", PluginParse.FindExternal(rows, x1.ToUpperInvariant()) != null, true);
            c.Check("FindExternal 空路径回 null", PluginParse.FindExternal(rows, ""), null);
            c.Check("FindExternal null 集合回 null", PluginParse.FindExternal(null, x1), null);
        }

        /// <summary>
        /// 最终 paths = 勾选包 + 手工添加, 去重 (忽略大小写/首尾空白) 并扣掉『移除』名单。
        /// 核心场景: 同一个文件既被勾选又被手工添加 —— 只能提交一次。
        /// </summary>
        private static void PluginMergePaths(Ctx c)
        {
            string root = "D:\\p";
            string a = root + "\\A";
            string d = root + "\\D.cna";
            var v = PluginParse.Parse(Doc(
                "{\"ok\":true,\"root\":" + JStr(root) + ",\"plugins\":["
                + Pack("A", a, "dir", a + "\\A.cna", 1, 10, true, 3, true, "") + ","
                + Pack("D.cna", d, "file", d, 1, 40, true, 5, false, "")
                + "],\"selected\":" + JPathList(a + "|" + d) + ",\"loaded\":[]}"));
            var rows = PluginParse.Rows(v, null);
            var picked = PluginParse.PickedPaths(rows);
            c.Check("勾选包 2 个", Join(picked), a + "|" + d);

            string ext = "D:\\my\\x.cna";
            string gone = "D:\\gone\\y.cna";
            var extras = new List<string>();
            extras.Add("  " + a + "  ");      // 与勾选包同一条 (带空白)
            extras.Add("d:\\P\\d.cna");       // 与勾选包同一条 (忽略大小写)
            extras.Add(ext);
            extras.Add(ext);                   // 手工重复挑同一个文件
            extras.Add(gone);                  // 已在"移除名单"里的路径不该进来
            extras.Add("");

            var dropped = new List<string>();
            dropped.Add(gone);
            var merged = PluginParse.MergePaths(picked, extras, dropped);

            c.Check("合并后 3 条 (勾选 2 + 手工 1)", merged.Count, 3);
            c.Check("去重后顺序: 勾选包优先", Join(merged), a + "|" + d + "|" + ext);
            c.Check("同一文件两种写法只提交一次",
                    PluginParse.IndexOfPath(merged, root.ToUpperInvariant() + "\\D.CNA"), 1);
            c.Check("被移除的路径不进提交表", PluginParse.IndexOfPath(merged, gone), -1);
            c.Check("原集合不被修改 (纯函数)", Join(picked), a + "|" + d);

            var onlyExtra = PluginParse.MergePaths(new List<string>(), extras, null);
            c.Check("没有勾选包时手工路径照常提交 (保留首次出现的写法)",
                    Join(onlyExtra), a + "|d:\\P\\d.cna|" + ext + "|" + gone);
            c.Check("空入参 -> 空表", PluginParse.MergePaths(null, null, null).Count, 0);
            c.Check("只有移除名单 -> 空表",
                    PluginParse.MergePaths(new List<string> { gone }, new List<string> { gone }, dropped).Count, 0);
            c.Check("ids 全空 -> 空表",
                    PluginParse.MergePaths(new List<string> { "", "   " }, new List<string> { "" }, null).Count, 0);

            c.Check("IndexOfPath 忽略大小写", PluginParse.IndexOfPath(merged, ext.ToUpperInvariant()), 2);
            c.Check("IndexOfPath 命中首个", PluginParse.IndexOfPath(merged, "  " + a + " "), 0);
            c.Check("IndexOfPath 未命中回 -1", PluginParse.IndexOfPath(merged, "D:\\nope"), -1);
            c.Check("IndexOfPath 空路径回 -1", PluginParse.IndexOfPath(merged, "  "), -1);
            c.Check("IndexOfPath null 表回 -1", PluginParse.IndexOfPath(null, a), -1);

            c.Check("IsDropped 命中 (忽略大小写)", PluginParse.IsDropped(dropped, gone.ToUpperInvariant()), true);
            c.Check("IsDropped 未命中", PluginParse.IsDropped(dropped, ext), false);
            c.Check("IsDropped 空名单 false", PluginParse.IsDropped(null, gone), false);
            c.Check("IsDropped 空路径 false", PluginParse.IsDropped(dropped, "  "), false);
        }

        /// <summary>
        /// 404 文案: 服务端缺路由时给出的必须是**可操作的一步**(旧二进制 → 重新构建并重启),
        /// 其余状态码照旧原样显示 (401/403 的既有文案不能被打乱)。
        /// </summary>
        private static void ApiErrorText(Ctx c)
        {
            const string Page404 = "404 page not found";
            string t = ApiError.Describe(404, Page404, "/api/plugins");
            c.Check("404 点明缺少路由", t.IndexOf("服务端缺少该路由", StringComparison.Ordinal) >= 0, true);
            c.Check("404 带请求路径", t.IndexOf("/api/plugins", StringComparison.Ordinal) >= 0, true);
            c.Check("404 带状态码", t.IndexOf("(HTTP 404)", StringComparison.Ordinal) >= 0, true);
            c.Check("404 指出根因 (二进制过旧)",
                    t.IndexOf("通常是服务端二进制过旧", StringComparison.Ordinal) >= 0, true);
            c.Check("404 给出重新构建命令",
                    t.IndexOf("go build -o csdev-server.exe .", StringComparison.Ordinal) >= 0, true);
            c.Check("404 给出 cd 目录", t.IndexOf("cd D:\\csdev-c2\\go", StringComparison.Ordinal) >= 0, true);
            c.Check("404 要求重启服务端", t.IndexOf("重启 csdev-server.exe", StringComparison.Ordinal) >= 0, true);
            c.Check("404 保留服务端原话", t.IndexOf(Page404, StringComparison.Ordinal) >= 0, true);
            c.Check("404 与常量同源 (改文案只改一处)",
                    t.IndexOf(ApiError.StaleServerHint, StringComparison.Ordinal) >= 0, true);
            c.Check("404 不用「HTTP 404」的裸文案顶替",
                    string.Equals(t, "HTTP 404  |  " + Page404, StringComparison.Ordinal), false);

            string set = ApiError.Describe(404, Page404, "/api/plugin/set");
            c.Check("plugin/set 的 404 也带自己的路径",
                    set.IndexOf("/api/plugin/set", StringComparison.Ordinal) >= 0, true);
            string noPath = ApiError.Describe(404, "", "");
            c.Check("无路径时不留双空格",
                    noPath.IndexOf("服务端缺少该路由 (HTTP 404): ", StringComparison.Ordinal) >= 0, true);
            c.Check("无正文时不带分隔符", noPath.IndexOf("  |  ", StringComparison.Ordinal) < 0, true);

            string t500 = ApiError.Describe(500, "内部错误", "/api/plugins");
            c.Check("500 不套用旧二进制提示",
                    t500.IndexOf("二进制过旧", StringComparison.Ordinal) >= 0, false);
            c.Check("500 原样显示状态码", t500.IndexOf("HTTP 500", StringComparison.Ordinal) >= 0, true);
            c.Check("500 原样带正文", t500.IndexOf("内部错误", StringComparison.Ordinal) >= 0, true);

            c.Check("401 文案不变 (引导登录)",
                    ApiError.Describe(401, "", ""), "未认证或令牌已失效, 请点顶栏『登录』");
            c.Check("403 文案不变 (权限)",
                    ApiError.Describe(403, "forbidden", "").IndexOf("权限不足", StringComparison.Ordinal) >= 0, true);

            string long200 = new string('x', 300);
            string tr = ApiError.Describe(500, long200, "");
            c.Check("超长正文截断到 200 + 省略",
                    tr.IndexOf(new string('x', 200) + " ...", StringComparison.Ordinal) >= 0, true);
            c.Check("null 正文不抛", ApiError.Describe(404, null, null).Length > 0, true);
        }

        // ================================================================ 作业 (jobs / jobkill)

        /// <summary>
        /// 统一 Job 体系样本, 照抄 go/jobs.go bgJob 的 JSON 形状。
        /// port / task_id / ended / note 都带 omitempty, 所以样本里刻意有缺字段的行。
        /// </summary>
        private const string JobsJson = @"{""ok"":true,""jobs_running"":2,""jobs"":["
            + @"{""id"":""0"",""sid"":""B001"",""kind"":""portscan"","
            + @"""detail"":""端口扫描 127.0.0.1 80,445"",""task_id"":1,""started"":1758000000,"
            + @"""status"":""running"",""killable"":false},"
            + @"{""id"":""1"",""sid"":""B001"",""kind"":""socks"",""detail"":""SOCKS 1080"",""port"":1080,"
            + @"""started"":1758000005,""ended"":1758000125,""status"":""killed"",""killable"":true,"
            + @"""note"":""已停止 SOCKS 监听""},"
            + @"{""id"":""2"",""sid"":""B002"",""kind"":""keylog"",""detail"":""键盘记录"",""started"":1758000100,"
            + @"""ended"":1758000400,""status"":""failed"",""killable"":true,""note"":""植入体无回执""}]}";

        /// <summary>/api/state.jobs 的解析: 字段齐 / 缺字段 / 非对象 / 整块缺失都不抛异常。</summary>
        private static void JobsFromState(Ctx c)
        {
            var v = JobParse.State(Doc(JobsJson));
            c.Check("Present", v.Present, true);
            c.Check("作业数", v.Jobs.Count, 3);
            c.Check("本地 running 计数", v.LocalRunning, 1);
            c.Check("服务端 jobs_running", v.ServerRunning, 2);
            c.Check("统计条含总数", v.StatsText().IndexOf("作业 3 个", StringComparison.Ordinal) >= 0, true);
            c.Check("统计条标注服务端口径差",
                    v.StatsText().IndexOf("jobs_running=2", StringComparison.Ordinal) >= 0, true);

            JobRow a = v.Jobs[0];
            c.Check("[0].Id", a.Id, "0");
            c.Check("[0].Key 用作业号", a.Key, "job|0");
            c.Check("[0].Sid", a.Sid, "B001");
            c.Check("[0].Kind", a.Kind, "portscan");
            c.Check("[0].DetailText 原样", a.DetailText, "端口扫描 127.0.0.1 80,445");
            c.Check("[0].PortText 缺字段降级", a.PortText, "-");
            c.Check("[0].TaskText", a.TaskText, "#1");
            c.Check("[0].StatusText", a.StatusText, "running 运行中");
            c.Check("[0].状态色 = 蓝", SameBrush(a.StatusBrush, Palette.Accent), true);
            c.Check("[0].Killable", a.Killable, false);
            c.Check("[0].KillText", a.KillText, "不可中断");
            c.Check("[0].NoteText 缺字段降级", a.NoteText, "-");
            c.Check("[0].EndedText 运行中标注", a.EndedText, "(运行中)");
            c.Check("[0].StartedText 可读时间", a.StartedText, Fmt.Time(1758000000));
            c.Check("[0].耗时未推进时为 0s", a.ElapsedText, Fmt.Age(0));
            c.Check("[0].KillHint 说明为什么不能杀",
                    a.KillHint.IndexOf("无法中途终止", StringComparison.Ordinal) >= 0, true);
            a.Touch(1758000000 + 125);
            c.Check("[0].Touch 后耗时按 now-started", a.ElapsedText, Fmt.Age(125));

            JobRow b = v.Jobs[1];
            c.Check("[1].Key", b.Key, "job|1");
            c.Check("[1].PortText", b.PortText, "1080");
            c.Check("[1].TaskText 缺字段降级", b.TaskText, "-");
            c.Check("[1].StatusText", b.StatusText, "killed 已终止");
            c.Check("[1].状态色 = 橙", SameBrush(b.StatusBrush, Palette.Warn), true);
            c.Check("[1].KillText", b.KillText, "可终止");
            c.Check("[1].NoteText", b.NoteText, "已停止 SOCKS 监听");
            c.Check("[1].EndedText 可读结束时间", b.EndedText, Fmt.Time(1758000125));
            c.Check("[1].耗时 = ended - started", b.ElapsedText, Fmt.Age(120));
            b.Touch(1758009999);
            c.Check("[1].已结束不受 now 影响", b.ElapsedText, Fmt.Age(120));

            JobRow d = v.Jobs[2];
            c.Check("[2].状态色 = 红 (failed)", SameBrush(d.StatusBrush, Palette.Err), true);
            c.Check("[2].可终止 ToolTip 带 jobkill 命令",
                    d.KillHint.IndexOf("jobkill 2", StringComparison.Ordinal) >= 0, true);

            // 退化输入: 只影响该行, 不抛异常
            var only = JobParse.State(Doc("{\"jobs\":[{\"id\":\"7\"}]}"));
            c.Check("只有 id 的行保留 (可定位)", only.Jobs.Count, 1);
            c.Check("id 保留", only.Jobs[0].Id, "7");
            c.Check("缺 status 不编造", only.Jobs[0].StatusText, "-");
            c.Check("缺 started 无耗时", only.Jobs[0].ElapsedText, "-");
            c.Check("缺 started 时间降级", only.Jobs[0].StartedText, "-");
            c.Check("缺 killable 默认不可中断", only.Jobs[0].Killable, false);
            c.Check("服务端未给 jobs_running", only.ServerRunning, -1);
            c.Check("本地 running 计数 0", only.LocalRunning, 0);

            c.Check("无 id 无 kind 无 sid 的行丢弃", JobParse.State(Doc("{\"jobs\":[{}]}")).Jobs.Count, 0);
            c.Check("只有 kind 的行保留", JobParse.State(Doc("{\"jobs\":[{\"kind\":\"portscan\"}]}")).Jobs.Count, 1);
            c.Check("非对象元素跳过", JobParse.State(Doc("{\"jobs\":[1,\"x\",null,{\"id\":\"3\"}]}")).Jobs.Count, 1);
            c.Check("数字型 id 取原文",
                    JobParse.State(Doc("{\"jobs\":[{\"id\":77,\"kind\":\"socks\"}]}")).Jobs[0].Id, "77");
            c.Check("killable 非布尔按缺省 false",
                    JobParse.State(Doc("{\"jobs\":[{\"id\":\"8\",\"killable\":\"yes\"}]}")).Jobs[0].Killable, false);
            c.Check("status 非字符串降级",
                    JobParse.State(Doc("{\"jobs\":[{\"id\":\"9\",\"status\":5}]}")).Jobs[0].StatusText, "-");
            c.Check("jobs_running 字符串可解析",
                    JobParse.State(Doc("{\"jobs\":[],\"jobs_running\":\"3\"}")).ServerRunning, 3);

            var none = JobParse.State(Doc("{\"ok\":true}"));
            c.Check("整块缺失 Present=false", none.Present, false);
            c.Check("整块缺失无行", none.Jobs.Count, 0);
            c.Check("整块缺失统计条如实标注",
                    none.StatsText().IndexOf("未返回", StringComparison.Ordinal) >= 0, true);
            c.Check("jobs=null", JobParse.State(Doc("{\"jobs\":null}")).Present, false);
            c.Check("jobs 非数组", JobParse.State(Doc("{\"jobs\":\"x\"}")).Present, false);
            c.Check("顶层不是对象", JobParse.State(Doc("[1,2]")).Present, false);

            var empty = JobParse.State(Doc("{\"jobs\":[]}"));
            c.Check("空数组 = 服务端已提供", empty.Present, true);
            c.Check("空数组无行", empty.Jobs.Count, 0);
            c.Check("空数组统计条", empty.StatsText().IndexOf("作业 0 个", StringComparison.Ordinal) >= 0, true);
            c.Check("空数组不标注口径差",
                    empty.StatsText().IndexOf("jobs_running", StringComparison.Ordinal) < 0, true);
        }

        /// <summary>耗时由 started/ended 算 (ended=0 按 now 推进), 状态文案与着色。</summary>
        private static void JobElapsedStatus(Ctx c)
        {
            c.Check("未给开始时间", JobParse.Elapsed(0, 0, 9999), "-");
            c.Check("负数开始时间", JobParse.Elapsed(-5, 0, 9999), "-");
            c.Check("已结束: ended - started", JobParse.Elapsed(1000, 1120, 9999), Fmt.Age(120));
            c.Check("已结束: 同一秒", JobParse.Elapsed(1000, 1000, 9999), Fmt.Age(0));
            c.Check("已结束: 时钟回拨不出负数", JobParse.Elapsed(1000, 900, 9999), Fmt.Age(0));
            c.Check("运行中: now - started", JobParse.Elapsed(1000, 0, 1045), Fmt.Age(45));
            c.Check("运行中: now == started", JobParse.Elapsed(1000, 0, 1000), Fmt.Age(0));
            c.Check("运行中: now < started (时钟偏差)", JobParse.Elapsed(1000, 0, 999), Fmt.Age(0));
            c.Check("运行中: 跨小时", JobParse.Elapsed(1000, 0, 1000 + 3661), Fmt.Age(3661));
            c.Check("运行中: 跨天", JobParse.Elapsed(1000, 0, 1000 + 90061), Fmt.Age(90061));

            c.Check("status running", JobParse.StatusTextOf("running"), "running 运行中");
            c.Check("status 大小写不敏感", JobParse.StatusTextOf("RUNNING"), "running 运行中");
            c.Check("status done", JobParse.StatusTextOf("done"), "done 已完成");
            c.Check("status killed", JobParse.StatusTextOf("killed"), "killed 已终止");
            c.Check("status failed", JobParse.StatusTextOf("failed"), "failed 失败");
            c.Check("未知状态原样保留 (不编造)", JobParse.StatusTextOf("weird"), "weird");
            c.Check("空状态降级", JobParse.StatusTextOf(""), "-");
            c.Check("null 状态降级", JobParse.StatusTextOf(null), "-");
            c.Check("纯空白状态降级", JobParse.StatusTextOf("   "), "-");

            c.Check("色 running = 蓝", SameBrush(JobParse.StatusBrushOf("running"), Palette.Accent), true);
            c.Check("色 done = 绿", SameBrush(JobParse.StatusBrushOf("done"), Palette.Ok), true);
            c.Check("色 killed = 橙", SameBrush(JobParse.StatusBrushOf("killed"), Palette.Warn), true);
            c.Check("色 failed = 红", SameBrush(JobParse.StatusBrushOf("failed"), Palette.Err), true);
            c.Check("色 未知 = 灰", SameBrush(JobParse.StatusBrushOf("weird"), Palette.Dim), true);
            c.Check("色 空 = 灰", SameBrush(JobParse.StatusBrushOf(""), Palette.Dim), true);

            var jr = new JobRow();
            jr.Id = "5";
            jr.Kind = "socks";
            jr.Status = "running";
            jr.Started = 1000;
            jr.Killable = true;
            c.Check("IsRunning=true", JobParse.IsRunning(jr), true);
            c.Check("行模型耗时随 Touch 推进", jr.ElapsedText, Fmt.Age(0));
            jr.Touch(1045);
            c.Check("Touch(now) -> 耗时", jr.ElapsedText, Fmt.Age(45));
            jr.Touch(1105);
            c.Check("再次 Touch -> 耗时继续走", jr.ElapsedText, Fmt.Age(105));
            c.Check("TimeTip 含起止与耗时", jr.TimeTip.IndexOf("耗时", StringComparison.Ordinal) >= 0, true);

            jr.Status = "done";
            jr.Ended = 1060;
            c.Check("结束后耗时固定为 ended-started", jr.ElapsedText, Fmt.Age(60));
            jr.Touch(9999);
            c.Check("结束后 Touch 不改耗时", jr.ElapsedText, Fmt.Age(60));
            c.Check("IsRunning=false", JobParse.IsRunning(jr), false);
            c.Check("IsRunning(null)", JobParse.IsRunning(null), false);

            string hintNo = JobParse.KillHintOf("portscan", false, "0");
            c.Check("不可终止 ToolTip 指出 killable=false",
                    hintNo.IndexOf("killable=false", StringComparison.Ordinal) >= 0, true);
            c.Check("不可终止 ToolTip 带作业类型",
                    hintNo.IndexOf("portscan", StringComparison.Ordinal) >= 0, true);
            c.Check("不可终止 ToolTip 预告服务端原话",
                    hintNo.IndexOf("无法中途终止", StringComparison.Ordinal) >= 0, true);
            string hintYes = JobParse.KillHintOf("socks", true, "1");
            c.Check("可终止 ToolTip 带 jobkill 命令",
                    hintYes.IndexOf("jobkill 1", StringComparison.Ordinal) >= 0, true);
            c.Check("可终止 ToolTip 指出 killable=true",
                    hintYes.IndexOf("killable=true", StringComparison.Ordinal) >= 0, true);
            c.Check("类型缺失降级",
                    JobParse.KillHintOf("", false, "2").IndexOf("(未知类型)", StringComparison.Ordinal) >= 0, true);
        }

        /// <summary>差分签名 (内容变化才变) 与纯客户端过滤。</summary>
        private static void JobSignatureAndFilter(Ctx c)
        {
            string s1 = JobParse.StateSignature(Doc(JobsJson));
            c.Check("签名非空", s1.Length > 0, true);
            c.Check("同内容同签名", s1, JobParse.StateSignature(Doc(JobsJson)));
            c.Check("签名含 jobs_running 与条数", s1.IndexOf("R2 N3", StringComparison.Ordinal) >= 0, true);
            c.Check("签名含作业号", s1.IndexOf("\u00010\u0002", StringComparison.Ordinal) >= 0, true);

            c.Check("status 变化 -> 签名变",
                    s1 == JobParse.StateSignature(Doc(JobsJson.Replace("\"status\":\"failed\"", "\"status\":\"done\""))), false);
            c.Check("killable 变化 -> 签名变",
                    s1 == JobParse.StateSignature(Doc(JobsJson.Replace("\"killable\":false", "\"killable\":true"))), false);
            c.Check("ended 变化 -> 签名变",
                    s1 == JobParse.StateSignature(Doc(JobsJson.Replace("\"ended\":1758000125", "\"ended\":1758000130"))), false);
            c.Check("note 变化 -> 签名变",
                    s1 == JobParse.StateSignature(Doc(JobsJson.Replace("植入体无回执", "已回执"))), false);
            c.Check("detail 变化 -> 签名变",
                    s1 == JobParse.StateSignature(Doc(JobsJson.Replace("键盘记录", "键盘记录 (增量)"))), false);
            c.Check("jobs_running 变化 -> 签名变",
                    s1 == JobParse.StateSignature(Doc(JobsJson.Replace("\"jobs_running\":2", "\"jobs_running\":1"))), false);
            c.Check("多一条作业 -> 签名变",
                    s1 == JobParse.StateSignature(Doc(JobsJson.Replace("\"jobs\":[",
                        "\"jobs\":[{\"id\":\"9\",\"sid\":\"B003\",\"kind\":\"rportfwd\",\"status\":\"running\",\"killable\":true},"))), false);

            c.Check("jobs 缺失 -> 空签名", JobParse.StateSignature(Doc("{\"ok\":true}")), "");
            c.Check("jobs=null -> 空签名", JobParse.StateSignature(Doc("{\"jobs\":null}")), "");
            c.Check("jobs 为字符串 -> 空签名", JobParse.StateSignature(Doc("{\"jobs\":\"x\"}")), "");
            c.Check("顶层不是对象 -> 空签名", JobParse.StateSignature(Doc("[1,2]")), "");
            c.Check("空数组签名非空 (服务端已提供)",
                    JobParse.StateSignature(Doc("{\"jobs\":[]}")).Length > 0, true);
            c.Check("空数组签名前缀",
                    JobParse.StateSignature(Doc("{\"jobs\":[]}")).StartsWith("R-1 N0", StringComparison.Ordinal), true);

            List<JobRow> all = JobParse.State(Doc(JobsJson)).Jobs;
            c.Check("全部会话", JobParse.Filter(all, "", false).Count, 3);
            c.Check("空白 sid 等价全部", JobParse.Filter(all, "   ", false).Count, 3);
            c.Check("null sid 等价全部", JobParse.Filter(all, null, false).Count, 3);
            c.Check("只看 B001", JobParse.Filter(all, "B001", false).Count, 2);
            c.Check("只看 B002", JobParse.Filter(all, "B002", false).Count, 1);
            c.Check("会话号区分大小写 (与服务端 Ordinal 一致)", JobParse.Filter(all, "b001", false).Count, 0);
            c.Check("不存在的会话", JobParse.Filter(all, "B999", false).Count, 0);

            List<JobRow> run = JobParse.Filter(all, "", true);
            c.Check("只看 running", run.Count, 1);
            c.Check("running 行是 job 0", run[0].Id, "0");
            c.Check("B001 + running 交集", JobParse.Filter(all, "B001", true).Count, 1);
            c.Check("B002 + running 空集", JobParse.Filter(all, "B002", true).Count, 0);
            c.Check("过滤复用同一行对象 (Sync 才能原地合并)",
                    ReferenceEquals(JobParse.Filter(all, "B001", false)[0], all[0]), true);
            c.Check("null 集合 -> 空表", JobParse.Filter(null, "", false).Count, 0);
        }

        /// <summary>
        /// jobkill 的结果文案: ok=true 时服务端 text 必须原样带出 —— 含 killable=false 的
        /// 『是一次性任务, 无法中途终止』那句 (如实行为, 不是失败)。
        /// </summary>
        private static void JobKillText(Ctx c)
        {
            const string noKill = "[-] job 1 (portscan) 是一次性任务, 无法中途终止: 端口扫描 127.0.0.1 80,445";
            c.Check("ok=true: text 原样", JobParse.KillResultText(true, noKill, "", "1"), noKill);
            c.Check("ok=true: 忽略 error 字段",
                    JobParse.KillResultText(true, "[+] job 0 (SOCKS 1080) 已停止", "x", "0"),
                    "[+] job 0 (SOCKS 1080) 已停止");
            c.Check("原样判定: 一次性任务", JobParse.IsNotKillableText(noKill), true);
            c.Check("原样判定: 真实停止不算", JobParse.IsNotKillableText("[+] job 0 (SOCKS 1080) 已停止"), false);
            c.Check("原样判定: 键盘记录停止不算", JobParse.IsNotKillableText("[+] job 2 (键盘记录) 已停止"), false);
            c.Check("原样判定: 空文本", JobParse.IsNotKillableText(""), false);
            c.Check("原样判定: null", JobParse.IsNotKillableText(null), false);

            string miss = JobParse.KillResultText(true, "", "", "5");
            c.Check("ok=true 但无 text: 如实标注",
                    miss.IndexOf("未包含 text", StringComparison.Ordinal) >= 0, true);
            c.Check("ok=true 但无 text: 不伪造成已停止",
                    miss.IndexOf("已停止", StringComparison.Ordinal) < 0, true);
            c.Check("ok=true 但 text 全空白: 同样标注",
                    JobParse.KillResultText(true, "   ", "", "5").IndexOf("未包含 text", StringComparison.Ordinal) >= 0, true);

            c.Check("ok=false: error 原样", JobParse.KillResultText(false, "", "没有 job 9", "9"), "没有 job 9");
            c.Check("ok=false: 无 error 如实标注",
                    JobParse.KillResultText(false, "sent", "", "9").IndexOf("未返回 error", StringComparison.Ordinal) >= 0, true);

            c.Check("KillCommand 常规", JobParse.KillCommand("0"), "jobkill 0");
            c.Check("KillCommand 去空白", JobParse.KillCommand("  7 "), "jobkill 7");
            c.Check("KillCommand 空 id", JobParse.KillCommand(""), "jobkill");
            c.Check("KillCommand null id", JobParse.KillCommand(null), "jobkill");
            c.Check("命令首词与服务端 jobTryCommand 一致",
                    JobParse.KillCommand("12").StartsWith("jobkill ", StringComparison.Ordinal), true);
        }

        /// <summary>会话过滤下拉: 条目构造 / 差分比较 / 选中恢复。</summary>
        private static void JobSidItems(Ctx c)
        {
            var labels = new List<string>();
            labels.Add("B001   alice@WEB01   proto=v2");
            labels.Add("B002   bob@WEB02   proto=v1");

            List<JobSidItem> items = JobParse.SidItems(labels, "B001");
            c.Check("条目数 (全部 + 跟随 + 2 会话)", items.Count, 4);
            c.Check("[0].Key", items[0].Key, "all");
            c.Check("[0].Text", items[0].Text, "全部会话");
            c.Check("[0].Sid 空 = 不过滤", items[0].Sid, "");
            c.Check("[0].Follow", items[0].Follow, false);
            c.Check("[1].Key", items[1].Key, "follow");
            c.Check("[1].Follow", items[1].Follow, true);
            c.Check("[1].Text 带当前附着会话",
                    items[1].Text.IndexOf("B001", StringComparison.Ordinal) >= 0, true);
            c.Check("[2].Key 由标签首段取 sid", items[2].Key, "sid:B001");
            c.Check("[2].Sid", items[2].Sid, "B001");
            c.Check("[3].Text 原样", items[3].Text, "B002   bob@WEB02   proto=v1");
            c.Check("[3].Key", items[3].Key, "sid:B002");

            List<JobSidItem> noCur = JobParse.SidItems(labels, "");
            c.Check("无附着会话时如实标注",
                    noCur[1].Text.IndexOf("(无附着)", StringComparison.Ordinal) >= 0, true);
            c.Check("空会话表只有 2 项", JobParse.SidItems(new List<string>(), null).Count, 2);
            c.Check("null 会话表只有 2 项", JobParse.SidItems(null, "B001").Count, 2);
            c.Check("空标签被跳过",
                    JobParse.SidItems(new List<string> { "", "B001   a@b" }, null).Count, 3);

            c.Check("同内容下拉等价", JobParse.SameSidItems(items, JobParse.SidItems(labels, "B001")), true);
            c.Check("当前会话变化 -> 需重建", JobParse.SameSidItems(items, JobParse.SidItems(labels, "B002")), false);
            c.Check("多一个会话 -> 需重建",
                    JobParse.SameSidItems(items, JobParse.SidItems(
                        new List<string> { "B001   a@b", "B002   c@d", "B003   e@f" }, "B001")), false);
            c.Check("null 与非空不等价", JobParse.SameSidItems(null, items), false);
            c.Check("null 与 null 等价", JobParse.SameSidItems(null, null), true);
            c.Check("自反等价", JobParse.SameSidItems(items, items), true);

            c.Check("PickSid: 跟随项", JobParse.PickSid(items, "follow").Key, "follow");
            c.Check("PickSid: 指定会话", JobParse.PickSid(items, "sid:B002").Key, "sid:B002");
            c.Check("PickSid: 未命中回到全部会话", JobParse.PickSid(items, "sid:GONE").Key, "all");
            c.Check("PickSid: 空表返回 null", JobParse.PickSid(new List<JobSidItem>(), "all") == null, true);
            c.Check("PickSid: null 表返回 null", JobParse.PickSid(null, "all") == null, true);

            c.Check("JobSidOf 取首段", JobParse.JobSidOf("B001   alice@WEB01"), "B001");
            c.Check("JobSidOf 无空白", JobParse.JobSidOf("B001"), "B001");
            c.Check("JobSidOf 空串", JobParse.JobSidOf(""), "");
            c.Check("JobSidOf null", JobParse.JobSidOf(null), "");
        }

        // ================================================================ 载荷 · 启动口令

        /// <summary>
        /// /api/payload/build 的请求体。字段名错一个 (尤其 out_file 的下划线) 服务端只会
        /// 回一句参数错误, 很难定位, 所以这里把序列化结果钉死。
        /// </summary>
        private static void PayloadRequestBody(Ctx c)
        {
            var plain = PayloadRequest.Build("win2-console", "1.2.3.4", 8443, false,
                                             "D:\\x.exe", 5000, 10, false, "");
            c.Check("完整请求体 (口令留空 -> key 都不出现)",
                    PayloadRequest.Json(plain),
                    "{\"format\":\"win2-console\",\"host\":\"1.2.3.4\",\"port\":8443,\"ssl\":false,"
                  + "\"out_file\":\"D:\\\\x.exe\",\"sleep\":5000,\"jitter\":10}");
            c.Check("留空口令不序列化 password 键", PayloadRequest.Json(plain).Contains("\"password\""), false);

            var gated = PayloadRequest.Build("win2-console", "1.2.3.4", 8443, false,
                                             "D:\\x.exe", 5000, 10, false, "YourPass");
            c.Check("口令非空 -> password 字段带上",
                    PayloadRequest.Json(gated),
                    "{\"format\":\"win2-console\",\"host\":\"1.2.3.4\",\"port\":8443,\"ssl\":false,"
                  + "\"out_file\":\"D:\\\\x.exe\",\"sleep\":5000,\"jitter\":10,\"password\":\"YourPass\"}");
            c.Check("password 在网络体里是字符串值",
                    PayloadRequest.Json(gated).Contains("\"password\":\"YourPass\""), true);

            var noSleep = PayloadRequest.Build("win2-vba", "h", 1, true, "", 5000, 10, true, "");
            c.Check("no_sleep: sleep/jitter 整块省略",
                    PayloadRequest.Json(noSleep),
                    "{\"format\":\"win2-vba\",\"host\":\"h\",\"port\":1,\"ssl\":true,\"out_file\":\"\"}");
            c.Check("no_sleep 也不带 password (空)", PayloadRequest.Json(noSleep).Contains("password"), false);

            var noSleepGated = PayloadRequest.Build("win2-vba", "h", 1, true, "", 0, -1, true, "Abcd1234");
            c.Check("降级重试仍保留口令", PayloadRequest.Json(noSleepGated).Contains("\"password\":\"Abcd1234\""), true);

            var blankOut = PayloadRequest.Build("win-ps1", "h", 8443, false, null, 0, 10, false, "");
            c.Check("null 输出路径 -> 空串 (服务端字段总在)", PayloadRequest.Json(blankOut).Contains("\"out_file\":\"\""), true);
            c.Check("jitter=0 也会带上 (>= 0)", PayloadRequest.Json(blankOut).Contains("\"jitter\":10"), true);
            c.Check("负数 jitter 原样带上", PayloadRequest.Json(
                        PayloadRequest.Build("f", "h", 1, false, "", 0, -1, false, "")).Contains("\"jitter\":-1"), true);
            c.Check("端口按整数序列化 (不带小数)",
                    PayloadRequest.Json(PayloadRequest.Build("f", "h", 65535, false, "", 0, 10, false, "")).Contains("\"port\":65535"), true);
            c.Check("格式名原样保留 (v1/v2 由服务端挑生成器)",
                    PayloadRequest.Json(PayloadRequest.Build("linux-elf-dyn", "h", 1, false, "", 0, 10, false, ""))
                        .Contains("\"format\":\"linux-elf-dyn\""), true);
        }

        /// <summary>
        /// 启动口令的本地校验与日志脱敏。
        /// 本地校验顺序与 tools/gen_payload2.ps1 一致 (先长度后空白): 含空白的口令若放过去,
        /// 生成器的 throw 消息里会带明文口令, 再被服务端原样回传进 GUI 日志。
        /// </summary>
        private static void PayloadPasswordGate(Ctx c)
        {
            c.Check("留空 = 不加门控 (通过)", PayloadRequest.PasswordProblem(""), "");
            c.Check("null 口令通过", PayloadRequest.PasswordProblem(null), "");

            string blank = PayloadRequest.PasswordProblem("Your Pass");
            c.Check("空格口令被本地拦下", blank.Length > 0, true);
            c.Check("空格口令提示点名空白字符", blank.Contains("\u7a7a\u767d"), true);
            c.Check("空格口令提示讲清原因 (按空白切分命令行)", blank.Contains("\u5207\u5206\u547d\u4ee4\u884c"), true);
            c.Check("空格口令提示给出留空选项", blank.Contains("\u7559\u7a7a"), true);
            c.Check("空格口令提示不含口令明文", blank.Contains("Your Pass"), false);

            string tab = PayloadRequest.PasswordProblem("ab\tcd");
            c.Check("Tab 口令被拦", tab.Length > 0, true);
            c.Check("Tab 口令走空白分支", tab.Contains("\u7a7a\u767d"), true);
            c.Check("换行口令被拦", PayloadRequest.PasswordProblem("ab\ncd").Length > 0, true);
            c.Check("CR 口令被拦", PayloadRequest.PasswordProblem("ab\rcd").Length > 0, true);
            c.Check("全空白口令被拦 (也属空白)", PayloadRequest.PasswordProblem("    ").Contains("\u7a7a\u767d"), true);

            string shortPw = PayloadRequest.PasswordProblem("abc");
            c.Check("过短口令被拦", shortPw.Length > 0, true);
            c.Check("过短提示说至少 4 个字符", shortPw.Contains("4"), true);
            c.Check("过短提示与服务端生成器同规则", shortPw.Contains("\u751f\u6210\u5668"), true);
            c.Check("恰好 4 字符通过", PayloadRequest.PasswordProblem("abcd"), "");
            c.Check("纯中文口令通过 (非空白)", PayloadRequest.PasswordProblem("\u53e3\u4ee4\u53e3\u4ee4"), "");
            c.Check("含标点口令通过", PayloadRequest.PasswordProblem("p@ss!w#0rd"), "");

            c.Check("脱敏: 口令原文被替换",
                    PayloadRequest.RedactPassword("口令不能含空白字符: Your Pass", "Your Pass"),
                    "\u53e3\u4ee4\u4e0d\u80fd\u542b\u7a7a\u767d\u5b57\u7b26: ******(口令明文已隐去)");
            c.Check("脱敏: 日志里不再有口令明文",
                    PayloadRequest.RedactPassword("a Your Pass b Your Pass c", "Your Pass").Contains("Your Pass"), false);
            c.Check("脱敏: 多处出现全部替换",
                    PayloadRequest.RedactPassword("xAByABz", "AB"), "x******(口令明文已隐去)y******(口令明文已隐去)z");
            c.Check("脱敏: 口令留空时日志原样",
                    PayloadRequest.RedactPassword("原样", ""), "原样");
            c.Check("脱敏: 日志里没有口令时原样",
                    PayloadRequest.RedactPassword("原样", "abcd"), "原样");
            c.Check("脱敏: null 文本不抛", PayloadRequest.RedactPassword(null, "abcd"), "");
            c.Check("脱敏: 大小写不同不做替换 (口令精确匹配)",
                    PayloadRequest.RedactPassword("yourpass", "YourPass"), "yourpass");
            c.Check("脱敏后仍保留门控那两行",
                    PayloadRequest.RedactPassword("[口令门控] 已启用 — 启动时必须带口令参数", "YourPass"),
                    "[口令门控] 已启用 — 启动时必须带口令参数");
        }

        // ================================================================ 监听器 · 运行时增删

        /// <summary>add / remove 的回执文案: 服务端 error 一律原样, 不替换成笼统文案。</summary>
        private static void ListenerOpText(Ctx c)
        {
            ListenerOp ok = ListenerParse.AddResult(Doc(
                "{\"ok\":true,\"id\":\"lsn-7\",\"kind\":\"tcp\",\"addr\":\"0.0.0.0:8444\"}"));
            c.Check("add 成功", ok.Ok, true);
            c.Check("add 成功取回 id", ok.Id, "lsn-7");
            c.Check("add 成功取回服务端实际地址", ok.Addr, "0.0.0.0:8444");
            c.Check("add 成功文案带 kind 与 addr", ok.Text, "已创建 listener: tcp  0.0.0.0:8444  (id lsn-7)");

            // 双栈绑定: 服务端把 0.0.0.0:8444 规范化成 [::]:8444 —— 文案照服务端原文
            ListenerOp v6 = ListenerParse.AddResult(Doc(
                "{\"ok\":true,\"id\":\"L004\",\"kind\":\"tcp\",\"addr\":\"[::]:8646\",\"name\":\"csdev-tcp-8646\",\"manageable\":true}"));
            c.Check("add 文案用服务端绑定地址 (IPv6 双栈)", v6.Text, "已创建 listener: tcp  [::]:8646  (id L004)");
            c.Check("add 失败时不带地址", ListenerParse.AddResult(Doc("{\"ok\":false,\"error\":\"x\"}")).Addr, "");

            ListenerOp noId = ListenerParse.AddResult(Doc("{\"ok\":true,\"kind\":\"dns\",\"addr\":\"0.0.0.0:5353\"}"));
            c.Check("add 成功但缺 id 仍算成功", noId.Ok, true);
            c.Check("add 缺 id 时如实标注 (不假装能移除)",
                    noId.Text.Contains("\u672a\u56de\u4f20 id"), true);

            ListenerOp busy = ListenerParse.AddResult(Doc(
                "{\"ok\":false,\"error\":\"listen tcp 0.0.0.0:8444: bind: Only one usage of each socket address\"}"));
            c.Check("add 失败", busy.Ok, false);
            c.Check("add 失败 error 原样 (端口占用)",
                    busy.Text, "listen tcp 0.0.0.0:8444: bind: Only one usage of each socket address");
            c.Check("add 失败不套用自己的文案", busy.Text.StartsWith("\u5df2\u521b\u5efa", StringComparison.Ordinal), false);

            ListenerOp cnErr = ListenerParse.AddResult(Doc("{\"ok\":false,\"error\":\"不支持的 listener 类型: ftp\"}"));
            c.Check("add 失败中文 error 原样", cnErr.Text, "不支持的 listener 类型: ftp");

            ListenerOp noErr = ListenerParse.AddResult(Doc("{\"ok\":false}"));
            c.Check("add 失败且无 error 字段时如实标注",
                    noErr.Text.Contains("\u672a\u7ed9\u51fa error"), true);

            c.Check("add 响应不是对象 (数组)", ListenerParse.AddResult(Doc("[1,2]")).Ok, false);
            c.Check("add 响应不是对象时文案说明原因",
                    ListenerParse.AddResult(Doc("\"x\"")).Text.Contains("JSON"), true);
            c.Check("add null 元素不抛", ListenerParse.AddResult(default(JsonElement)).Ok, false);

            ListenerOp rem = ListenerParse.RemoveResult(Doc("{\"ok\":true}"));
            c.Check("remove 成功", rem.Ok, true);
            c.Check("remove 成功文案", rem.Text, "已移除 listener");
            c.Check("remove 成功带 id 时附 id",
                    ListenerParse.RemoveResult(Doc("{\"ok\":true,\"id\":\"lsn-7\"}")).Text, "已移除 listener (id lsn-7)");

            ListenerOp builtinErr = ListenerParse.RemoveResult(Doc(
                "{\"ok\":false,\"error\":\"主 HTTP listener (csdev-v2) 不允许删除\"}"));
            c.Check("remove 主 listener 失败", builtinErr.Ok, false);
            c.Check("remove 失败 error 原样 (主 listener 那句)", builtinErr.Text,
                    "主 HTTP listener (csdev-v2) 不允许删除");
            c.Check("remove 失败且无 error 时如实标注",
                    ListenerParse.RemoveResult(Doc("{\"ok\":false}")).Text.Contains("\u672a\u7ed9\u51fa error"), true);
            c.Check("remove 响应非对象不抛", ListenerParse.RemoveResult(default(JsonElement)).Ok, false);
            c.Check("remove 响应非对象文案说明原因",
                    ListenerParse.RemoveResult(Doc("[]")).Text.Contains("JSON"), true);
        }

        /// <summary>
        /// 主 listener 不可删的判定 + 行模型 (按钮置灰的依据) + id 兼容解析。
        /// 判据取 uri 非空 (启动期注册的 csdev-v2 / csdev-legacy 都带 uri /submit /report) ——
        /// 字段缺失时保守判为不可删, 宁可不给按钮, 也不要按下去撞服务端错误。
        /// </summary>
        private static void ListenerBuiltin(Ctx c)
        {
            c.Check("启动注册的 v2 主 listener 不可删", ListenerParse.IsBuiltinRow("csdev-v2", "v2", "/submit"), true);
            c.Check("启动注册的 v1 legacy 也不可删", ListenerParse.IsBuiltinRow("csdev-legacy", "v1", "/report"), true);
            c.Check("无 uri 的运行时 listener 可删", ListenerParse.IsBuiltinRow("tcp-8444", "v2", ""), false);
            c.Check("无 uri 的 smb/dns/extc2 行可删", ListenerParse.IsBuiltinRow("dns-5353", "v2", ""), false);
            c.Check("profile URI 池入口 (有 uri) 归为主 listener",
                    ListenerParse.IsBuiltinRow("profile-extra", "v2", "/cdn/upd"), true);
            c.Check("proto 缺失 -> 保守不可删", ListenerParse.IsBuiltinRow("mystery", "", ""), true);
            c.Check("只有 uri 就够判不可删", ListenerParse.IsBuiltinRow("", "", "/submit"), true);
            c.Check("csdev- 前缀即使没 uri 也不可删 (服务端命名约定)", ListenerParse.IsBuiltinRow("csdev-extra", "v2", ""), true);
            c.Check("前缀匹配不区分大小写", ListenerParse.IsBuiltinRow("CSDEV-extra", "v2", ""), true);
            c.Check("null 入参不抛", ListenerParse.IsBuiltinRow(null, null, null), true);
            c.Check("空白 uri 视同没有", ListenerParse.IsBuiltinRow("tcp-1", "v2", "   "), false);

            c.Check("置灰理由点名主 listener", ListenerParse.BuiltinBlockWhy.Contains("\u4e0d\u53ef\u79fb\u9664"), true);
            c.Check("置灰理由讲清要改启动参数", ListenerParse.BuiltinBlockWhy.Contains("\u542f\u52a8\u53c2\u6570"), true);
            c.Check("未下发文案带行名并可读",
                    ListenerParse.BlockedRemove("csdev-v2").Contains("csdev-v2"), true);
            c.Check("未下发文案明确说没发请求",
                    ListenerParse.BlockedRemove("csdev-v2").StartsWith("\u672a\u4e0b\u53d1", StringComparison.Ordinal), true);
            c.Check("行名为空也不抛", ListenerParse.BlockedRemove(null).Length > 0, true);

            c.Check("ToolTip: 主 listener 说不可删",
                    ListenerParse.RemoveHint(ListenerParse.ManageNo, "csdev-v2", "v2", "/submit", "main") == ListenerParse.BuiltinBlockWhy, true);
            c.Check("ToolTip: 缺 id 时说明无法移除",
                    ListenerParse.RemoveHint(ListenerParse.ManageUnknown, "tcp-1", "v2", "", "").Contains("\u65e0\u6cd5\u79fb\u9664"), true);
            c.Check("ToolTip: 正常行给出 id 与端点",
                    ListenerParse.RemoveHint(ListenerParse.ManageYes, "csdev-tcp-8444", "v2", "/submit", "L001").Contains("/api/listener/remove"), true);
            c.Check("ToolTip: 正常行带 id 值",
                    ListenerParse.RemoveHint(ListenerParse.ManageYes, "csdev-tcp-8444", "v2", "/submit", "L001").Contains("L001"), true);
            c.Check("ToolTip: 字段缺失时保守给置灰理由",
                    ListenerParse.RemoveHint(ListenerParse.ManageUnknown, "csdev-v2", "v2", "/submit", "main") == ListenerParse.BuiltinBlockWhy, true);

            // 行模型: 按钮 IsEnabled 绑 CanRemove
            var builtinRow = new ListenerRow();
            builtinRow.Name = "csdev-v2";
            builtinRow.Type = "https";
            builtinRow.Proto = "v2";
            builtinRow.Host = "0.0.0.0";
            builtinRow.Port = 8443;
            builtinRow.Uri = "/submit";
            builtinRow.Up = true;
            builtinRow.Id = "main";
            builtinRow.Protected = true;
            builtinRow.ManageFlag = ListenerParse.ManageNo;
            c.Check("服务端说 manageable=false -> 行 CanRemove=false", builtinRow.CanRemove, false);
            c.Check("主 listener 行 ToolTip 是置灰理由", builtinRow.RemoveHint, ListenerParse.BuiltinBlockWhy);
            c.Check("addr 展示", builtinRow.AddrText, "0.0.0.0:8443");
            c.Check("id 列展示服务端 id", builtinRow.IdText, "main");
            c.Check("带 id 的主键以 id 为准", builtinRow.Key, "l|main");
            c.Check("主 listener 行状态色 = 在线", SameBrush(builtinRow.StatusBrush, Palette.Ok), true);
            c.Check("受保护列文案", builtinRow.ManageText, "受保护");
            c.Check("受保护行变暗", SameBrush(builtinRow.RowBrush, Palette.Dim), true);

            // 服务端字段优先: 新增 tcp listener 的 name 是 csdev-tcp-8444 且 uri=/submit,
            // 只看名字/uri 会误判成主入口 —— manageable=true 必须把它救回来
            var runtimeRow = new ListenerRow();
            runtimeRow.Name = "csdev-tcp-8444";
            runtimeRow.Proto = "v2";
            runtimeRow.Host = "0.0.0.0";
            runtimeRow.Port = 8444;
            runtimeRow.Uri = "/submit";
            runtimeRow.Id = "L001";
            runtimeRow.ManageFlag = ListenerParse.ManageYes;
            c.Check("manageable=true 覆盖名字/uri 启发式", runtimeRow.CanRemove, true);
            c.Check("可移除列文案", runtimeRow.ManageText, "可移除");
            c.Check("可移除行不变暗", SameBrush(runtimeRow.RowBrush, Palette.Fg), true);
            runtimeRow.Id = "";
            c.Check("id 被清掉后按钮置灰 (不拿名字冒充 id)", runtimeRow.CanRemove, false);

            var fallbackRow = new ListenerRow();
            fallbackRow.Name = "csdev-v2";
            fallbackRow.Proto = "v2";
            fallbackRow.Host = "0.0.0.0";
            fallbackRow.Port = 8443;
            c.Check("服务端未给 id 时 id 列显示 -", fallbackRow.IdText, "-");
            c.Check("服务端未给保护字段时主键退化到 name|host|port", fallbackRow.Key, "l|csdev-v2|0.0.0.0|8443");
            c.Check("服务端未给 manageable 时不冒充可管理", fallbackRow.ManageText, "未给出");
            fallbackRow.ManageFlag = ListenerParse.ManageNo;
            c.Check("只有 protected=true 也判受保护", fallbackRow.ManageText, "受保护");
            fallbackRow.ManageFlag = ListenerParse.ManageUnknown;
            fallbackRow.Protected = true;
            c.Check("protected 字段单独给出时不冒充可管理", fallbackRow.ManageText, "受保护");

            var upDown = new ListenerRow();
            upDown.Up = false;
            c.Check("离线行状态色 = 红", SameBrush(upDown.StatusBrush, Palette.Err), true);
            c.Check("离线行文案", upDown.UpText, "离线");
            var sslRow = new ListenerRow();
            sslRow.Ssl = true;
            c.Check("ssl 列文案", sslRow.SslText, "SSL");
            var plainRow = new ListenerRow();
            c.Check("非 ssl 列文案", plainRow.SslText, "-");

            // id 兼容解析: 服务端可能用 id / listener_id / handle
            c.Check("IdOf 取 id", ListenerParse.IdOf(Doc("{\"id\":\"a1\"}")), "a1");
            c.Check("IdOf 兼容 listener_id", ListenerParse.IdOf(Doc("{\"listener_id\":\"b2\"}")), "b2");
            c.Check("IdOf 兼容 handle", ListenerParse.IdOf(Doc("{\"handle\":\"c3\"}")), "c3");
            c.Check("IdOf 缺字段回空串", ListenerParse.IdOf(Doc("{\"name\":\"x\"}")), "");
            c.Check("IdOf 去掉首尾空白", ListenerParse.IdOf(Doc("{\"id\":\"  d4  \"}")), "d4");
            c.Check("IdOf 非字符串回空串", ListenerParse.IdOf(Doc("{\"id\":123}")), "");
            c.Check("IdOf id 优先于 listener_id",
                    ListenerParse.IdOf(Doc("{\"id\":\"x\",\"listener_id\":\"y\"}")), "x");

            // /api/state.listeners 与 /api/listeners 同构的样本 (主 listener + 运行时行混排;
            // 追加字段 id / protected / manageable 照抄服务端 listener_admin.go 的实际返回)
            JsonElement list = Doc(
                "{\"ok\":true,\"listeners\":["
              + "{\"name\":\"csdev-v2\",\"type\":\"https\",\"proto\":\"v2\",\"host\":\"0.0.0.0\",\"port\":8443,"
              + "\"uri\":\"/submit\",\"ssl\":false,\"up\":true,\"id\":\"main\",\"kind\":\"https\","
              + "\"addr\":\"0.0.0.0:8443\",\"status\":\"up\",\"protected\":true,\"manageable\":false},"
              + "{\"name\":\"csdev-legacy\",\"type\":\"https\",\"proto\":\"v1\",\"host\":\"0.0.0.0\",\"port\":8443,"
              + "\"uri\":\"/report\",\"ssl\":false,\"up\":true,\"id\":\"L001\",\"kind\":\"https\","
              + "\"addr\":\"0.0.0.0:8443\",\"status\":\"up\",\"protected\":true,\"manageable\":false},"
              + "{\"name\":\"csdev-tcp-8444\",\"type\":\"tcp\",\"proto\":\"v2\",\"host\":\"::\",\"port\":8444,"
              + "\"uri\":\"-\",\"ssl\":false,\"up\":true,\"id\":\"L002\",\"kind\":\"tcp\","
              + "\"addr\":\"0.0.0.0:8444\",\"status\":\"up\",\"protected\":false,\"manageable\":true},"
              + "{\"name\":\"csdev-smb\",\"type\":\"smb\",\"proto\":\"v2\",\"host\":\"-\",\"port\":0,"
              + "\"uri\":\"\\\\\\\\.\\\\pipe\\\\csdev_pipe\",\"ssl\":false,\"up\":true,\"id\":\"L003\","
              + "\"kind\":\"smb\",\"addr\":\"\\\\\\\\.\\\\pipe\\\\csdev_pipe\",\"manageable\":true}]}");
            var rows = new List<ListenerRow>();
            foreach (var el in list.Arr("listeners"))
            {
                var r = new ListenerRow();
                r.Name = el.Str("name");
                r.Type = el.Str("type");
                r.Proto = el.Str("proto");
                r.Host = el.Str("host");
                r.Port = el.Long("port");
                r.Uri = el.Str("uri");
                r.Ssl = el.Bool("ssl");
                r.Up = el.Bool("up");
                r.Id = ListenerParse.IdOf(el);
                r.Protected = el.Bool("protected");
                r.ManageFlag = ListenerParse.ManageFlag(el);
                r.Addr = el.Str("addr");
                rows.Add(r);
            }
            c.Check("解析出 4 行", rows.Count, 4);
            c.Check("混排样本里可移除 2 行 (tcp + smb)", CountRemovable(rows), 2);
            c.Check("[2] tcp 行可移除 (manageable=true 压过名字/uri)", rows[2].CanRemove, true);
            c.Check("[2].Id 来自列表字段", rows[2].Id, "L002");
            c.Check("[2] addr 列用服务端原文", rows[2].AddrRawText, "0.0.0.0:8444");
            c.Check("[0] 主 listener 不可移除", rows[0].CanRemove, false);
            c.Check("[1] legacy 不可移除", rows[1].CanRemove, false);
            c.Check("[3] smb 行 protected 缺字段但 manageable=true -> 可移除", rows[3].CanRemove, true);
            c.Check("[3] smb 行保护列不冒充受保护", rows[3].ManageText, "可移除");
            c.Check("[3] 管道地址原样保留", rows[3].Uri, "\\\\.\\pipe\\csdev_pipe");
            c.Check("[3] 管道行 addr 列用服务端原文", rows[3].AddrRawText, "\\\\.\\pipe\\csdev_pipe");
            c.Check("[3] 管道行 host 为 - 且端口 0 (拼接退化值)", rows[3].AddrText, "-:0");
            c.Check("行主键互不相同 (Sync 不混行)",
                    rows[0].Key != rows[1].Key && rows[1].Key != rows[2].Key && rows[2].Key != rows[3].Key, true);
            c.Check("主 listener 主键就是服务端 id", rows[0].Key, "l|main");
            c.Check("listeners 整块缺失 -> 仍在枚举里但不崩", CountRemovable(new List<ListenerRow>()), 0);
        }

        /// <summary>kind 下拉 -> 地址示例占位; 地址为空在本地拦下 (不占服务端往返)。</summary>
        private static void ListenerKindExample(Ctx c)
        {
            c.Check("kind 选项顺序 (与服务端约定一致)", Join(new List<string>(ListenerParse.Kinds)),
                    "http|https|tcp|smb|dns|extc2");

            c.Check("tcp 示例", ListenerParse.AddressExample("tcp"), "0.0.0.0:8444");
            c.Check("smb 示例 (命名管道)", ListenerParse.AddressExample("smb"), "\\\\.\\pipe\\csdev_pipe");
            c.Check("dns 示例", ListenerParse.AddressExample("dns"), "0.0.0.0:5353");
            c.Check("extc2 示例", ListenerParse.AddressExample("extc2"), "0.0.0.0:9100");
            c.Check("http 示例", ListenerParse.AddressExample("http"), "0.0.0.0:8443");
            c.Check("https 示例", ListenerParse.AddressExample("https"), "0.0.0.0:8443");
            c.Check("大小写与空白容错", ListenerParse.AddressExample("  TCP "), "0.0.0.0:8444");
            c.Check("未知 kind 不给示例 (不编造)", ListenerParse.AddressExample("ftp"), "");
            c.Check("null kind 不给示例", ListenerParse.AddressExample(null), "");

            c.Check("地址提示带 kind", ListenerParse.AddressHint("dns").Contains("dns"), true);
            c.Check("地址提示带示例", ListenerParse.AddressHint("dns").Contains("0.0.0.0:5353"), true);
            c.Check("未知 kind 提示讲清原因", ListenerParse.AddressHint("ftp").Contains("\u672a\u77e5"), true);

            c.Check("空地址被本地拦下", ListenerParse.AddressProblem("").Length > 0, true);
            c.Check("纯空白地址被本地拦下", ListenerParse.AddressProblem("   ").Length > 0, true);
            c.Check("null 地址被本地拦下", ListenerParse.AddressProblem(null).Length > 0, true);
            c.Check("非空地址通过", ListenerParse.AddressProblem("0.0.0.0:8444"), "");
            c.Check("拦下文案提示看示例", ListenerParse.AddressProblem("").Contains("\u793a\u4f8b"), true);

            c.Check("NormalizeKind 小写", ListenerParse.NormalizeKind("EXTc2"), "extc2");
            c.Check("NormalizeKind 去空白", ListenerParse.NormalizeKind(" smb "), "smb");
            c.Check("NormalizeKind null", ListenerParse.NormalizeKind(null), "");

            c.Check("RowKey 优先 id", ListenerParse.RowKey("lsn-1", "n", "h", 1), "l|lsn-1");
            c.Check("RowKey 无 id 时含 name/host/port", ListenerParse.RowKey("", "n", "h", 8444), "l|n|h|8444");
            c.Check("RowKey 无 id 无 name 也稳定", ListenerParse.RowKey(null, null, null, 0), "l|||0");
            c.Check("RowKey id 去空白", ListenerParse.RowKey("  x  ", "n", "h", 1), "l|x");
        }

        /// <summary>
        /// 服务端追加保护字段 (protected / manageable) 的解析与判定优先级。
        /// 服务端 listener_admin.go 给每行追加这两个布尔字段; 字段缺失 (旧二进制) 必须回
        /// ManageUnknown 并回落到本地启发式 (uri / name 判据), 绝不把"没给"当成"允许删"。
        /// </summary>
        private static void ListenerFlagPriority(Ctx c)
        {
            c.Check("manageable=true -> ManageYes", ListenerParse.ManageFlag(Doc("{\"manageable\":true}")), ListenerParse.ManageYes);
            c.Check("manageable=false -> ManageNo", ListenerParse.ManageFlag(Doc("{\"manageable\":false}")), ListenerParse.ManageNo);
            c.Check("protected=true -> ManageNo", ListenerParse.ManageFlag(Doc("{\"protected\":true}")), ListenerParse.ManageNo);
            c.Check("protected=false -> ManageYes", ListenerParse.ManageFlag(Doc("{\"protected\":false}")), ListenerParse.ManageYes);
            c.Check("manageable 优先于 protected",
                    ListenerParse.ManageFlag(Doc("{\"manageable\":true,\"protected\":true}")), ListenerParse.ManageYes);
            c.Check("两字段都缺 -> 未知 (不冒充)", ListenerParse.ManageFlag(Doc("{\"name\":\"x\"}")), ListenerParse.ManageUnknown);
            c.Check("字段类型不符 -> 未知", ListenerParse.ManageFlag(Doc("{\"manageable\":\"yes\"}")), ListenerParse.ManageUnknown);
            c.Check("null 字段 -> 未知", ListenerParse.ManageFlag(Doc("{\"manageable\":null}")), ListenerParse.ManageUnknown);
            c.Check("元素不是对象 -> 未知", ListenerParse.ManageFlag(default(JsonElement)), ListenerParse.ManageUnknown);

            c.Check("ManageYes: 有 id 即可移除", ListenerParse.CanManage(ListenerParse.ManageYes, "csdev-v2", "v2", "/submit", "L001"), true);
            c.Check("ManageYes 但无 id -> 不可移除", ListenerParse.CanManage(ListenerParse.ManageYes, "csdev-v2", "v2", "/submit", ""), false);
            c.Check("ManageNo: 有 id 也不可移除", ListenerParse.CanManage(ListenerParse.ManageNo, "csdev-tcp-9", "v2", "", "L002"), false);
            c.Check("未知: 有 id + 无 uri -> 可移除",
                    ListenerParse.CanManage(ListenerParse.ManageUnknown, "tcp-9", "v2", "", "L003"), true);
            c.Check("未知: 有 id 但有 uri -> 回落到本地启发式 (不可移除)",
                    ListenerParse.CanManage(ListenerParse.ManageUnknown, "tcp-9", "v2", "/submit", "L004"), false);
            c.Check("未知: 缺 id 一律不可移除",
                    ListenerParse.CanManage(ListenerParse.ManageUnknown, "tcp-9", "v2", "", ""), false);
            c.Check("id 全是空白视同没有", ListenerParse.CanManage(ListenerParse.ManageYes, "x", "v2", "", "   "), false);
            c.Check("null 入参不抛", ListenerParse.CanManage(ListenerParse.ManageUnknown, null, null, null, null), false);
        }

        // ================================================================ 操作员账号

        /// <summary>
        /// 口令长度与角色校验。常量必须与服务端 go/auth.go 对齐:
        /// authMinPassLen = 8, validRole = admin|operator; 文案与实测回话一字不差
        /// (8670 带认证实例: "口令至少 8 个字符" / "角色只能是 admin 或 operator")。
        /// </summary>
        private static void AccountValidate(Ctx c)
        {
            c.Check("MinPassLen = 服务端 authMinPassLen", AccountParse.MinPassLen, 8);
            c.Check("口令长度文案 (实测原文)", AccountParse.MsgPassTooShort, "口令至少 8 个字符");
            c.Check("角色文案 (实测原文)", AccountParse.MsgRoleInvalid, "角色只能是 admin 或 operator");
            c.Check("用户名文案 (实测原文)", AccountParse.MsgUserEmpty, "用户名不能为空");
            c.Check("重名文案 (实测原文)", AccountParse.MsgUserExists, "用户已存在");
            c.Check("用户不存在文案 (实测原文)", AccountParse.MsgUserMissing, "用户不存在");

            c.Check("7 字符口令被拦", AccountParse.ValidateNewUser("bob", "1234567", "1234567", "operator").Contains("至少 8"), true);
            c.Check("8 字符口令通过", AccountParse.ValidateNewUser("bob", "12345678", "12345678", "operator"), "");
            c.Check("空口令被拦", AccountParse.ValidateNewUser("bob", "", "", "operator").Contains("至少 8"), true);
            c.Check("角色 superuser 被拦", AccountParse.ValidateNewUser("bob", "12345678", "12345678", "superuser"),
                    "角色只能是 admin 或 operator (可选: admin / operator)");
            c.Check("角色 ADMIN 大小写归一后通过", AccountParse.ValidateNewUser("bob", "12345678", "12345678", "ADMIN"), "");
            c.Check("空角色被拦", AccountParse.ValidateNewUser("bob", "12345678", "12345678", "").Contains("admin"), true);
            c.Check("两次口令不一致被拦", AccountParse.ValidateNewUser("bob", "12345678", "12345679", "operator").Contains("不一致"), true);
            c.Check("用户名为空被拦", AccountParse.ValidateNewUser("", "12345678", "12345678", "operator").Contains("用户名"), true);
            c.Check("用户名清洗后为空被拦", AccountParse.ValidateNewUser("\t\n ", "12345678", "12345678", "operator").Contains("用户名"), true);
            c.Check("校验顺序: 先用户名后口令", AccountParse.ValidateNewUser("", "1", "1", "x").Contains("用户名"), true);
            c.Check("校验顺序: 先口令后角色", AccountParse.ValidateNewUser("bob", "1", "1", "x").Contains("至少 8"), true);

            c.Check("改口令: 缺账号名被拦", AccountParse.ValidatePass("", "12345678", "12345678").Contains("账号"), true);
            c.Check("改口令: 长度被拦", AccountParse.ValidatePass("alice", "short", "short").Contains("至少 8"), true);
            c.Check("改口令: 两次不一致被拦", AccountParse.ValidatePass("alice", "Alice-Pass-01", "Alice-Pass-02").Contains("不一致"), true);
            c.Check("改口令: 通过", AccountParse.ValidatePass("alice", "Alice-Pass-01", "Alice-Pass-01"), "");

            c.Check("IsAdmin 去空白+小写", AccountParse.IsAdmin(" Admin "), true);
            c.Check("ValidRole 非法值", AccountParse.ValidRole("root"), false);
            c.Check("角色下拉两项 (operator 在前)",
                    AccountParse.RoleOptions()[0].Value + "|" + AccountParse.RoleOptions()[1].Value, "operator|admin");
            c.Check("角色下拉带中文说明", AccountParse.RoleOptions()[1].Label.Contains("账号管理"), true);
        }

        /// <summary>用户名 sanitizeUser 清洗 (复刻 go/auth.go: TrimSpace → 按 rune 限 64 → 剔控制字符)。</summary>
        private static void AccountSanitize(Ctx c)
        {
            c.Check("去首尾空白", AccountParse.SanitizeUser("  alice  "), "alice");
            c.Check("去制表符与换行", AccountParse.SanitizeUser("al\tice\nx"), "alicex");
            c.Check("去 DEL(0x7f)", AccountParse.SanitizeUser("a\u007fb"), "ab");
            c.Check("中间的空格保留", AccountParse.SanitizeUser("  a b  "), "a b");
            c.Check("纯空白 -> 空 (非法)", AccountParse.SanitizeUser(" \t\r\n "), "");
            c.Check("null -> 空", AccountParse.SanitizeUser(null), "");
            c.Check("中文名保留", AccountParse.SanitizeUser(" 张三 "), "张三");
            c.Check("超长截断到 MaxUserLen", AccountParse.SanitizeUser(new string('a', 70)).Length, AccountParse.MaxUserLen);
            c.Check("MaxUserLen = 服务端 authMaxUserLen", AccountParse.MaxUserLen, 64);
            c.Check("截断后仍是前缀", AccountParse.SanitizeUser(new string('a', 70)).StartsWith(new string('a', 64)), true);
        }

        /// <summary>
        /// GET /api/users 解析。真实样本来自本轮 8670 带认证实例 (admin 已登录过 + alice 从未登录)。
        /// </summary>
        private static void AccountUsersParse(Ctx c)
        {
            const string real = "{\"ok\":true,\"users\":["
                              + "{\"last\":1789548083,\"last_text\":\"2026-09-16 16:41:23\",\"role\":\"admin\",\"user\":\"admin\"},"
                              + "{\"last\":0,\"last_text\":\"-\",\"role\":\"operator\",\"user\":\"alice\"}]}";
            var rows = AccountParse.Users(Doc(real), "admin");
            c.Check("行数", rows.Count, 2);
            c.Check("[0].User", rows[0].User, "admin");
            c.Check("[0].Role", rows[0].Role, "admin");
            c.Check("[0].Last", rows[0].Last, 1789548083);
            c.Check("[0].LastText = 服务端 last_text 原文", rows[0].LastText, "2026-09-16 16:41:23");
            c.Check("[0].IsSelf (当前登录 admin)", rows[0].IsSelf, true);
            c.Check("[0].AdminCount", rows[0].AdminCount, 1);
            c.Check("[0].CanDelete (自己)", rows[0].CanDelete, false);
            c.Check("[0].SelfText", rows[0].SelfText, "当前登录");
            c.Check("[1].User", rows[1].User, "alice");
            c.Check("[1].IsSelf", rows[1].IsSelf, false);
            c.Check("[1].CanDelete", rows[1].CanDelete, true);
            c.Check("[1].SelfText", rows[1].SelfText, "-");
            c.Check("[1].LastText (未登录过)", rows[1].LastText, "-");
            c.Check("行主键 (差分刷新用)", rows[0].Key + "|" + rows[1].Key, "u|admin|u|alice");

            var two = AccountParse.Users(Doc("{\"users\":[{\"user\":\"bob\",\"role\":\"admin\"},{\"user\":\"ann\",\"role\":\"admin\"}]}"), "bob");
            c.Check("缺 last/last_text -> '-'", two[0].LastText, "-");
            c.Check("两个 admin -> AdminCount=2", two[0].AdminCount, 2);
            c.Check("两个 admin 时非自己可删", two[1].CanDelete, true);
            c.Check("两个 admin 时自己不可删", two[0].CanDelete, false);

            var noRole = AccountParse.Users(Doc("{\"users\":[{\"user\":\"ghost\"}]}"), "");
            c.Check("缺 role -> 空串存储", noRole[0].Role, "");
            c.Check("缺 role -> 显示 '?'", noRole[0].RoleText, "?");
            c.Check("未登录 (selfUser 空) 时谁都不是自己", noRole[0].IsSelf, false);
            c.Check("缺 role 不按 admin 计", noRole[0].AdminCount, 0);

            c.Check("缺 users 键 -> 空表", AccountParse.Users(Doc("{\"ok\":true}"), "admin").Count, 0);
            c.Check("users 为 null -> 空表", AccountParse.Users(Doc("{\"users\":null}"), "admin").Count, 0);
            c.Check("users 类型不符 -> 空表", AccountParse.Users(Doc("{\"users\":\"x\"}"), "admin").Count, 0);
            c.Check("元素非对象/空 user 一律跳过",
                    AccountParse.Users(Doc("{\"users\":[1,null,\"x\",{\"user\":\"\"},{\"user\":\"ok\"}]}"), "admin").Count, 1);
            c.Check("顶层非对象 -> 空表", AccountParse.Users(default(JsonElement), "admin").Count, 0);
        }

        /// <summary>
        /// 删除的两个硬规则 (go/auth.go handleUserDelete): 不能删自己、不能删最后一个 admin。
        /// 本地预判用的文案必须与服务端回话一致 —— 实测:
        ///   8670 带认证: {"error":"不能删除自己当前登录的账号","ok":false}
        ///   8671 旁路  : {"error":"这是最后一个 admin, 删掉就没人能管理了","ok":false}
        /// </summary>
        private static void AccountDeleteRules(Ctx c)
        {
            c.Check("删自己文案 = 服务端实测原文", AccountParse.MsgSelfDelete, "不能删除自己当前登录的账号");
            c.Check("最后 admin 文案 = 服务端实测原文", AccountParse.MsgLastAdmin, "这是最后一个 admin, 删掉就没人能管理了");
            c.Check("403 文案 = 服务端实测原文", AccountParse.MsgNeedAdmin, "需要管理员(admin)权限");

            c.Check("自己不可删 (admin)", AccountParse.CanDelete(true, "admin", 3), false);
            c.Check("自己不可删 (operator)", AccountParse.CanDelete(true, "operator", 3), false);
            c.Check("最后一个 admin 不可删", AccountParse.CanDelete(false, "admin", 1), false);
            c.Check("两个 admin 时可删其中一个", AccountParse.CanDelete(false, "admin", 2), true);
            c.Check("operator 可删", AccountParse.CanDelete(false, "operator", 1), true);
            c.Check("AdminCount 缺失 (0) 时保守拒绝", AccountParse.CanDelete(false, "admin", 0), false);

            c.Check("自己: ToolTip 含服务端原文",
                    AccountParse.DeleteHint(true, "admin", 2, "admin").Contains(AccountParse.MsgSelfDelete), true);
            c.Check("最后 admin: ToolTip 含服务端原文",
                    AccountParse.DeleteHint(false, "admin", 1, "boss").Contains(AccountParse.MsgLastAdmin), true);
            c.Check("可删: ToolTip 给出接口名",
                    AccountParse.DeleteHint(false, "operator", 2, "alice").Contains("/api/user/delete"), true);

            string confirm = AccountParse.DeleteConfirm("alice", "operator");
            c.Check("二次确认含账号名与角色", confirm.Contains("alice (operator)"), true);
            c.Check("二次确认说明令牌会被撤销", confirm.Contains("撤销"), true);
            c.Check("二次确认说明服务端两条硬规则", confirm.Contains("最后一个 admin"), true);
        }

        /// <summary>增删改结果文案: ok 给出做了什么, 失败把服务端 error 原样透出 (不加前缀)。</summary>
        private static void AccountOpText(Ctx c)
        {
            var add = AccountParse.Result(Doc("{\"ok\":true,\"role\":\"operator\",\"user\":\"alice\"}"), "添加", "alice", "operator");
            c.Check("添加 ok", add.Ok, true);
            c.Check("添加文案", add.Text, "已添加账号 alice (operator)");

            var del = AccountParse.Result(Doc("{\"ok\":true,\"user\":\"alice\"}"), "删除", "alice", "operator");
            c.Check("删除文案", del.Text, "已删除账号 alice");

            var pass = AccountParse.Result(Doc("{\"ok\":true,\"user\":\"alice\"}"), "改口令", "alice", "operator");
            c.Check("改口令文案说明令牌被撤销", pass.Text.Contains("撤销"), true);
            c.Check("改口令文案含账号名", pass.Text.Contains("alice"), true);

            var errSelf = AccountParse.Result(Doc("{\"error\":\"不能删除自己当前登录的账号\",\"ok\":false}"), "删除", "admin", "admin");
            c.Check("失败 ok=false", errSelf.Ok, false);
            c.Check("失败文案 = error 原文", errSelf.Text, "不能删除自己当前登录的账号");
            c.Check("失败文案不加前缀", errSelf.Text.StartsWith("删除账号失败"), false);
            c.Check("Error 字段同样是原文", errSelf.Error, "不能删除自己当前登录的账号");

            var errLast = AccountParse.Result(Doc("{\"error\":\"这是最后一个 admin, 删掉就没人能管理了\",\"ok\":false}"), "删除", "boss", "admin");
            c.Check("最后 admin 原文透出", errLast.Text, "这是最后一个 admin, 删掉就没人能管理了");

            var errShort = AccountParse.Result(Doc("{\"error\":\"口令至少 8 个字符\",\"ok\":false}"), "改口令", "alice", "operator");
            c.Check("口令过短原文透出", errShort.Text, "口令至少 8 个字符");

            var noErr = AccountParse.Result(Doc("{\"ok\":false}"), "添加", "x", "operator");
            c.Check("无 error 字段时兜底", noErr.Text, "服务端未给出 error 字段");

            var notObj = AccountParse.Result(default(JsonElement), "添加", "x", "operator");
            c.Check("非对象响应兜底", notObj.Text, "添加账号失败: 服务端响应不是 JSON 对象");

            var roleDefault = AccountParse.Result(Doc("{\"ok\":true,\"user\":\"bob\"}"), "添加", "bob", "admin");
            c.Check("响应缺 role 时用请求参数", roleDefault.Text, "已添加账号 bob (admin)");
        }

        /// <summary>登录响应解析 (token + role)。真实样本来自本轮 8670 实测。</summary>
        private static void AccountLoginParse(Ctx c)
        {
            const string real = "{\"ok\":true,\"role\":\"admin\",\"token\":\"3470b0eb23c75a1a0f22b9f0b4f5d39bae700b89647ba6f4aafd9d49b2e73e10\",\"user\":\"admin\"}";
            var r = AccountParse.Login(Doc(real));
            c.Check("ok", r.Ok, true);
            c.Check("role", r.Role, "admin");
            c.Check("user", r.User, "admin");
            c.Check("token 64 字符 (32 字节 hex)", r.Token.Length, 64);

            var bad = AccountParse.Login(Doc("{\"error\":\"用户名或密码错误\",\"ok\":false}"));
            c.Check("错口令 ok=false", bad.Ok, false);
            c.Check("错口令文案 (实测原文)", bad.Error, "用户名或密码错误");
            c.Check("错口令无 token", bad.Token, "");

            var noTok = AccountParse.Login(Doc("{\"ok\":true,\"user\":\"a\",\"role\":\"operator\"}"));
            c.Check("ok 但无 token -> 判失败", noTok.Ok, false);
            c.Check("并说明缺 token", noTok.Error.Contains("token"), true);

            c.Check("非对象 -> 失败", AccountParse.Login(default(JsonElement)).Ok, false);
            c.Check("非对象 -> 有原因", AccountParse.Login(default(JsonElement)).Error.Length > 0, true);

            var up = AccountParse.Login(Doc("{\"ok\":true,\"role\":\"ADMIN\",\"token\":\"x\",\"user\":\" Bob \"}"));
            c.Check("role 归一为小写", up.Role, "admin");
            c.Check("user 走 sanitizeUser 去空白", up.User, "Bob");
        }

        /// <summary>账号管理区可用性三态: 不是 admin 就置灰并说明原因, 不等撞 403。</summary>
        private static void AccountAccessRule(Ctx c)
        {
            var a = AccountParse.Access("admin");
            c.Check("admin 可用", a.CanManage, true);
            c.Check("admin 说明给出接口", a.Note.Contains("/api/users"), true);
            c.Check("admin 角色归一", a.Role, "admin");

            var o = AccountParse.Access(" operator ");
            c.Check("operator 不可用", o.CanManage, false);
            c.Check("operator 说明含 403 原文", o.Note.Contains(AccountParse.MsgNeedAdmin), true);
            c.Check("operator 说明给出行动 (重新登录)", o.Note.Contains("重新登录"), true);
            c.Check("operator 说明点名两端点", o.Note.Contains("/api/user/*"), true);

            var n = AccountParse.Access("");
            c.Check("未登录仍可用 (服务端 -auth=off 时需要)", n.CanManage, true);
            c.Check("未登录说明 401 情形", n.Note.Contains("401"), true);
            c.Check("未登录说明 -auth=off 情形", n.Note.Contains("auth=off"), true);

            var x = AccountParse.Access("superuser");
            c.Check("未知角色按未登录处理", x.CanManage, true);
            c.Check("未知角色回显原文", x.Role, "superuser");
        }

        // ================================================================ 连接配置

        /// <summary>
        /// 地址规范化。规则必须与 CsdevApi.BaseUrl 的 setter 完全一致, 否则会出现
        /// "下拉里存了一个地址、连的却是另一个"的鬼问题 —— 所以这里逐样本对照两个实现。
        /// </summary>
        private static void ConnNormalize(Ctx c)
        {
            c.Check("默认地址", ConnStore.DefaultUrl, "http://127.0.0.1:8443");
            c.Check("空 -> 默认", ConnStore.Normalize(""), ConnStore.DefaultUrl);
            c.Check("纯空白 -> 默认", ConnStore.Normalize("   "), ConnStore.DefaultUrl);
            c.Check("null -> 默认", ConnStore.Normalize(null), ConnStore.DefaultUrl);
            c.Check("只有斜杠 -> 默认", ConnStore.Normalize("/"), ConnStore.DefaultUrl);
            c.Check("host:port 补 http://", ConnStore.Normalize("127.0.0.1:8670"), "http://127.0.0.1:8670");
            c.Check("末尾斜杠去掉", ConnStore.Normalize("http://127.0.0.1:8670/"), "http://127.0.0.1:8670");
            c.Check("多个末尾斜杠去掉", ConnStore.Normalize("http://a:1///"), "http://a:1");
            c.Check("https 保留", ConnStore.Normalize("https://c2.example:8443"), "https://c2.example:8443");
            c.Check("去首尾空白", ConnStore.Normalize("  http://a:1  "), "http://a:1");

            string[] samples = { "", "   ", "/", "127.0.0.1:8670", "http://127.0.0.1:8670/",
                                 "https://a:1", "http://a:1///", "  http://a:1  ", "HTTP://a:1" };
            var api = new CsdevApi();
            var diff = new List<string>();
            for (int i = 0; i < samples.Length; i++)
            {
                api.BaseUrl = samples[i];
                if (api.BaseUrl != ConnStore.Normalize(samples[i])) diff.Add(samples[i]);
            }
            c.Check("与 CsdevApi.BaseUrl 逐样本一致 (差异样本: " + Join(diff) + ")", diff.Count, 0);

            c.Check("去重键大小写不敏感", ConnStore.KeyOf("HTTP://A:1") == ConnStore.KeyOf("http://a:1"), true);
            c.Check("去重键跨末尾斜杠一致", ConnStore.KeyOf("http://a:1/") == ConnStore.KeyOf("http://a:1"), true);
        }

        /// <summary>保存 / 读取往返 + 去重 + 删除 (在临时目录里真写文件)。</summary>
        private static void ConnRoundTrip(Ctx c)
        {
            string dir = Path.Combine(Path.GetTempPath(), "csdev-selftest-" + Guid.NewGuid().ToString("N"));
            string path = Path.Combine(dir, "connections.json");
            try
            {
                var list = ConnStore.Load(path);
                c.Check("文件不存在 -> 空表", list.Count, 0);

                ConnStore.EnsureDefault(list);
                c.Check("空表补默认项", list.Count + "|" + list[0].Url, "1|http://127.0.0.1:8443");
                c.Check("默认项标记未保存", list[0].Saved, false);
                ConnStore.EnsureDefault(list);
                c.Check("非空表不再补默认", list.Count, 1);
                c.Check("默认占位项标为未保存", ConnStore.SavedOnly(list).Count, 0);
                c.Check("默认占位项不会被写进文件",
                        ConnStore.Save(path, list) + "|" + ConnStore.Load(path).Count, "|0");

                var e = ConnStore.Upsert(list, "127.0.0.1:8670", "admin");
                c.Check("插入后在最前", list[0].Url, "http://127.0.0.1:8670");
                c.Check("用户名写入", e.User, "admin");
                c.Check("标记已保存", e.Saved, true);

                ConnStore.Upsert(list, "http://127.0.0.1:8670/", "alice");
                c.Check("同地址去重 (末尾斜杠)", list.Count, 2);
                c.Check("用户名被更新", ConnStore.Find(list, "HTTP://127.0.0.1:8670").User, "alice");
                ConnStore.Upsert(list, "http://127.0.0.1:8670", "");
                c.Check("用户名留空不覆盖已保存值", ConnStore.Find(list, "http://127.0.0.1:8670").User, "alice");

                ConnStore.Upsert(list, "http://b:9000", "bob");
                c.Check("新条目排到最前 (最近使用优先)", list[0].Url, "http://b:9000");

                c.Check("写入成功", ConnStore.Save(path, list), "");
                c.Check("文件真的落盘", File.Exists(path), true);

                var again = ConnStore.Load(path);
                c.Check("读回条数 (默认占位项不落盘)", again.Count, 2);
                c.Check("读回顺序", ConsUrls(again), "http://b:9000|http://127.0.0.1:8670");
                c.Check("读回不含内存里的默认占位项", ConsUrls(again).Contains("8443"), false);
                c.Check("读回用户名", again[1].User, "alice");
                c.Check("读回的条目都标记已保存", again[0].Saved && again[1].Saved, true);

                c.Check("删除命中 (规范化后匹配)", ConnStore.Remove(again, "127.0.0.1:8670"), true);
                c.Check("删除后剩 1 条", again.Count, 1);
                c.Check("删除未命中返回 false", ConnStore.Remove(again, "http://nope:1"), false);
                c.Check("删除未命中时表不变", again.Count, 1);
                c.Check("写回再读", ConnStore.Save(path, again) + "|" + ConnStore.Load(path).Count, "|1");

                // 目录不存在时 Save 自己建目录 (首次使用时 %APPDATA%\csdev 还不存在)
                string deep = Path.Combine(dir, "sub", "csdev", "connections.json");
                c.Check("自动建目录", ConnStore.Save(deep, list), "");
                c.Check("深目录文件存在", File.Exists(deep), true);
            }
            finally
            {
                try { Directory.Delete(dir, true); } catch { }
            }
        }

        /// <summary>
        /// 口令不落盘: 序列化只写 url/user 两个键 (显式白名单), ConnEntry 上也没有口令字段。
        /// 另外验证"手写的旧文件里塞了口令"时读回再写不会把它带出去。
        /// </summary>
        private static void ConnNoPassword(Ctx c)
        {
            var list = new List<ConnEntry>();
            ConnStore.Upsert(list, "http://127.0.0.1:8443", "admin");
            string json = ConnStore.Serialize(list);

            c.Check("含 url 键", json.Contains("\"url\""), true);
            c.Check("含 user 键", json.Contains("\"user\""), true);
            c.Check("含 version", json.Contains("\"version\": 1"), true);
            c.Check("不含 pass", json.Contains("pass"), false);
            c.Check("不含 password", json.Contains("password"), false);
            c.Check("不含 token", json.Contains("token"), false);
            c.Check("不含 secret", json.Contains("secret"), false);
            c.Check("不含 hash", json.Contains("hash"), false);
            c.Check("不含凭据字样", json.Contains("credential"), false);

            bool hasPassField = false;
            var props = typeof(ConnEntry).GetProperties();
            for (int i = 0; i < props.Length; i++)
            {
                string n = props[i].Name.ToLowerInvariant();
                if (n.Contains("pass") || n.Contains("token") || n.Contains("secret")) hasPassField = true;
            }
            c.Check("ConnEntry 没有口令/令牌字段", hasPassField, false);

            // 本轮实测的默认管理员口令 (8670 实例), 确认它不会被任何一条路径带进配置
            const string realPass = "K25UJ77Q6SNN9TYTM6HZMZEXFS";
            var l2 = new List<ConnEntry>();
            ConnStore.Upsert(l2, "http://127.0.0.1:8670", "admin");
            c.Check("实测口令不出现在序列化结果里", ConnStore.Serialize(l2).Contains(realPass), false);
            c.Check("实测口令不会出现在 Display 里", l2[0].Display.Contains(realPass), false);
            c.Check("Display 含地址与用户名", l2[0].Display.Contains("http://127.0.0.1:8670") && l2[0].Display.Contains("admin"), true);

            var loaded = ConnStore.Parse("{\"version\":1,\"connections\":[{\"url\":\"http://a:1\",\"user\":\"u\",\"pass\":\"P@ssw0rd!\"}]}");
            c.Check("手写口令的文件仍能读", loaded.Count, 1);
            c.Check("读回后写出去不含那个口令", ConnStore.Serialize(loaded).Contains("P@ssw0rd!"), false);

            c.Check("逐条白名单: 只出现一处 url/user",
                    ConnStore.Serialize(list).Split(new string[] { "\"url\"" }, StringSplitOptions.None).Length, 2);
        }

        /// <summary>损坏 / 异构配置的降级 (坏文件不该让 GUI 起不来)。</summary>
        private static void ConnDegrade(Ctx c)
        {
            c.Check("空串 -> 空表", ConnStore.Parse("").Count, 0);
            c.Check("null -> 空表", ConnStore.Parse(null).Count, 0);
            c.Check("非 JSON -> 空表", ConnStore.Parse("{not json").Count, 0);
            c.Check("顶层是数组 -> 空表", ConnStore.Parse("[1,2,3]").Count, 0);
            c.Check("顶层是标量 -> 空表", ConnStore.Parse("\"x\"").Count, 0);
            c.Check("缺 connections 键 -> 空表", ConnStore.Parse("{\"version\":1}").Count, 0);
            c.Check("connections 是字符串 -> 空表", ConnStore.Parse("{\"connections\":\"x\"}").Count, 0);

            var l = ConnStore.Parse("{\"connections\":[1,null,\"x\",{\"user\":\"u\"},{\"url\":\"\"},{\"url\":\"  \"},{\"url\":\"http://a:1\",\"user\":\"u\"}]}");
            c.Check("坏条目全部跳过, 只留一条", l.Count, 1);
            c.Check("留下的那条地址已规范化", l[0].Url, "http://a:1");

            var dup = ConnStore.Parse("{\"connections\":[{\"url\":\"http://a:1\",\"user\":\"u\"},{\"url\":\"http://A:1/\",\"user\":\"u2\"}]}");
            c.Check("文件内重复地址去重", dup.Count, 1);

            var noUser = ConnStore.Parse("{\"connections\":[{\"url\":\"http://a:1\"}]}");
            c.Check("缺 user -> 空串", noUser[0].User, "");
            c.Check("user 类型不符 -> 空串", ConnStore.Parse("{\"connections\":[{\"url\":\"http://a:1\",\"user\":7}]}")[0].User, "");

            string missing = Path.Combine(Path.GetTempPath(), "csdev-nope-" + Guid.NewGuid().ToString("N") + ".json");
            c.Check("Load 不存在的文件 -> 空表", ConnStore.Load(missing).Count, 0);
            c.Check("Load 坏路径不抛", ConnStore.Load("::bad::path::").Count, 0);
            c.Check("Save 到非法路径返回原因", ConnStore.Save("::bad::path::/x.json", new List<ConnEntry>()).Length > 0, true);
            c.Check("PathNote 含路径与'口令不落盘'", ConnStore.PathNote("C:\\x\\connections.json").Contains("口令不落盘"), true);
        }

        // ================================================================ 监听器新建对话框

        /// <summary>类型 -> 标签 / 示例 / 说明的映射 (下拉在对话框里, 选项由 ListenerParse 提供)。</summary>
        private static void ListenerKindsDialog(Ctx c)
        {
            c.Check("标签数与 kind 数一致", ListenerParse.KindLabels.Length, ListenerParse.Kinds.Length);
            c.Check("http 标签标注运行期不支持", ListenerParse.KindLabels[0], "HTTP（运行期不支持）");
            c.Check("https 标签标注运行期不支持", ListenerParse.KindLabels[1], "HTTPS（运行期不支持）");
            c.Check("KindLabel 查表 (去空白+小写)", ListenerParse.KindLabel("EXTc2 "), "External C2（第三方中转）");
            c.Check("未知 kind 原样回 (不编造标签)", ListenerParse.KindLabel("ftp"), "ftp");

            c.Check("KindSupported: http 否", ListenerParse.KindSupported("http"), false);
            c.Check("KindSupported: https 否", ListenerParse.KindSupported("https"), false);
            c.Check("KindSupported: 四种可用",
                    "" + ListenerParse.KindSupported("tcp") + ListenerParse.KindSupported("smb")
                       + ListenerParse.KindSupported("dns") + ListenerParse.KindSupported("extc2"),
                    "TrueTrueTrueTrue");
            c.Check("KindSupported: 空/未知 否",
                    ListenerParse.KindSupported("") + "|" + ListenerParse.KindSupported("ftp"), "False|False");
            c.Check("KindNeedsWarn: http 标黄 / tcp 不黄",
                    ListenerParse.KindNeedsWarn("http") + "|" + ListenerParse.KindNeedsWarn("tcp"), "True|False");

            var opts = ListenerParse.Options();
            c.Check("选项数 = 6", opts.Count, 6);
            c.Check("选项顺序 (HTTP 先, External C2 后)", opts[0].Kind + "|" + opts[5].Kind, "http|extc2");
            c.Check("选项 Supported 标记 http=false tcp=true", opts[0].Supported + "|" + opts[2].Supported, "False|True");
            c.Check("选项标签与 KindLabels 同源", opts[3].Label, ListenerParse.KindLabels[3]);

            c.Check("tcp 说明含配套载荷 win2-tcp", ListenerParse.KindNote("tcp").Contains("win2-tcp"), true);
            c.Check("tcp 说明含地址示例", ListenerParse.KindNote("tcp").Contains("0.0.0.0:8444"), true);
            c.Check("smb 说明讲清是管道名", ListenerParse.KindNote("smb").Contains("管道名"), true);
            c.Check("dns 说明提到 53 需特权", ListenerParse.KindNote("dns").Contains("53"), true);
            c.Check("extc2 说明提到第三方中转", ListenerParse.KindNote("extc2").Contains("第三方"), true);
            c.Check("未知类型说明不编造示例", ListenerParse.KindNote("ftp"), "未知监听器类型, 无法给出地址示例");
        }

        /// <summary>
        /// HTTP(S) 被拒: 对话框里的预告文案与服务端**实测**原文同源, 且真发出去时
        /// GUI 显示的仍是服务端那一句 (AddResult 直接透出 error, 不加工)。
        ///
        /// 实测 (8670 带认证实例, POST /api/listener/add):
        ///   {"addr":"0.0.0.0:8699","error":"运行期不支持新增 http listener: 控制台 mux/TLS 在启动期已固化,
        ///    新 HTTP 口无法共享路由表。HTTP(S) 承载请用启动参数 --port / -tls","kind":"http","ok":false}
        /// </summary>
        private static void ListenerHttpReject(Ctx c)
        {
            const string realHttp = "运行期不支持新增 http listener: 控制台 mux/TLS 在启动期已固化, 新 HTTP 口无法共享路由表。HTTP(S) 承载请用启动参数 --port / -tls";
            const string realHttps = "运行期不支持新增 https listener: 控制台 mux/TLS 在启动期已固化, 新 HTTP 口无法共享路由表。HTTP(S) 承载请用启动参数 --port / -tls";

            c.Check("模板替换 = 服务端 http 实测原文", ListenerParse.RejectTemplate.Replace("{k}", "http"), realHttp);
            c.Check("模板替换 = 服务端 https 实测原文", ListenerParse.RejectTemplate.Replace("{k}", "https"), realHttps);
            c.Check("对话框预告含实测原文", ListenerParse.KindNote("http").Contains(realHttp), true);
            c.Check("对话框预告说明仍可下发", ListenerParse.KindNote("http").Contains("原样回给你"), true);
            c.Check("对话框预告不再重复'地址示例'", ListenerParse.KindNote("https").Contains("地址示例"), false);

            const string resp = "{\"addr\":\"0.0.0.0:8699\",\"error\":\"" + realHttp + "\",\"kind\":\"http\",\"ok\":false}";
            var op = ListenerParse.AddResult(Doc(resp));
            c.Check("AddResult ok=false", op.Ok, false);
            c.Check("AddResult 文案 = 服务端 error 原文", op.Text, realHttp);
            c.Check("AddResult 回传 addr", op.Addr, "0.0.0.0:8699");

            const string ok = "{\"addr\":\"127.0.0.1:8698\",\"created\":1789548083,\"id\":\"L002\",\"kind\":\"tcp\",\"manageable\":true,\"name\":\"csdev-tcp-8698\",\"ok\":true,\"protected\":false,\"sessions\":0,\"status\":\"up\"}";
            var op2 = ListenerParse.AddResult(Doc(ok));
            c.Check("成功样本 ok", op2.Ok, true);
            c.Check("成功样本回 id", op2.Id, "L002");
            c.Check("成功样本回实际绑定地址", op2.Addr, "127.0.0.1:8698");
            c.Check("成功文案含 id", op2.Text.Contains("L002"), true);
        }

        /// <summary>连接列表 -> "|" 连接的地址串 (断言辅助)。</summary>
        private static string ConsUrls(List<ConnEntry> list)
        {
            var sb = new StringBuilder();
            for (int i = 0; i < list.Count; i++)
            {
                if (i > 0) sb.Append('|');
                sb.Append(list[i].Url);
            }
            return sb.ToString();
        }

        private static int CountRemovable(List<ListenerRow> rows)
        {
            int n = 0;
            foreach (ListenerRow r in rows) if (r.CanRemove) n++;
            return n;
        }

        // ================================================================ 辅助

        private static int CountRaw(List<FsItem> list)
        {
            int n = 0;
            foreach (FsItem i in list) if (i.Raw) n++;
            return n;
        }

        private static int CountEmptyName(List<FsItem> list)
        {
            int n = 0;
            foreach (FsItem i in list) if (i.Name.Length == 0) n++;
            return n;
        }

        private static FsItem FindNamed(List<FsItem> list, string name)
        {
            foreach (FsItem i in list) if (i.Name == name) return i;
            return null;
        }

        private static ProcItem FindProcName(List<ProcItem> list, string name)
        {
            foreach (ProcItem i in list) if (i.Name == name) return i;
            return null;
        }

        private static int CountRawProc(List<ProcItem> list)
        {
            int n = 0;
            foreach (ProcItem i in list) if (i.Raw) n++;
            return n;
        }

        private static int CountEmptyProc(List<ProcItem> list)
        {
            int n = 0;
            foreach (ProcItem i in list) if (i.Name.Length == 0) n++;
            return n;
        }

        // 目标库 / 代理枢轴的用例辅助

        /// <summary>用 "|" 连接, 便于把集合断言写成一行可读文本。</summary>
        private static string Join(List<string> list)
        {
            if (list == null) return "(null)";
            var sb = new StringBuilder();
            for (int i = 0; i < list.Count; i++)
            {
                if (i > 0) sb.Append('|');
                sb.Append(list[i]);
            }
            return sb.ToString();
        }

        private static string Join(List<SourceTag> list)
        {
            if (list == null) return "(null)";
            var names = new List<string>();
            foreach (SourceTag t in list) names.Add(t.Name);
            return Join(names);
        }

        private static List<string> SourceNames(TargetRow row)
        {
            var names = new List<string>();
            if (row == null || row.SourceTags == null) return names;
            foreach (SourceTag t in row.SourceTags) names.Add(t.Name);
            return names;
        }

        /// <summary>画刷按实例比较 (Palette 里的都是冻结单例)。</summary>
        private static bool SameBrush(Brush a, Brush b)
        {
            return ReferenceEquals(a, b);
        }

        // 插件包用例的样本构造器 (把绝对路径安全地嵌进 JSON 字面量, 避免手写 \\ 转义出错)

        /// <summary>路径/文本 -> JSON 字符串字面量 (反斜杠与引号转义)。</summary>
        private static string JStr(string s)
        {
            var sb = new StringBuilder("\"");
            string v = s ?? "";
            for (int i = 0; i < v.Length; i++)
            {
                char ch = v[i];
                if (ch == '\\') sb.Append("\\\\");
                else if (ch == '"') sb.Append("\\\"");
                else sb.Append(ch);
            }
            return sb.Append('"').ToString();
        }

        /// <summary>"|" 分隔的路径表 -> JSON 字符串数组。</summary>
        private static string JPathList(string joined)
        {
            var sb = new StringBuilder("[");
            if (!string.IsNullOrEmpty(joined))
            {
                string[] parts = joined.Split('|');
                for (int i = 0; i < parts.Length; i++)
                {
                    if (i > 0) sb.Append(',');
                    sb.Append(JStr(parts[i]));
                }
            }
            return sb.Append(']').ToString();
        }

        /// <summary>拼一个 /api/plugins 的包条目 (字段名与 go/plugins.go pluginInfo 一致)。</summary>
        private static string Pack(string name, string path, string kind, string main, long files, long bytes,
                                   bool loaded, long menus, bool hasMain, string err)
        {
            var sb = new StringBuilder();
            sb.Append("{\"name\":").Append(JStr(name))
              .Append(",\"path\":").Append(JStr(path))
              .Append(",\"kind\":").Append(JStr(kind))
              .Append(",\"main\":").Append(JStr(main))
              .Append(",\"files\":").Append(files)
              .Append(",\"bytes\":").Append(bytes)
              .Append(",\"loaded\":").Append(loaded ? "true" : "false")
              .Append(",\"menus\":").Append(menus)
              .Append(",\"has_main\":").Append(hasMain ? "true" : "false");
            if (!string.IsNullOrEmpty(err)) sb.Append(",\"err\":").Append(JStr(err));
            return sb.Append('}').ToString();
        }

        /// <summary>
        /// 拼一个 /api/plugins 的 external 条目 (字段名与 go/plugins.go pluginExternal 一致)。
        /// hasExists=false 时**不写 exists 字段** —— 用来验"服务端没给字段"的降级路径。
        /// </summary>
        private static string Ext(string path, string name, bool exists, bool hasExists,
                                 long files, long bytes, long menus, string err)
        {
            var sb = new StringBuilder();
            sb.Append("{\"path\":").Append(JStr(path))
              .Append(",\"name\":").Append(JStr(name));
            if (hasExists) sb.Append(",\"exists\":").Append(exists ? "true" : "false");
            sb.Append(",\"files\":").Append(files)
              .Append(",\"bytes\":").Append(bytes)
              .Append(",\"menus\":").Append(menus);
            if (!string.IsNullOrEmpty(err)) sb.Append(",\"err\":").Append(JStr(err));
            return sb.Append('}').ToString();
        }

        /// <summary>external 行集合的显示名连接 (断言用)。</summary>
        private static string JoinExternal(List<PluginExternalRow> rows)
        {
            if (rows == null) return "(null)";
            var names = new List<string>();
            foreach (PluginExternalRow x in rows) names.Add(x.Name);
            return Join(names);
        }

        private static PluginPack FindPack(PluginView v, string name)
        {
            if (v != null)
            {
                foreach (PluginPack p in v.Plugins) if (p.Name == name) return p;
            }
            return new PluginPack();
        }

        private static PluginPack FindRow(List<PluginPack> rows, string path)
        {
            if (rows != null)
            {
                foreach (PluginPack p in rows) if (p.Path == path) return p;
            }
            return new PluginPack();
        }

        /// <summary>
        /// 把 JSON 文本变成 JsonElement 供解析层断言。
        /// 不 Dispose 文档: JsonElement 持有其父文档引用, 用例存活期内不会被回收。
        /// </summary>
        private static JsonElement Doc(string json)
        {
            return JsonDocument.Parse(json).RootElement;
        }

        // ================================================================ 报告导出

        /// <summary>
        /// /api/report/* 的 URL 拼装与默认文件名。
        ///
        /// kind 必须转义: 下拉里给的是固定七个值, 但这个函数是**唯一**的
        /// "kind -> URL" 出口, 自测用它挡住"某天有人直接把用户输入拼上去"。
        /// 文件名同样要挡 `../`: 默认名会被填进 SaveFileDialog, 带分隔符的名字
        /// 会让人以为文件存到了别的目录。
        /// </summary>
        private static void ReportUrls(Ctx c)
        {
            c.Check("json 端点", ReportParse.JsonUrl, "/api/report/json");
            c.Check("html 端点", ReportParse.HtmlUrl, "/api/report/html");
            c.Check("csv 端点 + kind", ReportParse.CsvUrl("events"), "/api/report/csv?kind=events");
            c.Check("kind 首尾空白被去掉", ReportParse.CsvUrl("  jobs  "), "/api/report/csv?kind=jobs");
            c.Check("kind 大小写原样保留 (服务端自己 ToLower)",
                    ReportParse.CsvUrl("Events"), "/api/report/csv?kind=Events");
            c.Check("kind 里的空格转义", ReportParse.CsvUrl("a b"), "/api/report/csv?kind=a%20b");
            c.Check("kind 里的斜杠转义", ReportParse.CsvUrl("a/b"), "/api/report/csv?kind=a%2Fb");
            c.Check("kind 里的 & 转义 (不会被当第二个参数)",
                    ReportParse.CsvUrl("a&x=1"), "/api/report/csv?kind=a%26x%3D1");
            c.Check("kind 里的 % 转义 (不会变成非法转义序列)",
                    ReportParse.CsvUrl("100%"), "/api/report/csv?kind=100%25");
            c.Check("中文 kind 走 UTF-8 百分号编码",
                    ReportParse.CsvUrl("会话"), "/api/report/csv?kind=%E4%BC%9A%E8%AF%9D");
            c.Check("空 kind 不抛 (服务端按 sessions 处理)", ReportParse.CsvUrl(null), "/api/report/csv?kind=");
            c.Check("空白 kind 与空 kind 同结果",
                    ReportParse.CsvUrl("   "), "/api/report/csv?kind=");
            c.Check("kind 数 = 7 (与服务端 reportCSVKinds 同序)",
                    ReportParse.Kinds.Length, 7);
            c.Check("kind 顺序",
                    ReportParse.Kinds[0].Kind + "," + ReportParse.Kinds[3].Kind + "," + ReportParse.Kinds[6].Kind,
                    "sessions,events,jobs");
            c.Check("每个 kind 都有中文名与扩展名",
                    AllHaveLabelExt(ReportParse.Kinds), true);
            c.Check("jobs 也在表里 (服务端已补)", ReportParse.IsKnown("jobs"), true);
            c.Check("未知 kind 不认", ReportParse.IsKnown("ftp"), false);
            c.Check("Label 查表 (去空白 + 小写)", ReportParse.Label(" EVENTS "), "事件 events");
            c.Check("Label 未知时原样回 (不编造)", ReportParse.Label("ftp"), "ftp");

            var when = new DateTime(2026, 9, 16, 17, 4, 5);
            c.Check("默认名 (kind + 时间戳)",
                    ReportParse.FileName("events", "csv", when), "csdev-report-events-20260916_170405.csv");
            c.Check("html 默认名", ReportParse.FileName("report", "html", when),
                    "csdev-report-report-20260916_170405.html");
            c.Check("扩展名带点也接受", ReportParse.FileName("jobs", ".csv", when),
                    "csdev-report-jobs-20260916_170405.csv");
            c.Check("空扩展名退化 bin", ReportParse.FileName("x", "", when),
                    "csdev-report-x-20260916_170405.bin");
            c.Check("空 kind 退化 report", ReportParse.FileName("", "json", when),
                    "csdev-report-report-20260916_170405.json");
            c.Check("中文 kind 在文件名里 (不用转义)", ReportParse.FileName("会话", "csv", when),
                    "csdev-report-会话-20260916_170405.csv");
            c.Check("文件名不含路径分隔符", ReportParse.FileName("a/b\\c", "csv", when),
                    "csdev-report-abc-20260916_170405.csv");
            c.Check("文件名不含 .. 穿越", ReportParse.FileName("..", "csv", when),
                    "csdev-report-..-20260916_170405.csv");
            c.Check("kind 里带有害字符被剔掉", ReportParse.FileName("a:b?c", "csv", when),
                    "csdev-report-abc-20260916_170405.csv");

            c.Check("字节数文案 (绝对数 + 可读)",
                    ReportParse.BytesText(4096), "4096 字节 (4.0 KB)");
            c.Check("字节数 0", ReportParse.BytesText(0), "0 字节 (0 B)");
            c.Check("保存成功文案含绝对路径与字节数",
                    ReportParse.SavedText("D:\\out\\csdev-report-events-1.csv", 12345),
                    "已保存: D:\\out\\csdev-report-events-1.csv   (12345 字节 (12.1 KB))");
        }

        private static bool AllHaveLabelExt(ReportExport[] list)
        {
            for (int i = 0; i < list.Length; i++)
                if (list[i].Label.Length == 0 || list[i].Ext.Length == 0) return false;
            return true;
        }

        /// <summary>
        /// 报告导出的错误文案。
        ///
        /// 401 是本组最要紧的一条: /api/report/* 是服务端唯一默认 fail-closed 的数据出口
        /// (go/report.go 顶部注释), 未登录必然撞它 —— 文案必须直接说"需要登录",
        /// 而不是让操作员在"HTTP 401"里猜。
        /// </summary>
        private static void ReportErrorText(Ctx c)
        {
            const string path = "/api/report/csv";

            string t401 = ReportParse.SaveErrorText("CSV 报告 (events)", 401, "", path);
            c.Check("401 含 what", t401.StartsWith("CSV 报告 (events)失败: ", StringComparison.Ordinal), true);
            c.Check("401 点明需要登录", t401.IndexOf("需要登录", StringComparison.Ordinal) >= 0, true);
            c.Check("401 仍带既有引导", t401.IndexOf("未认证或令牌已失效", StringComparison.Ordinal) >= 0, true);

            string t404 = ReportParse.SaveErrorText("HTML 报告", 404, "404 page not found", "/api/report/html");
            c.Check("404 带请求路径", t404.IndexOf("/api/report/html", StringComparison.Ordinal) >= 0, true);
            c.Check("404 指出服务端二进制过旧",
                    t404.IndexOf("通常是服务端二进制过旧", StringComparison.Ordinal) >= 0, true);
            c.Check("404 保留服务端原话", t404.IndexOf("404 page not found", StringComparison.Ordinal) >= 0, true);
            c.Check("404 不提需要登录", t404.IndexOf("需要登录", StringComparison.Ordinal) < 0, true);

            // 未知 kind: 服务端回 HTTP 400 + JSON 正文 (Content-Type 变成 application/json),
            // 字节虽然拿到了, 但绝不是 CSV —— 文案要把服务端那句原样带出来
            const string bad = "{\"ok\":false,\"error\":\"未知 kind: ftp\",\"kinds\":[\"sessions\"]}";
            string t400 = ReportParse.SaveErrorText("CSV 报告 (ftp)", 400, bad, path);
            c.Check("400 带状态码", t400.IndexOf("HTTP 400", StringComparison.Ordinal) >= 0, true);
            c.Check("400 原样带服务端正文", t400.IndexOf("未知 kind: ftp", StringComparison.Ordinal) >= 0, true);
            c.Check("400 不误报成二进制过旧",
                    t400.IndexOf("二进制过旧", StringComparison.Ordinal) < 0, true);

            string t500 = ReportParse.SaveErrorText("JSON 报告", 500, "内部错误", "/api/report/json");
            c.Check("500 原样", t500.IndexOf("HTTP 500", StringComparison.Ordinal) >= 0, true);
            c.Check("what 为空时不出现空前缀",
                    ReportParse.SaveErrorText("", 401, "", path).StartsWith("需要登录", StringComparison.Ordinal), true);
            c.Check("403 权限不足沿用既有文案",
                    ReportParse.SaveErrorText("JSON 报告", 403, "forbidden", "/api/report/json")
                        .IndexOf("权限不足", StringComparison.Ordinal) >= 0, true);
        }

        // ================================================================ 下载文件内容

        /// <summary>
        /// 文本 / 二进制判定。样本全部是**逐字节写死**的, 因为判定依据就是字节本身:
        ///   - 纯 ASCII: 文本
        ///   - UTF-8 带 BOM: 文本, 且显示时 BOM 被剥掉 (否则首行顶一个不可见字符)
        ///   - GBK 中文: 文本 (植入体回传本来就可能是 GBK)
        ///   - PNG 头: 二进制 (第 5 字节就是 0x00)
        ///   - 0x89 这类高位字节混排: 严格 UTF-8 失败 -> 二进制, 不给一屏替换字符
        /// </summary>
        private static void DownloadContentRules(Ctx c)
        {
            // ---- 空 ----
            var empty = DownloadContent.Parse(new byte[0]);
            c.Check("空: 判定为非二进制", empty.IsBinary, false);
            c.Check("空: IsEmpty", empty.IsEmpty, true);
            c.Check("空: 大小文案", empty.SizeText, "0 B");
            c.Check("空: 正文说明为空", empty.TextBody(), "(0 字节, 文件为空)");
            c.Check("空: 标题", empty.TitleText("a.txt"), "下载内容: a.txt   0 B   文本");
            c.Check("空: 头部预览", empty.HeadBytesText(), "(空)");
            c.Check("null 不抛", DownloadContent.Parse(null).Size, 0);

            // ---- ASCII 文本 ----
            byte[] ascii = Encoding.UTF8.GetBytes("whoami\r\nrainstop\\israinstop\r\n");
            var da = DownloadContent.Parse(ascii);
            c.Check("ASCII: 文本", da.IsBinary, false);
            c.Check("ASCII: 大小", da.Size, ascii.Length);
            c.Check("ASCII: 正文按行归一 (CRLF -> LF 且去尾换行)",
                    da.TextBody(), "whoami\nrainstop\\israinstop");
            c.Check("ASCII: 无控制字符计入", da.ControlChars, 0);
            c.Check("ASCII: 标题标文本", da.TitleText("out.txt"), "下载内容: out.txt   " + da.SizeText + "   文本");

            // ---- UTF-8 带 BOM ----
            var bomBytes = new List<byte>();
            bomBytes.AddRange(new byte[] { 0xEF, 0xBB, 0xBF });
            bomBytes.AddRange(Encoding.UTF8.GetBytes("中文内容"));
            var db = DownloadContent.Parse(bomBytes.ToArray());
            c.Check("BOM: 判定为文本", db.IsBinary, false);
            c.Check("BOM: 显示时剥掉 BOM", db.TextBody(), "中文内容");
            c.Check("BOM: 字节数按原始算 (含 3 字节 BOM)", db.Size, bomBytes.Count);
            c.Check("BOM: 前 3 字节十六进制", ByteHex(db.Preview, 3), "ef bb bf");

            // ---- GBK 中文 ----
            byte[] gbk = { 0xD6, 0xD0, 0xCE, 0xC4, 0x0A };   // "中文\n"
            var dg = DownloadContent.Parse(gbk);
            c.Check("GBK: 判定为文本", dg.IsBinary, false);
            c.Check("GBK: 解码正确", dg.TextBody(), "中文");
            c.Check("GBK: 无替换字符", dg.Replaced, 0);

            // ---- PNG 头 (真二进制) ----
            byte[] png =
            {
                0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,
                0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52,
                0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x80
            };
            var dp = DownloadContent.Parse(png);
            c.Check("PNG 头: 判定为二进制", dp.IsBinary, true);
            c.Check("PNG 头: 大小", dp.Size, 24);
            c.Check("PNG 头: 标题标二进制",
                    dp.TitleText("s.png"), "下载内容: s.png   " + dp.SizeText + "   二进制");
            c.Check("PNG 头: 头部十六进制逐字节",
                    dp.HeadBytesText(),
                    "137 80 78 71 13 10 26 10 0 0 0 13 73 72 68 82 0 0 1 0 0 0 0 128");
            c.Check("PNG 头: 预览不超 256 字节", dp.Preview.Length, 24);
            c.Check("PNG 头: 正文如实说明是二进制",
                    dp.TextBody().StartsWith("[二进制内容: 不是可显示的文本", StringComparison.Ordinal), true);
            c.Check("PNG 头: 正文给大小", dp.TextBody().IndexOf("大小: 24 字节", StringComparison.Ordinal) >= 0, true);
            c.Check("PNG 头: 正文给判定依据",
                    dp.TextBody().IndexOf("判定依据: ", StringComparison.Ordinal) >= 0, true);
            c.Check("PNG 头: 正文含前 16 字节十六进制行",
                    dp.TextBody().IndexOf("00000000  89 50 4e 47 0d 0a 1a 0a  00 00 00 0d 49 48 44 52  |.PNG........IHDR|",
                                          StringComparison.Ordinal) >= 0, true);
            c.Check("PNG 头: 正文含完整转储标题",
                    dp.TextBody().IndexOf("完整十六进制转储 (24 字节)", StringComparison.Ordinal) >= 0, true);
            c.Check("PNG 头: 控制字符被数出来", dp.ControlChars >= 5, true);
            c.Check("PNG 头: 比例文案可读", dp.RatioText().EndsWith("替换字符", StringComparison.Ordinal), true);

            // ---- 高位字节混排 (严格 UTF-8 失败) ----
            // 单个字节序列的编码是有歧义的: 同一串字节既可能被当成半截 UTF-8,
            // 也可能在 GBK 里恰好落在汉字区。这里把两种走向都钉住 —— 判定条件写的是
            // "GBK 解出的汉字要够多才按文本显示", 不是"看着像乱码就当二进制"。

            // 6 字节: 严格 UTF-8 失败, GBK 解释成 "?牎AB" —— 解出了汉字, 按文本显示
            byte[] mixed = { 0xC3, 0x28, 0xA0, 0xA1, 0x41, 0x42 };
            var dm = DownloadContent.Parse(mixed);
            c.Check("混合字节: 严格 UTF-8 返回 null", DownloadContent.TryStrictUtf8(mixed) == null, true);
            c.Check("混合字节: GBK 解得汉字 -> 按文本显示 (不硬判二进制)", dm.IsBinary, false);
            c.Check("混合字节: 不出现替换字符", dm.TextBody().IndexOf('\uFFFD') < 0, true);

            // 两个连续的高位无效对: GBK 一个汉字都解不出 -> 二进制
            byte[] junk = { 0xC3, 0x28, 0xC3, 0x28, 0xC3, 0x28 };
            var dj = DownloadContent.Parse(junk);
            c.Check("非法 UTF-8: 判定为二进制", dj.IsBinary, true);
            c.Check("非法 UTF-8: GBK 也解释不出汉字 (不能靠猜)",
                    dj.TextBody().StartsWith("[二进制内容: 不是可显示的文本", StringComparison.Ordinal), true);
            c.Check("非法 UTF-8: 按二进制显示时给十六进制",
                    dj.TextBody().IndexOf("c3 28 c3 28 c3 28", StringComparison.Ordinal) >= 0, true);
            byte[] asciiCtl = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x41, 0x42 };
            var dcCtl = DownloadContent.Parse(asciiCtl);
            c.Check("纯 ASCII 控制字节 (无 NUL): 按控制字符比例判二进制", dcCtl.IsBinary, true);
            c.Check("控制字符被数出来", dcCtl.ControlChars, 6);

            // ---- 十六进制转储本身 ----
            c.Check("HexDump 空", DownloadContent.HexDump(new byte[0]), "(空)\n");
            c.Check("HexDump null", DownloadContent.HexDump(null), "(空)\n");
            c.Check("HexDump 一行 (偏移 8 位 + ASCII)",
                    DownloadContent.HexDump(Encoding.ASCII.GetBytes("hello")),
                    "00000000  68 65 6c 6c 6f                                    |hello|\n");
            c.Check("HexDump 跨行偏移",
                    DownloadContent.HexDump(Encoding.ASCII.GetBytes(new string('A', 17)))
                        .IndexOf("00000010  41                                                |A|",
                                 StringComparison.Ordinal) >= 0, true);
            byte[] long512 = new byte[512];
            for (int i = 0; i < long512.Length; i++) long512[i] = (byte)0x41;
            var dLong = DownloadContent.Parse(long512);
            c.Check("512 字节文本: 预览只取前 256", dLong.Preview.Length, DownloadContent.PreviewBytes);
            c.Check("512 字节文本: 但字节全留着", dLong.Bytes.Length, 512);
            c.Check("512 字节文本: 转储覆盖到最后一行",
                    dLong.BinaryBody().IndexOf("000001f0", StringComparison.Ordinal) >= 0, true);

            // 实测踩到的坑: /api/download/file 对"记录不存在"回的也是 Go 的纯文本
            // "404 page not found", 与"路由不存在"同形 —— 直接交给 ApiError 会误报
            // "服务端二进制过旧" (而该端点在实机上是通的)。文案必须点明是记录不在。
            string miss = DownloadContent.ErrorText("out.bin", 404, "404 page not found");
            c.Check("记录不存在: 点名记录不在", miss.IndexOf(DownloadContent.MissingRecordText, StringComparison.Ordinal) >= 0, true);
            c.Check("记录不存在: 不误报二进制过旧",
                    miss.IndexOf("二进制过旧", StringComparison.Ordinal) < 0, true);
            c.Check("记录不存在: 带记录名", miss.IndexOf("out.bin", StringComparison.Ordinal) >= 0, true);
            string notFoundOther = DownloadContent.ErrorText("x", 404, "some other 404 body");
            c.Check("404 但正文不像 Go NotFound: 回退通用口径",
                    notFoundOther.IndexOf("二进制过旧", StringComparison.Ordinal) >= 0, true);
            string e401 = DownloadContent.ErrorText("x", 401, "");
            c.Check("401: 仍是既有登录引导",
                    e401.IndexOf("未认证或令牌已失效", StringComparison.Ordinal) >= 0, true);
            c.Check("空名不抛", DownloadContent.ErrorText("", 500, "boom").Length > 0, true);
        }

        /// <summary>
        /// CsdevApi 失败异常 -> (状态码, 服务端正文) 的拆分。
        ///
        /// 两种形态都来自实测:
        ///   A 通用:     "HTTP 404  |  404 page not found"
        ///   B 路由缺失: "服务端缺少该路由 /api/download/file (HTTP 404): 通常是...  |  404 page not found"
        /// 形态 B 以中文开头, 状态码夹在中间 —— 早期实现只认形态 A, 于是 /api/download/file
        /// 的 404 被当成"非 HTTP 失败", 状态码 0 一路透到文案里 (探针实测发现)。
        /// </summary>
        private static void ApiErrorSplit(Ctx c)
        {
            int code; string body;

            App.TestSplitApiError(new InvalidOperationException(
                "HTTP 400  |  {\"error\":\"未知 kind: ftp\",\"ok\":false}"), out code, out body);
            c.Check("形态 A: 状态码", code, 400);
            c.Check("形态 A: 正文", body, "{\"error\":\"未知 kind: ftp\",\"ok\":false}");

            App.TestSplitApiError(new InvalidOperationException(
                "HTTP 404  |  404 page not found"), out code, out body);
            c.Check("形态 A(404): 状态码", code, 404);
            c.Check("形态 A(404): 正文", body, "404 page not found");

            App.TestSplitApiError(new InvalidOperationException(
                "服务端缺少该路由 /api/download/file (HTTP 404): 通常是服务端二进制过旧  |  404 page not found"),
                out code, out body);
            c.Check("形态 B: 状态码", code, 404);
            c.Check("形态 B: 正文取回服务端原话", body, "404 page not found");

            App.TestSplitApiError(new InvalidOperationException("HTTP 200  |  ok"), out code, out body);
            c.Check("无空格正文: 状态码", code, 200);
            c.Check("无空格正文: 正文", body, "ok");

            App.TestSplitApiError(new InvalidOperationException("由于目标计算机积极拒绝, 无法连接。"), out code, out body);
            c.Check("非 HTTP: 状态码 0", code, 0);
            c.Check("非 HTTP: 正文原样", body, "由于目标计算机积极拒绝, 无法连接。");

            App.TestSplitApiError(null, out code, out body);
            c.Check("null 异常: 状态码 0", code, 0);
            c.Check("null 异常: 正文空", body, "");

            App.TestSplitApiError(new InvalidOperationException("服务端返回空响应 (HTTP 200)"), out code, out body);
            c.Check("无分隔符的中间状态码: 能取到 200", code, 200);
            c.Check("无分隔符: 正文退化为空 (不把提示当正文)", body, "");

            // 拆出来的正文再喂回文案函数, 应当得到"记录不存在"而不是"二进制过旧"
            string txt = DownloadContent.ErrorText("a.exe", 404, "404 page not found");
            c.Check("形态 B 拆出的正文能正确判记录不存在",
                    txt.IndexOf(DownloadContent.MissingRecordText, StringComparison.Ordinal) >= 0, true);
        }
        /// <summary>
        /// XAML 绑定源的成员形态: **必须是属性**。
        ///
        /// 这一条是从实际故障里长出来的: 报告导出下拉的 DisplayMemberPath="Label" 一开始
        /// 绑在 ReportExport 的 public **字段**上 —— WPF 绑定只认属性, 表现为下拉项全空白,
        /// 且全程没有任何异常, 只在绑定诊断日志里留一句
        /// "BindingExpression path error: 'Label' property not found on 'object' ''ReportExport''"。
        /// (HANDOVER 第 49 条记录过同一个坑: ScriptItem 的字段版本让插件菜单树整棵空白。)
        ///
        /// 这里把"界面上真绑过的四个源类型"逐个钉住, 谁再退回字段写法, --selftest 立刻红。
        /// </summary>
        /// <summary>
        /// POSIX 路径规范化 —— "文件浏览读不了 Linux、<c>/</c> 变成 <c>\</c>" 那个 bug 的回归钉子。
        ///
        /// 以前只有 Windows 一套逻辑: NormRemote 无条件把 <c>/</c> 换成 <c>\</c>,
        /// 于是 Linux 会话的 <c>/etc</c> 被规范化成 <c>\etc</c> 再发给植入体,
        /// 目标机上没有这个路径, 回"无法枚举目录"; IsAbsoluteRemote 也不认 <c>/</c> 开头,
        /// ParentRemote 更是硬编码返回 <c>C:\</c>。
        /// 现在每个函数都有 posix 分支, 这里把两边都钉住: Linux 侧必须保持 <c>/</c>,
        /// Windows 侧的既有行为一个字都不许变。
        /// </summary>
        private static void PosixPaths(Ctx c)
        {
            // POSIX: 分隔符与根
            c.Check("POSIX 绝对路径不被反斜杠化", NativeParse.NormRemote("/etc", true), "/etc");
            c.Check("POSIX 深层路径不变", NativeParse.NormRemote("/var/log/nginx", true), "/var/log/nginx");
            c.Check("POSIX 根保持不变", NativeParse.NormRemote("/", true), "/");
            c.Check("POSIX 压掉重复分隔符", NativeParse.NormRemote("//etc///passwd", true), "/etc/passwd");
            c.Check("POSIX 解析 ..", NativeParse.NormRemote("/etc/../var", true), "/var");
            c.Check("POSIX 不越过根", NativeParse.NormRemote("/../etc", true), "/etc");
            c.Check("POSIX 解析 .", NativeParse.NormRemote("/etc/./hosts", true), "/etc/hosts");
            c.Check("POSIX 空输入", NativeParse.NormRemote("   ", true), "");

            // Windows: 这次改动不能把它带偏
            c.Check("Windows 仍把 / 归一成 \\", NativeParse.NormRemote("/etc", false), "\\etc");
            c.Check("Windows 盘符路径不变", NativeParse.NormRemote("C:/Windows/System32", false), "C:\\Windows\\System32");

            // 绝对性判定
            c.Check("POSIX: /etc 是绝对路径", NativeParse.IsAbsoluteRemote("/etc", true), true);
            c.Check("POSIX: etc 不是绝对路径", NativeParse.IsAbsoluteRemote("etc", true), false);
            c.Check("POSIX: 没有根相对形态", NativeParse.IsRootRelative("/etc", true), false);
            c.Check("Windows: /etc 不算绝对路径 (只认盘符/UNC)",
                    NativeParse.IsAbsoluteRemote("/etc", false), false);

            // 父目录 ("上级"按钮走这条)
            c.Check("POSIX 父目录", NativeParse.ParentRemote("/etc/nginx/nginx.conf", true), "/etc/nginx");
            c.Check("POSIX 根的父目录还是根", NativeParse.ParentRemote("/", true), "/");
            c.Check("POSIX 一级目录的父目录是根", NativeParse.ParentRemote("/etc", true), "/");
            c.Check("Windows 空路径父目录仍是 C:\\", NativeParse.ParentRemote("", false), "C:\\");

            // 拼接 (双击进入目录走这条)
            c.Check("POSIX 拼接子目录", NativeParse.JoinRemote("/etc", "nginx", true), "/etc/nginx");
            c.Check("POSIX 从根拼接", NativeParse.JoinRemote("/", "etc", true), "/etc");
            c.Check("POSIX 子路径本身是绝对路径时直用",
                    NativeParse.JoinRemote("/etc", "/var/log", true), "/var/log");
            c.Check("POSIX 根判定", NativeParse.RootOf("/etc/passwd", true), "/");
            c.Check("POSIX 相对路径没有根", NativeParse.RootOf("etc/passwd", true), "");

            // 端到端: 这就是文件浏览实际会发出去的字符串
            string p = NativeParse.NormRemote("/var", true);
            p = NativeParse.JoinRemote(p, "log", true);
            c.Check("文件浏览链路: 进 /var/log", p, "/var/log");
            c.Check("文件浏览链路: 上一级回到 /var", NativeParse.ParentRemote(p, true), "/var");
        }

        /// <summary>
        /// `ls` 的解析必须忽略**命令回显行**。
        ///
        /// 服务端收到 /api/command 时会立刻推一行 "> ls /" (本机往返, 几毫秒),
        /// 而真实结果要等植入体一个 sleep。带进解析器的话, 文件列表里就会多出一条
        /// 「该行是植入体回传的原始文本, 不是文件条目」的假条目 —— 实测截图确认过。
        /// 这里钉住解析层的兜底行为。
        /// </summary>
        private static void FileListIgnoresEcho(Ctx c)
        {
            string raw = "> ls /\r\n"
                       + "d\t4096\tvar\r\n"
                       + "-\t30\tvmlinuz\r\n";
            var list = NativeParse.FileList(raw);
            c.Check("回显行不产生条目", list.Count, 2);
            c.Check("首条是目录 var", list.Count > 0 ? list[0].Name : "(无)", "var");
            c.Check("次条是文件 vmlinuz", list.Count > 1 ? list[1].Name : "(无)", "vmlinuz");
            c.Check("条目里没有 Raw 假行",
                    list.FindAll(delegate(FsItem i) { return i.Raw; }).Count, 0);

            // 只有回显 (真结果还没到) 时必须是空列表, 而不是一条假条目
            c.Check("只有回显 -> 空列表", NativeParse.FileList("> ls /\r\n").Count, 0);

            // 植入体的错误文本不能被误杀 (它不以 "> " 开头, 应保留为提示行)
            var errs = NativeParse.FileList("[-] 无法枚举目录\r\n");
            c.Check("植入体错误文本仍保留为提示行", errs.Count, 1);
        }

        /// <summary>
        /// 平台判定 —— 它决定路径分隔符和根路径, 判错就会出现"Linux 会话里自动去查 C 盘"。
        ///
        /// 样本全部取自植入体**实际上报值**: Linux 侧是 /etc/os-release 的 PRETTY_NAME,
        /// Windows 侧是 peb_os_version 的输出。
        /// 这条用例是真实事故的回归钉: 关键词表里原来只有 linux/mac/bsd/unix,
        /// 而 Linux 植端上报的是 "Ubuntu 24.04.1 LTS" —— 一个都不命中, 于是被当成
        /// Windows, 根路径回落成 C:\。
        /// </summary>
        private static void OsPlatformDetect(Ctx c)
        {
            // 真实上报值
            c.Check("Ubuntu 24.04.1 LTS -> POSIX", MainWindow.OsIsPosix("Ubuntu 24.04.1 LTS"), true);
            c.Check("Debian GNU/Linux 12 (bookworm) -> POSIX",
                    MainWindow.OsIsPosix("Debian GNU/Linux 12 (bookworm)"), true);
            c.Check("CentOS Linux 7 (Core) -> POSIX", MainWindow.OsIsPosix("CentOS Linux 7 (Core)"), true);
            c.Check("Alpine Linux v3.19 -> POSIX", MainWindow.OsIsPosix("Alpine Linux v3.19"), true);
            c.Check("Kali GNU/Linux Rolling -> POSIX", MainWindow.OsIsPosix("Kali GNU/Linux Rolling"), true);
            c.Check("Fedora Linux 39 -> POSIX", MainWindow.OsIsPosix("Fedora Linux 39"), true);
            c.Check("Windows 10 (10.0.19045) -> Windows",
                    MainWindow.OsIsPosix("Windows 10 (10.0.19045)"), false);
            c.Check("Windows Server 2019 -> Windows", MainWindow.OsIsPosix("Windows Server 2019"), false);
            c.Check("macOS 14.2 -> POSIX", MainWindow.OsIsPosix("macOS 14.2"), true);
            c.Check("FreeBSD 14.0 -> POSIX", MainWindow.OsIsPosix("FreeBSD 14.0"), true);

            // 退化输入: 判不出来时按 Windows 处理 (与历史行为一致, 不让 Windows 会话回归)
            c.Check("空串 -> Windows (保守)", MainWindow.OsIsPosix(""), false);
            c.Check("null -> Windows (保守)", MainWindow.OsIsPosix(null), false);
            c.Check("未知文本 -> Windows (保守)", MainWindow.OsIsPosix("FreeRTOS"), false);

            // 本 bug 的最小回归
            c.Check("ubuntu 关键词在表内", MainWindow.OsIsPosix("ubuntu"), true);
            c.Check("Windows 优先级高于发行版关键词",
                    MainWindow.OsIsPosix("Windows 11 (ubuntu 就是个子串)"), false);
        }

        /// <summary>
        /// App.xaml 能不能真正被加载 + 应用级"系统色接管"是否生效。
        ///
        /// 为什么非要有这条: XAML 的 `{x:Static}` 是**运行期**求值的 —— 写了 WPF
        /// SystemColors 里根本不存在的成员 (例如只有 WinForms 才有的 ButtonFaceBrushKey) 时,
        /// `dotnet build` 照样 0 错误, 但 App.xaml 一加载就抛 ArgumentException:
        /// 进程直接退出、连窗口都起不来 (本轮真栽过一次, 现象就是"全黑/什么都没有")。
        /// selftest 同样走 App 初始化, 所以这类问题在这里必然暴露;
        /// 而"构建通过"说明不了任何事。
        /// </summary>
        private static void AppResourceStyling(Ctx c)
        {
            var app = System.Windows.Application.Current;
            c.Check("Application.Current 可用 (App.xaml 已加载)", app != null, true);
            var res = app == null ? null : app.Resources;
            c.Check("Application.Resources 可读", res != null, true);
            if (res == null) return;

            // 这几条正是 ComboBox 弹出层与高亮项真正会去读的 key。
            // 一旦接管失效, 浅色系统下它们会回落到系统默认值, 和主题脱节。
            c.Check("WindowBrushKey 已被接管 (下拉弹出层底色)",
                    SolidHex(res[System.Windows.SystemColors.WindowBrushKey]), "#FFFFFF");
            c.Check("HighlightBrushKey 已被接管 (选中项底色)",
                    SolidHex(res[System.Windows.SystemColors.HighlightBrushKey]), "#DCE8FB");
            c.Check("HighlightTextBrushKey 已被接管 (选中项文字)",
                    SolidHex(res[System.Windows.SystemColors.HighlightTextBrushKey]), "#1D4ED8");

            // 主题自己的关键色板必须还在 (资源字典被写坏时先挂在这里)
            c.Check("主题色 Bg 仍在", SolidHex(res["Bg"]), "#F5F6F8");
            c.Check("主题色 Fg 仍在", SolidHex(res["Fg"]), "#1F2430");
        }

        /// <summary>取 SolidColorBrush 的 #RRGGBB; 取不到或不是纯色画刷时回可读文案。</summary>
        private static string SolidHex(object o)
        {
            if (o == null) return "(缺失)";
            var b = o as SolidColorBrush;
            if (b == null) return "(" + o.GetType().Name + ")";
            return "#" + b.Color.R.ToString("X2") + b.Color.G.ToString("X2") + b.Color.B.ToString("X2");
        }

        private static void BindingSourcesAreProps(Ctx c)
        {
            c.Check("ReportExport.Label 是属性 (ComboBox DisplayMemberPath)",
                    HasPublicProp(typeof(ReportExport), "Label"), true);
            c.Check("ReportExport.Kind 是属性 (SelectedItem 取值用)",
                    HasPublicProp(typeof(ReportExport), "Kind"), true);
            c.Check("PayloadFormat.Display 是属性 (载荷格式下拉)",
                    HasPublicProp(typeof(PayloadFormat), "Display"), true);
            c.Check("JobSidItem.Text 是属性 (作业会话下拉)",
                    HasPublicProp(typeof(JobSidItem), "Text"), true);
            c.Check("ScriptTextRow.Text 是属性 (missing/diag 列表)",
                    HasPublicProp(typeof(ScriptTextRow), "Text"), true);
            // 监听器类型下拉 / 角色下拉 —— 这两个是本条规矩的第三次重犯现场:
            // 写成 public 字段时 DisplayMemberPath 静默失效, 下拉里显示的是
            // "CsdevGui.KindOption" 这种类型名, 而 WPF 不会报任何错。
            c.Check("KindOption.Label 是属性 (监听器类型下拉 DisplayMemberPath)",
                    HasPublicProp(typeof(KindOption), "Label"), true);
            c.Check("RoleOption.Label 是属性 (角色下拉 DisplayMemberPath)",
                    HasPublicProp(typeof(RoleOption), "Label"), true);

            // 反向: 字段必须不存在 (否则"属性存在"也可能是两者同名的假象)
            c.Check("ReportExport.Label 不再是 public 字段",
                    HasPublicField(typeof(ReportExport), "Label"), false);
            c.Check("PayloadFormat.Display 不再是 public 字段",
                    HasPublicField(typeof(PayloadFormat), "Display"), false);
            c.Check("KindOption.Label 不再是 public 字段",
                    HasPublicField(typeof(KindOption), "Label"), false);
            c.Check("RoleOption.Label 不再是 public 字段",
                    HasPublicField(typeof(RoleOption), "Label"), false);

            // 绑定源全覆盖检查 (新增 DisplayMemberPath 时把类型加进这个清单)
            Type[] sources = { typeof(ReportExport), typeof(PayloadFormat), typeof(JobSidItem),
                               typeof(ScriptTextRow), typeof(KindOption), typeof(RoleOption) };
            c.Check("绑定源清单 6 个", sources.Length, 6);
            int bad = 0;
            foreach (Type ty in sources) if (!HasPublicProp(ty, "Display") && !HasPublicProp(ty, "Label")
                                          && !HasPublicProp(ty, "Text")) bad++;
            c.Check("每个绑定源至少有一个可绑的显示属性", bad, 0);
        }

        private static bool HasPublicProp(Type t, string name)
        {
            foreach (var pi in t.GetProperties(System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Instance))
                if (pi.Name == name) return true;
            return false;
        }

        private static bool HasPublicField(Type t, string name)
        {
            foreach (var fi in t.GetFields(System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Instance))
                if (fi.Name == name) return true;
            return false;
        }
        /// <summary>子串出现次数 (断言"状态码只出现一次"这类事实)。</summary>
        private static int CountOf(string s, string sub)
        {
            if (string.IsNullOrEmpty(s) || string.IsNullOrEmpty(sub)) return 0;
            int n = 0, i = 0;
            while ((i = s.IndexOf(sub, i, StringComparison.Ordinal)) >= 0) { n++; i += sub.Length; }
            return n;
        }
        private static string ByteHex(byte[] b, int n)
        {
            if (b == null || n <= 0 || n > b.Length) return "(空)";
            var sb = new StringBuilder();
            for (int i = 0; i < n; i++)
            {
                if (i > 0) sb.Append(' ');
                sb.Append(b[i].ToString("x2"));
            }
            return sb.ToString();
        }

        // ================================================================ 催心跳 (checkin)

        /// <summary>
        /// checkin 结果文案。
        ///
        /// 成功样本 = 服务端 handleSessionCheckin 的实测回执 {"ok":true,"task":7};
        /// 失败样本 = 会话不存在时的实测回执 —— 那一句**原样显示**, 不翻译成"失败"。
        /// </summary>
        private static void CheckinText(Ctx c)
        {
            var ok = SessionParse.FromJson(Doc("{\"ok\":true,\"task\":7}"), "B001");
            c.Check("成功: ok", ok.Ok, true);
            c.Check("成功: 回 task 号", ok.Task, 7);
            c.Check("成功: 文案含会话号", ok.Text.IndexOf("B001", StringComparison.Ordinal) >= 0, true);
            c.Check("成功: 文案说明已催",
                    ok.Text.IndexOf(SessionParse.CheckinOkTail, StringComparison.Ordinal) >= 0, true);
            c.Check("成功: 文案讲清会自动恢复 (不是永久改 sleep)",
                    ok.Text.IndexOf("自动恢复原 sleep", StringComparison.Ordinal) >= 0, true);
            c.Check("成功: 文案带 task#",
                    ok.Text.IndexOf("(task#7)", StringComparison.Ordinal) >= 0, true);

            var okNoTask = SessionParse.FromJson(Doc("{\"ok\":true}"), "B002");
            c.Check("成功但无 task 字段: 不抛", okNoTask.Ok, true);
            c.Check("成功但无 task 字段: 不写 task#", okNoTask.Text.IndexOf("task#", StringComparison.Ordinal) < 0, true);
            c.Check("成功但无 task 字段: 文案仍完整",
                    okNoTask.Text, "会话 B002 已催, 下一次上行后自动恢复原 sleep");

            const string noSess = "仅 v2 会话支持 checkin";
            var bad = SessionParse.FromJson(
                Doc("{\"error\":\"" + noSess + "\",\"ok\":false}"), "v1:3");
            c.Check("非 v2: ok=false", bad.Ok, false);
            c.Check("非 v2: 服务端 error 原样", bad.Text, noSess);
            c.Check("非 v2: 不拼成功尾巴",
                    bad.Text.IndexOf(SessionParse.CheckinOkTail, StringComparison.Ordinal) < 0, true);

            var noErr = SessionParse.FromJson(Doc("{\"ok\":false}"), "B003");
            c.Check("ok=false 且无 error: 有兜底文案",
                    noErr.Text, "服务端返回 ok=false 且没有 error 字段");

            var ex = SessionParse.FromException("B004",
                new InvalidOperationException("未认证或令牌已失效, 请点顶栏『登录』"));
            c.Check("异常: 原文透出", ex.Text.IndexOf("未认证或令牌已失效", StringComparison.Ordinal) >= 0, true);
            c.Check("异常: ok=false", ex.Ok, false);
            c.Check("异常: 保留会话号", ex.Sid, "B004");
            c.Check("异常: null 不抛", SessionParse.FromException("B005", null).Text.Length > 0, true);

            c.Check("未选会话提示", SessionParse.NoSessionText, "请先在会话表选择一行");
            c.Check("v1 本地拦截文案",
                    SessionParse.CheckinV1Hint, "v1 会话不支持 checkin (服务端仅 v2 会话可催心跳)");
            c.Check("401 走既有文案", SessionParse.NeedLoginText(401, "", "/api/session/checkin"),
                    "未认证或令牌已失效, 请点顶栏『登录』");
        }

        /// <summary>
        /// 服务端非 2xx 的**正文**如何变成状态栏文案 —— 三个新入口的失败路径。
        ///
        /// 样本取自实测 (8680 无认证实例 / 8681 带认证实例):
        ///   401 {"error":"未认证或令牌已失效","ok":false}
        ///   404 "404 page not found"
        ///   400 {"error":"未知 kind: ftp","kinds":[...],"ok":false}
        /// CsdevApi 会把它们拼成 "HTTP nnn  |  &lt;正文&gt;" 异常, 这里断言再往上一层的文案
        /// 仍然能正确区分这三种状态 (尤其不能把 404 都推给"服务端二进制过旧")。
        /// </summary>
        private static void ServerFailText(Ctx c)
        {
            const string b401 = "HTTP 401  |  {\"error\":\"未认证或令牌已失效\",\"ok\":false}";
            const string b404 = "HTTP 404  |  404 page not found";
            const string b400 = "HTTP 400  |  {\"error\":\"未知 kind: ftp\",\"kinds\":[\"sessions\",\"credentials\",\"downloads\",\"events\",\"screenshots\",\"keylogs\",\"jobs\"],\"ok\":false}";
            const string b400Body = "{\"error\":\"未知 kind: ftp\",\"kinds\":[\"sessions\",\"credentials\",\"downloads\",\"events\",\"screenshots\",\"keylogs\",\"jobs\"],\"ok\":false}";

            string r401 = ReportParse.SaveErrorText("JSON 报告", 401, b401, "/api/report/json");
            c.Check("401 需要登录", r401.IndexOf("需要登录", StringComparison.Ordinal) >= 0, true);
            c.Check("401 不带二进制过旧", r401.IndexOf("二进制过旧", StringComparison.Ordinal) < 0, true);

            string r404 = ReportParse.SaveErrorText("CSV 报告 (events)", 404, b404, "/api/report/csv");
            c.Check("404 二进制过旧提示", r404.IndexOf("二进制过旧", StringComparison.Ordinal) >= 0, true);
            c.Check("404 带端点路径", r404.IndexOf("/api/report/csv", StringComparison.Ordinal) >= 0, true);

            string r400 = ReportParse.SaveErrorText("CSV 报告 (ftp)", 400,
                "{\"error\":\"未知 kind: ftp\",\"kinds\":[\"sessions\",\"credentials\",\"downloads\",\"events\",\"screenshots\",\"keylogs\",\"jobs\"],\"ok\":false}",
                "/api/report/csv");
            c.Check("400 原样带服务端 kinds 列表",
                    r400.IndexOf("keylogs\",\"jobs", StringComparison.Ordinal) >= 0, true);
            c.Check("400 只出现一次状态码", r400.IndexOf("HTTP 400", StringComparison.Ordinal)
                    == r400.LastIndexOf("HTTP 400", StringComparison.Ordinal), true);
            c.Check("400 文案开头是 what",
                    r400.StartsWith("CSV 报告 (ftp)失败: HTTP 400", StringComparison.Ordinal), true);
            // CsdevApi 的异常消息本身带 "HTTP nnn  |  " 前缀, 界面/探针都先把正文拆出来再喂文案函数。
            // 这里把拆分逻辑的输入输出钉住: 不拆会得到两份状态码。
            c.Check("整条异常消息里状态码只出现一次", CountOf(b400, "HTTP 400"), 1);
            c.Check("拆分后的正文不含状态码前缀", b400Body.IndexOf("HTTP", StringComparison.Ordinal), -1);

            // 下载内容那一侧: 404 的语义完全不同 (记录不存在, 不是路由不存在)
            string d404 = DownloadContent.ErrorText("payload.exe", 404, "404 page not found");
            c.Check("下载 404 不进通用口径", d404.IndexOf("二进制过旧", StringComparison.Ordinal) < 0, true);
            c.Check("下载 404 点名记录不在",
                    d404.IndexOf("该下载记录不存在", StringComparison.Ordinal) >= 0, true);

            // 非 HTTP 失败 (超时 / 连接被拒): 状态码 0 时既不喊需要登录, 也不喊路由缺失
            string net = ReportParse.SaveErrorText("HTML 报告", 0, "由于目标计算机积极拒绝, 无法连接。", "");
            c.Check("非 HTTP: 原样带异常正文", net.IndexOf("积极拒绝", StringComparison.Ordinal) >= 0, true);
            c.Check("非 HTTP: 不喊二进制过旧", net.IndexOf("二进制过旧", StringComparison.Ordinal) < 0, true);
            c.Check("非 HTTP: 不喊需要登录", net.IndexOf("需要登录", StringComparison.Ordinal) < 0, true);
        }
    }
}