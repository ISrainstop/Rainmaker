using System;
using System.Collections.Generic;
using System.Text;
using System.Text.Json;

namespace CsdevGui
{
    // ---------------------------------------------------------------- 菜单模型

    /// <summary>
    /// 插件菜单的挂载位置。由 /api/scripts 的 popup parent 决定:
    /// beacon / beacon_top / beacon_bottom -> 会话右键菜单;
    /// processbrowser -> 进程浏览器右键; targets -> 目标库右键;
    /// 其余 (aggressor/view/payloads/attacks/sitemgmt/reporting/help/ssh/pgraph/
    /// keystrokes/screenshots/downloads/filebrowser ...) -> 「脚本插件」子菜单。
    /// </summary>
    public enum ScriptMount { Session, Process, Targets, Plugin }

    /// <summary>菜单栏登记项 (menubar("显示名","popup id"))。</summary>
    public sealed class MenuBarEntry
    {
        public string Label = "";        // 原样 (含 & 助记符)
        public string Text = "";         // 去助记符后的显示名
        public string Id = "";

        public override string ToString() { return Text + " -> " + Id; }
    }

    /// <summary>
    /// 一个菜单项。字段与 go/aggressor_c2.go menuSummary 的输出一一对应:
    /// name / action / kind / children, 缺失字段按"无子项 / 不可执行"降级。
    ///
    /// <b>必须是属性而不是字段</b>: 这些成员由 XAML 直接绑定
    /// (TreeView 的 HierarchicalDataTemplate 绑 Children 与 Text), 而 WPF 绑定
    /// 只能解析 public 属性 —— 写成 public 字段时绑定静默失败, 表现是
    /// 菜单树整棵空白, 只有开着 CSDEV_GUI_TRACE=1 才在日志里看到
    /// "property not found on ... 'ScriptItem'"。
    /// </summary>
    public sealed class ScriptItem
    {
        public string Parent { get; set; } = "";           // 所属 popup 名 (挂载点)
        public string Raw { get; set; } = "";              // 服务端原样 name (含 &)
        public string Text { get; set; } = "";             // 去助记符后的显示名
        public string Command { get; set; } = "";          // 候选命令名 (Text 去首尾空白)
        public string Kind { get; set; } = "item";         // item / menu / sep (未知值原样保留)
        public bool Action { get; set; }                   // 服务端 action: 该项是否带可执行体
        public int Depth { get; set; }
        public List<ScriptItem> Children { get; set; } = new List<ScriptItem>();

        public bool HasChildren { get { return Children.Count > 0; } }

        /// <summary>分隔线 (渲染为 Separator)。</summary>
        public bool IsSep { get { return string.Equals(Kind, "sep", StringComparison.OrdinalIgnoreCase); } }

        /// <summary>带子项 -> 渲染为子菜单 (body 无从触发, 见 HANDOVER 能力边界)。</summary>
        public bool IsSubmenu { get { return HasChildren; } }

        /// <summary>可点击项: 有执行体且不是分隔线。有子项时由子菜单承载, 本体不点击。</summary>
        public bool CanRun { get { return Action && !IsSep && !HasChildren; } }

        /// <summary>服务端明确说没有执行体 (灰显, 不静默变成一个"点了没反应"的项)。</summary>
        public bool Inert { get { return !IsSep && !Action && !HasChildren; } }

        public override string ToString() { return Kind + ":" + Text; }
    }

    /// <summary>一个 popup 定义 (挂载点 + 其下的菜单树)。</summary>
    public sealed class ScriptMenu
    {
        public string Parent = "";
        public ScriptMount Mount = ScriptMount.Plugin;
        public List<ScriptItem> Items = new List<ScriptItem>();

        /// <summary>递归计数: 项 / 子菜单 / 分隔线。</summary>
        public void Count(ref int items, ref int menus, ref int seps)
        {
            CountIn(Items, ref items, ref menus, ref seps);
        }

        private static void CountIn(List<ScriptItem> list, ref int items, ref int menus, ref int seps)
        {
            foreach (ScriptItem it in list)
            {
                if (it.IsSep) seps++;
                else if (it.HasChildren) menus++;
                else items++;
                if (it.HasChildren) CountIn(it.Children, ref items, ref menus, ref seps);
            }
        }
    }

    // ---------------------------------------------------------------- 解析结果

    /// <summary>GET /api/scripts 的解析结果。字段缺失一律降级为空集合, 不抛异常。</summary>
    public sealed class ScriptSummary
    {
        public bool Present;                                   // 服务端是否返回了合法对象
        public readonly List<string> Loaded = new List<string>();
        public readonly List<string> Commands = new List<string>();
        public readonly List<string> Missing = new List<string>();
        public readonly List<string> Diag = new List<string>();
        public readonly List<string> Output = new List<string>();
        public readonly List<MenuBarEntry> MenuBar = new List<MenuBarEntry>();
        public readonly List<ScriptMenu> Menus = new List<ScriptMenu>();

        public int ItemCount;      // 叶子可点击/惰性项
        public int MenuCount;      // 带子项的子菜单
        public int SepCount;       // 分隔线
        public int SessionMounts;  // 挂到会话右键的 popup 数
        public int ProcessMounts;
        public int TargetMounts;
        public int PluginMounts;

        /// <summary>总菜单项 (递归, 含子菜单与分隔线)。</summary>
        public int TotalItems { get { return ItemCount + MenuCount + SepCount; } }

        public string CommandsText()
        {
            return Commands.Count == 0 ? "(无)" : string.Join(", ", Commands.ToArray());
        }

        public string MountsText()
        {
            return "会话 " + SessionMounts + " · 进程 " + ProcessMounts
                 + " · 目标库 " + TargetMounts + " · 脚本插件 " + PluginMounts;
        }
    }

    // ---------------------------------------------------------------- 纯函数解析层

    /// <summary>
    /// /api/scripts 的解析层 (Aggressor 插件菜单 / 命令 / 诊断)。
    ///
    /// 与 UI 解耦 (只依赖 BCL 与 System.Text.Json), 因此
    /// <c>csdev-gui.exe --selftest</c> 能在无窗口环境下逐样本断言。
    ///
    /// 依据 (只读核对 go/, 未修改):
    ///   go/aggressor_c2.go menuSummary  -> "parent" + "items"[{name,action,kind,children}]
    ///   go/aggressor_c2.go handleScripts-> loaded[] / commands[] / menubar[{label,id}] /
    ///                                      missing[] / diag[] / output[]
    ///   go/aggressor.go   menuItem.Kind -> "item" / "menu" / "sep"
    ///   go/v2_api.go      scriptSummary -> /api/state.scripts = {loaded:数字, commands[], menus:数字}
    /// </summary>
    public static class ScriptParse
    {
        // ------------------------------------------------------------ 助记符

        /// <summary>
        /// 去掉 Windows 菜单助记符标记: 单个 <c>&amp;</c> 是"下一个字符为快捷键"的标记,
        /// 显示时删除; <c>&amp;&amp;</c> 表示一个字面 <c>&amp;</c>。
        /// 例: "&amp;Interact" -> "Interact", "E&amp;xport Data" -> "Export Data",
        /// "A&amp;&amp;B" -> "A&amp;B", 末尾孤立 "&amp;" -> 删除。
        /// </summary>
        public static string StripMnemonic(string name)
        {
            if (string.IsNullOrEmpty(name)) return "";
            var sb = new StringBuilder(name.Length);
            for (int i = 0; i < name.Length; i++)
            {
                char ch = name[i];
                if (ch != '&') { sb.Append(ch); continue; }
                if (i + 1 < name.Length && name[i + 1] == '&') { sb.Append('&'); i++; continue; }
                // 单个 &: 助记符标记本身不显示
            }
            return sb.ToString();
        }

        // ------------------------------------------------------------ 挂载点

        /// <summary>popup parent -> 挂载点。</summary>
        public static ScriptMount MountOf(string parent)
        {
            string p = (parent ?? "").Trim().ToLowerInvariant();
            if (p == "beacon" || p.StartsWith("beacon_", StringComparison.Ordinal)) return ScriptMount.Session;
            if (p == "processbrowser") return ScriptMount.Process;
            if (p == "targets") return ScriptMount.Targets;
            return ScriptMount.Plugin;
        }

        public static string MountLabel(ScriptMount m)
        {
            switch (m)
            {
                case ScriptMount.Session: return "会话右键";
                case ScriptMount.Process: return "进程浏览器右键";
                case ScriptMount.Targets: return "目标库右键";
                default: return "脚本插件子菜单";
            }
        }

        // ------------------------------------------------------------ 字符串数组

        /// <summary>把 JSON 字符串数组读成 List: 字符串原样, 数字取原文, 其余跳过。</summary>
        public static List<string> StrList(JsonElement owner, string field)
        {
            var list = new List<string>();
            var v = owner.Field(field);
            if (v.ValueKind != JsonValueKind.Array) return list;
            foreach (var e in v.EnumerateArray())
            {
                if (e.ValueKind == JsonValueKind.String)
                {
                    string s = e.GetString();
                    if (s != null) list.Add(s);
                }
                else if (e.ValueKind == JsonValueKind.Number)
                {
                    list.Add(e.GetRawText());
                }
            }
            return list;
        }

        // ------------------------------------------------------------ 菜单树

        /// <summary>解析 menus 数组 (含 menubar)。</summary>
        public static ScriptSummary Parse(JsonElement root)
        {
            var s = new ScriptSummary();
            if (root.ValueKind != JsonValueKind.Object) return s;
            s.Present = true;

            s.Loaded.AddRange(StrList(root, "loaded"));
            s.Commands.AddRange(StrList(root, "commands"));
            s.Missing.AddRange(StrList(root, "missing"));
            s.Diag.AddRange(StrList(root, "diag"));
            s.Output.AddRange(StrList(root, "output"));

            foreach (var e in root.Arr("menubar"))
            {
                var m = new MenuBarEntry();
                m.Label = e.Str("label");
                m.Id = e.Str("id");
                m.Text = StripMnemonic(m.Label);
                s.MenuBar.Add(m);
            }

            foreach (var e in root.Arr("menus"))
            {
                // 非对象元素直接跳过 (与 ItemsIn 同一套容错口径): 否则会凭空多出一个空 parent 的根节点
                if (e.ValueKind != JsonValueKind.Object) continue;
                var md = new ScriptMenu();
                md.Parent = e.Str("parent");
                md.Mount = MountOf(md.Parent);
                md.Items = ItemsIn(e.Arr("items"), md.Parent, 0);
                s.Menus.Add(md);

                switch (md.Mount)
                {
                    case ScriptMount.Session: s.SessionMounts++; break;
                    case ScriptMount.Process: s.ProcessMounts++; break;
                    case ScriptMount.Targets: s.TargetMounts++; break;
                    default: s.PluginMounts++; break;
                }
            }

            int items = 0, menus = 0, seps = 0;
            foreach (ScriptMenu md in s.Menus) md.Count(ref items, ref menus, ref seps);
            s.ItemCount = items;
            s.MenuCount = menus;
            s.SepCount = seps;
            return s;
        }

        /// <summary>把一串菜单项元素递归读成对象 (children 缺失/非数组 = 叶子)。</summary>
        public static List<ScriptItem> ItemsIn(IEnumerable<JsonElement> seq, string parent, int depth)
        {
            var list = new List<ScriptItem>();
            if (seq == null) return list;

            foreach (var e in seq)
            {
                if (e.ValueKind != JsonValueKind.Object) continue;
                var it = new ScriptItem();
                it.Parent = parent ?? "";
                it.Raw = e.Str("name");
                it.Kind = e.Str("kind", "item");
                if (it.Kind.Length == 0) it.Kind = "item";
                it.Action = e.Bool("action");
                it.Depth = depth;
                it.Text = StripMnemonic(it.Raw);
                it.Command = it.Text.Trim();

                var ch = e.Field("children");
                if (ch.ValueKind == JsonValueKind.Array)
                    it.Children = ItemsIn(ch.EnumerateArray(), parent, depth + 1);
                list.Add(it);
            }
            return list;
        }

        // ------------------------------------------------------------ 命令匹配

        /// <summary>
        /// 菜单项名是否为脚本命令名 (精确匹配, 不区分大小写)。
        ///
        /// 依据: handleScriptRun 走 a.RunCommand(name, ...) —— 命中命令表才执行,
        /// 未命中回 "未找到脚本命令 &lt;name&gt;"。因此只有与 command 同名的菜单项
        /// 才能经 REST 真正执行, 其余如实报错 (不静默吞掉)。
        /// </summary>
        public static bool IsCommand(List<string> commands, string name)
        {
            if (commands == null || string.IsNullOrEmpty(name)) return false;
            for (int i = 0; i < commands.Count; i++)
            {
                if (string.Equals(commands[i], name, StringComparison.OrdinalIgnoreCase)) return true;
            }
            return false;
        }

        /// <summary>找一个挂载点下所有可执行项 (供"命令可双击执行"列表与自测使用)。</summary>
        public static List<ScriptItem> RunnableItems(ScriptSummary s)
        {
            var outList = new List<ScriptItem>();
            if (s == null) return outList;
            foreach (ScriptMenu md in s.Menus) Collect(md.Items, outList);
            return outList;
        }

        private static void Collect(List<ScriptItem> list, List<ScriptItem> outList)
        {
            foreach (ScriptItem it in list)
            {
                if (it.CanRun) outList.Add(it);
                if (it.HasChildren) Collect(it.Children, outList);
            }
        }

        // ------------------------------------------------------------ 菜单树视图模型

        /// <summary>
        /// 脚本视图 TreeView 的根: 每个 popup parent 一个根节点, 文案标注它的右键挂载位置。
        /// 同一 parent 多次声明时合并到同一个根 (保序); 根按「挂载点 -> parent 名」排序,
        /// 保证同一份脚本状态每次都得到完全相同的树 (结构未变时 GUI 不重建树, 展开态得以保留)。
        /// </summary>
        public static List<ScriptItem> Roots(ScriptSummary s)
        {
            var roots = new List<ScriptItem>();
            if (s == null) return roots;

            var index = new Dictionary<string, ScriptItem>(StringComparer.OrdinalIgnoreCase);
            foreach (ScriptMenu md in s.Menus)
            {
                ScriptItem root;
                if (!index.TryGetValue(md.Parent, out root))
                {
                    root = new ScriptItem();
                    root.Parent = md.Parent;
                    root.Raw = md.Parent;
                    root.Kind = "root";
                    root.Text = RootText(md.Parent, md.Mount);
                    index[md.Parent] = root;
                    roots.Add(root);
                }
                root.Children.AddRange(md.Items);
            }
            roots.Sort(delegate(ScriptItem a, ScriptItem b)
            {
                int ma = (int)MountOf(a.Parent), mb = (int)MountOf(b.Parent);
                if (ma != mb) return ma - mb;
                return string.Compare(a.Parent, b.Parent, StringComparison.OrdinalIgnoreCase);
            });
            return roots;
        }

        /// <summary>根节点文案: "beacon   [会话右键]"; parent 为空时如实标注。</summary>
        public static string RootText(string parent, ScriptMount mount)
        {
            string p = parent ?? "";
            if (p.Length == 0) p = "(无 parent)";
            return p + "   [" + MountLabel(mount) + "]";
        }

        /// <summary>
        /// 菜单树结构签名 (parent / 名字 / 类型 / action / 层级)。
        /// 相同则 GUI 不重建 TreeView —— 刷新与轮询都不会打断展开态与选中。
        /// </summary>
        public static string TreeSignature(ScriptSummary s)
        {
            var sb = new StringBuilder();
            if (s == null) return "";
            foreach (ScriptMenu md in s.Menus)
            {
                sb.Append(md.Parent).Append('\u0001');
                SigIn(md.Items, sb);
            }
            return sb.ToString();
        }

        private static void SigIn(List<ScriptItem> list, StringBuilder sb)
        {
            foreach (ScriptItem it in list)
            {
                sb.Append(it.Raw).Append('\u0002').Append(it.Kind).Append('\u0002')
                  .Append(it.Action ? '1' : '0').Append('\u0003');
                if (it.HasChildren) SigIn(it.Children, sb);
            }
        }

        /// <summary>某命令名在菜单树里出现几次 (命中说明右键点击也能执行到它)。</summary>
        public static string CmdHitText(ScriptSummary s, string name)
        {
            if (s == null) return "-";
            int n = 0;
            foreach (ScriptItem it in RunnableItems(s))
            {
                if (string.Equals(it.Command, name, StringComparison.OrdinalIgnoreCase)) n++;
            }
            return n > 0 ? n + " 项" : "-";
        }

        // ------------------------------------------------------------ 差分签名

        /// <summary>
        /// /api/state.scripts 的差分签名 (loaded 计数 / menus 计数 / commands 列表)。
        /// 与上次相同就不必再拉一次 GET /api/scripts —— 轮询仍是单定时器 2 秒。
        /// 服务端未返回 scripts 块时返回空串 (此时不主动拉取, 如实显示未提供)。
        /// </summary>
        public static string StateSignature(JsonElement stateRoot)
        {
            var sc = stateRoot.Field("scripts");
            if (sc.ValueKind != JsonValueKind.Object) return "";
            return "L" + sc.Long("loaded") + " M" + sc.Long("menus")
                 + " C[" + string.Join(",", StrList(sc, "commands").ToArray()) + "]";
        }

        /// <summary>/api/state.scripts 是否提供了命令数组 (旧版服务端可能只给计数)。</summary>
        public static bool StateHasCommands(JsonElement stateRoot)
        {
            var sc = stateRoot.Field("scripts");
            if (sc.ValueKind != JsonValueKind.Object) return false;
            return sc.Field("commands").ValueKind == JsonValueKind.Array;
        }

        // ------------------------------------------------------------ 执行结果文案

        /// <summary>
        /// 把 /api/script/run 或 /api/script/menu 的响应转成一句可读结果 (原样带上服务端 error)。
        /// </summary>
        public static string RunResultText(bool ok, string error, string name)
        {
            if (ok) return "已执行脚本菜单项: " + name;
            string e = (error ?? "").Trim();
            if (e.Length == 0) return "脚本项 " + name + " 失败 (服务端未返回 error 字段)";
            if (e.IndexOf("未找到脚本命令", StringComparison.Ordinal) >= 0)
            {
                return "脚本未执行: " + e
                     + "  (该名字不在命令表里; 插件菜单项应走 /api/script/menu 按 parent+name 定位)";
            }
            return "脚本项 " + name + " 返回错误: " + e;
        }

        /// <summary>
        /// /api/script/menu 响应里的 warnings 数组 -> 一行提示。
        /// 这些是"本引擎没有 CS 客户端私有 UI, 执行时跳过的函数", 必须显示出来,
        /// 否则操作员会以为菜单项完整跑通了。
        /// </summary>
        public static string WarniText(JsonElement root)
        {
            try
            {
                JsonElement arr;
                if (!root.TryGetProperty("warnings", out arr) || arr.ValueKind != JsonValueKind.Array) return "";
                int n = arr.GetArrayLength();
                if (n == 0) return "";
                var sb = new StringBuilder();
                int i = 0;
                foreach (var x in arr.EnumerateArray())
                {
                    if (i++ >= 3) { sb.Append(" …"); break; }
                    if (sb.Length > 0) sb.Append("; ");
                    sb.Append(x.GetString());
                }
                return "[已跳过 " + n + " 项] " + sb;
            }
            catch { return ""; }
        }
    }

    // ---------------------------------------------------------------- 视图行模型

    /// <summary>脚本视图里的通用文本行 (缺失函数 / 加载诊断 / 脚本输出共用)。</summary>
    public sealed class ScriptTextRow : RowBase, IKeyed
    {
        private string _kind = "", _text = "", _key = "";

        public string Kind { get { return _kind; } set { if (Set(ref _kind, value ?? "", nameof(Kind))) Notify(nameof(KindText)); } }
        public string Text { get { return _text; } set { Set(ref _text, value ?? "", nameof(Text)); } }
        public string Key { get { return _key; } set { Set(ref _key, value ?? "", nameof(Key)); } }

        public string KindText
        {
            get
            {
                if (_kind == "missing") return "未实现";
                if (_kind == "diag") return "诊断";
                return "输出";
            }
        }
    }

    /// <summary>脚本注册命令的一行 (可双击执行, $1 = 当前会话号)。</summary>
    public sealed class ScriptCmdRow : RowBase, IKeyed
    {
        private string _name = "", _hit = "";

        /// <summary>命令名 (服务端 CommandNames, 精确匹配)。</summary>
        public string Name { get { return _name; } set { if (Set(ref _name, value ?? "", nameof(Name))) Notify(nameof(Key)); } }

        /// <summary>同名菜单项个数提示 (有的话说明右键点击也能命中)。</summary>
        public string Hit { get { return _hit; } set { Set(ref _hit, value ?? "", nameof(Hit)); } }

        public string Key { get { return "cmd|" + _name; } }
    }

    /// <summary>已加载脚本的一行 (服务端返回绝对/相对路径)。</summary>
    public sealed class ScriptFileRow : RowBase, IKeyed
    {
        private string _path = "", _name = "";

        public string Path { get { return _path; } set { if (Set(ref _path, value ?? "", nameof(Path))) Notify(nameof(Key)); } }

        /// <summary>文件名 (展示用, 完整路径进 ToolTip)。</summary>
        public string Name
        {
            get { return _name; }
            set { Set(ref _name, value ?? "", nameof(Name)); }
        }

        public string Key { get { return "f|" + _path; } }

        /// <summary>从路径取文件名; 空路径降级为原样文本。</summary>
        public static string BaseName(string path)
        {
            string p = (path ?? "").Trim();
            if (p.Length == 0) return "";
            int i = p.LastIndexOfAny(new char[] { '\\', '/' });
            if (i < 0) return p;
            return i + 1 < p.Length ? p.Substring(i + 1) : p;
        }
    }
}
