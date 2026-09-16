using System;
using System.Collections.Generic;
using System.Text;
using System.Text.Json;
using System.Windows.Media;

namespace CsdevGui
{
    // ---------------------------------------------------------------- 插件包

    /// <summary>
    /// GET /api/plugins 的一个"插件包"(目录或散装 .cna)。
    ///
    /// 字段与 go/plugins.go pluginInfo 一一对应:
    ///   name / path / kind(dir|file) / main / files / bytes / loaded / menus / err / has_main
    ///
    /// 服务端口径(只读核对 go/plugins.go, 未修改):
    ///   loaded  = 该包路径在当前选中集合里(不等于"加载成功");
    ///   menus   = 只在"已选中 且 有主文件"时被计算, 其余情况恒为 0;
    ///   has_main= 目录包是否找到同名主文件 —— 散装 .cna 恒为 false 但 main 非空。
    /// 因此"能不能勾选加载"的判据是 <b>main 非空</b>, 不是 has_main。
    /// </summary>
    public sealed class PluginPack : RowBase, IKeyed
    {
        private string _name = "", _path = "", _kind = "", _main = "", _err = "";
        private long _files, _bytes, _menus;
        private bool _loaded, _hasMain, _checked;

        /// <summary>显示名 (目录名或文件名)。</summary>
        public string Name { get { return _name; } set { Set(ref _name, value ?? "", nameof(Name)); } }

        /// <summary>绝对路径 (选中/加载用的就是它)。</summary>
        public string Path { get { return _path; } set { Set(ref _path, value ?? "", nameof(Path)); } }

        /// <summary>服务端原样 kind: "dir" / "file" (未知值原样保留)。</summary>
        public string Kind { get { return _kind; } set { Set(ref _kind, value ?? "", nameof(Kind)); } }

        /// <summary>实际入口 .cna (服务端 pluginResolveMain 的结果)。为空 = 无法加载。</summary>
        public string Main { get { return _main; } set { Set(ref _main, value ?? "", nameof(Main)); } }

        /// <summary>服务端 err 字段原文 (main 为空的原因), 界面上原样显示而不是吞掉。</summary>
        public string Err { get { return _err; } set { Set(ref _err, value ?? "", nameof(Err)); } }

        /// <summary>包内 .cna 个数。</summary>
        public long Files { get { return _files; } set { if (Set(ref _files, value, nameof(Files))) Notify(nameof(FilesText)); } }

        /// <summary>包内 .cna 总字节。</summary>
        public long Bytes { get { return _bytes; } set { if (Set(ref _bytes, value, nameof(Bytes))) Notify(nameof(SizeText)); } }

        /// <summary>当前贡献的菜单项数 (未选中或未加载时服务端恒回 0)。</summary>
        public long Menus { get { return _menus; } set { if (Set(ref _menus, value, nameof(Menus))) { Notify(nameof(MenusText)); Notify(nameof(MenusBrush)); } } }

        /// <summary>服务端 loaded 字段 = 在当前选中集合里。</summary>
        public bool Loaded { get { return _loaded; } set { if (Set(ref _loaded, value, nameof(Loaded))) { Notify(nameof(StatusText)); Notify(nameof(StatusBrush)); Notify(nameof(RowBrush)); } } }

        /// <summary>服务端 has_main 字段 (仅目录包有意义)。</summary>
        public bool HasMain { get { return _hasMain; } set { Set(ref _hasMain, value, nameof(HasMain)); } }

        /// <summary>
        /// 界面勾选态 = 操作员的意图。取值分两层:
        ///   有未应用的勾选改动时以改动为准 (见 PluginParse.Rows 的 pending 覆盖),
        ///   否则 = 服务端 loaded (刷新列表不会擅自改掉操作员的勾选)。
        /// </summary>
        public bool Checked { get { return _checked; } set { Set(ref _checked, value, nameof(Checked)); } }

        /// <summary>行主键: 路径优先, 无路径时退化为名字 (路径为空的行仍不丢)。</summary>
        public string Key { get { return "p|" + (_path.Length > 0 ? _path : _name); } }

        /// <summary>可勾选加载: 服务端给出了入口文件。main 为空时勾选会被服务端整单回错。</summary>
        public bool Selectable { get { return _main.Length > 0; } }

        /// <summary>不可勾选的原因 (ToolTip 用, 原样带服务端 err)。</summary>
        public string BlockWhy
        {
            get
            {
                if (Selectable) return "";
                if (_err.Length > 0) return _err;
                return "服务端没有给出可加载的主文件 (main 为空), 无法勾选加载";
            }
        }

        /// <summary>类型列: 服务端 kind 的中文注记 (未知值降级为原样, 空为 "-")。</summary>
        public string KindText
        {
            get
            {
                string k = _kind.Trim().ToLowerInvariant();
                if (k == "dir") return "目录";
                if (k == "file") return "文件";
                return _kind.Length > 0 ? _kind : "-";
            }
        }

        public string FilesText { get { return _files.ToString(); } }

        /// <summary>包内 .cna 总字节 (负数/缺失降级为 "-", 由 Fmt.Size 负责)。</summary>
        public string SizeText { get { return _bytes < 0 ? "-" : Fmt.Size(_bytes); } }

        /// <summary>菜单项数列 (menus=0 有两种可能: 未选中, 或已选中但该包没注册菜单项)。</summary>
        public string MenusText { get { return _menus.ToString(); } }

        /// <summary>当前是否在服务端选中集合里。</summary>
        public string StatusText { get { return _loaded ? "已选中" : "未选中"; } }

        /// <summary>主文件 / 错误信息列: 有 err 原样显示 err, 否则显示主文件名。</summary>
        public string DetailText
        {
            get
            {
                if (_err.Length > 0) return _err;
                if (_main.Length > 0) return ScriptFileRow.BaseName(_main);
                return "(服务端未给出主文件)";
            }
        }

        /// <summary>完整信息 (ToolTip): 路径 / 主文件 / 原始 kind / err 都不隐藏。</summary>
        public string TooltipText
        {
            get
            {
                var sb = new StringBuilder();
                sb.Append("名称: ").Append(_name.Length > 0 ? _name : "(无)");
                sb.Append("\n路径: ").Append(_path.Length > 0 ? _path : "(无)");
                sb.Append("\n类型: ").Append(_kind.Length > 0 ? _kind : "(无)")
                  .Append("    has_main=").Append(_hasMain ? "true" : "false");
                sb.Append("\n主文件: ").Append(_main.Length > 0 ? _main : "(无)");
                sb.Append("\n包内 .cna: ").Append(_files).Append(" 个 / ").Append(SizeText);
                sb.Append("\n当前: ").Append(StatusText).Append("    menus=").Append(_menus);
                if (_err.Length > 0) sb.Append("\n服务端 err: ").Append(_err);
                if (!Selectable) sb.Append("\n不可勾选: ").Append(BlockWhy);
                return sb.ToString();
            }
        }

        public Brush StatusBrush { get { return _loaded ? Palette.Ok : Palette.Dim; } }

        public Brush MenusBrush { get { return _menus > 0 ? Palette.Ok : Palette.Dim; } }

        /// <summary>整行前景: 不可勾选(需要人工看 err) 用警示色, 已选中用正常色, 其余淡色。</summary>
        public Brush RowBrush
        {
            get
            {
                if (!Selectable) return Palette.Warn;
                return _loaded ? Palette.Fg : Palette.Dim;
            }
        }
    }

    // ---------------------------------------------------------------- 手工添加的脚本 (external)

    /// <summary>
    /// GET /api/plugins 的 external 条目: **选中集合里不在插件根目录下的路径** ——
    /// 也就是操作员用『浏览…(选 .cna 文件)』手工挑进来的脚本。
    ///
    /// 字段与 go/plugins.go pluginExternal 一一对应:
    ///   path / name / exists / files / bytes / menus / err(omitempty)
    /// 服务端口径 (只读核对 go/plugins.go pluginExternals, 未修改):
    ///   os.Stat 失败           -> exists=false, err="路径不存在(可能被移动或删除)", files/bytes/menus 全 0;
    ///   目录存在但入口定位失败 -> exists=true **且** err 非空 (pluginResolveMain 的错误原文);
    ///   menus 只在引擎里真的加载了它时才非 0 (与包列表同一口径)。
    /// 为什么必须回显: 这些路径同样被服务端持久化, 重启后引擎照常加载它们 ——
    /// 界面不回显就是"看不见的加载", 想卸载都找不到入口。
    ///
    /// Local=true 是 GUI 侧叠加的状态 (服务端不知道"对话框刚选中、还没提交"的路径):
    /// 此时 exists / menus 都还没有实测值, 面板如实标成『本地登记』而不是编造一个"存在"。
    /// </summary>
    public sealed class PluginExternalRow : RowBase, IKeyed
    {
        private string _path = "", _name = "", _err = "";
        private long _files, _bytes, _menus;
        private bool _exists, _local, _hasExists;

        /// <summary>绝对路径 (提交 / 移除用的就是它)。</summary>
        public string Path { get { return _path; } set { Set(ref _path, value ?? "", nameof(Path)); } }

        /// <summary>显示名 (服务端 name, 通常是文件名/目录名)。</summary>
        public string Name { get { return _name; } set { Set(ref _name, value ?? "", nameof(Name)); } }

        /// <summary>服务端 err 原文 (路径失效 / 入口定位失败), 原样显示不吞。</summary>
        public string Err
        {
            get { return _err; }
            set { if (Set(ref _err, value ?? "", nameof(Err))) { Notify(nameof(DetailText)); Notify(nameof(ExistsText)); Notify(nameof(ExistsBrush)); Notify(nameof(RowBrush)); } }
        }

        public long Files { get { return _files; } set { if (Set(ref _files, value, nameof(Files))) { Notify(nameof(FilesText)); Notify(nameof(DetailText)); } } }

        /// <summary>字节数 (缺失记 -1, 展示层据此显示 "-", 不用 0 B 冒充)。</summary>
        public long Bytes { get { return _bytes; } set { if (Set(ref _bytes, value, nameof(Bytes))) { Notify(nameof(SizeText)); Notify(nameof(DetailText)); } } }

        public long Menus { get { return _menus; } set { if (Set(ref _menus, value, nameof(Menus))) { Notify(nameof(MenusText)); Notify(nameof(MenusBrush)); } } }

        /// <summary>服务端 exists 字段 (os.Stat 成功)。</summary>
        public bool Exists { get { return _exists; } set { if (Set(ref _exists, value, nameof(Exists))) { Notify(nameof(ExistsText)); Notify(nameof(ExistsBrush)); Notify(nameof(RowBrush)); Notify(nameof(DetailText)); } } }

        /// <summary>
        /// 服务端到底给没给 exists 字段。缺字段时不能宣称"路径已失效"
        /// (那是把"未知"说成"确定不存在"), 面板如实标成"状态未知"。
        /// 正常响应里 pluginExternal 的 exists 无 omitempty, 恒有值。
        /// </summary>
        public bool HasExists { get { return _hasExists; } set { if (Set(ref _hasExists, value, nameof(HasExists))) { Notify(nameof(ExistsText)); Notify(nameof(ExistsBrush)); Notify(nameof(RowBrush)); } } }

        /// <summary>GUI 侧标记: 对话框刚选中、还没有服务端实测值的路径。</summary>
        public bool Local { get { return _local; } set { if (Set(ref _local, value, nameof(Local))) { Notify(nameof(ExistsText)); Notify(nameof(ExistsBrush)); Notify(nameof(RowBrush)); Notify(nameof(DetailText)); } } }

        public string Key { get { return "x|" + (_path.Length > 0 ? _path : _name); } }

        /// <summary>是否存在列: 服务端才是权威; 本地登记的如实标注未实测。</summary>
        public string ExistsText
        {
            get
            {
                if (_local) return "本地登记";
                if (!_hasExists) return "状态未知";
                if (!_exists) return "路径已失效";
                if (_err.Length > 0) return "存在·无入口";
                return "存在";
            }
        }

        public string FilesText { get { return _files.ToString(); } }

        public string SizeText { get { return _bytes < 0 ? "-" : Fmt.Size(_bytes); } }

        public string MenusText { get { return _menus.ToString(); } }

        /// <summary>详情列: err 原样 > 本地说明 > 文件数/大小。</summary>
        public string DetailText
        {
            get
            {
                if (_err.Length > 0) return _err;
                if (_local) return "等待『应用选择』提交 (服务端提交时会校验路径存在性)";
                if (_bytes < 0) return _files + " 个文件";
                return _files + " 个文件 / " + SizeText;
            }
        }

        /// <summary>完整信息 (ToolTip): 路径 / 存在性 / 菜单贡献 / err / 移除说明都不隐藏。</summary>
        public string TooltipText
        {
            get
            {
                var sb = new StringBuilder();
                sb.Append("名称: ").Append(_name.Length > 0 ? _name : "(无)");
                sb.Append("\n路径: ").Append(_path.Length > 0 ? _path : "(无)")
                  .Append("\n这是手工添加的脚本 (不在插件根目录下)");
                sb.Append("\n存在性: ").Append(ExistsText);
                if (!_local)
                {
                    sb.Append("\n包内 .cna: ").Append(_files).Append(" 个 / ").Append(SizeText);
                    sb.Append("\n贡献菜单项: ").Append(_menus);
                }
                else
                {
                    sb.Append("\n还没提交: 服务端尚未回显 exists / menus, 点『应用选择』才会实测");
                }
                if (_err.Length > 0) sb.Append("\n服务端 err: ").Append(_err);
                if (!_local && _hasExists && !_exists) sb.Append("\n路径已失效: 文件被移动或删除, 引擎下次重建时它加载不了 —— 点『移除』后『应用选择』即可卸载。");
                else if (!_local && !_hasExists) sb.Append("\n服务端没给 exists 字段: 存在性未知。");
                else sb.Append("\n点『移除』把这条从待提交集合里去掉, 之后『应用选择』即卸载它。");
                return sb.ToString();
            }
        }

        public Brush MenusBrush { get { return _menus > 0 ? Palette.Ok : Palette.Dim; } }

        /// <summary>存在性列的着色: 失效=红, 无入口=橙, 本地未实测=蓝, 状态未知=灰, 正常=绿。</summary>
        public Brush ExistsBrush
        {
            get
            {
                if (_local) return Palette.Accent;
                if (!_hasExists) return Palette.Dim;
                if (!_exists) return Palette.Err;
                if (_err.Length > 0) return Palette.Warn;
                return Palette.Ok;
            }
        }

        /// <summary>整行前景: 失效=红, 无入口=橙, 本地登记=蓝, 状态未知=灰, 正常=白。</summary>
        public Brush RowBrush
        {
            get
            {
                if (_local) return Palette.Accent;
                if (!_hasExists) return Palette.Dim;
                if (!_exists) return Palette.Err;
                if (_err.Length > 0) return Palette.Warn;
                return Palette.Fg;
            }
        }
    }

    // ---------------------------------------------------------------- 解析结果

    /// <summary>
    /// GET /api/plugins 的解析结果。字段缺失一律降级为空集合 / 零值, 不抛异常。
    /// 服务端在"插件目录未配置/不存在"时也回 HTTP 200 + ok=false + error, 所以
    /// Present 与 Ok 必须分开看: Present=响应是对象, Ok=服务端说这次列表有效。
    /// </summary>
    public sealed class PluginView
    {
        /// <summary>响应是 JSON 对象 (false = 根本不是对象)。</summary>
        public bool Present;

        /// <summary>服务端 ok 字段。</summary>
        public bool Ok;

        /// <summary>ok=false 时的原因 (原样)。</summary>
        public string Error = "";

        /// <summary>服务端当前插件根目录 (可能为空 = 未配置)。</summary>
        public string Root = "";

        public readonly List<PluginPack> Plugins = new List<PluginPack>();

        /// <summary>服务端 external[]: 手工挑的、不在插件根下的路径 (含失效条目)。</summary>
        public readonly List<PluginExternalRow> External = new List<PluginExternalRow>();

        public readonly List<string> Selected = new List<string>();
        public readonly List<string> Loaded = new List<string>();

        /// <summary>
        /// selected 里有、但既不在 plugins 列表里、也不在 external 列表里的路径
        /// (插件目录换过、或手工添加的脚本被删掉后的残留)。
        /// external 里的路径**不算残留** —— 它们本来就是"不在插件根下"的合法选中项。
        /// </summary>
        public readonly List<string> SelectedMissing = new List<string>();

        public int SelectableCount;    // 可勾选 (main 非空)
        public int BlockedCount;       // 无主文件, 不可勾选
        public int LoadedCount;        // 服务端 loaded=true 的包数
        public long MenusTotal;        // 已选中包贡献的菜单项合计
        public int ExternalBroken;     // external 里 exists=false 的条目数 (路径已失效)
        public long ExternalMenus;     // external 贡献的菜单项合计

        /// <summary>一句话摘要 (标题 / 状态栏 / 自测复用), 说清"有多少包 / 加载出来什么 / 已加载多少个脚本文件"。</summary>
        public string StatsText()
        {
            if (!Present) return "服务端响应不是 JSON 对象 —— 插件列表不可用";
            if (!Ok)
            {
                return "插件列表不可用: "
                     + (Error.Length > 0 ? Error : "服务端返回 ok=false 但未给出 error 字段")
                     + (Root.Length > 0 ? "  (root=" + Root + ")" : "");
            }

            var sb = new StringBuilder();
            sb.Append("插件根 ").Append(Root.Length > 0 ? Root : "(服务端未配置)")
              .Append("   包 ").Append(Plugins.Count).Append(" 个 (可勾选 ").Append(SelectableCount)
              .Append(" · 无主文件 ").Append(BlockedCount).Append(")")
              .Append("   当前选中 ").Append(LoadedCount).Append(" 个")
              .Append("   已选中贡献菜单项 ").Append(MenusTotal)
              .Append("   已加载脚本文件 ").Append(Loaded.Count).Append(" 个");
            if (External.Count > 0)
            {
                sb.Append("   服务端 external ").Append(External.Count).Append(" 个");
                sb.Append(" (失效 ").Append(ExternalBroken).Append(" · 贡献菜单项 ").Append(ExternalMenus).Append(")");
            }
            if (SelectedMissing.Count > 0)
            {
                sb.Append("   [警告] selected 里 ").Append(SelectedMissing.Count)
                  .Append(" 个路径不在当前插件根的列表里 (插件目录换过?): ")
                  .Append(string.Join(" · ", SelectedMissing.ToArray()));
            }
            return sb.ToString();
        }

        /// <summary>插件根的一行展示 (空 = 如实说明服务端未配置)。</summary>
        public string RootText()
        {
            return Root.Length > 0 ? Root : "(服务端未配置插件目录, 启动加 --plugins-dir <目录>)";
        }
    }

    /// <summary>POST /api/plugin/set 的响应 (ok / error / selected / loaded / commands)。</summary>
    public sealed class PluginSetResult
    {
        public bool Present;                       // 响应是 JSON 对象
        public bool Ok;
        public string Error = "";
        public readonly List<string> Selected = new List<string>();
        public readonly List<string> Loaded = new List<string>();
        public readonly List<string> Commands = new List<string>();
    }

    // ---------------------------------------------------------------- 纯函数解析层

    /// <summary>
    /// /api/plugins 与 /api/plugin/set 的解析层 (插件包级选择加载)。
    ///
    /// 与 UI 解耦 (只依赖 BCL / System.Text.Json / 冻结画刷), 因此
    /// <c>csdev-gui.exe --selftest</c> 能在无窗口环境下逐样本断言:
    /// 包列表 / 无主文件的 err 包 / selected 残留路径 / 空列表 / 字段缺失降级 /
    /// 应用结果文案 / 勾选态与待应用覆盖。
    ///
    /// 依据 (只读核对 go/plugins.go, 未修改):
    ///   handlePlugins   -> {ok, root, plugins[{name,path,kind,main,files,bytes,loaded,menus,err,has_main}], selected[], loaded[]}
    ///   失败形态        -> HTTP 200 + {ok:false, error, root}(未配置/目录不存在)
    ///   handlePluginSet -> {ok, selected[], loaded[], commands[]}; 失败 {ok:false, error}
    ///                      paths=[] = 全部卸载; root 非空 = 先改插件根再重建
    /// </summary>
    public static class PluginParse
    {
        /// <summary>解析 GET /api/plugins 响应。</summary>
        public static PluginView Parse(JsonElement root)
        {
            var v = new PluginView();
            if (root.ValueKind != JsonValueKind.Object) return v;
            v.Present = true;
            v.Ok = root.Bool("ok");
            v.Error = root.Str("error");
            v.Root = root.Str("root");

            v.Selected.AddRange(ScriptParse.StrList(root, "selected"));
            v.Loaded.AddRange(ScriptParse.StrList(root, "loaded"));

            foreach (var e in root.Arr("plugins"))
            {
                if (e.ValueKind != JsonValueKind.Object) continue;   // 非对象元素跳过, 不凭空造包
                var p = new PluginPack();
                p.Name = e.Str("name");
                p.Path = e.Str("path");
                p.Kind = e.Str("kind");
                p.Main = e.Str("main");
                p.Err = e.Str("err");
                p.Files = e.Long("files");
                // bytes 缺失记 -1: 展示层据此显示 "-"(服务端没给), 不用 "0 B" 冒充空包
                p.Bytes = e.Field("bytes").ValueKind == JsonValueKind.Undefined ? -1 : e.Long("bytes");
                p.Menus = e.Long("menus");
                p.Loaded = e.Bool("loaded");
                p.HasMain = e.Bool("has_main");

                // 既无名字又无路径的行无法作为勾选/展示对象, 丢弃 (正常响应里不会出现)
                if (p.Name.Length == 0 && p.Path.Length == 0) continue;
                if (p.Name.Length == 0) p.Name = ScriptFileRow.BaseName(p.Path);
                p.Checked = p.Loaded;      // 初始勾选态 = 服务端当前选择
                v.Plugins.Add(p);
            }

            // 手工添加的脚本 (不在插件根下的选中项): 同样要回显, 否则"加载了什么"看不见
            foreach (var e in root.Arr("external"))
            {
                if (e.ValueKind != JsonValueKind.Object) continue;
                var x = new PluginExternalRow();
                x.Path = e.Str("path");
                x.Name = e.Str("name");
                x.Err = e.Str("err");
                x.Files = e.Long("files");
                x.Bytes = e.Field("bytes").ValueKind == JsonValueKind.Undefined ? -1 : e.Long("bytes");
                x.Menus = e.Long("menus");
                // 只认真正的布尔值: 类型不符 (如 "exists":"yes") 降级为"未知", 不冒充"已失效"
                JsonValueKind ek = e.Field("exists").ValueKind;
                x.HasExists = ek == JsonValueKind.True || ek == JsonValueKind.False;
                x.Exists = e.Bool("exists");
                if (x.Path.Length == 0 && x.Name.Length == 0) continue;
                if (x.Name.Length == 0) x.Name = ScriptFileRow.BaseName(x.Path);
                v.External.Add(x);
                if (!x.Exists) v.ExternalBroken++;
                v.ExternalMenus += x.Menus;
            }

            // selected 里既不在 packages 也不在 external 里的路径: 如实列出 (插件目录换过会有残留)
            foreach (string s in v.Selected)
            {
                if (s == null || s.Trim().Length == 0) continue;
                if (Find(v.Plugins, s) != null) continue;
                if (PluginParse.FindExternal(v.External, s) != null) continue;
                if (ContainsPath(v.SelectedMissing, s)) continue;
                v.SelectedMissing.Add(s);
            }

            foreach (PluginPack p in v.Plugins)
            {
                if (p.Selectable) v.SelectableCount++;
                else v.BlockedCount++;
                if (p.Loaded)
                {
                    v.LoadedCount++;
                    v.MenusTotal += p.Menus;
                }
            }
            return v;
        }

        /// <summary>解析 POST /api/plugin/set 响应。</summary>
        public static PluginSetResult ParseSet(JsonElement root)
        {
            var r = new PluginSetResult();
            if (root.ValueKind != JsonValueKind.Object) return r;
            r.Present = true;
            r.Ok = root.Bool("ok");
            r.Error = root.Str("error");
            r.Selected.AddRange(ScriptParse.StrList(root, "selected"));
            r.Loaded.AddRange(ScriptParse.StrList(root, "loaded"));
            r.Commands.AddRange(ScriptParse.StrList(root, "commands"));
            return r;
        }

        /// <summary>
        /// 构造界面行集合。pending 是"已勾选但还没应用"的覆盖表 (键 = 包路径, 区分大小写与非区分
        /// 大小写各查一次), 有覆盖时以覆盖为准 —— 这样刷新列表不会把操作员的勾选改动冲掉。
        /// </summary>
        public static List<PluginPack> Rows(PluginView v, IDictionary<string, bool> pending)
        {
            var rows = new List<PluginPack>();
            if (v == null) return rows;
            foreach (PluginPack p in v.Plugins)
            {
                bool val;
                if (Lookup(pending, p, out val)) p.Checked = val;
                rows.Add(p);
            }
            return rows;
        }

        private static bool Lookup(IDictionary<string, bool> pending, PluginPack p, out bool val)
        {
            val = false;
            if (pending == null) return false;
            if (pending.TryGetValue(p.Path, out val)) return true;
            // 路径大小写在不同来源下可能不一致 (服务端 filepath.Abs 保留原样), 再试一次忽略大小写的兜底
            foreach (var kv in pending)
            {
                if (string.Equals(kv.Key, p.Path, StringComparison.OrdinalIgnoreCase)) { val = kv.Value; return true; }
            }
            return false;
        }

        /// <summary>
        /// 勾选且可加载的包路径 (服务端要求的绝对路径), 按列表顺序。
        /// 不可勾选的行即使被 pending 置了 true 也不会进这条路径表 ——
        /// 服务端对"不能定位入口"的包是整单回错, 不能让一行坏包废掉整次应用。
        /// </summary>
        public static List<string> PickedPaths(IEnumerable<PluginPack> rows)
        {
            var list = new List<string>();
            if (rows == null) return list;
            foreach (PluginPack p in rows)
            {
                if (!p.Checked || !p.Selectable) continue;
                if (p.Path.Trim().Length == 0) continue;
                list.Add(p.Path);
            }
            return list;
        }

        /// <summary>勾选计数 (与 PickedPaths 同一口径: 只数真正会提交的包)。</summary>
        public static int PickedCount(IEnumerable<PluginPack> rows)
        {
            return PickedPaths(rows).Count;
        }

        // ------------------------------------------------------------ 手工添加的路径

        /// <summary>
        /// 最终提交的 paths = 目录里勾选的包 + 『浏览…』手工挑进来的路径。
        ///
        /// 去重规则: 路径首尾空白先修掉, 之后**忽略大小写**比较 —— Windows 下同一条路径
        /// 可能从服务端回显 (`filepath.Abs` 保留原样) 与文件对话框里拿到两种写法, 不忽略
        /// 大小写就会把同一个文件提交两次。保留**首次出现的原文写法**(即勾选包优先)。
        /// dropped 里的路径 (被『移除』过的手工条目) 不进提交表 —— 这就是"移除后应用即卸载它"。
        /// </summary>
        public static List<string> MergePaths(IEnumerable<string> picked, IEnumerable<string> extras, ICollection<string> dropped)
        {
            var list = new List<string>();
            AddMissing(list, picked, dropped);
            AddMissing(list, extras, dropped);
            return list;
        }

        private static void AddMissing(List<string> acc, IEnumerable<string> src, ICollection<string> dropped)
        {
            if (src == null) return;
            foreach (string raw in src)
            {
                string p = (raw ?? "").Trim();
                if (p.Length == 0) continue;
                if (IsDropped(dropped, p)) continue;
                if (ContainsPath(acc, p)) continue;
                acc.Add(p);
            }
        }

        /// <summary>路径是否在"已移除"集合里 (忽略大小写与首尾空白)。</summary>
        public static bool IsDropped(ICollection<string> dropped, string path)
        {
            if (dropped == null) return false;
            string p = (path ?? "").Trim();
            if (p.Length == 0) return false;
            foreach (string d in dropped)
            {
                if (string.Equals((d ?? "").Trim(), p, StringComparison.OrdinalIgnoreCase)) return true;
            }
            return false;
        }

        /// <summary>在路径表里找同一条路径 (忽略大小写与首尾空白) 的下标; 找不到回 -1。</summary>
        public static int IndexOfPath(IList<string> list, string path)
        {
            string p = (path ?? "").Trim();
            if (list == null || p.Length == 0) return -1;
            for (int i = 0; i < list.Count; i++)
            {
                if (string.Equals((list[i] ?? "").Trim(), p, StringComparison.OrdinalIgnoreCase)) return i;
            }
            return -1;
        }

        /// <summary>
        /// 面板要显示的 external 行集合 = 服务端 external[] ∪ 本地手工登记(还没提交)∪ 去重;
        /// 命中 dropped 的不显示 (它已被操作员移除, 待应用即卸载)。
        /// 同一路径以**服务端条目优先** —— 它带 exists / files / menus 实测值, 本地条目只有路径。
        /// </summary>
        public static List<PluginExternalRow> ExternalRows(PluginView v, IEnumerable<string> extras, ICollection<string> dropped)
        {
            var rows = new List<PluginExternalRow>();
            if (v != null)
            {
                foreach (PluginExternalRow x in v.External)
                {
                    if (IsDropped(dropped, x.Path)) continue;
                    if (FindExternal(rows, x.Path) != null) continue;   // 服务端自己也重复时只留一条
                    rows.Add(x);
                }
            }
            if (extras != null)
            {
                foreach (string raw in extras)
                {
                    string p = (raw ?? "").Trim();
                    if (p.Length == 0) continue;
                    if (IsDropped(dropped, p)) continue;
                    if (FindExternal(rows, p) != null) continue;
                    var x = new PluginExternalRow();
                    x.Path = p;
                    x.Name = ScriptFileRow.BaseName(p);
                    x.Bytes = -1;        // 服务端还没给字节数
                    x.Local = true;
                    rows.Add(x);
                }
            }
            return rows;
        }

        /// <summary>external 面板标题栏的一行摘要 (空集合也说清楚, 不显示半截)。</summary>
        public static string ExternalSummaryText(List<PluginExternalRow> rows)
        {
            int n = rows == null ? 0 : rows.Count;
            if (n == 0) return "手工添加 0 个";
            int broken = 0, local = 0;
            long menus = 0;
            foreach (PluginExternalRow r in rows)
            {
                if (r.Local) local++;
                else if (!r.Exists) broken++;
                menus += r.Menus;
            }
            var sb = new StringBuilder();
            sb.Append("手工添加 ").Append(n).Append(" 个");
            sb.Append(" (失效 ").Append(broken).Append(" · 贡献菜单项 ").Append(menus);
            if (local > 0) sb.Append(" · 本地待提交 ").Append(local);
            sb.Append(')');
            return sb.ToString();
        }

        /// <summary>面板的操作提示 (随"有没有失效条目 / 有没有本地待提交"变化)。</summary>
        public static string ExternalHint(List<PluginExternalRow> rows)
        {
            if (rows == null || rows.Count == 0)
                return "点『浏览…(选 .cna 文件)』挑任意位置 .cna (可多选), 与勾选的包合并提交; 服务端会在提交时校验路径。";
            int broken = 0, local = 0;
            foreach (PluginExternalRow r in rows)
            {
                if (r.Local) local++;
                else if (!r.Exists) broken++;
            }
            var sb = new StringBuilder();
            sb.Append("『移除』只登记意图, 点『应用选择』才卸载。");
            if (local > 0) sb.Append(" 有 ").Append(local).Append(" 个本地待提交条目 (还没生效)。");
            if (broken > 0) sb.Append(" 有 ").Append(broken).Append(" 个路径已失效 (文件被移动或删除), 建议移除后应用。");
            return sb.ToString();
        }

        /// <summary>从 external 行集合里按路径找 (忽略大小写与首尾空白)。</summary>
        public static PluginExternalRow FindExternal(List<PluginExternalRow> list, string path)
        {
            string want = (path ?? "").Trim();
            if (list == null || want.Length == 0) return null;
            for (int i = 0; i < list.Count; i++)
            {
                if (string.Equals(list[i].Path, want, StringComparison.OrdinalIgnoreCase)) return list[i];
            }
            return null;
        }

        /// <summary>
        /// 一条可读的应用结果 (失败时原样带出服务端 error, 不静默)。
        /// picked = 本次提交的包数 (paths 数组长度)。
        /// </summary>
        public static string SetResultText(PluginSetResult r, int picked)
        {
            if (r == null || !r.Present)
                return "应用插件选择失败: 服务端响应不是 JSON 对象 (勾选 " + picked
                     + " 个包;『刷新列表』可核对服务端当前选择)";

            if (r.Ok)
            {
                return "已应用插件选择: 勾选 " + picked + " 个包 / 服务端选中 " + r.Selected.Count
                     + " 个 / 已加载脚本 " + r.Loaded.Count + " 个文件 / 命令 " + r.Commands.Count
                     + " 个 (引擎已重建, 菜单树/命令/诊断已刷新)";
            }

            string why = r.Error.Length > 0 ? r.Error : "服务端返回 ok=false 但未给出 error 字段";
            return "应用插件选择失败: " + why + " (勾选 " + picked
                 + " 个包;『刷新列表』可核对服务端当前选择)";
        }

        /// <summary>切换插件根的结果文案 (服务端不回声 root, 用请求里的路径如实复述)。</summary>
        public static string RootSetText(PluginSetResult r, string root, int picked)
        {
            if (r != null && r.Present && r.Ok)
            {
                return "插件目录已切换为 " + (root ?? "") + ": 服务端选中 " + r.Selected.Count
                     + " 个包 / 已加载脚本 " + r.Loaded.Count + " 个文件 / 命令 " + r.Commands.Count + " 个";
            }
            return "切换插件目录失败: " + SetResultText(r, picked);
        }

        private static PluginPack Find(List<PluginPack> list, string path)
        {
            string want = (path ?? "").Trim();
            for (int i = 0; i < list.Count; i++)
            {
                if (string.Equals(list[i].Path, want, StringComparison.OrdinalIgnoreCase)) return list[i];
            }
            return null;
        }

        private static bool ContainsPath(List<string> list, string path)
        {
            for (int i = 0; i < list.Count; i++)
            {
                if (string.Equals(list[i], path, StringComparison.OrdinalIgnoreCase)) return true;
            }
            return false;
        }
    }
}
