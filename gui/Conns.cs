using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.Json;

namespace CsdevGui
{
    /// <summary>
    /// 登录门到主窗口之间传递"已认证会话"的载体。
    ///
    /// 用静态属性而不是给 MainWindow 加构造参数: 后者会牵动 selftest、自动附着钩子
    /// 以及所有构造点, 而真正要传的只有地址 / 令牌 / 用户 / 角色四个值。
    /// 只在 App.OnStartup 里登录成功后写一次, MainWindow 构造时读一次。
    ///
    /// 令牌只活在进程内存里, 不落盘 (与 ConnEntry 的口令策略一致)。
    /// </summary>
    public static class PreAuth
    {
        public static string BaseUrl = "";
        public static string Token = "";
        public static string User = "";
        public static string Role = "";

        public static bool Has { get { return BaseUrl.Length > 0 && Token.Length > 0; } }

        public static void Clear()
        {
            BaseUrl = ""; Token = ""; User = ""; Role = "";
        }
    }

    /// <summary>
    /// 一条保存过的服务端连接。
    ///
    /// **只存地址与用户名**。口令不落盘是硬约束: 明文口令写进配置文件等于把服务端
    /// 管理口令留在用户的磁盘上 (还会被备份/同步工具带走), 而登录本身只花一次输入 ——
    /// 所以每次连接时由 LoginDialog 现取现用, 用完只在内存里换成 Bearer 令牌。
    /// 本类型没有口令字段, 序列化也只写 url/user 两个键 (见 <see cref="ConnStore.Serialize"/>),
    /// 这不是"小心别写错", 而是从数据结构上就没有可写的地方。
    /// </summary>
    public sealed class ConnEntry
    {
        /// <summary>规范化后的服务端地址 (带 scheme, 无末尾斜杠)。</summary>
        public string Url = "";

        /// <summary>该地址上次登录用的操作员名 (仅用于预填登录框, 不是凭据)。</summary>
        public string User = "";

        /// <summary>是否已写入磁盘。内存里临时连过的地址 Saved=false, 下拉里如实标注。</summary>
        public bool Saved;

        /// <summary>下拉里显示的文本。</summary>
        public string Display
        {
            get
            {
                string u = (User ?? "").Length > 0 ? User : "(未填用户名)";
                return (Url ?? "") + "  ·  " + u + (Saved ? "" : "  ·  未保存");
            }
        }

        /// <summary>
        /// 可编辑 ComboBox 选中一项时, 文本框内容取的是选中项的 ToString()
        /// (本类故意不用 DisplayMemberPath —— 那会把"地址 · 用户名"整串灌进地址框)。
        /// </summary>
        public override string ToString() { return Url ?? ""; }
    }

    /// <summary>
    /// 连接配置的读写与去重 (纯逻辑, 无 UI 依赖 —— --selftest 直接用临时目录断言往返)。
    ///
    /// 落盘位置: <c>%APPDATA%\csdev\connections.json</c>
    /// <code>
    /// { "version": 1, "connections": [ { "url": "http://127.0.0.1:8443", "user": "admin" } ] }
    /// </code>
    /// 读取对损坏/缺字段/类型不符一律降级为空表 (或跳过坏条目), 不抛异常 ——
    /// 一个坏掉的配置文件不该让 GUI 起不来。
    /// </summary>
    public static class ConnStore
    {
        /// <summary>列表为空时的默认地址 (与服务端默认监听端口一致)。</summary>
        public const string DefaultUrl = "http://127.0.0.1:8443";

        public const int Version = 1;

        /// <summary>配置文件路径: %APPDATA%\csdev\connections.json。</summary>
        public static string DefaultPath()
        {
            string dir = "";
            try { dir = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData); }
            catch { }
            if (string.IsNullOrEmpty(dir))
            {
                try { dir = Path.GetTempPath(); } catch { dir = "."; }
            }
            return Path.Combine(dir, "csdev", "connections.json");
        }

        /// <summary>
        /// 地址规范化。规则与 <see cref="CsdevApi.BaseUrl"/> 的 setter **完全一致**
        /// (去首尾空白 → 去末尾斜杠 → 空则回默认 → 缺 scheme 补 http://):
        /// 两处规则一旦分叉, 就会出现"下拉里存了一个地址、连的却是另一个"的鬼问题。
        /// selftest 里对这两个实现做了逐样本对照。
        /// </summary>
        public static string Normalize(string url)
        {
            string v = (url ?? "").Trim().TrimEnd('/');
            if (v.Length == 0) return DefaultUrl;
            if (!v.StartsWith("http://", StringComparison.OrdinalIgnoreCase) &&
                !v.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                v = "http://" + v;
            return v;
        }

        /// <summary>去重键: 规范化 + 大小写不敏感 (主机名与 scheme 都不区分大小写)。</summary>
        public static string KeyOf(string url) { return Normalize(url).ToLowerInvariant(); }

        /// <summary>解析配置文件内容; 任何异常/异构输入都降级为空表。</summary>
        public static List<ConnEntry> Parse(string json)
        {
            var list = new List<ConnEntry>();
            if (string.IsNullOrWhiteSpace(json)) return list;
            try
            {
                using (var doc = JsonDocument.Parse(json))
                {
                    var root = doc.RootElement;
                    if (root.ValueKind != JsonValueKind.Object) return list;

                    foreach (var el in root.Arr("connections"))
                    {
                        if (el.ValueKind != JsonValueKind.Object) continue;   // 非对象条目跳过
                        string url = el.Str("url");
                        if (url.Trim().Length == 0) continue;                 // 没地址的条目无意义
                        var e = new ConnEntry();
                        e.Url = Normalize(url);
                        e.User = (el.Str("user") ?? "").Trim();
                        e.Saved = true;
                        AddIfNew(list, e);                                    // 文件里写重复也去重
                    }
                }
            }
            catch { }
            return list;
        }

        /// <summary>
        /// 序列化。只写 version / connections[].url / connections[].user —— 显式白名单,
        /// 没有口令字段可写。selftest 会断言输出里不含口令相关的键名与口令明文。
        /// </summary>
        public static string Serialize(IList<ConnEntry> list)
        {
            using (var ms = new MemoryStream())
            {
                using (var w = new Utf8JsonWriter(ms, new JsonWriterOptions { Indented = true }))
                {
                    w.WriteStartObject();
                    w.WriteNumber("version", Version);
                    w.WriteStartArray("connections");
                    if (list != null)
                    {
                        for (int i = 0; i < list.Count; i++)
                        {
                            var e = list[i];
                            if (e == null || (e.Url ?? "").Trim().Length == 0) continue;
                            w.WriteStartObject();
                            w.WriteString("url", Normalize(e.Url));
                            w.WriteString("user", (e.User ?? "").Trim());
                            w.WriteEndObject();
                        }
                    }
                    w.WriteEndArray();
                    w.WriteEndObject();
                }
                return Encoding.UTF8.GetString(ms.ToArray());
            }
        }

        /// <summary>读文件。不存在或损坏都回空表 (调用方再用 EnsureDefault 补默认项)。</summary>
        public static List<ConnEntry> Load(string path)
        {
            try
            {
                if (!File.Exists(path)) return new List<ConnEntry>();
                return Parse(File.ReadAllText(path, Encoding.UTF8));
            }
            catch { return new List<ConnEntry>(); }
        }

        /// <summary>
        /// 只保留已落盘的条目。内存里那条"列表为空时补的默认地址" (Saved=false) 是给下拉
        /// 用的占位, 不该被写进配置文件 —— 否则用户什么都没做, 文件里就凭空多出一条。
        /// </summary>
        public static List<ConnEntry> SavedOnly(IList<ConnEntry> list)
        {
            var keep = new List<ConnEntry>();
            if (list == null) return keep;
            for (int i = 0; i < list.Count; i++)
            {
                var e = list[i];
                if (e == null || !e.Saved) continue;
                if ((e.Url ?? "").Trim().Length == 0) continue;
                keep.Add(e);
            }
            return keep;
        }

        /// <summary>
        /// 写文件 (临时文件 + 覆盖改名, 避免写一半留下半个 JSON); 只写 <see cref="SavedOnly"/> 那一份。
        /// 返回空串 = 成功; 非空 = 直接可显示的错误原因。
        /// </summary>
        public static string Save(string path, IList<ConnEntry> list)
        {
            try
            {
                string dir = Path.GetDirectoryName(path);
                if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);

                string tmp = path + ".tmp";
                File.WriteAllText(tmp, Serialize(SavedOnly(list)), new UTF8Encoding(false));
                File.Move(tmp, path, true);
                return "";
            }
            catch (Exception ex) { return ex.Message; }
        }

        /// <summary>
        /// 插入或更新一条 (按规范化地址去重)。已存在则更新用户名并**移到首位**
        /// (最近使用在前), 用户名留空时不覆盖已保存的名字。返回该条目。
        /// </summary>
        public static ConnEntry Upsert(List<ConnEntry> list, string url, string user)
        {
            if (list == null) return null;
            string key = KeyOf(url);
            string u = (user ?? "").Trim();

            for (int i = 0; i < list.Count; i++)
            {
                if (!string.Equals(KeyOf(list[i].Url), key, StringComparison.Ordinal)) continue;
                list[i].Url = Normalize(url);
                if (u.Length > 0) list[i].User = u;
                list[i].Saved = true;
                var hit = list[i];
                if (i != 0) { list.RemoveAt(i); list.Insert(0, hit); }
                return hit;
            }

            var e = new ConnEntry();
            e.Url = Normalize(url);
            e.User = u;
            e.Saved = true;
            list.Insert(0, e);
            return e;
        }

        /// <summary>删除一条 (按规范化地址匹配)。返回是否真的删掉了一条。</summary>
        public static bool Remove(List<ConnEntry> list, string url)
        {
            if (list == null) return false;
            string key = KeyOf(url);
            for (int i = 0; i < list.Count; i++)
            {
                if (!string.Equals(KeyOf(list[i].Url), key, StringComparison.Ordinal)) continue;
                list.RemoveAt(i);
                return true;
            }
            return false;
        }

        /// <summary>按规范化地址找条目 (下拉选中恢复用)。</summary>
        public static ConnEntry Find(List<ConnEntry> list, string url)
        {
            if (list == null) return null;
            string key = KeyOf(url);
            for (int i = 0; i < list.Count; i++)
                if (string.Equals(KeyOf(list[i].Url), key, StringComparison.Ordinal)) return list[i];
            return null;
        }

        /// <summary>
        /// 空表时补一条默认地址 (Saved=false, 因为它还没落盘)。
        /// 任务要求"列表为空时给默认值 http://127.0.0.1:8443"。
        /// </summary>
        public static void EnsureDefault(List<ConnEntry> list)
        {
            if (list == null || list.Count > 0) return;
            list.Add(new ConnEntry { Url = DefaultUrl, User = "", Saved = false });
        }

        /// <summary>配置文件的可读位置说明 (进 ToolTip, 让操作员找得到文件)。</summary>
        public static string PathNote(string path)
        {
            return "连接配置: " + (path ?? DefaultPath()) + "  (只存地址与用户名, 口令不落盘)";
        }

        private static void AddIfNew(List<ConnEntry> list, ConnEntry e)
        {
            if (Find(list, e.Url) != null) return;
            list.Add(e);
        }
    }
}
