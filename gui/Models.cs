using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Reflection;
using System.Windows.Media;

namespace CsdevGui
{
    // ---------------------------------------------------------------- 基类

    /// <summary>可差分刷新的表格行。</summary>
    public interface IKeyed
    {
        /// <summary>行主键, 用于轮询时原地更新而不是整体重建。</summary>
        string Key { get; }
    }

    /// <summary>行基类: 属性变更通知, 使 DataGrid 只刷新变化的单元格。</summary>
    public abstract class RowBase : INotifyPropertyChanged
    {
        public event PropertyChangedEventHandler PropertyChanged;

        protected void Notify(string name)
        {
            var h = PropertyChanged;
            if (h != null) h(this, new PropertyChangedEventArgs(name));
        }

        protected bool Set<T>(ref T field, T value, string name)
        {
            if (EqualityComparer<T>.Default.Equals(field, value)) return false;
            field = value;
            Notify(name);
            return true;
        }

        // 反射属性表缓存: 键为具体行类型, 值为可写且可读的公开实例属性
        private static readonly Dictionary<Type, PropertyInfo[]> PropCache = new Dictionary<Type, PropertyInfo[]>();
        private static readonly object PropLock = new object();

        /// <summary>
        /// 把另一行的可写属性合并进本行: 值相同则跳过 (不触发通知)。
        /// 用于轮询时原地刷新, 保持 DataGrid 选中行 / 滚动位置 / 排序不变。
        /// </summary>
        public void MergeFrom(RowBase src)
        {
            if (src == null) return;
            PropertyInfo[] props = Props(GetType());
            for (int i = 0; i < props.Length; i++)
            {
                PropertyInfo pi = props[i];
                object nv = pi.GetValue(src, null);
                object ov = pi.GetValue(this, null);
                if (object.Equals(nv, ov)) continue;
                pi.SetValue(this, nv, null);
            }
        }

        private static PropertyInfo[] Props(Type t)
        {
            lock (PropLock)
            {
                PropertyInfo[] cached;
                if (PropCache.TryGetValue(t, out cached)) return cached;

                var list = new List<PropertyInfo>();
                foreach (PropertyInfo pi in t.GetProperties(BindingFlags.Public | BindingFlags.Instance))
                {
                    if (pi.CanRead && pi.CanWrite && pi.GetIndexParameters().Length == 0) list.Add(pi);
                }
                cached = list.ToArray();
                PropCache[t] = cached;
                return cached;
            }
        }
    }

    // ---------------------------------------------------------------- 格式化

    public static class Fmt
    {
        /// <summary>Unix 秒 -&gt; 本地时间。</summary>
        public static string Time(long unixSec)
        {
            if (unixSec <= 0) return "-";
            try { return DateTimeOffset.FromUnixTimeSeconds(unixSec).ToLocalTime().ToString("MM-dd HH:mm:ss"); }
            catch { return unixSec.ToString(); }
        }

        /// <summary>秒 -&gt; 人类可读时长。</summary>
        public static string Age(long sec)
        {
            if (sec < 0) return "-";
            if (sec < 60) return sec + "s";
            if (sec < 3600) return (sec / 60) + "m" + (sec % 60) + "s";
            if (sec < 86400) return (sec / 3600) + "h" + ((sec % 3600) / 60) + "m";
            return (sec / 86400) + "d" + ((sec % 86400) / 3600) + "h";
        }

        /// <summary>字节 -&gt; 人类可读长度。</summary>
        public static string Size(long bytes)
        {
            if (bytes < 0) return "-";
            if (bytes < 1024) return bytes + " B";
            if (bytes < 1048576) return (bytes / 1024.0).ToString("0.0") + " KB";
            if (bytes < 1073741824L) return (bytes / 1048576.0).ToString("0.00") + " MB";
            return (bytes / 1073741824.0).ToString("0.00") + " GB";
        }

        public static Brush MakeBrush(string hex)
        {
            try
            {
                var c = (Color)ColorConverter.ConvertFromString(hex);
                var b = new SolidColorBrush(c);
                b.Freeze();
                return b;
            }
            catch { return Brushes.Gray; }
        }
    }

    /// <summary>冻结画刷缓存 (跨线程/跨行共享, 不做资源查找以免依赖 App.xaml)。</summary>
    public static class Palette
    {
        public static readonly Brush Fg = Fmt.MakeBrush("#D5DAE3");
        public static readonly Brush Dim = Fmt.MakeBrush("#6E7A8F");
        public static readonly Brush Accent = Fmt.MakeBrush("#4A9EFF");
        public static readonly Brush Ok = Fmt.MakeBrush("#3FB950");
        public static readonly Brush Err = Fmt.MakeBrush("#F85149");
        public static readonly Brush Warn = Fmt.MakeBrush("#D29922");
        public static readonly Brush Purple = Fmt.MakeBrush("#A371F7");
    }

    // ---------------------------------------------------------------- 会话

    public class SessionRow : RowBase, IKeyed
    {
        private string _sid = "", _proto = "", _host = "", _user = "", _arch = "";
        private string _proc = "", _os = "", _addr = "";
        private long _idle, _pid, _ppid, _sleep, _jitter;
        private bool _hasTask;

        public string Sid { get { return _sid; } set { Set(ref _sid, value ?? "", nameof(Sid)); } }
        public string Proto { get { return _proto; } set { if (Set(ref _proto, value ?? "", nameof(Proto))) Notify(nameof(ProtoBrush)); } }
        public string Host { get { return _host; } set { Set(ref _host, value ?? "", nameof(Host)); } }
        public string User { get { return _user; } set { Set(ref _user, value ?? "", nameof(User)); } }
        public string Arch { get { return _arch; } set { Set(ref _arch, value ?? "", nameof(Arch)); } }
        public string Proc { get { return _proc; } set { Set(ref _proc, value ?? "", nameof(Proc)); } }
        public string Os { get { return _os; } set { Set(ref _os, value ?? "", nameof(Os)); } }
        public string Addr { get { return _addr; } set { Set(ref _addr, value ?? "", nameof(Addr)); } }

        public long Idle { get { return _idle; } set { if (Set(ref _idle, value, nameof(Idle))) Notify(nameof(IdleText)); } }
        public long Pid { get { return _pid; } set { if (Set(ref _pid, value, nameof(Pid))) Notify(nameof(PidText)); } }
        public long Ppid { get { return _ppid; } set { Set(ref _ppid, value, nameof(Ppid)); } }
        public long Sleep { get { return _sleep; } set { if (Set(ref _sleep, value, nameof(Sleep))) Notify(nameof(SleepText)); } }
        public long Jitter { get { return _jitter; } set { if (Set(ref _jitter, value, nameof(Jitter))) Notify(nameof(JitterText)); } }
        public bool HasTask { get { return _hasTask; } set { if (Set(ref _hasTask, value, nameof(HasTask))) Notify(nameof(TaskText)); } }

        // 只读展示属性
        public string Key { get { return _sid; } }
        public string IdleText { get { return Fmt.Age(_idle); } }
        public string PidText { get { return _pid <= 0 ? "-" : _pid.ToString(); } }
        public string PpidText { get { return _ppid <= 0 ? "-" : _ppid.ToString(); } }
        public string SleepText { get { return _sleep <= 0 ? "-" : _sleep + " ms"; } }
        public string JitterText { get { return _jitter <= 0 ? "0%" : _jitter + "%"; } }
        public string TaskText { get { return _hasTask ? "排队中" : ""; } }
        public bool IsV2 { get { return string.Equals(_proto, "v2", StringComparison.OrdinalIgnoreCase); } }

        public Brush ProtoBrush
        {
            get
            {
                if (IsV2) return Palette.Ok;
                if (string.Equals(_proto, "v1", StringComparison.OrdinalIgnoreCase)) return Palette.Warn;
                return Palette.Dim;
            }
        }

        /// <summary>会话下拉框 (启动 SOCKS / rportfwd 时选会话) 的显示文本。</summary>
        public string PickerText
        {
            get { return _sid + "   " + _user + "@" + _host + "   proto=" + _proto; }
        }

        /// <summary>右键"复制信息"用的文本块。</summary>
        public string ToInfoText()
        {
            var sb = new System.Text.StringBuilder();
            sb.AppendLine("sid      : " + _sid);
            sb.AppendLine("proto    : " + _proto);
            sb.AppendLine("host     : " + _host);
            sb.AppendLine("user     : " + _user);
            sb.AppendLine("arch     : " + _arch);
            sb.AppendLine("pid      : " + PidText + "  (ppid " + PpidText + ")");
            sb.AppendLine("proc     : " + _proc);
            sb.AppendLine("os       : " + _os);
            sb.AppendLine("addr     : " + _addr);
            sb.AppendLine("idle     : " + IdleText);
            sb.AppendLine("sleep    : " + SleepText + "  jitter " + JitterText);
            return sb.ToString();
        }
    }

    // ---------------------------------------------------------------- 监听器

    /// <summary>
    /// 一行监听器 (/api/state.listeners[] 或 GET /api/listeners)。
    ///
    /// 基础字段与服务端 go/v2_api.go 的 ListenerInfo 对齐
    /// (name / type / proto / host / port / uri / ssl / up);
    /// 运行时增删落地后服务端会**追加** id 字段, 这里兼容解析:
    /// 没有 id 的行不可移除 (按钮置灰), 而不是拿 name 冒充 id。
    /// 主 listener (uri 非空, 即启动期注册的 csdev-v2 / csdev-legacy) 一律不可移除。
    /// </summary>
    public class ListenerRow : RowBase, IKeyed
    {
        private string _name = "", _type = "", _proto = "", _host = "", _uri = "", _id = "", _addr = "";
        private long _port;
        private bool _ssl, _up, _protected;
        private int _manage = ListenerParse.ManageUnknown;

        public string Name { get { return _name; } set { if (Set(ref _name, value ?? "", nameof(Name))) { Notify(nameof(CanRemove)); Notify(nameof(RemoveHint)); } } }
        public string Type { get { return _type; } set { Set(ref _type, value ?? "", nameof(Type)); } }
        public string Proto { get { return _proto; } set { if (Set(ref _proto, value ?? "", nameof(Proto))) { Notify(nameof(CanRemove)); Notify(nameof(RemoveHint)); } } }
        public string Host { get { return _host; } set { if (Set(ref _host, value ?? "", nameof(Host))) { Notify(nameof(AddrText)); Notify(nameof(Key)); } } }
        public string Uri { get { return _uri; } set { if (Set(ref _uri, value ?? "", nameof(Uri))) { Notify(nameof(CanRemove)); Notify(nameof(RemoveHint)); } } }
        public long Port { get { return _port; } set { if (Set(ref _port, value, nameof(Port))) { Notify(nameof(AddrText)); Notify(nameof(Key)); } } }
        public bool Ssl { get { return _ssl; } set { if (Set(ref _ssl, value, nameof(Ssl))) Notify(nameof(SslText)); } }
        public bool Up { get { return _up; } set { if (Set(ref _up, value, nameof(Up))) { Notify(nameof(UpText)); Notify(nameof(StatusBrush)); } } }

        /// <summary>服务端给的句柄 (POST /api/listener/add 返回, 或列表里的追加字段); 空 = 无法按 id 移除。</summary>
        public string Id { get { return _id; } set { if (Set(ref _id, value ?? "", nameof(Id))) { Notify(nameof(Key)); Notify(nameof(IdText)); Notify(nameof(CanRemove)); Notify(nameof(RemoveHint)); } } }

        /// <summary>服务端 protected 字段 (true = 控制台入口, 不可 API 删除)。</summary>
        public bool Protected { get { return _protected; } set { if (Set(ref _protected, value, nameof(Protected))) { Notify(nameof(ProtectedText)); Notify(nameof(RowBrush)); } } }

        /// <summary>
        /// 服务端回传的实际监听地址 (listener_admin.go 的追加字段 addr)。
        /// 与 host/port 拼出来的 AddrText 不同: 端口 0 或双栈绑定时服务端给的是
        /// [::]:8644 这类规范化形式, 直接显示原文比二次拼接可信。
        /// </summary>
        public string Addr { get { return _addr; } set { if (Set(ref _addr, value ?? "", nameof(Addr))) Notify(nameof(AddrRawText)); } }

        /// <summary>
        /// 服务端 manageable 字段的三态 (ManageUnknown/Yes/No)。
        /// 用 int 而不是 bool: "服务端没给这个字段"必须与"服务端说不能删"区分开,
        /// 前者回落到本地启发式, 后者直接置灰。
        /// </summary>
        public int ManageFlag { get { return _manage; } set { if (Set(ref _manage, value, nameof(ManageFlag))) { Notify(nameof(CanRemove)); Notify(nameof(RemoveHint)); Notify(nameof(ManageText)); Notify(nameof(RowBrush)); } } }

        /// <summary>行主键: 优先服务端 id, 否则 name|host|port (轮询时原地合并, 不重建列表)。</summary>
        public string Key { get { return ListenerParse.RowKey(_id, _name, _host, _port); } }
        public string AddrText { get { return _host + ":" + _port; } }
        public string SslText { get { return _ssl ? "SSL" : "-"; } }
        public string UpText { get { return _up ? "在线" : "离线"; } }
        public string IdText { get { return _id.Length > 0 ? _id : "-"; } }
        /// <summary>addr 列: 服务端原文, 缺字段时退回 host:port 拼接。</summary>
        public string AddrRawText { get { return _addr.Length > 0 ? _addr : AddrText; } }
        public Brush StatusBrush { get { return _up ? Palette.Ok : Palette.Err; } }

        /// <summary>保护列文案: 服务端字段缺失时如实说"未给出", 不冒充可管理。</summary>
        public string ProtectedText
        {
            get
            {
                if (_manage == ListenerParse.ManageUnknown) return _protected ? "受保护" : "未给出";
                return _manage == ListenerParse.ManageNo ? "受保护" : "可移除";
            }
        }

        public string ManageText { get { return ProtectedText; } }
        public Brush RowBrush { get { return _manage == ListenerParse.ManageNo ? Palette.Dim : Palette.Fg; } }

        /// <summary>能否移除: 服务端 manageable 说了算; 缺字段时用启发式 (主 listener 不可删)。</summary>
        public bool CanRemove
        {
            get { return ListenerParse.CanManage(_manage, _name, _proto, _uri, _id); }
        }

        public string RemoveHint { get { return ListenerParse.RemoveHint(_manage, _name, _proto, _uri, _id); } }
    }

    // ---------------------------------------------------------------- 操作员账号

    /// <summary>
    /// 一行操作员账号 (GET /api/users 的 users[])。
    ///
    /// 字段与服务端 go/auth.go 的 writeUsersList 对齐: user / role / last / last_text。
    /// 盐与摘要**不出网**, 所以这里也不存在任何口令相关字段。
    /// IsSelf 与 AdminCount 由 AccountParse.Users 在解析时按当前登录账号与 admin 总数填好,
    /// 「删除」按钮据此置灰 —— 服务端会拒绝删自己, 也拒绝删最后一个 admin。
    /// </summary>
    public class OperatorRow : RowBase, IKeyed
    {
        private string _user = "", _role = "", _lastTextRaw = "";
        private long _last;
        private bool _isSelf;
        private int _adminCount;

        public string User
        {
            get { return _user; }
            set { if (Set(ref _user, value ?? "", nameof(User))) { Notify(nameof(Key)); Notify(nameof(SelfText)); Notify(nameof(DeleteHint)); } }
        }

        public string Role
        {
            get { return _role; }
            set { if (Set(ref _role, value ?? "", nameof(Role))) { Notify(nameof(RoleText)); Notify(nameof(IsAdminRole)); Notify(nameof(CanDelete)); Notify(nameof(DeleteHint)); } }
        }

        public long Last { get { return _last; } set { if (Set(ref _last, value, nameof(Last))) Notify(nameof(LastText)); } }

        /// <summary>服务端已格式化好的 last_text (为空时由 LastText 用 last 兜底)。</summary>
        public string LastTextRaw
        {
            get { return _lastTextRaw; }
            set { if (Set(ref _lastTextRaw, value ?? "", nameof(LastTextRaw))) Notify(nameof(LastText)); }
        }

        /// <summary>列表里 admin 的个数 (删最后一个 admin 会被服务端拒绝)。</summary>
        public int AdminCount
        {
            get { return _adminCount; }
            set { if (Set(ref _adminCount, value, nameof(AdminCount))) { Notify(nameof(CanDelete)); Notify(nameof(DeleteHint)); } }
        }

        /// <summary>是不是当前登录的账号 (服务端拒绝删除它自己)。</summary>
        public bool IsSelf
        {
            get { return _isSelf; }
            set { if (Set(ref _isSelf, value, nameof(IsSelf))) { Notify(nameof(SelfText)); Notify(nameof(CanDelete)); Notify(nameof(DeleteHint)); } }
        }

        public string Key { get { return "u|" + _user; } }
        public string RoleText { get { return _role.Length > 0 ? _role : "?"; } }
        public bool IsAdminRole { get { return AccountParse.IsAdmin(_role); } }
        public string SelfText { get { return _isSelf ? "当前登录" : "-"; } }
        public string LastText { get { return _lastTextRaw.Length > 0 ? _lastTextRaw : Fmt.Time(_last); } }
        public bool CanDelete { get { return AccountParse.CanDelete(_isSelf, _role, _adminCount); } }
        public string DeleteHint { get { return AccountParse.DeleteHint(_isSelf, _role, _adminCount, _user); } }
    }

    // ---------------------------------------------------------------- 凭据

    public class CredRow : RowBase, IKeyed
    {
        private long _id, _ts, _kind;
        private string _user = "", _secret = "", _source = "", _sid = "";

        public long Id { get { return _id; } set { Set(ref _id, value, nameof(Id)); } }
        public long Ts { get { return _ts; } set { if (Set(ref _ts, value, nameof(Ts))) Notify(nameof(TsText)); } }
        public long CredKind { get { return _kind; } set { Set(ref _kind, value, nameof(CredKind)); } }
        public string User { get { return _user; } set { Set(ref _user, value ?? "", nameof(User)); } }
        public string Secret { get { return _secret; } set { Set(ref _secret, value ?? "", nameof(Secret)); } }
        public string Source { get { return _source; } set { Set(ref _source, value ?? "", nameof(Source)); } }
        public string Sid { get { return _sid; } set { Set(ref _sid, value ?? "", nameof(Sid)); } }

        public string Key { get { return "c" + _id + "|" + _user; } }
        public string TsText { get { return Fmt.Time(_ts); } }
    }

    // ---------------------------------------------------------------- 下载

    public class DownloadRow : RowBase, IKeyed
    {
        private long _id, _ts, _size;
        private string _name = "", _path = "", _remote = "", _sid = "";

        public long Id { get { return _id; } set { Set(ref _id, value, nameof(Id)); } }
        public long Ts { get { return _ts; } set { if (Set(ref _ts, value, nameof(Ts))) Notify(nameof(TsText)); } }
        public long Size { get { return _size; } set { if (Set(ref _size, value, nameof(Size))) Notify(nameof(SizeText)); } }
        public string Name { get { return _name; } set { Set(ref _name, value ?? "", nameof(Name)); } }
        public string Path { get { return _path; } set { Set(ref _path, value ?? "", nameof(Path)); } }
        public string RemotePath { get { return _remote; } set { Set(ref _remote, value ?? "", nameof(RemotePath)); } }
        public string Sid { get { return _sid; } set { Set(ref _sid, value ?? "", nameof(Sid)); } }

        public string Key { get { return "d" + _id; } }
        public string TsText { get { return Fmt.Time(_ts); } }
        public string SizeText { get { return Fmt.Size(_size); } }
    }

    // ---------------------------------------------------------------- 截屏

    public class ShotRow : RowBase, IKeyed
    {
        private long _id, _ts, _size;
        private string _sid = "", _path = "";
        private ImageSource _thumb;

        public long Id { get { return _id; } set { Set(ref _id, value, nameof(Id)); } }
        public long Ts { get { return _ts; } set { if (Set(ref _ts, value, nameof(Ts))) Notify(nameof(TsText)); } }
        public long Size { get { return _size; } set { if (Set(ref _size, value, nameof(Size))) Notify(nameof(SizeText)); } }
        public string Sid { get { return _sid; } set { Set(ref _sid, value ?? "", nameof(Sid)); } }
        public string Path { get { return _path; } set { Set(ref _path, value ?? "", nameof(Path)); } }

        /// <summary>已解码的内存位图 (BitmapCacheOption.OnLoad, 不持有文件句柄)。</summary>
        public ImageSource Thumb { get { return _thumb; } set { Set(ref _thumb, value, nameof(Thumb)); } }

        public string Key { get { return "s" + _id; } }
        public string TsText { get { return Fmt.Time(_ts); } }
        public string SizeText { get { return Fmt.Size(_size); } }
        public string CapText { get { return _sid + "  " + Fmt.Time(_ts); } }
    }

    // ---------------------------------------------------------------- 键盘记录

    public class KeylogRow : RowBase, IKeyed
    {
        private long _id, _ts;
        private string _sid = "", _source = "", _text = "";

        public long Id { get { return _id; } set { Set(ref _id, value, nameof(Id)); } }
        public long Ts { get { return _ts; } set { if (Set(ref _ts, value, nameof(Ts))) Notify(nameof(TsText)); } }
        public string Sid { get { return _sid; } set { Set(ref _sid, value ?? "", nameof(Sid)); } }
        public string Source { get { return _source; } set { Set(ref _source, value ?? "", nameof(Source)); } }
        public string Text { get { return _text; } set { Set(ref _text, value ?? "", nameof(Text)); } }

        public string Key { get { return "k" + _id; } }
        public string TsText { get { return Fmt.Time(_ts); } }
    }

    // ---------------------------------------------------------------- 事件

    public class EventRow : RowBase, IKeyed
    {
        private long _id, _ts;
        private string _cat = "", _sid = "", _action = "", _detail = "", _who = "";

        public long Id { get { return _id; } set { Set(ref _id, value, nameof(Id)); } }
        public long Ts { get { return _ts; } set { if (Set(ref _ts, value, nameof(Ts))) Notify(nameof(TsText)); } }
        public string Cat { get { return _cat; } set { if (Set(ref _cat, value ?? "", nameof(Cat))) Notify(nameof(CatBrush)); } }
        public string Sid { get { return _sid; } set { Set(ref _sid, value ?? "", nameof(Sid)); } }
        public string Action { get { return _action; } set { Set(ref _action, value ?? "", nameof(Action)); } }
        public string Detail { get { return _detail; } set { Set(ref _detail, value ?? "", nameof(Detail)); } }
        public string Who { get { return _who; } set { Set(ref _who, value ?? "", nameof(Who)); } }

        public string Key { get { return "e" + _id; } }
        public string TsText { get { return Fmt.Time(_ts); } }

        /// <summary>按类别着色: beacon=蓝 operator=绿 listener=橙 system=灰 其他=紫。</summary>
        public Brush CatBrush
        {
            get
            {
                switch ((_cat ?? "").ToLowerInvariant())
                {
                    case "beacon": return Palette.Accent;
                    case "operator": return Palette.Ok;
                    case "listener": return Palette.Warn;
                    case "system": return Palette.Dim;
                    default: return Palette.Purple;
                }
            }
        }
    }

    // ---------------------------------------------------------------- 文件浏览器

    /// <summary>
    /// ls 的一行。可能是正常条目, 也可能是植入体回传的提示/报错文本
    /// (Raw=true 时 Name 存整行原文, Size=-1, 由 UI 灰显)。
    /// </summary>
    public class FsItem : RowBase, IKeyed
    {
        private string _name = "", _kind = "文件";
        private long _size;
        private bool _isDir, _raw;

        public string Name { get { return _name; } set { Set(ref _name, value ?? "", nameof(Name)); } }
        public string Kind { get { return _kind; } set { if (Set(ref _kind, value ?? "", nameof(Kind))) Notify(nameof(KindBrush)); } }
        public long Size { get { return _size; } set { if (Set(ref _size, value, nameof(Size))) Notify(nameof(SizeText)); } }
        public bool IsDir { get { return _isDir; } set { if (Set(ref _isDir, value, nameof(IsDir))) Notify(nameof(TypeMark)); } }
        public bool Raw { get { return _raw; } set { if (Set(ref _raw, value, nameof(Raw))) { Notify(nameof(KindBrush)); Notify(nameof(SizeText)); } } }

        /// <summary>行主键: 同一目录内名字唯一, 加类型位避免同名文件/目录互相覆盖。</summary>
        public string Key { get { return (_isDir ? "D|" : "F|") + _name; } }
        public string TypeMark { get { return _raw ? "?" : (_isDir ? "d" : "-"); } }
        public string SizeText { get { return _raw ? "-" : (_isDir ? "" : Fmt.Size(_size)); } }
        public string OpText { get { return _raw ? "" : (_isDir ? "进入" : "下载"); } }

        public Brush KindBrush
        {
            get
            {
                if (_raw) return Palette.Dim;
                return _isDir ? Palette.Accent : Palette.Fg;
            }
        }

        /// <summary>该行能否作为文件操作的目标 (目录可 rm/cd, 提示行不能)。</summary>
        public bool Actionable { get { return !_raw; } }
    }

    // ---------------------------------------------------------------- 进程浏览器

    /// <summary>ps 的一行。字段缺失/非数字时降级为 Raw 提示行。</summary>
    public class ProcItem : RowBase, IKeyed
    {
        private long _pid, _ppid, _threads;
        private string _name = "", _hint = "";
        private bool _raw, _self;

        public long Pid { get { return _pid; } set { if (Set(ref _pid, value, nameof(Pid))) Notify(nameof(PidText)); } }
        public long Ppid { get { return _ppid; } set { if (Set(ref _ppid, value, nameof(Ppid))) Notify(nameof(PpidText)); } }
        public long Threads { get { return _threads; } set { if (Set(ref _threads, value, nameof(Threads))) Notify(nameof(ThreadsText)); } }
        public string Name { get { return _name; } set { Set(ref _name, value ?? "", nameof(Name)); } }
        public string Hint { get { return _hint; } set { if (Set(ref _hint, value ?? "", nameof(Hint))) Notify(nameof(RowBrush)); } }
        public bool Raw { get { return _raw; } set { if (Set(ref _raw, value, nameof(Raw))) { Notify(nameof(RowBrush)); Notify(nameof(RowMark)); } } }

        /// <summary>是否等于当前会话自身的 pid (界面用不同前景色标出)。</summary>
        public bool Self { get { return _self; } set { if (Set(ref _self, value, nameof(Self))) { Notify(nameof(RowBrush)); Notify(nameof(RowMark)); } } }

        public string Key { get { return _raw ? "R|" + _name : "P" + _pid; } }
        public string PidText { get { return _raw ? "-" : _pid.ToString(); } }
        public string PpidText { get { return _raw ? "-" : _ppid.ToString(); } }
        public string ThreadsText { get { return _raw ? "-" : _threads.ToString(); } }
        public string RowMark { get { return _self ? "<本会话>" : (_raw ? "提示" : ""); } }

        public Brush RowBrush
        {
            get
            {
                if (_raw) return Palette.Dim;
                if (_self) return Palette.Warn;     // 自身进程: 醒目
                return Palette.Fg;
            }
        }
    }

    // ---------------------------------------------------------------- 目标库

    /// <summary>
    /// source 集合里的单个标签。颜色在构造时算好并冻结,
    /// 模板里直接绑定, 不做值转换器也不查资源 (self-test 无 Application 也能构造)。
    /// </summary>
    public sealed class SourceTag
    {
        public string Name { get; private set; }
        public Brush Brush { get; private set; }

        private SourceTag(string name, Brush brush)
        {
            Name = name ?? "";
            Brush = brush;
        }

        public static SourceTag Make(string name)
        {
            return new SourceTag(name, TargetParse.SourceBrush(name));
        }

        /// <summary>
        /// 序列等价判定。差分轮询每 2 秒会把 SourceTags 整个换一遍新对象,
        /// 若不做内容比较, DataGrid 每轮都会重绘标签单元格。
        /// </summary>
        public static bool SameSeq(List<SourceTag> a, List<SourceTag> b)
        {
            if (ReferenceEquals(a, b)) return true;
            if (a == null || b == null) return false;
            if (a.Count != b.Count) return false;
            for (int i = 0; i < a.Count; i++)
            {
                if (!string.Equals(a[i].Name, b[i].Name, StringComparison.Ordinal)) return false;
            }
            return true;
        }
    }

    /// <summary>
    /// 目标库的一行 (GET /api/state.targets 的条目)。
    /// 字段全部走安全取值, 缺失时展示层降级为 "-", 不抛异常。
    /// </summary>
    public class TargetRow : RowBase, IKeyed
    {
        private long _id, _ts;
        private string _kind = "", _host = "", _ip = "", _os = "", _source = "", _sid = "", _note = "";
        private List<SourceTag> _tags = new List<SourceTag>();

        public long Id { get { return _id; } set { Set(ref _id, value, nameof(Id)); } }
        public long Ts { get { return _ts; } set { if (Set(ref _ts, value, nameof(Ts))) Notify(nameof(TsText)); } }
        public string Kind { get { return _kind; } set { Set(ref _kind, value ?? "", nameof(Kind)); } }

        public string Host { get { return _host; } set { Set(ref _host, value ?? "", nameof(Host)); } }
        public string Ip { get { return _ip; } set { if (Set(ref _ip, value ?? "", nameof(Ip))) Notify(nameof(IpText)); } }
        public string Os { get { return _os; } set { if (Set(ref _os, value ?? "", nameof(Os))) Notify(nameof(OsText)); } }
        public string Sid { get { return _sid; } set { if (Set(ref _sid, value ?? "", nameof(Sid))) { Notify(nameof(SidText)); Notify(nameof(HasSid)); } } }
        public string Note { get { return _note; } set { if (Set(ref _note, value ?? "", nameof(Note))) Notify(nameof(NoteText)); } }

        /// <summary>逗号分隔的来源集合原文 (beacon / scan / lateral / manual)。</summary>
        public string Source
        {
            get { return _source; }
            set
            {
                if (!Set(ref _source, value ?? "", nameof(Source))) return;
                SourceTags = TargetParse.Tags(_source);
                Notify(nameof(SourceText));
            }
        }

        public List<SourceTag> SourceTags
        {
            get { return _tags; }
            set
            {
                var v = value ?? new List<SourceTag>();
                if (SourceTag.SameSeq(_tags, v)) return;
                _tags = v;
                Notify(nameof(SourceTags));
            }
        }

        /// <summary>主键: 有 id 用 id, 否则退化为 host (服务端按 host 去重)。</summary>
        public string Key { get { return _id > 0 ? "tg" + _id : "h|" + _host; } }

        public string IpText { get { return TargetParse.Or(_ip, "-"); } }
        public string OsText { get { return TargetParse.Or(_os, "-"); } }
        public string SidText { get { return TargetParse.Or(_sid, "-"); } }
        public string NoteText { get { return TargetParse.Or(_note, "-"); } }
        public string SourceText { get { return TargetParse.Or(_source, "-"); } }
        public string TsText { get { return Fmt.Time(_ts); } }

        /// <summary>是否带会话 id (右键"对该目标发起命令"据此判定)。</summary>
        public bool HasSid { get { return _sid.Length > 0; } }
    }

    // ---------------------------------------------------------------- 代理枢轴

    /// <summary>SOCKS 入口一行 (proxy.socks[])。</summary>
    public class SocksRow : RowBase, IKeyed
    {
        private string _sid = "", _listen = "";
        private long _port, _chans, _txTlv, _rxB, _upB;

        public string Sid { get { return _sid; } set { Set(ref _sid, value ?? "", nameof(Sid)); } }
        public long Port { get { return _port; } set { if (Set(ref _port, value, nameof(Port))) Notify(nameof(PortText)); } }
        public string Listen { get { return _listen; } set { if (Set(ref _listen, value ?? "", nameof(Listen))) Notify(nameof(ListenText)); } }

        /// <summary>活跃通道数。</summary>
        public long Chans { get { return _chans; } set { if (Set(ref _chans, value, nameof(Chans))) Notify(nameof(ChansText)); } }

        /// <summary>已下发植入体的数据任务 (TLV) 计数。</summary>
        public long TxTlv { get { return _txTlv; } set { if (Set(ref _txTlv, value, nameof(TxTlv))) Notify(nameof(TxTlvText)); } }

        /// <summary>从本地客户端读入的字节 (代理上行入口)。</summary>
        public long RxB { get { return _rxB; } set { if (Set(ref _rxB, value, nameof(RxB))) Notify(nameof(RxBText)); } }

        /// <summary>已发往植入体的上行载荷字节。</summary>
        public long UpB { get { return _upB; } set { if (Set(ref _upB, value, nameof(UpB))) Notify(nameof(UpBText)); } }

        public string Key { get { return "s|" + _sid + "|" + _port; } }
        public string PortText { get { return _port > 0 ? _port.ToString() : "-"; } }
        public string ListenText { get { return TargetParse.Or(_listen, "-"); } }
        public string ChansText { get { return _chans.ToString(); } }
        public string TxTlvText { get { return _txTlv.ToString(); } }
        public string RxBText { get { return Fmt.Size(_rxB); } }
        public string UpBText { get { return Fmt.Size(_upB); } }

        /// <summary>合法的端口号 (供本地拼 usage 用), 非法返回 0。</summary>
        public int ValidPort { get { return (_port > 0 && _port <= 65535) ? (int)_port : 0; } }
    }

    /// <summary>反向端口转发一行 (proxy.rportfwd[])。</summary>
    public class RportRow : RowBase, IKeyed
    {
        private string _sid = "", _target = "";
        private long _port;

        public string Sid { get { return _sid; } set { Set(ref _sid, value ?? "", nameof(Sid)); } }
        public long Port { get { return _port; } set { if (Set(ref _port, value, nameof(Port))) Notify(nameof(PortText)); } }
        public string Target { get { return _target; } set { if (Set(ref _target, value ?? "", nameof(Target))) Notify(nameof(TargetText)); } }

        public string Key { get { return "r|" + _sid + "|" + _port; } }
        public string PortText { get { return _port > 0 ? _port.ToString() : "-"; } }
        public string TargetText { get { return TargetParse.Or(_target, "-"); } }
        public int ValidPort { get { return (_port > 0 && _port <= 65535) ? (int)_port : 0; } }
    }

    // ---------------------------------------------------------------- 载荷格式

    public class PayloadFormat
    {
        public string Id { get; set; }
        public string Desc { get; set; }
        public string Kind { get; set; }
        public string Proto { get; set; }

        public PayloadFormat() { Id = ""; Desc = ""; Kind = ""; Proto = ""; }

        /// <summary>下拉框显示文本。</summary>
        public string Display { get { return Id + "   " + Desc; } }

        /// <summary>按格式推断输出扩展名 (本地降级: 后端不回传真实产物名)。</summary>
        public string Ext
        {
            get
            {
                string id = (Id ?? "").ToLowerInvariant();
                if (id.EndsWith("-raw")) return ".bin";
                if (id.EndsWith("-ps1")) return ".ps1";
                if (id.EndsWith("-vba")) return ".bas";
                if (id.EndsWith("-vbs")) return ".vbs";
                if (id.EndsWith("-cs")) return ".cs";
                if (id.EndsWith("-dll")) return ".dll";
                if (id.StartsWith("linux")) return ".elf";
                return ".exe";
            }
        }
    }
}
