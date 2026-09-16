using System;
using System.Collections.Generic;
using System.Text;
using System.Text.Json;
using System.Windows.Media;

namespace CsdevGui
{
    // ---------------------------------------------------------------- 作业行

    /// <summary>
    /// 一个后台作业 (/api/state.jobs[] / GET /api/jobs 的条目)。
    ///
    /// 字段与服务端 go/jobs.go 的 bgJob 一一对应 (JSON tag 为小写蛇形):
    ///   id / sid / kind / detail / port / task_id / started / ended / status / killable / note
    ///
    /// status 取值: running / done / killed / failed。未知值原样保留 (不编造)。
    /// ended == 0 表示仍在运行, 耗时按"当前时刻 - started"实时推进。
    /// </summary>
    public class JobRow : RowBase, IKeyed
    {
        private string _id = "", _sid = "", _kind = "", _detail = "", _status = "", _note = "";
        private long _port, _taskId, _started, _ended, _now;
        private bool _killable;

        /// <summary>作业号 (服务端全局递增的十进制字符串, 直接用于 jobkill &lt;id&gt;)。</summary>
        public string Id { get { return _id; } set { Set(ref _id, value ?? "", nameof(Id)); } }

        public string Sid { get { return _sid; } set { Set(ref _sid, value ?? "", nameof(Sid)); } }

        public string Kind { get { return _kind; } set { if (Set(ref _kind, value ?? "", nameof(Kind))) Notify(nameof(KillHint)); } }

        public string Detail { get { return _detail; } set { if (Set(ref _detail, value ?? "", nameof(Detail))) Notify(nameof(DetailText)); } }

        /// <summary>SOCKS / rportfwd 的端口 (其余作业为 0)。</summary>
        public long Port { get { return _port; } set { if (Set(ref _port, value, nameof(Port))) Notify(nameof(PortText)); } }

        /// <summary>绑定的植入体任务号 (bind 类作业才有)。</summary>
        public long TaskId { get { return _taskId; } set { if (Set(ref _taskId, value, nameof(TaskId))) Notify(nameof(TaskText)); } }

        /// <summary>开始时间 (Unix 秒)。</summary>
        public long Started { get { return _started; } set { if (Set(ref _started, value, nameof(Started))) { Notify(nameof(StartedText)); Notify(nameof(ElapsedText)); } } }

        /// <summary>结束时间 (Unix 秒); 0 = 仍在运行。</summary>
        public long Ended { get { return _ended; } set { if (Set(ref _ended, value, nameof(Ended))) { Notify(nameof(EndedText)); Notify(nameof(ElapsedText)); } } }

        /// <summary>running / done / killed / failed (未知值原样保留)。</summary>
        public string Status { get { return _status; } set { if (Set(ref _status, value ?? "", nameof(Status))) { Notify(nameof(StatusText)); Notify(nameof(StatusBrush)); } } }

        /// <summary>服务端如实标注的可终止性 (SOCKS/rportfwd/keylog 为 true, portscan 为 false)。</summary>
        public bool Killable { get { return _killable; } set { if (Set(ref _killable, value, nameof(Killable))) { Notify(nameof(KillText)); Notify(nameof(KillHint)); } } }

        public string Note { get { return _note; } set { if (Set(ref _note, value ?? "", nameof(Note))) Notify(nameof(NoteText)); } }

        /// <summary>行主键: 服务端作业号全局唯一; 缺失时退化为 (会话, 类型, 开始时间)。</summary>
        public string Key
        {
            get
            {
                if (_id.Length > 0) return "job|" + _id;
                return "job|" + _sid + "|" + _kind + "|" + _started;
            }
        }

        // 只读展示属性 (无 setter -> 不参与 RowBase.MergeFrom 的属性拷贝)

        public string DetailText { get { return TargetParse.Or(_detail, "-"); } }
        public string NoteText { get { return TargetParse.Or(_note, "-"); } }
        public string PortText { get { return _port > 0 ? _port.ToString() : "-"; } }
        public string TaskText { get { return _taskId > 0 ? "#" + _taskId : "-"; } }
        public string StartedText { get { return Fmt.Time(_started); } }
        public string EndedText { get { return _ended > 0 ? Fmt.Time(_ended) : "(运行中)"; } }
        public string StatusText { get { return JobParse.StatusTextOf(_status); } }
        public Brush StatusBrush { get { return JobParse.StatusBrushOf(_status); } }
        public string KillText { get { return _killable ? "可终止" : "不可中断"; } }
        public string KillHint { get { return JobParse.KillHintOf(_kind, _killable, _id); } }

        /// <summary>耗时 (由 started/ended 算; ended=0 时按 _now 推进)。</summary>
        public string ElapsedText { get { return JobParse.Elapsed(_started, _ended, _now); } }

        /// <summary>起止时间明细 (耗时列 ToolTip)。</summary>
        public string TimeTip
        {
            get
            {
                return "started  " + StartedText + "\nended    " + EndedText
                     + "\n耗时     " + ElapsedText
                     + "\ntask_id  " + TaskText + "\nport     " + PortText;
            }
        }

        /// <summary>
        /// 推进"运行中"作业的耗时显示 (轮询签名未变时也调用, 让计时器继续走)。
        /// 已结束的作业不受 now 影响。
        /// </summary>
        public void Touch(long now)
        {
            if (_ended > 0) return;
            if (_now == now) return;
            _now = now;
            Notify(nameof(ElapsedText));
            Notify(nameof(TimeTip));
        }
    }

    // ---------------------------------------------------------------- 会话下拉项

    /// <summary>
    /// 作业页的会话过滤器条目。
    /// Follow = 跟随当前附着会话 (顶栏/会话页切换时自动跟随)。
    /// </summary>
    public sealed class JobSidItem
    {
        public string Sid { get; private set; }
        public bool Follow { get; private set; }
        public string Text { get; private set; }

        public JobSidItem(string sid, bool follow, string text)
        {
            Sid = sid ?? "";
            Follow = follow;
            Text = text ?? "";
        }

        /// <summary>稳定键 (不含 curSid): 重建下拉后据此恢复选中项。</summary>
        public string Key
        {
            get
            {
                if (Follow) return "follow";
                return Sid.Length > 0 ? "sid:" + Sid : "all";
            }
        }

        public override string ToString() { return Text; }
    }

    // ---------------------------------------------------------------- 解析结果

    /// <summary>
    /// /api/state 里作业块的解析结果。整块缺失时 Present=false, 页面如实标注而不是假装空表。
    /// </summary>
    public sealed class JobView
    {
        public readonly List<JobRow> Jobs = new List<JobRow>();

        /// <summary>服务端是否返回了 jobs 数组。</summary>
        public bool Present;

        /// <summary>服务端 jobs_running 计数 (-1 = 该字段未提供)。</summary>
        public long ServerRunning = -1;

        /// <summary>本侧按 status == running 统计的条数。</summary>
        public int LocalRunning;

        public string StatsText()
        {
            if (!Present) return "服务端未返回 /api/state.jobs —— 作业页不可用";
            var sb = new StringBuilder();
            sb.Append("作业 ").Append(Jobs.Count).Append(" 个")
              .Append("    running ").Append(LocalRunning);
            if (ServerRunning >= 0 && ServerRunning != LocalRunning)
                sb.Append("  (服务端 jobs_running=").Append(ServerRunning).Append(")");
            return sb.ToString();
        }
    }

    // ---------------------------------------------------------------- 纯函数解析层

    /// <summary>
    /// 统一 Job 体系 (jobs / jobkill) 的纯函数解析层。
    ///
    /// 与 UI 解耦 (只依赖 BCL 与冻结画刷), 因此
    /// <c>csdev-gui.exe --selftest</c> 能在无窗口环境下逐样本断言:
    /// 字段解析 / 缺失降级 / 耗时计算 / 状态着色 / 差分签名 / 过滤 / jobkill 文案。
    ///
    /// 依据 (只读核对 go/, 未修改):
    ///   go/jobs.go  bgJob            -> id,sid,kind,detail,port,task_id,started,ended,status,killable,note
    ///   go/jobs.go  handleJobs       -> {"ok":true,"jobs":[...],"running":N}
    ///   go/jobs.go  jobTryCommand    -> jobs / jobkill &lt;id&gt; 在服务端侧被拦截, 回 {"ok":true,"text":"..."}
    ///   go/jobs.go  bgJobKill        -> 不可终止的类型回 ok=true + "[-] job N (kind) 是一次性任务, 无法中途终止: ..."
    ///   go/v2_api.go handleState     -> /api/state 的 "jobs" 数组与 "jobs_running" 整数
    /// </summary>
    public static class JobParse
    {
        // ------------------------------------------------------------ 状态

        /// <summary>状态文案: 已知值附中文注解, 未知值原样保留 (不编造)。</summary>
        public static string StatusTextOf(string status)
        {
            string s = (status ?? "").Trim();
            if (s.Length == 0) return "-";
            if (string.Equals(s, "running", StringComparison.OrdinalIgnoreCase)) return "running 运行中";
            if (string.Equals(s, "done", StringComparison.OrdinalIgnoreCase)) return "done 已完成";
            if (string.Equals(s, "killed", StringComparison.OrdinalIgnoreCase)) return "killed 已终止";
            if (string.Equals(s, "failed", StringComparison.OrdinalIgnoreCase)) return "failed 失败";
            return s;
        }

        /// <summary>状态着色: running=蓝 done=绿 killed=橙 failed=红 未知=灰。</summary>
        public static Brush StatusBrushOf(string status)
        {
            string s = (status ?? "").Trim();
            if (string.Equals(s, "running", StringComparison.OrdinalIgnoreCase)) return Palette.Accent;
            if (string.Equals(s, "done", StringComparison.OrdinalIgnoreCase)) return Palette.Ok;
            if (string.Equals(s, "killed", StringComparison.OrdinalIgnoreCase)) return Palette.Warn;
            if (string.Equals(s, "failed", StringComparison.OrdinalIgnoreCase)) return Palette.Err;
            return Palette.Dim;
        }

        public static bool IsRunning(JobRow j)
        {
            return j != null && string.Equals((j.Status ?? "").Trim(), "running", StringComparison.OrdinalIgnoreCase);
        }

        // ------------------------------------------------------------ 耗时

        /// <summary>
        /// 耗时 (由 started/ended 算)。
        ///   started &lt;= 0        -> "-"   (服务端没给开始时间)
        ///   ended == 0           -> 按 now 推进 (仍在运行)
        ///   ended &lt; started      -> "0s"  (时钟回拨, 不显示负数)
        /// </summary>
        public static string Elapsed(long started, long ended, long now)
        {
            if (started <= 0) return "-";
            if (ended > 0) return Fmt.Age(ended >= started ? ended - started : 0);
            return Fmt.Age(now > started ? now - started : 0);
        }

        // ------------------------------------------------------------ 解析

        /// <summary>
        /// 解析 /api/state 的作业块。字段缺失 / 类型不符 / 非对象元素都只影响该行,
        /// 不抛异常; 既无 id 又无 kind/sid 的行无法定位, 直接丢弃 (不会出现在正常响应里)。
        /// </summary>
        public static JobView State(JsonElement root)
        {
            var v = new JobView();
            var block = root.Field("jobs");
            if (block.ValueKind != JsonValueKind.Array) return v;
            v.Present = true;

            foreach (var e in root.Arr("jobs"))
            {
                if (e.ValueKind != JsonValueKind.Object) continue;

                var r = new JobRow();
                r.Id = IdOf(e);
                r.Sid = e.Str("sid");
                r.Kind = e.Str("kind");
                r.Detail = e.Str("detail");
                r.Port = e.Long("port");
                r.TaskId = e.Long("task_id");
                r.Started = e.Long("started");
                r.Ended = e.Long("ended");
                r.Status = e.Str("status");
                r.Killable = e.Bool("killable");
                r.Note = e.Str("note");

                if (r.Id.Length == 0 && r.Kind.Length == 0 && r.Sid.Length == 0) continue;
                if (IsRunning(r)) v.LocalRunning++;
                v.Jobs.Add(r);
            }

            v.ServerRunning = root.Long("jobs_running", -1);
            return v;
        }

        /// <summary>推进一批"运行中"作业的耗时显示。</summary>
        public static void Touch(List<JobRow> jobs, long now)
        {
            if (jobs == null) return;
            for (int i = 0; i < jobs.Count; i++)
            {
                if (IsRunning(jobs[i])) jobs[i].Touch(now);
            }
        }

        /// <summary>
        /// 取作业号: 服务端恒为十进制字符串; 数字型也取原文 (与 ScriptParse.StrList 同一容错口径)。
        /// 其余类型降级为空, 该行随后按"无法定位"规则丢弃。
        /// </summary>
        public static string IdOf(JsonElement e)
        {
            var v = e.Field("id");
            if (v.ValueKind == JsonValueKind.String) return v.GetString() ?? "";
            if (v.ValueKind == JsonValueKind.Number) return v.GetRawText();
            return "";
        }

        // ------------------------------------------------------------ 差分签名

        /// <summary>
        /// /api/state.jobs 的差分签名 (running 计数 + 每条作业的关键字段)。
        /// 与上次相同就不重建行集合, 只推进运行中作业的耗时 —— 轮询仍是单定时器 2 秒。
        /// 服务端未返回 jobs 数组时返回空串 (此时不显示表格内容, 如实标注)。
        /// </summary>
        public static string StateSignature(JsonElement root)
        {
            var arr = root.Field("jobs");
            if (arr.ValueKind != JsonValueKind.Array) return "";

            var sb = new StringBuilder();
            sb.Append("R").Append(root.Long("jobs_running", -1))
              .Append(" N").Append(arr.GetArrayLength());
            foreach (var e in arr.EnumerateArray())
            {
                sb.Append('\u0001').Append(e.Str("id")).Append('\u0002')
                  .Append(e.Str("sid")).Append('\u0002')
                  .Append(e.Str("kind")).Append('\u0002')
                  .Append(e.Str("status")).Append('\u0002')
                  .Append(e.Bool("killable") ? '1' : '0').Append('\u0002')
                  .Append(e.Long("started")).Append('\u0002')
                  .Append(e.Long("ended")).Append('\u0002')
                  .Append(e.Long("task_id")).Append('\u0002')
                  .Append(e.Str("detail")).Append('\u0002')
                  .Append(e.Str("note"));
            }
            return sb.ToString();
        }

        // ------------------------------------------------------------ 过滤

        /// <summary>
        /// 纯客户端过滤: sid 为空串 = 全部会话; runningOnly = 只留 status == running。
        /// 返回新列表 (行对象复用, 不改内容), 交给 Sync 差分合并。
        /// </summary>
        public static List<JobRow> Filter(List<JobRow> all, string sid, bool runningOnly)
        {
            var outList = new List<JobRow>();
            if (all == null) return outList;

            string s = (sid ?? "").Trim();
            for (int i = 0; i < all.Count; i++)
            {
                JobRow j = all[i];
                if (j == null) continue;
                if (s.Length > 0 && !string.Equals(j.Sid, s, StringComparison.Ordinal)) continue;
                if (runningOnly && !IsRunning(j)) continue;
                outList.Add(j);
            }
            return outList;
        }

        // ------------------------------------------------------------ 会话下拉

        /// <summary>
        /// 构造会话过滤器条目: [全部会话] [当前会话 (跟随)] [各会话 sid ...]。
        /// <paramref name="sids"/> 是已格式化好的会话标签 (形如 "B001   alice@WEB01   proto=v2")。
        /// </summary>
        public static List<JobSidItem> SidItems(List<string> sids, string curSid)
        {
            string cur = (curSid ?? "").Trim();
            var list = new List<JobSidItem>();
            list.Add(new JobSidItem("", false, "全部会话"));
            list.Add(new JobSidItem("", true, cur.Length > 0
                ? "当前会话 (跟随): " + cur
                : "当前会话 (跟随): (无附着)"));
            if (sids != null)
            {
                for (int i = 0; i < sids.Count; i++)
                {
                    if (string.IsNullOrEmpty(sids[i])) continue;
                    list.Add(new JobSidItem(JobSidOf(sids[i]), false, sids[i]));
                }
            }
            return list;
        }

        /// <summary>从会话标签里取 sid (标签以 sid 开头, 后跟空白)。</summary>
        public static string JobSidOf(string label)
        {
            string s = (label ?? "").Trim();
            if (s.Length == 0) return "";
            int cut = s.IndexOfAny(new char[] { ' ', '\t' });
            return cut > 0 ? s.Substring(0, cut) : s;
        }

        /// <summary>条目序列是否等价 (Key + Text 都比): 相同就不重建下拉, 不打断用户选择。</summary>
        public static bool SameSidItems(List<JobSidItem> a, List<JobSidItem> b)
        {
            if (ReferenceEquals(a, b)) return true;
            if (a == null || b == null) return false;
            if (a.Count != b.Count) return false;
            for (int i = 0; i < a.Count; i++)
            {
                if (!string.Equals(a[i].Key, b[i].Key, StringComparison.Ordinal)) return false;
                if (!string.Equals(a[i].Text, b[i].Text, StringComparison.Ordinal)) return false;
            }
            return true;
        }

        /// <summary>按 Key 恢复选中项; 找不到时回到"全部会话" (第 0 项)。</summary>
        public static JobSidItem PickSid(List<JobSidItem> items, string key)
        {
            if (items == null || items.Count == 0) return null;
            string k = key ?? "";
            for (int i = 0; i < items.Count; i++)
            {
                if (string.Equals(items[i].Key, k, StringComparison.Ordinal)) return items[i];
            }
            return items[0];
        }

        // ------------------------------------------------------------ jobkill

        /// <summary>终止命令原文 (服务端 jobTryCommand 精确匹配首词 jobkill)。</summary>
        public static string KillCommand(string id)
        {
            string s = (id ?? "").Trim();
            return s.Length > 0 ? "jobkill " + s : "jobkill";
        }

        /// <summary>
        /// jobkill 响应的显示文本。ok=true 时**原样**返回服务端 text —— 包括
        /// killable=false 那句"是一次性任务, 无法中途终止": 这是如实行为, 不是失败,
        /// 界面必须原样显示, 不得改写、吞掉或染成失败色。
        /// </summary>
        public static string KillResultText(bool ok, string text, string error, string id)
        {
            if (ok)
            {
                string t = (text ?? "").Trim();
                if (t.Length == 0)
                    return "服务端返回 ok=true 但未包含 text 字段 (jobkill " + id + ")";
                return t;
            }
            string e = (error ?? "").Trim();
            if (e.Length == 0) return "jobkill " + id + " 失败 (服务端未返回 error 字段)";
            return e;
        }

        /// <summary>
        /// 服务端对不可终止作业的 jobkill 回的是 ok=true + 这句明确说明。
        /// 判定它只为界面换一种语气 (仍按成功路径显示原话), 绝不当作失败。
        /// </summary>
        public static bool IsNotKillableText(string text)
        {
            return (text ?? "").IndexOf("无法中途终止", StringComparison.Ordinal) >= 0;
        }

        /// <summary>可终止列的 ToolTip: killable=false 时说明"为什么不能杀"。</summary>
        public static string KillHintOf(string kind, bool killable, string id)
        {
            string k = TargetParse.Or((kind ?? "").Trim(), "(未知类型)");
            if (killable)
            {
                return "服务端标注 killable=true: 该作业有真实停止通道。\n"
                     + "jobkill " + (id ?? "") + "  (" + k + ")";
            }
            return "服务端标注 killable=false: " + k + " 是一次性下发, 没有中途掐断的通道。\n"
                 + "点『终止选中作业』时服务端会原样回: [-] job " + (id ?? "")
                 + " (" + k + ") 是一次性任务, 无法中途终止: …\n"
                 + "这是如实行为, 不是失败, 界面原样显示这句话。";
        }
    }
}
