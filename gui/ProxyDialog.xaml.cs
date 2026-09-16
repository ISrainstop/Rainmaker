using System;
using System.Collections;
using System.Threading.Tasks;
using System.Windows;

namespace CsdevGui
{
    /// <summary>
    /// 启动 SOCKS / 反向端口转发共用的参数对话框。
    ///
    /// 与 TargetDialog 同样走注入式提交回调: 服务端 error (端口被占用、目标格式不对、
    /// 无此 v2 会话 ...) 会原样显示在框内, 用户当场改参数重试。
    /// </summary>
    public partial class ProxyDialog : Window
    {
        /// <summary>提交回调: 返回空串 = 成功 (关闭对话框); 非空 = 要原样显示的 error 文本。</summary>
        public Func<ProxyDialog, Task<string>> Submit;

        private readonly string _mode;      // "socks" 或 "rportfwd"
        private SessionRow _sess;
        private int _port;
        private string _target = "";

        public ProxyDialog(string mode, IEnumerable sessions, SessionRow preselect)
        {
            InitializeComponent();

            _mode = string.Equals(mode, "rportfwd", StringComparison.OrdinalIgnoreCase)
                    ? "rportfwd" : "socks";
            bool rp = _mode == "rportfwd";

            Title = rp ? "启动反向端口转发" : "启动 SOCKS";
            HeadText.Text = Title;
            SubText.Text = rp
                ? "POST /api/proxy/rportfwd/start {sid, port, target}：植入体绑定 port 并监听，"
                  + "该端口上的连接由服务端回连到 target"
                : "POST /api/proxy/start {sid, port}：服务端在 127.0.0.1:port 起 SOCKS5 入口，"
                  + "命令走会话隧道到植入体";
            PortLabel.Text = rp ? "植入体绑定端口（0.0.0.0:port）" : "本地监听端口（127.0.0.1:port）";
            PortBox.Text = rp ? "8080" : "1080";
            TargetPanel.Visibility = rp ? Visibility.Visible : Visibility.Collapsed;

            SessBox.ItemsSource = sessions;
            SessBox.DisplayMemberPath = "PickerText";
            if (preselect != null) SessBox.SelectedItem = preselect;
            else if (SessBox.Items.Count > 0) SessBox.SelectedIndex = 0;

            Loaded += delegate
            {
                if (SessBox.SelectedItem == null) SessBox.Focus();
                else { PortBox.Focus(); PortBox.SelectAll(); }
            };
        }

        public string SidValue { get { return _sess == null ? "" : _sess.Sid; } }
        public int PortValue { get { return _port; } }
        public string TargetValue { get { return _target; } }

        private void Cancel_Click(object sender, RoutedEventArgs e)
        {
            DialogResult = false;
        }

        private async void Ok_Click(object sender, RoutedEventArgs e)
        {
            ErrorText.Text = "";

            var sess = SessBox.SelectedItem as SessionRow;
            if (sess == null)
            {
                ErrorText.Text = "请选择一个在线会话（服务端只接受 v2 会话）";
                return;
            }

            string ptxt = (PortBox.Text ?? "").Trim();
            int port;
            if (!int.TryParse(ptxt, out port) || port <= 0 || port > 65535)
            {
                ErrorText.Text = "端口必须是 1 到 65535 之间的整数, 收到: "
                                 + (ptxt.Length == 0 ? "(空)" : ptxt);
                PortBox.Focus();
                return;
            }

            string target = (TargetBox.Text ?? "").Trim();
            if (_mode == "rportfwd" && target.Length > 0)
            {
                // 服务端用 net.SplitHostPort 校验, 这里先拦掉明显不合法的格式 (省一次往返)
                int colon = target.LastIndexOf(':');
                if (colon <= 0 || colon == target.Length - 1)
                {
                    ErrorText.Text = "回连目标格式应为 host:port, 收到: " + target;
                    TargetBox.Focus();
                    return;
                }
                int tp;
                if (!int.TryParse(target.Substring(colon + 1), out tp) || tp <= 0 || tp > 65535)
                {
                    ErrorText.Text = "回连目标的端口部分不合法 (应为 1 到 65535): " + target;
                    TargetBox.Focus();
                    return;
                }
            }

            _sess = sess;
            _port = port;
            _target = target;

            if (Submit == null)
            {
                DialogResult = true;
                return;
            }

            BtnOk.IsEnabled = false;
            try
            {
                string err = await Submit(this);
                if (string.IsNullOrEmpty(err))
                {
                    DialogResult = true;
                    return;
                }
                ErrorText.Text = err;      // 服务端 error 原样显示
            }
            catch (Exception ex)
            {
                ErrorText.Text = "提交异常: " + ex.Message;
            }
            finally
            {
                BtnOk.IsEnabled = true;
            }
        }
    }
}
