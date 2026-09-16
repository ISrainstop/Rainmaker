using System;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace CsdevGui
{
    /// <summary>
    /// 新建监听器对话框: 下拉选类型 → 框内显示该类型的地址示例与说明 → 填地址 → 确定才下发。
    ///
    /// 与 ProxyDialog 同一模式 (注入式提交回调): 服务端的 error —— 端口占用、
    /// 绑定失败、"运行期不支持新增 http listener: ..." —— **原样**显示在框内。
    ///
    /// HTTP / HTTPS 保留在下拉里并标注"运行期不支持": 它们不该凭空消失, 而是让操作员
    /// 选中后看到原因, 点『仍要下发』拿到服务端那句原文 (GUI 不替服务端改写理由)。
    /// </summary>
    public partial class ListenerDialog : Window
    {
        /// <summary>提交回调: 返回空串 = 成功 (关闭对话框); 非空 = 要原样显示的 error 文本。</summary>
        public Func<ListenerDialog, Task<string>> Submit;

        private bool _switchGuard;      // 程序改 AddrBox 时不要被当成用户输入

        public ListenerDialog(string presetKind)
        {
            InitializeComponent();

            KindBox.ItemsSource = ListenerParse.Options();
            KindBox.DisplayMemberPath = "Label";

            string want = ListenerParse.NormalizeKind(presetKind);
            int idx = Array.IndexOf(ListenerParse.Kinds, want);
            KindBox.SelectedIndex = idx >= 0 ? idx : 2;      // 默认 tcp (运行期可用的第一个)

            Loaded += delegate { AddrBox.Focus(); AddrBox.SelectAll(); };
        }

        /// <summary>选中的 kind (小写, 服务端取值)。</summary>
        public string KindValue { get { return KindOf(KindBox.SelectedItem); } }

        /// <summary>地址原文 (去首尾空白后下发)。</summary>
        public string AddrValue { get { return (AddrBox.Text ?? "").Trim(); } }

        private static string KindOf(object item)
        {
            var o = item as KindOption;
            return o == null ? "" : o.Kind;
        }

        private void Kind_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            string kind = KindValue;
            if (kind.Length == 0) return;

            bool warn = ListenerParse.KindNeedsWarn(kind);

            KindNote.Text = ListenerParse.KindNote(kind);
            KindNote.Foreground = (Brush)FindResource(warn ? "Warn" : "Dim");
            BtnOk.Content = warn ? "仍要下发" : "创建";

            string example = ListenerParse.AddressExample(kind);
            // 地址框为空, 或还停在上一个类型的示例上时, 直接换成新类型的示例 ——
            // 操作员自己敲过的地址一律不动。
            if (!_switchGuard && (AddrValue.Length == 0 || IsAnyExample(AddrValue)))
            {
                _switchGuard = true;
                AddrBox.Text = example;
                AddrBox.SelectAll();
                _switchGuard = false;
            }

            AddrNote.Text = ListenerParse.AddressHint(kind);
            AddrNote.Foreground = (Brush)FindResource("Dim");
        }

        private static bool IsAnyExample(string addr)
        {
            for (int i = 0; i < ListenerParse.Kinds.Length; i++)
                if (string.Equals(ListenerParse.AddressExample(ListenerParse.Kinds[i]), addr, StringComparison.Ordinal))
                    return true;
            return false;
        }

        private void Cancel_Click(object sender, RoutedEventArgs e)
        {
            DialogResult = false;
        }

        private async void Ok_Click(object sender, RoutedEventArgs e)
        {
            ErrorText.Text = "";

            string kind = KindValue;
            if (kind.Length == 0)
            {
                ErrorText.Text = "请选择一个 listener 类型";
                return;
            }

            string addr = AddrValue;
            string problem = ListenerParse.AddressProblem(addr);
            if (problem.Length > 0)
            {
                ErrorText.Text = problem;
                AddrBox.Focus();
                return;
            }

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
                ErrorText.Text = err;                 // 服务端 error 原样 (含 HTTP 的拒绝理由)
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
