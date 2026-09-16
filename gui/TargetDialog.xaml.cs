using System;
using System.Threading.Tasks;
using System.Windows;

namespace CsdevGui
{
    /// <summary>
    /// 新增目标对话框。
    ///
    /// 提交走外部注入的回调 (<see cref="Submit"/>), 因此服务端返回的 error
    /// 能原样显示在对话框内, 用户不必关掉重开。回调返回空串表示成功。
    /// </summary>
    public partial class TargetDialog : Window
    {
        /// <summary>提交回调: 返回空串 = 成功 (关闭对话框); 非空 = 要原样显示的 error 文本。</summary>
        public Func<TargetDialog, Task<string>> Submit;

        public TargetDialog()
        {
            InitializeComponent();
            Loaded += delegate { HostBox.Focus(); };
        }

        public string HostValue { get { return (HostBox.Text ?? "").Trim(); } }
        public string IpValue { get { return (IpBox.Text ?? "").Trim(); } }
        public string OsValue { get { return (OsBox.Text ?? "").Trim(); } }
        public string NoteValue { get { return (NoteBox.Text ?? "").Trim(); } }

        private void Cancel_Click(object sender, RoutedEventArgs e)
        {
            DialogResult = false;
        }

        private async void Ok_Click(object sender, RoutedEventArgs e)
        {
            ErrorText.Text = "";

            // 服务端会以 "host 不能为空" 拒绝, 这里先拦一次省一个往返 (提示与服务端保持一致)
            if (HostValue.Length == 0)
            {
                ErrorText.Text = "host 不能为空";
                HostBox.Focus();
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
