using System;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace CsdevGui
{
    /// <summary>
    /// 操作员账号对话框 (添加 / 改口令共用)。
    ///
    /// 与 TargetDialog / ProxyDialog 同一个模式: 走注入式提交回调, 服务端的 error
    /// (用户已存在 / 口令至少 8 个字符 / 角色只能是 admin 或 operator / 用户不存在 ...)
    /// 原样显示在框内, 操作员当场改输入重试, 不用关掉对话框再点一次。
    ///
    /// mode = "new": 用户名 + 角色下拉 + 口令 + 确认口令  -> POST /api/user/new
    /// mode = "pass": 用户名只读          + 口令 + 确认口令  -> POST /api/user/pass
    ///
    /// 口令只在内存里从 PasswordBox 取一次就交给回调, 不写日志、不进任何配置。
    /// </summary>
    public partial class UserDialog : Window
    {
        /// <summary>提交回调: 返回空串 = 成功 (关闭对话框); 非空 = 要原样显示的 error 文本。</summary>
        public Func<UserDialog, Task<string>> Submit;

        private readonly string _mode;   // "new" 或 "pass"

        public UserDialog(string mode, string user)
        {
            InitializeComponent();

            _mode = string.Equals(mode, "pass", StringComparison.OrdinalIgnoreCase) ? "pass" : "new";
            bool edit = _mode == "pass";

            Title = edit ? "修改口令" : "添加操作员账号";
            HeadText.Text = Title;
            BtnOk.Content = edit ? "改口令" : "添加";
            SubText.Text = edit
                ? "POST /api/user/pass {user, pass}：服务端要求 admin 权限；改别人的口令会撤销他已发出的令牌"
                : "POST /api/user/new {user, pass, role}：服务端要求 admin 权限，口令至少 "
                  + AccountParse.MinPassLen + " 个字符";

            RoleBox.ItemsSource = AccountParse.RoleOptions();
            RoleBox.DisplayMemberPath = "Label";
            RoleBox.SelectedIndex = 0;               // 默认 operator (最小权限)

            if (edit)
            {
                UserBox.Text = AccountParse.SanitizeUser(user);
                UserBox.IsReadOnly = true;
                UserBox.Foreground = (Brush)FindResource("Dim");
                UserBox.ToolTip = "用户名不可改：服务端只有改口令接口，没有改名接口";
                UserNote.Text = "账号名固定；口令至少 " + AccountParse.MinPassLen + " 个字符";
                RolePanel.Visibility = Visibility.Collapsed;
            }

            Loaded += delegate
            {
                if (edit) { PassBox.Focus(); return; }
                UserBox.Focus();
                UserBox.SelectAll();
            };
        }

        /// <summary>清洗后的用户名 (服务端也按同一规则清洗后建账号)。</summary>
        public string UserValue { get { return AccountParse.SanitizeUser(UserBox.Text); } }

        /// <summary>所选角色 (改口令模式下 RolePanel 不可见, 回传空串)。</summary>
        public string RoleValue
        {
            get
            {
                var o = RoleBox.SelectedItem as RoleOption;
                return o == null ? "" : o.Value;
            }
        }

        /// <summary>明文口令 (只在内存里存在这一瞬)。</summary>
        public string PasswordValue { get { return PassBox.Password; } }

        /// <summary>输入与清洗结果不同时先说明白, 免得操作员以为服务端改了名字。</summary>
        private void UserBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            if (_mode == "pass") return;
            string raw = UserBox.Text ?? "";
            string clean = AccountParse.SanitizeUser(raw);
            if (clean.Length == 0)
            {
                UserNote.Text = "服务端按 sanitizeUser 清洗: 去首尾空白、去控制字符, 清洗后为空即非法";
                return;
            }
            UserNote.Text = string.Equals(raw, clean, StringComparison.Ordinal)
                ? "将创建账号: " + clean
                : "将按清洗后的名字创建: " + clean + "  (输入含空白或控制字符)";
        }

        private void Cancel_Click(object sender, RoutedEventArgs e)
        {
            DialogResult = false;
        }

        private async void Ok_Click(object sender, RoutedEventArgs e)
        {
            ErrorText.Text = "";

            string user = UserValue;
            string pass = PassBox.Password;
            string pass2 = Pass2Box.Password;
            string role = RoleValue;

            string problem = _mode == "pass"
                ? AccountParse.ValidatePass(user, pass, pass2)
                : AccountParse.ValidateNewUser(user, pass, pass2, role);

            if (problem.Length > 0)
            {
                ErrorText.Text = problem;
                if (user.Length == 0) UserBox.Focus();
                else if (pass.Length < AccountParse.MinPassLen) PassBox.Focus();
                else Pass2Box.Focus();
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
                ErrorText.Text = err;               // 服务端 error 原样
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
