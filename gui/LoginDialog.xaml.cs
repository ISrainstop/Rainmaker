using System;
using System.Windows;

namespace CsdevGui
{
    /// <summary>
    /// 登录门。两种用法:
    ///   1) 启动时无参构造 —— 出"地址 + 账号 + 口令"完整表单, 通过后由 App 建主窗口;
    ///   2) 运行中带参构造 (api, defaultUser) —— 服务端要求认证时重新取令牌。
    ///
    /// 成功后把令牌写进 csdev 的 CsdevApi, 并通过 Result* 属性回传给调用方。
    ///
    /// 注意: 服务端以 -auth=off 启动时, 任意账号都能拿到令牌 (authCheck 直接放行) ——
    /// 这里的"登录"只是形式, 真正的访问控制开关在服务端。
    /// </summary>
    public partial class LoginDialog : Window
    {
        private readonly CsdevApi _api;
        private readonly bool _standalone;

        /// <summary>登录成功的操作员名 (供调用方显示认证状态)。</summary>
        public string UserName { get; private set; }

        /// <summary>
        /// 令牌里的角色 (admin / operator)。账号管理区据此决定可用性 ——
        /// 不是 admin 就置灰并说明原因, 而不是等撞 403 才报错。
        /// </summary>
        public string Role { get; private set; }

        /// <summary>登录成功后实际使用的服务端地址 (规范化后的)。</summary>
        public string ResultBaseUrl { get; private set; } = "";
        public string ResultToken { get; private set; } = "";
        public string ResultUser { get; private set; } = "";
        public string ResultRole { get; private set; } = "";

        /// <summary>启动门用法: 自己持有 CsdevApi, 没有任何窗口依赖。</summary>
        public LoginDialog() : this(new CsdevApi(), "", true) { }

        /// <summary>运行中用法: 复用调用方已有的 api 实例 (令牌写回它)。</summary>
        public LoginDialog(CsdevApi api, string defaultUser) : this(api, defaultUser, false) { }

        private LoginDialog(CsdevApi api, string defaultUser, bool standalone)
        {
            InitializeComponent();

            _api = api ?? new CsdevApi();
            _standalone = standalone;

            // 地址: 启动门优先用上次连接过的; 运行中用法沿用当前 api 的地址
            string url = _api.BaseUrl ?? "";
            UrlBox.Text = url.Length > 0 ? url : "127.0.0.1:8443";
            UserBox.Text = string.IsNullOrEmpty(defaultUser) ? "admin" : defaultUser;

            // 运行中重新登录时不再让用户改地址 (换了地址令牌也无效), 但保留可见
            UrlBox.IsReadOnly = !standalone;
            SubTitle.Text = standalone ? "连接到控制台" : "服务端要求认证, 请重新登录";

            Loaded += delegate
            {
                // 启动门: 有地址就跳到用户名; 否则先让用户填地址
                if (standalone && url.Length == 0) UrlBox.Focus();
                else UserBox.Focus();
            };
        }

        private async void Ok_Click(object sender, RoutedEventArgs e)
        {
            string url = (UrlBox.Text ?? "").Trim();
            string user = (UserBox.Text ?? "").Trim();

            if (url.Length == 0) { ErrorText.Text = "请填写服务端地址"; UrlBox.Focus(); return; }
            if (user.Length == 0) { ErrorText.Text = "请填写用户名"; UserBox.Focus(); return; }
            if (PassBox.Password.Length == 0) { ErrorText.Text = "请填写口令"; PassBox.Focus(); return; }

            BtnOk.IsEnabled = false;
            ErrorText.Text = "正在连接并登录 ...";
            try
            {
                string norm = ConnStore.Normalize(url);
                if (norm.Length == 0) { ErrorText.Text = "服务端地址不合法"; return; }
                _api.BaseUrl = norm;

                // 走 LoginFullAsync: 除了令牌还要把 role 带回来 (账号管理区要用)
                var res = await _api.LoginFullAsync(user, PassBox.Password);
                if (!res.Ok)
                {
                    ErrorText.Text = "登录失败: " + res.Error;
                    return;
                }
                _api.Token = res.Token;
                UserName = res.User.Length > 0 ? res.User : user;
                Role = res.Role;

                ResultBaseUrl = norm;
                ResultToken = res.Token;
                ResultUser = UserName;
                ResultRole = Role ?? "";

                DialogResult = true;
            }
            catch (Exception ex)
            {
                ErrorText.Text = "登录失败: " + ex.Message;
            }
            finally
            {
                BtnOk.IsEnabled = true;
            }
        }

        private void Cancel_Click(object sender, RoutedEventArgs e)
        {
            DialogResult = false;
        }
    }
}
