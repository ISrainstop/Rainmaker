using System.Windows;

namespace CsdevGui
{
    /// <summary>sleep / jitter 调整小对话框。校验规则与服务端 handleSessionSleep 的下限/上限一致。</summary>
    public partial class SleepDialog : Window
    {
        public long SleepMs { get; private set; }
        public long Jitter { get; private set; }

        public SleepDialog(string sid, long sleepMs, long jitter)
        {
            InitializeComponent();

            SleepMs = sleepMs;
            Jitter = jitter;
            SleepBox.Text = sleepMs.ToString();
            JitterBox.Text = jitter.ToString();
            TargetText.Text = "目标会话: " + sid;

            Loaded += delegate
            {
                SleepBox.Focus();
                SleepBox.SelectAll();
            };
        }

        private void Ok_Click(object sender, RoutedEventArgs e)
        {
            long ms;
            if (!long.TryParse(SleepBox.Text.Trim(), out ms) || ms < 100 || ms > 86400000)
            {
                ErrorText.Text = "sleep 需要 100 至 86400000 之间的整数毫秒 (服务端会把小于 100 的值抬到 100)";
                return;
            }

            long j;
            if (!long.TryParse(JitterBox.Text.Trim(), out j) || j < 0 || j > 99)
            {
                ErrorText.Text = "jitter 需要 0 至 99 之间的整数百分比 (服务端把大于 99 的值压到 99)";
                return;
            }

            SleepMs = ms;
            Jitter = j;
            DialogResult = true;
        }

        private void Cancel_Click(object sender, RoutedEventArgs e)
        {
            DialogResult = false;
        }
    }
}
