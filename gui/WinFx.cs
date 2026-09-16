using System;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;
using System.Windows.Media;

namespace CsdevGui
{
    /// <summary>
    /// 窗口特效: 亚克力/毛玻璃 背景 + DWM 边框圆角与标题栏染色。
    ///
    /// 全都是**尽力而为**的调用 —— 每个 API 在不同 Windows 版本上支持程度不同
    /// (亚克力要 Win10 1803+, 圆角与标题栏染色要 Win11 22000+), 失败就静默跳过、
    /// 界面回落到普通不透明背景。绝不因为系统不支持就让窗口起不来。
    ///
    /// 为什么要用 Win32 而不是纯 WPF: WPF 自身没有"模糊窗口背后内容"的能力,
    /// 只能靠 DwmEnableBlurBehindWindow / SetWindowCompositionAttribute 这类 DWM 接口。
    /// </summary>
    internal static class WinFx
    {
        // ---------------------------------------------------------------- Win32

        [DllImport("user32.dll")]
        private static extern int SetWindowCompositionAttribute(
            IntPtr hwnd, ref WindowCompositionAttributeData data);

        [DllImport("dwmapi.dll", PreserveSig = true)]
        private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int value, int size);

        private enum AccentState
        {
            Disabled = 0,
            EnableGradient = 1,
            EnableTransparentGradient = 2,
            EnableBlurBehind = 3,      // Win10 早期
            EnableAcrylicBlurBehind = 4, // Win10 1803+: 亚克力 (真正的毛玻璃)
            EnableHostBackdrop = 5
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct AccentPolicy
        {
            public int AccentState;
            public int AccentFlags;
            public uint GradientColor;   // ABGR
            public int AnimationId;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct WindowCompositionAttributeData
        {
            public int Attribute;
            public IntPtr Data;
            public int SizeOfData;
        }

        // ---------------------------------------------------------------- 版本

        private static Version _osVer;
        private static bool _osVerTried;

        private static Version OsVersion
        {
            get
            {
                if (!_osVerTried)
                {
                    _osVerTried = true;
                    try { _osVer = Environment.OSVersion.Version; }
                    catch { _osVer = new Version(6, 1); }
                }
                return _osVer;
            }
        }

        /// <summary>Win11 (build 22000+) —— 支持窗口圆角与标题栏染色。</summary>
        private static bool IsWin11
        {
            get { return OsVersion.Major >= 10 && OsVersion.Build >= 22000; }
        }

        // ---------------------------------------------------------------- 主入口

        /// <summary>
        /// 给窗口加上亚克力背景 + DWM 圆角 + 浅色标题栏。
        /// <paramref name="tint"/> 是叠加在模糊之上的色调 (通常给主题的面板色, 带 alpha)。
        /// 不支持的项会被跳过, 不影响窗口正常显示。
        /// </summary>
        public static void Apply(Window w, Color tint)
        {
            if (w == null) return;
            try
            {
                var helper = new WindowInteropHelper(w);
                IntPtr hwnd = helper.Handle;
                if (hwnd == IntPtr.Zero) return;   // 还没建句柄, 调用方应在 SourceInitialized 之后调

                EnableAcrylic(hwnd, tint);
                EnableRoundCorners(hwnd);
                SetCaptionColor(hwnd, tint);
            }
            catch
            {
                // 特效失败绝不影响可用性
            }
        }

        /// <summary>
        /// 亚克力 (Acrylic) 背景。GradientColor 是 ABGR 打包的 32 位色 ——
        /// 注意**不是** WPF 的 ARGB, 字节序是 A-B-G-R, 写反了颜色会整体偏红/偏蓝。
        /// </summary>
        private static void EnableAcrylic(IntPtr hwnd, Color tint)
        {
            uint abgr = (uint)((tint.A << 24) | (tint.B << 16) | (tint.G << 8) | tint.R);

            var policy = new AccentPolicy
            {
                AccentState = (int)AccentState.EnableAcrylicBlurBehind,
                AccentFlags = 0x20,          // 让模糊覆盖整窗 (含标题栏区域)
                GradientColor = abgr,
                AnimationId = 0
            };

            int size = Marshal.SizeOf(policy);
            IntPtr ptr = Marshal.AllocHGlobal(size);
            try
            {
                Marshal.StructureToPtr(policy, ptr, false);
                var data = new WindowCompositionAttributeData
                {
                    Attribute = 19,          // WCA_ACCENT_POLICY
                    Data = ptr,
                    SizeOfData = size
                };
                SetWindowCompositionAttribute(hwnd, ref data);
            }
            finally
            {
                Marshal.FreeHGlobal(ptr);
            }
        }

        /// <summary>Win11 窗口圆角 (DWMWA_WINDOW_CORNER_PREFERENCE = 33)。</summary>
        private static void EnableRoundCorners(IntPtr hwnd)
        {
            if (!IsWin11) return;
            int pref = 2;   // DWMWCP_ROUND
            DwmSetWindowAttribute(hwnd, 33, ref pref, sizeof(int));
        }

        /// <summary>
        /// 标题栏染色 (DWMWA_CAPTION_COLOR = 35, Win11 22000+)。
        /// 目的: 让系统标题栏跟浅色界面同色, 不再是一条突兀的深灰。
        /// </summary>
        private static void SetCaptionColor(IntPtr hwnd, Color tint)
        {
            if (!IsWin11) return;

            // 标题栏要不透明, 否则文字会和底下的模糊糊在一起
            int caption = (tint.R << 16) | (tint.G << 8) | tint.B;   // COLORREF 是 BGR 顺序的 0x00BBGGRR
            DwmSetWindowAttribute(hwnd, 35, ref caption, sizeof(int));

            int text = 0x30241F;   // 深色文字 (#1F2430 的 BGR)
            DwmSetWindowAttribute(hwnd, 36, ref text, sizeof(int));
        }
    }
}
