"""
cs_dev :: unpack_stage.py  --  还原 CS stage 的自解密 stub

从 stage 入口反汇编还原出的算法:
    0x00: cld
    0x01: call 0x10                 ; 压入返回地址 0x06
    0x10: jmp  0x39
    0x39: call 0x12                 ; 压入返回地址 0x3E
    0x12: pop  rbx                  ; rbx = 0x3E  (自身定位)
    0x13: mov  ebp, [rbx]           ; ebp = [0x3E]         <- XOR 密钥
    0x15: add  rbx, 4
    0x18: mov  eax, [rbx]           ; eax = [0x42]
    0x1A: xor  eax, ebp             ; eax = 密文长度
    0x1C: add  rbx, 4               ; rbx = 0x46           <- 密文起点
    0x1F: push rbx                  ; 保存密文起点, 解密完跳到这里
    0x20: mov  edx, [rbx]
    0x22: xor  edx, ebp             ; 解密一个 DWORD
    0x24: mov  [rbx], edx           ; 原地写回
    0x26: xor  ebp, edx             ; 密钥链式更新
    0x28: add  rbx, 4
    0x2B: sub  eax, 4
    0x30: cmp  eax, 0
    0x32: je   0x36
    0x34: jmp  0x20
    0x36: pop  rbp                  ; rbp = 0x46
    0x37: jmp  rbp                  ; 跳入解密后的明文
"""
import sys, struct

def main():
    src = sys.argv[1] if len(sys.argv) > 1 else r"D:\cobalt_strike_4.7\cs_dev\build\stager\stage_full.bin"
    dst = sys.argv[2] if len(sys.argv) > 2 else r"D:\cobalt_strike_4.7\cs_dev\build\stager\stage_plain.bin"

    b = bytearray(open(src, "rb").read())
    print("[*] 输入 %d 字节" % len(b))

    key       = struct.unpack_from("<I", b, 0x3E)[0]
    enc_len   = struct.unpack_from("<I", b, 0x42)[0]
    plain_len = enc_len ^ key
    start     = 0x46

    print("    key(0x3E)       = 0x%08X" % key)
    print("    raw(0x42)       = 0x%08X" % enc_len)
    print("    plain_len(^key) = 0x%08X  (%d 字节)" % (plain_len, plain_len))
    print("    密文起点        = 0x%X" % start)

    if plain_len <= 0 or plain_len > len(b) - start:
        print("[!] 长度不合理, 与文件大小不匹配 (剩余 %d 字节)" % (len(b) - start))
        return

    ebp = key
    rbx = start
    remaining = plain_len
    while remaining > 0:
        edx = struct.unpack_from("<I", b, rbx)[0]
        edx ^= ebp
        struct.pack_into("<I", b, rbx, edx)
        ebp ^= edx
        rbx += 4
        remaining -= 4
        if remaining <= 0:
            break

    out = bytes(b[start:start + plain_len])
    open(dst, "wb").write(out)
    print("[+] 已还原 %d 字节 -> %s" % (len(out), dst))
    print()
    print("=== 明文前 64 字节 ===")
    for i in range(0, min(64, len(out)), 16):
        seg = out[i:i+16]
        print("  %04X: %s" % (i, " ".join("%02X" % x for x in seg)))
    print()
    print("=== 明文特征 ===")
    print("  MZ 头 (PE)     : %s" % (out[:2] == b"MZ"))
    txt = out.decode("latin-1")
    for k in ("LoadLibraryA", "GetProcAddress", "VirtualAlloc", "VirtualProtect",
              "kernel32", "wininet", "WinHttp", "ReflectiveLoader", "ntdll",
              "beacon", "Sleep", "CreateThread"):
        if k in txt:
            print("  含字符串: %s" % k)
    if out[:2] == b"MZ":
        pe = struct.unpack_from("<I", out, 0x3C)[0]
        print("  PE 偏移        : 0x%X" % pe)
        print("  机器码         : 0x%04X" % struct.unpack_from("<H", out, pe + 4)[0])

main()
